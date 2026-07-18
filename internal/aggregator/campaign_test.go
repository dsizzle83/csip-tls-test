package aggregator

// Pure-Go tests for the scenario engine's DATA + JUDGMENT surfaces (T06.6/T06.7):
// the campaign schema decode/reject table, the UnitSel union, the oracle registry
// and each oracle's decision table against synthetic evidence, the verdict-layer
// helpers, and a compile-all pass over every shipped qa/aggregator/*.json (a
// broken seed fails CI, not a live campaign). These run under `make test-fast`:
// they compile cgo transitively via mbtls but drive no wolfSSL handshake, so
// wolfssl.Init is not needed. The loopback engine proof is the integration test.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validCampaignJSON is a minimal well-formed campaign used as the base for the
// reject table (each case mutates one thing).
const validCampaignJSON = `{
  "camp_v": 1,
  "id": "t",
  "name": "test",
  "role": "GridServiceSunSpec",
  "target": "gateway",
  "steps": [
    {"do": "write_point", "unit": 2, "model": 704, "point": "WMaxLimPct", "value": 50},
    {"do": "readback", "unit": 2, "model": 704, "point": "WMaxLimPct", "expect": 50, "sla_s": 10}
  ],
  "oracle": {"name": "convergeWithinSLA"},
  "expected_verdicts": ["PASS"]
}`

func TestDecodeCampaign_Valid(t *testing.T) {
	c, err := DecodeCampaign([]byte(validCampaignJSON))
	if err != nil {
		t.Fatalf("valid campaign rejected: %v", err)
	}
	if c.ID != "t" || c.Role != RoleGridService || c.Target != TargetGateway || len(c.Steps) != 2 {
		t.Fatalf("decoded campaign wrong: %+v", c)
	}
	if c.Oracle.Name != "convergeWithinSLA" {
		t.Errorf("oracle = %q", c.Oracle.Name)
	}
}

// TestDecodeCampaign_Rejects is the load-time validation table: each input is
// malformed in exactly one documented way and must fail with an error naming the
// offending field.
func TestDecodeCampaign_Rejects(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"bad version", `{"camp_v":2,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"discover"}],"oracle":{"name":"convergeWithinSLA"}}`, "camp_v"},
		{"missing id", `{"camp_v":1,"name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"discover"}],"oracle":{"name":"convergeWithinSLA"}}`, "id"},
		{"unknown role", `{"camp_v":1,"id":"t","name":"n","role":"Nope","target":"gateway","steps":[{"do":"discover"}],"oracle":{"name":"convergeWithinSLA"}}`, "role"},
		{"bad target", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"hub","steps":[{"do":"discover"}],"oracle":{"name":"convergeWithinSLA"}}`, "target"},
		{"no steps", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[],"oracle":{"name":"convergeWithinSLA"}}`, "no steps"},
		{"unknown verb", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"teleport"}],"oracle":{"name":"convergeWithinSLA"}}`, "unknown verb"},
		{"unknown field", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"discover","bogus":1}],"oracle":{"name":"convergeWithinSLA"}}`, "bogus"},
		{"write unknown model", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"write_point","unit":2,"model":705,"point":"Ena","value":1}],"oracle":{"name":"convergeWithinSLA"}}`, "705"},
		{"write bad point", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"write_point","unit":2,"model":704,"point":"Nope","value":1}],"oracle":{"name":"convergeWithinSLA"}}`, "not in model"},
		{"write unit 0", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"write_point","unit":0,"model":704,"point":"WMaxLimPct","value":1}],"oracle":{"name":"convergeWithinSLA"}}`, "unit must be"},
		{"readback no sla", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"readback","unit":2,"model":704,"point":"WMaxLimPct","expect":50}],"oracle":{"name":"convergeWithinSLA"}}`, "sla_s"},
		{"readback bad phase", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"readback","unit":2,"model":704,"point":"WMaxLimPct","expect":50,"sla_s":5,"phase":"whoops"}],"oracle":{"name":"reversionOnExpiry"}}`, "phase"},
		{"poll bad period", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"poll","period_s":0}],"oracle":{"name":"convergeWithinSLA"}}`, "period_s"},
		{"sleep bad", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"sleep_s","seconds":0}],"oracle":{"name":"convergeWithinSLA"}}`, "seconds"},
		{"sim_fault no target", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"sim_fault","fault":{"kind":"drop_session"}}],"oracle":{"name":"convergeWithinSLA"}}`, "target"},
		{"sim_fault no body", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"sim_fault","target":"solar"}],"oracle":{"name":"convergeWithinSLA"}}`, "fault body"},
		{"connect_as bad role", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"connect_as","role":"Nope"}],"oracle":{"name":"convergeWithinSLA"}}`, "role"},
		{"unknown oracle", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"discover"}],"oracle":{"name":"noSuchOracle"}}`, "not registered"},
		{"oracle stray params", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"discover"}],"oracle":{"name":"convergeWithinSLA","params":{"x":1}}}`, "takes no params"},
		{"bad verdict", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"discover"}],"oracle":{"name":"convergeWithinSLA"},"expected_verdicts":["GREAT"]}`, "expected_verdicts"},
		{"units bad string", `{"camp_v":1,"id":"t","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"poll","period_s":1,"units":"all"}],"oracle":{"name":"convergeWithinSLA"}}`, `units string must be`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeCampaign([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected rejection mentioning %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestUnitSel_Unmarshal(t *testing.T) {
	var star UnitSel
	if err := json.Unmarshal([]byte(`"*"`), &star); err != nil || !star.All {
		t.Errorf(`"*" => %+v, err %v`, star, err)
	}
	var list UnitSel
	if err := json.Unmarshal([]byte(`[2,3,10]`), &list); err != nil || list.All || len(list.Units) != 3 {
		t.Errorf("list => %+v, err %v", list, err)
	}
	var bad UnitSel
	if err := json.Unmarshal([]byte(`"everything"`), &bad); err == nil {
		t.Error(`"everything" should be rejected`)
	}
}

// TestLoadCampaignDir_Seeds compiles every shipped campaign — the acceptance bar
// that a broken seed fails CI, not a live run.
func TestLoadCampaignDir_Seeds(t *testing.T) {
	camps, errs := LoadCampaignDir(filepath.Join("..", "..", "qa", "aggregator"))
	for _, e := range errs {
		t.Errorf("campaign load error: %v", e)
	}
	if len(camps) < 4 {
		t.Fatalf("loaded %d campaigns, want >= 4 seeds", len(camps))
	}
	want := map[string]bool{
		"curtail-solar-50": false, "role-denial-readonly": false,
		"battery-hold-dispatch": false, "ramp-limit-reversion": false,
		// T06.8 TLS-fault probe campaigns.
		"resumption-after-drop": false, "mid-session-drop": false,
		"renego-refusal": false,
	}
	for _, c := range camps {
		if _, ok := want[c.ID]; ok {
			want[c.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("seed campaign %q not loaded", id)
		}
	}
}

// TestLoadCampaignDir_IDCollision proves a duplicate id is a load error naming
// the file, and never a silent shadow, while other files still load.
func TestLoadCampaignDir_IDCollision(t *testing.T) {
	dir := t.TempDir()
	body := func(id string) string {
		return `{"camp_v":1,"id":"` + id + `","name":"n","role":"GridServiceSunSpec","target":"gateway","steps":[{"do":"discover"}],"oracle":{"name":"convergeWithinSLA"}}`
	}
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(body("dup")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(body("dup")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.json"), []byte(body("unique")), 0o644); err != nil {
		t.Fatal(err)
	}
	camps, errs := LoadCampaignDir(dir)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "collides") {
		t.Fatalf("want 1 collision error, got %v", errs)
	}
	if len(camps) != 2 { // a.json + c.json load; b.json is excluded
		t.Errorf("want 2 loaded (collision excludes one), got %d", len(camps))
	}
}

// ── Oracle decision tables ───────────────────────────────────────────────────

func rbStep(idx int, phase string, expect float64, converged, hadRead bool, tookS, slaS float64) StepResult {
	return StepResult{
		Index: idx, Do: StepReadback, OK: converged,
		Readback: &ReadbackRecord{
			Unit: 2, Model: 704, Point: "WMaxLimPct", Phase: phase,
			Expect: expect, Tol: 1, SLAS: slaS, Converged: converged,
			HadRead: hadRead, Final: expect, Reads: 1, TookS: tookS,
		},
	}
}

func exStep(idx int, code, expected uint8, wrote bool) StepResult {
	dr := DenialResult{Unit: 2, Model: 704, Point: "WMaxLimPct", Stage: "write", FC: 0x10, ExceptionCode: code, Denied: code == 1, Wrote: wrote}
	return StepResult{
		Index: idx, Do: StepExpectException, OK: !wrote && code == expected,
		Exception: &ExceptionCheck{Result: dr, Expected: expected, Match: !wrote && code == expected},
	}
}

func TestConvergeWithinSLA(t *testing.T) {
	cases := []struct {
		name  string
		steps []StepResult
		want  Verdict
	}{
		{"all converged", []StepResult{rbStep(0, "", 50, true, true, 0.2, 10)}, VerdictPass},
		{"not converged", []StepResult{rbStep(0, "", 50, false, true, 10, 10)}, VerdictFail},
		{"slow", []StepResult{rbStep(0, "", 50, true, true, 9, 10)}, VerdictDegraded},
		{"blind never read", []StepResult{rbStep(0, "", 50, false, false, 10, 10)}, VerdictBlind},
		{"no readback", []StepResult{{Index: 0, Do: StepDiscover, OK: true}}, VerdictInconclusive},
		{"fail dominates slow", []StepResult{rbStep(0, "", 50, true, true, 9, 10), rbStep(1, "", 100, false, true, 10, 10)}, VerdictFail},
		{"write transport fail", []StepResult{{Index: 0, Do: StepWritePoint, OK: false, Err: "conn reset"}, rbStep(1, "", 50, true, true, 0.1, 10)}, VerdictInconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &CampaignReport{Steps: tc.steps}
			got, _ := convergeWithinSLA(rep)
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDenyExpected(t *testing.T) {
	cases := []struct {
		name  string
		steps []StepResult
		want  Verdict
	}{
		{"all denied 01", []StepResult{exStep(0, 1, 1, false), exStep(1, 1, 1, false)}, VerdictPass},
		{"write accepted", []StepResult{exStep(0, 0, 1, true)}, VerdictFail},
		{"wrong code", []StepResult{exStep(0, 2, 1, false)}, VerdictFail},
		{"no probe", []StepResult{{Index: 0, Do: StepDiscover, OK: true}}, VerdictInconclusive},
		{"transport error probe", []StepResult{{Index: 0, Do: StepExpectException, OK: false, Err: "conn reset"}}, VerdictInconclusive},
		{"fail dominates pass", []StepResult{exStep(0, 1, 1, false), exStep(1, 0, 1, true)}, VerdictFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &CampaignReport{Steps: tc.steps}
			got, _ := denyExpected(rep)
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestReversionOnExpiry(t *testing.T) {
	cases := []struct {
		name  string
		steps []StepResult
		want  Verdict
	}{
		{"held then reverted", []StepResult{rbStep(0, "hold", 50, true, true, 0.1, 10), rbStep(1, "revert", 100, true, true, 0.1, 15)}, VerdictPass},
		{"stuck curtailment", []StepResult{rbStep(0, "hold", 50, true, true, 0.1, 10), rbStep(1, "revert", 100, false, true, 15, 15)}, VerdictFail},
		{"ceiling never took", []StepResult{rbStep(0, "hold", 50, false, true, 10, 10), rbStep(1, "revert", 100, true, true, 0.1, 15)}, VerdictInconclusive},
		{"no revert readback", []StepResult{rbStep(0, "hold", 50, true, true, 0.1, 10)}, VerdictInconclusive},
		{"hold never read", []StepResult{rbStep(0, "hold", 50, false, false, 10, 10), rbStep(1, "revert", 100, true, true, 0.1, 15)}, VerdictBlind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &CampaignReport{Steps: tc.steps}
			got, _ := reversionOnExpiry(rep)
			if got != tc.want {
				t.Errorf("verdict = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestVerdictHelpers(t *testing.T) {
	if worse(VerdictPass, VerdictFail) != VerdictFail {
		t.Error("FAIL should dominate PASS")
	}
	if worse(VerdictInconclusive, VerdictDegraded) != VerdictInconclusive {
		t.Error("INCONCLUSIVE should dominate DEGRADED")
	}
	if worse("", VerdictPass) != VerdictPass {
		t.Error("empty should lose to any verdict")
	}
	if !verdictIn(VerdictPass, nil) {
		t.Error("empty expected set accepts any verdict")
	}
	if verdictIn(VerdictFail, []Verdict{VerdictPass}) {
		t.Error("FAIL not in {PASS} should be false")
	}
	if !ValidVerdict(VerdictBlind) || ValidVerdict(Verdict("NOPE")) {
		t.Error("ValidVerdict wrong")
	}
}

// TestCampaignReport_JSONRoundTrip proves the verdict layer serializes cleanly and
// the human summary is populated.
func TestCampaignReport_JSONRoundTrip(t *testing.T) {
	rep := &CampaignReport{
		CampV: CampaignV, ID: "curtail", Name: "n", Role: RoleGridService, Target: TargetGateway,
		Oracle: "convergeWithinSLA", Verdict: VerdictPass, ExpectedVerdicts: []Verdict{VerdictPass},
		VerdictExpected: true,
		Steps: []StepResult{
			{Index: 0, Do: StepWritePoint, OK: true, LatencyMS: 12, Write: &WriteRecord{Unit: 2, Model: 704, Point: "WMaxLimPct", Value: 50, OK: true}},
			rbStep(1, "", 50, true, true, 0.2, 10),
		},
		Findings: []string{"converged"},
	}
	rep.SummaryHuman = rep.renderSummary()
	if !strings.Contains(rep.SummaryHuman, "PASS") || !strings.Contains(rep.SummaryHuman, "converged") {
		t.Errorf("summary missing key content: %q", rep.SummaryHuman)
	}
	raw, err := rep.JSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back CampaignReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Verdict != VerdictPass || len(back.Steps) != 2 || back.Steps[1].Readback == nil {
		t.Errorf("round-trip lost data: %+v", back)
	}
}

// TestOracleRegistry_Complete proves the three shipped oracles are registered and
// build without params.
func TestOracleRegistry_Complete(t *testing.T) {
	for _, name := range []string{"convergeWithinSLA", "denyExpected", "reversionOnExpiry"} {
		if _, err := buildOracle(OracleRef{Name: name}); err != nil {
			t.Errorf("oracle %q did not build: %v", name, err)
		}
	}
	if _, err := buildOracle(OracleRef{Name: "ghost"}); err == nil {
		t.Error("unknown oracle should not build")
	}
}
