package main

// scenariospec_test.go — TASK-076 unit coverage: schema decode/validation,
// the compiler (oracle registry + action vocabulary), and end-to-end parity
// checks that a compiled spec calls the exact same mayhemDriver methods,
// with the exact same bodies, that its hand-written Go twin calls. These are
// unit-level proofs (fake HTTP backends via httptest, no bench) — the
// pilot's live-bench ×3 parity run is out of this task's lane (see the
// launch brief) and stays a documented residual like several other P6 tasks
// this deadline push.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ── test fixture: a recording fake backend ─────────────────────────────────

type recordedCall struct {
	Method string
	Path   string
	Body   map[string]any
}

type callLog struct {
	mu    sync.Mutex
	calls []recordedCall
}

func (c *callLog) record(r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body) // best-effort; GETs/empty bodies decode to nil, fine
	}
	c.mu.Lock()
	c.calls = append(c.calls, recordedCall{Method: r.Method, Path: r.URL.Path, Body: body})
	c.mu.Unlock()
}

// find returns the first recorded call matching method+path, or nil.
func (c *callLog) find(method, path string) *recordedCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.calls {
		if c.calls[i].Method == method && c.calls[i].Path == path {
			return &c.calls[i]
		}
	}
	return nil
}

// count returns how many calls matched method+path (e.g. inject_env fires on
// every tick, so per_tick assertions want a count, not just presence).
func (c *callLog) count(method, path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, call := range c.calls {
		if call.Method == method && call.Path == path {
			n++
		}
	}
	return n
}

// newRecordingServer answers every request 200 (with a mock mRID for
// POST /admin/control, and a non-empty default body for GET /admin/default,
// so suppressDefault's restore path has something to restore) while logging
// every call the compiled closures make.
func newRecordingServer(t *testing.T, log *callLog) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/admin/control":
			_ = json.NewEncoder(w).Encode(map[string]string{"mrid": "test-mrid"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin/default"):
			_ = json.NewEncoder(w).Encode(map[string]any{"exp_lim_W": 5000})
		default:
			w.Write([]byte("{}"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestDriver wires one recording server per backend name and returns the
// driver plus a lookup of that backend's log.
func newTestDriver(t *testing.T, names ...string) (*mayhemDriver, map[string]*callLog) {
	t.Helper()
	backends := map[string]string{}
	logs := map[string]*callLog{}
	for _, n := range names {
		l := &callLog{}
		srv := newRecordingServer(t, l)
		backends[n] = srv.URL
		logs[n] = l
	}
	d := newMayhemDriver(backends)
	d.pvHighW = 4800 // as baseline() would set post-nameplate-read
	return d, logs
}

func repoRootFromTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd() // cmd/dashboard
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

// ── decode / validate ────────────────────────────────────────────────────────

func TestDecodeSpec_PilotFileRoundTrips(t *testing.T) {
	path := filepath.Join(repoRootFromTest(t), "qa", "scenarios", "export-cap-full-battery.json")
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading pilot spec: %v", err)
	}
	spec, err := decodeSpec(buf)
	if err != nil {
		t.Fatalf("decodeSpec: %v", err)
	}
	if spec.ID != "export-cap-full-battery" {
		t.Errorf("ID = %q, want export-cap-full-battery", spec.ID)
	}
	if spec.Oracle.Name != "diagnoseConstraint" {
		t.Errorf("Oracle.Name = %q, want diagnoseConstraint", spec.Oracle.Name)
	}
	if spec.Constraint == nil || spec.Constraint.Type != "exportCap" {
		t.Errorf("Constraint = %+v, want type exportCap", spec.Constraint)
	}
}

func TestDecodeSpec_UnknownFieldRejected(t *testing.T) {
	buf := []byte(`{"spec_v":1,"id":"x","name":"x","category":"x","hypothesis":"x","expected":"x","hold_s":10,"oracle":{"name":"diagnoseRecovery"},"typo_field":true}`)
	if _, err := decodeSpec(buf); err == nil {
		t.Fatal("expected an error for an unknown top-level field, got nil")
	}
}

func TestValidateSpec_Errors(t *testing.T) {
	base := func() *scenarioSpec {
		return &scenarioSpec{
			SpecV: 1, ID: "x", Name: "x", Category: "x",
			Hypothesis: "x", Expected: "x", HoldS: 10,
			Oracle: scenarioOracleRef{Name: "diagnoseRecovery"},
		}
	}
	cases := []struct {
		name     string
		mutate   func(*scenarioSpec)
		wantErrs []string // substrings that must all appear
	}{
		{"bad spec_v", func(s *scenarioSpec) { s.SpecV = 2 }, []string{"spec_v"}},
		{"missing id", func(s *scenarioSpec) { s.ID = "" }, []string{`"id"`}},
		{"missing hypothesis", func(s *scenarioSpec) { s.Hypothesis = "  " }, []string{`"hypothesis"`}},
		{"hold_s zero", func(s *scenarioSpec) { s.HoldS = 0 }, []string{"hold_s"}},
		{"missing oracle name", func(s *scenarioSpec) { s.Oracle.Name = "" }, []string{"oracle.name"}},
		{"bad expected_verdicts", func(s *scenarioSpec) { s.ExpectedVerdicts = []string{"MAYBE"} }, []string{"expected_verdicts", "MAYBE"}},
		{
			"unknown action", func(s *scenarioSpec) {
				s.Setup = []scenarioAction{{Action: "teleport"}}
			}, []string{"setup[0]", "teleport"},
		},
		{
			"sim_post unknown target", func(s *scenarioSpec) {
				s.Setup = []scenarioAction{{Action: actSimPost, Target: "toaster", Path: "/inject"}}
			}, []string{"setup[0]", "toaster"},
		},
		{
			"at_tick outside setup", func(s *scenarioSpec) {
				tick := 3
				s.Setup = []scenarioAction{{Action: actInjectEnv, AtTick: &tick}}
			}, []string{"setup[0]", "at_tick"},
		},
		{
			"at_tick out of range", func(s *scenarioSpec) {
				tick := 99
				s.PerTick = []scenarioAction{{Action: actInjectEnv, AtTick: &tick}}
			}, []string{"per_tick[0]", "99"},
		},
		{
			"constraint action in per_tick", func(s *scenarioSpec) {
				s.PerTick = []scenarioAction{{Action: actPostCap, Typ: "exportCap", HoldS: 5}}
			}, []string{"per_tick[0]", "post_cap"},
		},
		{
			"suppress_default in per_tick", func(s *scenarioSpec) {
				s.PerTick = []scenarioAction{{Action: actSuppressDefault}}
			}, []string{"per_tick[0]", "suppress_default"},
		},
		{
			"sleep_s in per_tick", func(s *scenarioSpec) {
				s.PerTick = []scenarioAction{{Action: actSleepS, Seconds: 1}}
			}, []string{"per_tick[0]", "sleep_s"},
		},
		{
			"constraint action in teardown", func(s *scenarioSpec) {
				s.Teardown = []scenarioAction{{Action: actPostConnect}}
			}, []string{"teardown[0]", "post_connect"},
		},
		{
			"bad constraint type", func(s *scenarioSpec) {
				s.Constraint = &scenarioConstraint{Type: "warpDrive", HoldS: 5}
			}, []string{"constraint", "warpDrive"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := base()
			c.mutate(spec)
			err := validateSpec(spec)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			for _, want := range c.wantErrs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err.Error(), want)
				}
			}
		})
	}
}

func TestValidateSpec_ValidPasses(t *testing.T) {
	tick := 5
	spec := &scenarioSpec{
		SpecV: 1, ID: "x", Name: "x", Category: "x",
		Hypothesis: "x", Expected: "x", HoldS: 10,
		Oracle:  scenarioOracleRef{Name: "diagnoseRecovery"},
		Setup:   []scenarioAction{{Action: actInjectEnv, PVW: json.RawMessage(`100`)}},
		PerTick: []scenarioAction{{Action: actInjectEnv, AtTick: &tick}},
	}
	if err := validateSpec(spec); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── oracle registry ──────────────────────────────────────────────────────────

func TestCompileSpec_UnknownOracle(t *testing.T) {
	spec := &scenarioSpec{
		SpecV: 1, ID: "x", Name: "x", Category: "x", Hypothesis: "x", Expected: "x", HoldS: 10,
		Oracle: scenarioOracleRef{Name: "diagnoseFrobnicate"},
	}
	_, err := compileSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("compileSpec error = %v, want a 'not registered' error", err)
	}
}

func TestCompileSpec_NoParamOracleRejectsParams(t *testing.T) {
	spec := &scenarioSpec{
		SpecV: 1, ID: "x", Name: "x", Category: "x", Hypothesis: "x", Expected: "x", HoldS: 10,
		Oracle: scenarioOracleRef{Name: "diagnoseRecovery", Params: json.RawMessage(`{"foo":1}`)},
	}
	_, err := compileSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "takes no params") {
		t.Fatalf("compileSpec error = %v, want 'takes no params'", err)
	}
}

func TestCompileSpec_DiagnoseSurvivalRequiresLabel(t *testing.T) {
	spec := &scenarioSpec{
		SpecV: 1, ID: "x", Name: "x", Category: "x", Hypothesis: "x", Expected: "x", HoldS: 10,
		Constraint: &scenarioConstraint{Type: "exportCap", HoldS: 10, LimitW: 0, Desc: "d"},
		Oracle:     scenarioOracleRef{Name: "diagnoseSurvival"},
	}
	_, err := compileSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "params.label") {
		t.Fatalf("compileSpec error = %v, want a missing params.label error", err)
	}
}

func TestCompileSpec_RequiresConstraintWhenOracleNeedsOne(t *testing.T) {
	spec := &scenarioSpec{
		SpecV: 1, ID: "x", Name: "x", Category: "x", Hypothesis: "x", Expected: "x", HoldS: 10,
		Oracle: scenarioOracleRef{Name: "diagnoseConstraint"}, // requiresConstraint, but no setup/constraint posts one
	}
	_, err := compileSpec(spec)
	if err == nil || !strings.Contains(err.Error(), "needs a constraint") {
		t.Fatalf("compileSpec error = %v, want a missing-constraint error", err)
	}
}

func TestCompileSpec_RecoveryOracleDoesNotRequireConstraint(t *testing.T) {
	spec := &scenarioSpec{
		SpecV: 1, ID: "x", Name: "x", Category: "x", Hypothesis: "x", Expected: "x", HoldS: 10,
		Oracle: scenarioOracleRef{Name: "diagnoseRecovery"},
	}
	if _, err := compileSpec(spec); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── pv_w sentinel ────────────────────────────────────────────────────────────

func TestResolvePVW(t *testing.T) {
	d := &mayhemDriver{pvHighW: 4321}
	highFn, err := resolvePVW(json.RawMessage(`"high"`))
	if err != nil {
		t.Fatalf("resolvePVW(high): %v", err)
	}
	if got := highFn(d); got != 4321 {
		t.Errorf("high sentinel = %v, want d.pvHighW = 4321", got)
	}
	numFn, err := resolvePVW(json.RawMessage(`300`))
	if err != nil {
		t.Fatalf("resolvePVW(300): %v", err)
	}
	if got := numFn(d); got != 300 {
		t.Errorf("numeric pv_w = %v, want 300", got)
	}
	if _, err := resolvePVW(json.RawMessage(`"medium"`)); err == nil {
		t.Error("expected an error for an unrecognised sentinel string")
	}
}

// ── proof #1 (required pilot): export-cap-full-battery ──────────────────────
//
// Loads the actual on-disk pilot spec (qa/scenarios/export-cap-full-battery.json)
// and asserts the compiled scenario issues EXACTLY the same bench calls, with
// the same bodies, as its Go twin (cmd/dashboard/mayhem.go, scenarios(),
// ID "export-cap-full-battery"):
//
//	setup:  battery /inject {SoC_pct:100,Conn:1}; solar /inject {W_W:pvHighW};
//	        meter /inject {LoadW_W:250}; gridsim /admin/control exportCap 0W
//	perTick: solar/meter inject repeats every tick
//	oracle: diagnoseConstraint
func TestCompileSpec_ExportCapFullBattery_MatchesGoTwin(t *testing.T) {
	path := filepath.Join(repoRootFromTest(t), "qa", "scenarios", "export-cap-full-battery.json")
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading pilot spec: %v", err)
	}
	spec, err := decodeSpec(buf)
	if err != nil {
		t.Fatalf("decodeSpec: %v", err)
	}
	sc, err := compileSpec(spec)
	if err != nil {
		t.Fatalf("compileSpec: %v", err)
	}
	if sc.Source != "spec" {
		t.Errorf("Source = %q, want spec", sc.Source)
	}
	if sc.HoldS != 100 {
		t.Errorf("HoldS = %d, want 100 (matches Go twin)", sc.HoldS)
	}

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")

	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "exportCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {Typ:exportCap LimW:0}", cons)
	}

	if call := logs["battery"].find("POST", "/inject"); call == nil {
		t.Error("expected battery POST /inject (SoC 100, Conn 1)")
	} else if call.Body["SoC_pct"] != float64(100) || call.Body["Conn"] != float64(1) {
		t.Errorf("battery inject body = %v, want SoC_pct:100 Conn:1", call.Body)
	}
	if call := logs["solar"].find("POST", "/inject"); call == nil {
		t.Error("expected solar POST /inject (W_W = pvHighW)")
	} else if call.Body["W_W"] != float64(4800) {
		t.Errorf("solar inject body = %v, want W_W:4800 (d.pvHighW)", call.Body)
	}
	if call := logs["meter"].find("POST", "/inject"); call == nil {
		t.Error("expected meter POST /inject (LoadW_W = 250)")
	} else if call.Body["LoadW_W"] != float64(250) {
		t.Errorf("meter inject body = %v, want LoadW_W:250", call.Body)
	}
	if call := logs["gridsim"].find("POST", "/admin/control"); call == nil {
		t.Fatal("expected gridsim POST /admin/control (the exportCap constraint)")
	} else {
		if call.Body["exp_lim_W"] != float64(0) {
			t.Errorf("control body exp_lim_W = %v, want 0", call.Body["exp_lim_W"])
		}
		if call.Body["duration_s"] != float64(120) { // holdS(100) + 20 s pad, per postCapProg
			t.Errorf("control body duration_s = %v, want 120", call.Body["duration_s"])
		}
	}

	// perTick must re-inject the environment every tick (no at_tick gate).
	before := logs["solar"].count("POST", "/inject")
	sc.perTick(d, 7)
	if got := logs["solar"].count("POST", "/inject"); got != before+1 {
		t.Errorf("perTick(7): solar /inject count = %d, want %d", got, before+1)
	}

	// teardown is empty in the spec (matches the Go twin, which has none) —
	// must not panic and must not call anything.
	before = len(logs["gridsim"].calls)
	sc.teardown(d)
	if got := len(logs["gridsim"].calls); got != before {
		t.Errorf("teardown made %d unexpected gridsim calls", got-before)
	}
}

// ── proof #2: grid-disconnect (post_connect + delete_controls) ─────────────
//
// A JSON twin of the Go "grid-disconnect" scenario (mayhem.go, ID
// "grid-disconnect"): battery inject, inject_env, a "connect":false constraint
// (post_connect), diagnoseDisconnect, and a delete_controls(0) teardown
// (re-energize). Proves post_connect + delete_controls + the "connect"
// constraint-sugar path.
const gridDisconnectSpecJSON = `{
  "spec_v": 1,
  "id": "spec-grid-disconnect",
  "name": "Cease-to-energize: grid commands a disconnect",
  "category": "Grid safety (INV-CONNECT)",
  "hypothesis": "test twin of grid-disconnect",
  "expected": "Drive solar output and battery discharge to ~0 within the reaction window.",
  "fix": "orchestrator connect handling",
  "hold_s": 45,
  "setup": [
    {"action": "sim_post", "target": "battery", "path": "/inject", "body": {"SoC_pct": 70, "Conn": 1}},
    {"action": "inject_env", "pv_w": "high", "load_w": 250}
  ],
  "per_tick": [
    {"action": "inject_env", "pv_w": "high", "load_w": 250}
  ],
  "teardown": [
    {"action": "delete_controls", "program": 0}
  ],
  "constraint": {"type": "connect", "connect": false, "hold_s": 45, "desc": "mayhem: cease-to-energize disconnect"},
  "oracle": {"name": "diagnoseDisconnect"}
}`

func TestCompileSpec_GridDisconnect_MatchesGoTwin(t *testing.T) {
	spec, err := decodeSpec([]byte(gridDisconnectSpecJSON))
	if err != nil {
		t.Fatalf("decodeSpec: %v", err)
	}
	sc, err := compileSpec(spec)
	if err != nil {
		t.Fatalf("compileSpec: %v", err)
	}

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")

	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "connect" {
		t.Errorf("constraint.Typ = %q, want connect", cons.Typ)
	}

	call := logs["gridsim"].find("POST", "/admin/control")
	if call == nil {
		t.Fatal("expected gridsim POST /admin/control (the disconnect constraint)")
	}
	if call.Body["connect"] != false {
		t.Errorf("control body connect = %v, want false", call.Body["connect"])
	}

	sc.teardown(d)
	del := logs["gridsim"].find("DELETE", "/admin/control")
	if del == nil {
		t.Fatal("expected gridsim DELETE /admin/control at teardown (re-energize)")
	}
	if got := del.Body["program"]; got != float64(0) {
		t.Errorf("delete_controls program = %v, want 0", got)
	}
}

// ── proof #3: wan-outage-hold (gridsim_admin at_tick + parameterized oracle) ──
//
// A JSON twin of the Go "wan-outage-hold" scenario: an exportCap constraint,
// inject_env every tick, and a gridsim_admin outage fired ONCE at tick 15 —
// proving at_tick gating and the gridsim_admin verb — judged by the
// parameterized diagnoseSurvival("the WAN outage") oracle.
const wanOutageHoldSpecJSON = `{
  "spec_v": 1,
  "id": "spec-wan-outage-hold",
  "name": "Utility server dies mid-control",
  "category": "Northbound resilience (INV-EXPORT survivability)",
  "hypothesis": "test twin of wan-outage-hold",
  "expected": "Keep enforcing the last-known-good control through the outage.",
  "hold_s": 90,
  "setup": [
    {"action": "sim_post", "target": "battery", "path": "/inject", "body": {"SoC_pct": 100, "Conn": 1}},
    {"action": "inject_env", "pv_w": "high", "load_w": 250}
  ],
  "per_tick": [
    {"action": "inject_env", "pv_w": "high", "load_w": 250},
    {"action": "gridsim_admin", "at_tick": 15, "path": "/admin/outage", "body": {"mode": "down", "duration_s": 45, "hang_s": 0}}
  ],
  "teardown": [
    {"action": "gridsim_admin", "path": "/admin/outage", "body": {"clear": true}}
  ],
  "constraint": {"type": "exportCap", "limit_w": 0, "hold_s": 90, "desc": "mayhem: cap through a WAN outage"},
  "oracle": {"name": "diagnoseSurvival", "params": {"label": "the WAN outage"}}
}`

func TestCompileSpec_WanOutageHold_MatchesGoTwin(t *testing.T) {
	spec, err := decodeSpec([]byte(wanOutageHoldSpecJSON))
	if err != nil {
		t.Fatalf("decodeSpec: %v", err)
	}
	sc, err := compileSpec(spec)
	if err != nil {
		t.Fatalf("compileSpec: %v", err)
	}

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	if _, err := sc.setup(d); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Ticks before 15 must not fire the outage.
	for i := 0; i < 15; i++ {
		sc.perTick(d, i)
	}
	if got := logs["gridsim"].count("POST", "/admin/outage"); got != 0 {
		t.Fatalf("outage fired before tick 15 (%d calls)", got)
	}
	sc.perTick(d, 15)
	call := logs["gridsim"].find("POST", "/admin/outage")
	if call == nil {
		t.Fatal("expected gridsim POST /admin/outage exactly at tick 15")
	}
	if call.Body["mode"] != "down" || call.Body["duration_s"] != float64(45) {
		t.Errorf("outage body = %v, want mode:down duration_s:45", call.Body)
	}
	// A later tick must not refire it (at_tick means exactly once).
	sc.perTick(d, 16)
	if got := logs["gridsim"].count("POST", "/admin/outage"); got != 1 {
		t.Errorf("outage fired %d times across ticks 0-16, want exactly 1 (only at tick 15)", got)
	}

	sc.teardown(d)
	clearCall := logs["gridsim"].find("POST", "/admin/outage")
	_ = clearCall // find() returns the first match; use count to confirm a second POST landed
	if got := logs["gridsim"].count("POST", "/admin/outage"); got != 2 {
		t.Errorf("expected teardown's clear:true outage POST as a second call, got %d total", got)
	}

	// The oracle must be the parameterized diagnoseSurvival, not the bare
	// diagnoseMalform it wraps — evidenced by the label substitution.
	f := sc.evaluate(sc, &activeConstraint{Typ: "exportCap"}, nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Errorf("evaluate with no samples: verdict = %q, want INCONCLUSIVE", f.Verdict)
	}
}

// ── suppress_default auto-restore ordering ──────────────────────────────────

const suppressDefaultSpecJSON = `{
  "spec_v": 1,
  "id": "spec-suppress-default-order",
  "name": "suppress_default ordering probe",
  "category": "test",
  "hypothesis": "test",
  "expected": "test",
  "hold_s": 10,
  "setup": [
    {"action": "suppress_default"},
    {"action": "inject_env", "pv_w": 100, "load_w": 50}
  ],
  "teardown": [
    {"action": "delete_controls", "program": 0}
  ],
  "oracle": {"name": "diagnoseRecovery"}
}`

func TestCompileSpec_SuppressDefault_RestoresAfterExplicitTeardown(t *testing.T) {
	spec, err := decodeSpec([]byte(suppressDefaultSpecJSON))
	if err != nil {
		t.Fatalf("decodeSpec: %v", err)
	}
	sc, err := compileSpec(spec)
	if err != nil {
		t.Fatalf("compileSpec: %v", err)
	}
	d, logs := newTestDriver(t, "solar", "meter", "gridsim")
	if _, err := sc.setup(d); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if logs["gridsim"].find("GET", "/admin/default") == nil {
		t.Fatal("expected suppress_default's GET /admin/default during setup")
	}
	// setup ALSO immediately POSTs /admin/default{clear:true} (suppressDefault
	// itself, not the restore) — only inspect calls made from teardown onward.
	beforeTeardown := len(logs["gridsim"].calls)
	sc.teardown(d)
	posts := logs["gridsim"].calls[beforeTeardown:]
	var order []string
	for _, c := range posts {
		if c.Method == "DELETE" || (c.Method == "POST" && c.Path == "/admin/default") {
			order = append(order, c.Method+" "+c.Path)
		}
	}
	if len(order) != 2 || order[0] != "DELETE /admin/control" || order[1] != "POST /admin/default" {
		t.Errorf("teardown order = %v, want [DELETE /admin/control, POST /admin/default] (restore last)", order)
	}
}

// ── post_control (generic escape hatch) ─────────────────────────────────────

func TestCompileConstraintAction_PostControl(t *testing.T) {
	a := scenarioAction{
		Action: actPostControl, Typ: "importCap", LimW: 1500,
		Body: map[string]any{"program": 0, "imp_lim_W": 1500, "duration_s": 30, "activate": true},
	}
	run, err := compileConstraintAction(a)
	if err != nil {
		t.Fatalf("compileConstraintAction: %v", err)
	}
	d, logs := newTestDriver(t, "gridsim")
	cons, err := run(d)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if cons.Typ != "importCap" || cons.LimW != 1500 || cons.MRID != "test-mrid" {
		t.Errorf("constraint = %+v, want {importCap 1500 test-mrid}", cons)
	}
	if logs["gridsim"].find("POST", "/admin/control") == nil {
		t.Error("expected gridsim POST /admin/control")
	}
}

// ── loadSpecScenarios: collisions never take the run down ───────────────────

func TestLoadSpecScenarios_CollisionIsLoggedNotFatal(t *testing.T) {
	dir := t.TempDir()
	spec := strings.Replace(gridDisconnectSpecJSON, `"id": "spec-grid-disconnect"`, `"id": "already-taken"`, 1)
	writeSpecFile(t, dir, "colliding.json", spec)
	writeSpecFile(t, dir, "clean.json", strings.Replace(wanOutageHoldSpecJSON, `"id": "spec-wan-outage-hold"`, `"id": "totally-new"`, 1))

	d := newMayhemDriver(map[string]string{})
	out, errs := d.loadSpecScenarios(dir, map[string]bool{"already-taken": true})
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly 1 collision error", errs)
	}
	if !strings.Contains(errs[0].Error(), "already-taken") {
		t.Errorf("error %v does not name the colliding id", errs[0])
	}
	if len(out) != 1 || out[0].ID != "totally-new" {
		t.Fatalf("out = %v, want exactly the non-colliding scenario", scenarioIDs(out))
	}
}

func TestLoadSpecScenarios_BadFileDoesNotBlockOthers(t *testing.T) {
	dir := t.TempDir()
	writeSpecFile(t, dir, "broken.json", `{not valid json`)
	writeSpecFile(t, dir, "clean.json", strings.Replace(wanOutageHoldSpecJSON, `"id": "spec-wan-outage-hold"`, `"id": "still-loads"`, 1))

	d := newMayhemDriver(map[string]string{})
	out, errs := d.loadSpecScenarios(dir, map[string]bool{})
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly 1 decode error", errs)
	}
	if len(out) != 1 || out[0].ID != "still-loads" {
		t.Fatalf("out = %v, want the clean spec despite the broken sibling", scenarioIDs(out))
	}
}

func TestLoadSpecScenarios_EmptyDirDisablesSpecs(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	out, errs := d.loadSpecScenarios("", map[string]bool{})
	if out != nil || errs != nil {
		t.Errorf("empty scenarioDir should be a pure no-op, got out=%v errs=%v", out, errs)
	}
}

func TestLoadSpecScenarios_MissingDirIsNotAnError(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	out, errs := d.loadSpecScenarios(filepath.Join(t.TempDir(), "does-not-exist"), map[string]bool{})
	if out != nil || errs != nil {
		t.Errorf("missing scenario dir should not error (not-yet-created authoring dir), got out=%v errs=%v", out, errs)
	}
}

func writeSpecFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func scenarioIDs(scs []*mayScenario) []string {
	ids := make([]string, len(scs))
	for i, s := range scs {
		ids[i] = s.ID
	}
	return ids
}

// ── scenarios() end-to-end: source tag + Go set is unaffected ──────────────

// TestScenarios_SpecDirEmpty_GoSetUnaffected pins the acceptance criterion
// "all Go scenarios unaffected" for the default (scenarioDir=="") case that
// every existing test driver uses: scenarios() must return exactly the Go
// set, nothing appended, nothing renumbered.
func TestScenarios_SpecDirEmpty_GoSetUnaffected(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	scs := d.scenarios()
	for _, s := range scs {
		if s.Source == "spec" {
			t.Fatalf("scenario %q has Source=spec with an empty scenarioDir", s.ID)
		}
	}
}

// TestScenarios_LoadsNonCollidingSpecAndTagsSource proves the plumbing
// end-to-end: a spec dropped in -scenario-dir with a non-colliding ID shows
// up in scenarios() (and so in /api/qa/scenarios) tagged source="spec", while
// the pilot's own ID (which DOES collide with its still-present Go twin)
// is rejected loudly and excluded — exactly the "specs load per run, colliding
// spec never shadows silently" behaviour the task requires.
func TestScenarios_LoadsNonCollidingSpecAndTagsSource(t *testing.T) {
	dir := t.TempDir()
	writeSpecFile(t, dir, "colliding-pilot.json", strings.Replace(
		mustReadPilot(t), `"id": "export-cap-full-battery"`, `"id": "export-cap-full-battery"`, 1)) // same ID as the Go twin, on purpose
	writeSpecFile(t, dir, "new-one.json", strings.Replace(wanOutageHoldSpecJSON, `"id": "spec-wan-outage-hold"`, `"id": "brand-new-spec-scenario"`, 1))

	d := newMayhemDriver(map[string]string{})
	d.scenarioDir = dir
	scs := d.scenarios()

	var goTwinCount, specCount int
	var sawNew bool
	for _, s := range scs {
		if s.ID == "export-cap-full-battery" {
			goTwinCount++
			if s.Source == "spec" {
				t.Error("the colliding spec must not have won over the Go twin")
			}
		}
		if s.ID == "brand-new-spec-scenario" {
			sawNew = true
			if s.Source != "spec" {
				t.Errorf("Source = %q, want spec", s.Source)
			}
			specCount++
		}
	}
	if goTwinCount != 1 {
		t.Errorf("export-cap-full-battery appeared %d times, want exactly 1 (the Go twin; the colliding spec must be excluded)", goTwinCount)
	}
	if !sawNew || specCount != 1 {
		t.Errorf("expected exactly one brand-new-spec-scenario tagged source=spec, sawNew=%v count=%d", sawNew, specCount)
	}
}

func mustReadPilot(t *testing.T) string {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join(repoRootFromTest(t), "qa", "scenarios", "export-cap-full-battery.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

// TestHandleScenarios_SourceTag exercises the actual HTTP handler (not just
// scenarios()) so a regression in the JSON field name breaks a test, not just
// a manual curl.
func TestHandleScenarios_SourceTag(t *testing.T) {
	dir := t.TempDir()
	writeSpecFile(t, dir, "new-one.json", strings.Replace(wanOutageHoldSpecJSON, `"id": "spec-wan-outage-hold"`, `"id": "http-tagged-spec"`, 1))
	d := newMayhemDriver(map[string]string{})
	d.scenarioDir = dir

	rr := httptest.NewRecorder()
	d.handleScenarios(rr, httptest.NewRequest(http.MethodGet, "/api/qa/scenarios", nil))
	var body struct {
		Scenarios []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	var sawGo, sawSpec bool
	for _, s := range body.Scenarios {
		if s.ID == "http-tagged-spec" {
			sawSpec = s.Source == "spec"
		}
		if s.ID == "export-cap-full-battery" {
			sawGo = s.Source == "go"
		}
	}
	if !sawGo {
		t.Error(`expected the Go "export-cap-full-battery" scenario tagged source="go"`)
	}
	if !sawSpec {
		t.Error(`expected "http-tagged-spec" tagged source="spec"`)
	}
}

// ── compile-all: every shipped spec must load cleanly ───────────────────────

// TestCompileAllScenarioSpecs walks qa/scenarios/*.json and compiles each —
// the "no dead/broken specs ship" gate (task step 8). Pure compile, no
// network: proves decode+validate+compile succeed independent of whether the
// bench is reachable.
func TestCompileAllScenarioSpecs(t *testing.T) {
	dir := filepath.Join(repoRootFromTest(t), "qa", "scenarios")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("qa/scenarios/ has no *.json specs — the pilot should be there")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			buf, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			spec, err := decodeSpec(buf)
			if err != nil {
				t.Fatalf("decodeSpec: %v", err)
			}
			if _, err := compileSpec(spec); err != nil {
				t.Fatalf("compileSpec: %v", err)
			}
		})
	}
}
