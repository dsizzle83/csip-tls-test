package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── pure parsers / builders ──────────────────────────────────────────────────

func TestParseBoolFieldLine(t *testing.T) {
	cases := []struct {
		line    string
		want    bool
		wantErr bool
	}{
		{`"enforce_aus_limits": true`, true, false},
		{`"enforce_aus_limits":false`, false, false},
		{`"enforce_aus_limits"   :   true`, true, false},
		{"", false, true},
		{`"enforce_aus_limits": maybe`, false, true},
	}
	for _, c := range cases {
		got, err := parseBoolFieldLine(c.line)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseBoolFieldLine(%q): expected an error, got none", c.line)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseBoolFieldLine(%q): unexpected error: %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseBoolFieldLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestAdvCurveSetContentHash_Deterministic(t *testing.T) {
	pts := advCurveTestPoints()
	h1 := advCurveSetContentHash("volt_var", advCurveTypeTest, advCurveXMult, advCurveYMult, 0, pts)
	h2 := advCurveSetContentHash("volt_var", advCurveTypeTest, advCurveXMult, advCurveYMult, 0, pts)
	if h1 != h2 {
		t.Fatalf("advCurveSetContentHash is not deterministic: %s != %s", h1, h2)
	}
	if h1 == "" {
		t.Fatal("advCurveSetContentHash returned an empty hash for a non-empty point set")
	}
}

func TestAdvCurveSetContentHash_SensitiveToContent(t *testing.T) {
	base := advCurveSetContentHash("volt_var", 1, 0, 0, 0, [][2]int32{{100, 50}, {200, -50}})
	cases := [][][2]int32{
		{{101, 50}, {200, -50}},           // x moved
		{{100, 51}, {200, -50}},           // y moved
		{{100, 50}, {200, -50}, {300, 0}}, // extra point
	}
	for _, pts := range cases {
		if got := advCurveSetContentHash("volt_var", 1, 0, 0, 0, pts); got == base {
			t.Errorf("advCurveSetContentHash(%v) unexpectedly equals the base hash", pts)
		}
	}
	if got := advCurveSetContentHash("watt_var", 1, 0, 0, 0, [][2]int32{{100, 50}, {200, -50}}); got == base {
		t.Error("advCurveSetContentHash: changing mode did not change the hash")
	}
	if got := advCurveSetContentHash("volt_var", 2, 0, 0, 0, [][2]int32{{100, 50}, {200, -50}}); got == base {
		t.Error("advCurveSetContentHash: changing curveType did not change the hash")
	}
}

// wireDesiredAdvanced is a minimal local mirror of bus.DesiredAdvanced's wire
// shape, used only to prove the hand-built JSON payloads below actually
// unmarshal into what WP-10's reconciler expects — protects against a typo in
// the Sprintf format strings that would otherwise only surface on a live bench.
type wireDesiredAdvanced struct {
	V            int    `json:"v"`
	DeviceClass  string `json:"device_class"`
	DeviceID     string `json:"device_id"`
	ReactiveMode *struct {
		Kind    string `json:"kind"`
		FixedPF *struct {
			PF          float64 `json:"pf"`
			OverExcited bool    `json:"over_excited"`
		} `json:"fixed_pf"`
		Curve *struct {
			CurveType uint16 `json:"curve_type"`
			XMult     int8   `json:"x_mult"`
			YMult     int8   `json:"y_mult"`
			Points    []struct {
				X int32 `json:"x"`
				Y int32 `json:"y"`
			} `json:"points"`
			Hash string `json:"hash"`
		} `json:"curve"`
	} `json:"reactive_mode"`
	Source   string `json:"source"`
	MRID     string `json:"mrid"`
	IssuedAt int64  `json:"issued_at"`
	Seq      uint64 `json:"seq"`
}

func TestDesiredAdvVoltVarPayload_Valid(t *testing.T) {
	payload := desiredAdvVoltVarPayload("inverter-0", "mrid-1", 1234)
	var doc wireDesiredAdvanced
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatalf("desiredAdvVoltVarPayload produced invalid JSON: %v\npayload: %s", err, payload)
	}
	if doc.V != 1 {
		t.Errorf("v = %d, want 1", doc.V)
	}
	if doc.DeviceClass != "solar" || doc.DeviceID != "inverter-0" {
		t.Errorf("device_class/device_id = %q/%q, want solar/inverter-0", doc.DeviceClass, doc.DeviceID)
	}
	if doc.ReactiveMode == nil || doc.ReactiveMode.Kind != "volt_var" {
		t.Fatalf("reactive_mode.kind = %+v, want volt_var", doc.ReactiveMode)
	}
	c := doc.ReactiveMode.Curve
	if c == nil {
		t.Fatal("reactive_mode.curve is nil")
	}
	if len(c.Points) != 2 || c.Points[0].X != 100 || c.Points[0].Y != 50 || c.Points[1].X != 200 || c.Points[1].Y != -50 {
		t.Errorf("curve.points = %+v, want [{100 50} {200 -50}]", c.Points)
	}
	if c.Hash == "" {
		t.Error("curve.hash is empty")
	}
	if doc.Source != "csip-event" || doc.MRID != "mrid-1" || doc.IssuedAt != 1234 {
		t.Errorf("source/mrid/issued_at = %q/%q/%d", doc.Source, doc.MRID, doc.IssuedAt)
	}
	// Cross-check the hash matches what a re-derivation from the same points
	// would produce — the property WP-10's readback verification depends on.
	wantHash := advCurveSetContentHash("volt_var", advCurveTypeTest, advCurveXMult, advCurveYMult, 0, advCurveTestPoints())
	if c.Hash != wantHash {
		t.Errorf("curve.hash = %q, want %q", c.Hash, wantHash)
	}
}

func TestDesiredAdvFixedPFPayload_Valid(t *testing.T) {
	payload := desiredAdvFixedPFPayload("inverter-0", "mrid-2", 0.9, true, 5678)
	var doc wireDesiredAdvanced
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatalf("desiredAdvFixedPFPayload produced invalid JSON: %v\npayload: %s", err, payload)
	}
	if doc.ReactiveMode == nil || doc.ReactiveMode.Kind != "fixed_pf" {
		t.Fatalf("reactive_mode.kind = %+v, want fixed_pf", doc.ReactiveMode)
	}
	fp := doc.ReactiveMode.FixedPF
	if fp == nil || fp.PF != 0.9 || !fp.OverExcited {
		t.Errorf("fixed_pf = %+v, want {0.9 true}", fp)
	}
}

func TestDesiredAdvReleasePayload_Valid(t *testing.T) {
	payload := desiredAdvReleasePayload("inverter-0", 999)
	var doc wireDesiredAdvanced
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatalf("desiredAdvReleasePayload produced invalid JSON: %v\npayload: %s", err, payload)
	}
	if doc.ReactiveMode != nil {
		t.Errorf("reactive_mode = %+v, want nil (release)", doc.ReactiveMode)
	}
	if doc.Source != "none" {
		t.Errorf("source = %q, want none", doc.Source)
	}
}

func TestAdvWriteSurfaceEqual(t *testing.T) {
	a := advSolarState{}
	a.Curves = []struct {
		Model     uint16       `json:"model"`
		AdoptRslt int          `json:"adopt_rslt"`
		ReadOnly  bool         `json:"read_only"`
		Points    [][2]float64 `json:"points"`
	}{{Model: 705, Points: [][2]float64{{100, 5}, {200, -5}}}}
	b := a
	if !advWriteSurfaceEqual(a, b) {
		t.Fatal("advWriteSurfaceEqual: identical snapshots reported unequal")
	}
	b.Curves = append([]struct {
		Model     uint16       `json:"model"`
		AdoptRslt int          `json:"adopt_rslt"`
		ReadOnly  bool         `json:"read_only"`
		Points    [][2]float64 `json:"points"`
	}(nil), b.Curves...)
	b.Curves[0].Points = [][2]float64{{100, 50}, {200, -50}} // simulates a landed write
	if advWriteSurfaceEqual(a, b) {
		t.Fatal("advWriteSurfaceEqual: a changed curve point was not detected")
	}
	// Meas701-only drift (animation noise) must NOT be flagged.
	c := a
	c.Meas701.WW = a.Meas701.WW + 500
	c.Meas701.PF = 0.5
	if !advWriteSurfaceEqual(a, c) {
		t.Fatal("advWriteSurfaceEqual: a Meas701-only change was incorrectly flagged as a write")
	}
}

// ── diagnoseAdvShadowNoWrites ────────────────────────────────────────────────

func TestDiagnoseAdvShadowNoWrites_Pass(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	before := advSolarState{}
	after := before
	f := diagnoseAdvShadowNoWrites(scFor("adv-shadow-no-writes"), s, true, before, true, after, true, 0, 3, 0, 0, 0, 0)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAdvShadowNoWrites_FailsOnRegisterChange(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	before := advSolarState{}
	after := before
	after.FixedPF.Ena = true
	after.FixedPF.PF = 0.9
	f := diagnoseAdvShadowNoWrites(scFor("adv-shadow-no-writes"), s, true, before, true, after, true, 0, 3, 0, 0, 0, 0)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAdvShadowNoWrites_FailsOnRealWriteCounter(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	before := advSolarState{}
	after := before
	f := diagnoseAdvShadowNoWrites(scFor("adv-shadow-no-writes"), s, true, before, true, after, true, 0, 3, 0, 1, 0, 0)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL when lexa_mb_adv_writes_total advanced (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAdvShadowNoWrites_DegradedOnNoWouldWrite(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {})
	before := advSolarState{}
	after := before
	f := diagnoseAdvShadowNoWrites(scFor("adv-shadow-no-writes"), s, true, before, true, after, true, 5, 5, 0, 0, 0, 0)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED when would_writes never advanced (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAdvShadowNoWrites_Inconclusive_NoSamples(t *testing.T) {
	f := diagnoseAdvShadowNoWrites(scFor("adv-shadow-no-writes"), nil, true, advSolarState{}, true, advSolarState{}, true, 0, 1, 0, 0, 0, 0)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseCurveAdoptDivergence ─────────────────────────────────────────────

func TestDiagnoseCurveAdoptDivergence_PassOnDiverged(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "volt_var", AdoptState: "diverged"}
	f := diagnoseCurveAdoptDivergence(scFor("curve-adopt-readback-divergence"), s, "volt_var", true, rep, nil)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseCurveAdoptDivergence_FailOnAdopted(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "volt_var", AdoptState: "adopted", CurveHash: "deadbeef"}
	f := diagnoseCurveAdoptDivergence(scFor("curve-adopt-readback-divergence"), s, "volt_var", true, rep, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL when the reconciler trusted the handshake (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseCurveAdoptDivergence_InconclusiveOnMissingReport(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	f := diagnoseCurveAdoptDivergence(scFor("curve-adopt-readback-divergence"), s, "volt_var", false, advReportMsg{}, errFakeSSH)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseCurveAdoptDivergence_InconclusiveOnWrongAxis(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "fixed_pf", AdoptState: "adopted"}
	f := diagnoseCurveAdoptDivergence(scFor("curve-adopt-readback-divergence"), s, "volt_var", true, rep, nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE for a mismatched axis (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseCurveAdoptDivergence_DegradedOnPending(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "volt_var", AdoptState: "pending"}
	f := diagnoseCurveAdoptDivergence(scFor("curve-adopt-readback-divergence"), s, "volt_var", true, rep, nil)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseCurveAdoptDivergence_InconclusiveOnUnsupported(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "volt_var", AdoptState: "unsupported"}
	f := diagnoseCurveAdoptDivergence(scFor("curve-adopt-readback-divergence"), s, "volt_var", true, rep, nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE (%s)", f.Verdict, f.Headline)
	}
}

// ── diagnosePFVarMeasuredConvergence ─────────────────────────────────────────

func TestDiagnosePFVarMeasuredConvergence_PassOnDiverged(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "fixed_pf", AdoptState: "diverged"}
	f := diagnosePFVarMeasuredConvergence(scFor("pf-var-measured-convergence"), s, 0.9, true, rep, nil, true, 2, 3, true, 0.6, 0.61)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnosePFVarMeasuredConvergence_FailOnAdopted(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "fixed_pf", AdoptState: "adopted"}
	f := diagnosePFVarMeasuredConvergence(scFor("pf-var-measured-convergence"), s, 0.9, true, rep, nil, true, 0, 0, true, 0.6, 0.6)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL when the reconciler trusted the ACK over measurement (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnosePFVarMeasuredConvergence_DegradedOnInconsistentMetric(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {})
	rep := advReportMsg{Axis: "fixed_pf", AdoptState: "diverged"}
	// Report says diverged but the divergence counter never moved — flagged,
	// not silently trusted.
	f := diagnosePFVarMeasuredConvergence(scFor("pf-var-measured-convergence"), s, 0.9, true, rep, nil, true, 5, 5, true, 0.6, 0.6)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED on inconsistent report/metric evidence (%s)", f.Verdict, f.Headline)
	}
}

// ── diagnoseAusGenCap / diagnoseAusLoadCap ───────────────────────────────────

func ausConsGen() *activeConstraint {
	return &activeConstraint{Typ: "genLimitAus", LimW: ausGenCapLimW, MRID: "M-aus-gen"}
}

func ausConsLoad() *activeConstraint {
	return &activeConstraint{Typ: "loadLimitAus", LimW: ausLoadCapLimW, MRID: "M-aus-load"}
}

func TestDiagnoseAusGenCap_Pass_NeverBreached(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {
		smp.SolarW, smp.SolarPossibleW = 1500, 1500
		smp.BatterySimOK, smp.BatterySimW = true, 0
		smp.Decisions = []string{"[csip-aus/gen-limit] gross generation cap 2000W: ceiling 2000W solar + 0W committed battery discharge (held continuously)→ceiling 1 inverters to ≤2000W total"}
	})
	f := diagnoseAusGenCap(scFor("aus-gen-cap"), ausConsGen(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAusGenCap_Fail_SustainedBreach(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {
		smp.SolarW, smp.SolarPossibleW = 5000, 5000 // well over the 2000W cap, the whole window
		smp.BatterySimOK, smp.BatterySimW = true, 0
		smp.Decisions = []string{"[csip-aus/gen-limit] gross generation cap 2000W: ceiling 2000W solar + 0W committed battery discharge (held continuously)→ceiling 1 inverters to ≤2000W total"}
	})
	f := diagnoseAusGenCap(scFor("aus-gen-cap"), ausConsGen(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAusGenCap_Degraded_CannotComplyReported(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {
		smp.SolarW, smp.SolarPossibleW = 5000, 5000
		smp.BatterySimOK, smp.BatterySimW = true, 0
		smp.Decisions = []string{"[csip-aus/gen-limit] gross generation cap 2000W…"}
		smp.CannotComply = true
	})
	f := diagnoseAusGenCap(scFor("aus-gen-cap"), ausConsGen(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED when CannotComply was reported (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAusGenCap_Pass_SettlesWithinDeadline(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {
		smp.Decisions = []string{"[csip-aus/gen-limit] …"}
		smp.BatterySimOK, smp.BatterySimW = true, 0
		if i < 10 {
			smp.SolarW, smp.SolarPossibleW = 5000, 5000 // breach in the opening settling window
		} else {
			smp.SolarW, smp.SolarPossibleW = 1500, 1500 // converged and held
		}
	})
	f := diagnoseAusGenCap(scFor("aus-gen-cap"), ausConsGen(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS for a settled-then-clean tail (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAusGenCap_Inconclusive_RuleNeverEngaged(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {
		smp.SolarW, smp.SolarPossibleW = 5000, 5000
		// No "[csip-aus/gen-limit]" decision ever logged.
	})
	f := diagnoseAusGenCap(scFor("aus-gen-cap"), ausConsGen(), s)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE when the AUS rule never logged a decision (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAusLoadCap_Pass_NeverBreached(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {
		smp.SolarW, smp.SolarPossibleW = 300, 300
		smp.RealGridW = 1000
		smp.BatterySimOK, smp.BatterySimW = true, 0
		smp.Decisions = []string{"[csip-aus/load-limit] gross load cap 3000W…"}
	})
	f := diagnoseAusLoadCap(scFor("aus-load-cap"), ausConsLoad(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseAusLoadCap_Fail_SustainedBreach(t *testing.T) {
	s := mkSamples(85, func(i int, smp *maySample) {
		smp.SolarW, smp.SolarPossibleW = 300, 300
		smp.RealGridW = 6000 // gross load ~6300W, well over the 3000W cap
		smp.BatterySimOK, smp.BatterySimW = true, 0
		smp.Decisions = []string{"[csip-aus/load-limit] gross load cap 3000W…"}
	})
	f := diagnoseAusLoadCap(scFor("aus-load-cap"), ausConsLoad(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
}

func TestAusGrossGenW_BlindWithoutSolar(t *testing.T) {
	s := maySample{SolarOK: false}
	if _, ok := ausGrossGenW(s); ok {
		t.Fatal("ausGrossGenW: expected ok=false with SolarOK=false")
	}
}

func TestAusGrossLoadW_BlindWithoutMeter(t *testing.T) {
	s := maySample{SolarOK: true, GridOK: false}
	if _, ok := ausGrossLoadW(s); ok {
		t.Fatal("ausGrossLoadW: expected ok=false with GridOK=false")
	}
}

func TestAppendShadowDivergenceNote_Unavailable(t *testing.T) {
	f := mayFinding{}
	appendShadowDivergenceNote(&f, false, 0, 0)
	if len(f.Diagnosis) != 1 || !strings.Contains(f.Diagnosis[0], "unavailable") {
		t.Fatalf("appendShadowDivergenceNote diagnosis = %v, want an 'unavailable' note", f.Diagnosis)
	}
}

func TestAppendShadowDivergenceNote_Informational(t *testing.T) {
	f := mayFinding{Verdict: "PASS"}
	appendShadowDivergenceNote(&f, true, 2, 5)
	if f.Verdict != "PASS" {
		t.Fatalf("appendShadowDivergenceNote must never change the verdict, got %s", f.Verdict)
	}
	if len(f.Diagnosis) != 1 || !strings.Contains(f.Diagnosis[0], "Informational only") {
		t.Fatalf("appendShadowDivergenceNote diagnosis = %v, want an informational-only note", f.Diagnosis)
	}
}

// errFakeSSH is a stand-in error for tests exercising the "SSH read failed"
// path without a real network call.
var errFakeSSH = &fakeSSHErr{}

type fakeSSHErr struct{}

func (*fakeSSHErr) Error() string { return "fake ssh failure" }
