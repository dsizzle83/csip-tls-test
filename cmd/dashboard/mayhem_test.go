package main

import "testing"

// mkSamples builds a flat timeline (1 s cadence) and applies a mutator so each
// test can describe just the signal it cares about.
func mkSamples(n int, mut func(i int, s *maySample)) []maySample {
	out := make([]maySample, n)
	for i := range out {
		s := maySample{
			T:              float64(i),
			GridOK:         true,
			SolarOK:        true,
			HubReachable:   true,
			SolarPossibleW: 6000,
			SolarW:         6000, // no curtailment unless a test sets it
		}
		mut(i, &s)
		out[i] = s
	}
	return out
}

func exportCons() *activeConstraint {
	return &activeConstraint{Typ: "exportCap", LimW: 0, MRID: "M-abc123def456"}
}

func scFor(id string) *mayScenario {
	return &mayScenario{ID: id, Name: id, Category: "test", Hypothesis: "h", Expected: "e"}
}

func TestDiagnoseConstraint_Pass(t *testing.T) {
	// Net grid at 0 → no export breach.
	s := mkSamples(10, func(i int, s *maySample) { s.RealGridW = 0; s.HubGridW = 0 })
	f := diagnoseConstraint(scFor("p"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseConstraint_NotAdopted(t *testing.T) {
	// Big export, hub never shows the control → adoption failure.
	s := mkSamples(10, func(i int, s *maySample) { s.RealGridW = -2000; s.HubGridW = -2000 })
	f := diagnoseConstraint(scFor("na"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if f.Metrics.HubAdopted {
		t.Error("HubAdopted should be false")
	}
	if f.Metrics.BreachSeconds <= 0 {
		t.Errorf("BreachSeconds = %v, want > 0", f.Metrics.BreachSeconds)
	}
	assertDiag(t, f, "never adopted")
}

func TestDiagnoseConstraint_AdoptedNoReaction(t *testing.T) {
	s := mkSamples(10, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = -2000, -2000
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		// SolarW == possible → no curtailment commanded.
	})
	f := diagnoseConstraint(scFor("anr"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !f.Metrics.HubAdopted || f.Metrics.HubReacted {
		t.Errorf("want adopted && !reacted, got adopted=%v reacted=%v", f.Metrics.HubAdopted, f.Metrics.HubReacted)
	}
	assertDiag(t, f, "no effective correction")
}

func TestDiagnoseConstraint_CannotComplyOutranksNoReaction(t *testing.T) {
	// Battery-empty import cap: no correction is physically possible (reacted
	// false), but the hub posted CannotComply. Admitting the limit must win over
	// the "adopted but didn't react" FAIL branch.
	s := mkSamples(10, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = -2000, -2000
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		// SolarW == possible → reacted is false.
		s.CannotComply = true
	})
	f := diagnoseConstraint(scFor("ccnr"), exportCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (CannotComply must outrank !reacted)", f.Verdict)
	}
	if f.Metrics.HubReacted {
		t.Error("precondition: HubReacted should be false in this case")
	}
}

func TestDiagnoseConstraint_CannotComplyIsDegraded(t *testing.T) {
	s := mkSamples(10, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = -2000, -2000
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.SolarW = 500 // curtailment commanded (possible 6000)
		s.CannotComply = true
	})
	f := diagnoseConstraint(scFor("cc"), exportCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
	if !f.Metrics.ReportedCannot {
		t.Error("ReportedCannot should be true")
	}
}

func TestDiagnoseConstraint_ClosedLoopGap(t *testing.T) {
	// Adopted + reacted + NOT cannot-comply + not blind → the dangerous case.
	s := mkSamples(10, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = -2000, -2000
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.SolarW = 500
	})
	f := diagnoseConstraint(scFor("cl"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "did not converge")
}

func TestDiagnoseConstraint_GridDivergenceIsNotBlind(t *testing.T) {
	// The hub's relayed display grid lagging the live meter is NOT blindness: the
	// optimizer sees the same relayed value and converges. A breach with adopted
	// control but no reaction is still a FAIL — but never a constraint-path BLIND
	// (genuine sensor-blindness is judged by diagnoseStale, not grid divergence).
	s := mkSamples(10, func(i int, s *maySample) {
		s.RealGridW = -2000
		s.HubGridW = 0 // hub display lags by 2000 W (relay latency)
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
	})
	f := diagnoseConstraint(scFor("div"), exportCons(), s)
	if f.Verdict == "BLIND" {
		t.Fatalf("grid divergence must not produce a BLIND verdict, got %s", f.Verdict)
	}
	if f.Metrics.HubBlind {
		t.Error("HubBlind must not be set from grid divergence in the constraint path")
	}
	if f.Verdict != "FAIL" {
		t.Errorf("verdict = %s, want FAIL (adopted but no reaction)", f.Verdict)
	}
}

func TestDiagnoseConstraint_Inconclusive(t *testing.T) {
	s := mkSamples(10, func(i int, s *maySample) {
		s.GridOK = false // meter unreachable everywhere
		s.RealGridW = 0
	})
	f := diagnoseConstraint(scFor("inc"), exportCons(), s)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

func TestDiagnoseConverge_UnreportedLagFails(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}
	s := mkSamples(10, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = 0, 0
		s.SolarW = 5000 // way over the 1000 W gen limit (possible 6000)
		s.HubAdopted, s.AdoptedTyp = true, "genLimit"
	})
	f := diagnoseConverge(scFor("conv"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "ACKed")
}

func TestDiagnoseConverge_ReportedLagIsDegraded(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}
	s := mkSamples(10, func(i int, s *maySample) {
		s.SolarW = 5000
		s.HubAdopted, s.AdoptedTyp = true, "genLimit"
		s.CannotComply = true
	})
	f := diagnoseConverge(scFor("conv2"), cons, s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED", f.Verdict)
	}
}

func TestDiagnoseStale_FrozenMeterIsBlind(t *testing.T) {
	cons := exportCons()
	s := mkSamples(10, func(i int, s *maySample) { s.RealGridW = -100 }) // never changes
	f := diagnoseStale(scFor("stale"), cons, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "frozen")
}

func TestDiagnoseStale_LiveMeterPasses(t *testing.T) {
	cons := exportCons()
	s := mkSamples(10, func(i int, s *maySample) { s.RealGridW = float64(-100 * i) }) // wide range
	f := diagnoseStale(scFor("live"), cons, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS", f.Verdict)
	}
}

func TestDiagnoseRecovery_StuckCurtailFails(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1500, MRID: "M-rec"}
	// Solar stays far below potential to the end → never restored.
	s := mkSamples(10, func(i int, s *maySample) { s.SolarW = 800; s.SolarPossibleW = 6000 })
	f := diagnoseRecovery(scFor("rec"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "stuck")
}

func TestDiagnoseRecovery_ReturnsToFullPasses(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1500, MRID: "M-rec"}
	s := mkSamples(10, func(i int, s *maySample) {
		if i < 5 {
			s.SolarW = 800 // curtailed / dropped out
		} else {
			s.SolarW = 5900 // back to ~full (possible 6000)
		}
	})
	f := diagnoseRecovery(scFor("rec2"), cons, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	if f.Metrics.RecoverySeconds < 0 {
		t.Error("RecoverySeconds should be set on a PASS")
	}
}

func assertDiag(t *testing.T, f mayFinding, want string) {
	t.Helper()
	for _, line := range f.Diagnosis {
		if containsFold(line, want) {
			return
		}
	}
	t.Errorf("diagnosis missing %q; got %v", want, f.Diagnosis)
}

func containsFold(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexFold(haystack, needle) >= 0)
}

func indexFold(s, sub string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
