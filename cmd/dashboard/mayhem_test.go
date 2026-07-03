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

func TestDiagnoseConstraint_BreachedThenConvergedPasses(t *testing.T) {
	// Export over the 0-cap for the first 8 s (curtailment ramping in), then net
	// settles at the cap and HOLDS for the rest of the window. A transient settling
	// ramp that resolves quickly must be PASS, not a closed-loop FAIL.
	s := mkSamples(40, func(i int, s *maySample) {
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		if i < 8 {
			s.RealGridW, s.HubGridW = -2000, -2000 // exporting over the cap
			s.SolarW = 6000                        // not yet curtailed
		} else {
			s.RealGridW, s.HubGridW = 0, 0 // converged to the cap
			s.SolarW = 200                 // curtailed (possible 6000)
		}
	})
	f := diagnoseConstraint(scFor("conv"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	if f.Metrics.ConvergedAtS <= 0 {
		t.Errorf("ConvergedAtS = %v, want > 0", f.Metrics.ConvergedAtS)
	}
	if !f.Metrics.TailClean {
		t.Error("TailClean should be true")
	}
}

func TestDiagnoseConstraint_SlowConvergeDegraded(t *testing.T) {
	// Breach persists past the settling deadline, then converges and holds. Correct
	// end state but sluggish → DEGRADED, not PASS and not FAIL.
	s := mkSamples(60, func(i int, s *maySample) {
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		if i < 40 { // > mayConvergeDeadlineS seconds of breach
			s.RealGridW, s.HubGridW = -1500, -1500
			s.SolarW = 6000
		} else {
			s.RealGridW, s.HubGridW = 0, 0
			s.SolarW = 200
		}
	})
	f := diagnoseConstraint(scFor("slow"), exportCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
	if f.Metrics.ConvergedAtS <= mayConvergeDeadlineS {
		t.Errorf("ConvergedAtS = %v, want > %d", f.Metrics.ConvergedAtS, mayConvergeDeadlineS)
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

func TestDiagnoseConverge_RampingTowardLimitIsDegraded(t *testing.T) {
	// Output slews from far over the cap down toward it, still slightly over at the
	// end — a bounded slew (ramp_limit), not an ignore. Must be DEGRADED, not FAIL.
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-ramp"}
	s := mkSamples(40, func(i int, smp *maySample) {
		smp.HubAdopted, smp.AdoptedTyp = true, "genLimit"
		w := 5000.0 - float64(i)*110.0 // slews down ~110/sample
		if w < 1150 {
			w = 1150 // lands just above the 1000 cap
		}
		smp.SolarW = w
	})
	f := diagnoseConverge(scFor("ramp"), cons, s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (slewing toward the limit)", f.Verdict)
	}
	if !f.Metrics.BreachConverging {
		t.Error("BreachConverging should be true for a shrinking breach")
	}
}

func TestDiagnoseConverge_FlatBreachStaysFail(t *testing.T) {
	// A flat, never-moving breach (ignore) must NOT be mistaken for a slew.
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-flat"}
	s := mkSamples(40, func(i int, smp *maySample) {
		smp.HubAdopted, smp.AdoptedTyp = true, "genLimit"
		smp.SolarW = 5000 // held flat over the cap
	})
	f := diagnoseConverge(scFor("flat"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (flat breach, not converging)", f.Verdict)
	}
	if f.Metrics.BreachConverging {
		t.Error("BreachConverging should be false for a flat breach")
	}
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

func importCons1000() *activeConstraint {
	return &activeConstraint{Typ: "importCap", LimW: 1000, MRID: "M-ev0001freeze"}
}

func TestDiagnoseEVFreeze_PassTracks(t *testing.T) {
	// Cap held (800 W < 1000 W) and the hub's EV view matches ground truth.
	s := mkSamples(12, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = 800, 800
		s.HubAdopted, s.AdoptedTyp = true, "importCap"
		s.EvSimOK, s.EvSimW, s.EvW = true, 1380, 1380
	})
	f := diagnoseEVFreeze(scFor("evf-pass"), importCons1000(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	if f.Metrics.HubBlind {
		t.Error("HubBlind should be false when the hub tracks truth")
	}
}

func TestDiagnoseEVFreeze_BlindOnDivergence(t *testing.T) {
	// Cap held, but the hub's MeterValues froze high (1380 W) while the charger
	// truly curtailed to 400 W — the hub is blind to the EVSE.
	s := mkSamples(12, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = 800, 800
		s.HubAdopted, s.AdoptedTyp = true, "importCap"
		s.EvSimOK, s.EvSimW, s.EvW = true, 400, 1380
	})
	f := diagnoseEVFreeze(scFor("evf-blind"), importCons1000(), s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
	if !f.Metrics.HubBlind {
		t.Error("HubBlind should be true on a sustained hub-vs-truth divergence")
	}
	assertDiag(t, f, "froze")
}

func TestDiagnoseEVFreeze_FailOnBreach(t *testing.T) {
	// Import cap breached for the whole window and never converged → the hub lost
	// the cap while blind, which outranks the observability note.
	s := mkSamples(12, func(i int, s *maySample) {
		s.RealGridW, s.HubGridW = 1800, 1800
		s.HubAdopted, s.AdoptedTyp = true, "importCap"
		s.EvSimOK, s.EvSimW, s.EvW = true, 1380, 1380
	})
	f := diagnoseEVFreeze(scFor("evf-fail"), importCons1000(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "lost the import cap")
}

func noneCons() *activeConstraint { return &activeConstraint{Typ: "none"} }

func TestDiagnoseBatteryGarbage_RejectedPasses(t *testing.T) {
	s := mkSamples(30, func(i int, s *maySample) { s.BatSOC = 55; s.BatteryW = 1000 })
	f := diagnoseBatteryGarbage(scFor("bg-pass"), noneCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseBatteryGarbage_IngestedFails(t *testing.T) {
	// 0x8000 decoded as a real SoC ⇒ a wild ~32768%.
	s := mkSamples(30, func(i int, s *maySample) { s.BatSOC = 32768; s.BatteryW = -32768 })
	f := diagnoseBatteryGarbage(scFor("bg-fail"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "impossible battery")
}

func TestDiagnoseEVUnits_RejectedPasses(t *testing.T) {
	// Hub reports a plausible current well under the station max → validated.
	s := mkSamples(30, func(i int, s *maySample) { s.EvCurrentA = 13; s.EvMaxA = 32; s.EvW = 3000 })
	f := diagnoseEVUnits(scFor("units-pass"), noneCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseEVUnits_IngestedFails(t *testing.T) {
	// Hub surfaces a mislabeled ~1000× current (mA reported as A).
	s := mkSamples(30, func(i int, s *maySample) { s.EvCurrentA = 13000; s.EvMaxA = 32; s.EvW = 3_000_000 })
	f := diagnoseEVUnits(scFor("units-fail"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "physically-impossible")
}

func TestDiagnoseEVFlap_StablePasses(t *testing.T) {
	s := mkSamples(30, func(i int, s *maySample) { s.EvW = 3000; s.EvCurrentA = 13; s.EvMaxA = 32 })
	f := diagnoseEVFlap(scFor("flap-pass"), noneCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseEVFlap_OverMaxFails(t *testing.T) {
	// Hub commands current well over the station max ⇒ it mis-tracked the flap.
	s := mkSamples(30, func(i int, s *maySample) { s.EvW = 9000; s.EvCurrentA = 40; s.EvMaxA = 32 })
	f := diagnoseEVFlap(scFor("flap-fail"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "station max")
}

func TestDiagnoseExpiry_ReleasedPasses(t *testing.T) {
	base := int64(1_700_000_000)
	// Adopted while valid (validUntil far ahead) for the first third, then released.
	s := mkSamples(30, func(i int, s *maySample) {
		s.SolarW, s.SolarPossibleW = 4000, 4000
		s.WallUnix = base + int64(i)
		if i < 10 {
			s.HubAdopted, s.AdoptedTyp = true, "exportCap"
			s.ValidUntil = base + 1000 // not expired while adopted
		}
	})
	f := diagnoseExpiry(scFor("exp-pass"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseExpiry_StillEnforcedFails(t *testing.T) {
	base := int64(1_700_000_000)
	// Hub keeps adopting a control whose validUntil is well in the past.
	s := mkSamples(30, func(i int, s *maySample) {
		s.WallUnix = base + int64(i)
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.ValidUntil = base - 100 // already expired (well past validUntil + grace)
	})
	f := diagnoseExpiry(scFor("exp-fail"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "must be released")
}

func TestDiagnoseExpiry_NeverAdoptedInconclusive(t *testing.T) {
	base := int64(1_700_000_000)
	s := mkSamples(30, func(i int, s *maySample) { s.WallUnix = base + int64(i) }) // never adopts
	f := diagnoseExpiry(scFor("exp-inc"), exportCons(), s)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

func TestDiagnoseReboot_RecoversPasses(t *testing.T) {
	// Hub stays up, SoC stays sane, and the tail shows a live battery.
	s := mkSamples(40, func(i int, s *maySample) { s.BatSOC = 60; s.BatteryW = -1000 })
	f := diagnoseReboot(scFor("rb-pass"), noneCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseReboot_HubDownFails(t *testing.T) {
	// Hub unreachable for most of the outage → the dead device blocked it.
	s := mkSamples(40, func(i int, s *maySample) {
		s.BatSOC = 60
		s.HubReachable = i < 5
	})
	f := diagnoseReboot(scFor("rb-down"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "must never take the hub down")
}

func TestDiagnoseReboot_GarbageSOCFails(t *testing.T) {
	// Hub surfaces an impossible SoC (255%) from the off-bus pack.
	s := mkSamples(40, func(i int, s *maySample) { s.BatSOC = 255 })
	f := diagnoseReboot(scFor("rb-garbage"), noneCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	assertDiag(t, f, "impossible battery")
}

func TestDiagnoseReboot_NeverRecoversBlind(t *testing.T) {
	// Survived, no garbage, but the battery reads dead (0%) through the whole tail.
	s := mkSamples(40, func(i int, s *maySample) { s.BatSOC = 0; s.BatteryW = 0 })
	f := diagnoseReboot(scFor("rb-blind"), noneCons(), s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
	assertDiag(t, f, "did not re-establish")
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

// diagnoseMeterInversion: PASS when the cap truly held, DEGRADED when the hub
// flagged/admitted while the true breach stood, FAIL when it was confidently
// wrong (sustained true breach, nothing flagged, nothing admitted).
func TestDiagnoseMeterInversion_Verdicts(t *testing.T) {
	sc := scFor("meter-ct-inverted")
	cons := exportCons() // exportCap ≤ 0 W

	// True export breach the whole window, hub silent → FAIL.
	silent := mkSamples(60, func(i int, s *maySample) {
		s.RealGridW = -4000 // ground truth: exporting 4 kW
		s.HubGridW = 4000   // hub's inverted view: importing 4 kW
	})
	if f := diagnoseMeterInversion(sc, cons, silent); f.Verdict != "FAIL" {
		t.Errorf("silent inverted breach = %s, want FAIL", f.Verdict)
	}

	// Same breach but the hub flagged the meter → DEGRADED.
	flagged := mkSamples(60, func(i int, s *maySample) {
		s.RealGridW = -4000
		if i > 20 {
			s.MeterStale = true
		}
	})
	if f := diagnoseMeterInversion(sc, cons, flagged); f.Verdict != "DEGRADED" {
		t.Errorf("flagged inverted breach = %s, want DEGRADED", f.Verdict)
	}

	// Same breach, CannotComply posted → DEGRADED.
	admitted := mkSamples(60, func(i int, s *maySample) {
		s.RealGridW = -4000
		if i > 20 {
			s.CannotComply = true
		}
	})
	if f := diagnoseMeterInversion(sc, cons, admitted); f.Verdict != "DEGRADED" {
		t.Errorf("admitted inverted breach = %s, want DEGRADED", f.Verdict)
	}

	// Cap actually held (hub saw through the lie) → PASS.
	held := mkSamples(60, func(i int, s *maySample) {
		s.RealGridW = 200 // truly importing a touch — within the cap
		s.HubGridW = -200
	})
	if f := diagnoseMeterInversion(sc, cons, held); f.Verdict != "PASS" {
		t.Errorf("held cap = %s, want PASS", f.Verdict)
	}

	// A breach confined to the settling ramp is excused → PASS.
	ramp := mkSamples(60, func(i int, s *maySample) {
		if float64(i) <= mayConvergeDeadlineS {
			s.RealGridW = -4000
		} else {
			s.RealGridW = 200
		}
	})
	if f := diagnoseMeterInversion(sc, cons, ramp); f.Verdict != "PASS" {
		t.Errorf("settling-only breach = %s, want PASS", f.Verdict)
	}

	if f := diagnoseMeterInversion(sc, cons, nil); f.Verdict != "INCONCLUSIVE" {
		t.Errorf("no samples = %s, want INCONCLUSIVE", f.Verdict)
	}
}
