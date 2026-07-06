package main

import "testing"

// ── ditherSquareWave / filterExtended / expectedDitherTransitions ──────────
// Pure cadence/selection helpers (TASK-054, GAP-08) — no bench required.

// TestDitherSquareWave_AlternatesEveryHalfPeriod locks the cadence contract
// both dither scenarios' perTick relies on: phaseA holds for exactly
// halfPeriodTicks ticks, then flips, and apply fires on EVERY tick (not just
// on a flip) so a re-injected phase (batsim's pendingSoC) keeps sticking.
func TestDitherSquareWave_AlternatesEveryHalfPeriod(t *testing.T) {
	const half = 4
	var calls int
	var phases []bool
	pt := ditherSquareWave(half, func(d *mayhemDriver, phaseA bool) {
		calls++
		phases = append(phases, phaseA)
	})

	for i := 0; i < half*4; i++ {
		pt(nil, i)
	}
	if calls != half*4 {
		t.Fatalf("apply called %d times over %d ticks, want %d (every tick)", calls, half*4, half*4)
	}
	// First half-period: phaseA true. Next: false. Next: true. Next: false.
	want := []bool{true, false, true, false}
	for block := 0; block < 4; block++ {
		for i := 0; i < half; i++ {
			idx := block*half + i
			if phases[idx] != want[block] {
				t.Errorf("tick %d (block %d): phaseA = %v, want %v", idx, block, phases[idx], want[block])
			}
		}
	}
}

// TestDitherSquareWave_FloorsPathologicalPeriod guards against a zero/negative
// half-period wedging the cadence into a divide-by-zero or infinite single
// phase.
func TestDitherSquareWave_FloorsPathologicalPeriod(t *testing.T) {
	pt := ditherSquareWave(0, func(d *mayhemDriver, phaseA bool) {})
	// Must not panic — floors to 1.
	pt(nil, 0)
	pt(nil, 1)
}

// TestFilterExtended_DropsUnlessOptedIn locks the RSK-12 selection rule: a
// default/full run drops Extended scenarios; includeExtended=true keeps them.
func TestFilterExtended_DropsUnlessOptedIn(t *testing.T) {
	scs := []*mayScenario{
		{ID: "short-1"},
		{ID: "export-dither-at-breach", Extended: true},
		{ID: "short-2"},
		{ID: "soc-dither-at-reserve", Extended: true},
	}

	got := filterExtended(scs, false)
	if len(got) != 2 {
		t.Fatalf("filterExtended(false): got %d scenarios, want 2 (Extended dropped): %+v", len(got), got)
	}
	for _, sc := range got {
		if sc.Extended {
			t.Errorf("filterExtended(false) kept an Extended scenario: %s", sc.ID)
		}
	}

	got = filterExtended(scs, true)
	if len(got) != len(scs) {
		t.Fatalf("filterExtended(true): got %d scenarios, want all %d", len(got), len(scs))
	}
}

// TestExpectedDitherTransitions_ScalesWithHoldAndPeriod locks the "at most one
// real transition per half-cycle" model batteryCommandFlaps is judged against.
func TestExpectedDitherTransitions_ScalesWithHoldAndPeriod(t *testing.T) {
	sc := &mayScenario{HoldS: ditherHoldS} // 300
	got := expectedDitherTransitions(sc)
	want := ditherHoldS / ditherHalfPeriodTicks
	if got != want {
		t.Errorf("expectedDitherTransitions(HoldS=%d) = %d, want %d", ditherHoldS, got, want)
	}

	// A tiny hold still expects at least one transition, never zero (avoids a
	// divide-by-zero-flavoured "anything counts as chatter" false positive).
	tiny := &mayScenario{HoldS: 1}
	if got := expectedDitherTransitions(tiny); got < 1 {
		t.Errorf("expectedDitherTransitions(HoldS=1) = %d, want >= 1", got)
	}
}

// ── batteryCommandFlaps / socReserveOverDischarge ───────────────────────────

// TestBatteryCommandFlaps_CountsSignTransitionsPastSettling locks the
// transition-counting rule: idle jitter around zero never counts, only
// post-settling samples count, and each discharge<->charge crossing is one
// flip.
func TestBatteryCommandFlaps_CountsSignTransitionsPastSettling(t *testing.T) {
	// Two clean half-cycles past settling: discharge, charge, discharge, charge
	// (3 transitions), each held for several samples so idle jitter is not the
	// signal under test.
	s := mkSamples(int(mayConvergeDeadlineS)+40, func(i int, s *maySample) {
		s.BatterySimOK = true
		t := i - int(mayConvergeDeadlineS)
		if t < 0 {
			s.BatterySimW = 0 // settling window: irrelevant, excluded anyway
			return
		}
		switch (t / 10) % 2 {
		case 0:
			s.BatterySimW = 200 // discharging
		default:
			s.BatterySimW = -200 // charging
		}
	})
	if got := batteryCommandFlaps(s); got != 3 {
		t.Errorf("batteryCommandFlaps = %d, want 3 (four 10-sample blocks -> 3 crossings)", got)
	}

	// Idle jitter around zero (within invSocActiveW) never counts as a flip.
	idle := mkSamples(int(mayConvergeDeadlineS)+20, func(i int, s *maySample) {
		s.BatterySimOK = true
		if i%2 == 0 {
			s.BatterySimW = 10
		} else {
			s.BatterySimW = -10
		}
	})
	if got := batteryCommandFlaps(idle); got != 0 {
		t.Errorf("batteryCommandFlaps(idle jitter) = %d, want 0", got)
	}

	// Samples without a coherent sim reading are skipped, not miscounted.
	noSim := mkSamples(int(mayConvergeDeadlineS)+20, func(i int, s *maySample) {
		s.BatterySimOK = false
		s.BatterySimW = 500
	})
	if got := batteryCommandFlaps(noSim); got != 0 {
		t.Errorf("batteryCommandFlaps(no sim ground truth) = %d, want 0", got)
	}
}

// TestSocReserveOverDischarge_FlagsAtOrBelowLineExcusesAboveAndSettling locks
// the boundary this predicate probes: SOCReserve (20%), not invariants.go's
// separate 10% harness floor (invSocReserveFloorPct) — that one is untouched.
func TestSocReserveOverDischarge_FlagsAtOrBelowLineExcusesAboveAndSettling(t *testing.T) {
	// Discharging at exactly the reserve line, past settling: a violation.
	atLine := mkSamples(int(mayConvergeDeadlineS)+10, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatterySimW = 200
		s.BatSimSOC = socDitherReserveLine
	})
	v := socReserveOverDischarge(atLine)
	if len(v) == 0 {
		t.Fatal("discharging at the SOCReserve line past settling should violate")
	}
	if v[0].Inv != "INV-SOC-RESERVE" {
		t.Errorf("violation name = %q, want INV-SOC-RESERVE", v[0].Inv)
	}

	// Discharging just ABOVE the line: excused (this predicate's whole point
	// is the line itself, not a lower danger floor).
	above := mkSamples(int(mayConvergeDeadlineS)+10, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatterySimW = 200
		s.BatSimSOC = socDitherReserveLine + 1
	})
	if v := socReserveOverDischarge(above); len(v) != 0 {
		t.Errorf("discharging above the reserve line flagged: %v", v)
	}

	// Discharging at the line but only during the opening settling window:
	// excused (mirrors pastSettling's grace elsewhere in the suite).
	settling := mkSamples(int(mayConvergeDeadlineS)-5, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatterySimW = 200
		s.BatSimSOC = socDitherReserveLine
	})
	if v := socReserveOverDischarge(settling); len(v) != 0 {
		t.Errorf("settling-window discharge at the line flagged: %v", v)
	}
}

// ── diagnoseExportDither ─────────────────────────────────────────────────────

// exportDitherSamples builds a synthetic timeline dithering export ±ε around
// the exportCap(0)+complianceTolW band without ever recovering past the
// invHunt hysteresis band — the same shape invariants_test.go's
// TestInvHunt_FlagsOscillationExcusesConvergence proves is NOT hunting.
func exportDitherSamples(n int, mut func(i int, s *maySample)) []maySample {
	return mkSamples(n, func(i int, s *maySample) {
		if i%2 == 0 {
			s.RealGridW = -200 // marginally over the band
		} else {
			s.RealGridW = 100 // marginally under — inside the hysteresis band
		}
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		if mut != nil {
			mut(i, s)
		}
	})
}

func TestDiagnoseExportDither_PureDitherPasses(t *testing.T) {
	s := exportDitherSamples(120, nil)
	f := diagnoseExportDither(scFor("export-dither-at-breach"), exportCons(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

// TestDiagnoseExportDither_CannotComplyFails is the CannotComply
// biconditional's "not sustained ⇒ no CannotComply" half in reverse: if the
// hub ever posts CannotComply during a pure dither that never sustains, that
// IS the failure (the leaky counter accumulated when it should have decayed).
func TestDiagnoseExportDither_CannotComplyFails(t *testing.T) {
	s := exportDitherSamples(120, func(i int, s *maySample) {
		if i > 60 {
			s.CannotComply = true
		}
	})
	f := diagnoseExportDither(scFor("export-dither-at-breach"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL on a CannotComply during pure dither (%s)", f.Verdict, f.Headline)
	}
}

// TestDiagnoseExportDither_HuntFails reuses the exact oscillation shape
// invariants_test.go proves DOES trip INV-HUNT (clear recovery, repeated
// re-entry) — a boundary-dither scenario must FAIL on real hunting, not just
// demote to DEGRADED the way the generic cross-cutting audit does.
func TestDiagnoseExportDither_HuntFails(t *testing.T) {
	cons := exportCons()
	hunt := mkSamples(90, func(i int, s *maySample) {
		if (i/5)%2 == 0 {
			s.RealGridW = -1500 // over the cap
		} else {
			s.RealGridW = 800 // clearly recovered
		}
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
	})
	f := diagnoseExportDither(scFor("export-dither-at-breach"), cons, hunt)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL on INV-HUNT (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseExportDither_Inconclusive(t *testing.T) {
	f := diagnoseExportDither(scFor("export-dither-at-breach"), exportCons(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE on no samples", f.Verdict)
	}
}

// ── diagnoseSocDither ────────────────────────────────────────────────────────

func socDitherScenario() *mayScenario {
	return &mayScenario{ID: "soc-dither-at-reserve", Name: "soc-dither-at-reserve", HoldS: 80}
}

func TestDiagnoseSocDither_CleanDitherPasses(t *testing.T) {
	// One clean transition per half-period (8 half-periods of 10 samples each
	// over an 80-sample, HoldS=80 timeline — matches expectedDitherTransitions).
	s := mkSamples(80, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = socDitherHighPct
		if (i/10)%2 == 0 {
			s.BatterySimW = 200 // discharging (SoC "high" phase — above reserve)
		} else {
			s.BatterySimW = 0 // reserve guard holds (SoC "low" phase)
		}
	})
	f := diagnoseSocDither(socDitherScenario(), importCons0(), s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseSocDither_ReserveBreachFails(t *testing.T) {
	s := mkSamples(80, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatterySimW = 200 // discharging throughout
		s.BatSimSOC = socDitherLowPct
	})
	f := diagnoseSocDither(socDitherScenario(), importCons0(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL on a sustained over-reserve discharge (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseSocDither_ChatterFails(t *testing.T) {
	// Above the reserve line throughout (no INV-SOC-RESERVE violation), but
	// flipping sign every sample — far more transitions than the ~8 the
	// HoldS=80 dither cadence would explain.
	s := mkSamples(80, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = socDitherHighPct
		if i%2 == 0 {
			s.BatterySimW = 200
		} else {
			s.BatterySimW = -200
		}
	})
	f := diagnoseSocDither(socDitherScenario(), importCons0(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL on command chatter (%s)", f.Verdict, f.Headline)
	}
}

func TestDiagnoseSocDither_Inconclusive(t *testing.T) {
	f := diagnoseSocDither(socDitherScenario(), importCons0(), nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE on no samples", f.Verdict)
	}
}

func importCons0() *activeConstraint {
	return &activeConstraint{Typ: "importCap", LimW: 0, MRID: "M-soc-dither"}
}
