package main

import "testing"

// ── modbusSurvivalFinding ────────────────────────────────────────────────────

// held75 is a 75s timeline where the grid meter shows net w throughout (0 =
// within a zero-export cap), reachable the whole time.
func held75(w float64) []maySample {
	return mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.RealGridW, smp.HubGridW = w, w
	})
}

func TestModbusSurvival_PassCapHeld(t *testing.T) {
	f := modbusSurvivalFinding(scFor("mtd-pass"), exportCons(), held75(0), "the dropped connection", "fix")
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
	if !containsFold(f.Headline, "dropped connection") {
		t.Errorf("headline = %q, want the fault label", f.Headline)
	}
}

func TestModbusSurvival_FailUnreachable(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = false })
	f := modbusSurvivalFinding(scFor("mtd-unreach"), exportCons(), s, "the torn reads", "fix")
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "stopped responding") {
		t.Errorf("headline = %q, want it to mention the hub not responding", f.Headline)
	}
}

func TestModbusSurvival_FailUnseated(t *testing.T) {
	// Exporting 3000 W the whole window against a 0 cap, still breaching at the end.
	f := modbusSurvivalFinding(scFor("mtd-unseat"), exportCons(), held75(-3000), "the wrong-slave reads", "fix")
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "unseated") {
		t.Errorf("headline = %q, want it to mention the control being unseated", f.Headline)
	}
}

func TestModbusSurvival_DegradedTransient(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		if i < 40 {
			smp.RealGridW, smp.HubGridW = -3000, -3000
		} else {
			smp.RealGridW, smp.HubGridW = 0, 0
		}
	})
	f := modbusSurvivalFinding(scFor("mtd-degr"), exportCons(), s, "the dropped connection", "fix")
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
}

// ── diagnoseNegativeLimit ────────────────────────────────────────────────────

func TestNegativeLimit_PassAdoptedNegative(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.AdoptedTyp, smp.AdoptedLimW = "exportCap", -5000
	})
	f := diagnoseNegativeLimit(scFor("neg-adopt"), nil, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s)", f.Verdict, f.Headline)
	}
	joined := joinDiag(f)
	if !containsFold(joined, "ADOPTED the negative") {
		t.Errorf("diagnosis should document the adopt-and-enforce handling: %v", f.Diagnosis)
	}
}

func TestNegativeLimit_PassClampedToZero(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.AdoptedTyp, smp.AdoptedLimW = "exportCap", 0
	})
	f := diagnoseNegativeLimit(scFor("neg-clamp"), nil, s)
	if f.Verdict != "PASS" || !containsFold(joinDiag(f), "CLAMPED") {
		t.Fatalf("want PASS+CLAMPED, got %s: %v", f.Verdict, f.Diagnosis)
	}
}

func TestNegativeLimit_PassRejected(t *testing.T) {
	// No exportCap ever adopted → the hub appears to reject the negative value.
	s := mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = true })
	f := diagnoseNegativeLimit(scFor("neg-reject"), nil, s)
	if f.Verdict != "PASS" || !containsFold(joinDiag(f), "REJECT") {
		t.Fatalf("want PASS+REJECT, got %s: %v", f.Verdict, f.Diagnosis)
	}
}

func TestNegativeLimit_FailUnreachable(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseNegativeLimit(scFor("neg-unreach"), nil, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
}

// ── diagnoseSaturatingWrite ──────────────────────────────────────────────────

func TestSaturatingWrite_PassSane(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.SolarCeilingOK, smp.SolarCeilingEna = true, true
		if i < 30 {
			smp.SolarCeilingPct = 20 // hard cap → low ceiling (exercised)
		} else {
			smp.SolarCeilingPct = 100 // absurd cap → saturated high
		}
	})
	f := diagnoseSaturatingWrite(scFor("sat-pass"), nil, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
	if !containsFold(joinDiag(f), "exercised") {
		t.Errorf("want the write-path-exercised note: %v", f.Diagnosis)
	}
}

func TestSaturatingWrite_FailWrapped(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.SolarCeilingOK, smp.SolarCeilingEna = true, true
		smp.SolarCeilingPct = 100
		if i > 40 {
			smp.SolarCeilingPct = -300 // wrapped int16 → negative percent
		}
	})
	f := diagnoseSaturatingWrite(scFor("sat-wrap"), nil, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "WRAPPED") {
		t.Errorf("headline = %q, want it to flag the wrap", f.Headline)
	}
}

func TestSaturatingWrite_BlindNoCeiling(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) { smp.HubReachable = true }) // SolarCeilingOK stays false
	f := diagnoseSaturatingWrite(scFor("sat-blind"), nil, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND", f.Verdict)
	}
}

func TestSaturatingWrite_FailUnreachable(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseSaturatingWrite(scFor("sat-unreach"), nil, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
}

// ── diagnoseBoundarySOC ──────────────────────────────────────────────────────

func TestBoundarySOC_PassNoViolation(t *testing.T) {
	s := mkSamples(45, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.BatterySimOK = true
		smp.BatterySimW, smp.BatSimSOC = 0, 10 // idle at the floor — no discharge
	})
	f := diagnoseBoundarySOC(scFor("soc-pass"), nil, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestBoundarySOC_FailDischargeBelowReserve(t *testing.T) {
	s := mkSamples(45, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.BatterySimOK = true
		smp.BatSimSOC = 5 // below the 10% reserve floor
		if i > 30 {
			smp.BatterySimW = 1000 // discharging past the deadline → INV-SOC violation
		}
	})
	f := diagnoseBoundarySOC(scFor("soc-fail"), nil, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "wrong way") {
		t.Errorf("headline = %q, want it to flag the boundary violation", f.Headline)
	}
}

func TestBoundarySOC_BlindProbeAbsent(t *testing.T) {
	// Battery sim never answered → a clean INV-SOC is untrustworthy silence.
	s := mkSamples(45, func(i int, smp *maySample) { smp.HubReachable = true }) // BatterySimOK stays false
	f := diagnoseBoundarySOC(scFor("soc-blind"), nil, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (%s)", f.Verdict, f.Headline)
	}
}

func TestBoundarySOC_FailUnreachable(t *testing.T) {
	s := mkSamples(45, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseBoundarySOC(scFor("soc-unreach"), nil, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
}

// ── diagnoseOCPPLifecycle ────────────────────────────────────────────────────

func TestOCPPLifecycle_PassCoherent(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.EvSimOK = true
		smp.EvSimW = 3000 // car truly drawing
		smp.EvW = 3000    // hub sees it
	})
	f := diagnoseOCPPLifecycle(scFor("ocpp-pass"), s, "the reordered events", "fix")
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
	if !containsFold(joinDiag(f), "does NOT validate") {
		t.Errorf("want the audited-non-validation note: %v", f.Diagnosis)
	}
}

func TestOCPPLifecycle_FailSilentBlind(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.EvSimOK = true
		smp.EvSimW = 3000 // car truly drawing
		smp.EvW = 0       // hub sees ~0 and does not flag stale → silent blindness
	})
	f := diagnoseOCPPLifecycle(scFor("ocpp-blind"), s, "the mid-tx boot", "fix")
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "silently blind") {
		t.Errorf("headline = %q, want it to flag silent blindness", f.Headline)
	}
}

func TestOCPPLifecycle_DegradedTransient(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.EvSimOK = true
		smp.EvSimW = 3000
		smp.EvW = 3000
		if i > 30 && i%3 == 0 {
			smp.EvW = 0 // blind on ~1/3 of post-settling live samples
		}
	})
	f := diagnoseOCPPLifecycle(scFor("ocpp-degr"), s, "the reordered events", "fix")
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
}

func TestOCPPLifecycle_PassNoLiveDraw(t *testing.T) {
	// The EV never drew, so coherence can't be exercised — survival still PASSes.
	s := mkSamples(60, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.EvSimOK = true
		smp.EvSimW = 0
	})
	f := diagnoseOCPPLifecycle(scFor("ocpp-nolive"), s, "the reordered events", "fix")
	if f.Verdict != "PASS" || !containsFold(f.Headline, "not exercised") {
		t.Fatalf("want PASS+not-exercised, got %s (%s)", f.Verdict, f.Headline)
	}
}

func TestOCPPLifecycle_FailUnreachable(t *testing.T) {
	s := mkSamples(60, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseOCPPLifecycle(scFor("ocpp-unreach"), s, "the reordered events", "fix")
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
}

// ── scenario construction sanity ─────────────────────────────────────────────

func TestTransportScenarios_WellFormed(t *testing.T) {
	d := &mayhemDriver{}
	seen := map[string]bool{}
	for _, sc := range d.transportScenarios() {
		if sc.ID == "" {
			t.Fatalf("scenario with empty ID: %+v", sc)
		}
		if seen[sc.ID] {
			t.Errorf("duplicate scenario ID %q", sc.ID)
		}
		seen[sc.ID] = true
		if sc.Hypothesis == "" || sc.Expected == "" || sc.Fix == "" {
			t.Errorf("%s: Hypothesis/Expected/Fix must not be empty", sc.ID)
		}
		if sc.HoldS < 30 || sc.HoldS > 90 {
			t.Errorf("%s: HoldS = %d, want in [30,90]", sc.ID, sc.HoldS)
		}
		if sc.setup == nil || sc.evaluate == nil || sc.teardown == nil {
			t.Errorf("%s: setup/evaluate/teardown must not be nil", sc.ID)
		}
	}
	wantIDs := []string{
		"modbus-tcp-drop", "modbus-unit-id-confusion", "modbus-register-tearing",
		"negative-export-limit", "saturating-write-clamp",
		"battery-soc-empty-discharge", "battery-soc-reserve-edge",
		"ocpp-out-of-order-txevent", "ocpp-boot-mid-tx",
	}
	for _, id := range wantIDs {
		if !seen[id] {
			t.Errorf("transportScenarios() missing expected ID %q", id)
		}
	}
}

// joinDiag flattens a finding's diagnosis bullets for substring assertions.
func joinDiag(f mayFinding) string {
	out := f.Headline
	for _, d := range f.Diagnosis {
		out += " " + d
	}
	return out
}
