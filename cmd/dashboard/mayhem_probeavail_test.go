package main

import "testing"

// WS-3 part 1: constraint-aware probe availability. breachOver and invSOC both
// treat an absent judging sensor as "no breach this tick" — correct for a
// single dropped poll, but if the sensor that actually judges an oracle (solar
// for genLimit, the grid meter for export/import, the battery sim for
// INV-SOC) is dead for most of the hold window, "no breach" is read as
// silence, not compliance. These tests pin the vacuous-PASS gap closed: a
// mostly-dead judging sensor must force BLIND, never PASS, while a genuine
// FAIL/DEGRADED reached from data the sensor DID deliver must never be
// softened, and a healthy (100% available) probe must leave every existing
// verdict bit-identical.

// ── genLimit / solar probe ───────────────────────────────────────────────────

// A dead solar probe on a genLimit scenario used to vacuous-PASS: SolarOK is
// false on every sample, so breachOver always returns "no breach" regardless
// of what solar was actually doing. diagnoseConstraint must refuse to call
// that a PASS.
func TestDiagnoseConstraint_DeadSolarProbeForcesBlind(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}
	s := mkSamples(20, func(i int, s *maySample) {
		s.SolarOK = false // solar sim entirely unreachable for the whole window
	})
	f := diagnoseConstraint(scFor("dead-solar"), cons, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (solar probe absent the whole window)", f.Verdict)
	}
	assertDiag(t, f, "solar")
	if !f.Metrics.HubBlind {
		t.Error("Metrics.HubBlind should be set when the verdict is forced BLIND")
	}
}

// The same dead-solar-probe gap must not resurface through diagnoseConverge
// (the ack_before_effect / reject_write / ramp_limit genLimit oracle): it
// wraps diagnoseConstraint and used to turn any non-PASS verdict into FAIL
// unconditionally, which would have clobbered the new BLIND right back into a
// misdiagnosis ("device never honoured the write" instead of "wasn't
// watching").
func TestDiagnoseConverge_DeadSolarProbeForcesBlind(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}
	s := mkSamples(20, func(i int, s *maySample) {
		s.SolarOK = false
		s.HubAdopted, s.AdoptedTyp = true, "genLimit"
	})
	f := diagnoseConverge(scFor("dead-solar-conv"), cons, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND, not FAIL (diagnoseConverge must pass BLIND through, not clobber it)", f.Verdict)
	}
}

// A genLimit scenario with a HEALTHY solar probe (100% availability) that
// genuinely holds the cap must still PASS — the gate must not fire on healthy
// data. This is the "verdicts unchanged when availability is 100%" contract.
func TestDiagnoseConstraint_HealthySolarProbeStillPasses(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}
	s := mkSamples(20, func(i int, s *maySample) {
		s.SolarW, s.SolarPossibleW = 500, 6000 // well under the 1000 W limit
	})
	f := diagnoseConstraint(scFor("healthy-solar"), cons, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (healthy probe, genuine compliance)", f.Verdict)
	}
}

// A genLimit scenario where the solar probe is dead for MOST of the window
// but the sensor's brief up-time already caught a real, un-adopted breach
// must stay FAIL — the probe-gap guard only ever tightens a would-be PASS,
// never softens a finding reached from data the sensor DID deliver.
func TestDiagnoseConstraint_DeadSolarProbeNeverSoftensRealFail(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}
	s := mkSamples(20, func(i int, s *maySample) {
		if i < 15 {
			s.SolarOK = false // dead for 75% of the window
			return
		}
		s.SolarW, s.SolarPossibleW = 5000, 6000 // the sensor comes up and catches a real breach
		// HubAdopted left false ⇒ diagnoseConstraint's "never adopted" FAIL path.
	})
	f := diagnoseConstraint(scFor("dead-solar-realfail"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (a real breach was observed; probe-gap must not soften it to BLIND)", f.Verdict)
	}
}

// ── boundary: exactly at the floor vs. just past it ─────────────────────────

func TestForceBlindOnProbeGap_BoundaryFraction(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}

	// Exactly 20% absent (2 of 10) ⇒ AT the floor, not BEYOND it: stays PASS.
	atFloor := mkSamples(10, func(i int, s *maySample) {
		if i < 2 {
			s.SolarOK = false
		} else {
			s.SolarW, s.SolarPossibleW = 200, 6000
		}
	})
	if f := diagnoseConstraint(scFor("at-floor"), cons, atFloor); f.Verdict != "PASS" {
		t.Fatalf("20%% absent (at the floor): verdict = %s, want PASS", f.Verdict)
	}

	// 30% absent (3 of 10) ⇒ past the floor: forced BLIND.
	pastFloor := mkSamples(10, func(i int, s *maySample) {
		if i < 3 {
			s.SolarOK = false
		} else {
			s.SolarW, s.SolarPossibleW = 200, 6000
		}
	})
	if f := diagnoseConstraint(scFor("past-floor"), cons, pastFloor); f.Verdict != "BLIND" {
		t.Fatalf("30%% absent (past the floor): verdict = %s, want BLIND", f.Verdict)
	}
}

// ── export/import cap / grid meter probe ─────────────────────────────────────

// diagnoseMalform judges a malform scenario's PASS off invExport, which is
// itself gated by breachOver's GridOK check — a dead meter must not let a
// malformed CSIP resource read as "contained" when the harness was actually
// blind to whether the safe cap held.
func TestDiagnoseMalform_DeadMeterProbeForcesBlind(t *testing.T) {
	cons := exportCons()
	s := mkSamples(40, func(i int, s *maySample) {
		s.HubReachable = true
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.GridOK = false // grid meter entirely unreachable
	})
	f := diagnoseMalform(scFor("malformed-csip"), cons, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (grid meter absent the whole window)", f.Verdict)
	}
	assertDiag(t, f, "meter")
}

// ── battery probe / INV-SOC ──────────────────────────────────────────────────

// diagnoseSOC's PASS rests on invSOC finding nothing wrong — but invSOC skips
// every sample where BatterySimOK is false. A dead batsim must not let a
// wrong-direction-battery scenario read as safe.
func TestDiagnoseSOC_DeadBatteryProbeForcesBlind(t *testing.T) {
	cons := &activeConstraint{Typ: "exportCap", LimW: 0, MRID: "M-bat"}
	s := mkSamples(20, func(i int, s *maySample) {
		s.BatterySimOK = false         // battery sim entirely unreachable
		s.RealGridW, s.HubGridW = 0, 0 // the cap itself reads clean (healthy meter)
	})
	f := diagnoseSOC(scFor("battery-wrong-sign"), cons, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict = %s, want BLIND (battery probe absent the whole window)", f.Verdict)
	}
	assertDiag(t, f, "battery")
}

// A healthy battery probe (100% availability) with no SoC violation must
// still PASS unchanged — mirrors TestDiagnoseSOC_Verdicts' "good" case but
// pins it explicitly against the new gate.
func TestDiagnoseSOC_HealthyBatteryProbeStillPasses(t *testing.T) {
	cons := &activeConstraint{Typ: "exportCap", LimW: 0, MRID: "M-bat"}
	s := mkSamples(20, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 55
		s.BatterySimW = -800 // charging, healthy mid-SoC
		s.RealGridW, s.HubGridW = 0, 0
	})
	f := diagnoseSOC(scFor("battery-wrong-sign"), cons, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (healthy battery probe, genuine compliance)", f.Verdict)
	}
}

// A dead battery probe must never soften a real FAIL: if invExport already
// caught a genuine, un-admitted cap breach (judged off a HEALTHY meter),
// diagnoseSOC's FAIL must stand even though the battery sim was unreachable
// the whole time.
func TestDiagnoseSOC_DeadBatteryProbeNeverSoftensRealFail(t *testing.T) {
	cons := &activeConstraint{Typ: "exportCap", LimW: 0, MRID: "M-bat"}
	s := mkSamples(40, func(i int, s *maySample) {
		s.BatterySimOK = false
		s.RealGridW, s.HubGridW = -3000, -3000 // exporting over the 0 cap, sustained
	})
	f := diagnoseSOC(scFor("battery-wrong-sign"), cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (real cap breach on a healthy meter; probe-gap must not soften it)", f.Verdict)
	}
}

// ── cross-cutting safety audit (applySafetyAudit) ────────────────────────────

// The safety audit's own INV-SOC leg (pastSettling(invSOC(s))) is judged from
// the same battery sim. A scenario whose OWN oracle is clean but where the
// battery sim was dead the whole window must not have the audit silently
// certify "no INV-SOC violation" — applySafetyAudit must downgrade the PASS
// to BLIND.
func TestApplySafetyAudit_DeadBatteryProbeForcesBlind(t *testing.T) {
	cons := &activeConstraint{Typ: "connect", MRID: "M-conn"}
	s := mkSamples(40, func(i int, smp *maySample) {
		smp.DisconnectActive = true
		smp.BatterySimOK = false // audit's INV-SOC leg is blind the whole window
		if float64(i) <= mayConvergeDeadlineS {
			smp.SolarW = 4000
		} else {
			smp.SolarW = 0
		}
	})
	base := diagnoseDisconnect(scFor("grid-disconnect"), cons, s)
	if base.Verdict != "PASS" {
		t.Fatalf("precondition: base disconnect verdict = %s, want PASS", base.Verdict)
	}
	f := applySafetyAudit(base, cons, s)
	if f.Verdict != "BLIND" {
		t.Fatalf("verdict after applySafetyAudit = %s, want BLIND (dead battery probe)", f.Verdict)
	}
}

// A healthy battery probe with nothing wrong must leave applySafetyAudit's
// output bit-identical to escalateForAudit's own contract: PASS stays PASS.
func TestApplySafetyAudit_HealthyBatteryProbeUnchanged(t *testing.T) {
	cons := &activeConstraint{Typ: "connect", MRID: "M-conn"}
	s := mkSamples(40, func(i int, smp *maySample) {
		smp.DisconnectActive = true
		smp.BatterySimOK = true
		smp.BatSimSOC = 55
		smp.BatterySimW = 0
		if float64(i) <= mayConvergeDeadlineS {
			smp.SolarW = 4000
		} else {
			smp.SolarW = 0
		}
	})
	base := diagnoseDisconnect(scFor("grid-disconnect"), cons, s)
	f := applySafetyAudit(base, cons, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (healthy battery probe)", f.Verdict)
	}
}

// applySafetyAudit must never downgrade a FAIL the audit itself escalated to
// (e.g. a sustained INV-CONNECT back-feed) just because the battery probe
// also happened to be dead — the probe-gap check only tightens a PASS.
func TestApplySafetyAudit_NeverDowngradesEscalatedFail(t *testing.T) {
	cons := &activeConstraint{Typ: "none"}
	s := mkSamples(40, func(i int, smp *maySample) {
		smp.DisconnectActive = true
		smp.SolarW = 4000 // sustained back-feed through a disconnect ⇒ INV-CONNECT
		smp.BatterySimOK = false
	})
	base := mayFinding{Verdict: "PASS"} // the scenario's own oracle saw nothing
	f := applySafetyAudit(base, cons, s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (INV-CONNECT escalation must win, dead battery probe must not soften it)", f.Verdict)
	}
}
