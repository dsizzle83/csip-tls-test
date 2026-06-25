package main

import "testing"

// invExport excuses a bounded opening ramp but flags a sustained post-deadline
// breach.
func TestInvExport_ExcusesRampFlagsSustained(t *testing.T) {
	cons := exportCons() // exportCap ≤ 0 W

	// Breach only in the opening settling window (t ≤ deadline): no violation.
	ramp := mkSamples(int(mayConvergeDeadlineS), func(i int, s *maySample) {
		s.RealGridW = -2000 // 2 kW export, over the 0 cap
	})
	if v := invExport(cons, ramp); len(v) != 0 {
		t.Fatalf("opening-ramp breach should be excused, got %d violations", len(v))
	}

	// Breach that persists past the deadline: every late sample is a violation.
	sustained := mkSamples(int(mayConvergeDeadlineS)+20, func(i int, s *maySample) {
		s.RealGridW = -2000
	})
	v := invExport(cons, sustained)
	if len(v) != 19 { // samples at t = deadline+1 .. deadline+19 (strictly > deadline)
		t.Fatalf("sustained breach: got %d violations, want 19", len(v))
	}
	if v[0].Inv != "INV-EXPORT" {
		t.Errorf("violation name = %q, want INV-EXPORT", v[0].Inv)
	}
}

// invConverge flags a sustained breach with no admission, but excuses one the
// hub admitted via CannotComply.
func TestInvConverge_AdmissionClearsViolation(t *testing.T) {
	cons := &activeConstraint{Typ: "genLimit", LimW: 1000, MRID: "M-gen"}

	mut := func(i int, s *maySample) {
		s.SolarW = 4000 // 4 kW, well over the 1 kW gen limit
		s.SolarPossibleW = 6000
	}
	breach := mkSamples(int(mayConvergeDeadlineS)+15, mut)
	if v := invConverge(cons, breach); len(v) == 0 {
		t.Fatal("unadmitted sustained breach should violate INV-CONVERGE")
	} else if v[0].Inv != "INV-CONVERGE" {
		t.Errorf("violation name = %q, want INV-CONVERGE", v[0].Inv)
	}

	admitted := mkSamples(int(mayConvergeDeadlineS)+15, func(i int, s *maySample) {
		mut(i, s)
		s.CannotComply = true // the hub admitted the limit
	})
	if v := invConverge(cons, admitted); len(v) != 0 {
		t.Fatalf("admitted breach should clear INV-CONVERGE, got %d violations", len(v))
	}
}

// invSOC flags discharging at/below the reserve floor and charging at/above the
// ceiling, and passes a healthy mid-SoC timeline.
func TestInvSOC_FlagsWrongWayAtBounds(t *testing.T) {
	// INV-SOC judges SIMULATOR ground truth, not the hub's view.
	// Discharging while empty (the wrong_sign danger): violation.
	empty := mkSamples(10, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 8 // below the 10% reserve floor
		s.BatterySimW = 1500
	})
	if v := invSOC(empty); len(v) == 0 {
		t.Fatal("discharging below the reserve floor should violate INV-SOC")
	} else if v[0].Inv != "INV-SOC" {
		t.Errorf("violation name = %q, want INV-SOC", v[0].Inv)
	}

	// Charging while full: violation.
	full := mkSamples(10, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 97 // above the 95% ceiling
		s.BatterySimW = -1500
	})
	if v := invSOC(full); len(v) == 0 {
		t.Fatal("charging above the ceiling should violate INV-SOC")
	}

	// Healthy mid-SoC discharge: no violation.
	healthy := mkSamples(10, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 55
		s.BatterySimW = 1500
	})
	if v := invSOC(healthy); len(v) != 0 {
		t.Fatalf("mid-SoC discharge should not violate INV-SOC, got %d", len(v))
	}

	// Idle near the floor (|W| below the active threshold): no violation.
	idle := mkSamples(10, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 8
		s.BatterySimW = 10 // below invSocActiveW
	})
	if v := invSOC(idle); len(v) != 0 {
		t.Fatalf("idle battery at the floor should not violate INV-SOC, got %d", len(v))
	}

	// No coherent sim reading: skipped (cannot judge ground truth).
	noSim := mkSamples(10, func(i int, s *maySample) {
		s.BatterySimOK = false
		s.BatSimSOC = 8
		s.BatterySimW = 1500
	})
	if v := invSOC(noSim); len(v) != 0 {
		t.Fatalf("samples without sim truth should be skipped, got %d", len(v))
	}
}

// diagnoseDisconnect: a DER still energizing past the reaction window during a
// disconnect is a FAIL; ceasing within the window is a PASS.
func TestDiagnoseDisconnect_Verdicts(t *testing.T) {
	cons := &activeConstraint{Typ: "connect", MRID: "M-conn"}

	// Solar keeps producing well past the reaction window → unsafe back-feed.
	bad := mkSamples(40, func(i int, s *maySample) {
		s.DisconnectActive = true
		s.SolarW = 4000 // still energizing
	})
	if f := diagnoseDisconnect(scFor("grid-disconnect"), cons, bad); f.Verdict != "FAIL" {
		t.Fatalf("back-feeding verdict = %q, want FAIL", f.Verdict)
	}

	// Solar ceases within the reaction window and holds at 0 → safe.
	good := mkSamples(40, func(i int, s *maySample) {
		s.DisconnectActive = true
		if float64(i) <= mayConvergeDeadlineS {
			s.SolarW = 4000 // reacting during the grace window
		} else {
			s.SolarW = 0
			s.BatteryW = 0
		}
	})
	if f := diagnoseDisconnect(scFor("grid-disconnect"), cons, good); f.Verdict != "PASS" {
		t.Fatalf("ceased-to-energize verdict = %q, want PASS", f.Verdict)
	}

	// Hub never adopts the disconnect → FAIL (upstream of actuation).
	never := mkSamples(20, func(i int, s *maySample) { s.SolarW = 0 })
	if f := diagnoseDisconnect(scFor("grid-disconnect"), cons, never); f.Verdict != "FAIL" {
		t.Fatalf("never-adopted verdict = %q, want FAIL", f.Verdict)
	}
}

func TestInvExpiredControl_FlagsStaleControl(t *testing.T) {
	// Control valid until server-time 1000, but the hub still applies it at
	// server-time 1100 — past validUntil + grace.
	stale := mkSamples(10, func(i int, s *maySample) {
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.ValidUntil, s.WallUnix, s.ClockOffsetS = 1000, 1100, 0
	})
	if v := invExpiredControl(stale); len(v) == 0 {
		t.Fatal("expected INV-EXPIRED for a control retained past validUntil+grace")
	}
	fresh := mkSamples(10, func(i int, s *maySample) {
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.ValidUntil, s.WallUnix = 2000, 1100
	})
	if v := invExpiredControl(fresh); len(v) != 0 {
		t.Errorf("unexpired control flagged: %v", v)
	}
}

func TestInvEVStationMax_FlagsOverdraw(t *testing.T) {
	over := mkSamples(10, func(i int, s *maySample) { s.EvCurrentA, s.EvMaxA = 40, 32 })
	if v := invEVStationMax(over); len(v) == 0 {
		t.Fatal("expected INV-EVMAX for EV drawing over station max")
	}
	ok := mkSamples(10, func(i int, s *maySample) { s.EvCurrentA, s.EvMaxA = 30, 32 })
	if v := invEVStationMax(ok); len(v) != 0 {
		t.Errorf("within-limit EV flagged: %v", v)
	}
}

func TestSafetyAudit_CatchesCrossCutting(t *testing.T) {
	// A SUSTAINED back-feed during a disconnect (past the reaction grace) must be
	// caught by the audit even though no constraint-specific oracle runs here.
	bad := mkSamples(40, func(i int, s *maySample) {
		s.DisconnectActive = true
		s.SolarW = 4000 // still energizing through the whole window
	})
	found := false
	for _, x := range safetyAudit(bad) {
		if x.Inv == "INV-CONNECT" {
			found = true
		}
	}
	if !found {
		t.Fatal("safetyAudit missed the sustained disconnect back-feed (INV-CONNECT)")
	}

	// A bounded cease-to-energize ramp (solar at 0 after the grace) is excused.
	ramp := mkSamples(40, func(i int, s *maySample) {
		s.DisconnectActive = true
		if float64(i) <= mayConvergeDeadlineS {
			s.SolarW = 4000 // ramping down during the grace
		} else {
			s.SolarW = 0
		}
	})
	if v := safetyAudit(ramp); len(v) != 0 {
		t.Errorf("bounded cease-to-energize ramp flagged by audit: %v", v)
	}

	clean := mkSamples(10, func(i int, s *maySample) { s.SolarW = 0; s.BatteryW = 0 })
	if v := safetyAudit(clean); len(v) != 0 {
		t.Errorf("clean timeline flagged: %v", v)
	}
}

// The audit excuses an INV-SOC violation confined to the opening settling window
// (the harness injects an extreme SoC at setup) but still catches a sustained one.
func TestSafetyAudit_ExcusesSettlingSOC(t *testing.T) {
	// Empty pack discharging only during settling (t=0..4 ≤ 30s deadline): excused.
	early := mkSamples(40, func(i int, s *maySample) {
		if i < 5 {
			s.BatterySimOK = true
			s.BatSimSOC = 5
			s.BatterySimW = 1200 // discharging below reserve, but during settling
		}
	})
	if v := safetyAudit(early); len(v) != 0 {
		t.Errorf("settling-window INV-SOC should be excused, got %d: %v", len(v), v)
	}

	// Same drain sustained past the deadline (t=34..39): caught.
	sustained := mkSamples(40, func(i int, s *maySample) {
		if i >= 34 {
			s.BatterySimOK = true
			s.BatSimSOC = 5
			s.BatterySimW = 1200
		}
	})
	if v := safetyAudit(sustained); len(v) == 0 {
		t.Error("a post-settling reserve drain must still be caught by the audit")
	}
}

// diagnoseMalform: surviving + holding the cap is PASS; a hang or an unseated
// safe control is FAIL — the hub's normal curtailment ramp must NOT be mistaken
// for a malform failure.
func TestDiagnoseMalform_Verdicts(t *testing.T) {
	cons := exportCons() // exportCap ≤ 0

	// Reachable and the cap held (no sustained breach) → contained → PASS.
	held := mkSamples(40, func(i int, s *maySample) {
		s.HubReachable = true
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.RealGridW, s.HubGridW = 0, 0
	})
	if f := diagnoseMalform(scFor("malformed-csip"), cons, held); f.Verdict != "PASS" {
		t.Fatalf("contained verdict = %q, want PASS (%s)", f.Verdict, f.Headline)
	}

	// /status stopped answering → panic/hang → FAIL.
	dead := mkSamples(40, func(i int, s *maySample) { s.HubReachable = false })
	if f := diagnoseMalform(scFor("malformed-csip"), cons, dead); f.Verdict != "FAIL" {
		t.Fatalf("unreachable verdict = %q, want FAIL", f.Verdict)
	}

	// Survived but the cap was sustained-breached with no CannotComply → the
	// malform unseated the safe control → FAIL.
	unseated := mkSamples(40, func(i int, s *maySample) {
		s.HubReachable = true
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.RealGridW, s.HubGridW = -3000, -3000 // exporting over the 0 cap, sustained
	})
	if f := diagnoseMalform(scFor("malformed-csip"), cons, unseated); f.Verdict != "FAIL" {
		t.Fatalf("unseated verdict = %q, want FAIL", f.Verdict)
	}

	// Sustained export breach WITH a CannotComply must still FAIL: for an export
	// cap the hub can always curtail PV, so an admission does not excuse exporting
	// freely over a cap it could have held (the malform unseated it).
	unseatedCannot := mkSamples(40, func(i int, s *maySample) {
		s.HubReachable = true
		s.HubAdopted, s.AdoptedTyp = true, "exportCap"
		s.RealGridW, s.HubGridW = -3000, -3000
		s.CannotComply = true
	})
	if f := diagnoseMalform(scFor("malformed-csip"), cons, unseatedCannot); f.Verdict != "FAIL" {
		t.Fatalf("unseated+CannotComply verdict = %q, want FAIL (export cap is always curtailable)", f.Verdict)
	}
}

// diagnoseSOC turns an INV-SOC violation into a FAIL and a clean timeline into a
// PASS.
func TestDiagnoseSOC_Verdicts(t *testing.T) {
	cons := &activeConstraint{Typ: "exportCap", LimW: 0, MRID: "M-bat"}

	bad := mkSamples(20, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 7
		s.BatterySimW = 1800 // discharging while empty (simulator ground truth)
	})
	if f := diagnoseSOC(scFor("battery-wrong-sign"), cons, bad); f.Verdict != "FAIL" {
		t.Fatalf("wrong-way discharge verdict = %q, want FAIL", f.Verdict)
	}

	good := mkSamples(20, func(i int, s *maySample) {
		s.BatterySimOK = true
		s.BatSimSOC = 60
		s.BatterySimW = -1200 // charging, healthy mid SoC
	})
	if f := diagnoseSOC(scFor("battery-wrong-sign"), cons, good); f.Verdict != "PASS" {
		t.Fatalf("healthy charge verdict = %q, want PASS", f.Verdict)
	}

	// SoC stays healthy, but the wrong-way discharge blows the active export cap
	// with no CannotComply — diagnoseSOC must also judge the cap, not just INV-SOC,
	// so this is a FAIL rather than a false PASS (T past the settling deadline).
	capBlown := mkSamples(40, func(i int, s *maySample) {
		s.BatSOC = 60       // no INV-SOC violation
		s.BatteryW = 1500   // discharging the wrong way
		s.RealGridW = -3000 // exporting over the 0 cap
		s.HubGridW = -3000
	})
	if f := diagnoseSOC(scFor("battery-wrong-sign"), cons, capBlown); f.Verdict != "FAIL" {
		t.Fatalf("cap-blowout w/o CannotComply verdict = %q, want FAIL", f.Verdict)
	}

	// Same cap breach, but the hub admitted it via CannotComply → DEGRADED.
	capAdmitted := mkSamples(40, func(i int, s *maySample) {
		s.BatSOC = 60
		s.BatteryW = 1500
		s.RealGridW = -3000
		s.HubGridW = -3000
		s.CannotComply = true
	})
	if f := diagnoseSOC(scFor("battery-wrong-sign"), cons, capAdmitted); f.Verdict != "DEGRADED" {
		t.Fatalf("cap-blowout w/ CannotComply verdict = %q, want DEGRADED", f.Verdict)
	}
}
