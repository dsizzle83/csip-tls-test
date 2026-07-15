package main

import (
	"testing"
	"time"
)

// TestFaultProfileReject: with profile_reject armed the charger declines the
// profile (Rejected) and does NOT apply the new limit; clearing restores normal
// accept-and-apply behaviour.
//
// handleSetChargingProfile is the protocol-agnostic core both OCPP 2.0.1's
// and OCPP 1.6's SetChargingProfile handlers delegate to (ocpp201.go /
// ocpp16.go) — exercising it directly here tests the fault-injection logic
// shared by both protocol versions in one place.
func TestFaultProfileReject(t *testing.T) {
	batt := newEVBattery(60000, 50, 230, 32, 1)
	batt.SetCommandedA(16)
	h := &csHandler{batt: batt}

	if err := h.ApplyFault([]byte(`{"kind":"profile_reject"}`)); err != nil {
		t.Fatalf("arm profile_reject: %v", err)
	}
	if accepted := h.handleSetChargingProfile(chargingLimit{LimitA: 8}); accepted {
		t.Fatal("accepted = true, want false (Rejected)")
	}
	if batt.commandedA != 16 {
		t.Fatalf("commandedA = %v, want 16 (rejected profile must not apply)", batt.commandedA)
	}

	if err := h.ApplyFault([]byte(`{"kind":"profile_reject","clear":true}`)); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if accepted := h.handleSetChargingProfile(chargingLimit{LimitA: 8}); !accepted {
		t.Fatal("accepted after clear = false, want true")
	}
	if batt.commandedA != 8 {
		t.Fatalf("commandedA after clear = %v, want 8 (profile applied)", batt.commandedA)
	}
}

// TestFaultApplyNextTx: with apply_next_tx armed the charger ACCEPTS the profile
// but does not apply it to the live session — the EV keeps its prior draw.
func TestFaultApplyNextTx(t *testing.T) {
	batt := newEVBattery(60000, 50, 230, 32, 1)
	batt.SetCommandedA(16)
	h := &csHandler{batt: batt}

	if err := h.ApplyFault([]byte(`{"kind":"apply_next_tx"}`)); err != nil {
		t.Fatalf("arm apply_next_tx: %v", err)
	}
	if accepted := h.handleSetChargingProfile(chargingLimit{LimitA: 8}); !accepted {
		t.Fatal("accepted = false, want true (accept-but-ignore)")
	}
	if batt.commandedA != 16 {
		t.Fatalf("commandedA = %v, want 16 (accepted but not applied to live session)", batt.commandedA)
	}

	if err := h.ApplyFault([]byte(`{"kind":"apply_next_tx","clear":true}`)); err != nil {
		t.Fatalf("clear: %v", err)
	}
	h.handleSetChargingProfile(chargingLimit{LimitA: 8})
	if batt.commandedA != 8 {
		t.Fatalf("commandedA after clear = %v, want 8 (now applied)", batt.commandedA)
	}
}

// TestFaultMinCurrentFloor: a hub command below the floor is silently raised to
// it, so the EV keeps drawing more than commanded.
func TestFaultMinCurrentFloor(t *testing.T) {
	batt := newEVBattery(60000, 50, 230, 32, 1)
	batt.SetCommandedA(4) // hub asks for a low 4 A to shed load
	h := &csHandler{batt: batt}

	if a, _ := batt.Tick(time.Second); a != 4 {
		t.Fatalf("baseline draw = %.1fA, want 4A", a)
	}
	if err := h.ApplyFault([]byte(`{"kind":"min_current_floor"}`)); err != nil { // default 6 A
		t.Fatalf("arm min_current_floor: %v", err)
	}
	if a, _ := batt.Tick(time.Second); a != 6 {
		t.Fatalf("draw under floor = %.1fA, want 6A (floored)", a)
	}
	if err := h.ApplyFault([]byte(`{"kind":"min_current_floor","clear":true}`)); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if a, _ := batt.Tick(time.Second); a != 4 {
		t.Fatalf("draw after clear = %.1fA, want 4A", a)
	}
}

// TestFaultStopMeterAndUnsupported: stop_metervalues toggles the flag; an
// unrecognised kind is rejected (simapi turns it into a 400).
func TestFaultStopMeterAndUnsupported(t *testing.T) {
	h := &csHandler{batt: newEVBattery(60000, 50, 230, 32, 1)}

	if err := h.ApplyFault([]byte(`{"kind":"stop_metervalues"}`)); err != nil {
		t.Fatalf("arm stop_metervalues: %v", err)
	}
	if _, _, stop := h.faults.get(); !stop {
		t.Fatal("stop_metervalues should be armed")
	}
	if err := h.ApplyFault([]byte(`{"kind":"stop_metervalues","clear":true}`)); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, _, stop := h.faults.get(); stop {
		t.Fatal("stop_metervalues should be cleared")
	}
	if err := h.ApplyFault([]byte(`{"kind":"bogus"}`)); err == nil {
		t.Error("unsupported kind should return an error")
	}
}
