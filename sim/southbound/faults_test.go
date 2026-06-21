package sim

import (
	"testing"

	"csip-tls-test/internal/southbound/sunspec"
)

// TestFaultRejectWrite_DropsControlValue verifies the reject_write injector: a
// control write is ACKed at the Modbus layer (the interceptor reports handled,
// apply=false) but the control register keeps its prior value, while any other
// register in the same write still lands. This is the accept-but-ignore fixture
// for INV-CONVERGE.
func TestFaultRejectWrite_DropsControlValue(t *testing.T) {
	const wmax = 8000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateSolar(r, wmax)
	ss := &SolarServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmax}
	cmd := b.M123Base + sunspec.M123_WMaxLimPct
	ena := b.M123Base + sunspec.M123_WMaxLimPct_Ena

	// Baseline: 100% ceiling (10000), enabled.
	if got := r.Get(cmd); got != 10000 {
		t.Fatalf("baseline WMaxLimPct = %d, want 10000", got)
	}

	if err := ss.ApplyFault([]byte(`{"kind":"reject_write"}`)); err != nil {
		t.Fatalf("arm reject_write: %v", err)
	}

	// Hub writes a 25% curtailment AND re-asserts Ena in the same multi-register
	// write. The interceptor must drop the WMaxLimPct change but keep Ena.
	curtail := sunspec.RawFromScaleSigned(25, -2)
	if applied := ss.interceptWrite(cmd, []uint16{curtail, 1}); applied {
		t.Fatal("interceptWrite returned apply=true; reject_write should handle the write")
	}
	if got := r.Get(cmd); got != 10000 {
		t.Fatalf("WMaxLimPct after rejected write = %d, want 10000 (command ignored)", got)
	}
	if got := r.Get(ena); got != 1 {
		t.Fatalf("Ena after rejected write = %d, want 1 (non-control reg must still land)", got)
	}

	// Clearing restores pass-through.
	if err := ss.ApplyFault([]byte(`{"kind":"reject_write","clear":true}`)); err != nil {
		t.Fatalf("clear reject_write: %v", err)
	}
	if applied := ss.interceptWrite(cmd, []uint16{curtail}); !applied {
		t.Fatal("after clear, interceptWrite should pass through (apply=true)")
	}
}

// TestFaultWrongSign_InvertsCommand verifies the wrong_sign injector on the
// battery: a signed WMaxLimPct command (negative=charge) is applied with its
// sign flipped, so a commanded charge lands as a discharge. This is the fixture
// for INV-SOC.
func TestFaultWrongSign_InvertsCommand(t *testing.T) {
	const wmaxKwh, wmaxW = 10.0, 5000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateBattery(r, wmaxKwh, wmaxW)
	bs := &BatteryServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmaxW, wmaxKwh: wmaxKwh}
	cmd := b.M123Base + sunspec.M123_WMaxLimPct

	if err := bs.ApplyFault([]byte(`{"kind":"wrong_sign"}`)); err != nil {
		t.Fatalf("arm wrong_sign: %v", err)
	}

	// Hub commands a 40% charge: signed −40% at SF −2 → raw −4000.
	charge := sunspec.RawFromScaleSigned(-40, -2)
	if applied := bs.interceptWrite(cmd, []uint16{charge}); applied {
		t.Fatal("interceptWrite returned apply=true; wrong_sign should handle the write")
	}
	got := int16(r.Get(cmd))
	want := -int16(charge) // sign flipped → positive (discharge)
	if got != want {
		t.Fatalf("WMaxLimPct after wrong_sign = %d, want %d (sign inverted)", got, want)
	}
	if want <= 0 {
		t.Fatalf("test setup: flipped command %d should be a positive (discharge) value", want)
	}
}

// TestBatteryFaults_UnsupportedKind verifies a sim rejects a kind it does not
// advertise (the battery does not support ack_before_effect), which simapi
// turns into a 400.
func TestBatteryFaults_UnsupportedKind(t *testing.T) {
	const wmaxKwh, wmaxW = 10.0, 5000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateBattery(r, wmaxKwh, wmaxW)
	bs := &BatteryServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmaxW, wmaxKwh: wmaxKwh}

	if err := bs.ApplyFault([]byte(`{"kind":"ack_before_effect","delay_s":5}`)); err == nil {
		t.Error("battery should reject ack_before_effect (not in its supported set)")
	}
	if err := bs.ApplyFault([]byte(`{"kind":"bogus"}`)); err == nil {
		t.Error("unsupported fault kind should return an error")
	}
}
