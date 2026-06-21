package sim

import (
	"testing"
	"time"

	"csip-tls-test/internal/southbound/sunspec"
)

// TestFaultRampLimit_SlewsTowardCommand verifies the effect-time ramp_limit
// injector: the honoured output ceiling slews toward the commanded ceiling at the
// configured rate using elapsed wall time, rather than snapping to it — and
// reaches the command without overshoot. Uses an injected clock for determinism.
func TestFaultRampLimit_SlewsTowardCommand(t *testing.T) {
	supported := map[FaultKind]bool{FaultRampLimit: true}
	fc := &faultController{label: "solar"}
	var now time.Time
	fc.nowFn = func() time.Time { return now }

	// Unarmed: identity pass-through.
	if got := fc.effectiveCeilW(3000); got != 3000 {
		t.Fatalf("unarmed effectiveCeilW = %v, want 3000 (identity)", got)
	}

	// A missing rate is rejected.
	if err := fc.apply([]byte(`{"kind":"ramp_limit"}`), supported); err == nil {
		t.Fatal("ramp_limit with no rate should error")
	}

	if err := fc.apply([]byte(`{"kind":"ramp_limit","max_ramp_w_per_s":100}`), supported); err != nil {
		t.Fatalf("arm ramp_limit: %v", err)
	}
	// First call after arming seeds at the current command — no jump.
	if got := fc.effectiveCeilW(5000); got != 5000 {
		t.Fatalf("seed effectiveCeilW = %v, want 5000 (no jump on arm)", got)
	}
	// Command drops to 1000 W. After 10 s at 100 W/s the honoured ceiling slews
	// down 1000 W to 4000 — not a snap to 1000.
	now = now.Add(10 * time.Second)
	if got := fc.effectiveCeilW(1000); got != 4000 {
		t.Fatalf("after 10s slew = %v, want 4000 (5000 - 100*10)", got)
	}
	// After enough time it reaches the command and clamps (no overshoot below it).
	now = now.Add(40 * time.Second)
	if got := fc.effectiveCeilW(1000); got != 1000 {
		t.Fatalf("after 50s total = %v, want 1000 (reached command, clamped)", got)
	}
	// Clearing restores identity.
	if err := fc.apply([]byte(`{"kind":"ramp_limit","clear":true}`), supported); err != nil {
		t.Fatalf("clear ramp_limit: %v", err)
	}
	if got := fc.effectiveCeilW(2500); got != 2500 {
		t.Fatalf("after clear = %v, want identity 2500", got)
	}
}

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

// TestFaultEnableGate_LandsValueButGatesEnable verifies the enable_gate injector:
// a curtailment write lands in the WMaxLimPct register (so a hub that verifies by
// reading the value back is fooled), but the enable flag is forced off so the
// limit is never enforced — and a later enable-only write cannot re-open it. This
// is the readback-looks-compliant fixture for INV-CONVERGE.
func TestFaultEnableGate_LandsValueButGatesEnable(t *testing.T) {
	const wmax = 8000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateSolar(r, wmax)
	ss := &SolarServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmax}
	cmd := b.M123Base + sunspec.M123_WMaxLimPct
	ena := b.M123Base + sunspec.M123_WMaxLimPct_Ena
	ss.faults.configureGate(ena) // NewSolarServer does this; the bare struct does not

	if err := ss.ApplyFault([]byte(`{"kind":"enable_gate"}`)); err != nil {
		t.Fatalf("arm enable_gate: %v", err)
	}

	// Hub writes a 25% curtailment and asserts Ena=1 in the same multi-register
	// write. The value must land (readback shows it) but Ena must be forced to 0.
	curtail := sunspec.RawFromScaleSigned(25, -2)
	if applied := ss.interceptWrite(cmd, []uint16{curtail, 1}); applied {
		t.Fatal("interceptWrite returned apply=true; enable_gate should handle the write")
	}
	if got := r.Get(cmd); got != curtail {
		t.Fatalf("WMaxLimPct after gated write = %d, want %d (value must land for readback)", int16(got), int16(curtail))
	}
	if got := r.Get(ena); got != 0 {
		t.Fatalf("Ena after gated write = %d, want 0 (limit must not be enforced)", got)
	}

	// A separate enable-only write must not re-open the gate.
	if applied := ss.interceptWrite(ena, []uint16{1}); applied {
		t.Fatal("interceptWrite returned apply=true on enable-only write; gate should hold it")
	}
	if got := r.Get(ena); got != 0 {
		t.Fatalf("Ena after enable-only write = %d, want 0 (gate must hold it off)", got)
	}

	// Clearing restores pass-through: a fresh enable write now lands.
	if err := ss.ApplyFault([]byte(`{"kind":"enable_gate","clear":true}`)); err != nil {
		t.Fatalf("clear enable_gate: %v", err)
	}
	if applied := ss.interceptWrite(ena, []uint16{1}); !applied {
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
