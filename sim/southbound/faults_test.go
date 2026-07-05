package sim

import (
	"testing"
	"time"

	"lexa-proto/sunspec"
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

// TestFaultSocRefuse_ZeroesBatteryOutput verifies the effect-time soc_refuse
// injector: the hub's discharge setpoint is ACCEPTED (the control register keeps
// it, so a register readback is fooled) but the pack produces zero power — the
// accept-but-do-nothing fixture for INV-CONVERGE.
func TestFaultSocRefuse_ZeroesBatteryOutput(t *testing.T) {
	const wmaxKwh, wmaxW = 10.0, 5000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateBattery(r, wmaxKwh, wmaxW)
	bs := &BatteryServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmaxW, wmaxKwh: wmaxKwh}
	bs.faults.label = "battery"
	cmd := b.M123Base + sunspec.M123_WMaxLimPct
	out := b.M103Base + sunspec.M103_W

	// Hub commands a +50% discharge (signed, positive=discharge): 2500 W.
	r.Set(b.M123Base+sunspec.M123_Conn, 1)
	r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
	sf := int16(r.Get(b.M123Base + sunspec.M123_WMaxLimPct_SF))
	r.Set(cmd, sunspec.RawFromScaleSigned(50, sf))

	applyHubBatteryWrite(r, b, wmaxW, &bs.faults)
	if got := int16(r.Get(out)); got != 2500 {
		t.Fatalf("baseline output = %dW, want 2500W (commanded discharge)", got)
	}

	// soc_refuse armed: the write still ACKs, the pack produces zero power.
	if err := bs.ApplyFault([]byte(`{"kind":"soc_refuse"}`)); err != nil {
		t.Fatalf("arm soc_refuse: %v", err)
	}
	applyHubBatteryWrite(r, b, wmaxW, &bs.faults)
	if got := int16(r.Get(out)); got != 0 {
		t.Fatalf("output under soc_refuse = %dW, want 0W (pack refused)", got)
	}
	if got := int16(r.Get(cmd)); got == 0 {
		t.Fatal("control register should still hold the accepted setpoint (readback fooled)")
	}

	// Clearing restores the commanded output.
	if err := bs.ApplyFault([]byte(`{"kind":"soc_refuse","clear":true}`)); err != nil {
		t.Fatalf("clear soc_refuse: %v", err)
	}
	applyHubBatteryWrite(r, b, wmaxW, &bs.faults)
	if got := int16(r.Get(out)); got != 2500 {
		t.Fatalf("output after clear = %dW, want 2500W", got)
	}
}

// TestFaultDirectionalDisable verifies charge_disabled / discharge_disabled zero
// only the matching direction (+ discharge / − charge) and pass the other through.
func TestFaultDirectionalDisable(t *testing.T) {
	const discharge, charge = 2500.0, -2500.0
	var fc faultController
	fc.label = "battery"

	// discharge_disabled: a discharge is refused, a charge still flows.
	fc.dischargeDisabled = true
	if got := fc.shapeBatteryW(discharge); got != 0 {
		t.Errorf("discharge_disabled: discharge = %.0fW, want 0", got)
	}
	if got := fc.shapeBatteryW(charge); got != charge {
		t.Errorf("discharge_disabled: charge = %.0fW, want %.0f (pass-through)", got, charge)
	}
	fc.dischargeDisabled = false

	// charge_disabled: a charge is refused, a discharge still flows.
	fc.chargeDisabled = true
	if got := fc.shapeBatteryW(charge); got != 0 {
		t.Errorf("charge_disabled: charge = %.0fW, want 0", got)
	}
	if got := fc.shapeBatteryW(discharge); got != discharge {
		t.Errorf("charge_disabled: discharge = %.0fW, want %.0f (pass-through)", got, discharge)
	}
	fc.chargeDisabled = false

	// Unarmed: both pass through.
	if got := fc.shapeBatteryW(discharge); got != discharge {
		t.Errorf("unarmed discharge = %.0fW, want %.0f", got, discharge)
	}
	if got := fc.shapeBatteryW(charge); got != charge {
		t.Errorf("unarmed charge = %.0fW, want %.0f", got, charge)
	}
}

// TestFaultTransportRead verifies the transport-layer (Modbus read-path) faults:
// nan_sentinel rewrites every value to 0x8000, exception_code returns an error,
// latency delays the read.
func TestFaultTransportRead(t *testing.T) {
	supported := map[FaultKind]bool{FaultNanSentinel: true, FaultLatency: true, FaultModbusException: true}
	fc := &faultController{label: "solar"}
	in := []uint16{100, 200, 300}

	// No fault: pass-through.
	if out, err := fc.transportRead(0, in); err != nil || len(out) != 3 || out[0] != 100 {
		t.Fatalf("passthrough = %v, %v", out, err)
	}

	// nan_sentinel: every value becomes the SunSpec 0x8000 N/A sentinel.
	if err := fc.apply([]byte(`{"kind":"nan_sentinel"}`), supported); err != nil {
		t.Fatalf("arm nan_sentinel: %v", err)
	}
	out, _ := fc.transportRead(0, in)
	for i, v := range out {
		if v != 0x8000 {
			t.Fatalf("nan_sentinel[%d] = %#x, want 0x8000", i, v)
		}
	}
	fc.apply([]byte(`{"kind":"nan_sentinel","clear":true}`), supported)

	// exception_code: returns a Modbus error, restored on clear.
	fc.apply([]byte(`{"kind":"exception_code"}`), supported)
	if _, err := fc.transportRead(0, in); err == nil {
		t.Fatal("exception_code should return an error")
	}
	fc.apply([]byte(`{"kind":"exception_code","clear":true}`), supported)
	if _, err := fc.transportRead(0, in); err != nil {
		t.Fatalf("after clear exception_code: %v", err)
	}

	// latency: the read is delayed by the configured amount.
	fc.apply([]byte(`{"kind":"latency","latency_ms":40}`), supported)
	start := time.Now()
	fc.transportRead(0, in)
	if time.Since(start) < 35*time.Millisecond {
		t.Error("latency fault did not delay the read")
	}
	fc.apply([]byte(`{"kind":"latency","clear":true}`), supported)
}

// TestFaultBadScale verifies bad_scale corrupts ONLY the configured scale-factor
// register (by address, in range) by +1 power of ten, and passes everything else
// through.
func TestFaultBadScale(t *testing.T) {
	supported := map[FaultKind]bool{FaultBadScale: true}
	fc := &faultController{label: "solar"}

	// Unconfigured → arming is rejected (a sim that doesn't wire a SF register).
	if err := fc.apply([]byte(`{"kind":"bad_scale"}`), supported); err == nil {
		t.Fatal("bad_scale without configureScale should error")
	}

	fc.configureScale(10) // W_SF lives at absolute address 10
	if err := fc.apply([]byte(`{"kind":"bad_scale"}`), supported); err != nil {
		t.Fatalf("arm bad_scale: %v", err)
	}

	// A read starting at 8 covers address 10 at offset 2; SF 0 → +1.
	in := []uint16{1000, 1000, 0, 1000}
	out, err := fc.transportRead(8, in)
	if err != nil {
		t.Fatalf("transportRead: %v", err)
	}
	if int16(out[2]) != 1 {
		t.Errorf("SF register = %d, want 1 (corrupted +1)", int16(out[2]))
	}
	if out[0] != 1000 || out[1] != 1000 || out[3] != 1000 {
		t.Errorf("non-SF registers altered: %v", out)
	}

	// A read that does NOT cover the SF register passes through untouched.
	out2, _ := fc.transportRead(20, in)
	for i := range in {
		if out2[i] != in[i] {
			t.Errorf("out-of-range read altered index %d: %d != %d", i, out2[i], in[i])
		}
	}

	fc.apply([]byte(`{"kind":"bad_scale","clear":true}`), supported)
	out3, _ := fc.transportRead(8, in)
	if int16(out3[2]) != 0 {
		t.Errorf("after clear, SF register = %d, want 0 (untouched)", int16(out3[2]))
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

// TestFaultInvertSign verifies the meter's CT-clamp-backwards injector: the
// configured signed registers flip sign on the read path, unconfigured
// registers pass through, the 0x8000 N/A sentinel is left alone, and the fault
// only arms on a sim that wired signed registers.
func TestFaultInvertSign(t *testing.T) {
	supported := map[FaultKind]bool{FaultInvertSign: true}

	// A controller with no signed registers configured rejects the arm.
	bare := &faultController{label: "meter"}
	if err := bare.apply([]byte(`{"kind":"invert_sign"}`), supported); err == nil {
		t.Fatal("invert_sign with no configured registers should error")
	}

	fc := &faultController{label: "meter"}
	fc.configureInvert(10, 12) // signed registers at addrs 10 and 12

	// Unarmed: pass-through.
	neg500 := uint16(0xFE0C) // int16(-500)
	in := []uint16{neg500, 42, 300} // addrs 10,11,12
	if out, _ := fc.transportRead(10, in); int16(out[0]) != -500 || out[1] != 42 || int16(out[2]) != 300 {
		t.Fatalf("unarmed passthrough = %v", out)
	}

	if err := fc.apply([]byte(`{"kind":"invert_sign"}`), supported); err != nil {
		t.Fatalf("arm invert_sign: %v", err)
	}

	// Armed: configured registers flip; the unconfigured one is untouched, and
	// the input slice is not mutated in place.
	out, err := fc.transportRead(10, in)
	if err != nil {
		t.Fatalf("transportRead: %v", err)
	}
	if int16(out[0]) != 500 || out[1] != 42 || int16(out[2]) != -300 {
		t.Errorf("inverted read = [%d %d %d], want [500 42 -300]", int16(out[0]), out[1], int16(out[2]))
	}
	if int16(in[0]) != -500 {
		t.Error("transportRead mutated the caller's slice")
	}

	// A read window that misses every configured register passes through.
	if out, _ := fc.transportRead(100, []uint16{7}); out[0] != 7 {
		t.Errorf("out-of-window read altered: %v", out)
	}

	// The 0x8000 N/A sentinel has no int16 negation — left as-is.
	if out, _ := fc.transportRead(10, []uint16{0x8000}); out[0] != 0x8000 {
		t.Errorf("sentinel inverted to %#x, want 0x8000 untouched", out[0])
	}

	// Clear restores pass-through.
	fc.apply([]byte(`{"kind":"invert_sign","clear":true}`), supported)
	if out, _ := fc.transportRead(10, in); int16(out[0]) != -500 {
		t.Errorf("after clear, read = %d, want -500", int16(out[0]))
	}
}

// TestMeterApplyFault verifies the meter advertises exactly the transport set
// (plus invert_sign) and rejects control-write faults that make no sense for a
// read-only device.
func TestMeterApplyFault(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	base := populateMeter(r, 1000)
	ms := &MeterServer{Server: &Server{Regs: r}, M201Base: base}
	ms.faults.label = "meter"
	ms.faults.configureInvert(base + sunspec.M201_W)

	if err := ms.ApplyFault([]byte(`{"kind":"invert_sign"}`)); err != nil {
		t.Fatalf("invert_sign: %v", err)
	}
	if err := ms.ApplyFault([]byte(`{"kind":"latency","latency_ms":100}`)); err != nil {
		t.Fatalf("latency: %v", err)
	}
	if err := ms.ApplyFault([]byte(`{"kind":"reject_write"}`)); err == nil {
		t.Error("meter should reject reject_write (read-only device)")
	}
	if err := ms.ApplyFault([]byte(`{"kind":"wrong_sign"}`)); err == nil {
		t.Error("meter should reject wrong_sign (that is the battery's write-path fault)")
	}
}
