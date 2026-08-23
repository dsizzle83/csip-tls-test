package sim

// solar_adv_test.go — unit tests for the advanced-DER (7xx) solar surface:
// model 701 encoding, the 705/706/711/712 curve-adopt handshake (success AND
// the curve_adopt_lies divergence), the 704 fixed-PF measured effect (and its
// pf_ack_ignore accept-but-ignore), the raise_alarm bitfield knob, and — since
// IW15-001/002 — the 704 active-power SETPOINT and the 702 rating/setting split.

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	modbuslib "github.com/simonvetter/modbus"
	"lexa-proto/sunspec"
)

// newAdvSolar builds an advanced solar register bank + SolarServer wired for
// unit tests WITHOUT a live Modbus listener (mirrors the faults_test.go bare
// struct pattern), so tests drive the register map and the effect functions
// directly.
func newAdvSolar(t *testing.T, wmax float64) *SolarServer {
	t.Helper()
	return newAdvSolarModels(t, wmax, false)
}

// newAdvSolarModels is newAdvSolar with the trip-model (707-710) choice made
// explicit, so a test can build either image without a listener.
func newAdvSolarModels(t *testing.T, wmax float64, withTrip bool) *SolarServer {
	t.Helper()
	return newAdvSolarOpts(t, wmax, AdvancedOptions{Trip: withTrip})
}

// newAdvSolarOpts builds a listener-less advanced sim under an explicit
// construction posture — the entry point for the curve-axis tests, which have
// to compare two devices that differ only in a declared scale factor.
func newAdvSolarOpts(t *testing.T, wmax float64, opts AdvancedOptions) *SolarServer {
	t.Helper()
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	varRating := wmax * 0.44
	bases, adv := populateSolarAdvanced(r, wmax, varRating, "", opts)
	ss := &SolarServer{
		Server: &Server{Regs: r}, bases: bases, wmaxW: wmax,
		advanced: true, adv: adv, varRating: varRating,
	}
	ss.faults.label = "solar"
	return ss
}

// curveByModel returns the curveBlock for a model id.
func (ss *SolarServer) curveByModel(id uint16) curveBlock {
	for _, cb := range ss.adv.Curves {
		if cb.id == id {
			return cb
		}
	}
	panic("no such curve model")
}

// TestAdv701RoundTrip verifies advMirror701 encodes the 103 physical state into
// model 701 such that the real Parse701 decodes coherent engineering values.
func TestAdv701RoundTrip(t *testing.T) {
	ss := newAdvSolar(t, 6000)
	r := ss.Regs
	b := ss.bases

	// Drive a known 103 physical state (3200 W, 241.0 V, 60.00 Hz), then mirror.
	r.Set(b.M103Base+sunspec.M103_W, uint16(int16(3200)))
	r.Set(b.M103Base+sunspec.M103_PhVphA, 2410) // V_SF=-1 → 241.0 V
	r.Set(b.M103Base+sunspec.M103_Hz, 6000)     // Hz_SF=-2 → 60.00 Hz
	r.Set(b.M103Base+sunspec.M103_St, 4)
	ss.advSync()

	m := sunspec.Parse701(readSlice(r, ss.adv.M701, ss.adv.M701Len))
	if m.W != 3200 {
		t.Errorf("701 W = %v, want 3200", m.W)
	}
	if m.LNV != 241.0 {
		t.Errorf("701 LNV = %v, want 241.0", m.LNV)
	}
	if m.Hz != 60.0 {
		t.Errorf("701 Hz = %v, want 60.00", m.Hz)
	}
	if m.ConnSt != 1 || m.St != 1 {
		t.Errorf("701 St=%d ConnSt=%d, want 1/1 (on, connected)", m.St, m.ConnSt)
	}
	if m.Alrm != 0 {
		t.Errorf("701 Alrm = %#x, want 0 (no alarm)", m.Alrm)
	}
}

// TestAdv701AccumulatorsMirrorTheAnimatedWh pins the fix for the gap the
// measurement-freshness design named: advMirror701 never wrote TotWhInj/
// TotWhAbs at all, so 701 always read them as an IMPLEMENTED accumulator
// (Tuint64's not-implemented sentinel is all-ones, not zero) that never moved
// — indistinguishable, over Modbus, from a device with freeze_block armed. S1
// (a hub comparing ΔTotWhInj against ∫W dt) had nothing real to check on the
// bench without this. TotWhInj must mirror the SAME Wh accumulator the legacy
// sim has always animated (M122's ActWh, advanced every running solarStep
// tick), and TotWhAbs must stay a truthful 0 — a PV inverter only injects.
func TestAdv701AccumulatorsMirrorTheAnimatedWh(t *testing.T) {
	ss := newAdvSolar(t, 6000)
	r, b, adv := ss.Regs, ss.bases, ss.adv

	var whAcc uint16
	for i := 0; i < 3; i++ {
		solarStep(r, ss.wmaxW, b, false /*running*/, 0 /*simTime*/, 0 /*cloud*/, false /*night*/, &ss.faults, &whAcc)
		advMirror701(r, b, adv, ss.wmaxW, ss.varRating, &ss.faults)
	}

	wantWh := float64(whAcc)
	if wantWh == 0 {
		t.Fatal("fixture bug: the Wh accumulator never advanced — the test proves nothing")
	}
	m701 := sunspec.Parse701(readSlice(r, adv.M701, adv.M701Len))
	if m701.TotWhInj != wantWh {
		t.Errorf("701 TotWhInj = %v, want %v (mirrored from the M122 ActWh accumulator solarStep just advanced)",
			m701.TotWhInj, wantWh)
	}
	if m701.TotWhAbs != 0 {
		t.Errorf("701 TotWhAbs = %v, want 0 — a PV inverter only injects", m701.TotWhAbs)
	}

	// A second wave of ticks must move it FURTHER still — pinning "mirrors the
	// LIVE accumulator" against a fix that only seeded it once at startup and
	// then left it as stale as the bug it replaces.
	prev := m701.TotWhInj
	for i := 0; i < 3; i++ {
		solarStep(r, ss.wmaxW, b, false, 0, 0, false, &ss.faults, &whAcc)
		advMirror701(r, b, adv, ss.wmaxW, ss.varRating, &ss.faults)
	}
	m701 = sunspec.Parse701(readSlice(r, adv.M701, adv.M701Len))
	if m701.TotWhInj <= prev {
		t.Errorf("701 TotWhInj did not advance on a second wave of ticks: %v -> %v", prev, m701.TotWhInj)
	}
}

// TestAdvSolarM103WHAlsoAnimates is the advanced-sim half of bench gap 4's
// fix (see TestSolarStep_103WHAccumulatorTracksIntegratedEnergy for the plain
// leg): solarStep is the SAME shared function both solar constructors
// animate through, so the advanced sim's own M103 block — its legacy 10x
// mirror, served alongside 701 — must also get a genuinely moving WH
// accumulator, not just the plain (non-advanced) sim. Before the fix neither
// leg wrote it; this pins that the advanced sim isn't a second, separately-
// broken copy of the same gap.
func TestAdvSolarM103WHAlsoAnimates(t *testing.T) {
	ss := newAdvSolar(t, 6000)
	r, b := ss.Regs, ss.bases
	whAddr := b.M103Base + sunspec.M103_WH
	sfAddr := b.M103Base + sunspec.M103_WH_SF

	readWh := func() float64 {
		raw := uint32(r.Get(whAddr))<<16 | uint32(r.Get(whAddr+1))
		return float64(raw) * math.Pow10(int(int16(r.Get(sfAddr))))
	}
	if wh := readWh(); wh != 0 {
		t.Fatalf("fixture assumption: 103 WH starts at 0, got %v", wh)
	}

	var whAcc uint16
	for i := 0; i < 3; i++ {
		solarStep(r, ss.wmaxW, b, false, 0, 0, false, &ss.faults, &whAcc)
	}
	if whAcc == 0 {
		t.Fatal("fixture bug: the Wh accumulator never advanced — the test proves nothing")
	}
	if got, want := readWh(), float64(whAcc); got != want {
		t.Errorf("advanced sim's 103 WH = %v, want %v — it must animate on THIS leg too, not just the "+
			"non-advanced sim", got, want)
	}
}

// TestAdv701BecalmedButLiveIsNotIndistinguishableFromFrozen is bench row #4,
// "becalmed-but-live", read through 701 — the model a freshness-aware hub
// actually prefers. Night is NOT a fault: it collapses W/VA/VAr to a genuine
// 0 and halts TotWhInj exactly as freeze_block would, but St/InvSt honestly
// report the device as connected-and-sleeping (not off, not frozen) and Hz
// keeps moving tick to tick. That distinction — a quiescent-but-live device
// vs. a stuck one — is the entire content of the false-positive row; a
// gateway that cannot tell them apart flags every nightfall as suspect.
func TestAdv701BecalmedButLiveIsNotIndistinguishableFromFrozen(t *testing.T) {
	ss := newAdvSolar(t, 8000)
	r, b, adv := ss.Regs, ss.bases, ss.adv

	var whAcc uint16
	solarStep(r, ss.wmaxW, b, false, 0, 0, false, &ss.faults, &whAcc)
	advMirror701(r, b, adv, ss.wmaxW, ss.varRating, &ss.faults)
	m701 := sunspec.Parse701(readSlice(r, adv.M701, adv.M701Len))
	if m701.W <= 0 {
		t.Fatalf("fixture bug: daytime 701 W = %v, want > 0", m701.W)
	}
	dayTotWhInj := m701.TotWhInj

	var hz []float64
	for i, st := range []float64{100, 200, 300} {
		solarStep(r, ss.wmaxW, b, false, st, 0, true /*night*/, &ss.faults, &whAcc)
		advMirror701(r, b, adv, ss.wmaxW, ss.varRating, &ss.faults)
		m701 = sunspec.Parse701(readSlice(r, adv.M701, adv.M701Len))
		if m701.W != 0 {
			t.Errorf("tick %d: 701 W = %v, want 0", i, m701.W)
		}
		if m701.TotWhInj != dayTotWhInj {
			t.Errorf("tick %d: 701 TotWhInj moved from %v to %v overnight — it must FLATTEN, not advance",
				i, dayTotWhInj, m701.TotWhInj)
		}
		if m701.InvSt != 2 {
			t.Errorf("tick %d: 701 InvSt = %d, want 2 (sleeping) — the device must report its own state "+
				"honestly, not merely go quiet", i, m701.InvSt)
		}
		if m701.St != 1 || m701.ConnSt != 1 {
			t.Errorf("tick %d: 701 St=%d ConnSt=%d, want 1/1 — a becalmed device is still ON and CONNECTED, "+
				"which is what tells a hub apart from an actually disconnected one", i, m701.St, m701.ConnSt)
		}
		hz = append(hz, m701.Hz)
	}
	if hz[0] == hz[1] && hz[1] == hz[2] {
		t.Error("701 Hz did not move across becalmed ticks — a live-but-quiescent device must still look " +
			"alive on its volatile-class points, or it is indistinguishable from freeze_block")
	}
}

// TestAdvRaiseAlarm verifies the raise_alarm fault sets the 701 Alrm bitfield
// that the animation re-stamps each tick, and clearing returns it to 0 (the RTN
// edge).
func TestAdvRaiseAlarm(t *testing.T) {
	ss := newAdvSolar(t, 5000)
	const acOverVolt = uint32(1 << 10) // hub-mapped 701 Alrm bit (logevent.go)

	if err := ss.ApplyFault([]byte(`{"kind":"raise_alarm","bits":1024}`)); err != nil {
		t.Fatalf("arm raise_alarm: %v", err)
	}
	ss.advSync()
	if got := sunspec.Parse701(readSlice(ss.Regs, ss.adv.M701, ss.adv.M701Len)).Alrm; got != acOverVolt {
		t.Errorf("Alrm after raise = %#x, want %#x", got, acOverVolt)
	}

	if err := ss.ApplyFault([]byte(`{"kind":"raise_alarm","clear":true}`)); err != nil {
		t.Fatalf("clear raise_alarm: %v", err)
	}
	ss.advSync()
	if got := sunspec.Parse701(readSlice(ss.Regs, ss.adv.M701, ss.adv.M701Len)).Alrm; got != 0 {
		t.Errorf("Alrm after clear = %#x, want 0", got)
	}
}

// TestAdvRaiseAlarmCouplesVoltage pins advCoupledVoltHz's job: a raise_alarm
// bit naming a grid-interface voltage condition must not be a bare flag —
// the SAME 701 read has to carry a voltage that actually sits outside the
// condition's threshold, on every voltage point (LNV, both other phases, and
// all three line-to-line points, per advMirror701's balanced-three-phase
// scaling), and clearing it must restore exactly the value the 103 model
// underneath was reporting all along (never a value this fault remembers).
func TestAdvRaiseAlarmCouplesVoltage(t *testing.T) {
	ss := newAdvSolar(t, 5000)
	r, b := ss.Regs, ss.bases
	// Known 103 physical state: 241.0 V nominal (V_SF=-1), 60.00 Hz.
	r.Set(b.M103Base+sunspec.M103_PhVphA, 2410)
	r.Set(b.M103Base+sunspec.M103_PhVphB, 2410)
	r.Set(b.M103Base+sunspec.M103_PhVphC, 2410)
	vll := uint16(math.Round(2410 * math.Sqrt(3)))
	r.Set(b.M103Base+sunspec.M103_PPVphAB, vll)
	r.Set(b.M103Base+sunspec.M103_PPVphBC, vll)
	r.Set(b.M103Base+sunspec.M103_PPVphCA, vll)
	r.Set(b.M103Base+sunspec.M103_Hz, 6000)

	const underVolt = uint32(1 << 11) // hub-mapped AC_UNDER_VOLT (logevent.go)
	if err := ss.ApplyFault([]byte(`{"kind":"raise_alarm","bits":2048}`)); err != nil {
		t.Fatalf("arm raise_alarm: %v", err)
	}
	ss.advSync()
	m := sunspec.Parse701(readSlice(r, ss.adv.M701, ss.adv.M701Len))
	if m.Alrm != underVolt {
		t.Fatalf("Alrm = %#x, want %#x", m.Alrm, underVolt)
	}
	if m.Hz != 60.0 {
		t.Errorf("Hz = %v, want 60.00 (frequency is untouched by a voltage-only alarm)", m.Hz)
	}
	const wantV = 205.0 // < 211.2 V (0.88 pu of 240 V nominal) — see advCoupledVoltHz
	for name, got := range map[string]float64{
		"LNV": m.LNV, "VL1": m.VL1, "VL2": m.VL2, "VL3": m.VL3,
	} {
		if !approx(got, wantV, 0.05) {
			t.Errorf("%s = %v, want ~%v (under the CSIP UNDER_VOLTAGE threshold)", name, got, wantV)
		}
	}
	wantLL := wantV * math.Sqrt(3)
	for name, got := range map[string]float64{
		"LLV": m.LLV, "VL1L2": m.VL1L2, "VL2L3": m.VL2L3, "VL3L1": m.VL3L1,
	} {
		if !approx(got, wantLL, 0.5) {
			t.Errorf("%s = %v, want ~%v (sqrt(3) x the derated phase voltage, same relation Inject "+
				"\"V_V\" applies)", name, got, wantLL)
		}
	}

	if err := ss.ApplyFault([]byte(`{"kind":"raise_alarm","clear":true}`)); err != nil {
		t.Fatalf("clear raise_alarm: %v", err)
	}
	ss.advSync()
	m = sunspec.Parse701(readSlice(r, ss.adv.M701, ss.adv.M701Len))
	if m.Alrm != 0 {
		t.Errorf("Alrm after clear = %#x, want 0", m.Alrm)
	}
	if !approx(m.LNV, 241.0, 0.05) {
		t.Errorf("LNV after clear = %v, want ~241.0 (the 103 model's own reading, not a value the "+
			"fault remembered)", m.LNV)
	}
}

// TestAdvRaiseAlarmCouplesFrequency is TestAdvRaiseAlarmCouplesVoltage's
// frequency counterpart: OVER_FREQUENCY/UNDER_FREQUENCY must derate Hz and
// leave voltage untouched, independently of the voltage bits.
func TestAdvRaiseAlarmCouplesFrequency(t *testing.T) {
	cases := []struct {
		name   string
		bits   string
		alrm   uint32
		wantHz float64
	}{
		{"under", `{"kind":"raise_alarm","bits":512}`, 1 << 9, 58.0}, // < 58.5 Hz
		{"over", `{"kind":"raise_alarm","bits":256}`, 1 << 8, 61.5},  // > 61.2 Hz
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ss := newAdvSolar(t, 5000)
			r, b := ss.Regs, ss.bases
			r.Set(b.M103Base+sunspec.M103_PhVphA, 2400)
			r.Set(b.M103Base+sunspec.M103_Hz, 6000)

			if err := ss.ApplyFault([]byte(c.bits)); err != nil {
				t.Fatalf("arm raise_alarm: %v", err)
			}
			ss.advSync()
			m := sunspec.Parse701(readSlice(r, ss.adv.M701, ss.adv.M701Len))
			if m.Alrm != c.alrm {
				t.Fatalf("Alrm = %#x, want %#x", m.Alrm, c.alrm)
			}
			if !approx(m.Hz, c.wantHz, 0.05) {
				t.Errorf("Hz = %v, want ~%v", m.Hz, c.wantHz)
			}
			if !approx(m.LNV, 240.0, 0.05) {
				t.Errorf("LNV = %v, want ~240.0 (voltage is untouched by a frequency-only alarm)", m.LNV)
			}
		})
	}
}

// TestAdvCoupledVoltHzNoFaultByteIdentical pins advCoupledVoltHz's no-op
// contract directly: with no mapped bit armed — including a manual-shutdown
// or any other UNmapped Alrm bit, which this function deliberately does not
// couple to anything — it must return volt/hz exactly unchanged, so the
// no-fault world (and every armed-but-unmapped-bit world) stays
// byte-identical to the pre-coupling behaviour.
func TestAdvCoupledVoltHzNoFaultByteIdentical(t *testing.T) {
	const (
		volt = 240.0
		hz   = 60.0
	)
	cases := []struct {
		name string
		bits uint32
	}{
		{"no alarm", 0},
		{"manual shutdown only (unmapped by this function)", 1 << 6},
		{"ground fault only (unmapped)", 1 << 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotV, gotHz := advCoupledVoltHz(c.bits, volt, hz)
			if gotV != volt || gotHz != hz {
				t.Errorf("advCoupledVoltHz(%#x, %v, %v) = %v, %v, want unchanged",
					c.bits, volt, hz, gotV, gotHz)
			}
		})
	}
}

// stageAndAdopt encodes curve c into the 705 staging slot (index 1) then drives
// the AdptCrvReq write through interceptAdopt, exactly as the hub's derbase
// adopt does (write staging, request adopt).
func stageVoltVar(t *testing.T, ss *SolarServer, c sunspec.VoltVarCurve) {
	t.Helper()
	cb := ss.curveByModel(sunspec.ModelDERVoltVar)
	regs := readSlice(ss.Regs, cb.base, cb.hdr.Len()+advNCrv*cb.stride)
	start, end, err := sunspec.Encode705Curve(regs, 1, c)
	if err != nil {
		t.Fatalf("encode staging curve: %v", err)
	}
	// Write the staged range back into the map (the staging-curve Modbus write).
	for i := start; i < end; i++ {
		ss.Regs.Set(cb.base+uint16(i), regs[i])
	}
	// The AdptCrvReq write (1-based staging index = 2) triggers the handshake.
	if !ss.interceptAdopt(cb.base+uint16(cb.reqOff), []uint16{2}) {
		t.Fatal("interceptAdopt did not handle the AdptCrvReq write")
	}
}

func readLiveVoltVar(t *testing.T, ss *SolarServer) sunspec.VoltVarCurve {
	t.Helper()
	cb := ss.curveByModel(sunspec.ModelDERVoltVar)
	regs := readSlice(ss.Regs, cb.base, cb.hdr.Len()+advNCrv*cb.stride)
	c, err := sunspec.Parse705Curve(regs, 0)
	if err != nil {
		t.Fatalf("parse live curve: %v", err)
	}
	return c
}

// TestAdvCurveAdoptSuccess verifies the correct-behaviour adopt: after
// AdptCrvReq the result is COMPLETED and the read-only live curve reflects the
// staged points.
func TestAdvCurveAdoptSuccess(t *testing.T) {
	ss := newAdvSolar(t, 5000)
	cb := ss.curveByModel(sunspec.ModelDERVoltVar)

	want := sunspec.VoltVarCurve{
		DeptRef: 1, Pri: 1,
		Points: []sunspec.VVPoint{{V: 230, Var: 30}, {V: 240, Var: 0}, {V: 250, Var: -30}},
	}
	stageVoltVar(t, ss, want)

	if got := ss.Regs.Get(cb.base + uint16(cb.rsltOff)); got != sunspec.AdptCompleted {
		t.Fatalf("AdptCrvRslt = %d, want COMPLETED(%d)", got, sunspec.AdptCompleted)
	}
	live := readLiveVoltVar(t, ss)
	if !live.ReadOnly {
		t.Error("adopted live curve should remain read-only")
	}
	if len(live.Points) != len(want.Points) {
		t.Fatalf("live curve has %d points, want %d", len(live.Points), len(want.Points))
	}
	for i, p := range want.Points {
		if live.Points[i] != p {
			t.Errorf("live point[%d] = %+v, want %+v", i, live.Points[i], p)
		}
	}
}

// TestAdvCurveAdoptLies is the INV-ADV-READBACK fixture: with curve_adopt_lies
// armed the handshake still reports COMPLETED, but the live curve stays at its
// OLD points — the "handshake says done, readback disagrees" divergence the
// WP-10 reconciler must catch as adopt_state=diverged.
func TestAdvCurveAdoptLies(t *testing.T) {
	ss := newAdvSolar(t, 5000)
	cb := ss.curveByModel(sunspec.ModelDERVoltVar)

	before := readLiveVoltVar(t, ss)

	if err := ss.ApplyFault([]byte(`{"kind":"curve_adopt_lies"}`)); err != nil {
		t.Fatalf("arm curve_adopt_lies: %v", err)
	}
	stageVoltVar(t, ss, sunspec.VoltVarCurve{
		DeptRef: 1, Pri: 1,
		Points: []sunspec.VVPoint{{V: 235, Var: 50}, {V: 245, Var: -50}},
	})

	// The handshake LIES: COMPLETED reported...
	if got := ss.Regs.Get(cb.base + uint16(cb.rsltOff)); got != sunspec.AdptCompleted {
		t.Fatalf("AdptCrvRslt = %d, want COMPLETED (the lie)", got)
	}
	// ...but the live curve is unchanged (stale readback → diverged).
	after := readLiveVoltVar(t, ss)
	if len(after.Points) != len(before.Points) {
		t.Fatalf("live curve changed under curve_adopt_lies: %d → %d points", len(before.Points), len(after.Points))
	}
	for i := range before.Points {
		if after.Points[i] != before.Points[i] {
			t.Errorf("live point[%d] moved under curve_adopt_lies: %+v → %+v", i, before.Points[i], after.Points[i])
		}
	}

	// Clearing restores honest adoption.
	if err := ss.ApplyFault([]byte(`{"kind":"curve_adopt_lies","clear":true}`)); err != nil {
		t.Fatalf("clear curve_adopt_lies: %v", err)
	}
	want := sunspec.VoltVarCurve{DeptRef: 1, Pri: 1, Points: []sunspec.VVPoint{{V: 236, Var: 12}}}
	stageVoltVar(t, ss, want)
	live := readLiveVoltVar(t, ss)
	if len(live.Points) != 1 || live.Points[0] != want.Points[0] {
		t.Errorf("after clear, live curve = %+v, want single point %+v", live.Points, want.Points[0])
	}
}

// TestAdvFixedPFEffect verifies a 704 fixed-PF command moves the MEASURED 701
// PF/Var, and that pf_ack_ignore makes the write ACK (register holds the
// command) while the measured PF/Var stays at its free-running value.
func TestAdvFixedPFEffect(t *testing.T) {
	ss := newAdvSolar(t, 5000)
	r := ss.Regs
	b := ss.bases
	// Fixed physical output at a known free-running PF (0.97).
	r.Set(b.M103Base+sunspec.M103_W, uint16(int16(3000)))
	r.Set(b.M103Base+sunspec.M103_PF, uint16(int16(9700))) // PF_SF=-2 → 97.00 → 0.97 ratio
	r.Set(b.M103Base+sunspec.M103_VAr, uint16(int16(700)))

	// Hub commands fixed PF 0.90, injecting, over-excited (via the 704 block).
	setFixedPF(r, ss.adv, 0.90, true)
	ss.advSync()
	meas := sunspec.Parse701(readSlice(r, ss.adv.M701, ss.adv.M701Len))
	if !approx(meas.PF, 0.90, 0.001) {
		t.Errorf("measured PF under fixed-PF = %v, want ≈0.90", meas.PF)
	}
	if meas.Var <= 0 {
		t.Errorf("measured Var under over-excited fixed-PF = %v, want > 0 (injecting)", meas.Var)
	}

	// pf_ack_ignore: the write still ACKs (register readback fooled) but the
	// measured PF returns to free-running 0.97.
	if err := ss.ApplyFault([]byte(`{"kind":"pf_ack_ignore"}`)); err != nil {
		t.Fatalf("arm pf_ack_ignore: %v", err)
	}
	ss.advSync()
	meas = sunspec.Parse701(readSlice(r, ss.adv.M701, ss.adv.M701Len))
	if !approx(meas.PF, 0.97, 0.001) {
		t.Errorf("measured PF under pf_ack_ignore = %v, want ≈0.97 (free-running, unmoved)", meas.PF)
	}
	// The 704 register still holds the accepted command (readback fooled).
	c := sunspec.Parse704(readSlice(r, ss.adv.M704, sunspec.L704.Len()))
	if !c.PFWInjEna || !approx(c.PFWInjPF, 0.90, 0.001) {
		t.Errorf("704 readback under pf_ack_ignore = ena:%v pf:%v, want ena:true pf:0.90 (register fooled)", c.PFWInjEna, c.PFWInjPF)
	}
}

// setFixedPF writes the 704 PFWInj sync group into the register map (mirrors
// derbase.SetFixedPF's whole-block RMW).
func setFixedPF(r *RegisterMap, adv solarAdvBases, pf float64, overExcited bool) {
	regs := readSlice(r, adv.M704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetBool("PFWInjEna", true)
	v.SetFloat("PFWInj_PF", pf)
	ext := uint16(sunspec.M704_Ext_OverExcited)
	if !overExcited {
		ext = sunspec.M704_Ext_UnderExcited
	}
	v.SetEnum("PFWInj_Ext", ext)
	writeSlice(r, adv.M704, regs)
}

// TestAdvFaultSet verifies the advanced sim advertises the 7xx fault kinds while
// a legacy sim rejects them, and that the legacy kinds still work on both.
func TestAdvFaultSet(t *testing.T) {
	adv := newAdvSolar(t, 5000)
	for _, k := range []string{"raise_alarm", "curve_adopt_lies", "pf_ack_ignore"} {
		if err := adv.ApplyFault([]byte(`{"kind":"` + k + `","clear":true}`)); err != nil {
			t.Errorf("advanced sim rejected %q: %v", k, err)
		}
	}
	// A legacy solar sim must NOT advertise the 7xx kinds.
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	legacy := &SolarServer{Server: &Server{Regs: r}, bases: populateSolar(r, 5000, ""), wmaxW: 5000}
	for _, k := range []string{"raise_alarm", "curve_adopt_lies", "pf_ack_ignore"} {
		if err := legacy.ApplyFault([]byte(`{"kind":"` + k + `"}`)); err == nil {
			t.Errorf("legacy sim accepted advanced kind %q (should reject)", k)
		}
	}
}

func approx(got, want, tol float64) bool {
	d := got - want
	if d < 0 {
		d = -d
	}
	return d <= tol
}

// TestAdv701VoltagePointsCoherentBeforeFirstTick pins the "Seed 701 before the
// first tick so an immediately-read advanced sim is coherent" invariant
// animateSolarAdvanced's doc comment claims (solar_adv.go) — specifically for
// the line-to-line quartet (LLV/VL1L2/VL2L3/VL3L1). advMirror701 mirrors those
// from M103's own PPVph{AB,BC,CA} registers, and populateSolarCore did not
// seed those before the fix this test pins, so a client reading model 701 the
// instant it connects to a freshly started modsim/mbapsdev — before the first
// 5s animation tick ever runs solarStep — saw all four read literal 0.0 V: an
// IMPLEMENTED value, not the SunSpec not-implemented sentinel, on a device
// declaring ACType=THREE_PHASE. That is a physically impossible machine (see
// advMirror701's file comment) and the exact shape of the MOD-4 step 3
// finding this fix closes (runs/stamped-fullsuite-20260730T075718/REPORT.md's
// MOD-4.701 assertion, though that specific run's NOT-IMPLEMENTED verdict
// traces to a separate, product-side gap — see internal/regmap/feed.go's "701
// per-phase voltage" note in lexa-gw).
//
// advSync() performs the exact advBridgeCeiling+advMirror701 pair the real
// animation goroutine's pre-loop seed calls (this bare-struct test harness
// never starts that goroutine), so this is the immediate, pre-first-tick
// state a real client sees.
func TestAdv701VoltagePointsCoherentBeforeFirstTick(t *testing.T) {
	ss := newAdvSolar(t, 6000)
	ss.advSync()

	regs := readSlice(ss.Regs, ss.adv.M701, ss.adv.M701Len)
	m := sunspec.Parse701(regs)
	if math.IsNaN(m.LLV) {
		t.Error("701 LLV is not-implemented immediately after construction")
	}
	if math.IsNaN(m.LNV) {
		t.Error("701 LNV is not-implemented immediately after construction")
	}
	if math.IsNaN(m.VL1) {
		t.Error("701 VL1 is not-implemented immediately after construction")
	}

	// VL2/VL3/VL1L2/VL2L3/VL3L1 are not carried by lexa-proto's ACMeasurement
	// struct, so read them straight off the layout view.
	v := sunspec.L701.View(regs)
	for _, name := range []string{"VL2", "VL3", "VL1L2", "VL2L3", "VL3L1"} {
		got := v.Float(name)
		if math.IsNaN(got) {
			t.Errorf("701 %s is not-implemented immediately after construction", name)
			continue
		}
		if got == 0 {
			t.Errorf("701 %s = 0 immediately after construction — a three-phase device (ACType=2) "+
				"asserting 0 V is implemented-but-wrong, the exact defect populateSolarCore's PPVph "+
				"seed exists to prevent", name)
		}
	}

	// Physical coherence: line-to-line = sqrt(3) x line-to-neutral for the
	// balanced three-phase model this sim runs (the same relation the
	// animation tick and the Inject "V_V" handler both apply).
	wantLL := m.LNV * math.Sqrt(3)
	for _, name := range []string{"LLV", "VL1L2", "VL2L3", "VL3L1"} {
		if got := v.Float(name); !approx(got, wantLL, 1.0) {
			t.Errorf("701 %s = %.1f, want ~%.1f (sqrt(3) x LNV=%.1f)", name, got, wantLL, m.LNV)
		}
	}
}

// TestModel703Served pins model 703 (DER Enter Service) into the advanced
// image's chain, between 702 and 704, and checks that every point
// profile1547.go's requiredPoints[703] names reads back as real,
// non-sentinel, IEEE 1547-2018-typical data — the fix for MOD-4's
// "MISSING [703]" finding (runs/stamped-fullsuite-20260730T075718/REPORT.md:
// "the DUT serves [1 701 702 704 705 706 707 708 709 710 711 712]; the IEEE
// 1547-2018 profile requires [... 703 ...]; MISSING [703]"). The profile's
// §3.5 Required Points table gives 703 no conditionality clause (unlike 713),
// so it belongs in the unconditional chain, not behind an opt-in flag.
func TestModel703Served(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	_, adv := populateSolarAdvanced(r, 6000, 6000*0.44, "", AdvancedOptions{})

	reader, err := sunspec.NewReader(&regMapTransport{r: r})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if !reader.HasModel(sunspec.ModelDEREnterService) {
		t.Fatal("the advanced image does not serve model 703 (DEREnterService)")
	}

	// Chain order: 701 < 702 < 703 < 704 (address order is discovery order).
	if !(adv.M701 < adv.M702 && adv.M702 < adv.M703 && adv.M703 < adv.M704) {
		t.Errorf("703 is not chained between 702 and 704: 701@%d 702@%d 703@%d 704@%d",
			adv.M701, adv.M702, adv.M703, adv.M704)
	}

	regs, err := reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		t.Fatalf("ReadModel(703): %v", err)
	}
	// Layout width assertion against lexa-proto's own table — the L701 bug
	// this fixture already guards against (703 registers instead of 137) had
	// exactly this shape: a length constant drifting from the layout that
	// derives it.
	if got, want := len(regs), sunspec.L703.Len(); got != want {
		t.Errorf("703 data length = %d, want %d (lexa-proto's L703 layout)", got, want)
	}

	es := sunspec.Parse703(regs)
	if !es.Enabled {
		t.Error("703 ES = disabled, want enabled (permit service)")
	}
	for _, tc := range []struct {
		name      string
		got, want float64
	}{
		{"ESVHi", es.VHi, 252.0},
		{"ESVLo", es.VLo, 220.0},
		{"ESHzHi", es.HzHi, 60.1},
		{"ESHzLo", es.HzLo, 59.5},
	} {
		if math.IsNaN(tc.got) {
			t.Errorf("703 %s is not-implemented", tc.name)
			continue
		}
		if !approx(tc.got, tc.want, 0.05) {
			t.Errorf("703 %s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if es.DelayS != 300 {
		t.Errorf("703 ESDlyTms = %d, want 300", es.DelayS)
	}
	if es.RampS != 300 {
		t.Errorf("703 ESRmpTms = %d, want 300", es.RampS)
	}

	v := sunspec.L703.View(regs)
	if _, ok := v.SF("V_SF"); !ok {
		t.Error("703 V_SF is not-implemented")
	}
	if _, ok := v.SF("Hz_SF"); !ok {
		t.Error("703 Hz_SF is not-implemented")
	}

	// The SF write-protection every advanced model gets (protect.go).
	for _, sf := range []string{"V_SF", "Hz_SF"} {
		addr := adv.M703 + uint16(sunspec.L703.Offset(sf))
		if !r.protected[addr] {
			t.Errorf("703 %s at %d is not write-protected", sf, addr)
		}
	}
}

// TestModel703ServedByBothSimInstances proves inv-plain (modsim, plain TCP)
// and inv-secure (mbapsdev, mbaps/mTLS) cannot drift on this: both build their
// SunSpec register world from the SAME sim.NewSolarServerAdvanced constructor
// (mbapsdev's -model inverter — see sim/mbapsdev/main.go's newModel), so
// adding 703 to populateSolar7xx serves it identically to both, without
// either binary's own main.go knowing 703 exists.
func TestModel703ServedByBothSimInstances(t *testing.T) {
	plain, err := NewSolarServerAdvanced("tcp://127.0.0.1:0", 6000, "BENCH-MODSIM-01")
	if err != nil {
		t.Fatalf("NewSolarServerAdvanced (inv-plain): %v", err)
	}
	defer plain.Stop()
	secure, err := NewSolarServerAdvanced("tcp://127.0.0.1:0", 6000, "BENCH-MBAPS-01")
	if err != nil {
		t.Fatalf("NewSolarServerAdvanced (inv-secure): %v", err)
	}
	defer secure.Stop()

	if plain.adv.M703 == 0 {
		t.Error("inv-plain (modsim) does not serve model 703")
	}
	if secure.adv.M703 == 0 {
		t.Error("inv-secure (mbapsdev) does not serve model 703")
	}
}

// TestPopulate702RateRatingsNotImplemented pins the sentinel-vs-implemented
// distinction the bench battery's finding turned on: a Tuint16 zero and the
// SunSpec not-implemented sentinel (0xFFFF) are NOT the same claim, and
// derbase's maxRatingBound (lexa-proto derbase/capability.go) treats them
// oppositely — an implemented zero DENIES the axis outright, while the
// sentinel imposes no bound at all. Before this fix, populate702 left
// WChaRteMaxRtg/WDisChaRteMaxRtg (and the WChaRteMax/WDisChaRteMax settings
// beside them) at the Go zero value, which read back as four IMPLEMENTED
// zero ratings and denied every nonzero active-power setpoint the sim was
// asked to hold — the exact shape that blocked setpoint-axis bench testing.
//
// This profile models a plain PV/solar inverter with no battery behind it, so
// the honest fix is the sentinel for all four charge/discharge rate points —
// NOT a real rating, which would be dishonest for a device that never had a
// charge axis to rate in the first place. The contrast against WMaxRtg (a
// point this profile DOES implement, and must keep reading as real data) is
// what makes this a sentinel-vs-implemented test rather than a "reads NaN"
// test.
func TestPopulate702RateRatingsNotImplemented(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	_, adv := populateSolarAdvanced(r, 6000, 6000*0.44, "", AdvancedOptions{})

	regs := readSlice(r, adv.M702, sunspec.L702.Len())
	v := sunspec.L702.View(regs)

	for _, name := range []string{"WChaRteMaxRtg", "WDisChaRteMaxRtg", "WChaRteMax", "WDisChaRteMax"} {
		got := v.Float(name)
		if !math.IsNaN(got) {
			t.Errorf("702 %s = %v, want NaN (not-implemented sentinel) — an implemented rating here "+
				"(even 0) denies every nonzero setpoint under maxRatingBound", name, got)
		}
	}

	// The contrast: this profile DOES implement WMaxRtg, and it must keep
	// reading as real, non-sentinel data — a regression that sentineled the
	// whole 702 block (rather than just the charge/discharge rate points)
	// would pass the loop above and be caught here instead.
	if got := v.Float("WMaxRtg"); math.IsNaN(got) || got != 6000 {
		t.Errorf("702 WMaxRtg = %v, want 6000 (implemented) — this profile DOES declare a real-power rating", got)
	}

	// Raw-wire assertion: the not-implemented sentinel for a Tuint16 point is
	// the literal register value 0xFFFF, not merely "whatever View.Float
	// happens to decode as NaN" — pin the wire encoding itself so a future
	// change to notImpl detection can't quietly stop writing the sentinel
	// while still passing the Float-based checks above.
	for _, name := range []string{"WChaRteMaxRtg", "WDisChaRteMaxRtg", "WChaRteMax", "WDisChaRteMax"} {
		off := sunspec.L702.Offset(name)
		if got := regs[off]; got != 0xFFFF {
			t.Errorf("702 %s raw register = 0x%04x, want 0xFFFF (the SunSpec not-implemented sentinel)", name, got)
		}
	}
}

// ── IW15-001: the solar active-power SETPOINT ────────────────────────────────
//
// Before this block existed, a 704 WSet write to the inverter was ACK'd,
// stored, echoed back — and physically ignored (advBridgeCeiling mirrored the
// CEILING and nothing read WSet at all). These tests pin the closure: the
// setpoint is a real, independent bound on output, it is NOT folded into the
// ceiling register, and its default decoding cannot be fooled.

// setSolarPotential seeds the panel's available power (M122 WAval), which a
// PAUSED solarStep holds as potW — the "available" term of the three-way min.
func setSolarPotential(ss *SolarServer, w float64) {
	ss.Regs.Set(ss.bases.M122Base+sunspec.M122_WAval, uint16(int16(w)))
}

// armSolar704Setpoint writes an ENABLED 704 setpoint in the given WSetMod.
// val is watts for M704_WSetMod_Watts and percent-of-WMax for MaxPct.
func armSolar704Setpoint(ss *SolarServer, mod uint16, val float64) {
	regs := readSlice(ss.Regs, ss.adv.M704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetBool("WSetEna", true)
	v.SetEnum("WSetMod", mod)
	if mod == sunspec.M704_WSetMod_Watts {
		v.SetFloat("WSet", val)
	} else {
		v.SetFloat("WSetPct", val)
	}
	writeSlice(ss.Regs, ss.adv.M704, regs)
}

// setSolar704Ceiling writes an ENABLED 704 WMaxLimPct (percent of WMax).
func setSolar704Ceiling(ss *SolarServer, pct float64) {
	regs := readSlice(ss.Regs, ss.adv.M704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetBool("WMaxLimPctEna", true)
	v.SetFloat("WMaxLimPct", pct)
	writeSlice(ss.Regs, ss.adv.M704, regs)
}

// stepSolarHeld runs ONE animation tick the way animateSolarAdvanced does —
// bridges, physical step, 701 mirror — with the animation PAUSED, so the
// injected potential is held and the environment does not move underneath the
// assertion.
func stepSolarHeld(ss *SolarServer) {
	var wh uint16
	advBridgeCeiling(ss.Regs, ss.bases, ss.adv)
	advBridgeSetpoint(ss.Regs, ss.bases, ss.wmaxW)
	solarStep(ss.Regs, ss.wmaxW, ss.bases, true /*paused*/, 0, 0, false, &ss.faults, &wh)
	advMirror701(ss.Regs, ss.bases, ss.adv, ss.wmaxW, ss.varRating, &ss.faults)
}

// solarMeasuredW reads the inverter's measured active power off M103.
func solarMeasuredW(ss *SolarServer) float64 {
	return sunspec.ApplyScaleSigned(ss.Regs.Get(ss.bases.M103Base+sunspec.M103_W),
		int16(ss.Regs.Get(ss.bases.M103Base+sunspec.M103_W_SF)))
}

// TestSolarSetpointThreeWayMin is THE IW15-001 row: output is
// min(available, ceiling, setpoint), with each term keeping its own meaning and
// its own evidence. A setpoint above what the panel can make is not a failure
// to converge; a ceiling below the setpoint still wins; and — the anti-fold pin
// — commanding a setpoint must never rewrite the M123/704 ceiling registers,
// because those are what a "a limit is not a setpoint" negative row reads back.
func TestSolarSetpointThreeWayMin(t *testing.T) {
	const wmax = 8000.0

	t.Run("setpoint below available binds", func(t *testing.T) {
		ss := newAdvSolar(t, wmax)
		setSolarPotential(ss, 6000)
		armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, 2000)
		stepSolarHeld(ss)
		if got := solarMeasuredW(ss); math.Abs(got-2000) > 1 {
			t.Fatalf("measured = %.0f W, want 2000 W (the setpoint): a 704 WSet write that does not "+
				"move the machine is the ack_no_apply fault, permanently armed", got)
		}
	})

	t.Run("setpoint above available: output at available", func(t *testing.T) {
		ss := newAdvSolar(t, wmax)
		setSolarPotential(ss, 3000)
		armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, 5000)
		stepSolarHeld(ss)
		if got := solarMeasuredW(ss); math.Abs(got-3000) > 1 {
			t.Fatalf("measured = %.0f W, want 3000 W (available): a setpoint cannot conjure irradiance", got)
		}
	})

	t.Run("ceiling below setpoint binds, and both stay visible", func(t *testing.T) {
		ss := newAdvSolar(t, wmax)
		setSolarPotential(ss, 6000)
		setSolar704Ceiling(ss, 25)                                // 2000 W
		armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, 4000) // above the ceiling
		stepSolarHeld(ss)
		if got := solarMeasuredW(ss); math.Abs(got-2000) > 1 {
			t.Fatalf("measured = %.0f W, want 2000 W (the ceiling binds independently of the setpoint)", got)
		}
		st := ss.Snapshot()
		if !st.Advanced.Ceiling704.Ena || math.Abs(st.Advanced.Ceiling704.Pct-25) > 0.01 {
			t.Errorf("704 ceiling reported as ena=%v pct=%v, want ena=true pct=25 — the ceiling must survive "+
				"a setpoint command intact", st.Advanced.Ceiling704.Ena, st.Advanced.Ceiling704.Pct)
		}
		if !st.Advanced.Setpoint704.Ena || math.Abs(st.Advanced.Setpoint704.EffectiveW-4000) > 1 {
			t.Errorf("704 setpoint reported as ena=%v effective=%v, want ena=true effective=4000 — the "+
				"setpoint is still in force at 4000 W, it is simply not the binding term",
				st.Advanced.Setpoint704.Ena, st.Advanced.Setpoint704.EffectiveW)
		}
	})

	t.Run("setpoint below ceiling binds WITHOUT rewriting the ceiling", func(t *testing.T) {
		ss := newAdvSolar(t, wmax)
		b := ss.bases
		setSolarPotential(ss, 6000)
		setSolar704Ceiling(ss, 75) // 6000 W
		armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, 1500)
		stepSolarHeld(ss)
		if got := solarMeasuredW(ss); math.Abs(got-1500) > 1 {
			t.Fatalf("measured = %.0f W, want 1500 W (the setpoint binds below the ceiling)", got)
		}
		// THE ANTI-FOLD PIN. A fold would have transcoded 1500 W into the M123
		// signed-percent cell (18.75 %) and destroyed the evidence that the
		// commanded LIMIT was 75 %.
		wantPct := 75.0
		gotPct := sunspec.ApplyScaleSigned(ss.Regs.Get(b.M123Base+sunspec.M123_WMaxLimPct),
			int16(ss.Regs.Get(b.M123Base+sunspec.M123_WMaxLimPct_SF)))
		if math.Abs(gotPct-wantPct) > 0.01 {
			t.Fatalf("M123 WMaxLimPct = %v %%, want %v %% — the setpoint was folded into the ceiling cell, "+
				"which erases the difference between a limit and a setpoint after the fact", gotPct, wantPct)
		}
		if st := ss.Snapshot(); math.Abs(st.Controls.WMaxLimPct_pct-wantPct) > 0.01 {
			t.Errorf("/state WMaxLimPct_pct = %v, want %v (same referee, through the snapshot)",
				st.Controls.WMaxLimPct_pct, wantPct)
		}
	})

	t.Run("WSetEna=0 leaves the setpoint out of the min", func(t *testing.T) {
		ss := newAdvSolar(t, wmax)
		setSolarPotential(ss, 6000)
		armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, 1500)
		regs := readSlice(ss.Regs, ss.adv.M704, sunspec.L704.Len())
		sunspec.L704.View(regs).SetBool("WSetEna", false)
		writeSlice(ss.Regs, ss.adv.M704, regs)
		stepSolarHeld(ss)
		if got := solarMeasuredW(ss); math.Abs(got-6000) > 1 {
			t.Fatalf("measured = %.0f W, want 6000 W: a setpoint nobody enabled commands nothing", got)
		}
	})

	t.Run("a negative setpoint is answered with zero, not with import", func(t *testing.T) {
		ss := newAdvSolar(t, wmax)
		setSolarPotential(ss, 6000)
		armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, -2000)
		stepSolarHeld(ss)
		if got := solarMeasuredW(ss); got != 0 {
			t.Fatalf("measured = %.0f W, want 0 W: a PV inverter cannot absorb", got)
		}
	})
}

// TestSolarSetpointWSetModDefaultIsPercent pins the honest default. WSetMod's
// populate value is raw 0 = MaxPct (derlayout.go), so a head end that writes
// WSet (WATTS) without also writing WSetMod has commanded a PERCENT — and the
// percent register it never wrote is 0, i.e. produce nothing. A sim that
// "helpfully" guessed watts here would let a gateway that forgot WSetMod pass a
// conformance row it should fail.
func TestSolarSetpointWSetModDefaultIsPercent(t *testing.T) {
	const wmax = 8000.0
	ss := newAdvSolar(t, wmax)
	setSolarPotential(ss, 6000)

	// The fixture must actually START at the default, or this test proves nothing.
	v0 := sunspec.L704.View(readSlice(ss.Regs, ss.adv.M704, sunspec.L704.Len()))
	if mod, ok := v0.Enum("WSetMod"); !ok || mod != sunspec.M704_WSetMod_MaxPct {
		t.Fatalf("fixture WSetMod = %d (ok=%v), want %d (MaxPct) — populate704's default is the whole "+
			"premise of this row", mod, ok, sunspec.M704_WSetMod_MaxPct)
	}

	// A WATTS-shaped write against the untouched (percent) mode.
	regs := readSlice(ss.Regs, ss.adv.M704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetBool("WSetEna", true)
	v.SetFloat("WSet", 3000) // watts — but WSetMod still says percent
	writeSlice(ss.Regs, ss.adv.M704, regs)
	stepSolarHeld(ss)

	if got := solarMeasuredW(ss); got != 0 {
		t.Fatalf("measured = %.0f W, want 0 W: WSetMod=MaxPct means WSetPct (untouched, 0 %%) is the "+
			"command, and WSet=3000 is not read at all", got)
	}
	st := ss.Snapshot().Advanced.Setpoint704
	if st.Mod != sunspec.M704_WSetMod_MaxPct || math.Abs(st.WSet_W-3000) > 1 || st.EffectiveW != 0 {
		t.Errorf("/state wset_704 = %+v, want mod=0, wset_W=3000 (stored and echoed), effective_W=0 "+
			"(what the device is actually holding itself to)", st)
	}

	// The percent the mode actually names does command.
	armSolar704Setpoint(ss, sunspec.M704_WSetMod_MaxPct, 50)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-4000) > 1 {
		t.Fatalf("measured = %.0f W, want 4000 W (50 %% of the 8000 W WMax setting)", got)
	}

	// Switching the mode makes the watts field the command.
	armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, 3000)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-3000) > 1 {
		t.Fatalf("measured = %.0f W, want 3000 W (WSetMod=Watts now names WSet)", got)
	}
}

// TestSolarSetpointTakesEffectAtWriteTime pins the OnWrite coherence: the
// instant a 704 WSet write lands over Modbus — with no animation tick in
// between — the 103 register, the 701 mirror the gateway prefers, and /state
// all already agree with the command. Without it a dump taken right after the
// write shows a pre-write value for up to a full tick, which a settle-deadline
// oracle scores as a device that ignored the write.
func TestSolarSetpointTakesEffectAtWriteTime(t *testing.T) {
	const wmax = 8000.0
	ss := newAdvSolar(t, wmax)
	ss.Regs.OnWrite = ss.solarOnWrite // wired by newSolarServerAdvanced in production

	setSolarPotential(ss, 6000)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-6000) > 1 {
		t.Fatalf("pre-write measured = %.0f W, want 6000 W", got)
	}

	// The whole-block RMW a gateway performs (derbase writes 704 as one block).
	regs := readSlice(ss.Regs, ss.adv.M704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetBool("WSetEna", true)
	v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
	v.SetFloat("WSet", 2500)
	if _, err := ss.Regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: ss.adv.M704, Quantity: uint16(len(regs)), IsWrite: true, Args: regs,
	}); err != nil {
		t.Fatalf("modbus 704 block write: %v", err)
	}

	if got := solarMeasuredW(ss); math.Abs(got-2500) > 1 {
		t.Fatalf("measured right after the write = %.0f W, want 2500 W (no tick in between)", got)
	}
	m701 := sunspec.Parse701(readSlice(ss.Regs, ss.adv.M701, ss.adv.M701Len))
	if math.Abs(m701.W-2500) > 1 {
		t.Errorf("701 W right after the write = %v, want 2500 — the model the gateway prefers must not "+
			"lag the one it does not", m701.W)
	}
	st := ss.Snapshot()
	if math.Abs(st.Advanced.Setpoint704.EffectiveW-2500) > 1 || math.Abs(st.Measurements.W_W-2500) > 1 {
		t.Errorf("/state effective_W=%v W_W=%v, want both 2500",
			st.Advanced.Setpoint704.EffectiveW, st.Measurements.W_W)
	}
	// The potential is untouched: the device is CURTAILED, not dark.
	if math.Abs(st.Measurements.Possible_W-6000) > 1 {
		t.Errorf("possible_W = %v, want 6000 (the setpoint bounds output, not irradiance)", st.Measurements.Possible_W)
	}

	// The /inject path lands in the same place. This is the bench-replay shape
	// — the animation paused, PV injected each tick — and Inject's own clip
	// knows only about the ceiling, so it is advSync's setpoint bridge that
	// keeps the held value from standing above the setpoint for a whole tick.
	if err := ss.Inject([]byte(`{"W_W":6000}`)); err != nil {
		t.Fatalf("inject W_W: %v", err)
	}
	if got := solarMeasuredW(ss); math.Abs(got-2500) > 1 {
		t.Fatalf("measured after an injected 6000 W potential = %.0f W, want 2500 W (the standing setpoint)", got)
	}
	if av := ss.Snapshot().Measurements.Possible_W; math.Abs(av-6000) > 1 {
		t.Errorf("possible_W = %v after the inject, want 6000 (the potential is recorded in full)", av)
	}
}

// TestSolarPowerOnResetClearsTheSetpoint: reboot_forget must forget the
// SETPOINT too. Before IW15-001 powerOnReset touched only the ceiling pair — a
// live WSet survived a simulated power cycle, so a gateway that never
// re-asserted its setpoint would have passed the row while the device it was
// steering had, in reality, come back holding a value nobody re-sent.
func TestSolarPowerOnResetClearsTheSetpoint(t *testing.T) {
	ss := newAdvSolar(t, 8000)
	setSolarPotential(ss, 6000)
	armSolar704Setpoint(ss, sunspec.M704_WSetMod_Watts, 1200)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-1200) > 1 {
		t.Fatalf("pre-reset measured = %.0f W, want 1200 W", got)
	}

	ss.powerOnReset()

	v := sunspec.L704.View(readSlice(ss.Regs, ss.adv.M704, sunspec.L704.Len()))
	if v.Bool("WSetEna") {
		t.Error("WSetEna survived the power cycle")
	}
	if w := v.Float("WSet"); w != 0 {
		t.Errorf("WSet = %v after the power cycle, want 0 (both registers of the Tint32, not just the low word)", w)
	}
	if p := v.Float("WSetPct"); p != 0 {
		t.Errorf("WSetPct = %v after the power cycle, want 0 — with WSetMod back at its MaxPct default it is "+
			"WSetPct that a re-enable would command from", p)
	}
	if _, ok := solarSetpointW(ss.Regs, ss.bases, ss.wmaxW); ok {
		t.Error("a setpoint is still in force after a power cycle")
	}
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-6000) > 1 {
		t.Errorf("post-reset measured = %.0f W, want 6000 W (uncommanded, at available)", got)
	}
}

// ── IW15-002: settings vs ratings on the advanced sim ────────────────────────

// TestSolarWMaxSettingMovesThePhysics is the IW15-002 row for the 7xx surface:
// the WMax SETTING is what percent-of-max controls resolve against, it is
// separately settable from the RATING, and moving it moves real watts. Before
// this, every physics path read a Go float captured at construction, so a
// written WMax was cosmetic and a gateway resolving percents against the rating
// was never contradicted by the device.
func TestSolarWMaxSettingMovesThePhysics(t *testing.T) {
	const wmax = 8000.0
	ss := newAdvSolar(t, wmax)
	if err := ss.Inject([]byte(`{"WMax_W":4000}`)); err != nil {
		t.Fatalf("inject WMax_W: %v", err)
	}

	// The setting moved in every model that carries it; the rating did not move
	// at all.
	v702 := sunspec.L702.View(readSlice(ss.Regs, ss.adv.M702, sunspec.L702.Len()))
	if got := v702.Float("WMax"); got != 4000 {
		t.Errorf("702 WMax = %v, want 4000", got)
	}
	if got := v702.Float("WMaxRtg"); got != wmax {
		t.Errorf("702 WMaxRtg = %v, want %v — a SETTING inject must not touch the RATING", got, wmax)
	}
	m121 := sunspec.ApplyScaleUint(ss.Regs.Get(ss.bases.M121Base+sunspec.M121_WMax),
		int16(ss.Regs.Get(ss.bases.M121Base+sunspec.M121_WMax_SF)))
	if m121 != 4000 {
		t.Errorf("121 WMax = %v, want 4000 — one physical setting, so every model that carries it moves together", m121)
	}
	if got := float64(ss.Regs.Get(ss.bases.M120Base + sunspec.M120_WRtg)); got != wmax {
		t.Errorf("120 WRtg = %v, want %v (the immutable rating)", got, wmax)
	}

	st := ss.Snapshot()
	if st.Nameplate.PctReferenceW != 4000 || st.Nameplate.WRtgW != wmax || st.Nameplate.WMaxW != wmax {
		t.Errorf("/state nameplate = %+v, want pct_reference_W=4000, m120_WRtg_W=%v, wmax_W=%v",
			st.Nameplate, wmax, wmax)
	}

	// The ceiling percent now resolves against 4000, not 8000. THIS is the
	// divergence a gateway that used the rating would land on the wire.
	setSolarPotential(ss, 6000)
	setSolar704Ceiling(ss, 50)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-2000) > 1 {
		t.Fatalf("50 %% ceiling produced %.0f W, want 2000 W (50 %% of the 4000 W SETTING). "+
			"4000 W would mean the device resolved the percent against its rating", got)
	}
	// And so does the setpoint percent.
	armSolar704Setpoint(ss, sunspec.M704_WSetMod_MaxPct, 25)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-1000) > 1 {
		t.Fatalf("25 %% setpoint produced %.0f W, want 1000 W (25 %% of the 4000 W SETTING)", got)
	}
}

// TestSolarCapacityRatingsAreDeclarationOnly: the rate SETTING/RATING pair must
// be independently settable on the solar 702 (a gateway's reference-resolution
// rule has to be testable against a fixture where they differ), and a rating
// inject must not silently rebuild the machine — the panel's physical
// capability is fixed at construction.
func TestSolarCapacityRatingsAreDeclarationOnly(t *testing.T) {
	const wmax = 8000.0
	ss := newAdvSolar(t, wmax)

	// The stock PV profile declares no rate limits at all (the sentinel), which
	// /state must report as JSON null rather than a fabricated 0.
	if st := ss.Snapshot().Advanced.Capacity702; st.WChaRteMaxW != nil || st.WChaRteMaxRtgW != nil {
		t.Errorf("stock rate points reported as %v/%v, want null: an implemented 0 is a positive "+
			"declaration of incapacity, which is a different claim from 'absent'",
			st.WChaRteMaxW, st.WChaRteMaxRtgW)
	}

	if err := ss.Inject([]byte(`{"WDisChaRteMax_W":3000,"WDisChaRteMaxRtg_W":7000}`)); err != nil {
		t.Fatalf("inject rate pair: %v", err)
	}
	v := sunspec.L702.View(readSlice(ss.Regs, ss.adv.M702, sunspec.L702.Len()))
	if got := v.Float("WDisChaRteMax"); got != 3000 {
		t.Errorf("702 WDisChaRteMax = %v, want 3000", got)
	}
	if got := v.Float("WDisChaRteMaxRtg"); got != 7000 {
		t.Errorf("702 WDisChaRteMaxRtg = %v, want 7000 — setting and rating must be settable apart", got)
	}

	// A rating inject moves the DECLARATION; possible_W still comes from the
	// physical panel the sim was constructed with.
	if err := ss.Inject([]byte(`{"WMaxRtg_W":3000}`)); err != nil {
		t.Fatalf("inject WMaxRtg_W: %v", err)
	}
	if got := ss.Snapshot().Nameplate.WMaxW; got != wmax {
		t.Errorf("wmax_W = %v after a rating inject, want %v: the declaration moved, the machine did not", got, wmax)
	}
}

// TestSolarWMaxSentinelFallsBackHonestly walks the whole reference-resolution
// chain down: 702 WMax → 121 WMax → the construction float. A sentinel is
// "not implemented", never "zero", and a device whose models say nothing usable
// must fall back to what it physically is rather than to 0 W.
func TestSolarWMaxSentinelFallsBackHonestly(t *testing.T) {
	const wmax = 8000.0
	ss := newAdvSolar(t, wmax)
	r, b := ss.Regs, ss.bases

	if err := ss.Inject([]byte(`{"M121_WMax_W":5000}`)); err != nil {
		t.Fatalf("inject M121_WMax_W: %v", err)
	}
	if got := solarWMaxRefW(r, b, wmax); got != wmax {
		t.Fatalf("reference = %v with 702 present, want %v: 702 WMax outranks the legacy 121 point", got, wmax)
	}
	// 702 unimplemented → the legacy setting answers.
	r.Set(b.M702Base+uint16(sunspec.L702.Offset("WMax")), 0xFFFF)
	if got := solarWMaxRefW(r, b, wmax); got != 5000 {
		t.Fatalf("reference = %v with 702 WMax at the sentinel, want 5000 (121 WMax)", got)
	}
	// Both unimplemented → the machine itself.
	r.Set(b.M121Base+sunspec.M121_WMax, 0xFFFF)
	if got := solarWMaxRefW(r, b, wmax); got != wmax {
		t.Fatalf("reference = %v with both models unimplemented, want the construction nameplate %v", got, wmax)
	}
}

// TestSolarStateMarshalsWithUnimplementedCapacityPoints guards GET /state
// against a 500. View.Float reports a not-implemented SunSpec point as NaN, and
// encoding/json REFUSES to marshal NaN — so reporting the 702 rate points (all
// four of which this PV profile leaves at the sentinel) as plain floats would
// have taken the whole state document down the first time a QA oracle fetched
// it. They are pointers, and null is also the honest answer.
func TestSolarStateMarshalsWithUnimplementedCapacityPoints(t *testing.T) {
	ss := newAdvSolar(t, 8000)
	// Blank a control point too, the shape a nan_sentinel fault or a garbage
	// whole-block write-back leaves behind.
	ss.Regs.Set(ss.adv.M704+uint16(sunspec.L704.Offset("WSetPct")), 0x8000)

	b, err := json.Marshal(ss.Snapshot())
	if err != nil {
		t.Fatalf("GET /state would 500: %v", err)
	}
	for _, want := range []string{`"pct_reference_W"`, `"wset_704"`, `"capacity_702"`, `"WChaRteMax_W":null`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("/state JSON is missing %s", want)
		}
	}
}

// ── Model 703: permit service (IW16-002) ─────────────────────────────────────

// TestSolarPermitServiceCeasesEnergization is the IW16-002 row: withdrawing
// permit service (M703 ES=0) must actually STOP the inverter.
//
// Before the fix, 703 was populated at startup and never read again: an ES
// write was ACK'd, stored, and read back correctly by /registers while the
// physics ignored it entirely. That is the ack_no_apply fault permanently armed
// on the exact axis a 2030.5 opModEnergize=false lands on, and it is what made
// the BASIC-009 bench row look like a gateway defect — lexa-gw judges
// cease-to-energize by MEASURED cessation, never by its own write's ACK, so it
// correctly read a still-exporting device as diverged and answered the head end
// cannot-comply. The DUT was wrong, not the gateway.
//
// MUTATION PROOF: delete the solarPermitService term from solarStep's cease
// fence (or make the function return true unconditionally) and this test fails
// with the inverter still exporting its full potential.
func TestSolarPermitServiceCeasesEnergization(t *testing.T) {
	const wmax = 8000.0
	ss := newAdvSolar(t, wmax)

	setSolarPotential(ss, 6000)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-6000) > 1 {
		t.Fatalf("fixture: pre-cease measured = %.0f W, want 6000 W", got)
	}
	if !solarPermitService(ss.Regs, ss.bases) {
		t.Fatal("fixture: populate703 must seed ES=permitted, or the test proves nothing")
	}

	// Withdraw permit service exactly as derbase does — a single-register write
	// to 703 ES, not a whole-block RMW (SetEnterServiceEnabled).
	ss.Regs.Set(ss.bases.M703Base+uint16(sunspec.L703.Offset("ES")), 0)
	stepSolarHeld(ss)

	if got := solarMeasuredW(ss); got != 0 {
		t.Errorf("measured = %.0f W after permit service was withdrawn, want 0 — "+
			"IEEE 1547-2018 §4.10.3: a DER that loses permit service ceases to energize", got)
	}
	m701 := sunspec.Parse701(readSlice(ss.Regs, ss.adv.M701, ss.adv.M701Len))
	if m701.W != 0 || m701.St != 0 || m701.ConnSt != 0 {
		t.Errorf("701 after the cease: W=%v St=%d ConnSt=%d, want 0/0/0 — the model the "+
			"gateway prefers must not still report a running, connected, exporting device",
			m701.W, m701.St, m701.ConnSt)
	}
	if av := ss.Snapshot().Measurements.Possible_W; av != 0 {
		t.Errorf("possible_W = %v after the cease, want 0 — a de-energized inverter offers "+
			"no available power (this is a cease, not a curtailment)", av)
	}

	// Restoring permit service lets the animation bring it back: the cease is a
	// STANDING condition, not a latch the sim can never leave.
	ss.Regs.Set(ss.bases.M703Base+uint16(sunspec.L703.Offset("ES")), 1)
	setSolarPotential(ss, 6000)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-6000) > 1 {
		t.Errorf("measured = %.0f W after permit service was restored, want 6000 W", got)
	}
}

// TestSolarPermitServiceCeasesAtWriteTime is the timing half. The gateway's
// verdict on this axis is MEASURED and its poll can land well inside one 5 s
// animation tick, so a cease that only takes effect on the next tick is still a
// window in which the device reports itself exporting against a command it has
// already accepted. The 703 write must move 103 AND the 701 mirror immediately
// — advSync alone cannot do it, because it re-derives 701 from a 103 image
// nothing has zeroed yet.
func TestSolarPermitServiceCeasesAtWriteTime(t *testing.T) {
	const wmax = 8000.0
	ss := newAdvSolar(t, wmax)
	ss.Regs.OnWrite = ss.solarOnWrite // wired by newSolarServerAdvanced in production

	setSolarPotential(ss, 6000)
	stepSolarHeld(ss)
	if got := solarMeasuredW(ss); math.Abs(got-6000) > 1 {
		t.Fatalf("fixture: pre-write measured = %.0f W, want 6000 W", got)
	}

	esAddr := ss.bases.M703Base + uint16(sunspec.L703.Offset("ES"))
	if _, err := ss.Regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: esAddr, Quantity: 1, IsWrite: true, Args: []uint16{0},
	}); err != nil {
		t.Fatalf("modbus 703 ES write: %v", err)
	}

	if got := solarMeasuredW(ss); got != 0 {
		t.Errorf("measured right after the ES=0 write = %.0f W, want 0 (no tick in between)", got)
	}
	m701 := sunspec.Parse701(readSlice(ss.Regs, ss.adv.M701, ss.adv.M701Len))
	if m701.W != 0 || m701.ConnSt != 0 {
		t.Errorf("701 right after the ES=0 write: W=%v ConnSt=%d, want 0/0", m701.W, m701.ConnSt)
	}
}

// TestSolarPermitServiceLegacySimIsAlwaysPermitted pins the no-op guarantee: a
// legacy (703-less) image has no permit-service register to withdraw, so the
// fence must never fire there. Without the M703Base==0 guard every legacy
// scenario would read address 0 — outside any model — and cease permanently.
func TestSolarPermitServiceLegacySimIsAlwaysPermitted(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, _ := populateSolarCore(r, 8000, "")
	if bases.M703Base != 0 {
		t.Fatalf("fixture: legacy bases must carry no 703, got %d", bases.M703Base)
	}
	if !solarPermitService(r, bases) {
		t.Fatal("a legacy sim has no enter-service model and must always be permitted")
	}
}
