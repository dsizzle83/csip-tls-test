package sim

// solar_adv_test.go — unit tests for the advanced-DER (7xx) solar surface:
// model 701 encoding, the 705/706/711/712 curve-adopt handshake (success AND
// the curve_adopt_lies divergence), the 704 fixed-PF measured effect (and its
// pf_ack_ignore accept-but-ignore), and the raise_alarm bitfield knob.

import (
	"testing"

	"lexa-proto/sunspec"
)

// newAdvSolar builds an advanced solar register bank + SolarServer wired for
// unit tests WITHOUT a live Modbus listener (mirrors the faults_test.go bare
// struct pattern), so tests drive the register map and the effect functions
// directly.
func newAdvSolar(t *testing.T, wmax float64) *SolarServer {
	t.Helper()
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	varRating := wmax * 0.44
	bases, adv := populateSolarAdvanced(r, wmax, varRating, "")
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
