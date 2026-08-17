package sim

// curvevsf_test.go — the oracle for the 7xx curve models' declared VOLTAGE
// axis resolution (H-A).
//
// WHAT WENT WRONG. This sim declared V_SF = 0 on 705/706, i.e. a device whose
// curve breakpoints land on whole percent of VNom. CSIP CTP v1.3's Figure 6
// Volt-VAr Settings — the test values a BASIC-006 run is required to publish —
// includes 95.70 %VNom (wire: xvalue 9570, xMultiplier -2). On a whole-percent
// device that value cannot be held; it rounds into the register as 96 and the
// row is then measuring the FIXTURE's granularity. The 2026-08-17 bench battery
// caught it in the readback: [[91,40],[96,0],[104,0],[106,-40]].
//
// WHAT THESE TESTS PIN. Two devices, both real, both required:
//
//   - the DEFAULT one (V_SF -2) can hold the certification suite's own values
//     exactly, so a Figure-6 row measures the product;
//   - the COARSE one (-der-curve-vsf 0) still exists on demand, because a field
//     inverter declaring whole-percent resolution is perfectly conformant and
//     the product's tolerance of a device's declared quantum is a path that has
//     to keep being exercised. Its quantisation is asserted here as a PROPERTY,
//     not tolerated as an accident.
//
// and the invariants that make the lever safe to use: the axis never leaves the
// legal sunssf domain, the chain geometry does not move with the scale factor,
// and the default live curve keeps its engineering meaning at every setting.

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

// ctpFigure6 is CSIP CTP v1.3 BASIC-006 Figure 6 Volt-VAr Settings, Test Values
// column, in ENGINEERING units: (9100, 4000) (9570, 0) (10400, 0) (10600,
// -4000) published at xMultiplier -2 and yMultiplier -2. The 95.70 is the whole
// point of this file — it is the one breakpoint a whole-percent device cannot
// hold, and it is the certification suite's own number, not an invented one.
//
// The same values appear in internal/certify/suitecsip/register.go as the
// BASIC-006 row's wire payload; they are transcribed rather than imported
// because a fixture that derived its expectation from the code under test would
// prove nothing.
var ctpFigure6 = []sunspec.VVPoint{
	{V: 91.00, Var: 40.00},
	{V: 95.70, Var: 0},
	{V: 104.00, Var: 0},
	{V: 106.00, Var: -40.00},
}

// rawVoltVarPoints returns the RAW register words of the live (index 0) 705
// curve's points — the wire truth, before any scale factor is applied. Every
// claim about representability is made here rather than on decoded floats: a
// decoded float can agree to within rounding while the register holds a
// different number, which is exactly the failure being pinned.
func rawVoltVarPoints(t *testing.T, ss *SolarServer, n int) [][2]uint16 {
	t.Helper()
	cb := ss.curveByModel(sunspec.ModelDERVoltVar)
	out := make([][2]uint16, n)
	for j := 0; j < n; j++ {
		po := sunspec.PointOffset705(0, j, cb.npt)
		out[j] = [2]uint16{
			ss.Regs.Get(cb.base + uint16(po)),
			ss.Regs.Get(cb.base + uint16(po) + 1),
		}
	}
	return out
}

// negWord is the two's-complement register word for a negative int16 value —
// the var axis is signed and Go will not fold a negative constant into uint16.
func negWord(mag int16) uint16 { return uint16(-mag) }

// declaredSF reads a scale factor out of a curve model's HEADER as served.
func declaredSF(t *testing.T, ss *SolarServer, model uint16, name string) int16 {
	t.Helper()
	cb := ss.curveByModel(model)
	regs := readSlice(ss.Regs, cb.base, cb.hdr.Len()+advNCrv*cb.stride)
	sf, ok := cb.hdr.View(regs).SF(name)
	if !ok {
		t.Fatalf("model %d declares %s not-implemented", model, name)
	}
	return sf
}

// TestAdvVoltVarAxisHoldsTheCTPFigure6Voltages is the H-A oracle: on the
// default advanced sim, every voltage the certification suite's own Figure 6
// prescribes is REPRESENTABLE — the staged value reaches the register
// unrounded and is served back exactly.
//
// RED BEFORE THE FIX: with V_SF 0 the third assertion below fails on point 1,
// register 96 against the required 9570 (and the decode returns 96.00 %VNom for
// a commanded 95.70).
func TestAdvVoltVarAxisHoldsTheCTPFigure6Voltages(t *testing.T) {
	ss := newAdvSolar(t, 5000)

	// Errorf, not Fatalf: when this regresses, the run should also SHOW the
	// register the wrong declaration produces, not stop at the declaration.
	if sf := declaredSF(t, ss, sunspec.ModelDERVoltVar, "V_SF"); sf != -2 {
		t.Errorf("705 declares V_SF %d, want -2 (hundredths of %%VNom)", sf)
	}

	stageVoltVar(t, ss, sunspec.VoltVarCurve{DeptRef: 1, Pri: 1, Points: ctpFigure6})

	// The wire truth: 95.70 %VNom is register 9570, not 96.
	wantRaw := [][2]uint16{
		{9100, 40},
		{9570, 0},
		{10400, 0},
		{10600, negWord(40)},
	}
	got := rawVoltVarPoints(t, ss, len(ctpFigure6))
	for j := range wantRaw {
		if got[j] != wantRaw[j] {
			t.Errorf("live point[%d] raw = %v, want %v — the device cannot hold Figure 6's own value",
				j, got[j], wantRaw[j])
		}
	}

	// ...and it decodes back to the commanded engineering value.
	live := readLiveVoltVar(t, ss)
	if len(live.Points) != len(ctpFigure6) {
		t.Fatalf("live curve has %d points, want %d", len(live.Points), len(ctpFigure6))
	}
	for j, want := range ctpFigure6 {
		if math.Abs(live.Points[j].V-want.V) > 1e-9 || math.Abs(live.Points[j].Var-want.Var) > 1e-9 {
			t.Errorf("live point[%d] = (%.4f %%VNom, %.4f) served back for a commanded (%.4f, %.4f)",
				j, live.Points[j].V, live.Points[j].Var, want.V, want.Var)
		}
	}
}

// TestAdvVoltVarCoarseDeviceStillQuantisesOnDemand pins the OTHER real fleet
// shape. A device declaring V_SF 0 is conformant, its quantum is something the
// product must tolerate rather than something the bench should hide, and the
// lever brings it back verbatim — including the exact 95.70 -> 96 rounding the
// battery observed, so the tolerance path stays exercisable.
func TestAdvVoltVarCoarseDeviceStillQuantisesOnDemand(t *testing.T) {
	coarse := int16(0)
	ss := newAdvSolarOpts(t, 5000, AdvancedOptions{CurveVoltageSF: &coarse})

	if sf := declaredSF(t, ss, sunspec.ModelDERVoltVar, "V_SF"); sf != 0 {
		t.Fatalf("705 declares V_SF %d under the coarse lever, want 0", sf)
	}

	stageVoltVar(t, ss, sunspec.VoltVarCurve{DeptRef: 1, Pri: 1, Points: ctpFigure6})

	// The battery's own readback shape, reproduced deliberately.
	wantRaw := [][2]uint16{
		{91, 40},
		{96, 0},
		{104, 0},
		{106, negWord(40)},
	}
	got := rawVoltVarPoints(t, ss, len(ctpFigure6))
	for j := range wantRaw {
		if got[j] != wantRaw[j] {
			t.Errorf("coarse live point[%d] raw = %v, want %v", j, got[j], wantRaw[j])
		}
	}

	live := readLiveVoltVar(t, ss)
	if live.Points[1].V != 96 {
		t.Errorf("coarse device served %.4f %%VNom for a commanded 95.70; the quantum this lever "+
			"exists to reproduce is gone", live.Points[1].V)
	}
}

// TestAdvCurveVoltageSFLeverMovesOnlyTheVoltageAxis proves the lever's scope:
// it changes what 705 and 706 declare for VOLTAGE and touches nothing else —
// not 705's var axis, not 706's watt axis, and above all not 712, whose x axis
// is measured in %W and shares no argument with a voltage.
func TestAdvCurveVoltageSFLeverMovesOnlyTheVoltageAxis(t *testing.T) {
	coarse := int16(0)
	fine := newAdvSolar(t, 5000)
	rough := newAdvSolarOpts(t, 5000, AdvancedOptions{CurveVoltageSF: &coarse})

	for _, m := range []uint16{sunspec.ModelDERVoltVar, sunspec.ModelDERVoltWatt} {
		if sf := declaredSF(t, fine, m, "V_SF"); sf != -2 {
			t.Errorf("model %d default V_SF = %d, want -2", m, sf)
		}
		if sf := declaredSF(t, rough, m, "V_SF"); sf != 0 {
			t.Errorf("model %d levered V_SF = %d, want 0", m, sf)
		}
		// Untouched by the lever, on both devices.
		for _, other := range []string{"DeptRef_SF", "RspTms_SF"} {
			a, b := declaredSF(t, fine, m, other), declaredSF(t, rough, m, other)
			if a != b {
				t.Errorf("model %d %s moved with the voltage lever: %d -> %d", m, other, a, b)
			}
		}
	}

	// 712's x axis is %W. A "voltage" lever that re-scaled it would silently
	// change what a watt-var curve means.
	for _, name := range []string{"W_SF", "DeptRef_SF"} {
		a := declaredSF(t, fine, sunspec.ModelDERWattVar, name)
		b := declaredSF(t, rough, sunspec.ModelDERWattVar, name)
		if a != 0 || b != 0 {
			t.Errorf("712 %s = %d (default) / %d (levered), want 0 on both — the voltage lever must "+
				"not reach a watt axis", name, a, b)
		}
	}
}

// TestAdvCurveVoltageSFDoesNotMoveTheChain proves the lever is a DECLARATION
// change and nothing more: two images built at different voltage scale factors
// occupy exactly the same addresses, so every model-discovery walk, register
// dump and block length is unaffected and only the words that encode a voltage
// (plus the V_SF registers themselves) differ.
func TestAdvCurveVoltageSFDoesNotMoveTheChain(t *testing.T) {
	coarse := int16(0)
	fine := newAdvSolar(t, 5000)
	rough := newAdvSolarOpts(t, 5000, AdvancedOptions{CurveVoltageSF: &coarse})

	if fine.adv.End != rough.adv.End {
		t.Fatalf("advanced image ends at %d (default) vs %d (levered) — the lever moved the chain",
			fine.adv.End, rough.adv.End)
	}
	if len(fine.adv.Curves) != len(rough.adv.Curves) {
		t.Fatalf("curve count %d vs %d", len(fine.adv.Curves), len(rough.adv.Curves))
	}
	for i := range fine.adv.Curves {
		a, b := fine.adv.Curves[i], rough.adv.Curves[i]
		if a.id != b.id || a.base != b.base || a.stride != b.stride || a.hdrLen != b.hdrLen {
			t.Errorf("curve block %d moved: %+v vs %+v", i, a, b)
		}
	}

	// The register SETS are identical (same addresses populated); only some
	// VALUES differ, and every one of them belongs to 705 or 706.
	for addr := range fine.Regs.regs {
		if _, ok := rough.Regs.regs[addr]; !ok {
			t.Fatalf("address %d populated by the default image and absent from the levered one", addr)
		}
	}
	for addr := range rough.Regs.regs {
		if _, ok := fine.Regs.regs[addr]; !ok {
			t.Fatalf("address %d populated by the levered image and absent from the default one", addr)
		}
	}
	inVoltageModel := func(addr uint16) bool {
		for _, cb := range fine.adv.Curves {
			if cb.id != sunspec.ModelDERVoltVar && cb.id != sunspec.ModelDERVoltWatt {
				continue
			}
			end := cb.base + uint16(cb.hdrLen+advNCrv*cb.stride)
			if addr >= cb.base && addr < end {
				return true
			}
		}
		return false
	}
	differed := 0
	for addr, v := range fine.Regs.regs {
		if rough.Regs.regs[addr] == v {
			continue
		}
		differed++
		if !inVoltageModel(addr) {
			t.Errorf("register %d changed with the voltage lever (%d -> %d) and is outside 705/706",
				addr, v, rough.Regs.regs[addr])
		}
	}
	if differed == 0 {
		t.Error("no register differed between V_SF -2 and V_SF 0 — the lever did nothing")
	}
}

// TestAdvDefaultLiveCurveKeepsItsEngineeringMeaning pins the seed regression the
// axis change could have introduced silently. The default live curve is
// arbitrary, but it is arbitrary in ENGINEERING units (100 %VNom / 200 %VNom,
// +5 / -5): a seed written as raw register words would have become a 1.00/2.00
// %VNom curve the moment the scale factor moved, and nothing would have said so.
func TestAdvDefaultLiveCurveKeepsItsEngineeringMeaning(t *testing.T) {
	for _, sf := range []int16{0, -1, -2, 1} {
		sf := sf
		t.Run(sfName(sf), func(t *testing.T) {
			ss := newAdvSolarOpts(t, 5000, AdvancedOptions{CurveVoltageSF: &sf})
			live := readLiveVoltVar(t, ss)
			if len(live.Points) != 2 {
				t.Fatalf("default live curve has %d points, want 2", len(live.Points))
			}
			want := []sunspec.VVPoint{{V: 100, Var: 5}, {V: 200, Var: -5}}
			for j, w := range want {
				if math.Abs(live.Points[j].V-w.V) > 1e-9 || math.Abs(live.Points[j].Var-w.Var) > 1e-9 {
					t.Errorf("V_SF %d: default point[%d] = (%.4f, %.4f), want (%.1f, %.1f)",
						sf, j, live.Points[j].V, live.Points[j].Var, w.V, w.Var)
				}
			}
		})
	}
}

func sfName(sf int16) string { return "V_SF_" + strconv.Itoa(int(sf)) }

// TestAdvCurveVoltageAxisSpansEveryVoltageTheStandardsUse checks the fine axis
// did not trade one unrepresentable value for another. A uint16 at V_SF -2 tops
// out at 655.34 %VNom; the voltages this catalog and IEEE 1547-2018 Table 11/13
// actually use are all far below it, and each must encode EXACTLY (never
// saturated, never rounded).
func TestAdvCurveVoltageAxisSpansEveryVoltageTheStandardsUse(t *testing.T) {
	// CSIP CTP Figure 6/Figure 11 breakpoints, and the 1547 Category III
	// must-disconnect voltages the trip models carry (0.50/0.88/1.10/1.20 pu).
	voltages := []float64{0, 0.01, 50.00, 60.00, 88.00, 91.00, 95.70, 100.00,
		104.00, 105.00, 106.00, 109.00, 110.00, 120.00, 200.00, 655.34}
	for _, v := range voltages {
		raw, outcome := sunspec.EncodeScaleUint(v, advCurveVoltageSF)
		if !outcome.Representable() {
			t.Errorf("%.2f %%VNom is not representable at V_SF %d (outcome %v)",
				v, advCurveVoltageSF, outcome)
			continue
		}
		back := float64(raw) * math.Pow10(int(advCurveVoltageSF))
		if math.Abs(back-v) > 1e-9 {
			t.Errorf("%.2f %%VNom round-trips to %.4f at V_SF %d", v, back, advCurveVoltageSF)
		}
	}
	if !sunspec.ValidSF(advCurveVoltageSF) {
		t.Fatalf("advCurveVoltageSF %d is outside the legal sunssf domain", advCurveVoltageSF)
	}
}

// TestAdvCurveVoltageSFRefusesAnIllegalScaleFactor: a scale factor outside the
// sunssf domain does not make a "wrong" device, it makes one whose every curve
// point encodes to the NOT_IMPLEMENTED sentinel (EncodeBadSF, LXR-004) — a
// fixture that answers a different question than the one asked. Construction
// fails where the operator can see it.
func TestAdvCurveVoltageSFRefusesAnIllegalScaleFactor(t *testing.T) {
	for _, sf := range []int16{11, -11, 127, -128} {
		sf := sf
		if err := (AdvancedOptions{CurveVoltageSF: &sf}).Validate(); err == nil {
			t.Errorf("V_SF %d accepted; want a construction error", sf)
		}
		srv, err := NewSolarServerAdvancedOpts("tcp://127.0.0.1:0", 5000, "",
			AdvancedOptions{CurveVoltageSF: &sf})
		if err == nil {
			t.Errorf("NewSolarServerAdvancedOpts accepted V_SF %d", sf)
			if srv != nil {
				srv.Stop()
			}
		}
	}
	// A LEGAL sunssf that this axis still cannot serve is refused too, and for
	// a stated reason: the curve point is a uint16, so -3 tops the axis out at
	// 65.534 %VNom — under every ride-through boundary and under the device's
	// own resting curve — while +3 rounds a 100 %VNom breakpoint to zero. Both
	// are inside [-10,+10] and neither is a device.
	for _, sf := range []int16{-10, -3, 3, 10} {
		sf := sf
		if err := (AdvancedOptions{CurveVoltageSF: &sf}).Validate(); err == nil {
			t.Errorf("V_SF %d accepted; a uint16 %%VNom axis cannot serve it", sf)
		} else if !strings.Contains(err.Error(), "V_SF") {
			t.Errorf("V_SF %d refusal does not name the axis: %v", sf, err)
		}
	}

	// ...and the ones this axis CAN serve are accepted.
	for _, sf := range []int16{-2, -1, 0, 1, 2} {
		sf := sf
		if err := (AdvancedOptions{CurveVoltageSF: &sf}).Validate(); err != nil {
			t.Errorf("servable V_SF %d refused: %v", sf, err)
		}
	}
}
