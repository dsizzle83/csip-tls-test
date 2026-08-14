package invariant

// curves_test.go exercises the curve decode both ways round: against a register
// image a conformant device would present, and against every image that must
// NOT be read as a device holding the curve it was asked for.
//
// The images are built with lexa-proto/sunspec's own encoders rather than by
// hand, so what is under test is this package's READING of a block the shared
// layout tables produced — not an agreement between two hand-written mistakes.

import (
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

const testNPt = 4

// voltVarBlock builds a model 705 data block whose LIVE curve (index 0) holds
// pts, with the adopt result and enable the caller asks for.
func voltVarBlock(t *testing.T, pts []sunspec.VVPoint, adoptRslt, ena uint16) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.CurveOffset705(2, testNPt))
	h := sunspec.L705Hdr.View(regs)
	h.SetU16At(sunspec.L705Hdr.Offset("NPt"), testNPt)
	h.SetU16At(sunspec.L705Hdr.Offset("NCrv"), 2)
	h.SetU16At(sunspec.L705Hdr.Offset("AdptCrvRslt"), adoptRslt)
	h.SetU16At(sunspec.L705Hdr.Offset("Ena"), ena)
	if _, _, err := sunspec.Encode705Curve(regs, 0, sunspec.VoltVarCurve{
		DeptRef: 1, Pri: 1, Points: pts,
	}); err != nil {
		t.Fatalf("encode the live volt-var curve: %v", err)
	}
	// Encode writes a STAGING curve, which is writable; the live one is
	// read-only on a conformant device.
	h.SetU16At(sunspec.CurveOffset705(0, testNPt)+sunspec.L705Crv.Offset("ReadOnly"), 1)
	return regs
}

func pts(vals ...float64) []sunspec.VVPoint {
	out := make([]sunspec.VVPoint, 0, len(vals)/2)
	for i := 0; i+1 < len(vals); i += 2 {
		out = append(out, sunspec.VVPoint{V: vals[i], Var: vals[i+1]})
	}
	return out
}

func want(vals ...float64) []CurvePoint {
	out := make([]CurvePoint, 0, len(vals)/2)
	for i := 0; i+1 < len(vals); i += 2 {
		out = append(out, CurvePoint{X: vals[i], Y: vals[i+1]})
	}
	return out
}

func exact(float64) float64 { return 0.5 }

func TestDecodeCurve_ReadsTheLiveCurveAndItsAdoptState(t *testing.T) {
	regs := voltVarBlock(t, pts(92, 60, 98, 0, 102, 0, 108, -60), sunspec.AdptCompleted, 1)
	v := DecodeCurve("test", sunspec.ModelDERVoltVar, regs)
	if !v.Present {
		t.Fatalf("a served, well-formed 705 decoded as absent: %s", v.Err)
	}
	if !v.Adopted || !v.Enabled || !v.ReadOnly {
		t.Fatalf("adopt/enable/read-only = %t/%t/%t, want true/true/true (%s)",
			v.Adopted, v.Enabled, v.ReadOnly, v.Describe())
	}
	if v.NPt != testNPt || v.NCrv != 2 {
		t.Errorf("geometry = NPt %d NCrv %d, want %d/2", v.NPt, v.NCrv, testNPt)
	}
	got := MatchPoints(v.Points, want(92, 60, 98, 0, 102, 0, 108, -60), exact)
	if !got.Matched {
		t.Fatalf("the decoded live curve does not match what was encoded into it: %s", got.Reason)
	}
	if !strings.Contains(v.Describe(), "M705 Volt-Var") {
		t.Errorf("Describe does not name the model: %s", v.Describe())
	}
}

// TestDecodeCurve_AbsentModelIsNotAnEmptyCurve: "the device does not serve this
// model" and "the device serves it and adopted nothing" are different answers
// to a conformance question, and collapsing them would let a device that cannot
// carry a function read the same as one that simply has not been given one.
func TestDecodeCurve_AbsentModelIsNotAnEmptyCurve(t *testing.T) {
	v := DecodeCurve("test", sunspec.ModelDERVoltVar, nil)
	if v.Present {
		t.Fatal("an unserved model decoded as present")
	}
	if v.Adopted || v.Enabled || len(v.Points) != 0 {
		t.Fatalf("an unserved model decoded with state: %+v", v)
	}
	if !strings.Contains(v.Describe(), "not served") {
		t.Errorf("Describe does not say the model is absent: %s", v.Describe())
	}
}

// TestDecodeCurve_ShortBlockIsAnErrorNotAZeroCurve: a truncated read must be
// reported, never decoded into a curve of zeroes that an oracle would then
// compare against.
func TestDecodeCurve_ShortBlockIsAnErrorNotAZeroCurve(t *testing.T) {
	v := DecodeCurve("test", sunspec.ModelDERVoltVar, make([]uint16, 3))
	if v.Present {
		t.Fatal("a truncated 705 decoded as present")
	}
	if v.Err == "" {
		t.Fatal("a truncated 705 decoded without recording why")
	}
}

// TestDecodeCurve_UnknownModelIsRefused: this package will not pretend to
// understand a model it has no layout for.
func TestDecodeCurve_UnknownModelIsRefused(t *testing.T) {
	v := DecodeCurve("test", 999, []uint16{1, 2, 3})
	if v.Present || v.Err == "" {
		t.Fatalf("model 999 decoded as %+v; it is not a curve model this package knows", v)
	}
}

// TestDecodeCurve_FreqDroopIsPointlessAndSaysSo: 711 stores a parametric droop,
// not breakpoints. A caller correlating a published curve's points has to be
// able to learn that from the view rather than infer it from an empty slice.
func TestDecodeCurve_FreqDroopIsPointlessAndSaysSo(t *testing.T) {
	regs := make([]uint16, sunspec.CtlOffset711(2))
	h := sunspec.L711Hdr.View(regs)
	h.SetU16At(sunspec.L711Hdr.Offset("NCtl"), 2)
	h.SetU16At(sunspec.L711Hdr.Offset("AdptCtlRslt"), sunspec.AdptCompleted)
	h.SetU16At(sunspec.L711Hdr.Offset("Ena"), 1)
	v := DecodeCurve("test", sunspec.ModelDERFreqDroop, regs)
	if !v.Present {
		t.Fatalf("a served 711 decoded as absent: %s", v.Err)
	}
	if !v.Pointless() {
		t.Fatal("711 did not report itself as carrying no breakpoint table")
	}
	if len(v.Points) != 0 {
		t.Fatalf("711 decoded %d breakpoints; it has no point table", len(v.Points))
	}
	if !strings.Contains(v.Describe(), "no breakpoint table") {
		t.Errorf("Describe does not say 711 is parametric: %s", v.Describe())
	}
}

// TestMatchPoints_HasTeeth is the whole comparison contract, one case per way a
// device can hold "a curve" that is not the commanded one.
func TestMatchPoints_HasTeeth(t *testing.T) {
	commanded := want(92, 60, 98, 0, 102, 0, 108, -60)

	if m := MatchPoints(want(92, 60, 98, 0, 102, 0, 108, -60), commanded, exact); !m.Matched {
		t.Fatalf("the exact commanded curve did not match: %s", m.Reason)
	}
	// Within a rounding step of the device's own scale factor.
	if m := MatchPoints(want(92, 60, 98, 0.4, 102, 0, 108, -60), commanded, exact); !m.Matched {
		t.Fatalf("a curve inside the tolerance did not match: %s", m.Reason)
	}

	for _, c := range []struct {
		name string
		got  []CurvePoint
		says string
	}{
		{"a different curve", want(230, 30, 240, 0, 250, -30, 260, -60), "differs"},
		{"the same points REORDERED — a different piecewise function",
			want(108, -60, 102, 0, 98, 0, 92, 60), "differs"},
		{"one breakpoint short", want(92, 60, 98, 0, 102, 0), "breakpoint(s)"},
		{"one breakpoint too many",
			want(92, 60, 98, 0, 102, 0, 108, -60, 112, -80), "breakpoint(s)"},
		{"the right shape on the wrong SIGN", want(92, -60, 98, 0, 102, 0, 108, 60), "differs"},
		{"no curve at all", nil, "breakpoint(s)"},
	} {
		m := MatchPoints(c.got, commanded, exact)
		if m.Matched {
			t.Errorf("%s was accepted as the commanded curve", c.name)
			continue
		}
		if !strings.Contains(m.Reason, c.says) {
			t.Errorf("%s: reason %q does not say %q", c.name, m.Reason, c.says)
		}
		// A reader has to be able to see BOTH curves to act on the failure.
		if !strings.Contains(m.Reason, "(92, 60)") {
			t.Errorf("%s: the reason does not quote the commanded curve: %s", c.name, m.Reason)
		}
	}
}

// TestMatchPoints_NoCommandedCurveIsNotAMatch: correlating against nothing is
// not a successful correlation.
func TestMatchPoints_NoCommandedCurveIsNotAMatch(t *testing.T) {
	if m := MatchPoints(want(1, 2), nil, exact); m.Matched {
		t.Fatal("an empty commanded curve matched — there was nothing to correlate")
	}
}

// TestCurveModelsAreTheOnesTheSourcesRead pins the one list: a model this
// package can decode but no source reads would be a decode that never runs, and
// a model read but not decodable would be registers nobody can interpret.
func TestCurveModelsAreTheOnesTheSourcesRead(t *testing.T) {
	for _, m := range CurveModels() {
		if _, ok := CurveAxisOf(m); !ok {
			t.Errorf("CurveModels lists %d, which CurveAxisOf cannot describe", m)
		}
		var found bool
		for _, r := range modelsOfInterest {
			if r == m {
				found = true
			}
		}
		if !found {
			t.Errorf("curve model %d is decodable but no register-image source reads it", m)
		}
	}
	for _, base := range []uint16{701, 702, 703, 704} {
		var found bool
		for _, r := range modelsOfInterest {
			if r == base {
				found = true
			}
		}
		if !found {
			t.Errorf("model %d dropped out of modelsOfInterest when the curve models were added", base)
		}
	}
}
