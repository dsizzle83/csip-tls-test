package suitecsip

// rampdefault_test.go — BASIC-007's teeth, in the same shape teeth_test.go and
// directoracle_test.go already established: every assertion is driven once
// with input that satisfies it and once with input that does not, and the
// second run is the one that matters.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"lexa-proto/sunspec"
)

// wrmp704 builds a minimal model 704 image holding the given WRmp raw value
// (an unscaled uint16 percent-of-WMax-per-second — derlayout.go's own F("WRmp",
// Tuint16), no scale factor). Every scale factor this layout declares is
// zeroed so nothing else in the block reads as a sentinel.
func wrmp704(t *testing.T, wRmp uint16) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	for _, sfName := range []string{"PF_SF", "WMaxLimPct_SF", "WSet_SF", "WSetPct_SF", "VarSet_SF", "VarSetPct_SF"} {
		v.SetEnum(sfName, 0)
	}
	v.SetEnum("WRmp", wRmp)
	return regs
}

// esrmp703 builds a minimal model 703 image holding the given ESRmpTms
// (seconds, uint32).
func esrmp703(t *testing.T, rampS uint32) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L703.Len())
	v := sunspec.L703.View(regs)
	v.SetEnum("V_SF", 0)
	v.SetEnum("Hz_SF", 0)
	v.SetU32("ESRmpTms", rampS)
	return regs
}

// ── rampGradientOracle: the WRmp half is asserted ───────────────────────────

// GREEN: the DER's own WRmp reads exactly the commanded setGradW-derived
// percent.
func TestRampGradientOracle_PassesADERHoldingTheCommandedWRmp(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW) // 9000 -> 90%
	uv := unitWith(map[uint16][]uint16{704: wrmp704(t, 90)})

	got := o.Judge(uv)
	if got.Verdict != certify.Pass {
		t.Fatalf("verdict = %s against a DER holding WRmp=90 for a commanded setGradW=9000 (90%%): %s",
			got.Verdict, findingObserved(got))
	}
	t.Logf("GREEN — %s", got.Observed)
}

// RED: the DER's WRmp did not move to the commanded percent. This is the
// mutation proof — a referee that always PASSed here would certify a gateway
// that never wrote the register at all.
func TestRampGradientOracle_FailsADERWithTheWrongWRmp(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW) // wants 90
	uv := unitWith(map[uint16][]uint16{704: wrmp704(t, 50)})

	got := o.Judge(uv)
	if got.Verdict != certify.Fail {
		t.Fatalf("verdict = %s against a DER holding WRmp=50 for a commanded 90%%: %s",
			got.Verdict, findingObserved(got))
	}
	for _, want := range []string{"reads 50", "setGradW=9000", "90.00%"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not mention %q, so a reader cannot check the mismatch themselves: %s",
				want, got.Observed)
		}
	}
	t.Logf("RED — %s", got.Observed)
}

// A ±1 register-step tolerance is allowed (704's WRmp carries no scale
// factor, so 1 is its own finest increment) — but not more than that.
func TestRampGradientOracle_ToleratesOneRegisterStepAndNoMore(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW) // wants 90

	if got := o.Judge(unitWith(map[uint16][]uint16{704: wrmp704(t, 89)})); got.Verdict != certify.Pass {
		t.Errorf("WRmp=89 against a commanded 90 should be within the register's own quantization: %s",
			findingObserved(got))
	}
	if got := o.Judge(unitWith(map[uint16][]uint16{704: wrmp704(t, 88)})); got.Verdict != certify.Fail {
		t.Errorf("WRmp=88 against a commanded 90 is TWO steps off and should not be tolerated: %s",
			findingObserved(got))
	}
}

// A DER with no model 704 at all is Unavailable, not FAILed — there is
// nowhere for this row's setGradW half to have landed.
func TestRampGradientOracle_UnavailableWithNoModel704(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW)
	got := o.Judge(unitWith(map[uint16][]uint16{}))
	if got.Unavailable == "" {
		t.Fatalf("a 704-less DER produced a verdict (%s) rather than an unavailability: %s",
			got.Verdict, got.Observed)
	}
}

// ── rampGradientOracle: the ESRmpTms half is reported, never graded ─────────

// The verdict must stay keyed to WRmp alone: an ESRmpTms register holding
// something OTHER than what setSoftGradW would imply must not turn a correct
// WRmp reading into a FAIL, because this row's own procedure never schedules
// the enter-service transition that would cause lexa-gw to write it at all.
func TestRampGradientOracle_ESRmpTmsIsReportedButNeverGrades(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW)
	// ESRmpTms=0 — the register's power-on/never-written value, deliberately
	// NOT the 25s a commanded setSoftGradW=400 would resolve to
	// (100/4.00%=25s) if an energize transition ever executed it.
	uv := unitWith(map[uint16][]uint16{704: wrmp704(t, 90), 703: esrmp703(t, 0)})

	got := o.Judge(uv)
	if got.Verdict != certify.Pass {
		t.Fatalf("a correct WRmp reading was FAILed by an unrelated ESRmpTms register: %s",
			findingObserved(got))
	}
	for _, want := range []string{"ESRmpTms reads 0", "REPORTED, NOT ASSERTED", "Default-Only"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the observed text does not mention %q, so a reader would not know this half was "+
				"measured but not graded: %s", want, got.Observed)
		}
	}
	t.Logf("PASS with ESRmpTms reported, not graded — %s", got.Observed)
}

// A DER with no model 703 at all still grades on WRmp alone, and says why the
// other half has nothing to report.
func TestRampGradientOracle_NoModel703StillGradesWRmp(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW)
	got := o.Judge(unitWith(map[uint16][]uint16{704: wrmp704(t, 90)}))
	if got.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: a 703-less DER should still be graded on its WRmp alone: %s",
			got.Verdict, findingObserved(got))
	}
	if !strings.Contains(got.Observed, "serves no model 703") {
		t.Errorf("the observed text does not explain the missing 703, so a reader would not know why "+
			"ESRmpTms is absent from the verdict: %s", got.Observed)
	}
}

// ── critDefaultDERControlCarriesRamp ────────────────────────────────────────

// rampDdercXML builds one <DefaultDERControl>, with setGradW/setSoftGradW as
// SIBLINGS of DERControlBase (IEEE Std 2030.5-2018 p.252's own placement) —
// present only when non-nil, so a caller can build the "neither element"
// shape too. Named distinctly from sepdata_test.go's own no-arg ddercXML,
// which builds an unrelated fixed fixture.
func rampDdercXML(href string, setGradW, setSoftGradW *uint16) string {
	body := `<DefaultDERControl xmlns="urn:ieee:std:2030.5:ns" href="` + href + `">` +
		`<mRID>DDERC-SP-001</mRID>` +
		`<DERControlBase><opModExpLimW><multiplier>0</multiplier><value>5000</value></opModExpLimW></DERControlBase>`
	if setGradW != nil {
		body += rampElemXML("setGradW", *setGradW)
	}
	if setSoftGradW != nil {
		body += rampElemXML("setSoftGradW", *setSoftGradW)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` + body + `</DefaultDERControl>`
}

// rampElemXML renders one <name>v</name> element, reusing teeth_test.go's
// own itoa (int64) rather than declaring a second uint16 overload.
func rampElemXML(name string, v uint16) string {
	return "<" + name + ">" + itoa(int64(v)) + "</" + name + ">"
}

// GREEN: the DUT fetched a DefaultDERControl carrying exactly the row's
// commanded pair.
func TestCritDefaultDERControlCarriesRamp_PassesOnMatchingSibling(t *testing.T) {
	body := rampDdercXML("/derp/0/dderc", ptr(uint16(9000)), ptr(uint16(400)))
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil, synthTranscript(get("/derp/0/dderc", 200, body)))
	if f.Unavailable != "" {
		t.Fatalf("declined to decide where the elements WERE on the wire: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s against an exact match: %s", f.Verdict, f.Observed)
	}
}

// RED: the DefaultDERControl still carries the FIGURE 7 DEFAULT column
// (10000/200), not the Test Values this row commands (9000/400) — the shape a
// stale or never-updated default would leave behind.
func TestCritDefaultDERControlCarriesRamp_FailsOnTheWrongValues(t *testing.T) {
	body := rampDdercXML("/derp/0/dderc", ptr(uint16(10000)), ptr(uint16(200)))
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil, synthTranscript(get("/derp/0/dderc", 200, body)))
	if f.Unavailable != "" {
		t.Fatalf("declined to decide where the elements WERE on the wire, just at the wrong values: %s",
			f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s against a DefaultDERControl still carrying the DEFAULT column, not the Test "+
			"Values: %s", f.Verdict, f.Observed)
	}
	for _, want := range []string{"10000", "200", "9000", "400"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not mention %q: %s", want, f.Observed)
		}
	}
}

// FAIL naming the gap, not Unavailable: a DefaultDERControl with NEITHER
// element is the bench lever never having been exercised at all, which is
// still a decided finding about this row, not an abstention.
func TestCritDefaultDERControlCarriesRamp_FailsWhenElementsAbsent(t *testing.T) {
	body := rampDdercXML("/derp/0/dderc", nil, nil)
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil, synthTranscript(get("/derp/0/dderc", 200, body)))
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s (unavailable=%q) against a DefaultDERControl with neither ramp element: %s",
			f.Verdict, f.Unavailable, f.Observed)
	}
	if !strings.Contains(f.Observed, "none carrying a setGradW/setSoftGradW pair") {
		t.Errorf("the FAIL does not say the pair was entirely absent: %s", f.Observed)
	}
}

// No DefaultDERControl in the transcript at all is Unavailable, not FAILed —
// a bench/capture gap, not a statement about the DUT.
func TestCritDefaultDERControlCarriesRamp_UnavailableWithNoDefaultDERControl(t *testing.T) {
	reason := wantUnavailable(t, "no DefaultDERControl",
		critDefaultDERControlCarriesRamp(9000, 400),
		synthTranscript(get("/derp/0/derc", 200, dercListXML())))
	if !strings.Contains(reason, "DefaultDERControl") {
		t.Errorf("the unavailability does not name what was missing: %q", reason)
	}
}

// THE STRUCTURAL PROPERTY this criterion exists to have, that
// critDefaultDERControl's own "first resource of this type" shortcut does
// not: gridsim serves one DefaultDERControl per program (0, 1, 2). A DUT
// that fetches program 1's plain default BEFORE program 0's ramp-bearing one
// must still PASS — a criterion that only looked at the first fetch would
// FAIL a compliant run purely on fetch order.
func TestCritDefaultDERControlCarriesRamp_ScansEveryProgramNotJustTheFirst(t *testing.T) {
	other := rampDdercXML("/derp/1/dderc", nil, nil)
	mine := rampDdercXML("/derp/0/dderc", ptr(uint16(9000)), ptr(uint16(400)))
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil,
		synthTranscript(get("/derp/1/dderc", 200, other), get("/derp/0/dderc", 200, mine)))
	if f.Unavailable != "" {
		t.Fatalf("declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: a matching DefaultDERControl fetched SECOND was not found because an "+
			"earlier, unrelated program's default was scanned first: %s", f.Verdict, f.Observed)
	}
}

// ── Registration ─────────────────────────────────────────────────────────────

// BASIC-007 must be a REAL row now: registered, requiring gridsim (it creates
// its own precondition), and in its historical order slot.
func TestBASIC007_IsRegisteredAsARealRow(t *testing.T) {
	reg, ok := certify.Default().Lookup(uid("BASIC-007"))
	if !ok {
		t.Fatal("BASIC-007 is not registered at all")
	}
	if reg.Check == nil {
		t.Fatal("BASIC-007 is registered with a nil Check")
	}
	if reg.Order != 53 {
		t.Errorf("order = %d, want 53 (its slot among the twelve BASIC-004..015 rows)", reg.Order)
	}
	needsGridSim := false
	for _, r := range reg.Requires {
		if r == "gridsim" {
			needsGridSim = true
		}
	}
	if !needsGridSim {
		t.Errorf("Requires = %v: this row authors its own DefaultDERControl precondition and cannot run "+
			"without gridsim's admin API", reg.Requires)
	}
}

// BASIC-007 must no longer appear in inverterControlRows: it has its own
// apparatus now (this row exists to pin that the migration in
// registerInverterControls does not silently regress into a double
// registration, which Register's own panic would catch at init() time, but
// this states the intent directly rather than relying on that side effect).
func TestBASIC007_IsNotInTheUniformInverterControlRows(t *testing.T) {
	for _, r := range inverterControlRows() {
		if r.id == "BASIC-007" {
			t.Fatal("BASIC-007 is still in inverterControlRows: it is registered a second time by " +
				"registerRampRates, which would have panicked at init() — but if this ever stops " +
				"panicking (e.g. a Register() change tolerating duplicates), this row's own apparatus " +
				"would be shadowed by the uniform machinery's unreachableMode shape")
		}
	}
}
