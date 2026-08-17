package suitecsip

// wattvar_test.go — the end-to-end MEASUREMENT of opModWattVar, and the honest
// record of the one piece that cannot be built yet.
//
// # The gap
//
// The product routes opModWattVar end to end (IW15-015) and nothing in this
// suite measured it. The axis matters more than its absence suggests: 712 (DER
// Watt-Var) is the bank BASIC-015 used to grade opModWattPF against, on a
// mapping that said "there being no Watt-PF model in the 7xx set". That was
// wrong — 712 is a different function — and BASIC-015 is now a REFUSAL row that
// asserts nothing in 712 moved. So this suite currently measures 712 only as an
// ABSENCE. Nothing proves the positive half: that a control which really is
// opModWattVar DOES land there. Without it, "the product does not confuse the
// two commands" rests on one of the two observations.
//
// # Why this is a test file and not a registered row
//
// A registered row needs a catalog UID, and THERE IS NONE. CSIP-CONF-v1.3's
// BASIC family stops at BASIC-015 and no procedure in it prescribes an
// opModWattVar curve — register.go says so already. Inventing one is not
// available: certify's runner ABORTS THE WHOLE CAMPAIGN on a registered uid the
// catalog does not contain (runner.go, "a registration for a uid the catalog
// does not contain means the suite and the specification have diverged"), and
// bypassing that by adding a case to the catalog would put a procedure into a
// conformance bundle that no published document asks for, with Test Values this
// harness invented. That is a fabricated conformance claim, and it is worth more
// to leave the row unregistered than to manufacture provenance for it.
//
// What IS buildable — and is built here — is every part of the row except its
// catalog identity: the binding, the publish path, the served document, the
// southbound adopt and the oracle's verdict, all driven through the SAME code a
// registered row would use. When a UID exists the row is one registration line,
// assembling parts that are already proven.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"lexa-proto/sunspec"
)

// adoptWattVar drives the REAL derbase adopt handshake with exactly the
// breakpoints the binding publishes — the write a gateway that EXECUTED this
// control would make.
//
// DeptRef comes from the binding's own yRefType through the same translation the
// oracle expects, never from a literal, so the fixture cannot model a gateway
// that wrote the points under a reference nobody commanded.
func (f *curveFixture) adoptWattVar(t *testing.T) {
	t.Helper()
	b := wattVarBinding()
	deptRef, ok := b.wantDeptRef(sunspec.ModelDERWattVar)
	if !ok {
		t.Fatalf("the binding's yRefType %d has no DeptRef translation for model 712", b.YRefType)
	}
	var pts []sunspec.WVPoint
	for _, p := range b.wantPoints() {
		pts = append(pts, sunspec.WVPoint{W: p.X, Var: p.Y})
	}
	if err := f.base.WriteWattVar(
		sunspec.WattVarCurve{DeptRef: deptRef, Pri: 1, Points: pts},
		"wattvar-oracle-test"); err != nil {
		t.Fatalf("derbase WriteWattVar (the real adopt handshake): %v", err)
	}
}

// TestWattVar_PublishesTheAxisAndTheServedDocumentCarriesIt proves the
// northbound half: the lever really puts an <opModWattVar> DERCurveLink on the
// wire, resolvable to a DERCurve of the right type.
//
// The assertion is on the SERVED document, not on what the publisher believes it
// sent — a binding can name an element the publisher drops or the server never
// serves, and both read from inside the harness as a row that authored it.
func TestWattVar_PublishesTheAxisAndTheServedDocumentCarriesIt(t *testing.T) {
	f := newCurveFixture(t)
	d, gs := f.withGridSimServer(t)
	spec := inverterControlSpec(curveMode("opModWattVar", wattVarBinding()),
		"a Watt-Var curve", "CERT-WATTVAR")

	params := map[string]string{pollWindowParam: "20ms"}
	if err := spec.Setup(context.Background(), d, params); err != nil {
		t.Fatalf("watt-var Setup: %v", err)
	}

	derc := servedByGridSim(t, gs, "/derp/0/derc")
	// A CurveLink, so the element carries an href ATTRIBUTE — matching on
	// "<opModWattVar>" would miss the very shape the axis is supposed to take.
	if !strings.Contains(derc, "<opModWattVar href=") {
		t.Fatalf("the served DERControlList carries no <opModWattVar href=...>; the axis never reached "+
			"the wire as a curve link:\n%s", derc)
	}
	href := params[curveHrefParam]
	if href == "" {
		t.Fatal("the row published no curve href, so the link resolves to nothing")
	}
	// The link on the wire must be the href the row recorded, or the row is
	// asserting against a curve the document does not point at.
	if !strings.Contains(derc, `<opModWattVar href="`+href+`"`) {
		t.Errorf("the served opModWattVar link does not point at the row's own curve %q:\n%s", href, derc)
	}
	curve := servedByGridSim(t, gs, href)
	// DERCurveType 14 is opModWattVar (IEEE Std 2030.5-2018 p.254). 10 is the
	// pre-publication draft's value and would mean the fixture is still citing
	// the document this bench renounced.
	if !strings.Contains(curve, "<curveType>14</curveType>") {
		t.Errorf("the resolved DERCurve at %s is not curveType 14 (opModWattVar):\n%s", href, curve)
	}
}

// TestWattVar_GoesGreenWhenTheDERAdoptsTheCurve is the positive half BASIC-015
// cannot provide: a control that really is opModWattVar DOES land in 712.
func TestWattVar_GoesGreenWhenTheDERAdoptsTheCurve(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	spec := inverterControlSpec(curveMode("opModWattVar", wattVarBinding()),
		"a Watt-Var curve", "CERT-WATTVAR")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := spec.Setup(ctx, d, params); err != nil {
		t.Fatalf("watt-var Setup: %v", err)
	}
	// Stand in for the DUT's poll cycle: adopt exactly what the row published.
	f.adoptWattVar(t)
	if err := spec.PostWait(ctx, d, params); err != nil {
		t.Fatalf("watt-var PostWait: %v", err)
	}

	obs := &Observation{Params: params}
	if got := spec.Verdict(obs); got != "" {
		t.Fatalf("the declared verdict on a DER that adopted this row's own Q(P) curve = %q, want \"\": %s",
			got, spec.Notes(obs))
	}
	if fnd := curveOutcome(wattVarBinding(), obs); fnd.Verdict != certify.Pass {
		t.Fatalf("the curve outcome on an adopting DER = %s: %s", fnd.Verdict, fnd.Observed)
	}
}

// TestWattVar_IsRedAgainstADERThatIgnoresTheAxis is the teeth. A row that could
// not tell an adopting DER from one that left 712 at its seeded default would be
// certifying the axis on the strength of having published it.
func TestWattVar_IsRedAgainstADERThatIgnoresTheAxis(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	spec := inverterControlSpec(curveMode("opModWattVar", wattVarBinding()),
		"a Watt-Var curve", "CERT-WATTVAR")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := spec.Setup(ctx, d, params); err != nil {
		t.Fatalf("watt-var Setup: %v", err)
	}
	// No adopt: the DER keeps whatever 712 already held.
	if err := spec.PostWait(ctx, d, params); err != nil {
		t.Fatalf("watt-var PostWait: %v", err)
	}
	obs := &Observation{Params: params}
	if fnd := curveOutcome(wattVarBinding(), obs); fnd.Verdict == certify.Pass {
		t.Fatalf("the curve outcome PASSED against a DER that never adopted the curve: %s", fnd.Observed)
	}
}

// TestWattVar_712HasNoOpenLoopTimingHome pins the model fact the binding rests
// on, against the compiled layout rather than against this file's opinion.
//
// 705/706/711 all declare RspTms and the oracle asserts openLoopTms against it.
// 712 does not, so a binding that authored an openLoopTms would be sending an
// element this referee must stay silent about southbound — and a future
// re-vendor that ADDED RspTms to 712 would silently turn that silence into a
// missed assertion.
func TestWattVar_712HasNoOpenLoopTimingHome(t *testing.T) {
	if home := openLoopHome(sunspec.ModelDERWattVar); home != "" {
		t.Errorf("openLoopHome(712) = %q, want empty: model 712's curve group is {ActPt, DeptRef, Pri, "+
			"ReadOnly} and declares no RspTms", home)
	}
	if sunspec.L712Crv.Has("RspTms") {
		t.Error("the compiled M712 curve layout now has RspTms — if the model genuinely gained one, the " +
			"staged watt-var binding should author an openLoopTms and the oracle should assert it")
	}
	// And the sibling that DOES have one, so this row cannot pass by the
	// helper simply always returning empty.
	if home := openLoopHome(sunspec.ModelDERVoltVar); home == "" {
		t.Error("openLoopHome(705) is empty, so the 712 assertion above proves nothing")
	}
}
