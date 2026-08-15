package suitecsip

// curve_oracle_test.go is IW15-008's teeth: the curve rows' southbound oracle
// and the refused-axis rows' refusal oracle, each exercised against input that
// satisfies it AND against every input that must not.
//
// The fixture is a REAL advanced DER simulator (sim/southbound's
// NewSolarServerAdvanced — models 701/702/703/704 plus the 705/706/711/712
// curve models with the §3.1.2 adopt handshake) driven through the REAL
// lexa-proto derbase writer the product's own reconciler uses. Nothing here
// hand-crafts a register map: a hand-built image can be made to agree with a
// hand-built oracle while both disagree with what a device actually holds, and
// that is precisely the class of error this file exists to catch.
//
// The RED case comes first and is the important one. A DER whose curve models
// were never written is EXACTLY the southbound state the current product leaves
// behind for these rows — it refuses the curve axes at receipt
// (lexa-gw internal/northbound/scheduler/supported.go: ScalarSupportedAxes
// carries no curve mode, and the advanced set is gated behind
// advanced_axes_enabled) — and before this change every one of those rows
// reported applicable-PASS against it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"csip-tls-test/sim/gridsim"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/derbase"
	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

// curveFixture is a live advanced DER sim, a real derbase writer onto it, and a
// RunCtx whose oracle sim slot serves that same device's register image through
// a simapi-shaped /registers — the shape internal/invariant.SimAPIDER reads in
// production, gw-campaign and gw-mayhem.
type curveFixture struct {
	ss   *sim.SolarServer
	base *derbase.Base
	rc   *certify.RunCtx
}

func newCurveFixture(t *testing.T) *curveFixture {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	url := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	ss, err := sim.NewSolarServerAdvanced(url, 5000, "SN-CURVE-ORACLE")
	if err != nil {
		t.Fatalf("start the advanced DER sim: %v", err)
	}
	t.Cleanup(ss.Stop)

	trans, err := modbus.NewTransport(url, 2*time.Second)
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	if err := trans.Open(); err != nil {
		t.Fatalf("open transport: %v", err)
	}
	t.Cleanup(func() { _ = trans.Close() })
	if err := trans.SetUnitID(1); err != nil {
		t.Fatalf("set unit id: %v", err)
	}
	reader, err := sunspec.NewReader(trans)
	if err != nil {
		t.Fatalf("sunspec reader: %v", err)
	}
	b, err := derbase.Init(reader, "curve-oracle-test")
	if err != nil {
		t.Fatalf("derbase init: %v", err)
	}
	b.AdoptPollTimeout = 500 * time.Millisecond

	mux := http.NewServeMux()
	mux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ss.Registers())
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"paused": false, "sessions": []any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &curveFixture{ss: ss, base: &b, rc: &certify.RunCtx{
		Case: &certify.Case{UID: "csip-conf-v1.3::BASIC-006", ID: "BASIC-006"},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, srv.URL, http.DefaultClient),
		},
	}}
}

// setHeaderReg writes one header register of a curve model directly into the
// device's bank. It is used ONLY to manufacture states a correct writer never
// produces (an adopted curve in a switched-off function), which is the whole
// point of an inverted test case; every state a correct writer DOES produce is
// produced here by the real writer.
func (f *curveFixture) setHeaderReg(t *testing.T, model uint16, field string, val uint16) {
	t.Helper()
	blk, err := sunspec.FindModel(f.base.Reader.Blocks(), model)
	if err != nil {
		t.Fatalf("find model %d in the sim's chain: %v", model, err)
	}
	hdr, _, _, _ := curveHeaderForTest(model)
	off := hdr.Offset(field)
	if off < 0 {
		t.Fatalf("model %d header has no %s", model, field)
	}
	f.ss.Regs.Set(blk.BaseAddr+uint16(off), val)
}

// rcCurveView reads one curve model back through the same referee path the
// oracle uses, so a test can assert on what the fingerprint will see.
func (f *curveFixture) rcCurveView(t *testing.T, model uint16) invariant.CurveView {
	t.Helper()
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER through the referee: %v", err)
	}
	return uv.Curve(oracleSimName, model)
}

// curveHeaderForTest mirrors invariant's own header table so a test can address
// a header register by name without exporting that table.
func curveHeaderForTest(model uint16) (*sunspec.Layout, string, string, string) {
	switch model {
	case sunspec.ModelDERVoltVar:
		return sunspec.L705Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	case sunspec.ModelDERVoltWatt:
		return sunspec.L706Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	case sunspec.ModelDERWattVar:
		return sunspec.L712Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	default:
		return sunspec.L711Hdr, "AdptCtlReq", "AdptCtlRslt", "NCtl"
	}
}

// basic006Binding is the BASIC-006 row's own binding, built from the identical
// literals register.go registers it with — so what this file proves is a
// property of the SHIPPING row, not of a curve invented for a test.
func basic006Binding() *curveBinding {
	return &curveBinding{
		Mode:   "volt_var",
		Points: []CurvePoint{{X: 92, Y: 60}, {X: 98, Y: 0}, {X: 102, Y: 0}, {X: 108, Y: -60}},
		Model:  sunspec.ModelDERVoltVar, YRefType: 3, Mapping: mappingVoltVar,
	}
}

// adoptBasic006Curve drives the REAL derbase adopt handshake with exactly the
// breakpoints BASIC-006 publishes — the write a gateway that EXECUTED this row's
// control would make.
//
// DeptRef comes from the row's OWN yRefType through the same translation the
// oracle expects, not from a literal. It was a hardcoded 1 (VAR_MAX_PCT) while
// the row published yRefType=3 (%statVarAvail, which is DeptRef 2), so this
// fixture modelled a gateway that wrote the points under a reference nobody
// commanded — the exact defect lexa-gw's curveDeptRef landed to end, reproduced
// inside the test that was supposed to certify the fix.
func (f *curveFixture) adoptBasic006Curve(t *testing.T) {
	t.Helper()
	f.adoptVoltVar(t, basic006DeptRef(t),
		[]sunspec.VVPoint{{V: 92, Var: 60}, {V: 98, Var: 0}, {V: 102, Var: 0}, {V: 108, Var: -60}})
}

// basic006DeptRef is the DeptRef a gateway executing BASIC-006 must write,
// derived from the SHIPPING row's yRefType rather than restated.
func basic006DeptRef(t *testing.T) uint16 {
	t.Helper()
	want, ok := basic006Binding().wantDeptRef()
	if !ok {
		t.Fatalf("BASIC-006's yRefType has no DeptRef translation — the row publishes a curve a " +
			"conformant DUT must refuse, which is not what this fixture is for")
	}
	return want
}

func (f *curveFixture) adoptVoltVar(t *testing.T, deptRef uint16, pts []sunspec.VVPoint) {
	t.Helper()
	if err := f.base.WriteVoltVar(sunspec.VoltVarCurve{DeptRef: deptRef, Pri: 1, Points: pts},
		"curve-oracle-test"); err != nil {
		t.Fatalf("derbase WriteVoltVar (the real adopt handshake): %v", err)
	}
}

// ── The RED case: the product's actual posture ──────────────────────────────

// TestOracleCurve_UnadoptedDERIsAFail is the finding, reproduced.
//
// The device is exactly as the current product leaves it for BASIC-006: it
// SERVES model 705, and nothing was ever adopted into it, because the gateway
// refuses the volt-var axis at receipt with the advanced overlay dark. Before
// IW15-008 this row's southbound criterion was a SKIP and the row reported
// applicable-PASS on the strength of an <opModVoltVar> element appearing in
// something the DUT fetched. It must now FAIL, and the FAIL must name what the
// DER actually holds so a reader can tell "never adopted" from "adopted the
// wrong thing".
func TestOracleCurve_UnadoptedDERIsAFail(t *testing.T) {
	f := newCurveFixture(t)
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("an unadopted DER = %s (%s), want FAIL — a row that measured nothing must not pass",
			got.Verdict, got.Observed)
	}
	for _, want := range []string{"never COMPLETED", "M705 Volt-Var", "(92, 60)"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not say %q; it said: %s", want, got.Observed)
		}
	}
}

// TestOracleCurve_AdoptedRowsOwnCurveIsAPass is the green half: a gateway that
// really did adopt this row's breakpoints, through the real derbase writer, is
// reported as such — so the FAIL above is a discrimination and not a constant.
func TestOracleCurve_AdoptedRowsOwnCurveIsAPass(t *testing.T) {
	f := newCurveFixture(t)
	f.adoptBasic006Curve(t)
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Pass {
		t.Fatalf("the row's own curve, adopted through the real derbase handshake = %s (%s), want PASS",
			got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "COMPLETED") || !strings.Contains(got.Observed, "ENABLED") {
		t.Errorf("the PASS does not state the adopt/enable state it rests on: %s", got.Observed)
	}
}

// TestOracleCurve_ADifferentCurveIsStillAFail: the device adopted A curve, just
// not this row's. "Some curve is present" is the weaker claim the pre-fix row
// could not even make; it must not be mistaken for this one.
func TestOracleCurve_ADifferentCurveIsStillAFail(t *testing.T) {
	f := newCurveFixture(t)
	f.adoptVoltVar(t, basic006DeptRef(t), []sunspec.VVPoint{{V: 230, Var: 30}, {V: 240, Var: 0}, {V: 250, Var: -30}})
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("an unrelated adopted curve = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "(230, 30)") || !strings.Contains(got.Observed, "(92, 60)") {
		t.Errorf("the FAIL must show BOTH curves so a reader can see the difference; it said: %s",
			got.Observed)
	}
}

// TestOracleCurve_ReorderedCurveIsStillAFail: the same four breakpoints in a
// different order describe a DIFFERENT piecewise function. A comparison that
// treated a curve as a set rather than a sequence would pass this.
func TestOracleCurve_ReorderedCurveIsStillAFail(t *testing.T) {
	f := newCurveFixture(t)
	f.adoptVoltVar(t, basic006DeptRef(t), []sunspec.VVPoint{{V: 108, Var: -60}, {V: 102, Var: 0}, {V: 98, Var: 0}, {V: 92, Var: 60}})
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("the row's breakpoints in reverse order = %s (%s), want FAIL — a curve is a sequence",
			got.Verdict, got.Observed)
	}
}

// TestOracleCurve_ExtraBreakpointIsStillAFail: a fifth segment nobody commanded
// is content the head end did not send.
func TestOracleCurve_ExtraBreakpointIsStillAFail(t *testing.T) {
	f := newCurveFixture(t)
	f.adoptVoltVar(t, basic006DeptRef(t), []sunspec.VVPoint{
		{V: 92, Var: 60}, {V: 98, Var: 0}, {V: 102, Var: 0}, {V: 108, Var: -60}, {V: 112, Var: -80}})
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("an extra breakpoint = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
}

// TestOracleCurve_RightPointsWrongDeptRefIsAFail is the D2 §6.4 shape, and the
// one defect in this family that EVERY other check in the suite is blind to.
//
// The device adopts exactly the breakpoints the row published, into the right
// model, with the handshake COMPLETED and the function ENABLED — and records
// that its y values are a percentage of the wrong rating. "-60" against
// VAR_MAX_PCT and "-60" against VAR_AVAL_PCT are different commands: on a
// 26.4 kvar DER at half its available reactive headroom they differ by 2x, and
// nothing about the points, the adopt state or the enable distinguishes them.
//
// The product's own read-back hash cannot catch it either, and that is why the
// referee has to: the hash carries the DOCUMENT's yRefType at both ends, so it
// can only ever confirm that the points round-tripped. Until 2026-08-14 the
// gateway copied whatever DeptRef the device's template already held and wrote
// the commanded points underneath it, which is exactly what this test now
// simulates.
func TestOracleCurve_RightPointsWrongDeptRefIsAFail(t *testing.T) {
	f := newCurveFixture(t)
	want := basic006DeptRef(t)
	f.adoptVoltVar(t, want+1, // any OTHER reference; the points below are the row's own
		[]sunspec.VVPoint{{V: 92, Var: 60}, {V: 98, Var: 0}, {V: 102, Var: 0}, {V: 108, Var: -60}})
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("the row's exact breakpoints under the WRONG y-axis reference = %s (%s), want FAIL — "+
			"the same numbers against a different base are a different command", got.Verdict, got.Observed)
	}
	for _, wantText := range []string{"DeptRef", "yRefType", "%statVarAvail"} {
		if !strings.Contains(got.Observed, wantText) {
			t.Errorf("the FAIL does not say %q; it said: %s", wantText, got.Observed)
		}
	}
}

// TestOracleCurve_AdoptedButDisabledIsStillAFail: the content is right and the
// function is switched off, so it commands nothing. A register-content check
// that ignored Ena would call this execution.
func TestOracleCurve_AdoptedButDisabledIsStillAFail(t *testing.T) {
	f := newCurveFixture(t)
	f.adoptBasic006Curve(t)
	f.setHeaderReg(t, sunspec.ModelDERVoltVar, "Ena", 0)
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("the right curve in a DISABLED function = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "DISABLED") {
		t.Errorf("the FAIL does not name the disable it turned on: %s", got.Observed)
	}
}

// TestOracleCurve_LyingAdoptIsStillAFail is the INV-ADV-READBACK shape: the
// device answers the handshake COMPLETED and never moves its live curve. An
// oracle that read the handshake register and stopped there would certify a
// device that adopted nothing — and it is a real device behaviour, which is why
// the sims model it.
func TestOracleCurve_LyingAdoptIsStillAFail(t *testing.T) {
	f := newCurveFixture(t)
	if err := f.ss.ApplyFault([]byte(`{"kind":"curve_adopt_lies"}`)); err != nil {
		t.Fatalf("arm curve_adopt_lies: %v", err)
	}
	f.adoptBasic006Curve(t)
	got := oracleCurve(basic006Binding())(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("a device that only SAID it adopted = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
}

// TestOracleCurve_UnreachableDERIsUnavailableNotAPass: an oracle that cannot
// read the DER must decline to decide, so the caller's Unavailable→FAIL path
// (curveOutcome) takes it rather than a silent pass.
func TestOracleCurve_UnreachableDERIsUnavailableNotAPass(t *testing.T) {
	rc := &certify.RunCtx{Case: &certify.Case{UID: "test::curve"}, Sims: map[string]*certify.SimClient{}}
	got := oracleCurve(basic006Binding())(context.Background(), rc)
	if got.Unavailable == "" {
		t.Fatalf("an unreachable DER returned a verdict (%s: %s) instead of declining", got.Verdict, got.Observed)
	}
}

// TestOracleCurve_ModelAbsentIsAFail: the DER serves no 712 at all, so the
// watt-PF row's content has nowhere to be. "The device cannot carry this
// function" is a real answer to a conformance question and it is not a pass.
func TestOracleCurve_ModelAbsentIsAFail(t *testing.T) {
	f := newCurveFixture(t)
	b := &curveBinding{
		Mode: "volt_watt", Points: []CurvePoint{{X: 106, Y: 100}, {X: 110, Y: 20}},
		// 707 (DERTripLV) is not served by the default advanced sim — the trip
		// models are opt-in (NewSolarServerTrip) — and is not a model this
		// referee decodes either, so it stands in for "no register home found".
		Model: 707, YRefType: 3, Mapping: "a mapping onto a model this device does not serve",
	}
	got := oracleCurve(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("a curve mapped onto an absent model = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "models the DER does serve") {
		t.Errorf("the FAIL does not name the models that ARE served: %s", got.Observed)
	}
}

// TestOracleCurve_FreqWattHasNoRegisterHomeAndSaysSoAsAFail pins BASIC-012's
// shape. opModFreqWatt is a breakpoint curve and the 7xx set stores frequency
// response as the parametric 711 droop, so there is nothing southbound that can
// hold the row's content. That is a gap in the EVIDENCE, and a gap in the
// evidence is a row that was not tested — it must FAIL with the reason, not
// skip, and not pass by asserting something weaker against 711.
func TestOracleCurve_FreqWattHasNoRegisterHomeAndSaysSoAsAFail(t *testing.T) {
	f := newCurveFixture(t)
	m := curveModeNoRegisterHome("opModFreqWatt", "freq_watt",
		[]CurvePoint{{X: 6000, Y: 100}, {X: 6050, Y: 0}}, 3, sunspec.ModelDERFreqDroop, noFreqWattRegister)
	got := oracleCurve(m.Curve)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("a mode with no southbound register home = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "no breakpoint table") {
		t.Errorf("the FAIL does not describe what the DER's nearest model actually is: %s", got.Observed)
	}
	if !strings.Contains(got.Observed, "NO southbound register home") {
		t.Errorf("the FAIL does not name the gap as the reason: %s", got.Observed)
	}
}

// TestCurveBinding_MultipliersAreAppliedExactlyOnce: the wire carries raw
// breakpoints plus a power-of-ten multiplier per axis, and the value the oracle
// expects is the product of the two. Applying it twice (or not at all) would
// judge a device against a number nobody sent.
func TestCurveBinding_MultipliersAreAppliedExactlyOnce(t *testing.T) {
	b := &curveBinding{Points: []CurvePoint{{X: 92, Y: 60}}, XMult: 1, YMult: -1}
	got := b.wantPoints()
	if len(got) != 1 || got[0].X != 920 || got[0].Y != 6 {
		t.Fatalf("wantPoints with x10^1 / y10^-1 = %+v, want (920, 6)", got)
	}
	plain := (&curveBinding{Points: []CurvePoint{{X: 92, Y: 60}}}).wantPoints()
	if plain[0].X != 92 || plain[0].Y != 60 {
		t.Fatalf("wantPoints with no multipliers = %+v, want the published values unchanged", plain)
	}
}

// ── curveOutcome: the transition, not the snapshot ──────────────────────────

func curveObs(params map[string]string) *Observation { return &Observation{Params: params} }

// TestCurveOutcome_RequiresTheReadingToHaveMoved is the same discipline the
// scalar oracle carries: a DER that ALREADY held this row's curve before the
// row published anything proves nothing, because a rerun that never re-applied
// the control reads identically to one that did.
func TestCurveOutcome_RequiresTheReadingToHaveMoved(t *testing.T) {
	moved := curveOutcome(curveObs(map[string]string{
		oraclePreVerdictParam:  string(certify.Fail),
		oraclePreObservedParam: "the DER held its factory curve",
		oracleVerdictParam:     string(certify.Pass),
		oracleObservedParam:    "the DER holds the published curve",
		curvePublishedParam:    "4 breakpoints",
	}))
	if moved.Verdict != certify.Pass {
		t.Fatalf("a curve that moved from absent to present = %s (%s), want PASS", moved.Verdict, moved.Observed)
	}

	stale := curveOutcome(curveObs(map[string]string{
		oraclePreVerdictParam:  string(certify.Pass),
		oraclePreObservedParam: "the DER already held the published curve",
		oracleVerdictParam:     string(certify.Pass),
		oracleObservedParam:    "the DER holds the published curve",
	}))
	if stale.Verdict != certify.Fail {
		t.Fatalf("a curve that was ALREADY adopted before the row published = %s (%s), want FAIL",
			stale.Verdict, stale.Observed)
	}
}

// TestCurveOutcome_UnavailableIsAFailNotASkip: an oracle that could not read the
// DER must FAIL the row. A Skip is severity 0 in the roll-up and cannot hold a
// release, which is how a misconfigured bench used to certify a product.
func TestCurveOutcome_UnavailableIsAFailNotASkip(t *testing.T) {
	f := curveOutcome(curveObs(map[string]string{
		oracleUnavailableParam: "no simapi sidecar is configured for modsim",
	}))
	if f.Verdict != certify.Fail {
		t.Fatalf("an unreachable curve oracle = %s (%s), want FAIL", f.Verdict, f.Observed)
	}
}

// TestCurveOutcome_NoRecordAtAllIsAFail: a params map with neither a verdict nor
// a reason means the oracle never ran or its result was lost. An unrecorded
// criterion is not a satisfied one.
func TestCurveOutcome_NoRecordAtAllIsAFail(t *testing.T) {
	if f := curveOutcome(curveObs(map[string]string{})); f.Verdict != certify.Fail {
		t.Fatalf("an empty live-phase record = %s (%s), want FAIL", f.Verdict, f.Observed)
	}
}

// TestCritDEREffectViaCurveOracle_CarriesNoSkipPath: the criterion must always
// decide. A Skip here would be exactly the hole IW15-008 closes.
func TestCritDEREffectViaCurveOracle_CarriesNoSkipPath(t *testing.T) {
	c := critDEREffectViaCurveOracle("a Volt-VAr curve", basic006Binding(), curveObs(map[string]string{}))
	if c.Skip != "" {
		t.Fatalf("the curve criterion carries a Skip path (%q) — a criterion that can skip cannot hold a "+
			"release, which is the defect this change is about", c.Skip)
	}
	if c.Tier != tierOracle {
		t.Errorf("the curve criterion is stamped %q; it reads the DER's registers, not the capture", c.Tier)
	}
	if f := c.Wire(nil, nil); f.Verdict != certify.Fail {
		t.Fatalf("the criterion with no live record = %s, want FAIL", f.Verdict)
	}
}

// ── The refusal oracle ──────────────────────────────────────────────────────

func basic014Binding() *refusalBinding {
	return &refusalBinding{
		Axis:      "the 704 active-power SETPOINT axis (WSet / WSetPct)",
		Points:    []string{"WSet", "WSetPct"},
		Commanded: "opModTargetW = 3000 W",
		Why:       "opModTargetW is an axis this product does not execute end to end",
	}
}

func (f *curveFixture) fingerprint(t *testing.T) string {
	t.Helper()
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER's own registers: %v", err)
	}
	fp, ok := refusalFingerprint(uv, basic014Binding().Points)
	if !ok {
		t.Fatal("the DER's 704 image carries neither WSet nor WSetPct — the fixture is wrong")
	}
	return fp
}

// TestOracleRefusal_NothingMovedIsAPass: the honest refusal — the DUT wrote
// nothing to the axis it said it could not perform.
func TestOracleRefusal_NothingMovedIsAPass(t *testing.T) {
	f := newCurveFixture(t)
	baseline := f.fingerprint(t)
	got := oracleRefusal(basic014Binding(), baseline)(context.Background(), f.rc)
	if got.Verdict != certify.Pass {
		t.Fatalf("an untouched setpoint axis = %s (%s), want PASS", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "no southbound trace") {
		t.Errorf("the PASS does not say what it is a pass OF: %s", got.Observed)
	}
}

// TestOracleRefusal_ASouthboundWriteIsStillAFail is the refusal row's teeth: a
// gateway that answers the head end "cannot comply" and then writes the axis
// anyway has told the head end one thing and the device another. The write here
// goes through the sim's own register bank exactly as a landed Modbus write
// leaves it.
func TestOracleRefusal_ASouthboundWriteIsStillAFail(t *testing.T) {
	f := newCurveFixture(t)
	baseline := f.fingerprint(t)

	blk, err := sunspec.FindModel(f.base.Reader.Blocks(), sunspec.ModelDERCtlAC)
	if err != nil {
		t.Fatalf("find M704: %v", err)
	}
	f.ss.Regs.Set(blk.BaseAddr+uint16(sunspec.L704.Offset("WSet")), 3000)
	f.ss.Regs.Set(blk.BaseAddr+uint16(sunspec.L704.Offset("WSetEna")), 1)
	f.ss.Regs.Set(blk.BaseAddr+uint16(sunspec.L704.Offset("WSetMod")), sunspec.M704_WSetMod_Watts)

	got := oracleRefusal(basic014Binding(), baseline)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("a landed write on a REFUSED axis = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
	for _, want := range []string{"LANDED", "before this row published", "opModTargetW = 3000 W"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not say %q; it said: %s", want, got.Observed)
		}
	}
}

// TestOracleRefusal_NoBaselineIsAFail: an absence asserted without a starting
// state is not an observation. It must not read as a clean refusal.
func TestOracleRefusal_NoBaselineIsAFail(t *testing.T) {
	f := newCurveFixture(t)
	got := oracleRefusal(basic014Binding(), "")(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("a refusal judged with no baseline = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
}

// TestOracleRefusal_UnreachableDERIsUnavailableNotAPass: "we could not look"
// must never read as "nothing was there".
func TestOracleRefusal_UnreachableDERIsUnavailableNotAPass(t *testing.T) {
	rc := &certify.RunCtx{Case: &certify.Case{UID: "test::refusal"}, Sims: map[string]*certify.SimClient{}}
	got := oracleRefusal(basic014Binding(), "WSet=0 W disabled(WSetMod=0)")(context.Background(), rc)
	if got.Unavailable == "" {
		t.Fatalf("an unreachable DER returned a verdict (%s: %s) instead of declining", got.Verdict, got.Observed)
	}
}

// TestRefusalOutcome_UnavailableIsAFailNotASkip mirrors the curve/scalar rule.
func TestRefusalOutcome_UnavailableIsAFailNotASkip(t *testing.T) {
	f := refusalOutcome(basic014Binding(), curveObs(map[string]string{oracleUnavailableParam: "the sidecar is down"}))
	if f.Verdict != certify.Fail {
		t.Fatalf("an unreachable refusal oracle = %s (%s), want FAIL", f.Verdict, f.Observed)
	}
	if e := refusalOutcome(basic014Binding(), curveObs(map[string]string{})); e.Verdict != certify.Fail {
		t.Fatalf("an empty refusal record = %s (%s), want FAIL", e.Verdict, e.Observed)
	}
}

// TestSettleRefusal_DoesNotShortCircuitOnAnEarlyAbsence is why a refusal cannot
// reuse settleOracle. settleOracle returns the instant it sees a Pass, which for
// an ABSENCE would mean concluding "nothing landed" from the first read — before
// the reconciler tick on which a southbound write actually arrives. A landing
// that happens late in the window must still be caught.
func TestSettleRefusal_DoesNotShortCircuitOnAnEarlyAbsence(t *testing.T) {
	calls := 0
	f := settleRefusal(context.Background(), 2*time.Second, time.Millisecond, func() Finding {
		calls++
		if calls < 4 {
			return Finding{Verdict: certify.Pass, Observed: "nothing has landed yet"}
		}
		return Finding{Verdict: certify.Fail, Observed: "a write landed on the refused axis"}
	})
	if f.Verdict != certify.Fail {
		t.Fatalf("settleRefusal returned %s (%s) — a late landing must still be caught", f.Verdict, f.Observed)
	}
	if calls < 4 {
		t.Fatalf("settleRefusal read %d times and stopped; it must poll the whole window for an absence", calls)
	}
}

// TestSettleRefusal_ReturnsTheAbsenceAtTheDeadline: a window in which nothing
// ever lands ends in the Pass it observed, not in a hang or a false FAIL.
func TestSettleRefusal_ReturnsTheAbsenceAtTheDeadline(t *testing.T) {
	calls := 0
	f := settleRefusal(context.Background(), 30*time.Millisecond, time.Millisecond, func() Finding {
		calls++
		return Finding{Verdict: certify.Pass, Observed: "nothing landed"}
	})
	if f.Verdict != certify.Pass {
		t.Fatalf("a window with no landing = %s (%s), want PASS at the deadline", f.Verdict, f.Observed)
	}
	if calls < 2 {
		t.Fatalf("settleRefusal read %d time(s); it must keep watching until the deadline", calls)
	}
}

// ── The refusal's northbound half ───────────────────────────────────────────

func responseExchange(status int, subject string) Exchange {
	body := `<DERControlResponse xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1</createdDateTime>` +
		`<endDeviceLFDI>ab</endDeviceLFDI><status>` + itoa(int64(status)) + `</status>` +
		`<subject>` + subject + `</subject></DERControlResponse>`
	return Exchange{Req: msg(Request, "POST", "/rsps/0/r", 0, body), Resp: msg(Response, "", "", 201, "")}
}

// TestCritRefusalAnswered_HasTeeth walks every answer a DUT can give a control
// whose axis it cannot execute.
func TestCritRefusalAnswered_HasTeeth(t *testing.T) {
	const row = "CERT-BASIC-014"

	// The honest refusal: received, then the partial-opt-out code this product
	// posts at receipt for an unsupported axis.
	wantVerdict(t, "received + partial-opt-out", critRefusalAnswered(row),
		synthTranscript(responseExchange(1, row), responseExchange(8, row)), certify.Pass)

	// The LEXA legacy code means the same thing on the wire and must not be
	// graded as a missing refusal.
	wantVerdict(t, "received + LEXA 0xF0", critRefusalAnswered(row),
		synthTranscript(responseExchange(1, row), responseExchange(0xF0, row)), certify.Pass)

	// THE defect: an execution signal for an axis nothing executed. This is
	// LXR-002 verbatim, and it must fail even when the refusal was also sent —
	// a DUT that says both has still told the head end the control ran.
	f := wantVerdict(t, "started for a refused axis", critRefusalAnswered(row),
		synthTranscript(responseExchange(1, row), responseExchange(2, row)), certify.Fail)
	if !strings.Contains(f.Observed, "Event started") {
		t.Errorf("the FAIL does not name the forbidden status: %s", f.Observed)
	}
	wantVerdict(t, "started AND refused", critRefusalAnswered(row),
		synthTranscript(responseExchange(8, row), responseExchange(2, row)), certify.Fail)
	wantVerdict(t, "completed for a refused axis", critRefusalAnswered(row),
		synthTranscript(responseExchange(3, row)), certify.Fail)

	// An acknowledgement alone is not a refusal: the head end is left believing
	// the control was accepted.
	wantVerdict(t, "received only", critRefusalAnswered(row),
		synthTranscript(responseExchange(1, row)), certify.Fail)

	// Another control's refusal says nothing about this row.
	wantUnavailable(t, "another control's refusal", critRefusalAnswered(row),
		synthTranscript(responseExchange(8, "SOMEBODY-ELSE")))
}

// TestCritRefusalAnswered_ServerTierAgrees: the tier-3 fallback must reach the
// same decisions, or a run whose capture could not be decrypted would grade the
// same DUT differently.
func TestCritRefusalAnswered_ServerTierAgrees(t *testing.T) {
	const row = "CERT-BASIC-014"
	c := critRefusalAnswered(row)
	ok := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: row, Status: 1}, {Subject: row, Status: 8}}}
	if f := c.Server(ok); f.Verdict != certify.Pass {
		t.Errorf("server-side honest refusal = %s: %s", f.Verdict, f.Observed)
	}
	started := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: row, Status: 1}, {Subject: row, Status: 2}}}
	if f := c.Server(started); f.Verdict != certify.Fail {
		t.Errorf("server-side Started for a refused axis = %s: %s", f.Verdict, f.Observed)
	}
	ackOnly := &ServerView{Available: true, Responses: []AdminResponse{{Subject: row, Status: 1}}}
	if f := c.Server(ackOnly); f.Verdict != certify.Fail {
		t.Errorf("server-side acknowledgement-only = %s: %s", f.Verdict, f.Observed)
	}
	none := &ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}
	if f := c.Server(none); f.Verdict != certify.Fail {
		t.Errorf("server-side no Response at all = %s: %s", f.Verdict, f.Observed)
	}
}

// ── The authoring gaps ──────────────────────────────────────────────────────

// TestUnauthorableRow_IsAFailNotASkip pins BASIC-004/005/007's new shape. The
// bench cannot put these modes on the wire, so the rows were never tested — and
// an untested row must not roll up as a passing one.
func TestUnauthorableRow_IsAFailNotASkip(t *testing.T) {
	m := unreachableMode("opModLVRTMustTrip", "gridsim has no ride-through curve mode")
	s := inverterControlSpec(m, "the low/high voltage ride-through settings", "CERT-BASIC-004")

	if s.Verdict == nil {
		t.Fatal("an unauthorable row declares no live verdict, so a run with no capture would report it as " +
			"a pass on an untested row")
	}
	if got := s.Verdict(&Observation{Params: map[string]string{}}); got != certify.Fail {
		t.Fatalf("an unauthorable row's declared verdict = %q, want FAIL", got)
	}
	for _, c := range s.Criteria(&Observation{Params: map[string]string{}}) {
		if c.Skip == "" {
			continue
		}
		if strings.Contains(c.Claim, "ride-through") {
			t.Fatalf("the unauthorable row still carries a Skip on its own claim (%q): %s", c.Claim, c.Skip)
		}
	}
	crit := critModeUnauthorable("the ride-through settings", "opModLVRTMustTrip", "no lever exists")
	f := crit.Wire(nil, nil)
	if f.Verdict != certify.Fail {
		t.Fatalf("critModeUnauthorable = %s, want FAIL", f.Verdict)
	}
	// It must be unmistakably a BENCH gap, or somebody files it against the
	// product and the real gap goes unfixed.
	if !strings.Contains(f.Observed, "BENCH capability gap") || !strings.Contains(f.Observed, "NOT tested") {
		t.Errorf("the FAIL does not identify itself as an untested row / bench gap: %s", f.Observed)
	}
}

// ── The whole row, end to end ───────────────────────────────────────────────

// rowByID returns the SHIPPING definition of one BASIC row, so the end-to-end
// tests below drive what a campaign drives.
func rowByID(t *testing.T, id string) inverterControlRow {
	t.Helper()
	for _, r := range inverterControlRows() {
		if r.id == id {
			return r
		}
	}
	t.Fatalf("no inverter-control row is registered for %s", id)
	return inverterControlRow{}
}

// withGridSim gives the fixture a real gridsim admin API on the same RunCtx, so
// a row's Setup can actually publish and its PostWait can actually read — the
// pattern inverterControlLifecycleRunCtx established for the scalar rows.
func (f *curveFixture) withGridSim(t *testing.T) *Driver {
	t.Helper()
	gs := gridsim.NewServer(benchLFDI)
	gsSrv := httptest.NewServer(gs.AdminHandler())
	t.Cleanup(gsSrv.Close)
	f.rc.GridSim = certify.NewAdminClient(gsSrv.URL, http.DefaultClient)
	f.rc.Targets = certify.Targets{GridSimAdmin: gsSrv.URL}
	return NewDriver(f.rc)
}

// TestBasic006Row_IsRedAgainstAProductThatRefusesTheCurveAxis is the finding
// closed, at the level a campaign runs it.
//
// It drives the SHIPPING BASIC-006 row — its real controlMode, its real
// published breakpoints, its real oracle — through the same live-phase sequence
// check.go's run() uses (Setup, then the DUT's poll cycle, then PostWait), with
// the DER left in exactly the state the current product leaves it in for this
// row: nothing adopted, because the gateway refuses the volt-var axis at
// receipt with the advanced overlay dark. The row must come out RED, and its
// declared verdict must be RED independently of the capture, because the
// capture would have shown a perfectly good <opModVoltVar> element and that is
// what used to carry the row to PASS.
func TestBasic006Row_IsRedAgainstAProductThatRefusesTheCurveAxis(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-006")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-006")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-006 Setup: %v", err)
	}
	// The DUT's poll cycle happens here. This product's does nothing southbound
	// for a refused axis, which is the whole point.
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-006 PostWait: %v", err)
	}

	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != certify.Fail {
		t.Fatalf("BASIC-006's declared live verdict against a product that never adopted the curve = %q, "+
			"want FAIL — this is the row that used to report applicable-PASS on element presence alone",
			got)
	}
	notes := s.Notes(obs)
	if !strings.Contains(notes, "independent southbound oracle: FAIL") {
		t.Errorf("the row's own notes do not carry the oracle's reason, so a run with no recovered session "+
			"would report an unexplained FAIL: %s", notes)
	}
	t.Logf("BASIC-006 verdict: FAIL\nnotes: %s", notes)

	// The row must have bound the mRID the SERVER minted, not its own synthetic
	// one: gridsim ignores any mRID a POST /admin/curve carries.
	if params["mrid"] == "CERT-BASIC-006" || !strings.HasPrefix(params["mrid"], "DERC-") {
		t.Errorf("the curve row's wire criteria are bound to %q, which is not the mRID gridsim minted",
			params["mrid"])
	}
	if params[curveHrefParam] == "" {
		t.Error("the row did not record the DERCurve href its control links, so the 404 case cannot be told " +
			"apart from a DUT that refused the axis")
	}
}

// TestBasic006Row_GoesGreenWhenTheDERActuallyAdoptsTheCurve is the other half of
// the proof: the same shipping row, the same sequence, with the southbound write
// a gateway that EXECUTED the control would have made — through the real derbase
// adopt handshake. If this did not pass, the RED above would be a constant
// rather than a measurement.
func TestBasic006Row_GoesGreenWhenTheDERActuallyAdoptsTheCurve(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-006")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-006")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-006 Setup: %v", err)
	}
	// Stand in for the DUT's poll cycle: fetch the control, resolve the curve,
	// adopt it southbound. Exactly the breakpoints the row published.
	f.adoptBasic006Curve(t)
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-006 PostWait: %v", err)
	}

	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != "" {
		t.Fatalf("BASIC-006's declared verdict on a DER that adopted the row's own curve = %q, want \"\" "+
			"(a satisfied oracle declares nothing and leaves the row to its wire criteria): %s",
			got, s.Notes(obs))
	}
	if f := curveOutcome(obs); f.Verdict != certify.Pass {
		t.Fatalf("the curve outcome on an adopting DER = %s: %s", f.Verdict, f.Observed)
	}
}

// TestBasic014Row_RefusalIsMeasuredEndToEnd drives the shipping BASIC-014 row.
// The product refuses opModTargetW, so the row's southbound half must come out
// PASS on an untouched axis — and it must be a MEASURED pass, recorded by the
// live phase, not the unmeasured SKIP the row used to carry.
func TestBasic014Row_RefusalIsMeasuredEndToEnd(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-014")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-014")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-014 Setup: %v", err)
	}
	if params[refusalBaselineParam] == "" {
		t.Fatal("BASIC-014's Setup recorded no pre-publication baseline of the refused axis, so its PostWait " +
			"cannot assert an absence against anything")
	}
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-014 PostWait: %v", err)
	}
	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != "" {
		t.Fatalf("BASIC-014's declared verdict on a DUT that wrote nothing = %q, want \"\": %s",
			got, s.Notes(obs))
	}
	if f := refusalOutcome(row.mode.Refusal, obs); f.Verdict != certify.Pass {
		t.Fatalf("the refusal outcome on an untouched axis = %s: %s", f.Verdict, f.Observed)
	}
	t.Logf("BASIC-014 notes: %s", s.Notes(obs))
}

// TestBasic014Row_IsRedWhenTheRefusedAxisIsWritten is the same row against a
// gateway that answered cannot-comply and wrote the setpoint anyway.
func TestBasic014Row_IsRedWhenTheRefusedAxisIsWritten(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-014")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-014")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-014 Setup: %v", err)
	}
	blk, err := sunspec.FindModel(f.base.Reader.Blocks(), sunspec.ModelDERCtlAC)
	if err != nil {
		t.Fatalf("find M704: %v", err)
	}
	f.ss.Regs.Set(blk.BaseAddr+uint16(sunspec.L704.Offset("WSet")), 3000)
	f.ss.Regs.Set(blk.BaseAddr+uint16(sunspec.L704.Offset("WSetEna")), 1)

	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-014 PostWait: %v", err)
	}
	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != certify.Fail {
		t.Fatalf("BASIC-014's declared verdict on a landed write to the REFUSED axis = %q, want FAIL: %s",
			got, s.Notes(obs))
	}
}

// TestBasic015Row_IsARefusalRowAndItsCurveBankStaysUntouched drives the
// shipping BASIC-015 row after its 2026-08-14 flip from an execution row to a
// refusal one.
//
// The row used to publish an opModWattPF curve and grade it against model 712,
// on a mapping that said "there being no Watt-PF model in the 7xx set" — which
// is exactly why the row was wrong: 712 is DER Watt-VAr, a different function.
// It passed because the product performed the same substitution. The product
// ended it (lexa-gw curve P1: watt_var is its own axis and is the only thing
// written to 712; opModWattPF is refused at receipt on a 7xx DER), so the row's
// evidence is now that the refusal was honest — nothing of 712 moved.
func TestBasic015Row_IsARefusalRowAndItsCurveBankStaysUntouched(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-015")
	if row.mode.Refusal == nil {
		t.Fatal("BASIC-015 is not a refusal row. It publishes opModWattPF, whose only exact register " +
			"home is legacy model 131; grading it against model 712 (DER Watt-Var) certifies the very " +
			"substitution the product stopped performing")
	}
	if row.mode.Refusal.Curve == nil || row.mode.Refusal.Curve.Model != sunspec.ModelDERWattVar {
		t.Fatalf("BASIC-015's refusal must be measured over model 712 — the bank the product used to "+
			"write opModWattPF into, and therefore the one a regression would land in: %+v",
			row.mode.Refusal.Curve)
	}
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-015")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 Setup: %v", err)
	}
	if params[refusalBaselineParam] == "" {
		t.Fatal("BASIC-015's Setup recorded no pre-publication baseline of the 712 curve bank, so its " +
			"PostWait cannot assert an absence against anything")
	}
	// The curve really was published — a refusal row whose control never
	// reached the wire would assert an absence nobody was offered a chance to
	// violate. gridsim mints the control's mRID, so Setup must have adopted it.
	if params[curveHrefParam] == "" {
		t.Error("BASIC-015 published no curve href: the row must put a REAL, resolvable curve on the " +
			"wire, or its refusal is not attributable to the axis")
	}
	if params["mrid"] == "CERT-BASIC-015" {
		t.Error("BASIC-015 kept its synthetic mRID: gridsim mints one for POST /admin/curve, and every " +
			"wire criterion on this row binds the minted one")
	}

	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 PostWait: %v", err)
	}
	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != "" {
		t.Fatalf("BASIC-015's declared verdict on a DUT that adopted nothing into 712 = %q, want \"\": %s",
			got, s.Notes(obs))
	}
	if f := refusalOutcome(row.mode.Refusal, obs); f.Verdict != certify.Pass {
		t.Fatalf("the refusal outcome on an untouched 712 = %s: %s", f.Verdict, f.Observed)
	}
	t.Logf("BASIC-015 notes: %s", s.Notes(obs))
}

// TestBasic015Row_IsRedWhenTheWattPFCurveLandsIn712 is the same row against the
// gateway this product USED to be: it answers the head end and writes the
// power-factor curve into the Watt-VAr bank anyway.
//
// This is the discrimination that makes the PASS above worth anything. It is
// also the exact historical regression — the substitution was live in shipped
// code until curve P1 — so the row must be able to catch its return.
func TestBasic015Row_IsRedWhenTheWattPFCurveLandsIn712(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-015")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-015")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 Setup: %v", err)
	}
	// The substitution, performed through the REAL derbase writer: the row's
	// own published breakpoints adopted into model 712.
	if err := f.base.WriteWattVar(sunspec.WattVarCurve{
		DeptRef: 2, Pri: 1,
		Points:  []sunspec.WVPoint{{W: 0, Var: 100}, {W: 50, Var: 98}, {W: 100, Var: 95}},
	}, "basic015-regression-test"); err != nil {
		t.Fatalf("derbase WriteWattVar (the substitution this row must catch): %v", err)
	}

	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 PostWait: %v", err)
	}
	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != certify.Fail {
		t.Fatalf("BASIC-015's declared verdict on a DUT that adopted the refused watt-PF curve into "+
			"model 712 = %q, want FAIL: %s", got, s.Notes(obs))
	}
}

// TestBasic015Row_IsRedWhenTheBaselineAlreadyHeldTheRefusedCurve is the
// CONTAMINATED-BASELINE shape, and it is the one a refusal row fails at
// silently rather than loudly.
//
// The DER is already holding the row's own watt-PF content in model 712 when
// the row starts — the state a regression from a PREVIOUS run leaves behind, or
// a leak from a preceding row. Nothing then moves during the window, because
// there is nothing left to move, and a refusal row that only compares
// fingerprints reads that as the cleanest possible refusal. The worse the
// contamination, the more reliably the row passed.
//
// That is exactly backwards, and it is what makes this different from
// TestBasic015Row_IsRedWhenTheWattPFCurveLandsIn712: there the write lands
// DURING the window and the fingerprint moves, so the row already caught it.
// Here the fingerprint is stable and correct, and the window is simply
// uninformative — which is not the same thing as an observed absence.
func TestBasic015Row_IsRedWhenTheBaselineAlreadyHeldTheRefusedCurve(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-015")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-015")

	// The contamination, landed BEFORE the row runs, through the real derbase
	// writer — the same call TestBasic015Row_IsRedWhenTheWattPFCurveLandsIn712
	// makes, only earlier, which is the whole distinction being drawn.
	if err := f.base.WriteWattVar(sunspec.WattVarCurve{
		DeptRef: 2, Pri: 1,
		Points:  []sunspec.WVPoint{{W: 0, Var: 100}, {W: 50, Var: 98}, {W: 100, Var: 95}},
	}, "basic015-contaminated-baseline-test"); err != nil {
		t.Fatalf("derbase WriteWattVar (seeding the contaminated baseline): %v", err)
	}

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 Setup: %v", err)
	}
	if got := certify.Verdict(params[oraclePreVerdictParam]); got != certify.Pass {
		t.Fatalf("Setup recorded pre-verdict %q for a DER that ALREADY holds the row's curve, want PASS "+
			"(oracleCurve's own answer to \"does it hold this content?\") — without it refusalOutcome has "+
			"nothing to detect the contamination with", got)
	}
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 PostWait: %v", err)
	}
	obs := &Observation{Params: params}

	// The fingerprint really is unchanged: this is NOT the landed-write case
	// wearing a different hat, and the row must fail for the other reason.
	if params[oracleVerdictParam] != string(certify.Pass) {
		t.Fatalf("the fingerprint MOVED during the window (%s: %s) — this test is about a window in which "+
			"nothing moves because the refused content was already there",
			params[oracleVerdictParam], params[oracleObservedParam])
	}
	if got := s.Verdict(obs); got != certify.Fail {
		t.Fatalf("BASIC-015's declared verdict against a CONTAMINATED baseline = %q, want FAIL. Nothing "+
			"moved, and nothing could have: the DER was already executing the control this row is "+
			"supposed to prove it refused. Notes: %s", got, s.Notes(obs))
	}
	got := refusalOutcome(row.mode.Refusal, obs)
	for _, want := range []string{"CONTAMINATED", "ALREADY held", "REMEDY"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not say %q — a contaminated bench must be told how to clean itself, "+
				"or the next run reproduces it: %s", want, got.Observed)
		}
	}
}

// TestBasic015Row_IsRedWhenTheRefusedCurveOnlyReachesStaging is the
// STAGE-AND-STOP shape: the gateway writes the refused watt-PF breakpoints into
// the bank's writable staging slot and never triggers the adopt handshake.
//
// Nothing about the LIVE curve changes, and the handshake registers do not move
// either — they move when the gateway ASKS the device to adopt, so they catch
// stage-then-adopt and are blind to this. A fingerprint over index 0 alone
// reports an untouched device.
//
// It is still a write that landed on an axis the DUT told the head end it could
// not perform, which is precisely what this row claims did not happen. Note the
// deliberate asymmetry with the EXECUTION curve oracle, which reads index 0 and
// only index 0: content in staging is a curve the device was offered, not one
// it adopted, so it must never count as execution — and must always count as a
// write.
func TestBasic015Row_IsRedWhenTheRefusedCurveOnlyReachesStaging(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-015")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-015")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 Setup: %v", err)
	}
	baseline := params[refusalBaselineParam]
	if baseline == "" {
		t.Fatal("no baseline recorded")
	}

	// Stage the refused curve at index 1 WITHOUT touching the handshake. Note
	// this happens AFTER Setup: the same write BEFORE Setup is a contaminated
	// baseline, which is a different finding —
	// TestBasic015Row_IsRedWhenTheBaselineIsContaminatedInAStagingSlot.
	f.stageRefusedWattPFCurve(t, 1)

	// The handshake really did not move — otherwise this test is just the
	// landed-write case again and proves nothing about staging.
	after := f.rcCurveView(t, sunspec.ModelDERWattVar)
	if after.AdoptReq != 0 || after.Adopted {
		t.Fatalf("the staging write moved the adopt handshake (req=%d rslt=%d) — this test is about a "+
			"write the handshake registers cannot see", after.AdoptReq, after.AdoptResult)
	}

	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 PostWait: %v", err)
	}
	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != certify.Fail {
		t.Fatalf("BASIC-015's declared verdict on a refused curve written into the STAGING slot = %q, "+
			"want FAIL: a staged write is still a write to an axis the DUT said it could not perform. "+
			"Notes: %s", got, s.Notes(obs))
	}
}

// stageRefusedWattPFCurve writes BASIC-015's own published breakpoints into one
// slot of the DER's model-712 bank through the real sunspec encoder, WITHOUT
// touching the adopt handshake — the raw register write a gateway's curve
// writer makes before it would ask the device to adopt.
func (f *curveFixture) stageRefusedWattPFCurve(t *testing.T, idx int) {
	t.Helper()
	blk, err := sunspec.FindModel(f.base.Reader.Blocks(), sunspec.ModelDERWattVar)
	if err != nil {
		t.Fatalf("find M712: %v", err)
	}
	regs, err := f.base.Reader.ReadModel(sunspec.ModelDERWattVar)
	if err != nil {
		t.Fatalf("read M712: %v", err)
	}
	staged := append([]uint16(nil), regs...)
	if _, _, err := sunspec.Encode712Curve(staged, idx, sunspec.WattVarCurve{
		DeptRef: 2, Pri: 1,
		Points:  []sunspec.WVPoint{{W: 0, Var: 100}, {W: 50, Var: 98}, {W: 100, Var: 95}},
	}); err != nil {
		t.Fatalf("encode the staged watt-PF curve at index %d: %v", idx, err)
	}
	for i, v := range staged {
		if v != regs[i] {
			f.ss.Regs.Set(blk.BaseAddr+uint16(i), v)
		}
	}
}

// TestBasic015Row_IsRedWhenTheBaselineIsContaminatedInAStagingSlot is the
// reviewer's N1 probe, and it is the previous fix's own hole.
//
// The contamination guard asked oracleCurve, which decodes index 0 and only
// index 0, while the fingerprint had just been widened to span the staging
// slots. So a baseline contaminated in STAGING read as clean: the pre-verdict
// said the bank was fine, nothing moved during the window because the content
// was already there, and the row certified. Worse, it is self-perpetuating —
// the first run against a stage-and-stop regression fails on MOVEMENT, but the
// contamination branch never fires, so nobody is ever told to reset the sim and
// every rerun from then on passes.
//
// The distinction from TestBasic015Row_IsRedWhenTheRefusedCurveOnlyReachesStaging
// is WHEN the write happens: there it lands inside the window and the
// fingerprint moves; here it is already there when the row starts, and the
// fingerprint cannot move at all.
func TestBasic015Row_IsRedWhenTheBaselineIsContaminatedInAStagingSlot(t *testing.T) {
	f := newCurveFixture(t)
	d := f.withGridSim(t)
	row := rowByID(t, "BASIC-015")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-015")

	// Contaminate STAGING before Setup — the live curve is left untouched, so
	// an index-0-only baseline check sees a pristine bank.
	f.stageRefusedWattPFCurve(t, 1)

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 Setup: %v", err)
	}
	if got := certify.Verdict(params[oraclePreVerdictParam]); got != certify.Pass {
		t.Fatalf("Setup recorded pre-verdict %q for a bank whose STAGING slot already holds the row's "+
			"content, want PASS (contaminated). The contamination read must span the same slots the "+
			"fingerprint does — an index-0-only read is what let this through", got)
	}
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-015 PostWait: %v", err)
	}

	// The fingerprint is unchanged, which is exactly why this is dangerous: the
	// row has nothing to fail on except the contamination.
	if params[oracleVerdictParam] != string(certify.Pass) {
		t.Fatalf("the fingerprint MOVED (%s: %s) — this test is about a window in which it cannot",
			params[oracleVerdictParam], params[oracleObservedParam])
	}
	obs := &Observation{Params: params}
	if got := s.Verdict(obs); got != certify.Fail {
		t.Fatalf("BASIC-015's declared verdict against a STAGING-contaminated baseline = %q, want FAIL. "+
			"Notes: %s", got, s.Notes(obs))
	}
	got := refusalOutcome(row.mode.Refusal, obs)
	for _, want := range []string{"CONTAMINATED", "STAGING curve 1", "REMEDY"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not say %q — a contaminated bench must be told WHICH slot and how to "+
				"clean it: %s", want, got.Observed)
		}
	}
}

// TestCoveredCurveSlots_FingerprintAndContaminationSpanTheSameSlots is the
// structural half of N1: the defect was two functions independently deciding
// which curves of a bank to look at, so the property that they cannot is what
// gets pinned, not just the one instance that went wrong.
func TestCoveredCurveSlots_FingerprintAndContaminationSpanTheSameSlots(t *testing.T) {
	f := newCurveFixture(t)
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER through the referee: %v", err)
	}
	b := rowByID(t, "BASIC-015").mode.Refusal
	views, _, ok := coveredCurveSlots(uv, b.Curve.Model)
	if !ok || len(views) < 2 {
		t.Fatalf("the fixture's M712 bank covers %d slot(s); this test needs a live curve AND at least "+
			"one staging slot to be able to tell the two reads apart", len(views))
	}

	// Every covered slot must be detectable by the contamination read. Written
	// as a loop over the SLOTS rather than as "index 1 works" so a future bank
	// with more staging curves is covered by the same assertion.
	for i := range views {
		f2 := newCurveFixture(t)
		f2.stageRefusedWattPFCurve(t, i)
		uv2, err := oracleUnitView(context.Background(), f2.rc, oracleSimName)
		if err != nil {
			t.Fatalf("slot %d: read the DER: %v", i, err)
		}
		where, ok := curveBaselineContamination(uv2, b.Curve)
		if !ok {
			t.Fatalf("slot %d: the contamination read could not read the bank", i)
		}
		if len(where) == 0 {
			t.Errorf("slot %d holds this row's content and the contamination read did not see it — the "+
				"fingerprint covers this slot, so a baseline contaminated here produces an "+
				"uninformative window that nothing would report", i)
		}
	}
}

// TestCoveredCurveSlots_BoundIsRealAndIsFour pins N7: the bound existed and its
// VALUE did not, so a refactor could widen it to 1000000 and leave the size of
// this row's bundle entry in the hands of whatever NCrv a device declares.
func TestCoveredCurveSlots_BoundIsRealAndIsFour(t *testing.T) {
	if maxStagingCurvesFingerprinted != 4 {
		t.Fatalf("maxStagingCurvesFingerprinted = %d, want 4. The fingerprint is a string that lands in "+
			"a conformance bundle and the loop bound comes from the DEVICE's own NCrv, so this number is "+
			"the only thing standing between a broken or hostile NCrv and an unbounded bundle entry. "+
			"Changing it is a decision, not a refactor.", maxStagingCurvesFingerprinted)
	}
	// And the bound is REACHED rather than merely declared: a bank claiming more
	// curves than the bound yields exactly bound+1 views and says how many it
	// left out.
	f := newCurveFixture(t)
	f.setHeaderReg(t, sunspec.ModelDERWattVar, "NCrv", 12)
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER: %v", err)
	}
	views, truncated, ok := coveredCurveSlots(uv, sunspec.ModelDERWattVar)
	if !ok {
		t.Fatal("the bank could not be read")
	}
	if len(views) != maxStagingCurvesFingerprinted+1 {
		t.Errorf("a device declaring NCrv=12 yielded %d views, want %d (live + the bound)",
			len(views), maxStagingCurvesFingerprinted+1)
	}
	if truncated != 12-maxStagingCurvesFingerprinted-1 {
		t.Errorf("truncated = %d, want %d — a bundle must say what it left out rather than silently "+
			"rendering a prefix", truncated, 12-maxStagingCurvesFingerprinted-1)
	}
	b := rowByID(t, "BASIC-015").mode.Refusal
	fp, ok := b.fingerprint(uv)
	if !ok {
		t.Fatal("no fingerprint")
	}
	if !strings.Contains(fp, "further staging curve(s) not fingerprinted") {
		t.Errorf("the truncated fingerprint does not say it is truncated: %s", fp)
	}
}

// TestRefusalOutcome_ScalarShapeHasNoContaminationGuardAndSaysSo pins the
// BOUND of the guard above, so the gap is a recorded decision rather than a
// second silent hole.
//
// A scalar refusal row cannot compute "the baseline already held the commanded
// value": refusalBinding.Commanded is prose, not a value. The obvious proxy —
// "the axis is already ENABLED" — is wrong here specifically, and provably so:
// BASIC-013 runs immediately before BASIC-014, commands opModFixedW, and
// legitimately leaves WSet/WSetPct enabled on the very points BASIC-014
// fingerprints (oracleFixedW reads the same two). A guard built on that proxy
// would fail BASIC-014 in every campaign that runs the rows in order.
func TestRefusalOutcome_ScalarShapeHasNoContaminationGuardAndSaysSo(t *testing.T) {
	b := basic014Binding()
	if b.Curve != nil {
		t.Fatal("BASIC-014 is a scalar refusal; this test is about the shape that cannot compute contamination")
	}
	// A satisfied scalar refusal passes even with a pre-verdict recorded — the
	// guard must not fire on a row whose binding cannot support it.
	obs := curveObs(map[string]string{
		oracleVerdictParam:    string(certify.Pass),
		oracleObservedParam:   "nothing of the setpoint axis moved",
		oraclePreVerdictParam: string(certify.Pass), // would trip the curve guard
	})
	if f := refusalOutcome(b, obs); f.Verdict != certify.Pass {
		t.Fatalf("a scalar refusal = %s (%s), want PASS: the curve guard must key on the BINDING, not on "+
			"whether a param happens to be present", f.Verdict, f.Observed)
	}
	// And the curve shape with the identical params does trip it, so the
	// difference above is the binding and nothing else.
	cb := &refusalBinding{Axis: "M712", Curve: &curveBinding{Mode: "watt_pf", Model: sunspec.ModelDERWattVar}}
	if f := refusalOutcome(cb, obs); f.Verdict != certify.Fail {
		t.Fatalf("a curve refusal with a PASSing pre-verdict = %s (%s), want FAIL", f.Verdict, f.Observed)
	}
}

// TestCritDERCurveResolvable_HasTeeth: a curve href the server answers 404 is a
// BENCH gap that makes any southbound silence unattributable, and the row has to
// be able to say which of the two it is looking at.
func TestCritDERCurveResolvable_HasTeeth(t *testing.T) {
	const href = "/derp/0/dc/0"
	wantVerdict(t, "curve resolves", critDERCurveResolvable(href),
		synthTranscript(get(href, 200, `<DERCurve xmlns="urn:ieee:std:2030.5:ns"/>`)), certify.Pass)
	f := wantVerdict(t, "curve 404s", critDERCurveResolvable(href),
		synthTranscript(get(href, 404, "")), certify.Fail)
	if !strings.Contains(f.Observed, "BENCH authoring gap") {
		t.Errorf("the 404 FAIL does not name it as a bench gap: %s", f.Observed)
	}
	wantUnavailable(t, "curve never fetched", critDERCurveResolvable(href),
		synthTranscript(get("/dcap", 200, dcapXML())))
}
