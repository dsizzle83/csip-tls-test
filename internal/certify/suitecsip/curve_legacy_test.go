package suitecsip

// curve_legacy_test.go — Stage 7's whole point, stated as tests.
//
// THE DISCIPLINE THIS FILE ENFORCES (IW15-004 / IW15-008, and the reason the
// design stages the harness BEFORE the product): a row that turns green at the
// same commit as the product it grades proves nothing. So every legacy curve
// row below is first shown RED against the SHIPPING product — a legacy DER
// whose curve models nobody has written, which is exactly the southbound state
// the current gateway leaves behind because it refuses every curve axis at
// receipt (lexa-gw internal/northbound/scheduler/supported.go's
// AdvancedSupportedAxes carries no curve mode, and the advanced set is gated
// behind advanced_axes_enabled) — and only then shown GREEN when the real
// machinery the product will gain is driven directly against the same device.
//
// The green half is driven through lexa-proto's OWN derbase.WriteLegacyCurve,
// the writer the gateway's legacy shell will call. Nothing here hand-writes a
// register: a hand-built image can be made to agree with a hand-built oracle
// while both disagree with what a device actually holds, and that is precisely
// the class of error these rows exist to catch. The two halves together are the
// discrimination proof — the rows are not merely "always red" (which a broken
// oracle also is) and not merely "always green" (which a fixture-shaped one is).
//
// The rows under test are the SHIPPING ones, fetched from the registry by
// catalog id. What this file proves is therefore a property of the rows a
// campaign runs, not of bindings invented for a test.

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

// legacyFixture is a live LEGACY-curve DER sim, a real derbase writer onto it,
// and a RunCtx whose oracle sim slot serves that same device's register image
// through a simapi-shaped /registers — the shape internal/invariant.SimAPIDER
// reads in production. It is newCurveFixture's sibling, one generation over.
type legacyFixture struct {
	ss   *sim.SolarServer
	base *derbase.Base
	rc   *certify.RunCtx
}

func newLegacyFixture(t *testing.T, opt sim.LegacyCurveOptions) *legacyFixture {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	url := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	ss, err := sim.NewSolarServerLegacyCurves(url, 5000, "SN-LEGACY-CURVE", opt)
	if err != nil {
		t.Fatalf("start the legacy-curve DER sim: %v", err)
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
	b, err := derbase.Init(reader, "legacy-curve-test")
	if err != nil {
		t.Fatalf("derbase init: %v", err)
	}

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

	return &legacyFixture{ss: ss, base: &b, rc: &certify.RunCtx{
		Case: &certify.Case{UID: "csip-conf-v1.3::BASIC-006", ID: "BASIC-006"},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, srv.URL, http.DefaultClient),
		},
	}}
}

// unitView reads the DER through the same referee path the oracle uses.
func (f *legacyFixture) unitView(t *testing.T) invariant.UnitView {
	t.Helper()
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER through the referee: %v", err)
	}
	return uv
}

// curveOf returns the row's own execution binding for a legacy bench.
//
// It reaches through the per-generation split the same way the runner does
// (forGeneration with the generation the DER actually reports), so a row that
// only executes on legacy — BASIC-015 — is exercised through the code path a
// campaign would take, not by reading its LegacyCurve field directly.
func legacyBindingOf(t *testing.T, id string) *curveBinding {
	t.Helper()
	m := rowByID(t, id).mode.forGeneration(map[string]string{
		curveGenParam: string(invariant.FamilyLegacy),
	})
	if m.Curve == nil {
		t.Fatalf("%s carries no curve execution binding on a legacy bench", id)
	}
	return m.Curve
}

// ── RED: the shipping product ────────────────────────────────────────────────

// TestLegacyCurveRowsAreRedAgainstTheShippingProduct is the mandatory red
// proof. The DER is a real legacy-curve device whose curve banks nobody has
// written — the state the shipping gateway leaves, because it refuses these
// axes at receipt — and every row that claims a legacy register home must say
// so in a decided FAIL, naming the model it looked at and what it found there.
//
// A row that passed here would be certifying an axis the product does not
// execute, which is the IW15-008 defect verbatim.
func TestLegacyCurveRowsAreRedAgainstTheShippingProduct(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})

	for _, tc := range []struct {
		id        string
		wantModel string
	}{
		{"BASIC-006", "M126 Static Volt-VAR"},
		{"BASIC-011", "M132 Volt-Watt"},
		{"BASIC-012", "M134 Freq-Watt Curve"},
		{"BASIC-015", "M131 Watt-PF"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			b := legacyBindingOf(t, tc.id)
			got := oracleCurve(b)(context.Background(), f.rc)
			if got.Verdict != certify.Fail {
				t.Fatalf("%s on a legacy bench = %s against the SHIPPING product, want FAIL.\n%s",
					tc.id, got.Verdict, got.Observed)
			}
			if !strings.Contains(got.Observed, tc.wantModel) {
				t.Errorf("%s's FAIL does not name the legacy model it measured (%s):\n%s",
					tc.id, tc.wantModel, got.Observed)
			}
			// The verbatim reason is the deliverable, not a debugging aid: a
			// red row whose reason nobody recorded is indistinguishable from a
			// red row nobody understood.
			t.Logf("%s RED against the shipping product:\n  %s", tc.id, got.Observed)
		})
	}
}

// TestBASIC012ResolvesTo134OnLegacyAndStaysADecidedFailOn7xx is D2's acceptance
// criterion as a test, and it is a statement about BOTH benches.
//
// On 7xx the row must go on refusing to measure: the set has no model that
// stores frequency-watt breakpoints, 711 is a parametric droop, and asserting
// something weaker against it is the substitution this suite exists to refuse.
// On legacy the same catalog row must become a real measurement against 134.
// One row, two benches, and it says which one it was on.
func TestBASIC012ResolvesTo134OnLegacyAndStaysADecidedFailOn7xx(t *testing.T) {
	b := rowByID(t, "BASIC-012").mode.Curve
	if b == nil {
		t.Fatal("BASIC-012 carries no curve binding")
	}

	legacy := newLegacyFixture(t, sim.LegacyCurveOptions{})
	target, ok := b.resolveTarget(legacy.unitView(t))
	if !ok {
		t.Fatal("BASIC-012 resolved no southbound target on a legacy bench")
	}
	if target.Model != sunspec.ModelFreqWattLegacy {
		t.Errorf("BASIC-012 resolved to M%d on a legacy bench, want M134", target.Model)
	}
	if target.NoRegisterHome != "" {
		t.Errorf("BASIC-012 still refuses to measure on a legacy bench: %s", target.NoRegisterHome)
	}
	got := oracleCurve(b)(context.Background(), legacy.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-012 on an unwritten legacy bench = %s, want FAIL: %s", got.Verdict, got.Observed)
	}
	if strings.Contains(got.Observed, "NO southbound register home") {
		t.Errorf("BASIC-012 on a legacy bench still reports the 7xx no-home refusal:\n%s", got.Observed)
	}

	sevenXx := newCurveFixture(t)
	uv7, err := oracleUnitView(context.Background(), sevenXx.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the 7xx DER through the referee: %v", err)
	}
	target7, ok := b.resolveTarget(uv7)
	if !ok {
		t.Fatal("BASIC-012 resolved no southbound target on a 7xx bench")
	}
	if target7.Model != sunspec.ModelDERFreqDroop || target7.NoRegisterHome == "" {
		t.Errorf("BASIC-012 on a 7xx bench resolved to M%d with no-home=%q, want M711 with the "+
			"no-register-home refusal intact", target7.Model, target7.NoRegisterHome)
	}
	got7 := oracleCurve(b)(context.Background(), sevenXx.rc)
	if got7.Verdict != certify.Fail || !strings.Contains(got7.Observed, "NO southbound register home") {
		t.Errorf("BASIC-012 on a 7xx bench = %s, want the decided no-register-home FAIL:\n%s",
			got7.Verdict, got7.Observed)
	}
	t.Logf("BASIC-012 on 7xx (unchanged):\n  %s", got7.Observed)
}

// TestBASIC015FlipsApparatusByGeneration pins the per-generation split, which
// is the one place a row changes the KIND of assertion it makes.
//
// On 7xx it must stay a REFUSAL row: 712 is DER Watt-Var, a different function,
// so a conformant DUT refuses opModWattPF and this row proves the refusal was
// honest. On legacy it must become an EXECUTION row against 131, because that
// DER can perform the axis and "refused it" would be the wrong thing to certify.
func TestBASIC015FlipsApparatusByGeneration(t *testing.T) {
	row := rowByID(t, "BASIC-015").mode

	on7xx := row.forGeneration(map[string]string{curveGenParam: string(invariant.Family7xx)})
	if on7xx.Refusal == nil || on7xx.Curve != nil {
		t.Errorf("BASIC-015 on a 7xx bench is not a refusal row (refusal=%v curve=%v)",
			on7xx.Refusal != nil, on7xx.Curve != nil)
	}
	if on7xx.Refusal != nil && on7xx.Refusal.Curve.Model7xx != sunspec.ModelDERWattVar {
		t.Errorf("BASIC-015's 7xx refusal watches M%d, want the 712 bank it used to be written to",
			on7xx.Refusal.Curve.Model7xx)
	}

	onLegacy := row.forGeneration(map[string]string{curveGenParam: string(invariant.FamilyLegacy)})
	if onLegacy.Curve == nil || onLegacy.Refusal != nil {
		t.Errorf("BASIC-015 on a legacy bench is not an execution row (refusal=%v curve=%v)",
			onLegacy.Refusal != nil, onLegacy.Curve != nil)
	}
	if onLegacy.Curve != nil && onLegacy.Curve.ModelLegacy != sunspec.ModelWattPFLegacy {
		t.Errorf("BASIC-015's legacy execution row targets M%d, want M131 (Watt-PF)",
			onLegacy.Curve.ModelLegacy)
	}

	// An UNKNOWN generation must not silently pick the legacy arm: a row that
	// guessed would grade an execution question against a bank it never read.
	unknown := row.forGeneration(map[string]string{curveGenParam: curveGenUnknown})
	if unknown.Refusal == nil || unknown.Curve != nil {
		t.Error("BASIC-015 with an unresolved generation flipped to the execution arm; the split must " +
			"default to the row as declared, never to a guess")
	}
}

// ── GREEN: the machinery the product will gain, run for real ────────────────

// legacyPlanFor builds the derbase write plan a gateway executing this row
// would make, from the row's OWN published curve.
//
// The DeptRef is a LITERAL of the legacy standards text, cross-checked against
// what the referee independently expects. Deriving it from the referee would
// make this test a tautology — the oracle would be judging its own answer — and
// stating it twice is what makes a divergence between the two visible.
func legacyPlanFor(t *testing.T, b *curveBinding, model uint16, axis string,
	deptRef uint16) derbase.LegacyCurvePlan {
	t.Helper()
	if deptRef != 0 {
		want, ok := b.wantDeptRef(model)
		if !ok {
			t.Fatalf("the referee expects no DeptRef on M%d, but this plan writes %d", model, deptRef)
		}
		if want != deptRef {
			t.Fatalf("the standards text says M%d DeptRef=%d for yRefType=%d, the referee expects %d — "+
				"one of the two transcriptions is wrong and this test exists to notice",
				model, deptRef, b.YRefType, want)
		}
	}
	pts := make([]sunspec.LegacyCurvePoint, 0, len(b.Points))
	for _, p := range b.wantPoints() {
		pts = append(pts, sunspec.LegacyCurvePoint{X: p.X, Y: p.Y})
	}
	return derbase.LegacyCurvePlan{ModelID: model, Axis: axis, Points: pts, DeptRef: deptRef}
}

// TestLegacyCurveRowsTurnGreenWhenTheRealLegacyWriterRuns is the discrimination
// proof. The SAME row, against the SAME device, after lexa-proto's own
// WriteLegacyCurve has installed exactly the curve the row publishes: the
// verdict must flip to PASS.
//
// Red-then-green over one binding is the whole claim. A row that were merely
// always red would look identical in the test above, and an oracle shaped to
// the fixture would look identical here; only the pair distinguishes a
// measurement from either.
func TestLegacyCurveRowsTurnGreenWhenTheRealLegacyWriterRuns(t *testing.T) {
	for _, tc := range []struct {
		id      string
		model   uint16
		axis    string
		deptRef uint16 // 0 = this model carries no DeptRef register
	}{
		// 126 declares {1 %WMax, 2 %VArMax, 3 %VArAval}; BASIC-006 publishes
		// yRefType 3 (%statVarAvail), which is %VArAval = 3 in that enum.
		{"BASIC-006", sunspec.ModelVoltVarLegacy, "opModVoltVar", 3},
		// 132 declares {1 %WMax, 2 %WAvail}; BASIC-011 publishes yRefType 1
		// (%setMaxW), which is %WMax = 1.
		{"BASIC-011", sunspec.ModelVoltWattLegacy, "opModVoltWatt", 1},
		// 134 carries no DeptRef: its y values are % WRef, a register in the
		// same block rather than an enum code.
		{"BASIC-012", sunspec.ModelFreqWattLegacy, "opModFreqWatt", 0},
		// 131 carries no DeptRef: the spec fixes x at %WMax and y is a power
		// factor, which is not a percentage OF anything.
		{"BASIC-015", sunspec.ModelWattPFLegacy, "opModWattPF", 0},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newLegacyFixture(t, sim.LegacyCurveOptions{})
			b := legacyBindingOf(t, tc.id)

			before := oracleCurve(b)(context.Background(), f.rc)
			if before.Verdict != certify.Fail {
				t.Fatalf("%s started %s on an unwritten bench, so a later PASS would prove nothing: %s",
					tc.id, before.Verdict, before.Observed)
			}

			out, err := f.base.WriteLegacyCurve(legacyPlanFor(t, b, tc.model, tc.axis, tc.deptRef),
				"legacy-curve-test")
			if err != nil {
				t.Fatalf("%s: the REAL derbase legacy writer refused this row's own curve: %v", tc.id, err)
			}

			after := oracleCurve(b)(context.Background(), f.rc)
			if after.Verdict != certify.Pass {
				t.Fatalf("%s after the real writer installed its curve into M%d bank %d = %s, want PASS.\n%s",
					tc.id, tc.model, out.Bank, after.Verdict, after.Observed)
			}
			t.Logf("%s GREEN after derbase.WriteLegacyCurve (bank %d, caseB=%t):\n  %s",
				tc.id, out.Bank, out.CaseB, after.Observed)
		})
	}
}

// TestLegacyWriterOnOneAxisLeavesTheOthersRed is the second half of the
// discrimination proof, and it is the one that catches an oracle that is
// really reading the bench rather than the model it names.
//
// Installing a volt-var curve into 126 must turn BASIC-006 green and must leave
// BASIC-011, BASIC-012 and BASIC-015 exactly as red as they were. A referee
// that resolved the wrong bank, or that graded "some curve is present", would
// go green on all four.
func TestLegacyWriterOnOneAxisLeavesTheOthersRed(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	vv := legacyBindingOf(t, "BASIC-006")
	if _, err := f.base.WriteLegacyCurve(
		legacyPlanFor(t, vv, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3), "legacy-curve-test"); err != nil {
		t.Fatalf("the real derbase legacy writer refused BASIC-006's curve: %v", err)
	}
	if got := oracleCurve(vv)(context.Background(), f.rc); got.Verdict != certify.Pass {
		t.Fatalf("BASIC-006 = %s after its own curve was installed: %s", got.Verdict, got.Observed)
	}
	for _, id := range []string{"BASIC-011", "BASIC-012", "BASIC-015"} {
		b := legacyBindingOf(t, id)
		got := oracleCurve(b)(context.Background(), f.rc)
		if got.Verdict != certify.Fail {
			t.Errorf("%s = %s after a VOLT-VAR curve was installed on a different model — this row is "+
				"reading the bench, not the register home it names:\n%s", id, got.Verdict, got.Observed)
		}
	}
}

// TestLegacyCurveOracleReadsTheActCrvBankAndNotBankOne is the single most
// important semantic difference between the generations, as a test.
//
// A curve sitting in a bank ActCrv does not select is a curve the device is NOT
// running — the legacy analogue of content in a 7xx staging slot. A referee
// that read bank 1 unconditionally would certify it.
func TestLegacyCurveOracleReadsTheActCrvBankAndNotBankOne(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{NCrv: 2})
	b := legacyBindingOf(t, "BASIC-006")

	// The device starts with ActCrv = 1. Write the row's curve into bank 2 and
	// leave the selection alone: the content is present on the device and is
	// not the curve it is running.
	uv := f.unitView(t)
	if cv := uv.Curve(oracleSimName, sunspec.ModelVoltVarLegacy); cv.ActCrv != 1 {
		t.Fatalf("the fixture starts with ActCrv=%d, this test needs 1", cv.ActCrv)
	}
	regs, err := f.base.Reader.ReadModel(sunspec.ModelVoltVarLegacy)
	if err != nil {
		t.Fatalf("read M126: %v", err)
	}
	pts := make([]sunspec.LegacyCurvePoint, 0, len(b.Points))
	for _, p := range b.wantPoints() {
		pts = append(pts, sunspec.LegacyCurvePoint{X: p.X, Y: p.Y})
	}
	start, end, err := sunspec.EncodeLegacy126Curve(regs, 2,
		sunspec.LegacyVoltVarCurve{DeptRef: 3, Pts: pts})
	if err != nil {
		t.Fatalf("encode into bank 2: %v", err)
	}
	if err := f.base.Reader.WriteModel(sunspec.ModelVoltVarLegacy, uint16(start), regs[start:end]); err != nil {
		t.Fatalf("write bank 2: %v", err)
	}

	got := oracleCurve(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-006 = %s with its curve in an UNSELECTED bank — the referee graded a curve the "+
			"device is not running:\n%s", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "ActCrv") {
		t.Errorf("the FAIL does not name the selection as the reason:\n%s", got.Observed)
	}
	t.Logf("BASIC-006 with content in an unselected bank:\n  %s", got.Observed)
}

// TestLegacyCurveOracleRefusesAnUnknownGeometry pins the fail-closed gate: a
// device whose declared L, NCrv and spec block length disagree has a register
// map nobody can compute offsets in, and a referee that read twenty point slots
// out of a ten-slot block would report a curve made of the wrong registers.
func TestLegacyCurveOracleRefusesAnUnknownGeometry(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{NCrv: 2, ShortBlockModel: 126})
	b := legacyBindingOf(t, "BASIC-006")
	got := oracleCurve(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-006 against a short-block M126 = %s, want FAIL: %s", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "block length") {
		t.Errorf("the FAIL does not name the geometry as the reason:\n%s", got.Observed)
	}
	t.Logf("BASIC-006 against a short-block M126:\n  %s", got.Observed)
}

// TestLegacyActCrvIgnoredKeepsTheRowRed proves the row survives a device that
// LIES about the commit. legacy_actcrv_ignored ACKs the ActCrv write and does
// not move the register, so the curve lands in a bank nothing selects — and a
// gateway that trusted its own write would report the axis executed.
func TestLegacyActCrvIgnoredKeepsTheRowRed(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{NCrv: 2})
	if err := f.ss.ApplyFault([]byte(`{"kind":"legacy_actcrv_ignored"}`)); err != nil {
		t.Fatalf("arm legacy_actcrv_ignored: %v", err)
	}
	b := legacyBindingOf(t, "BASIC-006")
	// The writer itself should notice (it verifies its read-back); whether it
	// errors or not, the ROW must not go green.
	_, _ = f.base.WriteLegacyCurve(
		legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3), "legacy-curve-test")
	got := oracleCurve(b)(context.Background(), f.rc)
	if got.Verdict == certify.Pass {
		t.Fatalf("BASIC-006 PASSED against a device that ignored the ActCrv commit:\n%s", got.Observed)
	}
	t.Logf("BASIC-006 under legacy_actcrv_ignored:\n  %s", got.Observed)
}

// TestLegacyCurveDisabledFunctionIsNotExecution: a curve installed into a
// function whose ModEna bit 0 is clear commands nothing, and the row must say
// so rather than grading the points alone.
func TestLegacyCurveDisabledFunctionIsNotExecution(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	b := legacyBindingOf(t, "BASIC-006")
	if _, err := f.base.WriteLegacyCurve(
		legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3), "legacy-curve-test"); err != nil {
		t.Fatalf("the real derbase legacy writer refused BASIC-006's curve: %v", err)
	}
	if got := oracleCurve(b)(context.Background(), f.rc); got.Verdict != certify.Pass {
		t.Fatalf("BASIC-006 = %s after a clean write: %s", got.Verdict, got.Observed)
	}
	// Switch the function off behind the writer's back — a state a correct
	// writer never leaves, which is why an inverted case has to manufacture it.
	if err := f.base.Reader.WriteModel(sunspec.ModelVoltVarLegacy,
		uint16(sunspec.L126Hdr.Offset("ModEna")), []uint16{0}); err != nil {
		t.Fatalf("clear ModEna: %v", err)
	}
	got := oracleCurve(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-006 = %s with ModEna cleared: a curve in a switched-off function commands "+
			"nothing.\n%s", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "DISABLED") {
		t.Errorf("the FAIL does not name the disable as the reason:\n%s", got.Observed)
	}
}

// TestLegacyCurveWrongDeptRefIsStillAFail: identical breakpoints under the
// wrong dependent reference are a DIFFERENT command, and the legacy enum is
// 1-based — so a gateway that copied the 7xx code would write 2 where 3 is
// meant and the points would all still match.
func TestLegacyCurveWrongDeptRefIsStillAFail(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	b := legacyBindingOf(t, "BASIC-006")
	plan := legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3)
	// 2 is %VArMax on the legacy enum — and it is ALSO what a gateway that
	// forgot the off-by-one would write for %VArAval, since %VArAval is 2 in
	// the 7xx numbering. This is the exact mis-translation the check exists for.
	plan.DeptRef = 2
	if _, err := f.base.WriteLegacyCurve(plan, "legacy-curve-test"); err != nil {
		t.Fatalf("write with the wrong DeptRef: %v", err)
	}
	got := oracleCurve(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-006 = %s with DeptRef=2 where the row's yRefType requires 3 — the points "+
			"matching proves nothing here.\n%s", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "WRONG y-axis reference") {
		t.Errorf("the FAIL does not name the reference as the reason:\n%s", got.Observed)
	}
	t.Logf("BASIC-006 with the 7xx DeptRef code copied onto a legacy bank:\n  %s", got.Observed)
}

// TestLegacyReadOnlyLiveBankDoesNotWarn pins the suppressed WARN. On 7xx a
// writable live curve is suspicious; on legacy every bank is ordinarily
// writable, so the same warning would fire on every correct legacy device and
// tell a reader something false about it.
func TestLegacyReadOnlyLiveBankDoesNotWarn(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	b := legacyBindingOf(t, "BASIC-006")
	if _, err := f.base.WriteLegacyCurve(
		legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3), "legacy-curve-test"); err != nil {
		t.Fatalf("the real derbase legacy writer refused BASIC-006's curve: %v", err)
	}
	uv := f.unitView(t)
	cv := uv.Curve(oracleSimName, sunspec.ModelVoltVarLegacy)
	if cv.ReadOnly {
		t.Fatalf("the fixture's live bank is READONLY, so this test is not exercising the suppression")
	}
	if got := oracleCurve(b)(context.Background(), f.rc); got.Verdict != certify.Pass {
		t.Fatalf("a correct legacy device with a writable live bank = %s, want PASS: %s",
			got.Verdict, got.Observed)
	}
}

// TestLegacyCurveCoveredSlotsSpanEveryBank pins the covered-set decision for
// the refusal apparatus: on legacy a write can land in ANY bank, because there
// is no staging slot, so all of 1..NCrv are covered and each appears once.
func TestLegacyCurveCoveredSlotsSpanEveryBank(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{NCrv: 3})
	views, truncated, ok := coveredCurveSlots(f.unitView(t), sunspec.ModelVoltVarLegacy)
	if !ok {
		t.Fatal("the legacy bank could not be read")
	}
	if truncated != 0 {
		t.Errorf("truncated = %d on a 3-bank device", truncated)
	}
	if len(views) != 3 {
		t.Fatalf("covered %d slots on a 3-bank device, want every bank exactly once", len(views))
	}
	seen := map[int]int{}
	for _, cv := range views {
		seen[cv.Bank]++
	}
	for bank := 1; bank <= 3; bank++ {
		if seen[bank] != 1 {
			t.Errorf("bank %d appears %d times in the covered set, want exactly once", bank, seen[bank])
		}
	}
}

// TestLegacyGenerationIsReadFromTheDeviceNotConfigured pins the resolution
// rule: which generation a row grades against is a fact about the DER.
func TestLegacyGenerationIsReadFromTheDeviceNotConfigured(t *testing.T) {
	legacy := newLegacyFixture(t, sim.LegacyCurveOptions{})
	if got := detectCurveGeneration(context.Background(), legacy.rc); got != string(invariant.FamilyLegacy) {
		t.Errorf("a legacy-curve DER reported generation %q, want %q", got, invariant.FamilyLegacy)
	}
	sevenXx := newCurveFixture(t)
	if got := detectCurveGeneration(context.Background(), sevenXx.rc); got != string(invariant.Family7xx) {
		t.Errorf("an advanced 7xx DER reported generation %q, want %q", got, invariant.Family7xx)
	}
}

// ── The rows, driven end to end, on a legacy bench ──────────────────────────

// withGridSim gives the legacy fixture a real gridsim admin API on the same
// RunCtx, so a row's Setup can actually publish and its PostWait can actually
// read — curveFixture.withGridSim's sibling.
func (f *legacyFixture) withGridSim(t *testing.T) (*Driver, *gridsim.Server, string) {
	t.Helper()
	gs := gridsim.NewServer(benchLFDI)
	adminSrv := httptest.NewServer(gs.AdminHandler())
	t.Cleanup(adminSrv.Close)
	// The DATA plane too, not only the admin one: this bench has to be able to
	// GET the DERCurve href a control links, which is the only way to tell "the
	// DUT refused the axis" apart from "the bench served the curve nowhere".
	dataSrv := httptest.NewServer(gs.Handler())
	t.Cleanup(dataSrv.Close)
	f.rc.GridSim = certify.NewAdminClient(adminSrv.URL, http.DefaultClient)
	f.rc.Targets = certify.Targets{GridSimAdmin: adminSrv.URL}
	return NewDriver(f.rc), gs, dataSrv.URL
}

// TestLegacyRowsAreRedEndToEndAgainstTheShippingProduct drives the SHIPPING
// rows through the same live-phase sequence check.go's run() uses (Setup, the
// DUT's poll cycle, PostWait) against a LEGACY DER, with the device left in
// exactly the state the current product leaves it: nothing written, because the
// gateway refuses every curve axis at receipt.
//
// This is the row-level red proof. The oracle-level one above shows the
// referee's answer; this shows the row's DECLARED VERDICT, which is what lands
// in a bundle — and it must be FAIL independently of the capture, because the
// capture would have shown a perfectly good <opModVoltVar> element and that is
// exactly what used to carry these rows to PASS.
func TestLegacyRowsAreRedEndToEndAgainstTheShippingProduct(t *testing.T) {
	for _, id := range []string{"BASIC-006", "BASIC-011", "BASIC-012", "BASIC-015"} {
		t.Run(id, func(t *testing.T) {
			f := newLegacyFixture(t, sim.LegacyCurveOptions{})
			d, _, dataURL := f.withGridSim(t)
			row := rowByID(t, id)
			s := inverterControlSpec(row.mode, row.subject, "CERT-"+id)

			ctx := context.Background()
			params := map[string]string{pollWindowParam: "20ms"}
			if err := s.Setup(ctx, d, params); err != nil {
				t.Fatalf("%s Setup: %v", id, err)
			}
			// The DUT's poll cycle happens here. This product does nothing
			// southbound for a refused axis, which is the whole point.
			if err := s.PostWait(ctx, d, params); err != nil {
				t.Fatalf("%s PostWait: %v", id, err)
			}

			obs := &Observation{Params: params}
			if got := s.Verdict(obs); got != certify.Fail {
				t.Fatalf("%s's declared live verdict on a LEGACY bench against the shipping product = %q, "+
					"want FAIL", id, got)
			}
			if params[curveGenParam] != "" && params[curveGenParam] != string(invariant.FamilyLegacy) {
				t.Errorf("%s recorded generation %q on a legacy bench", id, params[curveGenParam])
			}
			if got := params[curveModelParam]; got == "" {
				t.Errorf("%s recorded no southbound model, so the bundle cannot say what it measured", id)
			}
			// The href the control links has to RESOLVE, or the southbound
			// silence this row observes is unattributable: a bench 404 and a
			// DUT that refused the axis look identical from outside.
			href := params[curveHrefParam]
			if href == "" {
				t.Fatalf("%s recorded no DERCurve href", id)
			}
			resp, err := http.Get(dataURL + href)
			if err != nil {
				t.Fatalf("GET %s: %v", href, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				t.Errorf("GET %s answered %d — the control this row published links a curve resource the "+
					"bench does not serve, so every southbound silence on this row is unattributable",
					href, resp.StatusCode)
			}
			t.Logf("%s end-to-end on a legacy bench: verdict=FAIL model=%s generation=%s curve=%s (%d)\n%s",
				id, params[curveModelParam], params[curveGenParam], href, resp.StatusCode, s.Notes(obs))
		})
	}
}

// TestLegacyRowTeardownActuallyClearsTheBench is §10's ordering constraint,
// checked rather than assumed.
//
// The nil-body DELETE bug (gridsim reads the program from the JSON body and
// answered 400 on the io.EOF a nil body produces, and the callers discarded the
// error) meant every curve row leaked its control and its curve into the rest of
// the run for as long as the teardown existed. It is fixed — and "it is fixed"
// is a claim, so this row's own Cleanup is run and the bench is then inspected:
// no admin-posted control, and no individually-addressable curve resource left
// answering at the href the control linked.
func TestLegacyRowTeardownActuallyClearsTheBench(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	d, _, dataURL := f.withGridSim(t)
	row := rowByID(t, "BASIC-006")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-006")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	href := params[curveHrefParam]
	mrid := params[curveResourceParam]
	if href == "" || mrid == "" {
		t.Fatalf("the row recorded href=%q curve mRID=%q, so there is nothing to check the teardown "+
			"against", href, mrid)
	}
	// The check is on the CONTENT at the href, not on whether the href is
	// served at all. Program 0's static fixture legitimately owns
	// /derp/0/dc/0, so a DELETE puts the FIXTURE curve back there rather than
	// removing the path — and "the path 404s" would therefore be the wrong
	// assertion, passing on program 1 and failing on program 0 for a reason
	// that is not about contamination. What must not survive is this row's own
	// curve, identified by the mRID gridsim minted for it.
	get := func(path string) string {
		t.Helper()
		resp, err := http.Get(dataURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 8192)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}
	if before := get(href); !strings.Contains(before, mrid) {
		t.Fatalf("GET %s does not serve this row's own curve (%s) BEFORE the teardown; this test cannot "+
			"show a clear that never had anything to clear:\n%s", href, mrid, before)
	}

	s.Cleanup(ctx, d)

	if got := d.CleanupErrors(); len(got) != 0 {
		t.Errorf("the teardown recorded errors, so the next row would grade a bench this one is still "+
			"driving: %v", got)
	}
	if after := get(href); strings.Contains(after, mrid) {
		t.Errorf("GET %s still serves this row's own curve (%s) after Cleanup — the curve this row "+
			"published is still fetchable, which is the contamination the clear exists to remove:\n%s",
			href, mrid, after)
	}
	if after := get("/derp/0/dc"); strings.Contains(after, mrid) {
		t.Errorf("the program's DERCurveList still lists this row's curve (%s) after Cleanup:\n%s",
			mrid, after)
	}

	// And the control list is back to a plain, empty one.
	if ctrls := get("/derp/0/derc"); strings.Contains(ctrls, "opModVoltVar") {
		t.Errorf("the admin-posted curve control survived the teardown:\n%s", ctrls)
	}
}
