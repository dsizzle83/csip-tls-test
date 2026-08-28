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
	"io"
	"log"
	"math"
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

// TestBASIC012MeasuresTheCurveOnLegacyAndTheDroopOn7xx is D2's acceptance
// criterion plus curve plan #32's re-adjudication of the other bench, and it is
// one statement about BOTH.
//
// Figure 12 prescribes two things — a frequency-WATT curve and an immediate
// frequency-DROOP control — and their register fates are exactly opposite:
//
//	7xx     no model stores frequency-watt breakpoints (711 is parametric), and
//	        711 IS the exact home of the droop's five parameters
//	legacy  M134 stores the breakpoints, and nothing stores the droop
//
// So the row measures whichever half the DER in front of it can hold, and says
// on every verdict which half it did not assert. Before #32 the 7xx arm was a
// DECIDED FAIL that no product behaviour could ever move, because the bench
// could not author the only content that generation can store; that is the
// thing this test now pins as closed.
//
// BOTH arms are RED here, against the SHIPPING product, and for two different
// honest reasons — the legacy banks are unwritten, and 711 holds its factory
// droop and never adopted. Neither is "no measurement was possible".
func TestBASIC012MeasuresTheCurveOnLegacyAndTheDroopOn7xx(t *testing.T) {
	b := rowByID(t, "BASIC-012").mode.Curve
	if b == nil {
		t.Fatal("BASIC-012 carries no curve binding")
	}
	if b.Droop == nil {
		t.Fatal("BASIC-012 authors no opModFreqDroop, so its 7xx arm has nothing to measure and Figure " +
			"12's other half is not on the wire at all")
	}

	// ── LEGACY: the breakpoints are measured, the droop is named ──
	legacy := newLegacyFixture(t, sim.LegacyCurveOptions{})
	target, how := b.resolveTarget(legacy.unitView(t))
	if how != curveResolved {
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
	// The droop was SERVED to this DUT and no legacy register can hold it. A
	// verdict that did not say so would let a reader take the M134 reading for
	// a statement about the whole of Figure 12.
	if !strings.Contains(got.Observed, "AUTHORED BUT NOT DEVICE-MAPPABLE") ||
		!strings.Contains(got.Observed, "opModFreqDroop") {
		t.Errorf("BASIC-012's legacy verdict does not disclose that the droop it authored has no register "+
			"home on this generation:\n%s", got.Observed)
	}
	t.Logf("BASIC-012 RED on legacy (M134 unwritten), droop named as unmappable:\n  %s", got.Observed)

	// ── 7xx: the DROOP is measured, the breakpoints are named ──
	sevenXx := newCurveFixture(t)
	uv7, err := oracleUnitView(context.Background(), sevenXx.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the 7xx DER through the referee: %v", err)
	}
	target7, how7 := b.resolveTarget(uv7)
	if how7 != curveResolved {
		t.Fatal("BASIC-012 resolved no southbound target on a 7xx bench")
	}
	// The BREAKPOINT arm is unchanged and must stay unchanged: 711 is named as
	// the nearest model and the refusal to grade points against it stands.
	if target7.Model != sunspec.ModelDERFreqDroop || target7.NoRegisterHome == "" {
		t.Errorf("BASIC-012 on a 7xx bench resolved to M%d with no-home=%q, want M711 with the "+
			"no-register-home refusal for the BREAKPOINTS intact", target7.Model, target7.NoRegisterHome)
	}
	if dt := b.Droop.resolve(invariant.Family7xx); dt.Model != sunspec.ModelDERFreqDroop ||
		dt.NoRegisterHome != "" {
		t.Errorf("BASIC-012's droop resolved to M%d with no-home=%q on 7xx, want M711 with a real home",
			dt.Model, dt.NoRegisterHome)
	}
	// The oracle's own measurability predicate must agree with the record the
	// bundle prints, on BOTH generations — they were two predicates once, and
	// the disagreement was a PASS with an authored element neither compared nor
	// disclosed.
	if !b.Droop.hasHome(invariant.Family7xx) {
		t.Error("BASIC-012's droop reports no 7xx home, so the oracle would skip the one half this " +
			"generation can measure")
	}
	if b.Droop.hasHome(invariant.FamilyLegacy) {
		t.Error("BASIC-012's droop claims a legacy home, so the unmappable clause would drop it from the " +
			"legacy verdict while nothing measured it")
	}
	got7 := oracleCurve(b)(context.Background(), sevenXx.rc)
	if got7.Verdict != certify.Fail {
		t.Fatalf("BASIC-012 on a 7xx bench with an unwritten 711 = %s, want FAIL:\n%s",
			got7.Verdict, got7.Observed)
	}
	// It must be the DROOP's FAIL, not the old "nothing could be measured" one.
	if !strings.Contains(got7.Observed, "M711") || !strings.Contains(got7.Observed, "opModFreqDroop") {
		t.Errorf("BASIC-012's 7xx verdict does not report a measurement of the droop against M711:\n%s",
			got7.Observed)
	}
	if !strings.Contains(got7.Observed, "NOT asserted here") {
		t.Errorf("BASIC-012's 7xx verdict does not disclose that the frequency-watt BREAKPOINTS it also "+
			"published are served and unasserted on this generation:\n%s", got7.Observed)
	}
	t.Logf("BASIC-012 RED on 7xx (M711 holds its factory droop and never adopted):\n  %s", got7.Observed)
}

// TestBASIC012DroopTurnsGreenWhenTheRealWriterRuns is the discrimination proof
// for the arm curve plan #32 opened, and it is the half that says the 7xx
// verdict above is a MEASUREMENT rather than a row that is simply always red.
//
// The writer is lexa-proto's own derbase.WriteFreqDroop — the one the product's
// reconciler calls (cmd/modbus's executeDroopLocked) — driven against the same
// device the referee reads, with the values translated out of the row's own
// authored FreqDroopType. Nothing here hand-writes a register.
//
// The PMin read-modify-write is the product's, not an invention of this test:
// model 711's PMin has no 2030.5 source, so a writer preserves whatever the
// device holds. Writing 0 would tell the device it may curtail to zero, which
// is a different machine.
func TestBASIC012DroopTurnsGreenWhenTheRealWriterRuns(t *testing.T) {
	f := newCurveFixture(t)
	b := rowByID(t, "BASIC-012").mode.Curve

	before := oracleCurve(b)(context.Background(), f.rc)
	if before.Verdict != certify.Fail {
		t.Fatalf("BASIC-012 started %s on a 7xx DER whose 711 nobody wrote, so a later PASS would prove "+
			"nothing:\n%s", before.Verdict, before.Observed)
	}

	live, err := f.base.ReadFreqDroop("basic012-droop-test")
	if err != nil {
		t.Fatalf("read the DER's own droop control: %v", err)
	}
	want := b.Droop.want711()
	if err := f.base.WriteFreqDroop(sunspec.FreqDroopCtl{
		DbOf: want.DbOfHz, DbUf: want.DbUfHz, KOf: want.KOf, KUf: want.KUf, RspTms: want.RspTmsS,
		PMin: live.PMin, // read-modify-write, exactly as the product does
	}, "basic012-droop-test"); err != nil {
		t.Fatalf("the REAL derbase writer refused this row's own droop: %v", err)
	}

	after := oracleCurve(b)(context.Background(), f.rc)
	if after.Verdict != certify.Pass {
		t.Fatalf("BASIC-012 after derbase.WriteFreqDroop installed its droop into M711 = %s, want PASS:\n%s",
			after.Verdict, after.Observed)
	}
	// Green on the droop must NOT read as green on the whole Figure.
	if !strings.Contains(after.Observed, "NOT asserted here") {
		t.Errorf("the PASS does not say that the frequency-watt breakpoints were served and not "+
			"asserted on this generation:\n%s", after.Observed)
	}
	t.Logf("BASIC-012 GREEN on 7xx after derbase.WriteFreqDroop:\n  %s", after.Observed)
}

// TestBASIC012DroopMismatchIsAFail is the teeth of the droop oracle: a device
// holding a droop that is NOT the commanded one must fail, per parameter, and
// say which one and by how much.
//
// The tolerance is half the last digit the WIRE can carry, so a device off by
// one thousandth of a Hz on the dead band fails — which is the point. A
// relative tolerance of the kind the breakpoint oracle uses would be 0.6 Hz on
// a 60.03 Hz dead band, twenty times the whole offset the Figure is about, and
// would accept a device that had ignored the setting entirely.
func TestBASIC012DroopMismatchIsAFail(t *testing.T) {
	f := newCurveFixture(t)
	b := rowByID(t, "BASIC-012").mode.Curve
	want := b.Droop.want711()
	live, err := f.base.ReadFreqDroop("basic012-droop-mismatch")
	if err != nil {
		t.Fatalf("read the DER's own droop control: %v", err)
	}

	for _, tc := range []struct {
		name  string
		ctl   sunspec.FreqDroopCtl
		names string
	}{
		{"dead band off by one wire digit", sunspec.FreqDroopCtl{
			DbOf: want.DbOfHz + 0.001, DbUf: want.DbUfHz, KOf: want.KOf, KUf: want.KUf,
			RspTms: want.RspTmsS, PMin: live.PMin}, "DbOf"},
		{"gain ignored", sunspec.FreqDroopCtl{
			DbOf: want.DbOfHz, DbUf: want.DbUfHz, KOf: 0.02, KUf: want.KUf,
			RspTms: want.RspTmsS, PMin: live.PMin}, "KOf"},
		{"response time from a different control", sunspec.FreqDroopCtl{
			DbOf: want.DbOfHz, DbUf: want.DbUfHz, KOf: want.KOf, KUf: want.KUf,
			RspTms: 5, PMin: live.PMin}, "RspTms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.base.WriteFreqDroop(tc.ctl, "basic012-droop-mismatch"); err != nil {
				t.Fatalf("write the near-miss droop: %v", err)
			}
			got := oracleCurve(b)(context.Background(), f.rc)
			if got.Verdict != certify.Fail {
				t.Fatalf("a DER holding a droop that differs in %s scored %s, want FAIL:\n%s",
					tc.names, got.Verdict, got.Observed)
			}
			if !strings.Contains(got.Observed, tc.names) {
				t.Errorf("the FAIL does not name the parameter that differs (%s):\n%s", tc.names, got.Observed)
			}
		})
	}
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
// would make, and it states the DEVICE ENGINEERING VALUES as literals.
//
// THE INDEPENDENT SIDE IS THE POINT. Before this, the plan's points came from
// b.wantPoints() and the oracle compared against b.wantPoints() — one function
// on both sides of the comparison, so a MIS-SCALED binding still transitioned
// Fail -> Pass: set BASIC-006's XMult to 1 and the writer installs breakpoints
// at 920 %VRef (9.2x nominal, a curve no inverter could run) while the oracle
// asks for the same 920 and reports PASS. The red-then-green shape stays
// discriminating either way, which is why it did not show up there; what it
// could not catch is the binding being wrong in a way both sides share.
//
// So the caller states what the DEVICE must physically hold — 91.00 %VRef, not
// "whatever the multipliers work out to" — and this cross-checks that against
// wantPoints() before writing anything. Two independent statements of the same
// number, exactly the rule this file already applied to DeptRef. When they
// disagree the test says which is which, instead of the representability gate
// in lexa-proto refusing the write and the writer taking the blame for a defect
// in the fixture.
func legacyPlanFor(t *testing.T, b *curveBinding, model uint16, axis string,
	deptRef uint16, wantEng []sunspec.LegacyCurvePoint) derbase.LegacyCurvePlan {
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
	if err := crossCheckEngineering(b, model, wantEng); err != nil {
		t.Fatal(err)
	}
	pts := append([]sunspec.LegacyCurvePoint(nil), wantEng...)
	return derbase.LegacyCurvePlan{ModelID: model, Axis: axis, Points: pts, DeptRef: deptRef}
}

// crossCheckEngineering is legacyPlanFor's comparison, as a pure function so
// the check itself can be shown to have teeth (see
// TestLegacyEngineeringCrossCheck_CatchesAMisScaledBinding).
func crossCheckEngineering(b *curveBinding, model uint16, wantEng []sunspec.LegacyCurvePoint) error {
	got := b.wantPoints()
	if len(got) != len(wantEng) {
		return fmt.Errorf("M%d: this row's binding resolves to %d breakpoint(s) and the device is expected "+
			"to hold %d — the published curve and the physical curve are not the same length",
			model, len(got), len(wantEng))
	}
	// The comparison is exact to within a float round-trip and nothing wider.
	// applyMult reaches 10^-2 by dividing by ten twice, so 98 -> 0.98 lands one
	// ulp off the literal; a MIS-SCALING is a factor of ten or more and is
	// nowhere near this epsilon. A percentage tolerance here would be the wrong
	// instrument — it would start absorbing the very errors the check is for.
	const ulp = 1e-9
	near := func(a, b float64) bool { return math.Abs(a-b) <= ulp*math.Max(1, math.Abs(b)) }
	for i := range wantEng {
		if !near(got[i].X, wantEng[i].X) || !near(got[i].Y, wantEng[i].Y) {
			return fmt.Errorf("M%d breakpoint %d: this row's binding resolves to (%g, %g) and the device "+
				"is expected to hold (%g, %g). The published values and the axis multipliers together are "+
				"what the DER physically receives, so a disagreement here is a MIS-SCALED BINDING — the "+
				"920 %%VRef shape — and it must be caught here rather than by a representability refusal "+
				"that would read as a defect in the writer",
				model, i+1, got[i].X, got[i].Y, wantEng[i].X, wantEng[i].Y)
		}
	}
	return nil
}

// legacyExpectations is the DEVICE ENGINEERING curve each row must produce, per
// row, stated independently of the binding.
//
// Every number here is the catalog Figure's raw value with its own multiplier
// applied by hand — 9100 at 10^-2 is 91.00 %VRef — so a reader can check the
// row against the procedure without running anything, and so this file and the
// binding are two statements that can disagree.
func legacyExpectations(t *testing.T, id string) []sunspec.LegacyCurvePoint {
	t.Helper()
	switch id {
	case "BASIC-006":
		// Figure 6 Test Values (9100,4000) (9570,0) (10400,0) (10600,-4000),
		// x and y at 10^-2: percent voltage against signed percent of DeptRef.
		return []sunspec.LegacyCurvePoint{
			{X: 91.00, Y: 40.00}, {X: 95.70, Y: 0}, {X: 104.00, Y: 0}, {X: 106.00, Y: -40.00},
		}
	case "BASIC-011":
		// Figure 11 Test Values (10000,10000) (10500,10000) (10900,0) at 10^-2.
		return []sunspec.LegacyCurvePoint{
			{X: 100.00, Y: 100.00}, {X: 105.00, Y: 100.00}, {X: 109.00, Y: 0},
		}
	case "BASIC-012":
		// Figure 12 Test Values (5900,100) (5950,80) (6050,80) (6200,0), x at
		// 10^-2 (ABSOLUTE Hz) and y at 10^0 (percent of WRef on M134).
		return []sunspec.LegacyCurvePoint{
			{X: 59.00, Y: 100}, {X: 59.50, Y: 80}, {X: 60.50, Y: 80}, {X: 62.00, Y: 0},
		}
	case "BASIC-015":
		// Not catalog-prescribed (BASIC-015 carries no curve Figure): this
		// suite's own Watt-PF curve, y at 10^-2 so 95 is a power factor of 0.95.
		return []sunspec.LegacyCurvePoint{
			{X: 0, Y: 1.00}, {X: 50, Y: 0.98}, {X: 100, Y: 0.95},
		}
	}
	t.Fatalf("no device-engineering expectation is stated for %s", id)
	return nil
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
		// unmappable is the element the row also AUTHORS and that this
		// generation stores in no register. The green verdict must name it, or
		// a reader would take the PASS for a statement about the whole Figure.
		// Empty for a row whose Figure asks for nothing beyond the curve.
		unmappable string
	}{
		// 126 declares {1 %WMax, 2 %VArMax, 3 %VArAval}; BASIC-006 publishes
		// yRefType 3 (%statVarAvail), which is %VArAval = 3 in that enum.
		//
		// Its openLoopTms goes on the wire (curve plan #32) and lands in no
		// legacy register — 126 carries ActCrv, ModEna, DeptRef and points and
		// no timing register at all — so the PASS has to say so.
		{"BASIC-006", sunspec.ModelVoltVarLegacy, "opModVoltVar", 3, "DERCurve.openLoopTms"},
		// 132 declares {1 %WMax, 2 %WAvail}; BASIC-011 publishes yRefType 1
		// (%setMaxW), which is %WMax = 1. Figure 11 prescribes nothing beyond
		// the curve, so this row's verdict must carry NO unmappable clause.
		{"BASIC-011", sunspec.ModelVoltWattLegacy, "opModVoltWatt", 1, ""},
		// 134 carries no DeptRef: its y values are % WRef, a register in the
		// same block rather than an enum code. Its opModFreqDroop has no legacy
		// home either — M127 is a different function — so the same disclosure
		// applies, one element up.
		{"BASIC-012", sunspec.ModelFreqWattLegacy, "opModFreqWatt", 0, "opModFreqDroop"},
		// 131 carries no DeptRef: the spec fixes x at %WMax and y is a power
		// factor, which is not a percentage OF anything.
		{"BASIC-015", sunspec.ModelWattPFLegacy, "opModWattPF", 0, ""},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newLegacyFixture(t, sim.LegacyCurveOptions{})
			b := legacyBindingOf(t, tc.id)

			before := oracleCurve(b)(context.Background(), f.rc)
			if before.Verdict != certify.Fail {
				t.Fatalf("%s started %s on an unwritten bench, so a later PASS would prove nothing: %s",
					tc.id, before.Verdict, before.Observed)
			}

			out, err := f.base.WriteLegacyCurve(
				legacyPlanFor(t, b, tc.model, tc.axis, tc.deptRef, legacyExpectations(t, tc.id)),
				"legacy-curve-test")
			if err != nil {
				t.Fatalf("%s: the REAL derbase legacy writer refused this row's own curve: %v", tc.id, err)
			}

			after := oracleCurve(b)(context.Background(), f.rc)
			if after.Verdict != certify.Pass {
				t.Fatalf("%s after the real writer installed its curve into M%d bank %d = %s, want PASS.\n%s",
					tc.id, tc.model, out.Bank, after.Verdict, after.Observed)
			}
			// A GREEN row must not be read as green on content nothing looked
			// at. The elements curve plan #32 put on the wire have no legacy
			// register home, and the PASS says which — or says nothing at all,
			// for a row that authored nothing beyond its curve.
			named := strings.Contains(after.Observed, "AUTHORED BUT NOT DEVICE-MAPPABLE")
			if tc.unmappable == "" {
				if named {
					t.Errorf("%s's PASS discloses an unmappable element, but this row's Figure prescribes "+
						"nothing beyond the curve:\n%s", tc.id, after.Observed)
				}
			} else if !named || !strings.Contains(after.Observed, tc.unmappable) {
				t.Errorf("%s's PASS does not disclose that it also served %s, which no legacy register can "+
					"hold — so the verdict reads as covering the whole of the row's Figure:\n%s",
					tc.id, tc.unmappable, after.Observed)
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
		legacyPlanFor(t, vv, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3, legacyExpectations(t, "BASIC-006")),
		"legacy-curve-test"); err != nil {
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
		legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3, legacyExpectations(t, "BASIC-006")),
		"legacy-curve-test")
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
		legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3, legacyExpectations(t, "BASIC-006")),
		"legacy-curve-test"); err != nil {
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
	plan := legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3, legacyExpectations(t, "BASIC-006"))
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
		legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3, legacyExpectations(t, "BASIC-006")),
		"legacy-curve-test"); err != nil {
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
	// Tee the standard logger into the server's log buffer, exactly as the
	// sim/server binary does. gridsim writes its per-request lines through
	// log.Printf, and GET /admin/logs streams that buffer — so without this the
	// request log a Driver reads is empty on every unit test, and any check
	// resting on "did the DUT fetch this?" would silently read zero.
	prevLog := log.Writer()
	log.SetOutput(io.MultiWriter(prevLog, gs.LogWriter()))
	t.Cleanup(func() { log.SetOutput(prevLog) })

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
			// THE DELIVERY FACT. This fixture has no gateway process at all —
			// nothing fetches anything — so the row's own text must say that,
			// instead of reading as though a DUT had considered the control and
			// declined it. The two produce identical register evidence and only
			// this sentence separates them in the headline verdict.
			notes := s.Notes(obs)
			if !strings.Contains(notes, "NO fetch of this row's control was observed") {
				t.Errorf("%s's verdict text does not say the control was never fetched, so a dead DUT and "+
					"a refusing one read identically here:\n%s", id, notes)
			}
			if !strings.Contains(notes, "never received the control at all") {
				t.Errorf("%s's verdict text does not name the ambiguity it is under:\n%s", id, notes)
			}
			t.Logf("%s end-to-end on a legacy bench: verdict=FAIL model=%s generation=%s curve=%s (%d)\n%s",
				id, params[curveModelParam], params[curveGenParam], href, resp.StatusCode, notes)
		})
	}
}

// TestLegacyRowTeardownCancelsTheEventItPublished is IEEE 2030.5-2018
// §10.2.3.3 c)'s end-of-event rule, checked rather than assumed.
//
// A curve row's teardown used to DELETE its control from gridsim
// (ClearControls/ClearCurves). That made the control VANISH — which §10.2.3.3
// c) is explicit is NOT how an event ends: "Service providers SHALL cancel
// Events that they wish clients to not act upon and/or provide new superseding
// Events." A spec-correct DUT that had ALREADY acquired the active event kept
// executing it for its full Duration, because it never OBSERVED a cancellation:
// the event simply disappeared from the list. That is CSIP-BENCH-BASIC007-
// ORACLE-STATE-CONTAMINATION — BASIC-006's opModVoltVar outlived its row on the
// DUT and became BASIC-007's effective control, failing that Default-Only row's
// baseline confirm while the product was correct.
//
// The teardown CANCELS-THEN-DELETES (teardown.go's releaseProgramControls): it
// server-CANCELS the control (currentStatus=6) so a spec-correct DUT observes the
// cancellation and drops the active event, awaits a fresh poll, and only THEN
// deletes the control so nothing is left advertised to accumulate into the next
// row. This runs the row's own Cleanup through a recording transport and proves:
// a Cancelled(6) edit was issued, a DELETE followed it (never preceded it), the
// teardown recorded no error, and the control is GONE from the data plane
// afterwards. There is deliberately NO reversion-verify — a global "any 704
// enable is contamination" gate false-FATALs the board's standing DefaultDERControl
// export limit; residual contamination is caught by the rows' own oracles.
func TestLegacyRowTeardownCancelsThenCleansTheEventItPublished(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	_, _, dataURL := f.withGridSim(t)
	// Re-wire the admin client through a recording transport so the teardown's
	// request SEQUENCE — cancel before delete — is checkable, not only its end
	// state. (withGridSim recorded the admin URL on the RunCtx.)
	rec := &recordingRT{inner: http.DefaultTransport}
	f.rc.GridSim = certify.NewAdminClient(f.rc.Targets.GridSimAdmin, rec)
	d := NewDriver(f.rc)

	row := rowByID(t, "BASIC-006")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-006")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
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
	// BEFORE the teardown the row's control is live on the wire — otherwise this
	// test cannot show a teardown that changed anything.
	before := get("/derp/0/derc")
	if !strings.Contains(before, "opModVoltVar") {
		t.Fatalf("the row's opModVoltVar control is not on the wire BEFORE the teardown:\n%s", before)
	}

	// Only the teardown's own requests are graded; Setup's precede this mark.
	teardownStart := len(rec.method)
	s.Cleanup(ctx, d)

	if got := d.CleanupErrors(); len(got) != 0 {
		t.Errorf("the teardown recorded errors, so the next row would grade a bench this one is still "+
			"driving: %v", got)
	}

	// The teardown must CANCEL (current_status=6) BEFORE it DELETEs: a
	// spec-correct DUT can only drop an event it acquired by OBSERVING the
	// cancellation, and a delete that ran first would make the control vanish
	// before it could — the exact defect this rework closes.
	cancelAt, deleteAt := -1, -1
	for i := teardownStart; i < len(rec.method); i++ {
		switch {
		case rec.method[i] == http.MethodPost && strings.Contains(rec.body[i], `"current_status":6`):
			if cancelAt < 0 {
				cancelAt = i
			}
		case rec.method[i] == http.MethodDelete:
			if deleteAt < 0 {
				deleteAt = i
			}
		}
	}
	if cancelAt < 0 {
		t.Errorf("the teardown issued no Cancelled(6) edit, so a spec-correct DUT never observes the event "+
			"end (requests: %v)", rec.method[teardownStart:])
	}
	if deleteAt < 0 {
		t.Errorf("the teardown issued no DELETE, so a cancelled control is left advertised to accumulate "+
			"into the next row (requests: %v)", rec.method[teardownStart:])
	}
	if cancelAt >= 0 && deleteAt >= 0 && cancelAt > deleteAt {
		t.Errorf("the teardown DELETED (request %d) BEFORE it CANCELLED (request %d) — deleting an "+
			"un-observed cancel out from under the DUT reproduces the vanish defect", deleteAt, cancelAt)
	}

	// AFTER the teardown the control is GONE from the data plane: cancelled, then
	// deleted — so nothing is left for the next row to inherit.
	after := get("/derp/0/derc")
	if strings.Contains(after, "opModVoltVar") {
		t.Errorf("the control is STILL advertised after the teardown; cancel-and-leave-advertised "+
			"accumulates applied state into the next row:\n%s", after)
	}
}

// TestLegacyEngineeringCrossCheck_CatchesAMisScaledBinding is the teeth of the
// independent side.
//
// The green proofs are genuinely discriminating — a row is red on an unwritten
// bench and green after the writer runs, and a volt-var write leaves the other
// three red — but that shape cannot see a binding that is wrong on BOTH sides
// of the comparison. With the plan and the oracle expectation both derived from
// wantPoints(), setting BASIC-006's XMult to 1 installs breakpoints at 920
// %VRef — 9.2x nominal, a curve no inverter on earth could run — and the row
// still transitions Fail -> Pass, because the oracle asks for the same 920.
//
// The device-engineering literals are what close it, so this proves they do.
func TestLegacyEngineeringCrossCheck_CatchesAMisScaledBinding(t *testing.T) {
	want := legacyExpectations(t, "BASIC-006")

	good := rowByID(t, "BASIC-006").mode.Curve
	if err := crossCheckEngineering(good, sunspec.ModelVoltVarLegacy, want); err != nil {
		t.Fatalf("the SHIPPING BASIC-006 binding fails its own engineering cross-check: %v", err)
	}

	// The probe: the multiplier the gate demonstrated a live PASS with.
	mis := *good
	mis.XMult = 1
	err := crossCheckEngineering(&mis, sunspec.ModelVoltVarLegacy, want)
	if err == nil {
		t.Fatal("a binding at xMultiplier 10^1 — breakpoints at 920 %VRef — passed the cross-check, so " +
			"the plan and the oracle are still deriving the same number from the same function and a " +
			"mis-scaled row would go green on a curve no device could run")
	}
	if !strings.Contains(err.Error(), "MIS-SCALED BINDING") {
		t.Errorf("the cross-check failed for the wrong reason: %v", err)
	}
	t.Logf("mis-scaled binding rejected:\n  %v", err)

	// A dropped breakpoint is caught too: the length arm.
	short := *good
	short.Points = good.Points[:2]
	if err := crossCheckEngineering(&short, sunspec.ModelVoltVarLegacy, want); err == nil {
		t.Error("a binding publishing two of its four prescribed breakpoints passed the cross-check")
	}
}

// TestLegacyCaseBRewriteTurnsTheRowGreenThroughTheRealWriter exercises the
// single-bank path, which every green run so far has missed.
//
// NCrv=1 is the FIELD-COMMON shape and the genuinely hard one: there is no
// spare bank, so the writer cannot stage — it must disable the function,
// rewrite the live bank in place and re-enable, with the device running no
// curve for the width of that window. Case A hides every ordering mistake in
// that sequence behind an atomic ActCrv switch, so a harness that only ever ran
// Case A has not exercised the path a real inverter will take.
func TestLegacyCaseBRewriteTurnsTheRowGreenThroughTheRealWriter(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{NCrv: 1})
	b := legacyBindingOf(t, "BASIC-006")

	// The device really is single-bank, or this test proves nothing.
	uv := f.unitView(t)
	if cv := uv.Curve(oracleSimName, sunspec.ModelVoltVarLegacy); cv.NCrv != 1 {
		t.Fatalf("the fixture declares NCrv=%d; this test needs the single-bank shape", cv.NCrv)
	}

	before := oracleCurve(b)(context.Background(), f.rc)
	if before.Verdict != certify.Fail {
		t.Fatalf("BASIC-006 started %s on an unwritten single-bank bench: %s", before.Verdict, before.Observed)
	}

	out, err := f.base.WriteLegacyCurve(
		legacyPlanFor(t, b, sunspec.ModelVoltVarLegacy, "opModVoltVar", 3, legacyExpectations(t, "BASIC-006")),
		"legacy-curve-test")
	if err != nil {
		t.Fatalf("the real derbase legacy writer refused a Case-B rewrite: %v", err)
	}
	if !out.CaseB {
		t.Fatalf("the writer reported caseB=false on a single-bank device (bank %d) — this test did not "+
			"exercise the in-place rewrite it exists for", out.Bank)
	}
	if out.Bank != 1 {
		t.Errorf("the Case-B rewrite landed in bank %d, and a single-bank device has only bank 1", out.Bank)
	}

	after := oracleCurve(b)(context.Background(), f.rc)
	if after.Verdict != certify.Pass {
		t.Fatalf("BASIC-006 after a Case-B rewrite = %s, want PASS.\n%s", after.Verdict, after.Observed)
	}
	t.Logf("BASIC-006 GREEN through a Case-B rewrite (bank %d, caseB=%t):\n  %s",
		out.Bank, out.CaseB, after.Observed)
}

// TestLegacyRowDeliveryFactDistinguishesAFetchFromSilence is the discrimination
// proof for the delivery sentence itself.
//
// A row that always said "no fetch observed" would be as useless as one that
// never said it: the sentence is only worth carrying if the bench can tell the
// two states apart. So the same row is run twice against the same bench — once
// with nothing fetching, and once with a client that fetches the control list
// exactly as a live DUT's walk would — and the verdict text must change.
func TestLegacyRowDeliveryFactDistinguishesAFetchFromSilence(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	d, _, dataURL := f.withGridSim(t)
	row := rowByID(t, "BASIC-006")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-006")
	ctx := context.Background()

	silent := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, silent); err != nil {
		t.Fatalf("Setup (silent): %v", err)
	}
	if err := s.PostWait(ctx, d, silent); err != nil {
		t.Fatalf("PostWait (silent): %v", err)
	}
	if got := silent[curveDeliveryParam]; !strings.Contains(got, "NO fetch") {
		t.Errorf("with nothing fetching, the delivery fact reads %q", got)
	}

	fetched := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, fetched); err != nil {
		t.Fatalf("Setup (fetched): %v", err)
	}
	// A live DUT's walk reaches the control list. Nothing else about the run
	// changes, so the delivery sentence is the only thing that can move.
	resp, err := http.Get(dataURL + "/derp/0/derc")
	if err != nil {
		t.Fatalf("fetch the control list: %v", err)
	}
	_ = resp.Body.Close()
	if err := s.PostWait(ctx, d, fetched); err != nil {
		t.Fatalf("PostWait (fetched): %v", err)
	}
	got := fetched[curveDeliveryParam]
	if !strings.Contains(got, "FETCHED this row's control") {
		t.Fatalf("after a real control-list fetch, the delivery fact still reads %q — the sentence cannot "+
			"tell a live peer from silence and is worth nothing", got)
	}
	// And the row is STILL red: delivery is context for the verdict, never a
	// substitute for the southbound measurement.
	if v := s.Verdict(&Observation{Params: fetched}); v != certify.Fail {
		t.Errorf("BASIC-006 = %s once the control was fetched; a fetch is not execution", v)
	}
	t.Logf("delivery observed:\n  %s", got)
}

// ── The both-generations device ─────────────────────────────────────────────

// bothGenerationsView is a DER serving 7xx AND legacy curve models. No bench
// builds one and no row was written for one, which is exactly why the
// resolution has to have an answer for it.
func bothGenerationsView() invariant.UnitView {
	return invariant.UnitView{Models: []uint16{
		1, 103, 120, 121, 122, 123,
		705, 706, 711, 712,
		126, 129, 130, 131, 132, 134,
	}}
}

// TestBothGenerationsDER_IsItsOwnAnswerAndNotATieBreak pins the ambiguity.
//
// Preferring one family silently is the worst available behaviour: it grades a
// bank the row's author never considered, and on BASIC-015 it swaps a refusal
// assertion for an execution one — so critRefusalAnswered, the LXR-002 catcher,
// stops running and the 712 fingerprint is never taken. A false negative on a
// real defect class is worse than refusing to grade.
func TestBothGenerationsDER_IsItsOwnAnswerAndNotATieBreak(t *testing.T) {
	uv := bothGenerationsView()
	if got := curveGenerationOf(uv); got != genAmbiguous {
		t.Fatalf("a DER serving both families reported generation %v, want ambiguous", got)
	}
	if got := curveGenerationOf(uv).String(); got != curveGenAmbiguous {
		t.Errorf("the ambiguous generation renders as %q, want %q", got, curveGenAmbiguous)
	}

	for _, id := range []string{"BASIC-006", "BASIC-011", "BASIC-012"} {
		b := rowByID(t, id).mode.Curve
		if _, how := b.resolveTarget(uv); how != curveAmbiguous {
			t.Errorf("%s resolved a target on a both-generations DER (how=%v); it must decline", id, how)
		}
	}

	// BASIC-015 keeps its declared REFUSAL apparatus, so the LXR-002 catcher
	// goes on running...
	row := rowByID(t, "BASIC-015").mode
	both := row.forGeneration(map[string]string{curveGenParam: curveGenAmbiguous})
	if both.Refusal == nil || both.Curve != nil {
		t.Errorf("BASIC-015 on a both-generations DER flipped to the execution arm (refusal=%v curve=%v): "+
			"critRefusalAnswered would stop running and the 712 fingerprint would never be taken",
			both.Refusal != nil, both.Curve != nil)
	}
	// ...and its southbound half declines to fingerprint a bank it cannot
	// choose, which is the "fail with the ambiguity named" half.
	if fp, ok := both.Refusal.fingerprint(uv); ok {
		t.Errorf("BASIC-015's refusal fingerprinted %q on a both-generations DER; it must decline rather "+
			"than watch a bank picked by a tie-break", fp)
	}
	if _, ok := curveBaselineContamination(uv, both.Refusal.Curve); ok {
		t.Error("the contamination read resolved a bank on a both-generations DER")
	}
}

// TestResolveTargetFallback_TieBreaksLegacyFirst pins the reconciliation.
//
// The two tie-breaks used to point opposite ways: generation resolution
// preferred legacy, and this fallback preferred 7xx, so a device the first
// function called legacy could still be graded against a 7xx bank here. Two
// tie-breaks disagreeing inside one resolution path is a bug waiting for the
// device that reaches both.
func TestResolveTargetFallback_TieBreaksLegacyFirst(t *testing.T) {
	// Neither named model is a CURVE model, so no generation is recognised and
	// the fallback is what decides — which is the only way to observe it.
	//
	// 701 AND 702, not the 707/708 this used to name. Those were chosen because
	// internal/invariant decoded no trip models, so a DER serving them belonged
	// to no generation; curve plan #32 made 707-710 real curve models with real
	// sub-curve decoding, so the same fixture now resolves cleanly as 7xx and
	// the fallback is never reached. The FIXTURE moved and the assertion did
	// not: 701 (DER AC Measurement) and 702 (DER Capacity) are read by every
	// register-image source and are curve models on neither generation, which is
	// exactly the property this test needs. A device serving only those is a
	// device this suite cannot place, and the fallback's ordering is the only
	// thing left to decide it.
	b := &curveBinding{
		Mode:     "volt_var",
		Model7xx: 701, Mapping7xx: "the 7xx arm",
		ModelLegacy: 702, MappingLegacy: "the legacy arm",
	}
	uv := invariant.UnitView{Models: []uint16{701, 702}}
	if got := curveGenerationOf(uv); got != genNone {
		t.Fatalf("this fixture recognises generation %v; the fallback would not be reached", got)
	}
	target, how := b.resolveTarget(uv)
	if how != curveResolved {
		t.Fatalf("the fallback resolved nothing (how=%v)", how)
	}
	if target.Model != 702 {
		t.Errorf("the fallback chose M%d; it must try LEGACY first, matching curveGenerationOf's own "+
			"ordering, or one resolution path holds two tie-breaks pointing opposite ways", target.Model)
	}
}
