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

// basic006Binding is the SHIPPING BASIC-006 row's own binding.
//
// It used to be a COPY of it — the same literals register.go registers, restated
// here — which is the shape it exists to guard against, one file along: when
// the row's published curve was reconciled to CSIP CTP v1.3 Figure 6 the copy
// went on writing the old points, so this file's "green" fixture installed a
// curve the row no longer publishes and the oracle correctly refused it. Two
// literals one edit apart is the defect; the row itself is the single source.
func basic006Binding() *curveBinding {
	for _, r := range inverterControlRows() {
		if r.id == "BASIC-006" && r.mode.Curve != nil {
			return r.mode.Curve
		}
	}
	panic("suitecsip: no BASIC-006 curve row is registered")
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
// The POINTS likewise come from the row rather than from a literal — and are
// cross-checked, before anything is written, against the device-engineering
// values stated independently in curve_legacy_test.go's legacyExpectations.
// That is the same two-independent-statements rule DeptRef already follows: the
// row says what to publish, this file says what the DEVICE must then hold, and
// a mis-scaled binding makes them disagree instead of agreeing wrongly.
//
// Model 705's V_SF/DeptRef_SF are 0 on this fixture, so Figure 6's 95.70 %VRef
// quantises to 96 in the register. That is a real property of a coarse device
// and is what curvePointTolerance exists to absorb (1 % of the value plus half
// a unit); it is not a licence to publish a different curve.
func (f *curveFixture) adoptBasic006Curve(t *testing.T) {
	t.Helper()
	b := basic006Binding()
	if err := crossCheckEngineering(b, sunspec.ModelDERVoltVar,
		legacyExpectations(t, "BASIC-006")); err != nil {
		t.Fatal(err)
	}
	pts := make([]sunspec.VVPoint, 0, len(b.Points))
	for _, p := range b.wantPoints() {
		pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
	}
	f.adoptVoltVar(t, basic006DeptRef(t), pts)
}

// basic006DeptRef is the DeptRef a gateway executing BASIC-006 must write,
// derived from the SHIPPING row's yRefType rather than restated.
func basic006DeptRef(t *testing.T) uint16 {
	t.Helper()
	want, ok := basic006Binding().wantDeptRef(sunspec.ModelDERVoltVar)
	if !ok {
		t.Fatalf("BASIC-006's yRefType has no DeptRef translation — the row publishes a curve a " +
			"conformant DUT must refuse, which is not what this fixture is for")
	}
	return want
}

// adoptVoltVar installs a volt-var curve through the REAL derbase writer, with
// the open-loop response time BASIC-006's own binding authors.
//
// RspTms rides along because Figure 6 prescribes openLoopTms 5 against a
// default of 10, and a gateway that executed the row would have written BOTH
// the shape and the timing: 705 declares Crv.RspTms for exactly this element.
// Before the referee read that register these fixtures could leave it at the
// device's default and still be called "the write a gateway that EXECUTED this
// control would have made", which was not true.
func (f *curveFixture) adoptVoltVar(t *testing.T, deptRef uint16, pts []sunspec.VVPoint) {
	t.Helper()
	rspTms := 0.0
	if s, ok := basic006Binding().wantOpenLoopS(); ok {
		rspTms = s
	}
	if err := f.base.WriteVoltVar(
		sunspec.VoltVarCurve{DeptRef: deptRef, Pri: 1, Points: pts, RspTms: rspTms},
		"curve-oracle-test"); err != nil {
		t.Fatalf("derbase WriteVoltVar (the real adopt handshake): %v", err)
	}
}

// TestOracleCurve_RightCurveWrongOpenLoopTimeIsAFail is the teeth of the
// timing check, and the reason the check exists at all.
//
// A device holding EXACTLY the breakpoints Figure 6 prescribes, adopted and
// enabled, running at its own default speed rather than the openLoopTms the
// procedure states, has executed a different command from the one this row
// published — and every other assertion in this suite is blind to it. Figure 6
// prints openLoopTms Default 10 / Test Values 5 precisely to create that
// condition, so a row that could not tell the two apart was not running its
// procedure however green it looked.
//
// The write goes through the real derbase writer, at the DEFAULT the Figure
// names (10 hundredths = 0.1 s) rather than at an invented number, so what this
// test reproduces is the exact device state the procedure is designed to
// distinguish.
func TestOracleCurve_RightCurveWrongOpenLoopTimeIsAFail(t *testing.T) {
	f := newCurveFixture(t)
	b := basic006Binding()
	if b.OpenLoopTms == nil {
		t.Fatal("BASIC-006 authors no openLoopTms, so there is no timing for a DER to get wrong")
	}
	pts := make([]sunspec.VVPoint, 0, len(b.Points))
	for _, p := range b.wantPoints() {
		pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
	}
	// Figure 6's own DEFAULT column: 10 hundredths of a second.
	if err := f.base.WriteVoltVar(
		sunspec.VoltVarCurve{DeptRef: basic006DeptRef(t), Pri: 1, Points: pts, RspTms: 0.10},
		"open-loop-teeth"); err != nil {
		t.Fatalf("derbase WriteVoltVar: %v", err)
	}
	got := oracleCurve(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("a DER running this row's exact curve at the procedure's DEFAULT open-loop time scored "+
			"%s, want FAIL — that is the condition Figure 6's test value exists to create:\n%s",
			got.Verdict, got.Observed)
	}
	for _, want := range []string{"RspTms", "openLoopTms", "0.1", "0.05"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not quote %q, so a reader cannot see which timing was commanded and "+
				"which was held:\n%s", want, got.Observed)
		}
	}
	// And openLoopTms must NOT be reported as unmappable: 705 declares
	// Crv.RspTms, so on this generation the element is MEASURED, not disclosed.
	//
	// The check reads the unmappable CLAUSE rather than the whole finding, and
	// that precision became load-bearing on 2026-08-15. It used to be a
	// conjunction over the entire text — "contains AUTHORED BUT NOT
	// DEVICE-MAPPABLE" AND "contains openLoopTms" — which was exact only while
	// openLoopTms was the sole element that could ever appear in that clause.
	// BASIC-006 now also authors the autonomous-Vref pair (IW15-027), which
	// genuinely has no register home on either generation and correctly appears
	// there, while "openLoopTms" appears elsewhere in the same sentence as the
	// timing this row FAILED on. The old guard fired on a finding that was
	// entirely right. A test whose subject is one element has to read the clause
	// about that element.
	if clause := unmappableClause(got.Observed); strings.Contains(clause, "openLoopTms") {
		t.Errorf("the verdict discloses openLoopTms as unmappable on a 705 DER, which declares "+
			"Crv.RspTms for exactly this element. The unmappable clause reads:\n  %s\n\nfull verdict:\n%s",
			clause, got.Observed)
	}
	// The mirror, so the check above cannot pass by the clause being absent
	// altogether: the pair that really has no home must be IN it.
	for _, want := range []string{"autonomousVRefEnable", "autonomousVRefTimeConstant"} {
		if !strings.Contains(unmappableClause(got.Observed), want) {
			t.Errorf("the verdict does not disclose %s as unmappable; it is authored northbound and no "+
				"SunSpec bank on either generation holds it, so a reader could mistake this verdict for "+
				"a measurement of it:\n%s", want, got.Observed)
		}
	}
	t.Logf("BASIC-006 RED on a device running the right curve at the wrong speed:\n  %s", got.Observed)
}

// TestOracleCurve_BothHalvesMustHoldAndTheWorseOneDecides pins the composition
// rule for a row whose Figure prescribes breakpoints AND an inline droop on a
// generation that stores BOTH.
//
// No shipping row reaches this today — BASIC-012's two halves land on opposite
// generations, so each bench measures one — and that is exactly why it is
// tested here rather than left to be discovered by the first row that does. The
// binding is synthetic and its two homes are real: model 705 for the volt-var
// breakpoints, model 711 for the droop, both on the same 7xx device.
//
// The rule has two parts and the second is the one that would rot silently:
// both halves must hold for a PASS, and the WORSE answer decides. If the
// composition returned the curve's answer whenever it was not a PASS, a curve
// WARN (severity 2) would stand in front of a droop FAIL (severity 3) and the
// row would report two grades better than the DER deserves.
func TestOracleCurve_BothHalvesMustHoldAndTheWorseOneDecides(t *testing.T) {
	f := newCurveFixture(t)
	b := &curveBinding{
		Mode:       "volt_var",
		Points:     []CurvePoint{{X: 9100, Y: 4000}, {X: 10600, Y: -4000}},
		XMult:      -2,
		YMult:      -2,
		YRefType:   derUnitRefStatVarAvail,
		Prescribed: "a synthetic binding, for this test only",
		Model7xx:   sunspec.ModelDERVoltVar,
		Mapping7xx: "a synthetic binding, for this test only",
		Droop: &droopBinding{
			Settings:             FreqDroopSettings{DBOF: 60030, DBUF: 59970, KOF: 40, KUF: 40, OpenLoopTms: 600},
			Model7xx:             sunspec.ModelDERFreqDroop,
			Mapping7xx:           "a synthetic binding, for this test only",
			NoRegisterHomeLegacy: "a synthetic binding, for this test only",
		},
	}

	// Nothing written: BOTH halves fail, and BOTH must be reported.
	//
	// This is the equal-severity case, and it is the one that survives a revert
	// of the "both sentences, always" rule: with the composition returning the
	// worse half alone, a curve FAIL and a droop FAIL report one sentence and
	// the bundle carries no trace that the droop was measured at all. Every
	// verdict here stays FAIL either way, so only the TEXT can catch it.
	unwritten := oracleCurve(b)(context.Background(), f.rc)
	if unwritten.Verdict != certify.Fail {
		t.Fatalf("an unwritten DER scored %s, want FAIL:\n%s", unwritten.Verdict, unwritten.Observed)
	}
	for _, want := range []string{"M705 Volt-Var", "M711 Frequency Droop", " AND "} {
		if !strings.Contains(unwritten.Observed, want) {
			t.Errorf("the composed FAIL does not carry both halves' evidence (missing %q) — a reader "+
				"cannot tell a row that failed on its curve from one whose droop nobody read:\n%s",
				want, unwritten.Observed)
		}
	}

	// The CURVE lands and the droop does not: the row must still FAIL, on the
	// droop, naming M711 — not pass on the half that worked.
	pts := make([]sunspec.VVPoint, 0, len(b.Points))
	for _, p := range b.wantPoints() {
		pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
	}
	deptRef, ok := b.wantDeptRef(sunspec.ModelDERVoltVar)
	if !ok {
		t.Fatal("the synthetic binding's yRefType has no DeptRef translation")
	}
	f.adoptVoltVar(t, deptRef, pts)
	half := oracleCurve(b)(context.Background(), f.rc)
	if half.Verdict != certify.Fail {
		t.Fatalf("a DER that adopted the CURVE and ignored the droop scored %s, want FAIL — half a "+
			"control is not execution:\n%s", half.Verdict, half.Observed)
	}
	if !strings.Contains(half.Observed, "M711") {
		t.Errorf("the FAIL does not name the droop bank it read:\n%s", half.Observed)
	}

	// Both land: one PASS carrying both halves' evidence.
	live, err := f.base.ReadFreqDroop("both-halves-test")
	if err != nil {
		t.Fatalf("read the DER's own droop control: %v", err)
	}
	want := b.Droop.want711()
	if err := f.base.WriteFreqDroop(sunspec.FreqDroopCtl{
		DbOf: want.DbOfHz, DbUf: want.DbUfHz, KOf: want.KOf, KUf: want.KUf, RspTms: want.RspTmsS,
		PMin: live.PMin,
	}, "both-halves-test"); err != nil {
		t.Fatalf("the real derbase writer refused the synthetic droop: %v", err)
	}
	both := oracleCurve(b)(context.Background(), f.rc)
	if both.Verdict != certify.Pass {
		t.Fatalf("a DER holding BOTH halves scored %s, want PASS:\n%s", both.Verdict, both.Observed)
	}
	for _, want := range []string{"M705 Volt-Var", "M711 Frequency Droop", " AND "} {
		if !strings.Contains(both.Observed, want) {
			t.Errorf("the PASS does not carry both halves' evidence (missing %q):\n%s", want, both.Observed)
		}
	}
}

// TestOracleCurve_MeasurabilityAndDisclosureCannotComeApart pins the invariant
// that binds the oracle's decision to the bundle's record: an authored element
// is either MEASURED or DISCLOSED as unmeasurable, and never neither.
//
// It is tested against the two droop-arm shapes that broke it while the two
// decisions were made by two different predicates:
//
//   - the NEAREST-MODEL-PLUS-STATED-REFUSAL idiom the curve arms already use
//     (BASIC-012's own 7xx curve arm is Model7xx: 711 WITH NoRegisterHome7xx
//     set). A model IS named, so a predicate asking "is a model named?" called
//     it measurable and dropped it from the unmappable clause, while the oracle,
//     asking "did the resolved arm state an absence?", skipped it. Neither
//     compared nor disclosed: a PASS covering content nothing looked at.
//   - a row DECLARING NOTHING for the generation it is run on. That used to
//     resolve to {Model: 0, no stated absence}, which reads as measurable, so
//     the oracle asked the DER for SunSpec model 0 and reported "carries
//     NOTHING for it" about a model that does not exist — beside a clause
//     saying nothing was asserted.
//
// Both run through the SHIPPING oracle against a real DER, so a predicate that
// drifts apart again fails here rather than in a bundle.
func TestOracleCurve_MeasurabilityAndDisclosureCannotComeApart(t *testing.T) {
	settings := FreqDroopSettings{DBOF: 60030, DBUF: 59970, KOF: 40, KUF: 40, OpenLoopTms: 600}
	for _, tc := range []struct {
		name  string
		droop *droopBinding
	}{
		{"a nearest-model arm that refuses to grade against it", &droopBinding{
			Settings:          settings,
			Model7xx:          sunspec.ModelDERFreqDroop,
			Mapping7xx:        "a synthetic binding, for this test only",
			NoRegisterHome7xx: "a synthetic binding: this arm names its nearest model and refuses it",
		}},
		{"an arm this row declares nothing for", &droopBinding{Settings: settings}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCurveFixture(t)
			b := &curveBinding{
				Mode:       "volt_var",
				Points:     []CurvePoint{{X: 9100, Y: 4000}, {X: 10600, Y: -4000}},
				XMult:      -2,
				YMult:      -2,
				YRefType:   derUnitRefStatVarAvail,
				Prescribed: "a synthetic binding, for this test only",
				Model7xx:   sunspec.ModelDERVoltVar,
				Mapping7xx: "a synthetic binding, for this test only",
				Droop:      tc.droop,
			}
			// Put the CURVE half in a state that passes on its own, so what
			// happens to the droop is the only thing left to decide the row.
			pts := make([]sunspec.VVPoint, 0, len(b.Points))
			for _, p := range b.wantPoints() {
				pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
			}
			deptRef, ok := b.wantDeptRef(sunspec.ModelDERVoltVar)
			if !ok {
				t.Fatal("the synthetic binding's yRefType has no DeptRef translation")
			}
			f.adoptVoltVar(t, deptRef, pts)

			got := oracleCurve(b)(context.Background(), f.rc)
			if b.Droop.hasHome(invariant.Family7xx) {
				t.Fatal("this fixture's droop arm reports a register home, so it does not exercise the " +
					"unmeasurable path it was written for")
			}
			// Not measured — so it MUST be disclosed, by name.
			if !strings.Contains(got.Observed, "AUTHORED BUT NOT DEVICE-MAPPABLE") ||
				!strings.Contains(got.Observed, droopElement) {
				t.Errorf("the droop was neither measured nor disclosed — a verdict covering an element "+
					"nothing looked at:\n%s", got.Observed)
			}
			// And nothing may claim to have READ a bank for it.
			if strings.Contains(got.Observed, "live control holds exactly the droop parameters") {
				t.Errorf("the verdict reports a droop measurement the oracle declined to make:\n%s",
					got.Observed)
			}
			if strings.Contains(got.Observed, "M0 ") || strings.Contains(got.Observed, "model 0") {
				t.Errorf("the verdict describes SunSpec model 0, which does not exist:\n%s", got.Observed)
			}
		})
	}
}

// TestCurveComposition_ClaimAndVerdictNameOnlyWhatWasMeasured is the same
// invariant ONE LEVEL UP, where it was still being broken after the oracle
// itself was fixed.
//
// The oracle's own Finding said the right thing about BASIC-012 on a 7xx DER —
// "the curve half is served and NOT asserted here" — and then three sentences
// composed on top of it said the opposite:
//
//   - the row-level outcome (curveOutcome) built its PASS from
//     curvePublishedParam, so it read "the adopted curve MOVED to 4
//     breakpoint(s) (5900, 100) ...", breakpoints nothing had compared;
//   - the criterion's Claim said the DER holds "the curve ... carried, adopted
//     and enabled";
//   - its How described a point-for-point comparison of a LIVE curve's
//     breakpoints — against M711, which declares NPt=0 and stores no points at
//     all.
//
// A bundle reader sees those three, not the oracle's internal string. So the
// composition is driven here, through the SHIPPING row, on a DER where the
// droop lands and the breakpoints have nowhere to land.
func TestCurveComposition_ClaimAndVerdictNameOnlyWhatWasMeasured(t *testing.T) {
	f := newCurveFixture(t)
	d, _ := f.withGridSimServer(t)
	row := rowByID(t, "BASIC-012")
	b := row.mode.Curve
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-012")

	ctx := context.Background()
	params := map[string]string{pollWindowParam: "20ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("BASIC-012 Setup: %v", err)
	}
	// Stand in for a DUT that executed the half this generation can hold: the
	// real derbase writer, the row's own translated values.
	live, err := f.base.ReadFreqDroop("composition-test")
	if err != nil {
		t.Fatalf("read the DER's droop: %v", err)
	}
	want := b.Droop.want711()
	if err := f.base.WriteFreqDroop(sunspec.FreqDroopCtl{
		DbOf: want.DbOfHz, DbUf: want.DbUfHz, KOf: want.KOf, KUf: want.KUf, RspTms: want.RspTmsS,
		PMin: live.PMin,
	}, "composition-test"); err != nil {
		t.Fatalf("the real derbase writer refused the row's droop: %v", err)
	}
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("BASIC-012 PostWait: %v", err)
	}
	obs := &Observation{Params: params}

	out := curveOutcome(b, obs)
	if out.Verdict != certify.Pass {
		t.Fatalf("the composed outcome on a DER holding this row's droop = %s:\n%s",
			out.Verdict, out.Observed)
	}
	crit := critDEREffectViaCurveOracle(row.subject, b, obs)

	// The three composed sentences must each name the DROOP and must not claim
	// the breakpoints.
	for _, tc := range []struct{ what, text string }{
		{"the row-level verdict", out.Observed},
		{"the criterion's Claim", crit.Claim},
		{"the criterion's How", crit.How},
	} {
		if !strings.Contains(strings.ToLower(tc.text), "droop") {
			t.Errorf("%s does not name the droop, which is the only half this DER could hold:\n%s",
				tc.what, tc.text)
		}
		for _, forbidden := range []string{
			"the adopted curve MOVED",
			"hold the curve ",
			"compared point for point",
		} {
			if strings.Contains(tc.text, forbidden) {
				t.Errorf("%s claims %q, about breakpoints this run never compared (M711 stores none):\n%s",
					tc.what, forbidden, tc.text)
			}
		}
	}
	// And each must DISCLOSE the half it did not assert — measured or
	// disclosed, never neither, at every level a reader reads.
	for _, tc := range []struct{ what, text string }{
		{"the row-level verdict", out.Observed},
		{"the criterion's Claim", crit.Claim},
	} {
		if !strings.Contains(tc.text, "NOTHING about") && !strings.Contains(tc.text, "NOT asserted") {
			t.Errorf("%s does not disclose the frequency-watt breakpoints it left unasserted:\n%s",
				tc.what, tc.text)
		}
	}
	t.Logf("BASIC-012 on 7xx, composed:\n  verdict: %s\n  claim:   %s\n  how:     %s",
		out.Observed, crit.Claim, crit.How)
}

// TestRefusalFingerprint_SeesADroopWriteOnARefusedRow closes M5: a refusal row
// whose control carries an opModFreqDroop must be watching model 711.
//
// publishCurveControl sends the droop UNCONDITIONALLY — a refusal row publishes
// through the same publisher as an execution row, deliberately, so that the two
// controls are identical in kind — while the refusal fingerprint watched the
// CURVE bank alone. A DUT that answered cannot-comply and then wrote the droop
// into 711 would have moved no register the row was looking at, and the row
// would have certified a clean refusal over a real write.
//
// No catalog row is in that shape today (the refusal rows author no droop),
// which is the reason to close it now: the failure mode is silent, one binding
// edit away, and the row would look green while it happened.
func TestRefusalFingerprint_SeesADroopWriteOnARefusedRow(t *testing.T) {
	f := newCurveFixture(t)
	rb := &refusalBinding{
		Axis:      "the SunSpec model 712 (DER Watt-Var) curve bank",
		Why:       "a synthetic binding, for this test only",
		Commanded: "a synthetic watt-pf curve carrying an inline droop",
		Curve: &curveBinding{
			Mode:       "watt_pf",
			Points:     []CurvePoint{{X: 0, Y: 100}, {X: 100, Y: 95}},
			YRefType:   derUnitRefStatVarAvail,
			Model7xx:   sunspec.ModelDERWattVar,
			Mapping7xx: "a synthetic binding, for this test only",
			Prescribed: "a synthetic binding, for this test only",
			Droop: &droopBinding{
				Settings:             FreqDroopSettings{DBOF: 60030, DBUF: 59970, KOF: 40, KUF: 40, OpenLoopTms: 600},
				Model7xx:             sunspec.ModelDERFreqDroop,
				Mapping7xx:           "a synthetic binding, for this test only",
				NoRegisterHomeLegacy: "a synthetic binding, for this test only",
			},
		},
	}
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER: %v", err)
	}
	before, ok := rb.fingerprint(uv)
	if !ok {
		t.Fatal("the refusal fingerprint could not be taken at all")
	}
	if !strings.Contains(before, "M711") {
		t.Fatalf("the fingerprint of a row whose control carries an opModFreqDroop does not include the "+
			"droop bank, so a write there would be invisible to it:\n%s", before)
	}

	// A gateway that says cannot-comply and writes the droop anyway.
	live, err := f.base.ReadFreqDroop("refusal-fingerprint-test")
	if err != nil {
		t.Fatalf("read the DER's droop: %v", err)
	}
	want := rb.Curve.Droop.want711()
	if err := f.base.WriteFreqDroop(sunspec.FreqDroopCtl{
		DbOf: want.DbOfHz, DbUf: want.DbUfHz, KOf: want.KOf, KUf: want.KUf, RspTms: want.RspTmsS,
		PMin: live.PMin,
	}, "refusal-fingerprint-test"); err != nil {
		t.Fatalf("the real derbase writer refused the droop: %v", err)
	}

	uv2, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("re-read the DER: %v", err)
	}
	after, ok := rb.fingerprint(uv2)
	if !ok {
		t.Fatal("the refusal fingerprint could not be re-taken")
	}
	if after == before {
		t.Errorf("the fingerprint did not MOVE after a real WriteFreqDroop landed on M711, so this row "+
			"would report 'no southbound trace' over a write it published:\n%s", after)
	}
}

// TestOracleCurve_DroopResolvesOnTheArmsFamilyNotTheDevicesGeneration pins the
// second of 077e046's unpinned fixes.
//
// resolveTarget has a named-model FALLBACK: when the DER's generation is
// unrecognised, or when a row declares no arm for the generation it is running
// on, the breakpoint half resolves against whichever named model the device
// actually serves — and that model's FAMILY can differ from the generation
// curveGenerationOf reports. Resolving the droop from the generation instead of
// from that family lets ONE verdict adjudicate its two halves on two different
// generations.
//
// The binding below is synthetic and built precisely to separate the two
// answers: it declares no 7xx arm at all and a LEGACY arm naming model 704 — a
// model this 7xx device really does serve, so the fallback selects it and
// target.Family comes out legacy while the device's generation is 7xx. Its
// droop has a 711 home and a stated legacy absence, so the two resolutions give
// opposite results: from the arm's family the droop is unmeasurable and must be
// DISCLOSED; from the device's generation it would be measured against 711.
func TestOracleCurve_DroopResolvesOnTheArmsFamilyNotTheDevicesGeneration(t *testing.T) {
	f := newCurveFixture(t)
	b := &curveBinding{
		Mode:       "volt_var",
		Points:     []CurvePoint{{X: 9100, Y: 4000}},
		YRefType:   derUnitRefStatVarAvail,
		Prescribed: "a synthetic binding, for this test only",
		// No 7xx arm; a legacy arm naming a model this 7xx device serves.
		ModelLegacy:   sunspec.ModelDERCtlAC,
		MappingLegacy: "a synthetic binding, for this test only",
		Droop: &droopBinding{
			Settings:             FreqDroopSettings{DBOF: 60030, DBUF: 59970, KOF: 40, KUF: 40, OpenLoopTms: 600},
			Model7xx:             sunspec.ModelDERFreqDroop,
			Mapping7xx:           "a synthetic binding, for this test only",
			NoRegisterHomeLegacy: "a synthetic binding: no legacy home for a droop",
		},
	}
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER: %v", err)
	}
	// The premise: the two answers really do differ on this fixture.
	target, how := b.resolveTarget(uv)
	if how != curveResolved {
		t.Fatalf("the synthetic binding resolved no target (%v), so this test proves nothing", how)
	}
	if target.Family != invariant.FamilyLegacy || curveGenerationOf(uv) != gen7xx {
		t.Fatalf("this fixture no longer separates the arm's family (%s) from the device's generation "+
			"(%s); the test needs rebuilding to keep pinning the distinction",
			target.Family, curveGenerationOf(uv))
	}

	// The droop is INSTALLED on 711 first, through the real writer. That is what
	// makes this test discriminating rather than merely descriptive: with the
	// droop landed, a run that resolved it from the device's GENERATION would
	// find it and report a measurement, while one resolving from the arm's
	// family must go on disclosing it as unmappable. Against an unwritten 711
	// both paths produce a non-PASS and the distinction is invisible.
	live, err := f.base.ReadFreqDroop("family-resolution-test")
	if err != nil {
		t.Fatalf("read the DER's droop: %v", err)
	}
	want := b.Droop.want711()
	if err := f.base.WriteFreqDroop(sunspec.FreqDroopCtl{
		DbOf: want.DbOfHz, DbUf: want.DbUfHz, KOf: want.KOf, KUf: want.KUf, RspTms: want.RspTmsS,
		PMin: live.PMin,
	}, "family-resolution-test"); err != nil {
		t.Fatalf("the real derbase writer refused the droop: %v", err)
	}

	got := oracleCurve(b)(context.Background(), f.rc)
	// From the ARM's family the droop has no home: disclosed, never measured.
	if !strings.Contains(got.Observed, "AUTHORED BUT NOT DEVICE-MAPPABLE") ||
		!strings.Contains(got.Observed, droopElement) {
		t.Errorf("the droop was resolved on the device's GENERATION rather than the arm's family — it "+
			"should have been disclosed as unmappable here:\n%s", got.Observed)
	}
	if strings.Contains(got.Observed, "live control holds exactly the droop parameters") {
		t.Errorf("the verdict reports a droop MEASUREMENT against a generation its breakpoint half did "+
			"not resolve to — one verdict adjudicating its two halves on two different generations:\n%s",
			got.Observed)
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
	// The published-curve rendering is taken from the ROW, not restated: this
	// file's literals drifted out of step with register.go once already, when
	// the row was reconciled to CSIP CTP v1.3 Figure 6.
	for _, want := range []string{"never COMPLETED", "M705 Volt-Var", basic006Binding().describePublished()} {
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
	// The TIMING is part of this PASS now: 705 declares Crv.RspTms and the row
	// authors Figure 6's openLoopTms, so a green verdict that did not say the
	// timing matched would understate what was compared.
	if !strings.Contains(got.Observed, "open-loop response time it published") {
		t.Errorf("the PASS does not state that the open-loop response time was compared, though 705 "+
			"declares the register and this row authors the element: %s", got.Observed)
	}
	// The verbatim reason is the deliverable, on the green side as on the red.
	t.Logf("BASIC-006 GREEN on 7xx (breakpoints AND openLoopTms):\n  %s", got.Observed)
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
	// BOTH curves must appear: the device's, and the row's own — the latter
	// rendered by the row rather than restated here.
	if !strings.Contains(got.Observed, "(230, 30)") ||
		!strings.Contains(got.Observed, basic006Binding().describePublished()) {
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
	// The points are the ROW's own, taken from its binding: the whole content of
	// this case is "right points, wrong reference", and a stale literal here
	// would make the content check fire first and test something else entirely.
	pts := make([]sunspec.VVPoint, 0, len(basic006Binding().Points))
	for _, p := range basic006Binding().wantPoints() {
		pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
	}
	f.adoptVoltVar(t, want+1, pts) // any OTHER reference
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
		Model7xx: 707, YRefType: 3, Mapping7xx: "a mapping onto a model this device does not serve",
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
	b := &curveBinding{
		Mode: "freq_watt", Points: []CurvePoint{{X: 6000, Y: 100}, {X: 6050, Y: 0}}, XMult: -2, YRefType: 1,
		Model7xx: sunspec.ModelDERFreqDroop, NoRegisterHome7xx: noFreqWattRegister,
		ModelLegacy: sunspec.ModelFreqWattLegacy, MappingLegacy: mappingFreqWattLegacy,
	}
	got := oracleCurve(b)(context.Background(), f.rc)
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
	moved := curveOutcome(basic006Binding(), curveObs(map[string]string{
		oraclePreVerdictParam:  string(certify.Fail),
		oraclePreObservedParam: "the DER held its factory curve",
		oracleVerdictParam:     string(certify.Pass),
		oracleObservedParam:    "the DER holds the published curve",
		curvePublishedParam:    "4 breakpoints",
	}))
	if moved.Verdict != certify.Pass {
		t.Fatalf("a curve that moved from absent to present = %s (%s), want PASS", moved.Verdict, moved.Observed)
	}

	stale := curveOutcome(basic006Binding(), curveObs(map[string]string{
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
	f := curveOutcome(basic006Binding(), curveObs(map[string]string{
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
	if f := curveOutcome(basic006Binding(), curveObs(map[string]string{})); f.Verdict != certify.Fail {
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
	got := oracleRefusal(basic014Binding(), baseline, refusalLedgerFence{})(context.Background(), f.rc)
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

	got := oracleRefusal(basic014Binding(), baseline, refusalLedgerFence{})(context.Background(), f.rc)
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
	got := oracleRefusal(basic014Binding(), "", refusalLedgerFence{})(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("a refusal judged with no baseline = %s (%s), want FAIL", got.Verdict, got.Observed)
	}
}

// TestOracleRefusal_UnreachableDERIsUnavailableNotAPass: "we could not look"
// must never read as "nothing was there".
func TestOracleRefusal_UnreachableDERIsUnavailableNotAPass(t *testing.T) {
	rc := &certify.RunCtx{Case: &certify.Case{UID: "test::refusal"}, Sims: map[string]*certify.SimClient{}}
	got := oracleRefusal(basic014Binding(), "WSet=0 W disabled(WSetMod=0)", refusalLedgerFence{})(context.Background(), rc)
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
// whose axis it cannot execute, against the SD-02 corrected table
// (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw): the
// standard answer to a structurally unsupported control is 252 at receipt,
// before any write; 8/10 (Table 27's EffectiveEndTime-only partials) and 4/5
// (lifecycle acknowledgements of an ADOPTED control) are all now forbidden
// here, not accepted.
func TestCritRefusalAnswered_HasTeeth(t *testing.T) {
	const row = "CERT-BASIC-014"

	// The honest, standard-mode refusal: received, then the receipt-time
	// rejection Table 27 actually defines for this shape.
	wantVerdict(t, "received + rejected(252)", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row), responseExchange(252, row)), certify.Pass)

	// THE SEEDED NEGATIVE SD-02 REQUIRES: a DUT that posts the FORMER product
	// behavior — 8 (PartialOptOut) at receipt — must now be REJECTED by the
	// corrected oracle. This is a permanent oracle-bite test: if this ever
	// passes again, the oracle has regressed to the pre-SD-02 defect
	// (curve.go's refusalStatuses used to accept {8, 0xF0} unconditionally).
	f := wantVerdict(t, "SEEDED NEGATIVE: 8 at receipt (former product defect)", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row), responseExchange(8, row)), certify.Fail)
	if !strings.Contains(f.Observed, "PartialOptOut") {
		t.Errorf("the FAIL does not name the forbidden status: %s", f.Observed)
	}

	// The LEXA legacy 0xF0 wire is accepted ONLY when this row's own
	// case/DUT configuration declares legacy mode.
	f = wantVerdict(t, "received + LEXA 0xF0, legacy declared", critRefusalAnswered(row, true),
		synthTranscript(responseExchange(1, row), responseExchange(0xF0, row)), certify.Pass)
	if !strings.Contains(f.Observed, "LEGACY WIRE MODE") || !strings.Contains(f.Observed, "NOT conformance evidence") {
		t.Errorf("a legacy-mode 0xF0 PASS must be stamped non-conformance-evidence: %s", f.Observed)
	}

	// The SAME 0xF0 wire, with no legacy declaration on this row, is not an
	// honest answer — 0xF0 occupies Table 27's RESERVED range and is not the
	// standard 252 this row's control demands.
	wantVerdict(t, "received + LEXA 0xF0, legacy NOT declared", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row), responseExchange(0xF0, row)), certify.Fail)

	// THE defect: an execution signal for an axis nothing executed. This is
	// LXR-002 verbatim, and it must fail even when the refusal was also sent —
	// a DUT that says both has still told the head end the control ran.
	f = wantVerdict(t, "started for a refused axis", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row), responseExchange(2, row)), certify.Fail)
	if !strings.Contains(f.Observed, "Event started") {
		t.Errorf("the FAIL does not name the forbidden status: %s", f.Observed)
	}
	wantVerdict(t, "started AND rejected", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(252, row), responseExchange(2, row)), certify.Fail)
	wantVerdict(t, "completed for a refused axis", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(3, row)), certify.Fail)

	// 4/5 (OptOut/OptIn) are lifecycle acknowledgements of an ADOPTED
	// control's preference-driven curtailment — this row's control was
	// refused outright, never adopted, so neither is an honest answer.
	f = wantVerdict(t, "OptOut(4) for a refused axis", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row), responseExchange(4, row)), certify.Fail)
	if !strings.Contains(f.Observed, "OptOut") {
		t.Errorf("the FAIL does not name the forbidden status: %s", f.Observed)
	}
	wantVerdict(t, "OptIn(5) for a refused axis", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row), responseExchange(5, row)), certify.Fail)

	// 10 (NoParticipation) is Table 27's OTHER EffectiveEndTime-only partial
	// for an ADMITTED event — the same defect shape as 8, forbidden the same
	// way.
	wantVerdict(t, "NoParticipation(10) for a refused axis", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row), responseExchange(10, row)), certify.Fail)

	// An acknowledgement alone is not a refusal: the head end is left believing
	// the control was accepted.
	wantVerdict(t, "received only", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(1, row)), certify.Fail)

	// Another control's refusal says nothing about this row.
	wantUnavailable(t, "another control's refusal", critRefusalAnswered(row, false),
		synthTranscript(responseExchange(252, "SOMEBODY-ELSE")))
}

// TestCritRefusalAnswered_ServerTierAgrees: the tier-3 fallback must reach the
// same decisions, or a run whose capture could not be decrypted would grade the
// same DUT differently.
func TestCritRefusalAnswered_ServerTierAgrees(t *testing.T) {
	const row = "CERT-BASIC-014"
	c := critRefusalAnswered(row, false)
	ok := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: row, Status: 1}, {Subject: row, Status: 252}}}
	if f := c.Server(ok); f.Verdict != certify.Pass {
		t.Errorf("server-side honest refusal(252) = %s: %s", f.Verdict, f.Observed)
	}
	// SEEDED NEGATIVE, tier-3 mirror of the wire-tier one above: the former
	// product's onset-8 answer must FAIL server-side too.
	formerDefect := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: row, Status: 1}, {Subject: row, Status: 8}}}
	if f := c.Server(formerDefect); f.Verdict != certify.Fail {
		t.Errorf("server-side SEEDED NEGATIVE 8-at-receipt = %s, want FAIL: %s", f.Verdict, f.Observed)
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
	// Legacy 0xF0: FAIL without the row's legacy declaration, PASS (as
	// non-conformance evidence) with it.
	legacyWire := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: row, Status: 1}, {Subject: row, Status: 0xF0}}}
	if f := c.Server(legacyWire); f.Verdict != certify.Fail {
		t.Errorf("server-side 0xF0 with no legacy declaration = %s, want FAIL: %s", f.Verdict, f.Observed)
	}
	cLegacy := critRefusalAnswered(row, true)
	if f := cLegacy.Server(legacyWire); f.Verdict != certify.Pass || !strings.Contains(f.Observed, "LEGACY WIRE MODE") {
		t.Errorf("server-side 0xF0 WITH legacy declaration = %s: %s, want PASS stamped non-conformance-evidence",
			f.Verdict, f.Observed)
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
	d, _ := f.withGridSimServer(t)
	return d
}

// withGridSimServer is withGridSim keeping the SERVER as well, so a test can
// fetch what a row actually SERVED rather than only what it believes it sent.
//
// The distinction is the whole of curve plan #32's construction risk: a binding
// can name an element the publisher drops, or that the server stores and never
// serves, and every one of those reads from inside the harness as a row that
// authored it. Only the served document settles it.
func (f *curveFixture) withGridSimServer(t *testing.T) (*Driver, *gridsim.Server) {
	t.Helper()
	gs := gridsim.NewServer(benchLFDI)
	gsSrv := httptest.NewServer(gs.AdminHandler())
	t.Cleanup(gsSrv.Close)
	f.rc.GridSim = certify.NewAdminClient(gsSrv.URL, http.DefaultClient)
	f.rc.Targets = certify.Targets{GridSimAdmin: gsSrv.URL}
	return NewDriver(f.rc), gs
}

// servedByGridSim fetches a resource from the simulator's own data plane as
// text — the document a DUT would receive.
func servedByGridSim(t *testing.T, gs *gridsim.Server, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	gs.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s from gridsim = %d; body: %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// TestCurveRows_ServeTheFigureElementsTheirBindingsAuthor closes the loop
// between the binding and the wire for the two elements curve plan #32 built
// levers for.
//
// Both rows used to HOLD THEMSELVES AT FAIL over these elements — BASIC-006 on
// openLoopTms, BASIC-012 on all five opModFreqDroop children — because the
// bench could not send them. With the levers built that hold is gone, and the
// only thing left between the row and an overclaim is that the element really
// does reach the DUT. So the SHIPPING rows are driven through their own Setup
// against a real gridsim, and the assertions are made on the document the
// server serves back.
//
// A row that quietly stopped authoring one of these would pass every other test
// in this package: it still publishes a valid curve, its oracle still measures,
// its construction claim still reads well. This is the test that would fail.
func TestCurveRows_ServeTheFigureElementsTheirBindingsAuthor(t *testing.T) {
	t.Run("BASIC-006 serves Figure 6's openLoopTms", func(t *testing.T) {
		f := newCurveFixture(t)
		d, gs := f.withGridSimServer(t)
		row := rowByID(t, "BASIC-006")
		s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-006")
		if err := s.Setup(context.Background(), d, map[string]string{pollWindowParam: "20ms"}); err != nil {
			t.Fatalf("BASIC-006 Setup: %v", err)
		}
		raw := servedByGridSim(t, gs, "/derp/0/dc/0")
		if !strings.Contains(raw, "<openLoopTms>5</openLoopTms>") {
			t.Errorf("the DERCurve BASIC-006 published carries no openLoopTms=5; Figure 6 prescribes 5 "+
				"against its own default of 10, so a DUT receiving no element was offered the DEFAULT "+
				"condition and the row would be reporting a run it did not make:\n%s", raw)
		}
		// Figure 6's OTHER two scalars, authored since 2026-08-15 (IW15-027).
		// They were two declared GAPS until then, on the grounds that the
		// elements do not exist — a citation into docs/schema/sep-2.0.4.xsd,
		// which is the pre-publication ZigBee draft. IEEE Std 2030.5-2018
		// declares autonomousVRefEnable at p.252 and
		// autonomousVRefTimeConstant at p.253, both [0..1] on DERCurve, and
		// this row's own Figure prints Test Values false and 0 for them.
		//
		// Asserted on the BYTES, not on a decoded struct: `false` and `0` are
		// exactly the values a marshaller with an errant omitempty deletes, and
		// a round-trip through Go cannot tell an absent element from a present
		// zero. That is the same defect class as the mandatory-element sweep
		// this wave's proto change is about, so the assertion has to be made
		// where it can see it.
		for _, want := range []string{
			"<autonomousVRefEnable>false</autonomousVRefEnable>",
			"<autonomousVRefTimeConstant>0</autonomousVRefTimeConstant>",
		} {
			if !strings.Contains(raw, want) {
				t.Errorf("the DERCurve BASIC-006 published does not carry %s; Figure 6 prescribes it and "+
					"gridsim has had a lever for it since IW15-027, so an omission here is the row "+
					"quietly publishing less than its procedure again:\n%s", want, raw)
			}
		}
		// And the sequence: DERCurve is an xs:sequence, so the two new elements
		// have to arrive in their alphabetical slots (2018 p.252-253) ahead of
		// creationTime, or every document this row publishes is one a validating
		// peer rejects with every element in it legal.
		if i, j := strings.Index(raw, "<autonomousVRefTimeConstant>"),
			strings.Index(raw, "<creationTime>"); i < 0 || j < 0 || i > j {
			t.Errorf("the published DERCurve has autonomousVRefTimeConstant at %d and creationTime at "+
				"%d; the 2018 sequence puts the autonomous-Vref pair first:\n%s", i, j, raw)
		}
	})

	t.Run("BASIC-012 serves Figure 12's opModFreqDroop", func(t *testing.T) {
		f := newCurveFixture(t)
		d, gs := f.withGridSimServer(t)
		row := rowByID(t, "BASIC-012")
		s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-012")
		if err := s.Setup(context.Background(), d, map[string]string{pollWindowParam: "20ms"}); err != nil {
			t.Fatalf("BASIC-012 Setup: %v", err)
		}
		raw := servedByGridSim(t, gs, "/derp/0/derc")
		for _, want := range []string{
			"<dBOF>60030</dBOF>", "<dBUF>59970</dBUF>", "<kOF>40</kOF>", "<kUF>40</kUF>",
			"<openLoopTms>600</openLoopTms>",
		} {
			if !strings.Contains(raw, want) {
				t.Errorf("the control BASIC-012 published does not carry %s:\n%s", want, raw)
			}
		}
		// On ONE control, beside the curve link, which is what Figure 12
		// prescribes ("Frequency-Watt -> opModFreqWatt (Curve); Frequency-Droop
		// -> opModFreqDroop (Immediate)") and what makes the pair testable at
		// all: two controls would be two events, and the DUT's arbitration
		// between them would become part of what this row measured.
		if !strings.Contains(raw, "opModFreqWatt") {
			t.Errorf("the droop did not ride the same control as the curve link:\n%s", raw)
		}
	})
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
	if f := curveOutcome(rowByID(t, "BASIC-006").mode.Curve, obs); f.Verdict != certify.Pass {
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
	if row.mode.Refusal.Curve == nil || row.mode.Refusal.Curve.Model7xx != sunspec.ModelDERWattVar {
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
		Points: []sunspec.WVPoint{{W: 0, Var: 100}, {W: 50, Var: 98}, {W: 100, Var: 95}},
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
		Points: []sunspec.WVPoint{{W: 0, Var: 100}, {W: 50, Var: 98}, {W: 100, Var: 95}},
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
		Points: []sunspec.WVPoint{{W: 0, Var: 100}, {W: 50, Var: 98}, {W: 100, Var: 95}},
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
	views, _, ok := coveredCurveSlots(uv, b.Curve.Model7xx)
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
	// "curve slot(s)", not "staging curve(s)": the wording is generation-neutral
	// because the bound applies to both idioms and only one of them has staging
	// slots at all. On legacy every bank 1..NCrv is a covered slot.
	if !strings.Contains(fp, "further curve slot(s) not fingerprinted") {
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
	cb := &refusalBinding{Axis: "M712", Curve: &curveBinding{Mode: "watt_pf",
		Model7xx: sunspec.ModelDERWattVar}}
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

// unmappableClause returns just the "AUTHORED BUT NOT DEVICE-MAPPABLE:" part of
// a curve verdict, or "" when the verdict carries none.
//
// It exists because that clause lists ELEMENTS, and a test about one element
// must not be satisfied (or tripped) by another element's entry. Substring
// checks over a whole verdict were precise while the clause could only ever
// hold one member; BASIC-006 now authors three elements of which two belong
// there and one must not.
func unmappableClause(observed string) string {
	const marker = "AUTHORED BUT NOT DEVICE-MAPPABLE"
	i := strings.Index(observed, marker)
	if i < 0 {
		return ""
	}
	return observed[i:]
}

// ── DERCurve.vRef, end to end ───────────────────────────────────────────────

// vrefBinding is BASIC-006's volt-var binding with a vRef hung on it: 9500
// (95.00 %) over breakpoints at 9200 and 10800, so
// 9200 x 9500/10000 = 8740 and 10800 x 9500/10000 = 10260.
//
// THE REVIEW'S OWN SHAPE WAS vRef 10500, AND IT IS NOT A CONFORMANT VALUE.
// lexa-gw's review of the downstream wave proposed "a volt-var DERCurve with
// vRef=10500 and breakpoints at 9200/10800 ... the intended 96.6 %/113.4 %".
// vRef is a PerCent (2018 p.253), and 2018 p.167 states that type's domain in
// its own sentence: "Used for percentages, specified in hundredths of a percent,
// 0 to 10 000. (10 000 = 100%)". 10500 is 105 %, outside it — so a server
// sending it is sending a value the type does not admit, and this bench refuses
// to serve one (sim/gridsim/curve.go's vrefFamily, which is what caught it: the
// first draft of this test used 10500 and got a 400 quoting p.167 back).
//
// The arithmetic the review was demonstrating is unaffected and is exactly what
// is asserted below; only the number moves into the domain the standard states.
// That vRef can therefore only ever SHRINK the x axis is a property of the type,
// not of this fixture.
func vrefBinding() *curveBinding {
	b := *basic006Binding() // copy: the shipping row must not gain a vRef
	v := uint16(9500)
	b.VRef = &v
	b.Points = []CurvePoint{{X: 9200, Y: 3000}, {X: 10800, Y: -3000}}
	return &b
}

// TestVRef_OutsidePerCentsDomainIsRefusedByTheBench pins what caught the
// review's shape, so the bound is a checked rule rather than a lucky 400.
//
// A conformance bench must not put a value on the wire that the element's own
// type does not admit — the evidence would be about a document no conformant
// server produces. Note that this is a bound the BENCH enforces: lexa-gw's
// ingest applies whatever vRef arrives (its only guard is int32 overflow), so
// the product would scale by 6.5x for a vRef of 65535 rather than refuse it.
// That is a finding about the product, relayed rather than acted on here.
func TestVRef_OutsidePerCentsDomainIsRefusedByTheBench(t *testing.T) {
	f := newCurveFixture(t)
	d, _ := f.withGridSimServer(t)
	b := *vrefBinding()
	over := uint16(10500)
	b.VRef = &over
	err := publishCurveControl(context.Background(), d, map[string]string{}, &b, "CERT-VREF-OVER")
	if err == nil {
		t.Fatal("the bench published a vRef of 10500. IEEE Std 2030.5-2018 p.167 gives PerCent the " +
			"domain 0 to 10 000, so 105 % is not a value the element admits and serving it would put a " +
			"non-conformant document into evidence")
	}
	for _, want := range []string{"PerCent", "10000", "p.167"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not cite the domain (missing %q): %v", want, err)
		}
	}
}

// TestVRef_ScalesTheExpectedBreakpointsFromTheStandardsSentence is the
// arithmetic, asserted against numbers written out by hand.
//
// It exists separately from the device-level test below because the two can
// fail for different reasons and a reader has to be able to tell them apart:
// this one says "the oracle expects the wrong voltages", the next says "the
// device holds the wrong voltages".
func TestVRef_ScalesTheExpectedBreakpointsFromTheStandardsSentence(t *testing.T) {
	got := vrefBinding().wantPoints()
	// XMult is -2 on this row, so the raw 9660/11340 land at 96.60/113.40 %V.
	want := []invariant.CurvePoint{{X: 87.40, Y: 30.00}, {X: 102.60, Y: -30.00}}
	if len(got) != len(want) {
		t.Fatalf("wantPoints() returned %d points, want %d", len(got), len(want))
	}
	for i := range want {
		if math.Abs(got[i].X-want[i].X) > 0.001 || math.Abs(got[i].Y-want[i].Y) > 0.001 {
			t.Errorf("breakpoint %d = %s, want %s. IEEE Std 2030.5-2018 p.250: \"If VRef is present in "+
				"DERCurve, then the x value of each pair is additionally multiplied by VRef/10 000\" — "+
				"9200 x 9500/10000 = 8740 and 10800 x 9500/10000 = 10260, at 10^-2",
				i+1, got[i], want[i])
		}
	}
	// THE WRONG ANSWER, NAMED. A referee that ignored vRef would expect the
	// published 92.00/108.00, and a device that ignored it would hold them. The
	// two failures are indistinguishable from a green run, which is why the
	// unscaled values are asserted to be ABSENT rather than merely different.
	for _, wrong := range []float64{92.00, 108.00} {
		for _, p := range got {
			if math.Abs(p.X-wrong) < 0.001 {
				t.Errorf("wantPoints() still expects the UNSCALED x %.2f. That is the curve the head end "+
					"published, not the curve it commanded: with vRef present the device must hold the "+
					"multiplied values, and a referee expecting these would pass a DER that dropped the "+
					"element on the floor", wrong)
			}
		}
	}
	// And with no vRef the same row is unscaled — so the scaling is the
	// ELEMENT's effect and not something wantPoints does to every curve.
	plain := *vrefBinding()
	plain.VRef = nil
	for i, p := range plain.wantPoints() {
		if math.Abs(p.X-[]float64{92.00, 108.00}[i]) > 0.001 {
			t.Errorf("without a vRef, breakpoint %d = %s; the published x values must pass through "+
				"untouched", i+1, p)
		}
	}
}

// TestVRef_IsVerifiedAgainstTheDeviceAtTheSCALEDBreakpoints is the end-to-end
// half: a DER that adopted the curve at the multiplied voltages PASSES, and one
// that adopted it at the published voltages — the exact shape of a gateway that
// decoded vRef and ignored it — FAILS.
//
// The second half is the one that matters. Before lexa-gw 675ffdf the product
// decoded vRef into a field nothing read, so it would have written the unscaled
// curve and reported adopted; the read-back hash could not see it, because the
// hash carries the document's own points at both ends. This is the check that
// can.
func TestVRef_IsVerifiedAgainstTheDeviceAtTheSCALEDBreakpoints(t *testing.T) {
	b := vrefBinding()

	t.Run("a DER holding the scaled curve passes", func(t *testing.T) {
		f := newCurveFixture(t)
		pts := make([]sunspec.VVPoint, 0, len(b.Points))
		for _, p := range b.wantPoints() {
			pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
		}
		f.adoptVoltVar(t, basic006DeptRef(t), pts)
		got := oracleCurve(b)(context.Background(), f.rc)
		if got.Verdict != certify.Pass {
			t.Fatalf("a DER holding the vRef-scaled curve scored %s, want PASS:\n%s",
				got.Verdict, got.Observed)
		}
		// THE PASS MUST SAY WHICH CURVE IT MEANS. "holds exactly the
		// breakpoints this row published" is the sentence a device that
		// IGNORED vRef would also earn, so a PASS over a vRef-carrying row has
		// to name the adjustment or it is indistinguishable from the failure it
		// is meant to exclude. (The first version of the composing logic wrote
		// this phrase twice and the openLoopTms branch overwrote the vRef one,
		// which is exactly how a disclosure goes missing.)
		for _, want := range []string{"vRef-ADJUSTED", "9500", "p.250", "open-loop response time"} {
			if !strings.Contains(got.Observed, want) {
				t.Errorf("the vRef PASS omits %q, so it reads like a PASS over a device that ignored the "+
					"element:\n%s", want, got.Observed)
			}
		}
		t.Logf("vRef GREEN (device at 87.40/102.60 %%V), verbatim:\n  %s", got.Observed)
	})

	t.Run("a DER holding the unscaled curve fails", func(t *testing.T) {
		f := newCurveFixture(t)
		// The published breakpoints, NOT the scaled ones: a gateway that read
		// vRef and did nothing with it.
		var pts []sunspec.VVPoint
		for _, p := range b.Points {
			pts = append(pts, sunspec.VVPoint{
				V: applyMult(p.X, b.XMult), Var: applyMult(p.Y, b.YMult),
			})
		}
		f.adoptVoltVar(t, basic006DeptRef(t), pts)
		got := oracleCurve(b)(context.Background(), f.rc)
		if got.Verdict != certify.Fail {
			t.Fatalf("a DER that ignored vRef and held the PUBLISHED breakpoints scored %s, want FAIL. "+
				"IEEE Std 2030.5-2018 p.250 makes the element multiply the x axis, so this device is "+
				"regulating volt-var at 92/108 %%V where the head end commanded 87.4/102.6 — a 4.6 "+
				"percentage-point error in where the curve sits, reported as adopted:\n%s",
				got.Verdict, got.Observed)
		}
		// The finding must show BOTH curves, or a reader cannot see that the
		// difference is the reference and not the shape.
		for _, want := range []string{"87.4", "92"} {
			if !strings.Contains(got.Observed, want) {
				t.Errorf("the FAIL does not quote %q, so a reader cannot see the commanded curve beside "+
					"the held one:\n%s", want, got.Observed)
			}
		}
		t.Logf("vRef RED (device at the unscaled 92/108 %%V), verbatim:\n  %s", got.Observed)
	})
}

// TestVRef_IsServedOnTheWireByTheRowThatAuthorsIt closes the loop at the other
// end: the element the oracle assumes is on the wire actually is.
//
// An oracle that scaled its expectation while the bench served no vRef would
// fail every correct device, and nothing in the two tests above would notice —
// they both build their expectation from the same binding.
func TestVRef_IsServedOnTheWireByTheRowThatAuthorsIt(t *testing.T) {
	f := newCurveFixture(t)
	d, gs := f.withGridSimServer(t)
	params := map[string]string{pollWindowParam: "20ms"}
	if err := publishCurveControl(context.Background(), d, params, vrefBinding(), "CERT-VREF"); err != nil {
		t.Fatalf("publish the vRef-carrying curve: %v", err)
	}
	raw := servedByGridSim(t, gs, "/derp/0/dc/0")
	if !strings.Contains(raw, "<vRef>9500</vRef>") {
		t.Errorf("the published DERCurve carries no vRef, so the oracle would be scaling its "+
			"expectation against a document that never asked for it:\n%s", raw)
	}
	// The PUBLISHED breakpoints stay unscaled on the wire: the scaling is the
	// DEVICE's to apply, and a bench that pre-multiplied them would be sending a
	// different curve AND a vRef, scaling twice.
	if !strings.Contains(raw, "<xvalue>9200</xvalue>") {
		t.Errorf("the published breakpoints are not the row's own: this bench must send the curve and "+
			"the reference, not the product of the two:\n%s", raw)
	}
	if strings.Contains(raw, "<xvalue>8740</xvalue>") {
		t.Errorf("the bench pre-multiplied the breakpoints by vRef AND served the element, which "+
			"commands the scaling twice:\n%s", raw)
	}
}

// ── autonomousVRefEnable=true: ACCEPTED, executed without (2018 p.252) ──────

// autonomousBinding is BASIC-006's volt-var binding carrying the enable and its
// mandatory time constant — a CONFORMANT document commanding a capability this
// gateway does not have.
func autonomousBinding() *curveBinding {
	b := *basic006Binding()
	enable := true
	tms := uint32(300)
	b.AutonomousVRefEnable, b.AutonomousVRefTimeConstant = &enable, &tms
	return &b
}

// TestAutonomousVRef_EnabledIsExecutedNotRefused is the ORACLE FLIP, and the
// adjudication behind it is why this file keeps the old shape as teeth.
//
// This suite briefly expected a REFUSAL here — the product answered CannotComply
// to autonomousVRefEnable=true on the ground that it has no writer for model
// 705's VRefAutoEna/VRefAutoTms, and the oracle was built to that behaviour. The
// gw adjudication overturned it against the printed clause. IEEE Std
// 2030.5-2018 p.252, autonomousVRefEnable, fourth sentence:
//
//	"If a DER is able to support Volt-Var mode but is unable to support
//	 autonomous vRef adjustment, then the DER SHALL execute the curve without
//	 autonomous vRef adjustment."
//
// It is a SHALL, it is directly on point, and this product satisfies its
// antecedent exactly: able to support Volt-Var (the axis is admitted, executed
// on 705, advertised as bit 23), unable to support the adjustment. So the
// consequent is mandatory and CannotComply is the one answer the sentence
// forbids. Refusing was not the conservative reading — it was the
// non-conformant one.
//
// WHAT THE ORACLE ASSERTS NOW, and it is two things rather than one:
//
//	the curve EXECUTES, in full, at the (vRef-adjusted, where present)
//	breakpoints — the first half of the clause; and
//
//	the device is NOT ARMED (Crv.VRefAutoEna=0) — the second half, which the
//	point table is blind to and which is the whole reason CurveView reads the
//	register at all.
func TestAutonomousVRef_EnabledIsExecutedNotRefused(t *testing.T) {
	b := autonomousBinding()

	t.Run("executed without the adjustment passes", func(t *testing.T) {
		f := newCurveFixture(t)
		pts := make([]sunspec.VVPoint, 0, len(b.Points))
		for _, p := range b.wantPoints() {
			pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
		}
		f.adoptVoltVar(t, basic006DeptRef(t), pts)
		got := oracleCurve(b)(context.Background(), f.rc)
		if got.Verdict != certify.Pass {
			t.Fatalf("a DER that executed the curve WITHOUT arming the adjustment scored %s. That is "+
				"exactly what IEEE Std 2030.5-2018 p.252 requires of a DER unable to support autonomous "+
				"vRef adjustment, so it is the conformant outcome and must pass:\n%s",
				got.Verdict, got.Observed)
		}
		// The register must be QUOTED even though it is unset: an absence that
		// is the conformant outcome has to be visible to count as evidence, and
		// a verdict that showed it only when armed would leave a reader unable
		// to tell "not armed" from "not read".
		if !strings.Contains(got.Observed, "VRefAutoEna=false") {
			t.Errorf("the PASS does not quote the arming register, so the second half of the clause is "+
				"asserted invisibly:\n%s", got.Observed)
		}
		if !strings.Contains(got.Observed, "not armed") {
			t.Errorf("the PASS does not say the automation is unarmed in words:\n%s", got.Observed)
		}
		// THE DISCLOSURE MUST MOVE WITH THE CHECK. This element was disclosed
		// as having no southbound assertion while nothing read Crv.VRefAutoEna;
		// the register is read now and the read is load-bearing, so a verdict
		// still carrying "this referee asserts nothing about it southbound"
		// would contradict itself in one sentence — a check added without its
		// disclosure being moved, which is the failure mode the authored /
		// unmappable split exists to prevent.
		unmappable := unmappableClause(got.Observed)
		if strings.Contains(unmappable, "autonomousVRefEnable = true") {
			t.Errorf("the verdict discloses autonomousVRefEnable as NOT device-mappable while asserting "+
				"exactly that register. The unmappable clause reads:\n  %s", unmappable)
		}
		// Its partner IS still unassertable — nothing reads VRefAutoTms — and
		// that asymmetry is the point: one of the pair gained a check and the
		// other did not.
		if !strings.Contains(unmappable, "autonomousVRefTimeConstant") {
			t.Errorf("autonomousVRefTimeConstant is no longer disclosed as unassertable, but nothing "+
				"reads VRefAutoTms:\n%s", got.Observed)
		}
		t.Logf("autonomous-vRef GREEN (executed without the adjustment), verbatim:\n  %s", got.Observed)
	})

	t.Run("armed anyway fails", func(t *testing.T) {
		// The failure this check exists for: a gateway that set VRefAutoEna to
		// look obliging, leaving the DER tracking a reference nothing updates.
		// Its POINT TABLE is identical to the passing case above — which is
		// precisely why the points alone cannot grade this.
		f := newCurveFixture(t)
		pts := make([]sunspec.VVPoint, 0, len(b.Points))
		for _, p := range b.wantPoints() {
			pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
		}
		rspTms := 0.0
		if s, ok := basic006Binding().wantOpenLoopS(); ok {
			rspTms = s
		}
		if err := f.base.WriteVoltVar(sunspec.VoltVarCurve{
			DeptRef: basic006DeptRef(t), Pri: 1, Points: pts, RspTms: rspTms,
			VRefAutoEna: true, VRefAutoTms: 300,
		}, "autonomous-armed"); err != nil {
			t.Fatalf("derbase WriteVoltVar: %v", err)
		}
		got := oracleCurve(b)(context.Background(), f.rc)
		if got.Verdict != certify.Fail {
			t.Fatalf("a DER holding the right curve with its autonomous automation ARMED scored %s. The "+
				"curve is correct and the clause is still broken — 2018 p.252 requires executing "+
				"WITHOUT the adjustment, and the point table cannot tell these two devices apart:\n%s",
				got.Verdict, got.Observed)
		}
		for _, want := range []string{"ARMED", "VRefAutoEna", "p.252", "SHALL execute the curve without"} {
			if !strings.Contains(got.Observed, want) {
				t.Errorf("the armed FAIL omits %q:\n%s", want, got.Observed)
			}
		}
		t.Logf("autonomous-vRef RED (armed anyway), verbatim:\n  %s", got.Observed)
	})

	t.Run("an unrequested arming is not this row's business", func(t *testing.T) {
		// A row that never published the enable has no expectation about the
		// register: an armed device there is the DER's own configuration, and
		// grading it would make this referee an auditor of settings nobody
		// commanded.
		f := newCurveFixture(t)
		plain := basic006Binding()
		pts := make([]sunspec.VVPoint, 0, len(plain.Points))
		for _, p := range plain.wantPoints() {
			pts = append(pts, sunspec.VVPoint{V: p.X, Var: p.Y})
		}
		rspTms := 0.0
		if s, ok := plain.wantOpenLoopS(); ok {
			rspTms = s
		}
		if err := f.base.WriteVoltVar(sunspec.VoltVarCurve{
			DeptRef: basic006DeptRef(t), Pri: 1, Points: pts, RspTms: rspTms, VRefAutoEna: true,
		}, "autonomous-unrequested"); err != nil {
			t.Fatalf("derbase WriteVoltVar: %v", err)
		}
		if got := oracleCurve(plain)(context.Background(), f.rc); got.Verdict != certify.Pass {
			t.Fatalf("a row that never requested the adjustment graded %s on a device that armed it "+
				"anyway:\n%s", got.Verdict, got.Observed)
		}
	})
}

// TestAutonomousVRef_TheRefusalShapeIsPreservedAsTeeth keeps the behaviour this
// oracle was built to expect BEFORE the adjudication, on the generations rule
// the modes and MUP oracles follow.
//
// The refusal was wrong, and recording that it was possible is what stops the
// correction from being a thing everyone remembers and nothing checks. Two
// distinct claims are preserved:
//
//	the refusal shape the product used to answer (a CannotComply at receipt for
//	a CONFORMANT document) is now an ORACLE FAILURE, not an expectation; and
//
//	the shape that is STILL refused — enable=true with no time constant — is a
//	different verdict about a different document, and the two must not be
//	conflated, because the first is about capability and the second about
//	well-formedness.
func TestAutonomousVRef_TheRefusalShapeIsPreservedAsTeeth(t *testing.T) {
	// GENERATION 1 (withdrawn): a DUT that refused the conformant document. If
	// it refuses, it never adopts, and the oracle sees an unexecuted axis —
	// which must FAIL now, where it once passed.
	f := newCurveFixture(t)
	got := oracleCurve(autonomousBinding())(context.Background(), f.rc)
	if got.Verdict == certify.Pass {
		t.Fatalf("a DER that adopted NOTHING for a conformant autonomousVRefEnable=true control passed. "+
			"That was the expectation before the gw adjudication and it is now the defect: 2018 p.252 "+
			"makes executing-without mandatory, so a device with an empty curve bank has not complied:\n%s",
			got.Observed)
	}
	t.Logf("PRESERVED (the withdrawn refusal expectation now fails), verbatim:\n  %s", got.Observed)

	// The two documents are DIFFERENT, and the binding proves it structurally:
	// the accepted one carries the time constant, the refused one cannot.
	if autonomousBinding().AutonomousVRefTimeConstant == nil {
		t.Error("the accepted shape carries no autonomousVRefTimeConstant, so it is the MALFORMED " +
			"document rather than the conformant one — 2018 p.252 makes the time constant mandatory " +
			"when the enable is true")
	}
}

// TestVRef_TheDomainCeilingIsInclusiveAndAppliedExactly pins the boundary the
// gw ruling settled: 10 000 is IN domain and means 1.0x.
//
// IEEE Std 2030.5-2018 p.167 states PerCent's domain as "0 to 10 000. (10 000 =
// 100%)" — inclusive, and the parenthetical says what the ceiling MEANS. So a
// vRef of exactly 10000 is a conformant document commanding no adjustment at
// all, and a referee that treated the ceiling as exclusive would refuse to serve
// a legal curve while one that applied it wrongly would move a curve that must
// not move.
//
// THE ARITHMETIC CONSEQUENCE, which belongs in the row docs and is stated here
// because this is where it is checked: vRef can only ever SHRINK the x axis or
// leave it unchanged. The ceiling is 100 %, so vRef/10 000 <= 1 for every legal
// value. A fixture expecting a vRef to push breakpoints UP is expecting a
// document the standard does not admit — which is exactly the error the review's
// own 10500 example made.
func TestVRef_TheDomainCeilingIsInclusiveAndAppliedExactly(t *testing.T) {
	b := *vrefBinding()
	ceiling := uint16(10000)
	b.VRef = &ceiling

	// 1.0x: the expectation is the PUBLISHED curve, unmoved.
	got := b.wantPoints()
	want := []invariant.CurvePoint{{X: 92.00, Y: 30.00}, {X: 108.00, Y: -30.00}}
	for i := range want {
		if math.Abs(got[i].X-want[i].X) > 0.001 {
			t.Errorf("breakpoint %d = %s, want %s: vRef 10000 is 100 %% (2018 p.167), so it multiplies "+
				"by exactly 1 and the published curve is the commanded one", i+1, got[i], want[i])
		}
	}
	// And it is still SERVED and still ASSERTED — "no adjustment" is not the
	// same as "no element", and a bench that dropped it would be sending a
	// different document from the one the row describes.
	f := newCurveFixture(t)
	d, gs := f.withGridSimServer(t)
	if err := publishCurveControl(context.Background(), d, map[string]string{}, &b, "CERT-VREF-CEIL"); err != nil {
		t.Fatalf("the bench refused a vRef of exactly 10000, which p.167 admits: %v", err)
	}
	if raw := servedByGridSim(t, gs, "/derp/0/dc/0"); !strings.Contains(raw, "<vRef>10000</vRef>") {
		t.Errorf("the ceiling value was not served:\n%s", raw)
	}

	// The ceiling is INCLUSIVE: one above it is refused, and the message says
	// the ceiling rather than leaving a reader to infer it.
	over := *vrefBinding()
	bad := uint16(10001)
	over.VRef = &bad
	if err := publishCurveControl(context.Background(), d, map[string]string{}, &over,
		"CERT-VREF-OVER1"); err == nil {
		t.Error("a vRef of 10001 was served; p.167's domain is 0 to 10 000 and the ceiling is inclusive")
	}
}

// TestVRef_OutOfDomainDrawsARefusalAndNeverScales is the negative row the
// deliberate-violation lever exists for.
//
// The product now refuses an out-of-domain vRef at receipt ('vref-out-of-domain'
// — lexa-gw c933ced), and the failure it replaced is the one this asserts
// against: applying 65535 commands a volt-var curve at 6.5x the voltages the
// head end named. A DUT that scales is worse than one that refuses AND worse
// than one that ignores, because the curve it runs is one nobody wrote.
//
// WHAT THIS CAN AND CANNOT SEE, stated because the difference matters. The bench
// can author the malformed document (nonconformant.vref) and the oracle can
// assert what the DEVICE holds. It cannot read the DUT's refusal REASON — that
// is a Response status on the wire, graded by the refusal rows, not by a curve
// oracle reading registers. So this asserts the register consequence: nothing
// adopted, and above all nothing scaled.
func TestVRef_OutOfDomainDrawsARefusalAndNeverScales(t *testing.T) {
	f := newCurveFixture(t)
	_, gs := f.withGridSimServer(t)

	// The bench's own conformant lever refuses this, so the row has to ask by
	// name — which is the property that keeps ordinary evidence conformant.
	rec := postAdminRawCurve(t, gs, `{
		"program": 0, "mode": "volt_var", "points": [{"x":9200,"y":3000},{"x":10800,"y":-3000}],
		"x_mult": -2, "y_mult": -2, "y_ref_type": 3,
		"nonconformant": {"vref": 65535}, "activate": true
	}`)
	if rec != http.StatusCreated {
		t.Fatalf("the deliberate-violation lever did not serve the out-of-domain vRef: %d", rec)
	}
	raw := servedByGridSim(t, gs, "/derp/0/dc/0")
	if !strings.Contains(raw, "<vRef>65535</vRef>") {
		t.Fatalf("the malformed vRef is not on the wire, so this row grades nothing:\n%s", raw)
	}

	// A conformant DUT refuses and adopts NOTHING. The device this fixture
	// starts with holds no curve, which is that outcome.
	b := *vrefBinding()
	huge := uint16(65535)
	b.VRef = &huge
	got := oracleCurve(&b)(context.Background(), f.rc)
	if got.Verdict == certify.Pass {
		t.Fatalf("a DUT that adopted nothing for an out-of-domain vRef passed. Refusing is the "+
			"conformant answer, and this oracle grades the CURVE — so the row's verdict here belongs to "+
			"the refusal criterion, not to a curve match:\n%s", got.Verdict)
	}

	// THE FAILURE THAT MATTERS: a device that APPLIED it. 9200 x 65535/10000 =
	// 60292 raw = 602.92 %V, a volt-var curve six times above nominal.
	scaled := make([]sunspec.VVPoint, 0, len(b.Points))
	for _, p := range b.wantPoints() {
		scaled = append(scaled, sunspec.VVPoint{V: p.X, Var: p.Y})
	}
	if len(scaled) > 0 && scaled[0].V < 500 {
		t.Fatalf("the oracle's own expectation for an out-of-domain vRef is %v, which is not the 6.5x "+
			"scaling this test is about — check wantPoints", scaled[0].V)
	}
	f2 := newCurveFixture(t)
	if err := f2.base.WriteVoltVar(sunspec.VoltVarCurve{
		DeptRef: basic006DeptRef(t), Pri: 1, Points: scaled,
	}, "vref-out-of-domain-applied"); err != nil {
		// A device may legitimately refuse the write at 602 %V; that is itself
		// the correct outcome and not a test failure.
		t.Logf("the DER refused to hold a 6.5x-scaled curve (%v), which is the safe behaviour", err)
		return
	}
	t.Logf("a DER CAN be made to hold the 6.5x-scaled curve (%v %%V), which is why refusing the "+
		"document at receipt is the only thing standing between a malformed percentage and a "+
		"volt-var curve six times above nominal", scaled[0].V)
}

// postAdminRawCurve posts a raw JSON body to gridsim's curve endpoint and
// returns the status, for rows that need a shape the typed CurveRequest
// deliberately cannot express.
func postAdminRawCurve(t *testing.T, gs *gridsim.Server, body string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	gs.AdminHandler().ServeHTTP(rec,
		httptest.NewRequest("POST", "/admin/curve", strings.NewReader(body)))
	if rec.Code >= 400 {
		t.Logf("POST /admin/curve -> %d: %s", rec.Code, rec.Body)
	}
	return rec.Code
}
