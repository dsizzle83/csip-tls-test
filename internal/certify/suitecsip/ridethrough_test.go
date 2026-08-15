package suitecsip

// ridethrough_test.go — the discrimination proof for BASIC-004/005, in the
// discipline curve_legacy_test.go's opening states.
//
// A ROW THAT TURNS GREEN AT THE SAME COMMIT AS THE PRODUCT IT GRADES PROVES
// NOTHING. So each of these rows is first shown RED against the SHIPPING
// product — a DER whose ride-through banks nobody has written, which is exactly
// the southbound state the current gateway leaves behind because it refuses
// every curve axis at receipt (lexa-gw internal/northbound/scheduler/
// supported.go's AdvancedSupportedAxes carries no curve mode, and the advanced
// set is gated behind advanced_axes_enabled, shipped `"adv": "off"` per
// facts-dut-capability.md §2.3) — and only then shown GREEN when the real
// machinery the product will gain is driven directly against the same device.
//
// The green half is driven through lexa-proto's OWN derbase writers — the ones
// a gateway executing these rows would call. Nothing here hand-writes a
// register: a hand-built image can be made to agree with a hand-built oracle
// while both disagree with what a device actually holds, and that is precisely
// the class of error these rows exist to catch.
//
// THE DEVICE ENGINEERING VALUES ARE STATED AS INDEPENDENT LITERALS, following
// legacyPlanFor's rule. With the plan's points and the oracle's expectation both
// derived from wantPoints(), a MIS-SCALED binding still transitions Fail ->
// Pass, because the oracle asks for whatever the binding computed. The literals
// below are the Figure's raw values with their own multiplier applied BY HAND —
// 12000 at 10^-2 is 120.00 %VNom — so this file and the binding are two
// statements that can disagree, and TestTripEngineeringCrossCheck_CatchesA
// MisScaledBinding proves the disagreement is detected.

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

// ── Fixtures ────────────────────────────────────────────────────────────────

// tripFixture is a live TRIP-capable 7xx DER sim (models 707/708/709/710 with
// the IEEE 1547-2018 Category III defaults), a real derbase writer onto it, and
// a RunCtx whose oracle sim slot serves that same device's register image
// through a simapi-shaped /registers — the shape internal/invariant.SimAPIDER
// reads in production.
//
// It is newCurveFixture's sibling one constructor over: NewSolarServerTrip
// rather than NewSolarServerAdvanced. The trip models are OPT-IN on the sim
// precisely so that the default advanced image stays byte-identical for every
// scenario that predates them, which means a ride-through row's fixture has to
// ask for them by name.
type tripFixture struct {
	ss   *sim.SolarServer
	base *derbase.Base
	rc   *certify.RunCtx
}

func newTripFixture(t *testing.T) *tripFixture {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	url := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	ss, err := sim.NewSolarServerTrip(url, 5000, "SN-TRIP-ORACLE")
	if err != nil {
		t.Fatalf("start the trip-capable DER sim: %v", err)
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
	b, err := derbase.Init(reader, "trip-oracle-test")
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

	return &tripFixture{ss: ss, base: &b, rc: &certify.RunCtx{
		Case: &certify.Case{UID: "csip-conf-v1.3::BASIC-004", ID: "BASIC-004"},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, srv.URL, http.DefaultClient),
		},
	}}
}

// unitView reads the DER through the same referee path the oracle uses.
func (f *tripFixture) unitView(t *testing.T) invariant.UnitView {
	t.Helper()
	uv, err := oracleUnitView(context.Background(), f.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the DER through the referee: %v", err)
	}
	return uv
}

// withGridSim gives the fixture a real gridsim admin API AND data plane on the
// same RunCtx, so a row's Setup can actually publish and a test can actually
// fetch the curve hrefs the control links. legacyFixture.withGridSim's sibling.
func (f *tripFixture) withGridSim(t *testing.T) (*Driver, *gridsim.Server, string) {
	t.Helper()
	gs := gridsim.NewServer(benchLFDI)
	prevLog := log.Writer()
	log.SetOutput(io.MultiWriter(prevLog, gs.LogWriter()))
	t.Cleanup(func() { log.SetOutput(prevLog) })

	adminSrv := httptest.NewServer(gs.AdminHandler())
	t.Cleanup(adminSrv.Close)
	dataSrv := httptest.NewServer(gs.Handler())
	t.Cleanup(dataSrv.Close)
	f.rc.GridSim = certify.NewAdminClient(adminSrv.URL, http.DefaultClient)
	f.rc.Targets = certify.Targets{GridSimAdmin: adminSrv.URL}
	return NewDriver(f.rc), gs, dataSrv.URL
}

// ── The device-engineering expectations, stated independently ───────────────

// tripExpectations is the DEVICE ENGINEERING curve each authored element must
// produce, per element, stated independently of the binding.
//
// Every number is the catalog Figure's raw value with its own multiplier
// applied BY HAND — 12000 at 10^-2 is 120.00, 27000 at 10^-2 is 270.00 s — in
// the (seconds, quantity) order this referee decodes a trip point into. A
// reader can check these against the procedure without running anything, and
// this file and the binding are therefore two statements that can disagree.
func tripExpectations(t *testing.T, element string) []invariant.CurvePoint {
	t.Helper()
	switch element {
	case "opModLVRTMustTrip":
		// Figure 4 Test Values (150,0)(150,5000)(1200,5000)(1200,7000)
		// (2200,7000)(2200,8800)(10000,8800), both axes at 10^-2.
		return []invariant.CurvePoint{
			{X: 1.5, Y: 0}, {X: 1.5, Y: 50}, {X: 12, Y: 50}, {X: 12, Y: 70},
			{X: 22, Y: 70}, {X: 22, Y: 88}, {X: 100, Y: 88},
		}
	case "opModLVRTMomentaryCessation":
		// Figure 4 Test Values (0,6000)(150,6000).
		return []invariant.CurvePoint{{X: 0, Y: 60}, {X: 1.5, Y: 60}}
	case "opModHVRTMustTrip":
		// Figure 4 Test Values (16,12000)(16,11000)(1200,11000)(1200,10000)
		// (10000,10000).
		return []invariant.CurvePoint{
			{X: 0.16, Y: 120}, {X: 0.16, Y: 110}, {X: 12, Y: 110}, {X: 12, Y: 100}, {X: 100, Y: 100},
		}
	case "opModHVRTMomentaryCessation":
		// Figure 4 Test Values (0,10000)(1200,10000).
		return []invariant.CurvePoint{{X: 0, Y: 100}, {X: 12, Y: 100}}
	case "opModLFRTMustTrip":
		// Figure 5 Test Values (16,5300)(16,5690)(27000,5690)(27000,5850)
		// (40000,5850) — y is ABSOLUTE Hz.
		return []invariant.CurvePoint{
			{X: 0.16, Y: 53.00}, {X: 0.16, Y: 56.90}, {X: 270, Y: 56.90},
			{X: 270, Y: 58.50}, {X: 400, Y: 58.50},
		}
	case "opModHFRTMustTrip":
		// Figure 5 Test Values (16,6500)(16,6100)(28000,6100)(28000,6050)
		// (40000,6050).
		return []invariant.CurvePoint{
			{X: 0.16, Y: 65.00}, {X: 0.16, Y: 61.00}, {X: 280, Y: 61.00},
			{X: 280, Y: 60.50}, {X: 400, Y: 60.50},
		}
	}
	t.Fatalf("no device-engineering expectation is stated for <%s>", element)
	return nil
}

// crossCheckTripEngineering compares one authored curve's own resolution
// against the independent literals above.
//
// It is a pure function so the check itself can be shown to have teeth (see
// TestTripEngineeringCrossCheck_CatchesAMisScaledBinding).
func crossCheckTripEngineering(c tripCurve, wantEng []invariant.CurvePoint) error {
	got := c.wantPoints()
	if len(got) != len(wantEng) {
		return fmt.Errorf("<%s>: this row's binding resolves to %d breakpoint(s) and the device is "+
			"expected to hold %d — the published curve and the physical curve are not the same length",
			c.Element, len(got), len(wantEng))
	}
	// Exact to within a float round-trip and nothing wider. applyMult reaches
	// 10^-2 by dividing by ten twice, so 5690 -> 56.9 lands one ulp off the
	// literal; a MIS-SCALING is a factor of ten or more and is nowhere near this
	// epsilon. A percentage tolerance would start absorbing the errors the check
	// is for.
	const ulp = 1e-9
	near := func(a, b float64) bool { return math.Abs(a-b) <= ulp*math.Max(1, math.Abs(b)) }
	for i := range wantEng {
		if !near(got[i].X, wantEng[i].X) || !near(got[i].Y, wantEng[i].Y) {
			return fmt.Errorf("<%s> breakpoint %d: this row's binding resolves to (%g, %g) and the device "+
				"is expected to hold (%g, %g). The published values and the axis multipliers together are "+
				"what the DER physically receives, so a disagreement here is a MIS-SCALED BINDING and it "+
				"must be caught here rather than by a representability refusal in lexa-proto that would "+
				"read as a defect in the writer",
				c.Element, i+1, got[i].X, got[i].Y, wantEng[i].X, wantEng[i].Y)
		}
	}
	return nil
}

// tripVSetFor builds the 707/708 VoltageTripSet a gateway executing this row
// would write, from the INDEPENDENT literals, cross-checked against the row.
//
// BOTH SUB-CURVES IN ONE SET, which is not a convenience: a 707 curve-set holds
// MustTrip, MayTrip and MomCess end to end and Encode707Set writes all three at
// once, so a gateway executing BASIC-004 makes exactly two writes (707 and 708)
// and not four. Writing them one sub-curve at a time would zero the other two.
func tripVSetFor(t *testing.T, b *tripBinding, mustTrip, momCess string) sunspec.VoltageTripSet {
	t.Helper()
	conv := func(element string) []sunspec.TripVPoint {
		if element == "" {
			return nil
		}
		c := tripCurveByElement(t, b, element)
		want := tripExpectations(t, element)
		if err := crossCheckTripEngineering(c, want); err != nil {
			t.Fatal(err)
		}
		// (seconds, %VNom) back into the register order the model stores,
		// {V, Tms} — the transposition internal/invariant performs on the way
		// out, performed here on the way in.
		out := make([]sunspec.TripVPoint, 0, len(want))
		for _, p := range want {
			out = append(out, sunspec.TripVPoint{V: p.Y, Tms: p.X})
		}
		return out
	}
	return sunspec.VoltageTripSet{MustTrip: conv(mustTrip), MomCess: conv(momCess)}
}

// tripHzSetFor is tripVSetFor for the 709/710 frequency geometry.
func tripHzSetFor(t *testing.T, b *tripBinding, mustTrip string) sunspec.FreqTripSet {
	t.Helper()
	c := tripCurveByElement(t, b, mustTrip)
	want := tripExpectations(t, mustTrip)
	if err := crossCheckTripEngineering(c, want); err != nil {
		t.Fatal(err)
	}
	out := make([]sunspec.TripHzPoint, 0, len(want))
	for _, p := range want {
		out = append(out, sunspec.TripHzPoint{Hz: p.Y, Tms: p.X})
	}
	return sunspec.FreqTripSet{MustTrip: out}
}

// writeBasic004 installs everything BASIC-004 publishes, through the REAL
// derbase writers a gateway executing the row would call.
func writeBasic004(t *testing.T, f *tripFixture) {
	t.Helper()
	b := tripRowByID(t, "BASIC-004")
	if err := f.base.WriteVoltageTripLV(
		tripVSetFor(t, b, "opModLVRTMustTrip", "opModLVRTMomentaryCessation"), "basic004-test"); err != nil {
		t.Fatalf("the REAL derbase.WriteVoltageTripLV refused this row's own curves: %v", err)
	}
	if err := f.base.WriteVoltageTripHV(
		tripVSetFor(t, b, "opModHVRTMustTrip", "opModHVRTMomentaryCessation"), "basic004-test"); err != nil {
		t.Fatalf("the REAL derbase.WriteVoltageTripHV refused this row's own curves: %v", err)
	}
}

// writeBasic005 installs everything BASIC-005 publishes.
func writeBasic005(t *testing.T, f *tripFixture) {
	t.Helper()
	b := tripRowByID(t, "BASIC-005")
	if err := f.base.WriteFreqTripLF(tripHzSetFor(t, b, "opModLFRTMustTrip"), "basic005-test"); err != nil {
		t.Fatalf("the REAL derbase.WriteFreqTripLF refused this row's own curve: %v", err)
	}
	if err := f.base.WriteFreqTripHF(tripHzSetFor(t, b, "opModHFRTMustTrip"), "basic005-test"); err != nil {
		t.Fatalf("the REAL derbase.WriteFreqTripHF refused this row's own curve: %v", err)
	}
}

// ── RED: the shipping product ───────────────────────────────────────────────

// TestRideThroughRowsAreRedAgainstTheShippingProduct is the mandatory red proof
// at the ORACLE level, on BOTH generations.
//
// The 7xx DER serves all four trip banks and holds the IEEE 1547-2018 Category
// III DEFAULTS in them — which is the state a device that nobody has commanded
// is in, and is deliberately NOT the curve either row publishes. The legacy DER
// serves 129/130 holding the same defaults in the legacy layout. Neither has
// been written by anything, because the shipping gateway refuses every curve
// axis at receipt.
//
// A row that passed here would be certifying axes the product does not execute,
// which is the IW15-008 defect verbatim.
func TestRideThroughRowsAreRedAgainstTheShippingProduct(t *testing.T) {
	for _, tc := range []struct {
		id        string
		wantModel string
	}{
		{"BASIC-004", "M707 DER Trip LV"},
		{"BASIC-005", "M709 DER Trip LF"},
	} {
		t.Run(tc.id+" on a 7xx DER", func(t *testing.T) {
			f := newTripFixture(t)
			b := tripRowByID(t, tc.id)
			got := oracleTrip(b)(context.Background(), f.rc)
			if got.Verdict != certify.Fail {
				t.Fatalf("%s on a trip-capable 7xx bench = %s against the SHIPPING product, want FAIL.\n%s",
					tc.id, got.Verdict, got.Observed)
			}
			if !strings.Contains(got.Observed, tc.wantModel) {
				t.Errorf("%s's FAIL does not name the model it measured (%s):\n%s",
					tc.id, tc.wantModel, got.Observed)
			}
			// The verbatim reason is the deliverable, not a debugging aid: a red
			// row whose reason nobody recorded is indistinguishable from a red row
			// nobody understood.
			t.Logf("%s RED against the shipping product (7xx):\n  %s", tc.id, got.Observed)
		})
	}

	for _, tc := range []struct {
		id string
		// wantAbsence is the legacy carriage gap this row must NAME rather than
		// skip past.
		wantAbsence string
	}{
		{"BASIC-004", "SINGLE region per bank"},
		{"BASIC-005", "NO legacy 12x model for frequency ride-through"},
	} {
		t.Run(tc.id+" on a legacy DER", func(t *testing.T) {
			f := newLegacyFixture(t, sim.LegacyCurveOptions{})
			b := tripRowByID(t, tc.id)
			got := oracleTrip(b)(context.Background(), f.rc)
			if got.Verdict != certify.Fail {
				t.Fatalf("%s on a legacy bench = %s against the SHIPPING product, want FAIL.\n%s",
					tc.id, got.Verdict, got.Observed)
			}
			if !strings.Contains(got.Observed, tc.wantAbsence) {
				t.Errorf("%s's legacy FAIL does not NAME the carriage absence it is under (%q):\n%s",
					tc.id, tc.wantAbsence, got.Observed)
			}
			t.Logf("%s RED against the shipping product (legacy):\n  %s", tc.id, got.Observed)
		})
	}
}

// TestRideThroughRowsAreRedEndToEndAgainstTheShippingProduct drives the
// SHIPPING rows through the same live-phase sequence check.go's run() uses
// (Setup, the DUT's poll cycle, PostWait) with the DER left in exactly the
// state the current product leaves it: nothing written, because the gateway
// refuses every curve axis at receipt with the advanced axes OFF — the shipping
// default (lexa-gw's AdvancedSupportedAxes behind advanced_axes_enabled,
// facts-dut-capability.md §2.3's `"adv": "off"`).
//
// This is the ROW-level red proof. The oracle-level one above shows the
// referee's answer; this shows the row's DECLARED VERDICT, which is what lands
// in a bundle — and it must be FAIL independently of the capture, because the
// capture would have shown four perfectly good ride-through elements on a
// well-formed DERControl and that is exactly what used to carry rows to PASS.
//
// It also proves the BENCH half that has to be true before any of it means
// anything: the control carries every element the Figure prescribes, and every
// curve href it links RESOLVES. A bench 404 and a DUT that refused the axis
// produce identical southbound silence.
func TestRideThroughRowsAreRedEndToEndAgainstTheShippingProduct(t *testing.T) {
	for _, tc := range []struct {
		id       string
		elements []string
	}{
		{"BASIC-004", []string{"opModLVRTMustTrip", "opModLVRTMomentaryCessation",
			"opModHVRTMustTrip", "opModHVRTMomentaryCessation"}},
		{"BASIC-005", []string{"opModLFRTMustTrip", "opModHFRTMustTrip"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newTripFixture(t)
			d, _, dataURL := f.withGridSim(t)
			b := tripRowByID(t, tc.id)
			s := rideThroughSpec(b, "the ride-through settings", "CERT-"+tc.id)

			ctx := context.Background()
			params := map[string]string{pollWindowParam: "20ms"}
			if err := s.Setup(ctx, d, params); err != nil {
				t.Fatalf("%s Setup: %v", tc.id, err)
			}
			// The DUT's poll cycle happens here. This product does nothing
			// southbound for a refused axis, which is the whole point.
			if err := s.PostWait(ctx, d, params); err != nil {
				t.Fatalf("%s PostWait: %v", tc.id, err)
			}

			obs := &Observation{Params: params}
			if got := s.Verdict(obs); got != certify.Fail {
				t.Fatalf("%s's declared live verdict against the shipping product = %q, want FAIL", tc.id, got)
			}
			if got := params[curveGenParam]; got != string(invariant.Family7xx) {
				t.Errorf("%s recorded generation %q on a 7xx trip bench", tc.id, got)
			}
			if got := params[curveModelParam]; got == "" {
				t.Errorf("%s recorded no southbound model, so the bundle cannot say what it measured", tc.id)
			}

			// EVERY element on ONE control, fetched from the bench's data plane.
			ctrls := httpGet(t, dataURL+"/derp/0/derc")
			for _, el := range tc.elements {
				if !strings.Contains(ctrls, "<"+el+" ") && !strings.Contains(ctrls, "<"+el+">") {
					t.Errorf("%s's published control does not carry <%s>. The procedure requires ONE "+
						"DERControl with the whole Figure on it, and a control missing an element never "+
						"offered the DUT the combination the row is about:\n%s", tc.id, el, ctrls)
				}
			}

			// EVERY curve href RESOLVES. Four links and a criterion that checked
			// one of them would leave three unverified.
			hrefs := tripHrefsOf(obs)
			if len(hrefs) != len(tc.elements) {
				t.Fatalf("%s recorded %d curve href(s) and publishes %d curve(s): %v",
					tc.id, len(hrefs), len(tc.elements), hrefs)
			}
			for _, href := range hrefs {
				resp, err := http.Get(dataURL + href)
				if err != nil {
					t.Fatalf("GET %s: %v", href, err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode/100 != 2 {
					t.Errorf("GET %s answered %d — the control links a curve resource the bench does not "+
						"serve, so every southbound silence on this row is unattributable", href, resp.StatusCode)
				}
			}

			// THE DELIVERY FACT. This fixture has no gateway process at all —
			// nothing fetches anything — so the row's own text must say that,
			// instead of reading as though a DUT had considered the control and
			// declined it.
			notes := s.Notes(obs)
			if !strings.Contains(notes, "NO fetch of this row's control was observed") {
				t.Errorf("%s's verdict text does not say the control was never fetched, so a dead DUT and "+
					"a refusing one read identically here:\n%s", tc.id, notes)
			}
			t.Logf("%s end-to-end RED against the shipping product: verdict=FAIL generation=%s models=%s "+
				"hrefs=%v\n%s", tc.id, params[curveGenParam], params[curveModelParam], hrefs, notes)
		})
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(body)
}

// ── GREEN: the machinery the product will gain, run for real ────────────────

// TestRideThroughRowsTurnGreenWhenTheRealDerbaseWritersRun is the
// discrimination proof. The SAME rows, against the SAME device, after
// lexa-proto's own WriteVoltageTripLV/HV and WriteFreqTripLF/HF have installed
// exactly the curves the rows publish: the verdict must flip to PASS.
//
// Red-then-green over one binding is the whole claim. A row that were merely
// always red would look identical in the tests above, and an oracle shaped to
// the fixture would look identical here; only the pair distinguishes a
// measurement from either.
func TestRideThroughRowsTurnGreenWhenTheRealDerbaseWritersRun(t *testing.T) {
	for _, tc := range []struct {
		id    string
		write func(*testing.T, *tripFixture)
	}{
		{"BASIC-004", writeBasic004},
		{"BASIC-005", writeBasic005},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newTripFixture(t)
			b := tripRowByID(t, tc.id)

			before := oracleTrip(b)(context.Background(), f.rc)
			if before.Verdict != certify.Fail {
				t.Fatalf("%s started %s on an unwritten bench, so a later PASS would prove nothing:\n%s",
					tc.id, before.Verdict, before.Observed)
			}

			tc.write(t, f)

			after := oracleTrip(b)(context.Background(), f.rc)
			if after.Verdict != certify.Pass {
				t.Fatalf("%s after the REAL derbase writers installed its curves = %s, want PASS.\n%s",
					tc.id, after.Verdict, after.Observed)
			}
			// A GREEN row must not be read as green on content nothing looked at.
			// The y-axis reference goes on the wire and lands in no register on
			// either generation, and BASIC-004 authors one.
			if tc.id == "BASIC-004" && !strings.Contains(after.Observed, "AUTHORED BUT NOT DEVICE-MAPPABLE") {
				t.Errorf("BASIC-004's PASS does not disclose that the yRefType it served has no register "+
					"home, so the verdict reads as covering the whole of Figure 4:\n%s", after.Observed)
			}
			t.Logf("%s GREEN after the real derbase trip writers:\n  %s", tc.id, after.Observed)
		})
	}
}

// TestRideThroughWriterOnOneAxisLeavesTheOtherRed is the second half of the
// discrimination proof, and it is the one that catches an oracle that is really
// reading the bench rather than the banks it names.
//
// Installing the VOLTAGE curves must turn BASIC-004 green and must leave
// BASIC-005 exactly as red as it was. A referee that resolved the wrong bank,
// or that graded "some trip curve is present", would go green on both.
func TestRideThroughWriterOnOneAxisLeavesTheOtherRed(t *testing.T) {
	f := newTripFixture(t)
	writeBasic004(t, f)

	four := tripRowByID(t, "BASIC-004")
	if got := oracleTrip(four)(context.Background(), f.rc); got.Verdict != certify.Pass {
		t.Fatalf("BASIC-004 = %s after its own curves were installed:\n%s", got.Verdict, got.Observed)
	}
	five := tripRowByID(t, "BASIC-005")
	got := oracleTrip(five)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Errorf("BASIC-005 = %s after only the VOLTAGE trip banks were written — this row is reading the "+
			"bench, not the register homes it names:\n%s", got.Verdict, got.Observed)
	}
	t.Logf("BASIC-005 still RED after the voltage banks were written:\n  %s", got.Observed)
}

// TestTripSubCurveAddressingIsNotSilent is the catcher for the defect
// sub-curve addressing exists to prevent.
//
// A 707 curve-set holds three sub-curves. If the referee read "the" point table
// of the bank — or defaulted to MustTrip — then BASIC-004's
// opModLVRTMomentaryCessation curve would be graded against the MUST-TRIP
// sub-curve, and the row would report a mismatch about a bank holding exactly
// what was commanded. Worse in the other direction: a run that wrote ONLY the
// momentary-cessation points would look like a correct must-trip execution.
//
// So: write the MomCess sub-curve alone, leaving MustTrip empty, and require
// the row to FAIL naming the must-trip sub-curve rather than passing on the
// content that landed next door.
func TestTripSubCurveAddressingIsNotSilent(t *testing.T) {
	f := newTripFixture(t)
	b := tripRowByID(t, "BASIC-004")

	// MomCess only. Encode707Set writes all three sub-curves of the set, so the
	// must-trip one comes back with ActPt = 0.
	only := sunspec.VoltageTripSet{
		MomCess: tripVSetFor(t, b, "", "opModLVRTMomentaryCessation").MomCess,
	}
	if err := f.base.WriteVoltageTripLV(only, "subcurve-test"); err != nil {
		t.Fatalf("derbase refused a momentary-cessation-only write: %v", err)
	}

	uv := f.unitView(t)
	// The referee's own reading, addressed both ways, is the evidence: the
	// MomCess sub-curve holds the two points and MustTrip holds none.
	mom := uv.TripCurve(oracleSimName, sunspec.ModelDERTripLV, invariant.SubCurveMomCess)
	must := uv.TripCurve(oracleSimName, sunspec.ModelDERTripLV, invariant.SubCurveMustTrip)
	if len(mom.Points) != 2 {
		t.Fatalf("the MomCess sub-curve holds %d point(s) after a MomCess-only write: %s",
			len(mom.Points), mom.Describe())
	}
	if len(must.Points) != 0 {
		t.Fatalf("the MustTrip sub-curve holds %d point(s) after a MomCess-only write, so this test "+
			"cannot show the distinction it is about: %s", len(must.Points), must.Describe())
	}

	got := oracleTrip(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-004 = %s when ONLY the momentary-cessation sub-curve was written — the referee is "+
			"grading the wrong sub-curve, or grading whichever one is non-empty:\n%s",
			got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "MustTrip") {
		t.Errorf("the FAIL does not name the sub-curve it read, so a reader cannot tell which of the "+
			"three the verdict is about:\n%s", got.Observed)
	}
	// And a reading that names NO sub-curve carries no points at all, which is
	// what makes the silent pick impossible rather than merely avoided.
	set := uv.Curve(oracleSimName, sunspec.ModelDERTripLV)
	if len(set.Points) != 0 {
		t.Errorf("an unaddressed reading of a trip bank came back with %d point(s); it must carry none, "+
			"or a caller that forgot to name a sub-curve silently grades one: %s",
			len(set.Points), set.Describe())
	}
	if !strings.Contains(set.Describe(), "MomCess") || !strings.Contains(set.Describe(), "MustTrip") {
		t.Errorf("an unaddressed trip reading does not render all three sub-curves, so the two the caller "+
			"did not ask about are invisible where a failure most needs them:\n%s", set.Describe())
	}
	t.Logf("sub-curve addressing is explicit:\n  %s", set.Describe())
}

// TestTripEngineeringCrossCheck_CatchesAMisScaledBinding is the teeth of the
// independent side.
//
// The green proofs are genuinely discriminating — red on an unwritten bench,
// green after the writers run, and a voltage write leaves the frequency row red
// — but that shape cannot see a binding that is wrong on BOTH sides of the
// comparison. With the plan and the oracle expectation both derived from
// wantPoints(), setting BASIC-004's XMult to 0 would install a must-trip curve
// whose knee is at 1200 SECONDS instead of 12, and the row would still
// transition Fail -> Pass because the oracle asks for the same 1200.
//
// The device-engineering literals are what close it, so this proves they do.
func TestTripEngineeringCrossCheck_CatchesAMisScaledBinding(t *testing.T) {
	good := tripCurveByElement(t, tripRowByID(t, "BASIC-004"), "opModLVRTMustTrip")
	want := tripExpectations(t, "opModLVRTMustTrip")
	if err := crossCheckTripEngineering(good, want); err != nil {
		t.Fatalf("the SHIPPING BASIC-004 binding fails its own engineering cross-check: %v", err)
	}

	// The probe: a lost x multiplier, which turns every duration into hundreds
	// of seconds and is exactly the kind of edit a reader would not see.
	mis := good
	mis.XMult = 0
	if err := crossCheckTripEngineering(mis, want); err == nil {
		t.Fatal("a binding at xMultiplier 10^0 — a must-trip knee at 1200 SECONDS instead of 12 — passed " +
			"the cross-check, so the independent literals are not independent and a mis-scaled binding " +
			"would go green")
	}

	// And a lost y multiplier, which turns 88.00 %VNom into 8800 %.
	mis = good
	mis.YMult = 0
	if err := crossCheckTripEngineering(mis, want); err == nil {
		t.Fatal("a binding at yMultiplier 10^0 — a trip boundary at 8800 % of nominal voltage — passed " +
			"the cross-check")
	}

	// A curve of the wrong LENGTH is caught too, and separately: a row that
	// dropped a breakpoint publishes a different piecewise function.
	short := good
	short.Points = short.Points[:len(short.Points)-1]
	if err := crossCheckTripEngineering(short, want); err == nil {
		t.Fatal("a binding one breakpoint short passed the cross-check")
	}
}

// ── The protective boundary ─────────────────────────────────────────────────

// TestLegacyRideThroughRefusesCaseBAndLeavesTheBoundaryUp is the never-disable
// arm, MEASURED.
//
// lexa-proto's WriteLegacyRideThrough refuses the Case-B single-bank rewrite —
// "installing this curve would delete the live trip boundary for the width of
// the rewrite. A protective function is not momentarily removed to update it" —
// and its failure arm restores the curve SELECTION rather than clearing ModEna.
// A one-bank legacy DER is exactly the device that provokes it.
//
// The claim is checked from OUTSIDE, through the referee, on the two facts that
// matter to a conformance bundle: the write is refused by the documented
// reason, and the protective function's enable register is where it was.
func TestLegacyRideThroughRefusesCaseBAndLeavesTheBoundaryUp(t *testing.T) {
	// NCrv 1 is the field-common single-bank shape and the one with no writable
	// idle bank.
	f := newLegacyFixture(t, sim.LegacyCurveOptions{NCrv: 1})
	b := tripRowByID(t, "BASIC-004")
	c := tripCurveByElement(t, b, "opModLVRTMustTrip")

	// BRING THE PROTECTIVE FUNCTION UP FIRST, and do it here rather than
	// skipping when it is down.
	//
	// The sim seeds every legacy curve model with ModEna = 0, which is a
	// device nobody has commissioned; a real DER ships with its must-disconnect
	// curve running. Without this the test would be asserting that a refused
	// write did not turn off something that was already off — true, and no
	// evidence at all about the never-disable arm. Skipping instead would be
	// worse: a skip is severity 0 and reads, in every roll-up, exactly like a
	// check that passed.
	//
	// The enable is written over the DEVICE's own Modbus write path, through
	// the same sunspec.Reader derbase uses, so the sim's write interception and
	// register map see an ordinary commissioning write. It is a PRECONDITION —
	// the state the test is about — and not the behaviour under test, which is
	// what the refused ride-through write does to it afterwards.
	hdr, _, _, ok := sunspec.LegacyCurveLayouts(sunspec.ModelLVRTLegacy)
	if !ok {
		t.Fatal("lexa-proto declares no legacy layout for model 129")
	}
	if err := f.base.Reader.WriteModel(sunspec.ModelLVRTLegacy,
		uint16(hdr.Offset("ModEna")), []uint16{1}); err != nil {
		t.Fatalf("commission M129 (ModEna bit 0): %v", err)
	}

	before := f.unitView(t)
	live := before.Curve(oracleSimName, sunspec.ModelLVRTLegacy)
	if !live.Present {
		t.Fatalf("the legacy fixture serves no M129: %s", live.Describe())
	}
	if !live.Enabled {
		t.Fatalf("M129 did not come up after the commissioning write, so this test cannot show a boundary "+
			"surviving a refused write: %s", live.Describe())
	}
	priorActCrv := live.ActCrv

	pts := make([]sunspec.LegacyCurvePoint, 0, len(c.Points))
	for _, p := range c.wantPoints() {
		// 129 stores (seconds, %VRef) — TIME FIRST — which is the order the
		// referee already decodes into, so no transposition here either.
		pts = append(pts, sunspec.LegacyCurvePoint{X: p.X, Y: p.Y})
	}
	_, err := f.base.WriteLegacyRideThrough(derbase.LegacyCurvePlan{
		ModelID: sunspec.ModelLVRTLegacy, Axis: c.Element, Points: pts,
	}, "ridethrough-caseb-test")
	if err == nil {
		t.Fatal("WriteLegacyRideThrough ACCEPTED a single-bank rewrite. Installing a ride-through curve " +
			"into the only bank deletes the live trip boundary for the width of the transaction, which " +
			"is the one refusal that makes the whole protective path safe")
	}
	if !strings.Contains(err.Error(), "legacy-ride-through-single-bank") {
		t.Errorf("the refusal does not carry its documented reason (legacy-ride-through-single-bank): %v", err)
	}

	after := f.unitView(t)
	post := after.Curve(oracleSimName, sunspec.ModelLVRTLegacy)
	if !post.Enabled {
		t.Errorf("M129's ModEna bit 0 is CLEAR after a refused ride-through write. A trip boundary is "+
			"protective and is never removed as a failure action — the fail-closed helper that writes "+
			"ModEna=0 takes a witness only nonProtective() can mint, and it refuses 129/130: %s",
			post.Describe())
	}
	if post.ActCrv != priorActCrv {
		t.Errorf("M129's ActCrv moved from %d to %d across a refused write; the failure arm restores the "+
			"selection recorded at engage", priorActCrv, post.ActCrv)
	}
	// And the criterion the row carries can SAY it.
	pre, _ := protectiveEnables(before)
	postCanon, _ := protectiveEnables(after)
	crit := critProtectiveBoundaryHeld(&Observation{Params: map[string]string{
		tripProtectivePreParam: pre, tripProtectivePostParam: postCanon,
	}})
	if f := crit.Construction(); f.Verdict != certify.Pass {
		t.Errorf("the protective-boundary criterion = %s over a refused write that changed nothing:\n%s",
			f.Verdict, f.Observed)
	}
	t.Logf("Case-B refused, boundary intact: %v\n  %s", err, post.Describe())
}

// TestLegacyRideThroughIsNotReachableThroughTheFailClosedWriter proves the
// STRUCTURAL half of the never-disable claim from outside lexa-proto.
//
// WriteLegacyCurve is the writer whose failure arm disables the function
// (ModEna=0) when a write fails after the selection has moved, and it can only
// do that because it holds a nonProtectiveCurve witness that nonProtective()
// refuses to mint for 129 and 130. The witness itself is unexported; what is
// observable from here is the consequence — WriteLegacyCurve REFUSES a
// ride-through model outright and says where such a write belongs.
func TestLegacyRideThroughIsNotReachableThroughTheFailClosedWriter(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	for _, model := range []uint16{sunspec.ModelLVRTLegacy, sunspec.ModelHVRTLegacy} {
		_, err := f.base.WriteLegacyCurve(derbase.LegacyCurvePlan{
			ModelID: model, Axis: "opModLVRTMustTrip",
			Points: []sunspec.LegacyCurvePoint{{X: 1.5, Y: 50}, {X: 12, Y: 70}},
		}, "ridethrough-structural-test")
		if err == nil {
			t.Errorf("WriteLegacyCurve ACCEPTED model %d. That writer's failure arm clears ModEna, and a "+
				"trip boundary must never be removed as a failure action — the two paths are separate "+
				"functions precisely so this cannot happen", model)
			continue
		}
		if !strings.Contains(err.Error(), "WriteLegacyRideThrough") {
			t.Errorf("model %d's refusal does not name the writer such a curve belongs to: %v", model, err)
		}
		t.Logf("M%d refused by the fail-closed writer: %v", model, err)
	}
}

// TestReleaseIsNoOpinionOnTheProtectiveModels is the last of the three
// structural facts the row's criterion states: a released control does not
// repeal a trip boundary.
//
// ReleaseLegacyCurve clears ModEna on 126/131/132 and returns NoOpinion on
// 129/130 — "ride-through is a protective trip boundary and is never stripped
// by a release". A gateway that treated a released ride-through control as an
// instruction to switch protection off would leave a device unprotected because
// a head-end event ended.
func TestReleaseIsNoOpinionOnTheProtectiveModels(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	for _, model := range []uint16{sunspec.ModelLVRTLegacy, sunspec.ModelHVRTLegacy} {
		before := f.unitView(t).Curve(oracleSimName, model)
		out, err := f.base.ReleaseLegacyCurve(model, "ridethrough-release-test")
		if err != nil {
			t.Fatalf("ReleaseLegacyCurve(M%d): %v", model, err)
		}
		if !out.NoOpinion || out.Released {
			t.Errorf("ReleaseLegacyCurve(M%d) reports NoOpinion=%t Released=%t, want a no-opinion that "+
				"writes nothing", model, out.NoOpinion, out.Released)
		}
		if !strings.Contains(out.Reason, "protective") {
			t.Errorf("M%d's release reason does not say why (%q)", model, out.Reason)
		}
		after := f.unitView(t).Curve(oracleSimName, model)
		if before.Enabled != after.Enabled {
			t.Errorf("M%d's enable moved from %t to %t across a RELEASE, which must write nothing at all",
				model, before.Enabled, after.Enabled)
		}
		t.Logf("M%d release is no-opinion: %s", model, out.Reason)
	}
}

// TestProtectiveBoundaryCriterionCatchesAStrippedBoundary is the teeth of the
// measured half.
//
// An agreement test that has only ever been seen agreeing has been
// demonstrated, not tested. This drives the criterion over the four shapes it
// has to distinguish, including the one it exists for.
func TestProtectiveBoundaryCriterionCatchesAStrippedBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pre, post string
		set       bool
		want      certify.Verdict
		mustSay   string
	}{
		{"a boundary that was up and stayed up", "129=on;130=on", "129=on;130=on", true,
			certify.Pass, "still switched on"},
		{"a boundary that was STRIPPED", "129=on;130=on", "129=off;130=on", true,
			certify.Fail, "M129"},
		{"a boundary that was already down", "129=off", "129=off", true,
			certify.Pass, "still switched on"},
		// The no-banks SENTINEL, not an empty string: protectiveEnables
		// returns "none" for a DER that serves no ride-through model, so that
		// "read it, there are none" and "never read" stay distinguishable in
		// the params a bundle carries.
		{"a DER with no ride-through bank at all", protectiveNoBanks, protectiveNoBanks, true,
			certify.Pass, "measured nothing"},
		{"no readings recorded", "", "", false,
			certify.Fail, "unrecorded criterion is not a satisfied one"},
		{"only one reading recorded", "129=on", "", false,
			certify.Fail, "one of the two readings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]string{}
			if tc.set {
				params[tripProtectivePreParam] = tc.pre
				params[tripProtectivePostParam] = tc.post
			} else if tc.pre != "" {
				params[tripProtectivePreParam] = tc.pre
			}
			f := critProtectiveBoundaryHeld(&Observation{Params: params}).Construction()
			if f.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s:\n%s", f.Verdict, tc.want, f.Observed)
			}
			if !strings.Contains(f.Observed, tc.mustSay) {
				t.Errorf("the finding does not say %q:\n%s", tc.mustSay, f.Observed)
			}
			t.Logf("%s -> %s: %s", tc.name, f.Verdict, f.Observed)
		})
	}
}

// TestProtectiveBoundaryStructureIsStatedWithoutClaimingToBeAMeasurement pins
// the disclosure that keeps the two halves apart.
//
// The structural criterion states properties of lexa-proto's writer. If it read
// as a measurement of the run, a bundle would carry a green "protection held"
// claim for a window in which nothing was measured — the exact
// absence-reads-as-success shape this suite exists to remove.
func TestProtectiveBoundaryStructureIsStatedWithoutClaimingToBeAMeasurement(t *testing.T) {
	f := critProtectiveBoundaryStructure().Construction()
	if f.Verdict != certify.Pass {
		t.Fatalf("the structural criterion = %s, want PASS:\n%s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "NOT A MEASUREMENT OF THIS RUN") {
		t.Errorf("the structural criterion does not disclaim being a measurement:\n%s", f.Observed)
	}
	for _, want := range []string{
		"legacy-ride-through-single-bank",
		"nonProtectiveCurve",
		"NoOpinion",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the structural criterion does not cite %q:\n%s", want, f.Observed)
		}
	}
}

// ── Composition ─────────────────────────────────────────────────────────────

// TestTripOracleCarriesEveryCurvesAnswerAndTheWorstDecides pins the composition
// rule, which is where a multi-curve row can most easily overclaim.
//
// A DUT that adopted the must-trip curves and ignored the momentary-cessation
// ones has executed half of one control, and half is not execution. Equally, a
// verdict that reported only the failing half would leave a bundle with no
// trace that the other half was measured at all.
func TestTripOracleCarriesEveryCurvesAnswerAndTheWorstDecides(t *testing.T) {
	f := newTripFixture(t)
	b := tripRowByID(t, "BASIC-004")

	// Write the LOW-voltage bank only. BASIC-004's other two curves live in 708
	// and are untouched.
	if err := f.base.WriteVoltageTripLV(
		tripVSetFor(t, b, "opModLVRTMustTrip", "opModLVRTMomentaryCessation"), "compose-test"); err != nil {
		t.Fatalf("derbase refused the LV write: %v", err)
	}

	got := oracleTrip(b)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-004 = %s with only two of its four curves installed — a half-executed control is "+
			"not an executed one:\n%s", got.Verdict, got.Observed)
	}
	// Both banks must appear: the failing 708 and the passing 707.
	for _, want := range []string{"M707 DER Trip LV", "M708 DER Trip HV"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the composed verdict does not mention %s, so a reader cannot tell which halves were "+
				"measured:\n%s", want, got.Observed)
		}
	}
	t.Logf("half-installed BASIC-004 composes to FAIL carrying both answers:\n  %s", got.Observed)
}

// TestTripRowsRegisterUnderTheirCatalogIDs is the registration guarantee.
//
// BASIC-004 and BASIC-005 left inverterControlRows when they stopped being
// unreachableMode rows, and a row that is defined but never registered runs in
// no campaign — which would read, in a bundle, exactly like a row that was
// never in the catalog.
func TestTripRowsRegisterUnderTheirCatalogIDs(t *testing.T) {
	reg := certify.NewRegistry()
	Register(reg)
	for _, id := range []string{"BASIC-004", "BASIC-005"} {
		if _, ok := reg.Lookup(uid(id)); !ok {
			t.Errorf("%s is not registered, so no campaign runs it", id)
		}
	}
	// And they are NOT also in inverterControlRows, which would register each
	// of them twice under two different apparatus.
	for _, r := range inverterControlRows() {
		if r.id == "BASIC-004" || r.id == "BASIC-005" {
			t.Errorf("%s is still an inverter-control row AND a ride-through row; it would be registered "+
				"twice, and which apparatus ran would depend on registration order", r.id)
		}
	}
}
