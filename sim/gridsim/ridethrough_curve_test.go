package gridsim

// ridethrough_curve_test.go — the two levers curve plan #32 added to
// POST /admin/curve, and the properties a conformance row rests on:
//
//  1. the TEN IEEE 2030.5 ride-through modes, each emitting the DERCurveType
//     code the standard assigns it and hanging off the DERControlBase field the
//     standard names; and
//  2. SEVERAL curves on ONE DERControl, because CSIP CTP v1.3's BASIC-004 asks
//     for "a DERControl instance with Low/High Voltage Ride Through values in
//     Figure 4" — singular — and Figure 4 prints four curves.
//
// The second is the one worth stating twice. Four separate DERControls would
// follow a procedure nobody wrote, and the conformance row could then never say
// the DUT had been offered the COMBINATION, which is the whole content of a
// ride-through test.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// postCurve posts a body to /admin/curve and returns the decoded response,
// failing on any status but 201.
func postCurve(t *testing.T, s *Server, body string) adminCurveResp {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d; body: %s", rec.Code, rec.Body)
	}
	var out adminCurveResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode the POST response: %v", err)
	}
	return out
}

// postCurveErr posts a body expected to be REFUSED and returns the message.
func postCurveErr(t *testing.T, s *Server, body string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/curve = %d, want 400; body: %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// TestCurveModeVocabularyIsComplete pins the mode table against the standard's
// own numbering and against the link fields.
//
// THREE PROPERTIES, and each has a specific failure it prevents:
//
//	every mode in curveModes resolves — a 400 that lists a mode the server
//	then refuses sends a caller round in a circle;
//	every mode's curveType is DISTINCT — two modes sharing a code means one of
//	them is mislabelled on the wire, which is exactly what IW15-027 found the
//	bench doing with the draft schema's numbering;
//	every mode sets a DIFFERENT DERControlBase field — two modes writing one
//	field is how a four-curve control silently becomes a three-curve one.
func TestCurveModeVocabularyIsComplete(t *testing.T) {
	byCode := map[uint16]string{}
	for _, mode := range curveModes {
		code, ok := curveTypeForMode(mode)
		if !ok {
			t.Errorf("curveModes lists %q and curveTypeForMode refuses it; the 400 this server answers "+
				"names a mode it will not serve", mode)
			continue
		}
		if prev, dup := byCode[code]; dup {
			t.Errorf("modes %q and %q both emit curveType %d — one of them goes on the wire under "+
				"another mode's label", prev, mode, code)
		}
		byCode[code] = mode

		// And the link field. Two modes writing one field is invisible in the
		// response and fatal to a multi-curve control.
		var base model.ExtendedDERControlBase
		setCurveLink(&base, mode, "/derp/0/dc/9")
		if n := countCurveLinks(base); n != 1 {
			t.Errorf("mode %q set %d DERControlBase curve link(s), want exactly 1 — a mode with no field "+
				"publishes a curve nothing references, and one that shares a field overwrites its "+
				"neighbour", mode, n)
		}
	}
	// The ten ride-through modes are all there. The list is stated here rather
	// than derived from curveModes, so a mode DELETED from the vocabulary is a
	// failure and not a silently smaller loop.
	for _, mode := range []string{
		"lvrt_must_trip", "lvrt_may_trip", "lvrt_momentary_cessation",
		"hvrt_must_trip", "hvrt_may_trip", "hvrt_momentary_cessation",
		"lfrt_must_trip", "lfrt_may_trip", "hfrt_must_trip", "hfrt_may_trip",
	} {
		if _, ok := curveTypeForMode(mode); !ok {
			t.Errorf("ride-through mode %q is not served; BASIC-004/005 cannot be published without it", mode)
		}
	}
	// AND THERE IS NO FREQUENCY MOMENTARY CESSATION. IEEE Std 2030.5-2018 p.254
	// assigns momentary-cessation curveType codes to the two VOLTAGE curves (4
	// and 9) and none to a frequency one, so a mode for it would be a curve
	// labelled with an invented code.
	for _, mode := range []string{"lfrt_momentary_cessation", "hfrt_momentary_cessation"} {
		if _, ok := curveTypeForMode(mode); ok {
			t.Errorf("this server serves %q. IEEE 2030.5-2018 p.254 assigns no DERCurveType to a "+
				"frequency momentary-cessation curve, so whatever code it emits belongs to another "+
				"mode", mode)
		}
	}
}

// countCurveLinks counts the curve links set on a control base.
func countCurveLinks(b model.ExtendedDERControlBase) int {
	n := 0
	for _, l := range []*model.CurveLink{
		b.OpModVoltVar, b.OpModVoltWatt, b.OpModFreqWatt, b.OpModWattPF, b.OpModWattVar,
		b.OpModLVRTMustTrip, b.OpModLVRTMayTrip, b.OpModLVRTMomentaryCessation,
		b.OpModHVRTMustTrip, b.OpModHVRTMayTrip, b.OpModHVRTMomentaryCessation,
		b.OpModLFRTMustTrip, b.OpModLFRTMayTrip, b.OpModHFRTMustTrip, b.OpModHFRTMayTrip,
	} {
		if l != nil {
			n++
		}
	}
	return n
}

// TestAdminCurve_MultiCurveBindsOneControl is BASIC-004's own shape, end to end
// through the server.
//
// Four curves, ONE DERControl, four resolvable hrefs, four distinct curveTypes
// and four distinct link fields. Every one of those is something the
// conformance row asserts about the bench before it asserts anything about the
// DUT, so every one of them is checked here against the served documents rather
// than against the response JSON alone.
func TestAdminCurve_MultiCurveBindsOneControl(t *testing.T) {
	s := NewServer("")
	body := `{"program":0,"activate":true,"curves":[
	  {"mode":"lvrt_must_trip","x_mult":-2,"y_mult":-2,"y_ref_type":4,
	   "points":[{"x":150,"y":0},{"x":150,"y":5000},{"x":1200,"y":5000},{"x":1200,"y":7000},
	             {"x":2200,"y":7000},{"x":2200,"y":8800},{"x":10000,"y":8800}]},
	  {"mode":"lvrt_momentary_cessation","x_mult":-2,"y_mult":-2,"y_ref_type":4,
	   "points":[{"x":0,"y":6000},{"x":150,"y":6000}]},
	  {"mode":"hvrt_must_trip","x_mult":-2,"y_mult":-2,"y_ref_type":4,
	   "points":[{"x":16,"y":12000},{"x":16,"y":11000},{"x":1200,"y":11000},
	             {"x":1200,"y":10000},{"x":10000,"y":10000}]},
	  {"mode":"hvrt_momentary_cessation","x_mult":-2,"y_mult":-2,"y_ref_type":4,
	   "points":[{"x":0,"y":10000},{"x":1200,"y":10000}]}
	]}`
	out := postCurve(t, s, body)
	if len(out.Curves) != 4 {
		t.Fatalf("the response reports %d curve(s), want 4: %+v", len(out.Curves), out.Curves)
	}
	// The back-compatible pair still names the FIRST curve, for the callers
	// written before this field existed.
	if out.CurveHref != out.Curves[0].CurveHref || out.CurveMRID != out.Curves[0].CurveMRID {
		t.Errorf("curve_href/curve_mrid (%s / %s) do not name the first curve (%s / %s)",
			out.CurveHref, out.CurveMRID, out.Curves[0].CurveHref, out.Curves[0].CurveMRID)
	}

	// ONE control, carrying all four links.
	var ctrls model.ExtendedDERControlList
	getXML(t, s, "/derp/0/derc", &ctrls)
	if len(ctrls.DERControl) != 1 {
		t.Fatalf("/derp/0/derc holds %d control(s), want ONE — the procedure prescribes a single "+
			"DERControl carrying the whole Figure", len(ctrls.DERControl))
	}
	base := ctrls.DERControl[0].DERControlBase
	if n := countCurveLinks(base); n != 4 {
		t.Errorf("the published control carries %d curve link(s), want 4", n)
	}
	for name, link := range map[string]*model.CurveLink{
		"opModLVRTMustTrip":           base.OpModLVRTMustTrip,
		"opModLVRTMomentaryCessation": base.OpModLVRTMomentaryCessation,
		"opModHVRTMustTrip":           base.OpModHVRTMustTrip,
		"opModHVRTMomentaryCessation": base.OpModHVRTMomentaryCessation,
	} {
		if link == nil {
			t.Errorf("the published control carries no <%s>", name)
		}
	}
	// And the element names really are on the WIRE, not merely in a struct: a
	// DUT parses the document.
	doc := rawGET(t, s, "/derp/0/derc")
	for _, el := range []string{
		"opModLVRTMustTrip", "opModLVRTMomentaryCessation",
		"opModHVRTMustTrip", "opModHVRTMomentaryCessation",
	} {
		// The element carries an href ATTRIBUTE, so the open tag is
		// "<opModLVRTMustTrip href=..." and never a bare "<opModLVRTMustTrip>".
		// Matching on the bare form would fail against a perfectly good
		// document, which is a false accusation against the server.
		if !strings.Contains(doc, "<"+el+" ") && !strings.Contains(doc, "<"+el+">") {
			t.Errorf("the served control document carries no <%s> element:\n%s", el, doc)
		}
	}

	// Every href RESOLVES, with the curveType the standard assigns its mode. A
	// link the DUT cannot fetch delivers no curve content at all, and the
	// conformance row's southbound silence would then be unattributable.
	wantType := map[string]uint16{
		"lvrt_must_trip":           model.CurveTypeLVRTMustTrip,
		"lvrt_momentary_cessation": model.CurveTypeLVRTMomentaryCessation,
		"hvrt_must_trip":           model.CurveTypeHVRTMustTrip,
		"hvrt_momentary_cessation": model.CurveTypeHVRTMomentaryCessation,
	}
	var hrefs []string
	for _, c := range out.Curves {
		var served model.DERCurve
		getXML(t, s, c.CurveHref, &served)
		if served.MRID != c.CurveMRID {
			t.Errorf("GET %s serves mRID %q, want the minted %q", c.CurveHref, served.MRID, c.CurveMRID)
		}
		if want := wantType[c.Mode]; served.CurveType != want {
			t.Errorf("the %s curve at %s serves curveType %d, want IEEE 2030.5-2018 p.254's %d",
				c.Mode, c.CurveHref, served.CurveType, want)
		}
		if served.XMultiplier != -2 || served.YMultiplier != -2 {
			t.Errorf("the %s curve serves multipliers %d/%d, want -2/-2 — the multipliers are what make "+
				"16 mean 0.16 s and 12000 mean 120.00 %%", c.Mode, served.XMultiplier, served.YMultiplier)
		}
		if served.YRefType != 4 {
			t.Errorf("the %s curve serves yRefType %d, want Figure 4's 4 (%%setEffectiveV)",
				c.Mode, served.YRefType)
		}
		hrefs = append(hrefs, c.CurveHref)
	}
	// Four DISTINCT hrefs. One reused href would serve one curve under four
	// links and the control would command the same shape on all four axes.
	sort.Strings(hrefs)
	for i := 1; i < len(hrefs); i++ {
		if hrefs[i] == hrefs[i-1] {
			t.Fatalf("two curves were published at the same href %s", hrefs[i])
		}
	}

	// The point count survives: seven breakpoints is Figure 4's own must-trip
	// curve, and a server that truncated would publish a different function.
	var lvrt model.DERCurve
	getXML(t, s, out.Curves[0].CurveHref, &lvrt)
	if len(lvrt.CurveData) != 7 {
		t.Errorf("the LVRT must-trip curve serves %d breakpoint(s), want Figure 4's 7", len(lvrt.CurveData))
	}
}

// TestAdminCurve_SingleCurveShapeStillWorks is the back-compatibility promise.
//
// Every caller written before the `curves` array sends the top-level fields,
// and it must behave exactly as it did: one curve, one control, the same
// response fields populated.
func TestAdminCurve_SingleCurveShapeStillWorks(t *testing.T) {
	s := NewServer("")
	out := postCurve(t, s, `{"program":0,"mode":"volt_var","x_mult":-2,"y_mult":-2,"y_ref_type":3,
	  "open_loop_tms":5,"points":[{"x":9100,"y":4000},{"x":10600,"y":-4000}],"activate":true}`)
	if len(out.Curves) != 1 {
		t.Fatalf("a single-curve POST reported %d curve(s)", len(out.Curves))
	}
	if out.CurveHref == "" || out.CurveMRID == "" || out.MRID == "" {
		t.Fatalf("a single-curve POST left a response field empty: %+v", out)
	}
	var served model.DERCurve
	getXML(t, s, out.CurveHref, &served)
	if served.CurveType != model.CurveTypeVoltVar {
		t.Errorf("curveType %d, want %d", served.CurveType, model.CurveTypeVoltVar)
	}
	if served.OpenLoopTms == nil || *served.OpenLoopTms != 5 {
		t.Errorf("openLoopTms %v, want 5 — the single-curve path still carries every element it did",
			served.OpenLoopTms)
	}
	var ctrls model.ExtendedDERControlList
	getXML(t, s, "/derp/0/derc", &ctrls)
	if len(ctrls.DERControl) != 1 || ctrls.DERControl[0].DERControlBase.OpModVoltVar == nil {
		t.Errorf("the single-curve POST did not bind one volt-var control: %+v", ctrls.DERControl)
	}
}

// TestAdminCurve_RefusesTheAmbiguousAndTheColliding pins the two refusals that
// keep a multi-curve request describable.
//
// A request carrying BOTH shapes has two answers to what it published, and a
// server that picked one would put a control on the wire that the caller's own
// record of the request does not describe. Two entries of one MODE write the
// same DERControlBase field, so the second silently replaces the first and the
// control carries one curve where the caller sent two — while both DERCurve
// resources stay published and fetchable, which is a curve at an href no
// control references.
func TestAdminCurve_RefusesTheAmbiguousAndTheColliding(t *testing.T) {
	s := NewServer("")
	for _, tc := range []struct {
		name, body, want string
	}{
		{
			"both shapes at once",
			`{"program":0,"mode":"volt_var","points":[{"x":1,"y":2}],
			  "curves":[{"mode":"lvrt_must_trip","points":[{"x":150,"y":0}]}],"activate":true}`,
			"BOTH a top-level curve",
		},
		{
			"two entries of one mode",
			`{"program":0,"activate":true,"curves":[
			  {"mode":"lvrt_must_trip","points":[{"x":150,"y":0}]},
			  {"mode":"lvrt_must_trip","points":[{"x":160,"y":0}]}]}`,
			"both carry mode",
		},
		{
			"an unknown mode inside the array",
			`{"program":0,"activate":true,"curves":[
			  {"mode":"lvrt_must_trip","points":[{"x":150,"y":0}]},
			  {"mode":"lfrt_momentary_cessation","points":[{"x":16,"y":5300}]}]}`,
			"curves[1]: mode must be one of",
		},
		{
			// The vRef family is opModVoltVar-only by a SHALL NOT (2018
			// p.252-253) and the check is PER ENTRY: a volt-var entry may carry
			// one and the ride-through entry beside it may not.
			"a vRef on a ride-through entry",
			`{"program":0,"activate":true,"curves":[
			  {"mode":"hvrt_must_trip","points":[{"x":16,"y":12000}],"vref":9500}]}`,
			"curves[0]: vref may only be served on a volt_var curve",
		},
		{
			"a removed x_ref_type inside the array",
			`{"program":0,"activate":true,"curves":[
			  {"mode":"lvrt_must_trip","points":[{"x":150,"y":0}],"x_ref_type":1}]}`,
			"curves[0]: x_ref_type is not a field of this API",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := postCurveErr(t, s, tc.body)
			if !strings.Contains(got, tc.want) {
				t.Errorf("the refusal does not say %q:\n%s", tc.want, got)
			}
		})
	}

	// AND THE BENCH IS LEFT AS IT WAS. A refused request must publish nothing:
	// a caller that asked for the four curves of Figure 4 and got two plus a 400
	// could not tell what state the bench was in.
	var dc model.DERCurveList
	getXML(t, s, "/derp/0/dc", &dc)
	if len(dc.DERCurve) != 1 || dc.DERCurve[0].MRID != "CURVE-VV-001" {
		t.Errorf("a refused multi-curve POST changed the program's curve list (%d entr(ies), first mRID "+
			"%q); every one of the requests above must publish NOTHING",
			len(dc.DERCurve), firstMRID(dc))
	}
}

func firstMRID(l model.DERCurveList) string {
	if len(l.DERCurve) == 0 {
		return ""
	}
	return l.DERCurve[0].MRID
}

// TestAdminCurve_MultiCurveTeardownClearsEveryHref is the multi-curve half of
// the contamination guarantee.
//
// DELETE /admin/curve restores the program's fixture, and a four-curve POST
// leaves FOUR individually-addressable resources behind. A teardown that
// cleared only the first would leave three curves from a finished run fetchable
// at hrefs nothing links — the exact leak the clear exists to remove, three
// times over.
func TestAdminCurve_MultiCurveTeardownClearsEveryHref(t *testing.T) {
	s := NewServer("")
	out := postCurve(t, s, `{"program":1,"activate":true,"curves":[
	  {"mode":"lfrt_must_trip","x_mult":-2,"y_mult":-2,"points":[{"x":16,"y":5300}]},
	  {"mode":"hfrt_must_trip","x_mult":-2,"y_mult":-2,"points":[{"x":16,"y":6500}]}]}`)
	if len(out.Curves) != 2 {
		t.Fatalf("the POST reported %d curve(s), want 2", len(out.Curves))
	}
	status := func(path string) int {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code
	}
	for _, c := range out.Curves {
		if got := status(c.CurveHref); got != http.StatusOK {
			t.Fatalf("GET %s = %d before the teardown; this test cannot show a clear that never had "+
				"anything to clear", c.CurveHref, got)
		}
	}

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec,
		httptest.NewRequest("DELETE", "/admin/curve", bytes.NewReader([]byte(`{"program":1}`))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/curve = %d; body: %s", rec.Code, rec.Body)
	}

	for _, c := range out.Curves {
		if got := status(c.CurveHref); got != http.StatusNotFound {
			t.Errorf("GET %s = %d after the teardown — a curve from a finished run is still served at an "+
				"href nothing links", c.CurveHref, got)
		}
	}
}
