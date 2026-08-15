package gridsim

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// getXML fetches a served resource through the main (non-admin) handler and
// unmarshals it into dst — the same wire path the hub's walker takes.
func getXML(t *testing.T, s *Server, path string, dst any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body: %s", path, rec.Code, rec.Body)
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
}

// A curve POST must make the served /derp/0/derc carry an ExtendedDERControl
// whose DERControlBase links the curve (opModVoltVar → the curve href), and
// must upsert that curve into the served /derp/0/dc with the correct
// Table-19 CurveType. This is the whole point of the endpoint: the hub
// discovers the bound control on its normal walk and resolves the curve link.
func TestAdminCurve_BindsVoltVarIntoServedControl(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	// y_ref_type 3 (%statVarAvail), not the 4 this body used to send: sep 2.0.4
	// makes 4 "%setEffectiveV", a VOLTAGE reference on the VAr axis of a
	// volt-var curve, and opModVoltVar's own documentation restricts the element
	// to {%setMaxW, %setMaxVar, %statVarAvail}. x_ref_type is gone from the API
	// entirely — the schema declares no such element; see TestAdminCurve_XRefTypeIsRejected.
	body := `{
		"program": 0,
		"mode": "volt_var",
		"vref": 240,
		"y_ref_type": 3,
		"points": [{"x":92,"y":30},{"x":98,"y":0},{"x":102,"y":0},{"x":108,"y":-30}],
		"duration_s": 600,
		"activate": true,
		"fixed_var_pct": -12.7
	}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	var created struct {
		MRID      string `json:"mrid"`
		CurveHref string `json:"curve_href"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode POST response: %v", err)
	}
	if created.MRID == "" || created.CurveHref != "/derp/0/dc/0" {
		t.Fatalf("POST response = %+v, want non-empty mrid and curve_href /derp/0/dc/0", created)
	}

	// The served DERControlList (extended) must carry the link.
	var derc model.ExtendedDERControlList
	getXML(t, s, "/derp/0/derc", &derc)
	if len(derc.DERControl) != 1 {
		t.Fatalf("/derp/0/derc has %d controls, want 1", len(derc.DERControl))
	}
	base := derc.DERControl[0].DERControlBase
	if base.OpModVoltVar == nil {
		t.Fatalf("bound control has no opModVoltVar link: %+v", base)
	}
	if base.OpModVoltVar.Href != "/derp/0/dc/0" {
		t.Errorf("opModVoltVar href = %q, want /derp/0/dc/0", base.OpModVoltVar.Href)
	}
	// The fixed_var_pct scalar overlay rides along on the same control.
	if base.OpModFixedVar == nil || base.OpModFixedVar.Value.Value != -13 {
		t.Errorf("opModFixedVar = %+v, want value -13 (rounded from -12.7)", base.OpModFixedVar)
	}
	if derc.DERControl[0].EventStatus == nil || derc.DERControl[0].EventStatus.CurrentStatus != 1 {
		t.Errorf("bound control should be Active (status 1): %+v", derc.DERControl[0].EventStatus)
	}

	// The served curve list must carry the curve with CurveType 0 (Volt-VAr).
	var dc model.DERCurveList
	getXML(t, s, "/derp/0/dc", &dc)
	if len(dc.DERCurve) != 1 {
		t.Fatalf("/derp/0/dc has %d curves, want 1 (replace on activate)", len(dc.DERCurve))
	}
	if dc.DERCurve[0].CurveType != model.CurveTypeVoltVar {
		t.Errorf("curve type = %d, want %d (Volt-VAr)", dc.DERCurve[0].CurveType, model.CurveTypeVoltVar)
	}
	if got := len(dc.DERCurve[0].CurveData); got != 4 {
		t.Errorf("curve has %d points, want 4", got)
	}
	if dc.DERCurve[0].Href != "/derp/0/dc/0" {
		t.Errorf("curve href = %q, want /derp/0/dc/0", dc.DERCurve[0].Href)
	}
	if got := dc.DERCurve[0].YRefType; got != 3 {
		t.Errorf("yRefType = %d, want 3 (%%statVarAvail) — the y-axis reference is what the DUT "+
			"translates into the curve bank's DeptRef, so serving the wrong one commands a "+
			"percentage of a rating nobody nominated", got)
	}
	if got := dc.DERCurve[0].XRefType; got != 0 {
		t.Errorf("xRefType = %d, want 0 (element absent) — sep 2.0.4 declares no xRefType on DERCurve, "+
			"so this server must not put one on the wire", got)
	}

	// GET /admin/status must surface the bound-curve label for the inspector.
	st := adminStatus(t, h)
	if len(st.Programs[0].Active) != 1 {
		t.Fatalf("program 0 active = %d, want 1", len(st.Programs[0].Active))
	}
	if got := st.Programs[0].Active[0].Curve; got != "volt_var -> /derp/0/dc/0" {
		t.Errorf("status curve label = %q, want %q", got, "volt_var -> /derp/0/dc/0")
	}
}

// TestAdminCurve_XRefTypeIsRejected: the removed field is refused loudly, not
// dropped quietly.
//
// sep 2.0.4 declares NO xRefType element on DERCurve, so this server cannot
// serve one and used to serve one anyway. Silently ignoring a request that
// still sets it would leave the caller believing the bench had configured
// something, which on a conformance bench is the same class of defect as
// serving the element in the first place.
func TestAdminCurve_XRefTypeIsRejected(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()
	body := `{"program":0,"mode":"volt_var","points":[{"x":1,"y":2}],"x_ref_type":1,"activate":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/curve with x_ref_type = %d, want 400; body: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "xRefType") {
		t.Errorf("the 400 does not say why: %s", rec.Body)
	}
}

// The four modes must each bind the matching DERControlBase link field with
// the Table-19 curve type the hub expects.
func TestAdminCurve_ModeToLinkAndType(t *testing.T) {
	cases := []struct {
		mode      string
		curveType uint16
		link      func(model.ExtendedDERControlBase) *model.CurveLink
	}{
		{"volt_var", model.CurveTypeVoltVar, func(b model.ExtendedDERControlBase) *model.CurveLink { return b.OpModVoltVar }},
		{"volt_watt", model.CurveTypeVoltWatt, func(b model.ExtendedDERControlBase) *model.CurveLink { return b.OpModVoltWatt }},
		{"freq_watt", model.CurveTypeFreqWatt, func(b model.ExtendedDERControlBase) *model.CurveLink { return b.OpModFreqWatt }},
		{"watt_pf", model.CurveTypeWattPF, func(b model.ExtendedDERControlBase) *model.CurveLink { return b.OpModWattPF }},
		// watt_var is the FIFTH mode, and its absence was a bench gap rather
		// than a scope decision: opModWattVar is the axis SunSpec model 712
		// actually implements, and nothing here could put an <opModWattVar>
		// DERCurveLink on the wire at all — which is how opModWattPF came to be
		// graded against 712 in its place.
		{"watt_var", model.CurveTypeWattVar, func(b model.ExtendedDERControlBase) *model.CurveLink { return b.OpModWattVar }},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			s := NewServer("")
			h := s.AdminHandler()
			body := `{"program":0,"mode":"` + c.mode + `","points":[{"x":1,"y":2}],"activate":true}`
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
			if rec.Code != http.StatusCreated {
				t.Fatalf("POST %s = %d; body: %s", c.mode, rec.Code, rec.Body)
			}
			var derc model.ExtendedDERControlList
			getXML(t, s, "/derp/0/derc", &derc)
			if len(derc.DERControl) != 1 {
				t.Fatalf("%s: derc has %d controls, want 1", c.mode, len(derc.DERControl))
			}
			if link := c.link(derc.DERControl[0].DERControlBase); link == nil || link.Href != "/derp/0/dc/0" {
				t.Errorf("%s: link = %+v, want href /derp/0/dc/0", c.mode, link)
			}
			var dc model.DERCurveList
			getXML(t, s, "/derp/0/dc", &dc)
			if dc.DERCurve[0].CurveType != c.curveType {
				t.Errorf("%s: curve type = %d, want %d", c.mode, dc.DERCurve[0].CurveType, c.curveType)
			}
		})
	}
}

// An invalid mode or out-of-range program is a 400 (fail-closed input gate).
func TestAdminCurve_RejectsBadInput(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()
	for _, body := range []string{
		`{"program":0,"mode":"nonsense","activate":true}`,
		`{"program":9,"mode":"volt_var","activate":true}`,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400", body, rec.Code)
		}
	}
}

// DELETE /admin/curve clears the bound control and restores program 0's
// static Volt-VAr fixture — and the scalar type at the derc/actderc paths, so
// the tree returns to its pre-curve shape.
func TestAdminCurve_DeleteRestoresStatic(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	post := `{"program":0,"mode":"watt_pf","points":[{"x":1,"y":2}],"activate":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(post))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/admin/curve", bytes.NewReader([]byte(`{"program":0}`))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/curve = %d, want 204; body: %s", rec.Code, rec.Body)
	}

	// derc back to an empty scalar list.
	if list, ok := s.resources["/derp/0/derc"].(*model.DERControlList); !ok {
		t.Errorf("/derp/0/derc type = %T, want *model.DERControlList after delete", s.resources["/derp/0/derc"])
	} else if len(list.DERControl) != 0 {
		t.Errorf("/derp/0/derc has %d controls after delete, want 0", len(list.DERControl))
	}
	// dc back to the static Volt-VAr fixture.
	var dc model.DERCurveList
	getXML(t, s, "/derp/0/dc", &dc)
	if len(dc.DERCurve) != 1 || dc.DERCurve[0].MRID != "CURVE-VV-001" {
		t.Errorf("/derp/0/dc not restored to static fixture: %+v", dc.DERCurve)
	}
}

// The scalar /admin/control post must still work after a curve has made
// derc/actderc extended (type-tolerance): the scalar control is widened into
// the extended list rather than dropped.
func TestAdminControl_ToleratesExtendedList(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	// Curve first (makes program 0's derc/actderc extended).
	post := `{"program":0,"mode":"volt_var","points":[{"x":1,"y":2}],"activate":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(post))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d", rec.Code)
	}

	// Now a scalar control with activate=true replaces the list.
	postControl(t, h, `{"program":0,"exp_lim_W":4200,"duration_s":300,"activate":true}`)

	st := adminStatus(t, h)
	if len(st.Programs[0].Active) != 1 {
		t.Fatalf("program 0 active = %d, want 1", len(st.Programs[0].Active))
	}
	got := st.Programs[0].Active[0].Base.ExpLimW
	if got == nil || *got != 4200 {
		t.Fatalf("scalar control after curve: exp_lim_W = %v, want 4200 (control was not dropped)", got)
	}
}

// TestAdminControl_ScalarPostOntoExtendedProgramKeepsResponseAttrs is the
// regression lock for the toExtendedControl bug audit 2026-08-01 found: a
// scalar /admin/control POST onto a program a PRIOR /admin/curve POST had
// already widened to Extended served its control with NO replyTo and NO
// responseRequired at all, because toExtendedControl (curve.go) copied every
// DERControl field except those two. That is indistinguishable on the wire
// from the standing, non-admin-seeded bench fixtures that legitimately omit
// them (buildProgram0's doc), so a conformance criterion reading either
// attribute for an admin-posted control on a curve-bound program got a false
// "not requested"/"not recovered" reading regardless of what gridsim was
// actually told to serve — this is what turned CORE-022's replyTo (assertion
// 3) and Started (assertion 2) criteria degraded once program 0 happened to
// be left curve-bound by earlier bench activity (coreResponsesSpec's doc,
// core.go). TestAdminControl_ToleratesExtendedList above already proves the
// control survives the widening at all; this test proves it survives with
// its RespondableResource attributes intact.
func TestAdminControl_ScalarPostOntoExtendedProgramKeepsResponseAttrs(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	// Curve first (makes program 0's derc/actderc extended) — same precondition
	// as TestAdminControl_ToleratesExtendedList.
	post := `{"program":0,"mode":"volt_var","points":[{"x":1,"y":2}],"activate":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(post))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d", rec.Code)
	}

	// A scalar control, explicit mRID, activate=true, no ResponseRequired
	// override — exactly coreResponsesSpec's Setup shape for CORE-022's
	// completing control.
	postControl(t, h, `{"program":0,"mrid":"CERT-CORE022-regress","exp_lim_W":4000,`+
		`"duration_s":120,"activate":true}`)

	var derc model.ExtendedDERControlList
	getXML(t, s, "/derp/0/derc", &derc)
	if len(derc.DERControl) != 1 {
		t.Fatalf("/derp/0/derc has %d controls, want 1", len(derc.DERControl))
	}
	ctrl := derc.DERControl[0]
	if ctrl.MRID != "CERT-CORE022-regress" {
		t.Fatalf("served control mRID = %q, want CERT-CORE022-regress", ctrl.MRID)
	}
	if ctrl.ReplyTo != adminResponseReplyTo {
		t.Errorf("ReplyTo = %q, want %q (an admin-posted control on an extended program lost its replyTo)",
			ctrl.ReplyTo, adminResponseReplyTo)
	}
	if ctrl.ResponseRequired == nil {
		t.Fatal("ResponseRequired is nil, want present by default (an admin-posted control on an extended " +
			"program lost its responseRequired)")
	}
	if got := uint8(*ctrl.ResponseRequired); got != uint8(adminDefaultResponseRequired) {
		t.Errorf("ResponseRequired = %#02x, want %#02x", got, uint8(adminDefaultResponseRequired))
	}

	// Also verified on the raw wire bytes, not just the unmarshalled struct:
	// the attribute must actually be present in the served XML, not merely
	// zero-valued-but-present in Go (an omitempty pointer would render "00"
	// if set-but-zero, and would render NOTHING if nil — this is the
	// distinction the bug actually turned on).
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `replyTo="`+adminResponseReplyTo+`"`) {
		t.Errorf("raw /derp/0/derc body carries no replyTo attribute: %s", body)
	}
	if !strings.Contains(body, `responseRequired="03"`) {
		t.Errorf("raw /derp/0/derc body carries no responseRequired attribute: %s", body)
	}
}

// TestAdminCurve_IndividualHrefResolves is the lever every curve row's
// attribution depends on.
//
// A curve-linked DERControl carries an HREF, not content. This server minted
// that href and stored only the LIST, so every individual /derp/{p}/dc/{i}
// answered 404: a DUT that followed the link received a link and no curve, and
// the resulting southbound silence was unattributable — "the DUT refused the
// axis" and "the bench served the curve nowhere" look identical from outside.
// critDERCurveResolvable exists to tell those apart and could not, because the
// bench always 404'd.
func TestAdminCurve_IndividualHrefResolves(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	// The static fixture's own href resolves before any admin lever runs: the
	// default tree advertised a curve at /derp/0/dc/0 and did not serve it.
	var fixture model.DERCurve
	getXML(t, s, "/derp/0/dc/0", &fixture)
	if fixture.MRID != "CURVE-VV-001" {
		t.Errorf("the static fixture curve at /derp/0/dc/0 has mRID %q, want CURVE-VV-001", fixture.MRID)
	}

	body := `{"program":1,"mode":"volt_watt","points":[{"x":106,"y":100},{"x":110,"y":20}],` +
		`"y_ref_type":1,"activate":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d; body: %s", rec.Code, rec.Body)
	}
	var minted struct {
		CurveHref string `json:"curve_href"`
		CurveMRID string `json:"curve_mrid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode the POST response: %v", err)
	}

	var got model.DERCurve
	getXML(t, s, minted.CurveHref, &got)
	if got.MRID != minted.CurveMRID {
		t.Errorf("GET %s served mRID %q, want the minted %q", minted.CurveHref, got.MRID, minted.CurveMRID)
	}
	if len(got.CurveData) != 2 || got.CurveData[0].XValue != 106 || got.CurveData[1].YValue != 20 {
		t.Errorf("GET %s served %+v, want the two breakpoints that were posted",
			minted.CurveHref, got.CurveData)
	}
	if got.YRefType != 1 {
		t.Errorf("GET %s served yRefType=%d, want the posted 1", minted.CurveHref, got.YRefType)
	}

	// And the teardown removes it, or the next row grades a bench this one is
	// still driving. Program 1 has no static fixture, so the path goes away
	// entirely; program 0's reverts to the fixture instead (see
	// TestAdminCurve_DeleteRestoresStatic).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/admin/curve", bytes.NewReader([]byte(`{"program":1}`))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/curve = %d, want 204; body: %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", minted.CurveHref, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET %s after the teardown = %d, want 404 — the curve this run published is still "+
			"fetchable", minted.CurveHref, rec.Code)
	}
}

// TestAdminCurve_DeleteReplacesProgramZeroCurveContent pins the OTHER half of
// the teardown, which is not "the path 404s": program 0's static fixture
// legitimately owns /derp/0/dc/0, so a clear must put the FIXTURE back there
// rather than leave the admin-posted curve fetchable at an href the control
// list no longer mentions.
func TestAdminCurve_DeleteReplacesProgramZeroCurveContent(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	body := `{"program":0,"mode":"volt_var","points":[{"x":92,"y":60}],"y_ref_type":3,"activate":true}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d; body: %s", rec.Code, rec.Body)
	}
	var minted struct {
		CurveMRID string `json:"curve_mrid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode the POST response: %v", err)
	}
	var live model.DERCurve
	getXML(t, s, "/derp/0/dc/0", &live)
	if live.MRID != minted.CurveMRID {
		t.Fatalf("/derp/0/dc/0 serves %q, want the posted curve %q", live.MRID, minted.CurveMRID)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/admin/curve", bytes.NewReader([]byte(`{"program":0}`))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/curve = %d, want 204", rec.Code)
	}
	var after model.DERCurve
	getXML(t, s, "/derp/0/dc/0", &after)
	if after.MRID != "CURVE-VV-001" {
		t.Errorf("/derp/0/dc/0 serves %q after the teardown, want the static fixture CURVE-VV-001 — the "+
			"posted curve is still fetchable at an href nothing links", after.MRID)
	}
}

// TestAdminCurve_ActivatingPostDropsTheCurvesItTruncated is the regression for
// the leak that arrives through the PUBLISH path rather than the teardown.
//
// An activating POST truncates the program's list to one entry
// (cl.DERCurve = nil, then append), so republishing 0..len-1 alone republishes
// only /dc/0 — and every /dc/{i} above it that a previous POST minted stays in
// the resource map, served, at an href the list no longer mentions. A DUT that
// remembered the old link (or a walker that had already fetched the list) goes
// on resolving a curve from a run that is over, which is precisely the
// contamination DELETE /admin/curve exists to prevent, one entry point along.
//
// The check is that the old indices are GONE, not merely that /dc/0 is right:
// the whole failure mode is invisible from the list.
func TestAdminCurve_ActivatingPostDropsTheCurvesItTruncated(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	post := func(body string) map[string]string {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/curve", bytes.NewReader([]byte(body))))
		if rec.Code != http.StatusCreated {
			t.Fatalf("POST /admin/curve = %d; body: %s", rec.Code, rec.Body)
		}
		var got map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode the POST response: %v", err)
		}
		return got
	}
	status := func(path string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code
	}

	// Program 1 has no static fixture, so every curve at /derp/1/dc/{i} got
	// there through this endpoint and nothing else can be blamed for it.
	// APPEND three, so the list holds indices 0, 1 and 2.
	var minted []map[string]string
	for _, mode := range []string{"volt_var", "volt_watt", "watt_pf"} {
		minted = append(minted, post(`{"program":1,"mode":"`+mode+
			`","points":[{"x":1,"y":2}],"activate":false}`))
	}
	for i, m := range minted {
		if got := status(m["curve_href"]); got != http.StatusOK {
			t.Fatalf("GET %s (curve %d) = %d before the truncating POST; this test cannot show a drop "+
				"that never had anything to drop", m["curve_href"], i, got)
		}
	}
	if want := "/derp/1/dc/2"; minted[2]["curve_href"] != want {
		t.Fatalf("the third append landed at %s, want %s", minted[2]["curve_href"], want)
	}

	// Now the truncating POST: activate=true replaces the list with ONE curve.
	fresh := post(`{"program":1,"mode":"freq_watt","points":[{"x":5900,"y":100}],"activate":true}`)
	if want := "/derp/1/dc/0"; fresh["curve_href"] != want {
		t.Fatalf("the activating POST landed at %s, want %s", fresh["curve_href"], want)
	}

	// The list holds exactly the new curve...
	var dc model.DERCurveList
	getXML(t, s, "/derp/1/dc", &dc)
	if len(dc.DERCurve) != 1 || dc.DERCurve[0].MRID != fresh["curve_mrid"] {
		t.Fatalf("/derp/1/dc holds %d curve(s) (%+v), want only the activating POST's %s",
			len(dc.DERCurve), dc.DERCurve, fresh["curve_mrid"])
	}
	// ...and the indices it truncated away are GONE from the resource map, not
	// merely absent from the list.
	for _, href := range []string{"/derp/1/dc/1", "/derp/1/dc/2"} {
		if got := status(href); got != http.StatusNotFound {
			t.Errorf("GET %s = %d after an activating POST truncated the list to one entry — a curve from "+
				"a finished run is still being served at an href nothing links", href, got)
		}
	}
	// Index 0 is republished with the NEW content, never left holding the old.
	var live model.DERCurve
	getXML(t, s, "/derp/1/dc/0", &live)
	if live.MRID != fresh["curve_mrid"] {
		t.Errorf("/derp/1/dc/0 serves %q, want the activating POST's %q", live.MRID, fresh["curve_mrid"])
	}
	if live.CurveType != model.CurveTypeFreqWatt {
		t.Errorf("/derp/1/dc/0 serves curveType %d, want the freq_watt POST's %d",
			live.CurveType, model.CurveTypeFreqWatt)
	}
}
