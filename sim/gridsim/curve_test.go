package gridsim

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
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

	body := `{
		"program": 0,
		"mode": "volt_var",
		"vref": 240,
		"x_ref_type": 1,
		"y_ref_type": 4,
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

	// GET /admin/status must surface the bound-curve label for the inspector.
	st := adminStatus(t, h)
	if len(st.Programs[0].Active) != 1 {
		t.Fatalf("program 0 active = %d, want 1", len(st.Programs[0].Active))
	}
	if got := st.Programs[0].Active[0].Curve; got != "volt_var -> /derp/0/dc/0" {
		t.Errorf("status curve label = %q, want %q", got, "volt_var -> /derp/0/dc/0")
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
