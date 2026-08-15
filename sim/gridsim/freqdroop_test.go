package gridsim

// freqdroop_test.go — the opModFreqDroop and openLoopTms levers (curve plan
// #32), proved on the WIRE rather than at the request struct.
//
// Every assertion below fetches the resource back through the main handler and
// decodes it with the vendored csipmodel, so what is pinned is what a DUT would
// receive. A test that inspected s.resources directly would pass on a server
// that had stored the element and never served it, which is the one failure
// mode these levers exist to make impossible: the rows they unblock hold
// themselves at FAIL precisely because the bench could not put the element on
// the wire.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// postAdmin drives one admin endpoint and returns the recorder, so a test can
// assert on the status as well as on the effect.
func postAdmin(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("POST", path, bytes.NewReader([]byte(body))))
	return rec
}

// figure12Droop is CSIP CTP v1.3 Figure 12's own Test Values column, in sep
// 2.0.4's units — the body BASIC-012 sends. Written once here so the round-trip
// and the teardown test cannot drift apart.
const figure12Droop = `"freq_droop":{"dbof":60030,"dbuf":59970,"kof":40,"kuf":40,"open_loop_tms":600}`

// TestFreqDroop_GoldenRoundTripThroughTheSchemasOwnDecode is the lever's
// primary proof: what this server serves decodes, through the CORRECTED
// csipmodel (lexa-proto 8a65431/R4a), back into the five values it was told to
// send, in the schema's own element order.
//
// The round trip is the whole assertion. The predecessor of this element
// decoded a conformant opModFreqDroop into four zeros with no error raised —
// a droop with no dead band and no gain, which is a real and aggressive machine
// rather than an absent setting — because the struct declared four element
// names no revision of IEEE 2030.5 contains. Encoding and decoding through the
// corrected
// model, and checking the ORDER of the elements on the wire, is what shows this
// lever is not emitting the same class of defect from the other side.
func TestFreqDroop_GoldenRoundTripThroughTheSchemasOwnDecode(t *testing.T) {
	s := NewServer("")
	rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "freq_watt", "y_ref_type": 1,
		"x_mult": -2, "y_mult": 0,
		"points": [{"x":5900,"y":100},{"x":5950,"y":80},{"x":6050,"y":80},{"x":6200,"y":0}],
		"duration_s": 600, "activate": true,
		`+figure12Droop+`
	}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d, want 201; body: %s", rec.Code, rec.Body)
	}

	// ── the DECODE half: through csipmodel, off the served wire ──
	var derc model.ExtendedDERControlList
	getXML(t, s, "/derp/0/derc", &derc)
	if len(derc.DERControl) != 1 {
		t.Fatalf("/derp/0/derc has %d controls, want 1", len(derc.DERControl))
	}
	base := derc.DERControl[0].DERControlBase
	if base.OpModFreqWatt == nil {
		t.Error("the control carries no opModFreqWatt link; Figure 12 prescribes the curve and the droop " +
			"on ONE DERControl, and splitting them would make the row's procedure unfollowable")
	}
	fd := base.OpModFreqDroop
	if fd == nil {
		t.Fatal("the served control carries NO opModFreqDroop; the whole point of this lever is that the " +
			"element reaches the DUT")
	}
	if want := (model.FreqDroop{DBOF: 60030, DBUF: 59970, KOF: 40, KUF: 40, OpenLoopTms: 600}); *fd != want {
		t.Errorf("the served opModFreqDroop decodes to %+v, want %+v — all five children are minOccurs=1 "+
			"and a decode that loses one is a wrong decode, not a partial one", *fd, want)
	}

	// ── the ORDER half: raw XML, against the XSD's own sequence ──
	raw := serveRaw(t, s, "/derp/0/derc")
	el := strings.Index(raw, "<opModFreqDroop>")
	if el < 0 {
		t.Fatal("the served XML carries no <opModFreqDroop> element at all")
	}
	inner := raw[el:]
	if end := strings.Index(inner, "</opModFreqDroop>"); end >= 0 {
		inner = inner[:end]
	}
	// FreqDroopType's sequence: dBOF, dBUF, kOF, kUF, openLoopTms. IEEE Std
	// 2030.5-2018 p.242 and Figure B.37 p.240, which the draft schema and
	// 2030.5-2023 p.269-270 agree with element for element (NORMATIVE_ANCHOR.md
	// §3.5) — one of the places all three documents say the same thing.
	last := -1
	for _, child := range []string{"<dBOF>", "<dBUF>", "<kOF>", "<kUF>", "<openLoopTms>"} {
		at := strings.Index(inner, child)
		if at < 0 {
			t.Errorf("the served opModFreqDroop is missing %s", child)
			continue
		}
		if at < last {
			t.Errorf("the served opModFreqDroop emits %s out of the schema's sequence (dBOF, dBUF, kOF, "+
				"kUF, openLoopTms):\n%s", child, inner)
		}
		last = at
	}
}

// TestFreqDroop_IsAuthoredWholeOrRefused pins the whole-or-nothing rule.
//
// All five children are minOccurs="1". A server that completed a partial
// element with zeros would put a droop with NO dead band and NO gain on the
// wire — a real machine, and not the one the caller asked for — inside
// documents used to certify conformance. So a partial request is 400 and
// NOTHING is published: not the droop, and not the curve that was riding with
// it, because a caller left holding one half of Figure 12 plus an error could
// not tell which state the bench was in.
func TestFreqDroop_IsAuthoredWholeOrRefused(t *testing.T) {
	for _, tc := range []struct {
		name, droop, wantMsg string
	}{
		{"missing kUF", `{"dbof":60030,"dbuf":59970,"kof":40,"open_loop_tms":600}`, "kuf"},
		{"missing everything but a brace", `{}`, "dbof"},
		{"dead band beyond UInt32", `{"dbof":4294967296,"dbuf":1,"kof":1,"kuf":1,"open_loop_tms":1}`,
			"UInt32"},
		{"negative gain", `{"dbof":1,"dbuf":1,"kof":-1,"kuf":1,"open_loop_tms":1}`, "UInt16"},
		{"response time beyond UInt16", `{"dbof":1,"dbuf":1,"kof":1,"kuf":1,"open_loop_tms":65536}`,
			"UInt16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer("")
			// The tree already serves standing bench controls, so "nothing was
			// published" is a DELTA against what was there before the refused
			// POST — not an empty list.
			before := serveRaw(t, s, "/derp/0/derc")
			rec := postAdmin(t, s, "/admin/curve", `{
				"program": 0, "mode": "freq_watt", "y_ref_type": 1,
				"points": [{"x":5900,"y":100}], "activate": true,
				"freq_droop":`+tc.droop+`
			}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST with %s = %d, want 400; body: %s", tc.name, rec.Code, rec.Body)
			}
			if !strings.Contains(strings.ToLower(rec.Body.String()), strings.ToLower(tc.wantMsg)) {
				t.Errorf("the refusal does not name %q, so an operator cannot tell which element or which "+
					"domain: %s", tc.wantMsg, rec.Body)
			}
			// And NOTHING was published — the curve half must not survive the
			// refusal of the droop half. A caller left holding one half of
			// Figure 12 plus a 400 cannot tell which state the bench is in, and
			// the row would report the run as made.
			if after := serveRaw(t, s, "/derp/0/derc"); after != before {
				t.Errorf("a refused droop still changed the served control list; a half-authored Figure is "+
					"worse than none:\nbefore: %s\nafter:  %s", before, after)
			}
			if raw := serveRaw(t, s, "/derp/0/dc"); strings.Contains(raw, "freq") ||
				strings.Contains(raw, "curveType>1<") {
				t.Errorf("a refused droop still published its curve:\n%s", raw)
			}
		})
	}
}

// TestFreqDroop_RidesTheScalarControlAndTheDefault proves the other two
// carriers. Figure 12 prescribes the droop on a DERControl; a droop is also a
// standing protective function, so the DefaultDERControl carries it too.
//
// Both storage paths WIDEN their resource to the extended type — the element
// exists nowhere else — and both must still SERVE under the same element names,
// which is what the decode below checks.
func TestFreqDroop_RidesTheScalarControlAndTheDefault(t *testing.T) {
	t.Run("POST /admin/control", func(t *testing.T) {
		s := NewServer("")
		rec := postAdmin(t, s, "/admin/control", `{
			"program": 0, "mrid": "CERT-DROOP-1", "duration_s": 600, "activate": true,
			"max_lim_W": 6000,
			`+figure12Droop+`
		}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("POST /admin/control = %d, want 201; body: %s", rec.Code, rec.Body)
		}
		var derc model.ExtendedDERControlList
		getXML(t, s, "/derp/0/derc", &derc)
		if len(derc.DERControl) != 1 {
			t.Fatalf("/derp/0/derc has %d controls, want 1", len(derc.DERControl))
		}
		base := derc.DERControl[0].DERControlBase
		if base.OpModFreqDroop == nil || base.OpModFreqDroop.DBOF != 60030 {
			t.Errorf("the scalar control's droop = %+v, want the Figure's dBOF 60030", base.OpModFreqDroop)
		}
		// The scalar fields must survive the widening — a control that lost its
		// opModMaxLimW on the way into extended storage would be a different
		// command, and this is exactly the drop toExtendedControl once had.
		if base.OpModMaxLimW == nil || base.OpModMaxLimW.Value != 6000 {
			t.Errorf("the widened control lost its opModMaxLimW: %+v", base.OpModMaxLimW)
		}
		if derc.DERControl[0].ReplyTo == "" || derc.DERControl[0].ResponseRequired == nil {
			t.Error("the widened control lost its replyTo/responseRequired, which is indistinguishable on " +
				"the wire from a standing fixture that legitimately omits them")
		}
	})

	t.Run("POST /admin/default", func(t *testing.T) {
		s := NewServer("")
		rec := postAdmin(t, s, "/admin/default", `{"program":0,"base":{`+figure12Droop+`}}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("POST /admin/default = %d, want 204; body: %s", rec.Code, rec.Body)
		}
		var dderc model.ExtendedDefaultDERControl
		getXML(t, s, "/derp/0/dderc", &dderc)
		if dderc.DERControlBase.OpModFreqDroop == nil {
			t.Fatal("the served DefaultDERControl carries no opModFreqDroop")
		}
		if got := dderc.DERControlBase.OpModFreqDroop.KUF; got != 40 {
			t.Errorf("the default's droop kUF = %d, want 40", got)
		}
		// The element name on the wire is unchanged by the widening: a DUT
		// walking the tree must not be able to tell which Go type this server
		// happened to store.
		if raw := serveRaw(t, s, "/derp/0/dderc"); !strings.Contains(raw, "<DefaultDERControl") {
			t.Errorf("the widened default no longer serves under <DefaultDERControl>:\n%s", raw)
		}
		// And the admin read-back sees it, rather than 404ing on a resource it
		// just accepted.
		grec := httptest.NewRecorder()
		s.AdminHandler().ServeHTTP(grec, httptest.NewRequest("GET", "/admin/default?program=0", nil))
		if grec.Code != http.StatusOK {
			t.Fatalf("GET /admin/default = %d, want 200", grec.Code)
		}
		var info adminBaseInfo
		if err := json.Unmarshal(grec.Body.Bytes(), &info); err != nil {
			t.Fatalf("decode /admin/default: %v", err)
		}
		if info.FreqDroop == nil || info.FreqDroop.DBOF != 60030 {
			t.Errorf("the admin read-back of the default does not carry the droop: %+v", info.FreqDroop)
		}
	})
}

// TestFreqDroop_TeardownRemovesIt is the teardown half of the lever, and it
// covers both directions the new content can be left behind in.
//
// A teardown that leaves an authored element on the bench is evidence
// contamination for every row that follows — the exact failure the suite's
// cleanup work was built to end. The droop rides a control (cleared by DELETE
// /admin/curve and DELETE /admin/control) and, separately, the DefaultDERControl
// (cleared by the default endpoint's own `clear`), and the second also has to
// put the resource's TYPE back, or the tree is not the one the golden pins.
func TestFreqDroop_TeardownRemovesIt(t *testing.T) {
	t.Run("from a curve-bound control", func(t *testing.T) {
		s := NewServer("")
		if rec := postAdmin(t, s, "/admin/curve", `{
			"program": 0, "mode": "freq_watt", "y_ref_type": 1,
			"points": [{"x":5900,"y":100}], "activate": true, `+figure12Droop+`
		}`); rec.Code != http.StatusCreated {
			t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
		}
		deleteAdmin(t, s, "/admin/curve", `{"program":0}`)
		if raw := serveRaw(t, s, "/derp/0/derc"); strings.Contains(raw, "opModFreqDroop") {
			t.Errorf("the droop is still served after DELETE /admin/curve:\n%s", raw)
		}
	})

	t.Run("from a scalar control", func(t *testing.T) {
		s := NewServer("")
		if rec := postAdmin(t, s, "/admin/control", `{
			"program": 0, "duration_s": 600, "activate": true, `+figure12Droop+`
		}`); rec.Code != http.StatusCreated {
			t.Fatalf("POST /admin/control = %d: %s", rec.Code, rec.Body)
		}
		deleteAdmin(t, s, "/admin/control", `{"program":0}`)
		if raw := serveRaw(t, s, "/derp/0/derc"); strings.Contains(raw, "opModFreqDroop") {
			t.Errorf("the droop is still served after DELETE /admin/control:\n%s", raw)
		}
	})

	t.Run("from the DefaultDERControl, type and all", func(t *testing.T) {
		s := NewServer("")
		// The type this server STARTS with, read the same way the assertion
		// below reads it — so the failure message names the thing teardown was
		// supposed to restore rather than a rendering of some XML.
		s.mu.RLock()
		started := fmt.Sprintf("%T", s.resources["/derp/0/dderc"])
		s.mu.RUnlock()

		if rec := postAdmin(t, s, "/admin/default", `{"program":0,"base":{`+figure12Droop+`}}`); rec.Code !=
			http.StatusNoContent {
			t.Fatalf("POST /admin/default = %d: %s", rec.Code, rec.Body)
		}
		// The fixture has to have WIDENED, or the narrowing assertion below
		// would pass against a server that never stored an extended resource.
		s.mu.RLock()
		_, widened := s.resources["/derp/0/dderc"].(*model.ExtendedDefaultDERControl)
		s.mu.RUnlock()
		if !widened {
			t.Fatalf("a droop-carrying default was not stored as the extended type, so this teardown "+
				"proves nothing (it is %s)", started)
		}

		if rec := postAdmin(t, s, "/admin/default", `{"program":0,"clear":true}`); rec.Code !=
			http.StatusNoContent {
			t.Fatalf("POST /admin/default clear = %d: %s", rec.Code, rec.Body)
		}
		if raw := serveRaw(t, s, "/derp/0/dderc"); strings.Contains(raw, "opModFreqDroop") {
			t.Errorf("the droop is still served after a default clear:\n%s", raw)
		}
		// The RESOURCE TYPE goes back too. A program left holding an extended
		// resource with an empty base is not the tree this server starts with,
		// and the next reader to type-assert it would find something else.
		s.mu.RLock()
		now := fmt.Sprintf("%T", s.resources["/derp/0/dderc"])
		s.mu.RUnlock()
		if now != started {
			t.Errorf("a cleared default is stored as %s; teardown must leave the tree as it found it, "+
				"which was %s", now, started)
		}
	})
}

// TestOpenLoopTms_IsServedOnTheCurveAndClearedByTeardown is the other #32
// lever, end to end.
//
// It belongs on the DERCurve rather than on the control — IEEE Std 2030.5-2018
// p.253 declares it an attribute of DERCurve, and CSIP CTP v1.3's Figure 6 names
// it "opModVoltVar.DERCurve.openLoopTms"
// for that reason — so a lever that put it on the control would be sending a
// different document.
func TestOpenLoopTms_IsServedOnTheCurveAndClearedByTeardown(t *testing.T) {
	s := NewServer("")
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "y_ref_type": 3, "x_mult": -2, "y_mult": -2,
		"points": [{"x":9100,"y":4000},{"x":9570,"y":0},{"x":10400,"y":0},{"x":10600,"y":-4000}],
		"activate": true, "open_loop_tms": 5
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}

	var curve model.DERCurve
	getXML(t, s, "/derp/0/dc/0", &curve)
	if curve.OpenLoopTms == nil {
		t.Fatal("the served DERCurve carries no openLoopTms; Figure 6 prescribes 5 against its own " +
			"default of 10, so a DUT that received no element was offered the DEFAULT condition")
	}
	if *curve.OpenLoopTms != 5 {
		t.Errorf("the served openLoopTms = %d, want 5", *curve.OpenLoopTms)
	}
	// Position, against the XSD's sequence: openLoopTms falls after curveType
	// and before the multipliers.
	raw := serveRaw(t, s, "/derp/0/dc/0")
	olt, xm := strings.Index(raw, "<openLoopTms>"), strings.Index(raw, "<xMultiplier>")
	if olt < 0 || xm < 0 || olt > xm {
		t.Errorf("openLoopTms is not emitted before xMultiplier as the schema's DERCurve sequence "+
			"requires:\n%s", raw)
	}
	// 0 is "no limit" — a real value, distinguishable from absence.
	s2 := NewServer("")
	if rec := postAdmin(t, s2, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "y_ref_type": 3,
		"points": [{"x":9100,"y":4000}], "activate": true, "open_loop_tms": 0
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve (0) = %d: %s", rec.Code, rec.Body)
	}
	var zero model.DERCurve
	getXML(t, s2, "/derp/0/dc/0", &zero)
	if zero.OpenLoopTms == nil || *zero.OpenLoopTms != 0 {
		t.Errorf("openLoopTms=0 was not served as an element (%v); 0 means 'no limit' and is not the "+
			"same document as omitting the element", zero.OpenLoopTms)
	}
	// A request that never mentions it must not gain one.
	s3 := NewServer("")
	if rec := postAdmin(t, s3, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "y_ref_type": 3,
		"points": [{"x":9100,"y":4000}], "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve (absent) = %d: %s", rec.Code, rec.Body)
	}
	if raw := serveRaw(t, s3, "/derp/0/dc/0"); strings.Contains(raw, "openLoopTms") {
		t.Errorf("a curve POST that carried no open_loop_tms served one anyway:\n%s", raw)
	}

	// Teardown: the curve resource goes back to the static fixture, timing
	// element included.
	deleteAdmin(t, s, "/admin/curve", `{"program":0}`)
	if raw := serveRaw(t, s, "/derp/0/dc/0"); strings.Contains(raw, "openLoopTms") {
		t.Errorf("the authored openLoopTms survives teardown at /derp/0/dc/0:\n%s", raw)
	}
}

// serveRaw fetches a resource through the main handler and returns the XML as
// text, for assertions about the DOCUMENT (element presence, element order)
// that a decode into a struct cannot make.
func serveRaw(t *testing.T, s *Server, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body: %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// deleteAdmin issues a teardown DELETE with the program in the BODY, which is
// where every admin DELETE on this server reads it from.
func deleteAdmin(t *testing.T, s *Server, path, body string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("DELETE", path, bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE %s = %d, want 204; body: %s", path, rec.Code, rec.Body)
	}
}
