package gridsim

// curvexml_test.go — what a DERCurve looks like ON THE WIRE, against
// sep-2.0.4.xsd rather than against the Go struct that produced it.
//
// Every assertion here is about the DOCUMENT: which elements are present, in
// which order, and which are absent. A decode into csipmodel cannot make any of
// them — Go's xml decoder is order-insensitive and silently tolerates a missing
// element — which is exactly why three schema violations lived in this
// simulator's output for as long as they did.

import (
	"net/http"
	"strings"
	"testing"
)

// derCurveSequence is sep-2.0.4.xsd's DERCurve sequence, in order. The
// IdentifiedObject fields (mRID, description, version) precede it; every
// element below is either minOccurs="1" (must always appear) or minOccurs="0"
// (must appear only when authored).
var derCurveSequence = []struct {
	name      string
	mandatory bool
}{
	{"creationTime", true},
	{"CurveData", true},
	{"curveType", true},
	{"openLoopTms", false},
	{"rampDecTms", false},
	{"rampIncTms", false},
	{"rampPT1Tms", false},
	{"xMultiplier", true},
	{"yMultiplier", true},
	{"yRefType", true},
}

// assertCurveDocument checks one served DERCurve document against the schema's
// sequence, and returns it for any further assertion.
func assertCurveDocument(t *testing.T, raw string) {
	t.Helper()
	last, lastName := -1, ""
	for _, el := range derCurveSequence {
		at := strings.Index(raw, "<"+el.name+">")
		if at < 0 {
			if el.mandatory {
				t.Errorf("the served DERCurve carries no <%s>, and the XSD declares it minOccurs=1:\n%s",
					el.name, raw)
			}
			continue
		}
		if at < last {
			t.Errorf("<%s> is emitted before <%s>, against the XSD's own sequence (%s):\n%s",
				el.name, lastName, "creationTime, CurveData, curveType, openLoopTms, rampDecTms, "+
					"rampIncTms, rampPT1Tms, xMultiplier, yMultiplier, yRefType", raw)
		}
		last, lastName = at, el.name
	}
	// Two elements sep 2.0.4 does not declare on DERCurve at all. The vendored
	// csipmodel struct has fields for both, so nothing but this conversion
	// keeps them off the wire.
	for _, gone := range []string{"vRef", "xRefType"} {
		if strings.Contains(raw, "<"+gone+">") {
			t.Errorf("the served DERCurve carries <%s>, which sep 2.0.4 does not declare on DERCurve:\n%s",
				gone, raw)
		}
	}
}

// TestServedCurve_CarriesEveryMandatoryElementIncludingZeros is M6: a value of
// ZERO is a value, and dropping it produces a document the schema rejects.
//
// BASIC-012's Figure 12 prescribes yMultiplier 0 — "these y values are raw
// percent, unscaled" — and csipmodel tags the field `omitempty`, so the element
// vanished from the wire for the one row whose procedure states it. The same
// applies to xMultiplier and to creationTime, all three minOccurs="1".
func TestServedCurve_CarriesEveryMandatoryElementIncludingZeros(t *testing.T) {
	s := NewServer("")
	// Figure 12's own multipliers: x -2, y 0. The y is the one that used to
	// disappear.
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "freq_watt", "y_ref_type": 1, "x_mult": -2, "y_mult": 0,
		"points": [{"x":5900,"y":100},{"x":6200,"y":0}], "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/derp/0/dc", "/derp/0/dc/0"} {
		raw := serveRaw(t, s, path)
		assertCurveDocument(t, raw)
		if !strings.Contains(raw, "<yMultiplier>0</yMultiplier>") {
			t.Errorf("%s does not carry <yMultiplier>0</yMultiplier> — a zero multiplier is 'no scaling', "+
				"which is what Figure 12 prescribes, and dropping it makes the document invalid:\n%s",
				path, raw)
		}
		if !strings.Contains(raw, "<xMultiplier>-2</xMultiplier>") {
			t.Errorf("%s does not carry the authored xMultiplier:\n%s", path, raw)
		}
	}
}

// TestServedCurve_OptionalTimingAppearsOnlyWhenAuthored is the converse: the
// minOccurs="0" family must NOT be manufactured. A server that emitted
// openLoopTms unconditionally would tell every DUT it had been given a timing
// constraint the procedure never sent.
func TestServedCurve_OptionalTimingAppearsOnlyWhenAuthored(t *testing.T) {
	s := NewServer("")
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "y_ref_type": 3, "x_mult": -2, "y_mult": -2,
		"points": [{"x":9100,"y":4000}], "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}
	raw := serveRaw(t, s, "/derp/0/dc/0")
	assertCurveDocument(t, raw)
	for _, optional := range []string{"openLoopTms", "rampDecTms", "rampIncTms", "rampPT1Tms"} {
		if strings.Contains(raw, "<"+optional+">") {
			t.Errorf("a curve that authored no %s served one anyway:\n%s", optional, raw)
		}
	}

	// And with one authored, it appears — in its schema position, between
	// curveType and xMultiplier.
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "y_ref_type": 3, "x_mult": -2, "y_mult": -2,
		"points": [{"x":9100,"y":4000}], "open_loop_tms": 5, "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}
	raw = serveRaw(t, s, "/derp/0/dc/0")
	assertCurveDocument(t, raw)
	if !strings.Contains(raw, "<openLoopTms>5</openLoopTms>") {
		t.Errorf("the authored openLoopTms is not on the wire:\n%s", raw)
	}
}

// TestServedCurve_StaticFixtureIsSchemaShaped covers the resource no admin call
// creates and every DELETE restores — the one that carried the vRef.
func TestServedCurve_StaticFixtureIsSchemaShaped(t *testing.T) {
	s := NewServer("")
	for _, path := range []string{"/derp/0/dc", "/derp/0/dc/0"} {
		assertCurveDocument(t, serveRaw(t, s, path))
	}
	// After a teardown too: the fixture is re-minted there, and a restored
	// fixture that was invalid would contaminate every row that followed.
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "y_ref_type": 3,
		"points": [{"x":9100,"y":4000}], "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}
	deleteAdmin(t, s, "/admin/curve", `{"program":0}`)
	for _, path := range []string{"/derp/0/dc", "/derp/0/dc/0"} {
		assertCurveDocument(t, serveRaw(t, s, path))
	}
}

// TestServedCurve_OpenLoopTmsDomainIsRefusedInTheSchemasVocabulary is L15: this
// element gets the same error hygiene as opModFreqDroop's five, rather than
// encoding/json's, which names neither the element nor its type.
func TestServedCurve_OpenLoopTmsDomainIsRefusedInTheSchemasVocabulary(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"negative", "-1"},
		{"beyond UInt16", "65536"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer("")
			rec := postAdmin(t, s, "/admin/curve", `{
				"program": 0, "mode": "volt_var", "y_ref_type": 3,
				"points": [{"x":1,"y":2}], "activate": true, "open_loop_tms": `+tc.value+`
			}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST with open_loop_tms %s = %d, want 400; body: %s", tc.value, rec.Code, rec.Body)
			}
			for _, want := range []string{"openLoopTms", "UInt16"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Errorf("the refusal does not name %q, so an operator cannot tell which element or "+
						"which domain: %s", want, rec.Body)
				}
			}
		})
	}
}
