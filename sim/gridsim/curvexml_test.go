package gridsim

// curvexml_test.go — what a DERCurve looks like ON THE WIRE, against IEEE Std
// 2030.5-2018 rather than against the Go struct that produced it.
//
// Every assertion here is about the DOCUMENT: which elements are present, in
// which order, and which are absent. A decode into csipmodel cannot make any of
// them — Go's xml decoder is order-insensitive and silently tolerates a missing
// element — which is exactly why the violations this file pins lived in this
// simulator's output for as long as they did.
//
// RE-ANCHORED 2026-08-15 (IW15-027), and this file is the reason the anchor
// correction needed a sweep rather than a targeted edit. It carried TWO wrong
// claims, and neither was a comment:
//
//   - derCurveSequence held the DRAFT's ten elements, so the three the standard
//     declares and this bench had just been taught to serve
//     (autonomousVRefEnable, autonomousVRefTimeConstant, vRef) had no position
//     to be checked in. A curve emitting them in the wrong slot would have
//     passed.
//   - assertCurveDocument asserted that <vRef> must be ABSENT from every served
//     DERCurve, "which sep 2.0.4 does not declare". IEEE 2030.5-2018 declares it
//     at p.253. That assertion was FALSE and LATENT: it passed only because no
//     test in this file authored a vRef, and it would have fired the first time
//     a row did — telling its author the standard forbids an element the
//     standard requires them to handle.
//
// The second one is the sharper lesson. A stale comment misleads a reader; a
// stale ASSERTION conscripts the test suite into enforcing the error. This file
// and TestAdminCurve_VRefFamilyIsServedOnVoltVar (curve_test.go) were, for two
// commits, two assertions in one package that disagreed about whether the same
// element was legal.

import (
	"net/http"
	"strings"
	"testing"
)

// derCurveSequence is IEEE Std 2030.5-2018's DERCurve sequence, in order
// (p.252-253, case-insensitively alphabetical over the standard's own attribute
// names — see lexa-proto NORMATIVE_ANCHOR.md §1.4 for how that order is derived
// and why it is flagged as the census's one inference).
//
// The IdentifiedObject fields (mRID, description, version) precede it; every
// element below is either [1] (must always appear, zero included) or [0..1]
// (must appear only when authored).
//
// THIRTEEN elements, not the draft schema's ten. The three at the top and
// middle — autonomousVRefEnable, autonomousVRefTimeConstant, vRef — are the ones
// IW15-027 restored, and their POSITIONS are the half a struct field cannot
// pin: DERCurve is an xs:sequence, so a document with all thirteen present and
// two transposed is one a validating peer rejects with every element in it
// legal.
var derCurveSequence = []struct {
	name      string
	mandatory bool
}{
	// [0..1], and FIRST: "autonomousvref..." sorts ahead of "creationtime".
	{"autonomousVRefEnable", false},
	{"autonomousVRefTimeConstant", false},
	{"creationTime", true},
	{"CurveData", true},
	{"curveType", true},
	{"openLoopTms", false},
	{"rampDecTms", false},
	{"rampIncTms", false},
	{"rampPT1Tms", false},
	// [0..1], between rampPT1Tms and xMultiplier.
	{"vRef", false},
	{"xMultiplier", true},
	{"yMultiplier", true},
	{"yRefType", true},
}

// assertCurveDocument checks one served DERCurve document against the schema's
// sequence, and returns it for any further assertion.
func assertCurveDocument(t *testing.T, raw string) {
	t.Helper()
	var order []string
	for _, el := range derCurveSequence {
		order = append(order, el.name)
	}
	last, lastName := -1, ""
	for _, el := range derCurveSequence {
		at := strings.Index(raw, "<"+el.name+">")
		if at < 0 {
			if el.mandatory {
				t.Errorf("the served DERCurve carries no <%s>, and IEEE Std 2030.5-2018 p.253 declares "+
					"it [1]:\n%s", el.name, raw)
			}
			continue
		}
		if at < last {
			t.Errorf("<%s> is emitted before <%s>, against IEEE 2030.5-2018's own sequence (%s):\n%s",
				el.name, lastName, strings.Join(order, ", "), raw)
		}
		last, lastName = at, el.name
	}
	// THE one element no revision declares on DERCurve: not 2018 (p.252-253),
	// not 2023 (p.265-266), not the vendored draft.
	//
	// vRef WAS ON THIS LIST until 2026-08-15, and that was the defect (see the
	// file doc). csipmodel no longer has an XRefType field at all, so nothing
	// can put one here by accident any more — this guards the BYTES against a
	// future hand-written emitter rather than against the shared struct.
	for _, gone := range []string{"xRefType"} {
		if strings.Contains(raw, "<"+gone+">") {
			t.Errorf("the served DERCurve carries <%s>, which NO revision of IEEE 2030.5 declares on "+
				"DERCurve:\n%s", gone, raw)
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
// creates and every DELETE restores — the one that carried <vRef>240</vRef>.
//
// That value is still gone and is still meant to be, but for the corrected
// reason: vRef is a PerCent — "hundredths of a percent, 0 to 10 000" (2018
// p.167) — so 240 was a VOLTS reading in a percentage element, which under 2018
// p.250 scaled every breakpoint of the default curve to 2.4 % of itself. The
// element was real; the number was the defect.
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

// TestDERCurveSequence_IsThe2018ElementSetInThe2018Order guards the TABLE the
// checker above walks, which nothing else does.
//
// assertCurveDocument can only be as right as derCurveSequence, and a sequence
// that silently loses an element stops checking it while every test that calls
// the checker goes on passing — which is exactly the state this file was in
// between the vRef restoration and IW15-027's sweep. So the table's own shape is
// asserted: the full 2018 element set, in case-insensitive alphabetical order,
// with the mandatory flags the standard's cardinalities give them.
func TestDERCurveSequence_IsThe2018ElementSetInThe2018Order(t *testing.T) {
	// IEEE Std 2030.5-2018 p.252-253, DERCurve's thirteen attributes with their
	// cardinalities. Written out here rather than derived from the table under
	// test — a check that rebuilt its expectation from its subject would pass
	// on any subject.
	want := []struct {
		name      string
		mandatory bool
	}{
		{"autonomousVRefEnable", false},       // p.252, boolean [0..1]
		{"autonomousVRefTimeConstant", false}, // p.253, UInt32 [0..1]
		{"creationTime", true},                // p.253, TimeType [1]
		{"CurveData", true},                   // p.253-254, [1..10]
		{"curveType", true},                   // p.253, DERCurveType [1]
		{"openLoopTms", false},                // p.253, UInt16 [0..1]
		{"rampDecTms", false},                 // p.253, UInt16 [0..1]
		{"rampIncTms", false},                 // p.253, UInt16 [0..1]
		{"rampPT1Tms", false},                 // p.253, UInt16 [0..1]
		{"vRef", false},                       // p.253, PerCent [0..1]
		{"xMultiplier", true},                 // p.253, PowerOfTenMultiplierType [1]
		{"yMultiplier", true},                 // p.253, PowerOfTenMultiplierType [1]
		{"yRefType", true},                    // p.253, DERUnitRefType [1]
	}
	if len(derCurveSequence) != len(want) {
		t.Fatalf("derCurveSequence has %d elements; IEEE 2030.5-2018 p.252-253 declares %d on DERCurve. "+
			"An element missing from this table is an element assertCurveDocument silently stops "+
			"checking, which is how <vRef> came to be asserted ABSENT for two commits after this bench "+
			"learned to serve it", len(derCurveSequence), len(want))
	}
	for i, w := range want {
		got := derCurveSequence[i]
		if got.name != w.name {
			t.Errorf("derCurveSequence[%d] = %q, want %q — the sequence is case-insensitively "+
				"alphabetical (2018 p.252-253) and DERCurve is an xs:sequence, so this order is the "+
				"document's validity and not a preference", i, got.name, w.name)
		}
		if got.mandatory != w.mandatory {
			t.Errorf("derCurveSequence[%d] (%s) mandatory = %t, want %t per the standard's cardinality",
				i, w.name, got.mandatory, w.mandatory)
		}
	}
	// The order claim, checked as a property rather than only element by
	// element: case-insensitive alphabetical is the RULE the sequence is
	// derived from, so a future addition that lands in the wrong slot fails
	// here even if someone updates `want` to match it.
	for i := 1; i < len(derCurveSequence); i++ {
		prev, cur := strings.ToLower(derCurveSequence[i-1].name), strings.ToLower(derCurveSequence[i].name)
		if prev >= cur {
			t.Errorf("derCurveSequence is not case-insensitively alphabetical at %d: %q then %q",
				i, derCurveSequence[i-1].name, derCurveSequence[i].name)
		}
	}
}
