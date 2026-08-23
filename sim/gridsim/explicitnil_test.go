package gridsim

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// ── the oracle's own document reader ─────────────────────────────────────────
//
// Everything below decodes the SERVED BYTES with encoding/xml and asserts on
// what came out. It shares no code with the emitter, deliberately: an oracle
// that reuses the splice's own notion of "where the children are" would agree
// with the emitter about a document neither of them reads correctly. Going
// through a real decoder also makes well-formedness a precondition of every
// assertion here rather than a separate test — a document that does not parse
// fails before any element is looked at.

const xsiNS = "http://www.w3.org/2001/XMLSchema-instance"

// baseChild is one top-level child element of a DERControlBase, as a decoder
// sees it: its name, its character content, and whether it carries the
// xsi:nil="true" marker with the xsi prefix RESOLVED to the XMLSchema-instance
// namespace. Resolution is the point — a document that spells the attribute
// without binding the prefix is not an explicit nil, it is a stray attribute,
// and only a namespace-aware reader tells the two apart.
type baseChild struct {
	name    string
	text    string
	nilMark bool
}

// controlBases decodes doc and returns, per DERControl mRID, the top-level
// children of that control's DERControlBase in document order.
func controlBases(t *testing.T, doc string) map[string][]baseChild {
	t.Helper()
	out := map[string][]baseChild{}

	dec := xml.NewDecoder(strings.NewReader(doc))
	var stack []string
	var mrid string
	var kids []baseChild
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the served document does not parse, so nothing below it can be schema-valid: %v\n%s",
				err, doc)
		}
		switch tv := tok.(type) {
		case xml.StartElement:
			stack = append(stack, tv.Name.Local)
			switch {
			case tv.Name.Local == "DERControl":
				mrid, kids = "", nil
			case len(stack) >= 3 &&
				stack[len(stack)-2] == "DERControlBase" &&
				stack[len(stack)-3] == "DERControl":
				k := baseChild{name: tv.Name.Local}
				for _, a := range tv.Attr {
					if a.Name.Space == xsiNS && a.Name.Local == "nil" && a.Value == "true" {
						k.nilMark = true
					}
				}
				kids = append(kids, k)
			}
		case xml.CharData:
			if n := len(stack); n > 0 {
				switch {
				case stack[n-1] == "mRID" && n >= 2 && stack[n-2] == "DERControl":
					mrid += string(tv)
				case n >= 3 && stack[n-2] == "DERControlBase" && stack[n-3] == "DERControl" &&
					len(kids) > 0:
					kids[len(kids)-1].text += string(tv)
				}
			}
		case xml.EndElement:
			if tv.Name.Local == "DERControl" {
				out[mrid] = kids
			}
			stack = stack[:len(stack)-1]
		}
	}
	return out
}

// namesOf flattens a base's children to their element names, for a sequence
// assertion that reads like the sequence it is checking.
func namesOf(kids []baseChild) []string {
	out := make([]string, 0, len(kids))
	for _, k := range kids {
		out = append(out, k.name)
	}
	return out
}

func childNamed(kids []baseChild, name string) (baseChild, bool) {
	for _, k := range kids {
		if k.name == name {
			return k, true
		}
	}
	return baseChild{}, false
}

// postControlOK posts an admin control and fails unless the server took it.
func postControlOK(t *testing.T, s *Server, body string) {
	t.Helper()
	if rec := postAdmin(t, s, "/admin/control", body); rec.Code != 201 {
		t.Fatalf("POST /admin/control = %d, want 201; body: %s\nrequest: %s", rec.Code, rec.Body, body)
	}
}

func dercDoc(t *testing.T, s *Server, program int) string {
	t.Helper()
	return serveRaw(t, s, fmt.Sprintf("/derp/%d/derc", program))
}

func newTestServer() *Server {
	return NewServer("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
}

// ── the oracle ───────────────────────────────────────────────────────────────

// TestExplicitNil_LandsInTheStandardsSequencePosition is RC0 §9.5 row 9's
// document, and the reason this lever exists: the row distinguishes a released
// axis served as an element that IS PRESENT and explicitly null from one served
// by leaving the element out, and gridsim could author only the second.
//
// THE POSITION IS THE ASSERTION, not the presence. DERControlBase is an
// xs:sequence, so a document carrying <opModVoltVar xsi:nil="true"/> after
// opModExpLimW is one a validating peer rejects with every element in it legal
// — and it would still contain the string the naive test greps for.
func TestExplicitNil_LandsInTheStandardsSequencePosition(t *testing.T) {
	s := newTestServer()
	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-ROW9","connect":true,`+
		`"max_lim_W":5000,"target_W":1000,"exp_lim_W":3000,"null_axes":["opModVoltVar"]}`)

	kids := controlBases(t, dercDoc(t, s, 0))["M-ROW9"]
	want := []string{"opModConnect", "opModMaxLimW", "opModTargetW", "opModVoltVar", "opModExpLimW"}
	if got := namesOf(kids); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the DERControlBase sequence is\n  %v\nwant\n  %v", got, want)
	}
	el, ok := childNamed(kids, "opModVoltVar")
	if !ok {
		t.Fatal("no <opModVoltVar> at all")
	}
	if !el.nilMark {
		t.Errorf("<opModVoltVar> carries no xsi:nil=\"true\" bound to %s — an unbound nil= attribute is "+
			"not an explicit null", xsiNS)
	}
	if strings.TrimSpace(el.text) != "" {
		t.Errorf("the explicitly-null <opModVoltVar> carries content %q", el.text)
	}
}

// TestExplicitNil_FreqWattAndVoltVarTogether is row 9's second half. Both axes
// are extended-only elements and both sort into the MIDDLE of the sequence, so
// this also proves two markers on one control do not collide or land at the end.
func TestExplicitNil_FreqWattAndVoltVarTogether(t *testing.T) {
	s := newTestServer()
	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-BOTH","connect":true,`+
		`"max_lim_W":5000,"exp_lim_W":3000,"null_axes":["opModVoltVar","opModFreqWatt"]}`)

	kids := controlBases(t, dercDoc(t, s, 0))["M-BOTH"]
	want := []string{"opModConnect", "opModFreqWatt", "opModMaxLimW", "opModVoltVar", "opModExpLimW"}
	if got := namesOf(kids); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the DERControlBase sequence is\n  %v\nwant\n  %v", got, want)
	}
	for _, name := range []string{"opModVoltVar", "opModFreqWatt"} {
		el, _ := childNamed(kids, name)
		if !el.nilMark {
			t.Errorf("<%s> is present but not xsi:nil-marked", name)
		}
	}
}

// TestExplicitNil_AbsentValuedAndNullAreThreeDocuments states the whole point
// in one place: the three conditions a §9.5 release row has to be able to tell
// apart have to be three different documents, or the row is measuring the
// harness rather than the DUT.
func TestExplicitNil_AbsentValuedAndNullAreThreeDocuments(t *testing.T) {
	s := newTestServer()
	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-3WAY","connect":true,`+
		`"null_axes":["opModVoltVar"]}`)

	kids := controlBases(t, dercDoc(t, s, 0))["M-3WAY"]

	// 1. VALUED: present, carrying its value, unmarked.
	valued, ok := childNamed(kids, "opModConnect")
	if !ok {
		t.Fatal("the valued axis opModConnect is absent")
	}
	if valued.nilMark {
		t.Error("the valued axis opModConnect is xsi:nil-marked")
	}
	if valued.text != "true" {
		t.Errorf("the valued axis opModConnect carries %q, want \"true\"", valued.text)
	}

	// 2. EXPLICITLY NULL: present, empty, marked.
	nulled, ok := childNamed(kids, "opModVoltVar")
	if !ok {
		t.Fatal("the explicitly-nulled axis opModVoltVar is absent — absence is the condition this row " +
			"exists to distinguish it from")
	}
	if !nulled.nilMark {
		t.Error("the explicitly-nulled axis opModVoltVar is present but unmarked, which on the wire is an " +
			"element with empty content, not an explicit null")
	}

	// 3. OMITTED: no element at all.
	if _, ok := childNamed(kids, "opModFreqWatt"); ok {
		t.Error("the omitted axis opModFreqWatt appears in the document")
	}
}

// TestExplicitNil_AppliesOnlyToTheNamedControl — the marker is keyed by mRID
// because a DERControlList carries every control the program has, and a
// wire-layer overlay that matched on element name alone would release an axis
// on controls the operator never named.
func TestExplicitNil_AppliesOnlyToTheNamedControl(t *testing.T) {
	s := newTestServer()
	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-MARKED","connect":true,`+
		`"null_axes":["opModVoltVar"]}`)
	postControlOK(t, s, `{"program":0,"mrid":"M-CLEAN","connect":true}`)

	bases := controlBases(t, dercDoc(t, s, 0))
	if _, ok := childNamed(bases["M-MARKED"], "opModVoltVar"); !ok {
		t.Error("the named control lost its marker when a second control joined the list")
	}
	if _, ok := childNamed(bases["M-CLEAN"], "opModVoltVar"); ok {
		t.Error("an unnamed control in the same list was given the marker too")
	}
}

// TestExplicitNil_IsOffByDefaultAndChangesNoByte. A lever that leaks one byte
// into a document nobody armed it for re-measures every row already recorded
// against these bytes. Two claims: never armed serves what it always served,
// and armed-then-released returns to exactly that.
func TestExplicitNil_IsOffByDefaultAndChangesNoByte(t *testing.T) {
	const plainBody = `{"program":0,"activate":true,"mrid":"M-SAME","connect":true,"max_lim_W":5000}`

	never := newTestServer()
	postControlOK(t, never, plainBody)
	baseline := string(unixSeconds.ReplaceAll([]byte(dercDoc(t, never, 0)), []byte("EPOCH")))

	if strings.Contains(baseline, "xsi") || strings.Contains(baseline, "nil=") {
		t.Fatalf("an unarmed server already serves xsi/nil markup:\n%s", baseline)
	}

	armed := newTestServer()
	postControlOK(t, armed, `{"program":0,"activate":true,"mrid":"M-SAME","connect":true,`+
		`"max_lim_W":5000,"null_axes":["opModVoltVar"]}`)
	// The release: same mRID, no null_axes, and — IW27-005 — no content fields
	// either. §10.2.3.3 c) permits only an EventStatus edit on an existing
	// mRID, so this update no longer resends connect/max_lim_W to keep them;
	// it omits them and lets adminCtrlPost inherit the STORED control
	// (including connect/max_lim_W from the post above) unchanged, dropping
	// only the marker. That is the release this test is actually about.
	postControlOK(t, armed, `{"program":0,"mrid":"M-SAME"}`)
	after := string(unixSeconds.ReplaceAll([]byte(dercDoc(t, armed, 0)), []byte("EPOCH")))

	if after != baseline {
		t.Errorf("a re-post without null_axes did not return the document to its unarmed bytes:\n"+
			"unarmed:\n%s\nafter:\n%s", baseline, after)
	}
}

// TestExplicitNil_DoesNotSurviveTheControlsRemoval — the marker lives beside
// the resource tree rather than in it, so nothing about deleting a control
// deletes it automatically. A stale marker is worse than a missing one: it
// re-attaches to whatever control next claims that mRID, and the bundle then
// records an explicit null the operator did not author.
func TestExplicitNil_DoesNotSurviveTheControlsRemoval(t *testing.T) {
	s := newTestServer()
	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-GONE","connect":true,`+
		`"null_axes":["opModVoltVar"]}`)
	deleteAdmin(t, s, "/admin/control", `{"program":0}`)

	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-GONE","connect":true}`)
	if _, ok := childNamed(controlBases(t, dercDoc(t, s, 0))["M-GONE"], "opModVoltVar"); ok {
		t.Error("a marker armed before DELETE /admin/control re-attached to a later control reusing the mRID")
	}
}

// ── teeth ────────────────────────────────────────────────────────────────────

// TestExplicitNil_RefusesWhatItCannotAuthor. Every refusal here is a document
// that would otherwise have been PUBLISHED — validation-before-storage, the
// rule the rest of this handler already follows, because a control that cannot
// be authored whole must not be half-served.
func TestExplicitNil_RefusesWhatItCannotAuthor(t *testing.T) {
	cases := []struct {
		name string
		body string
		why  string
	}{
		{
			name: "an axis no DERControlBase declares",
			body: `{"program":0,"mrid":"M-BAD","null_axes":["opModTeapot"]}`,
			why:  "a typo would otherwise be served as silence — the operator's release simply would not happen",
		},
		{
			name: "an axis spelled as a curve mode rather than an element",
			body: `{"program":0,"mrid":"M-BAD","null_axes":["volt_var"]}`,
			why:  "the vocabulary is the model's own element names; a near-miss must not pass",
		},
		{
			name: "the same axis twice",
			body: `{"program":0,"mrid":"M-BAD","null_axes":["opModVoltVar","opModVoltVar"]}`,
			why:  "one element cannot be nil twice, and the second would land out of sequence",
		},
		{
			name: "an axis that also carries a value",
			body: `{"program":0,"mrid":"M-BAD","connect":true,"null_axes":["opModConnect"]}`,
			why:  "an element cannot be both present-with-a-value and present-and-nil",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer()
			rec := postAdmin(t, s, "/admin/control", tc.body)
			if rec.Code != 400 {
				t.Fatalf("POST /admin/control = %d, want 400 — %s\nbody: %s", rec.Code, tc.why, tc.body)
			}
			if _, ok := controlBases(t, dercDoc(t, s, 0))["M-BAD"]; ok {
				t.Errorf("the refused control was stored anyway: %s", tc.body)
			}
		})
	}
}

// ── the derived sequence ─────────────────────────────────────────────────────

// emittedElementOrder marshals v with encoding/xml and returns the order its
// top-level child elements actually came out in.
//
// It asks the MARSHALLER, not reflection, because the claim being checked is
// that the model's field order is the emitted sequence. Re-deriving the order
// by reflection here would only prove reflection agrees with itself.
func emittedElementOrder(t *testing.T, v any) []string {
	t.Helper()
	data, err := xml.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out []string
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		switch tv := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 {
				out = append(out, tv.Name.Local)
			}
		case xml.EndElement:
			depth--
		}
	}
	return out
}

// fillPointers returns a copy of the zero struct T with every pointer field
// non-nil, so a marshal of it emits EVERY element the type declares. Values are
// zero; only presence and order matter here.
func fillPointers[T any](t *testing.T) *T {
	t.Helper()
	v := reflect.New(reflect.TypeOf(*new(T))).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Ptr && f.CanSet() {
			f.Set(reflect.New(f.Type().Elem()))
		}
	}
	out := v.Addr().Interface().(*T)
	return out
}

// TestDERControlBaseSequenceIsWhatTheMarshallerEmits is the load-bearing claim
// under the whole splice: the insertion index is computed from csipmodel's
// FIELD ORDER, and that is only a safe thing to do because Go emits struct
// fields in declaration order. If encoding/xml ever stopped doing that — or if
// a field grew a tag this package's reader does not understand — every marker
// would go on being placed, at a position derived from something that is no
// longer the document's own order.
func TestDERControlBaseSequenceIsWhatTheMarshallerEmits(t *testing.T) {
	got := emittedElementOrder(t, fillPointers[model.ExtendedDERControlBase](t))
	if strings.Join(got, ",") != strings.Join(derControlBaseElements, ",") {
		t.Fatalf("the derived sequence and the emitted one disagree:\n derived: %v\n emitted: %v",
			derControlBaseElements, got)
	}
	// The two axes RC0 §9.5 row 9 needs, and the neighbours that pin them.
	// IEEE Std 2030.5-2018 p.248 puts opModFreqWatt between opModFreqDroop and
	// the ride-through block; p.250 puts opModVoltVar between opModTargetW and
	// opModVoltWatt.
	for _, want := range [][3]string{
		{"opModFreqDroop", "opModFreqWatt", "opModHFRTMayTrip"},
		{"opModTargetW", "opModVoltVar", "opModVoltWatt"},
	} {
		before, axis, after := derControlBaseIndex[want[0]], derControlBaseIndex[want[1]], derControlBaseIndex[want[2]]
		if !(before < axis && axis < after) {
			t.Errorf("<%s> does not sit between <%s> and <%s> in the derived sequence: %v",
				want[1], want[0], want[2], derControlBaseElements)
		}
	}
}

// TestDERControlBaseIsASubsequenceOfTheExtendedBase holds the assumption that
// lets ONE canonical order serve both control-base shapes: gridsim stores some
// controls in the narrow csipmodel.DERControlBase and some in the extended one,
// and the splice computes positions from the extended order for both. That is
// correct exactly as long as the narrow type's elements appear in the extended
// type's order — a subsequence, not merely a subset.
func TestDERControlBaseIsASubsequenceOfTheExtendedBase(t *testing.T) {
	narrow := emittedElementOrder(t, fillPointers[model.DERControlBase](t))
	at := -1
	for _, name := range narrow {
		idx, ok := derControlBaseIndex[name]
		if !ok {
			t.Fatalf("the narrow DERControlBase emits <%s>, which the extended one does not declare at "+
				"all — the splice would have no position for it", name)
		}
		if idx <= at {
			t.Fatalf("the narrow DERControlBase emits <%s> out of the extended type's order (%v vs %v)",
				name, narrow, derControlBaseElements)
		}
		at = idx
	}
}

// ── the shapes RC0 §9.5 row 9 actually sends ─────────────────────────────────

// TestExplicitNil_AReleaseOnlyControlIsWellFormed. A release commands nothing
// else, so its DERControlBase holds the marker and nothing else — which is the
// one case with no sibling to hang the insertion off, and the case a splice
// written against a non-empty example would get wrong.
func TestExplicitNil_AReleaseOnlyControlIsWellFormed(t *testing.T) {
	for _, tc := range []struct {
		name string
		axes string
		want []string
	}{
		{"one axis", `["opModVoltVar"]`, []string{"opModVoltVar"}},
		// Two markers into an empty base land at the SAME insertion point, and
		// have to come out in the standard's order however the request listed
		// them — hence freq_watt second here and first in the document.
		{"two axes, listed out of order", `["opModVoltVar","opModFreqWatt"]`,
			[]string{"opModFreqWatt", "opModVoltVar"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer()
			postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-BARE","null_axes":`+tc.axes+`}`)

			doc := dercDoc(t, s, 0)
			// controlBases fails the test if doc does not parse, so
			// well-formedness is asserted before anything else here is.
			kids := controlBases(t, doc)["M-BARE"]
			if got := namesOf(kids); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("the release-only DERControlBase holds %v, want %v:\n%s", got, tc.want, doc)
			}
			for _, k := range kids {
				if !k.nilMark {
					t.Errorf("<%s> is present but not xsi:nil-marked:\n%s", k.name, doc)
				}
			}
		})
	}
}

// TestExplicitNil_ReachesTheActiveControlList. A DUT reads the schedule at
// /derc and the active set at /actderc, and the two have to agree about what
// the control commands — a marker on one and not the other is a server telling
// the DUT two different things about one event.
func TestExplicitNil_ReachesTheActiveControlList(t *testing.T) {
	s := newTestServer()
	rec := postAdmin(t, s, "/admin/control",
		`{"program":0,"activate":true,"connect":true,"null_axes":["opModVoltVar"]}`)
	if rec.Code != 201 {
		t.Fatalf("POST /admin/control = %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		MRID string `json:"mrid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode the POST response: %v", err)
	}

	for _, path := range []string{"/derp/0/derc", "/derp/0/actderc"} {
		kids := controlBases(t, serveRaw(t, s, path))[created.MRID]
		el, ok := childNamed(kids, "opModVoltVar")
		if !ok || !el.nilMark {
			t.Errorf("%s serves control %s without the xsi:nil marker: %v", path, created.MRID, kids)
		}
	}
}

// TestExplicitNil_ReleasesACurveBoundControl is row 9 end to end: a volt-var
// curve is published and then RELEASED by an explicitly-null opModVoltVar. It
// is also the only path that exercises the extended control list, which
// POST /admin/curve leaves behind at these hrefs.
func TestExplicitNil_ReleasesACurveBoundControl(t *testing.T) {
	s := newTestServer()
	rec := postAdmin(t, s, "/admin/curve",
		`{"program":0,"activate":true,"mode":"volt_var","y_ref_type":3,`+
			`"points":[{"x":9200,"y":3000},{"x":10800,"y":-3000}]}`)
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}
	if armed := controlBases(t, dercDoc(t, s, 0)); len(armed) != 1 {
		t.Fatalf("expected exactly one curve-bound control before the release, got %d", len(armed))
	}

	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"M-RELEASE","null_axes":["opModVoltVar"]}`)

	doc := dercDoc(t, s, 0)
	kids := controlBases(t, doc)["M-RELEASE"]
	el, ok := childNamed(kids, "opModVoltVar")
	if !ok || !el.nilMark {
		t.Fatalf("the release control does not carry an xsi:nil opModVoltVar: %v\n%s", kids, doc)
	}
	if strings.Contains(doc, `<opModVoltVar href=`) {
		t.Errorf("the released document still links a curve from opModVoltVar:\n%s", doc)
	}
}

// TestExplicitNil_DefaultDERControlRefusesTheLever. POST /admin/default shares
// this request struct, so null_axes decodes there whether or not it means
// anything. Silently ignoring it would hand the operator a 204 for a document
// that was never authored.
func TestExplicitNil_DefaultDERControlRefusesTheLever(t *testing.T) {
	s := newTestServer()
	rec := postAdmin(t, s, "/admin/default", `{"program":0,"base":{"null_axes":["opModVoltVar"]}}`)
	if rec.Code != 400 {
		t.Fatalf("POST /admin/default with null_axes = %d, want 400; body: %s", rec.Code, rec.Body)
	}
	if strings.Contains(serveRaw(t, s, "/derp/0/dderc"), "nil=") {
		t.Error("the refused default was authored anyway")
	}
}

// ── the transform on its own ─────────────────────────────────────────────────

// TestApplyExplicitNil_IsIndifferentToIndentation calls the transform directly,
// the way malform_test.go calls its byte splices, on a document produced by the
// UNINDENTED encoding/xml marshal. Nothing in gridsim serves that shape today —
// it is what a caller marshalling without MarshalIndent would hand it — and the
// point is that the mechanism keys off element boundaries rather than off
// whitespace, so it cannot quietly become wrong if a caller changes how it
// marshals.
func TestApplyExplicitNil_IsIndifferentToIndentation(t *testing.T) {
	doc, err := xml.Marshal(&model.DERControlList{
		Resource: model.Resource{Href: "/derp/0/derc"},
		All:      1, Results: 1,
		DERControl: []model.DERControl{{
			MRID:           "M-TIGHT",
			DERControlBase: model.DERControlBase{OpModExpLimW: &model.ActivePower{Value: 3000}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := applyExplicitNil(doc, map[string][]string{"M-TIGHT": {"opModVoltVar"}})
	if err != nil {
		t.Fatalf("applyExplicitNil: %v", err)
	}
	kids := controlBases(t, string(out))["M-TIGHT"]
	want := []string{"opModVoltVar", "opModExpLimW"} // opModExpLimW sorts last: it is not a 2030.5 element
	if got := namesOf(kids); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sequence %v, want %v:\n%s", got, want, out)
	}
	if !kids[0].nilMark {
		t.Errorf("the spliced element is not xsi:nil-marked:\n%s", out)
	}
}

// TestApplyExplicitNil_RefusesToDuplicateAValuedElement. The admin handler
// refuses this combination at the request, but the marker and the control are
// stored apart, so a later POST /admin/curve could in principle give an armed
// mRID a real opModVoltVar. Serving both would put the same element twice into
// an xs:sequence; dropping the marker would serve a document the run's own log
// says carries one. The transform refuses, and serveXML turns that into a 500.
func TestApplyExplicitNil_RefusesToDuplicateAValuedElement(t *testing.T) {
	doc, err := xml.MarshalIndent(&model.ExtendedDERControlList{
		Resource: model.Resource{Href: "/derp/0/derc"},
		All:      1, Results: 1,
		DERControl: []model.ExtendedDERControl{{
			MRID: "M-CLASH",
			DERControlBase: model.ExtendedDERControlBase{
				OpModVoltVar: &model.CurveLink{Href: "/derp/0/dc/0"},
			},
		}},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyExplicitNil(doc, map[string][]string{"M-CLASH": {"opModVoltVar"}}); err == nil {
		t.Fatal("a control already serving a valued <opModVoltVar> was given a second, nil one")
	}
}

// TestApplyExplicitNil_UnarmedReturnsTheSameBytes is the byte-identity claim at
// the level it is actually guaranteed: no markers in, the input slice back.
func TestApplyExplicitNil_UnarmedReturnsTheSameBytes(t *testing.T) {
	doc := []byte("<DERControlList><DERControl><mRID>M</mRID><DERControlBase/></DERControl></DERControlList>")
	out, err := applyExplicitNil(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, doc) {
		t.Errorf("an unarmed overlay rewrote the document:\n%s", out)
	}
}

// TestExplicitNil_AStaleMarkerCannotResurrectOntoARecycledMRID is the row that
// PINS the orphan sweep, and it exists because the sweep was previously pinned
// by nothing.
//
// GATE FINDING F3. TestExplicitNil_DoesNotSurviveTheControlsRemoval re-POSTS the
// same mRID WITHOUT null_axes to show the marker is gone — but a re-POST through
// POST /admin/control disarms the marker itself (setExplicitNilLocked deletes
// the key when a request names no axes), so that row stays green with
// forgetOrphanedExplicitNilLocked deleted. It proved the disarm, not the sweep.
//
// The unmasked path is a RECYCLED mRID, and it is not hypothetical: POST
// /admin/curve mints "DERC-<prog>-CURVE-<unix seconds>" (curve.go), so two
// writes in the same second get the SAME mRID by construction. Without the
// sweep the sequence below leaves a marker keyed to an mRID whose control was
// deleted, a new curve control reclaims that mRID carrying a VALUED
// opModVoltVar, and the overlay is then asked to insert an xsi:nil element for
// an axis the document already carries — which baseSplices correctly refuses,
// so serveXML answers 500 and /derp/0/derc becomes UNFETCHABLE FOR EVERY
// CLIENT, not merely wrong for one.
//
// Mutation-proved: with the two forgetOrphanedExplicitNilLocked calls on the
// control paths removed, this row fails on the 500.
func TestExplicitNil_AStaleMarkerCannotResurrectOntoARecycledMRID(t *testing.T) {
	s := newTestServer()

	// The mRID POST /admin/curve will mint THIS SECOND. Computed from the
	// server's own clock and the same format string the minting site uses, so
	// the row collides by construction rather than by racing.
	recycled := fmt.Sprintf("DERC-%s-CURVE-%d", progPrefixes[0], s.Now())

	// Arm a marker on it, then take its control away.
	postControlOK(t, s, `{"program":0,"activate":true,"mrid":"`+recycled+`",`+
		`"connect":true,"null_axes":["opModVoltVar"]}`)
	deleteAdmin(t, s, "/admin/control", `{"program":0}`)

	// A curve control minted in the same second RECLAIMS that mRID, and it
	// carries a valued opModVoltVar curve link.
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "x_mult": -2, "y_mult": 0,
		"points": [{"x":9570,"y":30},{"x":10430,"y":-30}], "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}

	// 1. The list is still SERVABLE. This is the assertion the missing sweep
	//    breaks, and it breaks it for every client of the program at once.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/derp/0/derc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /derp/0/derc = %d, want 200: a marker armed on a DELETED control was still "+
			"registered when a new control reclaimed its mRID, and the overlay was asked to nil an "+
			"element the document already carries. Body: %s", rec.Code, rec.Body)
	}

	// 2. And the recycled control did not inherit a release nobody armed on it:
	//    its opModVoltVar is the VALUED curve link the curve request authored.
	kids := controlBases(t, rec.Body.String())[recycled]
	vv, ok := childNamed(kids, "opModVoltVar")
	if !ok {
		t.Fatalf("the recycled control carries no opModVoltVar at all; document:\n%s", rec.Body.String())
	}
	if vv.nilMark {
		t.Errorf("the recycled control's opModVoltVar is xsi:nil-marked — it inherited a release armed " +
			"on the DIFFERENT control that previously held this mRID")
	}
}
