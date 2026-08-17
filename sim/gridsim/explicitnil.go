package gridsim

// explicitnil.go — serving a DERControlBase element that is PRESENT AND
// EXPLICITLY NULL, which is a document Go's encoding/xml cannot produce and
// which this bench previously could not author at all.
//
// ── The gap this closes ──────────────────────────────────────────────────────
//
// RC0 §9.5's bench battery, row 9, grades what the DUT does when a head end
// RELEASES an axis by sending the element with xsi:nil="true" rather than by
// leaving it out: "explicit-null volt_var => ModEna = 0, ActCrv untouched;
// explicit-null freq_watt => no write at all". The row was recorded SKIP —
// "structurally unavailable on this harness" — because every release gridsim
// could author was an ABSENCE (omit the field) or a CANCELLATION (currentStatus
// 6, DELETE /admin/control, POST /admin/default {"clear":true}), and those are
// the conditions the row exists to distinguish an explicit null FROM. A skip
// recorded for a harness limitation reads, in a bundle, exactly like a skip
// recorded for a product limitation.
//
// ── Why this is a WIRE-layer mechanism and not a model change ────────────────
//
// Every DERControlBase / ExtendedDERControlBase field is a `*T` with
// `,omitempty` (lexa-proto csipmodel/resources.go and csipmodel/der.go). Go's
// encoding/xml has no nil-marshalling mode: a nil pointer is DROPPED and a
// non-nil pointer is marshalled by value, so "present and null" has no
// representation anywhere in the struct space. That is a property of
// encoding/xml, not a defect in csipmodel, and no field could be added to
// csipmodel that would fix it — which is why this lives here and lexa-proto is
// untouched.
//
// So the marker is applied to the MARSHALLED BYTES, at serveXML — the one place
// every document this server emits passes through. That follows malform.go's
// precedent, where the genuinely structural malformations (a stripped href, a
// duplicated control) are likewise byte transforms "which is faithful, since
// the whole point is bytes the parser must survive". The alternative — a local
// wire-shape struct in curvexml.go's style — was rejected for a specific
// reason: DERControlBase has thirty elements, and a local copy of all thirty
// would be exactly the hand-maintained second opinion of the model that
// curvexml.go's own file doc warns about, for the sake of one attribute on one
// of them.
//
// ── What the standard does and does not say ─────────────────────────────────
//
// IEEE Std 2030.5-2018 declares every DERControlBase element [0..1] — optional,
// at most once (p.248-251: opModConnect through rampTms). It says NOTHING about
// explicit nil. The words "nillable" and "xsi:nil" do not occur in the document
// at all, and neither does "null"; the only use of the XML Schema Instance
// namespace anywhere in the standard is xsi:TYPE, required by §4.7's resource
// design rules (p.24) for subordinate resources of a list that supports
// multiple types, and shown once in the Annex C Notification example (p.278).
//
// SO THIS LEVER DOES NOT IMPLEMENT A REQUIREMENT. It does not make gridsim
// "more conformant", and a DUT that ignores the marker is not thereby
// non-conformant under 2030.5-2018. What it does is let the bench PRESENT a
// document whose distinction the PRODUCT claims to act on, so that claim can be
// graded against bytes instead of against a skip. Anything written into a
// bundle from this lever has to say the same thing: the condition is the
// product's, the standard is silent.
//
// (xsi:nil itself is W3C XML Schema Part 1, §2.6.2 — a schema-level facility
// available only to elements a schema declares nillable="true". Whether any
// DERControlBase element is nillable is a question about a schema document, not
// about IEEE Std 2030.5-2018, and the sep-2.0.4.xsd vendored in lexa-proto is a
// PRE-PUBLICATION SEP 2.0 draft that is reference-only here and settles
// nothing. This lever therefore takes no position on schema-validity: it
// guarantees WELL-FORMEDNESS and sequence position, which is what the tests
// assert, and nothing more.)
//
// ── What would go wrong without the care taken here ─────────────────────────
//
//  1. SEQUENCE. DERControlBase is an xs:sequence, so an element in the wrong
//     position makes a document a validating peer rejects with every element in
//     it legal. The insertion index is derived by REFLECTION over
//     csipmodel.ExtendedDERControlBase's field order (Go emits struct fields in
//     declaration order, so that order IS the emitted sequence), which means the
//     marker cannot drift out of position when the model's element set changes.
//     A hand-written element list here would be a second opinion about the
//     sequence, and the one that is not compiled against is the one that rots.
//
//  2. BLAST RADIUS. A DERControlList carries every control a program has. The
//     marker is keyed by mRID so it lands on the control the operator named and
//     no other — a name-only match would silently release an axis on controls
//     nobody armed.
//
//  3. STALENESS. The marker lives beside the resource tree rather than in it,
//     so deleting a control does not delete it. Every control-list mutation
//     path sweeps markers whose mRID the program no longer serves
//     (forgetOrphanedExplicitNilLocked); otherwise a marker armed for one run
//     re-attaches to whatever control next claims that mRID, and the bundle
//     records an explicit null the operator did not author.
//
// ── Scope, stated so it is not mistaken for coverage ────────────────────────
//
// The overlay applies to the DERControlList and ExtendedDERControlList served
// at /derp/{p}/derc and /derp/{p}/actderc, and to nothing else. NOT to
// DefaultDERControl (/derp/{p}/dderc): a DefaultDERControl is not an event and
// has no release semantics to grade, and POST /admin/default refuses null_axes
// rather than accepting and ignoring it. NOT to Subscription Notification
// bodies, which subscribe.go marshals on its own path — subscriptions are off
// by default and §9.5's rows are poll-driven, so extending it there would be
// untested surface rather than coverage.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"

	model "lexa-proto/csipmodel"
)

// xsiNamespace is the XML Schema Instance namespace. It is declared ON THE NIL
// ELEMENT ITSELF rather than on the document root, for two reasons: the splice
// edits an already-marshalled document and would otherwise have to rewrite a
// root element it did not build, and a root declaration would be left dangling
// in every document where no control matched. Element-scoped declaration is
// ordinary XML Namespaces 1.0 and is the same technique subscribe.go's
// notifyResource uses for its hand-written xsi:type attribute.
const xsiNamespace = "http://www.w3.org/2001/XMLSchema-instance"

// wireIndent is the indent serveXML marshals with (server.go's
// xml.MarshalIndent(out, "", "  ")). It is used only to indent a marker spliced
// into an OTHERWISE EMPTY DERControlBase, where there is no sibling to copy the
// indentation from; every other insertion mirrors the whitespace already in the
// document, so a document marshalled without indentation stays that way.
const wireIndent = "  "

// explicitNilKey identifies the control an explicit-nil marker belongs to.
//
// The PROGRAM is part of the key, not decoration: serveXML recovers it from the
// list resource's own href, so a marker armed on /derp/0 can never reach a
// same-mRID control served under /derp/1.
type explicitNilKey struct {
	program int
	mrid    string
}

// derControlBaseElements is the DERControlBase element sequence, and
// derControlBaseIndex its inverse, both derived by reflection from
// csipmodel.ExtendedDERControlBase — the WIDER of the two bases, whose field
// order contains the narrow DERControlBase's as a subsequence
// (TestDERControlBaseIsASubsequenceOfTheExtendedBase holds that, so one
// canonical order is correct for both shapes).
//
// Derived, not written down, because Go emits struct fields in declaration
// order: the model's field order is not merely a description of the emitted
// sequence, it IS the emitted sequence. A copy here could disagree with the
// document it is inserting into.
var derControlBaseElements, derControlBaseIndex = deriveControlBaseSequence()

func deriveControlBaseSequence() ([]string, map[string]int) {
	t := reflect.TypeOf(model.ExtendedDERControlBase{})
	names := make([]string, 0, t.NumField())
	index := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, ok := xmlElementName(t.Field(i))
		if !ok {
			continue
		}
		index[name] = len(names)
		names = append(names, name)
	}
	return names, index
}

// xmlElementName reports the element name a struct field marshals to, and
// whether it marshals as a child ELEMENT at all. Attributes, chardata, innerxml
// and xml.Name fields are not elements and are excluded — none exists on either
// control base today, and excluding them is what keeps that true rather than
// assumed.
func xmlElementName(f reflect.StructField) (string, bool) {
	if f.PkgPath != "" || f.Type == reflect.TypeOf(xml.Name{}) {
		return "", false
	}
	tag := f.Tag.Get("xml")
	if tag == "-" {
		return "", false
	}
	parts := strings.Split(tag, ",")
	for _, opt := range parts[1:] {
		switch opt {
		case "attr", "chardata", "innerxml", "comment", "any", "cdata":
			return "", false
		}
	}
	name := parts[0]
	// encoding/xml's "namespace local" form; the local half is the element name.
	if i := strings.LastIndex(name, " "); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = f.Name
	}
	return name, true
}

// ── request-side validation ──────────────────────────────────────────────────

// explicitNilAxes validates a request's null_axes and returns them in the
// standard's own sequence order.
//
// SORTED CANONICALLY, deliberately: the operator's list order is not the
// document's, and returning it sorted means the splice's insertion offsets come
// out non-decreasing, which is what lets several markers on one control compose
// without a second sorting pass reasoning about the same order twice.
//
// It does NOT check the value conflict — an axis nulled and valued in the same
// request — because that needs the base this request will actually serve, which
// the handler builds afterwards. See explicitNilValueConflict.
func (req adminCtrlReq) explicitNilAxes() ([]string, error) {
	if len(req.NullAxes) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(req.NullAxes))
	for _, axis := range req.NullAxes {
		if _, ok := derControlBaseIndex[axis]; !ok {
			return nil, fmt.Errorf("null_axes %q is not a DERControlBase element; the vocabulary is the "+
				"model's own element names: %s", axis, strings.Join(derControlBaseElements, ", "))
		}
		if seen[axis] {
			return nil, fmt.Errorf("null_axes names %q twice; DERControlBase is an xs:sequence and each "+
				"element may appear at most once (IEEE Std 2030.5-2018 p.248-251 declares every one of "+
				"them [0..1])", axis)
		}
		seen[axis] = true
		out = append(out, axis)
	}
	sort.Slice(out, func(i, j int) bool {
		return derControlBaseIndex[out[i]] < derControlBaseIndex[out[j]]
	})
	return out, nil
}

// explicitNilValueConflict refuses a request that both VALUES and NULLS the
// same axis. The two are contradictory instructions about one element — it
// cannot be present carrying a value and present carrying xsi:nil at once — and
// resolving the contradiction silently, either way, publishes a control that
// the operator's own record of the request does not describe. Same rule, and
// the same reason, as curve.go's refusal of a request carrying both `mode` and
// `curves`.
//
// bases are the control bases this request will actually serve (the narrow one
// always, the extended one too when a request widened the control). Each is
// inspected by reflection rather than field by field, so an axis added to
// csipmodel is covered here the day it lands.
func explicitNilValueConflict(axes []string, bases ...any) error {
	if len(axes) == 0 {
		return nil
	}
	valued := map[string]bool{}
	for _, b := range bases {
		for name := range valuedElements(b) {
			valued[name] = true
		}
	}
	for _, axis := range axes {
		if valued[axis] {
			return fmt.Errorf("null_axes names %q, but this request also gives it a value; an element "+
				"cannot be both present-with-a-value and present-and-nil", axis)
		}
	}
	return nil
}

// valuedElements returns the element names a control base will actually emit.
// Every field of both bases is a pointer with `,omitempty`, so non-nil is
// exactly "this element appears in the document".
func valuedElements(base any) map[string]bool {
	v := reflect.ValueOf(base)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	out := map[string]bool{}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		name, ok := xmlElementName(t.Field(i))
		if !ok {
			continue
		}
		f := v.Field(i)
		if f.Kind() == reflect.Ptr && f.IsNil() {
			continue
		}
		out[name] = true
	}
	return out
}

// ── server-side store ────────────────────────────────────────────────────────

// setExplicitNilLocked arms (or, with no axes, disarms) the marker for one
// control. Caller must hold s.mu.
//
// A request that names no null_axes DISARMS rather than leaves alone, because a
// POST replaces the control at that mRID: a control re-posted without the lever
// is a control that does not carry the marker, and leaving a previous arming in
// place would serve one that does.
func (s *Server) setExplicitNilLocked(program int, mrid string, axes []string) {
	key := explicitNilKey{program: program, mrid: mrid}
	if len(axes) == 0 {
		delete(s.explicitNil, key)
		return
	}
	if s.explicitNil == nil {
		s.explicitNil = map[explicitNilKey][]string{}
	}
	s.explicitNil[key] = append([]string(nil), axes...)
}

// forgetOrphanedExplicitNilLocked drops every marker for a program whose mRID
// the program's scheduled control list no longer carries. Caller must hold
// s.mu.
//
// RECONCILIATION rather than bookkeeping at each mutation site, because the
// control-list writers are several (POST/DELETE /admin/control, POST/DELETE
// /admin/curve) and each has its own replace/append/upsert semantics. Deriving
// "which markers are still live" from the list that was just written cannot
// disagree with the list; four hand-maintained clear-outs eventually would.
func (s *Server) forgetOrphanedExplicitNilLocked(program int) {
	if len(s.explicitNil) == 0 {
		return
	}
	live := map[string]bool{}
	switch list := s.resources[fmt.Sprintf("/derp/%d/derc", program)].(type) {
	case *model.DERControlList:
		for _, c := range list.DERControl {
			live[c.MRID] = true
		}
	case *model.ExtendedDERControlList:
		for _, c := range list.DERControl {
			live[c.MRID] = true
		}
	}
	for key := range s.explicitNil {
		if key.program == program && !live[key.mrid] {
			delete(s.explicitNil, key)
		}
	}
}

// explicitNilOverlay returns the mRID→axes markers that apply to one resource
// about to be served, or nil when none do.
//
// The PROGRAM comes from the resource's own href rather than from the caller,
// which is what confines a marker to the program it was armed on and, at the
// same time, confines the whole mechanism to the two control lists: any other
// resource returns nil here and is served byte-for-byte as before.
func (s *Server) explicitNilOverlay(resource any) map[string][]string {
	var href string
	switch v := resource.(type) {
	case *model.DERControlList:
		href = v.Href
	case *model.ExtendedDERControlList:
		href = v.Href
	default:
		return nil
	}
	program, ok := programOfControlList(href)
	if !ok {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	var out map[string][]string
	for key, axes := range s.explicitNil {
		if key.program != program {
			continue
		}
		if out == nil {
			out = make(map[string][]string, len(s.explicitNil))
		}
		out[key.mrid] = axes
	}
	return out
}

// programOfControlList recovers the program number from a scheduled or active
// control list's href, and reports whether href is one of those two lists at
// all. A query string is ignored: pagination serves the same list under an href
// carrying ?s=/?l= (paginate.go).
func programOfControlList(href string) (int, bool) {
	if i := strings.IndexByte(href, '?'); i >= 0 {
		href = href[:i]
	}
	rest, ok := strings.CutPrefix(href, "/derp/")
	if !ok {
		return 0, false
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return 0, false
	}
	switch rest[slash+1:] {
	case "derc", "actderc":
	default:
		return 0, false
	}
	program, err := strconv.Atoi(rest[:slash])
	if err != nil {
		return 0, false
	}
	return program, true
}

// ── the wire realisation ─────────────────────────────────────────────────────

// splice is one insertion: the byte offset in the marshalled document to insert
// before, and the text to insert.
type splice struct {
	at   int
	text string
}

// applyExplicitNil rewrites one already-marshalled document so that each
// DERControl named in byMRID carries an xsi:nil element for each of its axes,
// in the standard's sequence position.
//
// It returns an ERROR rather than a best-effort document. The two things that
// can go wrong — the document does not parse, or the control already carries a
// valued element for an axis the operator also asked to null — both produce
// evidence that lies: the first would serve a document silently missing the
// marker the run is about, and the second a DERControlBase with the same
// element twice. serveXML turns either into a 500 and a log line, which is a
// bench that stops rather than a bundle that has to be withdrawn.
func applyExplicitNil(data []byte, byMRID map[string][]string) ([]byte, error) {
	if len(byMRID) == 0 {
		return data, nil
	}
	splices, err := explicitNilSplices(data, byMRID)
	if err != nil {
		return nil, err
	}
	if len(splices) == 0 {
		return data, nil
	}
	sort.SliceStable(splices, func(i, j int) bool { return splices[i].at < splices[j].at })

	var out bytes.Buffer
	out.Grow(len(data) + 128*len(splices))
	last := 0
	for _, sp := range splices {
		out.Write(data[last:sp.at])
		out.WriteString(sp.text)
		last = sp.at
	}
	out.Write(data[last:])
	return out.Bytes(), nil
}

// baseLayout is where one control's DERControlBase sits in the marshalled
// bytes: the offset of the '<' in <DERControlBase>, the top-level child element
// names in document order with the offset of each one's '<', and the offset of
// the '<' in </DERControlBase>.
type baseLayout struct {
	openAt  int
	kids    []string
	kidAt   []int
	closeAt int
}

// explicitNilSplices walks the marshalled document and works out, for every
// control named in byMRID, where each marker has to go.
//
// The walk is a real xml.Decoder rather than a string search because the
// offsets have to be element boundaries: splicing at a byte that is inside a
// tag, or inside a nested child, produces a document that does not parse — and
// this is a bench whose product is documents. Using the decoder also makes the
// mechanism indifferent to indentation, so it behaves the same on serveXML's
// indented marshal as it would on an unindented one.
func explicitNilSplices(data []byte, byMRID map[string][]string) ([]splice, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var (
		out   []splice
		stack []string
		mrid  string
		lay   *baseLayout
		// prev is the offset the token about to be examined STARTS at:
		// InputOffset reports where the last token ended, and MarshalIndent
		// puts the whitespace between two elements in its own CharData token,
		// so the end of the previous token is the '<' of this one.
		prev int64
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("explicit-nil overlay: the marshalled document does not parse: %w", err)
		}
		switch tv := tok.(type) {
		case xml.StartElement:
			stack = append(stack, tv.Name.Local)
			n := len(stack)
			switch {
			case tv.Name.Local == "DERControl":
				mrid, lay = "", nil
			case tv.Name.Local == "DERControlBase" && n >= 2 && stack[n-2] == "DERControl":
				lay = &baseLayout{openAt: int(prev), closeAt: -1}
			case lay != nil && n >= 2 && stack[n-2] == "DERControlBase":
				lay.kids = append(lay.kids, tv.Name.Local)
				lay.kidAt = append(lay.kidAt, int(prev))
			}
		case xml.CharData:
			if n := len(stack); n >= 2 && stack[n-1] == "mRID" && stack[n-2] == "DERControl" {
				mrid += string(tv)
			}
		case xml.EndElement:
			if tv.Name.Local == "DERControlBase" && lay != nil && lay.closeAt < 0 {
				lay.closeAt = int(prev)
			}
			if tv.Name.Local == "DERControl" {
				if axes, ok := byMRID[strings.TrimSpace(mrid)]; ok && lay != nil {
					sp, err := baseSplices(data, lay, strings.TrimSpace(mrid), axes)
					if err != nil {
						return nil, err
					}
					out = append(out, sp...)
				}
				mrid, lay = "", nil
			}
			stack = stack[:len(stack)-1]
		}
		prev = dec.InputOffset()
	}
	return out, nil
}

// baseSplices places one control's markers inside its DERControlBase.
//
// The rule is the sequence's: a marker goes immediately before the first
// element already present that sorts AFTER it, and before </DERControlBase>
// when there is none. Elements the model does not declare are stepped over
// rather than compared — the ordering of something this build has never heard
// of is not knowable, and guessing would move a marker on the strength of it.
//
// Markers landing at the SAME point are emitted as one splice rather than
// several. Two independent insertions at one offset would each have to reason
// about whether they were the first or the last in order to get the separating
// whitespace right, and one of them would be wrong.
func baseSplices(data []byte, lay *baseLayout, mrid string, axes []string) ([]splice, error) {
	// axes arrive in the standard's own sequence order (explicitNilAxes sorts
	// them), so appending within a group preserves that order too.
	var offsets []int
	grouped := map[int][]string{}
	for _, axis := range axes {
		want, ok := derControlBaseIndex[axis]
		if !ok {
			// Unreachable through the admin handler, which refuses an unknown
			// axis before storing it. Checked anyway: a marker whose position
			// is unknown must not be placed at a guessed one.
			return nil, fmt.Errorf("explicit-nil overlay: %q is not a DERControlBase element", axis)
		}
		at := lay.closeAt
		for i, kid := range lay.kids {
			if kid == axis {
				return nil, fmt.Errorf("explicit-nil overlay: control %s already serves a valued <%s>, "+
					"so the marker would make the element appear twice in an xs:sequence", mrid, axis)
			}
			if idx, known := derControlBaseIndex[kid]; known && idx > want && at == lay.closeAt {
				at = lay.kidAt[i]
			}
		}
		if _, seen := grouped[at]; !seen {
			offsets = append(offsets, at)
		}
		grouped[at] = append(grouped[at], axis)
	}
	out := make([]splice, 0, len(offsets))
	for _, at := range offsets {
		out = append(out, splice{at: at, text: nilElementsText(data, lay, at, grouped[at])})
	}
	return out, nil
}

// nilElementsText renders the markers for one insertion point, plus whatever
// whitespace keeps the document looking like the one they are spliced into.
//
// The whitespace rule is "mirror the layout that is already there, invent
// none": an insertion before a sibling reproduces that sibling's own line
// indent, an insertion before the closing tag steps in one level and back out,
// an insertion into an EMPTY DERControlBase — the release-only control, which
// is RC0 §9.5 row 9's own shape — takes the indentation the base's own line
// implies, and a document with no line breaks at all (encoding/xml's unindented
// Marshal) gets the elements and nothing else. Cosmetic: every branch produces
// the same XML infoset. It is here because a conformance bundle is read by
// people, and a document that looks hand-edited invites the question of what
// else was.
func nilElementsText(data []byte, lay *baseLayout, at int, axes []string) string {
	elems := make([]string, 0, len(axes))
	for _, axis := range axes {
		elems = append(elems, fmt.Sprintf("<%s xmlns:xsi=%q xsi:nil=%q/>", axis, xsiNamespace, "true"))
	}

	baseIndent, indented := lineIndentBefore(data, lay.openAt)
	if !indented {
		return strings.Join(elems, "")
	}
	childIndent := baseIndent + wireIndent
	if len(lay.kidAt) > 0 {
		if kidIndent, ok := lineIndentBefore(data, lay.kidAt[0]); ok && strings.HasPrefix(kidIndent, baseIndent) {
			childIndent = kidIndent
		}
	}
	sep := "\n" + childIndent

	if at != lay.closeAt {
		// Before a sibling: the break and indent that introduce it are already
		// in the document, so this text only has to recreate them behind itself.
		return strings.Join(elems, sep) + sep
	}
	if closeIndent, ok := lineIndentBefore(data, at); ok {
		// Before a </DERControlBase> on its own line: step in to the children's
		// level, then back out to the closing tag's.
		step := wireIndent
		if strings.HasPrefix(childIndent, closeIndent) {
			step = strings.TrimPrefix(childIndent, closeIndent)
		}
		return step + strings.Join(elems, sep) + "\n" + closeIndent
	}
	// An empty <DERControlBase></DERControlBase>, whose closing tag abuts its
	// opening one: there is no sibling and no break to mirror, so both come
	// from the base's own line.
	return sep + strings.Join(elems, sep) + "\n" + baseIndent
}

// lineIndentBefore returns the run of spaces and tabs between the newline
// preceding at and at itself, and reports whether at begins a line at all.
func lineIndentBefore(data []byte, at int) (string, bool) {
	i := at
	for i > 0 && (data[i-1] == ' ' || data[i-1] == '\t') {
		i--
	}
	if i == 0 || data[i-1] != '\n' {
		return "", false
	}
	return string(data[i:at]), true
}
