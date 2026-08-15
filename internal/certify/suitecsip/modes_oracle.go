package suitecsip

// modes_oracle.go is the INDEPENDENT oracle for DERCapability.modesSupported.
//
// # The defect class this file exists to kill
//
// A DER advertises what it can do in one 32-bit field, and every bit of it is a
// promise to a utility server. Grading that promise needs two things: the bit
// POSITIONS (which bit means which mode) and the EVIDENCE (which modes the
// device demonstrably honours). This suite already has machinery for the
// second. The first is where conformance harnesses go blind.
//
// The blindness has a name here — IW15-011, "shared-oracle blindness". The
// harness and the product both live in a tree that shares lexa-proto's
// csipmodel, and csipmodel carries a Mode* constant block. A harness that
// imported those constants to decode modesSupported would be asking the
// product's own table whether the product's own table is right. Every row would
// agree with every other row, the campaign would report green, and a wrong
// table would survive for months — which is exactly what happened to the
// DERCurveType codes, where product and harness agreed on an assignment that
// was wrong for every code ≥ 4 and nothing in a 282-case catalogue noticed. The
// same csipmodel Mode* block was wrong when this oracle was designed, and said
// so in its own doc comment ("RECORDED DIVERGENCE"): sixteen of the schema's
// twenty-two modes on the wrong bit.
//
// So this file HAND-TRANSCRIBES the bit positions from the schema text, cites
// the schema line for every one of them, and imports nothing from csipmodel.
// That is not a stylistic preference; it is the only thing that makes a green
// row mean anything. sepxml.go's doc comment states the same rule one layer
// down ("a model shared with the DUT's own parser would let a mutual misreading
// of the standard pass both sides") and this is that rule applied to a bitmap
// instead of to an element name.
//
// The agreement between this table and csipmodel's is asserted by
// TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong
// (modes_oracle_test.go). lexa-proto 9856710 corrected the product's table
// from the same schema, independently, while this file was being written, so
// that test passes — and the same file proves the comparison would have gone
// red against the table it was written for. When it does fail, its text refuses
// to say which side is wrong: it names both values and sends the reader to the
// schema, because a tripwire that assumed the harness was right would be the
// same single point of trust in a nicer costume.
//
// # Provenance of the table below
//
// Source: lexa-proto docs/schema/sep-2.0.4.xsd
//	sha256 2e0f7e22caa2cb98a85598d9ae8cb7cb5ca9ffac32f74e90377b274f688762ac
//	(lexa-proto @ 468f8bf, read 2026-08-15)
//
// Two places in that file are transcribed:
//
//   - lines 3825-3855, complexType "DERControlType" — the bit assignments
//     themselves, twenty-two of them, 0..21, under the sentence "Bit positions
//     SHALL be defined as follows". Line 3853 declares the type's base as
//     HexBinary32, which is what parseModesSupported reads it as.
//   - lines 3689-3794, complexType "DERControlBase" — the twenty opMod*
//     ELEMENTS a DERControl actually carries on the wire, which is how a mode
//     becomes observable in a transcript at all. Each element line is cited
//     against the bit it corresponds to.
//
// The two lists are not the same length and that is a fact about the schema, not
// a transcription slip: bits 19 (Charge mode) and 20 (Discharge mode) have NO
// DERControlBase element of their own — they are storage direction modes carried
// through opModFixedW's sign — so no transcript can ever evidence them by
// element name. They are in the table, marked with no element, and the oracle
// says so rather than silently treating them as unevidenceable-therefore-fine.
//
// modesSupported itself is declared at line 3571 of the same file
// (DERCapability's sequence, minOccurs=1) with type DERControlType.
//
// # One cross-document disagreement, recorded rather than absorbed
//
// CORE-014's own observables carry the line "modesSupported bit for
// opModMaxLimW shown as modesSupported=20 in the doc". Twenty is not
// opModMaxLimW's bit under sep 2.0.4 — that is bit 13 (line 3841) — and 20 is
// not the mask either, under any reading: hexadecimal 20 is bit 5
// (opModLVRTMomentaryCessation) and decimal 20 is bits 2 and 4. Whatever
// CSIP-CONF-v1.3 meant by the number, this oracle grades against the SCHEMA,
// which is the document the payload is validated by and the only one with a
// normative "Bit positions SHALL be defined as follows". The disagreement is
// written down here so that a reader who finds it in the catalogue knows it was
// seen and not quietly reconciled.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"csip-tls-test/internal/certify"
)

// derControlTypeBit is one row of sep 2.0.4's DERControlType bit assignment,
// hand-transcribed, with the schema line that says so.
type derControlTypeBit struct {
	// Bit is the position, 0-based, as the schema numbers it.
	Bit uint
	// Mode is the schema's own name for the mode at this position, verbatim
	// from the DERControlType documentation line.
	Mode string
	// Element is the DERControlBase element that carries this mode on the wire,
	// or "" for a bit the schema names but gives no element (bits 19 and 20).
	Element string
	// XSDLine is the line of sep-2.0.4.xsd carrying the bit assignment.
	XSDLine int
	// ElementLine is the line of sep-2.0.4.xsd declaring Element inside
	// complexType DERControlBase, or 0 when Element is "".
	ElementLine int
}

// derControlTypeBits is the transcription. TWENTY-TWO entries, 0..21.
//
// Read it against the schema, not against any Go source in this tree. Every
// XSDLine is a line you can `sed -n '<line>p'` out of lexa-proto's
// docs/schema/sep-2.0.4.xsd and compare word for word; the test file quotes the
// whole documentation block verbatim and rebuilds this table from the quote, so
// a typo here cannot pass unnoticed even without the schema file present.
var derControlTypeBits = []derControlTypeBit{
	// XSD 3828: "0 - opModVoltVar (Volt-Var Mode)"
	{Bit: 0, Mode: "opModVoltVar", Element: "opModVoltVar", XSDLine: 3828, ElementLine: 3774},
	// XSD 3829: "1 - opModFreqWatt (Frequency-Watt Curve Mode)"
	{Bit: 1, Mode: "opModFreqWatt", Element: "opModFreqWatt", XSDLine: 3829, ElementLine: 3724},
	// XSD 3830: "2 - opModFreqDroop (Frequency-Watt Parameterized Mode)"
	{Bit: 2, Mode: "opModFreqDroop", Element: "opModFreqDroop", XSDLine: 3830, ElementLine: 3719},
	// XSD 3831: "3 - opModWattPF (Watt-PowerFactor Mode)"
	{Bit: 3, Mode: "opModWattPF", Element: "opModWattPF", XSDLine: 3831, ElementLine: 3784},
	// XSD 3832: "4 - opModVoltWatt (Volt-Watt Mode)"
	{Bit: 4, Mode: "opModVoltWatt", Element: "opModVoltWatt", XSDLine: 3832, ElementLine: 3779},
	// XSD 3833: "5 - opModLVRTMomentaryCessation (Low Voltage Ride Through, Momentary Cessation Mode)"
	{Bit: 5, Mode: "opModLVRTMomentaryCessation", Element: "opModLVRTMomentaryCessation",
		XSDLine: 3833, ElementLine: 3749},
	// XSD 3834: "6 - opModLVRTMustTrip (Low Voltage Ride Through, Must Trip Mode)"
	{Bit: 6, Mode: "opModLVRTMustTrip", Element: "opModLVRTMustTrip", XSDLine: 3834, ElementLine: 3754},
	// XSD 3835: "7 - opModHVRTMomentaryCessation (High Voltage Ride Through, Momentary Cessation Mode)"
	{Bit: 7, Mode: "opModHVRTMomentaryCessation", Element: "opModHVRTMomentaryCessation",
		XSDLine: 3835, ElementLine: 3734},
	// XSD 3836: "8 - opModHVRTMustTrip (High Voltage Ride Through, Must Trip Mode)"
	{Bit: 8, Mode: "opModHVRTMustTrip", Element: "opModHVRTMustTrip", XSDLine: 3836, ElementLine: 3739},
	// XSD 3837: "9 - opModLFRTMustTrip (Low Frequency Ride Through, Must Trip Mode)"
	{Bit: 9, Mode: "opModLFRTMustTrip", Element: "opModLFRTMustTrip", XSDLine: 3837, ElementLine: 3744},
	// XSD 3838: "10 - opModHFRTMustTrip (High Frequency Ride Through, Must Trip Mode)"
	{Bit: 10, Mode: "opModHFRTMustTrip", Element: "opModHFRTMustTrip", XSDLine: 3838, ElementLine: 3729},
	// XSD 3839: "11 - opModConnect (Connect / Disconnect - implies galvanic isolation)"
	{Bit: 11, Mode: "opModConnect", Element: "opModConnect", XSDLine: 3839, ElementLine: 3694},
	// XSD 3840: "12 - opModEnergize (Energize / De-Energize)"
	{Bit: 12, Mode: "opModEnergize", Element: "opModEnergize", XSDLine: 3840, ElementLine: 3699},
	// XSD 3841: "13 - opModMaxLimW (Maximum Active Power)"
	{Bit: 13, Mode: "opModMaxLimW", Element: "opModMaxLimW", XSDLine: 3841, ElementLine: 3759},
	// XSD 3842: "14 - opModFixedVar (Reactive Power Setpoint)"
	{Bit: 14, Mode: "opModFixedVar", Element: "opModFixedVar", XSDLine: 3842, ElementLine: 3709},
	// XSD 3843: "15 - opModFixedPF (Fixed Power Factor Setpoint)"
	{Bit: 15, Mode: "opModFixedPF", Element: "opModFixedPF", XSDLine: 3843, ElementLine: 3704},
	// XSD 3844: "16 - opModFixedW (Charge / Discharge Setpoint)"
	{Bit: 16, Mode: "opModFixedW", Element: "opModFixedW", XSDLine: 3844, ElementLine: 3714},
	// XSD 3845: "17 - opModTargetW (Target Active Power)"
	{Bit: 17, Mode: "opModTargetW", Element: "opModTargetW", XSDLine: 3845, ElementLine: 3769},
	// XSD 3846: "18 - opModTargetVar (Target Reactive Power)"
	{Bit: 18, Mode: "opModTargetVar", Element: "opModTargetVar", XSDLine: 3846, ElementLine: 3764},
	// XSD 3847: "19 - Charge mode". No DERControlBase element: the schema names
	// the mode and gives it no carriage of its own.
	{Bit: 19, Mode: "Charge mode", Element: "", XSDLine: 3847},
	// XSD 3848: "20 - Discharge mode". Likewise.
	{Bit: 20, Mode: "Discharge mode", Element: "", XSDLine: 3848},
	// XSD 3849: "21 - opModWattVar (Watt-Var Mode)"
	{Bit: 21, Mode: "opModWattVar", Element: "opModWattVar", XSDLine: 3849, ElementLine: 3789},
}

// modesSupportedReservedFrom is the first bit position sep 2.0.4 does NOT
// assign. Line 3850: "All other values reserved." A DER that sets one is
// advertising a mode the standard has not defined, which no evidence can ever
// justify and which this oracle grades as an overclaim in its own right.
const modesSupportedReservedFrom = 22

// bitForElement resolves a DERControlBase element name to its schema bit.
func bitForElement(element string) (derControlTypeBit, bool) {
	for _, b := range derControlTypeBits {
		if b.Element != "" && b.Element == element {
			return b, true
		}
	}
	return derControlTypeBit{}, false
}

// bitAt returns the transcription row for a bit position.
func bitAt(pos uint) (derControlTypeBit, bool) {
	for _, b := range derControlTypeBits {
		if b.Bit == pos {
			return b, true
		}
	}
	return derControlTypeBit{}, false
}

// setBits lists the positions set in a mask, ascending.
func setBits(mask uint32) []uint {
	var out []uint
	for i := uint(0); i < 32; i++ {
		if mask&(1<<i) != 0 {
			out = append(out, i)
		}
	}
	return out
}

// describeMask renders a mask as the schema's own mode names, so a finding
// never makes a reader do hex in their head.
func describeMask(mask uint32) string {
	pos := setBits(mask)
	if len(pos) == 0 {
		return "no bits set"
	}
	var parts []string
	for _, p := range pos {
		if b, ok := bitAt(p); ok {
			parts = append(parts, fmt.Sprintf("bit %d %s", p, b.Mode))
			continue
		}
		parts = append(parts, fmt.Sprintf("bit %d RESERVED by sep 2.0.4 (line 3850)", p))
	}
	return strings.Join(parts, ", ")
}

// hexBinary32 is the lexical space of the type modesSupported extends
// (sep-2.0.4.xsd line 3853, `<xs:extension base="HexBinary32"/>`): up to eight
// hexadecimal digits.
var hexBinary32 = regexp.MustCompile(`^[0-9a-fA-F]{1,8}$`)

// decimalText matches a wholly decimal rendering, which is what a serializer
// that treats modesSupported as a plain integer emits.
var decimalText = regexp.MustCompile(`^[0-9]{1,10}$`)

// modesMask is a decoded modesSupported, with the ambiguity kept rather than
// resolved away.
//
// # Why there are two numbers here
//
// The schema says HexBinary32 (line 3853), so the SCHEMA reading of the element
// text is hexadecimal, and that is the reading Value carries and the reading
// the oracle grades on. But a serializer that models the field as a bare
// unsigned integer emits decimal — lexa-proto's own DERCapabilityFull does
// exactly that, `ModesSupported uint32` with no hexBinary marshaller — and for
// a text made only of the digits 0-9 both readings are lexically valid and
// numerically different: "8192" is bit 13 read as decimal and bits 1,4,7,8,15
// read as hex. A reader of a bundle is entitled to know when the number they
// are being shown depended on which of the two the harness picked.
//
// LEADING ZEROS SETTLE IT, and that is why this is a narrow disclosure rather
// than a permanent caveat on every row. A HexBinary32 is conventionally written
// to its full width, and no integer serializer emits "00002000" for two
// thousand — it writes "2000". So a text longer than one character that starts
// with '0' is unambiguously the schema's rendering, and Decimal stays nil.
// Decimal is filled in only for a text that BOTH readings could plausibly have
// produced: all decimal digits, no leading zero, and the two values differ.
type modesMask struct {
	// Text is the element's character data, verbatim.
	Text string
	// Value is the schema (HexBinary32) reading.
	Value uint32
	// Decimal is the alternate decimal reading when the text admits one AND it
	// differs from Value; nil otherwise.
	Decimal *uint32
}

// Ambiguous reports whether the wire text reads differently under the schema's
// HexBinary32 and under a plain-decimal serialization.
func (m modesMask) Ambiguous() bool { return m.Decimal != nil }

// parseModesSupported decodes the character data of a <modesSupported> element.
func parseModesSupported(text string) (modesMask, error) {
	t := strings.TrimSpace(text)
	if t == "" {
		return modesMask{}, fmt.Errorf("the <modesSupported> element is present but empty; sep 2.0.4 " +
			"line 3571 declares it minOccurs=1 with type DERControlType, whose lexical space (line 3853, " +
			"base HexBinary32) has no empty member")
	}
	if !hexBinary32.MatchString(t) {
		return modesMask{}, fmt.Errorf("the <modesSupported> text %q is not a HexBinary32 value; sep 2.0.4 "+
			"line 3853 gives DERControlType the base HexBinary32, whose lexical space is one to eight "+
			"hexadecimal digits", t)
	}
	v, err := strconv.ParseUint(t, 16, 32)
	if err != nil {
		return modesMask{}, fmt.Errorf("the <modesSupported> text %q did not decode as HexBinary32: %w", t, err)
	}
	m := modesMask{Text: t, Value: uint32(v)}
	// Zero-padded text is the schema's own rendering and nothing else's — see
	// the type's doc. Only an unpadded all-decimal text is genuinely ambiguous.
	if decimalText.MatchString(t) && (len(t) == 1 || t[0] != '0') {
		if d, derr := strconv.ParseUint(t, 10, 32); derr == nil && uint32(d) != m.Value {
			alt := uint32(d)
			m.Decimal = &alt
		}
	}
	return m, nil
}

// ── The evidence half ────────────────────────────────────────────────────────

// modeControlEvidence is what one DERControlBase element got from the DUT.
type modeControlEvidence struct {
	// Carried are the mRIDs of controls the DUT FETCHED that named this mode.
	Carried []string
	// Executed are the mRIDs the DUT answered with status 2 (Event started) or
	// 3 (Event completed) — the statuses that assert the control ran.
	Executed []string
	// Refused are the mRIDs the DUT answered with a cannot-comply status
	// (refusalStatuses, curve.go) and never with 2 or 3.
	Refused []string
}

// modesEvidence is everything the oracle knows before it grades.
type modesEvidence struct {
	// Mask is the DERCapability the DUT served, decoded.
	Mask modesMask
	// MaskWhere says which observation the mask came from, in a sentence.
	MaskWhere string
	// MaskMsg is the message to cite, when the mask came from the transcript.
	MaskMsg *Message
	// MaskErr is set when a DERCapability was found but its modesSupported
	// could not be decoded.
	MaskErr error

	// ByMode is the per-element execution record, keyed by DERControlBase
	// element name.
	ByMode map[string]*modeControlEvidence

	// Scope is the honest description of HOW FAR the executed-mode half
	// reaches: this row's own window, or a wider transcript.
	Scope string

	// PICS is the operator-declared mode list, empty when none was supplied.
	PICS []string
	// PICSRaw is what the operator actually typed, for the finding.
	PICSRaw string
}

// gatherModesEvidence reads a transcript for everything the oracle needs.
//
// The transcript is the only place the mode↔mRID correspondence exists.
// gridsim's admin API records Responses as (subject, status, lfdi) and its
// control list as (mrid, description, ...) — neither carries the DERControlBase
// element that says WHICH MODE a control commanded, so a run whose transcript
// did not decrypt cannot evidence the executed-mode half at all, and the
// tier-3 evaluator says exactly that rather than passing on a vacuum.
func gatherModesEvidence(t *Transcript) modesEvidence {
	e := modesEvidence{ByMode: map[string]*modeControlEvidence{}}

	// The DUT's own claim first: the DERCapability it PUT. Last one wins — a
	// DUT that re-reports mid-window is reporting a change, and the current
	// claim is the one being graded.
	for _, ex := range t.Method("PUT") {
		if ex.Req == nil || len(ex.Req.Body) == 0 {
			continue
		}
		doc, err := ex.Req.SEP()
		if err != nil || doc.Local() != "DERCapability" {
			continue
		}
		e.readMask(doc, ex.Req, "the DERCapability the DUT PUT to "+ex.Req.Target)
	}
	// Failing that, the server's copy served back on a GET — CORE-014 erratum
	// 23 makes those the values the client previously PUT.
	if e.MaskWhere == "" {
		if ex, doc, ok := t.Resource("DERCapability"); ok {
			e.readMask(doc, ex.Resp, "the DERCapability the server served back on GET "+ex.Req.Target+
				" (CORE-014 erratum 23: a GET returns the values the client previously PUT)")
		}
	}

	// mRID -> modes, over every DERControlList the DUT fetched.
	modesOf := map[string][]string{}
	for _, ex := range t.ByResource("DERControlList") {
		doc, err := ex.Resp.SEP()
		if err != nil {
			continue
		}
		for _, ctrl := range doc.Children("DERControl") {
			mrid, _ := ctrl.TextOf("mRID")
			if mrid == "" {
				continue
			}
			base := ctrl.Child("DERControlBase")
			if base == nil {
				continue
			}
			for _, kid := range base.Kids {
				name := kid.Local()
				if _, ok := bitForElement(name); !ok {
					continue
				}
				modesOf[mrid] = appendUnique(modesOf[mrid], name)
				e.mode(name).Carried = appendUnique(e.mode(name).Carried, mrid)
			}
		}
	}

	// subject -> statuses, from the Response-family POSTs.
	statusesOf := map[string]map[uint64]bool{}
	for _, ex := range t.Method("POST") {
		if ex.Req == nil || len(ex.Req.Body) == 0 {
			continue
		}
		doc, err := ex.Req.SEP()
		if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
			continue
		}
		subj, _ := doc.TextOf("subject")
		if subj == "" {
			continue
		}
		st, ok := doc.UintOf("status")
		if !ok {
			continue
		}
		if statusesOf[subj] == nil {
			statusesOf[subj] = map[uint64]bool{}
		}
		statusesOf[subj][st] = true
	}

	for mrid, modes := range modesOf {
		sts := statusesOf[mrid]
		executed := sts[2] || sts[3]
		refused := false
		for _, s := range refusalStatuses {
			if sts[uint64(s)] {
				refused = true
			}
		}
		for _, m := range modes {
			switch {
			case executed:
				e.mode(m).Executed = appendUnique(e.mode(m).Executed, mrid)
			case refused:
				e.mode(m).Refused = appendUnique(e.mode(m).Refused, mrid)
			}
		}
	}
	e.sortRecords()
	return e
}

// readMask decodes a DERCapability document's modesSupported into the evidence.
func (e *modesEvidence) readMask(doc *Node, cite *Message, where string) {
	el := doc.Child("modesSupported")
	if el == nil {
		e.MaskErr = fmt.Errorf("%s carries NO <modesSupported> element at all, and sep 2.0.4 line 3571 "+
			"declares it minOccurs=1 on DERCapability — it is not an optional field", where)
		e.MaskWhere, e.MaskMsg = where, cite
		return
	}
	m, err := parseModesSupported(el.Text)
	e.Mask, e.MaskErr, e.MaskWhere, e.MaskMsg = m, err, where, cite
}

// mode returns (creating if needed) the record for a DERControlBase element.
func (e *modesEvidence) mode(name string) *modeControlEvidence {
	if e.ByMode[name] == nil {
		e.ByMode[name] = &modeControlEvidence{}
	}
	return e.ByMode[name]
}

func (e *modesEvidence) sortRecords() {
	for _, r := range e.ByMode {
		sort.Strings(r.Carried)
		sort.Strings(r.Executed)
		sort.Strings(r.Refused)
	}
}

// modeNames lists the element names in the evidence, sorted, for stable prose.
func (e *modesEvidence) modeNames() []string {
	out := make([]string, 0, len(e.ByMode))
	for k := range e.ByMode {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

// ── The grading half ─────────────────────────────────────────────────────────

// gradeModesSupported decides both directions and writes the sentence.
//
// It NEVER returns Unavailable for anything that is a fact about the DUT. The
// only unavailability it can produce is "no DERCapability was observed at all",
// which is a fact about the window and is left to the next tier — see
// critModesSupportedCoherent's Server arm, and CORE-014's own
// critDERPut("DERCapability"), which fails the row for that absence anyway.
func gradeModesSupported(e modesEvidence) Finding {
	if e.MaskWhere == "" {
		return unavailable("no DERCapability was observed in this window, so the DUT's modesSupported " +
			"could not be read; this criterion has nothing to grade and the row's own DERCapability PUT " +
			"criterion is where that absence is a verdict")
	}
	if e.MaskErr != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%s could not be decoded as the schema's own type: %v. An advertisement a conformance reader "+
				"cannot decode is not a weaker advertisement, it is an undecidable one, and this oracle "+
				"grades it as a failure of the payload rather than reporting the DUT as unmeasured",
			e.MaskWhere, e.MaskErr)}
	}

	verdict, body := gradeMaskAgainstEvidence(e, e.Mask.Value, "")
	if e.Mask.Ambiguous() {
		altVerdict, altBody := gradeMaskAgainstEvidence(e, *e.Mask.Decimal, "")
		note := fmt.Sprintf(". AMBIGUOUS SERIALIZATION: the wire text %q is lexically valid under BOTH "+
			"sep 2.0.4's HexBinary32 (line 3853), which this oracle graded and which reads it as 0x%08X "+
			"(%s), AND under a plain-decimal serialization, which reads it as 0x%08X (%s). Under the "+
			"decimal reading this criterion would be %s: %s. Which serialization the DUT intended is a "+
			"question about the DUT that the wire does not answer, and it must be settled before either "+
			"verdict is relied on",
			e.Mask.Text, e.Mask.Value, describeMask(e.Mask.Value), *e.Mask.Decimal,
			describeMask(*e.Mask.Decimal), altVerdict, altBody)
		body += note
		// The schema reading passing while the other fails is not a pass: it is
		// a pass that depended on a choice the payload left open.
		if verdict == certify.Pass && altVerdict != certify.Pass {
			verdict = certify.Warn
		}
	}
	return Finding{Verdict: verdict, Observed: body}
}

// gradeMaskAgainstEvidence is the decision, run on ONE reading of the mask.
func gradeMaskAgainstEvidence(e modesEvidence, mask uint32, _ string) (certify.Verdict, string) {
	var overclaims, underclaims, reserved []string
	var advertised, evidenced, silent []string

	// ── Direction (b): executed but not advertised ───────────────────────
	for _, name := range e.modeNames() {
		r := e.ByMode[name]
		if len(r.Executed) == 0 {
			continue
		}
		b, ok := bitForElement(name)
		if !ok {
			continue
		}
		evidenced = append(evidenced, fmt.Sprintf("%s (bit %d, mRID %s)", name, b.Bit,
			strings.Join(r.Executed, "/")))
		if mask&(1<<b.Bit) == 0 {
			underclaims = append(underclaims, fmt.Sprintf(
				"%s: the DUT answered Response status 2 (Event started) or 3 (Event completed) for "+
					"control(s) %s whose DERControlBase named <%s>, and bit %d — which sep 2.0.4 line %d "+
					"assigns to %s — is CLEAR in the mask it advertises",
				name, strings.Join(r.Executed, ", "), name, b.Bit, b.XSDLine, b.Mode))
		}
	}

	// ── Direction (a): advertised but refused, or reserved ───────────────
	for _, pos := range setBits(mask) {
		b, ok := bitAt(pos)
		if !ok {
			reserved = append(reserved, fmt.Sprintf(
				"bit %d is set and sep 2.0.4 assigns no mode to it — line 3850 of the schema says \"All "+
					"other values reserved\" of every position above %d, so nothing the DUT could do "+
					"would make this bit honest", pos, modesSupportedReservedFrom-1))
			continue
		}
		advertised = append(advertised, fmt.Sprintf("bit %d %s", b.Bit, b.Mode))
		r := e.ByMode[b.Element]
		switch {
		case b.Element == "":
			silent = append(silent, fmt.Sprintf("bit %d %s (the schema gives this mode no DERControlBase "+
				"element, so no transcript can evidence it either way)", b.Bit, b.Mode))
		case r == nil || (len(r.Executed) == 0 && len(r.Refused) == 0):
			if picsDeclares(e.PICS, b) {
				continue
			}
			silent = append(silent, fmt.Sprintf("bit %d %s (no control naming <%s> drew an execution or a "+
				"refusal in this evidence)", b.Bit, b.Mode, b.Element))
		case len(r.Executed) > 0:
			// Advertised and demonstrably honoured. Nothing to say.
		default:
			overclaims = append(overclaims, fmt.Sprintf(
				"%s: bit %d is SET — sep 2.0.4 line %d assigns it to %s — and the DUT REFUSED every "+
					"control that named <%s> (mRID %s), answering a cannot-comply status and never 2 "+
					"(Event started) or 3 (Event completed). The mask promises a utility server a mode "+
					"the DUT declines to perform",
				b.Element, b.Bit, b.XSDLine, b.Mode, b.Element, strings.Join(r.Refused, ", ")))
		}
	}

	// ── Direction (a), PICS half: advertised outside the declaration ─────
	if len(e.PICS) > 0 {
		for _, pos := range setBits(mask) {
			b, ok := bitAt(pos)
			if !ok || picsDeclares(e.PICS, b) {
				continue
			}
			if r := e.ByMode[b.Element]; r != nil && len(r.Executed) > 0 {
				overclaims = append(overclaims, fmt.Sprintf(
					"%s: bit %d is set and the DUT demonstrably executes it, but the operator-supplied "+
						"PICS (%s) does not declare it. The device and its own declaration disagree, "+
						"which is a finding about the submission whichever of the two is right",
					b.Mode, b.Bit, e.PICSRaw))
				continue
			}
			overclaims = append(overclaims, fmt.Sprintf(
				"%s: bit %d is SET — sep 2.0.4 line %d — and it is neither declared by the "+
					"operator-supplied PICS (%s) nor evidenced by anything the DUT did in this evidence. "+
					"A bit outside the declaration is an advertisement nobody stands behind",
				b.Mode, b.Bit, b.XSDLine, e.PICSRaw))
		}
	}

	// ── The sentence ─────────────────────────────────────────────────────
	head := fmt.Sprintf("%s advertises modesSupported=%q, which sep 2.0.4 (line 3853, base HexBinary32) "+
		"reads as 0x%08X = %s. Scope of the executed-mode half: %s",
		e.MaskWhere, e.Mask.Text, mask, describeMask(mask), e.Scope)
	if len(e.PICS) > 0 {
		head += fmt.Sprintf(". PICS declaration supplied by the operator: %s", e.PICSRaw)
	}
	if len(evidenced) > 0 {
		head += ". Modes this evidence PROVES the DUT executed: " + strings.Join(evidenced, "; ")
	} else {
		head += ". This evidence proves NO mode executed (no control drew a status 2 or 3), so the " +
			"executed-but-not-advertised direction had nothing to test"
	}

	var problems []string
	problems = append(problems, underclaims...)
	problems = append(problems, overclaims...)
	problems = append(problems, reserved...)
	if len(problems) > 0 {
		return certify.Fail, fmt.Sprintf("%s. INCOHERENT in %d place(s): %s", head, len(problems),
			strings.Join(problems, " | "))
	}
	tail := ". Every bit set is a mode this evidence or the declaration stands behind, and every mode " +
		"this evidence proves executed has its bit set"
	if len(advertised) == 0 {
		tail = ". The mask sets NO bits: the DUT advertises no operating mode at all, which is coherent " +
			"with this evidence only because nothing in it proves a mode executed"
	}
	if len(silent) > 0 {
		tail += ". Bits set that this evidence can say nothing about, neither for nor against: " +
			strings.Join(silent, "; ")
	}
	return certify.Pass, head + tail
}

// picsDeclares reports whether the operator's PICS list names this bit, by
// either the schema's mode name or its bit number.
func picsDeclares(pics []string, b derControlTypeBit) bool {
	for _, p := range pics {
		if strings.EqualFold(p, b.Mode) || strings.EqualFold(p, b.Element) || p == strconv.Itoa(int(b.Bit)) {
			return true
		}
	}
	return false
}

// modesSupportedPICSParam is how an operator supplies the vendor's PICS
// declaration to this oracle: a comma-separated list of sep 2.0.4 mode names
// (opModMaxLimW), DERControlBase element names, or bit numbers.
//
// Without it, a set bit that the evidence neither proves nor refutes is
// DISCLOSED and not graded — the honest answer for a window that did not
// exercise the mode. With it, such a bit becomes gradable: a bit outside the
// declaration is an advertisement nobody stands behind, and a mode the DUT
// executes but the declaration omits is a disagreement between the device and
// its own paperwork.
const modesSupportedPICSParam = "csip.pics_modes_supported"

// parsePICSModes splits the operator's declaration.
func parsePICSModes(raw string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ── The criterion ────────────────────────────────────────────────────────────

// modesScopeRowWindow is the honest Scope sentence for a row that grades the
// mask against its OWN window rather than against a whole campaign transcript.
const modesScopeRowWindow = "this row's own capture window only — the executed-but-not-advertised " +
	"direction can only see modes THIS row's window put on the wire and this row's window drew a " +
	"Response for, so it under-reports a DUT that executes a mode elsewhere in the campaign; a bit " +
	"this window cannot speak to is disclosed, never credited"

// critModesSupportedCoherent is the independent modesSupported oracle as a
// catalog-row criterion. Both directions, one verdict.
//
//	(a) OVERCLAIM — every bit SET must be a mode the DUT stands behind. A bit
//	    whose mode the DUT REFUSED (cannot-comply, never started/completed) is a
//	    promise to a utility server the device declines to keep, and fails. A bit
//	    sep 2.0.4 does not assign at all fails on the schema alone. With a PICS
//	    supplied, a bit outside the declaration fails too.
//
//	(b) UNDERCLAIM — every mode this evidence PROVES executed (a control naming
//	    that DERControlBase element which the DUT answered status 2 or 3) must
//	    have its bit SET. A device that runs a mode it does not advertise has told
//	    the head end something false in the safer direction, and a head end that
//	    reads modesSupported to decide what to send will never send it.
//
// The bit positions come from derControlTypeBits — this file's own hand
// transcription of sep-2.0.4.xsd — and from nothing else. Not from
// lexa-proto/csipmodel, whose table is wrong today and whose agreement with the
// DUT would make every verdict below vacuous.
//
// There is no SKIP path through the decision: once a DERCapability is in hand,
// this criterion returns a verdict. The single Unavailable it can return is "no
// DERCapability was observed at all", which hands the question to the next tier
// rather than to nobody.
func critModesSupportedCoherent(o *Observation, picsRaw string) criterion {
	pics := parsePICSModes(picsRaw)
	return criterion{
		Claim: "every bit set in the DERCapability.modesSupported the DUT serves is a mode it stands " +
			"behind, and every mode it demonstrably executed has its bit set",
		How: "the modesSupported bitmap decoded against bit positions HAND-TRANSCRIBED from " +
			"lexa-proto docs/schema/sep-2.0.4.xsd lines 3828-3849 (complexType DERControlType, \"Bit " +
			"positions SHALL be defined as follows\") as HexBinary32 (line 3853), carrying NO dependency " +
			"on lexa-proto/csipmodel's Mode* constants — the product's own table, which currently " +
			"disagrees with the schema and whose agreement with the DUT would make this check vacuous " +
			"(IW15-011) — cross-checked against the DERControlBase element each control carried " +
			"(schema lines 3694-3789) and the Response status the DUT POSTed for it",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			e := gatherModesEvidence(t)
			e.Scope, e.PICS, e.PICSRaw = modesScopeRowWindow, pics, picsRaw
			if e.MaskWhere == "" {
				// The transcript had no DERCapability. Before giving up on the
				// tier, try what the server stored for THIS RUN — the DER
				// self-reports are cadence-driven and routinely predate a
				// narrow window (see ServerView.RunDERPuts).
				if f, ok := maskFromServer(&o.Server, &e); ok {
					return f
				}
			}
			f := gradeModesSupported(e)
			if f.Unavailable != "" || e.MaskMsg == nil {
				return f
			}
			return citeMessage(t, e.MaskMsg, f.Verdict, "%s", f.Observed)
		},
		Server: func(v *ServerView) Finding {
			e := modesEvidence{ByMode: map[string]*modeControlEvidence{}, PICS: pics, PICSRaw: picsRaw}
			e.Scope = "NOTHING — this run graded the mask from gridsim's stored DER self-report, and " +
				"gridsim records Responses as (subject, status, LFDI) and controls as (mRID, " +
				"description): neither carries the DERControlBase element that says which MODE a " +
				"control commanded, so the executed-but-not-advertised direction is not testable at " +
				"this tier and no bit is credited by it"
			if f, ok := maskFromServer(v, &e); ok {
				return f
			}
			return unavailable("gridsim recorded no DERCapability PUT from the DUT in this run, so there " +
				"is no served modesSupported to grade")
		},
		Skip: "neither the decrypted transcript nor gridsim's stored DER self-reports carried a " +
			"DERCapability for this run, so the DUT's modesSupported was never observed at all",
	}
}

// maskFromServer fills e's mask from gridsim's stored DER self-reports and
// grades. It prefers the run-scoped record for the reason RunDERPuts exists:
// the DUT self-reports on its own cadence and the one a case is written to
// observe routinely lands before that case's window opens.
func maskFromServer(v *ServerView, e *modesEvidence) (Finding, bool) {
	if v == nil {
		return Finding{}, false
	}
	puts := v.PutsFor("DERCapability")
	where := "the DERCapability the DUT PUT during this row's window, as gridsim stored it"
	if len(puts) == 0 {
		puts = v.PutsForInRun("DERCapability")
		where = "the DERCapability the DUT PUT earlier in this RUN, as gridsim stored it (the DER " +
			"self-reports are cadence-driven and routinely predate a single row's window)"
	}
	if len(puts) == 0 {
		return Finding{}, false
	}
	doc, err := ParseSEP([]byte(puts[len(puts)-1].Body))
	if err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DERCapability body gridsim stored for this DUT did not parse as sep+xml: %v", err)}, true
	}
	e.readMask(doc, nil, where)
	f := gradeModesSupported(*e)
	if f.Unavailable != "" {
		return f, true
	}
	f.Observed += " (evaluated on the body gridsim stored, not on the wire)"
	return f, true
}
