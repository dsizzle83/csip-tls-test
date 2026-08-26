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
// was wrong for every code ≥ 4 and nothing in a 282-case catalogue noticed.
//
// # The independence rule, as the campaign had to learn it (IW15-027)
//
// The FIRST version of this file obeyed the rule as far as CODE goes: it
// hand-transcribed the bit table rather than importing csipmodel's, cited a
// line of docs/schema/sep-2.0.4.xsd for every position, and imported nothing
// from the product. Three witnesses — this transcription, csipmodel's constants,
// and the census test that parsed the file — then agreed, and the tripwire below
// went green.
//
// All three had read the SAME BOOK, and the book was the wrong one.
// docs/schema/sep-2.0.4.xsd is the pre-publication ZigBee Smart Energy Profile
// 2.0 draft (its own header says version 2.0.4, © 2011-2013 ZigBee Alliance, and
// its targetNamespace is http://ieee.org/2030.5 rather than the published
// urn:ieee:std:2030.5:ns every document on this bench carries). It assigns
// twenty-two bits in a completely different order from the standard this product
// is certified against.
//
//	A WITNESS IS INDEPENDENT ONLY IF ITS SOURCE IS. Agreement among three
//	readers of one document is one witness wearing three coats.
//
// So the table below is transcribed from IEEE Std 2030.5-2018 — the PUBLISHED
// standard, printed pages 251-252 — which is a document that does not live in
// this repository and cannot be re-derived from anything that does. The test
// file carries the standard's own sentence verbatim, with its page cite, and
// rebuilds the table from that text; a reviewer compares text against text. See
// lexa-proto docs/schema/NORMATIVE_ANCHOR.md for the full three-way census
// (2018 vs 2023 vs the draft) and for why the draft is a reference artifact and
// not an anchor.
//
// The XSD is still worth citing where it AGREES, and the divergence is itself
// asserted (TestModesOracleBitTable_DivergesFromTheDraftExactlyAsTheCensusSays)
// so that a re-vendored schema — or a future edit that quietly re-anchors this
// file to the file it can reach — fails loudly instead of silently.
//
// # Provenance of the table below
//
// Source: IEEE Std 2030.5-2018, "IEEE Standard for Smart Energy Profile
// Application Protocol", © 2018 IEEE. Local corpus copy:
// ~/Documents/standards/20305-2018.pdf. PAGE CITES ARE PRINTED PAGE NUMBERS,
// which run one lower than the PDF page index.
//
// Two places in that document are transcribed:
//
//   - printed p.251-252, "DERControlType object (HexBinary32) — Control modes
//     supported by the DER. Bit positions SHALL be defined as follows:" —
//     twenty-seven assignments, bits 0..26, then "All other values reserved."
//     The object's own declaration gives it the base HexBinary32, which is what
//     parseModesSupported reads the element text as (2018 p.174).
//   - printed p.248-251, "DERControlBase object ()" — the twenty-five opMod*
//     ATTRIBUTES a DERControl actually carries on the wire, which is how a mode
//     becomes observable in a transcript at all. Each is cited by page against
//     the bit it corresponds to.
//
// The two lists are not the same length and that is a fact about the standard,
// not a transcription slip: bits 0 (Charge mode) and 1 (Discharge mode) have NO
// DERControlBase element of their own — they are storage direction modes carried
// through opModFixedW's sign — so no transcript can ever evidence them by
// element name. They are in the table, marked with no element, and the oracle
// says so rather than silently treating them as unevidenceable-therefore-fine.
//
// IEEE Std 2030.5-2023 (p.274-275) is the corroborating witness: identical for
// bits 0..26, and it DEFINES 27..31 (opModDeltaVar, opModDeltaW, opModFixedV,
// opModGridConnectPermit, opModIslandPermit) which 2018 reserves. This oracle is
// anchored to 2018, so it grades 27..31 as reserved and says the 2023 sentence
// out loud when it does — a DUT built to the newer revision must not be told it
// invented a bit.
//
// # A cross-document disagreement, now WITHDRAWN
//
// CORE-014's own observables carry the line "modesSupported bit for
// opModMaxLimW shown as modesSupported=20 in the doc". Under the draft schema
// that number matched nothing, and this file used to record the mismatch as an
// unreconciled disagreement with the catalog. Under the published standard it
// is simply RIGHT: IEEE 2030.5-2018 p.252 assigns opModMaxLimW to bit 20. The
// catalog was correct and the accusation is withdrawn — which is the shape this
// whole wave keeps taking, and the reason the draft was worth un-anchoring from.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"csip-tls-test/internal/certify"
)

// derControlTypeBit is one row of IEEE 2030.5-2018's DERControlType bit
// assignment, hand-transcribed, with the printed page that says so.
type derControlTypeBit struct {
	// Bit is the position, 0-based, as the standard numbers it.
	Bit uint
	// Mode is the standard's own name for the mode at this position, verbatim
	// from the DERControlType assignment line.
	Mode string
	// Element is the DERControlBase element that carries this mode on the wire,
	// or "" for a bit the standard names but gives no element (bits 0 and 1).
	Element string
	// Page is the PRINTED page of IEEE Std 2030.5-2018 carrying the bit
	// assignment. Printed page = PDF page index − 1.
	Page int
	// ElementPage is the printed page declaring Element as an attribute of
	// DERControlBase, or 0 when Element is "".
	ElementPage int
}

// derControlTypeBits is the transcription. TWENTY-SEVEN entries, 0..26.
//
// Read it against IEEE Std 2030.5-2018, not against any Go source in this tree
// and not against the vendored draft schema. Every Page is a printed page you
// can open and compare word for word; the test file quotes the standard's whole
// assignment block verbatim and rebuilds this table from the quote, so a typo
// here cannot pass unnoticed even on a machine with no copy of the standard.
var derControlTypeBits = []derControlTypeBit{
	// 2018 p.251: "0 = Charge mode". No DERControlBase element: the standard
	// names the mode and gives it no carriage of its own.
	{Bit: 0, Mode: "Charge mode", Element: "", Page: 251},
	// 2018 p.251: "1 = Discharge mode". Likewise.
	{Bit: 1, Mode: "Discharge mode", Element: "", Page: 251},
	// 2018 p.251: "2 = opModConnect (connect/disconnect—implies galvanic isolation)"
	{Bit: 2, Mode: "opModConnect", Element: "opModConnect", Page: 251, ElementPage: 248},
	// 2018 p.251: "3 = opModEnergize (energize/de-energize)"
	{Bit: 3, Mode: "opModEnergize", Element: "opModEnergize", Page: 251, ElementPage: 248},
	// 2018 p.251: "4 = opModFixedPFAbsorbW (fixed power factor setpoint when absorbing active power)"
	{Bit: 4, Mode: "opModFixedPFAbsorbW", Element: "opModFixedPFAbsorbW", Page: 251, ElementPage: 248},
	// 2018 p.251: "5 = opModFixedPFInjectW (fixed power factor setpoint when injecting active power)"
	{Bit: 5, Mode: "opModFixedPFInjectW", Element: "opModFixedPFInjectW", Page: 251, ElementPage: 248},
	// 2018 p.251: "6 = opModFixedVar (reactive power setpoint)"
	{Bit: 6, Mode: "opModFixedVar", Element: "opModFixedVar", Page: 251, ElementPage: 248},
	// 2018 p.252: "7 = opModFixedW (charge/discharge setpoint)"
	{Bit: 7, Mode: "opModFixedW", Element: "opModFixedW", Page: 252, ElementPage: 248},
	// 2018 p.252: "8 = opModFreqDroop (Frequency-Watt Parameterized mode)"
	{Bit: 8, Mode: "opModFreqDroop", Element: "opModFreqDroop", Page: 252, ElementPage: 248},
	// 2018 p.252: "9 = opModFreqWatt (Frequency-Watt Curve mode)"
	{Bit: 9, Mode: "opModFreqWatt", Element: "opModFreqWatt", Page: 252, ElementPage: 248},
	// 2018 p.252: "10 = opModHFRTMayTrip (High Frequency Ride-Through, May Trip mode)"
	{Bit: 10, Mode: "opModHFRTMayTrip", Element: "opModHFRTMayTrip", Page: 252, ElementPage: 248},
	// 2018 p.252: "11 = opModHFRTMustTrip (High Frequency Ride-Through, Must Trip mode)"
	{Bit: 11, Mode: "opModHFRTMustTrip", Element: "opModHFRTMustTrip", Page: 252, ElementPage: 249},
	// 2018 p.252: "12 = opModHVRTMayTrip (High Voltage Ride-Through, May Trip mode)"
	{Bit: 12, Mode: "opModHVRTMayTrip", Element: "opModHVRTMayTrip", Page: 252, ElementPage: 249},
	// 2018 p.252: "13 = opModHVRTMomentaryCessation (High Voltage Ride-Through, Momentary Cessation mode)"
	{Bit: 13, Mode: "opModHVRTMomentaryCessation", Element: "opModHVRTMomentaryCessation",
		Page: 252, ElementPage: 249},
	// 2018 p.252: "14 = opModHVRTMustTrip (High Voltage Ride-Through, Must Trip mode)"
	{Bit: 14, Mode: "opModHVRTMustTrip", Element: "opModHVRTMustTrip", Page: 252, ElementPage: 249},
	// 2018 p.252: "15 = opModLFRTMayTrip (Low Frequency Ride-Through, May Trip mode)"
	{Bit: 15, Mode: "opModLFRTMayTrip", Element: "opModLFRTMayTrip", Page: 252, ElementPage: 249},
	// 2018 p.252: "16 = opModLFRTMustTrip (Low Frequency Ride-Through, Must Trip mode)"
	{Bit: 16, Mode: "opModLFRTMustTrip", Element: "opModLFRTMustTrip", Page: 252, ElementPage: 249},
	// 2018 p.252: "17 = opModLVRTMayTrip (Low Voltage Ride-Through, May Trip mode)"
	{Bit: 17, Mode: "opModLVRTMayTrip", Element: "opModLVRTMayTrip", Page: 252, ElementPage: 249},
	// 2018 p.252: "18 = opModLVRTMomentaryCessation (Low Voltage Ride-Through, Momentary Cessation mode)"
	{Bit: 18, Mode: "opModLVRTMomentaryCessation", Element: "opModLVRTMomentaryCessation",
		Page: 252, ElementPage: 250},
	// 2018 p.252: "19 = opModLVRTMustTrip (Low Voltage Ride-Through, Must Trip mode)"
	{Bit: 19, Mode: "opModLVRTMustTrip", Element: "opModLVRTMustTrip", Page: 252, ElementPage: 250},
	// 2018 p.252: "20 = opModMaxLimW (maximum active power)"
	{Bit: 20, Mode: "opModMaxLimW", Element: "opModMaxLimW", Page: 252, ElementPage: 250},
	// 2018 p.252: "21 = opModTargetVar (target reactive power)"
	{Bit: 21, Mode: "opModTargetVar", Element: "opModTargetVar", Page: 252, ElementPage: 250},
	// 2018 p.252: "22 = opModTargetW (target active power)"
	{Bit: 22, Mode: "opModTargetW", Element: "opModTargetW", Page: 252, ElementPage: 250},
	// 2018 p.252: "23 = opModVoltVar (Volt-Var mode)"
	{Bit: 23, Mode: "opModVoltVar", Element: "opModVoltVar", Page: 252, ElementPage: 250},
	// 2018 p.252: "24 = opModVoltWatt (Volt-Watt mode)"
	{Bit: 24, Mode: "opModVoltWatt", Element: "opModVoltWatt", Page: 252, ElementPage: 250},
	// 2018 p.252: "25 = opModWattPF (Watt-Powerfactor mode)"
	{Bit: 25, Mode: "opModWattPF", Element: "opModWattPF", Page: 252, ElementPage: 251},
	// 2018 p.252: "26 = opModWattVar (Watt-Var mode)"
	{Bit: 26, Mode: "opModWattVar", Element: "opModWattVar", Page: 252, ElementPage: 251},
}

// modesSupportedReservedFrom is the first bit position IEEE Std 2030.5-2018
// does NOT assign. p.252: "All other values reserved." A DER that sets one is
// advertising a mode the anchor revision has not defined, which no evidence can
// ever justify and which this oracle grades as an overclaim in its own right.
//
// IT IS 27 UNDER 2018 AND ONLY UNDER 2018. IEEE Std 2030.5-2023 p.275 DEFINES
// bits 27..31 — opModDeltaVar, opModDeltaW, opModFixedV, opModGridConnectPermit
// and opModIslandPermit — so a device built to the newer revision can set one of
// them honestly. The finding text says so (see reservedBitNote): a bundle reader
// must be able to tell "this DUT invented a bit" from "this DUT is newer than
// the revision this campaign certifies against", and those are different
// sentences about different problems.
const modesSupportedReservedFrom = 27

// reservedBitNote is the 2023 half of a reserved-bit finding, written once so
// every path that reports one says the same thing.
const reservedBitNote = "IEEE Std 2030.5-2023 p.275 DEFINES bits 27-31 (opModDeltaVar, opModDeltaW, " +
	"opModFixedV, opModGridConnectPermit, opModIslandPermit); this campaign is anchored to 2018, under " +
	"which they are reserved, so a DUT built to the newer revision must be read as ahead of this " +
	"anchor rather than as inventing a mode"

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
		parts = append(parts, fmt.Sprintf("bit %d RESERVED by IEEE 2030.5-2018 (p.252)", p))
	}
	return strings.Join(parts, ", ")
}

// hexBinary32 is the lexical space of the type modesSupported extends. IEEE Std
// 2030.5-2018 p.251 declares "DERControlType object (HexBinary32)" and p.174
// gives HexBinary32 as "A 32-bit field encoded as a hex string (8 hex
// characters maximum)": up to eight hexadecimal digits.
var hexBinary32 = regexp.MustCompile(`^[0-9a-fA-F]{1,8}$`)

// decimalText matches a wholly decimal rendering — what a serializer that
// models the element as a plain integer emits, which is what lexa-proto did
// until 72d91be and what the next DUT this suite grades may still do.
var decimalText = regexp.MustCompile(`^[0-9]{1,10}$`)

// modesMask is a decoded modesSupported, with the ambiguity kept rather than
// resolved away.
//
// # Why there are two numbers here
//
// The standard says HexBinary32 (2018 p.251), so the STANDARD's reading of the
// element text is hexadecimal, and that is the reading Value carries and the
// reading the oracle grades on. But a serializer that models the field as a bare
// unsigned integer emits DECIMAL, and for a text made only of the digits 0-9
// both readings are lexically valid and numerically different: "8192" is bit 13
// read as decimal and bits 1,4,7,8,15 read as hex. Neither end can detect it —
// both agree the string parsed. A reader of a bundle is entitled to know when
// the number they are being shown depended on which of the two the harness
// picked.
//
// THIS IS NOT HYPOTHETICAL, AND IT IS NOW FIXED UPSTREAM. lexa-proto's
// DERCapabilityFull declared `ModesSupported uint32` with no hexBinary
// marshaller, so every DERCapability this product PUT carried a decimal
// rendering of a field the schema types HexBinary32. This oracle's ambiguity
// disclosure is what surfaced it; lexa-proto 72d91be swept the whole class —
// modesSupported, MirrorUsagePoint/RateComponent roleFlags, Reading localID and
// qualityFlags — onto a HexBinary type that emits UPPERCASE, ZERO-PADDED to the
// type's full width ("00002000", not "2000") and decodes strictly as hex.
//
// The disclosure stays, for two reasons that outlive the fix: this oracle grades
// whatever DUT is in front of it, not only this one, and the next DUT may still
// be emitting decimal; and a bundle re-verified years from now may hold a
// document written before 72d91be, which a reader must be able to interpret
// without knowing the product's git history.
//
// LEADING ZEROS SETTLE IT, and that is why this is a narrow disclosure rather
// than a permanent caveat on every row. A HexBinary32 is conventionally written
// to its full width — 72d91be's encoding does exactly that — and no integer
// serializer emits "00002000" for two thousand; it writes "2000". So a text
// longer than one character that starts with '0' is unambiguously the schema's
// rendering, and Decimal stays nil. Decimal is filled in only for a text that
// BOTH readings could plausibly have produced: all decimal digits, no leading
// zero, and the two values differ.
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
		return modesMask{}, fmt.Errorf("the <modesSupported> element is present but empty; IEEE Std " +
			"2030.5-2018 p.246 declares it a mandatory [1] attribute of DERCapability with type " +
			"DERControlType, whose lexical space (p.251, HexBinary32) has no empty member")
	}
	if !hexBinary32.MatchString(t) {
		return modesMask{}, fmt.Errorf("the <modesSupported> text %q is not a HexBinary32 value; IEEE Std "+
			"2030.5-2018 p.251 declares DERControlType a HexBinary32 and p.174 gives that type's lexical "+
			"space as one to eight hexadecimal digits", t)
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
	// (252, 253, or 0xF0 legacy — see refusalAcceptedStatus, curve.go, for the
	// per-row conformance-verdict gate this DESCRIPTIVE sweep does not apply)
	// and never with 2 or 3.
	Refused []string
	// Unhonoured are the mRIDs of a control that named this mode, was served
	// ACTIVE (EventStatus.currentStatus = 1, its interval underway) and never
	// rejected at receipt (not in Refused), but by end of window answered with
	// neither an execution status (2/3) nor a refusal status (252/253/0xF0):
	// no lifecycle progression at all, or stuck at Received(1) and nothing
	// past it.
	//
	// The ACTIVE qualifier is load-bearing (CSIP-BENCH-CORE014-REHOME-WINDOW-
	// TIMING): a control the DUT MERELY FETCHED while NOT active — a
	// SCHEDULED-future, CANCELLED, SUPERSEDED or already-expired one it
	// correctly does nothing about yet — is NOT unhonoured, even if it POSTed a
	// Received acknowledging it. Its silence is a fact about the control's
	// lifecycle, not about the DUT's honour, and grading it as an overclaim
	// FAILs a conformant DUT for not executing a control that was never due.
	// Those land in Pending instead, which gradeMaskAgainstEvidence discloses
	// rather than grades. The SD-02 fault posture this bucket exists for is
	// about a control the DUT is SUPPOSED to be executing NOW going silent, and
	// only an active control is that.
	//
	// F6: this bucket restores the overclaim detection dropping status 8 from
	// refusalStatuses removed. Under the PRE-SD-02 reading, an admitted mode
	// the DUT never honoured answered 8 (PartialOptOut) at receipt — a
	// defective shape, but one gradeMaskAgainstEvidence could still see AS a
	// refusal and flag if the mode was also advertised. SD-02
	// (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw,
	// adjudication #3) now has the product's fault-class producers answer
	// such a control with NO invented lifecycle status at all — Received,
	// maybe Started if actually confirmed, then silence — so the SAME
	// admitted-then-unhonoured defect now leaves no refusal status to catch
	// it on. Unhonoured is what gradeMaskAgainstEvidence reads instead.
	Unhonoured []string
	// Pending are the mRIDs of a control that named this mode but was NOT
	// admitted in this window — fetched in a list while SCHEDULED, CANCELLED,
	// SUPERSEDED or expired, and never responded to. Silence on such a control
	// is coherent, so these are DISCLOSED (they explain why a bit is otherwise
	// silent) and never graded as an overclaim. See Unhonoured.
	Pending []string
}

// eventStatusActive is IEEE 2030.5 EventStatus.currentStatus = 1: the
// control's interval is currently underway. Every other value — Scheduled(0),
// Cancelled(2/3, and gridsim's 6), Superseded(4) — means the control is not
// executing now, so a DUT that FETCHED it and did nothing has not overclaimed
// the mode it names; it has correctly left a not-due control alone.
const eventStatusActive = 1

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

	// LegacyDeclared is this run's own declaration (modesSupportedLegacyParam)
	// that its DUT/case configuration runs the LEXA profile's legacy
	// CannotComply wire (0xF0) — the same meaning curve.go's
	// refusalBinding.LegacyCannotComply carries per-row, but CORE-014 grades
	// the WHOLE mask in one criterion, so this is a run-wide declaration
	// rather than a per-control one. Every run defaults this false: the
	// product's default and the certification profile are both standard-mode
	// (F11, docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw).
	LegacyDeclared bool
	// LegacyWireMRIDs are the mRIDs gatherModesEvidence saw answered with the
	// LEXA legacy extension (status=0xF0), collected REGARDLESS of
	// LegacyDeclared — gathering evidence and grading it against a
	// declaration are different steps, and this file's own long-standing
	// discipline (see gatherModesEvidence's refused sweep) is that the
	// DESCRIPTIVE half never conditions on a verdict-time flag. What
	// LegacyDeclared decides is what gradeMaskAgainstEvidence does with a
	// non-empty list: legacyDisclaimer'd non-conformance evidence when
	// declared, a finding in its own right when not (F11).
	LegacyWireMRIDs []string
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

	// mRID -> modes, over every DERControlList the DUT fetched, and mRID ->
	// whether that control was served ACTIVE (its interval underway). A control
	// served in any other lifecycle state — Scheduled, Cancelled, Superseded,
	// expired — is not DUE, so a DUT that fetched it and drew no Response has
	// not overclaimed the mode; it correctly left a not-due control alone
	// (CSIP-BENCH-CORE014-REHOME-WINDOW-TIMING).
	modesOf := map[string][]string{}
	activeOf := map[string]bool{}
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
			if es := ctrl.Child("EventStatus"); es != nil {
				if st, ok := es.IntOf("currentStatus"); ok && st == eventStatusActive {
					// A DUT may fetch the same mRID more than once (a re-walk, a
					// list plus the active-list); ANY sighting as Active makes it
					// due, so this only ever latches true.
					activeOf[mrid] = true
				}
			}
			base := ctrl.Child("DERControlBase")
			if base == nil {
				continue
			}
			for _, kid := range base.Kids {
				name := kid.Local()
				// EVERY opMod* element, not only the ones this file's table can
				// place. DERControlBase's own non-mode member is rampTms, so the
				// prefix is the whole filter and it is a syntactic property of
				// the schema's naming rather than a judgement about which modes
				// exist.
				//
				// Collecting the ones with NO bit is the point. A DUT can
				// execute a mode DERControlType gives no position for — IEEE
				// Std 2030.5-2018 p.251-252 assigns bits 0..26 and reserves the
				// rest — and this product ships two such modes, opModExpLimW and
				// opModGenLimW, the CSIP-Aus dynamic-operating-envelope elements
				// the standard does not declare. (This cited sep 2.0.4 until
				// IW15-027: anchoring an unadvertisability claim to the draft was
				// the very defect this file's own header renounces, restated four
				// hundred lines below it.) Those modes are UNADVERTISABLE in this
				// bitmap rather
				// than missing from it. Dropping them here would have let the
				// finding imply the mask accounted for everything the DUT ran.
				// gradeMaskAgainstEvidence discloses them instead.
				if !strings.HasPrefix(name, "opMod") {
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
		// This is a DESCRIPTIVE sweep across the whole transcript, not a
		// per-row certification verdict, so it recognises the standard
		// receipt rejections (252, 253) AND the LEXA legacy wire (0xF0) as
		// evidence of a refusal regardless of any one row's own legacy
		// declaration (contrast curve.go's critRefusalAnswered/
		// refusalAcceptedStatus, which gate 0xF0 on a row's
		// LegacyCannotComply flag for a conformance VERDICT — and gate on 252
		// alone, not 253, because that criterion only ever grades the
		// specific "structurally unsupported axis" refusal shape). Status
		// 254 (rejected — already expired) is deliberately NOT counted as a
		// refusal here: it says the event arrived too late to matter, not
		// that the DUT declines the mode, so treating it as refusal evidence
		// would be its own misattribution. Status 8/10 are deliberately NOT
		// checked here any more (SD-02): they are Table 27's
		// EffectiveEndTime-only partials for an ADMITTED event, not a
		// refusal, and counting them here would misclassify an executing
		// control's late partial as a refused one.
		refused := sts[252] || sts[253] || sts[0xF0]
		if sts[0xF0] {
			// F11: gathered regardless of this run's own legacy declaration —
			// see LegacyWireMRIDs' doc. gradeMaskAgainstEvidence is where the
			// declaration is consulted.
			e.LegacyWireMRIDs = appendUnique(e.LegacyWireMRIDs, mrid)
		}
		// DUE = the control was served ACTIVE, its interval underway. Only a
		// due control that then falls silent is an overclaim: under SD-02 the
		// silence of a control the DUT is SUPPOSED to be executing is itself
		// the fault signal (Received, maybe Started, then nothing). A control
		// the DUT merely fetched while it was NOT active — Scheduled-future,
		// Cancelled, Superseded or expired — is not due; the DUT correctly
		// neither executes nor refuses it, and even a Received it may have
		// POSTed is an acknowledgement of a not-yet-due control, not a promise
		// to run it now. Those are coherent silence and go to Pending, which
		// gradeMaskAgainstEvidence discloses rather than grades. This is the
		// whole of CSIP-BENCH-CORE014-REHOME-WINDOW-TIMING: gridsim's DERC-SP-004
		// is a scheduled event carrying opModConnect that no row drives, and the
		// clean product was reconciled to FAIL for correctly leaving it alone.
		due := activeOf[mrid]
		for _, m := range modes {
			switch {
			case executed:
				e.mode(m).Executed = appendUnique(e.mode(m).Executed, mrid)
			case refused:
				e.mode(m).Refused = appendUnique(e.mode(m).Refused, mrid)
			case due:
				// F6: DUE (served Active) but by end of window neither executed
				// nor refused — no invented lifecycle status, which under
				// SD-02's fault posture is itself the wire signal (case 6/11)
				// rather than an absence of evidence.
				e.mode(m).Unhonoured = appendUnique(e.mode(m).Unhonoured, mrid)
			default:
				// Fetched but never active in this window: a not-yet/no-longer
				// due control the DUT correctly left alone. Disclosed, not
				// graded.
				e.mode(m).Pending = appendUnique(e.mode(m).Pending, mrid)
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
		e.MaskErr = fmt.Errorf("%s carries NO <modesSupported> element at all, and IEEE Std 2030.5-2018 "+
			"p.246 declares it [1] on DERCapability — it is not an optional field", where)
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
		sort.Strings(r.Unhonoured)
		sort.Strings(r.Pending)
	}
	sort.Strings(e.LegacyWireMRIDs)
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
			"%s could not be decoded as IEEE Std 2030.5-2018's HexBinary32 (p.251): %v. An advertisement a "+
				"conformance reader "+
				"cannot decode is not a weaker advertisement, it is an undecidable one, and this oracle "+
				"grades it as a failure of the payload rather than reporting the DUT as unmeasured",
			e.MaskWhere, e.MaskErr)}
	}

	verdict, body := gradeMaskAgainstEvidence(e, e.Mask.Value, "")
	if e.Mask.Ambiguous() {
		altVerdict, altBody := gradeMaskAgainstEvidence(e, *e.Mask.Decimal, "")
		note := fmt.Sprintf(". AMBIGUOUS SERIALIZATION: the wire text %q is lexically valid under BOTH "+
			"IEEE 2030.5-2018's HexBinary32 (p.251), which this oracle graded and which reads it as 0x%08X "+
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
	var advertised, evidenced, silent, unadvertisable []string

	// ── Direction (b): executed but not advertised ───────────────────────
	for _, name := range e.modeNames() {
		r := e.ByMode[name]
		if len(r.Executed) == 0 {
			continue
		}
		b, ok := bitForElement(name)
		if !ok {
			// A mode the DUT demonstrably RAN and 2030.5 gives no bit for. This
			// is not an underclaim and grading it as one would demand a bit that
			// does not exist — but it is not nothing either: the mask is then a
			// strictly incomplete description of what this device does, and a
			// reader comparing "modes supported" against a campaign transcript is
			// entitled to know which executed modes the field COULD NOT have
			// carried. The PICS is where they have to be declared; this says so
			// rather than leaving a silent gap.
			unadvertisable = append(unadvertisable, fmt.Sprintf(
				"<%s> (executed under mRID %s; IEEE 2030.5-2018's DERControlType (p.251-252) assigns it "+
					"no bit, so no value of modesSupported can advertise it and the device's PICS is the "+
					"only place it can be declared)", name, strings.Join(r.Executed, "/")))
			continue
		}
		evidenced = append(evidenced, fmt.Sprintf("%s (bit %d, mRID %s)", name, b.Bit,
			strings.Join(r.Executed, "/")))
		if mask&(1<<b.Bit) == 0 {
			underclaims = append(underclaims, fmt.Sprintf(
				"%s: the DUT answered Response status 2 (Event started) or 3 (Event completed) for "+
					"control(s) %s whose DERControlBase named <%s>, and bit %d — which IEEE 2030.5-2018 "+
					"p.%d assigns to %s — is CLEAR in the mask it advertises",
				name, strings.Join(r.Executed, ", "), name, b.Bit, b.Page, b.Mode))
		}
	}

	// ── Direction (a): advertised but refused, or reserved ───────────────
	for _, pos := range setBits(mask) {
		b, ok := bitAt(pos)
		if !ok {
			reserved = append(reserved, fmt.Sprintf(
				"bit %d is set and IEEE Std 2030.5-2018 assigns no mode to it — p.252 says \"All other "+
					"values reserved\" of every position above %d, so nothing the DUT could do would make "+
					"this bit honest under the revision this campaign certifies against. (%s.)",
				pos, modesSupportedReservedFrom-1, reservedBitNote))
			continue
		}
		advertised = append(advertised, fmt.Sprintf("bit %d %s", b.Bit, b.Mode))
		r := e.ByMode[b.Element]
		switch {
		case b.Element == "":
			silent = append(silent, fmt.Sprintf("bit %d %s (the standard gives this mode no DERControlBase "+
				"element, so no transcript can evidence it either way)", b.Bit, b.Mode))
		case r == nil || (len(r.Executed) == 0 && len(r.Refused) == 0 && len(r.Unhonoured) == 0):
			if picsDeclares(e.PICS, b) {
				continue
			}
			if r != nil && len(r.Pending) > 0 {
				// The mode WAS carried, but only by control(s) that were not due
				// in this window — Scheduled, Cancelled, Superseded or expired,
				// and never responded to. Silence there is coherent, so the bit
				// is disclosed as unspoken-to rather than graded (the whole
				// point of CSIP-BENCH-CORE014-REHOME-WINDOW-TIMING).
				silent = append(silent, fmt.Sprintf("bit %d %s (the only control(s) naming <%s> in this "+
					"window were not active — %s — so the DUT correctly drew no execution or refusal for "+
					"them; a not-due control cannot evidence the mask either way)",
					b.Bit, b.Mode, b.Element, strings.Join(r.Pending, ", ")))
				continue
			}
			silent = append(silent, fmt.Sprintf("bit %d %s (no control naming <%s> drew an execution, a "+
				"refusal, or an unhonoured-adoption in this evidence)", b.Bit, b.Mode, b.Element))
		case len(r.Executed) > 0:
			// Advertised and demonstrably honoured. Nothing to say.
		case len(r.Refused) > 0:
			overclaims = append(overclaims, fmt.Sprintf(
				"%s: bit %d is SET — IEEE 2030.5-2018 p.%d assigns it to %s — and the DUT REFUSED every "+
					"control that named <%s> (mRID %s), answering a cannot-comply status and never 2 "+
					"(Event started) or 3 (Event completed). The mask promises a utility server a mode "+
					"the DUT declines to perform",
				b.Element, b.Bit, b.Page, b.Mode, b.Element, strings.Join(r.Refused, ", ")))
		default:
			// F6: r.Unhonoured > 0, Executed and Refused both empty — a control
			// naming this mode was ADOPTED (not rejected at receipt) but by end
			// of window told the head end neither that it ran nor that it could
			// not. Under SD-02's fault posture (docs/design/
			// SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw, adjudication
			// #3) that silence is the wire signal itself, not an absence of
			// evidence — and a mask bit whose ONLY standing evidence is that
			// silence is exactly the admitted-then-unhonoured overclaim this
			// bucket exists to restore detection for (parity with the
			// pre-SD-02 8-as-refusal reading this file relied on before status
			// 8 was retired from refusal evidence).
			overclaims = append(overclaims, fmt.Sprintf(
				"%s: bit %d is SET — IEEE 2030.5-2018 p.%d assigns it to %s — and every control that named "+
					"<%s> (mRID %s) was ADOPTED but by end of window carries neither an execution status "+
					"(2/3) nor a refusal status (252/253/0xF0): under SD-02 that silence is itself the wire "+
					"signal for a fault/structural non-honour, and the mask has promised a utility server a "+
					"mode the evidence shows the DUT adopted and never made good on",
				b.Element, b.Bit, b.Page, b.Mode, b.Element, strings.Join(r.Unhonoured, ", ")))
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
				"%s: bit %d is SET — IEEE 2030.5-2018 p.%d — and it is neither declared by the "+
					"operator-supplied PICS (%s) nor evidenced by anything the DUT did in this evidence. "+
					"A bit outside the declaration is an advertisement nobody stands behind",
				b.Mode, b.Bit, b.Page, e.PICSRaw))
		}
	}

	// ── The sentence ─────────────────────────────────────────────────────
	head := fmt.Sprintf("%s advertises modesSupported=%q, which IEEE Std 2030.5-2018 (p.251, "+
		"DERControlType is a HexBinary32) reads as 0x%08X = %s. Scope of the executed-mode half: %s",
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
	if len(unadvertisable) > 0 {
		head += ". Executed modes this bitmap CANNOT express, so their absence from it is not an " +
			"underclaim and their presence in it is impossible: " + strings.Join(unadvertisable, "; ")
	}

	// F11 (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw):
	// 0xF0 evidence gathered with NO legacy declaration on this run is a
	// finding in its own right — Table 27 reserves 0xF0 (15-251, 255; there
	// is no manufacturer range), so a DUT that spoke it in what this run
	// believes is standard mode has spoken a retired extension outside its
	// config-gated fallback. This is independent of the overclaim/underclaim
	// sweep above: a mode can be perfectly coherent (correctly refused via
	// 252, say, on every OTHER control) while a DIFFERENT control for it
	// still answered 0xF0 undeclared.
	var legacyProblems []string
	if len(e.LegacyWireMRIDs) > 0 && !e.LegacyDeclared {
		legacyProblems = append(legacyProblems, fmt.Sprintf(
			"control(s) %s answered with the LEXA legacy extension (status=0xF0) and this run's own "+
				"case/DUT configuration does not declare legacy CannotComply mode: IEEE 2030.5-2018 Table 27 "+
				"reserves 0xF0 (15-251, 255 — the standard defines no manufacturer range at all), so a DUT "+
				"speaking it in what this run believes is standard mode has spoken a retired extension "+
				"outside its config-gated fallback",
			strings.Join(e.LegacyWireMRIDs, ", ")))
	}

	var problems []string
	problems = append(problems, underclaims...)
	problems = append(problems, overclaims...)
	problems = append(problems, reserved...)
	problems = append(problems, legacyProblems...)
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
	if len(e.LegacyWireMRIDs) > 0 && e.LegacyDeclared {
		// F11: a PASS whose refusal evidence includes 0xF0 is not conformance
		// evidence — see curve.go's legacyDisclaimer, reused verbatim here so
		// a bundle reader sees the identical stamp regardless of which
		// criterion the 0xF0 evidence surfaced through.
		tail += legacyDisclaimer
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
// declaration to this oracle: a comma-separated list of IEEE Std 2030.5-2018 mode names (p.251-252)
// (opModMaxLimW), DERControlBase element names, or bit numbers.
//
// Without it, a set bit that the evidence neither proves nor refutes is
// DISCLOSED and not graded — the honest answer for a window that did not
// exercise the mode. With it, such a bit becomes gradable: a bit outside the
// declaration is an advertisement nobody stands behind, and a mode the DUT
// executes but the declaration omits is a disagreement between the device and
// its own paperwork.
const modesSupportedPICSParam = "csip.pics_modes_supported"

// modesSupportedLegacyParam is how an operator declares that THIS RUN's
// DUT/case configuration runs the LEXA profile's legacy CannotComply wire
// (0xF0) rather than the standard Table 27 answer — the run-wide counterpart
// of curve.go's per-row refusalBinding.LegacyCannotComply, needed because
// CORE-014 grades modesSupported as one whole-mask criterion rather than
// per-control (F11, docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md,
// lexa-gw). "true" declares legacy mode; anything else (including absent,
// the default) does not — matching every row in the current RC0 catalog,
// which is standard-mode by default.
const modesSupportedLegacyParam = "csip.legacy_cannot_comply"

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
//	    IEEE 2030.5-2018 does not assign at all fails on the standard alone (with
//	    the 2023 sentence quoted beside it, so "ahead of this anchor" is
//	    distinguishable from "invented"). With a PICS supplied, a bit outside the
//	    declaration fails too.
//
//	(b) UNDERCLAIM — every mode this evidence PROVES executed (a control naming
//	    that DERControlBase element which the DUT answered status 2 or 3) must
//	    have its bit SET. A device that runs a mode it does not advertise has told
//	    the head end something false in the safer direction, and a head end that
//	    reads modesSupported to decide what to send will never send it.
//
// The bit positions come from derControlTypeBits — this file's own hand
// transcription of IEEE Std 2030.5-2018 p.251-252 — and from nothing else.
// Not from lexa-proto/csipmodel, whose agreement with the DUT would make every
// verdict below vacuous, and not from the vendored draft schema, which is what
// made the FIRST version of this oracle agree with a wrong table (IW15-027).
//
// There is no SKIP path through the decision: once a DERCapability is in hand,
// this criterion returns a verdict. The single Unavailable it can return is "no
// DERCapability was observed at all", which hands the question to the next tier
// rather than to nobody.
//
// legacy is this run's own declaration that its DUT/case configuration runs
// the LEXA legacy CannotComply wire (0xF0) — modesSupportedLegacyParam,
// threaded from coreDERSettings the same way picsRaw is. F11
// (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw): without
// it, 0xF0 evidence still counts toward the refusal/overclaim sweep (that
// half is unconditional — see gatherModesEvidence's refused sweep), but a
// PASS earned partly on undeclared 0xF0 evidence would say nothing about it,
// and this run's own OWN speaking of a retired extension outside its
// config-gated fallback would go unflagged entirely.
func critModesSupportedCoherent(o *Observation, picsRaw string, legacy bool) criterion {
	pics := parsePICSModes(picsRaw)
	return criterion{
		Claim: "every bit set in the DERCapability.modesSupported the DUT serves is a mode it stands " +
			"behind, and every mode it demonstrably executed has its bit set",
		How: "the modesSupported bitmap decoded against bit positions HAND-TRANSCRIBED from IEEE Std " +
			"2030.5-2018, printed pages 251-252 (\"DERControlType object (HexBinary32) — Control modes " +
			"supported by the DER. Bit positions SHALL be defined as follows:\", bits 0-26), read as a " +
			"HexBinary32, carrying NO dependency on lexa-proto/csipmodel's Mode* constants — the " +
			"product's own table, whose agreement with the DUT would make this check vacuous (IW15-011) " +
			"— and none on the vendored sep-2.0.4.xsd, which is the pre-publication ZigBee draft whose " +
			"bit order differs and whose use as an anchor is the defect IW15-027 corrects; cross-checked " +
			"against the DERControlBase element each control carried (2018 p.248-251) and the Response " +
			"status the DUT POSTed for it",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			e := gatherModesEvidence(t)
			e.Scope, e.PICS, e.PICSRaw, e.LegacyDeclared = modesScopeRowWindow, pics, picsRaw, legacy
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
			e := modesEvidence{ByMode: map[string]*modeControlEvidence{}, PICS: pics, PICSRaw: picsRaw,
				LegacyDeclared: legacy}
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
