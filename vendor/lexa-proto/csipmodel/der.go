// This file extends the csipmodel package (see resources.go for the package
// doc comment and the XML-namespace invariant) with the full IEEE 2030.5 DER
// function set: DERControlBase (all operating modes, including curve-linked
// ride-through and inverter control modes), DERCurve, DERAvailability, and
// expanded DERCapability / DERStatus as specified in IEEE 2030.5-2018 §10.10.
package csipmodel

import "encoding/xml"

// ─── Operating-mode bitmask constants (DERCapability.ModesSupported) ──────────
//
// DERControlType is a HexBinary32 bitmap. A DER sets bit N to advertise that it
// IMPLEMENTS the mode the STANDARD assigns to N — "Bitmap indicating the DER
// Controls implemented by the device" (IEEE Std 2030.5-2018 p.246,
// DERCapability's modesSupported; the companion modesEnabled on DERSettings is
// the ENABLED subset).
//
// ANCHOR: IEEE Std 2030.5-2018, printed p.251-252, "DERControlType object
// (HexBinary32) — Control modes supported by the DER. Bit positions SHALL be
// defined as follows:", bits 0..26, then "All other values reserved."
// Corroborated by IEEE Std 2030.5-2023 p.274-275, which is identical for bits
// 0..26 and adds 27..31. See docs/schema/NORMATIVE_ANCHOR.md §3.1.
//
// RE-DERIVED 2026-08-15 (registry IW15-027), and this is the SECOND correction
// of this table in one day. The first one — 9856710, part of the Stage-9
// conformance pass — transcribed it faithfully from docs/schema/sep-2.0.4.xsd
// and was therefore faithful to the WRONG DOCUMENT: that file is the
// pre-publication ZigBee SEP 2.0 draft, not IEEE 2030.5-2018, and it assigns 22
// bits in a completely different order. The table it replaced happened to match
// 2018 on twelve of twenty-two positions; the "fix" took that to zero. Three
// witnesses agreed on it because all three read the same file. A witness is
// independent only if its SOURCE is.
//
// The four opMod*MayTrip modes (bits 10, 12, 15, 17) are REAL and advertisable;
// the draft schema has no bit for them, which is why the previous pass declared
// them unadvertisable. opModFixedPFAbsorbW and opModFixedPFInjectW have their
// OWN bits (4 and 5); the draft's single "opModFixedPF" is a draft artifact and
// the fold that used to live in ModeBit is gone. opModMaxLimW is bit 20 — which
// is what the CSIP-CONF catalog's CORE-014 said all along.
//
// TestModeBitsMatch2018 parses the VERBATIM QUOTE from 2018 embedded in the
// test file (with its page cite) and proves this table reproduces it in both
// directions, rather than restating it. TestCensus_ModeBitsDivergeFromXSD
// asserts the divergence from the vendored draft is exactly what the census
// documents, so a re-vendored schema or a drifted census row fails loudly.
//
// TWO MODES THE STANDARD NAMES WITHOUT AN ELEMENT still get a constant (Charge,
// Discharge): the table's job is to reproduce the standard's assignment, and a
// hole in it is how a neighbouring bit gets mis-numbered. Whether the product
// SETS a bit is a separate question, answered per device by the publisher
// (lexa-gw internal/derproducer).
//
// FOUR ELEMENTS THIS PACKAGE DECODES HAVE NO BIT in any revision, and cannot be
// advertised in this bitmap at all: opModExpLimW / opModGenLimW / opModImpLimW
// / opModLoadLimW are the CSIP-Aus dynamic-operating-envelope quartet, absent
// from 2030.5-2018, 2030.5-2023 and sep 2.0.4 alike (see
// ExtendedDERControlBase). A gateway that executes them must say so somewhere
// other than modesSupported.
const (
	ModeCharge                 HexBinary32 = 1 << 0  // 2018 p.251 — "0 = Charge mode"
	ModeDischarge              HexBinary32 = 1 << 1  // 2018 p.251 — "1 = Discharge mode"
	ModeConnect                HexBinary32 = 1 << 2  // 2018 p.251 — opModConnect (connect/disconnect—implies galvanic isolation)
	ModeEnergize               HexBinary32 = 1 << 3  // 2018 p.251 — opModEnergize (energize/de-energize)
	ModeFixedPFAbsorbW         HexBinary32 = 1 << 4  // 2018 p.251 — opModFixedPFAbsorbW (fixed PF setpoint when absorbing active power)
	ModeFixedPFInjectW         HexBinary32 = 1 << 5  // 2018 p.251 — opModFixedPFInjectW (fixed PF setpoint when injecting active power)
	ModeFixedVar               HexBinary32 = 1 << 6  // 2018 p.251 — opModFixedVar (reactive power setpoint)
	ModeFixedW                 HexBinary32 = 1 << 7  // 2018 p.252 — opModFixedW (charge/discharge setpoint)
	ModeFreqDroop              HexBinary32 = 1 << 8  // 2018 p.252 — opModFreqDroop (Frequency-Watt Parameterized mode)
	ModeFreqWatt               HexBinary32 = 1 << 9  // 2018 p.252 — opModFreqWatt (Frequency-Watt Curve mode)
	ModeHFRTMayTrip            HexBinary32 = 1 << 10 // 2018 p.252 — opModHFRTMayTrip
	ModeHFRTMustTrip           HexBinary32 = 1 << 11 // 2018 p.252 — opModHFRTMustTrip
	ModeHVRTMayTrip            HexBinary32 = 1 << 12 // 2018 p.252 — opModHVRTMayTrip
	ModeHVRTMomentaryCessation HexBinary32 = 1 << 13 // 2018 p.252 — opModHVRTMomentaryCessation
	ModeHVRTMustTrip           HexBinary32 = 1 << 14 // 2018 p.252 — opModHVRTMustTrip
	ModeLFRTMayTrip            HexBinary32 = 1 << 15 // 2018 p.252 — opModLFRTMayTrip
	ModeLFRTMustTrip           HexBinary32 = 1 << 16 // 2018 p.252 — opModLFRTMustTrip
	ModeLVRTMayTrip            HexBinary32 = 1 << 17 // 2018 p.252 — opModLVRTMayTrip
	ModeLVRTMomentaryCessation HexBinary32 = 1 << 18 // 2018 p.252 — opModLVRTMomentaryCessation
	ModeLVRTMustTrip           HexBinary32 = 1 << 19 // 2018 p.252 — opModLVRTMustTrip
	ModeMaxLimW                HexBinary32 = 1 << 20 // 2018 p.252 — opModMaxLimW (maximum active power)
	ModeTargetVar              HexBinary32 = 1 << 21 // 2018 p.252 — opModTargetVar (target reactive power)
	ModeTargetW                HexBinary32 = 1 << 22 // 2018 p.252 — opModTargetW (target active power)
	ModeVoltVar                HexBinary32 = 1 << 23 // 2018 p.252 — opModVoltVar (Volt-Var mode)
	ModeVoltWatt               HexBinary32 = 1 << 24 // 2018 p.252 — opModVoltWatt (Volt-Watt mode)
	ModeWattPF                 HexBinary32 = 1 << 25 // 2018 p.252 — opModWattPF (Watt-Powerfactor mode)
	ModeWattVar                HexBinary32 = 1 << 26 // 2018 p.252 — opModWattVar (Watt-Var mode)
)

// modeBits is the element-name → bit index projection of the table above, and
// the ONLY supported way to turn a mode NAME into a modesSupported bit.
//
// It exists because the consumer that needs the mapping (lexa-gw's
// derproducer, which composes a per-device mask out of the receipt screen's
// axis names) would otherwise keep its own copy of the assignment — and a
// second copy of a bit table is precisely how the divergence this stage
// corrected survived unnoticed for as long as it did. One table, parsed against
// the schema by one test.
//
// Keys are the standard's own element names, verbatim, including the two bits
// 2030.5-2018 names WITHOUT an element ("Charge mode" / "Discharge mode" →
// "Charge" / "Discharge"). Bits with no mode name, and names with no bit, do
// not appear.
var modeBits = map[string]HexBinary32{
	"Charge":                      ModeCharge,
	"Discharge":                   ModeDischarge,
	"opModConnect":                ModeConnect,
	"opModEnergize":               ModeEnergize,
	"opModFixedPFAbsorbW":         ModeFixedPFAbsorbW,
	"opModFixedPFInjectW":         ModeFixedPFInjectW,
	"opModFixedVar":               ModeFixedVar,
	"opModFixedW":                 ModeFixedW,
	"opModFreqDroop":              ModeFreqDroop,
	"opModFreqWatt":               ModeFreqWatt,
	"opModHFRTMayTrip":            ModeHFRTMayTrip,
	"opModHFRTMustTrip":           ModeHFRTMustTrip,
	"opModHVRTMayTrip":            ModeHVRTMayTrip,
	"opModHVRTMomentaryCessation": ModeHVRTMomentaryCessation,
	"opModHVRTMustTrip":           ModeHVRTMustTrip,
	"opModLFRTMayTrip":            ModeLFRTMayTrip,
	"opModLFRTMustTrip":           ModeLFRTMustTrip,
	"opModLVRTMayTrip":            ModeLVRTMayTrip,
	"opModLVRTMomentaryCessation": ModeLVRTMomentaryCessation,
	"opModLVRTMustTrip":           ModeLVRTMustTrip,
	"opModMaxLimW":                ModeMaxLimW,
	"opModTargetVar":              ModeTargetVar,
	"opModTargetW":                ModeTargetW,
	"opModVoltVar":                ModeVoltVar,
	"opModVoltWatt":               ModeVoltWatt,
	"opModWattPF":                 ModeWattPF,
	"opModWattVar":                ModeWattVar,
}

// ModeBit returns the DERControlType bit for a mode named by its IEEE
// 2030.5-2018 element name, and reports whether the standard assigns that name
// a bit at all.
//
// FALSE IS A REAL ANSWER, not an error to paper over: opModExpLimW and its
// three CSIP-Aus siblings are modes this tree decodes and (on some benches)
// executes, and no revision of 2030.5 gives them a bit — a caller composing a
// modesSupported mask must DROP them rather than pick a spare position.
//
// THE FOUR MayTrip NAMES NOW ANSWER TRUE (bits 10, 12, 15, 17). They answered
// false between 9856710 and this commit, because the draft schema that pass was
// anchored to declares no such modes; 2030.5-2018 p.252 does. Callers that
// relied on the false — lexa-gw's derproducer drop list and its test, and
// discovery's curvemode_element_test — invert with this change and are on the
// follow-up wave's worklist (registry IW15-027).
//
// THERE IS NO ABSORB/INJECT FOLD ANY MORE. 2030.5-2018 gives
// opModFixedPFAbsorbW and opModFixedPFInjectW their own bits (4 and 5); the
// single "opModFixedPF" bit the fold targeted exists only in the draft schema.
// A DER that can hold a fixed power factor in one direction only now says so.
func ModeBit(name string) (HexBinary32, bool) {
	b, ok := modeBits[name]
	return b, ok
}

// ModeBitName is ModeBit's inverse over bit POSITIONS 0..31: it returns the
// standard's name for a position, or "" for one 2030.5-2018 reserves. It exists
// so a log line, a PICS table or a defect record can print a mask as the modes
// it claims instead of as a hex integer, and so the mapping is assertable in
// both directions (TestModeBitsMatch2018).
//
// Bits 27..31 are reserved in 2018 and defined in 2030.5-2023 (opModDeltaVar,
// opModDeltaW, opModFixedV, opModGridConnectPermit, opModIslandPermit). This
// package is anchored to 2018, so they answer "" — a 2023-only mask read here
// under-reports rather than mis-reports.
func ModeBitName(pos int) string {
	if pos < 0 || pos > 31 {
		return ""
	}
	bit := HexBinary32(1) << uint(pos)
	for name, b := range modeBits {
		if b == bit {
			return name
		}
	}
	return ""
}

// ─── DERCurve curve-type codes ────────────────────────────────────────────────
//
// ANCHOR: IEEE Std 2030.5-2018, printed p.254, "DERCurveType object (UInt8)",
// FIFTEEN values 0..14, then "All other values reserved." Corroborated by IEEE
// Std 2030.5-2023 p.266-267 (identical). Each code is also stated a second time
// in 2018 per-attribute on DERControlBase — "Specify DERCurveLink for curveType
// == 11" under opModVoltVar (p.250) and so on — which is an in-document
// cross-check and the reason the CSIP-CONF catalog's curveType-11 prescription
// was right. See docs/schema/NORMATIVE_ANCHOR.md §3.2.
//
// RE-DERIVED 2026-08-15 (registry IW15-027), overturning R4b's re-adjudication.
// R4b (2026-08-14) rebuilt this table from docs/schema/sep-2.0.4.xsd, which is
// the pre-publication ZigBee draft and declares only ELEVEN values in a
// different order. Its central finding — 'the string "MayTrip" appears ZERO
// times in the whole schema, so the four CurveType*MayTrip constants have no
// referent to renumber to' — is a true statement about that file and a FALSE
// statement about IEEE 2030.5-2018, which defines all four (codes 1, 3, 6, 8).
// They are restored.
//
// Under the correct anchor the pre-R4b table was ALSO wrong, so R4b was fixing
// something real; it just fixed it towards the wrong document. The specific
// number that moved twice: opModWattVar is curveType 14 in 2018, was 10 under
// R4b, and was 10-decodes-as-HFRTMayTrip before that.
//
// BLAST RADIUS, re-checked against the same consumers R4b swept. Nothing in
// this tree, in lexa-gw or in csip-tls-test BRANCHES on a curve-type number:
// curve mode is derived from the opMod* element a curve is linked from
// (discovery.CurveModeLinks is the single owner of that mapping), never from
// curveType, and every production use of the field is a verbatim pass-through.
// bus.CurveSetContentHash hashes the value that arrived ON THE WIRE, never
// these constants, so no digest moves and no CurveSetV bump is implied. What
// DOES move: csip-tls-test's gridsim curveTypeForMode and
// suitecsip/register.go:950 both carry literal numbers derived from the draft
// (WattVar 10, VoltVar 0, FreqWatt 1, WattPF 2, VoltWatt 3) and every one of
// them is wrong under 2018 (14, 11, 0, 13, 12). That is the follow-up wave's
// worklist, reported with this change and NOT edited here.
const (
	CurveTypeFreqWatt               uint16 = 0  // 2018 p.254 — opModFreqWatt (Frequency-Watt Curve mode)
	CurveTypeHFRTMayTrip            uint16 = 1  // 2018 p.254 — opModHFRTMayTrip
	CurveTypeHFRTMustTrip           uint16 = 2  // 2018 p.254 — opModHFRTMustTrip
	CurveTypeHVRTMayTrip            uint16 = 3  // 2018 p.254 — opModHVRTMayTrip
	CurveTypeHVRTMomentaryCessation uint16 = 4  // 2018 p.254 — opModHVRTMomentaryCessation
	CurveTypeHVRTMustTrip           uint16 = 5  // 2018 p.254 — opModHVRTMustTrip
	CurveTypeLFRTMayTrip            uint16 = 6  // 2018 p.254 — opModLFRTMayTrip
	CurveTypeLFRTMustTrip           uint16 = 7  // 2018 p.254 — opModLFRTMustTrip
	CurveTypeLVRTMayTrip            uint16 = 8  // 2018 p.254 — opModLVRTMayTrip
	CurveTypeLVRTMomentaryCessation uint16 = 9  // 2018 p.254 — opModLVRTMomentaryCessation
	CurveTypeLVRTMustTrip           uint16 = 10 // 2018 p.254 — opModLVRTMustTrip
	CurveTypeVoltVar                uint16 = 11 // 2018 p.254, cross-cited p.250 — opModVoltVar
	CurveTypeVoltWatt               uint16 = 12 // 2018 p.254, cross-cited p.250 — opModVoltWatt
	CurveTypeWattPF                 uint16 = 13 // 2018 p.254, cross-cited p.251 — opModWattPF
	CurveTypeWattVar                uint16 = 14 // 2018 p.254, cross-cited p.251 — opModWattVar
)

// CurveTypeName maps a DERCurveType code to the opMod* element it names, and
// returns "" for a code IEEE 2030.5-2018 reserves. It exists so a log line or a
// defect record can say what a server actually sent instead of printing a bare
// integer, and so the mapping is assertable in both directions.
func CurveTypeName(code uint16) string {
	switch code {
	case CurveTypeFreqWatt:
		return "opModFreqWatt"
	case CurveTypeHFRTMayTrip:
		return "opModHFRTMayTrip"
	case CurveTypeHFRTMustTrip:
		return "opModHFRTMustTrip"
	case CurveTypeHVRTMayTrip:
		return "opModHVRTMayTrip"
	case CurveTypeHVRTMomentaryCessation:
		return "opModHVRTMomentaryCessation"
	case CurveTypeHVRTMustTrip:
		return "opModHVRTMustTrip"
	case CurveTypeLFRTMayTrip:
		return "opModLFRTMayTrip"
	case CurveTypeLFRTMustTrip:
		return "opModLFRTMustTrip"
	case CurveTypeLVRTMayTrip:
		return "opModLVRTMayTrip"
	case CurveTypeLVRTMomentaryCessation:
		return "opModLVRTMomentaryCessation"
	case CurveTypeLVRTMustTrip:
		return "opModLVRTMustTrip"
	case CurveTypeVoltVar:
		return "opModVoltVar"
	case CurveTypeVoltWatt:
		return "opModVoltWatt"
	case CurveTypeWattPF:
		return "opModWattPF"
	case CurveTypeWattVar:
		return "opModWattVar"
	}
	return "" // "All other values reserved." — IEEE Std 2030.5-2018 p.254
}

// ─── DER status code constants ────────────────────────────────────────────────

// Generator connection status codes (genConnectStatus).
const (
	GenConnectAvailable uint8 = 0 // available but not connected
	GenConnectConnected uint8 = 1 // connected and operating
	GenConnectTest      uint8 = 2 // in test mode
	GenConnectFault     uint8 = 3 // fault condition
)

// Operational mode status codes (operationalModeStatus).
const (
	OpStatusIdle      uint8 = 0
	OpStatusOperating uint8 = 1
	OpStatusStandby   uint8 = 2
	OpStatusShutdown  uint8 = 3
	OpStatusFault     uint8 = 4
	OpStatusSleeping  uint8 = 5
)

// Storage mode status codes (storageModeStatus).
const (
	StorageIdle        uint8 = 0
	StorageCharging    uint8 = 1
	StorageDischarging uint8 = 2
)

// Inverter status codes (inverterStatus).
const (
	InverterIdle      uint8 = 0
	InverterOperating uint8 = 1
	InverterOff       uint8 = 2
	InverterFault     uint8 = 3
)

// ─── Curve types ──────────────────────────────────────────────────────────────

// CurveLink is a reference to a DERCurve resource, embedded in DERControlBase.
// The server populates the href attribute; the client resolves the curve from
// its local DERCurveList cache.
type CurveLink struct {
	Href string `xml:"href,attr,omitempty"`
}

// DERCurveData is one (x, y) point in a piecewise-linear DERCurve.
// Units depend on the curve type (e.g., voltage in % of nominal for Volt-VAr).
type DERCurveData struct {
	XValue int32 `xml:"xvalue"` // x-axis value
	YValue int32 `xml:"yvalue"` // y-axis value
}

// DERCurve is a piecewise-linear inverter characteristic curve.
// It is referenced from DERControlBase via the opMod*Link fields.
//
// ANCHOR: IEEE Std 2030.5-2018, printed p.252-253, "DERCurve object
// (IdentifiedObject)" and its thirteen attributes. Corroborated by 2030.5-2023
// p.265-266. See docs/schema/NORMATIVE_ANCHOR.md §3.3.
//
// FIELD ORDER IS THE STANDARD'S SEQUENCE, and that is load-bearing rather than
// cosmetic: DERCurve is an xs:sequence (an ORDERED particle) extending
// IdentifiedObject (mRID, description, version), and Go's encoding/xml emits
// struct fields in declaration order. Decode is order-tolerant, so a divergence
// is invisible on every document this tree READS; it becomes a validity defect
// the moment a document is EMITTED to a validating peer.
//
// 2030.5-2018 prints no XSD, so the sequence is derived: the standard's
// attribute listing is case-insensitive alphabetical, the draft schema's
// xs:sequence over the same elements is EXACTLY that order, and the restored
// elements take their alphabetical slots. NORMATIVE_ANCHOR.md §1.4 flags this
// as the census's one inference. TestDERCurveFieldOrderMatches2018 pins the
// result; TestSequenceIsCaseInsensitiveAlphabetical pins the rule.
//
// FOUR MANDATORY ELEMENTS HAVE NO omitempty — creationTime, xMultiplier,
// yMultiplier, yRefType. All four are [1] (2018 p.253) and all four have a
// MEANINGFUL zero: xMultiplier/yMultiplier 0 is "×10^0", the commonest
// multiplier there is, and yRefType 0 is DERUnitRefType's "N/A" (2018 p.256).
// `omitempty` DROPPED the element at that value, so the most ordinary curve in
// the standard emitted a document with a mandatory element missing. omitempty
// belongs on [0..1] elements only. (Fixed 9856710; the anchor correction does
// not disturb it — the draft and the standard agree on all four cardinalities.)
//
// THREE OF THE FOUR "PHANTOM" FIELDS ARE BACK, and this is the correction
// registry IW15-027 exists for. 9856710 deleted autonomousVRefEnable,
// autonomousVRefTimeConstant, vRef and xRefType on the evidence that each had
// ZERO occurrences in docs/schema/sep-2.0.4.xsd. That evidence was true and
// irrelevant: the file is the pre-publication ZigBee draft. IEEE 2030.5-2018
// declares the first three (p.252-253) and 2030.5-2023 declares them too
// (p.265-266); only xRefType is a genuine phantom, absent from both published
// revisions AND the draft, and it stays deleted. The downstream consequence —
// csip-tls-test's gridsim answering 400 when asked to SERVE a vRef — must
// partly revert; that is the follow-up wave's row.
// TestDERCurveHasNoPhantomElements now guards only xRefType;
// TestDERCurveRestoredVRefElementsRoundTrip guards the three that came back.
type DERCurve struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurve"`
	Resource

	// ── IdentifiedObject (2018 p.215 Fig B.26 for the shape) ─────────────────
	// mRID is [1] and keeps its omitempty: unlike the four numeric elements
	// below it has no meaningful zero — an empty mRID is not a curve identity,
	// and emitting `<mRID></mRID>` would be invalid in a different way
	// (mRIDType is a 16-octet HexBinary128, 2018 p.167). A curve with no mRID
	// is a caller defect, not an encoding one.
	MRID        string `xml:"mRID,omitempty"`
	Description string `xml:"description,omitempty"` // [0..1]
	Version     uint16 `xml:"version,omitempty"`     // [0..1]

	// ── DERCurve's own sequence, alphabetical (2018 p.252-253) ───────────────

	// AutonomousVRefEnable — 2018 p.252, boolean [0..1]. "If the curveType is
	// opModVoltVar, then this field MAY be present. If the curveType is not
	// opModVoltVar, then this field SHALL NOT be present. Enable/disable
	// autonomous vRef adjustment. ... If a DER is able to support Volt-Var mode
	// but is unable to support autonomous vRef adjustment, then the DER SHALL
	// execute the curve without autonomous vRef adjustment. If not specified,
	// then the value is false." A POINTER, so "absent" and "explicitly false"
	// stay distinguishable — the SHALL NOT above makes presence itself carry
	// meaning.
	AutonomousVRefEnable *bool `xml:"autonomousVRefEnable,omitempty"`

	// AutonomousVRefTimeConstant — 2018 p.253, UInt32 [0..1], "Adjustment range
	// for vRef time constant, in hundredths of a second." Same opModVoltVar-only
	// SHALL NOT, and 2018 p.252 makes it mandatory-when-enabled:
	// autonomousVRefEnable true "SHALL" be accompanied by this element.
	AutonomousVRefTimeConstant *uint32 `xml:"autonomousVRefTimeConstant,omitempty"`

	// CreationTime — 2018 p.253, TimeType [1]. NOT omitempty: see the type doc.
	CreationTime int64 `xml:"creationTime"`

	// CurveData is the ordered list of (x,y) breakpoints — 2018 p.253-254,
	// [1..10]. It precedes curveType in the sequence (case-insensitively,
	// "curvedata" < "curvetype"). omitempty is a no-op on a slice (an empty
	// slice emits nothing either way) and is kept only so a zero-value DERCurve
	// marshals without an empty element.
	CurveData []DERCurveData `xml:"CurveData,omitempty"`

	// CurveType identifies what this curve represents — 2018 p.253, [1];
	// see the CurveType* constants and 2018 p.254 for the enumeration.
	CurveType uint16 `xml:"curveType"`

	// OpenLoopTms: time (in hundredths of a second) to ramp up to 90 % of the
	// new target — 2018 p.253, UInt16 [0..1]. 0 means no limit.
	OpenLoopTms *uint16 `xml:"openLoopTms,omitempty"`

	// Ramp timing — all UInt16 [0..1], 2018 p.253. rampDecTms/rampIncTms are
	// hundredths of a percent per second; rampPT1Tms is hundredths of a second.
	RampDecTms *uint16 `xml:"rampDecTms,omitempty"`
	RampIncTms *uint16 `xml:"rampIncTms,omitempty"`
	RampPT1Tms *uint16 `xml:"rampPT1Tms,omitempty"`

	// VRef — 2018 p.253, PerCent [0..1]: "The nominal ac voltage (rms)
	// adjustment to the voltage curve points for Volt-Var curves." It is not
	// decoration: 2018 p.250 makes it multiply the x axis — "If VRef is present
	// in DERCurve, then the x value of each pair is additionally multiplied by
	// VRef/10 000." Dropping it silently rescales every breakpoint of a
	// volt-var curve. Same opModVoltVar-only SHALL NOT as the two above.
	VRef *PerCent `xml:"vRef,omitempty"`

	// Axis multipliers: apply 10^multiplier to all x or y values — 2018 p.253,
	// PowerOfTenMultiplierType, both [1]. NOT omitempty: 0 means ×10^0.
	XMultiplier int8 `xml:"xMultiplier"`
	YMultiplier int8 `xml:"yMultiplier"`

	// YRefType is the Y-axis units context — 2018 p.253, DERUnitRefType [1].
	// NOT omitempty: 0 is that enumeration's "N/A" (2018 p.256), a value the
	// standard admits and a server may legitimately send.
	YRefType uint8 `xml:"yRefType"`
}

// DERCurveList is a collection of DERCurve resources belonging to one DERProgram.
type DERCurveList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurveList"`
	Resource

	All      uint32     `xml:"all,attr"`
	Results  uint32     `xml:"results,attr"`
	PollRate uint32     `xml:"pollRate,attr,omitempty"`
	DERCurve []DERCurve `xml:"DERCurve"`
}

// ─── FreqDroop (anti-islanding / frequency droop settings) ───────────────────
//
// opModFreqDroop is the only DERControlBase mode that carries inline parameters
// rather than a curve link. It is used for active anti-islanding and frequency
// regulation.

// FreqDroop defines frequency droop (Frequency-Watt parameterized) parameters.
//
// ANCHOR: IEEE Std 2030.5-2018, printed p.242 ("FreqDroopType object ()") and
// Figure B.37 p.240, which shows all five attributes without a [0..1] marker.
// Corroborated by 2030.5-2023 p.269-270 and by docs/schema/sep-2.0.4.xsd:3298,
// which AGREE with 2018 element-for-element, type-for-type and unit-for-unit.
// ALL FIVE elements are [1] — a conformant opModFreqDroop carries every one of
// them, so a decode that silently zeroes four of them is not a partial decode,
// it is a wrong one. See docs/schema/NORMATIVE_ANCHOR.md §3.5.
//
// CORRECTED 2026-08-14 (R4a), and RE-VERIFIED 2026-08-15 against the published
// standard rather than the draft schema R4a cited. The fix STANDS unchanged:
// the names it corrected TO are 2018 vocabulary, which is exactly what one
// expects, since this package was always a 2018 model with a wrong citation.
//
// The previous struct declared dBuf / dF / dP / openLoopTms / tResponse. Only
// openLoopTms exists in the standard; the other four element names do not
// appear in 2030.5-2018 anywhere, so a conformant opModFreqDroop decoded to a
// struct in which four of the five parameters were zero — a droop control with
// no dead band and no gain — with no error raised. Two of the four also had the
// wrong width: dBOF/dBUF are UInt32, not UInt16.
//
// UNITS, per IEEE Std 2030.5-2018 p.242:
//
//	dBOF, dBUF     thousandths of Hz (frequency droop dead band, over/under)
//	kOF, kUF       thousandths, unitless (per-unit frequency change per
//	               per-unit power change, over/under)
//	openLoopTms    hundredths of a second; 0 means "no limit"
//
// Note that these are NOT the same quantities the old field names implied:
// there is no single dead-band width (there is an over- and an under-frequency
// one) and there is no "W per Hz" gain (k is dimensionless per-unit).
type FreqDroop struct {
	// dBOF: frequency droop dead band for OVER-frequency conditions, in
	// thousandths of Hz.
	DBOF uint32 `xml:"dBOF"`
	// dBUF: frequency droop dead band for UNDER-frequency conditions, in
	// thousandths of Hz.
	DBUF uint32 `xml:"dBUF"`
	// kOF: per-unit frequency change for over-frequency conditions
	// corresponding to a 1 per-unit power output change. Thousandths, unitless.
	KOF uint16 `xml:"kOF"`
	// kUF: the same for under-frequency conditions. Thousandths, unitless.
	KUF uint16 `xml:"kUF"`
	// openLoopTms: open-loop response time — the duration from a step change in
	// the control input until the output has changed by 90 % of its final
	// change, in hundredths of a second. 0 means no limit.
	OpenLoopTms uint16 `xml:"openLoopTms"`
}

// ─── ReactivePower / WattPower — for opModTargetVar / opModTargetW ───────────

// ReactivePower represents a reactive power set point.
// Value is in VAr; apply 10^Multiplier to get actual VAr.
type ReactivePower struct {
	Multiplier int8  `xml:"multiplier"`
	Value      int16 `xml:"value"`
}

// ─── Expanded DERControlBase ──────────────────────────────────────────────────
//
// The DERControlBase in resources.go holds the scalar modes. This file extends
// it with the curve-linked and droop modes that are defined elsewhere in the
// 2030.5 XSD.
//
// We cannot embed two structs with overlapping XML element names in Go's
// encoding/xml, so we extend DERControlBase directly with additional fields.
// The struct in resources.go is replaced by this comprehensive version.

// ExtendedDERControlBase is the full IEEE 2030.5 DERControlBase with both scalar
// operating modes and curve-linked / droop modes.
//
// The narrower DERControlBase in resources.go is kept for compatibility with the
// scheduler (which only ever touches scalar modes). The walker resolves curve
// links and stores them in the schedule layer, not here.
//
// ANCHOR: IEEE Std 2030.5-2018, printed p.248-252 (the prose attribute listing)
// and Figure B.37 p.240 (the UML box, same order, same cardinalities).
// TWENTY-SIX elements, every one [0..1]. Corroborated by 2030.5-2023 p.251+.
// See docs/schema/NORMATIVE_ANCHOR.md §3.4.
//
// XML element names match the standard exactly (case-sensitive), and so does
// the field ORDER.
//
// FIELD ORDER IS THE STANDARD'S SEQUENCE. DERControlBase is an xs:sequence, an
// ORDERED particle: a validating peer rejects a document whose elements arrive
// in a different order even when every element is legal. Go's encoding/xml
// emits struct fields in declaration order, so the struct layout IS the emitted
// sequence. Decode is order-tolerant, which is why a wrong order survives
// forever on a tree that only READS.
//
// The order is ALPHABETICAL by element name (case-insensitively), which is why
// the grouping below looks arbitrary: opModFreqDroop sits between opModFixedW
// and opModFreqWatt because "freqd" < "freqw", not because the droop belongs
// with the setpoints. 2030.5-2018 prints no XSD; NORMATIVE_ANCHOR.md §1.4
// records how the sequence is derived and flags it as the census's one
// inference. TestDERControlBaseFieldOrderMatches2018 pins the result.
//
// RE-DERIVED 2026-08-15 (registry IW15-027). 9856710 put this struct into the
// sequence of docs/schema/sep-2.0.4.xsd — the pre-publication ZigBee draft —
// whose DERControlBase has 21 elements: it folds opModFixedPFAbsorbW/InjectW
// into a single opModFixedPF and declares no opMod*MayTrip links at all. Both
// of those readings are now reversed. The ORDERING RULE it established survives
// intact; only the element SET it was applied to was short by five.
//
// THE FOUR MayTrip LINKS ARE REAL 2018 ELEMENTS (p.248 HFRT, p.249 HVRT and
// LFRT, p.249-250 LVRT) and now sit in their alphabetical sequence slots rather
// than in a "not in the schema" tail. A conformant server may send any of them
// and this struct is where they belong. lexa-gw's advaxis/fanOutClasses
// enumerate them; registry IW15-020's premise — that they name modes no
// revision defines — is withdrawn.
//
// ONLY THE CSIP-Aus QUARTET IS STILL AFTER rampTms, because it really is not
// 2030.5: absent from 2030.5-2018, 2030.5-2023 and sep 2.0.4 alike. Keeping the
// standard-declared prefix contiguous and in sequence is what lets a control
// carrying only 2030.5 elements marshal to a valid document.
type ExtendedDERControlBase struct {
	// ── IEEE 2030.5-2018 DERControlBase, in sequence (all [0..1]) ────────────
	OpModConnect  *bool `xml:"opModConnect,omitempty"`  // 2018 p.248
	OpModEnergize *bool `xml:"opModEnergize,omitempty"` // 2018 p.248
	// 2018 p.248 declares BOTH of these as first-class elements, typed
	// PowerFactorWithExcitation, with their own DERControlType bits (4 and 5).
	// The draft schema's single "opModFixedPF" — and the divergence note
	// 9856710 recorded here — were artifacts of the wrong anchor: this package
	// was right and the draft is the outlier.
	//
	// CLOSED (NORMATIVE_ANCHOR.md §5.1, follow-up wave): 2018 p.258 types both
	// as PowerFactorWithExcitation — {displacement UInt16, excitation boolean,
	// multiplier PowerOfTenMultiplierType}, all mandatory — and they were
	// *SignedPerCent, a bare chardata Int16 that decoded a conformant
	// <opModFixedPFInjectW><displacement>950</displacement>... to ZERO. See that
	// type's doc for why the scalar shape gets no decode tolerance.
	OpModFixedPFAbsorbW *PowerFactorWithExcitation `xml:"opModFixedPFAbsorbW,omitempty"`
	OpModFixedPFInjectW *PowerFactorWithExcitation `xml:"opModFixedPFInjectW,omitempty"`
	OpModFixedVar       *FixedVar                  `xml:"opModFixedVar,omitempty"` // 2018 p.248
	OpModFixedW         *SignedPerCent             `xml:"opModFixedW,omitempty"`   // 2018 p.248. SignedPerCent, not watts — IW13-001. Sign selects reference: + = %setMaxW/%setMaxDischargeRateW, - = %setMaxChargeRateW.
	// Frequency droop (inline parameters, not a curve link) — 2018 p.248, and
	// alphabetically ahead of opModFreqWatt.
	OpModFreqDroop *FreqDroop `xml:"opModFreqDroop,omitempty"`
	// Frequency-Watt — 2018 p.248, "Specify DERCurveLink for curveType == 0".
	OpModFreqWatt *CurveLink `xml:"opModFreqWatt,omitempty"`
	// The ride-through block, 2018 p.248-250, in alphabetical order. Each cites
	// the curveType its linked DERCurve must carry.
	OpModHFRTMayTrip            *CurveLink     `xml:"opModHFRTMayTrip,omitempty"`            // 2018 p.248 — curveType == 1
	OpModHFRTMustTrip           *CurveLink     `xml:"opModHFRTMustTrip,omitempty"`           // 2018 p.249 — curveType == 2
	OpModHVRTMayTrip            *CurveLink     `xml:"opModHVRTMayTrip,omitempty"`            // 2018 p.249 — curveType == 3
	OpModHVRTMomentaryCessation *CurveLink     `xml:"opModHVRTMomentaryCessation,omitempty"` // 2018 p.249 — curveType == 4
	OpModHVRTMustTrip           *CurveLink     `xml:"opModHVRTMustTrip,omitempty"`           // 2018 p.249 — curveType == 5
	OpModLFRTMayTrip            *CurveLink     `xml:"opModLFRTMayTrip,omitempty"`            // 2018 p.249 — curveType == 6
	OpModLFRTMustTrip           *CurveLink     `xml:"opModLFRTMustTrip,omitempty"`           // 2018 p.249 — curveType == 7
	OpModLVRTMayTrip            *CurveLink     `xml:"opModLVRTMayTrip,omitempty"`            // 2018 p.249 — curveType == 8
	OpModLVRTMomentaryCessation *CurveLink     `xml:"opModLVRTMomentaryCessation,omitempty"` // 2018 p.250 — curveType == 9
	OpModLVRTMustTrip           *CurveLink     `xml:"opModLVRTMustTrip,omitempty"`           // 2018 p.250 — curveType == 10
	OpModMaxLimW                *PerCent       `xml:"opModMaxLimW,omitempty"`                // 2018 p.250. PerCent of setMaxW in hundredths, not watts — IW13-001.
	OpModTargetVar              *ReactivePower `xml:"opModTargetVar,omitempty"`              // 2018 p.250 — target reactive power, in var
	OpModTargetW                *ActivePower   `xml:"opModTargetW,omitempty"`                // 2018 p.250 — target output power, in watts
	// Volt-Var — 2018 p.250, "Specify DERCurveLink for curveType == 11", which
	// is the number CSIP-CONF's catalog prescribes.
	OpModVoltVar *CurveLink `xml:"opModVoltVar,omitempty"`
	// Volt-Watt — 2018 p.250-251, curveType == 12.
	OpModVoltWatt *CurveLink `xml:"opModVoltWatt,omitempty"`
	// Watt-PF — 2018 p.251, curveType == 13.
	OpModWattPF *CurveLink `xml:"opModWattPF,omitempty"`
	// Watt-Var — 2018 p.251, curveType == 14; DERControlType bit 26.
	//
	// ADDED 2026-08-14 (R4c): it was previously absent from this struct
	// entirely, so a server that sent opModWattVar had it silently DISCARDED at
	// decode — the control looked, to everything downstream, like a control that
	// commanded nothing on that axis. The fix stands under the 2018 anchor; only
	// the bit and curveType numbers moved.
	OpModWattVar *CurveLink `xml:"opModWattVar,omitempty"`
	RampTms      *uint16    `xml:"rampTms,omitempty"` // 2018 p.251 — the standard's last element, hundredths of a second

	// ── NOT IEEE 2030.5 — everything below this line ─────────────────────────
	//
	// ExpLimW/GenLimW/ImpLimW/LoadLimW are NOT IEEE 2030.5 elements in ANY
	// revision: verified absent from 2030.5-2018 (p.248-252), from 2030.5-2023,
	// and from sep.xsd 2.0.4. They match the CSIP-Aus dynamic-operating-envelope
	// extension quartet, which types them ActivePower (watts) as here. The
	// governing extension schema is not in the local standards corpus — confirm
	// against it before any conformance claim on these axes. See
	// docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1.2. DERControlType has
	// no bit for any of them either, so they cannot be advertised in
	// modesSupported (see ModeBit).
	OpModExpLimW  *ActivePower `xml:"opModExpLimW,omitempty"`
	OpModGenLimW  *ActivePower `xml:"opModGenLimW,omitempty"`
	OpModImpLimW  *ActivePower `xml:"opModImpLimW,omitempty"`
	OpModLoadLimW *ActivePower `xml:"opModLoadLimW,omitempty"`
}

// ExtendedDERControl wraps a DERControl with the full ExtendedDERControlBase.
// The walker populates this when DERCurveListLink is present in a program.
type ExtendedDERControl struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERControl"`
	Resource

	// Event-base RespondableResource attributes (audit CSIP-004) — the
	// extended (curve-linked) DERControl carries the same replyTo/
	// responseRequired the plain DERControl does; see DERControl in
	// resources.go for semantics. Additive/omitempty.
	ReplyTo          string            `xml:"replyTo,attr,omitempty"`
	ResponseRequired *ResponseRequired `xml:"responseRequired,attr,omitempty"`

	MRID              string                 `xml:"mRID,omitempty"`
	Description       string                 `xml:"description,omitempty"`
	Version           uint16                 `xml:"version,omitempty"`
	CreationTime      int64                  `xml:"creationTime,omitempty"`
	EventStatus       *EventStatus           `xml:"EventStatus,omitempty"`
	Interval          DateTimeInterval       `xml:"interval"`
	DERControlBase    ExtendedDERControlBase `xml:"DERControlBase"`
	RandomizeStart    *int32                 `xml:"randomizeStart,omitempty"`
	RandomizeDuration *int32                 `xml:"randomizeDuration,omitempty"`
}

// ExtendedDERControlList is a collection of ExtendedDERControl events.
type ExtendedDERControlList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERControlList"`
	Resource

	All        uint32               `xml:"all,attr"`
	Results    uint32               `xml:"results,attr"`
	PollRate   uint32               `xml:"pollRate,attr,omitempty"`
	DERControl []ExtendedDERControl `xml:"DERControl"`
}

// ExtendedDefaultDERControl is a DefaultDERControl with the full control base.
type ExtendedDefaultDERControl struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DefaultDERControl"`
	Resource

	MRID           string                 `xml:"mRID,omitempty"`
	Description    string                 `xml:"description,omitempty"`
	Version        uint16                 `xml:"version,omitempty"`
	DERControlBase ExtendedDERControlBase `xml:"DERControlBase"`
}

// ─── DERCapability (expanded) ─────────────────────────────────────────────────

// DERCapabilityFull is the expanded DERCapability with modesSupported bitmask
// and all nameplate ratings required by §10.10.2.
type DERCapabilityFull struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCapability"`
	Resource

	// Type is DERType — IEEE Std 2030.5-2018 printed p.245. That page cite was an
	// inference when NORMATIVE_ANCHOR.md §5.3 filed this row and the
	// citation-verification pass confirmed it exactly right, so it stands as a
	// verified cite rather than a guess:
	//
	//	0 = not applicable        5 = combined heat and power
	//	1 = virtual or mixed      6 = other generation
	//	2 = reciprocating engine  80 = other storage
	//	3 = fuel cell             81 = electric vehicle
	//	4 = photovoltaic system   82 = EVSE
	//	                          83 = combined PV and storage
	//
	// THE LIST THIS REPLACES WAS WRONG IN EVERY POSITION PAST 2 — it named a
	// "wind" type 2030.5 does not declare in any revision, and put photovoltaic
	// at 80, where the standard puts other-storage. Comment-level only: nothing
	// in this tree branches on the value, which is precisely why it went
	// unchecked for as long as it did. Anything that starts branching on it owes
	// a golden decode first.
	Type uint8 `xml:"type"`

	// ModesSupported is a bitmask of the DERControlBase operating modes this
	// DER supports. See Mode* constants defined above.
	ModesSupported HexBinary32 `xml:"modesSupported"`

	// Nameplate ratings (all use ActivePower — value × 10^multiplier in W or VA or VAr).
	RtgMaxW              ActivePower  `xml:"rtgMaxW"`                        // nameplate peak active power
	RtgMaxVA             *ActivePower `xml:"rtgMaxVA,omitempty"`             // nameplate peak apparent power
	RtgMaxVar            *ActivePower `xml:"rtgMaxVar,omitempty"`            // nameplate peak reactive power (absorb)
	RtgMaxVarNeg         *ActivePower `xml:"rtgMaxVarNeg,omitempty"`         // nameplate peak reactive power (inject)
	RtgMinPFOverExcited  *int16       `xml:"rtgMinPFOverExcited,omitempty"`  // min power factor, over-excited
	RtgMinPFUnderExcited *int16       `xml:"rtgMinPFUnderExcited,omitempty"` // min power factor, under-excited
	RtgMaxChargeRateW    *ActivePower `xml:"rtgMaxChargeRateW,omitempty"`    // max charge rate (storage)
	RtgMaxDischargeRateW *ActivePower `xml:"rtgMaxDischargeRateW,omitempty"` // max discharge rate
	RtgVNom              *int32       `xml:"rtgVNom,omitempty"`              // nominal voltage (V)
	RtgVarNomPct         *int16       `xml:"rtgVarNomPct,omitempty"`         // var at nominal voltage (% of rtgMaxVA)
	RtgWOvPF             *int16       `xml:"rtgWOvPF,omitempty"`             // reactive power capability at rated W, over PF (VAr)
}

// ─── DERStatus (full) ─────────────────────────────────────────────────────────

// DERStatusValue is a typed measurement + timestamp.
type DERStatusValue struct {
	DateTime int64 `xml:"dateTime"`
	Value    uint8 `xml:"value"`
}

// DERStatusFull contains the complete real-time DER operational status.
type DERStatusFull struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERStatus"`
	Resource

	// ReadingTime is when this status snapshot was captured (Unix seconds).
	ReadingTime int64 `xml:"readingTime,omitempty"`

	// GenConnectStatus: generator connection state (see GenConnect* constants).
	GenConnectStatus *DERStatusValue `xml:"genConnectStatus,omitempty"`

	// InverterStatus: current inverter operating state (see Inverter* constants).
	InverterStatus *DERStatusValue `xml:"inverterStatus,omitempty"`

	// LocalControlModeStatus: 0=remote, 1=local.
	LocalControlModeStatus *DERStatusValue `xml:"localControlModeStatus,omitempty"`

	// ManufacturerStatus: manufacturer-defined status code.
	ManufacturerStatus *struct {
		DateTime    int64  `xml:"dateTime"`
		Description string `xml:"description,omitempty"`
		PEVInfo     string `xml:"pEVInfo,omitempty"`
	} `xml:"manufacturerStatus,omitempty"`

	// OperationalModeStatus: current operating mode (see OpStatus* constants).
	OperationalModeStatus *DERStatusValue `xml:"operationalModeStatus,omitempty"`

	// StateOfChargeStatus: battery state-of-charge in percent × 100 (0–10000).
	StateOfChargeStatus *struct {
		DateTime int64 `xml:"dateTime"`
		Value    int16 `xml:"value"` // 0–10000 (= 0–100.00 %)
	} `xml:"stateOfChargeStatus,omitempty"`

	// StorageModeStatus: charge/discharge/idle (see Storage* constants).
	StorageModeStatus *DERStatusValue `xml:"storageModeStatus,omitempty"`
}

// ─── DERAvailability ─────────────────────────────────────────────────────────

// DERAvailability represents the device's current and short-term available power.
type DERAvailability struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERAvailability"`
	Resource

	// ReadingTime is when this reading was captured (Unix seconds).
	ReadingTime int64 `xml:"readingTime,omitempty"`

	// AvailabilityDuration is how long the device can sustain its current
	// output (seconds). 0 means the information is not available.
	AvailabilityDuration *uint32 `xml:"availabilityDuration,omitempty"`

	// MaxChargeDuration is how long the device can sustain its maximum charge
	// rate (seconds). Storage only.
	MaxChargeDuration *uint32 `xml:"maxChargeDuration,omitempty"`

	// EstimatedVarAvail is the estimated reactive power available right now.
	EstimatedVarAvail *ReactivePower `xml:"estimatedVarAvail,omitempty"`

	// EstimatedWAvail is the estimated real power available right now.
	EstimatedWAvail *ActivePower `xml:"estimatedWAvail,omitempty"`

	// MaxForecastW is the forecast of maximum available real power over the
	// next period. Used for look-ahead dispatch.
	MaxForecastW *ActivePower `xml:"maxForecastW,omitempty"`
}

// ─── DERSettings (expanded) ──────────────────────────────────────────────────

// DERSettingsFull is the expanded DERSettings including all configurable limits.
type DERSettingsFull struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERSettings"`
	Resource

	UpdatedTime int64 `xml:"updatedTime,omitempty"`

	// Power limits — operator-configured ceilings.
	SetMaxW      *ActivePower `xml:"setMaxW,omitempty"`      // max real power output
	SetMaxVA     *ActivePower `xml:"setMaxVA,omitempty"`     // max apparent power
	SetMaxVar    *ActivePower `xml:"setMaxVar,omitempty"`    // max reactive power (absorb)
	SetMaxVarNeg *ActivePower `xml:"setMaxVarNeg,omitempty"` // max reactive power (inject)

	// Power factor limits (signed, hundredths: 95 = 0.95 leading).
	SetMinPFOverExcited  *int16 `xml:"setMinPFOverExcited,omitempty"`
	SetMinPFUnderExcited *int16 `xml:"setMinPFUnderExcited,omitempty"`

	// Storage-specific limits.
	SetMaxChargeRateW    *ActivePower `xml:"setMaxChargeRateW,omitempty"`
	SetMaxDischargeRateW *ActivePower `xml:"setMaxDischargeRateW,omitempty"`
	SetStorBattTarget    *int16       `xml:"setStorBattTarget,omitempty"` // target SOC % × 100

	// Voltage reference for Volt-VAr curves (V, integer).
	SetVRef *int32 `xml:"setVRef,omitempty"`
}
