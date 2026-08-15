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
// IMPLEMENTS the mode the schema assigns to N — "Bitmap indicating the DER
// Controls implemented by the device" (sep-2.0.4.xsd:3573, DERCapability's
// modesSupported; the companion modesEnabled on DERSettings, xsd:3372, is the
// ENABLED subset, and the schema is explicit that a supported-but-not-enabled
// control "will not be executed").
//
// CORRECTED 2026-08-15 — LEGACY_CURVES_RC0_2026-08-14 §10 stage 9, the
// "modesSupported truth" stage; registry IW15-011. The previous table was a
// different assignment ENTIRELY: it packed the modes into bits 0..26 in its own
// order, gave one bit to "opModConnect / opModEnergize" jointly, invented four
// MayTrip bits for modes the schema does not define, and spent bits 23..26 on
// the CSIP-Aus dynamic-operating-envelope quartet, which DERControlType has no
// bit for at all. Sixteen of the twenty-two schema modes landed on the wrong
// bit. It was LATENT rather than live — lexa-gw's derproducer hardcoded
// ModesSupported: 0 and nothing else populated the field — and the correction
// lands together with the code that first populates it truthfully.
//
// Every constant is transcribed from the vendored schema's own bit table:
// docs/schema/sep-2.0.4.xsd, complexType "DERControlType" (line 3825), whose
// xs:documentation says "Bit positions SHALL be defined as follows:" and then
// lists bits 0..21 on lines 3828..3849 — one line per bit, cited per constant
// below. Line 3850 closes with "All other values reserved.", so bits 22..31
// have no meaning and this package declares none.
//
// TestModeBitsMatchXSD PARSES that block and proves this table reproduces it in
// both directions, rather than restating it — the discipline the R4a/R4b
// corrections established, and the one that would have caught this table.
//
// THREE MODES THE SCHEMA NAMES AND THIS PRODUCT DOES NOT IMPLEMENT still get a
// constant (opModFixedPF, Charge, Discharge): the table's job is to reproduce
// the schema's assignment, and a hole in it is how a neighbouring bit gets
// mis-numbered. Whether the product SETS a bit is a separate question, answered
// per device by the publisher (lexa-gw internal/derproducer).
//
// FOUR ELEMENTS THIS PACKAGE DECODES HAVE NO BIT, and cannot be advertised in
// this bitmap at all: opModExpLimW / opModGenLimW / opModImpLimW /
// opModLoadLimW are the CSIP-Aus dynamic-operating-envelope quartet, absent
// from sep 2.0.4 (see ExtendedDERControlBase). The old table gave them bits
// 23..26, which is a claim on reserved positions. A gateway that executes them
// must say so somewhere other than modesSupported.
const (
	ModeVoltVar                HexBinary32 = 1 << 0  // xsd:3828 — 0 opModVoltVar (Volt-Var Mode)
	ModeFreqWatt               HexBinary32 = 1 << 1  // xsd:3829 — 1 opModFreqWatt (Frequency-Watt Curve Mode)
	ModeFreqDroop              HexBinary32 = 1 << 2  // xsd:3830 — 2 opModFreqDroop (Frequency-Watt Parameterized Mode)
	ModeWattPF                 HexBinary32 = 1 << 3  // xsd:3831 — 3 opModWattPF (Watt-PowerFactor Mode)
	ModeVoltWatt               HexBinary32 = 1 << 4  // xsd:3832 — 4 opModVoltWatt (Volt-Watt Mode)
	ModeLVRTMomentaryCessation HexBinary32 = 1 << 5  // xsd:3833 — 5 opModLVRTMomentaryCessation
	ModeLVRTMustTrip           HexBinary32 = 1 << 6  // xsd:3834 — 6 opModLVRTMustTrip
	ModeHVRTMomentaryCessation HexBinary32 = 1 << 7  // xsd:3835 — 7 opModHVRTMomentaryCessation
	ModeHVRTMustTrip           HexBinary32 = 1 << 8  // xsd:3836 — 8 opModHVRTMustTrip
	ModeLFRTMustTrip           HexBinary32 = 1 << 9  // xsd:3837 — 9 opModLFRTMustTrip
	ModeHFRTMustTrip           HexBinary32 = 1 << 10 // xsd:3838 — 10 opModHFRTMustTrip
	ModeConnect                HexBinary32 = 1 << 11 // xsd:3839 — 11 opModConnect (implies galvanic isolation)
	ModeEnergize               HexBinary32 = 1 << 12 // xsd:3840 — 12 opModEnergize (Energize / De-Energize)
	ModeMaxLimW                HexBinary32 = 1 << 13 // xsd:3841 — 13 opModMaxLimW (Maximum Active Power)
	ModeFixedVar               HexBinary32 = 1 << 14 // xsd:3842 — 14 opModFixedVar (Reactive Power Setpoint)
	ModeFixedPF                HexBinary32 = 1 << 15 // xsd:3843 — 15 opModFixedPF (Fixed Power Factor Setpoint)
	ModeFixedW                 HexBinary32 = 1 << 16 // xsd:3844 — 16 opModFixedW (Charge / Discharge Setpoint)
	ModeTargetW                HexBinary32 = 1 << 17 // xsd:3845 — 17 opModTargetW (Target Active Power)
	ModeTargetVar              HexBinary32 = 1 << 18 // xsd:3846 — 18 opModTargetVar (Target Reactive Power)
	ModeCharge                 HexBinary32 = 1 << 19 // xsd:3847 — 19 Charge mode (no opMod element; a mode, not a control)
	ModeDischarge              HexBinary32 = 1 << 20 // xsd:3848 — 20 Discharge mode (no opMod element)
	ModeWattVar                HexBinary32 = 1 << 21 // xsd:3849 — 21 opModWattVar (Watt-Var Mode)
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
// Keys are the schema's own element names, verbatim, including the two bits the
// schema names WITHOUT an element ("Charge mode" / "Discharge mode" → "Charge"
// / "Discharge"). Bits with no mode name, and names with no bit, do not appear.
var modeBits = map[string]HexBinary32{
	"opModVoltVar":                ModeVoltVar,
	"opModFreqWatt":               ModeFreqWatt,
	"opModFreqDroop":              ModeFreqDroop,
	"opModWattPF":                 ModeWattPF,
	"opModVoltWatt":               ModeVoltWatt,
	"opModLVRTMomentaryCessation": ModeLVRTMomentaryCessation,
	"opModLVRTMustTrip":           ModeLVRTMustTrip,
	"opModHVRTMomentaryCessation": ModeHVRTMomentaryCessation,
	"opModHVRTMustTrip":           ModeHVRTMustTrip,
	"opModLFRTMustTrip":           ModeLFRTMustTrip,
	"opModHFRTMustTrip":           ModeHFRTMustTrip,
	"opModConnect":                ModeConnect,
	"opModEnergize":               ModeEnergize,
	"opModMaxLimW":                ModeMaxLimW,
	"opModFixedVar":               ModeFixedVar,
	"opModFixedPF":                ModeFixedPF,
	"opModFixedW":                 ModeFixedW,
	"opModTargetW":                ModeTargetW,
	"opModTargetVar":              ModeTargetVar,
	"Charge":                      ModeCharge,
	"Discharge":                   ModeDischarge,
	"opModWattVar":                ModeWattVar,
}

// ModeBit returns the DERControlType bit for a mode named by its sep 2.0.4
// element name, and reports whether the schema assigns that name a bit at all.
//
// FALSE IS A REAL ANSWER, not an error to paper over: opModExpLimW and its
// three CSIP-Aus siblings are modes this tree decodes and (on some benches)
// executes, and sep 2.0.4 gives them no bit — a caller composing a
// modesSupported mask must DROP them rather than pick a spare position. The
// same goes for the four opMod*MayTrip links, which name modes the schema does
// not define at all.
//
// The two product-specific power-factor axes are folded here rather than at
// each call site: this package implements opModFixedPF as the
// opModFixedPFAbsorbW / opModFixedPFInjectW pair (see
// ExtendedDERControlBase), and the schema has ONE bit for the function. A DER
// that can hold a fixed power factor in either direction implements
// opModFixedPF, so both names answer with bit 15.
func ModeBit(name string) (HexBinary32, bool) {
	switch name {
	case "opModFixedPFAbsorbW", "opModFixedPFInjectW":
		return ModeFixedPF, true
	}
	b, ok := modeBits[name]
	return b, ok
}

// ModeBitName is ModeBit's inverse over bit POSITIONS 0..31: it returns the
// schema's name for a position, or "" for one the schema reserves. It exists so
// a log line, a PICS table or a defect record can print a mask as the modes it
// claims instead of as a hex integer, and so the mapping is assertable in both
// directions (TestModeBitsMatchXSD).
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
// Transcribed from the vendored schema: docs/schema/sep-2.0.4.xsd, complexType
// "DERCurveType". ELEVEN values, 0..10, proven against the XSD text by
// TestCurveTypeCodesMatchXSD.
//
// CORRECTED 2026-08-14 (R4b). The previous table was wrong for every code ≥ 4
// and had fourteen entries. Most consequentially, curveType = 10 — opModWattVar
// — decoded as "HFRTMayTrip", and the ride-through pairs were transposed (the
// old table put HVRT before LVRT; the XSD orders LVRT first). The old table also
// declared four MayTrip curve types that do not exist in sep 2.0.4 at all: the
// string "MayTrip" appears ZERO times in the whole schema, and DERCurveType's
// ride-through values are only MomentaryCessation and MustTrip. The four
// CurveType*MayTrip constants are therefore REMOVED rather than renumbered —
// they had no referent to renumber to.
//
// BLAST RADIUS, checked before the change was made. Nothing in this tree, in
// lexa-gw or in csip-tls-test BRANCHES on a curve-type number: curve mode is
// derived from the opMod* element a curve is linked from
// (discovery.CurveModeLinks is the single owner of that mapping), never from
// curveType, and every production use of the field is a verbatim pass-through.
// The one mechanism that consumes the number, bus.CurveSetContentHash, hashes
// the value that arrived ON THE WIRE from the server; it never reads these
// constants, so no digest moves and no CurveSetV bump is implied. The only
// assignments of a named constant anywhere — gridsim's curveTypeForMode and a
// handful of tests — use codes 0..3, which the XSD leaves unchanged. The four
// removed MayTrip constants had zero references in either consumer repo.
const (
	CurveTypeVoltVar                uint16 = 0  // opModVoltVar
	CurveTypeFreqWatt               uint16 = 1  // opModFreqWatt (the curve-based mode)
	CurveTypeWattPF                 uint16 = 2  // opModWattPF
	CurveTypeVoltWatt               uint16 = 3  // opModVoltWatt
	CurveTypeLVRTMomentaryCessation uint16 = 4  // opModLVRTMomentaryCessation
	CurveTypeLVRTMustTrip           uint16 = 5  // opModLVRTMustTrip
	CurveTypeHVRTMomentaryCessation uint16 = 6  // opModHVRTMomentaryCessation
	CurveTypeHVRTMustTrip           uint16 = 7  // opModHVRTMustTrip
	CurveTypeLFRTMustTrip           uint16 = 8  // opModLFRTMustTrip
	CurveTypeHFRTMustTrip           uint16 = 9  // opModHFRTMustTrip
	CurveTypeWattVar                uint16 = 10 // opModWattVar
)

// CurveTypeName maps a DERCurveType code to the opMod* element it names, and
// returns "" for a reserved code. It exists so a log line or a defect record can
// say what a server actually sent instead of printing a bare integer, and so the
// mapping is assertable in both directions.
func CurveTypeName(code uint16) string {
	switch code {
	case CurveTypeVoltVar:
		return "opModVoltVar"
	case CurveTypeFreqWatt:
		return "opModFreqWatt"
	case CurveTypeWattPF:
		return "opModWattPF"
	case CurveTypeVoltWatt:
		return "opModVoltWatt"
	case CurveTypeLVRTMomentaryCessation:
		return "opModLVRTMomentaryCessation"
	case CurveTypeLVRTMustTrip:
		return "opModLVRTMustTrip"
	case CurveTypeHVRTMomentaryCessation:
		return "opModHVRTMomentaryCessation"
	case CurveTypeHVRTMustTrip:
		return "opModHVRTMustTrip"
	case CurveTypeLFRTMustTrip:
		return "opModLFRTMustTrip"
	case CurveTypeHFRTMustTrip:
		return "opModHFRTMustTrip"
	case CurveTypeWattVar:
		return "opModWattVar"
	}
	return "" // "All other values reserved." — sep 2.0.4, DERCurveType
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
// FIELD ORDER IS THE SCHEMA'S SEQUENCE, and that is load-bearing rather than
// cosmetic: sep 2.0.4 declares DERCurve as an xs:sequence (an ORDERED particle,
// docs/schema/sep-2.0.4.xsd:3856-3912) extending IdentifiedObject (xsd:5141; mRID 5148, description 5153, version 5158 —
// mRID, description, version), and Go's encoding/xml emits struct fields in
// declaration order. Decode is order-tolerant, so the divergence was invisible
// on every document this tree READS; it becomes a validity defect the moment a
// document is EMITTED to a validating peer. Corrected 2026-08-15 (legacy Stage
// 9 / IW15-021's csipmodel docket): CurveData used to be declared AFTER
// curveType, and the ramp/multiplier block was interleaved with fields the
// schema does not declare at all. TestDERCurveFieldOrderMatchesXSD parses the
// sequence out of the schema and compares it to this struct.
//
// THREE MANDATORY ELEMENTS LOST THEIR omitempty in the same pass —
// creationTime, xMultiplier, yMultiplier (and yRefType, found by the same
// sweep). All four are minOccurs="1", and all four have a MEANINGFUL zero:
// xMultiplier/yMultiplier 0 is "×10^0", the commonest multiplier there is, and
// yRefType 0 is DERUnitRefType's "N/A". `omitempty` DROPPED the element at that
// value, so the most ordinary curve in the standard emitted a
// schema-invalid document with a mandatory element missing. omitempty belongs
// on minOccurs="0" elements only.
//
// FOUR PHANTOM FIELDS WERE REMOVED in the same pass — autonomousVRefEnable,
// autonomousVRefTimeConstant, vRef and xRefType. Each named an element with
// ZERO occurrences in sep 2.0.4 (`grep -c` on the vendored schema: 0, 0, 0, 0),
// so each would silently ACCEPT, from any server, an element the standard does
// not define — and, being `omitempty` pointers/values, could equally have put
// one on the wire from a struct literal. The x-axis reference in particular is
// fixed by the MODE at both ends (a volt-var curve's x is an effective percent
// voltage by definition) and needs no carriage; the standard's only
// V-reference elements are setVRef / setVRefOfs on DERSettings.
// TestDERCurveHasNoPhantomElements keeps them gone.
type DERCurve struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurve"`
	Resource

	// ── IdentifiedObject (xsd:5141) ──────────────────────────────────────────
	// mRID is minOccurs="1" and keeps its omitempty: unlike the four numeric
	// elements below it has no meaningful zero — an empty mRID is not a curve
	// identity, and emitting `<mRID></mRID>` would be invalid in a different
	// way (mRIDType is a 16-octet HexBinary128). A curve with no mRID is a
	// caller defect, not an encoding one.
	MRID        string `xml:"mRID,omitempty"`
	Description string `xml:"description,omitempty"` // xsd:5153, minOccurs 0
	Version     uint16 `xml:"version,omitempty"`     // xsd:5158, minOccurs 0

	// ── DERCurve's own sequence (xsd:3863 onward) ────────────────────────────

	// CreationTime — xsd:3863, minOccurs="1". NOT omitempty: see the type doc.
	CreationTime int64 `xml:"creationTime"`

	// CurveData is the ordered list of (x,y) breakpoints — xsd:3868,
	// minOccurs="1" maxOccurs="10". It precedes curveType in the schema
	// sequence, which is the correction this ordering carries. omitempty is a
	// no-op on a slice (an empty slice emits nothing either way) and is kept
	// only so a zero-value DERCurve marshals without an empty element.
	CurveData []DERCurveData `xml:"CurveData,omitempty"`

	// CurveType identifies what this curve represents — xsd:3869,
	// minOccurs="1"; see the CurveType* constants.
	CurveType uint16 `xml:"curveType"`

	// OpenLoopTms: time (in hundredths of a second) to reach 90 % of the
	// commanded output — xsd:3874, minOccurs="0".
	OpenLoopTms *uint16 `xml:"openLoopTms,omitempty"`

	// Ramp timing — all minOccurs="0". rampDecTms/rampIncTms are hundredths of
	// a percent per second (xsd:3879, 3884); rampPT1Tms is hundredths of a
	// second (xsd:3889).
	RampDecTms *uint16 `xml:"rampDecTms,omitempty"`
	RampIncTms *uint16 `xml:"rampIncTms,omitempty"`
	RampPT1Tms *uint16 `xml:"rampPT1Tms,omitempty"`

	// Axis multipliers: apply 10^multiplier to all x or y values — xsd:3894 and
	// xsd:3899, both minOccurs="1". NOT omitempty: 0 means ×10^0.
	XMultiplier int8 `xml:"xMultiplier"`
	YMultiplier int8 `xml:"yMultiplier"`

	// YRefType is the Y-axis units context — xsd:3904, minOccurs="1", a
	// DERUnitRefType. NOT omitempty: 0 is that enumeration's "N/A", a value the
	// schema admits and a server may legitimately send.
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
// Element names, types and cardinality are transcribed from the vendored
// schema: docs/schema/sep-2.0.4.xsd, complexType "FreqDroopType". ALL FIVE
// elements are minOccurs="1" — a conformant opModFreqDroop carries every one of
// them, so a decode that silently zeroes four of them is not a partial decode,
// it is a wrong one.
//
// CORRECTED 2026-08-14 (R4a). The previous struct declared dBuf / dF / dP /
// openLoopTms / tResponse. Only openLoopTms exists in the schema; the other four
// element names do not appear in sep 2.0.4 anywhere, so a conformant
// opModFreqDroop decoded to a struct in which four of the five parameters were
// zero — a droop control with no dead band and no gain — with no error raised.
// Two of the four also had the wrong width: dBOF/dBUF are UInt32, not UInt16.
//
// UNITS, per the XSD's own documentation:
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
// XML element names match the 2030.5 schema exactly (case-sensitive), and so —
// since 2026-08-15 — does the field ORDER.
//
// FIELD ORDER IS THE SCHEMA'S SEQUENCE. sep 2.0.4 declares DERControlBase as an
// xs:sequence (docs/schema/sep-2.0.4.xsd:3689-3799), which is an ORDERED
// particle: a validating peer rejects a document whose elements arrive in a
// different order even when every element is legal. Go's encoding/xml emits
// struct fields in declaration order, so the struct layout IS the emitted
// sequence. This struct used to declare rampTms in the middle, the curve links
// after the scalars, opModFreqDroop last and the ride-through pairs grouped by
// frequency/voltage — a shape no validator would accept. Decode is
// order-tolerant, which is why it survived: nothing this tree READS was ever
// affected. Recorded as IW15-021's csipmodel docket; corrected here.
//
// The schema's own order is ALPHABETICAL by element name, which is why the
// grouping below looks arbitrary: opModFreqDroop sits between opModFixedW and
// opModFreqWatt because "FreqD" < "FreqW", not because the droop belongs with
// the setpoints. Each field cites its schema line so the sequence is checkable
// against the anchor rather than against this comment.
// TestDERControlBaseFieldOrderMatchesXSD parses the sequence and compares.
//
// THE NON-SCHEMA FIELDS ARE ALL AT THE END, after rampTms — the four
// opMod*MayTrip links and the CSIP-Aus quartet. That is deliberate: it makes
// the schema-declared prefix of this struct contiguous and in sequence, so a
// control carrying only sep 2.0.4 elements marshals to a valid document. Their
// own position among themselves has no normative meaning (sep 2.0.4 declares
// none of them).
type ExtendedDERControlBase struct {
	// ── sep 2.0.4 DERControlBase, in schema sequence ─────────────────────────
	OpModConnect  *bool `xml:"opModConnect,omitempty"`  // xsd:3694
	OpModEnergize *bool `xml:"opModEnergize,omitempty"` // xsd:3699
	// xsd:3704 declares ONE element here, opModFixedPF, typed PowerFactor. This
	// package implements the opModFixedPFAbsorbW / opModFixedPFInjectW pair the
	// product is built and certified against — a divergence that predates this
	// work and is recorded, not resolved, here (see
	// TestDERControlBaseMatchesXSDElementSet's wantMissing/wantExtra). They
	// occupy opModFixedPF's sequence slot, which is where a reader looking for
	// the fixed-PF function expects to find it.
	OpModFixedPFAbsorbW *SignedPerCent `xml:"opModFixedPFAbsorbW,omitempty"`
	OpModFixedPFInjectW *SignedPerCent `xml:"opModFixedPFInjectW,omitempty"`
	OpModFixedVar       *FixedVar      `xml:"opModFixedVar,omitempty"` // xsd:3709
	OpModFixedW         *SignedPerCent `xml:"opModFixedW,omitempty"`   // xsd:3714. SignedPerCent, not watts — IW13-001. Sign selects reference: + = %setMaxW/%setMaxDischargeRateW, - = %setMaxChargeRateW.
	// Frequency droop (inline parameters, not a curve link) — xsd:3719, and
	// alphabetically ahead of opModFreqWatt, which is why it is here rather
	// than at the end of the struct where it used to sit.
	OpModFreqDroop *FreqDroop `xml:"opModFreqDroop,omitempty"`
	// Frequency-Watt — droop-based frequency regulation (§10.10.4.3) — xsd:3724.
	OpModFreqWatt               *CurveLink     `xml:"opModFreqWatt,omitempty"`
	OpModHFRTMustTrip           *CurveLink     `xml:"opModHFRTMustTrip,omitempty"`           // xsd:3729
	OpModHVRTMomentaryCessation *CurveLink     `xml:"opModHVRTMomentaryCessation,omitempty"` // xsd:3734
	OpModHVRTMustTrip           *CurveLink     `xml:"opModHVRTMustTrip,omitempty"`           // xsd:3739
	OpModLFRTMustTrip           *CurveLink     `xml:"opModLFRTMustTrip,omitempty"`           // xsd:3744
	OpModLVRTMomentaryCessation *CurveLink     `xml:"opModLVRTMomentaryCessation,omitempty"` // xsd:3749
	OpModLVRTMustTrip           *CurveLink     `xml:"opModLVRTMustTrip,omitempty"`           // xsd:3754
	OpModMaxLimW                *PerCent       `xml:"opModMaxLimW,omitempty"`                // xsd:3759. PerCent of setMaxW, not watts — IW13-001.
	OpModTargetVar              *ReactivePower `xml:"opModTargetVar,omitempty"`              // xsd:3764
	OpModTargetW                *ActivePower   `xml:"opModTargetW,omitempty"`                // xsd:3769 — nested ActivePower, watts (§1.1)
	// Dynamic Volt-VAr — anti-islanding baseline mode (§10.10.4.2) — xsd:3774.
	OpModVoltVar *CurveLink `xml:"opModVoltVar,omitempty"`
	// Volt-Watt — ramp real power output as a function of voltage (§10.10.4.4) — xsd:3779.
	OpModVoltWatt *CurveLink `xml:"opModVoltWatt,omitempty"`
	// Watt-PF — power-factor as a function of real power output (§10.10.4.5) — xsd:3784.
	OpModWattPF *CurveLink `xml:"opModWattPF,omitempty"`
	// Watt-Var — reactive power as a function of real power output — xsd:3789.
	// Present in sep 2.0.4's DERControlBase (type DERCurveLink) and in
	// DERControlType at bit 21, with its own DERCurveType code (10).
	//
	// ADDED 2026-08-14 (R4c): it was previously absent from this struct
	// entirely, so a server that sent opModWattVar had it silently DISCARDED at
	// decode — the control looked, to everything downstream, like a control that
	// commanded nothing on that axis.
	OpModWattVar *CurveLink `xml:"opModWattVar,omitempty"`
	RampTms      *uint16    `xml:"rampTms,omitempty"` // xsd:3794 — the schema's last element

	// ── NOT IN sep 2.0.4 — everything below this line ────────────────────────
	//
	// The four opMod*MayTrip links: the schema's DERControlBase carries only
	// MustTrip and MomentaryCessation links, and the string "MayTrip" does not
	// occur anywhere in it. They are kept because removing them would break
	// consumers that enumerate the link set (lexa-gw's advaxis/fanOutClasses —
	// registry IW15-020 tracks their retirement), and they are harmless on
	// decode: a conformant server never sends them, so they simply stay nil.
	// Nothing may treat their presence as evidence of anything, and nothing
	// should MARSHAL them.
	OpModHFRTMayTrip *CurveLink `xml:"opModHFRTMayTrip,omitempty"`
	OpModHVRTMayTrip *CurveLink `xml:"opModHVRTMayTrip,omitempty"`
	OpModLFRTMayTrip *CurveLink `xml:"opModLFRTMayTrip,omitempty"`
	OpModLVRTMayTrip *CurveLink `xml:"opModLVRTMayTrip,omitempty"`

	// ExpLimW/GenLimW/ImpLimW/LoadLimW are NOT IEEE 2030.5 core elements:
	// verified ABSENT from sep.xsd 2.0.4 on 2026-08-13 (IW14 review — this
	// supersedes the earlier "no XSD on this machine" caveat). They match the
	// CSIP-Aus dynamic-operating-envelope extension quartet, which types them
	// ActivePower (watts) as here. The governing extension schema is not in
	// the local standards corpus — confirm against it before any conformance
	// claim on these axes. See docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1.2.
	// DERControlType has no bit for any of them either, so they cannot be
	// advertised in modesSupported (see ModeBit).
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

	// Type: 0=unknown, 1=virtual/mixed, 2=reciprocating engine, 80=PV, 81=wind,
	// 82=running CHP, 83=storage, 84=electric vehicle, 85=EVSE, 86=combined PV+storage.
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
