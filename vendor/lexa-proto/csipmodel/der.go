// This file extends the csipmodel package (see resources.go for the package
// doc comment and the XML-namespace invariant) with the full IEEE 2030.5 DER
// function set: DERControlBase (all operating modes, including curve-linked
// ride-through and inverter control modes), DERCurve, DERAvailability, and
// expanded DERCapability / DERStatus as specified in IEEE 2030.5-2018 §10.10.
package csipmodel

import "encoding/xml"

// ─── Operating-mode bitmask constants (DERCapability.ModesSupported) ──────────
//
// A DER device sets the corresponding bit to advertise support for each mode.
//
// RECORDED DIVERGENCE — these bit positions do NOT match sep 2.0.4 (R4b's
// sibling, deliberately NOT fixed here). The vendored schema
// (docs/schema/sep-2.0.4.xsd, complexType "DERControlType") assigns:
//
//	0 opModVoltVar   1 opModFreqWatt  2 opModFreqDroop  3 opModWattPF
//	4 opModVoltWatt  5 LVRTMomCess    6 LVRTMustTrip    7 HVRTMomCess
//	8 HVRTMustTrip   9 LFRTMustTrip  10 HFRTMustTrip   11 opModConnect
//	12 opModEnergize 13 opModMaxLimW 14 opModFixedVar  15 opModFixedPF
//	16 opModFixedW   17 opModTargetW 18 opModTargetVar 19 Charge
//	20 Discharge     21 opModWattVar
//
// The table below is a different assignment entirely, and — unlike the
// DERCurveType codes, which are only ever read FROM the wire — this one is
// WRITTEN to the wire: derproducer publishes ModesSupported from it, so
// correcting it changes what the gateway advertises to a utility server and has
// to move together with the PICS, the harness expectations and the
// per-generation capability work. That is scheduled as its own stage
// (LEGACY_CURVES_RC0_2026-08-14 §10 stage 9, "modesSupported truth"); changing
// it here would advertise a different mask than the product can honour.
const (
	ModeConnect                uint32 = 1 << 0  // opModConnect / opModEnergize
	ModeMaxLimW                uint32 = 1 << 1  // opModMaxLimW
	ModeFixedW                 uint32 = 1 << 2  // opModFixedW
	ModeFixedVar               uint32 = 1 << 3  // opModFixedVar
	ModeFixedPFAbsorb          uint32 = 1 << 4  // opModFixedPFAbsorbW
	ModeFixedPFInject          uint32 = 1 << 5  // opModFixedPFInjectW
	ModeVoltVar                uint32 = 1 << 6  // opModVoltVar (dynamic Volt-VAr)
	ModeFreqWatt               uint32 = 1 << 7  // opModFreqWatt (Freq-Watt)
	ModeWattPF                 uint32 = 1 << 8  // opModWattPF (Watt-PF)
	ModeVoltWatt               uint32 = 1 << 9  // opModVoltWatt (Volt-Watt)
	ModeHFRTMayTrip            uint32 = 1 << 10 // opModHFRTMayTrip
	ModeHFRTMustTrip           uint32 = 1 << 11 // opModHFRTMustTrip
	ModeHVRTMayTrip            uint32 = 1 << 12 // opModHVRTMayTrip
	ModeHVRTMomentaryCessation uint32 = 1 << 13 // opModHVRTMomentaryCessation
	ModeHVRTMustTrip           uint32 = 1 << 14 // opModHVRTMustTrip
	ModeLFRTMayTrip            uint32 = 1 << 15 // opModLFRTMayTrip
	ModeLFRTMustTrip           uint32 = 1 << 16 // opModLFRTMustTrip
	ModeLVRTMayTrip            uint32 = 1 << 17 // opModLVRTMayTrip
	ModeLVRTMomentaryCessation uint32 = 1 << 18 // opModLVRTMomentaryCessation
	ModeLVRTMustTrip           uint32 = 1 << 19 // opModLVRTMustTrip
	ModeFreqDroop              uint32 = 1 << 20 // opModFreqDroop
	ModeTargetW                uint32 = 1 << 21 // opModTargetW
	ModeTargetVar              uint32 = 1 << 22 // opModTargetVar
	ModeExpLimW                uint32 = 1 << 23 // opModExpLimW
	ModeImpLimW                uint32 = 1 << 24 // opModImpLimW
	ModeGenLimW                uint32 = 1 << 25 // opModGenLimW
	ModeLoadLimW               uint32 = 1 << 26 // opModLoadLimW
)

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
type DERCurve struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCurve"`
	Resource

	MRID         string `xml:"mRID,omitempty"`
	Description  string `xml:"description,omitempty"`
	Version      uint16 `xml:"version,omitempty"`
	CreationTime int64  `xml:"creationTime,omitempty"`

	// CurveType identifies what this curve represents (see CurveType* constants).
	CurveType uint16 `xml:"curveType"`

	// CurveData is the ordered list of (x,y) breakpoints.
	CurveData []DERCurveData `xml:"CurveData,omitempty"`

	// AutonomousVRefEnable: when true (for Volt-VAr), the device computes its own
	// voltage reference. Enabling this implicitly enables autonomous anti-islanding.
	AutonomousVRefEnable *bool `xml:"autonomousVRefEnable,omitempty"`
	// AutonomousVRefTimeConstant is the filtering time constant (seconds) for the
	// autonomous voltage reference (Volt-VAr curves only).
	AutonomousVRefTimeConstant *uint32 `xml:"autonomousVRefTimeConstant,omitempty"`

	// OpenLoopTms: time (in hundredths of a second) to reach 90 % of the
	// commanded output. Applies to VoltVar and VoltWatt modes.
	OpenLoopTms *uint16 `xml:"openLoopTms,omitempty"`

	// Ramp timing — all in hundredths of a second.
	RampDecTms *uint16 `xml:"rampDecTms,omitempty"` // output decrease ramp time
	RampIncTms *uint16 `xml:"rampIncTms,omitempty"` // output increase ramp time
	RampPT1Tms *uint16 `xml:"rampPT1Tms,omitempty"` // first-order lag time constant

	// Axis multipliers: apply 10^multiplier to all x or y values.
	XMultiplier int8 `xml:"xMultiplier,omitempty"`
	YMultiplier int8 `xml:"yMultiplier,omitempty"`

	// VRef: nominal AC voltage reference in V for VoltVar / VoltWatt curves.
	VRef *int16 `xml:"vRef,omitempty"`

	// XRefType / YRefType indicate the physical quantity on each axis (Table 19).
	XRefType uint8 `xml:"xRefType,omitempty"`
	YRefType uint8 `xml:"yRefType,omitempty"`
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
// XML element names match the 2030.5 schema exactly (case-sensitive).
type ExtendedDERControlBase struct {
	// ── Scalar modes ─────────────────────────────────────────────────────────
	OpModConnect        *bool          `xml:"opModConnect,omitempty"`
	OpModEnergize       *bool          `xml:"opModEnergize,omitempty"`
	OpModFixedPFAbsorbW *SignedPerCent `xml:"opModFixedPFAbsorbW,omitempty"`
	OpModFixedPFInjectW *SignedPerCent `xml:"opModFixedPFInjectW,omitempty"`
	OpModFixedVar       *FixedVar      `xml:"opModFixedVar,omitempty"`
	OpModFixedW         *SignedPerCent `xml:"opModFixedW,omitempty"`  // SignedPerCent, not watts — IW13-001. Sign selects reference: + = %setMaxW/%setMaxDischargeRateW, - = %setMaxChargeRateW.
	OpModMaxLimW        *PerCent       `xml:"opModMaxLimW,omitempty"` // PerCent of setMaxW, not watts — IW13-001.
	// ExpLimW/GenLimW/ImpLimW/LoadLimW are NOT IEEE 2030.5 core elements:
	// verified ABSENT from sep.xsd 2.0.4 on 2026-08-13 (IW14 review — this
	// supersedes the earlier "no XSD on this machine" caveat). They match the
	// CSIP-Aus dynamic-operating-envelope extension quartet, which types them
	// ActivePower (watts) as here. The governing extension schema is not in
	// the local standards corpus — confirm against it before any conformance
	// claim on these axes. See docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1.2.
	OpModExpLimW   *ActivePower   `xml:"opModExpLimW,omitempty"`
	OpModGenLimW   *ActivePower   `xml:"opModGenLimW,omitempty"`
	OpModImpLimW   *ActivePower   `xml:"opModImpLimW,omitempty"`
	OpModLoadLimW  *ActivePower   `xml:"opModLoadLimW,omitempty"`
	OpModTargetW   *ActivePower   `xml:"opModTargetW,omitempty"` // already correct — nested ActivePower, watts (§1.1)
	OpModTargetVar *ReactivePower `xml:"opModTargetVar,omitempty"`
	RampTms        *uint16        `xml:"rampTms,omitempty"`

	// ── Curve-linked modes — each holds an href to a DERCurve ────────────────
	// Dynamic Volt-VAr — anti-islanding baseline mode (§10.10.4.2).
	OpModVoltVar *CurveLink `xml:"opModVoltVar,omitempty"`
	// Frequency-Watt — droop-based frequency regulation (§10.10.4.3).
	OpModFreqWatt *CurveLink `xml:"opModFreqWatt,omitempty"`
	// Watt-PF — power-factor as a function of real power output (§10.10.4.5).
	OpModWattPF *CurveLink `xml:"opModWattPF,omitempty"`
	// Volt-Watt — ramp real power output as a function of voltage (§10.10.4.4).
	OpModVoltWatt *CurveLink `xml:"opModVoltWatt,omitempty"`
	// Watt-Var — reactive power as a function of real power output. Present in
	// sep 2.0.4's DERControlBase (type DERCurveLink) and in DERControlType at
	// bit 21, with its own DERCurveType code (10).
	//
	// ADDED 2026-08-14 (R4c): it was previously absent from this struct
	// entirely, so a server that sent opModWattVar had it silently DISCARDED at
	// decode — the control looked, to everything downstream, like a control that
	// commanded nothing on that axis.
	OpModWattVar *CurveLink `xml:"opModWattVar,omitempty"`

	// High-frequency ride-through curves.
	//
	// NOTE on the four opMod*MayTrip fields below: they are NOT in sep 2.0.4.
	// The schema's DERControlBase carries only MustTrip and MomentaryCessation
	// links, and the string "MayTrip" does not occur anywhere in it. They are
	// kept because removing them would break consumers that enumerate the link
	// set, and they are harmless on decode — a conformant server never sends
	// them, so they simply stay nil. Nothing may treat their presence as
	// evidence of anything, and nothing should MARSHAL them.
	OpModHFRTMayTrip  *CurveLink `xml:"opModHFRTMayTrip,omitempty"`
	OpModHFRTMustTrip *CurveLink `xml:"opModHFRTMustTrip,omitempty"`
	// High-voltage ride-through curves.
	OpModHVRTMayTrip            *CurveLink `xml:"opModHVRTMayTrip,omitempty"`
	OpModHVRTMomentaryCessation *CurveLink `xml:"opModHVRTMomentaryCessation,omitempty"`
	OpModHVRTMustTrip           *CurveLink `xml:"opModHVRTMustTrip,omitempty"`
	// Low-frequency ride-through curves.
	OpModLFRTMayTrip  *CurveLink `xml:"opModLFRTMayTrip,omitempty"`
	OpModLFRTMustTrip *CurveLink `xml:"opModLFRTMustTrip,omitempty"`
	// Low-voltage ride-through curves.
	OpModLVRTMayTrip            *CurveLink `xml:"opModLVRTMayTrip,omitempty"`
	OpModLVRTMomentaryCessation *CurveLink `xml:"opModLVRTMomentaryCessation,omitempty"`
	OpModLVRTMustTrip           *CurveLink `xml:"opModLVRTMustTrip,omitempty"`

	// ── Frequency droop (inline, not a curve link) ────────────────────────────
	OpModFreqDroop *FreqDroop `xml:"opModFreqDroop,omitempty"`
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
	ModesSupported uint32 `xml:"modesSupported"`

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
