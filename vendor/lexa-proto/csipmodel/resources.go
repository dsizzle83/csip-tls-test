// Package csipmodel defines Go structs for the IEEE 2030.5 / CSIP XML data
// model — the wire-format types both lexa-hub (client-side unmarshal) and
// csip-tls-test's gridsim (server-side marshal) work from (TASK-023). This is
// the data model only: walkers, schedulers, identity, and DNS-SD stay
// repo-local forks that merely import this package.
//
// Every struct uses XML tags that match the 2030.5 schema exactly,
// including the mandatory namespace urn:ieee:std:2030.5:ns.
// The inheritance hierarchy in the XSD (Resource → IdentifiedObject →
// SubscribableResource, etc.) is flattened into Go structs with embedded
// fields, because Go's encoding/xml handles embedded struct tags correctly.
//
// Only the resource types required by a CSIP DER client (and the gridsim
// that serves them) are defined here. Prepayment and messaging function
// sets are out of scope.
//
// CRITICAL — silent-failure hazard: a 2030.5 root element unmarshalled
// without its namespace (urn:ieee:std:2030.5:ns) decodes to a zero-value
// struct with NO error from encoding/xml. Every root element below carries
// an explicit `xml:"urn:ieee:std:2030.5:ns <Name>"` XMLName tag for exactly
// this reason — never add a root element type without one, and never edit
// an existing tag without re-running the round-trip suite in
// resources_test.go plus both consumers' conformance suites.
package csipmodel

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// XMLNamespace is the IEEE 2030.5 XML namespace required on all root elements.
const XMLNamespace = "urn:ieee:std:2030.5:ns"

// ───────────────────────────────────────────────────────────────────────
// Base types — these model the XSD inheritance chain
// ───────────────────────────────────────────────────────────────────────

// Link is the base type for all link elements (EndDeviceListLink, TimeLink, etc.).
// In the XSD every *Link type has an href attribute.
type Link struct {
	Href string `xml:"href,attr"`
}

// ListLink extends Link with an "all" attribute indicating the total
// number of items in the referenced list.
type ListLink struct {
	Link
	All uint32 `xml:"all,attr,omitempty"`
}

// Resource is the base of most 2030.5 types — it carries an href.
type Resource struct {
	Href string `xml:"href,attr,omitempty"`
}

// ResponseRequired is the IEEE 2030.5 Event-base `responseRequired` bitmap
// (XSD type hexBinary8), carried as an XML attribute on Event-derived
// resources such as DERControl. It tells the client which Response
// acknowledgements the server wants for that event (Table 27 / §D.2.2
// RespondableResource semantics):
//
//	bit 0 (0x01) — the client shall POST a Response indicating the event
//	               message was received;
//	bit 1 (0x02) — the client shall POST a Response with the specific
//	               outcome (started/completed/etc.);
//	bit 2 (0x04) — end-user / customer response is required.
//
// A value of 0 means the server explicitly wants NO Response. On DERControl
// this is modelled as a *pointer* so a consumer can distinguish "attribute
// absent" (nil — no server instruction, keep the consumer's default
// behaviour) from "attribute present and zero" (an explicit request for
// silence). Added additively for audit CSIP-004 (replyTo/responseRequired
// were dropped at parse time); absent on the wire ⇒ nil ⇒ byte-identical
// round-trips, so lexa-hub and gridsim are unaffected until they populate it.
type ResponseRequired uint8

// responseRequired bit flags (IEEE 2030.5 RespondableResource).
const (
	RespReqMessageReceived  ResponseRequired = 1 << 0 // 0x01
	RespReqSpecificResponse ResponseRequired = 1 << 1 // 0x02
	RespReqCustomerResponse ResponseRequired = 1 << 2 // 0x04
)

// UnmarshalXMLAttr decodes the hexBinary8 attribute (e.g. "03") into the
// bitmap. Accepts upper- or lower-case hex; a malformed or out-of-range
// (>0xFF) value is an error so a corrupt control is rejected rather than
// silently misread — mirroring the package's XML silent-failure discipline.
func (r *ResponseRequired) UnmarshalXMLAttr(attr xml.Attr) error {
	v, err := strconv.ParseUint(strings.TrimSpace(attr.Value), 16, 8)
	if err != nil {
		return fmt.Errorf("csipmodel: responseRequired %q: %w", attr.Value, err)
	}
	*r = ResponseRequired(v)
	return nil
}

// MarshalXMLAttr encodes the bitmap back to a two-digit hexBinary8 attribute
// (uppercase, matching the 2030.5 example encodings). Value receiver so a
// *ResponseRequired struct field marshals correctly; a nil pointer field is
// omitted by encoding/xml before this is ever reached (attr,omitempty).
func (r ResponseRequired) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	return xml.Attr{Name: name, Value: fmt.Sprintf("%02X", uint8(r))}, nil
}

// ─── hexBinary ELEMENTS ───────────────────────────────────────────────────────
//
// ResponseRequired above is a hexBinary8 ATTRIBUTE and has always encoded
// correctly. The hexBinary ELEMENTS did not: they were declared as plain Go
// integers, and Go's encoding/xml writes an integer in DECIMAL. Added
// 2026-08-15 (legacy Stage 9), found by the independent bit-position oracle
// while it was grading the modesSupported mask this wave makes truthful.
//
// WHY IT MATTERS, and it is not cosmetic. sep 2.0.4 types several bitmap
// elements as HexBinary8/16/32 (xsd:6034-6089), each documented as "a N-bit
// field encoded as a hex string ... bit 0, or the least significant bit, goes
// on the right". For a value whose decimal rendering happens to contain only
// the digits 0-9, BOTH readings parse and they are DIFFERENT numbers:
//
//	<modesSupported>8192</modesSupported>
//	  decimal 8192 = 0x2000 -> bit 13 (opModMaxLimW)
//	  hex     8192          -> bits 1, 4, 7, 8, 15 (five completely different modes)
//
// So a decimal-encoded mask is not merely non-canonical — it is a document that
// says something the writer did not mean, with no way for a reader to tell.
// Nothing detects it either: both ends of an all-decimal-digit string agree
// that it parsed.
//
// THE ENCODING: uppercase, ZERO-PADDED to the type's full width. Padding is a
// deliberate choice beyond validity (xs:hexBinary only requires an even digit
// count): a full-width mask is unambiguous on inspection, and it is what makes
// a conformance grader able to PASS the value rather than flag it as ambiguous.
// Uppercase matches ResponseRequired and the 2030.5 example encodings.
//
// THE DECODE IS STRICTLY HEX, and that is the only defensible reading: the
// schema says hexBinary, so "20" is 32 and not 20. A lenient "try decimal too"
// decode cannot help — for exactly the strings where the ambiguity exists, both
// parses succeed — and would silently pick the wrong one for the rest. A
// malformed or over-wide value is an ERROR rather than a zero, mirroring
// ResponseRequired and this package's silent-failure discipline (see the
// package doc): a corrupt capability bitmap must not decode to "supports
// nothing".
//
// WIRE COMPATIBILITY, adjudicated rather than assumed: the only one of these
// this product has ever EMITTED is modesSupported, and derproducer hardcoded it
// to 0 until this same wave — and 0 reads identically under both conventions.
// There is no deployed decimal mask to be compatible with.

// HexBinary32 is a 32-bit bitmap element encoded as sep 2.0.4's HexBinary32
// (xsd:6050): eight uppercase hex digits, zero-padded, least-significant bit on
// the right. DERControlType (modesSupported / modesEnabled) is its extension.
type HexBinary32 uint32

// MarshalXML writes the value as eight zero-padded uppercase hex digits.
func (h HexBinary32) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(fmt.Sprintf("%08X", uint32(h)), start)
}

// UnmarshalXML parses a hexBinary32 element. Strictly hex; whitespace-trimmed;
// an unparsable or >32-bit value is an error.
func (h *HexBinary32) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		*h = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return fmt.Errorf("csipmodel: %s is a hexBinary32 and %q is not one: %w", start.Name.Local, s, err)
	}
	*h = HexBinary32(v)
	return nil
}

// HexBinary16 is a 16-bit bitmap element encoded as sep 2.0.4's HexBinary16
// (xsd:6042): four uppercase hex digits, zero-padded. RoleFlagsType is its
// extension; localID and qualityFlags are typed with it directly.
type HexBinary16 uint16

// MarshalXML writes the value as four zero-padded uppercase hex digits.
func (h HexBinary16) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(fmt.Sprintf("%04X", uint16(h)), start)
}

// UnmarshalXML parses a hexBinary16 element. Strictly hex; see HexBinary32.
func (h *HexBinary16) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		*h = 0
		return nil
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return fmt.Errorf("csipmodel: %s is a hexBinary16 and %q is not one: %w", start.Name.Local, s, err)
	}
	*h = HexBinary16(v)
	return nil
}

// ───────────────────────────────────────────────────────────────────────
// DeviceCapability — the root of the resource tree (GET /dcap)
// ───────────────────────────────────────────────────────────────────────

// DeviceCapability is returned by the server at the well-known /dcap URI.
// It is the entry point for all resource discovery. The client reads the
// link elements to find where EndDeviceList, Time, etc. live.
type DeviceCapability struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DeviceCapability"`
	Resource

	// PollRate is the default polling interval for this function set, in seconds.
	// If omitted the spec default is 900 (15 min).
	PollRate uint32 `xml:"pollRate,attr,omitempty"`

	// Links inherited from FunctionSetAssignmentsBase
	DERProgramListLink    *ListLink `xml:"DERProgramListLink,omitempty"`
	TimeLink              *Link     `xml:"TimeLink,omitempty"`
	ResponseSetListLink   *ListLink `xml:"ResponseSetListLink,omitempty"`
	TariffProfileListLink *ListLink `xml:"TariffProfileListLink,omitempty"`

	// DeviceCapability-specific links
	EndDeviceListLink        *ListLink `xml:"EndDeviceListLink,omitempty"`
	MirrorUsagePointListLink *ListLink `xml:"MirrorUsagePointListLink,omitempty"`
	SelfDeviceLink           *Link     `xml:"SelfDeviceLink,omitempty"`
}

// ───────────────────────────────────────────────────────────────────────
// Time
// ───────────────────────────────────────────────────────────────────────

// Time is the server's current time resource. CSIP clients must
// synchronize to the server's time for event scheduling.
type Time struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns Time"`
	Resource

	// CurrentTime is seconds since Unix epoch (2030.5 uses Unix time).
	CurrentTime int64 `xml:"currentTime"`

	// DstEndTime is the end of DST in Unix time.
	DstEndTime int64 `xml:"dstEndTime"`

	// DstOffset is the DST offset in seconds.
	DstOffset int32 `xml:"dstOffset"`

	// TzOffset is the timezone offset from UTC in seconds.
	TzOffset int32 `xml:"tzOffset"`

	// Quality describes the clock source quality.
	Quality uint8 `xml:"quality,omitempty"`

	PollRate uint32 `xml:"pollRate,attr,omitempty"`
}

// ───────────────────────────────────────────────────────────────────────
// EndDevice and EndDeviceList
// ───────────────────────────────────────────────────────────────────────

// EndDevice represents a single DER device registered with the server.
// The client finds itself in the EndDeviceList by matching its LFDI.
type EndDevice struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns EndDevice"`
	Resource

	// Subscribable indicates subscription support. 0=none, 1=non-conditional, 3=conditional.
	Subscribable uint8 `xml:"subscribable,attr,omitempty"`

	// LFDI is the Long-Form Device Identifier (hex-encoded, 40 chars).
	LFDI string `xml:"lFDI,omitempty"`

	// SFDI is the Short-Form Device Identifier (decimal, up to 10 digits).
	SFDI uint64 `xml:"sFDI,omitempty"`

	// ChangedTime is the last-modified timestamp.
	ChangedTime int64 `xml:"changedTime,omitempty"`

	// Enabled indicates whether the device is enabled by the server.
	Enabled *bool `xml:"enabled,omitempty"`

	// Links to subordinate resources
	DERListLink                     *ListLink `xml:"DERListLink,omitempty"`
	FunctionSetAssignmentsListLink  *ListLink `xml:"FunctionSetAssignmentsListLink,omitempty"`
	RegistrationLink                *Link     `xml:"RegistrationLink,omitempty"`
	LogEventListLink                *ListLink `xml:"LogEventListLink,omitempty"`
	FlowReservationRequestListLink  *ListLink `xml:"FlowReservationRequestListLink,omitempty"`
	FlowReservationResponseListLink *ListLink `xml:"FlowReservationResponseListLink,omitempty"`
}

// EndDeviceList is a collection of EndDevice resources.
type EndDeviceList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns EndDeviceList"`
	Resource

	All       uint32      `xml:"all,attr"`
	Results   uint32      `xml:"results,attr"`
	PollRate  uint32      `xml:"pollRate,attr,omitempty"`
	EndDevice []EndDevice `xml:"EndDevice"`
}

// ───────────────────────────────────────────────────────────────────────
// Registration
// ───────────────────────────────────────────────────────────────────────

// Registration holds the registration info for an EndDevice, including the PIN.
type Registration struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns Registration"`
	Resource

	DateTimeRegistered int64  `xml:"dateTimeRegistered"`
	PIN                uint32 `xml:"pIN"`
}

// ───────────────────────────────────────────────────────────────────────
// FunctionSetAssignments (FSA)
// ───────────────────────────────────────────────────────────────────────

// FunctionSetAssignments groups a set of programs assigned to a device.
// Each EndDevice has a FunctionSetAssignmentsListLink pointing to its FSAs.
type FunctionSetAssignments struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns FunctionSetAssignments"`
	Resource

	// Subscribable indicates subscription support.
	Subscribable uint8 `xml:"subscribable,attr,omitempty"`

	// Links to assigned function set resource lists.
	DERProgramListLink      *ListLink `xml:"DERProgramListLink,omitempty"`
	TimeLink                *Link     `xml:"TimeLink,omitempty"`
	TariffProfileListLink   *ListLink `xml:"TariffProfileListLink,omitempty"`
	CustomerAccountListLink *ListLink `xml:"CustomerAccountListLink,omitempty"`
	MRID                    string    `xml:"mRID,omitempty"`
	Description             string    `xml:"description,omitempty"`
	Version                 uint16    `xml:"version,omitempty"`
}

// FunctionSetAssignmentsList is a collection of FSA resources.
type FunctionSetAssignmentsList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns FunctionSetAssignmentsList"`
	Resource

	All                    uint32                   `xml:"all,attr"`
	Results                uint32                   `xml:"results,attr"`
	PollRate               uint32                   `xml:"pollRate,attr,omitempty"`
	FunctionSetAssignments []FunctionSetAssignments `xml:"FunctionSetAssignments"`
}

// ───────────────────────────────────────────────────────────────────────
// DERProgram
// ───────────────────────────────────────────────────────────────────────

// DERProgram represents a utility's DER management program.
// It contains links to control lists, default controls, and curves.
type DERProgram struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERProgram"`
	Resource

	// Subscribable indicates subscription support.
	Subscribable uint8 `xml:"subscribable,attr,omitempty"`

	MRID        string `xml:"mRID,omitempty"`
	Description string `xml:"description,omitempty"`
	Version     uint16 `xml:"version,omitempty"`

	// Primacy determines which program's controls take priority.
	// Lower value = higher priority. CSIP requires this.
	Primacy uint8 `xml:"primacy"`

	// Links to subordinate resources
	DERControlListLink       *ListLink `xml:"DERControlListLink,omitempty"`
	DERCurveListLink         *ListLink `xml:"DERCurveListLink,omitempty"`
	DefaultDERControlLink    *Link     `xml:"DefaultDERControlLink,omitempty"`
	ActiveDERControlListLink *ListLink `xml:"ActiveDERControlListLink,omitempty"`
}

// DERProgramList is a collection of DERProgram resources.
type DERProgramList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERProgramList"`
	Resource

	All        uint32       `xml:"all,attr"`
	Results    uint32       `xml:"results,attr"`
	PollRate   uint32       `xml:"pollRate,attr,omitempty"`
	DERProgram []DERProgram `xml:"DERProgram"`
}

// ───────────────────────────────────────────────────────────────────────
// DERControl and DefaultDERControl
// ───────────────────────────────────────────────────────────────────────

// DateTimeInterval represents a time interval with start and duration.
type DateTimeInterval struct {
	Duration uint32 `xml:"duration"`
	Start    int64  `xml:"start"`
}

// SignedPerCent represents a signed percentage × 100 (so 50% = 5000).
type SignedPerCent struct {
	Value int16 `xml:",chardata"`
}

// ActivePower represents watts with a power-of-ten multiplier.
type ActivePower struct {
	Multiplier int8  `xml:"multiplier"`
	Value      int16 `xml:"value"`
}

// PerCent represents an unsigned percentage × 100 (hundredths), used where
// the 2030.5 XSD's PerCent type applies (opModMaxLimW). sep.xsd defines
// PerCent as extending UInt16 (xs:unsignedShort) — UNSIGNED, unlike
// SignedPerCent's Int16 — so the wire domain is [0,65535] and a negative
// chardata is a schema-layer rejection the XML decoder itself makes. The
// tighter ≤100.00% (10000) product bound is prose/table-defined (CSIP IG 2.1
// Table 9), NOT a schema facet, so it stays an application-layer rule
// enforced downstream at the decode/conversion boundary, not in this struct.
// See docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1.
type PerCent struct {
	Value uint16 `xml:",chardata"`
}

// ─── DERUnitRefType: what a percentage is a percentage OF ─────────────────────
//
// These match the DERUnitRefType enumeration in the IEEE 2030.5-2018 XSD. The
// code is NOT decoration: a percentage without its reference is not a
// quantity, and the three reactive codes name three DIFFERENT physical
// quantities on the same machine. On a 60 kW / 26.4 kvar DER, "80 %" is
// 48 000 var under RefTypeSetMaxW and 21 120 var under RefTypeSetMaxVar — a
// consumer that reads the value and drops the code is wrong for at least two
// of the three codes it could have been sent.
//
// RefTypeNA is the one code that names no reference at all. It is not a
// default and not "the usual one": it is a document that declined to say what
// it was commanding, and the only defensible answers to it are to refuse or to
// leave the device alone (see derbase.varSetModForRefType).
const (
	RefTypeNA                   uint8 = 0 // N/A — no rating nominated
	RefTypeSetMaxW              uint8 = 1 // %setMaxW — percent of the max active-power setting
	RefTypeSetMaxVar            uint8 = 2 // %setMaxVar — percent of the max reactive-power setting
	RefTypeStatVarAvail         uint8 = 3 // %statVarAvail — percent of PRESENTLY available reactive power
	RefTypeSetEffectiveV        uint8 = 4 // %setEffectiveV — percent of the effective voltage setting
	RefTypeSetMaxChargeRateW    uint8 = 5 // %setMaxChargeRateW
	RefTypeSetMaxDischargeRateW uint8 = 6 // %setMaxDischargeRateW
	RefTypeStatWAvail           uint8 = 7 // %statWAvail — percent of presently available active power
)

// FixedVar represents reactive power setting.
//
// RefType names the base Value is a percentage of (see the DERUnitRefType
// constants above) and MUST be read by any consumer that acts on Value —
// including RefTypeNA, which must be refused rather than assumed.
type FixedVar struct {
	RefType uint8         `xml:"refType"`
	Value   SignedPerCent `xml:"value"`
}

// DERControlBase contains the actual control parameters — what the DER
// should do. This is the payload of both DERControl events and the
// DefaultDERControl fallback.
// FIELD ORDER IS THE SCHEMA'S SEQUENCE (docs/schema/sep-2.0.4.xsd:3689-3799),
// for the reason spelled out on ExtendedDERControlBase in der.go: xs:sequence
// is ordered and Go emits fields in declaration order, so the layout IS the
// emitted sequence. The scalar prefix here was already in schema order; the
// 2026-08-15 correction moved the four CSIP-Aus elements — which sep 2.0.4 does
// not declare at all — from between opModMaxLimW and rampTms to AFTER rampTms,
// so the schema-declared part of the struct is contiguous and in sequence.
type DERControlBase struct {
	// ── sep 2.0.4 DERControlBase, in schema sequence ─────────────────────────
	// Each mode is optional; the server sends only what it wants to control.
	OpModConnect  *bool `xml:"opModConnect,omitempty"`  // xsd:3694
	OpModEnergize *bool `xml:"opModEnergize,omitempty"` // xsd:3699
	// xsd:3704's single opModFixedPF, implemented here as the AbsorbW/InjectW
	// pair — see ExtendedDERControlBase for the recorded divergence.
	OpModFixedPFAbsorbW *SignedPerCent `xml:"opModFixedPFAbsorbW,omitempty"`
	OpModFixedPFInjectW *SignedPerCent `xml:"opModFixedPFInjectW,omitempty"`
	OpModFixedVar       *FixedVar      `xml:"opModFixedVar,omitempty"` // xsd:3709
	OpModFixedW         *SignedPerCent `xml:"opModFixedW,omitempty"`   // xsd:3714. SignedPerCent, not watts — IW13-001. Sign selects reference: + = %setMaxW/%setMaxDischargeRateW, - = %setMaxChargeRateW.
	OpModMaxLimW        *PerCent       `xml:"opModMaxLimW,omitempty"`  // xsd:3759. PerCent of setMaxW, not watts — IW13-001.
	RampTms             *uint16        `xml:"rampTms,omitempty"`       // xsd:3794 — the schema's last element

	// ── NOT IN sep 2.0.4 ─────────────────────────────────────────────────────
	// ExpLimW/GenLimW/ImpLimW/LoadLimW are NOT IEEE 2030.5 core elements:
	// verified ABSENT from sep.xsd 2.0.4 on 2026-08-13 (IW14 review — this
	// supersedes the earlier "no XSD on this machine" caveat). They match the
	// CSIP-Aus dynamic-operating-envelope extension quartet, which types them
	// ActivePower (watts) as here. The governing extension schema is not in
	// the local standards corpus — confirm against it before any conformance
	// claim on these axes. See docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1.2.
	OpModExpLimW  *ActivePower `xml:"opModExpLimW,omitempty"`
	OpModGenLimW  *ActivePower `xml:"opModGenLimW,omitempty"`
	OpModImpLimW  *ActivePower `xml:"opModImpLimW,omitempty"`
	OpModLoadLimW *ActivePower `xml:"opModLoadLimW,omitempty"`
}

// EventStatus describes the current state of an event.
type EventStatus struct {
	CurrentStatus         uint8 `xml:"currentStatus"`
	DateTime              int64 `xml:"dateTime"`
	PotentiallySuperseded bool  `xml:"potentiallySuperseded"`
}

// DERControl is a time-bound control event within a DERProgram.
// This is the main thing your client acts on.
type DERControl struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERControl"`
	Resource

	// ReplyTo and ResponseRequired are the IEEE 2030.5 Event-base
	// (RespondableResource) addressing/requirement attributes. Before audit
	// CSIP-004 they were dropped at parse time, so a Response could not be
	// routed to the server's own reply URI nor gated by its stated
	// requirement. Both are additive and omitempty: a wire DERControl without
	// them round-trips byte-identically.
	//
	// ReplyTo is the href the client should POST Response objects for THIS
	// event to, overriding the default ResponseSet. Empty ⇒ absent ⇒ the
	// consumer falls back to its configured/advertised default response set.
	ReplyTo string `xml:"replyTo,attr,omitempty"`
	// ResponseRequired is the responseRequired bitmap (hexBinary8). nil ⇒
	// absent ⇒ no server instruction (consumer keeps its default). Present
	// and zero ⇒ the server explicitly requests no Response for this event.
	ResponseRequired *ResponseRequired `xml:"responseRequired,attr,omitempty"`

	MRID           string           `xml:"mRID,omitempty"`
	Description    string           `xml:"description,omitempty"`
	Version        uint16           `xml:"version,omitempty"`
	CreationTime   int64            `xml:"creationTime,omitempty"`
	EventStatus    *EventStatus     `xml:"EventStatus,omitempty"`
	Interval       DateTimeInterval `xml:"interval"`
	DERControlBase DERControlBase   `xml:"DERControlBase"`

	// Randomize fields for staggering device responses
	RandomizeStart    *int32 `xml:"randomizeStart,omitempty"`
	RandomizeDuration *int32 `xml:"randomizeDuration,omitempty"`
}

// DERControlList is a collection of DERControl events.
type DERControlList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERControlList"`
	Resource

	All        uint32       `xml:"all,attr"`
	Results    uint32       `xml:"results,attr"`
	PollRate   uint32       `xml:"pollRate,attr,omitempty"`
	DERControl []DERControl `xml:"DERControl"`
}

// DefaultDERControl is the fallback control that applies when no active
// DERControl event is in effect. Critical safety mechanism — prevents
// uncontrolled operation if comms are lost.
type DefaultDERControl struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DefaultDERControl"`
	Resource

	MRID           string         `xml:"mRID,omitempty"`
	Description    string         `xml:"description,omitempty"`
	Version        uint16         `xml:"version,omitempty"`
	DERControlBase DERControlBase `xml:"DERControlBase"`
}

// ───────────────────────────────────────────────────────────────────────
// DER resource (device-level DER info)
// ───────────────────────────────────────────────────────────────────────

// DER represents a logical DER associated with an EndDevice.
type DER struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DER"`
	Resource

	DERCapabilityLink   *Link `xml:"DERCapabilityLink,omitempty"`
	DERSettingsLink     *Link `xml:"DERSettingsLink,omitempty"`
	DERStatusLink       *Link `xml:"DERStatusLink,omitempty"`
	DERAvailabilityLink *Link `xml:"DERAvailabilityLink,omitempty"`
}

// DERList is a collection of DER resources.
type DERList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERList"`
	Resource

	All     uint32 `xml:"all,attr"`
	Results uint32 `xml:"results,attr"`
	DER     []DER  `xml:"DER"`
}

// ───────────────────────────────────────────────────────────────────────
// MirrorUsagePoint (telemetry)
// ───────────────────────────────────────────────────────────────────────

// MirrorUsagePoint is used by the client to POST telemetry readings
// back to the utility server.
type MirrorUsagePoint struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns MirrorUsagePoint"`
	Resource

	MRID                string      `xml:"mRID,omitempty"`
	Description         string      `xml:"description,omitempty"`
	RoleFlags           HexBinary16 `xml:"roleFlags,omitempty"` // RoleFlagsType = HexBinary16 (xsd)
	ServiceCategoryKind uint8       `xml:"serviceCategoryKind,omitempty"`
	Status              uint8       `xml:"status,omitempty"`
	DeviceLFDI          string      `xml:"deviceLFDI,omitempty"`
	PostRate            uint32      `xml:"postRate,omitempty"`
}

// MirrorUsagePointList is a collection of MirrorUsagePoint resources.
type MirrorUsagePointList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns MirrorUsagePointList"`
	Resource

	All              uint32             `xml:"all,attr"`
	Results          uint32             `xml:"results,attr"`
	PollRate         uint32             `xml:"pollRate,attr,omitempty"`
	MirrorUsagePoint []MirrorUsagePoint `xml:"MirrorUsagePoint"`
}

// ───────────────────────────────────────────────────────────────────────
// MirrorMeterReading (telemetry POST payload)
// ───────────────────────────────────────────────────────────────────────

// ReadingType describes the measurement commodity, units, and accumulation
// behaviour of a set of readings. IEEE 2030.5 table 22.
type ReadingType struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns ReadingType"`
	Resource

	AccumulationBehaviour     uint8  `xml:"accumulationBehaviour,omitempty"`
	CommodityType             uint8  `xml:"commodity,omitempty"`
	DataQualifier             uint8  `xml:"dataQualifier,omitempty"`
	FlowDirection             uint8  `xml:"flowDirection,omitempty"`
	IntervalLength            uint32 `xml:"intervalLength,omitempty"`
	Kind                      uint8  `xml:"kind,omitempty"`
	NumberOfConsumptionBlocks uint8  `xml:"numberOfConsumptionBlocks,omitempty"`
	NumberOfTouTiers          uint8  `xml:"numberOfTouTiers,omitempty"`
	Phase                     uint16 `xml:"phase,omitempty"`
	PowerOfTenMultiplier      int8   `xml:"powerOfTenMultiplier,omitempty"`
	TieredConsumptionBlocks   *bool  `xml:"tieredConsumptionBlocks,omitempty"`
	Uom                       uint8  `xml:"uom,omitempty"`
}

// Reading is a single measured value within a MirrorReadingSet.
type Reading struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns Reading"`

	// LocalID disambiguates multiple readings in one set.
	LocalID      HexBinary16       `xml:"localID,omitempty"`
	TimePeriod   *DateTimeInterval `xml:"timePeriod,omitempty"`
	Value        int64             `xml:"value,omitempty"`
	QualityFlags HexBinary16       `xml:"qualityFlags,omitempty"`
}

// MirrorReadingSet is a timestamped batch of readings for one reporting interval.
type MirrorReadingSet struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns MirrorReadingSet"`
	Resource

	StartTime int64     `xml:"timePeriod>start"`
	Duration  uint32    `xml:"timePeriod>duration"`
	Reading   []Reading `xml:"Reading"`
}

// MirrorMeterReading is the payload the client POSTs to /mup/{n}
// to report periodic telemetry. Each POST is one reading set.
type MirrorMeterReading struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns MirrorMeterReading"`
	Resource

	MRID             string             `xml:"mRID,omitempty"`
	Description      string             `xml:"description,omitempty"`
	ReadingType      *ReadingType       `xml:"ReadingType,omitempty"`
	MirrorReadingSet []MirrorReadingSet `xml:"MirrorReadingSet,omitempty"`
}

// ───────────────────────────────────────────────────────────────────────
// Response resources (GEN.044 — client must acknowledge events)
// ───────────────────────────────────────────────────────────────────────

// Response status codes (IEEE 2030.5 table 27).
const (
	ResponseEventReceived   uint8 = 1 // event text received and understood
	ResponseEventStarted    uint8 = 2 // event interval began
	ResponseEventCompleted  uint8 = 3 // event interval ended
	ResponseOptIn           uint8 = 4 // client opted in (for opt-in programs)
	ResponseOptOut          uint8 = 5 // client opted out
	ResponseEventCancelled  uint8 = 6 // event cancelled by the server (CORE-022)
	ResponseEventSuperseded uint8 = 7 // event superseded by an overlapping event (CORE-023)

	// Remaining Table 27 lifecycle / rejection statuses (CORE-022/023 code
	// discipline — the standard vocabulary the LEXA 0xF0 extension below is
	// being migrated onto; see the responses tracker's D5 mapping).
	ResponsePartialOptOut   uint8 = 8   // event partially completed (user/DER opt-out during the interval)
	ResponseNoParticipation uint8 = 10  // event interval elapsed with no participation
	ResponseAbortedServer   uint8 = 13  // event aborted — server cancelled/deleted it
	ResponseAbortedProgram  uint8 = 14  // event aborted — superseding program change
	ResponseRejectedParam   uint8 = 252 // rejected — parameter not applicable to this DER
	ResponseRejectedInvalid uint8 = 253 // rejected — invalid/out-of-range event content
	ResponseRejectedExpired uint8 = 254 // rejected — event already expired at receipt

	// ResponseCannotComply is a LEXA profile extension (NOT an IEEE 2030.5
	// Table 27 status). It alerts the server that the DER physically cannot meet
	// an active control limit — e.g. an import cap that would require battery
	// discharge below its SOC reserve. Chosen in the 0xF0–0xFF manufacturer
	// range so it never collides with a standard status (1–7); the gridsim
	// server treats any status ≥ 0xF0 as a resource-limited non-compliance
	// alert rather than a lifecycle acknowledgement.
	ResponseCannotComply uint8 = 0xF0 // 240 — LEXA: DER unable to honour the control
)

// IEEE 2030.5 UomType codes (Table for ReadingType.uom) used by MUP telemetry.
const (
	UomWatts uint8 = 38 // real power, W
	UomVolts uint8 = 29 // voltage, V
	UomHertz uint8 = 33 // frequency, Hz
)

// DataQualifier codes (ReadingType.dataQualifier).
const DataQualifierAverage uint8 = 2

// KindType codes (ReadingType.kind).
const (
	KindPower   uint8 = 37 // power (W)
	KindVoltage uint8 = 12 // voltage
	KindFreq    uint8 = 38 // frequency
)

// Response is posted by the client to the server's ResponseSetListLink
// to acknowledge receipt and state transitions of DERControl events.
// Per GEN.044, a conformant client must POST a Response for each event
// at each transition: received (1), started (2), completed (3).
type Response struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns Response"`
	Resource

	// CreatedDateTime is when this response was generated (server time).
	CreatedDateTime int64 `xml:"createdDateTime,omitempty"`
	// EndDeviceLFDI identifies the responding device.
	EndDeviceLFDI string `xml:"endDeviceLFDI,omitempty"`
	// Status is one of the ResponseEvent* constants above.
	Status uint8 `xml:"status"`
	// Subject is the mRID of the DERControl being acknowledged.
	Subject string `xml:"subject,omitempty"`
}

// ResponseSet groups Response resources for a single DERProgram.
// The server advertises the ResponseSet endpoint via ResponseSetListLink
// in DeviceCapability.
type ResponseSet struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns ResponseSet"`
	Resource

	MRID         string    `xml:"mRID,omitempty"`
	ResponseList *ListLink `xml:"ResponseListLink,omitempty"`
}

// ResponseSetList is a collection of ResponseSet resources.
type ResponseSetList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns ResponseSetList"`
	Resource

	All         uint32        `xml:"all,attr"`
	Results     uint32        `xml:"results,attr"`
	ResponseSet []ResponseSet `xml:"ResponseSet"`
}

// ResponseList is a collection of Response resources within a ResponseSet.
type ResponseList struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns ResponseList"`
	Resource

	All      uint32     `xml:"all,attr"`
	Results  uint32     `xml:"results,attr"`
	Response []Response `xml:"Response"`
}

// ───────────────────────────────────────────────────────────────────────
// DERStatus, DERCapability, DERSettings (monitoring/reporting)
// ───────────────────────────────────────────────────────────────────────

// DERCapability describes the nameplate capabilities of a DER.
type DERCapability struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERCapability"`
	Resource

	// Type of DER: 0=unknown, 1=virtual, 2=reciprocating engine, 80=PV, 81=wind, 83=storage
	Type             uint8        `xml:"type"`
	RtgMaxW          ActivePower  `xml:"rtgMaxW"`
	RtgMaxVA         *ActivePower `xml:"rtgMaxVA,omitempty"`
	RtgMaxVar        *ActivePower `xml:"rtgMaxVar,omitempty"`
	RtgMaxChargeW    *ActivePower `xml:"rtgMaxChargeRateW,omitempty"`
	RtgMaxDischargeW *ActivePower `xml:"rtgMaxDischargeRateW,omitempty"`
}

// DERSettings contains the current operational settings of a DER.
type DERSettings struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERSettings"`
	Resource

	SetMaxW     *ActivePower `xml:"setMaxW,omitempty"`
	SetMaxVA    *ActivePower `xml:"setMaxVA,omitempty"`
	UpdatedTime int64        `xml:"updatedTime,omitempty"`
}

// DERStatus contains the current operational status of a DER.
type DERStatus struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns DERStatus"`
	Resource

	GenConnectStatus      *uint8 `xml:"genConnectStatus>value,omitempty"`
	OperationalModeStatus *uint8 `xml:"operationalModeStatus>value,omitempty"`
	ReadingTime           int64  `xml:"readingTime,omitempty"`
}
