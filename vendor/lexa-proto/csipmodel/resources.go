// Package csipmodel defines Go structs for the IEEE 2030.5 / CSIP XML data
// model — the wire-format types both the gateway (client-side unmarshal) and
// csip-tls-test's gridsim (server-side marshal) work from (TASK-023). This is
// the data model only: walkers, schedulers, identity, and DNS-SD stay
// repo-local forks that merely import this package.
//
// THE NORMATIVE ANCHOR IS IEEE Std 2030.5-2018. Every wire-type, cardinality,
// enumeration and bit-assignment claim in this package cites it by printed
// page, and docs/schema/NORMATIVE_ANCHOR.md holds the declaration plus a
// three-way divergence census (2018 / 2030.5-2023 / the vendored
// docs/schema/sep-2.0.4.xsd). READ THAT DOCUMENT BEFORE CHANGING A CONSTANT.
//
// The vendored sep-2.0.4.xsd is a REFERENCE artifact — the pre-publication
// ZigBee SEP 2.0 draft, five years older than the published standard, in a
// different namespace, and divergent on the DERControlType bit table, the
// DERCurveType enumeration, three DERCurve attributes and five DERControlBase
// elements. Anchoring to it cost this package a whole re-derivation on
// 2026-08-15 (registry IW15-027). A claim may cite it only where the census
// marks the row AGREES, and then as corroboration rather than as the source.
//
// Every struct uses XML tags that match the standard exactly, including the
// mandatory namespace urn:ieee:std:2030.5:ns. The inheritance hierarchy
// (Resource → IdentifiedObject → SubscribableResource, etc.) is flattened into
// Go structs with embedded fields, because Go's encoding/xml handles embedded
// struct tags correctly. Element ORDER within a struct is load-bearing: the
// standard's particles are xs:sequence, Go emits fields in declaration order,
// and a validating peer rejects an out-of-order document even when every
// element is legal.
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
// Base types — these model 2030.5's inheritance chain. The vendored
// sep-2.0.4.xsd is used below only as the machine-readable REFERENCE for
// element STRUCTURE, which is what §1.2 of NORMATIVE_ANCHOR.md keeps it for;
// it is never the authority for a semantic requirement.
// ───────────────────────────────────────────────────────────────────────

// Link is the base type for all link elements (EndDeviceListLink, TimeLink, etc.).
// Every *Link type carries an href attribute — IEEE Std 2030.5-2018 p.155:
// "Link object () — Links provide a reference, via URI, to another resource."
// with "href attribute (anyURI) «XSDattribute»". The reference XSD agrees on
// the structure.
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

// ResponseRequired is the IEEE 2030.5 Event-base `responseRequired` bitmap —
// HexBinary8, IEEE Std 2030.5-2018 p.174 ("An 8-bit field encoded as a hex
// string (2 hex characters)") — carried as an XML attribute on Event-derived
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
// WHY IT MATTERS, and it is not cosmetic. IEEE Std 2030.5-2018 p.174 types
// several bitmap elements as HexBinary8/16/32, each documented as "a N-bit
// field encoded as a hex string ... Where applicable, bit 0, or the least
// significant bit, goes on the right." (Identical in 2030.5-2023 and in
// sep.xsd — NORMATIVE_ANCHOR.md §3.7 — so this whole section is
// anchor-independent and survived the IW15-027 re-derivation untouched.) For a
// value whose decimal rendering happens to contain only the digits 0-9, BOTH
// readings parse and they are DIFFERENT numbers:
//
//	<modesSupported>1048576</modesSupported>
//	  decimal 1048576 = 0x100000  -> bit 20 (opModMaxLimW, 2018 p.252)
//	  hex     1048576 = 17 073 526 -> bits 1, 2, 4, 5, 6, 8, 10, 15, 18, 24:
//	                                 TEN completely different modes
//
// (That second line read "over-wide: not even a 32-bit value" until 2026-08-15,
// which is simply false — 0x1048576 is 17 073 526, comfortably inside 32 bits —
// and it was the WEAKER claim as well as the wrong one. An over-wide value is
// self-announcing: a reader rejects it. A value that parses cleanly under both
// readings into two different mode sets is the whole hazard this section is
// about, and this example is one of its sharpest instances. Found by the
// independent bit-position oracle, whose own ambiguity fixture asserts exactly
// this bit list.)
//
//	<modesSupported>132</modesSupported>
//	  decimal 132 = 0x84   -> bits 2 and 7 (opModConnect, opModFixedW)
//	  hex     132 = 0x0132 -> bits 1, 4, 5, 8 (four completely different modes)
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
// standard types these elements hexBinary (2018 p.174, quoted above), so "20"
// is 32 and not 20. A lenient "try decimal too"
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

// HexBinary32 is a 32-bit bitmap element encoded as IEEE 2030.5-2018's
// HexBinary32 (p.174): eight uppercase hex digits, zero-padded,
// least-significant bit on the right. DERControlType (modesSupported /
// modesEnabled) extends it (2018 p.251).
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

// HexBinary16 is a 16-bit bitmap element encoded as IEEE 2030.5-2018's
// HexBinary16 (p.174): four uppercase hex digits, zero-padded. RoleFlagsType
// extends it (2018 p.169); localID and qualityFlags are typed with it directly
// (2018 p.210, Figure B.23).
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
	DERProgramListLink *ListLink `xml:"DERProgramListLink,omitempty"`
	TimeLink           *Link     `xml:"TimeLink,omitempty"`

	// ResponseSetListLink is this FSA's OWN Response function set — the head
	// of the chain a client follows to find where undirected Responses for
	// events discovered under THIS FSA are POSTed (ResponseSetList → the
	// selected ResponseSet → ResponseListLink → ResponseList).
	//
	// It is inherited, not FSA-specific. IEEE Std 2030.5-2018 Annex B §B.2.5
	// (Figure B.11, printed p.180) hangs `ResponseSetListLink` at multiplicity
	// [0..1] off `FunctionSetAssignmentsBase`, and declares
	// "FunctionSetAssignments object (FunctionSetAssignmentsBase)" immediately
	// below it — the same base `DeviceCapability` derives from (Figure B.2,
	// printed p.154, whose own note explains the arrangement: "Making
	// DeviceCapability inherit from FunctionSetAssignments allows those group
	// resources to be published with or without use of FunctionSetAssignments").
	// §B.2.7 (Figure B.13, printed p.183) draws the Response package rooted at
	// `FunctionSetAssignmentsBase` for exactly that reason. So a server may
	// publish the Response chain at /dcap, per FSA, or both, and a client that
	// models the link on only one of the two subclasses cannot even SEE the
	// per-FSA advertisement — it is dropped at decode, before any walker gets a
	// chance to follow it. That was this type's state until registry
	// FSA-LEVEL-RESPONSE-SET-LINK-UNDECODABLE.
	//
	// Declared identically to DeviceCapability's field above — same Go type,
	// same element name, same (inherited default) namespace — because it is
	// literally the same inherited link, and a client resolving one chain must
	// not have to care which resource advertised it.
	ResponseSetListLink *ListLink `xml:"ResponseSetListLink,omitempty"`

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

// SignedPerCent represents a signed percentage × 100 (so 50 % = 5000).
//
// IEEE Std 2030.5-2018 p.170: "SignedPerCent object (Int16) — Used for signed
// percentages, specified in hundredths of a percent, −10 000 to 10 000.
// (10 000 = 100%)". Identical in 2030.5-2023 p.180 and in sep.xsd — see
// docs/schema/NORMATIVE_ANCHOR.md §3.8. opModFixedW is typed with it (2018
// p.248) and the sign selects the reference rating.
type SignedPerCent struct {
	Value int16 `xml:",chardata"`
}

// PowerFactorWithExcitation is the wire type of opModFixedPFAbsorbW and
// opModFixedPFInjectW — IEEE Std 2030.5-2018 printed p.258, referenced from
// DERControlBase at p.248. THREE MANDATORY sub-elements:
//
//	displacement (UInt16 [1])                  — the PF magnitude, scaled
//	excitation   (boolean [1])                 — see the polarity below
//	multiplier   (PowerOfTenMultiplierType [1]) — apply 10^multiplier
//
// so the displacement power factor is displacement × 10^multiplier. p.258's own
// worked example: "a value of 0.95 may be specified as a displacement of 950 and
// a multiplier of −3".
//
// ── THE EXCITATION POLARITY, QUOTED, BECAUSE GETTING IT BACKWARDS COMMANDS
//
//	REACTIVE POWER IN THE OPPOSITE DIRECTION AT FULL MAGNITUDE ──────────────
//
// 2018 p.258, excitation attribute (boolean), verbatim and complete:
//
//	"True when DER is absorbing reactive power (under-excited), false when DER
//	 is injecting reactive power (over-excited)."
//
// So TRUE means UNDER-excited, and 0.950 OVER-excited is {displacement 950,
// excitation FALSE, multiplier -3}. This comment said "true = over-excited"
// until 2026-08-15 and every production consumer agreed with the comment rather
// than with the standard.
//
// THE TRAP IS THAT `excitation` READS LIKE A DEGREE, NOT A DIRECTION. "Excited"
// sounds like more, and more excitation sounds like injecting — but the flag
// names the ABSORBING case, which is the under-excited one. Downstream, SunSpec
// model 704 numbers the same pair in the opposite order again
// (M704_Ext_OverExcited = 0, M704_Ext_UnderExcited = 1), so any consumer of this
// field crosses TWO conventions and must convert rather than copy:
//
//	overExcited := !p.Excitation
//
// A caller that assigns the boolean straight through writes PFWInj_Ext = 0
// (over-excited) for a document that said "absorb", and the inverter injects.
// Pinned at the writer by derbase's
// TestSetFixedPF_ExcitationTrueWritesUnderExcited.
//
// Identical in 2030.5-2023 p.271, which adds only a wrapper
// (PowerFactorWithExcitationControlType) carrying the new `disabled` attribute
// — backward compatible with this element content.
//
// WHY IT REPLACES *SignedPerCent, AND WHY THAT TYPING WAS NEVER RIGHT UNDER ANY
// ANCHOR (NORMATIVE_ANCHOR.md §5.1, closed here). These two elements were typed
// `*SignedPerCent` — a bare chardata Int16 — so a conformant document's
//
//	<opModFixedPFInjectW><displacement>950</displacement>
//	  <excitation>true</excitation><multiplier>-3</multiplier></opModFixedPFInjectW>
//
// decoded to ZERO: encoding/xml finds no character data at the element's own
// level and leaves the Int16 at its zero value, silently. Not a partial decode,
// not an error — a fixed power factor of 0.0000, which is not a power factor at
// all. The defect outranked the rest of §5 the moment the capability mask
// started advertising DERControlType bit 5 (IW15-027): the product cannot
// advertise a mode whose conformant wire form it decodes to nothing.
//
// NO DECODE TOLERANCE FOR THE OLD SHAPE, deliberately. The tempting move is to
// also accept a bare chardata value "for compatibility". There is nothing to be
// compatible WITH: `<opModFixedPFInjectW>9500</opModFixedPFInjectW>` is not a
// shape 2030.5-2018 declares, not one 2030.5-2023 declares, and not one the
// vendored SEP 2.0.4 draft declares either — the draft's single opModFixedPF is
// typed PowerFactor, itself a two-element structure. The scalar typing was this
// package's own invention, so no server anywhere emits it, and a tolerance arm
// would exist solely to guess at a document no implementation produces. A
// chardata-only element now decodes to displacement 0 and is refused by the
// consumer's plausibility gate, which is the correct treatment of a malformed
// document.
//
// THE ZERO VALUE IS NOT A POWER FACTOR and callers must not treat it as one:
// displacement 0 means "the element was absent or malformed", which is why every
// consumer in this family gates on a plausibility check rather than reading the
// field raw. PF() below returns ok=false for it.
// ── ABSENT IS NOT FALSE (gate #18 E-5) ──────────────────────────────────────
//
// All three sub-elements are MANDATORY [1], and Excitation is a plain bool, so
// a document that omits <excitation> decoded to false — which this very type
// documents as OVER-EXCITED, injecting reactive power. A missing direction
// therefore became a confident command in one specific direction, at whatever
// magnitude the displacement carried. The "no decode tolerance" and "the zero
// value is not a power factor" arguments above hold at the GO TYPE level and
// say nothing about the XML boundary, where absence is the failure mode.
//
// UnmarshalXML below records which mandatory sub-elements were missing, so
// absent and false stop being the same fact. It does NOT return an error: one
// malformed element must not fail the whole DERControlList and take every
// well-formed control in it down with it. The axis is refused instead, by name,
// through Command() — the same shape as PF()'s existing ok=false gate.
//
// The struct FIELDS are unchanged, deliberately. Making Excitation a *bool
// would be tidier Go and would break roughly twenty construction sites across
// three repositories for a fact that exists only at the decode boundary. A
// Go-constructed literal is complete BY CONSTRUCTION — it never passes through
// UnmarshalXML — so the zero value of `missing` means "complete", and every
// hand-built value keeps working untouched.
type PowerFactorWithExcitation struct {
	Displacement uint16 `xml:"displacement"`
	Excitation   bool   `xml:"excitation"`
	Multiplier   int8   `xml:"multiplier"`

	// missing names the mandatory sub-elements UnmarshalXML did not find, in
	// document order. nil means complete (or Go-constructed).
	missing []string
}

// UnmarshalXML decodes the three mandatory sub-elements through POINTERS, so
// absent is distinguishable from the zero value, and records the absentees.
func (p *PowerFactorWithExcitation) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// A shadow struct with the same tags and no UnmarshalXML of its own, so
	// this does not recurse.
	var raw struct {
		Displacement *uint16 `xml:"displacement"`
		Excitation   *bool   `xml:"excitation"`
		Multiplier   *int8   `xml:"multiplier"`
	}
	if err := d.DecodeElement(&raw, &start); err != nil {
		return err
	}
	*p = PowerFactorWithExcitation{}
	if raw.Displacement != nil {
		p.Displacement = *raw.Displacement
	} else {
		p.missing = append(p.missing, "displacement")
	}
	if raw.Excitation != nil {
		p.Excitation = *raw.Excitation
	} else {
		p.missing = append(p.missing, "excitation")
	}
	if raw.Multiplier != nil {
		p.Multiplier = *raw.Multiplier
	} else {
		p.missing = append(p.missing, "multiplier")
	}
	return nil
}

// Missing returns the mandatory sub-elements the decoder did not find, for a
// refusal message. Empty for a complete document and for any Go-constructed
// value.
func (p PowerFactorWithExcitation) Missing() []string { return p.missing }

// Command returns the commanded displacement power factor together with its
// excitation direction — overExcited = injecting reactive power, i.e. the
// NEGATION of the wire flag — and whether both are usable.
//
// This is the accessor anything actuating on this element should use, because
// here the magnitude and the direction are not separable facts: 0.95
// over-excited and 0.95 under-excited are opposite reactive commands, so a
// magnitude with an unknown direction is not a power factor at all. PF() gates
// only the magnitude and is kept for callers that genuinely want just that.
//
// ok is false when any mandatory sub-element was absent from the document, or
// when PF() itself refuses the magnitude. The caller answers false with a NAMED
// refusal — never with a default direction, which is exactly the failure this
// gate found.
func (p PowerFactorWithExcitation) Command() (pf float64, overExcited bool, ok bool) {
	if len(p.missing) > 0 {
		return 0, false, false
	}
	v, vok := p.PF()
	if !vok {
		return v, false, false
	}
	return v, !p.Excitation, true
}

// PF returns the displacement power factor as a float (displacement ×
// 10^multiplier) and whether the value is a usable one.
//
// ok is FALSE for displacement 0 (absent/malformed — see the type doc) and for a
// resulting magnitude outside (0, 1], which is the domain of a displacement
// power factor: |PF| > 1 is not a power factor, and a server sending one has
// sent a value no DER can execute. Callers answer a false with a NAMED refusal
// rather than a clamp — clamping a power factor moves reactive power to a
// quantity the head end did not request.
//
// The multiplier is applied by repeated division/multiplication by ten rather
// than math.Pow to keep the result exact for the multipliers that actually
// occur (-4..0 in practice): math.Pow(10, -3) is not exactly 0.001, and a PF
// that is 0.9500000000000001 fails an equality-shaped test for no reason.
func (p PowerFactorWithExcitation) PF() (float64, bool) {
	if p.Displacement == 0 {
		return 0, false
	}
	v := float64(p.Displacement)
	for m := p.Multiplier; m < 0; m++ {
		v /= 10
	}
	for m := p.Multiplier; m > 0; m-- {
		v *= 10
	}
	if v <= 0 || v > 1 {
		return v, false
	}
	return v, true
}

// ActivePower represents watts with a power-of-ten multiplier.
type ActivePower struct {
	Multiplier int8  `xml:"multiplier"`
	Value      int16 `xml:"value"`
}

// PerCent represents an unsigned percentage × 100 (hundredths), used where
// 2030.5's PerCent type applies (opModMaxLimW, DERCurve.vRef).
//
// IEEE Std 2030.5-2018 p.167: "PerCent object (UInt16) — Used for percentages,
// specified in hundredths of a percent, 0 to 10 000. (10 000 = 100%)".
// Identical in 2030.5-2023 p.178 and in sep.xsd — NORMATIVE_ANCHOR.md §3.8,
// and the confirmation of IW14-002: PerCent is UNSIGNED, unlike SignedPerCent's
// Int16. The wire domain is therefore [0,65535] and a negative chardata is a
// schema-layer rejection the XML decoder itself makes. The tighter ≤100.00 %
// (10000) product bound is prose/table-defined (CSIP IG 2.1 Table 9), NOT a
// schema facet, so it stays an application-layer rule enforced downstream at
// the decode/conversion boundary, not in this struct. See
// docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1.
type PerCent struct {
	Value uint16 `xml:",chardata"`
}

// ─── DERUnitRefType: what a percentage is a percentage OF ─────────────────────
//
// These match the DERUnitRefType enumeration in IEEE Std 2030.5-2018 p.256
// (0 N/A, 1 %setMaxW, 2 %setMaxVar, 3 %statVarAvail, 4 %setEffectiveV,
// 5 %setMaxChargeRateW, 6 %setMaxDischargeRateW, 7 %statWAvail, "All other
// values reserved."). The code is NOT decoration: a percentage without its
// reference is not a
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
// FIELD ORDER IS THE STANDARD'S SEQUENCE (IEEE Std 2030.5-2018 p.248-252 and
// Figure B.37 p.240), for the reason spelled out on ExtendedDERControlBase in
// der.go: xs:sequence is ordered and Go emits fields in declaration order, so
// the layout IS the emitted sequence. These eight are a SUBSEQUENCE of the
// standard's twenty-six — a struct that omits optional elements is still in
// sequence as long as the ones it keeps are in order — and they are.
//
// The 2026-08-15 correction moved the four CSIP-Aus elements, which no revision
// of 2030.5 declares, from between opModMaxLimW and rampTms to AFTER rampTms,
// so the standard-declared part of the struct is contiguous and in sequence.
// That correction stands under the re-anchoring (registry IW15-027); nothing in
// this struct's element set differs between 2030.5-2018 and the draft schema.
type DERControlBase struct {
	// ── IEEE 2030.5-2018 DERControlBase, in sequence ─────────────────────────
	// Each mode is [0..1]; the server sends only what it wants to control.
	OpModConnect  *bool `xml:"opModConnect,omitempty"`  // 2018 p.248
	OpModEnergize *bool `xml:"opModEnergize,omitempty"` // 2018 p.248
	// 2018 p.248 declares both directions as first-class elements with their own
	// DERControlType bits (4 and 5), typed PowerFactorWithExcitation (p.258).
	OpModFixedPFAbsorbW *PowerFactorWithExcitation `xml:"opModFixedPFAbsorbW,omitempty"`
	OpModFixedPFInjectW *PowerFactorWithExcitation `xml:"opModFixedPFInjectW,omitempty"`
	OpModFixedVar       *FixedVar                  `xml:"opModFixedVar,omitempty"` // 2018 p.248
	OpModFixedW         *SignedPerCent             `xml:"opModFixedW,omitempty"`   // 2018 p.248. SignedPerCent, not watts — IW13-001. Sign selects reference: + = %setMaxW/%setMaxDischargeRateW, - = %setMaxChargeRateW.
	OpModMaxLimW        *PerCent                   `xml:"opModMaxLimW,omitempty"`  // 2018 p.250. PerCent of setMaxW in hundredths, not watts — IW13-001.
	RampTms             *uint16                    `xml:"rampTms,omitempty"`       // 2018 p.251 — the standard's last element

	// ── NOT IEEE 2030.5 ──────────────────────────────────────────────────────
	// ExpLimW/GenLimW/ImpLimW/LoadLimW are NOT IEEE 2030.5 elements in ANY
	// revision: verified absent from 2030.5-2018 (p.248-252), 2030.5-2023, and
	// sep.xsd 2.0.4. They match the CSIP-Aus dynamic-operating-envelope
	// extension quartet, which types them ActivePower (watts) as here. The
	// governing extension schema is not in the local standards corpus — confirm
	// against it before any conformance claim on these axes. See
	// docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1.2.
	OpModExpLimW  *ActivePower `xml:"opModExpLimW,omitempty"`
	OpModGenLimW  *ActivePower `xml:"opModGenLimW,omitempty"`
	OpModImpLimW  *ActivePower `xml:"opModImpLimW,omitempty"`
	OpModLoadLimW *ActivePower `xml:"opModLoadLimW,omitempty"`
}

// EventStatus describes the current state of an event (IEEE 2030.5-2018
// Annex B, "EventStatus object", p.159-160).
type EventStatus struct {
	CurrentStatus         uint8 `xml:"currentStatus"`
	DateTime              int64 `xml:"dateTime"`
	PotentiallySuperseded bool  `xml:"potentiallySuperseded"`
}

// EventStatus.currentStatus values — IEEE 2030.5-2018 Annex B,
// "currentStatus attribute (UInt8)", p.159-160 (REV0907-B1):
//
//	0 = Scheduled                    — event scheduled, not yet started.
//	1 = Active                       — event has reached its earliest
//	                                    Effective Start Time.
//	2 = Cancelled                    — "Client devices SHALL ... cancel the
//	                                    event immediately if applicable."
//	3 = Cancelled with Randomization — cancel immediately, but only after
//	                                    the end randomization: the larger of
//	                                    |randomizeStart| and
//	                                    |randomizeDuration|, in seconds.
//	                                    "SHALL NOT be used with 'regular'
//	                                    Events, only with specializations of
//	                                    RandomizableEvent."
//	4 = Superseded                   — "client SHALL terminate execution of
//	                                    the event immediately and commence
//	                                    execution of the new event
//	                                    immediately, unless the current time
//	                                    is within the start randomization
//	                                    window of the superseded event, in
//	                                    which case the client SHALL obey the
//	                                    start randomization of the new
//	                                    event."
//	"All other values reserved."
//
// REV0907-B1 (CRITICAL): the product tested `currentStatus == 6` at seven
// call sites in lexa-gw. 6 is not a currentStatus value at all — it is
// ResponseEventCancelled (see the Table 27 Response status codes below),
// the *different, Response-object* enumeration for "event cancelled by the
// server", transposed into this enumeration by mistake. Under the standard,
// 6 on currentStatus is one of the reserved values above: a client MUST NOT
// treat it as Cancelled. These constants exist so the correct values (2, 3)
// are named and typed, and so nobody "corrects" this back to 6 — that
// transposition is exactly the defect this task fixes. lexa-gw's call
// sites are repointed at these constants in WP2-T2, after this module is
// pinned to the fixed lexa-proto revision.
const (
	EventStatusScheduled                  uint8 = 0
	EventStatusActive                     uint8 = 1
	EventStatusCancelled                  uint8 = 2
	EventStatusCancelledWithRandomization uint8 = 3
	EventStatusSuperseded                 uint8 = 4
)

// IsCancelled reports whether s is Cancelled (2) or Cancelled with
// Randomization (3) — IEEE 2030.5-2018 p.159-160. It does not report
// Superseded (4): a superseded event is replaced by a new event, not
// withdrawn, and the standard's client obligations differ (see IsSuperseded).
// Reserved values (>4, including the legacy-mistaken 6) are never cancelled —
// see IsReserved.
func (s EventStatus) IsCancelled() bool {
	return s.CurrentStatus == EventStatusCancelled || s.CurrentStatus == EventStatusCancelledWithRandomization
}

// IsSuperseded reports whether s is Superseded (4) — IEEE 2030.5-2018
// p.159-160: the client terminates the superseded event and commences the
// new one (subject to the new event's start randomization if still within
// the superseded event's own start randomization window).
func (s EventStatus) IsSuperseded() bool {
	return s.CurrentStatus == EventStatusSuperseded
}

// IsTerminal reports whether s is a status the standard requires a client to
// stop acting on: Cancelled (2), Cancelled with Randomization (3), or
// Superseded (4). Scheduled (0) and Active (1) are not terminal. Reserved
// values are not terminal either — see IsReserved.
func (s EventStatus) IsTerminal() bool {
	return s.IsCancelled() || s.IsSuperseded()
}

// IsReserved reports whether s.CurrentStatus falls outside the defined
// 0-4 range — IEEE 2030.5-2018 p.160: "All other values reserved." A
// reserved value (this includes the legacy-mistaken 6, ResponseEventCancelled
// transposed from Table 27) is deliberately NOT cancelled and NOT terminal:
// the standard gives a client no obligation to act on a value it reserves,
// and treating an unknown value as if it meant something specific is exactly
// the class of error REV0907-B1 found. A caller encountering a reserved
// value should log it once (not per-poll) so an actual future extension of
// the enumeration is noticed rather than silently misread.
func (s EventStatus) IsReserved() bool {
	return s.CurrentStatus > EventStatusSuperseded
}

// EndRandomizationS returns the end randomization, in seconds, a client must
// wait before acting on a Cancelled with Randomization (3) event — IEEE
// 2030.5-2018 p.159-160: "using the larger of (absolute value of
// randomizeStart) and (absolute value of randomizeDuration) as the end
// randomization, in seconds." randomizeStart/randomizeDuration are signed
// (DERControl.RandomizeStart/RandomizeDuration), hence the absolute values
// here. For every status other than 3 the standard defines no end
// randomization, so this returns 0 — including for Cancelled (2), which the
// standard says to cancel "immediately" with no randomization step, and for
// reserved/other values, which carry no defined behavior at all (see
// IsReserved).
func (s EventStatus) EndRandomizationS(randomizeStart, randomizeDuration int32) int32 {
	if s.CurrentStatus != EventStatusCancelledWithRandomization {
		return 0
	}
	rs, rd := abs32(randomizeStart), abs32(randomizeDuration)
	if rs > rd {
		return rs
	}
	return rd
}

// abs32 returns the absolute value of v. Go's signed-integer negation wraps
// rather than panics, so the one non-representable case (v == -2^31, whose
// positive counterpart does not fit in int32) returns v unchanged instead of
// trapping; EndRandomizationS's inputs are wire-derived randomizeStart/
// randomizeDuration second offsets, for which that boundary value is not a
// realistic input, so this stays a total function without needing "math".
func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
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
//
// ANCHOR: IEEE Std 2030.5-2018 p.215 (Figure B.26 and the MirrorUsagePoint
// prose) and p.217 (UsagePointBase). MirrorUsagePoint extends UsagePointBase
// extends IdentifiedObject, so the element set is: mRID [1], description
// [0..1], version [0..1], roleFlags [1], serviceCategoryKind [1], status [1],
// deviceLFDI [1], MirrorMeterReading [0..*], postRate [0..1]. Corroborated by
// 2030.5-2023 p.224 and by sep.xsd:6267/:6366, which AGREE — this row of the
// census is revision-independent. See NORMATIVE_ANCHOR.md §3.6 and §3.10.
//
// THREE MANDATORY ELEMENTS LOST THEIR omitempty on 2026-08-15 (registry
// IW15-028), and this was a LIVE defect on every POST this product has ever
// made, not a latent one. roleFlags, serviceCategoryKind and status are all
// [1], and this product's values for two of them are exactly the zero
// `omitempty` deletes: serviceCategoryKind 0 is "electricity" (2018 p.169,
// ServiceKind) and status 0 is "off" (2018 p.217). An all-zero MUP emitted none
// of the three. Nothing noticed because the certify path grades the harness's
// MUP fixtures, never the DUT's.
//
// roleFlags carries a SHALL on top of its cardinality: 2018 p.169, "Bit 0 -
// isMirror - SHALL be set if the server is not the measurement device". On a
// MirrorUsagePoint the server is by definition not the measurement device, so
// bit 0 is mandatory for this product. Choosing the rest of the value
// (isDER, isSubmeter, ...) is the caller's job — cmd/telemetry's registerMUP —
// and a DUT-side oracle for it is on the IW15-028 worklist.
//
// deviceLFDI is [1] and KEEPS its omitempty, on the same reasoning as mRID: it
// is a string with no meaningful zero, and `<deviceLFDI></deviceLFDI>` is
// invalid in a different way (HexBinary160). A MUP with no LFDI is a caller
// defect, not an encoding one.
type MirrorUsagePoint struct {
	XMLName xml.Name `xml:"urn:ieee:std:2030.5:ns MirrorUsagePoint"`
	Resource

	MRID        string `xml:"mRID,omitempty"`
	Description string `xml:"description,omitempty"` // 2018 p.215 — [0..1]

	// RoleFlags is RoleFlagsType = HexBinary16 (2018 p.169). [1] — NOT
	// omitempty; see the type doc. Bit 0 isMirror is a SHALL here.
	RoleFlags HexBinary16 `xml:"roleFlags"`
	// ServiceCategoryKind is ServiceKind (2018 p.169-170). [1] — NOT omitempty:
	// 0 is "electricity", this product's own value.
	ServiceCategoryKind uint8 `xml:"serviceCategoryKind"`
	// Status is UInt8, 0 = off / 1 = on (2018 p.217). [1] — NOT omitempty:
	// 0 is a legal, meaningful value.
	Status uint8 `xml:"status"`

	DeviceLFDI string `xml:"deviceLFDI,omitempty"` // 2018 p.215 — [1], see the type doc
	PostRate   uint32 `xml:"postRate,omitempty"`   // 2018 p.215 — [0..1]
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
	ResponseOptOut          uint8 = 4 // user actively chose to opt out, or device auto-opts out per user preference; sent at the time of opt-out, which may precede event start — IEEE 2030.5-2018 Table 27
	ResponseOptIn           uint8 = 5 // user chose to opt back in after a prior opt-out; sent at the time of opt-in, which may precede event start — IEEE 2030.5-2018 Table 27
	ResponseEventCancelled  uint8 = 6 // event cancelled by the server (CORE-022)
	ResponseEventSuperseded uint8 = 7 // event superseded by an overlapping event (CORE-023)

	// Remaining Table 27 lifecycle / rejection statuses (CORE-022/023 code
	// discipline — the standard vocabulary the LEXA 0xF0 extension below is
	// being migrated onto; see the responses tracker's D5 mapping).
	ResponsePartialOptOut    uint8 = 8   // event partially completed (user/DER opt-out during the interval); sent at EffectiveEndTime only — never at onset/receipt
	ResponsePartialOptIn     uint8 = 9   // "Event partially completed due to user opt-in" — user opted back in after a prior opt-out partway through the interval; sent at EffectiveEndTime only — never at onset/receipt — IEEE 2030.5-2018 Table 27
	ResponseNoParticipation  uint8 = 10  // event interval elapsed with no participation; sent at EffectiveEndTime only — never at onset/receipt
	ResponseUserAcknowledged uint8 = 11  // "User has acknowledged the event" — user actively acknowledged the event, distinct from a device-generated Received/Started/Completed; requires responseRequired bit 2 (RespReqCustomerResponse, 0x04) — IEEE 2030.5-2018 Table 27
	ResponseAbortedServer    uint8 = 13  // event aborted — server cancelled/deleted it
	ResponseAbortedProgram   uint8 = 14  // event aborted — superseding program change
	ResponseRejectedParam    uint8 = 252 // rejected — parameter not applicable to this DER
	ResponseRejectedInvalid  uint8 = 253 // rejected — invalid/out-of-range event content
	ResponseRejectedExpired  uint8 = 254 // rejected — event already expired at receipt

	// ResponseCannotComply is a LEXA profile extension (NOT an IEEE 2030.5
	// Table 27 status). It alerts the server that the DER physically cannot meet
	// an active control limit — e.g. an import cap that would require battery
	// discharge below its SOC reserve. Value 0xF0 (240) sits inside Table 27's
	// RESERVED range (15-251, 255) — the standard defines no manufacturer
	// range at all. Retained at 0xF0 only for legacy wire compatibility: this
	// is a Lexa profile extension, config-gated to legacy mode only, and MUST
	// NOT be advertised or used as IEEE 2030.5/CSIP conformance behavior.
	ResponseCannotComply uint8 = 0xF0 // 240 — LEXA: DER unable to honour the control
)

// Table27RequiredBit returns the IEEE 2030.5-2018 Table 27 "Response
// required" bit — the single ResponseRequired bit (see above) a server must
// have set on an Event's responseRequired attribute before a client is
// expected to send a Response carrying the given status. Per Table 27's
// "Response required" column:
//
//	status 1  (ResponseEventReceived)     -> RespReqMessageReceived  (0x01)
//	status 11 (ResponseUserAcknowledged)   -> RespReqCustomerResponse (0x04)
//	every other defined lifecycle/rejection status (2-10, 13, 14, 252-254)
//	                                        -> RespReqSpecificResponse (0x02)
//	anything else — undefined, reserved, or the 0xF0 Lexa extension -> 0:
//	this table has no opinion and a caller must not gate on it.
//
// This exists so the gateway's per-bit response gating reads this one table
// instead of re-deriving — or worse, re-typing — Table 27's response-required
// column a second time; duplicating it in two repos invites exactly the kind
// of silent drift this package's other Table 27 constants have already had
// (values 4/5 were once transposed). Keep it in lockstep with the status
// constants above; TestTable27RequiredBit is the drift check.
func Table27RequiredBit(status uint8) uint8 {
	switch {
	case status == ResponseEventReceived:
		return uint8(RespReqMessageReceived)
	case status == ResponseUserAcknowledged:
		return uint8(RespReqCustomerResponse)
	case (status >= ResponseEventStarted && status <= ResponseNoParticipation) ||
		status == 12 || // "Cannot be displayed" — Messaging-only, bit 1 per Table 27; no named constant because this DER product never posts it
		status == ResponseAbortedServer || status == ResponseAbortedProgram ||
		(status >= ResponseRejectedParam && status <= ResponseRejectedExpired):
		return uint8(RespReqSpecificResponse)
	default:
		return 0
	}
}

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
