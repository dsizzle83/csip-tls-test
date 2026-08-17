package gridsim

// curve.go — POST/DELETE /admin/curve: push one or more dynamic DER curves
// (Volt-VAr / Volt-Watt / Freq-Watt / Watt-PF / Watt-Var and the ten IEEE
// 2030.5 ride-through curves) AND bind them into ONE active DERControl so the
// hub discovers and adopts them via its normal walk. The static tree serves one
// Volt-VAr curve at /derp/0/dc but no control references it (the hub sees an
// empty CurveSet); this endpoint is what lights the curve path up.
//
// ── ONE CONTROL MAY CARRY SEVERAL CURVES, because procedures prescribe it ────
//
// CSIP CTP v1.3's BASIC-004 says the Service Point DERProgram "shall have a
// DERControl instance with Low/High Voltage Ride Through values in Figure 4" —
// singular — and Figure 4 prints FOUR curves: opModLVRTMustTrip,
// opModLVRTMomentaryCessation, opModHVRTMustTrip and
// opModHVRTMomentaryCessation. BASIC-005 says the same about Figure 5's TWO
// frequency curves. A DERControlBase carries a separate CurveLink field per
// mode, so all of them fit on one control; publishing them as four separate
// DERControls would follow a procedure nobody wrote, and the row could then
// never say the DUT had been offered the COMBINATION — which is the whole
// content of a ride-through test.
//
// So the request takes a `curves` ARRAY, each entry carrying its own mode,
// points, multipliers and yRefType. The pre-existing top-level single-curve
// fields still work and are treated as an implicit one-entry request, so every
// caller written before this keeps its exact behaviour. What is REFUSED is
// sending both at once: a request with a top-level mode AND a curves array has
// two answers to "what did this publish", and guessing one of them is how a
// bundle ends up describing a control the bench never served.
//
// EVERY VALIDATION IS PER ENTRY. The vRef family's opModVoltVar-only SHALL NOT,
// the x_ref_type refusal and openLoopTms's domain check are properties of ONE
// curve, so a four-curve request gets four independent checks and a 400 names
// which entry failed. A per-REQUEST check would have let a volt-var entry's
// vRef authorise a ride-through entry beside it.
//
// The bound control is stored as an ExtendedDERControl (its DERControlBase
// carries opMod*<curve> link hrefs). Because ExtendedDERControlList shares its
// XMLName ("DERControlList") with the scalar DERControlList, a walker fetching
// /derp/{p}/derc parses either — so the derc/actderc paths can hold either
// type after this endpoint runs (see the type-tolerant edits in admin.go).

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sort"
	"strings"

	model "lexa-proto/csipmodel"
)

// curvePoint is one (x, y) breakpoint in the request. Accepted as float64 and
// rounded into the model's int32 CurveData.
type curvePoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// adminCurveEntry is ONE curve of a request: everything IEEE 2030.5 declares on
// a DERCurve, plus the DERControlBase link field it hangs off.
//
// It exists because a DERControl may carry several curves at once (see the file
// doc) and every one of them is an independent document with its own
// multipliers, its own y reference and its own conformance rules. Sharing any
// of those across entries would let one curve's settings silently govern
// another's — the shape in which a four-curve Figure becomes one curve plus
// three copies of it.
type adminCurveEntry struct {
	// Mode is the curve mode, which selects both the DERCurveType code and the
	// DERControlBase link field. See curveTypeForMode for the vocabulary.
	Mode   string       `json:"mode"`
	Points []curvePoint `json:"points"`
	XMult  int8         `json:"x_mult"` // 10^n multiplier on x values
	YMult  int8         `json:"y_mult"` // 10^n multiplier on y values
	// YRefType is the DERUnitRefType for the y axis (2018 p.256). Zero — "N/A"
	// — is a legal wire value and is what a Figure prescribing no y reference
	// produces; the ride-through FREQUENCY curves are exactly that case,
	// because their y axis is an absolute frequency in Hz and a frequency is
	// not a percentage of anything.
	YRefType uint8 `json:"y_ref_type"`
	// XRefTypeGone traps a caller still sending the removed field, per entry.
	XRefTypeGone *uint8 `json:"x_ref_type,omitempty"`

	// The opModVoltVar-only family and openLoopTms, documented on the
	// single-curve fields below, which is where they were introduced.
	VRef                       *int64              `json:"vref,omitempty"`
	AutonomousVRefEnable       *bool               `json:"autonomous_vref_enable,omitempty"`
	AutonomousVRefTimeConstant *int64              `json:"autonomous_vref_time_constant,omitempty"`
	OpenLoopTms                *int64              `json:"open_loop_tms,omitempty"`
	Nonconformant              *nonconformantCurve `json:"nonconformant,omitempty"`
	// Description overrides the request's for this curve's own resource. Empty
	// takes the request's, so a multi-curve caller that wants one label for the
	// set does not have to repeat it.
	Description string `json:"description,omitempty"`
}

// adminCurveReq is the JSON body for POST /admin/curve.
type adminCurveReq struct {
	Program int `json:"program"`
	// ResponseRequired overrides the responseRequired bitmap this control
	// carries. Nil takes adminDefaultResponseRequired — the same default
	// POST /admin/control applies — so a curve control ASKS the DUT for the
	// Response lifecycle exactly as a scalar one does.
	//
	// It exists for the same one reason /admin/control's does: a scenario
	// proving the DUT correctly WITHHOLDS a Response nobody asked for has to be
	// able to ask for nothing (0), and 0 is a request for nothing, which is a
	// different document from the attribute being absent.
	ResponseRequired *uint8 `json:"response_required,omitempty"`
	// Curves publishes SEVERAL curves on ONE control. Mutually exclusive with
	// the single-curve fields below — see entries() for the refusal and the
	// file doc for why a procedure needs it.
	Curves []adminCurveEntry `json:"curves,omitempty"`

	Mode   string       `json:"mode"` // volt_var|volt_watt|freq_watt|watt_pf|watt_var|<ride-through>
	Points []curvePoint `json:"points"`
	XMult  int8         `json:"x_mult"` // 10^n multiplier on x values
	YMult  int8         `json:"y_mult"` // 10^n multiplier on y values
	// x_ref_type is GONE (2026-08-14) and STAYS gone. A request still carrying
	// it is REJECTED (400) rather than silently ignored — see XRefTypeGone
	// below. NO revision declares an xRefType element on DERCurve: not IEEE
	// 2030.5-2018 (p.252-253, whose thirteen attributes run
	// autonomousVRefEnable..yRefType), not 2030.5-2023 (p.265-266), and not the
	// vendored draft schema. It is the one genuine phantom of the four this
	// bench once refused, and it is the only one that stayed refused when the
	// anchor was corrected (IW15-027). The x-axis reference is fixed by the MODE
	// at both ends and needs no carriage: volt-var and volt-watt take an
	// effective percent voltage, freq-watt takes Hz, watt-PF takes %setMaxW.
	YRefType uint8 `json:"y_ref_type"` // DERUnitRefType for the y axis (2018 p.256)
	// XRefTypeGone traps a caller still sending the removed field. A pointer,
	// so "absent" and "sent as 0" are distinguishable: silently accepting a
	// request whose x_ref_type the server no longer honours would leave the
	// caller believing it had set something.
	XRefTypeGone *uint8 `json:"x_ref_type,omitempty"`

	// ── The Volt-Var reference family, RESTORED (IW15-027) ────────────────
	//
	// These three were deleted on 2026-08-15 as elements "sep 2.0.4 declares
	// NO such element on DERCurve", and that sentence was TRUE and about the
	// WRONG DOCUMENT. docs/schema/sep-2.0.4.xsd is the pre-publication ZigBee
	// SEP 2.0 draft; IEEE Std 2030.5-2018 declares all three on DERCurve
	// (p.252-253) and 2030.5-2023 declares them too (p.265-266). A bench that
	// cannot serve them cannot put the standard's own Volt-Var curve on the
	// wire, and BASIC-006's Figure 6 prescribes two of them by name.
	//
	// ALL THREE ARE opModVoltVar-ONLY, and that is a SHALL NOT rather than a
	// convention. 2018 p.252, on each of them: "If the curveType is
	// opModVoltVar, then this field MAY be present. If the curveType is not
	// opModVoltVar, then this field SHALL NOT be present." So the handler
	// refuses them on any other mode — a bench that let a caller hang a vRef
	// off a freq-watt curve would be minting a non-conformant document into a
	// conformance bundle, which is the same defect the deletion was trying to
	// prevent, arriving from the other side.

	// VRef is DERCurve.vRef: PerCent [0..1] (2018 p.253), "The nominal ac
	// voltage (rms) adjustment to the voltage curve points for Volt-Var
	// curves."
	//
	// It is LOAD-BEARING, not decoration. 2018 p.250, under opModVoltVar: "If
	// VRef is present in DERCurve, then the x value of each pair is
	// additionally multiplied by VRef/10 000." A curve served with a vRef is a
	// different curve from the same breakpoints without one.
	//
	// A pointer to a SIGNED int64 for the reason OpenLoopTms is: the pointer
	// keeps "absent" distinguishable from "sent as 0" (and 0 is a legal
	// PerCent), and the signed 64-bit width is what lets the handler refuse an
	// out-of-domain value in the standard's own vocabulary rather than leaving
	// encoding/json to answer with a Go type name.
	//
	// NO FIGURE IN THE CATALOG PRESCRIBES IT, so no row authors one today and
	// none claims to. The lever exists because the element is real and the
	// bench's job is to be able to serve the standard; the moment a procedure
	// asks for a vRef, the row can send it without a bench change.
	VRef *int64 `json:"vref,omitempty"`

	// AutonomousVRefEnable is DERCurve.autonomousVRefEnable: boolean [0..1]
	// (2018 p.252). "Enable/disable autonomous vRef adjustment. When enabled,
	// the Volt-Var curve characteristic SHALL be adjusted autonomously as vRef
	// changes and autonomousVRefTimeConstant SHALL be present."
	//
	// CSIP CTP v1.3's Figure 6 (Volt-VAr Settings) prescribes it by name —
	// "opModVoltVar.DERCurve.autonomousVrefEnable", Default false, Test Values
	// false — and BASIC-006 held itself with a gap saying the element did not
	// exist. It does; the row authors it now.
	AutonomousVRefEnable *bool `json:"autonomous_vref_enable,omitempty"`

	// AutonomousVRefTimeConstant is DERCurve.autonomousVRefTimeConstant: UInt32
	// [0..1] (2018 p.253), "Adjustment range for vRef time constant, in
	// hundredths of a second." Figure 6 prescribes it too (Default 0, Test
	// Values 0 — the catalog spells it "autonomousVrefTimeContant").
	AutonomousVRefTimeConstant *int64 `json:"autonomous_vref_time_constant,omitempty"`

	// Nonconformant deliberately violates a stated SHALL, for the NEGATIVE rows
	// that grade what a DUT does with a malformed document.
	//
	// IT IS OPT-IN, PER REQUEST, AND NAMES THE CLAUSE. A conformance bench must
	// not serve a non-conformant document by accident — the evidence would be
	// about a document no conformant server produces — so the ordinary levers
	// above enforce every SHALL they can (vrefFamily), and a row that needs the
	// violation has to ask for it by name. That is the same reasoning the
	// malform channel (malform.go) rests on, at per-request granularity instead
	// of a server-wide armed mode, because these are properties of ONE curve
	// rather than of a resource type.
	Nonconformant *nonconformantCurve `json:"nonconformant,omitempty"`

	Description string `json:"description"`
	DurationS   int    `json:"duration_s"`     // default 300
	StartOffset int    `json:"start_offset_s"` // seconds from now
	Activate    bool   `json:"activate"`       // true = replace curve + control lists
	// FixedVarPct, when present, rides along as an opModFixedVar scalar overlay
	// on the same control, mirroring adminCtrlReq. It is emitted with
	// DERUnitRefType 2 (%setMaxVar) — a percentage of the REACTIVE nameplate;
	// see the emission site for why it used to say RefType 1.
	FixedVarPct *float64 `json:"fixed_var_pct,omitempty"`
	// OpenLoopTms is the DERCurve's own openLoopTms element: the time to reach
	// 90 % of the commanded output after a step change, in HUNDREDTHS of a
	// second, 0 meaning "no limit" (IEEE Std 2030.5-2018 p.253,
	// DERCurve.openLoopTms, [0..1]).
	//
	// It is here because a certification Figure prescribes it and this server
	// could not send it: CSIP CTP v1.3's Figure 6 prints openLoopTms Default 10
	// against Test Values 5, so a BASIC-006 run without this field never offered
	// the DUT the condition the row exists to create, and the row held itself at
	// FAIL saying exactly that. Figure 6 prescribes two more DERCurve scalars —
	// autonomousVrefEnable and autonomousVrefTimeContant, above, restored to
	// this API by IW15-027 — and beyond those four (plus CurveData, the two
	// multipliers, curveType and yRefType) no Figure in the catalog prescribes a
	// DERCurve element at all: rampDecTms/rampIncTms/rampPT1Tms appear in none,
	// and neither does vRef, so no row authors them and none claims to.
	//
	// A pointer to a SIGNED int64, for the two reasons freqDroopReq's fields
	// are: the pointer keeps "absent" distinguishable from "sent as 0", and the
	// signed 64-bit width is what lets the handler refuse an out-of-domain value
	// in the schema's own vocabulary instead of leaving encoding/json to answer
	// with "cannot unmarshal number -1 into Go value of type uint16", which
	// names neither the element nor its type.
	OpenLoopTms *int64 `json:"open_loop_tms,omitempty"`
	// FreqDroop rides along as an INLINE opModFreqDroop element on the same
	// control that carries the curve link, which is the shape CSIP CTP v1.3's
	// Figure 12 prescribes for BASIC-012: ONE DERControl carrying both the
	// frequency-WATT curve (opModFreqWatt, a curve link) and the immediate
	// frequency-DROOP control (opModFreqDroop, inline parameters). See
	// freqdroop.go for the units, the whole-or-nothing rule and the element
	// ordering note.
	FreqDroop *freqDroopReq `json:"freq_droop,omitempty"`
}

// curveTypeForMode maps the request's mode to the IEEE 2030.5-2018 DERCurveType
// code (p.254) and returns whether the mode is recognized.
//
// EVERY ONE OF THESE NUMBERS MOVED on 2026-08-15 (IW15-027) and none of them is
// written here as a literal, which is why they moved correctly: the constants
// live in lexa-proto/csipmodel and were re-derived from the published standard
// there. The comments below record the new value beside the draft-schema value
// each replaced, because the CATALOG's printed curveType — 11 for volt-var, 12
// for volt-watt, 0 for freq-watt — used to disagree with what this bench emitted
// and now AGREES with it exactly. See suitecsip/register.go's curveTypeAgreement.
func curveTypeForMode(mode string) (uint16, bool) {
	switch mode {
	case "volt_var":
		return model.CurveTypeVoltVar, true // 2018 p.254: 11 (the draft said 0)
	case "freq_watt":
		return model.CurveTypeFreqWatt, true // 2018 p.254: 0 (the draft said 1)
	case "watt_pf":
		return model.CurveTypeWattPF, true // 2018 p.254: 13 (the draft said 2)
	case "volt_watt":
		return model.CurveTypeVoltWatt, true // 2018 p.254: 12 (the draft said 3)
	case "watt_var":
		// opModWattVar. It is the axis SunSpec model 712 actually implements,
		// and until curve plan #32 there was no lever that could put an
		// <opModWattVar> DERCurveLink on the wire at all — so the strongest
		// curve axis the 7xx product has was the one nothing exercised, and
		// BASIC-015's opModWattPF was graded against 712 in its place. Both
		// halves of that substitution are now expressible separately, which is
		// the only way a row can show they are different commands.
		return model.CurveTypeWattVar, true // 2018 p.254: 14 (the draft said 10)

	// ── The ten RIDE-THROUGH curves (curve plan #32) ─────────────────────────
	//
	// All ten are real IEEE Std 2030.5-2018 DERControlBase elements with real
	// DERCurveType codes (p.254, cross-cited element by element on p.248-250),
	// and until now this server could publish none of them: BASIC-004 and
	// BASIC-005 were decided-FAIL rows held by a constant explaining that the
	// bench had no lever. The lever is here.
	//
	// THE FULL TEN, not the six the two Figures prescribe. The MayTrip modes
	// appear in no Figure of this catalog and no row authors one — a value
	// nothing asks for is a value nothing tests, which is the suite's own rule
	// — but the SERVER's job is to be able to serve the standard, and a
	// vocabulary with holes in it invites a future row to reach for a mode that
	// is missing for no reason. Every code comes from lexa-proto/csipmodel
	// rather than being written here as a literal, for the reason the four
	// above give: these constants were re-derived from the published standard
	// after IW15-027 found the bench emitting the pre-publication draft's
	// numbering.
	//
	// MOMENTARY CESSATION EXISTS ONLY ON THE VOLTAGE SIDE. 2018 p.254 assigns
	// codes to opModLVRTMomentaryCessation (9) and opModHVRTMomentaryCessation
	// (4) and assigns NONE to a frequency equivalent, so there is no
	// lfrt_momentary_cessation / hfrt_momentary_cessation mode here and a
	// caller asking for one gets the ordinary unknown-mode 400 rather than a
	// curve labelled with an invented code.
	case "lvrt_must_trip":
		return model.CurveTypeLVRTMustTrip, true // 2018 p.254: 10, cross-cited p.250
	case "lvrt_may_trip":
		return model.CurveTypeLVRTMayTrip, true // 2018 p.254: 8, cross-cited p.249
	case "lvrt_momentary_cessation":
		return model.CurveTypeLVRTMomentaryCessation, true // 2018 p.254: 9, cross-cited p.250
	case "hvrt_must_trip":
		return model.CurveTypeHVRTMustTrip, true // 2018 p.254: 5, cross-cited p.249
	case "hvrt_may_trip":
		return model.CurveTypeHVRTMayTrip, true // 2018 p.254: 3, cross-cited p.249
	case "hvrt_momentary_cessation":
		return model.CurveTypeHVRTMomentaryCessation, true // 2018 p.254: 4, cross-cited p.249
	case "lfrt_must_trip":
		return model.CurveTypeLFRTMustTrip, true // 2018 p.254: 7, cross-cited p.249
	case "lfrt_may_trip":
		return model.CurveTypeLFRTMayTrip, true // 2018 p.254: 6, cross-cited p.249
	case "hfrt_must_trip":
		return model.CurveTypeHFRTMustTrip, true // 2018 p.254: 2, cross-cited p.249
	case "hfrt_may_trip":
		return model.CurveTypeHFRTMayTrip, true // 2018 p.254: 1, cross-cited p.248
	default:
		return 0, false
	}
}

// curveModes is the mode vocabulary, in the order a 400 lists it. Derived from
// nothing — it is the list, and curveTypeForMode is the switch over it — so the
// two are kept in step by TestCurveModeVocabularyIsComplete rather than by a
// comment asking a reader to remember.
var curveModes = []string{
	"volt_var", "volt_watt", "freq_watt", "watt_pf", "watt_var",
	"lvrt_must_trip", "lvrt_may_trip", "lvrt_momentary_cessation",
	"hvrt_must_trip", "hvrt_may_trip", "hvrt_momentary_cessation",
	"lfrt_must_trip", "lfrt_may_trip", "hfrt_must_trip", "hfrt_may_trip",
}

// nonconformantCurve is the deliberate-violation opt-in. Each field names the
// SHALL it breaks, so a reader of a request — or of a bundle carrying it — can
// see which sentence the row is testing the DUT against.
type nonconformantCurve struct {
	// AutonomousVRefWithoutTimeConstant serves autonomousVRefEnable=true with
	// NO autonomousVRefTimeConstant, violating IEEE Std 2030.5-2018 p.252's
	// second sentence: "When enabled, the Volt-Var curve characteristic SHALL be
	// adjusted autonomously as vRef changes and autonomousVRefTimeConstant SHALL
	// be present."
	//
	// A conformant DUT REFUSES this document. It is a well-formedness verdict
	// rather than a capability one, so it stands whether or not the DUT could
	// ever arm the adjustment — which is exactly what makes it a different test
	// from the ACCEPTED enable=true-with-time-constant shape beside it.
	AutonomousVRefWithoutTimeConstant bool `json:"autonomous_vref_without_time_constant,omitempty"`

	// VRef serves a vRef the PerCent type does not admit, bypassing the domain
	// check in vrefFamily. IEEE Std 2030.5-2018 p.167 gives PerCent the domain
	// "0 to 10 000"; a UInt16 carries six times that ceiling, so this is the
	// lever for grading what a DUT does with, say, 65535 — apply it and command
	// the curve at 6.5x the voltages the head end named, or refuse it.
	//
	// A pointer: 0 is IN domain and would be an ordinary request, so a
	// value-typed field could not tell "no violation asked for" from "serve a
	// zero".
	VRef *int64 `json:"vref,omitempty"`
}

// armed reports whether any deliberate violation was requested.
func (n *nonconformantCurve) armed() bool {
	return n != nil && (n.AutonomousVRefWithoutTimeConstant || n.VRef != nil)
}

// voltVarOnlyMode is the mode the three vRef-family elements may be served on.
//
// IEEE Std 2030.5-2018 p.252-253 attaches the identical sentence to
// autonomousVRefEnable, autonomousVRefTimeConstant and vRef: "If the curveType
// is opModVoltVar, then this field MAY be present. If the curveType is not
// opModVoltVar, then this field SHALL NOT be present."
const voltVarOnlyMode = "volt_var"

// vrefFamily validates the three opModVoltVar-only DERCurve elements and renders
// them into the model's own widths, or returns the reason they cannot be served.
//
// It is ONE function for all three because the SHALL NOT is one rule: a caller
// that hangs any of them off a non-volt-var curve gets the same refusal naming
// the same sentence, and a future fourth member of the family joins here rather
// than growing a fourth almost-identical check somewhere else.
//
// IT TAKES ONE ENTRY, NOT THE REQUEST. The SHALL NOT is a property of ONE
// curve's curveType, so a four-curve control gets four independent checks: a
// volt-var entry may carry a vRef while the ride-through entry beside it may
// not, and a per-request check would have let the first authorise the second.
func vrefFamily(req *adminCurveEntry) (vref *model.PerCent, enable *bool, tms *uint32, err error) {
	named := map[string]bool{
		"vref":                          req.VRef != nil,
		"autonomous_vref_enable":        req.AutonomousVRefEnable != nil,
		"autonomous_vref_time_constant": req.AutonomousVRefTimeConstant != nil,
	}
	var sent []string
	for k, v := range named {
		if v {
			sent = append(sent, k)
		}
	}
	sort.Strings(sent)
	if len(sent) > 0 && req.Mode != voltVarOnlyMode {
		return nil, nil, nil, fmt.Errorf("%s may only be served on a %s curve: IEEE Std 2030.5-2018 "+
			"p.252-253 says of each of vRef, autonomousVRefEnable and autonomousVRefTimeConstant "+
			"\"If the curveType is not opModVoltVar, then this field SHALL NOT be present\", and this "+
			"request's mode is %q. Remove the field, or publish it on a volt_var curve",
			strings.Join(sent, " and "), voltVarOnlyMode, req.Mode)
	}
	if v := req.VRef; v != nil {
		// PerCent is UInt16, hundredths of a percent, 0..10000 (2018 p.167).
		// The domain is the TYPE's, not uint16's: 10001 parses fine and means
		// nothing.
		if *v < 0 || *v > 10000 {
			return nil, nil, nil, fmt.Errorf("DERCurve.vRef %d is outside PerCent's domain [0,10000] "+
				"(IEEE Std 2030.5-2018 p.167: \"Used for percentages, specified in hundredths of a "+
				"percent, 0 to 10 000. (10 000 = 100%%)\"). Note the UNIT: this element is a percentage, "+
				"not volts — the 240 this bench once served on its static fixture was a volts value in a "+
				"PerCent element, which is why the restored lever does not restore that number",
				*v)
		}
		p := model.PerCent{Value: uint16(*v)}
		vref = &p
	}
	if b := req.AutonomousVRefEnable; b != nil {
		v := *b
		enable = &v
		// 2018 p.252: when autonomous adjustment is ENABLED, the time constant
		// "SHALL be present". A bench that let a caller enable it without one
		// would serve a document the standard forbids.
		if v && req.AutonomousVRefTimeConstant == nil {
			return nil, nil, nil, fmt.Errorf("autonomous_vref_enable is true without an " +
				"autonomous_vref_time_constant: IEEE Std 2030.5-2018 p.252 says that when autonomous " +
				"vRef adjustment is enabled the Volt-Var curve \"SHALL be adjusted autonomously as vRef " +
				"changes and autonomousVRefTimeConstant SHALL be present\"")
		}
	}
	if v := req.AutonomousVRefTimeConstant; v != nil {
		if *v < 0 || *v > math.MaxUint32 {
			return nil, nil, nil, fmt.Errorf("DERCurve.autonomousVRefTimeConstant %d is outside UInt32's "+
				"wire domain [0,%d] (IEEE Std 2030.5-2018 p.253; the unit is hundredths of a second)",
				*v, uint32(math.MaxUint32))
		}
		n := uint32(*v)
		tms = &n
	}
	return vref, enable, tms, nil
}

// setCurveLink attaches the curve href to the DERControlBase link field that
// matches the mode (volt_var→OpModVoltVar, etc.).
//
// It is called ONCE PER ENTRY on the SAME base, which is what puts four curves
// on one control: each mode owns a different CurveLink field, so the four
// assignments do not collide. Two entries of the SAME mode would collide, and
// entries() refuses that before this is ever reached — silently overwriting
// would publish one curve while the caller believed it had sent two.
func setCurveLink(b *model.ExtendedDERControlBase, mode, href string) {
	link := &model.CurveLink{Href: href}
	switch mode {
	case "volt_var":
		b.OpModVoltVar = link
	case "volt_watt":
		b.OpModVoltWatt = link
	case "freq_watt":
		b.OpModFreqWatt = link
	case "watt_pf":
		b.OpModWattPF = link
	case "watt_var":
		b.OpModWattVar = link
	case "lvrt_must_trip":
		b.OpModLVRTMustTrip = link
	case "lvrt_may_trip":
		b.OpModLVRTMayTrip = link
	case "lvrt_momentary_cessation":
		b.OpModLVRTMomentaryCessation = link
	case "hvrt_must_trip":
		b.OpModHVRTMustTrip = link
	case "hvrt_may_trip":
		b.OpModHVRTMayTrip = link
	case "hvrt_momentary_cessation":
		b.OpModHVRTMomentaryCessation = link
	case "lfrt_must_trip":
		b.OpModLFRTMustTrip = link
	case "lfrt_may_trip":
		b.OpModLFRTMayTrip = link
	case "hfrt_must_trip":
		b.OpModHFRTMustTrip = link
	case "hfrt_may_trip":
		b.OpModHFRTMayTrip = link
	}
}

// entries resolves a request into the list of curves it publishes, applying the
// single-curve back-compatibility rule and refusing the ambiguous shape.
//
// THE REFUSAL IS THE POINT. A request carrying both a top-level `mode` and a
// `curves` array has two answers to "what did this publish", and a server that
// picked one would put a control on the wire that the caller's own record of
// the request does not describe. That is the class of defect a conformance
// bundle cannot survive: the evidence would be about a document nobody
// intended. So it is a 400 naming both halves.
//
// DUPLICATE MODES ARE REFUSED for the same reason one level down. Two entries
// of one mode write the same DERControlBase CurveLink field, so the second
// would silently replace the first and the control would carry one curve where
// the caller sent two — and, worse, both DERCurve resources would still be
// published and fetchable, so the bench would be serving a curve no control
// references.
func (r *adminCurveReq) entries() ([]adminCurveEntry, error) {
	singleNamed := r.Mode != "" || len(r.Points) > 0
	switch {
	case len(r.Curves) > 0 && singleNamed:
		return nil, fmt.Errorf("this request carries BOTH a top-level curve (mode=%q, %d point(s)) and a "+
			"`curves` array of %d entr(ies), and the two are alternatives: the top-level fields are the "+
			"single-curve shape kept for callers written before multi-curve controls existed, and `curves` "+
			"is the shape a Figure prescribing several curves on ONE DERControl needs. Sending both leaves "+
			"no answer to what this control published. Send one or the other",
			r.Mode, len(r.Points), len(r.Curves))
	case len(r.Curves) == 0:
		// The implicit one-entry request: every top-level field, unchanged.
		return []adminCurveEntry{{
			Mode: r.Mode, Points: r.Points, XMult: r.XMult, YMult: r.YMult,
			YRefType: r.YRefType, XRefTypeGone: r.XRefTypeGone,
			VRef: r.VRef, AutonomousVRefEnable: r.AutonomousVRefEnable,
			AutonomousVRefTimeConstant: r.AutonomousVRefTimeConstant,
			OpenLoopTms:                r.OpenLoopTms, Nonconformant: r.Nonconformant,
		}}, nil
	}
	seen := map[string]int{}
	for i, e := range r.Curves {
		if prev, dup := seen[e.Mode]; dup {
			return nil, fmt.Errorf("curves[%d] and curves[%d] both carry mode %q: a DERControlBase has one "+
				"CurveLink field per mode, so the second would silently replace the first and this control "+
				"would carry one curve where the request sent two", prev, i, e.Mode)
		}
		seen[e.Mode] = i
	}
	return r.Curves, nil
}

func (s *Server) handleAdminCurve(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.adminCurvePost(w, r)
	case http.MethodDelete:
		s.adminCurveDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// validatedCurve is one entry after every check has passed, with its values
// already rendered into the model's own widths.
//
// The whole list is built BEFORE anything is stored, which is the multi-curve
// form of a rule this handler already followed: a request whose THIRD curve is
// malformed must publish none of them, or a caller that asked for the four
// curves of Figure 4 gets two of them plus a 400 and cannot tell what state the
// bench was left in.
type validatedCurve struct {
	entry       adminCurveEntry
	curveType   uint16
	openLoopTms *uint16
	vref        *model.PerCent
	autoEnable  *bool
	autoTms     *uint32
}

// validateCurveEntry runs every per-curve check. label prefixes the error with
// the entry it is about ("curves[2]: ...") on a multi-curve request and is
// empty on the single-curve shape, so a caller written before this change gets
// character-identical error text.
func validateCurveEntry(label string, e adminCurveEntry) (validatedCurve, error) {
	fail := func(format string, args ...any) (validatedCurve, error) {
		return validatedCurve{}, fmt.Errorf(label+format, args...)
	}
	if e.XRefTypeGone != nil {
		return fail("x_ref_type is not a field of this API: NO revision of IEEE 2030.5 declares an " +
			"xRefType element on DERCurve — not 2018 (p.252-253), not 2023 (p.265-266), not the " +
			"vendored draft — so this server cannot serve one. Remove it from the request; the x-axis " +
			"reference is fixed by the mode. (vRef, autonomousVRefEnable and autonomousVRefTimeConstant " +
			"were refused alongside it until 2026-08-15 and are now SERVED: those three are real 2018 " +
			"elements and the refusal was an artifact of a draft-schema anchor. xRefType is the one " +
			"genuine phantom of the four.)")
	}
	curveType, ok := curveTypeForMode(e.Mode)
	if !ok {
		return fail("mode must be one of %s", strings.Join(curveModes, "|"))
	}
	// Both authored elements are validated BEFORE anything is stored: a request
	// whose content cannot be authored must publish no curve either.
	openLoopTms, err := curveOpenLoopTms(e.OpenLoopTms)
	if err != nil {
		return fail("%s", err)
	}
	// The vRef family, per entry: the SHALL NOT it enforces is a property of
	// THIS curve's curveType and not of the request.
	vref, autoEnable, autoTms, err := vrefFamily(&e)
	if err != nil {
		return fail("%s", err)
	}
	// The deliberate violations, applied AFTER the conformant path has had its
	// say — so an armed entry still has to be well-formed in every respect it
	// did not ask to break, and a typo elsewhere in it is still a 400 rather
	// than being swallowed by the opt-in.
	if e.Nonconformant.armed() {
		if e.Mode != voltVarOnlyMode {
			return fail("nonconformant vRef violations are only expressible on a " + voltVarOnlyMode +
				" curve: the SHALLs they break (IEEE Std 2030.5-2018 p.252-253) are the ones that apply " +
				"WHEN the curveType is opModVoltVar. On any other mode the elements are already refused " +
				"by the SHALL NOT, which is a different test")
		}
		if e.Nonconformant.AutonomousVRefWithoutTimeConstant {
			enable := true
			autoEnable, autoTms = &enable, nil
		}
		if v := e.Nonconformant.VRef; v != nil {
			if *v < 0 || *v > 65535 {
				return fail("nonconformant.vref %d is outside UInt16's WIRE domain "+
					"[0,65535]: this lever exists to serve a value PerCent does not admit, not one the "+
					"XML type cannot carry — an element that cannot be encoded is a different defect and "+
					"this server has no way to put it on the wire", *v)
			}
			p := model.PerCent{Value: uint16(*v)}
			vref = &p
		}
	}
	return validatedCurve{entry: e, curveType: curveType, openLoopTms: openLoopTms,
		vref: vref, autoEnable: autoEnable, autoTms: autoTms}, nil
}

// adminCurvePublished is one curve this request put on the wire, as the
// response reports it.
type adminCurvePublished struct {
	Mode      string `json:"mode"`
	CurveType uint16 `json:"curve_type"`
	CurveMRID string `json:"curve_mrid"`
	CurveHref string `json:"curve_href"`
}

// adminCurveResp is POST /admin/curve's answer.
//
// CurveMRID/CurveHref name the FIRST curve and are kept for the callers that
// read them before multi-curve controls existed. Curves is the whole list, and
// a caller publishing a Figure with several curves must read that instead: the
// first entry alone would let a row report one href as "the" curve it published
// while three more went out beside it unrecorded.
type adminCurveResp struct {
	MRID      string                `json:"mrid"`
	CurveMRID string                `json:"curve_mrid"`
	CurveHref string                `json:"curve_href"`
	Curves    []adminCurvePublished `json:"curves"`
}

func (s *Server) adminCurvePost(w http.ResponseWriter, r *http.Request) {
	var req adminCurveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}
	entries, err := req.entries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	valid := make([]validatedCurve, 0, len(entries))
	modes := make([]string, 0, len(entries))
	for i, e := range entries {
		label := ""
		if len(req.Curves) > 0 {
			label = fmt.Sprintf("curves[%d]: ", i)
		}
		vc, err := validateCurveEntry(label, e)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		valid = append(valid, vc)
		modes = append(modes, e.Mode)
	}
	droop, err := req.FreqDroop.toModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.DurationS <= 0 {
		req.DurationS = 300
	}
	if req.Description == "" {
		req.Description = fmt.Sprintf("Admin %s curve", strings.Join(modes, "+"))
	}
	for _, vc := range valid {
		if !vc.entry.Nonconformant.armed() {
			continue
		}
		log.Printf("[gridsim] POST /admin/curve: NONCONFORMANT BY REQUEST — program=%d mode=%s "+
			"autonomous_vref_without_time_constant=%v vref=%v. This document deliberately violates a "+
			"stated SHALL (IEEE Std 2030.5-2018 p.252-253) and exists to grade a DUT's refusal",
			req.Program, vc.entry.Mode, vc.entry.Nonconformant.AutonomousVRefWithoutTimeConstant,
			vc.entry.Nonconformant.VRef)
	}

	now := s.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// ── 1. upsert the curves into the program's DERCurveList (/derp/{p}/dc) ──
	dcPath := fmt.Sprintf("/derp/%d/dc", req.Program)
	cl, _ := s.resources[dcPath].(*model.DERCurveList)
	if cl == nil {
		cl = &model.DERCurveList{Resource: model.Resource{Href: dcPath}, PollRate: 300}
		s.resources[dcPath] = cl
	}
	if req.Activate {
		cl.DERCurve = nil // replace: these become the only curves
	}

	// ── 2. build the ExtendedDERControl that binds every curve ──────────────
	//
	// ONE base, one link per entry. This is what makes "a DERControl instance
	// with the values in Figure 4" a document this bench can actually serve.
	base := model.ExtendedDERControlBase{}
	published := make([]adminCurvePublished, 0, len(valid))
	for _, vc := range valid {
		e := vc.entry
		idx := len(cl.DERCurve)
		curveHref := fmt.Sprintf("/derp/%d/dc/%d", req.Program, idx)
		desc := e.Description
		if desc == "" {
			desc = req.Description
		}
		curve := model.DERCurve{
			Resource: model.Resource{Href: curveHref},
			// The INDEX rides in the mRID as well as the mode. Two curves of one
			// mode are already refused, so mode alone would be unique within a
			// request — but a non-activating POST appends, and two requests in
			// the same clock second would otherwise mint the same mRID for two
			// resources at different hrefs.
			MRID:         fmt.Sprintf("CURVE-%s-%d-%d-%d", strings.ToUpper(e.Mode), req.Program, idx, now),
			Description:  desc,
			CreationTime: now,
			CurveType:    vc.curveType,
			XMultiplier:  e.XMult,
			YMultiplier:  e.YMult,
			// The opModVoltVar-only family (2018 p.252-253). Nil unless the caller
			// authored them, and vrefFamily has already refused them on any other
			// mode, so a non-volt-var curve cannot carry one however this struct is
			// later edited.
			//
			// csipmodel has NO XRefType field any more and this server no longer
			// has anywhere to put one: that deletion (lexa-proto 9856710) was the
			// one of the four that survived the anchor correction.
			VRef:                       vc.vref,
			AutonomousVRefEnable:       vc.autoEnable,
			AutonomousVRefTimeConstant: vc.autoTms,
			YRefType:                   e.YRefType,
			CurveData:                  pointsToCurveData(e.Points),
			// openLoopTms rides on the DERCurve, not on the control: IEEE Std
			// 2030.5-2018 p.253 declares it a child of DERCurve, and the Figure
			// that prescribes it
			// (Figure 6) names it "opModVoltVar.DERCurve.openLoopTms" for that
			// reason. A copy, so a later mutation of the request cannot reach a
			// curve this server has already published.
			OpenLoopTms: vc.openLoopTms,
		}
		cl.DERCurve = append(cl.DERCurve, curve)
		setCurveLink(&base, e.Mode, curveHref)
		published = append(published, adminCurvePublished{
			Mode: e.Mode, CurveType: vc.curveType, CurveMRID: curve.MRID, CurveHref: curveHref,
		})
	}
	cl.All = uint32(len(cl.DERCurve))
	cl.Results = cl.All

	// A curve-linked DERControl carries an HREF, not content. Until now the
	// server MINTED that href and stored only the list, so every individual
	// /derp/{p}/dc/{i} answered 404 and a DUT that followed the link received a
	// link and no curve. That made every curve row's southbound silence
	// unattributable: "the DUT refused the axis" and "the bench served the
	// curve nowhere" look identical from outside, which is exactly the
	// ambiguity critDERCurveResolvable was written to disambiguate and could
	// not, because the bench always 404'd. Publish the individual resources so
	// the link a control carries actually resolves.
	// The clear MUST come first. An activating POST truncates the list to one
	// entry, so republishing 0..len-1 alone would leave every /derp/{p}/dc/{i}
	// this program had published above that index still served — a curve at an
	// href the list no longer mentions, which is precisely the leak the
	// teardown exists to prevent, arriving through the publish path instead.
	s.clearCurveResourcesLocked(req.Program)
	s.publishCurveResourcesLocked(req.Program, cl)

	// Ensure the program advertises its DERCurveList so the walker discovers
	// the curve (program 0 already links it; 1/2 get the link on first use).
	s.ensureCurveListLinkLocked(req.Program, dcPath, cl.All)

	// ── 3. finish the control the curve links were bound into ─────────────
	activeNow := req.StartOffset <= 0
	var status uint8
	if activeNow {
		status = 1 // Active
	} else {
		status = 0 // Scheduled
	}
	// The inline droop, on the SAME control as the curve link. Figure 12
	// prescribes exactly that pairing for BASIC-012 — opModFreqWatt (Curve) and
	// opModFreqDroop (Immediate) on one DERControl — and publishing them as two
	// controls would have made the row's own procedure unfollowable.
	base.OpModFreqDroop = droop
	if req.FixedVarPct != nil {
		base.OpModFixedVar = &model.FixedVar{
			// DERUnitRefType 2 = %setMaxVar: a percentage of the REACTIVE
			// nameplate, which is what this field has always meant end-to-end
			// ("fixed_var_pct ... signed % of setMaxVar" on the bus doc both
			// consumers carry it on).
			//
			// It used to emit RefType 1 under the comment "1 = rated
			// capacity". That is the wrong code for that sentence: 1 is
			// %setMaxW, a percentage of the ACTIVE-power nameplate. It went
			// unnoticed while derbase ignored refType entirely and resolved
			// every code against VarMaxPct — the fixture was wrong and the
			// product was wrong in the opposite direction, and the two
			// cancelled. lexa-proto d60e1ca made derbase READ the code, so
			// they stop cancelling: on the 60 kW / 26.4 kvar bench inverter
			// this would ask 80 % of 60 kW = 48 kvar from a 26.4 kvar machine
			// (DIFF-CTL-001), and 24x that on a 2 kvar one (DIFF-CTL-002).
			RefType: model.RefTypeSetMaxVar,
			Value:   model.SignedPerCent{Value: int16(math.Round(*req.FixedVarPct))},
		}
	}
	// The RespondableResource attributes, which this path used to omit entirely.
	//
	// A curve-bound control is a DERControl like any other and the DUT must
	// answer it — but IEEE 2030.5 does not have a client volunteer a Response
	// nobody asked for, so without these a spec-honest DUT answering with
	// SILENCE is correct, and any criterion grading the Response lifecycle on a
	// curve row would be grading the bench's own omission. That is the same
	// false reading toExtendedControl's doc records for the scalar-onto-widened
	// -program path; this path had the identical hole, and nothing caught it
	// because no curve row graded Responses until now.
	responseRequired := model.ResponseRequired(adminDefaultResponseRequired)
	if req.ResponseRequired != nil {
		responseRequired = model.ResponseRequired(*req.ResponseRequired)
	}
	ctrl := model.ExtendedDERControl{
		Resource:         model.Resource{Href: fmt.Sprintf("/derp/%d/derc/curve", req.Program)},
		ReplyTo:          adminResponseReplyTo,
		ResponseRequired: &responseRequired,
		MRID:             fmt.Sprintf("DERC-%s-CURVE-%d", progPrefixes[req.Program], now),
		Description:      req.Description,
		CreationTime:     now,
		EventStatus: &model.EventStatus{
			CurrentStatus: status,
			DateTime:      now,
		},
		Interval: model.DateTimeInterval{
			Duration: uint32(req.DurationS),
			Start:    now + int64(req.StartOffset),
		},
		DERControlBase: base,
	}

	// ── 4. store into derc (scheduled list the walker reads) ──────────────
	dercPath := fmt.Sprintf("/derp/%d/derc", req.Program)
	s.putExtendedControl(dercPath, ctrl, req.Activate)

	// ── 5. mirror active into actderc (status display; active events only) ─
	actPath := fmt.Sprintf("/derp/%d/actderc", req.Program)
	switch {
	case req.Activate && activeNow:
		s.resources[actPath] = &model.ExtendedDERControlList{
			Resource:   model.Resource{Href: actPath},
			All:        1,
			Results:    1,
			PollRate:   s.controlListPollRateLocked(),
			DERControl: []model.ExtendedDERControl{ctrl},
		}
	case req.Activate:
		// future event with activate=true clears the stale active list
		s.resources[actPath] = &model.ExtendedDERControlList{
			Resource: model.Resource{Href: actPath}, PollRate: s.controlListPollRateLocked(),
		}
	case activeNow:
		s.putExtendedControl(actPath, ctrl, false)
	}

	// This endpoint mints its own mRIDs and can REPLACE the whole list
	// (activate), so it can retire a control an operator had armed an
	// explicit-nil marker on. Sweep the orphans for the same reason
	// /admin/control does — see explicitnil.go.
	s.forgetOrphanedExplicitNilLocked(req.Program)

	hrefs := make([]string, 0, len(published))
	for _, p := range published {
		hrefs = append(hrefs, p.Mode+"->"+p.CurveHref)
	}
	log.Printf("[gridsim] POST /admin/curve: program=%d curves=%d [%s] control=%s active_now=%v",
		req.Program, len(published), strings.Join(hrefs, " "), ctrl.MRID, activeNow)

	resp := adminCurveResp{MRID: ctrl.MRID, Curves: published}
	if len(published) > 0 {
		// The first curve, for the pre-multi-curve callers. See adminCurveResp.
		resp.CurveMRID, resp.CurveHref = published[0].CurveMRID, published[0].CurveHref
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// adminCurveDelete clears the program's bound control (derc + actderc) and
// resets its curve list (/derp/{p}/dc) to the original static curve —
// program 0 back to its Volt-VAr fixture, others back to an empty list.
func (s *Server) adminCurveDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Program int `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}

	now := s.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear the control lists back to empty scalar lists (restores the normal
	// type at these paths so subsequent scalar /admin/control posts are plain).
	for _, path := range []string{
		fmt.Sprintf("/derp/%d/derc", req.Program),
		fmt.Sprintf("/derp/%d/actderc", req.Program),
	} {
		s.resources[path] = &model.DERControlList{
			Resource: model.Resource{Href: path}, PollRate: s.controlListPollRateLocked(),
		}
	}
	// A teardown that leaves a marker behind is the same contamination as one
	// that leaves a fetchable curve behind (explicitnil.go).
	s.forgetOrphanedExplicitNilLocked(req.Program)

	// Reset the curve list to the original static fixture — and with it the
	// INDIVIDUAL curve resources, or a cleared program would go on serving the
	// previous run's curve at an href its control list no longer mentions. A
	// teardown that leaves a fetchable curve behind is the contamination the
	// clear exists to remove.
	dcPath := fmt.Sprintf("/derp/%d/dc", req.Program)
	s.clearCurveResourcesLocked(req.Program)
	reset := staticCurveList(req.Program, now)
	s.resources[dcPath] = reset
	s.publishCurveResourcesLocked(req.Program, reset)
	s.ensureCurveListLinkLocked(req.Program, dcPath, reset.All)

	w.WriteHeader(http.StatusNoContent)
}

// putExtendedControl stores ctrl into the ExtendedDERControlList at path,
// replacing the list when activate is set, else appending. If the path
// currently holds a scalar DERControlList (or nothing), a fresh
// ExtendedDERControlList is created — the append case starts fresh rather than
// mixing control types in one list.
func (s *Server) putExtendedControl(path string, ctrl model.ExtendedDERControl, activate bool) {
	if activate {
		s.resources[path] = &model.ExtendedDERControlList{
			Resource:   model.Resource{Href: path},
			All:        1,
			Results:    1,
			PollRate:   s.controlListPollRateLocked(),
			DERControl: []model.ExtendedDERControl{ctrl},
		}
		return
	}
	el, ok := s.resources[path].(*model.ExtendedDERControlList)
	if !ok {
		el = &model.ExtendedDERControlList{
			Resource: model.Resource{Href: path}, PollRate: s.controlListPollRateLocked(),
		}
		s.resources[path] = el
	}
	el.DERControl = append(el.DERControl, ctrl)
	el.All = uint32(len(el.DERControl))
	el.Results = el.All
}

// publishCurveResourcesLocked serves every DERCurve of a program's list at its
// OWN href, so a DERControl's curve link resolves for a DUT that follows it.
//
// Each entry is stored as a COPY rather than as a pointer into the list's
// backing array: appending to cl.DERCurve reallocates, and a stored pointer
// into the old array would go on serving a curve the list no longer holds.
// Caller must hold s.mu.
func (s *Server) publishCurveResourcesLocked(program int, cl *model.DERCurveList) {
	if cl == nil {
		return
	}
	for i := range cl.DERCurve {
		c := cl.DERCurve[i]
		href := c.Href
		if href == "" {
			href = fmt.Sprintf("/derp/%d/dc/%d", program, i)
			c.Href = href
		}
		s.resources[href] = &c
		s.curveHrefs[href] = true
	}
}

// clearCurveResourcesLocked removes the individually-addressable curve
// resources this server minted for a program. Caller must hold s.mu.
func (s *Server) clearCurveResourcesLocked(program int) {
	prefix := fmt.Sprintf("/derp/%d/dc/", program)
	for href := range s.curveHrefs {
		if strings.HasPrefix(href, prefix) {
			delete(s.resources, href)
			delete(s.curveHrefs, href)
		}
	}
}

// ensureCurveListLinkLocked wires (or refreshes) the DERProgram's
// DERCurveListLink so a walker following /edev/2/fsa/0/derp discovers the
// curve list. Program 0 ships with the link; 1/2 gain it on first curve POST.
// Caller must hold s.mu.
func (s *Server) ensureCurveListLinkLocked(program int, dcPath string, count uint32) {
	dpl, ok := s.resources["/edev/2/fsa/0/derp"].(*model.DERProgramList)
	if !ok || program < 0 || program >= len(dpl.DERProgram) {
		return
	}
	dp := &dpl.DERProgram[program]
	if dp.DERCurveListLink == nil {
		dp.DERCurveListLink = &model.ListLink{Link: model.Link{Href: dcPath}}
	}
	dp.DERCurveListLink.All = count
}

// staticCurveList returns the fixture curve list a DELETE restores a program
// to: program 0's Volt-VAr curve, or an empty list for the others (which have
// no original static curve).
//
// The restored fixture is stamped with the CURRENT server clock rather than the
// tree's build time: creationTime is minOccurs="1" and a teardown that restored
// a zero would serve an invalid document (see staticVoltVarCurve0).
func staticCurveList(program int, now int64) *model.DERCurveList {
	if program == 0 {
		return staticVoltVarCurve0(now)
	}
	path := fmt.Sprintf("/derp/%d/dc", program)
	return &model.DERCurveList{Resource: model.Resource{Href: path}, PollRate: 300}
}

// pointsToCurveData rounds request points into the model's int32 CurveData.
func pointsToCurveData(pts []curvePoint) []model.DERCurveData {
	if len(pts) == 0 {
		return nil
	}
	out := make([]model.DERCurveData, 0, len(pts))
	for _, p := range pts {
		out = append(out, model.DERCurveData{
			XValue: int32(math.Round(p.X)),
			YValue: int32(math.Round(p.Y)),
		})
	}
	return out
}

// ── scalar → extended control conversion (for the type-tolerant scalar
// /admin/control post when a curve has already made derc/actderc extended) ──

// toExtendedControl widens a scalar DERControl into an ExtendedDERControl so a
// scalar /admin/control post can append to a list a prior curve post made
// extended, without mixing types.
//
// ReplyTo/ResponseRequired must ride along explicitly (audit 2026-08-01):
// they are adminCtrlPost's own RespondableResource attributes (see
// adminDefaultResponseRequired/adminResponseReplyTo in admin.go), set fresh on
// every scalar ctrl it builds, and ExtendedDERControl carries the identical
// pair of fields for exactly this reason (der.go's ExtendedDERControl doc:
// "the extended (curve-linked) DERControl carries the same replyTo/
// responseRequired the plain DERControl does"). Before this fix they were the
// only two fields this conversion dropped, so a scalar /admin/control POST
// landing on a program a PRIOR /admin/curve POST had already widened to
// Extended silently served that control with NO replyTo and NO
// responseRequired at all — indistinguishable on the wire from one of the
// standing, non-admin-seeded bench fixtures (buildProgram0's doc) that
// legitimately omit them to exercise the DUT's fallback-to-advertised-default
// path. A conformance check reading either attribute for an admin-posted
// control on a curve-bound program got exactly that false "not requested" /
// "not recovered" reading regardless of what gridsim was actually told to
// serve — see CORE-022's coreResponsesSpec doc and
// TestAdminControl_ScalarPostOntoExtendedProgramKeepsResponseAttrs
// (curve_test.go) for the reproduction.
func toExtendedControl(c model.DERControl) model.ExtendedDERControl {
	return model.ExtendedDERControl{
		Resource:          c.Resource,
		ReplyTo:           c.ReplyTo,
		ResponseRequired:  c.ResponseRequired,
		MRID:              c.MRID,
		Description:       c.Description,
		Version:           c.Version,
		CreationTime:      c.CreationTime,
		EventStatus:       c.EventStatus,
		Interval:          c.Interval,
		DERControlBase:    scalarBaseToExtended(c.DERControlBase),
		RandomizeStart:    c.RandomizeStart,
		RandomizeDuration: c.RandomizeDuration,
	}
}

func scalarBaseToExtended(b model.DERControlBase) model.ExtendedDERControlBase {
	return model.ExtendedDERControlBase{
		OpModConnect:        b.OpModConnect,
		OpModEnergize:       b.OpModEnergize,
		OpModFixedPFAbsorbW: b.OpModFixedPFAbsorbW,
		OpModFixedPFInjectW: b.OpModFixedPFInjectW,
		OpModFixedVar:       b.OpModFixedVar,
		OpModFixedW:         b.OpModFixedW,
		OpModMaxLimW:        b.OpModMaxLimW,
		OpModExpLimW:        b.OpModExpLimW,
		OpModGenLimW:        b.OpModGenLimW,
		OpModImpLimW:        b.OpModImpLimW,
		OpModLoadLimW:       b.OpModLoadLimW,
		RampTms:             b.RampTms,
	}
}

// ── extended → adminCtrlInfo (for GET /admin/status) ──────────────────────

// extCtrlToInfo renders an ExtendedDERControl into the same adminCtrlInfo the
// status endpoint uses for scalar controls, adding the bound-curve label.
func extCtrlToInfo(c model.ExtendedDERControl) adminCtrlInfo {
	info := adminCtrlInfo{
		MRID:        c.MRID,
		Description: c.Description,
		Start:       c.Interval.Start,
		DurationS:   int(c.Interval.Duration),
		Base:        extBaseToInfo(c.DERControlBase),
		Curve:       curveLabel(c.DERControlBase),
	}
	if c.EventStatus != nil {
		info.Status = int(c.EventStatus.CurrentStatus)
	}
	return info
}

// curveLabel renders EVERY bound curve as "<mode> -> <href>", joined by "; ",
// or "" when no curve link is set.
//
// IT USED TO RENDER THE FIRST ONE AND STOP — a switch whose arms each returned
// — which was indistinguishable from a control carrying one curve while there
// was only ever one to carry. A ride-through control carries four, and an
// inspector that showed one of them would tell an operator the bench had
// published a quarter of Figure 4. It also knew four of the fifteen modes:
// watt_var and the ten ride-through curves rendered as "", i.e. as "no curve
// bound at all", which is the worst answer available for a control that has
// one.
func curveLabel(b model.ExtendedDERControlBase) string {
	var parts []string
	for _, l := range []struct {
		mode string
		link *model.CurveLink
	}{
		{"volt_var", b.OpModVoltVar},
		{"volt_watt", b.OpModVoltWatt},
		{"freq_watt", b.OpModFreqWatt},
		{"watt_pf", b.OpModWattPF},
		{"watt_var", b.OpModWattVar},
		{"lvrt_must_trip", b.OpModLVRTMustTrip},
		{"lvrt_may_trip", b.OpModLVRTMayTrip},
		{"lvrt_momentary_cessation", b.OpModLVRTMomentaryCessation},
		{"hvrt_must_trip", b.OpModHVRTMustTrip},
		{"hvrt_may_trip", b.OpModHVRTMayTrip},
		{"hvrt_momentary_cessation", b.OpModHVRTMomentaryCessation},
		{"lfrt_must_trip", b.OpModLFRTMustTrip},
		{"lfrt_may_trip", b.OpModLFRTMayTrip},
		{"hfrt_must_trip", b.OpModHFRTMustTrip},
		{"hfrt_may_trip", b.OpModHFRTMayTrip},
	} {
		if l.link != nil {
			parts = append(parts, l.mode+" -> "+l.link.Href)
		}
	}
	return strings.Join(parts, "; ")
}

// extBaseToInfo mirrors baseToInfo (admin.go) for the extended control base —
// same scalar fields, surfaced identically so status JSON is uniform.
func extBaseToInfo(b model.ExtendedDERControlBase) adminBaseInfo {
	info := adminBaseInfo{
		Connect:  b.OpModConnect,
		Energize: b.OpModEnergize,
	}
	if b.OpModExpLimW != nil {
		v := apW(b.OpModExpLimW)
		info.ExpLimW = &v
	}
	if b.OpModMaxLimW != nil {
		// IW13-001: PerCent, not ActivePower — see baseToInfo's identical
		// correction in admin.go.
		v := int64(b.OpModMaxLimW.Value)
		info.MaxLimW = &v
	}
	if b.OpModImpLimW != nil {
		v := apW(b.OpModImpLimW)
		info.ImpLimW = &v
	}
	if b.OpModGenLimW != nil {
		v := apW(b.OpModGenLimW)
		info.GenLimW = &v
	}
	if b.OpModLoadLimW != nil {
		v := apW(b.OpModLoadLimW)
		info.LoadLimW = &v
	}
	if b.OpModFixedW != nil {
		// IW13-001: SignedPerCent, not ActivePower.
		v := int64(b.OpModFixedW.Value)
		info.FixedW = &v
	}
	if b.OpModTargetW != nil {
		v := apW(b.OpModTargetW)
		info.TargetW = &v
	}
	info.FixedPFInjectW = fixedPFToInfo(b.OpModFixedPFInjectW)
	info.FixedPFAbsorbW = fixedPFToInfo(b.OpModFixedPFAbsorbW)
	if b.OpModFixedVar != nil {
		v := int64(b.OpModFixedVar.Value.Value)
		info.FixedVarPct = &v
	}
	info.FreqDroop = freqDroopToInfo(b.OpModFreqDroop)
	return info
}

// curveOpenLoopTms range-checks the authored openLoopTms and renders it into the
// model's own width, or returns the reason it cannot be served.
//
// It exists so this element gets the SAME error hygiene as the droop's five
// (freqdroop.go): a caller who sends -1 or 70000 is told which element and which
// wire type it missed, in the schema's vocabulary, instead of being handed
// encoding/json's "cannot unmarshal number -1 into Go value of type uint16" —
// which names neither, and which is what this field answered when it was typed
// *uint16 on the request.
func curveOpenLoopTms(v *int64) (*uint16, error) {
	if v == nil {
		return nil, nil
	}
	if *v < 0 || *v > 65535 {
		return nil, fmt.Errorf("DERCurve.openLoopTms %d is outside UInt16's wire domain [0,65535] "+
			"(IEEE Std 2030.5-2018 p.253, DERCurve.openLoopTms: the unit is hundredths of a "+
				"second, and a value of 0 means no limit)", *v)
	}
	n := uint16(*v)
	return &n, nil
}
