package invariant

// curves.go is this package's decode of the SunSpec curve/control models —
// 705 (Volt-Var), 706 (Volt-Watt), 707/708 (Voltage Trip LV/HV), 709/710
// (Frequency Trip LF/HF), 711 (Frequency Droop) and 712 (Watt-Var) — the
// southbound half of every CURVE-linked IEEE 2030.5 control mode.
//
// It exists for the same reason units.go does, and under the same rule
// (doc.go): this package shares ONLY the SunSpec register-offset tables with
// the product and none of its CSIP/derbase interpretation. A referee that asked
// the gateway what it had written down would repeat the gateway's own mistake
// back at it; a referee that reads the DER's registers and re-derives the curve
// from the device's own NPt and scale factors can catch a curve that never
// landed, landed on the wrong model, landed with the wrong points, or was
// "adopted" by a device that only said so (the curve_adopt_lies shape the sims
// already model).
//
// WHAT IS ASSERTABLE HERE, AND WHAT IS NOT
//
// The device sims adopt curves realistically — a writable staging curve, an
// AdptCrvReq/AdptCrvRslt handshake, and a read-only live curve at index 0 that
// reflects the staged points on COMPLETED — but they simulate NO curve PHYSICS:
// a volt-var curve on the sim changes no measured var. So every assertion this
// file supports is about the REGISTERS and the ADOPT STATE, never about an
// effect on output. A caller that wants "the DER's output followed the curve"
// is asking a question this bench cannot answer, and must say so rather than
// answer a different one.
//
// The LIVE curve (index 0) is the only one read. Index 1+ are the writable
// staging curves; content sitting in staging is a curve the device was OFFERED,
// not one it adopted, and grading a staged curve as an adopted one would accept
// exactly the half-completed write the adopt handshake exists to distinguish.
//
// TWO GENERATIONS, ONE REFEREE
//
// This file now decodes BOTH SunSpec curve idioms, and they do not agree about
// what "the live curve" means. That single sentence is the whole of the
// extension and every other difference falls out of it:
//
//	7xx     nested Crv[NCrv]{Pt[NPt]}; the live curve is index 0 and is
//	        read-only; 1..NCrv-1 are writable STAGING slots; an
//	        AdptCrvReq/AdptCrvRslt handshake promotes one into the other, so
//	        "adopted" is a register the device SETS.
//
//	legacy  flat curve[NCrv], banks numbered from 1, twenty inlined point
//	        slots each; NO staging slot and NO handshake. ActCrv SELECTS which
//	        bank is live and ModEna bit 0 switches the function on, so
//	        "adopted" is not a register at all — it is the statement "ActCrv
//	        names the bank whose content this is", and this referee derives it
//	        rather than reading it.
//
// Three consequences a reader must hold on to:
//
//	1. On legacy, Index 0 means "whatever bank ActCrv names", not "bank 0".
//	   Decoding bank 1 unconditionally would grade a curve the device is not
//	   running, which is the same error as grading a 7xx staging slot.
//	2. A live legacy bank may LEGITIMATELY be READWRITE. On 7xx a writable live
//	   curve is suspicious (it suggests the index-0 convention does not hold on
//	   that device); on legacy it is the normal state of every bank, and the
//	   caller must suppress that warning for FamilyLegacy or it fires on every
//	   legacy row.
//	3. DeptRef is 1-BASED on legacy against the 7xx enum's 0-based one. The two
//	   are a translation in both directions and never a copy — see DeptRefName.
//
// A THIRD SHAPE: THE 1547 TRIP BANKS (707/708/709/710)
//
// The ride-through models are a 7xx-family idiom with one extra dimension, and
// it is the dimension that makes them worth a separate paragraph. A trip model
// declares NCrvSet curve-SETS (index 0 live and read-only, 1..NCrvSet-1
// writable staging, promoted by the same AdptCrvReq/AdptCrvRslt handshake), and
// EACH SET holds THREE SUB-CURVES laid end to end — MustTrip, MayTrip and
// MomCess — each with its own ActPt and its own point table. So "the live
// curve" is not a curve at all here: it is three of them.
//
// This referee therefore refuses to answer "what does M707 hold?" with a point
// list. A reading of a trip bank must NAME its sub-curve (CurveView.Sub), and a
// reading that names none carries NO Points at all — see DecodeCurveSubAt. The
// alternative would be to pick one silently, and the two shapes a silent pick
// produces are both wrong in the certifying direction: grading an
// opModLVRTMomentaryCessation curve against the MustTrip sub-curve would report
// a mismatch about a bank that holds exactly what was commanded, and grading a
// MustTrip curve against whichever sub-curve happened to be non-empty would
// report a match for a curve nobody commanded. Describe() renders all three
// sub-curves on every trip reading, addressed or not, so an absence in one is
// visible beside the content of the others.
//
// THE DECODED POINT ORDER IS (TIME, QUANTITY) AND THE REGISTER ORDER IS NOT.
// This is the one place in this file where the two differ, and it is stated
// here because a reader checking a finding against a register dump will
// otherwise think the referee transposed the curve:
//
//	707/708 registers   V (uint16, VNomPct ×V_SF)  then  Tms (uint32, Secs ×Tms_SF)
//	709/710 registers   Hz (uint32, Hz ×Hz_SF)     then  Tms (uint32, Secs ×Tms_SF)
//	decoded CurvePoint  X = Tms (seconds)                Y = the electrical quantity
//
// The normalisation is done HERE, once, because it is the order IEEE 2030.5's
// own ride-through DERCurve uses (x is a duration, y is the percent voltage or
// the frequency — see the axis names below) and the order the LEGACY 129/130
// blocks already store natively. One normalisation in the decoder means one
// comparison in every caller; a swap performed in a caller's binding instead
// would be invisible at the point a verdict is read.
//
// THE POINT NAMED "Tms" IS IN SECONDS. model_707.json and model_709.json both
// give Pt.Tms the units string "Secs", scaled by Tms_SF — not milliseconds,
// whatever the name suggests. A referee that assumed milliseconds would be
// wrong by a factor of 1000 in the direction that certifies: a 0.16 s trip
// commanded and 160 s read back would compare equal. It is the same class of
// trap as the IW15-002a percent/watt pathology, one model family over, and it
// is written down here because nothing in the register image announces it.

import (
	"fmt"
	"math"
	"strings"

	"lexa-proto/sunspec"
)

// CurvePoint is one decoded breakpoint of a curve model's live curve, in the
// device's own engineering units (its scale factors already applied).
type CurvePoint struct {
	X float64
	Y float64
}

// String renders a point the way a finding quotes one.
func (p CurvePoint) String() string { return fmt.Sprintf("(%s, %s)", trimFloat(p.X), trimFloat(p.Y)) }

// CurveAxis is the static description of one curve/control model: which model
// it is, what a reader should call it, and what its two axes MEAN. The axis
// names are load-bearing in a finding — "the DER's 706 live curve holds
// (106 V, 100 W)" tells a reader something "(106, 100)" does not.
type CurveAxis struct {
	Model uint16
	// Family says which SunSpec curve IDIOM this model belongs to, and it is
	// load-bearing rather than decorative: it decides what "the live curve"
	// means (index 0 vs the bank ActCrv names), whether an adopt handshake
	// exists to read, whether DeptRef is 0-based or 1-based, and whether a
	// writable live curve is suspicious or ordinary. See the file doc.
	Family CurveFamily
	// Name is the human label, e.g. "M705 Volt-Var".
	Name string
	// XName/YName name the physical quantity on each axis.
	XName, YName string
	// Pointless marks a model that carries no breakpoint table at all — 711,
	// whose frequency response is a PARAMETRIC droop (deadbands and gains), not
	// a curve of points. A caller correlating breakpoints must not pretend
	// otherwise; see CurveView.Pointless.
	Pointless bool
	// Subcurved marks a model whose curve-SET holds THREE point tables rather
	// than one — the IEEE 1547 trip banks 707/708/709/710, whose MustTrip,
	// MayTrip and MomCess sub-curves are laid end to end inside a single set
	// with a single ActPt each.
	//
	// It is a property of the MODEL and not of a reading, and it exists so that
	// a caller cannot ask a trip bank for "its points" without saying which of
	// the three it means: DecodeCurveSubAt refuses to guess, and CurveView.Sub
	// records the answer on every reading that gave one.
	Subcurved bool
}

// CurveSub names one sub-curve of a 1547 trip bank.
//
// The zero value is SubCurveNone — "this reading addresses no sub-curve" —
// which is the value every non-trip model carries and the value a trip reading
// carries when the caller asked for the SET rather than for one of its curves.
// It is deliberately not an alias for MustTrip: a default that silently meant
// "the must-trip curve" would make every unaddressed read look like a
// measurement of the one sub-curve certification procedures care most about.
type CurveSub int

const (
	// SubCurveNone addresses no sub-curve. A trip reading carrying it has NO
	// Points; its three sub-curves are in SubPoints and are rendered by
	// Describe().
	SubCurveNone CurveSub = iota
	// SubCurveMustTrip is the sub-curve a DER SHALL trip on — IEEE 2030.5's
	// opModLVRTMustTrip / opModHVRTMustTrip / opModLFRTMustTrip /
	// opModHFRTMustTrip.
	SubCurveMustTrip
	// SubCurveMayTrip is the manufacturer-defined region between the must-trip
	// curve and mandatory operation — opMod*MayTrip.
	SubCurveMayTrip
	// SubCurveMomCess is momentary cessation — opModLVRTMomentaryCessation /
	// opModHVRTMomentaryCessation. IT EXISTS ONLY ON THE VOLTAGE MODELS as far
	// as IEEE 2030.5 is concerned: 2018 p.254's DERCurveType assigns codes 4 and
	// 9 to the two VOLTAGE momentary-cessation curves and assigns none to a
	// frequency one. SunSpec's 709/710 register geometry nevertheless carries a
	// third sub-curve, because the trip-model layout is shared, so this package
	// decodes and renders it on the frequency banks too — as content the device
	// holds, never as content a 2030.5 control could have commanded.
	SubCurveMomCess
)

func (s CurveSub) String() string {
	switch s {
	case SubCurveMustTrip:
		return "MustTrip"
	case SubCurveMayTrip:
		return "MayTrip"
	case SubCurveMomCess:
		return "MomCess"
	}
	return "no sub-curve addressed"
}

// TripSubCurves is the fixed order every trip sub-curve is rendered and
// iterated in — the order the register block lays them out (SubCurveOffset707's
// 0/1/2), so a finding reads in the same order as a register dump.
var TripSubCurves = []CurveSub{SubCurveMustTrip, SubCurveMayTrip, SubCurveMomCess}

// CurveFamily is which SunSpec curve idiom a model belongs to.
type CurveFamily string

const (
	// Family7xx is the IEEE 1547-2018 / SunSpec 7xx set: nested curves, a
	// read-only live curve at index 0, writable staging slots, and the §3.1.2
	// AdptCrvReq/AdptCrvRslt handshake.
	Family7xx CurveFamily = "7xx"
	// FamilyLegacy is the legacy 12x set: flat fixed-size banks numbered from
	// 1, no staging slot, no handshake, ActCrv selecting the live bank and
	// ModEna bit 0 switching the function on.
	FamilyLegacy CurveFamily = "12x"
)

// curveAxes is the one table of curve models this package decodes. A model
// absent from it is a model this package will not pretend to understand.
//
// The legacy rows carry their axis names in the LEGACY block's own order, which
// is not always the northbound one: 129/130 store (duration, voltage) with the
// TIME FIRST while IEEE 2030.5's opModLVRTMustTrip curve is (x = duration,
// y = voltage). They agree by accident of naming and not by convention, so the
// names here describe the REGISTERS, which is what this referee reads.
//
// THE TRIP ROWS ARE THE ONE EXCEPTION and their names say so. 707/708/709/710
// store the electrical quantity FIRST and the time second, and this package
// normalises the decoded point to (time, quantity) — see the file doc — so the
// names below describe the DECODED CurvePoint rather than the register order.
// Naming them the other way round would be truthful about the block and would
// mislabel every finding, because every finding quotes the decoded pair.
var curveAxes = []CurveAxis{
	{Model: sunspec.ModelDERVoltVar, Family: Family7xx, Name: "M705 Volt-Var", XName: "V", YName: "var"},
	{Model: sunspec.ModelDERVoltWatt, Family: Family7xx, Name: "M706 Volt-Watt", XName: "V", YName: "W"},
	// 707/708: Pt.V is "VNomPct" — a PER CENT OF NOMINAL VOLTAGE, scaled by
	// V_SF — and Pt.Tms is "Secs", scaled by Tms_SF (model_707.json). Decoded
	// as (seconds, %VNom).
	{Model: sunspec.ModelDERTripLV, Family: Family7xx, Name: "M707 DER Trip LV",
		XName: "s", YName: "%VNom", Subcurved: true},
	{Model: sunspec.ModelDERTripHV, Family: Family7xx, Name: "M708 DER Trip HV",
		XName: "s", YName: "%VNom", Subcurved: true},
	// 709/710: Pt.Hz is "Hz" — an ABSOLUTE frequency, not a deviation and not a
	// percentage — scaled by Hz_SF, and Pt.Tms is "Secs" (model_709.json).
	// Decoded as (seconds, Hz). The absoluteness is why the frequency Figure
	// prescribes no yRefType while the voltage one prescribes %setEffectiveV.
	{Model: sunspec.ModelDERTripLF, Family: Family7xx, Name: "M709 DER Trip LF",
		XName: "s", YName: "Hz", Subcurved: true},
	{Model: sunspec.ModelDERTripHF, Family: Family7xx, Name: "M710 DER Trip HF",
		XName: "s", YName: "Hz", Subcurved: true},
	{Model: sunspec.ModelDERFreqDroop, Family: Family7xx, Name: "M711 Frequency Droop", XName: "Hz", YName: "W",
		Pointless: true},
	{Model: sunspec.ModelDERWattVar, Family: Family7xx, Name: "M712 Watt-Var", XName: "W", YName: "var"},

	{Model: sunspec.ModelVoltVarLegacy, Family: FamilyLegacy, Name: "M126 Static Volt-VAR",
		XName: "%VRef", YName: "%DeptRef"},
	{Model: sunspec.ModelLVRTLegacy, Family: FamilyLegacy, Name: "M129 LVRT Must-Disconnect",
		XName: "s", YName: "%VRef"},
	{Model: sunspec.ModelHVRTLegacy, Family: FamilyLegacy, Name: "M130 HVRT Must-Disconnect",
		XName: "s", YName: "%VRef"},
	{Model: sunspec.ModelWattPFLegacy, Family: FamilyLegacy, Name: "M131 Watt-PF",
		XName: "%WMax", YName: "PF"},
	{Model: sunspec.ModelVoltWattLegacy, Family: FamilyLegacy, Name: "M132 Volt-Watt",
		XName: "%VRef", YName: "%DeptRef"},
	{Model: sunspec.ModelFreqWattLegacy, Family: FamilyLegacy, Name: "M134 Freq-Watt Curve",
		XName: "Hz", YName: "%WRef"},
}

// LegacyCurveModels are the 12x curve models this referee decodes, ascending.
// Exported so a caller that must decide which GENERATION a device belongs to
// asks this package rather than keeping a second list.
func LegacyCurveModels() []uint16 {
	out := make([]uint16, 0, len(curveAxes))
	for _, a := range curveAxes {
		if a.Family == FamilyLegacy {
			out = append(out, a.Model)
		}
	}
	return out
}

// CurveModels are the models a register-image source reads for curve evidence,
// in ascending order. Exported so a source (and a test) reads the same set this
// file can decode, rather than a second list that can drift from it.
func CurveModels() []uint16 {
	out := make([]uint16, 0, len(curveAxes))
	for _, a := range curveAxes {
		out = append(out, a.Model)
	}
	return out
}

// CurveAxisOf returns the static description of a curve model, and false for a
// model this package does not decode.
func CurveAxisOf(model uint16) (CurveAxis, bool) {
	for _, a := range curveAxes {
		if a.Model == model {
			return a, true
		}
	}
	return CurveAxis{}, false
}

// CurveView is one curve model's LIVE curve (index 0) plus the adopt-handshake
// state around it, as the device's own registers report them.
//
// Present is false when the device does not serve the model at all, which is a
// different fact from "serves it and adopted nothing" and must stay
// distinguishable: the first is a device that cannot carry the function, the
// second is a device that can and did not.
type CurveView struct {
	// Source names where this reading came from, for a finding that cites it.
	Source string
	Axis   CurveAxis

	// Index is which curve of the bank this reading is. 0 is the LIVE curve —
	// the one the device is actually running — and 1..NCrv-1 are the writable
	// STAGING slots a gateway writes before it triggers the adopt handshake.
	// The distinction is load-bearing in both directions: content sitting in
	// staging is a curve the device was OFFERED and not one it adopted, so
	// grading a staged curve as an executed one would accept exactly the
	// half-completed write the handshake exists to distinguish — and yet a
	// staged write is still a WRITE, which is what a refusal row has to be able
	// to see (see the refusal fingerprint in suitecsip).
	Index int

	// Present is true when the device served the model and it decoded.
	Present bool
	// Err records why a served model did not decode. Present is false then.
	Err string

	// Enabled is the model's own Ena register: the function switched ON.
	// A curve adopted into a disabled function commands nothing.
	Enabled bool
	// EnaRaw is Ena's raw register value, for a finding that must quote it.
	EnaRaw uint16

	// AdoptReq / AdoptResult are the handshake registers (AdptCrvReq /
	// AdptCrvRslt, or AdptCtlReq / AdptCtlRslt on 711).
	AdoptReq    uint16
	AdoptResult uint16
	// Adopted is AdoptResult == COMPLETED.
	Adopted bool

	// DeptRef is the live curve's DeptRef register — SunSpec's "curve dependent
	// reference", the base its y values are a percentage OF. HasDeptRef is false
	// for a model that carries no such register (711, which is parametric).
	//
	// It is decoded because a curve's y values are a PERCENTAGE, and a
	// percentage is not a quantity without the thing it is a percentage of. IEEE
	// 2030.5 names that base on every DERCurve (yRefType, minOccurs=1) and
	// SunSpec names it per curve bank (DeptRef); a referee that read the points
	// and not this register would grade "-30 % of setMaxVar" and "-30 % of
	// setMaxW" as the same curve, which on a 60 kW / 26.4 kvar DER is a 2.3x
	// error and on a 2 kvar machine a 30x one.
	DeptRef    uint16
	HasDeptRef bool

	// ReadOnly is the live curve's own ReadOnly flag. The live curve of a
	// conformant device is read-only; a writable "live" curve means the index-0
	// convention does not hold on this device and the reading below is not the
	// active curve.
	ReadOnly bool

	// NPt / NCrv are the device's own declared geometry.
	NPt, NCrv int

	// ── LEGACY (12x) only ──
	//
	// ActCrv is the header's own curve-SELECTION register: which 1-based bank
	// the device is running, 0 for none. It is the legacy generation's whole
	// commit mechanism and has no 7xx counterpart (there, promotion is the
	// adopt handshake), so it is reported separately rather than folded into
	// AdoptReq — a reader must be able to see WHICH bank is live, not merely
	// that something was requested.
	ActCrv int
	// Bank is the 1-based bank this view decoded. On a legacy Index-0 view it
	// is whatever ActCrv named; on Index i>0 it is i. Zero on 7xx.
	Bank int

	// Sub is WHICH sub-curve of a trip bank this reading addressed, and
	// SubCurveNone when it addressed none (which is every reading of every
	// model that is not a trip bank, and a trip reading taken of the SET).
	//
	// It is load-bearing in a finding rather than decorative: "M707 holds
	// (1.5 s, 50 %VNom)" is three different statements depending on whether the
	// points came from MustTrip, MayTrip or MomCess, and only one of them
	// answers whatever question the caller asked.
	Sub CurveSub

	// SubPoints is EVERY sub-curve of the addressed curve-SET, whether or not
	// this reading addressed one. nil for a model that is not Subcurved.
	//
	// It is populated even on an addressed reading, and Describe() renders all
	// three, because a trip bank's sub-curves are read from ONE register block
	// and the two the caller did not ask about are free evidence: a MustTrip
	// comparison that failed while the commanded points sit in MomCess is a
	// specific, nameable defect, and a referee that had thrown the other two
	// away could only report "the curve does not match".
	SubPoints map[CurveSub][]CurvePoint

	// Points is the live curve's breakpoints, device engineering units. Always
	// empty for a Pointless axis, and always empty on a Subcurved model when
	// Sub is SubCurveNone — on a trip bank there is no such thing as "the"
	// point table, and inventing one is the silent pick this package refuses.
	Points []CurvePoint

	// RspTmsS is this CURVE's own open-loop response time, in seconds — SunSpec
	// 705/706 Crv.RspTms scaled by the model's RspTms_SF, labelled "Open Loop
	// Response Time" in both model definitions. nil for a model that declares no
	// such register: 712 has none, and the legacy banks carry a PT1 FILTER time
	// (126 Crv.RmpTms, 132/134 Crv.RmpPt1Tms — "the time of the PT1 ... to
	// accomplish a change of 95%"), which is IEEE 2030.5's rampPT1Tms and a
	// different quantity.
	//
	// It is decoded because IEEE 2030.5's DERCurve.openLoopTms lands exactly
	// here, and nothing was reading it: a referee that compared the breakpoints
	// and left the timing unread cannot tell a device that executed the curve
	// its procedure prescribes from one that executed the same SHAPE at its own
	// default speed. CSIP CTP v1.3's Figure 6 prescribes openLoopTms 5 against a
	// default of 10 — the timing is part of what that row commands.
	//
	// NOT DroopReading.RspTmsS, which is model 711's response time for the
	// PARAMETRIC droop: a different register in a different model, carrying
	// opModFreqDroop's own openLoopTms rather than a curve's.
	RspTmsS *float64

	// VRefAutoEna / VRefAutoTmsS are model 705's OWN autonomous volt-reference
	// automation: Crv.VRefAutoEna (enum16) and Crv.VRefAutoTms. nil on every
	// model that declares neither (everything but 705).
	//
	// They are decoded because IEEE Std 2030.5-2018 p.252's autonomousVRefEnable
	// clause turns on what a DER DOES, and until this wave nothing here could
	// see it. The clause says a DER able to support Volt-Var but unable to
	// support autonomous vRef adjustment "SHALL execute the curve without
	// autonomous vRef adjustment" — so a gateway that accepts such a control has
	// two obligations, and only one of them is about the breakpoints: it must
	// execute the curve, AND it must not arm an adjustment it cannot manage.
	//
	// A referee reading only the point table can see the first and is blind to
	// the second. That blindness has a specific bad outcome: a gateway that
	// wrote VRefAutoEna=1 to "honour" the request would leave the DER tracking a
	// reference the gateway never updates, which drifts the whole curve over
	// time and looks, in the point table, exactly like a correct execution.
	// These fields are what make "executed WITHOUT the adjustment" a measured
	// claim instead of an assumed one.
	VRefAutoEna  *bool
	VRefAutoTmsS *float64

	// Params carries a Pointless model's parameters (711's deadbands, gains and
	// response time), rendered, since there is no point table to carry them.
	Params string

	// Droop is the SAME parameters as numbers, in the device's own engineering
	// units, for a caller that has to COMPARE them rather than print them.
	//
	// It exists because Params alone made 711 unassertable: a referee holding a
	// commanded dead band of 0.03 Hz and a rendered string "DbOf=0.036 Hz ..."
	// can only match by parsing its own prose back, which is not a measurement.
	// A Pointless model is not an unmeasurable one — it is one whose content is
	// parametric — and the distinction is what lets a frequency-droop control be
	// graded on a 7xx DER at all.
	//
	// nil for every model that is not 711, and for a 711 whose control block did
	// not decode. Never a zero-valued struct standing in for an unread device:
	// zeros here are a real machine (no dead band, no gain), which is exactly
	// the confusion the corrected csipmodel decode exists to prevent.
	Droop *DroopReading
}

// DroopReading is model 711's parametric frequency-droop control as the
// device's own registers report it, in the units the SunSpec model declares —
// NOT the thousandths/hundredths IEEE 2030.5 sends. The translation between the
// two belongs to whoever compares them, and doing it here would bury it.
//
//	DbOfHz, DbUfHz   dead bands, over/under, in Hz          (711 DbOf/DbUf ×Db_SF)
//	KOf, KUf         droop gains, over/under, unitless      (711 KOf/KUf ×K_SF)
//	RspTmsS          open-loop response time, in seconds    (711 RspTms ×RspTms_SF)
//	PMin             the control's minimum power register
//
// PMIN IS REPORTED AND IS NOT A COMPARISON TARGET, which is worth stating
// because it is easy to mistake for an omission. IEEE 2030.5's FreqDroopType
// has no PMin — nothing a head end can send corresponds to it — so a referee
// has no COMMANDED value to check it against, and asserting one would be
// inventing it. What a writer does with PMin is PRESERVE it (read-modify-write;
// writing 0 tells the device it may curtail to zero, which is a different
// machine), so catching a writer that did not is a BEFORE-and-AFTER question
// about one device rather than a wire-to-register one. It is decoded so that a
// caller holding both readings can ask it, and so every finding can quote the
// register it saw.
type DroopReading struct {
	DbOfHz, DbUfHz float64
	KOf, KUf       float64
	RspTmsS        float64
	PMin           float64
}

// Pointless reports whether this axis carries no breakpoint table, so a caller
// correlating a northbound DERCurve's points against it knows the correlation
// is not available (and must not report a verdict as though it were).
func (c CurveView) Pointless() bool { return c.Axis.Pointless }

// Legacy reports whether this reading came from the legacy 12x idiom, which a
// caller needs in order to know that a writable live bank is ordinary here and
// that there is no adopt result to interpret.
func (c CurveView) Legacy() bool { return c.Axis.Family == FamilyLegacy }

// Subcurved reports whether this reading is of a 1547 trip bank, whose set
// holds three sub-curves rather than one point table.
func (c CurveView) Subcurved() bool { return c.Axis.Subcurved }

// Describe renders what the device holds, for a finding that must say what it
// read rather than only what it wanted.
func (c CurveView) Describe() string {
	name := c.Axis.Name
	switch {
	case c.Axis.Subcurved && c.Index > 0:
		// A trip bank's non-zero index is a staging SET, and the sub-curve
		// rides on the name because a reading that did not say which of the
		// three it was about would be unattributable.
		name = fmt.Sprintf("%s staging curve-set %d %s", c.Axis.Name, c.Index, c.Sub)
	case c.Axis.Subcurved:
		name = fmt.Sprintf("%s live curve-set %s", c.Axis.Name, c.Sub)
	case c.Axis.Family == FamilyLegacy && c.Index > 0:
		// "staging curve" is a 7xx word and there is no such thing here: every
		// legacy bank is an ordinary bank and exactly one of them is selected.
		name = fmt.Sprintf("%s bank %d", c.Axis.Name, c.Index)
	case c.Index > 0:
		name = fmt.Sprintf("%s staging curve %d", c.Axis.Name, c.Index)
	}
	if !c.Present {
		if c.Err != "" {
			return fmt.Sprintf("%s did not decode: %s", name, c.Err)
		}
		return fmt.Sprintf("%s is not served by this device", name)
	}
	// Ena, the adopt handshake and NPt/NCrv belong to the MODEL, not to any one
	// curve of it, so they are rendered ONCE — on the live curve's line. A
	// staging line that repeated them would show the same numbers under a
	// different heading and read as if the slot had its own enable and its own
	// adopt state, which is exactly the confusion the live/staging distinction
	// exists to prevent.
	var parts []string
	switch {
	case c.Legacy():
		// The legacy header's own vocabulary. There is no adopt result to
		// print and printing one would invent a device state: what stands in
		// its place is the SELECTION, which is why ActCrv is rendered on every
		// line rather than only on the live one — on this generation "which
		// bank is live" is the fact a bank reading is meaningless without.
		parts = append(parts,
			fmt.Sprintf("ModEna=%#04x (%s, bitfield bit 0)", c.EnaRaw, enabledWord(c.Enabled)),
			fmt.Sprintf("adopt handshake n/a (ActCrv=%d selects; this reading is bank %d)",
				c.ActCrv, c.Bank),
			fmt.Sprintf("NPt=%d NCrv=%d", c.NPt, c.NCrv),
			fmt.Sprintf("bank read-only=%t", c.ReadOnly),
		)
	case c.Subcurved():
		// The trip banks' own vocabulary: NCrvSet counts SETS, not curves, and
		// each set holds three sub-curves. Rendered on every reading including
		// the staging ones, because on this shape a reader needs the geometry to
		// know how many sub-curves the numbers below are drawn from.
		parts = append(parts,
			fmt.Sprintf("Ena=%d (%s)", c.EnaRaw, enabledWord(c.Enabled)),
			fmt.Sprintf("adopt req=%d rslt=%d (%s)", c.AdoptReq, c.AdoptResult, adoptWord(c.Adopted)),
			fmt.Sprintf("NPt=%d NCrvSet=%d (each set holds MustTrip/MayTrip/MomCess)", c.NPt, c.NCrv),
			fmt.Sprintf("curve-set read-only=%t", c.ReadOnly),
		)
	case c.Index == 0:
		parts = append(parts,
			fmt.Sprintf("Ena=%d (%s)", c.EnaRaw, enabledWord(c.Enabled)),
			fmt.Sprintf("adopt req=%d rslt=%d (%s)", c.AdoptReq, c.AdoptResult, adoptWord(c.Adopted)),
			fmt.Sprintf("NPt=%d NCrv=%d", c.NPt, c.NCrv),
			fmt.Sprintf("live curve read-only=%t", c.ReadOnly),
		)
	default:
		parts = append(parts, fmt.Sprintf("read-only=%t", c.ReadOnly))
	}
	if c.HasDeptRef {
		parts = append(parts, fmt.Sprintf("DeptRef=%d (%s)", c.DeptRef, DeptRefName(c.Axis.Model, c.DeptRef)))
	}
	if c.RspTmsS != nil {
		// The curve's own open-loop response time, quoted on every reading of a
		// model that has the register — a finding about a curve's TIMING has to
		// show the register it read, exactly as one about its y reference does.
		parts = append(parts, fmt.Sprintf("RspTms=%s s (open-loop response)", trimFloat(*c.RspTmsS)))
	}
	if c.VRefAutoEna != nil {
		// Quoted on EVERY 705 reading, armed or not, for the reason DeptRef is:
		// a finding that showed this register only when it was set would leave a
		// reader unable to tell "not armed" from "not read", and the whole point
		// of IEEE 2030.5-2018 p.252's execute-without clause is that NOT arming
		// it is the conformant outcome — an absence that has to be visible to
		// count as evidence.
		state := "not armed"
		if *c.VRefAutoEna {
			state = "ARMED"
		}
		parts = append(parts, fmt.Sprintf("VRefAutoEna=%t (%s, the device's own autonomous volt-reference "+
			"automation)", *c.VRefAutoEna, state))
	}
	which := "live curve"
	switch {
	case c.Legacy() && c.Index == 0:
		which = fmt.Sprintf("live bank %d", c.Bank)
	case c.Index > 0:
		which = "this curve"
	}
	switch {
	case c.Axis.Pointless:
		parts = append(parts, "no breakpoint table (parametric control): "+orNone(c.Params))
	case c.Subcurved():
		// ALL THREE, always, whichever one this reading addressed.
		//
		// They come out of one register block, so the other two cost nothing to
		// render and are exactly what a reader needs when an addressed
		// comparison fails: commanded points sitting in MomCess while MustTrip
		// is empty is a specific defect with a specific owner, and a finding
		// that had printed only the addressed sub-curve could say nothing
		// beyond "the curve does not match".
		//
		// The ADDRESSED one is marked, so a reader can tell what the verdict
		// beside this dump is about.
		for _, sub := range TripSubCurves {
			mark := ""
			if sub == c.Sub {
				mark = " <- this reading"
			}
			pts := c.SubPoints[sub]
			if len(pts) == 0 {
				parts = append(parts, fmt.Sprintf("%s holds NO points%s", sub, mark))
				continue
			}
			rendered := make([]string, 0, len(pts))
			for _, p := range pts {
				rendered = append(rendered, p.String())
			}
			parts = append(parts, fmt.Sprintf("%s %s/%s points: %s%s", sub, c.Axis.XName, c.Axis.YName,
				strings.Join(rendered, " "), mark))
		}
	case len(c.Points) == 0:
		parts = append(parts, which+" holds NO points")
	default:
		pts := make([]string, 0, len(c.Points))
		for _, p := range c.Points {
			pts = append(pts, p.String())
		}
		parts = append(parts, fmt.Sprintf("%s %s/%s points: %s", which, c.Axis.XName, c.Axis.YName,
			strings.Join(pts, " ")))
	}
	return name + " — " + strings.Join(parts, ", ")
}

// DeptRefName spells a DeptRef code out for a finding, per model, so a reader
// sees which rating the device says its y values are a percentage of rather
// than a bare integer.
//
// PROVENANCE. Transcribed from the vendored SunSpec model JSON in lexa-proto
// (docs/schema/sunspec-models/): model_705.json and model_712.json declare
// {0 W_MAX_PCT, 1 VAR_MAX_PCT, 2 VAR_AVAL_PCT, 3 VA_MAX_PCT}; model_706.json
// declares {0 W_MAX_PCT, 1 W_AVAL_PCT}. Transcribed rather than bound
// mechanically because the sunspec package declares no DeptRef constants —
// stated plainly so the weakness is visible rather than implied. The DUT's own
// cmd/modbus/reconcile_adv.go carries the identical transcription with the
// identical provenance note; this referee restates it from the same source
// rather than importing it, which is this package's whole discipline.
func DeptRefName(model uint16, v uint16) string {
	switch model {
	case sunspec.ModelDERVoltVar, sunspec.ModelDERWattVar:
		switch v {
		case 0:
			return "W_MAX_PCT"
		case 1:
			return "VAR_MAX_PCT"
		case 2:
			return "VAR_AVAL_PCT"
		case 3:
			return "VA_MAX_PCT"
		}
	case sunspec.ModelDERVoltWatt:
		switch v {
		case 0:
			return "W_MAX_PCT"
		case 1:
			return "W_AVAL_PCT"
		}

	// THE LEGACY ENUM IS 1-BASED. It is not the 7xx enum with different names:
	// %WMax is 1 here and 0 there, so a referee that shared one table between
	// the generations would report every legacy DeptRef one place along — and
	// would do it silently, because both tables have a valid symbol at every
	// code it would land on. Transcribed from the vendored model_126.json /
	// model_132.json enum blocks, the same provenance rule the 7xx half above
	// states, and never derived from the 7xx codes by adding one.
	case sunspec.ModelVoltVarLegacy:
		switch v {
		case 1:
			return "%WMax"
		case 2:
			return "%VArMax"
		case 3:
			return "%VArAval"
		}
	case sunspec.ModelVoltWattLegacy:
		switch v {
		case 1:
			return "%WMax"
		case 2:
			return "%WAvail"
		}
	}
	return "unknown for this model"
}

func enabledWord(on bool) string {
	if on {
		return "ENABLED"
	}
	return "disabled"
}

func adoptWord(done bool) string {
	if done {
		return "COMPLETED"
	}
	return "not COMPLETED"
}

func orNone(s string) string {
	if s == "" {
		return "none read"
	}
	return s
}

// Curve decodes this unit's live curve for one curve model.
func (u UnitView) Curve(source string, model uint16) CurveView {
	return DecodeCurve(fmt.Sprintf("%s unit %d", source, u.Unit), model, u.Regs[model])
}

// CurveAt is Curve for one specific curve of the bank.
//
// The index means different things per generation, which is the whole content
// of the two idioms' difference: on 7xx, 0 is the live curve and 1..NCrv-1 are
// the writable staging slots; on legacy, 0 is "whatever bank ActCrv names" and
// 1..NCrv address the banks directly.
func (u UnitView) CurveAt(source string, model uint16, idx int) CurveView {
	return DecodeCurveAt(fmt.Sprintf("%s unit %d", source, u.Unit), model, u.Regs[model], idx)
}

// TripCurve decodes ONE sub-curve of this unit's LIVE (set 0) trip bank.
//
// It is the only way to get Points out of a 707/708/709/710 reading, and that
// is the point: a caller has to say which of MustTrip / MayTrip / MomCess it is
// asking about, because a trip set holds all three and no default answer is
// honest. See the file doc.
func (u UnitView) TripCurve(source string, model uint16, sub CurveSub) CurveView {
	return u.TripCurveAt(source, model, 0, sub)
}

// TripCurveAt is TripCurve for one specific curve-SET of the bank: 0 is the
// live set, 1..NCrvSet-1 the writable staging sets the adopt handshake promotes.
func (u UnitView) TripCurveAt(source string, model uint16, idx int, sub CurveSub) CurveView {
	return DecodeCurveSubAt(fmt.Sprintf("%s unit %d", source, u.Unit), model, u.Regs[model], idx, sub)
}

// DecodeCurve reads a curve model's header and its LIVE (index 0) curve out of
// that model's data registers.
//
// An empty regs slice is "the device does not serve this model" — the shape
// UnitView.Regs takes for a model the chain walk did not find — and is reported
// as absent, never as an empty curve, because "adopted nothing" and "cannot
// carry this function at all" are different answers to a conformance question.
func DecodeCurve(source string, model uint16, regs []uint16) CurveView {
	return DecodeCurveAt(source, model, regs, 0)
}

// DecodeCurveAt is DecodeCurve for one specific curve of the bank. idx 0 is the
// LIVE curve; 1..NCrv-1 are the writable staging slots.
//
// The header fields (Ena, the adopt handshake, NPt/NCrv) belong to the MODEL and
// are the same whatever idx is; only ReadOnly, DeptRef and the points come from
// the indexed curve.
//
// 711 is indexed too, and the earlier claim here that "a non-zero idx there
// decodes the same parametric control as idx 0" was simply wrong:
// sunspec.Parse711Ctl takes the index and reads the idx'th CONTROL of the bank
// (711 declares NCtl controls, not NCrv curves, which is why curveHeaderOf
// reports its count under a different field). What is true of 711 is that it
// carries no point TABLE — its response is parametric, and Points is empty for
// every index.
func DecodeCurveAt(source string, model uint16, regs []uint16, idx int) CurveView {
	return DecodeCurveSubAt(source, model, regs, idx, SubCurveNone)
}

// DecodeCurveSubAt is DecodeCurveAt addressing one SUB-CURVE of a 1547 trip
// bank (707/708/709/710), whose curve-set holds MustTrip, MayTrip and MomCess
// end to end rather than one point table.
//
// sub is SubCurveNone for every model that is not a trip bank, and passing
// anything else there is a DECODE ERROR rather than an ignored argument: a
// caller asking model 705 for its MomCess curve has confused two shapes, and
// answering with 705's ordinary point table would hand back a curve under a
// name it does not have.
//
// A TRIP READING WITH sub == SubCurveNone IS LEGAL AND CARRIES NO POINTS. It is
// how a caller reads the SET — its enable, its adopt state, its geometry and
// all three sub-curves' contents through SubPoints — without asserting anything
// about a particular one. What it must never do is come back with Points, and
// that is why the field stays empty rather than defaulting to MustTrip.
func DecodeCurveSubAt(source string, model uint16, regs []uint16, idx int, sub CurveSub) CurveView {
	axis, known := CurveAxisOf(model)
	if !known {
		return CurveView{Source: source, Axis: CurveAxis{Model: model,
			Name: fmt.Sprintf("M%d", model), XName: "x", YName: "y"},
			Err: fmt.Sprintf("model %d is not a curve model this referee decodes", model)}
	}
	v := CurveView{Source: source, Axis: axis, Index: idx, Sub: sub}
	if sub != SubCurveNone && !axis.Subcurved {
		v.Err = fmt.Sprintf("%s carries no sub-curves, so it cannot be read for %s: MustTrip / MayTrip / "+
			"MomCess are sub-curves of the IEEE 1547 trip banks (707/708/709/710) and this model has a "+
			"single point table", axis.Name, sub)
		return v
	}
	if len(regs) == 0 {
		return v
	}
	if axis.Subcurved {
		return decodeTripSetAt(v, model, regs, idx)
	}
	if axis.Family == FamilyLegacy {
		return decodeLegacyCurveAt(v, model, regs, idx)
	}

	hdr, reqField, rsltField, nField := curveHeaderOf(model)
	if len(regs) < hdr.Len() {
		v.Err = fmt.Sprintf("the %s block is %d registers, shorter than its own %d-register header",
			axis.Name, len(regs), hdr.Len())
		return v
	}
	h := hdr.View(regs)
	v.EnaRaw = h.U16At(hdr.Offset("Ena"))
	v.Enabled = v.EnaRaw == 1
	v.AdoptReq = h.U16At(hdr.Offset(reqField))
	v.AdoptResult = h.U16At(hdr.Offset(rsltField))
	v.Adopted = v.AdoptResult == sunspec.AdptCompleted
	if nField == "NCtl" {
		v.NCrv = int(h.U16At(hdr.Offset("NCtl")))
	} else {
		v.NPt = int(h.U16At(hdr.Offset("NPt")))
		v.NCrv = int(h.U16At(hdr.Offset("NCrv")))
	}

	switch model {
	case sunspec.ModelDERVoltVar:
		c, err := sunspec.Parse705Curve(regs, idx)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		// 705 declares Crv.RspTms ("Open Loop Response Time", uint32 Secs,
		// scaled by RspTms_SF). It is where IEEE 2030.5's openLoopTms lands.
		v.RspTmsS = &c.RspTms
		// The autonomous-vRef arming state, for the 2018 p.252 clause. Copied
		// into locals first: &c.Field would alias the loop-scoped parse result.
		autoEna, autoTms := c.VRefAutoEna, c.VRefAutoTms
		v.VRefAutoEna, v.VRefAutoTmsS = &autoEna, &autoTms
		for _, p := range c.Points {
			v.Points = append(v.Points, CurvePoint{X: p.V, Y: p.Var})
		}
	case sunspec.ModelDERVoltWatt:
		c, err := sunspec.Parse706Curve(regs, idx)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		// 706 declares the same register, with the same label and units.
		v.RspTmsS = &c.RspTms
		for _, p := range c.Points {
			v.Points = append(v.Points, CurvePoint{X: p.V, Y: p.W})
		}
	case sunspec.ModelDERWattVar:
		c, err := sunspec.Parse712Curve(regs, idx)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		for _, p := range c.Points {
			v.Points = append(v.Points, CurvePoint{X: p.W, Y: p.Var})
		}
	case sunspec.ModelDERFreqDroop:
		c, err := sunspec.Parse711Ctl(regs, idx)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.Params = fmt.Sprintf("DbOf=%s Hz DbUf=%s Hz KOf=%s KUf=%s RspTms=%s s PMin=%s",
			trimFloat(c.DbOf), trimFloat(c.DbUf), trimFloat(c.KOf), trimFloat(c.KUf),
			trimFloat(c.RspTms), trimFloat(c.PMin))
		// The same numbers, unrendered, for a caller that must compare rather
		// than print. Set from the SAME parse as Params so the two can never
		// describe different registers.
		v.Droop = &DroopReading{
			DbOfHz: c.DbOf, DbUfHz: c.DbUf, KOf: c.KOf, KUf: c.KUf,
			RspTmsS: c.RspTms, PMin: c.PMin,
		}
	}
	v.Present = true
	return v
}

// decodeTripSetAt is DecodeCurveSubAt's 1547-trip half: one curve-SET of a
// 707/708/709/710 block, with all three of its sub-curves decoded and the
// addressed one (if any) promoted into Points.
//
// EVERY POINT IS TRANSPOSED ON THE WAY OUT, and this is the only place in this
// package that does it. lexa-proto hands back the register order —
// TripVPoint{V, Tms} and TripHzPoint{Hz, Tms} — and this returns
// CurvePoint{X: Tms, Y: the quantity}, so that the decoded pair is in the
// (time, quantity) order IEEE 2030.5's ride-through DERCurve uses and the
// legacy 129/130 blocks already store natively. See the file doc for why the
// normalisation belongs here and not in a caller's binding.
//
// Tms IS SECONDS. Both models' JSON gives Pt.Tms the units string "Secs",
// scaled by Tms_SF; lexa-proto's ScaleU32At has already applied the scale
// factor, so what arrives here is seconds and nothing further is done to it.
func decodeTripSetAt(v CurveView, model uint16, regs []uint16, idx int) CurveView {
	hdr, reqField, rsltField, _ := curveHeaderOf(model)
	if len(regs) < hdr.Len() {
		v.Err = fmt.Sprintf("the %s block is %d registers, shorter than its own %d-register header",
			v.Axis.Name, len(regs), hdr.Len())
		return v
	}
	h := hdr.View(regs)
	v.EnaRaw = h.U16At(hdr.Offset("Ena"))
	v.Enabled = v.EnaRaw == 1
	v.AdoptReq = h.U16At(hdr.Offset(reqField))
	v.AdoptResult = h.U16At(hdr.Offset(rsltField))
	v.Adopted = v.AdoptResult == sunspec.AdptCompleted
	v.NPt = int(h.U16At(hdr.Offset("NPt")))
	// NCrv carries NCrvSet here. The trip banks count SETS where 705/706/712
	// count curves, and Describe() says so on every reading rather than letting
	// the number be read as a curve count.
	v.NCrv = int(h.U16At(hdr.Offset("NCrvSet")))

	v.SubPoints = map[CurveSub][]CurvePoint{}
	switch model {
	case sunspec.ModelDERTripLV, sunspec.ModelDERTripHV:
		set, err := sunspec.Parse707Set(regs, idx)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = set.ReadOnly
		v.SubPoints[SubCurveMustTrip] = tripVoltagePoints(set.MustTrip)
		v.SubPoints[SubCurveMayTrip] = tripVoltagePoints(set.MayTrip)
		v.SubPoints[SubCurveMomCess] = tripVoltagePoints(set.MomCess)
	case sunspec.ModelDERTripLF, sunspec.ModelDERTripHF:
		set, err := sunspec.Parse709Set(regs, idx)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = set.ReadOnly
		v.SubPoints[SubCurveMustTrip] = tripFreqPoints(set.MustTrip)
		v.SubPoints[SubCurveMayTrip] = tripFreqPoints(set.MayTrip)
		v.SubPoints[SubCurveMomCess] = tripFreqPoints(set.MomCess)
	default:
		v.Err = fmt.Sprintf("model %d is marked sub-curved in the axis table but has no trip decode here",
			model)
		return v
	}
	if v.Sub != SubCurveNone {
		v.Points = v.SubPoints[v.Sub]
	}
	v.Present = true
	return v
}

// tripVoltagePoints transposes 707/708's (V, Tms) register pairs into this
// package's (seconds, %VNom) CurvePoints.
func tripVoltagePoints(pts []sunspec.TripVPoint) []CurvePoint {
	if len(pts) == 0 {
		return nil
	}
	out := make([]CurvePoint, 0, len(pts))
	for _, p := range pts {
		out = append(out, CurvePoint{X: p.Tms, Y: p.V})
	}
	return out
}

// tripFreqPoints transposes 709/710's (Hz, Tms) register pairs into this
// package's (seconds, Hz) CurvePoints.
func tripFreqPoints(pts []sunspec.TripHzPoint) []CurvePoint {
	if len(pts) == 0 {
		return nil
	}
	out := make([]CurvePoint, 0, len(pts))
	for _, p := range pts {
		out = append(out, CurvePoint{X: p.Tms, Y: p.Hz})
	}
	return out
}

// decodeLegacyCurveAt is DecodeCurveAt's legacy (12x) half.
//
// THE ONE LINE THAT MATTERS is the bank selection. On this generation the
// device runs the bank ActCrv names, and there is no register anywhere that
// says "a curve was adopted" — so a referee that read bank 1 unconditionally
// would report content the device is not running, which is the identical error
// to grading a 7xx staging slot as executed. Index 0 therefore resolves through
// ActCrv, and only an explicit 1..NCrv addresses a bank directly.
//
// Everything runs through lexa-proto's own accessors, which apply the
// fail-closed GEOMETRY GATE before computing any offset: a device whose
// declared L, NCrv and spec block length disagree has an unknown register map,
// and this referee reports that as a decode failure rather than reading twenty
// point slots out of a block that may only have ten. A bounds check would not
// catch it — every spec offset is inside such a device's block, and every one
// of them is the wrong register.
func decodeLegacyCurveAt(v CurveView, model uint16, regs []uint16, idx int) CurveView {
	hdr, err := sunspec.ParseLegacyCurveHeader(model, regs)
	if err != nil {
		v.Err = err.Error()
		return v
	}
	// ModEna is a bitfield16 and its raw word is kept: a device that sets a
	// reserved bit alongside bit 0 is ENABLED, and a finding has to be able to
	// quote the word it read rather than a boolean derived from it.
	v.EnaRaw, v.Enabled = hdr.ModEnaRaw, hdr.ModEna
	v.NCrv, v.NPt = hdr.NCrv, hdr.NPt
	v.ActCrv = hdr.ActCrv

	bank := idx
	if idx == 0 {
		bank = hdr.ActCrv
		if bank == 0 {
			// A model that is present, decodes, and is running NO curve. That
			// is a different fact from "does not serve the model" and from
			// "runs the wrong one", and collapsing any two of the three would
			// send the finding to the wrong owner. Present, not adopted.
			v.Present = true
			return v
		}
	}
	v.Bank = bank

	geom, gerr := sunspec.LegacyCurveGeometryOf(model, len(regs), regs)
	if gerr != nil {
		v.Err = gerr.Error()
		return v
	}
	if _, ok := geom.BankOffset(bank); !ok {
		v.Err = fmt.Sprintf("bank %d is not addressable: this device declares NCrv=%d (banks are 1-based)",
			bank, geom.NCrv)
		return v
	}

	switch model {
	case sunspec.ModelVoltVarLegacy:
		c, err := sunspec.ParseLegacy126Curve(regs, bank)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		v.Points = legacyPoints(c.Pts)
	case sunspec.ModelVoltWattLegacy:
		c, err := sunspec.ParseLegacy132Curve(regs, bank)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.DeptRef, v.HasDeptRef = c.DeptRef, true
		v.Points = legacyPoints(c.Pts)
	case sunspec.ModelWattPFLegacy:
		c, err := sunspec.ParseLegacy131Curve(regs, bank)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		// 131 carries NO DeptRef: the spec fixes its x axis at %WMax and its y
		// axis is a power factor, which is not a percentage OF anything, so
		// HasDeptRef stays false rather than reporting a zero.
		v.ReadOnly = c.ReadOnly
		v.Points = legacyPoints(c.Pts)
	case sunspec.ModelFreqWattLegacy:
		c, err := sunspec.ParseLegacy134Curve(regs, bank)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.Points = legacyPoints(c.Pts)
		// 134's y values are % WRef, not % WMax, and a CSIP opModFreqWatt
		// curve's y is %setMaxW. Those are equal only when WRef == setMaxW, so
		// the reference the device is actually answering percentages against —
		// and whether snapshot mode has replaced it with the instantaneous
		// output at trigger time — is rendered on every reading rather than
		// assumed. A curve whose base is unstated is a curve nobody can name.
		v.Params = fmt.Sprintf("WRef=%s W SnptW=%t (snapshot mode %s) WRefStrHz=%s WRefStopHz=%s",
			trimFloat(c.WRefW), c.SnptW, enabledWord(c.SnptW),
			trimFloat(c.WRefStrHz), trimFloat(c.WRefStopHz))
	case sunspec.ModelLVRTLegacy:
		c, err := sunspec.ParseLegacy129Curve(regs, bank)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.Points = legacyPoints(c.Pts)
	case sunspec.ModelHVRTLegacy:
		c, err := sunspec.ParseLegacy130Curve(regs, bank)
		if err != nil {
			v.Err = err.Error()
			return v
		}
		v.ReadOnly = c.ReadOnly
		v.Points = legacyPoints(c.Pts)
	default:
		v.Err = fmt.Sprintf("model %d is in the legacy curve family table but has no decode here", model)
		return v
	}

	// "Adopted" on legacy is DERIVED, never read: the device is running this
	// bank exactly when ActCrv names it. There is no AdptCrvRslt to consult and
	// inventing one would report a device claim that was never made.
	v.Adopted = hdr.ActCrv != 0 && bank == hdr.ActCrv
	v.Present = true
	return v
}

// legacyPoints converts lexa-proto's legacy breakpoints into this package's.
func legacyPoints(pts []sunspec.LegacyCurvePoint) []CurvePoint {
	if len(pts) == 0 {
		return nil
	}
	out := make([]CurvePoint, 0, len(pts))
	for _, p := range pts {
		out = append(out, CurvePoint{X: p.X, Y: p.Y})
	}
	return out
}

// curveHeaderOf returns a curve model's header layout and the names of its
// handshake and geometry registers. 711 is the odd one: it carries CONTROLS,
// not curves, so its handshake is AdptCtlReq/AdptCtlRslt and its count is NCtl.
//
// The trip banks are the other odd ones: they count SETS, so their geometry
// register is NCrvSet rather than NCrv, and each set holds three sub-curves.
// They are listed EXPLICITLY rather than left to the default arm — the default
// returns 711's layout, which would have decoded a trip bank's Ena and
// handshake at 711's offsets and reported plausible numbers read from the wrong
// registers.
func curveHeaderOf(model uint16) (hdr *sunspec.Layout, reqField, rsltField, nField string) {
	switch model {
	case sunspec.ModelDERVoltVar:
		return sunspec.L705Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	case sunspec.ModelDERVoltWatt:
		return sunspec.L706Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	case sunspec.ModelDERWattVar:
		return sunspec.L712Hdr, "AdptCrvReq", "AdptCrvRslt", "NPt"
	case sunspec.ModelDERTripLV, sunspec.ModelDERTripHV:
		return sunspec.L707Hdr, "AdptCrvReq", "AdptCrvRslt", "NCrvSet"
	case sunspec.ModelDERTripLF, sunspec.ModelDERTripHF:
		return sunspec.L709Hdr, "AdptCrvReq", "AdptCrvRslt", "NCrvSet"
	default:
		return sunspec.L711Hdr, "AdptCtlReq", "AdptCtlRslt", "NCtl"
	}
}

// CurveMatch is the result of comparing a device's live curve against the
// breakpoints a control published northbound.
type CurveMatch struct {
	// Matched is true only when EVERY published point has a counterpart on the
	// device, in order, within tolerance, and the device holds no extra points.
	Matched bool
	// Reason explains a non-match in the language of the two point sets.
	Reason string
}

// MatchPoints compares a device's live curve against want, the breakpoints the
// northbound control published (already converted into the device's own
// engineering units by the caller, which owns that conversion because it owns
// the axis multipliers the wire carried).
//
// Order matters and extra points fail. A curve is a piecewise function: the
// same three breakpoints in a different order describe a different function,
// and a fourth breakpoint the head end never sent is a segment nobody asked
// for. Accepting either would let "the DER holds SOME curve" pass for "the DER
// holds THIS curve".
//
// tol is the slack allowed on ONE axis value, given that value — a function
// rather than a constant because a device's own scale factors decide the size
// of a rounding step, and a fixed absolute tolerance is either too tight on a
// coarse device or too loose on a fine one.
func MatchPoints(got, want []CurvePoint, tol func(want float64) float64) CurveMatch {
	if len(want) == 0 {
		return CurveMatch{Reason: "the control published no breakpoints, so there is nothing to correlate"}
	}
	if len(got) != len(want) {
		return CurveMatch{Reason: fmt.Sprintf("the device's live curve holds %d breakpoint(s) and the "+
			"control published %d: %s vs %s", len(got), len(want), renderPoints(got), renderPoints(want))}
	}
	for i := range want {
		if math.Abs(got[i].X-want[i].X) > tol(want[i].X) || math.Abs(got[i].Y-want[i].Y) > tol(want[i].Y) {
			return CurveMatch{Reason: fmt.Sprintf("breakpoint %d differs: the device holds %s, the control "+
				"published %s (device curve %s, published curve %s)", i+1, got[i], want[i],
				renderPoints(got), renderPoints(want))}
		}
	}
	return CurveMatch{Matched: true, Reason: fmt.Sprintf("the device's live curve holds exactly the "+
		"published breakpoints, in order: %s", renderPoints(got))}
}

func renderPoints(pts []CurvePoint) string {
	if len(pts) == 0 {
		return "(no points)"
	}
	out := make([]string, 0, len(pts))
	for _, p := range pts {
		out = append(out, p.String())
	}
	return strings.Join(out, " ")
}
