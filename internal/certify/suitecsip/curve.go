package suitecsip

// curve.go — IW15-008. The southbound half of the CURVE-linked inverter-control
// rows (BASIC-004/005/006/011/012/015) and of the rows whose axis this product
// deliberately REFUSES (BASIC-007/014).
//
// ── The finding this file closes ────────────────────────────────────────────
//
// Every one of those rows certified applicable-PASS on a product that does not
// execute the axis at all, and it did so by the same mechanism the repaired
// BASIC-013 was failing by: the row carried NO southbound oracle, so its "the
// DER's output followed the control" criterion was a Skip, and a Skip is the
// LOWEST severity there is (bundle.Verdict.Severity: Skip 0 < Pass 1) while
// every roll-up in the runner raises only. Absence of measurement read as
// success. The northbound half — an <opModVoltVar> element appearing inside a
// DERControlBase the DUT fetched — was the whole of the evidence, and it is
// evidence that the BENCH published a control, not that the DUT did anything
// with it.
//
// So: no Skip path survives here. Every row below either MEASURES the DER's own
// registers and reports what it found, or says in a decided FAIL exactly which
// link of the chain it could not measure and why. "We could not test it" must
// never read like "it passed".
//
// ── What a curve oracle can and cannot assert on this bench ─────────────────
//
// The device sims adopt curves realistically (a writable staging curve, the
// §3.1.2 AdptCrvReq/AdptCrvRslt handshake, a read-only live curve at index 0
// that reflects the staged points on COMPLETED) but they simulate NO curve
// PHYSICS: a volt-var curve on the sim moves no measured var. Every assertion
// here is therefore REGISTER- and ADOPT-STATE-based — the curve content landed
// in the model's own live curve, the handshake reached COMPLETED, and the
// function is enabled — correlated to the breakpoints THIS row published. It is
// deliberately NOT an effect-on-output oracle; building one against a sim with
// no curve physics would be measuring the fixture.
//
// ── The authoring gaps are named, not hidden ───────────────────────────────
//
// gridsim authors four of IEEE 2030.5's fourteen curve-valued modes (volt_var,
// volt_watt, freq_watt, watt_pf — sim/gridsim/curve.go). The ride-through modes
// BASIC-004/005 are about, and the ramp gradients BASIC-007 is about, cannot be
// placed on the wire from this bench at all. That is a real gap in the
// evidence, and a gap in the evidence is a row that has not been tested: those
// rows now FAIL, naming the missing lever, instead of skipping past it into a
// PASS. Closing them needs a bench lever, not a change here.

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// The Observation.Params keys the curve and refusal rows add to the oracled
// scalar rows' set (basic.go). They are DISTINCT keys, never the scalar ones
// reused, so a bundle can show exactly which apparatus produced a verdict — and
// so a test asserting "the curve row recorded what it published" cannot be
// satisfied by a scalar row's leftover.
const (
	curvePublishedParam = "iw15.curve_published"
	curveModelParam     = "iw15.curve_model"
	curveMRIDNoteParam  = "iw15.curve_mrid_note"
	curveHrefParam      = "iw15.curve_href"
	curveResourceParam  = "iw15.curve_resource_mrid"

	refusalAxisParam     = "iw15.refusal_axis"
	refusalBaselineParam = "iw15.refusal_baseline"

	// curveGenParam records WHICH SunSpec curve generation the DER under test
	// turned out to be, resolved live from its own model chain. It is what lets
	// the post-hoc citation phase — which has no live context and cannot read
	// the DER — describe the bank it measured, and what lets a row whose
	// CORRECT posture differs by generation (BASIC-015) pick its apparatus.
	curveGenParam = "iw15.curve_generation"
	// curveGenUnknown is recorded when the DER serves neither generation's
	// curve models, or could not be read at all. It is deliberately not a
	// default of either generation: a row that guessed would attribute a
	// verdict to a bank it never read.
	curveGenUnknown = "unknown"
	// curveGenAmbiguous is recorded for a DER that serves BOTH generations'
	// curve models. It is a THIRD answer, not a tie-break: no row was written
	// for such a device, and picking one silently would grade a bank the row's
	// author never considered — and, on BASIC-015, would swap a refusal
	// assertion for an execution one and stop running the LXR-002 catcher.
	curveGenAmbiguous = "both"

	// curveDeliveryParam carries what the bench's own data plane saw the DUT
	// fetch during this row's window. It exists because a southbound ABSENCE
	// has two causes that read identically in a verdict — the DUT refused the
	// axis, or the DUT never received the control (it is wedged, or dead, or
	// the bench never served it) — and the per-criterion record that already
	// distinguishes them (critDERControlCarriesModeFrom, critDERCurveResolvable)
	// is carried in Skip assertions, which are severity 0 and never appear in
	// the headline verdict text a reader acts on. This makes the distinction
	// LEGIBLE where the FAIL is stated; it does not add a mechanism.
	curveDeliveryParam = "iw15.curve_delivery"
	// curveDeliveryBaselineParam is the GET count Setup recorded, so PostWait
	// reports a DELTA over this row's own window rather than the whole of the
	// server's bounded request ring.
	curveDeliveryBaselineParam = "iw15.curve_delivery_baseline"

	// curveGenAmbiguousParam records that this row DECLINED to choose a
	// generation, and why. Present only on a DER serving both families.
	curveGenAmbiguousParam = "iw15.curve_generation_ambiguous"
)

// ── Curve rows: the binding ─────────────────────────────────────────────────

// curveBinding is what a CURVE-linked row carries beyond a plain one: the
// breakpoints it publishes northbound, and the SunSpec model those breakpoints
// must be found in southbound.
//
// The two live in ONE structure for the reason oracleBinding's doc gives for the
// scalar rows: the published curve and the oracle that judges it must not be
// able to disagree about what was commanded. The row states its points once,
// the publisher sends those points, and the oracle expects those points.
type curveBinding struct {
	// Mode is gridsim's own curve-mode name (sim/gridsim/curve.go's
	// curveTypeForMode vocabulary): volt_var | volt_watt | freq_watt |
	// watt_pf | watt_var.
	Mode string
	// Points are the breakpoints this row publishes, in the wire's own raw
	// units — the axis multipliers below say what power of ten they carry.
	Points []CurvePoint
	// XMult/YMult are the DERCurve axis multipliers this row publishes with.
	// They are what converts a published breakpoint into the device
	// engineering value the oracle expects (wantPoints), so they must travel
	// with the points rather than being assumed zero at one end.
	XMult, YMult int8
	// YRefType is the DERUnitRefType code the published curve's y axis carries
	// (IEEE Std 2030.5-2018 p.256). It said "the Table-19 code" until
	// IW15-027 — "Table 19" is a table of the pre-publication ZigBee SEP 2.0.4
	// draft, and naming it sent a reader to the document this whole wave exists
	// to stop citing.
	YRefType uint8

	// OpenLoopTms is the DERCurve's own openLoopTms element this row authors —
	// hundredths of a second, 0 meaning "no limit" — or nil to omit it.
	//
	// Until the #32 lever landed this bench could not send it at all:
	// BASIC-006's Figure 6 prints openLoopTms Default 10 / Test Values 5, so
	// every run of that row left the DUT in the procedure's DEFAULT timing while
	// the report claimed the test condition, and the row held itself at FAIL
	// saying exactly that.
	//
	// It has NO register home on either SunSpec curve generation (see
	// noOpenLoopTmsRegister). That does not make it droppable — the procedure
	// prescribes it and the DUT must be OFFERED it — so it is authored
	// northbound and declared, through authored() below, as an element this
	// referee asserts nothing about southbound.
	OpenLoopTms *uint16

	// AutonomousVRefEnable / AutonomousVRefTimeConstant are DERCurve's
	// autonomous volt-reference pair — IEEE Std 2030.5-2018 p.252 and p.253,
	// both [0..1] and both opModVoltVar-only ("If the curveType is not
	// opModVoltVar, then this field SHALL NOT be present"). Nil omits.
	//
	// They are here because Figure 6 prescribes both by name and this bench
	// could not send either: BASIC-006 carried two GAPS asserting that "sep
	// 2.0.4 declares NO such element on DERCurve", which is a true statement
	// about the pre-publication draft schema and a false one about the standard
	// the evidence is about (IW15-027). Both gaps are gone and the row authors
	// the Figure's own values.
	//
	// Like openLoopTms they have NO register home on either SunSpec curve
	// generation and are declared as such through authored(). Unlike openLoopTms
	// they are IMMATERIAL by the catalog's own test — Figure 6 prints the same
	// value in both its columns, and 2018 p.252 makes false the value of an
	// ABSENT autonomousVRefEnable — so authoring them cannot change what a
	// correct DUT does. That is exactly why it is worth doing: the row publishes
	// its whole Figure at no risk to what it measures, and stops carrying a
	// false sentence about the standard into every bundle.
	AutonomousVRefEnable       *bool
	AutonomousVRefTimeConstant *uint32

	// VRef is DERCurve.vRef — PerCent, hundredths of a percent (IEEE Std
	// 2030.5-2018 p.253), opModVoltVar-only. nil omits the element.
	//
	// IT IS THE ONE AUTHORED ELEMENT THAT CHANGES WHAT THE DEVICE MUST HOLD.
	// 2018 p.250, under opModVoltVar: "If VRef is present in DERCurve, then the
	// x value of each pair is additionally multiplied by VRef/10 000." So a row
	// that publishes a vRef is publishing a curve at DIFFERENT VOLTAGES than
	// its breakpoints read, and wantPoints() applies the same multiplication
	// before the oracle compares — see there for why that is derived from the
	// standard's sentence rather than from the product's code.
	//
	// A bench that served a vRef and expected the UNSCALED points would fail a
	// correct device; one that served it and expected the unscaled points to be
	// held would pass a device that ignored the element entirely. Both are the
	// same defect from opposite sides, and both are what this field exists to
	// make impossible.
	//
	// IT CAN ONLY SHRINK THE X AXIS, OR LEAVE IT ALONE. vRef is a PerCent, and
	// 2018 p.167 states that type's domain as "0 to 10 000. (10 000 = 100%)" —
	// so vRef/10 000 is at most 1 for every value the element admits, and the
	// ceiling means "no adjustment" rather than being an exclusive bound. A
	// fixture expecting a vRef to push breakpoints UP is expecting a document
	// the standard does not admit; the review that opened this work made exactly
	// that error with a 10500 example, and the bench's own domain check caught
	// it. See TestVRef_TheDomainCeilingIsInclusiveAndAppliedExactly.
	VRef *uint16

	// Droop, when set, is an INLINE opModFreqDroop element this row authors on
	// the SAME control that carries the curve link, and the register home its
	// five parameters must be found in per generation.
	//
	// It is a separate structure from the breakpoints because it is a separate
	// KIND of content — IEEE Std 2030.5-2018's one DERControlBase mode (p.248-251)
	// that carries its
	// parameters inline rather than behind a DERCurve link — and because its
	// register home and the curve's are on OPPOSITE generations: a 7xx DER
	// stores frequency response parametrically in model 711 and has no
	// freq-watt breakpoint table anywhere, while the legacy 12x set stores the
	// breakpoints in model 134 and has no home for the droop parameters at all.
	// One row, both halves authored, and each half measured on the generation
	// that can hold it. See droopBinding.
	Droop *droopBinding

	// ── The southbound target, PER GENERATION ──
	//
	// A row's northbound half is one control and does not change; its
	// southbound half is a different register bank on a 7xx DER and on a legacy
	// 12x one, and on some rows one of the two generations has no bank for it
	// at all. Both arms live on ONE binding, and which applies is resolved at
	// run time FROM THE DER'S OWN MODEL CHAIN (resolveTarget) rather than from
	// configuration — so a single catalog row runs on either bench and says
	// which one it measured.
	//
	// Naming them separately is also what stops a substitution from being
	// expressible. Before this the binding carried one Model, so "opModWattPF
	// lands on 712" and "opModWattPF lands on 131" were the same field with
	// different contents, and grading a PF curve against a var bank looked like
	// configuration rather than like the defect it was.

	// Model7xx is the 7xx-family model this mode's content must be found in,
	// or the NEAREST model when NoRegisterHome7xx explains that there is none.
	Model7xx uint16
	// Mapping7xx records WHERE that correspondence comes from, so a FAIL naming
	// a register bank can be checked by a reader who did not write it.
	Mapping7xx string
	// NoRegisterHome7xx, when non-empty, says the 7xx family has no
	// breakpoint-carrying home for this mode, and why.
	NoRegisterHome7xx string

	// ModelLegacy / MappingLegacy / NoRegisterHomeLegacy are the same three
	// facts for the legacy 12x family.
	ModelLegacy          uint16
	MappingLegacy        string
	NoRegisterHomeLegacy string

	// Prescribed states WHERE the breakpoints above come from — the catalog
	// Figure and column, verbatim enough that a reader can find it — or says
	// plainly that the procedure prescribes none and these are the suite's own.
	//
	// It exists because the alternative is what was here: BASIC-006 published
	// (92,60)(98,0)(102,0)(108,-60) with no multipliers, which is not Figure 6's
	// curve at any scale. It is the gridsim STATIC FIXTURE's shape, inherited
	// when the row was first written and never reconciled to the procedure.
	// That changed no verdict while every curve row's southbound half was a
	// decided FAIL on every bench; it stopped being harmless the moment a
	// legacy DER could execute the curve, because the row would then go GREEN
	// on content the certification procedure never asked for — a false PASS
	// into a conformance bundle, and the IW15-004 class BASIC-013 has a pinning
	// test for while no curve row did.
	Prescribed string

	// Gaps are prescribed elements of this row's Figure that THIS BENCH cannot
	// place on the wire. They are named rather than omitted, on the same rule
	// noRideThrough/noRampRate follow: a row whose control was authored without
	// part of what the procedure specifies has not been run to the procedure,
	// and a bundle that did not say so would be overclaiming.
	Gaps []curveGap
}

// curveGap is one prescribed element this bench cannot author.
type curveGap struct {
	// Element is the procedure's own name for it
	// ("opModVoltVar.DERCurve.openLoopTms").
	Element string
	// Prescribed and Default are the Figure's two columns, as printed.
	Prescribed, Default string
	// Why names the missing lever, so the gap has an owner.
	Why string
	// Material is true when the procedure's TEST value differs from its own
	// DEFAULT — i.e. omitting the element means the DUT was never offered the
	// condition the row exists to create. An immaterial gap (test value equals
	// the default, or a transcription divergence this bench deliberately does
	// not follow) is still named, and does not hold the row.
	Material bool
}

// droopBinding is the inline opModFreqDroop half of a row: the five
// FreqDroopType values it authors (IEEE Std 2030.5-2018 p.242), and the register home those values must be
// found in on each SunSpec generation.
//
// THE FIVE VALUES ARE THE PROCEDURE'S, in the wire's own units, and nothing in
// this bench rescales them on the way out — the pcap has to carry the numbers
// the Figure prints or the evidence is about a different control. The
// translation into a device's engineering units happens ONCE, in want711, on
// the reading side, where a reader can check it against the two standards'
// own sentences.
type droopBinding struct {
	// Settings are the five values, exactly as the request carries them:
	// dBOF/dBUF in thousandths of Hz, kOF/kUF in thousandths (unitless),
	// openLoopTms in hundredths of a second.
	Settings FreqDroopSettings

	// Model7xx is the 7xx-family model whose registers hold this content, or 0
	// with NoRegisterHome7xx set. Mapping7xx records where the correspondence
	// comes from, on the same rule the curve arms follow: a FAIL that names a
	// register bank must be checkable by whoever reads the bundle.
	Model7xx             uint16
	Mapping7xx           string
	NoRegisterHome7xx    string
	ModelLegacy          uint16
	MappingLegacy        string
	NoRegisterHomeLegacy string
}

// droopTarget is the droop half's resolved home on THIS DER's generation.
type droopTarget struct {
	Model          uint16
	Mapping        string
	NoRegisterHome string
}

// resolve picks the droop half's register home for a FAMILY, mirroring
// resolveTarget for the breakpoint half.
//
// IT TAKES THE FAMILY THE BREAKPOINT HALF RESOLVED TO, not the generation read
// off the device, and the difference is not academic. resolveTarget has a
// named-model FALLBACK: a DER whose generation is unrecognised, or one whose
// generation the row has no arm for, can still resolve its breakpoints against
// whichever named model the device does serve. Resolving the droop from
// curveGenerationOf() instead would let one verdict adjudicate its two halves
// on two different generations — the composed sentence would say "on a legacy
// DER" about one and "on a 7xx DER" about the other, and the unmappable clause
// would be computed for a third answer again.
//
// A family this row declares NEITHER a model NOR a stated absence for resolves
// to a NAMED ABSENCE, never to a measurable-looking target with model 0. The
// earlier version returned {Model: 0, NoRegisterHome: ""} there, which read as
// "measurable" one caller up: the oracle then asked the device for SunSpec
// model 0, failed to decode it, and reported "the DER's register image carries
// nothing for it" about a model that does not exist — beside an unmappable
// clause saying nothing was asserted. One verdict, two contradictory sentences.
// resolveTarget guards exactly this case; this now guards it identically.
func (d *droopBinding) resolve(fam invariant.CurveFamily) droopTarget {
	var t droopTarget
	switch fam {
	case invariant.FamilyLegacy:
		t = droopTarget{Model: d.ModelLegacy, Mapping: d.MappingLegacy,
			NoRegisterHome: d.NoRegisterHomeLegacy}
	case invariant.Family7xx:
		t = droopTarget{Model: d.Model7xx, Mapping: d.Mapping7xx,
			NoRegisterHome: d.NoRegisterHome7xx}
	default:
		return droopTarget{NoRegisterHome: "this DER's SunSpec curve generation could not be determined, " +
			"so which register bank (if any) would hold an authored opModFreqDroop on it has no answer here"}
	}
	if t.Model == 0 && t.NoRegisterHome == "" {
		t.NoRegisterHome = "this row declares no opModFreqDroop arm for the " + string(fam) + " generation " +
			"at all — neither a register home nor a reason there is none — so nothing southbound can be " +
			"asserted about the droop it authored, and this run says so rather than grading a bank no row " +
			"named"
	}
	return t
}

// hasHome reports whether this droop has a register home on a family, by the
// SAME rule the oracle uses to decide whether to measure it.
//
// It exists because the two decisions were made in two places and disagreed.
// authored() asked "is a Model named?" while the oracle asked "did the resolved
// arm state an absence?", and the nearest-model-plus-stated-refusal idiom the
// curve arms already use (BASIC-012's own 7xx curve arm is Model7xx: 711 WITH
// NoRegisterHome7xx set) satisfies the first and not the second. A droop arm
// written that way would have been skipped by the oracle as unmeasurable AND
// dropped from the unmappable clause as measurable: a PASS with an authored
// element neither compared nor disclosed, which is the exact overclaim this
// mechanism exists to prevent.
func (d *droopBinding) hasHome(fam invariant.CurveFamily) bool {
	return d.resolve(fam).NoRegisterHome == ""
}

// droopSettings hands the publisher the five values, or nil for a row that
// authors no droop. The row states them once, on the binding, and the publisher
// and the oracle both read that one statement — the same rule the breakpoints
// follow, and for the same reason: the published control and the oracle that
// judges it must not be able to disagree about what was commanded.
func droopSettings(d *droopBinding) *FreqDroopSettings {
	if d == nil {
		return nil
	}
	s := d.Settings
	return &s
}

// describe names the element and renders its five authored values, for a
// verdict sentence that has to say what was published.
func (d *droopBinding) describe() string { return droopElement + " " + d.describeValues() }

// describeValues is describe WITHOUT the element name, for a record that
// already carries the name in its own column — printing it twice reads as two
// different things having been sent.
func (d *droopBinding) describeValues() string {
	s := d.Settings
	return fmt.Sprintf("dBOF=%d dBUF=%d (thousandths of Hz) kOF=%d kUF=%d (thousandths, unitless) "+
		"openLoopTms=%d (hundredths of a second)", s.DBOF, s.DBUF, s.KOF, s.KUF, s.OpenLoopTms)
}

// droopElement is the procedure's own name for the inline element, written once
// so the binding, the authored-element record and every verdict spell it alike.
const droopElement = "opModFreqDroop"

// want711 translates the authored FreqDroopType into the model-711 engineering
// values the DER must be found holding.
//
// It is a translation this referee performs INDEPENDENTLY, from the two
// standards' own unit statements rather than from the product's table — the
// same rule wantDeptRef follows and for the same reason. Both sentences are
// quoted here so a reader can check the arithmetic without either codebase:
//
//	2018 p.242 FreqDroopType     SunSpec model 711 Ctl      conversion
//	──────────────────────────    ─────────────────────      ──────────
//	dBOF "in thousandths of Hz"   DbOf, scaled by Db_SF      / 1000 -> Hz
//	dBUF "in thousandths of Hz"   DbUf, scaled by Db_SF      / 1000 -> Hz
//	kOF  "in thousandths,         KOf,  scaled by K_SF       / 1000 -> unitless
//	      unitless"
//	kUF  same                     KUf,  scaled by K_SF       / 1000 -> unitless
//	openLoopTms "in hundredths    RspTms, scaled by          / 100  -> seconds
//	      of a second"            RspTms_SF
//
// NO NOMINAL FREQUENCY ENTERS, and that is the property that makes the mapping
// exact rather than interpretive: kOF/kUF are already per-unit frequency change
// per per-unit power change, and IEEE Std 2030.5-2018 (p.242) and the 711 spec
// state that in
// verbatim identical words, so nothing here needs to know whether the grid is
// 50 or 60 Hz. A referee that had to assume one would be grading its own
// assumption.
func (d *droopBinding) want711() invariant.DroopReading {
	s := d.Settings
	return invariant.DroopReading{
		DbOfHz:  float64(s.DBOF) / 1000,
		DbUfHz:  float64(s.DBUF) / 1000,
		KOf:     float64(s.KOF) / 1000,
		KUf:     float64(s.KUF) / 1000,
		RspTmsS: float64(s.OpenLoopTms) / 100,
	}
}

// The droop comparison's tolerances: HALF the last digit the WIRE itself can
// carry, per quantity, and nothing more.
//
// They are absolute, where every other tolerance in this suite is relative plus
// a floor (oracleTolerance), and the departure is deliberate. A droop dead band
// is printed by the procedure as an ABSOLUTE frequency — Figure 12's dBOF is
// 60030 thousandths, i.e. 60.030 Hz — so 1 % of it is 0.6 Hz, which is twenty
// times the whole 0.030 Hz offset the row is about: a relative tolerance would
// accept a device that had ignored the setting entirely. Half of the wire's own
// last digit is the tightest comparison that cannot fail an exact device, and
// anything coarser than that in the DEVICE (a scale factor with less resolution
// than the wire) is a real finding about that device — it cannot represent what
// it was commanded — and is reported rather than absorbed.
const (
	droopDeadbandToleranceHz = 0.0005 // wire step: thousandths of Hz
	droopGainTolerance       = 0.0005 // wire step: thousandths, unitless
	droopResponseToleranceS  = 0.005  // wire step: hundredths of a second

	// curveOpenLoopToleranceS is the same rule for DERCurve.openLoopTms, whose
	// wire unit is likewise hundredths of a second: half the last digit the wire
	// can carry. It is deliberately the same number as the droop's rather than a
	// reference to it — the two are different elements of different modes that
	// happen to share a unit, and collapsing them would make a future change to
	// one silently change the other.
	curveOpenLoopToleranceS = 0.005
)

// authoredElement is one element this row places on the wire BEYOND the
// breakpoints and the axis multipliers, with the register home — if any — it
// can be read back at on each generation.
//
// It exists so that "authored northbound" and "measurable southbound" stay
// SEPARATE facts about the same element. An element with no register home is
// not a gap (the bench sent exactly what the procedure prescribes) and it is
// not evidence of execution either (nothing on the device can show it landed),
// and a bundle that collapsed the two would either hold a row for a bench
// capability it has, or claim a measurement it never made.
type authoredElement struct {
	// Element is the procedure's own name for it.
	Element string
	// Value is what this row authored, in the wire's units.
	Value string
	// Home7xx / HomeLegacy name the register home per generation, empty for a
	// generation that has none.
	Home7xx, HomeLegacy string
	// Why7xx / WhyLegacy explain the absence, PER GENERATION, and each is read
	// only where its own home is empty.
	//
	// They are two fields rather than one because the reasons genuinely differ
	// and a single one printed the wrong explanation beside the wrong
	// generation: opModFreqDroop's absence on legacy is about model 127's
	// registers, and its (hypothetical) absence on 7xx would be about something
	// else entirely. A bundle that gave a reader the 7xx reason under "no
	// register home on a legacy 12x DER" would send them to the wrong model.
	Why7xx, WhyLegacy string
}

// homeOn returns this element's register home on a family, and whether it has
// one there.
func (a authoredElement) homeOn(fam invariant.CurveFamily) (string, bool) {
	home := a.Home7xx
	if fam == invariant.FamilyLegacy {
		home = a.HomeLegacy
	}
	return home, home != ""
}

// whyOn returns the reason this element has no register home on a family.
func (a authoredElement) whyOn(fam invariant.CurveFamily) string {
	why := a.Why7xx
	if fam == invariant.FamilyLegacy {
		why = a.WhyLegacy
	}
	return orText(why, "this row records no reason for the absence")
}

// openLoopHome names the register a curve model's own open-loop response time
// lives in, or "" for a model that declares none.
//
// SunSpec 705 and 706 both declare Crv.RspTms — "Open Loop Response Time",
// uint32 seconds scaled by the model's RspTms_SF — and that is exactly what
// IEEE 2030.5's DERCurve.openLoopTms commands. 712 declares no such register.
//
// NO LEGACY MODEL HAS ONE, and the near-miss is worth naming because it is what
// a reader will check: 126 declares Crv.RmpTms and 132/134 declare
// Crv.RmpPt1Tms, both documented as "the time of the PT1 ... to accomplish a
// change of 95%%". A PT1 filter time constant is rampPT1Tms (IEEE Std
// 2030.5-2018 p.253), a
// SEPARATE element of the same DERCurve, and writing an openLoopTms into it
// would command a different behaviour under a name that sounds alike.
func openLoopHome(model uint16) string {
	switch model {
	case sunspec.ModelDERVoltVar, sunspec.ModelDERVoltWatt:
		return fmt.Sprintf("M%d Crv.RspTms (uint32 seconds x RspTms_SF, \"Open Loop Response Time\")", model)
	}
	return ""
}

// wantOpenLoopS is the authored openLoopTms in the DEVICE's units: hundredths
// of a second on the wire (IEEE Std 2030.5-2018 p.253, the standard's own unit
// for the element) into the
// seconds 705/706 store. One fixed decimal shift, performed here, once.
func (b *curveBinding) wantOpenLoopS() (float64, bool) {
	if b.OpenLoopTms == nil {
		return 0, false
	}
	return float64(*b.OpenLoopTms) / 100, true
}

// authored is the list of elements this row places on the wire beyond the
// breakpoints and multipliers — the positive half of the record whose negative
// half is Gaps.
func (b *curveBinding) authored() []authoredElement {
	var out []authoredElement
	if b.OpenLoopTms != nil {
		// openLoopTms DOES have a 7xx register home on the two models that
		// declare one, and saying otherwise was a false statement of fact
		// quoted into every bundle this row appeared in: SunSpec 705 and 706
		// both carry Crv.RspTms, labelled "Open Loop Response Time" in their own
		// definitions and scaled by RspTms_SF — which is precisely where IEEE
		// 2030.5's DERCurve.openLoopTms lands. 712 declares none, and neither
		// does any legacy bank (their Crv.RmpTms / Crv.RmpPt1Tms is a PT1 FILTER
		// time, rampPT1Tms — IEEE Std 2030.5-2018 p.253, a different element).
		out = append(out, authoredElement{
			Element:    "DERCurve.openLoopTms",
			Value:      fmt.Sprintf("%d (hundredths of a second)", *b.OpenLoopTms),
			Home7xx:    openLoopHome(b.Model7xx),
			HomeLegacy: openLoopHome(b.ModelLegacy),
			Why7xx:     noOpenLoopTmsRegister7xx,
			WhyLegacy:  noOpenLoopTmsRegisterLegacy,
		})
	}
	// The autonomous volt-reference pair. Authored northbound, asserted about
	// southbound by NOTHING on either generation — and unlike openLoopTms that
	// is not a gap in SunSpec's coverage but a difference in kind: 2030.5's
	// autonomous vRef adjustment is an inverter-internal behaviour with no
	// single register that holds "is it on", and the 705 VRefAutoEna/VRefAutoTms
	// pair that looks like a home is model 705's OWN volt-var reference
	// automation, written by the DER's settings rather than by a curve. Grading
	// a DERCurve element against it would be the substitution this suite
	// refuses, so the row says so instead.
	if b.VRef != nil {
		// vRef is the one member of this family with a southbound assertion, and
		// it is the STRONGEST kind: it does not land in a register of its own,
		// it moves the breakpoints, so wantPoints() folds it in and the ordinary
		// point comparison measures it on BOTH generations. Saying "no register
		// home" here would be true and misleading — a reader would take it as
		// "not asserted", and it is asserted harder than anything else the row
		// authors.
		out = append(out, authoredElement{
			Element: "DERCurve.vRef",
			Value: fmt.Sprintf("%d (hundredths of a percent) — IEEE 2030.5-2018 p.250 multiplies every "+
				"published x by vRef/10 000, so the breakpoints this row asserts on the device are the "+
				"SCALED ones, not the ones printed above", *b.VRef),
			Home7xx:    "the curve bank's own point table (the scaling is folded into the expected x values)",
			HomeLegacy: "the curve bank's own point table (the scaling is folded into the expected x values)",
		})
	}
	if b.AutonomousVRefEnable != nil {
		el := authoredElement{
			Element:   "DERCurve.autonomousVRefEnable",
			Value:     fmt.Sprintf("%t", *b.AutonomousVRefEnable),
			Why7xx:    noAutonomousVRefRegister,
			WhyLegacy: noAutonomousVRefRegister,
		}
		// AN ENABLE OF TRUE *IS* ASSERTED SOUTHBOUND ON 705, and saying
		// otherwise was a verdict contradicting itself.
		//
		// This element used to be disclosed as having no register home on either
		// generation, which was true while nothing read Crv.VRefAutoEna. It is
		// read now, and IEEE Std 2030.5-2018 p.252's execute-without clause makes
		// the reading load-bearing: the device must come back NOT armed. So the
		// verdict was carrying "this referee asserts nothing about it southbound"
		// in the same sentence as the assertion — the exact class of false
		// disclosure this suite's authored/unmappable split exists to prevent,
		// arriving because a check was added and its disclosure was not moved
		// with it.
		//
		// WHAT IS ASSERTED IS A NEGATIVE, and the home says so: the register must
		// be CLEAR. An enable of FALSE keeps the old disclosure, because there is
		// then nothing the standard requires of the register in either direction
		// and a device that happens to be armed is running its own configuration.
		if *b.AutonomousVRefEnable {
			el.Home7xx = "model 705's Crv.VRefAutoEna, asserted to be CLEAR — 2018 p.252 requires a DER " +
				"unable to support the adjustment to execute the curve WITHOUT it, so the conformant " +
				"reading of this register is the unset one"
			el.WhyLegacy = "the legacy 12x banks declare no autonomous volt-reference automation at all, " +
				"so on that generation this element is served northbound and nothing southbound can " +
				"show what became of it"
		}
		out = append(out, el)
	}
	if b.AutonomousVRefTimeConstant != nil {
		out = append(out, authoredElement{
			Element:   "DERCurve.autonomousVRefTimeConstant",
			Value:     fmt.Sprintf("%d (hundredths of a second)", *b.AutonomousVRefTimeConstant),
			Why7xx:    noAutonomousVRefRegister,
			WhyLegacy: noAutonomousVRefRegister,
		})
	}
	if b.Droop != nil {
		// The home is read through hasHome — the SAME predicate the oracle
		// measures by — so "disclosed as unmappable" and "skipped as
		// unmeasurable" can never come apart. Naming a model is not enough: an
		// arm may name its NEAREST model and refuse to grade against it, which
		// is measurable to one predicate and not the other.
		home := func(fam invariant.CurveFamily, model uint16) string {
			if !b.Droop.hasHome(fam) {
				return ""
			}
			return fmt.Sprintf("M%d (%s)", model, droopRegisterNames)
		}
		out = append(out, authoredElement{
			Element:    droopElement,
			Value:      b.Droop.describeValues(),
			Home7xx:    home(invariant.Family7xx, b.Droop.Model7xx),
			HomeLegacy: home(invariant.FamilyLegacy, b.Droop.ModelLegacy),
			// Each generation's own reason, from that generation's own arm.
			Why7xx:    b.Droop.resolve(invariant.Family7xx).NoRegisterHome,
			WhyLegacy: b.Droop.resolve(invariant.FamilyLegacy).NoRegisterHome,
		})
	}
	return out
}

// describeAuthored renders every authored element with its per-generation
// register home, for the criterion that has to say what went on the wire and
// what can be read back.
func describeAuthored(els []authoredElement) string {
	if len(els) == 0 {
		return "none beyond the breakpoints and axis multipliers"
	}
	parts := make([]string, 0, len(els))
	for _, a := range els {
		// The REASON rides with the generation it is about, and only where
		// there is an absence to explain. An element with a home on both has
		// nothing to account for, and a trailing "this row records no reason"
		// beside it would read as a defect in the row rather than the ordinary
		// case.
		clause := func(gen string, fam invariant.CurveFamily, h string) string {
			if h != "" {
				return gen + ": " + h
			}
			return "no register home on " + gen + " — " + a.whyOn(fam)
		}
		parts = append(parts, fmt.Sprintf("%s = %s [%s; %s]", a.Element, a.Value,
			clause("a 7xx DER", invariant.Family7xx, a.Home7xx),
			clause("a legacy 12x DER", invariant.FamilyLegacy, a.HomeLegacy)))
	}
	return strings.Join(parts, "; ")
}

// unmappableOn are the elements this row authored that have NO register home on
// a generation — served northbound, and asserted about by nothing southbound.
func (b *curveBinding) unmappableOn(fam invariant.CurveFamily) []authoredElement {
	var out []authoredElement
	for _, a := range b.authored() {
		if _, ok := a.homeOn(fam); !ok {
			out = append(out, a)
		}
	}
	return out
}

// describeUnmappable is the sentence an oracle verdict carries so that an
// authored element with no device home is NAMED where the measurement is
// reported, and never silently dropped between the two.
func describeUnmappable(fam invariant.CurveFamily, els []authoredElement) string {
	if len(els) == 0 {
		return ""
	}
	parts := make([]string, 0, len(els))
	for _, a := range els {
		parts = append(parts, fmt.Sprintf("%s = %s (%s)", a.Element, a.Value, a.whyOn(fam)))
	}
	return " AUTHORED BUT NOT DEVICE-MAPPABLE: this row also placed " + strings.Join(parts, "; ") +
		" on the wire, and this generation stores it in no register — so it was SERVED to the DUT and " +
		"this referee asserts nothing about it southbound. That is a property of the device model, not a " +
		"gap in the bench, and it is stated here rather than left out so no reader can mistake this " +
		"verdict for a measurement of it."
}

// materialGaps are the gaps that mean this row was not run to its procedure.
func (b *curveBinding) materialGaps() []curveGap {
	var out []curveGap
	for _, g := range b.Gaps {
		if g.Material {
			out = append(out, g)
		}
	}
	return out
}

// describeGaps renders every gap, material or not, for a criterion that has to
// say what was left off the wire.
func describeGaps(gaps []curveGap) string {
	if len(gaps) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(gaps))
	for _, g := range gaps {
		parts = append(parts, fmt.Sprintf("%s (procedure: test %s, default %s) — %s",
			g.Element, g.Prescribed, g.Default, g.Why))
	}
	return strings.Join(parts, "; ")
}

// curveTarget is the southbound home this row resolved to on THIS DER.
type curveTarget struct {
	// Model is the SunSpec model whose live curve must hold this row's content
	// on this DER. Zero when NoRegisterHome is set and the arm names no
	// nearest model at all.
	Model uint16
	// Family is which idiom that model belongs to, which decides what "live"
	// means and whether a writable live bank is suspicious.
	Family invariant.CurveFamily
	// Mapping / NoRegisterHome are the resolved arm's provenance and refusal.
	Mapping        string
	NoRegisterHome string
}

// curveGeneration is the answer to "which SunSpec curve generation is this
// DER?", and it has FOUR values because the question has four honest answers.
type curveGeneration int

const (
	genNone      curveGeneration = iota // serves neither family's curve models
	genLegacy                           // serves 12x and not 7xx
	gen7xx                              // serves 7xx and not 12x
	genAmbiguous                        // serves BOTH
)

func (g curveGeneration) String() string {
	switch g {
	case genLegacy:
		return string(invariant.FamilyLegacy)
	case gen7xx:
		return string(invariant.Family7xx)
	case genAmbiguous:
		return curveGenAmbiguous
	}
	return curveGenUnknown
}

// curveGenerationOf reports which SunSpec curve generation a DER belongs to,
// read from the models it actually serves.
//
// A DEVICE SERVING BOTH IS ITS OWN ANSWER, not a tie-break. This used to prefer
// legacy silently, which is the worst of the available behaviours: no row in
// this suite was written for a device carrying 705 AND 126, so a silent choice
// grades a bank the row's author never considered — and on BASIC-015, whose
// posture differs in KIND by generation, it would swap the refusal assertion
// for an execution one, so critRefusalAnswered (the LXR-002 catcher: a DUT
// reporting Started for an axis nothing executed) would never run and the 712
// fingerprint would never be taken. A false negative on a real defect class is
// a worse outcome than refusing to grade, so the ambiguity is reported and the
// caller decides.
func curveGenerationOf(uv invariant.UnitView) curveGeneration {
	serves := func(models []uint16) bool {
		for _, m := range models {
			for _, have := range uv.Models {
				if have == m {
					return true
				}
			}
		}
		return false
	}
	var sevenXx []uint16
	for _, m := range invariant.CurveModels() {
		if axis, ok := invariant.CurveAxisOf(m); ok && axis.Family == invariant.Family7xx {
			sevenXx = append(sevenXx, m)
		}
	}
	legacy, seven := serves(invariant.LegacyCurveModels()), serves(sevenXx)
	switch {
	case legacy && seven:
		return genAmbiguous
	case legacy:
		return genLegacy
	case seven:
		return gen7xx
	}
	return genNone
}

// describeGeneration renders which models put the DER in the generation it is
// in, for a finding that has to be checkable.
func describeGeneration(uv invariant.UnitView) string {
	return fmt.Sprintf("generation %s; the models the DER serves are %s",
		curveGenerationOf(uv), modelList(uv))
}

// curveResolution says how a row's southbound arm was decided, or why it could
// not be. The three outcomes take different verdict paths and must stay
// distinguishable: an ambiguous device and an unequipped one are not the same
// finding and do not have the same owner.
type curveResolution int

const (
	curveResolved   curveResolution = iota // an arm was selected
	curveUnresolved                        // the DER has no home for this mode on either generation
	curveAmbiguous                         // the DER serves BOTH generations; this suite refuses to choose
)

// resolveTarget picks this row's southbound arm from the DER's own model chain.
//
// It resolves by GENERATION first and by named-model presence second. The order
// matters for the rows whose 7xx arm names a NEAREST model rather than a real
// home (BASIC-012 points at 711, which stores no breakpoints): on a 7xx DER
// that arm must be selected so the row can say WHY there is nothing to measure,
// and asking "is 711 served?" first would have made a 7xx DER that happens not
// to publish 711 fall through to the legacy arm and grade against a model it
// does not serve either.
//
// A device serving BOTH generations resolves to nothing. See curveGenerationOf
// for why refusing to grade beats guessing here.
func (b *curveBinding) resolveTarget(uv invariant.UnitView) (curveTarget, curveResolution) {
	legacyArm := curveTarget{Model: b.ModelLegacy, Family: invariant.FamilyLegacy,
		Mapping: b.MappingLegacy, NoRegisterHome: b.NoRegisterHomeLegacy}
	sevenArm := curveTarget{Model: b.Model7xx, Family: invariant.Family7xx,
		Mapping: b.Mapping7xx, NoRegisterHome: b.NoRegisterHome7xx}

	switch curveGenerationOf(uv) {
	case genAmbiguous:
		return curveTarget{}, curveAmbiguous
	case genLegacy:
		if b.ModelLegacy != 0 || b.NoRegisterHomeLegacy != "" {
			return legacyArm, curveResolved
		}
	case gen7xx:
		if b.Model7xx != 0 || b.NoRegisterHome7xx != "" {
			return sevenArm, curveResolved
		}
	}
	// No generation was recognised (or the row has no arm for the one that
	// was). Fall back to whichever named model the DER does serve, which is the
	// only remaining fact about this device that can decide it.
	//
	// LEGACY IS TRIED FIRST, matching curveGenerationOf's own ordering. The two
	// used to disagree — generation resolution preferred legacy, this fallback
	// preferred 7xx — which meant a device the first function called legacy
	// could still be graded against a 7xx bank here. Two tie-breaks pointing
	// opposite ways in one resolution path is a bug waiting for the device that
	// reaches both.
	for _, arm := range []curveTarget{legacyArm, sevenArm} {
		if arm.Model == 0 {
			continue
		}
		for _, have := range uv.Models {
			if have == arm.Model {
				return arm, curveResolved
			}
		}
	}
	return curveTarget{}, curveUnresolved
}

// describeTargets renders both arms, for a criterion's How and for the
// unresolved FAIL — which has to name what it was looking for on each
// generation before it says it found neither.
func (b *curveBinding) describeTargets() string {
	part := func(gen string, model uint16, none string) string {
		switch {
		case none != "":
			if model != 0 {
				return fmt.Sprintf("%s: no register home (nearest model M%d) — %s", gen, model, none)
			}
			return fmt.Sprintf("%s: no register home — %s", gen, none)
		case model != 0:
			return fmt.Sprintf("%s: M%d", gen, model)
		default:
			return gen + ": this row declares no target"
		}
	}
	return part("on a 7xx DER", b.Model7xx, b.NoRegisterHome7xx) + "; " +
		part("on a legacy 12x DER", b.ModelLegacy, b.NoRegisterHomeLegacy)
}

// wantPoints converts the published breakpoints into the device engineering
// values the oracle expects to read back, applying the axis multipliers exactly
// once, here.
func (b *curveBinding) wantPoints() []invariant.CurvePoint {
	out := make([]invariant.CurvePoint, 0, len(b.Points))
	for _, p := range b.Points {
		out = append(out, invariant.CurvePoint{
			X: applyMult(b.scaledX(p.X), b.XMult),
			Y: applyMult(p.Y, b.YMult),
		})
	}
	return out
}

// scaledX applies DERCurve.vRef to one published x value, which is the whole of
// what IEEE Std 2030.5-2018 p.250 says about it:
//
//	"If VRef is present in DERCurve, then the x value of each pair is
//	 additionally multiplied by VRef/10 000."
//
// DERIVED FROM THAT SENTENCE, not from the product. lexa-gw applies the same
// adjustment in its authority (applyVRef, internal/authority/csipin_curves.go)
// and this referee must not read it: an oracle that computed its expectation
// with the product's own expression would agree with the product however wrong
// both were, which is the IW15-011 shared-oracle blindness one arithmetic step
// further down than the bit tables.
//
// ROUNDING IS NOT SPECIFIED BY THE STANDARD, and this rounds half away from
// zero — the ordinary convention, and the one that keeps a symmetric curve
// symmetric. A device (or a product) that rounds half-to-even instead differs by
// at most one raw unit on a point that lands exactly on .5, which the caller's
// own per-value tolerance absorbs; MatchPoints takes that tolerance as a
// function precisely because a rounding step is a property of the scale in play.
// The oracle therefore does NOT turn a rounding convention into a conformance
// verdict, while still catching the failure that matters: a device holding the
// UNSCALED curve, which for any vRef worth sending is off by percent, not by a
// unit.
//
// Y IS UNTOUCHED. The sentence is about the x value of each pair, and a volt-var
// curve's y axis is a reactive-power percentage whose base is yRefType — nothing
// to do with the voltage reference. Scaling both would be a plausible-looking
// error that no test comparing only shapes would catch.
func (b *curveBinding) scaledX(x float64) float64 {
	if b.VRef == nil || *b.VRef == 0 {
		return x
	}
	// vRef IS opModVoltVar-ONLY, AND SO IS THIS SCALING. IEEE Std 2030.5-2018
	// p.253: "If the curveType is opModVoltVar, then this field MAY be present.
	// If the curveType is not opModVoltVar, then this field SHALL NOT be
	// present." The product refuses a vRef on any other mode at receipt
	// ('vref-on-non-voltvar'), and this bench refuses to AUTHOR one
	// (sim/gridsim/curve.go's vrefFamily), so a non-volt-var row carrying a
	// vRef is not reachable through any conformant path.
	//
	// The guard is here anyway because "not reachable" was doing load-bearing
	// work with nothing enforcing it: a binding is a plain struct, a future row
	// can set VRef on a freq-watt mode in one line, and the oracle would then
	// have silently scaled its expectation for a control the DUT is required to
	// REFUSE — a fabricated southbound expectation for a curve that never
	// executes. Returning x unscaled makes the oracle's expectation match what a
	// conformant DUT does with such a row, which is nothing.
	if b.Mode != "volt_var" {
		return x
	}
	scaled := x * float64(*b.VRef) / 10000
	if scaled >= 0 {
		return math.Floor(scaled + 0.5)
	}
	return math.Ceil(scaled - 0.5)
}

// wantDeptRef translates the yRefType this row PUBLISHES into the SunSpec
// DeptRef the DER must be found holding, or returns ok=false for a mode whose
// curve bank carries no such register.
//
// It is a translation this referee performs INDEPENDENTLY, from the standards
// text rather than from the product's table, which is the whole point of the
// check. A curve's y values are a percentage and a percentage is not a quantity
// without its base: IEEE 2030.5 names that base on every DERCurve (yRefType,
// minOccurs=1) and SunSpec names it per bank (DeptRef). Until 2026-08-14 the
// product never translated one into the other — it copied whatever DeptRef the
// device's template already held and wrote the commanded points underneath it —
// and the read-back hash could not see it, because the hash carries the doc's
// OWN yRefType at both ends and so can only ever confirm that the POINTS round
// tripped. This oracle reads the register.
//
// The mapping, from IEEE Std 2030.5-2018's own element documentation
// (opModVoltVar p.250, opModVoltWatt p.250, opModWattVar p.251):
//
//	opModVoltVar / opModWattVar   y is "one of %setMaxW, %setMaxVar, or
//	                              %statVarAvail" -> W_MAX_PCT / VAR_MAX_PCT /
//	                              VAR_AVAL_PCT
//	opModVoltWatt                 y is "an active power output in %setMaxW"
//	                              and nothing else -> W_MAX_PCT
//
// ok=false is returned for any other model, and for a yRefType outside the set
// its mode allows — those are curves a conformant DUT REFUSES, so this row has
// no register expectation to assert and says so instead of inventing one.
func (b *curveBinding) wantDeptRef(model uint16) (uint16, bool) {
	switch model {
	case sunspec.ModelDERVoltVar, sunspec.ModelDERWattVar:
		switch b.YRefType {
		case derUnitRefSetMaxW:
			return deptRefWMaxPct, true
		case derUnitRefSetMaxVar:
			return deptRefVarMaxPct, true
		case derUnitRefStatVarAvail:
			return deptRefVarAvalPct, true
		}
	case sunspec.ModelDERVoltWatt:
		if b.YRefType == derUnitRefSetMaxW {
			return deptRefWMaxPct, true
		}

	// THE LEGACY CODES ARE 1-BASED and this is a second, independent
	// transcription of the same standards text — not the 7xx answer with one
	// added. Deriving it by arithmetic would work today and would keep working
	// for the wrong reason: 126's admissible set happens to line up with
	// DERUnitRefType 1/2/3 one for one, and 132's does not (its second code is
	// %WAvail, which is DERUnitRefType 7 and not 2). A referee that added one
	// would silently accept %setMaxVar on a volt-WATT curve.
	case sunspec.ModelVoltVarLegacy:
		switch b.YRefType {
		case derUnitRefSetMaxW:
			return legacyDeptRefWMax, true
		case derUnitRefSetMaxVar:
			return legacyDeptRefVArMax, true
		case derUnitRefStatVarAvail:
			return legacyDeptRefVArAval, true
		}
	case sunspec.ModelVoltWattLegacy:
		switch b.YRefType {
		case derUnitRefSetMaxW:
			return legacyDeptRefWMax, true
		case derUnitRefStatWAvail:
			return legacyDeptRefWAvail, true
		}

		// 131 (Watt-PF) and 134 (Freq-Watt) carry NO DeptRef register. 131's y is a
		// power factor, which is not a percentage of anything; 134's is % WRef,
		// which is a REGISTER in the same block rather than an enum code. Returning
		// ok=false is the honest answer: there is no reference register to check,
		// and 134's actual base is rendered by the referee on every reading.
	}
	return 0, false
}

// DERUnitRefType codes (IEEE Std 2030.5-2018 p.256, "Specifies context for
// interpreting percent values") and the SunSpec DeptRef codes they translate to. Named here so the
// rows and the oracle read one vocabulary; see wantDeptRef for the provenance
// of the translation and invariant.DeptRefName for the DeptRef enums'.
const (
	derUnitRefNA           uint8 = 0
	derUnitRefSetMaxW      uint8 = 1
	derUnitRefSetMaxVar    uint8 = 2
	derUnitRefStatVarAvail uint8 = 3

	derUnitRefStatWAvail uint8 = 7

	deptRefWMaxPct    uint16 = 0 // 705/706/712
	deptRefVarMaxPct  uint16 = 1 // 705/712 only
	deptRefVarAvalPct uint16 = 2 // 705/712 only

	// The LEGACY DeptRef codes are 1-based and are a different enum, not an
	// offset of the one above. 126 declares {1 %WMax, 2 %VArMax, 3 %VArAval};
	// 132 declares {1 %WMax, 2 %WAvail}. Transcribed from the vendored
	// model_126.json / model_132.json enum blocks.
	legacyDeptRefWMax    uint16 = 1
	legacyDeptRefVArMax  uint16 = 2
	legacyDeptRefVArAval uint16 = 3
	legacyDeptRefWAvail  uint16 = 2
)

// applyMult applies a 2030.5 power-of-ten axis multiplier.
func applyMult(v float64, mult int8) float64 {
	switch {
	case mult == 0:
		return v
	case mult > 0:
		for i := int8(0); i < mult; i++ {
			v *= 10
		}
	default:
		for i := int8(0); i > mult; i-- {
			v /= 10
		}
	}
	return v
}

// describePublished renders the breakpoints this row published, for a finding
// that has to show both curves side by side.
func (b *curveBinding) describePublished() string {
	pts := make([]string, 0, len(b.Points))
	for _, p := range b.Points {
		pts = append(pts, fmt.Sprintf("(%s, %s)", trimNum(p.X), trimNum(p.Y)))
	}
	s := fmt.Sprintf("%d breakpoint(s) %s", len(b.Points), strings.Join(pts, " "))
	if b.XMult != 0 || b.YMult != 0 {
		s += fmt.Sprintf(" (x multiplier 10^%d, y multiplier 10^%d)", b.XMult, b.YMult)
	}
	// vRef makes PUBLISHED and ASSERTED two different curves, and a finding that
	// showed only the first would be quietly wrong about what the device was
	// required to hold. IEEE Std 2030.5-2018 p.250: "If VRef is present in
	// DERCurve, then the x value of each pair is additionally multiplied by
	// VRef/10 000." So the row publishes these x values AND a reference, and the
	// device must hold their product — which is what the comparison uses.
	if b.VRef != nil && *b.VRef != 0 {
		want := make([]string, 0, len(b.Points))
		for _, p := range b.wantPoints() {
			want = append(want, fmt.Sprintf("(%s, %s)", trimNum(p.X), trimNum(p.Y)))
		}
		s += fmt.Sprintf(", with vRef=%d — IEEE 2030.5-2018 p.250 multiplies every x by vRef/10 000, so "+
			"the curve the DEVICE must hold is %s and it is those values this row asserts",
			*b.VRef, strings.Join(want, " "))
	}
	return s
}

func trimNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// derUnitRefName spells a DERUnitRefType out in a finding, so a reader sees
// what the row published rather than a code.
func derUnitRefName(v uint8) string {
	switch v {
	case 0:
		return "N/A — no reference named"
	case 1:
		return "%setMaxW"
	case 2:
		return "%setMaxVar"
	case 3:
		return "%statVarAvail"
	case 4:
		return "%setEffectiveV"
	case 5:
		return "%setMaxChargeRateW"
	case 6:
		return "%setMaxDischargeRateW"
	case 7:
		return "%statWAvail"
	}
	return "reserved/unknown"
}

// curvePointTolerance is the slack the curve oracle allows one breakpoint
// value: 1 % of the value plus half a unit, the same shape (and for the same
// stated reason) as oracleTolerance — the last register count of a device's own
// scale factor must not fail a curve that is otherwise exactly right.
func curvePointTolerance(want float64) float64 { return oracleTolerance(want, 0.5) }

// ── Curve rows: the oracle ──────────────────────────────────────────────────

// oracleCurve builds the independent southbound oracle for a curve-linked row:
// it reads the DER's OWN curve-model registers through internal/invariant
// (which shares only the SunSpec register-offset tables with the product and
// none of its CSIP/derbase interpretation) and answers ONE question — does the
// DER's live curve for this mode hold the breakpoints THIS row published, in a
// function that is adopted and enabled?
//
// Every terminal is decided. There is no Skip and no "unavailable" that a row
// can rest on: an unreachable sidecar is reported through the same
// Unavailable→FAIL path oracleOutcome already applies to the scalar rows, and
// every register state below is a statement about what the DER holds.
//
// The checks are ordered so the FAIL says the most useful thing first — the
// model is absent, or present-but-never-adopted, or adopted-but-disabled, or
// adopted-and-enabled-with-the-wrong-content — because those are four different
// defects with four different owners, and a bundle that collapsed them into
// "the curve did not land" would send every one of them to the wrong person.
//
// ── A ROW CAN CARRY TWO KINDS OF CONTENT, AND THEY LIVE ON DIFFERENT
//
//	GENERATIONS (curve plan #32) ────────────────────────────────────────────
//
// BASIC-012's Figure 12 prescribes a frequency-WATT curve and an immediate
// frequency-DROOP control on one DERControl, and the two have opposite
// register fates: the 7xx set stores frequency response PARAMETRICALLY in model
// 711 and has no breakpoint table for the curve anywhere, while the legacy 12x
// set stores the breakpoints in model 134 and has no home for the droop
// parameters at all. So this oracle measures WHATEVER THIS DER CAN HOLD of what
// the row authored, and states plainly which authored content it did not
// assert — rather than reporting a decided FAIL because one half of a row has
// no home on the bench that is running.
//
// Both halves, where both have homes, must hold. A device that adopted the
// curve and ignored the droop has not executed this control.
func oracleCurve(b *curveBinding) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		published := b.describePublished()

		// WHICH register bank this row is about is a question about the DEVICE,
		// answered here from the models it actually serves — not from
		// configuration, and not from a single Model the row was built with.
		// The same catalog row therefore measures 705 on a 7xx bench and 126 on
		// a legacy one, and says which it did.
		target, how := b.resolveTarget(uv)
		switch how {
		case curveAmbiguous:
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound and the DER under test serves BOTH SunSpec curve "+
					"generations, so which register bank this row is about has no answer: %s. This row "+
					"declares %s. No row in this suite was written for a device carrying both families, "+
					"and choosing one silently would grade a bank the row's author never considered — so "+
					"the ambiguity is reported as a FAIL rather than resolved by a tie-break. REMEDY: "+
					"grade this DER on a bench serving one generation, or extend the row with an explicit "+
					"per-device target",
				published, describeGeneration(uv), b.describeTargets())}
		case curveUnresolved:
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound and the DER under test serves NEITHER generation's "+
					"register home for it (%s). The models the DER does serve are %s. With no southbound "+
					"bank to read, this row's second half cannot be measured at all — which is reported as a "+
					"FAIL rather than skipped, because an unmeasured criterion is not a satisfied one",
				published, b.describeTargets(), modelList(uv))}
		}
		cv := uv.Curve(oracleSimName, target.Model)

		// The DROOP half, resolved on the FAMILY THE BREAKPOINT HALF RESOLVED
		// TO — target.Family, not the generation read off the device. The two
		// can differ: resolveTarget falls back to a named model when the DER's
		// generation is unrecognised or when this row has no arm for it, and a
		// verdict that adjudicated its two halves on two different generations
		// would describe a device that does not exist. nil for every row that
		// authors no opModFreqDroop, so nothing that does not carry one pays
		// for this.
		var droop *droopTarget
		if b.Droop != nil {
			d := b.Droop.resolve(target.Family)
			droop = &d
		}
		// Whatever this row authored that THIS generation stores in no register.
		// It rides on every verdict below rather than on one of them: an
		// element served northbound and asserted about by nothing must be named
		// wherever the measurement is reported, or a reader takes the verdict
		// for a statement about it.
		unmapped := describeUnmappable(target.Family, b.unmappableOn(target.Family))

		if target.NoRegisterHome != "" {
			// The BREAKPOINTS have no home here. Before this was the end of the
			// row: a decided FAIL, because there was nothing else the row
			// carried. A row that ALSO authored a droop with a real home on
			// this generation is a different case — there IS something to
			// measure, and refusing to measure it would be the mirror of the
			// substitution this suite exists to refuse (asserting nothing where
			// an exact assertion exists).
			if droop != nil && droop.NoRegisterHome == "" {
				return withNote(b.droopOutcome(uv, *droop, target, published), unmapped)
			}
			return withNote(Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound, and there is NO southbound register home on this DER for "+
					"that content: %s. The row's southbound half therefore cannot be measured at all, which "+
					"is reported as a FAIL rather than skipped — an unmeasured criterion is not a satisfied "+
					"one. What the DER does hold on the nearest model: %s",
				published, target.NoRegisterHome, cv.Describe())}, unmapped)
		}
		f := curveContentOutcome(b, uv, target, cv, published)
		if droop == nil || droop.NoRegisterHome != "" {
			return withNote(f, unmapped)
		}
		// BOTH halves have a home, so BOTH are measured and the WORSE answer
		// decides. A device that adopted the curve and ignored the droop has
		// executed half of this control, and half is not execution.
		//
		// The droop is judged even when the curve half did not PASS, and the
		// comparison is by SEVERITY rather than by "the curve failed, stop".
		// Returning the curve's answer whenever it was not a PASS would let a
		// WARN (an index-0 curve reporting ReadOnly=false, severity 2) stand in
		// front of a droop FAIL (severity 3) and report the row two grades
		// better than the DER deserves — the same absence-reads-as-success
		// shape this file exists to remove, one composition level up.
		//
		// BOTH sentences are carried on EVERY outcome, not only on a double
		// PASS. Reporting the worse half alone would leave a bundle with no
		// trace that the other half was measured at all — which is the same
		// "the reader cannot tell what was asserted" failure this change exists
		// to remove, in the red direction: a row failing on its curve would look
		// exactly like a row whose droop nobody read.
		d := b.droopOutcome(uv, *droop, target, published)
		worse, other := f, d
		if d.Verdict.Severity() > f.Verdict.Severity() {
			worse, other = d, f
		}
		worse.Observed += " AND " + other.Observed
		return withNote(worse, unmapped)
	}
}

// withNote appends a note to a finding's observation, leaving the verdict
// alone. An empty note is a no-op, so a row with nothing to disclose reads
// exactly as it did before.
func withNote(f Finding, note string) Finding {
	if note == "" {
		return f
	}
	f.Observed += note
	return f
}

// droopOutcome measures the authored opModFreqDroop against the DER's own
// parametric droop control, and is the reason a Pointless model is not an
// unmeasurable one.
//
// The order of the checks mirrors the breakpoint oracle's for the same reason:
// model absent, present-but-never-adopted, adopted-but-disabled, and
// adopted-and-enabled-with-the-wrong-parameters are four different defects with
// four different owners.
//
// It states, on EVERY terminal, that the row's breakpoint half is not asserted
// here when that is the case. A verdict reading "the DER holds the droop this
// row commanded" against a row whose Figure also prescribes a curve would
// otherwise be read as covering both.
func (b *curveBinding) droopOutcome(uv invariant.UnitView, target droopTarget, curve curveTarget,
	published string) Finding {
	preface := ""
	if curve.NoRegisterHome != "" {
		preface = fmt.Sprintf("this row also published %s northbound, and this DER's generation stores "+
			"frequency-watt BREAKPOINTS in no register at all (%s) — so the curve half is served and "+
			"NOT asserted here, and what follows is about the parametric droop only. ",
			published, curve.NoRegisterHome)
	}
	cv := uv.Curve(oracleSimName, target.Model)
	authored := b.Droop.describe()
	if !cv.Present {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%sthis row published %s and the DER's own register image carries NOTHING for it: %s. %s The "+
				"models the DER does serve are %s",
			preface, authored, cv.Describe(), target.Mapping, modelList(uv))}
	}
	if cv.Droop == nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%sthis row published %s and the DER serves %s but its droop control did not decode, so there "+
				"is nothing to compare: %s. %s",
			preface, authored, cv.Axis.Name, cv.Describe(), target.Mapping)}
	}
	if !cv.Adopted {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%sthis row published %s and the DER's %s adopt handshake never COMPLETED, so no droop was "+
				"taken up: %s. %s",
			preface, authored, cv.Axis.Name, cv.Describe(), target.Mapping)}
	}
	if diff := droopMismatch(b.Droop.want711(), *cv.Droop); diff != "" {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%sthe DER's %s holds a droop control that is NOT the one this row published: %s. This row "+
				"published %s, which is %s on this device. Full register state: %s",
			preface, cv.Axis.Name, diff, authored, describeWant711(b.Droop.want711()), cv.Describe())}
	}
	if !cv.Enabled {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%sthe DER's %s holds exactly the droop parameters this row published, but the function itself "+
				"is DISABLED (Ena=%d): a control adopted into a switched-off function commands nothing, so "+
				"this is not execution. %s",
			preface, cv.Axis.Name, cv.EnaRaw, cv.Describe())}
	}
	if !cv.ReadOnly {
		return Finding{Verdict: certify.Warn, Observed: fmt.Sprintf(
			"%sthe DER's %s holds exactly the droop parameters this row published and is enabled, but its "+
				"index-0 control reports ReadOnly=false — on a conformant device the ACTIVE control is "+
				"read-only and the writable ones are the staging indices, so this reading may be of a "+
				"staged control rather than the governing one. %s",
			preface, cv.Axis.Name, cv.Describe())}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"%sthe DER's own %s live control holds exactly the droop parameters this row published (%s, which "+
			"is %s on this device), its adopt handshake COMPLETED and the function is enabled: %s",
		preface, cv.Axis.Name, authored, describeWant711(b.Droop.want711()), cv.Describe())}
}

// droopMismatch compares the five commanded parameters against the DER's own,
// and returns the FIRST disagreement in full — or "" when every one matches
// within the wire's own last digit.
//
// Every parameter is named with both numbers and the tolerance applied, because
// a droop that missed by one register count and one that ignored the command
// entirely must not read the same in a bundle.
//
// FIVE, NOT SIX: model 711's PMin is deliberately not compared. IEEE Std
// 2030.5-2018's FreqDroopType (p.242) has no PMin, so this row commanded no value for it and a
// referee asserting one would be grading its own invention. See
// invariant.DroopReading, which decodes it so a finding can quote it.
func droopMismatch(want, got invariant.DroopReading) string {
	for _, c := range []struct {
		name      string
		want, got float64
		tol       float64
		unit      string
	}{
		{"DbOf (over-frequency dead band)", want.DbOfHz, got.DbOfHz, droopDeadbandToleranceHz, "Hz"},
		{"DbUf (under-frequency dead band)", want.DbUfHz, got.DbUfHz, droopDeadbandToleranceHz, "Hz"},
		{"KOf (over-frequency droop gain)", want.KOf, got.KOf, droopGainTolerance, ""},
		{"KUf (under-frequency droop gain)", want.KUf, got.KUf, droopGainTolerance, ""},
		{"RspTms (open-loop response time)", want.RspTmsS, got.RspTmsS, droopResponseToleranceS, "s"},
	} {
		if math.Abs(c.got-c.want) > c.tol {
			unit := c.unit
			if unit != "" {
				unit = " " + unit
			}
			return fmt.Sprintf("%s is %s%s where this row commanded %s%s (tolerance %s%s, half the last "+
				"digit the wire itself can carry)", c.name, trimNum(c.got), unit, trimNum(c.want), unit,
				trimNum(c.tol), unit)
		}
	}
	return ""
}

// describeWant711 renders the commanded droop in the DEVICE's units, so a
// verdict shows both sides of the translation rather than asking a reader to
// perform it.
func describeWant711(w invariant.DroopReading) string {
	return fmt.Sprintf("DbOf=%s Hz DbUf=%s Hz KOf=%s KUf=%s RspTms=%s s in model 711's own units",
		trimNum(w.DbOfHz), trimNum(w.DbUfHz), trimNum(w.KOf), trimNum(w.KUf), trimNum(w.RspTmsS))
}

// curveContentOutcome is the BREAKPOINT half of a curve row's southbound
// assertion — everything oracleCurve did before a row could also carry a droop.
// Unchanged in substance; extracted so the two halves can be composed.
func curveContentOutcome(b *curveBinding, uv invariant.UnitView, target curveTarget,
	cv invariant.CurveView, published string) Finding {
	if !cv.Present {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"this row published %s northbound and the DER's own register image carries NOTHING for it: "+
				"%s. %s The models the DER does serve are %s",
			published, cv.Describe(), target.Mapping, modelList(uv))}
	}
	if !cv.Adopted {
		// The two generations reach "not adopted" by different routes and a
		// finding that named the wrong one would send a reader to a
		// register that does not exist: on 7xx the adopt HANDSHAKE never
		// COMPLETED; on legacy there is no handshake at all and the fact is
		// that ActCrv does not select the bank this content would be in.
		how := "adopt handshake never COMPLETED, so no curve was taken up"
		if cv.Legacy() {
			how = fmt.Sprintf("ActCrv selects no bank holding this row's content (ActCrv=%d) — on this "+
				"generation there is no adopt handshake, so the SELECTION is the whole of the commit "+
				"and a bank nobody selected commands nothing", cv.ActCrv)
		}
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"this row published %s northbound and the DER's %s %s: %s. %s",
			published, cv.Axis.Name, how, cv.Describe(), target.Mapping)}
	}
	match := invariant.MatchPoints(cv.Points, b.wantPoints(), curvePointTolerance)
	if !match.Matched {
		// "an adopted curve" is the 7xx wording and it would be misleading
		// here: on legacy nothing was adopted, a bank was SELECTED, and the
		// reading is of whatever that bank happens to hold — very often the
		// device's own factory curve, which is exactly the state a DUT that
		// never wrote anything leaves behind.
		held := "reports an adopted curve whose CONTENT is not the one this row published"
		if cv.Legacy() {
			held = fmt.Sprintf("is running the bank ActCrv selects (bank %d), and its CONTENT is not "+
				"the curve this row published", cv.Bank)
		}
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's %s %s: %s. This row published %s. Full register state: %s. The models the DER "+
				"serves are %s",
			cv.Axis.Name, held, match.Reason, published, cv.Describe(), modelList(uv))}
	}
	// The y-axis REFERENCE, checked separately from the points and after
	// them, because the two are different defects with different owners and
	// the second is invisible to the first. Identical breakpoints under the
	// wrong DeptRef are a different command: "-30" against VAR_MAX_PCT and
	// "-30" against W_MAX_PCT are a 2.3x difference on a 60 kW / 26.4 kvar
	// DER and a 30x one on a 2 kvar machine, in the wrong direction, with
	// every point matching. A referee that stopped at the points would
	// certify that.
	if want, ok := b.wantDeptRef(target.Model); ok {
		if !cv.HasDeptRef {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DER's %s holds this row's breakpoints but its curve bank reports no DeptRef at "+
					"all, so what its y values are a percentage OF cannot be read. This row published "+
					"yRefType=%d (%s). Full register state: %s",
				cv.Axis.Name, b.YRefType, derUnitRefName(b.YRefType), cv.Describe())}
		}
		if cv.DeptRef != want {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DER's %s holds exactly the breakpoints this row published, under the WRONG y-axis "+
					"reference: DeptRef=%d (%s), where this row's yRefType=%d (%s) requires DeptRef=%d "+
					"(%s). The points matching proves nothing here — the same numbers against a "+
					"different base are a different command, and a read-back hash cannot see it "+
					"because it carries the document's own yRefType at both ends. Full register "+
					"state: %s",
				cv.Axis.Name, cv.DeptRef, invariant.DeptRefName(target.Model, cv.DeptRef),
				b.YRefType, derUnitRefName(b.YRefType), want, invariant.DeptRefName(target.Model, want),
				cv.Describe())}
		}
	}
	// The curve's own TIMING, checked separately from the points and after them,
	// on the same rule as the y-axis reference: it is a different defect with a
	// different owner and it is invisible to the point comparison. Figure 6
	// prescribes openLoopTms 5 against a default of 10, so a device holding the
	// right SHAPE at its own default speed executed a different command from the
	// one this row published — and until this check existed, nothing in the
	// suite could tell the two apart.
	//
	// Only where the resolved model HAS the register (705/706 do; 712 and every
	// legacy bank do not). Where it does not, the element is disclosed as
	// unmappable on the composed verdict instead — measured or disclosed, never
	// neither.
	if want, ok := b.wantOpenLoopS(); ok && openLoopHome(target.Model) != "" {
		switch {
		case cv.RspTmsS == nil:
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DER's %s holds this row's breakpoints, but its open-loop response register could not "+
					"be read at all, so the timing this row commanded (openLoopTms=%d hundredths of a "+
					"second = %s s) cannot be shown to have landed. Full register state: %s",
				cv.Axis.Name, *b.OpenLoopTms, trimNum(want), cv.Describe())}
		case math.Abs(*cv.RspTmsS-want) > curveOpenLoopToleranceS:
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DER's %s holds exactly the breakpoints this row published, at the WRONG open-loop "+
					"response time: RspTms=%s s where this row published openLoopTms=%d (hundredths of a "+
					"second) = %s s, outside the %s s tolerance. The points matching proves nothing about "+
					"the timing — a device running the right curve at its own default speed is executing "+
					"a different command from the one the procedure prescribes, which is exactly the "+
					"condition Figure 6's 5-against-a-default-of-10 exists to create. Full register "+
					"state: %s",
				cv.Axis.Name, trimNum(*cv.RspTmsS), *b.OpenLoopTms, trimNum(want),
				trimNum(curveOpenLoopToleranceS), cv.Describe())}
		}
	}
	if !cv.Enabled {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's %s holds exactly the breakpoints this row published, but the function itself is "+
				"DISABLED (Ena=%d): a curve adopted into a switched-off function commands nothing, so "+
				"this is not execution of the control. %s",
			cv.Axis.Name, cv.EnaRaw, cv.Describe())}
	}
	// The read-only warning is 7xx-ONLY, and suppressing it on legacy is a
	// correctness rule rather than noise reduction. On 7xx the live curve is
	// index 0 and a conformant device keeps it read-only, so a writable one
	// means the index-0 convention does not hold and this reading may be of
	// a staged curve. On legacy EVERY bank is ordinarily writable — that is
	// how a gateway installs a curve at all, there being no staging slot —
	// so the same warning would fire on every correct legacy device and
	// would be telling a reader something false about it.
	if !cv.ReadOnly && !cv.Legacy() {
		return Finding{Verdict: certify.Warn, Observed: fmt.Sprintf(
			"the DER's %s holds exactly the breakpoints this row published and is enabled, but its "+
				"index-0 curve reports ReadOnly=false — on a conformant device the ACTIVE curve is "+
				"read-only and the writable ones are the staging indices, so this reading may be of a "+
				"staged curve rather than the governing one. %s",
			cv.Axis.Name, cv.Describe())}
	}
	// The PASS says HOW the curve became live, per generation, because that
	// is the fact a reader checks the bundle for: on 7xx the adopt
	// handshake COMPLETED, on legacy ActCrv selects the bank the content is
	// in. Printing "adopt handshake COMPLETED" against a device with no
	// such register would describe evidence that does not exist.
	became := "its adopt handshake COMPLETED and the function is enabled"
	if cv.Legacy() {
		became = fmt.Sprintf("ActCrv selects that bank (bank %d) and ModEna bit 0 is set", cv.Bank)
	}
	// The PASS names the timing when the timing was part of the comparison —
	// the counterpart of the FAIL above. A verdict that said only "holds
	// exactly the breakpoints" over a run that also checked Crv.RspTms would
	// understate what was measured, exactly as one that said it over a run that
	// did NOT check it would overstate.
	// The two qualifications COMPOSE rather than overwrite each other, and that
	// is not cosmetic: BASIC-006 carries both an openLoopTms and (in the vRef
	// fixtures) a reference, and the first version of this wrote `held` twice,
	// so the second assignment silently dropped the vRef sentence — a PASS that
	// said "holds exactly the breakpoints this row published" over a device
	// holding the ADJUSTED ones. That is the same words a PASS would use for a
	// device that ignored vRef entirely, which is precisely the confusion the
	// disclosure exists to prevent.
	held := "holds exactly the breakpoints this row published"
	if b.VRef != nil && *b.VRef != 0 {
		held = fmt.Sprintf("holds exactly the vRef-ADJUSTED breakpoints this row commanded (vRef=%d, so "+
			"IEEE 2030.5-2018 p.250 multiplies each published x by vRef/10 000)", *b.VRef)
	}
	if want, ok := b.wantOpenLoopS(); ok && openLoopHome(target.Model) != "" {
		held += fmt.Sprintf(", at the open-loop response time it published (openLoopTms=%d hundredths of "+
			"a second = %s s, against the device's Crv.RspTms)", *b.OpenLoopTms, trimNum(want))
	}
	// THE EXECUTE-WITHOUT CLAUSE, MEASURED (IEEE Std 2030.5-2018 p.252).
	//
	// A row that authored autonomousVRefEnable=true commanded something this
	// gateway cannot do, and the standard says what conformance looks like then:
	// "If a DER is able to support Volt-Var mode but is unable to support
	// autonomous vRef adjustment, then the DER SHALL execute the curve without
	// autonomous vRef adjustment." That is TWO obligations, and the point table
	// only shows one of them. The other is that nothing armed an adjustment
	// nobody can manage — a gateway that wrote VRefAutoEna=1 to look obliging
	// would leave the DER tracking a reference the gateway never updates, which
	// drifts the whole curve and reads, in the points, exactly like a correct
	// execution.
	//
	// So a PASS is withheld when the device came back ARMED, and the failure
	// says which half of the clause was broken.
	if f, bad := b.autonomousArmingFinding(cv); bad {
		return f
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the DER's own %s live curve %s, %s: %s. %s",
		cv.Axis.Name, held, became, match.Reason, cv.Describe())}
}

// autonomousArmingFinding grades the second half of IEEE Std 2030.5-2018
// p.252's execute-without clause: the device must NOT have armed an autonomous
// vRef adjustment this gateway has no writer for.
//
// It returns bad=false — no opinion — in the two cases where there is genuinely
// nothing to say: a row that did not ask for the adjustment (an unrequested
// register this referee has no expectation about), and a device whose model
// carries no such register at all (everything but 705).
//
// THE ASYMMETRY IS DELIBERATE. enable=true and the device NOT armed is the
// conformant outcome and needs no separate credit beyond appearing in the
// verdict's register dump; enable=true and the device ARMED is a finding. A
// referee that also failed an armed device on a row which never requested it
// would be grading the DER's own configuration, which is not this row's
// business.
func (b *curveBinding) autonomousArmingFinding(cv invariant.CurveView) (Finding, bool) {
	if b.AutonomousVRefEnable == nil || !*b.AutonomousVRefEnable {
		return Finding{}, false
	}
	if cv.VRefAutoEna == nil || !*cv.VRefAutoEna {
		return Finding{}, false
	}
	return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
		"the DER's %s holds this row's curve, but its autonomous volt-reference automation is ARMED "+
			"(Crv.VRefAutoEna=1). This row published autonomousVRefEnable=true, and IEEE Std "+
			"2030.5-2018 p.252 says what a DER that cannot support the adjustment must do about it: "+
			"\"If a DER is able to support Volt-Var mode but is unable to support autonomous vRef "+
			"adjustment, then the DER SHALL execute the curve without autonomous vRef adjustment.\" "+
			"Executing the curve is half of that; not arming an adjustment nothing maintains is the "+
			"other half. A gateway with no writer for VRefAutoTms that sets VRefAutoEna anyway leaves "+
			"the DER tracking a reference nobody updates — the curve drifts, and the point table looks "+
			"exactly like a correct execution while it does. Full register state: %s",
		cv.Axis.Name, cv.Describe())}, true
}

// modelList renders the SunSpec models the DER actually served, so a FAIL about
// a missing model names what IS there.
func modelList(uv invariant.UnitView) string {
	if len(uv.Models) == 0 {
		return "(the chain walk found none)"
	}
	out := make([]string, 0, len(uv.Models))
	for _, m := range uv.Models {
		out = append(out, strconv.FormatUint(uint64(m), 10))
	}
	return strings.Join(out, " ")
}

// ── Curve rows: the live phase ──────────────────────────────────────────────

// curveSetup is a curve row's Setup: read the DER's own curve registers BEFORE
// publishing anything, then publish this row's curve and record the mRID the
// server actually minted for it.
//
// The pre-read is what makes the post-read evidence, for exactly the reason
// oracledSetup's doc gives: "the DER holds this curve after the control was
// published" is a fact about the DER, not about the DUT, until it is paired
// with "and it did not hold it before". Curve rows have no ladder to fall back
// on — a curve is the row's own published content and may not be substituted —
// so a DER that already holds the row's curve produces a decided non-PASS
// (curveOutcome), not a quiet pass on a stale register.
//
// Recording the minted mRID is a correctness fix in its own right. gridsim
// MINTS the mRID for a curve-bound control (sim/gridsim/curve.go: it is
// "DERC-SP-CURVE-<epoch>", not anything the caller chose), and the row's wire
// criterion binds THIS ROW'S OWN mRID (critDERControlCarriesModeFrom,
// IW15-004). Left at the row's synthetic "CERT-BASIC-006", the criterion was
// binding to an mRID that has never been on any wire.
func curveSetup(ctx context.Context, d *Driver, params map[string]string, b *curveBinding, mrid string) error {
	pre := oracleCurve(b)(ctx, d.rc)
	params[oraclePreVerdictParam] = string(pre.Verdict)
	params[oraclePreObservedParam] = findingObserved(pre)
	params[curvePublishedParam] = b.describePublished()
	recordCurveTarget(ctx, d, params, b)
	recordCurveDeliveryBaseline(ctx, d, params, 0)

	return publishCurveControl(ctx, d, params, b, mrid)
}

// detectCurveGeneration reads the DER and reports which SunSpec curve
// generation it serves, or curveGenUnknown when it serves neither (or could not
// be read at all).
//
// Unknown is a real answer and never a default of either generation: a row that
// guessed would choose an apparatus on the strength of nothing, and would then
// certify a refusal or a failure of execution against a bank it never looked at.
func detectCurveGeneration(ctx context.Context, rc *certify.RunCtx) string {
	uv, err := oracleUnitView(ctx, rc, oracleSimName)
	if err != nil {
		return curveGenUnknown
	}
	return curveGenerationOf(uv).String()
}

// ── The delivery fact ───────────────────────────────────────────────────────
//
// A southbound absence has two causes and one verdict text. "The DER holds no
// curve" is what a DUT that REFUSED the axis leaves behind, and it is also
// exactly what a DUT that never received the control leaves behind — one that
// is wedged, or not running, or pointed at a different server. The rows already
// carry criteria that distinguish them (critDERControlCarriesModeFrom, and
// critDERCurveResolvable, which returns Unavailable when the DUT issued no GET),
// and the bundle does record it — in Skip assertions, which are severity 0 and
// appear nowhere in the headline verdict a reader acts on.
//
// So this adds no mechanism. It reads the bench's own data plane once, at
// PostWait, and makes the distinction LEGIBLE in the sentence that carries the
// FAIL.

// curveControlPaths are the resources a DUT must fetch to have received this
// row's control at all.
//
// The CONTROL list, not the curve href: a DUT that refuses the axis at receipt
// has no reason to resolve the curve link (critDERCurveResolvable's own doc
// says so), so counting curve fetches would report every correct refusal as a
// non-delivery. Fetching the control list is what a live DUT does whether it
// goes on to execute the axis or refuse it.
func curveControlPaths(program int) []string {
	return []string{
		fmt.Sprintf("/derp/%d/derc", program),
		fmt.Sprintf("/derp/%d/actderc", program),
	}
}

// countCurveFetches totals this row's control-list GETs in a server view.
func countCurveFetches(v ServerView, program int) int {
	n := 0
	for _, p := range curveControlPaths(program) {
		n += v.GETs(p)
	}
	return n
}

// recordCurveDeliveryBaseline stamps the control-list GET count BEFORE the row
// publishes, so PostWait reports a delta over this row's own window instead of
// whatever the server's bounded request ring happens to hold.
func recordCurveDeliveryBaseline(ctx context.Context, d *Driver, params map[string]string, program int) {
	if d == nil || !d.Available() {
		return
	}
	params[curveDeliveryBaselineParam] = strconv.Itoa(countCurveFetches(d.Snapshot(ctx), program))
}

// recordCurveDelivery states, in one sentence a verdict can quote, whether the
// bench saw the DUT come and fetch this row's control.
//
// A NEGATIVE delta is reported as unknown rather than as zero. gridsim's request
// log is a bounded ring, so a count that went down means the ring evicted the
// baseline, not that fetches un-happened — the same trap ServerView.Since's
// RequestLogGap exists to keep a criterion out of.
func recordCurveDelivery(ctx context.Context, d *Driver, params map[string]string, program int) {
	if d == nil || !d.Available() {
		params[curveDeliveryParam] = "the bench has no admin API on this run, so whether the DUT ever " +
			"fetched this row's control was not established"
		return
	}
	base, haveBase := params[curveDeliveryBaselineParam]
	v := d.Snapshot(ctx)
	now := countCurveFetches(v, program)
	if !haveBase {
		params[curveDeliveryParam] = "no pre-publication fetch baseline was recorded, so this run cannot " +
			"say whether the DUT fetched this row's control during its window"
		return
	}
	before, err := strconv.Atoi(base)
	if err != nil || now < before {
		params[curveDeliveryParam] = fmt.Sprintf("the bench's request log cannot be delta'd across this "+
			"row's window (it holds %d control-list GET(s) now against a %q baseline; the log is a bounded "+
			"ring), so delivery is UNKNOWN and no conclusion is drawn from it", now, base)
		return
	}
	if n := now - before; n > 0 {
		at := "an unrecorded time"
		for _, r := range v.Requests {
			if r.Method != "GET" {
				continue
			}
			for _, p := range curveControlPaths(program) {
				if r.Path == p && !r.At.IsZero() {
					at = r.At.Format(time.RFC3339)
				}
			}
		}
		params[curveDeliveryParam] = fmt.Sprintf("the DUT FETCHED this row's control from the bench during "+
			"its window (%d control-list GET(s), the last at %s on the server's clock), so it was live and "+
			"the control reached it", n, at)
		return
	}
	params[curveDeliveryParam] = "NO fetch of this row's control was observed on the bench's data plane " +
		"during its window, so this reading cannot distinguish a DUT that refused the axis from one that " +
		"never received the control at all (not running, wedged, or pointed elsewhere)"
}

// deliveryClause appends the delivery fact to a verdict that rests on a
// southbound absence.
func deliveryClause(o *Observation) string {
	if o == nil {
		return ""
	}
	if s := o.Params[curveDeliveryParam]; s != "" {
		return " DELIVERY: " + s
	}
	return " DELIVERY: the bench recorded no fetch observation for this row, so whether the DUT received " +
		"the control at all is not established here (the per-criterion record — the mode-on-the-wire and " +
		"curve-resolvable criteria — carries what was seen)."
}

// recordCurveTarget writes which generation and which model this row resolved
// to into the observation, so the citation phase — which has no live context —
// can say what was measured rather than what the row was built with.
//
// A row whose target could not be resolved records the generation as unknown
// rather than defaulting to one: the FAIL that follows names both arms, and a
// default here would put a model number beside a verdict that never read it.
func recordCurveTarget(ctx context.Context, d *Driver, params map[string]string, b *curveBinding) {
	uv, err := oracleUnitView(ctx, d.rc, oracleSimName)
	if err != nil {
		params[curveGenParam] = curveGenUnknown
		return
	}
	gen := curveGenerationOf(uv)
	params[curveGenParam] = gen.String()
	if gen == genAmbiguous {
		// The bundle has to record that a CHOICE WAS DECLINED, not merely which
		// generation was written down. Without this a reader sees a generation
		// field and assumes it was determined; the interesting fact is that the
		// device made it undeterminable.
		params[curveGenAmbiguousParam] = describeGeneration(uv)
	}
	if target, how := b.resolveTarget(uv); how == curveResolved && target.Model != 0 {
		params[curveModelParam] = strconv.FormatUint(uint64(target.Model), 10)
	}
}

// publishCurveControl puts one row's curve on the wire through gridsim's curve
// API and records what the server minted for it.
//
// It is shared by curveSetup and refusalSetup rather than written twice, and
// that sharing is load-bearing rather than tidiness: a REFUSAL row's evidence
// is only about the AXIS if the control it published is identical in kind to
// the one an execution row publishes. Two publishers one edit apart could drift
// into "the DUT refused it because the bench sent it differently", which is the
// one conclusion this row must never support.
func publishCurveControl(ctx context.Context, d *Driver, params map[string]string, b *curveBinding, mrid string) error {
	pub, err := d.PostCurveDetail(ctx, CurveRequest{
		Program: 0, Mode: b.Mode, Points: b.Points, YRefType: b.YRefType,
		XMult: b.XMult, YMult: b.YMult,
		// Everything else the row's Figure prescribes rides the SAME request,
		// because it rides the same control on the wire: openLoopTms on the
		// DERCurve, opModFreqDroop inline on the DERControlBase beside the curve
		// link. Publishing them separately would produce two controls where the
		// procedure prescribes one, and the row would then be unable to say the
		// DUT was ever offered the combination.
		OpenLoopTms: b.OpenLoopTms,
		// The autonomous volt-reference pair rides the same request for the same
		// reason: Figure 6 prescribes them on the SAME DERCurve as its
		// breakpoints and its openLoopTms, and a bench that published them
		// separately would produce two curves where the procedure prescribes
		// one. gridsim refuses them on any mode but volt_var (2018's SHALL NOT),
		// so a row that sets them on the wrong binding fails loudly at publish
		// rather than quietly on the wire.
		AutonomousVRefEnable:       b.AutonomousVRefEnable,
		AutonomousVRefTimeConstant: b.AutonomousVRefTimeConstant,
		VRef:                       vrefRequest(b.VRef),
		FreqDroop:                  droopSettings(b.Droop),
		Description:                "certify " + b.Mode,
		// The oracled window, not curveMode's old 180 s: the PostWait oracle
		// can read the DER anywhere out to wait+settle (see oracleWindow), and
		// a control that released under that read would convert a correct
		// device into a false FAIL at the late edge.
		DurationS: oracleWindow.durationS, StartOffset: oracleWindow.startOffsetS, Activate: true,
	})
	if err != nil {
		return err
	}
	if pub.CurveHref != "" {
		params[curveHrefParam] = pub.CurveHref
	}
	if pub.CurveMRID != "" {
		params[curveResourceParam] = pub.CurveMRID
	}
	if pub.MRID == "" {
		params[curveMRIDNoteParam] = "the server returned no mRID for the curve-bound control it created, so " +
			"this row's wire criteria fall back to the row's own synthetic mRID (" + mrid + ") and will not " +
			"find it: the correlation is unavailable, not satisfied"
		return nil
	}
	params["mrid"] = pub.MRID
	params[curveMRIDNoteParam] = "the curve-bound control's mRID is the SERVER's (" + pub.MRID + "), not this " +
		"row's synthetic " + mrid + ": gridsim mints it for a POST /admin/curve and ignores any mRID the " +
		"request carries, so every wire criterion on this row binds the minted one"
	return nil
}

// curveOutcome collapses everything the live phase recorded about a curve row
// into ONE decided verdict — the same job oracleOutcome does for the scalar
// oracled rows, over the same Observation.Params keys, in the vocabulary of a
// curve.
//
// It is a separate function rather than a parameterisation of oracleOutcome
// because the two say materially different things: a scalar row reports a
// value that moved, a curve row reports a piecewise function that was adopted
// into an enabled register bank. Sharing the prose would make one of the two
// bundles lie about what was measured.
// curveHalves is which of a row's authored halves the DER that ran it could
// actually hold — resolved from the model the LIVE phase recorded, so the
// citation phase reaches the same answer the oracle did.
//
// It exists because the row-level text, the criterion's Claim and its How were
// all written when a curve row had exactly one half, and each of them says
// "curve" unconditionally. On a 7xx bench BASIC-012 now measures its DROOP and
// nothing else, and those three sentences went on describing a point-for-point
// comparison of breakpoints against a model that stores none (M711, NPt=0) —
// a GREEN claim about the half nothing measured, which is the same
// measured-and-disclosed violation the oracle itself was corrected for, one
// composition level up.
type curveHalves struct {
	// Family is the generation the live phase resolved, and Known says whether
	// it was resolved at all. An unknown family describes both arms rather than
	// guessing one, exactly as curveModelLabel already does.
	Family invariant.CurveFamily
	Known  bool
	// Curve / Droop are whether each half had a register home on that family.
	Curve, Droop bool
	// OpenLoop is whether the authored openLoopTms had a home on the resolved
	// MODEL (705/706 declare Crv.RspTms; 712 and the legacy banks do not), so
	// the How can say whether the timing was part of the comparison.
	OpenLoop bool
}

// halvesFrom resolves which halves a run measured, from what Setup recorded.
func (b *curveBinding) halvesFrom(o *Observation) curveHalves {
	h := curveHalves{}
	if o == nil {
		return h
	}
	raw := o.Params[curveModelParam]
	if raw == "" {
		return h
	}
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return h
	}
	model := uint16(n)
	axis, ok := invariant.CurveAxisOf(model)
	if !ok {
		return h
	}
	h.Family, h.Known = axis.Family, true
	switch axis.Family {
	case invariant.FamilyLegacy:
		h.Curve = b.NoRegisterHomeLegacy == ""
	default:
		h.Curve = b.NoRegisterHome7xx == ""
	}
	h.Droop = b.Droop != nil && b.Droop.hasHome(axis.Family)
	h.OpenLoop = b.OpenLoopTms != nil && openLoopHome(model) != ""
	return h
}

// measured names, in a verdict's own voice, the content this run compared.
func (h curveHalves) measured() string {
	switch {
	case !h.Known:
		return "the content this row published"
	case h.Curve && h.Droop:
		return "the curve's breakpoints AND the parametric frequency droop"
	case h.Droop:
		return "the parametric frequency droop"
	case h.Curve && h.OpenLoop:
		return "the curve's breakpoints and its open-loop response time"
	case h.Curve:
		return "the curve's breakpoints"
	}
	return "the content this row published"
}

// compared describes, for the How, the comparison this run actually performed —
// a point table and a parametric control are read with different words, and a
// bundle that printed the wrong one describes evidence that does not exist.
func (h curveHalves) compared() string {
	var parts []string
	if h.Curve || !h.Known {
		parts = append(parts, "the breakpoints of its LIVE (index 0) curve, compared point for point and "+
			"IN ORDER against the breakpoints this row itself published — raw values as published, with "+
			"no axis re-interpretation by this referee, and its DeptRef against the yRefType the row sent")
	}
	if h.OpenLoop {
		parts = append(parts, "its Crv.RspTms open-loop response register against the openLoopTms the "+
			"row published (hundredths of a second into the seconds the model stores)")
	}
	if h.Droop {
		parts = append(parts, "its parametric droop control (DbOf/DbUf dead bands, KOf/KUf gains and "+
			"RspTms response time) compared parameter for parameter against the five FreqDroopType "+
			"values this row published, each translated into the model's own units by this referee from "+
			"the two standards' unit statements")
	}
	if len(parts) == 0 {
		return "whatever content the resolved register bank could hold"
	}
	return strings.Join(parts, "; and ")
}

// unasserted names the authored content this run did NOT compare, or "" when
// there was none — the other half of every sentence measured() appears in.
func (h curveHalves) unasserted(b *curveBinding) string {
	if !h.Known {
		return ""
	}
	var parts []string
	if !h.Curve {
		parts = append(parts, "the frequency-watt breakpoints (this generation stores none)")
	}
	if b.Droop != nil && !h.Droop {
		parts = append(parts, "the opModFreqDroop parameters (this generation stores none)")
	}
	if b.OpenLoopTms != nil && !h.OpenLoop {
		parts = append(parts, "the DERCurve openLoopTms (this model declares no open-loop register)")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " and ")
}

func curveOutcome(b *curveBinding, o *Observation) Finding {
	post := o.Params[oracleObservedParam]
	pre := o.Params[oraclePreObservedParam]
	// WHAT MOVED is the content this run actually compared, not the breakpoints
	// this row published: on a bench that measured only the droop, "the adopted
	// curve MOVED to 4 breakpoint(s) ..." is a green claim about a comparison
	// that never ran. curvePublishedParam still records the published curve —
	// it is what the DUT was OFFERED, and the criteria that report the wire read
	// it — but it is not what this verdict is about.
	halves := b.halvesFrom(o)
	moved := halves.measured()
	if s := halves.unasserted(b); s != "" {
		moved += " (this run asserts NOTHING about " + s + ")"
	}

	if reason := o.Params[oracleUnavailableParam]; reason != "" {
		return Finding{Verdict: certify.Fail, Observed: "the independent southbound oracle could not read the " +
			"DER's own curve registers at all: " + reason + " — and an oracle that cannot read the DER " +
			"cannot certify that a curve control was executed. This row FAILs on that unavailability rather " +
			"than skipping past it: the southbound read is the ONLY check in this suite that can tell a " +
			"gateway which ADOPTED this curve from one which refused the axis and answered the head end anyway"}
	}
	switch verdict := certify.Verdict(o.Params[oracleVerdictParam]); {
	case verdict == "":
		return Finding{Verdict: certify.Fail, Observed: "the live phase left no southbound curve-oracle result " +
			"behind at all — neither a verdict (" + oracleVerdictParam + ") nor a reason it could not reach " +
			"one (" + oracleUnavailableParam + ") is recorded, so the oracle either never ran or its result " +
			"was lost. An unrecorded criterion is not a satisfied one" + deliveryClause(o)}
	case verdict != certify.Pass:
		if post == "" {
			post = "the oracle recorded no observation with its " + string(verdict)
		}
		// The delivery fact rides on every non-PASS, because every non-PASS
		// here rests on what the DER does NOT hold — and an absence is only
		// about the DUT's REFUSAL if the DUT was there to refuse.
		return Finding{Verdict: verdict, Observed: post + deliveryClause(o)}
	}
	switch certify.Verdict(o.Params[oraclePreVerdictParam]) {
	case certify.Fail:
		return Finding{Verdict: certify.Pass, Observed: "the DER did NOT hold this row's content before it " +
			"was published (" + pre + ") and DOES hold it after the DUT's poll cycle (" + post + ") — " +
			moved + " MOVED, so the match is evidence this control was executed, not content an earlier " +
			"run left in the register bank"}
	case certify.Pass:
		return Finding{Verdict: certify.Fail, Observed: "the DER holds " + moved + " (" + post + ") but " +
			"ALREADY held it before this row published anything (" + pre + "). A curve row has no ladder to " +
			"depart onto — its content is the content the row is about — so nothing in this reading " +
			"distinguishes a curve the DUT fetched and adopted from one left over from an earlier run, and " +
			"it is not reported as a PASS"}
	default:
		return Finding{Verdict: certify.Warn, Observed: "the DER holds " + moved + " (" + post + "), but " +
			"the pre-publication baseline was not recovered (" + orText(pre, "no reading was recorded") +
			"), so this run cannot show that the adopted content CHANGED. The content is right; that it was " +
			"THIS row's control that put it there is not established"}
	}
}

// critDEREffectViaCurveOracle is critDEREffectUnobservable's replacement on a
// curve-linked row. Like its scalar sibling it carries NO Skip path: every
// shape the live phase can leave behind comes back from curveOutcome as a
// decided verdict, because a Skip cannot dent a case verdict and so cannot hold
// a release.
func critDEREffectViaCurveOracle(subject string, b *curveBinding, o *Observation) criterion {
	f := curveOutcome(b, o)
	// The CLAIM and the HOW are assembled from the halves this run actually
	// measured, for the reason curveHalves exists: a claim that the DER "holds
	// the curve ... adopted and enabled", over a How describing a point-for-point
	// comparison, is a false description of a run that compared a parametric
	// droop against a model with no point table — and it is false in the
	// direction that overclaims.
	halves := b.halvesFrom(o)
	claim := "the DER's own southbound registers hold " + halves.measured() + " that " + subject +
		" carried, adopted and enabled"
	if s := halves.unasserted(b); s != "" {
		claim += " — this criterion asserts NOTHING about " + s
	}
	return criterion{
		Claim:       claim,
		LoadBearing: true,
		How: fmt.Sprintf("an independent read of the DER's raw SunSpec %s image (internal/invariant, which "+
			"shares only the register-offset tables with the product and none of its CSIP/derbase "+
			"interpretation), taken BEFORE this row published anything and again after the DUT's poll "+
			"cycle: the model's own adopt handshake, its function enable (Ena), and %s. %s. The device "+
			"sims model curve ADOPTION but no curve PHYSICS, so this is a register/adopt-state assertion "+
			"and deliberately not an effect-on-output one",
			curveModelLabel(b, o), halves.compared(), b.describeTargets()),
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}

// curveModelLabel names the model this row actually measured, taken from what
// the live phase resolved (curveModelParam) rather than from the binding.
//
// It falls back to naming BOTH arms, which is the honest answer when nothing
// was resolved: a criterion that printed one generation's model on a run that
// read the other's would describe evidence that does not exist.
func curveModelLabel(b *curveBinding, o *Observation) string {
	if o != nil {
		if raw := o.Params[curveModelParam]; raw != "" {
			if n, err := strconv.ParseUint(raw, 10, 16); err == nil {
				if axis, ok := invariant.CurveAxisOf(uint16(n)); ok {
					return axis.Name
				}
				return fmt.Sprintf("M%d", n)
			}
		}
	}
	return "curve model (" + b.describeTargets() + ")"
}

// critDERCurveResolvable asserts that the DERCurve resource this row's control
// LINKS is one the DUT could actually fetch.
//
// It exists because a curve-linked DERControl carries an href, not content: a
// control whose curve href answers 404 delivers nothing to the DUT however
// perfect the control itself is, and the resulting southbound silence is a
// BENCH gap wearing the DUT's clothes. The 2026-08-14 sim-surface sub-audit
// found exactly that shape on this server (individual DERCurve hrefs 404), so
// the row says which of the two it is instead of leaving a reader to guess.
//
// Unavailable — not FAIL — when the DUT never fetched the href at all: a DUT
// that refuses the axis at receipt has no reason to resolve the curve, and
// grading that as a bench 404 would blame the wrong party. The southbound
// oracle is what carries this row's teeth; this criterion only disambiguates.
func critDERCurveResolvable(href string) criterion {
	return criterion{
		Claim: "the DERCurve resource this row's DERControl links resolves for the DUT",
		How: "a GET on " + href + " in the recovered transcript, and the status line the server answered " +
			"it with",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.Method("GET") {
				if e.Req == nil || e.Resp == nil || !strings.HasSuffix(e.Req.Target, href) {
					continue
				}
				if e.Resp.Status/100 == 2 {
					return citeExchange(t, e, certify.Pass, "GET %s answered %s", e.Req.Target, e.Resp.Line())
				}
				return citeExchange(t, e, certify.Fail,
					"GET %s answered %s — the control this row published links a curve resource the server "+
						"does not serve, so the DUT received a link and no curve content. This is a BENCH "+
						"authoring gap, not a DUT defect, and it makes any southbound silence for this row "+
						"unattributable until it is closed", e.Req.Target, e.Resp.Line())
			}
			return unavailable("the DUT issued no GET for %s in this window, so whether the link resolves was "+
				"not exercised (a DUT that refuses this axis at receipt has no reason to fetch the curve)", href)
		},
	}
}

// critCurvePublishedTheProcedureValues asserts that what went on the wire is
// what the certification procedure prescribes.
//
// It is a CONSTRUCTION claim carried into the bundle, not a measurement: the
// row's own binding is the thing under assertion, pinned against the catalog by
// the construction tests, and this criterion restates that provenance where a
// reader of the report will see it — together with every prescribed element
// this bench could not place on the wire.
//
// It FAILs when a MATERIAL element is missing: one whose prescribed test value
// differs from the procedure's own default, so omitting it means the DUT was
// never offered the condition the row exists to create. That is the same rule
// critModeUnauthorable applies one level up — an untested claim must not roll
// up as a passing one — applied to a row that IS otherwise testable. An
// immaterial gap is named and does not hold the row.
func critCurvePublishedTheProcedureValues(subject string, b *curveBinding) criterion {
	material := b.materialGaps()
	prescribed := orText(b.Prescribed, "this row's binding records no provenance for its published values")
	// What this row places on the wire BEYOND the breakpoints and multipliers,
	// with the register home each has per generation. It is stated here, in the
	// construction claim, because that is where a reader learns what the row
	// sent; whether any of it could then be MEASURED is the southbound
	// criterion's business, and the two are deliberately separate sentences.
	authored := describeAuthored(b.authored())
	return criterion{
		Claim: "the control this row published carries the values the certification procedure prescribes " +
			"for " + subject,
		How: "the row's own curve binding, pinned against the catalog's Figure by a construction test " +
			"(TestCurveRows_PublishTheCatalogPrescribedValues) rather than restated here: " + prescribed,
		// CONSTRUCTION, not Wire. This claim is about what the ROW IS BUILT TO
		// SEND and which prescribed elements it declares this bench cannot
		// author — a fact about this suite's own configuration that no capture
		// could confirm or refute. Carried on Wire it was evaluated only when a
		// session had been recovered, so a captureless run dropped the material-
		// gap HOLD onto a severity-0 Skip: no false PASS, but a hold that
		// disappears when the pcap does is not a hold.
		Construction: func() Finding {
			if len(material) > 0 {
				return Finding{Verdict: certify.Fail, Observed: "this row published " + prescribed +
					", and the following element(s) the procedure prescribes could NOT be placed on the " +
					"wire by this bench: " + describeGaps(material) + ". Each carries a test value that " +
					"DIFFERS from the procedure's own default, so the DUT was never offered the condition " +
					"this row exists to create. This is a BENCH capability gap, not a defect of the device " +
					"under test — and it is reported as a FAIL rather than skipped, because a row that was " +
					"not run to its procedure must not roll up as one that was. Elements the row DOES " +
					"author beyond the breakpoints and multipliers: " + authored + ". Elements omitted " +
					"with no material effect (test value equal to the default, or a transcription " +
					"divergence this bench deliberately does not follow): " + describeGaps(immaterialGaps(b))}
			}
			return Finding{Verdict: certify.Pass, Observed: "this row published " + prescribed +
				". Elements the row authors beyond the breakpoints and multipliers, with the register " +
				"home each has per generation: " + authored + ". Elements omitted with no material " +
				"effect (test value equal to the default, or a transcription divergence this bench " +
				"deliberately does not follow): " + describeGaps(immaterialGaps(b))}
		},
	}
}

// immaterialGaps are the named-but-not-holding gaps.
func immaterialGaps(b *curveBinding) []curveGap {
	var out []curveGap
	for _, g := range b.Gaps {
		if !g.Material {
			out = append(out, g)
		}
	}
	return out
}

// ── Refused-axis rows ───────────────────────────────────────────────────────

// refusalBinding is what a REFUSED-axis row carries: the axis the control names,
// the 704 points a write of that axis would land on, and the control that names
// it.
//
// A refusal row asserts the OPPOSITE of an execution row, and it is a
// materially different check rather than a negated one. An execution oracle
// asks "does the DER hold what was commanded?"; wired to an axis the product
// correctly refuses it would FAIL every conformant DUT (see oracleTargetW's own
// doc, which flagged exactly this and stopped). This asks two questions
// instead:
//
//	the DUT answered the head end that it cannot comply — not Started, not
//	Completed; and
//
//	NOTHING of that axis moved in the DER's own registers during the row's
//	window.
//
// Both must hold. A gateway that answers CannotComply and writes the setpoint
// anyway is lying to the head end; one that writes nothing but reports Started
// is lying about execution. Either alone would let one of the two through.
type refusalBinding struct {
	// Axis is the human label of the refused axis, for the criterion's prose.
	Axis string
	// Points are the 704 command points a write of this axis would land on
	// (internal/invariant's DecodeCommands vocabulary).
	Points []string
	// Commanded describes what the control asked for, in the row's own terms.
	Commanded string
	// Why records why this product refuses the axis, so the row's PASS says
	// what it is a PASS of.
	Why string
	// Publish puts the refused control on the wire under this row's mRID.
	// nil exactly when Curve is set — a curve-axis refusal publishes through
	// publishCurveControl instead, so that it and an EXECUTION curve row put
	// materially identical controls on the wire.
	Publish func(ctx context.Context, d *Driver, mrid string) error

	// Curve, when set, makes this a CURVE-axis refusal instead of a scalar one,
	// and changes what "nothing moved" is measured over: a refused curve axis
	// would land in a curve MODEL (its adopt handshake, its enable and its live
	// breakpoints), not on a 704 setpoint register, so Points above is empty and
	// the fingerprint is the curve bank's whole state.
	//
	// WHY A REFUSAL ROW PUBLISHES A REAL, WELL-FORMED CURVE. The row's claim is
	// that the DUT refuses this AXIS. A malformed or unresolvable curve would
	// also draw a refusal, and the two are indistinguishable from the outside —
	// so the control has to be one that a DUT which supported the axis would
	// have executed. That is why the publisher is shared with the execution
	// rows and why critDERCurveResolvable still runs on this row: it separates
	// "refused the axis" from "could not fetch the curve".
	Curve *curveBinding

	// LegacyCannotComply declares that THIS ROW's own DUT/case configuration
	// runs the LEXA profile's legacy CannotComply wire (the config-gated 0xF0
	// extension), rather than the standard Table 27 answer (252 at receipt).
	//
	// It is NOT about DER generation (contrast the file's other "legacy" —
	// the 12x-vs-7xx register-bank distinction elsewhere in this file, an
	// unrelated meaning of the same word). Every row in the current RC0
	// catalog leaves this false: the product's default and the certification
	// profile are both standard-mode, and a false-by-default posture is what
	// makes a corrected oracle reject the product's former 8-at-receipt
	// defect instead of grandfathering it in. A row that DOES set this is
	// exercising the config-gated fallback wire on purpose, and
	// critRefusalAnswered marks any PASS it earns as non-conformance evidence
	// (SD-02).
	LegacyCannotComply bool
}

// coveredCurveSlots is THE decision about which curves of a bank this row's
// refusal apparatus looks at, and it exists as one function because the last
// defect here was two functions making that decision independently.
//
// The fingerprint spanned slots 0..maxStagingCurvesFingerprinted while the
// contamination read called oracleCurve, which decodes index 0 and only index
// 0. A baseline contaminated in a STAGING slot therefore read as clean: the
// window looked informative, the run failed on movement if the write happened
// again, nobody was ever told to reset the sim, and every subsequent rerun
// passed — the exact "worse contamination, more reliable pass" shape the
// contamination guard was added to close, relocated into the slot that guard
// introduced. Both callers now iterate this, so they cannot disagree again
// without the disagreement being a change to this function.
//
// ok=false is "the bank could not be read at all", which is a different answer
// from "read it and it was empty" and must stay distinguishable: the first
// cannot establish anything, the second establishes a clean baseline.
func coveredCurveSlots(uv invariant.UnitView, model uint16) (views []invariant.CurveView, truncated int, ok bool) {
	live := uv.Curve(oracleSimName, model)
	if !live.Present {
		return nil, 0, false
	}
	views = []invariant.CurveView{live}

	// WHICH SLOTS THE COVERED SET IS DIFFERS BY GENERATION, and it differs
	// because the generations disagree about what a non-live slot IS.
	//
	// On 7xx there is one live curve at index 0 and the rest are STAGING slots
	// a gateway writes before it triggers the handshake, so the covered set is
	// index 0 plus 1..NCrv-1.
	//
	// On legacy there is no staging slot at all: banks are numbered from 1,
	// ActCrv selects one of them, and a gateway installs a curve by writing
	// whichever bank is not live. So EVERY bank 1..NCrv is a place a write can
	// land, which makes all of them the covered set — the live view above
	// already renders the ActCrv bank, so it is skipped in the loop rather than
	// rendered twice under two different headings.
	if live.Legacy() {
		others := live.NCrv
		if live.ActCrv >= 1 && live.ActCrv <= live.NCrv {
			others-- // the live bank is already in views
		}
		shown := 0
		for i := 1; i <= live.NCrv && shown < maxStagingCurvesFingerprinted; i++ {
			if i == live.ActCrv {
				continue
			}
			views = append(views, uv.CurveAt(oracleSimName, model, i))
			shown++
		}
		if n := others - shown; n > 0 {
			truncated = n
		}
		return views, truncated, true
	}

	for i := 1; i < live.NCrv && i <= maxStagingCurvesFingerprinted; i++ {
		views = append(views, uv.CurveAt(oracleSimName, model, i))
	}
	if n := live.NCrv - maxStagingCurvesFingerprinted - 1; n > 0 {
		truncated = n
	}
	return views, truncated, true
}

// fingerprint renders the state a write of this refused axis would have moved,
// so two readings taken minutes apart can be compared for ANY movement.
//
// The two shapes measure different register banks because a refused axis lands
// in different places depending on what kind of axis it is, and measuring the
// wrong bank would report an absence that was never in question.
//
// For a CURVE axis the whole covered bank is rendered, not just the live curve.
// An execution oracle reads index 0 alone on purpose — content in staging is a
// curve the device was OFFERED, not one it adopted, and grading it as executed
// would accept the half-completed write the adopt handshake exists to
// distinguish. But this row asserts that NO WRITE LANDED, and a gateway that
// stages a refused curve and never triggers the handshake has still written to
// an axis it told the head end it could not perform. The handshake registers
// alone do not cover it: they move when the gateway ASKS the device to adopt,
// so they catch stage-then-adopt and are blind to stage-and-stop.
func (b *refusalBinding) fingerprint(uv invariant.UnitView) (string, bool) {
	if b.Curve == nil {
		return refusalFingerprint(uv, b.Points)
	}
	target, how := b.Curve.resolveTarget(uv)
	if how != curveResolved || target.Model == 0 {
		// Either the DER has no bank of this axis at all, or it serves both
		// generations and this suite refuses to choose. Neither is an absence
		// this row can certify: it cannot tell "the DUT refused" from "there
		// was nowhere for a write to land", nor from "we watched the wrong
		// bank". refusalOutcome turns the unavailability into a decided FAIL.
		return "", false
	}
	views, truncated, ok := coveredCurveSlots(uv, target.Model)
	if !ok {
		// Same posture as the scalar shape's empty-points case: a bank we
		// cannot read cannot tell a refused axis from an unreadable one.
		return "", false
	}
	parts := make([]string, 0, len(views)+2)
	for _, cv := range views {
		parts = append(parts, cv.Describe())
	}
	if truncated > 0 {
		parts = append(parts, fmt.Sprintf("(%d further curve slot(s) not fingerprinted)", truncated))
	}
	// THE DROOP BANK TOO, whenever this row's control carries an
	// opModFreqDroop — because publishCurveControl sends it unconditionally,
	// and a refusal row's whole claim is that NOTHING of what it published
	// landed.
	//
	// Without this the fingerprint watches the curve bank alone: a DUT that
	// answered cannot-comply and then wrote the droop into model 711 would move
	// no register this row was looking at, and the row would certify a clean
	// refusal over a real write. No catalog row is in that shape today — the
	// refusal rows author no droop — which is exactly why it had to be closed
	// before one is: the failure would be silent and the row would look green.
	if b.Curve.Droop != nil {
		droop := b.Curve.Droop.resolve(target.Family)
		if droop.NoRegisterHome == "" && droop.Model != 0 {
			for _, cv := range coveredDroopSlots(uv, droop.Model) {
				parts = append(parts, cv.Describe())
			}
		}
	}
	return strings.Join(parts, " | "), true
}

// coveredDroopSlots are the control slots of a parametric droop model this
// row's refusal apparatus watches: the LIVE control and the staging slots a
// gateway would write before triggering the adopt handshake, on the same
// bounded rule coveredCurveSlots follows for a point table.
//
// Staging is covered for the identical reason: a gateway that writes a refused
// droop into a staging control and never asks for adoption has still written to
// an axis it told the head end it could not perform, and the handshake
// registers alone are blind to it.
func coveredDroopSlots(uv invariant.UnitView, model uint16) []invariant.CurveView {
	live := uv.Curve(oracleSimName, model)
	if !live.Present {
		// Rendered anyway: "the DER does not serve M711" is itself part of the
		// fingerprint, and a window in which the model appeared would then MOVE.
		return []invariant.CurveView{live}
	}
	out := []invariant.CurveView{live}
	for i := 1; i < live.NCrv && i <= maxStagingCurvesFingerprinted; i++ {
		out = append(out, uv.CurveAt(oracleSimName, model, i))
	}
	return out
}

// curveBaselineContamination reports which of the covered slots ALREADY hold
// this row's published breakpoints, over exactly the slots the fingerprint
// renders.
//
// The criterion is the row's own CONTENT, and deliberately not oracleCurve's
// execution question (adopted AND enabled AND the right DeptRef). What makes a
// refusal window uninformative is that a write of the refused content would not
// move the fingerprint, and that is true of a slot already holding those
// breakpoints whether or not the function was ever adopted or switched on — a
// gateway that writes points and stops moves nothing at all. Requiring the
// adopt/enable state as well would have let the points-only case through, which
// is precisely the staging shape.
//
// It does NOT compare DeptRef: a slot holding the right points under a
// different reference would still MOVE when the reference was written, so that
// window is informative and reporting it as contaminated would be a false
// accusation against a clean bench.
func curveBaselineContamination(uv invariant.UnitView, b *curveBinding) (where []string, ok bool) {
	target, how := b.resolveTarget(uv)
	if how != curveResolved || target.Model == 0 {
		return nil, false
	}
	views, _, ok := coveredCurveSlots(uv, target.Model)
	if !ok {
		return nil, false
	}
	want := b.wantPoints()
	for _, cv := range views {
		if len(cv.Points) == 0 {
			continue
		}
		if invariant.MatchPoints(cv.Points, want, curvePointTolerance).Matched {
			where = append(where, slotLabel(cv))
		}
	}
	return where, true
}

// slotLabel names one curve of a bank for a finding.
func slotLabel(cv invariant.CurveView) string {
	if cv.Legacy() {
		// "staging curve" is a 7xx word with no legacy referent, and using it
		// here would tell a reader the bank was a scratch slot when on this
		// generation it is an ordinary bank one ActCrv write away from being
		// live.
		if cv.Index == 0 {
			return fmt.Sprintf("the LIVE bank (bank %d, selected by ActCrv=%d, %s)",
				cv.Bank, cv.ActCrv, enabledLabel(cv.Enabled))
		}
		return fmt.Sprintf("bank %d (not selected; ActCrv=%d)", cv.Index, cv.ActCrv)
	}
	if cv.Index == 0 {
		return fmt.Sprintf("the LIVE curve (index 0, %s, %s)",
			enabledLabel(cv.Enabled), adoptLabel(cv.Adopted))
	}
	return fmt.Sprintf("STAGING curve %d", cv.Index)
}

func adoptLabel(done bool) string {
	if done {
		return "adopt COMPLETED"
	}
	return "adopt not COMPLETED"
}

// maxStagingCurvesFingerprinted bounds how much of a curve bank the refusal
// apparatus covers. A device declares its own NCrv and nothing stops it
// declaring a large one; the fingerprint is a STRING that lands in a bundle, so
// it needs a bound that does not depend on the device's honesty. Devices this
// bench grades declare NCrv=2 (one live, one staging), so the practical cost of
// the bound is nil — and when it does bite, the fingerprint says so rather than
// silently truncating.
//
// Its VALUE is pinned by TestCoveredCurveSlots_BoundIsRealAndIsFour: a bound
// nothing checks is a bound that can be widened to 1000000 in a refactor, at
// which point a hostile or broken device's NCrv decides how much of a bundle
// this row writes.
const maxStagingCurvesFingerprinted = 4

// describeAxisRegisters names what the fingerprint above covers, for the
// criterion's How and for an unavailability message.
func (b *refusalBinding) describeAxisRegisters(o *Observation) string {
	if b.Curve == nil {
		// The 704 points this row named, AND the legacy scalar surface the
		// fingerprint reads unconditionally. Naming only the first would
		// describe a 7xx bench and misdescribe a legacy one, on which the 704
		// points do not exist and model 123 is the whole of what was watched.
		return strings.Join(b.Points, ", ") + " on a 7xx DER (model 704), and model 123's whole " +
			"immediate-controls block — the connect register and the active-power ceiling with its " +
			"enable and scale factor — on a legacy one, whichever the DER under test serves"
	}
	return curveModelLabel(b.Curve, o) + " (the selection/adopt state, the function enable, DeptRef, and " +
		"the breakpoints of EVERY covered curve slot of the bank — on 7xx the live curve and its writable " +
		"staging slots, on legacy every bank 1..NCrv, since that generation has no staging slot and a " +
		"write can land in any of them)"
}

// refusalFingerprint renders the exact state of the axis's registers — raw
// value, enable, and the mode enum that selects between them — so two readings
// taken minutes apart can be compared for ANY movement, not only for movement
// towards the commanded value.
//
// Comparing fingerprints rather than "does it hold the commanded number" is
// deliberate. A gateway that half-executes a refused axis — writes the enable,
// or writes a value the arbitration then clamped, or flips WSetMod on its way
// to giving up — has written to an axis it told the head end it could not
// perform, and every one of those is a landing this row must catch. Equality of
// the whole fingerprint is the only statement that covers them.
//
// ── IT READS BOTH GENERATIONS (the parked BASIC-014 widening) ───────────────
//
// It used to read model 704 and nothing else, through invariant.UnitView's
// Commands. On a 7xx bench that is the whole scalar control surface. On a
// LEGACY bench there is no 704 at all — the generation puts its scalar controls
// in model 123 (one active-power ceiling, one connect register) — so the
// fingerprint came back with no parts, this function returned ok=false, and
// oracleRefusal reported the axis Unavailable. BASIC-014 therefore FAILED on
// every legacy DER for want of a register to look at, which is a bench gap
// wearing a verdict's clothes: the row was reporting on itself, not on the DUT.
//
// So a reading now covers the model-123 surface too, through
// invariant.LegacyControls (internal/invariant/legacyctl.go), whenever the
// device serves it. A device serving neither model is still ok=false, which is
// the honest answer: there is nowhere for a scalar write to land and therefore
// nothing to certify an absence over.
//
// TWO CAUTIONS RIDE WITH THE LEGACY HALF, and both are stated on every reading
// it produces rather than only here.
//
// The first is that its point names are MODEL-QUALIFIED ("M123.WMaxLimPct").
// Model 704 has a WMaxLimPct too, meaning a different thing against a different
// enable and a different scale factor, and this suite's own oracleMaxLimW
// selects it by bare name — an unqualified legacy point would have been picked
// up by that oracle and judged under 704 semantics.
//
// The second is [invariant.DescribeM123Divergence]: the register map SunSpec
// publishes for model 123 and the hand-written offsets lexa-proto's writer uses
// disagree at every point. This referee reads the PUBLISHED map, so on a legacy
// DER it is watching different registers than the writer under test believes it
// is moving. That does not weaken the fingerprint — LegacyControls renders the
// WHOLE model-123 block, so a write that lands at any offset moves it — and it
// is disclosed on the reading so a bundle cannot be read as agreeing with a
// transcription this referee does not share.
func refusalFingerprint(uv invariant.UnitView, points []string) (string, bool) {
	want := map[string]bool{}
	for _, p := range points {
		want[p] = true
	}
	var parts []string
	for _, c := range uv.Commands(oracleSimName) {
		if !want[c.Point] {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s %s(%s=%d)", c.Point, c.Raw,
			enabledLabel(c.Enabled), orText(c.ModePoint, "mode"), c.ModeVal))
	}
	if lc := uv.LegacyCommands(oracleSimName); lc.Present {
		if fp, ok := lc.Fingerprint(); ok {
			parts = append(parts, "M123 (legacy scalar control surface): "+fp)
			if d := invariant.DescribeM123Divergence(); d != "" {
				parts = append(parts, "TRANSCRIPTION: "+d)
			}
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, ", "), true
}

func enabledLabel(on bool) string {
	if on {
		return "ENABLED"
	}
	return "disabled"
}

// oracleRefusal builds the southbound half of a refusal row: it re-reads the
// axis's registers and reports whether ANYTHING there has moved since the
// baseline the row recorded before it published.
//
// A Fail here means a write landed on an axis the DUT was supposed to refuse.
// Everything else is Pass — with one exception the caller decides, not this
// closure: a baseline that ALREADY held the commanded content makes the whole
// window uninformative, which refusalOutcome reports rather than passing.
//
// THAT EXCEPTION WAS A CLAIM THIS FILE MADE AND DID NOT KEEP until 2026-08-15.
// refusalOutcome had no such guard, so a DUT that had landed the refused
// content BEFORE the row's window — a regression left by an earlier run, or a
// leak from a preceding row — fingerprinted as "nothing moved" and certified as
// a clean refusal on every rerun. The failure mode is the nastier direction: the
// worse the contamination, the more reliably the row passed.
//
// It is now kept for the CURVE shape, where "already holds this row's content"
// is precisely computable: curveBaselineContamination asks whether ANY slot the
// fingerprint covers already holds this row's breakpoints. (It asked oracleCurve
// at first, which answers the EXECUTION question about index 0 alone — so a
// baseline contaminated in a staging slot read as clean, and the guard had the
// hole it was written to close. coveredCurveSlots is now the single decision
// about which slots both halves look at.) It is NOT kept for the scalar shape, and that is a
// bounded gap rather than an oversight: refusalBinding.Commanded is prose, not a
// value, so there is nothing to compare a baseline against, and the obvious
// proxy — "the axis is already ENABLED" — would fail BASIC-014 in every
// campaign, because BASIC-013 runs immediately before it, commands opModFixedW,
// and legitimately leaves WSet/WSetPct enabled on the very points BASIC-014
// fingerprints (oracleFixedW reads the same two). Closing it needs a commanded
// VALUE on the scalar binding, which is oracleBinding's shape and a separate
// change.
func oracleRefusal(b *refusalBinding, baseline string, fence refusalLedgerFence) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		got, ok := b.fingerprint(uv)
		if !ok {
			return unavailable("the DER's own register image carries nothing a write of %s would land on "+
				"(%s), so this row cannot tell a refused axis from an unreadable one",
				b.Axis, b.describeAxisRegisters(nil))
		}
		// LEDGER ATTRIBUTION (preferred): attribute a WSet-axis write to THIS
		// control by the publish-time seq fence, so a PRIOR control's release
		// (BASIC-013's WSet=4800 dropping its enable bit during this window) is
		// not counted as BASIC-014's own write — the misattribution the bare
		// fingerprint diff below made (HARNESS-TEARDOWN-CANCEL-ONLY-LEAVES-
		// APPLIED-STATE). It declines (decided=false) when the sim has no wire
		// tap, the axis has no mapped register span, or the ledger cannot be
		// read now; the fingerprint diff is the fallback, never a false PASS.
		if f, decided := refusalLedgerAttribution(ctx, rc, b, fence, uv, baseline, got); decided {
			return f
		}
		if baseline == "" {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"no pre-publication baseline of %s was recorded, so this reading (%s) cannot show that "+
					"nothing moved — an unestablished starting state cannot certify an absence", b.Axis, got)}
		}
		if got != baseline {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"a southbound write of %s LANDED on the DER during this row's window, on an axis the DUT is "+
					"supposed to have refused: the registers read %s before this row published its control "+
					"and %s after the DUT's poll cycle. This row commanded %s. A gateway that answers the "+
					"head end that it cannot comply and then writes the axis anyway has told the head end "+
					"one thing and the device another. (No ledger fence was available to attribute the write "+
					"to this control by seq, so this rests on the register diff alone.)",
				b.Axis, baseline, got, b.Commanded)}
		}
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"nothing of %s moved in the DER's own registers across this row's window: they read %s both "+
				"before this row published its control and after the DUT's poll cycle, so the refusal left "+
				"no southbound trace. %s", b.Axis, got, b.Why)}
	}
}

// refusalOutcome collapses a refusal row's live-phase record into one decided
// verdict, the way oracleOutcome and curveOutcome do for the execution rows.
//
// It takes the BINDING as well as the observation, which curveOutcome does not
// need to, because whether the baseline-contamination guard applies is a
// property of the ROW (a curve refusal can compute it; a scalar one cannot —
// see oracleRefusal) and not of whether some param happens to be present. An
// absent param must not be the thing that decides whether a check runs.
func refusalOutcome(b *refusalBinding, o *Observation) Finding {
	if reason := o.Params[oracleUnavailableParam]; reason != "" {
		return Finding{Verdict: certify.Fail, Observed: "the independent southbound oracle could not read the " +
			"DER at all: " + reason + " — and an oracle that cannot read the DER cannot certify that a " +
			"refused axis was left untouched. This row FAILs on that unavailability rather than skipping " +
			"past it: an unobserved absence is not an observed one"}
	}
	switch verdict := certify.Verdict(o.Params[oracleVerdictParam]); {
	case verdict == "":
		return Finding{Verdict: certify.Fail, Observed: "the live phase left no southbound refusal-oracle " +
			"result behind at all — neither a verdict (" + oracleVerdictParam + ") nor a reason it could " +
			"not reach one (" + oracleUnavailableParam + ") is recorded. An unrecorded criterion is not a " +
			"satisfied one"}
	case verdict != certify.Pass:
		return Finding{Verdict: verdict,
			Observed: orText(o.Params[oracleObservedParam], "the oracle recorded no observation with its "+
				string(verdict))}
	}
	// Nothing MOVED. That is only evidence of a refusal if the thing this row
	// refuses was not already there when the row started — see oracleRefusal's
	// doc for why this guard exists and why it is curve-only.
	if b != nil && b.Curve != nil {
		post := o.Params[oracleObservedParam]
		pre := orText(o.Params[oraclePreObservedParam], "no pre-publication reading was recorded")
		switch certify.Verdict(o.Params[oraclePreVerdictParam]) {
		case certify.Pass:
			return Finding{Verdict: certify.Fail, Observed: "THE BASELINE WAS CONTAMINATED: the DER " +
				"ALREADY held this row's own " + b.Curve.Mode + " content BEFORE " +
				"this row published anything (" + pre + "). Nothing moved during the window (" + post +
				") — and nothing could have, because the refused content was already there. This row " +
				"cannot prove a refusal against a device that is executing the very thing it is supposed " +
				"to have refused: an unchanged reading distinguishes a DUT that refused the control from " +
				"one that landed it on an earlier run only if the starting state was clean. REMEDY: clear " +
				"the DER's curve bank before the row runs — DELETE /admin/curve (Driver.ClearCurves) " +
				"clears only the CSIP-side control and curve, not the device's registers, so this needs a " +
				"fresh sim (the modsim /control reset resumes the animation and does not reset the " +
				"register image) or a bench lever that resets the " + curveModelLabel(b.Curve, o) +
				" bank. Until then this is reported as a FAIL " +
				"rather than a PASS, because an uninformative window is not an observed absence"}
		case certify.Fail:
			// The clean case: the DER did NOT hold this row's content before the
			// window, and still does not. The absence means something.
		default:
			// Everything that is neither "clean" nor "contaminated". Unset is
			// the ordinary case (the bank could not be read); any OTHER verdict
			// is a shape recordCurveContamination does not produce, so it is
			// reported as itself rather than described as a missing reading —
			// mislabelling a present-but-unexpected verdict as "not recovered"
			// sends whoever reads the bundle looking for the wrong fault.
			why := "was not recovered"
			if v := o.Params[oraclePreVerdictParam]; v != "" {
				why = "came back " + v + ", which is not a state this row's baseline check produces"
			}
			return Finding{Verdict: certify.Fail, Observed: "the pre-publication reading of the " +
				b.Curve.Mode + " bank " + why + " (" + pre + "), so this run cannot show that the " +
				"baseline was clean. Nothing moved during the window (" + post + "), but an unchanged " +
				"reading is only evidence of a refusal against a starting state that was established — " +
				"an unestablished one cannot certify an absence, the same posture this row already takes " +
				"for a missing fingerprint baseline"}
		}
	}
	// A refusal PASS is an ABSENCE, so the delivery fact is not decoration here
	// — it is the difference between "the DUT was offered this control and left
	// the axis alone" and "nothing ever reached the DUT". The verdict is not
	// downgraded on it (the per-criterion record, critDERControlCarriesModeFrom
	// and critRefusalAnswered, is what grades delivery), but a PASS that did not
	// state it would be a PASS a reader cannot check.
	return Finding{Verdict: certify.Pass, Observed: o.Params[oracleObservedParam] + deliveryClause(o)}
}

// critRefusedAxisNoSouthboundTrace is the refusal row's southbound criterion:
// the DER shows no trace of the axis the DUT refused.
func critRefusedAxisNoSouthboundTrace(b *refusalBinding, o *Observation) criterion {
	f := refusalOutcome(b, o)
	return criterion{
		Claim:       "no southbound write of " + b.Axis + " reached the DER while this row's refused control was live",
		LoadBearing: true,
		How: "an independent read of the DER's own raw SunSpec image (internal/invariant, which shares only " +
			"the register-offset tables with the product and none of its CSIP/derbase interpretation), " +
			"taken BEFORE this row published its control and again after the DUT's poll cycle: " +
			b.describeAxisRegisters(o) + " is fingerprinted and compared for ANY movement, not only for " +
			"movement towards the commanded value",
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}

// refusalAcceptedStatus reports whether status is an honest "cannot comply"
// answer for a row whose control the DUT REFUSES OUTRIGHT — the control names
// an axis the product does not/cannot execute at all — under this row's own
// legacy-wire declaration.
//
// IEEE 2030.5-2018 Table 27, p.74-76 DOES define a receipt-time rejection for
// exactly this shape: 252 ("rejected — parameter not applicable to this DER"),
// sent at first receipt, before any southbound write — this is the RC0
// decision table's case 2 (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md,
// lexa-gw), and it corrects this file's own former claim that "Table 27 has no
// cannot-comply status": it has one, at 252, and this product's prior 8/0xF0
// answer was reaching for a status Table 27 reserves for a DIFFERENT, later
// event (an ADMITTED control that only PARTIALLY executes — see
// refusalForbiddenStatuses below).
//
// The LEXA profile's 0xF0 (manufacturer-range squatting on Table 27's
// RESERVED range — 15-251 and 255; the standard defines no manufacturer range
// at all) remains an acceptable wire ONLY when this row's own DUT/case
// configuration explicitly declares legacy mode (refusalBinding.
// LegacyCannotComply). It is a config-gated fallback, never a conformance
// behavior and never in PICS — a row that passes on this path is stamped
// non-conformance-evidence in its Observed text (see legacyDisclaimer below)
// so a bundle reader cannot mistake it for the standard answer.
func refusalAcceptedStatus(status uint64, legacy bool) bool {
	if status == 252 {
		return true
	}
	return legacy && status == 0xF0
}

// legacyDisclaimer is appended to a refusal Finding's Observed text whenever
// the accepted status was the config-gated 0xF0 wire, so a bundle reader
// cannot read this row's PASS as conformance evidence (SD-02).
const legacyDisclaimer = " — LEGACY WIRE MODE (0xF0, config-gated): this row's DUT/case declares legacy " +
	"CannotComply and this PASS is NOT conformance evidence; the standard answer is 252"

// refusalForbiddenStatuses are the answers that make a refusal dishonest for a
// row whose control is refused OUTRIGHT — an axis the product never admits at
// all, so nothing about the event's lifecycle is this row's to report.
//
//   - 2/3 (Started/Completed) are EXECUTION signals for a control nothing ever
//     executed — the LXR-002 defect verbatim.
//   - 8/10 (PartialOptOut/NoParticipation) are Table 27's OWN EffectiveEndTime-
//     only statuses for an event that WAS admitted and PARTIALLY honoured.
//     This row's control was never admitted, so nothing was ever partially
//     honoured — posting either here is both the wrong send-time (receipt, not
//     EffectiveEndTime) and the wrong shape (this is a rejection, not a
//     partial), which is exactly the defective former product behavior SD-02
//     corrects.
//   - 4/5 (OptOut/OptIn) are lifecycle acknowledgements of a preference-driven
//     curtailment on a control the DUT DID adopt into its control loop. A
//     structurally unsupported control was never adopted, so it cannot have
//     opted in or out of anything.
//
// None of the five is an honest answer to "I cannot perform this control at
// all".
var refusalForbiddenStatuses = map[uint64]string{
	2: "Event started — an EXECUTION signal for an axis this product does not execute",
	3: "Event completed — an EXECUTION signal for an axis this product does not execute",
	8: "PartialOptOut — Table 27's EffectiveEndTime-only partial for an ADMITTED, partially-honoured " +
		"event; this row's control was never admitted, so nothing was ever partially honoured (SD-02: the " +
		"defective former onset-8 shape)",
	10: "NoParticipation — Table 27's EffectiveEndTime-only partial for an ADMITTED event observed " +
		"breaching throughout; this row's control was never admitted at all",
	4: "OptOut — a lifecycle acknowledgement of an ADOPTED control's preference-driven curtailment; this " +
		"row's control was refused outright, never adopted",
	5: "OptIn — a lifecycle acknowledgement this row's outright-refused control never earns",
}

// critRefusalAnswered asserts the DUT told the head end it could not comply
// with this row's control — and did NOT tell it the event started or completed
// (or any of Table 27's other lifecycle/partial statuses this outright-refused
// control never earns).
//
// legacy threads refusalBinding.LegacyCannotComply: only when the row's own
// DUT/case configuration declares legacy wire mode is the LEXA profile's 0xF0
// accepted, and then only as non-conformance evidence (legacyDisclaimer).
//
// The forbidden half is the load-bearing half. A DUT that silently drops an
// axis it cannot execute and reports Started is the LXR-002 defect verbatim:
// the head end receives an execution signal for a control nothing ever
// executed. That is the shape this criterion has to be able to catch, and a
// criterion that only looked for the refusal status would grade a DUT that sent
// BOTH as compliant.
func critRefusalAnswered(mridKey string, legacy bool) criterion {
	accepted := "252 (rejected — parameter not applicable to this DER), sent at receipt before any write"
	if legacy {
		accepted += ", or — this row's case declares legacy wire mode — the LEXA profile's 0xF0 " +
			"(non-conformance evidence only)"
	}
	// #17/F2: 252/253/254 share Table27RequiredBit's bit 0x02
	// (RespReqSpecificResponse) — same as 253/254 — so 252 is representative
	// for the gate; 0xF0 (legacy) has no Table 27 entry (Table27RequiredBit
	// returns 0) and is never gated, matching the gateway's own "extension
	// statuses keep the old behaviour" fallback. Only the POSITIVE "must
	// report a rejection" half is gated: the forbidden-status half (2, 3, 4,
	// 5, 8, 10 must NOT appear) is a claim about what the DUT volunteered,
	// which Table 27 does not excuse just because nobody asked for it.
	var notRequested string
	return criterion{
		Claim: "the DUT answered this row's control with a cannot-comply Response, and never reported it " +
			"started, completed, or any other Table 27 lifecycle/partial status",
		How: "the sep+xml body of every Response-family POST in the session whose <subject> is this row's " +
			"own mRID, and the <status> each carried: a rejection status (" + accepted + ") must be present " +
			"and none of 2, 3, 4, 5, 8, or 10 may be (the rejection requirement gated per #17/F2 against " +
			"the control's own responseRequired)",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			var seen []string
			var refused, forbidden *Message
			var refusedStatus, forbiddenStatus uint64
			var forbiddenWhat string
			for _, e := range t.Method("POST") {
				if e.Req == nil || len(e.Req.Body) == 0 {
					continue
				}
				doc, err := e.Req.SEP()
				if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
					continue
				}
				subj, _ := doc.TextOf("subject")
				if subj != mridKey {
					continue
				}
				st, _ := doc.UintOf("status")
				seen = append(seen, fmt.Sprintf("status=%d", st))
				if what, bad := refusalForbiddenStatuses[st]; bad && forbidden == nil {
					forbidden, forbiddenStatus, forbiddenWhat = e.Req, st, what
				}
				if refusalAcceptedStatus(st, legacy) && refused == nil {
					refused, refusedStatus = e.Req, st
				}
			}
			switch {
			case forbidden != nil:
				return citeMessage(t, forbidden, certify.Fail,
					"the DUT reported <status>%d</status> for this row's control (mRID=%s), which this row's "+
						"outright refusal must never carry: %s. Every Response this row's control drew: %s",
					forbiddenStatus, mridKey, forbiddenWhat, strings.Join(seen, ", "))
			case refused != nil:
				obs := fmt.Sprintf("the DUT answered this row's control (mRID=%s) with a cannot-comply "+
					"Response (status=%d) and reported neither started, completed, nor any other Table 27 "+
					"lifecycle/partial status; the Responses it sent were: %s",
					mridKey, refusedStatus, strings.Join(seen, ", "))
				if refusedStatus == 0xF0 {
					obs += legacyDisclaimer
				}
				return citeMessage(t, refused, certify.Pass, "%s", obs)
			case len(seen) > 0:
				if reason := respReqNotRequested(t, 252, mridKey); reason != "" {
					notRequested = reason
					return Finding{Unavailable: fmt.Sprintf("the DUT POSTed %d Response(s) for this row's "+
						"control (mRID=%s) and none of them says it cannot comply, but %s — a spec-compliant "+
						"DUT is not obliged to report the rejection status on this claim", len(seen), mridKey, reason)}
				}
				return found(certify.Fail, allFrames(t.Method("POST")),
					"the DUT POSTed %d Response(s) for this row's control (mRID=%s) and none of them says it "+
						"cannot comply: %s. A structurally unsupported control must be rejected at receipt "+
						"(status 252), not left on an acknowledgement",
					len(seen), mridKey, strings.Join(seen, ", "))
			default:
				return unavailable("the recovered transcript holds no Response POST for subject %s", mridKey)
			}
		},
		Server: func(v *ServerView) Finding {
			// #17/F2: honour a not-requested ruling Wire already made — tier 3
			// has no visibility into a control's own wire responseRequired, so
			// left to re-decide on bare Response presence it could turn the
			// exact false-FAIL this gate exists to prevent right back into one.
			if notRequested != "" {
				return Finding{Unavailable: notRequested}
			}
			got := v.ResponsesFor(mridKey)
			if len(got) == 0 {
				if !v.SessionEstablished() {
					return noSessionUnavailable()
				}
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"gridsim received no Response POST at all for this row's control (mRID=%s), so the head "+
						"end was never told the DUT could not comply", mridKey)}
			}
			var statuses []string
			var refused bool
			var refusedStatus uint8
			for _, r := range got {
				statuses = append(statuses, fmt.Sprintf("status=%d", r.Status))
				if what, bad := refusalForbiddenStatuses[uint64(r.Status)]; bad {
					return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
						"gridsim received a Response reporting %q for this row's control (mRID=%s), which "+
							"this row's outright refusal must never carry. All: %s",
						what, mridKey, strings.Join(statuses, ", "))}
				}
				if refusalAcceptedStatus(uint64(r.Status), legacy) {
					refused, refusedStatus = true, r.Status
				}
			}
			if refused {
				obs := fmt.Sprintf("gridsim received a cannot-comply Response (status=%d) for this row's "+
					"control (mRID=%s) and no started/completed/lifecycle status: %s",
					refusedStatus, mridKey, strings.Join(statuses, ", "))
				if refusedStatus == 0xF0 {
					obs += legacyDisclaimer
				}
				return Finding{Verdict: certify.Pass, Observed: obs}
			}
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"gridsim received %d Response(s) for this row's control (mRID=%s), none saying it cannot "+
					"comply: %s. The standard answer to a structurally unsupported control is 252 at receipt",
				len(got), mridKey, strings.Join(statuses, ", "))}
		},
	}
}

// refusalSetup is a refusal row's Setup: fingerprint the axis BEFORE anything
// is published, so the post-read has a baseline to be an absence against, then
// publish the control the DUT is expected to refuse.
func refusalSetup(ctx context.Context, d *Driver, params map[string]string, b *refusalBinding, mrid string) error {
	params[refusalAxisParam] = b.Axis
	if b.Curve != nil {
		params[curvePublishedParam] = b.Curve.describePublished()
		recordCurveTarget(ctx, d, params, b.Curve)
	}
	recordCurveDeliveryBaseline(ctx, d, params, 0)
	// ONE read of the DER answers both baseline questions, which is deliberate:
	// they must describe the same instant, and the fingerprint and the
	// contamination read must not be able to disagree about what the bank held.
	if uv, err := oracleUnitView(ctx, d.rc, oracleSimName); err == nil {
		if fp, ok := b.fingerprint(uv); ok {
			params[refusalBaselineParam] = fp
			params[oraclePreObservedParam] = fp
		} else {
			params[oraclePreObservedParam] = "the DER's own register image carries nothing of " +
				b.describeAxisRegisters(nil)
		}
		if b.Curve != nil {
			recordCurveContamination(params, uv, b.Curve)
		}
	} else {
		params[oraclePreObservedParam] = "the baseline reading could not be taken: " + err.Error()
		// oraclePreVerdictParam is deliberately left UNSET on this path: with no
		// reading there is no clean baseline to certify against, and
		// refusalOutcome turns the unset state into a FAIL rather than a pass.
	}
	if b.Curve != nil {
		return publishCurveControl(ctx, d, params, b.Curve, mrid)
	}
	// SCALAR refusal only: capture the DER ledger's high-water seq at the instant
	// BEFORE publishing, so a write the DUT issues in RESPONSE to this control is
	// stamped seq > fence and a prior control's release (already recorded at a
	// lower seq) is excluded. This is what lets oracleRefusal attribute a WSet
	// write to THIS control rather than to BASIC-013's release
	// (HARNESS-TEARDOWN-CANCEL-ONLY-LEAVES-APPLIED-STATE). Best-effort: a sim
	// with no wire tap records no fence and the oracle falls back to the
	// fingerprint diff. See refusalledger.go.
	captureRefusalLedgerFence(ctx, d, params, b)
	return b.Publish(ctx, d, mrid)
}

// recordCurveContamination answers the second baseline question — "does the
// bank already hold the content this row is about?" — and records it under the
// key curveOutcome already uses, in the same polarity, so refusalOutcome reads
// it the way that function's sibling does.
//
// THE POLARITY IS WORTH READING TWICE because it is inverted relative to what
// the words suggest: oraclePreVerdictParam = Pass means the DER DOES hold this
// row's content, which for an EXECUTION row is a stale-register problem and for
// a REFUSAL row is a contaminated baseline. Fail means it does not, which is
// what a refusal row needs. Unset means the bank could not be read.
func recordCurveContamination(params map[string]string, uv invariant.UnitView, b *curveBinding) {
	where, ok := curveBaselineContamination(uv, b)
	if !ok {
		return // unset: refusalOutcome fails on an unestablished baseline
	}
	if len(where) == 0 {
		params[oraclePreVerdictParam] = string(certify.Fail)
		return
	}
	params[oraclePreVerdictParam] = string(certify.Pass)
	params[oraclePreObservedParam] = fmt.Sprintf(
		"%s already held this row's own %s breakpoints (%s) before this row published anything",
		strings.Join(where, " and "), b.Mode, b.describePublished())
}

// settleRefusal is settleOracle's mirror image, and the difference is the whole
// point of it.
//
// settleOracle waits for an effect to APPEAR and returns the moment it does: a
// Pass short-circuits, because an effect once observed cannot be un-observed.
// A refusal asserts an ABSENCE, and an absence observed early is worth nothing
// — the southbound write this row must catch lands on the reconciler's own
// tick, which is exactly the beat settleOracle exists to wait out. So this
// polls the WHOLE window and returns early only on a decided FAIL (a landing
// caught in the act). An Unavailable is retried, as it is there, and the last
// reading is what the deadline returns.
func settleRefusal(ctx context.Context, window, step time.Duration, eval func() Finding) Finding {
	deadline := time.Now().Add(window)
	last := eval()
	for last.Verdict != certify.Fail && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return last
		case <-time.After(step):
		}
		last = eval()
	}
	return last
}

// ── Unauthorable rows ───────────────────────────────────────────────────────

// critModeUnauthorable replaces the honest-looking SKIP a row used to carry
// when this bench has no lever for its control mode.
//
// A SKIP was the wrong shape and it hid a real gap for as long as it existed.
// The row's claim is that the DUT received and applied a control carrying this
// mode; nothing on this bench can put that mode on the wire, so the claim was
// never tested — and because Skip is the lowest severity in the roll-up, a row
// that tested nothing reported the same verdict as a row that tested everything
// and passed. Three rows of a twelve-row family certified that way.
//
// It is a FAIL rather than a WARN because the consequence is the same as a
// failure: a conformance bundle that claims these rows were exercised is wrong,
// and a reader has to be stopped rather than nudged. It is a BENCH gap, not a
// DUT defect, and the Observed text says so in its first sentence so nobody
// files it against the product.
func critModeUnauthorable(subject, element, why string) criterion {
	observed := "this row was NOT tested: no lever on this bench can place <" + element + "> on the wire, so " +
		"the DUT was never offered the control this row is about and nothing here is evidence about the " +
		"DUT. This is a BENCH capability gap, not a defect of the device under test — but it is reported " +
		"as a FAIL rather than skipped, because an untested row must not roll up as a passing one (a SKIP " +
		"is the lowest severity in the verdict roll-up and cannot hold a release). The gap: " + why
	return criterion{
		Claim:       "the DUT received and applied a DERControl carrying " + subject,
		LoadBearing: true,
		How: "the presence of a <" + element + "> element inside a DERControlBase the DUT fetched — which " +
			"this bench cannot produce; see the observation",
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return Finding{Verdict: certify.Fail, Observed: observed}
		},
	}
}

// critEffectBlockedByAuthoringGap is the southbound half of the same gap: with
// no control on the wire there is nothing for a southbound oracle to look for,
// so the DER's registers cannot answer this row's question either.
func critEffectBlockedByAuthoringGap(subject, element string) criterion {
	observed := "no southbound reading can settle this claim, because no control carrying <" + element +
		"> was ever placed on the wire for the DER to respond to (see the criterion above). The independent " +
		"southbound oracle this suite runs for the executable modes has nothing to correlate against here; " +
		"reporting that as anything but a FAIL would let an untested row certify itself"
	return criterion{
		Claim:       "the DER's own southbound registers reflect " + subject,
		LoadBearing: true,
		How: "an independent read of the DER's own SunSpec registers, correlated against the control this " +
			"row published — which, for this row, does not exist",
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return Finding{Verdict: certify.Fail, Observed: observed}
		},
	}
}

// vrefRequest renders a binding's authored vRef into the admin request's own
// width, or nil to omit the element.
//
// The widening is deliberate: gridsim takes a SIGNED int64 so it can refuse an
// out-of-domain value in the standard's vocabulary (PerCent is 0..10 000, 2018
// p.167) rather than letting encoding/json answer with a Go type name. A row
// cannot construct an out-of-domain value — curveBinding.VRef is a *uint16 — but
// the request type is shared with hand-written admin calls that can.
func vrefRequest(v *uint16) *int64 {
	if v == nil {
		return nil
	}
	n := int64(*v)
	return &n
}
