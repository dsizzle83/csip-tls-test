package suitecsip

// ridethrough.go — curve plan #32's last two decided-FAIL bench gaps.
//
// ── What this file closes ───────────────────────────────────────────────────
//
// BASIC-004 (Low/High Voltage Ride-Through) and BASIC-005 (Low/High Frequency
// Ride-Through) were `unreachableMode` rows: this bench had no lever that could
// put an <opModLVRTMustTrip> — or any of its nine siblings — on the wire, so
// the rows reported a decided FAIL naming the missing lever (register.go's
// withdrawn noRideThrough) and nothing about them had been tested. That was the
// honest posture while it lasted; it was not a measurement.
//
// The lever exists now (sim/gridsim/curve.go's ride-through modes and its
// multi-curve `curves` array), the referee decodes the register banks the
// curves land in (internal/invariant/curves.go's 707/708/709/710 sub-curve
// addressing), and the bench sim can hold the procedure's own seven-point curve
// (sim/southbound/trip1547.go's NPt). So these two rows become REAL measured
// rows, on the same terms every other curve row in this suite runs on.
//
// ── The terms, restated, because they bound what a green row here means ─────
//
// ZERO CURVE PHYSICS. The device sims adopt curves realistically — a writable
// staging set, the §3.1.2 AdptCrvReq/AdptCrvRslt handshake, a read-only live
// set at index 0 that reflects the staged points on COMPLETED — and simulate no
// trip BEHAVIOUR whatever: nothing on this bench disconnects when the voltage
// leaves the ride-through envelope. Every assertion below is therefore
// REGISTER- and ADOPT-STATE-based, exactly like curve.go's, and deliberately
// not an effect-on-output one. A row here says "the DER's own trip bank holds
// the curve this row published, adopted and enabled", and says nothing at all
// about what the DER would do at 0.88 pu.
//
// ── Why a row here is not a curveBinding ────────────────────────────────────
//
// A curveBinding carries ONE curve and ONE register home per generation.
// BASIC-004's Figure 4 prescribes FOUR curves and BASIC-005's Figure 5
// prescribes TWO, and the procedure puts each set on ONE DERControl ("The
// Service Point DERProgram shall have a DERControl instance with Low/High
// Voltage Ride Through values in Figure 4" — singular). Four curveBindings
// would be four controls; one curveBinding cannot express four curves. So the
// binding here carries a LIST, and every part of the apparatus — the publisher,
// the oracle, the criteria, the verdict — is written over that list.
//
// The four curves also land in DIFFERENT register banks and, on the 7xx
// generation, in different SUB-CURVES of the same bank: opModLVRTMustTrip is
// model 707's MustTrip sub-curve and opModLVRTMomentaryCessation is the SAME
// model's MomCess sub-curve. A binding that named only a model would have had
// no way to say which of the three it meant, and the referee would have had to
// pick — which is the silent substitution internal/invariant refuses to make.
//
// ── This file is a deliberate sibling of curve.go and basic.go, not a fork ──
//
// rideThroughSpec below duplicates the SHAPE of basic.go's inverterControlSpec
// — the discovery criteria, the mode-on-the-wire criterion, the default-control
// criterion, the Setup/PostWait/Cleanup wiring — and shares every one of their
// implementations by calling the same constructors. It is a separate function
// because inverterControlSpec dispatches on controlMode's four apparatus fields
// (Oracle, Curve, Refusal, LegacyCurve) and a fifth belongs there only if the
// owner of that file puts it there. Nothing here reimplements a criterion, a
// settle loop, a delivery record or a teardown: every one of those is the
// existing shared helper, called from a different assembly point.
//
// ── The authoring gaps that remain are NAMED ────────────────────────────────
//
// Two things this bench serves northbound have no southbound register home at
// all, and both are stated on every verdict rather than dropped:
//
//   - DERCurve.yRefType 4 (%setEffectiveV), which Figure 4 prescribes. The
//     SunSpec trip banks carry no DeptRef register — there is nothing in
//     707/708 that says what the y values are a percentage OF — so the element
//     is served and unasserted. See yRefTypeNoTripRegister.
//   - The whole southbound half of BASIC-005 on a LEGACY DER, and the
//     momentary-cessation half of BASIC-004 on one. See the two refusals in
//     the bindings below; neither is skipped.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// The Observation.Params keys the ride-through rows add. They are DISTINCT from
// the curve rows' (curve.go's iw15.curve_*), never those reused, so a bundle can
// show which apparatus produced a verdict and a test asserting "the trip row
// recorded what it published" cannot be satisfied by a curve row's leftover.
const (
	tripPublishedParam = "iw15.trip_published"
	tripTargetsParam   = "iw15.trip_targets"
	tripHrefsParam     = "iw15.trip_hrefs"

	// The protective-boundary readings, taken before this row publishes and
	// again after the DUT's poll cycle. See critProtectiveBoundaryHeld.
	tripProtectivePreParam  = "iw15.trip_protective_pre"
	tripProtectivePostParam = "iw15.trip_protective_post"
)

// derUnitRefSetEffectiveV is DERUnitRefType code 4, "%setEffectiveV" — IEEE Std
// 2030.5-2018 p.256, the same table curve.go's derUnitRef* constants are
// transcribed from.
//
// It lives here rather than beside them because it is the ride-through rows'
// code and nothing else in this suite publishes it: 2030.5 gives the voltage
// ride-through curves a y axis that is a percentage of the DER's EFFECTIVE
// voltage, which is why Figure 4 prescribes a yRefType and Figure 5 — whose y
// axis is absolute hertz — prescribes none. curve.go's derUnitRefName already
// spells the code out in a finding; what was missing was a name for the code
// itself, and a row publishing a bare 4 would be publishing a number no reader
// could check against the table it came from.
const derUnitRefSetEffectiveV uint8 = 4

// ── The binding ─────────────────────────────────────────────────────────────

// tripCurve is ONE authored ride-through curve: what goes on the wire, and
// where — exactly — it must be found on each SunSpec generation.
//
// It is curveBinding's per-curve half with one field added and several removed.
// The addition is Sub7xx, because a trip bank holds three curves and naming the
// model is not naming the curve. The removals are the volt-var family (vRef,
// the autonomous-vRef pair) and openLoopTms: IEEE Std 2030.5-2018 p.252-253
// makes the first three opModVoltVar-only by a SHALL NOT, and no Figure in this
// catalog prescribes an openLoopTms on a ride-through curve — a value nothing
// asks for is a value nothing tests, which is this suite's own rule.
type tripCurve struct {
	// Element is the DERControlBase child the DUT must be seen to receive, in
	// IEEE 2030.5's own spelling.
	//
	// THE STANDARD'S SPELLING, NOT THE CATALOG'S, for the two momentary-cessation
	// curves, and the divergence is the catalog's own. CSIP CTP v1.3's Figure 4
	// settings table prints "opModLVRTMustTripMomentaryCessation" and
	// "opModHVRTMustTripMomentaryCessation" while its Function table — and IEEE
	// Std 2030.5-2018 p.249-250, and lexa-proto/csipmodel's element names —
	// print "opModLVRTMomentaryCessation" and "opModHVRTMomentaryCessation". The
	// catalog's own `notes` field records the inconsistency. This bench follows
	// 2030.5: a DERControlBase has no element by the Figure's longer name, so
	// serving one would produce a document no conformant DUT could parse, and
	// the Figure's own Function table agrees with the standard against its
	// settings table.
	Element string
	// Mode is gridsim's own mode name for this curve (sim/gridsim/curve.go's
	// curveTypeForMode vocabulary).
	Mode string
	// Points are the breakpoints this curve publishes, in the wire's own raw
	// units; the multipliers below say what power of ten they carry.
	//
	// x IS TIME AND y IS THE ELECTRICAL QUANTITY on every one of these curves,
	// which is the fact everything downstream rests on. IEEE 2030.5's
	// ride-through DERCurves are duration-against-magnitude: with xMultiplier
	// and yMultiplier both -2, opModHVRTMustTrip's (16, 12000) is 0.16 s at
	// 120.00 % voltage, and opModLFRTMustTrip's (27000, 5690) is 270.00 s at
	// 56.90 Hz. A reader who took x for the voltage would find every one of
	// these curves absurd, which is why it is written down here.
	Points []CurvePoint
	// XMult/YMult are the DERCurve axis multipliers this curve publishes with.
	XMult, YMult int8
	// YRefType is the DERUnitRefType code the y axis carries (2018 p.256).
	//
	// Figure 4 prescribes 4 (%setEffectiveV) for the VOLTAGE curves and Figure 5
	// prescribes nothing at all for the frequency ones — which is not an
	// omission in the document. A frequency curve's y values are ABSOLUTE hertz
	// (model_709.json gives Pt.Hz the units string "Hz"), and an absolute
	// quantity is not a percentage of anything, so there is no reference for the
	// Figure to name. 0 is DERUnitRefType's own "N/A" and is what the frequency
	// rows publish.
	YRefType uint8

	// ── The southbound target, PER GENERATION ──
	//
	// Both arms live on ONE curve and which applies is resolved at run time from
	// the DER's own model chain, exactly as curveBinding does it, so a single
	// catalog row runs on either bench and says which one it measured.

	// Model7xx is the 7xx trip model this curve's content must be found in, and
	// Sub7xx is WHICH of that model's three sub-curves. Both are required: a
	// trip set holds MustTrip, MayTrip and MomCess end to end, and a target that
	// named only the model would leave the referee to choose.
	Model7xx uint16
	Sub7xx   invariant.CurveSub
	// Mapping7xx records where that correspondence comes from, so a FAIL naming
	// a register bank can be checked by a reader who did not write it.
	Mapping7xx string
	// NoRegisterHome7xx, when non-empty, says the 7xx family has no home for
	// this curve and why.
	NoRegisterHome7xx string

	// ModelLegacy / MappingLegacy / NoRegisterHomeLegacy are the same facts for
	// the legacy 12x family. The legacy ride-through banks carry a SINGLE region
	// per bank — there is no sub-curve axis at all — so there is no SubLegacy.
	ModelLegacy          uint16
	MappingLegacy        string
	NoRegisterHomeLegacy string
}

// tripBinding is a ride-through row's whole apparatus: the list of curves it
// publishes on ONE DERControl, where those values come from, and whatever the
// procedure prescribes that this bench cannot author.
type tripBinding struct {
	// Curves are the row's authored curves, in the order the Figure prints
	// them. All of them ride one control.
	Curves []tripCurve
	// Prescribed states WHERE the values come from — the catalog Figure and
	// column, verbatim enough that a reader can find it.
	Prescribed string
	// Gaps are prescribed elements this bench cannot place on the wire, on the
	// same rule curveBinding.Gaps follows: a row whose control was authored
	// without part of what the procedure specifies has not been run to the
	// procedure, and a bundle that did not say so would be overclaiming.
	Gaps []curveGap
}

// elements renders the DERControlBase children this row publishes.
func (b *tripBinding) elements() []string {
	out := make([]string, 0, len(b.Curves))
	for _, c := range b.Curves {
		out = append(out, c.Element)
	}
	return out
}

// element is the row's headline element, for the prose that needs one name.
// It is the FIRST authored curve's, and every criterion that can name all of
// them does (see rideThroughSpec's per-curve wire criteria).
func (b *tripBinding) element() string {
	if len(b.Curves) == 0 {
		return "no element"
	}
	return b.Curves[0].Element
}

// materialGaps are the gaps that mean this row was not run to its procedure.
func (b *tripBinding) materialGaps() []curveGap {
	var out []curveGap
	for _, g := range b.Gaps {
		if g.Material {
			out = append(out, g)
		}
	}
	return out
}

// immaterialGaps are the named-but-not-holding gaps.
func (b *tripBinding) immaterialGaps() []curveGap {
	var out []curveGap
	for _, g := range b.Gaps {
		if !g.Material {
			out = append(out, g)
		}
	}
	return out
}

// wantPoints converts one authored curve's published breakpoints into the
// device engineering values the oracle expects to read back, applying the axis
// multipliers exactly once, here.
//
// NOTHING ELSE HAPPENS TO THEM. There is no vRef to fold in (2018 p.253 forbids
// the element on any curveType but opModVoltVar) and no transposition to
// perform: internal/invariant already normalises a decoded trip point to
// (seconds, quantity), which is the order the published pair is in. A
// transposition here would be a second one.
func (c tripCurve) wantPoints() []invariant.CurvePoint {
	out := make([]invariant.CurvePoint, 0, len(c.Points))
	for _, p := range c.Points {
		out = append(out, invariant.CurvePoint{
			X: applyMult(p.X, c.XMult),
			Y: applyMult(p.Y, c.YMult),
		})
	}
	return out
}

// describePublished renders one authored curve, for a finding that has to show
// both curves side by side.
func (c tripCurve) describePublished() string {
	pts := make([]string, 0, len(c.Points))
	for _, p := range c.Points {
		pts = append(pts, fmt.Sprintf("(%s, %s)", trimNum(p.X), trimNum(p.Y)))
	}
	s := fmt.Sprintf("<%s> %d breakpoint(s) %s", c.Element, len(c.Points), strings.Join(pts, " "))
	if c.XMult != 0 || c.YMult != 0 {
		s += fmt.Sprintf(" (x multiplier 10^%d, y multiplier 10^%d)", c.XMult, c.YMult)
	}
	// The engineering values the DEVICE must hold, spelled out beside the raw
	// ones. On these curves the multipliers are what makes 16 mean 0.16 s and
	// 12000 mean 120.00 %, and a finding showing only the raw pairs asks a
	// reader to do the arithmetic that the comparison already did.
	eng := make([]string, 0, len(c.Points))
	for _, p := range c.wantPoints() {
		eng = append(eng, fmt.Sprintf("(%s s, %s)", trimNum(p.X), trimNum(p.Y)))
	}
	s += fmt.Sprintf(" = %s in the device's own units", strings.Join(eng, " "))
	s += fmt.Sprintf(", yRefType=%d (%s)", c.YRefType, derUnitRefName(c.YRefType))
	return s
}

// describePublished renders every authored curve of a row.
func (b *tripBinding) describePublished() string {
	parts := make([]string, 0, len(b.Curves))
	for _, c := range b.Curves {
		parts = append(parts, c.describePublished())
	}
	return fmt.Sprintf("%d curve(s) on ONE DERControl: %s", len(b.Curves), strings.Join(parts, "; "))
}

// tripTarget is one authored curve's resolved southbound home on THIS DER's
// generation.
type tripTarget struct {
	Model uint16
	// Sub is which sub-curve of a 7xx trip bank holds it, and SubCurveNone on
	// the legacy generation, whose banks have no sub-curve axis at all.
	Sub            invariant.CurveSub
	Family         invariant.CurveFamily
	Mapping        string
	NoRegisterHome string
}

// resolve picks this curve's register home for a FAMILY.
//
// A family this curve declares NEITHER a model NOR a stated absence for
// resolves to a NAMED ABSENCE, never to a measurable-looking target with model
// 0 — the trap droopBinding.resolve documents: model 0 reads as "measurable"
// one caller up, and the oracle then reports what it found in a model that does
// not exist.
func (c tripCurve) resolve(fam invariant.CurveFamily) tripTarget {
	var t tripTarget
	switch fam {
	case invariant.FamilyLegacy:
		t = tripTarget{Model: c.ModelLegacy, Family: fam, Mapping: c.MappingLegacy,
			NoRegisterHome: c.NoRegisterHomeLegacy}
	case invariant.Family7xx:
		t = tripTarget{Model: c.Model7xx, Sub: c.Sub7xx, Family: fam, Mapping: c.Mapping7xx,
			NoRegisterHome: c.NoRegisterHome7xx}
	default:
		return tripTarget{Family: fam, NoRegisterHome: "this DER's SunSpec curve generation could not be " +
			"determined, so which register bank (if any) would hold an authored <" + c.Element +
			"> on it has no answer here"}
	}
	if t.Model == 0 && t.NoRegisterHome == "" {
		t.NoRegisterHome = "this row declares no <" + c.Element + "> arm for the " + string(fam) +
			" generation at all — neither a register home nor a reason there is none — so nothing " +
			"southbound can be asserted about the curve it published, and this run says so rather than " +
			"grading a bank no row named"
	}
	if t.Family == invariant.Family7xx && t.NoRegisterHome == "" && t.Sub == invariant.SubCurveNone {
		// A 7xx arm that named a model and no sub-curve is a CONSTRUCTION defect
		// and is reported as an absence rather than resolved by a default. The
		// default that suggests itself is MustTrip, and it is the worst
		// available: a momentary-cessation curve graded against the must-trip
		// sub-curve would report a mismatch about a bank holding exactly what
		// was commanded.
		t.NoRegisterHome = "this row's 7xx arm for <" + c.Element + "> names model " +
			strconv.FormatUint(uint64(t.Model), 10) + " and no SUB-CURVE, and a trip bank holds three " +
			"(MustTrip / MayTrip / MomCess). Choosing one here would grade a curve the row's author never " +
			"named, so nothing is asserted instead"
	}
	return t
}

// describeTargets renders both arms of every authored curve, for a criterion's
// How and for a FAIL that has to name what it was looking for.
func (b *tripBinding) describeTargets() string {
	part := func(gen string, model uint16, sub invariant.CurveSub, none string) string {
		switch {
		case none != "":
			if model != 0 {
				return fmt.Sprintf("%s: no register home (nearest model M%d) — %s", gen, model, none)
			}
			return fmt.Sprintf("%s: no register home — %s", gen, none)
		case model != 0 && sub != invariant.SubCurveNone:
			return fmt.Sprintf("%s: M%d %s", gen, model, sub)
		case model != 0:
			return fmt.Sprintf("%s: M%d", gen, model)
		default:
			return gen + ": this row declares no target"
		}
	}
	parts := make([]string, 0, len(b.Curves))
	for _, c := range b.Curves {
		parts = append(parts, fmt.Sprintf("<%s> [%s; %s]", c.Element,
			part("on a 7xx DER", c.Model7xx, c.Sub7xx, c.NoRegisterHome7xx),
			part("on a legacy 12x DER", c.ModelLegacy, invariant.SubCurveNone, c.NoRegisterHomeLegacy)))
	}
	return strings.Join(parts, "; ")
}

// ── The y-axis reference, served and unassertable ───────────────────────────

// yRefTypeNoTripRegister is why an authored ride-through yRefType has no
// southbound assertion on either generation.
//
// IT IS A DIFFERENCE OF KIND, not a coverage gap. SunSpec's volt-var and
// volt-watt banks declare a DeptRef register precisely because their y values
// are a percentage and a percentage is not a quantity without its base; the
// trip banks declare NONE, because their y axis is fixed by the model. 707/708
// give Pt.V the units string "VNomPct" — per cent of NOMINAL voltage — and
// 709/710 give Pt.Hz the units "Hz", an absolute frequency. There is no
// register that could hold "and the base is %setEffectiveV", so there is
// nothing for this referee to read.
//
// THE VOLTAGE BASE IS NOT LITERALLY THE SAME QUANTITY, and this is the caveat
// worth carrying: Figure 4 names %setEffectiveV and the device's register names
// VNomPct. They coincide exactly when the DER's effective voltage IS its
// nominal voltage, which is true of every device on this bench and is not true
// by definition. It is the same shape as model 134's WRef against CSIP's
// %setMaxW (mappingFreqWattLegacy) — two references that agree by
// configuration rather than by construction — so the comparison is made on the
// NUMBERS and the assumption is stated rather than buried.
const yRefTypeNoTripRegister = "no SunSpec ride-through bank on either generation carries a DeptRef " +
	"register: 707/708 fix their y axis at VNomPct (per cent of NOMINAL voltage) and 709/710 at absolute " +
	"Hz, so there is nothing on the device that could hold the yRefType this row served. It is SERVED " +
	"northbound exactly as Figure 4 prescribes — that half is real evidence about what the DUT was " +
	"offered — and no southbound read can show what became of it. NOTE the base the device's own register " +
	"names is VNomPct where the control named %setEffectiveV; the two coincide when the DER's effective " +
	"voltage is its nominal voltage, which is the case on this bench and is not true by construction, so " +
	"the comparison below is of the NUMBERS under that stated assumption"

// unmappableClause is the sentence every trip verdict carries so that an
// element served northbound and asserted about by nothing is NAMED where the
// measurement is reported.
//
// It is unconditional on these rows rather than computed per generation, unlike
// curveBinding's, because the answer is the same on both: no trip bank of
// either family carries a y-reference register. A per-generation computation
// would suggest the answer could differ and invite a reader to check which one
// they were looking at.
func (b *tripBinding) unmappableClause() string {
	var named []string
	for _, c := range b.Curves {
		if c.YRefType != 0 {
			named = append(named, fmt.Sprintf("<%s> yRefType=%d (%s)", c.Element, c.YRefType,
				derUnitRefName(c.YRefType)))
		}
	}
	if len(named) == 0 {
		return ""
	}
	return " AUTHORED BUT NOT DEVICE-MAPPABLE: this row also placed " + strings.Join(named, ", ") +
		" on the wire, and " + yRefTypeNoTripRegister + ". That is a property of the device model, not a " +
		"gap in the bench, and it is stated here rather than left out so no reader can mistake this " +
		"verdict for a measurement of it."

}

// ── The oracle ──────────────────────────────────────────────────────────────

// oracleTrip builds the independent southbound oracle for a ride-through row.
//
// It asks ONE question per authored curve — does the DER's own trip bank hold
// the breakpoints THIS curve published, in a function that is adopted and
// enabled? — and composes the answers. Every terminal is decided: there is no
// Skip and no "unavailable" a row can rest on, because an unmeasured criterion
// is not a satisfied one and a Skip is severity 0 in every roll-up.
//
// THE COMPOSITION RULE IS "THE WORST ANSWER DECIDES, AND EVERY ANSWER IS
// CARRIED". A DUT that adopted the must-trip curve and ignored the
// momentary-cessation one has executed half of one control, and half is not
// execution; a verdict that reported only the failing half would leave a bundle
// with no trace that the other half was measured at all. Both failures are the
// same "the reader cannot tell what was asserted" defect, in opposite
// directions, and curve.go's droop composition already resolves them this way.
//
// A CURVE WITH NO REGISTER HOME IS NOT A FAILURE OF THE ROW — it is a fact
// about the DER in front of it, and it is reported as such alongside the curves
// that WERE measured. The alternative was tried and is worse: BASIC-005 on a
// legacy DER has no southbound home for either of its curves, and a row that
// FAILED for that would be reporting a bench limitation as a device finding.
// What it must not do is go green, and it cannot: a row with nothing measurable
// at all returns a decided FAIL naming both arms (see the empty-measured case).
func oracleTrip(b *tripBinding) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		published := b.describePublished()

		gen := curveGenerationOf(uv)
		if gen == genAmbiguous {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound and the DER under test serves BOTH SunSpec curve "+
					"generations, so which register banks this row is about has no answer: %s. This row "+
					"declares %s. No row in this suite was written for a device carrying both families, and "+
					"choosing one silently would grade banks the row's author never considered — so the "+
					"ambiguity is reported as a FAIL rather than resolved by a tie-break. REMEDY: grade this "+
					"DER on a bench serving one generation, or extend the row with an explicit per-device "+
					"target",
				published, describeGeneration(uv), b.describeTargets())}
		}
		fam := invariant.CurveFamily(gen.String())

		var measured []Finding
		var unmeasured []string
		for _, c := range b.Curves {
			t := c.resolve(fam)
			if t.NoRegisterHome != "" {
				unmeasured = append(unmeasured, fmt.Sprintf("<%s> (%s)", c.Element, t.NoRegisterHome))
				continue
			}
			measured = append(measured, tripCurveOutcome(c, t, uv))
		}

		unmappable := b.unmappableClause()
		absence := ""
		if len(unmeasured) > 0 {
			absence = " SERVED AND NOT ASSERTED SOUTHBOUND on this DER's generation (" + string(fam) +
				"): " + strings.Join(unmeasured, "; ") + ". Those curves went on the wire and this " +
				"referee asserts nothing about them here."
		}

		if len(measured) == 0 {
			// Nothing this row published has a register home on this device. That
			// is a decided FAIL and not a Skip: the row's southbound half could
			// not be measured AT ALL, and an unmeasured criterion is not a
			// satisfied one. The FAIL names both arms of every curve so a reader
			// can see it is a property of the bench in front of them.
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound and the DER under test has NO southbound register home "+
					"for ANY of it (%s). The models the DER does serve are %s. With no bank to read, this "+
					"row's second half cannot be measured at all — which is reported as a FAIL rather than "+
					"skipped.%s%s",
				published, b.describeTargets(), modelList(uv), absence, unmappable)}
		}

		worst := measured[0]
		others := make([]string, 0, len(measured))
		for _, f := range measured[1:] {
			if f.Verdict.Severity() > worst.Verdict.Severity() {
				others = append(others, worst.Observed)
				worst = f
				continue
			}
			others = append(others, f.Observed)
		}
		out := worst
		if len(others) > 0 {
			out.Observed += " AND " + strings.Join(others, " AND ")
		}
		out.Observed += absence + unmappable
		return out
	}
}

// tripCurveOutcome measures ONE authored curve against its resolved bank.
//
// The checks are ordered so the FAIL says the most useful thing first — the
// model is absent, or present-but-never-adopted, or adopted-but-disabled, or
// adopted-and-enabled-with-the-wrong-content — because those are four different
// defects with four different owners, and a bundle that collapsed them into
// "the curve did not land" would send every one of them to the wrong person. It
// is curveContentOutcome's shape, over a sub-curve.
func tripCurveOutcome(c tripCurve, t tripTarget, uv invariant.UnitView) Finding {
	published := c.describePublished()
	cv := tripView(uv, t)
	where := fmt.Sprintf("the DER's %s", cv.Axis.Name)
	if t.Sub != invariant.SubCurveNone {
		where = fmt.Sprintf("the DER's %s %s sub-curve", cv.Axis.Name, t.Sub)
	}

	if !cv.Present {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"this row published %s northbound and the DER's own register image carries NOTHING for it: "+
				"%s. %s The models the DER does serve are %s",
			published, cv.Describe(), t.Mapping, modelList(uv))}
	}
	if !cv.Adopted {
		// The two generations reach "not adopted" by different routes and a
		// finding that named the wrong one would send a reader to a register that
		// does not exist: on 7xx the adopt HANDSHAKE never COMPLETED; on legacy
		// there is no handshake at all and the fact is that ActCrv does not
		// select the bank this content would be in.
		how := "adopt handshake never COMPLETED, so no curve-set was taken up"
		if cv.Legacy() {
			how = fmt.Sprintf("ActCrv selects no bank holding this row's content (ActCrv=%d) — on this "+
				"generation there is no adopt handshake, so the SELECTION is the whole of the commit and "+
				"a bank nobody selected commands nothing", cv.ActCrv)
		}
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"this row published %s northbound and %s %s: %s. %s",
			published, where, how, cv.Describe(), t.Mapping)}
	}
	match := invariant.MatchPoints(cv.Points, c.wantPoints(), curvePointTolerance)
	if !match.Matched {
		held := "reports an adopted curve-set whose CONTENT is not the one this row published"
		if cv.Legacy() {
			held = fmt.Sprintf("is running the bank ActCrv selects (bank %d), and its CONTENT is not the "+
				"curve this row published", cv.Bank)
		}
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%s %s: %s. This row published %s. Full register state: %s",
			where, held, match.Reason, published, cv.Describe())}
	}
	if !cv.Enabled {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%s holds exactly the breakpoints this row published, but the function itself is DISABLED "+
				"(Ena=%d): a ride-through curve adopted into a switched-off trip function commands "+
				"nothing, so this is not execution of the control. %s",
			where, cv.EnaRaw, cv.Describe())}
	}
	// The read-only warning is 7xx-ONLY, on the same correctness rule
	// curveContentOutcome states: on 7xx the live set is index 0 and a
	// conformant device keeps it read-only, so a writable one means the index-0
	// convention does not hold and this reading may be of a staged set. On
	// legacy EVERY bank is ordinarily writable — that is how a gateway installs
	// a curve at all, there being no staging slot — so the same warning would
	// fire on every correct legacy device.
	if !cv.ReadOnly && !cv.Legacy() {
		return Finding{Verdict: certify.Warn, Observed: fmt.Sprintf(
			"%s holds exactly the breakpoints this row published and is enabled, but its index-0 "+
				"curve-set reports ReadOnly=false — on a conformant device the ACTIVE set is read-only and "+
				"the writable ones are the staging indices, so this reading may be of a staged set rather "+
				"than the governing one. %s",
			where, cv.Describe())}
	}
	became := "its adopt handshake COMPLETED and the function is enabled"
	if cv.Legacy() {
		became = fmt.Sprintf("ActCrv selects that bank (bank %d) and ModEna bit 0 is set", cv.Bank)
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"%s holds exactly the breakpoints this row published for <%s>, %s: %s. %s",
		where, c.Element, became, match.Reason, cv.Describe())}
}

// tripView reads the resolved bank through the referee, addressing the
// sub-curve on 7xx and the whole (single-region) bank on legacy.
//
// The legacy banks take the ORDINARY curve read and not a sub-curve one, and
// that is a statement about the generation rather than a convenience: models
// 129 and 130 declare one point table per bank and no sub-curve axis anywhere,
// so asking them for a MustTrip sub-curve is asking for something that does not
// exist. internal/invariant answers such a request with a decode error, which
// is the correct answer and the wrong one to put in front of a reader here.
func tripView(uv invariant.UnitView, t tripTarget) invariant.CurveView {
	if t.Sub == invariant.SubCurveNone {
		return uv.Curve(oracleSimName, t.Model)
	}
	return uv.TripCurve(oracleSimName, t.Model, t.Sub)
}

// ── The protective boundary ─────────────────────────────────────────────────

// protectiveEnables reports, for every ride-through bank this DER serves,
// whether its function is switched on.
//
// TWO RENDERINGS, and the split matters. canonical is a stable machine-readable
// string ("129=on;130=off") that a before/after comparison can be made over
// without re-reading the device; human is what a verdict quotes. Deriving the
// comparison from the prose would make a wording change into a behaviour
// change.
func protectiveEnables(uv invariant.UnitView) (canonical, human string) {
	models := []uint16{
		sunspec.ModelLVRTLegacy, sunspec.ModelHVRTLegacy,
		sunspec.ModelDERTripLV, sunspec.ModelDERTripHV,
		sunspec.ModelDERTripLF, sunspec.ModelDERTripHF,
	}
	var canon, prose []string
	for _, m := range models {
		cv := uv.Curve(oracleSimName, m)
		if !cv.Present {
			continue
		}
		state := "off"
		if cv.Enabled {
			state = "on"
		}
		canon = append(canon, fmt.Sprintf("%d=%s", m, state))
		prose = append(prose, fmt.Sprintf("M%d %s (raw enable register %#04x)", m, strings.ToUpper(state),
			cv.EnaRaw))
	}
	if len(canon) == 0 {
		// A SENTINEL, not an empty string, and the difference is the whole
		// reason this function returns a canonical form at all. "the DER serves
		// no ride-through bank" is a real answer and "this reading was never
		// taken" is not, and both would render as "" — so the criterion would
		// report a device with nothing to protect and a device it could not read
		// with the same verdict, which is the absence-reads-as-success shape
		// this suite exists to remove.
		return protectiveNoBanks, "this DER serves no ride-through bank at all"
	}
	return strings.Join(canon, ";"), strings.Join(prose, ", ")
}

// protectiveNoBanks is the canonical reading of a DER that serves no
// ride-through model at all. See protectiveEnables for why it is not "".
const protectiveNoBanks = "none"

// parseProtectiveEnables turns a canonical rendering back into a map. The
// no-banks sentinel parses to an empty map, which is the same thing it means.
func parseProtectiveEnables(s string) map[uint16]bool {
	out := map[uint16]bool{}
	if s == protectiveNoBanks {
		return out
	}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(k), 10, 16)
		if err != nil {
			continue
		}
		out[uint16(n)] = strings.TrimSpace(v) == "on"
	}
	return out
}

// critProtectiveBoundaryHeld is the MEASURED half of the never-disable claim:
// no ride-through function that was switched ON before this row published is
// switched OFF after it.
//
// WHY A RIDE-THROUGH ROW NEEDS THIS AND A VOLT-VAR ROW DOES NOT. A trip curve
// is a PROTECTIVE setting. Every other curve axis in this suite fails closed —
// lexa-proto's WriteLegacyCurve disables the function (ModEna=0) when a write
// fails after the selection has moved, because a curve the gateway cannot vouch
// for is worse than no curve — and doing that to a trip boundary would delete
// the device's protection as a failure action. lexa-proto refuses to:
// WriteLegacyRideThrough is a SEPARATE function whose failure arm restores
// ActCrv and never writes ModEna, and it is structurally unable to reach the
// fail-closed helper at all (see critProtectiveBoundaryStructure).
//
// That is a claim about the writer. THIS criterion is the claim about the RUN:
// whatever the DUT did during this row's window, the boundary that was up is
// still up. It is a before/after comparison over readings this row's own Setup
// and PostWait took, which is the only form the claim can take from outside —
// a single reading cannot tell "the gateway disabled it" from "it was already
// off when we arrived".
//
// A BANK THAT WAS ALREADY OFF IS REPORTED AND DOES NOT FAIL. Nothing this row
// did turned it off, and grading the DER's own resting configuration is not
// this row's business — the same asymmetry autonomousArmingFinding applies to
// an unrequested VRefAutoEna.
func critProtectiveBoundaryHeld(o *Observation) criterion {
	pre, post := o.Param(tripProtectivePreParam), o.Param(tripProtectivePostParam)
	return criterion{
		Claim: "no ride-through function that was ENABLED on the DER before this row published is " +
			"disabled after it — a protective trip boundary is never stripped as a side effect of " +
			"commanding one",
		How: "two independent reads of the DER's own ride-through banks (models 129/130 on a legacy DER, " +
			"707/708/709/710 on a 7xx one) through internal/invariant: one in this row's Setup, before " +
			"anything was published, and one in PostWait after the DUT's poll cycle. The comparison is of " +
			"each bank's own enable register",
		Tier: tierOracle,
		Construction: func() Finding {
			switch {
			case pre == "" && post == "":
				// Both readings absent. That is a decided FAIL rather than a
				// skip: this row's whole southbound apparatus reads the DER, so
				// two missing readings mean the oracle never ran or its record
				// was lost, and an unrecorded criterion is not a satisfied one.
				return Finding{Verdict: certify.Fail, Observed: "neither the pre-publication nor the " +
					"post-publication reading of the DER's ride-through banks was recorded, so whether " +
					"this row's window left a protective trip boundary disabled cannot be said. An " +
					"unrecorded criterion is not a satisfied one"}
			case pre == "" || post == "":
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"only one of the two readings this comparison needs was recorded (pre=%q post=%q), so "+
						"a boundary that went down during this row's window would be indistinguishable "+
						"from one that was never up",
					orText(pre, "not recorded"), orText(post, "not recorded"))}
			}
			before, after := parseProtectiveEnables(pre), parseProtectiveEnables(post)
			var stripped []string
			models := make([]int, 0, len(before))
			for m := range before {
				models = append(models, int(m))
			}
			sort.Ints(models)
			for _, m := range models {
				if before[uint16(m)] && !after[uint16(m)] {
					stripped = append(stripped, fmt.Sprintf("M%d", m))
				}
			}
			if len(stripped) > 0 {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"the DER's %s ride-through function(s) were ENABLED before this row published and are "+
						"DISABLED after it. A trip boundary is a protective setting and is never removed "+
						"as a failure action or a side effect of commanding one: lexa-proto's "+
						"WriteLegacyRideThrough refuses the Case-B rewrite for exactly this reason "+
						"(\"a protective function is not momentarily removed to update it\") and its "+
						"failure arm restores the curve SELECTION rather than clearing ModEna. Something "+
						"in this window did what that writer will not. Readings: before [%s], after [%s]",
					strings.Join(stripped, " and "), pre, post)}
			}
			if len(before) == 0 {
				// Nothing to strip. Stated in the plainest terms available, and
				// deliberately NOT dressed up as a passing measurement of the
				// never-disable arm: this run exercised nothing of it.
				return Finding{Verdict: certify.Pass, Observed: "this DER serves NO ride-through bank at " +
					"all, so there was no protective trip boundary for this row's window to strip and this " +
					"criterion measured nothing. It is recorded as satisfied because the claim — that " +
					"nothing was stripped — is true of a device with nothing to strip, and NOT because " +
					"the never-disable behaviour was exercised here; the structural claim beside it says " +
					"where that is proven"}
			}
			return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
				"every ride-through function the DER had switched on before this row published is still "+
					"switched on after it. Readings: before [%s], after [%s]", pre, post)}
		},
	}
}

// critProtectiveBoundaryStructure is the CONSTRUCTION half of the never-disable
// claim: the properties of lexa-proto's own ride-through writer that make the
// measured half something other than luck.
//
// It is a construction criterion — asserted with or without a recovered capture
// — because it is a claim about the WRITER, which no pcap could confirm or
// refute. Every clause is quoted from that writer's own doc comments so a
// reader can check it in the source rather than trusting this sentence, and
// each is exercised by a named test in this package: an unexercised structural
// claim is a comment, not a guarantee.
//
// IT DOES NOT CLAIM TO BE A MEASUREMENT OF THIS RUN, and says so. The pairing
// is deliberate: this states what the machinery guarantees, the criterion above
// states what this window observed, and neither is allowed to stand in for the
// other.
func critProtectiveBoundaryStructure() criterion {
	return criterion{
		Claim: "the legacy ride-through writer this product will call CANNOT disable a protective trip " +
			"boundary as a failure action — structurally, not by convention",
		How: "lexa-proto/derbase/legacycurve.go's own documented behaviour, exercised from this package by " +
			"TestLegacyRideThroughRefusesCaseBAndLeavesTheBoundaryUp, " +
			"TestLegacyRideThroughIsNotReachableThroughTheFailClosedWriter and " +
			"TestReleaseIsNoOpinionOnTheProtectiveModels",
		Tier: tierOracle,
		Construction: func() Finding {
			return Finding{Verdict: certify.Pass, Observed: "THIS IS A PROPERTY OF THE WRITER, NOT A " +
				"MEASUREMENT OF THIS RUN (the criterion beside it carries that). Three facts, each from " +
				"lexa-proto/derbase/legacycurve.go's own doc comments: (1) the fail-closed helper that " +
				"writes ModEna=0 takes a nonProtectiveCurve WITNESS which only nonProtective() can mint " +
				"and which refuses models 129 and 130, so \"the ride-through writer cannot reach the " +
				"fail-closed helper — not 'does not', CANNOT\"; (2) WriteLegacyRideThrough REFUSES the " +
				"Case-B single-bank rewrite with reason legacy-ride-through-single-bank, because " +
				"\"rewriting the live bank means deleting the trip boundary for the width of the " +
				"transaction, and a protective setting is not something to momentarily delete\"; (3) its " +
				"failure arm RESTORES the ActCrv selection recorded at engage and never writes ModEna, " +
				"\"because a known-wrong trip boundary is better than an unknown one\". A fourth, from " +
				"ReleaseLegacyCurve: releasing a control on 129/130 is NoOpinion — " +
				"\"ride-through is a protective trip boundary and is never stripped by a release\""}
		},
	}
}

// ── The construction criterion ──────────────────────────────────────────────

// critTripPublishedTheProcedureValues asserts that what went on the wire is
// what the certification procedure prescribes.
//
// It is critCurvePublishedTheProcedureValues' sibling and carries the same
// posture: a CONSTRUCTION claim, pinned against the catalog by
// TestRideThroughRows_PublishTheCatalogPrescribedValues rather than restated
// here, FAILing when a MATERIAL element is missing — one whose prescribed test
// value differs from the procedure's own default, so omitting it means the DUT
// was never offered the condition the row exists to create.
func critTripPublishedTheProcedureValues(subject string, b *tripBinding) criterion {
	material := b.materialGaps()
	prescribed := orText(b.Prescribed, "this row's binding records no provenance for its published values")
	return criterion{
		Claim: "the control this row published carries the values the certification procedure prescribes " +
			"for " + subject + ", as ONE DERControl carrying all " + strconv.Itoa(len(b.Curves)) +
			" of the Figure's curves",
		How: "the row's own trip binding, pinned against the catalog's Figure by a construction test " +
			"(TestRideThroughRows_PublishTheCatalogPrescribedValues) rather than restated here: " + prescribed,
		Construction: func() Finding {
			authored := fmt.Sprintf("the elements this row places on the wire are %s, all linked from ONE "+
				"DERControl. Their y-axis references are served and NOT device-mappable: %s",
				strings.Join(b.elements(), ", "), yRefTypeNoTripRegister)
			if len(material) > 0 {
				return Finding{Verdict: certify.Fail, Observed: "this row published " + prescribed +
					", and the following element(s) the procedure prescribes could NOT be placed on the " +
					"wire by this bench: " + describeGaps(material) + ". Each carries a test value that " +
					"DIFFERS from the procedure's own default, so the DUT was never offered the condition " +
					"this row exists to create. This is a BENCH capability gap, not a defect of the device " +
					"under test — and it is reported as a FAIL rather than skipped, because a row that was " +
					"not run to its procedure must not roll up as one that was. " + authored +
					". Elements omitted with no material effect: " + describeGaps(b.immaterialGaps())}
			}
			return Finding{Verdict: certify.Pass, Observed: "this row published " + prescribed + ". " +
				authored + ". Elements omitted with no material effect (test value equal to the default, " +
				"or a transcription divergence this bench deliberately does not follow): " +
				describeGaps(b.immaterialGaps())}
		},
	}
}

// critTripCurvesResolvable asserts that EVERY DERCurve resource this row's
// control links is one the DUT could actually fetch.
//
// It is critDERCurveResolvable over a list, and the list is the point: a
// ride-through control carries four hrefs and a criterion that checked one of
// them would leave three unverified. A 404 on any of them delivers a link and
// no curve content for that axis, and the resulting southbound silence is a
// BENCH gap wearing the DUT's clothes.
//
// Unavailable — not FAIL — when the DUT never fetched a given href: a DUT that
// refuses the axis at receipt has no reason to resolve the curve, and grading
// that as a bench 404 would blame the wrong party.
func critTripCurvesResolvable(hrefs []string) criterion {
	return criterion{
		Claim: "every DERCurve resource this row's DERControl links resolves for the DUT",
		How: "a GET on each of " + orText(strings.Join(hrefs, ", "), "(no hrefs were recorded)") +
			" in the recovered transcript, and the status line the server answered it with",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			if len(hrefs) == 0 {
				return unavailable("this row recorded no DERCurve hrefs, so which resources the control " +
					"linked cannot be checked from here")
			}
			var fetched, missing []string
			for _, href := range hrefs {
				found := false
				for _, e := range t.Method("GET") {
					if e.Req == nil || e.Resp == nil || !strings.HasSuffix(e.Req.Target, href) {
						continue
					}
					found = true
					if e.Resp.Status/100 != 2 {
						return citeExchange(t, e, certify.Fail,
							"GET %s answered %s — the control this row published links a curve resource "+
								"the server does not serve, so the DUT received a link and no curve "+
								"content for that axis. This is a BENCH authoring gap, not a DUT defect, "+
								"and it makes any southbound silence for that axis unattributable until "+
								"it is closed", e.Req.Target, e.Resp.Line())
					}
					fetched = append(fetched, href)
					break
				}
				if !found {
					missing = append(missing, href)
				}
			}
			if len(fetched) == 0 {
				return unavailable("the DUT issued no GET for any of this row's %d curve hrefs (%s) in "+
					"this window, so whether the links resolve was not exercised (a DUT that refuses "+
					"these axes at receipt has no reason to fetch the curves)",
					len(hrefs), strings.Join(hrefs, ", "))
			}
			if len(missing) > 0 {
				return Finding{Verdict: certify.Warn, Observed: fmt.Sprintf(
					"the DUT fetched %d of this row's %d curve hrefs and every one it fetched resolved "+
						"(%s); it issued no GET at all for %s, so those links were not exercised. A DUT "+
						"that fetches some of a control's curves and not others may be refusing the "+
						"unfetched axes at receipt, which is a different fact from a bench 404 and is "+
						"reported as such rather than graded",
					len(fetched), len(hrefs), strings.Join(fetched, ", "), strings.Join(missing, ", "))}
			}
			return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
				"the DUT fetched all %d of this row's curve hrefs and every one resolved: %s",
				len(hrefs), strings.Join(fetched, ", "))}
		},
	}
}

// ── The live phase ──────────────────────────────────────────────────────────

// tripSetup is a ride-through row's Setup: read the DER's own trip banks BEFORE
// publishing anything, then publish this row's whole Figure as ONE control.
//
// The pre-read is what makes the post-read evidence, for the reason curveSetup
// states: "the DER holds this curve after the control was published" is a fact
// about the DER, not about the DUT, until it is paired with "and it did not
// hold it before". Trip rows have no ladder to fall back on — the curve is the
// row's own published content and may not be substituted — so a DER that
// already holds the row's curves produces a decided non-PASS (tripOutcome), not
// a quiet pass on a stale register.
func tripSetup(ctx context.Context, d *Driver, params map[string]string, b *tripBinding, mrid string) error {
	pre := oracleTrip(b)(ctx, d.rc)
	params[oraclePreVerdictParam] = string(pre.Verdict)
	params[oraclePreObservedParam] = findingObserved(pre)
	params[tripPublishedParam] = b.describePublished()
	params[tripTargetsParam] = b.describeTargets()
	recordTripTarget(ctx, d, params, b)
	recordProtectiveBoundary(ctx, d, params, tripProtectivePreParam)
	recordCurveDeliveryBaseline(ctx, d, params, 0)
	return publishTripControl(ctx, d, params, b, mrid)
}

// recordTripTarget writes which generation this row resolved to into the
// observation, so the citation phase — which has no live context — can say what
// was measured rather than what the row was built with.
func recordTripTarget(ctx context.Context, d *Driver, params map[string]string, b *tripBinding) {
	uv, err := oracleUnitView(ctx, d.rc, oracleSimName)
	if err != nil {
		params[curveGenParam] = curveGenUnknown
		return
	}
	gen := curveGenerationOf(uv)
	params[curveGenParam] = gen.String()
	if gen == genAmbiguous {
		params[curveGenAmbiguousParam] = describeGeneration(uv)
	}
	fam := invariant.CurveFamily(gen.String())
	var models []string
	for _, c := range b.Curves {
		t := c.resolve(fam)
		if t.NoRegisterHome != "" || t.Model == 0 {
			continue
		}
		label := strconv.FormatUint(uint64(t.Model), 10)
		if t.Sub != invariant.SubCurveNone {
			label += "/" + t.Sub.String()
		}
		models = append(models, label)
	}
	if len(models) > 0 {
		params[curveModelParam] = strings.Join(models, " ")
	}
}

// recordProtectiveBoundary stamps the DER's ride-through enable states into the
// observation under key, for critProtectiveBoundaryHeld's before/after
// comparison.
//
// A read that FAILS records nothing rather than an empty state, and the
// difference is the whole point: an empty canonical string means "the DER
// serves no ride-through bank", which is a real answer, while an absent key
// means "this reading was not taken". The criterion treats them differently and
// would otherwise report a device with no banks and a device it could not read
// identically.
func recordProtectiveBoundary(ctx context.Context, d *Driver, params map[string]string, key string) {
	uv, err := oracleUnitView(ctx, d.rc, oracleSimName)
	if err != nil {
		return
	}
	canonical, _ := protectiveEnables(uv)
	params[key] = canonical
}

// publishTripControl puts a row's whole Figure on the wire as ONE curve-linked
// DERControl and records what the server minted for it.
//
// EVERY CURVE IN ONE REQUEST, which is the shape the procedure prescribes and
// the reason gridsim grew a `curves` array. Publishing them one POST at a time
// would produce four DERControls where BASIC-004 asks for one, and the row
// could never state that the DUT had been offered the combination.
func publishTripControl(ctx context.Context, d *Driver, params map[string]string, b *tripBinding,
	mrid string) error {
	entries := make([]CurveEntry, 0, len(b.Curves))
	for _, c := range b.Curves {
		entries = append(entries, CurveEntry{
			Mode: c.Mode, Points: c.Points, XMult: c.XMult, YMult: c.YMult, YRefType: c.YRefType,
			Description: "certify " + c.Element,
		})
	}
	pub, err := d.PostCurveDetail(ctx, CurveRequest{
		Program: 0, Curves: entries,
		Description: "certify " + strings.Join(b.elements(), "+"),
		// The oracled window, not curveMode's old 180 s: the PostWait oracle can
		// read the DER anywhere out to wait+settle (see oracleWindow), and a
		// control that released under that read would convert a correct device
		// into a false FAIL at the late edge.
		DurationS: oracleWindow.durationS, StartOffset: oracleWindow.startOffsetS, Activate: true,
	})
	if err != nil {
		return err
	}
	hrefs := make([]string, 0, len(pub.Curves))
	for _, c := range pub.Curves {
		hrefs = append(hrefs, c.CurveHref)
	}
	if len(hrefs) > 0 {
		params[tripHrefsParam] = strings.Join(hrefs, " ")
		// curveHrefParam too, so a reader of the bundle finds this row's first
		// curve where every other curve row's is. The LIST is what this row's
		// own criterion reads; this is for the shared readers.
		params[curveHrefParam] = hrefs[0]
	}
	if pub.MRID == "" {
		params[curveMRIDNoteParam] = "the server returned no mRID for the curve-bound control it created, " +
			"so this row's wire criteria fall back to the row's own synthetic mRID (" + mrid + ") and will " +
			"not find it: the correlation is unavailable, not satisfied"
		return nil
	}
	params["mrid"] = pub.MRID
	params[curveMRIDNoteParam] = "the curve-bound control's mRID is the SERVER's (" + pub.MRID + "), not " +
		"this row's synthetic " + mrid + ": gridsim mints it for a POST /admin/curve and ignores any mRID " +
		"the request carries, so every wire criterion on this row binds the minted one"
	return nil
}

// tripHrefsOf recovers the curve hrefs this row published.
func tripHrefsOf(o *Observation) []string {
	if o == nil {
		return nil
	}
	s := o.Param(tripHrefsParam)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// tripOutcome collapses everything the live phase recorded into ONE decided
// verdict — the job curveOutcome does for the curve rows, in the vocabulary of
// a set of ride-through curves.
func tripOutcome(b *tripBinding, o *Observation) Finding {
	post := o.Params[oracleObservedParam]
	pre := o.Params[oraclePreObservedParam]

	if reason := o.Params[oracleUnavailableParam]; reason != "" {
		return Finding{Verdict: certify.Fail, Observed: "the independent southbound oracle could not read " +
			"the DER's own ride-through registers at all: " + reason + " — and an oracle that cannot read " +
			"the DER cannot certify that a ride-through control was executed. This row FAILs on that " +
			"unavailability rather than skipping past it: the southbound read is the ONLY check in this " +
			"suite that can tell a gateway which ADOPTED these curves from one which refused the axes and " +
			"answered the head end anyway"}
	}
	switch verdict := certify.Verdict(o.Params[oracleVerdictParam]); {
	case verdict == "":
		return Finding{Verdict: certify.Fail, Observed: "the live phase left no southbound trip-oracle " +
			"result behind at all — neither a verdict (" + oracleVerdictParam + ") nor a reason it could " +
			"not reach one (" + oracleUnavailableParam + ") is recorded, so the oracle either never ran " +
			"or its result was lost. An unrecorded criterion is not a satisfied one" + deliveryClause(o)}
	case verdict != certify.Pass:
		if post == "" {
			post = "the oracle recorded no observation with its " + string(verdict)
		}
		// The delivery fact rides on every non-PASS, because every non-PASS here
		// rests on what the DER does NOT hold — and an absence is only about the
		// DUT's REFUSAL if the DUT was there to refuse.
		return Finding{Verdict: verdict, Observed: post + deliveryClause(o)}
	}
	moved := fmt.Sprintf("the %d ride-through curve(s) this row published", len(b.Curves))
	switch certify.Verdict(o.Params[oraclePreVerdictParam]) {
	case certify.Fail:
		return Finding{Verdict: certify.Pass, Observed: "the DER did NOT hold this row's content before it " +
			"was published (" + pre + ") and DOES hold it after the DUT's poll cycle (" + post + ") — " +
			moved + " MOVED, so the match is evidence this control was executed, not content an earlier " +
			"run left in the register banks"}
	case certify.Pass:
		return Finding{Verdict: certify.Fail, Observed: "the DER holds " + moved + " (" + post + ") but " +
			"ALREADY held it before this row published anything (" + pre + "). A ride-through row has no " +
			"ladder to depart onto — its content is the content the row is about — so nothing in this " +
			"reading distinguishes curves the DUT fetched and adopted from ones left over from an earlier " +
			"run, and it is not reported as a PASS"}
	default:
		return Finding{Verdict: certify.Warn, Observed: "the DER holds " + moved + " (" + post + "), but " +
			"the pre-publication baseline was not recovered (" + orText(pre, "no reading was recorded") +
			"), so this run cannot show that the adopted content CHANGED. The content is right; that it " +
			"was THIS row's control that put it there is not established"}
	}
}

// critDEREffectViaTripOracle is the southbound criterion, carrying the live
// phase's decided finding into the citation phase. Like every oracled
// criterion in this suite it has NO Skip path.
//
// IT IS ALSO MARKED LoadBearing, and the marker was MISSING here until an
// adversarial gate noticed — which is the exact hole doc.go warns the
// per-criterion no-Skip discipline leaves. doc.go's release-enforcing list
// names the ride-through southbound oracle among the three families, and its
// siblings (critDEREffectViaSouthboundOracle, critDEREffectViaCurveOracle,
// critRefusedAxisNoSouthboundTrace, critDERValueRemainedAcrossTheWindow,
// critDEREffectViaDirectOracle) all carry it; this one did not, so a future
// edit that gave BASIC-004/005's only "did the DER actually do it" criterion a
// Skip path would have produced rows passing on their wire assertions alone
// with nothing in the arithmetic to notice. The omission cannot recur: this
// criterion is now in loadbearing_test.go's releaseEnforcingCriteria, whose
// three tests assert the marker is set, that no marked criterion carries a Skip
// reason, and that the marker reaches the minted assertion.
func critDEREffectViaTripOracle(subject string, b *tripBinding, o *Observation) criterion {
	f := tripOutcome(b, o)
	return criterion{
		Claim: "the DER's own southbound registers hold the " + strconv.Itoa(len(b.Curves)) +
			" ride-through curve(s) " + subject + " carried, adopted and enabled",
		LoadBearing: true,
		How: "an independent read of the DER's raw SunSpec ride-through image (internal/invariant, which " +
			"shares only the register-offset tables with the product and none of its CSIP/derbase " +
			"interpretation), taken BEFORE this row published anything and again after the DUT's poll " +
			"cycle: each bank's adopt handshake, its function enable (Ena), and — per authored curve — the " +
			"breakpoints of the SUB-CURVE that curve names, compared point for point and IN ORDER against " +
			"what the row itself published. " + b.describeTargets() + ". The device sims model curve " +
			"ADOPTION but no trip PHYSICS, so this is a register/adopt-state assertion and deliberately " +
			"not an effect-on-output one: nothing here says what the DER would do at 0.88 pu",
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}

// ── The row ─────────────────────────────────────────────────────────────────

// rideThroughRow is the registration shape register.go's two ride-through
// entries hand back: everything basicInverterControl would need, for an
// apparatus controlMode has no field for.
type rideThroughRow struct {
	binding *tripBinding
	subject string
}

// basicRideThrough builds BASIC-004/005's certify.Check.
//
// It is basicInverterControl's sibling. controlMode carries four apparatus
// fields — Oracle, Curve, Refusal, LegacyCurve — and none of them can express a
// LIST of curves bound into one control, so this row assembles its own spec
// rather than adding a fifth field to a file this change does not own. Every
// criterion and every live-phase helper it uses is the shared one; what is
// local is the assembly.
func basicRideThrough(r rideThroughRow, nonce string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		// Nonced for the same reason basicInverterControl's is — see its doc.
		mrid := withRunNonce("CERT-"+strings.ToUpper(rc.Case.ID), nonce)
		return run(ctx, rc, rideThroughSpec(r.binding, r.subject, mrid))
	}
}

// rideThroughSpec is the spec basicRideThrough runs. Factored out — the same
// shape as inverterControlSpec — so a test can drive Setup and PostWait
// directly against a real Driver without booting the whole certify.Check
// machinery, which needs a live capture window run() cannot fake.
func rideThroughSpec(b *tripBinding, subject, mrid string) spec {
	s := spec{
		Notes: func(o *Observation) string {
			notes := fmt.Sprintf("published ONE DERControl (%s) carrying %s and waited %s for the DUT to "+
				"fetch it", mrid, strings.Join(b.elements(), " + "), o.Waited.Round(rounding))
			f := tripOutcome(b, o)
			return notes + "; the independent southbound oracle says: " + f.Observed
		},
		Criteria: func(o *Observation) []criterion {
			crits := []criterion{critDiscoveryRoot(), critProgramList(0)}
			// ONE criterion per authored element, each bound to THIS row's own
			// mRID. Four criteria rather than one is what makes a partial
			// delivery legible: a DUT that fetched a control carrying the
			// must-trip curves and not the momentary-cessation ones produces two
			// green rows and two red ones, where a single criterion looking for
			// any one element would go green on a quarter of the Figure.
			//
			// Binding the same mRID on all of them is also what establishes they
			// were on ONE control, which is the shape the procedure prescribes:
			// the criterion looks for the element inside the DERControl with
			// that mRID, so four hits are four elements of one document.
			for _, c := range b.Curves {
				crits = append(crits, critDERControlCarriesModeFrom(c.Element,
					"the DUT fetched a DERControl carrying "+subject+" — <"+c.Element+">",
					o.Param("mrid"), nil))
			}
			crits = append(crits, critDefaultDERControl(),
				critTripPublishedTheProcedureValues(subject, b),
				critTripCurvesResolvable(tripHrefsOf(o)),
				critDEREffectViaTripOracle(subject, b, o),
				critProtectiveBoundaryHeld(o),
				critProtectiveBoundaryStructure())
			// The northbound lifecycle, for the same reason the other execution
			// rows carry it (basic.go's inverterControlSpec): a ride-through row
			// graded the four curves southbound and asserted NOTHING about
			// whether the DUT ever told the head end it had received or started
			// the control carrying them.
			//
			// This row publishes through publishTripControl, which posts to
			// gridsim's /admin/curve — the same path whose control now carries
			// responseRequired, so the Started(2) claim grades a question that
			// was actually put rather than reporting "not requested".
			crits = append(crits,
				critResponsePosted(1, "Event received", o.Param("mrid")),
				critResponseStarted(o.Param("mrid")))
			return crits
		},
		// A MEASURED row's verdict does not depend on the capture (IW14-003 —
		// see spec.Verdict): the southbound oracle's decided FAIL would
		// otherwise become a severity-0 SkipAssertion in any run whose capture
		// yielded no session.
		Verdict: func(o *Observation) certify.Verdict {
			if f := tripOutcome(b, o); f.Verdict != certify.Pass {
				return f.Verdict
			}
			// A satisfied oracle declares nothing: the wire criteria decide this
			// row. Declaring PASS here would let a row with NO recovered session
			// pass on the southbound read alone, which is the opposite mistake.
			return ""
		},
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			params["mrid"] = mrid
			return tripSetup(ctx, d, params, b, mrid)
		},
		// The settle poll spends a second poll-cycle window on a row that is not
		// satisfied at once, so the budget arithmetic has to know (IW14-005).
		SettlePoll: true,
		PostWait: func(ctx context.Context, d *Driver, params map[string]string) error {
			// Read the bench's own data plane ONCE and write down whether the DUT
			// came and fetched this row's control. Every verdict rests on what
			// the DER does or does not hold, and an absence is only about the
			// DUT's refusal if the DUT was there to refuse.
			recordCurveDelivery(ctx, d, params, 0)
			judge := oracleTrip(b)
			f := settleOracle(ctx, oracleSettleDeadline(params), func() Finding { return judge(ctx, d.rc) })
			switch {
			case f.Unavailable != "":
				params[oracleUnavailableParam] = f.Unavailable
			default:
				params[oracleVerdictParam] = string(f.Verdict)
				params[oracleObservedParam] = f.Observed
			}
			// The protective boundary AFTER the window, for the before/after
			// comparison. Taken last, so it reflects everything the DUT did
			// during the settle poll and not only what it had done when the
			// oracle first read.
			recordProtectiveBoundary(ctx, d, params, tripProtectivePostParam)
			return nil
		},
		Cleanup: func(ctx context.Context, d *Driver) {
			_ = d.ClearControls(ctx, 0)
			_ = d.ClearCurves(ctx, 0)
		},
	}
	return s
}

// ── The two shipping rows ───────────────────────────────────────────────────

// The mode→bank mappings, stated once so a row and a verdict cannot disagree
// about which registers were read, and stated as claims about the STANDARDS'
// own carriage rather than about either codebase — the same rule the curve
// rows' mappingVoltVar family follows. Model numbers come from the vendored
// SunSpec model JSON (lexa-proto docs/schema/sunspec-models) and the axis
// semantics from each model's own point descriptions.
const (
	mappingTripLV = "IEEE 2030.5's low-voltage ride-through curves are carried by SunSpec model 707 " +
		"(DERTripLV). One curve-SET holds THREE sub-curves — MustTrip, MayTrip, MomCess — each with its " +
		"own ActPt and its own point table, which is why this row's arms name a sub-curve and not just a " +
		"model. Each point is Pt.V (uint16, units \"VNomPct\" — per cent of NOMINAL voltage, scaled by " +
		"V_SF) against Pt.Tms (uint32, units \"Secs\", scaled by Tms_SF). THE POINT NAMED Tms IS IN " +
		"SECONDS: model_707.json says \"Secs\", and a referee that read the name as milliseconds would be " +
		"wrong by a factor of 1000 in the direction that certifies — a 0.16 s trip commanded and 160 s " +
		"held would compare equal. This referee decodes the pair as (seconds, %VNom), which is the order " +
		"IEEE 2030.5's own ride-through DERCurve uses; the REGISTERS store V first"

	mappingTripHV = "IEEE 2030.5's high-voltage ride-through curves are carried by SunSpec model 708 " +
		"(DERTripHV), which is model 707's geometry point for point — the same three sub-curves, the same " +
		"(V VNomPct, Tms Secs) pairs, the same Tms-is-seconds trap — applied to the over-voltage side"

	mappingTripLF = "IEEE 2030.5's low-frequency ride-through curve is carried by SunSpec model 709 " +
		"(DERTripLF). Same three-sub-curve geometry as 707/708, different point shape: Pt.Hz (uint32, " +
		"units \"Hz\", scaled by Hz_SF) against Pt.Tms (uint32, \"Secs\"). The frequency is ABSOLUTE — not " +
		"a deviation from nominal and not a percentage — which is why Figure 5 prescribes no yRefType " +
		"where Figure 4 prescribes %setEffectiveV. Decoded as (seconds, Hz)"

	mappingTripHF = "IEEE 2030.5's high-frequency ride-through curve is carried by SunSpec model 710 " +
		"(DERTripHF), model 709's geometry applied to the over-frequency side"

	mappingTripLVLegacy = "the LEGACY 12x carriage of opModLVRTMustTrip is model 129 (LVRT Must " +
		"Disconnect). Its banks store the pair TIME FIRST — Tms<n> (uint16, \"Secs\", scaled by Tms_SF) " +
		"then V<n> (uint16, \"% VRef\", scaled by V_SF) — which happens to be the same order IEEE 2030.5's " +
		"curve uses, by accident of the model's naming rather than by convention. There is no adopt " +
		"handshake: ActCrv selects the live bank and ModEna bit 0 switches the function on"

	mappingTripHVLegacy = "the LEGACY 12x carriage of opModHVRTMustTrip is model 130 (HVRT Must " +
		"Disconnect), model 129's layout applied to the over-voltage side"

	// The legacy absences. Both are REAL and both are named rather than skipped,
	// on the same rule BASIC-012's missing 7xx freq-watt breakpoint table is
	// named: a row whose southbound half has no home on the bench in front of it
	// must say so where the verdict is read.

	noLegacyMomentaryCessation = "the legacy 12x ride-through models store a SINGLE region per bank. " +
		"Models 129 and 130 are named \"Must Disconnect\" and declare exactly one point table each " +
		"(ActPt, Tms1..Tms20, V1..V20) — there is no MayTrip and no MomCess sub-curve anywhere in the " +
		"legacy set, and no separate legacy model for momentary cessation either. So the " +
		"momentary-cessation half of this row's Figure is SERVED northbound and has nowhere on a legacy " +
		"DER to land. That is a property of the legacy device model, not a gap in this bench, and it is " +
		"stated rather than skipped"

	noLegacyFrequencyRideThrough = "there is NO legacy 12x model for frequency ride-through in the " +
		"carriage this bench and this product share. The legacy curve family lexa-proto decodes is " +
		"126/127/128/129/130/131/132/134/160 (sunspec/legacycurve.go) and the vendored SunSpec model JSON " +
		"directory carries the same set: 129 and 130 are the two ride-through models and both are " +
		"VOLTAGE. SunSpec's own legacy numbering does define frequency ride-through models above 134, and " +
		"neither lexa-proto's decoder nor the vendored schema carries them — so on a legacy DER this " +
		"row's ENTIRE southbound half is served and unassertable, and this run says so instead of " +
		"reporting a device finding for a carriage nobody implements"
)

// rideThroughRegistration is one ride-through row as the registry takes it.
type rideThroughRegistration struct {
	id    string
	order int
	row   rideThroughRow
}

// registerRideThroughControls binds BASIC-004 and BASIC-005.
func registerRideThroughControls(reg *certify.Registry, nonce string) {
	for _, r := range rideThroughRows() {
		reg.Register(uid(r.id), Suite, basicRideThrough(r.row, nonce),
			certify.WithRequires(needGridSim...), certify.WithOrder(r.order))
	}
}

// rideThroughRows is the two rows' one definition, factored out of the
// registration for the reason inverterControlRows is: a test must be able to
// drive the SHIPPING row — its real curves, its real oracle — rather than a
// copy of its literals that can silently drift from it (IW15-004/IW15-008).
func rideThroughRows() []rideThroughRegistration {
	return []rideThroughRegistration{
		{"BASIC-004", 50, rideThroughRow{
			subject: "the low/high voltage ride-through settings",
			binding: &tripBinding{
				// THE ORDER IS THE FIGURE'S FUNCTION TABLE, not its settings
				// table, and the two differ. The catalog's Function-mapping line
				// lists "opModLVRTMustTrip, opModLVRTMomentaryCessation,
				// opModHVRTMustTrip, opModHVRTMomentaryCessation" — low then high,
				// must-trip then momentary-cessation — while the settings rows are
				// printed high-voltage first. Nothing depends on the order (each
				// curve hangs off its own DERControlBase field), so this follows
				// the ordering that matches the test's own title.
				Curves: []tripCurve{
					{
						Element: "opModLVRTMustTrip",
						Mode:    "lvrt_must_trip",
						// CSIP CTP v1.3 BASIC-004, Figure 4 Low/High Voltage Trip
						// Settings, Test Values: SEVEN breakpoints at 10^-2 on
						// both axes — 1.50 s at 0.00 %V, 1.50 s at 50.00 %V,
						// 12.00 s at 50.00 %V, 12.00 s at 70.00 %V, 22.00 s at
						// 70.00 %V, 22.00 s at 88.00 %V, 100.00 s at 88.00 %V.
						//
						// SEVEN IS WHY THE SIM'S NPt MOVED. Encode707Set refuses a
						// curve with more points than the device's declared NPt,
						// and the bench sim declared four — so until
						// sim/southbound/trip1547.go raised it to eight, this
						// bench could not hold the certification procedure's own
						// curve and the row would have failed on the fixture's
						// geometry while reporting a device finding.
						Points: []CurvePoint{
							{X: 150, Y: 0}, {X: 150, Y: 5000}, {X: 1200, Y: 5000}, {X: 1200, Y: 7000},
							{X: 2200, Y: 7000}, {X: 2200, Y: 8800}, {X: 10000, Y: 8800},
						},
						XMult: -2, YMult: -2, YRefType: derUnitRefSetEffectiveV,
						Model7xx: sunspec.ModelDERTripLV, Sub7xx: invariant.SubCurveMustTrip,
						Mapping7xx:    mappingTripLV,
						ModelLegacy:   sunspec.ModelLVRTLegacy,
						MappingLegacy: mappingTripLVLegacy,
					},
					{
						// THE 2030.5 SPELLING. Figure 4's settings table prints
						// this row as "opModLVRTMustTripMomentaryCessation"; the
						// same Figure's Function table, IEEE Std 2030.5-2018
						// p.250, and csipmodel's own element all print
						// "opModLVRTMomentaryCessation", and the catalog's `notes`
						// field records that its two tables disagree. A
						// DERControlBase has no child by the longer name, so
						// serving one would produce a document no conformant DUT
						// could parse.
						Element: "opModLVRTMomentaryCessation",
						Mode:    "lvrt_momentary_cessation",
						// Figure 4 Test Values: 0.00 s at 60.00 %V, 1.50 s at
						// 60.00 %V. (Its Default column is 50.00 %V, so this row's
						// values are a real test condition and not the device's
						// resting state.)
						Points: []CurvePoint{{X: 0, Y: 6000}, {X: 150, Y: 6000}},
						XMult:  -2, YMult: -2, YRefType: derUnitRefSetEffectiveV,
						Model7xx: sunspec.ModelDERTripLV, Sub7xx: invariant.SubCurveMomCess,
						Mapping7xx:           mappingTripLV,
						NoRegisterHomeLegacy: noLegacyMomentaryCessation,
					},
					{
						Element: "opModHVRTMustTrip",
						Mode:    "hvrt_must_trip",
						// Figure 4 Test Values: 0.16 s at 120.00 %V, 0.16 s at
						// 110.00 %V, 12.00 s at 110.00 %V, 12.00 s at 100.00 %V,
						// 100.00 s at 100.00 %V.
						Points: []CurvePoint{
							{X: 16, Y: 12000}, {X: 16, Y: 11000}, {X: 1200, Y: 11000},
							{X: 1200, Y: 10000}, {X: 10000, Y: 10000},
						},
						XMult: -2, YMult: -2, YRefType: derUnitRefSetEffectiveV,
						Model7xx: sunspec.ModelDERTripHV, Sub7xx: invariant.SubCurveMustTrip,
						Mapping7xx:    mappingTripHV,
						ModelLegacy:   sunspec.ModelHVRTLegacy,
						MappingLegacy: mappingTripHVLegacy,
					},
					{
						Element: "opModHVRTMomentaryCessation",
						Mode:    "hvrt_momentary_cessation",
						// Figure 4 Test Values: 0.00 s at 100.00 %V, 12.00 s at
						// 100.00 %V.
						Points: []CurvePoint{{X: 0, Y: 10000}, {X: 1200, Y: 10000}},
						XMult:  -2, YMult: -2, YRefType: derUnitRefSetEffectiveV,
						Model7xx: sunspec.ModelDERTripHV, Sub7xx: invariant.SubCurveMomCess,
						Mapping7xx:           mappingTripHV,
						NoRegisterHomeLegacy: noLegacyMomentaryCessation,
					},
				},
				Prescribed: "CSIP CTP v1.3 BASIC-004, Figure 4 Low/High Voltage Trip Settings, Test " +
					"Values column — all four curves on ONE DERControl, which is what the procedure's " +
					"own Setup step 5 requires (\"a DERControl instance with Low/High Voltage Ride " +
					"Through values in Figure 4\"). The two momentary-cessation curves are served under " +
					"IEEE 2030.5's element names (opModLVRTMomentaryCessation / " +
					"opModHVRTMomentaryCessation) and not under the longer names the Figure's settings " +
					"table prints, because the same Figure's Function table, the standard (2018 p.249-250) " +
					"and the DERControlBase schema all use the shorter ones — the catalog's own notes " +
					"record the document's inconsistency. curveType is not restated by this bench: " +
					"gridsim emits lexa-proto/csipmodel's constant for each mode, and Figure 4's printed " +
					"{4, 5, 9, 10} are exactly IEEE Std 2030.5-2018 p.254's codes for the four elements " +
					"this row publishes",
				// NO GAPS. Figure 4's settings are four CurveData rows, curveType,
				// xMultiplier, yMultiplier and yRefType, and this bench places
				// every one of them on the wire. yRefType is authored and has no
				// southbound register home — see yRefTypeNoTripRegister — which is
				// a disclosure carried on every verdict and NOT a gap: the bench
				// sent exactly what the procedure prescribes.
			},
		}},
		{"BASIC-005", 51, rideThroughRow{
			subject: "the low/high frequency ride-through settings",
			binding: &tripBinding{
				Curves: []tripCurve{
					{
						Element: "opModLFRTMustTrip",
						Mode:    "lfrt_must_trip",
						// CSIP CTP v1.3 BASIC-005, Figure 5 Low/High Frequency
						// Trip Settings, Test Values: 0.16 s at 53.00 Hz, 0.16 s
						// at 56.90 Hz, 270.00 s at 56.90 Hz, 270.00 s at 58.50 Hz,
						// 400.00 s at 58.50 Hz — x and y both at 10^-2, and the y
						// axis is ABSOLUTE frequency.
						//
						// The row differs from its own Default column in exactly
						// one place (270.00 s where the default is 300.00 s), so
						// it is a real test condition.
						Points: []CurvePoint{
							{X: 16, Y: 5300}, {X: 16, Y: 5690}, {X: 27000, Y: 5690},
							{X: 27000, Y: 5850}, {X: 40000, Y: 5850},
						},
						// yRefType 0 — DERUnitRefType's own "N/A". Figure 5
						// prescribes none, and that is correct rather than an
						// omission: a frequency is an absolute quantity and not a
						// percentage of anything, so there is no reference for the
						// Figure to name. Publishing Figure 4's %setEffectiveV
						// here would be inventing a reference for an axis that has
						// none.
						XMult: -2, YMult: -2, YRefType: derUnitRefNA,
						Model7xx: sunspec.ModelDERTripLF, Sub7xx: invariant.SubCurveMustTrip,
						Mapping7xx:           mappingTripLF,
						NoRegisterHomeLegacy: noLegacyFrequencyRideThrough,
					},
					{
						Element: "opModHFRTMustTrip",
						Mode:    "hfrt_must_trip",
						// Figure 5 Test Values: 0.16 s at 65.00 Hz, 0.16 s at
						// 61.00 Hz, 280.00 s at 61.00 Hz, 280.00 s at 60.50 Hz,
						// 400.00 s at 60.50 Hz.
						//
						// The catalog's notes flag a LINE-WRAP AMBIGUITY in this
						// Figure's DEFAULT column — "(16,6400),(16,6200),(30000,
						// 6200),(30000,6050), (40000,6050)" — and none in its Test
						// Values column, which is the column a run uses. The
						// values below are the Test Values verbatim; the ambiguity
						// is recorded here so a future reader does not "correct"
						// them against the defaults.
						Points: []CurvePoint{
							{X: 16, Y: 6500}, {X: 16, Y: 6100}, {X: 28000, Y: 6100},
							{X: 28000, Y: 6050}, {X: 40000, Y: 6050},
						},
						XMult: -2, YMult: -2, YRefType: derUnitRefNA,
						Model7xx: sunspec.ModelDERTripHF, Sub7xx: invariant.SubCurveMustTrip,
						Mapping7xx:           mappingTripHF,
						NoRegisterHomeLegacy: noLegacyFrequencyRideThrough,
					},
				},
				Prescribed: "CSIP CTP v1.3 BASIC-005, Figure 5 Low/High Frequency Trip Settings, Test " +
					"Values column — both curves on ONE DERControl, per the procedure's Setup step 5c " +
					"(\"a DERControl instance with Low/High Frequency Ride Through values in Figure 5\"). " +
					"Figure 5 prescribes NO yRefType and NO momentary-cessation curve, and this row " +
					"authors neither: a frequency curve's y axis is absolute hertz and has no percentage " +
					"reference to name, and IEEE Std 2030.5-2018 p.254 assigns momentary-cessation " +
					"curveType codes to the two VOLTAGE curves only (4 and 9) and none to a frequency " +
					"one. curveType is not restated by this bench: gridsim emits csipmodel's constant per " +
					"mode, and Figure 5's printed {2, 7} are exactly p.254's codes for opModHFRTMustTrip " +
					"and opModLFRTMustTrip",
				// NO GAPS: Figure 5's settings are two CurveData rows, curveType
				// and the two multipliers, and this bench sends all of them.
			},
		}},
	}
}
