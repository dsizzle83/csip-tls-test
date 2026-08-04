package derbase

import (
	"fmt"
	"math"

	model "lexa-proto/csipmodel"
	"lexa-proto/sunspec"
)

// opModFixedVar's refType → SunSpec 704 VarSetMod (DERBASE-VAR-REFTYPE).
//
// ── What was wrong ───────────────────────────────────────────────────────────
//
// csipmodel parsed FixedVar.RefType and nothing read it. SetConstantVar wrote
// VarSetMod=VarMaxPct unconditionally, so EVERY DERUnitRefType resolved
// against the same SunSpec base. On the differential run's balanced-60kW
// device (WMax 60 kW, VarMaxInj 26.4 kvar), opModFixedVar{refType=1,
// value=8000} put VarSetPct=80 % of VarMaxInj = 21 120 var on the wire where
// %setMaxW asks for 80 % of WMax = 48 000 var; on a 2 kvar machine the same
// document was a 30× error. Whatever the codes mean they cannot all mean the
// same thing, so one hardcoded base is wrong for at least two of them.
//
// ── The rule ─────────────────────────────────────────────────────────────────
//
// A percentage is applied ONLY when its base is named AND the device has a
// register that expresses that base. Three outcomes, and only one of them
// writes:
//
//	refType          VarSetMod         written?  why
//	───────────────  ────────────────  ────────  ──────────────────────────────
//	1 %setMaxW       WMaxPct    (0)    yes       percent of the active nameplate
//	2 %setMaxVar     VarMaxPct  (1)    yes       percent of the reactive nameplate
//	3 %statVarAvail  VarAvailPct(2)    yes       percent of present headroom
//	0 N/A            —                 REFUSE    ErrInvalidControl: the document
//	                                             named no base, so no party can
//	                                             state what the setpoint commands
//	4 %setEffectiveV —                 REFUSE    ErrUnsupportedControl: 704's
//	5 %setMaxChaRteW —                 REFUSE    VarSetMod enum has no code for
//	6 %setMaxDisRteW —                 REFUSE    these bases, so the device has
//	7 %statWAvail    —                 REFUSE    no way to express them
//	≥8               —                 REFUSE    ErrInvalidControl: not a code
//	                                             the enumeration defines
//
// The 0-vs-4..7 split is deliberate and is the split the gateway routes on.
// refType=0 is a MALFORMED REQUEST — the head end can fix it by naming a base.
// refType=4..7 are well-formed requests this DEVICE CLASS cannot carry out —
// SunSpec 704 defines VarSetMod ∈ {WMaxPct, VarMaxPct, VarAvailPct, VAMaxPct,
// Vars} and none of those is a percent of voltage, of a charge rate or of
// available watts. That is CannotComply, and no firmware update to this
// device makes it otherwise.
//
// VAMaxPct (3) and Vars (4) are reachable by no refType: 2030.5 has no
// %setMaxVA code, and Vars is an absolute quantity while opModFixedVar is
// always a percentage. They are deliberately not in the table — mapping a
// refType onto a base it did not name is the defect this file closes.
//
// ── The second question ──────────────────────────────────────────────────────
//
// Resolving the base says WHICH quantity the percentage is a percentage of. It
// does not say whether the var quantity that resolution produces is one the
// machine can make, and on %setMaxW those answers routinely differ — see
// checkVarWithinReactiveCapability, which is the other half of this file.
func varSetModForRefType(axis string, refType uint8) (uint16, string, error) {
	switch refType {
	case model.RefTypeSetMaxW:
		return sunspec.M704_VarSetMod_WMaxPct, "WMaxPct", nil
	case model.RefTypeSetMaxVar:
		return sunspec.M704_VarSetMod_VarMaxPct, "VarMaxPct", nil
	case model.RefTypeStatVarAvail:
		return sunspec.M704_VarSetMod_VarAvailPct, "VarAvailPct", nil
	case model.RefTypeNA:
		return 0, "", &InvalidControlError{Axis: axis, Reason: "refType=0 (N/A): the document " +
			"nominated no rating, so the percentage names no physical quantity — a setpoint no " +
			"party can state the meaning of is refused, never applied against a guessed base"}
	case model.RefTypeSetEffectiveV, model.RefTypeSetMaxChargeRateW,
		model.RefTypeSetMaxDischargeRateW, model.RefTypeStatWAvail:
		return 0, "", &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
			"refType=%d names a base the device cannot express: SunSpec M704 VarSetMod has codes "+
				"only for %%setMaxW, %%setMaxVar and %%statVarAvail, so there is no register on "+
				"this device class that resolves the percentage", refType)}
	}
	return 0, "", &InvalidControlError{Axis: axis, Reason: fmt.Sprintf(
		"refType=%d is not a value the DERUnitRefType enumeration defines", refType)}
}

// requireVarBase is the deny-by-default half of the mapping: a VarSetMod the
// device has no BASE for is refused, the same way an axis with no CtrlModes
// bit is (capability.go).
//
// The base is a quantity the device publishes in model 702, and the device
// resolves the percentage against it internally — so if it never published
// one, "80 %" is as uninterpretable as refType=0 was, and applying it would be
// the same defect one level down. Both the SETTING and the RATING are
// accepted: 702 carries VarMaxInj/VarMaxAbs as configurable settings and
// VarMaxInjRtg/VarMaxAbsRtg as nameplate ratings, and a device that declares
// either has declared the base.
//
// VarAvailPct is deliberately NOT gated HERE. Its base is instantaneous
// headroom the device computes from its own operating point — there is no
// register to consult and no claim the spec gives a device any way to make, so
// gating on one would be denial by construction, which is the same reasoning
// that leaves opModEnergize and opModConnect on model presence. That is a
// statement about EXISTENCE, not about magnitude: the reactive nameplate is
// still an upper bound on how large that headroom can be, and
// checkVarWithinReactiveCapability applies it.
//
// pct carries the sign of the request because the reactive nameplate is
// two-sided: injecting resolves against VarMaxInj, absorbing against
// VarMaxAbs. A request of exactly zero var needs no base — zero is zero under
// every one of them — so it is not gated.
func (b *Base) requireVarBase(axis string, mod uint16, pct float64) error {
	switch mod {
	case sunspec.M704_VarSetMod_WMaxPct:
		if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
			return &UnsupportedControlError{Axis: axis, Reason: "refType %setMaxW resolves against " +
				"the active-power nameplate, and the device publishes no usable WMax"}
		}
	case sunspec.M704_VarSetMod_VarMaxPct:
		if pct == 0 {
			return nil
		}
		point, setting, rating := reactiveSide(b.Cap, pct)
		if !b.HasCap || (!usableBase(setting) && !usableBase(rating)) {
			return &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
				"refType %%setMaxVar resolves against %s, and the device declares no usable "+
					"reactive nameplate on that side (%s=%g, %sRtg=%g)",
				point, point, setting, point, rating)}
		}
	}
	return nil
}

// reactiveSide names the two model-702 points that govern the sign of a
// commanded reactive quantity, and returns both readings of that side. The
// reactive nameplate is TWO-SIDED — a machine may be rated to absorb more than
// it injects, or the reverse — so the sign of the request selects the side
// before any magnitude is compared. It is a free function over Capacity so
// that the base resolver and the capability bound below cannot pick different
// points for the same request.
func reactiveSide(c sunspec.Capacity, pct float64) (point string, setting, rating float64) {
	if pct < 0 {
		return "VarMaxAbs", c.VarMaxAbs, c.VarMaxAbsRtg
	}
	return "VarMaxInj", c.VarMaxInj, c.VarMaxInjRtg
}

// reactiveCapability reports the largest reactive magnitude the device has
// DECLARED it can produce on the side pct commands, and the 702 point that
// declaration came from. ok=false is honest unknown — the device published
// neither reading on that side, so there is nothing to exceed.
//
// The SETTING wins over the RATING when both are published: 702 carries
// VarMaxInj/VarMaxAbs as the limits in force on the device and
// VarMaxInjRtg/VarMaxAbsRtg as what the hardware could do if it were not
// configured otherwise, and a control is answered by the machine as
// configured. The order matters for a second reason: this must be the SAME
// quantity requireVarBase resolves %setMaxVar against, or a %setMaxVar request
// at 100 % could be refused for exceeding a bound read off a different point —
// see commandedVar.
func (b *Base) reactiveCapability(pct float64) (point string, limit float64, ok bool) {
	if !b.HasCap {
		return "", 0, false
	}
	point, setting, rating := reactiveSide(b.Cap, pct)
	switch {
	case usableBase(setting):
		return point, setting, true
	case usableBase(rating):
		return point + "Rtg", rating, true
	}
	return "", 0, false
}

// commandedVar resolves what an opModFixedVar percentage actually COMMANDS, in
// var, once the device applies it to the base mod names. ok=false means the
// base is not one this package can resolve, so no magnitude claim is made.
//
// This is where the refType asymmetry bites, and it is the whole reason the
// check above it exists: the RESULT is reactive power under every base, but
// %setMaxW takes its percentage of the ACTIVE nameplate. A machine's reactive
// rating is a fraction of its watt rating on every product you can buy, so a
// large enough %setMaxW percentage names a var quantity the machine is not
// built to make — 80 % of a 60 kW nameplate is 48 kvar on a 26.4 kvar machine
// and on a 2 kvar one alike.
//
// %statVarAvail (refType=3) is resolved here TOO, against the reactive
// nameplate, and that is a decision worth stating rather than an oversight.
// Its true base is instantaneous headroom the device computes from its own
// operating point and never publishes, so this package cannot know it — but it
// does know a bound on it: available reactive power is the part of the rated
// reactive capability not already in use, so VarAval <= the reactive
// nameplate, always, on any device where the phrase means anything. Resolving
// refType=3 against the nameplate therefore yields an UPPER bound on the
// commanded quantity, which is exactly the sanity bound wanted here. Its
// consequence is that refType=3 can never breach the check for |pct| <= 100 —
// a percentage of a quantity cannot exceed that quantity — and that is the
// correct outcome, not dead code: it says a conformant %statVarAvail request
// is never refused on nameplate grounds, while leaving the bound in place to
// catch a base that is ever widened past the rating.
//
// The multiplication is ordered pct*base BEFORE the divide by 100 so that a
// request sitting exactly on its own bound (44 % of a 60 kW nameplate is
// 26 400 var to the last digit) divides exactly, instead of landing a rounding
// step above the rating and being refused for arithmetic.
func (b *Base) commandedVar(mod uint16, pct float64) (float64, bool) {
	switch mod {
	case sunspec.M704_VarSetMod_WMaxPct:
		if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
			return 0, false
		}
		return pct * b.Wmax / 100, true
	case sunspec.M704_VarSetMod_VarMaxPct, sunspec.M704_VarSetMod_VarAvailPct:
		_, limit, ok := b.reactiveCapability(pct)
		if !ok {
			return 0, false
		}
		return pct * limit / 100, true
	}
	return 0, false
}

// checkVarWithinReactiveCapability refuses a reactive setpoint whose resolved
// magnitude exceeds what the device declared it can produce on the commanded
// side (DERBASE-VAR-OVERRATED, DIFF-CTL-001/002).
//
// Mapping refType→VarSetMod (above) made the device resolve the percentage
// against the base the DOCUMENT named. It did not ask whether the quantity
// that resolution produces is one the machine can make; those are independent
// questions and only this one is about physics. opModFixedW beyond the
// nameplate already refuses (DERBASE-SILENT-CLAMP); opModFixedVar beyond the
// REACTIVE nameplate applied, and 80 % of WMax on a 2 kvar machine is a 24x
// overcommand of the reactive rating.
//
// ── The asymmetry, stated here because the two rules live apart ──────────────
//
// A CEILING above the nameplate CLAMPS and is satisfied: "do not exceed
// 200 kW" is in force, unbroken, on a machine that cannot reach 60 kW — a
// bound wider than the device is met exactly by the device, and no quantity
// was substituted (SetWMaxLimPctW). A COMMANDED quantity beyond capability
// REFUSES: "produce 48 kvar" and "produce 26.4 kvar" are different commands,
// and answering the first with the second leaves the head end holding a model
// of the fleet that is wrong with nothing on either side holding the truth.
// That is CannotComply, which is what SetpointRangeError renders.
//
// An undeclared reactive nameplate imposes NO bound — honest unknown, the same
// reading checkSetpointWithinNameplate gives an unknown WMax. A device that
// declared nothing has declared nothing to exceed.
func (b *Base) checkVarWithinReactiveCapability(axis string, mod uint16, pct float64) error {
	commanded, known := b.commandedVar(mod, pct)
	if !known {
		return nil
	}
	point, limit, ok := b.reactiveCapability(pct)
	if !ok || math.Abs(commanded) <= limit {
		return nil
	}
	achievable := limit
	if pct < 0 {
		achievable = -limit
	}
	return &SetpointRangeError{Axis: axis, Point: "M704 VarSetPct", Commanded: commanded,
		Achievable: achievable, Bound: point + " reactive nameplate (var)"}
}

// usableBase reports whether a 702 base quantity is a number a percentage can
// be taken of. NaN is the not-implemented/unusable-scale-factor case; zero and
// negative are a declared incapacity, not a base (maxRatingBound's reasoning).
func usableBase(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0
}
