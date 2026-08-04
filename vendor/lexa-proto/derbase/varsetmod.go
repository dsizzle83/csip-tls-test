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
// VarAvailPct is deliberately NOT gated. Its base is instantaneous headroom
// the device computes from its own operating point — there is no register to
// consult and no claim the spec gives a device any way to make, so gating on
// one would be denial by construction, which is the same reasoning that leaves
// opModEnergize and opModConnect on model presence.
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
		point, setting, rating := "VarMaxInj", b.Cap.VarMaxInj, b.Cap.VarMaxInjRtg
		if pct < 0 {
			point, setting, rating = "VarMaxAbs", b.Cap.VarMaxAbs, b.Cap.VarMaxAbsRtg
		}
		if !b.HasCap || (!usableBase(setting) && !usableBase(rating)) {
			return &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
				"refType %%setMaxVar resolves against %s, and the device declares no usable "+
					"reactive nameplate on that side (%s=%g, %sRtg=%g)",
				point, point, setting, point, rating)}
		}
	}
	return nil
}

// usableBase reports whether a 702 base quantity is a number a percentage can
// be taken of. NaN is the not-implemented/unusable-scale-factor case; zero and
// negative are a declared incapacity, not a base (maxRatingBound's reasoning).
func usableBase(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0
}
