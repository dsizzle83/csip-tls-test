package diff

// csipref.go is the REFEREE for the control differential: this bench's own
// reading of what an IEEE 2030.5 / CSIP DERControlBase asks a DER to do,
// expressed in the DER's own physical units.
//
// It is written from the standard, not from lexa-proto/derbase, and it must
// never be reconciled with it. internal/csipref/CLAUDE.md states that rule for
// the walker and the scheduler; this file is the same rule applied to the
// control-application half, which had no referee until now. If this file is
// ever "fixed" to agree with the product, the ctl family stops being able to
// find anything.
//
// # What it deliberately does NOT re-decide
//
// The wire TYPES come from lexa-proto/csipmodel, which both sides share. A
// DERControlBase field is spelled the same for both readers. The referee differs
// on three things, and those three are where the defect class lives:
//
//  1. WHAT THE FIELD MEANS. opModFixedVar carries a refType that selects which
//     rating its percentage is a percentage OF. A reader that drops refType is
//     not making a rounding error; it is answering a different question.
//
//  2. WHAT KIND OF THING IT IS. A limit is not a setpoint. "Do not import more
//     than 5 kW" and "import 5 kW" are different instructions, and on a battery
//     that was idle they differ by 5 kW of real power flow. [Kind] carries that
//     distinction through to the comparison so it cannot be lost in a magnitude
//     check that both sides pass.
//
//  3. WHAT HAPPENS WHEN SEVERAL ARRIVE AT ONCE. A DERControlBase may carry
//     several limits together. Limits are CONJUNCTIVE — each one must hold — so
//     the binding limit is the narrowest, and a reader that takes the first one
//     it finds has not implemented a limit, it has implemented a preference.
//     [Intents] therefore reduces a set of ceilings to their minimum and records
//     which ones it reduced, so a differential can ask whether the product's
//     single applied number is the binding one.
//
// # The reference bases
//
// opModFixedVar.refType is an IEEE 2030.5 DERUnitRefType. The referee reads it
// as: 1 = %setMaxW, 2 = %setMaxVar, 3 = %statVarAvail, 0 = N/A (no base
// nominated, so nothing is resolvable). That reading is stated here in the open
// so a reviewer with the standard in front of them can check it — and note that
// the ctl family's principal finding does not depend on it. Whatever the three
// codes mean, they cannot all mean the same thing, so a client that writes the
// same SunSpec reference base for every one of them is wrong for at least two
// of the three.

import (
	"fmt"
	"math"

	"csip-tls-test/internal/invariant"
	model "lexa-proto/csipmodel"
)

// Kind is what a control instruction IS, as distinct from what number it
// carries. The differential compares kind as well as magnitude because the two
// failures look identical in a value check and could not be more different on a
// battery.
type Kind string

// The kinds a DERControlBase mode can be.
const (
	// KindSetpoint — the device shall produce this value.
	KindSetpoint Kind = "setpoint"
	// KindCeiling — the device shall not EXCEED this value. Conjunctive with
	// every other ceiling in force.
	KindCeiling Kind = "ceiling"
	// KindPowerFactor — a displacement power factor with an excitation sense.
	KindPowerFactor Kind = "power-factor"
	// KindBoolean — connect / energize.
	KindBoolean Kind = "boolean"
)

// DERUnitRefType values, as this referee reads IEEE 2030.5. Named rather than
// inlined so the reading is greppable and reviewable.
const (
	RefTypeNA              uint8 = 0
	RefTypePctSetMaxW      uint8 = 1
	RefTypePctSetMaxVar    uint8 = 2
	RefTypePctStatVarAvail uint8 = 3
)

// Intent is one physical instruction the referee reads out of a DERControlBase.
type Intent struct {
	// Mode is the CSIP element name, e.g. "opModFixedVar".
	Mode string
	Kind Kind
	// Want is the instruction in the DER's own physical units, resolved
	// against the DER's own nameplate and present operating point.
	Want invariant.Quantity
	// Ref is the rating the document's percentage was taken against, when it
	// was a percentage. Recorded because "80 % of WHAT" is the question the
	// whole family exists to ask.
	Ref invariant.RefBase
	// Raw is the number as the document carried it, before resolution.
	Raw invariant.Quantity
	// BaseUsed names the 702 point the referee resolved the percentage
	// against, e.g. "WMax" or "VarAvail capped by VarMaxInjRtg".
	BaseUsed string
	// Unresolved, when set, says why this intent could not be turned into a
	// physical quantity. An unresolved intent is a SKIP with a reason, never a
	// guess.
	Unresolved string
	// SupersededBy names the other mode that bound tighter, for a ceiling that
	// was reduced away. The reduced intent is still returned, because "the
	// document also said this and the product ignored it" is the finding.
	SupersededBy string
	// Binding is false for a ceiling that a tighter one superseded.
	Binding bool
}

// String renders an intent for a report.
func (i Intent) String() string {
	if i.Unresolved != "" {
		return fmt.Sprintf("%s (%s): unresolved — %s", i.Mode, i.Kind, i.Unresolved)
	}
	base := ""
	if i.Ref != invariant.RefNone {
		name := i.BaseUsed
		if name == "" {
			name = string(i.Ref)
		}
		base = fmt.Sprintf(" [%s of %s]", i.Raw, name)
	}
	return fmt.Sprintf("%s (%s) = %s%s", i.Mode, i.Kind, i.Want, base)
}

// Intents reads a DERControlBase into physical instructions against a specific
// device's nameplate and present measurement.
//
// n and meas come from the DEVICE's own 702/701, never from the gateway's
// report of the device: a percentage resolved against the gateway's idea of the
// nameplate would agree with the gateway by construction.
func Intents(ctrl model.DERControlBase, n invariant.Nameplate, meas invariant.Measurement) []Intent {
	var out []Intent

	if ctrl.OpModEnergize != nil {
		out = append(out, Intent{Mode: "opModEnergize", Kind: KindBoolean, Binding: true,
			Raw:  invariant.Q(boolVal(*ctrl.OpModEnergize), invariant.UnitNone),
			Want: invariant.Q(boolVal(*ctrl.OpModEnergize), invariant.UnitNone)})
	}
	if ctrl.OpModConnect != nil {
		out = append(out, Intent{Mode: "opModConnect", Kind: KindBoolean, Binding: true,
			Raw:  invariant.Q(boolVal(*ctrl.OpModConnect), invariant.UnitNone),
			Want: invariant.Q(boolVal(*ctrl.OpModConnect), invariant.UnitNone)})
	}

	if pf := ctrl.OpModFixedPFInjectW; pf != nil {
		out = append(out, pfIntent("opModFixedPFInjectW", pf))
	}
	if pf := ctrl.OpModFixedPFAbsorbW; pf != nil {
		out = append(out, pfIntent("opModFixedPFAbsorbW", pf))
	}

	if fv := ctrl.OpModFixedVar; fv != nil {
		out = append(out, fixedVarIntent(*fv, n, meas))
	}

	if ctrl.OpModFixedW != nil {
		// opModFixedW is a SETPOINT: the device is told to produce this much
		// active power, not merely permitted to.
		w := activePowerWatts(ctrl.OpModFixedW)
		out = append(out, Intent{Mode: "opModFixedW", Kind: KindSetpoint, Binding: true,
			Raw: w, Want: w})
	}

	// Export / generation / maximum ceilings. Each is an independent upper
	// bound on active power, so all of them hold at once and the binding one is
	// the smallest. Reducing them here — rather than picking one — is the
	// referee's whole disagreement with a first-non-nil reader.
	out = append(out, ceilingIntents(invariant.UnitWatt, 1, []namedPower{
		{"opModExpLimW", ctrl.OpModExpLimW},
		{"opModMaxLimW", ctrl.OpModMaxLimW},
		{"opModGenLimW", ctrl.OpModGenLimW},
	})...)

	// Import / load ceilings. Same conjunctive reduction; the sign convention
	// is this bench's usual one (+ export / discharge, − import / charge), so
	// an import ceiling is a bound on the MAGNITUDE of a negative flow and is
	// carried as a negative quantity.
	out = append(out, ceilingIntents(invariant.UnitWatt, -1, []namedPower{
		{"opModImpLimW", ctrl.OpModImpLimW},
		{"opModLoadLimW", ctrl.OpModLoadLimW},
	})...)

	return out
}

type namedPower struct {
	mode string
	ap   *model.ActivePower
}

// ceilingIntents reduces a set of simultaneously-commanded ceilings to their
// binding minimum, marking the others superseded but keeping them, because a
// product that applied a non-binding one has demonstrably discarded a limit and
// the report needs to name which.
func ceilingIntents(unit invariant.Unit, sign float64, ps []namedPower) []Intent {
	var present []Intent
	for _, p := range ps {
		if p.ap == nil {
			continue
		}
		q := activePowerWatts(p.ap)
		q.Val = math.Abs(q.Val) * sign
		present = append(present, Intent{Mode: p.mode, Kind: KindCeiling, Raw: q, Want: q})
	}
	if len(present) == 0 {
		return nil
	}
	// The binding ceiling is the one with the smallest magnitude: it is the
	// bound that is reached first.
	bind := 0
	for i := range present {
		if math.Abs(present[i].Want.Val) < math.Abs(present[bind].Want.Val) {
			bind = i
		}
	}
	for i := range present {
		if i == bind {
			present[i].Binding = true
			continue
		}
		present[i].SupersededBy = present[bind].Mode
	}
	return present
}

// fixedVarIntent resolves opModFixedVar into vars against the base its refType
// names. This is the referee's most consequential function and the one the ctl
// family's headline finding comes out of.
func fixedVarIntent(fv model.FixedVar, n invariant.Nameplate, meas invariant.Measurement) Intent {
	// SignedPerCent is hundredths of a percent (5000 = 50.00 %).
	pct := float64(fv.Value.Value) / 100.0
	in := Intent{
		Mode:    "opModFixedVar",
		Kind:    KindSetpoint,
		Raw:     invariant.Q(pct, invariant.UnitPercent),
		Binding: true,
	}

	var ref invariant.RefBase
	switch fv.RefType {
	case RefTypePctSetMaxW:
		ref = invariant.RefWMax
	case RefTypePctSetMaxVar:
		// setMaxVar is directional on a SunSpec device: injection and
		// absorption have separate ratings, and the sign of the setpoint says
		// which one applies.
		if pct < 0 {
			ref = invariant.RefVarMaxAbs
		} else {
			ref = invariant.RefVarMaxInj
		}
	case RefTypePctStatVarAvail:
		ref = invariant.RefVarAvail
	case RefTypeNA:
		in.Unresolved = "opModFixedVar carries refType 0 (N/A): the document nominated no rating for its " +
			"percentage to be a percentage of, so there is nothing to resolve it against"
		return in
	default:
		in.Unresolved = fmt.Sprintf("opModFixedVar carries refType %d, which this referee's reading of "+
			"DERUnitRefType does not define (it knows 0=N/A, 1=%%setMaxW, 2=%%setMaxVar, 3=%%statVarAvail)",
			fv.RefType)
		return in
	}
	in.Ref = ref

	if !n.Present {
		in.Unresolved = "the device serves no M702, so " + string(ref) + " has no value on it"
		return in
	}
	base, err := n.Base(ref, meas)
	if err != nil {
		in.Unresolved = fmt.Sprintf("cannot resolve %s on this device: %v", ref, err)
		return in
	}
	if ref == invariant.RefVarAvail {
		base = capVarAvail(base, n, pct)
	}
	in.BaseUsed = base.Name
	// The RESULT is reactive power regardless of which rating the percentage
	// was taken against — that asymmetry is the trap, and it is handled the
	// same way internal/invariant's ResolveCommand handles it.
	in.Want = invariant.Q(pct/100*base.Q.Val, invariant.UnitVar)
	return in
}

// capVarAvail narrows the available-reactive-power base to what the device can
// actually do.
//
// internal/invariant computes VarAvail as the apparent-power headroom
// sqrt(VAMax² − W²), which is the right first term and the one an inverter's
// thermal envelope imposes. It is not the whole answer: a machine whose
// converter is happy to supply 47 kvar of apparent-power headroom but whose
// reactive rating is 26.4 kvar has 26.4 kvar available, not 47. The available
// figure is the SMALLER of the two, and using the uncapped one would have this
// referee assert an intent no device could satisfy — which would then be scored
// against the product as a disagreement the product is not responsible for.
//
// This is deliberately fixed HERE, in the referee, and not in
// internal/invariant: that package's Base is used by I1 to bound what a device
// was COMMANDED, where the wider figure is the conservative choice (it fails
// fewer things), while this package uses it to state what the head-end ASKED
// for, where the narrower figure is the honest one. The two callers want
// different edges of the same quantity, and a shared helper that picked one
// would be wrong for the other.
func capVarAvail(base invariant.LimitRef, n invariant.Nameplate, pct float64) invariant.LimitRef {
	sign := 1
	if pct < 0 {
		sign = -1
	}
	lim, ok := n.Limit(invariant.UnitVar, sign)
	if !ok || !lim.Q.Known() {
		return base
	}
	if lim.Q.Val < base.Q.Val {
		return invariant.LimitRef{Q: lim.Q, Name: "VarAvail capped by " + lim.Name}
	}
	return base
}

func pfIntent(mode string, spc *model.SignedPerCent) Intent {
	// A displacement power factor is carried as a signed percentage; the
	// magnitude is the PF and the sign is the excitation sense.
	pf := math.Abs(float64(spc.Value)) / 10000.0
	return Intent{
		Mode: mode, Kind: KindPowerFactor, Binding: true,
		Raw:  invariant.Q(float64(spc.Value), invariant.UnitNone),
		Want: invariant.Q(pf, invariant.UnitPF),
	}
}

// activePowerWatts expands an ActivePower into watts. The multiplier is a
// power of ten, so this is exact for the magnitudes involved.
func activePowerWatts(ap *model.ActivePower) invariant.Quantity {
	return invariant.Q(float64(ap.Value)*math.Pow10(int(ap.Multiplier)), invariant.UnitWatt)
}

func boolVal(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
