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
		//
		// IW13-001 (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §1/§2.1):
		// SignedPerCent, not ActivePower — a percentage of the device's OWN
		// setMaxW/setMaxDischargeRateW (positive) or setMaxChargeRateW
		// (negative), resolved against THIS device's own 702 (n), never the
		// DUT's report of it (referee independence, package doc). The sign
		// picks the reference: invariant.RefWRteMax reads WChaRteMaxRtg for a
		// negative percent and WDisChaRteMaxRtg for a positive one, falling
		// back to the nameplate only where the device implements neither —
		// which is what derbase's fixedWReference does on the product side.
		// This referee resolved both signs against RefWMax until IW14-001/F5,
		// which made it disagree with a CORRECT product by the ratio of the
		// nameplate to the rate rating on any asymmetric pack.
		out = append(out, fixedWIntent(*ctrl.OpModFixedW, n, meas))
	}

	// Export / generation / maximum ceilings. Each is an independent upper
	// bound on active power, so all of them hold at once and the binding one is
	// the smallest. Reducing them here — rather than picking one — is the
	// referee's whole disagreement with a first-non-nil reader.
	//
	// opModMaxLimW joins this same combine as a WATTS quantity resolved from
	// its own PerCent against n (IW13-001 §1/§3.3) — ExpLimW/GenLimW are
	// unaffected (§1.2, still genuine ActivePower/watts). This referee already
	// evaluates one device at a time (n/meas are THIS device's own), so there
	// is no site-level/per-device split to model here the way csipin.go's
	// two-tier combine has to: from this referee's vantage every one of these
	// three axes is already a per-device watts ceiling by the time it reaches
	// the combine.
	out = append(out, ceilingIntents(invariant.UnitWatt, 1, []namedPower{
		{"opModExpLimW", apQty(ctrl.OpModExpLimW)},
		{"opModMaxLimW", maxLimWQty(ctrl.OpModMaxLimW, n)},
		{"opModGenLimW", apQty(ctrl.OpModGenLimW)},
	})...)

	// Import / load ceilings. Same conjunctive reduction; the sign convention
	// is this bench's usual one (+ export / discharge, − import / charge), so
	// an import ceiling is a bound on the MAGNITUDE of a negative flow and is
	// carried as a negative quantity.
	out = append(out, ceilingIntents(invariant.UnitWatt, -1, []namedPower{
		{"opModImpLimW", apQty(ctrl.OpModImpLimW)},
		{"opModLoadLimW", apQty(ctrl.OpModLoadLimW)},
	})...)

	return out
}

// namedPower pairs a CSIP axis name with its already-resolved watts quantity
// (nil = axis absent). Resolved BEFORE reaching ceilingIntents so the combine
// itself stays unit-agnostic — opModMaxLimW's PerCent-via-nameplate resolution
// (maxLimWQty) and opModExpLimW/opModGenLimW's/opModImpLimW's/opModLoadLimW's
// plain ActivePower decode (apQty) produce the identical shape by the time
// they get here (IW13-001 §3.3).
type namedPower struct {
	mode string
	q    *invariant.Quantity
}

// apQty decodes an ActivePower axis to a watts Quantity pointer, nil when the
// axis is absent — ExpLimW/GenLimW/ImpLimW/LoadLimW's unchanged path (§1.2).
func apQty(ap *model.ActivePower) *invariant.Quantity {
	if ap == nil {
		return nil
	}
	q := activePowerWatts(ap)
	return &q
}

// maxLimWQty resolves opModMaxLimW's PerCent against n's own WMax (IW13-001
// §1/§3.3) — nil when the axis is absent OR when n cannot resolve WMax
// (device serves no M702 / declares neither WMaxRtg nor WMax), the same
// honest-unknown-nameplate refusal fixedWIntent and csipin.go's own
// fixedWReference take: this axis needs THIS device's own rating to mean
// anything, so there is no watts-safe fallback to guess.
func maxLimWQty(pc *model.PerCent, n invariant.Nameplate) *invariant.Quantity {
	if pc == nil || !n.Present {
		return nil
	}
	base, err := n.Base(invariant.RefWMax, 1, invariant.Measurement{})
	if err != nil {
		return nil
	}
	pct := float64(pc.Value) / 100.0
	q := invariant.Q(pct/100*base.Q.Val, invariant.UnitWatt)
	return &q
}

// fixedWIntent resolves opModFixedW's SignedPerCent into watts against the
// reference its OWN SIGN selects on this device (IW13-001 §1/§2.1 via
// invariant.RefWRteMax — see the call site's comment). Unresolved (not a
// guess) when n supplies no reference at all, and equally unresolved when the
// device DECLARES it cannot move in the commanded direction: a rated maximum
// of zero is a claim, and quietly resolving the percent against the nameplate
// instead would grade a command the product itself refuses to send.
func fixedWIntent(spc model.SignedPerCent, n invariant.Nameplate, meas invariant.Measurement) Intent {
	pct := float64(spc.Value) / 100.0
	sign := 1
	if pct < 0 {
		sign = -1
	}
	in := Intent{
		Mode:    "opModFixedW",
		Kind:    KindSetpoint,
		Raw:     invariant.Q(pct, invariant.UnitPercent),
		Ref:     invariant.RefWRteMax,
		Binding: true,
	}
	if !n.Present {
		in.Unresolved = "the device serves no M702, so neither a rate rating nor a WMax has a value on it"
		return in
	}
	base, err := n.Base(invariant.RefWRteMax, sign, meas)
	if err != nil {
		in.Unresolved = fmt.Sprintf("cannot resolve what the commanded %.2f%% is a percentage of on this "+
			"device: %v", pct, err)
		return in
	}
	in.BaseUsed = base.Name
	in.Want = invariant.Q(pct/100*base.Q.Val, invariant.UnitWatt)
	return in
}

// ceilingIntents reduces a set of simultaneously-commanded ceilings to their
// binding minimum, marking the others superseded but keeping them, because a
// product that applied a non-binding one has demonstrably discarded a limit and
// the report needs to name which.
func ceilingIntents(unit invariant.Unit, sign float64, ps []namedPower) []Intent {
	var present []Intent
	for _, p := range ps {
		if p.q == nil {
			continue
		}
		q := *p.q
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
//
// ── %statVarAvail is defined ONCE, and not here (DIFF-CTL-004) ──────────────
//
// This function used to post-process invariant.Nameplate.Base's answer for
// refType=3 through a local helper, capVarAvail, which narrowed the base to the
// reactive nameplate because internal/invariant returned the uncapped
// apparent-power headroom sqrt(VAMax^2 - W^2). Two definitions of the same
// quantity, 1.8x apart on an ordinary idle inverter, and the differential duly
// reported the gap between its own two halves as a finding against the product.
//
// The reconciliation kept the narrower reading and moved it into
// invariant.Nameplate.Base, whose doc comment now carries the definition and
// its citations: available reactive power is the SMALLER of the apparent-power
// headroom and the REACTIVE nameplate on the commanded side, because IEEE 1547
// Table 28 declares those as two separate mandatory ratings and 2030.5's
// statVarAvail is a directional (injection-side, in 2018) quantity that a
// sign-symmetric sqrt cannot express. The old helper's stated reason for the
// split — that I1 wants the wider figure because "it fails fewer things" — was
// backwards on inspection: a wider VarAvail base makes the resolved command
// LARGER, so I1 compares a bigger number against the same nameplate and fails
// MORE. It was manufacturing an over-nameplate violation against a device
// commanded to 100 % of a headroom it does not have.
//
// The rule this leaves: the referee is entitled to its own INTERPRETATION of a
// document, which is what everything below is. It is not entitled to a private
// physics for a quantity the checker it feeds also has to resolve.
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
	// The sign selects the side of every two-sided rating, %statVarAvail's
	// included — see the note above this function on where that definition
	// lives now.
	sign := 1
	if pct < 0 {
		sign = -1
	}
	base, err := n.Base(ref, sign, meas)
	if err != nil {
		in.Unresolved = fmt.Sprintf("cannot resolve %s on this device: %v", ref, err)
		return in
	}
	in.BaseUsed = base.Name
	// The RESULT is reactive power regardless of which rating the percentage
	// was taken against — that asymmetry is the trap, and it is handled the
	// same way internal/invariant's ResolveCommand handles it.
	in.Want = invariant.Q(pct/100*base.Q.Val, invariant.UnitVar)
	return in
}

// pfIntent renders one PowerFactorWithExcitation as this family's Intent.
//
// IT USED TO READ A SIGNED PERCENTAGE, under the comment "the magnitude is the
// PF and the sign is the excitation sense" — a shape lexa-proto invented and no
// revision of 2030.5 declares (IEEE Std 2030.5-2018 p.258 gives the element
// three mandatory children). Two consequences, and the second is the one that
// mattered: the PF was computed as |value|/10000, which is the -4 multiplier
// the scalar implied rather than the one the document carries, so a conformant
// server's {900, false, -3} would have been read as 0.09 rather than 0.9 — off
// by a factor of ten, in the direction that looks plausible. And EXCITATION was
// inferred from a sign, so a document asserting under-excited at a positive
// magnitude was indistinguishable from one asserting over-excited.
//
// Both are now read from the element itself. PF() applies the document's own
// multiplier and is the same arithmetic the product applies at receipt.
//
// A REFUSED value is still an Intent, with Binding false: a control naming an
// unusable power factor is a fact about what the head end sent, and this family
// exists to describe what was commanded. Dropping it would make the intent list
// silently shorter than the control.
func pfIntent(mode string, pf *model.PowerFactorWithExcitation) Intent {
	v, ok := pf.PF()
	return Intent{
		Mode: mode, Kind: KindPowerFactor, Binding: ok,
		// Raw is the displacement as the wire carries it, unscaled — the
		// number a reader finds in the pcap.
		Raw:  invariant.Q(float64(pf.Displacement), invariant.UnitNone),
		Want: invariant.Q(v, invariant.UnitPF),
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
