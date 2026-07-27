package invariant

// i1.go — No value commanded to a DER exceeds that device's nameplate or the
// narrowest applicable limit, IN THE DER'S OWN UNITS.
//
// Grounding defect: BR-01, an absolute var count written into a
// percent-of-rated field.
//
// # Why the unit clause is the whole invariant
//
// Write this check the obvious way and it does not catch its own grounding
// defect. "Is the commanded number bigger than the rating number" compares two
// floats that have forgotten what they measure. A device rated 2 000 var
// injection, commanded VarSetPct = 80 while declaring VarSetMod = 0 ("percent
// of WMax") with WMax = 100 kW, is being told to produce 80 000 var — a 40×
// overcommand — and the obvious check sees 80 against 2000 and says PASS. The
// bug is invisible precisely because the checker made the same unit mistake the
// product did.
//
// So I1 does three things in order, and the order is the point:
//
//  1. Read the DER's OWN model 702 from the DER, not from the DUT's report of
//     it. A gateway that mis-parsed a nameplate would otherwise be audited
//     against its own misparse.
//  2. Resolve every model 704 setpoint through the reference base the DEVICE
//     declares in its mode enum — VarSetMod for reactive power, WSetMod for
//     active — into the DER's own physical unit. Where the base cannot be
//     resolved, SKIP that point with the reason. Never assume a base.
//  3. Only then compare, and refuse the comparison outright if the two operands
//     are not in the same unit (see Tolerance.Exceeds, which returns an error
//     rather than a verdict for a cross-unit compare).
//
// # What it checks, and what it cannot
//
// Checked: every enabled 704 setpoint on every reachable DER, against that
// DER's narrowest published rating (the smaller of the read-only *Rtg and the
// settable counterpart, named in the finding so "over the configured WMax,
// inside the hardware rating" is distinguishable from blowing past the
// hardware). Also checked: the DUT's own northbound projection of the same
// points against the same nameplate, because a projection that exceeds the
// device's rating is a violation wherever it is observed — and it is observable
// even when the physical device is unreachable.
//
// Also checked, at WARN: a setpoint parked in a currently-disabled register
// that would violate the nameplate the moment it were enabled. It commands
// nothing today; it is one enable-write from commanding something impossible,
// and the distinction is worth keeping rather than collapsing in either
// direction.
//
// Not checked: site-level limits that live only in an operator's configuration.
// They are not observable from outside the device by any means, so they are
// compared only when supplied as -param site_limit_w, and the statement says so.
// Per-DER allocation of a site-level head-end limit (opModMaxLimW across N
// inverters) is likewise not externally derivable — the allocation policy is
// internal — so I1 does not attempt it and does not pretend to.

import (
	"context"
	"fmt"
	"math"
)

type i1 struct{ p Params }

// NewI1 returns the nameplate/limit invariant.
func NewI1(p Params) Invariant { return &i1{p: p} }

func (i *i1) ID() string { return "I1" }

func (i *i1) Grounding() string {
	return "BR-01 — an absolute var count written into a percent-of-rated field, " +
		"which a unit-blind comparison cannot see because it makes the same mistake."
}

func (i *i1) Statement() string {
	return "No value commanded to a DER exceeds that device's nameplate or the narrowest " +
		"applicable limit, in the DER's own units: every model-704 setpoint is resolved " +
		"through the reference base the device itself declares (VarSetMod / WSetMod) against " +
		"the device's own model-702 ratings before any comparison is made, and a cross-unit " +
		"comparison is refused rather than performed. " +
		"PARTIAL, and deliberately so: (a) site-level export limits exist only in operator " +
		"configuration and are compared only when supplied as -param site_limit_w; (b) the " +
		"per-DER allocation of a site-level head-end limit is not externally derivable and is " +
		"not checked; (c) a percentage whose reference base needs a live measurement the device " +
		"is not reporting is SKIPped with that reason, never guessed."
}

func (i *i1) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	views := deviceViews(obs)
	if len(views) == 0 {
		return skipf("no device register image was readable this tick (%s)", unreachableReason(obs)), nil
	}

	// Nameplates come from the DEVICES' own images and are keyed by device so
	// the DUT's projection of a device is audited against that device's real
	// ratings rather than against the DUT's copy of them.
	nameplates := map[string]Nameplate{}
	measurements := map[string]Measurement{}
	for _, v := range derViews(obs) {
		nameplates[v.Device] = v.Unit.Nameplate(v.Source)
		measurements[v.Device] = v.Unit.Measurement(v.Source)
	}

	res := Result{Verdict: Pass}
	var skipped []string

	for _, v := range views {
		cmds := v.Unit.Commands(v.Source)
		if len(cmds) == 0 {
			continue
		}
		np, meas := i.ratingsFor(v, nameplates, measurements)
		if !np.Present {
			skipped = append(skipped, fmt.Sprintf("%s: no model 702 to bound its setpoints", v.Label))
			continue
		}
		for _, c := range cmds {
			r := ResolveCommand(c, np, meas)
			verdict, checked, facts := i.judge(v, r, np, meas)
			res.Checked += checked
			if checked == 0 && r.Unresolved != "" {
				skipped = append(skipped, fmt.Sprintf("%s %s: %s", v.Label, r.Point, r.Unresolved))
			}
			if verdict == Pass {
				continue
			}
			res.Verdict = Worse(res.Verdict, verdict)
			res.Facts = append(res.Facts, facts...)
			res.Facts = append(res.Facts, np.Facts(v.Label)...)
			res.Assertions = append(res.Assertions, narrate(
				fmt.Sprintf("%s %s is within the device's own %s rating", v.Label, r.Point, r.Physical.Unit),
				"resolve the setpoint through the device-declared reference base into the device's "+
					"physical units, then compare against the narrower of its M702 rating and setting",
				verdict,
				i.describe(v, r, np),
			))
			if res.Reason == "" {
				res.Reason = i.describe(v, r, np)
			}
		}
	}

	// Optional site-level aggregate, only when the operator supplied the limit.
	if sv, ok := i.p.Float("site_limit_w"); ok {
		verdict, checked, facts, reason := i.checkSiteLimit(obs, nameplates, measurements, sv)
		res.Checked += checked
		if verdict != Pass {
			res.Verdict = Worse(res.Verdict, verdict)
			res.Facts = append(res.Facts, facts...)
			if res.Reason == "" {
				res.Reason = reason
			}
		}
	}

	if res.Checked == 0 {
		reason := "no setpoint could be resolved into physical units this tick"
		if len(skipped) > 0 {
			reason += ": " + joinComma(skipped)
		}
		return skipf("%s", reason), nil
	}
	if res.Verdict == Warn && res.Reason == "" {
		res.Reason = "a disabled setpoint holds a value that would exceed the nameplate if enabled"
	}
	if len(skipped) > 0 && res.Verdict == Pass {
		res.Assertions = append(res.Assertions, narrate(
			"every setpoint that could be resolved was within the device's rating",
			"unit-resolved nameplate comparison",
			Pass,
			fmt.Sprintf("%d setpoints checked; %d not resolvable (%s)", res.Checked, len(skipped), joinComma(skipped)),
		))
	}
	return res, nil
}

// ratingsFor picks the nameplate and measurement a view's setpoints are judged
// against. A DER is judged against itself. The DUT's projection of a unit is
// judged against the physical device's own ratings when the pairing is known,
// and otherwise against the ratings the DUT itself publishes for that unit —
// which is weaker (a DUT that mis-parsed a nameplate would be self-consistent)
// but is still capable of catching an absolute-into-percent write, because the
// resolved magnitude blows past any plausible rating.
func (i *i1) ratingsFor(v devView, nps map[string]Nameplate, ms map[string]Measurement) (Nameplate, Measurement) {
	if np, ok := nps[v.Device]; ok && np.Present {
		return np, ms[v.Device]
	}
	if v.Witness == witnessDUT {
		// Exactly one DER observed: the projection can only be of that device.
		if len(nps) == 1 {
			for d, np := range nps {
				if np.Present {
					return np, ms[d]
				}
			}
		}
	}
	return v.Unit.Nameplate(v.Source), v.Unit.Measurement(v.Source)
}

// judge evaluates one resolved command. It returns the verdict, how many
// sub-claims it actually asserted (the assertion floor), and the facts.
func (i *i1) judge(v devView, c Command, np Nameplate, meas Measurement) (Verdict, int, []Fact) {
	if c.Unresolved != "" {
		return Pass, 0, nil
	}

	// Power factor is bounded by physics, not by a nameplate.
	if c.Raw.Unit == UnitPF {
		return i.judgePF(v, c, np)
	}
	if !c.Physical.Known() {
		return Pass, 0, nil
	}
	limit, ok := np.Limit(c.Physical.Unit, c.Sign)
	if !ok {
		return Pass, 0, nil
	}
	over, exceeded, err := i.p.Tol.Exceeds(c.Physical, limit.Q)
	if err != nil {
		// A cross-unit comparison reaching this point is a defect in this
		// package, not in the DUT, and must be surfaced as such rather than
		// silently swallowed.
		return Warn, 1, []Fact{F(v.Label+"."+c.Point+".compare_error", "", v.Source, "%v", err)}
	}
	if !exceeded {
		return Pass, 1, nil
	}
	facts := i.facts(v, c, limit, over)
	if !c.Enabled {
		facts = append(facts, F(v.Label+"."+c.Point+".enabled", "", v.Source, "false (staged, not governing)"))
		return Warn, 1, facts
	}
	return Fail, 1, facts
}

// judgePF checks a commanded power factor. A |PF| > 1 is not a curtailment
// mistake, it is an encoding mistake, and it is a FAIL. A PF that is legal but
// demands more reactive power at rated real power than the device is rated to
// produce is a WARN: IEEE 1547 lets a head-end command a PF the device cannot
// meet at every operating point, and the device is expected to prioritise, so
// calling it a safety violation would be inventing a requirement.
func (i *i1) judgePF(v devView, c Command, np Nameplate) (Verdict, int, []Fact) {
	pf := c.Raw.Val
	if !c.Raw.Known() {
		return Pass, 0, nil
	}
	if math.Abs(pf) > 1.0+1e-9 {
		return Fail, 1, []Fact{
			F(v.Label+"."+c.Point+".raw", "PF", v.Source, "%s", trimFloat(pf)),
			F(v.Label+"."+c.Point+".enabled", "", v.Source, "%t", c.Enabled),
			F(v.Label+"."+c.Point+".violation", "", v.Source,
				"|PF| > 1 is not physically representable; the register holds a value that is not a power factor"),
		}
	}
	if !c.Enabled || pf == 0 {
		return Pass, 1, nil
	}
	wLimit, okW := np.Limit(UnitWatt, 1)
	varLimit, okVar := np.Limit(UnitVar, c.Sign)
	if !okW || !okVar {
		return Pass, 1, nil
	}
	// Reactive demand at rated real power: |Q| = P·tan(acos|PF|).
	demand := wLimit.Q.Val * math.Tan(math.Acos(math.Abs(pf)))
	if demand <= varLimit.Q.Val*(1+i.p.Tol.Rel) {
		return Pass, 1, nil
	}
	return Warn, 1, []Fact{
		F(v.Label+"."+c.Point+".raw", "PF", v.Source, "%s", trimFloat(pf)),
		F(v.Label+"."+c.Point+".var_demand_at_rated_W", "var", v.Source, "%s", trimFloat(demand)),
		F(v.Label+"."+c.Point+".var_limit", "var", v.Source, "%s (%s)", trimFloat(varLimit.Q.Val), varLimit.Name),
		F(v.Label+"."+c.Point+".note", "", v.Source,
			"the commanded power factor cannot be met at rated real power; 1547 permits this and expects "+
				"the device to prioritise, so it is reported rather than failed"),
	}
}

// facts renders the full unit provenance of a violation. Every number here
// carries its unit and the register that produced it, because a violation
// record that drops a unit reproduces the defect it is reporting.
func (i *i1) facts(v devView, c Command, limit LimitRef, over float64) []Fact {
	pfx := v.Label + "." + c.Point
	facts := []Fact{
		F(pfx+".raw", string(c.Raw.Unit), v.Source, "%s", trimFloat(c.Raw.Val)),
		F(pfx+".enabled", "", v.Source, "%t", c.Enabled),
		F(pfx+".physical", string(c.Physical.Unit), v.Source, "%s", trimFloat(c.Physical.Val)),
		F(pfx+".limit", string(limit.Q.Unit), v.Source, "%s (%s)", trimFloat(limit.Q.Val), limit.Name),
		F(pfx+".over_by", string(limit.Q.Unit), v.Source, "%s", trimFloat(over)),
		F(pfx+".witness", "", v.Source, "%s", v.Witness),
	}
	if c.Ref != RefNone {
		facts = append(facts,
			F(pfx+".ref_base", "", v.Source, "%s", c.Ref),
			F(pfx+".ref_declared_by", "", v.Source, "%s=%d", c.ModePoint, c.ModeVal),
			F(pfx+".ref_value", "", v.Source, "%s", c.BaseUsed),
		)
	}
	if limit.Q.Val > 0 {
		facts = append(facts, F(pfx+".ratio", "x", v.Source, "%.2f", math.Abs(c.Physical.Val)/limit.Q.Val))
	}
	return facts
}

// describe is the one-sentence finding, written so the unit error is legible
// without opening the facts.
func (i *i1) describe(v devView, c Command, np Nameplate) string {
	limit, ok := np.Limit(c.Physical.Unit, c.Sign)
	if !ok {
		return fmt.Sprintf("%s %s = %s could not be bounded", v.Label, c.Point, c.Physical)
	}
	if c.Ref != RefNone {
		return fmt.Sprintf(
			"%s commands %s = %s, which the device's own %s=%d declares to be a percentage of %s (%s); "+
				"that resolves to %s against a %s of %s — %.1f× over",
			v.Label, c.Point, c.Raw, c.ModePoint, c.ModeVal, c.Ref, c.BaseUsed,
			c.Physical, limit.Name, limit.Q, math.Abs(c.Physical.Val)/limit.Q.Val)
	}
	return fmt.Sprintf("%s commands %s = %s against a %s of %s — %.1f× over",
		v.Label, c.Point, c.Physical, limit.Name, limit.Q, math.Abs(c.Physical.Val)/limit.Q.Val)
}

// checkSiteLimit sums the resolved active-power commands across every DER and
// compares the total against an operator-supplied site limit. It runs only when
// the parameter is present, because nothing observable carries a site limit.
func (i *i1) checkSiteLimit(o *Observation, nps map[string]Nameplate, ms map[string]Measurement, siteW float64) (Verdict, int, []Fact, string) {
	total := 0.0
	contributing := 0
	var facts []Fact
	for _, v := range derViews(o) {
		np, ok := nps[v.Device]
		if !ok || !np.Present {
			continue
		}
		for _, c := range enabledCommands(v.Unit.Commands(v.Source)) {
			r := ResolveCommand(c, np, ms[v.Device])
			if !r.Physical.Known() || r.Physical.Unit != UnitWatt {
				continue
			}
			total += math.Abs(r.Physical.Val)
			contributing++
			facts = append(facts, F(v.Label+"."+c.Point+".physical", "W", v.Source, "%s", trimFloat(r.Physical.Val)))
		}
	}
	if contributing == 0 {
		return Pass, 0, nil, ""
	}
	over, exceeded, err := i.p.Tol.Exceeds(Q(total, UnitWatt), Q(siteW, UnitWatt))
	if err != nil || !exceeded {
		return Pass, 1, nil, ""
	}
	facts = append(facts,
		F("site.commanded_total", "W", "aggregate", "%s", trimFloat(total)),
		F("site.limit", "W", "-param site_limit_w", "%s", trimFloat(siteW)),
		F("site.over_by", "W", "aggregate", "%s", trimFloat(over)),
	)
	return Fail, 1, facts, fmt.Sprintf(
		"the DERs are collectively commanded to %s W against an operator-declared site limit of %s W",
		trimFloat(total), trimFloat(siteW))
}
