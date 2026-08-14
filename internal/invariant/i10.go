package invariant

// i10.go — The device never accepts a control it cannot safely carry out, and
// says so (CannotComply) rather than partially applying it.
//
// Grounding: CSIP response-code handling. IEEE 2030.5 gives a client a way to
// decline — Table 27's rejection codes 252/253/254, the partial-opt-out 8, and
// this bench's legacy 0xF0 extension — and the safety property is that a
// control is either carried out in full or declined in full. The dangerous
// middle is a control accepted with a success response and then applied on
// some axes and not others: a curtailment where the export limit landed but the
// power-factor command did not is a plausible-looking operating point nobody
// authorised, and nothing alarms on it.
//
// # How an axis is judged "carried out"
//
// This is the honest part and the statement carries it. A DERControlBase axis
// is counted as carried out when the corresponding SunSpec control point is
// ENABLED at some DER and its value is consistent with what was commanded — a
// limit axis (opModExpLimW, opModMaxLimW) is satisfied by a resolved
// WMaxLimPct at or below the commanded watts, a setpoint axis (opModFixedVar,
// opModFixedW) by the matching 704 point being enabled, and the connect/energize
// axes by the device's own 701 connection state.
//
// Two things are NOT counted, and are named in the finding rather than silently
// treated as satisfied: an axis with no SunSpec analogue in the models this
// bench reads, and any axis at all when the head-end's site-level limit would
// have to be allocated across several DERs — that allocation is internal policy
// and is not externally derivable, so with more than one DER the limit axes are
// judged by the site total rather than per device.
//
// # PENDING, again for a good reason
//
// A control that has been served but not yet responded to and not yet applied
// is not a violation; it is a control the device has not got to. I10 reports
// [Pending] for it and lets the end of the run decide, exactly as I2 and I9 do.
// The falsification is "the run ended with the control neither carried out nor
// declined", which needs no invented deadline.

import (
	"context"
	"fmt"
	"math"
)

type i10 struct{ p Params }

// NewI10 returns the all-or-decline invariant.
func NewI10(p Params) Invariant { return &i10{p: p} }

func (i *i10) ID() string { return "I10" }

func (i *i10) Grounding() string {
	return "CSIP response-code handling — a control must be carried out in full or declined in " +
		"full; the dangerous middle is a success response over a partially applied control."
}

func (i *i10) Statement() string {
	return "The device never accepts a control it cannot safely carry out: every active control is " +
		"either reflected on ALL of its axes in the DERs' own register images, or declined with a " +
		"cannot-comply response and reflected on NONE. A partially applied control, or a success " +
		"response over a control with nothing applied, is the violation. PARTIAL: an axis is judged " +
		"carried out by the corresponding SunSpec control point being enabled and consistent; axes " +
		"with no SunSpec analogue in models 701/704 are counted as unjudgeable and NAMED rather " +
		"than assumed satisfied; and with more than one DER the site-level limit axes are judged " +
		"against the site total, because the per-device allocation is internal policy and is not " +
		"externally derivable. A served-but-not-yet-answered control is PENDING, not a failure."
}

func (i *i10) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	if !obs.HeadEnd.Reachable {
		return skipf("the head-end is unreachable, so no control is observable (%s)", obs.HeadEnd.Err), nil
	}
	ders := derViews(obs)
	if len(ders) == 0 {
		return skipf("no DER's own register image was readable, so nothing can be judged applied"), nil
	}

	now := obs.HeadEnd.ServerTime
	if now.IsZero() {
		now = obs.At
	}
	res := Result{Verdict: Pass}
	seen := 0

	for _, prog := range obs.HeadEnd.Programs {
		for _, c := range prog.Active {
			if !c.Covers(now) {
				continue
			}
			axes := c.Base.Axes()
			if len(axes) == 0 {
				continue
			}
			seen++
			applied, unjudgeable, detail := appliedAxes(c, ders, i.p.Tol)
			judgeable := len(axes) - unjudgeable
			declined := i.declined(obs.HeadEnd, c.MRID)
			succeeded := i.reportedSuccess(obs.HeadEnd, c.MRID)

			if judgeable == 0 {
				res.Assertions = append(res.Assertions, narrate(
					fmt.Sprintf("control %s is carried out in full or declined in full", c.MRID),
					"compare each DERControlBase axis against the DERs' own register images",
					Skip, fmt.Sprintf("none of control %s's %d axes has a SunSpec analogue this bench reads (%s)",
						c.MRID, len(axes), detail)))
				continue
			}
			res.Checked++

			switch {
			case applied == judgeable:
				// Carried out in full. Nothing to report.
			case applied == 0 && declined:
				// Declined in full and said so. This is the good refusal path.
			case applied > 0 && applied < judgeable:
				res.Verdict = Fail
				res.Facts = append(res.Facts, i.facts(prog, c, applied, judgeable, unjudgeable, detail, declined, succeeded)...)
				if res.Reason == "" {
					res.Reason = fmt.Sprintf(
						"control %s (program %s, primacy %d) is PARTIALLY applied — %d of %d judgeable axes are "+
							"reflected at the DERs (%s); the device is running an operating point nobody commanded",
						c.MRID, prog.MRID, prog.Primacy, applied, judgeable, detail)
				}
				res.Assertions = append(res.Assertions, narrate(
					fmt.Sprintf("control %s is applied on all axes or none", c.MRID),
					"count the axes of the control's base reflected in the DERs' own register images",
					Fail, res.Reason))
			case applied == 0 && succeeded:
				res.Verdict = Fail
				res.Facts = append(res.Facts, i.facts(prog, c, applied, judgeable, unjudgeable, detail, declined, succeeded)...)
				if res.Reason == "" {
					res.Reason = fmt.Sprintf(
						"control %s was acknowledged as started/completed but NONE of its %d judgeable axes is "+
							"reflected at any DER (%s) — the device accepted a control it did not carry out",
						c.MRID, judgeable, detail)
				}
			case applied == 0:
				res.Verdict = Worse(res.Verdict, Pending)
				res.Facts = append(res.Facts, i.facts(prog, c, applied, judgeable, unjudgeable, detail, declined, succeeded)...)
				if res.Reason == "" {
					res.Reason = fmt.Sprintf(
						"control %s is being served and none of its %d judgeable axes is applied yet, and the DUT "+
							"has neither reported success nor declined it — no deadline is applied; the run ending "+
							"in this state is the failure", c.MRID, judgeable)
				}
			}
		}
	}

	if seen == 0 {
		return skipf("the head-end is serving no active control covering now, so all-or-decline is not under test"), nil
	}
	if res.Checked == 0 {
		return skipf("none of the %d active controls has an axis this bench can judge", seen), nil
	}
	if res.Verdict == Pass {
		res.Assertions = append(res.Assertions, narrate(
			"every active control is carried out in full or declined in full",
			"count the reflected axes of each active control in the DERs' own register images and compare "+
				"against the DUT's response",
			Pass, fmt.Sprintf("%d active controls judged", res.Checked)))
	}
	return res, nil
}

func (i *i10) facts(prog Program, c Ctrl, applied, judgeable, unjudgeable int, detail string, declined, succeeded bool) []Fact {
	pfx := "i10." + c.MRID
	return []Fact{
		F(pfx+".program", "", "gridsim-admin", "%s (primacy %d)", prog.MRID, prog.Primacy),
		F(pfx+".axes_total", "count", "gridsim-admin", "%d", len(c.Base.Axes())),
		F(pfx+".axes_judgeable", "count", "gridsim-admin", "%d", judgeable),
		F(pfx+".axes_unjudgeable", "count", "gridsim-admin", "%d", unjudgeable),
		F(pfx+".axes_applied", "count", "der register images", "%d", applied),
		F(pfx+".detail", "", "der register images", "%s", detail),
		F(pfx+".declined", "", "gridsim-admin", "%t", declined),
		F(pfx+".reported_success", "", "gridsim-admin", "%t", succeeded),
	}
}

// declined reports whether the DUT told the head-end it could not comply with
// this control.
func (i *i10) declined(h HeadEndView, mrid string) bool {
	for _, a := range h.Alerts {
		if a.Subject == mrid {
			return true
		}
	}
	for _, r := range h.Responses {
		if r.Subject == mrid && (r.Status == 8 || r.Status == 10 || r.Status >= 252) {
			return true
		}
	}
	return false
}

// reportedSuccess reports whether the DUT acknowledged this control as started
// or completed.
func (i *i10) reportedSuccess(h HeadEndView, mrid string) bool {
	for _, r := range h.Responses {
		if r.Subject == mrid && isSuccessStatus(r.Status) {
			return true
		}
	}
	return false
}

// appliedAxes counts how many of a control's axes are reflected in the DERs'
// own register images, how many have no SunSpec analogue this bench can judge,
// and a per-axis detail string.
//
// It is shared with I7, which needs the same "did anything actually happen"
// question answered for a different reason.
func appliedAxes(c Ctrl, ders []devView, tol Tolerance) (applied, unjudgeable int, detail string) {
	var parts []string
	siteW, siteWOK := siteCommandedWatts(ders)

	for _, ax := range c.Base.Axes() {
		switch ax.Name {
		case "opModExpLimW", "opModGenLimW", "opModImpLimW", "opModLoadLimW":
			// Still genuine site-level watts (§1.2, unaffected by IW13-001) —
			// opModMaxLimW moved to its own case below, since a per-device
			// percent axis has no site total to judge.
			if !siteWOK {
				unjudgeable++
				parts = append(parts, ax.Name+"=unjudgeable(no DER resolves an active-power setpoint)")
				continue
			}
			// A limit is carried out when the site is commanded at or below it.
			if siteW <= math.Abs(ax.Value)*(1+tol.Rel) {
				applied++
				parts = append(parts, fmt.Sprintf("%s=applied(site %s W <= %s W)", ax.Name, trimFloat(siteW), trimFloat(ax.Value)))
			} else {
				parts = append(parts, fmt.Sprintf("%s=NOT applied(site %s W > %s W)", ax.Name, trimFloat(siteW), trimFloat(ax.Value)))
			}
		case "opModMaxLimW":
			// IW13-001 §1/§3.3: PerCent of EACH DEVICE'S OWN setMaxW, not a
			// site-level watts figure — the "judge by the site total because
			// the per-device allocation is internal policy and is not
			// externally derivable" reasoning (this file's own package doc)
			// no longer applies: a per-device percent has no allocation to
			// guess at all, every admitted DER independently applies the
			// SAME commanded percent to ITS OWN rating. Applied when EVERY
			// DER that reports an enabled WMaxLimPct holds it at or below
			// the commanded percent — direct percent-to-percent (both sides
			// already express %setMaxW), no nameplate/watts resolution
			// needed for this comparison at all.
			judged, allSatisfy, judgedDetail := maxLimWAppliedPerDevice(ders, ax.Value, tol)
			if !judged {
				unjudgeable++
				parts = append(parts, ax.Name+"=unjudgeable(no DER reports an enabled WMaxLimPct)")
			} else if allSatisfy {
				applied++
				parts = append(parts, fmt.Sprintf("%s=applied(%s, commanded %s%%)", ax.Name, judgedDetail, trimFloat(ax.Value)))
			} else {
				parts = append(parts, fmt.Sprintf("%s=NOT applied(%s, commanded %s%%)", ax.Name, judgedDetail, trimFloat(ax.Value)))
			}
		case "opModFixedW":
			// IW13-001: a real MAGNITUDE check now, not just the enable bit —
			// the sibling ceiling branches above always checked magnitude;
			// this axis only checked the enable bit before the retype
			// (i10.go's own pre-fix gap the design names explicitly). §2.1
			// Phase 1 (mirroring csipin.go's fixedWReference/derbase's own
			// judgment call): resolved against each DER's own WMax
			// symmetrically for both signs, since this package's Nameplate
			// type (like csipin.go's) has no distinct charge/discharge
			// rating to prefer instead.
			judged, allSatisfy, judgedDetail := fixedWAppliedPerDevice(ders, ax.Value, tol)
			if !judged {
				unjudgeable++
				parts = append(parts, ax.Name+"=unjudgeable(no DER resolves an enabled WSet/WSetPct against its own nameplate)")
			} else if allSatisfy {
				applied++
				parts = append(parts, fmt.Sprintf("%s=applied(%s, commanded %s%%)", ax.Name, judgedDetail, trimFloat(ax.Value)))
			} else {
				parts = append(parts, fmt.Sprintf("%s=NOT applied(%s, commanded %s%%)", ax.Name, judgedDetail, trimFloat(ax.Value)))
			}
		case "opModFixedVar":
			if anyEnabled(ders, "VarSet", "VarSetPct") {
				applied++
				parts = append(parts, ax.Name+"=applied(VarSet/VarSetPct enabled)")
			} else {
				parts = append(parts, ax.Name+"=NOT applied(no VarSet/VarSetPct enabled)")
			}
		case "opModFixedPFInjectW":
			if anyEnabled(ders, "PFWInj_PF") {
				applied++
				parts = append(parts, ax.Name+"=applied(PFWInjEna set)")
			} else {
				parts = append(parts, ax.Name+"=NOT applied(PFWInjEna clear)")
			}
		case "opModFixedPFAbsorbW":
			if anyEnabled(ders, "PFWAbs_PF") {
				applied++
				parts = append(parts, ax.Name+"=applied(PFWAbsEna set)")
			} else {
				parts = append(parts, ax.Name+"=NOT applied(PFWAbsEna clear)")
			}
		case "opModConnect", "opModEnergize":
			want := ax.Value != 0
			got, ok := anyConnected(ders)
			if !ok {
				unjudgeable++
				parts = append(parts, ax.Name+"=unjudgeable(no DER reports a connection state)")
				continue
			}
			if got == want {
				applied++
				parts = append(parts, fmt.Sprintf("%s=applied(ConnSt matches want=%t)", ax.Name, want))
			} else {
				parts = append(parts, fmt.Sprintf("%s=NOT applied(want=%t, DER reports %t)", ax.Name, want, got))
			}
		default:
			unjudgeable++
			parts = append(parts, ax.Name+"=unjudgeable(no SunSpec analogue in models 701/704)")
		}
	}
	return applied, unjudgeable, joinComma(parts)
}

// siteCommandedWatts sums the resolved active-power commands across the DERs.
func siteCommandedWatts(ders []devView) (float64, bool) {
	total, counted := 0.0, 0
	for _, v := range ders {
		np := v.Unit.Nameplate(v.Source)
		meas := v.Unit.Measurement(v.Source)
		if !np.Present {
			continue
		}
		for _, c := range enabledCommands(v.Unit.Commands(v.Source)) {
			r := ResolveCommand(c, np, meas)
			if r.Physical.Known() && r.Physical.Unit == UnitWatt {
				total += math.Abs(r.Physical.Val)
				counted++
			}
		}
	}
	return total, counted > 0
}

// maxLimWAppliedPerDevice checks opModMaxLimW per device (IW13-001 §1/§3.3):
// each DER's own enabled WMaxLimPct register is compared DIRECTLY against the
// commanded percent — both sides already express %setMaxW, so no nameplate or
// watts resolution is needed at all, unlike the site-level ceiling axes above.
// A CEILING comparison (one-sided: at or below), matching WMaxLimPct's own
// KindCeiling semantics (ctl.go's resolveHeld). judged=false when no DER
// reports an enabled WMaxLimPct at all.
func maxLimWAppliedPerDevice(ders []devView, commandedPct float64, tol Tolerance) (judged, allSatisfy bool, detail string) {
	allSatisfy = true
	var details []string
	for _, v := range ders {
		for _, c := range enabledCommands(v.Unit.Commands(v.Source)) {
			if c.Point != "WMaxLimPct" || !c.Raw.Known() || c.Raw.Unit != UnitPercent {
				continue
			}
			judged = true
			got := c.Raw.Val
			details = append(details, fmt.Sprintf("%s WMaxLimPct=%s%%", v.Label, trimFloat(got)))
			if got > commandedPct*(1+tol.Rel) {
				allSatisfy = false
			}
		}
	}
	return judged, allSatisfy, joinComma(details)
}

// fixedWAppliedPerDevice checks opModFixedW per device (IW13-001 §1/§2.1):
// each DER's own resolved WSet/WSetPct watts value is compared against the
// SAME commanded percent resolved against THAT DER's own PER-SIGN rate
// reference (RefWRteMax — WChaRteMaxRtg charging, WDisChaRteMaxRtg
// discharging, the nameplate where the device implements neither), which is
// the reference derbase's fixedWReference writes against on the product side.
// A SETPOINT comparison (two-sided: must match, not merely not-exceed),
// matching WSet/WSetPct's own KindSetpoint semantics. judged=false when no DER
// resolves both an enabled setpoint AND that reference.
//
// It resolved BOTH signs against WMax until IW14-001/F5. See Nameplate.wRteMax
// for why that reported a correct gateway as NOT applied — and passed a
// nameplate-fallback one — on every device whose charge and discharge ratings
// differ.
func fixedWAppliedPerDevice(ders []devView, commandedPct float64, tol Tolerance) (judged, allSatisfy bool, detail string) {
	allSatisfy = true
	var details []string
	sign := 1
	if commandedPct < 0 {
		sign = -1
	}
	for _, v := range ders {
		np := v.Unit.Nameplate(v.Source)
		meas := v.Unit.Measurement(v.Source)
		if !np.Present {
			continue
		}
		base, err := np.Base(RefWRteMax, sign, meas)
		if err != nil {
			continue
		}
		wantW := commandedPct / 100 * base.Q.Val
		for _, c := range enabledCommands(v.Unit.Commands(v.Source)) {
			if c.Point != "WSet" && c.Point != "WSetPct" {
				continue
			}
			r := ResolveCommand(c, np, meas)
			if !r.Physical.Known() || r.Physical.Unit != UnitWatt {
				continue
			}
			judged = true
			gotW := r.Physical.Val
			details = append(details, fmt.Sprintf("%s want %s W (%s%% of %s = %s W) got %s W",
				v.Label, trimFloat(wantW), trimFloat(commandedPct), base.Name,
				trimFloat(base.Q.Val), trimFloat(gotW)))
			if math.Abs(gotW-wantW) > math.Abs(wantW)*tol.Rel+tol.Abs {
				allSatisfy = false
			}
		}
	}
	return judged, allSatisfy, joinComma(details)
}

// anyEnabled reports whether any DER has one of the named 704 points enabled.
func anyEnabled(ders []devView, points ...string) bool {
	for _, v := range ders {
		cmds := v.Unit.Commands(v.Source)
		for _, p := range points {
			if c, ok := commandOf(cmds, p); ok && c.Enabled {
				return true
			}
		}
	}
	return false
}

// anyConnected reports the DERs' own connection state, and whether any of them
// publishes one.
func anyConnected(ders []devView) (bool, bool) {
	any, known := false, false
	for _, v := range ders {
		m := v.Unit.Measurement(v.Source)
		if !m.Present {
			continue
		}
		known = true
		if m.ConnSt != 0 {
			any = true
		}
	}
	return any, known
}
