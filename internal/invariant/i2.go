package invariant

// i2.go — With control authority lost or expired, the device converges to the
// configured failsafe within its stated deadline, AND leaves failsafe when
// authority legitimately returns.
//
// Grounding defect: FI-03, fail-safe latching permanently to zero export.
//
// # Two arms, and only one of them needs an operator
//
// The convergence half cannot be checked without knowing what the failsafe IS
// and what deadline was promised. Neither is externally observable — they live
// in the DUT's configuration — so both come from -param, and the arm SKIPs with
// that as its reason when they are absent. Inventing a plausible failsafe would
// produce a check that fails devices for being configured differently than this
// package guessed, which is worse than not checking.
//
// The release half needs no such thing, and it is the half that catches the
// grounding defect. FI-03 was a device that entered failsafe and never left.
// Detecting that requires no knowledge of the failsafe value and no deadline:
// once the authority-loss fault has been CLEARED and the head-end is serving an
// active control that asks for something other than what the device is doing,
// the device must eventually do the new thing. "Eventually" is the operative
// word — the gateway backs off to fifteen minutes and promises nothing about
// promptness, so this arm reports [Pending] while it waits and lets the end of
// the run decide. A run that ends with the device still latched is a FAIL, and
// no threshold had to be invented to say so.
//
// The asymmetry is deliberate: the arm that needs a promise the product made
// asks the operator for it; the arm that needs only "it must not latch forever"
// runs unconditionally.

import (
	"context"
	"fmt"
	"math"
	"time"
)

type i2 struct{ p Params }

// NewI2 returns the failsafe convergence/release invariant.
func NewI2(p Params) Invariant { return &i2{p: p} }

func (i *i2) ID() string { return "I2" }

func (i *i2) Grounding() string {
	return "FI-03 — fail-safe latching permanently to zero export, so that a device which " +
		"correctly protected the grid during an outage never resumed producing afterwards."
}

func (i *i2) Statement() string {
	return "With control authority lost or expired, the device converges to the configured " +
		"failsafe within its stated deadline, and leaves failsafe when authority legitimately " +
		"returns. PARTIAL: the convergence half needs the configured failsafe and deadline, " +
		"which the device does not publish, so it runs only when given -param failsafe_wmaxlimpct " +
		"and -param failsafe_deadline and SKIPs otherwise. The release half runs unconditionally " +
		"and encodes NO promptness threshold — the gateway's 15-minute backoff promises none — so " +
		"it reports PENDING while a latched device has not yet released and is resolved to FAIL " +
		"only by the run ending with it still latched."
}

func (i *i2) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	authFaults := obs.Faults.Of(ClassAuthorityLoss)
	if len(authFaults) == 0 {
		return skipf("the campaign has armed no authority-loss fault, so neither convergence nor release is under test"), nil
	}

	res := Result{Verdict: Pass}
	// I2's two arms are two different findings and must never share an
	// identity: "the device never REACHED the failsafe" and "the device never
	// LEFT it" are opposite defects, and only the second is FI-03. The device
	// is the identity within each arm; the elapsed times and the observed
	// setpoint are corroboration and are kept out (see [keyer]).
	key := keysOf(&res)

	convV, convChecked, convFacts, convReason, convDev := i.convergence(w, obs)
	res.Checked += convChecked
	res.Verdict = Worse(res.Verdict, convV)
	res.Facts = append(res.Facts, convFacts...)
	if convV != Pass {
		key.note(convV, "failsafe-not-reached:%s", convDev)
	}

	relV, relChecked, relFacts, relReason, relDev := i.release(w, obs)
	res.Checked += relChecked
	res.Verdict = Worse(res.Verdict, relV)
	res.Facts = append(res.Facts, relFacts...)
	if relV != Pass {
		key.note(relV, "failsafe-latched:%s", relDev)
	}

	switch res.Verdict {
	case Fail:
		res.Reason = firstNonEmpty(convReason, relReason)
		if convV == Fail && relV == Fail {
			res.Reason = convReason + "; and " + relReason
		}
	case Pending:
		res.Reason = firstNonEmpty(relReason, convReason)
	case Warn:
		res.Reason = firstNonEmpty(convReason, relReason)
	}
	if res.Checked == 0 {
		return skipf("%s", firstNonEmpty(convReason, relReason,
			"neither arm was assertable: no failsafe parameters supplied and no authority-loss fault has been cleared yet")), nil
	}
	if res.Verdict == Pass {
		res.Assertions = append(res.Assertions, narrate(
			"the device held failsafe while authority was lost and released it when authority returned",
			"compare each DER's own WMaxLimPct against the configured failsafe across the authority-loss window",
			Pass, fmt.Sprintf("%d sub-claims asserted across %d authority-loss faults", res.Checked, len(authFaults))))
	}
	return res, nil
}

// convergence checks that every DER sits at the configured failsafe once the
// stated deadline has passed with authority still lost. Its last return value
// is the DEVICE the finding is about — the identity half of [Result.Key].
func (i *i2) convergence(w *World, obs *Observation) (Verdict, int, []Fact, string, string) {
	fs, okFS := i.p.Float("failsafe_wmaxlimpct")
	deadline, okDL := i.p.Duration("failsafe_deadline")
	if !okFS || !okDL {
		return Pass, 0, nil, "convergence arm needs -param failsafe_wmaxlimpct and -param failsafe_deadline " +
			"(the DUT publishes neither), so it was not asserted", ""
	}
	active := obs.Faults.ActiveOf(obs.At, ClassAuthorityLoss)
	if len(active) == 0 {
		return Pass, 0, nil, "no authority-loss fault is in force, so convergence is not under test right now", ""
	}
	// The deadline runs from the EARLIEST authority-loss fault still in force:
	// a second, later outage does not restart the clock on a device that should
	// already have converged.
	earliest := active[0].Armed
	for _, f := range active {
		if f.Armed.Before(earliest) {
			earliest = f.Armed
		}
	}
	elapsed := obs.At.Sub(earliest)
	if elapsed < deadline {
		return Pass, 0, nil, fmt.Sprintf("still inside the stated %s convergence deadline (%s elapsed)", deadline, dur(elapsed)), ""
	}

	checked := 0
	var facts []Fact
	verdict := Pass
	reason := ""
	device := ""
	for _, v := range derViews(obs) {
		cmd, ok := commandOf(v.Unit.Commands(v.Source), "WMaxLimPct")
		if !ok || !cmd.Raw.Known() {
			continue
		}
		checked++
		if cmd.Enabled && math.Abs(cmd.Raw.Val-fs) <= math.Max(0.5, math.Abs(fs)*i.p.Tol.Rel) {
			continue
		}
		verdict = Fail
		facts = append(facts,
			F(v.Label+".WMaxLimPct.raw", "%", v.Source, "%s", trimFloat(cmd.Raw.Val)),
			F(v.Label+".WMaxLimPct.enabled", "", v.Source, "%t", cmd.Enabled),
			F(v.Label+".failsafe_expected", "%", "-param failsafe_wmaxlimpct", "%s", trimFloat(fs)),
			F(v.Label+".authority_lost_for", "s", "manifest", "%s", dur(elapsed)),
			F(v.Label+".deadline", "s", "-param failsafe_deadline", "%s", dur(deadline)),
		)
		if reason == "" {
			reason = fmt.Sprintf(
				"authority has been lost for %s (deadline %s) but %s is at WMaxLimPct=%s%% (enabled=%t), "+
					"not the configured failsafe of %s%%",
				dur(elapsed), dur(deadline), v.Label, trimFloat(cmd.Raw.Val), cmd.Enabled, trimFloat(fs))
			device = v.Label
		}
	}
	if checked == 0 {
		return Pass, 0, nil, "no DER published a readable WMaxLimPct to compare against the failsafe", ""
	}
	return verdict, checked, facts, reason, device
}

// release checks that a device which entered failsafe leaves it once authority
// legitimately returns. It is Pending while waiting, because the product never
// promised how fast. Its last return value is the DEVICE the finding is about —
// the identity half of [Result.Key].
func (i *i2) release(w *World, obs *Observation) (Verdict, int, []Fact, string, string) {
	restored, ok := obs.Faults.LatestCleared(func(f Fault) bool { return f.Class == ClassAuthorityLoss })
	if !ok {
		return Pass, 0, nil, "no authority-loss fault has been cleared yet, so release is not under test", ""
	}
	if obs.At.Before(restored) {
		return Pass, 0, nil, "authority was restored after this observation", ""
	}
	if !obs.HeadEnd.Reachable {
		return Pass, 0, nil, "the head-end is unreachable, so there is no evidence authority actually returned", ""
	}
	// Authority has genuinely returned only if the head-end is serving
	// something for the device to obey.
	wanted, wantOK := i.wantedLimit(obs)
	if !wantOK {
		return Pass, 0, nil, "the head-end serves no active control since authority returned, so the device is " +
			"correct to keep doing what it was doing", ""
	}

	fs, okFS := i.p.Float("failsafe_wmaxlimpct")
	checked := 0
	var facts []Fact
	pendingReason := ""
	device := ""
	for _, v := range derViews(obs) {
		cmd, ok := commandOf(v.Unit.Commands(v.Source), "WMaxLimPct")
		if !ok || !cmd.Raw.Known() {
			continue
		}
		checked++
		atFailsafe := okFS && cmd.Enabled &&
			math.Abs(cmd.Raw.Val-fs) <= math.Max(0.5, math.Abs(fs)*i.p.Tol.Rel)
		heldSinceRestore := i.unchangedSince(w, restored, v.Device, cmd.Raw.Val)
		// The device has released when it is no longer sitting at the failsafe,
		// or (with no failsafe parameter) when its setpoint has moved at all
		// since authority returned.
		if okFS && !atFailsafe {
			continue
		}
		if !okFS && !heldSinceRestore {
			continue
		}
		facts = append(facts,
			F(v.Label+".WMaxLimPct.raw", "%", v.Source, "%s", trimFloat(cmd.Raw.Val)),
			F(v.Label+".authority_restored_at", "", "manifest", "%s", restored.Format(time.RFC3339)),
			F(v.Label+".since_restore", "s", "manifest", "%s", dur(obs.At.Sub(restored))),
			F(v.Label+".head_end_wants", "W", obs.HeadEnd.Source, "%s", trimFloat(wanted)),
		)
		if pendingReason == "" {
			pendingReason = fmt.Sprintf(
				"authority returned %s ago and the head-end is serving an active control (%s W), but %s is still "+
					"holding WMaxLimPct=%s%% — no promptness threshold is applied; the run ending in this state is the failure",
				dur(obs.At.Sub(restored)), trimFloat(wanted), v.Label, trimFloat(cmd.Raw.Val))
			device = v.Label
		}
	}
	if checked == 0 {
		return Pass, 0, nil, "no DER published a readable WMaxLimPct to judge release by", ""
	}
	if pendingReason != "" {
		return Pending, checked, facts, pendingReason, device
	}
	return Pass, checked, nil, "", ""
}

// wantedLimit returns the active-power limit the head-end is presently serving,
// in watts, if any control covers now.
func (i *i2) wantedLimit(obs *Observation) (float64, bool) {
	for _, p := range obs.HeadEnd.Programs {
		for _, c := range p.Active {
			if !c.Covers(obs.HeadEnd.ServerTime) && !c.Covers(obs.At) {
				continue
			}
			for _, ax := range c.Base.Axes() {
				if ax.Unit == UnitWatt {
					return ax.Value, true
				}
			}
		}
	}
	return 0, false
}

// unchangedSince reports whether a device's WMaxLimPct has held the same value
// at every retained observation since t.
func (i *i2) unchangedSince(w *World, t time.Time, device string, now float64) bool {
	seen := 0
	for _, o := range w.Since(t) {
		d, ok := o.DERs[device]
		if !ok || !d.Reachable {
			continue
		}
		cmd, ok := commandOf(d.Unit.Commands(d.Source), "WMaxLimPct")
		if !ok || !cmd.Raw.Known() {
			continue
		}
		seen++
		if math.Abs(cmd.Raw.Val-now) > 0.5 {
			return false
		}
	}
	return seen >= 2
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
