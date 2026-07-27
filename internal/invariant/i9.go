package invariant

// i9.go — A recoverable outage is recovered from without human intervention, in
// bounded time.
//
// Grounding: the fifteen-minute backoff with no link-up reset. A device that
// backs off exponentially and never notices the interface came back is
// functionally down until somebody restarts it, and everything internal to it
// looks fine.
//
// # The threshold trap, and how this avoids it
//
// The obvious implementation picks a number — "recovery within five minutes" —
// and fails the device when it takes six. That number is an invention. The
// product promises eventual recovery; it explicitly backs off to fifteen
// minutes, and a fifteen-minute reconnect is CORRECT behaviour, not a defect.
// An invariant that failed it would be reporting our expectation as the device's
// bug, and the strategy is explicit that I9 is about eventual recovery, not
// promptness.
//
// So this invariant encodes no default deadline at all. While a cleared,
// recoverable fault has not yet been recovered from, the verdict is [Pending] —
// the claim is not decidable yet — and it carries the elapsed time so an
// operator watching the console sees the clock running. Two things can resolve
// it:
//
//	the channel recovers, and it becomes PASS with the observed recovery time
//	recorded (which is how this suite accumulates evidence about what the
//	device's real recovery times ARE, without ever having asserted one); or
//
//	the run ends with it still unrecovered, and Monitor.Finalize turns the
//	Pending into a FAIL. "The run ended and it never came back" needs no
//	threshold; it is a fact.
//
// An operator who DOES have a contractual recovery bound can supply it as
// -param recovery_budget, and then exceeding it is a FAIL during the run. That
// is the only way a deadline enters this invariant: somebody who is entitled to
// state one states it.
//
// # What "recovered" means per target
//
// Each is an independent witness of the channel, never the DUT's own opinion of
// it:
//
//	head-end  — the head-end has received something new FROM the DUT since the
//	            fault cleared (a report PUT, a response POST).
//	a DER     — that DER's own request counter has advanced since the fault
//	            cleared.
//	gateway   — the DUT's northbound register map is readable again.

import (
	"context"
	"fmt"
	"time"
)

type i9 struct{ p Params }

// NewI9 returns the recovery invariant.
func NewI9(p Params) Invariant { return &i9{p: p} }

func (i *i9) ID() string { return "I9" }

func (i *i9) Grounding() string {
	return "the 15-minute backoff with no link-up reset — a device that stops noticing the " +
		"interface came back is functionally down while looking healthy from inside."
}

func (i *i9) Statement() string {
	return "A recoverable outage is recovered from without human intervention: after the campaign " +
		"clears a fault it declared recoverable, the affected channel resumes — the head-end " +
		"receives something new from the DUT, a DER's own request counter advances, or the " +
		"northbound becomes readable again. NO PROMPTNESS THRESHOLD IS ENCODED: the product backs " +
		"off to fifteen minutes and promises only eventual recovery, so an unrecovered channel is " +
		"reported PENDING with the elapsed time and is resolved to FAIL only by the run ending " +
		"while it is still down. An operator entitled to state a bound may supply -param " +
		"recovery_budget, and only then does exceeding a deadline fail during the run."
}

func (i *i9) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	var cleared []Fault
	for _, f := range obs.Faults.Faults {
		if f.Recoverable && !f.Cleared.IsZero() && !f.Cleared.After(obs.At) {
			cleared = append(cleared, f)
		}
	}
	if len(cleared) == 0 {
		return skipf("the campaign has cleared no fault it declared recoverable, so recovery is not under test"), nil
	}
	budget, hasBudget := i.p.Duration("recovery_budget")

	res := Result{Verdict: Pass}
	for _, f := range cleared {
		res.Checked++
		recovered, at, detail := i.recovered(w, obs, f)
		elapsed := obs.At.Sub(f.Cleared)
		if recovered {
			res.Assertions = append(res.Assertions, narrate(
				fmt.Sprintf("the %s channel recovered after %s was cleared", f.Target, f.Kind),
				"observe the channel's own independent witness for activity after the clear time",
				Pass, fmt.Sprintf("%s recovered %s after the clear (%s)", f.Target, dur(at.Sub(f.Cleared)), detail)))
			res.Facts = append(res.Facts,
				F("i9."+f.ID+".recovery_time", "s", "monitor", "%s", dur(at.Sub(f.Cleared))))
			continue
		}
		facts := []Fact{
			F("i9."+f.ID+".fault", "", "manifest", "%s", f),
			F("i9."+f.ID+".cleared_at", "", "manifest", "%s", f.Cleared.Format(time.RFC3339)),
			F("i9."+f.ID+".unrecovered_for", "s", "monitor", "%s", dur(elapsed)),
			F("i9."+f.ID+".witness", "", "monitor", "%s", detail),
		}
		if hasBudget && elapsed > budget {
			res.Verdict = Fail
			res.Facts = append(res.Facts, append(facts,
				F("i9."+f.ID+".budget", "s", "-param recovery_budget", "%s", dur(budget)))...)
			if res.Reason == "" {
				res.Reason = fmt.Sprintf("%s was cleared %s ago and the %s channel has not recovered, exceeding the "+
					"operator-supplied recovery budget of %s (%s)", f.ID, dur(elapsed), f.Target, dur(budget), detail)
			}
			res.Assertions = append(res.Assertions, narrate(
				fmt.Sprintf("the %s channel recovers after %s is cleared", f.Target, f.Kind),
				"observe the channel's own independent witness for activity after the clear time",
				Fail, res.Reason))
			continue
		}
		res.Verdict = Worse(res.Verdict, Pending)
		res.Facts = append(res.Facts, facts...)
		if res.Reason == "" {
			res.Reason = fmt.Sprintf("%s was cleared %s ago and the %s channel has not recovered yet (%s); no "+
				"promptness threshold is applied — the run ending in this state is the failure",
				f.ID, dur(elapsed), f.Target, detail)
		}
	}
	return res, nil
}

// recovered reports whether the channel a fault affected shows independent
// evidence of life after the fault cleared.
func (i *i9) recovered(w *World, obs *Observation, f Fault) (bool, time.Time, string) {
	switch {
	case f.Target == "head-end" || f.Target == "headend":
		if !obs.HeadEnd.Reachable {
			return false, time.Time{}, "the head-end itself is unreachable, so its record cannot be read"
		}
		newest := time.Time{}
		for _, r := range obs.HeadEnd.Reports {
			if r.Received.After(newest) {
				newest = r.Received
			}
		}
		for _, a := range obs.HeadEnd.Alerts {
			if a.ReceivedAt.After(newest) {
				newest = a.ReceivedAt
			}
		}
		if newest.After(f.Cleared) {
			return true, newest, fmt.Sprintf("the head-end received something from the DUT at %s", newest.Format(time.RFC3339))
		}
		return false, time.Time{}, "the head-end has received nothing from the DUT since the clear"

	case f.Target == "gateway" || f.Target == "dut":
		for _, o := range w.Since(f.Cleared) {
			if o.DUT.Reachable {
				return true, o.At, "the DUT's northbound register map became readable again"
			}
		}
		return false, time.Time{}, "the DUT's northbound has not been readable since the clear"

	default:
		// A named DER: its own request counter must have advanced.
		since := w.Since(f.Cleared)
		var base int
		haveBase := false
		for _, o := range since {
			d, ok := o.DERs[f.Target]
			if !ok || !d.HasPollCount {
				continue
			}
			if !haveBase {
				base, haveBase = d.PollRequests, true
				continue
			}
			if d.PollRequests > base {
				return true, o.At, fmt.Sprintf("%s saw its request counter advance %d→%d after the clear",
					f.Target, base, d.PollRequests)
			}
		}
		if !haveBase {
			return false, time.Time{}, fmt.Sprintf("%s publishes no request counter, so its recovery is not observable", f.Target)
		}
		return false, time.Time{}, fmt.Sprintf("%s has seen no new request from the DUT since the clear (counter stuck at %d)", f.Target, base)
	}
}
