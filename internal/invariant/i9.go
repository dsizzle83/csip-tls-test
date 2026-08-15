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
	// The identity is the CHANNEL that did not come back, named by the fault's
	// target and kind rather than by its [Fault.ID]. The ID looks stable and is
	// not: it embeds the arm-order index (`target.kind#n`), which renumbers
	// between runs of the same seed and again under every shrink subset — so an
	// ID-keyed signature would stop matching exactly when the shrinker needs it
	// to. The elapsed times and the witness detail stay out too. See [keyer].
	key := keysOf(&res)
	var blind []string
	for _, f := range cleared {
		state, at, detail := i.recovered(w, obs, f)
		elapsed := obs.At.Sub(f.Cleared)

		// A channel whose recovery CANNOT BE OBSERVED is not a channel that
		// failed to recover. Conflating the two is the single most dangerous
		// mistake available to this invariant: an unobservable channel would go
		// Pending, stay Pending, and Finalize would resolve it into a P1 FAIL
		// against a device that did nothing wrong — the harness's blindness
		// reported as the device's defect. So it does not count as a sub-claim
		// at all, and if NOTHING was observable the whole check SKIPs naming
		// what it was missing.
		if state == recoveryUnobservable {
			blind = append(blind, fmt.Sprintf("%s (%s)", f.ID, detail))
			continue
		}
		res.Checked++
		if state == recoveryDone {
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
			key.note(Fail, "no-recovery:%s:%s", f.Target, f.Kind)
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
		key.note(Pending, "no-recovery:%s:%s", f.Target, f.Kind)
		res.Facts = append(res.Facts, facts...)
		if res.Reason == "" {
			res.Reason = fmt.Sprintf("%s was cleared %s ago and the %s channel has not recovered yet (%s); no "+
				"promptness threshold is applied — the run ending in this state is the failure",
				f.ID, dur(elapsed), f.Target, detail)
		}
	}
	if res.Checked == 0 {
		return skipf("every cleared recoverable fault was on a channel whose recovery this run cannot observe, "+
			"so eventual recovery was not under test: %s", joinComma(blind)), nil
	}
	if len(blind) > 0 {
		res.Facts = append(res.Facts, F("i9.unobservable", "count", "monitor", "%d", len(blind)))
	}
	return res, nil
}

// readableBefore reports whether the DUT's northbound was reachable at any
// retained observation strictly before t — the precondition for treating a
// later unreachability as a failure to recover rather than as a channel that
// never worked.
func readableBefore(w *World, t time.Time) bool {
	for _, o := range w.History() {
		if o.At.Before(t) && o.DUT.Reachable {
			return true
		}
	}
	return false
}

// recoveryState is the tri-state this invariant must distinguish. The middle
// value is the whole reason the type exists: "I cannot see whether it
// recovered" and "it has not recovered" are different claims, and only the
// second one is ever a finding.
type recoveryState int

const (
	// recoveryDone — an independent witness showed the channel alive after the
	// clear.
	recoveryDone recoveryState = iota
	// recoveryWaiting — the witness exists, is readable, and shows nothing new.
	// This is the only state that may become a violation.
	recoveryWaiting
	// recoveryUnobservable — this run has no witness for the channel at all.
	// Never a violation; the check SKIPs saying so.
	recoveryUnobservable
)

// recovered reports whether the channel a fault affected shows independent
// evidence of life after the fault cleared, or whether this run can see at all.
func (i *i9) recovered(w *World, obs *Observation, f Fault) (recoveryState, time.Time, string) {
	switch {
	case f.Target == "head-end" || f.Target == "headend":
		if !obs.HeadEnd.Reachable {
			// A head-end fault has been cleared and the head-end is STILL
			// unreachable. That is not blindness — the witness is the head-end
			// itself, and its continued absence is exactly the non-recovery
			// this invariant is looking for.
			return recoveryWaiting, time.Time{}, "the head-end itself is still unreachable after the clear"
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
			return recoveryDone, newest, fmt.Sprintf("the head-end received something from the DUT at %s", newest.Format(time.RFC3339))
		}
		if len(obs.HeadEnd.Reports) == 0 && len(obs.HeadEnd.Alerts) == 0 {
			// The head-end is reachable but has never received anything from
			// the DUT, in this run or before it. There is no "before" to
			// compare against, so an absence now proves nothing.
			return recoveryUnobservable, time.Time{},
				"the head-end has no record of the DUT at all, so there is no baseline against which a resumption could be seen"
		}
		return recoveryWaiting, time.Time{}, "the head-end has received nothing from the DUT since the clear"

	case f.Target == "gateway" || f.Target == "dut":
		for _, o := range w.Since(f.Cleared) {
			if o.DUT.Reachable {
				return recoveryDone, o.At, "the DUT's northbound register map became readable again"
			}
		}
		if len(w.Since(f.Cleared)) == 0 {
			return recoveryUnobservable, time.Time{},
				"the run ended before any observation was taken after the clear"
		}
		// "It has not come back" is only a finding if it was ever THERE. A
		// channel that was already unreadable before the fault was armed cannot
		// have failed to RECOVER from that fault — there is nothing to recover
		// to, and reporting one would blame the adversary for a condition it
		// did not create.
		//
		// This is the third place in this invariant where "I cannot see" had to
		// be separated from "it is broken", and it was found the same way as
		// the others: a live campaign produced a confident P1 whose own
		// baseline tick showed the witness had been blind from the first
		// second. The pattern is worth naming — an invariant that does not
		// check its own preconditions reports the bench as the device.
		if !readableBefore(w, f.Armed) {
			return recoveryUnobservable, time.Time{},
				"the DUT's northbound was never readable in this run, including before the fault was armed, so " +
					"there is no working state for it to have returned to"
		}
		return recoveryWaiting, time.Time{}, "the DUT's northbound has not been readable since the clear"

	default:
		// A named DER: its own request counter must have advanced.
		//
		// The counter is the ONLY witness here, and a device that does not
		// publish one leaves this invariant blind rather than falsified. Saying
		// so — instead of returning a bare "not recovered" that reads
		// identically to a stuck counter — is what keeps a bench arrangement
		// from being reported as a device defect.
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
				return recoveryDone, o.At, fmt.Sprintf("%s saw its request counter advance %d→%d after the clear",
					f.Target, base, d.PollRequests)
			}
		}
		if !haveBase {
			return recoveryUnobservable, time.Time{},
				fmt.Sprintf("%s publishes no request counter, so nothing in this run can witness its recovery", f.Target)
		}
		return recoveryWaiting, time.Time{}, fmt.Sprintf("%s has seen no new request from the DUT since the clear (counter stuck at %d)", f.Target, base)
	}
}
