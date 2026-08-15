package suitecsip

// hold.go — "and it was STILL there".
//
// ── The follow-up this closes ───────────────────────────────────────────────
//
// The scalar southbound oracle (basic.go, IW13-001/IW14-003) asks whether the
// DER's own registers came to hold the value the row commanded, and it asks it
// with settleOracle: poll until the effect ARRIVES, return the moment it does.
// That is the right instrument for the mid-propagation race it was built for
// (oracleSettleWindow's three measured latencies), and it is a complete
// statement about arrival and NOTHING WHATEVER about persistence.
//
// For an active-power SETPOINT that is arguably the whole question. For a
// LIMIT it is not. opModMaxLimW does not command a value, it commands a
// CONSTRAINT — "the maximum active power generation level at which the DER may
// operate" — and a constraint that is applied and then quietly relaxed a poll
// cycle later has not been complied with in any sense a certifier would accept.
// A gateway whose arbitration re-derives the desired state each tick and drops
// the ceiling when some other input changes; one whose reversion timer fires
// early because the lease was armed in the wrong units; one that applies the
// limit and then has its southbound write undone by a reconnect — every one of
// those reads as a PASS to an oracle that stops looking the instant it sees the
// number it wanted.
//
// So a MaxLim row asserts BOTH halves: the ceiling arrived, and it was still
// there when the row looked again, N times, across the rest of the row's own
// window.
//
// ── Written in the release-enforcing style ─────────────────────────────────
//
// doc.go's rule: a criterion carrying a row's whole subject gets NO Skip path,
// because Skip is severity 0 in the roll-up and every roll-up raises only — an
// unmeasured row would report the same verdict as a measured one that passed.
// The hold is exactly such a criterion, so every shape it can end in is a
// decided verdict: it did not hold (Fail), the bench went away mid-hold (Fail,
// naming the sample that could not be taken), the arrival oracle never passed
// so there was nothing to hold (Fail, deferring to the arrival verdict), and no
// hold was run at all on a row that declared one (Fail, saying so).
//
// The ONE shape that is not a Fail is a row that declares no hold: those record
// nothing here and the criterion is not built for them at all, which is
// different from a Skip — the criterion is absent from the case rather than
// present and abstaining.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// The Observation.Params keys the hold writes. DISTINCT from the arrival
// oracle's (oracleVerdictParam and friends), never reused, so a bundle shows
// which apparatus produced which half and a test asserting the hold ran cannot
// be satisfied by the arrival read.
const (
	holdVerdictParam  = "iw15.hold_verdict"
	holdObservedParam = "iw15.hold_observed"
	// holdSamplesParam records how many confirming samples were actually
	// taken, so a PASS states its own strength rather than implying one.
	holdSamplesParam = "iw15.hold_samples"
	// holdNotRunParam records that a row declaring a hold did not run one, and
	// why. It is the shape a Skip would have covered, kept as a decided FAIL.
	holdNotRunParam = "iw15.hold_not_run"
)

// holdBinding is the persistence half of an oracled row: how long the value
// must remain, and how often that is checked.
//
// It is a SEPARATE structure from oracleBinding rather than two more fields on
// it, for the reason the curve/droop split follows: it asks a different
// question of the same register, and a row that arms it is making a claim
// ("this is a standing constraint") that a row commanding a setpoint may not
// want to make. Which rows arm it is therefore a per-row decision, visible at
// the registration, and not a property every oracled row silently acquires.
type holdBinding struct {
	// Samples is how many CONFIRMING reads must succeed after arrival. Two is
	// the minimum that says anything — one confirms only that the arrival read
	// was not a transient — and the default below is three.
	Samples int
	// Step is the spacing between them.
	Step time.Duration
	// Why states what a failure of this half MEANS, in the row's own terms, so
	// the verdict is about the control and not about the apparatus.
	Why string
}

// holdDefaults is one definition of the sampling shape, so a row arms the hold
// by declaring the CLAIM and not by choosing numbers.
//
// Three samples at four seconds is ~12 s of extra wall clock on a row whose own
// control is active for 690 s (oracleWindow) and whose settle poll may already
// have spent a poll-cycle window. It is deliberately modest: the budget is
// shared with every other row in a campaign, and the failure modes this is for
// — an arbitration that re-derives and drops the ceiling, a lease that expires
// early — do not need minutes to show themselves, because they are driven by
// the reconciler's own ~10 s tick (oracleSettleWindow records it). A hold that
// spans at least one such tick has seen the mechanism most likely to undo the
// write; the soak is where a longer horizon belongs, and it has one.
var holdDefaults = holdBinding{Samples: 3, Step: 4 * time.Second}

// holdMaxLim is BASIC-010's hold: the commanded ceiling is a standing
// constraint, so it must still be the DER's ceiling when the row looks again.
var holdMaxLim = holdBinding{
	Samples: holdDefaults.Samples,
	Step:    holdDefaults.Step,
	Why: "opModMaxLimW commands a CONSTRAINT rather than a value — sep 2.0.4: \"the maximum active " +
		"power generation level at which an EndDevice may operate\" — and a ceiling that is applied and " +
		"then relaxed while the control is still active has not been complied with. The arrival oracle " +
		"returns the instant the register matches (settleOracle), so on its own it cannot tell a held " +
		"ceiling from one the gateway's next reconcile tick undid",
}

// holdOracle takes the confirming samples.
//
// It is called ONLY after the arrival oracle has passed — a hold over a value
// that never arrived would report the arrival failure twice under two headings
// — and it returns the FIRST sample that did not confirm, because that is the
// evidence: a reader needs to know when the ceiling went away, not merely that
// the last of N reads disagreed.
//
// An Unavailable sample is a FAILURE of this criterion and not an abstention,
// which is the release-enforcing rule applied at the sample level. The arrival
// oracle retries an Unavailable because there it is the not-yet-enabled shape
// it exists to wait out (oracleSettleWindow). Here the value has ALREADY been
// observed in place, so "the DER's register image is no longer readable" is a
// statement that the row can no longer support the claim it is making, and the
// honest verdict is that it did not establish persistence.
func holdOracle(ctx context.Context, h holdBinding, eval func() Finding) Finding {
	n := h.Samples
	if n <= 0 {
		n = holdDefaults.Samples
	}
	step := h.Step
	if step <= 0 {
		step = holdDefaults.Step
	}
	for i := 1; i <= n; i++ {
		select {
		case <-ctx.Done():
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the run was cancelled after %d of %d confirming sample(s), so this row did not establish "+
					"that the commanded value REMAINED in place", i-1, n)}
		case <-time.After(step):
		}
		f := eval()
		switch {
		case f.Unavailable != "":
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"confirming sample %d of %d could not be taken (%s). The value was observed in place "+
					"before this sample, so an unreadable DER here is not the not-yet-applied shape the "+
					"arrival poll waits out — it is this row losing the ability to say the value stayed",
				i, n, f.Unavailable)}
		case f.Verdict != certify.Pass:
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the commanded value ARRIVED and then did NOT REMAIN: confirming sample %d of %d, taken "+
					"%s after the arrival read, no longer holds it — %s",
				i, n, (time.Duration(i) * step).String(), findingObserved(f))}
		}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the commanded value REMAINED in place across %d confirming read(s) spaced %s apart (%s of "+
			"observation after arrival), each an independent read of the DER's own register image",
		n, step, (time.Duration(n) * step).String())}
}

// recordHold runs the hold and writes its result into the observation.
//
// It is given the SAME judge closure the arrival oracle used, built from the
// value Setup actually commanded — never a fresh one built from the binding —
// so the two halves cannot disagree about what was asked for. That is the same
// rule oracleBinding's doc states for the publish/judge pair, applied one level
// down.
func recordHold(ctx context.Context, h holdBinding, params map[string]string,
	arrival Finding, judge func() Finding) {
	if arrival.Verdict != certify.Pass {
		params[holdNotRunParam] = "the commanded value never arrived, so there was nothing to hold: this " +
			"row's verdict rests on the arrival oracle's own finding and no persistence claim is made"
		return
	}
	f := holdOracle(ctx, h, judge)
	params[holdVerdictParam] = string(f.Verdict)
	params[holdObservedParam] = f.Observed
	if f.Verdict == certify.Pass {
		params[holdSamplesParam] = strconv.Itoa(h.Samples)
	}
}

// holdOutcome collapses what recordHold left in the params into ONE decided
// verdict, the same job oracleOutcome does for the arrival half.
//
// Its shapes, in the order they are decided:
//
//	the hold ran and said something          that verdict, with its observation
//	the hold did not run because arrival     Skip-free deferral: the arrival
//	  failed                                 half already carries this row's
//	                                         non-PASS, and reporting it twice
//	                                         would double-count one defect
//	the row declared a hold and neither       Fail — the row claims persistence
//	  key is present                          and did not measure it
func holdOutcome(h *holdBinding, o *Observation) Finding {
	if h == nil || o == nil {
		return Finding{}
	}
	if v := o.Params[holdVerdictParam]; v != "" {
		return Finding{Verdict: certify.Verdict(v), Observed: o.Params[holdObservedParam]}
	}
	if why := o.Params[holdNotRunParam]; why != "" {
		// DEFERRED, not passed. The criterion still reports a non-PASS so the
		// row cannot roll up green on the strength of a hold that never ran;
		// what it does not do is invent a second, independent failure for one
		// underlying defect the arrival criterion already names.
		return Finding{Verdict: certify.Fail, Observed: "no persistence was established: " + why}
	}
	return Finding{Verdict: certify.Fail, Observed: "this row declares that the value it commands must " +
		"REMAIN in place, and no confirming samples were recorded at all — the live phase left neither a " +
		"hold verdict nor a reason it did not run, so the claim is unmeasured. " + h.Why}
}

// critDERValueRemainedAcrossTheWindow is the persistence half's criterion, in
// the release-enforcing style: no Skip path, every shape a decided verdict.
//
// It is a SEPARATE criterion from critDEREffectViaSouthboundOracle rather than
// a stiffening of it, because the two make different claims and a bundle has to
// show which one failed. "The gateway never applied the ceiling" and "the
// gateway applied the ceiling and then let it go" are different defects with
// different owners, and folding them into one criterion would have made the
// second unreportable — which is how it stayed unmeasured.
func critDERValueRemainedAcrossTheWindow(subject string, h *holdBinding, o *Observation) criterion {
	f := holdOutcome(h, o)
	why := ""
	if h != nil {
		why = h.Why
	}
	return criterion{
		Claim: "the DER's own southbound registers STILL held the value " + subject + " commanded when " +
			"this row read them again, across the rest of the row's active window",
		How: "repeated independent reads of the DER's raw SunSpec register image (internal/invariant), " +
			"taken after the arrival oracle first observed the commanded value and judged by the SAME " +
			"comparison against the SAME commanded number, so arrival and persistence cannot disagree " +
			"about what was asked for. " + why,
		LoadBearing: true,
		Tier:        tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}

// holdClause appends the persistence half to a row-level sentence that has
// already stated the arrival half, or the empty string for a row with no hold.
func holdClause(h *holdBinding, o *Observation) string {
	if h == nil || o == nil {
		return ""
	}
	switch {
	case o.Params[holdObservedParam] != "":
		return " HELD: " + o.Params[holdObservedParam]
	case o.Params[holdNotRunParam] != "":
		return " HELD: not established — " + o.Params[holdNotRunParam]
	}
	return " HELD: this row claims the value must remain and recorded no confirming samples at all."
}

// describeHold renders a hold binding for a construction test or a report.
func describeHold(h *holdBinding) string {
	if h == nil {
		return "none"
	}
	return fmt.Sprintf("%d confirming sample(s) spaced %s apart", h.Samples, h.Step)
}

// holdKeys are the params a hold writes, so a test can assert that a row which
// declares one leaves exactly one of them behind.
func holdKeys() []string {
	return []string{holdVerdictParam, holdObservedParam, holdSamplesParam, holdNotRunParam}
}

// holdRecorded reports whether the live phase left any hold record at all.
func holdRecorded(o *Observation) bool {
	if o == nil {
		return false
	}
	for _, k := range holdKeys() {
		if o.Params[k] != "" {
			return true
		}
	}
	return false
}

// holdSummary is a short, single-line rendering for a log or a test failure.
func holdSummary(o *Observation) string {
	if o == nil {
		return "no observation"
	}
	var parts []string
	for _, k := range holdKeys() {
		if v := o.Params[k]; v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return "no hold record"
	}
	return strings.Join(parts, " ")
}
