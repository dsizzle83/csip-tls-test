package suitecsip

// check.go is the body every CSIP check shares, so that no individual check has
// to remember the four things it would be catastrophic to forget:
//
//	1. CLAIM the endpoint, or the check produces no citable evidence at all;
//	2. take a BASELINE of the server's view, or it passes on another test case's
//	   evidence;
//	3. CLEAN UP the fault it armed, whatever happens, or it corrupts every later
//	   test case on a shared bench;
//	4. recover the session and mint the criteria from the CAPTURE, not from what
//	   the live phase thought it saw.
//
// A check therefore declares a spec — what to set up, what to wait for, what to
// assert — and this file runs it.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// defaultWait is the FLOOR of the poll-cycle wait, and the fallback when the
// cadence the DUT actually keeps cannot be read at all.
//
// It used to be the wait, flat, for every row in this suite — and a constant is
// the wrong shape for this number twice over. IEEE 2030.5 §10.2.3 lets a
// non-subscribing client poll as slowly as every 15 minutes, so 90 s is nowhere
// near enough for a DUT at the slow end; and against the bench's own 60 s
// advertisement it is 1.5 periods, which is not margin, it is a coin toss. The
// 2026-08-07 WAN/LAN split soak is the record of what that costs: nine cycles,
// 0-3 FAILs each, flapping across a different handful of BASIC event rows every
// cycle, every one of them "gridsim's request log records no GET /dcap from the
// DUT in this window". None of those was a fact about the DUT.
//
// So the default is now DERIVED from the cadence (see fetchWait) and this is
// only its floor: a wait shorter than 90 s buys nothing and a run whose cadence
// cannot be read at all still fails fast and visibly rather than hanging.
const defaultWait = 90 * time.Second

// waitParam is the operator override for the poll-cycle wait. It outranks the
// derivation entirely — see fetchWait.
const waitParam = "csip.wait"

// waitPeriods, waitSlack and waitCap shape the derived default.
//
// TWO periods, not one, is the whole point: a period that has just elapsed when
// the window opens leaves a whole one inside it, so the wait no longer depends
// on where the run happens to start relative to the DUT's own poll boundary.
// The slack on top absorbs walk duration and RTT jitter (8-40 ms on the bench's
// WiFi leg, and a walk is dozens of round trips).
//
// waitCap exists because the derivation must not be allowed to run away. A
// 2030.5 server may advertise the §10.2.3 maximum of 900 s, and 2x900+30 is
// half an hour PER ROW — a suite run that would never finish. Past the cap the
// honest answer is not a longer default but an operator who has decided to
// spend the time, which is what -param csip.wait is for; the explanation says
// so in as many words when the cap bites.
const (
	waitPeriods = 2
	waitSlack   = 30 * time.Second
	waitCap     = 5 * time.Minute
)

// dutNorthboundConfig and dutDiscoveryField are where the DUT records the FLOOR
// beneath the advertised rate.
//
// The DUT ships in poll_rate_mode "honor": it paces its walk at whatever
// pollRate the server advertises but never polls faster than its own configured
// interval, so the cadence a window has to span is max(advertised, this) — the
// two rules in the order the DUT applies them. Deriving from either alone is a
// way to wait the wrong amount of time, and the bench has been bitten by both
// directions (see certify.ObservationWait's doc).
const (
	dutNorthboundConfig = "/etc/lexa/northbound.json"
	dutDiscoveryField   = "discovery_interval_s"
)

// waitBudgetReserve is what fetchWait keeps back from the check's own -timeout
// for everything in the live phase that is not a poll-cycle wait: the baseline
// and post-wait snapshots, the subscription read the notification claim needs,
// the PostWait probe, and the admin round-trips Setup and Change make.
//
// Without it, widening the default would trade one bench artefact for another:
// a check killed by -timeout produces no criteria at all, which is a worse
// bundle than a check whose window was slightly too short.
const waitBudgetReserve = 45 * time.Second

// waitWhyParam records the derivation in the observation's params, so the
// number travels with the evidence and not only with the run log.
const waitWhyParam = "csip.wait_derivation"

// changeSettle is how long a check keeps observing after it makes the
// procedure's post-subscription change. A Notification is dispatched
// synchronously with the mutation, so this is not waiting for the push — it is
// waiting for the DUT's answer to land in the server's delivery record and for
// the follow-up GET the procedures ask for.
const changeSettle = 15 * time.Second

// changeWaitFullCycle is spec.ChangeWait's request for a second FULL poll-cycle
// wait — the same duration, and the same -param csip.wait override, as the
// first one.
//
// It is a negative sentinel rather than a bool so that ChangeWait's zero value
// keeps meaning "the short settle", which is what most rows want: a row whose
// change the client must POLL for and a row whose change it merely ANSWERS are
// waiting for different things, and giving the second one a poll cycle would
// multiply every campaign's runtime for nothing.
const changeWaitFullCycle = -1

// changeFailed is the params key recording that the post-subscription change
// could not be made, so a criterion depending on it says so rather than
// reporting the absence of a Notification as a DUT fault.
const changeFailed = "csip.change_failed"

// endpointClaimReason is the argument, printed in every bundle this suite
// produces, for why attributing frames by endpoint rather than by connection
// 4-tuple is sound here.
const endpointClaimReason = "the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the " +
	"DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame " +
	"to or from the CSIP server endpoint during this check's interval. That is sound on this bench because " +
	"the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be " +
	"sound if a second conformance run were driving the same simulator concurrently, which is why live runs " +
	"in this campaign are serialized"

// fetchWait decides how long this check's live phase gives the DUT to poll, and
// returns the sentence that tells a bundle reader why the window was that wide.
//
// The precedence, and why the order is not arbitrary:
//
//  1. `-param csip.wait` is used EXACTLY as given — not floored, not capped,
//     not trimmed to fit -timeout. An operator who passes it has decided what
//     their bench needs, and the long-window rows (BASIC-029, CORE-022,
//     CORE-023) are run as separate invocations precisely so they can. A
//     harness that "helpfully" shortened an 8-minute window an operator asked
//     for would silently invalidate the run they were paying for.
//  2. A spec that names its own Wait keeps it, for the same reason.
//  3. Otherwise the wait is derived from the cadence the DUT actually keeps —
//     max(the pollRate gridsim advertises, the DUT's own configured floor),
//     which is what a poll_rate_mode "honor" client does — as
//     waitPeriods x cadence + waitSlack, floored at defaultWait and capped at
//     waitCap. certify.ObservationWait is the shared implementation of that
//     rule and of the sentence naming which source won; this suite supplies
//     the shape (2 periods, 30 s, [90 s, 5 m]) and the config location.
//  4. A DERIVED wait is then trimmed, if it must be, to fit the check's own
//     -timeout — but never below defaultWait, so this can never produce a
//     window narrower than the fixed 90 s it replaced.
func fetchWait(ctx context.Context, rc *certify.RunCtx, s spec) (time.Duration, string) {
	if v, ok := rc.Param(waitParam); ok {
		d, err := time.ParseDuration(v)
		switch {
		case err != nil:
			rc.Logf("ignoring -param %s=%q: %v", waitParam, v, err)
		case d <= 0:
			rc.Logf("ignoring -param %s=%q: %s is not a positive duration", waitParam, v, d)
		default:
			return d, fmt.Sprintf("%s, set explicitly with -param %s=%s. An operator's own value is used "+
				"verbatim: it is neither raised to the %s floor, nor capped at %s, nor trimmed to fit the "+
				"check's -timeout", d, waitParam, v, defaultWait, waitCap)
		}
	}
	if s.Wait > 0 {
		return s.Wait, fmt.Sprintf("%s, fixed by this test case's own spec rather than derived from the "+
			"cadence", s.Wait)
	}

	wait, why := rc.ObservationWait(ctx, certify.ObservationSpec{
		What:       "IEEE 2030.5 discovery interval",
		ConfigPath: dutNorthboundConfig,
		Field:      dutDiscoveryField,
		// This is the northbound walk, whose rate the SERVER sets. Leaving this
		// false would derive every window in this suite from a FLOOR the DUT is
		// entitled to poll more slowly than.
		ServerPollRate: true,
		Fallback:       defaultWait,
		Periods:        waitPeriods,
		Slack:          waitSlack,
		Min:            defaultWait,
		Max:            waitCap,
		// Param is deliberately empty: the operator override is handled above,
		// so that it can bypass the deadline trim below. Passing it here would
		// return the operator's value through the clamping path instead.
		Param: "",
	})

	fitted, trim := fitWaitToBudget(wait, deadlineRemaining(ctx), liveOverhead(s), waitSlots(s))
	if trim != "" {
		why += " — " + trim
	}
	return fitted, why
}

// waitSlots reports how many FULL poll-cycle waits this spec's live phase
// performs. Most rows wait once, for the DUT to fetch what Setup published; the
// rows whose post-subscription change is something the DUT must FETCH rather
// than merely ANSWER ask for a second full cycle (changeWaitFullCycle), and
// those two waits share one -timeout.
func waitSlots(s spec) int {
	if s.Change != nil && s.ChangeWait == changeWaitFullCycle {
		return 2
	}
	return 1
}

// liveOverhead estimates everything in the live phase that is not a full
// poll-cycle wait, so the budget arithmetic is about the time actually left.
func liveOverhead(s spec) time.Duration {
	over := waitBudgetReserve
	if s.Change != nil && s.ChangeWait >= 0 {
		if s.ChangeWait > 0 {
			over += s.ChangeWait
		} else {
			over += changeSettle
		}
	}
	return over
}

// deadlineRemaining is how much of the check's own -timeout is left, or 0 when
// the check is running without one (a unit test, or a runner with no timeout),
// in which case there is no budget to fit into.
func deadlineRemaining(ctx context.Context) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	if left := time.Until(dl); left > 0 {
		return left
	}
	return 0
}

// fitWaitToBudget trims a DERIVED wait so that the slots that have to share the
// check's remaining -timeout still fit inside it, and returns the sentence
// saying so — or "" when the derivation was affordable as it stood.
//
// It never trims below defaultWait. That floor is what makes this change
// strictly safe: whatever the budget says, the window is at least the fixed
// 90 s it replaced, so a check that fits today still fits. A spec whose two
// full cycles cannot fit even at the floor is a run whose -timeout was already
// too small for it before this derivation existed.
func fitWaitToBudget(wait, remaining, overhead time.Duration, slots int) (time.Duration, string) {
	if remaining <= 0 || slots <= 0 {
		return wait, ""
	}
	perSlot := (remaining - overhead) / time.Duration(slots)
	if perSlot < defaultWait {
		perSlot = defaultWait
	}
	if perSlot >= wait {
		return wait, ""
	}
	return perSlot, fmt.Sprintf("the derivation asked for %s, and this check has %s of its -timeout left to "+
		"spend across %d full poll-cycle wait(s) plus about %s of other live-phase work, so the wait is the "+
		"%s that fits and NOT the %d periods the cadence asks for. A window this check chose for its own "+
		"deadline rather than for the DUT's cadence is weaker evidence: raise -timeout, or set -param %s "+
		"explicitly, to get the derived window", wait, remaining.Round(time.Second), slots,
		overhead.Round(time.Second), perSlot.Round(time.Second), waitPeriods, waitParam)
}

// spec declares one check's live phase and its pass criteria.
// specWant returns the wait predicate for this run, or nil when the spec has no
// Want or its Want yields no predicate for this baseline. A nil result means
// "take the AwaitWalk path"; it must never be handed to Await, which would
// panic on the first want(view).
func specWant(s spec, base ServerView) func(ServerView) bool {
	if s.Want == nil {
		return nil
	}
	return s.Want(base)
}

type spec struct {
	// Setup drives the bench into the state the procedure requires. It may
	// stash facts for the citation phase in params. A returned error means the
	// test could not be carried out, which the runner records as a FAIL saying
	// no conclusion about the DUT can be drawn.
	Setup func(ctx context.Context, d *Driver, params map[string]string) error

	// Want builds the wait predicate from the baseline. A nil Want — OR a Want
	// that RETURNS a nil predicate for this run, as the aggregator's does when the
	// scenario has no lifecycles — waits for one fresh discovery walk, which is
	// what most rows need. specWant collapses the two nils into one.
	Want func(base ServerView) func(ServerView) bool

	// Wait overrides the poll-cycle wait for this check.
	Wait time.Duration

	// PostWait is a read-only observation taken right after the live phase's
	// wait for the DUT's poll cycle (or Await predicate) is done, and BEFORE
	// Change. Unlike Change it runs unconditionally — it does not require
	// gridsim's admin API (d.Available()) — because its lever is typically
	// something else entirely: rc.Gateway, the read-only -gateway-ssh
	// introspection channel, for a fact that is internal DUT state and not
	// wire-observable at all (CORE-005's clock-adoption probe is the first
	// consumer). A returned error is recorded in Params under whatever key the
	// caller chose and never fatal: a probe that could not be taken is a bench
	// fact the criteria should report, not a reason to abandon the evidence
	// already collected from the wire.
	PostWait func(ctx context.Context, d *Driver, params map[string]string) error

	// Change is the mutation the procedure makes AFTER the client has taken up
	// what Setup put there, and it exists because half the aggregator rows
	// cannot be driven without it.
	//
	// Every subscription row has the same shape: the client subscribes, and
	// THEN the server changes the subscribed resource so a Notification is
	// owed. A mutation performed in Setup happens before the DUT has POSTed
	// anything, so it matches no subscription and pushes nothing — the row
	// would report "the server pushed no Notification" forever, on a bench that
	// works. Change runs after the wait, when the subscription the DUT made
	// during this window exists to be matched.
	//
	// It is given the same params map as Setup and its failure is recorded, not
	// fatal: a lever that could not be pulled is a bench fact the criteria
	// should report, not a reason to abandon the evidence already collected.
	Change func(ctx context.Context, d *Driver, params map[string]string) error

	// ChangeWait is how long to keep observing after Change. Zero uses
	// changeSettle. It is short by design: a Notification is dispatched
	// synchronously with the mutation, so what this waits for is the DUT's
	// ANSWER and its follow-up GET, not the push.
	//
	// changeWaitFullCycle asks for a second full poll-cycle wait instead, for
	// the rows whose change is something the DUT must FETCH.
	ChangeWait time.Duration

	// Cleanup always runs, including on error and on a cancelled context. It is
	// given a context that is NOT the check's, so a check killed by its timeout
	// still disarms what it armed.
	Cleanup func(ctx context.Context, d *Driver)

	// Criteria are the pass criteria, evaluated in the citation phase.
	Criteria func(o *Observation) []criterion

	// Verdict, when non-nil, declares the case's LIVE verdict from the
	// observation the live phase built, independently of anything the citation
	// phase can recover from the capture. An empty return declares nothing and
	// leaves the verdict entirely to the criteria, which is what every spec
	// without one already does.
	//
	// It exists because a criterion is not a verdict route (IW14-003). The
	// citation phase can only assert what it can hang on a recovered session:
	// criterion.assert reaches its Wire evaluator only when RecoverSession
	// produced a Transcript, so a criterion carrying a DECIDED live finding —
	// the southbound oracle's FAIL — silently became a SkipAssertion in any run
	// whose capture yielded no session, and a SKIP cannot dent a case verdict
	// (Result.rollUp and worstOf are raise-only). The one thing that survives a
	// missing capture is the declared Result.Verdict, which registry.go
	// documents as stricter-only, so a live FAIL declared here can be raised by
	// the citation phase and never lowered by it.
	Verdict func(o *Observation) certify.Verdict

	// Notes renders the test case's prose line in the bundle.
	Notes func(o *Observation) string

	// RequiresGridSim declares that the check cannot run at all without the
	// admin API. Most can: the handshake tier needs only the capture.
	RequiresGridSim bool
}

// run executes a spec as a certify.Check.
func run(ctx context.Context, rc *certify.RunCtx, s spec) (certify.Result, error) {
	target, err := certify.AddrPort(rc.Targets.GridSim)
	if err != nil {
		return certify.Skipped("the bench's 2030.5 server address %q is not an ip:port: %v",
			rc.Targets.GridSim, err), nil
	}
	if err := rc.ClaimEndpointDuring("tcp", target, endpointClaimReason); err != nil {
		return certify.Result{}, fmt.Errorf("claim the CSIP server endpoint: %w", err)
	}

	d := NewDriver(rc)
	if s.RequiresGridSim && !d.Available() {
		return certify.Skipped("this test case needs gridsim's admin API to create its precondition, " +
			"and no admin URL was configured (-gridsim-admin)"), nil
	}
	if s.Cleanup != nil {
		// A context detached from the check's own deadline: a check killed by
		// -timeout must still disarm the fault it armed on a shared bench.
		defer func() {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			s.Cleanup(cctx, d)
		}()
	}

	obs := &Observation{Case: rc.Case, Params: map[string]string{}}
	base := d.Snapshot(ctx)
	// The first snapshot of the run fixes where this run's DER self-reports
	// begin in gridsim's append-only, cross-campaign log.
	markRunBaseline(base)
	obs.Server = base

	if s.Setup != nil {
		if err := s.Setup(ctx, d, obs.Params); err != nil {
			return certify.Result{}, fmt.Errorf("set up the procedure's precondition on the bench: %w", err)
		}
	}

	// The wait is decided AFTER Setup, deliberately: Setup is what publishes the
	// thing the DUT has to fetch, so the window that matters starts here, and
	// the -timeout budget the derivation fits into is what Setup left behind.
	wait, waitWhy := fetchWait(ctx, rc, s)
	obs.Params[waitWhyParam] = waitWhy
	rc.Logf("poll-cycle window for this check: %s", waitWhy)

	var view ServerView
	var waited time.Duration
	var satisfied bool
	if d.Available() {
		// A spec may carry a Want that returns a nil predicate for THIS run — the
		// aggregator's Want yields nil when the scenario has no lifecycles to wait
		// on. That is not "wait forever on nothing"; it is the AwaitWalk case, the
		// same fallback taken when a spec carries no Want at all. Deciding it here
		// keeps a nil predicate from ever reaching Await (where it would panic on
		// the first want(view) — see runs/shakedown-20260729T003843, AGG-002).
		if want := specWant(s, base); want != nil {
			view, waited, satisfied = d.Await(ctx, wait, want)
		} else {
			view, waited, satisfied = d.AwaitWalk(ctx, base, wait)
		}
		obs.Server = view.Since(base)
		obs.Server.Available = view.Available
		obs.Server.BaseURL = view.BaseURL
		obs.Server.Status = view.Status
		obs.Server.Errors = view.Errors
		obs.Server.RunDERPuts = derPutsInRun(view)
	} else {
		// No admin API: nothing to wait for and nothing to observe server-side.
		// The handshake tier still works, so the check is not pointless — but it
		// must wait anyway, or the capture window closes before the DUT polls.
		if err := rc.Sleep(ctx, wait); err != nil {
			return certify.Result{}, err
		}
		waited = wait
	}
	obs.Waited, obs.Satisfied = waited, satisfied
	rc.Logf("waited %s for the DUT's poll cycle (predicate satisfied: %t)", waited.Round(time.Second), satisfied)

	if s.PostWait != nil {
		if err := s.PostWait(ctx, d, obs.Params); err != nil {
			rc.Logf("post-wait observation failed: %v", err)
		}
	}

	// The endpoint claim goes in BEFORE the change: a Notification the change
	// causes is dispatched synchronously, so a claim made afterwards would be
	// opened after the frames it is supposed to attribute had already passed.
	claimNotificationEndpoints(ctx, rc, d, obs)

	if s.Change != nil && d.Available() {
		if err := s.Change(ctx, d, obs.Params); err != nil {
			obs.Params[changeFailed] = err.Error()
			rc.Logf("the procedure's post-subscription change could not be made: %v", err)
		}
		settle := s.ChangeWait
		switch {
		case settle == 0:
			settle = changeSettle
		case settle < 0:
			settle = wait
		}
		if err := rc.Sleep(ctx, settle); err == nil {
			after := d.Snapshot(ctx)
			obs.Server = after.Since(base)
			obs.Server.Available, obs.Server.BaseURL = after.Available, after.BaseURL
			obs.Server.Status, obs.Server.Errors = after.Status, after.Errors
			obs.Server.RunDERPuts = derPutsInRun(after)
			obs.Waited = waited + settle
		}
	}

	notes := ""
	if s.Notes != nil {
		notes = s.Notes(obs)
	}
	// Every row's prose already says how long it waited; this says why that was
	// the number. The pair is what makes an empty window interpretable — "no
	// GET /dcap in 1m30s" is only a finding about the DUT if the reader can see
	// that 1m30s was more than the cadence, and until 2026-08-07 it was not.
	if waitWhy != "" {
		if notes != "" {
			notes += "; "
		}
		notes += "poll-cycle window: " + waitWhy
	}

	// A spec that can decide something from the live phase alone says so here,
	// before the capture is ever opened — see spec.Verdict. A nil Verdict (every
	// spec but the oracled inverter-control rows) leaves this empty, which is
	// exactly what this function returned before.
	var declared certify.Verdict
	if s.Verdict != nil {
		declared = s.Verdict(obs)
	}

	return certify.Result{
		Verdict: declared,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			t, rerr := RecoverSession(ev, target)
			if rerr != nil {
				obs.NoSession = rerr.Error()
			} else {
				obs.Transcript = t
			}
			if s.Criteria == nil {
				return nil, fmt.Errorf("suitecsip: %s declared no criteria", rc.Case.UID)
			}
			return mint(ev, obs, s.Criteria(obs))
		},
	}, nil
}

// notifyClaimParam records what the notification leg of the capture claim
// managed to attribute, so the fact ends up in the run log rather than only in
// the window's claim list.
const notifyClaimParam = "csip.notification_claim"

// claimNotificationEndpoints adds the SECOND capture claim an aggregator run
// needs: the DUT's inbound notification listener.
//
// # Why one claim is not enough
//
// Every other exchange in this suite happens on a connection the DUT DIALS to
// the bench's 2030.5 server, and run() claims that endpoint at the top. A
// Notification is the one message that goes the other way: the SERVER dials the
// client's notificationURI. Those frames carry a different 4-tuple entirely, so
// under the existing claim they are unattributed background traffic — present
// in the capture, citable by nobody.
//
// # Where the address comes from
//
// It cannot be known statically. The DUT chooses its listener and announces it
// in the <notificationURI> of the Subscription it POSTs, so the only party that
// knows it before the Notification is sent is the SERVER the subscription was
// POSTed to. gridsim publishes it at GET /admin/subscriptions and this reads it
// back — after the wait, because that is when a subscription the DUT made
// during this window exists to be read.
//
// # What it refuses to do
//
// A notificationURI whose host is a NAME rather than an address is not
// resolved here. Resolving it would mean claiming frames on the strength of
// this machine's DNS agreeing with the DUT's, and a claim is an assertion that
// specific frames belong to this check. The URI is logged instead, and the
// notification traffic stays unattributed — visibly, with the reason, rather
// than silently or wrongly.
func claimNotificationEndpoints(ctx context.Context, rc *certify.RunCtx, d *Driver, obs *Observation) {
	subs := d.Subscriptions(ctx)
	if len(subs) == 0 {
		return
	}
	claimed := map[string]bool{}
	var unresolved []string
	for _, s := range subs {
		if s.NotificationURI == "" {
			continue
		}
		ep, err := notificationEndpoint(s.NotificationURI)
		if err != nil {
			unresolved = append(unresolved, fmt.Sprintf("%s (%v)", s.NotificationURI, err))
			continue
		}
		if claimed[ep.String()] {
			continue
		}
		reason := fmt.Sprintf("the DUT's inbound Notification listener, taken from the <notificationURI> of "+
			"the Subscription it POSTed for %s (gridsim GET /admin/subscriptions reports it as %s). A "+
			"Notification is dialled BY the server, so its frames carry neither this check's local port nor "+
			"the 2030.5 server endpoint claimed above, and without this claim they belong to nobody. It is an "+
			"endpoint claim rather than a connection claim for the same reason as the outbound leg: the "+
			"dialling side's ephemeral port is not knowable here",
			s.SubscribedResource, s.NotificationURI)
		if err := rc.ClaimEndpointDuring("tcp", ep, reason); err != nil {
			unresolved = append(unresolved, fmt.Sprintf("%s (%v)", s.NotificationURI, err))
			continue
		}
		claimed[ep.String()] = true
		obs.NotifyEndpoints = append(obs.NotifyEndpoints, ep)
	}

	var parts []string
	if len(claimed) > 0 {
		eps := make([]string, 0, len(claimed))
		for e := range claimed {
			eps = append(eps, e)
		}
		sort.Strings(eps)
		parts = append(parts, "claimed "+strings.Join(eps, ", "))
	}
	if len(unresolved) > 0 {
		parts = append(parts, "NOT claimed, so any Notification traffic to them is unattributed: "+
			strings.Join(unresolved, "; "))
	}
	if len(parts) == 0 {
		return
	}
	msg := "notification listener(s) from the DUT's subscriptions: " + strings.Join(parts, "; ")
	obs.Params[notifyClaimParam] = msg
	rc.Logf("%s", msg)
}

// notificationEndpoint turns a notificationURI into the ip:port a capture claim
// can be made against, or an error saying precisely why it cannot.
func notificationEndpoint(uri string) (netip.AddrPort, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("not a URI: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return netip.AddrPort{}, errors.New("the URI names no host")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("host %q is a name, not an address, and this check will not "+
			"resolve it: a capture claim asserts that particular frames are this test case's evidence, and "+
			"resolving a name here would rest that assertion on this machine's DNS agreeing with the DUT's",
			host)
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return netip.AddrPort{}, fmt.Errorf("the URI names no port and its scheme %q implies none", u.Scheme)
		}
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port %q: %w", port, err)
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(p)), nil
}

// notApplicable is the check registered for every catalog row the §4 profile
// matrix excludes for this DUT.
//
// It is a real registration rather than an omission on purpose. Coverage that
// simply lacked these uids would read as "nobody got to them"; a registered row
// that reports NOT APPLICABLE and quotes the catalog's own applicability_reason
// reads as a decision a reviewer can check against the profile matrix — and
// disagree with, which is the point.
//
// It also prints the row's published ERRATA, and that breadcrumb has already
// earned its keep once. Until 2026-07-28 twenty-eight rows landed here, and
// twenty-two of them were excluded for a single reason: the DUT was scoped as a
// direct DER client while the §4 matrix marked them required for a DER
// AGGREGATOR client. When the owner re-scoped the certification, whoever
// implemented those rows had to read `steps` and `expected` — which are,
// correctly, a verbatim extraction of the UNAMENDED printed procedure — and
// would otherwise have implemented a body Annex A had already corrected. The
// corrections were in front of them, in this note, before the rows went live.
// The six rows still reported here are excluded for reasons no re-scope can
// change: four are §4 rows required of NO profile, and two are about a 2030.5
// server this DUT does not implement.
func notApplicable(_ context.Context, rc *certify.RunCtx) (certify.Result, error) {
	reason := strings.TrimSpace(rc.Case.ApplicabilityReason)
	if reason == "" {
		reason = "the catalog marks this test case inapplicable to this DUT but records no reason"
	}
	return certify.Result{
		Verdict: certify.Skip,
		Notes: fmt.Sprintf("NOT APPLICABLE to this DUT (%s). %s%s",
			roleWord(rc.Case), reason, errataBreadcrumb(rc)),
		OffWire: true,
		OffWireReason: "applicability is a property of the profile matrix in CSIP Conformance Test Procedures " +
			"V1.3 §4 and of what the DUT implements, not of any exchange on the wire. Asserting it from a " +
			"capture is not possible and pretending otherwise would be the dishonest option; the catalog's " +
			"applicability_reason above is the auditable record of the decision",
	}, nil
}

// errataBreadcrumb renders the row's client-relevant published corrections, or
// "" when it has none.
//
// A check MUST honour the errata for the case it implements — running the
// uncorrected step and calling the result a conformance failure would be the
// harness's bug, not the DUT's — and the rows this suite reports NOT APPLICABLE
// have no check to honour them yet. This is the record that survives until one
// exists.
func errataBreadcrumb(rc *certify.RunCtx) string {
	er := rc.Errata()
	if len(er) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, " PUBLISHED ERRATA that a future implementation of this row MUST honour "+
		"(CSIP Conformance Test Procedures V1.3, Annex A — Errata I, pp. 226-234); the catalog's steps "+
		"and expected criteria are the UNAMENDED printed text and must be read through these %d "+
		"correction(s):", len(er))
	for _, e := range er {
		fmt.Fprintf(&b, " [seq %d] %s → %s", e.Seq,
			strings.TrimSpace(e.Description), strings.Join(e.CorrectiveAction, " "))
		if impact := strings.TrimSpace(e.ObservableImpact); impact != "" {
			fmt.Fprintf(&b, " (observable impact: %s)", impact)
		}
	}
	return b.String()
}

func roleWord(c *certify.Case) string {
	switch c.DUTRole {
	case "":
		return "no DUT role recorded"
	default:
		return "catalog dut_role: " + string(c.DUTRole)
	}
}
