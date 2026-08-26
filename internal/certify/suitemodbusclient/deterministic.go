package suitemodbusclient

// deterministic.go is the live phase every rewritten row runs, and the reason
// none of them decides a verdict by elapsed time any more.
//
// # What was wrong
//
// The DUT is the Modbus CLIENT: it polls the bench on its own ~10 s ticker and
// the bench cannot make it poll. Every row therefore had to wait, and the only
// waits available were `time.Sleep(n * pollInterval)` and — later, as a partial
// fix — `awaitJournalEvidence`, which watches the DUT's own systemd journal for
// a line that looks like a reaction.
//
// Both are guesses about the wrong thing. A sleep cannot tell "the client did
// not do it" from "the client had not got to it yet", which are opposite
// verdicts. The journal is better but it is the PRODUCT'S OWN ACCOUNT OF
// ITSELF, watched with substring matches on words like "err" and "fail": it is
// evidence about the thing under test, offered by the thing under test, and a
// row that used it to decide when to stop looking was letting the DUT choose
// its own examination window.
//
// A live bench run (runs/warnmeas-mc-ssm-20260802T134537) is the record of what
// that cost: several fault classes reported "observed: none" while the fault
// had genuinely been armed the whole time, and one recovery assertion FAILED
// outright because the window closed before the DUT's reconnect backoff
// finished.
//
// # What replaces it
//
// The simulator now publishes a fence and a barrier (sim/simapi/API.md,
// control-plane 1.1.0), and every row here follows the same four steps:
//
//	ARM     POST /fault … → {"epoch":N}      the epoch the provocation is in
//	                                         force from
//	AWAIT   GET /poll/wait?epoch=…           block until the DUT has FINISHED a
//	                                         poll cycle that began after N
//	GRADE   GET /ledger?since_epoch=N        the transactions the provocation
//	                                         could have touched, and no earlier
//	                                         one
//	CITE    the pcap, as before               unchanged: the ledger tells the
//	                                         row its window is right, it does
//	                                         not replace the citation
//
// The only assumption left about timing is that the DUT eventually polls, and
// that is bounded by the check's own context rather than by a number someone
// chose.
//
// # Two barriers, and which question each answers
//
// awaitPoll asks "has the DUT FINISHED a poll cycle". That is the right
// question for a row whose criterion is about the SHAPE of a whole read cycle
// (READ-1, READ-2, INFO-1): a window holding half a cycle would grade a pattern
// the client never emitted.
//
// awaitLedger asks "has the DUT ISSUED a request under my fence". That is the
// right question for every PROVOKING row, and the only answerable one for
// several of them: lexa-gw drops its southbound session on a Modbus exception
// and reconnects on the next poll (cmd/modbus/main.go:1303-1307), so under a
// persistent exception it is met once per SESSION and completes no cycle at
// all. A row that waited on the poll barrier there would report a timeout while
// its provocation landed perfectly.
//
// The two are not interchangeable, and the epoch is what keeps the second one
// honest: a ledger page fenced at the arming epoch CANNOT contain a
// pre-provocation transaction, whatever the DUT's cycle boundaries were doing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// pollWaitSlice is how long ONE /poll/wait request blocks before answering
// reached=false. It is deliberately shorter than the framework's 15 s HTTP
// client timeout, so a caller's transport never decides anything; awaitPoll
// loops over slices until its own budget or context runs out.
const pollWaitSlice = 8 * time.Second

// pollBudget bounds a barrier wait. It is generous against a 10 s poll — six
// cycles — because the DUT's reconnect-with-backoff after a Modbus exception
// can legitimately trail a fault clear by several, and this budget is the
// difference between reporting that patiently and reporting it as a FAIL.
// Every row that uses it is registered with a check timeout above it.
const pollBudget = 90 * time.Second

// errNoDeterministicSim is what a row reports when the sim cannot fence.
var errNoDeterministicSim = errors.New("this simulator does not publish the deterministic control plane")

// determinism is the observer's handle on the sim's fence-and-barrier surface.
// A row builds one with observer.determinism and either gets a usable handle or
// the reason it cannot have one — which is a SKIP with a named capability, not
// a fall-back to sleeping.
type determinism struct {
	o  *observer
	rc *certify.RunCtx

	// baselineEpoch is the epoch the row's opening reset established.
	baselineEpoch uint64
	// reset records what the reset put back, for the assertion text.
	reset resetResult
}

// determinism prepares the deterministic layer, or returns the reason it is
// unavailable.
//
// It probes GET /version rather than assuming: a bench running an older sim,
// or one started with -tap=false, must produce a row that says so by name
// instead of one that reads an empty ledger as "the DUT did nothing".
func (o *observer) determinism(ctx context.Context) (*determinism, error) {
	if !o.simAvailable() {
		return nil, fmt.Errorf("%w: modsim's simapi control plane is not configured (-modsim-api)",
			errNoDeterministicSim)
	}
	ver, err := simVersionOf(ctx, o.sim)
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s/version failed (%v); simapi %s or later is needed for the "+
			"epoch fence, the poll barrier and the transaction ledger",
			errNoDeterministicSim, o.sim.BaseURL, err, simAPIVersionNeeded)
	}
	have := strings.Join(ver.Endpoints, " ")
	var missing []string
	for _, want := range []string{"GET /ledger", "GET /poll/wait", "POST /reset", "epoch"} {
		if !strings.Contains(have, want) {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: the sim at %s reports api_version %q and does not offer %s. The "+
			"deterministic rows need simapi %s AND the wire tap interposed — restart modsim without "+
			"-tap=false",
			errNoDeterministicSim, o.sim.BaseURL, ver.APIVersion, strings.Join(missing, ", "),
			simAPIVersionNeeded)
	}
	return &determinism{o: o, rc: o.rc}, nil
}

// begin puts the device at a known baseline and returns the epoch it is true
// from. Every deterministic row starts here: a row that armed a fault without
// first knowing what device it was arming on would be measuring the previous
// row's leftovers.
//
// anchor, when non-nil, DECLARES the poll-cycle anchor rather than letting the
// sim learn it — which costs two poll cycles of learning after every reconnect.
// A row that has already observed the anchor (from a previous /poll) passes it
// on; a row that has not leaves it nil and lets the sim work it out.
func (d *determinism) begin(ctx context.Context, anchor *PollAnchor) error {
	body := map[string]any{"baseline": "as-built"}
	if anchor != nil && anchor.Addr != 0 {
		body["poll_anchor"] = map[string]any{"addr": anchor.Addr, "count": anchor.Count}
	}
	ack, err := postForEpoch(ctx, d.o.sim, "/reset", body)
	if err != nil {
		return fmt.Errorf("reset the sim to its as-built baseline: %w", err)
	}
	d.baselineEpoch = ack.Epoch
	if len(ack.Result) > 0 {
		_ = jsonInto(ack.Result, &d.reset)
	}
	d.o.injected = append(d.o.injected, fmt.Sprintf(
		"POST %s/reset {\"baseline\":\"as-built\"} → epoch %d (cleared: %s)",
		d.o.sim.BaseURL, ack.Epoch, joinOr(d.reset.Cleared, "nothing was armed")))
	d.rc.Logf("sim reset to its as-built baseline at epoch %d; cleared %v", ack.Epoch, d.reset.Cleared)
	return nil
}

// arm posts a fault and returns the epoch it is armed from — the fence for
// every later ledger query about it.
func (d *determinism) arm(ctx context.Context, spec map[string]any, why string) (uint64, error) {
	if !d.o.injectOK {
		return 0, fmt.Errorf("fault injection is disabled for this run (-param %s=off)", paramInject)
	}
	ack, err := postForEpoch(ctx, d.o.sim, "/fault", spec)
	if err != nil {
		return 0, err
	}
	d.o.injected = append(d.o.injected, fmt.Sprintf("POST %s/fault %s → epoch %d (%s)",
		d.o.sim.BaseURL, jsonish(spec), ack.Epoch, why))
	d.rc.Logf("armed on modsim at epoch %d: %s — %s", ack.Epoch, jsonish(spec), why)
	return ack.Epoch, nil
}

// inject posts an /inject body and returns the epoch it is in force from.
func (d *determinism) inject(ctx context.Context, body map[string]any, why string) (uint64, error) {
	if !d.o.injectOK {
		return 0, fmt.Errorf("injection is disabled for this run (-param %s=off)", paramInject)
	}
	ack, err := postForEpoch(ctx, d.o.sim, "/inject", body)
	if err != nil {
		return 0, err
	}
	d.o.injected = append(d.o.injected, fmt.Sprintf("POST %s/inject %s → epoch %d (%s)",
		d.o.sim.BaseURL, jsonish(body), ack.Epoch, why))
	d.rc.Logf("injected on modsim at epoch %d: %s — %s", ack.Epoch, jsonish(body), why)
	return ack.Epoch, nil
}

// clear disarms a fault kind and records it. A failure is recorded, never
// swallowed: a bench left in a fault state invalidates whatever runs next.
func (d *determinism) clear(ctx context.Context, kind string) {
	cctx, cancel := context.WithTimeout(withoutCancel(ctx), 20*time.Second)
	defer cancel()
	spec := map[string]any{"kind": kind, "clear": true}
	if _, err := postForEpoch(cctx, d.o.sim, "/fault", spec); err != nil {
		d.o.injected = append(d.o.injected, fmt.Sprintf("FAILED to clear %q on modsim: %v", kind, err))
		d.rc.Logf("WARNING: could not clear fault %q on modsim: %v", kind, err)
		return
	}
	d.o.injected = append(d.o.injected, fmt.Sprintf("POST %s/fault %s", d.o.sim.BaseURL, jsonish(spec)))
}

// restore puts the sim back to its as-built baseline, unconditionally. Rows
// defer it: a device left relocated, re-addressed or poked would corrupt every
// later row's discovery, not just this one's.
func (d *determinism) restore(ctx context.Context) {
	cctx, cancel := context.WithTimeout(withoutCancel(ctx), 30*time.Second)
	defer cancel()
	ack, err := postForEpoch(cctx, d.o.sim, "/reset", map[string]any{"baseline": "as-built"})
	if err != nil {
		d.o.injected = append(d.o.injected, fmt.Sprintf("FAILED to restore the sim's baseline: %v", err))
		d.rc.Logf("WARNING: could not restore the sim's as-built baseline: %v", err)
		return
	}
	d.o.injected = append(d.o.injected, fmt.Sprintf("POST %s/reset {\"baseline\":\"as-built\"} → epoch %d",
		d.o.sim.BaseURL, ack.Epoch))
}

// awaitPoll blocks until the sim has counted n MORE completed poll cycles than
// it had when this was called, then returns its state.
//
// A cycle that was already OPEN when the call was made counts towards that: it
// is a genuine, complete cycle of the client's, and for the rows that use this
// barrier — whose criterion is the shape of a read cycle — that is exactly what
// they want to see. A row whose evidence must be strictly POST-provocation does
// not use this barrier at all; it fences the ledger on the arming epoch, which
// cannot contain a pre-fence transaction whatever the cycle boundaries did.
//
// It returns observed=false — never an error — when the budget runs out with
// the DUT not having polled. That is an observation a row must report, not a
// failure of the wait, and every caller says so in its assertion.
func (d *determinism) awaitPoll(ctx context.Context, n uint64) (rep PollReport, observed bool, err error) {
	start, err := pollNow(ctx, d.o.sim)
	if err != nil {
		return rep, false, err
	}
	want := start.Poll.Completed + n
	if !start.Poll.AnchorLocked {
		// The sim has not worked out the client's cycle shape yet, so no
		// ordinal it reports means anything — including the zero it is
		// currently reporting. Ask for the count the tracker credits itself
		// the moment it LOCKS (anchorLockOccurrences-1 = two cycles the client
		// demonstrably completed), plus what was asked for, so a caller that
		// starts before the anchor is known still waits for real cycles.
		want = 2 + n - 1
	}
	d.rc.Logf("waiting on the sim's poll barrier for cycle %d (completed %d, open %d, anchor %s)",
		want, start.Poll.Completed, start.Poll.Open, start.Poll.Anchor)

	deadline := time.Now().Add(pollBudget)
	for {
		rep, err = pollWaitOnce(ctx, d.o.sim, want, pollWaitSlice)
		if err != nil {
			return rep, false, err
		}
		if rep.Reached {
			return rep, true, nil
		}
		if ctx.Err() != nil {
			return rep, false, ctx.Err()
		}
		if !time.Now().Before(deadline) {
			d.rc.Logf("the poll barrier did not reach cycle %d within %s: the DUT completed %d cycle(s) "+
				"(anchor %s, locked=%v)", want, pollBudget, rep.Poll.Completed, rep.Poll.Anchor,
				rep.Poll.AnchorLocked)
			return rep, false, nil
		}
	}
}

// awaitLedger blocks until the sim has recorded at least min transactions at
// or after the fence, then returns them.
//
// This is the barrier most provoking rows need, and it is a different question
// from awaitPoll's. awaitPoll asks "has the DUT FINISHED a poll cycle", which
// several provocations make unanswerable: lexa-gw drops its southbound session
// on any Modbus exception and reconnects on the next poll
// (cmd/modbus/main.go:1303-1307), so a device answering every measurement read
// with an exception is met once per SESSION and finishes no cycle at all. A row
// that waited on the poll barrier there would report a timeout while its
// provocation landed perfectly on every session.
//
// This asks "has the DUT ISSUED a request under my fence", which is answerable
// in both cases and is what an exception, truncation or drop row grades.
//
// observed=false is an observation, not an error: the DUT did not talk to this
// server while the provocation was in force, and the caller says so.
func (d *determinism) awaitLedger(ctx context.Context, epoch uint64, min int) (page LedgerPage,
	observed bool, err error) {

	if min < 1 {
		min = 1
	}
	deadline := time.Now().Add(pollBudget)
	for {
		page, err = ledgerWaitOnce(ctx, d.o.sim, epoch, min, pollWaitSlice)
		if err != nil {
			return page, false, err
		}
		if page.Total >= min {
			return page, true, nil
		}
		if ctx.Err() != nil {
			return page, false, ctx.Err()
		}
		if !time.Now().Before(deadline) {
			d.rc.Logf("the DUT issued %d transaction(s) at or after epoch %d within %s; %d were needed",
				page.Total, epoch, pollBudget, min)
			return page, false, nil
		}
	}
}

// meet is the whole loop in one call: arm a fault, wait for the DUT to meet it,
// grade the ledger from the arming epoch, and clear.
//
// It is the shape almost every provoking row wants, and having it in one place
// means a row cannot accidentally grade a window that predates its own
// provocation — the mistake the sleep-based version made silently.
//
// minTxns is how many transactions under the fence constitute "the DUT met
// it": one for a provocation the DUT walks into on its next request, more for
// one whose point is that it recurs.
//
// The fault is cleared AFTER the ledger is read, so the page a caller grades
// covers exactly the interval the fault was armed for and nothing after it.
// clearKind may be empty for a one-shot, which disarms itself by firing.
func (d *determinism) meet(ctx context.Context, spec map[string]any, why, clearKind string,
	minTxns int) (meeting, error) {

	return d.meetWith(ctx, spec, why, clearKind, minTxns, d.arm)
}

// meetInject is meet for a provocation that goes through POST /inject rather
// than POST /fault — a spliced model, a seeded sentinel, a poked register.
//
// The two endpoints are not interchangeable and the distinction is not
// cosmetic: /fault arms a BEHAVIOUR the sim clears by name, while /inject
// changes the register IMAGE, which POST /reset restores wholesale. An inject
// therefore has no clear kind, and its clean-up is the row's deferred restore.
func (d *determinism) meetInject(ctx context.Context, body map[string]any, why string,
	minTxns int) (meeting, error) {

	return d.meetWith(ctx, body, why, "", minTxns, d.inject)
}

// meetWith is the shared body of meet and meetInject.
func (d *determinism) meetWith(ctx context.Context, spec map[string]any, why, clearKind string,
	minTxns int, post func(context.Context, map[string]any, string) (uint64, error)) (meeting, error) {

	m := meeting{Spec: jsonish(spec), Why: why}
	epoch, err := post(ctx, spec, why)
	if err != nil {
		m.ArmErr = err
		return m, nil
	}
	m.Epoch, m.Armed = epoch, true
	if clearKind != "" {
		defer d.clear(ctx, clearKind)
	}

	page, observed, err := d.awaitLedger(ctx, epoch, minTxns)
	if err != nil {
		return m, err
	}
	m.Page, m.Met = page, observed
	if rep, perr := pollNow(ctx, d.o.sim); perr == nil {
		m.Poll = rep
	}
	return m, nil
}

// meeting is what one arm-await-grade cycle produced.
type meeting struct {
	// Spec and Why are the provocation, verbatim, for the assertion text.
	Spec, Why string
	// Armed and Epoch record whether the fault took and the fence it is in
	// force from.
	Armed bool
	Epoch uint64
	// ArmErr is why it did not take.
	ArmErr error
	// Met says the DUT issued the transactions asked for while the provocation
	// was in force.
	Met bool
	// Poll is the sim's poll accounting as the meeting ended, for the note.
	Poll PollReport
	// Page is the sim's ledger from Epoch onward — the transactions this
	// provocation could have touched, and no earlier one.
	Page LedgerPage
	// LedgerErr is why the ledger could not be read.
	LedgerErr error
}

// reason renders, in one sentence, what happened to this provocation — the
// text a SKIP needs so a reader can act on it.
func (m meeting) reason() string {
	switch {
	case m.ArmErr != nil:
		return fmt.Sprintf("the provocation %s could not be armed on the server: %v", m.Spec, m.ArmErr)
	case m.LedgerErr != nil:
		return fmt.Sprintf("the provocation %s was armed at epoch %d but the sim's transaction ledger "+
			"could not be read: %v", m.Spec, m.Epoch, m.LedgerErr)
	case !m.Met:
		return fmt.Sprintf("the provocation %s was armed at epoch %d and the DUT issued %d transaction(s) "+
			"to this server while it was in force — not enough to grade. The sim's own record is the "+
			"witness here: the DUT was not polling this server during this test case's window, which is "+
			"a fact about the bench rather than about the DUT's conformance",
			m.Spec, m.Epoch, m.Page.Total)
	default:
		return fmt.Sprintf("the provocation %s was armed at epoch %d and the DUT met it: %s",
			m.Spec, m.Epoch, m.Page.Summary())
	}
}

// ok reports whether the meeting produced gradeable evidence.
func (m meeting) ok() bool {
	return m.Armed && m.ArmErr == nil && m.LedgerErr == nil && m.Met && len(m.Page.Entries) > 0
}

// ledgerSource is the Source string every ledger-backed Narrative names. It
// says what the source IS, so a reader weighing the assertion knows it is the
// server's own record and not the client's.
func (d *determinism) ledgerSource() string {
	return fmt.Sprintf("GET %s/ledger — the simulator's own append-only record of every Modbus "+
		"transaction, written by its wire layer as the bytes crossed it, independently of anything the "+
		"DUT logs", d.o.sim.BaseURL)
}

// pollRuleNote renders the barrier's own statement of what it counted, for an
// assertion that rests on a cycle count. A bundle must carry the definition
// beside the number.
func pollRuleNote(rep PollReport) string {
	st := rep.Poll
	if !st.AnchorLocked {
		return fmt.Sprintf("the sim had not yet identified the DUT's poll-cycle anchor (candidates so "+
			"far: %v), so no cycle count is meaningful", st.Learning)
	}
	return fmt.Sprintf("the sim counted %d completed poll cycle(s) over %d session(s) (%d abandoned "+
		"mid-cycle by a reconnect), using anchor %s, %s. Its rule: %s",
		st.Completed, st.Sessions, st.Abandoned, st.Anchor, st.AnchorSource, st.Rule)
}

// deterministicSkip renders the reason a row could not run deterministically,
// in the form doc.go requires: the missing capability, named precisely enough
// to be actioned.
func deterministicSkip(err error) string {
	return fmt.Sprintf("%v. Until the bench serves it, this row can only be driven by sleeping through "+
		"the DUT's poll interval and hoping the provocation landed inside the window — which is exactly "+
		"the guess a live run (runs/warnmeas-mc-ssm-20260802T134537) showed produces 'observed: none' "+
		"while the fault was armed the whole time", err)
}

// withoutCancel returns a context carrying ctx's values but not its
// cancellation, for the clean-up a check must perform even when it has been
// cancelled. A teardown that inherited the cancellation would leave the bench
// in a fault state precisely when a check timed out — the case it matters most.
func withoutCancel(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}

// jsonInto decodes raw JSON into v, ignoring an empty payload.
func jsonInto(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// reconnect severs the DUT's southbound connection so its next poll has to
// re-establish it — the only way this bench can make a client that has been
// connected for hours perform its discovery sequence again inside a test
// case's window. It returns the epoch the severance happened at.
//
// tcp_drop is a one-shot action on the sim's listener, not a sticky state, so
// there is nothing to clear.
func (d *determinism) reconnect(ctx context.Context, why string) (uint64, error) {
	return d.arm(ctx, map[string]any{"kind": "tcp_drop"}, why)
}

// relocate re-homes the server's SunSpec map and returns the epoch it moved at.
// base 0, 40000 and 50000 are the three standard SunSpec bases (§2.4.4 CLI-4
// requires discovery to work at all three); any other value deliberately
// serves a noncompliant map (§2.9.1 ERR-1's 40001).
func (d *determinism) relocate(ctx context.Context, base uint16, why string) (uint64, error) {
	return d.arm(ctx, map[string]any{"kind": "relocate", "base": int(base)}, why)
}

// warmUp gives the sim's barrier something to learn from before a row needs it:
// it waits for enough poll cycles that the anchor locks, and reports what was
// learned.
//
// A row calls it when it wants to AIM at the block the DUT polls (ERR-2,
// INFO-2) or wants cycle counts to mean anything. It is bounded by the same
// budget as every other wait, and an unlocked anchor is reported rather than
// worked around: a fault aimed at a block the sim only guessed at would be a
// row grading the wrong register.
func (d *determinism) warmUp(ctx context.Context) (PollReport, bool, error) {
	rep, err := pollNow(ctx, d.o.sim)
	if err != nil {
		return rep, false, err
	}
	if rep.Poll.AnchorLocked {
		return rep, true, nil
	}
	rep, observed, err := d.awaitPoll(ctx, 1)
	if err != nil {
		return rep, false, err
	}
	return rep, observed && rep.Poll.AnchorLocked, nil
}

// deviceName is the DUT's device entry for the plain-text server, used to
// correlate its journal lines. It is a parameter because a gateway with more
// than one southbound device would otherwise have this suite reading the wrong
// device's readback line.
func deviceName(rc *certify.RunCtx) string {
	if v, ok := rc.Param(paramDevice); ok && v != "" {
		return v
	}
	return defaultDeviceName
}

// awaitMatch blocks until the sim's ledger, fenced at epoch, satisfies want.
//
// awaitLedger answers "has the DUT issued N transactions"; this answers "has
// the DUT done the PARTICULAR thing I am waiting for" — issued a write, read a
// given block, reconnected. It is built on the same bounded ledger barrier, so
// it still holds no timer: each round trip blocks on an append, and the loop
// simply raises the bar past whatever it has already seen.
//
// what names the thing being waited for, for the log line and for the caller's
// SKIP text when it does not happen.
func (d *determinism) awaitMatch(ctx context.Context, epoch uint64, what string,
	want func(LedgerPage) bool) (page LedgerPage, observed bool, err error) {

	deadline := time.Now().Add(pollBudget)
	min := 1
	for {
		page, err = ledgerWaitOnce(ctx, d.o.sim, epoch, min, pollWaitSlice)
		if err != nil {
			return page, false, err
		}
		if want(page) {
			return page, true, nil
		}
		if ctx.Err() != nil {
			return page, false, ctx.Err()
		}
		if !time.Now().Before(deadline) {
			d.rc.Logf("the DUT did not %s within %s of epoch %d (%d transaction(s) seen: %s)",
				what, pollBudget, epoch, page.Total, page.Summary())
			return page, false, nil
		}
		// Raise the bar past what has already been seen, so the next request
		// blocks on a NEW append rather than returning the same page at once.
		if page.Total >= min {
			min = page.Total + 1
		}
	}
}

// ── Forced rediscovery, held on the sim's own record ──────────────────────────

// rediscovery is what one forced reconnect produced.
type rediscovery struct {
	// Fence is the epoch the connection was severed at.
	Fence uint64
	// Err is why it could not be severed.
	Err error
	// Page is the sim's record of what the DUT did afterwards, and Observed
	// says whether the rediscovery burst arrived at all.
	Page     LedgerPage
	Observed bool
}

// rediscoverMinReads is how many transactions constitute a rediscovery burst.
// lexa-gw's reconnect replays the SunSpec probe, a header read per model in the
// chain, the settings model and then the measurement read
// (lexa-proto/sunspec/scanner.go, derbase.Init), so three is a floor a
// genuine rediscovery clears comfortably and a stalled client does not.
const rediscoverMinReads = 3

// rediscover severs the DUT's connection and waits, on the simulator's ledger,
// for the rediscovery burst that follows.
//
// It replaces the pattern every discovery row used to run — forceReconnect,
// then sleep two or three poll intervals and hope the burst landed inside them
// — which a live run showed routinely caught the fast header walk and missed
// what came after it.
func rediscover(ctx context.Context, d *determinism, row string) (rediscovery, error) {
	var r rediscovery
	fence, err := d.reconnect(ctx, fmt.Sprintf("sever the DUT's southbound connection so its reconnect "+
		"performs the full SunSpec discovery sequence inside %s's observation window", row))
	if err != nil {
		r.Err = err
		return r, nil
	}
	r.Fence = fence
	page, ok, err := d.awaitLedger(ctx, fence, rediscoverMinReads)
	if err != nil {
		return r, err
	}
	r.Page, r.Observed = page, ok
	return r, nil
}

// note renders the rediscovery for an assertion's Observed text.
func (r rediscovery) note() string {
	switch {
	case r.Err != nil:
		return fmt.Sprintf(" (no reconnect was forced — %v — so only the DUT's steady-state polling was "+
			"observed; a client that connected before the capture began does not repeat its discovery "+
			"sequence)", r.Err)
	case !r.Observed:
		return fmt.Sprintf(" after its southbound connection was severed at epoch %d, though the "+
			"simulator recorded only %d transaction(s) afterwards", r.Fence, r.Page.Total)
	default:
		return fmt.Sprintf(" after its southbound connection was severed at epoch %d, so that its "+
			"reconnect would perform discovery inside this test case's window", r.Fence)
	}
}

// evalRediscovery asserts, from the sim's own record, that the rediscovery
// happened — which is what makes every discovery assertion in the row about a
// conversation that actually took place inside the window.
func evalRediscovery(r rediscovery, d *determinism) finding {
	claim := "the DUT re-established its southbound connection and performed a fresh SunSpec discovery " +
		"inside this test case's window"
	method := "sever the DUT's connection at a named control-plane epoch, then wait on the simulator's " +
		"own transaction ledger — not on a poll interval — for the rediscovery burst"
	switch {
	case r.Err != nil:
		return skipf(claim, method, "the DUT's connection could not be severed: %v", r.Err)
	case !r.Observed:
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"the DUT's connection was severed at epoch %d and it issued only %d transaction(s) "+
				"afterwards within the barrier's budget — fewer than a rediscovery burst. Every "+
				"discovery assertion in this row is therefore about whatever traffic did arrive: %s",
			r.Fence, r.Page.Total, r.Page.Summary())
	default:
		return narrativef(claim, method, d.ledgerSource(), certify.Pass,
			"the DUT's connection was severed at epoch %d and it issued %d transaction(s) afterwards "+
				"across %d session(s) — %s — starting at %s. The discovery assertions in this row are "+
				"about that conversation",
			r.Fence, r.Page.Total, r.Page.Poll.Sessions, r.Page.Summary(), r.Page.Entries[0])
	}
}

// commonModelBodyGap is the one criterion CLI-1..CLI-4, PROT-1 and READ-2 all
// share and none of them can reach after boot. It is stated once, in one place,
// because it is one fact about the DUT rather than five separate gaps.
func commonModelBodyGap() finding {
	return skipf(
		"the DUT logged the contents of all the Common Model points",
		"observation of the DUT reading model 1's BODY — not merely its ID/length header — inside a "+
			"test case's window",
		"lexa-gw reads model 1's body EXACTLY ONCE, during admission, on a separate short-lived "+
			"connection at boot (internal/southbound/admission/identify.go's identifyNow calls "+
			"sunspec.ReadCommon there and nowhere else). Its steady-state poll reads only the "+
			"measurement model, and even a full reconnect rediscovery walks the chain's HEADERS and "+
			"then goes straight to that model — lexa-proto/sunspec/reader.go caches the block layout "+
			"per session and never re-reads model 1's body. So no provocation available to this bench "+
			"can make the DUT re-read the Common Model inside a window: it would take a process "+
			"restart, which a shared-bench conformance run must not perform. THIS IS A DUT-SIDE "+
			"OBSERVABILITY GAP, not a missing sim verb. Closing it needs either a re-identify "+
			"diagnostic on the DUT that a read-only client can trigger, or a run whose capture begins "+
			"before the DUT's own boot so the admission connection falls inside it")
}
