package sim

// poll.go — WHAT "ONE POLL CYCLE" MEANS, MEASURED RATHER THAN GUESSED.
//
// # The problem this replaces
//
// Every row of SS-MODBUS-CLIENT-CONF-v1.1 has to wait for the client under
// test to come round. The client is an autonomous gateway on its own ticker;
// the bench cannot make it poll. Until now the wait was `time.Sleep(n *
// pollInterval)`, and the entire suite's reliability rested on that guess. A
// live bench run (runs/warnmeas-mc-ssm-20260802T134537) measured what the
// guess costs: several fault classes reported "observed: none" while the fault
// had genuinely been armed the whole time, and one recovery assertion FAILED
// outright because the window closed before the DUT's reconnect backoff
// finished. A sleep cannot tell "the client did not do it" from "the client
// had not got to it yet", and those are opposite verdicts.
//
// A barrier can. This file counts the client's poll cycles from the SERVER's
// side of the wire and lets a caller block until a given cycle has finished —
// no clock, no interval parameter, no margin.
//
// # The definition, and where it comes from
//
// The rule below is not a general theory of Modbus clients. It is derived from
// what lexa-gw's southbound client actually does, and every clause cites it.
//
//	The poll loop is a plain, un-jittered ticker at poll_interval_s (default
//	10) — internal/southbound/registry/registry.go:656 `time.NewTicker(
//	reg.pollInterval)`, config key cmd/modbus/config.go:818, shipped value 10
//	in configs/modbus.json. Each tick runs registry.poll() (registry.go:
//	669-708), which spawns one goroutine per due device; that goroutine's whole
//	body is retryDevice.ReadMeasurements (cmd/modbus/main.go:1266-1314) under
//	the per-device mutex.
//
//	THE MODEL CHAIN IS NOT RE-WALKED PER CYCLE. lexa-proto/sunspec/reader.go:
//	9-15 — "it scans the device once at startup and caches the block layout so
//	subsequent reads are single Modbus transactions". The "SunS" probe at
//	40000/0/50000 and the id/length header walk happen once per TCP SESSION,
//	at open and at every reconnect (sunspec/scanner.go:17-21, :40-67, :134-170)
//	— never inside a steady-state cycle. So "a full read of the model chain"
//	is a SESSION event, not a cycle event, and a rule that waited for one
//	would wait forever.
//
//	WHAT DOES HAPPEN EVERY CYCLE is exactly one read of the device's
//	MEASUREMENT MODEL at its cached absolute base address — derbase.go:299-311
//	picks 701 if present, else the first of 103/102/101; inverter.go:83 calls
//	sunspec Reader.ReadModel, which issues FC 0x03 at the block's base for
//	min(declaredLen, 125) registers and, for a longer model, a continuation at
//	base+125 (reader.go:59, :65-98). It is issued FIRST in the cycle and it is
//	the only read whose failure drops the session (main.go:1303-1307).
//
//	Everything else on that socket is CONDITIONAL and follows it: the M704
//	ceiling/setpoint readbacks when a control document stands (reconcile_solar
//	.go:740, setpoint_axis.go:798), the M702/M121 settings refresh every 300 s
//	(settings_refresh.go:75-113), the battery M713/M802 metrics read
//	(battery/metrics.go:54-61), the rate-limited freshness probe
//	(freshness.go:1307-1328). A cycle is therefore two transactions or six,
//	and COUNTING TRANSACTIONS CANNOT WORK.
//
// So:
//
//	A POLL CYCLE IS THE INTERVAL BETWEEN TWO CONSECUTIVE ARRIVALS OF THE
//	CYCLE ANCHOR — the one read request the client repeats every cycle. Cycle
//	N is COMPLETE when the anchor opening cycle N+1 has arrived AND every
//	transaction of cycle N has been resolved (answered, excepted, dropped or
//	abandoned) at the sim's wire layer.
//
// The second clause is what makes the barrier usable as a fence: when
// /poll/wait returns for cycle N, every transaction of cycle N is already in
// the ledger. A caller can grade immediately, with nothing still in flight.
//
// The cost is inherent and worth stating plainly: a cycle's completion is
// observable only when the next one starts, so the barrier trails the client
// by up to one poll interval. That is not a margin — it is the earliest
// instant at which "the cycle contained nothing further" is a fact rather than
// a bet.
//
// # Finding the anchor without being told
//
// The tracker does not know the DUT's configuration, so it LEARNS the anchor
// from the traffic. Within one session the client's reads are:
//
//	probe(base,2) … header(a,2) header(b,2) …   ← all distinct, once per session
//	M702-or-M121                                ← once at derbase.Init
//	MEAS(base,125)  MEAS(base+125,28)           ← cycle 1
//	[optional 704/settings/probe reads]
//	MEAS(base,125)  MEAS(base+125,28)           ← cycle 2
//	…
//
// The measurement read is the first key to recur, and it recurs every cycle.
// The tracker therefore locks onto the key that reaches THREE occurrences
// first — three, not two, because a key can repeat once for an innocent
// reason (derbase.Init's M702 read at session open followed by the settings
// refresher's first M702 read) and never again, while the real anchor keeps
// coming. Requiring a key to have delimited two whole cycles before it is
// believed costs about two poll intervals after a reconnect and removes that
// whole class of mistake.
//
// A bench that already knows its DUT can skip the learning entirely by
// DECLARING the anchor (Declare / POST /reset {"poll_anchor":{…}}). Either
// way the anchor in force is published on GET /poll, so a row can cite the
// rule it relied on instead of asserting that the tool got it right.
//
// # What is deliberately not here
//
// No timers. Nothing in this file reads a clock to decide anything; the only
// time value it records is a timestamp for the ledger. A tracker that fell
// back to "…or 12 seconds, whichever comes first" would have reintroduced the
// guess it exists to remove, in a place nobody would look for it.

import (
	"context"
	"sync"
)

// anchorLockOccurrences is how many times a candidate read key must be seen
// before it is believed to be the cycle anchor. See the package comment: two
// occurrences can happen by accident (a session-open read repeated once by a
// slow-cadence refresher), three means the key has delimited two whole cycles.
const anchorLockOccurrences = 3

// ReadKey identifies one read request by what it asked for. Two requests with
// the same key are the same question, asked twice.
//
// The unit id is part of the key because a client that addresses two units on
// one connection (a Modbus gateway fronting a bus) is polling two devices, and
// their cycles are not the same cycle.
type ReadKey struct {
	UnitID uint8  `json:"unit_id"`
	Addr   uint16 `json:"addr"`
	Count  uint16 `json:"count"`
}

// AnchorSpec is a declared cycle anchor. Count is optional: a spec with
// Count == 0 matches any quantity at Addr, which is what a caller wants when
// it knows the model base but not the device's declared model length. UnitID
// is optional in the same way — 0 is not a legal Modbus unit id, so it is
// unambiguous as "any".
type AnchorSpec struct {
	UnitID uint8  `json:"unit_id,omitempty"`
	Addr   uint16 `json:"addr"`
	Count  uint16 `json:"count,omitempty"`
}

func (a AnchorSpec) matches(k ReadKey) bool {
	if a.Addr != k.Addr {
		return false
	}
	if a.Count != 0 && a.Count != k.Count {
		return false
	}
	if a.UnitID != 0 && a.UnitID != k.UnitID {
		return false
	}
	return true
}

// PollState is the tracker's public account of itself — the evidence a row
// cites when it says which rule it waited on.
type PollState struct {
	// Completed is the number of poll cycles that have finished: the anchor
	// opening the next cycle arrived and every transaction of this one
	// resolved. It is the number /poll/wait's `epoch` parameter refers to.
	Completed uint64 `json:"completed"`
	// Open is the ordinal of the cycle currently in progress (Completed+1
	// while one is open, 0 when none is).
	Open uint64 `json:"open"`
	// OpenReads is how many read requests the open cycle has seen so far, and
	// OpenPending how many of its transactions are still unresolved.
	OpenReads   int `json:"open_reads"`
	OpenPending int `json:"open_pending"`

	// Anchor is the cycle anchor in force, and AnchorLocked whether one has
	// been established at all. Source is "declared" or "learned".
	Anchor       AnchorSpec `json:"anchor"`
	AnchorLocked bool       `json:"anchor_locked"`
	AnchorSource string     `json:"anchor_source,omitempty"`

	// Learning is the candidate table while no anchor is locked, so an
	// operator can see what the tracker is looking at rather than only that it
	// has not decided. Newest-first is not useful here; it is in
	// first-occurrence order, which is the order the client asked.
	Learning []PollCandidate `json:"learning,omitempty"`

	// Sessions counts client connections the tracker has seen open, and
	// Abandoned counts cycles that ended with the connection rather than with
	// the next anchor — a reconnect mid-cycle, which is not a completed poll.
	Sessions  uint64 `json:"sessions"`
	Abandoned uint64 `json:"abandoned"`

	// Rule is the one-line statement of the detection rule, carried in the
	// response so a bundle records the definition alongside the number.
	Rule string `json:"rule"`
}

// PollCandidate is one key the tracker is considering as the anchor.
type PollCandidate struct {
	Key ReadKey `json:"key"`
	N   int     `json:"n"`
}

// pollRule is the sentence every /poll response carries.
const pollRule = "a poll cycle is the interval between two consecutive arrivals of the cycle anchor " +
	"(the read request the client repeats every cycle); cycle N is COMPLETE when the anchor opening " +
	"cycle N+1 has arrived and every transaction of cycle N has been resolved at the sim's wire layer"

// PollTracker counts the client's poll cycles and lets callers block on them.
//
// Safe for concurrent use. Every method is non-blocking except Wait, which
// blocks only on its caller's context and on the client's own behaviour —
// never on a timer of its own.
type PollTracker struct {
	mu sync.Mutex

	// completed is both the NUMBER of poll cycles that have finished and the
	// ordinal of the last one, which are the same integer because an abandoned
	// cycle's ordinal is not consumed: the next cycle to open reuses it. That
	// identity is what lets a caller say "wait for cycle Completed+1" and get
	// the next cycle the client actually finishes, however many reconnects
	// interrupt it on the way.
	completed uint64
	sessions  uint64
	abandoned uint64

	anchor       AnchorSpec
	anchorLocked bool
	anchorSource string

	// counts/order drive the learning phase.
	counts map[ReadKey]int
	order  []ReadKey

	// open cycle state
	openOrdinal uint64
	openReads   int
	openPending int

	// closing holds a cycle that has met the "next anchor arrived" clause but
	// still has unresolved transactions. It completes when its pending count
	// reaches zero. Only one cycle is ever closing: a cycle cannot start
	// closing until the next opens, and that next one cannot close until the
	// one after it opens, by which point this one has been settled either way.
	closingOrdinal uint64
	closingPending int

	// waiters are broadcast-woken on every advance of completed.
	waiters map[chan struct{}]struct{}
}

// NewPollTracker returns an empty tracker with no anchor.
func NewPollTracker() *PollTracker {
	return &PollTracker{
		counts:  make(map[ReadKey]int),
		waiters: make(map[chan struct{}]struct{}),
	}
}

// Declare pins the cycle anchor instead of learning it, and restarts cycle
// accounting from the next matching read. Passing the zero AnchorSpec clears a
// declared anchor and returns the tracker to learning.
func (p *PollTracker) Declare(a AnchorSpec) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetLocked()
	if a.Addr == 0 && a.Count == 0 && a.UnitID == 0 {
		return
	}
	p.anchor, p.anchorLocked, p.anchorSource = a, true, "declared"
}

// Reset forgets everything: the anchor, the candidate table, the open cycle
// and the completed count. It is what POST /reset calls, because a reset means
// "start over" and a cycle counter that survived it would let a row fence
// against a cycle belonging to the previous baseline.
func (p *PollTracker) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetLocked()
	p.broadcastLocked()
}

func (p *PollTracker) resetLocked() {
	p.completed = 0
	p.abandoned = 0
	p.anchor = AnchorSpec{}
	p.anchorLocked = false
	p.anchorSource = ""
	p.counts = make(map[ReadKey]int)
	p.order = nil
	p.openOrdinal = 0
	p.openReads = 0
	p.openPending = 0
	p.closingOrdinal = 0
	p.closingPending = 0
}

// SessionOpened records a new client connection. The anchor survives it — the
// client's loop shape does not change when its socket does — but the open
// cycle does not: a cycle interrupted by a reconnect never completed.
func (p *PollTracker) SessionOpened() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions++
	p.abandonOpenLocked()
	// A cycle still waiting on transactions when the connection dropped can
	// never have them resolved, so it is settled now rather than left holding
	// the counter back forever.
	p.settleClosingLocked(true)
	// Learning is per-session: the candidate table's premise is the sequence
	// of reads on ONE connection, and a reconnect replays the discovery burst,
	// whose keys would otherwise accumulate as false candidates.
	if !p.anchorLocked {
		p.counts = make(map[ReadKey]int)
		p.order = nil
	}
}

// SessionClosed records a client connection ending. An open cycle is
// abandoned, never completed.
//
// The caller must Resolve every outstanding transaction BEFORE calling this,
// so a closing cycle completes on its own merits; the force-settle here is the
// backstop that guarantees the counter can never wedge.
func (p *PollTracker) SessionClosed() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.abandonOpenLocked()
	p.settleClosingLocked(true)
}

func (p *PollTracker) abandonOpenLocked() {
	if p.openOrdinal != 0 {
		p.abandoned++
	}
	p.openOrdinal = 0
	p.openReads = 0
	p.openPending = 0
}

// ObserveRead records one read request arriving and returns the ordinal of the
// cycle it belongs to. Zero means "no cycle" — the read arrived while the
// anchor was still being learned, or before the first anchor of a session, and
// crediting it to a cycle would attribute pre-fence traffic to a post-fence
// window.
//
// The caller must later call Resolve exactly once with the returned ordinal,
// so the "every transaction resolved" clause can be evaluated. A write takes
// no part in cycle accounting and must not be passed here.
func (p *PollTracker) ObserveRead(k ReadKey) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch {
	case !p.anchorLocked:
		if !p.learnLocked(k) {
			return 0
		}
		// learnLocked opened the cycle this very read starts; falling through
		// to openCycleLocked would immediately close it again.
	case p.anchor.matches(k):
		p.openCycleLocked()
	}
	if p.openOrdinal == 0 {
		return 0
	}
	p.openReads++
	p.openPending++
	return p.openOrdinal
}

// learnLocked advances the candidate table and reports whether this read just
// locked the anchor (and therefore already opened a cycle).
func (p *PollTracker) learnLocked(k ReadKey) bool {
	if _, seen := p.counts[k]; !seen {
		p.order = append(p.order, k)
	}
	p.counts[k]++
	if p.counts[k] < anchorLockOccurrences {
		return false
	}
	p.anchor = AnchorSpec{UnitID: k.UnitID, Addr: k.Addr, Count: k.Count}
	p.anchorLocked = true
	p.anchorSource = "learned"
	// By its third occurrence the key has delimited two whole cycles, and
	// those two are as real as any later one: the client asked the identical
	// question twice with other traffic in between. Crediting them here means
	// a row that waits for cycle N need not know whether the anchor was
	// already locked when it started.
	p.completed = anchorLockOccurrences - 1
	p.openOrdinal = p.completed + 1
	p.openReads = 0
	p.openPending = 0
	p.broadcastLocked()
	return true
}

// openCycleLocked closes whatever cycle is open (subject to its transactions
// resolving) and opens the next.
func (p *PollTracker) openCycleLocked() {
	if p.openOrdinal != 0 {
		// Any older closing cycle can get no further transactions now that a
		// newer one has closed behind it.
		p.settleClosingLocked(true)
		p.closingOrdinal = p.openOrdinal
		p.closingPending = p.openPending
		p.settleClosingLocked(false)
	}
	p.openOrdinal = p.nextOrdinalLocked()
	p.openReads = 0
	p.openPending = 0
}

// nextOrdinalLocked is the ordinal the cycle about to open gets: one past the
// last COMPLETED cycle, or one past a cycle still settling.
//
// An ABANDONED cycle's ordinal is deliberately not consumed. A reconnect
// mid-cycle is common (every fault this suite arms provokes one), and a
// counter that skipped an ordinal each time would stop being a count of
// completed polls — so "wait for cycle Completed+1" would sometimes wait for a
// cycle that can never exist.
func (p *PollTracker) nextOrdinalLocked() uint64 {
	if p.closingOrdinal != 0 {
		return p.closingOrdinal + 1
	}
	return p.completed + 1
}

// settleClosingLocked completes the closing cycle once its transactions have
// all resolved, or when force says they never will (the connection ended, or a
// newer cycle has already closed behind it).
func (p *PollTracker) settleClosingLocked(force bool) {
	if p.closingOrdinal == 0 {
		return
	}
	if p.closingPending > 0 && !force {
		return
	}
	if p.closingOrdinal > p.completed {
		p.completed = p.closingOrdinal
		p.broadcastLocked()
	}
	p.closingOrdinal = 0
	p.closingPending = 0
}

// Resolve records that a read transaction previously reported by ObserveRead
// has finished — answered, excepted, dropped or abandoned; the tracker does
// not care which, only that nothing is still in flight. ordinal is
// ObserveRead's return value; 0 is a no-op, for reads that belonged to no
// cycle.
func (p *PollTracker) Resolve(ordinal uint64) {
	if ordinal == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case ordinal == p.openOrdinal && p.openPending > 0:
		p.openPending--
	case ordinal == p.closingOrdinal && p.closingPending > 0:
		p.closingPending--
		p.settleClosingLocked(false)
	}
}

// Snapshot returns the tracker's current state.
func (p *PollTracker) Snapshot() PollState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshotLocked()
}

func (p *PollTracker) snapshotLocked() PollState {
	st := PollState{
		Completed:    p.completed,
		Open:         p.openOrdinal,
		OpenReads:    p.openReads,
		OpenPending:  p.openPending,
		Anchor:       p.anchor,
		AnchorLocked: p.anchorLocked,
		AnchorSource: p.anchorSource,
		Sessions:     p.sessions,
		Abandoned:    p.abandoned,
		Rule:         pollRule,
	}
	if !p.anchorLocked {
		for _, k := range p.order {
			st.Learning = append(st.Learning, PollCandidate{Key: k, N: p.counts[k]})
		}
	}
	return st
}

// Wait blocks until at least want poll cycles have completed, then returns the
// state. It returns early — reached=false, state as it stands — when ctx is
// done.
//
// This is the whole point of the file: the caller's only bound is its own
// context, and the only thing that can satisfy it is the client actually
// polling. There is no internal timer, no margin, no "or n seconds".
func (p *PollTracker) Wait(ctx context.Context, want uint64) (reached bool, st PollState) {
	for {
		p.mu.Lock()
		if p.completed >= want {
			st = p.snapshotLocked()
			p.mu.Unlock()
			return true, st
		}
		ch := make(chan struct{})
		p.waiters[ch] = struct{}{}
		p.mu.Unlock()

		select {
		case <-ch:
			// A cycle completed; loop and re-test under the lock.
		case <-ctx.Done():
			p.mu.Lock()
			delete(p.waiters, ch)
			st = p.snapshotLocked()
			reached = p.completed >= want
			p.mu.Unlock()
			return reached, st
		}
	}
}

// broadcastLocked wakes every waiter. A woken channel is removed from the set
// by the broadcast itself, so a waiter that has gone away (its context fired
// between the wake and its re-acquisition of the lock) leaks nothing.
// Callers hold p.mu.
func (p *PollTracker) broadcastLocked() {
	for ch := range p.waiters {
		close(ch)
		delete(p.waiters, ch)
	}
}
