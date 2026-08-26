package sim

// poll_test.go pins the poll-cycle detection rule against the shape lexa-gw's
// southbound client actually produces, and against the shapes that would fool
// a naive rule.
//
// Every case here drives PollTracker directly rather than through a socket:
// the rule is a pure function of the sequence of read keys, and a test that
// went through TCP to exercise it would be testing the relay as well and
// telling you less about either. tap_test.go drives the same rule over a real
// connection with a scripted client, which is the other half of the proof.

import (
	"context"
	"testing"
	"time"
)

// meas/measCont are the two reads lexa-gw's steady-state cycle issues for a
// model 701 device: the block's first 125 registers and the 28-register
// continuation (sunspec/reader.go readChunked, maxHoldingRead = 125).
var (
	meas     = ReadKey{UnitID: 1, Addr: 40070, Count: 125}
	measCont = ReadKey{UnitID: 1, Addr: 40195, Count: 28}
	// The discovery burst: the base probe and a few id/length header reads,
	// each distinct, issued once per SESSION (sunspec/scanner.go).
	probe    = ReadKey{UnitID: 1, Addr: 40000, Count: 2}
	hdr1     = ReadKey{UnitID: 1, Addr: 40002, Count: 2}
	hdr2     = ReadKey{UnitID: 1, Addr: 40070, Count: 2}
	settings = ReadKey{UnitID: 1, Addr: 40224, Count: 50} // M702, derbase.Init
	ceiling  = ReadKey{UnitID: 1, Addr: 40350, Count: 65} // M704 readback
)

// feed observes a sequence of reads and resolves each immediately, which is
// what a healthy device does: every request is answered before the next
// arrives on a serialized socket.
func feed(p *PollTracker, keys ...ReadKey) {
	for _, k := range keys {
		p.Resolve(p.ObserveRead(k))
	}
}

// cycle is one steady-state lexa-gw poll: the measurement read and its
// continuation.
func cycle(p *PollTracker) { feed(p, meas, measCont) }

// TestPollTracker_LearnsTheMeasurementRead is the headline case: given the
// exact read sequence lexa-gw produces, the tracker locks onto the measurement
// read and counts cycles from it.
func TestPollTracker_LearnsTheMeasurementRead(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()

	// Session open: the discovery burst, all distinct keys.
	feed(p, probe, hdr1, hdr2, settings)
	if st := p.Snapshot(); st.AnchorLocked {
		t.Fatalf("the tracker locked an anchor during the discovery burst (anchor %+v); every key there "+
			"is distinct and none of them delimits a cycle", st.Anchor)
	}

	cycle(p) // occurrence 1 of the anchor
	cycle(p) // occurrence 2
	if st := p.Snapshot(); st.AnchorLocked {
		t.Fatalf("the tracker locked on the anchor's SECOND occurrence (%+v); two occurrences can happen "+
			"by accident, which is why the rule needs three", st.Anchor)
	}
	cycle(p) // occurrence 3 — locks

	st := p.Snapshot()
	if !st.AnchorLocked {
		t.Fatalf("no anchor was locked after three measurement reads; candidates: %+v", st.Learning)
	}
	if st.Anchor.Addr != meas.Addr || st.Anchor.Count != meas.Count {
		t.Fatalf("anchor = %+v, want the measurement read %+v — the tracker locked onto the wrong key, "+
			"so every cycle count from here is a different cycle than the client's", st.Anchor, meas)
	}
	if st.AnchorSource != "learned" {
		t.Errorf("anchor source = %q, want %q", st.AnchorSource, "learned")
	}
	if st.Completed != 2 {
		t.Fatalf("completed = %d after the anchor's third occurrence, want 2 — it has delimited exactly "+
			"two whole cycles by then", st.Completed)
	}

	cycle(p)
	if st := p.Snapshot(); st.Completed != 3 {
		t.Fatalf("completed = %d after a fourth measurement read, want 3", st.Completed)
	}
}

// TestPollTracker_ConditionalReadsDoNotSplitACycle covers the extras lexa-gw
// issues on the SAME socket after the measurement read — the M704 ceiling
// readback, a settings refresh — which a rule that counted transactions, or
// that closed a cycle on any repeated key, would miscount.
func TestPollTracker_ConditionalReadsDoNotSplitACycle(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})

	// Cycle 1: two transactions. Cycle 2: five, including a repeat of the
	// ceiling readback within the one cycle (the reconciler reads it for both
	// the ceiling axis and the setpoint axis).
	feed(p, meas, measCont)
	feed(p, meas, measCont, ceiling, ceiling, settings)
	feed(p, meas, measCont)

	st := p.Snapshot()
	if st.Completed != 2 {
		t.Fatalf("completed = %d, want 2 — a cycle is delimited by the ANCHOR, and a non-anchor read "+
			"repeating inside one (the 704 readback issued twice) must not close it", st.Completed)
	}
	if st.Open != 3 {
		t.Fatalf("open cycle = %d, want 3", st.Open)
	}
}

// TestPollTracker_CompletionWaitsForOutstandingTransactions is the second half
// of the definition: cycle N is complete when the next anchor has arrived AND
// every transaction of cycle N has resolved. It is what lets a caller grade the
// ledger the instant the barrier returns, with nothing still in flight.
func TestPollTracker_CompletionWaitsForOutstandingTransactions(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})

	p.Resolve(p.ObserveRead(meas)) // cycle 1 opens and this resolves
	stuck := p.ObserveRead(measCont)
	// The next anchor arrives while cycle 1 still has one transaction in
	// flight: the device is holding the continuation's response.
	p.Resolve(p.ObserveRead(meas))
	if st := p.Snapshot(); st.Completed != 0 {
		t.Fatalf("completed = %d with a transaction of cycle 1 still in flight, want 0 — a barrier that "+
			"returned here would hand its caller a ledger missing that transaction", st.Completed)
	}
	p.Resolve(stuck)
	if st := p.Snapshot(); st.Completed != 1 {
		t.Fatalf("completed = %d once cycle 1's last transaction resolved, want 1", st.Completed)
	}
}

// TestPollTracker_ReconnectAbandonsTheOpenCycle: a cycle interrupted by a
// reconnect never completed, and must not be counted as though it had.
func TestPollTracker_ReconnectAbandonsTheOpenCycle(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})

	feed(p, meas, measCont)
	feed(p, meas, measCont) // completes cycle 1, opens cycle 2
	if st := p.Snapshot(); st.Completed != 1 {
		t.Fatalf("completed = %d, want 1", st.Completed)
	}
	p.SessionClosed() // cycle 2 dies with the socket

	st := p.Snapshot()
	if st.Completed != 1 {
		t.Fatalf("completed = %d after the connection dropped mid-cycle, want 1 — an interrupted cycle "+
			"is not a completed poll", st.Completed)
	}
	if st.Abandoned != 1 {
		t.Fatalf("abandoned = %d, want 1", st.Abandoned)
	}

	// The anchor survives the reconnect: the client's loop shape does not
	// change when its socket does.
	p.SessionOpened()
	if st := p.Snapshot(); !st.AnchorLocked {
		t.Fatal("the declared anchor was lost across a reconnect")
	}
	feed(p, probe, hdr1) // the reconnect's discovery burst
	feed(p, meas, measCont)
	feed(p, meas, measCont)
	if st := p.Snapshot(); st.Completed != 2 {
		t.Fatalf("completed = %d after one full cycle on the new session, want 2", st.Completed)
	}
}

// TestPollTracker_ReadsBeforeTheFirstAnchorBelongToNoCycle: the discovery
// burst must not be credited to the cycle that follows it, or a row that
// fenced on a cycle would find pre-fence transactions inside its window.
func TestPollTracker_ReadsBeforeTheFirstAnchorBelongToNoCycle(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})

	for _, k := range []ReadKey{probe, hdr1, hdr2, settings} {
		if got := p.ObserveRead(k); got != 0 {
			t.Errorf("read %+v was credited to cycle %d; every read before the first anchor belongs to "+
				"no cycle", k, got)
		}
		p.Resolve(0)
	}
	if got := p.ObserveRead(meas); got != 1 {
		t.Fatalf("the first anchor opened cycle %d, want 1", got)
	}
}

// TestPollTracker_AnchorWithNoDeclaredCount matches any quantity at the
// address, which is what a caller wants when it knows the model base but not
// the device's declared model length.
func TestPollTracker_AnchorWithNoDeclaredCount(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: 40070})

	feed(p, ReadKey{UnitID: 1, Addr: 40070, Count: 125}, measCont)
	feed(p, ReadKey{UnitID: 1, Addr: 40070, Count: 96}) // a shorter model, same base
	if st := p.Snapshot(); st.Completed != 1 {
		t.Fatalf("completed = %d, want 1 — an anchor with no declared count matches any quantity at its "+
			"address", st.Completed)
	}
}

// TestPollTracker_UnitIDIsPartOfTheKey: a client addressing two units on one
// connection is polling two devices, and their cycles are not the same cycle.
func TestPollTracker_UnitIDIsPartOfTheKey(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{UnitID: 1, Addr: 40070, Count: 125})

	feed(p, meas)
	feed(p, ReadKey{UnitID: 2, Addr: 40070, Count: 125}) // a different slave
	if st := p.Snapshot(); st.Completed != 0 {
		t.Fatalf("completed = %d, want 0 — the same block read at a DIFFERENT unit id is a different "+
			"device's poll and must not close this one's cycle", st.Completed)
	}
	feed(p, meas)
	if st := p.Snapshot(); st.Completed != 1 {
		t.Fatalf("completed = %d, want 1", st.Completed)
	}
}

// TestPollTracker_SlowRefresherDoesNotBecomeTheAnchor is the case the
// three-occurrence rule exists for: derbase.Init reads M702 at session open,
// and the settings refresher reads it once more. Two occurrences, and it never
// comes back — while the real anchor keeps arriving.
func TestPollTracker_SlowRefresherDoesNotBecomeTheAnchor(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()

	feed(p, probe, hdr1, settings) // derbase.Init's M702 read: occurrence 1
	feed(p, meas, measCont)
	feed(p, settings) // the refresher's first M702 read: occurrence 2
	feed(p, meas, measCont)
	feed(p, meas, measCont) // the anchor's third occurrence — locks

	st := p.Snapshot()
	if !st.AnchorLocked {
		t.Fatalf("no anchor locked; candidates %+v", st.Learning)
	}
	if st.Anchor.Addr != meas.Addr {
		t.Fatalf("anchor = %+v, want the measurement read at %d — a key that repeats ONCE for an "+
			"innocent reason must not win over the one that repeats every cycle",
			st.Anchor, meas.Addr)
	}
}

// TestPollTracker_ResetForgetsEverything: a reset means "start over", and a
// cycle counter that survived it would let a row fence against a cycle
// belonging to the previous baseline.
func TestPollTracker_ResetForgetsEverything(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})
	feed(p, meas, measCont, meas, measCont)
	if st := p.Snapshot(); st.Completed == 0 {
		t.Fatal("setup did not complete a cycle")
	}
	p.Reset()
	st := p.Snapshot()
	if st.Completed != 0 || st.AnchorLocked || st.Open != 0 {
		t.Fatalf("after Reset: completed=%d anchorLocked=%v open=%d — want a tracker that has seen "+
			"nothing", st.Completed, st.AnchorLocked, st.Open)
	}
}

// TestPollTracker_WaitReturnsWhenTheCycleCompletes proves the barrier blocks on
// the client's behaviour and nothing else.
func TestPollTracker_WaitReturnsWhenTheCycleCompletes(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})

	done := make(chan PollState, 1)
	go func() {
		_, st := p.Wait(context.Background(), 2)
		done <- st
	}()

	// Nothing must satisfy the wait until the second cycle genuinely closes.
	feed(p, meas, measCont)
	feed(p, meas, measCont)
	select {
	case st := <-done:
		t.Fatalf("Wait(2) returned after only one completed cycle (completed=%d)", st.Completed)
	case <-time.After(20 * time.Millisecond):
	}
	feed(p, meas, measCont)
	select {
	case st := <-done:
		if st.Completed < 2 {
			t.Fatalf("Wait(2) returned with completed=%d", st.Completed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Wait(2) did not return after the second cycle completed")
	}
}

// TestPollTracker_WaitHonoursItsContext: a caller's cancellation is the only
// bound the barrier has, and it must be observed promptly and reported as
// reached=false rather than as an error.
func TestPollTracker_WaitHonoursItsContext(t *testing.T) {
	p := NewPollTracker()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	reached, st := p.Wait(ctx, 5)
	if reached {
		t.Fatal("Wait reported reached=true with no cycles observed at all")
	}
	if st.Completed != 0 {
		t.Fatalf("completed = %d, want 0", st.Completed)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Wait took %s to honour a 30ms context", d)
	}
}

// TestPollTracker_WaitAlreadySatisfied returns immediately rather than waiting
// for another cycle — a caller asking for a cycle that has already happened is
// asking a question with an answer, not making a request.
func TestPollTracker_WaitAlreadySatisfied(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})
	feed(p, meas, meas, meas)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reached, st := p.Wait(ctx, 1)
	if !reached || st.Completed < 1 {
		t.Fatalf("Wait(1) after two completed cycles: reached=%v completed=%d", reached, st.Completed)
	}
}

// TestPollTracker_ConcurrentWaiters proves the broadcast wakes every waiter,
// which is the property a suite with several rows sharing one sim depends on.
func TestPollTracker_ConcurrentWaiters(t *testing.T) {
	p := NewPollTracker()
	p.SessionOpened()
	p.Declare(AnchorSpec{Addr: meas.Addr, Count: meas.Count})

	const waiters = 8
	done := make(chan bool, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			reached, _ := p.Wait(context.Background(), 1)
			done <- reached
		}()
	}
	// Give the waiters a moment to register, then complete a cycle.
	time.Sleep(10 * time.Millisecond)
	feed(p, meas, measCont, meas)

	deadline := time.After(3 * time.Second)
	for i := 0; i < waiters; i++ {
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("a waiter woke with reached=false after a cycle completed")
			}
		case <-deadline:
			t.Fatalf("only %d of %d waiters woke", i, waiters)
		}
	}
}
