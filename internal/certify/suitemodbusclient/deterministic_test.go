package suitemodbusclient

// deterministic_test.go covers the machinery LAB29-011 put in place of the
// sleeps, and the row decision logic built on it.
//
// Two halves:
//
//	the CLIENT half — postForEpoch, awaitLedger, awaitMatch, awaitPoll and the
//	capability probe, driven against a scripted HTTP simulator. What is under
//	test is that a wait ends because the CONDITION was met, that a wait that is
//	never met reports an observation rather than an error, and that a caller's
//	cancellation is honoured promptly. None of these tests sleeps to make its
//	point.
//
//	the DECISION half — the eval* functions each row's Cite callback calls,
//	driven with hand-built ledger pages. They are pure functions of a page and
//	a meeting, which is what lets a unit test drive them with no bench, no sim
//	and no capture in the room.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

// ── Fixtures ──────────────────────────────────────────────────────────────────

// mbap wraps a PDU in a Modbus/TCP header and renders it as the ledger does.
func ledgerADU(txn uint16, unit uint8, pdu ...byte) string {
	out := []byte{byte(txn >> 8), byte(txn), 0, 0,
		byte((len(pdu) + 1) >> 8), byte(len(pdu) + 1), unit}
	return hex.EncodeToString(append(out, pdu...))
}

// readReqHex is an FC 0x03 request ADU.
func lgReadReq(txn uint16, addr, count uint16) string {
	return ledgerADU(txn, 1, 0x03, byte(addr>>8), byte(addr), byte(count>>8), byte(count))
}

// readRspHex is an FC 0x03 response ADU carrying vals.
func lgReadRsp(txn uint16, vals ...uint16) string {
	pdu := []byte{0x03, byte(len(vals) * 2)}
	for _, v := range vals {
		pdu = append(pdu, byte(v>>8), byte(v))
	}
	return ledgerADU(txn, 1, pdu...)
}

// writeReqHex is an FC 0x10 request ADU.
func lgWriteReq(txn uint16, addr uint16, vals ...uint16) string {
	pdu := []byte{0x10, byte(addr >> 8), byte(addr), byte(len(vals) >> 8), byte(len(vals)),
		byte(len(vals) * 2)}
	for _, v := range vals {
		pdu = append(pdu, byte(v>>8), byte(v))
	}
	return ledgerADU(txn, 1, pdu...)
}

// answeredRead is a completed read transaction.
func lgRead(seq, epoch uint64, addr uint16, vals ...uint16) LedgerEntry {
	now := time.Now().UTC()
	return LedgerEntry{
		Seq: seq, Epoch: epoch, Poll: 1, Conn: 1, Peer: "69.0.0.2:41234",
		TxnID: uint16(seq), UnitID: 1, FC: FCReadHoldingRegisters,
		Addr: addr, Count: uint16(len(vals)),
		Request:  lgReadReq(uint16(seq), addr, uint16(len(vals))),
		Response: lgReadRsp(uint16(seq), vals...), Outcome: outcomeAnswered,
		RequestAt: now, ResponseAt: &now,
	}
}

// exceptionRead is a read the device answered with an exception.
func lgException(seq, epoch uint64, addr uint16, code uint8) LedgerEntry {
	e := lgRead(seq, epoch, addr, 0)
	e.Outcome, e.Exception = outcomeException, code
	e.Response = ledgerADU(uint16(seq), 1, FCReadHoldingRegisters|0x80, code)
	return e
}

// writeTxn is a completed FC 0x10 write.
func lgWrite(seq, epoch uint64, addr uint16, vals ...uint16) LedgerEntry {
	now := time.Now().UTC()
	return LedgerEntry{
		Seq: seq, Epoch: epoch, Poll: 1, Conn: 1, Peer: "69.0.0.2:41234",
		TxnID: uint16(seq), UnitID: 1, FC: FCWriteMultipleRegisters,
		Addr: addr, Count: uint16(len(vals)),
		Request: lgWriteReq(uint16(seq), addr, vals...), Outcome: outcomeAnswered,
		RequestAt: now, ResponseAt: &now,
	}
}

// page wraps entries as GET /ledger would.
func lgPage(entries ...LedgerEntry) LedgerPage {
	p := LedgerPage{APIVersion: "1.1.0", Entries: entries, Total: len(entries)}
	if n := len(entries); n > 0 {
		p.NextSeq, p.HighSeq = entries[n-1].Seq, entries[n-1].Seq
	}
	p.Poll = PollState{Completed: 3, AnchorLocked: true,
		Anchor: PollAnchor{UnitID: 1, Addr: 40070, Count: 125},
		Rule:   "a poll cycle is the interval between two consecutive arrivals of the cycle anchor"}
	return p
}

// met builds a meeting that produced gradeable evidence.
func lgMet(epoch uint64, spec string, entries ...LedgerEntry) meeting {
	return meeting{Spec: spec, Epoch: epoch, Armed: true, Met: true, Page: lgPage(entries...)}
}

// ── The ledger decoders ───────────────────────────────────────────────────────

func TestLedgerEntryDecodesItsOwnBytes(t *testing.T) {
	r := lgRead(1, 5, 40070, 0x5375, 0x6E53, 0x1234)
	vals, ok := r.Values()
	if !ok {
		t.Fatalf("a well-formed read response did not decode: %s", r.Response)
	}
	if len(vals) != 3 || vals[0] != 0x5375 || vals[2] != 0x1234 {
		t.Fatalf("decoded %v, want [5375 6e53 1234]", vals)
	}
	if !r.Covers(40070) || !r.Covers(40072) || r.Covers(40073) || r.Covers(40069) {
		t.Errorf("Covers is wrong for a 3-register read at 40070")
	}
	if !r.IsRead() || r.IsWrite() {
		t.Errorf("an FC 0x03 transaction must classify as a read")
	}

	// An exception is NOT a read response, and must not decode as one — a
	// caller that mistook a two-byte exception PDU for a one-register answer
	// would report a fabricated value.
	if _, ok := lgException(2, 5, 40070, 0x04).Values(); ok {
		t.Error("an exception response decoded as register values")
	}

	w := lgWrite(3, 5, 40350, 0x1388, 0x0001)
	wv, ok := w.WriteValues()
	if !ok || len(wv) != 2 || wv[0] != 0x1388 {
		t.Fatalf("WriteValues decoded %v ok=%v, want [1388 0001]", wv, ok)
	}
	if !w.IsWrite() || w.IsRead() {
		t.Errorf("an FC 0x10 transaction must classify as a write")
	}
	// A write request is not a read response.
	if _, ok := w.Values(); ok {
		t.Error("a write request decoded as read response values")
	}
}

func TestLedgerPageSelectors(t *testing.T) {
	p := lgPage(
		lgRead(1, 5, 40000, 0x5375, 0x6E53),
		lgException(2, 5, 40070, 0x04),
		lgWrite(3, 6, 40350, 1),
	)
	if len(p.Reads()) != 2 || len(p.Writes()) != 1 {
		t.Fatalf("Reads=%d Writes=%d, want 2/1", len(p.Reads()), len(p.Writes()))
	}
	if got := p.Exceptions()[0x04]; len(got) != 1 || got[0].Seq != 2 {
		t.Fatalf("Exceptions()[0x04] = %+v", got)
	}
	if got := p.Addresses(); len(got) != 2 || got[0] != 40000 || got[1] != 40070 {
		t.Fatalf("Addresses() = %v, want the two read addresses sorted", got)
	}
	if !strings.Contains(p.Summary(), "3 transaction(s)") {
		t.Errorf("Summary() = %q", p.Summary())
	}
	// A truncated page must say so in its own summary, or a row could read an
	// incomplete window as an absence.
	p.Truncated = true
	if !strings.Contains(p.Summary(), "may be incomplete") {
		t.Errorf("a truncated page's summary does not warn: %q", p.Summary())
	}
}

// ── The client half, against a scripted simulator ────────────────────────────

// simScript is an HTTP simulator whose answers a test dictates.
type simScript struct {
	t *testing.T

	mu sync.Mutex
	// version is what GET /version answers; the zero value is a 1.1.0 sim with
	// everything registered.
	version string
	// epoch is bumped by every mutation.
	epoch uint64
	// noEpoch makes mutations answer 204, as a pre-1.1.0 sim does.
	noEpoch bool
	// entries is the ledger, and polls the completed cycle count. A test
	// mutates them from another goroutine to satisfy a wait.
	entries []LedgerEntry
	polls   uint64
	// anchorLocked reports whether the sim has worked out the cycle anchor.
	anchorLocked bool
	// waits counts /ledger?min_entries= and /poll/wait requests, so a test can
	// prove a barrier LOOPED rather than returning on its first answer.
	ledgerWaits, pollWaits int

	srv *httptest.Server
}

func newSimScript(t *testing.T) *simScript {
	t.Helper()
	s := &simScript{t: t, epoch: 1, anchorLocked: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		v := s.version
		s.mu.Unlock()
		if v == "" {
			v = `{"api_version":"1.1.0","endpoints":["GET /ledger","GET /poll","GET /poll/wait",` +
				`"POST /reset","POST /fault","epoch-acknowledged mutations"]}`
		}
		_, _ = w.Write([]byte(v))
	})
	mutate := func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if s.noEpoch {
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.epoch++
		ep := s.epoch
		s.mu.Unlock()
		// REV0907-H2: the epoch response write is checked and surfaced
		// through t, not discarded — a broken write here would otherwise
		// silently strand a test waiting on an epoch bump that never left
		// the wire.
		if _, err := fmt.Fprintf(w, `{"api_version":"1.1.0","epoch":%d}`, ep); err != nil {
			t.Errorf("mutate handler: write epoch response: %v", err)
		}
	}
	mux.HandleFunc("/fault", mutate)
	mux.HandleFunc("/inject", mutate)
	mux.HandleFunc("/reset", mutate)
	mux.HandleFunc("/ledger", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseUint(r.URL.Query().Get("since_epoch"), 10, 64)
		minEntries, _ := strconv.Atoi(r.URL.Query().Get("min_entries"))
		s.mu.Lock()
		if minEntries > 0 {
			s.ledgerWaits++
		}
		var out []LedgerEntry
		for _, e := range s.entries {
			if e.Epoch >= since {
				out = append(out, e)
			}
		}
		s.mu.Unlock()
		writeLedgerJSON(w, out)
	})
	poll := func(wait bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			want, _ := strconv.ParseUint(r.URL.Query().Get("epoch"), 10, 64)
			s.mu.Lock()
			if wait {
				s.pollWaits++
			}
			reached := !wait || s.polls >= want
			s.mu.Unlock()
			if wait && !reached {
				// The real endpoint blocks for its own `timeout` before
				// answering reached=false. Standing in for that keeps a
				// caller's retry loop a WAIT rather than a hot spin, which is
				// the behaviour under test.
				deadline := time.Now().Add(120 * time.Millisecond)
				for time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
					s.mu.Lock()
					reached = s.polls >= want
					s.mu.Unlock()
					if reached {
						break
					}
				}
			}
			s.mu.Lock()
			body := fmt.Sprintf(`{"api_version":"1.1.0","reached":%v,"want":%d,"epoch":%d,`+
				`"poll":{"completed":%d,"open":%d,"anchor":{"unit_id":1,"addr":40070,"count":125},`+
				`"anchor_locked":%v,"anchor_source":"learned","sessions":1,"rule":"the cycle rule"},`+
				`"tap":{"connections":1}}`,
				reached, want, s.epoch, s.polls, s.polls+1, s.anchorLocked)
			s.mu.Unlock()
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("/poll", poll(false))
	mux.HandleFunc("/poll/wait", poll(true))
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func writeLedgerJSON(w http.ResponseWriter, out []LedgerEntry) {
	var sb strings.Builder
	sb.WriteString(`{"api_version":"1.1.0","entries":[`)
	for i, e := range out {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"seq":%d,"epoch":%d,"poll":%d,"conn":%d,"peer":%q,"txn_id":%d,`+
			`"unit_id":%d,"fc":%d,"addr":%d,"count":%d,"request":%q,"response":%q,`+
			`"exception":%d,"outcome":%q,"fault":%q}`,
			e.Seq, e.Epoch, e.Poll, e.Conn, e.Peer, e.TxnID, e.UnitID, e.FC, e.Addr, e.Count,
			e.Request, e.Response, e.Exception, e.Outcome, e.Fault)
	}
	fmt.Fprintf(&sb, `],"total":%d,"high_seq":%d}`, len(out), len(out))
	_, _ = w.Write([]byte(sb.String()))
}

// add appends a ledger entry, as the DUT transacting would.
func (s *simScript) add(e LedgerEntry) {
	s.mu.Lock()
	s.entries = append(s.entries, e)
	s.mu.Unlock()
}

// completeCycles advances the poll counter.
func (s *simScript) completeCycles(n uint64) {
	s.mu.Lock()
	s.polls += n
	s.mu.Unlock()
}

func (s *simScript) counts() (ledger, poll int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ledgerWaits, s.pollWaits
}

// testRunCtx is the minimum RunCtx these unit tests need. Case is set because
// RunCtx.Logf prefixes every line with the case uid and would otherwise
// dereference a nil.
func testRunCtx(simURL string) *certify.RunCtx {
	return &certify.RunCtx{
		Case:    &certify.Case{UID: "ss-modbus-client-conf-v1.1::TEST"},
		Targets: certify.Targets{ModSim: "69.0.0.20:5020", ModSimAPI: simURL},
		Sims:    map[string]*certify.SimClient{"modsim": certify.NewSimClient("modsim", simURL, nil)},
		Params:  map[string]string{},
		Log:     certify.DiscardLogger,
	}
}

// dut builds a determinism handle against the scripted sim.
func (s *simScript) dut(t *testing.T) *determinism {
	t.Helper()
	rc := testRunCtx(s.srv.URL)
	o, why := newObserver(rc)
	if o == nil {
		t.Fatalf("newObserver: %s", why)
	}
	d, err := o.determinism(context.Background())
	if err != nil {
		t.Fatalf("determinism: %v", err)
	}
	return d
}

func TestDeterminismRefusesASimThatCannotFence(t *testing.T) {
	s := newSimScript(t)
	for _, tc := range []struct {
		name, version, want string
	}{
		{"a pre-1.1.0 sim", `{"api_version":"1.0.0","endpoints":["GET /state","POST /fault"]}`,
			"GET /ledger"},
		{"a sim started with -tap=false",
			`{"api_version":"1.1.0","endpoints":["POST /reset","epoch-acknowledged mutations"]}`,
			"-tap=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.mu.Lock()
			s.version = tc.version
			s.mu.Unlock()
			o, _ := newObserver(testRunCtx(s.srv.URL))
			_, err := o.determinism(context.Background())
			if err == nil {
				t.Fatal("a sim that cannot fence was accepted; the row would then read an empty " +
					"ledger as 'the DUT did nothing'")
			}
			if !errors.Is(err, errNoDeterministicSim) {
				t.Errorf("error %v does not wrap errNoDeterministicSim", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal %q does not name %q", err, tc.want)
			}
			// The row's SKIP text must be actionable, not just a complaint.
			if skip := deterministicSkip(err); !strings.Contains(skip, "observed: none") {
				t.Errorf("the SKIP text does not say what the alternative costs: %s", skip)
			}
		})
	}
	s.mu.Lock()
	s.version = ""
	s.mu.Unlock()
}

func TestPostForEpochRefusesASimWithNoEpoch(t *testing.T) {
	s := newSimScript(t)
	s.mu.Lock()
	s.noEpoch = true
	s.mu.Unlock()
	client := certify.NewSimClient("modsim", s.srv.URL, nil)

	_, err := postForEpoch(context.Background(), client, "/fault", map[string]any{"kind": "tcp_drop"})
	if err == nil {
		t.Fatal("a 204 acknowledgement was accepted as a fence; epoch 0 fences nothing, and a row " +
			"that fenced on it would grade the whole run's traffic")
	}
	if !strings.Contains(err.Error(), simAPIVersionNeeded) {
		t.Errorf("the error %q does not name the version needed", err)
	}
}

func TestAwaitLedgerReturnsWhenTheTransactionsArrive(t *testing.T) {
	s := newSimScript(t)
	d := s.dut(t)

	// Nothing yet: the first slice must come back unsatisfied, and the wait
	// must LOOP rather than give up on one answer.
	go func() {
		time.Sleep(30 * time.Millisecond)
		s.add(lgRead(1, 2, 40070, 1, 2))
		s.add(lgRead(2, 2, 40195, 3))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got, observed, err := d.awaitLedger(ctx, 2, 2)
	if err != nil {
		t.Fatalf("awaitLedger: %v", err)
	}
	if !observed {
		t.Fatalf("the wait reported the DUT never transacted, though two transactions arrived: %+v", got)
	}
	if got.Total != 2 {
		t.Fatalf("returned %d transaction(s), want 2", got.Total)
	}
	if l, _ := s.counts(); l < 1 {
		t.Errorf("the barrier issued %d bounded ledger request(s); it must go through /ledger's own "+
			"wait rather than busy-polling", l)
	}
}

func TestAwaitLedgerReportsAnUnmetProvocationRatherThanFailing(t *testing.T) {
	s := newSimScript(t)
	d := s.dut(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	got, observed, err := d.awaitLedger(ctx, 9, 1)
	// A cancelled context is reported as an error to the caller's own ctx, and
	// an exhausted budget as observed=false. Either way the caller learns "the
	// DUT did not transact", never "the wait failed".
	if observed {
		t.Fatal("the wait claimed the DUT transacted when nothing was in the ledger")
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Total != 0 {
		t.Fatalf("returned %d transaction(s), want 0", got.Total)
	}
}

func TestAwaitMatchWaitsForTheParticularThing(t *testing.T) {
	s := newSimScript(t)
	d := s.dut(t)
	// Reads arrive first and must NOT satisfy a wait for a write.
	s.add(lgRead(1, 2, 40070, 1))
	s.add(lgRead(2, 2, 40195, 2))
	go func() {
		time.Sleep(40 * time.Millisecond)
		s.add(lgWrite(3, 2, 40350, 0x1388))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got, observed, err := d.awaitMatch(ctx, 2, "issue a register write",
		func(p LedgerPage) bool { return len(p.Writes()) > 0 })
	if err != nil {
		t.Fatalf("awaitMatch: %v", err)
	}
	if !observed {
		t.Fatalf("the wait ended without the write it was waiting for: %+v", got)
	}
	if w := got.Writes(); len(w) != 1 || w[0].Addr != 40350 {
		t.Fatalf("returned writes %+v, want the one at 40350", w)
	}
}

func TestAwaitPollWaitsForACompleteCycle(t *testing.T) {
	s := newSimScript(t)
	d := s.dut(t)
	go func() {
		time.Sleep(30 * time.Millisecond)
		s.completeCycles(3)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rep, observed, err := d.awaitPoll(ctx, 1)
	if err != nil {
		t.Fatalf("awaitPoll: %v", err)
	}
	if !observed {
		t.Fatalf("the barrier reported the DUT never completed a cycle: %+v", rep.Poll)
	}
	if _, p := s.counts(); p < 1 {
		t.Errorf("the barrier issued %d /poll/wait request(s)", p)
	}
	if note := pollRuleNote(rep); !strings.Contains(note, "rule") {
		t.Errorf("the note a bundle records does not carry the barrier's own rule: %s", note)
	}
}

// TestAwaitPollCountsFromWhereItStarted: the barrier asks for n MORE completed
// cycles, not for cycle n. A caller that started at cycle 5 and asked for one
// must not be satisfied by the five that were already finished.
func TestAwaitPollCountsFromWhereItStarted(t *testing.T) {
	s := newSimScript(t)
	s.completeCycles(5)
	d := s.dut(t)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, observed, _ := d.awaitPoll(ctx, 1); observed {
		t.Fatal("awaitPoll was satisfied by cycles that had already completed before it was called")
	}

	// One more completes WHILE the barrier is waiting, and it returns.
	go func() {
		time.Sleep(30 * time.Millisecond)
		s.completeCycles(1)
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	rep, observed, err := d.awaitPoll(ctx2, 1)
	if err != nil {
		t.Fatalf("awaitPoll: %v", err)
	}
	if !observed {
		t.Fatalf("the barrier did not see the cycle that completed: %+v", rep.Poll)
	}
}

// TestAwaitPollWithNoAnchorYetWaitsForRealCycles: while the sim is still
// learning the client's cycle shape it reports zero, and zero means "I do not
// know" rather than "none happened". A barrier that took it at face value
// would return the instant the anchor locked and credit itself cycles it never
// waited for.
func TestAwaitPollWithNoAnchorYetWaitsForRealCycles(t *testing.T) {
	s := newSimScript(t)
	s.mu.Lock()
	s.anchorLocked = false
	s.mu.Unlock()
	d := s.dut(t)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, observed, _ := d.awaitPoll(ctx, 1); observed {
		t.Fatal("the barrier was satisfied while the sim had not yet identified the cycle anchor")
	}
	// Two cycles is what the tracker credits itself the moment it locks.
	go func() {
		time.Sleep(30 * time.Millisecond)
		s.completeCycles(2)
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if _, observed, _ := d.awaitPoll(ctx2, 1); !observed {
		t.Fatal("the barrier did not return once the tracker had counted its first cycles")
	}
}

func TestPollRuleNoteReportsAnUnlockedAnchorHonestly(t *testing.T) {
	rep := PollReport{Poll: PollState{Completed: 4, AnchorLocked: false}}
	note := pollRuleNote(rep)
	if !strings.Contains(note, "not yet identified") {
		t.Errorf("an unlocked anchor must not be reported as though its cycle count meant something: %s",
			note)
	}
	if strings.Contains(note, "4 completed") {
		t.Errorf("the note quoted a cycle count from a tracker with no anchor: %s", note)
	}
}

// ── ERR-2's decision logic ────────────────────────────────────────────────────

func TestEvalERR2PassesEachClassTheLedgerConfirms(t *testing.T) {
	d := &determinism{o: &observer{sim: certify.NewSimClient("modsim", "http://sim", nil)}}
	phases := []*exceptionPhase{
		{Code: 0x04, M: lgMet(7, `{"kind":"exception_code" "code":4}`, lgException(1, 7, 40070, 0x04))},
		{Code: 0x0B, M: lgMet(9, `{"kind":"exception_code" "code":11}`, lgException(2, 9, 40070, 0x0B))},
	}
	fs := evalERR2(nil, phases, d)
	if len(fs) != 2 {
		t.Fatalf("%d finding(s), want one per class", len(fs))
	}
	for i, f := range fs {
		if f.Verdict != certify.Pass {
			t.Errorf("class %d: verdict %s, want PASS: %s", i, f.Verdict, f.Observed)
		}
		if f.Kind != citeNarrative {
			t.Errorf("class %d: with no capture the claim must be a Narrative naming the ledger", i)
		}
	}
}

func TestEvalERR2WarnsWhenTheArmedClassIsNotWhatArrived(t *testing.T) {
	d := &determinism{o: &observer{sim: certify.NewSimClient("modsim", "http://sim", nil)}}
	// Armed 0x02, the device answered 0x04. That is the sim's contract and its
	// wire behaviour disagreeing — a BENCH defect, and the assertion must say
	// so rather than failing the DUT.
	phases := []*exceptionPhase{
		{Code: 0x02, M: lgMet(7, `{"code":2}`, lgException(1, 7, 40070, 0x04))},
	}
	f := evalERR2(nil, phases, d)[0]
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "bench defect") {
		t.Errorf("the finding blames the DUT for a bench problem: %s", f.Observed)
	}
}

func TestEvalERR2SkipsAClassTheDUTNeverMet(t *testing.T) {
	d := &determinism{o: &observer{sim: certify.NewSimClient("modsim", "http://sim", nil)}}
	phases := []*exceptionPhase{
		{Code: 0x03, M: meeting{Spec: `{"code":3}`, Armed: true, Epoch: 7, Met: false}},
		{Code: 0x01, M: meeting{Spec: `{"code":1}`, ArmErr: errors.New("no such kind")}},
	}
	fs := evalERR2(nil, phases, d)
	for i, f := range fs {
		if f.Verdict != certify.Skip {
			t.Errorf("phase %d: verdict %s, want SKIP: %s", i, f.Verdict, f.Observed)
		}
	}
	if !strings.Contains(fs[1].Observed, "no such kind") {
		t.Errorf("the arming failure was not reported: %s", fs[1].Observed)
	}
}

func TestEvalERR2RecoveryFailsAClientThatNeverComesBack(t *testing.T) {
	d := &determinism{o: &observer{sim: certify.NewSimClient("modsim", "http://sim", nil)}}
	f := evalERR2Recovery(nil, LedgerPage{}, false, 12, d)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL: %s", f.Verdict, f.Observed)
	}
	// A client that transacts but never SUCCEEDS has also not recovered.
	f = evalERR2Recovery(nil, lgPage(lgException(1, 12, 40070, 0x04)), true, 12, d)
	if f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL when nothing completed normally: %s", f.Verdict, f.Observed)
	}
	// And one that does succeed has.
	f = evalERR2Recovery(nil, lgPage(lgRead(1, 12, 40070, 1, 2)), true, 12, d)
	if f.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
}

func TestERR2JournalDistinguishesAnErrorLineFromANamedCode(t *testing.T) {
	// §2.9.2's criterion is "accurately log all exception codes". A line
	// saying a device is unavailable does not say WHICH code — and the
	// assertion must not accept it as though it did.
	f := err2Journal([]string{"lexa-modbus: device inv-plain session dropped — will reconnect on next poll"},
		"inv-plain")
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "does not say which code") {
		t.Errorf("the finding does not draw the distinction the criterion turns on: %s", f.Observed)
	}
	// A line that DOES name a class passes.
	f = err2Journal([]string{"lexa-modbus: inv-plain read error: server device failure"}, "inv-plain")
	if f.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS when the class is named: %s", f.Verdict, f.Observed)
	}
}

// ── ERR-1's decision logic ────────────────────────────────────────────────────

func err1Determinism() *determinism {
	return &determinism{o: &observer{sim: certify.NewSimClient("modsim", "http://sim", nil)}}
}

func TestEvalERR1PassesAClientThatProbesOnlyLegalBases(t *testing.T) {
	d := err1Determinism()
	p := lgPage(
		lgRead(1, 7, 40000, 0, 0),
		lgRead(2, 7, 0, 0, 0),
		lgRead(3, 7, 50000, 0, 0),
	)
	f := evalERR1Probes(nil, p, true, 7, nil, nil, d)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
	for _, want := range []string{"40001", "40000", "50000"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the finding does not mention %s: %s", want, f.Observed)
		}
	}
}

func TestEvalERR1FailsAClientThatHuntsAtTheNoncompliantOffset(t *testing.T) {
	d := err1Determinism()
	p := lgPage(
		lgRead(1, 7, 40000, 0, 0),
		lgRead(2, 7, noncompliantBase, 0x5375, 0x6E53), // found the map where it should not look
	)
	f := evalERR1Probes(nil, p, true, 7, nil, nil, d)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL: %s", f.Verdict, f.Observed)
	}
}

func TestEvalERR1CallsAServedIdentifierABenchDefect(t *testing.T) {
	d := err1Determinism()
	// The relocation did not take: a legal base still answers with the
	// identifier. That is the sim's fault, not the DUT's.
	p := lgPage(lgRead(1, 7, 40000, 0x5375, 0x6E53))
	f := evalERR1Probes(nil, p, true, 7, nil, nil, d)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !strings.Contains(f.Observed, "bench defect") {
		t.Errorf("a provocation that did not hold must not read as a DUT finding: %s", f.Observed)
	}
}

func TestEvalERR1SkipsWithItsOwnReasons(t *testing.T) {
	d := err1Determinism()
	for _, tc := range []struct {
		name string
		f    finding
		want string
	}{
		{"the map could not move",
			evalERR1Probes(nil, LedgerPage{}, false, 0, errors.New("no such kind"), nil, d), "no such kind"},
		{"the connection could not be severed",
			evalERR1Probes(nil, LedgerPage{}, false, 7, nil, errors.New("refused"), d), "caches the block layout"},
		{"the DUT did not re-probe",
			evalERR1Probes(nil, LedgerPage{}, false, 7, nil, nil, d), "fewer than the three base probes"},
	} {
		if tc.f.Verdict != certify.Skip {
			t.Errorf("%s: verdict %s, want SKIP", tc.name, tc.f.Verdict)
		}
		if !strings.Contains(tc.f.Observed, tc.want) {
			t.Errorf("%s: the reason does not say %q: %s", tc.name, tc.want, tc.f.Observed)
		}
	}
}

func TestEvalERR1RecoveryNeedsACompletedTransaction(t *testing.T) {
	d := err1Determinism()
	if f := evalERR1Recovery(LedgerPage{}, false, 9, nil, d); f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL when the client never comes back", f.Verdict)
	}
	if f := evalERR1Recovery(lgPage(lgRead(1, 9, 40000, 0x5375, 0x6E53)), true, 9, nil, d); f.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS", f.Verdict)
	}
}

// ── PROT-1's decision logic ───────────────────────────────────────────────────

func TestEvalPartialReadingGradesWhatWasDelivered(t *testing.T) {
	d := err1Determinism()
	dropped := lgRead(1, 5, 40070, 1)
	dropped.Outcome, dropped.Response, dropped.Fault = outcomeDropped, "", "next_response:drop"
	r := &partialReading{
		Name: "a response the server never sent", Action: "drop", Outcome: outcomeDropped,
		Doc: "the client is left holding an incomplete transaction",
		M:   lgMet(5, `{"action":"drop"}`, dropped),
	}
	f := evalPartialReading(nil, r, d)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "nothing at all") {
		t.Errorf("the finding does not say what the client actually received: %s", f.Observed)
	}

	// A one-shot the sim did not honour is a BENCH defect.
	r.M = lgMet(5, `{"action":"drop"}`, lgRead(1, 5, 40070, 1))
	f = evalPartialReading(nil, r, d)
	if f.Verdict != certify.Warn || !strings.Contains(f.Observed, "bench defect") {
		t.Errorf("verdict = %s: an unhonoured one-shot must read as a bench defect: %s",
			f.Verdict, f.Observed)
	}
}

func TestEvalPartialRecoveryIsHeldOnTheLedger(t *testing.T) {
	d := err1Determinism()
	r := &partialReading{Name: "a truncated response", M: meeting{Armed: true, Epoch: 5}, Fence: 6}
	if f := evalPartialRecovery(r, d); f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL when the client never transacts again", f.Verdict)
	}
	r.Recovered, r.Recovery = true, lgPage(lgRead(1, 6, 40070, 1))
	if f := evalPartialRecovery(r, d); f.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS", f.Verdict)
	}
	// A reading that was never delivered has nothing to recover from.
	r2 := &partialReading{Name: "x", M: meeting{ArmErr: errors.New("nope")}}
	if f := evalPartialRecovery(r2, d); f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
}

func TestPROT1NamesTheCommonModelGapAsADUTGap(t *testing.T) {
	f := prot1CommonModelGap()
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP", f.Verdict)
	}
	for _, want := range []string{"identifyNow", "DUT-side", "process restart"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the gap text does not carry %q, so a reader cannot act on it: %s", want, f.Observed)
		}
	}
}

// ── WR-1 / WR-2 ───────────────────────────────────────────────────────────────

func TestWR1QuotesTheProcedureAndBothReadings(t *testing.T) {
	f := wr1NotApplicable(nil)
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP (recorded as addressed and not executed)", f.Verdict)
	}
	// The judgement must quote the text it rests on…
	for _, want := range []string{
		"Validates that all implemented adjustable points in the model can be written individually " +
			"using Modbus Function Code 0x06",
		"fcWriteMultipleRegisters",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the N/A judgement does not quote %q: %s", want, f.Observed)
		}
	}
	// …AND state the reading that would make it a product gap, so a lab can
	// disagree with it on the evidence rather than on faith.
	if !strings.Contains(f.Observed, "PRODUCT GAP") {
		t.Errorf("the judgement does not state the counter-reading: %s", f.Observed)
	}
	if !strings.Contains(f.Observed, "§2.6.2") {
		t.Errorf("the judgement does not cite the sibling row that covers the same points: %s", f.Observed)
	}
}

func TestEvalWR2WriteGradesFraming(t *testing.T) {
	d := err1Determinism()
	run := &writeRun{HaveFirst: true, First: lgWrite(3, 5, 40350, 0x1388, 0x0001)}
	if f := evalWR2Write(nil, run, d); f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}

	// A quantity that disagrees with the payload is a FAIL, and one over the
	// 123-register ceiling too.
	bad := lgWrite(3, 5, 40350, 0x1388)
	bad.Count = 9
	run.First = bad
	if f := evalWR2Write(nil, run, d); f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL on a quantity/byte-count disagreement", f.Verdict)
	}

	run.HaveFirst = false
	f := evalWR2Write(nil, run, d)
	if f.Verdict != certify.Skip || !strings.Contains(f.Observed, paramDERControl) {
		t.Errorf("an absent write must SKIP naming the lever that would produce one: %s", f.Observed)
	}
}

func TestEvalWR2ReassertNeedsTheDivergedAddressBack(t *testing.T) {
	d := err1Determinism()
	run := &writeRun{
		HaveFirst: true, First: lgWrite(3, 5, 40350, 0x1388),
		DivergeAddr: 40350, DivergeEpoch: 6,
		ReassertPage: lgPage(lgRead(4, 6, 40070, 1)),
	}
	f := evalWR2Reassert(run, d)
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN when no re-assert follows: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "trusting its own last write") {
		t.Errorf("the finding does not distinguish the two explanations: %s", f.Observed)
	}

	run.HaveReassert, run.Reassert = true, lgWrite(5, 6, 40350, 0x1388)
	if f := evalWR2Reassert(run, d); f.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
}

func TestEvalWR2ReadBackComparesTheWrittenWordWithTheReadWord(t *testing.T) {
	d := err1Determinism()
	run := &writeRun{
		DivergeAddr:  40350,
		HaveReassert: true, Reassert: lgWrite(5, 6, 40350, 0x1388, 0x0001),
		HaveReadBack: true, ReadBack: lgRead(6, 6, 40350, 0x1388, 0x0001),
	}
	if f := evalWR2ReadBack(run, d); f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}

	// A write that was acknowledged and did not take is the failure this
	// assertion exists to catch.
	run.ReadBack = lgRead(6, 6, 40350, 0x2710, 0x0001)
	f := evalWR2ReadBack(run, d)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "did not take") {
		t.Errorf("the finding does not name the failure: %s", f.Observed)
	}

	run.HaveReadBack = false
	if f := evalWR2ReadBack(run, d); f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP when no read-back was observed", f.Verdict)
	}
}

// ── CLI-3 and CLI-4 ───────────────────────────────────────────────────────────

func TestEvalUnitIDsFromLedger(t *testing.T) {
	d := err1Determinism()
	disc := rediscovery{Observed: true, Page: lgPage(
		lgRead(1, 2, 40000, 1), lgRead(2, 2, 40070, 2))}
	if f := evalUnitIDsFromLedger(disc, "", false, d); f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
	// A declared unit id that does not match is a FAIL against the operator's
	// own statement.
	if f := evalUnitIDsFromLedger(disc, "7", true, d); f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL against a mismatched -param declaration", f.Verdict)
	}
	// The RTU broadcast address has no meaning over Modbus/TCP.
	bad := lgRead(1, 2, 40000, 1)
	bad.UnitID = 0
	if f := evalUnitIDsFromLedger(rediscovery{Observed: true, Page: lgPage(bad)}, "", false, d); f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL on unit id 0", f.Verdict)
	}
}

func TestEvalCLI3ReaddressedIsAnObservationNotTheCriterion(t *testing.T) {
	d := err1Determinism()
	m := lgMet(4, `{"kind":"unit_id","unit_id":247}`, lgException(1, 4, 40070, 0x0B))
	f := evalCLI3Readdressed(m, d)
	// The suite's own rule: an observation adjacent to a criterion carries
	// SKIP, never PASS, or it would silently promote a row nobody demonstrated.
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP: this is adjacent evidence, not §2.4.3's criterion", f.Verdict)
	}
	if !strings.Contains(f.Observed, "OBSERVATION, not the criterion") {
		t.Errorf("the finding does not say what it is not: %s", f.Observed)
	}
}

func TestCLI3GapNamesTheDUTSideConstraint(t *testing.T) {
	f := cli3DifferentUnitIDs()
	for _, want := range []string{"BENCH HALF IS READY", "process start", "READ-ONLY BY CONSTRUCTION"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the gap text does not carry %q: %s", want, f.Observed)
		}
	}
}

func TestEvalBaseSweepGradesEachLegOnItsOwnPage(t *testing.T) {
	d := err1Determinism()
	sunS := func(seq, epoch uint64, base uint16) LedgerEntry {
		return lgRead(seq, epoch, base, 0x5375, 0x6E53)
	}
	sweep := []baseAttempt{
		{Base: 0, Disc: rediscovery{Fence: 3, Observed: true,
			Page: lgPage(sunS(1, 3, 0), lgRead(2, 3, 2, 1, 2))}},
		{Base: 50000, Disc: rediscovery{Fence: 5, Observed: true,
			Page: lgPage(sunS(3, 5, 50000), lgRead(4, 5, 50002, 1, 2))}},
		{Base: 40000, Disc: rediscovery{Fence: 7, Observed: true,
			Page: lgPage(sunS(5, 7, 40000), lgRead(6, 7, 40002, 1, 2))}},
	}
	f := evalBaseSweep(sweep, "", d)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}

	// One leg that never got its identifier back downgrades the whole finding
	// and says which.
	sweep[1].Disc.Page = lgPage(lgRead(3, 5, 50000, 0, 0))
	f = evalBaseSweep(sweep, "", d)
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "base 50000: the DUT probed it, but no response carried") {
		t.Errorf("the finding does not name the failing leg: %s", f.Observed)
	}

	// A relocation that failed is reported as such, not as a DUT finding.
	sweep[0] = baseAttempt{Base: 0, RelocateErr: errors.New("refused")}
	f = evalBaseSweep(sweep, "", d)
	if !strings.Contains(f.Observed, "could not be re-homed") {
		t.Errorf("a failed relocation must be reported as a bench fact: %s", f.Observed)
	}
	if f := evalBaseSweep(nil, "injection is off", d); f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP with no sweep at all", f.Verdict)
	}
}

func TestEvalRediscoveryReportsWhatArrived(t *testing.T) {
	d := err1Determinism()
	if f := evalRediscovery(rediscovery{Err: errors.New("refused")}, d); f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP when the connection could not be severed", f.Verdict)
	}
	if f := evalRediscovery(rediscovery{Fence: 3}, d); f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN when no burst arrived", f.Verdict)
	}
	f := evalRediscovery(rediscovery{Fence: 3, Observed: true,
		Page: lgPage(lgRead(1, 3, 40000, 0x5375, 0x6E53))}, d)
	if f.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
}

func TestCommonModelBodyGapIsStatedAsADUTGap(t *testing.T) {
	f := commonModelBodyGap()
	for _, want := range []string{"identifyNow", "DUT-SIDE OBSERVABILITY GAP", "process restart"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the gap text does not carry %q: %s", want, f.Observed)
		}
	}
}

// ── INFO-2's sweep ────────────────────────────────────────────────────────────

// TestInfoSentinelTablesAgree pins this suite's own sentinel table against the
// widths the sweep lays out with. A disagreement here would seed a datatype at
// an address the next one overwrites.
func TestInfoSentinelTablesAgree(t *testing.T) {
	for _, typ := range infoDatatypes {
		w := infoSentinelWords(typ)
		if len(w) == 0 {
			t.Errorf("datatype %q has no sentinel words in this suite's table", typ)
			continue
		}
		if len(w) != infoSentinelWidth(typ) {
			t.Errorf("datatype %q: %d word(s) but width %d", typ, len(w), infoSentinelWidth(typ))
		}
	}
	// The two variable-width types are the ones a caller must pass a length
	// for, and their defaults must be the ones the sweep uses.
	if infoSentinelWidth("ipv6addr") != 8 {
		t.Errorf("ipv6addr width = %d, want 8 (128 bits)", infoSentinelWidth("ipv6addr"))
	}
	if got := len(infoDatatypes); got != 22 {
		t.Errorf("%d datatypes, want the 22 the catalog's own precondition list enumerates", got)
	}
}

func TestEvalINFO2SweepConfirmsEachSeededType(t *testing.T) {
	d := err1Determinism()
	sweep := []seeded{
		{Type: "int16", Addr: 40072, Words: []uint16{0x8000}},
		{Type: "uint16", Addr: 40073, Words: []uint16{0xFFFF}},
		{Type: "int32", Addr: 40074, Words: []uint16{0x8000, 0x0000}},
	}
	// The DUT read the whole block back, sentinels and all.
	m := lgMet(9, `{"unimplemented":[…]}`,
		lgRead(1, 9, 40072, 0x8000, 0xFFFF, 0x8000, 0x0000))
	f := evalINFO2Sweep(sweep, m, nil, d)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
	for _, typ := range []string{"int16", "uint16", "int32"} {
		if !strings.Contains(f.Observed, typ) {
			t.Errorf("the finding does not name %q: %s", typ, f.Observed)
		}
	}

	// A type the DUT did not read is reported as unread, not as absent.
	m = lgMet(9, `{"unimplemented":[…]}`, lgRead(1, 9, 40072, 0x8000))
	f = evalINFO2Sweep(sweep, m, nil, d)
	if f.Verdict != certify.Warn || !strings.Contains(f.Observed, "fell outside the registers") {
		t.Errorf("verdict = %s: an unread seed must be distinguished from a wrong one: %s",
			f.Verdict, f.Observed)
	}

	// A value that came back WRONG is a bench defect, not a DUT finding.
	m = lgMet(9, `{"unimplemented":[…]}`, lgRead(1, 9, 40072, 0x1234, 0xFFFF, 0x8000, 0x0000))
	f = evalINFO2Sweep(sweep, m, nil, d)
	if !strings.Contains(f.Observed, "bench defect") {
		t.Errorf("a served value other than the one seeded must read as a bench defect: %s", f.Observed)
	}

	if f := evalINFO2Sweep(nil, meeting{}, errors.New("no anchor"), d); f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP when the sweep could not be laid out", f.Verdict)
	}
}

func TestEvalINFO2BlanketNeedsAWhollySentinelResponse(t *testing.T) {
	d := err1Determinism()
	// 0x8000 is int16's not-implemented value; a response of them all is the
	// blanket in force.
	m := lgMet(4, `{"kind":"nan_sentinel"}`, lgRead(1, 4, 40070, 0x8000, 0x8000, 0x8000))
	if f := evalINFO2Blanket(m, d); f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
	// A response with a real value in it means the blanket was not in force.
	m = lgMet(4, `{"kind":"nan_sentinel"}`, lgRead(1, 4, 40070, 0x8000, 0x1234))
	if f := evalINFO2Blanket(m, d); f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN", f.Verdict)
	}
}

func TestINFO2RenderingGapNamesTheSpecificationsOwnAmbiguity(t *testing.T) {
	f := info2RenderingGap()
	if !strings.Contains(f.Observed, "acc16") || !strings.Contains(f.Observed, "ZERO") {
		t.Errorf("the gap text does not record that some datatypes' sentinel is indistinguishable "+
			"from an ordinary reading: %s", f.Observed)
	}
}

// ── The meeting vocabulary ────────────────────────────────────────────────────

func TestMeetingReasonSaysWhichThingWentWrong(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    meeting
		want string
	}{
		{"arming failed", meeting{Spec: "{}", ArmErr: errors.New("no such kind")}, "could not be armed"},
		{"the ledger could not be read",
			meeting{Spec: "{}", Armed: true, Epoch: 3, LedgerErr: errors.New("500")}, "could not be read"},
		{"the DUT never met it", meeting{Spec: "{}", Armed: true, Epoch: 3}, "not polling this server"},
		{"it was met", lgMet(3, "{}", lgRead(1, 3, 40070, 1)), "the DUT met it"},
	} {
		if got := tc.m.reason(); !strings.Contains(got, tc.want) {
			t.Errorf("%s: reason %q does not say %q", tc.name, got, tc.want)
		}
	}
	if lgMet(3, "{}", lgRead(1, 3, 40070, 1)).ok() != true {
		t.Error("a meeting with evidence must report ok()")
	}
	if (meeting{Armed: true, Met: true}).ok() {
		t.Error("a meeting with no transactions must not report ok()")
	}
}
