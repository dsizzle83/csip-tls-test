package sim

// tap_test.go drives the wire tap the way the bench does: a scripted Modbus
// client, shaped like lexa-gw's poll loop, talking through a real relay to a
// real socket.
//
// Two things are being proved, and they are different:
//
//	TRANSPARENCY — with nothing armed, every byte the client sends reaches the
//	device and every byte the device sends reaches the client, unchanged and in
//	order. This is the licence for the tap to be ON BY DEFAULT while the two
//	adversary relays beside it are opt-in, so it is pinned rather than asserted
//	in a comment.
//
//	DETERMINISM — the poll barrier and the one-shot fault land where they are
//	aimed, every time. These cases carry no sleeps of their own: they wait on
//	the barrier or on a bounded socket deadline, which is exactly the property
//	the whole exercise exists to give the conformance rows. Run them with
//	-count=50 -race and they must not flake, because a bench row cannot.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ── A device to talk to ───────────────────────────────────────────────────────

// fakeDevice is a minimal Modbus/TCP server: it answers FC 0x03 with a
// deterministic register pattern and FC 0x10 with the standard echo. It is
// written from the specification, by hand, for the same reason wire.go's
// framer is: a test that drove the tap through the same library the tap parses
// would not be testing the parse.
type fakeDevice struct {
	t  *testing.T
	ln net.Listener

	mu    sync.Mutex
	seen  [][]byte // every request frame, verbatim, as the device received it
	sent  [][]byte // every response frame, verbatim, as the device composed it
	excFC map[uint16]uint8
	wg    sync.WaitGroup
	done  chan struct{}
}

func newFakeDevice(t *testing.T) *fakeDevice {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake device listen: %v", err)
	}
	d := &fakeDevice{t: t, ln: ln, excFC: map[uint16]uint8{}, done: make(chan struct{})}
	d.wg.Add(1)
	go d.serve()
	t.Cleanup(d.close)
	return d
}

func (d *fakeDevice) addr() string { return d.ln.Addr().String() }

func (d *fakeDevice) close() {
	select {
	case <-d.done:
		return
	default:
	}
	close(d.done)
	_ = d.ln.Close()
	d.wg.Wait()
}

// exceptAt makes the device answer any read covering addr with the given
// Modbus exception code, so the ledger's exception path has something real to
// record.
func (d *fakeDevice) exceptAt(addr uint16, code uint8) {
	d.mu.Lock()
	d.excFC[addr] = code
	d.mu.Unlock()
}

func (d *fakeDevice) serve() {
	defer d.wg.Done()
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			// d.close (t.Cleanup) waits on d.wg before returning, so this
			// still runs within the test's active lifetime and t.Errorf
			// here is safe.
			defer func() {
				if err := conn.Close(); err != nil {
					d.t.Errorf("fakeDevice: close conn: %v", err)
				}
			}()
			for {
				frame, err := readMBAPFrame(conn)
				if err != nil {
					return
				}
				d.mu.Lock()
				d.seen = append(d.seen, append([]byte(nil), frame...))
				d.mu.Unlock()
				resp := d.answer(frame)
				d.mu.Lock()
				d.sent = append(d.sent, append([]byte(nil), resp...))
				d.mu.Unlock()
				if _, err := conn.Write(resp); err != nil {
					return
				}
			}
		}()
	}
}

// regValue is the deterministic contents of one holding register, so a test
// can assert the CLIENT received the DEVICE's values without threading a
// register map through.
func regValue(addr uint16) uint16 { return addr ^ 0xA5A5 }

func (d *fakeDevice) answer(req []byte) []byte {
	txn := binary.BigEndian.Uint16(req[0:2])
	unit := req[6]
	pdu := req[mbapHeaderLen:]
	fc, addr, count := decodePDU(pdu)

	d.mu.Lock()
	code, isExc := d.excFC[addr]
	d.mu.Unlock()
	if isExc {
		return mbapFrame(txn, unit, []byte{fc | exceptionBit, code})
	}

	switch fc {
	case fcReadHolding, fcReadInput:
		body := make([]byte, 0, 2+int(count)*2)
		body = append(body, fc, byte(count*2))
		for i := uint16(0); i < count; i++ {
			body = binary.BigEndian.AppendUint16(body, regValue(addr+i))
		}
		return mbapFrame(txn, unit, body)
	case fcWriteMultiple:
		body := []byte{fc}
		body = binary.BigEndian.AppendUint16(body, addr)
		body = binary.BigEndian.AppendUint16(body, count)
		return mbapFrame(txn, unit, body)
	case fcWriteSingle:
		return mbapFrame(txn, unit, append([]byte(nil), pdu...))
	default:
		return mbapFrame(txn, unit, []byte{fc | exceptionBit, 0x01})
	}
}

// mbapFrame wraps a PDU in a Modbus/TCP header.
func mbapFrame(txn uint16, unit uint8, pdu []byte) []byte {
	out := make([]byte, mbapHeaderLen, mbapHeaderLen+len(pdu))
	binary.BigEndian.PutUint16(out[0:2], txn)
	binary.BigEndian.PutUint16(out[2:4], 0)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(pdu)+1))
	out[6] = unit
	return append(out, pdu...)
}

// ── A client to talk with ─────────────────────────────────────────────────────

// scriptedClient is a Modbus/TCP client with lexa-gw's shape: one connection,
// serialized transactions, a transaction id that advances per request
// (vendored tcp_transport.go's lastTxnId), a bounded per-request deadline.
type scriptedClient struct {
	t    *testing.T
	conn net.Conn
	txn  uint16
	unit uint8
}

func dialTap(t *testing.T, addr string) *scriptedClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tap %s: %v", addr, err)
	}
	c := &scriptedClient{t: t, conn: conn, unit: 1}
	t.Cleanup(func() { _ = conn.Close() })
	return c
}

// request sends one PDU and returns the response frame, or the error the
// client's own deadline produced.
func (c *scriptedClient) request(pdu []byte, deadline time.Duration) ([]byte, error) {
	c.txn++
	frame := mbapFrame(c.txn, c.unit, pdu)
	if err := c.conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(frame); err != nil {
		return nil, err
	}
	return readMBAPFrame(c.conn)
}

// read issues FC 0x03 for count registers at addr.
func (c *scriptedClient) read(addr, count uint16, deadline time.Duration) ([]byte, error) {
	pdu := []byte{fcReadHolding}
	pdu = binary.BigEndian.AppendUint16(pdu, addr)
	pdu = binary.BigEndian.AppendUint16(pdu, count)
	return c.request(pdu, deadline)
}

// mustRead fails the test if the read does not complete.
func (c *scriptedClient) mustRead(addr, count uint16) []byte {
	c.t.Helper()
	resp, err := c.read(addr, count, 2*time.Second)
	if err != nil {
		c.t.Fatalf("read %d×%d: %v", addr, count, err)
	}
	return resp
}

// writeMultiple issues FC 0x10.
func (c *scriptedClient) writeMultiple(addr uint16, vals []uint16) ([]byte, error) {
	pdu := []byte{fcWriteMultiple}
	pdu = binary.BigEndian.AppendUint16(pdu, addr)
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(len(vals)))
	pdu = append(pdu, byte(len(vals)*2))
	for _, v := range vals {
		pdu = binary.BigEndian.AppendUint16(pdu, v)
	}
	return c.request(pdu, 2*time.Second)
}

// pollCycle is lexa-gw's steady-state cycle: the measurement read and its
// continuation, in that order, on the one connection.
func (c *scriptedClient) pollCycle() {
	c.t.Helper()
	c.mustRead(40070, 125)
	c.mustRead(40195, 28)
}

// discoveryBurst is what the client does on a fresh session: the SunSpec base
// probe, a couple of model-chain header reads, and the settings model.
func (c *scriptedClient) discoveryBurst() {
	c.t.Helper()
	c.mustRead(40000, 2)
	c.mustRead(40002, 2)
	c.mustRead(40070, 2)
	c.mustRead(40224, 50)
}

// ── The rig ───────────────────────────────────────────────────────────────────

type tapRig struct {
	dev   *fakeDevice
	tap   *Tap
	epoch *Epoch
}

func newTapRig(t *testing.T) *tapRig {
	t.Helper()
	dev := newFakeDevice(t)
	ep := NewEpoch()
	tap, err := NewTap("127.0.0.1:0", dev.addr(), ep, NewLedger(0), NewPollTracker())
	if err != nil {
		t.Fatalf("NewTap: %v", err)
	}
	t.Cleanup(tap.Close)
	return &tapRig{dev: dev, tap: tap, epoch: ep}
}

// arm posts a fault body and returns the epoch it is armed from, the way the
// simapi layer does (bump after the handler accepts).
func (r *tapRig) arm(t *testing.T, body string) uint64 {
	t.Helper()
	handled, err := r.tap.ApplyFault([]byte(body))
	if err != nil {
		t.Fatalf("ApplyFault(%s): %v", body, err)
	}
	if !handled {
		t.Fatalf("ApplyFault(%s): the tap did not claim this kind", body)
	}
	return r.epoch.Next()
}

// waitCycles blocks for n more completed cycles, bounded so a wedged test
// fails rather than hangs.
func (r *tapRig) waitCycles(t *testing.T, n uint64) PollState {
	t.Helper()
	want := r.tap.Polls().Snapshot().Completed + n
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reached, st := r.tap.Polls().Wait(ctx, want)
	if !reached {
		t.Fatalf("the poll barrier did not reach cycle %d within 10s (state %+v)", want, st)
	}
	return st
}

// ── Transparency ──────────────────────────────────────────────────────────────

// TestTap_PassThroughIsByteIdentical is the licence for the tap to be
// interposed by default: with nothing armed it changes nothing.
func TestTap_PassThroughIsByteIdentical(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())

	var clientSaw [][]byte
	c.discoveryBurst()
	for i := 0; i < 3; i++ {
		clientSaw = append(clientSaw, c.mustRead(40070, 125), c.mustRead(40195, 28))
	}
	if _, err := c.writeMultiple(40350, []uint16{1, 2, 3}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Requests: what the client sent is what the device received.
	r.dev.mu.Lock()
	seen := append([][]byte(nil), r.dev.seen...)
	sent := append([][]byte(nil), r.dev.sent...)
	r.dev.mu.Unlock()

	if len(seen) != 11 {
		t.Fatalf("the device received %d request(s), want 11 — the tap dropped or duplicated one", len(seen))
	}
	// The client's request bytes are reconstructible from the ledger, which is
	// itself a copy of what crossed the tap; comparing the device's copy with
	// the ledger's proves the relay did not alter the request direction.
	page := r.tap.Ledger().Since(LedgerQuery{})
	if len(page.Entries) != 11 {
		t.Fatalf("the ledger holds %d entry(ies), want 11", len(page.Entries))
	}
	for i, e := range page.Entries {
		if got := hex.EncodeToString(seen[i]); got != e.Request {
			t.Fatalf("request %d: the device received %s but the ledger recorded %s — the tap altered the "+
				"request direction, and the device's account of what was asked is no longer independent "+
				"evidence", i, got, e.Request)
		}
		if got := hex.EncodeToString(sent[i]); got != e.Response {
			t.Fatalf("response %d: the device composed %s but the client received %s", i, got, e.Response)
		}
	}

	// Responses: what the device composed is what the client received, values
	// included.
	for i, resp := range clientSaw[:2] {
		addr := uint16(40070)
		count := uint16(125)
		if i == 1 {
			addr, count = 40195, 28
		}
		want := mbapFrame(binary.BigEndian.Uint16(resp[0:2]), 1, readResponsePDU(addr, count))
		if !bytes.Equal(resp, want) {
			t.Fatalf("response %d differed from the device's own composition", i)
		}
	}
}

// readResponsePDU rebuilds the PDU fakeDevice composes for a read, so a test
// can compare against it without reaching into the device.
func readResponsePDU(addr, count uint16) []byte {
	body := []byte{fcReadHolding, byte(count * 2)}
	for i := uint16(0); i < count; i++ {
		body = binary.BigEndian.AppendUint16(body, regValue(addr+i))
	}
	return body
}

// ── The ledger ────────────────────────────────────────────────────────────────

// TestTap_LedgerRecordsTheTransaction pins every field a conformance row grades
// on.
func TestTap_LedgerRecordsTheTransaction(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	before := r.epoch.Load()

	c.mustRead(40070, 125)
	page := r.tap.Ledger().Since(LedgerQuery{})
	if len(page.Entries) != 1 {
		t.Fatalf("ledger holds %d entries, want 1", len(page.Entries))
	}
	e := page.Entries[0]
	switch {
	case e.Seq != 1:
		t.Errorf("seq = %d, want 1", e.Seq)
	case e.Epoch != before:
		t.Errorf("epoch = %d, want the epoch in force when the request arrived (%d)", e.Epoch, before)
	case e.FC != fcReadHolding:
		t.Errorf("fc = %#02x, want %#02x", e.FC, fcReadHolding)
	case e.Addr != 40070:
		t.Errorf("addr = %d, want 40070", e.Addr)
	case e.Count != 125:
		t.Errorf("count = %d, want 125", e.Count)
	case e.UnitID != 1:
		t.Errorf("unit id = %d, want 1", e.UnitID)
	case e.Outcome != OutcomeAnswered:
		t.Errorf("outcome = %q, want %q", e.Outcome, OutcomeAnswered)
	case e.Conn != 1:
		t.Errorf("conn = %d, want 1", e.Conn)
	case e.Peer == "":
		t.Error("peer is empty; a ledger that cannot say which socket a transaction was on cannot " +
			"distinguish a reconnect")
	case e.ResponseAt == nil:
		t.Error("response_at is nil for an answered transaction")
	case e.Request == "" || e.Response == "":
		t.Error("the request or response bytes were not recorded")
	}
	if !e.IsRead() || e.IsWrite() {
		t.Error("an FC 0x03 transaction must classify as a read and not as a write")
	}
}

// TestTap_LedgerRecordsExceptions: an exception is an ANSWER, and §2.9.2 is
// entirely about which one.
func TestTap_LedgerRecordsExceptions(t *testing.T) {
	r := newTapRig(t)
	r.dev.exceptAt(40070, 0x04)
	c := dialTap(t, r.tap.Addr())
	c.mustRead(40070, 125)

	page := r.tap.Ledger().Since(LedgerQuery{})
	e := page.Entries[len(page.Entries)-1]
	if e.Outcome != OutcomeException {
		t.Fatalf("outcome = %q, want %q", e.Outcome, OutcomeException)
	}
	if e.Exception != 0x04 {
		t.Fatalf("exception = %#02x, want 0x04 SERVER DEVICE FAILURE", e.Exception)
	}
}

// TestTap_LedgerEpochFence is the property the whole design turns on: fencing
// on the epoch a change was made at selects exactly the transactions that
// happened under it.
func TestTap_LedgerEpochFence(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())

	c.mustRead(40070, 125)
	c.mustRead(40195, 28)
	fence := r.epoch.Next() // as if a fault had just been armed
	c.mustRead(40070, 125)

	page := r.tap.Ledger().Since(LedgerQuery{SinceEpoch: fence})
	if len(page.Entries) != 1 {
		t.Fatalf("%d entry(ies) at or after epoch %d, want exactly the 1 transaction that followed it",
			len(page.Entries), fence)
	}
	if page.Entries[0].Epoch < fence {
		t.Fatalf("entry epoch %d < fence %d", page.Entries[0].Epoch, fence)
	}
	if page.HighSeq != 3 {
		t.Fatalf("high_seq = %d, want 3 — a caller must be able to tell 'nothing happened' from "+
			"'nothing that matched happened'", page.HighSeq)
	}
}

// TestLedger_PagingAndEviction covers the two cursor forms and the honesty
// requirement on a window that reaches past the ring.
func TestLedger_PagingAndEviction(t *testing.T) {
	l := NewLedger(4)
	for i := 0; i < 6; i++ {
		l.Append(LedgerEntry{Epoch: uint64(i + 1), Outcome: OutcomeAnswered})
	}
	page := l.Since(LedgerQuery{})
	if page.Evicted != 2 {
		t.Fatalf("evicted = %d, want 2", page.Evicted)
	}
	if !page.Truncated {
		t.Fatal("a query for everything, with entries already evicted, must report truncated=true — a " +
			"missing transaction and an evicted one are different facts")
	}
	if len(page.Entries) != 4 {
		t.Fatalf("%d entries survive, want the ring's 4", len(page.Entries))
	}
	if page.NextSeq != 6 || page.HighSeq != 6 {
		t.Fatalf("next_seq=%d high_seq=%d, want 6/6", page.NextSeq, page.HighSeq)
	}

	first := l.Since(LedgerQuery{SinceSeq: 3, Limit: 2})
	if len(first.Entries) != 2 || first.Entries[0].Seq != 4 {
		t.Fatalf("paging from seq 3 with limit 2 returned %d entries starting at %d",
			len(first.Entries), first.Entries[0].Seq)
	}
	if first.Total != 3 {
		t.Fatalf("total = %d before the limit was applied, want 3", first.Total)
	}
	second := l.Since(LedgerQuery{SinceSeq: first.NextSeq})
	if len(second.Entries) != 1 || second.Entries[0].Seq != 6 {
		t.Fatalf("continuing from next_seq %d returned %d entries", first.NextSeq, len(second.Entries))
	}
	// A caller that pages within the surviving window is not being lied to.
	if second.Truncated {
		t.Error("a query whose window lies entirely inside the ring must not report truncated")
	}
}

// ── The poll barrier over a real socket ───────────────────────────────────────

// TestTap_PollBarrierOverTheWire is the end-to-end determinism case: a client
// with lexa-gw's shape, a barrier that returns exactly when a cycle closes, and
// a ledger that is complete at that instant.
func TestTap_PollBarrierOverTheWire(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	c.discoveryBurst()

	// Three cycles teach the tap its anchor; the third completes cycles 1-2.
	c.pollCycle()
	c.pollCycle()
	c.pollCycle()

	st := r.tap.Polls().Snapshot()
	if !st.AnchorLocked {
		t.Fatalf("no anchor was learned from a lexa-gw-shaped conversation; candidates %+v", st.Learning)
	}
	if st.Anchor.Addr != 40070 || st.Anchor.Count != 125 {
		t.Fatalf("anchor = %+v, want the measurement read 40070×125", st.Anchor)
	}
	if st.Completed != 2 {
		t.Fatalf("completed = %d after three cycles, want 2", st.Completed)
	}

	// Now the barrier. Cycle 3 is already OPEN at this point (the third
	// measurement read opened it when it locked the anchor), so the first
	// cycle that lies wholly on the far side of the fence is cycle 4 — and
	// that is what a row fencing on an epoch actually gets. Waiting for
	// cycle 3 here and then filtering on the fence would be asserting against
	// a cycle that began before the provocation.
	fence := r.epoch.Next()
	want := st.Completed + 2
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.pollCycle() // completes cycle 3, opens cycle 4
		c.pollCycle() // completes cycle 4, opens cycle 5
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reached, after := r.tap.Polls().Wait(ctx, want)
	if !reached {
		t.Fatalf("the barrier did not reach cycle %d (state %+v)", want, after)
	}
	<-done

	page := r.tap.Ledger().Since(LedgerQuery{SinceEpoch: fence})
	var inCycle int
	for _, e := range page.Entries {
		if e.Poll == want {
			inCycle++
			if e.Outcome == "" {
				t.Fatalf("transaction seq %d in cycle %d is in the ledger with no outcome — the barrier "+
					"returned with a transaction still in flight", e.Seq, want)
			}
		}
	}
	if inCycle != 2 {
		t.Fatalf("cycle %d holds %d transaction(s) in the ledger, want the 2 the client issued — the "+
			"barrier's whole contract is that the cycle is complete when it returns", want, inCycle)
	}
}

// TestTap_ReconnectIsVisibleWithoutACapture: the ledger's connection number is
// what lets a row tell a reconnect from a continuing session with no pcap.
func TestTap_ReconnectIsVisibleWithoutACapture(t *testing.T) {
	r := newTapRig(t)
	c1 := dialTap(t, r.tap.Addr())
	c1.mustRead(40070, 125)
	_ = c1.conn.Close()

	c2 := dialTap(t, r.tap.Addr())
	c2.mustRead(40070, 125)

	page := r.tap.Ledger().Since(LedgerQuery{})
	if len(page.Entries) != 2 {
		t.Fatalf("ledger holds %d entries, want 2", len(page.Entries))
	}
	if page.Entries[0].Conn == page.Entries[1].Conn {
		t.Fatalf("both transactions report conn %d; a reconnect must be visible in the ledger",
			page.Entries[0].Conn)
	}
}

// ── One-shot response faults ──────────────────────────────────────────────────

// TestTap_OneShotDropLandsInsideTheMatchingTransaction is PROT-1's fix. The
// old provocation (severing the connection) routinely landed BETWEEN requests;
// this one cannot, because it is armed against the next matching REQUEST.
func TestTap_OneShotDropLandsInsideTheMatchingTransaction(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	c.mustRead(40070, 125) // a normal transaction first

	fence := r.arm(t, `{"kind":"next_response","action":"drop","on_fc":3,"on_addr":[40070,40195]}`)

	// The matching read gets no answer at all, and the client's own deadline
	// is what ends it — exactly the shape a real client's read timeout has.
	if _, err := c.read(40070, 125, 300*time.Millisecond); err == nil {
		t.Fatal("the matching read was answered; a dropped response must leave the client waiting")
	} else if !stalled(err) {
		t.Fatalf("the matching read failed with %v, want a read timeout — the connection must stay OPEN, "+
			"which is what distinguishes a dropped response from a severed session", err)
	}

	// The one-shot is consumed: the very next read is answered normally. The
	// client's transaction ids have moved on, so it dials a fresh socket
	// rather than trying to resynchronise a stream with an orphaned response
	// in it — which is what a real client does after a timeout, too.
	c2 := dialTap(t, r.tap.Addr())
	c2.mustRead(40070, 125)

	page := r.tap.Ledger().Since(LedgerQuery{SinceEpoch: fence})
	if len(page.Entries) != 2 {
		t.Fatalf("%d transaction(s) since the arm epoch, want 2", len(page.Entries))
	}
	dropped, normal := page.Entries[0], page.Entries[1]
	if dropped.Outcome != OutcomeDropped {
		t.Fatalf("the matching transaction's outcome = %q, want %q", dropped.Outcome, OutcomeDropped)
	}
	if dropped.Response != "" {
		t.Fatalf("a dropped transaction recorded response bytes (%s); the client received none",
			dropped.Response)
	}
	if dropped.Fault == "" {
		t.Error("a transaction shaped by an armed fault must name the fault, or a reader cannot tell it " +
			"from a device that simply failed")
	}
	if normal.Outcome != OutcomeAnswered {
		t.Fatalf("the transaction after the one-shot has outcome %q, want %q — a one-shot that stayed "+
			"armed would be a blanket", normal.Outcome, OutcomeAnswered)
	}
}

// TestTap_OneShotShortTruncatesWithoutMovingTheLengthField: the header still
// promises bytes that are not coming, which is what makes it a PARTIAL
// response rather than a short-but-consistent one.
func TestTap_OneShotShortTruncatesWithoutMovingTheLengthField(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	fence := r.arm(t, `{"kind":"next_response","action":"short","truncate_bytes":2,"on_fc":3}`)

	// The client frames by length, so it waits for bytes that never arrive.
	if _, err := c.read(40070, 125, 300*time.Millisecond); err == nil {
		t.Fatal("the truncated response satisfied the client's framer")
	} else if !stalled(err) {
		t.Fatalf("read failed with %v, want a read timeout", err)
	}

	page := r.tap.Ledger().Since(LedgerQuery{SinceEpoch: fence})
	e := page.Entries[0]
	if e.Outcome != OutcomeTruncated {
		t.Fatalf("outcome = %q, want %q", e.Outcome, OutcomeTruncated)
	}
	raw, err := hex.DecodeString(e.Response)
	if err != nil {
		t.Fatalf("decode recorded response: %v", err)
	}
	if len(raw) != mbapHeaderLen+2 {
		t.Fatalf("the client received %d byte(s), want the 7-byte header plus 2 PDU bytes", len(raw))
	}
	promised := int(binary.BigEndian.Uint16(raw[4:6]))
	if promised == len(raw)-mbapHeaderLen+1 {
		t.Fatalf("the MBAP length field (%d) agrees with the bytes delivered; truncating the length too "+
			"would be a consistent short frame, which is a different and far less interesting fault",
			promised)
	}
}

// TestTap_OneShotDelayHoldsThenDelivers: the response is complete and correct,
// just late — the case a client's per-request deadline decides.
func TestTap_OneShotDelayHoldsThenDelivers(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	fence := r.arm(t, `{"kind":"next_response","action":"delay","delay_ms":150,"on_fc":3}`)

	// A client whose deadline is shorter than the hold gives up.
	if _, err := c.read(40070, 4, 40*time.Millisecond); err == nil {
		t.Fatal("a read with a 40ms deadline survived a 150ms hold")
	} else if !stalled(err) {
		t.Fatalf("read failed with %v, want a read timeout", err)
	}

	// The transaction is still recorded, with the hold visible in its latency,
	// and the tap counted it.
	deadline := time.Now().Add(5 * time.Second)
	var e LedgerEntry
	for time.Now().Before(deadline) {
		page := r.tap.Ledger().Since(LedgerQuery{SinceEpoch: fence})
		if len(page.Entries) > 0 {
			e = page.Entries[0]
			break
		}
	}
	if e.Seq == 0 {
		t.Fatal("the delayed transaction never reached the ledger")
	}
	if e.Outcome != OutcomeDelayed && e.Outcome != OutcomeAbandoned {
		t.Fatalf("outcome = %q, want %q (delivered late) or %q (the client had already gone)",
			e.Outcome, OutcomeDelayed, OutcomeAbandoned)
	}
}

// TestTap_OneShotMatchesByFunctionAndAddress proves the match is a scope and
// not a coin flip: a read outside the armed range passes through untouched and
// leaves the one-shot armed for the read that is inside it.
func TestTap_OneShotMatchesByFunctionAndAddress(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	fence := r.arm(t, `{"kind":"next_response","action":"drop","on_fc":3,"on_addr":[40350,40415]}`)

	c.mustRead(40070, 125) // outside the range: must be answered
	c.mustRead(40195, 28)  // also outside

	if _, err := c.read(40350, 65, 300*time.Millisecond); err == nil {
		t.Fatal("the read INSIDE the armed range was answered")
	} else if !stalled(err) {
		t.Fatalf("read failed with %v, want a read timeout", err)
	}

	page := r.tap.Ledger().Since(LedgerQuery{SinceEpoch: fence})
	if len(page.Entries) != 3 {
		t.Fatalf("%d transaction(s), want 3", len(page.Entries))
	}
	for i, e := range page.Entries[:2] {
		if e.Outcome != OutcomeAnswered {
			t.Fatalf("transaction %d at address %d has outcome %q; it lies outside the armed range and "+
				"must be untouched", i, e.Addr, e.Outcome)
		}
	}
	if page.Entries[2].Outcome != OutcomeDropped {
		t.Fatalf("the transaction inside the armed range has outcome %q, want %q",
			page.Entries[2].Outcome, OutcomeDropped)
	}
}

// TestTap_OneShotFunctionCodeScope: a write must not consume a one-shot armed
// for reads.
func TestTap_OneShotFunctionCodeScope(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	r.arm(t, `{"kind":"next_response","action":"drop","on_fc":3}`)

	if _, err := c.writeMultiple(40350, []uint16{7}); err != nil {
		t.Fatalf("the write was affected by a one-shot armed for FC 0x03: %v", err)
	}
	if _, err := c.read(40070, 4, 300*time.Millisecond); err == nil {
		t.Fatal("the read did not consume the one-shot")
	}
}

// TestTap_OneShotClear disarms without firing.
func TestTap_OneShotClear(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	r.arm(t, `{"kind":"next_response","action":"drop","on_fc":3}`)
	r.arm(t, `{"kind":"next_response","clear":true}`)
	c.mustRead(40070, 4)
}

// TestTap_OneShotRejectsNonsense: every refusal names what was wrong, because
// a bench that armed a one-shot which could never fire would run the whole row
// against an unprovoked device and report the result as a product finding.
func TestTap_OneShotRejectsNonsense(t *testing.T) {
	r := newTapRig(t)
	for _, body := range []string{
		`{"kind":"next_response"}`,
		`{"kind":"next_response","action":"explode"}`,
		`{"kind":"next_response","action":"delay"}`,
		`{"kind":"next_response","action":"delay","delay_ms":600000}`,
		`{"kind":"next_response","action":"drop","on_addr":[40070,40070]}`,
		`{"kind":"next_response","action":"drop","on_addr":[1,2,3]}`,
	} {
		handled, err := r.tap.ApplyFault([]byte(body))
		if !handled {
			t.Errorf("%s: the tap did not claim its own kind", body)
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted, want a refusal naming what is wrong", body)
		}
	}
}

// ── The unit-id gate ──────────────────────────────────────────────────────────

// TestTap_UnitIDGate re-addresses the device, which is §2.4.3 CLI-3's setup
// step: "run Server 1 with a different Unit ID".
func TestTap_UnitIDGate(t *testing.T) {
	r := newTapRig(t)
	fence := r.arm(t, `{"kind":"unit_id","unit_id":7}`)

	c := dialTap(t, r.tap.Addr())
	c.unit = 1
	resp := c.mustRead(40070, 4)
	pdu := resp[mbapHeaderLen:]
	if pdu[0] != fcReadHolding|exceptionBit || pdu[1] != gwTargetFailedToRespond {
		t.Fatalf("a request for unit 1 against a device re-addressed to 7 answered %x; want the "+
			"exception function code %#02x and exception %#02x GATEWAY TARGET DEVICE FAILED TO RESPOND",
			pdu, fcReadHolding|exceptionBit, gwTargetFailedToRespond)
	}
	// The device behind the gate never heard it — which is what a Modbus
	// gateway does for a unit it does not front.
	r.dev.mu.Lock()
	seen := len(r.dev.seen)
	r.dev.mu.Unlock()
	if seen != 0 {
		t.Fatalf("the device received %d request(s) addressed to a unit id it no longer answers", seen)
	}

	// The configured unit id passes through untouched.
	c.unit = 7
	c.mustRead(40070, 4)

	page := r.tap.Ledger().Since(LedgerQuery{SinceEpoch: fence})
	if len(page.Entries) != 2 {
		t.Fatalf("%d transaction(s), want 2", len(page.Entries))
	}
	if page.Entries[0].Exception != gwTargetFailedToRespond {
		t.Fatalf("the refused transaction records exception %#02x, want %#02x",
			page.Entries[0].Exception, gwTargetFailedToRespond)
	}
	if page.Entries[1].Outcome != OutcomeAnswered {
		t.Fatalf("the transaction at the new unit id has outcome %q, want %q",
			page.Entries[1].Outcome, OutcomeAnswered)
	}

	// Clearing restores a device that answers anything.
	r.arm(t, `{"kind":"unit_id","clear":true}`)
	c.unit = 1
	c.mustRead(40070, 4)
}

// TestTap_UnitIDGateRejectsIllegalAddresses.
func TestTap_UnitIDGateRejectsIllegalAddresses(t *testing.T) {
	r := newTapRig(t)
	for _, body := range []string{
		`{"kind":"unit_id"}`,
		`{"kind":"unit_id","unit_id":0}`,
		`{"kind":"unit_id","unit_id":248}`,
	} {
		if _, err := r.tap.ApplyFault([]byte(body)); err == nil {
			t.Errorf("%s: accepted, want a refusal — 0 is the RTU broadcast address and has no meaning "+
				"over Modbus/TCP", body)
		}
	}
}

// TestTap_UnclaimedKindsFallThrough: the tap must not swallow a kind it does
// not own, or a device-level fault would silently stop working the moment the
// tap was interposed.
func TestTap_UnclaimedKindsFallThrough(t *testing.T) {
	r := newTapRig(t)
	for _, body := range []string{
		`{"kind":"tcp_drop"}`,
		`{"kind":"exception_code","code":4}`,
		`{"kind":"relocate","base":0}`,
	} {
		handled, err := r.tap.ApplyFault([]byte(body))
		if handled || err != nil {
			t.Errorf("%s: handled=%v err=%v, want the tap to leave it for the next layer", body, handled, err)
		}
		if !TapFaultRequested([]byte(body)) {
			continue
		}
		t.Errorf("%s: TapFaultRequested claimed a kind the tap does not own", body)
	}
	for _, body := range []string{
		`{"kind":"next_response","action":"drop"}`,
		`{"kind":"unit_id","unit_id":3}`,
	} {
		if !TapFaultRequested([]byte(body)) {
			t.Errorf("%s: TapFaultRequested must recognise the tap's own kinds so a sim without a tap "+
				"can refuse them BY NAME rather than as an unknown kind", body)
		}
	}
}

// TestTap_ClearFaultsDisarmsEverything is what POST /reset relies on.
func TestTap_ClearFaultsDisarmsEverything(t *testing.T) {
	r := newTapRig(t)
	r.arm(t, `{"kind":"next_response","action":"drop","on_fc":3}`)
	r.arm(t, `{"kind":"unit_id","unit_id":9}`)
	if s := r.tap.Stats(); !s.OneShotArmed || s.UnitID != 9 {
		t.Fatalf("setup did not arm: %+v", s)
	}
	r.tap.ClearFaults()
	if s := r.tap.Stats(); s.OneShotArmed || s.UnitID != 0 {
		t.Fatalf("after ClearFaults: %+v, want nothing armed", s)
	}
	c := dialTap(t, r.tap.Addr())
	c.unit = 1
	c.mustRead(40070, 4)
}

// TestTap_StatsCountWhatHappened: the tap's counters are evidence a fault
// fired, not an inference from a client's reaction.
func TestTap_StatsCountWhatHappened(t *testing.T) {
	r := newTapRig(t)
	c := dialTap(t, r.tap.Addr())
	c.mustRead(40070, 4)
	r.arm(t, `{"kind":"next_response","action":"drop","on_fc":3}`)
	_, _ = c.read(40070, 4, 200*time.Millisecond)

	s := r.tap.Stats()
	if s.Connections != 1 {
		t.Errorf("connections = %d, want 1", s.Connections)
	}
	if s.Requests != 2 {
		t.Errorf("requests = %d, want 2", s.Requests)
	}
	if s.Dropped != 1 {
		t.Errorf("dropped = %d, want 1", s.Dropped)
	}
	if s.Ledger != 2 {
		t.Errorf("ledger entries = %d, want 2", s.Ledger)
	}
}

// TestTap_ConstructionRefusesMissingCollaborators — a tap without a ledger or
// a poll tracker would be a relay pretending to be a witness.
func TestTap_ConstructionRefusesMissingCollaborators(t *testing.T) {
	if _, err := NewTap("127.0.0.1:0", "127.0.0.1:1", nil, NewLedger(0), NewPollTracker()); err == nil {
		t.Error("NewTap accepted a nil epoch")
	}
	if _, err := NewTap("127.0.0.1:0", "127.0.0.1:1", NewEpoch(), nil, NewPollTracker()); err == nil {
		t.Error("NewTap accepted a nil ledger")
	}
	if _, err := NewTap("127.0.0.1:0", "127.0.0.1:1", NewEpoch(), NewLedger(0), nil); err == nil {
		t.Error("NewTap accepted a nil poll tracker")
	}
}

// TestEpoch_MonotonicAndPostIncrement pins the contract POST /fault's
// acknowledgement rests on: the number handed back is the epoch the change is
// in force FROM.
func TestEpoch_MonotonicAndPostIncrement(t *testing.T) {
	e := NewEpoch()
	if got := e.Load(); got != 1 {
		t.Fatalf("a fresh epoch reads %d, want 1 — 0 must stay distinguishable from an unset field", got)
	}
	if got := e.Next(); got != 2 {
		t.Fatalf("Next() = %d, want the POST-increment value 2", got)
	}
	if got := e.Load(); got != 2 {
		t.Fatalf("Load() = %d after one Next(), want 2", got)
	}
	var nilEpoch *Epoch
	if nilEpoch.Load() != 0 || nilEpoch.Next() != 0 {
		t.Error("a nil *Epoch must read 0 rather than panic; a sim without one is a valid configuration")
	}
}

// stalled reports whether err is what a client sees when an answer never
// arrives: its own read deadline, or a frame cut in half by that deadline.
// wire_test.go's isTimeout covers only the first, which is the right predicate
// there and too narrow here — a truncated response reaches the framer as a
// short read, not as a timeout.
func stalled(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

// TestLedger_WaitForBlocksOnTheAppend is the OTHER barrier, and the one a row
// needs when its provocation prevents a poll cycle from ever completing.
func TestLedger_WaitForBlocksOnTheAppend(t *testing.T) {
	l := NewLedger(0)
	q := LedgerQuery{SinceEpoch: 5}

	done := make(chan LedgerPage, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- l.WaitFor(ctx, q, 2)
	}()

	// A transaction BELOW the fence must not satisfy it.
	l.Append(LedgerEntry{Epoch: 4, Outcome: OutcomeAnswered})
	l.Append(LedgerEntry{Epoch: 5, Outcome: OutcomeException})
	select {
	case p := <-done:
		t.Fatalf("WaitFor(min 2) returned with %d matching entry(ies)", p.Total)
	case <-time.After(20 * time.Millisecond):
	}

	l.Append(LedgerEntry{Epoch: 6, Outcome: OutcomeAnswered})
	select {
	case p := <-done:
		if p.Total != 2 {
			t.Fatalf("WaitFor returned %d entries, want the 2 at or above the fence", p.Total)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitFor did not return once two transactions matched")
	}
}

// TestLedger_WaitForHonoursItsContext: the caller's cancellation is the only
// bound, and it returns what it has rather than an error.
func TestLedger_WaitForHonoursItsContext(t *testing.T) {
	l := NewLedger(0)
	l.Append(LedgerEntry{Epoch: 9, Outcome: OutcomeAnswered})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	page := l.WaitFor(ctx, LedgerQuery{SinceEpoch: 9}, 5)
	if page.Total != 1 {
		t.Fatalf("WaitFor returned %d entries on timeout, want the 1 that matched", page.Total)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("WaitFor took %s to honour a 30ms context", d)
	}
}

// TestLedger_WaitForAlreadySatisfied returns immediately.
func TestLedger_WaitForAlreadySatisfied(t *testing.T) {
	l := NewLedger(0)
	l.Append(LedgerEntry{Epoch: 1, Outcome: OutcomeAnswered})
	l.Append(LedgerEntry{Epoch: 1, Outcome: OutcomeAnswered})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if page := l.WaitFor(ctx, LedgerQuery{}, 2); page.Total != 2 {
		t.Fatalf("WaitFor returned %d entries, want 2", page.Total)
	}
}

// TestTap_LedgerBarrierSurvivesASessionThatNeverCompletesACycle is the case
// the ledger barrier exists for: the client is met once per session and
// reconnects, so no poll cycle ever finishes, and a row waiting on the POLL
// barrier would time out while its provocation landed perfectly.
func TestTap_LedgerBarrierSurvivesASessionThatNeverCompletesACycle(t *testing.T) {
	r := newTapRig(t)
	r.dev.exceptAt(40070, 0x04)
	fence := r.epoch.Next()

	go func() {
		// Three sessions, each one measurement read then a disconnect — the
		// shape lexa-gw produces when the device answers its measurement read
		// with an exception (cmd/modbus/main.go:1303-1307 drops the session).
		for i := 0; i < 3; i++ {
			conn, err := net.DialTimeout("tcp", r.tap.Addr(), 2*time.Second)
			if err != nil {
				return
			}
			c := &scriptedClient{t: t, conn: conn, unit: 1}
			_, _ = c.read(40070, 125, time.Second)
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	page := r.tap.Ledger().WaitFor(ctx, LedgerQuery{SinceEpoch: fence}, 3)
	if page.Total < 3 {
		t.Fatalf("the ledger barrier saw %d transaction(s), want 3", page.Total)
	}
	for _, e := range page.Entries {
		if e.Outcome != OutcomeException || e.Exception != 0x04 {
			t.Fatalf("transaction %d resolved as %q/%#02x, want an exception 0x04", e.Seq, e.Outcome, e.Exception)
		}
	}
	if st := r.tap.Polls().Snapshot(); st.Completed != 0 {
		t.Fatalf("the POLL barrier counted %d completed cycle(s); a row waiting on it here would have "+
			"timed out while its provocation was landing on every session", st.Completed)
	}
}
