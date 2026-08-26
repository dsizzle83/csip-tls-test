package sim

// tap.go — THE WIRE TAP: the sim's own eyes on the Modbus/TCP conversation.
//
// # What it is
//
// An MBAP-aware TCP relay that sits between the client under test and the
// sim's Modbus server. It frames BOTH directions, records every transaction in
// the ledger, feeds the poll tracker, and can shape exactly one response on
// demand. With nothing armed it forwards every byte of every frame verbatim,
// in order, in both directions — see faultlayers_noop_test.go's sibling,
// tap_test.go, for the byte-identity pin.
//
// # Why it exists, when wire.go's Mangler already relays
//
// The Mangler and the ProtoRelay are ADVERSARIES: they exist to corrupt, they
// are opt-in for exactly that reason, and each is a blanket ("every response
// from now on is truncated"). This is a WITNESS. Its default behaviour is to
// change nothing and to write down what happened, which is why it is on by
// default and they are not. Three capabilities follow from being in the byte
// path, and none of them can be had anywhere else in the sim:
//
//	the MBAP transaction identifier — the RequestHandler the register map
//	implements never sees it (modbuslib.HoldingRegistersRequest carries
//	ClientAddr, UnitId, Addr, Quantity and nothing more), so a ledger written
//	at the register layer could not pair a response to its request the way the
//	protocol itself does;
//
//	the request/response PAIR, with both timestamps — which is what makes
//	"the client asked and got no answer" a recordable fact rather than an
//	absence;
//
//	a ONE-SHOT response fault. Everything else in this package arms a
//	condition and waits for the client to walk into it. A one-shot arms
//	against the NEXT MATCHING REQUEST, so the fault lands inside a
//	transaction the bench can name, instead of inside whichever transaction
//	the client happened to be running when a blanket was thrown over it.
//	PROT-1's whole difficulty was that its provocation kept landing BETWEEN
//	requests; a one-shot cannot.
//
// # Chaining
//
// The tap always takes the public port and forwards inward. When -mangle or
// -protofault is also in play, the chain is
//
//	client → tap(:5020) → mangler(:15020) → device(:25020)
//
// so the tap records what the CLIENT actually received, mangling included.
// That is the right side to stand on: the ledger's purpose is to say what the
// device under test had to work with, not what the sim originally composed.
//
// # What it does not do
//
// It does not parse SunSpec, does not know what a model is, and does not
// interpret register values. It reads seven header bytes and the first five
// bytes of a PDU. Everything above that lives in the suite, which must decode
// the wire independently of the product — and would gain nothing from decoding
// it independently of the sim only to then trust the sim's decode.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Modbus function codes the tap decodes. Anything else is relayed and
// recorded with its raw bytes and no decoded address.
const (
	fcReadHolding   uint8 = 0x03
	fcReadInput     uint8 = 0x04
	fcWriteSingle   uint8 = 0x06
	fcWriteMultiple uint8 = 0x10
)

// exceptionBit marks a response PDU as an exception: the request's function
// code with the high bit set, followed by a one-byte exception code.
const exceptionBit uint8 = 0x80

// gwTargetFailedToRespond is Modbus exception 0x0B, the answer a Modbus
// gateway gives for a unit id it does not front. It is what the tap's unit-id
// gate returns, because that is exactly the situation it models.
const gwTargetFailedToRespond uint8 = 0x0B

// FaultNextResponse is the one-shot: shape the NEXT response whose REQUEST
// matches (function code, address range). See oneShotSpec for the actions.
const FaultNextResponse FaultKind = "next_response"

// FaultUnitID re-addresses the served device: while armed, the tap answers
// only requests carrying the given unit id and returns exception 0x0B to every
// other, exactly as a Modbus/TCP gateway does for a unit that is not behind
// it. It is the SunSpec Modbus client procedure's "run Server 1 with a
// different Unit ID" (§2.4.3 CLI-3 step 1) expressed as a runtime lever, and
// it is deliberately NOT the existing unit_id_confusion fault, which makes the
// device refuse EVERY unit id including its own.
const FaultUnitID FaultKind = "unit_id"

// tapFaultKinds is the set this file owns.
var tapFaultKinds = map[FaultKind]bool{
	FaultNextResponse: true,
	FaultUnitID:       true,
}

// One-shot actions.
const (
	// ActionDrop swallows the response entirely and leaves the connection
	// open. The client is left waiting for an answer that will never come,
	// which is §2.8.1's "partial response" in its most literal form — and,
	// unlike severing the connection, it is scoped to ONE transaction that the
	// bench chose.
	ActionDrop = "drop"
	// ActionShort writes the MBAP header and TruncateBytes of the PDU, leaving
	// the length field promising the rest. A client that frames by length
	// waits; one that reads whatever is next splices the following response
	// onto this value.
	ActionShort = "short"
	// ActionDelay holds the response for DelayMS and then writes it in full.
	// The client's own per-request deadline (5 s in lexa-gw —
	// cmd/modbus/transport_factory.go:52) decides whether it survives.
	ActionDelay = "delay"
)

// oneShotSpec is an armed one-shot response fault.
type oneShotSpec struct {
	Action string `json:"action"`
	// OnFC restricts the match to one function code; 0 matches any.
	OnFC uint8 `json:"on_fc,omitempty"`
	// OnAddr is the half-open register range [start, end) a matching request
	// must OVERLAP. An empty range matches any address.
	OnAddrStart uint16 `json:"on_addr_start,omitempty"`
	OnAddrEnd   uint16 `json:"on_addr_end,omitempty"`
	AnyAddr     bool   `json:"any_addr,omitempty"`

	TruncateBytes int `json:"truncate_bytes,omitempty"`
	DelayMS       int `json:"delay_ms,omitempty"`

	// ArmedAt is the control-plane epoch at which this one-shot was armed —
	// the number POST /fault hands back so a caller can fence the ledger on it.
	ArmedAt uint64 `json:"armed_at"`
}

func (s *oneShotSpec) matches(fc uint8, addr, count uint16) bool {
	if s.OnFC != 0 && s.OnFC != fc {
		return false
	}
	if s.AnyAddr {
		return true
	}
	if s.OnAddrEnd <= s.OnAddrStart {
		return true
	}
	end := uint32(addr) + uint32(count)
	if count == 0 {
		end = uint32(addr) + 1
	}
	return end > uint32(s.OnAddrStart) && uint32(addr) < uint32(s.OnAddrEnd)
}

// TapStats is the tap's own account of what it relayed, for GET /state.
type TapStats struct {
	Connections  uint64 `json:"connections"`
	Requests     uint64 `json:"requests"`
	Responses    uint64 `json:"responses"`
	Dropped      uint64 `json:"dropped"`
	Truncated    uint64 `json:"truncated"`
	Delayed      uint64 `json:"delayed"`
	UnitRefused  uint64 `json:"unit_refused"`
	Abandoned    uint64 `json:"abandoned"`
	Ledger       int    `json:"ledger_entries"`
	UnitID       uint8  `json:"unit_id,omitempty"`
	OneShotArmed bool   `json:"one_shot_armed"`
}

// Tap is the MBAP-aware witness relay. Construct with NewTap.
type Tap struct {
	listenAddr string
	upstream   string

	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	epoch  *Epoch
	ledger *Ledger
	polls  *PollTracker

	mu      sync.Mutex
	connSeq uint64
	unitID  uint8
	oneShot *oneShotSpec
	stats   TapStats
}

// NewTap starts a tap on listenAddr forwarding to upstream (both host:port).
// It returns as soon as the listener is bound, so a caller may dial
// immediately. epoch, ledger and polls must all be non-nil.
func NewTap(listenAddr, upstream string, epoch *Epoch, ledger *Ledger, polls *PollTracker) (*Tap, error) {
	if epoch == nil || ledger == nil || polls == nil {
		return nil, errors.New("sim: tap needs an epoch, a ledger and a poll tracker")
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("sim: tap listen %s: %w", listenAddr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &Tap{
		listenAddr: ln.Addr().String(),
		upstream:   upstream,
		ln:         ln,
		ctx:        ctx,
		cancel:     cancel,
		epoch:      epoch,
		ledger:     ledger,
		polls:      polls,
	}
	t.wg.Add(1)
	go t.serve()
	return t, nil
}

// Addr returns the address the tap is listening on (useful when the caller
// asked for port 0).
func (t *Tap) Addr() string { return t.listenAddr }

// Ledger returns the transaction ledger the tap writes.
func (t *Tap) Ledger() *Ledger { return t.ledger }

// Polls returns the poll tracker the tap feeds.
func (t *Tap) Polls() *PollTracker { return t.polls }

// Close stops the tap and waits for its goroutines.
func (t *Tap) Close() {
	t.cancel()
	_ = t.ln.Close()
	t.wg.Wait()
}

// Stats snapshots the tap's counters.
func (t *Tap) Stats() TapStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stats
	s.UnitID = t.unitID
	s.OneShotArmed = t.oneShot != nil
	s.Ledger = t.ledger.Len()
	return s
}

// ClearFaults disarms everything this tap owns: the one-shot and the unit-id
// gate. Called by POST /reset, which must leave no provocation standing.
func (t *Tap) ClearFaults() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.oneShot = nil
	t.unitID = 0
}

func (t *Tap) serve() {
	defer t.wg.Done()
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return // listener closed
		}
		t.mu.Lock()
		t.connSeq++
		id := t.connSeq
		t.stats.Connections++
		t.mu.Unlock()
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.handle(id, conn)
		}()
	}
}

// pendingTxn is one request the tap has forwarded and not yet resolved.
type pendingTxn struct {
	entry  LedgerEntry
	poll   uint64
	action *oneShotSpec
}

// tapConn is one client connection's state.
type tapConn struct {
	t    *Tap
	id   uint64
	peer string

	mu sync.Mutex
	// pending is keyed by MBAP transaction id. Modbus/TCP permits an id to be
	// reused while an earlier request carrying it is still outstanding, so the
	// value is a FIFO queue rather than a single entry: the answer belongs to
	// the OLDEST outstanding request with that id, which is the only ordering
	// the protocol itself guarantees on one socket.
	pending map[uint16][]*pendingTxn
	// live preserves arrival order, so a connection teardown can resolve what
	// is outstanding in the order the client asked rather than in map order.
	live []*pendingTxn
}

// handle relays one client connection.
func (t *Tap) handle(id uint64, client net.Conn) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", t.upstream, 5*time.Second)
	if err != nil {
		log.Printf("[tap] upstream %s unreachable: %v", t.upstream, err)
		return
	}
	defer up.Close()

	c := &tapConn{
		t:       t,
		id:      id,
		peer:    client.RemoteAddr().String(),
		pending: make(map[uint16][]*pendingTxn),
	}
	t.polls.SessionOpened()

	done := make(chan struct{}, 2)
	go func() { c.pumpRequests(client, up); done <- struct{}{} }()
	go func() { c.pumpResponses(up, client); done <- struct{}{} }()

	select {
	case <-done:
	case <-t.ctx.Done():
	}
	_ = up.Close()
	_ = client.Close()
	<-done

	// Everything still outstanding is abandoned — the client asked and the
	// conversation ended. Resolving before SessionClosed lets a cycle that was
	// only waiting on these complete on its own merits.
	c.abandonAll()
	t.polls.SessionClosed()
}

// pumpRequests frames the client→device direction, records each request, and
// forwards it VERBATIM. The device must see exactly the bytes the client sent
// or its own account of what was asked would stop being independent evidence.
func (c *tapConn) pumpRequests(client, up net.Conn) {
	for {
		frame, err := readMBAPFrame(client)
		if err != nil {
			return
		}
		forward, err := c.onRequest(frame, client)
		if err != nil || !forward {
			if err != nil {
				return
			}
			continue
		}
		if _, err := up.Write(frame); err != nil {
			return
		}
	}
}

// onRequest records one request and decides whether it reaches the device.
// It returns forward=false when the tap answered it itself (the unit-id gate).
func (c *tapConn) onRequest(frame []byte, client net.Conn) (forward bool, err error) {
	txn := binary.BigEndian.Uint16(frame[0:2])
	unit := frame[6]
	pdu := frame[mbapHeaderLen:]
	fc, addr, count := decodePDU(pdu)
	now := time.Now().UTC()

	c.t.mu.Lock()
	c.t.stats.Requests++
	gate := c.t.unitID
	var action *oneShotSpec
	if c.t.oneShot != nil && c.t.oneShot.matches(fc, addr, count) {
		action = c.t.oneShot
		c.t.oneShot = nil // one-shot: consumed by the request that matched it
	}
	c.t.mu.Unlock()

	entry := LedgerEntry{
		Epoch:     c.t.epoch.Load(),
		Conn:      c.id,
		Peer:      c.peer,
		TxnID:     txn,
		UnitID:    unit,
		FC:        fc,
		Addr:      addr,
		Count:     count,
		Request:   hexOf(frame),
		RequestAt: now,
	}
	p := &pendingTxn{entry: entry, action: action}
	if fc == fcReadHolding || fc == fcReadInput {
		p.poll = c.t.polls.ObserveRead(ReadKey{UnitID: unit, Addr: addr, Count: count})
		p.entry.Poll = p.poll
	}

	// The unit-id gate answers here rather than forwarding: a Modbus gateway
	// that does not front the addressed unit answers 0x0B itself, and the
	// device behind it never hears the request at all.
	if gate != 0 && unit != gate {
		c.t.mu.Lock()
		c.t.stats.UnitRefused++
		c.t.mu.Unlock()
		resp := exceptionFrame(txn, unit, fc)
		at := time.Now().UTC()
		c.resolve(p, hexOf(resp), OutcomeException, gwTargetFailedToRespond, &at)
		_, werr := client.Write(resp)
		return false, werr
	}

	c.mu.Lock()
	c.pending[txn] = append(c.pending[txn], p)
	c.live = append(c.live, p)
	c.mu.Unlock()
	return true, nil
}

// pumpResponses frames the device→client direction, applies whatever one-shot
// was armed against the matching request, and writes the result.
func (c *tapConn) pumpResponses(up, client net.Conn) {
	for {
		frame, err := readMBAPFrame(up)
		if err != nil {
			return
		}
		if err := c.onResponse(frame, client); err != nil {
			return
		}
	}
}

func (c *tapConn) onResponse(frame []byte, client net.Conn) error {
	txn := binary.BigEndian.Uint16(frame[0:2])
	p := c.take(txn)

	c.t.mu.Lock()
	c.t.stats.Responses++
	c.t.mu.Unlock()

	if p == nil {
		// A response to a request this tap never framed. That is not a
		// condition the sim can produce on its own, so it is relayed rather
		// than swallowed — hiding it would hide a bench defect — and it simply
		// has no ledger entry to complete.
		_, err := client.Write(frame)
		return err
	}

	code, isExc := exceptionCodeOf(frame)
	outcome := OutcomeAnswered
	if isExc {
		outcome = OutcomeException
	}

	out := frame
	if a := p.action; a != nil {
		switch a.Action {
		case ActionDrop:
			c.t.count(&c.t.stats.Dropped)
			at := time.Now().UTC()
			c.resolve(p, "", OutcomeDropped, 0, &at)
			return nil
		case ActionShort:
			keep := mbapHeaderLen + a.TruncateBytes
			if keep < mbapHeaderLen {
				keep = mbapHeaderLen
			}
			if keep > len(frame) {
				keep = len(frame)
			}
			// The length field is left exactly as the device wrote it, so the
			// header still promises bytes that are not coming. Truncating the
			// length too would be a short-but-consistent frame, which is a
			// different and far less interesting fault.
			out = frame[:keep]
			outcome = OutcomeTruncated
			c.t.count(&c.t.stats.Truncated)
		case ActionDelay:
			d := time.Duration(a.DelayMS) * time.Millisecond
			timer := time.NewTimer(d)
			select {
			case <-timer.C:
			case <-c.t.ctx.Done():
				timer.Stop()
				at := time.Now().UTC()
				c.resolve(p, "", OutcomeAbandoned, 0, &at)
				return io.EOF
			}
			outcome = OutcomeDelayed
			c.t.count(&c.t.stats.Delayed)
		}
	}

	if isExc && outcome == OutcomeAnswered {
		outcome = OutcomeException
	}
	// RECORDED BEFORE IT IS WRITTEN, deliberately.
	//
	// A successful Write is not a delivery receipt — it means the bytes
	// reached the kernel's send buffer, which is exactly as much as the sim
	// can ever know about what the client received. Recording afterwards would
	// buy no extra truth and would cost the one property the ledger exists
	// for: that a caller holding the response ALSO holds its ledger entry. A
	// row that read the ledger the instant its client's read returned would
	// otherwise be racing the tap's own bookkeeping, which is precisely the
	// class of timing bet this whole layer removes.
	at := time.Now().UTC()
	c.resolve(p, hexOf(out), outcome, code, &at)
	if _, err := client.Write(out); err != nil {
		return err
	}
	return nil
}

// take pops the oldest outstanding request bearing txn.
func (c *tapConn) take(txn uint16) *pendingTxn {
	c.mu.Lock()
	defer c.mu.Unlock()
	q := c.pending[txn]
	if len(q) == 0 {
		return nil
	}
	p := q[0]
	if len(q) == 1 {
		delete(c.pending, txn)
	} else {
		c.pending[txn] = q[1:]
	}
	for i, l := range c.live {
		if l == p {
			c.live = append(c.live[:i], c.live[i+1:]...)
			break
		}
	}
	return p
}

// abandonAll resolves every outstanding request as abandoned, in the order the
// client asked.
func (c *tapConn) abandonAll() {
	c.mu.Lock()
	live := c.live
	c.live = nil
	c.pending = make(map[uint16][]*pendingTxn)
	c.mu.Unlock()
	for _, p := range live {
		c.t.count(&c.t.stats.Abandoned)
		c.resolve(p, "", OutcomeAbandoned, 0, nil)
	}
}

// resolve completes one transaction: it finishes the ledger entry, appends it,
// and tells the poll tracker the transaction is no longer in flight.
func (c *tapConn) resolve(p *pendingTxn, respHex, outcome string, exc uint8, at *time.Time) {
	e := p.entry
	e.Response = respHex
	e.Outcome = outcome
	e.Exception = exc
	if p.action != nil {
		e.Fault = string(FaultNextResponse) + ":" + p.action.Action
	}
	if at != nil {
		t := *at
		e.ResponseAt = &t
		e.LatencyMS = float64(t.Sub(e.RequestAt).Microseconds()) / 1000
	}
	c.t.ledger.Append(e)
	c.t.polls.Resolve(p.poll)
}

func (t *Tap) count(field *uint64) {
	t.mu.Lock()
	*field++
	t.mu.Unlock()
}

// decodePDU reads the function code and, for the four function codes whose
// layout this file models, the starting address and register count.
//
// FC 0x06 writes exactly one register, so its count is 1 by definition — the
// PDU has no quantity field. An unmodelled function code yields (fc, 0, 0),
// and the ledger still carries every byte of the request.
func decodePDU(pdu []byte) (fc uint8, addr, count uint16) {
	if len(pdu) == 0 {
		return 0, 0, 0
	}
	fc = pdu[0]
	switch fc {
	case fcReadHolding, fcReadInput, fcWriteMultiple:
		if len(pdu) >= 5 {
			return fc, binary.BigEndian.Uint16(pdu[1:3]), binary.BigEndian.Uint16(pdu[3:5])
		}
	case fcWriteSingle:
		if len(pdu) >= 5 {
			return fc, binary.BigEndian.Uint16(pdu[1:3]), 1
		}
	}
	return fc, 0, 0
}

// exceptionCodeOf reports the exception code of a response frame, if it is one.
func exceptionCodeOf(frame []byte) (uint8, bool) {
	pdu := frame[mbapHeaderLen:]
	if len(pdu) < 2 || pdu[0]&exceptionBit == 0 {
		return 0, false
	}
	return pdu[1], true
}

// exceptionFrame builds a Modbus/TCP exception response for a request: the
// same transaction and unit ids, the request's function code with the
// exception bit set, and exception 0x0B GATEWAY TARGET DEVICE FAILED TO
// RESPOND.
//
// It is composed here, by hand, rather than by asking the Modbus library —
// the same referee-independence rule wire.go states for its framer. Four bytes
// of PDU do not need a dependency.
func exceptionFrame(txn uint16, unit, fc uint8) []byte {
	out := make([]byte, mbapHeaderLen+2)
	binary.BigEndian.PutUint16(out[0:2], txn)
	binary.BigEndian.PutUint16(out[2:4], 0) // protocol id
	binary.BigEndian.PutUint16(out[4:6], 3) // unit id + 2 PDU bytes
	out[6] = unit
	out[7] = fc | exceptionBit
	out[8] = gwTargetFailedToRespond
	return out
}

// ── POST /fault ───────────────────────────────────────────────────────────────

// tapSpec is the POST /fault body for the kinds this file owns.
type tapSpec struct {
	Kind  FaultKind `json:"kind"`
	Clear bool      `json:"clear,omitempty"`

	// next_response
	Action        string `json:"action,omitempty"`
	OnFC          int    `json:"on_fc,omitempty"`
	OnAddr        []int  `json:"on_addr,omitempty"`
	TruncateBytes int    `json:"truncate_bytes,omitempty"`
	DelayMS       int    `json:"delay_ms,omitempty"`

	// unit_id
	UnitID *int `json:"unit_id,omitempty"`
}

// maxOneShotDelayMS bounds a delay action. A delay is meant to outrun the
// client's per-request deadline (5 s on lexa-gw), not to wedge the sim: the
// response pump is serialized per connection, so an unbounded delay would
// stall every later transaction on that socket for as long as it lasted.
const maxOneShotDelayMS = 60000

// ApplyFault arms or clears one of this tap's kinds. It reports handled=false
// for a kind it does not own, so a sim binary can offer one POST /fault
// endpoint that routes a tap kind here and everything else onward — the same
// contract wire.go's Mangler and protorelay.go's ProtoRelay use.
func (t *Tap) ApplyFault(body []byte) (handled bool, err error) {
	var spec tapSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, fmt.Errorf("fault: %w", e)
	}
	if !tapFaultKinds[spec.Kind] {
		return false, nil
	}
	switch spec.Kind {
	case FaultNextResponse:
		return true, t.applyNextResponse(spec)
	case FaultUnitID:
		return true, t.applyUnitID(spec)
	}
	return true, nil
}

func (t *Tap) applyNextResponse(spec tapSpec) error {
	if spec.Clear {
		t.mu.Lock()
		t.oneShot = nil
		t.mu.Unlock()
		log.Printf("[tap] %s: next_response disarmed", t.listenAddr)
		return nil
	}
	s := &oneShotSpec{Action: strings.ToLower(strings.TrimSpace(spec.Action))}
	switch s.Action {
	case ActionDrop:
	case ActionShort:
		s.TruncateBytes = spec.TruncateBytes
		if s.TruncateBytes <= 0 {
			s.TruncateBytes = 2 // function code and byte count survive; data does not
		}
	case ActionDelay:
		s.DelayMS = spec.DelayMS
		if s.DelayMS <= 0 {
			return fmt.Errorf("fault %q: action %q needs a positive delay_ms", spec.Kind, s.Action)
		}
		if s.DelayMS > maxOneShotDelayMS {
			return fmt.Errorf("fault %q: delay_ms %d exceeds the %d ms ceiling — a longer hold would "+
				"stall every later transaction on the same socket, which is a wedged bench rather than "+
				"a fault", spec.Kind, s.DelayMS, maxOneShotDelayMS)
		}
	case "":
		return fmt.Errorf("fault %q: action is required (one of %q, %q, %q)",
			spec.Kind, ActionDrop, ActionShort, ActionDelay)
	default:
		return fmt.Errorf("fault %q: action %q is not one of %q, %q, %q",
			spec.Kind, spec.Action, ActionDrop, ActionShort, ActionDelay)
	}
	if spec.OnFC < 0 || spec.OnFC > 0xFF {
		return fmt.Errorf("fault %q: on_fc %d is not a Modbus function code", spec.Kind, spec.OnFC)
	}
	s.OnFC = uint8(spec.OnFC)
	switch len(spec.OnAddr) {
	case 0:
		s.AnyAddr = true
	case 1:
		s.OnAddrStart = uint16(spec.OnAddr[0])
		s.OnAddrEnd = s.OnAddrStart + 1
	case 2:
		s.OnAddrStart = uint16(spec.OnAddr[0])
		s.OnAddrEnd = uint16(spec.OnAddr[1])
		if s.OnAddrEnd <= s.OnAddrStart {
			return fmt.Errorf("fault %q: on_addr [%d,%d) is empty — a range that matches nothing would "+
				"arm a one-shot that can never fire", spec.Kind, s.OnAddrStart, s.OnAddrEnd)
		}
	default:
		return fmt.Errorf("fault %q: on_addr must have 0 (any), 1 (a single register) or 2 ([start,end)) "+
			"elements", spec.Kind)
	}
	s.ArmedAt = t.epoch.Load() + 1 // the epoch simapi will assign to this call
	t.mu.Lock()
	t.oneShot = s
	t.mu.Unlock()
	log.Printf("[tap] %s: next_response action=%s on_fc=%d on_addr=[%d,%d) any_addr=%v armed",
		t.listenAddr, s.Action, s.OnFC, s.OnAddrStart, s.OnAddrEnd, s.AnyAddr)
	return nil
}

func (t *Tap) applyUnitID(spec tapSpec) error {
	if spec.Clear {
		t.mu.Lock()
		t.unitID = 0
		t.mu.Unlock()
		log.Printf("[tap] %s: unit_id gate cleared — the device answers any unit id again", t.listenAddr)
		return nil
	}
	if spec.UnitID == nil {
		return fmt.Errorf("fault %q: unit_id is required (1..247; %q clears the gate)",
			spec.Kind, `{"kind":"unit_id","clear":true}`)
	}
	if *spec.UnitID < 1 || *spec.UnitID > 247 {
		return fmt.Errorf("fault %q: unit_id %d is outside the legal Modbus range 1..247 (0 is the RTU "+
			"broadcast address and has no meaning over Modbus/TCP)", spec.Kind, *spec.UnitID)
	}
	t.mu.Lock()
	t.unitID = uint8(*spec.UnitID)
	t.mu.Unlock()
	log.Printf("[tap] %s: device re-addressed to unit id %d; every other unit id now answers 0x%02x "+
		"GATEWAY TARGET DEVICE FAILED TO RESPOND", t.listenAddr, *spec.UnitID, gwTargetFailedToRespond)
	return nil
}

// tapKindNames lists this tap's kinds, for a sim binary's error message when a
// tap fault is requested but no tap is interposed.
func tapKindNames() string {
	names := make([]string, 0, len(tapFaultKinds))
	for k := range tapFaultKinds {
		names = append(names, string(k))
	}
	sortNames(names)
	return strings.Join(names, ", ")
}

// ErrNoTap is returned by a sim that was asked for a tap-level fault while
// running without an interposed tap, so a scenario reports SKIP-with-reason
// rather than mistaking "we never asked" for "the client passed".
var ErrNoTap = errors.New("the deterministic wire tap is not interposed: restart the sim without " +
	"-tap=false (kinds: " + tapKindNames() + "; endpoints: GET /ledger, GET /poll, GET /poll/wait)")

// TapFaultRequested reports whether a POST /fault body names a tap kind.
func TapFaultRequested(body []byte) bool {
	var spec tapSpec
	if json.Unmarshal(body, &spec) != nil {
		return false
	}
	return tapFaultKinds[spec.Kind]
}

func sortNames(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ── Report shapes ─────────────────────────────────────────────────────────────

// PollReport is what a sim answers GET /poll and GET /poll/wait with.
//
// It carries the poll accounting, the tap's own counters and the control-plane
// epoch together, because a caller that has just waited for a cycle wants all
// three in one answer: the cycle number to fence on, the evidence that the
// rule it relied on was the rule it thought, and the epoch to query the ledger
// with. Three round trips to assemble one fact is three chances for the device
// to move between them.
type PollReport struct {
	// Reached says whether the requested cycle had completed when this
	// answered. It is false — with a 200, not an error — when the request's
	// own timeout elapsed first, because "the client has not polled yet" is an
	// observation, not a failure of the endpoint.
	Reached bool `json:"reached"`
	// Want echoes the cycle ordinal the caller asked for (0 for a plain
	// GET /poll).
	Want uint64 `json:"want"`
	// Epoch is the control-plane epoch in force as this answered.
	Epoch uint64    `json:"epoch"`
	Poll  PollState `json:"poll"`
	Tap   TapStats  `json:"tap"`
}

// Report assembles a PollReport from the tap's current state.
func (t *Tap) Report(reached bool, want uint64, st PollState) PollReport {
	return PollReport{
		Reached: reached,
		Want:    want,
		Epoch:   t.epoch.Load(),
		Poll:    st,
		Tap:     t.Stats(),
	}
}

// LedgerReport is what a sim answers GET /ledger with: the matching page,
// inlined, plus the epoch and poll accounting in force as it answered.
type LedgerReport struct {
	Epoch uint64    `json:"epoch"`
	Poll  PollState `json:"poll"`
	LedgerPage
}

// LedgerReportFor answers a ledger query with the surrounding state.
func (t *Tap) LedgerReportFor(q LedgerQuery) LedgerReport {
	return LedgerReport{
		Epoch:      t.epoch.Load(),
		Poll:       t.polls.Snapshot(),
		LedgerPage: t.ledger.Since(q),
	}
}

// LedgerReportWaiting is LedgerReportFor, blocked until the query matches at
// least min transactions or ctx is done. See Ledger.WaitFor for why a row
// sometimes needs this rather than the poll barrier.
func (t *Tap) LedgerReportWaiting(ctx context.Context, q LedgerQuery, min int) LedgerReport {
	page := t.ledger.WaitFor(ctx, q, min)
	return LedgerReport{
		Epoch:      t.epoch.Load(),
		Poll:       t.polls.Snapshot(),
		LedgerPage: page,
	}
}
