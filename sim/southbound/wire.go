package sim

// wire.go — THE MBAP WIRE MANGLER: the lies a device tells with its FRAMING
// rather than with its values.
//
// Everything in lying.go and faults.go is a lie about what a register CONTAINS.
// It is expressed through the sim's RequestHandler, which means the Modbus
// library still builds a perfectly well-formed response around it: correct
// length, correct unit id, correct transaction id, one response per request,
// in order. A hub can therefore be completely wrong about the world while its
// framing layer never sees anything unusual.
//
// The faults here are the other half, and they cannot be expressed above the
// framing layer at all:
//
//	truncate_response   the PDU stops mid-value while the length still claims more
//	mbap_length_lie     the length field disagrees with the bytes that follow
//	wrong_unit_id       the answer is stamped with a different slave's address
//	txn_id_swap         the answer is stamped with a different transaction's id
//	stack_responses     N answers are held and released together, out of order
//
// These are the framing bugs that turn "the device is misbehaving" into "the
// hub is now reading device B's power and calling it device A's" — the same
// silent-wrong-control failure class as a lying register, arrived at from
// underneath. A hub that indexes its in-flight requests by transaction id and
// verifies the unit id survives them; a hub that assumes request/response
// lockstep on one socket does not, and the assumption is invisible in code
// review because it is almost always true.
//
// # How it is interposed
//
// The mangler is a TCP relay: it binds the address the hub dials, forwards each
// request verbatim to the real Modbus server on a loopback port, and mangles
// the RESPONSE stream on the way back. Requests are never touched — the DUT's
// own bytes must reach the device unaltered or the device's ground truth would
// no longer be a witness to what the DUT asked for.
//
// Interposition is OPT-IN (modsim -mangle). With it off, the sim binds its port
// directly and not one byte of the existing bench behaviour changes; the flag
// exists precisely so a live shared bench is never silently reframed.
//
// # Why it does not reuse a Modbus library
//
// Referee independence (PN-1/C9, AD-003(f)): an adversary built from the same
// framer as the product cannot produce the frames that framer cannot produce,
// which are exactly the frames worth sending. The seven-byte MBAP header is
// parsed here by hand, in about ten lines, and that is the point.
//
// # Pairing with internal/invariant
//
// I7 (a status must not claim something that did not happen) and I8 (no
// unbounded growth) are the invariants these faults exist to try to falsify: a
// mismatched answer accepted as an answer is a false report, and a hub that
// reconnects per stalled transaction grows its connection table without bound.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Wire-level fault kinds. They are FaultKinds like any other so a scenario arms
// them through the same POST /fault, but they are routed to the Mangler rather
// than to a register-level controller (see Mangler.ApplyFault).
const (
	// FaultTruncateResponse cuts each response's PDU short while leaving the
	// MBAP length field claiming the full size. The client is left waiting for
	// bytes that will never arrive: a correct one times out that transaction
	// and resynchronises; one that reads whatever is next in the stream will
	// splice the FOLLOWING response's bytes onto this value and decode a
	// number that was never sent. TruncBytes sets how much of the PDU survives.
	FaultTruncateResponse FaultKind = "truncate_response"

	// FaultMBAPLengthLie perturbs the MBAP length field by LenDelta while
	// leaving the payload exactly as the server produced it. A positive delta
	// makes the client over-read into the next response (every later frame is
	// then off by delta, and every value it decodes is wrong but plausible); a
	// negative delta leaves unread bytes in the stream, so the client's next
	// header is read from the middle of this response's data. Either way the
	// connection desynchronises silently — no error, no exception, just answers
	// that belong to other questions.
	FaultMBAPLengthLie FaultKind = "mbap_length_lie"

	// FaultWrongUnitID rewrites the response's unit-id byte to UnitID. The
	// device is answering as a slave the hub did not address. This is the
	// "answers a different unit id than the one addressed" lie in its literal
	// form, and it is dangerous rather than merely odd: on a shared bus (or
	// behind a Modbus gateway, which is exactly what mbaps is) a hub that does
	// not check the echoed unit id will file inverter 2's measurements under
	// inverter 1 and curtail the wrong machine.
	FaultWrongUnitID FaultKind = "wrong_unit_id"

	// FaultTxnIDSwap perturbs the response's transaction id by TxnDelta (1 by
	// default). Modbus/TCP allows several transactions in flight on one socket
	// precisely because the id pairs each answer to its question; a hub that
	// ignores the field is assuming lockstep, and this is the fault that finds
	// out. Combined with slow_poll (which makes several transactions really be
	// in flight) it is the sharpest tool in this file.
	FaultTxnIDSwap FaultKind = "txn_id_swap"

	// FaultStackResponses holds StackN responses and then releases them in
	// REVERSE order. The device answers everything, correctly, with correct
	// ids — just not in the order asked. A hub that pairs by transaction id is
	// unaffected; a hub that pairs by arrival order now has every answer
	// attributed to the wrong request, which is the same wrong-value outcome as
	// a lying register with none of the register-level evidence to catch it.
	FaultStackResponses FaultKind = "stack_responses"
)

// wireKinds is the set the Mangler owns.
var wireKinds = map[FaultKind]bool{
	FaultTruncateResponse: true,
	FaultMBAPLengthLie:    true,
	FaultWrongUnitID:      true,
	FaultTxnIDSwap:        true,
	FaultStackResponses:   true,
}

// mbapHeaderLen is the Modbus/TCP MBAP header: transaction id (2), protocol id
// (2), length (2), unit id (1). The length counts the unit-id byte plus the PDU.
const mbapHeaderLen = 7

// maxFrameLen bounds a relayed frame. The MBAP length field is attacker-
// controlled in both directions here, so an unbounded read on it would be this
// file's own I8 violation.
const maxFrameLen = 300

// wireSpec is the POST /fault body as the Mangler reads it.
type wireSpec struct {
	Kind  FaultKind `json:"kind"`
	Clear bool      `json:"clear,omitempty"`

	TruncBytes int  `json:"trunc_bytes,omitempty"` // truncate_response: PDU bytes to keep (default 2)
	LenDelta   int  `json:"len_delta,omitempty"`   // mbap_length_lie: added to the length field (default +4)
	UnitID     *int `json:"unit_id,omitempty"`     // wrong_unit_id: id to stamp (default: addressed id + 1)
	TxnDelta   int  `json:"txn_delta,omitempty"`   // txn_id_swap: added to the transaction id (default +1)
	StackN     int  `json:"stack_n,omitempty"`     // stack_responses: responses to hold (default 2)
}

// Mangler is an MBAP-aware TCP relay that corrupts the RESPONSE direction.
//
// It is deliberately a separate object from the sims: it knows nothing about
// SunSpec, registers or devices, only about frames, so it can be put in front
// of any Modbus/TCP server — modsim, a battery sim, or a real inverter on the
// bench — without either side knowing.
type Mangler struct {
	listenAddr string
	upstream   string

	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu sync.Mutex
	// armed lies
	trunc      bool
	truncBytes int
	lenLie     bool
	lenDelta   int
	wrongUnit  bool
	unitID     int // <0 means "the addressed id plus one"
	txnSwap    bool
	txnDelta   int
	stackN     int

	// counters
	frames  uint64
	mangled map[FaultKind]uint64
}

// WireStats is the mangler's own account of what it relayed and what it did to
// it — the evidence a test uses to prove a wire lie fired, rather than inferring
// it from a client error that could have had any cause.
type WireStats struct {
	Frames  uint64            `json:"frames"`
	Mangled map[string]uint64 `json:"mangled,omitempty"`
}

// NewMangler starts a relay on listenAddr forwarding to upstream (both
// host:port). It returns as soon as the listener is bound, so a caller may dial
// immediately.
func NewMangler(listenAddr, upstream string) (*Mangler, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("sim: mangler listen %s: %w", listenAddr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Mangler{
		listenAddr: ln.Addr().String(),
		upstream:   upstream,
		ln:         ln,
		cancel:     cancel,
		unitID:     -1,
		mangled:    make(map[FaultKind]uint64),
	}
	m.wg.Add(1)
	go m.serve(ctx)
	return m, nil
}

// Addr returns the address the mangler is listening on (useful when the caller
// asked for port 0).
func (m *Mangler) Addr() string { return m.listenAddr }

// Close stops the relay and waits for its goroutines.
func (m *Mangler) Close() {
	m.cancel()
	_ = m.ln.Close()
	m.wg.Wait()
}

// Stats snapshots the relay's counters.
func (m *Mangler) Stats() WireStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := WireStats{Frames: m.frames, Mangled: make(map[string]uint64, len(m.mangled))}
	for k, v := range m.mangled {
		out.Mangled[string(k)] = v
	}
	return out
}

func (m *Mangler) serve(ctx context.Context) {
	defer m.wg.Done()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return // listener closed
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.handle(ctx, conn)
		}()
	}
}

// handle relays one client connection. The request direction is a verbatim
// io.Copy — the device must see exactly the bytes the DUT sent, or its own
// account of what was asked ceases to be independent evidence. Only the
// response direction is framed and mangled.
func (m *Mangler) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", m.upstream, 5*time.Second)
	if err != nil {
		log.Printf("[wire] mangler: upstream %s unreachable: %v", m.upstream, err)
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { m.pumpResponses(up, client); done <- struct{}{} }()

	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = up.Close()
	_ = client.Close()
	<-done
}

// pumpResponses frames the upstream's response stream and writes each frame to
// the client, mangled per the armed faults. A framing error ends the relay for
// this connection rather than guessing, because a mangler that silently
// resynchronised would be hiding evidence from the very test using it.
func (m *Mangler) pumpResponses(up, client net.Conn) {
	var held [][]byte
	flush := func() {
		// Release in REVERSE arrival order: the device answered everything, in
		// the wrong sequence. See FaultStackResponses.
		for i := len(held) - 1; i >= 0; i-- {
			if _, err := client.Write(held[i]); err != nil {
				return
			}
		}
		held = held[:0]
	}
	for {
		frame, err := readMBAPFrame(up)
		if err != nil {
			flush()
			return
		}
		m.mu.Lock()
		m.frames++
		stackN := m.stackN
		m.mu.Unlock()

		out := m.mangle(frame)
		if stackN > 1 {
			held = append(held, out)
			m.count(FaultStackResponses)
			if len(held) < stackN {
				continue
			}
			flush()
			continue
		}
		if _, err := client.Write(out); err != nil {
			return
		}
	}
}

// readMBAPFrame reads exactly one Modbus/TCP frame: the 7-byte header, then the
// PDU whose size the header's length field declares (minus the unit-id byte it
// counts). This is the whole of the independent framer.
func readMBAPFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, mbapHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[4:6]))
	if length < 1 || length > maxFrameLen {
		return nil, fmt.Errorf("wire: implausible MBAP length %d", length)
	}
	frame := make([]byte, mbapHeaderLen+length-1)
	copy(frame, hdr)
	if _, err := io.ReadFull(r, frame[mbapHeaderLen:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// mangle applies the armed wire faults to one well-formed response frame and
// returns the bytes to send. Order matters and is chosen to match what a broken
// device would produce: the header fields are stamped first (they are decided
// when the response is composed), then the payload is cut (that is a transmit
// failure, which happens last).
func (m *Mangler) mangle(frame []byte) []byte {
	m.mu.Lock()
	trunc, truncBytes := m.trunc, m.truncBytes
	lenLie, lenDelta := m.lenLie, m.lenDelta
	wrongUnit, unitID := m.wrongUnit, m.unitID
	txnSwap, txnDelta := m.txnSwap, m.txnDelta
	m.mu.Unlock()

	if !trunc && !lenLie && !wrongUnit && !txnSwap {
		return frame
	}
	out := append([]byte(nil), frame...)

	if txnSwap {
		txn := binary.BigEndian.Uint16(out[0:2])
		binary.BigEndian.PutUint16(out[0:2], uint16(int(txn)+txnDelta))
		m.count(FaultTxnIDSwap)
	}
	if wrongUnit {
		id := unitID
		if id < 0 {
			id = int(out[6]) + 1
		}
		out[6] = byte(id)
		m.count(FaultWrongUnitID)
	}
	if lenLie {
		l := int(binary.BigEndian.Uint16(out[4:6])) + lenDelta
		if l < 0 {
			l = 0
		}
		if l > 0xFFFF {
			l = 0xFFFF
		}
		binary.BigEndian.PutUint16(out[4:6], uint16(l))
		m.count(FaultMBAPLengthLie)
	}
	if trunc {
		// Cut the PDU but leave the length field alone, so the header still
		// promises bytes that are not coming. Truncating the length too would
		// merely be a short-but-consistent frame, which is a different (and far
		// less interesting) fault.
		keep := mbapHeaderLen + truncBytes
		if keep < mbapHeaderLen {
			keep = mbapHeaderLen
		}
		if keep < len(out) {
			out = out[:keep]
			m.count(FaultTruncateResponse)
		}
	}
	return out
}

func (m *Mangler) count(k FaultKind) {
	m.mu.Lock()
	if m.mangled == nil {
		m.mangled = make(map[FaultKind]uint64)
	}
	m.mangled[k]++
	m.mu.Unlock()
}

// ApplyFault arms or clears a wire fault. It reports handled=false for a kind
// it does not own, so a sim binary can offer one POST /fault endpoint that
// routes a wire kind here and everything else to the device.
func (m *Mangler) ApplyFault(body []byte) (handled bool, err error) {
	var spec wireSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, fmt.Errorf("fault: %w", e)
	}
	if !wireKinds[spec.Kind] {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch spec.Kind {
	case FaultTruncateResponse:
		if spec.Clear {
			m.trunc = false
			break
		}
		n := spec.TruncBytes
		if n <= 0 {
			n = 2 // the function code and the byte count survive; the data does not
		}
		m.trunc, m.truncBytes = true, n

	case FaultMBAPLengthLie:
		if spec.Clear {
			m.lenLie = false
			break
		}
		d := spec.LenDelta
		if d == 0 {
			d = 4
		}
		m.lenLie, m.lenDelta = true, d

	case FaultWrongUnitID:
		if spec.Clear {
			m.wrongUnit = false
			break
		}
		id := -1
		if spec.UnitID != nil {
			if *spec.UnitID < 0 || *spec.UnitID > 255 {
				return true, fmt.Errorf("fault %q: unit_id %d is not a Modbus address", spec.Kind, *spec.UnitID)
			}
			id = *spec.UnitID
		}
		m.wrongUnit, m.unitID = true, id

	case FaultTxnIDSwap:
		if spec.Clear {
			m.txnSwap = false
			break
		}
		d := spec.TxnDelta
		if d == 0 {
			d = 1
		}
		m.txnSwap, m.txnDelta = true, d

	case FaultStackResponses:
		if spec.Clear {
			m.stackN = 0
			break
		}
		n := spec.StackN
		if n <= 0 {
			n = 2
		}
		if n < 2 {
			return true, fmt.Errorf("fault %q: stack_n must be >= 2 (holding one response reorders nothing)", spec.Kind)
		}
		m.stackN = n
	}
	log.Printf("[wire] mangler %s: %s armed=%v", m.listenAddr, spec.Kind, !spec.Clear)
	return true, nil
}

// WireKindNames lists the mangler's kinds, for a sim binary's error message
// when a wire fault is requested but no mangler is interposed.
func wireKindNames() string {
	names := make([]string, 0, len(wireKinds))
	for k := range wireKinds {
		names = append(names, string(k))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ErrNoMangler is returned by a sim that was asked for a wire-level fault while
// running without an interposed mangler. It names the flag rather than failing
// vaguely, because "framing faults are not available on this sim" is a fact a
// scenario must report as a SKIP-with-reason rather than as a failure — the
// difference between "the gateway passed" and "we never asked".
var ErrNoMangler = errors.New("wire-level framing faults need an interposed mangler: restart the sim with -mangle (kinds: " + wireKindNames() + ")")

// WireFaultRequested reports whether a POST /fault body names a wire-level
// kind. A sim binary uses it to answer ErrNoMangler when it is running without
// a mangler, instead of passing the body to a device-level controller that
// would reject it as an unknown kind and hide the real reason.
func WireFaultRequested(body []byte) bool {
	var spec wireSpec
	if json.Unmarshal(body, &spec) != nil {
		return false
	}
	return wireKinds[spec.Kind]
}
