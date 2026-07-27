package sim

// wire_test.go — TEETH for the MBAP wire mangler.
//
// These tests are deliberately written at TWO levels, because either alone
// would be dishonest:
//
//   - RAW BYTES. Each framing lie is asserted on the wire itself, by speaking
//     MBAP by hand. A client library's reaction to a corrupt frame is its own
//     policy — one library times out, another resynchronises, a third returns a
//     value — so asserting "the client errored" proves the mangler did
//     SOMETHING, not that it did the right thing. Asserting the bytes proves
//     the fault is the fault it claims to be.
//   - A REAL CLIENT. One test then drives the same relay with a real Modbus/TCP
//     client and asserts it fails, so we know the corruption is not merely
//     cosmetic — a lie no client can be made to notice is not a fault, it is a
//     rounding error.
//
// Every case is paired with the same probe through the relay UNARMED, which
// must succeed. A pass-through relay that quietly broke everything would
// otherwise satisfy every "the client failed" assertion in the file.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	modbuslib "github.com/simonvetter/modbus"
)

// wireRig is a real sim behind a mangler: the sim binds loopback, the mangler
// binds the address a client dials.
type wireRig struct {
	sim *SolarServer
	m   *Mangler
}

func newWireRig(t *testing.T) *wireRig {
	t.Helper()
	upstream := freeAddr(t)
	ss, err := NewSolarServer("tcp://"+upstream, 8000, "")
	if err != nil {
		t.Fatalf("sim: %v", err)
	}
	m, err := NewMangler("127.0.0.1:0", upstream)
	if err != nil {
		ss.Stop()
		t.Fatalf("mangler: %v", err)
	}
	t.Cleanup(func() { m.Close(); ss.Stop() })
	return &wireRig{sim: ss, m: m}
}

// freeAddr reserves an ephemeral port and releases it, so two listeners in one
// test do not have to guess at a free number.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func (r *wireRig) arm(t *testing.T, body string) {
	t.Helper()
	handled, err := r.m.ApplyFault([]byte(body))
	if !handled {
		t.Fatalf("the mangler did not claim %s", body)
	}
	if err != nil {
		t.Fatalf("arm %s: %v", body, err)
	}
}

// readHolding sends one FC03 by hand and returns the raw response frame the
// relay produced. txn and unit are ours to choose so the echoes can be checked.
func readHolding(t *testing.T, addr string, txn uint16, unit byte, reg, qty uint16, timeout time.Duration) ([]byte, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	req := make([]byte, 12)
	binary.BigEndian.PutUint16(req[0:2], txn)
	binary.BigEndian.PutUint16(req[2:4], 0) // protocol id
	binary.BigEndian.PutUint16(req[4:6], 6) // unit + 5 PDU bytes
	req[6] = unit
	req[7] = 0x03
	binary.BigEndian.PutUint16(req[8:10], reg)
	binary.BigEndian.PutUint16(req[10:12], qty)
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))

	hdr := make([]byte, mbapHeaderLen)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[4:6]))
	body := make([]byte, length-1)
	if _, err := io.ReadFull(c, body); err != nil {
		return append(hdr, body...), err
	}
	return append(hdr, body...), nil
}

const solarBase = 40070 // any register inside the populated SunSpec window

// TestMangler_PassesThroughUnarmed is the control every other test in this file
// depends on: an unarmed relay must be invisible. Without it, "the client
// failed with the fault armed" would be consistent with a relay that simply
// does not work.
func TestMangler_PassesThroughUnarmed(t *testing.T) {
	r := newWireRig(t)
	frame, err := readHolding(t, r.m.Addr(), 0x1234, 1, solarBase, 4, 2*time.Second)
	if err != nil {
		t.Fatalf("unarmed relay: %v", err)
	}
	if txn := binary.BigEndian.Uint16(frame[0:2]); txn != 0x1234 {
		t.Fatalf("transaction id echoed as %#04x, want 0x1234", txn)
	}
	if frame[6] != 1 {
		t.Fatalf("unit id echoed as %d, want 1", frame[6])
	}
	if frame[7] != 0x03 || frame[8] != 8 {
		t.Fatalf("response is not an 8-byte FC03 payload: fc=%#02x len=%d", frame[7], frame[8])
	}
	if r.m.Stats().Frames == 0 {
		t.Fatal("the relay counted no frames — the client did not go through it")
	}
}

// TestMangler_WrongUnitID is the literal "answers a different unit id" lie. The
// assertion is on the echoed byte, because that byte is the only thing a hub
// behind a Modbus gateway has with which to tell one device's answer from
// another's.
func TestMangler_WrongUnitID(t *testing.T) {
	r := newWireRig(t)
	r.arm(t, `{"kind":"wrong_unit_id","unit_id":9}`)
	frame, err := readHolding(t, r.m.Addr(), 1, 1, solarBase, 4, 2*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if frame[6] != 9 {
		t.Fatalf("unit id = %d, want the 9 the device is falsely claiming to be", frame[6])
	}
	if n := r.m.Stats().Mangled["wrong_unit_id"]; n == 0 {
		t.Fatal("the mangler did not count the rewrite")
	}

	r.arm(t, `{"kind":"wrong_unit_id","clear":true}`)
	frame, err = readHolding(t, r.m.Addr(), 1, 1, solarBase, 4, 2*time.Second)
	if err != nil {
		t.Fatalf("read after clear: %v", err)
	}
	if frame[6] != 1 {
		t.Fatalf("unit id = %d after clear, want the addressed 1", frame[6])
	}
}

// TestMangler_TxnIDSwap covers the id a hub uses to pair an answer with its
// question. A hub that ignores it is assuming request/response lockstep, and
// this fault is the only way to find out on a bench.
func TestMangler_TxnIDSwap(t *testing.T) {
	r := newWireRig(t)
	r.arm(t, `{"kind":"txn_id_swap","txn_delta":1}`)
	frame, err := readHolding(t, r.m.Addr(), 0x0100, 1, solarBase, 4, 2*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if txn := binary.BigEndian.Uint16(frame[0:2]); txn != 0x0101 {
		t.Fatalf("transaction id = %#04x, want 0x0101 — the answer is not mispaired", txn)
	}
}

// TestMangler_MBAPLengthLie asserts the header stops describing the payload. It
// checks the raw field rather than the client's reaction because a positive
// delta produces a stall and a negative one produces a desync — two very
// different client symptoms of one identical wire fault.
func TestMangler_MBAPLengthLie(t *testing.T) {
	r := newWireRig(t)

	honest, err := readHolding(t, r.m.Addr(), 1, 1, solarBase, 4, 2*time.Second)
	if err != nil {
		t.Fatalf("honest read: %v", err)
	}
	want := binary.BigEndian.Uint16(honest[4:6])

	// A NEGATIVE delta leaves the payload LONGER than the header admits, so the
	// whole frame is still readable and both halves of the lie are assertable:
	// the declared length shrank, the bytes on the wire did not.
	r.arm(t, `{"kind":"mbap_length_lie","len_delta":-2}`)
	raw := readAllRaw(t, r.m.Addr(), solarBase, 4)
	got := binary.BigEndian.Uint16(raw[4:6])
	if got != want-2 {
		t.Fatalf("length field = %d, want %d (the honest %d minus 2)", got, want-2, want)
	}
	if declared := mbapHeaderLen + int(got) - 1; declared >= len(raw) {
		t.Fatalf("the header declares %d bytes and %d arrived — the payload shrank with the field, "+
			"which is a short-but-CONSISTENT frame and desynchronises nothing", declared, len(raw))
	}
}

// readAllRaw sends one FC03 and returns every byte the relay sends back before
// it goes quiet — the only way to see a frame whose own length field is lying
// about how long it is.
func readAllRaw(t *testing.T, addr string, reg, qty uint16) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	req := make([]byte, 12)
	binary.BigEndian.PutUint16(req[0:2], 1)
	binary.BigEndian.PutUint16(req[4:6], 6)
	req[6], req[7] = 1, 0x03
	binary.BigEndian.PutUint16(req[8:10], reg)
	binary.BigEndian.PutUint16(req[10:12], qty)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out []byte
	buf := make([]byte, 256)
	for {
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out
		}
	}
}

// TestMangler_TruncateResponse asserts the frame stops mid-PDU while the header
// still promises the rest, which is what leaves a client blocked on bytes that
// are not coming.
func TestMangler_TruncateResponse(t *testing.T) {
	r := newWireRig(t)
	r.arm(t, `{"kind":"truncate_response","trunc_bytes":2}`)

	c, err := net.DialTimeout("tcp", r.m.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	req := []byte{0, 1, 0, 0, 0, 6, 1, 0x03, 0, 0, 0, 4}
	binary.BigEndian.PutUint16(req[8:10], solarBase)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))

	buf := make([]byte, 64)
	n, err := io.ReadFull(c, buf[:mbapHeaderLen+2])
	if err != nil {
		t.Fatalf("header+2: %v", err)
	}
	length := int(binary.BigEndian.Uint16(buf[4:6]))
	if length <= 2 {
		t.Fatalf("length field = %d, want it to still promise the untruncated PDU", length)
	}
	// The promised remainder must never arrive.
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, err := c.Read(buf[n:]); err == nil {
		t.Fatal("more bytes arrived after the truncation point — the response was not cut")
	} else if !isTimeout(err) && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected read error: %v", err)
	}
}

// TestMangler_StackResponsesReordersThem proves the reordering rather than
// assuming it: two requests go out in order, both are answered, and the
// transaction ids come back reversed. A hub pairing by arrival order now has
// every value under the wrong question.
func TestMangler_StackResponsesReordersThem(t *testing.T) {
	r := newWireRig(t)
	r.arm(t, `{"kind":"stack_responses","stack_n":2}`)

	c, err := net.DialTimeout("tcp", r.m.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	for _, txn := range []uint16{0x0011, 0x0022} {
		req := make([]byte, 12)
		binary.BigEndian.PutUint16(req[0:2], txn)
		binary.BigEndian.PutUint16(req[4:6], 6)
		req[6], req[7] = 1, 0x03
		binary.BigEndian.PutUint16(req[8:10], solarBase)
		binary.BigEndian.PutUint16(req[10:12], 2)
		if _, err := c.Write(req); err != nil {
			t.Fatalf("write %#04x: %v", txn, err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))

	var order []uint16
	for i := 0; i < 2; i++ {
		hdr := make([]byte, mbapHeaderLen)
		if _, err := io.ReadFull(c, hdr); err != nil {
			t.Fatalf("response %d header: %v", i, err)
		}
		rest := make([]byte, int(binary.BigEndian.Uint16(hdr[4:6]))-1)
		if _, err := io.ReadFull(c, rest); err != nil {
			t.Fatalf("response %d body: %v", i, err)
		}
		order = append(order, binary.BigEndian.Uint16(hdr[0:2]))
	}
	if order[0] != 0x0022 || order[1] != 0x0011 {
		t.Fatalf("responses arrived as %#04x,%#04x — want 0x0022 then 0x0011 (reversed)", order[0], order[1])
	}
}

// TestMangler_ARealClientNoticesTheTruncation is the level-two assertion: a
// production-grade Modbus/TCP client, given the truncated frame, must fail
// rather than return a value. It is the difference between a fault and a
// curiosity — and, run without the fault, it also proves the whole relay is
// transparent enough for a real client to work through.
func TestMangler_ARealClientNoticesTheTruncation(t *testing.T) {
	r := newWireRig(t)
	c, err := modbuslib.NewClient(&modbuslib.ClientConfiguration{
		URL:     "tcp://" + r.m.Addr(),
		Timeout: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := c.Open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()
	if err := c.SetUnitId(1); err != nil {
		t.Fatalf("unit: %v", err)
	}

	if _, err := c.ReadRegisters(solarBase, 4, modbuslib.HOLDING_REGISTER); err != nil {
		t.Fatalf("a real client could not read through the UNARMED relay: %v", err)
	}
	r.arm(t, `{"kind":"truncate_response","trunc_bytes":2}`)
	if vals, err := c.ReadRegisters(solarBase, 4, modbuslib.HOLDING_REGISTER); err == nil {
		t.Fatalf("a real client returned %v from a frame that was cut mid-PDU — "+
			"the truncation is not reaching it", vals)
	}
}

// TestMangler_RejectsAnImplausibleUpstreamFrame is the mangler's own I8: the
// length field it reads is attacker-controlled, and a relay that allocated on
// it would be the unbounded-growth defect this suite exists to find, sitting
// inside the tool that finds it.
func TestMangler_RejectsAnImplausibleUpstreamFrame(t *testing.T) {
	bad := []byte{0, 1, 0, 0, 0xFF, 0xFF, 1, 0x03}
	if _, err := readMBAPFrame(byteReader(bad)); err == nil {
		t.Fatal("a 65535-byte MBAP length must be refused, not allocated")
	}
	short := []byte{0, 1, 0, 0, 0, 0, 1}
	if _, err := readMBAPFrame(byteReader(short)); err == nil {
		t.Fatal("a zero MBAP length must be refused")
	}
}

// TestMangler_UnknownKindIsNotClaimed keeps the routing honest: a sim binary
// offers one /fault endpoint, and a mangler that claimed a device-level kind
// would silently swallow it.
func TestMangler_UnknownKindIsNotClaimed(t *testing.T) {
	m := &Mangler{unitID: -1, mangled: map[FaultKind]uint64{}}
	if handled, _ := m.ApplyFault([]byte(`{"kind":"reject_write"}`)); handled {
		t.Fatal("the mangler claimed a device-level fault kind")
	}
	if handled, _ := m.ApplyFault([]byte(`{"kind":"wrong_unit_id"}`)); !handled {
		t.Fatal("the mangler did not claim its own kind")
	}
	if !WireFaultRequested([]byte(`{"kind":"truncate_response"}`)) {
		t.Fatal("WireFaultRequested missed a wire kind")
	}
	if WireFaultRequested([]byte(`{"kind":"nan_sentinel"}`)) {
		t.Fatal("WireFaultRequested claimed a device kind")
	}
}

// byteReader adapts a byte slice to io.Reader for the framer tests.
func byteReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
