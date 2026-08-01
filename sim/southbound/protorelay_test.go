package sim

// protorelay_test.go — TEETH for the second relay (segment_response,
// short_response). Mirrors wire_test.go's two-level pattern: the pure
// writeFrame core is asserted on raw bytes (what a real socket's write
// pattern cannot prove deterministically — TCP segment coalescing on
// loopback is not something a test should race), and one test drives a real
// Modbus/TCP client through a live relay to prove the fault is not merely
// cosmetic. freeAddr/readHolding/isTimeout are wire_test.go's helpers,
// reused as-is (same package, same idiom).

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	modbuslib "github.com/simonvetter/modbus"
)

// protoRig is a real sim behind a ProtoRelay: the sim binds loopback, the
// relay binds the address a client dials.
type protoRig struct {
	sim *SolarServer
	p   *ProtoRelay
}

func newProtoRig(t *testing.T) *protoRig {
	t.Helper()
	upstream := freeAddr(t)
	ss, err := NewSolarServer("tcp://"+upstream, 8000, "")
	if err != nil {
		t.Fatalf("sim: %v", err)
	}
	p, err := NewProtoRelay("127.0.0.1:0", upstream)
	if err != nil {
		ss.Stop()
		t.Fatalf("protorelay: %v", err)
	}
	t.Cleanup(func() { p.Close(); ss.Stop() })
	return &protoRig{sim: ss, p: p}
}

func (r *protoRig) arm(t *testing.T, body string) {
	t.Helper()
	handled, err := r.p.ApplyFault([]byte(body))
	if !handled {
		t.Fatalf("the relay did not claim %s", body)
	}
	if err != nil {
		t.Fatalf("arm %s: %v", body, err)
	}
}

// TestProtoRelay_PassesThroughUnarmed is the control every other test here
// depends on: an unarmed relay must be invisible.
func TestProtoRelay_PassesThroughUnarmed(t *testing.T) {
	r := newProtoRig(t)
	frame, err := readHolding(t, r.p.Addr(), 0x1234, 1, solarBase, 4, 2*time.Second)
	if err != nil {
		t.Fatalf("unarmed relay: %v", err)
	}
	if txn := binary.BigEndian.Uint16(frame[0:2]); txn != 0x1234 {
		t.Fatalf("transaction id echoed as %#04x, want 0x1234", txn)
	}
	if frame[7] != 0x03 || frame[8] != 8 {
		t.Fatalf("response is not an 8-byte FC03 payload: fc=%#02x len=%d", frame[7], frame[8])
	}
	if r.p.Stats().Frames == 0 {
		t.Fatal("the relay counted no frames — the client did not go through it")
	}
}

// recordingWriter records each Write call's bytes (copied) as a separate
// slice, so a test can assert exactly how many writes happened and what
// each one contained — the only reliable way to prove "two writes", since a
// real socket's OS/NIC is free to coalesce or split them.
type recordingWriter struct{ writes [][]byte }

func (rw *recordingWriter) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	rw.writes = append(rw.writes, cp)
	return len(p), nil
}

// TestProtoRelay_WriteFrame_DefaultPassthrough pins "zero behaviour change
// when unused" at the pure-function level: with nothing armed, writeFrame
// makes exactly one Write call with the frame unchanged.
func TestProtoRelay_WriteFrame_DefaultPassthrough(t *testing.T) {
	p := &ProtoRelay{applied: map[FaultKind]uint64{}}
	frame := []byte{0, 1, 0, 0, 0, 3, 1, 0x03, 0}
	if err := p.writeFrame(&recordingWriter{}, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	rw := &recordingWriter{}
	if err := p.writeFrame(rw, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if len(rw.writes) != 1 {
		t.Fatalf("unarmed writeFrame made %d writes, want exactly 1", len(rw.writes))
	}
	if !bytes.Equal(rw.writes[0], frame) {
		t.Fatalf("unarmed writeFrame wrote %x, want the untouched frame %x", rw.writes[0], frame)
	}
}

// TestProtoRelay_WriteFrame_SegmentSplitsIntoTwoWrites proves segment_response
// is exactly two Write calls whose concatenation reconstructs the original
// frame, split at the requested offset.
func TestProtoRelay_WriteFrame_SegmentSplitsIntoTwoWrites(t *testing.T) {
	p := &ProtoRelay{applied: map[FaultKind]uint64{}}
	if handled, err := p.ApplyFault([]byte(`{"kind":"segment_response","split_after":5}`)); !handled || err != nil {
		t.Fatalf("arm: handled=%v err=%v", handled, err)
	}
	frame := []byte{0, 1, 0, 0, 0, 7, 1, 0x03, 4, 0xAA, 0xBB, 0xCC, 0xDD} // length=7 (unit+6-byte PDU) for a 13-byte frame
	rw := &recordingWriter{}
	if err := p.writeFrame(rw, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if len(rw.writes) != 2 {
		t.Fatalf("segment_response made %d writes, want exactly 2", len(rw.writes))
	}
	if len(rw.writes[0]) != 5 {
		t.Fatalf("first write was %d bytes, want 5 (split_after)", len(rw.writes[0]))
	}
	rejoined := append(append([]byte{}, rw.writes[0]...), rw.writes[1]...)
	if !bytes.Equal(rejoined, frame) {
		t.Fatalf("the two writes rejoined to %x, want the original frame %x", rejoined, frame)
	}
	if n := p.Stats().Applied["segment_response"]; n != 1 {
		t.Fatalf("segment_response counter = %d, want 1", n)
	}
}

// TestProtoRelay_WriteFrame_ShortResponseLiesAboutLength proves the length
// field is left UNTOUCHED (still promising the full PDU) while fewer bytes
// than that are actually written.
func TestProtoRelay_WriteFrame_ShortResponseLiesAboutLength(t *testing.T) {
	p := &ProtoRelay{applied: map[FaultKind]uint64{}}
	if handled, err := p.ApplyFault([]byte(`{"kind":"short_response","truncate_bytes":2}`)); !handled || err != nil {
		t.Fatalf("arm: handled=%v err=%v", handled, err)
	}
	frame := []byte{0, 1, 0, 0, 0, 7, 1, 0x03, 4, 0xAA, 0xBB, 0xCC, 0xDD} // length=7 (unit+6-byte PDU) for a 13-byte frame
	rw := &recordingWriter{}
	if err := p.writeFrame(rw, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if len(rw.writes) != 1 {
		t.Fatalf("short_response made %d writes, want exactly 1", len(rw.writes))
	}
	sent := rw.writes[0]
	wantKeep := mbapHeaderLen + 2
	if len(sent) != wantKeep {
		t.Fatalf("bytes actually sent = %d, want %d (header + 2 truncate_bytes)", len(sent), wantKeep)
	}
	declaredLen := int(binary.BigEndian.Uint16(sent[4:6]))
	fullFrameLen := mbapHeaderLen + declaredLen - 1
	if fullFrameLen != len(frame) {
		t.Fatalf("the length field was rewritten (declares a frame of %d bytes, original was %d) — "+
			"short_response must leave it lying about the ORIGINAL full size", fullFrameLen, len(frame))
	}
	if len(sent) >= fullFrameLen {
		t.Fatal("the bytes actually sent must be fewer than the header's declared length")
	}
}

// TestProtoRelay_SegmentResponse_RealClientStillWorks proves segmentation
// alone is transparent to a well-behaved client: PROT-2's own assertion #3
// is that a correct client depends on the length field, not on segment
// boundaries.
func TestProtoRelay_SegmentResponse_RealClientStillWorks(t *testing.T) {
	r := newProtoRig(t)
	r.arm(t, `{"kind":"segment_response","split_after":3}`)

	c, err := modbuslib.NewClient(&modbuslib.ClientConfiguration{
		URL:     "tcp://" + r.p.Addr(),
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
		t.Fatalf("a real client failed to reassemble a segmented response: %v", err)
	}
	if n := r.p.Stats().Applied["segment_response"]; n == 0 {
		t.Fatal("the relay did not record applying segment_response")
	}
}

// TestProtoRelay_ShortResponse_ConnectionStaysOpen proves the socket is not
// closed after a short response: a further write on the SAME connection
// must still succeed.
func TestProtoRelay_ShortResponse_ConnectionStaysOpen(t *testing.T) {
	r := newProtoRig(t)
	r.arm(t, `{"kind":"short_response","truncate_bytes":2}`)

	c, err := net.DialTimeout("tcp", r.p.Addr(), 3*time.Second)
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
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("read the short response: %v", err)
	}

	// The connection must still accept a further write — a closed socket
	// would fail this with a broken-pipe/reset error.
	req2 := []byte{0, 2, 0, 0, 0, 6, 1, 0x03, 0, 0, 0, 4}
	binary.BigEndian.PutUint16(req2[8:10], solarBase)
	if _, err := c.Write(req2); err != nil {
		t.Fatalf("second write on the same connection failed — short_response closed it: %v", err)
	}
}

// TestProtoRelay_ApplyFault_ArmClearUnknownKind mirrors wire_test.go's
// TestMangler_UnknownKindIsNotClaimed for this relay's own two kinds.
func TestProtoRelay_ApplyFault_ArmClearUnknownKind(t *testing.T) {
	p := &ProtoRelay{applied: map[FaultKind]uint64{}}
	if handled, _ := p.ApplyFault([]byte(`{"kind":"reject_write"}`)); handled {
		t.Fatal("the relay claimed a device-level fault kind")
	}
	if handled, _ := p.ApplyFault([]byte(`{"kind":"segment_response"}`)); !handled {
		t.Fatal("the relay did not claim its own kind")
	}
	if handled, err := p.ApplyFault([]byte(`{"kind":"segment_response","clear":true}`)); !handled || err != nil {
		t.Fatalf("clear: handled=%v err=%v", handled, err)
	}
	p.mu.Lock()
	seg := p.segment
	p.mu.Unlock()
	if seg {
		t.Fatal("segment_response must be disarmed after clear")
	}
	if !ProtoFaultRequested([]byte(`{"kind":"short_response"}`)) {
		t.Fatal("ProtoFaultRequested missed a proto kind")
	}
	if ProtoFaultRequested([]byte(`{"kind":"nan_sentinel"}`)) {
		t.Fatal("ProtoFaultRequested claimed a device kind")
	}
}
