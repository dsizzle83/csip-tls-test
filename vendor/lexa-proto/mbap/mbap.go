// Package mbap implements strict MBAP (Modbus/TCP Application Protocol)
// framing for Secure SunSpec Modbus (lexa-gw design doc 01, §2).
//
// The codec is deliberately narrow: it frames and unframes ADUs over a byte
// stream (in production, a TLS session — see lexa-platform/securemodbus),
// parses and builds the four PDU shapes the gateway speaks (FC 03/04/06/16),
// and provides a minimal single-outstanding-request Client. It carries no
// I/O policy of its own: no deadlines, no retries, no reconnects — when the
// underlying stream is a net.Conn, deadlines are the caller's job.
//
// Strictness contract: Decode rejects any frame with a nonzero protocol
// identifier or an out-of-range length field with a *FrameError. A
// *FrameError means the byte stream can no longer be trusted to be
// frame-aligned — callers must close the connection, never resynchronize by
// guessing. A clean peer close between frames surfaces as bare io.EOF; that
// is the only condition under which errors.Is(err, io.EOF) holds.
//
// Direction matters for one rule and one rule only, so there are two entry
// points. Decode is direction-agnostic and is what a CLIENT uses to read
// responses. DecodeRequest is Decode plus the request-side length rule: for
// the function codes whose request size the protocol fixes, a declared Length
// the function code cannot have is rejected before the promised body is read.
// Servers must use DecodeRequest — see its doc for what that buys and, just
// as importantly, what it cannot buy.
package mbap

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Wire layout: TID(2) PID(2) Length(2) UnitID(1) PDU(Length-1), big-endian.
const (
	headerLen = 7 // TID + PID + Length + UnitID

	// MaxPDU is the largest legal PDU (function code + data), fixed by the
	// Modbus spec so that a serial ADU fits in 256 bytes.
	MaxPDU = 253

	// minLength/maxLength bound the MBAP Length field (UnitID + PDU).
	// The strict floor is 3: every real PDU is at least FC + one data byte
	// (the shortest, an exception response, is exactly 2 bytes).
	minLength = 3
	maxLength = 1 + MaxPDU // 254
)

// Header is the 7-byte MBAP header. PID is always 0 on the wire; Length
// counts UnitID + PDU (i.e. len(PDU)+1).
type Header struct {
	TID    uint16 // transaction identifier, echoed by the server
	PID    uint16 // protocol identifier, must be 0
	Length uint16 // bytes following the Length field: UnitID + PDU
	UnitID uint8  // target unit (gateway southbound routing key)
}

// ADU is one MBAP frame: header plus PDU. The PDU is the function-code byte
// followed by its data, 1..253 bytes.
type ADU struct {
	Header
	PDU []byte
}

// FrameError reports a violation of the MBAP framing rules — a malformed
// header field, an out-of-range length, or a frame truncated mid-body. It is
// never io.EOF: after a *FrameError the stream is not frame-aligned and the
// caller must close the connection.
type FrameError struct {
	Reason string
}

func (e *FrameError) Error() string { return "mbap: malformed frame: " + e.Reason }

// Encode serializes a into wire bytes. a.PID must be 0 and a.PDU must be
// 1..253 bytes. The Length field is computed from the PDU; if a.Length is
// nonzero it must already be consistent (len(PDU)+1) or Encode fails —
// this catches callers that patch a PDU without refreshing the header.
//
// Note: a 1-byte PDU is legal to encode per the ADU definition, but this
// package's strict Decode requires FC + at least one data byte; every real
// Modbus request, response, and exception qualifies.
func Encode(a ADU) ([]byte, error) {
	if a.PID != 0 {
		return nil, &FrameError{Reason: fmt.Sprintf("protocol id 0x%04x, want 0", a.PID)}
	}
	n := len(a.PDU)
	if n < 1 || n > MaxPDU {
		return nil, &FrameError{Reason: fmt.Sprintf("pdu length %d out of range [1,%d]", n, MaxPDU)}
	}
	if a.Length != 0 && int(a.Length) != n+1 {
		return nil, &FrameError{Reason: fmt.Sprintf("header length %d inconsistent with pdu length %d (want %d)", a.Length, n, n+1)}
	}
	buf := make([]byte, headerLen+n)
	binary.BigEndian.PutUint16(buf[0:2], a.TID)
	// buf[2:4] (PID) stays zero.
	binary.BigEndian.PutUint16(buf[4:6], uint16(n+1))
	buf[6] = a.UnitID
	copy(buf[headerLen:], a.PDU)
	return buf, nil
}

// Decode reads exactly one MBAP frame from r.
//
// Strict: PID must be 0 and 3 <= Length <= 254, so the returned PDU is
// always 2..253 bytes. Violations return a *FrameError (close the
// connection). A clean peer close before any header byte returns bare
// io.EOF; a close mid-frame is a *FrameError, not io.EOF. Other read
// failures (e.g. deadline expiry on a net.Conn) are returned wrapped —
// the stream position is then unknown, so those also warrant a close.
func Decode(r io.Reader) (ADU, error) {
	h, err := decodeHeader(r)
	if err != nil {
		return ADU{}, err
	}
	pdu := make([]byte, h.Length-1)
	if err := readBody(r, pdu); err != nil {
		return ADU{}, err
	}
	return ADU{Header: h, PDU: pdu}, nil
}

// DecodeRequest reads exactly one MBAP frame from r, applying every rule
// Decode applies PLUS the request-direction length rule of checkRequestLength:
// for the function codes whose request size the MODBUS Application Protocol
// FIXES, the declared MBAP Length must be one the function code can actually
// have. Servers must use this; Decode stays the direction-agnostic codec the
// Client uses for responses (whose sizes differ — an FC 03 reply is 2+2*count
// bytes, not 5).
//
// Why a server needs it. A TCP stream carries no frame boundaries: the only
// thing that tells a receiver where a frame ends is the Length field the
// SENDER declared. A peer that sends a header promising more bytes than it
// then delivers therefore turns whatever arrives NEXT into the missing tail —
// the following request's bytes are silently spliced onto the stalled frame
// and answered under the stalled frame's transaction id (LAB29-008 /
// ss-modbus-conf-v1.4::TCP-2). The damage scales with the lie: a header
// declaring Length 254 behind FC 03 swallows 253 following bytes — up to
// twenty complete 12-byte ADUs — and on a write function code those swallowed
// bytes become register VALUES, i.e. a fabricated actuation of a DER.
//
// The declared length is the one part of that lie a receiver can catch with
// certainty and with no timing assumption whatsoever, because the protocol
// fixes the request size for these function codes. So the check is applied at
// the earliest moment it CAN be: after reading exactly one body byte (the
// function code) and BEFORE reading any of the bytes the header asked for.
// The offending peer is refused having cost us 8 bytes, never 260.
//
// It is deliberately not a whitelist of the function codes this gateway
// implements: an unimplemented but well-formed request must still be read in
// full and answered with exception 01 (SunSpecTCP-40), so function codes whose
// request size the protocol does not fix are left entirely alone here and
// travel on to the ladder.
//
// What it does NOT do — stated plainly because the boundary matters. When the
// declared length IS consistent with the function code (an FC 03 header that
// says Length 6 and then delivers only part of its five PDU bytes), the bytes
// that follow are indistinguishable, at the byte level, from that same request
// arriving in two TCP segments — which SS-MODBUS-CONF-v1.4 §2.7.8 (TCP-3)
// REQUIRES a conformant server to reassemble. No codec can separate those two
// cases; only elapsed time can, which is why the frame-assembly deadline lives
// in the listener (which owns the connection and its deadlines) and not here.
func DecodeRequest(r io.Reader) (ADU, error) {
	h, err := decodeHeader(r)
	if err != nil {
		return ADU{}, err
	}
	pdu := make([]byte, h.Length-1)
	// One byte — the function code — then judge the declared length against
	// it before committing to read the rest.
	if err := readBody(r, pdu[:1]); err != nil {
		return ADU{}, err
	}
	if err := checkRequestLength(pdu[0], len(pdu)); err != nil {
		return ADU{}, err
	}
	if err := readBody(r, pdu[1:]); err != nil {
		return ADU{}, err
	}
	return ADU{Header: h, PDU: pdu}, nil
}

// decodeHeader reads and validates the 7-byte MBAP header. The error contract
// is Decode's: bare io.EOF for a clean close BEFORE any header byte, a
// *FrameError for a malformed or out-of-range header, and a wrapped read error
// otherwise (including a deadline expiry, after which the stream position is
// unknown and the caller must close).
func decodeHeader(r io.Reader) (Header, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		switch err {
		case io.EOF:
			return Header{}, io.EOF // clean close between frames
		case io.ErrUnexpectedEOF:
			return Header{}, &FrameError{Reason: "truncated header"}
		default:
			return Header{}, fmt.Errorf("mbap: read header: %w", err)
		}
	}
	h := Header{
		TID:    binary.BigEndian.Uint16(hdr[0:2]),
		PID:    binary.BigEndian.Uint16(hdr[2:4]),
		Length: binary.BigEndian.Uint16(hdr[4:6]),
		UnitID: hdr[6],
	}
	if h.PID != 0 {
		return Header{}, &FrameError{Reason: fmt.Sprintf("protocol id 0x%04x, want 0", h.PID)}
	}
	if h.Length < minLength || h.Length > maxLength {
		return Header{}, &FrameError{Reason: fmt.Sprintf("length %d out of range [%d,%d]", h.Length, minLength, maxLength)}
	}
	return h, nil
}

// readBody fills buf from r, mapping a short read to the *FrameError the
// truncated-body contract promises. A zero-length buf is a no-op, so it is
// safe to call for the tail of a 2-byte PDU.
func readBody(r io.Reader, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return &FrameError{Reason: fmt.Sprintf("truncated frame body: got fewer than %d pdu bytes", len(buf))}
		}
		return fmt.Errorf("mbap: read frame body: %w", err)
	}
	return nil
}

// requestPDUShape reports the PDU-length constraint the MODBUS Application
// Protocol Specification fixes for a REQUEST carrying function code fc:
// lo..hi bytes, and whether the length must additionally be even. ok is false
// for every function code whose request size the protocol does NOT fix, which
// this package leaves unconstrained.
func requestPDUShape(fc uint8) (lo, hi int, even, ok bool) {
	switch fc {
	case 0x01, 0x02, FCReadHolding, FCReadInput, 0x05, FCWriteSingle:
		// Read Coils / Read Discrete Inputs / Read Holding Registers / Read
		// Input Registers / Write Single Coil / Write Single Register are all
		// fc(1) + address(2) + quantity-or-value(2): exactly 5 bytes.
		return 5, 5, false, true
	case 0x0F:
		// Write Multiple Coils: fc(1) + address(2) + quantity(2) +
		// byteCount(1) + byteCount data bytes, with byteCount = ceil(qty/8)
		// for qty 1..1968, i.e. 1..246.
		return 1 + 2 + 2 + 1 + 1, 1 + 2 + 2 + 1 + 246, false, true
	case FCWriteMultiple:
		// Write Multiple Registers: the same head, with byteCount = 2*qty for
		// qty 1..MaxWriteCount. byteCount is therefore EVEN, 2..246 — and the
		// whole PDU is even too, which rejects a further half of the
		// otherwise-in-range lengths.
		return 1 + 2 + 2 + 1 + 2, 1 + 2 + 2 + 1 + 2*MaxWriteCount, true, true
	}
	return 0, 0, false, false
}

// checkRequestLength judges a request's declared MBAP Length (expressed here
// as the pduLen it implies, Length-1) against its function code. See
// DecodeRequest for why this is the one framing lie a receiver can catch
// without a timing assumption.
func checkRequestLength(fc uint8, pduLen int) error {
	lo, hi, even, ok := requestPDUShape(fc)
	if !ok {
		return nil // size not fixed by the protocol — not ours to judge
	}
	if pduLen < lo || pduLen > hi {
		return &FrameError{Reason: fmt.Sprintf(
			"declared length %d impossible for request function 0x%02x: pdu %d bytes, want %s",
			pduLen+1, fc, pduLen, describeRange(lo, hi, even))}
	}
	if even && pduLen%2 != 0 {
		return &FrameError{Reason: fmt.Sprintf(
			"declared length %d impossible for request function 0x%02x: pdu %d bytes is odd, want %s",
			pduLen+1, fc, pduLen, describeRange(lo, hi, even))}
	}
	return nil
}

func describeRange(lo, hi int, even bool) string {
	if lo == hi {
		return fmt.Sprintf("exactly %d", lo)
	}
	if even {
		return fmt.Sprintf("an even %d..%d", lo, hi)
	}
	return fmt.Sprintf("%d..%d", lo, hi)
}

// ExCode is a Modbus exception code as carried in an exception-response PDU.
type ExCode uint8

// The exception codes the gateway emits (design doc 01 §2).
const (
	ExIllegalFunction ExCode = 0x01 // AuthZ denial + unsupported FC (SunSpecTCP-40)
	ExIllegalAddress  ExCode = 0x02
	ExIllegalValue    ExCode = 0x03
	ExDeviceFailure   ExCode = 0x04
	ExServerBusy      ExCode = 0x06
	ExGatewayPath     ExCode = 0x0A // unknown unit
	ExGatewayTarget   ExCode = 0x0B // known unit, southbound device down
)

// String returns a short human-readable name for logging.
func (c ExCode) String() string {
	switch c {
	case ExIllegalFunction:
		return "illegal function"
	case ExIllegalAddress:
		return "illegal data address"
	case ExIllegalValue:
		return "illegal data value"
	case ExDeviceFailure:
		return "server device failure"
	case ExServerBusy:
		return "server busy"
	case ExGatewayPath:
		return "gateway path unavailable"
	case ExGatewayTarget:
		return "gateway target failed to respond"
	default:
		return fmt.Sprintf("ExCode(0x%02x)", uint8(c))
	}
}

// Exception builds the exception response for req: same TID and unit, PDU =
// {FC|0x80, code}. req must be a successfully decoded request ADU (strict
// Decode guarantees a nonempty PDU, so the FC byte is always present).
func Exception(req ADU, code ExCode) ADU {
	var fc byte
	if len(req.PDU) > 0 {
		fc = req.PDU[0]
	}
	return ADU{
		Header: Header{TID: req.TID, Length: 3, UnitID: req.UnitID},
		PDU:    []byte{fc | 0x80, byte(code)},
	}
}

// ExceptionError is a decoded exception response, returned by Client when
// the server answers FC|0x80. It is a protocol-level answer, not a transport
// failure: the connection remains frame-aligned and usable.
type ExceptionError struct {
	Code ExCode
}

func (e *ExceptionError) Error() string {
	return fmt.Sprintf("mbap: server exception 0x%02x (%s)", uint8(e.Code), e.Code)
}
