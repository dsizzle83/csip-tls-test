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
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		switch err {
		case io.EOF:
			return ADU{}, io.EOF // clean close between frames
		case io.ErrUnexpectedEOF:
			return ADU{}, &FrameError{Reason: "truncated header"}
		default:
			return ADU{}, fmt.Errorf("mbap: read header: %w", err)
		}
	}
	h := Header{
		TID:    binary.BigEndian.Uint16(hdr[0:2]),
		PID:    binary.BigEndian.Uint16(hdr[2:4]),
		Length: binary.BigEndian.Uint16(hdr[4:6]),
		UnitID: hdr[6],
	}
	if h.PID != 0 {
		return ADU{}, &FrameError{Reason: fmt.Sprintf("protocol id 0x%04x, want 0", h.PID)}
	}
	if h.Length < minLength || h.Length > maxLength {
		return ADU{}, &FrameError{Reason: fmt.Sprintf("length %d out of range [%d,%d]", h.Length, minLength, maxLength)}
	}
	pdu := make([]byte, h.Length-1)
	if _, err := io.ReadFull(r, pdu); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return ADU{}, &FrameError{Reason: fmt.Sprintf("truncated frame body: got fewer than %d pdu bytes", len(pdu))}
		}
		return ADU{}, fmt.Errorf("mbap: read frame body: %w", err)
	}
	return ADU{Header: h, PDU: pdu}, nil
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
