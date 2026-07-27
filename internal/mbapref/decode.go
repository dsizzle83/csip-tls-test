package mbapref

// decode.go is the bench's own MBAP/Modbus reader, written from MODBUS
// Application Protocol Specification V1.1b3 and MODBUS Messaging on TCP/IP
// Implementation Guide V1.0b. It imports nothing from lexa-proto and nothing
// from the product. See doc.go for why that matters.
//
// # It is deliberately a different SHAPE, not a paraphrase
//
// An independent implementation that mirrors the original's structure is not
// independent in any useful sense — it makes the same decisions in the same
// order and therefore makes the same mistakes. The product frames from an
// io.Reader, one frame per call, consuming as it goes; a framing bug there is
// a bug about what got consumed. This one frames from a byte SLICE with
// explicit offsets and returns every frame in the buffer at once, so a framing
// bug here is a bug about arithmetic on offsets. The two failure modes do not
// overlap, which is the only reason comparing them is informative.
//
// The offset-based shape has a second payoff: every frame carries the byte
// range it occupied, so a divergence found against a capture cites a position
// in the reassembled stream, and netdis turns that position back into packet
// numbers. A finding reads "at stream offset 1184, packets 812-813" rather
// than "somewhere in this 17 KB blob".
//
// # Where this reader is deliberately more permissive than the product
//
// The spec's framing layer and its application layer are different layers, and
// the spec puts different things in each. Length is "number of following
// bytes" and the PDU is capped at 253, so the framing layer's own constraint
// is 2 <= Length <= 254 — a Length of 2 frames a one-byte PDU, which is a
// function code with no data. No legal Modbus message has that shape, but it
// is a MESSAGE error, not a FRAMING error, and the distinction is observable:
// a framing error means the byte stream is no longer trustworthy and the
// connection must close, while a message error is answered with an exception
// and the connection continues.
//
// This reader therefore frames what the framing layer permits and judges shape
// at the PDU layer, where the spec puts it. The product conflates the two (its
// floor is Length >= 3). That is a legitimate strictness choice for a server
// that speaks only four function codes, so it is an ENUMERATED divergence in
// divergence.go rather than a finding — but it is enumerated explicitly, with
// its consequence written down, precisely so that nobody has to rediscover
// which layer refused and what the peer therefore saw.

import (
	"encoding/binary"
	"fmt"
)

// Framing constants, straight from the two specs named above.
const (
	// HeaderLen is TID(2) + PID(2) + Length(2) + UnitID(1).
	HeaderLen = 7

	// MaxPDU is the largest MODBUS PDU. The value descends from the serial
	// line ADU limit of 256 bytes: 256 - 1 (address) - 2 (CRC) = 253.
	MaxPDU = 253

	// ProtocolID is the only protocol identifier assigned to MODBUS.
	ProtocolID = 0

	// MinLengthField frames a one-byte PDU: UnitID + a bare function code.
	// The spec's framing layer permits it; see the package comment.
	MinLengthField = 2

	// MaxLengthField is UnitID + MaxPDU.
	MaxLengthField = 1 + MaxPDU
)

// Frame is one MBAP ADU located in a byte stream.
//
// Off and End are the half-open byte range the frame occupied, relative to the
// start of the buffer that was framed. They are the whole reason this reader
// takes a slice: an assertion that cites a range can be turned back into
// packets by netdis, and a differential that cites a range can be replayed by
// hand.
type Frame struct {
	TID    uint16
	PID    uint16
	Length uint16
	Unit   uint8
	PDU    []byte

	Off int
	End int
}

// String renders a frame the way a hexdump annotation should read.
func (f Frame) String() string {
	fc := byte(0)
	if len(f.PDU) > 0 {
		fc = f.PDU[0]
	}
	return fmt.Sprintf("[%d,%d) tid=%d unit=%d len=%d fc=0x%02x pdu=%d B",
		f.Off, f.End, f.TID, f.Unit, f.Length, fc, len(f.PDU))
}

// Fault is a framing failure: the point at which the stream stopped being
// interpretable as MBAP.
//
// Truncated separates "this buffer ended mid-frame" from "these bytes are
// wrong". The distinction is essential when framing a capture, because a
// capture legitimately ends mid-frame — the run stopped, or the last segment
// was not captured — and treating that as a protocol violation would report a
// finding against every truncated stream on the bench. It is equally essential
// on a live socket, where truncation means "read more" and a violation means
// "close the connection", and confusing the two is how a reader resynchronises
// on attacker-chosen bytes.
type Fault struct {
	Off       int
	Reason    string
	Truncated bool
}

func (e *Fault) Error() string {
	if e.Truncated {
		return fmt.Sprintf("mbapref: stream ends mid-frame at offset %d: %s", e.Off, e.Reason)
	}
	return fmt.Sprintf("mbapref: framing violation at offset %d: %s", e.Off, e.Reason)
}

// FrameStream splits b into MBAP frames.
//
// It returns every frame it could read, and a Fault when it stopped short of
// the end of the buffer. A nil Fault means the buffer ended exactly on a frame
// boundary. Framing NEVER resynchronises: once a frame does not parse, the
// remaining bytes are not searched for a plausible header, because a reader
// that hunts for the next header lets a peer choose where the next frame
// begins. That is the property this function exists to hold, and the
// differential checks the product holds it too.
func FrameStream(b []byte) ([]Frame, *Fault) {
	var out []Frame
	off := 0
	for off < len(b) {
		f, adv, fault := frameAt(b, off)
		if fault != nil {
			return out, fault
		}
		out = append(out, f)
		off += adv
	}
	return out, nil
}

// frameAt reads the single frame beginning at off.
func frameAt(b []byte, off int) (Frame, int, *Fault) {
	if len(b)-off < HeaderLen {
		return Frame{}, 0, &Fault{
			Off:       off,
			Reason:    fmt.Sprintf("have %d of %d header bytes", len(b)-off, HeaderLen),
			Truncated: true,
		}
	}
	h := b[off : off+HeaderLen]
	f := Frame{
		TID:    binary.BigEndian.Uint16(h[0:2]),
		PID:    binary.BigEndian.Uint16(h[2:4]),
		Length: binary.BigEndian.Uint16(h[4:6]),
		Unit:   h[6],
		Off:    off,
	}
	if f.PID != ProtocolID {
		return Frame{}, 0, &Fault{
			Off:    off,
			Reason: fmt.Sprintf("protocol id 0x%04x, want 0x%04x", f.PID, ProtocolID),
		}
	}
	if f.Length < MinLengthField || f.Length > MaxLengthField {
		return Frame{}, 0, &Fault{
			Off: off,
			Reason: fmt.Sprintf("length field %d outside the framing range [%d,%d]",
				f.Length, MinLengthField, MaxLengthField),
		}
	}
	pduLen := int(f.Length) - 1
	end := off + HeaderLen + pduLen
	if end > len(b) {
		return Frame{}, 0, &Fault{
			Off:       off,
			Reason:    fmt.Sprintf("length field claims %d pdu bytes, %d remain", pduLen, len(b)-off-HeaderLen),
			Truncated: true,
		}
	}
	// The PDU aliases b. Callers that keep frames past the life of the buffer
	// must copy; the differential does not, and copying every PDU would double
	// the allocation of a fuzz target whose whole point is bounded cost.
	f.PDU = b[off+HeaderLen : end]
	f.End = end
	return f, HeaderLen + pduLen, nil
}

// Encode serialises a frame back to wire bytes.
//
// The Length field is RECOMPUTED from the PDU rather than copied from the
// struct, and this is the interesting half of the identity oracle. If a
// decoder accepted a frame whose declared length disagreed with the PDU it
// actually handed on, re-encoding through a recomputing encoder produces
// different bytes and the identity check fires. An encoder that copied the
// declared length would reproduce the input faithfully and hide exactly the
// bug worth finding.
func Encode(f Frame) ([]byte, error) {
	if f.PID != ProtocolID {
		return nil, fmt.Errorf("mbapref: encode: protocol id 0x%04x, want 0x%04x", f.PID, ProtocolID)
	}
	if len(f.PDU) < 1 || len(f.PDU) > MaxPDU {
		return nil, fmt.Errorf("mbapref: encode: pdu length %d outside [1,%d]", len(f.PDU), MaxPDU)
	}
	out := make([]byte, HeaderLen+len(f.PDU))
	binary.BigEndian.PutUint16(out[0:2], f.TID)
	binary.BigEndian.PutUint16(out[2:4], ProtocolID)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(f.PDU)+1))
	out[6] = f.Unit
	copy(out[HeaderLen:], f.PDU)
	return out, nil
}

// ---------------------------------------------------------------------------
// PDU layer
// ---------------------------------------------------------------------------

// Function codes. Only the four the gateway speaks are named; everything else
// decodes as KindUnsupported, which is a legitimate outcome and not an error —
// a capture of a real bus carries function codes this bench does not model,
// and a reader that treated them as corruption would desynchronise on traffic
// that is perfectly well formed.
const (
	FCReadHolding   uint8 = 0x03
	FCReadInput     uint8 = 0x04
	FCWriteSingle   uint8 = 0x06
	FCWriteMultiple uint8 = 0x10

	// ExceptionBit is set on the function code of an exception response.
	ExceptionBit uint8 = 0x80
)

// Register-count ceilings, derived rather than quoted, because a derived bound
// is one a reader can check. A read response carries FC + byteCount + 2*N and
// must fit in MaxPDU: (253-2)/2 = 125. A multiple-write request carries FC +
// addr + count + byteCount + 2*N: (253-6)/2 = 123.
const (
	MaxReadCount  = (MaxPDU - 2) / 2
	MaxWriteCount = (MaxPDU - 6) / 2
)

// Kind is what a PDU turned out to be. Direction is an input to decoding, not
// an output: the same five bytes are a read request from a client and a
// write-single response from a server, and nothing in the bytes distinguishes
// them. A decoder that guesses is a decoder that will eventually read a
// setpoint echo as a fresh command.
type Kind string

const (
	KindReadReq      Kind = "read-request"
	KindReadResp     Kind = "read-response"
	KindWriteReq     Kind = "write-request"
	KindWriteResp    Kind = "write-response"
	KindException    Kind = "exception"
	KindUnsupported  Kind = "unsupported-function"
	KindIndecipherab Kind = "undecodable"
)

// Dir is which end of the conversation emitted a PDU.
type Dir string

const (
	FromClient Dir = "client" // request direction
	FromServer Dir = "server" // response direction
)

// PDU is a decoded Modbus application message.
//
// Values holds registers for a read response or a write request; Addr and
// Count are meaningful for everything except an exception. Nothing here is a
// pointer and nothing is optional-by-nil: a field that does not apply to the
// Kind is zero, and the Kind is what says which fields to read. That is
// clumsier than an interface and much easier to compare, and comparing is the
// only thing this type exists for.
type PDU struct {
	Kind      Kind
	FC        uint8
	Addr      uint16
	Count     uint16
	Values    []uint16
	ByteCount int
	ExCode    uint8

	// Why is set when Kind is KindIndecipherab, and names the rule broken.
	Why string
}

// DecodePDU decodes one PDU in the given direction.
//
// It never returns an error. A PDU that breaks a shape rule comes back as
// KindIndecipherab with Why set, because in a differential "this decoder
// refused, and here is the rule it invoked" is a comparable value while an
// error string is not. The caller decides whether refusal is a finding.
func DecodePDU(p []byte, dir Dir) PDU {
	if len(p) == 0 {
		return PDU{Kind: KindIndecipherab, Why: "empty pdu"}
	}
	fc := p[0]
	if fc&ExceptionBit != 0 {
		if len(p) != 2 {
			return PDU{Kind: KindIndecipherab, FC: fc,
				Why: fmt.Sprintf("exception pdu length %d, want 2", len(p))}
		}
		if dir == FromClient {
			return PDU{Kind: KindIndecipherab, FC: fc,
				Why: "exception response sent in the request direction"}
		}
		return PDU{Kind: KindException, FC: fc &^ ExceptionBit, ExCode: p[1]}
	}
	switch fc {
	case FCReadHolding, FCReadInput:
		if dir == FromClient {
			return decodeReadReq(p)
		}
		return decodeReadResp(p)
	case FCWriteSingle:
		// FC 06's request and response are byte-identical by design: the
		// server echoes the request. Both directions decode the same way, and
		// the Kind differs only to keep a request from being compared against
		// a response as if the pairing had been checked.
		return decodeWriteSingle(p, dir)
	case FCWriteMultiple:
		if dir == FromClient {
			return decodeWriteMultiReq(p)
		}
		return decodeWriteMultiResp(p)
	default:
		return PDU{Kind: KindUnsupported, FC: fc}
	}
}

func decodeReadReq(p []byte) PDU {
	if len(p) != 5 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("read request pdu length %d, want 5", len(p))}
	}
	d := PDU{Kind: KindReadReq, FC: p[0],
		Addr:  binary.BigEndian.Uint16(p[1:3]),
		Count: binary.BigEndian.Uint16(p[3:5])}
	if d.Count < 1 || d.Count > MaxReadCount {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("read count %d outside [1,%d]", d.Count, MaxReadCount)}
	}
	if int(d.Addr)+int(d.Count) > 0x10000 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("read span %d+%d runs past the register space", d.Addr, d.Count)}
	}
	return d
}

func decodeReadResp(p []byte) PDU {
	if len(p) < 2 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("read response pdu length %d, want >= 2", len(p))}
	}
	bc := int(p[1])
	if bc%2 != 0 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("read response byte count %d is odd", bc)}
	}
	if len(p) != 2+bc {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("read response pdu length %d inconsistent with byte count %d (want %d)", len(p), bc, 2+bc)}
	}
	d := PDU{Kind: KindReadResp, FC: p[0], ByteCount: bc, Count: uint16(bc / 2)}
	d.Values = make([]uint16, bc/2)
	for i := range d.Values {
		d.Values[i] = binary.BigEndian.Uint16(p[2+2*i:])
	}
	return d
}

func decodeWriteSingle(p []byte, dir Dir) PDU {
	if len(p) != 5 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("fc 06 pdu length %d, want 5", len(p))}
	}
	k := KindWriteReq
	if dir == FromServer {
		k = KindWriteResp
	}
	return PDU{Kind: k, FC: p[0],
		Addr:   binary.BigEndian.Uint16(p[1:3]),
		Count:  1,
		Values: []uint16{binary.BigEndian.Uint16(p[3:5])}}
}

func decodeWriteMultiReq(p []byte) PDU {
	if len(p) < 7 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("fc 16 request pdu length %d, want >= 7", len(p))}
	}
	count := binary.BigEndian.Uint16(p[3:5])
	bc := int(p[5])
	if count < 1 || count > MaxWriteCount {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("fc 16 register count %d outside [1,%d]", count, MaxWriteCount)}
	}
	if bc != 2*int(count) {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("fc 16 byte count %d inconsistent with register count %d", bc, count)}
	}
	if len(p) != 6+bc {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("fc 16 pdu length %d inconsistent with byte count %d (want %d)", len(p), bc, 6+bc)}
	}
	d := PDU{Kind: KindWriteReq, FC: p[0],
		Addr:      binary.BigEndian.Uint16(p[1:3]),
		Count:     count,
		ByteCount: bc,
		Values:    make([]uint16, count)}
	if int(d.Addr)+int(count) > 0x10000 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("fc 16 span %d+%d runs past the register space", d.Addr, count)}
	}
	for i := range d.Values {
		d.Values[i] = binary.BigEndian.Uint16(p[6+2*i:])
	}
	return d
}

func decodeWriteMultiResp(p []byte) PDU {
	if len(p) != 5 {
		return PDU{Kind: KindIndecipherab, FC: p[0],
			Why: fmt.Sprintf("fc 16 response pdu length %d, want 5", len(p))}
	}
	return PDU{Kind: KindWriteResp, FC: p[0],
		Addr:  binary.BigEndian.Uint16(p[1:3]),
		Count: binary.BigEndian.Uint16(p[3:5])}
}

// EncodePDU re-serialises a decoded PDU. It is the PDU-layer half of the
// identity oracle and, like Encode, recomputes every derived field (byte
// counts, register counts) rather than echoing what was decoded, so a decoder
// that accepted an inconsistent PDU is caught by the bytes not matching.
func EncodePDU(d PDU) ([]byte, error) {
	switch d.Kind {
	case KindReadReq:
		out := make([]byte, 5)
		out[0] = d.FC
		binary.BigEndian.PutUint16(out[1:3], d.Addr)
		binary.BigEndian.PutUint16(out[3:5], d.Count)
		return out, nil
	case KindReadResp:
		out := make([]byte, 2+2*len(d.Values))
		out[0] = d.FC
		out[1] = byte(2 * len(d.Values))
		for i, v := range d.Values {
			binary.BigEndian.PutUint16(out[2+2*i:], v)
		}
		return out, nil
	case KindWriteReq:
		if d.FC == FCWriteSingle {
			if len(d.Values) != 1 {
				return nil, fmt.Errorf("mbapref: encode fc 06 with %d values", len(d.Values))
			}
			out := make([]byte, 5)
			out[0] = d.FC
			binary.BigEndian.PutUint16(out[1:3], d.Addr)
			binary.BigEndian.PutUint16(out[3:5], d.Values[0])
			return out, nil
		}
		out := make([]byte, 6+2*len(d.Values))
		out[0] = d.FC
		binary.BigEndian.PutUint16(out[1:3], d.Addr)
		binary.BigEndian.PutUint16(out[3:5], uint16(len(d.Values)))
		out[5] = byte(2 * len(d.Values))
		for i, v := range d.Values {
			binary.BigEndian.PutUint16(out[6+2*i:], v)
		}
		return out, nil
	case KindWriteResp:
		out := make([]byte, 5)
		out[0] = d.FC
		binary.BigEndian.PutUint16(out[1:3], d.Addr)
		if d.FC == FCWriteSingle {
			if len(d.Values) != 1 {
				return nil, fmt.Errorf("mbapref: encode fc 06 response with %d values", len(d.Values))
			}
			binary.BigEndian.PutUint16(out[3:5], d.Values[0])
		} else {
			binary.BigEndian.PutUint16(out[3:5], d.Count)
		}
		return out, nil
	case KindException:
		return []byte{d.FC | ExceptionBit, d.ExCode}, nil
	default:
		return nil, fmt.Errorf("mbapref: cannot re-encode a %s pdu", d.Kind)
	}
}
