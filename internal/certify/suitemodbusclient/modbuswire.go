package suitemodbusclient

// modbuswire.go is this suite's own Modbus/TCP dissector.
//
// # Why a dissector lives here rather than being imported
//
// The bench is the referee (PN-1 / C9 / AD-003(f)). The DUT is a Modbus CLIENT,
// so every fact this suite asserts is a fact about bytes the DUT emitted and
// bytes it consumed. If the referee decoded those bytes with the same framing
// code the DUT frames them with, a framing bug would be invisible: the product
// would write a wrong MBAP length and the bench would read it back with the
// same wrong arithmetic and call it conformant. So the ADU parser below is
// written from the MODBUS Application Protocol V1.1b3 and MODBUS Messaging on
// TCP/IP V1.0b specifications directly, in this package, and shares nothing
// with the product — not even lexa-proto/mbap.
//
// # What it parses
//
// A reassembled TCP direction, not a packet. Modbus/TCP is a byte stream with
// self-delimiting ADUs; segment boundaries are meaningless to the protocol and
// the whole point of PROT-2 is that a conformant client must not care where
// they fall. Every ADU therefore carries the byte range it occupies in the
// reassembled direction, and the capture frames those bytes arrived in — which
// is exactly what certify.Evidence.CiteBytes and CiteFrames need to turn a
// decoded field into a citation a stranger can re-check in Wireshark.
//
// # Resynchronisation
//
// A capture that starts after the DUT's connection did (the normal case on a
// bench where the gateway has been polling for hours) delivers a direction
// whose first byte is somewhere in the middle of an ADU. Parsing from offset 0
// would then produce confident nonsense. Resync scans forward for the first
// offset at which several ADUs parse consecutively and reports how many bytes
// it had to discard, so a reader of the bundle can see that the first partial
// message was dropped rather than guessed at.

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MBAP and PDU size constants, from MODBUS Messaging on TCP/IP V1.0b §4.1 and
// MODBUS Application Protocol V1.1b3 §4.1.
const (
	// MBAPHeaderLen is transaction id (2) + protocol id (2) + length (2) +
	// unit id (1). The length field counts the unit id plus the PDU.
	MBAPHeaderLen = 7
	// MaxPDU is the Modbus PDU size limit that gives FC 0x03 its 125-register
	// ceiling: 253 bytes.
	MaxPDU = 253
	// MaxADU is the largest legal Modbus/TCP ADU.
	MaxADU = MBAPHeaderLen + MaxPDU
	// MaxReadQuantity is the register ceiling for FC 0x03 / 0x04 — the limit
	// READ-2 is about.
	MaxReadQuantity = 125
	// MaxWriteQuantity is the register ceiling for FC 0x10.
	MaxWriteQuantity = 123
	// ModbusTCPProtocolID is the only legal value of the MBAP protocol id.
	ModbusTCPProtocolID = 0
)

// Function codes this suite recognises. Anything else is carried through as an
// opaque code rather than rejected: an unexpected function code on the wire is
// an observation, not a parse failure.
const (
	FCReadCoils              = 0x01
	FCReadDiscreteInputs     = 0x02
	FCReadHoldingRegisters   = 0x03
	FCReadInputRegisters     = 0x04
	FCWriteSingleCoil        = 0x05
	FCWriteSingleRegister    = 0x06
	FCWriteMultipleRegisters = 0x10
	FCMaskWriteRegister      = 0x16
	FCReadWriteMultiple      = 0x17
	// FCExceptionBit is OR'd into the request's function code to mark an
	// exception response (MODBUS Application Protocol V1.1b3 §7).
	FCExceptionBit = 0x80
)

// exceptionNames are the standard Modbus exception codes. ERR-2 names codes
// 1–4; 0x0B is included because it is what a gateway-style server returns when
// the addressed unit does not answer, which is one of the two exception classes
// the bench can actually provoke.
var exceptionNames = map[uint8]string{
	0x01: "ILLEGAL FUNCTION",
	0x02: "ILLEGAL DATA ADDRESS",
	0x03: "ILLEGAL DATA VALUE",
	0x04: "SERVER DEVICE FAILURE",
	0x05: "ACKNOWLEDGE",
	0x06: "SERVER DEVICE BUSY",
	0x08: "MEMORY PARITY ERROR",
	0x0A: "GATEWAY PATH UNAVAILABLE",
	0x0B: "GATEWAY TARGET DEVICE FAILED TO RESPOND",
}

// ExceptionName renders an exception code the way the specification names it.
func ExceptionName(code uint8) string {
	if n, ok := exceptionNames[code]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", code)
}

// FunctionName renders a function code for an assertion's Observed text.
func FunctionName(fc uint8) string {
	switch fc &^ FCExceptionBit {
	case FCReadCoils:
		return "Read Coils"
	case FCReadDiscreteInputs:
		return "Read Discrete Inputs"
	case FCReadHoldingRegisters:
		return "Read Holding Registers"
	case FCReadInputRegisters:
		return "Read Input Registers"
	case FCWriteSingleCoil:
		return "Write Single Coil"
	case FCWriteSingleRegister:
		return "Write Single Register"
	case FCWriteMultipleRegisters:
		return "Write Multiple Registers"
	case FCMaskWriteRegister:
		return "Mask Write Register"
	case FCReadWriteMultiple:
		return "Read/Write Multiple Registers"
	default:
		return fmt.Sprintf("FC 0x%02x", fc&^FCExceptionBit)
	}
}

// ADU is one Modbus/TCP Application Data Unit as it appeared in a reassembled
// direction: the MBAP header, the PDU, and the provenance of both.
type ADU struct {
	// TxID, ProtoID, Length and UnitID are the MBAP header fields, verbatim.
	// Length is the field as transmitted, NOT a recomputed value: an assertion
	// about framing has to be able to see a wrong length.
	TxID    uint16
	ProtoID uint16
	Length  uint16
	UnitID  uint8
	// FC is the function code byte, exception bit included.
	FC uint8
	// Payload is the PDU after the function code.
	Payload []byte
	// Start and End are the ADU's half-open byte range in the direction's
	// reassembled stream — what CiteBytes takes.
	Start, End int
	// Frames are the capture frames those bytes arrived in, ascending. More
	// than one means the ADU was delivered across multiple TCP segments, which
	// is the fact PROT-2 exists to assert.
	Frames []int
}

// IsException reports whether the ADU is an exception response.
func (a ADU) IsException() bool { return a.FC&FCExceptionBit != 0 }

// ExceptionCode returns the exception code of an exception response.
func (a ADU) ExceptionCode() (uint8, bool) {
	if !a.IsException() || len(a.Payload) < 1 {
		return 0, false
	}
	return a.Payload[0], true
}

// Segmented reports whether this ADU's bytes arrived in more than one frame.
func (a ADU) Segmented() bool { return len(a.Frames) > 1 }

// LengthConsistent reports whether the MBAP length field agrees with the bytes
// actually present: length counts the unit id plus the PDU.
func (a ADU) LengthConsistent() bool {
	return int(a.Length) == 1+1+len(a.Payload) // unit id + function code + payload
}

// ReadRequest decodes an FC 0x03 / 0x04 request.
func (a ADU) ReadRequest() (start, quantity uint16, ok bool) {
	if a.IsException() || len(a.Payload) != 4 {
		return 0, 0, false
	}
	switch a.FC {
	case FCReadHoldingRegisters, FCReadInputRegisters:
	default:
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(a.Payload[0:2]), binary.BigEndian.Uint16(a.Payload[2:4]), true
}

// ReadResponse decodes an FC 0x03 / 0x04 response into registers. The byte
// count is returned separately so a check can assert on the field itself rather
// than on len(registers)*2, which would launder a wrong byte count.
func (a ADU) ReadResponse() (byteCount uint8, regs []uint16, ok bool) {
	if a.IsException() || len(a.Payload) < 1 {
		return 0, nil, false
	}
	switch a.FC {
	case FCReadHoldingRegisters, FCReadInputRegisters:
	default:
		return 0, nil, false
	}
	bc := a.Payload[0]
	body := a.Payload[1:]
	if int(bc) != len(body) || bc%2 != 0 {
		return bc, nil, false
	}
	regs = make([]uint16, len(body)/2)
	for i := range regs {
		regs[i] = binary.BigEndian.Uint16(body[2*i:])
	}
	return bc, regs, true
}

// WriteSingle decodes an FC 0x06 request or its echo response, which share a
// payload shape.
func (a ADU) WriteSingle() (addr, value uint16, ok bool) {
	if a.IsException() || a.FC != FCWriteSingleRegister || len(a.Payload) != 4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(a.Payload[0:2]), binary.BigEndian.Uint16(a.Payload[2:4]), true
}

// WriteMultipleRequest decodes an FC 0x10 request.
func (a ADU) WriteMultipleRequest() (addr, quantity uint16, byteCount uint8, vals []uint16, ok bool) {
	if a.IsException() || a.FC != FCWriteMultipleRegisters || len(a.Payload) < 5 {
		return 0, 0, 0, nil, false
	}
	addr = binary.BigEndian.Uint16(a.Payload[0:2])
	quantity = binary.BigEndian.Uint16(a.Payload[2:4])
	byteCount = a.Payload[4]
	body := a.Payload[5:]
	if int(byteCount) != len(body) || byteCount%2 != 0 {
		return addr, quantity, byteCount, nil, false
	}
	vals = make([]uint16, len(body)/2)
	for i := range vals {
		vals[i] = binary.BigEndian.Uint16(body[2*i:])
	}
	return addr, quantity, byteCount, vals, true
}

// WriteMultipleResponse decodes an FC 0x10 response (address + quantity only).
func (a ADU) WriteMultipleResponse() (addr, quantity uint16, ok bool) {
	if a.IsException() || a.FC != FCWriteMultipleRegisters || len(a.Payload) != 4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(a.Payload[0:2]), binary.BigEndian.Uint16(a.Payload[2:4]), true
}

// String renders an ADU the way a report line wants it.
func (a ADU) String() string {
	switch {
	case a.IsException():
		code, _ := a.ExceptionCode()
		return fmt.Sprintf("txid=%d unit=%d EXCEPTION 0x%02x to %s: 0x%02x %s",
			a.TxID, a.UnitID, a.FC, FunctionName(a.FC), code, ExceptionName(code))
	case a.FC == FCReadHoldingRegisters || a.FC == FCReadInputRegisters:
		if start, qty, ok := a.ReadRequest(); ok {
			return fmt.Sprintf("txid=%d unit=%d FC=0x%02x read start=%d(0x%04x) quantity=%d",
				a.TxID, a.UnitID, a.FC, start, start, qty)
		}
		if bc, regs, ok := a.ReadResponse(); ok {
			return fmt.Sprintf("txid=%d unit=%d FC=0x%02x response bytecount=%d(0x%02x) registers=%d",
				a.TxID, a.UnitID, a.FC, bc, bc, len(regs))
		}
	case a.FC == FCWriteSingleRegister:
		if addr, val, ok := a.WriteSingle(); ok {
			return fmt.Sprintf("txid=%d unit=%d FC=0x06 write addr=%d(0x%04x) value=%d(0x%04x)",
				a.TxID, a.UnitID, addr, addr, val, val)
		}
	case a.FC == FCWriteMultipleRegisters:
		if addr, qty, bc, _, ok := a.WriteMultipleRequest(); ok {
			return fmt.Sprintf("txid=%d unit=%d FC=0x10 write addr=%d(0x%04x) quantity=%d bytecount=%d",
				a.TxID, a.UnitID, addr, addr, qty, bc)
		}
		if addr, qty, ok := a.WriteMultipleResponse(); ok {
			return fmt.Sprintf("txid=%d unit=%d FC=0x10 ack addr=%d(0x%04x) quantity=%d",
				a.TxID, a.UnitID, addr, addr, qty)
		}
	}
	return fmt.Sprintf("txid=%d unit=%d FC=0x%02x length=%d payload=%d bytes",
		a.TxID, a.UnitID, a.FC, a.Length, len(a.Payload))
}

// Hex renders the whole ADU (MBAP header included) as the hex string READ-1,
// READ-2, WR-1 and WR-2 all require the log data to be represented as.
func (a ADU) Hex() string {
	b := make([]byte, 0, MBAPHeaderLen+1+len(a.Payload))
	var hdr [MBAPHeaderLen + 1]byte
	binary.BigEndian.PutUint16(hdr[0:2], a.TxID)
	binary.BigEndian.PutUint16(hdr[2:4], a.ProtoID)
	binary.BigEndian.PutUint16(hdr[4:6], a.Length)
	hdr[6] = a.UnitID
	hdr[7] = a.FC
	b = append(b, hdr[:]...)
	b = append(b, a.Payload...)
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

// ParseResult is everything parsing one direction learned, including what it
// could not make sense of. The failure fields are as important as ADUs: a
// direction with a structural problem is evidence about the peer that produced
// it, and silently dropping it would hide exactly the defect PROT-1 looks for.
type ParseResult struct {
	// ADUs are the complete, structurally well-formed ADUs, in stream order.
	ADUs []ADU
	// Discarded is how many leading bytes resynchronisation threw away because
	// the capture began mid-ADU.
	Discarded int
	// TrailingBytes is the count of bytes after the last complete ADU. A
	// non-zero value at the end of a direction means the last message was
	// incomplete — which is either a capture that stopped mid-message or a peer
	// that stopped mid-message, and the difference matters to PROT-1.
	TrailingBytes int
	// TrailingStart is where those bytes begin.
	TrailingStart int
	// Problems records structural findings: a non-zero protocol id, a length
	// field inconsistent with the delivered payload, an unparseable run.
	Problems []string
}

// ParseADUs parses a byte stream into Modbus/TCP ADUs.
//
// frameAt maps a byte range to the capture frames that delivered it; pass nil
// when parsing bytes that did not come from a capture (a unit test).
// resync should be true when the stream may have started mid-message.
func ParseADUs(data []byte, frameAt func(start, end int) []int, resync bool) *ParseResult {
	base := 0
	if resync {
		if off, ok := findADUStart(data); ok {
			base = off
		} else if len(data) > 0 {
			return &ParseResult{
				Discarded:     len(data),
				TrailingStart: 0,
				TrailingBytes: len(data),
				Problems: []string{fmt.Sprintf("no Modbus/TCP ADU boundary found in %d bytes: "+
					"the stream is either not Modbus/TCP or the capture missed too much of it", len(data))},
			}
		}
	}
	res := &ParseResult{Discarded: base}
	if base > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf(
			"discarded %d leading byte(s): the capture began part-way through an ADU, so offsets "+
				"before the first complete message are not message boundaries", base))
	}
	off := base
	for off < len(data) {
		a, n, err := parseOne(data, off)
		if err != nil {
			if _, ok := err.(incompleteErr); ok {
				break // a partial tail — reported as TrailingBytes below
			}
			res.Problems = append(res.Problems,
				fmt.Sprintf("stream offset %d: %v", off, err))
			break
		}
		if frameAt != nil {
			a.Frames = frameAt(a.Start, a.End)
		}
		if a.ProtoID != ModbusTCPProtocolID {
			res.Problems = append(res.Problems, fmt.Sprintf(
				"stream offset %d: MBAP protocol identifier is %d, not 0 — MODBUS Messaging on TCP/IP "+
					"V1.0b §4.1 fixes it at 0 for the MODBUS protocol", a.Start, a.ProtoID))
		}
		if !a.LengthConsistent() {
			res.Problems = append(res.Problems, fmt.Sprintf(
				"stream offset %d: MBAP length field is %d but the message carries %d byte(s) after it",
				a.Start, a.Length, 1+1+len(a.Payload)))
		}
		res.ADUs = append(res.ADUs, a)
		off += n
	}
	if off < len(data) {
		res.TrailingStart = off
		res.TrailingBytes = len(data) - off
	}
	return res
}

// incompleteErr marks "the rest of this message has not arrived", which is a
// normal end-of-stream condition rather than a structural fault.
type incompleteErr struct{ want, have int }

func (e incompleteErr) Error() string {
	return fmt.Sprintf("incomplete ADU: %d of %d bytes present", e.have, e.want)
}

// parseOne decodes the ADU starting at off.
func parseOne(data []byte, off int) (ADU, int, error) {
	if len(data)-off < MBAPHeaderLen+1 {
		return ADU{}, 0, incompleteErr{want: MBAPHeaderLen + 1, have: len(data) - off}
	}
	l := binary.BigEndian.Uint16(data[off+4 : off+6])
	// The length field counts the unit id plus the PDU, so it is at least 2
	// (unit id + function code) and at most 1+253.
	if l < 2 || int(l) > 1+MaxPDU {
		return ADU{}, 0, fmt.Errorf("MBAP length field %d is outside the legal range 2..%d, so the "+
			"message boundary cannot be located", l, 1+MaxPDU)
	}
	total := 6 + int(l)
	if len(data)-off < total {
		return ADU{}, 0, incompleteErr{want: total, have: len(data) - off}
	}
	a := ADU{
		TxID:    binary.BigEndian.Uint16(data[off+0 : off+2]),
		ProtoID: binary.BigEndian.Uint16(data[off+2 : off+4]),
		Length:  l,
		UnitID:  data[off+6],
		FC:      data[off+7],
		Payload: append([]byte(nil), data[off+8:off+total]...),
		Start:   off,
		End:     off + total,
	}
	return a, total, nil
}

// findADUStart locates the first offset from which several ADUs parse back to
// back. Requiring a RUN rather than a single success is what keeps it from
// locking onto a coincidental 0x0000 protocol id inside a register payload.
func findADUStart(data []byte) (int, bool) {
	const wantRun = 3
	limit := len(data)
	if limit > MaxADU*4 {
		limit = MaxADU * 4 // an ADU boundary within four message lengths, or never
	}
	for off := 0; off < limit; off++ {
		cur, run := off, 0
		for run < wantRun {
			a, n, err := parseOne(data, cur)
			if err != nil {
				if _, ok := err.(incompleteErr); ok && run > 0 {
					// Ran out of stream after at least one good message: a
					// short but consistent tail is good enough.
					return off, true
				}
				break
			}
			if a.ProtoID != ModbusTCPProtocolID {
				break
			}
			run++
			cur += n
		}
		if run >= wantRun {
			return off, true
		}
	}
	if len(data) == 0 {
		return 0, true
	}
	return 0, false
}

// Exchange is a request and the response the server sent for it.
type Exchange struct {
	Request ADU
	// Response is nil when no response was matched — either the server never
	// answered (the PROT-1 case) or the capture ended first.
	Response *ADU
}

// Matched reports whether the request was answered.
func (e Exchange) Matched() bool { return e.Response != nil }

// pairExchanges matches responses to requests by transaction identifier and
// unit identifier, in stream order.
//
// It deliberately does NOT fall back to positional matching when the ids do not
// line up. Positional matching would paper over exactly the defect this suite
// is looking for — a client that ignores the transaction id and treats whatever
// arrives next as the answer to whatever it asked last.
func pairExchanges(reqs, rsps []ADU) []Exchange {
	used := make([]bool, len(rsps))
	out := make([]Exchange, 0, len(reqs))
	for _, q := range reqs {
		ex := Exchange{Request: q}
		for i := range rsps {
			if used[i] {
				continue
			}
			r := rsps[i]
			if r.TxID != q.TxID || r.UnitID != q.UnitID {
				continue
			}
			// A response cannot precede its request on the wire.
			if len(r.Frames) > 0 && len(q.Frames) > 0 && r.Frames[0] < q.Frames[0] {
				continue
			}
			// The function code must be the request's, with or without the
			// exception bit.
			if r.FC&^FCExceptionBit != q.FC&^FCExceptionBit {
				continue
			}
			used[i] = true
			rr := r
			ex.Response = &rr
			break
		}
		out = append(out, ex)
	}
	return out
}

// TxIDReport summarises transaction-identifier discipline over a connection.
type TxIDReport struct {
	// Requests is how many requests were examined.
	Requests int
	// Increasing counts consecutive request pairs whose transaction id
	// advanced (modulo 2^16).
	Increasing int
	// Repeats counts a transaction id reused while an earlier request carrying
	// it was still unanswered — a genuine ambiguity, not merely wrap-around.
	Repeats int
	// Unmatched is how many requests never got a response.
	Unmatched int
	// Mismatched is how many responses carried a transaction id no outstanding
	// request had used.
	Mismatched int
	// First and Last are the transaction ids at the ends of the run.
	First, Last uint16
}

// analyseTxIDs computes the transaction-id report for a set of exchanges.
func analyseTxIDs(exchanges []Exchange, rsps []ADU) TxIDReport {
	rep := TxIDReport{Requests: len(exchanges)}
	outstanding := map[uint16]int{}
	known := map[uint16]bool{}
	var prev uint16
	for i, ex := range exchanges {
		id := ex.Request.TxID
		known[id] = true
		if i == 0 {
			rep.First = id
		} else if id != prev {
			// uint16 subtraction wraps, so "advanced" survives the 65535→0 roll.
			if id-prev < 0x8000 {
				rep.Increasing++
			}
		}
		if outstanding[id] > 0 {
			rep.Repeats++
		}
		if !ex.Matched() {
			outstanding[id]++
			rep.Unmatched++
		}
		prev = id
		rep.Last = id
	}
	for _, r := range rsps {
		if !known[r.TxID] {
			rep.Mismatched++
		}
	}
	return rep
}

// RegisterView is the server's register image as reconstructed from what the
// DUT actually read: every FC 0x03 / 0x04 response the check owns, laid down at
// the address its request named.
//
// It is the bench's independent picture of the SunSpec map — built only from
// wire bytes, never from the sim's own /registers dump — which is what lets a
// model-chain assertion be a citation rather than an act of faith.
type RegisterView struct {
	regs map[uint16]uint16
	// from records, per address, the ADU byte range the value came from, so a
	// chain-walk assertion can cite the exact response bytes.
	from map[uint16]byteRef
}

// byteRef locates one register value inside a reassembled direction.
type byteRef struct {
	start, end int
	frames     []int
}

func newRegisterView() *RegisterView {
	return &RegisterView{regs: map[uint16]uint16{}, from: map[uint16]byteRef{}}
}

// apply lays a read response down at the address its request named.
func (v *RegisterView) apply(start uint16, regs []uint16, rsp ADU) {
	// The register payload begins after the MBAP header, the function code and
	// the byte-count byte.
	payloadStart := rsp.Start + MBAPHeaderLen + 1 + 1
	for i, r := range regs {
		addr := start + uint16(i)
		v.regs[addr] = r
		v.from[addr] = byteRef{
			start:  payloadStart + 2*i,
			end:    payloadStart + 2*i + 2,
			frames: rsp.Frames,
		}
	}
}

// Get returns a register the DUT actually read.
func (v *RegisterView) Get(addr uint16) (uint16, bool) {
	r, ok := v.regs[addr]
	return r, ok
}

// Ref returns the byte range a register value was read from.
func (v *RegisterView) Ref(addr uint16) (byteRef, bool) {
	r, ok := v.from[addr]
	return r, ok
}

// Len is the number of distinct registers observed.
func (v *RegisterView) Len() int { return len(v.regs) }

// Addresses returns every observed address, ascending.
func (v *RegisterView) Addresses() []uint16 {
	out := make([]uint16, 0, len(v.regs))
	for a := range v.regs {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Frames returns every capture frame that contributed a register this view
// holds, deduplicated and ascending. It is what a check cites when it wants
// to point at "everything this register image was built from" rather than
// one specific address — the "no candidate found" case in evalScaleFactor
// (checks_info.go) is the reason this exists: a WARN that a value could not
// be derived should still cite exactly what was searched, which for a
// frozen-scoped view (registersAsOf) is a strict subset of the check's full
// attributed frames.
func (v *RegisterView) Frames() []int {
	seen := map[int]bool{}
	var out []int
	for _, ref := range v.from {
		for _, f := range ref.frames {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.Ints(out)
	return out
}

// registersAsOf reconstructs the register image using only read exchanges
// whose response arrived AT OR BEFORE cutoff, according to at — a resolver
// from frame index to capture timestamp. A read is EXCLUDED, not merely
// superseded, when any frame carrying its response fails the cutoff or has an
// unresolvable time: an unknown time is not evidence a read happened before
// whatever boundary cutoff names.
//
// # Why this exists beside apply's ordinary last-write-wins
//
// buildConversation's loop (conversation.go) applies every owned read in
// stream order and lets the last one win, which is the right answer for
// every other check in this suite: a check that provokes a write, or a fault,
// wants the LATEST value, because that is the one the provocation produced.
//
// checkINFO1 (checks_info.go) is different: it freezes the server's animation,
// reads it, and only THEN resumes — but the resume is a deferred call that
// fires when the check function returns, while the DUT keeps polling on its
// own independent ~10-second schedule regardless of what the check is doing.
// A poll already in flight when resume lands can have some of its responses
// timestamped before the boundary and some after, and BOTH still land inside
// the check's own attributed frames — there is no window-boundary trick that
// separates them, because there is no boundary between them; it is the same
// window's own live phase straddling the moment resume actually happened.
// Ordinary apply()'d accumulation would then silently let whichever arrived
// later win, which is not always the frozen one. registersAsOf answers the
// question a frozen-instant comparison actually needs: what did the DUT see
// while frozen, not what did it see last.
//
// Everything else this suite's checks read off a Conversation (ModelChain,
// coverage, per-write assertions) keeps using apply's full, last-write-wins
// image via Conversation.Registers — this constructor is additive, and
// touches no other check's evidence.
func registersAsOf(exchanges []Exchange, cutoff time.Time, at func(frame int) (time.Time, bool)) *RegisterView {
	v := newRegisterView()
	for _, ex := range exchanges {
		start, _, ok := ex.Request.ReadRequest()
		if !ok || ex.Response == nil {
			continue
		}
		if !framesAtOrBefore(ex.Response.Frames, cutoff, at) {
			continue
		}
		if _, regs, ok := ex.Response.ReadResponse(); ok {
			v.apply(start, regs, *ex.Response)
		}
	}
	return v
}

// framesAtOrBefore reports whether every frame in frames has a resolvable
// timestamp at or before cutoff. An ADU with no frames at all (should not
// happen — see ownedOnly, which drops those) is conservatively excluded.
func framesAtOrBefore(frames []int, cutoff time.Time, at func(frame int) (time.Time, bool)) bool {
	if len(frames) == 0 {
		return false
	}
	for _, f := range frames {
		t, ok := at(f)
		if !ok || t.After(cutoff) {
			return false
		}
	}
	return true
}
