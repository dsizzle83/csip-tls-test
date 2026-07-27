package suitemodbusserver

// pdu.go is this suite's own Modbus PDU layer and its own single-outstanding
// request client.
//
// lexa-proto/mbap already provides both, and this suite uses its Encode/Decode
// for the 7-byte MBAP header — framing is the wire format and a divergent
// framing codec would be a bug, not independent verification. But the PDUs
// themselves are built and parsed here, for two reasons:
//
//  1. Referee independence. mbap's BuildReadReq/ParseReadResp are the same
//     functions the DUT's serve path uses. A shared off-by-one in the byte-count
//     field would be invisible to a checker built on them.
//  2. Control. Three of the procedures in this suite need to do things a
//     well-behaved client library will not let them do: send an undefined
//     function code (EXC-3), send an ADU that is deliberately short (TCP-2), and
//     split one ADU across two writes (TCP-3). A client whose only surface is
//     ReadHolding/WriteSingle cannot express any of them.
//
// The client is deliberately synchronous and single-outstanding: every request
// is followed by exactly one response read, so the exchange log this suite
// builds (and later re-derives from the capture) is unambiguous.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"lexa-proto/mbap"
)

// Modbus function codes this suite emits.
const (
	fcReadHolding   byte = 0x03
	fcWriteSingle   byte = 0x06
	fcWriteMultiple byte = 0x10
	// fcUndefined is the function code EXC-3 names as its example: 50 (0x32) is
	// absent from the Modbus specification.
	fcUndefined byte = 0x32
)

// maxReadRegisters is the Modbus application protocol's ceiling on a single
// FC 3 read. MOD-2 turns on it: a model longer than this may legitimately be
// read with several requests, a model shorter than it may not.
const maxReadRegisters = 125

// buildReadReq builds an FC 3 / FC 4 read request PDU.
func buildReadReq(fc byte, addr, count uint16) ([]byte, error) {
	if count == 0 || count > maxReadRegisters {
		return nil, fmt.Errorf("suitemodbusserver: read quantity %d out of range [1,%d]", count, maxReadRegisters)
	}
	pdu := make([]byte, 5)
	pdu[0] = fc
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	binary.BigEndian.PutUint16(pdu[3:5], count)
	return pdu, nil
}

// parseReadResp validates a read response PDU and returns its registers. The
// byte-count field is checked against the request's quantity, which is the
// check a shared library would make identically and a DUT bug could otherwise
// slip past.
func parseReadResp(fc byte, count uint16, pdu []byte) ([]uint16, error) {
	if len(pdu) < 2 {
		return nil, fmt.Errorf("suitemodbusserver: read response pdu is %d bytes, want at least 2", len(pdu))
	}
	if pdu[0] != fc {
		return nil, fmt.Errorf("suitemodbusserver: read response function 0x%02x, want 0x%02x", pdu[0], fc)
	}
	n := int(pdu[1])
	if n != int(count)*2 {
		return nil, fmt.Errorf("suitemodbusserver: read response byte count %d, want %d for %d registers",
			n, int(count)*2, count)
	}
	if len(pdu) != 2+n {
		return nil, fmt.Errorf("suitemodbusserver: read response is %d bytes, want %d", len(pdu), 2+n)
	}
	out := make([]uint16, count)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(pdu[2+i*2 : 4+i*2])
	}
	return out, nil
}

// buildWriteSingleReq builds an FC 6 write request PDU.
func buildWriteSingleReq(addr, value uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = fcWriteSingle
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	binary.BigEndian.PutUint16(pdu[3:5], value)
	return pdu
}

// parseWriteSingleResp validates the FC 6 echo.
func parseWriteSingleResp(addr, value uint16, pdu []byte) error {
	if len(pdu) != 5 || pdu[0] != fcWriteSingle {
		return fmt.Errorf("suitemodbusserver: FC 6 response is % x, want a 5-byte echo", pdu)
	}
	gotAddr := binary.BigEndian.Uint16(pdu[1:3])
	gotVal := binary.BigEndian.Uint16(pdu[3:5])
	if gotAddr != addr || gotVal != value {
		return fmt.Errorf("suitemodbusserver: FC 6 response echoes address %d value 0x%04x, wrote address %d value 0x%04x",
			gotAddr, gotVal, addr, value)
	}
	return nil
}

// buildWriteMultipleReq builds an FC 16 write request PDU.
func buildWriteMultipleReq(addr uint16, values []uint16) ([]byte, error) {
	if len(values) == 0 || len(values) > 123 {
		return nil, fmt.Errorf("suitemodbusserver: FC 16 quantity %d out of range [1,123]", len(values))
	}
	pdu := make([]byte, 6+len(values)*2)
	pdu[0] = fcWriteMultiple
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	binary.BigEndian.PutUint16(pdu[3:5], uint16(len(values)))
	pdu[5] = byte(len(values) * 2)
	for i, v := range values {
		binary.BigEndian.PutUint16(pdu[6+i*2:8+i*2], v)
	}
	return pdu, nil
}

// parseWriteMultipleResp validates the FC 16 echo.
func parseWriteMultipleResp(addr uint16, count int, pdu []byte) error {
	if len(pdu) != 5 || pdu[0] != fcWriteMultiple {
		return fmt.Errorf("suitemodbusserver: FC 16 response is % x, want a 5-byte echo", pdu)
	}
	gotAddr := binary.BigEndian.Uint16(pdu[1:3])
	gotCount := binary.BigEndian.Uint16(pdu[3:5])
	if gotAddr != addr || int(gotCount) != count {
		return fmt.Errorf("suitemodbusserver: FC 16 response echoes address %d quantity %d, wrote address %d quantity %d",
			gotAddr, gotCount, addr, count)
	}
	return nil
}

// excError is a Modbus exception response. It is a protocol-level ANSWER, not a
// transport failure: the session stays frame-aligned and usable, and for half
// the procedures in this suite an exception is the expected result.
type excError struct {
	// FC is the request function code (without the 0x80 exception bit).
	FC byte
	// Code is the exception code byte.
	Code mbap.ExCode
	// TID is the transaction the exception answered.
	TID uint16
}

func (e *excError) Error() string {
	return fmt.Sprintf("modbus exception 0x%02x (%s) to function 0x%02x", uint8(e.Code), e.Code, e.FC)
}

// asException returns the exception carried by err, if any.
func asException(err error) (*excError, bool) {
	var e *excError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// exchange is one request/response pair as this suite saw it at the socket. It
// is the harness-side application-layer log the procedures' evidence sections
// call for — and, critically, it is what the citation phase re-derives from the
// capture and compares against, so a claim in the report is backed by bytes on
// the wire rather than by this record alone.
type exchange struct {
	TID    uint16
	Unit   uint8
	Req    []byte // request PDU
	Resp   []byte // response PDU, nil when none arrived
	Sent   time.Time
	Recvd  time.Time
	Err    error
	Note   string
	Elapse time.Duration

	// ReqOff and RespOff are the byte offsets of this ADU in the two
	// directions' APPLICATION streams — the plaintext streams, which for an
	// mbaps session are not the streams the capture holds. They are tracked
	// here because they are the only way to cite bytes that the MBAP re-parse
	// cannot find: TCP-2's deliberately truncated frame desynchronises the
	// request direction, and a check still has to be able to point at exactly
	// the bytes it sent. ReqLen / RespLen are the ADU lengths, header included.
	ReqOff, ReqLen   int
	RespOff, RespLen int
}

// client is a single-outstanding-request Modbus/TCP client over an established
// stream (a plain TCP conn, or the decrypted stream of an mbaps session).
type client struct {
	conn    net.Conn
	unit    uint8
	tid     uint16
	timeout time.Duration
	// log accumulates every exchange, in order.
	log []exchange
	// sent and recvd are the running byte counts of the two application
	// streams, which give every logged exchange its stream offsets.
	sent, recvd int
}

func newClient(conn net.Conn, unit uint8, timeout time.Duration) *client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &client{conn: conn, unit: unit, timeout: timeout}
}

// nextTID allocates the next transaction identifier. It starts at 1 so a zero
// TID in the capture is always a bug rather than a legitimate first request.
func (c *client) nextTID() uint16 {
	c.tid++
	if c.tid == 0 {
		c.tid = 1
	}
	return c.tid
}

// do sends one request PDU and reads one response. A Modbus exception response
// is returned as *excError with the exchange still recorded; every other error
// leaves the stream in an unknown position and the caller must stop using it.
func (c *client) do(pdu []byte, note string) ([]byte, error) {
	tid := c.nextTID()
	frame, err := mbap.Encode(mbap.ADU{Header: mbap.Header{TID: tid, UnitID: c.unit}, PDU: pdu})
	if err != nil {
		return nil, err
	}
	x := exchange{TID: tid, Unit: c.unit, Req: append([]byte(nil), pdu...), Note: note, Sent: time.Now(),
		ReqOff: c.sent, ReqLen: len(frame), RespOff: c.recvd}

	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		x.Err = err
		c.log = append(c.log, x)
		return nil, err
	}
	if _, err := c.conn.Write(frame); err != nil {
		x.Err = fmt.Errorf("write request: %w", err)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	c.sent += len(frame)
	adu, err := mbap.Decode(c.conn)
	x.Recvd = time.Now()
	x.Elapse = x.Recvd.Sub(x.Sent)
	if err != nil {
		x.Err = fmt.Errorf("read response: %w", err)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	x.Resp = append([]byte(nil), adu.PDU...)
	x.RespLen = 7 + len(adu.PDU)
	c.recvd += x.RespLen
	if adu.TID != tid {
		x.Err = fmt.Errorf("response tid 0x%04x, want 0x%04x", adu.TID, tid)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	if adu.UnitID != c.unit {
		x.Err = fmt.Errorf("response unit %d, want %d", adu.UnitID, c.unit)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	if adu.PDU[0] == pdu[0]|0x80 {
		if len(adu.PDU) != 2 {
			x.Err = fmt.Errorf("exception pdu is %d bytes, want 2", len(adu.PDU))
			c.log = append(c.log, x)
			return nil, x.Err
		}
		x.Err = &excError{FC: pdu[0], Code: mbap.ExCode(adu.PDU[1]), TID: tid}
		c.log = append(c.log, x)
		return nil, x.Err
	}
	c.log = append(c.log, x)
	return adu.PDU, nil
}

// readHolding issues one FC 3 request.
func (c *client) readHolding(addr, count uint16, note string) ([]uint16, error) {
	req, err := buildReadReq(fcReadHolding, addr, count)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req, note)
	if err != nil {
		return nil, err
	}
	return parseReadResp(fcReadHolding, count, resp)
}

// writeSingle issues one FC 6 request.
func (c *client) writeSingle(addr, value uint16, note string) error {
	resp, err := c.do(buildWriteSingleReq(addr, value), note)
	if err != nil {
		return err
	}
	return parseWriteSingleResp(addr, value, resp)
}

// writeMultiple issues one FC 16 request.
func (c *client) writeMultiple(addr uint16, values []uint16, note string) error {
	req, err := buildWriteMultipleReq(addr, values)
	if err != nil {
		return err
	}
	resp, err := c.do(req, note)
	if err != nil {
		return err
	}
	return parseWriteMultipleResp(addr, len(values), resp)
}

// writeRaw sends an already-built ADU in n chunks with a pause between them,
// then reads one response. It is what TCP-3 needs: chunks of {4, rest} split
// the ADU inside its 7-byte MBAP header, which is the case most likely to break
// a server that assumes one segment is one PDU.
func (c *client) writeSplit(pdu []byte, splitAt int, gap time.Duration, note string) ([]byte, error) {
	tid := c.nextTID()
	frame, err := mbap.Encode(mbap.ADU{Header: mbap.Header{TID: tid, UnitID: c.unit}, PDU: pdu})
	if err != nil {
		return nil, err
	}
	if splitAt <= 0 || splitAt >= len(frame) {
		return nil, fmt.Errorf("suitemodbusserver: split offset %d outside the %d-byte ADU", splitAt, len(frame))
	}
	x := exchange{TID: tid, Unit: c.unit, Req: append([]byte(nil), pdu...), Note: note, Sent: time.Now(),
		ReqOff: c.sent, ReqLen: len(frame), RespOff: c.recvd}
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		x.Err = err
		c.log = append(c.log, x)
		return nil, err
	}
	if _, err := c.conn.Write(frame[:splitAt]); err != nil {
		x.Err = fmt.Errorf("write first segment: %w", err)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	time.Sleep(gap)
	if _, err := c.conn.Write(frame[splitAt:]); err != nil {
		x.Err = fmt.Errorf("write second segment: %w", err)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	c.sent += len(frame)
	adu, err := mbap.Decode(c.conn)
	x.Recvd = time.Now()
	x.Elapse = x.Recvd.Sub(x.Sent)
	if err != nil {
		x.Err = fmt.Errorf("read response: %w", err)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	x.Resp = append([]byte(nil), adu.PDU...)
	x.RespLen = 7 + len(adu.PDU)
	c.recvd += x.RespLen
	if adu.TID != tid {
		x.Err = fmt.Errorf("response tid 0x%04x, want 0x%04x", adu.TID, tid)
		c.log = append(c.log, x)
		return nil, x.Err
	}
	if adu.PDU[0] == pdu[0]|0x80 {
		x.Err = &excError{FC: pdu[0], Code: mbap.ExCode(adu.PDU[1]), TID: tid}
		c.log = append(c.log, x)
		return nil, x.Err
	}
	c.log = append(c.log, x)
	return adu.PDU, nil
}

// writeTruncated sends a deliberately incomplete ADU: a complete MBAP header
// whose Length field promises more PDU bytes than are actually sent. It reads
// nothing — TCP-2's whole point is what happens to the NEXT request.
func (c *client) writeTruncated(pdu []byte, keep int, note string) (uint16, error) {
	tid := c.nextTID()
	frame, err := mbap.Encode(mbap.ADU{Header: mbap.Header{TID: tid, UnitID: c.unit}, PDU: pdu})
	if err != nil {
		return 0, err
	}
	if keep < 7 || keep >= len(frame) {
		return 0, fmt.Errorf("suitemodbusserver: truncation length %d must keep the 7-byte header and drop at least one pdu byte of %d",
			keep, len(frame))
	}
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	_, err = c.conn.Write(frame[:keep])
	c.log = append(c.log, exchange{
		TID: tid, Unit: c.unit, Req: append([]byte(nil), pdu[:keep-7]...),
		Note: note, Sent: time.Now(), Err: err,
		ReqOff: c.sent, ReqLen: keep, RespOff: c.recvd,
	})
	c.sent += keep
	return tid, err
}

// doTolerant sends a request and returns whatever ADU comes back, without
// requiring the transaction identifier to match.
//
// It exists for TCP-2 alone. After a deliberately truncated request a
// conformant-but-different server may answer the follow-up request with a
// mismatched transaction id (having consumed the follow-up's bytes as the tail
// of the truncated one), close the connection, or say nothing at all. All three
// are observations the procedure wants recorded; none of them should be turned
// into a transport error by a client that insists on its own bookkeeping.
func (c *client) doTolerant(pdu []byte, note string) (uint16, mbap.ADU, error) {
	tid := c.nextTID()
	frame, err := mbap.Encode(mbap.ADU{Header: mbap.Header{TID: tid, UnitID: c.unit}, PDU: pdu})
	if err != nil {
		return 0, mbap.ADU{}, err
	}
	x := exchange{TID: tid, Unit: c.unit, Req: append([]byte(nil), pdu...), Note: note, Sent: time.Now(),
		ReqOff: c.sent, ReqLen: len(frame), RespOff: c.recvd}
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		x.Err = err
		c.log = append(c.log, x)
		return tid, mbap.ADU{}, err
	}
	if _, err := c.conn.Write(frame); err != nil {
		x.Err = fmt.Errorf("write request: %w", err)
		c.log = append(c.log, x)
		return tid, mbap.ADU{}, x.Err
	}
	c.sent += len(frame)
	adu, derr := mbap.Decode(c.conn)
	x.Recvd = time.Now()
	x.Elapse = x.Recvd.Sub(x.Sent)
	if derr != nil {
		x.Err = derr
		c.log = append(c.log, x)
		return tid, mbap.ADU{}, derr
	}
	x.Resp = append([]byte(nil), adu.PDU...)
	x.RespLen = 7 + len(adu.PDU)
	c.recvd += x.RespLen
	c.log = append(c.log, x)
	return tid, adu, nil
}

// u32 decodes a big-endian 32-bit point from two registers.
func u32(regs []uint16) uint32 {
	if len(regs) < 2 {
		return 0
	}
	return uint32(regs[0])<<16 | uint32(regs[1])
}

// put32 encodes a 32-bit value as two registers.
func put32(v uint32) []uint16 { return []uint16{uint16(v >> 16), uint16(v)} }

// decodeString decodes a SunSpec string point: UTF-8, NUL-terminated or padded.
func decodeString(regs []uint16) string {
	b := make([]byte, 0, len(regs)*2)
	for _, r := range regs {
		b = append(b, byte(r>>8), byte(r))
	}
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}
	// Trim trailing spaces: padding with 0x20 is common and is not part of the
	// value.
	for len(b) > 0 && b[len(b)-1] == ' ' {
		b = b[:len(b)-1]
	}
	return string(b)
}
