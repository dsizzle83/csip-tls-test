package mbap

import (
	"encoding/binary"
	"fmt"
)

// The function codes the gateway speaks (design doc 01 §2). Anything else is
// answered with ExIllegalFunction by the server layer.
const (
	FCReadHolding   uint8 = 0x03
	FCReadInput     uint8 = 0x04
	FCWriteSingle   uint8 = 0x06
	FCWriteMultiple uint8 = 0x10
)

// Register-count hard bounds, fixed by the Modbus spec so every PDU fits in
// MaxPDU bytes.
const (
	MaxReadCount  = 125 // registers per FC 03/04 request
	MaxWriteCount = 123 // registers per FC 16 request
)

// PDUError reports a malformed or out-of-bounds PDU. Ex carries the Modbus
// exception code a server should answer the offending request with (via
// Exception); client-side builders use it purely as a typed error.
type PDUError struct {
	Reason string
	Ex     ExCode
}

func (e *PDUError) Error() string { return "mbap: bad pdu: " + e.Reason }

// ReadReq is a decoded FC 03/04 (read holding/input registers) request.
type ReadReq struct {
	FC    uint8  // FCReadHolding or FCReadInput
	Addr  uint16 // starting register address, 0-based
	Count uint16 // registers to read, 1..MaxReadCount
}

// WriteReq is a decoded FC 06/16 (write single/multiple registers) request.
type WriteReq struct {
	FC     uint8    // FCWriteSingle or FCWriteMultiple
	Addr   uint16   // starting register address, 0-based
	Values []uint16 // exactly 1 value for FC 06; 1..MaxWriteCount for FC 16
}

// checkSpan rejects address windows that run past the 16-bit register space.
func checkSpan(addr, count uint16) error {
	if uint32(addr)+uint32(count) > 0x10000 {
		return &PDUError{
			Reason: fmt.Sprintf("register span %d+%d exceeds address space", addr, count),
			Ex:     ExIllegalAddress,
		}
	}
	return nil
}

func checkReadFC(fc uint8) error {
	if fc != FCReadHolding && fc != FCReadInput {
		return &PDUError{Reason: fmt.Sprintf("function 0x%02x is not a read", fc), Ex: ExIllegalFunction}
	}
	return nil
}

func checkReadCount(count uint16) error {
	if count < 1 || count > MaxReadCount {
		return &PDUError{
			Reason: fmt.Sprintf("read count %d out of range [1,%d]", count, MaxReadCount),
			Ex:     ExIllegalValue,
		}
	}
	return nil
}

// ParseReadReq decodes an FC 03/04 request PDU: fc, addr(2), count(2).
func ParseReadReq(pdu []byte) (ReadReq, error) {
	if len(pdu) == 0 {
		return ReadReq{}, &PDUError{Reason: "empty pdu", Ex: ExIllegalFunction}
	}
	if err := checkReadFC(pdu[0]); err != nil {
		return ReadReq{}, err
	}
	if len(pdu) != 5 {
		return ReadReq{}, &PDUError{
			Reason: fmt.Sprintf("read request pdu length %d, want 5", len(pdu)),
			Ex:     ExIllegalValue,
		}
	}
	req := ReadReq{
		FC:    pdu[0],
		Addr:  binary.BigEndian.Uint16(pdu[1:3]),
		Count: binary.BigEndian.Uint16(pdu[3:5]),
	}
	if err := checkReadCount(req.Count); err != nil {
		return ReadReq{}, err
	}
	if err := checkSpan(req.Addr, req.Count); err != nil {
		return ReadReq{}, err
	}
	return req, nil
}

// BuildReadReq encodes an FC 03/04 request PDU (client side), enforcing the
// same bounds ParseReadReq does.
func BuildReadReq(req ReadReq) ([]byte, error) {
	if err := checkReadFC(req.FC); err != nil {
		return nil, err
	}
	if err := checkReadCount(req.Count); err != nil {
		return nil, err
	}
	if err := checkSpan(req.Addr, req.Count); err != nil {
		return nil, err
	}
	pdu := make([]byte, 5)
	pdu[0] = req.FC
	binary.BigEndian.PutUint16(pdu[1:3], req.Addr)
	binary.BigEndian.PutUint16(pdu[3:5], req.Count)
	return pdu, nil
}

// BuildReadResp encodes the response to req (server side): fc, byteCount(1),
// then one big-endian word per register. len(values) must equal req.Count.
func BuildReadResp(req ReadReq, values []uint16) ([]byte, error) {
	if err := checkReadFC(req.FC); err != nil {
		return nil, err
	}
	if err := checkReadCount(req.Count); err != nil {
		return nil, err
	}
	if len(values) != int(req.Count) {
		return nil, &PDUError{
			Reason: fmt.Sprintf("got %d values for a %d-register read", len(values), req.Count),
			Ex:     ExDeviceFailure,
		}
	}
	pdu := make([]byte, 2+2*len(values))
	pdu[0] = req.FC
	pdu[1] = byte(2 * len(values))
	for i, v := range values {
		binary.BigEndian.PutUint16(pdu[2+2*i:], v)
	}
	return pdu, nil
}

// ParseReadResp decodes the response to req (client side) and returns the
// register values. The Client strips exception responses before this runs;
// standalone callers see a *PDUError for any shape mismatch, including an
// exception PDU.
func ParseReadResp(req ReadReq, pdu []byte) ([]uint16, error) {
	if err := checkReadFC(req.FC); err != nil {
		return nil, err
	}
	if err := checkReadCount(req.Count); err != nil {
		return nil, err
	}
	if len(pdu) == 0 {
		return nil, &PDUError{Reason: "empty pdu", Ex: ExIllegalValue}
	}
	if pdu[0] != req.FC {
		return nil, &PDUError{
			Reason: fmt.Sprintf("response function 0x%02x, want 0x%02x", pdu[0], req.FC),
			Ex:     ExIllegalValue,
		}
	}
	wantBytes := 2 * int(req.Count)
	if len(pdu) != 2+wantBytes || int(pdu[1]) != wantBytes {
		return nil, &PDUError{
			Reason: fmt.Sprintf("read response shape (len %d, byte count %d) inconsistent with %d-register read",
				len(pdu), pdu[1], req.Count),
			Ex: ExIllegalValue,
		}
	}
	values := make([]uint16, req.Count)
	for i := range values {
		values[i] = binary.BigEndian.Uint16(pdu[2+2*i:])
	}
	return values, nil
}

// checkWriteShape validates the FC/value-count pairing shared by the write
// builders and parsers.
func checkWriteShape(fc uint8, nvalues int) error {
	switch fc {
	case FCWriteSingle:
		if nvalues != 1 {
			return &PDUError{
				Reason: fmt.Sprintf("fc 06 carries exactly 1 value, got %d", nvalues),
				Ex:     ExIllegalValue,
			}
		}
	case FCWriteMultiple:
		if nvalues < 1 || nvalues > MaxWriteCount {
			return &PDUError{
				Reason: fmt.Sprintf("write count %d out of range [1,%d]", nvalues, MaxWriteCount),
				Ex:     ExIllegalValue,
			}
		}
	default:
		return &PDUError{Reason: fmt.Sprintf("function 0x%02x is not a write", fc), Ex: ExIllegalFunction}
	}
	return nil
}

// ParseWriteReq decodes an FC 06 request PDU (fc, addr(2), value(2)) or an
// FC 16 request PDU (fc, addr(2), count(2), byteCount(1), values(2*count)).
// FC 16 byte-count inconsistency is rejected, never repaired.
func ParseWriteReq(pdu []byte) (WriteReq, error) {
	if len(pdu) == 0 {
		return WriteReq{}, &PDUError{Reason: "empty pdu", Ex: ExIllegalFunction}
	}
	switch fc := pdu[0]; fc {
	case FCWriteSingle:
		if len(pdu) != 5 {
			return WriteReq{}, &PDUError{
				Reason: fmt.Sprintf("fc 06 request pdu length %d, want 5", len(pdu)),
				Ex:     ExIllegalValue,
			}
		}
		return WriteReq{
			FC:     fc,
			Addr:   binary.BigEndian.Uint16(pdu[1:3]),
			Values: []uint16{binary.BigEndian.Uint16(pdu[3:5])},
		}, nil

	case FCWriteMultiple:
		if len(pdu) < 6 {
			return WriteReq{}, &PDUError{
				Reason: fmt.Sprintf("fc 16 request pdu length %d, want >= 6", len(pdu)),
				Ex:     ExIllegalValue,
			}
		}
		count := binary.BigEndian.Uint16(pdu[3:5])
		if err := checkWriteShape(fc, int(count)); err != nil {
			return WriteReq{}, err
		}
		byteCount := int(pdu[5])
		if byteCount != 2*int(count) {
			return WriteReq{}, &PDUError{
				Reason: fmt.Sprintf("fc 16 byte count %d inconsistent with register count %d", byteCount, count),
				Ex:     ExIllegalValue,
			}
		}
		if len(pdu) != 6+byteCount {
			return WriteReq{}, &PDUError{
				Reason: fmt.Sprintf("fc 16 request pdu length %d inconsistent with byte count %d (want %d)",
					len(pdu), byteCount, 6+byteCount),
				Ex: ExIllegalValue,
			}
		}
		req := WriteReq{
			FC:     fc,
			Addr:   binary.BigEndian.Uint16(pdu[1:3]),
			Values: make([]uint16, count),
		}
		for i := range req.Values {
			req.Values[i] = binary.BigEndian.Uint16(pdu[6+2*i:])
		}
		if err := checkSpan(req.Addr, count); err != nil {
			return WriteReq{}, err
		}
		return req, nil

	default:
		return WriteReq{}, &PDUError{
			Reason: fmt.Sprintf("function 0x%02x is not a write", pdu[0]),
			Ex:     ExIllegalFunction,
		}
	}
}

// BuildWriteReq encodes an FC 06/16 request PDU (client side), enforcing the
// same bounds ParseWriteReq does.
func BuildWriteReq(req WriteReq) ([]byte, error) {
	if err := checkWriteShape(req.FC, len(req.Values)); err != nil {
		return nil, err
	}
	if err := checkSpan(req.Addr, uint16(len(req.Values))); err != nil {
		return nil, err
	}
	if req.FC == FCWriteSingle {
		pdu := make([]byte, 5)
		pdu[0] = req.FC
		binary.BigEndian.PutUint16(pdu[1:3], req.Addr)
		binary.BigEndian.PutUint16(pdu[3:5], req.Values[0])
		return pdu, nil
	}
	pdu := make([]byte, 6+2*len(req.Values))
	pdu[0] = req.FC
	binary.BigEndian.PutUint16(pdu[1:3], req.Addr)
	binary.BigEndian.PutUint16(pdu[3:5], uint16(len(req.Values)))
	pdu[5] = byte(2 * len(req.Values))
	for i, v := range req.Values {
		binary.BigEndian.PutUint16(pdu[6+2*i:], v)
	}
	return pdu, nil
}

// BuildWriteResp encodes the response to req (server side): FC 06 echoes
// fc, addr, value; FC 16 answers fc, addr, count.
func BuildWriteResp(req WriteReq) ([]byte, error) {
	if err := checkWriteShape(req.FC, len(req.Values)); err != nil {
		return nil, err
	}
	pdu := make([]byte, 5)
	pdu[0] = req.FC
	binary.BigEndian.PutUint16(pdu[1:3], req.Addr)
	if req.FC == FCWriteSingle {
		binary.BigEndian.PutUint16(pdu[3:5], req.Values[0])
	} else {
		binary.BigEndian.PutUint16(pdu[3:5], uint16(len(req.Values)))
	}
	return pdu, nil
}

// ParseWriteResp verifies the response to req (client side): the server must
// echo exactly what BuildWriteResp would produce for req.
func ParseWriteResp(req WriteReq, pdu []byte) error {
	want, err := BuildWriteResp(req)
	if err != nil {
		return err
	}
	if len(pdu) != len(want) {
		return &PDUError{
			Reason: fmt.Sprintf("write response pdu length %d, want %d", len(pdu), len(want)),
			Ex:     ExIllegalValue,
		}
	}
	for i := range want {
		if pdu[i] != want[i] {
			return &PDUError{
				Reason: fmt.Sprintf("write response echo mismatch at byte %d: got 0x%02x, want 0x%02x",
					i, pdu[i], want[i]),
				Ex: ExIllegalValue,
			}
		}
	}
	return nil
}
