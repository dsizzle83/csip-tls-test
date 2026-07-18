package mbap

import (
	"fmt"
	"io"
	"sync"
)

// TIDMismatchError reports a response whose transaction identifier does not
// match the outstanding request. With a single outstanding request this
// means the stream is desynchronized (e.g. a late reply to a request the
// caller already timed out) — close the connection.
type TIDMismatchError struct {
	Want, Got uint16
}

func (e *TIDMismatchError) Error() string {
	return fmt.Sprintf("mbap: response tid 0x%04x, want 0x%04x", e.Got, e.Want)
}

// Client is a minimal Modbus/TCP client over any io.ReadWriter: it assigns
// incrementing TIDs, allows a single outstanding request at a time (enforced
// with a mutex, so it is safe for concurrent use), and matches each response
// to its request by TID.
//
// Deadlines are the caller's job: Client never sets read or write deadlines.
// When rw is a net.Conn (in production, a securemodbus TLS session), call
// SetDeadline / SetReadDeadline around Do or the convenience methods.
//
// Error contract: a *ExceptionError is a protocol-level answer — the
// connection stays frame-aligned and usable. Every other error from Do
// (FrameError, TIDMismatchError, wrapped I/O errors, deadline expiry) leaves
// the stream in an unknown position: close the connection and redial.
type Client struct {
	mu  sync.Mutex
	rw  io.ReadWriter
	tid uint16 // last TID assigned; first request uses 1
}

// NewClient wraps rw. The Client owns no connection lifecycle: the caller
// opens, deadlines, and closes rw.
func NewClient(rw io.ReadWriter) *Client {
	return &Client{rw: rw}
}

// Do sends pdu to unitID and returns the response PDU. The unit identifier
// is passed through untouched (gateway southbound routing key). A server
// exception response is returned as *ExceptionError; a response whose FC
// neither echoes the request nor flags an exception is a *FrameError.
func (c *Client) Do(unitID uint8, pdu []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tid++
	tid := c.tid
	frame, err := Encode(ADU{Header: Header{TID: tid, UnitID: unitID}, PDU: pdu})
	if err != nil {
		return nil, err
	}
	if _, err := c.rw.Write(frame); err != nil {
		return nil, fmt.Errorf("mbap: write request: %w", err)
	}
	resp, err := Decode(c.rw)
	if err != nil {
		return nil, err
	}
	if resp.TID != tid {
		return nil, &TIDMismatchError{Want: tid, Got: resp.TID}
	}
	if resp.UnitID != unitID {
		return nil, &FrameError{Reason: fmt.Sprintf("response unit id %d, want %d", resp.UnitID, unitID)}
	}
	fc := pdu[0]         // Encode guaranteed len(pdu) >= 1
	switch resp.PDU[0] { // Decode guaranteed len(resp.PDU) >= 2
	case fc | 0x80:
		if len(resp.PDU) != 2 {
			return nil, &FrameError{Reason: fmt.Sprintf("exception pdu length %d, want 2", len(resp.PDU))}
		}
		return nil, &ExceptionError{Code: ExCode(resp.PDU[1])}
	case fc:
		return resp.PDU, nil
	default:
		return nil, &FrameError{Reason: fmt.Sprintf("response function 0x%02x, want 0x%02x", resp.PDU[0], fc)}
	}
}

// ReadHolding reads count holding registers (FC 03) starting at addr.
func (c *Client) ReadHolding(unitID uint8, addr, count uint16) ([]uint16, error) {
	return c.read(unitID, ReadReq{FC: FCReadHolding, Addr: addr, Count: count})
}

// ReadInput reads count input registers (FC 04) starting at addr.
func (c *Client) ReadInput(unitID uint8, addr, count uint16) ([]uint16, error) {
	return c.read(unitID, ReadReq{FC: FCReadInput, Addr: addr, Count: count})
}

func (c *Client) read(unitID uint8, req ReadReq) ([]uint16, error) {
	pdu, err := BuildReadReq(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(unitID, pdu)
	if err != nil {
		return nil, err
	}
	return ParseReadResp(req, resp)
}

// WriteSingle writes one register (FC 06) at addr.
func (c *Client) WriteSingle(unitID uint8, addr, value uint16) error {
	return c.write(unitID, WriteReq{FC: FCWriteSingle, Addr: addr, Values: []uint16{value}})
}

// WriteMultiple writes values to consecutive registers (FC 16) starting at
// addr.
func (c *Client) WriteMultiple(unitID uint8, addr uint16, values []uint16) error {
	return c.write(unitID, WriteReq{FC: FCWriteMultiple, Addr: addr, Values: values})
}

func (c *Client) write(unitID uint8, req WriteReq) error {
	pdu, err := BuildWriteReq(req)
	if err != nil {
		return err
	}
	resp, err := c.Do(unitID, pdu)
	if err != nil {
		return err
	}
	return ParseWriteResp(req, resp)
}
