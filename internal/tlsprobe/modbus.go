package tlsprobe

// modbus.go carries one SunSpec read inside the established tunnel and decides,
// from the raw bytes, whether the DUT answered it.
//
// Requests are BUILT with lexa-proto/mbap because the wire format is the wire
// format and a divergent framing codec would produce bugs rather than
// independent verification. Responses are DECIDED here, from the bytes, without
// mbap.Decode — "did the DUT emit a conformant seven-byte header" is not a
// question to ask a decoder whose job is to normalise. It is the same division
// internal/certify/suitessm/session.go states, for the same reason.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"lexa-proto/mbap"
)

// The SunSpec chain markers. "SunS" as two big-endian registers is the identity
// of a SunSpec device map; 0xFFFF ends the model chain.
const (
	sunsMagic0 uint16 = 0x5375 // "Su"
	sunsMagic1 uint16 = 0x6E53 // "nS"
	endMarker  uint16 = 0xFFFF
)

// commonModelID is SunSpec Model 1, the Common Model every device serves first
// and the one CRYP-002 §2.5.2.1 step 5 reads.
const commonModelID uint16 = 1

// opDeadline bounds one request/response pair inside an established session.
const opDeadline = 8 * time.Second

// fcReadHolding is Modbus function code 3, the one the procedures read with.
const fcReadHolding byte = 0x03

// Exchange is one request/response pair with the exact bytes preserved, because
// the bytes are what an assertion is made from.
type Exchange struct {
	// Label describes the operation in report prose.
	Label string
	// Request and Response are the complete MBAP ADUs as written and read.
	Request, Response []byte
	// Err is a TRANSPORT failure — the DUT closed, the read timed out, the
	// frame was malformed. A Modbus EXCEPTION is not an error: it is a
	// Response, and Registers reports it as one.
	Err error
}

// ModelRead is the SunSpec Common Model read a completed probe carries.
type ModelRead struct {
	// Attempted distinguishes "no read was asked for" from "a read was asked
	// for and produced nothing".
	Attempted bool
	// Unit and Base are where it was read from.
	Unit uint8
	Base uint16
	// Marker and Header are the discovery reads that located Model 1: the
	// "SunS" identifier at Base, and the (id, length) block header after it.
	Marker, Header Exchange
	// Read is THE Model 1 read — FC 0x03 at the Common Model's first data
	// register — and is the exchange an assertion cites.
	Read Exchange
	// Length is the model's declared register count.
	Length uint16
	// Values are the decoded registers. Prose only, never a verdict.
	Values []uint16
	// Err is the first thing that went wrong, or nil.
	Err error
}

// OK reports a read that was attempted and succeeded.
func (m ModelRead) OK() bool { return m.Attempted && m.Err == nil }

// Summary renders the read for an assertion's Observed field.
func (m ModelRead) Summary() string {
	switch {
	case !m.Attempted:
		return "no Model 1 read was attempted"
	case m.Err != nil:
		return fmt.Sprintf("the SunSpec Model 1 read on unit %d at base %d FAILED: %v", m.Unit, m.Base, m.Err)
	}
	out := fmt.Sprintf("SunSpec Model 1 read on unit %d: FC 0x03 at %d for %d register(s), answered with a "+
		"conformant %d-byte ADU", m.Unit, m.Base+4, m.Length, len(m.Read.Response))
	if id := m.Identity(); id != "" {
		out += " — " + id
	}
	return out
}

// Identity renders the Common Model's manufacturer / model / serial when they
// are present, so a report line says WHICH device answered rather than only
// that one did.
//
// Model 1's data block is Mn[16] Md[16] Opt[8] Vr[8] SN[16] DA[1] registers,
// each string field a run of big-endian register pairs holding NUL-padded
// ASCII. It is decoded here for PROSE ONLY: nothing in this package reaches a
// verdict from it.
func (m ModelRead) Identity() string {
	if len(m.Values) < 48 {
		return ""
	}
	mn := regString(m.Values[0:16])
	md := regString(m.Values[16:32])
	sn := regString(m.Values[48:min(64, len(m.Values))])
	parts := make([]string, 0, 3)
	if mn != "" {
		parts = append(parts, "Mn "+mn)
	}
	if md != "" {
		parts = append(parts, "Md "+md)
	}
	if sn != "" {
		parts = append(parts, "SN "+sn)
	}
	return strings.Join(parts, ", ")
}

// regString decodes a SunSpec string field: big-endian register pairs of ASCII,
// NUL-padded.
func regString(regs []uint16) string {
	b := make([]byte, 0, len(regs)*2)
	for _, r := range regs {
		b = append(b, byte(r>>8), byte(r))
	}
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

// modbusConn is the decrypted stream a probe drives Modbus over, with its own
// transaction counter.
type modbusConn struct {
	conn net.Conn
	tid  uint16
}

// nextTID returns a fresh transaction identifier. Zero is skipped so a missing
// echo cannot be mistaken for a matching one.
func (m *modbusConn) nextTID() uint16 {
	m.tid++
	if m.tid == 0 {
		m.tid = 1
	}
	return m.tid
}

// readHolding issues one FC 0x03 and returns the raw exchange.
func (m *modbusConn) readHolding(unit uint8, addr, count uint16, label string) Exchange {
	ex := Exchange{Label: label}
	tid := m.nextTID()
	pdu := []byte{fcReadHolding, byte(addr >> 8), byte(addr), byte(count >> 8), byte(count)}
	raw, err := mbap.Encode(mbap.ADU{Header: mbap.Header{TID: tid, UnitID: unit}, PDU: pdu})
	if err != nil {
		ex.Err = fmt.Errorf("encode FC 0x03 %d+%d: %w", addr, count, err)
		return ex
	}
	ex.Request = raw
	if derr := m.conn.SetDeadline(time.Now().Add(opDeadline)); derr != nil {
		ex.Err = fmt.Errorf("arm the %s operation deadline: %w", opDeadline, derr)
		return ex
	}
	if _, werr := m.conn.Write(raw); werr != nil {
		ex.Err = fmt.Errorf("write the request: %w", werr)
		return ex
	}
	ex.Response, ex.Err = readADU(m.conn)
	return ex
}

// readADU reads exactly one MBAP frame: the seven-byte header, then Length-1
// more bytes. It returns RAW BYTES rather than a decoded ADU because every
// assertion downstream is about the bytes, and it returns what it managed to
// read alongside the error because a malformed Length field is itself the
// finding.
func readADU(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("read the 7-byte MBAP header: %w", err)
	}
	length := binary.BigEndian.Uint16(hdr[4:6])
	if length < 2 || length > 254 {
		return hdr, fmt.Errorf("the MBAP Length field is %d, outside the legal 2..254", length)
	}
	body := make([]byte, int(length)-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return hdr, fmt.Errorf("read the %d-byte MBAP body: %w", len(body), err)
	}
	return append(hdr, body...), nil
}

// Registers validates one FC 0x03 exchange against the request it answers and
// returns the decoded registers.
//
// Every check here is a separate sentence in the error on purpose: "the read
// failed" is not an actionable statement, and a header defect, a wrong
// transaction id and a Modbus exception are three different findings about a
// device.
func Registers(ex Exchange, wantTID uint16, wantUnit uint8, wantCount uint16) ([]uint16, error) {
	if ex.Err != nil {
		return nil, ex.Err
	}
	if len(ex.Response) < 7 {
		return nil, fmt.Errorf("the response is %d byte(s); an MBAP ADU is at least 8", len(ex.Response))
	}
	tid := binary.BigEndian.Uint16(ex.Response[0:2])
	proto := binary.BigEndian.Uint16(ex.Response[2:4])
	length := binary.BigEndian.Uint16(ex.Response[4:6])
	unit := ex.Response[6]
	pdu := ex.Response[7:]

	switch {
	case tid != wantTID:
		return nil, fmt.Errorf("the response Transaction ID is 0x%04X, not the 0x%04X of the request it "+
			"answers", tid, wantTID)
	case proto != 0:
		return nil, fmt.Errorf("the response Protocol ID is 0x%04X, not the 0x0000 Modbus requires", proto)
	case unit != wantUnit:
		return nil, fmt.Errorf("the response Unit ID is %d, not the %d addressed", unit, wantUnit)
	case int(length) != len(pdu)+1:
		return nil, fmt.Errorf("the response Length field is %d but the frame carries %d PDU byte(s) plus "+
			"the unit id, which is %d", length, len(pdu), len(pdu)+1)
	case len(pdu) < 2:
		return nil, fmt.Errorf("the response PDU is %d byte(s)", len(pdu))
	}
	if pdu[0]&0x80 != 0 {
		return nil, fmt.Errorf("the DUT answered with Modbus exception %d (%s)", pdu[1], mbap.ExCode(pdu[1]))
	}
	if pdu[0] != fcReadHolding {
		return nil, fmt.Errorf("the response function code is 0x%02X, not the 0x03 of the request", pdu[0])
	}
	n := int(pdu[1])
	if n != int(wantCount)*2 {
		return nil, fmt.Errorf("the response byte count is %d, not the %d that %d register(s) occupy",
			n, wantCount*2, wantCount)
	}
	if len(pdu) < 2+n {
		return nil, fmt.Errorf("the response declares %d payload byte(s) but carries %d", n, len(pdu)-2)
	}
	out := make([]uint16, 0, n/2)
	for i := 2; i+1 < 2+n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(pdu[i:i+2]))
	}
	return out, nil
}

// requestTID recovers the transaction id from a request this package built, so
// Registers can be handed what to expect without the caller tracking it.
func requestTID(ex Exchange) uint16 {
	if len(ex.Request) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(ex.Request[0:2])
}

// readModel1 locates and reads the SunSpec Common Model on one unit.
//
// Three reads, and each is a separate step of the same sentence: the device
// identifies itself as SunSpec ("SunS" at base), the chain's first model header
// says which model and how long, and then Model 1's data block is read. A
// device whose marker is absent is not a device this read can be attempted on,
// and saying so is more useful than reading 66 registers of whatever is there.
func readModel1(mc *modbusConn, unit uint8, base uint16) ModelRead {
	m := ModelRead{Attempted: true, Unit: unit, Base: base}

	m.Marker = mc.readHolding(unit, base, 2, "SunSpec identifier")
	marker, err := Registers(m.Marker, requestTID(m.Marker), unit, 2)
	if err != nil {
		m.Err = fmt.Errorf("read the SunSpec identifier at %d on unit %d: %w", base, unit, err)
		return m
	}
	if marker[0] != sunsMagic0 || marker[1] != sunsMagic1 {
		m.Err = fmt.Errorf("unit %d has no SunSpec identifier at %d: read 0x%04X 0x%04X, want 0x%04X 0x%04X "+
			"(\"SunS\")", unit, base, marker[0], marker[1], sunsMagic0, sunsMagic1)
		return m
	}

	m.Header = mc.readHolding(unit, base+2, 2, "first model header")
	hdr, err := Registers(m.Header, requestTID(m.Header), unit, 2)
	if err != nil {
		m.Err = fmt.Errorf("read the first model header at %d: %w", base+2, err)
		return m
	}
	switch {
	case hdr[0] == endMarker:
		m.Err = fmt.Errorf("the chain at %d ends immediately: the header at %d is the 0x%04X end marker, so "+
			"there is no Common Model to read", base, base+2, endMarker)
		return m
	case hdr[0] != commonModelID:
		m.Err = fmt.Errorf("the first model in the chain is %d, not the Common Model 1 SunSpec requires "+
			"first", hdr[0])
		return m
	case hdr[1] == 0 || hdr[1] > 123:
		m.Err = fmt.Errorf("Model 1 declares a length of %d register(s), which no Common Model has", hdr[1])
		return m
	}
	m.Length = hdr[1]

	// The chain header is the authority on how long Model 1 is: read exactly
	// what the DUT declared, never a constant this package believes.
	m.Read = mc.readHolding(unit, base+4, m.Length, "SunSpec Common Model (Model 1)")
	values, err := Registers(m.Read, requestTID(m.Read), unit, m.Length)
	if err != nil {
		m.Err = fmt.Errorf("read Model 1's %d register(s) at %d: %w", m.Length, base+4, err)
		return m
	}
	m.Values = values
	return m
}

// findUnit locates a unit id that answers the SunSpec identifier read, so a
// caller need not know which of the gateway's slots is populated. It is bounded
// at eight because a scan is a diagnostic convenience, not a discovery
// protocol.
func findUnit(mc *modbusConn, base uint16) (uint8, ModelRead) {
	var last ModelRead
	for u := uint8(1); u <= 8; u++ {
		m := readModel1(mc, u, base)
		if m.Err == nil {
			return u, m
		}
		last = m
	}
	return 0, last
}
