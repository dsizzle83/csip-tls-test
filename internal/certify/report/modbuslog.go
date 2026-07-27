package report

// modbuslog.go implements §4 of SS-MODBUS-RESULTS-v1.2: the Detailed Test Logs.
//
// These are the archived half of a submission — never published, used by
// SunSpec only to confirm the results — and the requirement on them is
// absolute: "a log of ALL Modbus messages exchanged for each of the tests
// performed", in UNENCRYPTED form, as ascii hex, with connection information
// for Modbus TCP. A harness that filtered, de-duplicated or summarised the
// traffic would be non-conformant, which is why the entries this package emits
// are derived from the capture (see mbapscan.go) rather than from what the
// tool's own Modbus client believed it sent.
//
// Three JSON objects, and the document's own inconsistencies about them:
//
//	Test Log Object   {"tests": [...], "entries": [...]}
//	                  The prose still describes an optional context id; the v1.2
//	                  revision history says "Removed cid." and the contents table
//	                  lists only the two elements. cid is treated as vestigial
//	                  and is NOT emitted — the leftover prose is a doc defect,
//	                  not a schema.
//	Log Entry Object  {"time","type","msg"} or {"time","type","ipaddr","ipport"}
//	                  §4.1.2 is headed "Log Entry Object" while its JSON block is
//	                  captioned "Message Object"; they are the same thing.
//	Test Logs Object  {"logs": [...]}
//
// One representation choice the document contradicts itself on. `ipport` is
// described in prose as a String and printed in the worked example as a bare
// JSON number (502, unquoted): a strict validator would reject the document's
// own example. The emitter follows the EXAMPLE — a number — because the example
// is what an ingest written against this document will have been tested with,
// and the divergence is recorded in the readiness report rather than resolved
// silently.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Log entry types, §4.1.2. Lowercase, exactly as printed.
const (
	// EntryReq — a Modbus request.
	EntryReq = "req"
	// EntryResp — a Modbus response. An EXCEPTION response is also "resp":
	// there is no separate type for it, and it is recognised by the high bit
	// set on the function code.
	EntryResp = "resp"
	// EntryConn — a Modbus TCP connection initiation.
	EntryConn = "conn"
	// EntryDisc — a Modbus TCP connection termination.
	EntryDisc = "disc"
)

// ModbusEntryTypes is the closed enumeration of §4.1.2's `type`.
var ModbusEntryTypes = []string{EntryReq, EntryResp, EntryConn, EntryDisc}

// ModbusLogEntry is one Log Entry Object: a single Modbus message, or a single
// Modbus TCP connection event. Never a batch — §4.1.2 is explicit.
type ModbusLogEntry struct {
	// Time is a number of seconds. Second accuracy is a MUST; sub-second is
	// "ideally", which for any revert- or timeout-sensitive procedure is
	// effectively mandatory, so the emitter always writes millisecond decimals.
	// The epoch is not stated normatively anywhere in the document; every
	// example is Unix epoch, and Unix epoch is what is emitted.
	Time float64 `json:"time"`
	// Type is one of ModbusEntryTypes.
	Type string `json:"type"`
	// Msg is the COMPLETE Modbus message as an ascii hex string: MBAP header
	// included for TCP, CRC included for RTU, no 0x prefix, no separators.
	Msg string `json:"msg,omitempty"`
	// IPAddr and IPPort identify the Modbus TCP endpoint of a connection event.
	// The document does not say whose address it is; its example ("192.168.0.10"
	// with port 502) reads as the SERVER being connected to, and that is what
	// the emitter writes.
	IPAddr string `json:"ipaddr,omitempty"`
	IPPort int    `json:"ipport,omitempty"`
}

// ModbusTestLog is one Test Log Object: the message stream evidencing one or
// more named test procedures. The one-log-to-many-tests allowance is
// deliberate — §4.1.1 permits a single capture to be cited by several verdict
// rows — and is why Tests is a slice.
type ModbusTestLog struct {
	Tests   []string         `json:"tests"`
	Entries []ModbusLogEntry `json:"entries"`
}

// ModbusTestLogs is the Test Logs Object: many test logs in one archivable
// document.
type ModbusTestLogs struct {
	Logs []ModbusTestLog `json:"logs"`
}

// MarshalJSON is not overridden anywhere here: the field tags ARE the schema,
// and a hand-rolled encoder would be one more place for the emitted shape to
// drift from the documented one.

// JSON renders the Test Logs Object.
func (l *ModbusTestLogs) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: encode Modbus test logs: %w", err)
	}
	return append(data, '\n'), nil
}

// ParseModbusTestLogs reads a Test Logs Object back. Unknown fields are
// rejected: §4.1.2 describes no extension elements, and a log carrying one is a
// log whose meaning this tool does not fully represent.
func ParseModbusTestLogs(data []byte) (*ModbusTestLogs, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	out := &ModbusTestLogs{}
	if err := dec.Decode(out); err != nil {
		return nil, fmt.Errorf("report: parse Modbus test logs: %w", err)
	}
	return out, nil
}

// UnixTime renders a wall-clock instant as the §4.1.2 `time` value: Unix epoch
// seconds carrying millisecond decimals.
func UnixTime(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

// MBAP is a decoded Modbus TCP Application Protocol header plus its PDU, per
// §4.1.2 Figure 2.
type MBAP struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
	FunctionCode  uint8
	Data          []byte
	// Exception is true when the function code has its high bit set, which is
	// how the EXC-* family's evidence is recognised — there is no distinct log
	// entry type for an exception response.
	Exception bool
}

// String renders the header for an assertion's Observed field.
func (m MBAP) String() string {
	fc := fmt.Sprintf("FC 0x%02X", m.FunctionCode)
	if m.Exception {
		code := byte(0)
		if len(m.Data) > 0 {
			code = m.Data[0]
		}
		fc = fmt.Sprintf("EXCEPTION to FC 0x%02X, exception code %d", m.FunctionCode&0x7F, code)
	}
	return fmt.Sprintf("TxID 0x%04X ProtoID 0x%04X Length %d UnitID %d %s",
		m.TransactionID, m.ProtocolID, m.Length, m.UnitID, fc)
}

// DecodeMBAP parses a Modbus TCP frame and enforces §4.1.2's own consistency
// rule: the Length field counts the Unit ID, the Function Code and the Data.
// A frame whose Length disagrees is rejected rather than trimmed — the log's
// whole value is that the bytes are the bytes.
func DecodeMBAP(frame []byte) (MBAP, error) {
	if len(frame) < 8 {
		return MBAP{}, fmt.Errorf("report: %d-byte frame is too short for a 6-byte MBAP header "+
			"plus unit id and function code", len(frame))
	}
	m := MBAP{
		TransactionID: be16(frame[0:2]),
		ProtocolID:    be16(frame[2:4]),
		Length:        be16(frame[4:6]),
		UnitID:        frame[6],
		FunctionCode:  frame[7],
		Data:          frame[8:],
	}
	m.Exception = m.FunctionCode&0x80 != 0
	if want := int(m.Length) + 6; want != len(frame) {
		return MBAP{}, fmt.Errorf("report: MBAP Length field is %d, so the frame should be %d bytes, "+
			"but it is %d", m.Length, want, len(frame))
	}
	if m.ProtocolID != 0 {
		return m, fmt.Errorf("report: MBAP Protocol ID is 0x%04X; Modbus is 0x0000", m.ProtocolID)
	}
	return m, nil
}

// DecodeRTU parses a Modbus RTU frame per §4.1.2 Figure 1: Unit ID, Function
// Code, Data, CRC — no MBAP header, and the CRC is part of the logged message
// rather than stripped. The CRC is verified, since a log entry whose CRC does
// not match its own bytes cannot be a faithful record of a frame the device
// accepted.
func DecodeRTU(frame []byte) (unit, fc uint8, data []byte, err error) {
	if len(frame) < 4 {
		return 0, 0, nil, fmt.Errorf("report: %d-byte frame is too short for an RTU frame "+
			"(unit, function, 2-byte CRC)", len(frame))
	}
	body, crc := frame[:len(frame)-2], frame[len(frame)-2:]
	// Modbus RTU transmits the CRC low byte first.
	got := uint16(crc[0]) | uint16(crc[1])<<8
	if want := crc16Modbus(body); got != want {
		return 0, 0, nil, fmt.Errorf("report: RTU CRC is 0x%04X, computed 0x%04X", got, want)
	}
	return body[0], body[1], body[2:], nil
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// crc16Modbus is the standard Modbus RTU CRC-16 (polynomial 0xA001, reflected).
func crc16Modbus(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// HexMsg renders raw frame bytes as the §4.1.2 `msg` value.
//
// Upper case, because both worked examples are upper case and the document
// says nothing about case; no 0x prefix and no separators, because the examples
// have neither and the rule is "the binary representation converted to ascii
// hex values".
func HexMsg(frame []byte) string { return strings.ToUpper(hex.EncodeToString(frame)) }

// DecodeHexMsg is the inverse, rejecting anything that is not an even-length
// run of hex digits — a `msg` with a 0x prefix, a space, or an odd digit count
// does not decode to bytes and so cannot be the complete message the format
// requires.
func DecodeHexMsg(msg string) ([]byte, error) {
	if msg == "" {
		return nil, fmt.Errorf("report: msg is empty")
	}
	if len(msg)%2 != 0 {
		return nil, fmt.Errorf("report: msg has %d hex digits, which is not a whole number of bytes", len(msg))
	}
	b, err := hex.DecodeString(msg)
	if err != nil {
		return nil, fmt.Errorf("report: msg is not ascii hex: %w", err)
	}
	return b, nil
}

// Transport selects which framing a log's `msg` values are validated against.
type Transport string

// The two framings §4.1.2 draws.
const (
	// TransportTCP — MBAP header, no CRC (Figure 2).
	TransportTCP Transport = "Modbus TCP"
	// TransportRTU — unit id, function code, data, CRC (Figure 1).
	TransportRTU Transport = "Modbus RTU"
)

// ValidateModbusTestLogs applies every machine-checkable rule §4.1 states,
// returning one finding per violation and nothing when the document conforms.
//
// The rules, and the catalog case each one satisfies:
//
//	RPT-LOG-4   tests[] and entries[] present, tests non-empty
//	RPT-LOG-13  every entry carries time and type
//	RPT-LOG-7   type is one of req|resp|conn|disc
//	RPT-LOG-14  req/resp entries carry a non-empty msg
//	RPT-LOG-15  conn entries carry ipaddr and ipport; disc need not
//	RPT-LOG-6   time is a number in seconds with at least second accuracy
//	RPT-LOG-8   msg is ascii hex decoding to a complete Modbus message
//	RPT-LOG-10  a TCP msg carries a full MBAP header whose Length is consistent
//	RPT-LOG-9   an RTU msg carries no MBAP header and a correct trailing CRC
//	RPT-LOG-16  logs[] is the container element
func ValidateModbusTestLogs(l *ModbusTestLogs, tr Transport) []string {
	var f []string
	if l == nil || len(l.Logs) == 0 {
		return []string{"Test Logs Object carries no `logs` array (§4.1.3)"}
	}
	for i, log := range l.Logs {
		where := fmt.Sprintf("logs[%d]", i)
		if len(log.Tests) == 0 {
			f = append(f, where+": `tests` is empty; a log that names no test procedure evidences nothing (§4.1.1)")
		}
		for j, t := range log.Tests {
			if strings.TrimSpace(t) == "" {
				f = append(f, fmt.Sprintf("%s.tests[%d]: empty test name", where, j))
			}
		}
		if len(log.Entries) == 0 {
			f = append(f, where+": `entries` is empty (§4.1.1)")
		}
		f = append(f, validateEntries(where, log.Entries, tr)...)
	}
	sort.Strings(f)
	return f
}

func validateEntries(where string, entries []ModbusLogEntry, tr Transport) []string {
	var f []string
	for i, e := range entries {
		at := fmt.Sprintf("%s.entries[%d]", where, i)
		// RPT-LOG-13: time and type on every entry. A zero time is treated as
		// absent: the epoch is Unix, and 1970-01-01T00:00:00Z is not a moment
		// any conformance run happened at.
		if e.Time == 0 {
			f = append(f, at+": `time` is absent or zero (§4.1.2 requirement 1)")
		} else if e.Time < 0 {
			f = append(f, fmt.Sprintf("%s: `time` is negative (%v)", at, e.Time))
		}
		if e.Type == "" {
			f = append(f, at+": `type` is absent (§4.1.2 requirement 1)")
			continue
		}
		if !containsStr(ModbusEntryTypes, e.Type) {
			f = append(f, fmt.Sprintf("%s: `type` is %q, not one of %s",
				at, e.Type, strings.Join(ModbusEntryTypes, " | ")))
			continue
		}
		switch e.Type {
		case EntryReq, EntryResp:
			if e.Msg == "" {
				f = append(f, at+": a req/resp entry has no `msg` (§4.1.2 requirement 2)")
				continue
			}
			if e.IPAddr != "" || e.IPPort != 0 {
				f = append(f, at+": a message entry carries connection fields; §4.1.2's message "+
					"contents table lists only time, type and msg")
			}
			raw, err := DecodeHexMsg(e.Msg)
			if err != nil {
				f = append(f, fmt.Sprintf("%s: %v", at, err))
				continue
			}
			switch tr {
			case TransportRTU:
				if _, _, _, err := DecodeRTU(raw); err != nil {
					f = append(f, fmt.Sprintf("%s: %v", at, err))
				}
			default:
				if _, err := DecodeMBAP(raw); err != nil {
					f = append(f, fmt.Sprintf("%s: %v", at, err))
				}
			}
		case EntryConn:
			if e.IPAddr == "" {
				f = append(f, at+": a conn entry has no `ipaddr` (§4.1.2 requirement 3)")
			}
			if e.IPPort == 0 {
				f = append(f, at+": a conn entry has no `ipport` (§4.1.2 requirement 3)")
			}
			if e.Msg != "" {
				f = append(f, at+": a conn entry carries a `msg`")
			}
		case EntryDisc:
			if e.Msg != "" {
				f = append(f, at+": a disc entry carries a `msg`")
			}
		}
	}
	return f
}

func containsStr(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// PairTransactions matches req entries to resp entries by MBAP Transaction ID,
// in order. It is what turns a flat log into the exchange a reviewer reads, and
// it is also a check: an unmatched request or a response with no request means
// the log is missing a message the "ALL Modbus messages" rule required.
func PairTransactions(entries []ModbusLogEntry) (paired int, unmatched []string) {
	open := map[uint16]int{}
	for i, e := range entries {
		if e.Type != EntryReq && e.Type != EntryResp {
			continue
		}
		raw, err := DecodeHexMsg(e.Msg)
		if err != nil || len(raw) < 2 {
			unmatched = append(unmatched, fmt.Sprintf("entry %d: msg does not decode", i))
			continue
		}
		tx := be16(raw[0:2])
		if e.Type == EntryReq {
			open[tx]++
			continue
		}
		if open[tx] == 0 {
			unmatched = append(unmatched, fmt.Sprintf(
				"entry %d: response for transaction 0x%04X has no logged request", i, tx))
			continue
		}
		open[tx]--
		paired++
	}
	var stillOpen []int
	for tx, n := range open {
		for i := 0; i < n; i++ {
			stillOpen = append(stillOpen, int(tx))
		}
	}
	sort.Ints(stillOpen)
	for _, tx := range stillOpen {
		unmatched = append(unmatched, fmt.Sprintf("request for transaction 0x%04X has no logged response", tx))
	}
	return paired, unmatched
}
