package report

// mbapscan.go turns a reassembled TCP conversation into §4.1.2 Log Entry
// objects — and is the reason this suite is worth anything.
//
// The easy way to satisfy "the detailed test logs consist of a log of ALL
// Modbus messages exchanged" is to log what the harness's own Modbus client
// believes it sent and received. That log is well-formed, passes every schema
// check, and is not evidence: it describes the library's intent, not the wire.
// A retransmit, a coalesced segment, a byte the stack rewrote, a response the
// client timed out on and never saw — none of it appears, and none of it can be
// caught by anyone reading the submission.
//
// So the log is DERIVED FROM THE CAPTURE. Every entry this file produces
// carries the byte range of the reassembled stream it was decoded from and the
// frames those bytes arrived in, which lets a check cite exactly the bytes the
// log entry renders. The log and the pcap in the same submission cannot
// disagree, because the log is a rendering of the pcap.
//
// Two refusals worth stating, because both are places where producing SOMETHING
// would be worse than producing nothing:
//
//   - A direction whose capture began mid-connection is not framed at all. MBAP
//     has no self-synchronising delimiter, so the first captured byte is not
//     known to be a message boundary; framing from it would emit `msg` values
//     that decode to plausible nonsense.
//   - A trailing partial message is reported, not emitted. "The complete Modbus
//     message content" is the requirement; half of one is not a short message.

import (
	"fmt"
	"net/netip"
	"sort"

	"csip-tls-test/internal/evidence/netdis"
)

// ScannedEntry is one log entry together with the evidence it was derived from.
// The provenance fields are what a check turns into a citation.
type ScannedEntry struct {
	Entry ModbusLogEntry
	// Dir is the reassembled direction the message bytes came from; nil for
	// conn and disc entries, which are derived from TCP control frames and have
	// no stream bytes of their own.
	Dir *netdis.Direction
	// Start and End are the half-open byte range of Dir this entry renders.
	Start, End int
	// Frames are the capture frames those bytes arrived in, or the single
	// control frame behind a conn/disc entry.
	Frames []int
}

// ModbusScan is one conversation's derived log, plus everything the scanner
// noticed that a reader of the evidence needs to know.
type ModbusScan struct {
	// Stream is the conversation scanned.
	Stream *netdis.Stream
	// Server is the endpoint treated as the Modbus server, which decides which
	// direction is "req" and which is "resp".
	Server netip.AddrPort
	// Entries are in wire order.
	Entries []ScannedEntry
	// Problems are integrity findings: a mid-stream capture, a partial trailing
	// message, an MBAP header that does not describe its own frame. They are
	// reported rather than dropped, because each one means the log is NOT the
	// complete record §4 requires.
	Problems []string
}

// LogEntries returns just the JSON objects, for emission.
func (s *ModbusScan) LogEntries() []ModbusLogEntry {
	out := make([]ModbusLogEntry, len(s.Entries))
	for i, e := range s.Entries {
		out[i] = e.Entry
	}
	return out
}

// TestLog wraps the derived entries as a §4.1.1 Test Log Object naming the test
// procedures they evidence.
func (s *ModbusScan) TestLog(tests ...string) ModbusTestLog {
	return ModbusTestLog{Tests: tests, Entries: s.LogEntries()}
}

// Count returns how many entries of a given type were derived.
func (s *ModbusScan) Count(typ string) int {
	n := 0
	for _, e := range s.Entries {
		if e.Entry.Type == typ {
			n++
		}
	}
	return n
}

// First returns the first derived entry of a type, which is what a check cites
// when the criterion is about the SHAPE of an entry rather than about all of
// them.
func (s *ModbusScan) First(typ string) (ScannedEntry, bool) {
	for _, e := range s.Entries {
		if e.Entry.Type == typ {
			return e, true
		}
	}
	return ScannedEntry{}, false
}

// ScanModbus derives §4.1.2 log entries from one TCP conversation.
//
// frames is the run's dissected frame list; it is needed for the conn and disc
// entries, which are TCP control events and carry no stream bytes. Passing the
// whole list rather than a filtered one keeps the caller from having to know
// how a stream key is computed.
func ScanModbus(st *netdis.Stream, frames []*netdis.Frame, server netip.AddrPort) (*ModbusScan, error) {
	if st == nil {
		return nil, fmt.Errorf("report: ScanModbus with no stream")
	}
	client, srv := st.Dirs[0], st.Dirs[1]
	if endpointAddrPort(client.Flow.Dst) != server {
		client, srv = srv, client
	}
	if endpointAddrPort(client.Flow.Dst) != server {
		return nil, fmt.Errorf("report: neither direction of %s is addressed to the Modbus server %s",
			st.Key, server)
	}
	return ScanModbusStreams(st, frames, server,
		DirectionStream(client, frames), DirectionStream(srv, frames)), nil
}

// ScanModbusStreams derives §4.1.2 log entries from two PLAINTEXT directions
// that are not necessarily netdis directions — the decrypted halves of a Secure
// SunSpec Modbus session, typically.
//
// It is the Modbus counterpart of [ScanHTTPStreams], and exists for the same
// reason: §4 requires the log to carry "all Modbus messages in unencrypted
// form", and on this bench the Modbus under test rides mbaps. A scanner that
// could only frame a cleartext conversation would emit an empty log for every
// session that matters and leave the submission's most important artefact
// silently short.
//
// st and frames are still needed even when the payload came from a decrypted
// stream: the `conn` and `disc` entries are TCP control events, they are in the
// clear whatever rode above them, and they are what §4's "connection
// information … for Modbus TCP implementations" requires.
func ScanModbusStreams(st *netdis.Stream, frames []*netdis.Frame, server netip.AddrPort,
	clientToServer, serverToClient ByteStream) *ModbusScan {
	sc := &ModbusScan{Stream: st, Server: server}
	synFrame, finFrame := controlFrames(st, frames)

	// §4.1.1's connection entry. It is emitted only when the SYN was actually
	// captured: a conn record synthesised from the first data frame would put a
	// connection-initiation time in the log that nothing observed.
	if synFrame != nil {
		sc.Entries = append(sc.Entries, ScannedEntry{
			Entry: ModbusLogEntry{
				Time:   UnixTime(synFrame.Time),
				Type:   EntryConn,
				IPAddr: server.Addr().String(),
				IPPort: int(server.Port()),
			},
			Frames: []int{synFrame.Index},
		})
	} else {
		sc.Problems = append(sc.Problems, fmt.Sprintf(
			"no SYN was captured for %s, so no `conn` entry can be emitted: §4's connection information "+
				"for this session is missing from the log", st.Key))
	}

	sc.frame(clientToServer, EntryReq)
	sc.frame(serverToClient, EntryResp)

	if finFrame != nil {
		sc.Entries = append(sc.Entries, ScannedEntry{
			Entry:  ModbusLogEntry{Time: UnixTime(finFrame.Time), Type: EntryDisc},
			Frames: []int{finFrame.Index},
		})
	}

	// Wire order. Ties break on frame number, and then on type so a request
	// that shares a frame timestamp with its response still reads req-first.
	sort.SliceStable(sc.Entries, func(i, j int) bool {
		a, b := sc.Entries[i], sc.Entries[j]
		if a.Entry.Time != b.Entry.Time {
			return a.Entry.Time < b.Entry.Time
		}
		fa, fb := firstFrame(a.Frames), firstFrame(b.Frames)
		if fa != fb {
			return fa < fb
		}
		return typeRank(a.Entry.Type) < typeRank(b.Entry.Type)
	})
	return sc
}

func typeRank(t string) int {
	switch t {
	case EntryConn:
		return 0
	case EntryReq:
		return 1
	case EntryResp:
		return 2
	default:
		return 3
	}
}

func firstFrame(f []int) int {
	if len(f) == 0 {
		return 1 << 30
	}
	return f[0]
}

// frame walks one plaintext direction, emitting one entry per complete MBAP
// frame.
func (s *ModbusScan) frame(bs ByteStream, typ string) {
	if len(bs.Data) == 0 {
		return
	}
	if d := bs.Dir; d != nil {
		if d.MidStream {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s was captured mid-connection: its first captured byte is not known to be a "+
					"message boundary, so no `%s` entries were derived from it", bs.Label, typ))
			return
		}
		if !d.Complete() {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s is missing %d byte(s): a segment was never captured, so the messages after the "+
					"gap cannot be framed from the capture", bs.Label, d.PendingGap()))
			return
		}
	}
	data := bs.Data
	for off := 0; off < len(data); {
		if off+mbapHeaderLen > len(data) {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s ends with %d byte(s) that are shorter than an MBAP header; the log omits an "+
					"incomplete trailing message rather than emitting a partial one", bs.Label, len(data)-off))
			return
		}
		length := int(be16(data[off+4 : off+6]))
		end := off + mbapHeaderLen + length
		if length < 2 {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s: MBAP Length at stream offset %d is %d, which cannot cover a unit id and a "+
					"function code; framing stopped", bs.Label, off, length))
			return
		}
		if end > len(data) {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s: the message at stream offset %d claims %d bytes but only %d were captured; "+
					"the log omits it rather than emitting a truncated `msg`", bs.Label, off, end-off, len(data)-off),
			)
			return
		}
		raw := data[off:end]
		if _, err := DecodeMBAP(raw); err != nil {
			s.Problems = append(s.Problems, fmt.Sprintf("direction %s offset %d: %v", bs.Label, off, err))
			return
		}
		entry := ModbusLogEntry{Type: typ, Msg: HexMsg(raw)}
		_, at, ok := bs.At(off)
		if !ok {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s offset %d: no capture frame carries this byte, so the entry would have no "+
					"`time`; it was not emitted", bs.Label, off))
			return
		}
		entry.Time = UnixTime(at)
		pkts := []int{}
		if bs.Frames != nil {
			pkts = bs.Frames(off, end)
		}
		s.Entries = append(s.Entries, ScannedEntry{
			Entry: entry, Dir: bs.Dir, Start: off, End: end, Frames: pkts,
		})
		off = end
	}
}

// mbapHeaderLen is the fixed MBAP header: transaction id, protocol id, length.
const mbapHeaderLen = 6

// controlFrames finds the connection's SYN and its first FIN or RST.
func controlFrames(st *netdis.Stream, frames []*netdis.Frame) (syn, fin *netdis.Frame) {
	for _, f := range frames {
		if f.TCP == nil {
			continue
		}
		fl, ok := f.Flow()
		if !ok || fl.Stream() != st.Key {
			continue
		}
		if syn == nil && f.TCP.Flags.Has(netdis.SYN) && !f.TCP.Flags.Has(netdis.ACK) {
			syn = f
		}
		if fin == nil && (f.TCP.Flags.Has(netdis.FIN) || f.TCP.Flags.Has(netdis.RST)) {
			fin = f
		}
	}
	return syn, fin
}

func frameIndex(frames []*netdis.Frame) map[int]*netdis.Frame {
	m := make(map[int]*netdis.Frame, len(frames))
	for _, f := range frames {
		m[f.Index] = f
	}
	return m
}

func endpointAddrPort(e netdis.Endpoint) netip.AddrPort {
	return netip.AddrPortFrom(e.Addr.Unmap(), e.Port)
}
