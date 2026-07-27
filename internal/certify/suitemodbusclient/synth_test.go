package suitemodbusclient

// synth_test.go builds the synthetic bench these tests run against: a Modbus
// server that answers correctly, one that does not, and the Ethernet/IP/TCP
// frames carrying the exchange.
//
// The frames are real frames — they go through netdis's own dissector and
// reassembler — so the tests exercise the same path the live bench does, right
// down to a response that spans two TCP segments. That matters: a test that
// handed the parser a []byte would prove the parser works and prove nothing
// about whether a citation's byte offsets line up with the frames the bundle
// names.

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

const (
	tcpFIN = 0x001
	tcpSYN = 0x002
	tcpPSH = 0x008
	tcpACK = 0x010
	tcpRST = 0x004
)

var (
	benchServer = netip.MustParseAddrPort("69.0.0.20:5020")
	benchClient = netip.MustParseAddrPort("69.0.0.2:41234")
	baseTime    = time.Date(2026, 7, 26, 21, 0, 0, 0, time.UTC)
)

// ── Modbus message construction ───────────────────────────────────────────────

// mbap frames a PDU.
func mbap(txid uint16, unit uint8, pdu []byte) []byte {
	out := make([]byte, MBAPHeaderLen+len(pdu))
	binary.BigEndian.PutUint16(out[0:2], txid)
	binary.BigEndian.PutUint16(out[2:4], 0)
	binary.BigEndian.PutUint16(out[4:6], uint16(1+len(pdu)))
	out[6] = unit
	copy(out[7:], pdu)
	return out
}

// readReq builds an FC 0x03 request.
func readReq(txid uint16, unit uint8, start, qty uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = FCReadHoldingRegisters
	binary.BigEndian.PutUint16(pdu[1:3], start)
	binary.BigEndian.PutUint16(pdu[3:5], qty)
	return mbap(txid, unit, pdu)
}

// readRsp builds an FC 0x03 response.
func readRsp(txid uint16, unit uint8, regs []uint16) []byte {
	pdu := make([]byte, 2+2*len(regs))
	pdu[0] = FCReadHoldingRegisters
	pdu[1] = byte(2 * len(regs))
	for i, r := range regs {
		binary.BigEndian.PutUint16(pdu[2+2*i:], r)
	}
	return mbap(txid, unit, pdu)
}

// excRsp builds an exception response.
func excRsp(txid uint16, unit uint8, fc, code uint8) []byte {
	return mbap(txid, unit, []byte{fc | FCExceptionBit, code})
}

// writeSingleReq builds an FC 0x06 request (its response echoes it).
func writeSingleReq(txid uint16, unit uint8, addr, val uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = FCWriteSingleRegister
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	binary.BigEndian.PutUint16(pdu[3:5], val)
	return mbap(txid, unit, pdu)
}

// writeMultiReq builds an FC 0x10 request.
func writeMultiReq(txid uint16, unit uint8, addr uint16, vals []uint16) []byte {
	pdu := make([]byte, 6+2*len(vals))
	pdu[0] = FCWriteMultipleRegisters
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	binary.BigEndian.PutUint16(pdu[3:5], uint16(len(vals)))
	pdu[5] = byte(2 * len(vals))
	for i, v := range vals {
		binary.BigEndian.PutUint16(pdu[6+2*i:], v)
	}
	return mbap(txid, unit, pdu)
}

// writeMultiRsp builds an FC 0x10 acknowledgement.
func writeMultiRsp(txid uint16, unit uint8, addr, qty uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = FCWriteMultipleRegisters
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	binary.BigEndian.PutUint16(pdu[3:5], qty)
	return mbap(txid, unit, pdu)
}

// ── A synthetic SunSpec server image ──────────────────────────────────────────

// sunspecServer is a register image the synthetic exchanges read from.
type sunspecServer struct {
	base uint16
	regs map[uint16]uint16
}

// newSunSpecServer lays out a chain that exercises everything the suite looks
// at: the identifier, a Common Model with identity strings, a short model, a
// model longer than the 125-register read ceiling, and the end marker.
func newSunSpecServer(base uint16) *sunspecServer {
	s := &sunspecServer{base: base, regs: map[uint16]uint16{}}
	s.regs[base] = SunSHigh
	s.regs[base+1] = SunSLow
	addr := base + 2

	addr = s.addModel(addr, CommonModelID, 66, func(body uint16) {
		s.putString(body+0, 16, "LEXA Bench")
		s.putString(body+16, 16, "modsim")
		s.putString(body+40, 8, "1.1")
		s.putString(body+48, 16, "SN-SOLAR-001")
		s.regs[body+64] = 1
	})
	// A model whose body the client will not read: the ERR-3 step-over case.
	addr = s.addModel(addr, 712, 60, nil)
	// A model longer than the 125-register ceiling: the READ-2 chunking case.
	addr = s.addModel(addr, 701, 137, func(body uint16) {
		s.regs[body+8] = 1676     // a watt reading
		s.regs[body+120] = 0xFFFE // its scale factor, −2
	})
	s.regs[addr] = ModelChainEnd
	return s
}

// addModel writes a header and returns the address of the next header.
func (s *sunspecServer) addModel(addr, id, length uint16, fill func(body uint16)) uint16 {
	s.regs[addr] = id
	s.regs[addr+1] = length
	body := addr + 2
	for i := uint16(0); i < length; i++ {
		if _, ok := s.regs[body+i]; !ok {
			s.regs[body+i] = 0
		}
	}
	if fill != nil {
		fill(body)
	}
	return body + length
}

func (s *sunspecServer) putString(addr, regs uint16, v string) {
	b := make([]byte, 2*regs)
	copy(b, v)
	for i := uint16(0); i < regs; i++ {
		s.regs[addr+i] = binary.BigEndian.Uint16(b[2*i:])
	}
}

// read returns qty registers from start.
func (s *sunspecServer) read(start, qty uint16) []uint16 {
	out := make([]uint16, qty)
	for i := uint16(0); i < qty; i++ {
		out[i] = s.regs[start+i]
	}
	return out
}

// model returns a model's header address and length.
func (s *sunspecServer) model(id uint16) (headerAddr, length uint16, ok bool) {
	addr := s.base + 2
	for i := 0; i < 64; i++ {
		mid, okID := s.regs[addr]
		if !okID || mid == ModelChainEnd {
			return 0, 0, false
		}
		l := s.regs[addr+1]
		if mid == id {
			return addr, l, true
		}
		addr = addr + 2 + l
	}
	return 0, 0, false
}

// ── Exchange scripting ────────────────────────────────────────────────────────

// msg is one message to place on the synthetic wire.
type msg struct {
	fromClient bool
	payload    []byte
	// splitAt, when non-zero, delivers the payload in two TCP segments — the
	// PROT-2 case.
	splitAt int
	flags   uint16
	delayMs int
}

// script is a sequence of messages plus the connection's framing events.
type script struct {
	msgs   []msg
	noSYN  bool
	fin    bool
	rst    bool
	stepMs int
}

// clientReads scripts a well-behaved client: identifier probe, chain walk,
// Common Model read, and a >125-register model read in maximal chunks.
func conformantClientScript(s *sunspecServer) *script {
	sc := &script{stepMs: 5}
	tx := uint16(1)
	add := func(start, qty uint16) {
		sc.msgs = append(sc.msgs,
			msg{fromClient: true, payload: readReq(tx, 1, start, qty)},
			msg{payload: readRsp(tx, 1, s.read(start, qty))})
		tx++
	}
	// Identifier + first model header, as a client locating the map does.
	add(s.base, 4)
	// Walk the chain: read each header pair.
	addr := s.base + 2
	for i := 0; i < 8; i++ {
		id := s.regs[addr]
		if id == ModelChainEnd {
			add(addr, 2)
			break
		}
		l := s.regs[addr+1]
		add(addr, 2)
		switch id {
		case 712:
			// Deliberately NOT read: the ERR-3 step-over case.
		default:
			body := addr + 2
			for off := uint16(0); off < l; off += MaxReadQuantity {
				q := uint16(MaxReadQuantity)
				if l-off < q {
					q = l - off
				}
				add(body+off, q)
			}
		}
		addr = addr + 2 + l
	}
	return sc
}

// ── Frames ────────────────────────────────────────────────────────────────────

type synthFrame struct {
	src, dst netip.AddrPort
	seq      uint32
	flags    uint16
	payload  []byte
	at       time.Time
}

// bytes renders the frame as Ethernet / IPv4 / TCP. Checksums are left zero:
// netdis does not verify them, and computing them here would prove nothing.
func (f synthFrame) bytes() []byte {
	tcp := make([]byte, 20+len(f.payload))
	binary.BigEndian.PutUint16(tcp[0:2], f.src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], f.dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], f.seq)
	flags := f.flags
	if flags == 0 {
		flags = tcpPSH | tcpACK
	}
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|flags)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], f.payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], f.src.Addr().AsSlice())
	copy(ip[16:20], f.dst.Addr().AsSlice())
	copy(ip[20:], tcp)

	eth := make([]byte, 14+len(ip))
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)
	return eth
}

// renderScript turns a script into capture packets, starting at index start.
func renderScript(sc *script, client, server netip.AddrPort, t0 time.Time, startIndex int) []pcapng.Packet {
	var frames []synthFrame
	cseq, sseq := uint32(1000), uint32(5000)
	now := t0
	step := time.Duration(sc.stepMs) * time.Millisecond
	if step == 0 {
		step = 5 * time.Millisecond
	}
	if !sc.noSYN {
		frames = append(frames,
			synthFrame{src: client, dst: server, seq: cseq, flags: tcpSYN, at: now},
			synthFrame{src: server, dst: client, seq: sseq, flags: tcpSYN | tcpACK, at: now.Add(step)})
		cseq++
		sseq++
		now = now.Add(2 * step)
	}
	for _, m := range sc.msgs {
		src, dst := server, client
		seq := &sseq
		if m.fromClient {
			src, dst = client, server
			seq = &cseq
		}
		now = now.Add(step + time.Duration(m.delayMs)*time.Millisecond)
		parts := [][]byte{m.payload}
		if m.splitAt > 0 && m.splitAt < len(m.payload) {
			parts = [][]byte{m.payload[:m.splitAt], m.payload[m.splitAt:]}
		}
		for i, p := range parts {
			frames = append(frames, synthFrame{
				src: src, dst: dst, seq: *seq, flags: m.flags, payload: p,
				at: now.Add(time.Duration(i) * time.Millisecond)})
			*seq += uint32(len(p))
		}
	}
	if sc.fin {
		now = now.Add(step)
		frames = append(frames, synthFrame{src: server, dst: client, seq: sseq, flags: tcpFIN | tcpACK, at: now})
	}
	if sc.rst {
		now = now.Add(step)
		frames = append(frames, synthFrame{src: server, dst: client, seq: sseq, flags: tcpRST, at: now})
	}

	out := make([]pcapng.Packet, 0, len(frames))
	for i, f := range frames {
		data := f.bytes()
		out = append(out, pcapng.Packet{
			Index:    startIndex + i,
			Time:     f.at.UTC(),
			LinkType: netdis.LinkTypeEthernet,
			OrigLen:  len(data),
			Data:     data,
		})
	}
	return out
}

// conversationFrom assembles packets and builds the suite's Conversation from
// them, with everything owned — the shape a unit test wants.
func conversationFrom(t *testing.T, pkts []pcapng.Packet, client, server netip.AddrPort) *Conversation {
	t.Helper()
	return conversationOwned(t, pkts, client, server, nil)
}

// conversationOwned is conversationFrom with an ownership predicate, for the
// test that proves ADUs whose frames belong to another test case are dropped.
func conversationOwned(t *testing.T, pkts []pcapng.Packet, client, server netip.AddrPort,
	owns func(int) bool) *Conversation {
	t.Helper()
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		f, err := netdis.DecodePacket(p)
		if err != nil {
			t.Fatalf("frame %d does not dissect: %v", p.Index, err)
		}
		asm.AddFrame(f)
	}
	srvEP := netdis.Endpoint{Addr: server.Addr(), Port: server.Port()}
	cliEP := netdis.Endpoint{Addr: client.Addr(), Port: client.Port()}
	key := netdis.FlowKey{Src: cliEP, Dst: srvEP}.Stream()
	var st *netdis.Stream
	for _, s := range asm.Streams() {
		if s.Key == key {
			st = s
		}
	}
	if st == nil {
		t.Fatalf("no stream %s in the synthetic capture", key)
	}
	req := st.ByFlow(netdis.FlowKey{Src: cliEP, Dst: srvEP})
	rsp := st.ByFlow(netdis.FlowKey{Src: srvEP, Dst: cliEP})
	return buildConversation(req, rsp, server, client, owns)
}

// scriptConversation is the common case: render a script and build its
// conversation.
func scriptConversation(t *testing.T, sc *script) *Conversation {
	t.Helper()
	c, _ := scriptConversationWithTimes(t, sc)
	return c
}

// scriptConversationWithTimes additionally returns the frame-timestamp lookup
// the timeout logic takes, built from the packets actually rendered — so a test
// of "the client waited 9 seconds" waits nine synthetic seconds rather than
// asserting against a number the test itself made up.
func scriptConversationWithTimes(t *testing.T, sc *script) (*Conversation, func(int) (time.Time, bool)) {
	t.Helper()
	pkts := renderScript(sc, benchClient, benchServer, baseTime, 1)
	return conversationFrom(t, pkts, benchClient, benchServer), timesOf(pkts)
}

// timesOf maps a frame index to its capture timestamp.
func timesOf(pkts []pcapng.Packet) func(int) (time.Time, bool) {
	at := make(map[int]time.Time, len(pkts))
	for _, p := range pkts {
		at[p.Index] = p.Time
	}
	return func(f int) (time.Time, bool) {
		v, ok := at[f]
		return v, ok
	}
}

// verdictsOf extracts the verdicts of the findings whose claim contains sub.
func verdictsOf(fs []finding, sub string) []finding {
	var out []finding
	for _, f := range fs {
		if containsFold(f.Claim, sub) {
			out = append(out, f)
		}
	}
	return out
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	ls, lsub := lower(s), lower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return i
		}
	}
	return -1
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// only returns the single finding whose claim contains sub, failing otherwise.
func only(t *testing.T, fs []finding, sub string) finding {
	t.Helper()
	hits := verdictsOf(fs, sub)
	if len(hits) != 1 {
		var claims []string
		for _, f := range fs {
			claims = append(claims, f.Claim)
		}
		t.Fatalf("want exactly one finding matching %q, got %d; claims: %v", sub, len(hits), claims)
	}
	return hits[0]
}

// pcapBytes renders packets as a classic little-endian microsecond pcap file —
// what tcpdump -w produces and what the framework's capture reader reads back.
func pcapBytes(pkts []pcapng.Packet) []byte {
	buf := make([]byte, 0, 24+len(pkts)*128)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(netdis.LinkTypeEthernet))
	buf = append(buf, hdr...)
	for _, p := range pkts {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(p.Time.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(p.Time.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p.Data)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(p.OrigLen))
		buf = append(buf, rec...)
		buf = append(buf, p.Data...)
	}
	return buf
}
