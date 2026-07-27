package report

// synth_test.go builds synthetic captures for the scanner and check tests.
//
// The scanners' whole value is that they render what was on the wire, so the
// tests have to be able to put arbitrary bytes on a synthetic wire — including
// the awkward cases a real bench rarely produces on demand: a message split
// across two segments, a capture that began mid-connection, a stream that ends
// half way through a frame. Building the packets here, byte for byte, is what
// makes those cases reachable.

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
	tcpRST = 0x004
	tcpPSH = 0x008
	tcpACK = 0x010
)

// synthFrame describes one packet to synthesise.
type synthFrame struct {
	src, dst netip.AddrPort
	seq      uint32
	flags    uint16
	payload  []byte
	at       time.Time
}

// bytes renders the frame as Ethernet / IPv4 / TCP. Checksums are left zero:
// netdis does not verify them (a capture is not a NIC).
func (s synthFrame) bytes() []byte {
	tcp := make([]byte, 20+len(s.payload))
	binary.BigEndian.PutUint16(tcp[0:2], s.src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], s.dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], s.seq)
	flags := s.flags
	if flags == 0 {
		flags = tcpPSH | tcpACK
	}
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|flags)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], s.payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], s.src.Addr().AsSlice())
	copy(ip[16:20], s.dst.Addr().AsSlice())
	copy(ip[20:], tcp)

	eth := make([]byte, 14+len(ip))
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)
	return eth
}

// synthPackets turns frame specs into pcapng.Packets with 1-based indices.
func synthPackets(specs []synthFrame) []pcapng.Packet {
	out := make([]pcapng.Packet, 0, len(specs))
	for i, s := range specs {
		data := s.bytes()
		out = append(out, pcapng.Packet{
			Index:    i + 1,
			Time:     s.at.UTC(),
			LinkType: netdis.LinkTypeEthernet,
			OrigLen:  len(data),
			Data:     data,
		})
	}
	return out
}

func dissectAll(t *testing.T, pkts []pcapng.Packet) []*netdis.Frame {
	t.Helper()
	out := make([]*netdis.Frame, 0, len(pkts))
	for _, p := range pkts {
		f, err := netdis.DecodePacket(p)
		if err != nil {
			t.Fatalf("frame %d does not dissect: %v", p.Index, err)
		}
		out = append(out, f)
	}
	return out
}

func assemble(frames []*netdis.Frame) []*netdis.Stream {
	asm := netdis.NewAssembler()
	for _, f := range frames {
		asm.AddFrame(f)
	}
	return asm.Streams()
}

func ap(s string) netip.AddrPort {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return a
}

// session builds a complete client/server TCP conversation carrying the given
// payloads, in the order given: a SYN, a SYN-ACK, then one frame per payload,
// then a FIN.
type exchange struct {
	fromClient bool
	payload    []byte
}

func session(client, server netip.AddrPort, base time.Time, xs []exchange, closeIt bool) []pcapng.Packet {
	return sessionStep(client, server, base, 37*time.Millisecond, xs, closeIt)
}

// sessionStep is session with an explicit inter-frame interval, for tests whose
// frames must land inside a certify window plus its attribution guard.
func sessionStep(client, server netip.AddrPort, base time.Time, step time.Duration, xs []exchange, closeIt bool) []pcapng.Packet {
	var specs []synthFrame
	cseq, sseq := uint32(1000), uint32(9000)
	at := base
	tick := func() time.Time { at = at.Add(step); return at }

	specs = append(specs,
		synthFrame{src: client, dst: server, seq: cseq, flags: tcpSYN, at: tick()},
		synthFrame{src: server, dst: client, seq: sseq, flags: tcpSYN | tcpACK, at: tick()},
	)
	cseq++
	sseq++
	for _, x := range xs {
		if x.fromClient {
			specs = append(specs, synthFrame{src: client, dst: server, seq: cseq, payload: x.payload, at: tick()})
			cseq += uint32(len(x.payload))
			continue
		}
		specs = append(specs, synthFrame{src: server, dst: client, seq: sseq, payload: x.payload, at: tick()})
		sseq += uint32(len(x.payload))
	}
	if closeIt {
		specs = append(specs, synthFrame{src: client, dst: server, seq: cseq, flags: tcpFIN | tcpACK, at: tick()})
	}
	return synthPackets(specs)
}
