package certify

// synth_test.go builds synthetic captures.
//
// The frame-attribution tests need a capture that looks like the real bench:
// the test's own connection INTERLEAVED with background traffic that was
// already flowing and keeps flowing — the 10-second southbound Modbus polls
// and the CSIP walk. Building it here, byte for byte, is what lets the tests
// assert the negative case that actually matters: that a check does not claim
// frames belonging to another conversation, even when those frames sit inside
// its time window.

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// synthFrame describes one packet to synthesise.
type synthFrame struct {
	src, dst netip.AddrPort
	seq      uint32
	flags    uint16
	payload  string
	at       time.Time
}

const (
	tcpFIN = 0x001
	tcpSYN = 0x002
	tcpACK = 0x010
	tcpPSH = 0x008
)

// bytes renders the frame as Ethernet / IPv4 / TCP. Checksums are left zero:
// netdis does not verify them (a capture is not a NIC), and computing them here
// would add a page of code that proves nothing about attribution.
func (s synthFrame) bytes() []byte {
	payload := []byte(s.payload)
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], s.src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], s.dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], s.seq)
	flags := s.flags
	if flags == 0 {
		flags = tcpPSH | tcpACK
	}
	// Data offset 5 (20 bytes) in the top nibble of byte 12, flags in 12..13.
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|flags)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6 // TCP
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

// writePcap writes packets as a classic little-endian microsecond pcap file,
// which is what tcpdump -w produces and what pcapng.Open reads back.
func writePcap(t *testing.T, path string, pkts []pcapng.Packet) {
	t.Helper()
	if err := os.WriteFile(path, pcapBytes(pkts), 0o644); err != nil {
		t.Fatalf("write synthetic capture: %v", err)
	}
}

// pcapBytes renders a classic pcap file in memory.
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

// dissect turns synthetic packets into the dissected frames attribute() takes.
func dissect(t *testing.T, pkts []pcapng.Packet) []*netdis.Frame {
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

func ap(s string) netip.AddrPort {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return a
}
