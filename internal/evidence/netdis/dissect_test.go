package netdis

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/pcapng"
)

// --- frame builders -------------------------------------------------------
//
// Everything below assembles frames from raw bytes rather than from a
// packet-crafting library, for the same reason the pcapng fixtures are
// hand-laid: a test that builds its input with the code under test proves only
// self-consistency.

func ethHdr(etherType uint16) []byte {
	h := make([]byte, 14)
	copy(h[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})  // dst
	copy(h[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}) // src
	binary.BigEndian.PutUint16(h[12:14], etherType)
	return h
}

func vlanTag(vid uint16, inner uint16) []byte {
	t := make([]byte, 4)
	binary.BigEndian.PutUint16(t[0:2], vid)
	binary.BigEndian.PutUint16(t[2:4], inner)
	return t
}

// ipv4Hdr builds an IPv4 header with optLen bytes of (no-op) options.
func ipv4Hdr(src, dst string, proto uint8, payloadLen, optLen int, fragFlags uint16) []byte {
	ihl := 20 + optLen
	h := make([]byte, ihl)
	h[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(h[2:4], uint16(ihl+payloadLen))
	binary.BigEndian.PutUint16(h[6:8], fragFlags)
	h[8] = 64 // TTL
	h[9] = proto
	copy(h[12:16], netip.MustParseAddr(src).AsSlice())
	copy(h[16:20], netip.MustParseAddr(dst).AsSlice())
	for i := 20; i < ihl; i++ {
		h[i] = 0x01 // NOP option
	}
	return h
}

func ipv6Hdr(src, dst string, next uint8, payloadLen int) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:6], uint16(payloadLen))
	h[6] = next
	h[7] = 64
	copy(h[8:24], netip.MustParseAddr(src).AsSlice())
	copy(h[24:40], netip.MustParseAddr(dst).AsSlice())
	return h
}

// tcpHdr builds a TCP header with optLen bytes of options.
func tcpHdr(sport, dport uint16, seq, ack uint32, flags TCPFlags, optLen int) []byte {
	off := 20 + optLen
	h := make([]byte, off)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint32(h[4:8], seq)
	binary.BigEndian.PutUint32(h[8:12], ack)
	h[12] = byte(off/4) << 4
	if flags&NS != 0 {
		h[12] |= 0x01
	}
	h[13] = byte(flags & 0xFF)
	binary.BigEndian.PutUint16(h[14:16], 0xFFFF)
	return h
}

func udpHdr(sport, dport uint16, payloadLen int) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], uint16(8+payloadLen))
	return h
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// --- tests ----------------------------------------------------------------

func TestDecodeLinkTypes(t *testing.T) {
	payload := []byte("mbaps-bytes")
	tcp := cat(tcpHdr(51422, 802, 1000, 1, PSH|ACK, 0), payload)
	ip4 := cat(ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 0), tcp)
	ip6 := cat(ipv6Hdr("fd00::14", "fd00::2", ipProtoTCP, len(tcp)), tcp)

	nullHdr := func(bo binary.ByteOrder, fam uint32) []byte {
		h := make([]byte, 4)
		bo.PutUint32(h, fam)
		return h
	}
	sllHdr := func(proto uint16) []byte {
		h := make([]byte, 16)
		binary.BigEndian.PutUint16(h[0:2], 0) // packet type: to us
		binary.BigEndian.PutUint16(h[2:4], 1) // ARPHRD_ETHER
		binary.BigEndian.PutUint16(h[4:6], 6)
		binary.BigEndian.PutUint16(h[14:16], proto)
		return h
	}
	sll2Hdr := func(proto uint16) []byte {
		h := make([]byte, 20)
		binary.BigEndian.PutUint16(h[0:2], proto)
		binary.BigEndian.PutUint32(h[4:8], 1) // ifindex
		binary.BigEndian.PutUint16(h[8:10], 1)
		h[10] = 0
		h[11] = 6
		return h
	}

	tests := []struct {
		name     string
		linkType uint16
		data     []byte
		wantSrc  string
		wantNet  NetProto
	}{
		{"ethernet ipv4", LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), ip4), "69.0.0.20", NetIPv4},
		{"ethernet ipv6", LinkTypeEthernet, cat(ethHdr(etherTypeIPv6), ip6), "fd00::14", NetIPv6},
		{"null little-endian AF_INET", LinkTypeNull, cat(nullHdr(binary.LittleEndian, 2), ip4), "69.0.0.20", NetIPv4},
		{"null big-endian AF_INET", LinkTypeNull, cat(nullHdr(binary.BigEndian, 2), ip4), "69.0.0.20", NetIPv4},
		{"null AF_INET6 (Linux 10)", LinkTypeNull, cat(nullHdr(binary.LittleEndian, 10), ip6), "fd00::14", NetIPv6},
		{"null AF_INET6 (macOS 30)", LinkTypeNull, cat(nullHdr(binary.LittleEndian, 30), ip6), "fd00::14", NetIPv6},
		{"openbsd loop", LinkTypeLoop, cat(nullHdr(binary.BigEndian, 2), ip4), "69.0.0.20", NetIPv4},
		{"raw ip v4", LinkTypeRaw, ip4, "69.0.0.20", NetIPv4},
		{"raw ip v6", LinkTypeRaw, ip6, "fd00::14", NetIPv6},
		{"linktype ipv4", LinkTypeIPv4, ip4, "69.0.0.20", NetIPv4},
		{"linktype ipv6", LinkTypeIPv6, ip6, "fd00::14", NetIPv6},
		{"linux sll", LinkTypeLinuxSLL, cat(sllHdr(etherTypeIPv4), ip4), "69.0.0.20", NetIPv4},
		{"linux sll2", LinkTypeSLL2, cat(sll2Hdr(etherTypeIPv6), ip6), "fd00::14", NetIPv6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Decode(tc.linkType, tc.data)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if f.Net != tc.wantNet {
				t.Fatalf("Net = %v, want %v (note %q)", f.Net, tc.wantNet, f.Note)
			}
			if f.Src.String() != tc.wantSrc {
				t.Errorf("Src = %v, want %v", f.Src, tc.wantSrc)
			}
			if f.TCP == nil {
				t.Fatalf("TCP not dissected (note %q)", f.Note)
			}
			if f.TCP.SrcPort != 51422 || f.TCP.DstPort != 802 {
				t.Errorf("ports = %d>%d, want 51422>802", f.TCP.SrcPort, f.TCP.DstPort)
			}
			if string(f.TCP.Payload) != "mbaps-bytes" {
				t.Errorf("payload = %q", f.TCP.Payload)
			}
			if !f.TCP.Flags.Has(PSH | ACK) {
				t.Errorf("flags = %v, want PSH|ACK", f.TCP.Flags)
			}
		})
	}
}

func TestDecodeStackedVLANs(t *testing.T) {
	payload := []byte("x")
	tcp := cat(tcpHdr(1, 802, 1, 0, ACK, 0), payload)
	ip4 := cat(ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 0), tcp)
	frame := cat(ethHdr(etherTypeQinQ), vlanTag(100, etherTypeVLAN), vlanTag(200, etherTypeIPv4), ip4)
	f, err := Decode(LinkTypeEthernet, frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(f.VLANs) != 2 || f.VLANs[0] != 100 || f.VLANs[1] != 200 {
		t.Fatalf("VLANs = %v, want [100 200]", f.VLANs)
	}
	if f.TCP == nil || string(f.TCP.Payload) != "x" {
		t.Fatalf("TCP payload not recovered through the VLAN stack (note %q)", f.Note)
	}
}

func TestDecodeIPv4Options(t *testing.T) {
	payload := []byte("with-options")
	tcp := cat(tcpHdr(51422, 802, 1, 0, PSH|ACK, 12 /* TCP options */), payload)
	ip4 := cat(ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 8 /* IPv4 options */, 0), tcp)
	f, err := Decode(LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), ip4))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.TCP == nil || string(f.TCP.Payload) != "with-options" {
		t.Fatalf("payload = %q, want it found past both option fields", f.TCP.Payload)
	}
	if f.TCP.HeaderLen != 32 || len(f.TCP.Options) != 12 {
		t.Errorf("TCP header len = %d, options = %d bytes; want 32 and 12", f.TCP.HeaderLen, len(f.TCP.Options))
	}
}

func TestDecodeIPv6ExtensionHeaders(t *testing.T) {
	payload := []byte("ext-hdr-payload")
	tcp := cat(tcpHdr(51422, 802, 1, 0, PSH|ACK, 0), payload)

	// Hop-by-hop (8 bytes) then destination options (16 bytes) then TCP.
	hop := make([]byte, 8)
	hop[0] = ipv6DestOpts
	hop[1] = 0 // (0+1)*8 = 8 bytes
	dst := make([]byte, 16)
	dst[0] = ipProtoTCP
	dst[1] = 1 // (1+1)*8 = 16 bytes

	body := cat(hop, dst, tcp)
	frame := cat(ethHdr(etherTypeIPv6), ipv6Hdr("fd00::14", "fd00::2", ipv6HopByHop, len(body)), body)
	f, err := Decode(LinkTypeEthernet, frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.TCP == nil {
		t.Fatalf("TCP not found past the extension chain (note %q)", f.Note)
	}
	if string(f.TCP.Payload) != "ext-hdr-payload" {
		t.Errorf("payload = %q", f.TCP.Payload)
	}
}

func TestDecodeFragmentsAreFlaggedNotParsed(t *testing.T) {
	payload := []byte("first-fragment-of-a-tcp-segment")
	tcp := cat(tcpHdr(51422, 802, 1, 0, PSH|ACK, 0), payload)

	t.Run("ipv4 more-fragments", func(t *testing.T) {
		ip4 := cat(ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 0x2000), tcp)
		f, err := Decode(LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), ip4))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !f.Fragmented {
			t.Fatal("Fragmented not set on an MF datagram")
		}
		if f.TCP != nil {
			t.Fatal("a fragment must not be dissected as a complete TCP segment")
		}
		if !strings.Contains(f.Note, "not reassembled") {
			t.Errorf("Note = %q, want it to explain the skip", f.Note)
		}
	})

	t.Run("ipv4 non-zero offset", func(t *testing.T) {
		ip4 := cat(ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 185), tcp)
		f, err := Decode(LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), ip4))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !f.Fragmented || f.FragOffset != 185*8 {
			t.Fatalf("Fragmented=%t FragOffset=%d, want true and %d", f.Fragmented, f.FragOffset, 185*8)
		}
	})

	t.Run("ipv6 fragment header", func(t *testing.T) {
		frag := make([]byte, 8)
		frag[0] = ipProtoTCP
		binary.BigEndian.PutUint16(frag[2:4], 0x0001) // offset 0, more=1
		body := cat(frag, tcp)
		frame := cat(ethHdr(etherTypeIPv6), ipv6Hdr("fd00::14", "fd00::2", ipv6Fragment, len(body)), body)
		f, err := Decode(LinkTypeEthernet, frame)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !f.Fragmented || f.TCP != nil {
			t.Fatalf("Fragmented=%t TCP=%v, want true and nil", f.Fragmented, f.TCP)
		}
	})
}

func TestDecodeNonIPIsNotAnError(t *testing.T) {
	arp := cat(ethHdr(0x0806), make([]byte, 28))
	f, err := Decode(LinkTypeEthernet, arp)
	if err != nil {
		t.Fatalf("ARP must dissect cleanly as a non-IP frame, got %v", err)
	}
	if f.Net != NetNone || f.TCP != nil {
		t.Fatalf("Net = %v, TCP = %v; want none and nil", f.Net, f.TCP)
	}
	if !strings.Contains(f.Note, "0x0806") {
		t.Errorf("Note = %q, want it to name the ethertype", f.Note)
	}
}

func TestDecodeUDP(t *testing.T) {
	payload := []byte("dns-sd")
	udp := cat(udpHdr(5353, 5353, len(payload)), payload)
	ip4 := cat(ipv4Hdr("69.0.0.20", "224.0.0.251", ipProtoUDP, len(udp), 0, 0), udp)
	f, err := Decode(LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), ip4))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.UDP == nil || string(f.UDP.Payload) != "dns-sd" {
		t.Fatalf("UDP = %+v", f.UDP)
	}
	flow, ok := f.Flow()
	if !ok || flow.Src.Port != 5353 {
		t.Fatalf("Flow = %v, ok = %t", flow, ok)
	}
}

func TestDecodeMalformed(t *testing.T) {
	tcp := cat(tcpHdr(51422, 802, 1, 0, ACK, 0), []byte("x"))
	good := cat(ethHdr(etherTypeIPv4), ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 0), tcp)

	tests := []struct {
		name     string
		linkType uint16
		data     []byte
		wantErr  string
	}{
		{"short ethernet header", LinkTypeEthernet, make([]byte, 10), "too short for a 14-byte Ethernet header"},
		{"short loopback header", LinkTypeNull, make([]byte, 3), "too short for a 4-byte loopback header"},
		{"short sll header", LinkTypeLinuxSLL, make([]byte, 12), "too short for a 16-byte Linux SLL header"},
		{"short sll2 header", LinkTypeSLL2, make([]byte, 12), "too short for a 20-byte Linux SLL2 header"},
		{"empty raw frame", LinkTypeRaw, nil, "raw-IP frame is empty"},
		{"short ipv4 header", LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), make([]byte, 12)), "too short for a 20-byte IPv4 header"},
		{"short ipv6 header", LinkTypeEthernet, cat(ethHdr(etherTypeIPv6), make([]byte, 20)), "too short for a 40-byte IPv6 header"},
		{
			name:     "ipv4 header length below minimum",
			linkType: LinkTypeEthernet,
			data: func() []byte {
				d := append([]byte(nil), good...)
				d[14] = 0x44 // version 4, IHL 4 (=16 bytes)
				return d
			}(),
			wantErr: "below the 20-byte minimum",
		},
		{
			name:     "ipv4 header length past the captured bytes",
			linkType: LinkTypeEthernet,
			data:     cat(ethHdr(etherTypeIPv4), []byte{0x4F}, make([]byte, 19)),
			wantErr:  "exceeds the 20 captured bytes",
		},
		{
			name:     "ipv4 version nibble is not 4",
			linkType: LinkTypeEthernet,
			data: func() []byte {
				d := append([]byte(nil), good...)
				d[14] = 0x55
				return d
			}(),
			wantErr: "carries version 5",
		},
		{
			name:     "tcp data offset below minimum",
			linkType: LinkTypeEthernet,
			data: func() []byte {
				d := append([]byte(nil), good...)
				d[14+20+12] = 0x30 // offset 3 words = 12 bytes
				return d
			}(),
			wantErr: "below the 20-byte minimum",
		},
		{"short tcp header", LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, 8, 0, 0), make([]byte, 8)), "too short for a 20-byte TCP header"},
		{"short udp header", LinkTypeEthernet, cat(ethHdr(etherTypeIPv4), ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoUDP, 4, 0, 0), make([]byte, 4)), "too short for an 8-byte UDP header"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.linkType, tc.data)
			if err == nil {
				t.Fatalf("want an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestDecodeTruncationSweep chops a good frame at every offset and demands that
// the dissector either parses a coherent prefix or errors — never panics. The
// dissector runs over attacker-influenced captures, so this is a hard contract.
func TestDecodeTruncationSweep(t *testing.T) {
	tcp := cat(tcpHdr(51422, 802, 1, 0, PSH|ACK, 8), []byte("payload-bytes"))
	frames := map[uint16][]byte{
		LinkTypeEthernet: cat(ethHdr(etherTypeIPv4), ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 4, 0), tcp),
		LinkTypeIPv6:     cat(ipv6Hdr("fd00::14", "fd00::2", ipProtoTCP, len(tcp)), tcp),
		LinkTypeSLL2:     cat(make([]byte, 20), ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 0), tcp),
	}
	for lt, full := range frames {
		for n := 0; n <= len(full); n++ {
			f, err := Decode(lt, full[:n])
			if err != nil {
				continue
			}
			if f.TCP != nil && len(f.TCP.Payload) > len(full) {
				t.Fatalf("link %d prefix %d: payload longer than the frame", lt, n)
			}
		}
	}
}

func TestFlowAndStreamKeys(t *testing.T) {
	a := Endpoint{Addr: netip.MustParseAddr("69.0.0.20"), Port: 51422}
	b := Endpoint{Addr: netip.MustParseAddr("69.0.0.2"), Port: 802}

	fwd := FlowKey{Src: a, Dst: b}
	rev := fwd.Reverse()
	if fwd.Stream() != rev.Stream() {
		t.Fatalf("both directions must canonicalise to one stream: %v vs %v", fwd.Stream(), rev.Stream())
	}
	s := fwd.Stream()
	// 69.0.0.2 sorts before 69.0.0.20, so it is the A side.
	if s.A != b || s.B != a {
		t.Fatalf("canonical order = %v, want the lower address first", s)
	}
	if got, want := s.String(), "69.0.0.2:802 <> 69.0.0.20:51422"; got != want {
		t.Errorf("StreamKey.String() = %q, want %q", got, want)
	}
	if s.DirIndex(fwd) != 1 || s.DirIndex(rev) != 0 {
		t.Errorf("DirIndex mismatch: fwd=%d rev=%d", s.DirIndex(fwd), s.DirIndex(rev))
	}
	if s.Flow(0) != rev || s.Flow(1) != fwd {
		t.Errorf("Flow round-trip mismatch")
	}
	if got, want := fwd.String(), "69.0.0.20:51422 > 69.0.0.2:802"; got != want {
		t.Errorf("FlowKey.String() = %q, want %q", got, want)
	}

	v6 := Endpoint{Addr: netip.MustParseAddr("fd00::2"), Port: 802}
	if got, want := v6.String(), "[fd00::2]:802"; got != want {
		t.Errorf("IPv6 endpoint = %q, want %q", got, want)
	}
}

func TestDecodePacketCarriesCaptureMetadata(t *testing.T) {
	tcp := cat(tcpHdr(51422, 802, 1, 0, ACK, 0), []byte("x"))
	data := cat(ethHdr(etherTypeIPv4), ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 0), tcp)
	p := pcapng.Packet{Index: 77, Time: time.Unix(1700000000, 0).UTC(), LinkType: LinkTypeEthernet, Data: data, OrigLen: len(data) + 40}
	f, err := DecodePacket(p)
	if err != nil {
		t.Fatalf("DecodePacket: %v", err)
	}
	if f.Index != 77 {
		t.Errorf("Index = %d, want 77", f.Index)
	}
	if !f.Truncated {
		t.Error("a snaplen-truncated packet must carry Truncated")
	}
	if !f.Time.Equal(p.Time) {
		t.Errorf("Time = %v, want %v", f.Time, p.Time)
	}

	bad := pcapng.Packet{Index: 78, LinkType: LinkTypeEthernet, Data: []byte{1, 2, 3}}
	if _, err := DecodePacket(bad); err == nil || !strings.Contains(err.Error(), "frame 78") {
		t.Fatalf("err = %v, want it to name frame 78", err)
	}
}
