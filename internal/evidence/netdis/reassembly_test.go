package netdis

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/pcapng"
)

var (
	epDesktop = Endpoint{Addr: netip.MustParseAddr("69.0.0.20"), Port: 51422}
	epGateway = Endpoint{Addr: netip.MustParseAddr("69.0.0.2"), Port: 802}
)

// seg describes one TCP segment to feed the reassembler. seq is absolute, so a
// test can place a stream anywhere in the 32-bit sequence space — which is how
// the wraparound cases are written.
type seg struct {
	pkt   int
	seq   uint32
	data  string
	flags TCPFlags
	rev   bool // gateway → desktop instead of desktop → gateway
}

func (s seg) frame() *Frame {
	src, dst := epDesktop, epGateway
	if s.rev {
		src, dst = epGateway, epDesktop
	}
	flags := s.flags
	if flags == 0 {
		flags = PSH | ACK
	}
	return &Frame{
		Index:    s.pkt,
		Time:     time.Unix(1_700_000_000, int64(s.pkt)*1_000_000).UTC(),
		LinkType: LinkTypeEthernet,
		Net:      NetIPv4,
		Src:      src.Addr,
		Dst:      dst.Addr,
		IPProto:  ipProtoTCP,
		TCP: &TCPSegment{
			SrcPort: src.Port,
			DstPort: dst.Port,
			Seq:     s.seq,
			Flags:   flags,
			Payload: []byte(s.data),
		},
	}
}

func feed(t *testing.T, segs []seg) *Stream {
	t.Helper()
	a := NewAssembler()
	for _, s := range segs {
		a.AddFrame(s.frame())
	}
	streams := a.Streams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	return streams[0]
}

// forward returns the desktop → gateway direction of a stream.
func forward(s *Stream) *Direction { return s.Dir(epDesktop) }

const isn = uint32(0x1000_0000)

func TestReassembly(t *testing.T) {
	tests := []struct {
		name string
		segs []seg

		want         string
		wantRetrans  int
		wantOOO      int
		wantOverlaps int
		wantConflict bool
		wantPending  int
		// offset → frame index that must be reported for that byte
		wantOwner map[int]int
	}{
		{
			name: "in order with a SYN",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "hello "},
				{pkt: 3, seq: isn + 7, data: "world"},
			},
			want:      "hello world",
			wantOwner: map[int]int{0: 2, 5: 2, 6: 3, 10: 3},
		},
		{
			name: "out of order, gap fills later",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "AAAA"},
				{pkt: 3, seq: isn + 9, data: "CCCC"}, // arrives before B
				{pkt: 4, seq: isn + 5, data: "BBBB"},
			},
			want:      "AAAABBBBCCCC",
			wantOOO:   1,
			wantOwner: map[int]int{0: 2, 4: 4, 8: 3},
		},
		{
			name: "two segments buffered out of order, delivered in one flush",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 9, data: "CCCC"},
				{pkt: 3, seq: isn + 5, data: "BBBB"},
				{pkt: 4, seq: isn + 1, data: "AAAA"},
			},
			want:      "AAAABBBBCCCC",
			wantOOO:   2,
			wantOwner: map[int]int{0: 4, 4: 3, 8: 2},
		},
		{
			name: "exact retransmission is dropped",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "PAYLOAD"},
				{pkt: 3, seq: isn + 1, data: "PAYLOAD"}, // duplicate
				{pkt: 4, seq: isn + 8, data: "-tail"},
			},
			want:         "PAYLOAD-tail",
			wantRetrans:  1,
			wantOverlaps: 1,
			wantOwner:    map[int]int{0: 2, 7: 4},
		},
		{
			name: "partial retransmission delivers only the new tail",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "ABCD"},
				{pkt: 3, seq: isn + 3, data: "CDEF"}, // 2 bytes already seen, 2 new
			},
			want:         "ABCDEF",
			wantOverlaps: 1,
			wantOwner:    map[int]int{0: 2, 3: 2, 4: 3},
		},
		{
			name: "overlapping segment with DIFFERENT bytes keeps the first writer and flags a conflict",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "ABCD"},
				{pkt: 3, seq: isn + 3, data: "XXEF"}, // claims C,D as X,X
			},
			want:         "ABCDEF",
			wantOverlaps: 1,
			wantConflict: true,
			wantOwner:    map[int]int{2: 2, 4: 3},
		},
		{
			name: "overlap between two BUFFERED segments is resolved first-writer-wins",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 5, data: "BBBB"}, // buffered behind a gap
				{pkt: 3, seq: isn + 7, data: "ZZCC"}, // overlaps the buffered BB
				{pkt: 4, seq: isn + 1, data: "AAAA"}, // fills the gap
			},
			want:         "AAAABBBBCC",
			wantOOO:      2,
			wantOverlaps: 1,
			wantConflict: true,
			wantOwner:    map[int]int{4: 2, 8: 3},
		},
		{
			name: "segment fully inside a buffered segment is dropped entirely",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 5, data: "BBBBBBBB"},
				{pkt: 3, seq: isn + 7, data: "BB"}, // wholly covered, identical
				{pkt: 4, seq: isn + 1, data: "AAAA"},
			},
			want:         "AAAABBBBBBBB",
			wantOOO:      1, // the covered segment contributed nothing, so it is not counted twice
			wantRetrans:  1,
			wantOverlaps: 1,
		},
		{
			name: "segment straddling a buffered segment is split into both gaps",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 5, data: "MMMM"},         // middle, buffered
				{pkt: 3, seq: isn + 1, data: "LLLLMMMMRRRR"}, // covers left, middle, right
			},
			want: "LLLLMMMMRRRR",
			// Only the middle segment arrived ahead of a gap; the straddling
			// one starts exactly at the delivery edge, so it is in order.
			wantOOO:      1,
			wantOverlaps: 1,
			// The middle four bytes must still be attributed to the first writer.
			wantOwner: map[int]int{0: 3, 4: 2, 8: 3},
		},
		{
			name: "missing segment leaves the stream short and the gap pending",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "AAAA"},
				{pkt: 3, seq: isn + 9, data: "CCCC"}, // B never arrives
			},
			want:        "AAAA",
			wantOOO:     1,
			wantPending: 4,
		},
		{
			name: "sequence numbers wrap around zero",
			segs: []seg{
				// ISN 0xFFFFFFF0 ⇒ first data byte at 0xFFFFFFF1; the 17-byte
				// segment runs off the top of the sequence space and the stream
				// continues at 0x00000002.
				{pkt: 1, seq: 0xFFFF_FFF0, flags: SYN},
				{pkt: 2, seq: 0xFFFF_FFF1, data: "before-the-wrap.."},
				{pkt: 3, seq: 0x0000_0002, data: "..across-zero.."},
				{pkt: 4, seq: 0x0000_0011, data: "after"},
			},
			want:      "before-the-wrap....across-zero..after",
			wantOwner: map[int]int{0: 2, 17: 3, 32: 4},
		},
		{
			name: "out-of-order across the wrap point",
			segs: []seg{
				{pkt: 1, seq: 0xFFFF_FFF0, flags: SYN},
				{pkt: 2, seq: 0x0000_0001, data: "SECOND"}, // 16 bytes into the stream
				{pkt: 3, seq: 0xFFFF_FFF1, data: "FIRST-BLOCK-BYTE"},
			},
			want:      "FIRST-BLOCK-BYTESECOND",
			wantOOO:   1,
			wantOwner: map[int]int{0: 3, 16: 2},
		},
		{
			name: "capture starts mid-connection",
			segs: []seg{
				{pkt: 9, seq: 0x2000_0000, data: "mid-stream"},
				{pkt: 10, seq: 0x2000_000A, data: "-continues"},
			},
			want:      "mid-stream-continues",
			wantOwner: map[int]int{0: 9, 10: 10},
		},
		{
			name: "pure ACKs and a FIN carry no bytes",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, flags: ACK},
				{pkt: 3, seq: isn + 1, data: "data"},
				{pkt: 4, seq: isn + 5, flags: FIN | ACK},
			},
			want: "data",
		},
		{
			name: "retransmitted SYN does not reset the stream",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "first"},
				{pkt: 3, seq: isn, flags: SYN}, // duplicate SYN
				{pkt: 4, seq: isn + 6, data: "second"},
			},
			want: "firstsecond",
		},
		{
			name: "segment implausibly far out of window is counted, not buffered",
			segs: []seg{
				{pkt: 1, seq: isn, flags: SYN},
				{pkt: 2, seq: isn + 1, data: "kept"},
				{pkt: 3, seq: isn + 1 + (1 << 31), data: "wild"},
				{pkt: 4, seq: isn + 5, data: "-more"},
			},
			want: "kept-more",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := feed(t, tc.segs)
			d := forward(st)
			if got := string(d.Bytes.Bytes()); got != tc.want {
				t.Fatalf("stream = %q, want %q", got, tc.want)
			}
			if d.Retransmits != tc.wantRetrans {
				t.Errorf("Retransmits = %d, want %d", d.Retransmits, tc.wantRetrans)
			}
			if d.OutOfOrder != tc.wantOOO {
				t.Errorf("OutOfOrder = %d, want %d", d.OutOfOrder, tc.wantOOO)
			}
			if len(d.Overlaps) != tc.wantOverlaps {
				t.Errorf("Overlaps = %d (%v), want %d", len(d.Overlaps), d.Overlaps, tc.wantOverlaps)
			}
			if d.HasConflictingOverlap() != tc.wantConflict {
				t.Errorf("HasConflictingOverlap = %t, want %t (%v)", d.HasConflictingOverlap(), tc.wantConflict, d.Overlaps)
			}
			if d.PendingGap() != tc.wantPending {
				t.Errorf("PendingGap = %d, want %d", d.PendingGap(), tc.wantPending)
			}
			if (tc.wantPending == 0) != d.Complete() {
				t.Errorf("Complete = %t with %d pending bytes", d.Complete(), d.PendingGap())
			}
			for off, wantPkt := range tc.wantOwner {
				if got := d.Bytes.OffsetToPacket(off); got != wantPkt {
					t.Errorf("OffsetToPacket(%d) = %d, want %d", off, got, wantPkt)
				}
			}
		})
	}
}

// TestOutOfWindowSegmentIsNotDelivered pins the specific counter, because the
// table above only asserts the resulting bytes.
func TestOutOfWindowSegmentIsNotDelivered(t *testing.T) {
	st := feed(t, []seg{
		{pkt: 1, seq: isn, flags: SYN},
		{pkt: 2, seq: isn + 1, data: "kept"},
		{pkt: 3, seq: isn + 1 + (1 << 31), data: "wild"},
	})
	d := forward(st)
	if d.OutOfWindow != 1 {
		t.Fatalf("OutOfWindow = %d, want 1", d.OutOfWindow)
	}
	if d.PendingGap() != 0 {
		t.Fatalf("an out-of-window segment must not allocate a %d-byte gap", d.PendingGap())
	}
}

func TestBothDirectionsAreIndependent(t *testing.T) {
	st := feed(t, []seg{
		{pkt: 1, seq: 100, flags: SYN},
		{pkt: 2, seq: 500, flags: SYN | ACK, rev: true},
		{pkt: 3, seq: 101, data: "request"},
		{pkt: 4, seq: 501, data: "response", rev: true},
		{pkt: 5, seq: 108, data: "-more"},
	})
	fwd, rev := st.Dir(epDesktop), st.Dir(epGateway)
	if got := string(fwd.Bytes.Bytes()); got != "request-more" {
		t.Errorf("desktop→gateway = %q", got)
	}
	if got := string(rev.Bytes.Bytes()); got != "response" {
		t.Errorf("gateway→desktop = %q", got)
	}
	if !fwd.SYNSeen || !rev.SYNSeen {
		t.Error("both directions should have seen their SYN")
	}
	if st.First != 1 || st.Last != 5 {
		t.Errorf("stream frame span = %d..%d, want 1..5", st.First, st.Last)
	}
	// ByFlow must agree with Dir.
	if st.ByFlow(FlowKey{Src: epDesktop, Dst: epGateway}) != fwd {
		t.Error("ByFlow disagrees with Dir")
	}
}

func TestPacketsForSpansSegments(t *testing.T) {
	st := feed(t, []seg{
		{pkt: 1, seq: isn, flags: SYN},
		{pkt: 10, seq: isn + 1, data: "0123456789"},
		{pkt: 11, seq: isn + 11, data: "abcdefghij"},
		{pkt: 12, seq: isn + 21, data: "KLMNOPQRST"},
	})
	sb := forward(st).Bytes
	for _, tc := range []struct {
		start, end int
		want       []int
	}{
		{0, 10, []int{10}},
		{0, 11, []int{10, 11}},
		{5, 25, []int{10, 11, 12}},
		{20, 30, []int{12}},
		{19, 21, []int{11, 12}},
		{29, 30, []int{12}},
		{0, 0, nil},
	} {
		got := sb.PacketsFor(tc.start, tc.end)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("PacketsFor(%d,%d) = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}

	if _, err := sb.Range(0, 31); err == nil {
		t.Error("Range past the end of the stream must fail rather than clamp")
	}
	b, err := sb.Range(10, 20)
	if err != nil || string(b) != "abcdefghij" {
		t.Errorf("Range(10,20) = %q, %v", b, err)
	}
	if got := sb.OffsetToPacket(-1); got != 0 {
		t.Errorf("OffsetToPacket(-1) = %d, want 0", got)
	}
	if got := sb.OffsetToPacket(999); got != 0 {
		t.Errorf("OffsetToPacket(999) = %d, want 0", got)
	}
}

// TestPendingBufferIsBounded proves a capture with a permanent hole cannot make
// the verifier allocate without limit.
func TestPendingBufferIsBounded(t *testing.T) {
	a := NewAssembler()
	a.MaxPending = 64
	a.AddFrame(seg{pkt: 1, seq: isn, flags: SYN}.frame())
	for i := 0; i < 20; i++ {
		// Every segment sits behind the same never-filled 1-byte gap.
		a.AddFrame(seg{pkt: 2 + i, seq: isn + 2 + uint32(i*10), data: "0123456789"}.frame())
	}
	d := forward(a.Streams()[0])
	if d.PendingGap() > 64 {
		t.Fatalf("pending buffer grew to %d bytes past the 64-byte cap", d.PendingGap())
	}
	if d.DroppedOOO == 0 {
		t.Fatal("segments past the cap should be counted as dropped")
	}
	if d.Bytes.Len() != 0 {
		t.Fatalf("nothing should be delivered while the first byte is missing, got %q", d.Bytes.Bytes())
	}
}

func TestAssemblerIgnoresFragmentsAndNonTCP(t *testing.T) {
	a := NewAssembler()
	frag := seg{pkt: 1, seq: isn + 1, data: "fragment"}.frame()
	frag.Fragmented = true
	a.AddFrame(frag)
	a.AddFrame(&Frame{Index: 2, Net: NetIPv4, IPProto: ipProtoUDP, UDP: &UDPDatagram{SrcPort: 5353, DstPort: 5353}})
	a.AddFrame(nil)
	if len(a.Streams()) != 0 {
		t.Fatalf("got %d streams, want none", len(a.Streams()))
	}
}

// TestAssemblerOverCapturedPackets runs the whole path — pcapng.Packet in,
// reassembled stream out — over synthesised Ethernet frames, so the wiring
// between DecodePacket and the reassembler is covered too.
func TestAssemblerOverCapturedPackets(t *testing.T) {
	mk := func(idx int, seq uint32, payload string, flags TCPFlags) pcapng.Packet {
		tcp := cat(tcpHdr(51422, 802, seq, 1, flags, 0), []byte(payload))
		ip := ipv4Hdr("69.0.0.20", "69.0.0.2", ipProtoTCP, len(tcp), 0, 0)
		data := cat(ethHdr(etherTypeIPv4), ip, tcp)
		return pcapng.Packet{Index: idx, LinkType: LinkTypeEthernet, Data: data, OrigLen: len(data)}
	}
	a := NewAssembler()
	for _, p := range []pcapng.Packet{
		mk(1, isn, "", SYN),
		mk(2, isn+1, "GET /dcap ", PSH|ACK),
		mk(3, isn+11, "HTTP/1.1\r\n", PSH|ACK),
	} {
		if _, err := a.AddPacket(p); err != nil {
			t.Fatalf("AddPacket: %v", err)
		}
	}
	streams := a.FindPort(802)
	if len(streams) != 1 {
		t.Fatalf("FindPort(802) returned %d streams", len(streams))
	}
	d := streams[0].Dir(epDesktop)
	if got, want := string(d.Bytes.Bytes()), "GET /dcap HTTP/1.1\r\n"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	if got := d.Bytes.PacketsFor(0, d.Bytes.Len()); fmt.Sprint(got) != "[2 3]" {
		t.Fatalf("PacketsFor = %v, want [2 3]", got)
	}
	if _, err := a.AddPacket(pcapng.Packet{Index: 4, LinkType: LinkTypeEthernet, Data: []byte{1, 2}}); err == nil {
		t.Fatal("a malformed packet must surface an error")
	}
}

func TestOverlapString(t *testing.T) {
	o := Overlap{Offset: 12, Length: 4, Packet: 9, KeptPacket: 7, Conflict: true}
	if got, want := o.String(), "CONFLICTING overlap at stream offset 12 (4 bytes): frame 9 discarded, frame 7 kept"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	o.Conflict = false
	if got := o.String(); got[:9] != "duplicate" {
		t.Errorf("String() = %q, want it to start with duplicate", got)
	}
}
