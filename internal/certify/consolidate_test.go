package certify

import (
	"net/netip"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
)

// tcpFrame builds a minimal dissected frame on one TCP conversation.
func tcpFrame(index int, at time.Time, srcPort, dstPort uint16) *netdis.Frame {
	return &netdis.Frame{
		Index:   index,
		Time:    at,
		Net:     netdis.NetIPv4,
		Src:     netip.MustParseAddr("69.0.0.2"),
		Dst:     netip.MustParseAddr("69.0.0.20"),
		IPProto: 6,
		TCP:     &netdis.TCPSegment{SrcPort: srcPort, DstPort: dstPort},
	}
}

// tcpFrameSeq builds a dissected frame carrying explicit flags and a sequence
// number, for tests that need the Assembler's generation-splitting (which
// keys off the initial sequence number of a bare SYN) to actually engage —
// tcpFrame's frames all carry flags 0, which never trips it.
func tcpFrameSeq(index int, at time.Time, srcPort, dstPort uint16, seq uint32, flags netdis.TCPFlags) *netdis.Frame {
	f := tcpFrame(index, at, srcPort, dstPort)
	f.TCP.Seq = seq
	f.TCP.Flags = flags
	return f
}

// TestConsolidateGivesASplitConversationToItsMajorityOwner is the regression
// test for the defect that left 126 assertions uncitable on 2026-07-28.
//
// A TLS session that straddles two checks' windows used to be SPLIT between
// them at frame granularity. Neither could then cite it — the runner refuses to
// let a check cite frames another check owns — so evidence that was sitting in
// the capture was unusable by anybody, and both checks reported it missing.
//
// A conversation is indivisible evidence, so the majority owner takes all of it.
func TestConsolidateGivesASplitConversationToItsMajorityOwner(t *testing.T) {
	base := time.Unix(1785000000, 0).UTC()
	// One conversation, five frames. The first four fall in A's window, the
	// fifth slips past the boundary into B's.
	var frames []*netdis.Frame
	for i := 0; i < 5; i++ {
		frames = append(frames, tcpFrame(i+1, base.Add(time.Duration(i)*time.Second), 40000, 11113))
	}

	remote := netip.MustParseAddrPort("69.0.0.20:11113")
	winA := NewWindow("case-A", "csip")
	if err := winA.ClaimEndpointDuring("tcp", remote, "test"); err != nil {
		t.Fatalf("claim A: %v", err)
	}
	winA.Open(base.Add(-time.Second))
	winA.Close(base.Add(3*time.Second + 500*time.Millisecond))

	winB := NewWindow("case-B", "csip")
	if err := winB.ClaimEndpointDuring("tcp", remote, "test"); err != nil {
		t.Fatalf("claim B: %v", err)
	}
	winB.Open(base.Add(3*time.Second + 600*time.Millisecond))
	winB.Close(base.Add(10 * time.Second))

	att := attribute(frames, []*Window{winA, winB})

	a, b := att.Sets["case-A"], att.Sets["case-B"]
	if a == nil || b == nil {
		t.Fatal("both windows should have frame sets")
	}
	if len(a.Frames) != 5 {
		t.Errorf("case-A owns %d frame(s), want all 5 — the majority owner takes the whole conversation "+
			"(frames: %v)", len(a.Frames), a.Frames)
	}
	if len(b.Frames) != 0 {
		t.Errorf("case-B owns %d frame(s), want 0 — it held a minority of a conversation case-A owns "+
			"(frames: %v)", len(b.Frames), b.Frames)
	}
	if b.Consolidated == 0 {
		t.Error("case-B.Consolidated = 0: yielding frames must be recorded, not silent")
	}
	// The conversation must be listed against exactly one check.
	if len(a.Streams) != 1 {
		t.Errorf("case-A streams = %v, want exactly the one conversation", a.Streams)
	}
	if len(b.Streams) != 0 {
		t.Errorf("case-B streams = %v, want none", b.Streams)
	}
}

// TestConsolidateLeavesAnUnsplitConversationAlone guards the blast radius: this
// pass must only ever repair a conversation that is ALREADY split.
func TestConsolidateLeavesAnUnsplitConversationAlone(t *testing.T) {
	base := time.Unix(1785000000, 0).UTC()
	var frames []*netdis.Frame
	for i := 0; i < 3; i++ {
		frames = append(frames, tcpFrame(i+1, base.Add(time.Duration(i)*time.Second), 40000, 11113))
	}
	// A second, independent conversation wholly inside B's window.
	for i := 0; i < 2; i++ {
		frames = append(frames, tcpFrame(10+i, base.Add(time.Duration(6+i)*time.Second), 40001, 11113))
	}

	remote := netip.MustParseAddrPort("69.0.0.20:11113")
	winA := NewWindow("case-A", "csip")
	if err := winA.ClaimEndpointDuring("tcp", remote, "test"); err != nil {
		t.Fatalf("claim A: %v", err)
	}
	winA.Open(base.Add(-time.Second))
	winA.Close(base.Add(4 * time.Second))

	winB := NewWindow("case-B", "csip")
	if err := winB.ClaimEndpointDuring("tcp", remote, "test"); err != nil {
		t.Fatalf("claim B: %v", err)
	}
	winB.Open(base.Add(5 * time.Second))
	winB.Close(base.Add(10 * time.Second))

	att := attribute(frames, []*Window{winA, winB})
	a, b := att.Sets["case-A"], att.Sets["case-B"]
	if len(a.Frames) != 3 {
		t.Errorf("case-A owns %d, want 3 (its own conversation, untouched)", len(a.Frames))
	}
	if len(b.Frames) != 2 {
		t.Errorf("case-B owns %d, want 2 (its own conversation, untouched)", len(b.Frames))
	}
	if a.Consolidated != 0 || b.Consolidated != 0 {
		t.Errorf("nothing was split, so nothing should have been consolidated (A=%d B=%d)",
			a.Consolidated, b.Consolidated)
	}
}

// TestConsolidateDoesNotMergeReusedPortAcrossCases is the regression test for
// census 20260731T234821 (see window.go's consolidateStreams doc): two
// SEQUENTIAL, entirely unrelated connections that the kernel happened to hand
// the identical local port — CRYP-001's small iteration-1 probe, then, much
// later, PKI-8's larger mutual-auth connection reusing port 50808. Before
// generation-aware grouping, majority-vote (correctly, for a real split
// connection) gave the small, earlier connection's frames to the bigger,
// later one — silently. case-A here stands in for CRYP-001 (fewer frames,
// first); case-B for PKI-8 (more frames, later): the shape that used to lose.
func TestConsolidateDoesNotMergeReusedPortAcrossCases(t *testing.T) {
	base := time.Unix(1785000000, 0).UTC()
	const port = 50808

	var frames []*netdis.Frame
	// Connection 1 (case-A's, small, early): SYN, one data frame, FIN.
	frames = append(frames,
		tcpFrameSeq(1, base, port, 802, 0x1000_0000, netdis.SYN),
		tcpFrameSeq(2, base.Add(1*time.Second), port, 802, 0x1000_0001, 0),
		tcpFrameSeq(3, base.Add(2*time.Second), port, 802, 0x1000_000B, netdis.FIN|netdis.ACK),
	)
	// Connection 2 (case-B's, larger, minutes later, same local port, an
	// unrelated ISN — the only signal a real capture offers): SYN and four
	// data frames.
	start2 := base.Add(5 * time.Minute)
	frames = append(frames,
		tcpFrameSeq(4, start2, port, 802, 0x9000_0000, netdis.SYN),
		tcpFrameSeq(5, start2.Add(1*time.Second), port, 802, 0x9000_0001, 0),
		tcpFrameSeq(6, start2.Add(2*time.Second), port, 802, 0x9000_0002, 0),
		tcpFrameSeq(7, start2.Add(3*time.Second), port, 802, 0x9000_0003, 0),
		tcpFrameSeq(8, start2.Add(4*time.Second), port, 802, 0x9000_0004, 0),
	)

	remote := netip.MustParseAddrPort("69.0.0.20:802")
	local := netip.MustParseAddrPort("69.0.0.2:50808")

	winA := NewWindow("case-A", "ssm")
	winA.ClaimAddrs("tcp", local, remote, "case-A connection")
	winA.Open(base.Add(-time.Second))
	winA.Close(base.Add(3 * time.Second))

	winB := NewWindow("case-B", "pki")
	winB.ClaimAddrs("tcp", local, remote, "case-B connection")
	winB.Open(start2.Add(-time.Second))
	winB.Close(start2.Add(5 * time.Second))

	att := attribute(frames, []*Window{winA, winB})
	a, b := att.Sets["case-A"], att.Sets["case-B"]
	if a == nil || b == nil {
		t.Fatal("both windows should have frame sets")
	}

	if want := []int{1, 2, 3}; !equalInts(a.Frames, want) {
		t.Errorf("case-A frames = %v, want %v — its own (smaller, earlier) connection must survive intact, "+
			"not be given away to case-B just because case-B's later connection reused its port", a.Frames, want)
	}
	if want := []int{4, 5, 6, 7, 8}; !equalInts(b.Frames, want) {
		t.Errorf("case-B frames = %v, want %v", b.Frames, want)
	}
	if a.Consolidated != 0 || b.Consolidated != 0 {
		t.Errorf("neither connection is actually split, so nothing should be marked consolidated (A=%d B=%d)",
			a.Consolidated, b.Consolidated)
	}
	if len(att.Contested) != 0 {
		t.Errorf("contested = %v, want none: two connections that never coexist in time are not ambiguous",
			att.Contested)
	}
	if len(att.Ambiguous) != 0 {
		t.Errorf("ambiguous = %v, want none", att.Ambiguous)
	}

	// The two connections must be citable as DIFFERENT streams — this is what
	// Evidence.Stream/StreamOn resolve through, and it is exactly what
	// production hit: CRYP-001's citation code asked for "the conversation on
	// 69.0.0.2:802 <> 69.0.0.20:50808" and, pre-fix, got told none existed.
	if len(a.Streams) != 1 || len(b.Streams) != 1 {
		t.Fatalf("stream lists = A:%v B:%v, want exactly one each", a.Streams, b.Streams)
	}
	if a.Streams[0] == b.Streams[0] {
		t.Errorf("both cases report the same stream identity %q; the two connections must be distinguishable",
			a.Streams[0])
	}
}

// TestConsolidateGenuineAmbiguitySurfacesAsContested constructs the one shape
// that can defeat the "one boundary crossing" doctrine even with correct
// generation splitting: a broad, weak (endpoint-only) claim whose window
// contains a narrow, strong (full 4-tuple) claim from a DIFFERENT case,
// touching the SAME physical connection. Per-frame attribution correctly
// prefers the more specific claim inside its interval (see narrow), which
// makes ownership of the one connection go A, A, A, B, B, A, A — not a single
// boundary crossing, so majority-vote has no honest answer. The fix must
// refuse to guess: every frame in it goes to nobody, loudly, rather than
// silently to whichever side has more frames.
func TestConsolidateGenuineAmbiguitySurfacesAsContested(t *testing.T) {
	base := time.Unix(1785000000, 0).UTC()
	var frames []*netdis.Frame
	for i := 0; i < 7; i++ {
		frames = append(frames, tcpFrame(i+1, base.Add(time.Duration(i)*time.Second), 40000, 11113))
	}

	remote := netip.MustParseAddrPort("69.0.0.20:11113")
	local := netip.MustParseAddrPort("69.0.0.2:40000")

	winA := NewWindow("case-A", "csip")
	if err := winA.ClaimEndpointDuring("tcp", remote, "broad: this suite cannot learn the DUT's local port"); err != nil {
		t.Fatalf("claim A: %v", err)
	}
	winA.Open(base.Add(-time.Second))
	winA.Close(base.Add(7 * time.Second))

	winB := NewWindow("case-B", "other")
	winB.ClaimAddrs("tcp", local, remote, "narrow: the exact connection this case opened")
	winB.Open(base.Add(2500 * time.Millisecond))
	winB.Close(base.Add(4500 * time.Millisecond))

	att := attribute(frames, []*Window{winA, winB})
	a, b := att.Sets["case-A"], att.Sets["case-B"]
	if a == nil || b == nil {
		t.Fatal("both windows should have frame sets")
	}

	if len(a.Frames) != 0 {
		t.Errorf("case-A frames = %v, want none: a genuinely ambiguous connection must not be guessed", a.Frames)
	}
	if len(b.Frames) != 0 {
		t.Errorf("case-B frames = %v, want none: a genuinely ambiguous connection must not be guessed", b.Frames)
	}
	if len(a.Streams) != 0 || len(b.Streams) != 0 {
		t.Errorf("stream lists = A:%v B:%v, want none: neither case may cite the ambiguous connection", a.Streams, b.Streams)
	}

	// Every frame of the connection must show up as contested — attributed to
	// nobody, both contenders named — not merely dropped.
	for _, idx := range []int{1, 2, 3, 4, 5, 6, 7} {
		uids, ok := att.Contested[idx]
		if !ok {
			t.Errorf("frame %d: not recorded as contested", idx)
			continue
		}
		if !equalStrings(uids, []string{"case-A", "case-B"}) {
			t.Errorf("frame %d contested by %v, want [case-A case-B]", idx, uids)
		}
	}

	// The ambiguity must be visible as PROSE, not just a frame-number diff —
	// this is what runner.go folds into the bundle's CaptureProblems, which is
	// what makes a run with this shape report itself as not OK.
	if len(att.Ambiguous) != 1 {
		t.Fatalf("Ambiguous = %v, want exactly one entry describing the ambiguous connection", att.Ambiguous)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
