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
