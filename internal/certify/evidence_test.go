package certify

import (
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
)

// evidenceFor builds the two-window attribution of the interleaved capture and
// hands back the Evidence a citation callback would receive.
func evidenceFor(t *testing.T, uid string) (*Evidence, *Evidence, *FrameIndex) {
	t.Helper()
	pkts := synthPackets(interleavedCapture())
	fi := NewFrameIndex(pkts)

	a := NewWindow("doc-a::A-001", "tls")
	a.Open(t0().Add(90 * time.Millisecond))
	a.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "session A")
	a.Close(t0().Add(200 * time.Millisecond))

	b := NewWindow("doc-a::A-002", "tls")
	b.Open(t0().Add(138 * time.Millisecond))
	b.ClaimAddrs("tcp", otherCheck, gatewayMBAPS, "session B")
	b.Close(t0().Add(160 * time.Millisecond))

	att := fi.Attribute([]*Window{a, b})
	cat := loadTestCatalog(t)
	mk := func(uid string) *Evidence {
		c, ok := cat.ByUID(uid)
		if !ok {
			t.Fatalf("no case %s", uid)
		}
		return &Evidence{Case: c, Set: att.Set(uid), Index: fi, Attribution: att}
	}
	_ = uid
	return mk("doc-a::A-001"), mk("doc-a::A-002"), fi
}

// The central guarantee: a check cannot cite a frame it did not cause.
func TestCiteFramesRefusesForeignFrames(t *testing.T) {
	evA, _, _ := evidenceFor(t, "doc-a::A-001")

	// Frames 5 and 6 are A's own TLS handshake.
	a, err := evA.CiteFrames("the server answered the ClientHello", "TLS record dissection",
		Pass, "ServerHello in frame 6", []int{5, 6})
	if err != nil {
		t.Fatalf("citing own frames: %v", err)
	}
	if a.FramesSHA256 == "" || len(a.Frames) != 2 {
		t.Errorf("assertion has no re-checkable citation: %+v", a)
	}

	for _, tc := range []struct {
		name  string
		frame int
		owner string
	}{
		{"background Modbus poll", 7, "no test case"},
		{"another check's connection", 11, "doc-a::A-002"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evA.CiteFrames("c", "m", Pass, "o", []int{tc.frame})
			if err == nil {
				t.Fatalf("frame %d was cited by a check that does not own it", tc.frame)
			}
			if !strings.Contains(err.Error(), tc.owner) {
				t.Errorf("error should name the real owner (%s): %v", tc.owner, err)
			}
		})
	}

	// A mixed citation — one own frame, one foreign — must be refused whole.
	if _, err := evA.CiteFrames("c", "m", Pass, "o", []int{5, 7}); err == nil {
		t.Error("a citation mixing an owned and a foreign frame was accepted")
	}
}

func TestCiteFramesRefusesAnEmptyCitation(t *testing.T) {
	evA, _, _ := evidenceFor(t, "doc-a::A-001")
	if _, err := evA.CiteFrames("c", "m", Pass, "o", nil); err == nil {
		t.Fatal("an assertion citing no frames at all was accepted as a citation")
	}
}

func TestCiteBytesOverAnOwnedStream(t *testing.T) {
	evA, _, _ := evidenceFor(t, "doc-a::A-001")
	st, err := evA.StreamOn(802)
	if err != nil {
		t.Fatalf("StreamOn(802): %v", err)
	}
	dir := st.ByFlow(netdis.FlowKey{
		Src: netdis.Endpoint{Addr: gatewayMBAPS.Addr(), Port: gatewayMBAPS.Port()},
		Dst: netdis.Endpoint{Addr: benchToGateway.Addr(), Port: benchToGateway.Port()},
	})
	if dir.Bytes.Len() == 0 {
		t.Fatalf("the gateway → bench direction reassembled to nothing")
	}
	got := string(dir.Bytes.Bytes())
	if !strings.Contains(got, "mbap-exception-01") {
		t.Fatalf("reassembled %q", got)
	}
	off := strings.Index(got, "mbap-exception-01")
	a, err := evA.CiteBytes("the gateway answered with exception code 01", "TCP stream reassembly",
		Pass, "mbap-exception-01", dir, off, off+len("mbap-exception-01"))
	if err != nil {
		t.Fatalf("CiteBytes: %v", err)
	}
	if a.BytesSHA256 == "" {
		t.Error("no byte digest recorded")
	}
	if len(a.Frames) != 1 || a.Frames[0] != 10 {
		t.Errorf("cited frames = %v, want [10]", a.Frames)
	}
}

func TestCiteBytesRefusesAForeignStream(t *testing.T) {
	evA, evB, _ := evidenceFor(t, "doc-a::A-001")
	stB, err := evB.StreamOn(802)
	if err != nil {
		t.Fatalf("B StreamOn: %v", err)
	}
	dirB := stB.Dirs[0]
	if _, err := evA.CiteBytes("c", "m", Pass, "o", dirB, 0, 0); err == nil {
		t.Fatal("check A cited check B's stream")
	} else if !strings.Contains(err.Error(), "not one of this") {
		t.Errorf("error = %v", err)
	}
}

// The framework must be able to say "there is nothing here" without lying about
// it — and the reason has to survive into the bundle.
func TestNoEvidenceAndSkipAssertion(t *testing.T) {
	pkts := synthPackets(interleavedCapture())
	fi := NewFrameIndex(pkts)
	w := NewWindow("doc-a::A-001", "tls")
	w.Open(t0())
	w.Close(t0().Add(time.Second))
	att := fi.Attribute([]*Window{w})
	cat := loadTestCatalog(t)
	c, _ := cat.ByUID("doc-a::A-001")
	ev := &Evidence{Case: c, Set: att.Set(c.UID), Index: fi, Attribution: att}

	if ev.HasFrames() {
		t.Fatal("a window with no claims reported frames")
	}
	a := ev.NoEvidence("the server sent a CertificateRequest")
	if a.Verdict != Skip {
		t.Errorf("verdict = %s, want SKIP", a.Verdict)
	}
	if !strings.Contains(a.Observed, "registered no connections") {
		t.Errorf("observed = %q; it must explain WHY there is no evidence", a.Observed)
	}
	if a.Citable() {
		t.Error("a SKIP must not carry a digest")
	}
}

func TestNarrativeRequiresASource(t *testing.T) {
	evA, _, _ := evidenceFor(t, "doc-a::A-001")
	if _, err := evA.Narrative("c", "m", Pass, "o", ""); err == nil {
		t.Fatal("an uncitable claim with no stated source was accepted")
	}
	a, err := evA.Narrative("the gridsim recorded a DERControlResponse status 1", "admin API",
		Pass, "status=1", "gridsim GET /admin/responses")
	if err != nil {
		t.Fatal(err)
	}
	if a.Citable() {
		t.Error("a narrative assertion must not claim to be re-checkable")
	}
	if !strings.Contains(a.Note, "gridsim GET /admin/responses") {
		t.Errorf("note = %q", a.Note)
	}
}

// A weaker attribution has to travel with the claim, not sit in a summary
// nobody reads.
func TestEndpointPrecisionAnnotatesEveryAssertion(t *testing.T) {
	pkts := synthPackets(interleavedCapture())
	fi := NewFrameIndex(pkts)
	w := NewWindow("doc-a::A-001", "tls")
	w.Open(t0())
	if err := w.ClaimEndpointDuring("tcp", gatewayMBAPS, "only this run dials the DUT's mbaps port"); err != nil {
		t.Fatal(err)
	}
	w.Close(t0().Add(time.Second))
	att := fi.Attribute([]*Window{w})
	cat := loadTestCatalog(t)
	c, _ := cat.ByUID("doc-a::A-001")
	ev := &Evidence{Case: c, Set: att.Set(c.UID), Index: fi, Attribution: att}

	a, err := ev.CiteFrames("c", "m", Pass, "o", []int{5})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Note, "not by connection 4-tuple") {
		t.Errorf("note = %q, want the weaker-attribution caveat", a.Note)
	}
	if !strings.Contains(a.Note, "only this run dials") {
		t.Errorf("note = %q, want the operator's justification", a.Note)
	}
}

func TestFrameIndexReportsIntegrityProblems(t *testing.T) {
	base := t0()
	// Two segments claiming the same sequence range with DIFFERENT bytes: the
	// classic evidence-tampering shape.
	pkts := synthPackets([]synthFrame{
		{src: benchToGateway, dst: gatewayMBAPS, seq: 100, flags: tcpSYN, at: base},
		{src: benchToGateway, dst: gatewayMBAPS, seq: 101, payload: "AAAA", at: base.Add(time.Millisecond)},
		{src: benchToGateway, dst: gatewayMBAPS, seq: 101, payload: "BBBB", at: base.Add(2 * time.Millisecond)},
	})
	fi := NewFrameIndex(pkts)
	found := false
	for _, p := range fi.Problems {
		if strings.Contains(p, "CONFLICTING") {
			found = true
		}
	}
	if !found {
		t.Errorf("problems = %v, want a conflicting-overlap finding", fi.Problems)
	}
}

func TestStreamLookupRefusesToGuess(t *testing.T) {
	evA, _, _ := evidenceFor(t, "doc-a::A-001")
	if _, err := evA.StreamOn(9999); err == nil {
		t.Error("a lookup of a port the check never touched succeeded")
	}
	if _, err := evA.Stream(modsim); err == nil {
		t.Error("a lookup of the background sim's endpoint succeeded")
	}
}

// TestFrameIndexAttributeReusesItsOwnAssembler guards the 2026-08-11 OOM fix:
// FrameIndex.Attribute must produce EXACTLY the same result as calling
// attribute() standalone (which reassembles from scratch), because it now
// reuses fi.asm — the Assembler NewFrameIndex already built — instead of
// paying for a second full TCP reassembly of the capture (see attribute's and
// FrameIndex.Attribute's doc comments in window.go/evidence.go). On the
// 2026-08-11 CSIP-leg capture that second reassembly held 1.34M background
// frames' worth of bytes twice for nothing; this test is the behavioural
// promise that skipping it changes nothing about what a check may cite.
func TestFrameIndexAttributeReusesItsOwnAssembler(t *testing.T) {
	pkts := synthPackets(interleavedCapture())
	frames := dissect(t, pkts)

	w := NewWindow("doc::TLS-001", "tls")
	w.Open(t0().Add(90 * time.Millisecond))
	w.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "mbaps session")
	w.Close(t0().Add(200 * time.Millisecond))

	want := attribute(frames, []*Window{w})

	fi := NewFrameIndex(pkts)
	got := fi.Attribute([]*Window{w})

	wantSet, gotSet := want.Set("doc::TLS-001"), got.Set("doc::TLS-001")
	if !equalInts(gotSet.Frames, wantSet.Frames) {
		t.Errorf("FrameIndex.Attribute frames = %v, want %v (attribute() standalone)", gotSet.Frames, wantSet.Frames)
	}
	if gotSet.Precision != wantSet.Precision {
		t.Errorf("precision = %s, want %s", gotSet.Precision, wantSet.Precision)
	}
	if got.Unattributed != want.Unattributed {
		t.Errorf("unattributed = %d, want %d", got.Unattributed, want.Unattributed)
	}
	if len(got.Contested) != len(want.Contested) {
		t.Errorf("contested = %v, want %v", got.Contested, want.Contested)
	}
	// The point of the fix: FrameIndex built exactly one Assembler's worth of
	// reassembled streams, and Attribute did not build a second.
	if got := len(fi.Streams()); got == 0 {
		t.Fatal("fi.asm was never populated — NewFrameIndex should have reassembled the capture")
	}
}
