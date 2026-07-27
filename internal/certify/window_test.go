package certify

import (
	"net"
	"testing"
	"time"
)

// The bench topology these tests reproduce: the desktop (69.0.0.20) is the
// bench, the gateway (69.0.0.2) is the DUT, and the gateway's continuous
// southbound Modbus poll of the desktop's modsim runs on the same wire
// throughout.
var (
	benchToGateway = ap("69.0.0.20:51422") // the test case's own connection
	gatewayMBAPS   = ap("69.0.0.2:802")
	gatewayPoll    = ap("69.0.0.2:41000") // the gateway's southbound poller
	modsim         = ap("69.0.0.20:5020")
	otherCheck     = ap("69.0.0.20:51500") // a second test case's connection
)

func t0() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) }

// interleavedCapture is the shape this framework has to get right: the check's
// own connection, a background Modbus poll that starts BEFORE the check and
// ends AFTER it, and a second check's connection to the same DUT port.
func interleavedCapture() []synthFrame {
	base := t0()
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	return []synthFrame{
		// 1-2: background Modbus poll, before anything else.
		{src: gatewayPoll, dst: modsim, seq: 1000, payload: "poll-req-1", at: at(0)},
		{src: modsim, dst: gatewayPoll, seq: 2000, payload: "poll-rsp-1", at: at(5)},
		// 3-6: the test case's own mbaps connection.
		{src: benchToGateway, dst: gatewayMBAPS, seq: 100, flags: tcpSYN, at: at(100)},
		{src: gatewayMBAPS, dst: benchToGateway, seq: 500, flags: tcpSYN | tcpACK, at: at(105)},
		{src: benchToGateway, dst: gatewayMBAPS, seq: 101, payload: "client-hello", at: at(110)},
		{src: gatewayMBAPS, dst: benchToGateway, seq: 501, payload: "server-hello", at: at(115)},
		// 7-8: the background poll again, INSIDE the check's window. This is
		// the pair a time-only attribution would steal.
		{src: gatewayPoll, dst: modsim, seq: 1010, payload: "poll-req-2", at: at(120)},
		{src: modsim, dst: gatewayPoll, seq: 2010, payload: "poll-rsp-2", at: at(125)},
		// 9-10: more of the test case's own traffic.
		{src: benchToGateway, dst: gatewayMBAPS, seq: 113, payload: "mbap-read", at: at(130)},
		{src: gatewayMBAPS, dst: benchToGateway, seq: 513, payload: "mbap-exception-01", at: at(135)},
		// 11-12: a DIFFERENT test case's connection to the same DUT port,
		// inside the first check's window. Also must not be stolen.
		{src: otherCheck, dst: gatewayMBAPS, seq: 900, flags: tcpSYN, at: at(140)},
		{src: gatewayMBAPS, dst: otherCheck, seq: 700, flags: tcpSYN | tcpACK, at: at(145)},
		// 13: the check's FIN, a few ms after the check returned — the guard
		// exists for exactly this frame.
		{src: benchToGateway, dst: gatewayMBAPS, seq: 130, flags: tcpFIN | tcpACK, at: at(210)},
		// 14: background poll after everything.
		{src: gatewayPoll, dst: modsim, seq: 1020, payload: "poll-req-3", at: at(400)},
	}
}

func TestAttributionExcludesBackgroundAndOtherChecks(t *testing.T) {
	frames := dissect(t, synthPackets(interleavedCapture()))

	w := NewWindow("doc::TLS-001", "tls")
	w.Open(t0().Add(90 * time.Millisecond))
	w.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "mbaps session")
	w.Close(t0().Add(200 * time.Millisecond))

	att := attribute(frames, []*Window{w})
	set := att.Set("doc::TLS-001")

	want := []int{3, 4, 5, 6, 9, 10, 13}
	if !equalInts(set.Frames, want) {
		t.Fatalf("attributed frames = %v, want %v", set.Frames, want)
	}
	if set.Precision != PrecisionConnection {
		t.Errorf("precision = %s, want %s", set.Precision, PrecisionConnection)
	}
	// Frames 7, 8 (background poll) and 11, 12 (the other check) sit strictly
	// inside the check's own interval; 1, 2 and 14 fall inside it once the
	// 250 ms guard is applied. All seven are rejected by the flow test alone,
	// which is the number that proves the second signal did the work.
	if set.TimeOnlyRejected != 7 {
		t.Errorf("TimeOnlyRejected = %d, want 7 (frames 1,2,7,8,11,12,14)", set.TimeOnlyRejected)
	}
	for _, f := range []int{1, 2, 7, 8, 11, 12, 14} {
		if set.Owns(f) {
			t.Errorf("frame %d was claimed but belongs to another conversation", f)
		}
	}
	if att.Unattributed != 7 {
		t.Errorf("unattributed = %d, want 7", att.Unattributed)
	}
	if len(att.Contested) != 0 {
		t.Errorf("contested = %v, want none", att.Contested)
	}
}

func TestAttributionTwoChecksSameDUTPort(t *testing.T) {
	frames := dissect(t, synthPackets(interleavedCapture()))

	a := NewWindow("doc::TLS-001", "tls")
	a.Open(t0().Add(90 * time.Millisecond))
	a.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "session A")
	a.Close(t0().Add(200 * time.Millisecond))

	b := NewWindow("doc::TLS-002", "tls")
	b.Open(t0().Add(138 * time.Millisecond))
	b.ClaimAddrs("tcp", otherCheck, gatewayMBAPS, "session B")
	b.Close(t0().Add(160 * time.Millisecond))

	att := attribute(frames, []*Window{a, b})
	if got := att.Set("doc::TLS-001").Frames; !equalInts(got, []int{3, 4, 5, 6, 9, 10, 13}) {
		t.Errorf("A frames = %v", got)
	}
	if got := att.Set("doc::TLS-002").Frames; !equalInts(got, []int{11, 12}) {
		t.Errorf("B frames = %v, want [11 12]", got)
	}
	if len(att.Contested) != 0 {
		t.Errorf("contested = %v, want none: the two connections differ in their 4-tuple", att.Contested)
	}
}

// A check that claims nothing gets nothing. The alternative — falling back to
// the time window — is the unsound behaviour the whole design rejects.
func TestAttributionWithoutAClaimYieldsNoFrames(t *testing.T) {
	frames := dissect(t, synthPackets(interleavedCapture()))
	w := NewWindow("doc::TLS-003", "tls")
	w.Open(t0())
	w.Close(t0().Add(500 * time.Millisecond))

	att := attribute(frames, []*Window{w})
	set := att.Set("doc::TLS-003")
	if len(set.Frames) != 0 {
		t.Fatalf("a window with no connection claim attributed %v; it must attribute nothing", set.Frames)
	}
	if set.Precision != PrecisionNone {
		t.Errorf("precision = %s, want %s", set.Precision, PrecisionNone)
	}
	if set.TimeOnlyRejected != len(frames) {
		t.Errorf("TimeOnlyRejected = %d, want %d (every frame in the interval)",
			set.TimeOnlyRejected, len(frames))
	}
}

// Port reuse: two checks whose connections share a 4-tuple inside the guard
// window. The frame is ambiguous, so it goes to neither.
func TestAttributionContestedFrameGoesToNobody(t *testing.T) {
	base := t0()
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	frames := dissect(t, synthPackets([]synthFrame{
		{src: benchToGateway, dst: gatewayMBAPS, seq: 1, payload: "a", at: at(100)},
	}))

	// Both windows contain the frame, with the guard and without, and both
	// claims are equally specific.
	a := NewWindow("doc::A", "s")
	a.Open(at(50))
	a.Close(at(150))
	a.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "A")

	b := NewWindow("doc::B", "s")
	b.Open(at(60))
	b.Close(at(140))
	b.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "B")

	att := attribute(frames, []*Window{a, b})
	if len(att.Set("doc::A").Frames) != 0 || len(att.Set("doc::B").Frames) != 0 {
		t.Fatalf("a contested frame was attributed: A=%v B=%v",
			att.Set("doc::A").Frames, att.Set("doc::B").Frames)
	}
	uids, ok := att.Contested[1]
	if !ok || len(uids) != 2 {
		t.Fatalf("contested = %v, want frame 1 claimed by both", att.Contested)
	}
}

// The guard breaks a tie when one window's un-guarded interval contains the
// frame and the other's does not.
func TestAttributionNarrowsByDroppingTheGuard(t *testing.T) {
	base := t0()
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	frames := dissect(t, synthPackets([]synthFrame{
		{src: benchToGateway, dst: gatewayMBAPS, seq: 1, payload: "a", at: at(500)},
	}))

	inside := NewWindow("doc::IN", "s")
	inside.Open(at(450))
	inside.Close(at(550))
	inside.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "in")

	// Ends before the frame, but the 250 ms guard reaches it.
	before := NewWindow("doc::BEFORE", "s")
	before.Open(at(100))
	before.Close(at(300))
	before.ClaimAddrs("tcp", benchToGateway, gatewayMBAPS, "before")

	att := attribute(frames, []*Window{inside, before})
	if got := att.Set("doc::IN").Frames; !equalInts(got, []int{1}) {
		t.Errorf("IN frames = %v, want [1]: its un-guarded interval contains the frame", got)
	}
	if got := att.Set("doc::BEFORE").Frames; len(got) != 0 {
		t.Errorf("BEFORE frames = %v, want none", got)
	}
}

func TestWindowClaimConnFromLiveSocket(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	go func() {
		c, err := lis.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	w := NewWindow("doc::X", "s")
	if err := w.ClaimConn(conn, "loopback"); err != nil {
		t.Fatalf("ClaimConn: %v", err)
	}
	claims := w.Claims()
	if len(claims) != 1 {
		t.Fatalf("claims = %v", claims)
	}
	if claims[0].Remote.String() != lis.Addr().String() {
		t.Errorf("claimed remote %s, want %s", claims[0].Remote, lis.Addr())
	}
	if w.Precision() != PrecisionConnection {
		t.Errorf("precision = %s", w.Precision())
	}
}

func TestClaimEndpointDuringRequiresAReason(t *testing.T) {
	w := NewWindow("doc::X", "s")
	if err := w.ClaimEndpointDuring("tcp", gatewayMBAPS, ""); err == nil {
		t.Fatal("an endpoint claim without a justification was accepted")
	}
	if err := w.ClaimEndpointDuring("tcp", gatewayMBAPS, "the DUT dials us; no other party reaches :802"); err != nil {
		t.Fatalf("ClaimEndpointDuring: %v", err)
	}
	if w.Precision() != PrecisionEndpoint {
		t.Errorf("precision = %s, want %s", w.Precision(), PrecisionEndpoint)
	}
}

// An endpoint claim still excludes traffic that never touches the endpoint.
func TestEndpointClaimStillExcludesOtherConversations(t *testing.T) {
	frames := dissect(t, synthPackets(interleavedCapture()))
	w := NewWindow("doc::EP", "s")
	w.Open(t0())
	if err := w.ClaimEndpointDuring("tcp", gatewayMBAPS, "only this run dials the DUT's mbaps port"); err != nil {
		t.Fatal(err)
	}
	w.Close(t0().Add(500 * time.Millisecond))

	set := attribute(frames, []*Window{w}).Set("doc::EP")
	// Everything to/from 69.0.0.2:802 — both checks' connections — but no
	// southbound poll.
	if !equalInts(set.Frames, []int{3, 4, 5, 6, 9, 10, 11, 12, 13}) {
		t.Fatalf("frames = %v", set.Frames)
	}
	if set.Precision != PrecisionEndpoint {
		t.Errorf("precision = %s", set.Precision)
	}
}

func equalInts(a, b []int) bool {
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
