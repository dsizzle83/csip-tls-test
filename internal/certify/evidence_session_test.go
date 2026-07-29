package certify

// evidence_session_test.go covers the session-indivisible citation rule: a
// check may cite the establishing handshake of a TLS conversation it owns even
// when that handshake landed in a gap before its window opened.
//
// This is the observation-correctness fix for PKI-4 in
// runs/overnight-20260729T045336/: the DUT presented its 2030.5 device identity
// on a long-lived connection whose Certificate rode a frame ~4000 frames before
// PKI-4's window, so the leaf the check was written to grade was uncitable and
// the whole case FAILed on "outside this check's window" — while PKI-5/6/7,
// which happened to catch a fresh handshake in-window, passed. The rule is the
// same one consolidateStreams already applies to a SPLIT conversation, reaching
// the one case consolidation cannot: a handshake attributed to no window at all.

import (
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
)

// dutCSIP and csipServer mirror the overnight batch's long-lived 34408 <> 11113
// conversation that surfaced the defect.
var (
	dutCSIP    = ap("69.0.0.2:34408")
	csipServer = ap("69.0.0.20:11113")
)

const identityLeaf = "DEVICE-LEAF-CERTIFICATE"

// longLivedIdentityCapture is a single DUT->server 2030.5 conversation whose
// Certificate is sent at establishment — well before the identity check's
// window — and whose application traffic then continues into the window.
func longLivedIdentityCapture() []synthFrame {
	base := t0()
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	return []synthFrame{
		// The connection is established long before the check runs.
		{src: dutCSIP, dst: csipServer, seq: 100, flags: tcpSYN, at: at(0)},
		{src: csipServer, dst: dutCSIP, seq: 900, flags: tcpSYN | tcpACK, at: at(0)},
		// The DUT's client Certificate — the identity under test — in a gap no
		// window covers.
		{src: dutCSIP, dst: csipServer, seq: 101, payload: identityLeaf, at: at(1)},
		// Application polls over the SAME long-lived connection, now inside the
		// identity check's window.
		{src: dutCSIP, dst: csipServer, seq: 101 + uint32(len(identityLeaf)), payload: "poll-1", at: at(120)},
		{src: dutCSIP, dst: csipServer, seq: 101 + uint32(len(identityLeaf)) + 6, payload: "poll-2", at: at(121)},
	}
}

// identityWindow opens the check's window over the two in-window polls, leaving
// the establishing handshake (frame 3) a gap orphan.
func identityWindow(t *testing.T) (*FrameIndex, *Attribution) {
	t.Helper()
	fi := NewFrameIndex(synthPackets(longLivedIdentityCapture()))
	w := NewWindow("ss::identity", "pki")
	w.Open(t0().Add(115 * time.Second))
	if err := w.ClaimEndpointDuring("tcp", csipServer,
		"the DUT dials the bench 2030.5 server on its own schedule; this suite may not restart it"); err != nil {
		t.Fatalf("claim endpoint: %v", err)
	}
	w.Close(t0().Add(125 * time.Second))
	return fi, fi.Attribute([]*Window{w})
}

func TestCiteReachesTheEstablishingHandshakeOfAnOwnedSession(t *testing.T) {
	fi, att := identityWindow(t)
	set := att.Set("ss::identity")
	ev := &Evidence{Case: &Case{UID: "ss::identity"}, Set: set, Index: fi, Attribution: att}

	// Precondition: the establishing handshake is a gap orphan, not attributed
	// by the window. If this stops holding the test proves nothing.
	if set.Owns(3) {
		t.Fatal("frame 3 should be a gap orphan; the window must not attribute it directly")
	}
	// But it is on the conversation the check owns the body of, so the
	// session-indivisible rule makes it citable.
	if ok, via := ev.mayCite(3); !ok || !via {
		t.Fatalf("mayCite(3) = (%v, %v), want (true, true)", ok, via)
	}

	st, err := ev.StreamOn(csipServer.Port())
	if err != nil {
		t.Fatalf("StreamOn(%d): %v", csipServer.Port(), err)
	}
	dir := st.ByFlow(netdis.FlowKey{
		Src: netdis.Endpoint{Addr: dutCSIP.Addr(), Port: dutCSIP.Port()},
		Dst: netdis.Endpoint{Addr: csipServer.Addr(), Port: csipServer.Port()},
	})
	body := string(dir.Bytes.Bytes())
	off := strings.Index(body, identityLeaf)
	if off < 0 {
		t.Fatalf("the leaf bytes did not reassemble: %q", body)
	}
	a, err := ev.CiteBytes("the DUT's leaf leaves the Subject empty and carries the SAN identity",
		"X.509 lifted from the TLS Certificate message", Pass, "empty Subject + SAN otherName",
		dir, off, off+len(identityLeaf))
	if err != nil {
		t.Fatalf("CiteBytes over the establishing handshake was refused: %v", err)
	}
	if a.BytesSHA256 == "" {
		t.Error("no byte digest recorded on the citation")
	}
	if len(a.Frames) != 1 || a.Frames[0] != 3 {
		t.Errorf("cited frames = %v, want [3] (the establishing handshake)", a.Frames)
	}
	if !strings.Contains(a.Note, "indivisible") {
		t.Errorf("a citation resting on the session rule must disclose it; note = %q", a.Note)
	}
}

// TestSessionRuleNeverStealsAForeignFrame guards the blast radius: the rule
// only reaches frames NO other check claims. A frame owned or contested by
// someone else stays off limits even when it rides a conversation this check
// owns.
func TestSessionRuleNeverStealsAForeignFrame(t *testing.T) {
	t.Run("owned by another check", func(t *testing.T) {
		fi, att := identityWindow(t)
		att.Sets["ss::other"] = &FrameSet{UID: "ss::other", owns: map[int]bool{3: true}}
		ev := &Evidence{Case: &Case{UID: "ss::identity"}, Set: att.Set("ss::identity"), Index: fi, Attribution: att}
		if ok, _ := ev.mayCite(3); ok {
			t.Fatal("frame 3 is owned by another check; the session rule must refuse it")
		}
		if _, err := ev.CiteFrames("c", "m", Pass, "o", []int{3}); err == nil {
			t.Fatal("CiteFrames accepted a frame another check owns")
		}
	})
	t.Run("contested", func(t *testing.T) {
		fi, att := identityWindow(t)
		att.Contested = map[int][]string{3: {"ss::identity", "ss::other"}}
		ev := &Evidence{Case: &Case{UID: "ss::identity"}, Set: att.Set("ss::identity"), Index: fi, Attribution: att}
		if ok, _ := ev.mayCite(3); ok {
			t.Fatal("frame 3 is contested; an ambiguous frame is not this check's evidence")
		}
	})
	t.Run("foreign stream", func(t *testing.T) {
		fi, att := identityWindow(t)
		ev := &Evidence{Case: &Case{UID: "ss::identity"}, Set: att.Set("ss::identity"), Index: fi, Attribution: att}
		// Frames 1/2 are the SYN of the very same conversation, so they ARE
		// citable; a frame on no owned stream is not. Frame 999 does not exist.
		if ok, _ := ev.mayCite(999); ok {
			t.Fatal("a non-existent frame must not be citable")
		}
	})
}
