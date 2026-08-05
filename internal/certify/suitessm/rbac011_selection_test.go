package suitessm

// rbac011_selection_test.go is the regression lock for the RBAC-011 half of
// CONFORMANCE-LEGB-EVIDENCE-GAPS: on the flashed-image leg every steady-state
// mbaps session RESUMES, and a resumed TLS 1.3 handshake carries NO Certificate
// message (RFC 8446 §2.2). The gateway's client certificate — and the SunSpec
// role extension RBAC-011 reads from it — appears only on a FULL handshake.
//
// The pre-fix citation bound to the FIRST conversation with a ClientHello
// (clientHalf.hello), which in steady state is a resumed session, so it reported
// "the decrypted handshake carries no Certificate message for this side" and the
// row went PASS->WARN even though a full handshake sat elsewhere in the very
// same capture (the forced reconnect). This test reproduces that shape — a
// resumed conversation FIRST, a full handshake SECOND, both to the same device
// sim — and proves clientCertView reaches past the resumed one to the full
// handshake and recovers the role. Decryption itself was never the miss:
// tlsdecrypt recovers the client Certificate from a full handshake fine (see
// rbac011_decrypt_test.go); the miss was choosing which conversation to look at.

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/tlsdecrypt"
)

// TestRBAC011SelectsFullHandshakeAmongResumedSessions builds a capture whose
// FIRST device-sim conversation resumed (no client Certificate on the wire) and
// whose SECOND is a full mTLS handshake carrying the gateway's role-bearing
// leaf, and asserts the citation picks the full one.
func TestRBAC011SelectsFullHandshakeAmongResumedSessions(t *testing.T) {
	root, rootKey := testCA(t, "rbac011-sel-root")
	gatewayLeaf, err := mintLeaf(root, rootKey, mintOpts{
		CommonName: "rbac011-sel-gateway", Role: "GridServiceSunSpec",
	})
	if err != nil {
		t.Fatalf("mint gateway leaf: %v", err)
	}
	simLeaf, err := mintLeaf(root, rootKey, mintOpts{CommonName: "rbac011-sel-mbapsdev"})
	if err != nil {
		t.Fatalf("mint device-sim leaf: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	simAddr, err := addrPortOf(lis.Addr())
	if err != nil {
		t.Fatalf("sim addr: %v", err)
	}

	// The device sim exports its own session secrets (the -keylog mechanism), and
	// keeps session tickets ENABLED so the second dial can resume — the very
	// resumption the fix must see past. bytes.Buffer is safe: read only after the
	// server loop has stopped (wg.Wait()).
	var simKeylog bytes.Buffer
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{simLeaf},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: lockedWriter{&simKeylog},
	}

	// serve accepts one connection, completes the handshake, writes a byte (so
	// the client's Read pumps the post-handshake NewSessionTicket into its cache)
	// and closes.
	var serveWG sync.WaitGroup
	serve := func() {
		defer serveWG.Done()
		conn, aerr := lis.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		srv := tls.Server(conn, serverCfg)
		_ = srv.SetDeadline(time.Now().Add(10 * time.Second))
		if herr := srv.Handshake(); herr != nil {
			return
		}
		_, _ = srv.Write([]byte("x"))
		_ = srv.CloseWrite()
		_, _ = srv.Read(make([]byte, 1))
	}

	// dial performs one client handshake, pumps the ticket, and (when tapped)
	// records the bytes. resume==true reuses cache so the handshake resumes.
	cache := tls.NewLRUClientSessionCache(4)
	dial := func(tp *tap, wantResume bool) (netip.AddrPort, bool) {
		serveWG.Add(1)
		go serve()
		raw, derr := net.Dial("tcp", lis.Addr().String())
		if derr != nil {
			t.Fatalf("dial: %v", derr)
		}
		local, _ := addrPortOf(raw.LocalAddr())
		conn := raw
		if tp != nil {
			conn = tp.wrap(raw)
		}
		cfg := &tls.Config{
			Certificates:       []tls.Certificate{gatewayLeaf},
			InsecureSkipVerify: true, //nolint:gosec // test-only loopback peer
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			ServerName:         "mbapsdev",
			ClientSessionCache: cache,
		}
		cli := tls.Client(conn, cfg)
		_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
		if herr := cli.Handshake(); herr != nil {
			t.Fatalf("client handshake (wantResume=%v): %v", wantResume, herr)
		}
		// Pump the NewSessionTicket so the cache is primed for the next dial.
		_, _ = cli.Read(make([]byte, 1))
		resumed := cli.ConnectionState().DidResume
		_ = cli.Close()
		serveWG.Wait()
		return local, resumed
	}

	// Prime the cache (NOT tapped — an establishing handshake "outside the
	// window").
	if _, resumed := dial(nil, false); resumed {
		t.Fatal("the priming dial should not have resumed")
	}

	tp := &tap{}
	// Conversation A: a RESUMED session — no client Certificate on the wire.
	localA, resumedA := dial(tp, true)
	if !resumedA {
		t.Skip("this Go build did not resume the TLS 1.3 session on loopback; the selection fix is still " +
			"covered by the full-handshake recovery in rbac011_decrypt_test.go")
	}
	// Conversation B: a FULL handshake — the gateway's client Certificate, with
	// its role extension, is on the wire. A fresh cache so it cannot resume.
	cache = tls.NewLRUClientSessionCache(4)
	localB, resumedB := dial(tp, false)
	if resumedB {
		t.Fatal("conversation B was supposed to be a FULL handshake but resumed")
	}

	// Build the capture and the two parsed conversations, A before B.
	pkts := tp.packets()
	fi := certify.NewFrameIndex(pkts)
	kl, err := keylog.Parse(bytes.NewReader(simKeylog.Bytes()))
	if err != nil {
		t.Fatalf("parse key log: %v", err)
	}
	ev := &certify.Evidence{KeyLog: kl}

	viewFor := func(local netip.AddrPort) *wireView {
		for _, st := range fi.Streams() {
			a, b := endpointAddr(st.Key.A), endpointAddr(st.Key.B)
			if (a == local && b == simAddr) || (a == simAddr && b == local) {
				v, verr := parseView(st, local, simAddr)
				if verr != nil {
					t.Fatalf("parseView: %v", verr)
				}
				return v
			}
		}
		t.Fatalf("no conversation for %s <> %s in the synthesised capture", local, simAddr)
		return nil
	}
	convA := viewFor(localA)
	convB := viewFor(localB)

	// The bug, stated: conversation A resumed, so its client flight decrypts
	// cleanly and carries NO Certificate — the exact "no Certificate message for
	// this side" the pre-fix citation surfaced after binding to it.
	if _, _, derr := decryptedCertificate(ev, convA, tlsdecrypt.Client); derr == nil {
		t.Fatal("conversation A was supposed to be resumed (no client Certificate), but one was recovered")
	}

	// The fix: scanning both conversations reaches past the resumed one to the
	// full handshake and recovers the role-bearing client certificate.
	v, cert, frames, res, reason := pickClientCertView(ev, []*wireView{convA, convB})
	if res != certFound {
		t.Fatalf("pickClientCertView resolution = %d (reason %q), want certFound", res, reason)
	}
	if v != convB {
		t.Error("the selected conversation is not the full-handshake one (B)")
	}
	if cert == nil || cert.Leaf() == nil || cert.Leaf().Info == nil {
		t.Fatal("no usable client Certificate was recovered from the full handshake")
	}
	if len(frames) == 0 {
		t.Error("the recovered Certificate carries no capture frames, so it could not be cited")
	}
	verdict, obs := roleExtensionVerdict(cert.Leaf().Info, "")
	if verdict != certify.Pass {
		t.Fatalf("role verdict = %s, want Pass (observed: %s)", verdict, obs)
	}
	if !strings.Contains(obs, "GridServiceSunSpec") {
		t.Errorf("observed = %q, want it to name the gateway's role", obs)
	}

	// And a capture with ONLY resumed sessions resolves to certAllResumed — the
	// distinct, resumption-honest status the off-wire fallback rests on, never a
	// silent no-cert obstacle.
	if _, _, _, res2, _ := pickClientCertView(ev, []*wireView{convA}); res2 != certAllResumed {
		t.Errorf("all-resumed resolution = %d, want certAllResumed", res2)
	}
}
