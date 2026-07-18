//go:build integration

package mbtls

// resumption_integration_test.go proves the T06.8 mbtls enhancement directly at
// the TLS layer: the client-side session cache makes a second Dial to the same
// peer+identity RESUME the prior session (SunSpecTCP-46), the resumed session
// still carries the peer leaf DER for role re-derivation (the sysroot's
// SESSION_CERTS), and ClearSessionCache forces a full handshake again. It also
// exercises Session.Renegotiate against a server that does not enable secure
// renegotiation, capturing the observed policy the renegotiation-refusal probe
// asserts on. Requires the amd64 wolfSSL sysroot (desktop, `make
// test-integration`); TestMain (wolfssl.Init) is shared with the handshake test.

import (
	"testing"
)

// TestSessionResumption_AcrossDials proves the cache: Dial #1 is a full
// handshake, and after a round trip (which pumps the TLS 1.3 NewSessionTicket)
// and Close (which captures the session), Dial #2 to the same address+identity
// RESUMES — Resumed is true and the peer identity survives for role extraction.
func TestSessionResumption_AcrossDials(t *testing.T) {
	ClearSessionCache() // isolate from any session cached by an earlier test
	p := newPKI(t)
	addr, results := startServer(t, p.serverProfile())

	// Dial #1: full handshake (nothing cached yet).
	c1, err := Dial(addr, p.clientProfile(happyRole))
	if err != nil {
		t.Fatalf("Dial #1: %v", err)
	}
	s1, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("server Accept #1: %v", err)
	}
	if c1.Resumed {
		t.Errorf("Dial #1 reported Resumed=true on a cold cache")
	}
	// A round trip pumps the post-handshake NewSessionTicket so the client has a
	// resumable TLS 1.3 session to capture on Close.
	assertRoundTrip(t, c1, s1)
	c1.Close() // captures the session into the process cache
	s1.Close()

	// Dial #2: same address + same client identity → resume.
	c2, err := Dial(addr, p.clientProfile(happyRole))
	if err != nil {
		t.Fatalf("Dial #2: %v", err)
	}
	defer c2.Close()
	s2, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("server Accept #2: %v", err)
	}
	defer s2.Close()

	if !c2.Resumed {
		t.Fatalf("Dial #2 did NOT resume (Resumed=false) — client session cache is not carrying the session across Dials")
	}
	if !s2.Resumed {
		t.Errorf("server reports Resumed=false on the resumed handshake")
	}
	// A resumed session must still expose the peer leaf so the gateway can
	// re-derive the role on every session (SESSION_CERTS; design 02 §1).
	if len(s2.PeerDER) == 0 {
		t.Fatal("resumed session has no client PeerDER — role re-derivation would be impossible")
	}
	role, err := s2.Role()
	if err != nil || role != happyRole {
		t.Errorf("resumed-session role = %q, err=%v; want %q", role, err, happyRole)
	}
	// The resumed session carries decrypted application bytes both ways.
	assertRoundTrip(t, c2, s2)
}

// TestSessionResumption_ClearForcesFullHandshake proves ClearSessionCache drops
// the captured session so the next Dial handshakes fully again — the isolation
// primitive a "no resume expected" probe (and cross-test hygiene) relies on.
func TestSessionResumption_ClearForcesFullHandshake(t *testing.T) {
	ClearSessionCache()
	p := newPKI(t)
	addr, results := startServer(t, p.serverProfile())

	c1, err := Dial(addr, p.clientProfile(happyRole))
	if err != nil {
		t.Fatalf("Dial #1: %v", err)
	}
	s1, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("server Accept #1: %v", err)
	}
	assertRoundTrip(t, c1, s1)
	c1.Close()
	s1.Close()

	ClearSessionCache() // drop the just-captured session

	c2, err := Dial(addr, p.clientProfile(happyRole))
	if err != nil {
		t.Fatalf("Dial #2: %v", err)
	}
	defer c2.Close()
	s2, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("server Accept #2: %v", err)
	}
	defer s2.Close()

	if c2.Resumed {
		t.Errorf("Dial #2 resumed after ClearSessionCache — the cache was not cleared")
	}
}

// TestRenegotiate_ServerPolicyObserved drives a client-initiated renegotiation
// against a server that advertises the indication but does NOT enable secure
// renegotiation (the product's conformant policy: indicate per TCP-62, refuse to
// actually renegotiate). The test asserts the OBSERVED behaviour is safe — either
// the attempt is refused, or it is handled with the peer identity still derivable
// — never a silent success that drops the client identity. This is the exact
// judgement the renegotiation-refusal oracle (T06.8) makes.
func TestRenegotiate_ServerPolicyObserved(t *testing.T) {
	ClearSessionCache()
	p := newPKI(t)
	addr, results := startServer(t, p.serverProfile())

	c, err := Dial(addr, p.clientProfile(happyRole))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	s, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("server Accept: %v", err)
	}
	defer s.Close()

	// Identity is present before any renegotiation.
	if len(c.PeerDER) == 0 {
		t.Fatal("client has no server PeerDER before renegotiation")
	}

	renegErr := c.Renegotiate()
	// The refusal path (the expected policy) returns an error; the session must
	// NOT have silently dropped the peer identity either way (role re-derivation
	// stays possible — design 02 §1).
	if renegErr != nil {
		t.Logf("renegotiation refused by server policy (expected): %v", renegErr)
	} else {
		t.Logf("renegotiation was handled by the server; asserting identity survived")
		if len(c.PeerDER) == 0 {
			t.Error("renegotiation succeeded but the client dropped the server identity")
		}
	}
}
