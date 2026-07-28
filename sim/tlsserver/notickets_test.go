package tlsserver

// notickets_test.go is the proof that Config.NoSessionTickets does what a
// conformance run needs it to do, which is not "no tickets" but "no
// resumption": a resumed session carries no certificates, and a window that
// catches one has no certificate evidence to cite.
//
// Both halves are asserted. A test that only showed the flag refusing
// resumption would pass just as well against a bench where resumption never
// worked in the first place, and would then be silent on the day the default
// stopped exercising the DUT's resumption path.

import (
	"testing"

	"csip-tls-test/internal/wolfssl"
)

func clientCfg() testClientConfig {
	return testClientConfig{
		CACertPath:     testdataPath("certs/ca-cert.pem"),
		ClientCertPath: testdataPath("certs/client-cert.pem"),
		ClientKeyPath:  testdataPath("certs/client-key.pem"),
	}
}

// dialTwice connects, captures the session, and connects again offering it
// back. It returns whether the SECOND handshake was a resumption.
func dialTwice(t *testing.T, addr string) bool {
	t.Helper()

	first, err := dialServerTestClient(t, addr, clientCfg())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	if first.Reused() {
		t.Fatal("the first handshake reports itself resumed, with nothing to resume")
	}
	sess := first.Session()
	if sess == nil {
		t.Fatal("no session handle was captured from the first handshake")
	}
	defer wolfssl.FreeSession(sess)
	first.Close()

	cfg := clientCfg()
	cfg.Resume = sess
	second, err := dialServerTestClient(t, addr, cfg)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer second.Close()
	return second.Reused()
}

// TestSessionsResumeByDefault is the control. Without it the negative test below
// proves nothing.
func TestSessionsResumeByDefault(t *testing.T) {
	addr, _ := startTestServer(t, defaultTestConfig())
	if !dialTwice(t, addr) {
		t.Error("the default server did not resume an offered session, so the -no-tickets test has no control")
	}
}

// TestNoSessionTicketsForcesAFullHandshake is the flag a conformance run throws:
// every dial is a full mTLS handshake, so every window that catches one can cite
// the certificate exchange.
func TestNoSessionTicketsForcesAFullHandshake(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.NoSessionTickets = true
	addr, _ := startTestServer(t, cfg)
	if dialTwice(t, addr) {
		t.Error("the server resumed a session with NoSessionTickets set: the handshake carried no certificates " +
			"and the window has nothing to cite")
	}
}
