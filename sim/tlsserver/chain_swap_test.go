//go:build integration

package tlsserver

// chain_swap_test.go proves the four properties COMM-004 D/E/F/G rest on. Three
// of them are about what the swap does; the fourth is about what it does NOT do,
// and that is the one that protects the rest of a campaign.
//
//	1. A connection opened AFTER a swap is offered the new chain.
//	2. A connection opened BEFORE a swap keeps working, on the old chain, for as
//	   long as it lives — so a swap mid-campaign cannot be mistaken, in the
//	   capture, for the DUT tearing a session down.
//	3. RestoreChain puts the original chain back, verifiably, by fingerprint.
//	4. A swap that cannot be loaded changes nothing at all: no window exists in
//	   which the listener is serving something other than a valid credential.

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// peerLeafSHA256 is the fingerprint of the leaf certificate the SERVER
// presented, read from the client's completed handshake. It is the same fact
// the conformance harness reads out of the pcap's Certificate message, which is
// what makes this test meaningful rather than self-referential.
func peerLeafSHA256(t *testing.T, c *serverTestClient) string {
	t.Helper()
	der := wolfssl.PeerChainLeafDER(unsafe.Pointer(c.ssl))
	if len(der) == 0 {
		t.Fatal("the client recovered no server leaf certificate from the handshake")
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// swapFixture mints a second, independent server credential — a fresh root and
// a leaf under it — and writes it where SwapChain can load it. It stands in for
// the COMM-004 invalid-MICA fixtures: what this test cares about is that the
// chain on the wire CHANGED, not what is wrong with it.
func swapFixture(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	root := mkCert(t, "swap-test root", true, nil, nil)
	leaf := mkCert(t, "swap-test server", false, &root, []string{"127.0.0.1", "localhost"})
	certPath = filepath.Join(dir, "swap-chain.pem")
	keyPath = filepath.Join(dir, "swap-key.pem")
	writeCertPEM(t, certPath, leaf.der, root.der)
	writeKeyPEM(t, keyPath, leaf.key)
	return certPath, keyPath
}

func TestSwapChain_NewConnectionsSeeTheNewChain(t *testing.T) {
	addr, srv := startTestServer(t, defaultTestConfig())

	orig := srv.ActiveChain()
	if orig.Label != "startup" || orig.LeafSHA256 == "" {
		t.Fatalf("start-up chain not recorded: %+v", orig)
	}
	if orig.Swaps != 0 {
		t.Errorf("a server that has swapped nothing reports Swaps=%d", orig.Swaps)
	}

	before, err := dialServerTestClient(t, addr, clientCfg())
	if err != nil {
		t.Fatalf("dial before the swap: %v", err)
	}
	defer before.Close()
	if got := peerLeafSHA256(t, before); got != orig.LeafSHA256 {
		t.Fatalf("pre-swap connection saw leaf %s, ActiveChain reports %s", got, orig.LeafSHA256)
	}

	certPath, keyPath := swapFixture(t, t.TempDir())
	swapped, err := srv.SwapChain("comm-004 fixture", certPath, keyPath)
	if err != nil {
		t.Fatalf("SwapChain: %v", err)
	}
	if swapped.LeafSHA256 == orig.LeafSHA256 {
		t.Fatal("the swap installed a chain with the same leaf fingerprint as the original")
	}
	if swapped.ChainLen != 2 {
		t.Errorf("swapped chain reports %d certificate(s), want 2", swapped.ChainLen)
	}
	if got := srv.ActiveChain(); got.Label != "comm-004 fixture" || got.Swaps != 1 {
		t.Errorf("ActiveChain after the swap = %+v", got)
	}

	// Property 2: the connection opened before the swap is still usable, and is
	// still the OLD chain's session — nothing was pulled out from under it.
	if _, err := before.Request("GET /dcap HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Errorf("the pre-swap connection broke when the chain was swapped: %v", err)
	}

	// Property 1: a connection opened after the swap sees the new chain. It is
	// dialled with a client that trusts the FIXTURE's root, because a client
	// trusting only the original root would (correctly) refuse — which would
	// prove the chain changed but not which chain arrived.
	after, err := dialServerTestClient(t, addr, testClientConfig{
		CACertPath:     certPath, // the fixture PEM carries its own root
		ClientCertPath: testdataPath("certs/client-cert.pem"),
		ClientKeyPath:  testdataPath("certs/client-key.pem"),
	})
	if err != nil {
		t.Fatalf("dial after the swap: %v", err)
	}
	defer after.Close()
	if got := peerLeafSHA256(t, after); got != swapped.LeafSHA256 {
		t.Errorf("post-swap connection saw leaf %s, want the fixture's %s", got, swapped.LeafSHA256)
	}
}

func TestRestoreChain_PutsTheOriginalBackVerifiably(t *testing.T) {
	addr, srv := startTestServer(t, defaultTestConfig())
	orig := srv.ActiveChain()

	certPath, keyPath := swapFixture(t, t.TempDir())
	if _, err := srv.SwapChain("comm-004 fixture", certPath, keyPath); err != nil {
		t.Fatalf("SwapChain: %v", err)
	}

	restored, err := srv.RestoreChain()
	if err != nil {
		t.Fatalf("RestoreChain: %v", err)
	}
	if restored.LeafSHA256 != orig.LeafSHA256 {
		t.Fatalf("restored leaf %s != original %s", restored.LeafSHA256, orig.LeafSHA256)
	}
	if !restored.Original {
		t.Error("the restored chain is not flagged as the original")
	}
	if got := srv.ActiveChain(); got.LeafSHA256 != orig.LeafSHA256 {
		t.Errorf("ActiveChain after restore reports %s, want %s", got.LeafSHA256, orig.LeafSHA256)
	}

	// And the bench really is usable again by a client that trusts only the
	// original root — the condition every later test case depends on.
	c, err := dialServerTestClient(t, addr, clientCfg())
	if err != nil {
		t.Fatalf("dial after the restore: %v", err)
	}
	defer c.Close()
	if got := peerLeafSHA256(t, c); got != orig.LeafSHA256 {
		t.Errorf("post-restore connection saw leaf %s, want %s", got, orig.LeafSHA256)
	}
}

func TestSwapChain_FailedLoadLeavesTheServingChainAlone(t *testing.T) {
	addr, srv := startTestServer(t, defaultTestConfig())
	orig := srv.ActiveChain()

	for _, tc := range []struct{ name, cert, key string }{
		{"missing file", filepath.Join(t.TempDir(), "nope.pem"), testdataPath("certs/server-key.pem")},
		{"not a certificate", testdataPath("certs/server-key.pem"), testdataPath("certs/server-key.pem")},
		{"key does not match the leaf", testdataPath("certs/server-cert.pem"), testdataPath("certs/client-key.pem")},
	} {
		if _, err := srv.SwapChain("bad "+tc.name, tc.cert, tc.key); err == nil {
			t.Errorf("%s: SwapChain accepted material it should have refused", tc.name)
		}
		if got := srv.ActiveChain(); got.LeafSHA256 != orig.LeafSHA256 || got.Label != orig.Label {
			t.Fatalf("%s: a refused swap changed the serving chain to %+v", tc.name, got)
		}
	}

	// An unlabelled swap is refused too: a chain nobody named cannot be
	// reported in a bundle, and a bundle that cannot say what was served is
	// not evidence.
	certPath, keyPath := swapFixture(t, t.TempDir())
	if _, err := srv.SwapChain("", certPath, keyPath); err == nil {
		t.Error("SwapChain accepted an empty label")
	}

	c, err := dialServerTestClient(t, addr, clientCfg())
	if err != nil {
		t.Fatalf("the server stopped serving after the refused swaps: %v", err)
	}
	defer c.Close()
	if got := peerLeafSHA256(t, c); got != orig.LeafSHA256 {
		t.Errorf("after the refused swaps the server presents %s, want %s", got, orig.LeafSHA256)
	}
}
