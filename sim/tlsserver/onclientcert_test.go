//go:build integration

package tlsserver

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"sync"
	"testing"

	"csip-tls-test/internal/csip/identity"
)

// TestOnClientCert_FiresWithCorrectDER verifies that the OnClientCert callback
// receives the peer cert DER bytes that decode to the expected LFDI.
// This is the Step A proof: the server extracts LFDI from the live cert, not
// from a pre-loaded file.
func TestOnClientCert_FiresWithCorrectDER(t *testing.T) {
	// Pre-compute the expected LFDI from the test client cert on disk.
	certData, err := os.ReadFile(testdataPath("certs/client-cert.pem"))
	if err != nil {
		t.Fatalf("read client cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("no PEM block")
	}
	wantCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	wantLFDI, _ := identity.FromCertificate(wantCert)

	// Capture the DER the server receives via OnClientCert.
	var (
		mu      sync.Mutex
		gotDER  []byte
		gotLFDI identity.LFDI
	)

	cfg := defaultTestConfig()
	addr, srv := startTestServer(t, cfg)
	srv.OnClientCert = func(der []byte) {
		lfdi, _ := identity.FromCertificateDER(der)
		mu.Lock()
		gotDER = der
		gotLFDI = lfdi
		mu.Unlock()
	}

	// Connect with the client cert; send a minimal request so handleConn completes.
	c, err := dialServerTestClient(t, addr, testClientConfig{
		CACertPath:     testdataPath("certs/ca-cert.pem"),
		ClientCertPath: testdataPath("certs/client-cert.pem"),
		ClientKeyPath:  testdataPath("certs/client-key.pem"),
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = c.Request("GET /dcap HTTP/1.1\r\nHost: x\r\n\r\n")
	c.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(gotDER) == 0 {
		t.Fatal("OnClientCert was not called — PeerCertificateDER returned nil")
	}
	if gotLFDI != wantLFDI {
		t.Errorf("LFDI from live cert = %s, want %s", gotLFDI, wantLFDI)
	}
	t.Logf("OnClientCert fired: %d bytes, LFDI=%s", len(gotDER), gotLFDI)
}
