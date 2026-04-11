//go:build integration

package integration_test

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/identity"
	"csip-tls-test/internal/gridsim"
	"csip-tls-test/internal/tlsclient"
	"csip-tls-test/internal/tlsserver"
	"csip-tls-test/internal/wolfssl"
)

// TestMain initializes wolfSSL once for the integration build. wolfSSL_Init
// is process-global C state; calling it more than once per process is
// undefined behavior.
//
// This TestMain only compiles when -tags=integration is set, so plain
// `go test ./tests/` (no tag) runs the pure-Go tests without cgo.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

// certDir returns the absolute path to the tlsclient test cert fixtures.
// Both client and server certs in that directory share the same test CA,
// so they work together for an in-process mTLS handshake.
func certDir(t *testing.T) string {
	t.Helper()
	// go test sets the working directory to the package under test (tests/).
	abs, err := filepath.Abs("../internal/tlsclient/testdata/certs")
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// lfdiFromPEM reads a PEM-encoded certificate file and returns the LFDI
// string derived from it per IEEE 2030.5-2018 §6.3.4.
func lfdiFromPEM(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cert %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert %s: %v", path, err)
	}
	lfdi, _ := identity.FromCertificate(cert)
	return lfdi.String()
}

// TestFullStack_WolfSSLFetcherWalksGridsim wires all four layers together:
//
//	discovery.Walker → WolfSSLFetcher → wolfSSL mTLS → tlsserver → gridsim.Handler()
//
// This is the Milestone 3 Step D test. It runs with -tags=integration
// because it requires cgo (wolfSSL). The LFDI is derived from the static
// test client cert rather than the live peer cert (Step A adds that).
func TestFullStack_WolfSSLFetcherWalksGridsim(t *testing.T) {
	dir := certDir(t)
	clientCertPath := filepath.Join(dir, "client-cert.pem")

	// Derive LFDI from the test client cert. gridsim must use the same
	// value so the walker's EndDevice match succeeds.
	lfdi := lfdiFromPEM(t, clientCertPath)

	// Boot gridsim with the known LFDI.
	sim := gridsim.NewServer(lfdi)

	// Start tlsserver with gridsim wired in as the HTTP handler.
	srv, err := tlsserver.New(tlsserver.Config{
		CACertPath:     filepath.Join(dir, "ca-cert.pem"),
		ServerCertPath: filepath.Join(dir, "server-cert.pem"),
		ServerKeyPath:  filepath.Join(dir, "server-key.pem"),
	})
	if err != nil {
		t.Fatalf("tlsserver.New: %v", err)
	}
	srv.Handler = sim.Handler()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		srv.Close()
		t.Fatalf("Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()
	t.Cleanup(func() {
		_ = lis.Close()
		if err := <-serveErr; err != nil {
			t.Errorf("Serve: %v", err)
		}
		srv.Close()
	})

	addr := lis.Addr().String()

	// WolfSSLFetcher: redials per Get call, same CA / client cert as above.
	fetcher, err := tlsclient.NewWolfSSLFetcher(tlsclient.Config{
		ServerAddr:     addr,
		CACertPath:     filepath.Join(dir, "ca-cert.pem"),
		ClientCertPath: clientCertPath,
		ClientKeyPath:  filepath.Join(dir, "client-key.pem"),
	})
	if err != nil {
		t.Fatalf("NewWolfSSLFetcher: %v", err)
	}
	defer fetcher.Free()

	// Run the full discovery walk over the mTLS stack.
	walker := discovery.NewWalker(fetcher, lfdi)
	tree, err := walker.Discover("/dcap")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// ── DeviceCapability ─────────────────────────────────────────
	if tree.DeviceCapability == nil {
		t.Fatal("DeviceCapability is nil")
	}
	if tree.DeviceCapability.Href != "/dcap" {
		t.Errorf("dcap href = %q", tree.DeviceCapability.Href)
	}

	// ── EndDevice LFDI match ──────────────────────────────────────
	if tree.SelfDevice == nil {
		t.Fatal("SelfDevice is nil — LFDI match failed")
	}
	if tree.SelfDevice.LFDI != lfdi {
		t.Errorf("SelfDevice.LFDI = %q, want %q", tree.SelfDevice.LFDI, lfdi)
	}

	// ── DERPrograms ───────────────────────────────────────────────
	if len(tree.Programs) == 0 {
		t.Fatal("no DERPrograms discovered")
	}
	ps := tree.Programs[0]
	if ps.DefaultControl == nil {
		t.Fatal("DefaultDERControl is nil")
	}
	if ps.DefaultControl.DERControlBase.OpModExpLimW == nil {
		t.Fatal("DefaultDERControl missing OpModExpLimW")
	}

	t.Logf("cipher: ECDHE-ECDSA-AES128-CCM-8 (verified by tlsserver tests)")
	t.Logf("SelfDevice LFDI: %s", tree.SelfDevice.LFDI)
	t.Logf("Programs: %d, DefaultDERControl OpModExpLimW: %dW",
		len(tree.Programs), ps.DefaultControl.DERControlBase.OpModExpLimW.Value)
}
