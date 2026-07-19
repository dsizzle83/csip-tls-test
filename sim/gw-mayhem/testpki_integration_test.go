//go:build integration

package gwmayhem

// testpki_integration_test.go points the loopback integration tests at the
// COMMITTED certs/mbaps tree (the same tree the mbtls fixture + ssm-conformance
// suites use) — its role certs, its full negative-fixture matrix, and its device
// server leaf (which carries a 127.0.0.1 SAN, and mbtls does no hostname check
// anyway). The committed expired / wrong-CA leaves are the ones the TLS layer
// provably rejects (ssm-conformance TCP-52), so the cert-authz family's
// handshake-layer assertions have real teeth here. The tree's keys are gitignored;
// this is a desktop/bench integration test (make test-integration), which
// regenerates them via make gen-mbaps-certs — a fresh checkout without keys skips.

import (
	"os"
	"path/filepath"
	"testing"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
)

// TestMain initialises wolfSSL once for the whole integration binary.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

type integrationPKI struct {
	dir            string
	serverCertFile string
	serverKeyFile  string
	caFile         string
}

// newIntegrationPKI resolves the committed certs/mbaps tree, skipping if its
// gitignored keys are absent (a fresh checkout — run make gen-mbaps-certs).
func newIntegrationPKI(t *testing.T) integrationPKI {
	t.Helper()
	dir := filepath.Join("..", "..", "certs", "mbaps")
	p := integrationPKI{
		dir:            dir,
		serverCertFile: filepath.Join(dir, "dev-server-cert.pem"),
		serverKeyFile:  filepath.Join(dir, "dev-server-key.pem"),
		caFile:         filepath.Join(dir, "ca-cert.pem"),
	}
	// The loopback needs the server key; the world needs the role client keys. All
	// are gitignored — a run without them is a checkout that never ran gen-mbaps-certs.
	for _, f := range []string{
		p.serverKeyFile,
		filepath.Join(dir, "clients", "grid-service-key.pem"),
		filepath.Join(dir, "negative", "wrong-ca-key.pem"),
	} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("committed certs/mbaps keys absent (%s) — run make gen-mbaps-certs", filepath.Base(f))
		}
	}
	return p
}

// serverProfile is the loopback's mbtls server profile: the committed device leaf,
// trusting the committed client CA to verify role certs.
func (p integrationPKI) serverProfile() mbtls.Profile {
	return mbtls.DefaultServerProfile(p.caFile, p.serverCertFile, p.serverKeyFile)
}

// world builds a gw-mayhem world pointed at addr over the committed PKI (the
// manifest device CA verifies the loopback's committed server leaf).
func (p integrationPKI) world(t *testing.T, addr string) *gwWorld {
	t.Helper()
	w, err := NewWorld(addr, p.dir, "")
	if err != nil {
		t.Fatalf("NewWorld: %v", err)
	}
	return w
}
