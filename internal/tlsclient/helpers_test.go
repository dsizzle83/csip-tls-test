package tlsclient

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"csip-tls-test/internal/tlsserver"
	"csip-tls-test/internal/wolfssl"
)

// TestMain initializes wolfSSL once per test binary. Same rationale as
// the tlsserver package's TestMain — wolfSSL_Init is process-global C
// state and double-init is undefined behavior.
//
// Both the unit tests in parsing_test.go and the integration tests
// in client_test.go share this TestMain.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

// testdataPath returns an absolute path to a file under the package's
// testdata/ directory.
func testdataPath(rel string) string {
	abs, err := filepath.Abs(filepath.Join("testdata", rel))
	if err != nil {
		panic(err)
	}
	return abs
}

// startInProcessServer brings up a tlsserver.Server on a random
// loopback port for the duration of a single test, registering all
// teardown via t.Cleanup. Returns the listen address the test client
// should connect to.
//
// This is the key inversion in client testing: rather than asking
// "is my server reachable from a remote client?", we ask "given a
// known-good server, does my client behave correctly?". The server
// becomes a test fixture for the client. Both sides share the same
// cgo wolfSSL bridge so there's no possibility of impedance mismatch
// from independent implementations.
func startInProcessServer(t *testing.T) (addr string) {
	t.Helper()

	srv, err := tlsserver.New(tlsserver.Config{
		CACertPath:     testdataPath("certs/ca-cert.pem"),
		ServerCertPath: testdataPath("certs/server-cert.pem"),
		ServerKeyPath:  testdataPath("certs/server-key.pem"),
	})
	if err != nil {
		t.Fatalf("tlsserver.New: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		srv.Close()
		t.Fatalf("Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(lis)
	}()

	t.Cleanup(func() {
		_ = lis.Close()
		if err := <-serveErr; err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
		srv.Close()
	})

	return lis.Addr().String()
}

// goodClientConfig returns a Config pointing at the standard test
// fixture certs, with ServerAddr set to the given address.
func goodClientConfig(addr string) Config {
	return Config{
		ServerAddr:     addr,
		CACertPath:     testdataPath("certs/ca-cert.pem"),
		ClientCertPath: testdataPath("certs/client-cert.pem"),
		ClientKeyPath:  testdataPath("certs/client-key.pem"),
	}
}

// startInProcessServerWithHandler brings up a tlsserver.Server with a
// custom http.Handler for testing persistent-connection scenarios.
func startInProcessServerWithHandler(t *testing.T, h http.Handler) (addr string) {
	t.Helper()

	srv, err := tlsserver.New(tlsserver.Config{
		CACertPath:     testdataPath("certs/ca-cert.pem"),
		ServerCertPath: testdataPath("certs/server-cert.pem"),
		ServerKeyPath:  testdataPath("certs/server-key.pem"),
	})
	if err != nil {
		t.Fatalf("tlsserver.New: %v", err)
	}
	srv.Handler = h

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		srv.Close()
		t.Fatalf("Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(lis)
	}()

	t.Cleanup(func() {
		_ = lis.Close()
		if err := <-serveErr; err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
		srv.Close()
	})

	return lis.Addr().String()
}
