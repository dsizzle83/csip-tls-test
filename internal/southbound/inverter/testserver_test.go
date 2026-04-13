package inverter

// testServer builds an in-process SunSpec Modbus server for inverter tests
// using the shared sim package so tests and cmd/modsim use identical register
// layouts.

import (
	"fmt"
	"net"
	"testing"

	"csip-tls-test/internal/southbound/sim"
)

// startTestServer launches a SunSpec Modbus TCP server on a random loopback
// port. Returns the "tcp://..." URL, the live register map (for write
// verification), and a stop function.
func startTestServer(t *testing.T) (url string, regs *sim.RegisterMap, stop func()) {
	t.Helper()

	// Pick a free port — simonvetter server does not support ":0".
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	url = fmt.Sprintf("tcp://127.0.0.1:%d", port)
	srv, err := sim.NewServer(url, 5000)
	if err != nil {
		t.Fatalf("start test server: %v", err)
	}
	return url, srv.Regs, func() { srv.Stop() }
}
