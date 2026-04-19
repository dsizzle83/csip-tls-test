package meter

// testserver_test.go — in-process SunSpec meter Modbus server for unit tests.

import (
	"fmt"
	"net"
	"testing"
	"time"

	"csip-tls-test/sim/southbound"
)

const defaultTimeout = 2 * time.Second

// startMeterTestServer starts an in-process SunSpec meter simulator.
// Returns the "tcp://..." URL, the MeterServer (for register access), and a
// stop function.
func startMeterTestServer(t *testing.T, netW float64) (url string, srv *sim.MeterServer, stop func()) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	url = fmt.Sprintf("tcp://127.0.0.1:%d", port)
	srv, err = sim.NewMeterServer(url, netW)
	if err != nil {
		t.Fatalf("start meter test server: %v", err)
	}
	return url, srv, func() { srv.Stop() }
}

// connectMeter creates a Meter backed by the in-process test server.
func connectMeter(t *testing.T, netW float64) (*Meter, *sim.MeterServer, func()) {
	t.Helper()
	url, srv, stopServer := startMeterTestServer(t, netW)

	m, err := New(url, defaultTimeout, 1)
	if err != nil {
		stopServer()
		t.Fatalf("New meter: %v", err)
	}
	return m, srv, func() {
		m.Close()
		stopServer()
	}
}
