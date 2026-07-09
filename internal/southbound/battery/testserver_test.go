package battery

// testServer builds an in-process SunSpec Modbus server for battery tests
// using sim.NewBatteryServer so the register layout matches production.

import (
	"fmt"
	"net"
	"testing"
	"time"

	"csip-tls-test/sim/southbound"
)

const defaultTimeout = 2 * time.Second

const (
	testWMaxKwh = 10.0   // kWh capacity
	testWMaxW   = 5000.0 // peak power watts
)

// startBatteryTestServer starts an in-process battery Modbus server.
// It returns the "tcp://..." URL, the live RegisterMap (for write verification),
// and a stop function.
func startBatteryTestServer(t *testing.T) (url string, regs *sim.RegisterMap, stop func()) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	url = fmt.Sprintf("tcp://127.0.0.1:%d", port)
	srv, err := sim.NewBatteryServer(url, testWMaxKwh, testWMaxW)
	if err != nil {
		t.Fatalf("start battery test server: %v", err)
	}
	return url, srv.Regs, func() { srv.Stop() }
}

// connectBattery creates a Battery backed by the in-process test server.
func connectBattery(t *testing.T) (*Battery, *sim.RegisterMap, func()) {
	t.Helper()
	url, regs, stopServer := startBatteryTestServer(t)

	b, err := New(url, defaultTimeout, 1)
	if err != nil {
		stopServer()
		t.Fatalf("New battery: %v", err)
	}
	return b, regs, func() {
		b.Close()
		stopServer()
	}
}
