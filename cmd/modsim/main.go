// modsim runs a standalone SunSpec Modbus TCP simulator using the same
// register layout as the inverter package's in-process test server.
// It is intended for development and Docker-based integration testing —
// point your Modbus client (running on the Pi or locally) at it and get
// a fully-functional 5000 W three-phase inverter without any hardware.
//
// Usage:
//
//	modsim [-port 5020] [-wmax 5000]
//
// The simulator exposes Models 1, 121, 103, and 123 starting at Modbus
// address 40001 (0-based: 40000). Initial measurement values:
//
//	W = 3000 W, V = 240.0 V, Hz = 60.00 Hz, PF = 0.968, TmpCab = 35.0 °C
//	WMax = <wmax> W, WMaxLimPct = 100 %, Conn = 1 (connected)
//
// Control writes (Model 123) are accepted and held — the simulator does not
// simulate any physical response to commands. Use this to validate that your
// client writes the right register values before connecting to real hardware.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"csip-tls-test/internal/southbound/sim"
)

func main() {
	port := flag.Int("port", 5020, "TCP port to listen on")
	wmax := flag.Float64("wmax", 5000, "Nameplate WMax in watts (written to Model 121)")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)

	log.Printf("modsim: starting SunSpec inverter simulator on %s (WMax=%.0f W)", listenURL, *wmax)
	log.Printf("modsim: models: 1 (Common), 121 (BasicSettings), 103 (Three-Phase Inverter), 123 (ImmediateCtrl)")
	log.Printf("modsim: initial state: W=3000 V=240 Hz=60 PF=0.968 Conn=1 WMaxLimPct=100%%")

	srv, err := sim.NewServer(listenURL, *wmax)
	if err != nil {
		log.Fatalf("modsim: %v", err)
	}
	log.Printf("modsim: listening — press Ctrl-C to stop")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("modsim: shutting down")
	srv.Stop()
}
