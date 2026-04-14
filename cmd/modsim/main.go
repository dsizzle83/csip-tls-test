// modsim runs an animated SunSpec PV inverter simulator for development and
// Docker-based integration testing. Registers update every 5 seconds to
// simulate realistic solar power output.
//
// Usage:
//
//	modsim [-port 5020] [-wmax 5000]
//
// Models exposed: 1 (Common), 120 (Nameplate), 121 (Basic Settings),
// 122 (Extended Status), 103 (Three-Phase Inverter), 123 (Immediate Controls).
//
// W follows a 10-minute sinusoidal irradiance cycle (5–95 % of WMax).
// Control writes to Model 123 (WMaxLimPct, Conn) are accepted and held.
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
	wmax := flag.Float64("wmax", 5000, "Nameplate WMax in watts")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)

	log.Printf("modsim: starting animated PV inverter on %s (WMax=%.0f W)", listenURL, *wmax)
	log.Printf("modsim: models: 1 (Common), 120 (Nameplate), 121 (BasicSettings), 122 (ExtStatus), 103 (InverterThreePh), 123 (ImmediateCtrl)")
	log.Printf("modsim: W cycles 5–95%% of WMax on a 600 s sine; updates every 5 s")

	srv, err := sim.NewSolarServer(listenURL, *wmax)
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
