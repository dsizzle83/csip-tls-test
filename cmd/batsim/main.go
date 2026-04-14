// batsim runs an animated SunSpec Li-Ion battery storage simulator for
// development and Docker-based integration testing. Registers update every
// 5 seconds to simulate a realistic charge/discharge cycle.
//
// Usage:
//
//	batsim [-port 5021] [-kwh 10] [-wmax 5000]
//
// Models exposed: 1 (Common), 120 (Nameplate), 121 (Basic Settings),
// 103 (Three-Phase Inverter/Converter AC), 123 (Immediate Controls),
// 802 (Li-Ion Battery Base).
//
// SoC follows a 20-minute sinusoidal cycle (20–90 %).
// W = −WMax·0.8·cos(phase): negative when charging, positive when discharging.
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
	port := flag.Int("port", 5021, "TCP port to listen on")
	kwh  := flag.Float64("kwh", 10, "Energy capacity in kWh (written to Model 802 WHRtg)")
	wmax := flag.Float64("wmax", 5000, "Max charge/discharge rate in watts (written to Models 120/121/802)")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)

	log.Printf("batsim: starting animated battery on %s (%.0f kWh, WMax=%.0f W)", listenURL, *kwh, *wmax)
	log.Printf("batsim: models: 1 (Common), 120 (Nameplate), 121 (BasicSettings), 103 (InverterThreePh), 123 (ImmediateCtrl), 802 (LithiumBattery)")
	log.Printf("batsim: SoC cycles 20–90%% on a 1200 s sine; W=%.0f W peak; updates every 5 s", *wmax*0.80)

	srv, err := sim.NewBatteryServer(listenURL, *kwh, *wmax)
	if err != nil {
		log.Fatalf("batsim: %v", err)
	}
	log.Printf("batsim: listening — press Ctrl-C to stop")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("batsim: shutting down")
	srv.Stop()
}
