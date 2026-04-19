// batsim runs an animated SunSpec Li-Ion battery storage simulator with a
// built-in HTTP API for GUI inspection and test injection.
//
// Usage:
//
//	batsim [-port 5021] [-kwh 10] [-wmax 5000] [-api-port 6021]
//
// Models exposed: 1 (Common), 120 (Nameplate), 121 (BasicSettings),
// 103 (Three-Phase Inverter/Converter AC), 123 (Immediate Controls),
// 802 (Li-Ion Battery Base).
//
// API (default :6021):
//
//	GET  /state      — JSON snapshot: measurements + battery SoC/SoH/ChaSt + controls
//	POST /inject     — override fields: {"SoC_pct":85.0,"W_W":-3000.0,...}
//	POST /control    — {"cmd":"pause"}, {"cmd":"resume"}, {"speed":10.0}
//	GET  /registers  — raw Modbus register dump
//	GET  /ws         — WebSocket; pushes /state every 2 s
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"csip-tls-test/sim/simapi"
	"csip-tls-test/sim/southbound"
)

func main() {
	port    := flag.Int("port", 5021, "Modbus TCP port")
	kwh     := flag.Float64("kwh", 10, "Energy capacity in kWh")
	wmax    := flag.Float64("wmax", 5000, "Max charge/discharge rate in watts")
	apiPort := flag.Int("api-port", 6021, "HTTP API port (0 to disable)")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	log.Printf("batsim: starting animated battery on %s (%.0f kWh, WMax=%.0f W)", listenURL, *kwh, *wmax)

	srv, err := sim.NewBatteryServer(listenURL, *kwh, *wmax)
	if err != nil {
		log.Fatalf("batsim: %v", err)
	}

	if *apiPort != 0 {
		apiAddr := fmt.Sprintf(":%d", *apiPort)
		simapi.New(
			apiAddr,
			func() any { return srv.Snapshot() },
			srv.Inject,
			func() any { return srv.Registers() },
			func(cmd simapi.ControlCmd) error {
				switch cmd.Cmd {
				case "pause":
					srv.Pause()
					log.Printf("batsim: animation paused")
				case "resume":
					srv.Resume()
					log.Printf("batsim: animation resumed")
				case "reset":
					srv.Resume()
				}
				if cmd.Speed > 0 {
					srv.SetSpeed(cmd.Speed)
					log.Printf("batsim: animation speed set to %.1f×", cmd.Speed)
				}
				return nil
			},
		)
	}

	log.Printf("batsim: listening — press Ctrl-C to stop")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("batsim: shutting down")
	srv.Stop()
}
