// modsim runs an animated SunSpec PV inverter simulator with a built-in HTTP
// API for GUI inspection and test injection.
//
// Usage:
//
//	modsim [-port 5020] [-wmax 5000] [-api-port 6020]
//
// Models exposed: 1 (Common), 120 (Nameplate), 121 (Basic Settings),
// 122 (Extended Status), 103 (Three-Phase Inverter), 123 (Immediate Controls).
//
// API (default :6020):
//
//	GET  /state      — JSON snapshot of all decoded measurements + controls
//	POST /inject     — override fields: {"W_W":4500.0,"Conn":0,...}
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
	port    := flag.Int("port", 5020, "Modbus TCP port")
	wmax    := flag.Float64("wmax", 5000, "Nameplate WMax in watts")
	apiPort := flag.Int("api-port", 6020, "HTTP API port (0 to disable)")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	log.Printf("modsim: starting animated PV inverter on %s (WMax=%.0f W)", listenURL, *wmax)

	srv, err := sim.NewSolarServer(listenURL, *wmax)
	if err != nil {
		log.Fatalf("modsim: %v", err)
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
					log.Printf("modsim: animation paused")
				case "resume":
					srv.Resume()
					log.Printf("modsim: animation resumed")
				case "reset":
					srv.Resume()
				}
				if cmd.Speed > 0 {
					srv.SetSpeed(cmd.Speed)
					log.Printf("modsim: animation speed set to %.1f×", cmd.Speed)
				}
				return nil
			},
		)
	}

	log.Printf("modsim: listening — press Ctrl-C to stop")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("modsim: shutting down")
	srv.Stop()
}
