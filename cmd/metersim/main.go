// metersim runs an animated SunSpec single-phase AC grid meter simulator.
//
// Usage:
//
//	metersim [-port 5022] [-peak 5000] [-api-port 6022]
//
// API (default :6022):
//
//	GET  /state      — JSON snapshot of measurements
//	POST /inject     — override fields: {"W_W":1250.0,"V_V":241.5}
//	POST /control    — {"cmd":"pause"}, {"cmd":"resume"}, {"speed":5.0}
//	GET  /registers  — raw register dump
//	GET  /ws         — WebSocket; pushes /state every 2 s
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"csip-tls-test/internal/simapi"
	"csip-tls-test/internal/southbound/sim"
)

func main() {
	port    := flag.Int("port", 5022, "Modbus TCP port")
	peak    := flag.Float64("peak", 5000, "Peak net power magnitude in watts")
	apiPort := flag.Int("api-port", 6022, "HTTP API port (0 to disable)")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	peakW := *peak
	log.Printf("metersim: starting grid meter on %s (peak ±%.0f W)", listenURL, peakW)

	srv, err := sim.NewMeterServer(listenURL, peakW*0.4)
	if err != nil {
		log.Fatalf("metersim: %v", err)
	}

	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if srv.IsPaused() {
					continue
				}
				t := float64(time.Now().Unix()) * srv.Speed()
				srv.SetNetW(peakW * math.Sin(2*math.Pi*t/600))
			}
		}
	}()

	if *apiPort != 0 {
		apiAddr := fmt.Sprintf(":%d", *apiPort)
		simapi.New(
			apiAddr,
			func() any { return srv.Snapshot("grid_meter") },
			srv.Inject,
			func() any { return srv.Registers() },
			func(cmd simapi.ControlCmd) error {
				switch cmd.Cmd {
				case "pause":
					srv.Pause()
					log.Printf("metersim: animation paused")
				case "resume":
					srv.Resume()
					log.Printf("metersim: animation resumed")
				}
				if cmd.Speed > 0 {
					srv.SetSpeed(cmd.Speed)
					log.Printf("metersim: speed set to %.1f×", cmd.Speed)
				}
				return nil
			},
		)
	}

	log.Printf("metersim: listening — press Ctrl-C to stop")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	close(stop)
	log.Printf("metersim: shutting down")
	srv.Stop()
}
