// loadsim runs an animated SunSpec home load simulator (always consuming).
//
// Usage:
//
//	loadsim [-port 5023] [-peak 5000] [-api-port 6023]
//
// API (default :6023):
//
//	GET  /state      — JSON snapshot of measurements
//	POST /inject     — override fields: {"W_W":3500.0}
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

	"csip-tls-test/sim/simapi"
	"csip-tls-test/sim/southbound"
)

func main() {
	port    := flag.Int("port", 5023, "Modbus TCP port")
	peak    := flag.Float64("peak", 5000, "Peak home load in watts")
	apiPort := flag.Int("api-port", 6023, "HTTP API port (0 to disable)")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	peakW := *peak
	log.Printf("loadsim: starting home load on %s (peak %.0f W)", listenURL, peakW)

	srv, err := sim.NewMeterServer(listenURL, peakW*0.67)
	if err != nil {
		log.Fatalf("loadsim: %v", err)
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
				frac := 0.665 + 0.335*math.Sin(2*math.Pi*t/600)
				srv.SetNetW(peakW * frac)
			}
		}
	}()

	if *apiPort != 0 {
		apiAddr := fmt.Sprintf(":%d", *apiPort)
		simapi.New(
			apiAddr,
			func() any { return srv.Snapshot("home_load") },
			srv.Inject,
			func() any { return srv.Registers() },
			func(cmd simapi.ControlCmd) error {
				switch cmd.Cmd {
				case "pause":
					srv.Pause()
					log.Printf("loadsim: animation paused")
				case "resume":
					srv.Resume()
					log.Printf("loadsim: animation resumed")
				}
				if cmd.Speed > 0 {
					srv.SetSpeed(cmd.Speed)
					log.Printf("loadsim: speed set to %.1f×", cmd.Speed)
				}
				return nil
			},
		)
	}

	log.Printf("loadsim: listening — press Ctrl-C to stop")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	close(stop)
	log.Printf("loadsim: shutting down")
	srv.Stop()
}
