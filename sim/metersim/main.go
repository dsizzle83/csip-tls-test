// metersim runs a SunSpec single-phase AC grid meter simulator.
//
// Two modes:
//
//  Sine mode (default): animates net power as a ±peak sine wave.
//
//  Linked mode (-solar-api / -battery-api): polls the solar and battery
//  simapi REST endpoints for their current W readings and computes the
//  meter reading from the energy balance at the site bus:
//
//	meter_W = load_W - solar_W - battery_W
//
//  where load_W is the total site load (home + EV, settable via inject).
//
// API (default :6022):
//
//	GET  /state      — JSON snapshot; linked mode adds "energy_balance" section
//	POST /inject     — override fields: {"LoadW_W":3000,"W_W":100,"V_V":241.5}
//	POST /control    — {"cmd":"pause"}, {"cmd":"resume"}, {"speed":5.0}
//	GET  /registers  — raw register dump
//	GET  /ws         — WebSocket; pushes /state every 2 s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"csip-tls-test/sim/simapi"
	sim "csip-tls-test/sim/southbound"
)

// energyBalance is the linked-mode extension added to the state snapshot.
type energyBalance struct {
	LoadW_W        float64 `json:"load_W"`
	SourceSolarW   float64 `json:"source_solar_W"`
	SourceBatteryW float64 `json:"source_battery_W"`
}

// linkedState embeds the standard meter snapshot and adds the energy balance
// breakdown so the GUI can display all three components.
type linkedState struct {
	sim.MeterState
	EnergyBalance energyBalance `json:"energy_balance"`
}

func main() {
	port       := flag.Int("port", 5022, "Modbus TCP port")
	peak       := flag.Float64("peak", 5000, "Peak net power magnitude in watts (sine mode only)")
	apiPort    := flag.Int("api-port", 6022, "HTTP API port (0 to disable)")
	solarAPI   := flag.String("solar-api", "", "Solar simapi base URL for linked mode (e.g. http://69.0.0.10:6020)")
	batteryAPI := flag.String("battery-api", "", "Battery simapi base URL for linked mode (e.g. http://69.0.0.11:6021)")
	initLoad   := flag.Float64("load", 3000, "Initial site load in watts (linked mode); injectable via LoadW_W")
	flag.Parse()

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	linked := *solarAPI != "" || *batteryAPI != ""

	if linked {
		log.Printf("metersim: linked mode on %s  solar=%s  battery=%s  load=%.0fW",
			listenURL, *solarAPI, *batteryAPI, *initLoad)
	} else {
		log.Printf("metersim: sine mode on %s (peak ±%.0f W)", listenURL, *peak)
	}

	srv, err := sim.NewMeterServer(listenURL, 0)
	if err != nil {
		log.Fatalf("metersim: %v", err)
	}

	// Shared linked-mode state — protected by mu.
	var mu sync.Mutex
	loadW := *initLoad
	var lastSolarW, lastBattW float64

	// injectFn intercepts LoadW_W (linked-mode load setpoint) and forwards
	// remaining fields (W_W, V_V, Hz_Hz) to the Modbus register layer.
	injectFn := func(body []byte) error {
		var raw map[string]json.Number
		if err := json.Unmarshal(body, &raw); err != nil {
			return fmt.Errorf("inject: %w", err)
		}
		if v, ok := raw["LoadW_W"]; ok {
			f, err := v.Float64()
			if err != nil {
				return fmt.Errorf("inject LoadW_W: %w", err)
			}
			mu.Lock()
			loadW = f
			mu.Unlock()
			log.Printf("metersim: load set to %.0f W", f)
			delete(raw, "LoadW_W")
		}
		if len(raw) == 0 {
			return nil
		}
		b, _ := json.Marshal(raw)
		return srv.Inject(b)
	}

	stop := make(chan struct{})

	if linked {
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
					sW := fetchW(*solarAPI)
					bW := fetchW(*batteryAPI)
					mu.Lock()
					lW := loadW
					lastSolarW = sW
					lastBattW = bW
					mu.Unlock()
					net := lW - sW - bW
					srv.SetNetW(net)
				}
			}
		}()
	} else {
		peakW := *peak
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
	}

	if *apiPort != 0 {
		apiAddr := fmt.Sprintf(":%d", *apiPort)
		simapi.New(
			apiAddr,
			func() any {
				snap := srv.Snapshot("grid_meter")
				if !linked {
					return snap
				}
				mu.Lock()
				lw, sw, bw := loadW, lastSolarW, lastBattW
				mu.Unlock()
				return linkedState{
					MeterState: snap,
					EnergyBalance: energyBalance{
						LoadW_W:        lw,
						SourceSolarW:   sw,
						SourceBatteryW: bw,
					},
				}
			},
			injectFn,
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

// fetchW retrieves the current W_W measurement from a simapi /state endpoint.
// Returns 0 on any error so the meter fails safe (no phantom generation).
func fetchW(baseURL string) float64 {
	if baseURL == "" {
		return 0
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/state")
	if err != nil {
		log.Printf("metersim: fetchW %s: %v", baseURL, err)
		return 0
	}
	defer resp.Body.Close()
	var state struct {
		Measurements struct {
			W_W float64 `json:"W_W"`
		} `json:"measurements"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		log.Printf("metersim: fetchW decode %s: %v", baseURL, err)
		return 0
	}
	return state.Measurements.W_W
}
