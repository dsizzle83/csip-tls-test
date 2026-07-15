// metersim runs a SunSpec single-phase AC grid meter simulator.
//
// Two modes:
//
//	 Sine mode (default): animates net power as a ±peak sine wave.
//
//	 Linked mode (-solar-api / -battery-api / -ev-api / -hub-api): polls the
//	 solar, battery, and EV charger endpoints and computes the meter reading
//	 from the energy balance at the site bus:
//
//		meter_W = load_W + ev_W - solar_W - battery_W
//
//	 where load_W is the site load, ev_W is the EV charging power (positive =
//	 consuming), solar_W is generation (positive = exporting), and battery_W is
//	 net battery power (positive = discharging, negative = charging).
//
//	 By default load_W follows a diurnal residential house-load curve (low
//	 overnight base, modest morning bump, dominant early-evening peak) scaled to
//	 -load-avg-kw (default 2 kW). The shape mirrors the hub's diurnalLoadForecast
//	 (internal/orchestrator/planner.go), evaluated at the same wall-clock local
//	 hour, so the dashboard's live "actual" load sits on the hub's planned load
//	 curve. A LoadW_W inject PINS a fixed load (scenario/replay/mayhem flows);
//	 LoadAvgW_W retargets the curve's mean and resumes it.
//
//	 EV power source priority: -hub-api (reads OCPP MeterValues via hub
//	 /status) beats -ev-api (polls evsim directly).  Use -hub-api when the
//	 meter Pi cannot reach the EV Pi's simapi port directly.
//
// API (default :6022):
//
//	GET  /state      — JSON snapshot; linked mode adds "energy_balance" section
//	POST /inject     — override fields: {"LoadW_W":3000,"LoadAvgW_W":2000,"W_W":100,"V_V":241.5}
//	POST /control    — {"cmd":"pause"}, {"cmd":"resume"}, {"speed":5.0}
//	GET  /registers  — raw register dump
//	GET  /ws         — WebSocket; pushes /state every 2 s
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	LoadEVW        float64 `json:"load_ev_W"`
}

// linkedState embeds the standard meter snapshot and adds the energy balance
// breakdown so the GUI can display all components.
type linkedState struct {
	sim.MeterState
	EnergyBalance energyBalance `json:"energy_balance"`
}

func main() {
	port := flag.Int("port", 5022, "Modbus TCP port")
	peak := flag.Float64("peak", 5000, "Peak net power magnitude in watts (sine mode only)")
	apiPort := flag.Int("api-port", 6022, "HTTP API port (0 to disable)")
	solarAPI := flag.String("solar-api", "", "Solar simapi base URL for linked mode (e.g. http://69.0.0.10:6020)")
	batteryAPI := flag.String("battery-api", "", "Battery simapi base URL for linked mode (e.g. http://69.0.0.11:6021)")
	evAPI := flag.String("ev-api", "", "EV charger simapi base URL for linked mode (e.g. http://69.0.0.14:6024)")
	hubAPI := flag.String("hub-api", "", "Hub status API for EV power via OCPP (e.g. https://69.0.0.1:9100 — lexa-api serves HTTPS self-signed on :9100, WS-B); preferred over -ev-api")
	hubTokenFile := flag.String("hub-token-file", "", "path to lexa-api's bearer token (TASK-014, AD-008); empty = no auth presented, today's behavior")
	initLoad := flag.Float64("load", 3000, "Flat site load in watts, used only when -load-avg-kw<=0 (legacy fixed-load mode)")
	loadAvgKw := flag.Float64("load-avg-kw", 2.0, "Diurnal residential baseload average in kW (linked mode): the meter presents a low-overnight / evening-peaked house-load curve scaled to this mean, mirroring the hub's diurnalLoadForecast. 0 => flat -load. Injectable: LoadAvgW_W sets the mean (W) and resumes the curve; LoadW_W pins a fixed load.")
	flag.Parse()

	// TASK-014: lexa-api's /status may require a bearer token once its
	// api_token_file is configured. Loaded once at startup — a missing or
	// empty file is not fatal, it just means no header is sent, which is
	// exactly today's behavior against a hub that isn't requiring auth yet
	// (staged rollout, AD-008).
	hubToken := ""
	if *hubTokenFile != "" {
		if data, err := os.ReadFile(*hubTokenFile); err != nil {
			log.Printf("metersim: -hub-token-file %s: %v — continuing without hub auth", *hubTokenFile, err)
		} else {
			hubToken = strings.TrimSpace(string(data))
		}
	}

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	linked := *solarAPI != "" || *batteryAPI != "" || *evAPI != "" || *hubAPI != ""

	if linked {
		loadDesc := fmt.Sprintf("diurnal avg %.2fkW", *loadAvgKw)
		if *loadAvgKw <= 0 {
			loadDesc = fmt.Sprintf("flat %.0fW", *initLoad)
		}
		log.Printf("metersim: linked mode on %s  solar=%s  battery=%s  ev=%s  hub=%s  load=%s",
			listenURL, *solarAPI, *batteryAPI, *evAPI, *hubAPI, loadDesc)
	} else {
		log.Printf("metersim: sine mode on %s (peak ±%.0f W)", listenURL, *peak)
	}

	srv, err := sim.NewMeterServer(listenURL, 0)
	if err != nil {
		log.Fatalf("metersim: %v", err)
	}

	// Shared linked-mode state — protected by mu.
	//
	// The site load is diurnal by default: currentLoadW evaluates the
	// residential house-load curve (residentialLoadW, mirroring the hub's
	// diurnalLoadForecast) at the current wall-clock local hour, scaled to
	// loadAvgW. A LoadW_W inject PINS a fixed load (pinnedW non-nil), which the
	// scenario/replay/mayhem flows rely on; LoadAvgW_W changes the mean and
	// resumes the curve. loadAvgW<=0 selects the legacy flat -load setpoint.
	var mu sync.Mutex
	loadAvgW := *loadAvgKw * 1000
	var pinnedW *float64
	if loadAvgW <= 0 {
		v := *initLoad
		pinnedW = &v
	}
	var lastSolarW, lastBattW, lastEVW float64

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
			pinnedW = &f // pin to a fixed load (overrides the diurnal curve)
			mu.Unlock()
			log.Printf("metersim: load pinned to %.0f W (diurnal curve overridden)", f)
			delete(raw, "LoadW_W")
		}
		if v, ok := raw["LoadAvgW_W"]; ok {
			f, err := v.Float64()
			if err != nil {
				return fmt.Errorf("inject LoadAvgW_W: %w", err)
			}
			mu.Lock()
			loadAvgW = f
			pinnedW = nil // resume the diurnal curve at the new mean
			mu.Unlock()
			log.Printf("metersim: diurnal load mean set to %.0f W (curve resumed)", f)
			delete(raw, "LoadAvgW_W")
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
					var eW float64
					if *hubAPI != "" {
						eW = fetchHubEVW(*hubAPI, hubToken)
					} else {
						eW = fetchEVW(*evAPI)
					}
					mu.Lock()
					lW := currentLoadW(time.Now(), pinnedW, loadAvgW)
					lastSolarW = sW
					lastBattW = bW
					lastEVW = eW
					mu.Unlock()
					// EV charging is a site load (increases grid import).
					net := lW + eW - sW - bW
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
		api := simapi.New(
			apiAddr,
			func() any {
				snap := srv.Snapshot("grid_meter")
				if !linked {
					return snap
				}
				mu.Lock()
				lw := currentLoadW(time.Now(), pinnedW, loadAvgW)
				sw, bw, ew := lastSolarW, lastBattW, lastEVW
				mu.Unlock()
				return linkedState{
					MeterState: snap,
					EnergyBalance: energyBalance{
						LoadW_W:        lw,
						SourceSolarW:   sw,
						SourceBatteryW: bw,
						LoadEVW:        ew,
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
		// QA fault injection (invert_sign / nan_sentinel / latency / exception_code).
		api.SetFaultFn(srv.ApplyFault)
		// Tee logs into the API ring so the dashboard's Logs tab can stream them.
		log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))
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

// fetchEVW retrieves the current charging power from an evsim /state endpoint.
// Returns 0 on any error (fails safe — no phantom load).
func fetchEVW(baseURL string) float64 {
	if baseURL == "" {
		return 0
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/state")
	if err != nil {
		log.Printf("metersim: fetchEVW %s: %v", baseURL, err)
		return 0
	}
	defer resp.Body.Close()
	var state struct {
		Battery struct {
			PowerW float64 `json:"power_W"`
		} `json:"battery"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		log.Printf("metersim: fetchEVW decode %s: %v", baseURL, err)
		return 0
	}
	return state.Battery.PowerW
}

// fetchHubEVW sums power_W across all EVSE stations reported by the hub's
// /status endpoint.  Uses hub OCPP MeterValues data, which is more reliable
// than polling the EV Pi's simapi port directly.
// Returns 0 on any error (fails safe — no phantom load).
//
// token is the bearer token to present (TASK-014); empty sends no
// Authorization header, matching a hub that isn't requiring auth yet.
func fetchHubEVW(baseURL, token string) float64 {
	if baseURL == "" {
		return 0
	}
	// WS-B: lexa-api serves HTTPS on :9100 with a per-device self-signed leaf.
	// Skip verification — air-gapped bench, trusted link, no CA to validate
	// against. The transport handles an https base URL regardless of default
	// (the flag value is operator-supplied at deploy). Ignored for http://.
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/status", nil)
	if err != nil {
		log.Printf("metersim: fetchHubEVW %s: %v", baseURL, err)
		return 0
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("metersim: fetchHubEVW %s: %v", baseURL, err)
		return 0
	}
	defer resp.Body.Close()
	var status struct {
		EVSEStations []struct {
			PowerW float64 `json:"power_W"`
		} `json:"evse_stations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		log.Printf("metersim: fetchHubEVW decode %s: %v", baseURL, err)
		return 0
	}
	var total float64
	for _, s := range status.EVSEStations {
		total += s.PowerW
	}
	return total
}

// ── Diurnal residential baseload ────────────────────────────────────────────
//
// The meter presents a realistic house-load curve so the hub's energy-balance
// inference (load = solar + battery + grid − ev) recovers a non-zero, evening-
// peaked demand instead of a flat baseline. The shape and mean-normalisation
// mirror lexa-hub internal/orchestrator/planner.go (residentialLoadShape /
// diurnalLoadForecast) so the dashboard's live "actual" load sits on the hub's
// planned load curve: both evaluate avg × shape(localHour) / shapeMean at the
// same wall-clock local hour.

// currentLoadW resolves the site load (W) at time t: a pinned fixed value when
// pinnedW is non-nil (LoadW_W inject / legacy flat mode), else the diurnal
// residential curve scaled to avgW.
func currentLoadW(t time.Time, pinnedW *float64, avgW float64) float64 {
	if pinnedW != nil {
		return *pinnedW
	}
	return residentialLoadW(t, avgW)
}

// residentialLoadW returns the instantaneous residential site load (W) at the
// local wall-clock hour of t, scaled so its 24 h mean equals avgW. Mirrors the
// hub's diurnalLoadForecast. Deterministic: a pure function of t and avgW.
func residentialLoadW(t time.Time, avgW float64) float64 {
	if avgW <= 0 || residentialShapeMean <= 0 {
		return 0
	}
	lt := t.Local()
	hour := float64(lt.Hour()) + float64(lt.Minute())/60 + float64(lt.Second())/3600
	return avgW * residentialLoadShape(hour) / residentialShapeMean
}

// residentialLoadShape is the UNNORMALISED residential load factor at a local
// hour-of-day — a low overnight base, a modest morning bump, and a dominant
// early-evening peak (the demand side of the "duck curve"). Copied verbatim
// from lexa-hub internal/orchestrator/planner.go so the sim's live load and the
// hub's plan share one shape; only the shape matters (residentialLoadW scales it
// to the configured mean).
func residentialLoadShape(hour float64) float64 {
	base := 0.5
	morning := 0.7 * gaussianBump(hour, 7.5, 1.5)
	midday := 0.25 * gaussianBump(hour, 13.0, 2.5)
	evening := 1.8 * gaussianBump(hour, 19.5, 2.5)
	return base + morning + midday + evening
}

// gaussianBump is an un-normalised Gaussian (peak 1.0 at mu) shaping the load
// curve's morning/evening humps.
func gaussianBump(x, mu, sigma float64) float64 {
	d := (x - mu) / sigma
	return math.Exp(-0.5 * d * d)
}

// residentialShapeMean is the 24 h mean of residentialLoadShape, sampled at the
// hub's 5-min resolution (288 steps) so residentialLoadW's scaling reproduces
// the hub's diurnalLoadForecast mean exactly.
var residentialShapeMean = func() float64 {
	const n = 288
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += residentialLoadShape(24.0 * float64(i) / float64(n))
	}
	return sum / float64(n)
}()
