package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/csip/scheduler"
	"csip-tls-test/internal/orchestrator"
	"csip-tls-test/internal/orchestrator/adapters"
	"csip-tls-test/internal/southbound/device"
)

type csipControlInfo struct {
	Source     string      `json:"source"`
	MRID      string      `json:"mrid,omitempty"`
	ValidUntil int64      `json:"valid_until,omitempty"`
	Base      derBaseJSON `json:"base"`
}

type hubMetrics struct {
	mu sync.RWMutex

	measurements map[string]device.Measurements

	discoveryRuns   int64
	discoveryErrors int64
	postOK          map[string]int64
	postErr         map[string]int64
	clockOffsetS    int64

	csipPrograms int
	csipControl  *csipControlInfo
}

func newHubMetrics() *hubMetrics {
	return &hubMetrics{
		measurements: make(map[string]device.Measurements),
		postOK:       make(map[string]int64),
		postErr:      make(map[string]int64),
	}
}

func (m *hubMetrics) recordMeasurement(name string, meas device.Measurements) {
	m.mu.Lock()
	m.measurements[name] = meas
	m.mu.Unlock()
}

func (m *hubMetrics) recordDiscovery(ok bool, clockOffset int64) {
	m.mu.Lock()
	m.discoveryRuns++
	if !ok {
		m.discoveryErrors++
	} else {
		m.clockOffsetS = clockOffset
	}
	m.mu.Unlock()
}

func (m *hubMetrics) recordPost(name string, err error) {
	m.mu.Lock()
	if err != nil {
		m.postErr[name]++
	} else {
		m.postOK[name]++
	}
	m.mu.Unlock()
}

func (m *hubMetrics) recordCSIPState(programs int, active *scheduler.ActiveControl) {
	m.mu.Lock()
	m.csipPrograms = programs
	if active != nil && active.Source != "default" {
		m.csipControl = &csipControlInfo{
			Source:     active.Source,
			MRID:      active.MRID,
			ValidUntil: active.ValidUntil,
			Base:      derBaseToJSON(active.Base),
		}
	} else {
		m.csipControl = nil
	}
	m.mu.Unlock()
}

// ── Log broadcaster ──────────────────────────────────────────────────────────

type logBroadcaster struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
	out     io.Writer
}

func newLogBroadcaster() *logBroadcaster {
	return &logBroadcaster{
		clients: make(map[chan string]struct{}),
		out:     os.Stderr,
	}
}

func (b *logBroadcaster) Write(p []byte) (int, error) {
	n, err := b.out.Write(p)
	line := strings.TrimRight(string(p), "\n")
	b.mu.Lock()
	for ch := range b.clients {
		select {
		case ch <- line:
		default:
		}
	}
	b.mu.Unlock()
	return n, err
}

func (b *logBroadcaster) subscribe() chan string {
	ch := make(chan string, 128)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *logBroadcaster) unsubscribe(ch chan string) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
}

// ── JSON helpers ─────────────────────────────────────────────────────────────

type derBaseJSON struct {
	ExpLimW        *int64 `json:"exp_lim_W,omitempty"`
	MaxLimW        *int64 `json:"max_lim_W,omitempty"`
	ImpLimW        *int64 `json:"imp_lim_W,omitempty"`
	GenLimW        *int64 `json:"gen_lim_W,omitempty"`
	LoadLimW       *int64 `json:"load_lim_W,omitempty"`
	FixedW         *int64 `json:"fixed_W,omitempty"`
	Connect        *bool  `json:"connect,omitempty"`
	Energize       *bool  `json:"energize,omitempty"`
	FixedPFInjectW *int64 `json:"fixed_pf_inject_pct,omitempty"`
	FixedPFAbsorbW *int64 `json:"fixed_pf_absorb_pct,omitempty"`
	FixedVarPct    *int64 `json:"fixed_var_pct,omitempty"`
}

func derBaseToJSON(b model.DERControlBase) derBaseJSON {
	j := derBaseJSON{Connect: b.OpModConnect, Energize: b.OpModEnergize}
	apW := func(ap *model.ActivePower) *int64 {
		if ap == nil {
			return nil
		}
		v := int64(math.Round(float64(ap.Value) * math.Pow10(int(ap.Multiplier))))
		return &v
	}
	j.ExpLimW = apW(b.OpModExpLimW)
	j.MaxLimW = apW(b.OpModMaxLimW)
	j.ImpLimW = apW(b.OpModImpLimW)
	j.GenLimW = apW(b.OpModGenLimW)
	j.LoadLimW = apW(b.OpModLoadLimW)
	j.FixedW = apW(b.OpModFixedW)
	if b.OpModFixedPFInjectW != nil {
		v := int64(b.OpModFixedPFInjectW.Value)
		j.FixedPFInjectW = &v
	}
	if b.OpModFixedPFAbsorbW != nil {
		v := int64(b.OpModFixedPFAbsorbW.Value)
		j.FixedPFAbsorbW = &v
	}
	if b.OpModFixedVar != nil {
		v := int64(b.OpModFixedVar.Value.Value)
		j.FixedVarPct = &v
	}
	return j
}

// ── HTTP metrics server ──────────────────────────────────────────────────────

func startMetricsServer(addr string, m *hubMetrics, ocppTracker *adapters.OCPPStateTracker, reader orchestrator.SystemReader, eng *orchestrator.Engine, lb *logBroadcaster) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.RLock()
		defer m.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		var sb strings.Builder

		sb.WriteString("# HELP csip_hub_discovery_runs_total Total discovery walk attempts\n")
		sb.WriteString("# TYPE csip_hub_discovery_runs_total counter\n")
		fmt.Fprintf(&sb, "csip_hub_discovery_runs_total %d\n", m.discoveryRuns)

		sb.WriteString("# HELP csip_hub_discovery_errors_total Discovery walks that failed\n")
		sb.WriteString("# TYPE csip_hub_discovery_errors_total counter\n")
		fmt.Fprintf(&sb, "csip_hub_discovery_errors_total %d\n", m.discoveryErrors)

		sb.WriteString("# HELP csip_hub_clock_offset_seconds CSIP server time minus local time\n")
		sb.WriteString("# TYPE csip_hub_clock_offset_seconds gauge\n")
		fmt.Fprintf(&sb, "csip_hub_clock_offset_seconds %d\n", m.clockOffsetS)

		sb.WriteString("# HELP csip_hub_telemetry_posts_total Successful telemetry POSTs per device\n")
		sb.WriteString("# TYPE csip_hub_telemetry_posts_total counter\n")
		for dev, n := range m.postOK {
			fmt.Fprintf(&sb, `csip_hub_telemetry_posts_total{device=%q} %d`+"\n", dev, n)
		}

		sb.WriteString("# HELP csip_hub_telemetry_post_errors_total Failed telemetry POSTs per device\n")
		sb.WriteString("# TYPE csip_hub_telemetry_post_errors_total counter\n")
		for dev, n := range m.postErr {
			fmt.Fprintf(&sb, `csip_hub_telemetry_post_errors_total{device=%q} %d`+"\n", dev, n)
		}

		sb.WriteString("# HELP csip_hub_device_power_W Real AC power per device (W; + export, - import)\n")
		sb.WriteString("# TYPE csip_hub_device_power_W gauge\n")
		for dev, meas := range m.measurements {
			if !math.IsNaN(meas.W) {
				fmt.Fprintf(&sb, `csip_hub_device_power_W{device=%q} %.3f`+"\n", dev, meas.W)
			}
		}

		sb.WriteString("# HELP csip_hub_device_voltage_V Phase voltage per device (V)\n")
		sb.WriteString("# TYPE csip_hub_device_voltage_V gauge\n")
		for dev, meas := range m.measurements {
			if !math.IsNaN(meas.V) {
				fmt.Fprintf(&sb, `csip_hub_device_voltage_V{device=%q} %.3f`+"\n", dev, meas.V)
			}
		}

		sb.WriteString("# HELP csip_hub_device_frequency_Hz AC frequency per device (Hz)\n")
		sb.WriteString("# TYPE csip_hub_device_frequency_Hz gauge\n")
		for dev, meas := range m.measurements {
			if !math.IsNaN(meas.Hz) {
				fmt.Fprintf(&sb, `csip_hub_device_frequency_Hz{device=%q} %.3f`+"\n", dev, meas.Hz)
			}
		}

		fmt.Fprint(w, sb.String())
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		m.mu.RLock()
		programs := m.csipPrograms
		ctrl := m.csipControl
		clockOff := m.clockOffsetS
		m.mu.RUnlock()

		sysState, _ := reader.ReadSystemState()
		lastPlan := eng.LastPlan()

		type deviceInfo struct {
			Role      string  `json:"role"`
			W         float64 `json:"W_W"`
			V         float64 `json:"V_V,omitempty"`
			Hz        float64 `json:"Hz_Hz,omitempty"`
			SOC       float64 `json:"soc_pct,omitempty"`
			MaxW      float64 `json:"max_W,omitempty"`
			Connected bool    `json:"connected"`
		}
		type powerSummary struct {
			SolarW   float64 `json:"solar_W"`
			BatteryW float64 `json:"battery_W"`
			GridW    float64 `json:"grid_W"`
			LoadW    float64 `json:"load_W"`
		}
		type decisionJSON struct {
			Rule   string `json:"rule"`
			Reason string `json:"reason"`
			Impact string `json:"impact"`
		}
		type planJSON struct {
			Timestamp string         `json:"timestamp"`
			Decisions []decisionJSON `json:"decisions"`
		}
		type statusResp struct {
			Timestamp    string                   `json:"timestamp"`
			ClockOffsetS int64                    `json:"clock_offset_s"`
			CSIPPrograms int                      `json:"csip_programs"`
			CSIPControl  *csipControlInfo         `json:"csip_control,omitempty"`
			Devices      map[string]deviceInfo    `json:"devices"`
			Power        powerSummary             `json:"power"`
			LastPlan     planJSON                 `json:"last_plan"`
			EVSEs        []orchestrator.EVSEState `json:"evse_stations,omitempty"`
		}

		devices := make(map[string]deviceInfo)
		for _, sol := range sysState.Solar {
			m.mu.RLock()
			meas := m.measurements[sol.Name]
			m.mu.RUnlock()
			di := deviceInfo{Role: "solar", W: sol.PowerW, MaxW: sol.MaxW, Connected: sol.Connected}
			if !math.IsNaN(meas.V) {
				di.V = meas.V
			}
			if !math.IsNaN(meas.Hz) {
				di.Hz = meas.Hz
			}
			devices[sol.Name] = di
		}
		for _, bat := range sysState.Batteries {
			m.mu.RLock()
			meas := m.measurements[bat.Name]
			m.mu.RUnlock()
			di := deviceInfo{Role: "battery", W: bat.PowerW, MaxW: bat.MaxDischargeW, Connected: bat.Connected}
			if !math.IsNaN(bat.SOC) {
				di.SOC = bat.SOC
			}
			if !math.IsNaN(meas.V) {
				di.V = meas.V
			}
			if !math.IsNaN(meas.Hz) {
				di.Hz = meas.Hz
			}
			devices[bat.Name] = di
		}
		m.mu.RLock()
		for name, meas := range m.measurements {
			if _, exists := devices[name]; !exists {
				di := deviceInfo{Role: "meter", Connected: true}
				if !math.IsNaN(meas.W) {
					di.W = meas.W
				}
				if !math.IsNaN(meas.V) {
					di.V = meas.V
				}
				if !math.IsNaN(meas.Hz) {
					di.Hz = meas.Hz
				}
				devices[name] = di
			}
		}
		m.mu.RUnlock()

		gridW := 0.0
		if !math.IsNaN(sysState.Grid.NetW) {
			gridW = sysState.Grid.NetW
		}
		loadW := 0.0
		if v := sysState.InferredLoadW(); !math.IsNaN(v) {
			loadW = v
		}

		var decisions []decisionJSON
		for _, d := range lastPlan.Decisions {
			decisions = append(decisions, decisionJSON{Rule: d.Rule, Reason: d.Reason, Impact: d.Impact})
		}
		if decisions == nil {
			decisions = []decisionJSON{}
		}

		resp := statusResp{
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
			ClockOffsetS: clockOff,
			CSIPPrograms: programs,
			CSIPControl:  ctrl,
			Devices:      devices,
			Power: powerSummary{
				SolarW:   sysState.TotalSolarW(),
				BatteryW: sysState.TotalBatteryW(),
				GridW:    gridW,
				LoadW:    loadW,
			},
			LastPlan: planJSON{
				Timestamp: lastPlan.Timestamp.UTC().Format(time.RFC3339),
				Decisions: decisions,
			},
		}
		if ocppTracker != nil {
			resp.EVSEs = ocppTracker.EVSEStates()
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("hub: /status encode: %v", err)
		}
	})

	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		f, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		ch := lb.subscribe()
		defer lb.unsubscribe(ch)
		for {
			select {
			case <-r.Context().Done():
				return
			case line := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", line)
				f.Flush()
			}
		}
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Printf("hub: metrics server on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("hub: metrics server: %v", err)
		}
	}()
}
