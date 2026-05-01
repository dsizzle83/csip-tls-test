// hub is the long-running CSIP DER hub process for a Raspberry Pi.
//
// It wires together the northbound (CSIP / IEEE 2030.5) and southbound
// (Modbus / SunSpec) stacks via the orchestrator engine:
//
//	wolfSSL fetcher → discovery walker → engine.SetCSIPPrograms()
//	                                           ↓
//	                               Optimizer.Optimize(SystemState)
//	                                           ↓
//	                     BatteryActuator / SolarActuator / EVSEActuator
//
// Goroutines:
//
//	discoveryLoop      — re-walks /dcap every N seconds; calls engine.SetCSIPPrograms();
//	                     drives the response POST state machine.
//	telemetryLoop      — registers one MUP per device at startup;
//	                     consumes registry.Updates() and POSTs per-device readings.
//	engine (internal)  — evaluates optimizer every EngineIntervalS; applies controls.
//	registry (internal)— polls Modbus every PollIntervalS; emits MeasurementUpdates.
//	batteryMetrics     — refreshes SOC/SOH from Modbus battery models.
//
// Response POST state machine (GEN.044 / CORE-022):
//
//	Received  (1): posted once when a DERControl event is first seen.
//	Started   (2): posted when the scheduler first makes the event active.
//	Completed (3): posted when the event expires or is superseded.
//
// Usage:
//
//	hub [-config hub.json]
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/identity"
	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/csip/scheduler"
	"csip-tls-test/internal/ocppserver"
	"csip-tls-test/internal/orchestrator"
	"csip-tls-test/internal/orchestrator/adapters"
	"csip-tls-test/internal/southbound/battery"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/inverter"
	"csip-tls-test/internal/southbound/meter"
	"csip-tls-test/internal/southbound/registry"
	"csip-tls-test/internal/tlsclient"
	"csip-tls-test/internal/wolfssl"
)

func main() {
	configPath := flag.String("config", "hub.json", "path to JSON config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("hub: load config %s: %v", *configPath, err)
	}

	wolfssl.Init()
	defer wolfssl.Cleanup()

	tlsCfg := tlsclient.Config{
		ServerAddr:     cfg.Server,
		CACertPath:     cfg.CACert,
		ClientCertPath: cfg.ClientCert,
		ClientKeyPath:  cfg.ClientKey,
	}

	// WolfSSLFetcher is not concurrent-safe (single wolfSSL session per
	// instance). Give each goroutine its own instance so their Dial/Get/Post
	// calls never interleave on the same SSL object.
	fetcherDisc, err := tlsclient.NewWolfSSLFetcher(tlsCfg)
	if err != nil {
		log.Fatalf("hub: init fetcher (discovery): %v", err)
	}
	defer fetcherDisc.Free()

	fetcherTelm, err := tlsclient.NewWolfSSLFetcher(tlsCfg)
	if err != nil {
		log.Fatalf("hub: init fetcher (telemetry): %v", err)
	}
	defer fetcherTelm.Free()

	// Derive LFDI from cert if not in config.
	lfdi := cfg.LFDI
	if lfdi == "" {
		lfdi, err = lfdiFromCertFile(cfg.ClientCert)
		if err != nil {
			log.Fatalf("hub: derive LFDI: %v", err)
		}
	}
	log.Printf("hub: LFDI=%s server=%s", lfdi, cfg.Server)

	// ── Southbound ────────────────────────────────────────────────────────

	reg := registry.New(cfg.PollInterval())
	ra := adapters.NewRegistryAdapter(reg)

	var battDevices []batEntry
	for _, dc := range cfg.Devices {
		dev, err := openDevice(dc)
		if err != nil {
			log.Printf("hub: device %s (%s): %v — skipped", dc.Name, dc.URL, err)
			continue
		}
		reg.Add(&registry.Entry{Name: dc.Name, Addr: dc.URL, Device: dev})
		ra.RegisterDevice(dc.Name, deviceRole(dc.Role), dc.MaxW)
		if bat, ok := dev.(*battery.Battery); ok {
			battDevices = append(battDevices, batEntry{name: dc.Name, bat: bat})
		}
		log.Printf("hub: device registered: %s (%s role=%s)", dc.Name, dc.URL, dc.Role)
	}

	// Separate scheduler for the response tracker. The engine has its own
	// internal scheduler; this one is only used to drive Received/Started/Completed.
	sched := scheduler.New()

	// ── OCPP CSMS ─────────────────────────────────────────────────────────

	var ocppTracker *adapters.OCPPStateTracker
	if cfg.OCPPPort != 0 {
		ocppSrv := ocppserver.New(ocppserver.Config{
			Port:     cfg.OCPPPort,
			CertPath: cfg.OCPPCert,
			KeyPath:  cfg.OCPPKey,
		})
		go ocppSrv.Start()
		defer ocppSrv.Stop()
		ocppTracker = adapters.NewOCPPStateTracker(ocppSrv.CSMS())
		log.Printf("hub: OCPP CSMS on :%d", cfg.OCPPPort)
	}

	// ── Orchestrator engine ───────────────────────────────────────────────

	compositeReader := &compositeSystemReader{registry: ra, ocpp: ocppTracker}
	opt := orchestrator.NewDefaultOptimizer()
	eng := orchestrator.New(compositeReader, opt, orchestrator.Config{
		Interval: cfg.EngineInterval(),
	})

	for _, dc := range cfg.Devices {
		switch dc.Role {
		case "battery":
			eng.RegisterBatteryActuator(dc.Name,
				adapters.NewRegistryBatteryActuator(reg, dc.Name, dc.MaxW))
		case "inverter":
			eng.RegisterSolarActuator(dc.Name,
				adapters.NewRegistrySolarActuator(reg, dc.MaxW))
		}
	}
	if ocppTracker != nil {
		eng.RegisterEVSEActuator("*", ocppTracker)
	}

	reg.Start()
	defer reg.Stop()
	ra.Start()
	defer ra.Stop()
	eng.Start()
	defer eng.Stop()

	// ── Metrics server ────────────────────────────────────────────────────

	met := newHubMetrics()
	startMetricsServer(cfg.MetricsAddr(), met, ocppTracker)

	// ── Goroutines ────────────────────────────────────────────────────────

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Shared clock offset: server_time = time.Now().Unix() + clockOffset.
	// Written by discoveryLoop; read by telemetryLoop for timestamps.
	var clockOffset atomic.Int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		discoveryLoop(ctx, cfg, fetcherDisc, lfdi, eng, sched, &clockOffset, met)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		telemetryLoop(ctx, cfg, fetcherTelm, lfdi, reg, &clockOffset, met)
	}()

	if len(battDevices) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			refreshBatteryMetrics(ctx, battDevices, ra, cfg.PollInterval()*3)
		}()
	}

	// ── Shutdown ──────────────────────────────────────────────────────────

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("hub: shutting down")
	cancel()
	wg.Wait()
	log.Printf("hub: stopped")
}

// openDevice constructs a device.Device from a DeviceConfig.
func openDevice(dc DeviceConfig) (device.Device, error) {
	switch dc.Role {
	case "inverter":
		return inverter.New(dc.URL, 5*time.Second, dc.UnitID)
	case "battery":
		return battery.New(dc.URL, 5*time.Second, dc.UnitID)
	case "meter":
		return meter.New(dc.URL, 5*time.Second, dc.UnitID)
	default:
		return nil, fmt.Errorf("unknown role %q (supported: inverter, battery, meter)", dc.Role)
	}
}

// deviceRole maps hub config role strings to adapters.DeviceRole.
func deviceRole(role string) adapters.DeviceRole {
	switch role {
	case "battery":
		return adapters.RoleBattery
	case "inverter":
		return adapters.RoleSolar
	case "meter":
		return adapters.RoleGridMeter
	default:
		return adapters.RoleGridMeter
	}
}

// batEntry pairs a device name with its concrete *battery.Battery for metrics polling.
type batEntry struct {
	name string
	bat  *battery.Battery
}

// compositeSystemReader merges RegistryAdapter state with OCPP tracker state.
type compositeSystemReader struct {
	registry *adapters.RegistryAdapter
	ocpp     *adapters.OCPPStateTracker // nil if OCPP disabled
}

func (r *compositeSystemReader) ReadSystemState() (orchestrator.SystemState, error) {
	state, err := r.registry.ReadSystemState()
	if err != nil {
		return state, err
	}
	if r.ocpp != nil {
		state.EVSEs = r.ocpp.EVSEStates()
	}
	return state, nil
}

// refreshBatteryMetrics polls battery SOC/SOH from Modbus and feeds the
// results into the registry adapter so the optimizer can use live values.
func refreshBatteryMetrics(
	ctx context.Context,
	bats []batEntry,
	ra *adapters.RegistryAdapter,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, b := range bats {
				m, err := b.bat.ReadBatteryMetrics()
				if err != nil {
					log.Printf("hub: battery metrics %s: %v", b.name, err)
					continue
				}
				ra.UpdateBatteryMetrics(b.name, m)
			}
		}
	}
}

// ── Discovery loop ─────────────────────────────────────────────────────────

func discoveryLoop(
	ctx context.Context,
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	eng *orchestrator.Engine,
	sched *scheduler.Scheduler,
	clockOffset *atomic.Int64,
	met *hubMetrics,
) {
	tracker := newResponseTracker(fetcher, lfdi, cfg.ResponseSetPath)

	// Discover immediately, then on the ticker.
	runDiscovery(fetcher, lfdi, eng, sched, tracker, clockOffset, met)

	ticker := time.NewTicker(cfg.DiscoveryInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runDiscovery(fetcher, lfdi, eng, sched, tracker, clockOffset, met)
		}
	}
}

// syncSystemClock steps the system real-time clock by offsetS seconds so
// that local time matches the CSIP server's time (IEEE 2030.5 §10.3).
//
// This is a hard step — appropriate for initial sync or when |offset| is
// large. The kernel equivalent of: date -s @$(( $(date +%s) + offset )).
//
// Requires CAP_SYS_TIME. On the Pi: sudo setcap cap_sys_time+ep bin/hub
// If the process lacks the capability the error is logged and ignored;
// the hub continues using the software clockOffset instead.
//
// Only called when |offsetS| >= 1 — sub-second accuracy is not achievable
// over HTTPS and unnecessary clock steps cause scheduling jitter.
func syncSystemClock(offsetS int64) {
	if offsetS == 0 {
		return
	}
	corrected := time.Now().Add(time.Duration(offsetS) * time.Second)
	tv := syscall.NsecToTimeval(corrected.UnixNano())
	if err := syscall.Settimeofday(&tv); err != nil {
		log.Printf("hub: clock sync skipped (need CAP_SYS_TIME?): %v", err)
		return
	}
	log.Printf("hub: system clock stepped %+ds → %s UTC",
		offsetS, corrected.UTC().Format(time.RFC3339))
}

func runDiscovery(
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	eng *orchestrator.Engine,
	sched *scheduler.Scheduler,
	tracker *responseTracker,
	clockOffset *atomic.Int64,
	met *hubMetrics,
) {
	walker := discovery.NewWalker(fetcher, lfdi)
	tree, err := walker.Discover("/dcap")
	if err != nil {
		log.Printf("hub: discovery error: %v", err)
		met.recordDiscovery(false, 0)
		return
	}

	// Sync system clock to server time; after the step clockOffset → ~0.
	syncSystemClock(tree.ClockOffset)

	clockOffset.Store(tree.ClockOffset)
	eng.SetCSIPPrograms(tree.Programs, tree.ClockOffset)
	met.recordDiscovery(true, tree.ClockOffset)

	serverNow := scheduler.ServerNow(tree.ClockOffset)
	active := sched.Evaluate(tree.Programs, serverNow)
	tracker.update(tree, active)
	met.recordCSIPState(len(tree.Programs), active)

	log.Printf("hub: discovery OK: programs=%d clockOffset=%ds",
		len(tree.Programs), tree.ClockOffset)
}

// ── Response POST state machine ────────────────────────────────────────────
//
// Full three-transition lifecycle per GEN.044 / CORE-022:
//
//	Received  (1) — posted once per event MRID when first seen in DERControlList
//	Started   (2) — posted when the event's time window becomes active
//	Completed (3) — posted when the event expires or is superseded
//
// The received map persists across discovery cycles so Received is only sent
// once per MRID per hub process lifetime. On restart the server receives a
// fresh Received for each event still in the list — servers must tolerate this.

type responseTracker struct {
	fetcher         *tlsclient.WolfSSLFetcher
	lfdi            string
	responseSetPath string
	clockOffset     int64

	received   map[string]bool // event MRIDs for which we have sent Received(1)
	activeMRID string          // MRID of the event we last sent Started(2) for
}

func newResponseTracker(fetcher *tlsclient.WolfSSLFetcher, lfdi, responseSetPath string) *responseTracker {
	return &responseTracker{
		fetcher:         fetcher,
		lfdi:            lfdi,
		responseSetPath: responseSetPath,
		received:        make(map[string]bool),
	}
}

// update drives all three response transitions based on the latest resource tree
// and the scheduler's current evaluation.
func (rt *responseTracker) update(tree *discovery.ResourceTree, active *scheduler.ActiveControl) {
	rt.clockOffset = tree.ClockOffset

	// ── Phase 1: Received (status=1) ─────────────────────────────────────
	// Walk every DERControlList in every program. Post Received the first time
	// we see each event MRID, regardless of whether the event window has opened.
	for _, ps := range tree.Programs {
		if ps.Controls == nil {
			continue
		}
		for _, ctrl := range ps.Controls.DERControl {
			// Skip cancelled events — server has already withdrawn them.
			if ctrl.EventStatus != nil && ctrl.EventStatus.CurrentStatus == 6 {
				continue
			}
			if !rt.received[ctrl.MRID] {
				rt.post(ctrl.MRID, model.ResponseEventReceived)
				rt.received[ctrl.MRID] = true
			}
		}
	}

	// ── Phase 2 & 3: Started (2) and Completed (3) ───────────────────────
	if active == nil || active.Source == "default" {
		// No active event. If we had one running, it just ended.
		if rt.activeMRID != "" {
			rt.post(rt.activeMRID, model.ResponseEventCompleted)
			rt.activeMRID = ""
		}
		return
	}

	// A new event became active (or the active event changed).
	if active.MRID != rt.activeMRID {
		if rt.activeMRID != "" {
			// Previous event superseded by this one.
			rt.post(rt.activeMRID, model.ResponseEventCompleted)
		}
		rt.post(active.MRID, model.ResponseEventStarted)
		rt.activeMRID = active.MRID
	}

	// Check whether the active event's window has closed since last check.
	if active.ValidUntil > 0 && scheduler.ServerNow(tree.ClockOffset) >= active.ValidUntil {
		rt.post(active.MRID, model.ResponseEventCompleted)
		rt.activeMRID = ""
	}
}

func (rt *responseTracker) post(mrid string, status uint8) {
	resp := model.Response{
		CreatedDateTime: scheduler.ServerNow(rt.clockOffset),
		EndDeviceLFDI:   rt.lfdi,
		Status:          status,
		Subject:         mrid,
	}
	body, err := xml.Marshal(&resp)
	if err != nil {
		log.Printf("hub: marshal Response: %v", err)
		return
	}
	if _, _, err = rt.fetcher.Post(rt.responseSetPath, body, "application/sep+xml"); err != nil {
		log.Printf("hub: POST response (mrid=%s status=%d): %v", mrid, status, err)
		return
	}
	statusName := map[uint8]string{1: "Received", 2: "Started", 3: "Completed"}[status]
	log.Printf("hub: response posted: %s mrid=%s", statusName, mrid)
}

// ── MUP telemetry loop ─────────────────────────────────────────────────────
//
// Registers ONE MirrorUsagePoint per device at startup, then POSTs a single
// MirrorMeterReading (with one ReadingSet containing W, V, Hz as separate
// Reading elements distinguished by LocalID) at mup_post_rate_s intervals.
// One POST per device per interval = one TLS handshake instead of three.
//
// LocalID conventions: 1 = real power (W), 2 = phase voltage (cV, ×100),
// 3 = frequency (cHz, ×100).

// ── Metrics ────────────────────────────────────────────────────────────────
//
// hubMetrics collects counters and gauges for the Prometheus text exposition
// at /metrics and the JSON snapshot at /status.

// csipControlInfo is the JSON shape for the active CSIP control in /status.
type csipControlInfo struct {
	Source     string `json:"source"`
	MRID       string `json:"mrid,omitempty"`
	ValidUntil int64  `json:"valid_until,omitempty"`
}

type hubMetrics struct {
	mu sync.RWMutex

	// latest per-device measurement snapshot (gauges)
	measurements map[string]device.Measurements

	// cumulative counters
	discoveryRuns   int64
	discoveryErrors int64
	postOK          map[string]int64
	postErr         map[string]int64
	clockOffsetS    int64

	// CSIP program state (updated by discoveryLoop)
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
			MRID:       active.MRID,
			ValidUntil: active.ValidUntil,
		}
	} else {
		m.csipControl = nil
	}
	m.mu.Unlock()
}

// startMetricsServer runs a minimal HTTP server on addr exposing:
//   - /healthz  liveness check
//   - /metrics  Prometheus text format
//   - /status   JSON snapshot (device measurements, CSIP state, OCPP stations)
func startMetricsServer(addr string, m *hubMetrics, ocppTracker *adapters.OCPPStateTracker) {
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

		// Discovery counters.
		sb.WriteString("# HELP csip_hub_discovery_runs_total Total discovery walk attempts\n")
		sb.WriteString("# TYPE csip_hub_discovery_runs_total counter\n")
		fmt.Fprintf(&sb, "csip_hub_discovery_runs_total %d\n", m.discoveryRuns)

		sb.WriteString("# HELP csip_hub_discovery_errors_total Discovery walks that failed\n")
		sb.WriteString("# TYPE csip_hub_discovery_errors_total counter\n")
		fmt.Fprintf(&sb, "csip_hub_discovery_errors_total %d\n", m.discoveryErrors)

		sb.WriteString("# HELP csip_hub_clock_offset_seconds CSIP server time minus local time\n")
		sb.WriteString("# TYPE csip_hub_clock_offset_seconds gauge\n")
		fmt.Fprintf(&sb, "csip_hub_clock_offset_seconds %d\n", m.clockOffsetS)

		// Telemetry POST counters.
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

		// Measurement gauges.
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

	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.RLock()
		deviceSnap := make(map[string]device.Measurements, len(m.measurements))
		for k, v := range m.measurements {
			deviceSnap[k] = v
		}
		programs := m.csipPrograms
		ctrl := m.csipControl
		clockOff := m.clockOffsetS
		m.mu.RUnlock()

		type deviceInfo struct {
			W  float64 `json:"W_W,omitempty"`
			V  float64 `json:"V_V,omitempty"`
			Hz float64 `json:"Hz_Hz,omitempty"`
		}
		type statusResp struct {
			Timestamp    string                   `json:"timestamp"`
			ClockOffsetS int64                    `json:"clock_offset_s"`
			CSIPPrograms int                      `json:"csip_programs"`
			CSIPControl  *csipControlInfo         `json:"csip_control,omitempty"`
			Devices      map[string]deviceInfo    `json:"devices"`
			EVSEs        []orchestrator.EVSEState `json:"evse_stations,omitempty"`
		}

		resp := statusResp{
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
			ClockOffsetS: clockOff,
			CSIPPrograms: programs,
			CSIPControl:  ctrl,
			Devices:      make(map[string]deviceInfo),
		}
		for name, meas := range deviceSnap {
			info := deviceInfo{}
			if !math.IsNaN(meas.W) {
				info.W = meas.W
			}
			if !math.IsNaN(meas.V) {
				info.V = meas.V
			}
			if !math.IsNaN(meas.Hz) {
				info.Hz = meas.Hz
			}
			resp.Devices[name] = info
		}
		if ocppTracker != nil {
			resp.EVSEs = ocppTracker.EVSEStates()
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("hub: /status encode: %v", err)
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

// deviceMUP holds the single server-assigned MUP path for one device
// and tracks consecutive POST failures for re-registration.
type deviceMUP struct {
	name     string
	path     string
	failures int // consecutive POST failures; reset to 0 on success
}

// mupReregisterThreshold is the number of consecutive POST failures that
// triggers MUP re-registration. Three failures covers transient network
// hiccups while catching a server restart quickly enough for the demo.
const mupReregisterThreshold = 3

func telemetryLoop(
	ctx context.Context,
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	reg *registry.Registry,
	clockOffset *atomic.Int64,
	met *hubMetrics,
) {
	// Register one MUP per device.
	var allMUPs []deviceMUP
	for _, dc := range cfg.Devices {
		path, err := registerDeviceMUP(fetcher, lfdi, dc.Name, cfg.MUPPostRateS)
		if err != nil {
			log.Printf("hub: MUP registration for %s failed: %v — skipping", dc.Name, err)
			continue
		}
		allMUPs = append(allMUPs, deviceMUP{name: dc.Name, path: path})
	}
	if len(allMUPs) == 0 {
		log.Printf("hub: no MUPs registered — telemetry disabled")
		return
	}

	postTicker := time.NewTicker(cfg.MUPPostRate())
	defer postTicker.Stop()

	updates := reg.Updates()
	latest := make(map[string]device.Measurements) // device name → latest snapshot

	for {
		select {
		case <-ctx.Done():
			return

		case upd, ok := <-updates:
			if !ok {
				return
			}
			if upd.Err == nil {
				latest[upd.Name] = upd.Measurements
				met.recordMeasurement(upd.Name, upd.Measurements)
			} else {
				log.Printf("hub: device %s poll error: %v", upd.Name, upd.Err)
			}

		case <-postTicker.C:
			for i := range allMUPs {
				dm := &allMUPs[i]
				m, ok := latest[dm.name]
				if !ok {
					continue // no reading yet for this device
				}
				postErr := postDeviceMeasurements(fetcher, dm.name, dm.path, m,
					clockOffset.Load(), cfg.MUPPostRateS)
				met.recordPost(dm.name, postErr)
				if postErr != nil {
					dm.failures++
					if dm.failures >= mupReregisterThreshold {
						log.Printf("hub: %d consecutive POST failures for %s; re-registering MUP",
							dm.failures, dm.name)
						newPath, rerr := registerDeviceMUP(fetcher, lfdi, dm.name, cfg.MUPPostRateS)
						if rerr != nil {
							log.Printf("hub: MUP re-registration for %s failed: %v", dm.name, rerr)
						} else {
							log.Printf("hub: MUP re-registered: %s → %s", dm.name, newPath)
							dm.path = newPath
							dm.failures = 0
						}
					}
				} else {
					dm.failures = 0
				}
			}
		}
	}
}

// registerDeviceMUP POSTs one MirrorUsagePoint for a device and returns the
// server-assigned path. The MRID is stable across restarts so the server can
// de-duplicate by MRID.
func registerDeviceMUP(fetcher *tlsclient.WolfSSLFetcher, lfdi, deviceName string, postRateS int) (string, error) {
	prefix := lfdi
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	mup := model.MirrorUsagePoint{
		MRID:                prefix + "-" + deviceName,
		Description:         deviceName + " Measurements (W/V/Hz)",
		RoleFlags:           0x0002,
		ServiceCategoryKind: 0,
		Status:              1,
		DeviceLFDI:          lfdi,
		PostRate:            uint32(postRateS),
	}
	body, err := xml.Marshal(&mup)
	if err != nil {
		return "", fmt.Errorf("marshal MUP: %w", err)
	}
	_, loc, err := fetcher.Post("/mup", body, "application/sep+xml")
	if err != nil {
		return "", fmt.Errorf("register MUP: %w", err)
	}
	log.Printf("hub: MUP registered: %s → %s", deviceName, loc)
	return loc, nil
}

// postDeviceMeasurements encodes W, V, Hz as a single MirrorMeterReading POST
// for one device. All three readings go in one ReadingSet, distinguished by
// LocalID (1=W, 2=cV×100, 3=cHz×100). One POST = one TLS handshake.
// NaN values are omitted; returns nil if all values are NaN (POST skipped).
func postDeviceMeasurements(
	fetcher *tlsclient.WolfSSLFetcher,
	deviceName string,
	mupPath string,
	m device.Measurements,
	clockOffset int64,
	intervalS int,
) error {
	now := time.Now().Unix() + clockOffset
	dur := uint32(intervalS)
	start := now - int64(dur)

	var readings []model.Reading
	if !math.IsNaN(m.W) {
		readings = append(readings, model.Reading{
			LocalID: 1, // real power, W
			Value:   int64(math.Round(m.W)),
			TimePeriod: &model.DateTimeInterval{Start: start, Duration: dur},
		})
	}
	if !math.IsNaN(m.V) {
		readings = append(readings, model.Reading{
			LocalID: 2, // phase voltage, centi-volts (V × 100)
			Value:   int64(math.Round(m.V * 100)),
			TimePeriod: &model.DateTimeInterval{Start: start, Duration: dur},
		})
	}
	if !math.IsNaN(m.Hz) {
		readings = append(readings, model.Reading{
			LocalID: 3, // frequency, centi-Hz (Hz × 100)
			Value:   int64(math.Round(m.Hz * 100)),
			TimePeriod: &model.DateTimeInterval{Start: start, Duration: dur},
		})
	}
	if len(readings) == 0 {
		return nil
	}

	mmr := model.MirrorMeterReading{
		MirrorReadingSet: []model.MirrorReadingSet{{
			StartTime: start,
			Duration:  dur,
			Reading:   readings,
		}},
	}
	body, err := xml.Marshal(&mmr)
	if err != nil {
		log.Printf("hub: marshal telemetry %s: %v", deviceName, err)
		return err
	}
	if _, _, err = fetcher.Post(mupPath, body, "application/sep+xml"); err != nil {
		log.Printf("hub: POST telemetry %s: %v", deviceName, err)
		return err
	}
	log.Printf("hub: telemetry posted: %s W=%.0f V=%.1f Hz=%.2f",
		deviceName, m.W, m.V, m.Hz)
	return nil
}

// ── Helpers ────────────────────────────────────────────────────────────────

func lfdiFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	lfdi, _ := identity.FromCertificate(cert)
	return lfdi.String(), nil
}
