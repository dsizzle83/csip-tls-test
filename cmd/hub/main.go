// hub is the long-running CSIP DER hub process for a Raspberry Pi.
//
// It wires together the northbound (CSIP / IEEE 2030.5) and southbound
// (Modbus / SunSpec) stacks:
//
//	wolfSSL fetcher → discovery walker → scheduler → bridge → registry → inverter(s)
//
// On each discovery cycle (default 60 s) it re-walks /dcap and pushes
// fresh programs and clock offset into the bridge. The bridge evaluates
// the scheduler on its own 30 s tick and applies the resulting
// DERControlBase to all registered devices.
//
// Additionally:
//   - Response POST loop: detects event transitions and POSTs status 2/3
//     to the server's ResponseSet (GEN.044 / CORE-022).
//   - MUP telemetry loop: registers MirrorUsagePoints on startup, then
//     POSTs real-power, voltage, and frequency readings every postRate seconds.
//
// Usage:
//
//	hub [-config hub.json]
//
// The config file is JSON; see hub-example.json for the full schema.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"csip-tls-test/internal/bridge"
	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/identity"
	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/csip/scheduler"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/inverter"
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

	fetcher, err := tlsclient.NewWolfSSLFetcher(tlsclient.Config{
		ServerAddr:     cfg.Server,
		CACertPath:     cfg.CACert,
		ClientCertPath: cfg.ClientCert,
		ClientKeyPath:  cfg.ClientKey,
	})
	if err != nil {
		log.Fatalf("hub: init fetcher: %v", err)
	}
	defer fetcher.Free()

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
	for _, dc := range cfg.Devices {
		dev, err := openDevice(dc)
		if err != nil {
			log.Printf("hub: device %s (%s): %v — skipped", dc.Name, dc.URL, err)
			continue
		}
		reg.Add(&registry.Entry{Name: dc.Name, Addr: dc.URL, Device: dev})
		log.Printf("hub: device registered: %s (%s role=%s)", dc.Name, dc.URL, dc.Role)
	}

	sched := scheduler.New()
	b := bridge.New(sched, reg, cfg.ControlInterval())

	reg.Start()
	defer reg.Stop()
	b.Start()
	defer b.Stop()

	// ── Goroutines ────────────────────────────────────────────────────────

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Shared clock offset (seconds): server_time = time.Now().Unix() + clockOffset.
	// Updated by discoveryLoop; read by telemetryLoop for timestamping.
	var clockOffset atomic.Int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		discoveryLoop(ctx, cfg, fetcher, lfdi, b, sched, &clockOffset)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		telemetryLoop(ctx, cfg, fetcher, lfdi, reg, &clockOffset)
	}()

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
// Currently only "inverter" is supported.
func openDevice(dc DeviceConfig) (device.Device, error) {
	switch dc.Role {
	case "inverter":
		return inverter.New(dc.URL, 5*time.Second, dc.UnitID)
	default:
		return nil, fmt.Errorf("unknown role %q (supported: inverter)", dc.Role)
	}
}

// ── Discovery loop ─────────────────────────────────────────────────────────

// discoveryLoop periodically walks the CSIP resource tree and updates the
// bridge. It also runs the response POST state machine on each cycle.
func discoveryLoop(
	ctx context.Context,
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	b *bridge.Bridge,
	sched *scheduler.Scheduler,
	clockOffset *atomic.Int64,
) {
	tracker := &responseTracker{
		fetcher:         fetcher,
		lfdi:            lfdi,
		responseSetPath: cfg.ResponseSetPath,
	}

	// Discover immediately, then on the ticker.
	runDiscovery(cfg, fetcher, lfdi, b, sched, tracker, clockOffset)

	ticker := time.NewTicker(cfg.DiscoveryInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runDiscovery(cfg, fetcher, lfdi, b, sched, tracker, clockOffset)
		}
	}
}

// runDiscovery performs one full walk and updates bridge + response tracker.
func runDiscovery(
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	b *bridge.Bridge,
	sched *scheduler.Scheduler,
	tracker *responseTracker,
	clockOffset *atomic.Int64,
) {
	walker := discovery.NewWalker(fetcher, lfdi)
	tree, err := walker.Discover("/dcap")
	if err != nil {
		log.Printf("hub: discovery error: %v", err)
		return
	}

	clockOffset.Store(tree.ClockOffset)
	b.SetPrograms(tree.Programs, tree.ClockOffset)

	// Check active control and drive response POST state machine.
	serverNow := scheduler.ServerNow(tree.ClockOffset)
	active := sched.Evaluate(tree.Programs, serverNow)
	tracker.update(active, tree.ClockOffset)

	log.Printf("hub: discovery OK: programs=%d clockOffset=%ds",
		len(tree.Programs), tree.ClockOffset)
}

// ── Response POST state machine ────────────────────────────────────────────

// responseTracker tracks which event was last acknowledged and POSTs
// status transitions to the server's ResponseSet per GEN.044 / CORE-022.
type responseTracker struct {
	fetcher         *tlsclient.WolfSSLFetcher
	lfdi            string
	responseSetPath string

	lastMRID   string // MRID of last event we sent EventStarted for
	lastStatus uint8  // last status POSTed for lastMRID (0 = none)

	clockOffset int64
}

// update compares active with the last-known state and POSTs any required
// Response transitions.
func (rt *responseTracker) update(active *scheduler.ActiveControl, clockOffset int64) {
	rt.clockOffset = clockOffset

	// No active event (default control or nothing).
	if active == nil || active.Source == "default" {
		if rt.lastMRID != "" && rt.lastStatus == model.ResponseEventStarted {
			rt.post(rt.lastMRID, model.ResponseEventCompleted)
			rt.lastMRID = ""
			rt.lastStatus = 0
		}
		return
	}

	// Active event: detect new or changed event.
	if active.MRID != rt.lastMRID {
		// Complete the previous event if one was in progress.
		if rt.lastMRID != "" && rt.lastStatus == model.ResponseEventStarted {
			rt.post(rt.lastMRID, model.ResponseEventCompleted)
		}
		// Start the new event.
		rt.post(active.MRID, model.ResponseEventStarted)
		rt.lastMRID = active.MRID
		rt.lastStatus = model.ResponseEventStarted
	}

	// Check if the current event has expired since the last check.
	if active.ValidUntil > 0 && scheduler.ServerNow(clockOffset) >= active.ValidUntil {
		rt.post(active.MRID, model.ResponseEventCompleted)
		rt.lastMRID = ""
		rt.lastStatus = 0
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
	log.Printf("hub: response posted: mrid=%s status=%d", mrid, status)
}

// ── MUP telemetry loop ─────────────────────────────────────────────────────

// telemetryLoop registers three MirrorUsagePoints (W, V, Hz) on startup and
// then posts measurements from the registry at the configured postRate.
// It exits cleanly on ctx cancellation.
func telemetryLoop(
	ctx context.Context,
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	reg *registry.Registry,
	clockOffset *atomic.Int64,
) {
	mupPaths, err := registerMUPs(fetcher, lfdi, cfg.MUPPostRateS)
	if err != nil {
		log.Printf("hub: MUP registration failed: %v — telemetry disabled", err)
		return
	}

	postTicker := time.NewTicker(cfg.MUPPostRate())
	defer postTicker.Stop()

	updates := reg.Updates()
	// latest holds the most recent measurement per device name.
	latest := make(map[string]device.Measurements)

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
			} else {
				log.Printf("hub: device %s measurement error: %v", upd.Name, upd.Err)
			}

		case <-postTicker.C:
			if len(latest) == 0 {
				continue
			}
			postMeasurements(fetcher, mupPaths, aggregateMeasurements(latest), clockOffset.Load())
		}
	}
}

// registerMUPs POSTs three MirrorUsagePoints (/mup) to register them with
// the server and returns a map from "W"/"V"/"Hz" to the assigned path.
func registerMUPs(fetcher *tlsclient.WolfSSLFetcher, lfdi string, postRateS int) (map[string]string, error) {
	// Use the first 8 chars of the LFDI as a stable prefix for MRIDs.
	prefix := lfdi
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}

	type mupDef struct {
		key  string
		mrid string
		desc string
	}
	defs := []mupDef{
		{"W", prefix + "-MUP-W", "Real Power (W)"},
		{"V", prefix + "-MUP-V", "Phase Voltage (V)"},
		{"Hz", prefix + "-MUP-Hz", "Frequency (Hz)"},
	}

	paths := make(map[string]string, len(defs))
	for _, d := range defs {
		mup := model.MirrorUsagePoint{
			MRID:                d.mrid,
			Description:         d.desc,
			RoleFlags:           0x0002, // export
			ServiceCategoryKind: 0,
			Status:              1,
			DeviceLFDI:          lfdi,
			PostRate:            uint32(postRateS),
		}
		body, err := xml.Marshal(&mup)
		if err != nil {
			return nil, fmt.Errorf("marshal MUP %s: %w", d.key, err)
		}
		_, loc, err := fetcher.Post("/mup", body, "application/sep+xml")
		if err != nil {
			return nil, fmt.Errorf("register MUP %s: %w", d.key, err)
		}
		paths[d.key] = loc
		log.Printf("hub: MUP registered: %s → %s", d.key, loc)
	}
	return paths, nil
}

// postMeasurements encodes m as three MirrorMeterReading POSTs (W, V, Hz).
// NaN values are skipped. clockOffset is added to the local wall time
// to produce the server-relative timestamp.
func postMeasurements(
	fetcher *tlsclient.WolfSSLFetcher,
	mupPaths map[string]string,
	m device.Measurements,
	clockOffset int64,
) {
	now := time.Now().Unix() + clockOffset
	dur := uint32(300) // nominal 5-minute interval

	type reading struct {
		key string
		val float64
	}
	readings := []reading{
		{"W", m.W},
		{"V", m.V},
		{"Hz", m.Hz},
	}

	for _, r := range readings {
		path, ok := mupPaths[r.key]
		if !ok || math.IsNaN(r.val) {
			continue
		}
		mmr := model.MirrorMeterReading{
			MirrorReadingSet: []model.MirrorReadingSet{
				{
					StartTime: now - int64(dur),
					Duration:  dur,
					Reading: []model.Reading{
						{
							Value: int64(math.Round(r.val)),
							TimePeriod: &model.DateTimeInterval{
								Start:    now - int64(dur),
								Duration: dur,
							},
						},
					},
				},
			},
		}
		body, err := xml.Marshal(&mmr)
		if err != nil {
			log.Printf("hub: marshal MirrorMeterReading %s: %v", r.key, err)
			continue
		}
		if _, _, err = fetcher.Post(path, body, "application/sep+xml"); err != nil {
			log.Printf("hub: POST telemetry %s: %v", r.key, err)
		}
	}
	log.Printf("hub: telemetry posted: W=%.0f V=%.1f Hz=%.2f", m.W, m.V, m.Hz)
}

// aggregateMeasurements reduces a per-device measurement map to a single
// Measurements value. Currently returns the first device's readings; future
// versions will sum real-power across devices in the same site.
func aggregateMeasurements(m map[string]device.Measurements) device.Measurements {
	for _, meas := range m {
		return meas
	}
	return device.Measurements{W: math.NaN(), V: math.NaN(), Hz: math.NaN()}
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
