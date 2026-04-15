// hub is the long-running CSIP DER hub process for a Raspberry Pi.
//
// It wires together the northbound (CSIP / IEEE 2030.5) and southbound
// (Modbus / SunSpec) stacks:
//
//	wolfSSL fetcher → discovery walker → scheduler → bridge → registry → inverter/battery
//
// Goroutines:
//
//	discoveryLoop  — re-walks /dcap every N seconds; updates bridge programs +
//	                 clock offset; drives the response POST state machine.
//	telemetryLoop  — registers one MUP per device × {W, V, Hz} at startup;
//	                 consumes registry.Updates() and POSTs per-device readings.
//	bridge (internal) — evaluates scheduler every 15 s; calls ApplyControl.
//	registry (internal) — polls Modbus every 10 s; emits MeasurementUpdates.
//
// Response POST state machine (GEN.044 / CORE-022):
//
//	Received  (1): posted once when a DERControl event is first seen in the
//	               DERControlList, even before its time window opens.
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
	"csip-tls-test/internal/southbound/battery"
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

	// Shared clock offset: server_time = time.Now().Unix() + clockOffset.
	// Written by discoveryLoop; read by telemetryLoop for timestamps.
	var clockOffset atomic.Int64

	wg.Add(1)
	go func() {
		defer wg.Done()
		discoveryLoop(ctx, cfg, fetcherDisc, lfdi, b, sched, &clockOffset)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		telemetryLoop(ctx, cfg, fetcherTelm, lfdi, reg, &clockOffset)
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
func openDevice(dc DeviceConfig) (device.Device, error) {
	switch dc.Role {
	case "inverter":
		return inverter.New(dc.URL, 5*time.Second, dc.UnitID)
	case "battery":
		return battery.New(dc.URL, 5*time.Second, dc.UnitID)
	default:
		return nil, fmt.Errorf("unknown role %q (supported: inverter, battery)", dc.Role)
	}
}

// ── Discovery loop ─────────────────────────────────────────────────────────

func discoveryLoop(
	ctx context.Context,
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	b *bridge.Bridge,
	sched *scheduler.Scheduler,
	clockOffset *atomic.Int64,
) {
	tracker := newResponseTracker(fetcher, lfdi, cfg.ResponseSetPath)

	// Discover immediately, then on the ticker.
	runDiscovery(fetcher, lfdi, b, sched, tracker, clockOffset)

	ticker := time.NewTicker(cfg.DiscoveryInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runDiscovery(fetcher, lfdi, b, sched, tracker, clockOffset)
		}
	}
}

func runDiscovery(
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

	serverNow := scheduler.ServerNow(tree.ClockOffset)
	active := sched.Evaluate(tree.Programs, serverNow)
	tracker.update(tree, active)

	log.Printf("hub: discovery OK: programs=%d clockOffset=%ds",
		len(tree.Programs), tree.ClockOffset)
}

// ── Response POST state machine ────────────────────────────────────────────
//
// Full three-transition lifecycle per GEN.044 / CORE-022:
//   Received  (1) — posted once per event MRID when first seen in DERControlList
//   Started   (2) — posted when the event's time window becomes active
//   Completed (3) — posted when the event expires or is superseded
//
// The received map persists across discovery cycles so Received is only sent
// once per MRID per hub process lifetime. On restart the server receives a
// fresh Received for each event still in the list — servers must tolerate this.

type responseTracker struct {
	fetcher         *tlsclient.WolfSSLFetcher
	lfdi            string
	responseSetPath string
	clockOffset     int64

	received    map[string]bool // event MRIDs for which we have sent Received(1)
	activeMRID  string          // MRID of the event we last sent Started(2) for
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

// deviceMUP holds the single server-assigned MUP path for one device.
type deviceMUP struct {
	name string
	path string
}

func telemetryLoop(
	ctx context.Context,
	cfg *Config,
	fetcher *tlsclient.WolfSSLFetcher,
	lfdi string,
	reg *registry.Registry,
	clockOffset *atomic.Int64,
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
			} else {
				log.Printf("hub: device %s poll error: %v", upd.Name, upd.Err)
			}

		case <-postTicker.C:
			for _, dm := range allMUPs {
				m, ok := latest[dm.name]
				if !ok {
					continue // no reading yet for this device
				}
				postDeviceMeasurements(fetcher, dm.name, dm.path, m,
					clockOffset.Load(), cfg.MUPPostRateS)
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
// NaN values are omitted; if all values are NaN the POST is skipped.
func postDeviceMeasurements(
	fetcher *tlsclient.WolfSSLFetcher,
	deviceName string,
	mupPath string,
	m device.Measurements,
	clockOffset int64,
	intervalS int,
) {
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
		return
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
		return
	}
	if _, _, err = fetcher.Post(mupPath, body, "application/sep+xml"); err != nil {
		log.Printf("hub: POST telemetry %s: %v", deviceName, err)
		return
	}
	log.Printf("hub: telemetry posted: %s W=%.0f V=%.1f Hz=%.2f",
		deviceName, m.W, m.V, m.Hz)
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
