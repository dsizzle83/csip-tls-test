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
//	                     subscribes to registry updates and POSTs per-device readings.
//	engine (internal)  — evaluates optimizer every EngineIntervalS; applies controls.
//	registry (internal)— polls Modbus every PollIntervalS; emits MeasurementUpdates.
//	batteryMetrics     — refreshes SOC/SOH from Modbus battery models.
//
// Usage:
//
//	hub [-config hub.json]
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/identity"
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
	opt.Debug = cfg.Debug
	eng := orchestrator.New(compositeReader, opt, orchestrator.Config{
		Interval: cfg.EngineInterval(),
		Debug:    cfg.Debug,
	})

	for _, dc := range cfg.Devices {
		switch dc.Role {
		case "battery":
			eng.RegisterBatteryActuator(dc.Name,
				adapters.NewRegistryBatteryActuator(reg, dc.Name, dc.MaxW))
		case "inverter":
			eng.RegisterSolarActuator(dc.Name,
				adapters.NewRegistrySolarActuator(reg, dc.Name, dc.MaxW))
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

	lb := newLogBroadcaster()
	log.SetOutput(lb)

	met := newHubMetrics()
	startMetricsServer(cfg.MetricsAddr(), met, ocppTracker, compositeReader, eng, lb)

	// ── Goroutines ────────────────────────────────────────────────────────

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

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

// ── Device helpers ────────────────────────────────────────────────────────

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

type batEntry struct {
	name string
	bat  *battery.Battery
}

type compositeSystemReader struct {
	registry *adapters.RegistryAdapter
	ocpp     *adapters.OCPPStateTracker
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
