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
//	discoveryLoop  — re-walks /dcap every N seconds; drives response POST state machine.
//	telemetryLoop  — registers one MUP per device; POSTs per-device readings.
//	engine         — evaluates optimizer every EngineIntervalS; applies controls.
//	registry       — polls Modbus every PollIntervalS; emits MeasurementUpdates.
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

	fetcherDisc, fetcherTelm, lfdi, err := initTLS(cfg)
	if err != nil {
		log.Fatalf("hub: %v", err)
	}
	defer fetcherDisc.Free()
	defer fetcherTelm.Free()

	reg, ra, battDevices := setupSouthbound(cfg)
	sched := scheduler.New()

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

	reader := &adapters.CompositeSystemReader{Registry: ra, OCPP: ocppTracker}
	eng := setupEngine(cfg, reader, reg, ocppTracker)

	reg.Start()
	defer reg.Stop()
	ra.Start()
	defer ra.Stop()
	eng.Start()
	defer eng.Stop()

	lb := newLogBroadcaster()
	log.SetOutput(lb)
	met := newHubMetrics()
	if cfg.MetricsEnabled() {
		startMetricsServer(cfg.MetricsAddr(), met, ocppTracker, reader, eng, lb)
	} else {
		log.Printf("hub: metrics/status server disabled (metrics_port=0)")
	}

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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("hub: shutting down")
	cancel()
	wg.Wait()
	log.Printf("hub: stopped")
}

// initTLS creates both TLS fetchers and resolves the device LFDI.
func initTLS(cfg *Config) (disc, telm *tlsclient.WolfSSLFetcher, lfdi string, err error) {
	tlsCfg := tlsclient.Config{
		ServerAddr:     cfg.Server,
		CACertPath:     cfg.CACert,
		ClientCertPath: cfg.ClientCert,
		ClientKeyPath:  cfg.ClientKey,
	}
	disc, err = tlsclient.NewWolfSSLFetcher(tlsCfg)
	if err != nil {
		return nil, nil, "", fmt.Errorf("init fetcher (discovery): %w", err)
	}
	telm, err = tlsclient.NewWolfSSLFetcher(tlsCfg)
	if err != nil {
		disc.Free()
		return nil, nil, "", fmt.Errorf("init fetcher (telemetry): %w", err)
	}
	lfdi = cfg.LFDI
	if lfdi == "" {
		lfdi, err = lfdiFromCertFile(cfg.ClientCert)
		if err != nil {
			disc.Free()
			telm.Free()
			return nil, nil, "", fmt.Errorf("derive LFDI: %w", err)
		}
	}
	log.Printf("hub: LFDI=%s server=%s", lfdi, cfg.Server)
	return disc, telm, lfdi, nil
}

// setupSouthbound opens all configured Modbus devices and registers them with
// the registry and registry adapter.
func setupSouthbound(cfg *Config) (reg *registry.Registry, ra *adapters.RegistryAdapter, bats []batEntry) {
	reg = registry.New(cfg.PollInterval())
	ra = adapters.NewRegistryAdapter(reg)
	for _, dc := range cfg.Devices {
		dev, err := openDevice(dc)
		if err != nil {
			log.Printf("hub: device %s (%s): %v — registering with deferred connect", dc.Name, dc.URL, err)
			dev = newPendingDevice(dc)
		} else {
			log.Printf("hub: device registered: %s (%s role=%s)", dc.Name, dc.URL, dc.Role)
		}
		reg.Add(&registry.Entry{Name: dc.Name, Addr: dc.URL, Device: dev})
		ra.RegisterDevice(dc.Name, deviceRole(dc.Role), dc.MaxW, dev)
		if bat, ok := dev.(*battery.Battery); ok {
			bats = append(bats, batEntry{name: dc.Name, bat: bat})
		}
	}
	return reg, ra, bats
}

// setupEngine creates the optimizer and engine and wires actuators for every device.
func setupEngine(cfg *Config, reader orchestrator.SystemReader, reg *registry.Registry, ocppTracker *adapters.OCPPStateTracker) *orchestrator.Engine {
	opt := orchestrator.NewDefaultOptimizer()
	opt.Debug = cfg.Debug
	eng := orchestrator.New(reader, opt, orchestrator.Config{
		Interval: cfg.EngineInterval(),
		Debug:    cfg.Debug,
	})
	for _, dc := range cfg.Devices {
		switch dc.Role {
		case "battery":
			eng.RegisterBatteryActuator(dc.Name, adapters.NewRegistryBatteryActuator(reg, dc.Name, dc.MaxW))
		case "inverter":
			eng.RegisterSolarActuator(dc.Name, adapters.NewRegistrySolarActuator(reg, dc.Name, dc.MaxW))
		}
	}
	if ocppTracker != nil {
		eng.RegisterEVSEActuator("*", ocppTracker)
	}
	return eng
}

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

func refreshBatteryMetrics(ctx context.Context, bats []batEntry, ra *adapters.RegistryAdapter, interval time.Duration) {
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

	if tree.ResponseSetPath != "" {
		tracker.responseSetPath = tree.ResponseSetPath
		log.Printf("hub: ResponseSetPath discovered: %s", tree.ResponseSetPath)
	}

	serverNow := scheduler.ServerNow(tree.ClockOffset)
	active := sched.Evaluate(tree.Programs, serverNow)
	tracker.update(tree, active)
	met.recordCSIPState(len(tree.Programs), active)

	log.Printf("hub: discovery OK: programs=%d clockOffset=%ds", len(tree.Programs), tree.ClockOffset)
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
	log.Printf("hub: system clock stepped %+ds → %s UTC", offsetS, corrected.UTC().Format(time.RFC3339))
}

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
