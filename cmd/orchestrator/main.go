// cmd/orchestrator is an example wiring of the orchestration engine.
//
// It connects:
//   - IEEE 2030.5 (CSIP) northbound stack for DER control signals
//   - Modbus/SunSpec southbound stack for inverters and batteries
//   - OCPP 2.0.1 CSMS for EV chargers
//
// To run:
//
//	go run ./cmd/orchestrator -config orchestrator.json
//
// The JSON config is the same format as cmd/hub, with additional fields for
// OCPP and the orchestration engine interval.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"csip-tls-test/internal/ocppserver"
	"csip-tls-test/internal/orchestrator"
	"csip-tls-test/internal/orchestrator/adapters"
	"csip-tls-test/internal/southbound/battery"
	"csip-tls-test/internal/southbound/inverter"
	"csip-tls-test/internal/southbound/meter"
	"csip-tls-test/internal/southbound/registry"
	"csip-tls-test/internal/wolfssl"
)

// Config is the JSON configuration for the orchestrator process.
type Config struct {
	// CSIP / IEEE 2030.5 northbound
	Server     string `json:"server"`
	CACert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`

	// Devices (Modbus URLs)
	Inverters []DeviceConf `json:"inverters"`
	Batteries []DeviceConf `json:"batteries"`
	Meters    []DeviceConf `json:"meters"` // AC grid meters (SunSpec 201/202/203)

	// OCPP
	OCPPPort int    `json:"ocpp_port"`
	OCPPCert string `json:"ocpp_cert"`
	OCPPKey  string `json:"ocpp_key"`

	// Engine tuning
	PollIntervalS    int `json:"poll_interval_s"`
	ControlIntervalS int `json:"control_interval_s"`
	EngineIntervalS  int `json:"engine_interval_s"`
}

type DeviceConf struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	UnitID uint8  `json:"unit_id"`
	MaxW   float64 `json:"max_w"`
}

func (c *Config) pollInterval() time.Duration {
	if c.PollIntervalS <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.PollIntervalS) * time.Second
}

func (c *Config) engineInterval() time.Duration {
	if c.EngineIntervalS <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.EngineIntervalS) * time.Second
}

func main() {
	configPath := flag.String("config", "orchestrator.json", "path to JSON config")
	flag.Parse()

	cfg := loadConfig(*configPath)

	wolfssl.Init()
	defer wolfssl.Cleanup()

	// ── Southbound: Modbus registry ───────────────────────────────────────────

	reg := registry.New(cfg.pollInterval())

	for _, ic := range cfg.Inverters {
		inv, err := inverter.New(ic.URL, 5*time.Second, ic.UnitID)
		if err != nil {
			log.Printf("orchestrator: inverter %s: %v — skipped", ic.Name, err)
			continue
		}
		reg.Add(&registry.Entry{Name: ic.Name, Addr: ic.URL, Device: inv})
		log.Printf("orchestrator: inverter registered: %s", ic.Name)
	}

	for _, mc := range cfg.Meters {
		mtr, err := meter.New(mc.URL, 5*time.Second, mc.UnitID)
		if err != nil {
			log.Printf("orchestrator: meter %s: %v — skipped", mc.Name, err)
			continue
		}
		reg.Add(&registry.Entry{Name: mc.Name, Addr: mc.URL, Device: mtr})
		log.Printf("orchestrator: meter registered: %s (model %d)", mc.Name, mtr.ModelID())
	}

	var battDevices []*battery.Battery
	for _, bc := range cfg.Batteries {
		bat, err := battery.New(bc.URL, 5*time.Second, bc.UnitID)
		if err != nil {
			log.Printf("orchestrator: battery %s: %v — skipped", bc.Name, err)
			continue
		}
		reg.Add(&registry.Entry{Name: bc.Name, Addr: bc.URL, Device: bat})
		battDevices = append(battDevices, bat)
		log.Printf("orchestrator: battery registered: %s", bc.Name)
	}

	// ── Registry adapter (SystemReader) ──────────────────────────────────────

	ra := adapters.NewRegistryAdapter(reg)
	for _, mc := range cfg.Meters {
		ra.RegisterDevice(mc.Name, adapters.RoleGridMeter, 0)
	}
	for _, ic := range cfg.Inverters {
		ra.RegisterDevice(ic.Name, adapters.RoleSolar, ic.MaxW)
	}
	for _, bc := range cfg.Batteries {
		ra.RegisterDevice(bc.Name, adapters.RoleBattery, bc.MaxW)
	}

	// ── OCPP CSMS ─────────────────────────────────────────────────────────────

	ocppSrv := ocppserver.New(ocppserver.Config{
		Port:     cfg.OCPPPort,
		CertPath: cfg.OCPPCert,
		KeyPath:  cfg.OCPPKey,
	})
	go ocppSrv.Start()

	ocppTracker := adapters.NewOCPPStateTracker(ocppSrv.CSMS())

	// ── Composite SystemReader that merges registry + OCPP ───────────────────

	compositeReader := &compositeSystemReader{
		registry: ra,
		ocpp:     ocppTracker,
	}

	// ── Optimizer ─────────────────────────────────────────────────────────────

	opt := orchestrator.NewDefaultOptimizer()
	opt.CostModel = orchestrator.DefaultTOUCostModel()
	opt.Debug = true

	// ── Engine ────────────────────────────────────────────────────────────────

	eng := orchestrator.New(compositeReader, opt, orchestrator.Config{
		Interval: cfg.engineInterval(),
		Debug:    true,
	})

	// Wire battery actuators (one per battery, via its own registry).
	for _, bc := range cfg.Batteries {
		batReg := registry.New(cfg.pollInterval())
		// In production: use a per-device registry or extend ApplyControl to
		// target a specific device.  For this example, both share the same reg.
		_ = batReg
		act := adapters.NewRegistryBatteryActuator(reg, bc.Name, bc.MaxW)
		eng.RegisterBatteryActuator(bc.Name, act)
	}
	for _, ic := range cfg.Inverters {
		act := adapters.NewRegistrySolarActuator(reg, ic.MaxW)
		eng.RegisterSolarActuator(ic.Name, act)
	}
	eng.RegisterEVSEActuator("*", ocppTracker) // wildcard: OCPP tracker handles all EVSEs

	// ── Start everything ──────────────────────────────────────────────────────

	reg.Start()
	defer reg.Stop()
	ra.Start()
	defer ra.Stop()
	eng.Start()
	defer eng.Stop()

	// Background: refresh battery metrics (SOC/SOH) periodically.
	ctx, cancel := context.WithCancel(context.Background())
	go refreshBatteryMetrics(ctx, battDevices, cfg.Batteries, ra, cfg.pollInterval()*3)

	// ── Shutdown ──────────────────────────────────────────────────────────────

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("orchestrator: shutting down")
	cancel()
	ocppSrv.Stop()
}

// refreshBatteryMetrics polls battery SOC/SOH from the Modbus connection and
// feeds it into the registry adapter so the optimizer can use live SOC values.
func refreshBatteryMetrics(
	ctx context.Context,
	bats []*battery.Battery,
	cfgs []DeviceConf,
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
			for i, bat := range bats {
				if i >= len(cfgs) {
					break
				}
				m, err := bat.ReadBatteryMetrics()
				if err != nil {
					log.Printf("orchestrator: battery metrics %s: %v", cfgs[i].Name, err)
					continue
				}
				ra.UpdateBatteryMetrics(cfgs[i].Name, m)
			}
		}
	}
}

// compositeSystemReader merges registry adapter state with OCPP tracker state.
type compositeSystemReader struct {
	registry *adapters.RegistryAdapter
	ocpp     *adapters.OCPPStateTracker
}

func (r *compositeSystemReader) ReadSystemState() (orchestrator.SystemState, error) {
	state, err := r.registry.ReadSystemState()
	if err != nil {
		return state, err
	}
	state.EVSEs = r.ocpp.EVSEStates()
	return state, nil
}

func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("orchestrator: no config at %s, using defaults", path)
		return &Config{OCPPPort: ocppserver.DefaultPort}
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("orchestrator: parse config: %v", err)
	}
	return &cfg
}
