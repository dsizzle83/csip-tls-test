// sim/orchestrator is an example wiring of the orchestration engine.
//
// It connects Modbus/SunSpec southbound devices (inverters, batteries, meters)
// and an OCPP 2.0.1 CSMS to the orchestrator engine, without the CSIP northbound
// discovery loop.  Use cmd/hub for the full production stack.
//
// Usage:
//
//	go run ./sim/orchestrator -config orchestrator.json
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

// Config is the JSON configuration for this example orchestrator.
type Config struct {
	Server     string `json:"server"`
	CACert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`

	Inverters []DeviceConf `json:"inverters"`
	Batteries []DeviceConf `json:"batteries"`
	Meters    []DeviceConf `json:"meters"`

	OCPPPort int    `json:"ocpp_port"`
	OCPPCert string `json:"ocpp_cert"`
	OCPPKey  string `json:"ocpp_key"`

	PollIntervalS   int `json:"poll_interval_s"`
	EngineIntervalS int `json:"engine_interval_s"`
}

type DeviceConf struct {
	Name   string  `json:"name"`
	URL    string  `json:"url"`
	UnitID uint8   `json:"unit_id"`
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

	reg := registry.New(cfg.pollInterval())
	ra := adapters.NewRegistryAdapter(reg)

	for _, ic := range cfg.Inverters {
		inv, err := inverter.New(ic.URL, 5*time.Second, ic.UnitID)
		if err != nil {
			log.Printf("orchestrator: inverter %s: %v — skipped", ic.Name, err)
			continue
		}
		reg.Add(&registry.Entry{Name: ic.Name, Addr: ic.URL, Device: inv})
		ra.RegisterDevice(ic.Name, adapters.RoleSolar, ic.MaxW)
		log.Printf("orchestrator: inverter registered: %s", ic.Name)
	}

	for _, mc := range cfg.Meters {
		mtr, err := meter.New(mc.URL, 5*time.Second, mc.UnitID)
		if err != nil {
			log.Printf("orchestrator: meter %s: %v — skipped", mc.Name, err)
			continue
		}
		reg.Add(&registry.Entry{Name: mc.Name, Addr: mc.URL, Device: mtr})
		ra.RegisterDevice(mc.Name, adapters.RoleGridMeter, 0)
		log.Printf("orchestrator: meter registered: %s (model %d)", mc.Name, mtr.ModelID())
	}

	var battNames []string
	var battDevices []*battery.Battery
	for _, bc := range cfg.Batteries {
		bat, err := battery.New(bc.URL, 5*time.Second, bc.UnitID)
		if err != nil {
			log.Printf("orchestrator: battery %s: %v — skipped", bc.Name, err)
			continue
		}
		reg.Add(&registry.Entry{Name: bc.Name, Addr: bc.URL, Device: bat})
		ra.RegisterDevice(bc.Name, adapters.RoleBattery, bc.MaxW)
		battNames = append(battNames, bc.Name)
		battDevices = append(battDevices, bat)
		log.Printf("orchestrator: battery registered: %s", bc.Name)
	}

	ocppSrv := ocppserver.New(ocppserver.Config{
		Port:     cfg.OCPPPort,
		CertPath: cfg.OCPPCert,
		KeyPath:  cfg.OCPPKey,
	})
	go ocppSrv.Start()
	defer ocppSrv.Stop()
	ocppTracker := adapters.NewOCPPStateTracker(ocppSrv.CSMS())

	reader := &adapters.CompositeSystemReader{Registry: ra, OCPP: ocppTracker}

	opt := orchestrator.NewDefaultOptimizer()
	opt.CostModel = orchestrator.DefaultTOUCostModel()
	opt.Debug = true

	eng := orchestrator.New(reader, opt, orchestrator.Config{
		Interval: cfg.engineInterval(),
		Debug:    true,
	})
	for _, bc := range cfg.Batteries {
		eng.RegisterBatteryActuator(bc.Name, adapters.NewRegistryBatteryActuator(reg, bc.Name, bc.MaxW))
	}
	for _, ic := range cfg.Inverters {
		eng.RegisterSolarActuator(ic.Name, adapters.NewRegistrySolarActuator(reg, ic.Name, ic.MaxW))
	}
	eng.RegisterEVSEActuator("*", ocppTracker)

	reg.Start()
	defer reg.Stop()
	ra.Start()
	defer ra.Stop()
	eng.Start()
	defer eng.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go refreshBatteryMetrics(ctx, battNames, battDevices, ra, cfg.pollInterval()*3)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Printf("orchestrator: shutting down")
}

func refreshBatteryMetrics(ctx context.Context, names []string, bats []*battery.Battery, ra *adapters.RegistryAdapter, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i, bat := range bats {
				m, err := bat.ReadBatteryMetrics()
				if err != nil {
					log.Printf("orchestrator: battery metrics %s: %v", names[i], err)
					continue
				}
				ra.UpdateBatteryMetrics(names[i], m)
			}
		}
	}
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
