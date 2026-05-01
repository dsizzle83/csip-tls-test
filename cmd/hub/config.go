package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DeviceConfig describes one southbound device in the hub config file.
type DeviceConfig struct {
	Name   string  `json:"name"`
	URL    string  `json:"url"`
	UnitID uint8   `json:"unit_id"`
	Role   string  `json:"role"` // "inverter" | "battery" | "meter"
	MaxW   float64 `json:"max_w"` // nameplate capacity (W); used by orchestrator actuators
}

// Config is the JSON configuration for the hub process.
type Config struct {
	// Northbound (CSIP / IEEE 2030.5 server)
	Server     string `json:"server"`
	CACert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	LFDI       string `json:"lfdi"` // derived from ClientCert if empty

	// Timing (seconds; defaults applied by loadConfig)
	DiscoveryIntervalS int `json:"discovery_interval_s"`
	ControlIntervalS   int `json:"control_interval_s"`
	PollIntervalS      int `json:"poll_interval_s"`
	MUPPostRateS       int `json:"mup_post_rate_s"`

	// Response acknowledgement (GEN.044 / CORE-022)
	ResponseSetPath string `json:"response_set_path"` // e.g. "/rsps/0/r"

	// Southbound devices
	Devices []DeviceConfig `json:"devices"`

	// MetricsPort is the TCP port for the Prometheus metrics HTTP server.
	// Default 9100 (node_exporter convention). Set to 0 to disable.
	MetricsPort int `json:"metrics_port"`

	// OCPP 2.0.1 CSMS (Security Profile 2). Set OCPPPort to 0 to disable.
	OCPPPort int    `json:"ocpp_port"` // default 8887 when non-zero
	OCPPCert string `json:"ocpp_cert"` // TLS cert path; empty → plain WebSocket
	OCPPKey  string `json:"ocpp_key"`  // TLS key path

	// EngineIntervalS is the orchestrator control tick in seconds. Default 15.
	EngineIntervalS int `json:"engine_interval_s"`
}

func (c *Config) DiscoveryInterval() time.Duration {
	return time.Duration(c.DiscoveryIntervalS) * time.Second
}
func (c *Config) ControlInterval() time.Duration {
	return time.Duration(c.ControlIntervalS) * time.Second
}
func (c *Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalS) * time.Second
}
func (c *Config) MUPPostRate() time.Duration {
	return time.Duration(c.MUPPostRateS) * time.Second
}

// loadConfig reads and parses the JSON config at path, applying defaults
// for missing integer fields.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.DiscoveryIntervalS == 0 {
		cfg.DiscoveryIntervalS = 60
	}
	if cfg.ControlIntervalS == 0 {
		cfg.ControlIntervalS = 30
	}
	if cfg.PollIntervalS == 0 {
		cfg.PollIntervalS = 10
	}
	if cfg.MUPPostRateS == 0 {
		cfg.MUPPostRateS = 300
	}
	if cfg.ResponseSetPath == "" {
		cfg.ResponseSetPath = "/rsps/0/r"
	}
	if cfg.MetricsPort == 0 {
		cfg.MetricsPort = 9100
	}
	return &cfg, nil
}

func (c *Config) MetricsAddr() string {
	return fmt.Sprintf(":%d", c.MetricsPort)
}

func (c *Config) EngineInterval() time.Duration {
	if c.EngineIntervalS <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.EngineIntervalS) * time.Second
}
