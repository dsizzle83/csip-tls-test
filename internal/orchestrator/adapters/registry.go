// Package adapters provides concrete implementations of the orchestrator
// interfaces that bridge existing components (registry, ocppserver) to the
// orchestrator's SystemReader and actuator contracts.
package adapters

import (
	"math"
	"sync"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/orchestrator"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/registry"
)

// DeviceRole classifies a registry entry for the orchestrator.
type DeviceRole uint8

const (
	RoleBattery    DeviceRole = iota
	RoleSolar
	RoleLoad
	RoleGridMeter // SunSpec AC meter at the main service entrance
)

// DeviceConfig describes one registered device.
type DeviceConfig struct {
	Name string
	Role DeviceRole
	// MaxW is the device's nameplate power capacity (W).  Used when the live
	// device does not expose it via ReadBatteryMetrics.
	MaxW float64
	// MaxCurrentA is the EVSE hardware limit (A); only used for RoleLoad EVSEs.
	MaxCurrentA float64
}

// RegistryAdapter builds an orchestrator.SystemState from a registry.Registry
// and a set of per-device role assignments.  It subscribes to the registry's
// Updates channel and maintains a latest-snapshot map.
//
// Usage:
//
//	ra := adapters.NewRegistryAdapter(reg)
//	ra.RegisterDevice("inverter-0", adapters.RoleSolar, 10000)
//	ra.RegisterDevice("battery-0", adapters.RoleBattery, 5000)
//	// wire ra as orchestrator.SystemReader
type RegistryAdapter struct {
	reg     *registry.Registry
	devices []DeviceConfig

	mu      sync.RWMutex
	latest  map[string]device.Measurements
	status  map[string]device.DeviceStatus
	metrics map[string]orchestrator.BatteryMetrics // battery-only

	// GridState can be injected externally (e.g. from a separate grid meter).
	grid orchestrator.GridState

	stop chan struct{}
	done chan struct{}
}

// NewRegistryAdapter creates an adapter backed by reg.
// Call RegisterDevice for each device, then Start to begin consuming updates.
func NewRegistryAdapter(reg *registry.Registry) *RegistryAdapter {
	return &RegistryAdapter{
		reg:     reg,
		latest:  make(map[string]device.Measurements),
		status:  make(map[string]device.DeviceStatus),
		metrics: make(map[string]orchestrator.BatteryMetrics),
		grid:    orchestrator.NewGridState(),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// RegisterDevice adds a named device with a role assignment.
func (ra *RegistryAdapter) RegisterDevice(name string, role DeviceRole, maxW float64) {
	ra.devices = append(ra.devices, DeviceConfig{Name: name, Role: role, MaxW: maxW})
}

// SetGridState injects externally-measured grid values (e.g. from a grid meter
// or a separate Modbus device).
func (ra *RegistryAdapter) SetGridState(g orchestrator.GridState) {
	ra.mu.Lock()
	ra.grid = g
	ra.mu.Unlock()
}

// Start begins consuming registry measurement updates.  Pair with Stop.
func (ra *RegistryAdapter) Start() {
	go ra.run()
}

// Stop shuts down the update consumer.
func (ra *RegistryAdapter) Stop() {
	close(ra.stop)
	<-ra.done
}

func (ra *RegistryAdapter) run() {
	defer close(ra.done)
	updates := ra.reg.Updates()
	for {
		select {
		case <-ra.stop:
			return
		case upd, ok := <-updates:
			if !ok {
				return
			}
			if upd.Err != nil {
				continue // keep stale snapshot on error
			}
			ra.mu.Lock()
			ra.latest[upd.Name] = upd.Measurements
			ra.mu.Unlock()
		}
	}
}

// UpdateBatteryMetrics stores battery-specific metrics for a device.
// Call this from a background goroutine that polls battery SoC etc.
func (ra *RegistryAdapter) UpdateBatteryMetrics(name string, m orchestrator.BatteryMetrics) {
	ra.mu.Lock()
	ra.metrics[name] = m
	ra.mu.Unlock()
}

// UpdateDeviceStatus stores a DeviceStatus snapshot (from a periodic poll).
func (ra *RegistryAdapter) UpdateDeviceStatus(name string, s device.DeviceStatus) {
	ra.mu.Lock()
	ra.status[name] = s
	ra.mu.Unlock()
}

// ReadSystemState implements orchestrator.SystemReader.
//
// Power sign mapping from device.Measurements.W to orchestrator types:
//
//	Solar    → SolarState.PowerW      = max(0, W)  (generation is always ≥ 0)
//	Battery  → BatteryState.PowerW   = W           (+ discharge, − charge)
//	Meter    → GridState.NetW        += W           (+ import from grid, − export)
func (ra *RegistryAdapter) ReadSystemState() (orchestrator.SystemState, error) {
	ra.mu.RLock()
	defer ra.mu.RUnlock()

	state := orchestrator.SystemState{
		Timestamp: time.Now(),
		Grid:      ra.grid,
	}

	for _, dc := range ra.devices {
		m := ra.latest[dc.Name]
		st := ra.status[dc.Name]

		switch dc.Role {
		case RoleBattery:
			b := orchestrator.NewBatteryState(dc.Name)
			b.PowerW = m.W
			b.Connected = st.Connected
			b.Energized = st.Energized
			b.MaxDischargeW = dc.MaxW
			b.MaxChargeW = dc.MaxW
			// Override with live metrics if available.
			if bm, ok := ra.metrics[dc.Name]; ok {
				if !math.IsNaN(bm.SOC) {
					b.SOC = bm.SOC
				}
				if !math.IsNaN(bm.SOH) {
					b.SOH = bm.SOH
				}
				if !math.IsNaN(bm.CapacityWh) {
					b.CapacityWh = bm.CapacityWh
				}
				if bm.MaxChargeW > 0 {
					b.MaxChargeW = bm.MaxChargeW
				}
				if bm.MaxDischargeW > 0 {
					b.MaxDischargeW = bm.MaxDischargeW
				}
			}
			state.Batteries = append(state.Batteries, b)

		case RoleSolar:
			sol := orchestrator.SolarState{
				Name:      dc.Name,
				PowerW:    math.Max(0, m.W), // solar only exports
				MaxW:      dc.MaxW,
				Connected: st.Connected,
				Energized: st.Energized,
			}
			state.Solar = append(state.Solar, sol)

		case RoleGridMeter:
			// Meter W: positive = importing, negative = exporting.
			// Maps directly to GridState.NetW (our convention: positive=import).
			// If multiple meters are registered (multi-service buildings), sum them.
			if !math.IsNaN(m.W) {
				if math.IsNaN(state.Grid.NetW) {
					state.Grid.NetW = m.W
				} else {
					state.Grid.NetW += m.W
				}
			}
		}
	}

	return state, nil
}

// ── BatteryActuator ───────────────────────────────────────────────────────────

// RegistryBatteryActuator applies BatteryCommands to the registry via
// DERControlBase.  It translates the orchestrator's watt-based setpoints into
// CSIP OpModExpLimW / OpModImpLimW commands.
type RegistryBatteryActuator struct {
	reg     *registry.Registry
	maxW    float64 // device nameplate, for percent conversion
	devName string
}

// NewRegistryBatteryActuator creates an actuator for a battery in reg.
// maxW is the battery's nameplate discharge capacity, used to convert watts
// to the CSIP percentage representation.
func NewRegistryBatteryActuator(reg *registry.Registry, devName string, maxW float64) *RegistryBatteryActuator {
	return &RegistryBatteryActuator{reg: reg, devName: devName, maxW: maxW}
}

// ApplyBatteryCommand implements orchestrator.BatteryActuator.
func (a *RegistryBatteryActuator) ApplyBatteryCommand(cmd orchestrator.BatteryCommand) error {
	if math.IsNaN(cmd.SetpointW) && cmd.Connect == nil {
		return nil // nothing to do
	}

	ctrl := model.DERControlBase{}
	ctrl.OpModConnect = cmd.Connect

	if !math.IsNaN(cmd.SetpointW) {
		if cmd.SetpointW >= 0 {
			// Discharge: set export limit to the requested discharge rate.
			w := int16(cmd.SetpointW)
			ctrl.OpModExpLimW = &model.ActivePower{Value: w, Multiplier: 0}
		} else {
			// Charge: set import limit to the requested charge rate.
			w := int16(-cmd.SetpointW) // positive magnitude
			ctrl.OpModImpLimW = &model.ActivePower{Value: w, Multiplier: 0}
		}
	}

	return a.reg.ApplyControlTo(a.devName, ctrl)
}

// ── SolarActuator ─────────────────────────────────────────────────────────────

// RegistrySolarActuator applies SolarCommands via the registry.
type RegistrySolarActuator struct {
	reg  *registry.Registry
	maxW float64
}

// NewRegistrySolarActuator creates an actuator for a solar inverter.
func NewRegistrySolarActuator(reg *registry.Registry, maxW float64) *RegistrySolarActuator {
	return &RegistrySolarActuator{reg: reg, maxW: maxW}
}

// ApplySolarCommand implements orchestrator.SolarActuator.
func (a *RegistrySolarActuator) ApplySolarCommand(cmd orchestrator.SolarCommand) error {
	if math.IsNaN(cmd.CurtailToW) {
		// No curtailment — restore full output (100%).
		pct := int16(100)
		return a.reg.ApplyControl(model.DERControlBase{
			OpModMaxLimW: &model.ActivePower{Value: pct, Multiplier: 0},
		})
	}
	w := int16(cmd.CurtailToW)
	return a.reg.ApplyControl(model.DERControlBase{
		OpModMaxLimW: &model.ActivePower{Value: w, Multiplier: 0},
	})
}
