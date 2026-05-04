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

// clampInt16 converts a float64 to int16, saturating at the type boundaries.
func clampInt16(v float64) int16 {
	if v > math.MaxInt16 {
		return math.MaxInt16
	}
	if v < math.MinInt16 {
		return math.MinInt16
	}
	return int16(v)
}

// DeviceRole classifies a registry entry for the orchestrator.
type DeviceRole uint8

const (
	RoleBattery DeviceRole = iota
	RoleSolar
	RoleGridMeter // SunSpec AC meter at the main service entrance
)

// DeviceConfig describes one registered device.
type DeviceConfig struct {
	Name string
	Role DeviceRole
	// MaxW is the device's nameplate power capacity (W).  Used when the live
	// device does not expose it via ReadBatteryMetrics.
	MaxW float64
	// MaxCurrentA is the EVSE hardware limit (A).
	MaxCurrentA float64
	// Dev is the direct device reference used for per-device polling and for
	// automatically reading BatteryMetrics on battery-role devices.
	// May be nil for simple measurement-only registrations.
	Dev device.Device
}

// RegistryAdapter builds an orchestrator.SystemState from a registry.Registry
// and a set of per-device role assignments. It subscribes to registry
// measurement updates and maintains a latest-snapshot map.
//
// A dispatcher goroutine fans update messages out to per-device goroutines so
// that a slow Modbus read on one device never delays state updates from others.
// Battery-role devices that implement BatteryMetricsReader have their metrics
// fetched automatically inside their own goroutine after each measurement update.
//
// Usage:
//
//	ra := adapters.NewRegistryAdapter(reg)
//	ra.RegisterDevice("inverter-0", adapters.RoleSolar, 10000, inverterDev)
//	ra.RegisterDevice("battery-0", adapters.RoleBattery, 5000, batteryDev)
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
	wg   sync.WaitGroup
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
	}
}

// RegisterDevice adds a named device with a role assignment.
// dev is the direct device reference; it enables automatic BatteryMetrics polling
// for battery-role devices and per-device goroutine isolation.  Pass nil to fall
// back to manual UpdateBatteryMetrics calls (e.g. in tests with mock devices that
// do not implement BatteryMetricsReader).
func (ra *RegistryAdapter) RegisterDevice(name string, role DeviceRole, maxW float64, dev device.Device) {
	ra.devices = append(ra.devices, DeviceConfig{Name: name, Role: role, MaxW: maxW, Dev: dev})
}

// SetGridState injects externally-measured grid values (e.g. from a grid meter
// or a separate Modbus device).
func (ra *RegistryAdapter) SetGridState(g orchestrator.GridState) {
	ra.mu.Lock()
	ra.grid = g
	ra.mu.Unlock()
}

// Start begins consuming registry measurement updates.  Pair with Stop.
//
// A dispatcher goroutine fans each MeasurementUpdate out to a per-device
// buffered channel. Per-device goroutines process their own channel so that a
// slow Modbus read on one device (including BatteryMetrics) never delays state
// updates from other devices.
func (ra *RegistryAdapter) Start() {
	sub, unsubscribe := ra.reg.Subscribe()

	// Build per-device channels.
	devChans := make(map[string]chan registry.MeasurementUpdate, len(ra.devices))
	for _, dc := range ra.devices {
		ch := make(chan registry.MeasurementUpdate, 4)
		devChans[dc.Name] = ch
		ra.wg.Add(1)
		go ra.runDevice(dc, ch)
	}

	// Dispatcher: drain the subscription channel and route to per-device channels.
	ra.wg.Add(1)
	go func() {
		defer ra.wg.Done()
		defer unsubscribe()
		defer func() {
			for _, ch := range devChans {
				close(ch)
			}
		}()
		for {
			select {
			case <-ra.stop:
				return
			case upd, ok := <-sub:
				if !ok {
					return
				}
				if ch, ok := devChans[upd.Name]; ok {
					select {
					case ch <- upd:
					default: // per-device channel full; drop stale update
					}
				}
			}
		}
	}()
}

// Stop shuts down all goroutines and waits for them to exit.
func (ra *RegistryAdapter) Stop() {
	close(ra.stop)
	ra.wg.Wait()
}

// runDevice processes measurement updates for one device and, for battery-role
// devices that implement BatteryMetricsReader, fetches metrics automatically
// after each successful measurement so the caller needs no manual wiring.
func (ra *RegistryAdapter) runDevice(dc DeviceConfig, updates <-chan registry.MeasurementUpdate) {
	defer ra.wg.Done()
	for upd := range updates { // exits when dispatcher closes the channel
		ra.mu.Lock()
		if upd.Err != nil {
			ra.status[upd.Name] = device.DeviceStatus{Connected: false}
		} else {
			ra.latest[upd.Name] = upd.Measurements
			ra.status[upd.Name] = device.DeviceStatus{Connected: true, Energized: true}
		}
		ra.mu.Unlock()

		// Auto-fetch battery metrics for devices that support it.
		if dc.Role == RoleBattery && dc.Dev != nil && upd.Err == nil {
			if bmr, ok := dc.Dev.(orchestrator.BatteryMetricsReader); ok {
				if m, err := bmr.ReadBatteryMetrics(); err == nil {
					ra.mu.Lock()
					ra.metrics[upd.Name] = m
					ra.mu.Unlock()
				}
			}
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
			ctrl.OpModExpLimW = &model.ActivePower{Value: clampInt16(cmd.SetpointW), Multiplier: 0}
		} else {
			ctrl.OpModImpLimW = &model.ActivePower{Value: clampInt16(-cmd.SetpointW), Multiplier: 0}
		}
	}

	return a.reg.ApplyControlTo(a.devName, ctrl)
}

// ── SolarActuator ─────────────────────────────────────────────────────────────

// RegistrySolarActuator applies SolarCommands via the registry.
type RegistrySolarActuator struct {
	reg     *registry.Registry
	devName string
	maxW    float64
}

// NewRegistrySolarActuator creates an actuator for the named solar inverter.
func NewRegistrySolarActuator(reg *registry.Registry, devName string, maxW float64) *RegistrySolarActuator {
	return &RegistrySolarActuator{reg: reg, devName: devName, maxW: maxW}
}

// ApplySolarCommand implements orchestrator.SolarActuator.
func (a *RegistrySolarActuator) ApplySolarCommand(cmd orchestrator.SolarCommand) error {
	var w int16
	if math.IsNaN(cmd.CurtailToW) {
		if a.maxW <= 0 {
			return nil // max_w not configured; leave device producing freely
		}
		// Restore full nameplate output.
		w = clampInt16(a.maxW)
	} else {
		w = clampInt16(math.Max(0, cmd.CurtailToW))
	}
	return a.reg.ApplyControlTo(a.devName, model.DERControlBase{
		OpModMaxLimW: &model.ActivePower{Value: w, Multiplier: 0},
	})
}
