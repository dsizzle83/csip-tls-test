// Package inverter implements device.Device for SunSpec-compliant grid-tied
// inverters. It reads measurements from Model 103 (Three-Phase Inverter) —
// or Model 101/102 for single/split-phase — and applies controls via
// Model 123 (Immediate Controls).
//
// Control mapping from CSIP DERControlBase:
//
//	OpModConnect  → Model 123 Conn register (0=disconnect, 1=connect)
//	OpModExpLimW  → Model 123 WMaxLimPct (% of nameplate WMax, from Model 121)
//	OpModMaxLimW  → same as OpModExpLimW (most restrictive wins at the bridge)
//
// Power-limit writes require the device's nameplate WMax (from Model 121).
// If Model 121 is absent, power limits are not applied and an error is returned.
package inverter

import (
	"fmt"
	"math"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/modbus"
	"csip-tls-test/internal/southbound/sunspec"
)

// Inverter implements device.Device for a SunSpec inverter over Modbus.
type Inverter struct {
	transport modbus.Transport
	reader    *sunspec.Reader
	wmax      float64 // nameplate WMax in watts; NaN if Model 121 absent
	measModel uint16  // model ID used for measurements (101, 102, or 103)
}

// New opens a Modbus connection to url, scans for SunSpec models, reads the
// nameplate WMax, and returns an Inverter. Caller must Close when done.
//
// url selects the physical layer ("tcp://host:502", "rtu:///dev/ttyS0", …).
// timeout applies to each Modbus transaction.
// unitID is the Modbus slave address (1 for most standalone inverters).
func New(url string, timeout time.Duration, unitID uint8) (*Inverter, error) {
	t, err := modbus.NewTransport(url, timeout)
	if err != nil {
		return nil, err
	}
	if err := t.Open(); err != nil {
		return nil, fmt.Errorf("inverter: open %s: %w", url, err)
	}
	if err := t.SetUnitID(unitID); err != nil {
		t.Close()
		return nil, fmt.Errorf("inverter: set unit id %d: %w", unitID, err)
	}
	inv, err := newFromTransport(t)
	if err != nil {
		t.Close()
		return nil, err
	}
	return inv, nil
}

// newFromTransport creates an Inverter using an already-open Transport.
// Used by tests that inject a pre-configured transport.
func newFromTransport(t modbus.Transport) (*Inverter, error) {
	r, err := sunspec.NewReader(t)
	if err != nil {
		return nil, fmt.Errorf("inverter: scan SunSpec blocks: %w", err)
	}

	// Pick the most capable inverter measurement model available.
	measModel := uint16(0)
	for _, candidate := range []uint16{sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh} {
		if r.HasModel(candidate) {
			measModel = candidate
			break
		}
	}
	if measModel == 0 {
		return nil, fmt.Errorf("inverter: device has no inverter model (101/102/103)")
	}

	// Read nameplate WMax from Model 121 (Basic Settings) if present.
	wmax := math.NaN()
	if r.HasModel(sunspec.ModelBasicSettings) {
		if w, err := readWMax(r); err == nil {
			wmax = w
		}
		// Non-fatal: power limits will fail if WMax is unknown, but
		// connect/disconnect still works.
	}

	return &Inverter{
		transport: t,
		reader:    r,
		wmax:      wmax,
		measModel: measModel,
	}, nil
}

// Close releases the Modbus transport.
func (inv *Inverter) Close() error {
	return inv.transport.Close()
}

// ReadMeasurements reads AC and DC measurements from the inverter model block.
func (inv *Inverter) ReadMeasurements() (device.Measurements, error) {
	regs, err := inv.reader.ReadModel(inv.measModel)
	if err != nil {
		return device.Measurements{}, fmt.Errorf("inverter: read model %d: %w", inv.measModel, err)
	}
	return parseInverterModel(regs), nil
}

// Status reads the operating state (St) from the inverter model.
// SunSpec St values: 1=Off, 2=Sleeping, 3=Starting, 4=MPPT, 5=Throttled,
// 6=ShuttingDown, 7=Fault, 8=Standby.
func (inv *Inverter) Status() (device.DeviceStatus, error) {
	regs, err := inv.reader.ReadModel(inv.measModel)
	if err != nil {
		return device.DeviceStatus{}, fmt.Errorf("inverter: read status: %w", err)
	}
	if len(regs) <= sunspec.M103_St {
		return device.DeviceStatus{}, fmt.Errorf("inverter: model %d too short for St register", inv.measModel)
	}
	st := regs[sunspec.M103_St]
	return device.DeviceStatus{
		// MPPT (4) or Throttled (5): grid-connected and producing.
		Connected: st == 4 || st == 5,
		// Starting (3) through ShuttingDown (6): energized.
		Energized: st >= 3 && st <= 6,
	}, nil
}

// ApplyControl writes control values to Model 123 (Immediate Controls).
// Nil fields in ctrl are left unchanged on the device.
func (inv *Inverter) ApplyControl(ctrl model.DERControlBase) error {
	if !inv.reader.HasModel(sunspec.ModelImmediateCtrl) {
		return fmt.Errorf("inverter: device has no Model 123 (Immediate Controls)")
	}

	if ctrl.OpModConnect != nil {
		if err := inv.setConnect(*ctrl.OpModConnect); err != nil {
			return err
		}
	}

	// OpModExpLimW and OpModMaxLimW both map to WMaxLimPct. If both are set,
	// use OpModExpLimW (the more specific export limit).
	lim := ctrl.OpModExpLimW
	if lim == nil {
		lim = ctrl.OpModMaxLimW
	}
	if lim != nil {
		if err := inv.setExportLimit(lim); err != nil {
			return err
		}
	}

	return nil
}

// setConnect writes to Model 123 Conn (offset 16): 1=connect, 0=disconnect.
func (inv *Inverter) setConnect(connect bool) error {
	val := uint16(0)
	if connect {
		val = 1
	}
	if err := inv.reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_Conn, []uint16{val}); err != nil {
		return fmt.Errorf("inverter: set connect=%v: %w", connect, err)
	}
	return nil
}

// setExportLimit converts ap (watts) to WMaxLimPct (% of WMax) and writes it
// to Model 123. Requires WMax from Model 121.
func (inv *Inverter) setExportLimit(ap *model.ActivePower) error {
	if math.IsNaN(inv.wmax) || inv.wmax <= 0 {
		return fmt.Errorf("inverter: cannot set export limit: WMax unknown (Model 121 absent or zero)")
	}

	// Convert ActivePower to watts: value × 10^multiplier.
	requestedW := float64(ap.Value) * math.Pow10(int(ap.Multiplier))

	// Clamp to [0, WMax].
	if requestedW < 0 {
		requestedW = 0
	}
	if requestedW > inv.wmax {
		requestedW = inv.wmax
	}

	// Read the WMaxLimPct scale factor from Model 123 (offset 20).
	regs, err := inv.reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return fmt.Errorf("inverter: read Model 123 for WMaxLimPct_SF: %w", err)
	}
	if len(regs) <= sunspec.M123_WMaxLimPct_SF {
		return fmt.Errorf("inverter: Model 123 too short for WMaxLimPct_SF")
	}
	sf := int16(regs[sunspec.M123_WMaxLimPct_SF])

	// Compute percent: (requestedW / WMax) × 100, then apply inverse scale factor.
	pct := (requestedW / inv.wmax) * 100.0
	raw := sunspec.RawFromScaleUint(pct, sf)

	// Write WMaxLimPct (offset 0) and set Ena=1 (offset 4).
	if err := inv.reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct, []uint16{raw}); err != nil {
		return fmt.Errorf("inverter: write WMaxLimPct: %w", err)
	}
	if err := inv.reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct_Ena, []uint16{1}); err != nil {
		return fmt.Errorf("inverter: enable WMaxLimPct: %w", err)
	}
	return nil
}

// readWMax reads the nameplate WMax (in watts) from Model 121 (Basic Settings).
func readWMax(r *sunspec.Reader) (float64, error) {
	regs, err := r.ReadModel(sunspec.ModelBasicSettings)
	if err != nil {
		return 0, err
	}
	if len(regs) <= sunspec.M121_WMax_SF {
		return 0, fmt.Errorf("sunspec: Model 121 too short for WMax_SF")
	}
	sf := int16(regs[sunspec.M121_WMax_SF])
	wmax := sunspec.ApplyScaleUint(regs[sunspec.M121_WMax], sf)
	if wmax <= 0 || math.IsNaN(wmax) {
		return 0, fmt.Errorf("sunspec: Model 121 WMax is %g (invalid)", wmax)
	}
	return wmax, nil
}

// parseInverterModel extracts Measurements from a slice of raw Model 10x registers.
// The register layout is the same for Models 101, 102, and 103.
func parseInverterModel(regs []uint16) device.Measurements {
	get := func(offset int) uint16 {
		if offset < len(regs) {
			return regs[offset]
		}
		return 0
	}
	sf := func(offset int) int16 {
		return int16(get(offset))
	}

	m := device.Measurements{TmpCab: math.NaN()}

	if len(regs) > sunspec.M103_W_SF {
		m.W = sunspec.ApplyScaleSigned(get(sunspec.M103_W), sf(sunspec.M103_W_SF))
	}
	if len(regs) > sunspec.M103_V_SF {
		m.V = sunspec.ApplyScaleUint(get(sunspec.M103_PhVphA), sf(sunspec.M103_V_SF))
	}
	if len(regs) > sunspec.M103_Hz_SF {
		m.Hz = sunspec.ApplyScaleUint(get(sunspec.M103_Hz), sf(sunspec.M103_Hz_SF))
	}
	if len(regs) > sunspec.M103_VA_SF {
		m.VA = sunspec.ApplyScaleSigned(get(sunspec.M103_VA), sf(sunspec.M103_VA_SF))
	}
	if len(regs) > sunspec.M103_VAr_SF {
		m.Var = sunspec.ApplyScaleSigned(get(sunspec.M103_VAr), sf(sunspec.M103_VAr_SF))
	}
	if len(regs) > sunspec.M103_PF_SF {
		// SunSpec PF is stored ×100; divide back to get -1..+1.
		m.PF = sunspec.ApplyScaleSigned(get(sunspec.M103_PF), sf(sunspec.M103_PF_SF)) / 100.0
	}
	if len(regs) > sunspec.M103_DCW_SF {
		m.DCV = sunspec.ApplyScaleUint(get(sunspec.M103_DCV), sf(sunspec.M103_DCV_SF))
		m.DCW = sunspec.ApplyScaleSigned(get(sunspec.M103_DCW), sf(sunspec.M103_DCW_SF))
	}
	if len(regs) > sunspec.M103_Tmp_SF {
		m.TmpCab = sunspec.ApplyScaleSigned(get(sunspec.M103_TmpCab), sf(sunspec.M103_Tmp_SF))
	}
	return m
}
