// Package battery implements device.Device for SunSpec-compliant Li-Ion
// battery storage systems. It reads AC measurements from Model 103 (same
// layout as an inverter) and applies controls via Model 123, exactly like
// the inverter package. The additional capability is reading battery state
// (SoC, SoH, ChaSt) from Model 802.
//
// Control mapping from CSIP DERControlBase:
//
//	OpModConnect  → Model 123 Conn register (0=disconnect, 1=connect)
//	OpModExpLimW  → Model 123 WMaxLimPct  (discharge limit, % of WMax)
//	OpModMaxLimW  → same as OpModExpLimW (most restrictive wins at the bridge)
//
// Note: charge-rate limiting (OpModImpLimW) and storage-specific modes
// (OpModStorageTargetW) are not yet implemented — they require Model 124
// or vendor-specific extensions.
package battery

import (
	"fmt"
	"math"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/modbus"
	"csip-tls-test/internal/southbound/sunspec"
)

// Battery implements device.Device for a SunSpec battery over Modbus.
type Battery struct {
	transport modbus.Transport
	reader    *sunspec.Reader
	wmax      float64 // nameplate WMax in watts; NaN if Model 121 absent
}

// New opens a Modbus connection to url, scans for SunSpec models, and
// returns a Battery. Caller must Close when done.
func New(url string, timeout time.Duration, unitID uint8) (*Battery, error) {
	t, err := modbus.NewTransport(url, timeout)
	if err != nil {
		return nil, err
	}
	if err := t.Open(); err != nil {
		return nil, fmt.Errorf("battery: open %s: %w", url, err)
	}
	if err := t.SetUnitID(unitID); err != nil {
		t.Close()
		return nil, fmt.Errorf("battery: set unit id %d: %w", unitID, err)
	}

	r, err := sunspec.NewReader(t)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("battery: scan SunSpec blocks: %w", err)
	}
	if !r.HasModel(sunspec.ModelInverterThreePh) &&
		!r.HasModel(sunspec.ModelInverterSplitPh) &&
		!r.HasModel(sunspec.ModelInverterSinglePh) {
		t.Close()
		return nil, fmt.Errorf("battery: device has no inverter model (101/102/103) for AC measurements")
	}

	wmax := math.NaN()
	if r.HasModel(sunspec.ModelBasicSettings) {
		if w, err := readWMax(r); err == nil {
			wmax = w
		}
	}

	return &Battery{transport: t, reader: r, wmax: wmax}, nil
}

// Close releases the Modbus transport.
func (b *Battery) Close() error {
	return b.transport.Close()
}

// ReadMeasurements reads AC measurements from Model 103 (Three-Phase).
// Positive W = discharging (export to grid); negative W = charging (import).
func (b *Battery) ReadMeasurements() (device.Measurements, error) {
	// Use the best available AC measurement model.
	measModel := uint16(0)
	for _, id := range []uint16{sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh} {
		if b.reader.HasModel(id) {
			measModel = id
			break
		}
	}
	regs, err := b.reader.ReadModel(measModel)
	if err != nil {
		return device.Measurements{}, fmt.Errorf("battery: read model %d: %w", measModel, err)
	}
	return parseACModel(regs), nil
}

// Status reads the battery connection state from Model 802 (if present) or
// falls back to the AC inverter model operating state.
func (b *Battery) Status() (device.DeviceStatus, error) {
	if b.reader.HasModel(sunspec.ModelLithiumBattery) {
		regs, err := b.reader.ReadModel(sunspec.ModelLithiumBattery)
		if err != nil {
			return device.DeviceStatus{}, fmt.Errorf("battery: read Model 802: %w", err)
		}
		if len(regs) > sunspec.M802_State {
			state := regs[sunspec.M802_State]
			chaSt := uint16(0)
			if len(regs) > sunspec.M802_ChaSt {
				chaSt = regs[sunspec.M802_ChaSt]
			}
			return device.DeviceStatus{
				// State 2=connected, 3=standby.
				Connected: state == 2 || state == 3,
				// ChaSt 3=discharging, 4=charging, 5=full, 6=holding.
				Energized: chaSt >= 3 && chaSt <= 6,
			}, nil
		}
	}

	// Fall back to AC inverter model St register.
	measModel := sunspec.ModelInverterThreePh
	if b.reader.HasModel(sunspec.ModelInverterSplitPh) {
		measModel = sunspec.ModelInverterSplitPh
	}
	regs, err := b.reader.ReadModel(measModel)
	if err != nil {
		return device.DeviceStatus{}, fmt.Errorf("battery: read status: %w", err)
	}
	if len(regs) <= sunspec.M103_St {
		return device.DeviceStatus{}, fmt.Errorf("battery: model too short for St")
	}
	st := regs[sunspec.M103_St]
	return device.DeviceStatus{
		Connected: st == 4 || st == 5,
		Energized: st >= 3 && st <= 6,
	}, nil
}

// ApplyControl writes control values to Model 123 (Immediate Controls).
func (b *Battery) ApplyControl(ctrl model.DERControlBase) error {
	if !b.reader.HasModel(sunspec.ModelImmediateCtrl) {
		return fmt.Errorf("battery: device has no Model 123 (Immediate Controls)")
	}
	if ctrl.OpModConnect != nil {
		if err := b.setConnect(*ctrl.OpModConnect); err != nil {
			return err
		}
	}
	lim := ctrl.OpModExpLimW
	if lim == nil {
		lim = ctrl.OpModMaxLimW
	}
	if lim != nil {
		if err := b.setExportLimit(lim); err != nil {
			return err
		}
	}
	return nil
}

func (b *Battery) setConnect(connect bool) error {
	val := uint16(0)
	if connect {
		val = 1
	}
	if err := b.reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_Conn, []uint16{val}); err != nil {
		return fmt.Errorf("battery: set connect=%v: %w", connect, err)
	}
	return nil
}

func (b *Battery) setExportLimit(ap *model.ActivePower) error {
	if math.IsNaN(b.wmax) || b.wmax <= 0 {
		return fmt.Errorf("battery: cannot set export limit: WMax unknown")
	}
	requestedW := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
	if requestedW < 0 {
		requestedW = 0
	}
	if requestedW > b.wmax {
		requestedW = b.wmax
	}
	regs, err := b.reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return fmt.Errorf("battery: read Model 123 for WMaxLimPct_SF: %w", err)
	}
	if len(regs) <= sunspec.M123_WMaxLimPct_SF {
		return fmt.Errorf("battery: Model 123 too short for WMaxLimPct_SF")
	}
	sf := int16(regs[sunspec.M123_WMaxLimPct_SF])
	pct := (requestedW / b.wmax) * 100.0
	raw := sunspec.RawFromScaleUint(pct, sf)
	if err := b.reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct, []uint16{raw}); err != nil {
		return fmt.Errorf("battery: write WMaxLimPct: %w", err)
	}
	if err := b.reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct_Ena, []uint16{1}); err != nil {
		return fmt.Errorf("battery: enable WMaxLimPct: %w", err)
	}
	return nil
}

// parseACModel extracts device.Measurements from Model 10x registers.
// Positive W means export; negative means import (charging).
func parseACModel(regs []uint16) device.Measurements {
	get := func(offset int) uint16 {
		if offset < len(regs) {
			return regs[offset]
		}
		return 0
	}
	sf := func(offset int) int16 { return int16(get(offset)) }

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

func readWMax(r *sunspec.Reader) (float64, error) {
	regs, err := r.ReadModel(sunspec.ModelBasicSettings)
	if err != nil {
		return 0, err
	}
	if len(regs) <= sunspec.M121_WMax_SF {
		return 0, fmt.Errorf("sunspec: Model 121 too short")
	}
	sf := int16(regs[sunspec.M121_WMax_SF])
	wmax := sunspec.ApplyScaleUint(regs[sunspec.M121_WMax], sf)
	if wmax <= 0 || math.IsNaN(wmax) {
		return 0, fmt.Errorf("sunspec: WMax is %g", wmax)
	}
	return wmax, nil
}
