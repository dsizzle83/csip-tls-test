// Package battery implements device.Device for SunSpec-compliant battery
// storage systems covering both legacy SunSpec models (101/102/103, 121, 123,
// 802) and the IEEE 1547-2018 SunSpec Modbus profile (701-713).
//
// Model preference (newest wins, older used as fallback):
//
//	Measurements : M701 (DERMeasureAC)       → M103/102/101
//	Nameplate    : M702 (DERCapacity).WMaxRtg → M121 (BasicSettings).WMax
//	Controls     : M704 (DERCtlAC)           → M123 (ImmediateCtrl)
//	Storage state: M713 (DERStorageCapacity) → M802 (LithiumBattery)
//
// Control mapping from CSIP DERControlBase:
//
//	OpModConnect          → M123 Conn (M704 has no connect register)
//	OpModEnergize         → M703 ES (enter-service / cease-to-energize)
//	OpModExpLimW/MaxLimW  → M704.WMaxLimPct  → M123.WMaxLimPct
//	OpModFixedPFAbsorbW   → M704.PFWInjEna + PFWInj_PF + PFWInj_Ext=0
//	OpModFixedPFInjectW   → M704.PFWInjEna + PFWInj_PF + PFWInj_Ext=1
//	OpModFixedVar         → M704.VarSetEna  + VarSetPct
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

// Battery implements device.Device for a SunSpec battery storage system over Modbus.
type Battery struct {
	transport modbus.Transport
	reader    *sunspec.Reader
	wmax      float64 // nameplate WMax in watts; NaN if unavailable
	measModel uint16  // model ID used for measurements: 701, 103, 102, or 101
	has701    bool    // DERMeasureAC present (IEEE 1547-2018)
	has702    bool    // DERCapacity present
	has703    bool    // DEREnterService present
	has704    bool    // DERCtlAC present
	has705    bool    // DERVoltVar present
	has706    bool    // DERVoltWatt present
	has707    bool    // DERTripLV present
	has708    bool    // DERTripHV present
	has709    bool    // DERTripLF present
	has710    bool    // DERTripHF present
	has711    bool    // DERFreqDroop present
	has712    bool    // DERWattVar present
	has713    bool    // DERStorageCapacity present (IEEE 1547-2018)
}

// New opens a Modbus connection to url, scans for SunSpec models, reads the
// nameplate WMax, and returns a Battery. Caller must Close when done.
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
	b, err := newFromTransport(t)
	if err != nil {
		t.Close()
		return nil, err
	}
	return b, nil
}

// newFromTransport creates a Battery using an already-open Transport.
// Used by tests that inject a pre-configured transport.
func newFromTransport(t modbus.Transport) (*Battery, error) {
	r, err := sunspec.NewReader(t)
	if err != nil {
		return nil, fmt.Errorf("battery: scan SunSpec blocks: %w", err)
	}

	b := &Battery{
		transport: t,
		reader:    r,
		wmax:      math.NaN(),
		has701:    r.HasModel(sunspec.ModelDERMeasureAC),
		has702:    r.HasModel(sunspec.ModelDERCapacity),
		has703:    r.HasModel(sunspec.ModelDEREnterService),
		has704:    r.HasModel(sunspec.ModelDERCtlAC),
		has705:    r.HasModel(sunspec.ModelDERVoltVar),
		has706:    r.HasModel(sunspec.ModelDERVoltWatt),
		has707:    r.HasModel(sunspec.ModelDERTripLV),
		has708:    r.HasModel(sunspec.ModelDERTripHV),
		has709:    r.HasModel(sunspec.ModelDERTripLF),
		has710:    r.HasModel(sunspec.ModelDERTripHF),
		has711:    r.HasModel(sunspec.ModelDERFreqDroop),
		has712:    r.HasModel(sunspec.ModelDERWattVar),
		has713:    r.HasModel(sunspec.ModelDERStorageCap),
	}

	// Measurement model: prefer M701, fall back to legacy M103/102/101.
	if b.has701 {
		b.measModel = sunspec.ModelDERMeasureAC
	} else {
		for _, candidate := range []uint16{sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh} {
			if r.HasModel(candidate) {
				b.measModel = candidate
				break
			}
		}
		if b.measModel == 0 {
			return nil, fmt.Errorf("battery: device has no AC measurement model (701, 103, 102, or 101)")
		}
	}

	// Nameplate WMax: prefer M702, fall back to M121.
	if b.has702 {
		if w, err := readWMaxFrom702(r); err == nil {
			b.wmax = w
		}
	} else if r.HasModel(sunspec.ModelBasicSettings) {
		if w, err := readWMax(r); err == nil {
			b.wmax = w
		}
	}

	return b, nil
}

// Close releases the Modbus transport.
func (b *Battery) Close() error {
	return b.transport.Close()
}

// ReadMeasurements reads AC measurements from the battery.
// Uses M701 (DERMeasureAC) when available; falls back to M103/102/101.
// Positive W = discharging (export to grid); negative W = charging (import).
func (b *Battery) ReadMeasurements() (device.Measurements, error) {
	regs, err := b.reader.ReadModel(b.measModel)
	if err != nil {
		return device.Measurements{}, fmt.Errorf("battery: read model %d: %w", b.measModel, err)
	}
	if b.measModel == sunspec.ModelDERMeasureAC {
		return parseM701(regs), nil
	}
	return parseACModel(regs), nil
}

// Status reads the battery connection state.
// Uses M701.St + M701.ConnSt when available; falls back to M802 or M103.St.
func (b *Battery) Status() (device.DeviceStatus, error) {
	if b.measModel == sunspec.ModelDERMeasureAC {
		regs, err := b.reader.ReadModel(sunspec.ModelDERMeasureAC)
		if err != nil {
			return device.DeviceStatus{}, fmt.Errorf("battery: read M701 status: %w", err)
		}
		if len(regs) <= sunspec.M701_ConnSt {
			return device.DeviceStatus{}, fmt.Errorf("battery: M701 too short for St/ConnSt")
		}
		st := sunspec.M701St(regs[sunspec.M701_St])
		return device.DeviceStatus{
			Connected: regs[sunspec.M701_ConnSt] == 1,
			Energized: st == sunspec.M701StOn || st == sunspec.M701StThrottled || st == sunspec.M701StStarting,
		}, nil
	}

	// M701 absent: try M802 for richer battery state.
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
				Connected: state == 2 || state == 3,
				Energized: chaSt >= 3 && chaSt <= 6,
			}, nil
		}
	}

	// Fall back to AC inverter model St register.
	regs, err := b.reader.ReadModel(b.measModel)
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

// ApplyControl writes control values to the battery.
// Prefers M704 (DERCtlAC) for power-factor and reactive-power controls when
// available; falls back to M123 (ImmediateCtrl) for legacy models.
// Connect/disconnect always uses M123.
func (b *Battery) ApplyControl(ctrl model.DERControlBase) error {
	// Cease-to-energize / permit-service → M703 Enter Service.
	if ctrl.OpModEnergize != nil && b.has703 {
		if err := b.setEnterService(*ctrl.OpModEnergize); err != nil {
			return err
		}
	}

	// Connect/disconnect → M123 Conn.
	if ctrl.OpModConnect != nil {
		if !b.reader.HasModel(sunspec.ModelImmediateCtrl) {
			return fmt.Errorf("battery: no M123 for connect control")
		}
		if err := b.setConnect(*ctrl.OpModConnect); err != nil {
			return err
		}
	}

	// Power factor → M704 preferred.
	if ctrl.OpModFixedPFInjectW != nil || ctrl.OpModFixedPFAbsorbW != nil {
		if b.has704 {
			if err := b.setPowerFactor704(ctrl); err != nil {
				return err
			}
		}
	}

	// Constant reactive power → M704 VarSetPct.
	if ctrl.OpModFixedVar != nil && b.has704 {
		if err := b.setConstantVar704(ctrl.OpModFixedVar); err != nil {
			return err
		}
	}

	// Active power limit → M704 preferred, M123 fallback.
	lim := ctrl.OpModExpLimW
	if lim == nil {
		lim = ctrl.OpModMaxLimW
	}
	if lim != nil {
		if b.has704 {
			if err := b.setWMaxLimPct704(lim); err != nil {
				return err
			}
		} else {
			if err := b.setExportLimit(lim); err != nil {
				return err
			}
		}
	}

	return nil
}

// ── IEEE 1547-2018 enter service ─────────────────────────────────────────────

// SetEnterService enables or disables permit-service on the battery via M703.
func (b *Battery) SetEnterService(s sunspec.DEREnterServiceSettings) error {
	if !b.has703 {
		return fmt.Errorf("battery: device has no M703 (DEREnterService)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return fmt.Errorf("battery: read M703: %w", err)
	}
	if err := sunspec.EncodeDEREnterService(regs, s); err != nil {
		return err
	}
	return b.reader.WriteModel(sunspec.ModelDEREnterService, 0, regs)
}

func (b *Battery) setEnterService(energize bool) error {
	regs, err := b.reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return fmt.Errorf("battery: read M703: %w", err)
	}
	if energize {
		regs[sunspec.M703_ES] = 1
	} else {
		regs[sunspec.M703_ES] = 0
	}
	return b.reader.WriteModel(sunspec.ModelDEREnterService, 0, regs[:1])
}

// ReadEnterService reads the current enter-service settings from M703.
func (b *Battery) ReadEnterService() (sunspec.DEREnterServiceSettings, error) {
	if !b.has703 {
		return sunspec.DEREnterServiceSettings{}, fmt.Errorf("battery: device has no M703")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return sunspec.DEREnterServiceSettings{}, fmt.Errorf("battery: read M703: %w", err)
	}
	return sunspec.ParseDEREnterService(regs)
}

// ── IEEE 1547-2018 DERCtlAC (M704) helpers ───────────────────────────────────

func (b *Battery) setPowerFactor704(ctrl model.DERControlBase) error {
	regs, err := b.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("battery: read M704: %w", err)
	}
	s, err := sunspec.ParseDERCtlAC(regs)
	if err != nil {
		return err
	}
	if ctrl.OpModFixedPFInjectW != nil {
		s.PFWInjEna = true
		s.PFWInj_PF = math.Abs(float64(ctrl.OpModFixedPFInjectW.Value)) / 10000.0
		s.PFWInj_Ext = true
	} else if ctrl.OpModFixedPFAbsorbW != nil {
		s.PFWInjEna = true
		s.PFWInj_PF = math.Abs(float64(ctrl.OpModFixedPFAbsorbW.Value)) / 10000.0
		s.PFWInj_Ext = false
	}
	if err := sunspec.EncodeDERCtlAC(regs, s); err != nil {
		return err
	}
	return b.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

func (b *Battery) setConstantVar704(fv *model.FixedVar) error {
	if fv == nil {
		return nil
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("battery: read M704 for var: %w", err)
	}
	s, err := sunspec.ParseDERCtlAC(regs)
	if err != nil {
		return err
	}
	s.VarSetEna = true
	s.VarSetPri = 1
	s.VarSetPct = float64(fv.Value.Value) / 100.0
	if err := sunspec.EncodeDERCtlAC(regs, s); err != nil {
		return err
	}
	return b.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

func (b *Battery) setWMaxLimPct704(ap *model.ActivePower) error {
	if math.IsNaN(b.wmax) || b.wmax <= 0 {
		return fmt.Errorf("battery: cannot set power limit: WMax unknown")
	}
	requestedW := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
	if requestedW < 0 {
		requestedW = 0
	}
	if requestedW > b.wmax {
		requestedW = b.wmax
	}
	pct := (requestedW / b.wmax) * 100.0

	regs, err := b.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("battery: read M704 for WMaxLimPct: %w", err)
	}
	s, err := sunspec.ParseDERCtlAC(regs)
	if err != nil {
		return err
	}
	s.WMaxLimPctEna = true
	s.WMaxLimPct = pct
	if err := sunspec.EncodeDERCtlAC(regs, s); err != nil {
		return err
	}
	return b.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// SetDERCtlAC writes a complete M704 settings struct to the device.
func (b *Battery) SetDERCtlAC(s sunspec.DERCtlACSettings) error {
	if !b.has704 {
		return fmt.Errorf("battery: device has no M704 (DERCtlAC)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("battery: read M704: %w", err)
	}
	if err := sunspec.EncodeDERCtlAC(regs, s); err != nil {
		return err
	}
	return b.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// ReadDERCtlAC reads the current M704 settings from the device.
func (b *Battery) ReadDERCtlAC() (sunspec.DERCtlACSettings, error) {
	if !b.has704 {
		return sunspec.DERCtlACSettings{}, fmt.Errorf("battery: device has no M704")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return sunspec.DERCtlACSettings{}, fmt.Errorf("battery: read M704: %w", err)
	}
	return sunspec.ParseDERCtlAC(regs)
}

// ReadDERCapacity reads the nameplate and configuration data from M702.
func (b *Battery) ReadDERCapacity() (sunspec.DERCapacity, error) {
	if !b.has702 {
		return sunspec.DERCapacity{}, fmt.Errorf("battery: device has no M702 (DERCapacity)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERCapacity)
	if err != nil {
		return sunspec.DERCapacity{}, fmt.Errorf("battery: read M702: %w", err)
	}
	return sunspec.ParseDERCapacity(regs)
}

// ReadStorageCapacity reads battery storage state from M713 (DERStorageCapacity).
func (b *Battery) ReadStorageCapacity() (sunspec.DERStorageCapacity, error) {
	if !b.has713 {
		return sunspec.DERStorageCapacity{}, fmt.Errorf("battery: device has no M713 (DERStorageCapacity)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERStorageCap)
	if err != nil {
		return sunspec.DERStorageCapacity{}, fmt.Errorf("battery: read M713: %w", err)
	}
	return sunspec.ParseDERStorageCapacity(regs)
}

// ── Volt-Var (M705) ──────────────────────────────────────────────────────────

// ReadVoltVar reads the active Q(V) curve from M705.
func (b *Battery) ReadVoltVar() (sunspec.VoltVarCurve, error) {
	if !b.has705 {
		return sunspec.VoltVarCurve{}, fmt.Errorf("battery: device has no M705 (DERVoltVar)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERVoltVar)
	if err != nil {
		return sunspec.VoltVarCurve{}, fmt.Errorf("battery: read M705: %w", err)
	}
	return sunspec.ParseVoltVarCurve(regs, 0)
}

// WriteVoltVar writes a Q(V) curve to M705 and requests curve adoption.
func (b *Battery) WriteVoltVar(c sunspec.VoltVarCurve) error {
	if !b.has705 {
		return fmt.Errorf("battery: device has no M705 (DERVoltVar)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERVoltVar)
	if err != nil {
		return fmt.Errorf("battery: read M705: %w", err)
	}
	start, end, err := sunspec.EncodeVoltVarCurve(regs, c)
	if err != nil {
		return err
	}
	if err := b.reader.WriteModel(sunspec.ModelDERVoltVar, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("battery: write M705 curve: %w", err)
	}
	return b.reader.WriteModel(sunspec.ModelDERVoltVar, sunspec.M705_AdptCrvReq, []uint16{1})
}

// ── Volt-Watt (M706) ─────────────────────────────────────────────────────────

// ReadVoltWatt reads the active P(V) curve from M706.
func (b *Battery) ReadVoltWatt() (sunspec.VoltWattCurve, error) {
	if !b.has706 {
		return sunspec.VoltWattCurve{}, fmt.Errorf("battery: device has no M706 (DERVoltWatt)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERVoltWatt)
	if err != nil {
		return sunspec.VoltWattCurve{}, fmt.Errorf("battery: read M706: %w", err)
	}
	return sunspec.ParseVoltWattCurve(regs, 0)
}

// WriteVoltWatt writes a P(V) curve to M706.
func (b *Battery) WriteVoltWatt(c sunspec.VoltWattCurve) error {
	if !b.has706 {
		return fmt.Errorf("battery: device has no M706 (DERVoltWatt)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERVoltWatt)
	if err != nil {
		return fmt.Errorf("battery: read M706: %w", err)
	}
	start, end, err := sunspec.EncodeVoltWattCurve(regs, c)
	if err != nil {
		return err
	}
	if err := b.reader.WriteModel(sunspec.ModelDERVoltWatt, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("battery: write M706 curve: %w", err)
	}
	return b.reader.WriteModel(sunspec.ModelDERVoltWatt, sunspec.M706_AdptCrvReq, []uint16{1})
}

// ── Voltage trip (M707/M708) ─────────────────────────────────────────────────

// ReadVoltageTripLV reads the active low-voltage must-trip curve from M707.
func (b *Battery) ReadVoltageTripLV() (sunspec.VoltageTripCurve, error) {
	if !b.has707 {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("battery: device has no M707 (DERTripLV)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERTripLV)
	if err != nil {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("battery: read M707: %w", err)
	}
	return sunspec.ParseVoltageTripCurve(regs, 0, false)
}

// WriteVoltageTripLV writes a low-voltage trip curve to M707.
func (b *Battery) WriteVoltageTripLV(c sunspec.VoltageTripCurve) error {
	if !b.has707 {
		return fmt.Errorf("battery: device has no M707 (DERTripLV)")
	}
	return b.writeTripCurve707(sunspec.ModelDERTripLV, sunspec.M707_AdptCrvReq, c)
}

// ReadVoltageTripHV reads the active high-voltage must-trip curve from M708.
func (b *Battery) ReadVoltageTripHV() (sunspec.VoltageTripCurve, error) {
	if !b.has708 {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("battery: device has no M708 (DERTripHV)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERTripHV)
	if err != nil {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("battery: read M708: %w", err)
	}
	return sunspec.ParseVoltageTripCurve(regs, 0, false)
}

// WriteVoltageTripHV writes a high-voltage trip curve to M708.
func (b *Battery) WriteVoltageTripHV(c sunspec.VoltageTripCurve) error {
	if !b.has708 {
		return fmt.Errorf("battery: device has no M708 (DERTripHV)")
	}
	return b.writeTripCurve707(sunspec.ModelDERTripHV, sunspec.M707_AdptCrvReq, c)
}

func (b *Battery) writeTripCurve707(modelID, adptReqOffset uint16, c sunspec.VoltageTripCurve) error {
	regs, err := b.reader.ReadModel(modelID)
	if err != nil {
		return fmt.Errorf("battery: read model %d: %w", modelID, err)
	}
	start, end, err := sunspec.EncodeVoltageTripCurve(regs, c, false)
	if err != nil {
		return err
	}
	if err := b.reader.WriteModel(modelID, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("battery: write model %d: %w", modelID, err)
	}
	return b.reader.WriteModel(modelID, adptReqOffset, []uint16{1})
}

// ── Frequency trip (M709/M710) ────────────────────────────────────────────────

// ReadFreqTripLF reads the active low-frequency must-trip curve from M709.
func (b *Battery) ReadFreqTripLF() (sunspec.FreqTripCurve, error) {
	if !b.has709 {
		return sunspec.FreqTripCurve{}, fmt.Errorf("battery: device has no M709 (DERTripLF)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERTripLF)
	if err != nil {
		return sunspec.FreqTripCurve{}, fmt.Errorf("battery: read M709: %w", err)
	}
	return sunspec.ParseFreqTripCurve(regs, 0, false)
}

// WriteFreqTripLF writes a low-frequency trip curve to M709.
func (b *Battery) WriteFreqTripLF(c sunspec.FreqTripCurve) error {
	if !b.has709 {
		return fmt.Errorf("battery: device has no M709 (DERTripLF)")
	}
	return b.writeTripCurve709(sunspec.ModelDERTripLF, c)
}

// ReadFreqTripHF reads the active high-frequency must-trip curve from M710.
func (b *Battery) ReadFreqTripHF() (sunspec.FreqTripCurve, error) {
	if !b.has710 {
		return sunspec.FreqTripCurve{}, fmt.Errorf("battery: device has no M710 (DERTripHF)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERTripHF)
	if err != nil {
		return sunspec.FreqTripCurve{}, fmt.Errorf("battery: read M710: %w", err)
	}
	return sunspec.ParseFreqTripCurve(regs, 0, false)
}

// WriteFreqTripHF writes a high-frequency trip curve to M710.
func (b *Battery) WriteFreqTripHF(c sunspec.FreqTripCurve) error {
	if !b.has710 {
		return fmt.Errorf("battery: device has no M710 (DERTripHF)")
	}
	return b.writeTripCurve709(sunspec.ModelDERTripHF, c)
}

func (b *Battery) writeTripCurve709(modelID uint16, c sunspec.FreqTripCurve) error {
	regs, err := b.reader.ReadModel(modelID)
	if err != nil {
		return fmt.Errorf("battery: read model %d: %w", modelID, err)
	}
	start, end, err := sunspec.EncodeFreqTripCurve(regs, c, false)
	if err != nil {
		return err
	}
	if err := b.reader.WriteModel(modelID, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("battery: write model %d: %w", modelID, err)
	}
	return b.reader.WriteModel(modelID, sunspec.M709_AdptCrvReq, []uint16{1})
}

// ── Frequency droop (M711) ────────────────────────────────────────────────────

// ReadFreqDroop reads the active frequency droop control set from M711.
func (b *Battery) ReadFreqDroop() (sunspec.FreqDroopCtl, error) {
	if !b.has711 {
		return sunspec.FreqDroopCtl{}, fmt.Errorf("battery: device has no M711 (DERFreqDroop)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERFreqDroop)
	if err != nil {
		return sunspec.FreqDroopCtl{}, fmt.Errorf("battery: read M711: %w", err)
	}
	return sunspec.ParseFreqDroop(regs, 0)
}

// WriteFreqDroop writes frequency droop parameters to M711.
func (b *Battery) WriteFreqDroop(c sunspec.FreqDroopCtl) error {
	if !b.has711 {
		return fmt.Errorf("battery: device has no M711 (DERFreqDroop)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERFreqDroop)
	if err != nil {
		return fmt.Errorf("battery: read M711: %w", err)
	}
	start, end, err := sunspec.EncodeFreqDroop(regs, c)
	if err != nil {
		return err
	}
	if err := b.reader.WriteModel(sunspec.ModelDERFreqDroop, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("battery: write M711: %w", err)
	}
	return b.reader.WriteModel(sunspec.ModelDERFreqDroop, sunspec.M711_AdptCtlReq, []uint16{1})
}

// ── Watt-Var (M712) ───────────────────────────────────────────────────────────

// ReadWattVar reads the active Q(P) curve from M712.
func (b *Battery) ReadWattVar() (sunspec.WattVarCurve, error) {
	if !b.has712 {
		return sunspec.WattVarCurve{}, fmt.Errorf("battery: device has no M712 (DERWattVar)")
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERWattVar)
	if err != nil {
		return sunspec.WattVarCurve{}, fmt.Errorf("battery: read M712: %w", err)
	}
	return sunspec.ParseWattVarCurve(regs, 0)
}

// WriteWattVar writes a Q(P) curve to M712.
// The curve must have exactly 6 points per IEEE 1547-2018 §2.7.
func (b *Battery) WriteWattVar(c sunspec.WattVarCurve) error {
	if !b.has712 {
		return fmt.Errorf("battery: device has no M712 (DERWattVar)")
	}
	if len(c.Pts) != 6 {
		return fmt.Errorf("battery: WattVar curve must have 6 points per IEEE 1547-2018 (got %d)", len(c.Pts))
	}
	regs, err := b.reader.ReadModel(sunspec.ModelDERWattVar)
	if err != nil {
		return fmt.Errorf("battery: read M712: %w", err)
	}
	start, end, err := sunspec.EncodeWattVarCurve(regs, c)
	if err != nil {
		return err
	}
	if err := b.reader.WriteModel(sunspec.ModelDERWattVar, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("battery: write M712: %w", err)
	}
	return b.reader.WriteModel(sunspec.ModelDERWattVar, sunspec.M712_AdptCrvReq, []uint16{1})
}

// ── Internal control helpers (legacy M123 path) ───────────────────────────────

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

// ── Model parse helpers ───────────────────────────────────────────────────────

// parseM701 extracts Measurements from M701 (DERMeasureAC) registers.
func parseM701(regs []uint16) device.Measurements {
	get := func(offset int) uint16 {
		if offset < len(regs) {
			return regs[offset]
		}
		return 0
	}
	sf := func(offset int) int16 { return int16(get(offset)) }

	m := device.Measurements{TmpCab: math.NaN()}
	if len(regs) > sunspec.M701_W_SF {
		m.W = sunspec.ApplyScaleSigned(get(sunspec.M701_W), sf(sunspec.M701_W_SF))
	}
	if len(regs) > sunspec.M701_V_SF {
		v := get(sunspec.M701_VL1)
		if v == 0x8000 {
			v = get(sunspec.M701_LNV)
		}
		m.V = sunspec.ApplyScaleUint(v, sf(sunspec.M701_V_SF))
	}
	if len(regs) > sunspec.M701_Hz_SF {
		m.Hz = sunspec.ApplyScaleUint(get(sunspec.M701_Hz), sf(sunspec.M701_Hz_SF))
	}
	if len(regs) > sunspec.M701_VA_SF {
		m.VA = sunspec.ApplyScaleSigned(get(sunspec.M701_VA), sf(sunspec.M701_VA_SF))
	}
	if len(regs) > sunspec.M701_Var_SF {
		m.Var = sunspec.ApplyScaleSigned(get(sunspec.M701_Var), sf(sunspec.M701_Var_SF))
	}
	if len(regs) > sunspec.M701_PF_SF {
		m.PF = sunspec.ApplyScaleSigned(get(sunspec.M701_PF), sf(sunspec.M701_PF_SF)) / 100.0
	}
	return m
}

// parseACModel extracts device.Measurements from Model 10x registers.
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

func readWMaxFrom702(r *sunspec.Reader) (float64, error) {
	regs, err := r.ReadModel(sunspec.ModelDERCapacity)
	if err != nil {
		return 0, err
	}
	if len(regs) <= sunspec.M702_W_SF {
		return 0, fmt.Errorf("sunspec: Model 702 too short for W_SF")
	}
	sf := int16(regs[sunspec.M702_W_SF])
	wmax := sunspec.ApplyScaleUint(regs[sunspec.M702_WMaxRtg], sf)
	if wmax <= 0 || math.IsNaN(wmax) {
		return 0, fmt.Errorf("sunspec: Model 702 WMaxRtg is %g (invalid)", wmax)
	}
	return wmax, nil
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
