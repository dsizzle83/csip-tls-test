// Package inverter implements device.Device for SunSpec-compliant grid-tied
// inverters covering both legacy SunSpec models (101/102/103, 121, 123) and
// the IEEE 1547-2018 SunSpec Modbus profile (701-712).
//
// Model preference (newest wins, older used as fallback):
//
//	Measurements : M701 (DERMeasureAC)       → M103/102/101
//	Nameplate    : M702 (DERCapacity).WMaxRtg → M121 (BasicSettings).WMax
//	Controls     : M704 (DERCtlAC)           → M123 (ImmediateCtrl)
//
// Control mapping from CSIP DERControlBase:
//
//	OpModConnect          → M123 Conn (M704 has no connect register)
//	OpModEnergize         → M703 ES (enter-service / cease-to-energize)
//	OpModExpLimW/MaxLimW  → M704.WMaxLimPct  → M123.WMaxLimPct
//	OpModFixedPFAbsorbW   → M704.PFWInjEna + PFWInj_PF + PFWInj_Ext=0
//	OpModFixedPFInjectW   → M704.PFWInjEna + PFWInj_PF + PFWInj_Ext=1
//	OpModFixedVar         → M704.VarSetEna  + VarSetPct
//
// Advanced IEEE 1547-2018 curves (M705-M712) are available via dedicated
// methods (WriteVoltVar, WriteVoltWatt, etc.) for initial commissioning and
// configuration. These are not invoked from ApplyControl automatically.
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

	inv := &Inverter{
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
	}

	// Measurement model: prefer M701, fall back to legacy M103/102/101.
	if inv.has701 {
		inv.measModel = sunspec.ModelDERMeasureAC
	} else {
		for _, candidate := range []uint16{sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh} {
			if r.HasModel(candidate) {
				inv.measModel = candidate
				break
			}
		}
		if inv.measModel == 0 {
			return nil, fmt.Errorf("inverter: device has no AC measurement model (701, 103, 102, or 101)")
		}
	}

	// Nameplate WMax: prefer M702, fall back to M121.
	if inv.has702 {
		if w, err := readWMaxFrom702(r); err == nil {
			inv.wmax = w
		}
	} else if r.HasModel(sunspec.ModelBasicSettings) {
		if w, err := readWMax(r); err == nil {
			inv.wmax = w
		}
	}

	return inv, nil
}

// Close releases the Modbus transport.
func (inv *Inverter) Close() error {
	return inv.transport.Close()
}

// ReadMeasurements reads AC and DC measurements from the inverter.
// Uses M701 (DERMeasureAC) when available; falls back to M103/102/101.
func (inv *Inverter) ReadMeasurements() (device.Measurements, error) {
	regs, err := inv.reader.ReadModel(inv.measModel)
	if err != nil {
		return device.Measurements{}, fmt.Errorf("inverter: read model %d: %w", inv.measModel, err)
	}
	if inv.measModel == sunspec.ModelDERMeasureAC {
		return parseM701(regs), nil
	}
	return parseInverterModel(regs), nil
}

// Status reads the operating state from the inverter.
// Uses M701.St + M701.ConnSt when available; falls back to M103.St.
func (inv *Inverter) Status() (device.DeviceStatus, error) {
	regs, err := inv.reader.ReadModel(inv.measModel)
	if err != nil {
		return device.DeviceStatus{}, fmt.Errorf("inverter: read status: %w", err)
	}
	if inv.measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_ConnSt {
			return device.DeviceStatus{}, fmt.Errorf("inverter: M701 too short for St/ConnSt")
		}
		st := sunspec.M701St(regs[sunspec.M701_St])
		return device.DeviceStatus{
			Connected: regs[sunspec.M701_ConnSt] == 1,
			Energized: st == sunspec.M701StOn || st == sunspec.M701StThrottled || st == sunspec.M701StStarting,
		}, nil
	}
	if len(regs) <= sunspec.M103_St {
		return device.DeviceStatus{}, fmt.Errorf("inverter: model %d too short for St", inv.measModel)
	}
	st := regs[sunspec.M103_St]
	return device.DeviceStatus{
		Connected: st == 4 || st == 5,
		Energized: st >= 3 && st <= 6,
	}, nil
}

// ApplyControl writes control values to the inverter.
// Prefers M704 (DERCtlAC) for power-factor and reactive-power controls when
// available; falls back to M123 (ImmediateCtrl) for the legacy models.
// Connect/disconnect always uses M123 (M704 has no connect register).
// Nil fields in ctrl are left unchanged on the device.
func (inv *Inverter) ApplyControl(ctrl model.DERControlBase) error {
	// Cease-to-energize / permit-service → M703 Enter Service.
	if ctrl.OpModEnergize != nil && inv.has703 {
		if err := inv.setEnterService(*ctrl.OpModEnergize); err != nil {
			return err
		}
	}

	// Connect/disconnect → M123 Conn (M704 has no connect register).
	if ctrl.OpModConnect != nil {
		if !inv.reader.HasModel(sunspec.ModelImmediateCtrl) {
			return fmt.Errorf("inverter: no M123 for connect control")
		}
		if err := inv.setConnect(*ctrl.OpModConnect); err != nil {
			return err
		}
	}

	// Power factor → M704 preferred, M123 fallback.
	if ctrl.OpModFixedPFInjectW != nil || ctrl.OpModFixedPFAbsorbW != nil {
		if inv.has704 {
			if err := inv.setPowerFactor704(ctrl); err != nil {
				return err
			}
		}
		// Legacy M123 OutPFSet is not updated here — it uses a different
		// representation. M704 is the canonical path for IEEE 1547-2018.
	}

	// Constant reactive power → M704 VarSetPct.
	if ctrl.OpModFixedVar != nil && inv.has704 {
		if err := inv.setConstantVar704(ctrl.OpModFixedVar); err != nil {
			return err
		}
	}

	// Active power limit → M704 preferred, M123 fallback.
	lim := ctrl.OpModExpLimW
	if lim == nil {
		lim = ctrl.OpModMaxLimW
	}
	if lim != nil {
		if inv.has704 {
			if err := inv.setWMaxLimPct704(lim); err != nil {
				return err
			}
		} else {
			if err := inv.setExportLimit(lim); err != nil {
				return err
			}
		}
	}

	return nil
}

// ── IEEE 1547-2018 enter service ─────────────────────────────────────────────

// SetEnterService enables or disables permit-service on the inverter via M703.
// Setting enabled=false issues a cease-to-energize command.
func (inv *Inverter) SetEnterService(s sunspec.DEREnterServiceSettings) error {
	if !inv.has703 {
		return fmt.Errorf("inverter: device has no M703 (DEREnterService)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return fmt.Errorf("inverter: read M703: %w", err)
	}
	if err := sunspec.EncodeDEREnterService(regs, s); err != nil {
		return err
	}
	return inv.reader.WriteModel(sunspec.ModelDEREnterService, 0, regs)
}

// setEnterService is the internal path called from ApplyControl.
func (inv *Inverter) setEnterService(energize bool) error {
	regs, err := inv.reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return fmt.Errorf("inverter: read M703: %w", err)
	}
	if energize {
		regs[sunspec.M703_ES] = 1
	} else {
		regs[sunspec.M703_ES] = 0
	}
	return inv.reader.WriteModel(sunspec.ModelDEREnterService, 0, regs[:1])
}

// ReadEnterService reads the current enter-service settings from M703.
func (inv *Inverter) ReadEnterService() (sunspec.DEREnterServiceSettings, error) {
	if !inv.has703 {
		return sunspec.DEREnterServiceSettings{}, fmt.Errorf("inverter: device has no M703")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return sunspec.DEREnterServiceSettings{}, fmt.Errorf("inverter: read M703: %w", err)
	}
	return sunspec.ParseDEREnterService(regs)
}

// ── IEEE 1547-2018 DERCtlAC (M704) helpers ───────────────────────────────────

// setPowerFactor704 maps CSIP OpModFixedPF* to M704 PFWInj fields.
func (inv *Inverter) setPowerFactor704(ctrl model.DERControlBase) error {
	regs, err := inv.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("inverter: read M704: %w", err)
	}
	s, err := sunspec.ParseDERCtlAC(regs)
	if err != nil {
		return err
	}
	if ctrl.OpModFixedPFInjectW != nil {
		// OpModFixedPFInjectW: SignedPerCent × 100 (e.g. 9400 = 0.94 PF)
		s.PFWInjEna = true
		s.PFWInj_PF = math.Abs(float64(ctrl.OpModFixedPFInjectW.Value)) / 10000.0
		s.PFWInj_Ext = true // injecting (over-excited)
	} else if ctrl.OpModFixedPFAbsorbW != nil {
		s.PFWInjEna = true
		s.PFWInj_PF = math.Abs(float64(ctrl.OpModFixedPFAbsorbW.Value)) / 10000.0
		s.PFWInj_Ext = false // absorbing (under-excited)
	}
	if err := sunspec.EncodeDERCtlAC(regs, s); err != nil {
		return err
	}
	return inv.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// setConstantVar704 maps CSIP OpModFixedVar to M704 VarSetPct.
func (inv *Inverter) setConstantVar704(fv *model.FixedVar) error {
	if fv == nil {
		return nil
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("inverter: read M704 for var: %w", err)
	}
	s, err := sunspec.ParseDERCtlAC(regs)
	if err != nil {
		return err
	}
	s.VarSetEna = true
	s.VarSetPri = 1 // REACTIVE priority per IEEE 1547-2018
	// FixedVar.Value is SignedPerCent (hundredths of percent, e.g. 5000 = 50%).
	s.VarSetPct = float64(fv.Value.Value) / 100.0
	if err := sunspec.EncodeDERCtlAC(regs, s); err != nil {
		return err
	}
	return inv.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// setWMaxLimPct704 maps an active power limit to M704.WMaxLimPct.
func (inv *Inverter) setWMaxLimPct704(ap *model.ActivePower) error {
	if math.IsNaN(inv.wmax) || inv.wmax <= 0 {
		return fmt.Errorf("inverter: cannot set power limit: WMax unknown")
	}
	requestedW := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
	if requestedW < 0 {
		requestedW = 0
	}
	if requestedW > inv.wmax {
		requestedW = inv.wmax
	}
	pct := (requestedW / inv.wmax) * 100.0

	regs, err := inv.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("inverter: read M704 for WMaxLimPct: %w", err)
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
	return inv.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// SetDERCtlAC writes a complete M704 settings struct to the device.
// Use this for commissioning (setting all fields at once).
func (inv *Inverter) SetDERCtlAC(s sunspec.DERCtlACSettings) error {
	if !inv.has704 {
		return fmt.Errorf("inverter: device has no M704 (DERCtlAC)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("inverter: read M704: %w", err)
	}
	if err := sunspec.EncodeDERCtlAC(regs, s); err != nil {
		return err
	}
	return inv.reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// ReadDERCtlAC reads the current M704 settings from the device.
func (inv *Inverter) ReadDERCtlAC() (sunspec.DERCtlACSettings, error) {
	if !inv.has704 {
		return sunspec.DERCtlACSettings{}, fmt.Errorf("inverter: device has no M704")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return sunspec.DERCtlACSettings{}, fmt.Errorf("inverter: read M704: %w", err)
	}
	return sunspec.ParseDERCtlAC(regs)
}

// ReadDERCapacity reads the nameplate and configuration data from M702.
func (inv *Inverter) ReadDERCapacity() (sunspec.DERCapacity, error) {
	if !inv.has702 {
		return sunspec.DERCapacity{}, fmt.Errorf("inverter: device has no M702 (DERCapacity)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERCapacity)
	if err != nil {
		return sunspec.DERCapacity{}, fmt.Errorf("inverter: read M702: %w", err)
	}
	return sunspec.ParseDERCapacity(regs)
}

// ── Volt-Var (M705) ──────────────────────────────────────────────────────────

// ReadVoltVar reads the active (read-only, index 0) Q(V) curve from M705.
func (inv *Inverter) ReadVoltVar() (sunspec.VoltVarCurve, error) {
	if !inv.has705 {
		return sunspec.VoltVarCurve{}, fmt.Errorf("inverter: device has no M705 (DERVoltVar)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERVoltVar)
	if err != nil {
		return sunspec.VoltVarCurve{}, fmt.Errorf("inverter: read M705: %w", err)
	}
	return sunspec.ParseVoltVarCurve(regs, 0)
}

// WriteVoltVar writes a Q(V) curve to the writable curve (index 1) of M705
// and requests curve adoption by writing AdptCrvReq=1.
func (inv *Inverter) WriteVoltVar(c sunspec.VoltVarCurve) error {
	if !inv.has705 {
		return fmt.Errorf("inverter: device has no M705 (DERVoltVar)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERVoltVar)
	if err != nil {
		return fmt.Errorf("inverter: read M705: %w", err)
	}
	start, end, err := sunspec.EncodeVoltVarCurve(regs, c)
	if err != nil {
		return err
	}
	if err := inv.reader.WriteModel(sunspec.ModelDERVoltVar, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("inverter: write M705 curve: %w", err)
	}
	// Request curve adoption.
	return inv.reader.WriteModel(sunspec.ModelDERVoltVar, sunspec.M705_AdptCrvReq, []uint16{1})
}

// ── Volt-Watt (M706) ─────────────────────────────────────────────────────────

// ReadVoltWatt reads the active P(V) curve from M706.
func (inv *Inverter) ReadVoltWatt() (sunspec.VoltWattCurve, error) {
	if !inv.has706 {
		return sunspec.VoltWattCurve{}, fmt.Errorf("inverter: device has no M706 (DERVoltWatt)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERVoltWatt)
	if err != nil {
		return sunspec.VoltWattCurve{}, fmt.Errorf("inverter: read M706: %w", err)
	}
	return sunspec.ParseVoltWattCurve(regs, 0)
}

// WriteVoltWatt writes a P(V) curve to M706.
func (inv *Inverter) WriteVoltWatt(c sunspec.VoltWattCurve) error {
	if !inv.has706 {
		return fmt.Errorf("inverter: device has no M706 (DERVoltWatt)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERVoltWatt)
	if err != nil {
		return fmt.Errorf("inverter: read M706: %w", err)
	}
	start, end, err := sunspec.EncodeVoltWattCurve(regs, c)
	if err != nil {
		return err
	}
	if err := inv.reader.WriteModel(sunspec.ModelDERVoltWatt, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("inverter: write M706 curve: %w", err)
	}
	return inv.reader.WriteModel(sunspec.ModelDERVoltWatt, sunspec.M706_AdptCrvReq, []uint16{1})
}

// ── Voltage trip (M707/M708) ─────────────────────────────────────────────────

// ReadVoltageTripLV reads the active low-voltage must-trip curve from M707.
func (inv *Inverter) ReadVoltageTripLV() (sunspec.VoltageTripCurve, error) {
	if !inv.has707 {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("inverter: device has no M707 (DERTripLV)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERTripLV)
	if err != nil {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("inverter: read M707: %w", err)
	}
	return sunspec.ParseVoltageTripCurve(regs, 0, false)
}

// WriteVoltageTripLV writes a low-voltage trip curve to M707.
func (inv *Inverter) WriteVoltageTripLV(c sunspec.VoltageTripCurve) error {
	if !inv.has707 {
		return fmt.Errorf("inverter: device has no M707 (DERTripLV)")
	}
	return inv.writeTripCurve707(sunspec.ModelDERTripLV, sunspec.M707_AdptCrvReq, c)
}

// ReadVoltageTripHV reads the active high-voltage must-trip curve from M708.
func (inv *Inverter) ReadVoltageTripHV() (sunspec.VoltageTripCurve, error) {
	if !inv.has708 {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("inverter: device has no M708 (DERTripHV)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERTripHV)
	if err != nil {
		return sunspec.VoltageTripCurve{}, fmt.Errorf("inverter: read M708: %w", err)
	}
	return sunspec.ParseVoltageTripCurve(regs, 0, false)
}

// WriteVoltageTripHV writes a high-voltage trip curve to M708.
func (inv *Inverter) WriteVoltageTripHV(c sunspec.VoltageTripCurve) error {
	if !inv.has708 {
		return fmt.Errorf("inverter: device has no M708 (DERTripHV)")
	}
	return inv.writeTripCurve707(sunspec.ModelDERTripHV, sunspec.M707_AdptCrvReq, c)
}

func (inv *Inverter) writeTripCurve707(modelID, adptReqOffset uint16, c sunspec.VoltageTripCurve) error {
	regs, err := inv.reader.ReadModel(modelID)
	if err != nil {
		return fmt.Errorf("inverter: read model %d: %w", modelID, err)
	}
	start, end, err := sunspec.EncodeVoltageTripCurve(regs, c, false)
	if err != nil {
		return err
	}
	if err := inv.reader.WriteModel(modelID, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("inverter: write model %d: %w", modelID, err)
	}
	return inv.reader.WriteModel(modelID, adptReqOffset, []uint16{1})
}

// ── Frequency trip (M709/M710) ────────────────────────────────────────────────

// ReadFreqTripLF reads the active low-frequency must-trip curve from M709.
func (inv *Inverter) ReadFreqTripLF() (sunspec.FreqTripCurve, error) {
	if !inv.has709 {
		return sunspec.FreqTripCurve{}, fmt.Errorf("inverter: device has no M709 (DERTripLF)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERTripLF)
	if err != nil {
		return sunspec.FreqTripCurve{}, fmt.Errorf("inverter: read M709: %w", err)
	}
	return sunspec.ParseFreqTripCurve(regs, 0, false)
}

// WriteFreqTripLF writes a low-frequency trip curve to M709.
func (inv *Inverter) WriteFreqTripLF(c sunspec.FreqTripCurve) error {
	if !inv.has709 {
		return fmt.Errorf("inverter: device has no M709 (DERTripLF)")
	}
	return inv.writeTripCurve709(sunspec.ModelDERTripLF, c)
}

// ReadFreqTripHF reads the active high-frequency must-trip curve from M710.
func (inv *Inverter) ReadFreqTripHF() (sunspec.FreqTripCurve, error) {
	if !inv.has710 {
		return sunspec.FreqTripCurve{}, fmt.Errorf("inverter: device has no M710 (DERTripHF)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERTripHF)
	if err != nil {
		return sunspec.FreqTripCurve{}, fmt.Errorf("inverter: read M710: %w", err)
	}
	return sunspec.ParseFreqTripCurve(regs, 0, false)
}

// WriteFreqTripHF writes a high-frequency trip curve to M710.
func (inv *Inverter) WriteFreqTripHF(c sunspec.FreqTripCurve) error {
	if !inv.has710 {
		return fmt.Errorf("inverter: device has no M710 (DERTripHF)")
	}
	return inv.writeTripCurve709(sunspec.ModelDERTripHF, c)
}

func (inv *Inverter) writeTripCurve709(modelID uint16, c sunspec.FreqTripCurve) error {
	regs, err := inv.reader.ReadModel(modelID)
	if err != nil {
		return fmt.Errorf("inverter: read model %d: %w", modelID, err)
	}
	start, end, err := sunspec.EncodeFreqTripCurve(regs, c, false)
	if err != nil {
		return err
	}
	if err := inv.reader.WriteModel(modelID, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("inverter: write model %d: %w", modelID, err)
	}
	return inv.reader.WriteModel(modelID, sunspec.M709_AdptCrvReq, []uint16{1})
}

// ── Frequency droop (M711) ────────────────────────────────────────────────────

// ReadFreqDroop reads the active frequency droop control set from M711.
func (inv *Inverter) ReadFreqDroop() (sunspec.FreqDroopCtl, error) {
	if !inv.has711 {
		return sunspec.FreqDroopCtl{}, fmt.Errorf("inverter: device has no M711 (DERFreqDroop)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERFreqDroop)
	if err != nil {
		return sunspec.FreqDroopCtl{}, fmt.Errorf("inverter: read M711: %w", err)
	}
	return sunspec.ParseFreqDroop(regs, 0) // read-only set 0
}

// WriteFreqDroop writes frequency droop parameters to M711.
func (inv *Inverter) WriteFreqDroop(c sunspec.FreqDroopCtl) error {
	if !inv.has711 {
		return fmt.Errorf("inverter: device has no M711 (DERFreqDroop)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERFreqDroop)
	if err != nil {
		return fmt.Errorf("inverter: read M711: %w", err)
	}
	start, end, err := sunspec.EncodeFreqDroop(regs, c)
	if err != nil {
		return err
	}
	if err := inv.reader.WriteModel(sunspec.ModelDERFreqDroop, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("inverter: write M711: %w", err)
	}
	return inv.reader.WriteModel(sunspec.ModelDERFreqDroop, sunspec.M711_AdptCtlReq, []uint16{1})
}

// ── Watt-Var (M712) ───────────────────────────────────────────────────────────

// ReadWattVar reads the active Q(P) curve from M712.
func (inv *Inverter) ReadWattVar() (sunspec.WattVarCurve, error) {
	if !inv.has712 {
		return sunspec.WattVarCurve{}, fmt.Errorf("inverter: device has no M712 (DERWattVar)")
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERWattVar)
	if err != nil {
		return sunspec.WattVarCurve{}, fmt.Errorf("inverter: read M712: %w", err)
	}
	return sunspec.ParseWattVarCurve(regs, 0)
}

// WriteWattVar writes a Q(P) curve to M712.
// The curve must have exactly 6 points per IEEE 1547-2018 §2.7.
// Points 0-2 cover load operation (W<0); set to zero if unused.
func (inv *Inverter) WriteWattVar(c sunspec.WattVarCurve) error {
	if !inv.has712 {
		return fmt.Errorf("inverter: device has no M712 (DERWattVar)")
	}
	if len(c.Pts) != 6 {
		return fmt.Errorf("inverter: WattVar curve must have 6 points per IEEE 1547-2018 (got %d)", len(c.Pts))
	}
	regs, err := inv.reader.ReadModel(sunspec.ModelDERWattVar)
	if err != nil {
		return fmt.Errorf("inverter: read M712: %w", err)
	}
	start, end, err := sunspec.EncodeWattVarCurve(regs, c)
	if err != nil {
		return err
	}
	if err := inv.reader.WriteModel(sunspec.ModelDERWattVar, uint16(start), regs[start:end]); err != nil {
		return fmt.Errorf("inverter: write M712: %w", err)
	}
	return inv.reader.WriteModel(sunspec.ModelDERWattVar, sunspec.M712_AdptCrvReq, []uint16{1})
}

// ── Internal control helpers (legacy M123 path) ───────────────────────────────

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

// readWMaxFrom702 reads the nameplate WMax (in watts) from Model 702 (DERCapacity).
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

// parseM701 extracts Measurements from a slice of raw Model 701 (DERMeasureAC) registers.
func parseM701(regs []uint16) device.Measurements {
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

	if len(regs) > sunspec.M701_W_SF {
		m.W = sunspec.ApplyScaleSigned(get(sunspec.M701_W), sf(sunspec.M701_W_SF))
	}
	if len(regs) > sunspec.M701_V_SF {
		// Prefer L1-N voltage; fall back to L-N average.
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
		// PF is stored ×100 (e.g. 9400 = 0.94); divide by 10000 for -1..+1.
		m.PF = sunspec.ApplyScaleSigned(get(sunspec.M701_PF), sf(sunspec.M701_PF_SF)) / 100.0
	}
	// M701 has no DC measurements.
	return m
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
