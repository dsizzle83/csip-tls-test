// Package derbase provides shared SunSpec DER device logic for inverter and
// battery packages. It handles IEEE 1547-2018 models (M701-M712), legacy
// models (M103/M121/M123), measurement parsing, and control application.
//
// Embed Base in a concrete device type and call Init after SunSpec scan.
package derbase

import (
	"fmt"
	"math"

	"csip-tls-test/internal/southbound/device"
	model "lexa-proto/csipmodel"
	"lexa-proto/sunspec"
)

// M701St enumerates the operating state reported by SunSpec Model 701
// (DERMeasureAC.St). The shared codec's sunspec.Parse701 returns St as a raw
// uint16 (sunspec.ACMeasurement.St) rather than a symbolic type; these mirror
// the SunSpec Alliance Model 701 spec values the old bench fork named as
// M701St/M701StOn/etc. This is a constants shim living on the bench side
// (never re-added to lexa-proto) per TASK-021 step 2.
const (
	M701StOff         = 0
	M701StSleeping    = 1
	M701StStarting    = 2
	M701StOn          = 3
	M701StThrottled   = 4
	M701StShuttingDwn = 5
	M701StFault       = 6
	M701StStandby     = 7
)

// Base holds shared SunSpec DER state and methods. Embed in concrete types.
type Base struct {
	Reader    *sunspec.Reader
	Wmax      float64 // nameplate WMax in watts; NaN if unavailable
	MeasModel uint16  // model ID for measurements: 701, 103, 102, or 101
	Has701    bool
	Has702    bool
	Has703    bool
	Has704    bool
	Has705    bool
	Has706    bool
	Has707    bool
	Has708    bool
	Has709    bool
	Has710    bool
	Has711    bool
	Has712    bool
}

// Init populates model-presence flags, selects the measurement model, and
// reads WMax. tag is used in error messages (e.g. "inverter", "battery").
func Init(r *sunspec.Reader, tag string) (Base, error) {
	b := Base{
		Reader: r,
		Wmax:   math.NaN(),
		Has701: r.HasModel(sunspec.ModelDERMeasureAC),
		Has702: r.HasModel(sunspec.ModelDERCapacity),
		Has703: r.HasModel(sunspec.ModelDEREnterService),
		Has704: r.HasModel(sunspec.ModelDERCtlAC),
		Has705: r.HasModel(sunspec.ModelDERVoltVar),
		Has706: r.HasModel(sunspec.ModelDERVoltWatt),
		Has707: r.HasModel(sunspec.ModelDERTripLV),
		Has708: r.HasModel(sunspec.ModelDERTripHV),
		Has709: r.HasModel(sunspec.ModelDERTripLF),
		Has710: r.HasModel(sunspec.ModelDERTripHF),
		Has711: r.HasModel(sunspec.ModelDERFreqDroop),
		Has712: r.HasModel(sunspec.ModelDERWattVar),
	}

	if b.Has701 {
		b.MeasModel = sunspec.ModelDERMeasureAC
	} else {
		for _, c := range []uint16{sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh} {
			if r.HasModel(c) {
				b.MeasModel = c
				break
			}
		}
		if b.MeasModel == 0 {
			return Base{}, fmt.Errorf("%s: device has no AC measurement model (701, 103, 102, or 101)", tag)
		}
	}

	if b.Has702 {
		if w, err := ReadWMaxFrom702(r); err == nil {
			b.Wmax = w
		}
	} else if r.HasModel(sunspec.ModelBasicSettings) {
		if w, err := ReadWMax(r); err == nil {
			b.Wmax = w
		}
	}

	return b, nil
}

// ── Measurements ─────────────────────────────────────────────────────────────

// ReadMeasurementsM701 parses M701 (DERMeasureAC) registers via the shared
// layout-engine codec. VL1 preferred over LNV (disposition doc §2c S2); PF is
// SF-only in this generation, no legacy ×100 convention (§2c S1).
func ReadMeasurementsM701(regs []uint16) device.Measurements {
	ac := sunspec.Parse701(regs)
	m := device.Measurements{TmpCab: math.NaN()}
	m.W = ac.W
	v := ac.VL1
	if math.IsNaN(v) {
		v = ac.LNV
	}
	m.V = v
	m.Hz = ac.Hz
	m.VA = ac.VA
	m.Var = ac.Var
	m.PF = ac.PF
	return m
}

// ReadMeasurementsACModel parses Model 10x (101/102/103) registers.
func ReadMeasurementsACModel(regs []uint16) device.Measurements {
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

// ── ApplyControl ─────────────────────────────────────────────────────────────

// ApplyControl writes CSIP DERControlBase to the device using the best
// available model path. tag is for error messages.
func (b *Base) ApplyControl(ctrl model.DERControlBase, tag string) error {
	if ctrl.OpModEnergize != nil && b.Has703 {
		if err := b.SetEnterServiceBool(*ctrl.OpModEnergize, tag); err != nil {
			return err
		}
	}

	if ctrl.OpModConnect != nil {
		if !b.Reader.HasModel(sunspec.ModelImmediateCtrl) {
			return fmt.Errorf("%s: no M123 for connect control", tag)
		}
		if err := b.SetConnect(*ctrl.OpModConnect, tag); err != nil {
			return err
		}
	}

	if ctrl.OpModFixedPFInjectW != nil || ctrl.OpModFixedPFAbsorbW != nil {
		if b.Has704 {
			if err := b.SetPowerFactor704(ctrl, tag); err != nil {
				return err
			}
		}
	}

	if ctrl.OpModFixedVar != nil && b.Has704 {
		if err := b.SetConstantVar704(ctrl.OpModFixedVar, tag); err != nil {
			return err
		}
	}

	lim := ctrl.OpModExpLimW
	if lim == nil {
		lim = ctrl.OpModMaxLimW
	}
	if lim != nil {
		if b.Has704 {
			if err := b.SetWMaxLimPct704(lim, tag); err != nil {
				return err
			}
		} else {
			if err := b.SetExportLimit(lim, tag); err != nil {
				return err
			}
		}
	}

	// OpModImpLimW: import (charge) setpoint.
	// Uses signed negative WMaxLimPct so the battery sim charges in the right direction.
	if ctrl.OpModImpLimW != nil {
		if b.Has704 {
			if err := b.SetWMaxLimPct704(ctrl.OpModImpLimW, tag); err != nil {
				return err
			}
		} else {
			if err := b.SetImportLimit(ctrl.OpModImpLimW, tag); err != nil {
				return err
			}
		}
	}

	return nil
}

// ── M703 enter service ───────────────────────────────────────────────────────
//
// Only the ApplyControl-reachable path (SetEnterServiceBool) is kept. The old
// bench fork also exposed a full-struct SetEnterService/ReadEnterService pair
// (DEREnterServiceSettings type) with zero callers and zero test coverage;
// removed rather than re-implemented against the shared codec's differently
// shaped EnterService/Parse703/Encode703 — leftover-fork disposal is TASK-082.

// SetEnterServiceBool is the internal path called from ApplyControl. Named-field
// offset lookup via the shared layout engine (no raw M703_ES constant exists
// in this generation).
func (b *Base) SetEnterServiceBool(energize bool, tag string) error {
	regs, err := b.Reader.ReadModel(sunspec.ModelDEREnterService)
	if err != nil {
		return fmt.Errorf("%s: read M703: %w", tag, err)
	}
	off := sunspec.L703.Offset("ES")
	sunspec.L703.View(regs).SetBool("ES", energize)
	return b.Reader.WriteModel(sunspec.ModelDEREnterService, uint16(off), regs[off:off+1])
}

// ── M704 DERCtlAC helpers ────────────────────────────────────────────────────
//
// These three are the only M704 write paths ApplyControl actually reaches;
// each touches only the named fields it needs via the shared layout engine's
// View (no DERCtlACSettings/EncodeDERCtlAC equivalent exists for a monolithic
// M704 struct write in this generation — by design, per Parse704's read-only
// doc comment). The full-struct SetDERCtlAC/ReadDERCtlAC and ReadDERCapacity
// helpers the old fork also exposed had zero callers/tests and are removed
// (TASK-082 disposal) rather than re-implemented against a shape with no
// equivalent.

// SetPowerFactor704 maps CSIP OpModFixedPF* to M704 PFWInj fields.
func (b *Base) SetPowerFactor704(ctrl model.DERControlBase, tag string) error {
	regs, err := b.Reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("%s: read M704: %w", tag, err)
	}
	v := sunspec.L704.View(regs)
	if ctrl.OpModFixedPFInjectW != nil {
		v.SetBool("PFWInjEna", true)
		v.SetFloat("PFWInj_PF", math.Abs(float64(ctrl.OpModFixedPFInjectW.Value))/10000.0)
		v.SetBool("PFWInj_Ext", true)
	} else if ctrl.OpModFixedPFAbsorbW != nil {
		v.SetBool("PFWInjEna", true)
		v.SetFloat("PFWInj_PF", math.Abs(float64(ctrl.OpModFixedPFAbsorbW.Value))/10000.0)
		v.SetBool("PFWInj_Ext", false)
	}
	return b.Reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// SetConstantVar704 maps CSIP OpModFixedVar to M704 VarSetPct.
func (b *Base) SetConstantVar704(fv *model.FixedVar, tag string) error {
	if fv == nil {
		return nil
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("%s: read M704 for var: %w", tag, err)
	}
	v := sunspec.L704.View(regs)
	v.SetBool("VarSetEna", true)
	v.SetEnum("VarSetPri", 1)
	v.SetFloat("VarSetPct", float64(fv.Value.Value)/100.0)
	return b.Reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// SetWMaxLimPct704 maps an active power limit to M704.WMaxLimPct.
func (b *Base) SetWMaxLimPct704(ap *model.ActivePower, tag string) error {
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return fmt.Errorf("%s: cannot set power limit: WMax unknown", tag)
	}
	requestedW := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
	if requestedW < 0 {
		requestedW = 0
	}
	if requestedW > b.Wmax {
		requestedW = b.Wmax
	}
	pct := (requestedW / b.Wmax) * 100.0

	regs, err := b.Reader.ReadModel(sunspec.ModelDERCtlAC)
	if err != nil {
		return fmt.Errorf("%s: read M704 for WMaxLimPct: %w", tag, err)
	}
	v := sunspec.L704.View(regs)
	v.SetBool("WMaxLimPctEna", true)
	v.SetFloat("WMaxLimPct", pct)
	return b.Reader.WriteModel(sunspec.ModelDERCtlAC, 0, regs)
}

// ── M705-M712 curve models, ReadDERCapacity ─────────────────────────────────
//
// The old bench fork exposed Read/Write pairs for M702 (DERCapacity), M705
// (VoltVar), M706 (VoltWatt), M707/M708 (voltage trip), M709/M710 (freq trip),
// M711 (freq droop), and M712 (WattVar). None had a caller outside their own
// pass-through wrappers in battery.go/inverter.go, and none had test coverage.
// They are removed here rather than re-implemented: the shared codec's curve
// write workflow is a genuinely different handshake (staged index + write +
// AdptCrvReq=2 + poll AdptCrvRslt + Ena=1, vs this fork's single write +
// AdptCrvReq=1, no poll/enable — disposition doc §2c S3), so a faithful port
// is new protocol logic, not a mechanical rename. Leftover-fork disposal
// (driver forks, bench derbase) is TASK-082.

// ── Legacy M123 helpers ──────────────────────────────────────────────────────

// SetConnect writes to Model 123 Conn: 1=connect, 0=disconnect.
func (b *Base) SetConnect(connect bool, tag string) error {
	val := uint16(0)
	if connect {
		val = 1
	}
	if err := b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_Conn, []uint16{val}); err != nil {
		return fmt.Errorf("%s: set connect=%v: %w", tag, connect, err)
	}
	return nil
}

// SetImportLimit writes a signed negative WMaxLimPct to M123, commanding the
// device to absorb power at the requested rate.  This uses a sign convention
// supported by the battery simulator: negative pct = charge direction.
func (b *Base) SetImportLimit(ap *model.ActivePower, tag string) error {
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return fmt.Errorf("%s: cannot set import limit: WMax unknown", tag)
	}
	requestedW := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
	if requestedW < 0 {
		requestedW = 0
	}
	if requestedW > b.Wmax {
		requestedW = b.Wmax
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return fmt.Errorf("%s: read Model 123 for SetImportLimit: %w", tag, err)
	}
	if len(regs) <= sunspec.M123_WMaxLimPct_SF {
		return fmt.Errorf("%s: Model 123 too short", tag)
	}
	sf := int16(regs[sunspec.M123_WMaxLimPct_SF])
	pct := -(requestedW / b.Wmax) * 100.0 // negative = charge direction
	raw := sunspec.RawFromScaleSigned(pct, sf)
	if err := b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct_RmpTms, []uint16{5}); err != nil {
		return fmt.Errorf("%s: set ramp time: %w", tag, err)
	}
	if err := b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct, []uint16{raw}); err != nil {
		return fmt.Errorf("%s: write WMaxLimPct (import): %w", tag, err)
	}
	if err := b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct_Ena, []uint16{1}); err != nil {
		return fmt.Errorf("%s: enable WMaxLimPct: %w", tag, err)
	}
	return nil
}

// SetExportLimit converts watts to WMaxLimPct and writes to M123.
func (b *Base) SetExportLimit(ap *model.ActivePower, tag string) error {
	if math.IsNaN(b.Wmax) || b.Wmax <= 0 {
		return fmt.Errorf("%s: cannot set export limit: WMax unknown (Model 121 absent or zero)", tag)
	}
	requestedW := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
	if requestedW < 0 {
		requestedW = 0
	}
	if requestedW > b.Wmax {
		requestedW = b.Wmax
	}
	regs, err := b.Reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		return fmt.Errorf("%s: read Model 123 for WMaxLimPct_SF: %w", tag, err)
	}
	if len(regs) <= sunspec.M123_WMaxLimPct_SF {
		return fmt.Errorf("%s: Model 123 too short for WMaxLimPct_SF", tag)
	}
	sf := int16(regs[sunspec.M123_WMaxLimPct_SF])
	pct := (requestedW / b.Wmax) * 100.0
	raw := sunspec.RawFromScaleUint(pct, sf)
	if err := b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct_RmpTms, []uint16{5}); err != nil {
		return fmt.Errorf("%s: set ramp time: %w", tag, err)
	}
	if err := b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct, []uint16{raw}); err != nil {
		return fmt.Errorf("%s: write WMaxLimPct: %w", tag, err)
	}
	if err := b.Reader.WriteModel(sunspec.ModelImmediateCtrl, sunspec.M123_WMaxLimPct_Ena, []uint16{1}); err != nil {
		return fmt.Errorf("%s: enable WMaxLimPct: %w", tag, err)
	}
	return nil
}

// ── WMax helpers ─────────────────────────────────────────────────────────────

func ReadWMax(r *sunspec.Reader) (float64, error) {
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

func ReadWMaxFrom702(r *sunspec.Reader) (float64, error) {
	regs, err := r.ReadModel(sunspec.ModelDERCapacity)
	if err != nil {
		return 0, err
	}
	wmax := sunspec.Parse702(regs).WMaxRtg
	if wmax <= 0 || math.IsNaN(wmax) {
		return 0, fmt.Errorf("sunspec: Model 702 WMaxRtg is %g (invalid)", wmax)
	}
	return wmax, nil
}
