package battery

import (
	"fmt"
	"math"

	"csip-tls-test/internal/orchestrator"
	"csip-tls-test/internal/southbound/sunspec"
)

// ReadBatteryMetrics reads battery-specific state from SunSpec Model 802
// (Lithium Battery) and returns it as an orchestrator.BatteryMetrics.
// Fields that are not supported by the device are set to math.NaN().
//
// This method implements orchestrator.BatteryMetricsReader so the orchestrator
// adapter can extract SOC/SOH without knowing the concrete Battery type.
func (b *Battery) ReadBatteryMetrics() (orchestrator.BatteryMetrics, error) {
	m := orchestrator.BatteryMetrics{
		SOC:           math.NaN(),
		SOH:           math.NaN(),
		CapacityWh:    math.NaN(),
		MaxChargeW:    math.NaN(),
		MaxDischargeW: math.NaN(),
	}

	if !b.reader.HasModel(sunspec.ModelLithiumBattery) {
		// Fall back to nameplate data from Model 121 only.
		if !math.IsNaN(b.wmax) {
			m.MaxChargeW = b.wmax
			m.MaxDischargeW = b.wmax
		}
		return m, nil
	}

	regs, err := b.reader.ReadModel(sunspec.ModelLithiumBattery)
	if err != nil {
		return m, fmt.Errorf("battery: read Model 802 for metrics: %w", err)
	}

	get := func(offset int) uint16 {
		if offset < len(regs) {
			return regs[offset]
		}
		return 0
	}
	sf := func(sfOffset int) int16 { return int16(get(sfOffset)) }

	// State of charge (M802_SoC @ offset 14, scale factor @ offset 13).
	if len(regs) > sunspec.M802_SoC {
		soc := sunspec.ApplyScaleUint(get(sunspec.M802_SoC), sf(sunspec.M802_SoC_SF))
		if !math.IsNaN(soc) && soc >= 0 {
			m.SOC = soc
		}
	}

	// State of health (M802_SoH @ offset 17, scale factor @ offset 18).
	if len(regs) > sunspec.M802_SoH {
		soh := sunspec.ApplyScaleUint(get(sunspec.M802_SoH), sf(sunspec.M802_SoH_SF))
		if !math.IsNaN(soh) && soh >= 0 {
			m.SOH = soh
		}
	}

	// Capacity in Wh (M802_WHRtg @ offset 0, scale factor @ offset 1).
	if len(regs) > sunspec.M802_WHRtg {
		cap := sunspec.ApplyScaleUint(get(sunspec.M802_WHRtg), sf(sunspec.M802_WHRtg_SF))
		if !math.IsNaN(cap) && cap > 0 {
			m.CapacityWh = cap
		}
	}

	// Max charge / discharge power (M802_WChaRteMax/WDisChaRteMax, shared M802_W_SF).
	if len(regs) > sunspec.M802_WDisChaRteMax {
		wSF := sf(sunspec.M802_W_SF)
		cha := sunspec.ApplyScaleUint(get(sunspec.M802_WChaRteMax), wSF)
		dis := sunspec.ApplyScaleUint(get(sunspec.M802_WDisChaRteMax), wSF)
		if !math.IsNaN(cha) && cha > 0 {
			m.MaxChargeW = cha
		} else if !math.IsNaN(b.wmax) {
			m.MaxChargeW = b.wmax
		}
		if !math.IsNaN(dis) && dis > 0 {
			m.MaxDischargeW = dis
		} else if !math.IsNaN(b.wmax) {
			m.MaxDischargeW = b.wmax
		}
	} else if !math.IsNaN(b.wmax) {
		m.MaxChargeW = b.wmax
		m.MaxDischargeW = b.wmax
	}

	return m, nil
}
