package sim

// battery.go — animated Li-Ion battery storage simulator.
//
// Register layout (Models 1 → 120 → 121 → 103 → 123 → 802 → end):
//
//	40000–40001: SunS header
//	40002–40069: Model 1   (Common,               66 data regs)
//	40070–40097: Model 120 (Nameplate,             26 data regs)
//	40098–40129: Model 121 (Basic Settings,        30 data regs)
//	40130–40181: Model 103 (Three-Phase Inverter,  50 data regs)
//	40182–40206: Model 123 (Immediate Controls,    23 data regs)
//	40207–40234: Model 802 (Li-Ion Battery Base,   26 data regs)
//	40235–40236: end marker
//
// Animation runs every 5 s on a 1200-second (20-minute) sinusoidal
// charge/discharge cycle:
//
//	SoC    = 55 + 35·sin(2π·t/1200)          20–90 %
//	W      = −WMax·0.8·cos(2π·t/1200)        negative=charging, positive=discharging
//	V      = 240 + 1.5·sin(2π·t/89)          ±1.5 V
//	Hz     = 60  + 0.03·sin(2π·t/67)         ±0.03 Hz
//	TmpCab = 25  + 15·|W/WMax|               25–40 °C

import (
	"math"
	"time"

	"csip-tls-test/internal/southbound/sunspec"
)

// NewBatteryServer creates and starts an animated Li-Ion battery simulator.
// wmaxKwh is the energy capacity (kWh); wmaxW is the max charge/discharge rate (W).
func NewBatteryServer(listenURL string, wmaxKwh, wmaxW float64) (*Server, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	m103Base, m802Base := populateBattery(regs, wmaxKwh, wmaxW)
	return newAnimatedServer(listenURL, regs, func(r *RegisterMap, stop <-chan struct{}) {
		animateBattery(r, wmaxW, m103Base, m802Base, stop)
	})
}

// populateBattery writes the full battery register layout into r.
// Returns the 0-based Modbus addresses of the first data registers of
// Model 103 and Model 802.
func populateBattery(r *RegisterMap, wmaxKwh, wmaxW float64) (m103Base, m802Base uint16) {
	sfN := func(v int16) uint16 { return uint16(v) }
	base := sunspec.SunSpecBase

	r.Set(base+0, sunspec.SunSMagic0)
	r.Set(base+1, sunspec.SunSMagic1)
	cursor := base + 2

	// Model 1 (Common) — 66 data regs
	const m1Len = 66
	r.Set(cursor, sunspec.ModelCommon)
	r.Set(cursor+1, m1Len)
	m1 := cursor + 2
	setStr16(r, m1+0, "SunSpec Sim")
	setStr8(r, m1+16, "CSIP-Battery-10kWh")
	setStr8(r, m1+32, "SN-BAT-001")
	cursor += 2 + m1Len

	// Model 120 (Nameplate) — 26 data regs
	r.Set(cursor, sunspec.ModelNameplate)
	r.Set(cursor+1, sunspec.M120Len)
	m120 := cursor + 2
	r.Set(m120+sunspec.M120_DERTyp, 80) // storage
	r.Set(m120+sunspec.M120_WRtg, uint16(wmaxW))
	r.Set(m120+sunspec.M120_VARtg, uint16(wmaxW*1.05))
	r.Set(m120+sunspec.M120_VArRtgQ1, uint16(int16(wmaxW*0.44)))
	r.Set(m120+sunspec.M120_VArRtgQ2, uint16(int16(-wmaxW*0.44))) // Q2 discharge
	r.Set(m120+sunspec.M120_ARtg, uint16(wmaxW/240))
	r.Set(m120+sunspec.M120_PFRtgQ1, uint16(int16(9500))) // 0.95
	r.Set(m120+sunspec.M120_WHRtg, uint16(wmaxKwh*1000))  // Wh
	r.Set(m120+sunspec.M120_AhrRtg, uint16(wmaxKwh*1000/48))
	r.Set(m120+sunspec.M120_MaxChaRte, uint16(wmaxW))
	r.Set(m120+sunspec.M120_MaxDisChaRte, uint16(wmaxW))
	r.Set(m120+sunspec.M120_W_SF, 0)
	r.Set(m120+sunspec.M120_VARtg_SF, 0)
	r.Set(m120+sunspec.M120_VArRtg_SF, 0)
	r.Set(m120+sunspec.M120_ARtg_SF, 0)
	r.Set(m120+sunspec.M120_PFRtg_SF, sfN(-2))
	r.Set(m120+sunspec.M120_WHRtg_SF, 0)
	r.Set(m120+sunspec.M120_AhrRtg_SF, 0)
	r.Set(m120+sunspec.M120_MaxChaRte_SF, 0)
	r.Set(m120+sunspec.M120_MaxDisChaRte_SF, 0)
	cursor += 2 + sunspec.M120Len

	// Model 121 (Basic Settings) — 30 data regs
	const m121Len = 30
	r.Set(cursor, sunspec.ModelBasicSettings)
	r.Set(cursor+1, m121Len)
	m121 := cursor + 2
	r.Set(m121+sunspec.M121_WMax, uint16(wmaxW))
	r.Set(m121+sunspec.M121_WMax_SF, 0)
	cursor += 2 + m121Len

	// Model 103 (Three-Phase Inverter/Converter AC measurements) — 50 data regs
	const m103Len = 50
	r.Set(cursor, sunspec.ModelInverterThreePh)
	r.Set(cursor+1, m103Len)
	m103Base = cursor + 2
	// Initial state: idle (W=0), connected
	r.Set(m103Base+sunspec.M103_W, 0)
	r.Set(m103Base+sunspec.M103_W_SF, 0)
	r.Set(m103Base+sunspec.M103_PhVphA, 2400) // 240.0 V (sf=-1)
	r.Set(m103Base+sunspec.M103_PhVphB, 2400)
	r.Set(m103Base+sunspec.M103_PhVphC, 2400)
	r.Set(m103Base+sunspec.M103_V_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_Hz, 6000) // 60.00 Hz (sf=-2)
	r.Set(m103Base+sunspec.M103_Hz_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_VA, 0)
	r.Set(m103Base+sunspec.M103_VA_SF, 0)
	r.Set(m103Base+sunspec.M103_VAr, 0)
	r.Set(m103Base+sunspec.M103_VAr_SF, 0)
	r.Set(m103Base+sunspec.M103_PF, uint16(int16(10000))) // 1.00 (sf=-2)
	r.Set(m103Base+sunspec.M103_PF_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_DCV, 0)
	r.Set(m103Base+sunspec.M103_DCV_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_DCW, 0)
	r.Set(m103Base+sunspec.M103_DCW_SF, 0)
	r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(250))) // 25.0 °C (sf=-1)
	r.Set(m103Base+sunspec.M103_Tmp_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_St, 8) // standby
	cursor += 2 + m103Len

	// Model 123 (Immediate Controls) — 23 data regs
	const m123Len = 23
	r.Set(cursor, sunspec.ModelImmediateCtrl)
	r.Set(cursor+1, m123Len)
	m123 := cursor + 2
	r.Set(m123+sunspec.M123_WMaxLimPct, 10000) // 100.00% (sf=-2)
	r.Set(m123+sunspec.M123_WMaxLimPct_Ena, 1)
	r.Set(m123+sunspec.M123_WMaxLimPct_SF, sfN(-2))
	r.Set(m123+sunspec.M123_Conn, 1)
	cursor += 2 + m123Len

	// Model 802 (Li-Ion Battery Base) — 26 data regs
	r.Set(cursor, sunspec.ModelLithiumBattery)
	r.Set(cursor+1, sunspec.M802Len)
	m802Base = cursor + 2
	whRtg := uint16(wmaxKwh * 1000)
	r.Set(m802Base+sunspec.M802_WHRtg, whRtg)
	r.Set(m802Base+sunspec.M802_WHRtg_SF, 0)
	r.Set(m802Base+sunspec.M802_AHRtg, uint16(wmaxKwh*1000/48))
	r.Set(m802Base+sunspec.M802_AHRtg_SF, 0)
	r.Set(m802Base+sunspec.M802_WChaRteMax, uint16(wmaxW))
	r.Set(m802Base+sunspec.M802_WDisChaRteMax, uint16(wmaxW))
	r.Set(m802Base+sunspec.M802_W_SF, 0)
	r.Set(m802Base+sunspec.M802_DisChaRte, 1) // 1%/day self-discharge
	r.Set(m802Base+sunspec.M802_DisChaRte_SF, 0)
	r.Set(m802Base+sunspec.M802_SoCMax, 9500)  // 95% max SoC (sf=-2)
	r.Set(m802Base+sunspec.M802_SoCMin, 500)   // 5% min SoC
	r.Set(m802Base+sunspec.M802_SoCRsvMax, 9000)
	r.Set(m802Base+sunspec.M802_SoCRsvMin, 1000)
	r.Set(m802Base+sunspec.M802_SoC_SF, sfN(-2)) // register × 0.01 = %
	r.Set(m802Base+sunspec.M802_SoC, 5500)        // 55.00% initial SoC
	r.Set(m802Base+sunspec.M802_DoD, 4500)         // 45.00% DoD
	r.Set(m802Base+sunspec.M802_DoD_SF, sfN(-2))
	r.Set(m802Base+sunspec.M802_SoH, 10000) // 100.00% healthy (sf=-2)
	r.Set(m802Base+sunspec.M802_SoH_SF, sfN(-2))
	r.Set(m802Base+sunspec.M802_ChaSt, 6)   // holding (idle)
	r.Set(m802Base+sunspec.M802_LocRemCtl, 1) // remote control
	r.Set(m802Base+sunspec.M802_Typ, 4)       // Li-Ion
	r.Set(m802Base+sunspec.M802_State, 2)     // connected
	cursor += 2 + sunspec.M802Len

	// End marker
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	return
}

// animateBattery updates Model 103 and Model 802 registers every 5 seconds.
// The cycle period is 1200 seconds (20 minutes).
//
//	SoC = 55 + 35·sin(phase)         → 20–90 %
//	W   = −WMax·0.8·cos(phase)       → negative=charging, positive=discharging
func animateBattery(r *RegisterMap, wmaxW float64, m103Base, m802Base uint16, stop <-chan struct{}) {
	sfN := func(v int16) uint16 { return uint16(v) }
	_ = sfN

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			t := float64(time.Now().Unix())
			phase := 2 * math.Pi * t / 1200

			// State of charge: 20–90 % sinusoidal.
			soc := 55.0 + 35.0*math.Sin(phase)
			// Power: positive = discharging (export), negative = charging (import).
			// W ∝ −d(SoC)/dt so it leads SoC by 90°.
			w := -wmaxW * 0.80 * math.Cos(phase)

			// Grid measurements.
			v := 240.0 + 1.5*math.Sin(2*math.Pi*t/89)
			hz := 60.0 + 0.03*math.Sin(2*math.Pi*t/67)
			absW := math.Abs(w)
			tmp := 25.0 + 15.0*(absW/wmaxW)

			// PF is high (near unity) for battery converters.
			pf := math.Max(0.95, math.Min(0.9999, 0.98+0.015*math.Cos(phase)))
			va := absW / pf
			varPwr := va * math.Sin(math.Acos(pf))
			if w < 0 {
				varPwr = -varPwr // reactive power sign follows real power direction
			}

			// DC battery bus voltage (approximately proportional to SoC).
			dcv := 44.0 + 6.0*(soc/100.0) // 44–50 V range (×10 for sf=-1 → 440–500)
			dcw := absW * 1.03              // conversion loss

			// Phase currents.
			iph := absW / (v * 3)
			if w < 0 {
				iph = -iph // charging = current flowing in
			}

			// Model 103 updates.
			r.Set(m103Base+sunspec.M103_A, uint16(int16(math.Round(iph*3))))
			r.Set(m103Base+sunspec.M103_AphA, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_AphB, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_AphC, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_PhVphA, uint16(math.Round(v*10))) // sf=-1
			r.Set(m103Base+sunspec.M103_PhVphB, uint16(math.Round(v*10)))
			r.Set(m103Base+sunspec.M103_PhVphC, uint16(math.Round(v*10)))
			r.Set(m103Base+sunspec.M103_W, uint16(int16(math.Round(w))))
			r.Set(m103Base+sunspec.M103_Hz, uint16(math.Round(hz*100))) // sf=-2
			r.Set(m103Base+sunspec.M103_VA, uint16(int16(math.Round(va))))
			r.Set(m103Base+sunspec.M103_VAr, uint16(int16(math.Round(varPwr))))
			r.Set(m103Base+sunspec.M103_PF, uint16(int16(math.Round(pf*10000))))
			r.Set(m103Base+sunspec.M103_DCV, uint16(math.Round(dcv*10))) // sf=-1
			r.Set(m103Base+sunspec.M103_DCW, uint16(int16(math.Round(dcw))))
			r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(math.Round(tmp*10)))) // sf=-1

			// Operating state: 4=MPPT/active, 8=standby at low current.
			if absW < wmaxW*0.02 {
				r.Set(m103Base+sunspec.M103_St, 8) // standby
			} else {
				r.Set(m103Base+sunspec.M103_St, 4) // active
			}

			// Model 802 updates.
			r.Set(m802Base+sunspec.M802_SoC, uint16(math.Round(soc*100))) // sf=-2 → %
			dod := 100.0 - soc
			r.Set(m802Base+sunspec.M802_DoD, uint16(math.Round(dod*100)))

			// Charge status: 3=discharging, 4=charging, 6=holding.
			var chaSt uint16
			switch {
			case w > wmaxW*0.02:
				chaSt = 3 // discharging
			case w < -wmaxW*0.02:
				chaSt = 4 // charging
			default:
				chaSt = 6 // holding
			}
			r.Set(m802Base+sunspec.M802_ChaSt, chaSt)

			// Battery state: 2=connected always in this sim.
			r.Set(m802Base+sunspec.M802_State, 2)
		}
	}
}
