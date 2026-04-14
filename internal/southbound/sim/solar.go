package sim

// solar.go — animated PV inverter simulator.
//
// Register layout (Models 1 → 120 → 121 → 122 → 103 → 123 → end):
//
//	40000–40001: SunS header
//	40002–40069: Model 1   (Common,               66 data regs)
//	40070–40097: Model 120 (Nameplate,             26 data regs)
//	40098–40129: Model 121 (Basic Settings,        30 data regs)
//	40130–40175: Model 122 (Extended Status,       44 data regs)
//	40176–40227: Model 103 (Three-Phase Inverter,  50 data regs)
//	40228–40252: Model 123 (Immediate Controls,    23 data regs)
//	40253–40254: end marker
//
// Animation runs every 5 s on a 600-second sinusoidal irradiance cycle:
//
//	W      = WMax × clamp(0.5 + 0.45·sin(2π·t/600), 0.05, 0.95)
//	V      = 240 + 2·sin(2π·t/73)           ±2 V
//	Hz     = 60  + 0.05·sin(2π·t/47)        ±0.05 Hz
//	TmpCab = 35  + 20·(W/WMax)              35–55 °C
//	DCV    = 380 + 30·sin(2π·t/600)         350–410 V DC
//	DCW    = W × 1.06                        conversion loss overhead

import (
	"math"
	"time"

	"csip-tls-test/internal/southbound/sunspec"
)

// NewSolarServer creates and starts an animated PV inverter simulator.
// wmaxW is the nameplate peak power in watts.
func NewSolarServer(listenURL string, wmaxW float64) (*Server, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	m103Base, m122Base := populateSolar(regs, wmaxW)
	return newAnimatedServer(listenURL, regs, func(r *RegisterMap, stop <-chan struct{}) {
		animateSolar(r, wmaxW, m103Base, m122Base, stop)
	})
}

// newAnimatedServer launches the Modbus TCP server and an animation goroutine.
// fn receives the register map and a stop channel; it must return when stop is closed.
func newAnimatedServer(listenURL string, regs *RegisterMap, fn func(*RegisterMap, <-chan struct{})) (*Server, error) {
	s, err := startServer(listenURL, regs)
	if err != nil {
		return nil, err
	}
	// startServer already launched a goroutine that closes s.done on stop.
	// We need our own done channel that the animation goroutine closes instead.
	anim := &Server{
		Regs: s.Regs,
		srv:  s.srv,
		stop: s.stop,
		done: make(chan struct{}),
	}
	// The default goroutine from startServer will close s.done when stop fires —
	// that's harmless since nobody waits on s.done.
	// Our animation goroutine closes anim.done so Stop() can drain it.
	go func() {
		defer close(anim.done)
		fn(anim.Regs, anim.stop)
	}()
	return anim, nil
}

// populateSolar writes the full solar inverter register layout into r.
// Returns the 0-based Modbus addresses of the first data registers of
// Model 103 and Model 122 (used by animateSolar).
func populateSolar(r *RegisterMap, wmaxW float64) (m103Base, m122Base uint16) {
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
	setStr8(r, m1+16, "CSIP-Solar-5000")
	setStr8(r, m1+32, "SN-SOLAR-001")
	cursor += 2 + m1Len

	// Model 120 (Nameplate) — 26 data regs
	r.Set(cursor, sunspec.ModelNameplate)
	r.Set(cursor+1, sunspec.M120Len)
	m120 := cursor + 2
	r.Set(m120+sunspec.M120_DERTyp, 4) // PV
	r.Set(m120+sunspec.M120_WRtg, uint16(wmaxW))
	r.Set(m120+sunspec.M120_VARtg, uint16(wmaxW*1.05))
	r.Set(m120+sunspec.M120_VArRtgQ1, uint16(int16(wmaxW*0.44)))
	r.Set(m120+sunspec.M120_ARtg, uint16(wmaxW/240))
	r.Set(m120+sunspec.M120_PFRtgQ1, uint16(int16(9500))) // 0.95 (sf=-2)
	r.Set(m120+sunspec.M120_W_SF, 0)
	r.Set(m120+sunspec.M120_VARtg_SF, 0)
	r.Set(m120+sunspec.M120_VArRtg_SF, 0)
	r.Set(m120+sunspec.M120_ARtg_SF, 0)
	r.Set(m120+sunspec.M120_PFRtg_SF, sfN(-2))
	cursor += 2 + sunspec.M120Len

	// Model 121 (Basic Settings) — 30 data regs
	const m121Len = 30
	r.Set(cursor, sunspec.ModelBasicSettings)
	r.Set(cursor+1, m121Len)
	m121 := cursor + 2
	r.Set(m121+sunspec.M121_WMax, uint16(wmaxW))
	r.Set(m121+sunspec.M121_WMax_SF, 0)
	cursor += 2 + m121Len

	// Model 122 (Extended Measurements) — 44 data regs
	r.Set(cursor, uint16(122))
	r.Set(cursor+1, sunspec.M122Len)
	m122Base = cursor + 2
	r.Set(m122Base+sunspec.M122_ECPConn, 1) // grid-connected
	r.Set(m122Base+sunspec.M122_PVConn, 1)  // PV strings connected
	r.Set(m122Base+sunspec.M122_WAval, uint16(wmaxW))
	r.Set(m122Base+sunspec.M122_WAval_SF, 0)
	cursor += 2 + sunspec.M122Len

	// Model 103 (Three-Phase Inverter) — 50 data regs
	const m103Len = 50
	r.Set(cursor, sunspec.ModelInverterThreePh)
	r.Set(cursor+1, m103Len)
	m103Base = cursor + 2
	r.Set(m103Base+sunspec.M103_W, uint16(int16(3000)))
	r.Set(m103Base+sunspec.M103_W_SF, 0)
	r.Set(m103Base+sunspec.M103_PhVphA, 2400) // 240.0 V (sf=-1)
	r.Set(m103Base+sunspec.M103_PhVphB, 2400)
	r.Set(m103Base+sunspec.M103_PhVphC, 2400)
	r.Set(m103Base+sunspec.M103_V_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_Hz, 6000) // 60.00 Hz (sf=-2)
	r.Set(m103Base+sunspec.M103_Hz_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_VA, uint16(int16(3100)))
	r.Set(m103Base+sunspec.M103_VA_SF, 0)
	r.Set(m103Base+sunspec.M103_VAr, uint16(int16(650)))
	r.Set(m103Base+sunspec.M103_VAr_SF, 0)
	r.Set(m103Base+sunspec.M103_PF, uint16(int16(9677)))
	r.Set(m103Base+sunspec.M103_PF_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_DCV, 3800) // 380.0 V (sf=-1)
	r.Set(m103Base+sunspec.M103_DCV_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_DCW, uint16(int16(3180)))
	r.Set(m103Base+sunspec.M103_DCW_SF, 0)
	r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(470))) // 47.0 °C (sf=-1)
	r.Set(m103Base+sunspec.M103_Tmp_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_St, 4) // MPPT
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

	// End marker
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	return
}

// animateSolar updates Model 103 and Model 122 WAval every 5 seconds.
// All values are derived from a 600-second sinusoidal irradiance cycle.
func animateSolar(r *RegisterMap, wmaxW float64, m103Base, m122Base uint16, stop <-chan struct{}) {
	sfN := func(v int16) uint16 { return uint16(v) }
	_ = sfN

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	// Accumulated energy counter (simplified, wraps as uint16).
	var whAcc uint16

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			t := float64(time.Now().Unix())

			// Irradiance: 0.05–0.95 × WMax on a 600-second sine cycle.
			irr := math.Max(0.05, math.Min(0.95, 0.5+0.45*math.Sin(2*math.Pi*t/600)))
			w := wmaxW * irr

			// Grid voltage: ±2 V, 73-second period.
			v := 240.0 + 2.0*math.Sin(2*math.Pi*t/73)
			// Frequency: ±0.05 Hz, 47-second period.
			hz := 60.0 + 0.05*math.Sin(2*math.Pi*t/47)
			// Power factor varies slightly.
			pf := math.Max(0.90, math.Min(0.99, 0.97+0.02*math.Sin(2*math.Pi*t/120)))
			va := w / pf
			varPwr := va * math.Sin(math.Acos(pf))
			// Cabinet temperature: 35–55 °C proportional to output.
			tmp := 35.0 + 20.0*irr
			// DC bus voltage tracks irradiance (350–410 V).
			dcv := 380.0 + 30.0*math.Sin(2*math.Pi*t/600)
			dcw := w * 1.06

			// Phase currents (A, sf=0, rounded).
			iph := w / (v * 3)

			// Model 103 updates (scale factors are written once in populateSolar
			// and never change; we update only the measurement registers here).
			r.Set(m103Base+sunspec.M103_A, uint16(int16(math.Round(iph*3))))
			r.Set(m103Base+sunspec.M103_AphA, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_AphB, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_AphC, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_PhVphA, uint16(math.Round(v*10))) // sf=-1
			r.Set(m103Base+sunspec.M103_PhVphB, uint16(math.Round(v*10)))
			r.Set(m103Base+sunspec.M103_PhVphC, uint16(math.Round(v*10)))
			r.Set(m103Base+sunspec.M103_PPVphAB, uint16(math.Round(v*10*math.Sqrt(3))))
			r.Set(m103Base+sunspec.M103_PPVphBC, uint16(math.Round(v*10*math.Sqrt(3))))
			r.Set(m103Base+sunspec.M103_PPVphCA, uint16(math.Round(v*10*math.Sqrt(3))))
			r.Set(m103Base+sunspec.M103_W, uint16(int16(math.Round(w))))
			r.Set(m103Base+sunspec.M103_Hz, uint16(math.Round(hz*100))) // sf=-2
			r.Set(m103Base+sunspec.M103_VA, uint16(int16(math.Round(va))))
			r.Set(m103Base+sunspec.M103_VAr, uint16(int16(math.Round(varPwr))))
			r.Set(m103Base+sunspec.M103_PF, uint16(int16(math.Round(pf*10000)))) // ×100, sf=-2
			r.Set(m103Base+sunspec.M103_DCV, uint16(math.Round(dcv*10))) // sf=-1
			r.Set(m103Base+sunspec.M103_DCW, uint16(int16(math.Round(dcw))))
			r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(math.Round(tmp*10)))) // sf=-1
			r.Set(m103Base+sunspec.M103_TmpSnk, uint16(int16(math.Round((tmp-5)*10))))

			// Operating state: MPPT(4) when producing, Sleeping(2) at minimum.
			if irr < 0.06 {
				r.Set(m103Base+sunspec.M103_St, 2) // sleeping
			} else {
				r.Set(m103Base+sunspec.M103_St, 4) // MPPT
			}

			// Model 122: update WAval (available power) and accumulated energy.
			r.Set(m122Base+sunspec.M122_WAval, uint16(math.Round(w)))
			whAcc += uint16(math.Round(w * 5 / 3600)) // 5-second interval in Wh
			r.Set(m122Base+sunspec.M122_ActWh+3, whAcc) // low word of uint64
		}
	}
}
