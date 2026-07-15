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
// Animation runs every 5 s on a 1200-second (20-minute) sinusoidal cycle:
//
//	SoC = 55 + 35·sin(2π·t/1200)        20–90 %
//	W   = −WMax·0.8·cos(2π·t/1200)      negative=charging, positive=discharging

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"lexa-proto/sunspec"
)

// BatteryBases holds the first data-register address of each model block.
type BatteryBases struct {
	M121Base uint16 // Model 121 (Basic Settings)
	M103Base uint16 // Model 103 (Three-Phase Inverter/Converter AC)
	M123Base uint16 // Model 123 (Immediate Controls)
	M802Base uint16 // Model 802 (Li-Ion Battery Base)
}

// BatteryServer is an animated Li-Ion battery simulator with a built-in API.
type BatteryServer struct {
	*Server
	bases   BatteryBases
	wmaxW   float64
	wmaxKwh float64
	// pendingSoC carries a POST /inject {"SoC_pct": X} value to the animation
	// goroutine so it seeds the integrator from the injected SOC rather than
	// from whatever the sinusoidal animation last wrote to the register.
	pendingSoC atomic.Pointer[float64]
	faults     faultController // shared fault-injection state (see faults.go)
}

// batteryFaultKinds is the set of POST /fault kinds the battery sim advertises.
var batteryFaultKinds = map[FaultKind]bool{
	FaultRejectWrite:       true,
	FaultWrongSign:         true,
	FaultSocRefuse:         true,
	FaultChargeDisabled:    true,
	FaultDischargeDisabled: true,
	FaultNanSentinel:       true,
	FaultLatency:           true,
	FaultModbusException:   true,
}

// NewBatteryServer creates and starts an animated Li-Ion battery simulator.
// wmaxKwh is the energy capacity; wmaxW is the max charge/discharge rate.
func NewBatteryServer(listenURL string, wmaxKwh, wmaxW float64) (*BatteryServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	bases := populateBattery(regs, wmaxKwh, wmaxW)

	// Allocate bs first so the write hook and animation closure can shape output
	// through its faultController (the effect-time soc_refuse fault).
	bs := &BatteryServer{bases: bases, wmaxW: wmaxW, wmaxKwh: wmaxKwh}
	bs.faults.label = "battery"

	// Install the hub-write hook before the Modbus server starts so the
	// assignment is never concurrent with a handler reading it (finding MOD-3).
	regs.OnWrite = func(startAddr uint16) {
		if startAddr >= bases.M123Base && startAddr < bases.M123Base+23 {
			applyHubBatteryWrite(regs, bases, wmaxW, &bs.faults)
		}
	}

	// Intercept control writes BEFORE they land so reject_write / wrong_sign can
	// alter the commanded WMaxLimPct; the OnWrite hook above still fires after
	// and reflects whatever value actually landed into the power registers.
	regs.OnWriteAttempt = bs.interceptWrite
	regs.OnRead = bs.faults.transportRead

	srv, err := newAnimatedServer(listenURL, regs, func(s *Server, r *RegisterMap, stop <-chan struct{}) {
		animateBattery(s, r, wmaxW, wmaxKwh, bases, &bs.pendingSoC, &bs.faults, stop)
	})
	if err != nil {
		return nil, err
	}
	bs.Server = srv
	return bs, nil
}

// interceptWrite is the RegisterMap.OnWriteAttempt hook. It delegates to the
// shared faultController acting on the battery's signed WMaxLimPct control
// register (negative=charge, positive=discharge). With no fault armed it is a
// pass-through.
func (bs *BatteryServer) interceptWrite(startAddr uint16, vals []uint16) bool {
	cmdAddr := bs.bases.M123Base + sunspec.M123_WMaxLimPct
	return bs.faults.intercept(bs.Regs, cmdAddr, startAddr, vals)
}

// ApplyFault arms or clears a fault for this sim. It is wired to simapi's
// POST /fault. Server-plumbing kinds (tcp_drop / unit_id_confusion /
// register_tearing) are handled first by the shared *Server; everything else
// is a register-level fault handled by the faultController.
func (bs *BatteryServer) ApplyFault(body []byte) error {
	if handled, err := bs.Server.applyServerFault(body); handled {
		return err
	}
	return bs.faults.apply(body, batteryFaultKinds)
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

// BatteryState is the JSON-serialisable snapshot returned by GET /state.
type BatteryState struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Animation struct {
		Paused bool    `json:"paused"`
		Speed  float64 `json:"speed"`
	} `json:"animation"`
	Nameplate struct {
		WMaxW      float64 `json:"wmax_W"`
		CapacityWh float64 `json:"capacity_Wh"`
	} `json:"nameplate"`
	Measurements struct {
		W_W      float64 `json:"W_W"`
		V_V      float64 `json:"V_V"`
		Hz_Hz    float64 `json:"Hz_Hz"`
		TmpCab_C float64 `json:"TmpCab_C"`
		St       int     `json:"St"`
		StText   string  `json:"St_text"`
	} `json:"measurements"`
	Battery struct {
		SoC_pct   float64 `json:"SoC_pct"`
		DoD_pct   float64 `json:"DoD_pct"`
		SoH_pct   float64 `json:"SoH_pct"`
		ChaSt     int     `json:"ChaSt"`
		ChaStText string  `json:"ChaSt_text"`
	} `json:"battery"`
	Controls struct {
		WMaxLimPct_pct float64 `json:"WMaxLimPct_pct"`
		Conn           int     `json:"Conn"`
	} `json:"controls"`
}

// Snapshot reads current register state and returns a decoded BatteryState.
func (bs *BatteryServer) Snapshot() BatteryState {
	r := bs.Regs
	b := bs.bases

	sf := func(addr uint16) int16 { return int16(r.Get(addr)) }
	signed := func(addr, sfAddr uint16) float64 {
		return sunspec.ApplyScaleSigned(r.Get(addr), sf(sfAddr))
	}
	unsigned := func(addr, sfAddr uint16) float64 {
		return sunspec.ApplyScaleUint(r.Get(addr), sf(sfAddr))
	}

	var st BatteryState
	st.Type = "battery"
	st.Timestamp = time.Now()
	st.Animation.Paused = bs.IsPaused()
	st.Animation.Speed = bs.Speed()
	st.Nameplate.WMaxW = bs.wmaxW
	st.Nameplate.CapacityWh = bs.wmaxKwh * 1000

	m := &st.Measurements
	m.W_W = signed(b.M103Base+sunspec.M103_W, b.M103Base+sunspec.M103_W_SF)
	m.V_V = unsigned(b.M103Base+sunspec.M103_PhVphA, b.M103Base+sunspec.M103_V_SF)
	m.Hz_Hz = unsigned(b.M103Base+sunspec.M103_Hz, b.M103Base+sunspec.M103_Hz_SF)
	m.TmpCab_C = signed(b.M103Base+sunspec.M103_TmpCab, b.M103Base+sunspec.M103_Tmp_SF)
	m.St = int(r.Get(b.M103Base + sunspec.M103_St))
	m.StText = batteryInverterStateText(m.St)

	bat := &st.Battery
	bat.SoC_pct = unsigned(b.M802Base+uint16(sunspec.M802_SoC), b.M802Base+uint16(sunspec.M802_SoC_SF))
	bat.DoD_pct = unsigned(b.M802Base+uint16(sunspec.M802_DoD), b.M802Base+uint16(sunspec.M802_DoD_SF))
	bat.SoH_pct = unsigned(b.M802Base+uint16(sunspec.M802_SoH), b.M802Base+uint16(sunspec.M802_SoH_SF))
	bat.ChaSt = int(r.Get(b.M802Base + uint16(sunspec.M802_ChaSt)))
	bat.ChaStText = chaStText(bat.ChaSt)

	c := &st.Controls
	c.WMaxLimPct_pct = signed(b.M123Base+sunspec.M123_WMaxLimPct, b.M123Base+sunspec.M123_WMaxLimPct_SF) / 100.0
	c.Conn = int(r.Get(b.M123Base + sunspec.M123_Conn))

	return st
}

// Registers returns a sparse map of non-zero register values for debugging.
func (bs *BatteryServer) Registers() map[string]uint16 {
	out := make(map[string]uint16)
	base := uint16(sunspec.SunSpecBase)
	for addr := base; addr <= base+236; addr++ {
		v := bs.Regs.Get(addr)
		if v != 0 {
			out[fmt.Sprintf("%d", addr)] = v
		}
	}
	return out
}

// Inject overrides one or more fields.
// Accepted keys: "W_W", "V_V", "Hz_Hz", "TmpCab_C",
// "SoC_pct" (0–100), "SoH_pct" (0–100),
// "WMaxLimPct_pct" (0–100), "Ena" (0 or 1), "Conn" (0 or 1), "St" (1–8), "ChaSt" (1–7).
func (bs *BatteryServer) Inject(body []byte) error {
	var fields map[string]float64
	if err := json.Unmarshal(body, &fields); err != nil {
		return fmt.Errorf("inject: %w", err)
	}
	r := bs.Regs
	b := bs.bases
	sf := func(addr uint16) int16 { return int16(r.Get(addr)) }

	for key, val := range fields {
		switch key {
		case "W_W":
			r.Set(b.M103Base+sunspec.M103_W,
				sunspec.RawFromScaleSigned(val, sf(b.M103Base+sunspec.M103_W_SF)))
		case "V_V":
			v10 := uint16(math.Round(val * 10))
			r.Set(b.M103Base+sunspec.M103_PhVphA, v10)
			r.Set(b.M103Base+sunspec.M103_PhVphB, v10)
			r.Set(b.M103Base+sunspec.M103_PhVphC, v10)
		case "Hz_Hz":
			r.Set(b.M103Base+sunspec.M103_Hz,
				sunspec.RawFromScaleUint(val, sf(b.M103Base+sunspec.M103_Hz_SF)))
		case "TmpCab_C":
			r.Set(b.M103Base+sunspec.M103_TmpCab,
				sunspec.RawFromScaleSigned(val, sf(b.M103Base+sunspec.M103_Tmp_SF)))
		case "SoC_pct":
			r.Set(b.M802Base+uint16(sunspec.M802_SoC),
				sunspec.RawFromScaleUint(val, int16(r.Get(b.M802Base+uint16(sunspec.M802_SoC_SF)))))
			v := val
			bs.pendingSoC.Store(&v)
		case "SoH_pct":
			r.Set(b.M802Base+uint16(sunspec.M802_SoH),
				sunspec.RawFromScaleUint(val, int16(r.Get(b.M802Base+uint16(sunspec.M802_SoH_SF)))))
		case "WMaxLimPct_pct":
			r.Set(b.M123Base+sunspec.M123_WMaxLimPct,
				sunspec.RawFromScaleSigned(val*100, sf(b.M123Base+sunspec.M123_WMaxLimPct_SF)))
			// val=0 means "release hub control"; clear Ena so animation runs free.
			if val == 0 {
				r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 0)
			} else {
				r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
			}
		case "Ena":
			// Explicit enable override, applied AFTER WMaxLimPct_pct's implicit
			// Ena handling (send it as a separate POST — map order within one
			// body is unspecified). {"WMaxLimPct_pct": 0} then {"Ena": 1} is
			// "hub-controlled idle": the pack holds 0 W instead of reverting to
			// the free-running demo sinusoid. The QA harness needs that state
			// between scenarios — its old pct-0-only reset RELEASED the pack,
			// and at a cycle boundary the hub's deduped idle command left it
			// free-running (±4 kW sinusoid) for up to 60 s into scenario 1
			// (QA 2026-07-03 v6: export-cap-full-battery INV-SOC FAIL).
			r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, uint16(val))
		case "Conn":
			r.Set(b.M123Base+sunspec.M123_Conn, uint16(val))
		case "St":
			r.Set(b.M103Base+sunspec.M103_St, uint16(val))
		case "ChaSt":
			r.Set(b.M802Base+uint16(sunspec.M802_ChaSt), uint16(val))
		default:
			return fmt.Errorf("inject: unknown field %q", key)
		}
	}
	return nil
}

func batteryInverterStateText(st int) string {
	switch st {
	case 4:
		return "active"
	case 8:
		return "standby"
	default:
		return fmt.Sprintf("st%d", st)
	}
}

func chaStText(st int) string {
	switch st {
	case 1:
		return "off"
	case 2:
		return "empty"
	case 3:
		return "discharging"
	case 4:
		return "charging"
	case 5:
		return "full"
	case 6:
		return "holding"
	case 7:
		return "testing"
	default:
		return fmt.Sprintf("chaSt%d", st)
	}
}

// ── populate ──────────────────────────────────────────────────────────────────

func populateBattery(r *RegisterMap, wmaxKwh, wmaxW float64) BatteryBases {
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
	r.Set(m120+sunspec.M120_DERTyp, 80)
	r.Set(m120+sunspec.M120_WRtg, uint16(wmaxW))
	r.Set(m120+sunspec.M120_VARtg, uint16(wmaxW*1.05))
	r.Set(m120+sunspec.M120_VArRtgQ1, uint16(int16(wmaxW*0.44)))
	r.Set(m120+sunspec.M120_VArRtgQ2, uint16(int16(-wmaxW*0.44)))
	r.Set(m120+sunspec.M120_ARtg, uint16(wmaxW/240))
	r.Set(m120+sunspec.M120_PFRtgQ1, uint16(int16(9500)))
	r.Set(m120+sunspec.M120_WHRtg, uint16(wmaxKwh*1000))
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
	m121Base := cursor + 2
	r.Set(m121Base+sunspec.M121_WMax, uint16(wmaxW))
	r.Set(m121Base+sunspec.M121_WMax_SF, 0)
	cursor += 2 + m121Len

	// Model 103 (Three-Phase Inverter/Converter AC) — 50 data regs
	const m103Len = 50
	r.Set(cursor, sunspec.ModelInverterThreePh)
	r.Set(cursor+1, m103Len)
	m103Base := cursor + 2
	r.Set(m103Base+sunspec.M103_W, 0)
	r.Set(m103Base+sunspec.M103_W_SF, 0)
	r.Set(m103Base+sunspec.M103_PhVphA, 2400)
	r.Set(m103Base+sunspec.M103_PhVphB, 2400)
	r.Set(m103Base+sunspec.M103_PhVphC, 2400)
	r.Set(m103Base+sunspec.M103_V_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_Hz, 6000)
	r.Set(m103Base+sunspec.M103_Hz_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_VA, 0)
	r.Set(m103Base+sunspec.M103_VA_SF, 0)
	r.Set(m103Base+sunspec.M103_VAr, 0)
	r.Set(m103Base+sunspec.M103_VAr_SF, 0)
	r.Set(m103Base+sunspec.M103_PF, uint16(int16(10000)))
	r.Set(m103Base+sunspec.M103_PF_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_DCV, 0)
	r.Set(m103Base+sunspec.M103_DCV_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_DCW, 0)
	r.Set(m103Base+sunspec.M103_DCW_SF, 0)
	r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(250)))
	r.Set(m103Base+sunspec.M103_Tmp_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_St, 8)
	cursor += 2 + m103Len

	// Model 123 (Immediate Controls) — 23 data regs
	const m123Len = 23
	r.Set(cursor, sunspec.ModelImmediateCtrl)
	r.Set(cursor+1, m123Len)
	m123Base := cursor + 2
	r.Set(m123Base+sunspec.M123_WMaxLimPct, 0)
	r.Set(m123Base+sunspec.M123_WMaxLimPct_Ena, 0) // hub sets Ena=1 when it takes control
	r.Set(m123Base+sunspec.M123_WMaxLimPct_SF, sfN(-2))
	r.Set(m123Base+sunspec.M123_Conn, 1)
	cursor += 2 + m123Len

	// Model 802 (Li-Ion Battery Base) — 26 data regs
	r.Set(cursor, sunspec.ModelLithiumBattery)
	r.Set(cursor+1, sunspec.M802Len)
	m802Base := cursor + 2
	whRtg := uint16(wmaxKwh * 1000)
	r.Set(m802Base+uint16(sunspec.M802_WHRtg), whRtg)
	r.Set(m802Base+uint16(sunspec.M802_WHRtg_SF), 0)
	r.Set(m802Base+uint16(sunspec.M802_AHRtg), uint16(wmaxKwh*1000/48))
	r.Set(m802Base+uint16(sunspec.M802_AHRtg_SF), 0)
	r.Set(m802Base+uint16(sunspec.M802_WChaRteMax), uint16(wmaxW))
	r.Set(m802Base+uint16(sunspec.M802_WDisChaRteMax), uint16(wmaxW))
	r.Set(m802Base+uint16(sunspec.M802_W_SF), 0)
	r.Set(m802Base+uint16(sunspec.M802_DisChaRte), 1)
	r.Set(m802Base+uint16(sunspec.M802_DisChaRte_SF), 0)
	r.Set(m802Base+uint16(sunspec.M802_SoCMax), 9500)
	r.Set(m802Base+uint16(sunspec.M802_SoCMin), 500)
	r.Set(m802Base+uint16(sunspec.M802_SoCRsvMax), 9000)
	r.Set(m802Base+uint16(sunspec.M802_SoCRsvMin), 1000)
	r.Set(m802Base+uint16(sunspec.M802_SoC_SF), sfN(-2))
	r.Set(m802Base+uint16(sunspec.M802_SoC), 5500)
	r.Set(m802Base+uint16(sunspec.M802_DoD), 4500)
	r.Set(m802Base+uint16(sunspec.M802_DoD_SF), sfN(-2))
	r.Set(m802Base+uint16(sunspec.M802_SoH), 10000)
	r.Set(m802Base+uint16(sunspec.M802_SoH_SF), sfN(-2))
	r.Set(m802Base+uint16(sunspec.M802_ChaSt), 6)
	r.Set(m802Base+uint16(sunspec.M802_LocRemCtl), 1)
	r.Set(m802Base+uint16(sunspec.M802_Typ), 4)
	r.Set(m802Base+uint16(sunspec.M802_State), 2)
	cursor += 2 + sunspec.M802Len

	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)

	return BatteryBases{
		M121Base: m121Base,
		M103Base: m103Base,
		M123Base: m123Base,
		M802Base: m802Base,
	}
}

// ── animation ─────────────────────────────────────────────────────────────────

// applyHubBatteryWrite immediately reflects a hub M123 write into the power and
// state registers (e.g. when the animation is paused). Called from RegisterMap
// OnWrite after each Modbus write into the M123 block.
func applyHubBatteryWrite(r *RegisterMap, bases BatteryBases, wmaxW float64, fc *faultController) {
	w := fc.shapeBatteryW(hubBatteryW(r, bases.M123Base, wmaxW))
	if math.IsNaN(w) {
		return
	}
	r.Set(bases.M103Base+sunspec.M103_W, uint16(int16(math.Round(w))))
	if math.Abs(w) < wmaxW*0.02 {
		r.Set(bases.M103Base+sunspec.M103_St, 8)
	} else {
		r.Set(bases.M103Base+sunspec.M103_St, 4)
	}
}

// hubBatteryW reads M123 registers and returns the hub-commanded W value.
// Returns NaN when Ena=0 (no hub command; animation should run freely).
// Positive W = discharge; negative W = charge.
// Encodes direction via a signed WMaxLimPct convention: the hub writes
// a negative percentage for charging and positive for discharging.
func hubBatteryW(r *RegisterMap, m123Base uint16, wmaxW float64) float64 {
	if r.Get(m123Base+sunspec.M123_Conn) == 0 {
		return 0 // disconnected
	}
	if r.Get(m123Base+sunspec.M123_WMaxLimPct_Ena) == 0 {
		return math.NaN() // no hub command; let animation run
	}
	raw := r.Get(m123Base + sunspec.M123_WMaxLimPct)
	sf := int16(r.Get(m123Base + sunspec.M123_WMaxLimPct_SF))
	pct := sunspec.ApplyScaleSigned(raw, sf) // signed: negative=charge, positive=discharge
	return wmaxW * pct / 100.0
}

// clampToSoC limits commanded power w (>0 discharge, <0 charge) to the energy
// the pack can physically source or sink over dtSim seconds at its current SoC,
// returning the (possibly reduced) power and the resulting SoC %.
//
// An empty pack cannot keep discharging, nor a full pack keep charging. Without
// this clamp the sim would report the full commanded power even at 0/100% SoC —
// fabricating phantom grid export/import and letting a hub that over-commands
// the battery see free energy, which corrupts cost/energy accounting.
func clampToSoC(w, socPct, capacityWh, dtSim float64) (float64, float64) {
	if dtSim <= 0 || capacityWh <= 0 {
		return w, socPct
	}
	// w > 0 → discharging → SoC falls; w < 0 → charging → SoC rises.
	dsoc := -w * dtSim * 100.0 / (capacityWh * 3600.0)
	if socPct+dsoc < 0 { // would discharge past empty
		dsoc = -socPct
		w = -dsoc * capacityWh * 3600.0 / (100.0 * dtSim)
	} else if socPct+dsoc > 100 { // would charge past full
		dsoc = 100 - socPct
		w = -dsoc * capacityWh * 3600.0 / (100.0 * dtSim)
	}
	return w, math.Max(0, math.Min(100, socPct+dsoc))
}

// animateBattery drives the batsim register bank every 5 real-time seconds.
//
// SoC behaviour:
//   - Free-running (hub Ena=0): SoC follows a sinusoidal cycle for visual demo.
//   - Hub-controlled (hub Ena=1): SoC integrates actual power against capacity,
//     so SOC rises when charging and falls when discharging.  The speed
//     multiplier (via s.Speed()) scales the integration rate so a 10× speed
//     setting makes SoC move 10× faster for demo visibility.
//   - POST /inject {"SoC_pct": X}: immediately seeds the integrator so the
//     hub-controlled path starts from the injected value.
func animateBattery(s *Server, r *RegisterMap, wmaxW, wmaxKwh float64, bases BatteryBases,
	pendingSoC *atomic.Pointer[float64], fc *faultController, stop <-chan struct{}) {
	m103Base := bases.M103Base
	m802Base := bases.M802Base
	m123Base := bases.M123Base

	// socMu protects socPct and socSeeded across the tick goroutine and OnWrite.
	var socMu sync.Mutex
	socPct := 55.0 // initial — overwritten on first hub-controlled tick
	socSeeded := false

	const tickInterval = 5.0 // real seconds between animation ticks

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if s.IsPaused() {
				continue
			}
			t := s.simTime()
			phase := 2 * math.Pi * t / 1200

			hw := fc.shapeBatteryW(hubBatteryW(r, m123Base, wmaxW))

			var w, soc float64
			// pendingSoC is sticky across free-running ticks so an operator
			// inject is preserved through the window between "resume" and the
			// hub picking up the new DERControl.  It is consumed only by the
			// hub-controlled branch, which uses it to seed the integrator.
			if !math.IsNaN(hw) {
				// Hub-controlled: integrate SoC from actual power.
				w = hw
				socMu.Lock()
				if ptr := pendingSoC.Swap(nil); ptr != nil {
					socPct = *ptr
					socSeeded = true
				} else if !socSeeded {
					raw := r.Get(m802Base + uint16(sunspec.M802_SoC))
					sf := int16(r.Get(m802Base + uint16(sunspec.M802_SoC_SF)))
					socPct = sunspec.ApplyScaleUint(raw, sf)
					socSeeded = true
				}
				// Effective simulation seconds per real tick includes speed factor.
				dtSim := tickInterval * s.Speed()
				capacityWh := wmaxKwh * 1000.0
				// Clamp the commanded power to the energy physically available so
				// the reported power matches what's delivered (see clampToSoC).
				w, socPct = clampToSoC(w, socPct, capacityWh, dtSim)
				soc = socPct
				socMu.Unlock()
			} else if ptr := pendingSoC.Load(); ptr != nil {
				// Free-running but operator has set an SoC: hold the injected
				// value (and keep the battery idle at whatever W the register
				// already shows) until the hub takes control.
				socMu.Lock()
				socPct = *ptr
				socSeeded = false
				soc = socPct
				socMu.Unlock()
				w = sunspec.ApplyScaleSigned(
					r.Get(m103Base+sunspec.M103_W),
					int16(r.Get(m103Base+sunspec.M103_W_SF)))
			} else {
				// Free-running: sinusoidal cycle; reset so next hub command re-seeds.
				soc = 55.0 + 35.0*math.Sin(phase)
				w = -wmaxW * 0.80 * math.Cos(phase)
				socMu.Lock()
				socPct = soc
				socSeeded = false
				socMu.Unlock()
			}

			v := 240.0 + 1.5*math.Sin(2*math.Pi*t/89)
			hz := 60.0 + 0.03*math.Sin(2*math.Pi*t/67)
			absW := math.Abs(w)
			tmp := 25.0 + 15.0*(absW/wmaxW)

			pf := math.Max(0.95, math.Min(0.9999, 0.98+0.015*math.Cos(phase)))
			va := absW / pf
			varPwr := va * math.Sin(math.Acos(pf))
			if w < 0 {
				varPwr = -varPwr
			}

			dcv := 44.0 + 6.0*(soc/100.0)
			dcw := absW * 1.03
			iph := absW / (v * 3)
			if w < 0 {
				iph = -iph
			}

			r.Set(m103Base+sunspec.M103_A, uint16(int16(math.Round(iph*3))))
			r.Set(m103Base+sunspec.M103_AphA, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_AphB, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_AphC, uint16(int16(math.Round(iph))))
			r.Set(m103Base+sunspec.M103_PhVphA, uint16(math.Round(v*10)))
			r.Set(m103Base+sunspec.M103_PhVphB, uint16(math.Round(v*10)))
			r.Set(m103Base+sunspec.M103_PhVphC, uint16(math.Round(v*10)))
			r.Set(m103Base+sunspec.M103_W, uint16(int16(math.Round(w))))
			r.Set(m103Base+sunspec.M103_Hz, uint16(math.Round(hz*100)))
			r.Set(m103Base+sunspec.M103_VA, uint16(int16(math.Round(va))))
			r.Set(m103Base+sunspec.M103_VAr, uint16(int16(math.Round(varPwr))))
			r.Set(m103Base+sunspec.M103_PF, uint16(int16(math.Round(pf*10000))))
			r.Set(m103Base+sunspec.M103_DCV, uint16(math.Round(dcv*10)))
			r.Set(m103Base+sunspec.M103_DCW, uint16(int16(math.Round(dcw))))
			r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(math.Round(tmp*10))))

			if absW < wmaxW*0.02 {
				r.Set(m103Base+sunspec.M103_St, 8)
			} else {
				r.Set(m103Base+sunspec.M103_St, 4)
			}

			r.Set(m802Base+uint16(sunspec.M802_SoC), uint16(math.Round(soc*100)))
			dod := 100.0 - soc
			r.Set(m802Base+uint16(sunspec.M802_DoD), uint16(math.Round(dod*100)))

			var chaSt uint16
			switch {
			case w > wmaxW*0.02:
				chaSt = 3
			case w < -wmaxW*0.02:
				chaSt = 4
			default:
				chaSt = 6
			}
			r.Set(m802Base+uint16(sunspec.M802_ChaSt), chaSt)
			r.Set(m802Base+uint16(sunspec.M802_State), 2)
		}
	}
}
