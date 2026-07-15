package sim

// meter.go — static single-phase AC meter simulator (SunSpec Model 201).
//
// Register layout (Models 1 → 201 → end):
//
//	40000–40001: SunS header
//	40002–40069: Model 1   (Common,              66 data regs)
//	40070–40176: Model 201 (Single-Phase Meter, 105 data regs)
//	40177–40178: end marker
//
// netW sign convention:
//
//	positive = site importing from grid  (utility is a source)
//	negative = site exporting to grid    (utility is a sink)
//
// Power registers (W, VA, VAR) use scale factor 1 (10 W resolution,
// ±327 670 W range) so large linked-mode sites don't wrap int16.

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"lexa-proto/sunspec"
)

// meterWSF is the scale factor for the meter's W/VA/VAR registers:
// raw × 10^1, i.e. 10 W resolution with a ±327 670 W range.
const meterWSF = int16(1)

// MeterServer is a running SunSpec AC meter simulator.
// It extends Server with a convenience method for changing the net power
// reading during tests.
type MeterServer struct {
	*Server
	// M201Base is the Modbus address of the first data register of Model 201.
	// Tests can write registers directly (W uses scale factor meterWSF):
	//   srv.Regs.Set(srv.M201Base+sunspec.M201_W, sunspec.RawFromScaleSigned(watts, 1))
	M201Base uint16

	// Energy accumulators (M201 TotWhImp/TotWhExp, finding MTR-2) — integrated
	// from net power on every SetNetW call.
	accMu    sync.Mutex
	accLast  time.Time
	totImpWh float64
	totExpWh float64

	// faults is the QA fault injector (POST /fault via simapi). Transport-layer
	// only — the meter is a read-only device, so all its faults live on the
	// Modbus read path; Snapshot/ground truth read the registers directly and
	// stay correct. See meterFaultKinds.
	faults faultController
}

// meterFaultKinds is the fault set the meter sim advertises: the transport
// faults every Modbus device can suffer, plus the meter-specific invert_sign
// (CT clamp installed backwards).
var meterFaultKinds = map[FaultKind]bool{
	FaultInvertSign:      true,
	FaultNanSentinel:     true,
	FaultLatency:         true,
	FaultModbusException: true,
}

// ApplyFault arms or clears a fault from a POST /fault body. Server-plumbing
// kinds (tcp_drop / unit_id_confusion / register_tearing) are handled first by
// the shared *Server; everything else is a register-level fault. See
// meterFaultKinds.
func (ms *MeterServer) ApplyFault(body []byte) error {
	if handled, err := ms.Server.applyServerFault(body); handled {
		return err
	}
	return ms.faults.apply(body, meterFaultKinds)
}

// NewMeterServer creates and starts a static single-phase AC meter simulator.
//
// netW is the initial net power (W):
//   - positive  → site is net importing
//   - negative  → site is net exporting
func NewMeterServer(listenURL string, netW float64) (*MeterServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	m201Base := populateMeter(regs, netW)
	srv, err := startServer(listenURL, regs)
	if err != nil {
		return nil, err
	}
	ms := &MeterServer{Server: srv, M201Base: m201Base}
	ms.faults.label = "meter"
	// invert_sign flips the signed instantaneous registers a backwards CT
	// reverses: real power, reactive power, and the current channels. (VA is
	// unsigned-magnitude and the energy accumulators keep counting on the wrong
	// side in a real install too — the instantaneous direction is the lie that
	// matters to a controller.)
	ms.faults.configureInvert(
		m201Base+sunspec.M201_W,
		m201Base+sunspec.M201_VAR,
		m201Base+sunspec.M201_A,
		m201Base+sunspec.M201_AphA,
	)
	regs.OnRead = ms.faults.transportRead
	return ms, nil
}

// SetNetW updates the W register so ReadMeasurements reflects a new reading.
// sf=1 → raw == tens of watts; valid range ±327 670 W (finding MTR-1: sf=0
// wrapped at ±32 767 W, reachable in linked mode with EV + load).
// Each call also integrates the reading into the TotWhImp/TotWhExp energy
// accumulators (callers update on a fixed tick, so power × elapsed = energy).
func (ms *MeterServer) SetNetW(netW float64) {
	ms.Regs.Set(ms.M201Base+uint16(sunspec.M201_W), sunspec.RawFromScaleSigned(netW, meterWSF))
	ms.Regs.Set(ms.M201Base+uint16(sunspec.M201_W_SF), uint16(meterWSF))
	writeDerivedPower(ms.Regs, ms.M201Base, netW)
	ms.accumulate(netW)
}

// writeDerivedPower refreshes the registers derived from net power: apparent
// power (fixed 0.95 PF model), reactive power, and current (from the live
// voltage register). Shared by populateMeter and SetNetW so VA/VAR/A track W
// instead of staying frozen at their startup values (caught by conformance
// check MTR-005: VA=0 while W=4 kW).
func writeDerivedPower(r *RegisterMap, m201Base uint16, netW float64) {
	const pf = 0.95
	va := math.Abs(netW) / pf
	r.Set(m201Base+sunspec.M201_VA, sunspec.RawFromScaleSigned(va, meterWSF))
	varPwr := netW * 0.329 // ≈ W × tan(acos(0.95))
	r.Set(m201Base+sunspec.M201_VAR, sunspec.RawFromScaleSigned(varPwr, meterWSF))

	v := sunspec.ApplyScaleUint(r.Get(m201Base+sunspec.M201_PhV), int16(r.Get(m201Base+sunspec.M201_V_SF)))
	if math.IsNaN(v) || v < 1 {
		v = 240.0
	}
	amps := uint16(int16(math.Round(netW / v)))
	r.Set(m201Base+sunspec.M201_A, amps)
	r.Set(m201Base+sunspec.M201_AphA, amps)
}

// accumulate integrates net power into the M201 energy accumulator registers.
// Positive net power counts as imported energy, negative as exported.
func (ms *MeterServer) accumulate(netW float64) {
	now := time.Now()
	ms.accMu.Lock()
	defer ms.accMu.Unlock()
	if !ms.accLast.IsZero() {
		dtH := now.Sub(ms.accLast).Hours()
		// Ignore long gaps (pause, clock step) — they aren't metered time.
		if dtH > 0 && dtH < 0.1 {
			if netW >= 0 {
				ms.totImpWh += netW * dtH
			} else {
				ms.totExpWh += -netW * dtH
			}
		}
	}
	ms.accLast = now
	ms.setAcc32(sunspec.M201_TotWhImp, uint32(ms.totImpWh))
	ms.setAcc32(sunspec.M201_TotWhExp, uint32(ms.totExpWh))
}

// setAcc32 writes a SunSpec acc32 value (most-significant word first).
func (ms *MeterServer) setAcc32(offset int, v uint32) {
	ms.Regs.Set(ms.M201Base+uint16(offset), uint16(v>>16))
	ms.Regs.Set(ms.M201Base+uint16(offset)+1, uint16(v))
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

// MeterState is the JSON-serialisable snapshot for GET /state.
type MeterState struct {
	Type      string    `json:"type"` // "grid_meter" or "home_load"
	Timestamp time.Time `json:"timestamp"`
	Animation struct {
		Paused bool    `json:"paused"`
		Speed  float64 `json:"speed"`
	} `json:"animation"`
	Measurements struct {
		W_W         float64 `json:"W_W"`
		V_V         float64 `json:"V_V"`
		Hz_Hz       float64 `json:"Hz_Hz"`
		VA_VA       float64 `json:"VA_VA"`
		PF          float64 `json:"PF"`
		A_A         float64 `json:"A_A"`
		TotWhImp_Wh float64 `json:"TotWhImp_Wh"`
		TotWhExp_Wh float64 `json:"TotWhExp_Wh"`
	} `json:"measurements"`
}

// Snapshot returns the decoded current state.
// simType should be "grid_meter" or "home_load".
func (ms *MeterServer) Snapshot(simType string) MeterState {
	r := ms.Regs
	b := ms.M201Base

	sf := func(offset int) int16 { return int16(r.Get(b + uint16(offset))) }
	signed := func(offset, sfOffset int) float64 {
		return sunspec.ApplyScaleSigned(r.Get(b+uint16(offset)), sf(sfOffset))
	}
	unsigned := func(offset, sfOffset int) float64 {
		return sunspec.ApplyScaleUint(r.Get(b+uint16(offset)), sf(sfOffset))
	}

	var st MeterState
	st.Type = simType
	st.Timestamp = time.Now()
	st.Animation.Paused = ms.IsPaused()
	st.Animation.Speed = ms.Speed()

	m := &st.Measurements
	m.W_W = signed(sunspec.M201_W, sunspec.M201_W_SF)
	m.V_V = unsigned(sunspec.M201_PhV, sunspec.M201_V_SF)
	m.Hz_Hz = unsigned(sunspec.M201_Hz, sunspec.M201_Hz_SF)
	m.VA_VA = signed(sunspec.M201_VA, sunspec.M201_VA_SF)
	m.PF = signed(sunspec.M201_PF, sunspec.M201_PF_SF) / 100.0
	m.A_A = signed(sunspec.M201_A, sunspec.M201_A_SF)
	acc32 := func(offset int) float64 {
		hi := uint32(r.Get(b + uint16(offset)))
		lo := uint32(r.Get(b + uint16(offset) + 1))
		return float64(hi<<16 | lo)
	}
	m.TotWhImp_Wh = acc32(sunspec.M201_TotWhImp)
	m.TotWhExp_Wh = acc32(sunspec.M201_TotWhExp)

	return st
}

// Registers returns a sparse map of non-zero register values.
func (ms *MeterServer) Registers() map[string]uint16 {
	out := make(map[string]uint16)
	base := uint16(sunspec.SunSpecBase)
	for addr := base; addr <= base+178; addr++ {
		v := ms.Regs.Get(addr)
		if v != 0 {
			out[fmt.Sprintf("%d", addr)] = v
		}
	}
	return out
}

// Inject overrides one or more meter fields.
// Accepted keys: "W_W", "V_V", "Hz_Hz".
func (ms *MeterServer) Inject(body []byte) error {
	var fields map[string]float64
	if err := json.Unmarshal(body, &fields); err != nil {
		return fmt.Errorf("inject: %w", err)
	}
	r := ms.Regs
	b := ms.M201Base

	for key, val := range fields {
		switch key {
		case "W_W":
			r.Set(b+uint16(sunspec.M201_W),
				sunspec.RawFromScaleSigned(val, int16(r.Get(b+uint16(sunspec.M201_W_SF)))))
		case "V_V":
			r.Set(b+uint16(sunspec.M201_PhV), uint16(math.Round(val*10)))
			r.Set(b+uint16(sunspec.M201_PhVphA), uint16(math.Round(val*10)))
		case "Hz_Hz":
			r.Set(b+uint16(sunspec.M201_Hz), uint16(math.Round(val*100)))
		default:
			return fmt.Errorf("inject: unknown field %q", key)
		}
	}
	return nil
}

// populateMeter writes the SunSpec header, Model 1, and Model 201 into r.
// Returns the Modbus address of the first Model 201 data register.
func populateMeter(r *RegisterMap, netW float64) uint16 {
	sfN := func(v int16) uint16 { return uint16(v) }
	base := sunspec.SunSpecBase

	// SunS header
	r.Set(base+0, sunspec.SunSMagic0)
	r.Set(base+1, sunspec.SunSMagic1)
	cursor := base + 2

	// Model 1 (Common) — 66 data registers
	const m1Len = 66
	r.Set(cursor, sunspec.ModelCommon)
	r.Set(cursor+1, m1Len)
	m1 := cursor + 2
	setStr16(r, m1+0, "SunSpec Sim")
	setStr8(r, m1+16, "CSIP-Meter-1Ph")
	setStr8(r, m1+32, "SN-MTR-001")
	cursor += 2 + m1Len

	// Model 201 (Single-Phase AC Meter) — 105 data registers
	r.Set(cursor, sunspec.ModelMeterSinglePh)
	r.Set(cursor+1, sunspec.M201Len)
	m201Base := cursor + 2

	// Voltage: 2400 × 10^-1 = 240.0 V
	r.Set(m201Base+sunspec.M201_PhV, 2400)
	r.Set(m201Base+sunspec.M201_PhVphA, 2400)
	r.Set(m201Base+sunspec.M201_V_SF, sfN(-1))

	// Frequency: 6000 × 10^-2 = 60.00 Hz
	r.Set(m201Base+sunspec.M201_Hz, 6000)
	r.Set(m201Base+sunspec.M201_Hz_SF, sfN(-2))

	// Net power (sf=1 → raw == tens of watts, range ±327 670 W)
	r.Set(m201Base+sunspec.M201_W, sunspec.RawFromScaleSigned(netW, meterWSF))
	r.Set(m201Base+sunspec.M201_W_SF, uint16(meterWSF))

	// Scale factors for the derived registers (values via writeDerivedPower).
	r.Set(m201Base+sunspec.M201_VA_SF, uint16(meterWSF))
	r.Set(m201Base+sunspec.M201_VAR_SF, uint16(meterWSF))
	r.Set(m201Base+sunspec.M201_A_SF, 0) // whole amps

	// Power factor: 9500 × 10^-2 = 0.9500
	r.Set(m201Base+sunspec.M201_PF, uint16(int16(9500)))
	r.Set(m201Base+sunspec.M201_PF_SF, sfN(-2))

	// Apparent/reactive power and current derived from netW.
	writeDerivedPower(r, m201Base, netW)

	// Energy accumulators start at zero; raw Wh (sf=0).
	r.Set(m201Base+sunspec.M201_TotWh_SF, 0)

	cursor += 2 + sunspec.M201Len

	// End marker
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)

	return m201Base
}
