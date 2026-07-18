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
	"encoding/json"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"lexa-proto/sunspec"
)

// SolarBases holds the first data-register address of each model block
// so that Snapshot, Inject, and the SF write-protection (protect.go) can
// locate registers without re-scanning.
type SolarBases struct {
	M120Base uint16 // Model 120 (Nameplate) data start
	M121Base uint16 // Model 121 (Basic Settings) data start
	M122Base uint16 // Model 122 (Extended Measurements) data start
	M103Base uint16 // Model 103 (Three-Phase Inverter) data start
	M123Base uint16 // Model 123 (Immediate Controls) data start
}

// SolarServer is an animated PV inverter simulator with a built-in API.
// It embeds *Server so callers can call srv.Stop(), srv.Regs, srv.Pause(), etc.
type SolarServer struct {
	*Server
	bases  SolarBases
	wmaxW  float64
	faults faultController // shared fault-injection state (see faults.go)

	// cloudCover is the current cloud-cover fraction (0=clear .. 1=overcast),
	// held as math.Float64bits for lock-free concurrent access: the HTTP
	// goroutine writes it via SetCloud (Inject "Cloud_pct" / modsim -cloud-pct),
	// the animation goroutine reads it via Cloud() each tick. It scales the
	// clear-sky irradiance through cloudTransmittance in the RUNNING branch only;
	// the zero value (clear sky) makes cloudTransmittance return exactly 1.0, so a
	// sim that is never clouded is byte-identical to the pre-cloud model.
	cloudCover atomic.Uint64

	// Advanced-DER (7xx) surface — populated only by NewSolarServerAdvanced.
	// When advanced is false the sim serves the legacy models only and behaves
	// exactly as today (see solar_adv.go).
	advanced  bool
	adv       solarAdvBases
	varRating float64 // reactive rating (var) — 702 VarMaxInj / fixed-var effect base
}

// solarFaultKinds is the set of POST /fault kinds the solar sim advertises.
var solarFaultKinds = map[FaultKind]bool{
	FaultAckBeforeEffect: true,
	FaultRejectWrite:     true,
	FaultEnableGate:      true,
	FaultRampLimit:       true,
	FaultNanSentinel:     true,
	FaultLatency:         true,
	FaultModbusException: true,
	FaultBadScale:        true,
}

// NewSolarServer creates and starts an animated PV inverter simulator.
// wmaxW is the nameplate peak power in watts. serial overrides the SunSpec
// Model 1 serial (SN) register when non-empty; empty keeps the historical
// "SN-SOLAR-001" default (see solarSerialOrDefault) — lets two co-located
// sims (e.g. modsim + mbapsdev -model inverter) present distinct device
// identity to a downstream gateway that keys identity on
// manufacturer|model|serial.
func NewSolarServer(listenURL string, wmaxW float64, serial string) (*SolarServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	bases := populateSolar(regs, wmaxW, serial)

	// Allocate ss first so the animation closure can shape output through its
	// faultController (the effect-time ramp_limit fault).
	ss := &SolarServer{bases: bases, wmaxW: wmaxW}
	ss.faults.label = "solar"
	ss.faults.configureGate(bases.M123Base + sunspec.M123_WMaxLimPct_Ena)
	ss.faults.configureScale(bases.M103Base + sunspec.M103_W_SF)

	srv, err := newAnimatedServer(listenURL, regs, func(s *Server, r *RegisterMap, stop <-chan struct{}) {
		animateSolar(s, r, wmaxW, bases, ss.Cloud, &ss.faults, stop)
	})
	if err != nil {
		return nil, err
	}
	ss.Server = srv
	regs.OnWriteAttempt = ss.interceptWrite
	regs.OnRead = ss.faults.transportRead
	return ss, nil
}

// solarCeilingW is the single source of truth for the output ceiling (W) the
// inverter honours this update: the hub's WMaxLimPct limit when enabled (else
// full nameplate), shaped by any effect-time fault. fc may be nil (no effect
// faults). Both Inject and solarStep use it so the commanded limit, the device's
// physical response, and the meter-visible output never diverge.
func solarCeilingW(r *RegisterMap, bases SolarBases, wmaxW float64, fc *faultController) float64 {
	limW := wmaxW
	if r.Get(bases.M123Base+sunspec.M123_WMaxLimPct_Ena) != 0 {
		limPct := sunspec.ApplyScaleSigned(
			r.Get(bases.M123Base+sunspec.M123_WMaxLimPct),
			int16(r.Get(bases.M123Base+sunspec.M123_WMaxLimPct_SF)),
		)
		limW = wmaxW * math.Max(0, limPct) / 100.0
	}
	if fc != nil {
		limW = fc.effectiveCeilW(limW)
	}
	return limW
}

// interceptWrite is the RegisterMap.OnWriteAttempt hook. It delegates to the
// shared faultController, which acts on the inverter's WMaxLimPct control
// register (see faults.go). With no fault armed it is a pass-through. On an
// advanced sim it first offers the write to the 7xx curve-adopt handler (a
// write to a curve model's AdptCrvReq/AdptCtlReq register triggers the SunSpec
// §3.1.2 adopt, see solar_adv.go).
func (ss *SolarServer) interceptWrite(startAddr uint16, vals []uint16) bool {
	if ss.advanced && ss.interceptAdopt(startAddr, vals) {
		return false // the adopt handler took responsibility for this write
	}
	cmdAddr := ss.bases.M123Base + sunspec.M123_WMaxLimPct
	return ss.faults.intercept(ss.Regs, cmdAddr, startAddr, vals)
}

// ApplyFault arms or clears a fault for this sim. It is wired to simapi's
// POST /fault. Body is a FaultSpec JSON object. A legacy sim advertises
// solarFaultKinds; an advanced sim additionally advertises the 7xx kinds
// (raise_alarm / curve_adopt_lies / pf_ack_ignore).
func (ss *SolarServer) ApplyFault(body []byte) error {
	// Server-plumbing kinds (tcp_drop / unit_id_confusion / register_tearing)
	// are handled first by the shared *Server; everything else is a
	// register-level fault handled by the faultController.
	if handled, err := ss.Server.applyServerFault(body); handled {
		return err
	}
	kinds := solarFaultKinds
	if ss.advanced {
		kinds = solarAdvFaultKinds
	}
	return ss.faults.apply(body, kinds)
}

// newAnimatedServer launches the Modbus TCP server and a single animation
// goroutine.  fn receives the Server (for Pause/Resume/Speed access), the
// register map, and a stop channel; it must return when stop is closed.
func newAnimatedServer(listenURL string, regs *RegisterMap, fn func(*Server, *RegisterMap, <-chan struct{})) (*Server, error) {
	s, err := startServerRaw(listenURL, regs)
	if err != nil {
		return nil, err
	}
	go func() {
		defer close(s.done)
		fn(s, s.Regs, s.stop)
	}()
	return s, nil
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

// SolarState is the JSON-serialisable snapshot returned by GET /state.
type SolarState struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Animation struct {
		Paused bool    `json:"paused"`
		Speed  float64 `json:"speed"`
	} `json:"animation"`
	Nameplate struct {
		WMaxW float64 `json:"wmax_W"`
	} `json:"nameplate"`
	Measurements struct {
		W_W        float64 `json:"W_W"`
		Possible_W float64 `json:"possible_W"` // pre-curtailment potential (M122 WAval)
		Cloud_pct  float64 `json:"Cloud_pct"`  // live cloud cover 0–100% (attenuates Possible_W)
		V_V        float64 `json:"V_V"`
		Hz_Hz      float64 `json:"Hz_Hz"`
		VA_VA      float64 `json:"VA_VA"`
		VAr_var    float64 `json:"VAr_var"`
		PF         float64 `json:"PF"`
		DCV_V      float64 `json:"DCV_V"`
		DCW_W      float64 `json:"DCW_W"`
		TmpCab_C   float64 `json:"TmpCab_C"`
		St         int     `json:"St"`
		StText     string  `json:"St_text"`
	} `json:"measurements"`
	Controls struct {
		WMaxLimPct_pct float64 `json:"WMaxLimPct_pct"`
		WMaxLimPctEna  int     `json:"WMaxLimPct_Ena"`
		Conn           int     `json:"Conn"`
	} `json:"controls"`

	// SFWriteRejects counts Modbus write cells that tried to CHANGE a
	// write-protected scale-factor register and were masked (protect.go).
	// Nonzero means something wrote over SF cells — the observable trace of
	// the E1 write-back-poisoning vector.
	SFWriteRejects uint64 `json:"sf_write_rejects"`

	// Advanced is the 7xx (IEEE 1547-2018) ground truth, present only on an
	// advanced sim. Nil on a legacy sim, so /state is unchanged there.
	Advanced *SolarAdvancedState `json:"advanced,omitempty"`
}

// Snapshot reads the current register state and returns a decoded SolarState.
func (ss *SolarServer) Snapshot() SolarState {
	r := ss.Regs
	b := ss.bases

	sf := func(addr uint16) int16 { return int16(r.Get(addr)) }
	signed := func(addr, sfAddr uint16) float64 {
		return sunspec.ApplyScaleSigned(r.Get(addr), sf(sfAddr))
	}
	unsigned := func(addr, sfAddr uint16) float64 {
		return sunspec.ApplyScaleUint(r.Get(addr), sf(sfAddr))
	}

	var st SolarState
	st.Type = "solar"
	st.Timestamp = time.Now()
	st.Animation.Paused = ss.IsPaused()
	st.Animation.Speed = ss.Speed()
	st.Nameplate.WMaxW = ss.wmaxW

	m := &st.Measurements
	m.W_W = signed(b.M103Base+sunspec.M103_W, b.M103Base+sunspec.M103_W_SF)
	// Possible_W is the panel's pre-curtailment potential (WAval). Reading it
	// from the same register snapshot as W_W lets a sampler compute curtailment
	// (possible − actual) coherently, with no chance of actual > possible.
	m.Possible_W = signed(b.M122Base+sunspec.M122_WAval, b.M122Base+sunspec.M122_WAval_SF)
	// Cloud cover is server state (not a register): expose it as a percent so the
	// dashboard can display the live weather the running animation is applying.
	m.Cloud_pct = ss.Cloud() * 100.0
	m.V_V = unsigned(b.M103Base+sunspec.M103_PhVphA, b.M103Base+sunspec.M103_V_SF)
	m.Hz_Hz = unsigned(b.M103Base+sunspec.M103_Hz, b.M103Base+sunspec.M103_Hz_SF)
	m.VA_VA = signed(b.M103Base+sunspec.M103_VA, b.M103Base+sunspec.M103_VA_SF)
	m.VAr_var = signed(b.M103Base+sunspec.M103_VAr, b.M103Base+sunspec.M103_VAr_SF)
	m.PF = signed(b.M103Base+sunspec.M103_PF, b.M103Base+sunspec.M103_PF_SF) / 100.0
	m.DCV_V = unsigned(b.M103Base+sunspec.M103_DCV, b.M103Base+sunspec.M103_DCV_SF)
	m.DCW_W = signed(b.M103Base+sunspec.M103_DCW, b.M103Base+sunspec.M103_DCW_SF)
	m.TmpCab_C = signed(b.M103Base+sunspec.M103_TmpCab, b.M103Base+sunspec.M103_Tmp_SF)
	m.St = int(r.Get(b.M103Base + sunspec.M103_St))
	m.StText = solarStateText(m.St)

	c := &st.Controls
	c.WMaxLimPct_pct = signed(b.M123Base+sunspec.M123_WMaxLimPct, b.M123Base+sunspec.M123_WMaxLimPct_SF) / 100.0
	c.WMaxLimPctEna = int(r.Get(b.M123Base + sunspec.M123_WMaxLimPct_Ena))
	c.Conn = int(r.Get(b.M123Base + sunspec.M123_Conn))

	st.SFWriteRejects = r.ProtectedRejects()

	if ss.advanced {
		st.Advanced = ss.advSnapshot()
	}

	return st
}

// Registers returns the raw SunSpec register contents for the debug panel.
// Returns a map of "decimal_address" → uint16 value covering all model blocks.
func (ss *SolarServer) Registers() map[string]uint16 {
	out := make(map[string]uint16)
	base := uint16(sunspec.SunSpecBase)
	// Cover the legacy solar layout (40000–40254); on an advanced sim the 7xx
	// models extend past that, so widen the window to the recorded end.
	end := base + 254
	if ss.advanced && ss.adv.End > end {
		end = ss.adv.End
	}
	for addr := base; addr <= end; addr++ {
		v := ss.Regs.Get(addr)
		if v != 0 {
			out[fmt.Sprintf("%d", addr)] = v
		}
	}
	return out
}

// SetCloud sets the cloud-cover fraction, clamped to [0,1]: 0 is clear sky
// (byte-identical to a cloud-free sim), 1 is full overcast. Safe to call from
// the HTTP goroutine (Inject "Cloud_pct", modsim -cloud-pct) while the animation
// goroutine reads the value via Cloud().
func (ss *SolarServer) SetCloud(frac float64) {
	if frac < 0 || math.IsNaN(frac) {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	ss.cloudCover.Store(math.Float64bits(frac))
}

// Cloud returns the current cloud-cover fraction (0..1).
func (ss *SolarServer) Cloud() float64 {
	return math.Float64frombits(ss.cloudCover.Load())
}

// Inject overrides one or more measurement or control fields.
// Accepted JSON keys: "W_W", "V_V", "Hz_Hz", "DCV_V", "TmpCab_C",
// "WMaxLimPct_pct" (0–100), "Conn" (0 or 1), "St" (1–8), "Cloud_pct" (0–100).
//
// "Cloud_pct" is not a register — it is an environmental input (like metersim's
// LoadW_W) that scales the running-animation irradiance via cloudTransmittance;
// it takes effect on the next animation tick and is unaffected by pause.
//
// Calling Inject does not automatically pause the animation; use
// POST /control {"cmd":"pause"} first if you want values to persist.
func (ss *SolarServer) Inject(body []byte) error {
	var fields map[string]float64
	if err := json.Unmarshal(body, &fields); err != nil {
		return fmt.Errorf("inject: %w", err)
	}
	r := ss.Regs
	b := ss.bases
	sf := func(addr uint16) int16 { return int16(r.Get(addr)) }

	for key, val := range fields {
		switch key {
		case "W_W":
			// Record the injected value as the panel POTENTIAL (available power)
			// so a paused animation re-applies WMaxLimPct curtailment to it.
			// Replay mode pauses the sim and injects PV each tick; without this
			// the held output would ignore the hub's curtailment commands.
			r.Set(b.M122Base+sunspec.M122_WAval, uint16(int16(math.Round(val))))
			// Write the live output as the CURTAILED value (potential clipped by
			// the honoured ceiling — WMaxLimPct shaped by any effect-time fault),
			// not the raw potential.  Writing the full potential here would briefly
			// expose an uncurtailed reading between the inject and the next
			// animation tick — which the linked meter can sample, spiking export
			// over an active cap for one tick.
			w := math.Min(val, solarCeilingW(r, b, ss.wmaxW, &ss.faults))
			r.Set(b.M103Base+sunspec.M103_W,
				sunspec.RawFromScaleSigned(w, sf(b.M103Base+sunspec.M103_W_SF)))
		case "V_V":
			v10 := uint16(math.Round(val * 10))
			r.Set(b.M103Base+sunspec.M103_PhVphA, v10)
			r.Set(b.M103Base+sunspec.M103_PhVphB, v10)
			r.Set(b.M103Base+sunspec.M103_PhVphC, v10)
		case "Hz_Hz":
			r.Set(b.M103Base+sunspec.M103_Hz,
				sunspec.RawFromScaleUint(val, sf(b.M103Base+sunspec.M103_Hz_SF)))
		case "DCV_V":
			r.Set(b.M103Base+sunspec.M103_DCV,
				sunspec.RawFromScaleUint(val, sf(b.M103Base+sunspec.M103_DCV_SF)))
		case "TmpCab_C":
			r.Set(b.M103Base+sunspec.M103_TmpCab,
				sunspec.RawFromScaleSigned(val, sf(b.M103Base+sunspec.M103_Tmp_SF)))
		case "WMaxLimPct_pct":
			r.Set(b.M123Base+sunspec.M123_WMaxLimPct,
				sunspec.RawFromScaleSigned(val*100, sf(b.M123Base+sunspec.M123_WMaxLimPct_SF)))
		case "Conn":
			r.Set(b.M123Base+sunspec.M123_Conn, uint16(val))
		case "St":
			r.Set(b.M103Base+sunspec.M103_St, uint16(val))
		case "Cloud_pct":
			// Environmental input, not a register: 0..100% → SetCloud [0,1]
			// (clamped). The running animation reads it via cloudTransmittance.
			ss.SetCloud(val / 100.0)
		default:
			return fmt.Errorf("inject: unknown field %q", key)
		}
	}
	// Keep the 701 measurement model coherent with the injected 103 state (and
	// re-apply any active 704 PF/var effect) so a paused, inject-driven advanced
	// sim reports through 701 what the hub will read.
	if ss.advanced {
		ss.advSync()
	}
	return nil
}

func solarStateText(st int) string {
	switch st {
	case 1:
		return "off"
	case 2:
		return "sleeping"
	case 3:
		return "starting"
	case 4:
		return "MPPT"
	case 5:
		return "throttled"
	case 6:
		return "shutting_down"
	case 7:
		return "fault"
	case 8:
		return "standby"
	default:
		return fmt.Sprintf("unknown(%d)", st)
	}
}

// ── populate ──────────────────────────────────────────────────────────────────

// populateSolar writes the full legacy solar inverter register layout into r
// and returns the data-start addresses for each model block. serial overrides
// the Model 1 SN register when non-empty (empty keeps the historical default
// — see solarSerialOrDefault).
func populateSolar(r *RegisterMap, wmaxW float64, serial string) SolarBases {
	bases, cursor := populateSolarCore(r, wmaxW, serial)
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	return bases
}

// defaultSolarSerial is the SunSpec Model 1 serial (SN) a solar sim reports
// when no override is given — the original hardcoded value, kept as the
// default so every pre-existing caller/test stays byte-identical.
const defaultSolarSerial = "SN-SOLAR-001"

// solarSerialOrDefault returns serial if non-empty, else defaultSolarSerial.
// Threaded through populateSolar/populateSolarCore/populateSolarAdvanced so
// NewSolarServer/NewSolarServerAdvanced (and modsim/mbapsdev's -serial flag)
// can give two co-located sims distinct SunSpec device identity — a
// downstream gateway that keys device identity on manufacturer|model|serial
// otherwise dedupes them into one device.
func solarSerialOrDefault(serial string) string {
	if serial == "" {
		return defaultSolarSerial
	}
	return serial
}

// populateSolarCore writes the legacy solar models (1/120/121/122/103/123) into
// r and returns the model bases plus the cursor positioned at the end-of-list
// slot (where either the SunS end marker or the advanced 7xx models follow).
// Split out of populateSolar so the advanced sim can append 7xx models before
// the end marker without duplicating the legacy layout. serial overrides the
// Model 1 SN register when non-empty (see solarSerialOrDefault).
func populateSolarCore(r *RegisterMap, wmaxW float64, serial string) (SolarBases, uint16) {
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
	setStr8(r, m1+32, solarSerialOrDefault(serial))
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
	r.Set(m120+sunspec.M120_PFRtgQ1, uint16(int16(9500)))
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
	m121Base := cursor + 2
	r.Set(m121Base+sunspec.M121_WMax, uint16(wmaxW))
	r.Set(m121Base+sunspec.M121_WMax_SF, 0)
	cursor += 2 + m121Len

	// Model 122 (Extended Measurements) — 44 data regs
	r.Set(cursor, uint16(122))
	r.Set(cursor+1, sunspec.M122Len)
	m122Base := cursor + 2
	r.Set(m122Base+sunspec.M122_ECPConn, 1)
	r.Set(m122Base+sunspec.M122_PVConn, 1)
	r.Set(m122Base+sunspec.M122_WAval, uint16(wmaxW))
	r.Set(m122Base+sunspec.M122_WAval_SF, 0)
	cursor += 2 + sunspec.M122Len

	// Model 103 (Three-Phase Inverter) — 50 data regs
	const m103Len = 50
	r.Set(cursor, sunspec.ModelInverterThreePh)
	r.Set(cursor+1, m103Len)
	m103Base := cursor + 2
	r.Set(m103Base+sunspec.M103_W, uint16(int16(3000)))
	r.Set(m103Base+sunspec.M103_W_SF, 0)
	r.Set(m103Base+sunspec.M103_PhVphA, 2400)
	r.Set(m103Base+sunspec.M103_PhVphB, 2400)
	r.Set(m103Base+sunspec.M103_PhVphC, 2400)
	r.Set(m103Base+sunspec.M103_V_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_Hz, 6000)
	r.Set(m103Base+sunspec.M103_Hz_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_VA, uint16(int16(3100)))
	r.Set(m103Base+sunspec.M103_VA_SF, 0)
	r.Set(m103Base+sunspec.M103_VAr, uint16(int16(650)))
	r.Set(m103Base+sunspec.M103_VAr_SF, 0)
	r.Set(m103Base+sunspec.M103_PF, uint16(int16(9677)))
	r.Set(m103Base+sunspec.M103_PF_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_DCV, 3800)
	r.Set(m103Base+sunspec.M103_DCV_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_DCW, uint16(int16(3180)))
	r.Set(m103Base+sunspec.M103_DCW_SF, 0)
	r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(470)))
	r.Set(m103Base+sunspec.M103_Tmp_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_St, 4)
	cursor += 2 + m103Len

	// Model 123 (Immediate Controls) — 23 data regs
	const m123Len = 23
	r.Set(cursor, sunspec.ModelImmediateCtrl)
	r.Set(cursor+1, m123Len)
	m123Base := cursor + 2
	r.Set(m123Base+sunspec.M123_WMaxLimPct, 10000)
	r.Set(m123Base+sunspec.M123_WMaxLimPct_Ena, 1)
	r.Set(m123Base+sunspec.M123_WMaxLimPct_SF, sfN(-2))
	r.Set(m123Base+sunspec.M123_Conn, 1)
	cursor += 2 + m123Len

	bases := SolarBases{
		M120Base: m120,
		M121Base: m121Base,
		M122Base: m122Base,
		M103Base: m103Base,
		M123Base: m123Base,
	}
	// SF registers are read-only on a real device: mask Modbus writes to them
	// so a bad hub write-back is an observable divergence, not silent
	// corruption (audit E1; see protect.go).
	protectSolarLegacySFs(r, bases)
	return bases, cursor
}

// ── animation ─────────────────────────────────────────────────────────────────

func animateSolar(s *Server, r *RegisterMap, wmaxW float64, bases SolarBases, cloud func() float64, fc *faultController, stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	var whAcc uint16

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			// cloud() reads the live cover each tick so an /inject Cloud_pct takes
			// effect on the next step (paused steps ignore it — see solarStep).
			solarStep(r, wmaxW, bases, s.IsPaused(), s.simTime(), cloud(), fc, &whAcc)
		}
	}
}

// cloudTransmittance returns the fraction of clear-sky irradiance that reaches
// the panel under cloud cover (0=clear .. 1=overcast) at simulation time t. It
// is deterministic and downward-only: the result lies in
// [Tsus·(1−DIPMAX), Tsus], where Tsus = 1 − cloud·(1−DF) is the sustained
// overcast attenuation (1.0 at clear sky, DF=0.15 — the diffuse floor a panel
// still sees under a thick deck — at full overcast).
//
// A "broken cloud" weight (4·cloud·(1−cloud), peaking at cloud=0.5) gates
// occasional deeper transient dips driven by a quasi-random, non-repeating sum
// of three incommensurate sinusoids, so partly-cloudy skies flicker while clear
// (cloud=0) and fully-overcast (cloud=1) skies are steady. cloud=0 returns
// exactly 1.0 for every t — so composing it into the irradiance model is
// byte-identical to the cloud-free sim — and cloud=1 returns exactly Tsus (=DF)
// with no transient.
//
// t shares the animation's simTime base (Unix seconds × speed), so cloud
// transients pass ~10× faster at 10× bench speed, matching the irradiance cycle.
func cloudTransmittance(simTime int64, cloud float64) float64 {
	if cloud <= 0 {
		return 1.0 // clear sky: exact 1.0 keeps potW byte-identical to pre-cloud
	}
	if cloud > 1 {
		cloud = 1
	}
	const (
		df     = 0.15 // diffuse floor: fraction still reaching the panel at full overcast
		dipMax = 0.7  // deepest transient dip, as a fraction of Tsus, under broken cloud
	)
	tsus := 1 - cloud*(1-df)          // sustained overcast attenuation
	broken := 4 * cloud * (1 - cloud) // "broken cloud" weight, peaks at cloud=0.5
	t := float64(simTime)
	u := (math.Sin(2*math.Pi*t/23) + math.Sin(2*math.Pi*t/37) + math.Sin(2*math.Pi*t/51)) / 3
	gust := math.Max(0, u-0.55) / 0.45 // mostly 0; occasional 0..1 spikes
	dip := dipMax * broken * math.Max(0, math.Min(1, gust))
	return tsus * (1 - dip)
}

// solarStep advances the inverter registers by one animation tick.  It is split
// out of animateSolar so the curtailment/pause behaviour can be unit-tested
// without waiting on the 5 s ticker.
//
// When paused it HOLDS the last injected potential (WAval) and freezes the
// time-varying environment, but still applies the hub's WMaxLimPct — the
// property the bench replay depends on, since the replay pauses this sim and
// injects PV each tick while expecting curtailment to take effect.
//
// cloud (0..1) attenuates the clear-sky irradiance in the RUNNING branch only,
// via cloudTransmittance; the paused branch is deliberately untouched so
// replay/mayhem HOLD-injected potentials stay byte-identical. cloud=0 is a
// no-op (cloudTransmittance returns exactly 1.0).
func solarStep(r *RegisterMap, wmaxW float64, bases SolarBases, paused bool, simTime float64, cloud float64, fc *faultController, whAcc *uint16) {
	m103Base := bases.M103Base
	m122Base := bases.M122Base
	m123Base := bases.M123Base

	// Disconnect (M123 Conn=0) zeroes output in BOTH running and paused modes: a
	// cease-to-energize command must take effect even when the environment
	// animation is frozen (replay injects PV each tick with the sim paused).
	if r.Get(m123Base+sunspec.M123_Conn) == 0 {
		r.Set(m103Base+sunspec.M103_W, 0)
		r.Set(m103Base+sunspec.M103_VA, 0)
		r.Set(m103Base+sunspec.M103_VAr, 0)
		r.Set(m103Base+sunspec.M103_St, 1) // off
		r.Set(m122Base+sunspec.M122_WAval, 0)
		return
	}

	// potW is the panel's potential (pre-curtailment) output.
	//   running → the irradiance model drives potW and the time-varying
	//             environment registers (V, Hz, DCV).
	//   paused  → HOLD the last injected potential (stored in WAval) and freeze
	//             the environment, but still fall through to the WMaxLimPct clip
	//             below.  Without this a paused inverter ignores the hub's
	//             curtailment and reports the raw injected value — making
	//             replay-mode curtailment inert (the meter fetches this register
	//             to compute net grid).
	var potW, v, pf float64
	if paused {
		potW = float64(int16(r.Get(m122Base + sunspec.M122_WAval)))
		v = float64(r.Get(m103Base+sunspec.M103_PhVphA)) / 10.0
		pf = float64(int16(r.Get(m103Base+sunspec.M103_PF))) / 10000.0
	} else {
		t := simTime
		irr := math.Max(0.05, math.Min(0.95, 0.5+0.45*math.Sin(2*math.Pi*t/600)))
		// Cloud cover scales the clear-sky potential (downward-only). cloud=0 ⇒
		// cloudTransmittance == 1.0, so potW is byte-identical to the pre-cloud
		// model. WAval/possible_W (below) therefore honestly reflect the
		// cloud-reduced available power, and WMaxLimPct still clips actual ≤ this.
		potW = wmaxW * irr * cloudTransmittance(int64(t), cloud)
		v = 240.0 + 2.0*math.Sin(2*math.Pi*t/73)
		hz := 60.0 + 0.05*math.Sin(2*math.Pi*t/47)
		pf = math.Max(0.90, math.Min(0.99, 0.97+0.02*math.Sin(2*math.Pi*t/120)))
		dcv := 380.0 + 30.0*math.Sin(2*math.Pi*t/600)
		r.Set(m103Base+sunspec.M103_PhVphA, uint16(math.Round(v*10)))
		r.Set(m103Base+sunspec.M103_PhVphB, uint16(math.Round(v*10)))
		r.Set(m103Base+sunspec.M103_PhVphC, uint16(math.Round(v*10)))
		r.Set(m103Base+sunspec.M103_PPVphAB, uint16(math.Round(v*10*math.Sqrt(3))))
		r.Set(m103Base+sunspec.M103_PPVphBC, uint16(math.Round(v*10*math.Sqrt(3))))
		r.Set(m103Base+sunspec.M103_PPVphCA, uint16(math.Round(v*10*math.Sqrt(3))))
		r.Set(m103Base+sunspec.M103_Hz, uint16(math.Round(hz*100)))
		r.Set(m103Base+sunspec.M103_DCV, uint16(math.Round(dcv*10)))
	}
	if v <= 0 {
		v = 240.0
	}
	if pf <= 0 {
		pf = 0.97
	}

	// WAval is the available (uncurtailed) potential.
	r.Set(m122Base+sunspec.M122_WAval, uint16(int16(math.Round(potW))))

	// Clip the potential to the honoured ceiling — the hub's WMaxLimPct (when
	// enabled) shaped by any effect-time fault (ramp_limit) — in both running and
	// paused modes, so the hub can curtail a held value and a slewing device
	// ramps toward it.
	w := math.Min(potW, solarCeilingW(r, bases, wmaxW, fc))

	// Power-derived registers (depend on the curtailed w).
	va := w / pf
	varPwr := va * math.Sin(math.Acos(pf))
	tmp := 35.0 + 20.0*(w/wmaxW)
	dcw := w * 1.06
	iph := w / (v * 3)

	r.Set(m103Base+sunspec.M103_A, uint16(int16(math.Round(iph*3))))
	r.Set(m103Base+sunspec.M103_AphA, uint16(int16(math.Round(iph))))
	r.Set(m103Base+sunspec.M103_AphB, uint16(int16(math.Round(iph))))
	r.Set(m103Base+sunspec.M103_AphC, uint16(int16(math.Round(iph))))
	r.Set(m103Base+sunspec.M103_W, uint16(int16(math.Round(w))))
	r.Set(m103Base+sunspec.M103_VA, uint16(int16(math.Round(va))))
	r.Set(m103Base+sunspec.M103_VAr, uint16(int16(math.Round(varPwr))))
	r.Set(m103Base+sunspec.M103_PF, uint16(int16(math.Round(pf*10000))))
	r.Set(m103Base+sunspec.M103_DCW, uint16(int16(math.Round(dcw))))
	r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(math.Round(tmp*10))))
	r.Set(m103Base+sunspec.M103_TmpSnk, uint16(int16(math.Round((tmp-5)*10))))

	switch {
	case potW < wmaxW*0.06:
		r.Set(m103Base+sunspec.M103_St, 2) // sleeping
	case w < potW*0.98:
		r.Set(m103Base+sunspec.M103_St, 5) // throttled by WMaxLimPct
	default:
		r.Set(m103Base+sunspec.M103_St, 4) // MPPT
	}

	// Energy accumulation advances only while running (time moves).
	if !paused {
		*whAcc += uint16(math.Round(w * 5 / 3600))
		r.Set(m122Base+sunspec.M122_ActWh+3, *whAcc)
	}
}
