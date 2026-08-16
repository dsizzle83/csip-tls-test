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
//
// The NIGHT/becalm control (SetBecalmed, Inject "Night") replaces the
// irradiance term with a genuine 0 rather than attenuating it — W/VA/VAr/DCW/
// WAval all collapse to 0 and the Wh accumulator stops climbing, while V and
// Hz keep their jitter unchanged and TmpCab gets a small ambient-jitter term
// in its place (±0.3 degC, 360 s period) so the slow-class point stays visibly
// alive too. See solarStep's night parameter.

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

	// M702Base and M704Base are the ADVANCED (7xx) blocks, ZERO on a legacy
	// sim. They ride here — rather than only on solarAdvBases — because the ONE
	// physics (solarStep, solarCeilingW) has to see them:
	//
	//   - 702 carries the WMax SETTING every percent-of-max control resolves
	//     against (solarWMaxRefW). Before IW15-002 the physics read a Go float
	//     captured at construction, so a written WMax was cosmetic.
	//   - 704 carries the WSet active-power SETPOINT (solarSetpointW), which is
	//     a THIRD independent bound on output alongside the potential and the
	//     ceiling — not a second field on the ceiling (solarStep's three-way
	//     min, and see advBridgeSetpoint for why it is not folded into 123).
	//
	// Keeping them here rather than widening solarStep's signature is what lets
	// every existing caller (and every existing test) stay byte-identical: a
	// legacy sim leaves both zero and every new branch is skipped.
	M702Base uint16 // Model 702 (DER Capacity)   data start — 0 on a legacy sim
	M704Base uint16 // Model 704 (DER AC Controls) data start — 0 on a legacy sim
}

// SolarServer is an animated PV inverter simulator with a built-in API.
// It embeds *Server so callers can call srv.Stop(), srv.Regs, srv.Pause(), etc.
type SolarServer struct {
	*Server
	bases  SolarBases
	wmaxW  float64
	faults faultController // shared fault-injection state (see faults.go)
	lies   lieController   // the LYING-device fault set (see lying.go)

	// cloudCover is the current cloud-cover fraction (0=clear .. 1=overcast),
	// held as math.Float64bits for lock-free concurrent access: the HTTP
	// goroutine writes it via SetCloud (Inject "Cloud_pct" / modsim -cloud-pct),
	// the animation goroutine reads it via Cloud() each tick. It scales the
	// clear-sky irradiance through cloudTransmittance in the RUNNING branch only;
	// the zero value (clear sky) makes cloudTransmittance return exactly 1.0, so a
	// sim that is never clouded is byte-identical to the pre-cloud model.
	cloudCover atomic.Uint64

	// becalmed is the NIGHT/becalm control (see SetBecalmed): NOT a fault —
	// an honest environmental state, orthogonal to cloudCover, that drives the
	// panel's available potential to zero (irradiance is genuinely zero at
	// night, not merely attenuated) while the animation KEEPS running, so the
	// points that do not depend on irradiance — line voltage, frequency, and
	// the small ambient thermal jitter it adds to TmpCab — keep moving. It
	// exists to give the measurement-freshness false-positive row somewhere
	// real to run: a device with nothing to report is not the same claim as a
	// device that has stopped reporting, and only a sim that can go dark on
	// cue over real Modbus can put a gateway through both and show it tells
	// them apart. The zero value (false) is the byte-identical default.
	becalmed atomic.Bool

	// Advanced-DER (7xx) surface — populated only by NewSolarServerAdvanced.
	// When advanced is false the sim serves the legacy models only and behaves
	// exactly as today (see solar_adv.go).
	advanced  bool
	adv       solarAdvBases
	varRating float64 // reactive rating (var) — 702 VarMaxInj / fixed-var effect base

	// LEGACY curve family (12x) — populated only by NewSolarServerLegacyCurves
	// and nil everywhere else, so no existing profile can change behaviour
	// through it. It is the OTHER generation from adv above and never coexists
	// with it: a device serving both 705 and 126 is not a machine anyone ships,
	// and on one every per-generation conformance binding would be ambiguous.
	// See curve12x.go.
	legacy *legacyCurveLayer
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
		animateSolar(s, r, wmaxW, bases, ss.Cloud, ss.Becalmed, &ss.faults, stop)
	})
	if err != nil {
		return nil, err
	}
	ss.Server = srv
	regs.OnWriteAttempt = ss.interceptWrite
	regs.OnRead = ss.faults.transportRead
	ss.installLies() // the lying-device layer, in front of the fault hooks (lying.go)
	return ss, nil
}

// solarWMaxRefW resolves the WMax SETTING this device applies its
// percent-of-max controls against — the number a WMaxLimPct ceiling and a
// WSetPct setpoint are percentages OF — in the order a gateway itself resolves
// it:
//
//	702 WMax (the advanced setting)  →  121 WMax (the legacy setting)  →  fallback
//
// fallback is the Go float captured at construction (ss.wmaxW), used only when
// no model carries a usable setting.
//
// IW15-002: BEFORE this, every physics path read the construction float and
// nothing else, so a WMax written over Modbus (or seeded differently per model)
// was COSMETIC — the register moved, the device did not. A gateway that
// resolves its percent against WMax and a device that resolves it against a
// hidden rating disagree by exactly wmaxRating/wmaxSetting, and the error does
// NOT cancel: it lands as real watts on the wire.
//
// THE RATING IS NOT IN THIS CHAIN, deliberately. 120 WRtg / 702 WMaxRtg are
// what the machine CAN do; the setting is what it is configured to do. The two
// are seeded equal (populateSolarCore/populate702) so every pre-existing
// scenario is byte-identical, and they are separately injectable so a bench row
// can drive them apart — which is the whole IW15-002a fixture (see Inject's
// "WMax_W" / "M121_WMax_W" / "WMaxRtg_W" keys).
func solarWMaxRefW(r *RegisterMap, bases SolarBases, fallback float64) float64 {
	if bases.M702Base != 0 {
		v := sunspec.L702.View(readSlice(r, bases.M702Base, sunspec.L702.Len()))
		if w := v.Float("WMax"); !math.IsNaN(w) && w > 0 {
			return w
		}
	}
	if bases.M121Base != 0 {
		raw := r.Get(bases.M121Base + sunspec.M121_WMax)
		if raw != 0xFFFF { // not-implemented sentinel
			w := sunspec.ApplyScaleUint(raw, int16(r.Get(bases.M121Base+sunspec.M121_WMax_SF)))
			if w > 0 {
				return w
			}
		}
	}
	return fallback
}

// solarCeilingW is the single source of truth for the output ceiling (W) the
// inverter honours this update: the hub's WMaxLimPct limit when enabled (else
// the full WMax setting), shaped by any effect-time fault. fc may be nil (no
// effect faults). Both Inject and solarStep use it so the commanded limit, the
// device's physical response, and the meter-visible output never diverge.
//
// The percent resolves against solarWMaxRefW — the live WMax SETTING — not
// against wmaxW, which is now only the fallback for a device whose models carry
// no usable setting. With Ena=0 the ceiling is that same setting: a WMax
// setting below the rating bounds output on its own, because that is what
// configuring a maximum active power output means.
func solarCeilingW(r *RegisterMap, bases SolarBases, wmaxW float64, fc *faultController) float64 {
	ref := solarWMaxRefW(r, bases, wmaxW)
	limW := ref
	if r.Get(bases.M123Base+sunspec.M123_WMaxLimPct_Ena) != 0 {
		limPct := sunspec.ApplyScaleSigned(
			r.Get(bases.M123Base+sunspec.M123_WMaxLimPct),
			int16(r.Get(bases.M123Base+sunspec.M123_WMaxLimPct_SF)),
		)
		limW = ref * math.Max(0, limPct) / 100.0
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
	// The LEGACY curve family has no adopt handshake to intercept; what it has
	// instead is per-bank write protection and an ActCrv/ModEna selection pair
	// whose faults act on the write path (curve12x.go). It takes responsibility
	// for any write that lands inside one of its models and returns handled=false
	// for every other address, so no other profile's write path changes.
	if ss.legacy != nil {
		if apply, handled := ss.legacy.interceptWrite(ss.Regs, startAddr, vals); handled {
			return apply
		}
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
	// LYING-device kinds (lying.go) — a device that answers plausibly and
	// falsely. Consulted before the faultController so a lie kind never reaches
	// that controller's supported-set check, which would call it unknown.
	if handled, err := ss.lies.apply(body); handled {
		return err
	}
	// LEGACY curve kinds (curve12x.go) — consulted before the faultController
	// for the same reason the lying kinds are: a kind that controller does not
	// know would be reported as unknown rather than handled.
	if ss.legacy != nil {
		if handled, err := ss.legacy.faults.apply(body); handled {
			return err
		}
	}
	kinds := solarFaultKinds
	switch {
	case ss.advanced:
		kinds = solarAdvFaultKinds
	case ss.legacy != nil:
		kinds = solarLegacyCurveFaultKinds
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
	// Nameplate reports the capacity numbers SEPARATELY (IW15-002), so an
	// oracle can see a rating/setting divergence without a Modbus client:
	//
	//	wmax_W          the PHYSICAL panel, fixed at construction (-wmax). What
	//	                the irradiance model computes possible_W from.
	//	m120_WRtg_W     the DECLARED rating (model 120).
	//	m121_WMax_W     the legacy SETTING (model 121).
	//	pct_reference_W the number the device's own percent-of-max controls
	//	                resolve against RIGHT NOW (solarWMaxRefW: 702 WMax →
	//	                121 WMax → wmax_W). This is the referee: a gateway that
	//	                computed its WMaxLimPct/WSetPct against anything else
	//	                is off by exactly the ratio, in watts.
	//
	// All four are equal on a stock fixture; they are separately injectable.
	Nameplate struct {
		WMaxW         float64 `json:"wmax_W"`
		WRtgW         float64 `json:"m120_WRtg_W"`
		M121WMaxW     float64 `json:"m121_WMax_W"`
		PctReferenceW float64 `json:"pct_reference_W"`
	} `json:"nameplate"`
	Measurements struct {
		W_W        float64 `json:"W_W"`
		Possible_W float64 `json:"possible_W"` // pre-curtailment potential (M122 WAval)
		Cloud_pct  float64 `json:"Cloud_pct"`  // live cloud cover 0–100% (attenuates Possible_W)
		Night      bool    `json:"night"`      // becalm control armed (SetBecalmed) — Possible_W forced to 0
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

	// LegacyCurves is the 12x family's ground truth, omitted entirely on a sim
	// that does not serve it so /state stays byte-identical for every existing
	// scenario. See curve12x.go.
	LegacyCurves *SolarLegacyCurveState `json:"legacy_curves,omitempty"`
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
	st.Nameplate.WRtgW = unsigned(b.M120Base+sunspec.M120_WRtg, b.M120Base+sunspec.M120_W_SF)
	st.Nameplate.M121WMaxW = unsigned(b.M121Base+sunspec.M121_WMax, b.M121Base+sunspec.M121_WMax_SF)
	st.Nameplate.PctReferenceW = solarWMaxRefW(r, b, ss.wmaxW)

	m := &st.Measurements
	m.W_W = signed(b.M103Base+sunspec.M103_W, b.M103Base+sunspec.M103_W_SF)
	// Possible_W is the panel's pre-curtailment potential (WAval). Reading it
	// from the same register snapshot as W_W lets a sampler compute curtailment
	// (possible − actual) coherently, with no chance of actual > possible.
	m.Possible_W = signed(b.M122Base+sunspec.M122_WAval, b.M122Base+sunspec.M122_WAval_SF)
	// Cloud cover is server state (not a register): expose it as a percent so the
	// dashboard can display the live weather the running animation is applying.
	m.Cloud_pct = ss.Cloud() * 100.0
	// Night is likewise server state, not a register (see SetBecalmed).
	m.Night = ss.Becalmed()
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
	// signed() already returns the register's engineering value (raw × 10^SF);
	// at SF −2 that IS the percent (raw 5000 → 50.0), so no further division
	// belongs here. RMD-046: this used to divide by 100 again to match Inject's
	// now-removed val*100 double-scale — see Inject's "WMaxLimPct_pct" case.
	c.WMaxLimPct_pct = signed(b.M123Base+sunspec.M123_WMaxLimPct, b.M123Base+sunspec.M123_WMaxLimPct_SF)
	c.WMaxLimPctEna = int(r.Get(b.M123Base + sunspec.M123_WMaxLimPct_Ena))
	c.Conn = int(r.Get(b.M123Base + sunspec.M123_Conn))

	st.SFWriteRejects = r.ProtectedRejects()

	if ss.advanced {
		st.Advanced = ss.advSnapshot()
	}
	st.LegacyCurves = ss.legacySnapshot()

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
	if ss.legacy != nil && ss.legacy.end > end {
		end = ss.legacy.end
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

// SetBecalmed arms or clears the NIGHT/becalm control (see the becalmed field
// doc). Safe to call from the HTTP goroutine (Inject "Night") while the
// animation goroutine reads it via Becalmed() each tick.
func (ss *SolarServer) SetBecalmed(on bool) {
	ss.becalmed.Store(on)
}

// Becalmed reports whether the NIGHT/becalm control is armed.
func (ss *SolarServer) Becalmed() bool {
	return ss.becalmed.Load()
}

// Inject overrides one or more measurement or control fields.
// Accepted JSON keys: "W_W", "V_V", "Hz_Hz", "DCV_V", "TmpCab_C",
// "WMaxLimPct_pct" (0–100, clamped), "Conn" (0 or 1), "St" (1–8),
// "Cloud_pct" (0–100), "Night" (0 or nonzero), and the capacity keys
// "WMax_W", "M121_WMax_W", "WMaxRtg_W", "WChaRteMax_W", "WChaRteMaxRtg_W",
// "WDisChaRteMax_W", "WDisChaRteMaxRtg_W" (see injectSolarCapacity).
//
// "Cloud_pct" is not a register — it is an environmental input (like metersim's
// LoadW_W) that scales the running-animation irradiance via cloudTransmittance;
// it takes effect on the next animation tick and is unaffected by pause.
//
// "Night" is likewise not a register — the becalm control (SetBecalmed): it
// takes effect on the next RUNNING animation tick (paused steps ignore it,
// same as Cloud_pct) and is a distinct axis from Cloud_pct, not an alias for
// "very cloudy" — cloud cover attenuates daytime irradiance but never reaches
// true zero (a diffuse floor remains under any deck), where night genuinely
// is zero.
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
			// All three phase-to-neutral voltages AND all three line-to-line
			// voltages move together — a balanced three-phase machine cannot
			// have one without the other. Updating only PhVph{A,B,C} left
			// PPVph{AB,BC,CA} at whatever the animation last wrote, so an
			// injected voltage produced a device whose L-N and L-L readings
			// disagreed by an arbitrary factor until the next animation tick.
			// The sqrt(3) relation is the same one the animator itself applies
			// (see the M103_PPVphAB writes in the animation loop).
			v10 := uint16(math.Round(val * 10))
			vLL10 := uint16(math.Round(val * 10 * math.Sqrt(3)))
			r.Set(b.M103Base+sunspec.M103_PhVphA, v10)
			r.Set(b.M103Base+sunspec.M103_PhVphB, v10)
			r.Set(b.M103Base+sunspec.M103_PhVphC, v10)
			r.Set(b.M103Base+sunspec.M103_PPVphAB, vLL10)
			r.Set(b.M103Base+sunspec.M103_PPVphBC, vLL10)
			r.Set(b.M103Base+sunspec.M103_PPVphCA, vLL10)
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
			// RMD-046: this used to encode RawFromScaleSigned(val*100, SF) against
			// SF=-2, i.e. val×10000 — a double scale that saturated the int16
			// register for any val above ~3.27 (an injected 80 landed as 327.67%).
			// The correct encoding is val itself: at SF=-2 the raw register is in
			// units of 0.01%, so 100 → raw 10000 (100.00%). WMaxLimPct is 0–100
			// per the DER model (SunSpec M123/M704); clamp rather than let an
			// out-of-range percent encode into a representable-but-meaningless
			// raw word.
			pct := math.Max(0, math.Min(100, val))
			r.Set(b.M123Base+sunspec.M123_WMaxLimPct,
				sunspec.RawFromScaleSigned(pct, sf(b.M123Base+sunspec.M123_WMaxLimPct_SF)))
		case "Conn":
			r.Set(b.M123Base+sunspec.M123_Conn, uint16(val))
		case "St":
			r.Set(b.M103Base+sunspec.M103_St, uint16(val))
		case "Cloud_pct":
			// Environmental input, not a register: 0..100% → SetCloud [0,1]
			// (clamped). The running animation reads it via cloudTransmittance.
			ss.SetCloud(val / 100.0)
		case "Night":
			// Environmental input, not a register (like Cloud_pct): the NIGHT/
			// becalm control (see SetBecalmed). Nonzero arms it, zero clears it.
			ss.SetBecalmed(val != 0)
		case "WMax_W", "WMaxRtg_W", "M121_WMax_W",
			"WChaRteMax_W", "WChaRteMaxRtg_W", "WDisChaRteMax_W", "WDisChaRteMaxRtg_W":
			// The IW15-002 capacity axis: SETTINGS and RATINGS, independently
			// settable. See injectSolarCapacity.
			if err := ss.injectSolarCapacity(key, val); err != nil {
				return err
			}
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

// injectSolarCapacity handles the POST /inject capacity keys — the IW15-002
// axis. A DER's capacity block carries TWO kinds of number and the whole defect
// is that this sim used to hold them as ONE:
//
//	RATINGS  (read-only facts about the machine)   120 WRtg,  702 WMaxRtg,
//	                                               702 W{,Dis}ChaRteMaxRtg
//	SETTINGS (read-write configuration)            121 WMax,  702 WMax,
//	                                               702 W{,Dis}ChaRteMax
//
// Keys, and exactly what each one moves:
//
//	"WMax_W"            the WMax SETTING, in EVERY model that carries it —
//	                    121 WMax and (advanced only) 702 WMax. One physical
//	                    setting, so the two models are written together; a
//	                    device that contradicts itself across models is a
//	                    defect this sim injects deliberately, never by accident.
//	                    THE PHYSICS OBEYS THIS: solarWMaxRefW resolves it and
//	                    both the ceiling and the setpoint percent-of-max
//	                    reference it from the next step onward.
//	"M121_WMax_W"       121 WMax ALONE — the deliberate cross-model divergence
//	                    lever, and on a LEGACY sim the only WMax there is.
//	                    On an advanced sim 702 wins the resolution, so this key
//	                    changes what a 121-reading client sees without changing
//	                    the physics: that asymmetry is the point (it is how a
//	                    "the two models disagree" row is staged), and it is why
//	                    the key is named after its model.
//	"WMaxRtg_W"         the RATING, in every model that carries it — 120 WRtg
//	                    and (advanced only) 702 WMaxRtg. DECLARATION ONLY: the
//	                    panel's physical capability is fixed at construction
//	                    (modsim -wmax) and is what potW is computed from, so
//	                    this key stages "the device declares a rating it does
//	                    not have" rather than rebuilding the machine.
//	"WChaRteMax_W" / "WDisChaRteMax_W" and their "…Rtg_W" pair
//	                    702 only, and DECLARATION ONLY on solar: a PV profile
//	                    models no charge/discharge rate physics (the pack does
//	                    — see injectPackCapacity, where the setting pair is
//	                    honoured by clampToRateRating). They exist here so a row
//	                    can build a solar fixture whose rate SETTING and rate
//	                    RATING differ, which is what a gateway's
//	                    reference-resolution rule has to be tested against.
//
// Every 702-only key is REFUSED BY NAME on a legacy sim rather than silently
// accepted: "I set WChaRteMax and nothing happened" is the diagnosis this
// simulator exists to make impossible (injectPackSetpoint's rule).
func (ss *SolarServer) injectSolarCapacity(key string, val float64) error {
	if val < 0 {
		return fmt.Errorf("inject: %q must be >= 0 (got %v): SunSpec capacity points are unsigned", key, val)
	}
	r, b := ss.Regs, ss.bases

	setLegacy := func(base, off, sfOff uint16) {
		r.Set(base+off, sunspec.RawFromScaleUint(val, int16(r.Get(base+sfOff))))
	}
	set702 := func(field string) error {
		if b.M702Base == 0 {
			return fmt.Errorf("inject: %q needs an advanced sim serving M702 (modsim -der-models advanced|full); "+
				"this sim serves the legacy models only", key)
		}
		regs := readSlice(r, b.M702Base, sunspec.L702.Len())
		sunspec.L702.View(regs).SetFloat(field, val)
		writeSlice(r, b.M702Base, regs)
		return nil
	}

	switch key {
	case "WMax_W":
		setLegacy(b.M121Base, sunspec.M121_WMax, sunspec.M121_WMax_SF)
		if b.M702Base != 0 {
			return set702("WMax")
		}
	case "M121_WMax_W":
		setLegacy(b.M121Base, sunspec.M121_WMax, sunspec.M121_WMax_SF)
	case "WMaxRtg_W":
		setLegacy(b.M120Base, sunspec.M120_WRtg, sunspec.M120_W_SF)
		if b.M702Base != 0 {
			return set702("WMaxRtg")
		}
	case "WChaRteMax_W":
		return set702("WChaRteMax")
	case "WChaRteMaxRtg_W":
		return set702("WChaRteMaxRtg")
	case "WDisChaRteMax_W":
		return set702("WDisChaRteMax")
	case "WDisChaRteMaxRtg_W":
		return set702("WDisChaRteMaxRtg")
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
// otherwise dedupes them into one device. The result is written to the SN
// field at m1+48 (see populateSolarCore) — NOT m1+32 (Opt), which lands at
// the wrong offset per lexa-proto/sunspec/identity.go's Model 1 layout and
// was the T05/T06 bench finding: two sims with distinct Opt but empty SN
// still deduped to one nb_unit.
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
	setStr16(r, m1+16, "CSIP-Solar-5000")
	// m1+32 (Opt, 8 regs) is intentionally left blank (zero/NUL) — this sim
	// advertises no device-options string. The device SERIAL belongs at
	// m1+48 (SN, 16 regs), NOT m1+32: lexa-proto/sunspec/identity.go's Model 1
	// layout is Mn(0,16) / Md(16,16) / Opt(32,8) / Vr(40,8) / SN(48,16)
	// (commonSNReg=48, commonSNEnd=64; m1Len=66 already covers it). A prior
	// version of this sim wrote the serial into Opt instead — bench finding:
	// the gateway's ReadCommon parsed Options="BENCH-MODSIM-01"/Serial="" for
	// two distinct sims, so both empty serials collapsed into one nb_unit on
	// manufacturer|model|serial.
	//
	// Vr (m1+40, 8 regs) is the DEVICE's firmware version and was never written
	// at all, so this sim served eight NUL registers there. That is a legal
	// "not implemented" string, but it is not what a real DER does, and the IEEE
	// 1547-2018 profile §3.2 Table 16 marks Vr REQUIRED — conformance case MOD-4
	// step 3 failed on it against this fixture. A gateway mirroring this device
	// cannot invent the value (a version string is a fact about the DER's
	// firmware, not about the gateway), so the fix has to be here.
	setStr8(r, m1+40, "4.2.1") // Vr — firmware version
	setStr16(r, m1+48, solarSerialOrDefault(serial))
	cursor += 2 + m1Len

	// Model 120 (Nameplate) — 26 data regs
	r.Set(cursor, sunspec.ModelNameplate)
	r.Set(cursor+1, sunspec.M120Len)
	m120 := cursor + 2
	r.Set(m120+sunspec.M120_DERTyp, 4) // PV
	// WRtg is the RATING — what this machine can physically do, immutable
	// (IW15-002). It is seeded at the same number as the 121 WMax SETTING
	// below, which is what a factory-configured device looks like and what
	// keeps every pre-existing scenario byte-identical, but the two are NOT the
	// same fact and are separately injectable ("WMaxRtg_W" vs "WMax_W" /
	// "M121_WMax_W"). Splitting them is what makes the legacy over-limit
	// exercisable: a gateway that computes a WMaxLimPct percent against the
	// RATING while the device applies it against a LOWER SETTING lands real
	// watts off target, and the error does not cancel anywhere.
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
	// WMax is the SETTING — read-write, and the reference the legacy ceiling
	// physics actually resolves against (solarWMaxRefW → solarCeilingW). See
	// the M120 WRtg seed above for the rating/setting split this is one half
	// of, and Inject's "M121_WMax_W" for the lever that moves it alone.
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
	// PPVph{AB,BC,CA} (line-to-line) are deliberately left at 0 here — the
	// animation loop (line ~717) and the Inject "V_V" handler both seed/update
	// them from PhVphA with the sqrt(3) relation, and the legacy (non-701)
	// image has served this exact sequence — 0 until the first tick — since
	// before this sim had a 701 model to mirror it into. Widening the seed
	// here would change model 103's register content for every existing
	// legacy-sim scenario the day this file is rebuilt, not just the
	// advanced/701 path that actually needs it — see populateSolarAdvanced's
	// own PPVph seed for the 701-scoped fix and its reasoning.
	r.Set(m103Base+sunspec.M103_V_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_Hz, 6000)
	r.Set(m103Base+sunspec.M103_Hz_SF, sfN(-2))
	r.Set(m103Base+sunspec.M103_VA, uint16(int16(3100)))
	r.Set(m103Base+sunspec.M103_VA_SF, 0)
	r.Set(m103Base+sunspec.M103_VAr, uint16(int16(650)))
	r.Set(m103Base+sunspec.M103_VAr_SF, 0)
	r.Set(m103Base+sunspec.M103_PF, uint16(int16(9677)))
	r.Set(m103Base+sunspec.M103_PF_SF, sfN(-2))
	// WH (offsets 22-23) starts at 0 — "has not accumulated anything yet" is a
	// legitimate acc32 value, not a sentinel — and solarStep advances it every
	// running tick (see there). WH_SF is set explicitly, even though 0 is also
	// the register's zero-initialised default, because leaving it implicit is
	// exactly what made this point invisible before: a reader has no way to
	// tell "the sim deliberately declares raw Wh" from "nobody ever touched
	// this register" (bench gap 4).
	r.Set(m103Base+sunspec.M103_WH_SF, 0)
	r.Set(m103Base+sunspec.M103_DCV, 3800)
	r.Set(m103Base+sunspec.M103_DCV_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_DCW, uint16(int16(3180)))
	r.Set(m103Base+sunspec.M103_DCW_SF, 0)
	r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(470)))
	r.Set(m103Base+sunspec.M103_Tmp_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_St, 4)
	cursor += 2 + m103Len

	// Model 123 (Immediate Controls). Laid down from sunspec.L123 by name, and
	// no longer from three copies of a hand offset list — see m123.go for the
	// map that was wrong at all 24 points and the fixture half of that finding.
	// The solar inverter rests uncurtailed: 10000 at SF -2 = 100.00 %, with the
	// limit ENABLED, connected.
	m123Base := cursor + 2
	cursor += PopulateM123(r, cursor, M123Defaults{
		WMaxLimPctRaw: 10000, WMaxLimPctSF: -2, WMaxLimEna: 1, Conn: 1,
	})

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

func animateSolar(s *Server, r *RegisterMap, wmaxW float64, bases SolarBases, cloud func() float64, night func() bool, fc *faultController, stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	var whAcc uint16

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			// cloud()/night() read the live environment each tick so an /inject
			// Cloud_pct or Night takes effect on the next step (paused steps
			// ignore both — see solarStep).
			solarStep(r, wmaxW, bases, s.IsPaused(), s.simTime(), cloud(), night(), fc, &whAcc)
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
//
// night, likewise RUNNING-branch-only, is the becalm control (SetBecalmed):
// unlike cloud it does not attenuate the irradiance model, it REPLACES it —
// potW is forced to exactly 0, the honest "irradiance is genuinely zero"
// claim a cloud deck (whose diffuse floor never reaches zero) cannot make.
// Every downstream computation is unchanged, so the existing formulas do the
// rest for free: W/VA/VAr/DCW/WAval collapse to 0, the accumulator gains
// nothing this tick (it FLATTENS rather than resets), and the potW<6% branch
// below reports St=2 (sleeping) — exactly the state a real inverter reports
// overnight. V and Hz are untouched by potW already, so they keep their
// existing jitter with no change here; TmpCab's ambient-jitter override below
// is the one addition night needs to keep its slow-class point visibly alive
// too, rather than pinned at exactly 35.0 forever.
func solarStep(r *RegisterMap, wmaxW float64, bases SolarBases, paused bool, simTime float64, cloud float64, night bool, fc *faultController, whAcc *uint16) {
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
		if night {
			// Night: irradiance is genuinely zero, not merely attenuated — see
			// the becalmed field doc and this function's own doc for why this
			// is a replacement of the irradiance model, not another multiplier
			// alongside cloudTransmittance.
			potW = 0
		} else {
			irr := math.Max(0.05, math.Min(0.95, 0.5+0.45*math.Sin(2*math.Pi*t/600)))
			// Cloud cover scales the clear-sky potential (downward-only). cloud=0 ⇒
			// cloudTransmittance == 1.0, so potW is byte-identical to the pre-cloud
			// model. WAval/possible_W (below) therefore honestly reflect the
			// cloud-reduced available power, and WMaxLimPct still clips actual ≤ this.
			potW = wmaxW * irr * cloudTransmittance(int64(t), cloud)
		}
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
	//
	// THREE-WAY MIN, not two (IW15-001). An enabled 704 WSet setpoint is a
	// THIRD, INDEPENDENT bound: output = min(available, ceiling, setpoint).
	// Each term keeps its own meaning —
	//
	//	setpoint ABOVE available ⇒ output at available (a setpoint cannot
	//	    conjure irradiance; the device is not "diverged", it is limited)
	//	setpoint BELOW available ⇒ output at the setpoint
	//	ceiling binds independently ⇒ a ceiling below the setpoint still wins,
	//	    and /state's WMaxLimPct_pct plus the 123/704 register dump still
	//	    show WHICH of the two is holding the device down
	//
	// — which is exactly what a limit-is-not-a-setpoint negative test needs, and
	// what folding WSet into the M123 ceiling cell would have destroyed (see
	// advBridgeSetpoint's doc). Skipped entirely on a legacy sim (M704Base==0).
	w := math.Min(potW, solarCeilingW(r, bases, wmaxW, fc))
	if sp, ok := solarSetpointW(r, bases, wmaxW); ok {
		w = math.Min(w, sp)
	}

	// Power-derived registers (depend on the curtailed w).
	va := w / pf
	varPwr := va * math.Sin(math.Acos(pf))
	tmp := 35.0 + 20.0*(w/wmaxW)
	if night {
		// With w forced to 0 the formula above pins tmp at exactly 35.0 forever
		// — flat, not merely quiet, which would make the becalm row prove the
		// wrong thing (a device with nothing to report would look identical to
		// one that stopped reporting). A real cabinet still tracks a slowly
		// swinging ambient temperature at night: small (±0.3 degC) and slow (a
		// 360 s period), in the neighbourhood of the "0.1 degC/6min" slowest-
		// genuine-signal figure the measurement-freshness design rests on, so
		// TmpCab stays visibly ALIVE on its own slow-class point even though W
		// has collapsed to zero. Gated on night so every non-becalmed scenario
		// (the overwhelming majority) is byte-identical to before this file.
		tmp = 35.0 + 0.3*math.Sin(2*math.Pi*simTime/360)
	}
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
		// Throttled — by the WMaxLimPct ceiling, by an enabled 704 WSet
		// setpoint, or by a WMax setting below the panel's rating. The state
		// says "I am producing less than I could"; WHICH bound is holding it
		// there is read from /state (Controls + advanced.wset_704) or the
		// registers, not guessed from St.
		r.Set(m103Base+sunspec.M103_St, 5)
	default:
		r.Set(m103Base+sunspec.M103_St, 4) // MPPT
	}

	// Energy accumulation advances only while running (time moves).
	if !paused {
		*whAcc += uint16(math.Round(w * 5 / 3600))
		r.Set(m122Base+sunspec.M122_ActWh+3, *whAcc)
		// Model 103's OWN acc32 (WH at offsets 22-23) mirrors the SAME
		// integrated energy — a DIFFERENT point from M122's ActWh above, and
		// one 701's TotWhInj mirror (advMirror701) never touches. Before this
		// it was never written at all: the register starts zero-initialised
		// and WH_SF (offset 24) is a legal, in-domain scale factor at its own
		// zero-initialised default, so a consumer gating a point's presence on
		// "is its SF valid" saw an IMPLEMENTED accumulator frozen at 0
		// forever — indistinguishable, over Modbus, from freeze_block, and it
		// left S1 (Δaccumulator vs ∫W dt) unexercisable on the legacy 10x leg
		// (bench gap 4). The high word (offset 22) stays 0, exactly like
		// M122's ActWh above, because *whAcc is itself only a uint16 running
		// total (a bench simplification, not a full 32/64-bit accumulator).
		r.Set(m103Base+sunspec.M103_WH+1, *whAcc)
	}
}
