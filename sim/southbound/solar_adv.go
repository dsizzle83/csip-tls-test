package sim

// solar_adv.go — the advanced-DER (IEEE 1547-2018 / SunSpec 7xx) surface of the
// PV inverter simulator, added by NewSolarServerAdvanced. It is OPT-IN: the
// legacy NewSolarServer serves only models 1/120/121/122/103/123 and behaves
// exactly as before, so every existing mayhem scenario is byte-identical. An
// advanced sim additionally advertises:
//
//	701 (DER AC Measurement)  — measurement + St/InvSt/ConnSt + Alrm bitfield,
//	                            mirrored every tick from the same physical state
//	                            the 103 model reports; the hub prefers 701 over
//	                            103 when present.
//	702 (DER Capacity)        — WMax + reactive rating (fixed-var convergence base).
//	703 (DER Enter Service)   — permit-service enable, IEEE 1547-2018-typical
//	                            enter-service voltage/frequency window and
//	                            delay/ramp timers. Unconditionally mandatory per
//	                            the profile's §3.5 Required Points table (unlike
//	                            713, it carries no conditionality clause) — see
//	                            populate703.
//	704 (DER AC Controls)     — WMaxLimPct (bridged to the 123 ceiling machinery),
//	                            PFWInj/PFWAbs fixed-PF sync groups, VarSet fixed-var,
//	                            all writable with MEASURED effect on 701 PF/Var.
//	705/706/711/712           — Volt-Var / Volt-Watt / Freq-Droop / Watt-Var, each
//	                            with the §3.1.2 adopt handshake: a read-only live
//	                            curve (index 0), a writable staging curve (index 1),
//	                            AdptCrvReq → AdptCrvRslt=COMPLETED, and on COMPLETED
//	                            the live curve reflects the staged points.
//
// Three advanced faults ride the same faultController: raise_alarm (701 Alrm
// bits — the voltage/frequency alarm bits also derate the LNV/LLV/Hz points
// that back them, see advCoupledVoltHz, so the alarm and the measurement it
// names agree), curve_adopt_lies (COMPLETED-but-stale — the INV-ADV-READBACK
// defense), and pf_ack_ignore (704 PF/var write ACKs but measured PF/var
// never moves).

import (
	"math"
	"time"

	"lexa-proto/sunspec"
)

const (
	advNPt  = 10 // device NPt: curve points per curve (headroom for CSIP curves)
	advNCrv = 2  // curve index 0 (live, read-only) + index 1 (writable staging)
)

// Model 701 Alrm bit positions this sim gives a real physical correlate to
// when raise_alarm arms them (see advCoupledVoltHz) — the standard
// model_701.json "Alrm" symbol positions, duplicated here rather than
// imported because lexa-proto/sunspec deliberately carries no bit vocabulary
// (parse layer, not semantics — see faults.go's raiseAlarmBits doc). These
// four are the same positions lexa-gw's hub-side alarm detector
// (lexa-hub/cmd/hub/logevent.go, alrm701ToTable14) maps directly onto CSIP
// Table 14 OVER_VOLTAGE(2)/UNDER_VOLTAGE(4)/OVER_FREQUENCY(6)/
// UNDER_FREQUENCY(8) — a "grid-interface measurement" alarm, which is why
// they are the ones worth backing with an actual out-of-band reading: a
// downstream client that cross-checks the alarm bit against the measurement
// it names (rather than trusting the flag blindly) must see them agree.
const (
	alrm701OverFrequency  uint32 = 1 << 8
	alrm701UnderFrequency uint32 = 1 << 9
	alrm701ACOverVolt     uint32 = 1 << 10
	alrm701ACUnderVolt    uint32 = 1 << 11
)

// advCoupledVoltHz returns the line-to-neutral voltage and frequency
// advMirror701 should report given the armed raise_alarm bits, backing a
// grid-interface alarm bit with a measurement that actually sits outside the
// condition's threshold — never just a flag with a nominal reading
// underneath it, which is a state no real DER reaches (the fault it claims
// and the measurement it reports would disagree). With no mapped bit armed
// it returns volt/hz unchanged, so the no-fault path stays byte-identical.
//
// Voltage and frequency are decided independently since a device can be
// simultaneously off-nominal on both; an over+under pair armed together for
// the same quantity (a fault-injection state no real device reaches) prefers
// UNDER, so the function always has one deterministic answer.
//
// Thresholds are set past the IEEE 1547-2018 Table 12 default Category III
// trip points so the condition is unambiguous to a client applying the same
// table: under-voltage trips at 0.88 pu (211.2 V of 240 V nominal) -> this
// reports 205 V; over-voltage trips at 1.10 pu (264 V) -> 270 V;
// under-frequency trips at 58.5 Hz -> 58.0 Hz; over-frequency trips at
// 61.2 Hz -> 61.5 Hz.
func advCoupledVoltHz(bits uint32, volt, hz float64) (float64, float64) {
	switch {
	case bits&alrm701ACUnderVolt != 0:
		volt = 205.0
	case bits&alrm701ACOverVolt != 0:
		volt = 270.0
	}
	switch {
	case bits&alrm701UnderFrequency != 0:
		hz = 58.0
	case bits&alrm701OverFrequency != 0:
		hz = 61.5
	}
	return volt, hz
}

// solarAdvFaultKinds is the advanced solar sim's advertised fault set: every
// legacy solar kind plus the three 7xx kinds. Built from solarFaultKinds so the
// two never drift.
var solarAdvFaultKinds = func() map[FaultKind]bool {
	m := make(map[FaultKind]bool, len(solarFaultKinds)+3)
	for k := range solarFaultKinds {
		m[k] = true
	}
	m[FaultRaiseAlarm] = true
	m[FaultCurveAdoptLies] = true
	m[FaultPFAckIgnore] = true
	return m
}()

// solarAdvBases holds the data-block base addresses of the advanced models and
// the descriptors for the curve models (for the adopt handshake + snapshot).
type solarAdvBases struct {
	M701    uint16
	M701Len int
	M702    uint16
	M703    uint16
	M704    uint16
	Curves  []curveBlock
	// Trips holds the 707/708/709/710 IEEE 1547 trip models, and is EMPTY
	// unless the sim was asked for them (NewSolarServerTrip, modsim
	// -der-models full). They are appended AFTER every other advanced model
	// precisely so an image without them is byte-identical to the one this sim
	// has always served — see populateSolar7xx and trip1547.go.
	Trips []tripBlock
	End   uint16 // last register address occupied by the advanced models
}

// curveBlock describes one curve/control model instance for the adopt handshake.
// The live curve is 0-based index 0 (read-only); staging is index 1+.
type curveBlock struct {
	id      uint16
	base    uint16          // data-block base address
	hdr     *sunspec.Layout // header layout (NPt/NCrv/AdptCrvReq/AdptCrvRslt/SFs)
	crv     *sunspec.Layout // per-curve (or per-ctl) layout
	npt     int             // device NPt (0 for the point-less 711 control)
	stride  int             // registers per curve = crv.Len() + 2*npt
	hdrLen  int
	reqOff  int // hdr offset of AdptCrvReq / AdptCtlReq
	rsltOff int // hdr offset of AdptCrvRslt / AdptCtlRslt
	roOff   int // per-curve offset of ReadOnly
}

// curveModelSpec is the static description of one advanced curve model.
type curveModelSpec struct {
	id                  uint16
	hdr, crv            *sunspec.Layout
	npt                 int
	reqField, rsltField string
	sfs                 map[string]int16 // header scale factors to seed
}

var solarCurveSpecs = []curveModelSpec{
	{sunspec.ModelDERVoltVar, sunspec.L705Hdr, sunspec.L705Crv, advNPt, "AdptCrvReq", "AdptCrvRslt",
		map[string]int16{"V_SF": 0, "DeptRef_SF": 0, "RspTms_SF": 0}},
	{sunspec.ModelDERVoltWatt, sunspec.L706Hdr, sunspec.L706Crv, advNPt, "AdptCrvReq", "AdptCrvRslt",
		map[string]int16{"V_SF": 0, "DeptRef_SF": 0, "RspTms_SF": 0}},
	// 711 (Freq Droop) is point-less (npt=0) and uses the AdptCtl* handshake.
	{sunspec.ModelDERFreqDroop, sunspec.L711Hdr, sunspec.L711Ctl, 0, "AdptCtlReq", "AdptCtlRslt",
		map[string]int16{"Db_SF": -3, "K_SF": -2, "RspTms_SF": 0}},
	{sunspec.ModelDERWattVar, sunspec.L712Hdr, sunspec.L712Crv, advNPt, "AdptCrvReq", "AdptCrvRslt",
		map[string]int16{"W_SF": 0, "DeptRef_SF": 0}},
}

// NewSolarServerAdvanced creates an animated PV inverter simulator that ALSO
// serves the IEEE 1547-2018 7xx models (see solar_adv.go). Use it for the
// advanced-DER QA scenarios; NewSolarServer stays the legacy default. serial
// overrides the SunSpec Model 1 serial (SN) register when non-empty; empty
// keeps the historical "SN-SOLAR-001" default (see solarSerialOrDefault).
func NewSolarServerAdvanced(listenURL string, wmaxW float64, serial string) (*SolarServer, error) {
	return newSolarServerAdvanced(listenURL, wmaxW, serial, false)
}

// NewSolarServerTrip creates an advanced PV inverter simulator that ALSO serves
// the IEEE 1547-2018 trip models 707/708/709/710 (DERTripLV/HV/LF/HF) with
// Category III default trip curves — see trip1547.go.
//
// It is a SEPARATE constructor, not a widening of NewSolarServerAdvanced, for
// one reason: the trip models occupy ~380 registers and would move nothing (the
// existing blocks keep their addresses) but ADD to the image, which changes
// every SunSpec chain walk, every model-discovery scan and every register dump
// the existing QA scenarios record. Those scenarios are the baseline the sim
// exists to protect, so the extra models are opt-in and the default advanced
// image is byte-identical to what it has always been —
// TestTripModelsDoNotDisturbTheDefaultAdvancedImage proves it.
func NewSolarServerTrip(listenURL string, wmaxW float64, serial string) (*SolarServer, error) {
	return newSolarServerAdvanced(listenURL, wmaxW, serial, true)
}

func newSolarServerAdvanced(listenURL string, wmaxW float64, serial string, withTrip bool) (*SolarServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	varRating := wmaxW * 0.44
	bases, adv := populateSolarAdvanced(regs, wmaxW, varRating, serial, withTrip)

	ss := &SolarServer{bases: bases, wmaxW: wmaxW, advanced: true, adv: adv, varRating: varRating}
	ss.faults.label = "solar"
	ss.faults.configureGate(bases.M123Base + sunspec.M123_WMaxLimPct_Ena)
	ss.faults.configureScale(bases.M103Base + sunspec.M103_W_SF)

	srv, err := newAnimatedServer(listenURL, regs, func(s *Server, r *RegisterMap, stop <-chan struct{}) {
		animateSolarAdvanced(s, r, wmaxW, bases, adv, varRating, ss.Cloud, &ss.faults, stop)
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

// ── Populate ─────────────────────────────────────────────────────────────────

func populateSolarAdvanced(r *RegisterMap, wmaxW, varRating float64, serial string, withTrip bool) (SolarBases, solarAdvBases) {
	bases, cursor := populateSolarCore(r, wmaxW, serial)
	seedLineToLineVoltage(r, bases)
	adv, cursor := populateSolar7xx(r, cursor, wmaxW, varRating, withTrip)
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	return bases, adv
}

// seedLineToLineVoltage seeds M103's PPVph{AB,BC,CA} (line-to-line voltage)
// from the phase-to-neutral voltage populateSolarCore just wrote, applying
// the SAME sqrt(3) relation the animation loop (solarStep) and the Inject
// "V_V" handler already use every tick/write.
//
// It is called ONLY from the advanced path — never from populateSolarCore
// itself, which the legacy (non-701) sim also uses and which deliberately
// keeps serving 0 there until the first tick (see that function's own
// comment) — because it is specifically the advanced sim's 701 mirror
// (advMirror701) that reads these M103 registers BEFORE the first animation
// tick, so an immediately-read advanced sim is coherent
// (animateSolarAdvanced's "Seed 701 before the first tick" comment).
//
// Without this, LLV/VL1L2/VL2L3/VL3L1 read a real, IMPLEMENTED 0.0 V for up
// to 5 real seconds after every advanced sim start, on a device declaring
// ACType=THREE_PHASE — a physically impossible machine (see advMirror701's
// file comment) and the exact shape of defect MOD-4 step 3 checks for.
// TestAdv701VoltagePointsCoherentBeforeFirstTick pins this.
func seedLineToLineVoltage(r *RegisterMap, bases SolarBases) {
	vRaw := r.Get(bases.M103Base + sunspec.M103_PhVphA)
	vll := uint16(math.Round(float64(vRaw) * math.Sqrt(3)))
	r.Set(bases.M103Base+sunspec.M103_PPVphAB, vll)
	r.Set(bases.M103Base+sunspec.M103_PPVphBC, vll)
	r.Set(bases.M103Base+sunspec.M103_PPVphCA, vll)
}

// populateSolar7xx appends the advanced models after the legacy layout (before
// the end marker) and returns their bases plus the next cursor.
//
// withTrip appends models 707/708/709/710 LAST. Appending rather than
// interleaving is deliberate and load-bearing: every block before them keeps
// the address it has always had, so a trip-capable sim and a plain advanced sim
// answer identically for models 1/103/120/121/122/123/701/702/703/704/705/706/
// 711/712, and only the end marker moves.
func populateSolar7xx(r *RegisterMap, cursor uint16, wmaxW, varRating float64, withTrip bool) (solarAdvBases, uint16) {
	var adv solarAdvBases

	adv.M701, adv.M701Len, cursor = populate701(r, cursor)
	adv.M702, cursor = populate702(r, cursor, wmaxW, varRating)
	adv.M703, cursor = populate703(r, cursor)
	adv.M704, cursor = populate704(r, cursor)
	for _, spec := range solarCurveSpecs {
		var cb curveBlock
		cb, cursor = populateCurveModel(r, cursor, spec)
		adv.Curves = append(adv.Curves, cb)
	}
	if withTrip {
		for _, spec := range solarTripSpecs {
			var tb tripBlock
			tb, cursor = populateTripModel(r, cursor, spec)
			adv.Trips = append(adv.Trips, tb)
		}
	}
	adv.End = cursor + 1

	// SF write-protection (protect.go), derived from the layouts themselves so
	// the set never drifts from the models served. Curve-model SFs live in the
	// header layouts only. This is what turns the hub's E1 write-back (an
	// all-0x8000 whole-block 704 RMW under nan_sentinel) from silent permanent
	// poisoning into an observable divergence.
	protectLayoutSFs(r, adv.M701, sunspec.L701)
	protectLayoutSFs(r, adv.M702, sunspec.L702)
	protectLayoutSFs(r, adv.M703, sunspec.L703)
	protectLayoutSFs(r, adv.M704, sunspec.L704)
	for _, cb := range adv.Curves {
		protectLayoutSFs(r, cb.base, cb.hdr)
	}
	for _, tb := range adv.Trips {
		protectLayoutSFs(r, tb.base, tb.hdr)
	}
	return adv, cursor
}

// writeModelHeader writes a [modelID, length] block header at cursor and returns
// the data-block base and the next cursor (past the data block).
func writeModelHeader(r *RegisterMap, cursor, modelID uint16, dataLen int) (base, next uint16) {
	r.Set(cursor, modelID)
	r.Set(cursor+1, uint16(dataLen))
	return cursor + 2, cursor + 2 + uint16(dataLen)
}

// writeSlice copies a model data slice into the register map at base.
func writeSlice(r *RegisterMap, base uint16, regs []uint16) {
	for i, v := range regs {
		r.Set(base+uint16(i), v)
	}
}

// readSlice reads n registers starting at base into a fresh slice.
func readSlice(r *RegisterMap, base uint16, n int) []uint16 {
	regs := make([]uint16, n)
	for i := range regs {
		regs[i] = r.Get(base + uint16(i))
	}
	return regs
}

// populate701 writes the FULL model 701 block — all 153 registers, including the
// optional MnAlrmInfo string past offset 121. The full model is wider than the
// 125-register Modbus single-read cap, so serving it here deliberately exercises
// the hub's chunked SunSpec read (lexa-proto sunspec.Reader.readChunked). A real
// certified inverter serves the full 701; the sim previously truncated to 121 to
// dodge the cap, which masked a real product bug (the hub could not read a
// spec-compliant 701) — do not re-truncate. Measurement values are seeded here
// and refreshed every tick by advMirror701.
func populate701(r *RegisterMap, cursor uint16) (base uint16, dataLen int, next uint16) {
	dataLen = sunspec.L701.Len() // 153: the full model 701 (>125 regs ⇒ forces a chunked read)
	base, next = writeModelHeader(r, cursor, sunspec.ModelDERMeasureAC, dataLen)
	regs := make([]uint16, dataLen)
	v := sunspec.L701.View(regs)
	// Scale factors (must be present so Float() decodes on the hub side).
	setSF(regs, sunspec.L701, "W_SF", 0)
	setSF(regs, sunspec.L701, "VA_SF", 0)
	setSF(regs, sunspec.L701, "Var_SF", 0)
	setSF(regs, sunspec.L701, "A_SF", 0)
	setSF(regs, sunspec.L701, "V_SF", -1)
	setSF(regs, sunspec.L701, "Hz_SF", -2)
	setSF(regs, sunspec.L701, "PF_SF", -4)
	setSF(regs, sunspec.L701, "TotWh_SF", 0)
	setSF(regs, sunspec.L701, "TotVarh_SF", 0)
	setSF(regs, sunspec.L701, "Tmp_SF", -1)
	v.SetEnum("ACType", 2) // three-phase
	v.SetEnum("St", 1)     // on
	v.SetEnum("InvSt", 4)  // MPPT-equivalent
	v.SetEnum("ConnSt", 1) // connected
	writeSlice(r, base, regs)
	return base, dataLen, next
}

// advSimCtrlModes is the 702 "supported control mode functions" bitfield this
// simulated DER declares — one bit per control function it actually publishes
// a model for, and nothing more.
//
// It exists because a capability claim stopped being optional. lexa-proto
// 87e246d (round-2 audit F2) made EVERY exported derbase writer require the
// positive M702 bit for the mode it is about to write, not just ApplyControl:
// before that, write704 asked only whether SOME declaration existed and the
// curve writers asked only for model presence, so a device declaring nothing
// had a fixed-PF setpoint written to it and a volt-var curve adopted and
// ENABLED on it.
//
// A zero-filled CtrlModes is not "unspecified" under that rule — it is the
// device positively declaring it performs no control function at all
// (derbase.CapClear), which denies every axis. A simulator that publishes
// 704/705/706/707/708/709/710/711/712 while declaring nothing is therefore not
// modelling a conformant DER; it is modelling one that contradicts itself, and
// every advanced test against it would quietly become a test of the refusal
// path instead of the path it was written for.
//
// Keep it in step with what this sim publishes: add a model above, add its bit
// here — the tests below will name whichever one was forgotten.
const advSimCtrlModes = sunspec.M702_CtrlMode_MaxW | sunspec.M702_CtrlMode_FixedW |
	sunspec.M702_CtrlMode_FixedVar | sunspec.M702_CtrlMode_FixedPF |
	sunspec.M702_CtrlMode_VoltVar | sunspec.M702_CtrlMode_VoltWatt |
	sunspec.M702_CtrlMode_WattVar | sunspec.M702_CtrlMode_FreqWatt |
	sunspec.M702_CtrlMode_LVTrip | sunspec.M702_CtrlMode_HVTrip |
	sunspec.M702_CtrlMode_LFTrip | sunspec.M702_CtrlMode_HFTrip

// populate702 writes a minimal model 702: WMax (so derbase reads the nameplate
// from 702), the reactive rating used as the fixed-var convergence base, and
// the CtrlModes capability declaration every 7xx writer now gates on.
func populate702(r *RegisterMap, cursor uint16, wmaxW, varRating float64) (base, next uint16) {
	dataLen := sunspec.L702.Len()
	base, next = writeModelHeader(r, cursor, sunspec.ModelDERCapacity, dataLen)
	regs := make([]uint16, dataLen)
	setSF(regs, sunspec.L702, "W_SF", 0)
	setSF(regs, sunspec.L702, "VA_SF", 0)
	setSF(regs, sunspec.L702, "Var_SF", 0)
	setSF(regs, sunspec.L702, "V_SF", 0)
	setSF(regs, sunspec.L702, "A_SF", 0)
	setSF(regs, sunspec.L702, "PF_SF", -4)
	setSF(regs, sunspec.L702, "S_SF", 0)
	v := sunspec.L702.View(regs)
	v.SetFloat("WMaxRtg", wmaxW)
	v.SetFloat("VAMaxRtg", wmaxW*1.05)
	v.SetFloat("VarMaxInjRtg", varRating)
	v.SetFloat("VarMaxAbsRtg", varRating)
	v.SetFloat("VNomRtg", 240)
	v.SetFloat("AMaxRtg", wmaxW/240)
	v.SetFloat("WMax", wmaxW)
	v.SetFloat("VAMax", wmaxW*1.05)
	v.SetFloat("VarMaxInj", varRating)
	v.SetFloat("VarMaxAbs", varRating)
	v.SetFloat("VNom", 240)
	v.SetU32("CtrlModes", advSimCtrlModes)
	writeSlice(r, base, regs)
	return base, next
}

// populate703 writes a model 703 (DER Enter Service) with a permit-to-operate
// enable and IEEE 1547-2018-typical default enter-service limits: voltage
// 91.7%-105% of the 240 V nominal the rest of this sim assumes (matches
// populate702's VNomRtg=240), frequency 59.5-60.1 Hz (matches the 60.00 Hz
// nominal the 103/701 animation runs around), a 300 s enter-service delay
// with a 300 s ramp, and a nonzero (but already-elapsed) randomized-delay
// window. The profile makes 703 unconditionally mandatory — unlike 713, its
// §3.5 Required Points table (Table 20) carries no conditionality clause —
// so every advanced/full sim serves it, not just the ones a scenario opts
// into. Every profile-required point (ES/ESVHi/ESVLo/ESHzHi/ESHzLo/
// ESDlyTms/ESRmpTms/V_SF/Hz_SF, profile1547.go's requiredPoints[703]) plus
// the two Table 21 optional timers (ESRndTms/ESDlyRemTms) are set explicitly
// so none reads back as not-implemented.
func populate703(r *RegisterMap, cursor uint16) (base, next uint16) {
	dataLen := sunspec.L703.Len()
	base, next = writeModelHeader(r, cursor, sunspec.ModelDEREnterService, dataLen)
	regs := make([]uint16, dataLen)
	setSF(regs, sunspec.L703, "V_SF", -1)
	setSF(regs, sunspec.L703, "Hz_SF", -2)
	v := sunspec.L703.View(regs)
	v.SetBool("ES", true)      // permit service — matches populate701's St=on/ConnSt=connected
	v.SetFloat("ESVHi", 252.0) // 1.05 x 240V nominal
	v.SetFloat("ESVLo", 220.0) // 0.917 x 240V nominal
	v.SetFloat("ESHzHi", 60.1)
	v.SetFloat("ESHzLo", 59.5)
	v.SetU32("ESDlyTms", 300)
	v.SetU32("ESRndTms", 60)
	v.SetU32("ESRmpTms", 300)
	v.SetU32("ESDlyRemTms", 0) // already in service: no delay remaining
	writeSlice(r, base, regs)
	return base, next
}

// populate704 writes a model 704 with every function disabled and its scale
// factors seeded. The hub read-modify-writes the whole block, so the SFs must be
// present before the first write.
func populate704(r *RegisterMap, cursor uint16) (base, next uint16) {
	dataLen := sunspec.L704.Len()
	base, next = writeModelHeader(r, cursor, sunspec.ModelDERCtlAC, dataLen)
	regs := make([]uint16, dataLen)
	setSF(regs, sunspec.L704, "PF_SF", -4)
	setSF(regs, sunspec.L704, "WMaxLimPct_SF", -2)
	setSF(regs, sunspec.L704, "WSet_SF", 0)
	setSF(regs, sunspec.L704, "WSetPct_SF", -2)
	setSF(regs, sunspec.L704, "VarSet_SF", 0)
	setSF(regs, sunspec.L704, "VarSetPct_SF", -2)
	v := sunspec.L704.View(regs)
	v.SetFloat("WMaxLimPct", 100) // 100% until the hub curtails
	writeSlice(r, base, regs)
	return base, next
}

// populateCurveModel writes one curve/control model (header + NCrv curves) with
// a non-trivial read-only live curve (index 0) and an empty staging curve
// (index 1). The default live curve is deliberately different from what QA
// scenarios command, so a successful adopt is observable as a change.
func populateCurveModel(r *RegisterMap, cursor uint16, spec curveModelSpec) (curveBlock, uint16) {
	stride := spec.crv.Len() + 2*spec.npt
	dataLen := spec.hdr.Len() + advNCrv*stride
	base, next := writeModelHeader(r, cursor, spec.id, dataLen)

	regs := make([]uint16, dataLen)
	h := spec.hdr.View(regs)
	if spec.hdr.Has("NPt") {
		h.SetEnum("NPt", uint16(spec.npt))
	}
	if spec.hdr.Has("NCrv") {
		h.SetEnum("NCrv", advNCrv)
	}
	if spec.hdr.Has("NCtl") {
		h.SetEnum("NCtl", advNCrv)
	}
	for name, sf := range spec.sfs {
		setSF(regs, spec.hdr, name, sf)
	}

	// Default live curve (index 0): read-only, non-empty.
	live := spec.hdr.Len()
	h.SetU16At(live+spec.crv.Offset("ReadOnly"), 1)
	if spec.npt > 0 {
		h.SetU16At(live+spec.crv.Offset("ActPt"), 2)
		if spec.crv.Has("DeptRef") {
			h.SetU16At(live+spec.crv.Offset("DeptRef"), 1)
		}
		if spec.crv.Has("Pri") {
			h.SetU16At(live+spec.crv.Offset("Pri"), 1)
		}
		// Two arbitrary flat-ish points (raw, since curve SFs are 0).
		pt := live + spec.crv.Len()
		y0, y1 := int16(5), int16(-5)
		h.SetU16At(pt+0, 100)        // x0
		h.SetU16At(pt+1, uint16(y0)) // y0
		h.SetU16At(pt+2, 200)        // x1
		h.SetU16At(pt+3, uint16(y1)) // y1
	} else {
		// Freq-droop control block (711): seed default droop parameters.
		h.SetScaledU32At(live+spec.crv.Offset("DbOf"), 0.05, "Db_SF")
		h.SetScaledU32At(live+spec.crv.Offset("DbUf"), 0.05, "Db_SF")
		h.SetScaledUintAt(live+spec.crv.Offset("KOf"), 20, "K_SF")
		h.SetScaledUintAt(live+spec.crv.Offset("KUf"), 20, "K_SF")
		h.SetScaledU32At(live+spec.crv.Offset("RspTms"), 5, "RspTms_SF")
	}

	writeSlice(r, base, regs)

	return curveBlock{
		id:      spec.id,
		base:    base,
		hdr:     spec.hdr,
		crv:     spec.crv,
		npt:     spec.npt,
		stride:  stride,
		hdrLen:  spec.hdr.Len(),
		reqOff:  spec.hdr.Offset(spec.reqField),
		rsltOff: spec.hdr.Offset(spec.rsltField),
		roOff:   spec.crv.Offset("ReadOnly"),
	}, next
}

// setSF writes a scale-factor register (int16) at a named layout offset in a
// model data slice.
func setSF(regs []uint16, l *sunspec.Layout, name string, sf int16) {
	off := l.Offset(name)
	if off >= 0 && off < len(regs) {
		regs[off] = uint16(sf)
	}
}

// ── Adopt handshake ──────────────────────────────────────────────────────────

// interceptAdopt handles a write to a curve model's AdptCrvReq/AdptCtlReq
// register: it performs (or, under curve_adopt_lies, only pretends to perform)
// the SunSpec §3.1.2 adoption. Returns true when it handled the write.
func (ss *SolarServer) interceptAdopt(startAddr uint16, vals []uint16) bool {
	if len(vals) == 0 {
		return false
	}
	for i := range ss.adv.Curves {
		cb := ss.adv.Curves[i]
		if startAddr == cb.base+uint16(cb.reqOff) {
			ss.applyAdopt(cb, vals[0])
			return true
		}
	}
	// The trip models (707-710) run the same §3.1.2 handshake over a different
	// geometry: a curve-SET rather than a curve, whose first register is the
	// ReadOnly flag (so roOff is 0) and whose stride is the whole three-
	// sub-curve set. Everything else — the 1-based staging index, the
	// COMPLETED result, the curve_adopt_lies fault — is shared with the curve
	// models by construction, because both call adoptInto.
	for i := range ss.adv.Trips {
		tb := ss.adv.Trips[i]
		if startAddr == tb.base+uint16(tb.reqOff) {
			ss.adoptInto(tb.base, tb.hdrLen, tb.setSize, 0, tb.rsltOff, vals[0])
			return true
		}
	}
	return false
}

// applyAdopt copies the staging curve (index req-1, i.e. the 1-based index the
// hub requests) into the read-only live curve (index 0) and reports COMPLETED —
// UNLESS curve_adopt_lies is armed, in which case it reports COMPLETED without
// the copy, leaving the live curve stale (the INV-ADV-READBACK divergence).
func (ss *SolarServer) applyAdopt(cb curveBlock, req uint16) {
	ss.adoptInto(cb.base, cb.hdrLen, cb.stride, cb.roOff, cb.rsltOff, req)
}

// adoptInto is the §3.1.2 adoption itself, expressed over the four numbers that
// are all any of these models differ by: where the block starts, how far past
// it the first curve (or curve-set) lives, how wide one of them is, and where
// its read-only flag sits.
//
// It is shared between the curve models (705/706/711/712) and the trip models
// (707-710) so the handshake — and the curve_adopt_lies fault that subverts it
// — has exactly one implementation. A second copy for the trip geometry would
// have been a second place for the "live entry is always read-only" rule to be
// forgotten, which is the rule the whole INV-ADV-READBACK defence rests on.
func (ss *SolarServer) adoptInto(base uint16, hdrLen, stride, roOff, rsltOff int, req uint16) {
	if req < 2 {
		return // §3.1.2 requires the 1-based staging index >1; ignore idle/invalid.
	}
	r := ss.Regs
	if !ss.faults.adoptLies() {
		stagingIdx := int(req) - 1
		src := base + uint16(hdrLen+stagingIdx*stride)
		dst := base + uint16(hdrLen) // live curve/curve-set is index 0
		for i := 0; i < stride; i++ {
			r.Set(dst+uint16(i), r.Get(src+uint16(i)))
		}
		r.Set(dst+uint16(roOff), 1) // the live entry is always read-only
	}
	r.Set(base+uint16(rsltOff), sunspec.AdptCompleted)
}

// ── Animation: 701 mirror + 704 effect ───────────────────────────────────────

func animateSolarAdvanced(s *Server, r *RegisterMap, wmaxW float64, bases SolarBases, adv solarAdvBases, varRating float64, cloud func() float64, fc *faultController, stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	var whAcc uint16

	// Seed 701 before the first tick so an immediately-read advanced sim is
	// coherent.
	advBridgeCeiling(r, bases, adv)
	advMirror701(r, bases, adv, wmaxW, varRating, fc)

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			// Bridge the hub's 704 ceiling into the 123 machinery BEFORE the
			// physical step, so curtailment (and its effect-time faults) apply.
			advBridgeCeiling(r, bases, adv)
			solarStep(r, wmaxW, bases, s.IsPaused(), s.simTime(), cloud(), fc, &whAcc)
			advMirror701(r, bases, adv, wmaxW, varRating, fc)
		}
	}
}

// advSync bridges the 704 ceiling and refreshes 701 outside the animation loop
// (used by the inject path so a paused advanced sim stays coherent).
func (ss *SolarServer) advSync() {
	advBridgeCeiling(ss.Regs, ss.bases, ss.adv)
	advMirror701(ss.Regs, ss.bases, ss.adv, ss.wmaxW, ss.varRating, &ss.faults)
}

// advBridgeCeiling mirrors an enabled 704 WMaxLimPct (the hub's advanced-path
// ceiling write) into the legacy 123 WMaxLimPct so the existing curtailment
// machinery (solarCeilingW + effect-time faults) applies it. When 704's ceiling
// is disabled it leaves 123 alone, so /inject-driven curtailment still works.
// Both registers are percent at SF −2, so the raw value copies directly. A hub
// release writes 100% (Ena stays 1), which flows through as full output.
func advBridgeCeiling(r *RegisterMap, bases SolarBases, adv solarAdvBases) {
	if r.Get(adv.M704+uint16(sunspec.L704.Offset("WMaxLimPctEna"))) != 1 {
		return
	}
	pctRaw := r.Get(adv.M704 + uint16(sunspec.L704.Offset("WMaxLimPct")))
	r.Set(bases.M123Base+sunspec.M123_WMaxLimPct, pctRaw)
	r.Set(bases.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
}

// advMirror701 writes the 701 measurement model from the 103 physical state the
// legacy animation just computed, applying the 704 fixed-PF / fixed-var effect
// to PF/Var and stamping the current raise_alarm bits into Alrm — deriving
// the voltage/frequency points those bits claim from advCoupledVoltHz first
// (see its doc), so a voltage or frequency alarm bit is never left backed by
// a nominal reading.
//
// THE MIRROR MUST NOT BE LOSSY. This model declares ACType = THREE_PHASE, and
// the 103 it mirrors from is a genuinely three-phase animation: it writes
// PhVph{A,B,C} together, derives PPVph{AB,BC,CA} as sqrt(3)x that, and splits
// current as Aph{A,B,C} = A/3. For a long time this function copied only the
// phase-A voltage into LNV and VL1 and left the other six voltage points — LLV,
// VL1L2, VL2, VL2L3, VL3, VL3L1 — plus every per-phase power point unwritten.
//
// Unwritten is not harmless here. The register map is zero-initialised, so those
// points read 0x0000, which in SunSpec is an IMPLEMENTED value of zero, not the
// 0xFFFF "not implemented" sentinel. The device was therefore asserting 0.0 V
// line-to-line and 0.0 V on phases B and C while declaring three phases — a
// physically impossible machine, and one that a conformant gateway is obliged to
// mirror faithfully onward. It also fails the IEEE 1547-2018 profile §3.3
// Table 17 rule that "the voltage points that are applicable must be
// implemented", where applicability is decided by exactly the ACType this
// function sets (conformance case MOD-4 step 3).
//
// Everything below is now derived from the same balanced-three-phase model the
// 103 animation already uses, and the line-to-line voltages are READ from the
// 103's own PPVph registers rather than recomputed, so the two models can never
// again disagree about the same physical quantity.
func advMirror701(r *RegisterMap, bases SolarBases, adv solarAdvBases, wmaxW, varRating float64, fc *faultController) {
	m103 := bases.M103Base
	sfAt := func(a uint16) int16 { return int16(r.Get(a)) }
	w := sunspec.ApplyScaleSigned(r.Get(m103+sunspec.M103_W), sfAt(m103+sunspec.M103_W_SF))
	vSF := sfAt(m103 + sunspec.M103_V_SF)
	volt := sunspec.ApplyScaleUint(r.Get(m103+sunspec.M103_PhVphA), vSF)
	voltB := sunspec.ApplyScaleUint(r.Get(m103+sunspec.M103_PhVphB), vSF)
	voltC := sunspec.ApplyScaleUint(r.Get(m103+sunspec.M103_PhVphC), vSF)
	vAB := sunspec.ApplyScaleUint(r.Get(m103+sunspec.M103_PPVphAB), vSF)
	vBC := sunspec.ApplyScaleUint(r.Get(m103+sunspec.M103_PPVphBC), vSF)
	vCA := sunspec.ApplyScaleUint(r.Get(m103+sunspec.M103_PPVphCA), vSF)
	hz := sunspec.ApplyScaleUint(r.Get(m103+sunspec.M103_Hz), sfAt(m103+sunspec.M103_Hz_SF))
	tmp := sunspec.ApplyScaleSigned(r.Get(m103+sunspec.M103_TmpCab), sfAt(m103+sunspec.M103_Tmp_SF))
	amp := sunspec.ApplyScaleSigned(r.Get(m103+sunspec.M103_A), sfAt(m103+sunspec.M103_A_SF))
	conn := r.Get(bases.M123Base + sunspec.M123_Conn)
	st103 := r.Get(m103 + sunspec.M103_St)

	// raise_alarm coupling (advCoupledVoltHz): read the armed bits ONCE and
	// reuse the same snapshot both to derate volt/hz below and to stamp Alrm
	// further down, so a single fault-controller read decides both
	// consistently — no window where the bit is set but the derived reading
	// has not caught up (or vice versa). A balanced three-phase machine
	// cannot have one phase off-nominal while its neighbours and the
	// line-to-line points sit at the healthy value, so an armed voltage
	// condition scales ALL six voltage points by the same ratio — the same
	// coupling Inject "V_V" already applies for an operator-injected voltage.
	alrm := fc.alarmBits()
	if cv, ch := advCoupledVoltHz(alrm, volt, hz); cv != volt || ch != hz {
		if cv != volt && volt != 0 {
			ratio := cv / volt
			volt, voltB, voltC = cv, voltB*ratio, voltC*ratio
			vAB, vBC, vCA = vAB*ratio, vBC*ratio, vCA*ratio
		}
		hz = ch
	}

	// Free-running PF/var the legacy 103 animation just wrote (the accept-but-
	// ignore fallback for pf_ack_ignore / no 704 reactive command).
	freePF := sunspec.ApplyScaleSigned(r.Get(m103+sunspec.M103_PF), sfAt(m103+sunspec.M103_PF_SF)) / 100.0
	freeVar := sunspec.ApplyScaleSigned(r.Get(m103+sunspec.M103_VAr), sfAt(m103+sunspec.M103_VAr_SF))

	pf, varPwr := advReactive(r, adv, varRating, w, freePF, freeVar, fc)
	va := math.Abs(w)
	if pf > 0 {
		va = math.Abs(w) / pf
	}

	regs := readSlice(r, adv.M701, adv.M701Len)
	v := sunspec.L701.View(regs)
	v.SetEnum("ACType", 2)
	if conn == 0 || st103 == 1 { // disconnected / off
		v.SetEnum("St", 0)
		v.SetEnum("ConnSt", 0)
	} else {
		v.SetEnum("St", 1)
		v.SetEnum("ConnSt", 1)
	}
	v.SetEnum("InvSt", uint16(st103))
	v.SetU32("Alrm", alrm)
	v.SetFloat("W", w)
	v.SetFloat("VA", va)
	v.SetFloat("Var", varPwr)
	v.SetFloat("PF", pf)
	v.SetFloat("A", math.Abs(amp))
	v.SetFloat("Hz", hz)
	v.SetFloat("TmpCab", tmp)
	v.SetFloat("ThrotPct", 0)

	// Voltages. LNV is the aggregate line-to-neutral figure and LLV the
	// aggregate line-to-line one; the six per-phase points carry the same
	// quantities phase by phase. All of them are mirrored from the 103's own
	// registers — never recomputed here — so the two models cannot drift apart,
	// including under an injected V_V (which moves the 103's L-N and L-L
	// registers together).
	v.SetFloat("LNV", volt)
	v.SetFloat("VL1", volt)
	v.SetFloat("VL2", voltB)
	v.SetFloat("VL3", voltC)
	v.SetFloat("LLV", vAB)
	v.SetFloat("VL1L2", vAB)
	v.SetFloat("VL2L3", vBC)
	v.SetFloat("VL3L1", vCA)

	// Per-phase power and current. The animation is a BALANCED machine — the
	// 103 writes equal phase voltages and equal phase currents (Aph{A,B,C} =
	// A/3) — so each phase carries one third of the aggregate real, apparent and
	// reactive power at the common power factor. Leaving these at 0 while W read
	// several kW made the per-phase and aggregate halves of the same model
	// contradict each other.
	third := 1.0 / 3.0
	for _, p := range []struct{ w, va, vr, pf, a string }{
		{"WL1", "VAL1", "VarL1", "PFL1", "AL1"},
		{"WL2", "VAL2", "VarL2", "PFL2", "AL2"},
		{"WL3", "VAL3", "VarL3", "PFL3", "AL3"},
	} {
		v.SetFloat(p.w, w*third)
		v.SetFloat(p.va, va*third)
		v.SetFloat(p.vr, varPwr*third)
		v.SetFloat(p.pf, pf)
		v.SetFloat(p.a, math.Abs(amp)*third)
	}
	writeSlice(r, adv.M701, regs)
}

// advReactive computes the inverter's power factor and reactive power (var) for
// the current real power w, honouring an active 704 fixed-PF / fixed-var
// command. With pf_ack_ignore armed — or no 704 reactive command — it returns
// the free-running (freePF, freeVar) the legacy 103 model carries, so the
// measured PF/var does NOT move off its natural value (accept-but-ignore).
func advReactive(r *RegisterMap, adv solarAdvBases, varRating, w, freePF, freeVar float64, fc *faultController) (pf, varPwr float64) {
	if fc.pfIgnored() {
		return freePF, freeVar
	}
	v := sunspec.L704.View(readSlice(r, adv.M704, sunspec.L704.Len()))
	switch {
	case v.Bool("VarSetEna"):
		pct := v.Float("VarSetPct")
		if math.IsNaN(pct) {
			pct = 0
		}
		varPwr = pct / 100.0 * varRating
		denom := math.Hypot(w, varPwr)
		if denom > 0 {
			pf = math.Abs(w) / denom
		} else {
			pf = 1
		}
		return pf, varPwr
	case v.Bool("PFWInjEna"):
		pf = v.Float("PFWInj_PF")
		ext, _ := v.Enum("PFWInj_Ext")
		return pf, pfVar(w, pf, ext == sunspec.M704_Ext_UnderExcited)
	case v.Bool("PFWAbsEna"):
		pf = v.Float("PFWAbs_PF")
		ext, _ := v.Enum("PFWAbs_Ext")
		return pf, pfVar(w, pf, ext == sunspec.M704_Ext_UnderExcited)
	}
	return freePF, freeVar
}

// pfVar returns the reactive power for real power w at power factor pf.
// underExcited flips the sign (absorbing rather than injecting vars).
func pfVar(w, pf float64, underExcited bool) float64 {
	if pf <= 0 || pf > 1 || math.IsNaN(pf) {
		return 0
	}
	mag := math.Abs(w) * math.Tan(math.Acos(pf))
	if underExcited {
		return -mag
	}
	return mag
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

// SolarAdvancedState is the 7xx ground truth exposed on GET /state (advanced sim
// only), so QA oracles can read the sim's real 701 measurement, 704 command
// readback, and live curve points without a Modbus client.
type SolarAdvancedState struct {
	Alrm       uint32          `json:"Alrm"`
	Meas701    adv701Meas      `json:"meas_701"`
	FixedPF    advPFState      `json:"fixed_pf"`
	FixedVar   advVarState     `json:"fixed_var"`
	Ceiling704 advCeilState    `json:"wmaxlimpct_704"`
	Curves     []advCurveState `json:"curves"`
	// Trips is the 707-710 ground truth, omitted entirely on a sim that does
	// not serve them so /state stays byte-identical for every existing
	// scenario. See trip1547.go.
	Trips []advTripState `json:"trips,omitempty"`
}

type adv701Meas struct {
	W_W     float64 `json:"W_W"`
	PF      float64 `json:"PF"`
	VAr_var float64 `json:"VAr_var"`
	Hz_Hz   float64 `json:"Hz_Hz"`
	St      int     `json:"St"`
	ConnSt  int     `json:"ConnSt"`
}

type advPFState struct {
	Ena bool    `json:"ena"`
	PF  float64 `json:"pf"`
}

type advVarState struct {
	Ena bool    `json:"ena"`
	Pct float64 `json:"pct"`
}

type advCeilState struct {
	Ena bool    `json:"ena"`
	Pct float64 `json:"pct"`
}

type advCurveState struct {
	Model     uint16       `json:"model"`
	AdoptRslt int          `json:"adopt_rslt"`
	ReadOnly  bool         `json:"read_only"`
	Points    [][2]float64 `json:"points"`
}

// advSnapshot reads the advanced models into a JSON-serialisable snapshot.
func (ss *SolarServer) advSnapshot() *SolarAdvancedState {
	r := ss.Regs
	out := &SolarAdvancedState{}

	m701 := sunspec.Parse701(readSlice(r, ss.adv.M701, ss.adv.M701Len))
	out.Alrm = m701.Alrm
	out.Meas701 = adv701Meas{
		W_W: m701.W, PF: m701.PF, VAr_var: m701.Var, Hz_Hz: m701.Hz,
		St: int(m701.St), ConnSt: int(m701.ConnSt),
	}

	c704 := sunspec.Parse704(readSlice(r, ss.adv.M704, sunspec.L704.Len()))
	out.FixedPF = advPFState{Ena: c704.PFWInjEna, PF: c704.PFWInjPF}
	out.FixedVar = advVarState{Ena: c704.VarSetEna, Pct: c704.VarSetPct}
	out.Ceiling704 = advCeilState{Ena: c704.WMaxLimPctEna, Pct: c704.WMaxLimPct}

	for _, cb := range ss.adv.Curves {
		cs := advCurveState{
			Model:     cb.id,
			AdoptRslt: int(r.Get(cb.base + uint16(cb.rsltOff))),
			ReadOnly:  r.Get(cb.base+uint16(cb.hdrLen)+uint16(cb.roOff)) == 1,
		}
		cs.Points = liveCurvePoints(r, cb)
		out.Curves = append(out.Curves, cs)
	}
	out.Trips = ss.tripSnapshot()
	return out
}

// liveCurvePoints reads the live curve's (index 0) point pairs as raw values.
// Returns nil for the point-less 711 control model.
func liveCurvePoints(r *RegisterMap, cb curveBlock) [][2]float64 {
	if cb.npt == 0 {
		return nil
	}
	live := cb.base + uint16(cb.hdrLen)
	actPt := int(r.Get(live + uint16(cb.crv.Offset("ActPt"))))
	if actPt > cb.npt {
		actPt = cb.npt
	}
	pts := make([][2]float64, actPt)
	pbase := live + uint16(cb.crv.Len())
	for j := 0; j < actPt; j++ {
		x := r.Get(pbase + uint16(2*j))
		y := int16(r.Get(pbase + uint16(2*j+1)))
		pts[j] = [2]float64{float64(x), float64(y)}
	}
	return pts
}
