package sim

// battery_pack.go — THE BENCH BATTERY PACK, in the two shapes the gateway's
// fail-safe posture is a function of.
//
// # Why this file exists
//
// Every review round since IW3 has closed with the same sentence, and
// lexa-gw's docs/known_issues.json BENCH-000 now repeats it three times:
// THE BENCH HAS NO BATTERY-SHAPED SIMULATOR. Both 7xx bench devices are
// inverters and the 704-less shape exists there only as an inverter
// (`modsim -der-models legacy`, registered as inv-legacy, der_gen "12x"), so
// nothing on the bench answers as role "battery" at all. RMD-025 (the
// shape-aware battery fail-safe) and RMD-028 (durable cease ownership) are
// therefore both Go-proven and bench-unproven, and SIX named rows are queued
// behind the gap: (e) cease posture on a 704-less pack, (f) reconnect on
// release, (g) the admission refusal against firmware that leaves Conn
// unimplemented, (h) the setpoint-shape regression, (j) a pre-disconnected
// pack at boot, (k) ownership across a real rail drop.
//
// The existing battery sims cannot stand in for it, and the reason is written
// into battery_adv.go's own file comment: its 704 "is NOT wired to physical
// effect ... a 704 write still round-trips correctly, it just does not
// additionally command the pack." A device that ACKs a setpoint, echoes it
// back, and never moves is not a battery — it is the ack_no_apply FAULT with
// no way to turn it off. Every setpoint-convergence row run against it would
// have measured the gateway's handling of a lying device while believing it
// measured convergence.
//
// # The two shapes
//
// The names are the gateway's own vocabulary — lexa-gw internal/topics'
// FailsafePostureSetpointZero / FailsafePostureCease, the value that rides on
// InventoryRecord.FailsafePosture — because the shape IS the posture. Naming
// the sim mode after the posture it will be measured to have is the whole
// point: an operator reading a bench log should not have to translate.
//
//	PackShapeSetpoint ("setpoint-zero")   1/120/121/103/123/802 + 701/702/703/704/713
//	    The 704-capable pack. M702 declares FIXED_W, M704 WSet is BRIDGED TO
//	    PHYSICAL EFFECT, and the fail-safe posture the gateway will measure is
//	    "idle at zero without leaving service".
//
//	PackShapeCease ("cease")              1/120/121/103/123/802
//	    The 704-LESS pack. No register expresses a setpoint of either sign, so
//	    the only executable containment is a physical cease through M123 Conn —
//	    which this shape implements, drives, and PROVES on both of the axis's
//	    two sides (the register reads back disconnected AND measured power
//	    collapses into the cessation band).
//
// Both shapes leave M123 Conn IMPLEMENTED. A pack that leaves it at the 0xFFFF
// sentinel is admission row (g), and it is reachable on either shape with
// `POST /fault {"kind":"sentinel_field","fields":["Conn"],"value":65535}`
// rather than by a third register image.
//
// # The WSet bridge — the piece the advanced battery lacks
//
// packBridgeSetpoint is the mirror of solar_adv.go's advBridgeCeiling, one axis
// over: an ENABLED 704 control is copied into the legacy 123
// machinery the pack's physics already runs on (hubBatteryW's signed
// WMaxLimPct convention: negative = charge, positive = discharge), so the
// SAME animation, the SAME SoC integration and the SAME effect-time faults
// apply to a 704 setpoint as to a legacy dispatch. Bridging rather than
// re-deriving is what keeps one physics: two independent power derivations
// would be two chances for /state and the wire to disagree about what the
// pack is doing, which is the divergence this simulator exists to make
// visible, not to contain.
//
// The bridge differs from the ceiling one in three ways, each of them the
// battery's nature rather than an implementation choice:
//
//   - It is SIGNED. A ceiling is a magnitude; a setpoint has a direction, and
//     the direction is the whole difference between charging and discharging.
//     WSet is watts (Tint32, "PRODUCE THIS"), so the bridge converts to the
//     123 point's signed percent-of-nameplate rather than copying a raw.
//   - It honours WSetMod. A head end may command watts or percent-of-max; both
//     land in the same physical quantity.
//   - The pack RAMPS. Measured power slews toward the commanded value at a
//     bounded rate instead of jumping, because an inverter does. That is not
//     decoration: it is what makes "commanded but not yet converged" a state
//     the bench can actually observe, and therefore what makes the gateway's
//     pending/converged/diverged machinery testable against something other
//     than an instantaneous device that is always already converged.
//
// A CONTACTOR IS NOT A RAMP, though. Conn=0 collapses measured power in the
// same tick — and on the write itself, so a paused pack still ceases. A cease
// that took 15 seconds to slew would put the sim inside the gateway's own
// settle window and make a correct cease look like a slow one.
//
// SOLAR HAS ITS OWN SETPOINT AXIS NOW (IW15-001), and it deliberately does NOT
// copy the fold above: an inverter's WSet is a THIRD term in solarStep's
// min(available, ceiling, setpoint) rather than a value transcoded into the
// M123 ceiling cell. The fold is right here — a pack's one physics IS the
// signed-percent dispatch, and the setpoint is the only thing driving it — and
// wrong there, where the ceiling register is the evidence a "a limit is not a
// setpoint" row reads back. Same defect closed on both sims, two different
// shapes, for reasons that are about the devices. See solarSetpointW.
//
// # What the ratings say, and why they are real
//
// solar_adv.go's populate702 leaves WChaRteMaxRtg/WDisChaRteMaxRtg at the
// not-implemented sentinel, and its comment says exactly what a storage
// profile must do instead: "it should write a real rating here, symmetric
// between the two directions unless the device truly is asymmetric, so the
// rating bound itself becomes exercisable rather than merely absent. No such
// profile exists in this sim yet; when one does, wire it to populate a real
// WChaRteMaxRtg/WDisChaRteMaxRtg pair instead of calling setNotImpl16." This
// is that profile. The pair is ASYMMETRIC (charge rating well below the
// discharge rating — packChaRteRatingFrac/packDisChaRteRatingFrac, since
// IW14-001 made the gateway resolve each opModFixedW sign against its own
// rating) and both STRICTLY BELOW the nameplate, which is what makes the
// bounds independently exercisable: a setpoint past the nameplate is refused by
// checkSetpointWithinNameplate, a setpoint between the rating and the
// nameplate is refused by validateSetpointW's rating bound, and the two
// refusals name different points. Equal ratings would make the second
// unreachable — the first check runs first — so the bound would ship
// untested. The pack also CLAMPS its own physical output to those ratings, so
// they are a fact about the device rather than a claim in a register: a
// direct write past the rating (one that never went through a gateway) is
// answered by a pack that does what it said it could do and no more.
//
// The APPARENT-power rate ratings stay at the sentinel, honestly: this profile
// models a real-power pack and does not model a VA charge/discharge rate, and
// setNotImpl16's own doc is the standard for saying so — a Tuint16 zero is
// IMPLEMENTED data declaring an incapacity, not an absence.
//
// # Faults
//
// Both shapes install the LYING-DEVICE layer (lying.go) that until now only
// the solar sims had, with the pack's control registers NAMED so the write
// path is targetable: "Conn" on both shapes, plus "WSet"/"WSetEna" on the
// setpoint shape. That is what makes the ack_no_apply rows expressible —
// a cease that ACKs and never opens the contactor, a setpoint that ACKs and
// never latches — which are the two false-Applied shapes the gateway's
// two-sided proofs exist to catch. freeze_block and sentinel_field ride the
// same layer, and the effect-time battery faults from faults.go
// (soc_refuse / charge_disabled / discharge_disabled) still shape the
// commanded power exactly as they always have, now including a power
// commanded through 704.
//
// Idle-at-zero needs no fault at all and deliberately so: a pack at SoC 100 %
// commanded to charge, or at 0 % commanded to discharge, holds a genuine 0 W
// through clampToSoC and reports ChaSt FULL/EMPTY. becalm/Night is a solar
// concept (a dark inverter) and has no battery analogue — a pack that is idle
// is idle because of its state of charge or because nobody asked it for
// anything, and both are reachable here without pretending it is night.

import (
	"fmt"
	"log"
	"math"
	"sync/atomic"
	"time"

	"lexa-proto/sunspec"
)

// BatteryPackShape names a pack register image by the fail-safe posture the
// gateway will MEASURE it to have. The string values are lexa-gw
// internal/topics' FailsafePostureSetpointZero / FailsafePostureCease
// verbatim, so a bench log and an InventoryRecord say the same word.
type BatteryPackShape string

const (
	// PackShapeSetpoint is the 704-capable pack: a setpoint of either sign is
	// expressible, so containment is "idle at zero" and the pack never leaves
	// service to be contained.
	PackShapeSetpoint BatteryPackShape = "setpoint-zero"
	// PackShapeCease is the 704-less pack: no register expresses a setpoint,
	// so containment is a physical cease through M123 Conn.
	PackShapeCease BatteryPackShape = "cease"
)

const (
	// packRampFrac is how much of nameplate the pack's measured power may move
	// in one animation tick. A real pack slews; more to the point, a pack that
	// jumps is a pack whose commanded state is ALWAYS already converged, and a
	// bench made of such devices can never exercise the gateway's
	// pending-then-converged path (or its diverged one). At 0.34 a full
	// zero-to-nameplate swing takes three ticks — long enough that the
	// intermediate state is observable, short enough that a bench row does not
	// wait a minute for it.
	packRampFrac = 0.34

	// packChaRteRatingFrac / packDisChaRteRatingFrac set the pack's declared
	// (and honoured) charge and discharge rate ratings as fractions of
	// nameplate. Both STRICTLY BELOW 1 so the M702 rating bound is exercisable
	// independently of the nameplate bound — see this file's header. They are
	// deliberately ASYMMETRIC (charge well below discharge) since IW14-001:
	// the gateway resolves a negative opModFixedW against WChaRteMaxRtg and a
	// positive one against WDisChaRteMaxRtg, and only asymmetric ratings make
	// the three possible references (charge rating, discharge rating,
	// nameplate) produce mutually distinguishable watts on the wire — with the
	// 5000 W default nameplate: −60% → −1200 W (charge rating 2000), +60% →
	// +2700 W (discharge rating 4500), vs ±3000 W on a nameplate fallback.
	packChaRteRatingFrac    = 0.40
	packDisChaRteRatingFrac = 0.90

	// packTickSeconds is the animation period, matching every other sim here.
	packTickSeconds = 5.0

	// packIdleBandFrac is the |W| below which the pack counts as idle for its
	// own ChaSt/St reporting — the same 2 % of nameplate animateBattery has
	// always used.
	packIdleBandFrac = 0.02
)

// M802 State (operational state) enum values this profile uses. Model 802's
// State is a Tenum16 whose codes are defined by the model, not by the parse
// layer, which is why lexa-proto/sunspec carries no vocabulary for them (same
// reasoning as solar_adv.go's alrm701* bit constants).
const (
	m802StateDisconnected uint16 = 1
	m802StateConnected    uint16 = 3
)

// M802 ChaSt (charge status) enum values, same provenance as above. OFF and
// EMPTY/FULL are the three animateBattery never reaches, and they are exactly
// the three a pack needs: a disconnected pack is OFF, and idle-at-zero is
// FULL or EMPTY rather than the HOLDING the demo animation reports.
const (
	m802ChaStOff       uint16 = 1
	m802ChaStEmpty     uint16 = 2
	m802ChaStFull      uint16 = 5
	m802ChaStHolding   uint16 = 6
	m802ChaStDischarge uint16 = 3
	m802ChaStCharge    uint16 = 4
)

// packProfile is everything about a pack that the legacy battery machinery
// does not already know: which shape it is, where its 7xx models live, how
// fast it slews, and what it declared it can do.
type packProfile struct {
	shape BatteryPackShape
	// has704 is the shape predicate every branch in this file gates on. It is
	// not derived from shape at each use so that a future third shape cannot
	// silently pick up 704 behaviour by naming.
	has704 bool
	adv    batteryAdvBases // zero on the cease shape
	m702   uint16          // 0 on the cease shape
	m703   uint16          // 0 on the cease shape

	rampW         float64 // max change in measured W per animation tick
	chaRteMaxW    float64 // declared AND honoured max charge rate (magnitude)
	disChaRteMaxW float64 // declared AND honoured max discharge rate
}

// NewBatteryPack starts the 704-CAPABLE bench pack: the setpoint-zero shape,
// serving 1/120/121/103/123/802 plus 701/702/703/704/713, with 704 WSet
// bridged to physical effect. This is the device BENCH-000 rows (h) and
// "setpoint convergence (battery sim mode w/ 704 WSet bridge)" are written
// against.
func NewBatteryPack(listenURL string, wmaxKwh, wmaxW float64) (*BatteryServer, error) {
	return newBatteryPack(listenURL, wmaxKwh, wmaxW, PackShapeSetpoint)
}

// NewBatteryPackLegacy starts the 704-LESS bench pack: the cease shape,
// serving 1/120/121/103/123/802 with M123 Conn implemented and driven. This
// is the device BENCH-000 rows (e), (f), (j) and (k) are written against.
func NewBatteryPackLegacy(listenURL string, wmaxKwh, wmaxW float64) (*BatteryServer, error) {
	return newBatteryPack(listenURL, wmaxKwh, wmaxW, PackShapeCease)
}

func newBatteryPack(listenURL string, wmaxKwh, wmaxW float64, shape BatteryPackShape) (*BatteryServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, pk, end := populateBatteryPack(regs, wmaxKwh, wmaxW, shape)

	bs := &BatteryServer{
		bases: bases, wmaxW: wmaxW, wmaxKwh: wmaxKwh,
		pack: pk, regEnd: end, advanced: pk.has704, adv: pk.adv,
	}
	bs.faults.label = "battery"
	bs.faults.configureGate(bases.M123Base + sunspec.M123_WMaxLimPct_Ena)
	bs.faults.configureScale(bases.M103Base + sunspec.M103_W_SF)

	// Hooks installed BEFORE the Modbus server starts, per finding MOD-3.
	regs.OnWrite = bs.packOnWrite
	regs.OnWriteAttempt = bs.interceptWrite
	regs.OnRead = bs.faults.transportRead
	bs.initPackReversion(regs)

	srv, err := newAnimatedServer(listenURL, regs, func(s *Server, r *RegisterMap, stop <-chan struct{}) {
		animateBatteryPack(s, r, wmaxW, wmaxKwh, bases, pk, &bs.pendingSoC, &bs.faults, stop)
	})
	if err != nil {
		return nil, err
	}
	bs.Server = srv
	bs.installBatteryLies() // the lying-device layer, in front of the fault hooks
	if bs.rvrt != nil {
		// The reversion timer gets its OWN goroutine — it is not part of the
		// physics tick and must not inherit its 5 s granularity (see
		// packReversionLoop) — and it is started LAST, deliberately. The
		// animation goroutine is running before bs.Server is assigned and
		// before the lying layer is wrapped around the hooks; a loop started in
		// there would reach bs.Regs (a promoted field of a not-yet-assigned
		// *Server) and race installBatteryLies' hook swap. Its lifetime is
		// still the server's, through the same stop channel Stop closes.
		go bs.packReversionLoop(srv.stop)
	}
	return bs, nil
}

// StartDisconnected opens the pack's contactor before any client can dial in —
// the register-image equivalent of a technician locking the pack out at the
// cabinet, which is the precondition of BENCH-000 row (j) (a PRE-DISCONNECTED
// PACK AT BOOT, which the gateway must leave alone because it owns no record
// of having disconnected it). Doing it here rather than through a post-start
// POST /inject removes the race in which the gateway dials, reads a connected
// pack, and adopts it before the injection lands.
func (bs *BatteryServer) StartDisconnected() {
	bs.Regs.Set(bs.bases.M123Base+sunspec.M123_Conn, 0)
	bs.packSync()
}

// ── Populate ─────────────────────────────────────────────────────────────────

// populateBatteryPack writes a pack register image and returns the model
// bases, the profile, and the last register the image occupies.
func populateBatteryPack(r *RegisterMap, wmaxKwh, wmaxW float64, shape BatteryPackShape) (BatteryBases, *packProfile, uint16) {
	bases, cursor := populateBatteryCore(r, wmaxKwh, wmaxW)

	pk := &packProfile{
		shape:         shape,
		has704:        shape == PackShapeSetpoint,
		rampW:         packRampFrac * wmaxW,
		chaRteMaxW:    packChaRteRatingFrac * wmaxW,
		disChaRteMaxW: packDisChaRteRatingFrac * wmaxW,
	}

	// The rate ratings are a fact about the pack, so every model that carries
	// them says the same number. populateBatteryCore seeds M120's MaxChaRte/
	// MaxDisChaRte and M802's WChaRteMax/WDisChaRteMax at the full nameplate,
	// which is right for the demo battery and wrong for a pack that declares
	// (and honours) a lower rate — a device contradicting itself across two
	// models is a defect this sim exists to inject deliberately, never to ship
	// by accident.
	r.Set(bases.M120Base+sunspec.M120_MaxChaRte, uint16(math.Round(pk.chaRteMaxW)))
	r.Set(bases.M120Base+sunspec.M120_MaxDisChaRte, uint16(math.Round(pk.disChaRteMaxW)))
	r.Set(bases.M802Base+uint16(sunspec.M802_WChaRteMax), uint16(math.Round(pk.chaRteMaxW)))
	r.Set(bases.M802Base+uint16(sunspec.M802_WDisChaRteMax), uint16(math.Round(pk.disChaRteMaxW)))
	// A pack powers on IN SERVICE and idle: contactor closed, no standing
	// dispatch. populateBatteryCore already leaves Conn=1 and Ena=0; naming it
	// here is the resting position this profile's reboot_forget restores to.
	r.Set(bases.M123Base+sunspec.M123_Conn, 1)

	if pk.has704 {
		pk.adv, pk.m702, pk.m703, cursor = populateBatteryPack7xx(r, cursor, wmaxKwh, wmaxW, pk)
	}
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)
	return bases, pk, cursor + 1
}

// populateBatteryPack7xx appends the setpoint shape's advanced models after
// the legacy layout, in chain order 701 → 702 → 703 → 704 → 713.
//
// It is a SEPARATE function from battery_adv.go's populateBattery7xx rather
// than a widening of it, for the reason NewSolarServerTrip gives one file
// over: mbapsdev's battery mode serves 701/704/713 and nothing else, and
// adding 702/703 there would lengthen the SunSpec chain every T06.3 scenario
// walks. The overlap is three shared populate calls, not a shared image.
func populateBatteryPack7xx(r *RegisterMap, cursor uint16, wmaxKwh, wmaxW float64, pk *packProfile) (
	adv batteryAdvBases, m702, m703, next uint16) {

	adv.M701, adv.M701Len, cursor = populate701(r, cursor)
	m702, cursor = populate702Pack(r, cursor, wmaxW, wmaxW*0.44, pk)
	m703, cursor = populate703(r, cursor)
	adv.M704, cursor = populate704(r, cursor)
	adv.M713, cursor = populate713(r, cursor, wmaxKwh)
	seedPackReversionDestinations(r, adv.M704)

	// SF write-protection (protect.go), derived from the layouts themselves —
	// see solar_adv.go's populateSolar7xx for the rationale.
	protectLayoutSFs(r, adv.M701, sunspec.L701)
	protectLayoutSFs(r, m702, sunspec.L702)
	protectLayoutSFs(r, m703, sunspec.L703)
	protectLayoutSFs(r, adv.M704, sunspec.L704)
	protectLayoutSFs(r, adv.M713, sunspec.L713)
	return adv, m702, m703, cursor
}

// packCtrlModes is the pack's M702 "supported control mode functions"
// declaration: one bit per control function it actually publishes a model for,
// and nothing more (advSimCtrlModes' rule, and its doc explains at length why
// a zero-filled CtrlModes is a positive denial rather than an absence).
//
// This pack publishes 704 and no curve or trip models, so it claims the four
// axes 704 carries and none of the curve ones. FIXED_W is the load-bearing bit:
// lexa-gw's admission gate (internal/southbound/admission's
// BatterySetpointRefusal) requires M704 AND a positive FIXED_W claim before it
// will admit a battery under the setpoint-zero posture, and a pack that
// published 704 while declaring nothing would be admitted under the CEASE
// posture instead — a shape mismatch that would look like a gateway bug.
const packCtrlModes = sunspec.M702_CtrlMode_MaxW | sunspec.M702_CtrlMode_FixedW |
	sunspec.M702_CtrlMode_FixedVar | sunspec.M702_CtrlMode_FixedPF

// populate702Pack writes the pack's model 702: the nameplate derbase reads,
// the reactive rating, the CtrlModes capability declaration, and — the part
// solar's populate702 explicitly defers to a storage profile — a REAL,
// ASYMMETRIC charge/discharge rate rating pair (2 000 W in, 4 500 W out on the
// default 5 kW nameplate). The asymmetry is load-bearing rather than colour: a
// signed opModFixedW resolves against the rating for the direction commanded,
// so equal ratings would make every candidate reference produce the same watts
// and hide a reference confusion in the product AND in the referee. See this
// file's header and packChaRteRatingFrac/packDisChaRteRatingFrac.
func populate702Pack(r *RegisterMap, cursor uint16, wmaxW, varRating float64, pk *packProfile) (base, next uint16) {
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
	v.SetU32("CtrlModes", packCtrlModes)

	// THE STORAGE FORK solar_adv.go's populate702 names. Real, asymmetric
	// (charge below discharge, per-sign references distinguishable), and both
	// below the nameplate so the bound is reachable — see this file's header.
	// The RW settings carry the same numbers as the read-only ratings: this
	// pack is configured at its full declared capability, so a head end that
	// reads either pair gets the same answer.
	v.SetFloat("WChaRteMaxRtg", pk.chaRteMaxW)
	v.SetFloat("WDisChaRteMaxRtg", pk.disChaRteMaxW)
	v.SetFloat("WChaRteMax", pk.chaRteMaxW)
	v.SetFloat("WDisChaRteMax", pk.disChaRteMaxW)

	// The APPARENT-power rate ratings stay honestly absent: this profile
	// models a real-power pack and declares no VA charge/discharge rate. A
	// Tuint16 zero here would be an implemented declaration of incapacity
	// (setNotImpl16's doc, and the exact defect LXR-005 closed one axis over).
	setNotImpl16(regs, sunspec.L702, "VAChaRteMaxRtg")
	setNotImpl16(regs, sunspec.L702, "VADisChaRteMaxRtg")
	setNotImpl16(regs, sunspec.L702, "VAChaRteMax")
	setNotImpl16(regs, sunspec.L702, "VADisChaRteMax")

	writeSlice(r, base, regs)
	return base, next
}

// ── The reversion timer ──────────────────────────────────────────────────────

// packReversionTickInterval is how often the pack LOOKS at its reversion
// timers. It is deliberately far finer than the 5 s animation tick: the
// remaining-time readback is polled by SS-MODBUS-CONF v1.4 §2.6 with a ±2 s
// tolerance, and a countdown republished only every 5 s would spend most of its
// life reporting a value up to five seconds stale — a fixture failing a
// conforming procedure for reasons that are the fixture's.
//
// It is REAL time, always, and it does not scale with the timebase. The
// timebase changes what the engine believes has ELAPSED; this interval changes
// only how often it looks. Under an accelerated timebase the countdown
// therefore moves in coarse jumps, which is exactly why the hermetic proofs
// drive packReversionStep directly instead of waiting on this ticker.
const packReversionTickInterval = 200 * time.Millisecond

// initPackReversion installs the 704 reversion engine and its write observer.
// Called by newBatteryPack and by the unit-test rig, so a test and a live pack
// cannot end up wired differently — the trap battery_pack_test.go's newTestPack
// exists to avoid on every other hook.
//
// The observer is wired unconditionally (it is a no-op with no engine) so that
// the cease shape, which serves no 704, does not carry a nil-check at the call
// site instead of here.
func (bs *BatteryServer) initPackReversion(r *RegisterMap) {
	if bs.pack != nil && bs.pack.has704 {
		bs.rvrt = newRvrt704Engine(bs.pack.adv.M704)
	}
	// The hook closes over r rather than reaching through bs.Regs: the Modbus
	// listener accepts clients from inside newAnimatedServer, which is BEFORE
	// bs.Server is assigned, so a hook that dereferenced the promoted field
	// would have a window in which a first write panicked. (packOnWrite's own
	// exposure to that window is why packSimTime exists.)
	r.OnWriteSpan = func(start uint16, n int) { bs.rvrt.observeWrite(r, start, n) }
}

// SetReversionTimebase installs the clock this pack's model 704 reversion
// timers count down against, and is THE ONLY WAY to accelerate them.
//
// The default is the wall clock; nothing else in this repo calls this — not
// batsim, not mbapsdev, not simapi, not a flag, not an environment variable —
// so no production or bench path can run accelerated by configuration, only by
// a test saying so in Go source. Read reversion704.go's header before using it:
// an accelerated proof establishes this harness's own expiry semantics and
// says NOTHING about a real device's timing.
//
// Passing nil restores the wall clock. Every armed countdown is dropped by the
// swap, because a deadline computed against one clock is meaningless against
// another.
func (bs *BatteryServer) SetReversionTimebase(tb ReversionTimebase) error {
	if bs.rvrt == nil {
		return fmt.Errorf("SetReversionTimebase: this image serves no model 704, so it has no reversion " +
			"timers to accelerate (batsim -pack setpoint-zero does)")
	}
	bs.rvrt.setTimebase(tb, bs.Regs)
	return nil
}

// packReversionLoop runs the reversion engine for the life of the animation.
//
// It DELIBERATELY IGNORES Pause, for the same reason packOnWrite ceases a
// paused pack on a Conn write: a reversion timer is the device's dead-man
// switch, not part of the animation, and a bench operator who paused the
// animation to read a steady register bank has not thereby made the pack
// unable to protect itself. A pack whose timers stopped while paused would also
// make "paused" a way to hold a curtailment past its lease, which is precisely
// the failure the timer exists to prevent.
func (bs *BatteryServer) packReversionLoop(stop <-chan struct{}) {
	tick := time.NewTicker(packReversionTickInterval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			bs.packReversionStep()
		}
	}
}

// packReversionStep runs ONE pass of the reversion engine and gives any expiry
// its physical consequence. It returns the groups that expired on this call.
//
// Split out of the loop so a test can drive expiry without a ticker and without
// a sleep — the same split batteryPackStep already uses for the physics, and
// the half of the accelerated-proof story that the timebase alone does not
// provide.
//
// packSync rather than a physics step: the revert changes what the pack is
// COMMANDED to do, and measured power still has to slew there over the
// animation's own ticks. A revert that snapped the measured watts would make
// every "did it converge, and how fast" row unable to see the ramp it is there
// to measure.
func (bs *BatteryServer) packReversionStep() []string {
	if bs.rvrt == nil {
		return nil
	}
	expired := bs.rvrt.step(bs.Regs)
	if len(expired) == 0 {
		return nil
	}
	bs.packSync()
	log.Printf("[sim] battery-%s: model 704 reversion timer expired for %v — the control(s) took their "+
		"*Rvrt value and *EnaRvrt enable (timebase: %s)",
		bs.pack.shape, expired, bs.rvrt.timebaseLabel())
	return expired
}

// seedPackReversionDestinations gives this pack an EXPLICIT reversion
// destination on the two axes it actually controls, instead of the accidental
// zeros populate704 leaves behind.
//
// lexa-proto derbase records the product-side half of this as IW13-004a: "the
// countdown DefaultRvrtTms already arms has never had a defined destination, so
// expiry today lands the device on whatever WSetRvrt/WSetEnaRvrt already hold —
// the factory default or a stale prior session, never a value this gateway
// chose." A real device HAS a factory default; a fixture whose default is an
// unstated zero would let an expiry row pass while proving nothing, because
// "reverted to zero" and "was never written" would be the same register value.
//
//   - WSet reverts to 0 W with WSetEnaRvrt = 1 — ENABLED at zero, not disabled.
//     That is this shape's declared fail-safe posture stated as device state
//     (PackShapeSetpoint = lexa-gw's FailsafePostureSetpointZero, "idle at zero
//     without leaving service"). Disabling instead would be the subtly wrong
//     answer and the interesting one: packBridgeSetpoint leaves the legacy 123
//     command ALONE when WSetEna is off, so a pack that reverted by disabling
//     would keep producing the last dispatched watts forever — an expiry that
//     looks correct on the 704 registers and is uncontained in the physics.
//   - WMaxLimPct reverts to 100 % with WMaxLimPctEnaRvrt = 0 — the uncurtailed
//     ceiling, limit off, matching populate704's own "100% until the hub
//     curtails" resting value. A ceiling's safe default is the ABSENCE of a
//     ceiling: a curtailment is a temporary instruction, and a device that
//     reverted a lapsed curtailment to some lower number would be enforcing an
//     instruction whose authority had expired.
//
// The PF and VarSet groups are left at their populated zeros. This profile
// models a real-power pack and states no reactive reversion destination, and
// inventing one would be a claim about a device that does not make it.
func seedPackReversionDestinations(r *RegisterMap, m704 uint16) {
	regs := readSlice(r, m704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetFloat("WSetRvrt", 0)
	v.SetFloat("WSetPctRvrt", 0)
	v.SetEnum("WSetEnaRvrt", 1)
	v.SetFloat("WMaxLimPctRvrt", 100)
	v.SetEnum("WMaxLimPctEnaRvrt", 0)
	writeSlice(r, m704, regs)
}

// ── The WSet bridge ──────────────────────────────────────────────────────────

// packBridgeSetpoint mirrors an ENABLED 704 active-power setpoint into the
// legacy 123 signed-WMaxLimPct convention hubBatteryW already reads, so the
// pack's ONE physics answers a 704 write and a legacy dispatch identically.
// It is advBridgeCeiling's counterpart on the setpoint axis; see this file's
// header for the three ways the two differ.
//
// With WSetEna off it leaves 123 alone, so an operator-driven pack (POST
// /inject {"WMaxLimPct_pct":…, "Ena":1}) still works and a released setpoint
// does not silently zero a dispatch nobody withdrew.
//
// The commanded value is clamped to ±nameplate before encoding. That is the
// pack's own physics (it cannot produce past its nameplate) and it is also
// what keeps the 123 mirror REPRESENTABLE: WMaxLimPct is a signed percent at
// SF −2, so a setpoint of 4× nameplate would encode past int16 and wrap into
// a value nobody commanded. The tighter, direction-dependent rate-rating
// clamp lives in the physical step, where it belongs.
func packBridgeSetpoint(r *RegisterMap, bases BatteryBases, adv batteryAdvBases, wmaxW float64) {
	if r.Get(adv.M704+uint16(sunspec.L704.Offset("WSetEna"))) != 1 {
		return
	}
	v := sunspec.L704.View(readSlice(r, adv.M704, sunspec.L704.Len()))
	w := packCommandedWatts(v, wmaxW)
	if math.IsNaN(w) {
		return
	}
	w = math.Max(-wmaxW, math.Min(wmaxW, w))
	pct := 100.0 * w / wmaxW
	sf := int16(r.Get(bases.M123Base + sunspec.M123_WMaxLimPct_SF))
	r.Set(bases.M123Base+sunspec.M123_WMaxLimPct, sunspec.RawFromScaleSigned(pct, sf))
	r.Set(bases.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
}

// packCommandedWatts resolves a 704 setpoint to watts, honouring WSetMod:
// MaxPct means WSetPct is a signed percent of the nameplate, Watts (the
// gateway's own choice — derbase SetActivePowerWatts always writes
// M704_WSetMod_Watts) means WSet is watts directly. A device that only
// understood one of them would silently mis-scale the other by a factor of
// wmaxW/100.
func packCommandedWatts(v sunspec.View, wmaxW float64) float64 {
	if mod, ok := v.Enum("WSetMod"); ok && mod == sunspec.M704_WSetMod_MaxPct {
		return v.Float("WSetPct") / 100.0 * wmaxW
	}
	return v.Float("WSet")
}

// rateLimits returns the charge and discharge rate limits (both positive
// magnitudes) this pack is honouring RIGHT NOW: the LIVE M702 WChaRteMax /
// WDisChaRteMax SETTINGS, falling back to the Go floats captured at
// construction when the pack serves no 702 (the cease shape) or the point reads
// the not-implemented sentinel.
//
// IW15-002: before this, the settings were captured once at construction and
// every physics path read the captured float, so a WChaRteMax written over
// Modbus — or injected — was COSMETIC. The register moved and the device did
// not, which is the ack_no_apply fault wearing a capacity block's clothes.
//
// A setting of EXACTLY ZERO is honoured, not treated as absent: "this pack may
// not charge" is a thing a configured device says, and the sentinel (0xFFFF,
// which View.Float reports as NaN) is the only way to say "not implemented".
//
// The RATINGS (WChaRteMaxRtg/WDisChaRteMaxRtg) are deliberately not consulted
// here. What a pack MAY do is its setting; what it COULD do is its rating, and
// the gap between the two is exactly what IW15-002 exists to make measurable.
func (pk *packProfile) rateLimits(r *RegisterMap) (cha, discha float64) {
	return pk.ratePair(r, "WChaRteMax", "WDisChaRteMax")
}

// ratePair reads one charge/discharge pair out of M702 with the construction
// floats as the fallback, so the SETTING pair and the RATING pair resolve
// through exactly one piece of code and cannot drift on what "absent" means.
func (pk *packProfile) ratePair(r *RegisterMap, chaField, disChaField string) (cha, discha float64) {
	cha, discha = pk.chaRteMaxW, pk.disChaRteMaxW
	if r == nil || pk.m702 == 0 {
		return cha, discha
	}
	v := sunspec.L702.View(readSlice(r, pk.m702, sunspec.L702.Len()))
	if x := v.Float(chaField); !math.IsNaN(x) && x >= 0 {
		cha = x
	}
	if x := v.Float(disChaField); !math.IsNaN(x) && x >= 0 {
		discha = x
	}
	return cha, discha
}

// rateRatings is rateLimits for the read-only RATINGS (WChaRteMaxRtg /
// WDisChaRteMaxRtg) — what the pack declares it COULD do, as against what it is
// configured to do. Reported on /state beside the settings so a divergence is
// visible without Modbus; no physics reads it, by design (see rateLimits).
func (pk *packProfile) rateRatings(r *RegisterMap) (cha, discha float64) {
	return pk.ratePair(r, "WChaRteMaxRtg", "WDisChaRteMaxRtg")
}

// clampToRateRating limits a commanded power to the rate limit the pack is
// CONFIGURED to honour in that direction, so the M702 numbers are a fact about
// the device rather than a claim in a register. Signed: + discharge, − charge.
// r supplies the live settings (see rateLimits) and may be nil.
func (pk *packProfile) clampToRateRating(r *RegisterMap, w float64) float64 {
	cha, discha := pk.rateLimits(r)
	switch {
	case w > discha:
		return discha
	case w < -cha:
		return -cha
	}
	return w
}

// packSlew moves measured power one tick toward the commanded value at no more
// than step W. Stateless — the previous measured value is READ from the
// register the last tick wrote — so a restarted animation, a paused one, and a
// test driving the step by hand all ramp identically.
func packSlew(prev, target, step float64) float64 {
	if step <= 0 {
		return target
	}
	switch {
	case target > prev+step:
		return prev + step
	case target < prev-step:
		return prev - step
	}
	return target
}

// ── The animation ────────────────────────────────────────────────────────────

// packAnimState is the per-animation SoC integrator state. It mirrors
// animateBattery's loop-local socPct/socSeeded pair; a struct rather than
// closure variables because batteryPackStep is called directly by tests, which
// need to drive many ticks without waiting on a ticker (the pattern
// solar_test.go uses against solarStep).
type packAnimState struct {
	socPct float64
	seeded bool
}

// animateBatteryPack drives a pack every 5 real seconds. Unlike
// animateBatteryAdvanced's two independent tickers, the 701/713 mirror runs
// INSIDE the same tick as the physics that produced it: a setpoint-convergence
// row reads 701 W, and a mirror lagging the physics by up to a tick would make
// convergence look intermittent for reasons that have nothing to do with the
// gateway.
func animateBatteryPack(s *Server, r *RegisterMap, wmaxW, wmaxKwh float64, bases BatteryBases,
	pk *packProfile, pendingSoC *atomic.Pointer[float64], fc *faultController, stop <-chan struct{}) {

	st := &packAnimState{socPct: 55.0}
	tick := time.NewTicker(packTickSeconds * time.Second)
	defer tick.Stop()

	// Seed before the first tick so an immediately-read pack is coherent (the
	// same reason animateSolarAdvanced seeds its 701). dtSim=0 integrates no
	// SoC and slews nothing, so this is a pure "publish what you already are".
	batteryPackStep(r, bases, pk, wmaxW, wmaxKwh, st, pendingSoC, fc, s.simTime(), 0)

	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if s.IsPaused() {
				continue
			}
			batteryPackStep(r, bases, pk, wmaxW, wmaxKwh, st, pendingSoC, fc,
				s.simTime(), packTickSeconds*s.Speed())
		}
	}
}

// batteryPackStep runs ONE animation tick of a pack: bridge the 704 setpoint
// into the physics, decide the commanded power, slew measured power toward it,
// integrate SoC, write the electrical image, and mirror the advanced models.
//
// dtSim is the simulated seconds this tick represents (0 seeds without
// advancing anything).
func batteryPackStep(r *RegisterMap, bases BatteryBases, pk *packProfile, wmaxW, wmaxKwh float64,
	st *packAnimState, pendingSoC *atomic.Pointer[float64], fc *faultController, t, dtSim float64) {

	if pk.has704 {
		// Before the physical step, so a setpoint (and its effect-time faults)
		// applies this tick — advBridgeCeiling's placement, one axis over.
		packBridgeSetpoint(r, bases, pk.adv, wmaxW)
	}

	connected := r.Get(bases.M123Base+sunspec.M123_Conn) != 0
	// hubBatteryW already answers 0 for a disconnected pack; connected is read
	// separately because the pack must distinguish "commanded to zero" from
	// "physically out of service", which report different ChaSt/St/ConnSt and
	// reach zero by different routes (a ramp versus a contactor).
	hw := fc.shapeBatteryW(hubBatteryW(r, bases.M123Base, wmaxW))

	var w, soc float64
	switch {
	case !connected:
		// A CONTACTOR IS NOT A RAMP. Measured power collapses in this tick.
		w = 0
		soc = packSeedSoC(r, bases, st, pendingSoC)
	case math.IsNaN(hw):
		// No standing dispatch: the free-running demo cycle, so an unattended
		// pack is a moving device rather than a suspiciously frozen one.
		if ptr := pendingSoC.Load(); ptr != nil {
			// An operator-injected SoC is held until the hub takes control —
			// animateBattery's rule, kept so /inject means the same thing on
			// both battery images.
			st.socPct, st.seeded = *ptr, false
			soc = st.socPct
			w = sunspec.ApplyScaleSigned(r.Get(bases.M103Base+sunspec.M103_W),
				int16(r.Get(bases.M103Base+sunspec.M103_W_SF)))
		} else {
			phase := 2 * math.Pi * t / 1200
			soc = 55.0 + 35.0*math.Sin(phase)
			w = -wmaxW * 0.80 * math.Cos(phase)
			st.socPct, st.seeded = soc, false
		}
	default:
		target := pk.clampToRateRating(r, hw)
		prev := sunspec.ApplyScaleSigned(r.Get(bases.M103Base+sunspec.M103_W),
			int16(r.Get(bases.M103Base+sunspec.M103_W_SF)))
		w = packSlew(prev, target, pk.rampW)
		soc = packSeedSoC(r, bases, st, pendingSoC)
		// Clamp to the energy actually available LAST, so a full pack asked to
		// charge (or an empty one asked to discharge) reports the honest 0 W
		// it delivers rather than the ramp's aspiration.
		w, st.socPct = clampToSoC(w, st.socPct, wmaxKwh*1000.0, dtSim)
		soc = st.socPct
	}

	writeBatteryPhysical(r, bases, wmaxW, w, soc, t)
	packWriteState(r, bases, pk, connected, w, soc, wmaxW)
	if pk.has704 {
		mirrorBattery701713Once(r, bases, pk.adv, wmaxKwh)
	}
}

// packSeedSoC returns the SoC the integrator should start this tick from,
// consuming a pending POST /inject {"SoC_pct"} if one is waiting. Lifted out
// of animateBattery's hub-controlled branch so both animations seed
// identically.
func packSeedSoC(r *RegisterMap, bases BatteryBases, st *packAnimState, pendingSoC *atomic.Pointer[float64]) float64 {
	if ptr := pendingSoC.Swap(nil); ptr != nil {
		st.socPct, st.seeded = *ptr, true
	} else if !st.seeded {
		st.socPct = sunspec.ApplyScaleUint(
			r.Get(bases.M802Base+uint16(sunspec.M802_SoC)),
			int16(r.Get(bases.M802Base+uint16(sunspec.M802_SoC_SF))))
		st.seeded = true
	}
	return st.socPct
}

// packWriteState overrides the three state points writeBatteryPhysical derives
// from power alone with the ones a PACK reports, which power alone cannot
// distinguish:
//
//	disconnected   103 St = OFF, 802 State = DISCONNECTED, ChaSt = OFF. A pack
//	               at 0 W because its contactor is open is not a pack idling at
//	               0 W, and the gateway's cease proof is two-sided precisely so
//	               that it needs BOTH this state and the collapsed power.
//	full / empty   ChaSt = FULL / EMPTY when the pack is holding zero because
//	               its state of charge will not let it move in the commanded
//	               direction. That is the idle-at-zero the bench needs to be
//	               able to express without a fault, and it is distinguishable
//	               from HOLDING, which means "nobody asked".
func packWriteState(r *RegisterMap, bases BatteryBases, pk *packProfile, connected bool, w, soc, wmaxW float64) {
	m103, m802 := bases.M103Base, bases.M802Base
	if !connected {
		r.Set(m103+sunspec.M103_St, 1) // OFF
		r.Set(m802+uint16(sunspec.M802_ChaSt), m802ChaStOff)
		r.Set(m802+uint16(sunspec.M802_State), m802StateDisconnected)
		return
	}
	r.Set(m802+uint16(sunspec.M802_State), m802StateConnected)

	if math.Abs(w) >= wmaxW*packIdleBandFrac {
		return // genuinely moving; writeBatteryPhysical's charge/discharge is right
	}
	// Idle. Was it asked to move and could not?
	cmd := hubBatteryW(r, bases.M123Base, wmaxW)
	if math.IsNaN(cmd) {
		return // nobody asked — HOLDING, as written
	}
	switch {
	case cmd < 0 && soc >= 99.95:
		r.Set(m802+uint16(sunspec.M802_ChaSt), m802ChaStFull)
	case cmd > 0 && soc <= 0.05:
		r.Set(m802+uint16(sunspec.M802_ChaSt), m802ChaStEmpty)
	}
}

// packOnWrite is the RegisterMap.OnWrite hook: it runs AFTER a write has
// landed and gives the write its immediate physical consequences.
//
// Only TWO things happen here, and the split is the pack's physics:
//
//   - A 704 write is BRIDGED at once, so /registers, a 123 read-back and the
//     next tick all agree about what was commanded the instant the write
//     lands. The measured power still ramps — the bridge sets the command, not
//     the output.
//   - Conn=0 CEASES at once, because a contactor opens in a contactor's time,
//     not an inverter's. This is also what makes a cease work on a PAUSED
//     pack, which matters: a bench operator who paused the animation to read a
//     steady register bank has not thereby made the pack unable to disconnect.
func (bs *BatteryServer) packOnWrite(startAddr uint16) {
	pk, b, r := bs.pack, bs.bases, bs.Regs
	if pk.has704 && startAddr >= pk.adv.M704 && startAddr < pk.adv.M704+uint16(sunspec.L704.Len()) {
		packBridgeSetpoint(r, b, pk.adv, bs.wmaxW)
	}
	if startAddr >= b.M123Base && startAddr < b.M123Base+23 && r.Get(b.M123Base+sunspec.M123_Conn) == 0 {
		w, soc := 0.0, packCurrentSoC(r, b)
		writeBatteryPhysical(r, b, bs.wmaxW, w, soc, bs.packSimTime())
		packWriteState(r, b, pk, false, w, soc, bs.wmaxW)
		if pk.has704 {
			mirrorBattery701713Once(r, b, pk.adv, bs.wmaxKwh)
		}
	}
}

// packSync re-derives a pack's command and advanced-model mirror outside the
// animation loop, so a PAUSED pack (or one nobody has ticked yet) answers
// coherently after an /inject. It is SolarServer.advSync's counterpart and,
// like it, does not advance the physics: measured power is the animation's to
// move, except on the contactor edge packOnWrite already owns.
func (bs *BatteryServer) packSync() {
	if bs.pack == nil {
		return
	}
	pk, b, r := bs.pack, bs.bases, bs.Regs
	if pk.has704 {
		packBridgeSetpoint(r, b, pk.adv, bs.wmaxW)
	}
	connected := r.Get(b.M123Base+sunspec.M123_Conn) != 0
	if !connected {
		w, soc := 0.0, packCurrentSoC(r, b)
		writeBatteryPhysical(r, b, bs.wmaxW, w, soc, bs.packSimTime())
	}
	w := sunspec.ApplyScaleSigned(r.Get(b.M103Base+sunspec.M103_W), int16(r.Get(b.M103Base+sunspec.M103_W_SF)))
	packWriteState(r, b, pk, connected, w, packCurrentSoC(r, b), bs.wmaxW)
	if pk.has704 {
		mirrorBattery701713Once(r, b, pk.adv, bs.wmaxKwh)
	}
}

// packSimTime is simTime with the construction window guarded: the Modbus
// listener is started by newAnimatedServer BEFORE bs.Server is assigned, so a
// client that writes inside that window would otherwise reach a nil embedded
// Server. Zero is a perfectly good simulation instant for the one thing that
// uses it there (writeBatteryPhysical's environmental wander).
func (bs *BatteryServer) packSimTime() float64 {
	if bs.Server == nil {
		return 0
	}
	return bs.simTime()
}

// packBounce severs live connections for reboot_forget, guarded the same way
// (and additionally usable from a unit test that never started a listener).
func (bs *BatteryServer) packBounce() error {
	if bs.Server == nil {
		return nil
	}
	return bs.dropConnections()
}

// packCurrentSoC reads the pack's state of charge out of the 802 block.
func packCurrentSoC(r *RegisterMap, bases BatteryBases) float64 {
	return sunspec.ApplyScaleUint(
		r.Get(bases.M802Base+uint16(sunspec.M802_SoC)),
		int16(r.Get(bases.M802Base+uint16(sunspec.M802_SoC_SF))))
}

// injectPackDispatch is the shape-agnostic "make this pack produce X watts"
// lever: signed watts (+ discharge, − charge), written through whichever axis
// the shape in hand actually has — 704 WSet on the setpoint shape, the legacy
// M123 signed-percent dispatch on the cease shape. One key, so a bench recipe
// does not have to branch on the device it was pointed at, and so the setpoint
// shape's answer cannot be silently overwritten by the bridge on the next tick
// (which is what would happen if this wrote 123 on a pack whose WSetEna is on).
//
// IT EXISTS BECAUSE "WMaxLimPct_pct" CANNOT EXPRESS A CHARGE DIRECTION. Until
// RMD-046, "WMaxLimPct_pct" also had an encoding defect of both this sim and
// the solar one — `RawFromScaleSigned(val*100, SF)` against SF=−2, i.e.
// val×10000, which SATURATED the register at 32767 for any injected percent
// above ~3.27 — but that has been fixed (see Inject's "WMaxLimPct_pct" case):
// the key now correctly encodes val directly and is CLAMPED to [0,100], the
// domain the DER model defines for it. Clamped-unsigned is exactly why it
// still cannot drive a pack's charge direction (negative watts) on its own —
// this lever exists for that, not to route around a saturation bug that no
// longer exists. See docs/QA_FAULT_INJECTION.md for the historical defect and
// its fix.
func (bs *BatteryServer) injectPackDispatch(w float64) error {
	if bs.pack == nil {
		return fmt.Errorf("inject: %q needs a battery PACK profile (batsim -pack …); "+
			"the historical image's dispatch key is \"WMaxLimPct_pct\"", "CommandedW_W")
	}
	if bs.pack.has704 {
		return bs.injectPackSetpoint("WSet_W", w)
	}
	b := bs.bases
	sf := int16(bs.Regs.Get(b.M123Base + sunspec.M123_WMaxLimPct_SF))
	// The convention hubBatteryW actually reads: the register holds the signed
	// percent of nameplate at the point's own scale factor. Nothing extra.
	bs.Regs.Set(b.M123Base+sunspec.M123_WMaxLimPct,
		sunspec.RawFromScaleSigned(100.0*w/bs.wmaxW, sf))
	bs.Regs.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
	return nil
}

// injectPackSetpoint handles the POST /inject "WSet_W" / "WSetEna" keys — the
// 704 setpoint axis, for driving a pack from the sidecar with no gateway in
// the loop. Refused by name on a shape with no 704 (see the caller).
func (bs *BatteryServer) injectPackSetpoint(key string, val float64) error {
	if bs.pack == nil || !bs.pack.has704 {
		return fmt.Errorf("inject: %q needs a 704-capable battery pack; this sim serves no M704", key)
	}
	m704 := bs.pack.adv.M704
	regs := readSlice(bs.Regs, m704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	switch key {
	case "WSet_W":
		v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
		v.SetFloat("WSet", val)
		v.SetBool("WSetEna", true) // a setpoint nobody enabled commands nothing
	case "WSetEna":
		v.SetBool("WSetEna", val != 0)
	}
	writeSlice(bs.Regs, m704, regs)
	return nil
}

// injectPackCapacity handles the POST /inject capacity keys — the pack's half
// of the IW15-002 axis (solar's is injectSolarCapacity, and the key names are
// deliberately identical so a bench recipe reads the same against either sim).
//
//	"WMax_W" / "WMaxRtg_W"                          702 WMax / WMaxRtg
//	"WChaRteMax_W" / "WDisChaRteMax_W"              702 rate SETTINGS
//	"WChaRteMaxRtg_W" / "WDisChaRteMaxRtg_W"        702 rate RATINGS
//
// THE RATE SETTINGS ARE PHYSICS. clampToRateRating reads them live, so an
// injected WChaRteMax below the rating is a pack that really will not charge
// past it — the property that makes "the device honours its configured limit"
// checkable rather than assertable.
//
// The RATINGS are declaration-only, and they carry a MIRROR: model 120's
// MaxChaRte/MaxDisChaRte hold the same nameplate fact, seeded from the same
// numbers by populateBatteryPack, and a device that contradicts itself across
// two models is a defect this sim injects deliberately (see that seed's
// comment), never by accident — so a rating inject writes both.
//
// MODEL 802's WChaRteMax/WDisChaRteMax PAIR IS LEFT ALONE, deliberately. It is
// seeded once from the pack's construction ratings and stays there: 802 is the
// storage model's own account of the cell stack, and freezing it makes
// "the 702 setting moved but the storage model did not" an injectable
// cross-model divergence with a name, instead of an invisible coupling. A row
// that wants the two coherent injects the rating key, which does not move 702's
// setting either.
//
// "WMax_W" on a pack is declaration-only as well: the pack's own nameplate
// bound lives in packBridgeSetpoint's ±wmaxW clamp (the construction float),
// because that clamp is also what keeps the 123 signed-percent mirror
// REPRESENTABLE. Moving it with a register would let an injected WMax wrap the
// int16 mirror, which is a fixture bug, not a device behaviour.
func (bs *BatteryServer) injectPackCapacity(key string, val float64) error {
	pk := bs.pack
	if pk == nil || pk.m702 == 0 {
		return fmt.Errorf("inject: %q needs a battery PACK serving M702 (batsim -pack setpoint); "+
			"this sim serves no DER capacity model", key)
	}
	if val < 0 {
		return fmt.Errorf("inject: %q must be >= 0 (got %v): SunSpec capacity points are unsigned", key, val)
	}
	field := map[string]string{
		"WMax_W":             "WMax",
		"WMaxRtg_W":          "WMaxRtg",
		"WChaRteMax_W":       "WChaRteMax",
		"WChaRteMaxRtg_W":    "WChaRteMaxRtg",
		"WDisChaRteMax_W":    "WDisChaRteMax",
		"WDisChaRteMaxRtg_W": "WDisChaRteMaxRtg",
	}[key]
	if field == "" {
		return fmt.Errorf("inject: unknown field %q", key)
	}
	regs := readSlice(bs.Regs, pk.m702, sunspec.L702.Len())
	sunspec.L702.View(regs).SetFloat(field, val)
	writeSlice(bs.Regs, pk.m702, regs)

	// The M120 nameplate mirror of the same RATING fact (see this function's
	// doc). Settings have no home in model 120, so they move nothing here.
	switch key {
	case "WChaRteMaxRtg_W":
		bs.Regs.Set(bs.bases.M120Base+sunspec.M120_MaxChaRte,
			sunspec.RawFromScaleUint(val, int16(bs.Regs.Get(bs.bases.M120Base+sunspec.M120_MaxChaRte_SF))))
	case "WDisChaRteMaxRtg_W":
		bs.Regs.Set(bs.bases.M120Base+sunspec.M120_MaxDisChaRte,
			sunspec.RawFromScaleUint(val, int16(bs.Regs.Get(bs.bases.M120Base+sunspec.M120_MaxDisChaRte_SF))))
	case "WMaxRtg_W":
		bs.Regs.Set(bs.bases.M120Base+sunspec.M120_WRtg,
			sunspec.RawFromScaleUint(val, int16(bs.Regs.Get(bs.bases.M120Base+sunspec.M120_W_SF))))
	}
	return nil
}

// ── The lying layer ──────────────────────────────────────────────────────────

// installBatteryLies configures and wires the lying-device controller onto a
// pack, after the sim's own hooks so the lies sit in front of them. It is the
// battery counterpart of SolarServer.installLies, and the three sim-specific
// facts the controller cannot discover for itself resolve differently here:
//
//   - The CONTROL register revert_after acts on is 704 WSetEna on the setpoint
//     shape, NOT WSet. WSet is a Tint32 and the controller reverts one
//     register; reverting the high word of a two-register point would restore
//     a value nobody wrote. The ENABLE is the single register whose silent
//     loss is exactly "the setpoint is no longer in force" — the fault's whole
//     content — and on the cease shape the legacy 123 WMaxLimPct plays the
//     same role it does on a legacy inverter.
//   - The default MEASUREMENT block freeze_block snapshots is 701 where it
//     exists (the model the gateway prefers) and 103 otherwise.
//   - A power-on reset for a PACK closes the contactor. That is a statement
//     about real hardware, not a convenience: a pack that has just been power
//     cycled comes back on its own local defaults, which is precisely
//     RMD-025's "DER reboot-to-defaults" row and the reason the gateway may
//     not assume a commanded cease survived one.
func (bs *BatteryServer) installBatteryLies() {
	b, pk := bs.bases, bs.pack

	cmdAddr := b.M123Base + sunspec.M123_WMaxLimPct
	measStart, measCount := b.M103Base, uint16(50)

	// Measurement points every shape carries, plus the CONTROL points that
	// make the write path targetable. Conn is here on BOTH shapes because
	// "ACK the cease and never open the contactor" is the false-Applied shape
	// the connect axis's two-sided proof exists to catch, and before this
	// there was no way to arm it against a battery at all.
	fields := map[string]uint16{
		"W":      b.M103Base + sunspec.M103_W,
		"VAr":    b.M103Base + sunspec.M103_VAr,
		"VA":     b.M103Base + sunspec.M103_VA,
		"PF":     b.M103Base + sunspec.M103_PF,
		"Hz":     b.M103Base + sunspec.M103_Hz,
		"A":      b.M103Base + sunspec.M103_A,
		"TmpCab": b.M103Base + sunspec.M103_TmpCab,
		"Conn":   b.M123Base + sunspec.M123_Conn,
		"SoC":    b.M802Base + uint16(sunspec.M802_SoC),
		"SoH":    b.M802Base + uint16(sunspec.M802_SoH),
		"ChaSt":  b.M802Base + uint16(sunspec.M802_ChaSt),
	}
	widths := map[string]uint16{} // entries wider than one register — see declareFieldWidths

	if pk.has704 {
		cmdAddr = pk.adv.M704 + uint16(sunspec.L704.Offset("WSetEna"))
		measStart, measCount = pk.adv.M701, uint16(pk.adv.M701Len)
		for name, off := range map[string]string{
			"W_701": "W", "VAr_701": "Var", "VA_701": "VA", "PF_701": "PF",
			"Hz_701": "Hz", "TmpCab_701": "TmpCab",
		} {
			fields[name] = pk.adv.M701 + uint16(sunspec.L701.Offset(off))
			widths[name] = layoutFieldWidth(sunspec.L701, off)
		}
		for name, off := range map[string]string{
			"WSet": "WSet", "WSetEna": "WSetEna",
			"WMaxLimPct": "WMaxLimPct", "WMaxLimPctEna": "WMaxLimPctEna",
		} {
			fields[name] = pk.adv.M704 + uint16(sunspec.L704.Offset(off))
			widths[name] = layoutFieldWidth(sunspec.L704, off)
		}
		fields["SoC_713"] = pk.adv.M713 + uint16(sunspec.L713.Offset("SoC"))
		// The legacy mirror the bridge writes, under an unambiguous name: on
		// this shape the bare "WMaxLimPct" is 704's, because that is the one
		// a head end writes.
		fields["WMaxLimPct_123"] = b.M123Base + sunspec.M123_WMaxLimPct
		fields["WMaxLimPctEna_123"] = b.M123Base + sunspec.M123_WMaxLimPct_Ena
	} else {
		fields["WMaxLimPct"] = b.M123Base + sunspec.M123_WMaxLimPct
		fields["WMaxLimPctEna"] = b.M123Base + sunspec.M123_WMaxLimPct_Ena
	}

	lc := &lieController{}
	lc.configure("battery-"+string(pk.shape), bs.Regs, cmdAddr, measStart, measCount, fields,
		bs.packPowerOnReset, bs.packBounce)
	lc.declareFieldWidths(widths)

	// Named windows for freeze_block's "models" list. Every model this shape
	// actually serves is registered, so a whole-device freeze is expressible
	// by name — and naming a model this shape does NOT serve is an arm-time
	// error rather than a freeze that silently covers nothing.
	lc.registerWindow("103", b.M103Base, 50)
	lc.registerWindow("123", b.M123Base, 23)
	lc.registerWindow("802", b.M802Base, sunspec.M802Len)
	if pk.has704 {
		lc.registerWindow("701", pk.adv.M701, uint16(pk.adv.M701Len))
		lc.registerWindow("704", pk.adv.M704, uint16(sunspec.L704.Len()))
		lc.registerWindow("713", pk.adv.M713, uint16(sunspec.L713.Len()))
	}

	lc.wrap(bs.Regs)
	bs.lies = lc
}

// packPowerOnReset returns the pack's COMMANDED state to what it holds after a
// power cycle: no standing dispatch, and the contactor CLOSED. Everything the
// gateway told this pack is gone — including a cease, which is the direction
// that matters, because it means a gateway that treats "the pack is back" as
// "the pack is still ceased" is now running an uncontained battery.
func (bs *BatteryServer) packPowerOnReset() {
	b, pk, r := bs.bases, bs.pack, bs.Regs
	r.Set(b.M123Base+sunspec.M123_WMaxLimPct, 0)
	r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 0)
	r.Set(b.M123Base+sunspec.M123_Conn, 1)
	if pk.has704 {
		m704 := pk.adv.M704
		regs := readSlice(r, m704, sunspec.L704.Len())
		v := sunspec.L704.View(regs)
		v.SetBool("WSetEna", false)
		v.SetFloat("WSet", 0)
		v.SetBool("WMaxLimPctEna", false)
		v.SetFloat("WMaxLimPct", 100)
		writeSlice(r, m704, regs)
		// Every reversion countdown dies with the rail. A pack that came back
		// from a power cycle still counting down a timer a controller armed
		// before the drop would be honouring an instruction it has no other
		// memory of — and this reset has just erased the instruction itself.
		bs.rvrt.disarmAll(r)
	}
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

// BatteryPackState is the pack's own account of itself on GET /state — the
// ground truth a QA oracle compares against what the device said over Modbus.
// The whole lying-device layer depends on this staying honest while the wire
// does not (lying.go's "ground truth is preserved, deliberately").
type BatteryPackState struct {
	// Shape is the register image served; FailsafePosture is the posture the
	// gateway should independently MEASURE this shape to have. They are the
	// same string today, and they are two fields because the second is a
	// prediction about the gateway that a bench row can check rather than
	// assume.
	Shape           string `json:"shape"`
	FailsafePosture string `json:"failsafe_posture"`

	Connected bool `json:"connected"`
	// CommandedW is what the pack has been told to produce (signed:
	// + discharge, − charge), NaN-free: null when nothing is commanded.
	CommandedW *float64 `json:"commanded_W"`
	MeasuredW  float64  `json:"measured_W"`
	// RampWPerTick is the slew bound between the two above, so an oracle can
	// tell "not yet converged" from "will never converge" without a stopwatch.
	RampWPerTick float64 `json:"ramp_W_per_tick"`
	// WChaRteMaxW/WDisChaRteMaxW are the rate SETTINGS the pack is HONOURING
	// this instant — read live from 702 (rateLimits), which is the same number
	// clampToRateRating just applied. WChaRteMaxRtgW/WDisChaRteMaxRtgW are the
	// RATINGS it DECLARES. IW15-002 split them: they are equal on a stock
	// fixture and separately injectable, so a row can prove a gateway resolved
	// its reference against the right one without opening a Modbus client.
	WChaRteMaxW       float64 `json:"w_cha_rte_max_W"`
	WDisChaRteMaxW    float64 `json:"w_discha_rte_max_W"`
	WChaRteMaxRtgW    float64 `json:"w_cha_rte_max_rtg_W"`
	WDisChaRteMaxRtgW float64 `json:"w_discha_rte_max_rtg_W"`

	// Setpoint704 is the 704 axis as the register bank really holds it,
	// omitted on the cease shape.
	Setpoint704 *packSetpointState `json:"setpoint_704,omitempty"`
	// Meas701 is the advanced measurement model's own reading, omitted on the
	// cease shape. It exists so a row can prove 701 and 103 agree rather than
	// trusting the mirror.
	Meas701 *adv701Meas `json:"meas_701,omitempty"`
	// Lies is the lying-device layer's counter set — what actually fired,
	// rather than what a sleep suggests fired.
	Lies *LieStats `json:"lies,omitempty"`
	// Reversion is the 704 reversion-timer engine's own account of itself,
	// omitted on the cease shape. It is on /state chiefly so the TIMEBASE is,
	// which is what makes an accelerated run self-declaring in its evidence.
	Reversion *PackReversionState `json:"reversion,omitempty"`
}

// PackReversionState is the pack's model 704 reversion engine on GET /state.
type PackReversionState struct {
	// Timebase names the clock the timers counted down against. It reads
	// "wall" on every production and bench path. ANYTHING ELSE means the run
	// was ACCELERATED and its timings are evidence about this harness's state
	// machine only — never about a real device. It is published rather than
	// merely documented so an evidence bundle cannot be misread later.
	Timebase string `json:"timebase"`
	// Groups lists every reversion timer that is configured (RvrtTms non-zero)
	// or running. A group that is neither is omitted rather than reported as a
	// row of zeros, so what is present on /state is what a reader must account
	// for.
	Groups []PackReversionGroupState `json:"groups,omitempty"`
}

// PackReversionGroupState is one reversion timer: what it was programmed for,
// whether the engine is counting it, and what the register bank is telling a
// Modbus client is left. Armed and RemS come from the two different places on
// purpose — the engine and the wire — so a row can prove they agree.
type PackReversionGroupState struct {
	Name  string `json:"name"`
	Armed bool   `json:"armed"`
	TmsS  uint32 `json:"tms_s"`
	RemS  uint32 `json:"rem_s"`
}

type packSetpointState struct {
	Ena    bool    `json:"ena"`
	Mod    int     `json:"wset_mod"`
	WSet_W float64 `json:"wset_W"`
	// EffectiveW is WSet resolved through WSetMod and clamped by the pack's
	// own nameplate — what the bridge actually commanded.
	EffectiveW float64 `json:"effective_W"`
}

// packSnapshot renders the pack's ground truth, or nil on a non-pack image
// (which is what keeps the historical GET /state document byte-identical).
func (bs *BatteryServer) packSnapshot() *BatteryPackState {
	pk := bs.pack
	if pk == nil {
		return nil
	}
	r, b := bs.Regs, bs.bases
	chaW, disChaW := pk.rateLimits(r)
	chaRtgW, disChaRtgW := pk.rateRatings(r)
	out := &BatteryPackState{
		Shape:           string(pk.shape),
		FailsafePosture: string(pk.shape),
		Connected:       r.Get(b.M123Base+sunspec.M123_Conn) != 0,
		MeasuredW: sunspec.ApplyScaleSigned(r.Get(b.M103Base+sunspec.M103_W),
			int16(r.Get(b.M103Base+sunspec.M103_W_SF))),
		RampWPerTick:      pk.rampW,
		WChaRteMaxW:       chaW,
		WDisChaRteMaxW:    disChaW,
		WChaRteMaxRtgW:    chaRtgW,
		WDisChaRteMaxRtgW: disChaRtgW,
	}
	if cmd := hubBatteryW(r, b.M123Base, bs.wmaxW); !math.IsNaN(cmd) {
		c := pk.clampToRateRating(r, cmd)
		out.CommandedW = &c
	}
	if pk.has704 {
		regs := readSlice(r, pk.adv.M704, sunspec.L704.Len())
		v := sunspec.L704.View(regs)
		mod, _ := v.Enum("WSetMod")
		eff := packCommandedWatts(v, bs.wmaxW)
		out.Setpoint704 = &packSetpointState{
			Ena: v.Bool("WSetEna"), Mod: int(mod), WSet_W: v.Float("WSet"),
			EffectiveW: math.Max(-bs.wmaxW, math.Min(bs.wmaxW, eff)),
		}
		m701 := sunspec.Parse701(readSlice(r, pk.adv.M701, pk.adv.M701Len))
		out.Meas701 = &adv701Meas{
			W_W: m701.W, PF: m701.PF, VAr_var: m701.Var, Hz_Hz: m701.Hz,
			St: int(m701.St), ConnSt: int(m701.ConnSt),
		}
		if bs.rvrt != nil {
			out.Reversion = &PackReversionState{
				Timebase: bs.rvrt.timebaseLabel(),
				Groups:   bs.rvrt.armedGroups(r),
			}
		}
	}
	if bs.lies != nil {
		s := bs.lies.Stats()
		out.Lies = &s
	}
	return out
}
