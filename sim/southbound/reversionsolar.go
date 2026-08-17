package sim

// reversionsolar.go — every reversion timer the SOLAR sims serve, and the
// wiring that makes them count.
//
// reversion.go holds the engine and model 704's five groups. This file holds
// the other three families, the SolarServer plumbing, and the runtime clock
// lever a bench needs to watch an expiry inside a bench window.
//
// # Why this file exists: §9.5 row 10
//
// The RC0 bench battery of 2026-08-16 ran row 10 ("Reversion: RvrtTms armed,
// read back, and ACTUAL EXPIRY observed") against `modsim -advanced` and had to
// record it PARTIAL: the sim "never decremented PFWInjRvrtTms (pinned at 258 s
// for 6½ minutes) and reports PFWInjRvrtRem = 0, i.e. it implements no
// reversion countdown". The engine existed; it was wired into the battery pack
// alone. Every solar sim — plain, advanced and legacy-curve — served reversion
// registers that were inert storage, so the device half of RC0-ENARVRT and
// RC0-PFVAR-REVERSION-ALTERNATE was unexercisable and the battery correctly
// refused to accept the GATEWAY's own release of the axis as evidence that a
// DEVICE timer had lapsed.
//
// # The timer set, DERIVED
//
// The set below was derived by walking the vendored SunSpec model definitions
// (lexa-proto docs/schema/sunspec-models/model_*.json) for every point whose
// name ends in RvrtTms, restricted to the models these sims actually serve. It
// is not a list anybody remembered, and it is pinned against the served layouts
// by TestEveryServedReversionTimerIsEngineManaged, which fails both ways: a
// served timer the engine does not manage, and a managed timer the image does
// not serve.
//
//	model 704   PFWInjRvrtTms PFWAbsRvrtTms WMaxLimPctRvrtTms WSetRvrtTms
//	            VarSetRvrtTms            (5, uint32, each with a *RvrtRem)
//	model 705   RvrtTms                  (1, uint32, with RvrtRem and RvrtCrv)
//	model 706   RvrtTms                  (1, uint32, with RvrtRem and RvrtCrv)
//	model 711   RvrtTms                  (1, uint32, with RvrtRem and RvrtCtl)
//	model 712   RvrtTms                  (1, uint32, with RvrtRem and RvrtCrv)
//	model 123   Conn_RvrtTms WMaxLimPct_RvrtTms OutPFSet_RvrtTms
//	            VArPct_RvrtTms           (4, uint16, NO remaining-time point)
//	models      RvrtTms on each of 126 129 130 131 132 134
//	12x                                  (6, uint16, NO remaining-time point)
//
// TWO POINT FAMILIES WERE ADJUDICATED OUT, deliberately, and a reader checking
// the derivation will find them next door in the same JSON:
//
//	WinTms  "Time window for volt-VAR change" (model_126.json), and the same
//	        point on 123's four families. A RANDOMISATION WINDOW BEFORE a
//	        setting takes effect — the opposite end of the control's life from a
//	        reversion timeout, and nothing in SunSpec DER Information Model V1.2
//	        §3.2 refers to it. Implementing it inside a reversion engine would
//	        conflate "when does this start" with "when does this stop".
//	RmpTms  "Ramp time for moving from current setpoint to new setpoint"
//	        (model_123.json). A slew rate, not a timer with an expiry.
//
// # What a timer reverts TO, per family — and where this file ADJUDICATES
//
// SunSpec DER Information Model V1.2 §3.2 says only that "the specified
// alternate set of function settings SHALL be applied to the function and the
// reversion timer transitions to the Stopped state". WHAT that alternate set IS
// is model-specific, and the four families differ:
//
//	704   The alternate set is EXPLICIT and includes an ENABLE: each group has
//	      *Rvrt value points and an *EnaRvrt. This is the only family on which
//	      the adjudicated LAPSE posture is expressible — a head end that arms a
//	      window with *EnaRvrt = 0 has stated that at expiry the axis's function
//	      is simply not enabled (§3.3: "When the enable field is set to 0, any
//	      changes made to the setting will not take effect"). Transcription, no
//	      adjudication. See revert704Group.
//
//	7xx   The alternate set is a CURVE INDEX: 705/706/712 declare RvrtCrv,
//	curve "Default curve after reversion timeout", and 711 declares RvrtCtl,
//	      "Default control after reversion timeout". None of the four declares
//	      an *EnaRvrt. So expiry writes the index into AdptCrvReq/AdptCtlReq and
//	      RE-RUNS THE MODEL'S OWN §3.1.2 ADOPT — the same code path a head end's
//	      write takes, including the curve_adopt_lies fault, because a reversion
//	      that adopted more honestly than a client would be a device nobody has.
//
//	      THE ADJUDICATION: when RvrtCrv/RvrtCtl is 0 — the models' own encoding
//	      of "no active curve" / "no active control" (model_712.json AdptCrvReq,
//	      model_711.json AdptCtlReq) — this file ALSO clears Ena. The reason is
//	      that the register image cannot express an empty selection any other
//	      way: the live entry IS index 0 and always holds a curve, so "no curve
//	      is in force" has exactly one encoding on this device, and §3.3 defines
//	      it. THE ALTERNATIVE READING, stated so it can be argued: leave Ena
//	      alone and let the function run on whatever the live entry holds. It
//	      was rejected because it makes "revert to no active curve" and "revert
//	      to the curve you already had" the same observable, which would let a
//	      bench row pass while proving nothing.
//
//	123   The alternate set is NOT EXPRESSIBLE AT ALL: model 123 declares four
//	      "Timeout period for ..." points and NO alternate-value points and NO
//	      remaining-time points. The only alternate this model can state is the
//	      DISABLED state (§3.3), so expiry clears the family's own enable —
//	      WMaxLim_Ena, OutPFSet_Ena, VArPct_Ena — and LEAVES THE VALUE IN PLACE,
//	      because §3.3 makes the enable, not the value, the thing that stops a
//	      setting taking effect. Conn is the exception and the obvious one: its
//	      timeout returns the connection control to CONNECT, since a temporary
//	      disconnect that times out reconnecting is the entire purpose of
//	      Conn_RvrtTms.
//
//	12x   The alternate set is the CURVE SELECTION, in the models' own words:
//	      RvrtTms is the "Timeout period for volt-VAR curve selection"
//	      (model_126.json) and ActCrv is the "Index of active curve. 0=no active
//	      curve". So expiry sets ActCrv to 0 and clears ModEna — the same
//	      adjudication, and the same alternative reading, as the 7xx curve
//	      models above.
//
// NOTE ON NORMATIVE WEIGHT. §3.2/§3.3 are the published state machine for the
// 7xx (IEEE 1547-2018 profile) models and are cited as such. Models 123 and the
// 12x family PREDATE that document; for them the per-model JSON descriptions
// quoted above are the source, and §3.2's state machine is followed because it
// is the only published one and a fixture whose two generations disagreed about
// what "expired" means would be a fixture nobody could reason about. That is a
// choice this file is making, not a citation.
//
// # What is NOT observable on 123 and the 12x family
//
// Neither declares a remaining-time point. On those models a Modbus client
// CANNOT WATCH THE COUNTDOWN — only the expiry transition is on the wire. The
// engine still counts them and GET /state carries the remaining seconds with
// rem_on_wire=false, which is the honest shape: the fixture knows, the wire
// does not, and the JSON says which.

import (
	"fmt"
	"log"
	"math"
	"time"

	"lexa-proto/sunspec"
)

// solarReversionTickInterval is how often a solar sim LOOKS at its reversion
// timers. Same reasoning as packReversionTickInterval: SS-MODBUS-CONF v1.4 §2.6
// polls the remaining-time readback with a ±2 s tolerance, and a countdown
// republished only on the 5 s animation tick would spend most of its life up to
// five seconds stale — a fixture failing a conforming procedure for reasons
// that are the fixture's.
//
// It is REAL time, always, and it does not scale with the timebase. The
// timebase changes what the engine believes has ELAPSED; this interval changes
// only how often it looks. Under an accelerated timebase the countdown
// therefore moves in coarse jumps — 60× acceleration advances the register by
// ~12 s per look — which is why the hermetic proofs drive reversionStep
// directly instead of waiting on this ticker, and why a bench row that wants
// per-second resolution should accelerate modestly rather than by 900×.
const solarReversionTickInterval = 200 * time.Millisecond

// ── The timer table ──────────────────────────────────────────────────────────

// solarReversionTimers is every reversion timer THIS sim's register image
// serves. It is rebuilt (not merely consulted) whenever the image is re-laid,
// because a timer descriptor carries a base address.
func (ss *SolarServer) solarReversionTimers() []rvrtTimer {
	var out []rvrtTimer

	// Model 123 is on every solar image, legacy and advanced alike.
	t123 := rvrt123Timers(ss.bases.M123Base)
	if ss.advanced {
		// On an advanced image 123's throttle and 704's WMaxLimPct are ONE
		// PHYSICAL AXIS in two register views — see coupleCeilingViews.
		coupleTimer(t123, "123.WMaxLimPct", ss.clearAdvCeilingView)
	}
	out = append(out, t123...)

	if ss.advanced {
		t704 := rvrt704Timers(ss.adv.M704)
		coupleTimer(t704, "704.WMaxLimPct", ss.releaseLegacyCeilingMirrorIfLapsed)
		out = append(out, t704...)
		for _, cb := range ss.adv.Curves {
			out = append(out, ss.rvrtCurve7xxTimer(cb))
		}
	}
	if ss.legacy != nil {
		for _, b := range ss.legacy.layout().blocks {
			out = append(out, ss.rvrtLegacyCurveTimer(b))
		}
	}
	return out
}

// ── The one active-power ceiling, in two register views ─────────────────────
//
// On an ADVANCED image, model 123's throttle (WMaxLimPct / WMaxLim_Ena) and
// model 704's WMaxLimPct are not two functions. They are ONE physical axis
// published twice, and advBridgeCeiling exists precisely to keep them that way:
// it mirrors an enabled 704 ceiling into 123, because 123 is what the physics
// (solarCeilingW) reads.
//
// That bridge is ONE-WAY AND WRITE-ONLY, and until gate finding F1 that made a
// reversion on this axis a lie in one of the two directions, whichever way it
// ran:
//
//	123 lapses   the revert cleared WMaxLim_Ena, then reversionStep's own
//	             advSync ran advBridgeCeiling, which — seeing 704's ceiling
//	             still enabled — set WMaxLim_Ena straight back to 1 and
//	             overwrote the value the revert had deliberately left in place.
//	             Engine, /state and the log all said "lapsed"; the wire said
//	             Ena=1 at 100 %. A bench recording either surface would have
//	             recorded the opposite of the other.
//	704 lapses   the revert set WMaxLimPctEna to WMaxLimPctEnaRvrt = 0 — the
//	             adjudicated lapse posture — and the bridge then simply STOPPED
//	             mirroring, leaving 123 holding the last commanded percent. The
//	             physics reads 123, so the device went on curtailing for ever on
//	             a control whose lease had expired: exactly the failure the
//	             timer exists to prevent.
//
// Both are fixed by stating the axis's unity at the two places a reversion can
// break it, rather than by rewriting the bridge. The two functions below are
// deliberately DIRECTIONAL — each says which view just lapsed and what follows
// — instead of one "if either view is disabled, disable both" rule, which would
// infer the situation from register state that the bridge may not have refreshed
// yet, and would be wrong in a way no test would show.
//
// WHAT IS NOT FIXED HERE, stated so it is not mistaken for coverage: a PLAIN
// CLIENT WRITE that disables 704's ceiling still leaves the legacy mirror
// standing, because the bridge has no memory of having written it and giving it
// one means ownership state in a hot path this change does not otherwise touch.
// It is a pre-existing limitation, not one this wave introduced, and it is not
// the product's release shape — a hub release writes 100 % with Ena still 1
// (advBridgeCeiling's own doc), which mirrors through as full output.

// coupleTimer wraps the named timer's revert with an additional step, run
// immediately after it and on the same register map.
//
// A wrapper rather than an edit to the family tables because the fact being
// expressed is not a property of model 123 or of model 704 — it is a property
// of THIS IMAGE serving both. rvrt123Timers is also built for the legacy image,
// where there is no 704 to keep in step, and rvrt704Timers is shared with the
// battery pack, which bridges a different axis entirely.
func coupleTimer(timers []rvrtTimer, name string, after func(*RegisterMap)) {
	for i := range timers {
		if timers[i].Name != name {
			continue
		}
		inner := timers[i].Revert
		timers[i].Revert = func(r *RegisterMap) {
			if inner != nil {
				inner(r)
			}
			after(r)
		}
	}
}

// clearAdvCeilingView withdraws the 704 view of the ceiling after the 123 view
// has lapsed. Without it the bridge re-enables the axis on the very next
// advSync — which reversionStep itself performs.
func (ss *SolarServer) clearAdvCeilingView(r *RegisterMap) {
	if off := sunspec.L704.Offset("WMaxLimPctEna"); off >= 0 {
		r.Set(ss.adv.M704+uint16(off), 0)
	}
}

// releaseLegacyCeilingMirrorIfLapsed withdraws the 123 view after the 704 view
// has lapsed — and ONLY then. A 704 timer whose WMaxLimPctEnaRvrt is 1 has
// reverted to an ENABLED ceiling at its *Rvrt percent, and the bridge will
// mirror that value on the advSync that follows; clearing 123 there would
// cancel a control the head end explicitly asked the device to fall back to.
//
// Only the ENABLE is cleared. §3.3 makes the enable, not the value, the thing
// that stops a setting taking effect, and solarCeilingW agrees — with
// WMaxLimPct_Ena at 0 it resolves the ceiling to the full WMax setting and the
// stale percent is inert. That is the same rule the 123 timers' own reverts
// follow, so the two cannot drift.
func (ss *SolarServer) releaseLegacyCeilingMirrorIfLapsed(r *RegisterMap) {
	if off := sunspec.L704.Offset("WMaxLimPctEna"); off < 0 || r.Get(ss.adv.M704+uint16(off)) == 1 {
		return
	}
	r.Set(ss.bases.M123Base+sunspec.M123_WMaxLimPct_Ena, 0)
}

// rvrt123Family names one of model 123's four reversion timers and the enable
// its expiry clears. Conn carries no enable — its "alternate" is a value — so
// it is described by connRevert instead.
type rvrt123Family struct {
	name string
	tms  string
	ena  string
}

var rvrt123Families = []rvrt123Family{
	{"WMaxLimPct", "WMaxLimPct_RvrtTms", "WMaxLim_Ena"},
	{"OutPFSet", "OutPFSet_RvrtTms", "OutPFSet_Ena"},
	{"VArPct", "VArPct_RvrtTms", "VArPct_Ena"},
}

// rvrt123Timers builds model 123's four timers over the block at base.
func rvrt123Timers(base uint16) []rvrtTimer {
	out := make([]rvrtTimer, 0, len(rvrt123Families)+1)
	for _, f := range rvrt123Families {
		f := f
		out = append(out, rvrtTimer{
			Name: "123." + f.name, Model: 123, Base: base, L: sunspec.L123,
			Tms: f.tms, // no Rem: model 123 declares none
			Revert: func(r *RegisterMap) {
				if off := sunspec.L123.Offset(f.ena); off >= 0 {
					r.Set(base+uint16(off), 0)
				}
			},
		})
	}
	out = append(out, rvrtTimer{
		Name: "123.Conn", Model: 123, Base: base, L: sunspec.L123,
		Tms: "Conn_RvrtTms",
		Revert: func(r *RegisterMap) {
			// 0 = disconnect, 1 = connect (sunspec models.go M123_Conn). A
			// disconnect whose timeout period elapses RECONNECTS; that is what
			// the timeout is for, and it is the only alternate this point can
			// take that is not the command itself.
			r.Set(base+uint16(sunspec.M123_Conn), 1)
		},
	})
	return out
}

// rvrtCurve7xxTimer builds the single reversion timer of one 7xx curve model
// (705/706/712 by curve index, 711 by control index).
//
// The reversion destination point is named RvrtCrv on the curve models and
// RvrtCtl on 711; the request point likewise. Both are read off the block's own
// header layout rather than named here per model, so a model whose header
// changes at re-vendor fails to resolve loudly instead of reverting the wrong
// register.
func (ss *SolarServer) rvrtCurve7xxTimer(cb curveBlock) rvrtTimer {
	dest := "RvrtCrv"
	if !cb.hdr.Has(dest) {
		dest = "RvrtCtl"
	}
	return rvrtTimer{
		Name: fmt.Sprintf("%d", cb.id), Model: cb.id, Base: cb.base, L: cb.hdr,
		Tms: "RvrtTms", Rem: "RvrtRem",
		Revert: func(r *RegisterMap) {
			destOff := cb.hdr.Offset(dest)
			if destOff < 0 {
				return
			}
			req := r.Get(cb.base + uint16(destOff))
			r.Set(cb.base+uint16(cb.reqOff), req)
			if req == 0 {
				// "0 = No active curve" / "0 = No active control". See this
				// file's header for the adjudication and the reading rejected.
				if off := cb.hdr.Offset("Ena"); off >= 0 {
					r.Set(cb.base+uint16(off), 0)
				}
				return
			}
			// The model's own §3.1.2 adoption, through the SAME function a
			// client write reaches, so an expiry under curve_adopt_lies lies
			// exactly as a client-driven adopt does.
			ss.applyAdopt(cb, req)
		},
	}
}

// rvrtLegacyCurveTimer builds the single reversion timer of one legacy 12x
// curve model.
func (ss *SolarServer) rvrtLegacyCurveTimer(b legacyBankBlock) rvrtTimer {
	layer := ss.legacy
	return rvrtTimer{
		Name: fmt.Sprintf("%d", b.id), Model: b.id, Base: b.base, L: b.hdr,
		Tms: "RvrtTms", // no Rem: the 12x models declare none
		Revert: func(r *RegisterMap) {
			r.Set(b.base+uint16(b.actCrvOff), 0) // "0=no active curve"
			// legacy_modena_sticky is a DEVICE property — "ModEna bit 0 cannot
			// be cleared" — so it binds the device's own reversion too. A
			// fixture whose timer could clear a bit the fault says is stuck
			// would be two devices at once.
			//
			// legacy_actcrv_ignored deliberately does NOT bind here: its whole
			// content is "a WRITE to ActCrv ACKs and the register does not
			// move", which is a statement about the client-facing write path,
			// not about what the device does to itself.
			if _, modEnaSticky, _, _ := layer.faults.snapshot(); modEnaSticky {
				return
			}
			r.Set(b.base+uint16(b.modEnaOff), 0)
		},
	}
}

// ReversionAccelerator is a simulator whose device-side reversion clock can be
// changed at run time. It exists so a sim BINARY can offer POST /control
// {"reversion_scale":N} without knowing which concrete model it is serving, and
// so a model that has no such clock is a nil of this type — which the binary
// turns into an explicit refusal rather than a silently ignored request.
type ReversionAccelerator interface {
	SetReversionScale(scale float64) error
}

// The solar sims are the implementation. The battery pack deliberately is NOT:
// its reversion clock stays a Go-source-only knob (SetReversionTimebase),
// because nothing on the bench needs to accelerate a pack and the narrower the
// surface the fewer ways an accelerated run can happen by accident.
var _ ReversionAccelerator = (*SolarServer)(nil)

// ── Wiring ───────────────────────────────────────────────────────────────────

// initSolarReversion installs this sim's reversion engine and its write
// observer. Called by every solar constructor and by the unit-test rigs, so a
// test and a live sim cannot end up wired differently — the trap newTestPack
// exists to avoid on the battery side.
//
// The hook closes over r rather than reaching through ss.Regs: the Modbus
// listener accepts clients from inside newAnimatedServer, which is BEFORE
// ss.Server is assigned, so a hook that dereferenced the promoted field would
// have a window in which a first write panicked.
//
// KNOWN INTERACTION, stated rather than discovered later: OnWriteSpan is handed
// the WIRE address of a transaction, and the lying layer's layout_shift fault
// (lying.go) serves a register image shifted by delta — so while THAT fault is
// armed, a write aimed at a reversion timer lands at a different real address
// than the span reports and the timer does not arm. Nothing silently
// mis-arms — the engine re-reads the timeout out of the bank rather than
// trusting the write it saw — and the two faults are not meant to be combined.
func (ss *SolarServer) initSolarReversion(r *RegisterMap) {
	ss.rvrt = newRvrtEngine(ss.solarReversionTimers())
	r.OnWriteSpan = func(start uint16, n int) { ss.rvrt.observeWrite(r, start, n) }
}

// rebuildSolarReversionTimers re-derives the timer table after the served
// register image has been RE-LAID — which today means the runtime short-block
// lever (curve12x.go), the only thing that moves a model's base address while
// the device is running.
//
// It disarms every countdown, because a deadline armed against a register that
// has since moved is a deadline against someone else's register. A bench that
// re-lays the image mid-countdown has re-enumerated the device, and a timer
// that survived that would be the fixture asserting continuity the device does
// not have.
func (ss *SolarServer) rebuildSolarReversionTimers(r *RegisterMap) {
	if ss.rvrt == nil {
		return
	}
	ss.rvrt.setTimers(ss.solarReversionTimers(), r)
}

// SetReversionTimebase installs the clock this sim's reversion timers count
// down against.
//
// Read reversion.go's header before using it: an accelerated proof establishes
// this harness's expiry state machine and says NOTHING about a real device's
// timing. Passing nil restores the wall clock. Every armed countdown is dropped
// by the swap, because a deadline computed against one clock is meaningless
// against another.
func (ss *SolarServer) SetReversionTimebase(tb ReversionTimebase) error {
	if ss.rvrt == nil {
		return fmt.Errorf("SetReversionTimebase: this sim has no reversion engine installed")
	}
	ss.rvrt.setTimebase(tb, ss.Regs)
	return nil
}

// ReversionTimebase returns the clock currently installed, so a bundle-producing
// run can record its declaration (RecordTimebase) from the sim itself rather
// than from a copy the caller kept.
func (ss *SolarServer) ReversionTimebase() ReversionTimebase {
	if ss.rvrt == nil {
		return nil
	}
	return ss.rvrt.timebase()
}

// SetReversionScale is the RUNTIME lever behind POST /control
// {"reversion_scale":N}: it installs a clock running N× the wall clock for this
// sim's reversion timers, and nothing else.
//
// The three values that mean something specific:
//
//	0     UNCHANGED, and the ONLY value that leaves armed countdowns alone.
//	      Matches POST /control's existing "speed" convention, so an operator
//	      who omits the key does not silently reset the clock — and, more
//	      importantly, so a body sent for some other purpose ({"cmd":"pause"})
//	      cannot reset it either.
//	1     THE WALL CLOCK, installed as WallTimebase and not as a 1× scaled one,
//	      so the declaration on /state reads "wall". A bundle that said "scaled"
//	      would be describing an acceleration that is not happening. It INSTALLS
//	      a clock, so like every other non-zero value it DISARMS every running
//	      countdown — "back to real time" is not a way to leave a live timer
//	      running at 1×, and a row that wants that must simply not send the key.
//	N>0   N× acceleration, up to MaxReversionScale. Also disarms.
//	>Max  REFUSED (see MaxReversionScale): past the bound the clock stops
//	      tracking its own multiplier, which is the failure gate finding F2
//	      measured.
//
// A non-positive or non-finite multiplier is REFUSED here rather than passed to
// NewScaledTimebase, which panics on one: an operator typo on a bench must be a
// 400, not a dead simulator.
//
// It logs, loudly and once, because the acceleration has to be discoverable
// from the sim's own journal by someone reading a capture later — /state shows
// the clock now, the log shows when it changed.
func (ss *SolarServer) SetReversionScale(scale float64) error {
	if ss.rvrt == nil {
		return fmt.Errorf("reversion_scale: this sim has no reversion engine installed")
	}
	switch {
	case scale == 0:
		return nil
	case math.IsNaN(scale) || math.IsInf(scale, 0) || scale < 0:
		return fmt.Errorf("reversion_scale %v: a device clock multiplier must be a positive finite "+
			"number (1 = real time)", scale)
	case scale > MaxReversionScale:
		// Refused rather than clamped. A bench that asked for 86400× and
		// silently got 3600× would read its countdown at a rate it did not
		// choose; a bench that asked for 86400× and got it would, past 29.7 h,
		// be reading a clock that had stopped — which is gate finding F2 and
		// the reason for the bound. See MaxReversionScale.
		return fmt.Errorf("reversion_scale %v: the largest multiplier this device clock can count at is "+
			"%d× (past it the clock stops tracking, which is the failure this bound exists to make "+
			"unreachable); a reversion window is seconds to minutes, so %d× turns a 258 s window into 72 ms",
			scale, MaxReversionScale, MaxReversionScale)
	case scale == 1:
		ss.rvrt.setTimebase(WallTimebase(), ss.Regs)
	default:
		ss.rvrt.setTimebase(NewScaledTimebase(scale), ss.Regs)
	}
	log.Printf("[sim] %s: DEVICE REVERSION CLOCK set to %s — every armed countdown was dropped by the "+
		"swap, so arm timers AFTER this call. Timings measured under this clock are evidence about "+
		"this simulator's state machine, never about a real device",
		ss.faults.label, ss.rvrt.timebaseLabel())
	return nil
}

// reversionStep runs ONE pass of the reversion engine and gives any expiry its
// physical consequence. It returns the timers that expired on this call.
//
// Split out of the loop so a test can drive expiry without a ticker and without
// a sleep — the same split solarStep already uses for the physics, and the half
// of the accelerated-proof story that the timebase alone does not provide.
//
// advSync rather than a physics step: a revert changes what the device is
// COMMANDED to do, and measured power still has to slew there over the
// animation's own ticks. A revert that snapped the measured watts would make
// every "did it converge, and how fast" row unable to see the ramp it exists to
// measure.
func (ss *SolarServer) reversionStep() []string {
	if ss.rvrt == nil {
		return nil
	}
	expired := ss.rvrt.step(ss.Regs)
	if len(expired) == 0 {
		return nil
	}
	if ss.advanced {
		ss.advSync()
	}
	log.Printf("[sim] %s: reversion timer expired for %v — each control took the alternate set its own "+
		"model defines (timebase: %s)", ss.faults.label, expired, ss.rvrt.timebaseLabel())
	return expired
}

// reversionLoop runs the reversion engine for the life of the animation.
//
// It DELIBERATELY IGNORES Pause, for the same reason packReversionLoop does: a
// reversion timer is the device's dead-man switch, not part of the animation,
// and a bench operator who paused the animation to read a steady register bank
// has not thereby made the device unable to protect itself. A sim whose timers
// stopped while paused would also make "paused" a way to hold a curtailment
// past its lease, which is precisely the failure the timer exists to prevent.
func (ss *SolarServer) reversionLoop(stop <-chan struct{}) {
	tick := time.NewTicker(solarReversionTickInterval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			ss.reversionStep()
		}
	}
}

// reversionSnapshot is the engine's own account of itself for GET /state.
//
// It is present on every solar sim, including one with no timer armed, because
// the TIMEBASE is the thing that has to be on the record: a bundle whose
// /state capture simply omitted the section could not be told apart from one
// taken before this file existed.
func (ss *SolarServer) reversionSnapshot() *ReversionState {
	if ss.rvrt == nil {
		return nil
	}
	return &ReversionState{
		Timebase: ss.rvrt.timebaseLabel(),
		Groups:   ss.rvrt.armedGroups(ss.Regs),
	}
}

// ── The advanced sim's declared reversion destinations ───────────────────────

// seedSolarReversionDestinations gives the advanced solar image an EXPLICIT
// reversion destination on every 704 group, instead of the accidental zeros
// populate704 leaves behind.
//
// lexa-proto's derbase records the product-side half of this as IW13-004a: "the
// countdown DefaultRvrtTms already arms has never had a defined destination, so
// expiry today lands the device on whatever WSetRvrt/WSetEnaRvrt already hold —
// the factory default or a stale prior session." A real device HAS a factory
// default; a fixture whose default is an unstated zero lets an expiry row pass
// while proving nothing, because "reverted to zero" and "was never written"
// are the same register value.
//
// THE VALUES ARE A PV INVERTER'S FAIL-SAFE, and they are NOT the battery pack's
// (seedPackReversionDestinations), because the two machines' safe states differ:
//
//	WMaxLimPct  reverts to 100.00 % with WMaxLimPctEnaRvrt = 1 — ENABLED at
//	            full output. A ceiling is a restriction; the safe end of a
//	            lapsed restriction on a generator is no restriction. Reverting
//	            by DISABLING would leave advBridgeCeiling holding the last
//	            commanded percent in the legacy 123 mirror, i.e. a curtailment
//	            that outlived its lease — the exact failure the timer prevents.
//	WSet        reverts to 0 W / 0 % with WSetEnaRvrt = 0 — DISABLED, not
//	            pinned at zero. The pack does the opposite (enabled at zero,
//	            its declared idle posture) because a battery idling at zero is
//	            still in service; a PV inverter pinned at a 0 W setpoint would
//	            be curtailed to nothing for ever after one expiry.
//	VarSet      reverts to 0 var with VarSetEnaRvrt = 0 — same reasoning.
//	PFWInj /    revert to unity power factor with *EnaRvrt = 0. Unity is the
//	PFWAbs      value a PF axis means "no displacement" by, and the enable is
//	            the lapse the adjudication settles on.
//
// Written through the layout's own setters so the scale factors seeded a few
// lines earlier in populate704 do the encoding — PF_SF is −4, so unity is raw
// 10000 and nothing here restates that.
func seedSolarReversionDestinations(r *RegisterMap, m704 uint16) {
	regs := readSlice(r, m704, sunspec.L704.Len())
	v := sunspec.L704.View(regs)

	v.SetFloat("WMaxLimPctRvrt", 100)
	v.SetEnum("WMaxLimPctEnaRvrt", 1)

	v.SetFloat("WSetRvrt", 0)
	v.SetFloat("WSetPctRvrt", 0)
	v.SetEnum("WSetEnaRvrt", 0)

	v.SetFloat("VarSetRvrt", 0)
	v.SetFloat("VarSetPctRvrt", 0)
	v.SetEnum("VarSetEnaRvrt", 0)

	v.SetFloat("PFWInjRvrt_PF", 1)
	v.SetEnum("PFWInjRvrt_Ext", sunspec.M704_Ext_OverExcited)
	v.SetEnum("PFWInjEnaRvrt", 0)

	v.SetFloat("PFWAbsRvrt_PF", 1)
	v.SetEnum("PFWAbsRvrt_Ext", sunspec.M704_Ext_OverExcited)
	v.SetEnum("PFWAbsEnaRvrt", 0)

	writeSlice(r, m704, regs)
}
