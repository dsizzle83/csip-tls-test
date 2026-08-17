package sim

// reversion.go — the DEVICE-SIDE REVERSION TIMER ENGINE these simulators count
// down, and the accelerated timebase that lets a row prove ACTUAL EXPIRY
// without spending the wall-clock seconds the register nominally counts.
//
// The engine is family-generic: ONE countdown implementation, driven by a table
// of rvrtTimer descriptors that each say where a timer's registers live and
// what "the alternate set of function settings" means for the model that owns
// it. Model 704's five groups are defined here because this is where the engine
// was born; every other family the sims serve — the 7xx curve models, model 123
// and the legacy 12x curve family — is defined in reversionsolar.go, derived
// from the vendored model definitions rather than listed from memory, and
// pinned by TestEveryServedReversionTimerIsEngineManaged.
//
// # What was here before: nothing at all
//
// Before this file, no simulator in this repo had a reversion engine. The 704
// reversion points EXISTED — populate704 lays down the whole L704 block, so
// WMaxLimPctRvrtTms / WMaxLimPctRvrtRem / WSetRvrtTms / WSetRvrtRem and their
// *Rvrt destinations all read as IMPLEMENTED (zero, not the 0xFFFFFFFF
// sentinel) — but they were inert cells. A client could write RvrtTms=20, read
// it back, and watch RvrtRem sit at 0 forever; nothing decremented, nothing
// expired, and no control ever returned to its reversion value. The registers
// were storage, not a timer.
//
// Three consequences, all of them the reason this file exists:
//
//   - sim/gw-mayhem's control-reversion-timer scenario says so in its own doc:
//     "NeedsBench: the register-echo loopback has no reversion engine, so this
//     runs live only" (control_loop.go). It therefore writes RvrtTms=20, sleeps
//     ctlReversionHoldS = 25 REAL seconds, and can only be run against a
//     gateway driving real hardware.
//   - internal/certify/suitemodbusserver's REV-1/REV-2/REV-3 (SS-MODBUS-CONF
//     v1.4 §2.6) arm the timer and then sample WMaxLimPctRvrtRem three times
//     against their own monotonic clock with a ±2 s tolerance. Against an inert
//     register that readback is 0 for the whole countdown, so every sample
//     drifts by the full reversion time and the procedure cannot pass — not
//     because the DUT is non-conformant but because the fixture has no timer.
//   - the RC0 §9.5 bench battery could not run row 10 at all. It armed a
//     fixed-PF control with a window against `modsim -advanced`, watched
//     PFWInjRvrtTms sit at 258 s for six and a half minutes and PFWInjRvrtRem
//     read 0 throughout, and correctly REFUSED to record the gateway's own
//     release of the axis as the device timer lapsing. The engine reached the
//     battery pack and no solar sim; reversionsolar.go closes that.
//
// # WMaxLimPctRvrtTms: units, scale, and the value that means "no reversion"
//
// Provenance — the vendored SunSpec model definition, lexa-proto
// docs/schema/sunspec-models/model_704.json, group DERCtlAC. The four points of
// the WMaxLimPct reversion group, verbatim from that JSON:
//
//	WMaxLimPctRvrtTms   type uint32, size 2, units "Secs", access RW, NO "sf" key
//	                    "Limit maximum active power percent reversion time."
//	WMaxLimPctRvrtRem   type uint32, size 2, units "Secs", NO access key (⇒ read-only)
//	                    "Limit maximum active power percent reversion time remaining."
//	WMaxLimPctRvrt      type uint16, units "Pct", sf "WMaxLimPct_SF", access RW
//	                    "Reversion limit maximum active power percent value."
//	WMaxLimPctEnaRvrt   type enum16, access RW
//	                    "Reversion limit maximum active power percent value enable."
//
// The three facts a future expiry row would get wrong if this were guessed:
//
//  1. UNITS ARE WHOLE SECONDS. "units": "Secs". Not milliseconds, not tenths.
//  2. THERE IS NO SCALE FACTOR. The JSON gives RvrtTms and RvrtRem no "sf" key
//     at all (unlike their siblings WMaxLimPctRvrt/WSetRvrt, which DO name one),
//     so the register value IS the number of seconds — raw, unscaled. A uint32
//     of 20 means twenty seconds, and applying WMaxLimPct_SF (−2) to it, which
//     a careless reader might by proximity, would make it 0.2 s.
//  3. ZERO MEANS NO REVERSION; 0xFFFFFFFF MEANS NOT IMPLEMENTED. uint32's
//     not-implemented sentinel is 0xFFFFFFFF (sunspec/layout.go's maxValidU32
//     comment and View.notImpl), so zero is a legitimate, implemented value and
//     the only sane reading of it is "no timer armed". Three independent places
//     in this tree already speak that convention and now agree with the engine
//     below: lexa-proto derbase.Base.DefaultRvrtTms ("when NON-ZERO, is written
//     as the reversion timeout (seconds) on 704 control writes"); gw-mayhem's
//     disarmControlAxis, which writes WMaxLimPctRvrtTms=0 to "clear any
//     reversion timer"; and suitemodbusserver's cleanupReversion, whose REV-3
//     cancel is a write of 0 to the timer point. So: 0 = disarm, N>0 = arm for
//     N seconds, 0xFFFFFFFF = this device has no such timer.
//
// The same shape repeats for the other four reversion groups 704 carries
// (PFWInj, PFWAbs, WSet, VarSet — see rvrt704Groups), which is why the engine
// is table-driven rather than written once for WMaxLimPct.
//
// # What a timer reverts TO, and why the copy is raw
//
// On expiry the group's controlled point takes the value of its *Rvrt sibling
// and its enable takes *EnaRvrt. The controlled point and its reversion value
// are declared with the SAME scale factor (WMaxLimPct and WMaxLimPctRvrt both
// name "WMaxLimPct_SF"; WSet and WSetRvrt both name "WSet_SF"), so the revert
// is a REGISTER-FOR-REGISTER copy: no decode, no re-encode, no rounding, and no
// opportunity for the engineering value to shift by a power of ten on the way
// through. That is a property of the model, not a shortcut, and it is asserted
// against the compiled layout by TestReversionPointTypesAndScales — which also
// pins the two facts above it, that RvrtTms/RvrtRem are uint32 and carry no
// scale factor at all.
//
// lexa-proto's derbase records the matching product-side finding (IW13-004a):
// "the countdown DefaultRvrtTms already arms has never had a defined
// destination, so expiry today lands the device on whatever WSetRvrt/
// WSetEnaRvrt already hold — the factory default or a stale prior session."
// A real device HAS a factory default. seedPackReversionDestinations gives this
// pack an explicit, documented one rather than leaving it at an accidental zero.
//
// # The accelerated timebase — and what it does NOT prove
//
// The engine reads the current instant from a ReversionTimebase. The default is
// WallTimebase: time.Now, 1×, no scaling of any kind, on every sim, every
// binary and every bench invocation. Nothing in the environment and no flag
// changes it.
//
// It CAN now be changed at run time, on the solar sims only, by an explicit
// operator request: POST /control {"reversion_scale":N} (simapi ControlCmd →
// SolarServer.SetReversionScale, reversionsolar.go). That route did not exist
// when this file was written, and the reason it does now is §9.5 row 10: a
// reversion window a head end programs is minutes long, a bench window is not
// unbounded, and the alternative — a fixture that FAKES the expiry transition
// on a short timer — would prove nothing about the state machine under test.
// Accelerating the clock keeps the whole mechanism real: the same arm, the same
// countdown, the same publication, the same revert.
//
// What keeps that safe to expose is that it is IMPOSSIBLE TO DO SILENTLY:
//
//   - it is never a default and never configuration. A sim starts on the wall
//     clock and stays there unless a request says otherwise, so no bench script
//     or unit file can drift into it.
//   - the request is logged by the sim at the moment it lands, naming the
//     multiplier.
//   - the resulting clock is SELF-DECLARING on GET /state and in any evidence
//     bundle that records it (below), and the label is derived from the
//     declaration rather than composed by hand — so an accelerated sim cannot
//     spell itself "wall".
//   - installing a clock DISARMS every running countdown (setTimebase), so a
//     mid-countdown acceleration cannot silently produce a meaningless
//     measurement.
//
// The declaration is — since IW15 H6 — neither this file's to word nor a thing
// that stays on the bench. Every timebase implements Declare, which returns an
// evidence-bundle clock declaration (internal/evidence/bundle's Timebase): the
// KIND and the SCALE as numbers, and the human label RENDERED FROM THEM by the
// bundle package. Two consequences, and they are the two halves of what the
// gate found missing:
//
//   - the label rides on GET /state (BatteryPackState.Reversion.Timebase, and
//     SolarState.Reversion.Timebase on the solar sims) but is not composed
//     here, so this file cannot spell an accelerated clock "wall" — the
//     mutation the gate made, which left every test in the tree green because
//     nothing asserted the string;
//   - RecordTimebase (below) puts the declaration INTO THE EVIDENCE BUNDLE at
//     capture time, where REPORT.md prints it as a banner and `certify -verify`
//     re-derives the label from the numbers. Before that, the declaration
//     existed only in a live HTTP response no bundle carried, so an accelerated
//     bundle and a wall-clock one were the same document on their face.
//
// WHAT AN ACCELERATED PROOF ESTABLISHES: that THIS HARNESS's reversion state
// machine is correct — that arming sets the remaining-time readback, that the
// countdown reaches zero, that expiry applies the model's own alternate set
// (the *Rvrt destination and *EnaRvrt enable on 704; the default curve index on
// the 7xx curve models; the disabled state on 123 and the 12x family), that a
// re-write restarts the countdown and a write of 0 cancels it, and that the
// device's physics then follows the reverted command.
//
// WHAT IT DOES NOT ESTABLISH, AND MUST NEVER BE CITED FOR: anything about a
// real device's TIMING. It says nothing about whether real firmware honours
// RvrtTms to ±2 s, nothing about clock drift on a device that has been powered
// for a month, nothing about what happens across a real comms outage, and
// nothing about the gateway's own scheduling latency. Simulated time is not
// evidence about hardware. A conformance claim that a DER's reversion timer
// fires on time can only come from a run against that DER on its own wall
// clock — which is exactly what gw-mayhem's control-reversion-timer scenario
// (NeedsBench, 25 real seconds) is for, and this file does not replace it.

import (
	"fmt"
	"math"
	"sync"
	"time"

	"lexa-proto/sunspec"

	"csip-tls-test/internal/evidence/bundle"
)

// ── The timebase ─────────────────────────────────────────────────────────────

// TimebaseComponent names this fixture in a bundle's clock declaration. A
// declaration that does not say WHOSE clock it describes cannot be acted on, so
// the string is fixed here rather than passed in by each caller — a component
// name a recorder chose for itself is a component name that will one day
// disagree with another recorder's.
const TimebaseComponent = "sim/southbound: model 704 reversion engine"

// ReversionTimebase is the clock a 704 reversion engine counts its timers down
// against. It exists so a test can prove EXPIRY BEHAVIOUR without spending the
// seconds the register names; see this file's header for what that proves and
// what it does not.
//
// Declare is part of the interface, not a debugging afterthought. A timebase
// must be able to state what it is in the form evidence takes — the bundle's
// clock declaration, whose numbers a verifier can re-derive its label from — so
// that a clock installable into this engine is by construction a clock a bundle
// can honestly describe. Label is DERIVED from that declaration and never
// composed independently; see this file's header for the mutation that
// convention exists to make impossible.
type ReversionTimebase interface {
	Now() time.Time
	Declare() bundle.Timebase
	Label() string
}

// RecordTimebase writes a fixture clock's declaration into an evidence bundle
// under construction, naming where the declaration came from.
//
// This is the one call a bundle-producing run makes, and it belongs at CAPTURE
// TIME beside the code that installed the clock — that code is the only party
// that knows, and the whole point of the channel is that the knowledge travels
// with the evidence rather than staying in the operator's head. source is the
// provenance: "in-process handle to the pack under test", "GET
// http://69.0.0.11:6021/state .reversion.timebase", whatever is true.
//
// A nil timebase records nothing: a run that installed no clock has nothing to
// declare about one, and inventing a wall-clock declaration on its behalf would
// be this package asserting something it was never told.
func RecordTimebase(b *bundle.Builder, tb ReversionTimebase, source string) {
	if b == nil || tb == nil {
		return
	}
	d := tb.Declare()
	d.Source = source
	b.AddTimebase(d)
}

// wallTimebase is the DEFAULT and the only timebase any shipped path uses:
// time.Now, unscaled.
type wallTimebase struct{}

func (wallTimebase) Now() time.Time { return time.Now() }

// Declare states real, unscaled time.
func (wallTimebase) Declare() bundle.Timebase { return bundle.DeclareWall(TimebaseComponent, "") }

// Label is the declaration's label and nothing else — see the interface doc.
func (tb wallTimebase) Label() string { return tb.Declare().Label }

// WallTimebase returns the real-time timebase every sim starts with. Exported
// so a test that deliberately wants the un-accelerated behaviour back can say
// so by name rather than by passing nil.
func WallTimebase() ReversionTimebase { return wallTimebase{} }

// ManualTimebase is a simulated clock that moves ONLY when a test advances it.
// It is the hermetic option: a proof built on it takes microseconds, contains
// no sleep, and cannot flake under CI load, because no wall-clock duration
// appears anywhere in it.
//
// Zero value is not usable; construct with NewManualTimebase.
type ManualTimebase struct {
	mu  sync.Mutex
	t0  time.Time
	now time.Time
}

// NewManualTimebase returns a manual clock parked at a fixed, arbitrary instant.
// The instant is fixed rather than time.Now so that two runs of the same test
// produce byte-identical timings.
func NewManualTimebase() *ManualTimebase {
	// A stable, obviously-synthetic epoch: no run of a test on this clock can
	// be confused with a timestamp taken from the bench.
	start := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	return &ManualTimebase{t0: start, now: start}
}

// Now reports the simulated instant.
func (tb *ManualTimebase) Now() time.Time {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.now
}

// Advance moves simulated time forward by d. Negative d is ignored rather than
// rewinding: a device's dead-man timer does not run backwards, and a test that
// could rewind one would be proving a behaviour no device has.
func (tb *ManualTimebase) Advance(d time.Duration) {
	if d <= 0 {
		return
	}
	tb.mu.Lock()
	tb.now = tb.now.Add(d)
	tb.mu.Unlock()
}

// Declare states simulated time and how far it has been advanced, taken at the
// instant of the call: a manual clock's position is part of what it is, and a
// declaration recorded halfway through a test says so.
func (tb *ManualTimebase) Declare() bundle.Timebase {
	tb.mu.Lock()
	elapsed := tb.now.Sub(tb.t0)
	tb.mu.Unlock()
	return bundle.DeclareManual(TimebaseComponent, "", elapsed)
}

// Label names this timebase on GET /state, loudly — in the evidence package's
// words, not this file's.
func (tb *ManualTimebase) Label() string { return tb.Declare().Label }

// ScaledTimebase runs at a fixed multiple of the wall clock from the moment it
// is constructed. It is the option for a test that must keep a real listener,
// a real ticker and real goroutine scheduling in the picture — where
// ManualTimebase cannot be used because nothing in the test drives the engine
// step by hand — and it buys back the wall-clock cost by the scale factor: a
// 900 s reversion at 900× expires in one real second.
//
// It is strictly weaker than ManualTimebase (it still depends on real elapsed
// time, so it can still flake under load) and strictly weaker again than a
// bench run (see the header). Prefer ManualTimebase where the test can drive
// the step itself.
type ScaledTimebase struct {
	scale float64
	real0 time.Time
	sim0  time.Time
}

// NewScaledTimebase returns a timebase running scale× faster than the wall
// clock. scale must be > 0; anything else is a programming error rather than
// something to silently coerce to 1, because a caller that asked for
// acceleration and got real time would sit in a 900-second test wondering why.
func NewScaledTimebase(scale float64) *ScaledTimebase {
	if !(scale > 0) || math.IsInf(scale, 0) {
		panic(fmt.Sprintf("sim: NewScaledTimebase(%v): scale must be a positive, finite multiplier", scale))
	}
	now := time.Now()
	return &ScaledTimebase{scale: scale, real0: now, sim0: now}
}

// Now reports the accelerated instant.
func (tb *ScaledTimebase) Now() time.Time {
	elapsed := time.Since(tb.real0)
	return tb.sim0.Add(time.Duration(float64(elapsed) * tb.scale))
}

// Declare states the multiplier this clock runs at.
//
// The error DeclareScaled can return is impossible here and is therefore
// dropped rather than plumbed: NewScaledTimebase already panics on a scale that
// is not a positive finite multiplier, and tb.scale is immutable after
// construction. Should that ever stop being true, the zero declaration this
// returns fails bundle.Timebase.Check — it names no component and no kind — so
// the bundle refuses to be written rather than shipping a clock nobody can
// describe.
func (tb *ScaledTimebase) Declare() bundle.Timebase {
	d, err := bundle.DeclareScaled(TimebaseComponent, "", tb.scale)
	if err != nil {
		return bundle.Timebase{}
	}
	return d
}

// Label names this timebase on GET /state, loudly — in the evidence package's
// words, not this file's. THIS IS THE STRING THE GATE MUTATED to the flat lie
// "wall" with nothing going red; it is now a projection of the declaration
// above, pinned by internal/evidence/bundle's timebase_pin_test.go.
func (tb *ScaledTimebase) Label() string { return tb.Declare().Label }

// ── One reversion timer ──────────────────────────────────────────────────────

// rvrtTimer is ONE reversion timer as the engine sees it: where its registers
// live, how to read the programmed timeout, where (if anywhere) the model can
// publish the remaining time, and what "the alternate set of function settings"
// (SunSpec DER Information Model V1.2 §3.2) means for the model that owns it.
//
// The descriptor is per-TIMER, not per-model, because both shapes occur: model
// 704 carries five independent timers in one block and model 705 carries one.
type rvrtTimer struct {
	// Name is this timer's label on /state, in the log line an expiry writes,
	// and in the value step returns. The convention is the model id, plus a dot
	// and the point family when the model carries more than one timer:
	// "704.WSet", "123.Conn", "705", "126".
	//
	// The model id is part of it because the engine's armed set is keyed by
	// Name and TWO SERVED MODELS SHARE A FAMILY NAME: an advanced solar sim
	// serves both 123's WMaxLimPct_RvrtTms and 704's WMaxLimPctRvrtTms, and a
	// bare "WMaxLimPct" would have made those one timer that two different
	// writes armed and one expiry reverted.
	Name string
	// Model is the owning SunSpec model id, used to key the derivation pin
	// (timerPoints) so a timer cannot claim a point of a model the image does
	// not serve.
	Model uint16
	// Base is the model's DATA-BLOCK base address (past the id/length header).
	Base uint16
	// L is the layout Tms/Rem resolve against. On the block-structured models
	// (123, 704) it is the whole model; on the curve models (705/706/711/712
	// and the 12x family) it is the HEADER layout, which is where the reversion
	// points live.
	L *sunspec.Layout
	// Tms is the reversion timeout point: RW, whole seconds, unscaled.
	Tms string
	// Rem is the remaining-time readback, or "" on a model that DEFINES NONE.
	// Model 123 and the whole 12x curve family are in the second class — they
	// declare a timeout and no countdown — so on those models the countdown is
	// not observable through the registers at all, only the expiry transition
	// is. That is a property of the models, not an omission here; /state
	// carries what the wire cannot.
	Rem string
	// Revert applies this model's alternate set of function settings. It runs
	// OUTSIDE the engine's lock, exactly like every other register write the
	// sims do, and is called at most once per expiry.
	Revert func(r *RegisterMap)
}

// key is the (model, timeout point) identity used by the derivation pin. Name
// is for humans and may be shortened; this may not.
func (t rvrtTimer) key() string { return fmt.Sprintf("%d.%s", t.Model, t.Tms) }

// ── The reversion groups of model 704 ────────────────────────────────────────

// rvrt704Group names one reversion timer's registers. Field names are L704
// point names (vendor/lexa-proto/sunspec/derlayout.go), which are in turn
// proven against the vendored model JSON by that package's
// TestLayoutsMatchVendoredSpec — so no offset or width is restated here.
type rvrt704Group struct {
	// Name is the group's own label in logs and on /state; it is the common
	// prefix of the group's points, so a reader can find the registers.
	Name string
	// Ena / EnaRvrt are the function enable and the enable value expiry
	// restores. Both enum16.
	Ena, EnaRvrt string
	// Tms / Rem are the reversion time (RW, seconds, unscaled) and the
	// remaining-time readback (read-only, seconds, unscaled).
	Tms, Rem string
	// Values pairs each controlled point with the *Rvrt point expiry copies
	// into it. Both members of a pair share one scale factor, so the copy is
	// raw — see this file's header.
	Values [][2]string
}

// rvrt704Groups is every reversion timer model 704 defines. All five are
// engine-managed even though this pack only bridges WSet to physical effect:
// the timer is a property of the REGISTER GROUP, and a device that counted down
// only the axes its physics happens to use would be a device whose conformance
// behaviour depended on its wiring — the exact confusion SS-MODBUS-CONF §2.6's
// "for each reversion timer that is implemented" is written to avoid.
var rvrt704Groups = []rvrt704Group{
	{
		Name: "PFWInj", Ena: "PFWInjEna", EnaRvrt: "PFWInjEnaRvrt",
		Tms: "PFWInjRvrtTms", Rem: "PFWInjRvrtRem",
		Values: [][2]string{{"PFWInj_PF", "PFWInjRvrt_PF"}, {"PFWInj_Ext", "PFWInjRvrt_Ext"}},
	},
	{
		Name: "PFWAbs", Ena: "PFWAbsEna", EnaRvrt: "PFWAbsEnaRvrt",
		Tms: "PFWAbsRvrtTms", Rem: "PFWAbsRvrtRem",
		Values: [][2]string{{"PFWAbs_PF", "PFWAbsRvrt_PF"}, {"PFWAbs_Ext", "PFWAbsRvrt_Ext"}},
	},
	{
		Name: "WMaxLimPct", Ena: "WMaxLimPctEna", EnaRvrt: "WMaxLimPctEnaRvrt",
		Tms: "WMaxLimPctRvrtTms", Rem: "WMaxLimPctRvrtRem",
		Values: [][2]string{{"WMaxLimPct", "WMaxLimPctRvrt"}},
	},
	{
		Name: "WSet", Ena: "WSetEna", EnaRvrt: "WSetEnaRvrt",
		Tms: "WSetRvrtTms", Rem: "WSetRvrtRem",
		// BOTH representations revert together. WSetMod selects which one is in
		// force, and a device that reverted only the one it happened to be
		// using would leave a stale setpoint in the other — live again the
		// instant a head end changed WSetMod.
		Values: [][2]string{{"WSet", "WSetRvrt"}, {"WSetPct", "WSetPctRvrt"}},
	},
	{
		Name: "VarSet", Ena: "VarSetEna", EnaRvrt: "VarSetEnaRvrt",
		Tms: "VarSetRvrtTms", Rem: "VarSetRvrtRem",
		Values: [][2]string{{"VarSet", "VarSetRvrt"}, {"VarSetPct", "VarSetPctRvrt"}},
	},
}

// rvrt704Timers turns the five groups above into engine timers for the model
// 704 block at base.
//
// Model 704 is the ONLY family in this repo whose alternate set includes an
// ENABLE (*EnaRvrt). That is what makes the adjudicated "lapse" posture
// expressible on it and only on it: a head end that arms a window with
// *EnaRvrt = 0 is stating that at expiry this axis's function is simply not
// enabled — §3.2's "alternate set of function settings" combined with §3.3's
// "when the enable field is set to 0, any changes made to the setting will not
// take effect". Every other family's alternate is a curve index or nothing at
// all; see reversionsolar.go.
func rvrt704Timers(base uint16) []rvrtTimer {
	out := make([]rvrtTimer, 0, len(rvrt704Groups))
	for _, g := range rvrt704Groups {
		g := g
		out = append(out, rvrtTimer{
			Name:  "704." + g.Name,
			Model: sunspec.ModelDERCtlAC,
			Base:  base, L: sunspec.L704,
			Tms: g.Tms, Rem: g.Rem,
			Revert: func(r *RegisterMap) { revert704Group(r, base, g) },
		})
	}
	return out
}

// revert704Group copies one group's reversion destination over its controlled
// points and its enable. The value copy is RAW, register for register: a
// controlled point and its *Rvrt sibling are declared with the same scale
// factor, so decoding and re-encoding could only lose precision (or, on a
// mis-typed pair, silently rescale) and could never add anything.
func revert704Group(r *RegisterMap, base uint16, g rvrt704Group) {
	regs := readSlice(r, base, sunspec.L704.Len())
	for _, pair := range g.Values {
		to, from := sunspec.L704.Offset(pair[0]), sunspec.L704.Offset(pair[1])
		width := int(layoutFieldWidth(sunspec.L704, pair[0]))
		if to < 0 || from < 0 || to+width > len(regs) || from+width > len(regs) {
			continue
		}
		copy(regs[to:to+width], regs[from:from+width])
	}
	if to, from := sunspec.L704.Offset(g.Ena), sunspec.L704.Offset(g.EnaRvrt); to >= 0 && from >= 0 {
		regs[to] = regs[from]
	}
	writeSlice(r, base, regs)
}

// ── The engine ───────────────────────────────────────────────────────────────

// rvrtEngine is a set of device-side reversion timers over one register map.
//
// The DEADLINE lives in Go, not in a register, because RvrtRem is a whole-second
// integer and a countdown stored only there would quantise its own expiry to the
// second and drift by one every time it was republished. The register is the
// PUBLICATION of the deadline (ceil of the remaining seconds, which is what a
// client polling it must see), never the state of record. Everything a Modbus
// client can observe still comes out of the register bank.
type rvrtEngine struct {
	mu     sync.Mutex
	tb     ReversionTimebase
	timers []rvrtTimer

	// armed maps timer Name -> deadline in the timebase's own frame. Absent
	// means disarmed, which is also what RvrtTms==0 means on the wire.
	armed map[string]time.Time
}

// newRvrtEngine builds an engine over an explicit timer table, on the wall
// clock.
func newRvrtEngine(timers []rvrtTimer) *rvrtEngine {
	return &rvrtEngine{tb: WallTimebase(), timers: timers, armed: make(map[string]time.Time, len(timers))}
}

// newRvrt704Engine is the battery pack's engine: model 704's five groups and
// nothing else, because that is the only reversion-bearing model the pack
// serves.
func newRvrt704Engine(base uint16) *rvrtEngine { return newRvrtEngine(rvrt704Timers(base)) }

// timerPoints reports every timer's (model, timeout point) identity, for the
// derivation pin that requires the table to cover exactly what the image
// serves. Exists so a test can ask the engine what it manages instead of
// re-deriving the answer from the same table it is checking.
func (e *rvrtEngine) timerPoints() []string {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.timers))
	for _, t := range e.timers {
		out = append(out, t.key())
	}
	return out
}

// setTimers replaces the timer table — what a device whose MODEL MAP was
// RE-LAID at run time needs, since a descriptor carries a base address — and
// disarms everything, for the same reason setTimebase does: a deadline armed
// against a register that has since moved is a deadline against someone else's
// register.
func (e *rvrtEngine) setTimers(timers []rvrtTimer, r *RegisterMap) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.timers = timers
	clear(e.armed)
	e.mu.Unlock()
	e.publish(r)
}

// setTimebase swaps the clock the timers count against and disarms everything,
// because a deadline computed in one frame is meaningless in another: a
// wall-clock deadline of 15:04:05 read against a manual clock parked in the
// year 2000 is 26 years in the future, and a test that swapped the clock
// mid-countdown without this would silently prove nothing.
func (e *rvrtEngine) setTimebase(tb ReversionTimebase, r *RegisterMap) {
	if tb == nil {
		tb = WallTimebase()
	}
	e.mu.Lock()
	e.tb = tb
	clear(e.armed)
	e.mu.Unlock()
	e.publish(r)
}

// timebase returns the clock currently installed, so a bundle-producing run can
// record its declaration (RecordTimebase) without holding a second copy of it.
func (e *rvrtEngine) timebase() ReversionTimebase {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tb
}

// timebaseLabel names the current clock for GET /state.
func (e *rvrtEngine) timebaseLabel() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tb.Label()
}

// covers reports whether a Modbus write of n registers starting at start
// touched any register of the point named on t. Any overlap counts: a single
// register FC6 into the low word of a uint32 timer is still a write to that
// timer, and the engine re-reads the full point from the bank afterwards rather
// than trusting the fragment it saw.
func (t rvrtTimer) covers(start uint16, n int) bool {
	off := t.L.Offset(t.Tms)
	if n <= 0 || off < 0 {
		return false
	}
	pt := uint32(t.Base) + uint32(off)
	width := uint32(layoutFieldWidth(t.L, t.Tms))
	wr := uint32(start)
	return wr < pt+width && pt < wr+uint32(n)
}

// observeWrite is the write hook: a Modbus write that LANDED on a timer's
// RvrtTms registers arms, re-arms or cancels that timer.
//
// THE TRIGGER IS THE WRITE, NOT A VALUE CHANGE, and that is load-bearing twice
// over. SS-MODBUS-CONF v1.4 REV-2 (Reversion Time Update) rewrites the timer
// register with THE SAME reversion time after half the countdown has elapsed
// and requires the countdown to restart from there; an engine that re-armed
// only on a changed value would leave REV-2's countdown running out at the
// original instant and fail a conforming procedure. SunSpec DER Information
// Model V1.2 §3.2 states the same rule in general terms: "If a setting is
// updated while the reversion timer is active or the function is re-enabled,
// the reversion timer SHALL be reinitialized with the reversion timeout value,
// and the timer is restarted."
//
// A write elsewhere in the block — the controlled point, a ramp rate, the
// anti-islanding enable — deliberately does NOT restart an armed countdown.
// derbase writes the whole 704 block read-modify-write, so its RvrtTms lands in
// the same transaction as its setpoint and the refresh happens anyway; making
// any 704 write refresh every timer would additionally mean that writing
// AntiIslEna silently extended a WSet dead-man switch, which is a device
// behaviour nobody would be able to justify to a reviewer.
//
// ARMING IS NOT GATED ON THE FUNCTION'S ENABLE, and that is a deliberate reading
// of §3.2 rather than an oversight. §3.2's Disabled state is "the function SHALL
// be either not enabled or the reversion timeout value SHALL be set to zero" —
// which would make a timer written against a disabled function inert. But
// SS-MODBUS-CONF v1.4 §2.6's REV-1 procedure arms by writing THE TIMER REGISTER
// ALONE and then requires the remaining-time readback to count down, and a
// fixture that refused to count for a conforming procedure would be failing the
// procedure on the fixture's opinion. So: RvrtTms > 0 arms, and the enable
// decides only what the expiry's alternate set means.
func (e *rvrtEngine) observeWrite(r *RegisterMap, start uint16, n int) {
	if e == nil || r == nil || n <= 0 {
		return
	}
	e.mu.Lock()
	now := e.tb.Now()
	for _, t := range e.timers {
		if !t.covers(start, n) {
			continue
		}
		// ok=false is the type's not-implemented sentinel (or an absent point)
		// — a device saying it has no such timer, which is disarmed for the
		// same reason zero is but for a different reason on the wire.
		switch tms, ok := t.readTms(r); {
		case !ok || tms == 0:
			delete(e.armed, t.Name)
		default:
			e.armed[t.Name] = now.Add(time.Duration(tms) * time.Second)
		}
	}
	e.mu.Unlock()

	// Republish every timer's remaining-time readback, not just the ones this
	// write armed. RvrtRem is read-only in the models but the register bank does
	// not enforce that (protecting it would make every derbase whole-block
	// read-modify-write during a live countdown log a masked-write rejection,
	// since the value it read a moment ago is no longer the value it is writing
	// back). Republishing after every write is the cheaper and quieter way to
	// keep the engine, not the client, authoritative over the countdown.
	e.publish(r)
}

// readTms reads a timer's programmed timeout out of the register bank, at
// whatever width the model declares it (uint32 on 704 and the 7xx curve models,
// uint16 on 123 and the 12x family). ok=false means absent or not-implemented.
func (t rvrtTimer) readTms(r *RegisterMap) (uint64, bool) {
	regs := readSlice(r, t.Base, t.L.Len())
	return t.L.View(regs).Raw(t.Tms)
}

// step advances every armed timer against the current timebase instant: it
// republishes the remaining-time readbacks and applies the reversion of any
// timer that has reached zero. It returns the names of the timers that expired
// on THIS call, so the caller can give the revert its physical consequences
// exactly once.
//
// Expiry moves a timer to §3.2's Stopped state — it is REMOVED from the armed
// set and only a fresh write may restart it — so a second step with no
// intervening write reverts nothing.
//
// Called from the sim's own reversion loop in production and directly by unit
// tests — the same split batteryPackStep already uses, and the reason an
// accelerated proof needs no ticker and no sleep.
func (e *rvrtEngine) step(r *RegisterMap) []string {
	if e == nil || r == nil {
		return nil
	}
	e.mu.Lock()
	now := e.tb.Now()
	var expired []rvrtTimer
	for _, t := range e.timers {
		deadline, ok := e.armed[t.Name]
		if !ok || now.Before(deadline) {
			continue
		}
		delete(e.armed, t.Name)
		expired = append(expired, t)
	}
	e.mu.Unlock()

	names := make([]string, 0, len(expired))
	for _, t := range expired {
		if t.Revert != nil {
			t.Revert(r)
		}
		names = append(names, t.Name)
	}
	e.publish(r)
	if len(names) == 0 {
		return nil
	}
	return names
}

// disarmAll cancels every timer without reverting anything — what a POWER CYCLE
// does. A reversion timer is volatile control state: a device that came back
// from a rail drop still counting down a timer a controller armed before the
// drop would be honouring an instruction it has no other memory of. This is
// packPowerOnReset's counterpart, and it deliberately does NOT apply the
// reversion values: the power-on reset already returns the controls to their own
// defaults, and reverting on top of that would let a controller's stale *Rvrt
// destination survive a power cycle that erased everything else it wrote.
func (e *rvrtEngine) disarmAll(r *RegisterMap) {
	if e == nil {
		return
	}
	e.mu.Lock()
	clear(e.armed)
	e.mu.Unlock()
	e.publish(r)
}

// publish writes every timer's remaining-time readback from the engine's own
// state: the CEILING of the seconds left on an armed timer, and zero on a
// disarmed one. Timers whose model defines no remaining-time point are skipped
// — there is nowhere on the wire to publish them (see rvrtTimer.Rem).
//
// Ceiling rather than round or truncate, because the readback is what a client
// polls to decide whether the timer has fired: truncation would report 0 for
// the last full second of a live timer, telling a conforming controller its
// control had already reverted while the device was still holding it.
func (e *rvrtEngine) publish(r *RegisterMap) {
	if e == nil || r == nil {
		return
	}
	// The timer table itself is snapshotted under the lock, not just the
	// remaining times: setTimers can replace it from another goroutine, and a
	// publish that iterated the live slice would be writing a countdown into
	// the register bank of a model that has moved.
	e.mu.Lock()
	now := e.tb.Now()
	timers := append([]rvrtTimer(nil), e.timers...)
	rem := make(map[string]uint64, len(timers))
	for _, t := range timers {
		deadline, ok := e.armed[t.Name]
		if !ok {
			rem[t.Name] = 0
			continue
		}
		left := deadline.Sub(now)
		if left <= 0 {
			// Reached zero but not yet stepped: report 0 rather than a negative
			// wrap. The expiry itself lands on the next step.
			rem[t.Name] = 0
			continue
		}
		rem[t.Name] = uint64(math.Ceil(left.Seconds()))
	}
	e.mu.Unlock()

	for _, t := range timers {
		if t.Rem == "" {
			continue
		}
		setLayoutUint(r, t.Base, t.L, t.Rem, rem[t.Name])
	}
}

// armedGroups reports the live countdowns for GET /state, read from the engine
// and the register bank together so the two can be compared by a reader rather
// than taken on trust.
//
// RemS on a model that publishes no remaining-time point is the ENGINE's
// number, because there is no register to read it from — and it is exactly why
// this section exists for those models: it is the only place the countdown of a
// 123 or 12x timer is visible at all.
func (e *rvrtEngine) armedGroups(r *RegisterMap) []ReversionGroupState {
	if e == nil || r == nil {
		return nil
	}
	e.mu.Lock()
	now := e.tb.Now()
	type live struct {
		armed bool
		rem   uint64
	}
	timers := append([]rvrtTimer(nil), e.timers...)
	state := make(map[string]live, len(timers))
	for _, t := range timers {
		deadline, ok := e.armed[t.Name]
		l := live{armed: ok}
		if ok {
			if left := deadline.Sub(now); left > 0 {
				l.rem = uint64(math.Ceil(left.Seconds()))
			}
		}
		state[t.Name] = l
	}
	e.mu.Unlock()

	var out []ReversionGroupState
	for _, t := range timers {
		tms, tmsOK := t.readTms(r)
		l := state[t.Name]
		if !l.armed && (!tmsOK || tms == 0) {
			continue // neither configured nor running: nothing to say about it
		}
		rem := l.rem
		if t.Rem != "" {
			regs := readSlice(r, t.Base, t.L.Len())
			if v, ok := t.L.View(regs).Raw(t.Rem); ok {
				rem = v // the wire's own answer, so /state and Modbus can be compared
			}
		}
		out = append(out, ReversionGroupState{
			Name: t.Name, Model: t.Model, Armed: l.armed,
			TmsS: uint32(tms), RemS: uint32(rem), RemOnWire: t.Rem != "",
		})
	}
	return out
}

// ── /state ───────────────────────────────────────────────────────────────────

// ReversionState is a sim's reversion engine on GET /state.
type ReversionState struct {
	// Timebase names the clock the timers counted down against. It reads
	// "wall" on every production and bench path that has not explicitly asked
	// for acceleration. ANYTHING ELSE means the run was ACCELERATED and its
	// timings are evidence about this harness's state machine only — never
	// about a real device. It is published rather than merely documented so an
	// evidence bundle cannot be misread later.
	Timebase string `json:"timebase"`
	// Groups lists every reversion timer that is configured (RvrtTms non-zero)
	// or running. A timer that is neither is omitted rather than reported as a
	// row of zeros, so what is present on /state is what a reader must account
	// for.
	Groups []ReversionGroupState `json:"groups,omitempty"`
}

// ReversionGroupState is one reversion timer: what it was programmed for,
// whether the engine is counting it, and what is left. Armed and RemS come from
// two different places on purpose — the engine and the wire — so a row can prove
// they agree.
type ReversionGroupState struct {
	Name  string `json:"name"`
	Model uint16 `json:"model"`
	Armed bool   `json:"armed"`
	TmsS  uint32 `json:"tms_s"`
	RemS  uint32 `json:"rem_s"`
	// RemOnWire says whether rem_s can also be read from a register. It is
	// FALSE for model 123 and the legacy 12x curve family, which declare a
	// reversion timeout and no remaining-time point at all — on those models
	// this JSON is the only countdown there is, and a reader who assumed
	// otherwise would go looking for a register that does not exist.
	RemOnWire bool `json:"rem_on_wire"`
}

// PackReversionState / PackReversionGroupState are the names the battery pack's
// /state document was written against, kept as aliases so that document — and
// anything decoding it — is unchanged by the engine becoming family-generic.
type (
	PackReversionState      = ReversionState
	PackReversionGroupState = ReversionGroupState
)

// ── Register helpers ─────────────────────────────────────────────────────────

// setLayoutUint writes an unsigned value into a named point of a
// layout-described block, at the width the layout declares (one register or
// two). It exists because the reversion engine spans models that declare their
// time points at different widths — uint32 on 704/705/706/711/712, uint16 on
// 123 and the 12x family — and a helper that assumed one of them would silently
// write half a value on the other.
//
// A value too wide for the declared field is clamped one below the type's
// not-implemented sentinel rather than truncated: reporting 0xFFFF ("this
// device has no such point") for a live countdown would be a lie of a
// completely different kind from reporting a saturated one.
func setLayoutUint(r *RegisterMap, base uint16, l *sunspec.Layout, name string, val uint64) {
	off := l.Offset(name)
	if off < 0 {
		return
	}
	switch layoutFieldWidth(l, name) {
	case 1:
		if val > 0xFFFE {
			val = 0xFFFE
		}
		r.Set(base+uint16(off), uint16(val))
	case 2:
		if val > 0xFFFFFFFE {
			val = 0xFFFFFFFE
		}
		setU32Reg(r, base+uint16(off), uint32(val))
	}
}

// setU32Reg writes a big-endian uint32 across two holding registers, the
// SunSpec wire order (most-significant register first — sunspec/layout.go's
// package doc). Sim-internal Set, so write-protection does not apply: the
// engine owns these cells the way the animation owns the measurement ones.
func setU32Reg(r *RegisterMap, addr uint16, val uint32) {
	r.Set(addr, uint16(val>>16))
	r.Set(addr+1, uint16(val))
}
