package sim

// reversion704.go — the DEVICE-SIDE REVERSION TIMER for SunSpec model 704, and
// the accelerated test timebase that lets a row prove ACTUAL EXPIRY without
// spending the wall-clock seconds the register nominally counts.
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
// Two consequences, both of them the reason this file exists:
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
// WallTimebase: time.Now, 1×, no scaling of any kind. There is no environment
// variable, no flag, and no simapi route that can change it — the ONLY way to
// accelerate a timer is for Go code holding the *BatteryServer to call
// SetReversionTimebase, which no production path, no sim binary and no bench
// script does. That is the whole design of the knob: acceleration cannot happen
// by accident or by configuration drift, only by a test saying so in source.
//
// It is also SELF-DECLARING, and — since IW15 H6 — the declaration is neither
// this file's to word nor a thing that stays on the bench. Every timebase
// implements Declare, which returns an evidence-bundle clock declaration
// (internal/evidence/bundle's Timebase): the KIND and the SCALE as numbers, and
// the human label RENDERED FROM THEM by the bundle package. Two consequences,
// and they are the two halves of what the gate found missing:
//
//   - the label rides on GET /state exactly as before
//     (BatteryPackState.Reversion.Timebase) but is no longer composed here, so
//     this file cannot spell an accelerated clock "wall" — the mutation the
//     gate made, which left every test in the tree green because nothing
//     asserted the string;
//   - RecordTimebase (below) puts the declaration INTO THE EVIDENCE BUNDLE at
//     capture time, where REPORT.md prints it as a banner and `certify -verify`
//     re-derives the label from the numbers. Before that, the declaration
//     existed only in a live HTTP response no bundle carried, so an accelerated
//     bundle and a wall-clock one were the same document on their face.
//
// WHAT AN ACCELERATED PROOF ESTABLISHES: that THIS HARNESS's reversion state
// machine is correct — that arming sets the remaining-time readback, that the
// countdown reaches zero, that expiry copies the *Rvrt destination into the
// controlled point and *EnaRvrt into the enable, that a re-write restarts the
// countdown and a write of 0 cancels it, and that the pack's physics then
// follows the reverted setpoint.
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

// ── The engine ───────────────────────────────────────────────────────────────

// rvrt704Engine is the device-side reversion timer set for one model 704 block.
//
// The DEADLINE lives in Go, not in a register, because RvrtRem is a whole-second
// uint32 and a countdown stored only there would quantise its own expiry to the
// second and drift by one every time it was republished. The register is the
// PUBLICATION of the deadline (ceil of the remaining seconds, which is what a
// client polling it must see), never the state of record. Everything a Modbus
// client can observe still comes out of the register bank.
type rvrt704Engine struct {
	mu   sync.Mutex
	tb   ReversionTimebase
	base uint16 // model 704 data-block base address

	// armed maps group name -> deadline in the timebase's own frame. Absent
	// means disarmed, which is also what RvrtTms==0 means on the wire.
	armed map[string]time.Time
}

func newRvrt704Engine(base uint16) *rvrt704Engine {
	return &rvrt704Engine{tb: WallTimebase(), base: base, armed: make(map[string]time.Time, len(rvrt704Groups))}
}

// setTimebase swaps the clock the timers count against and disarms everything,
// because a deadline computed in one frame is meaningless in another: a
// wall-clock deadline of 15:04:05 read against a manual clock parked in the
// year 2000 is 26 years in the future, and a test that swapped the clock
// mid-countdown without this would silently prove nothing.
func (e *rvrt704Engine) setTimebase(tb ReversionTimebase, r *RegisterMap) {
	if tb == nil {
		tb = WallTimebase()
	}
	e.mu.Lock()
	e.tb = tb
	clear(e.armed)
	e.mu.Unlock()
	e.publish(r)
}

// timebaseLabel names the current clock for GET /state.
func (e *rvrt704Engine) timebaseLabel() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tb.Label()
}

// covers reports whether a Modbus write of n registers starting at start
// touched any register of a point at layout offset off. Any overlap counts: a
// single-register FC6 into the low word of a uint32 timer is still a write to
// that timer, and the engine re-reads the full point from the bank afterwards
// rather than trusting the fragment it saw.
func (e *rvrt704Engine) covers(start uint16, n int, off int, width uint16) bool {
	if n <= 0 || off < 0 {
		return false
	}
	pt := uint32(e.base) + uint32(off)
	wr := uint32(start)
	return wr < pt+uint32(width) && pt < wr+uint32(n)
}

// observeWrite is the write hook: a Modbus write that LANDED on a group's
// RvrtTms registers arms, re-arms or cancels that group's timer.
//
// THE TRIGGER IS THE WRITE, NOT A VALUE CHANGE, and that is load-bearing:
// SS-MODBUS-CONF v1.4 REV-2 (Reversion Time Update) rewrites the timer register
// with THE SAME reversion time after half the countdown has elapsed and
// requires the countdown to restart from there. An engine that re-armed only on
// a changed value would leave REV-2's countdown running out at the original
// instant and fail a conforming procedure.
//
// A write elsewhere in the block — the controlled point, a ramp rate, the
// anti-islanding enable — deliberately does NOT restart an armed countdown.
// derbase writes the whole 704 block read-modify-write, so its RvrtTms lands in
// the same transaction as its setpoint and the refresh happens anyway; making
// any 704 write refresh every timer would additionally mean that writing
// AntiIslEna silently extended a WSet dead-man switch, which is a device
// behaviour nobody would be able to justify to a reviewer.
func (e *rvrt704Engine) observeWrite(r *RegisterMap, start uint16, n int) {
	if e == nil || r == nil || n <= 0 {
		return
	}
	regs := readSlice(r, e.base, sunspec.L704.Len())
	v := sunspec.L704.View(regs)

	e.mu.Lock()
	now := e.tb.Now()
	for _, g := range rvrt704Groups {
		if !e.covers(start, n, sunspec.L704.Offset(g.Tms), layoutFieldWidth(sunspec.L704, g.Tms)) {
			continue
		}
		// ok=false is the 0xFFFFFFFF not-implemented sentinel (or an absent
		// point) — a device saying it has no such timer, which is disarmed for
		// the same reason zero is but for a different reason on the wire.
		switch tms, ok := v.U32(g.Tms); {
		case !ok || tms == 0:
			delete(e.armed, g.Name)
		default:
			e.armed[g.Name] = now.Add(time.Duration(tms) * time.Second)
		}
	}
	e.mu.Unlock()

	// Republish every group's remaining-time readback, not just the ones this
	// write armed. RvrtRem is read-only in the model but the register bank does
	// not enforce that (protecting it would make every derbase whole-block
	// read-modify-write during a live countdown log a masked-write rejection,
	// since the value it read a moment ago is no longer the value it is writing
	// back). Republishing after every write is the cheaper and quieter way to
	// keep the engine, not the client, authoritative over the countdown.
	e.publish(r)
}

// step advances every armed timer against the current timebase instant: it
// republishes the remaining-time readbacks and applies the reversion of any
// timer that has reached zero. It returns the names of the groups that expired
// on THIS call, so the caller can give the revert its physical consequences
// exactly once.
//
// Called from the pack's own reversion loop in production and directly by unit
// tests — the same split batteryPackStep already uses, and the reason an
// accelerated proof needs no ticker and no sleep.
func (e *rvrt704Engine) step(r *RegisterMap) []string {
	if e == nil || r == nil {
		return nil
	}
	e.mu.Lock()
	now := e.tb.Now()
	var expired []string
	for _, g := range rvrt704Groups {
		deadline, ok := e.armed[g.Name]
		if !ok || now.Before(deadline) {
			continue
		}
		delete(e.armed, g.Name)
		expired = append(expired, g.Name)
	}
	e.mu.Unlock()

	for _, name := range expired {
		e.applyRevert(r, name)
	}
	e.publish(r)
	return expired
}

// disarmAll cancels every timer without reverting anything — what a POWER CYCLE
// does. A reversion timer is volatile control state: a device that came back
// from a rail drop still counting down a timer a controller armed before the
// drop would be honouring an instruction it has no other memory of. This is
// packPowerOnReset's counterpart for the 704 block, and it deliberately does
// NOT apply the reversion values: the power-on reset already returns the
// controls to their own defaults, and reverting on top of that would let a
// controller's stale *Rvrt destination survive a power cycle that erased
// everything else it wrote.
func (e *rvrt704Engine) disarmAll(r *RegisterMap) {
	if e == nil {
		return
	}
	e.mu.Lock()
	clear(e.armed)
	e.mu.Unlock()
	e.publish(r)
}

// applyRevert copies one group's reversion destination over its controlled
// points and its enable. The value copy is RAW, register for register: a
// controlled point and its *Rvrt sibling are declared with the same scale
// factor, so decoding and re-encoding could only lose precision (or, on a
// mis-typed pair, silently rescale) and could never add anything.
func (e *rvrt704Engine) applyRevert(r *RegisterMap, name string) {
	var g rvrt704Group
	for _, cand := range rvrt704Groups {
		if cand.Name == name {
			g = cand
			break
		}
	}
	if g.Name == "" {
		return
	}
	regs := readSlice(r, e.base, sunspec.L704.Len())
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
	writeSlice(r, e.base, regs)
}

// publish writes every group's remaining-time readback from the engine's own
// state: the CEILING of the seconds left on an armed timer, and zero on a
// disarmed one.
//
// Ceiling rather than round or truncate, because the readback is what a client
// polls to decide whether the timer has fired: truncation would report 0 for
// the last full second of a live timer, telling a conforming controller its
// control had already reverted while the device was still holding it.
func (e *rvrt704Engine) publish(r *RegisterMap) {
	if e == nil || r == nil {
		return
	}
	e.mu.Lock()
	now := e.tb.Now()
	rem := make(map[string]uint32, len(rvrt704Groups))
	for _, g := range rvrt704Groups {
		deadline, ok := e.armed[g.Name]
		if !ok {
			rem[g.Name] = 0
			continue
		}
		left := deadline.Sub(now)
		if left <= 0 {
			// Reached zero but not yet stepped: report 0 rather than a negative
			// wrap. The expiry itself lands on the next step.
			rem[g.Name] = 0
			continue
		}
		rem[g.Name] = uint32(math.Ceil(left.Seconds()))
	}
	e.mu.Unlock()

	for _, g := range rvrt704Groups {
		off := sunspec.L704.Offset(g.Rem)
		if off < 0 {
			continue
		}
		setU32Reg(r, e.base+uint16(off), rem[g.Name])
	}
}

// armedGroups reports the live countdowns for GET /state, newest state first
// read from the engine and the register bank together so the two can be
// compared by a reader rather than taken on trust.
func (e *rvrt704Engine) armedGroups(r *RegisterMap) []PackReversionGroupState {
	if e == nil || r == nil {
		return nil
	}
	regs := readSlice(r, e.base, sunspec.L704.Len())
	v := sunspec.L704.View(regs)

	e.mu.Lock()
	defer e.mu.Unlock()
	var out []PackReversionGroupState
	for _, g := range rvrt704Groups {
		tms, tmsOK := v.U32(g.Tms)
		rem, _ := v.U32(g.Rem)
		_, armed := e.armed[g.Name]
		if !armed && (!tmsOK || tms == 0) {
			continue // neither configured nor running: nothing to say about it
		}
		out = append(out, PackReversionGroupState{
			Name: g.Name, Armed: armed, TmsS: tms, RemS: rem,
		})
	}
	return out
}

// setU32Reg writes a big-endian uint32 across two holding registers, the
// SunSpec wire order (most-significant register first — sunspec/layout.go's
// package doc). Sim-internal Set, so write-protection does not apply: the
// engine owns these cells the way the animation owns the measurement ones.
func setU32Reg(r *RegisterMap, addr uint16, val uint32) {
	r.Set(addr, uint16(val>>16))
	r.Set(addr+1, uint16(val))
}
