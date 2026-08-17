package sim

// reversion704_test.go — the ACCELERATED-EXPIRY proof for the pack's model 704
// reversion timer (reversion704.go).
//
// The rows here prove three things that could not be proved before this engine
// existed, and one thing about the proof itself:
//
//	hold-then-revert   a setpoint written with WSetRvrtTms holds for the whole
//	                   countdown and is REPLACED by its reversion destination
//	                   the moment the timer runs out — in the registers AND in
//	                   the pack's commanded watts.
//	REV-2 / REV-3      rewriting the timer restarts the countdown; writing zero
//	                   cancels it (SS-MODBUS-CONF v1.4 §2.6's own two follow-on
//	                   procedures, expressed against the fixture).
//	the units          RvrtTms/RvrtRem are unscaled whole seconds and every
//	                   controlled/reversion value pair shares one scale factor,
//	                   proven against the layout rather than restated here.
//
// And the fourth: TestPack704ReversionAssertionHasTeeth is the RED PROOF. The
// same assertion the green row passes is run against three devices that do NOT
// revert, and each must FAIL it — including the one that is hardest to catch,
// a device that never applied the setpoint at all and therefore ENDS ON THE
// REVERSION VALUE without a timer having done anything. A green row that could
// not tell that device from a reverting one would be proving nothing.
//
// EVERY ROW HERE RUNS ON A MANUAL TIMEBASE. Read reversion704.go's header
// first: an accelerated proof establishes this harness's expiry semantics and
// its state machine, and says NOTHING about a real device's timing. Nothing in
// this file may be cited as evidence that firmware honours RvrtTms.

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"lexa-proto/sunspec"
)

// ── Rig ──────────────────────────────────────────────────────────────────────

const (
	// revTestTmsS is the reversion time the rows program: fifteen minutes on
	// the REGISTER's clock, which on a wall-clock fixture would be a
	// fifteen-minute test and here is a handful of microseconds. It is
	// deliberately long enough that nobody could mistake these rows for having
	// waited it out.
	revTestTmsS = 900
	// revTestHeldW is the setpoint the rows command: a charge (negative) at the
	// pack's declared charge-rate rating, so the commanded value is inside
	// every bound the pack honours and a failure to hold cannot be blamed on a
	// clamp.
	revTestHeldW = -packChaRteRatingFrac * testPackWmax // −2000 W
)

// newRevTestPack builds a 704-capable pack on a MANUAL timebase and returns
// both, so a row can move the device's clock without moving the machine's.
func newRevTestPack(t *testing.T) (*BatteryServer, *ManualTimebase) {
	t.Helper()
	bs := newTestPack(t, PackShapeSetpoint)
	tb := NewManualTimebase()
	if err := bs.SetReversionTimebase(tb); err != nil {
		t.Fatalf("SetReversionTimebase on the 704-capable pack: %v", err)
	}
	return bs, tb
}

// armWSetWithReversion writes the setpoint AND its reversion time in ONE
// whole-block read-modify-write, which is the shape the product produces:
// derbase's SetActivePowerWatts writes WSetRvrtTms (from Base.DefaultRvrtTms)
// in the same transaction as WSet. Arming through a bench-only two-write
// sequence would prove the engine against a wire shape nothing sends.
func armWSetWithReversion(t *testing.T, bs *BatteryServer, w float64, tmsS uint32) {
	t.Helper()
	m704 := bs.pack.adv.M704
	regs := mbRead(t, bs, m704, uint16(sunspec.L704.Len()))
	v := sunspec.L704.View(regs)
	v.SetBool("WSetEna", true)
	v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
	v.SetFloat("WSet", w)
	v.SetU32("WSetRvrtTms", tmsS)
	mbWrite(t, bs, m704, regs...)
}

// readRvrtU32 reads one of 704's uint32 reversion points THROUGH THE MODBUS
// HANDLER, so the row sees what a client sees rather than what the engine
// believes.
func readRvrtU32(t *testing.T, bs *BatteryServer, point string) uint32 {
	t.Helper()
	off := sunspec.L704.Offset(point)
	if off < 0 {
		t.Fatalf("model 704 carries no point %q", point)
	}
	regs := mbRead(t, bs, bs.pack.adv.M704+uint16(off), 2)
	return uint32(regs[0])<<16 | uint32(regs[1])
}

// packCommandedW is the pack's standing dispatch in watts (+ discharge, −
// charge), read out of the legacy 123 mirror the 704 bridge writes and the
// physics reads. NaN means no dispatch is in force at all.
func packCommandedW(bs *BatteryServer) float64 {
	return hubBatteryW(bs.Regs, bs.bases.M123Base, bs.wmaxW)
}

// ── The three-way assertion ──────────────────────────────────────────────────

// revertOutcome is what a device DID with a setpoint that had a reversion timer
// armed against it. There are four, and telling them apart is the entire point:
// three of them are distinct defects and only one is the behaviour under test.
type revertOutcome string

const (
	outcomeReverted     revertOutcome = "REVERTED"
	outcomeNeverApplied revertOutcome = "WAS NEVER APPLIED"
	outcomeStillHeld    revertOutcome = "STILL HELD"
	outcomeWrongValue   revertOutcome = "REVERTED TO THE WRONG VALUE"
)

// reversionObs is one observation of a device across an expiry boundary: what
// it was commanded to, what it was actually doing on each side of the deadline,
// and what its own remaining-time readback said on each side.
type reversionObs struct {
	// WantHeld is the value the client commanded; WantRevert is the value the
	// device's own *Rvrt register says it reverts TO.
	WantHeld, WantRevert float64
	// CommandedBefore/After are the pack's standing dispatch in watts, sampled
	// strictly before and strictly after the deadline.
	CommandedBefore, CommandedAfter float64
	// RemBefore/After are the device's own remaining-time readback (seconds) at
	// the same two instants.
	RemBefore, RemAfter uint32
	// TolW is the watt tolerance: the 123 signed-percent mirror is a percent at
	// SF −2, so a round trip is exact to 0.01 % of nameplate.
	TolW float64
}

// classify decides which of the four outcomes this observation shows.
//
// ORDER MATTERS, and the first branch is the one that exists because of a real
// trap: a device that ACKs the setpoint and never applies it ENDS at the
// reversion value, because it never left it. Checking "did it end on the
// reversion value" first would score that device a PASS. So the first question
// is always "was the setpoint ever in force at all", and only a device that
// held it gets asked whether it let go.
func (obs reversionObs) classify() revertOutcome {
	near := func(a, b float64) bool { return math.Abs(a-b) <= obs.TolW }
	switch {
	case !near(obs.CommandedBefore, obs.WantHeld):
		return outcomeNeverApplied
	case near(obs.CommandedAfter, obs.WantHeld):
		return outcomeStillHeld
	case !near(obs.CommandedAfter, obs.WantRevert):
		return outcomeWrongValue
	}
	return outcomeReverted
}

// assertReverted returns "" when obs shows a genuine, timer-driven revert, and
// otherwise every reason it does not — as text, so the same function serves the
// green row and the red proof and the two cannot drift apart.
//
// The countdown readback is checked alongside the value, because "the control
// changed" and "the control changed BECAUSE THE TIMER FIRED" are different
// claims and only the second is what a reversion row is for.
func assertReverted(obs reversionObs) string {
	var bad []string
	if got := obs.classify(); got != outcomeReverted {
		bad = append(bad, fmt.Sprintf("outcome is %s, want %s: commanded %.1f W before the deadline and "+
			"%.1f W after, against a commanded setpoint of %.1f W and a reversion destination of %.1f W",
			got, outcomeReverted, obs.CommandedBefore, obs.CommandedAfter, obs.WantHeld, obs.WantRevert))
	}
	if obs.RemBefore == 0 {
		bad = append(bad, "the remaining-time readback was 0 BEFORE the deadline: this device's timer never "+
			"armed, so whatever happened to the control afterwards was not this timer firing")
	}
	if obs.RemAfter != 0 {
		bad = append(bad, fmt.Sprintf("the remaining-time readback is %d AFTER the deadline, want 0: the "+
			"device is still counting a timer that should have expired", obs.RemAfter))
	}
	if len(bad) == 0 {
		return ""
	}
	return strings.Join(bad, "\n  - ")
}

// ── The row: hold, then revert, across the boundary ──────────────────────────

// TestPack704WSetReversionHoldsThenRevertsInAcceleratedTime is the row the
// engine exists for: a setpoint armed with a 900-second reversion timer is held
// for the whole countdown and replaced by the pack's declared reversion
// destination the instant the timer runs out — proven in microseconds, on a
// manual clock, with no sleep anywhere in it.
//
// It proves the boundary from BOTH sides. A row that only looked after expiry
// could not tell a timer from a device that never applied the setpoint; a row
// that only looked before it could not tell a timer from a device that ignores
// them. Every intermediate step is asserted, so a failure names which half of
// the mechanism broke.
func TestPack704WSetReversionHoldsThenRevertsInAcceleratedTime(t *testing.T) {
	bs, tb := newRevTestPack(t)
	anim := newPackAnim()

	// The destination is a fact about the DEVICE, read out of its own register
	// before anything is commanded — never a constant restated by the test,
	// which would make the row agree with itself rather than with the pack.
	wantRevert := sunspec.L704.View(readSlice(bs.Regs, bs.pack.adv.M704, sunspec.L704.Len())).Float("WSetRvrt")
	if wantRevert != 0 {
		t.Fatalf("the pack's WSetRvrt destination reads %v W, want the seeded 0 W "+
			"(seedPackReversionDestinations)", wantRevert)
	}

	// ── Arm ──
	armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)
	if got := readRvrtU32(t, bs, "WSetRvrtTms"); got != revTestTmsS {
		t.Fatalf("WSetRvrtTms reads %d s, want %d — the arming write did not land", got, revTestTmsS)
	}
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != revTestTmsS {
		t.Fatalf("WSetRvrtRem reads %d s immediately after arming, want the full %d: the countdown "+
			"readback must start at the programmed time, not at zero", got, revTestTmsS)
	}

	// ── Applied ──
	// The setpoint reaches the physics: the commanded dispatch is the setpoint,
	// and measured power ramps to it (the pack slews, so this takes ticks).
	if got := packCommandedW(bs); math.Abs(got-revTestHeldW) > packWTol {
		t.Fatalf("commanded %.1f W right after the arming write, want %.1f — the 704 bridge did not "+
			"apply the setpoint at all", got, revTestHeldW)
	}
	packTicks(bs, anim, 4)
	if got := packMeasuredW(bs); math.Abs(got-revTestHeldW) > packWTol {
		t.Fatalf("measured %.1f W after four ticks, want %.1f — the pack never converged on the setpoint, "+
			"so a later revert would be indistinguishable from never having applied it", got, revTestHeldW)
	}

	// ── The clock alone must not do it ──
	// Stepping the engine WITHOUT advancing time must change nothing. Without
	// this the row could not tell an expiry from an engine that reverts on
	// every step it is given.
	if fired := bs.packReversionStep(); len(fired) != 0 {
		t.Fatalf("the reversion engine fired %v at t+0 with 900 s on the clock — it is reverting on the "+
			"step, not on the deadline", fired)
	}

	// ── Hold, right up to one second before the deadline ──
	tb.Advance((revTestTmsS - 1) * time.Second)
	if fired := bs.packReversionStep(); len(fired) != 0 {
		t.Fatalf("the reversion engine fired %v one second BEFORE the deadline: %v", fired, "early expiry")
	}
	obs := reversionObs{
		WantHeld: revTestHeldW, WantRevert: wantRevert, TolW: packWTol,
		CommandedBefore: packCommandedW(bs),
		RemBefore:       readRvrtU32(t, bs, "WSetRvrtRem"),
	}
	if obs.RemBefore != 1 {
		t.Errorf("WSetRvrtRem reads %d s at t+%d s of a %d s timer, want 1 — the countdown does not track "+
			"the timebase", obs.RemBefore, revTestTmsS-1, revTestTmsS)
	}
	if !sunspec.L704.View(readSlice(bs.Regs, bs.pack.adv.M704, sunspec.L704.Len())).Bool("WSetEna") {
		t.Error("WSetEna went false before the deadline: the setpoint was released early")
	}

	// ── Cross the boundary ──
	tb.Advance(2 * time.Second)
	fired := bs.packReversionStep()
	// "704.WSet", not "WSet": the engine's armed set is keyed by timer name and
	// it now spans models. An advanced SOLAR sim serves both 123's
	// WMaxLimPct_RvrtTms and 704's WMaxLimPctRvrtTms, so a bare family name
	// would have made those one timer that two different writes armed and one
	// expiry reverted. The pack serves only 704 and could never have shown it.
	if len(fired) != 1 || fired[0] != "704.WSet" {
		t.Fatalf("the reversion engine fired %v crossing the deadline, want exactly [704.WSet] — the other "+
			"four 704 timers were never armed and must not fire", fired)
	}
	obs.CommandedAfter = packCommandedW(bs)
	obs.RemAfter = readRvrtU32(t, bs, "WSetRvrtRem")

	if bad := assertReverted(obs); bad != "" {
		t.Fatalf("the pack did not revert across the expiry boundary:\n  - %s", bad)
	}

	// ── The revert is in the registers, not only in the derived command ──
	v := sunspec.L704.View(readSlice(bs.Regs, bs.pack.adv.M704, sunspec.L704.Len()))
	if got := v.Float("WSet"); math.Abs(got-wantRevert) > packWTol {
		t.Errorf("704 WSet reads %.1f W after expiry, want the reversion destination %.1f W", got, wantRevert)
	}
	if !v.Bool("WSetEna") {
		t.Error("704 WSetEna is false after expiry, want true — WSetEnaRvrt is 1 on this shape, and a pack " +
			"that reverted by DISABLING would leave the legacy 123 command untouched and keep producing")
	}

	// ── And the physics follows ──
	packTicks(bs, anim, 4)
	if got := packMeasuredW(bs); math.Abs(got-wantRevert) > packWTol {
		t.Errorf("measured %.1f W four ticks after expiry, want %.1f — the revert reached the registers but "+
			"not the pack", got, wantRevert)
	}

	// ── And /state says the run was accelerated ──
	snap := bs.packSnapshot()
	if snap.Reversion == nil {
		t.Fatal("GET /state carries no reversion block on a 704-capable pack")
	}
	if !strings.Contains(snap.Reversion.Timebase, "ACCELERATED TEST TIME") {
		t.Errorf("/state reports timebase %q; an accelerated run must SAY SO in its own evidence",
			snap.Reversion.Timebase)
	}
}

// ── The red proof ────────────────────────────────────────────────────────────

// TestPack704ReversionAssertionHasTeeth runs the SAME assertion the green row
// passes against three devices that do not revert. Each must fail it, and the
// failure is logged verbatim so a reader can see what the row would actually
// say rather than take the verdict's word for it.
//
// The three are chosen to hit three different branches:
//
//	no engine        the device this repo shipped before reversion704.go: the
//	                 704 reversion registers are storage, nothing counts down,
//	                 nothing expires. This is the regression guard — if the
//	                 engine were ever unwired, the green row above must go red.
//	counts, never    a device whose remaining-time readback tracks the countdown
//	fires            perfectly and whose control never lets go. The nastiest
//	                 real firmware defect in this family, and invisible to any
//	                 row that only polls the countdown.
//	never applied    a device that ACKs the setpoint and stores nothing
//	                 (ack_no_apply on WSet). It ENDS ON THE REVERSION VALUE
//	                 because it never left it, so an assertion that only asked
//	                 "did it end at the reversion value" would score it PASS.
func TestPack704ReversionAssertionHasTeeth(t *testing.T) {
	t.Run("no reversion engine at all (the pre-reversion704.go device)", func(t *testing.T) {
		bs, tb := newRevTestPack(t)
		anim := newPackAnim()
		// Unwire the engine BEFORE the arming write, which is exactly the
		// device that existed before this file: RvrtTms lands in the register
		// bank, RvrtRem never moves, nothing expires.
		bs.rvrt = nil
		armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)
		packTicks(bs, anim, 4)

		obs := reversionObs{
			WantHeld: revTestHeldW, WantRevert: 0, TolW: packWTol,
			CommandedBefore: packCommandedW(bs),
			RemBefore:       readRvrtU32(t, bs, "WSetRvrtRem"),
		}
		tb.Advance((revTestTmsS + 1) * time.Second)
		bs.packReversionStep() // a no-op with no engine, which is the point
		obs.CommandedAfter = packCommandedW(bs)
		obs.RemAfter = readRvrtU32(t, bs, "WSetRvrtRem")

		bad := assertReverted(obs)
		if bad == "" {
			t.Fatal("a device with NO reversion engine passed the reversion assertion — the assertion has " +
				"no teeth and the green row above proves nothing")
		}
		if got := obs.classify(); got != outcomeStillHeld {
			t.Errorf("classified %s, want %s", got, outcomeStillHeld)
		}
		t.Logf("RED PROOF (no reversion engine — the device sim/southbound shipped before reversion704.go), "+
			"verbatim:\nthe pack did not revert across the expiry boundary:\n  - %s", bad)
	})

	t.Run("counts down correctly and never fires", func(t *testing.T) {
		bs, tb := newRevTestPack(t)
		anim := newPackAnim()
		armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)
		packTicks(bs, anim, 4)

		// This device PUBLISHES its countdown but never applies an expiry:
		// publish without step. Its remaining-time readback is therefore
		// perfect all the way to zero — the row must catch it on the CONTROL,
		// which is the only place the defect shows.
		tb.Advance((revTestTmsS - 1) * time.Second)
		bs.rvrt.publish(bs.Regs)
		obs := reversionObs{
			WantHeld: revTestHeldW, WantRevert: 0, TolW: packWTol,
			CommandedBefore: packCommandedW(bs),
			RemBefore:       readRvrtU32(t, bs, "WSetRvrtRem"),
		}
		tb.Advance(2 * time.Second)
		bs.rvrt.publish(bs.Regs)
		obs.CommandedAfter = packCommandedW(bs)
		obs.RemAfter = readRvrtU32(t, bs, "WSetRvrtRem")

		if obs.RemBefore != 1 || obs.RemAfter != 0 {
			t.Fatalf("this red device is meant to have a PERFECT countdown (1 then 0); it read %d then %d, "+
				"so the row that follows would be catching the wrong defect", obs.RemBefore, obs.RemAfter)
		}
		bad := assertReverted(obs)
		if bad == "" {
			t.Fatal("a device that counted its timer to zero and never let go of the control passed the " +
				"reversion assertion")
		}
		if got := obs.classify(); got != outcomeStillHeld {
			t.Errorf("classified %s, want %s", got, outcomeStillHeld)
		}
		t.Logf("RED PROOF (countdown perfect, expiry never applied), verbatim:\n"+
			"the pack did not revert across the expiry boundary:\n  - %s", bad)
	})

	t.Run("never applied the setpoint (ends on the reversion value by accident)", func(t *testing.T) {
		bs, tb := newRevTestPack(t)
		anim := newPackAnim()
		// ack_no_apply targets WSet's two registers ONLY, so WSetEna and
		// WSetRvrtTms still land: the timer arms and counts perfectly while the
		// setpoint itself was never stored.
		if err := bs.ApplyFault([]byte(`{"kind":"ack_no_apply","fields":["WSet"]}`)); err != nil {
			t.Fatalf("arm ack_no_apply on WSet: %v", err)
		}
		armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)
		packTicks(bs, anim, 4)

		obs := reversionObs{
			WantHeld: revTestHeldW, WantRevert: 0, TolW: packWTol,
			CommandedBefore: packCommandedW(bs),
			RemBefore:       readRvrtU32(t, bs, "WSetRvrtRem"),
		}
		tb.Advance((revTestTmsS + 1) * time.Second)
		bs.packReversionStep()
		obs.CommandedAfter = packCommandedW(bs)
		obs.RemAfter = readRvrtU32(t, bs, "WSetRvrtRem")

		// The trap, stated: this device ends EXACTLY on the reversion value.
		if math.Abs(obs.CommandedAfter-obs.WantRevert) > packWTol {
			t.Fatalf("this red device is meant to end on the reversion destination %.1f W by never having "+
				"left it; it ended at %.1f W, so it is not the trap this row exists to close",
				obs.WantRevert, obs.CommandedAfter)
		}
		bad := assertReverted(obs)
		if bad == "" {
			t.Fatal("a device that ACKed the setpoint, stored nothing, and therefore ended on the reversion " +
				"value passed the reversion assertion — the row cannot tell a revert from a lie")
		}
		if got := obs.classify(); got != outcomeNeverApplied {
			t.Errorf("classified %s, want %s", got, outcomeNeverApplied)
		}
		t.Logf("RED PROOF (ack_no_apply on WSet — ends on the reversion value having never left it), "+
			"verbatim:\nthe pack did not revert across the expiry boundary:\n  - %s", bad)
	})
}

// ── REV-2 / REV-3: the other two §2.6 procedures ─────────────────────────────

// TestPack704ReversionRewriteRestartsAndZeroCancels covers the two follow-on
// procedures of SS-MODBUS-CONF v1.4 §2.6 against the fixture, both of which
// turn on observeWrite's "the TRIGGER is the write, not a value change" rule:
//
//	REV-2  after half the countdown, the timer register is rewritten with THE
//	       SAME reversion time; the countdown restarts from there and the
//	       ORIGINAL deadline must pass with the control still in force.
//	REV-3  a write of zero cancels the timer outright; the original deadline
//	       passes with the control still in force and the readback at 0.
func TestPack704ReversionRewriteRestartsAndZeroCancels(t *testing.T) {
	writeTms := func(t *testing.T, bs *BatteryServer, tmsS uint32) {
		t.Helper()
		off := uint16(sunspec.L704.Offset("WSetRvrtTms"))
		mbWrite(t, bs, bs.pack.adv.M704+off, uint16(tmsS>>16), uint16(tmsS))
	}

	t.Run("REV-2 a rewrite of the same value restarts the countdown", func(t *testing.T) {
		bs, tb := newRevTestPack(t)
		armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)

		tb.Advance(revTestTmsS / 2 * time.Second)
		bs.packReversionStep()
		writeTms(t, bs, revTestTmsS) // the SAME value, mid-countdown
		if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != revTestTmsS {
			t.Fatalf("WSetRvrtRem reads %d s straight after the rewrite, want the full %d: an engine that "+
				"re-armed only on a CHANGED value would leave REV-2's countdown running out early",
				got, revTestTmsS)
		}

		// Walk past the ORIGINAL deadline. Nothing may fire.
		tb.Advance((revTestTmsS/2 + 2) * time.Second)
		if fired := bs.packReversionStep(); len(fired) != 0 {
			t.Fatalf("the timer fired %v at the ORIGINAL deadline after a REV-2 rewrite extended it", fired)
		}
		if got := packCommandedW(bs); math.Abs(got-revTestHeldW) > packWTol {
			t.Fatalf("commanded %.1f W past the original deadline, want the still-held %.1f", got, revTestHeldW)
		}
		// ... and the NEW deadline still fires, so the rewrite extended the
		// timer rather than disabling it.
		tb.Advance(revTestTmsS * time.Second)
		if fired := bs.packReversionStep(); len(fired) != 1 || fired[0] != "704.WSet" {
			t.Fatalf("the extended timer fired %v at its new deadline, want [704.WSet]", fired)
		}
	})

	t.Run("REV-3 a write of zero cancels the timer", func(t *testing.T) {
		bs, tb := newRevTestPack(t)
		armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)

		tb.Advance(revTestTmsS / 2 * time.Second)
		writeTms(t, bs, 0) // zero = NO REVERSION (model_704.json: uint32 Secs,
		// unscaled; 0xFFFFFFFF is the not-implemented sentinel, so 0 is a value)
		if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != 0 {
			t.Fatalf("WSetRvrtRem reads %d s after a cancel, want 0", got)
		}
		tb.Advance(revTestTmsS * time.Second)
		if fired := bs.packReversionStep(); len(fired) != 0 {
			t.Fatalf("the timer fired %v after being cancelled with a write of 0", fired)
		}
		if got := packCommandedW(bs); math.Abs(got-revTestHeldW) > packWTol {
			t.Fatalf("commanded %.1f W after a cancelled timer's original deadline, want the still-held "+
				"%.1f — a cancel must not be a slow expiry", got, revTestHeldW)
		}
	})
}

// TestPack704ReversionSurvivesNothingAcrossAPowerCycle pins the volatility of
// the timers: a power-on reset cancels every countdown WITHOUT applying its
// reversion values. A pack that came back from a rail drop still counting a
// timer would be honouring an instruction the same reset just erased.
func TestPack704ReversionSurvivesNothingAcrossAPowerCycle(t *testing.T) {
	bs, tb := newRevTestPack(t)
	armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got == 0 {
		t.Fatal("the timer did not arm, so this row would prove nothing about surviving a power cycle")
	}

	bs.packPowerOnReset()
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != 0 {
		t.Errorf("WSetRvrtRem reads %d s after a power-on reset, want 0", got)
	}
	tb.Advance((revTestTmsS + 1) * time.Second)
	if fired := bs.packReversionStep(); len(fired) != 0 {
		t.Errorf("a timer armed before a power cycle fired %v after it", fired)
	}
}

// TestPack704ReversionLoopFiresOnAScaledTimebase covers the half of the engine
// the manual rows above deliberately bypass: the PRODUCTION path, in which
// nobody calls packReversionStep and the pack's own 200 ms loop is what notices
// the deadline.
//
// It is the one row here that spends real time, and it spends about a third of
// a second: a 900-second timer on a 10 000× ScaledTimebase expires 90 ms after
// it is armed, and the loop's next tick applies it. The deadline below is two
// orders of magnitude beyond that, so a machine under load makes this row slow,
// never red.
//
// THE PACK IS PAUSED THROUGHOUT, on purpose. packReversionLoop ignores Pause
// because a reversion timer is the device's dead-man switch and not part of the
// animation; a pack whose timers stopped while an operator froze the register
// bank would make "paused" a way to hold a curtailment past its lease.
func TestPack704ReversionLoopFiresOnAScaledTimebase(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	// MaxReversionScale, the fastest this clock is allowed to count (gate
	// finding F2). A 900 s window lands in 250 ms, still two orders of
	// magnitude inside the deadline below.
	if err := bs.SetReversionTimebase(NewScaledTimebase(MaxReversionScale)); err != nil {
		t.Fatalf("SetReversionTimebase: %v", err)
	}
	bs.Pause()

	armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)
	if got := packCommandedW(bs); math.Abs(got-revTestHeldW) > packWTol {
		t.Fatalf("commanded %.1f W after arming, want %.1f", got, revTestHeldW)
	}

	stop := make(chan struct{})
	go bs.packReversionLoop(stop)
	defer close(stop)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := packCommandedW(bs); math.Abs(got) <= packWTol {
			break // reverted to the seeded 0 W destination
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pack's own reversion loop did not apply a %d s timer on a %d× timebase "+
				"within 10 real seconds (expected ≈0.25 s); commanded %.1f W, WSetRvrtRem %d s",
				revTestTmsS, MaxReversionScale, packCommandedW(bs), readRvrtU32(t, bs, "WSetRvrtRem"))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != 0 {
		t.Errorf("WSetRvrtRem reads %d s after the loop applied the expiry, want 0", got)
	}
	if !bs.IsPaused() {
		t.Error("the row did not actually run against a PAUSED pack, so it did not prove the loop ignores Pause")
	}
}

// ── The units, proven against the layout ─────────────────────────────────────

// TestReversionPointTypesAndScales is the citation for reversion704.go's
// units claim, checked against the compiled layout rather than restated in
// prose: the vendored model JSON (docs/schema/sunspec-models/model_704.json)
// declares every *RvrtTms and *RvrtRem as uint32 with units "Secs" and NO "sf"
// key, and declares each controlled point and its *Rvrt sibling with the SAME
// scale factor.
//
// Both halves matter to every future expiry row. If RvrtTms carried a scale
// factor and this engine ignored it, every armed timer would be wrong by a
// power of ten; if a controlled/reversion pair did NOT share one scale factor,
// applyRevert's raw register copy would silently rescale the value it restored.
func TestReversionPointTypesAndScales(t *testing.T) {
	for _, g := range rvrt704Groups {
		for _, name := range []string{g.Tms, g.Rem} {
			f, ok := sunspec.L704.FieldOf(name)
			if !ok {
				t.Errorf("%s: model 704 carries no point %q", g.Name, name)
				continue
			}
			if f.Type != sunspec.Tuint32 {
				t.Errorf("%s: %s is %v, want Tuint32 — the spec declares size 2, type uint32",
					g.Name, name, f.Type)
			}
			if f.SF != "" {
				t.Errorf("%s: %s names scale factor %q; the spec gives it NO \"sf\" key, so its value is "+
					"whole seconds RAW and applying a scale factor would misprogram every timer",
					g.Name, name, f.SF)
			}
		}
		for _, pair := range g.Values {
			ctl, okC := sunspec.L704.FieldOf(pair[0])
			rvt, okR := sunspec.L704.FieldOf(pair[1])
			if !okC || !okR {
				t.Errorf("%s: model 704 carries no %q/%q pair", g.Name, pair[0], pair[1])
				continue
			}
			if ctl.SF != rvt.SF {
				t.Errorf("%s: %s is scaled by %q but %s by %q — applyRevert copies these registers RAW, "+
					"which is only correct while they share one scale factor",
					g.Name, pair[0], ctl.SF, pair[1], rvt.SF)
			}
			if ctl.Type != rvt.Type {
				t.Errorf("%s: %s is %v but %s is %v — a raw copy between different widths would restore a "+
					"value nobody wrote", g.Name, pair[0], ctl.Type, pair[1], rvt.Type)
			}
		}
		for _, name := range []string{g.Ena, g.EnaRvrt} {
			f, ok := sunspec.L704.FieldOf(name)
			if !ok {
				t.Errorf("%s: model 704 carries no point %q", g.Name, name)
				continue
			}
			if f.Type != sunspec.Tenum16 {
				t.Errorf("%s: %s is %v, want Tenum16", g.Name, name, f.Type)
			}
		}
	}
}

// TestReversionTimebaseDefaultsToWallClock pins the knob's default. This is the
// row that would go red if anyone ever wired acceleration into a constructor, a
// flag or the simapi surface: a pack nobody told to accelerate must report the
// wall clock, and the cease shape (which serves no 704) must REFUSE the knob
// rather than silently accept it.
func TestReversionTimebaseDefaultsToWallClock(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	snap := bs.packSnapshot()
	if snap.Reversion == nil {
		t.Fatal("a 704-capable pack reports no reversion block on /state")
	}
	if snap.Reversion.Timebase != "wall" {
		t.Errorf("a freshly-built pack reports timebase %q, want %q — acceleration must never be the default",
			snap.Reversion.Timebase, "wall")
	}

	cease := newTestPack(t, PackShapeCease)
	if err := cease.SetReversionTimebase(NewManualTimebase()); err == nil {
		t.Error("the 704-LESS pack accepted a reversion timebase; it serves no 704 and has no timers, so " +
			"accepting one would let a row believe it had accelerated something")
	}
	if snap := cease.packSnapshot(); snap.Reversion != nil {
		t.Error("the 704-LESS pack reports a reversion block on /state")
	}
}

// TestReversionArmingIgnoresWritesOutsideTheTimer pins observeWrite's other
// half: a write that lands in the 704 block but NOT on a group's RvrtTms must
// not restart that group's countdown. A dead-man switch silently extended by an
// unrelated register write is a dead-man switch nobody can reason about.
func TestReversionArmingIgnoresWritesOutsideTheTimer(t *testing.T) {
	bs, tb := newRevTestPack(t)
	armWSetWithReversion(t, bs, revTestHeldW, revTestTmsS)

	tb.Advance(revTestTmsS / 2 * time.Second)
	bs.packReversionStep()
	half := readRvrtU32(t, bs, "WSetRvrtRem")
	if half == 0 || half > revTestTmsS/2+1 {
		t.Fatalf("WSetRvrtRem reads %d s at the half-way point of a %d s timer, want about %d",
			half, revTestTmsS, revTestTmsS/2)
	}

	// A single-register write to AntiIslEna: inside model 704, nowhere near any
	// timer.
	off := uint16(sunspec.L704.Offset("AntiIslEna"))
	mbWrite(t, bs, bs.pack.adv.M704+off, 1)
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != half {
		t.Errorf("writing AntiIslEna moved WSetRvrtRem from %d s to %d s — an unrelated 704 write restarted "+
			"the WSet dead-man timer", half, got)
	}
}

// ── The accelerated clock's own failure mode (gate finding F2) ───────────────

// TestScaledTimebaseSaturatesFORWARDAndSaysSo is the row for the defect the
// lever built to fix RC0 row 10 could itself reproduce.
//
// ScaledTimebase.Now() multiplies the elapsed wall duration by the scale and
// converts to a time.Duration, which is an int64 of nanoseconds. Past MaxInt64
// that conversion is not defined to saturate — on amd64 it pins to INT64_MIN —
// so a large enough multiplier made Now() jump BACKWARDS and stay there. The
// measured consequence: at 1e9× the clock froze after 9.2 s of real time, at
// 86400× after 29.7 h, and at 1e18× it never moved at all — RvrtRem reading its
// armed value for ever while /state went on declaring the scale and never said
// the clock had stopped. That is verbatim the observation row 10 was blocked by,
// reachable through the lever built to unblock it.
//
// Two properties are asserted, and the first is the one that matters: a
// dead-man timer's clock may stop, but it may NEVER run backwards. Saturating
// FORWARD makes every armed timer fire; pinning backwards makes none of them
// ever fire, and only one of those two is the safe direction to fail in.
func TestScaledTimebaseSaturatesFORWARDAndSaysSo(t *testing.T) {
	// Built field-wise on purpose: NewScaledTimebase now refuses a multiplier
	// this large, and this row is about what happens if saturation is reached
	// anyway — which the accepted maximum still permits after ~29.6 days.
	now := time.Now()
	tb := &ScaledTimebase{scale: 1e18, real0: now, sim0: now}

	got := tb.Now()
	if got.Before(tb.sim0) {
		t.Fatalf("an overflowing scaled clock reports %v, which is BEFORE its own epoch %v — the "+
			"int64 nanosecond conversion pinned to INT64_MIN and the clock now runs backwards",
			got, tb.sim0)
	}
	// Monotone across calls, too: a clock that saturates must stay saturated.
	if second := tb.Now(); second.Before(got) {
		t.Errorf("a saturated clock went backwards between two reads: %v then %v", got, second)
	}

	// And it must SAY so, in the declaration a bundle carries — otherwise an
	// accelerated bundle and a frozen one are the same document on their face,
	// which is the exact failure the declaration channel exists to prevent.
	d := tb.Declare()
	if err := d.Check(); err != nil {
		t.Fatalf("the saturated clock's declaration is not self-consistent: %v", err)
	}
	if !strings.Contains(strings.ToLower(d.Label), "saturat") {
		t.Errorf("the saturated clock labels itself %q, which does not say the clock stopped tracking "+
			"its multiplier", d.Label)
	}
}

// TestSaturatedClockStillExpiresItsTimers is the consequence of failing forward
// rather than backwards, measured through the registers.
func TestSaturatedClockStillExpiresItsTimers(t *testing.T) {
	bs := newTestPack(t, PackShapeSetpoint)
	now := time.Now()
	if err := bs.SetReversionTimebase(&ScaledTimebase{scale: 1e18, real0: now, sim0: now}); err != nil {
		t.Fatalf("SetReversionTimebase: %v", err)
	}
	armWSetWithReversion(t, bs, revTestHeldW, 300)
	if fired := bs.packReversionStep(); len(fired) != 1 || fired[0] != "704.WSet" {
		t.Fatalf("a timer on a saturated clock fired %v, want [704.WSet]. A clock pinned to INT64_MIN "+
			"never reaches any deadline, so RvrtRem reads its armed value for ever — which is exactly "+
			"the inert register RC0 row 10 was blocked by", fired)
	}
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != 0 {
		t.Errorf("WSetRvrtRem = %d after the timer fired on a saturated clock, want 0", got)
	}
}

// TestReversionScaleRefusesAMultiplierThatCannotBeCountedOn bounds the operator
// lever, which is the other half of the fix: saturation is unreachable in any
// plausible bench session at an accepted multiplier, so the loudness above is a
// backstop rather than the defence.
func TestReversionScaleRefusesAMultiplierThatCannotBeCountedOn(t *testing.T) {
	ss, _ := newRevSolarAdvanced(t, 8000)
	for _, scale := range []float64{3601, 86400, 1e9, 1e18, math.Inf(1), math.NaN()} {
		if err := ss.SetReversionScale(scale); err == nil {
			t.Errorf("reversion_scale %v was accepted; past the bound the device clock stops tracking "+
				"and a bench sits watching a countdown that has quietly stopped", scale)
		}
	}
	// The bound itself is usable, or the refusal is worse than the gap.
	if err := ss.SetReversionScale(3600); err != nil {
		t.Errorf("reversion_scale 3600 was refused: %v", err)
	}
	// NewScaledTimebase refuses it too, so no Go-source path can install one
	// either — the lever is not the only door.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("NewScaledTimebase accepted a multiplier past the bound")
			}
		}()
		NewScaledTimebase(1e9)
	}()
}

// TestRemainingTimeIsCEILEDNotTruncated pins the rounding of the remaining-time
// readback, on a FRACTIONAL remainder.
//
// GATE FINDING F5: every other hermetic row advances the manual clock by whole
// seconds, so the remainder is always integral and Ceil, Floor and Round are
// indistinguishable — changing publish's math.Ceil to math.Floor left the suite
// green. The choice is not cosmetic. RvrtRem is what a client polls to decide
// whether its control has reverted, so truncation reports 0 for the whole last
// second of a LIVE timer: a conforming controller would be told its control had
// already reverted while the device was still holding it, which is the one
// direction of rounding error that produces a wrong action rather than a late
// one.
func TestRemainingTimeIsCEILEDNotTruncated(t *testing.T) {
	bs, tb := newRevTestPack(t)
	armWSetWithReversion(t, bs, revTestHeldW, 10)

	// 5.5 s left: Ceil says 6, Floor says 5, Round says 6 — so the assertion
	// separates Floor from the other two, which is the mutation that matters.
	tb.Advance(4500 * time.Millisecond)
	bs.packReversionStep()
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != 6 {
		t.Errorf("WSetRvrtRem = %d with 5.5 s left, want 6 (ceiling). Truncation would publish 5 and, in "+
			"the last second, 0 — telling a controller its control had reverted while the device still "+
			"held it", got)
	}

	// One nanosecond left is still a LIVE timer, and this is where truncation
	// does its damage: it would publish 0 here, which is the value that means
	// "expired".
	tb.Advance(5500*time.Millisecond - 1)
	bs.packReversionStep()
	if got := readRvrtU32(t, bs, "WSetRvrtRem"); got != 1 {
		t.Errorf("WSetRvrtRem = %d with 1 ns left, want 1: a timer that has not fired must never publish "+
			"the value that means it has", got)
	}
	if got := packCommandedW(bs); math.Abs(got-revTestHeldW) > packWTol {
		t.Errorf("commanded %.1f W with 1 ns left, want the still-held %.1f — the row must be asserting "+
			"the readback of a LIVE timer", got, revTestHeldW)
	}
}
