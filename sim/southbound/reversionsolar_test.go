package sim

// reversionsolar_test.go — the ORACLE for the solar sims' device-side reversion
// timers (reversionsolar.go).
//
// # What was not exercisable before these rows
//
// The RC0 §9.5 bench battery (lexa-gw runs/bench-20260816T195212Z-535b118-battery)
// recorded row 10 — "Reversion: RvrtTms armed, read back, and ACTUAL EXPIRY
// observed" — as PARTIAL, for a reason that is entirely the fixture's:
//
//	"the sim never decremented PFWInjRvrtTms (pinned at 258 s for 6½ minutes)
//	 and reports PFWInjRvrtRem = 0, i.e. it implements no reversion countdown.
//	 The PFWInjEna 1 → 0 transition that did occur was the GATEWAY releasing the
//	 axis at the CSIP control's expiry, not the timer lapsing — so it must not be
//	 recorded as satisfying the row."
//
// The bench was running `modsim -advanced`, i.e. a *SolarServer. A reversion
// engine existed in this package but was wired into the BATTERY PACK only
// (battery_pack.go initPackReversion), so every solar sim — the plain one, the
// advanced 7xx one and the legacy-curve one — served reversion registers that
// were inert storage. These rows are the proof that they are no longer.
//
// The rows below observe the countdown and the expiry THROUGH THE MODBUS
// HANDLER, never through engine internals, because that is the only surface the
// bench has: `curl modsim:6020/registers` and a SunSpec read are register reads,
// and a countdown that only the Go engine believes in is exactly the thing the
// battery refused to record.
//
// EVERY ROW HERE RUNS ON A MANUAL OR SCALED TIMEBASE. Read reversion.go's header
// before citing any of them: an accelerated proof establishes this harness's
// expiry state machine and says NOTHING about a real device's timing.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	modbuslib "github.com/simonvetter/modbus"
	"lexa-proto/sunspec"
)

// ── Rigs ─────────────────────────────────────────────────────────────────────

// mbWriteMap performs a Modbus write through the real request handler on a bare
// register map, so every hook the wire path has fires — including OnWriteSpan,
// which is the hook the reversion engine arms from. A test that reached past it
// with Set() would arm nothing and prove nothing.
func mbWriteMap(t *testing.T, r *RegisterMap, addr uint16, vals ...uint16) {
	t.Helper()
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: addr, Quantity: uint16(len(vals)), IsWrite: true, Args: vals,
	}); err != nil {
		t.Fatalf("modbus write at %d: %v", addr, err)
	}
}

// mbReadMap performs a Modbus read through the real request handler on a bare
// register map.
func mbReadMap(t *testing.T, r *RegisterMap, addr uint16, n uint16) []uint16 {
	t.Helper()
	got, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: 1, Addr: addr, Quantity: n,
	})
	if err != nil {
		t.Fatalf("modbus read at %d: %v", addr, err)
	}
	return got
}

// newRevSolarAdvanced builds an ADVANCED (7xx) solar sim wired exactly as
// NewSolarServerAdvanced wires it — same hooks, same reversion initialiser —
// but with no listener and on a manual clock. A rig that wired the timer
// differently from the constructor would be proving a device the bench never
// runs, which is the trap newTestPack exists to avoid on the battery side.
func newRevSolarAdvanced(t *testing.T, wmax float64) (*SolarServer, *ManualTimebase) {
	t.Helper()
	ss := newAdvSolar(t, wmax)
	ss.Regs.OnWriteAttempt = ss.interceptWrite
	ss.Regs.OnWrite = ss.solarOnWrite
	ss.initSolarReversion(ss.Regs)
	tb := NewManualTimebase()
	if err := ss.SetReversionTimebase(tb); err != nil {
		t.Fatalf("SetReversionTimebase on the advanced solar sim: %v", err)
	}
	return ss, tb
}

// newRevSolarLegacyCurves builds a LEGACY-CURVE (12x) solar sim on a manual
// clock, wired as NewSolarServerLegacyCurves wires it.
func newRevSolarLegacyCurves(t *testing.T, wmax float64) (*SolarServer, *ManualTimebase) {
	t.Helper()
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, cursor := populateSolarCore(r, wmax, "")
	layer := newLegacyCurveLayer(r, cursor, wmax, LegacyCurveOptions{})
	ss := &SolarServer{Server: &Server{Regs: r}, bases: bases, wmaxW: wmax, legacy: layer}
	ss.faults.label = "solar-legacy-curves"
	r.OnWriteAttempt = ss.interceptWrite
	ss.initSolarReversion(r)
	tb := NewManualTimebase()
	if err := ss.SetReversionTimebase(tb); err != nil {
		t.Fatalf("SetReversionTimebase on the legacy-curve solar sim: %v", err)
	}
	return ss, tb
}

// revU32 reads a uint32 reversion point of a layout-described block THROUGH THE
// MODBUS HANDLER: what a client sees, not what the engine believes.
func revU32(t *testing.T, r *RegisterMap, base uint16, l *sunspec.Layout, point string) uint32 {
	t.Helper()
	off := l.Offset(point)
	if off < 0 {
		t.Fatalf("%s carries no point %q", l.Name(), point)
	}
	regs := mbReadMap(t, r, base+uint16(off), 2)
	return uint32(regs[0])<<16 | uint32(regs[1])
}

// revU16 reads a uint16 point of a layout-described block through the handler.
func revU16(t *testing.T, r *RegisterMap, base uint16, l *sunspec.Layout, point string) uint16 {
	t.Helper()
	off := l.Offset(point)
	if off < 0 {
		t.Fatalf("%s carries no point %q", l.Name(), point)
	}
	return mbReadMap(t, r, base+uint16(off), 1)[0]
}

// ── Row 1: model 704, the axis the bench actually watched ─────────────────────

// revBenchTmsS is the reversion time the bench armed and watched go nowhere:
// 258 seconds, read verbatim from the battery's register watch
// (raw/row-10-reversion, EARNED-CASES.md RC0-ENARVRT). Using the bench's own
// number rather than a round one keeps this row and that evidence comparable.
const revBenchTmsS = 258

// TestSolar704FixedPFCountsDownThroughTheRegistersAndLapsesAtExpiry is the row
// §9.5 row 10 could not run.
//
// It arms the EXACT shape the gateway armed on hardware — a fixed-PF injection
// with a window and the LAPSE alternate (PFWInjEnaRvrt = 0, the adjudicated
// "at expiry this axis's function is not enabled" posture) — in one whole-block
// read-modify-write, which is the transaction shape derbase produces, and then:
//
//	arm       PFWInjRvrtTms reads back the programmed 258 s and PFWInjRvrtRem
//	          reads 258 s. On the bench PFWInjRvrtRem read 0 forever; that is
//	          the observable the registry's primary instruction asks for.
//	count     after 100 device-seconds PFWInjRvrtRem reads 158 — DECREMENTING,
//	          which is the single fact the bench could not establish.
//	lapse     at expiry PFWInjEna goes 1 → 0 (SunSpec DER Information Model
//	          V1.2 §3.2's "the specified alternate set of function settings
//	          SHALL be applied", §3.3's "when the enable field is set to 0 ...
//	          the setting will not take effect") and PFWInjRvrtRem reads 0.
//
// The distinction the battery refused to fudge — device timer versus gateway
// release — is structural here: nothing in this test is a gateway. The only
// actor that can clear PFWInjEna is the device's own engine.
func TestSolar704FixedPFCountsDownThroughTheRegistersAndLapsesAtExpiry(t *testing.T) {
	ss, tb := newRevSolarAdvanced(t, 8000)
	r, m704 := ss.Regs, ss.adv.M704

	// Arm: PF 0.900 over-excited, injection axis, lapse alternate, 258 s window.
	regs := mbReadMap(t, r, m704, uint16(sunspec.L704.Len()))
	v := sunspec.L704.View(regs)
	v.SetEnum("PFWInjEna", 1)
	v.SetFloat("PFWInj_PF", 0.900)
	v.SetEnum("PFWInj_Ext", sunspec.M704_Ext_OverExcited)
	v.SetEnum("PFWInjEnaRvrt", 0) // the LAPSE alternate
	v.SetU32("PFWInjRvrtTms", revBenchTmsS)
	mbWriteMap(t, r, m704, regs...)

	if got := revU32(t, r, m704, sunspec.L704, "PFWInjRvrtTms"); got != revBenchTmsS {
		t.Fatalf("PFWInjRvrtTms read back %d s, want the programmed %d s", got, revBenchTmsS)
	}
	if got := revU32(t, r, m704, sunspec.L704, "PFWInjRvrtRem"); got != revBenchTmsS {
		t.Fatalf("PFWInjRvrtRem = %d s immediately after arming, want %d s. THIS IS THE BENCH'S "+
			"OBSERVATION: a sim that reports 0 here implements no countdown at all", got, revBenchTmsS)
	}

	// Count: 100 device-seconds later the readback must have moved.
	tb.Advance(100 * time.Second)
	ss.reversionStep()
	if got := revU32(t, r, m704, sunspec.L704, "PFWInjRvrtRem"); got != revBenchTmsS-100 {
		t.Fatalf("PFWInjRvrtRem = %d s at t+100, want %d s (the countdown must DECREMENT — the bench "+
			"watched this register sit at %d for 6½ minutes)", got, revBenchTmsS-100, revBenchTmsS)
	}
	if got := revU16(t, r, m704, sunspec.L704, "PFWInjEna"); got != 1 {
		t.Fatalf("PFWInjEna = %d before expiry, want 1: the control must be HELD for the whole "+
			"countdown, or the row after it proves nothing", got)
	}

	// Lapse: past the deadline, the device — not a gateway — clears the enable.
	tb.Advance((revBenchTmsS - 100) * time.Second)
	expired := ss.reversionStep()
	if len(expired) != 1 || expired[0] != "704.PFWInj" {
		t.Fatalf("expired groups = %v, want exactly [704.PFWInj]", expired)
	}
	if got := revU16(t, r, m704, sunspec.L704, "PFWInjEna"); got != 0 {
		t.Fatalf("PFWInjEna = %d after expiry, want 0. The armed alternate was PFWInjEnaRvrt = 0, and "+
			"SunSpec DER Information Model V1.2 §3.2 requires the alternate set to be applied at "+
			"expiry; §3.3 makes enable=0 mean the setting does not take effect", got)
	}
	if got := revU32(t, r, m704, sunspec.L704, "PFWInjRvrtRem"); got != 0 {
		t.Fatalf("PFWInjRvrtRem = %d after expiry, want 0", got)
	}
	// §3.2: expiry moves the timer to Stopped, not back to Running. A second
	// step with no new write must not revert anything again.
	if again := ss.reversionStep(); len(again) != 0 {
		t.Fatalf("a second step expired %v; §3.2 puts an expired timer in the Stopped state, and only a "+
			"fresh write may restart it", again)
	}
}

// TestSolar704ReversionRestartsOnRewriteAndCancelsOnZero pins the two follow-on
// behaviours SunSpec DER Information Model V1.2 §3.2 states and SS-MODBUS-CONF
// v1.4 §2.6 procedures REV-2 and REV-3 measure:
//
//	REV-2  "If a setting is updated while the reversion timer is active ... the
//	       reversion timer SHALL be reinitialized with the reversion timeout
//	       value, and the timer is restarted."
//	REV-3  "In this state, the function SHALL be either not enabled or the
//	       reversion timeout value SHALL be set to zero (0)" — writing zero is
//	       the Disabled state, i.e. a cancel.
func TestSolar704ReversionRestartsOnRewriteAndCancelsOnZero(t *testing.T) {
	ss, tb := newRevSolarAdvanced(t, 8000)
	r, m704 := ss.Regs, ss.adv.M704

	arm := func(tms uint32) {
		regs := mbReadMap(t, r, m704, uint16(sunspec.L704.Len()))
		v := sunspec.L704.View(regs)
		v.SetEnum("WMaxLimPctEna", 1)
		v.SetFloat("WMaxLimPct", 60)
		v.SetU32("WMaxLimPctRvrtTms", tms)
		mbWriteMap(t, r, m704, regs...)
	}

	arm(200)
	tb.Advance(100 * time.Second)
	ss.reversionStep()
	if got := revU32(t, r, m704, sunspec.L704, "WMaxLimPctRvrtRem"); got != 100 {
		t.Fatalf("WMaxLimPctRvrtRem = %d at half-time, want 100", got)
	}

	// REV-2: rewrite the SAME value. The trigger is the write, not a change.
	arm(200)
	if got := revU32(t, r, m704, sunspec.L704, "WMaxLimPctRvrtRem"); got != 200 {
		t.Fatalf("WMaxLimPctRvrtRem = %d after an identical rewrite, want the full 200: §3.2 restarts "+
			"the timer on a setting update, and REV-2 rewrites the SAME reversion time on purpose", got)
	}

	// REV-3: writing zero cancels without reverting.
	arm(0)
	if got := revU32(t, r, m704, sunspec.L704, "WMaxLimPctRvrtRem"); got != 0 {
		t.Fatalf("WMaxLimPctRvrtRem = %d after a cancel, want 0", got)
	}
	tb.Advance(10 * time.Hour)
	if expired := ss.reversionStep(); len(expired) != 0 {
		t.Fatalf("a cancelled timer expired %v ten hours later; zero means Disabled, not deferred", expired)
	}
	if got := revU16(t, r, m704, sunspec.L704, "WMaxLimPctEna"); got != 1 {
		t.Fatalf("WMaxLimPctEna = %d after a cancelled timer, want 1: a cancel must not revert anything", got)
	}
}

// ── Row 2: the 7xx curve models ──────────────────────────────────────────────

// TestSolar705CurveReversionRestoresTheDefaultCurveIndex proves the curve
// models' own reversion timer, whose alternate set is NOT an enable pair.
//
// Model 705/706/712 declare `RvrtCrv` — "Default curve after reversion timeout"
// — and 711 declares `RvrtCtl` — "Default control after reversion timeout"
// (lexa-proto docs/schema/sunspec-models/model_705.json and model_711.json).
// Neither declares an *EnaRvrt point, so the alternate set of function settings
// these models can express is a curve SELECTION, and expiry re-runs the model's
// own §3.1.2 adopt handshake onto it. That asymmetry with 704 is a property of
// the models, and the row asserts it rather than papering over it.
func TestSolar705CurveReversionRestoresTheDefaultCurveIndex(t *testing.T) {
	ss, tb := newRevSolarAdvanced(t, 8000)
	r := ss.Regs
	cb := ss.curveByModel(sunspec.ModelDERVoltVar)

	// Stage curve 2 with a recognisable first breakpoint, then adopt it, so the
	// live curve is demonstrably NOT the seeded default before the timer runs.
	stage := cb.base + uint16(cb.hdrLen+cb.stride) // 1-based index 2 → slot 1
	ptOff := uint16(cb.crv.Len())                  // first (V, Var) pair of the curve
	mbWriteMap(t, r, stage+ptOff, 1234)
	mbWriteMap(t, r, cb.base+uint16(cb.reqOff), 2)
	live := cb.base + uint16(cb.hdrLen)
	if got := mbReadMap(t, r, live+ptOff, 1)[0]; got != 1234 {
		t.Fatalf("the staged curve did not adopt (live V[0] = %d, want 1234); the row cannot show a "+
			"revert away from a curve that was never live", got)
	}

	// Arm the model's reversion timer with RvrtCrv = 1 (back to the seeded
	// default), through one whole-header read-modify-write.
	hdr := mbReadMap(t, r, cb.base, uint16(cb.hdrLen))
	hv := cb.hdr.View(hdr)
	hv.SetEnum("Ena", 1)
	hv.SetU32("RvrtTms", 120)
	hv.SetU16At(cb.hdr.Offset("RvrtCrv"), 2) // re-adopt staging slot 2 at expiry
	mbWriteMap(t, r, cb.base, hdr...)

	if got := revU32(t, r, cb.base, cb.hdr, "RvrtRem"); got != 120 {
		t.Fatalf("705 RvrtRem = %d immediately after arming, want 120", got)
	}
	tb.Advance(45 * time.Second)
	ss.reversionStep()
	if got := revU32(t, r, cb.base, cb.hdr, "RvrtRem"); got != 75 {
		t.Fatalf("705 RvrtRem = %d at t+45, want 75", got)
	}

	// Overwrite the live curve so the expiry's re-adopt is observable.
	mbWriteMap(t, r, live+ptOff, 4321)
	tb.Advance(120 * time.Second)
	if expired := ss.reversionStep(); len(expired) != 1 || expired[0] != "705" {
		t.Fatalf("expired groups = %v, want exactly [705]", expired)
	}
	if got := revU16(t, r, cb.base, cb.hdr, "AdptCrvReq"); got != 2 {
		t.Fatalf("705 AdptCrvReq = %d after expiry, want the RvrtCrv value 2: the model's alternate set "+
			"is its default CURVE INDEX", got)
	}
	if got := mbReadMap(t, r, live+ptOff, 1)[0]; got != 1234 {
		t.Fatalf("705 live V[0] = %d after expiry, want 1234 — the reversion must actually re-run the "+
			"§3.1.2 adopt, not merely move the request register", got)
	}
}

// TestSolar7xxCurveReversionToNoActiveCurveDisablesTheFunction pins the one
// place the sim ADJUDICATES rather than transcribes, so the choice is visible.
//
// RvrtCrv = 0 is the models' own encoding of "no active curve" (model_712.json
// AdptCrvReq: "Set active curve. 0 = No active curve"; model_711.json
// AdptCtlReq: "Set active control. 0 = No active control"). The register image
// cannot express an empty live entry — the live curve IS index 0 and always
// holds something — so the only way this device can say "no curve is in force"
// is the enable, which §3.3 defines as exactly that. See reversionsolar.go for
// the alternative reading and why it was not taken.
func TestSolar7xxCurveReversionToNoActiveCurveDisablesTheFunction(t *testing.T) {
	ss, tb := newRevSolarAdvanced(t, 8000)
	r := ss.Regs
	cb := ss.curveByModel(sunspec.ModelDERFreqDroop)

	hdr := mbReadMap(t, r, cb.base, uint16(cb.hdrLen))
	hv := cb.hdr.View(hdr)
	hv.SetEnum("Ena", 1)
	hv.SetU32("RvrtTms", 30)
	hv.SetU16At(cb.hdr.Offset("RvrtCtl"), 0) // "0 = No active control"
	mbWriteMap(t, r, cb.base, hdr...)

	tb.Advance(30 * time.Second)
	if expired := ss.reversionStep(); len(expired) != 1 || expired[0] != "711" {
		t.Fatalf("expired groups = %v, want exactly [711]", expired)
	}
	if got := revU16(t, r, cb.base, cb.hdr, "Ena"); got != 0 {
		t.Fatalf("711 Ena = %d after reverting to 'no active control', want 0", got)
	}
}

// ── Row 3: model 123, the legacy immediate-controls timers ───────────────────

// TestSolarM123ReversionLapsesTheThrottleAndReconnects proves model 123's four
// reversion timers.
//
// 123 is the OTHER shape: it declares Conn_RvrtTms / WMaxLimPct_RvrtTms /
// OutPFSet_RvrtTms / VArPct_RvrtTms ("Timeout period for ..." in
// model_123.json) and NO remaining-time point and NO alternate-value points at
// all. Two consequences the row states rather than hides:
//
//   - the countdown is NOT observable through the registers on this model, only
//     the transition is. GET /state carries it (asserted below) because the
//     engine has it; the wire does not, because the model has nowhere to put it.
//   - the only alternate this model can express is the DISABLED state (§3.3),
//     which for the three setting families means clearing their enable and for
//     Conn means returning to CONNECT — a temporary disconnect that times out
//     reconnects, which is the whole reason its timeout exists.
func TestSolarM123ReversionLapsesTheThrottleAndReconnects(t *testing.T) {
	ss, tb := newRevSolarLegacyCurves(t, 8000)
	r, m123 := ss.Regs, ss.bases.M123Base

	regs := mbReadMap(t, r, m123, uint16(sunspec.L123.Len()))
	v := sunspec.L123.View(regs)
	v.SetEnum("WMaxLim_Ena", 1)
	v.SetU16At(sunspec.L123.Offset("WMaxLimPct"), 6000) // 60.00 %
	v.SetU16At(sunspec.L123.Offset("WMaxLimPct_RvrtTms"), 90)
	v.SetEnum("Conn", 0) // DISCONNECT
	v.SetU16At(sunspec.L123.Offset("Conn_RvrtTms"), 45)
	mbWriteMap(t, r, m123, regs...)

	// The countdown has nowhere to live on the wire, so /state is the only
	// place a bench can watch it — and it must be there.
	st := ss.reversionSnapshot()
	if st == nil {
		t.Fatal("GET /state carries no reversion section on a sim with two armed 123 timers")
	}
	var sawConn, sawThrottle bool
	for _, g := range st.Groups {
		switch g.Name {
		case "123.Conn":
			sawConn = g.Armed && g.TmsS == 45
		case "123.WMaxLimPct":
			sawThrottle = g.Armed && g.TmsS == 90
		}
	}
	if !sawConn || !sawThrottle {
		t.Fatalf("/state reversion groups = %+v, want armed 123.Conn (45 s) and 123.WMaxLimPct (90 s)",
			st.Groups)
	}

	tb.Advance(45 * time.Second)
	if expired := ss.reversionStep(); len(expired) != 1 || expired[0] != "123.Conn" {
		t.Fatalf("expired groups at t+45 = %v, want exactly [123.Conn]", expired)
	}
	if got := revU16(t, r, m123, sunspec.L123, "Conn"); got != 1 {
		t.Fatalf("123 Conn = %d after its timeout, want 1 (CONNECT): a disconnect whose timeout period "+
			"elapses reconnects, which is what the timeout is for", got)
	}
	if got := revU16(t, r, m123, sunspec.L123, "WMaxLim_Ena"); got != 1 {
		t.Fatalf("123 WMaxLim_Ena = %d at t+45, want 1: the throttle's own timer has 45 s left and "+
			"the two must be independent", got)
	}

	tb.Advance(45 * time.Second)
	if expired := ss.reversionStep(); len(expired) != 1 || expired[0] != "123.WMaxLimPct" {
		t.Fatalf("expired groups at t+90 = %v, want exactly [123.WMaxLimPct]", expired)
	}
	if got := revU16(t, r, m123, sunspec.L123, "WMaxLim_Ena"); got != 0 {
		t.Fatalf("123 WMaxLim_Ena = %d after its timeout, want 0", got)
	}
	if got := revU16(t, r, m123, sunspec.L123, "WMaxLimPct"); got != 6000 {
		t.Fatalf("123 WMaxLimPct = %d after its timeout, want the value 6000 LEFT IN PLACE: §3.3 makes "+
			"the enable, not the value, the thing that stops the setting taking effect", got)
	}
}

// ── Row 4: the legacy 12x curve family ───────────────────────────────────────

// TestSolarLegacyCurveReversionDropsTheCurveSelection proves the 12x family's
// timer.
//
// model_126.json spells the point's meaning out: RvrtTms is the "Timeout period
// for volt-VAR CURVE SELECTION", and ActCrv is "Index of active curve. 0=no
// active curve". So the alternate set here is the selection, and reverting it
// means ActCrv → 0 with the function's own enable cleared — a curve-based
// function with no selected curve is not operating, and ModEna is where this
// model says so.
func TestSolarLegacyCurveReversionDropsTheCurveSelection(t *testing.T) {
	ss, tb := newRevSolarLegacyCurves(t, 8000)
	r := ss.Regs
	var blk legacyBankBlock
	for _, b := range ss.legacy.layout().blocks {
		if b.id == sunspec.ModelVoltVarLegacy {
			blk = b
		}
	}
	if blk.id == 0 {
		t.Fatal("the legacy-curve sim serves no model 126")
	}

	hdr := mbReadMap(t, r, blk.base, uint16(blk.hdrLen))
	hv := blk.hdr.View(hdr)
	hv.SetU16At(blk.actCrvOff, 1)
	hv.SetU16At(blk.modEnaOff, 1)
	hv.SetU16At(blk.hdr.Offset("RvrtTms"), 60)
	mbWriteMap(t, r, blk.base, hdr...)

	tb.Advance(30 * time.Second)
	ss.reversionStep()
	if got := mbReadMap(t, r, blk.base+uint16(blk.modEnaOff), 1)[0]; got != 1 {
		t.Fatalf("126 ModEna = %d at half-time, want 1", got)
	}

	tb.Advance(30 * time.Second)
	if expired := ss.reversionStep(); len(expired) != 1 || expired[0] != "126" {
		t.Fatalf("expired groups = %v, want exactly [126]", expired)
	}
	if got := mbReadMap(t, r, blk.base+uint16(blk.actCrvOff), 1)[0]; got != 0 {
		t.Fatalf("126 ActCrv = %d after expiry, want 0 (no active curve)", got)
	}
	if got := mbReadMap(t, r, blk.base+uint16(blk.modEnaOff), 1)[0]; got != 0 {
		t.Fatalf("126 ModEna = %d after expiry, want 0", got)
	}
}

// ── Row 5: the derivation itself ─────────────────────────────────────────────

// TestEveryServedReversionTimerIsEngineManaged is the row that makes the timer
// table a DERIVATION rather than a list somebody remembered.
//
// It walks the layouts each solar image actually serves, finds every point
// whose name ends in RvrtTms — the SunSpec DER Information Model V1.2 §3.2
// spelling of "reversion timeout value", and the same name the vendored model
// JSON uses on the legacy models — and requires the engine to be managing a
// timer for each. A model gaining a reversion timer at re-vendor, or a family
// being forgotten here, fails this row rather than silently serving an inert
// register the way every solar sim did before this file existed.
func TestEveryServedReversionTimerIsEngineManaged(t *testing.T) {
	// The advanced image: 704's five groups plus one per curve model.
	adv, _ := newRevSolarAdvanced(t, 8000)
	// The legacy-curve image: 123's four plus one per 12x curve model.
	leg, _ := newRevSolarLegacyCurves(t, 8000)

	for _, img := range []struct {
		label string
		ss    *SolarServer
	}{{"advanced (7xx)", adv}, {"legacy-curves (12x)", leg}} {
		served := map[uint16][]string{} // model id → RvrtTms point names
		add := func(id uint16, l *sunspec.Layout) {
			for _, f := range l.Fields {
				if strings.HasSuffix(f.Name, "RvrtTms") {
					served[id] = append(served[id], f.Name)
				}
			}
		}
		add(123, sunspec.L123)
		if img.ss.advanced {
			add(704, sunspec.L704)
			for _, cb := range img.ss.adv.Curves {
				add(cb.id, cb.hdr)
			}
		}
		if img.ss.legacy != nil {
			for _, b := range img.ss.legacy.layout().blocks {
				add(b.id, b.hdr)
			}
		}

		managed := map[string]bool{}
		for _, tm := range img.ss.rvrt.timerPoints() {
			managed[tm] = true
		}
		for id, points := range served {
			for _, p := range points {
				key := fmt.Sprintf("%d.%s", id, p)
				if !managed[key] {
					t.Errorf("%s image: model %d serves %s and the reversion engine does not manage it "+
						"(managed set: %v)", img.label, id, p, img.ss.rvrt.timerPoints())
				}
			}
		}
		// And nothing the engine claims to manage may be absent from the image:
		// a timer pointed at a model this device does not serve would count down
		// against registers belonging to something else.
		for _, tm := range img.ss.rvrt.timerPoints() {
			var id uint16
			var point string
			if _, err := fmt.Sscanf(tm, "%d.%s", &id, &point); err != nil {
				t.Fatalf("%s image: unparseable managed timer key %q", img.label, tm)
			}
			found := false
			for _, p := range served[id] {
				if p == point {
					found = true
				}
			}
			if !found {
				t.Errorf("%s image: the engine manages %s, which this image does not serve", img.label, tm)
			}
		}
	}
}

// ── Row 6: the acceleration lever, and what it declares ──────────────────────

// TestSolarReversionTimebaseDefaultsToWallAndDeclaresAcceleration proves the
// lever that lets a BENCH row see an expiry inside a bench window without
// stubbing the transition.
//
// The three properties that make it safe to expose at runtime at all:
//
//	default    a sim nobody accelerated reports the wall clock, so an
//	           un-accelerated bundle says so on its face.
//	declared   the label on GET /state is DERIVED from the timebase's own
//	           bundle declaration (reversion.go), so an accelerated sim cannot
//	           spell itself "wall".
//	disarming  installing a clock drops every armed countdown, because a
//	           deadline computed in one frame is meaningless in another. A
//	           bench that accelerated mid-countdown and kept counting would be
//	           measuring nothing, so the lever refuses to let that happen
//	           quietly.
func TestSolarReversionTimebaseDefaultsToWallAndDeclaresAcceleration(t *testing.T) {
	ss := newAdvSolar(t, 8000)
	ss.Regs.OnWriteAttempt = ss.interceptWrite
	ss.initSolarReversion(ss.Regs)

	if got := ss.reversionSnapshot().Timebase; got != WallTimebase().Label() {
		t.Fatalf("a freshly built sim reports timebase %q, want the wall clock %q",
			got, WallTimebase().Label())
	}

	if err := ss.SetReversionTimebase(NewScaledTimebase(60)); err != nil {
		t.Fatalf("SetReversionTimebase(60×): %v", err)
	}
	label := ss.reversionSnapshot().Timebase
	if label == WallTimebase().Label() {
		t.Fatal("an accelerated sim still reports the wall clock on /state — the declaration is the " +
			"only thing that keeps an accelerated bundle from being read as a real-time one")
	}
	if !strings.Contains(label, "60") {
		t.Fatalf("the accelerated timebase label %q does not name its multiplier", label)
	}

	// The declaration also has to survive into a snapshot a bench actually
	// captures, which is JSON.
	blob, err := json.Marshal(ss.Snapshot())
	if err != nil {
		t.Fatalf("marshal /state: %v", err)
	}
	if !strings.Contains(string(blob), label) {
		t.Fatalf("GET /state does not carry the timebase label %q", label)
	}
}

// TestSolarReversionTimebaseSwapDisarmsEveryCountdown is the teeth on the
// disarming half: a countdown that survived a clock swap would be counting
// against a deadline in the old frame, which on a manual clock parked in the
// year 2000 is decades away and on a scaled one is simply wrong.
func TestSolarReversionTimebaseSwapDisarmsEveryCountdown(t *testing.T) {
	ss, _ := newRevSolarAdvanced(t, 8000)
	r, m704 := ss.Regs, ss.adv.M704

	regs := mbReadMap(t, r, m704, uint16(sunspec.L704.Len()))
	sunspec.L704.View(regs).SetU32("WSetRvrtTms", 300)
	mbWriteMap(t, r, m704, regs...)
	if got := revU32(t, r, m704, sunspec.L704, "WSetRvrtRem"); got != 300 {
		t.Fatalf("WSetRvrtRem = %d after arming, want 300", got)
	}

	if err := ss.SetReversionTimebase(NewManualTimebase()); err != nil {
		t.Fatalf("SetReversionTimebase: %v", err)
	}
	if got := revU32(t, r, m704, sunspec.L704, "WSetRvrtRem"); got != 0 {
		t.Fatalf("WSetRvrtRem = %d after a clock swap, want 0 — the swap must disarm", got)
	}
}

// TestSolarReversionScaleLeverRefusesNonsense pins the runtime lever's input
// domain. A bench that asked for acceleration and silently got real time would
// sit through the full RvrtTms wondering why, which is the failure
// NewScaledTimebase's panic exists to prevent — so the lever validates BEFORE
// it constructs one.
func TestSolarReversionScaleLeverRefusesNonsense(t *testing.T) {
	ss, _ := newRevSolarAdvanced(t, 8000)
	for _, scale := range []float64{-1, -0.0001} {
		if err := ss.SetReversionScale(scale); err == nil {
			t.Errorf("SetReversionScale(%v) was accepted; a non-positive multiplier is not a clock", scale)
		}
	}
	// 1× is the way back to real time and must be spelled as the wall clock,
	// not as "scaled 1×" — a bundle that read "scaled" would be describing an
	// acceleration that is not happening.
	if err := ss.SetReversionScale(1); err != nil {
		t.Fatalf("SetReversionScale(1): %v", err)
	}
	if got := ss.reversionSnapshot().Timebase; got != WallTimebase().Label() {
		t.Fatalf("after SetReversionScale(1) the timebase is %q, want the wall clock %q",
			got, WallTimebase().Label())
	}
	// 0 is "unchanged", matching POST /control's speed convention, so an
	// operator who omits the key does not silently reset the clock.
	if err := ss.SetReversionScale(0); err != nil {
		t.Fatalf("SetReversionScale(0) must be a no-op, got %v", err)
	}
}

// ── Row 7: the red proof ─────────────────────────────────────────────────────

// TestSolarReversionRowHasTeeth runs the SAME assertions the green rows use
// against a sim whose engine has been removed, and requires every one of them
// to fail. A row that passed on the device the bench actually met — the one
// that pins RvrtTms and reports RvrtRem = 0 forever — would be proving nothing,
// and that device is exactly what this repo shipped until this file existed.
func TestSolarReversionRowHasTeeth(t *testing.T) {
	ss := newAdvSolar(t, 8000)
	ss.Regs.OnWriteAttempt = ss.interceptWrite
	// NO initSolarReversion: this is the pre-reversionsolar.go device.
	r, m704 := ss.Regs, ss.adv.M704

	regs := mbReadMap(t, r, m704, uint16(sunspec.L704.Len()))
	v := sunspec.L704.View(regs)
	v.SetEnum("PFWInjEna", 1)
	v.SetU32("PFWInjRvrtTms", revBenchTmsS)
	mbWriteMap(t, r, m704, regs...)

	if got := revU32(t, r, m704, sunspec.L704, "PFWInjRvrtTms"); got != revBenchTmsS {
		t.Fatalf("even the inert device stores RvrtTms; got %d", got)
	}
	if got := revU32(t, r, m704, sunspec.L704, "PFWInjRvrtRem"); got != 0 {
		t.Fatalf("PFWInjRvrtRem = %d on a device with no engine, want 0 — this is the bench's "+
			"observation and the red proof depends on reproducing it", got)
	}
	if got := revU16(t, r, m704, sunspec.L704, "PFWInjEna"); got != 1 {
		t.Fatalf("PFWInjEna = %d on a device with no engine, want 1: nothing may lapse without a timer", got)
	}
	t.Logf("RED PROOF: the pre-engine solar sim stores RvrtTms=%d, reports RvrtRem=0 and never lapses "+
		"— precisely what the RC0 §9.5 battery recorded for row 10", revBenchTmsS)
}

// ── Row 8: the same 123 timers, on the image the bench actually runs ─────────

// TestSolarM123ThrottleReversionLapsesOnTheADVANCEDImageToo is the row the
// legacy-only version of it could not have caught.
//
// GATE FINDING F1. TestSolarM123ReversionLapsesTheThrottleAndReconnects runs on
// newRevSolarLegacyCurves, which serves no 704 and therefore no 704→123 bridge.
// `modsim -advanced` — the image the RC0 battery ran — serves both, and
// reversionStep's own advSync calls advBridgeCeiling, which resurrected the
// WMaxLim_Ena the revert had just cleared and overwrote the value the revert had
// deliberately left in place. Engine, /state and the log all said "lapsed"; the
// wire said Ena=1. That is a fixture telling a bench two different things about
// one function, which is the failure mode the whole engine exists to avoid.
//
// So this row asserts the ENGINE and the WIRE together, on the advanced image,
// and it asserts BOTH register views of the one physical axis.
func TestSolarM123ThrottleReversionLapsesOnTheADVANCEDImageToo(t *testing.T) {
	ss, tb := newRevSolarAdvanced(t, 8000)
	r, m123, m704 := ss.Regs, ss.bases.M123Base, ss.adv.M704

	// A 704 ceiling is in force — the precondition for the bridge to run at
	// all, and the ordinary state of an advanced device under CSIP control.
	regs := mbReadMap(t, r, m704, uint16(sunspec.L704.Len()))
	sunspec.L704.View(regs).SetEnum("WMaxLimPctEna", 1)
	mbWriteMap(t, r, m704, regs...)

	// A legacy client arms the 123 throttle with a timeout.
	m123regs := mbReadMap(t, r, m123, uint16(sunspec.L123.Len()))
	v := sunspec.L123.View(m123regs)
	v.SetEnum("WMaxLim_Ena", 1)
	v.SetU16At(sunspec.L123.Offset("WMaxLimPct"), 6000) // 60.00 %
	v.SetU16At(sunspec.L123.Offset("WMaxLimPct_RvrtTms"), 90)
	mbWriteMap(t, r, m123, m123regs...)

	tb.Advance(90 * time.Second)
	if expired := ss.reversionStep(); len(expired) != 1 || expired[0] != "123.WMaxLimPct" {
		t.Fatalf("expired timers = %v, want exactly [123.WMaxLimPct]", expired)
	}

	// THE ENGINE's account.
	for _, g := range ss.reversionSnapshot().Groups {
		if g.Name == "123.WMaxLimPct" && g.Armed {
			t.Error("/state still reports 123.WMaxLimPct armed after its expiry")
		}
	}
	// THE WIRE's account — the half that was wrong.
	if got := revU16(t, r, m123, sunspec.L123, "WMaxLim_Ena"); got != 0 {
		t.Errorf("123 WMaxLim_Ena = %d on the wire after the timeout, want 0. The engine reverted it and "+
			"the 704→123 ceiling bridge set it straight back to 1 — a device that reports a lapse on "+
			"/state and a live throttle on Modbus", got)
	}
	if got := revU16(t, r, m123, sunspec.L123, "WMaxLimPct"); got != 6000 {
		t.Errorf("123 WMaxLimPct = %d after the timeout, want the commanded 6000 LEFT IN PLACE; the "+
			"bridge overwrote it with 704's own percent", got)
	}
	// AND the other view of the same physical axis. 123's throttle and 704's
	// WMaxLimPct are one function on this device — that is why the bridge
	// exists — so a lapse that left 704 enabled would put the two views into
	// exactly the disagreement the model-qualified timer names exist to name.
	if got := revU16(t, r, m704, sunspec.L704, "WMaxLimPctEna"); got != 0 {
		t.Errorf("704 WMaxLimPctEna = %d after the 123 throttle lapsed, want 0: one physical axis "+
			"cannot be off in one register view and on in the other", got)
	}
	// The physics is the referee: the curtailment must actually be gone.
	if got := solarCeilingW(r, ss.bases, ss.wmaxW, &ss.faults); got != 8000 {
		t.Errorf("the device is still curtailed to %.0f W after the throttle lapsed, want the full 8000 W", got)
	}
}

// TestSolar704CeilingReversionToDisabledReleasesTheLegacyMirror is F1's sibling,
// found while fixing it and fixed with it.
//
// The bridge is ONE-WAY and only ever WRITES: it mirrors while 704's ceiling is
// enabled and simply stops when it is not, leaving whatever it last wrote
// standing in 123. So a 704 ceiling that lapsed to DISABLED (the head end's own
// WMaxLimPctEnaRvrt = 0, the adjudicated lapse posture) left the legacy mirror
// holding the last commanded percent — and solarCeilingW reads 123, so the
// device went on curtailing for ever on a control whose lease had expired. That
// is the exact failure a reversion timer exists to prevent.
func TestSolar704CeilingReversionToDisabledReleasesTheLegacyMirror(t *testing.T) {
	ss, tb := newRevSolarAdvanced(t, 8000)
	r, m123, m704 := ss.Regs, ss.bases.M123Base, ss.adv.M704

	regs := mbReadMap(t, r, m704, uint16(sunspec.L704.Len()))
	v := sunspec.L704.View(regs)
	v.SetEnum("WMaxLimPctEna", 1)
	v.SetFloat("WMaxLimPct", 60)
	v.SetEnum("WMaxLimPctEnaRvrt", 0) // lapse at expiry, not revert-to-a-value
	v.SetU32("WMaxLimPctRvrtTms", 60)
	mbWriteMap(t, r, m704, regs...)

	// The bridge has mirrored it: the device is genuinely curtailed before the
	// timer runs out, or the row after this proves nothing.
	if got := revU16(t, r, m123, sunspec.L123, "WMaxLim_Ena"); got != 1 {
		t.Fatalf("123 WMaxLim_Ena = %d before expiry, want 1 (the bridge should have mirrored)", got)
	}
	if got := solarCeilingW(r, ss.bases, ss.wmaxW, &ss.faults); got != 4800 {
		t.Fatalf("the device is limited to %.0f W before expiry, want 4800 (60%% of 8000)", got)
	}

	tb.Advance(60 * time.Second)
	if expired := ss.reversionStep(); len(expired) != 1 || expired[0] != "704.WMaxLimPct" {
		t.Fatalf("expired timers = %v, want exactly [704.WMaxLimPct]", expired)
	}

	if got := revU16(t, r, m704, sunspec.L704, "WMaxLimPctEna"); got != 0 {
		t.Fatalf("704 WMaxLimPctEna = %d after expiry, want 0 (WMaxLimPctEnaRvrt was 0)", got)
	}
	if got := revU16(t, r, m123, sunspec.L123, "WMaxLim_Ena"); got != 0 {
		t.Errorf("123 WMaxLim_Ena = %d after the 704 ceiling lapsed, want 0: the bridge only ever writes, "+
			"so a lapse nobody withdraws from the legacy mirror is a curtailment that outlived its lease", got)
	}
	if got := solarCeilingW(r, ss.bases, ss.wmaxW, &ss.faults); got != 8000 {
		t.Errorf("the device is still curtailed to %.0f W after its ceiling lapsed, want the full 8000 W", got)
	}
}
