package gwmayhem

// control_loop.go is FAMILY C — control-loop integrity. Where the wave-1 families
// probe the gateway's northbound AUTHZ and the wave-2 families its FAIL-CLOSED
// behaviour, this family drives the gateway's full write→apply→readback control
// loop ADVERSARIALLY over :802 and asserts the loop itself stays sound. The smoke
// test proved the happy path (a single curtail converges + echoes back); these
// attack it: hammer the setpoint faster than the poll cadence, arm a reversion
// timer and demand the safe revert, race the exclusive mbaps authority, and dither
// on the operating bounds. Every scenario reuses the aggregator's own control /
// readback / reversion primitives (Conn.WritePoint / ReadPoint — the same
// ControlEcho projection convergeWithinSLA / reversionOnExpiry judge), so the QA
// never touches the product's securemodbus (referee independence, C9); the pure
// diagnoseControlLoop oracle judges the sampled controlLoopOutcome.
//
// Go-literal, not a data campaign: the write-burst ordering, the drift/override
// detection, and the converge-to-LAST assertion are real logic outside the
// aggregator campaign schema.
//
// NOTE — the out-of-range setpoint gap (WMaxLimPct=150 / -10 accepted, no mbaps
// range check, design 02 §4.4) is pinned ONCE, canonically, as
// authz-out-of-range-setpoint in malformed.go (it reads cleanest as a malformed
// WRITE). This family deliberately does NOT duplicate it — the dither scenario
// stays strictly in-range so it never re-triggers (and so never double-counts)
// that one canonical gateway gap.

import (
	"context"
	"fmt"
	"math"
	"time"

	"csip-tls-test/internal/aggregator"
)

// Control-loop tuning. The values are live-sized: an SLA long enough for the
// gateway to complete a write→project→echo cycle, a poll interval short enough that
// a fast write-through echo converges on the first or second read.
const (
	ctlPollInterval = 200 * time.Millisecond
	ctlSettleSLA    = 6.0   // seconds to converge a settle/confirm readback
	ctlConfirmSLA   = 2.0   // seconds for a short "did it stay?" confirm read
	ctlTol          = 1.0   // absolute tolerance (½-LSB of a scaled SunSpec percent, matches the aggregator)
	ctlUncapped     = 100.0 // the safe / uncapped WMaxLimPct the teardown releases to

	// reversion timing mirrors qa/aggregator/ramp-limit-reversion.json: a short
	// RvrtTms, a hold long enough to read the ceiling, then a sleep past expiry.
	ctlReversionTms   = 20   // WMaxLimPctRvrtTms value written
	ctlReversionHoldS = 25.0 // seconds to sleep past RvrtTms before the revert read
	ctlReversionPct   = 40.0 // the commanded ceiling that must hold then revert

	ctlAuthorityPct = 60.0 // the exclusive-mbaps authority setpoint the CSIP side must not override

	// pointWMaxLimPctEna / RvrtTms are the 704 companions the reversion scenario
	// writes alongside WMaxLimPct.
	pointWMaxLimPctEna     = "WMaxLimPctEna"
	pointWMaxLimPctRvrtTms = "WMaxLimPctRvrtTms"
)

// controlLoopScenarios is family C. The whole family drives the REAL gateway's
// write→apply→readback control loop over :802 and is NeedsBench (live-driven,
// skipped on the plain :802 loopback), matching the wave-2 precedent: the control
// loop needs the gateway's live ControlEcho projection, its reversion-timer engine
// (T04.9), and its exclusive-authority engine — and the shared authz-loopback's
// session-cap model makes a multi-write control burst flaky in the FULL hermetic
// suite. The hermetic teeth are the pure diagnoseControlLoop decision table
// (oracles_test.go, make test-fast). dither is additionally Extended (a default run
// excludes it).
func controlLoopScenarios() []gwScenario {
	return []gwScenario{
		controlRapidRecurtail(),
		controlReversionTimer(),
		controlConflictingAuthority(),
		controlDitherAtBounds(),
	}
}

// controlRapidRecurtail hammers WMaxLimPct 50→100→30→80 faster than the poll
// cadence and asserts the readback converges to the LAST written value (no lost /
// stale echo), stays there (no oscillation), and the loop never crashes.
func controlRapidRecurtail() gwScenario {
	return gwScenario{
		ID:         "control-rapid-recurtail",
		Desc:       "hammer WMaxLimPct 50→100→30→80 faster than the poll cadence — readback converges to the LAST value, no oscillation, no crash",
		Category:   "control-loop",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "controlLoop",
		arm:        armControlRapidRecurtail,
		teardown:   releaseControlUnit,
	}
}

func armControlRapidRecurtail(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	unit, ok := beginControl(ctx, w, ev, "rapid-recurtail")
	if !ok {
		return nil
	}
	o := ev.ControlLoop
	conn, err := w.connectAs(aggregator.RoleGridService)
	if err != nil {
		ev.SetupErr = "connect GridService: " + err.Error()
		return nil
	}
	defer conn.Close()

	// The burst: back-to-back writes with NO readback between them — faster than any
	// poll cadence. WMaxLimPctEna stays off, so this exercises the ECHO/command
	// channel without actually curtailing a live DER; the last value is the target.
	burst := []float64{50, 100, 30, 80}
	o.Commanded = burst
	o.LastCmd = burst[len(burst)-1]
	noteWriteBlip(o, writeBurst(ctx, conn, unit, burst))
	// Settle: the echo must converge to the LAST commanded value (80), not a stale
	// intermediate (50/100/30). A burst write that truly failed shows here as a
	// non-converged settle (a FAIL), not a false "dark".
	o.Readbacks = append(o.Readbacks, pollReadback(ctx, conn, unit, o.LastCmd, ctlTol, ctlSettleSLA, "settle", ""))
	// Two confirm reads prove it STAYS at 80 (no oscillation / late-arriving stale echo).
	o.Readbacks = append(o.Readbacks, pollReadback(ctx, conn, unit, o.LastCmd, ctlTol, ctlConfirmSLA, "confirm-1", ""))
	o.Readbacks = append(o.Readbacks, pollReadback(ctx, conn, unit, o.LastCmd, ctlTol, ctlConfirmSLA, "confirm-2", ""))
	o.Observed = true
	markControlDark(o)
	return nil
}

// controlReversionTimer writes a setpoint with a reversion timer (WMaxLimPctRvrtTms)
// and asserts the gateway reverts to the safe default at expiry (SunSpec 704
// reversion; the gw's reversion-timer engine, T04.9). NeedsBench: the register-echo
// loopback has no reversion engine, so this runs live only.
func controlReversionTimer() gwScenario {
	return gwScenario{
		ID:         "control-reversion-timer",
		Desc:       "write WMaxLimPct=40 with WMaxLimPctRvrtTms — ceiling holds, then the gateway reverts to safe on expiry (704 reversion, T04.9)",
		Category:   "control-loop",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "controlLoop",
		arm:        armControlReversionTimer,
		teardown:   releaseControlUnit,
	}
}

func armControlReversionTimer(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	unit, ok := beginControl(ctx, w, ev, "reversion")
	if !ok {
		return nil
	}
	o := ev.ControlLoop
	conn, err := w.connectAs(aggregator.RoleGridService)
	if err != nil {
		ev.SetupErr = "connect GridService: " + err.Error()
		return nil
	}
	defer conn.Close()

	// Enable the limit, command the ceiling, and arm the reversion timer companion.
	o.Commanded = []float64{ctlReversionPct}
	o.LastCmd = ctlReversionPct
	_ = writePointRetry(ctx, conn, unit, pointWMaxLimPctEna, 1)
	noteWriteBlip(o, writeBlip(writePointRetry(ctx, conn, unit, matrixCtrlPoint, ctlReversionPct)))
	_ = writePointRetry(ctx, conn, unit, pointWMaxLimPctRvrtTms, ctlReversionTms)

	// Hold: the ceiling must have taken (echo converges to 40).
	o.Readbacks = append(o.Readbacks, pollReadback(ctx, conn, unit, ctlReversionPct, ctlTol, 10, "hold", "hold"))
	// Wait past RvrtTms, then the gateway must have ACTIVELY reverted to the safe
	// default — a value stuck at 40 is the stuck-curtailment safety regression.
	ctlSleep(ctx, secondsToDur(ctlReversionHoldS))
	o.Readbacks = append(o.Readbacks, pollReadback(ctx, conn, unit, ctlUncapped, ctlTol, 15, "revert", "revert"))
	o.Observed = true
	markControlDark(o)
	return nil
}

// controlConflictingAuthority is design-aware: with exclusive-authority=mbaps (the
// shipped default), a CSIP control attempt must NOT override the mbaps authority.
// It commands an mbaps setpoint and asserts it HOLDS on the echo across a window
// while the CSIP head-end is live — a drift to a value the mbaps authority never
// wrote is a cross-interface override (an authority violation). NeedsBench: the
// plain loopback has no CSIP head-end to conflict, so the authority race is live.
func controlConflictingAuthority() gwScenario {
	return gwScenario{
		ID:         "control-conflicting-north-south",
		Desc:       "exclusive-authority=mbaps: an mbaps setpoint HOLDS on the echo while the CSIP head-end is live — a CSIP control never overrides the mbaps authority",
		Category:   "control-loop",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "controlLoop",
		arm:        armControlConflictingAuthority,
		teardown:   releaseControlUnit,
	}
}

func armControlConflictingAuthority(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	unit, ok := beginControl(ctx, w, ev, "authority")
	if !ok {
		return nil
	}
	o := ev.ControlLoop
	o.AuthorityPeer = "the CSIP head-end (northbound)"
	conn, err := w.connectAs(aggregator.RoleGridService)
	if err != nil {
		ev.SetupErr = "connect GridService: " + err.Error()
		return nil
	}
	defer conn.Close()

	// Command the mbaps authority setpoint and confirm it takes.
	o.Commanded = []float64{ctlAuthorityPct}
	o.LastCmd = ctlAuthorityPct
	_ = writePointRetry(ctx, conn, unit, pointWMaxLimPctEna, 1)
	noteWriteBlip(o, writeBlip(writePointRetry(ctx, conn, unit, matrixCtrlPoint, ctlAuthorityPct)))
	o.Readbacks = append(o.Readbacks, pollReadback(ctx, conn, unit, ctlAuthorityPct, ctlTol, ctlSettleSLA, "authority-set", ""))

	// Hold across a window while the CSIP head-end is live. Any read that drifts off
	// the mbaps-commanded value to something the authority never wrote is a CSIP
	// override — the exclusive-authority contract broken.
	for i := 0; i < 4; i++ {
		ctlSleep(ctx, 3*time.Second)
		if ctx.Err() != nil {
			break
		}
		v, err := conn.ReadPoint(unit, matrixCtrlModel, matrixCtrlPoint)
		if err != nil || math.IsNaN(v) {
			continue
		}
		o.Observed = true
		if math.Abs(v-ctlAuthorityPct) > ctlTol {
			o.OverrideSeen = true
			o.OverridePct = v
			break
		}
	}
	if !o.OverrideSeen {
		o.Note = joinNote(o.Note, "mbaps authority setpoint held on the echo throughout — no CSIP override observed (strength depends on the head-end serving a conflicting DERControl during the window)")
	}
	o.Observed = true
	markControlDark(o)
	return nil
}

// controlDitherAtBounds dithers WMaxLimPct with small IN-RANGE steps around the
// operating bounds (0 and 100) and asserts each write tracks cleanly on the echo
// with no flapping / instability. It stays strictly in [0,100] so it never
// re-triggers the canonical out-of-range gap (authz-out-of-range-setpoint) — true
// out-of-range clamping is that scenario's job, not double-counted here. Extended:
// a default/full run excludes it (it is a deliberately long boundary walk).
func controlDitherAtBounds() gwScenario {
	return gwScenario{
		ID:         "control-setpoint-dither-at-bounds",
		Desc:       "dither WMaxLimPct ±ε (in-range) around 0 and 100 — clean tracking, no flapping/instability [Extended; out-of-range clamp is authz-out-of-range-setpoint]",
		Category:   "control-loop",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		Extended:   true,
		NeedsBench: true,
		oracle:     "controlLoop",
		arm:        armControlDitherAtBounds,
		teardown:   releaseControlUnit,
	}
}

func armControlDitherAtBounds(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	unit, ok := beginControl(ctx, w, ev, "dither")
	if !ok {
		return nil
	}
	o := ev.ControlLoop
	conn, err := w.connectAs(aggregator.RoleGridService)
	if err != nil {
		ev.SetupErr = "connect GridService: " + err.Error()
		return nil
	}
	defer conn.Close()

	// ±ε around each bound, all in-range: the low bound (0) and the high bound (100).
	// WMaxLimPctEna stays off so this is an echo/stability walk, not an actual
	// curtailment to 0% on a live DER.
	dither := []float64{0, 0.5, 0, 1, 100, 99.5, 100, 99}
	for cycle := 0; cycle < 2; cycle++ {
		for _, v := range dither {
			if ctx.Err() != nil {
				break
			}
			noteWriteBlip(o, writeBlip(writePointRetry(ctx, conn, unit, matrixCtrlPoint, v)))
			o.Commanded = append(o.Commanded, v)
			o.LastCmd = v
			rb := pollReadback(ctx, conn, unit, v, ctlTol, ctlConfirmSLA, ditherLabel(cycle, v), "")
			o.Readbacks = append(o.Readbacks, rb)
			o.Observed = true
			ctlSleep(ctx, 500*time.Millisecond)
		}
	}
	markControlDark(o)
	return nil
}

// ── shared helpers ───────────────────────────────────────────────────────────

// beginControl discovers a served control unit and seeds ev.ControlLoop. It
// reports the unit and ok=false (with a SetupErr the oracle turns INCONCLUSIVE)
// when nothing serves the 704 control model.
func beginControl(ctx context.Context, w *gwWorld, ev *gwEvidence, kind string) (uint8, bool) {
	o := &controlLoopOutcome{Kind: kind, LastCmd: math.NaN()}
	ev.ControlLoop = o
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		ev.SetupErr = "no served unit advertises the control model (704) — cannot drive the control loop"
		return 0, false
	}
	o.Unit = unit
	return unit, true
}

// releaseControlUnit is the shared teardown: best-effort release the DER back to
// uncapped/disabled and clear any reversion timer so a control-loop scenario never
// leaves the live bench curtailed.
func releaseControlUnit(ctx context.Context, w *gwWorld) {
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		return
	}
	conn, err := w.connectAs(aggregator.RoleGridService)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = writePointRetry(ctx, conn, unit, pointWMaxLimPctRvrtTms, 0)
	_ = writePointRetry(ctx, conn, unit, matrixCtrlPoint, ctlUncapped)
	_ = writePointRetry(ctx, conn, unit, pointWMaxLimPctEna, 0)
}

// writeBurst writes every value back-to-back (no readback between them — faster
// than any poll cadence) and reports whether any write hit a PERSISTENT transport
// error (a blip that survived writePointRetry's redials). A blip is only a NOTE,
// never a verdict: whether the burst really landed is judged by the settle readback
// (a write that failed shows there as a non-converged echo, i.e. a FAIL; a transient
// that the echo still reflects is a PASS), so a momentary error can never produce a
// false "dark".
func writeBurst(ctx context.Context, conn *aggregator.Conn, unit uint8, values []float64) bool {
	blip := false
	for _, v := range values {
		if writeBlip(writePointRetry(ctx, conn, unit, matrixCtrlPoint, v)) {
			blip = true
		}
	}
	return blip
}

// writeBlip reports whether err is a PERSISTENT transport failure (not nil, not a
// protocol exception) — the only write outcome worth noting for a control-loop
// scenario.
func writeBlip(err error) bool { return err != nil && !isException(err) }

// noteWriteBlip records a persistent write-transport blip on the outcome (a
// diagnostic breadcrumb; the verdict still comes from the readbacks).
func noteWriteBlip(o *controlLoopOutcome, blip bool) {
	if blip {
		o.Note = joinNote(o.Note, "a control write hit a persistent transport error — the readback below judges whether the command actually landed")
	}
}

// markControlDark sets WentDark only when the loop produced readback attempts yet
// NONE of them ever returned a value — the session was up (connect succeeded) but
// every echo read wedged across its full SLA, a genuine dark loop. A single
// transient never trips it (the resilient readbacks recover at least one value).
func markControlDark(o *controlLoopOutcome) {
	if len(o.Readbacks) == 0 {
		return
	}
	for _, rb := range o.Readbacks {
		if rb.HadRead {
			return // read at least one value → the loop is alive
		}
	}
	o.WentDark = true
}

// writePointRetry writes a control point, retrying a TRANSIENT transport failure a
// couple of times (the aggregator's next op redials transparently, so a momentary
// error — e.g. the mode service briefly busy right after a reversion — recovers on
// the retry). It returns nil on success, the protocol exception on a clean
// rejection, or the last transport error only after the retries are exhausted (a
// genuinely dark loop).
func writePointRetry(ctx context.Context, conn *aggregator.Conn, unit uint8, point string, value float64) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 && !ctlSleep(ctx, 250*time.Millisecond) {
			return err
		}
		err = conn.WritePoint(unit, matrixCtrlModel, point, value)
		if err == nil || isException(err) {
			return err
		}
	}
	return err
}

// pollReadback polls the 704 WMaxLimPct echo until it converges to expect within
// tol, or slaS elapses — the control-loop analogue of the aggregator's doReadback,
// recording a pure ctlReadback the oracle judges. A transport error or a NaN
// sentinel keeps polling (the point may come back); never returning a value leaves
// HadRead=false so the oracle calls it BLIND, not FAIL.
func pollReadback(ctx context.Context, conn *aggregator.Conn, unit uint8, expect, tol, slaS float64, label, phase string) ctlReadback {
	rb := ctlReadback{Label: label, Phase: phase, Expect: expect, Tol: tol, SLAS: slaS}
	deadline := time.Now().Add(secondsToDur(slaS))
	for {
		v, err := conn.ReadPoint(unit, matrixCtrlModel, matrixCtrlPoint)
		switch {
		case err != nil:
			// keep trying until the SLA — the echo may recover.
		case math.IsNaN(v):
			// present but sentinel this cycle — no fresh value yet.
		default:
			rb.HadRead = true
			rb.Final = v
			if math.Abs(v-expect) <= tol {
				rb.Converged = true
			}
		}
		if rb.Converged || !time.Now().Before(deadline) {
			return rb
		}
		if !ctlSleep(ctx, ctlPollInterval) {
			return rb
		}
	}
}

// ctlSleep waits d, returning false if ctx was cancelled (so a SIGINT during a long
// live hold stops the readback loop promptly).
func ctlSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// secondsToDur converts a fractional-second SLA to a Duration.
func secondsToDur(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// isException reports whether err is a Modbus protocol exception (an expected,
// reported outcome) rather than a transport failure.
func isException(err error) bool {
	_, ok := aggregator.AsException(err)
	return ok
}

// ditherLabel tags a dither readback with its cycle and bound.
func ditherLabel(cycle int, v float64) string {
	bound := "hi"
	if v <= 50 {
		bound = "lo"
	}
	return fmt.Sprintf("dither-c%d-%s-%g", cycle, bound, v)
}
