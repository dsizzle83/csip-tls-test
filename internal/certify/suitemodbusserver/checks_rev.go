package suitemodbusserver

// checks_rev.go implements the Reversion Tests of SunSpec Modbus Conformance
// Test Procedures v1.4 §2.6: REV-1 Reversion Timeout, REV-2 Reversion Time
// Update, REV-3 Reversion Cancel.
//
// A reversion timer is the DER model's dead-man switch: a control written with
// a reversion time reverts to its safe value when the timer expires unless the
// controller refreshes it. All three procedures are about the same mechanism
// seen three ways — does it fire, can it be extended, can it be cancelled — and
// all three depend on a remaining-time readback that tracks real elapsed time
// within two seconds.
//
// # Which timer, and which points
//
// The document does not name any register: "the reversion timer register" and
// "the reversion time remaining point" are model-specific and come from the
// PICS. This suite exercises model 704's WMaxLimPct group, the limit-active-
// power control, because it is the one reversion group whose controlled point
// the DUT actually applies:
//
//	controlled  WMaxLimPct          the setpoint the client writes
//	reverts to  WMaxLimPctRvrt      the value the timer restores
//	timer       WMaxLimPctRvrtTms   the reversion time, in seconds
//	remaining   WMaxLimPctRvrtRem   the countdown readback, read-only
//
// Step 2 of REV-1 ("set the points to values that are different than current
// settings") is read as the CONTROLLED points, not the reversion values: the
// *Rvrt registers are what the timer reverts TO, and step 6's criterion is that
// they are what the controlled point holds after expiry. Writing them would be
// changing the answer before asking the question.
//
// # Timing tolerance
//
// The procedure allows two seconds, twice. Every comparison below uses the
// harness's own monotonic clock against the DUT's readback, and every sample is
// recorded in the assertion so a reader can see the drift rather than take the
// verdict's word for it.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// revTolerance is the ±2 s the procedure allows on both the remaining-time
// readback and the expiry instant.
const revTolerance = 2 * time.Second

// defaultReversionSeconds is the reversion time the checks program when the
// operator does not choose one. It has to be long enough for at least three
// countdown samples (REV-1 step 4) and for a mid-countdown rewrite after half
// of it has elapsed (REV-2 step 4), and short enough that three reversion
// procedures fit inside a run.
const defaultReversionSeconds = 20

// reversionGroup names the registers of one reversion timer.
type reversionGroup struct {
	Ref        modelRef
	Controlled Point
	RevertTo   Point
	Timer      Point
	Remaining  Point
	EnaRevert  Point
	Label      string
}

// findReversionGroup locates the WMaxLimPct reversion group in the chain.
func findReversionGroup(ch *chain) (reversionGroup, bool) {
	ref, present := ch.Model(704)
	if !present {
		return reversionGroup{}, false
	}
	def := Models[704]
	get := func(name string) (Point, bool) { return def.Point(name) }
	ctl, ok1 := get("WMaxLimPct")
	rvt, ok2 := get("WMaxLimPctRvrt")
	tms, ok3 := get("WMaxLimPctRvrtTms")
	rem, ok4 := get("WMaxLimPctRvrtRem")
	ena, ok5 := get("WMaxLimPctEnaRvrt")
	if !(ok1 && ok2 && ok3 && ok4 && ok5) {
		return reversionGroup{}, false
	}
	return reversionGroup{
		Ref: ref, Controlled: ctl, RevertTo: rvt, Timer: tms, Remaining: rem, EnaRevert: ena,
		Label: "model 704 WMaxLimPct",
	}, true
}

// revSample is one poll of the remaining-time readback.
type revSample struct {
	At        time.Duration // elapsed since the timer was written
	Remaining uint32        // what the DUT reported
	Expected  time.Duration // what it should have reported
	Drift     time.Duration
}

func (s revSample) String() string {
	return fmt.Sprintf("t+%.1fs: DUT says %ds remaining, expected %.1fs (drift %+.1fs)",
		s.At.Seconds(), s.Remaining, s.Expected.Seconds(), s.Drift.Seconds())
}

// revSetup is the state the three reversion procedures share once the timer has
// been armed.
type revSetup struct {
	Group reversionGroup
	// Probe is the control write that established the timer register is
	// writable at all.
	Probe *writeProbe
	// OrigCtl and RevertTo are the controlled point's pre-test value and the
	// value the timer will revert it to.
	OrigCtl, RevertTo int64
	// Written is the value the controlled point was set to.
	Written int64
	// Seconds is the programmed reversion time.
	Seconds int
	// ArmedAt is when the timer register was written.
	ArmedAt time.Time
	// Implemented lists the reversion points that read as not implemented.
	Unimplemented []string
	// Blocked, when non-empty, says why the procedure could not be run.
	Blocked string
	// TIDs are the setup's transactions.
	TIDs []uint16
}

// armReversion runs the shared preamble of all three reversion procedures:
// locate the group, verify its points are implemented, establish that the timer
// register accepts a write, set the controlled point to a value different from
// both its current value and its reversion value, and arm the timer.
func armReversion(rc *certify.RunCtx, c *client, ch *chain, label string) (*revSetup, error) {
	g, ok := findReversionGroup(ch)
	if !ok {
		return &revSetup{Blocked: "the DUT serves no model 704, so it exposes no reversion timer this suite " +
			"is prepared to exercise"}, nil
	}
	seconds, err := paramSeconds(rc, paramReversionS, defaultReversionSeconds)
	if err != nil {
		return nil, err
	}
	st := &revSetup{Group: g, Seconds: seconds}
	before := len(c.log)
	defer func() { st.TIDs = tidsSince(c, before) }()

	block, berr := readModelBlock(c, g.Ref, label+" model snapshot")
	if berr != nil {
		return nil, fmt.Errorf("read model 704: %w", berr)
	}
	// Step 1 — every reversion point implemented for this timer.
	for _, p := range []Point{g.RevertTo, g.Timer, g.Remaining, g.EnaRevert} {
		regs, ok := pointRegs(block, p)
		if !ok {
			st.Unimplemented = append(st.Unimplemented, p.Name+" (outside the model's declared length)")
			continue
		}
		if p.Type.NotImplemented(regs) {
			st.Unimplemented = append(st.Unimplemented, p.Name+" (reads its type's not-implemented value)")
		}
	}
	ctlRegs, ok := pointRegs(block, g.Controlled)
	if !ok {
		st.Blocked = "the controlled point WMaxLimPct is outside model 704's declared length"
		return st, nil
	}
	st.OrigCtl = decodeRaw(g.Controlled, ctlRegs)
	if rvRegs, ok := pointRegs(block, g.RevertTo); ok {
		st.RevertTo = decodeRaw(g.RevertTo, rvRegs)
	}
	if len(st.Unimplemented) > 0 {
		st.Blocked = "the reversion group is incomplete: " + strings.Join(st.Unimplemented, ", ")
		return st, nil
	}

	// The control write, on the timer register itself.
	probe, perr := probeWrite(c, g.Ref, g.Timer, label+" timer control")
	if perr != nil {
		return nil, perr
	}
	st.Probe = probe
	if !probe.Accepted {
		st.Blocked = probe.Reason
		return st, nil
	}

	// Step 2 — set the controlled point to a value different from its current
	// setting AND from the value it will revert to, so step 6's comparison
	// distinguishes "reverted" from "never changed".
	target := st.OrigCtl + 1
	if target == st.RevertTo {
		target++
	}
	if target > 0xFFFF {
		target = st.OrigCtl - 1
		if target == st.RevertTo {
			target--
		}
	}
	regs, eerr := encode(g.Controlled, target)
	if eerr != nil {
		st.Blocked = eerr.Error()
		return st, nil
	}
	if werr := writePoint(c, g.Ref, g.Controlled, regs, label+" step 2: set the controlled point"); werr != nil {
		st.Blocked = "the controlled point could not be set: " + errText(werr)
		return st, nil
	}
	st.Written = target

	// Step 3 — arm the timer.
	tregs, _ := encode(g.Timer, int64(seconds))
	if werr := writePoint(c, g.Ref, g.Timer, tregs, label+" step 3: set the reversion timer"); werr != nil {
		st.Blocked = "the reversion timer could not be set: " + errText(werr)
		return st, nil
	}
	st.ArmedAt = time.Now()
	return st, nil
}

// pollRemaining samples the remaining-time readback n times, spread across the
// countdown.
func pollRemaining(ctx context.Context, rc *certify.RunCtx, c *client, st *revSetup,
	deadline time.Time, n int, label string) ([]revSample, error) {

	var out []revSample
	for i := 0; i < n; i++ {
		if err := rc.Sleep(ctx, time.Until(deadline)/time.Duration(n-i+1)); err != nil {
			return out, err
		}
		regs, err := readPoint(c, st.Group.Ref, st.Group.Remaining, fmt.Sprintf("%s poll %d", label, i+1))
		if err != nil {
			return out, fmt.Errorf("read the remaining-time point: %w", err)
		}
		now := time.Now()
		expected := deadline.Sub(now)
		if expected < 0 {
			expected = 0
		}
		rem := u32(regs)
		s := revSample{
			At:        now.Sub(st.ArmedAt),
			Remaining: rem,
			Expected:  expected,
			Drift:     time.Duration(rem)*time.Second - expected,
		}
		out = append(out, s)
	}
	return out, nil
}

// cleanupReversion cancels the timer and restores the controlled point.
func cleanupReversion(c *client, st *revSetup, label string) {
	if st == nil || st.Probe == nil || !st.Probe.Accepted {
		return
	}
	zero, _ := encode(st.Group.Timer, 0)
	_ = writePoint(c, st.Group.Ref, st.Group.Timer, zero, label+" cleanup: cancel the reversion timer")
	if orig, err := encode(st.Group.Controlled, st.OrigCtl); err == nil {
		_ = writePoint(c, st.Group.Ref, st.Group.Controlled, orig, label+" cleanup: restore the controlled point")
	}
	_ = restore(c, st.Probe, label+" cleanup")
}

// revGateNote is §2.6's applicability gate, quoted, and why it decides the
// verdict of an unimplemented reversion group.
const revGateNote = "SS-MODBUS-CONF-v1.4 §2.6, the section preamble: \"Reversion tests verify the reversion " +
	"timer functionality. IF THIS FUNCTIONALITY IS NOT IMPLEMENTED IN A MODEL, THE TESTS ARE NOT PERFORMED. " +
	"The following tests must be performed for each reversion timer that is implemented.\" REV-1 step 1 then " +
	"scopes itself further — \"all reversion points are implemented for the reversion timer SPECIFIED IN THE " +
	"PICS\". With no implemented reversion timer and no PICS declaring one, these tests are not applicable: " +
	"the finding below is recorded as context, not as a conformance result. Supply -param " +
	paramPICSReversion + "=1 when the PICS DOES declare this timer, and the same observation becomes a FAIL."

// blockedResult is the shared shape of "the reversion procedure could not be
// exercised", with the reason cited from the wire where there is one.
//
// picsDeclared says the PICS claims a reversion timer. It is what §2.6's gate
// turns on: absent a declared timer an incomplete reversion group means the
// tests ARE NOT PERFORMED, and step 1's "verify all reversion points are
// implemented" has nothing to be verified against. Run 20260726T225512 emitted
// that step as a FAIL regardless — the runner logged SKIP, the report showed
// FAIL, and no reversion behaviour had been exercised at all.
func blockedResult(s *session, st *revSetup, claims []string, picsDeclared bool) certify.Result {
	stepOneVerdict := certify.Skip
	if picsDeclared {
		stepOneVerdict = certify.Fail
	}
	return certify.Result{
		Verdict: certify.Skip,
		Notes:   st.Blocked,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason, claims...), nil
			}
			out, err := transportPlus(c, certify.Skip)
			if err != nil {
				return nil, err
			}
			if len(st.Unimplemented) > 0 {
				observed := strings.Join(st.Unimplemented, ", ")
				if !picsDeclared {
					observed += " — so no reversion timer is implemented in this model and §2.6's gate applies: " +
						"these tests are NOT PERFORMED"
				}
				a, err := c.frames(
					"every reversion point the timer needs is implemented in the model",
					"FC 3 read of model 704's register block; each reversion point compared against its type's "+
						"not-implemented sentinel",
					stepOneVerdict, observed, st.TIDs)
				if err != nil {
					return nil, err
				}
				a.Note = joinNote(a.Note, revGateNote)
				out = append(out, a)
			}
			for _, cl := range claims {
				out = append(out, ev.SkipAssertion(cl,
					"drive the reversion timer and poll its remaining-time readback", st.Blocked))
			}
			return out, nil
		},
	}
}

// checkREV1 implements SS-MODBUS-CONF-v1.4 REV-1, Reversion Timeout.
func checkREV1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "REV-1 reversion timeout")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}
	claims := []string{
		"the reversion-time-remaining point tracks the countdown to within two seconds, sampled at least " +
			"three times",
		"the reversion timer expires within two seconds of the programmed reversion time",
		"the reversion settings are in effect once the timer has expired",
	}
	st, err := armReversion(rc, s.client, ch, "REV-1")
	if err != nil {
		return certify.Result{}, err
	}
	if st.Blocked != "" {
		return blockedResult(s, st, claims, paramBool(rc, paramPICSReversion)), nil
	}
	defer cleanupReversion(s.client, st, "REV-1")

	deadline := st.ArmedAt.Add(time.Duration(st.Seconds) * time.Second)
	samples, err := pollRemaining(ctx, rc, s.client, st, deadline, 3, "REV-1 step 4")
	if err != nil {
		return certify.Result{}, err
	}
	// Step 5 — wait past the deadline and observe the expiry.
	if err := rc.Sleep(ctx, time.Until(deadline.Add(revTolerance/2))); err != nil {
		return certify.Result{}, err
	}
	remRegs, err := readPoint(s.client, st.Group.Ref, st.Group.Remaining, "REV-1 step 5: remaining after expiry")
	if err != nil {
		return certify.Result{}, fmt.Errorf("read the remaining-time point after expiry: %w", err)
	}
	expiredAt := time.Now()
	ctlRegs, err := readPoint(s.client, st.Group.Ref, st.Group.Controlled, "REV-1 step 6: controlled point after expiry")
	if err != nil {
		return certify.Result{}, fmt.Errorf("read the controlled point after expiry: %w", err)
	}

	trackOK := len(samples) >= 3
	var sampleText []string
	for _, smp := range samples {
		sampleText = append(sampleText, smp.String())
		if smp.Drift > revTolerance || smp.Drift < -revTolerance {
			trackOK = false
		}
	}
	expiredRem := u32(remRegs)
	expiryOK := expiredRem == 0 && expiredAt.Sub(deadline) <= revTolerance
	afterCtl := decodeRaw(st.Group.Controlled, ctlRegs)
	revertOK := afterCtl == st.RevertTo

	verdict := verdictIf(trackOK && expiryOK && revertOK)
	notes := fmt.Sprintf("armed %s for %ds; %s; after expiry remaining=%d and the controlled point reads %d "+
		"(reversion value %d, written %d)",
		st.Group.Label, st.Seconds, strings.Join(sampleText, "; "), expiredRem, afterCtl, st.RevertTo, st.Written)

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason, claims...), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			a, err := c.frames(
				"every reversion point the timer needs is implemented in the model",
				"FC 3 read of model 704's register block; each reversion point compared against its type's "+
					"not-implemented sentinel",
				certify.Pass, "WMaxLimPctRvrt, WMaxLimPctEnaRvrt, WMaxLimPctRvrtTms and WMaxLimPctRvrtRem all "+
					"carry implemented values", st.TIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			tids := tidsFor(s.client.log, "REV-1")
			a, err = c.frames(claims[0],
				"at least three FC 3 reads of the remaining-time readback during the countdown, each compared "+
					"against the harness's own elapsed-time measurement with the procedure's two-second tolerance",
				verdictIf(trackOK), strings.Join(sampleText, "; "), tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = c.frames(claims[1],
				"an FC 3 read of the remaining-time readback taken after the programmed reversion time has "+
					"elapsed, timestamped against the write that armed the timer",
				verdictIf(expiryOK),
				fmt.Sprintf("the timer was armed for %ds; %0.1fs after arming the readback reads %d",
					st.Seconds, expiredAt.Sub(st.ArmedAt).Seconds(), expiredRem), tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = c.frames(claims[2],
				"an FC 3 read of the controlled point after expiry, compared against the reversion value read "+
					"before the test and against the value the test wrote",
				verdictIf(revertOK),
				fmt.Sprintf("the controlled point reads %d; the reversion value is %d and the test had "+
					"written %d", afterCtl, st.RevertTo, st.Written), tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			return out, nil
		},
	}, nil
}

// checkREV2 implements SS-MODBUS-CONF-v1.4 REV-2, Reversion Time Update.
//
// After at least half the reversion time has elapsed the timer register is
// rewritten with the full reversion time; the countdown must restart from
// there, the original timeout instant must pass without the reversion settings
// being applied, and the whole extend-and-verify cycle must succeed at least
// three times.
func checkREV2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "REV-2 reversion time update")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}
	claims := []string{
		"rewriting the reversion time mid-countdown restarts the countdown, and the remaining-time readback " +
			"tracks the updated time to within two seconds",
		"the reversion settings are NOT applied at the original timeout instant once the time has been updated",
	}
	st, err := armReversion(rc, s.client, ch, "REV-2")
	if err != nil {
		return certify.Result{}, err
	}
	if st.Blocked != "" {
		return blockedResult(s, st, claims, paramBool(rc, paramPICSReversion)), nil
	}
	defer cleanupReversion(s.client, st, "REV-2")

	const cycles = 3
	full := time.Duration(st.Seconds) * time.Second
	lastArmed := st.ArmedAt
	var lines []string
	trackOK, holdOK := true, true

	for i := 1; i <= cycles; i++ {
		originalExpiry := lastArmed.Add(full)
		// Step 4 — rewrite after at least half the reversion time has elapsed.
		if err := rc.Sleep(ctx, time.Until(lastArmed.Add(full/2))); err != nil {
			return certify.Result{}, err
		}
		tregs, _ := encode(st.Group.Timer, int64(st.Seconds))
		if werr := writePoint(s.client, st.Group.Ref, st.Group.Timer, tregs,
			fmt.Sprintf("REV-2 cycle %d step 4: rewrite the reversion time", i)); werr != nil {
			lines = append(lines, fmt.Sprintf("cycle %d: the mid-countdown rewrite was refused: %s", i, errText(werr)))
			trackOK = false
			break
		}
		rewroteAt := time.Now()

		// Step 5 — the readback must now track the UPDATED time.
		regs, rerr := readPoint(s.client, st.Group.Ref, st.Group.Remaining,
			fmt.Sprintf("REV-2 cycle %d step 5: remaining after the rewrite", i))
		if rerr != nil {
			return certify.Result{}, fmt.Errorf("read the remaining-time point: %w", rerr)
		}
		rem := u32(regs)
		expected := full - time.Since(rewroteAt)
		drift := time.Duration(rem)*time.Second - expected
		if drift > revTolerance || drift < -revTolerance {
			trackOK = false
		}
		lines = append(lines, fmt.Sprintf("cycle %d: rewrote at t+%.1fs, readback %ds against an expected "+
			"%.1fs (drift %+.1fs)", i, rewroteAt.Sub(st.ArmedAt).Seconds(), rem, expected.Seconds(), drift.Seconds()))

		// Steps 6-8 — run past the ORIGINAL timeout instant and verify the
		// timer is still running and the reversion settings have not landed.
		//
		// The observation instant has to be strictly between the original
		// expiry and the extended one, or the check would be reading the state
		// after the EXTENDED timer legitimately fired and calling that a
		// failure. The procedure's two-second margin is right for a reversion
		// time of tens of seconds; for a shorter one the margin is narrowed to
		// a quarter of the reversion time, which keeps the instant inside the
		// window the extension bought.
		margin := revTolerance
		if q := full / 4; q < margin {
			margin = q
		}
		if err := rc.Sleep(ctx, time.Until(originalExpiry.Add(margin))); err != nil {
			return certify.Result{}, err
		}
		regs, rerr = readPoint(s.client, st.Group.Ref, st.Group.Remaining,
			fmt.Sprintf("REV-2 cycle %d step 7: remaining past the original timeout", i))
		if rerr != nil {
			return certify.Result{}, fmt.Errorf("read the remaining-time point: %w", rerr)
		}
		stillRunning := u32(regs) > 0
		ctlRegs, cerr := readPoint(s.client, st.Group.Ref, st.Group.Controlled,
			fmt.Sprintf("REV-2 cycle %d step 8: controlled point past the original timeout", i))
		if cerr != nil {
			return certify.Result{}, fmt.Errorf("read the controlled point: %w", cerr)
		}
		held := decodeRaw(st.Group.Controlled, ctlRegs) == st.Written
		if !stillRunning || !held {
			holdOK = false
		}
		lines = append(lines, fmt.Sprintf("cycle %d: %.1fs past the original timeout the readback reads %ds "+
			"and the controlled point reads %d (written %d, reversion value %d)",
			i, time.Since(originalExpiry).Seconds(), u32(regs),
			decodeRaw(st.Group.Controlled, ctlRegs), st.Written, st.RevertTo))
		lastArmed = rewroteAt
	}

	verdict := verdictIf(trackOK && holdOK)
	return certify.Result{
		Verdict: verdict,
		Notes:   strings.Join(lines, "; "),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason, claims...), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			tids := tidsFor(s.client.log, "REV-2")
			a, err := c.frames(claims[0],
				fmt.Sprintf("%d extend-and-verify cycles, each rewriting the reversion time register after at "+
					"least half the reversion time has elapsed and re-reading the remaining-time point, with "+
					"the procedure's two-second tolerance", cycles),
				verdictIf(trackOK), strings.Join(lines, "; "), tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			a, err = c.frames(claims[1],
				"an FC 3 read of the remaining-time point and of the controlled point, taken after the "+
					"ORIGINAL timeout instant of each cycle has passed",
				verdictIf(holdOK), strings.Join(lines, "; "), tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			return out, nil
		},
	}, nil
}

// checkREV3 implements SS-MODBUS-CONF-v1.4 REV-3, Reversion Cancel.
//
// Writing 0 to the reversion time after at least half of it has elapsed must
// take the remaining-time readback to 0 and must mean the reversion settings
// are never applied — the written values stay in effect past the instant the
// original timer would have fired.
func checkREV3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "REV-3 reversion cancel")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}
	claims := []string{
		"writing 0 to the reversion time takes the reversion-time-remaining point to 0",
		"the reversion settings are never applied after the timer has been cancelled, past the instant the " +
			"original timer would have fired",
	}
	st, err := armReversion(rc, s.client, ch, "REV-3")
	if err != nil {
		return certify.Result{}, err
	}
	if st.Blocked != "" {
		return blockedResult(s, st, claims, paramBool(rc, paramPICSReversion)), nil
	}
	defer cleanupReversion(s.client, st, "REV-3")

	full := time.Duration(st.Seconds) * time.Second
	originalExpiry := st.ArmedAt.Add(full)

	// Step 3 — watch the countdown before cancelling, so "it was running" is
	// established rather than assumed.
	samples, err := pollRemaining(ctx, rc, s.client, st, st.ArmedAt.Add(full/2), 2, "REV-3 step 3")
	if err != nil {
		return certify.Result{}, err
	}
	countdownOK := len(samples) > 0
	var sampleText []string
	for _, smp := range samples {
		sampleText = append(sampleText, smp.String())
		if smp.Drift > revTolerance || smp.Drift < -revTolerance {
			countdownOK = false
		}
	}

	// Step 4 — cancel.
	zero, _ := encode(st.Group.Timer, 0)
	cancelOK := true
	cancelText := ""
	if werr := writePoint(s.client, st.Group.Ref, st.Group.Timer, zero, "REV-3 step 4: write 0 to the reversion time"); werr != nil {
		cancelOK = false
		cancelText = "the cancel write was refused: " + errText(werr)
	} else {
		regs, rerr := readPoint(s.client, st.Group.Ref, st.Group.Remaining, "REV-3 step 5: remaining after the cancel")
		if rerr != nil {
			return certify.Result{}, fmt.Errorf("read the remaining-time point after the cancel: %w", rerr)
		}
		rem := u32(regs)
		cancelOK = rem == 0
		cancelText = fmt.Sprintf("after writing 0 to the reversion time the remaining-time point reads %d", rem)
	}

	// Steps 6-7 — run past the original timeout and verify nothing reverted.
	if err := rc.Sleep(ctx, time.Until(originalExpiry.Add(revTolerance))); err != nil {
		return certify.Result{}, err
	}
	ctlRegs, err := readPoint(s.client, st.Group.Ref, st.Group.Controlled, "REV-3 step 7: controlled point past the original timeout")
	if err != nil {
		return certify.Result{}, fmt.Errorf("read the controlled point: %w", err)
	}
	after := decodeRaw(st.Group.Controlled, ctlRegs)
	heldOK := after == st.Written
	heldText := fmt.Sprintf("%.1fs past the instant the original timer would have fired, the controlled point "+
		"reads %d (the test wrote %d; the reversion value is %d)",
		time.Since(originalExpiry).Seconds(), after, st.Written, st.RevertTo)

	verdict := verdictIf(countdownOK && cancelOK && heldOK)
	return certify.Result{
		Verdict: verdict,
		Notes:   strings.Join(append(sampleText, cancelText, heldText), "; "),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason, claims...), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			tids := tidsFor(s.client.log, "REV-3")
			a, err := c.frames(
				"the reversion timer was demonstrably running before it was cancelled",
				"FC 3 reads of the remaining-time readback during the first half of the countdown, compared "+
					"against the harness's elapsed-time measurement with the two-second tolerance",
				verdictIf(countdownOK), strings.Join(sampleText, "; "), tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			a, err = c.frames(claims[0],
				"an FC 16 write of 0 to the reversion time register after at least half the reversion time had "+
					"elapsed, followed by an FC 3 read of the remaining-time point",
				verdictIf(cancelOK), cancelText, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			a, err = c.frames(claims[1],
				"an FC 3 read of the controlled point taken after the instant the original reversion timer "+
					"would have expired",
				verdictIf(heldOK), heldText, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			return out, nil
		},
	}, nil
}
