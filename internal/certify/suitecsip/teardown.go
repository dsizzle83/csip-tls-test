package suitecsip

// teardown.go is the CANCEL-THEN-DELETE event-row teardown.
//
// ── Why not a bare delete, and why not a reversion-verify either ────────────
//
// The ORIGINAL teardown DELETEd the row's control(s) from gridsim. A DELETE
// makes the control VANISH from the advertised list, but IEEE 2030.5-2018
// §10.2.3.3 c) ends an event by CANCEL, not by removal, and a spec-correct DUT
// that has already ACQUIRED an active event keeps executing it until it OBSERVES
// the cancellation — which it cannot do if the control simply disappeared. So a
// still-live event could outlive its row on the DUT and become the next row's
// effective control (CSIP-BENCH-BASIC007-ORACLE-STATE-CONTAMINATION — the ONE
// row a plain DELETE contaminated; RUN-1's plain-DELETE bench run was 46/47
// clean, and this was the 47th).
//
// A brief experiment REPLACED the delete with a fatal "did the applied axis
// release?" register verify. That was UNSOUND on the live board and is gone: the
// verify read the DER's GLOBAL model-704 image and flagged ANY enabled axis, but
// the board runs a STANDING DefaultDERControl (gridsim program-0 exp_lim_W over
// WMax leaves WMaxLimPct enabled at ~62.5% BY DESIGN). That default is not an
// event to release — it legitimately persists — and a global "any 704 enable is
// contamination" gate cannot tell it from an event-applied axis, so it
// false-FATALed almost every row on the board (9/10). The verify's unit tests
// only passed because the as-built fixture leaves enable=0.
//
// ── The teardown, restored to cancel → fence → delete, BEST-EFFORT ──────────
//
// releaseProgramControls does, in order, and none of it is fatal:
//
//	a. server-CANCEL every live control on every program (status-only
//	   Cancelled(2)) so a spec-correct DUT OBSERVES the cancellation;
//	b. await a STRICTLY-NEWER DUT poll, so the DUT sees the Cancelled(2) and
//	   drops any active event BEFORE the delete removes it from the list — the
//	   one thing BASIC-006 → BASIC-007 needs; and
//	c. DELETE the control and curve (ClearControls/ClearCurves). The DUT reverts
//	   applied EVENT state on the deletion; the standing DEFAULT is neither
//	   touched nor graded.
//
// It is recorded-not-fatal (its original contract): ClearControls/ClearCurves
// record a failed clear to Driver.cleanupErrs, which run()'s deferred appends to
// the row's notes. Residual contamination is caught where it was found in the
// first place — by the ROWS' OWN oracles — not by a blunt global register gate
// that a by-design standing default makes unusable.

import (
	"context"
	"time"
)

// releaseProgramControls is the cancel-then-delete teardown for one or more
// gridsim DERPrograms. Best-effort throughout: the cancel lets a spec-correct
// DUT observe the event ending, the fence gives it a poll to observe it in, and
// the delete cleans the list up. A bench with no admin API armed nothing, so it
// is a no-op there.
//
// The two programs of the CORE-022 pair go in one call so both are cancelled and
// both are deleted in the one teardown; there is no per-program register verify
// to sequence around any more.
func (d *Driver) releaseProgramControls(ctx context.Context, programs ...int) error {
	// No admin API: nothing was armed on this bench, so there is nothing to
	// release and nothing to have leaked (adminClear takes the same guard).
	if !d.Available() || len(programs) == 0 {
		return nil
	}

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// (a) Capture the DUT's poll ordinal BEFORE any cancel, then server-cancel
	//     every live control on every program. A spec-correct DUT that has
	//     acquired an active event drops it only when it OBSERVES the Cancelled(2)
	//     (§10.2.3.3 c); a bare delete would make the control vanish before it
	//     could. cancelProgramControls is best-effort (recorded via its own
	//     path); a cancel failure is not fatal — the delete still cleans up.
	pollStart, havePoll := derPollOrdinal(ctx, d)
	for _, program := range programs {
		record(d.cancelProgramControls(ctx, program))
	}

	// (b) Await a STRICTLY-NEWER DUT poll so the DUT observes the Cancelled(2)
	//     and drops any active event BEFORE the delete removes it from the list.
	//     Best-effort, exactly as the ramp baseline's own fence is: a bench that
	//     publishes no /poll barrier degrades to skipping the wait.
	if havePoll {
		awaitFreshDERPoll(ctx, d, pollStart, teardownFenceWindow(ctx))
	}

	// (c) DELETE the control and curve for every program. The DUT reverts applied
	//     EVENT state on the deletion (RUN-1's plain DELETE proved this — 46/47
	//     rows clean); the standing DefaultDERControl (e.g. WMaxLimPct from
	//     exp_lim_W) legitimately persists and is neither touched nor graded here.
	//     ClearControls/ClearCurves record a failure to cleanupErrs — recorded,
	//     not fatal (the original teardown contract).
	for _, program := range programs {
		record(d.ClearControls(ctx, program))
		record(d.ClearCurves(ctx, program))
	}
	return firstErr
}

// teardownFenceWindow bounds how long the teardown waits for the DUT to observe
// the Cancelled(2) on a fresh poll before it deletes. It is the teardown's own
// detached-context budget (check.go's teardownCleanupBudget, scaled to the
// bench's advertised poll cadence), never a second fixed cap: awaitFreshDERPoll
// returns the instant a fresh poll lands, so this is only the ceiling for a
// bench that never polls. A near/expired deadline clamps to zero, leaving a
// small reserve for the DELETEs that follow.
func teardownFenceWindow(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		rem := time.Until(dl) - deleteHeadroom
		if rem < 0 {
			rem = 0
		}
		return rem
	}
	// No deadline — only a direct-driver unit test reaches here; fall back to the
	// budget's own ceiling rather than a shorter fixed cap.
	return 4 * time.Minute
}

// deleteHeadroom is reserved, after the poll fence, for the ClearControls +
// ClearCurves DELETEs to complete inside the same detached context.
const deleteHeadroom = 5 * time.Second
