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
	"fmt"
	"sync"
	"time"

	"csip-tls-test/internal/invariant"
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

	// (d) WP7-T6: log — never fail — where the DER's own ceiling axis sits
	// once the fence and the deletes above are done. See
	// logPostTeardownBaseline's own doc: this is what lets the NEXT row's
	// baseline-contamination message (basic.go's markBaselineContamination)
	// attribute a residual reading to the teardown that actually left it,
	// instead of leaving a reader to guess which of several prior rows did.
	logPostTeardownBaseline(ctx, d, programs)

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

// ── The post-teardown baseline note (WP7-T6) ────────────────────────────────
//
// # What this closes
//
// Residual applied state from row N used to be caught only by row N+1's own
// oracle, at row N+1's Setup — by which point the contamination has already
// happened and the only thing row N+1 can say is "residual from prior row?",
// a question with no answer a bundle reader can chase down. This makes it an
// answer: teardown itself, best-effort and non-fatal exactly like the
// cancel-then-delete it follows, reads the DER's own ceiling axis (the
// registers this file's header doc already names as "the standing
// DefaultDERControl") right after its own fence-and-delete finishes, and
// records what it saw. The NEXT row's markBaselineContamination (basic.go)
// reads it back and folds it into ITS reason, so a contamination is
// attributed to the row whose teardown actually left it — not merely
// flagged as unexplained residue.
//
// # Why package-level state
//
// A fresh *Driver is built for every row (run(), check.go), so nothing on d
// survives from one row's Cleanup to the next row's Setup. observe.go's own
// runDERBaseline* (markRunBaseline/derPutsInRun) already carries a
// process-wide fact the same way, for the same structural reason — one
// process runs every row of a campaign in sequence, and "the last thing
// teardown saw" is exactly that kind of fact.
var (
	teardownNoteMu  sync.Mutex
	teardownNoteVal string
)

// logPostTeardownBaseline is releaseProgramControls' step (d): read the DER's
// ceiling axis and record what it holds, for the reason given above.
//
// It is BEST-EFFORT, like everything else in this file — an unreadable DER,
// no admin API, or a DER that serves neither ceiling generation all produce a
// short, honest note rather than an error, and NOTHING here can fail the row
// whose Cleanup is calling it. The read runs inside whatever remains of the
// teardown's own detached context (teardownFenceWindow's caller already
// budgeted deleteHeadroom for the deletes above; this shares that same
// context rather than opening a new one, so it costs no additional wall time
// budget of its own).
func logPostTeardownBaseline(ctx context.Context, d *Driver, programs []int) {
	if d == nil || d.rc == nil {
		return
	}
	uid := "?"
	if d.rc.Case != nil {
		uid = d.rc.Case.UID
	}
	note := func(text string) {
		teardownNoteMu.Lock()
		teardownNoteVal = fmt.Sprintf("%s's teardown (program(s) %v) left the DER's ceiling axis reading: "+
			"%s (observed %s)", uid, programs, text, time.Now().UTC().Format(time.RFC3339))
		teardownNoteMu.Unlock()
	}

	uv, err := oracleUnitView(ctx, d.rc, oracleSimName)
	if err != nil {
		note(fmt.Sprintf("could not be read after teardown: %v", err))
		return
	}
	home, why := ceilingHomeOf(uv)
	if why != "" {
		note("no ceiling register home on this DER: " + why)
		return
	}
	meas := uv.Measurement(oracleSimName)
	for _, c := range home.Cmds {
		if c.Point != home.Point {
			continue
		}
		r := invariant.ResolveCommand(c, home.NP, meas)
		note(fmt.Sprintf("%s enabled=%v, resolves to %s", home.Point, c.Enabled, r.Physical))
		return
	}
	note(fmt.Sprintf("%s not present in the DER's own command surface after teardown", home.Point))
}

// lastTeardownNote returns the most recent post-teardown observation
// logPostTeardownBaseline recorded, or "" when none has run yet in this
// process (the first row of a campaign, or a run with no gridsim admin API
// to have driven a teardown at all). markBaselineContamination (basic.go)
// folds this into its own reason when non-empty.
func lastTeardownNote() string {
	teardownNoteMu.Lock()
	defer teardownNoteMu.Unlock()
	return teardownNoteVal
}

// resetTeardownNote clears the process-wide teardown note. It exists for
// tests that exercise it directly (mirrors observe.go's resetRunBaseline);
// the runner never calls it.
func resetTeardownNote() {
	teardownNoteMu.Lock()
	teardownNoteVal = ""
	teardownNoteMu.Unlock()
}
