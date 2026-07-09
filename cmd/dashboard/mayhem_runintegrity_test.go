package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// WS-3 part 2: run-integrity hardening. These tests use the recording-server
// fixtures from scenariospec_test.go (newTestDriver/newRecordingServer) so
// d.run/d.runGuarded can exercise a full scenario against fake HTTP backends
// with no live bench.

// ── (a) malformed /api/qa/start body ────────────────────────────────────────

// A non-empty but malformed JSON body used to be silently discarded
// (`_ = json.Decode`), launching the full hostile suite on a typo'd request.
// It must now 400 and start nothing.
func TestHandleStart_RejectsMalformedBody(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/api/qa/start", strings.NewReader(`{"sample_ms": `)) // truncated JSON
	rec := httptest.NewRecorder()
	d.handleStart(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	d.mu.Lock()
	running := d.status.Running
	d.mu.Unlock()
	if running {
		t.Error("a malformed body must not start a run")
	}
}

// A genuinely empty body is not malformed — it must still fall back to
// defaults and launch a run, exactly as before this hardening.
func TestHandleStart_EmptyBodyStillAccepted(t *testing.T) {
	d := newMayhemDriver(map[string]string{}) // baseline() will fail fast (unknown backend) and self-abort
	req := httptest.NewRequest(http.MethodPost, "/api/qa/start", nil)
	rec := httptest.NewRecorder()
	d.handleStart(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (empty body keeps defaults)", rec.Code)
	}
}

// A well-formed, non-empty body must also still be accepted.
func TestHandleStart_ValidBodyStillAccepted(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/api/qa/start", bytes.NewReader([]byte(`{"sample_ms":500}`)))
	rec := httptest.NewRecorder()
	d.handleStart(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
}

// ── (b) a diagnoser panic must not kill the dashboard ───────────────────────

// runGuarded must recover a panic escaping run() (e.g. a buggy diagnoser),
// mark the run aborted with an error explaining why, and return normally —
// proven here by the test itself completing rather than the test binary
// crashing, plus the resulting status.
func TestRunGuarded_RecoversPanicKeepsDashboardAlive(t *testing.T) {
	d, _ := newTestDriver(t, "gridsim", "solar", "meter", "battery", "ev")
	sc := &mayScenario{
		ID: "panic-scenario", Name: "n", Category: "c", Hypothesis: "h", Expected: "e",
		HoldS: 0, // ticks clamps to 1; combined with a 1ms sample this holds ~1ms
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			panic("diagnoser exploded")
		},
	}
	d.mu.Lock()
	d.status = mayhemStatus{Running: true, StartedAt: time.Now(), Total: 1, Phase: "setup"}
	d.mu.Unlock()

	// Direct (synchronous) call — the point under test is that the panic
	// never escapes runGuarded, not the goroutine scheduling handleStart
	// normally does around it.
	d.runGuarded(context.Background(), []*mayScenario{sc}, 1*time.Millisecond)

	d.mu.Lock()
	st := d.status
	d.mu.Unlock()
	if st.Running {
		t.Error("Running should be false after a panicked run")
	}
	if !st.Aborted {
		t.Error("Aborted should be true after a panicked run")
	}
	if !containsFold(st.LastError, "panic") {
		t.Errorf("LastError = %q, want it to mention the panic", st.LastError)
	}
}

// ── (c) abort-truncated scenarios must be marked, not look normal ──────────

// Canceling the run context mid-hold truncates the sample window a diagnoser
// judges. The resulting finding must read as an aborted, untrustworthy
// partial judgement (INCONCLUSIVE + "aborted" in the headline) — never a
// normal-looking PASS/FAIL/DEGRADED, even if the diagnoser's own logic would
// have produced one from the partial data.
func TestRun_AbortMidScenarioMarksInconclusiveAborted(t *testing.T) {
	d, _ := newTestDriver(t, "gridsim", "solar", "meter", "battery", "ev")
	ctx, cancel := context.WithCancel(context.Background())
	sc := &mayScenario{
		ID: "abort-mid-hold", Name: "n", Category: "c", Hypothesis: "h", Expected: "e",
		HoldS: 5, // long hold; canceled after the first tick so it never completes
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			return exportCons(), nil
		},
		perTick: func(d *mayhemDriver, i int) {
			if i == 1 {
				cancel()
			}
		},
		evaluate: diagnoseConstraint,
	}
	d.mu.Lock()
	d.status = mayhemStatus{Running: true, StartedAt: time.Now(), Total: 1, Phase: "setup"}
	d.mu.Unlock()

	d.run(ctx, []*mayScenario{sc}, 5*time.Millisecond)

	d.mu.Lock()
	findings := append([]mayFinding(nil), d.status.Findings...)
	aborted := d.status.Aborted
	d.mu.Unlock()

	if !aborted {
		t.Fatal("run status should be Aborted")
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Verdict != "INCONCLUSIVE" {
		t.Errorf("verdict = %s, want INCONCLUSIVE for an abort-truncated scenario", f.Verdict)
	}
	if !containsFold(f.Headline, "aborted") {
		t.Errorf("headline = %q, want it to say the run was aborted", f.Headline)
	}
}

// ── (d) delayed-fault goroutines are context-cancellable ────────────────────

// afterDelay must not run fn once the current scenario's context has been
// canceled, even if the cancellation races the timer.
func TestAfterDelay_CanceledSkipsFn(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	d.scenarioCtx = ctx
	d.mu.Unlock()

	fired := make(chan struct{}, 1)
	d.afterDelay(30*time.Millisecond, func() { fired <- struct{}{} })
	cancel() // cancel well before the delay elapses

	select {
	case <-fired:
		t.Fatal("afterDelay ran fn after its scenario context was canceled")
	case <-time.After(80 * time.Millisecond):
		// fn correctly never fired
	}
}

// afterDelay must still fire fn normally when the scenario context is never
// canceled — the common case (the fault arms on schedule mid-hold).
func TestAfterDelay_FiresWhenNotCanceled(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	d.mu.Lock()
	d.scenarioCtx = context.Background()
	d.mu.Unlock()

	fired := make(chan struct{}, 1)
	d.afterDelay(5*time.Millisecond, func() { fired <- struct{}{} })

	select {
	case <-fired:
		// good
	case <-time.After(200 * time.Millisecond):
		t.Fatal("afterDelay never ran fn")
	}
}

// End-to-end: run() must cancel the scenario context BEFORE calling teardown,
// so any delayed-fault goroutine still waiting on its timer sees the
// cancellation before teardown does its own cleanup — teardown is always the
// last writer, never a goroutine that fires after it.
func TestRun_CancelsScenarioContextBeforeTeardown(t *testing.T) {
	d, _ := newTestDriver(t, "gridsim", "solar", "meter", "battery", "ev")
	var sawCanceledAtTeardown bool
	sc := &mayScenario{
		ID: "ctx-cancel-order", Name: "n", Category: "c", Hypothesis: "h", Expected: "e",
		HoldS: 0,
		teardown: func(d *mayhemDriver) {
			d.mu.Lock()
			ctx := d.scenarioCtx
			d.mu.Unlock()
			sawCanceledAtTeardown = ctx != nil && ctx.Err() != nil
		},
	}
	d.mu.Lock()
	d.status = mayhemStatus{Running: true, StartedAt: time.Now(), Total: 1, Phase: "setup"}
	d.mu.Unlock()

	d.run(context.Background(), []*mayScenario{sc}, 1*time.Millisecond)

	if !sawCanceledAtTeardown {
		t.Fatal("scenario context must already be canceled by the time teardown runs")
	}
}

// A scenario whose setup fails after arming a delayed-fault goroutine must
// still cancel that goroutine — a setup error skips the hold entirely, so
// nothing scheduled from it should ever fire.
func TestRun_SetupErrorCancelsPendingDelayedFault(t *testing.T) {
	d, _ := newTestDriver(t, "gridsim", "solar", "meter", "battery", "ev")
	fired := make(chan struct{}, 1)
	sc := &mayScenario{
		ID: "setup-fail", Name: "n", Category: "c", Hypothesis: "h", Expected: "e",
		HoldS: 0,
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			d.afterDelay(5*time.Millisecond, func() { fired <- struct{}{} })
			return nil, fmt.Errorf("boom")
		},
	}
	d.mu.Lock()
	d.status = mayhemStatus{Running: true, StartedAt: time.Now(), Total: 1, Phase: "setup"}
	d.mu.Unlock()

	d.run(context.Background(), []*mayScenario{sc}, 1*time.Millisecond)

	select {
	case <-fired:
		t.Fatal("delayed fault fired after its scenario's setup failed")
	case <-time.After(60 * time.Millisecond):
		// correctly never fired
	}
}
