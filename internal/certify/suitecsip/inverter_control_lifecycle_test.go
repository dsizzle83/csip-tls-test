package suitecsip

// inverter_control_lifecycle_test.go pins the IW13-005 timing fix: the
// independent southbound oracle (controlMode.Oracle, wired to BASIC-010 and
// BASIC-013 by register.go) must fire in inverterControlSpec's PostWait, not
// its Setup.
//
// oracle_test.go already proves the oracle CLOSURES themselves are correct —
// oracleMaxLimW/oracleFixedW read the right register and compare it right,
// hermetically, against a real derbase.ApplyControl write. What that file
// cannot show is the bug this one guards against: even a perfectly correct
// oracle closure produces a false SKIP if it is invoked before the DUT could
// possibly have applied the control it was just asked to fetch. That is a
// property of WHEN inverterControlSpec calls m.Oracle relative to the
// check.go run() phases (Setup -> wait for the DUT's poll cycle -> PostWait),
// not of the oracle's own arithmetic — so it has to be proven at the
// spec/Setup/PostWait level, against a Driver wired to a real gridsim, the
// same way nonce_test.go's gridsimDriver drives coreResponsesSpec/
// coreSupersedingSpec directly.
//
// The DUT itself is not in this test's loop (there is no live DUT on this
// bench's CI), so "the DUT fetched and applied the control" is stood in for
// by driving the SAME real derbase.ApplyControl write oracle_test.go uses,
// timed by hand between calling Setup and calling PostWait — which is exactly
// the timing check.go's own wait is meant to buy the real DUT.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/diff"
	"csip-tls-test/internal/invariant"
	"csip-tls-test/sim/gridsim"
	model "lexa-proto/csipmodel"
)

// TestOracledScalarWindow_ContainsEveryPostWaitRead is the IW13-005 window
// regression guard. The PostWait oracle can read the DER anywhere from when
// AwaitWalk returns (~fetchWait, itself ranging over [defaultWait, waitCap] —
// check.go) out to a whole settle poll beyond that, since IW14-005 gave the
// poll the row's own poll-cycle window. An oracled scalar control
// (scalarModeOracled -> oracleWindow) must stay active across that ENTIRE
// range, or a read at a slower cadence overruns the control's release edge. (The read-too-EARLY edge
// of the same race — the DER read before the board applies the fetched control
// — is the settle poll's job, guarded by the TestSettleOracle_* tests; this
// one guards the late edge.) The default (fetch-only) scalarWindow deliberately
// does NOT contain the range — nothing reads the DER during it — and the test
// pins that asymmetry too, so a future edit that points an oracled row back at
// the short window fails here.
func TestOracledScalarWindow_ContainsEveryPostWaitRead(t *testing.T) {
	winOpen := time.Duration(oracleWindow.startOffsetS) * time.Second
	winClose := time.Duration(oracleWindow.startOffsetS+oracleWindow.durationS) * time.Second

	// The earliest possible read (defaultWait) must land strictly AFTER the
	// control becomes active, with margin.
	if winOpen >= defaultWait {
		t.Fatalf("oracled control opens at +%s, but the earliest PostWait read is +%s (defaultWait) — "+
			"the oracle can read the DER before its control is active", winOpen, defaultWait)
	}
	// The LATEST possible read is now two windows out, not one (IW14-005): the
	// wait itself can run to waitCap, and the settle poll that follows it runs
	// for up to the SAME derived poll-cycle window, which is itself capped at
	// waitCap. A control sized for the wait alone would release under precisely
	// the slow-bench read the settle widening exists to protect — trading the
	// read-too-early false FAIL for a read-too-late one.
	latestRead := waitCap + waitCap
	if winClose <= latestRead {
		t.Fatalf("oracled control closes at +%s, but the latest PostWait read is +%s (waitCap for the wait "+
			"+ waitCap for the settle poll) — the oracle can read the DER at/after its control's release "+
			"boundary (the IW13-005 false FAIL, at the far edge)", winClose, latestRead)
	}

	// The default fetch-only window is NOT expected to contain the read range;
	// pinning it guards against silently widening every scalar row (and against
	// an oracled row being pointed back at it).
	defClose := time.Duration(scalarWindow.startOffsetS+scalarWindow.durationS) * time.Second
	if defClose > waitCap {
		t.Fatalf("the default (fetch-only) scalar window now closes at +%s, past waitCap (+%s) — either the "+
			"window widened for every row (unintended) or waitCap shrank; the oracled rows carry the wide "+
			"window on purpose, the rest should not", defClose, waitCap)
	}

	// The PRESCRIBED default (IW15-004) sits UNDERNEATH the row's own control
	// and must outlive it, the way a DefaultDERControl would: it opens
	// immediately (Setup blocks until it lands, so a start offset is pure
	// latency on the row's critical path) and closes after the event above it.
	defaultOpen := time.Duration(oracleDefaultWindow.startOffsetS) * time.Second
	defaultClose := time.Duration(oracleDefaultWindow.startOffsetS+oracleDefaultWindow.durationS) * time.Second
	if defaultOpen != 0 {
		t.Errorf("the prescribed default opens at +%s; Setup WAITS for it to land, so every second of "+
			"offset is a second added to the row before it can command anything", defaultOpen)
	}
	if defaultClose <= winClose {
		t.Errorf("the prescribed default closes at +%s, at or before the row's own control (+%s) — the "+
			"default is the state the procedure prescribes for this DER and must still be standing when "+
			"the event that supersedes it ends", defaultClose, winClose)
	}
}

// inverterControlLifecycleRunCtx wires ONE *certify.RunCtx to two in-process
// fixtures: a real gridsim admin API (so Setup's m.Publish — a live
// d.PostControl round trip — has something to publish to, exactly as
// gridsimDriver in nonce_test.go sets up for coreResponsesSpec), and a
// simapi-shaped register server reading dev's live snapshot (the same shape
// oracle_test.go's oracleTestRunCtx builds, so PostWait's m.Oracle(ctx, d.rc)
// has a real DER register image to read). Both live behind the SAME RunCtx
// because inverterControlSpec's PostWait closure reads d.rc, the identical
// object Setup's d.PostControl used.
func inverterControlLifecycleRunCtx(t *testing.T, dev *diff.Device) (*certify.RunCtx, *Driver) {
	t.Helper()

	gs := gridsim.NewServer(benchLFDI)
	gsSrv := httptest.NewServer(gs.AdminHandler())
	t.Cleanup(gsSrv.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		snap := dev.Snapshot()
		out := make(map[string]uint16, len(snap))
		for addr, v := range snap {
			out[fmt.Sprintf("%d", addr)] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"paused": false, "sessions": []any{}})
	})
	oracleSrv := httptest.NewServer(mux)
	t.Cleanup(oracleSrv.Close)

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::BASIC-010", ID: "BASIC-010"},
		GridSim: certify.NewAdminClient(gsSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: gsSrv.URL},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, oracleSrv.URL, http.DefaultClient),
		},
	}
	return rc, NewDriver(rc)
}

// TestSettleOracle_RetriesUntilTheEffectLands is the IW13-005 propagation-race
// guard. AwaitWalk returns at the START of the DUT's walk, so the first oracle
// read can land while the fetched control is still traveling the
// northbound->MQTT->reconciler->Modbus pipeline to the DER's registers (the
// live bench read the program default ~1s before "applied CeilingW=4800"). The
// PostWait oracle must POLL through that beat, not sample once. Here eval FAILs
// the first two reads (DER still mid-propagation) then PASSes — settleOracle
// must return Pass and must actually have re-read.
func TestSettleOracle_RetriesUntilTheEffectLands(t *testing.T) {
	calls := 0
	f := settleOracleWindow(context.Background(), 2*time.Second, time.Millisecond, func() Finding {
		calls++
		if calls < 3 {
			return Finding{Verdict: certify.Fail, Observed: "not applied yet"}
		}
		return Finding{Verdict: certify.Pass, Observed: "applied"}
	})
	if f.Verdict != certify.Pass {
		t.Fatalf("settleOracle after a Fail->Fail->Pass sequence = %+v, want Pass", f)
	}
	if calls != 3 {
		t.Fatalf("settleOracle made %d reads, want 3 — it must re-read across the propagation beat, not sample once", calls)
	}
}

// TestSettleOracle_FailsAtDeadlineOnPersistentMismatch proves the settle never
// masks a real defect: a DER that never reaches the commanded value (wrong
// register, wrong value) FAILs at the deadline with the value it read, it does
// not hang or silently pass.
func TestSettleOracle_FailsAtDeadlineOnPersistentMismatch(t *testing.T) {
	calls := 0
	f := settleOracleWindow(context.Background(), 50*time.Millisecond, time.Millisecond, func() Finding {
		calls++
		return Finding{Verdict: certify.Fail, Observed: "wrong value on the wire"}
	})
	if f.Verdict != certify.Fail {
		t.Fatalf("settleOracle on a persistent mismatch = %+v, want Fail at the deadline", f)
	}
	if calls < 2 {
		t.Fatalf("settleOracle made %d reads, want >=2 — it must keep polling until the deadline before conceding FAIL", calls)
	}
}

// TestSettleOracle_ReturnsOnlyPassAtOnce pins the ONE outcome that is not worth
// re-reading for: a Pass, which is already settled.
//
// It replaces the pre-IW14-003 shape (which pinned Unavailable as returning at
// once too). Unavailable is now retried: the oracles' "the DER reports no
// enabled WMaxLimPct/WSet in its own 704 image" terminal — the commonest
// mid-propagation reading there is — used to arrive here as an Unavailable and
// so was the one shape that never got the window this poll exists to give it.
// That terminal is a decided FAIL now (noEnabledAxis), and a transport-level
// Unavailable is retried as well, because a sidecar that answers on the second
// read is worth more than 15 saved seconds on a bench that is already broken.
func TestSettleOracle_ReturnsOnlyPassAtOnce(t *testing.T) {
	passCalls := 0
	if f := settleOracleWindow(context.Background(), time.Hour, time.Second, func() Finding {
		passCalls++
		return Finding{Verdict: certify.Pass}
	}); f.Verdict != certify.Pass || passCalls != 1 {
		t.Fatalf("settleOracle on an immediate Pass = %+v after %d call(s), want Pass after exactly 1", f, passCalls)
	}
	unavailCalls := 0
	f := settleOracleWindow(context.Background(), 50*time.Millisecond, time.Millisecond, func() Finding {
		unavailCalls++
		return unavailable("DER unreachable")
	})
	if f.Unavailable == "" {
		t.Fatalf("settleOracle on a persistent Unavailable = %+v, want the last finding (still Unavailable) "+
			"returned at the deadline", f)
	}
	if unavailCalls < 2 {
		t.Fatalf("settleOracle made %d read(s) on an Unavailable, want >=2 — an unavailable reading must be "+
			"retried inside the window, not conceded on the first sample (IW14-003)", unavailCalls)
	}
}

// TestSettleOracle_RetriesTheNotYetEnabledShape is IW14-003's own settle guard,
// written in the oracles' real vocabulary rather than in abstract verdicts: the
// DER answers, its 704 image simply has no ENABLED setpoint on the commanded
// axis yet, because the DUT's write has not landed. That reading must be polled
// through — it is the definition of mid-propagation — and must resolve to the
// Pass that follows it, not be conceded on the first sample.
func TestSettleOracle_RetriesTheNotYetEnabledShape(t *testing.T) {
	uv := invariant.UnitView{}
	calls := 0
	f := settleOracleWindow(context.Background(), 2*time.Second, time.Millisecond, func() Finding {
		calls++
		if calls < 3 {
			// Exactly what oracleFixedW/oracleMaxLimW return while the DER's
			// register still holds nothing enabled on the commanded axis.
			return noEnabledAxis("WSet/WSetPct", 60, "WDisChaRteMaxRtg", 8000, 4800, uv)
		}
		return Finding{Verdict: certify.Pass, Observed: "the DER's own WSet resolves to 4800.0 W"}
	})
	if f.Verdict != certify.Pass {
		t.Fatalf("settleOracle across a not-yet-enabled -> not-yet-enabled -> applied sequence = %+v, want "+
			"Pass: the no-enabled-axis reading is the mid-propagation shape this poll exists for", f)
	}
	if calls != 3 {
		t.Fatalf("settleOracle made %d read(s), want 3 — it must re-read through the not-yet-enabled beat", calls)
	}
}

// TestOracleSettleDeadline_ComesFromTheRowsPollWindow is IW14-005's unit guard
// on WHERE the settle deadline comes from.
//
// The fixed 15s window decided rows on a coin toss: the southbound write follows
// the modbus reconciler's own ~10s tick, not the DUT's fetch, so the same board
// applying the same value took 0.5s, 13.2s and 20.3s on three consecutive
// bench rows (oracleSettleWindow's doc records all three, with the FAIL). The
// deadline is now the poll-cycle window run() already derived from the DUT's
// cadence and already prints in the bundle — a stated reason instead of a guess
// — recovered from the params the live phase carries between its phases.
func TestOracleSettleDeadline_ComesFromTheRowsPollWindow(t *testing.T) {
	for _, c := range []struct {
		name   string
		params map[string]string
		want   time.Duration
	}{
		{"the row's own derived window", map[string]string{pollWindowParam: "2m30s"}, 150 * time.Second},
		{"an operator's longer window", map[string]string{pollWindowParam: "8m"}, 8 * time.Minute},
		{"no params at all (a unit test's PostWait)", map[string]string{}, oracleSettleWindow},
		{"an unparseable value", map[string]string{pollWindowParam: "soon"}, oracleSettleWindow},
		{"a non-positive value", map[string]string{pollWindowParam: "0s"}, oracleSettleWindow},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := oracleSettleDeadline(c.params); got != c.want {
				t.Fatalf("oracleSettleDeadline(%v) = %s, want %s", c.params, got, c.want)
			}
		})
	}
	// The fallback must never be the thing production uses: a run whose params
	// carry the window has to poll for the window, and 15s is not it.
	if oracleSettleDeadline(map[string]string{pollWindowParam: "2m30s"}) == oracleSettleWindow {
		t.Fatal("the derived window resolved to the 15s fallback — the IW14-005 regression, verbatim")
	}
}

// TestInverterControlSpec_SettlePollRunsForThePollWindow proves the deadline
// reaches the REAL PostWait, not just the helper: it drives an oracled row's
// PostWait against a DER that never applies anything (a persistent FAIL, so the
// poll can never short-circuit) and measures how long it polls for.
//
// Wall-clock in a test earns its keep here. The defect being guarded is a
// duration, the pass-through is otherwise invisible from outside, and the bench
// evidence for it cost two live runs; the bounds below are wide enough that only
// a genuinely wrong deadline can trip them.
func TestInverterControlSpec_SettlePollRunsForThePollWindow(t *testing.T) {
	dev, _ := oracleFixture(t) // nothing applied, ever: every read is a decided FAIL
	_, d := inverterControlLifecycleRunCtx(t, dev)
	s := inverterControlSpec(basic010Mode(), "a maximum active power limit", "CERT-SETTLE-WINDOW")

	elapsed := func(window string) time.Duration {
		params := map[string]string{pollWindowParam: window}
		start := time.Now()
		if err := s.PostWait(context.Background(), d, params); err != nil {
			t.Fatalf("PostWait: %v", err)
		}
		took := time.Since(start)
		if params[oracleVerdictParam] != string(certify.Fail) {
			t.Fatalf("PostWait recorded %s=%q, want the decided Fail a DER holding nothing must produce — "+
				"the timing below means nothing if the poll short-circuited on a Pass",
				oracleVerdictParam, params[oracleVerdictParam])
		}
		return took
	}

	short, long := elapsed("1s"), elapsed("4s")
	if short > 3*time.Second {
		t.Fatalf("a 1s poll window took %s — the row is not reading its deadline from %s (the pre-fix %s "+
			"constant, or something else entirely)", short, pollWindowParam, oracleSettleWindow)
	}
	if long < 3500*time.Millisecond {
		t.Fatalf("a 4s poll window conceded after %s — the settle poll is not honouring the window the row "+
			"derived, which is the IW14-005 false FAIL (the bench's write landed 20.3s after the walk, "+
			"5.3s past the old 15s deadline)", long)
	}
	if long <= short {
		t.Fatalf("a 4s window (%s) did not outlast a 1s window (%s): the deadline is not coming from the "+
			"params at all", long, short)
	}
	t.Logf("settle poll honoured its window: 1s -> %s, 4s -> %s", short.Round(time.Millisecond),
		long.Round(time.Millisecond))
}

// TestInverterControlSpec_DeclaresSettlePollOnlyWhenOracled pins the budget
// half of IW14-005 at its source. A row whose PostWait can spend a second full
// poll-cycle window must declare it (waitSlots counts the declaration —
// wait_test.go owns that arithmetic), or fetchWait sizes the FIRST window as if
// it owned the whole -timeout and the check is killed between the two, which
// yields no criteria at all: the worse bundle waitBudgetReserve's doc argues
// against. A row with no oracle must NOT declare it, or its window is halved to
// pay for a poll it never makes.
func TestInverterControlSpec_DeclaresSettlePollOnlyWhenOracled(t *testing.T) {
	if s := inverterControlSpec(basic010Mode(), "a maximum active power limit", "CERT-SLOTS"); !s.SettlePoll {
		t.Error("an ORACLED row does not declare SettlePoll, so its second window is invisible to the budget")
	}
	plain := inverterControlSpec(scalarMode("opModConnect", func(r *ControlRequest) { r.Connect = ptr(false) }),
		"a connect/disconnect command", "CERT-SLOTS-PLAIN")
	if plain.SettlePoll {
		t.Error("a row with no Oracle declares SettlePoll — it has no settle poll to pay for, and the " +
			"declaration would halve its poll-cycle window for nothing")
	}
}

// TestInverterControlSpec_OracleFiresPostWaitNotSetup is the lifecycle proof
// the review asked for: it drives inverterControlSpec's Setup and PostWait
// directly, in that order, against a register view that is EMPTY at Setup
// time and correct only afterward — proving the fix flips a real Skip into a
// real Pass, not just that Setup and PostWait are wired to different funcs.
func TestInverterControlSpec_OracleFiresPostWaitNotSetup(t *testing.T) {
	dev, base := oracleFixture(t) // Bench702 fixture; no control applied yet
	_, d := inverterControlLifecycleRunCtx(t, dev)
	ctx := context.Background()

	m := basic010Mode()
	subject := "a maximum active power limit"
	s := inverterControlSpec(m, subject, "CERT-LIFECYCLE-BASIC010")

	// --- Setup: publishes the control and takes the PRE-publication baseline
	// (IW14-003), and must NOT populate the POST-oracle keys ---
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if params["mrid"] != "CERT-LIFECYCLE-BASIC010" {
		t.Fatalf("Setup did not stash mrid: params = %v", params)
	}
	if v, ok := params[oracleVerdictParam]; ok {
		t.Fatalf("Setup populated %s=%q — the POST oracle fired during Setup, before the DUT could have "+
			"applied anything (the exact IW13-005 bug this test guards against)", oracleVerdictParam, v)
	}
	if v, ok := params[oracleUnavailableParam]; ok {
		t.Fatalf("Setup populated %s=%q — the POST oracle must not fire during Setup at all, unavailable "+
			"or otherwise", oracleUnavailableParam, v)
	}
	// The PRE keys are the opposite requirement: Setup MUST have taken the
	// baseline, or the post-read it is compared against is not evidence of a
	// transition at all (IW14-003). They are distinct keys precisely so both
	// assertions can be made about the same run.
	if params[oraclePreVerdictParam] != string(certify.Fail) {
		t.Fatalf("after Setup, %s = %q, want %q — before the control was published the DER's own 704 image "+
			"held nothing enabled on the commanded axis, and that baseline is what makes the post-read "+
			"mean anything", oraclePreVerdictParam, params[oraclePreVerdictParam], certify.Fail)
	}
	if !strings.Contains(params[oraclePreObservedParam], "NO enabled") {
		t.Fatalf("after Setup, %s = %q, want it to name what the pre-publication read actually saw",
			oraclePreObservedParam, params[oraclePreObservedParam])
	}
	if params[oracleCommandedParam] != "6000" {
		t.Fatalf("after Setup, %s = %q, want the catalog's own 6000: the DER held nothing, so no ladder "+
			"alternate was called for", oracleCommandedParam, params[oracleCommandedParam])
	}
	if n, ok := params[oracleNoteParam]; ok {
		t.Fatalf("after Setup, %s = %q — a row that commanded the catalog's value has no departure to "+
			"record", oracleNoteParam, n)
	}

	// Prove what the SAME oracle finds at Setup-time: a decided FAIL, because
	// the DER's own register genuinely holds nothing enabled yet. Run the
	// production criterion over that exact finding and confirm it DECIDES.
	// Before IW14-003 this shape was an Unavailable that the criterion turned
	// into a Skip, which no roll-up in the runner can act on — a criterion that
	// "ran", found the DER unhelpful, and let the case pass anyway.
	early := m.Oracle.Judge(m.Oracle.Commanded)(ctx, d.rc)
	if early.Verdict != certify.Fail {
		t.Fatalf("the oracle evaluated at Setup-time (before the DUT could apply the control) = %+v, "+
			"want a decided Fail — the DER's own register genuinely holds nothing yet, and that is a "+
			"finding about the DER, not an unavailability of the bench", early)
	}
	if early.Unavailable != "" {
		t.Fatalf("the Setup-time oracle reading carries Unavailable=%q; the no-enabled-axis terminal is a "+
			"decided FAIL now (IW14-003), so the settle poll retries it and the criterion can act on it",
			early.Unavailable)
	}
	earlyObs := &Observation{Params: map[string]string{oracleVerdictParam: string(early.Verdict),
		oracleObservedParam: early.Observed, oraclePreVerdictParam: string(certify.Fail)}}
	earlyCrit := critDEREffectViaSouthboundOracle(subject, earlyObs)
	if earlyCrit.Skip != "" {
		t.Fatalf("critDEREffectViaSouthboundOracle at Setup-time carries Skip=%q — this criterion must "+
			"never degrade to a SKIP: SKIP is severity 0 and every roll-up in the runner raises only, so "+
			"a skipping oracle cannot hold a release (IW14-003)", earlyCrit.Skip)
	}
	if earlyCrit.Wire == nil {
		t.Fatal("critDEREffectViaSouthboundOracle carries no Wire evaluator, so mint() has nothing to " +
			"grade and falls through to SkipAssertion — the degrade path IW14-003 closed")
	}
	wantVerdict(t, "DER effect via oracle (setup-time)", earlyCrit, nil, certify.Fail)

	// --- Simulate the DUT's poll cycle: it fetched the control and applied
	// it southbound. Drive the SAME real derbase write path oracle_test.go
	// uses, so the register the oracle reads next is genuinely conformant,
	// not a hand-set field. ---
	pc := model.PerCent{Value: 6000} // 60.00%, matching m's commanded 6000
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "lifecycle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}

	// --- PostWait: this is where the fix says the oracle must fire ---
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("PostWait: %v", err)
	}
	if params[oracleVerdictParam] != string(certify.Pass) {
		t.Fatalf("after PostWait, %s = %q, want %q — PostWait must read the DER's registers AFTER the "+
			"simulated poll cycle, not before", oracleVerdictParam, params[oracleVerdictParam], certify.Pass)
	}
	if _, unavailable := params[oracleUnavailableParam]; unavailable {
		t.Fatalf("after PostWait, %s is still set (%q) even though the register now genuinely holds the "+
			"commanded value", oracleUnavailableParam, params[oracleUnavailableParam])
	}

	// Finally, the production criterion itself — the thing a bundle reader
	// actually sees — must resolve to a real Pass off PostWait's params, and
	// must say WHY it is one: the reading moved.
	postObs := &Observation{Params: params}
	postCrit := critDEREffectViaSouthboundOracle(subject, postObs)
	f := wantVerdict(t, "DER effect via oracle (post-wait)", postCrit, nil, certify.Pass)
	if !strings.Contains(f.Observed, "did NOT hold") {
		t.Errorf("the passing oracle criterion = %q, want it to cite the pre-publication baseline it "+
			"moved from — a post-read alone is a fact about the DER, not about the DUT", f.Observed)
	}
	if postCrit.Tier != tierOracle {
		t.Errorf("the oracle criterion's tier = %q, want %q: its answer comes from the DER's own "+
			"registers, and stamping the capture's handshake tier on it tells a bundle reader the pcap "+
			"backed a fact the pcap never saw", postCrit.Tier, tierOracle)
	}
	// The case verdict route (spec.Verdict) must be quiet on a good run: the
	// wire criteria decide a row whose southbound half is satisfied.
	if v := s.Verdict(postObs); v != "" {
		t.Errorf("spec.Verdict on a satisfied oracle = %q, want empty — declaring PASS here would let a "+
			"row with no recovered session pass on the southbound read alone", v)
	}
	t.Logf("post-wait oracle criterion: %s", f.Observed)
}

// basic010Mode builds the BASIC-010 controlMode exactly as register.go binds
// it, so the lifecycle tests exercise the row the campaign runs rather than a
// look-alike assembled here.
func basic010Mode() controlMode {
	return withOracle(scalarModeOracled("opModMaxLimW", 6000, func(r *ControlRequest, hundredths int64) {
		r.MaxLimW = ptr(hundredths)
	}), oracleMaxLimW)
}

// basic013Mode builds the BASIC-013 controlMode exactly as register.go binds it
// after IW15-004: the procedure's own 50% default, the procedure's own 60% test
// value, and no ladder.
func basic013Mode() controlMode {
	return withOracle(scalarModeOracledDefaultFirst("opModFixedW", 5000, 6000,
		func(r *ControlRequest, hundredths int64) {
			r.FixedW = ptr(hundredths)
		}), oracleFixedW)
}

// TestOracledRow_PrescribedRowCarriesNoLadder is IW15-004's construction-level
// guarantee: a row whose procedure states its values must have no mechanism for
// substituting one.
//
// The two are mutually exclusive by design rather than by discipline. A ladder
// on a prescribed row would let Setup depart from the catalog's value at run
// time — which is exactly what produced a BASIC-013 report claiming conformance
// for a 40% command the procedure never asked for — and no amount of care at
// the call site is worth as much as the departure being unrepresentable.
func TestOracledRow_PrescribedRowCarriesNoLadder(t *testing.T) {
	b := basic013Mode().Oracle
	if b.Prescribed != 5000 {
		t.Errorf("BASIC-013's prescribed default = %d, want the catalog's 5000 (50.00%%) — CSIP CTP v1.3 "+
			"Figure 13 states it", b.Prescribed)
	}
	if b.Commanded != 6000 {
		t.Errorf("BASIC-013's commanded value = %d, want the catalog's 6000 (60.00%%)", b.Commanded)
	}
	if len(b.Ladder) != 0 {
		t.Errorf("BASIC-013 carries a %d-entry ladder (%s): a row whose procedure states its values may "+
			"not substitute another one, and the stale-register case the ladder existed for is what the "+
			"prescribed default now handles", len(b.Ladder), pctList(b.Ladder))
	}
	if b.PublishDefault == nil {
		t.Error("BASIC-013 prescribes a default and carries no publisher for it, so Setup cannot put the " +
			"DER into the state the procedure requires")
	}
	// The converse, so the two shapes cannot converge: a laddered row must not
	// acquire a prescribed default it would then have two ways to depart from.
	if l := basic010Mode().Oracle; l.Prescribed != 0 || len(l.Ladder) == 0 {
		t.Errorf("BASIC-010's binding = prescribed %d / %d ladder entries, want the ladder shape it has "+
			"always had (its procedure states no default to reset through)", l.Prescribed, len(l.Ladder))
	}
}

// TestPrescribedSetup_DrivesTheDefaultThenCommandsTheCatalogValue is the
// IW15-004 sequence end to end, against a real gridsim and a real DER register
// image: publish the prescribed 50% default under its OWN mRID, wait for it to
// land, then publish exactly the catalog's 60% under the row's mRID.
//
// The DER is moved by the test between the two phases, standing in for the DUT
// fetching and applying — the same substitution
// TestInverterControlSpec_OracleFiresPostWaitNotSetup makes, for the same
// reason: what is under test is the row's sequencing, not the DUT.
func TestPrescribedSetup_DrivesTheDefaultThenCommandsTheCatalogValue(t *testing.T) {
	dev, base := oracleFixture(t)
	_, d := inverterControlLifecycleRunCtx(t, dev)
	ctx := context.Background()

	m := basic013Mode()
	s := inverterControlSpec(m, "a set-active-power command", "CERT-BASIC-013")

	// The DUT applies the 50% default one beat after it is published. A
	// goroutine, because Setup BLOCKS on the default landing — which is the
	// property under test.
	applied := make(chan struct{})
	go func() {
		defer close(applied)
		time.Sleep(20 * time.Millisecond)
		spc := model.SignedPerCent{Value: 5000} // 50.00%, the prescribed default
		if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &spc}, "prescribed-default"); err != nil {
			t.Errorf("ApplyControl(opModFixedW=5000): %v", err)
		}
	}()

	// A short window: this test is about the sequence, not the duration, and
	// the deadline honours the params (prescribedDefaultDeadline).
	params := map[string]string{pollWindowParam: "5s"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	<-applied

	if got := params[oracleDefaultCommandedParam]; got != "5000" {
		t.Fatalf("%s = %q, want the procedure's own 5000", oracleDefaultCommandedParam, got)
	}
	if got := params[oracleDefaultMRIDParam]; got != "CERT-BASIC-013"+defaultControlMRIDSuffix {
		t.Fatalf("%s = %q, want the default published under its OWN mRID — sharing the row's would make "+
			"gridsim update the control in place and would satisfy the row's own wire criterion",
			oracleDefaultMRIDParam, got)
	}
	if got := params[oracleDefaultVerdictParam]; got != string(certify.Pass) {
		t.Fatalf("%s = %q (%s), want PASS: the row must WAIT for the prescribed default to reach the DER's "+
			"own registers, not merely publish it", oracleDefaultVerdictParam, got,
			params[oracleDefaultObservedParam])
	}
	// The catalog's value, exactly, with no substitution available.
	if got := params[oracleCommandedParam]; got != "6000" {
		t.Fatalf("%s = %q, want exactly the catalog's 6000 — a prescribed row has no ladder to depart to",
			oracleCommandedParam, got)
	}
	// And the baseline for THAT value was taken from the prescribed state: the
	// DER holds 50%, so it does NOT hold 60%, which is what makes the post-read
	// a transition.
	if got := params[oraclePreVerdictParam]; got != string(certify.Fail) {
		t.Fatalf("%s = %q, want the decided FAIL that proves the DER did not already hold the commanded "+
			"value when the row published it", oraclePreVerdictParam, got)
	}
	if !strings.Contains(params[oracleNoteParam], "stated sequence") {
		t.Errorf("%s = %q, want the bundle to carry the sequence this row followed", oracleNoteParam,
			params[oracleNoteParam])
	}

	// Both controls are on the wire, under different mRIDs, with the row's own
	// created later so it supersedes the default it sits on.
	pub := d.Published()
	for _, want := range []string{"CERT-BASIC-013", "CERT-BASIC-013" + defaultControlMRIDSuffix} {
		if _, ok := pub[want]; !ok {
			t.Errorf("no control was published under mRID %q (published: %v)", want, pub)
		}
	}
	if !pub["CERT-BASIC-013"].After(pub["CERT-BASIC-013"+defaultControlMRIDSuffix]) {
		t.Error("the row's own control was not created AFTER the default it supersedes; at equal primacy " +
			"2030.5 resolves an overlap by creationTime, so the default would win")
	}
}

// TestPrescribedSetup_StaleRegisterIsResetThroughTheDefault is the review's
// "stale 60% must be reset through the 50% default and then transition",
// stated as the run that used to produce a false PASS.
//
// A previous run left the DER at exactly the value this row is about to
// command. The pre-IW15-004 row saw that, departed to a ladder alternate and
// certified a value the procedure never states. This row instead drives the DER
// to the prescribed 50%, which makes the stale 60% disappear, and then commands
// the catalog's 60% — so the transition it certifies is both real AND the one
// the procedure describes.
func TestPrescribedSetup_StaleRegisterIsResetThroughTheDefault(t *testing.T) {
	dev, base := oracleFixture(t)
	stale := model.SignedPerCent{Value: 6000} // the previous run's setpoint, still there
	if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &stale}, "previous-run"); err != nil {
		t.Fatalf("ApplyControl(the previous run's opModFixedW=6000): %v", err)
	}
	_, d := inverterControlLifecycleRunCtx(t, dev)
	ctx := context.Background()

	m := basic013Mode()
	subject := "a set-active-power command"
	s := inverterControlSpec(m, subject, "CERT-BASIC-013")

	go func() {
		time.Sleep(20 * time.Millisecond)
		def := model.SignedPerCent{Value: 5000}
		if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &def}, "prescribed-default"); err != nil {
			t.Errorf("ApplyControl(opModFixedW=5000): %v", err)
		}
	}()

	params := map[string]string{pollWindowParam: "5s"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := params[oracleCommandedParam]; got != "6000" {
		t.Fatalf("%s = %q against a DER that ALREADY held 6000; want 6000 anyway — the reset is what "+
			"makes the value re-commandable, and substituting one is what IW15-004 forbids",
			oracleCommandedParam, got)
	}
	if got := params[oraclePreVerdictParam]; got != string(certify.Fail) {
		t.Fatalf("%s = %q, want FAIL: after the reset the DER holds 50%%, so it does not hold the "+
			"commanded 60%% and the post-read has somewhere to move from", oraclePreVerdictParam, got)
	}
	if n, ok := params[oracleNoteParam]; ok && strings.Contains(n, "ALREADY held") {
		t.Errorf("the row recorded a ladder departure: %q", n)
	}

	// The DUT now fetches and applies the row's own control. The full PostWait
	// path must reach a Pass, and the criterion must rest on the transition.
	applied := model.SignedPerCent{Value: 6000}
	if err := base.ApplyControl(model.DERControlBase{OpModFixedW: &applied}, "lifecycle-test"); err != nil {
		t.Fatalf("ApplyControl(opModFixedW=6000): %v", err)
	}
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("PostWait: %v", err)
	}
	obs := &Observation{Params: params}
	f := wantVerdict(t, "prescribed transition", critDEREffectViaSouthboundOracle(subject, obs), nil,
		certify.Pass)
	if !strings.Contains(f.Observed, "MOVED") {
		t.Errorf("the PASS does not rest on the transition it observed: %q", f.Observed)
	}
	if !strings.Contains(f.Observed, "prescribed") {
		t.Errorf("the PASS does not say the starting state was the procedure's own, which is the whole "+
			"difference between this row and the one the review rejected: %q", f.Observed)
	}
}

// TestPrescribedDefaultShortfall_FailsEvenWhenThePostReadMatches is the teeth on
// the default step. A DUT that never applies the prescribed default leaves the
// row unable to say what the DER was doing beforehand — and a post-read that
// matches is then satisfied just as well by a register nobody moved.
//
// The verdict must be FAIL, not WARN: this is the exact shape the 2026-08-14
// report presented as a PASS, and a WARN would leave it presentable.
func TestPrescribedDefaultShortfall_FailsEvenWhenThePostReadMatches(t *testing.T) {
	obs := &Observation{Params: map[string]string{
		oracleDefaultCommandedParam: "5000",
		oracleDefaultMRIDParam:      "CERT-BASIC-013-DEFAULT",
		oracleDefaultWindowParam:    "2m30s",
		oracleDefaultVerdictParam:   string(certify.Fail),
		oracleDefaultObservedParam:  "the DER reports NO enabled WSet/WSetPct setpoint in its own 704 image",
		// Everything else about the run looks perfect.
		oracleVerdictParam:     string(certify.Pass),
		oracleObservedParam:    "the DER actuated this command as a SETPOINT: its own WSet resolves to 4800.0 W",
		oraclePreVerdictParam:  string(certify.Fail),
		oraclePreObservedParam: "the DER reports NO enabled WSet/WSetPct",
	}}
	f := wantVerdict(t, "prescribed default never landed",
		critDEREffectViaSouthboundOracle("a set-active-power command", obs), nil, certify.Fail)
	for _, want := range []string{"50.00%", "CERT-BASIC-013-DEFAULT", "2m30s"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not name %q, so a reader cannot tell WHICH step of the prescribed "+
				"sequence was not completed: %s", want, f.Observed)
		}
	}
	// The case verdict route carries it too, so a run with no recovered capture
	// still fails.
	s := inverterControlSpec(basic013Mode(), "a set-active-power command", "CERT-BASIC-013")
	if v := s.Verdict(obs); v != certify.Fail {
		t.Fatalf("spec.Verdict with an unestablished prescribed default = %q, want FAIL", v)
	}
	// A row that prescribes nothing is untouched by any of this.
	plain := &Observation{Params: map[string]string{
		oracleVerdictParam:    string(certify.Pass),
		oracleObservedParam:   "the DER's own WMaxLimPct resolves to a 36000.0 W ceiling",
		oraclePreVerdictParam: string(certify.Fail),
	}}
	if _, ok := prescribedDefaultShortfall(plain); ok {
		t.Error("a row with no prescribed default was graded against one")
	}
}

// TestInverterControlSpec_NonOracleRowUnaffected is the behavior-preservation
// check for the far more common shape (every BASIC-004..015 row except
// BASIC-010/013): no Oracle at all, so this fix must not add a PostWait hook
// that did not exist before, and Setup's shape (publish, stash mrid, nothing
// else) is unchanged.
func TestInverterControlSpec_NonOracleRowUnaffected(t *testing.T) {
	dev, _ := oracleFixture(t)
	_, d := inverterControlLifecycleRunCtx(t, dev)
	ctx := context.Background()

	m := scalarMode("opModFixedPFInjectW", func(r *ControlRequest) {
		r.FixedPFInjectW = &figure8FixedPF
	})
	s := inverterControlSpec(m, "a fixed power factor while injecting", "CERT-LIFECYCLE-BASIC008")

	if s.PostWait != nil {
		t.Fatal("a controlMode with no Oracle must not get a PostWait hook at all")
	}
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if params["mrid"] != "CERT-LIFECYCLE-BASIC008" {
		t.Fatalf("Setup did not stash mrid: params = %v", params)
	}
	if len(params) != 1 {
		t.Fatalf("a non-oracle row's Setup should leave params holding only mrid, got %v", params)
	}
}

// TestInverterControlSpec_UnreachableRowDrivesNothing pins the Publish==nil
// shape (the ride-through / ramp-rate rows): no Setup, no PostWait, no Cleanup,
// because there is nothing this bench can put on the wire for them.
//
// Their VERDICT is a different matter and changed with IW15-008: a row that
// drives nothing has tested nothing, and now says so in a decided FAIL — see
// TestUnauthorableRow_IsAFailNotASkip in curve_oracle_test.go. What is pinned
// here is only that such a row still arms no bench lever.
func TestInverterControlSpec_UnreachableRowDrivesNothing(t *testing.T) {
	m := unreachableMode("opModLVRTMustTrip", "no lever on this bench")
	s := inverterControlSpec(m, "the low/high voltage ride-through settings", "CERT-LIFECYCLE-BASIC004")
	if s.Setup != nil {
		t.Fatal("an unreachable mode (Publish == nil) must not get a Setup hook")
	}
	if s.PostWait != nil {
		t.Fatal("an unreachable mode (Publish == nil) must not get a PostWait hook")
	}
	if s.Cleanup != nil {
		t.Fatal("an unreachable mode (Publish == nil) must not get a Cleanup hook")
	}
	if s.RequiresGridSim {
		t.Fatal("an unreachable mode must not claim RequiresGridSim — it has nothing to publish")
	}
}

// TestOracleCriterion_UnavailableIsAFailNotASkip is IW14-003's headline: an
// oracle that could not reach the DER must FAIL the row, not skip past it.
//
// The pre-fix criterion turned oracleUnavailableParam into criterion.Skip, and a
// SKIP is severity 0 (bundle.Verdict.Severity) while every roll-up in the runner
// — Result.rollUp, worstOf, the citation-phase merge — takes only the WORSE of
// what it has. So the single check that can catch a southbound units or
// actuation defect was, by construction, incapable of denting a case verdict:
// point the harness at the wrong sidecar and BASIC-010/013 report a clean PASS
// having certified nothing.
func TestOracleCriterion_UnavailableIsAFailNotASkip(t *testing.T) {
	obs := &Observation{Params: map[string]string{
		oracleUnavailableParam: "no simapi sidecar is configured for modsim",
		oraclePreVerdictParam:  string(certify.Fail),
	}}
	c := critDEREffectViaSouthboundOracle("a maximum active power limit", obs)
	if c.Skip != "" {
		t.Fatalf("an unavailable oracle produced criterion.Skip=%q — a SKIP cannot lower a case verdict, "+
			"so this is a criterion that reports nothing and blocks nothing", c.Skip)
	}
	f := wantVerdict(t, "oracle unavailable", c, nil, certify.Fail)
	if !strings.Contains(f.Observed, "no simapi sidecar is configured for modsim") {
		t.Errorf("the FAIL does not name why the oracle could not read the DER: %q", f.Observed)
	}
	// And the case verdict route carries the same answer, so the row fails even
	// in a run whose capture yielded no session to hang the assertion on.
	s := inverterControlSpec(basic010Mode(), "a maximum active power limit", "CERT-UNAVAIL")
	if v := s.Verdict(obs); v != certify.Fail {
		t.Fatalf("spec.Verdict with an unavailable oracle = %q, want FAIL", v)
	}
}

// TestOracleCriterion_MissingParamsIsAFail closes the latent hole beside it: a
// params map carrying NEITHER a verdict nor a reason produced Finding{Verdict:
// ""} — a "decided" finding with no verdict at all, which mint() would have
// stamped onto an assertion whose verdict string is empty. Nobody could read
// that, and severity 0 meant nobody had to.
func TestOracleCriterion_MissingParamsIsAFail(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params map[string]string
	}{
		{"nothing at all", map[string]string{}},
		{"an empty verdict", map[string]string{oracleVerdictParam: ""}},
		{"only the pre-read", map[string]string{oraclePreVerdictParam: string(certify.Fail)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := critDEREffectViaSouthboundOracle("a maximum active power limit",
				&Observation{Params: tc.params})
			if c.Skip != "" {
				t.Fatalf("criterion.Skip = %q, want a decided criterion", c.Skip)
			}
			f := wantVerdict(t, "oracle params missing", c, nil, certify.Fail)
			if f.Observed == "" {
				t.Fatal("the FAIL carries no observation, so a bundle reader cannot tell what went wrong")
			}
		})
	}
}

// TestInverterControlSpec_StaleRegisterCannotFalsePass is the stale-register
// proof (IW14-003). This bench has no register-clear lever, so a rerun of
// BASIC-010 against a DER still holding the previous run's 60% would once have
// read exactly like a run in which the DUT fetched and applied the control —
// the false PASS the old Cleanup comment described and accepted.
//
// The row now reads the DER BEFORE it publishes. Finding the commanded value
// already there, it commands a ladder alternate the DER provably does not hold,
// so the post-read has something to move TO — and if nothing moves, the row
// FAILs.
func TestInverterControlSpec_StaleRegisterCannotFalsePass(t *testing.T) {
	dev, base := oracleFixture(t)
	// An earlier run of this same row left the DER holding the catalog's own
	// commanded 60.00%. Nothing clears it.
	stale := model.PerCent{Value: 6000}
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &stale}, "previous-run"); err != nil {
		t.Fatalf("ApplyControl(the previous run's opModMaxLimW=6000): %v", err)
	}
	_, d := inverterControlLifecycleRunCtx(t, dev)
	ctx := context.Background()

	m := basic010Mode()
	subject := "a maximum active power limit"
	s := inverterControlSpec(m, subject, "CERT-LIFECYCLE-STALE")

	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if params[oracleCommandedParam] == "6000" {
		t.Fatalf("Setup commanded the catalog's 6000 against a DER that ALREADY held it — the post-read "+
			"would then be satisfied by the DUT doing nothing at all (params = %v)", params)
	}
	alt := params[oracleCommandedParam]
	if alt != "4000" {
		t.Fatalf("Setup commanded %q, want the first ladder entry (4000): the ladder is fixed and ordered "+
			"so a rerun is reproducible, never random", alt)
	}
	if params[oraclePreVerdictParam] != string(certify.Fail) {
		t.Fatalf("the recorded baseline for the value actually commanded = %q, want FAIL — the whole point "+
			"of the alternate is that the DER provably does NOT hold it", params[oraclePreVerdictParam])
	}
	if !strings.Contains(params[oracleNoteParam], "ALREADY held") {
		t.Fatalf("the departure from the catalog's value is not recorded for the bundle: %s = %q",
			oracleNoteParam, params[oracleNoteParam])
	}

	// Leg 1 — the DUT does NOT re-apply anything (the rerun this test is
	// about). The oracle judges the value Setup actually commanded against the
	// stale register and must FAIL. The judge is called directly rather than
	// through PostWait: PostWait would spend the full production settle window
	// (oracleSettleWindow) re-reading a register this leg deliberately never
	// changes, and what is under test here is the verdict, not the poll (which
	// TestSettleOracle_* covers).
	stalePost := m.Oracle.Judge(commandedValue(params, m.Oracle))(ctx, d.rc)
	if stalePost.Verdict != certify.Fail {
		t.Fatalf("the post-read against a DER that never moved = %+v, want FAIL", stalePost)
	}
	staleParams := clonePairs(params, oracleVerdictParam, string(stalePost.Verdict),
		oracleObservedParam, stalePost.Observed)
	staleObs := &Observation{Params: staleParams}
	wantVerdict(t, "stale rerun", critDEREffectViaSouthboundOracle(subject, staleObs), nil, certify.Fail)
	if v := s.Verdict(staleObs); v != certify.Fail {
		t.Fatalf("spec.Verdict on a rerun that never re-applied the control = %q, want FAIL", v)
	}

	// Leg 2 — the DUT fetches and applies the alternate this run commanded.
	// Now the register genuinely MOVED, and the full production PostWait path
	// (settle poll included) must reach a Pass.
	applied := model.PerCent{Value: 4000} // 40.00%, the ladder alternate
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &applied}, "lifecycle-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=4000): %v", err)
	}
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("PostWait: %v", err)
	}
	if params[oracleVerdictParam] != string(certify.Pass) {
		t.Fatalf("after the DUT applied the commanded alternate, %s = %q (%s), want PASS",
			oracleVerdictParam, params[oracleVerdictParam], params[oracleObservedParam])
	}
	obs := &Observation{Params: params}
	f := wantVerdict(t, "moved register", critDEREffectViaSouthboundOracle(subject, obs), nil, certify.Pass)
	if !strings.Contains(f.Observed, "MOVED") {
		t.Errorf("the PASS does not rest on the transition it observed: %q", f.Observed)
	}
	if v := s.Verdict(obs); v != "" {
		t.Errorf("spec.Verdict on a satisfied oracle = %q, want empty", v)
	}
}

// clonePairs copies params and applies the k,v pairs that follow, so a test can
// branch one live-phase params map into two outcomes without either mutating the
// other.
func clonePairs(params map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(params)+len(kv)/2)
	for k, v := range params {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

// TestInverterControlSpec_OracleVerdictReachesTheCaseVerdict pins the route
// IW14-003 added: an oracled row declares its verdict from the LIVE phase
// (spec.Verdict -> certify.Result.Verdict), not only through a criterion the
// citation phase might never reach.
//
// criterion.assert calls a Wire evaluator only when RecoverSession produced a
// Transcript, so before this route existed a decided oracle FAIL in a run whose
// capture yielded no session became a SkipAssertion — and severity 0 cannot
// lower anything. Result.Verdict is the one channel that survives a missing
// capture, and registry.go documents it as stricter-only, so a live FAIL
// declared here can be raised by the citation phase and never lowered by it.
// The runner-side half of that guarantee (rollUp/finalise across a citation
// phase of PASSes) is pinned in internal/certify: see
// TestDeclaredLiveFailSurvivesACitationPhaseOfPasses.
func TestInverterControlSpec_OracleVerdictReachesTheCaseVerdict(t *testing.T) {
	oracled := inverterControlSpec(basic010Mode(), "a maximum active power limit", "CERT-VERDICT")
	if oracled.Verdict == nil {
		t.Fatal("an oracled row declares no live verdict, so its oracle can only speak through a criterion " +
			"the citation phase reaches — the IW14-003 hole")
	}
	// Every non-oracled row is untouched: no live verdict declaration at all.
	plain := inverterControlSpec(scalarMode("opModFixedPFInjectW", func(r *ControlRequest) {
		r.FixedPFInjectW = &figure8FixedPF
	}), "a fixed power factor while injecting", "CERT-VERDICT-PLAIN")
	if plain.Verdict != nil {
		t.Fatal("a non-oracled row declared a live verdict; this route belongs to the oracled rows alone")
	}

	// A run with NO transcript at all: the criterion degrades to a SkipAssertion
	// (that is assert()'s honest, unchanged behaviour when no session was
	// recovered), and the case verdict must carry the FAIL anyway.
	noSession := &Observation{
		NoSession: "no TLS session to the 2030.5 server was recovered from this capture",
		Params: map[string]string{
			oracleVerdictParam:     string(certify.Fail),
			oracleObservedParam:    "the DER's own WMaxLimPct resolves to a 60000.0 W ceiling (commanded 36000.0 W)",
			oraclePreVerdictParam:  string(certify.Fail),
			oraclePreObservedParam: "the DER's own WMaxLimPct resolves to a 60000.0 W ceiling",
		},
	}
	if v := oracled.Verdict(noSession); v != certify.Fail {
		t.Fatalf("spec.Verdict on a decided oracle FAIL with no recovered session = %q, want FAIL: this is "+
			"the only channel left when the citation phase has nothing to assert against", v)
	}
	if certify.Fail.Severity() <= certify.Pass.Severity() {
		t.Fatal("FAIL no longer outranks PASS in bundle.Verdict.Severity — the runner's raise-only roll-ups " +
			"would let a citation phase of PASSes bury this row's declared FAIL")
	}
	// The bundle's own prose carries the reason too, so a FAIL declared live is
	// never an unexplained one.
	notes := oracled.Notes(noSession)
	if !strings.Contains(notes, "independent southbound oracle") {
		t.Errorf("the row's notes do not carry the oracle's finding: %q", notes)
	}
}

// TestOracleOutcome_WarnsWhenTheBaselineIsMissing records the one shape that is
// neither a clean transition nor a provable stall: the post-read matches, but
// the pre-publication read could not be taken, so nothing shows the register
// MOVED. That is not a PASS (the value may have been there all along) and not a
// FAIL (nothing says the DUT misbehaved) — it is the caveat WARN exists for, and
// it is decided, so a reader sees it.
func TestOracleOutcome_WarnsWhenTheBaselineIsMissing(t *testing.T) {
	obs := &Observation{Params: map[string]string{
		oracleVerdictParam:     string(certify.Pass),
		oracleObservedParam:    "the DER's own WMaxLimPct resolves to a 36000.0 W ceiling",
		oraclePreVerdictParam:  "", // the pre-read could not be taken
		oraclePreObservedParam: "the reading could not be taken: modsim's sidecar refused the connection",
	}}
	f := wantVerdict(t, "no baseline", critDEREffectViaSouthboundOracle("a limit", obs), nil, certify.Warn)
	if !strings.Contains(f.Observed, "not established") {
		t.Errorf("the WARN does not say what is unestablished: %q", f.Observed)
	}
	s := inverterControlSpec(basic010Mode(), "a limit", "CERT-NOBASE")
	if v := s.Verdict(obs); v != certify.Warn {
		t.Fatalf("spec.Verdict with no baseline = %q, want WARN carried to the case", v)
	}
}

// TestStartedGradedWindows_OutlastThePollCadence is
// CSIP-ORACLE-BASIC008-STARTED-RESPONSE-TIMING's guard. Every inverterControlSpec
// row grades a Started(2), and the DUT posts Started only for an event it
// fetched WHILE STILL SCHEDULED and then watched go Active. The bench paces the
// DUT at a 1m0s pollRate with a 1m0s discovery floor, so 60s is the longest gap
// between two polls; an event whose start offset does not EXCEED that can be
// fetched already-active (past its start) on an unlucky phase and draw no
// Started — the race that flipped BASIC-008 when BASIC-007's baseline step
// shifted the campaign clock. Both windows the Started-graded rows use must open
// their event strictly after one poll interval so the DUT's next poll always
// finds it Scheduled, regardless of upstream row timing.
func TestStartedGradedWindows_OutlastThePollCadence(t *testing.T) {
	// The single source of truth every Started(2)-graded SCHEDULED control uses.
	if scheduledStartedStartOffsetS <= pollCadenceS {
		t.Errorf("scheduledStartedStartOffsetS is +%ds, not past the %ds poll cadence — a scheduled control "+
			"opened at it can be fetched ALREADY ACTIVE and never post Started(2) "+
			"(CSIP-ORACLE-BASIC008-STARTED-RESPONSE-TIMING)", scheduledStartedStartOffsetS, pollCadenceS)
	}
	// It must also stay UNDER defaultWait, or an oracled row's earliest read can
	// land before its control is active (the pinned oracleWindow invariant).
	if time.Duration(scheduledStartedStartOffsetS)*time.Second >= defaultWait {
		t.Errorf("scheduledStartedStartOffsetS (+%ds) is at/after defaultWait (%s) — an oracled read could "+
			"land before the control is active", scheduledStartedStartOffsetS, defaultWait)
	}
	// The inverterControl windows must carry it (a literal that drifted below the
	// cadence would race).
	for _, w := range []struct {
		name string
		win  scalarControlWindow
	}{
		{"scalarWindow", scalarWindow},
		{"oracleWindow", oracleWindow},
	} {
		if w.win.startOffsetS <= pollCadenceS {
			t.Errorf("%s opens its event at +%ds, not past the %ds poll cadence — the DUT can fetch it "+
				"ALREADY ACTIVE on an unlucky phase and never post Started(2) "+
				"(CSIP-ORACLE-BASIC008-STARTED-RESPONSE-TIMING)", w.name, w.win.startOffsetS, pollCadenceS)
		}
	}
}

// TestAggregatorLifecycleControls_OutlastThePollCadence enumerates the
// aggregator scenarios MECHANICALLY (aggScenarios(), no hardcoded row list) and
// asserts that every control a Lifecycle grades a 1/2/3 sequence for — i.e.
// every Started(2)-graded control — opens past the poll cadence. A superseded or
// non-lifecycle control (e.g. CERT-AGG009SY at +60s) is not graded on Started
// and is deliberately exempt. These rows are the DER-AGGREGATOR-CLIENT profile's
// and do NOT run for this DER-Client candidate, but the invariant keeps them
// from racing if a future profile ever selects that column.
func TestAggregatorLifecycleControls_OutlastThePollCadence(t *testing.T) {
	scenarios := aggScenarios()
	if len(scenarios) == 0 {
		t.Fatal("aggScenarios() is empty — the enumeration would vacuously pass")
	}
	// Documented exceptions (guardrail: a row whose lifecycle arithmetic cannot
	// take the bump without breaking a downstream assertion is left and named,
	// not silently changed). CERT-AGG012SY's +60s start is COUPLED to
	// CERT-AGG012TFA's LateAfterS:75 — AGG-012's whole premise is "the TFA event
	// is created only AFTER the SY event has STARTED" (the independent-mode
	// counterpart of AGG-009), so raising SY past +75 collapses that ordering and
	// the "no status 7" discriminator it sets up. It sits AT the cadence (a
	// boundary, not a clear miss), and AGG-012 is a DER-AGGREGATOR-CLIENT profile
	// row NOT selected for this DER-Client candidate — so it never runs here and
	// the bounded boundary risk cannot be re-verified on the board. Revisit with
	// a coupled LateAfterS bump IF a profile ever selects the aggregator column.
	exceptions := map[string]string{
		"CERT-AGG012SY": "start coupled to CERT-AGG012TFA LateAfterS (AGG-012 'TFA after SY started'); " +
			"aggregator-profile, not selected for the DER-Client candidate",
	}
	checked := 0
	for id, sc := range scenarios {
		byMRID := map[string]aggControl{}
		for _, c := range sc.Controls {
			byMRID[c.MRID] = c
		}
		for _, lc := range sc.Lifecycles {
			c, ok := byMRID[lc.MRID]
			if !ok {
				continue // a Lifecycle may name a control published by a sibling row
			}
			checked++
			if c.StartOffset <= pollCadenceS {
				if reason, ok := exceptions[lc.MRID]; ok {
					t.Logf("%s: DOCUMENTED EXCEPTION — Started-graded control %s at +%ds (<= %ds cadence): %s",
						id, lc.MRID, c.StartOffset, pollCadenceS, reason)
					continue
				}
				t.Errorf("%s: Started-graded control %s opens at +%ds, not past the %ds poll cadence — it "+
					"can be fetched already-active and never post Started(2); if it genuinely cannot take "+
					"the bump, add it to exceptions with a reason", id, lc.MRID, c.StartOffset, pollCadenceS)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no aggregator Lifecycle controls were checked — the enumeration is not reaching them")
	}
}

// recordingControlDriver backs a Driver with a fake admin that records every
// ControlRequest a spec's Setup publishes, so a test can inspect the actual
// StartOffset/Activate the row puts on the wire — mechanical, not a re-declared
// literal.
func recordingControlDriver(t *testing.T) (*Driver, *[]ControlRequest) {
	t.Helper()
	var mu sync.Mutex
	var recorded []ControlRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req ControlRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		recorded = append(recorded, req)
		mu.Unlock()
		mrid := req.MRID
		if mrid == "" {
			mrid = "MINTED-" + req.Description
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mrid": mrid})
	})
	mux.HandleFunc("/admin/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, AdminStatus{Programs: []AdminProgram{{ID: 0, MRID: "P0", Primacy: 1}}, ServerTime: 1})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	d := &Driver{rc: &certify.RunCtx{Case: &certify.Case{UID: "invariant"}}, Admin: certify.NewAdminClient(srv.URL, nil)}
	return d, &recorded
}

// TestStartedGradedCoreSpecs_ScheduleControlsPastTheCadence drives the two core
// Started(2)-graded specs' Setup and inspects the controls they ACTUALLY publish
// (not a re-declared offset): every SCHEDULED control — a future StartOffset the
// DUT must fetch while still Scheduled to witness its start — must open past the
// poll cadence. CORE-022 (coreResponses) publishes only Activate:true /
// StartOffset:0 controls (already active, no Scheduled->Active transition to
// miss), so it is correctly exempt; CORE-023 (coreSuperseding) publishes a
// scheduled winner+loser pair that MUST clear the cadence.
func TestStartedGradedCoreSpecs_ScheduleControlsPastTheCadence(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec spec
	}{
		{"CORE-022 coreResponses", coreResponsesSpec("inv")},
		{"CORE-023 coreSuperseding", coreSupersedingSpec("inv")},
	} {
		d, recorded := recordingControlDriver(t)
		if tc.spec.Setup == nil {
			t.Fatalf("%s has no Setup to drive", tc.name)
		}
		if err := tc.spec.Setup(context.Background(), d, map[string]string{}); err != nil {
			t.Fatalf("%s Setup: %v", tc.name, err)
		}
		if len(*recorded) == 0 {
			t.Fatalf("%s published no control — the inspection is vacuous", tc.name)
		}
		for _, req := range *recorded {
			// A control that is Activate:true, or opens at/before now (StartOffset
			// <= 0), is ALREADY active when fetched — there is no Scheduled->Active
			// transition for the DUT to miss, so it is not subject to the race.
			if req.Activate || req.StartOffset <= 0 {
				continue
			}
			if req.StartOffset <= pollCadenceS {
				t.Errorf("%s: scheduled control %q opens at +%ds, not past the %ds poll cadence — it can be "+
					"fetched already-active and never post Started(2)", tc.name, req.MRID, req.StartOffset,
					pollCadenceS)
			}
		}
	}
}
