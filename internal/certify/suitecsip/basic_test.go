package suitecsip

// basic_test.go pins eventScenarioSpec's Want fix (2026-08-11, standalone
// BASIC-020: runs/wave11-qa-20260811/rerun-BASIC-020).
//
// Before this fix, basicEventScenario's spec carried no Want at all, so
// run() (check.go) fell through to its AwaitWalk default — a predicate
// satisfied by the FIRST fresh discovery walk, full stop. A walk and the
// Response the DUT posts afterward are two separate round trips, so on a
// bench where the walk itself resolves quickly the observation window (and
// the server-side snapshot critResponsePosted's Server tier reads) could
// close a beat before the Response landed, no matter how generous
// -param csip.wait was — the derived/overridden wait never got to matter
// because Await returned long before spending it. That is what standalone
// BASIC-020 hit: the window closed ~62s in, the same second the DUT's
// status=1 landed, and gridsim's admin API reported no Response POST in the
// window even though the board's own journal proved the DUT ran the full
// [1 2 3] lifecycle moments later.
//
// The fix gives ExpectWinner rows a Want built from WantNewResponse — the
// same idiom coreResponsesSpec uses for CORE-022's own false-early-exit fix
// (nonce_test.go) — so Await keeps polling, for up to the full csip.wait
// window, until the winning control's own Response actually exists.

import (
	"testing"

	"csip-tls-test/internal/certify"
)

// scenarioRunCtx is a minimal RunCtx sufficient for eventScenarioSpec: only
// its Setup closure touches rc (for the case ID in a control's description),
// and none of these tests call Setup.
func scenarioRunCtx() *certify.RunCtx {
	return &certify.RunCtx{Case: &certify.Case{UID: "csip-conf-v1.3::BASIC-020", ID: "BASIC-020"}}
}

// basic020Fixture mirrors the real BASIC-020 row (register.go's
// eventScenarioRows): 2 DERPrograms, 2 DefaultDERControls, 2 non-overlapping
// similar DERControls, service point's control expected to win.
func basic020Fixture() eventScenario {
	return eventScenario{
		Summary:      "2 DERPrograms, 2 DefaultDERControls, 2 non-overlapping similar DERControls",
		ExpectWinner: "CERT-B020A",
		Controls: []scenarioControl{
			{MRID: "CERT-B020A", Program: 0, StartOffset: 30, DurationS: 60, MaxLimW: 4000},
			{MRID: "CERT-B020B", Program: 2, StartOffset: 120, DurationS: 60, MaxLimW: 3000},
		},
	}
}

func TestEventScenarioSpec_WantWaitsForTheWinnersResponseNotMerelyAWalk(t *testing.T) {
	rc := scenarioRunCtx()
	s := eventScenarioSpec(basic020Fixture(), rc)
	if s.Want == nil {
		t.Fatal("eventScenarioSpec with ExpectWinner set carries no Want — falls back to AwaitWalk, the exact " +
			"2026-08-11 standalone BASIC-020 bug")
	}

	want := s.Want(ServerView{})

	// A walk alone — no Response at all — must NOT satisfy it. This is the
	// discriminating case: AwaitWalk (the old behaviour) would have been
	// satisfied here; WantNewResponse must not be.
	if want(ServerView{Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}) {
		t.Error("Want was satisfied by a bare discovery walk with no Response — this is the exact bug: the " +
			"window must stay open until the winner's own Response lands")
	}
	if want(ServerView{}) {
		t.Error("Want was satisfied by an empty view (no new Response at all)")
	}

	// A fresh Response for the WINNING mRID satisfies it — any status counts
	// (status=1/Received is the floor a spec-compliant DUT posts first; the
	// criteria phase, not this predicate, grades WHICH status is required).
	if !want(ServerView{Responses: []AdminResponse{{Subject: "CERT-B020A", Status: 1}}}) {
		t.Error("Want was not satisfied by a fresh status=1 Response for the scenario's own ExpectWinner")
	}

	// A Response for the LOSING control, or for an unrelated mRID, must not
	// satisfy it — Want is keyed on ExpectWinner specifically.
	if want(ServerView{Responses: []AdminResponse{{Subject: "CERT-B020B", Status: 1}}}) {
		t.Error("Want was satisfied by a Response for the scenario's LOSING control, not its ExpectWinner")
	}

	// A Response already present in the BASELINE (a prior run's leftover, or a
	// long-lived gridsim's history) must not satisfy it either — only a
	// Response posted after the baseline the Want closure was built from
	// counts (WantNewResponse's own staleness guard, observe.go).
	baseline := ServerView{Responses: []AdminResponse{{Subject: "CERT-B020A", Status: 1}}}
	staleWant := s.Want(baseline)
	if staleWant(baseline) {
		t.Error("Want was satisfied by a Response already present at baseline time — it must require a NEW one")
	}
}

// TestEventScenarioSpec_NoExpectWinnerKeepsTheAwaitWalkFallback pins the other
// half of the fix: a row with nothing to wait a Response FOR (BASIC-016 — 0
// DERControls, DefaultDERControls only) must keep run()'s ordinary AwaitWalk
// behaviour unchanged, not be forced to wait for a Response that will never
// come.
func TestEventScenarioSpec_NoExpectWinnerKeepsTheAwaitWalkFallback(t *testing.T) {
	rc := scenarioRunCtx()
	sc := eventScenario{Summary: "2 DERPrograms, 2 DefaultDERControls, 0 DERControls"}
	s := eventScenarioSpec(sc, rc)
	if s.Want == nil {
		t.Fatal("eventScenarioSpec must still declare a Want func (returning nil per-run) so specWant can call it")
	}
	if got := s.Want(ServerView{}); got != nil {
		t.Error("a scenario with no ExpectWinner must yield a nil predicate — specWant then routes run() to " +
			"AwaitWalk, exactly as before this fix")
	}
}
