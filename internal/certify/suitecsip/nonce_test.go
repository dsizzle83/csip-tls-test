package suitecsip

// nonce_test.go pins the per-run mRID uniqueness fix for CORE-022/CORE-023
// (core.go's coreResponses/coreSuperseding, via coreResponsesSpec and
// coreSupersedingSpec) and the withRunNonce/runNonce helpers (register.go)
// they share with BASIC-017..026's eventScenario.withNonce (basic.go).
//
// The bug class this guards against: lexa-gw's Response tracker dedupes
// Received(1) — and the rest of the DERControl Response lifecycle — on the
// bare mRID string, kept for the process's whole lifetime AND persisted to
// disk. A conformance case that republishes the SAME hardcoded mRID on every
// run earns a fresh Response only on the FIRST run against a long-lived
// bench; every run after that FAILs the assertions that grade the Response
// lifecycle, regardless of what the DUT does that day. The fix mints one
// random per-run token (runNonce) and appends it (withRunNonce) to every
// hardcoded mRID a claim-bearing case publishes, so every run presents mRIDs
// the tracker has never seen — what a real ATL run's genuinely fresh events
// would do, not a defect being papered over. See withRunNonce's doc
// (register.go) and coreResponses'/coreSuperseding's (core.go) for the full
// argument.
//
// What is pinned here, specifically:
//  1. withRunNonce's own contract (identity on "", distinct output for
//     distinct nonces).
//  2. runNonce's uniqueness source: two consecutive mints do not collide.
//  3. That coreResponsesSpec/coreSupersedingSpec — constructed twice, with two
//     different nonces, exactly as two Register() calls or a campaign
//     re-running the same case would — really PUBLISH two different mRIDs (a
//     live round trip through gridsim's admin API, not just string
//     concatenation), and that Setup and Want agree on exactly the mRID(s)
//     that construction posted, not the other one's.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
)

// TestWithRunNonce pins the one-mRID building block eventScenario.withNonce
// and coreResponsesSpec/coreSupersedingSpec all share.
func TestWithRunNonce(t *testing.T) {
	if got := withRunNonce("CERT-CORE022", ""); got != "CERT-CORE022" {
		t.Errorf("an empty nonce must be the identity: got %q", got)
	}
	if got := withRunNonce("CERT-CORE022", "ab12cd34"); got != "CERT-CORE022-ab12cd34" {
		t.Errorf(`withRunNonce("CERT-CORE022", "ab12cd34") = %q, want "CERT-CORE022-ab12cd34"`, got)
	}
	a := withRunNonce("CERT-CORE022", "aaaaaaaa")
	b := withRunNonce("CERT-CORE022", "bbbbbbbb")
	if a == b {
		t.Fatalf("two different nonces applied to the same base produced the SAME mRID: %q", a)
	}
}

// TestRunNonce_ConsecutiveCallsAreDistinct pins the uniqueness SOURCE that
// coreResponses/coreSuperseding and the event-precedence scenarios all share
// (the task's "same uniqueness source" requirement): two nonces minted
// back-to-back — the shape of two Register() calls, or a bench re-running the
// same case twice in one process — must not collide, and must never be empty
// (an empty nonce is withRunNonce's identity case, which would silently
// un-fix this class of bug).
func TestRunNonce_ConsecutiveCallsAreDistinct(t *testing.T) {
	a, b := runNonce(), runNonce()
	if a == "" || b == "" {
		t.Fatalf("runNonce must never return empty: got %q, %q", a, b)
	}
	if a == b {
		t.Fatalf("two consecutive runNonce() calls collided: both %q", a)
	}
}

// gridsimDriver starts an in-process gridsim and wires a Driver to its admin
// API exactly as the real bench's -gridsim-admin flag would, so a test can
// call a spec's Setup/Want directly without booting the whole certify.Check
// machinery — which needs a live capture window (check.go's run(), via
// RunCtx.ClaimEndpointDuring) that a unit test has no way to fake.
func gridsimDriver(t *testing.T) *Driver {
	t.Helper()
	s := gridsim.NewServer(benchLFDI)
	srv := httptest.NewServer(s.AdminHandler())
	t.Cleanup(srv.Close)
	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::CORE-022"},
		GridSim: certify.NewAdminClient(srv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: srv.URL},
	}
	return NewDriver(rc)
}

// TestCoreResponsesSpec_TwoConstructionsPublishDistinctMRIDs is the
// regression lock for CORE-022's half of the fix. Before it, coreResponses
// hardcoded "CERT-CORE022" for every construction — which is exactly the
// shape that let a long-lived bench's Response tracker dedupe every run after
// the first into a FAIL of critResponsePosted (assertion 1), regardless of
// DUT behavior. Two constructions with two different per-run nonces must
// really publish two different mRIDs to gridsim (not merely compute two
// different strings nobody sends), and Setup/Want must agree on exactly the
// one each construction used.
func TestCoreResponsesSpec_TwoConstructionsPublishDistinctMRIDs(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s1 := coreResponsesSpec("nonceaaa1")
	p1 := map[string]string{}
	if err := s1.Setup(ctx, d, p1); err != nil {
		t.Fatalf("first construction's Setup: %v", err)
	}
	if p1["mrid"] != "CERT-CORE022-nonceaaa1" {
		t.Fatalf("first construction published mrid %q, want %q", p1["mrid"], "CERT-CORE022-nonceaaa1")
	}

	s2 := coreResponsesSpec("nonceaaa2")
	p2 := map[string]string{}
	if err := s2.Setup(ctx, d, p2); err != nil {
		t.Fatalf("second construction's Setup: %v", err)
	}
	if p2["mrid"] != "CERT-CORE022-nonceaaa2" {
		t.Fatalf("second construction published mrid %q, want %q", p2["mrid"], "CERT-CORE022-nonceaaa2")
	}

	if p1["mrid"] == p2["mrid"] {
		t.Fatal("two consecutive coreResponsesSpec constructions published the SAME mrid — the whole point of " +
			"the nonce is that they must not")
	}

	// Want must be keyed on the mrid THIS construction just published, not the
	// other one's: a fresh Response for construction 1's own mrid satisfies
	// construction 1's Want...
	want1 := s1.Want(ServerView{})
	if !want1(ServerView{Responses: []AdminResponse{{Subject: p1["mrid"], Status: 1}}}) {
		t.Error("construction 1's Want was not satisfied by a fresh Response for construction 1's own mrid")
	}
	// ...but a Response for the OTHER construction's mrid must not satisfy it —
	// if it did, Setup and Want would have silently drifted onto different
	// mRIDs, which is exactly the class of bug a single shared local variable
	// (see coreResponsesSpec) exists to make impossible.
	if want1(ServerView{Responses: []AdminResponse{{Subject: p2["mrid"], Status: 1}}}) {
		t.Error("construction 1's Want was satisfied by a Response for construction 2's mrid — Setup and Want " +
			"must agree on exactly one mrid per construction")
	}
}

// TestCoreSupersedingSpec_TwoConstructionsPublishDistinctPairs is
// coreResponsesSpec's sibling test for CORE-023, which carries a PAIR of
// hardcoded mRIDs ("CERT-CORE023-WIN"/"CERT-CORE023-LOSE") rather than one.
// Both must move together under the SAME nonce (so the within-run winner/loser
// correlation critResponsePosted/critResponseStarted and the superseded-status
// criterion rely on still holds — see coreSuperseding's doc), while differing
// from a second construction's pair.
func TestCoreSupersedingSpec_TwoConstructionsPublishDistinctPairs(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s1 := coreSupersedingSpec("aone")
	p1 := map[string]string{}
	if err := s1.Setup(ctx, d, p1); err != nil {
		t.Fatalf("first construction's Setup: %v", err)
	}
	wantWinner1, wantLoser1 := "CERT-CORE023-WIN-aone", "CERT-CORE023-LOSE-aone"
	if p1["winner"] != wantWinner1 || p1["loser"] != wantLoser1 {
		t.Fatalf("first construction published winner=%q loser=%q, want %q/%q",
			p1["winner"], p1["loser"], wantWinner1, wantLoser1)
	}

	s2 := coreSupersedingSpec("btwo")
	p2 := map[string]string{}
	if err := s2.Setup(ctx, d, p2); err != nil {
		t.Fatalf("second construction's Setup: %v", err)
	}
	wantWinner2, wantLoser2 := "CERT-CORE023-WIN-btwo", "CERT-CORE023-LOSE-btwo"
	if p2["winner"] != wantWinner2 || p2["loser"] != wantLoser2 {
		t.Fatalf("second construction published winner=%q loser=%q, want %q/%q",
			p2["winner"], p2["loser"], wantWinner2, wantLoser2)
	}

	if p1["winner"] == p2["winner"] || p1["loser"] == p2["loser"] {
		t.Fatal("two consecutive coreSupersedingSpec constructions published the SAME winner/loser mRID(s)")
	}
	if p1["winner"] == p1["loser"] {
		t.Fatal("within one construction, winner and loser must not collide with each other")
	}

	// Want must be keyed on THIS construction's own winner/loser pair, not the
	// other construction's — the same drift guard as coreResponsesSpec above,
	// exercised through coreSupersedingWant's composed (winner AND loser)
	// predicate.
	want1 := s1.Want(ServerView{})
	own := ServerView{Responses: []AdminResponse{
		{Subject: p1["winner"], Status: 1}, {Subject: p1["loser"], Status: 7},
	}}
	if !want1(own) {
		t.Error("construction 1's Want was not satisfied by fresh Responses for construction 1's own winner/loser")
	}
	crossed := ServerView{Responses: []AdminResponse{
		{Subject: p2["winner"], Status: 1}, {Subject: p2["loser"], Status: 7},
	}}
	if want1(crossed) {
		t.Error("construction 1's Want was satisfied by construction 2's winner/loser pair — Setup and Want " +
			"must agree on exactly one mRID pair per construction")
	}
}
