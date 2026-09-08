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
//  4. That both Wants (audit 2026-07-31) require status>=2 (Started) for the
//     mRID(s) they grade the started/completed lifecycle for — CORE-022's
//     mrid and CORE-023's winner — not merely a fresh Response of any status:
//     a status=1 (Received)-only Response must NOT satisfy either. See
//     WantResponseAtLeast's doc (observe.go) for the false-early-exit bug
//     this closes.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/sim/gridsim"
	csipmodel "lexa-proto/csipmodel"
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
//
// Updated 2026-08-01 for the two-phase (completing + server-cancelled
// control) fix: coreResponsesSpec now publishes TWO mRIDs per construction
// (params["mrid"], params["cancelMrid"]), and phase 1's Want now waits for
// status>=3 (Completed), not merely status>=2 (Started) — see
// coreResponsesSpec's Want doc for why.
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
	if p1["cancelMrid"] != "CERT-CORE022-CANCEL-nonceaaa1" {
		t.Fatalf("first construction published cancelMrid %q, want %q",
			p1["cancelMrid"], "CERT-CORE022-CANCEL-nonceaaa1")
	}
	if p1["mrid"] == p1["cancelMrid"] {
		t.Fatal("within one construction, the completing and cancelled controls must not share an mRID")
	}

	s2 := coreResponsesSpec("nonceaaa2")
	p2 := map[string]string{}
	if err := s2.Setup(ctx, d, p2); err != nil {
		t.Fatalf("second construction's Setup: %v", err)
	}
	if p2["mrid"] != "CERT-CORE022-nonceaaa2" {
		t.Fatalf("second construction published mrid %q, want %q", p2["mrid"], "CERT-CORE022-nonceaaa2")
	}
	if p2["cancelMrid"] != "CERT-CORE022-CANCEL-nonceaaa2" {
		t.Fatalf("second construction published cancelMrid %q, want %q",
			p2["cancelMrid"], "CERT-CORE022-CANCEL-nonceaaa2")
	}

	if p1["mrid"] == p2["mrid"] {
		t.Fatal("two consecutive coreResponsesSpec constructions published the SAME mrid — the whole point of " +
			"the nonce is that they must not")
	}
	if p1["cancelMrid"] == p2["cancelMrid"] {
		t.Fatal("two consecutive coreResponsesSpec constructions published the SAME cancelMrid — the whole " +
			"point of the nonce is that they must not")
	}

	// Want must be keyed on the mrid THIS construction just published, not the
	// other one's, AND must wait for status>=3 (Completed) — the full natural
	// 1/2/3 lifecycle, not merely status>=2 (Started) — audit 2026-08-01, see
	// coreResponsesSpec's Want doc. Neither status=1 alone...
	want1 := s1.Want(ServerView{})
	if want1(ServerView{Responses: []AdminResponse{{Subject: p1["mrid"], Status: 1}}}) {
		t.Error("construction 1's Want was satisfied by a status=1 (Received)-only Response — it must wait for " +
			"status>=3 (Completed) before the observation window is allowed to close")
	}
	// ...nor status=2 alone (this is the exact regression the 2026-07-31 fix
	// left behind: it closed the window on status=2, before the interval's
	// own completion had any chance to be observed)...
	if want1(ServerView{Responses: []AdminResponse{{Subject: p1["mrid"], Status: 2}}}) {
		t.Error("construction 1's Want was satisfied by a status<=2 Response — it must wait for status>=3 " +
			"(Completed) before the observation window is allowed to close")
	}
	// ...but a status=3 (Completed) Response for the same mrid does.
	if !want1(ServerView{Responses: []AdminResponse{{Subject: p1["mrid"], Status: 3}}}) {
		t.Error("construction 1's Want was not satisfied by a fresh status=3 Response for construction 1's own mrid")
	}
	// A Response for the OTHER construction's mrid — even status=3 — must not
	// satisfy it either: if it did, Setup and Want would have silently drifted
	// onto different mRIDs, which is exactly the class of bug a single shared
	// local variable (see coreResponsesSpec) exists to make impossible.
	if want1(ServerView{Responses: []AdminResponse{{Subject: p2["mrid"], Status: 3}}}) {
		t.Error("construction 1's Want was satisfied by a Response for construction 2's mrid — Setup and Want " +
			"must agree on exactly one mrid per construction")
	}
	// A status=3 Response for construction 1's OWN cancelMrid must not satisfy
	// phase 1 either: the cancelled control is driven by Change, which must
	// not fire until phase 1 is done, so gating phase 1 on it too would let
	// the two phases race (see the Want doc's "two phases race each other"
	// paragraph).
	if want1(ServerView{Responses: []AdminResponse{{Subject: p1["cancelMrid"], Status: 3}}}) {
		t.Error("construction 1's Want was satisfied by a Response for its OWN cancelMrid — phase 1 must be " +
			"gated on the completing control alone")
	}
}

// TestCoreResponsesSpec_ChangeCancelsTheSecondControlInPlace drives Setup then
// Change against a REAL in-process gridsim (not a fabricated ServerView) and
// confirms Change performs the exact two-step update-in-place server-cancel
// sim/gridsim/admin.go documents (see also
// TestAdminControl_ExplicitMRIDUpdatesInPlace in
// sim/gridsim/admin_ctrl_test.go, which pins the seam itself and — like this
// test — reads it back through the SCHEDULED list, /derp/N/derc, not the
// active-list mirror: an admin control POST that names an explicit mRID
// upserts /derc unconditionally, but only mirrors into /actderc when that
// mRID was ALREADY present there, so a brand-new admin-created control never
// appears in the active-list mirror at all — a pre-existing gridsim quirk
// this test works around rather than one this fix needs to touch. The DUT
// itself is unaffected: it discovers and schedules events from
// DERControlListLink (/derc), never from the active-list mirror): ONE
// control, same mRID, whose EventStatus.currentStatus flips to 6 (Cancelled)
// — not a second control added alongside the first, which would leave the
// DUT one live (uncancelled) event plus one it never got a chance to receive
// before it was already cancelled ("the hub drops events that arrive
// already-cancelled" — admin.go's adminCtrlReq doc).
func TestCoreResponsesSpec_ChangeCancelsTheSecondControlInPlace(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s := coreResponsesSpec("cancelseam1")
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if s.Change == nil {
		t.Fatal("coreResponsesSpec no longer declares a Change hook")
	}

	// Before Change: the cancelled-to-be control is freshly posted and
	// scheduled, not yet cancelled.
	before := d.Snapshot(ctx)
	prog := findProgram(t, before, 1)
	ctrl := findControl(t, prog.Scheduled, params["cancelMrid"])
	if (csipmodel.EventStatus{CurrentStatus: uint8(ctrl.Status)}).IsTerminal() {
		t.Fatalf("setup: the second control already reports a terminal status (%d) before Change ran", ctrl.Status)
	}

	if err := s.Change(ctx, d, params); err != nil {
		t.Fatalf("Change: %v", err)
	}

	after := d.Snapshot(ctx)
	prog = findProgram(t, after, 1)

	// Exactly one entry for cancelMrid — an in-place flip, not an added
	// second control.
	var matches int
	for _, c := range prog.Scheduled {
		if c.MRID == params["cancelMrid"] {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("after Change, program 1's scheduled list carries %d entries for %s, want exactly 1 (an "+
			"in-place update, not an added control)", matches, params["cancelMrid"])
	}
	ctrl = findControl(t, prog.Scheduled, params["cancelMrid"])
	// REV0907-B1: gridsim's "cancel" lever must serve currentStatus=2
	// (Cancelled — IEEE Std 2030.5-2018 Annex B, p.159-160), NOT 6 — Table
	// 27's Response status for "event cancelled", transposed into the wrong
	// enumeration. This is the referee's OWN defect this task closes: before
	// the fix, CORE-022's Change sent CurrentStatus=6, gridsim served it
	// verbatim, and this test (like the product) treated 6 as if it meant
	// Cancelled. A run that regresses Change back to the raw 6 override
	// fails BOTH assertions below.
	if ctrl.Status != int(csipmodel.EventStatusCancelled) {
		t.Fatalf("after Change, the second control's currentStatus = %d, want %d (Cancelled)",
			ctrl.Status, csipmodel.EventStatusCancelled)
	}
	if ctrl.Status == 6 {
		t.Fatalf("after Change, the second control's currentStatus = 6 — REV0907-B1: 6 is Table 27's " +
			"Response status for \"event cancelled\", not a currentStatus value; IEEE Std 2030.5-2018 Annex B " +
			"reserves it, so a spec-correct DUT must NOT treat this control as cancelled")
	}
	if !(csipmodel.EventStatus{CurrentStatus: uint8(ctrl.Status)}).IsCancelled() {
		t.Fatalf("after Change, csipmodel.EventStatus{CurrentStatus: %d}.IsCancelled() = false, want true — "+
			"the served value must be one the shared model actually recognises as Cancelled", ctrl.Status)
	}

	// The FIRST (completing) control must be untouched by Change: it lives on
	// a different program and Change only ever names cancelMrid.
	progA := findProgram(t, after, 0)
	ctrlA := findControl(t, progA.Scheduled, params["mrid"])
	if (csipmodel.EventStatus{CurrentStatus: uint8(ctrlA.Status)}).IsCancelled() {
		t.Fatalf("Change cancelled the WRONG control: the completing control (%s, program 0) now reports "+
			"currentStatus=%d, which IsCancelled() too", params["mrid"], ctrlA.Status)
	}
}

// TestCoreResponsesSpec_ChangeDoesNotServeTheLegacyMistakenSix is
// REV0907-B1's direct mutation-verify lock: it pins that coreResponsesSpec's
// Change hook drives gridsim's NAMED "cancel" lever (Cancel: true) rather
// than the raw CurrentStatus override, by checking the ONE observable fact
// that distinguishes them — the value gridsim ends up serving. Reverting
// core.go's Change to `CurrentStatus: ptr(uint8(6))` (the pre-fix code) makes
// this test fail with a message naming the mechanism (see the task's
// mutation-check evidence).
func TestCoreResponsesSpec_ChangeDoesNotServeTheLegacyMistakenSix(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s := coreResponsesSpec("cancelseam2")
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := s.Change(ctx, d, params); err != nil {
		t.Fatalf("Change: %v", err)
	}

	after := d.Snapshot(ctx)
	ctrl := findControl(t, findProgram(t, after, 1).Scheduled, params["cancelMrid"])
	if ctrl.Status == 6 {
		t.Fatalf("CORE-022's Change served currentStatus=6 — the exact REV0907-B1 defect (Table 27's "+
			"Response status transposed into currentStatus): want %d (Cancelled)", csipmodel.EventStatusCancelled)
	}
	if ctrl.Status != int(csipmodel.EventStatusCancelled) {
		t.Fatalf("CORE-022's Change served currentStatus=%d, want %d (Cancelled)",
			ctrl.Status, csipmodel.EventStatusCancelled)
	}
}

func findProgram(t *testing.T, v ServerView, id int) AdminProgram {
	t.Helper()
	for _, p := range v.Status.Programs {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("no program with id=%d in gridsim's admin status", id)
	return AdminProgram{}
}

func findControl(t *testing.T, ctrls []AdminControl, mrid string) AdminControl {
	t.Helper()
	for _, c := range ctrls {
		if c.MRID == mrid {
			return c
		}
	}
	t.Fatalf("no control with mrid=%s in the given list", mrid)
	return AdminControl{}
}

// TestCoreResponsesSpec_CompositeLifecycleCriterion exercises assertion 4's
// grading directly — the composite "1/2/3 for the completing control, 6 for
// the server-cancelled one" claim this whole fix exists to make affirmatively
// gradable (it could only ever WARN before: see the Server evaluator's
// pre-fix version, which had no cancel phase and no way to observe 6 at all).
// It must PASS once every phase landed, WARN naming the precise gap when only
// some of it did, and FAIL only when NEITHER control earned any Response at
// all (with a session established) — never a false FAIL for a partial
// capture, which is a window-timing fact, not necessarily a DUT one.
func TestCoreResponsesSpec_CompositeLifecycleCriterion(t *testing.T) {
	s := coreResponsesSpec("gradingnonce")
	mrid, cancelMrid := "CERT-CORE022-gradingnonce", "CERT-CORE022-CANCEL-gradingnonce"

	find := func(o *Observation) criterion {
		for _, c := range s.Criteria(o) {
			if strings.Contains(c.Claim, "server cancels") {
				return c
			}
		}
		t.Fatal("coreResponsesSpec's Criteria no longer carries the event-lifecycle composite criterion")
		return criterion{}
	}

	// Full lifecycle observed on both controls: PASS.
	full := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: mrid, Status: 1}, {Subject: mrid, Status: 2}, {Subject: mrid, Status: 3},
		{Subject: cancelMrid, Status: 1}, {Subject: cancelMrid, Status: 2}, {Subject: cancelMrid, Status: 6},
	}}
	if f := find(&Observation{Server: *full}).Server(full); f.Verdict != certify.Pass {
		t.Errorf("full 1/2/3 + 6 lifecycle = %s, want Pass: %s", f.Verdict, f.Observed)
	}

	// The cancelled control needs only 6 itself, not its own preceding 1/2 —
	// the claim is "for an event the server cancels", and a DUT may cancel an
	// event it never explicitly acknowledged Started for.
	cancelOnlySix := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: mrid, Status: 1}, {Subject: mrid, Status: 2}, {Subject: mrid, Status: 3},
		{Subject: cancelMrid, Status: 6},
	}}
	if f := find(&Observation{Server: *cancelOnlySix}).Server(cancelOnlySix); f.Verdict != certify.Pass {
		t.Errorf("cancelled control with only status=6 (no preceding 1/2) = %s, want Pass: %s", f.Verdict, f.Observed)
	}

	// Partial capture — exactly the pre-fix WARN shape (1, 2 only, no 3, no
	// cancel phase reached at all) — must still WARN, precisely, never FAIL.
	partial := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: mrid, Status: 1}, {Subject: mrid, Status: 2},
	}}
	f := find(&Observation{Server: *partial}).Server(partial)
	if f.Verdict != certify.Warn {
		t.Fatalf("partial capture (1, 2 only) = %s, want Warn: %s", f.Verdict, f.Observed)
	}
	for _, want := range []string{"3 (completed)", "6 (cancelled)"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("Warn observed text %q does not name the missing %s", f.Observed, want)
		}
	}

	// Total silence WITH a session established: a real FAIL, unchanged from
	// before this fix.
	silent := &ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}
	if f := find(&Observation{Server: *silent}).Server(silent); f.Verdict != certify.Fail {
		t.Errorf("session established, zero Responses for either control = %s, want Fail: %s", f.Verdict, f.Observed)
	}

	// No session at all: unavailable, not a FAIL.
	empty := &ServerView{Available: true}
	if f := find(&Observation{Server: *empty}).Server(empty); f.Unavailable == "" {
		t.Errorf("no session at all returned a verdict (%s) instead of unavailable", f.Verdict)
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
	// predicate. The winner half also needs status>=2 (Started), not merely a
	// fresh Response (audit 2026-07-31, same class of bug as CORE-022's fix —
	// see coreSupersedingWant's doc); the loser stays satisfied by any fresh
	// Response, per its own criteria (status 7/14, never status>=2).
	want1 := s1.Want(ServerView{})
	winnerStatus1Only := ServerView{Responses: []AdminResponse{
		{Subject: p1["winner"], Status: 1}, {Subject: p1["loser"], Status: 7},
	}}
	if want1(winnerStatus1Only) {
		t.Error("construction 1's Want was satisfied by the winner's status=1 (Received) alone — it must wait " +
			"for the winner's status>=2 (Started) before the observation window is allowed to close")
	}
	own := ServerView{Responses: []AdminResponse{
		{Subject: p1["winner"], Status: 2}, {Subject: p1["loser"], Status: 7},
	}}
	if !want1(own) {
		t.Error("construction 1's Want was not satisfied by a fresh status=2 winner Response and a fresh loser " +
			"Response, both for construction 1's own pair")
	}
	crossed := ServerView{Responses: []AdminResponse{
		{Subject: p2["winner"], Status: 2}, {Subject: p2["loser"], Status: 7},
	}}
	if want1(crossed) {
		t.Error("construction 1's Want was satisfied by construction 2's winner/loser pair — Setup and Want " +
			"must agree on exactly one mRID pair per construction")
	}
}

// TestCoreResponsesSpec_ReplyToCriterionGradesControlASpecifically is the
// regression lock for the OTHER half of the 2026-08-01 audit (see
// core.go's replyTo criterion, in coreResponsesSpec's Criteria): before the
// fix, the Wire evaluator graded whichever Response POST it found FIRST in
// capture order, of ANY subject — harmless with CORE-022's old single-control
// shape, but with two live controls (the completing control, mrid, and the
// server-cancelled one, cancelMrid) it could cite the WRONG control's
// exchange for a claim that is specifically about the control under test.
//
// The reproduction: cancelMrid's Response is the one that lands FIRST in
// capture order and its own DERControl was never recovered in this window (a
// realistic shape — a control on a different program, GETed on a different
// poll cycle than the one this synthetic window happens to cover), while
// mrid's DERControl WAS recovered, correctly carrying replyTo, and mrid's own
// Response correctly targets it. An evaluator that does not filter by
// subject grades cancelMrid's exchange and reports WARN ("...was not
// recovered in this window") — exactly the shape audit 2026-08-01 saw in
// runs/tail-core022-20260801T202520 (there for an unrelated reason — a
// gridsim bug that stripped mrid's OWN replyTo — but the missing subject
// filter here is a second, independent gap this fix also closes). A
// correctly-filtered evaluator skips cancelMrid's POST and grades mrid's own,
// which resolves cleanly to Pass.
func TestCoreResponsesSpec_ReplyToCriterionGradesControlASpecifically(t *testing.T) {
	s := coreResponsesSpec("replytonc")
	mrid, cancelMrid := "CERT-CORE022-replytonc", "CERT-CORE022-CANCEL-replytonc"

	find := func(o *Observation) criterion {
		for _, c := range s.Criteria(o) {
			if strings.Contains(c.Claim, "replyTo URI") {
				return c
			}
		}
		t.Fatal("coreResponsesSpec's Criteria no longer carries the replyTo criterion")
		return criterion{}
	}

	respBody := func(status int, subject string) string {
		return `<DERControlResponse xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1</createdDateTime>` +
			`<endDeviceLFDI>ab</endDeviceLFDI><status>` + itoa(int64(status)) + `</status>` +
			`<subject>` + subject + `</subject></DERControlResponse>`
	}
	post := func(path string, status int, subject string) Exchange {
		return Exchange{Req: msg(Request, "POST", path, 0, respBody(status, subject)),
			Resp: msg(Response, "", "", 201, "")}
	}
	derc := func(path, ctrlMRID, replyTo string) string {
		return `<?xml version="1.0" encoding="UTF-8"?>` +
			`<DERControlList xmlns="urn:ieee:std:2030.5:ns" href="` + path + `" all="1" results="1">` +
			`<DERControl href="` + path + `/` + ctrlMRID + `" replyTo="` + replyTo + `">` +
			`<mRID>` + ctrlMRID + `</mRID><description>t</description><creationTime>1</creationTime>` +
			`<EventStatus><currentStatus>1</currentStatus><dateTime>1</dateTime></EventStatus>` +
			`<interval><duration>120</duration><start>1</start></interval>` +
			`<DERControlBase></DERControlBase></DERControl></DERControlList>`
	}

	// Capture order: cancelMrid's Response POST first (its own DERControl is
	// NOT in this transcript at all — "not recovered"), then mrid's
	// DERControl GET (correctly carrying replyTo) and mrid's own Response,
	// correctly targeted at it.
	tr := synthTranscript(
		post("/rsps/1/r", 1, cancelMrid),
		get("/derp/0/derc", 200, derc("/derp/0/derc", mrid, "/rsps/0/r")),
		post("/rsps/0/r", 1, mrid),
	)

	f := wantVerdict(t, "replyTo grades control A, not the cancelled control", find(&Observation{}), tr,
		certify.Pass)
	if !strings.Contains(f.Observed, mrid) {
		t.Errorf("replyTo criterion's Observed text does not cite control A's own subject %s: %q", mrid, f.Observed)
	}
	if strings.Contains(f.Observed, cancelMrid) {
		t.Errorf("replyTo criterion cited the OTHER (cancelled) control %s instead of control A: %q",
			cancelMrid, f.Observed)
	}
}

// TestCoreResponsesSpec_FullLifecycleAssertionsGradeCorrectly is the
// end-to-end reproduction the 2026-08-01 audit was for: CORE-022's exact
// two-phase shape (control A completes 1/2/3 on program 0, control B is
// cancelled to 6 mid-flight on program 1) driven against a REAL in-process
// gridsim, with program 0 deliberately left curve-bound BEFORE Setup runs —
// the precondition runs/tail-core022-20260801T202520 was captured under
// (some earlier bench activity had bound a curve to program 0 and never
// cleared it) — to prove the whole pipeline is robust to it now, not merely
// that toExtendedControl in isolation is.
//
// The DERControlList bodies are the REAL bytes gridsim serves (fetched
// through s.Handler(), the same handler the DUT talks to), not hand-typed
// fixtures — so a regression in gridsim's own XML rendering would fail this
// test even if every unit-level one above still passed. Only the DUT's
// Response POSTs are synthetic: there is no real DUT in this process, and
// every other Wire-tier test in this package synthesizes them the same way.
//
// Assertions 1/2/3 must PASS, all three against control A specifically, and
// assertion 4 (the composite completion+cancel criterion) must PASS spanning
// both controls — the state this row regressed FROM (3/4 PASS, pre-rework)
// plus the coverage the rework ADDED, together, which is the whole point of
// the fix.
func TestCoreResponsesSpec_FullLifecycleAssertionsGradeCorrectly(t *testing.T) {
	s := gridsim.NewServer(benchLFDI)
	adminSrv := httptest.NewServer(s.AdminHandler())
	t.Cleanup(adminSrv.Close)
	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::CORE-022"},
		GridSim: certify.NewAdminClient(adminSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: adminSrv.URL},
	}
	d := NewDriver(rc)
	ctx := context.Background()

	// The precondition: program 0 curve-bound before this check ever runs,
	// exactly as a long-lived bench can leave it from unrelated earlier
	// activity (curve.go's admin curve endpoint, sim/gridsim).
	curveBody := `{"program":0,"mode":"volt_var","points":[{"x":1,"y":2}],"activate":true}`
	curveRec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(curveRec, httptest.NewRequest("POST", "/admin/curve", strings.NewReader(curveBody)))
	if curveRec.Code != http.StatusCreated {
		t.Fatalf("setup: POST /admin/curve = %d; body: %s", curveRec.Code, curveRec.Body)
	}

	spec := coreResponsesSpec("e2enonce")
	params := map[string]string{}
	if err := spec.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := spec.Change(ctx, d, params); err != nil {
		t.Fatalf("Change: %v", err)
	}
	mrid, cancelMrid := params["mrid"], params["cancelMrid"]

	// fetchDerc reads the REAL served DERControlList for path (through the
	// DUT-facing handler, not the admin one) and returns both its raw body
	// (for the GET exchange) and the replyTo it recovered for ctrlMRID (so
	// the synthetic Response POSTs below target wherever gridsim ACTUALLY
	// told the DUT to reply, rather than an assumed constant).
	fetchDerc := func(path, ctrlMRID string) (body, replyTo string) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d; body: %s", path, rec.Code, rec.Body)
		}
		body = rec.Body.String()
		doc, err := msg(Response, "", "", 200, body).SEP()
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, c := range doc.Children("DERControl") {
			if m, _ := c.TextOf("mRID"); m != ctrlMRID {
				continue
			}
			rt, ok := c.Attr("replyTo")
			if !ok {
				t.Fatalf("%s: DERControl %s carries no replyTo attribute at all (the exact bug this test "+
					"guards against)", path, ctrlMRID)
			}
			replyTo = rt
		}
		if replyTo == "" {
			t.Fatalf("%s: DERControl %s not found or carries an empty replyTo", path, ctrlMRID)
		}
		return body, replyTo
	}
	dercA, replyToA := fetchDerc("/derp/0/derc", mrid)
	dercB, replyToB := fetchDerc("/derp/1/derc", cancelMrid)

	respPost := func(replyTo string, status int, subject string) Exchange {
		body := `<DERControlResponse xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1</createdDateTime>` +
			`<endDeviceLFDI>ab</endDeviceLFDI><status>` + itoa(int64(status)) + `</status>` +
			`<subject>` + subject + `</subject></DERControlResponse>`
		return Exchange{Req: msg(Request, "POST", replyTo, 0, body), Resp: msg(Response, "", "", 201, "")}
	}

	tr := synthTranscript(
		get("/derp/0/derc", 200, dercA),
		get("/derp/1/derc", 200, dercB),
		respPost(replyToA, 1, mrid),
		respPost(replyToA, 2, mrid),
		respPost(replyToA, 3, mrid),
		respPost(replyToB, 1, cancelMrid),
		respPost(replyToB, 2, cancelMrid),
		respPost(replyToB, 6, cancelMrid),
	)

	crits := spec.Criteria(&Observation{})
	if len(crits) != 4 {
		t.Fatalf("coreResponsesSpec's Criteria returned %d criteria, want 4", len(crits))
	}
	names := []string{"1 (Received)", "2 (Started)", "3 (replyTo)", "4 (composite lifecycle)"}
	for i := 0; i < 3; i++ {
		if f := crits[i].Wire(nil, tr); f.Verdict != certify.Pass {
			t.Errorf("assertion %s = %s, want Pass: %s (unavailable: %s)",
				names[i], f.Verdict, f.Observed, f.Unavailable)
		}
	}

	view := &ServerView{Available: true, Responses: []AdminResponse{
		{Subject: mrid, Status: 1}, {Subject: mrid, Status: 2}, {Subject: mrid, Status: 3},
		{Subject: cancelMrid, Status: 1}, {Subject: cancelMrid, Status: 2}, {Subject: cancelMrid, Status: 6},
	}}
	if f := crits[3].Server(view); f.Verdict != certify.Pass {
		t.Errorf("assertion %s = %s, want Pass: %s", names[3], f.Verdict, f.Observed)
	}
}

// TestAggregatorRowsPublishNoncedMRIDs is the aggregator half of the same
// isolation fix, and the precondition criteria_agg.go's lifecycleReach now
// relies on instead of a cross-campaign log lookup (F3/F4, 2026-08-14).
//
// Every row registerAggregator binds goes through aggRows, and every mRID it
// carries — the controls it publishes and the four kinds of criterion that name
// one back — must carry this run's token. Two properties matter and both are
// asserted here, because either alone is useless:
//
//	(1) the mRIDs really are fresh per run, so gridsim's append-only Response
//	    log cannot already hold an acknowledgment for one and the lifecycle
//	    criterion's FAIL stays reachable for a DUT that has regressed;
//	(2) within ONE run the cross-references still point at that row's own
//	    controls, so the supersession, independence and per-device criteria are
//	    still about the events the row published rather than about nothing.
func TestAggregatorRowsPublishNoncedMRIDs(t *testing.T) {
	const nonceA, nonceB = "aggnonce1", "aggnonce2"

	// The table itself stays static — an empty nonce is the identity, which is
	// what every scenario-table test reads.
	if got := aggScenarios()["AGG-011"].Lifecycles[0].MRID; got != "CERT-AGG011TFA" {
		t.Fatalf("the scenario table's own mRID = %q, want the static CERT-AGG011TFA: the nonce belongs to "+
			"registration, not to the transcription of the document", got)
	}

	owner := map[string]string{} // mRID -> the row that published it
	for _, r := range aggRows(nonceA) {
		controls := map[string]bool{}
		for _, c := range r.sc.Controls {
			if !strings.HasSuffix(c.MRID, "-"+nonceA) {
				t.Errorf("%s publishes control %q with no run nonce — a re-run would re-publish an mRID the "+
					"DUT has already run to terminal, and its lifecycle criterion could no longer tell a DUT "+
					"that never acknowledged the event from one that acknowledged it last campaign", r.id, c.MRID)
			}
			if prev, dup := owner[c.MRID]; dup {
				t.Errorf("%s and %s both publish %q — one run's rows must not collide with each other either",
					prev, r.id, c.MRID)
			}
			owner[c.MRID] = r.id
			controls[c.MRID] = true
		}
		for _, l := range r.sc.Lifecycles {
			checkAggRef(t, r.id, "lifecycle", l.MRID, nonceA, controls)
		}
		checkAggRef(t, r.id, "supersession", r.sc.Superseded, nonceA, controls)
		for _, m := range r.sc.Independent {
			checkAggRef(t, r.id, "independence", m, nonceA, controls)
		}
		for _, f := range r.sc.FanOut {
			checkAggRef(t, r.id, "fan-out", f.MRID, nonceA, controls)
			if f.Unobservable != "" && f.MRID != "" {
				t.Errorf("%s: a fan-out bullet with no wire artefact names mRID %q", r.id, f.MRID)
			}
		}
	}

	// Two constructions — two campaigns, or the same campaign re-run — must
	// share no mRID at all.
	second := map[string]bool{}
	for _, r := range aggRows(nonceB) {
		for _, c := range r.sc.Controls {
			second[c.MRID] = true
		}
	}
	for mrid, id := range owner {
		if second[mrid] {
			t.Errorf("%s published %q under BOTH nonces — the whole point of the token is that two runs "+
				"present mRIDs the DUT's Response tracker has never seen", id, mrid)
		}
	}
	if len(second) != len(owner) || len(owner) == 0 {
		t.Fatalf("the two constructions published %d and %d controls; they must publish the same (non-zero) "+
			"set of rows", len(owner), len(second))
	}
}

// checkAggRef asserts one criterion's back-reference: it carries the run's
// token and names a control THIS row published. An empty reference is a row
// that makes no such claim (a scenario with no supersession, a fan-out bullet
// about a setpoint) and must stay empty rather than becoming "-<nonce>".
func checkAggRef(t *testing.T, id, kind, mrid, nonce string, controls map[string]bool) {
	t.Helper()
	if mrid == "" {
		return
	}
	if !strings.HasSuffix(mrid, "-"+nonce) {
		t.Errorf("%s's %s criterion names %q, which carries no run nonce: it would grade the Responses of an "+
			"event this run never published", id, kind, mrid)
		return
	}
	if !controls[mrid] {
		t.Errorf("%s's %s criterion names %q, which is not one of the controls this row publishes — the "+
			"within-run correlation the nonce must preserve is broken", id, kind, mrid)
	}
}

// TestUtilDERRetrievalSpecPublishesItsOwnNoncedMRID is UTIL-004's half: the one
// aggregator row outside the scenario table, with the same static-mRID history
// and the same lifecycle criterion reading it. Driven through a REAL in-process
// gridsim, because "Setup computed a string" and "Setup published that control"
// are different claims and only the second one matters.
func TestUtilDERRetrievalSpecPublishesItsOwnNoncedMRID(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s1 := utilDERRetrievalSpec(withRunNonce("CERT-UTIL004", "utilnonce1"))
	p1 := map[string]string{}
	if err := s1.Setup(ctx, d, p1); err != nil {
		t.Fatalf("first construction's Setup: %v", err)
	}
	if p1["mrid"] != "CERT-UTIL004-utilnonce1" {
		t.Fatalf("UTIL-004 published mrid %q, want %q", p1["mrid"], "CERT-UTIL004-utilnonce1")
	}

	s2 := utilDERRetrievalSpec(withRunNonce("CERT-UTIL004", "utilnonce2"))
	p2 := map[string]string{}
	if err := s2.Setup(ctx, d, p2); err != nil {
		t.Fatalf("second construction's Setup: %v", err)
	}
	if p1["mrid"] == p2["mrid"] {
		t.Fatal("two UTIL-004 constructions published the SAME mrid — the second campaign would re-publish " +
			"an event the DUT had already acknowledged, which is what left its lifecycle criterion unable " +
			"to convict a regressed DUT")
	}

	// Setup and Want must agree on this construction's own mRID, not the other's.
	want1 := s1.Want(ServerView{})
	if !want1(ServerView{Responses: []AdminResponse{{Subject: p1["mrid"], Status: 1}}}) {
		t.Error("UTIL-004's Want was not satisfied by a fresh Response for the mrid its own Setup published")
	}
	if want1(ServerView{Responses: []AdminResponse{{Subject: p2["mrid"], Status: 1}}}) {
		t.Error("UTIL-004's Want was satisfied by a Response for the OTHER construction's mrid")
	}
}

// gridsimDriverWithAdmin is gridsimDriver plus the admin base URL, so a test
// can read back the tree gridsim actually serves rather than only the mRIDs the
// Driver reports.
func gridsimDriverWithAdmin(t *testing.T) (*Driver, string) {
	t.Helper()
	s := gridsim.NewServer(benchLFDI)
	srv := httptest.NewServer(s.AdminHandler())
	t.Cleanup(srv.Close)
	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::CORE-022"},
		GridSim: certify.NewAdminClient(srv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: srv.URL},
	}
	return NewDriver(rc), srv.URL
}

// adminScheduled reads one program's SCHEDULED control list back out of
// gridsim, keyed by mRID.
func adminScheduled(t *testing.T, adminURL string, program int) map[string]struct {
	MRID      string `json:"mrid"`
	Start     int64  `json:"start"`
	DurationS int    `json:"duration_s"`
	Status    int    `json:"status"`
	Base      struct {
		MaxLimW *int64 `json:"max_lim_W"`
		GenLimW *int64 `json:"gen_lim_W"`
		ExpLimW *int64 `json:"exp_lim_W"`
		FixedW  *int64 `json:"fixed_W"`
	} `json:"base"`
} {
	t.Helper()
	type ctrl = struct {
		MRID      string `json:"mrid"`
		Start     int64  `json:"start"`
		DurationS int    `json:"duration_s"`
		Status    int    `json:"status"`
		Base      struct {
			MaxLimW *int64 `json:"max_lim_W"`
			GenLimW *int64 `json:"gen_lim_W"`
			ExpLimW *int64 `json:"exp_lim_W"`
			FixedW  *int64 `json:"fixed_W"`
		} `json:"base"`
	}
	resp, err := http.Get(adminURL + "/admin/status")
	if err != nil {
		t.Fatalf("GET /admin/status: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Programs []struct {
			ID        int    `json:"id"`
			Scheduled []ctrl `json:"scheduled"`
		} `json:"programs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode /admin/status: %v", err)
	}
	out := map[string]ctrl{}
	for _, p := range got.Programs {
		if p.ID != program {
			continue
		}
		for _, c := range p.Scheduled {
			out[c.MRID] = c
		}
	}
	return out
}

// TestCoreResponsesSpec_CancelTargetIsAxisIndependent is CORE-022's
// server-cancel fixture lock, and it exists because the fixture — not the DUT —
// was what made status 6 unobservable on the 2026-08-19 bench
// (runs/verify-796fbc3-20260819T203800Z, both runs: the cancel target was
// answered [1 14] and never 6, identically, at an 8-minute wait budget).
//
// The cancel target used to command opModMaxLimW, the same axis as the
// completing control, over an interval that spans it. IEEE Std 2030.5-2018
// §10.2.3.3 d) forbids a client from executing both, n) hands the axis to the
// higher-primacy program (gridsim: program 0 primacy 1 beats program 1 primacy
// 5 — rule f)'s creationTime tiebreak never gets a turn), and Table 27 rows
// 7/14 are what the loser is owed. The event was therefore terminally reported
// ceased on the walk it arrived, and the cancellation the check served
// afterwards had nothing live left to cancel: §10.2.3.3 i) keeps a superseded
// event superseded.
//
// §10.2.3.3 t) is the rule that makes the row answerable — "differing controls
// … within DERControl Events are independent and are allowed to overlap or nest
// without superseding" — so the two controls must command DIFFERENT axes. That
// is what this test pins, at the only place it can be checked without a DUT:
// the documents gridsim actually serves.
func TestCoreResponsesSpec_CancelTargetIsAxisIndependent(t *testing.T) {
	d, adminURL := gridsimDriverWithAdmin(t)
	ctx := context.Background()

	s := coreResponsesSpec("axisnonce")
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	completing := adminScheduled(t, adminURL, 0)[params["mrid"]]
	cancelling := adminScheduled(t, adminURL, 1)[params["cancelMrid"]]
	if completing.MRID == "" {
		t.Fatalf("completing control %q was not served on program 0", params["mrid"])
	}
	if cancelling.MRID == "" {
		t.Fatalf("cancel target %q was not served on program 1", params["cancelMrid"])
	}

	if completing.Base.MaxLimW == nil {
		t.Errorf("completing control commands no opModMaxLimW: base = %+v", completing.Base)
	}
	if cancelling.Base.GenLimW == nil {
		t.Errorf("cancel target commands no opModGenLimW: base = %+v", cancelling.Base)
	}
	// The load-bearing assertion: no axis in common. Two controls sharing one
	// axis over one interval is a supersession by §10.2.3.3 n), and the loser is
	// answered 7/14 rather than left alive for the server to cancel.
	shares := func(name string, a, b *int64) {
		t.Helper()
		if a != nil && b != nil {
			t.Errorf("the completing control and the server-cancel target BOTH command %s — §10.2.3.3 n) "+
				"makes that a supersession, which terminally reports the cancel target before any "+
				"cancellation can reach it (see core022CancelGenLimW)", name)
		}
	}
	shares("opModMaxLimW", completing.Base.MaxLimW, cancelling.Base.MaxLimW)
	shares("opModGenLimW", completing.Base.GenLimW, cancelling.Base.GenLimW)
	shares("opModExpLimW", completing.Base.ExpLimW, cancelling.Base.ExpLimW)
	shares("opModFixedW", completing.Base.FixedW, cancelling.Base.FixedW)

	// Both must be LIVE and overlapping, or the cancel is not "mid-flight":
	// the cancel target's window has to still be open when the completing
	// control's own lifecycle has run out.
	if cancelling.DurationS <= completing.DurationS {
		t.Errorf("cancel target duration %ds does not outlast the completing control's %ds — the cancel would "+
			"land on an event that had already elapsed on its own", cancelling.DurationS, completing.DurationS)
	}

	// Phase 2: the cancel itself. It must flip status to 2 (Cancelled — IEEE
	// Std 2030.5-2018 Annex B, p.159-160; REV0907-B1: NOT 6, Table 27's
	// Response status for "event cancelled") on the SAME event — same mRID,
	// same axis, and (§10.2.3.3 c), gridsim's own guard) the same
	// creationTime and interval it was already being served with.
	if err := s.Change(ctx, d, params); err != nil {
		t.Fatalf("Change: %v", err)
	}
	after := adminScheduled(t, adminURL, 1)[params["cancelMrid"]]
	if after.MRID == "" {
		t.Fatalf("cancel target %q vanished from program 1 — a cancel is a status update, not a removal "+
			"(§10.2.3.3 c) and s))", params["cancelMrid"])
	}
	if after.Status != int(csipmodel.EventStatusCancelled) {
		t.Errorf("after the cancel, currentStatus = %d, want %d (Cancelled)", after.Status, csipmodel.EventStatusCancelled)
	}
	if after.Base.GenLimW == nil || cancelling.Base.GenLimW == nil ||
		*after.Base.GenLimW != *cancelling.Base.GenLimW {
		t.Errorf("the cancel changed the control base: %+v -> %+v", cancelling.Base, after.Base)
	}
	if after.Start != cancelling.Start || after.DurationS != cancelling.DurationS {
		t.Errorf("the cancel moved the event's interval: start/duration %d/%ds -> %d/%ds; §10.2.3.3 c) "+
			"allows an update to change the STATUS and nothing else",
			cancelling.Start, cancelling.DurationS, after.Start, after.DurationS)
	}
}
