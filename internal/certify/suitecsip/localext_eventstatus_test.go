package suitecsip

// localext_eventstatus_test.go proves REV0907-B1's referee-side fix two ways,
// per the task's own fallback (no in-process fake-DUT fixture exists in this
// tree — nonce_test.go's gridsimDriver wires only a real gridsim admin
// server, never a simulated 2030.5 client):
//
//  1. the GRIDSIM SERVE PATH: EXT-002/EXT-003's Change hooks, driven against a
//     real in-process gridsim exactly as nonce_test.go does for CORE-022,
//     serve the currentStatus value each row's own claim depends on.
//  2. THE ORACLE'S EXPECTATION TABLE: each row's own Criteria, evaluated
//     directly against synthetic ServerView/Transcript fixtures (the same
//     technique TestCoreResponsesSpec_CompositeLifecycleCriterion uses),
//     PASS/FAIL exactly where the claim says they must.

import (
	"context"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	csipmodel "lexa-proto/csipmodel"
)

// ── EXT-002: the gridsim serve path ─────────────────────────────────────────

// TestReservedCurrentStatusSpec_ChangeServesTheReservedValueVerbatim pins that
// EXT-002's Change actually serves the RESERVED value (6) its own claim
// depends on — if gridsim ever "corrected" this to a real currentStatus (e.g.
// 2, the Cancel lever), the row would stop testing what it claims to.
func TestReservedCurrentStatusSpec_ChangeServesTheReservedValueVerbatim(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s := reservedCurrentStatusSpec("ext002nonce1")
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := s.Change(ctx, d, params); err != nil {
		t.Fatalf("Change: %v", err)
	}

	after := d.Snapshot(ctx)
	ctrl := findControl(t, findProgram(t, after, 2).Scheduled, params["mrid"])
	if ctrl.Status != 6 {
		t.Fatalf("EXT-002's Change served currentStatus=%d, want 6 (the RESERVED value this negative "+
			"row's whole claim depends on)", ctrl.Status)
	}
	if (csipmodel.EventStatus{CurrentStatus: uint8(ctrl.Status)}).IsCancelled() {
		t.Fatalf("csipmodel.EventStatus{CurrentStatus: %d}.IsCancelled() = true — a reserved value must "+
			"never be recognised as Cancelled, or this row is not testing what it claims to", ctrl.Status)
	}
}

// ── EXT-002: the oracle's expectation table ─────────────────────────────────

// TestReservedCurrentStatusSpec_NegativeCriterion exercises EXT-002's own
// negative claim directly: a DUT that never posts status=6 for the
// reserved-currentStatus control PASSes, and REV0907-B1's shared-defect shape
// — a DUT (or a referee) that treats 6 as Cancelled and posts it — FAILs.
func TestReservedCurrentStatusSpec_NegativeCriterion(t *testing.T) {
	s := reservedCurrentStatusSpec("ext002nonce2")
	mrid := withRunNonce("CERT-EXT002-RESERVED", "ext002nonce2")

	find := func(o *Observation) criterion {
		for _, c := range s.Criteria(o) {
			if c.Server != nil && c.Wire == nil {
				return c
			}
		}
		t.Fatal("reservedCurrentStatusSpec's Criteria no longer carries the reserved-value negative criterion")
		return criterion{}
	}

	// GREEN: no status=6 ever posted for this mRID.
	clean := &ServerView{Available: true}
	if f := find(&Observation{Server: *clean}).Server(clean); f.Verdict != certify.Pass {
		t.Errorf("no status=6 posted = %s, want Pass: %s", f.Verdict, f.Observed)
	}

	// RED: the exact REV0907-B1 shape — a status=6 posted for a control the
	// server only ever advertised a reserved currentStatus on.
	dirty := &ServerView{Available: true, Responses: []AdminResponse{{Subject: mrid, Status: 6}}}
	if f := find(&Observation{Server: *dirty}).Server(dirty); f.Verdict != certify.Fail {
		t.Errorf("status=6 posted for the reserved-currentStatus control = %s, want Fail: %s",
			f.Verdict, f.Observed)
	}
}

// ── EXT-003: the gridsim serve path ─────────────────────────────────────────

// TestCancelWithRandomizationSpec_ChangeServesStatusThree pins that EXT-003's
// Change serves currentStatus=3 (Cancelled with Randomization) and records
// its own wall-clock time for the timing criterion to check against.
func TestCancelWithRandomizationSpec_ChangeServesStatusThree(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s := cancelWithRandomizationSpec("ext003nonce1")
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	before := time.Now()
	if err := s.Change(ctx, d, params); err != nil {
		t.Fatalf("Change: %v", err)
	}
	after := time.Now()

	changedAtRaw := params[ext003ChangeAtParam]
	if changedAtRaw == "" {
		t.Fatalf("Change did not record %s in params", ext003ChangeAtParam)
	}
	changedAt, err := time.Parse(time.RFC3339Nano, changedAtRaw)
	if err != nil {
		t.Fatalf("params[%s]=%q did not parse as RFC3339: %v", ext003ChangeAtParam, changedAtRaw, err)
	}
	if changedAt.Before(before.Add(-time.Second)) || changedAt.After(after.Add(time.Second)) {
		t.Errorf("recorded changeAt %s is not within [%s, %s]", changedAt, before, after)
	}

	snap := findControl(t, findProgram(t, d.Snapshot(ctx), 2).Scheduled, params["mrid"])
	if snap.Status != int(csipmodel.EventStatusCancelledWithRandomization) {
		t.Fatalf("EXT-003's Change served currentStatus=%d, want %d (Cancelled with Randomization)",
			snap.Status, csipmodel.EventStatusCancelledWithRandomization)
	}
}

// ── EXT-003: the oracle's expectation table ─────────────────────────────────

// TestCancelWithRandomizationSpec_TimingCriterion is REV0907-B1's positive
// mutation-verify lock for the end-randomization floor: a status=6 Response
// posted before changedAt+floor FAILs, and one posted at or after it PASSes.
// csipmodel.EventStatus.EndRandomizationS supplies the floor, so this also
// pins that EXT-003's floor computation agrees with the vendored model's own
// arithmetic rather than a locally re-derived one.
func TestCancelWithRandomizationSpec_TimingCriterion(t *testing.T) {
	nonce := "ext003timingnonce"
	mrid := withRunNonce("CERT-EXT003-RANDCANCEL", nonce)
	changedAt := time.Unix(2_000_000_000, 0).UTC()

	s := cancelWithRandomizationSpec(nonce)
	o := &Observation{Params: map[string]string{ext003ChangeAtParam: changedAt.Format(time.RFC3339Nano)}}

	var timing criterion
	found := false
	for _, c := range s.Criteria(o) {
		if c.Wire != nil {
			timing, found = c, true
		}
	}
	if !found {
		t.Fatal("cancelWithRandomizationSpec's Criteria no longer carries a Wire-tier timing criterion")
	}

	floor := time.Duration(ext003RandomizeDurationS) * time.Second

	// RED: withdrawn 1s before the floor.
	early := responsePOST(mrid, 6)
	early.Req.Time = changedAt.Add(floor - time.Second)
	if f := timing.Wire(nil, synthTranscript(early)); f.Verdict != certify.Fail {
		t.Errorf("status=6 1s before the floor = %s, want Fail: %s", f.Verdict, f.Observed)
	}

	// GREEN: withdrawn exactly at the floor.
	onTime := responsePOST(mrid, 6)
	onTime.Req.Time = changedAt.Add(floor)
	if f := timing.Wire(nil, synthTranscript(onTime)); f.Verdict != certify.Pass {
		t.Errorf("status=6 exactly at the floor = %s, want Pass: %s", f.Verdict, f.Observed)
	}

	// GREEN: withdrawn well after the floor.
	late := responsePOST(mrid, 6)
	late.Req.Time = changedAt.Add(floor + time.Minute)
	if f := timing.Wire(nil, synthTranscript(late)); f.Verdict != certify.Pass {
		t.Errorf("status=6 1m after the floor = %s, want Pass: %s", f.Verdict, f.Observed)
	}

	// UNAVAILABLE: no status=6 Response recovered at all — a window-timing
	// fact, not a decided FAIL.
	if f := timing.Wire(nil, synthTranscript()); f.Unavailable == "" {
		t.Errorf("no status=6 Response at all should be Unavailable, got verdict=%s: %s", f.Verdict, f.Observed)
	}
}

// TestCancelWithRandomizationSpec_FloorMatchesEndRandomizationS pins that
// ext003RandomizeDurationS (randomizeStart=0) produces the SAME floor the
// vendored model's own EndRandomizationS computes — the row's Criteria and
// its Setup must agree on the number, or the timing criterion checks a floor
// the control it grades never actually carried.
func TestCancelWithRandomizationSpec_FloorMatchesEndRandomizationS(t *testing.T) {
	got := (csipmodel.EventStatus{CurrentStatus: csipmodel.EventStatusCancelledWithRandomization}).
		EndRandomizationS(0, ext003RandomizeDurationS)
	if got != ext003RandomizeDurationS {
		t.Fatalf("EndRandomizationS(0, %d) = %d, want %d", ext003RandomizeDurationS, got, ext003RandomizeDurationS)
	}
}

// ── EXT-004: the gridsim serve path ─────────────────────────────────────────

// TestExpiredAtReceiptSpec_SetupServesAnAlreadyElapsedIntervalWithStatusZero
// pins that EXT-004's Setup actually constructs the exact combination its own
// claim depends on: a control whose Specified End Time (Interval.Start+
// Interval.Duration) has ALREADY PASSED at post time, served with
// currentStatus=0 (Scheduled) — never 1 (Active), which is what an ordinary
// past-start control defaults to. If gridsim ever "corrected" this (e.g. by
// defaulting to currentStatus=1 the way every other past-start control
// does), the row would stop testing what it claims to.
func TestExpiredAtReceiptSpec_SetupServesAnAlreadyElapsedIntervalWithStatusZero(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s := expiredAtReceiptSpec("ext004nonce1")
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	after := d.Snapshot(ctx)
	ctrl := findControl(t, findProgram(t, after, 2).Scheduled, params["mrid"])
	if ctrl.Status != int(csipmodel.EventStatusScheduled) {
		t.Fatalf("EXT-004's Setup served currentStatus=%d, want %d (Scheduled) even though its own interval "+
			"has already elapsed", ctrl.Status, csipmodel.EventStatusScheduled)
	}
	if end := ctrl.Start + int64(ctrl.DurationS); end >= after.Status.ServerTime {
		t.Fatalf("the served interval (start=%d duration=%d, end=%d) is not actually in gridsim's past "+
			"(server time=%d) — EXT-004 is not testing what it claims to", ctrl.Start, ctrl.DurationS, end,
			after.Status.ServerTime)
	}
}

// TestExpiredAtReceiptSpec_SetupRecordsACeilingBaseline pins that Setup
// stashes SOME pre-publication ceiling snapshot into params, even when no
// live DER is configured (gridsimDriver wires only gridsim's admin API,
// never a sim) — readCeilingSnapshot must degrade to an Unavailable
// snapshot rather than leaving the param unset or panicking, which is what
// ext004CeilingStabilityCriterion needs to report the criterion as
// Unavailable rather than crash decoding an empty string.
func TestExpiredAtReceiptSpec_SetupRecordsACeilingBaseline(t *testing.T) {
	d := gridsimDriver(t)
	ctx := context.Background()

	s := expiredAtReceiptSpec("ext004nonce2")
	params := map[string]string{}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	raw, ok := params[ext004CeilingPreParam]
	if !ok || raw == "" {
		t.Fatalf("Setup did not record %s in params", ext004CeilingPreParam)
	}
	snap := decodeCeilingSnapshot(raw)
	if snap.Available {
		t.Fatalf("decodeCeilingSnapshot(%q) reports Available=true with no sim configured — want a graceful "+
			"Unavailable snapshot", raw)
	}
	if want := params[ext004WantParam]; want == "" {
		t.Error("Setup did not record a chosen commanded value in params")
	}
}

// ── EXT-004: the oracle's expectation table (Response-status criterion) ────

// TestExt004ResponseCriterion_Grading exercises EXT-004's primary claim
// directly against synthetic ServerViews: exactly one status=254 and none of
// 1/2/3 PASSes; any of 1/2/3 present FAILs (the DUT adopted or executed an
// already-expired event); zero or more than one status=254 also FAILs (a
// correct rejection is owed exactly once).
func TestExt004ResponseCriterion_Grading(t *testing.T) {
	mrid := "CERT-EXT004-EXPIRED-test"
	c := ext004ResponseCriterion(mrid)
	if c.Server == nil {
		t.Fatal("ext004ResponseCriterion did not build a Server-tier evaluator")
	}

	cases := []struct {
		name    string
		resp    []AdminResponse
		session bool
		want    certify.Verdict
	}{
		{"exactly one 254, nothing else", []AdminResponse{{Subject: mrid, Status: 254}}, true, certify.Pass},
		{"254 plus an unrelated mrid's response", []AdminResponse{
			{Subject: mrid, Status: 254}, {Subject: "OTHER", Status: 1}}, true, certify.Pass},
		{"Received(1) posted — REV0907-B2's own defect shape", []AdminResponse{
			{Subject: mrid, Status: 1}, {Subject: mrid, Status: 254}}, true, certify.Fail},
		{"Started(2) posted, no 254 at all", []AdminResponse{{Subject: mrid, Status: 2}}, true, certify.Fail},
		{"Completed(3) posted alongside 254", []AdminResponse{
			{Subject: mrid, Status: 254}, {Subject: mrid, Status: 3}}, true, certify.Fail},
		// A session DID establish (the DUT connected and fetched the control
		// list — a real GET is what SessionEstablished() looks for) but posted
		// NOTHING for this mrid: silently ignoring an expired event is not the
		// same as correctly rejecting it, so this must FAIL, not merely be
		// Unavailable for lack of a session.
		{"no 254 at all (silently ignored, never rejected)", nil, true, certify.Fail},
		{"254 posted twice", []AdminResponse{
			{Subject: mrid, Status: 254}, {Subject: mrid, Status: 254}}, true, certify.Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &ServerView{Available: true, Responses: tc.resp}
			if tc.session {
				v.Requests = []ServerRequest{{Method: "GET", Path: "/dcap"}}
			}
			f := c.Server(v)
			if f.Verdict != tc.want {
				t.Errorf("statuses %v -> verdict=%s (%s), want %s", tc.resp, f.Verdict, f.Observed, tc.want)
			}
		})
	}
}

// TestExt004ResponseCriterion_NoSessionIsUnavailableNotFail pins that a
// window with no TLS session at all (gridsim logged nothing because the DUT
// never connected) is graded Unavailable, not a FAIL — the same
// noSessionUnavailable discipline every other Server-tier criterion in this
// suite already gets.
func TestExt004ResponseCriterion_NoSessionIsUnavailableNotFail(t *testing.T) {
	c := ext004ResponseCriterion("CERT-EXT004-NOSESSION")
	f := c.Server(&ServerView{Available: true})
	if f.Unavailable == "" {
		t.Errorf("no session at all should be Unavailable, got verdict=%s: %s", f.Verdict, f.Observed)
	}
}

// ── EXT-004: the ceiling-stability criterion ────────────────────────────────

// TestExt004CeilingFinding_Grading is REV0907-B2's mutation-verify lock for
// the supporting ceiling-axis check: an unmoved register PASSes, a moved one
// FAILs, and either read being unavailable degrades the criterion to
// Unavailable rather than a decided verdict.
func TestExt004CeilingFinding_Grading(t *testing.T) {
	unchanged := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Enabled: true, Raw: 100}
	moved := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Enabled: true, Raw: 12.34}
	unavailablePre := ceilingSnapshot{Note: "no sim configured"}

	if f := ext004CeilingFinding(unchanged, unchanged, 1234); f.Verdict != certify.Pass {
		t.Errorf("identical pre/post = %s, want Pass: %s", f.Verdict, f.Observed)
	}
	if f := ext004CeilingFinding(unchanged, moved, 1234); f.Verdict != certify.Fail {
		t.Errorf("pre=%v post=%v = %s, want Fail: %s", unchanged, moved, f.Verdict, f.Observed)
	}
	if f := ext004CeilingFinding(unavailablePre, unchanged, 1234); f.Unavailable == "" {
		t.Errorf("unavailable pre-read should be Unavailable, got verdict=%s: %s", f.Verdict, f.Observed)
	}
	if f := ext004CeilingFinding(unchanged, unavailablePre, 1234); f.Unavailable == "" {
		t.Errorf("unavailable post-read should be Unavailable, got verdict=%s: %s", f.Verdict, f.Observed)
	}
	// An enabled flip with the SAME raw value is still a move: the axis'
	// governing state changed even if the magnitude did not.
	flippedEnable := ceilingSnapshot{Available: true, Point: "WMaxLimPct", Enabled: false, Raw: 100}
	if f := ext004CeilingFinding(unchanged, flippedEnable, 1234); f.Verdict != certify.Fail {
		t.Errorf("enabled flip with unchanged raw = %s, want Fail: %s", f.Verdict, f.Observed)
	}
}

// TestCeilingSnapshot_EncodeDecodeRoundTrips pins the Params serialization
// EXT-004's Setup/PostWait (encode) and its citation-phase criterion
// (decode) must agree on — a live-phase fact that decodes back differently
// than it was encoded is corrupted evidence, not a working ceiling read.
func TestCeilingSnapshot_EncodeDecodeRoundTrips(t *testing.T) {
	cases := []ceilingSnapshot{
		{Available: true, Point: "WMaxLimPct", Enabled: true, Raw: 42.5},
		{Available: true, Point: "M123.WMaxLimPct", Enabled: false, Raw: 0},
		{Note: "the DER serves no model 704 and no model 123"},
	}
	for _, want := range cases {
		got := decodeCeilingSnapshot(want.encode())
		if got.Available != want.Available || got.Point != want.Point || got.Enabled != want.Enabled ||
			got.Raw != want.Raw {
			t.Errorf("round-trip of %+v = %+v (via %q)", want, got, want.encode())
		}
		if !want.Available && got.Note == "" {
			t.Errorf("round-trip of an unavailable snapshot lost its Note: %+v -> %+v", want, got)
		}
	}
}
