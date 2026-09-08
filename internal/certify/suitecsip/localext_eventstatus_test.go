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
