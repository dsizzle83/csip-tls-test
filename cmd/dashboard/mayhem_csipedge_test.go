package main

import (
	"fmt"
	"testing"
)

// ── diagnoseCancelledSuperseded ──────────────────────────────────────────────

func supersededResp() gridResponse {
	return gridResponse{Subject: supersedeLoserMRID, Status: 7}
}
func cancelledResp() gridResponse {
	return gridResponse{Subject: serverCancelMRID, Status: 6}
}

func reachable75() []maySample {
	return mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = true })
}

func TestDiagnoseCancelledSuperseded_PassBoth(t *testing.T) {
	resps := []gridResponse{
		{Subject: supersedeLoserMRID, Status: 1}, // received
		supersededResp(),
		{Subject: serverCancelMRID, Status: 1},
		cancelledResp(),
	}
	f := diagnoseCancelledSuperseded(scFor("cs-pass"), reachable75(), resps, nil)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseCancelledSuperseded_FailNeither(t *testing.T) {
	resps := []gridResponse{{Subject: supersedeLoserMRID, Status: 1}, {Subject: serverCancelMRID, Status: 2}}
	f := diagnoseCancelledSuperseded(scFor("cs-neither"), reachable75(), resps, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "neither") {
		t.Errorf("headline = %q, want it to mention neither ack", f.Headline)
	}
}

func TestDiagnoseCancelledSuperseded_FailMissingSuperseded(t *testing.T) {
	resps := []gridResponse{cancelledResp()} // 6 present, 7 absent
	f := diagnoseCancelledSuperseded(scFor("cs-no7"), reachable75(), resps, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "superseded") {
		t.Errorf("headline = %q, want it to flag the missing Superseded(7)", f.Headline)
	}
}

func TestDiagnoseCancelledSuperseded_FailMissingCancelled(t *testing.T) {
	resps := []gridResponse{supersededResp()} // 7 present, 6 absent
	f := diagnoseCancelledSuperseded(scFor("cs-no6"), reachable75(), resps, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "cancel") {
		t.Errorf("headline = %q, want it to flag the missing Cancelled(6)", f.Headline)
	}
}

// A supersede(7)/cancel(6) match must be MRID-specific: a 7 for the wrong
// subject must not satisfy the loser assertion.
func TestDiagnoseCancelledSuperseded_WrongSubjectDoesNotMatch(t *testing.T) {
	resps := []gridResponse{
		{Subject: "SOME-OTHER-MRID", Status: 7},
		cancelledResp(),
	}
	f := diagnoseCancelledSuperseded(scFor("cs-wrongsubj"), reachable75(), resps, nil)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (a 7 for the wrong subject must not count)", f.Verdict)
	}
}

func TestDiagnoseCancelledSuperseded_FetchErrInconclusive(t *testing.T) {
	f := diagnoseCancelledSuperseded(scFor("cs-fetcherr"), reachable75(), nil, fmt.Errorf("connection refused"))
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

func TestDiagnoseCancelledSuperseded_UnreachableInconclusive(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseCancelledSuperseded(scFor("cs-unreach"), s, []gridResponse{supersededResp(), cancelledResp()}, nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

func TestDiagnoseCancelledSuperseded_NoSamplesInconclusive(t *testing.T) {
	f := diagnoseCancelledSuperseded(scFor("cs-nosamples"), nil, nil, nil)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", f.Verdict)
	}
}

// ── diagnoseRandomizeDuration ────────────────────────────────────────────────

const (
	rdBase = 240
	rdRand = -60
)

func randCtrl() gridControl { return gridControl{MRID: randomizeMRID, Start: 1000, DurationS: rdBase} }

// adoptedSamples returns a 75s timeline where the hub has adopted the
// randomized control with the given validUntil (server unix).
func adoptedSamples(validUntil int64) []maySample {
	return mkSamples(75, func(i int, smp *maySample) {
		smp.HubReachable = true
		smp.AdoptedMRID = randomizeMRID
		smp.ValidUntil = validUntil
	})
}

func TestDiagnoseRandomizeDuration_PassInBandShortened(t *testing.T) {
	// honored = 1210 - 1000 = 210 ∈ [180,300]; differs from base 240 ⇒ offset proven.
	f := diagnoseRandomizeDuration(scFor("rd-pass"), adoptedSamples(1210), randCtrl(), nil, rdBase, rdRand)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
}

func TestDiagnoseRandomizeDuration_PassExactBaseNoted(t *testing.T) {
	// honored = 240 == base ⇒ still legal, PASS with the "offset ~0" note.
	f := diagnoseRandomizeDuration(scFor("rd-base"), adoptedSamples(1240), randCtrl(), nil, rdBase, rdRand)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS", f.Verdict)
	}
}

func TestDiagnoseRandomizeDuration_FailOutOfBand(t *testing.T) {
	// honored = 1400 - 1000 = 400, well past 300+tol ⇒ mishandled.
	f := diagnoseRandomizeDuration(scFor("rd-oob"), adoptedSamples(1400), randCtrl(), nil, rdBase, rdRand)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "outside") {
		t.Errorf("headline = %q, want it to flag the out-of-band window", f.Headline)
	}
}

func TestDiagnoseRandomizeDuration_FailNeverAdopted(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = true }) // no AdoptedMRID/ValidUntil
	f := diagnoseRandomizeDuration(scFor("rd-noadopt"), s, randCtrl(), nil, rdBase, rdRand)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "never adopted") {
		t.Errorf("headline = %q, want it to flag non-adoption", f.Headline)
	}
}

func TestDiagnoseRandomizeDuration_NoStartInconclusive(t *testing.T) {
	f := diagnoseRandomizeDuration(scFor("rd-nostart"), adoptedSamples(1210), gridControl{}, nil, rdBase, rdRand)
	if f.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %s, want INCONCLUSIVE (no control start)", f.Verdict)
	}
}

// ── edgeSurvivalFinding (via diagnoseResource410 / diagnoseSlowLoris) ─────────

func TestEdgeSurvival_Pass(t *testing.T) {
	cons := exportCons()
	s := mkSamples(75, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = 0, 0 })
	f := diagnoseResource410(scFor("410-pass"), cons, s)
	if f.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS (%s): %v", f.Verdict, f.Headline, f.Diagnosis)
	}
	if !containsFold(f.Headline, "410") {
		t.Errorf("headline = %q, want the 410 fault label", f.Headline)
	}
}

func TestEdgeSurvival_FailUnreachable(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) { smp.HubReachable = false })
	f := diagnoseEventDelay(scFor("delay-unreach"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL", f.Verdict)
	}
	if !containsFold(f.Headline, "stopped responding") {
		t.Errorf("headline = %q, want it to mention the hub not responding", f.Headline)
	}
}

func TestEdgeSurvival_FailUnseated(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) { smp.RealGridW, smp.HubGridW = -3000, -3000 })
	f := diagnoseSlowLoris(scFor("slow-unseated"), exportCons(), s)
	if f.Verdict != "FAIL" {
		t.Fatalf("verdict = %s, want FAIL (%s)", f.Verdict, f.Headline)
	}
	if !containsFold(f.Headline, "unseated") {
		t.Errorf("headline = %q, want it to mention the control being unseated", f.Headline)
	}
}

func TestEdgeSurvival_DegradedTransient(t *testing.T) {
	s := mkSamples(75, func(i int, smp *maySample) {
		if i < 40 {
			smp.RealGridW, smp.HubGridW = -3000, -3000
		} else {
			smp.RealGridW, smp.HubGridW = 0, 0
		}
	})
	f := diagnoseResource410(scFor("410-degraded"), exportCons(), s)
	if f.Verdict != "DEGRADED" {
		t.Fatalf("verdict = %s, want DEGRADED (%s)", f.Verdict, f.Headline)
	}
}

// ── scenario construction sanity ─────────────────────────────────────────────

func TestCSIPEdgeScenarios_WellFormed(t *testing.T) {
	d := &mayhemDriver{}
	seen := map[string]bool{}
	for _, sc := range d.csipEdgeScenarios() {
		if sc.ID == "" {
			t.Fatalf("scenario with empty ID: %+v", sc)
		}
		if seen[sc.ID] {
			t.Errorf("duplicate scenario ID %q", sc.ID)
		}
		seen[sc.ID] = true
		if sc.Hypothesis == "" || sc.Expected == "" || sc.Fix == "" {
			t.Errorf("%s: Hypothesis/Expected/Fix must not be empty", sc.ID)
		}
		if sc.HoldS < 60 || sc.HoldS > 90 {
			t.Errorf("%s: HoldS = %d, want in [60,90]", sc.ID, sc.HoldS)
		}
		if sc.setup == nil || sc.evaluate == nil || sc.teardown == nil {
			t.Errorf("%s: setup/evaluate/teardown must not be nil", sc.ID)
		}
	}
	wantIDs := []string{
		"cancelled-superseded-roundtrip", "randomize-duration-honored",
		"resource-410-failclosed", "csip-event-delay", "csip-slow-loris",
	}
	for _, id := range wantIDs {
		if !seen[id] {
			t.Errorf("csipEdgeScenarios() missing expected ID %q", id)
		}
	}
}
