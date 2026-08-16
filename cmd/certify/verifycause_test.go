package main

// verifycause_test.go — what a verification failure is ATTRIBUTED to.
//
// The summary line asserted "A hash mismatch means the capture and the report
// disagree" on EVERY failure. Verification has several independent legs — file
// digests, assertion citations, the metrics channel, the fixture timebase, and
// the case-verdict re-derivation — and most of them fail with every byte
// matching. A campaign bundle that declares no capture is the common one: its
// files hash correctly, and a reader chasing a phantom hash mismatch is being
// sent to look at the only part of the bundle that is demonstrably fine.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

func TestVerifyFailureCause_AttributesByActualCause(t *testing.T) {
	badFile := bundle.FileCheck{Name: "capture.pcapng", OK: false}
	goodFile := bundle.FileCheck{Name: "bundle.json", OK: true}
	badCite := bundle.AssertionCheck{Case: "CORE-001", Citable: true, OK: false}
	goodCite := bundle.AssertionCheck{Case: "CORE-001", Citable: true, OK: true}
	// An UNCITABLE assertion cannot fail verification — there is nothing to
	// check — and must never be counted as a citation failure.
	narrative := bundle.AssertionCheck{Case: "CORE-002", Citable: false, OK: false}

	for _, tc := range []struct {
		name    string
		rep     bundle.VerifyReport
		want    string
		notWant string
	}{{
		name: "a real file digest mismatch",
		rep:  bundle.VerifyReport{Files: []bundle.FileCheck{badFile, goodFile}},
		want: "1 manifest file(s) hash to something other than",
	}, {
		name: "a real citation mismatch",
		rep:  bundle.VerifyReport{Assertions: []bundle.AssertionCheck{badCite, goodCite}},
		want: "1 cited assertion(s) do not hash",
	}, {
		name: "both",
		rep: bundle.VerifyReport{
			Files:      []bundle.FileCheck{badFile},
			Assertions: []bundle.AssertionCheck{badCite},
		},
		want: "1 manifest file(s) and 1 cited assertion(s)",
	}, {
		// THE CASE THAT WAS MISDIAGNOSED. Every byte matches; the bundle failed
		// a structural leg — a campaign bundle declaring no capture, a
		// re-derived case verdict weaker than its own assertions, a relabelled
		// timebase.
		name: "every digest matches and a structural leg failed",
		rep: bundle.VerifyReport{
			Files:      []bundle.FileCheck{goodFile},
			Assertions: []bundle.AssertionCheck{goodCite, narrative},
			Problems:   []string{"the bundle declares no capture"},
		},
		want:    "NOT a hash mismatch",
		notWant: "capture and the report disagree",
	}, {
		name: "an empty report still says something true",
		rep:  bundle.VerifyReport{},
		want: "NOT a hash mismatch",
	}} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := verifyFailureCause(&tc.rep)
			if !strings.Contains(got, tc.want) {
				t.Errorf("cause = %q, want it to contain %q", got, tc.want)
			}
			if tc.notWant != "" && strings.Contains(got, tc.notWant) {
				t.Errorf("cause = %q, must NOT claim %q — every digest matched", got, tc.notWant)
			}
		})
	}
}

// The old sentence, as a would-have-caught record: it was unconditional, so it
// was wrong on every structural failure.
func TestVerifyFailureCause_IsNoLongerUnconditional(t *testing.T) {
	clean := bundle.VerifyReport{Files: []bundle.FileCheck{{Name: "bundle.json", OK: true}}}
	dirty := bundle.VerifyReport{Files: []bundle.FileCheck{{Name: "bundle.json", OK: false}}}
	if verifyFailureCause(&clean) == verifyFailureCause(&dirty) {
		t.Fatal("the failure cause is the same string whether or not a digest actually mismatched, " +
			"which is the defect: an unconditional attribution is wrong on every failure it does not " +
			"happen to describe")
	}
}
