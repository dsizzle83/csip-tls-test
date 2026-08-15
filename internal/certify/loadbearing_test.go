package certify

// loadbearing_test.go — the runner's half of the silent-skip cap.
//
// worstOf and bundle.TestCaseResult.RollUp must agree exactly. worstOf decides
// the verdict the RUNNER records; RollUp decides the one a reader re-derives
// from the bundle's own assertions. If they disagreed, a bundle would carry a
// case whose stated verdict does not follow from the assertions printed
// underneath it — which is the one thing an evidence bundle may never do.

import (
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

func lbAssertion(v Verdict, loadBearing bool) Assertion {
	return Assertion{Claim: "c", Method: "m", Verdict: v, LoadBearing: loadBearing}
}

func TestWorstOf_CapsOnAnUnmeasuredLoadBearingAssertion(t *testing.T) {
	supporting := []Assertion{lbAssertion(Pass, false), lbAssertion(Pass, false)}

	if got := worstOf(append(append([]Assertion{}, supporting...), lbAssertion(Skip, false))); got != Pass {
		t.Fatalf("an UNMARKED skip rolls up to %s; PASS is the pre-existing behaviour and this is the "+
			"record of what the marker changes", got)
	}
	if got := worstOf(append(append([]Assertion{}, supporting...), lbAssertion(Skip, true))); got != Warn {
		t.Fatalf("a set whose LOAD-BEARING assertion skipped rolls up to %s, want WARN", got)
	}
}

// The two roll-ups are driven over the SAME inputs and required to agree. A
// table here and a table in bundle's own test would be two statements that can
// drift; this one compares the implementations directly.
func TestWorstOf_AgreesWithTheBundleRollUp(t *testing.T) {
	sets := [][]Assertion{
		nil,
		{lbAssertion(Pass, false)},
		{lbAssertion(Skip, true)},
		{lbAssertion(Pass, false), lbAssertion(Skip, true)},
		{lbAssertion(Fail, false), lbAssertion(Skip, true)},
		{lbAssertion(Warn, false), lbAssertion(Skip, true)},
		{lbAssertion(Pass, true), lbAssertion(Skip, false)},
		{lbAssertion(Skip, false), lbAssertion(Skip, false)},
	}
	for i, as := range sets {
		runner := worstOf(as)
		rolled := bundle.TestCaseResult{Assertions: as}.RollUp()
		// worstOf returns "" for an empty set where RollUp returns Skip; the
		// two mean the same thing (nothing raised the floor) and the runner's
		// callers only ever compare severities, so the empty string is
		// normalised rather than special-cased in production code.
		if runner == "" {
			runner = bundle.Skip
		}
		if runner != rolled {
			t.Errorf("set %d: the runner rolls up to %s and the bundle to %s — a case would carry a "+
				"verdict its own printed assertions do not produce", i, runner, rolled)
		}
	}
}
