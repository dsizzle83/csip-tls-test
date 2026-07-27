package gwmayhem

// assertionfloor_test.go pins the rule that a gw-mayhem run which asserted
// NOTHING cannot report success.
//
// Every scenario in this suite is allowed to decline: no bench, no sim admin
// API, a board mutation the orchestrator did not arm. Each of those lands as
// INCONCLUSIVE, which deliberately does not count as a gate failure — declining
// is not failing. But the sum of those decisions used to be indistinguishable
// from a clean full run: both printed "GATE PASS". A gate that reports success
// for work it did not do is worse than no gate, because the operator stops
// reading it.
//
// These tests are the teeth for that rule. The last one is the important one:
// it fails if someone reintroduces the old behaviour by making the assertion
// floor conditional.

import (
	"strings"
	"testing"
)

// summaryOf builds a BatchSummary with the given verdict counts, as RunSuite
// would have accumulated it.
func summaryOf(counts map[Verdict]int, gateFailures int) BatchSummary {
	sum := BatchSummary{ByVerdict: map[Verdict]int{}, GateFailures: gateFailures}
	for v, n := range counts {
		sum.ByVerdict[v] = n
		sum.Total += n
	}
	return sum
}

func TestAssertionFloor(t *testing.T) {
	tests := []struct {
		name       string
		counts     map[Verdict]int
		gateFails  int
		wantPass   bool
		wantSubstr string
	}{
		{
			name:       "every scenario declined — must not pass",
			counts:     map[Verdict]int{VerdictInconclusive: 37},
			wantPass:   false,
			wantSubstr: "nothing asserted",
		},
		{
			name:     "blind is not an assertion either",
			counts:   map[Verdict]int{VerdictBlind: 5, VerdictInconclusive: 12},
			wantPass: false,
		},
		{
			name:     "one real PASS among declines is a legitimate pass",
			counts:   map[Verdict]int{VerdictPass: 1, VerdictInconclusive: 36},
			wantPass: true,
		},
		{
			name:     "a DEGRADED verdict counts as having asserted",
			counts:   map[Verdict]int{VerdictDegraded: 1, VerdictInconclusive: 9},
			wantPass: true,
		},
		{
			// A FAIL that was PINNED as expected leaves GateFailures at 0. The run
			// still asserted, so the floor must not fire and turn an expected-fail
			// run into a confusing double failure.
			name:     "expected FAIL asserted, so the floor does not fire",
			counts:   map[Verdict]int{VerdictFail: 1, VerdictInconclusive: 20},
			wantPass: true,
		},
		{
			name:      "a genuine gate failure still dominates",
			counts:    map[Verdict]int{VerdictPass: 3, VerdictFail: 1},
			gateFails: 1,
			wantPass:  false,
		},
		{
			// Nothing selected at all (e.g. an -only that matched no id) is not a
			// pass claim about the suite, but it is also not the floor's case — it
			// has no scenarios to have declined. Kept explicit so the boundary is
			// deliberate rather than incidental.
			name:     "an empty selection is not the floor's case",
			counts:   map[Verdict]int{},
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := rollupLine(summaryOf(tc.counts, tc.gateFails))
			gotPass := strings.Contains(line, "GATE PASS")
			if gotPass != tc.wantPass {
				t.Errorf("gate pass = %v, want %v\n  line: %s", gotPass, tc.wantPass, line)
			}
			if tc.wantSubstr != "" && !strings.Contains(line, tc.wantSubstr) {
				t.Errorf("roll-up does not explain itself: want substring %q\n  line: %s", tc.wantSubstr, line)
			}
		})
	}
}

// TestRollupAlwaysReportsAssertionCount pins that the assertion count is printed
// on EVERY run, not only when it is zero. An operator has to be able to see "we
// asserted 8 of 37" on a green run — that is the number that says how much of
// the suite the result actually covers, and hiding it on success is how a
// mostly-declined run gets mistaken for a full one.
func TestRollupAlwaysReportsAssertionCount(t *testing.T) {
	for _, sum := range []BatchSummary{
		summaryOf(map[Verdict]int{VerdictPass: 8, VerdictInconclusive: 29}, 0),
		summaryOf(map[Verdict]int{VerdictPass: 37}, 0),
		summaryOf(map[Verdict]int{VerdictInconclusive: 37}, 0),
	} {
		line := rollupLine(sum)
		if !strings.Contains(line, "asserted ") {
			t.Errorf("roll-up hides the assertion count: %s", line)
		}
	}
}
