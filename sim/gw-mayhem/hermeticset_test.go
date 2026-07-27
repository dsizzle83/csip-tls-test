package gwmayhem

// hermeticset_test.go pins WHICH scenarios the hermetic (-loopback) mode actually
// reaches, and therefore how large the hermetic gate is.
//
// The documented default invocation — `gw-mayhem -loopback -pki certs/mbaps` —
// runs nine of the suite's thirty-eight scenarios and declines the rest. That is
// not a defect in itself: a declined scenario judges an effect only the real
// gateway produces, and the loopback is a PEER, not a gateway (see
// qa/gw-scenarios/README.md for the case-by-case argument). What WAS a defect is
// that nothing recorded the number. A scenario acquiring NeedsBench — for a good
// reason or by a copy-paste — shrinks the hermetic gate silently, and the run
// still prints GATE PASS, because a decline is an expected INCONCLUSIVE.
//
// So the set is data here, and moving it is a deliberate act with a diff. The test
// asserts the exact ids, not just the count: a swap (one scenario becomes bench-
// only while another becomes hermetic) keeps the count and is exactly the change
// most likely to go unnoticed.

import (
	"sort"
	"strings"
	"testing"
)

// hermeticApplicable is the scenario set a -loopback run can run: everything that
// needs neither the live bench nor a board mutation. Extended scenarios are listed
// here if they are hermetic (none are today) because -extended and -only can still
// select them; the run-mode filter is a separate axis.
var hermeticApplicable = []string{
	"authz-cert-negatives",
	"authz-gridservice-write-granted",
	"authz-malformed-writes",
	"authz-networkadmin-write-denied",
	"authz-out-of-range-setpoint",
	"authz-role-denial-matrix",
	"transport-renegotiation-refusal",
	"transport-resume-after-drop",
	"transport-session-flood",
}

// TestHermeticApplicableSetIsPinned fails when the set of scenarios a -loopback
// run can reach changes. If the change is intended, update hermeticApplicable AND
// the reach table in qa/gw-scenarios/README.md in the same commit — the point of
// the pin is that the two cannot drift apart.
func TestHermeticApplicableSetIsPinned(t *testing.T) {
	scenarios, loadErrs := AllScenarios("../../qa/gw-scenarios")
	for _, e := range loadErrs {
		t.Fatalf("AllScenarios: %v", e)
	}
	var got []string
	for _, sc := range scenarios {
		if !sc.NeedsBench && !sc.NeedsBoard {
			got = append(got, sc.ID)
		}
	}
	sort.Strings(got)
	want := append([]string(nil), hermeticApplicable...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the hermetic (-loopback) scenario set changed.\n got: %v\nwant: %v\n"+
			"If that is intended, update hermeticApplicable here and the reach table in "+
			"qa/gw-scenarios/README.md together — a hermetic gate that shrinks silently still prints GATE PASS.",
			got, want)
	}
}

// TestEveryBoardScenarioCanBeArmed asserts a board-mutating scenario carries the
// hook its decline prints. A decline that cannot tell the orchestrator what to arm
// is a scenario that will never run in any mode — the quiet way a suite's declared
// size drifts away from what it actually checks.
func TestEveryBoardScenarioCanBeArmed(t *testing.T) {
	scenarios, _ := AllScenarios("../../qa/gw-scenarios")
	if len(scenarios) == 0 {
		t.Fatal("no scenarios loaded")
	}
	for _, sc := range scenarios {
		if !sc.NeedsBoard {
			continue
		}
		switch {
		case sc.Board == nil:
			t.Errorf("%s is board-mutating but carries no boardHook", sc.ID)
		case strings.TrimSpace(sc.Board.Arm) == "":
			t.Errorf("%s carries a boardHook with no Arm command — nothing to hand the orchestrator", sc.ID)
		}
	}
}

// TestRollupSeparatesDeclinedFromUnobserved is the teeth for the roll-up's new
// denominator: two runs with the SAME verdict tally must read differently when one
// of them declined the scenarios and the other attempted them.
func TestRollupSeparatesDeclinedFromUnobserved(t *testing.T) {
	declinedRun := BatchSummary{
		Total: 3, ByVerdict: map[Verdict]int{VerdictPass: 1, VerdictInconclusive: 2},
		Declined: 2, DeclinedBy: map[string]int{declineBench: 2},
		Reports: []*gwReport{
			{ID: "a", Verdict: VerdictPass, VerdictExpected: true},
			{ID: "b", Verdict: VerdictInconclusive, VerdictExpected: true, Declined: true, DeclineKind: declineBench},
			{ID: "c", Verdict: VerdictInconclusive, VerdictExpected: true, Declined: true, DeclineKind: declineBench},
		},
	}
	attemptedRun := BatchSummary{
		Total: 3, ByVerdict: map[Verdict]int{VerdictPass: 1, VerdictInconclusive: 2},
		Reports: []*gwReport{
			{ID: "a", Verdict: VerdictPass, VerdictExpected: true},
			{ID: "b", Verdict: VerdictInconclusive, VerdictExpected: true},
			{ID: "c", Verdict: VerdictInconclusive, VerdictExpected: true},
		},
	}
	dl, at := rollupLine(declinedRun), rollupLine(attemptedRun)
	if dl == at {
		t.Fatalf("a run that DECLINED two scenarios rolls up identically to one that attempted and could not observe them:\n%s", dl)
	}
	if !strings.Contains(dl, "asserted 1/1 applicable") {
		t.Errorf("declined run should score its assertion against the applicable set: %s", dl)
	}
	if !strings.Contains(dl, "2 need the live bench") {
		t.Errorf("declined run should say what the declines needed: %s", dl)
	}
	if !strings.Contains(at, "asserted 1/3 applicable") {
		t.Errorf("attempted run should score against all three, none having declined: %s", at)
	}
}

// TestRollupFailsWhenNothingWasApplicable covers the other end of the floor: a
// mode that could not run a single scenario has not gated anything, and must not
// print a pass even though every decline is an "expected" INCONCLUSIVE.
func TestRollupFailsWhenNothingWasApplicable(t *testing.T) {
	sum := BatchSummary{
		Total: 2, ByVerdict: map[Verdict]int{VerdictInconclusive: 2},
		Declined: 2, DeclinedBy: map[string]int{declineBoard: 2},
		Reports: []*gwReport{
			{ID: "a", Verdict: VerdictInconclusive, VerdictExpected: true, Declined: true, DeclineKind: declineBoard},
			{ID: "b", Verdict: VerdictInconclusive, VerdictExpected: true, Declined: true, DeclineKind: declineBoard},
		},
	}
	line := rollupLine(sum)
	if !strings.Contains(line, "GATE FAIL") {
		t.Errorf("a run in which nothing was applicable printed a pass: %s", line)
	}
	if !strings.Contains(line, "applicable") {
		t.Errorf("the gate failure does not say the mode had nothing to run: %s", line)
	}
}
