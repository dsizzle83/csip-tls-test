package aggregator

// verdict.go is the VERDICT LAYER (T06.6): the pass/fail vocabulary the scenario
// engine's oracles emit, kept deliberately separate from the T06.4 RunState,
// which stays a verdict-FREE recorder (runstate.go). A campaign's raw
// observations (session facts, samples, writes, denials) accrue in RunState; a
// named oracle (oracle.go / readback.go) then reads those observations and the
// per-step results and returns exactly one Verdict + human-readable findings.
// This is the "oracles are code, scenarios are data" boundary the bench guards
// (qa/scenarios/README.md), applied to the aggregator's control campaigns: a
// campaign JSON selects an oracle by name and supplies steps; it can never
// define pass/fail logic.

// Verdict is a campaign oracle's judgment. The five values mirror the bench's
// established Mayhem verdict vocabulary (cmd/dashboard/mayhem.go,
// qa/scenarios/README.md) so an aggregator run report reads the same as the
// hostile-QA reports the dashboard already renders:
//
//   - PASS         — the oracle's expectation held.
//   - DEGRADED     — it held, but with reduced margin (e.g. a readback that
//     converged only near the end of its SLA): worth flagging,
//     not a failure.
//   - FAIL         — the expectation was violated: a real finding (a control
//     that never converged, a denial that leaked write access, a
//     curtailment that never reverted).
//   - BLIND        — the campaign could not see what it needed to judge (a
//     target point that never returned a value): a coverage gap.
//   - INCONCLUSIVE — a setup/transport problem prevented a verdict (the session
//     broke, the target would not connect, or no step of the
//     judged kind ran).
type Verdict string

// The campaign verdict set. Kept byte-identical to the Mayhem set so both QA
// drivers speak one verdict language to the dashboard and to CI gates.
const (
	VerdictPass         Verdict = "PASS"
	VerdictDegraded     Verdict = "DEGRADED"
	VerdictFail         Verdict = "FAIL"
	VerdictBlind        Verdict = "BLIND"
	VerdictInconclusive Verdict = "INCONCLUSIVE"
)

// ValidVerdict reports whether v is one of the five recognised verdicts — used
// to validate a campaign's expected_verdicts at load time.
func ValidVerdict(v Verdict) bool {
	switch v {
	case VerdictPass, VerdictDegraded, VerdictFail, VerdictBlind, VerdictInconclusive:
		return true
	}
	return false
}

// verdictSeverity ranks verdicts so an oracle folding several per-step outcomes
// into one campaign verdict can keep the WORST. FAIL is the loudest signal a QA
// driver can raise; a can't-observe INCONCLUSIVE outranks a mere DEGRADED
// (better to report "we could not judge" than to imply a soft pass); PASS is the
// quietest. Callers use worse() rather than comparing the strings directly.
func verdictSeverity(v Verdict) int {
	switch v {
	case VerdictFail:
		return 4
	case VerdictInconclusive:
		return 3
	case VerdictBlind:
		return 2
	case VerdictDegraded:
		return 1
	case VerdictPass:
		return 0
	}
	return 3 // an unknown verdict is treated as inconclusive, never a silent PASS
}

// worse returns whichever of a, b is the more severe verdict (see
// verdictSeverity). An empty verdict (no judgment yet) loses to any real one.
func worse(a, b Verdict) Verdict {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if verdictSeverity(b) > verdictSeverity(a) {
		return b
	}
	return a
}

// verdictIn reports whether v is listed in the campaign's expected_verdicts. An
// empty list means "no expectation declared" and always reports true, so a
// campaign that omits expected_verdicts never trips the CI gate — matching the
// Mayhem convention where expected_verdicts is documentation the runner may
// enforce, not a mandatory field.
func verdictIn(v Verdict, expected []Verdict) bool {
	if len(expected) == 0 {
		return true
	}
	for _, e := range expected {
		if e == v {
			return true
		}
	}
	return false
}
