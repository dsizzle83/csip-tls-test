package gwmayhem

// runner.go is the headless runner + gate: it lists the suite, filters by --only,
// runs each scenario through the arm→(perTick)→teardown→oracle lifecycle (the
// mayScenario run loop), folds the verdicts into a PASS/FAIL gate, and prints the
// evidence table. A scenario whose verdict falls OUTSIDE its pinned expected set is
// a gate failure (so a security-critical non-PASS trips the gate unless it is a
// documented, pinned gap), as is any spec load error — the binary exits non-zero,
// the CI contract.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// BatchSummary is the roll-up of a suite run.
type BatchSummary struct {
	Total        int             `json:"total"`
	ByVerdict    map[Verdict]int `json:"by_verdict"`
	GateFailures int             `json:"gate_failures"`
	Reports      []*gwReport     `json:"reports"`
	LoadErrors   []string        `json:"load_errors,omitempty"`

	// Declined counts the scenarios this MODE could not run at all, and DeclinedBy
	// groups them by reason (declineBench / declineBoard). They exist so the
	// roll-up can state the suite's size FOR THIS RUN rather than in the abstract:
	// a hermetic -loopback run reaches nine of thirty-eight scenarios, and a
	// denominator of thirty-eight makes that gate look four times larger than it
	// is. Applicable() is the number actually in play.
	Declined   int            `json:"declined"`
	DeclinedBy map[string]int `json:"declined_by,omitempty"`
}

// ListScenarios prints the suite (id, source, security, description) plus any spec
// load errors, mirroring `mayhem.py --list`. It runs nothing.
func ListScenarios(out io.Writer, scenarios []gwScenario, loadErrs []error) {
	fmt.Fprintf(out, "gw-mayhem: %d scenario(s)\n", len(scenarios))
	for _, sc := range scenarios {
		sec := " "
		if sc.Security {
			sec = "S"
		}
		fmt.Fprintf(out, "  [%-4s] %s %-32s %-8s %s\n", sc.Source, sec, sc.ID, listTags(sc), sc.Desc)
	}
	for _, e := range loadErrs {
		fmt.Fprintf(out, "  LOAD-ERR %v\n", e)
	}
	fmt.Fprint(out, modeCoverage(scenarios))
}

// modeCoverage states, before anyone runs anything, how much of the suite each
// run mode can actually reach. It exists because "gw-mayhem: 38 scenario(s)" is
// the number a reader carries away, and the documented hermetic invocation runs
// nine of them. A suite that does not say which mode reaches what invites its
// operators to read a hermetic GATE PASS as a whole-suite result.
func modeCoverage(scenarios []gwScenario) string {
	var hermetic, bench, board, ext int
	for _, sc := range scenarios {
		switch {
		case sc.NeedsBoard:
			board++
		case sc.NeedsBench:
			bench++
		default:
			hermetic++
		}
		if sc.Extended {
			ext++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\nreach by run mode (a scenario counts once, in the strongest thing it needs):\n")
	fmt.Fprintf(&b, "  %2d  -loopback (hermetic, no bench)\n", hermetic)
	fmt.Fprintf(&b, "  %2d  + the live bench: the sim admin APIs, or engines only the real gateway has [bench]\n", bench)
	fmt.Fprintf(&b, "  %2d  + a board mutation the orchestrator arms out of band [board]\n", board)
	if ext > 0 {
		fmt.Fprintf(&b, "  %2d  of the above are [ext] and are excluded from a default run unless -extended or -only names them\n", ext)
	}
	fmt.Fprintf(&b, "  why a [bench] scenario cannot run hermetically, one by one: qa/gw-scenarios/README.md\n")
	return b.String()
}

// listTags renders the run-mode tags for a scenario in the -list output:
// [bench] (needs the live bench), [board] (board-mutating), [ext] (Extended).
func listTags(sc gwScenario) string {
	var t []string
	if sc.NeedsBench {
		t = append(t, "bench")
	}
	if sc.NeedsBoard {
		t = append(t, "board")
	}
	if sc.Extended {
		t = append(t, "ext")
	}
	if len(t) == 0 {
		return ""
	}
	return "[" + strings.Join(t, ",") + "]"
}

// RunSuite runs the (optionally --only-filtered) scenarios against w, writing the
// per-scenario verdict lines + evidence table to out, and returns the BatchSummary.
// A spec load error is folded into the gate. extended opts an Extended (long
// boundary-dither) scenario into a default/full run; -only always overrides it (an
// explicit selection runs an Extended scenario regardless). jsonOut also dumps the
// summary as JSON.
func RunSuite(ctx context.Context, w *gwWorld, scenarios []gwScenario, loadErrs []error, only []string, extended, jsonOut bool, out io.Writer) BatchSummary {
	sum := BatchSummary{ByVerdict: map[Verdict]int{}}
	for _, e := range loadErrs {
		sum.LoadErrors = append(sum.LoadErrors, e.Error())
		sum.GateFailures++
		fmt.Fprintf(out, "LOAD-ERR  %v\n", e)
	}
	selected := selectScenarios(scenarios, only, extended)
	for i := range selected {
		if ctx.Err() != nil {
			break
		}
		rep := runScenario(ctx, w, selected[i])
		sum.Total++
		sum.ByVerdict[rep.Verdict]++
		if rep.Declined {
			sum.Declined++
			if sum.DeclinedBy == nil {
				sum.DeclinedBy = map[string]int{}
			}
			sum.DeclinedBy[rep.DeclineKind]++
		}
		sum.Reports = append(sum.Reports, rep)
		if !rep.VerdictExpected {
			sum.GateFailures++
		}
		fmt.Fprintln(out, scenarioLine(rep))
	}
	fmt.Fprint(out, evidenceTable(sum))
	fmt.Fprintln(out, rollupLine(sum))
	if jsonOut {
		if raw, err := json.MarshalIndent(sum, "", "  "); err == nil {
			fmt.Fprintln(out, string(raw))
		}
	}
	return sum
}

// runScenario executes one scenario end to end: arm the fault + sample, re-apply it
// per tick, tear it down, then judge the sampled evidence with the named oracle. It
// never panics out — an arm-time error is captured as SetupErr (the oracle turns
// that into INCONCLUSIVE), and a missing oracle is itself INCONCLUSIVE.
func runScenario(ctx context.Context, w *gwWorld, sc gwScenario) *gwReport {
	start := time.Now()
	// A bench-required scenario with no bench wired DECLINES — an expected
	// INCONCLUSIVE, not a gate failure. A -loopback :802-only run cannot drive the
	// HTTP sim admin APIs (wave-2) or exercise the real gateway's reversion /
	// exclusive-authority engines (wave-3 control-loop), and the loopback is a PEER,
	// not a gateway: it echoes registers, it does not reconcile a head-end control
	// onto a DER, so there is no honest way for it to stand in. The hermetic proof
	// is the pure-oracle unit tests (+ the httptest bench stub for wave-2). A live
	// run wires the bench, so the scenario runs for real.
	if sc.NeedsBench && !w.bench.benchReady() {
		return skipReport(sc, start, declineBench,
			"declined: needs the live bench (not wired in this run) — it judges an effect only the real gateway produces, so the "+
				"register-echo loopback cannot stand in; hermetic coverage is the pure-oracle unit tests (+ the bench stub for wave-2). "+
				"See qa/gw-scenarios/README.md")
	}
	// A BOARD-MUTATING scenario (family D) DECLINES until the ORCHESTRATOR arms its
	// mutation out of band and re-runs with -board-armed <id>. This suite never
	// mutates the board; the decline prints the exact hook to run.
	if sc.NeedsBoard && !w.isBoardArmed(sc.ID) {
		msg := "declined: BOARD-MUTATING — the orchestrator arms it out of band, then re-runs with -board-armed " + sc.ID
		if sc.Board != nil {
			msg += " | ARM: " + sc.Board.Arm + " | TEARDOWN: " + sc.Board.Teardown
		}
		return skipReport(sc, start, declineBoard, msg)
	}
	ev := &gwEvidence{Scenario: sc.ID}
	if sc.arm != nil {
		if err := sc.arm(ctx, w, ev); err != nil {
			ev.SetupErr = err.Error()
		}
	}
	for i := 0; i < sc.HoldTicks && sc.perTick != nil; i++ {
		if ctx.Err() != nil {
			break
		}
		sc.perTick(ctx, w, ev, i)
	}
	if sc.teardown != nil {
		sc.teardown(ctx, w)
	}

	verdict := VerdictInconclusive
	findings := []string{fmt.Sprintf("oracle %q not registered (have %s)", sc.oracle, registeredOracles())}
	if oracle, ok := oracleRegistry[sc.oracle]; ok {
		verdict, findings = oracle(ev)
	}

	expected := sc.Expected
	if len(expected) == 0 && sc.Security {
		expected = []Verdict{VerdictPass} // a security scenario defaults to "must PASS"
	}
	rep := &gwReport{
		ID: sc.ID, Desc: sc.Desc, Category: sc.Category, Source: sc.Source,
		Security: sc.Security, Verdict: verdict, Expected: expected,
		VerdictExpected: verdictIn(verdict, expected), Findings: findings,
		DurationS: time.Since(start).Seconds(),
	}
	// A spec scenario carries its full aggregator report; a Go scenario carries its
	// sampled evidence.
	if ev.Campaign != nil {
		rep.Campaign = ev.Campaign.report
	} else {
		rep.Evidence = ev
	}
	return rep
}

// skipReport builds the synthetic expected-INCONCLUSIVE report for a scenario the
// runner DECLINED to run in this mode (no bench wired, or a board mutation not
// armed) — never a gate failure, so a default run stays green while the decline
// explains what to wire or arm. kind (declineBench / declineBoard) is what lets
// the roll-up say how much of the suite this mode could not reach, instead of
// burying it in the same INCONCLUSIVE tally as a scenario that ran and saw
// nothing.
func skipReport(sc gwScenario, start time.Time, kind, finding string) *gwReport {
	return &gwReport{
		ID: sc.ID, Desc: sc.Desc, Category: sc.Category, Source: sc.Source,
		Security: sc.Security, Verdict: VerdictInconclusive, Expected: sc.Expected,
		VerdictExpected: true,
		Findings:        []string{finding},
		DurationS:       time.Since(start).Seconds(),
		Declined:        true,
		DeclineKind:     kind,
	}
}

// selectScenarios applies the -only filter and, absent it, the Extended exclusion.
// An explicit -only selection always wins (an Extended scenario named in -only
// runs); otherwise Extended scenarios are dropped unless extended opts them in.
func selectScenarios(scenarios []gwScenario, only []string, extended bool) []gwScenario {
	if len(only) > 0 {
		return filterOnly(scenarios, only)
	}
	return filterExtended(scenarios, extended)
}

// filterExtended drops Extended scenarios from a default/full run so a long
// boundary-dither walk cannot silently inflate every campaign's wall-clock time
// (mirrors the Mayhem rule, RSK-12). Pure, so the selection rule is unit-testable.
func filterExtended(scenarios []gwScenario, includeExtended bool) []gwScenario {
	if includeExtended {
		return scenarios
	}
	out := make([]gwScenario, 0, len(scenarios))
	for _, sc := range scenarios {
		if !sc.Extended {
			out = append(out, sc)
		}
	}
	return out
}

// filterOnly returns the scenarios whose IDs are in only (order = suite order); an
// empty only selects everything. Unknown ids are ignored (a caller typo runs
// nothing for that id, not a crash).
func filterOnly(scenarios []gwScenario, only []string) []gwScenario {
	if len(only) == 0 {
		return scenarios
	}
	want := make(map[string]bool, len(only))
	for _, id := range only {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	var out []gwScenario
	for _, sc := range scenarios {
		if want[sc.ID] {
			out = append(out, sc)
		}
	}
	return out
}

// scenarioLine is the one-line verdict for a scenario in the batch print.
func scenarioLine(rep *gwReport) string {
	tag := "ok       "
	if !rep.VerdictExpected {
		tag = fmt.Sprintf("UNEXPECTED(want %v)", rep.Expected)
	}
	sec := ""
	if rep.Security {
		sec = " [sec]"
	}
	// A declined scenario says so on its own line. Its verdict column reads
	// INCONCLUSIVE like any other non-observation, and without this marker the two
	// are indistinguishable at a glance — which is how 28 never-run scenarios came
	// to look like 28 attempted ones.
	if rep.Declined {
		sec += " [declined:" + rep.DeclineKind + "]"
	}
	return fmt.Sprintf("%-12s %-32s %-6s %.2fs  %s%s", rep.Verdict, rep.ID, rep.Source, rep.DurationS, tag, sec)
}

// evidenceTable renders the per-scenario evidence block (verdict, pinned set,
// findings) — the human artifact an operator reads without opening the JSON.
func evidenceTable(sum BatchSummary) string {
	var b strings.Builder
	b.WriteString("\n=== gw-mayhem evidence ===\n")
	for _, rep := range sum.Reports {
		pin := ""
		if len(rep.Expected) > 0 {
			pin = fmt.Sprintf(" expected=%v", rep.Expected)
		}
		flag := ""
		if !rep.VerdictExpected {
			flag = "  <-- OUTSIDE EXPECTED"
		}
		if rep.Declined {
			flag += "  [DECLINED: " + rep.DeclineKind + "]"
		}
		fmt.Fprintf(&b, "[%s] %s (%s/%s)%s%s\n", rep.Verdict, rep.ID, rep.Source, rep.Category, pin, flag)
		for _, f := range rep.Findings {
			fmt.Fprintf(&b, "    %s\n", f)
		}
	}
	return b.String()
}

// Asserted counts the scenarios that actually reached a judgement — PASS, FAIL
// or DEGRADED. BLIND and INCONCLUSIVE are non-assertions: the scenario did not
// run, or ran without being able to observe what it needed.
func (s BatchSummary) Asserted() int {
	return s.ByVerdict[VerdictPass] + s.ByVerdict[VerdictFail] + s.ByVerdict[VerdictDegraded]
}

// Applicable counts the scenarios this MODE could actually run — the selection
// minus the ones it declined. It is the honest denominator for the assertion
// count: "asserted 9/37" invites the reader to think 28 checks were attempted and
// came back unreadable, when in fact this mode never had 28 of them to run.
func (s BatchSummary) Applicable() int { return s.Total - s.Declined }

// declinedDetail renders the decline tally in suite order of severity of
// surprise: bench first (the large group), then board, then anything added later.
func declinedDetail(by map[string]int) string {
	if len(by) == 0 {
		return ""
	}
	label := map[string]string{
		declineBench: "need the live bench",
		declineBoard: "need a board mutation",
	}
	kinds := make([]string, 0, len(by))
	for k := range by {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		name := label[k]
		if name == "" {
			name = k
		}
		parts = append(parts, fmt.Sprintf("%d %s", by[k], name))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// rollupLine summarises the run: per-verdict tallies, how much of the selection
// actually asserted anything, and the gate outcome.
//
// ASSERTION FLOOR. A run in which NOTHING was asserted must not be able to print
// GATE PASS. Every scenario here can decline to run — a missing bench, an unwired
// sim admin API, a board mutation the orchestrator did not arm — and each of
// those lands as INCONCLUSIVE, which does not increment GateFailures. A run whose
// scenarios all declined therefore used to print the same "GATE PASS" as a run
// that exercised the whole suite, and the two are not remotely the same claim.
// That is the failure mode that makes a QA gate worse than no gate: it reports
// success for work it did not do, and the operator stops reading it.
//
// So the assertion count is ALWAYS printed (not just when it is bad), and a zero
// count is itself a gate failure with the reason spelled out. This is the
// gw-mayhem half of lexa-gw docs/ADVERSARIAL_QA_STRATEGY.md wave 1, "make the
// existing harnesses honest".
//
// THE DENOMINATOR. The assertion count used to be printed over the whole
// selection — "asserted 9/37" for the documented hermetic invocation. That
// denominator is not a measure of anything: 28 of those 37 are scenarios the
// hermetic mode never had to run, because they judge an effect only the real
// gateway produces. Reporting them alongside the nine it did run makes the gate
// look four times larger than it is, and buries a scenario that RAN and could not
// observe (a real signal, possibly a finding) in the same tally as 28 that were
// never applicable. The roll-up therefore states the mode's own size first —
// applicable, declined, and why — and scores the assertion count against the
// applicable set.
func rollupLine(sum BatchSummary) string {
	var parts []string
	for _, v := range []Verdict{VerdictPass, VerdictDegraded, VerdictFail, VerdictBlind, VerdictInconclusive} {
		if n := sum.ByVerdict[v]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, v))
		}
	}
	tally := strings.Join(parts, ", ")
	if tally == "" {
		tally = "no scenarios"
	}
	asserted, applicable := sum.Asserted(), sum.Applicable()
	gate := "GATE PASS"
	switch {
	case sum.GateFailures > 0:
		gate = fmt.Sprintf("GATE FAIL (%d)", sum.GateFailures)
	case sum.Total > 0 && applicable == 0:
		gate = "GATE FAIL (no scenario in this run mode was applicable — wire the bench or arm a board mutation)"
	case sum.Total > 0 && asserted == 0:
		gate = "GATE FAIL (nothing asserted — every applicable scenario declined to reach a judgement)"
	}
	return fmt.Sprintf("Roll-up: %d scenario(s) [%s] | applicable %d, declined %d%s | asserted %d/%d applicable | %s | %d load error(s)",
		sum.Total, tally, applicable, sum.Declined, declinedDetail(sum.DeclinedBy),
		asserted, applicable, gate, len(sum.LoadErrors))
}

// SortReportsByID sorts a summary's reports by ID (stable evidence ordering for a
// diff-friendly artifact).
func SortReportsByID(sum *BatchSummary) {
	sort.Slice(sum.Reports, func(i, j int) bool { return sum.Reports[i].ID < sum.Reports[j].ID })
}
