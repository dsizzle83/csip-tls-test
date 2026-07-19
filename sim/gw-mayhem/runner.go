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
	// A bench-required scenario with no bench wired is SKIPPED as an expected
	// INCONCLUSIVE, not a gate failure — a -loopback :802-only run cannot drive the
	// HTTP sim admin APIs (wave-2) or exercise the real gateway's reversion /
	// exclusive-authority engines (wave-3 control-loop), and the hermetic proof is
	// the pure-oracle unit tests (+ the bench stub for wave-2). A live run wires the
	// bench, so the scenario runs for real.
	if sc.NeedsBench && !w.bench.benchReady() {
		return skipReport(sc, start,
			"skipped: needs the live bench (not wired in this run) — hermetic coverage is the loopback + the pure-oracle unit tests")
	}
	// A BOARD-MUTATING scenario (family D) is SKIPPED until the ORCHESTRATOR arms its
	// mutation out of band and re-runs with -board-armed <id>. This suite never
	// mutates the board; the skip prints the exact hook to run.
	if sc.NeedsBoard && !w.isBoardArmed(sc.ID) {
		msg := "skipped: BOARD-MUTATING — the orchestrator arms it out of band, then re-runs with -board-armed " + sc.ID
		if sc.Board != nil {
			msg += " | ARM: " + sc.Board.Arm + " | TEARDOWN: " + sc.Board.Teardown
		}
		return skipReport(sc, start, msg)
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
// runner skips (no bench wired, or a board mutation not armed) — never a gate
// failure, so a default run stays green while the skip explains what to wire/arm.
func skipReport(sc gwScenario, start time.Time, finding string) *gwReport {
	return &gwReport{
		ID: sc.ID, Desc: sc.Desc, Category: sc.Category, Source: sc.Source,
		Security: sc.Security, Verdict: VerdictInconclusive, Expected: sc.Expected,
		VerdictExpected: true,
		Findings:        []string{finding},
		DurationS:       time.Since(start).Seconds(),
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
		fmt.Fprintf(&b, "[%s] %s (%s/%s)%s%s\n", rep.Verdict, rep.ID, rep.Source, rep.Category, pin, flag)
		for _, f := range rep.Findings {
			fmt.Fprintf(&b, "    %s\n", f)
		}
	}
	return b.String()
}

// rollupLine summarises the run: per-verdict tallies + the gate outcome.
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
	gate := "GATE PASS"
	if sum.GateFailures > 0 {
		gate = fmt.Sprintf("GATE FAIL (%d)", sum.GateFailures)
	}
	return fmt.Sprintf("Roll-up: %d scenario(s) [%s] | %s | %d load error(s)", sum.Total, tally, gate, len(sum.LoadErrors))
}

// SortReportsByID sorts a summary's reports by ID (stable evidence ordering for a
// diff-friendly artifact).
func SortReportsByID(sum *BatchSummary) {
	sort.Slice(sum.Reports, func(i, j int) bool { return sum.Reports[i].ID < sum.Reports[j].ID })
}
