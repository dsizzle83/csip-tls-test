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
		fmt.Fprintf(out, "  [%-4s] %s %-32s %s\n", sc.Source, sec, sc.ID, sc.Desc)
	}
	for _, e := range loadErrs {
		fmt.Fprintf(out, "  LOAD-ERR %v\n", e)
	}
}

// RunSuite runs the (optionally --only-filtered) scenarios against w, writing the
// per-scenario verdict lines + evidence table to out, and returns the BatchSummary.
// A spec load error is folded into the gate. jsonOut also dumps the summary as JSON.
func RunSuite(ctx context.Context, w *gwWorld, scenarios []gwScenario, loadErrs []error, only []string, jsonOut bool, out io.Writer) BatchSummary {
	sum := BatchSummary{ByVerdict: map[Verdict]int{}}
	for _, e := range loadErrs {
		sum.LoadErrors = append(sum.LoadErrors, e.Error())
		sum.GateFailures++
		fmt.Fprintf(out, "LOAD-ERR  %v\n", e)
	}
	selected := filterOnly(scenarios, only)
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
	// A wave-2 (bench-required) scenario with no bench wired is SKIPPED as an
	// expected INCONCLUSIVE, not a gate failure — a -loopback :802-only run cannot
	// drive the HTTP sim admin APIs, and its hermetic proof is the bench-stub unit
	// tests. Live runs pass the sims' admin URLs, so the scenario runs for real.
	if sc.NeedsBench && !w.bench.benchReady() {
		return &gwReport{
			ID: sc.ID, Desc: sc.Desc, Category: sc.Category, Source: sc.Source,
			Security: sc.Security, Verdict: VerdictInconclusive, Expected: sc.Expected,
			VerdictExpected: true,
			Findings:        []string{"skipped: no bench wired (wave-2 needs -gridsim-admin + the -inv-* DER sims; hermetic coverage is the bench-stub unit tests)"},
			DurationS:       time.Since(start).Seconds(),
		}
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
