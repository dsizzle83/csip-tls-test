package certify

// report.go is the console reporter, in the house style of
// sim/ssm-conformance/report.go: one ✓ PASS / ✗ FAIL / · SKIP / ⚠ WARN line per
// test case, a running tally, and a final summary whose acceptance line is
// "ALL TEST CASES ADDRESSED".
//
// That acceptance line is the point. Any harness can print a tally of the tests
// it chose to run. What a certification reviewer needs to know is whether the
// tool ran everything the standard contains — so the summary refuses to print
// the clean line while any APPLICABLE selected case has no implementation, and
// names the missing uids instead. An omission is a finding, printed with the
// same prominence as a failure.
//
// It also emits the markdown sections the bundle carries: COVERAGE.md, and a
// section that slots into the repository's CONFORMANCE_REPORT.md unchanged.

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Reporter writes the live log.
type Reporter struct {
	w       io.Writer
	started time.Time
	counts  map[Verdict]int
	seen    int
	// provisional records the verdict each case was PRINTED with during the
	// live phase, so Reconcile can name the ones the citation phase moved.
	provisional map[string]Verdict
}

// NewReporter tees the run log to w.
func NewReporter(w io.Writer) *Reporter {
	return &Reporter{w: w, started: time.Now(), counts: map[Verdict]int{}}
}

func (r *Reporter) printf(format string, a ...any) {
	if r.w == nil {
		return
	}
	fmt.Fprintf(r.w, format, a...)
}

// Line writes a framework-level status line.
func (r *Reporter) Line(format string, a ...any) { r.printf("  · "+format+"\n", a...) }

const rule = 78

// Header prints the run banner.
func (r *Reporter) Header(run *Runner, rep *RunReport) {
	total, applicable, implemented, missing := rep.Coverage.Totals()
	r.printf("%s\n", strings.Repeat("═", rule))
	r.printf("CSIP / SUNSPEC CONFORMANCE EVIDENCE RUN\n")
	r.printf("%s\n", strings.Repeat("─", rule))
	r.printf("Catalog:      %s\n", rep.Catalog.Source)
	r.printf("              sha256 %s · %d cases · %d document(s)\n",
		rep.Catalog.SHA256, rep.Catalog.Cases, len(rep.Catalog.Docs))
	r.printf("Selected:     %d case(s) — %d applicable, %d implemented, %d unimplemented\n",
		total, applicable, implemented, missing)
	if run != nil {
		r.printf("DUT:          %s\n", orNone(run.opts.Targets.Gateway))
		if !run.opts.NoCapture {
			r.printf("Capture:      %s%s\n", run.opts.Iface, filterSuffix(run.opts.BPF))
		}
		if run.opts.KeyLogPath != "" {
			r.printf("Key log:      %s\n", run.opts.KeyLogPath)
		}
		r.printf("Out:          %s\n", orNone(run.opts.OutDir))
	}
	r.printf("Date:         %s\n", time.Now().UTC().Format(time.RFC3339))
	r.printf("%s\n", strings.Repeat("═", rule))
	if rep.DryRun {
		r.printf("DRY RUN — nothing will be executed and no bundle will be written.\n")
	}
}

func filterSuffix(bpf string) string {
	if bpf == "" {
		return " (no filter)"
	}
	return " filter " + bpf
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// PlanListing prints what a dry run would execute.
func (r *Reporter) PlanListing(plan []Planned) {
	r.printf("\n%s\nPLAN — %d case(s) in execution order\n%s\n", strings.Repeat("─", rule), len(plan), strings.Repeat("─", rule))
	doc := ""
	for _, p := range plan {
		if p.Case.Doc != doc {
			doc = p.Case.Doc
			r.printf("\n[%s]\n", doc)
		}
		switch {
		case !p.Implemented:
			r.printf("  ·          %-14s %-52s  %s\n", p.Case.ID, trunc(p.Case.Title, 52), p.Skip)
		case p.Skip != "":
			r.printf("  · skip     %-14s %-52s  %s\n", p.Case.ID, trunc(p.Case.Title, 52), p.Skip)
		default:
			r.printf("  → run      %-14s %-52s  [%s]\n", p.Case.ID, trunc(p.Case.Title, 52), p.Registration.Suite)
		}
	}
	r.printf("\n")
}

// ExecutionBanner announces the case lines and states plainly that they are
// PROVISIONAL.
//
// They have to be. The line is printed the moment a check returns, which is
// before the capture has been stopped and long before the citation phase has
// re-derived each criterion from the pcap — and the citation phase can only
// make a verdict worse. A console that printed those numbers as final and a
// summary that printed different ones is a tool disagreeing with itself in
// front of the person who has to defend the run: 11 FAIL on screen and 17 in
// the summary, in run 20260726T225512. Reconcile prints the differences once
// they are known.
func (r *Reporter) ExecutionBanner() {
	r.printf("\n%s\n", strings.Repeat("─", rule))
	r.printf("EXECUTION — the verdict on each line below is PROVISIONAL\n")
	r.printf("%s\n", strings.Repeat("─", rule))
	r.printf("  Each line is printed when the check returns, from what its own socket saw. The\n")
	r.printf("  CITATION phase then re-derives every criterion from the capture, which can only\n")
	r.printf("  lower a verdict. The reconciliation below the last line, and the summary after\n")
	r.printf("  it, are the final word.\n")
}

// Case prints one test case's PROVISIONAL verdict line and updates the running
// tally. See ExecutionBanner.
func (r *Reporter) Case(res CaseResult) {
	r.seen++
	r.counts[res.Verdict]++
	if r.provisional == nil {
		r.provisional = map[string]Verdict{}
	}
	r.provisional[res.Case.UID] = res.Verdict
	pass, fail, skip, warn := r.counts[Pass], r.counts[Fail], r.counts[Skip], r.counts[Warn]
	detail := res.Notes
	if detail == "" && len(res.Assertions) > 0 {
		detail = res.Assertions[0].Observed
	}
	frames := ""
	if res.FrameSet != nil && len(res.FrameSet.Frames) > 0 {
		frames = fmt.Sprintf(" frames %s", res.FrameSet.Span())
	}
	r.printf("  %s~ %-32s %-46s [%d/%d/%d/%d]%s\n",
		Glyph(res.Verdict), res.Case.UID, trunc(oneLine(detail), 46), pass, fail, skip, warn, frames)
}

// Reconcile prints every case whose verdict changed between the provisional
// line and the bundle, and says which one stands.
//
// Printing nothing when nothing moved is deliberate: the block is a signal, and
// a signal that appears on every run is not one.
func (r *Reporter) Reconcile(rep *RunReport) {
	type change struct {
		uid      string
		from, to Verdict
		why      string
	}
	var changes []change
	for _, c := range rep.Cases {
		was, ok := r.provisional[c.Case.UID]
		if !ok || was == c.Verdict {
			continue
		}
		changes = append(changes, change{uid: c.Case.UID, from: was, to: c.Verdict, why: c.Reconciled})
	}
	if len(changes) == 0 {
		return
	}
	r.printf("\n%s\nVERDICT RECONCILIATION — %d case(s) changed after the citation phase\n%s\n",
		strings.Repeat("─", rule), len(changes), strings.Repeat("─", rule))
	r.printf("  The provisional line came from what the check's own socket saw. The verdict\n")
	r.printf("  below came from re-deriving the same criteria out of the capture, which is the\n")
	r.printf("  only evidence a reader of the bundle has. Where they differ, the capture wins.\n\n")
	for _, ch := range changes {
		r.printf("  %-32s %s  →  %s\n", ch.uid, Glyph(ch.from), Glyph(ch.to))
		if ch.why != "" {
			r.printf("      %s\n", trunc(oneLine(ch.why), rule-8))
		}
	}
	r.printf("\n")
}

// Glyph is the house-style marker for a verdict.
func Glyph(v Verdict) string {
	switch v {
	case Pass:
		return "✓ PASS"
	case Fail:
		return "✗ FAIL"
	case Warn:
		return "⚠ WARN"
	case Skip:
		return "· SKIP"
	default:
		return "? ????"
	}
}

// CoverageListing prints the coverage of the standard.
func (r *Reporter) CoverageListing(cov Coverage) {
	r.printf("%s\nCOVERAGE OF THE STANDARD\n%s\n", strings.Repeat("─", rule), strings.Repeat("─", rule))
	for _, d := range cov.Docs {
		r.printf("\n  %s (%s)\n", d.Doc, d.Version)
		r.printf("    %d case(s) selected · %d applicable · %d implemented · %d NOT implemented · %d inapplicable\n",
			d.Total, d.Applicable, len(d.Implemented), len(d.Unimplemented), len(d.Inapplicable))
		for _, e := range d.Unimplemented {
			r.printf("      ✗ NOT IMPLEMENTED  %-14s %-46s (%s, %s)\n",
				e.ID, trunc(e.Title, 46), e.DUTRole, e.Automatable)
		}
	}
	if len(cov.Orphans) > 0 {
		r.printf("\n  ✗ %d REGISTERED UID(S) ARE NOT IN THE CATALOG: %s\n",
			len(cov.Orphans), strings.Join(cov.Orphans, ", "))
	}
	r.printf("\n")
}

// Summary prints the final tally and the acceptance line. It returns true when
// the run is clean: every applicable case addressed, no failures, no
// capture-integrity problem.
func (r *Reporter) Summary(rep *RunReport) bool {
	pass, fail, skip, warn := rep.Counts()
	missing := rep.Unaddressed()

	r.printf("\n%s\nCONFORMANCE RUN SUMMARY\n%s\n", strings.Repeat("═", rule), strings.Repeat("═", rule))
	r.printf("  Catalog:      %s (sha256 %s)\n", rep.Catalog.Source, short(rep.Catalog.SHA256, 16))
	r.printf("  Test cases:   %d\n", len(rep.Cases))
	r.printf("  PASS:         %d\n", pass)
	r.printf("  FAIL:         %d\n", fail)
	r.printf("  SKIP:         %d  (addressed, not assertable here — see the reason on each)\n", skip)
	r.printf("  WARN:         %d\n", warn)
	if rep.Capture.Packets > 0 {
		r.printf("  Capture:      %d frames, %d bytes, %s\n",
			rep.Capture.Packets, rep.Capture.FileBytes, rep.Capture.Format)
	}
	if rep.Attribution != nil {
		r.printf("  Attribution:  %s\n", rep.Attribution.Summary())
	}
	if rep.BundleDir != "" {
		r.printf("  Bundle:       %s\n", rep.BundleDir)
	}

	for _, p := range rep.CaptureProblems {
		r.printf("\n  ⚠ CAPTURE INTEGRITY: %s\n", p)
	}
	if len(missing) > 0 {
		r.printf("\n  ✗ %d APPLICABLE TEST CASE(S) NOT ADDRESSED — no suite implements them:\n", len(missing))
		for _, e := range missing {
			r.printf("      %-14s %s\n", e.UID, trunc(e.Title, 56))
		}
	}
	if len(rep.Coverage.Orphans) > 0 {
		r.printf("\n  ✗ %d REGISTERED UID(S) ARE NOT IN THE CATALOG: %s\n",
			len(rep.Coverage.Orphans), strings.Join(rep.Coverage.Orphans, ", "))
	}
	var downgraded []string
	for _, c := range rep.Cases {
		if c.Downgraded != "" {
			downgraded = append(downgraded, c.Case.UID)
		}
	}
	if len(downgraded) > 0 {
		r.printf("\n  ⚠ %d verdict(s) were downgraded for want of a re-checkable citation: %s\n",
			len(downgraded), strings.Join(downgraded, ", "))
	}

	ok := rep.OK()
	switch {
	case len(missing) > 0 || len(rep.Coverage.Orphans) > 0:
		r.printf("\n  ✗ INCOMPLETE — the standard is not fully addressed by this run\n")
	case fail > 0:
		r.printf("\n  ✗ %d TEST CASE(S) FAILED — review the bundle for the cited frames\n", fail)
	case len(rep.CaptureProblems) > 0:
		r.printf("\n  ⚠ ALL TEST CASES ADDRESSED, 0 FAILURES — but the capture has integrity findings\n")
	default:
		r.printf("\n  ✓ ALL TEST CASES ADDRESSED, 0 FAILURES\n")
	}
	r.printf("%s\n\n", strings.Repeat("═", rule))
	return ok
}

// CoverageMarkdown renders COVERAGE.md: the "coverage of the standard"
// deliverable, per document, naming what is implemented and what is not.
func CoverageMarkdown(cov Coverage) string {
	var b strings.Builder
	total, applicable, implemented, missing := cov.Totals()
	fmt.Fprintf(&b, "# Coverage of the conformance catalog\n\n")
	fmt.Fprintf(&b, "**Catalog:** `%s`  \n**sha256:** `%s`  \n**Cases:** %d\n\n",
		cov.Catalog.Source, cov.Catalog.SHA256, cov.Catalog.Cases)
	fmt.Fprintf(&b, "This run selected **%d** test case(s): %d applicable to this product, "+
		"%d with an implementation, **%d applicable with none**.\n\n", total, applicable, implemented, missing)
	if missing == 0 && len(cov.Orphans) == 0 {
		fmt.Fprintf(&b, "> ✓ Every applicable selected test case has an implementation.\n\n")
	} else {
		fmt.Fprintf(&b, "> ✗ The tool does not cover the whole selection. The gaps are listed below "+
			"by name; nothing has been omitted silently.\n\n")
	}

	for _, d := range cov.Docs {
		fmt.Fprintf(&b, "## %s (%s)\n\n", d.Doc, d.Version)
		fmt.Fprintf(&b, "%d selected · %d applicable · %d implemented · %d unimplemented · %d inapplicable\n\n",
			d.Total, d.Applicable, len(d.Implemented), len(d.Unimplemented), len(d.Inapplicable))

		if len(d.Implemented) > 0 {
			fmt.Fprintf(&b, "### Implemented\n\n| Case | Title | Suite | Role | Automatable |\n")
			fmt.Fprintf(&b, "|------|-------|-------|------|-------------|\n")
			for _, e := range d.Implemented {
				fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
					e.ID, md(e.Title), e.Suite, e.DUTRole, e.Automatable)
			}
			fmt.Fprintf(&b, "\n")
		}
		if len(d.Unimplemented) > 0 {
			fmt.Fprintf(&b, "### NOT implemented — applicable, no check registered\n\n")
			fmt.Fprintf(&b, "| Case | Title | Role | Automatable |\n|------|-------|------|-------------|\n")
			for _, e := range d.Unimplemented {
				fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", e.ID, md(e.Title), e.DUTRole, e.Automatable)
			}
			fmt.Fprintf(&b, "\n")
		}
		if len(d.Inapplicable) > 0 {
			fmt.Fprintf(&b, "### Not applicable to this product\n\n")
			fmt.Fprintf(&b, "| Case | Title | Reason |\n|------|-------|--------|\n")
			for _, e := range d.Inapplicable {
				fmt.Fprintf(&b, "| `%s` | %s | %s |\n", e.ID, md(e.Title), md(firstSentence(e.Reason)))
			}
			fmt.Fprintf(&b, "\n")
		}
	}
	if len(cov.Orphans) > 0 {
		fmt.Fprintf(&b, "## Orphaned registrations\n\n")
		fmt.Fprintf(&b, "These uids have an implementation but no catalog record. The suite and the "+
			"catalog have diverged.\n\n")
		for _, o := range cov.Orphans {
			fmt.Fprintf(&b, "- `%s`\n", o)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

// MarkdownSection renders the run's section for CONFORMANCE_REPORT.md, in the
// same shape as the repository's other conformance sections so it appends
// cleanly.
func MarkdownSection(rep *RunReport) string {
	var b strings.Builder
	pass, fail, skip, warn := rep.Counts()
	fmt.Fprintf(&b, "## CSIP / SunSpec conformance evidence — %s\n\n", rep.Started.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "**Tool:** `%s` (internal/certify) driving the bench's own independent stacks — "+
		"the referee never uses the product's implementations (PN-1/C9/AD-003(f)).\n", ToolName)
	fmt.Fprintf(&b, "**Catalog:** `%s`, sha256 `%s`, %d extracted test cases.\n",
		rep.Catalog.Source, rep.Catalog.SHA256, rep.Catalog.Cases)
	if rep.Capture.Path != "" {
		fmt.Fprintf(&b, "**Capture:** `%s` — %d frames on %s.\n",
			rep.Capture.Path, rep.Capture.Packets, rep.Capture.Interface)
	}
	if rep.BundleDir != "" {
		fmt.Fprintf(&b, "**Bundle:** `%s` (verify with `sha256sum -c MANIFEST.sha256` plus the "+
			"evidence verifier).\n", rep.BundleDir)
	}
	fmt.Fprintf(&b, "\nResult: **%d PASS / %d FAIL / %d SKIP / %d WARN** across %d test case(s).\n\n",
		pass, fail, skip, warn, len(rep.Cases))

	byDoc := map[string][]CaseResult{}
	var order []string
	for _, c := range rep.Cases {
		if _, ok := byDoc[c.Case.Doc]; !ok {
			order = append(order, c.Case.Doc)
		}
		byDoc[c.Case.Doc] = append(byDoc[c.Case.Doc], c)
	}
	sort.Strings(order)
	for _, doc := range order {
		fmt.Fprintf(&b, "### %s\n\n", doc)
		fmt.Fprintf(&b, "| Case | Title | Verdict | Frames | Evidence |\n")
		fmt.Fprintf(&b, "|------|-------|---------|--------|----------|\n")
		for _, c := range byDoc[doc] {
			frames := "—"
			if c.FrameSet != nil {
				frames = c.FrameSet.Span()
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
				c.Case.ID, md(c.Case.Title), c.Verdict, frames, md(oneLine(evidenceSummary(c))))
		}
		fmt.Fprintf(&b, "\n")
	}

	missing := rep.Unaddressed()
	if len(missing) > 0 {
		fmt.Fprintf(&b, "### Not addressed\n\n")
		fmt.Fprintf(&b, "%d applicable test case(s) have no implementation. They are named here rather "+
			"than omitted, because an unstated gap in coverage is the one defect that would make this "+
			"report untrustworthy.\n\n", len(missing))
		for _, e := range missing {
			fmt.Fprintf(&b, "- `%s` — %s\n", e.UID, md(e.Title))
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

// evidenceSummary condenses a case's evidence for a table cell.
func evidenceSummary(c CaseResult) string {
	cited := 0
	for _, a := range c.Assertions {
		if a.Citable() {
			cited++
		}
	}
	switch {
	case c.Panic != "":
		return "suite panic — see the bundle"
	case c.Err != nil:
		return "not carried out: " + c.Err.Error()
	case len(c.Assertions) == 0:
		return orNone(c.Notes)
	default:
		return fmt.Sprintf("%d assertion(s), %d re-checkable; %s", len(c.Assertions), cited, c.Notes)
	}
}

func md(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
