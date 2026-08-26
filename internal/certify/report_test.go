package certify

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func reportFixture(t *testing.T, verdicts map[string]Verdict, implemented []string) *RunReport {
	t.Helper()
	cat := loadTestCatalog(t)
	reg := NewRegistry()
	for _, uid := range implemented {
		reg.Register(uid, "suite", noopCheck)
	}
	rep := &RunReport{
		Catalog:  cat.Ref(),
		Coverage: reg.Coverage(cat, Filter{}),
		Started:  time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC),
	}
	for _, c := range cat.All() {
		v, ok := verdicts[c.UID]
		if !ok {
			continue
		}
		rep.Cases = append(rep.Cases, CaseResult{
			Case: c, Suite: "suite", Verdict: v, Executed: true,
			Assertions: []Assertion{{Claim: "c", Verdict: v, FramesSHA256: strings.Repeat("a", 64), Frames: []int{7}}},
			FrameSet:   &FrameSet{UID: c.UID, Frames: []int{7}, Precision: PrecisionConnection},
		})
	}
	return rep
}

// The acceptance line is the whole point of the summary: it must not appear
// while a case is unaddressed, however many others passed.
func TestSummaryRefusesTheCleanLineWithAGap(t *testing.T) {
	rep := reportFixture(t,
		map[string]Verdict{"doc-a::A-001": Pass},
		[]string{"doc-a::A-001"}) // A-002 and B-001 are applicable and unimplemented

	var buf bytes.Buffer
	ok := NewReporter(&buf).Summary(rep)
	out := buf.String()
	if ok {
		t.Error("Summary reported a clean run with unaddressed cases")
	}
	if strings.Contains(out, "ALL TEST CASES ADDRESSED") {
		t.Errorf("the clean acceptance line was printed with gaps:\n%s", out)
	}
	for _, want := range []string{"2 APPLICABLE TEST CASE(S) NOT ADDRESSED", "doc-a::A-002", "doc-b::B-001", "INCOMPLETE"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary does not contain %q:\n%s", want, out)
		}
	}
}

func TestSummaryCleanRun(t *testing.T) {
	rep := reportFixture(t,
		map[string]Verdict{"doc-a::A-001": Pass, "doc-a::A-002": Pass, "doc-a::A-003": Skip, "doc-b::B-001": Pass},
		[]string{"doc-a::A-001", "doc-a::A-002", "doc-a::A-003", "doc-b::B-001"})

	var buf bytes.Buffer
	ok := NewReporter(&buf).Summary(rep)
	if !ok {
		t.Errorf("a complete, failure-free run was not reported clean:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "✓ ALL TEST CASES ADDRESSED, 0 FAILURES") {
		t.Errorf("missing acceptance line:\n%s", buf.String())
	}
}

// TestHeadlineSplitsApplicableFromInformative pins Bug #5: the headline must not
// fold an INFORMATIVE FAIL (a row the suite implements but the product does not
// claim) into the same number as a claim-relevant FAIL. No verdict changes; only
// the grouping. Both the console summary and the REPORT.md carry the split.
func TestHeadlineSplitsApplicableFromInformative(t *testing.T) {
	rep := &RunReport{
		Started: time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC),
		Cases: []CaseResult{
			{Case: &Case{UID: "a", Doc: "doc-a", Applicable: true}, Verdict: Fail, Executed: true},
			{Case: &Case{UID: "b", Doc: "doc-a", Applicable: true}, Verdict: Pass, Executed: true},
			{Case: &Case{UID: "c", Doc: "doc-a", Applicable: false}, Verdict: Fail, Executed: true},
			{Case: &Case{UID: "d", Doc: "doc-a", Applicable: false}, Verdict: Skip, Executed: true},
		},
	}

	app, inf := rep.CountsByClaim()
	if app.Pass != 1 || app.Fail != 1 {
		t.Errorf("applicable split = %+v, want 1 PASS 1 FAIL", app)
	}
	if inf.Fail != 1 || inf.Skip != 1 {
		t.Errorf("informative split = %+v, want 1 FAIL 1 SKIP", inf)
	}

	var buf bytes.Buffer
	NewReporter(&buf).Summary(rep)
	out := buf.String()
	// The aggregate FAIL count stays truthful AND the split is shown.
	for _, want := range []string{
		"FAIL:         2",
		"applicable to the claim",
		"informative (implemented, not claimed)",
		"2 TEST CASE(S) FAILED (1 applicable to the claim, 1 informative",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("console summary missing %q:\n%s", want, out)
		}
	}

	md := MarkdownSection(rep)
	for _, want := range []string{
		"1 PASS / 2 FAIL",
		"Applicable to the claim: **1 PASS / 1 FAIL",
		"Informative (implemented, not claimed): **0 PASS / 1 FAIL",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown section missing %q:\n%s", want, md)
		}
	}
}

// A claim-only run (no informative rows) must NOT grow the split lines.
func TestHeadlineIsQuietWhenEveryRowIsApplicable(t *testing.T) {
	rep := &RunReport{
		Started: time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC),
		Cases: []CaseResult{
			{Case: &Case{UID: "a", Doc: "doc-a", Applicable: true}, Verdict: Pass, Executed: true},
			{Case: &Case{UID: "b", Doc: "doc-a", Applicable: true}, Verdict: Fail, Executed: true},
		},
	}
	var buf bytes.Buffer
	NewReporter(&buf).Summary(rep)
	if strings.Contains(buf.String(), "informative") {
		t.Errorf("the split appeared on a run with no informative rows:\n%s", buf.String())
	}
	if strings.Contains(MarkdownSection(rep), "Informative (implemented, not claimed)") {
		t.Error("the markdown split appeared on a claim-only run")
	}
}

func TestSummaryReportsFailuresAndCaptureProblems(t *testing.T) {
	rep := reportFixture(t,
		map[string]Verdict{"doc-a::A-001": Fail, "doc-a::A-002": Pass, "doc-a::A-003": Skip, "doc-b::B-001": Pass},
		[]string{"doc-a::A-001", "doc-a::A-002", "doc-a::A-003", "doc-b::B-001"})
	rep.CaptureProblems = []string{"stream x has CONFLICTING overlapping segments"}

	var buf bytes.Buffer
	if NewReporter(&buf).Summary(rep) {
		t.Error("a run with a FAIL was reported clean")
	}
	out := buf.String()
	if !strings.Contains(out, "1 TEST CASE(S) FAILED") {
		t.Errorf("failure not reported:\n%s", out)
	}
	if !strings.Contains(out, "CAPTURE INTEGRITY") {
		t.Errorf("capture integrity finding not reported:\n%s", out)
	}
}

func TestCaseLineShowsTheRunningTally(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf)
	cat := loadTestCatalog(t)
	c, _ := cat.ByUID("doc-a::A-001")
	r.Case(CaseResult{Case: c, Verdict: Pass, Notes: "ok", FrameSet: &FrameSet{Frames: []int{4, 5, 6}}})
	r.Case(CaseResult{Case: c, Verdict: Fail, Notes: "no CertificateRequest"})
	out := buf.String()
	if !strings.Contains(out, "✓ PASS") || !strings.Contains(out, "✗ FAIL") {
		t.Errorf("house-style glyphs missing:\n%s", out)
	}
	if !strings.Contains(out, "[1/0/0/0]") || !strings.Contains(out, "[1/1/0/0]") {
		t.Errorf("running tally missing:\n%s", out)
	}
	if !strings.Contains(out, "frames 4–6") {
		t.Errorf("frame span missing:\n%s", out)
	}
}

func TestCoverageMarkdownNamesTheGaps(t *testing.T) {
	cat := loadTestCatalog(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "tls", noopCheck)
	md := CoverageMarkdown(reg.Coverage(cat, Filter{}), nil)

	for _, want := range []string{
		cat.Ref().SHA256,
		"NOT implemented",
		"`A-002`",
		"`B-001`",
		"Not applicable to this product",
		"`A-003`",
		"Aggregator-client profile test.",
		"does not cover the whole selection",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("COVERAGE.md does not contain %q:\n%s", want, md)
		}
	}
}

func TestCoverageMarkdownCleanRun(t *testing.T) {
	cat := loadTestCatalog(t)
	reg := NewRegistry()
	for _, c := range cat.All() {
		reg.Register(c.UID, "all", noopCheck)
	}
	md := CoverageMarkdown(reg.Coverage(cat, Filter{}), nil)
	if !strings.Contains(md, "✓ Every applicable selected test case has an implementation") {
		t.Errorf("clean coverage not reported:\n%s", md)
	}
}

func TestMarkdownSectionListsGaps(t *testing.T) {
	rep := reportFixture(t, map[string]Verdict{"doc-a::A-001": Pass}, []string{"doc-a::A-001"})
	md := MarkdownSection(rep)
	for _, want := range []string{"### DOC-A", "`A-001`", "### Not addressed", "`doc-a::A-002`", rep.Catalog.SHA256} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown section does not contain %q:\n%s", want, md)
		}
	}
}

func TestTruncPreservesRunes(t *testing.T) {
	if got := trunc("señales de conformidad", 8); len([]rune(got)) != 8 {
		t.Errorf("trunc = %q (%d runes)", got, len([]rune(got)))
	}
	if got := trunc("short", 40); got != "short" {
		t.Errorf("trunc = %q", got)
	}
}

// TestConsoleAndBundleCannotSilentlyDisagree pins the reconciliation.
//
// The per-case line is printed the moment a check returns, from what its own
// socket saw. The citation phase then re-derives every criterion from the
// capture and can only make a verdict worse. Run 20260726T225512 printed 11 FAIL
// on screen and 17 in the summary, with nothing on the console explaining the
// difference — and logged SKIP for three REV cases the bundle published as FAIL.
func TestConsoleAndBundleCannotSilentlyDisagree(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf)
	cat := loadTestCatalog(t)
	c, _ := cat.ByUID("doc-a::A-001")

	r.ExecutionBanner()
	if out := buf.String(); !strings.Contains(out, "PROVISIONAL") {
		t.Errorf("the execution banner must say the case lines are provisional:\n%s", out)
	}

	// Printed provisionally as PASS...
	r.Case(CaseResult{Case: c, Verdict: Pass, Notes: "the socket saw a clean exchange"})
	// ...and the citation phase makes it a FAIL.
	rep := &RunReport{Cases: []CaseResult{{
		Case: c, Verdict: Fail, Executed: true, LiveVerdict: Pass,
		Reconciled: "the live phase declared PASS from what the socket saw; the citation phase re-derived " +
			"the criteria from the capture and the case is FAIL.",
	}}}
	r.Reconcile(rep)

	out := buf.String()
	if !strings.Contains(out, "VERDICT RECONCILIATION") {
		t.Fatalf("a verdict that moved after the citation phase was not reported:\n%s", out)
	}
	if !strings.Contains(out, "doc-a::A-001") {
		t.Errorf("the reconciliation does not name the case:\n%s", out)
	}
	if !strings.Contains(out, "✓ PASS") || !strings.Contains(out, "✗ FAIL") {
		t.Errorf("the reconciliation must show BOTH verdicts, or it explains nothing:\n%s", out)
	}
}

// TestReconcileIsSilentWhenNothingMoved: the block is a signal, and a signal
// that appears on every run is not one.
func TestReconcileIsSilentWhenNothingMoved(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf)
	cat := loadTestCatalog(t)
	c, _ := cat.ByUID("doc-a::A-001")
	r.Case(CaseResult{Case: c, Verdict: Pass})
	before := buf.Len()
	r.Reconcile(&RunReport{Cases: []CaseResult{{Case: c, Verdict: Pass, Executed: true, LiveVerdict: Pass}}})
	if buf.Len() != before {
		t.Errorf("Reconcile printed something when no verdict moved:\n%s", buf.String()[before:])
	}
}
