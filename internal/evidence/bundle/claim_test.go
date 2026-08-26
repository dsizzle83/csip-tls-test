package bundle

// claim_test.go pins the applicable/informative bucketing of REPORT.md.
//
// The bug it locks out: runs/certfix-validate-20260729T192416 announced
// "✗ 8 test case(s) FAILED" over a table in which AGG-009, AGG-012 and UTIL-002
// — three of the twenty-two aggregator-only rows the catalog marks
// applicable:false under the DER-Client claim — sat unmarked beside five
// claim-relevant failures. Nothing in the run was mis-scoped: the catalog flag
// was right, the runner carried it into every per-case record, and bundle.json
// held it. REPORT.md, the artefact an assessor actually reads, ignored it.

import (
	"strings"
	"testing"
)

// aggRow is one of the aggregator-only rows: implemented, run, not claimed.
func aggRow(id string, v Verdict) TestCaseResult {
	return TestCaseResult{ID: id, Doc: "CSIP-CONF-v1.3", Title: id + " title",
		Verdict: v, Applicable: false}
}

func claimRow(id string, v Verdict) TestCaseResult {
	return TestCaseResult{ID: id, Doc: "CSIP-CONF-v1.3", Title: id + " title",
		Verdict: v, Applicable: true}
}

// derClientRun is the shape of the campaign that exposed the bug: five
// claim-relevant FAILs and three informative ones.
func derClientRun() *Bundle {
	return &Bundle{Cases: []TestCaseResult{
		claimRow("BASIC-028", Fail), claimRow("BASIC-029", Fail), claimRow("CORE-009", Fail),
		claimRow("CORE-014", Fail), claimRow("ERR-001", Fail),
		claimRow("CORE-003", Pass), claimRow("COMM-003", Warn), claimRow("CORE-013", Skip),
		aggRow("AGG-009", Fail), aggRow("AGG-012", Fail), aggRow("UTIL-002", Fail),
		aggRow("AGG-001", Pass), aggRow("CORE-018", Warn), aggRow("UTIL-004", Skip),
	}}
}

func TestCountsByClaimBucketsAggregatorRowsAsInformative(t *testing.T) {
	app, inf := derClientRun().CountsByClaim()
	if app.Fail != 5 {
		t.Errorf("applicable FAIL = %d, want 5 (BASIC-028/029, CORE-009/014, ERR-001)", app.Fail)
	}
	if inf.Fail != 3 {
		t.Errorf("informative FAIL = %d, want 3 (AGG-009, AGG-012, UTIL-002)", inf.Fail)
	}
	if app.Total() != 8 || inf.Total() != 6 {
		t.Errorf("totals = %d applicable / %d informative, want 8 / 6", app.Total(), inf.Total())
	}
	// The split regroups; it must never lose or invent a case.
	pass, fail, skip, warn, _ := derClientRun().Counts()
	if app.Pass+inf.Pass != pass || app.Fail+inf.Fail != fail ||
		app.Skip+inf.Skip != skip || app.Warn+inf.Warn != warn {
		t.Error("the split does not add back up to the flat tally")
	}
}

func TestReportSeparatesTheInformativeFailures(t *testing.T) {
	report := derClientRun().Report()
	for _, want := range []string{
		"**Applicable to the claim:** 1 PASS · 5 FAIL · 1 SKIP · 1 WARN (8 in-scope case(s))",
		"1 PASS · 3 FAIL · 1 SKIP · 1 WARN (6 in-scope case(s))",
		"✗ 8 test case(s) FAILED — 5 applicable to the claim, 3 informative",
		"Only the applicable failures bear on the certification claim",
		"| AGG-009 | AGG-009 title | info | FAIL |",
		"| CORE-009 | CORE-009 title | yes | FAIL |",
		"**Informative row — NOT applicable to the certification claim.**",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("REPORT.md does not carry %q\n---\n%s", want, report)
		}
	}
	if strings.Contains(report, "%!") {
		t.Error("REPORT.md contains a formatting error")
	}
}

// A claim-only run must not grow the split: a bundle with nothing informative
// in it should read exactly as it did before.
func TestReportIsQuietWhenEveryRowIsApplicable(t *testing.T) {
	b := &Bundle{Cases: []TestCaseResult{claimRow("CORE-003", Pass), claimRow("ERR-001", Fail)}}
	report := b.Report()
	if strings.Contains(report, "Informative") || strings.Contains(report, "informative") {
		t.Errorf("the split appeared on a claim-only run:\n%s", report)
	}
	if !strings.Contains(report, "✗ 1 test case(s) FAILED.") {
		t.Errorf("the plain headline is missing:\n%s", report)
	}
}

// A clean run says so whichever bucket its rows are in.
func TestReportStaysCleanWithInformativePasses(t *testing.T) {
	b := &Bundle{Cases: []TestCaseResult{claimRow("CORE-003", Pass), aggRow("AGG-001", Pass)}}
	report := b.Report()
	if !strings.Contains(report, "✓ No failures.") {
		t.Errorf("a run with no FAIL must report clean:\n%s", report)
	}
	if !strings.Contains(report, "**Informative**") {
		t.Errorf("the informative row must still be disclosed:\n%s", report)
	}
}
