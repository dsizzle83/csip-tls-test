package bundle

// reportbanner_test.go — the rendering pin for REPORT.md's result banner.

import (
	"strings"
	"testing"
)

// bundleWith builds a bundle of the given cases with the minimum a report needs.
func bundleWith(cases ...TestCaseResult) *Bundle {
	return &Bundle{Cases: cases}
}

// TestReportBanner_InformativeFailIsNotNoFailures is gate finding D1-b.
//
// A bundle whose ONLY failure is non-certifiable is a clean run by the
// certification criterion — b.OK() is true and should be — but it is NOT a run
// with no failures, and the banner must not say so.
func TestReportBanner_InformativeFailIsNotNoFailures(t *testing.T) {
	b := bundleWith(
		TestCaseResult{ID: "csip-conf-v1.3::BASIC-006", Applicable: true, Verdict: Pass},
		TestCaseResult{ID: "local-ext-v1::EXT-001", Applicable: true, NonCertifiable: true, Verdict: Fail},
	)
	if !b.OK() {
		t.Fatal("a bundle whose only FAIL is non-certifiable is not OK; the claim criterion is wrong")
	}
	md := b.Report()

	if strings.Contains(md, "✓ No failures.") {
		t.Errorf("REPORT.md claims '✓ No failures.' over a report whose own headline counts one:\n%s",
			firstLines(md, 14))
	}
	// The split branch's wording — correct, and previously unreachable here.
	if !strings.Contains(md, "1 test case(s) FAILED") {
		t.Errorf("REPORT.md does not state the failure count:\n%s", firstLines(md, 14))
	}
	if !strings.Contains(md, "0 applicable to the claim, 1 informative") {
		t.Errorf("REPORT.md does not attribute the failure to the informative half:\n%s", firstLines(md, 14))
	}
}

// TestReportBanner_NoFailuresStillSaysSo is the other side: the banner must
// still appear when there genuinely are none, or the fix would have traded one
// wrong statement for another.
func TestReportBanner_NoFailuresStillSaysSo(t *testing.T) {
	b := bundleWith(
		TestCaseResult{ID: "csip-conf-v1.3::BASIC-006", Applicable: true, Verdict: Pass},
		TestCaseResult{ID: "local-ext-v1::EXT-001", Applicable: true, NonCertifiable: true, Verdict: Pass},
	)
	if md := b.Report(); !strings.Contains(md, "✓ No failures.") {
		t.Errorf("REPORT.md withholds the clean banner from a bundle with no failures at all:\n%s",
			firstLines(md, 14))
	}
}

// TestReportBanner_ApplicableFailIsUnchanged pins that a real conformance
// failure still reads as one.
func TestReportBanner_ApplicableFailIsUnchanged(t *testing.T) {
	b := bundleWith(
		TestCaseResult{ID: "csip-conf-v1.3::BASIC-006", Applicable: true, Verdict: Fail},
	)
	md := b.Report()
	if strings.Contains(md, "✓ No failures.") {
		t.Error("REPORT.md claims no failures over a failing applicable case")
	}
	if !strings.Contains(md, "1 test case(s) FAILED") {
		t.Errorf("REPORT.md does not report the applicable failure:\n%s", firstLines(md, 14))
	}
}

// TestReportBanner_InformativeBulletNamesBothTags — the bullet used to promise
// rows were marked `info` while a local-extension row is tagged `local-ext`, so
// a reader following the instruction found nothing.
func TestReportBanner_InformativeBulletNamesBothTags(t *testing.T) {
	b := bundleWith(
		TestCaseResult{ID: "csip-conf-v1.3::BASIC-006", Applicable: true, Verdict: Pass},
		TestCaseResult{ID: "local-ext-v1::EXT-001", Applicable: true, NonCertifiable: true, Verdict: Pass},
	)
	md := b.Report()
	for _, tag := range []string{informativeTag, localExtTag} {
		if !strings.Contains(md, "`"+tag+"`") {
			t.Errorf("the Informative bullet does not name the %q tag a reader must look for:\n%s",
				tag, firstLines(md, 14))
		}
	}
	// And the row really does carry the tag the bullet promises.
	if !strings.Contains(md, "| "+localExtTag+" |") {
		t.Errorf("no row is tagged %q in the table:\n%s", localExtTag, md)
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// ── The bundle's own claim rule (gate finding D1-c) ──────────────────────────

// TestBundleOK_ExcludesNonCertifiableFailures pins the BUNDLE half of the rule
// certify.RunReport.OK applies to the live run.
//
// The two must agree, and only the runner's half was pinned. That is the wrong
// half to leave undefended: the bundle is the SHIPPED ARTIFACT — the thing a
// third party re-verifies months later, long after the run that produced it is
// gone — so a divergence here is a divergence nobody is present to notice.
func TestBundleOK_ExcludesNonCertifiableFailures(t *testing.T) {
	b := bundleWith(
		TestCaseResult{ID: "csip-conf-v1.3::BASIC-006", Applicable: true, Verdict: Pass},
		TestCaseResult{ID: "local-ext-v1::EXT-001", Applicable: true, NonCertifiable: true, Verdict: Fail},
	)
	if !b.OK() {
		t.Error("a bundle whose only FAIL is on a row NO PUBLISHED PROCEDURE COVERS is not OK. The " +
			"clean-run criterion is stated over a specification; a row that specification does not " +
			"contain cannot decide it")
	}
	// The failure is re-attributed, never hidden.
	_, fail, _, _ := b.Counts()
	if fail != 1 {
		t.Errorf("Counts() = %d FAIL, want 1", fail)
	}
	app, inf := b.CountsByClaim()
	if app.Fail != 0 || inf.Fail != 1 {
		t.Errorf("CountsByClaim = %d applicable / %d informative FAIL, want 0 / 1", app.Fail, inf.Fail)
	}
}

// TestBundleOK_StillFailsOnACertifiableFailure is the teeth: the exclusion must
// never swallow a real conformance failure.
func TestBundleOK_StillFailsOnACertifiableFailure(t *testing.T) {
	b := bundleWith(
		TestCaseResult{ID: "csip-conf-v1.3::BASIC-006", Applicable: true, Verdict: Fail},
		TestCaseResult{ID: "local-ext-v1::EXT-001", Applicable: true, NonCertifiable: true, Verdict: Pass},
	)
	if b.OK() {
		t.Fatal("a bundle with a failing published, applicable procedure reports OK")
	}
}

// TestBundleBearsOnClaim_ReadsBothFacts is the direct pin on the predicate the
// two functions above share. Mutating it to ignore NonCertifiable — the exact
// mutation that left the tree green before this row existed — fails here.
func TestBundleBearsOnClaim_ReadsBothFacts(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    TestCaseResult
		want bool
	}{
		{"applicable, covered by a procedure", TestCaseResult{Applicable: true}, true},
		{"applicable, covered by NO procedure",
			TestCaseResult{Applicable: true, NonCertifiable: true}, false},
		{"inapplicable", TestCaseResult{Applicable: false}, false},
		{"inapplicable and non-certifiable",
			TestCaseResult{Applicable: false, NonCertifiable: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.BearsOnClaim(); got != tc.want {
				t.Errorf("BearsOnClaim() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBundleAndRunnerAgreeOnTheClaimRule states the invariant the two halves
// exist to keep, in one place, so a future edit to either is a visible
// divergence rather than a silent one.
//
// It is a truth table rather than a cross-package call: internal/certify imports
// this package, so this package cannot import it back, and a rule asserted on
// both sides of an import cycle has to be asserted twice. The runner's half is
// certify.TestBearsOnClaim_SeparatesTheSpecificationFromTheProduct — the two
// tables must stay identical, and this comment is the pointer between them.
func TestBundleAndRunnerAgreeOnTheClaimRule(t *testing.T) {
	type row struct{ applicable, nonCertifiable, bears bool }
	for _, r := range []row{
		{applicable: true, nonCertifiable: false, bears: true},
		{applicable: true, nonCertifiable: true, bears: false},
		{applicable: false, nonCertifiable: false, bears: false},
		{applicable: false, nonCertifiable: true, bears: false},
	} {
		c := TestCaseResult{Applicable: r.applicable, NonCertifiable: r.nonCertifiable}
		if got := c.BearsOnClaim(); got != r.bears {
			t.Errorf("applicable=%v nonCertifiable=%v: BearsOnClaim=%v, want %v — and if this row is the "+
				"one that changed, certify.Case.BearsOnClaim must change with it or the live run and the "+
				"bundle it writes will disagree about which failures were certification failures",
				r.applicable, r.nonCertifiable, got, r.bears)
		}
	}
}
