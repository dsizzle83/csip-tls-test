package bundle

// notapplicable_test.go pins the verdict a row gets when it was never in scope,
// and the three rules that stop it becoming a way to make an inconvenient row
// disappear.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func naRow(id string, src NASource) TestCaseResult {
	return TestCaseResult{
		ID: id, Doc: "SSM-CONF-v0.8", Title: id + " title",
		Verdict: VerdictNotApplicable, Applicable: true,
		NotApplicable: &NotApplicable{
			Reason: "the candidate does not claim the Secure SunSpec CLIENT direction",
			Source: src,
			Detail: "secure_sunspec.roles = [server]",
		},
		Assertions: []Assertion{{
			Claim: "the test case is in scope for the candidate under test", Method: "scope declaration",
			Verdict: VerdictNotApplicable, Observed: "not claimed",
		}},
	}
}

// ── the vocabulary ────────────────────────────────────────────────────────

// N/A must never out-rank a measurement: it is the absence of an outcome, and
// an absence that could raise a roll-up would let a scope declaration overwrite
// a FAIL.
func TestNotApplicableSitsAtTheBottomOfTheSeverityOrder(t *testing.T) {
	if VerdictNotApplicable.Severity() != Skip.Severity() {
		t.Errorf("Severity(N/A) = %d, Severity(SKIP) = %d; both are the absence of an outcome",
			VerdictNotApplicable.Severity(), Skip.Severity())
	}
	for _, v := range []Verdict{Pass, Warn, Fail} {
		if VerdictNotApplicable.Severity() >= v.Severity() {
			t.Errorf("N/A out-ranks %s", v)
		}
	}
}

func TestRollUpOfAnAllNotApplicableCase(t *testing.T) {
	tc := naRow("RBAC-011", NASourceManifest)
	if got := tc.RollUp(); got != VerdictNotApplicable {
		t.Errorf("RollUp() = %s, want %s", got, VerdictNotApplicable)
	}
	// One N/A beside real assertions is a NOTE, not a scope declaration about
	// the case.
	tc.Assertions = append(tc.Assertions, Assertion{Verdict: Pass, Claim: "something was measured"})
	if got := tc.RollUp(); got != Pass {
		t.Errorf("RollUp() = %s with a PASS beside the N/A, want PASS", got)
	}
}

func TestCountsSeparateNotApplicableFromSkip(t *testing.T) {
	b := &Bundle{Cases: []TestCaseResult{
		{ID: "a", Verdict: Pass, Applicable: true},
		{ID: "b", Verdict: Skip, Applicable: true},
		naRow("c", NASourceManifest), naRow("d", NASourceCatalog),
	}}
	pass, fail, skip, warn, na := b.Counts()
	if pass != 1 || fail != 0 || skip != 1 || warn != 0 || na != 2 {
		t.Errorf("Counts() = %d/%d/%d/%d/%d, want 1/0/1/0/2", pass, fail, skip, warn, na)
	}
	app, _ := b.CountsByClaim()
	if app.NotApplicable != 2 || app.InScope() != 2 || app.Total() != 4 {
		t.Errorf("applicable tally = %+v; InScope=%d Total=%d", app, app.InScope(), app.Total())
	}
}

// A bundle every row of which was out of scope has established NOTHING, and must
// not report itself clean.
func TestOKIsFalseWhenEveryRowWasOutOfScope(t *testing.T) {
	all := &Bundle{Cases: []TestCaseResult{naRow("a", NASourceManifest), naRow("b", NASourceManifest)}}
	if all.OK() {
		t.Error("a bundle in which nothing was measured reported itself clean")
	}
	some := &Bundle{Cases: []TestCaseResult{naRow("a", NASourceManifest), {ID: "b", Verdict: Pass, Applicable: true}}}
	if !some.OK() {
		t.Error("a bundle with one pass and one out-of-scope row did not report clean")
	}
}

// ── verification ──────────────────────────────────────────────────────────

func writeBundleDir(t *testing.T, b *Bundle) string {
	t.Helper()
	dir := t.TempDir()
	if b.Schema == "" {
		b.Schema = SchemaVersion
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BundleFile), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func verifyProblems(t *testing.T, b *Bundle) []string {
	t.Helper()
	dir := writeBundleDir(t, b)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	rep := &VerifyReport{Dir: dir, OK: true}
	verifyCaseVerdicts(loaded, rep)
	return rep.Problems
}

func TestVerifyAcceptsAWellFormedNotApplicableRow(t *testing.T) {
	b := &Bundle{Cases: []TestCaseResult{naRow("RBAC-011", NASourceManifest)}}
	if p := verifyProblems(t, b); len(p) != 0 {
		t.Errorf("Verify rejected a well-formed N/A row: %v", p)
	}
}

func TestVerifyRefusesAnUnexplainedNotApplicable(t *testing.T) {
	cases := map[string]TestCaseResult{
		"no record": {ID: "x", Verdict: VerdictNotApplicable, Applicable: true},
		"empty reason": {ID: "x", Verdict: VerdictNotApplicable, Applicable: true,
			NotApplicable: &NotApplicable{Reason: "  ", Source: NASourceCatalog}},
		"unknown source": {ID: "x", Verdict: VerdictNotApplicable, Applicable: true,
			NotApplicable: &NotApplicable{Reason: "because", Source: "vibes"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := verifyProblems(t, &Bundle{Cases: []TestCaseResult{tc}})
			if len(p) == 0 {
				t.Fatal("Verify accepted an N/A a reader cannot check")
			}
		})
	}
}

// A row cannot be both graded and out of scope: a reader would not know which
// sentence to act on.
func TestVerifyRefusesAGradedRowCarryingAScopeRecord(t *testing.T) {
	tc := TestCaseResult{ID: "x", Verdict: Fail, Applicable: true,
		NotApplicable: &NotApplicable{Reason: "not claimed", Source: NASourceManifest}}
	p := verifyProblems(t, &Bundle{Cases: []TestCaseResult{tc}})
	if len(p) == 0 {
		t.Fatal("Verify accepted a FAIL that also declared itself out of scope")
	}
	if !strings.Contains(strings.Join(p, " "), "either out of scope or graded") {
		t.Errorf("the problem does not explain the contradiction: %v", p)
	}
}

// The scope declaration cannot launder a FAIL: the roll-up still runs.
func TestVerifyStillCatchesAFailLaunderedAsNotApplicable(t *testing.T) {
	tc := naRow("x", NASourceManifest)
	tc.Assertions = append(tc.Assertions, Assertion{Verdict: Fail, Claim: "the device did the thing"})
	p := verifyProblems(t, &Bundle{Cases: []TestCaseResult{tc}})
	if len(p) == 0 {
		t.Fatal("a FAIL assertion under an N/A heading verified clean")
	}
}

// ── schema ────────────────────────────────────────────────────────────────

// Every bundle in the archive must go on verifying.
func TestSchemaV1BundlesStillLoad(t *testing.T) {
	b := &Bundle{Schema: SchemaVersion1, Cases: []TestCaseResult{{ID: "a", Verdict: Pass, Applicable: true}}}
	dir := writeBundleDir(t, b)
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() = %v; every /1 bundle in the archive must still verify", err)
	}
	if loaded.Schema != SchemaVersion1 {
		t.Errorf("Schema = %q", loaded.Schema)
	}
	rep := &VerifyReport{Dir: dir, OK: true}
	verifyCaseVerdicts(loaded, rep)
	if len(rep.Problems) != 0 {
		t.Errorf("a /1 bundle raised problems: %v", rep.Problems)
	}
}

// A /1 bundle carrying /2 vocabulary was not written by the engine it claims.
func TestSchemaV1RefusesTheNotApplicableVerdict(t *testing.T) {
	b := &Bundle{Schema: SchemaVersion1, Cases: []TestCaseResult{naRow("x", NASourceManifest)}}
	p := verifyProblems(t, b)
	if len(p) == 0 {
		t.Fatal("a schema /1 bundle carrying an N/A verdict verified clean")
	}
	if !strings.Contains(strings.Join(p, " "), SchemaVersion) {
		t.Errorf("the problem does not name the schema that introduced the verdict: %v", p)
	}
}

func TestLoadRefusesAnUnknownSchema(t *testing.T) {
	b := &Bundle{Schema: "lexa-evidence-bundle/99", Cases: []TestCaseResult{{ID: "a", Verdict: Pass}}}
	dir := writeBundleDir(t, b)
	if _, err := Load(dir); err == nil {
		t.Fatal("Load() accepted a schema this verifier does not understand")
	}
}

func TestNewBundlesDeclareTheCurrentSchema(t *testing.T) {
	if SchemaVersion == SchemaVersion1 {
		t.Fatal("the schema was not bumped, so a /1-era verifier meeting an N/A verdict would report " +
			"its own age as a finding about the evidence")
	}
	bld := NewBuilder(RunMeta{Tool: "t"})
	bld.AddCase(naRow("x", NASourceCatalog))
	out, err := bld.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out.Schema != SchemaVersion {
		t.Errorf("written schema = %q, want %q", out.Schema, SchemaVersion)
	}
}

// ── the artefact a reviewer reads ─────────────────────────────────────────

func TestReportTalliesNotApplicableSeparately(t *testing.T) {
	b := &Bundle{Schema: SchemaVersion, Cases: []TestCaseResult{
		{ID: "a", Doc: "SSM-CONF-v0.8", Verdict: Pass, Applicable: true},
		naRow("RBAC-011", NASourceManifest),
	}}
	report := b.Report()
	for _, want := range []string{
		"across 1 in-scope test case(s)",
		"1 further case(s) are **NOT APPLICABLE**",
		"**NOT APPLICABLE — not run.**",
		"Declared by: `manifest`",
		"secure_sunspec.roles = [server]",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("REPORT.md does not carry %q\n---\n%s", want, report)
		}
	}
	if strings.Contains(report, "%!") {
		t.Error("REPORT.md contains a formatting error")
	}
}

func TestReportSaysSoWhenNothingWasMeasured(t *testing.T) {
	b := &Bundle{Schema: SchemaVersion, Cases: []TestCaseResult{naRow("a", NASourceManifest)}}
	report := b.Report()
	if !strings.Contains(report, "Nothing was measured") {
		t.Errorf("a bundle in which every row was out of scope still says 'No failures':\n%s", report)
	}
}

// A bundle with nothing out of scope must read exactly as it did before this
// verdict existed.
func TestReportIsUnchangedWithNoNotApplicableRows(t *testing.T) {
	b := &Bundle{Schema: SchemaVersion, Cases: []TestCaseResult{{ID: "a", Verdict: Pass, Applicable: true}}}
	report := b.Report()
	if strings.Contains(report, "NOT APPLICABLE") || strings.Contains(report, "not applicable") {
		t.Errorf("a bundle with no out-of-scope rows grew N/A prose:\n%s", report)
	}
	if !strings.Contains(report, "across 1 in-scope test case(s)") {
		t.Errorf("headline changed unexpectedly:\n%s", report)
	}
}
