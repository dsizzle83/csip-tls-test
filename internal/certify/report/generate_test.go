package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGenerateRefusesAnIncompleteSubmission is the guard that keeps a
// half-configured bench run from producing something that looks submittable.
func TestGenerateRefusesAnIncompleteSubmission(t *testing.T) {
	dir := t.TempDir()
	_, err := Generate(GenerateOptions{
		Dir: dir, CertType: CertTypeModbus, Config: &SubmissionConfig{},
		ModbusLogs: goodModbusLogs(),
	})
	if err == nil {
		t.Fatal("a submission with no lab or submitter metadata was written as if complete")
	}
	for _, want := range []string{"Certificate Number", "Test Laboratory", "Company Name"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q: %v", want, err)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, PublicDir, SummaryFile)); statErr == nil {
		t.Error("a SUMMARY.csv was written despite the refusal")
	}
}

// TestGenerateIncompleteUsesAnUnmistakableName: when the operator explicitly
// accepts an incomplete submission, the file name has to say so. A warning in a
// log is read once; a file name travels with the artefact.
func TestGenerateIncompleteUsesAnUnmistakableName(t *testing.T) {
	dir := t.TempDir()
	sub, err := Generate(GenerateOptions{
		Dir: dir, CertType: CertTypeModbus, Config: &SubmissionConfig{},
		ModbusLogs: goodModbusLogs(), AllowIncomplete: true, Tool: Tool,
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(sub.SummaryPath) != IncompleteFile {
		t.Errorf("summary written as %s, want %s", filepath.Base(sub.SummaryPath), IncompleteFile)
	}
	if sub.Complete {
		t.Error("the submission reported itself complete")
	}
	if sub.Readiness.Submittable() {
		t.Error("the readiness report called an unconfigured submission submittable")
	}
	md, err := os.ReadFile(filepath.Join(dir, ReadinessFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "NOT SUBMITTABLE") {
		t.Error("the readiness report does not say the submission is not submittable")
	}
	for _, want := range []string{"RPT-KV-2", "RPT-KV-11"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("the readiness report does not name the unmet requirement %s", want)
		}
	}
}

func TestGenerateSplitsPublicFromArchive(t *testing.T) {
	dir := t.TempDir()
	sub, err := Generate(GenerateOptions{
		Dir: dir, CertType: CertTypeModbus, Doc: DocModbus, Config: fullConfig(),
		Verdicts:   []TestVerdict{{ID: "MB-1", Verdict: "PASS"}, {ID: "EXC-3", Verdict: "PASS"}},
		ModbusLogs: goodModbusLogs(), Tool: Tool, ToolVersion: "test",
		Now: time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sub.Complete {
		t.Fatalf("missing %v problems %v", sub.Summary.MissingKeys(), sub.Summary.Problems)
	}
	if got := filepath.Base(sub.SummaryPath); got != SummaryFile {
		t.Errorf("summary file = %s", got)
	}
	if rel, _ := filepath.Rel(dir, sub.SummaryPath); !strings.HasPrefix(rel, PublicDir) {
		t.Errorf("the public summary is at %s, outside %s/", rel, PublicDir)
	}
	if rel, _ := filepath.Rel(dir, sub.LogsPath); !strings.HasPrefix(rel, ArchiveDir) {
		t.Errorf("the private detailed logs are at %s, outside %s/", rel, ArchiveDir)
	}

	// The manifest must cover everything written, and its digests must match.
	man, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(man)), "\n")
	if len(lines) != len(sub.Files) {
		t.Errorf("manifest has %d lines for %d files", len(lines), len(sub.Files))
	}

	// The generator's own statement of fact belongs in Additional Test Comments,
	// appended to the operator's text rather than replacing it.
	row, ok := sub.Summary.Lookup("Additional Test Comments")
	if !ok {
		t.Fatal("no Additional Test Comments row")
	}
	if !strings.Contains(row.Value, Tool) || !strings.Contains(row.Value, "SHA-256") {
		t.Errorf("Additional Test Comments = %q; the tool identity and the checksum algorithm "+
			"have nowhere else to go in this format", row.Value)
	}
}

func TestGenerateReadinessNamesEveryOutcome(t *testing.T) {
	dir := t.TempDir()
	sub, err := Generate(GenerateOptions{
		Dir: dir, CertType: CertTypeModbus, Doc: DocModbus, Config: fullConfig(),
		Verdicts: []TestVerdict{{ID: "MB-1", Verdict: "PASS"}}, ModbusLogs: goodModbusLogs(),
		Tool: Tool,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := sub.Readiness
	seen := map[string]bool{}
	for _, q := range r.Requirements {
		seen[q.ID] = true
		if q.Detail == "" {
			t.Errorf("%s has status %s with no detail; a verdict without a reason is what this suite "+
				"exists to prevent", q.ID, q.Status)
		}
	}
	// Every case ID of the document must be assessed — an omission would be the
	// readiness report quietly not answering part of the question.
	for _, id := range ModbusCaseIDs {
		if !seen[id] {
			t.Errorf("the readiness report does not assess %s", id)
		}
	}
	met, unmet, na := r.Counts()
	if met+unmet+na != len(r.Requirements) {
		t.Error("the counts do not add up")
	}
	if unmet != 0 {
		var names []string
		for _, q := range r.Unmet() {
			names = append(names, q.ID+": "+q.Detail)
		}
		t.Errorf("a fully configured submission has unmet requirements: %s", strings.Join(names, "; "))
	}
	if na == 0 {
		t.Error("nothing was reported NOT ASSESSED; the process constraints on the laboratory are not " +
			"decidable from any artefact and must be reported as such")
	}
}

func TestReadinessAssessesTheCSIPDocumentToo(t *testing.T) {
	cfg := fullConfig()
	cfg.CertificateType = CertTypeCSIP
	cfg.TestDescription = "Test performed in compliance with California Rule 21 Phase 2 and Phase 3."
	r := Assess(AssessInput{
		Doc: DocCSIP, CertType: CertTypeCSIP, Config: cfg,
		Summary:  BuildSummary(cfg, CertTypeCSIP, []TestVerdict{{ID: "BASIC-001", Verdict: "PASS"}}),
		CSIPLogs: goodCSIPLogs(),
	})
	seen := map[string]bool{}
	for _, q := range r.Requirements {
		seen[q.ID] = true
	}
	for _, id := range CSIPCaseIDs {
		if !seen[id] {
			t.Errorf("the readiness report does not assess %s", id)
		}
	}
	// RPT-060 has no COMM-004 scenario in this input, and must say so rather
	// than pass or fail.
	q, _ := r.Find(uidCSIP("RPT-060"))
	if q.Status != ReqNotAssessed || !strings.Contains(q.Detail, "COMM-004") {
		t.Errorf("RPT-060 = %s %q", q.Status, q.Detail)
	}
}

// TestReadinessFailsOnABrokenLog proves the assessment is driven by the
// artefacts and not by optimism.
func TestReadinessFailsOnABrokenLog(t *testing.T) {
	logs := goodModbusLogs()
	logs.Logs[0].Entries[1].Msg = "NOTHEX"
	r := Assess(AssessInput{
		Doc: DocModbus, CertType: CertTypeModbus, Config: fullConfig(),
		Summary:    BuildSummary(fullConfig(), CertTypeModbus, []TestVerdict{{ID: "MB-1", Verdict: "PASS"}}),
		ModbusLogs: logs,
	})
	if r.Submittable() {
		t.Fatal("a submission whose detailed log carries a non-hex msg was called submittable")
	}
	q, _ := r.Find(uidModbus("RPT-LOG-8"))
	if q.Status != ReqUnmet {
		t.Errorf("RPT-LOG-8 = %s", q.Status)
	}
}

// TestReadinessSurvivesAnAbsentDetailedLog pins a crash this generator shipped
// with.
//
// A submission with NO detailed test log is the ordinary case, not an edge: a
// CSIP campaign's 2030.5 traffic rides TLS, and a run that did not decrypt it
// has no plaintext HTTP to render. Assess's job in that situation is to report
// the artefact absent — and instead it panicked, because describeCSIPLogs was
// evaluated eagerly as a metIf argument and dereferenced the nil pointer while
// building the description for the branch that was not taken.
//
// Both documents are covered: the Modbus side has always been nil-safe, and a
// test that only covered the broken one would let it regress.
func TestReadinessSurvivesAnAbsentDetailedLog(t *testing.T) {
	for _, tc := range []struct {
		name     string
		doc      string
		certType string
	}{
		{"csip", DocCSIP, CertTypeCSIP},
		{"modbus", DocModbus, CertTypeModbus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig()
			cfg.CertificateType = tc.certType
			// Deliberately: no ModbusLogs, no CSIPLogs, no Traces.
			r := Assess(AssessInput{
				Doc: tc.doc, CertType: tc.certType, Config: cfg,
				Summary: BuildSummary(cfg, tc.certType, []TestVerdict{{ID: "X-1", Verdict: "PASS"}}),
			})
			if r == nil || len(r.Requirements) == 0 {
				t.Fatal("Assess produced no requirements")
			}
			// The log rows must be present and must NOT claim to be met: an
			// absent artefact that reported itself satisfied would be worse
			// than the panic.
			met, _, _ := r.Counts()
			if met == len(r.Requirements) {
				t.Error("every requirement reported met with no detailed log supplied")
			}
			if md := r.Markdown(); md == "" {
				t.Error("the readiness report renders empty")
			}
		})
	}
}
