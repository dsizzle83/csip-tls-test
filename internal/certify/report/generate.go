package report

// generate.go writes the submission.
//
// The directory layout is not a preference; it is §1's requirement rendered as
// filesystem. Both specifications split the deliverable in two — the Summary
// Test Results are "posted on the SunSpec web site and made available to the
// general public", the Detailed Test Logs are "archived by SunSpec, used only
// for confirming test results, and NOT shared with the public" — and a
// generator that emitted them into one flat directory would leave the submitter
// to keep the two apart by hand, which is exactly the mistake that puts a
// customer's captured traffic on a public web page.
//
//	<dir>/public/    SUMMARY.csv               the publishable half
//	<dir>/archive/   DETAILED-TEST-LOGS.json   the private half
//	<dir>/archive/traces/<scenario>.pcap       Chapter 5, COMM-004 only
//	<dir>/SUBMISSION-READINESS.md              the self-assessment
//	<dir>/MANIFEST.sha256                      every file above, digested
//
// And the refusal that gives the rest of it teeth: when a required key has no
// value, Generate fails unless the caller passes AllowIncomplete, and when it
// does the summary is written as SUMMARY-INCOMPLETE.csv. A file with that name
// does not get forwarded to a laboratory by accident, and no amount of
// reading past a warning in a log turns it back into a submission.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// File names inside a submission directory. Fixed, so a reviewer handed the
// directory needs no explanation of what is public and what is not.
const (
	PublicDir      = "public"
	ArchiveDir     = "archive"
	TraceDir       = "traces"
	SummaryFile    = "SUMMARY.csv"
	IncompleteFile = "SUMMARY-INCOMPLETE.csv"
	LogsFile       = "DETAILED-TEST-LOGS.json"
	ReadinessFile  = "SUBMISSION-READINESS.md"
	ManifestFile   = "MANIFEST.sha256"
)

// GenerateOptions is everything a submission is built from.
type GenerateOptions struct {
	// Dir is the submission directory. It is created if absent.
	Dir string
	// CertType selects the governing specification. Empty is inferred from Doc.
	CertType string
	// Doc is the catalog document being reported against, for the readiness
	// report's heading.
	Doc string
	// Config is the submitter/lab metadata. A nil Config is legal and produces
	// a submission whose every manual field is visibly missing — which is the
	// honest output of a bench run nobody configured.
	Config *SubmissionConfig
	// Verdicts are the `Test <Test ID>` rows.
	Verdicts []TestVerdict
	// ModbusLogs and CSIPLogs are the detailed test logs. Exactly one is
	// normally set, matching CertType.
	ModbusLogs *ModbusTestLogs
	CSIPLogs   *CSIPTestLogs
	// Transport selects which framing the Modbus `msg` values are validated
	// against. Defaults to Modbus TCP.
	Transport Transport
	// Traces are the Chapter 5 COMM-004 packet traces, already exported.
	Traces []TraceInfo
	// AllowIncomplete permits writing a submission with missing required keys,
	// under the INCOMPLETE filename.
	AllowIncomplete bool
	// Tool and ToolVersion identify the generator. §3.1.1's Additional Test
	// Comments is the only key the format has for it, and RPT-038's own note
	// says that is where it belongs.
	Tool        string
	ToolVersion string
	// Now overrides the clock, for reproducible tests.
	Now time.Time
}

// Submission is what was written.
type Submission struct {
	Dir      string
	CertType string
	Summary  *Summary
	// SummaryPath is the CSV actually written — SUMMARY.csv when complete,
	// SUMMARY-INCOMPLETE.csv when not.
	SummaryPath string
	LogsPath    string
	Traces      []TraceInfo
	Readiness   *Readiness
	// Files are every path written, relative to Dir, in manifest order.
	Files []string
	// Complete is true when nothing required is missing.
	Complete bool
}

// Generate writes a submission and its self-assessment.
func Generate(o GenerateOptions) (*Submission, error) {
	if o.Dir == "" {
		return nil, fmt.Errorf("report: Generate needs an output directory")
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.Transport == "" {
		o.Transport = TransportTCP
	}
	cfg := o.Config
	if cfg == nil {
		cfg = &SubmissionConfig{}
	}
	certType := o.CertType
	if certType == "" {
		certType = cfg.CertificateTypeOrDefault(o.Doc)
	}

	// The generator's own statement of fact goes in Additional Test Comments,
	// appended to whatever the operator wrote. It is the only free-text key the
	// format has, and RPT-025 and RPT-038 both point at it: the checksum
	// ALGORITHM has no key of its own, and the testing tool's identity is
	// conventionally stated here. Appending never overwrites.
	local := *cfg
	local.AdditionalTestComments = composeComments(cfg, o)

	sum := BuildSummary(&local, certType, o.Verdicts)
	sub := &Submission{Dir: o.Dir, CertType: certType, Summary: sum, Complete: sum.Complete()}

	if !sub.Complete && !o.AllowIncomplete {
		return sub, fmt.Errorf("report: the submission is not complete and AllowIncomplete was not set — "+
			"%d required key(s) have no value (%s); %d supplied value(s) are wrong for their key (%s)",
			len(sum.Missing), strings.Join(sum.MissingKeys(), ", "),
			len(sum.Problems), strings.Join(sum.Problems, "; "))
	}

	csvName := SummaryFile
	if !sub.Complete {
		csvName = IncompleteFile
	}
	csvRel := filepath.Join(PublicDir, csvName)
	csvBytes, err := sum.CSV()
	if err != nil {
		return sub, err
	}
	if err := writeFile(o.Dir, csvRel, csvBytes); err != nil {
		return sub, err
	}
	sub.SummaryPath = filepath.Join(o.Dir, csvRel)
	sub.Files = append(sub.Files, csvRel)

	switch {
	case o.ModbusLogs != nil:
		data, err := o.ModbusLogs.JSON()
		if err != nil {
			return sub, err
		}
		rel := filepath.Join(ArchiveDir, LogsFile)
		if err := writeFile(o.Dir, rel, data); err != nil {
			return sub, err
		}
		sub.LogsPath, sub.Files = filepath.Join(o.Dir, rel), append(sub.Files, rel)
	case o.CSIPLogs != nil:
		data, err := o.CSIPLogs.JSON()
		if err != nil {
			return sub, err
		}
		rel := filepath.Join(ArchiveDir, LogsFile)
		if err := writeFile(o.Dir, rel, data); err != nil {
			return sub, err
		}
		sub.LogsPath, sub.Files = filepath.Join(o.Dir, rel), append(sub.Files, rel)
	}

	for _, t := range o.Traces {
		if t.Path == "" {
			continue
		}
		if rel, err := filepath.Rel(o.Dir, t.Path); err == nil && !strings.HasPrefix(rel, "..") {
			sub.Files = append(sub.Files, rel)
		}
	}
	sub.Traces = o.Traces

	sub.Readiness = Assess(AssessInput{
		Doc: o.Doc, CertType: certType, Config: cfg, Summary: sum,
		ModbusLogs: o.ModbusLogs, CSIPLogs: o.CSIPLogs, Transport: o.Transport,
		Traces: o.Traces, Generated: o.Now, Tool: o.Tool, ToolVersion: o.ToolVersion,
	})
	if err := writeFile(o.Dir, ReadinessFile, []byte(sub.Readiness.Markdown())); err != nil {
		return sub, err
	}
	sub.Files = append(sub.Files, ReadinessFile)

	man, err := manifest(o.Dir, sub.Files)
	if err != nil {
		return sub, err
	}
	if err := writeFile(o.Dir, ManifestFile, man); err != nil {
		return sub, err
	}
	return sub, nil
}

// composeComments builds the Additional Test Comments value: the operator's own
// text first, then the facts the format has no other key for. Each addition is
// a statement about this tool or this run — never about the lab or the vendor.
func composeComments(cfg *SubmissionConfig, o GenerateOptions) string {
	parts := []string{}
	if s := strings.TrimSpace(cfg.AdditionalTestComments); s != "" {
		parts = append(parts, s)
	}
	if o.Tool != "" {
		v := o.Tool
		if o.ToolVersion != "" {
			v += " " + o.ToolVersion
		}
		parts = append(parts, "Test results generated by "+v+".")
	}
	if a := strings.TrimSpace(cfg.ChecksumAlgorithm); a != "" {
		parts = append(parts, "Software Checksum algorithm: "+a+
			" (the Summary Test Results format defines no key for the checksum algorithm).")
	}
	if len(o.Traces) > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d COMM-004 TLS packet trace(s) accompany this report (Chapter 5).", len(o.Traces)))
	}
	return strings.Join(parts, " ")
}

func writeFile(dir, rel string, data []byte) error {
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("report: create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("report: write %s: %w", path, err)
	}
	return nil
}

// manifest digests every written file, in the sha256sum -c format, so a
// recipient can verify the submission arrived intact with a tool they already
// have.
func manifest(dir string, files []string) ([]byte, error) {
	rels := append([]string(nil), files...)
	sort.Strings(rels)
	var b strings.Builder
	for _, rel := range rels {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return nil, fmt.Errorf("report: digest %s: %w", rel, err)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), filepath.ToSlash(rel))
	}
	return []byte(b.String()), nil
}
