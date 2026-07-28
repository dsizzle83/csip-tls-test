package main

// trr.go is the mode that turns a campaign's evidence into the artefact SunSpec
// actually receives: a Test Results Report package.
//
// # Why it is not just -report with a second bundle
//
// -report answers "make a submission out of THIS bundle for THAT certificate
// type", and the operator supplies the type. A real campaign does not work that
// way. One bench run covers five documents at once — the SunSpec Modbus server
// procedures, the Modbus client procedures, the 1547 profile, Secure SunSpec
// Modbus and the test PKI — plus CSIP, and those six documents are governed by
// TWO Results Reporting specifications. The submission is therefore two
// summaries and two logs, and deciding which verdict belongs in which is a
// routing question with a right answer, not a flag the operator should have to
// get right (see report.DocCertType).
//
// So this mode takes one or more completed bundles, routes every case by its
// document, maps each bench verdict by the rule report/trr.go derives from the
// two §3.1.1 tables, and writes one package containing both reports plus the
// statement of what it does not carry.
//
// # The three refusals
//
//  1. A required key the SUBMITTER could have supplied is a hard error naming
//     every one of them at once. No blank is written in its place.
//  2. A required key only SunSpec or an Appendix A1 laboratory can supply is
//     NOT an error but is not filled in either: -allow-incomplete writes the
//     package with the SELF-TEST declaration in Additional Test Comments and
//     the summary named SUMMARY-INCOMPLETE.csv.
//  3. Two bundles that disagree about one procedure's verdict stop the run.
//     Which campaign is the submitted one is the operator's decision; the fix
//     is to narrow a source with `dir=<doc-key>`.

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/report"
	"csip-tls-test/internal/evidence/bundle"
)

func (c *cli) runTRR(stdout, stderr io.Writer) int {
	if c.trrOut == "" {
		fmt.Fprintf(stderr, "certify: -trr needs -trr-out <dir>. There is no safe default: a package built "+
			"from several bundles belongs beside none of them, and writing it inside one would make that "+
			"bundle stop verifying.\n")
		return exitUsage
	}
	sources, rc := c.loadTRRSources(stdout, stderr)
	if rc != exitOK {
		return rc
	}

	var cfg *report.SubmissionConfig
	if c.configPath != "" {
		loaded, err := report.LoadConfig(c.configPath)
		if err != nil {
			fatal(stderr, err)
			return exitUsage
		}
		cfg = loaded
	} else {
		cfg = &report.SubmissionConfig{}
	}
	if err := cfg.ApplyParams(c.opts.Params); err != nil {
		fatal(stderr, err)
		return exitUsage
	}

	// The verdict rows first, because the §4 logs may only name procedures the
	// summaries actually report: a log claiming to evidence a test that carries
	// no verdict row is claiming evidence for nothing.
	collated, err := report.Collate(sources)
	if err != nil {
		fatal(stderr, err)
		return exitFail
	}

	opts := report.TRROptions{
		Dir:                c.trrOut,
		Sources:            sources,
		Config:             cfg,
		Tool:               certify.ToolName,
		ToolVersion:        toolVersionOf(sources),
		AllowAuthorityGaps: c.allowIncomplete,
	}
	if c.deriveLogs {
		d := deriveTRRLogs(sources, collated, cfg.ContextID)
		opts.ModbusLogs, opts.CSIPLogs = d.Modbus, d.CSIP
		opts.LogNotes, opts.LogUndecryptable = d.Notes, d.Undecryptable
	} else {
		opts.LogNotes = []string{"-derive-logs=false: no §4 detailed test log is emitted"}
	}

	fmt.Fprintf(stdout, "TEST RESULTS REPORT from %d evidence bundle(s)\n", len(sources))
	for _, s := range sources {
		scope := "all documents"
		if len(s.Docs) > 0 {
			scope = strings.Join(s.Docs, ",")
		}
		fmt.Fprintf(stdout, "  %-46s %3d case(s), %s\n", s.Dir, len(s.Bundle.Cases), scope)
		if s.Note != "" {
			fmt.Fprintf(stdout, "  %-46s ⚠ %s\n", "", s.Note)
		}
	}
	if c.configPath != "" {
		fmt.Fprintf(stdout, "  metadata: %s\n", c.configPath)
	} else {
		fmt.Fprintf(stdout, "  metadata: NONE — every submitter key will be reported missing\n")
	}
	for _, n := range opts.LogNotes {
		fmt.Fprintf(stdout, "  logs:     %s\n", n)
	}
	fmt.Fprintln(stdout)

	trr, err := report.GenerateTRR(opts)
	if err != nil {
		fatal(stderr, err)
		return exitFail
	}

	fmt.Fprintf(stdout, "  written to %s\n", trr.Dir)
	for _, f := range trr.Files {
		fmt.Fprintf(stdout, "    %s\n", f)
	}
	if trr.Fill != nil {
		for _, f := range trr.Fill.Filled {
			fmt.Fprintf(stdout, "  checksum: %s\n", f)
		}
		for _, u := range trr.Fill.Unresolved {
			fmt.Fprintf(stdout, "  checksum: ⚠ %s\n", u)
		}
	}

	complete := true
	fmt.Fprintln(stdout)
	for _, part := range trr.Parts {
		counts := part.Collated.Counts()
		fmt.Fprintf(stdout, "  %s (%s)\n", part.CertType, filepath.Base(part.Submission.Dir))
		fmt.Fprintf(stdout, "    %d verdict row(s): %d PASS, %d FAIL, %d NOT SUPPORTED\n",
			len(part.Collated.Verdicts), counts["PASS"], counts["FAIL"], counts["NOT SUPPORTED"])
		fmt.Fprintf(stdout, "    %d procedure(s) omitted with a recorded gap (see %s)\n",
			len(part.Collated.Gaps), report.ReadinessFile)
		if len(part.AuthorityGaps) > 0 {
			complete = false
			fmt.Fprintf(stdout, "    %d key(s) only SunSpec or an Authorized Test Laboratory can supply:\n",
				len(part.AuthorityGaps))
			for _, m := range part.AuthorityGaps {
				fmt.Fprintf(stdout, "      · %s — %s\n", m.Key, m.Why)
			}
		}
	}

	fmt.Fprintf(stdout, "\n%s\n", strings.Repeat("═", 78))
	if complete {
		fmt.Fprintf(stdout, "✓ SUBMITTABLE — every required key has a value. Read %s and each part's %s\n"+
			"  before sending: they are this tool's self-assessment, not a laboratory's.\n",
			report.TRRReadmeFile, report.ReadinessFile)
		fmt.Fprintf(stdout, "%s\n", strings.Repeat("═", 78))
		return exitOK
	}
	fmt.Fprintf(stdout, "⚠ SELF-TEST — the laboratory and certificate keys are absent because no SunSpec\n"+
		"  Authorized Test Laboratory ran this campaign. Each summary is written as %s\n"+
		"  and carries the SELF-TEST declaration. This tool will not invent those values.\n", report.IncompleteFile)
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("═", 78))
	return exitFail
}

// loadTRRSources parses the -trr arguments and loads each bundle.
//
// A bundle that does not VERIFY is refused, exactly as -report refuses one: a
// submission built from evidence nobody can re-derive is not a submission, and
// discovering that after it reaches a laboratory is the worst possible time.
func (c *cli) loadTRRSources(stdout, stderr io.Writer) ([]report.Source, int) {
	var out []report.Source
	for _, spec := range c.trr {
		dir, docs := spec, []string(nil)
		if d, rest, ok := strings.Cut(spec, "="); ok {
			dir = d
			for _, part := range strings.Split(rest, ",") {
				if part = strings.TrimSpace(part); part != "" {
					docs = append(docs, part)
				}
			}
		}
		b, err := bundle.Load(dir)
		if err != nil {
			fmt.Fprintf(stderr, "certify: %s is not a readable evidence bundle: %v\n", dir, err)
			return nil, exitUsage
		}
		vr, verr := bundle.Verify(dir)
		switch {
		case verr != nil:
			fmt.Fprintf(stderr, "certify: %s could not be verified: %v\n", dir, verr)
			return nil, exitFail
		case !vr.OK:
			fmt.Fprintf(stderr, "certify: %s does NOT verify — refusing to build a Test Results Report from "+
				"evidence whose report and capture disagree. Run: certify -verify %s\n", dir, dir)
			return nil, exitFail
		}
		src := report.Source{Dir: dir, Bundle: b, Docs: docs}
		na, aerr := report.LoadApplicability(dir, b)
		src.Applicability = na
		if aerr != nil {
			src.Note = aerr.Error()
		}
		out = append(out, src)
	}
	if len(out) == 0 {
		fmt.Fprintf(stderr, "certify: -trr needs at least one evidence bundle directory\n")
		return nil, exitUsage
	}
	return out, exitOK
}

// trrLogs is every source bundle's contribution to the two §4 documents,
// merged, with what could not be rendered kept separate from what was.
type trrLogs struct {
	Modbus        *report.ModbusTestLogs
	CSIP          *report.CSIPTestLogs
	Notes         []string
	Undecryptable []string
}

// deriveTRRLogs renders every source bundle's capture into the two §4
// documents, and collects the statement of what could not be rendered.
func deriveTRRLogs(sources []report.Source, collated map[string]*report.Collated, cid string) trrLogs {
	modbusTests := verdictIDs(collated[report.CertTypeModbus])
	csipTests := verdictIDs(collated[report.CertTypeCSIP])

	var modbus []*report.ModbusTestLogs
	var csip []*report.CSIPTestLogs
	out := trrLogs{}
	for _, s := range sources {
		d := report.DeriveTestLogs(report.LogInput{
			Dir: s.Dir, Bundle: s.Bundle,
			ModbusTests: modbusTests, CSIPTests: csipTests, CID: cid,
		})
		modbus = append(modbus, d.Modbus)
		csip = append(csip, d.CSIP)
		out.Notes = append(out.Notes, d.Notes...)
		out.Undecryptable = append(out.Undecryptable, d.Undecryptable...)
	}
	out.Modbus = report.MergeModbusLogs(modbus...)
	out.CSIP = report.MergeCSIPLogs(csip...)
	return out
}

// verdictIDs lists the procedures a derived log may name: exactly those that
// carry a verdict row.
func verdictIDs(c *report.Collated) []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Verdicts))
	for _, v := range c.Verdicts {
		out = append(out, v.ID)
	}
	sort.Strings(out)
	return out
}

// toolVersionOf reports the tool version the evidence was produced by, and says
// so plainly when the bundles disagree rather than picking one.
func toolVersionOf(sources []report.Source) string {
	seen := map[string]bool{}
	var vs []string
	for _, s := range sources {
		if s.Bundle == nil || s.Bundle.Run.ToolVersion == "" {
			continue
		}
		if !seen[s.Bundle.Run.ToolVersion] {
			seen[s.Bundle.Run.ToolVersion] = true
			vs = append(vs, s.Bundle.Run.ToolVersion)
		}
	}
	sort.Strings(vs)
	return strings.Join(vs, "+")
}
