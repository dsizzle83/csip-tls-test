package main

// submit.go turns an evidence bundle into a SunSpec submission: the public
// Summary Test Results CSV (§3.1), the archived Detailed Test Logs (§4), and a
// per-requirement readiness self-assessment.
//
// # Why this is a separate mode and not the end of a run
//
// A submission needs facts a bench cannot know and must never invent: the
// certificate number SunSpec assigns, the submitter's legal name, which of the
// thirteen authorized labs supervised the test. Those arrive in a -config file
// written by a human. Keeping generation separate means the campaign that
// touches the DUT does not have to wait on paperwork, and — more importantly —
// the paperwork can be revised and the report regenerated WITHOUT re-running
// the device. The evidence is fixed at capture time; the covering document is
// not.
//
// # The three refusals inherited from internal/certify/report
//
//  1. No invented metadata. A key nobody supplied is not emitted; it is listed
//     as missing, and the CSV is written as SUMMARY-INCOMPLETE.csv — a filename
//     nobody forwards to a lab by accident. -allow-incomplete is required to
//     write one at all.
//  2. No manufactured verdicts. §3.1.1 enumerates exactly PASS, FAIL and NOT
//     SUPPORTED. A bench SKIP is none of those — it means "addressed but not
//     asserted here" — so SKIP and WARN rows are OMITTED from the CSV and named
//     in this mode's output. Mapping them to PASS would forge a result; mapping
//     them to NOT SUPPORTED would misreport the product's capabilities.
//  3. No log that disagrees with the capture. The §4 detailed logs are DERIVED
//     from the bundle's pcap (see deriveModbusLogs), not from what some client
//     library believed it sent, so the log and the capture cannot drift.
//
// # The honest limit of log derivation
//
// Only CLEARTEXT conversations can be rendered. A capture whose Modbus rode
// inside mbaps is ciphertext on the wire, and this mode does not decrypt it: it
// counts those conversations and says so, so a reader knows the emitted log is
// partial and why, rather than reading an empty log as an empty bench.

import (
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/report"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/netdis"
)

func (c *cli) runReport(stdout, stderr io.Writer) int {
	dir := c.report
	b, err := bundle.Load(dir)
	if err != nil {
		fmt.Fprintf(stderr, "certify: %s is not a readable evidence bundle: %v\n", dir, err)
		return exitUsage
	}

	// A submission built from a bundle that does not verify is a submission
	// built from evidence nobody can check. Verify FIRST, refuse loudly, and
	// make the override explicit rather than implicit in a flag nobody read.
	vr, verr := bundle.Verify(dir)
	switch {
	case verr != nil:
		fmt.Fprintf(stderr, "certify: %s could not be verified: %v\n", dir, verr)
		return exitFail
	case !vr.OK:
		fmt.Fprintf(stderr, "certify: %s does NOT verify — refusing to build a submission from evidence "+
			"whose report and capture disagree. Run: certify -verify %s\n", dir, dir)
		return exitFail
	}

	var cfg *report.SubmissionConfig
	if c.configPath != "" {
		cfg, err = report.LoadConfig(c.configPath)
		if err != nil {
			fatal(stderr, err)
			return exitUsage
		}
	}
	if err := (&report.SubmissionConfig{}).ApplyParams(c.opts.Params); err != nil {
		// Validate the overlay's syntax before using it, so a typo in
		// -param report.x=y is reported here and not as a missing key later.
		fatal(stderr, err)
		return exitUsage
	}
	if cfg == nil {
		cfg = &report.SubmissionConfig{}
	}
	if err := cfg.ApplyParams(c.opts.Params); err != nil {
		fatal(stderr, err)
		return exitUsage
	}

	certType := c.certType
	if certType == "" {
		certType = cfg.CertificateTypeOrDefault("")
	}
	doc := report.DocCSIP
	if certType == report.CertTypeModbus {
		doc = report.DocModbus
	}

	rows, omitted := report.Verdicts(b)

	out, err := submissionDir(dir, c.reportOut)
	if err != nil {
		fatal(stderr, err)
		return exitUsage
	}

	opts := report.GenerateOptions{
		Dir:             out,
		CertType:        certType,
		Doc:             doc,
		Config:          cfg,
		Verdicts:        rows,
		AllowIncomplete: c.allowIncomplete,
		Tool:            certify.ToolName,
		ToolVersion:     b.Run.ToolVersion,
	}

	var logNotes []string
	switch {
	case !c.deriveLogs:
		logNotes = append(logNotes, "-derive-logs=false: no §4 detailed test log is emitted")
	case certType == report.CertTypeModbus:
		logs, notes := deriveModbusLogs(dir, b)
		opts.ModbusLogs = logs
		logNotes = notes
	default:
		// The CSIP §4 logs are HTTP messages, and on this bench every CSIP
		// exchange rides TLS to the gridsim. Rendering them means decrypting the
		// capture, which this mode does not do. Saying so is the whole point: an
		// absent artefact WITH a reason is a gap a reviewer can assess; an
		// absent artefact with no explanation is one they are right to distrust.
		// The readiness report already lists the RPT-LOG rows as unmet.
		logNotes = append(logNotes, "no §4 CSIP HTTP log is derived here: the DUT's 2030.5 exchanges ride "+
			"TLS, and rendering them as the required plaintext needs the capture decrypted — see the "+
			"RPT-LOG rows in "+report.ReadinessFile)
	}

	fmt.Fprintf(stdout, "SUBMISSION from %s\n", dir)
	fmt.Fprintf(stdout, "  certification type: %s (%s)\n", certType, doc)
	fmt.Fprintf(stdout, "  bundle:             %d case(s), tool %s %s\n",
		len(b.Cases), b.Run.Tool, b.Run.ToolVersion)
	if c.configPath != "" {
		fmt.Fprintf(stdout, "  metadata:           %s\n", c.configPath)
	} else {
		fmt.Fprintf(stdout, "  metadata:           NONE — every submitter and laboratory key will be missing\n")
	}
	for _, n := range logNotes {
		fmt.Fprintf(stdout, "  logs:               %s\n", n)
	}
	fmt.Fprintln(stdout)

	sub, err := report.Generate(opts)
	if err != nil {
		fatal(stderr, err)
		if sub != nil && sub.Summary != nil && len(sub.Summary.Missing) > 0 {
			fmt.Fprintf(stderr, "\nSupply them in -config, or pass -allow-incomplete to write the report\n"+
				"as SUMMARY-INCOMPLETE.csv with the gaps named inside it.\n")
		}
		return exitFail
	}

	fmt.Fprintf(stdout, "  written to %s\n", sub.Dir)
	for _, f := range sub.Files {
		fmt.Fprintf(stdout, "    %s\n", f)
	}

	// The verdict rows the CSV could not carry. Naming them is the whole point:
	// a reader must be able to tell a test that was not run from a test that
	// was run and passed.
	if len(omitted) > 0 {
		sort.Strings(omitted)
		fmt.Fprintf(stdout, "\n  %d bundle case(s) are NOT in the summary, because §3.1.1's verdict\n"+
			"  enumeration (PASS / FAIL / NOT SUPPORTED) has no member meaning \"addressed but\n"+
			"  not asserted here\":\n", len(omitted))
		for _, o := range omitted {
			fmt.Fprintf(stdout, "    · %s\n", o)
		}
	}
	if sub.Summary != nil && len(sub.Summary.Missing) > 0 {
		fmt.Fprintf(stdout, "\n  %d required key(s) have no value:\n", len(sub.Summary.Missing))
		for _, m := range sub.Summary.MissingKeys() {
			fmt.Fprintf(stdout, "    · %s\n", m)
		}
	}

	fmt.Fprintf(stdout, "\n%s\n", strings.Repeat("═", 78))
	if sub.Complete {
		fmt.Fprintf(stdout, "✓ SUBMITTABLE — every required key has a value. Read %s\n  before sending: it is "+
			"this tool's self-assessment, not the lab's.\n", report.ReadinessFile)
		fmt.Fprintf(stdout, "%s\n", strings.Repeat("═", 78))
		return exitOK
	}
	fmt.Fprintf(stdout, "⚠ NOT SUBMITTABLE — written as %s. The named keys are facts only a\n"+
		"  laboratory or the submitter can supply; this tool will not invent them.\n",
		filepath.Base(sub.SummaryPath))
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("═", 78))
	return exitFail
}

// submissionDir resolves where the submission is written, and refuses to write
// it INSIDE the evidence bundle.
//
// This is a fix for a bug in this mode's first default, which was
// `<bundle>/submission`. A bundle verifies in part by checking that every file
// present in the directory is listed in MANIFEST.sha256 — that is what stops
// somebody slipping an extra artefact in beside the evidence — so writing the
// submission there made the SOURCE BUNDLE stop verifying the moment the report
// was generated. Worse, the failure appeared one step later, on the next
// `-verify`, looking exactly like tampering.
//
// The default is now a sibling: `runs/2026-07-26` → `runs/2026-07-26-submission`.
// An explicit -report-out inside the bundle is refused rather than quietly
// relocated, because the operator asked for something specific and the reason it
// cannot be honoured is worth one line of their attention.
func submissionDir(bundleDir, requested string) (string, error) {
	if requested == "" {
		clean := filepath.Clean(bundleDir)
		return filepath.Join(filepath.Dir(clean), filepath.Base(clean)+"-submission"), nil
	}
	absBundle, err := filepath.Abs(bundleDir)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", bundleDir, err)
	}
	absOut, err := filepath.Abs(requested)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", requested, err)
	}
	rel, err := filepath.Rel(absBundle, absOut)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("-report-out %s is inside the evidence bundle %s. A bundle verifies partly by "+
			"checking that every file in it is listed in its manifest, so writing the submission there would "+
			"make the evidence itself stop verifying — and the failure would surface later, on a -verify, "+
			"looking like tampering. Write it beside the bundle instead", requested, bundleDir)
	}
	return requested, nil
}

// deriveModbusLogs renders the §4 Detailed Test Logs from the bundle's OWN
// capture.
//
// Every cleartext TCP conversation in the pcap is offered to report.ScanModbus;
// one that does not decode as MBAP contributes nothing and is not an error,
// because a bench capture legitimately carries HTTP, TLS and the sims' own
// traffic alongside the Modbus under test. What IS reported back to the
// operator is the count of conversations that carried TLS records: those are
// Modbus this mode could not render, and an unexplained short log is exactly
// the kind of gap a certification reviewer is right to distrust.
//
// The returned notes are for the console; the Problems each scan recorded
// travel no further than that on purpose — they describe the capture, and the
// capture's integrity findings already live in the bundle.
func deriveModbusLogs(dir string, b *bundle.Bundle) (*report.ModbusTestLogs, []string) {
	if b.Files.Capture == "" {
		return nil, []string{"the bundle declares no capture, so no §4 detailed log can be derived from one"}
	}
	path := filepath.Join(dir, filepath.FromSlash(b.Files.Capture))
	fi, err := certify.LoadFrameIndex(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("capture %s could not be read back: %v", b.Files.Capture, err)}
	}

	// The tests every derived log cites.
	//
	// §4.1.1 lets one log evidence several procedures, and it is tempting to
	// list every case in the bundle. That would be a small forgery: a case that
	// SKIPped never drove the wire, so a log claiming to evidence it is
	// claiming evidence that does not exist. The list is therefore exactly the
	// cases carrying a reportable verdict — the same set report.Verdicts puts
	// in the summary CSV — so the log and the CSV cite one another and nothing
	// else.
	var tests []string
	for _, c := range b.Cases {
		if c.Verdict == bundle.Pass || c.Verdict == bundle.Fail {
			tests = append(tests, c.ID)
		}
	}
	if len(tests) == 0 {
		return nil, []string{"no bundle case carries a PASS or FAIL verdict, so no §4 log has a procedure to cite"}
	}

	logs := &report.ModbusTestLogs{}
	frames := fi.Frames()
	encrypted, decoded, msgs := 0, 0, 0
	for _, st := range fi.Streams() {
		if streamIsTLS(st) {
			encrypted++
			continue
		}
		// Try both endpoints as "the server": ScanModbus needs to know which
		// direction is req and which is resp, and a bundle does not record it.
		// The orientation that yields requests from the client side is the
		// right one; MBAP is asymmetric enough that the wrong one yields
		// nothing.
		var best *report.ModbusScan
		for _, srv := range []netdis.Endpoint{st.Key.A, st.Key.B} {
			sc, err := report.ScanModbus(st, frames, endpointAddrPort(srv))
			if err != nil || sc == nil {
				continue
			}
			if n := sc.Count(report.EntryReq) + sc.Count(report.EntryResp); n > 0 {
				if best == nil || n > best.Count(report.EntryReq)+best.Count(report.EntryResp) {
					best = sc
				}
			}
		}
		if best == nil {
			continue
		}
		decoded++
		msgs += best.Count(report.EntryReq) + best.Count(report.EntryResp)
		logs.Logs = append(logs.Logs, best.TestLog(tests...))
	}

	var notes []string
	switch {
	case decoded == 0 && encrypted == 0:
		notes = append(notes, "no Modbus conversation was found in the capture; no §4 log was emitted")
	case decoded == 0:
		notes = append(notes, fmt.Sprintf(
			"no cleartext Modbus was found; %d conversation(s) carried TLS records and are NOT rendered "+
				"(this mode does not decrypt), so no §4 log was emitted", encrypted))
	default:
		notes = append(notes, fmt.Sprintf(
			"derived %d message(s) from %d cleartext conversation(s) in the bundle's own capture", msgs, decoded))
		if encrypted > 0 {
			notes = append(notes, fmt.Sprintf(
				"%d further conversation(s) carried TLS records and are NOT in the log: §4 wants ALL Modbus "+
					"messages unencrypted, and this mode does not decrypt", encrypted))
		}
	}
	if len(logs.Logs) == 0 {
		return nil, notes
	}
	return logs, notes
}

// endpointAddrPort converts a dissected endpoint to the address form
// report.ScanModbus takes.
func endpointAddrPort(e netdis.Endpoint) netip.AddrPort {
	return netip.AddrPortFrom(e.Addr.Unmap(), e.Port)
}

// streamIsTLS reports whether either direction opens with a TLS record header —
// content type 0x14..0x17 followed by a 0x03 0x0x version. It is a cheap
// classifier and only ever used to EXCLUDE a conversation from log derivation
// and count it aloud, so a false positive costs a note and never a wrong log
// entry.
func streamIsTLS(st *netdis.Stream) bool {
	for _, d := range st.Dirs {
		if d == nil {
			continue
		}
		b := d.Bytes.Bytes()
		if len(b) < 3 {
			continue
		}
		if b[0] >= 0x14 && b[0] <= 0x17 && b[1] == 0x03 {
			return true
		}
	}
	return false
}
