package main

// report.go is the ssm-conformance Reporter: one PASS/FAIL/SKIP line per Secure
// SunSpec Modbus/TCP requirement, keyed by its SunSpecTCP-N id, in the exact
// house style of sim/modsim-conformance and sim/conformance (✓ PASS / ✗ FAIL,
// a running tally, a final summary). It additionally tracks WHICH of the 62 rows
// were addressed so the suite can prove — as its own acceptance bar (T06.10) —
// that no requirement printed "NOT ADDRESSED", and it emits a CONFORMANCE_REPORT.md
// section that slots into the root report unchanged.

import (
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

// Status is the verdict for one requirement.
type Status string

const (
	// StatusPass — the requirement was asserted on the wire and held.
	StatusPass Status = "PASS"
	// StatusFail — the requirement was asserted and did NOT hold.
	StatusFail Status = "FAIL"
	// StatusSkip — the requirement is addressed but not wire-assertable by this
	// bench (a project/deployment-policy row, or one needing bench hardware /
	// server-side config not observable from a client). The Evidence carries the
	// reason. A SKIP is still "addressed" — it is not an unaddressed row.
	StatusSkip Status = "SKIP"
	// StatusWarn — asserted but with a caveat (e.g. an ephemeral loopback port for
	// the port-802 SHOULD, or a MAY that this run did not exercise).
	StatusWarn Status = "WARN"
)

// reqMeta is one SunSpecTCP requirement's identity, transcribed from
// docs/requirements/secure-sunspec-modbus-traceability.md (the bench's own source
// of truth — not imported from the product, PN-1/C9). Section is the spec block
// (5.1..5.5), Applies is the direction (server/client/both/project).
type reqMeta struct {
	n       int
	section string
	applies string
	summary string
}

// requirements is the complete 62-row Secure SunSpec Modbus/TCP requirement set.
// The suite MUST record a Status for every one of these (T06.10 acceptance: no
// row prints "NOT ADDRESSED"); missingRows() enforces it at the end of a run.
var requirements = []reqMeta{
	// §5.1 Transport Layer Security
	{1, "5.1", "server+client", "Port 802 SHOULD be used for mbaps"},
	{2, "5.1", "server+client", "MUST support ≥10 root certificates"},
	{3, "5.1", "server+client", "Secure add/remove of root & server certs; all stored certs considered"},
	{4, "5.1", "server+client", "TLS 1.2 (RFC 5246) MUST be supported"},
	{5, "5.1", "server+client", "TLS 1.3 (RFC 8446) MAY be supported"},
	{6, "5.1", "server+client", "Mutual client/server TLS authentication MUST be used"},
	{7, "5.1", "server+client", "X.509v3 certificates (RFC 5280) MUST be the credentials"},
	{8, "5.1", "server", "Authorization MUST use the role from the X.509v3 cert extension"},
	{9, "5.1", "server+client", "No change to the mbap protocol inside the tunnel"},
	{10, "5.1", "server+client", "Mutual authentication during handshake MUST"},
	{11, "5.1", "server", "Server MUST send CertificateRequest"},
	{12, "5.1", "client", "Client MUST send ClientCertificate on request"},
	{13, "5.1", "server", "Server MUST send fatal alert + terminate if client sends no cert"},
	{14, "5.1", "server+client", "Connection MUST NOT resume after fatal alert"},
	// §5.2 Cipher Suite Selection
	{15, "5.2", "server+client", "Cipher suites MUST be IANA-listed"},
	{16, "5.2", "server+client", "Ciphers MUST accommodate X.509v3"},
	{17, "5.2", "server+client", "TLS 1.2 minimum suites, in order (GCM > ChaCha20 > CCM-8)"},
	{18, "5.2", "server+client", "TLS 1.3 minimum suites, in order (GCM > ChaCha20 > CCM)"},
	{19, "5.2", "server+client", "Cipher suite order MUST match TCP-17/18"},
	{20, "5.2", "server+client", "MUST be able to disable IANA-discouraged suites"},
	// §5.3 Role-Based Client Authorization
	{21, "5.3", "server", "Role-based client AuthZ per MODBUS/TCP Security §8.4"},
	{22, "5.3", "server", "MUST support ReadOnly/GridService/NetworkAdmin/SuperAdmin roles"},
	{23, "5.3", "server", "MAY support IEC 62351-8 roles"},
	{24, "5.3", "server", "Vendor MUST provide roles-to-rights DB for all supported points"},
	{25, "5.3", "server", "Mandatory roles MUST use the SunSpec rbac map"},
	{26, "5.3", "server", "Role extension + AuthZ algorithm + rules DB REQUIRED"},
	{27, "5.3", "client", "Client MUST be provisioned with X.509v3 domain cert"},
	{28, "5.3", "client", "Client cert MUST include Role extension (server cert need not)"},
	{29, "5.3", "both", "Role MUST use PEN OID 1.3.6.1.4.1.50316.802.1"},
	{30, "5.3", "both", "Role MUST be ASN1:UTF8String"},
	{31, "5.3", "both", "Exactly one role per certificate; whole string is the role"},
	{32, "5.3", "server", "No role in cert ⇒ server returns exception code 01"},
	{33, "5.3", "server", "AuthZ algorithm defined by vendor"},
	{34, "5.3", "server", "Rules DB syntax/semantics defined by vendor"},
	{35, "5.3", "server", "Rules DB configured per vendor design"},
	{36, "5.3", "server", "Rules DB MUST be configurable"},
	{37, "5.3", "server", "Rules DB MUST NOT have unchangeable hardcoded default roles"},
	{38, "5.3", "both", "Cert role values consistent with rules DB design"},
	{39, "5.3", "server", "Server MUST extract client role from received cert"},
	{40, "5.3", "server", "AuthZ rejection ⇒ exception code 01"},
	{41, "5.3", "server", "Rejected request ⇒ exception, no additional information"},
	// §5.4 Public Key Infrastructure
	{42, "5.4", "both", "ECC devices MUST support P-256"},
	{43, "5.4", "client", "Supported Elliptic Curves extension in ClientHello"},
	{44, "5.4", "client", "Supported Point Format extension in ClientHello"},
	{45, "5.4", "both", "Mutual authentication handshake MUST"},
	{46, "5.4", "both", "Resumed session handshake SHOULD"},
	{47, "5.4", "both", "Session ticket resumption MAY"},
	{48, "5.4", "server", "Server MUST reject handshake without client cert"},
	{49, "5.4", "both", "Self-signed MAY be used; key lifecycle SHOULD follow NIST SP 800-57"},
	{50, "5.4", "both", "Public-network comms MUST use CA-signed certs"},
	{51, "5.4", "both", "MUST send full chain to root"},
	{52, "5.4", "both", "Certs MUST conform to RFC 5280"},
	{53, "5.4", "both", "Encryption-required scenarios ⇒ encrypting IANA suite"},
	{54, "5.4", "both", "MUST NOT use HMAC-MD5 / HMAC-SHA-1 / NULL HMAC"},
	{55, "5.4", "both", "MUST provide HMAC-SHA-256"},
	{56, "5.4", "both", "MUST NOT use HMAC-SHA-1 in the TLS 1.2 PRF"},
	{57, "5.4", "both", "MUST use HMAC-SHA-256 in the TLS 1.2 PRF"},
	{58, "5.4", "project", "Crypto import/export conformance determined early"},
	// §5.5 Packet and Session Requirements
	{59, "5.5", "both", "Maximum Fragment Length Negotiation (RFC 6066) MUST"},
	{60, "5.5", "both", "MUST support negotiating MFL of 512 bytes"},
	{61, "5.5", "client", "ClientHello CompressionMethod MUST be NULL"},
	{62, "5.5", "both", "Renegotiation Indication Extension (RFC 5746) MUST"},
}

// metaByN indexes requirements by their number for O(1) lookup.
var metaByN = func() map[int]reqMeta {
	m := make(map[int]reqMeta, len(requirements))
	for _, r := range requirements {
		m[r.n] = r
	}
	return m
}()

// reqID formats a requirement number as its spec id.
func reqID(n int) string { return fmt.Sprintf("SunSpecTCP-%d", n) }

// Result is one requirement's recorded verdict plus its evidence string.
type Result struct {
	ID       string
	N        int
	Section  string
	Summary  string
	Status   Status
	Evidence string
}

// Reporter accumulates one Result per SunSpecTCP requirement and writes the
// house-style live log. It is NOT safe for concurrent use — the suite runs its
// checks sequentially (one outstanding mbaps request at a time is the protocol's
// own discipline anyway).
type Reporter struct {
	w       io.Writer
	results map[int]Result
	order   []int
	target  string
	device  string
	started time.Time
}

// newReporter tees the live log to stdout and, when logPath is non-empty, to a
// file — the same shape as modsim-conformance's newReporter.
func newReporter(logPath, target, device string) (*Reporter, func()) {
	writers := []io.Writer{os.Stdout}
	cleanup := func() {}
	if logPath != "" {
		f, err := os.Create(logPath)
		if err != nil {
			log.Fatalf("open log file %s: %v", logPath, err)
		}
		writers = append(writers, f)
		cleanup = func() { _ = f.Close() }
	}
	return &Reporter{
		w:       io.MultiWriter(writers...),
		results: make(map[int]Result, len(requirements)),
		target:  target,
		device:  device,
		started: time.Now(),
	}, cleanup
}

func (r *Reporter) printf(format string, args ...any) { fmt.Fprintf(r.w, format, args...) }

// header prints the run banner.
func (r *Reporter) header() {
	r.printf("%s\n", strings.Repeat("═", 72))
	r.printf("SECURE SUNSPEC MODBUS (mbaps) CONFORMANCE TEST — 62 requirements\n")
	r.printf("%s\n", strings.Repeat("─", 72))
	r.printf("Target:        %s\n", r.target)
	if r.device != "" {
		r.printf("Device target: %s\n", r.device)
	}
	r.printf("Reference:     SunSpec Secure SunSpec Modbus v1.0 (Approved 2025-12-10)\n")
	r.printf("Date:          %s\n", r.started.UTC().Format(time.RFC3339))
	r.printf("%s\n", strings.Repeat("═", 72))
}

// section prints a spec-block divider.
func (r *Reporter) section(id, name string) {
	r.printf("\n%s\n[§%s] %s\n%s\n", strings.Repeat("─", 72), id, name, strings.Repeat("─", 72))
}

// record files a verdict for requirement n and prints the house-style line. Each
// row is expected to be recorded exactly once by its owning check; a second
// record for the same n keeps the WORSE status (FAIL > WARN > PASS > SKIP) and
// appends the evidence, so a row asserted by two checks can only get stricter,
// never silently downgraded.
func (r *Reporter) record(n int, st Status, evidenceFmt string, args ...any) {
	meta, ok := metaByN[n]
	if !ok {
		r.printf("  ! internal: recorded unknown requirement %d\n", n)
		return
	}
	evidence := fmt.Sprintf(evidenceFmt, args...)
	if prev, seen := r.results[n]; seen {
		if statusSeverity(st) > statusSeverity(prev.Status) {
			prev.Status = st
		}
		prev.Evidence = strings.TrimSpace(prev.Evidence + " ⋯ " + evidence)
		r.results[n] = prev
	} else {
		r.results[n] = Result{ID: reqID(n), N: n, Section: meta.section, Summary: meta.summary, Status: st, Evidence: evidence}
		r.order = append(r.order, n)
	}
	glyph := map[Status]string{StatusPass: "✓ PASS", StatusFail: "✗ FAIL", StatusSkip: "· SKIP", StatusWarn: "⚠ WARN"}[st]
	r.printf("  %s  %-15s %s\n", glyph, reqID(n), evidence)
}

func (r *Reporter) pass(n int, f string, a ...any) { r.record(n, StatusPass, f, a...) }
func (r *Reporter) fail(n int, f string, a ...any) { r.record(n, StatusFail, f, a...) }
func (r *Reporter) skip(n int, f string, a ...any) { r.record(n, StatusSkip, f, a...) }
func (r *Reporter) warn(n int, f string, a ...any) { r.record(n, StatusWarn, f, a...) }

// verdict records PASS when ok, else FAIL — the common "assert X" shape.
func (r *Reporter) verdict(n int, ok bool, f string, a ...any) {
	if ok {
		r.pass(n, f, a...)
	} else {
		r.fail(n, f, a...)
	}
}

func statusSeverity(s Status) int {
	switch s {
	case StatusFail:
		return 3
	case StatusWarn:
		return 2
	case StatusPass:
		return 1
	default:
		return 0
	}
}

// counts tallies the recorded results by status.
func (r *Reporter) counts() (pass, fail, skip, warn int) {
	for _, res := range r.results {
		switch res.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
		case StatusSkip:
			skip++
		case StatusWarn:
			warn++
		}
	}
	return
}

// missingRows returns the SunSpecTCP numbers with no recorded verdict — a suite
// bug (a requirement went unaddressed), which is the T06.10 acceptance guard.
func (r *Reporter) missingRows() []int {
	var missing []int
	for _, meta := range requirements {
		if _, ok := r.results[meta.n]; !ok {
			missing = append(missing, meta.n)
		}
	}
	sort.Ints(missing)
	return missing
}

// summary prints the final tally and any unaddressed rows. It returns true when
// the run is a clean pass: every requirement addressed and none FAILed.
func (r *Reporter) summary() bool {
	pass, fail, skip, warn := r.counts()
	missing := r.missingRows()
	r.printf("\n%s\n", strings.Repeat("═", 72))
	r.printf("SECURE SUNSPEC MODBUS CONFORMANCE SUMMARY\n")
	r.printf("%s\n", strings.Repeat("═", 72))
	r.printf("  Requirements: %d\n", len(requirements))
	r.printf("  PASS:         %d\n", pass)
	r.printf("  FAIL:         %d\n", fail)
	r.printf("  SKIP:         %d  (addressed, not wire-assertable — see evidence)\n", skip)
	r.printf("  WARN:         %d\n", warn)
	if len(missing) > 0 {
		r.printf("\n  ✗ %d REQUIREMENT(S) NOT ADDRESSED: %v — suite bug\n", len(missing), missingIDs(missing))
	}
	switch {
	case len(missing) > 0:
		r.printf("\n  ✗ INCOMPLETE — some requirements were never checked\n")
	case fail > 0:
		r.printf("\n  ✗ %d REQUIREMENT(S) FAILED — review log for details\n", fail)
	default:
		r.printf("\n  ✓ ALL REQUIREMENTS ADDRESSED, 0 FAILURES\n")
	}
	r.printf("%s\n\n", strings.Repeat("═", 72))
	return len(missing) == 0 && fail == 0
}

func missingIDs(ns []int) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = reqID(n)
	}
	return out
}

// markdownSection renders the CONFORMANCE_REPORT.md section — a dated header, a
// per-block requirement table (Req / Applies / Summary / Status / Evidence), and
// a roll-up — in the same shape as the root report so it appends cleanly.
func (r *Reporter) markdownSection() string {
	var b strings.Builder
	pass, fail, skip, warn := r.counts()
	fmt.Fprintf(&b, "## Secure SunSpec Modbus conformance — %s\n\n", r.started.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "**Suite:** `sim/ssm-conformance` (T06.10) — the bench's independent 62-requirement\n")
	fmt.Fprintf(&b, "Secure SunSpec Modbus/TCP walker (referee-independent mbaps client, PN-1/C9).\n")
	fmt.Fprintf(&b, "**Reference:** SunSpec *Secure SunSpec Modbus Specification* v1.0 (Approved 2025-12-10).\n")
	fmt.Fprintf(&b, "**Target:** `%s`", r.target)
	if r.device != "" {
		fmt.Fprintf(&b, " · **Device target:** `%s`", r.device)
	}
	fmt.Fprintf(&b, "\n\n")
	fmt.Fprintf(&b, "Result: **%d PASS / %d FAIL / %d SKIP / %d WARN** of %d requirements.\n\n",
		pass, fail, skip, warn, len(requirements))

	blocks := []struct{ id, name string }{
		{"5.1", "Transport Layer Security"},
		{"5.2", "Cipher Suite Selection"},
		{"5.3", "Role-Based Client Authorization"},
		{"5.4", "Public Key Infrastructure"},
		{"5.5", "Packet and Session Requirements"},
	}
	for _, blk := range blocks {
		fmt.Fprintf(&b, "### §%s %s\n\n", blk.id, blk.name)
		fmt.Fprintf(&b, "| Req | Applies | Summary | Status | Evidence |\n")
		fmt.Fprintf(&b, "|-----|---------|---------|--------|----------|\n")
		for _, meta := range requirements {
			if meta.section != blk.id {
				continue
			}
			res, ok := r.results[meta.n]
			status := "NOT ADDRESSED"
			evidence := "—"
			if ok {
				status = string(res.Status)
				evidence = mdEscape(res.Evidence)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				reqID(meta.n), meta.applies, mdEscape(meta.summary), status, evidence)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

// mdEscape neutralises the pipe so an evidence string never breaks the table.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}
