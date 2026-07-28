package report

// suite.go is the run-scoped state the checks share and the two primitives they
// are built from: the submission builder and the wire probe.
//
// # Why a wire probe at all, in a suite about a document
//
// Fifteen of the Modbus rows and six of the CSIP rows are requirements on the
// CONTENT of the detailed logs — that a `msg` is the complete Modbus message as
// ascii hex, that a `conn` entry carries the endpoint, that an HTTP message is
// recorded in plaintext with all its headers. A check could satisfy those by
// emitting a log from a fixture and validating it, and would prove only that
// this package can write JSON that matches its own schema.
//
// So each of those checks conducts a real exchange it claims, and in the
// citation phase derives the log entry FROM THE CAPTURED BYTES and cites the
// exact byte range the entry renders. What the bundle then contains is not
// "the emitter produced a well-formed entry" but "these captured bytes, whose
// sha256 is in the bundle, are what this log entry says they are". That is a
// claim a stranger can check with a pcap viewer and a hex editor.
//
// The exchange goes to a SIM, never to the gateway: the reporting suite has no
// business perturbing the DUT, and a plain Modbus sim gives cleartext frames
// whose reassembly needs no key material.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
)

// SuiteName is the -suite selector for these checks.
const SuiteName = "results-report"

// Tool identifies the generator in Additional Test Comments.
const Tool = "csip-certify/report"

// Suite is the run-scoped state.
//
// It is a value rather than package-level state so a test can stand up its own
// suite against its own registry without the global one seeing it — the same
// reason certify.NewRegistry exists.
type Suite struct {
	mu sync.Mutex

	cfg       *SubmissionConfig
	cfgLoaded bool
	cfgErr    error
	// cfgSupplied is false when the operator configured nothing at all, which
	// is a SKIP for every submitter/lab row rather than a pile of failures.
	cfgSupplied bool

	src    *bundle.Bundle
	srcErr error
	srcSet bool

	outDir string
}

// NewSuite returns an empty suite.
func NewSuite() *Suite { return &Suite{} }

// param reads a -param report.<name> value.
func param(rc *certify.RunCtx, name string) (string, bool) {
	return rc.Param(paramPrefix + name)
}

// Config resolves the submission metadata once per run.
//
// Sources, in order: the file named by -param report.config, then any
// -param report.<key>=<value> overlay. An operator who supplied neither gets an
// empty configuration and a false second result, which the checks turn into a
// SKIP naming what to supply — never into invented values.
func (s *Suite) Config(rc *certify.RunCtx) (*SubmissionConfig, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfgLoaded {
		return s.cfg, s.cfgSupplied, s.cfgErr
	}
	s.cfgLoaded = true
	cfg := &SubmissionConfig{}
	if path, ok := param(rc, "config"); ok && path != "" {
		loaded, err := LoadConfig(path)
		if err != nil {
			s.cfg, s.cfgErr = cfg, err
			return s.cfg, false, err
		}
		cfg = loaded
		s.cfgSupplied = true
	}
	if err := cfg.ApplyParams(rc.Params); err != nil {
		s.cfg, s.cfgErr = cfg, err
		return s.cfg, s.cfgSupplied, err
	}
	for k := range rc.Params {
		if name, ok := strings.CutPrefix(k, paramPrefix); ok && !reservedParams[name] {
			s.cfgSupplied = true
		}
	}
	s.cfg = cfg
	return s.cfg, s.cfgSupplied, nil
}

// SourceBundle loads the evidence bundle a submission is built from.
//
// This is the normal use of the whole suite: a conformance campaign writes a
// bundle, and a second run over that bundle turns it into a submission. Without
// one there are no test-procedure verdicts to report, and the rows that carry
// verdicts SKIP saying so.
func (s *Suite) SourceBundle(rc *certify.RunCtx) (*bundle.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srcSet {
		return s.src, s.srcErr
	}
	s.srcSet = true
	dir, ok := param(rc, "bundle")
	if !ok || dir == "" {
		return nil, nil
	}
	b, err := bundle.Load(dir)
	if err != nil {
		s.srcErr = fmt.Errorf("report: load source evidence bundle %s: %w", dir, err)
		return nil, s.srcErr
	}
	s.src = b
	return b, nil
}

// TRRDir names an ALREADY-EMITTED Test Results Report package the document
// rows should be asserted against, from -param report.trr.
//
// Without it the checks build a summary from the configuration and validate
// that, which proves the generator agrees with itself. With it they parse the
// bytes on disk — the file that will actually be sent — and the claim changes
// from "this package can emit a conformant CSV" to "the CSV in this directory
// is conformant". That is the difference between a self-test and a check, and
// it is why the parameter exists.
func (s *Suite) TRRDir(rc *certify.RunCtx) string {
	dir, ok := param(rc, "trr")
	if !ok {
		return ""
	}
	return strings.TrimSpace(dir)
}

// Subject is the Summary Test Results a document-shape check asserts against.
type Subject struct {
	// Parsed is the re-parsed CSV. Every assertion is made against THIS: what
	// the file says is the only thing a reviewer at SunSpec will ever see.
	Parsed *ParsedSummary
	// Summary is the model behind it, when this run built it. Nil for an
	// on-disk package, which is exactly the point — there is no model to
	// consult, only the document.
	Summary *Summary
	// Source names the artefact, for the assertion's provenance field.
	Source string
	// OnDisk is true when the subject is an emitted package rather than a
	// summary this run generated.
	OnDisk bool
	// Supplied is false when there is nothing to assert: no emitted package and
	// no submission metadata.
	Supplied bool
}

// Subject resolves what the document-shape checks assert against.
func (s *Suite) Subject(rc *certify.RunCtx, certType string, verdicts []TestVerdict) (*Subject, error) {
	if dir := s.TRRDir(rc); dir != "" {
		path, data, err := ReadEmittedSummary(dir, certType)
		if err != nil {
			return nil, err
		}
		p, perr := ParseSummary(data)
		if perr != nil {
			return nil, fmt.Errorf("report: %s does not parse as a Summary Test Results CSV: %w", path, perr)
		}
		return &Subject{Parsed: p, Source: path, OnDisk: true, Supplied: true}, nil
	}
	cfg, supplied, err := s.Config(rc)
	if err != nil {
		return nil, err
	}
	sum := BuildSummary(cfg, certType, verdicts)
	data, err := sum.CSV()
	if err != nil {
		return nil, err
	}
	p, err := ParseSummary(data)
	if err != nil {
		return nil, fmt.Errorf("report: the Summary Test Results this run emitted does not re-parse as CSV: %w", err)
	}
	return &Subject{
		Parsed: p, Summary: sum, Supplied: supplied,
		Source: "the Summary Test Results CSV this run generated",
	}, nil
}

// ReadEmittedSummary finds one certificate type's Summary Test Results inside a
// Test Results Report package.
//
// Both file names are tried, because which one a package carries is itself a
// statement: SUMMARY.csv means every required key had a value, and
// SUMMARY-INCOMPLETE.csv means some did not. A checker that only looked for the
// first would report a package as absent when it is merely honest about being
// short.
func ReadEmittedSummary(dir, certType string) (string, []byte, error) {
	base := filepath.Join(dir, certTypeSlug(certType), PublicDir)
	var tried []string
	for _, name := range []string{SummaryFile, IncompleteFile} {
		path := filepath.Join(base, name)
		tried = append(tried, path)
		data, err := os.ReadFile(path)
		if err == nil {
			return path, data, nil
		}
	}
	return "", nil, fmt.Errorf("report: the Test Results Report package %s carries no Summary Test Results "+
		"for %s; looked for %s", dir, certType, strings.Join(tried, " and "))
}

// ReadEmittedLogs reads one certificate type's §4 Detailed Test Logs out of a
// package, or reports that the archive is absent.
func ReadEmittedLogs(dir, certType string) (string, []byte, error) {
	path := filepath.Join(dir, certTypeSlug(certType), ArchiveDir, LogsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return path, nil, err
	}
	return path, data, nil
}

// OutDir is where the submission is written. -param report.out names it; with
// no parameter a per-run temporary directory is used and its path is recorded
// in the case notes, so a run that was not asked to persist a submission still
// leaves one a reviewer can look at.
func (s *Suite) OutDir(rc *certify.RunCtx) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outDir != "" {
		return s.outDir, nil
	}
	if dir, ok := param(rc, "out"); ok && dir != "" {
		s.outDir = dir
		return dir, nil
	}
	dir, err := os.MkdirTemp("", "csip-submission-")
	if err != nil {
		return "", fmt.Errorf("report: create submission directory: %w", err)
	}
	s.outDir = dir
	return dir, nil
}

// Verdicts maps a source bundle's test cases to `Test <Test ID>` rows.
//
// It is [MapVerdict] applied case by case, with no catalog: this entry point
// takes a bundle and nothing else, and without the catalog the bundle archived
// there is nothing that licenses a NOT SUPPORTED row, so every SKIP and every
// WARN is omitted and named. That is the conservative direction — a report that
// claims less, never more — and it is why the richer path ([Collate], which
// reads each bundle's own archived catalog) is what the -trr mode uses.
//
// The rule itself, and the §3.1.1 text it comes from, is derived once in
// trr.go's file comment. Nothing here re-decides it.
func Verdicts(b *bundle.Bundle) (rows []TestVerdict, omitted []string) {
	if b == nil {
		return nil, nil
	}
	for _, c := range b.Cases {
		if ReportOnSelf[DocKeyOf(c.ID)] {
			continue
		}
		row, gap := MapVerdict(c, nil, "")
		if gap != nil {
			omitted = append(omitted, fmt.Sprintf("%s (%s)", gap.ID, gap.BenchVerdict))
			continue
		}
		rows = append(rows, *row)
	}
	return rows, omitted
}

// Build assembles a submission from everything the run has.
func (s *Suite) Build(rc *certify.RunCtx, certType string, logs any) (*Submission, []string, error) {
	cfg, _, err := s.Config(rc)
	if err != nil {
		return nil, nil, err
	}
	src, err := s.SourceBundle(rc)
	if err != nil {
		return nil, nil, err
	}
	rows, omitted := Verdicts(src)
	dir, err := s.OutDir(rc)
	if err != nil {
		return nil, nil, err
	}
	opts := GenerateOptions{
		Dir:      filepath.Join(dir, strings.ToLower(strings.ReplaceAll(certTypeSlug(certType), " ", "-"))),
		CertType: certType, Doc: docFor(certType), Config: cfg, Verdicts: rows,
		AllowIncomplete: true, Tool: Tool, ToolVersion: toolVersion(src),
	}
	switch l := logs.(type) {
	case *ModbusTestLogs:
		opts.ModbusLogs = l
	case *CSIPTestLogs:
		opts.CSIPLogs = l
	}
	sub, err := Generate(opts)
	return sub, omitted, err
}

func certTypeSlug(certType string) string {
	if certType == CertTypeModbus {
		return "sunspec-modbus"
	}
	return "ieee-2030.5-csip"
}

func docFor(certType string) string {
	if certType == CertTypeModbus {
		return DocModbus
	}
	return DocCSIP
}

func toolVersion(b *bundle.Bundle) string {
	if b == nil {
		return ""
	}
	return b.Run.ToolVersion
}

// ---------------------------------------------------------------------------
// The wire probe
// ---------------------------------------------------------------------------

// Probe is one exchange a check conducted and claimed, kept so the citation
// phase can find the conversation again after the socket is gone.
type Probe struct {
	Server netip.AddrPort
	Local  netip.AddrPort
	// Sent and Received are what the check's own socket saw, which is the
	// cross-check against what the capture says: a difference between the two
	// is a capture problem, and the check reports it rather than citing.
	Sent     [][]byte
	Received []byte
}

// modbusTarget resolves the Modbus endpoint to probe: -param report.modbus, or
// the plain SunSpec sim. Never the gateway — see the file comment.
func modbusTarget(rc *certify.RunCtx) (string, error) {
	if t, ok := param(rc, "modbus"); ok && t != "" {
		return t, nil
	}
	if rc.Targets.ModSim == "" {
		return "", fmt.Errorf("no Modbus endpoint configured (-modsim, or -param report.modbus=host:port)")
	}
	return rc.Targets.ModSim, nil
}

// ProbeModbus opens a Modbus TCP connection, exchanges n read-holding-register
// transactions, and closes it — producing a capture window that contains a
// complete session: SYN, requests, responses, FIN.
//
// The transaction ids ascend, which matters: the §4.1.2 examples show 0x0000 on
// both request and response, and a log derived from a real exchange should show
// them varying and pairing. A check asserts exactly that.
func ProbeModbus(ctx context.Context, rc *certify.RunCtx, n int) (*Probe, error) {
	target, err := modbusTarget(rc)
	if err != nil {
		return nil, err
	}
	server, err := certify.AddrPort(target)
	if err != nil {
		return nil, err
	}
	conn, err := rc.DialTCP(ctx, target, "Modbus TCP exchange for detailed-test-log evidence")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	local, err := localAddrPort(conn)
	if err != nil {
		return nil, err
	}
	p := &Probe{Server: server, Local: local}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	for i := 0; i < n; i++ {
		req := readHoldingRegisters(uint16(i+1), 1, sunSpecIDRegister, 2)
		if _, err := conn.Write(req); err != nil {
			return nil, fmt.Errorf("write Modbus request %d: %w", i+1, err)
		}
		p.Sent = append(p.Sent, req)
		resp, err := readMBAP(conn)
		if err != nil {
			return nil, fmt.Errorf("read Modbus response %d: %w", i+1, err)
		}
		p.Received = append(p.Received, resp...)
	}
	return p, nil
}

// sunSpecIDRegister is the SunSpec identifier's conventional base holding
// register. Any readable address would do — the evidence is the FRAMING, not
// the register contents — but reading the identifier means a response that is
// meaningful to anyone opening the pcap.
const sunSpecIDRegister = 40000

// readHoldingRegisters builds an MBAP-framed FC 0x03 request.
func readHoldingRegisters(txid uint16, unit uint8, addr, qty uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], txid)
	binary.BigEndian.PutUint16(b[2:4], 0) // protocol id
	binary.BigEndian.PutUint16(b[4:6], 6) // unit + fc + addr + qty
	b[6] = unit
	b[7] = 0x03
	binary.BigEndian.PutUint16(b[8:10], addr)
	binary.BigEndian.PutUint16(b[10:12], qty)
	return b
}

// readMBAP reads exactly one MBAP-framed message: the 6-byte header first, then
// the Length the header declares. Reading "whatever arrives" would make the
// check's own record of the exchange depend on segmentation, and the whole
// point is that it does not.
func readMBAP(conn net.Conn) ([]byte, error) {
	head := make([]byte, mbapHeaderLen)
	if _, err := readFull(conn, head); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(head[4:6]))
	if length < 2 || length > 253 {
		return nil, fmt.Errorf("MBAP Length field is %d, outside the 2..253 a Modbus PDU can occupy", length)
	}
	body := make([]byte, length)
	if _, err := readFull(conn, body); err != nil {
		return nil, err
	}
	return append(head, body...), nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// httpTarget resolves a plain-HTTP endpoint to probe for the CSIP message-object
// rows: -param report.http, else the gridsim admin API, else a sim's simapi.
func httpTarget(rc *certify.RunCtx) (string, error) {
	if t, ok := param(rc, "http"); ok && t != "" {
		return t, nil
	}
	for _, raw := range []string{rc.Targets.GridSimAdmin, rc.Targets.ModSimAPI, rc.Targets.MBAPSDevAPI} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		return u.Host, nil
	}
	return "", fmt.Errorf("no plain-HTTP endpoint configured (-gridsim-admin, or -param report.http=host:port)")
}

// ProbeHTTP conducts one plaintext HTTP request/response exchange and claims it.
//
// It is deliberately a request the bench's own sim answers rather than a CSIP
// resource on the DUT. The rows being evidenced (RPT-051..RPT-055) are
// requirements on the SHAPE of a logged HTTP message — that it carries the
// method, the URI, the version, every header, the body, and on a response the
// status code as a string and the reason with its CRLF. A sim's answer
// exercises every one of them, and the assertion says plainly which exchange it
// was derived from. The sep+xml DeviceCapability payload of §4.1.2's worked
// example needs a real 2030.5 session, and the check that wants it SKIPs with
// that reason rather than dressing this exchange up as one.
func ProbeHTTP(ctx context.Context, rc *certify.RunCtx, path string) (*Probe, error) {
	target, err := httpTarget(rc)
	if err != nil {
		return nil, err
	}
	server, err := certify.AddrPort(target)
	if err != nil {
		return nil, err
	}
	conn, err := rc.DialTCP(ctx, target, "plaintext HTTP exchange for detailed-test-log evidence")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	local, err := localAddrPort(conn)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	req := []byte("GET " + path + " HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Accept: application/sep+xml\r\n" +
		"User-Agent: " + Tool + "\r\n" +
		"Connection: close\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write HTTP request: %w", err)
	}
	p := &Probe{Server: server, Local: local, Sent: [][]byte{req}}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		p.Received = append(p.Received, buf[:n]...)
		if err != nil {
			break
		}
	}
	if len(p.Received) == 0 {
		return nil, fmt.Errorf("the HTTP endpoint %s returned nothing", target)
	}
	return p, nil
}

func localAddrPort(conn net.Conn) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("report: local address %q: %w", conn.LocalAddr(), err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

// offWire is the mandatory justification for a criterion the wire cannot show.
// It is a function rather than a constant so every use names the artefact and
// the rule, which is what makes the declaration honest rather than a way to
// silence the uncited-PASS downgrade.
func offWire(artefact, rule string) string {
	return "this row is a requirement on the TEST RESULTS REPORT, not on any exchange with the DUT: " +
		rule + ". The observation is a parse of " + artefact + ", which this run generated and re-read; " +
		"no packet can evidence it, so no frame citation exists"
}

// docAssertion is a live-phase assertion about an emitted document. It carries
// no digest, which is why the check that returns it must also declare OffWire —
// otherwise the runner is right to downgrade the PASS.
func docAssertion(claim, method string, v certify.Verdict, observed, source string) certify.Assertion {
	return certify.Assertion{
		Claim: claim, Method: method, Verdict: v, Observed: observed,
		Note: "not wire-cited; source: " + source,
	}
}

// skipAssertion is the live-phase SKIP: addressed, not asserted, with the reason.
func skipAssertion(claim, method, reason string) certify.Assertion {
	return certify.Assertion{
		Claim: claim, Method: method, Verdict: certify.Skip,
		Observed: reason, Note: "not asserted in this run",
	}
}

// summarise renders a byte count and a first-bytes preview for an Observed
// field, bounded so one large body cannot fill a report.
func preview(b []byte, n int) string {
	if len(b) <= n {
		return fmt.Sprintf("%d byte(s): %q", len(b), string(b))
	}
	return fmt.Sprintf("%d byte(s), first %d: %q…", len(b), n, string(b[:n]))
}
