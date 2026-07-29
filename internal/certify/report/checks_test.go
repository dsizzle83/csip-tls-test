package report

// checks_test.go drives the whole pipeline — runner, capture, attribution,
// citation, bundle — on loopback, with no bench, no NIC and no root.
//
// The pattern is sim/ssm-conformance's: stand up an in-process peer, run the
// real thing against it, and prove BOTH directions. A conformant exchange must
// produce a PASS whose assertions carry digests bundle.Verify re-derives; a
// capture that does not contain the exchange must NOT produce a PASS, because a
// suite that cannot fail is a suite whose passes mean nothing.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/netdis"
)

// recorder is an in-process peer that keeps a record of the conversation, which
// is what the synthetic capture is built from. It stands in for a bench sim and
// for the packet capture at the same time, so the test needs neither.
type recorder struct {
	ln net.Listener

	mu     sync.Mutex
	client netip.AddrPort
	server netip.AddrPort
	xs     []exchange
	opened time.Time
	closed time.Time
}

func (r *recorder) addr() string { return r.ln.Addr().String() }

func (r *recorder) note(fromClient bool, b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.xs = append(r.xs, exchange{fromClient: fromClient, payload: append([]byte(nil), b...)})
}

// modbusRecorder answers FC 0x03 with two registers, echoing the transaction id
// so the derived log's request/response pairing is meaningful.
func modbusRecorder(t *testing.T) *recorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.client, _ = netip.ParseAddrPort(conn.RemoteAddr().String())
			r.server, _ = netip.ParseAddrPort(conn.LocalAddr().String())
			r.opened = time.Now()
			r.mu.Unlock()
			go func() {
				defer func() {
					r.mu.Lock()
					r.closed = time.Now()
					r.mu.Unlock()
					_ = conn.Close()
				}()
				head := make([]byte, 6)
				for {
					if _, err := io.ReadFull(conn, head); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(head[4:6]))
					body := make([]byte, n)
					if _, err := io.ReadFull(conn, body); err != nil {
						return
					}
					r.note(true, append(append([]byte{}, head...), body...))

					resp := make([]byte, 9+4)
					copy(resp[0:2], head[0:2]) // echo the transaction id
					binary.BigEndian.PutUint16(resp[4:6], 7)
					resp[6] = body[0] // unit id
					resp[7] = 0x03
					resp[8] = 4
					binary.BigEndian.PutUint16(resp[9:11], 0x5375)  // "Su"
					binary.BigEndian.PutUint16(resp[11:13], 0x6E53) // "nS"
					if _, err := conn.Write(resp); err != nil {
						return
					}
					r.note(false, resp)
				}
			}()
		}
	}()
	return r
}

// httpRecorder answers any request with a small sep+xml document.
func httpRecorder(t *testing.T) *recorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.client, _ = netip.ParseAddrPort(conn.RemoteAddr().String())
			r.server, _ = netip.ParseAddrPort(conn.LocalAddr().String())
			r.opened = time.Now()
			r.mu.Unlock()
			go func() {
				defer func() {
					r.mu.Lock()
					r.closed = time.Now()
					r.mu.Unlock()
					_ = conn.Close()
				}()
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				r.note(true, buf[:n])
				body := dcapBody
				resp := "HTTP/1.1 200 OK\r\nContent-Type: application/sep+xml; charset=utf-8\r\n" +
					"Content-Length: " + itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
				if _, err := conn.Write([]byte(resp)); err != nil {
					return
				}
				r.note(false, []byte(resp))
			}()
		}
	}()
	return r
}

// synthCapture is the certify.Capturer seam: on Stop it writes a pcap built
// from what the recorder saw, using the real 4-tuple the check dialled so the
// framework's attribution has something to match.
type synthCapture struct {
	path string
	rec  *recorder
	// drop truncates the recorded exchange, which is how the test produces a
	// capture that does not contain what the check did.
	drop int
	// step is the inter-frame interval; small enough that every frame lands
	// inside the check's window plus the attribution guard.
	step time.Duration
}

func (c *synthCapture) Start(context.Context) error { return nil }
func (c *synthCapture) Path() string                { return c.path }

func (c *synthCapture) Stop() (capture.Summary, error) {
	c.rec.mu.Lock()
	xs := append([]exchange(nil), c.rec.xs...)
	client, server, opened := c.rec.client, c.rec.server, c.rec.opened
	c.rec.mu.Unlock()
	if c.drop > 0 && len(xs) > c.drop {
		xs = xs[:len(xs)-c.drop]
	}
	if !client.IsValid() {
		return capture.Summary{}, fmt.Errorf("no connection was recorded")
	}
	step := c.step
	if step == 0 {
		step = 2 * time.Millisecond
	}
	pkts := sessionStep(client, server, opened.Add(-step), step, xs, true)
	var buf bytes.Buffer
	if err := WritePcap(&buf, netdis.LinkTypeEthernet, pkts); err != nil {
		return capture.Summary{}, err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return capture.Summary{}, err
	}
	if err := os.WriteFile(c.path, buf.Bytes(), 0o644); err != nil {
		return capture.Summary{}, err
	}
	return capture.Summary{
		Tool: "synthetic", Path: c.path, Format: "pcap",
		Packets: len(pkts), FileBytes: int64(buf.Len()),
	}, nil
}

// nullCapture is a live capture that records nothing: a valid, empty libpcap
// file. It is how a test exercises a check whose capability requirement is
// "capture" while proving the check refuses to cite frames that do not exist.
type nullCapture struct{ path string }

func (c *nullCapture) Start(context.Context) error { return nil }
func (c *nullCapture) Path() string                { return c.path }

func (c *nullCapture) Stop() (capture.Summary, error) {
	var buf bytes.Buffer
	if err := WritePcap(&buf, netdis.LinkTypeEthernet, nil); err != nil {
		return capture.Summary{}, err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return capture.Summary{}, err
	}
	return capture.Summary{Tool: "synthetic", Path: c.path, Format: "pcap"},
		os.WriteFile(c.path, buf.Bytes(), 0o644)
}

// runSuite executes one catalog uid through the real runner.
func runSuite(t *testing.T, uid string, opts func(*certify.Options)) (*certify.RunReport, string, string) {
	t.Helper()
	cat := loadCatalog(t)
	reg := certify.NewRegistry()
	RegisterInto(reg)

	out := t.TempDir()
	var console bytes.Buffer
	o := certify.DefaultOptions()
	o.UIDs = []string{uid}
	o.OutDir = out
	o.PKIDir = ""
	o.Out = &console
	o.Log = certify.DiscardLogger
	o.Targets = certify.Targets{}
	o.Params = map[string]string{}
	o.NoCapture = true
	if opts != nil {
		opts(&o)
	}
	run, err := certify.New(reg, cat, o)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v\n%s", err, console.String())
	}
	if len(rep.Cases) != 1 {
		t.Fatalf("%d case results, want 1\n%s", len(rep.Cases), console.String())
	}
	return rep, out, console.String()
}

// TestModbusLogRuleCitesTheCapturedBytes is the suite's central proof: the
// RPT-LOG-8 verdict rests on a byte range of the pcap whose digest the bundle's
// own verifier re-derives.
func TestModbusLogRuleCitesTheCapturedBytes(t *testing.T) {
	rec := modbusRecorder(t)
	uid := uidModbus("RPT-LOG-8")
	rep, out, console := runSuite(t, uid, func(o *certify.Options) {
		o.NoCapture = false
		o.Targets.ModSim = rec.addr()
		o.Capturer = &synthCapture{path: filepath.Join(t.TempDir(), "run.pcap"), rec: rec}
	})
	c := rep.Cases[0]
	if c.Verdict != certify.Pass {
		t.Fatalf("verdict %s: %s\nassertions %+v\n%s", c.Verdict, c.Notes, c.Assertions, console)
	}
	cited := 0
	for _, a := range c.Assertions {
		if a.Citable() {
			cited++
		}
	}
	if cited == 0 {
		t.Fatal("the PASS carries no re-checkable citation")
	}

	// The cited assertion must actually say the log renders those bytes.
	var msg string
	for _, a := range c.Assertions {
		if strings.Contains(a.Claim, "COMPLETE Modbus message as an ascii hex string") {
			msg = a.Observed
			if a.BytesSHA256 == "" {
				t.Error("the RPT-LOG-8 assertion cites no byte range")
			}
			if len(a.Frames) == 0 {
				t.Error("the RPT-LOG-8 assertion names no frames")
			}
		}
	}
	if !strings.Contains(msg, `"msg"`) {
		t.Errorf("the RPT-LOG-8 assertion does not quote the emitted value: %q", msg)
	}

	vr, err := bundle.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("the bundle does not verify:\n%s", vr.String())
	}
}

// TestModbusLogRuleRefusesACaptureThatIsMissingMessages is the other half. If
// the capture does not account for everything the check's own socket saw, the
// derived log is not the complete record §4 demands, and no PASS may survive.
func TestModbusLogRuleRefusesACaptureThatIsMissingMessages(t *testing.T) {
	rec := modbusRecorder(t)
	uid := uidModbus("RPT-LOG-1")
	rep, _, console := runSuite(t, uid, func(o *certify.Options) {
		o.NoCapture = false
		o.Targets.ModSim = rec.addr()
		o.Capturer = &synthCapture{
			path: filepath.Join(t.TempDir(), "run.pcap"), rec: rec,
			drop: 2, // the last transaction never made it into the capture
		}
	})
	c := rep.Cases[0]
	if c.Verdict == certify.Pass {
		t.Fatalf("a PASS survived a capture missing two messages:\n%+v\n%s", c.Assertions, console)
	}
	found := false
	for _, a := range c.Assertions {
		if strings.Contains(a.Claim, "accounts for exactly the Modbus bytes") && a.Verdict == certify.Fail {
			found = true
			if !strings.Contains(a.Observed, "THEY DIFFER") {
				t.Errorf("the mismatch is not stated: %q", a.Observed)
			}
		}
	}
	if !found {
		t.Errorf("the socket/capture cross-check did not fail:\n%+v", c.Assertions)
	}
}

// TestModbusLogRuleWithoutACaptureDoesNotPass covers the -no-capture path: a
// check that would have cited must not stand as a PASS when nothing was
// captured.
func TestModbusLogRuleWithoutACaptureDoesNotPass(t *testing.T) {
	rec := modbusRecorder(t)
	rep, _, _ := runSuite(t, uidModbus("RPT-LOG-8"), func(o *certify.Options) {
		o.NoCapture = false
		o.Targets.ModSim = rec.addr()
		o.Capturer = &nullCapture{path: filepath.Join(t.TempDir(), "empty.pcap")}
	})
	c := rep.Cases[0]
	if c.Verdict == certify.Pass {
		t.Fatalf("verdict %s though the capture contains nothing: %+v", c.Verdict, c.Assertions)
	}
	if len(c.Assertions) == 0 || c.Assertions[0].Verdict != certify.Skip {
		t.Fatalf("want a SKIP explaining the absent evidence, got %+v", c.Assertions)
	}
	if !strings.Contains(c.Assertions[0].Observed, "no capture frames were attributed") {
		t.Errorf("observed = %q", c.Assertions[0].Observed)
	}
}

func TestCSIPMessageRuleCitesTheCapturedBytes(t *testing.T) {
	rec := httpRecorder(t)
	rep, out, console := runSuite(t, uidCSIP("RPT-052"), func(o *certify.Options) {
		o.NoCapture = false
		o.Targets.GridSimAdmin = "http://" + rec.addr()
		o.Capturer = &synthCapture{path: filepath.Join(t.TempDir(), "run.pcap"), rec: rec}
	})
	c := rep.Cases[0]
	if c.Verdict != certify.Pass {
		t.Fatalf("verdict %s: %s\n%+v\n%s", c.Verdict, c.Notes, c.Assertions, console)
	}
	if !c.Citable() {
		t.Fatal("the PASS carries no re-checkable citation")
	}
	vr, err := bundle.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("the bundle does not verify:\n%s", vr.String())
	}
}

// TestKeyRowWithoutConfigurationSkips: the absence of lab metadata is a SKIP
// with instructions, never a PASS and never an invented value.
func TestKeyRowWithoutConfigurationSkips(t *testing.T) {
	rep, _, _ := runSuite(t, uidModbus("RPT-KV-3"), nil)
	c := rep.Cases[0]
	if c.Verdict != certify.Skip {
		t.Fatalf("verdict %s, want SKIP: %s", c.Verdict, c.Notes)
	}
	if !strings.Contains(c.Notes, "does not invent") {
		t.Errorf("the SKIP does not explain itself: %q", c.Notes)
	}
}

// TestKeyRowWithConfigurationPassesOffWire proves the OffWire declaration is
// carried: an uncited PASS survives only because the check said, in the bundle,
// why no packet could evidence a CSV row.
func TestKeyRowWithConfigurationPassesOffWire(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "submission.json")
	if err := os.WriteFile(cfg, []byte(`{"company_name":"Acme, Incorporated"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, out, console := runSuite(t, uidModbus("RPT-KV-3"), func(o *certify.Options) {
		o.Params[paramPrefix+"config"] = cfg
	})
	c := rep.Cases[0]
	if c.Verdict != certify.Pass {
		t.Fatalf("verdict %s: %s\n%+v\n%s", c.Verdict, c.Notes, c.Assertions, console)
	}
	if c.Downgraded != "" {
		t.Errorf("the off-wire declaration did not suppress the downgrade: %s", c.Downgraded)
	}
	if c.Citable() {
		t.Error("a CSV row was reported as wire-cited")
	}
	if !strings.Contains(c.Notes, "requirement on the TEST RESULTS REPORT") {
		t.Errorf("the off-wire reason is not in the bundle notes: %q", c.Notes)
	}
	// And the value's FORM was asserted, not its truth.
	found := false
	for _, a := range c.Assertions {
		if strings.Contains(a.Observed, `Company Name,"Acme, Incorporated"`) {
			found = true
			if !strings.Contains(a.Note, "never its truth") {
				t.Errorf("the claim overreaches: %q", a.Note)
			}
		}
	}
	if !found {
		t.Errorf("the emitted row was not quoted in any assertion:\n%+v", c.Assertions)
	}
	if _, err := bundle.Load(out); err != nil {
		t.Fatal(err)
	}
}

// TestKeyRowWithAWrongValueFails proves the key checks can fail.
func TestKeyRowWithAWrongValueFails(t *testing.T) {
	rep, _, _ := runSuite(t, uidModbus("RPT-KV-11"), func(o *certify.Options) {
		o.Params[paramPrefix+"test_laboratory"] = "Dmitri's Garage"
	})
	c := rep.Cases[0]
	if c.Verdict != certify.Fail {
		t.Fatalf("verdict %s for a laboratory outside Appendix A1: %s", c.Verdict, c.Notes)
	}
}

// TestVerdictRowsOmitUnmappableCases is the honesty test for RPT-KV-30: a bench
// SKIP has no member in the PASS|FAIL|NOT SUPPORTED enumeration, so it must be
// omitted and named, never mapped to PASS.
func TestVerdictRowsOmitUnmappableCases(t *testing.T) {
	src := writeSourceBundle(t)
	rep, _, console := runSuite(t, uidModbus("RPT-KV-30"), func(o *certify.Options) {
		o.Params[paramPrefix+"bundle"] = src
	})
	c := rep.Cases[0]
	if c.Verdict != certify.Warn {
		t.Fatalf("verdict %s: %s\n%s", c.Verdict, c.Notes, console)
	}
	var omitted string
	for _, a := range c.Assertions {
		if strings.Contains(a.Claim, "OMITTED") {
			omitted = a.Observed
		}
	}
	if !strings.Contains(omitted, "TCP-2") || !strings.Contains(omitted, "SKIP") {
		t.Errorf("the omitted case was not named: %q", omitted)
	}
	if strings.Contains(omitted, "TCP-1") {
		t.Errorf("a PASS case was reported omitted: %q", omitted)
	}
}

// writeSourceBundle writes a minimal evidence bundle for the verdict rows to be
// built from — the normal input to this suite in a real campaign.
func writeSourceBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	b := bundle.NewBuilder(bundle.RunMeta{
		Tool: "csip-certify", ToolVersion: "test",
		Started: time.Now().UTC(), Finished: time.Now().UTC(),
	})
	b.AddCase(bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::TCP-1", Title: "x", Verdict: bundle.Pass})
	b.AddCase(bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::TCP-2", Title: "y", Verdict: bundle.Skip})
	b.AddCase(bundle.TestCaseResult{ID: "ss-modbus-conf-v1.4::EXC-1", Title: "z", Verdict: bundle.Fail})
	if _, err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestTraceRowFailsWithoutAScenario: RPT-060 is registered only under the
// CSIP claim, so its running at all means the campaign claims CSIP and RRS
// v1.1 Chapter 5 makes the trace a submission requirement — a SKIP here used
// to make a forgotten -param report.comm004 indistinguishable from "not
// required", which is exactly the silent gap the row must not produce.
func TestTraceRowFailsWithoutAScenario(t *testing.T) {
	rep, _, _ := runSuite(t, uidCSIP("RPT-060"), func(o *certify.Options) {
		o.NoCapture = false
		o.Capturer = &nullCapture{path: filepath.Join(t.TempDir(), "empty.pcap")}
	})
	c := rep.Cases[0]
	if c.Verdict != certify.Fail {
		t.Fatalf("verdict %s: %s", c.Verdict, c.Notes)
	}
	if !strings.Contains(c.Notes, "COMM-004") || !strings.Contains(c.Notes, "not optional") {
		t.Errorf("the FAIL does not explain itself: %q", c.Notes)
	}
}

// TestNotAssessableRowsCarryTheirReason: a registered SKIP with a reason reads
// as an engineering judgement. A SKIP with an empty note reads as an oversight,
// and this suite has 8 of them, so the reasons matter.
func TestNotAssessableRowsCarryTheirReason(t *testing.T) {
	for _, uid := range []string{
		uidCSIP("RPT-003"), uidCSIP("RPT-004"), uidCSIP("RPT-041"),
		uidModbus("RPT-GEN-2"), uidModbus("RPT-GEN-3"), uidModbus("RPT-LOG-9"),
		uidModbus("RPT-TRR-3"),
	} {
		rep, _, _ := runSuite(t, uid, nil)
		c := rep.Cases[0]
		if c.Verdict != certify.Skip {
			t.Errorf("%s: verdict %s", uid, c.Verdict)
		}
		if len(c.Notes) < 120 {
			t.Errorf("%s: the reason is %d characters — too short to be a judgement: %q",
				uid, len(c.Notes), c.Notes)
		}
	}
}

// TestDeliverableRowWritesASubmission runs the end-to-end generator through the
// framework and checks the artefact on disk, not the intent behind it.
func TestDeliverableRowWritesASubmission(t *testing.T) {
	rec := modbusRecorder(t)
	sub := t.TempDir()
	rep, _, console := runSuite(t, uidModbus("RPT-TRR-1"), func(o *certify.Options) {
		o.NoCapture = false
		o.Targets.ModSim = rec.addr()
		o.Capturer = &synthCapture{path: filepath.Join(t.TempDir(), "run.pcap"), rec: rec}
		o.Params[paramPrefix+"out"] = sub
	})
	c := rep.Cases[0]
	if c.Verdict == certify.Fail {
		t.Fatalf("verdict %s: %s\n%+v\n%s", c.Verdict, c.Notes, c.Assertions, console)
	}
	root := filepath.Join(sub, "sunspec-modbus")
	for _, rel := range []string{
		filepath.Join(PublicDir, IncompleteFile),
		filepath.Join(ArchiveDir, LogsFile),
		ReadinessFile, ManifestFile,
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("submission is missing %s: %v", rel, err)
		}
	}
	// The archived detailed log must be the one derived from the capture.
	data, err := os.ReadFile(filepath.Join(root, ArchiveDir, LogsFile))
	if err != nil {
		t.Fatal(err)
	}
	logs, err := ParseModbusTestLogs(data)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(allEntries(logs)); n < 4 {
		t.Errorf("the archived log carries %d entries; the exchange had a conn, two pairs and a disc", n)
	}
	if f := ValidateModbusTestLogs(logs, TransportTCP); len(f) != 0 {
		t.Errorf("the archived log does not validate: %v", f)
	}
}
