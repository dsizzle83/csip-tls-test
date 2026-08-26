package suitemodbusserver

// harness_test.go drives one check through the whole framework — selection,
// capture, live phase, frame attribution, citation, bundle — against the
// loopback device.
//
// Running the REAL runner rather than calling checks directly is deliberate.
// Half the honesty machinery this suite depends on lives in the framework, not
// here: the refusal to let a check cite another check's frames, the downgrade
// of an uncited PASS, the bundle's digests. A test that called checkDEV1
// directly would prove the check's arithmetic and none of that.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/pcapng"
)

// fakeCapture stands in for dumpcap: its Stop synthesises the capture from the
// device's recording, so the citation phase sees the real exchange.
type fakeCapture struct {
	path    string
	build   func() []pcapng.Packet
	started time.Time
}

func (f *fakeCapture) Start(context.Context) error { f.started = time.Now().UTC(); return nil }
func (f *fakeCapture) Path() string                { return f.path }

func (f *fakeCapture) Stop() (capture.Summary, error) {
	pkts := f.build()
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return capture.Summary{}, err
	}
	if err := os.WriteFile(f.path, pcapBytes(pkts), 0o644); err != nil {
		return capture.Summary{}, err
	}
	fi, err := os.Stat(f.path)
	if err != nil {
		return capture.Summary{}, err
	}
	sum := capture.Summary{
		Tool: "synthetic", ToolVersion: "test", Interface: "lo",
		Path: f.path, Format: string(pcapng.FormatPcap),
		Started: f.started, Stopped: time.Now().UTC(),
		FileBytes: fi.Size(), Packets: len(pkts),
	}
	if len(pkts) > 0 {
		sum.FirstPacket, sum.LastPacket = pkts[0].Time, pkts[len(pkts)-1].Time
	}
	return sum, nil
}

// runOutcome is what a harness run hands back to a test.
type runOutcome struct {
	Case    certify.CaseResult
	Report  *certify.RunReport
	OutDir  string
	Console string
}

// cited reports whether any assertion carries a re-checkable digest.
func (o runOutcome) cited() bool {
	for _, a := range o.Case.Assertions {
		if a.Citable() {
			return true
		}
	}
	return false
}

// assertion returns the first assertion whose claim contains sub.
func (o runOutcome) assertion(t *testing.T, sub string) bundle.Assertion {
	t.Helper()
	for _, a := range o.Case.Assertions {
		if contains(a.Claim, sub) {
			return a
		}
	}
	t.Fatalf("no assertion whose claim contains %q; assertions:\n%s", sub, o.dump())
	return bundle.Assertion{}
}

// hasAssertion reports whether any assertion's claim contains sub.
func (o runOutcome) hasAssertion(sub string) bool {
	for _, a := range o.Case.Assertions {
		if contains(a.Claim, sub) {
			return true
		}
	}
	return false
}

func (o runOutcome) dump() string {
	var b bytes.Buffer
	b.WriteString("verdict=" + string(o.Case.Verdict) + " notes=" + o.Case.Notes + "\n")
	if o.Case.Err != nil {
		b.WriteString("err=" + o.Case.Err.Error() + "\n")
	}
	if o.Case.Panic != "" {
		b.WriteString("panic=" + o.Case.Panic + "\n")
	}
	for _, a := range o.Case.Assertions {
		b.WriteString("  [" + string(a.Verdict) + "] " + a.Claim + "\n      observed: " + a.Observed + "\n")
		if a.Note != "" {
			b.WriteString("      note: " + a.Note + "\n")
		}
	}
	return b.String()
}

func contains(s, sub string) bool {
	return len(sub) <= len(s) && bytes.Contains([]byte(s), []byte(sub))
}

// runCheck selects exactly one catalog uid, binds it to check, and runs it
// against dev with a synthetic capture of the exchange.
func runCheck(t *testing.T, uid string, check certify.Check, dev *device, params map[string]string) runOutcome {
	t.Helper()

	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	// Registered WITHOUT capability requirements: the loopback transport needs
	// neither the bench nor the PKI fixtures, and requiring them here would
	// turn every test into a skip.
	reg.Register(uid, SuiteName, check)

	out := filepath.Join(t.TempDir(), "bundle")
	console := &bytes.Buffer{}
	opts := certify.DefaultOptions()
	opts.OutDir = out
	opts.Out = console
	opts.Log = certify.DiscardLogger
	opts.PKIDir = ""
	opts.UIDs = []string{uid}
	opts.CheckTimeout = 120 * time.Second
	opts.Targets = certify.Targets{
		Gateway:     dev.Addr(),
		GatewayHost: "127.0.0.1",
	}
	// The DUT here is a loopback SunSpec device with no arbitration layer at
	// all, so the write rows' control-authority precondition (certify's
	// authority.go) has nothing to be read off and no posture to be in. That
	// check fails closed with no gateway transport, correctly, and this is the
	// documented escape: an EXPLORATORY run that says out loud it is not gating —
	// which a loopback suite test is.
	opts.SkipPreflight = true
	opts.Params = map[string]string{
		paramTransport:   "plain",
		paramUnit:        "1",
		paramReversionS:  "3",
		paramUnitScanMax: "2",
	}
	for k, v := range params {
		opts.Params[k] = v
	}
	opts.Capturer = &fakeCapture{
		path:  filepath.Join(t.TempDir(), "run.pcap"),
		build: dev.synthesise,
	}

	run, err := certify.New(reg, cat, opts)
	if err != nil {
		t.Fatalf("build runner: %v", err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v\n%s", err, console.String())
	}
	if len(rep.Cases) != 1 {
		t.Fatalf("expected 1 case result, got %d\n%s", len(rep.Cases), console.String())
	}
	return runOutcome{Case: rep.Cases[0], Report: rep, OutDir: out, Console: console.String()}
}

// wantVerdict fails the test when the case's verdict is not v.
func (o runOutcome) wantVerdict(t *testing.T, v certify.Verdict) {
	t.Helper()
	if o.Case.Verdict != v {
		t.Fatalf("verdict = %s, want %s\n%s", o.Case.Verdict, v, o.dump())
	}
}

// wantVerifiableBundle proves the evidence the run wrote actually verifies.
func (o runOutcome) wantVerifiableBundle(t *testing.T) {
	t.Helper()
	vr, err := bundle.Verify(o.OutDir)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if !vr.OK {
		t.Fatalf("the bundle this run produced does not verify:\n%s", vr.String())
	}
}
