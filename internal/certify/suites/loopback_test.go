package suites_test

// loopback_test.go is this tool's acceptance bar, and it is deliberately the
// harshest one available without a bench:
//
//	a REAL packet capture (dumpcap on lo, not a synthesised pcap),
//	against a REAL SunSpec Modbus device (sim/southbound, the same server the
//	    bench's modsim runs),
//	driven by the REAL runner and the REAL registry with all six suites linked,
//	producing a REAL evidence bundle,
//	which is then handed to bundle.Verify — the same function a third party runs.
//
// # Why a non-conformant peer is not optional
//
// A check that always returns PASS passes against a good device too. So the same
// two checks run twice: once against a device built to the specification, and
// once against a device whose Common Model manufacturer string reads its
// not-implemented value — the one thing DEV-2 exists to catch. The second run
// must FAIL, and its FAIL must carry a citation the verifier re-derives from
// the capture. That pairing is what makes the first run's PASS mean anything;
// it is the pattern sim/ssm-conformance set for itself and internal/certify's
// per-suite harnesses follow, applied here to the whole assembled CLI stack.
//
// # What this proves that a per-suite test cannot
//
// Each suite already tests its own checks. What none of them can test is the
// assembly: that all six suites link into one binary without a duplicate
// registration, that the catalog the binary finds is the one the suites were
// written against (no orphans), that a real capture on a real interface
// attributes to the right check, and that what comes out the far end verifies.
// Those are the failures that only appear when everything is in the same
// process, which is exactly when nobody is looking.
//
// # Why plain Modbus and not mbaps
//
// The transport is orthogonal to what is under test here, and plaintext frames
// mean the assertion citations point at bytes a reviewer can read in Wireshark
// with no key material — which is also why the bench's southbound modsim is
// plaintext on purpose. SunSpecTCP-9 is the requirement that the two transports
// are identical above the socket, and the suite's own tests cover the mbaps
// path.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suites"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	southbound "csip-tls-test/sim/southbound"
)

// The two catalog cases this test drives. DEV-1 asserts the discovery
// machinery (identifier at a standard base, walkable chain, terminated); DEV-2
// asserts model 1's mandatory points. DEV-2 is the one the broken device fails.
const (
	uidDEV1 = "ss-modbus-conf-v1.4::DEV-1"
	uidDEV2 = "ss-modbus-conf-v1.4::DEV-2"
)

// mnFirstReg / mnRegCount are the register range holding model 1's Mn
// (manufacturer) point: SunSpec base 40000, the two-register start marker,
// model 1's (ID, L) header, then Mn as the first 16 registers of the block.
// Zeroing them makes a mandatory String point read its not-implemented value —
// a real, specific non-conformance, not a corrupted socket.
const (
	mnFirstReg = 40004
	mnRegCount = 16
)

// A finding, recorded here because it is why this file uses NewSolarServer
// rather than the simpler NewServer:
//
// southbound.Populate — the static inverter behind southbound.NewServer —
// writes the Model 1 serial with setStr8(m1Base+32), and offset 32 is Opt, not
// SN. The canonical layout (lexa-proto/sunspec/identity.go) is Mn(0,16) /
// Md(16,16) / Opt(32,8) / Vr(40,8) / SN(48,16), so that device serves an empty
// SN, which is a mandatory Common Model point reading its not-implemented
// value. populateSolarCore was fixed for exactly this (its comment names the
// bench finding: two sims collapsing into one nb_unit because both serials were
// empty); Populate was not.
//
// DEV-2 catches it, which is the referee doing its job — but a device that
// fails a check for a reason unrelated to what the test is demonstrating makes
// a bad fixture, so the conformant peer here is the corrected one. The bug is
// in sim/southbound, outside this package, and is reported rather than silently
// patched around.

// device is a running loopback SunSpec device. southbound's solar server type
// embeds *southbound.Server, so both the register bank and Stop come from it.
type device = southbound.SolarServer

func TestLoopbackCampaignProducesAVerifiableBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: this test spawns a real packet capture")
	}
	requireCapture(t)

	// The conformant device and the broken one, on separate ports so each run's
	// capture filter isolates its own traffic.
	_, goodAddr := startDevice(t, nil)
	_, badAddr := startDevice(t, func(d *device) {
		for i := uint16(0); i < mnRegCount; i++ {
			d.Regs.Set(mnFirstReg+i, 0)
		}
	})

	t.Run("conformant device passes with citations", func(t *testing.T) {
		out := campaign(t, goodAddr)
		requireVerdict(t, out, uidDEV1, certify.Pass)
		requireVerdict(t, out, uidDEV2, certify.Pass)
		requireCited(t, out, uidDEV1)
		requireCited(t, out, uidDEV2)
		verifyBundle(t, out.dir, true)
	})

	// The teeth. Same binary, same checks, same capture machinery; one register
	// block reads its not-implemented value and the verdict must turn over.
	t.Run("non-conformant device fails the check it violates", func(t *testing.T) {
		out := campaign(t, badAddr)
		requireVerdict(t, out, uidDEV2, certify.Fail)
		requireCited(t, out, uidDEV2)

		// The failure must SAY what was wrong, and say it about the right
		// point: a FAIL whose evidence does not name the violated criterion is
		// no better than a coin toss that landed correctly.
		if got := findAssertion(t, out, uidDEV2, "mandatory"); !strings.Contains(got.Observed, "Mn=") {
			t.Errorf("the failing assertion does not report Mn's observed value: %+v", got)
		} else if !strings.Contains(got.Observed, "not-implemented") {
			t.Errorf("the failing assertion does not name the not-implemented sentinel: %s", got.Observed)
		}

		// A bundle recording a FAIL must still verify: verification is about
		// whether the cited bytes are in the capture, not about whether the DUT
		// behaved. Conflating the two would make a failing run unciteable,
		// which is precisely when the evidence matters most.
		verifyBundle(t, out.dir, true)
	})
}

// outcome is one campaign's result plus where its bundle landed.
type outcome struct {
	rep     *certify.RunReport
	dir     string
	console string
}

// campaign runs the two checks against addr with a live capture, exactly the
// way cmd/certify does: the process-wide registry with all six suites linked,
// the committed catalog, one capture for the whole run.
func campaign(t *testing.T, addr string) outcome {
	t.Helper()
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	dir := t.TempDir()
	console := &strings.Builder{}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}

	opts := certify.DefaultOptions()
	opts.UIDs = []string{uidDEV1, uidDEV2}
	opts.Targets = certify.Targets{Gateway: addr}
	// The suite requires a "pki" capability even for the plain transport,
	// because the tag records whether a fixture directory was configured at
	// all. The plain transport asks it for nothing; pointing it at the
	// committed fixture set is what an operator does and keeps the tag
	// truthful.
	opts.PKIDir = pkiDir(t)
	opts.Iface = "lo"
	// Filter to this device's port. A bench capture without a filter is the
	// right default — a frame excluded by a filter is unrecoverable — but here
	// the point is to prove attribution against a known, bounded set.
	opts.BPF = "tcp port " + port
	opts.OutDir = dir
	opts.Out = console
	opts.Log = certify.DiscardLogger
	opts.Operator = "loopback acceptance test"
	opts.CheckTimeout = 60 * time.Second
	opts.Params = map[string]string{
		// Plain Modbus/TCP: no TLS, so the citations point at bytes a reviewer
		// reads without key material.
		"modbus.transport": "plain",
		// The device answers on unit 1; bounding the scan keeps the run short
		// and the capture small.
		"modbus.unit": "1",
	}

	runner, err := certify.New(suites.Registry(), cat, opts)
	if err != nil {
		t.Fatalf("build runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	rep, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, console.String())
	}
	if rep.BundleDir == "" {
		t.Fatalf("the run wrote no bundle\n%s", console.String())
	}
	// A run whose capture caught nothing has not tested the thing this file
	// exists to test.
	if rep.Capture.Packets == 0 {
		t.Fatalf("the capture recorded no packets — nothing was attributed or cited\n%s", console.String())
	}
	return outcome{rep: rep, dir: rep.BundleDir, console: console.String()}
}

// startDevice brings up an in-process SunSpec Modbus TCP server on a free
// loopback port. breakIt, when non-nil, is applied after population and is how
// a specific non-conformance is introduced.
func startDevice(t *testing.T, breakIt func(*device)) (*device, string) {
	t.Helper()
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// The solar sim, not the static one: see the finding recorded at the top of
	// this file about southbound.Populate's misplaced serial.
	dev, err := southbound.NewSolarServer("tcp://"+addr, 5000, "LOOPBACK-ACCEPT-1")
	if err != nil {
		t.Fatalf("start SunSpec device on %s: %v", addr, err)
	}
	if breakIt != nil {
		breakIt(dev)
	}
	t.Cleanup(dev.Stop)
	return dev, addr
}

// freePort asks the kernel for an unused port and gives it straight back, which
// is the only way to get one that does not race with another test binary.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return port
}

// requireCapture skips rather than fails when no capture tool is usable. A
// developer without dumpcap's capabilities should not see a red test they
// cannot fix; CI and the desktop bench both have it (`getcap
// /usr/bin/dumpcap` → cap_net_admin,cap_net_raw=eip).
func requireCapture(t *testing.T) {
	t.Helper()
	tool, err := capture.Detect()
	if err != nil {
		t.Skipf("no packet-capture tool available: %v", err)
	}
	probe, err := capture.New("lo", "tcp port 1", filepath.Join(t.TempDir(), "probe.pcapng"))
	if err != nil {
		t.Skipf("capture unavailable (%s): %v", tool, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := probe.Start(ctx); err != nil {
		t.Skipf("cannot capture on lo with %s (needs cap_net_raw or root): %v", tool, err)
	}
	if _, err := probe.Stop(); err != nil {
		t.Skipf("probe capture did not stop cleanly: %v", err)
	}
}

// pkiDir locates the committed mbaps fixture directory from this package.
func pkiDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "certs", "mbaps")
	if _, err := os.Stat(dir); err != nil {
		// Not a reason to fail: the plain transport needs no certificate, and
		// the capability tag only records that a directory was configured.
		return t.TempDir()
	}
	return dir
}

// requireVerdict asserts one case's verdict, printing the whole console on a
// mismatch — the notes are where the reason lives.
func requireVerdict(t *testing.T, o outcome, uid string, want certify.Verdict) {
	t.Helper()
	c := caseResult(t, o, uid)
	if c.Verdict != want {
		t.Fatalf("%s: verdict %s, want %s\nnotes: %s\n\n%s", uid, c.Verdict, want, c.Notes, o.console)
	}
}

// requireCited asserts the case carries at least one assertion the verifier can
// re-derive. A verdict with no citation is the failure mode this whole
// framework exists to prevent, and it must be impossible in the happy path too.
func requireCited(t *testing.T, o outcome, uid string) {
	t.Helper()
	c := caseResult(t, o, uid)
	for _, a := range c.Assertions {
		if a.Citable() {
			return
		}
	}
	t.Fatalf("%s: no assertion carries a re-checkable citation\nnotes: %s\n\n%s", uid, c.Notes, o.console)
}

func caseResult(t *testing.T, o outcome, uid string) certify.CaseResult {
	t.Helper()
	for _, c := range o.rep.Cases {
		if c.Case.UID == uid {
			return c
		}
	}
	t.Fatalf("%s is not in the run report\n%s", uid, o.console)
	return certify.CaseResult{}
}

// findAssertion returns the first assertion of a case whose claim contains sub.
func findAssertion(t *testing.T, o outcome, uid, sub string) certify.Assertion {
	t.Helper()
	c := caseResult(t, o, uid)
	for _, a := range c.Assertions {
		if strings.Contains(a.Claim, sub) {
			return a
		}
	}
	t.Fatalf("%s: no assertion whose claim contains %q; have %d assertion(s)", uid, sub, len(c.Assertions))
	return certify.Assertion{}
}

// verifyBundle runs the standalone verifier over the written bundle, which is
// the only claim this tool actually makes to a third party.
func verifyBundle(t *testing.T, dir string, wantOK bool) {
	t.Helper()
	rep, err := bundle.Verify(dir)
	if err != nil {
		t.Fatalf("verify %s: %v", dir, err)
	}
	if rep.OK != wantOK {
		t.Fatalf("verify %s: OK=%v, want %v\n%s", dir, rep.OK, wantOK, rep.String())
	}
	if wantOK && rep.Checked == 0 {
		t.Fatalf("verify %s: the bundle verified, but not one assertion carried a digest to check — "+
			"an empty proof is not a proof\n%s", dir, rep.String())
	}
}

// TestTamperedCaptureBreaksVerification proves the verifier is load-bearing:
// change one byte of the capture a bundle cites and verification must fail.
//
// Without this, "the bundle verifies" would be an untested claim about an
// untested function, and every PASS in every bundle would rest on it.
func TestTamperedCaptureBreaksVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: this test spawns a real packet capture")
	}
	requireCapture(t)

	_, addr := startDevice(t, nil)
	out := campaign(t, addr)
	verifyBundle(t, out.dir, true)

	b, err := bundle.Load(out.dir)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	path := filepath.Join(out.dir, filepath.FromSlash(b.Files.Capture))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	// Flip a bit deep in the file, past the headers, where payload lives.
	if len(data) < 512 {
		t.Fatalf("capture is only %d bytes; nothing to tamper with", len(data))
	}
	data[len(data)-16] ^= 0xFF
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write tampered capture: %v", err)
	}

	rep, err := bundle.Verify(out.dir)
	if err == nil && rep.OK {
		t.Fatalf("a tampered capture still verified — the bundle's guarantee is worthless\n%s", rep.String())
	}
}
