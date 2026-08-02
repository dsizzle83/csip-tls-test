package certify

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// fakeCapture stands in for dumpcap. Its Stop synthesises the capture from a
// builder the test supplies, which is how a runner test can exercise the whole
// two-phase pipeline — live check, stop, attribute, cite, bundle, verify —
// without a NIC, root, or a wireshark install.
type fakeCapture struct {
	path    string
	build   func() []pcapng.Packet
	started time.Time
}

func (f *fakeCapture) Start(context.Context) error {
	f.started = time.Now().UTC()
	return nil
}

func (f *fakeCapture) Path() string { return f.path }

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

// catalogFile writes the miniature catalog to a real file so the runner can
// copy it into the bundle, which is how a bundle names its own specification.
func catalogFile(t *testing.T) *Catalog {
	t.Helper()
	p := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(p, []byte(testCatalog), 0o644); err != nil {
		t.Fatal(err)
	}
	cat, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// echoServer is the loopback peer a check dials, standing in for the DUT.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 512)
				n, err := c.Read(buf)
				if err == nil {
					_, _ = c.Write(append([]byte("reply:"), buf[:n]...))
				}
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() { _ = lis.Close() })
	return lis
}

// observedConn is what the live phase records so the synthetic capturer can
// build a capture containing the check's real 4-tuple.
type observedConn struct {
	mu             sync.Mutex
	local, remote  netip.AddrPort
	at             time.Time
	haveConnection bool
	// req / rsp are the payload bytes the synthetic capture will show for the
	// claimed connection. They default to a short exchange; a test whose check
	// asserts on the actual bytes sets them to what really went over the wire.
	req, rsp string
}

func (o *observedConn) note(c net.Conn) {
	l, _ := addrPortOf(c.LocalAddr())
	r, _ := addrPortOf(c.RemoteAddr())
	o.mu.Lock()
	defer o.mu.Unlock()
	o.local, o.remote, o.at, o.haveConnection = l, r, time.Now().UTC(), true
}

// noteAddrs records a connection the check claimed but the test never held a
// net.Conn for.
func (o *observedConn) noteAddrs(local, remote netip.AddrPort) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.local, o.remote, o.at, o.haveConnection = local, remote, time.Now().UTC(), true
}

func (o *observedConn) endpoints() (local, remote netip.AddrPort) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.local, o.remote
}

// synthesise builds a capture containing the observed connection's exchange
// plus background traffic on the same wire — the bench's southbound poll —
// timestamped inside the check's window.
func (o *observedConn) synthesise() []pcapng.Packet {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.haveConnection {
		return nil
	}
	at := o.at
	req, rsp := o.req, o.rsp
	if req == "" {
		req, rsp = "hello", "reply:hello"
	}
	return synthPackets([]synthFrame{
		{src: gatewayPoll, dst: modsim, seq: 1, payload: "poll-req", at: at.Add(-time.Millisecond)},
		{src: o.local, dst: o.remote, seq: 100, flags: tcpSYN, at: at},
		{src: o.remote, dst: o.local, seq: 200, flags: tcpSYN | tcpACK, at: at.Add(time.Millisecond)},
		{src: o.local, dst: o.remote, seq: 101, payload: req, at: at.Add(2 * time.Millisecond)},
		{src: o.remote, dst: o.local, seq: 201, payload: rsp, at: at.Add(3 * time.Millisecond)},
		{src: modsim, dst: gatewayPoll, seq: 2, payload: "poll-rsp", at: at.Add(4 * time.Millisecond)},
	})
}

// baseOptions is a runner configuration that touches nothing outside the test's
// temporary directory.
func baseOptions(t *testing.T, obs *observedConn) (Options, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle")
	opts := DefaultOptions()
	opts.OutDir = out
	opts.Targets = Targets{}
	opts.PKIDir = ""
	opts.Out = &bytes.Buffer{}
	opts.Log = DiscardLogger
	opts.CheckTimeout = 20 * time.Second
	if obs != nil {
		opts.Capturer = &fakeCapture{
			path:  filepath.Join(t.TempDir(), "run.pcap"),
			build: obs.synthesise,
		}
	} else {
		opts.NoCapture = true
	}
	return opts, out
}

func console(o Options) string { return o.Out.(*bytes.Buffer).String() }

// The worked example, end to end: a check dials the peer, claims the
// connection, and cites the reply frame — and the bundle it produces verifies.
func TestRunnerEndToEndProducesAVerifiableBundle(t *testing.T) {
	lis := echoServer(t)
	obs := &observedConn{}
	cat := catalogFile(t)

	reg := NewRegistry()
	reg.Register("doc-a::A-001", "example", func(ctx context.Context, rc *RunCtx) (Result, error) {
		conn, err := rc.DialTCP(ctx, lis.Addr().String(), "example session")
		if err != nil {
			return Result{}, err
		}
		defer func() { _ = conn.Close() }()
		obs.note(conn)
		if _, err := conn.Write([]byte("hello")); err != nil {
			return Result{}, err
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return Result{}, err
		}
		reply := string(buf[:n])

		local, remote := obs.endpoints()
		return Result{Verdict: Pass, Notes: "the peer answered", Cite: func(_ context.Context, ev *Evidence) ([]Assertion, error) {
			if !ev.HasFrames() {
				return []Assertion{ev.NoEvidence("the peer answered on the wire")}, nil
			}
			st, err := ev.StreamOn(remote.Port())
			if err != nil {
				return nil, err
			}
			dir := st.ByFlow(netdis.FlowKey{
				Src: netdis.Endpoint{Addr: remote.Addr(), Port: remote.Port()},
				Dst: netdis.Endpoint{Addr: local.Addr(), Port: local.Port()},
			})
			a, err := ev.CiteBytes("the peer answered the request", "TCP stream reassembly",
				Pass, reply, dir, 0, len(reply))
			if err != nil {
				return nil, err
			}
			return []Assertion{a}, nil
		}}, nil
	})

	opts, out := baseOptions(t, obs)
	opts.Note = "framework self-test"
	opts.DUT = bundle.DUT{Name: "loopback peer", Address: lis.Addr().String()}
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console(opts))
	}

	// The one implemented case passed with a citation; the three others were
	// recorded, not omitted.
	if len(rep.Cases) != 4 {
		t.Fatalf("cases = %d, want 4 (every selected case gets a record)", len(rep.Cases))
	}
	var a1 *CaseResult
	for i := range rep.Cases {
		if rep.Cases[i].Case.UID == "doc-a::A-001" {
			a1 = &rep.Cases[i]
		}
	}
	if a1 == nil || a1.Verdict != Pass {
		t.Fatalf("A-001 = %+v, want PASS", a1)
	}
	if !a1.Citable() {
		t.Errorf("A-001 passed without a re-checkable citation: %+v", a1.Assertions)
	}
	if len(a1.Frames) != 4 {
		t.Errorf("A-001 frames = %v, want the 4 frames of its own connection", a1.Frames)
	}
	if a1.FrameSet.TimeOnlyRejected != 2 {
		t.Errorf("TimeOnlyRejected = %d, want 2 background poll frames",
			a1.FrameSet.TimeOnlyRejected)
	}

	// The run is INCOMPLETE, loudly, because two applicable cases have no check.
	if rep.OK() {
		t.Error("OK() is true while applicable cases are unimplemented")
	}
	if got := len(rep.Unaddressed()); got != 2 {
		t.Errorf("unaddressed = %d, want 2", got)
	}
	log := console(opts)
	for _, want := range []string{"APPLICABLE TEST CASE(S) NOT ADDRESSED", "INCOMPLETE", "doc-a::A-002"} {
		if !strings.Contains(log, want) {
			t.Errorf("console output does not mention %q:\n%s", want, log)
		}
	}

	// The bundle exists, contains its specification, and verifies.
	for _, f := range []string{"bundle.json", "REPORT.md", "MANIFEST.sha256", "COVERAGE.md", "catalog.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("bundle is missing %s: %v", f, err)
		}
	}
	vr, err := bundle.Verify(out)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !vr.OK {
		t.Fatalf("the bundle does not verify:\n%s", vr.String())
	}
	// The catalog's digest must be recoverable from the bundle itself.
	if !strings.Contains(rep.Bundle.Run.Note, cat.Ref().SHA256) {
		t.Errorf("bundle note does not name the catalog digest: %q", rep.Bundle.Run.Note)
	}
	sum, err := os.ReadFile(filepath.Join(out, "MANIFEST.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sum), cat.Ref().SHA256) {
		t.Error("the manifest does not cover the catalog with its expected digest")
	}
}

// A panicking check must not cost the run the evidence of every other case.
func TestRunnerContainsPanics(t *testing.T) {
	cat := catalogFile(t)
	ran := false
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "boom", func(context.Context, *RunCtx) (Result, error) {
		var p *Case
		_ = p.UID // nil dereference, deliberately
		return Result{}, nil
	}, WithOrder(0))
	reg.Register("doc-a::A-002", "after", func(context.Context, *RunCtx) (Result, error) {
		ran = true
		return Skipped("ran after the panic"), nil
	}, WithOrder(1))

	opts, _ := baseOptions(t, nil)
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ran {
		t.Fatal("the run aborted after a check panicked")
	}
	var boom *CaseResult
	for i := range rep.Cases {
		if rep.Cases[i].Case.UID == "doc-a::A-001" {
			boom = &rep.Cases[i]
		}
	}
	if boom.Verdict != Fail {
		t.Errorf("verdict = %s, want FAIL", boom.Verdict)
	}
	if boom.Panic == "" || !strings.Contains(boom.Panic, "runner.go") {
		t.Errorf("no panic stack was recorded: %q", boom.Panic)
	}
	if !strings.Contains(boom.Notes, "bug in the suite, not a DUT failure") {
		t.Errorf("notes = %q; a suite panic must not read as a DUT failure", boom.Notes)
	}
	// The evidence of the panic must survive into the bundle.
	found := false
	for _, c := range rep.Bundle.Cases {
		if c.ID == "doc-a::A-001" && strings.Contains(c.Notes, "Panic stack") {
			found = true
		}
	}
	if !found {
		t.Error("the bundle does not carry the panic stack")
	}
}

// A panic in the citation phase is contained the same way.
func TestRunnerContainsCitationPanics(t *testing.T) {
	obs := &observedConn{}
	lis := echoServer(t)
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "boom", func(ctx context.Context, rc *RunCtx) (Result, error) {
		c, err := rc.DialTCP(ctx, lis.Addr().String(), "s")
		if err != nil {
			return Result{}, err
		}
		obs.note(c)
		_, _ = c.Write([]byte("hello"))
		_ = c.Close()
		return Result{Verdict: Pass, Cite: func(context.Context, *Evidence) ([]Assertion, error) {
			panic("citation bug")
		}}, nil
	})
	opts, _ := baseOptions(t, obs)
	run, _ := New(reg, cat, opts)
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Cases[0]
	if c.Verdict != Fail {
		t.Errorf("verdict = %s, want FAIL: a verdict reached without its evidence is not a verdict", c.Verdict)
	}
	if !strings.Contains(c.Notes, "citation phase PANICKED") {
		t.Errorf("notes = %q", c.Notes)
	}
}

// "We could not test it" must never read as "it passed".
func TestCheckErrorIsAFailure(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		return Result{}, context.DeadlineExceeded
	})
	opts, _ := baseOptions(t, nil)
	run, _ := New(reg, cat, opts)
	rep, _ := run.Run(context.Background())
	if rep.Cases[0].Verdict != Fail {
		t.Fatalf("verdict = %s, want FAIL", rep.Cases[0].Verdict)
	}
	if !strings.Contains(rep.Cases[0].Assertions[0].Note, "no conformance conclusion") {
		t.Errorf("assertion = %+v", rep.Cases[0].Assertions[0])
	}
}

// A PASS nobody can re-check is not a PASS.
func TestUncitedPassIsDowngraded(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		return Result{Verdict: Pass, Notes: "trust me"}, nil
	})
	opts, _ := baseOptions(t, nil)
	run, _ := New(reg, cat, opts)
	rep, _ := run.Run(context.Background())
	c := rep.Cases[0]
	if c.Verdict != Warn {
		t.Fatalf("verdict = %s, want WARN", c.Verdict)
	}
	if !strings.Contains(c.Downgraded, "no assertion carries a digest") {
		t.Errorf("downgrade reason = %q", c.Downgraded)
	}
	if !strings.Contains(console(opts), "downgraded") {
		t.Error("the downgrade was not reported on the console")
	}
}

// An honestly-declared off-wire criterion keeps its PASS, with the declaration
// recorded.
func TestOffWirePassIsKeptWithItsReason(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		return Result{
			Verdict:       Pass,
			Notes:         "the device's certificate store holds 12 roots",
			OffWire:       true,
			OffWireReason: "a certificate-store capacity requirement is not observable on the wire",
		}, nil
	})
	opts, _ := baseOptions(t, nil)
	run, _ := New(reg, cat, opts)
	rep, _ := run.Run(context.Background())
	c := rep.Cases[0]
	if c.Verdict != Pass {
		t.Fatalf("verdict = %s, want PASS", c.Verdict)
	}
	if !strings.Contains(c.Notes, "off-wire criterion") {
		t.Errorf("notes = %q, want the declaration recorded", c.Notes)
	}
}

// -no-capture must not let wire-cited cases silently keep a PASS.
func TestNoCaptureDowngradesCitingChecks(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		return Result{Verdict: Pass, Cite: func(context.Context, *Evidence) ([]Assertion, error) {
			t.Error("the citation phase ran without a capture")
			return nil, nil
		}}, nil
	})
	opts, _ := baseOptions(t, nil) // nil obs => NoCapture
	run, _ := New(reg, cat, opts)
	rep, _ := run.Run(context.Background())
	c := rep.Cases[0]
	if c.Verdict != Warn {
		t.Errorf("verdict = %s, want WARN", c.Verdict)
	}
	if !strings.Contains(c.Assertions[0].Observed, "no capture was taken") {
		t.Errorf("assertion = %+v", c.Assertions[0])
	}
}

func TestDryRunExecutesNothing(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		t.Error("a check ran during a dry run")
		return Result{}, nil
	})
	opts, out := baseOptions(t, nil)
	opts.DryRun = true
	run, _ := New(reg, cat, opts)
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Cases) != 0 {
		t.Errorf("cases = %d, want 0", len(rep.Cases))
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a dry run wrote a bundle directory")
	}
	log := console(opts)
	for _, want := range []string{"DRY RUN", "→ run", "COVERAGE OF THE STANDARD", "NOT IMPLEMENTED"} {
		if !strings.Contains(log, want) {
			t.Errorf("dry-run output does not contain %q:\n%s", want, log)
		}
	}
}

// A registration for a uid the catalog does not have means the suite and the
// specification have diverged; the run must refuse rather than produce a bundle
// nobody can interpret.
func TestRunnerRefusesOrphanedRegistrations(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-z::GHOST-001", "x", noopCheck)
	opts, _ := baseOptions(t, nil)
	run, _ := New(reg, cat, opts)
	if _, err := run.Run(context.Background()); err == nil {
		t.Fatal("a run with an orphaned registration proceeded")
	} else if !strings.Contains(err.Error(), "GHOST-001") {
		t.Errorf("err = %v", err)
	}
}

func TestRunnerHonoursCancellation(t *testing.T) {
	cat := catalogFile(t)
	ctx, cancel := context.WithCancel(context.Background())
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		cancel()
		return Skipped("first"), nil
	}, WithOrder(0))
	reg.Register("doc-a::A-002", "x", func(context.Context, *RunCtx) (Result, error) {
		t.Error("a check ran after the context was cancelled")
		return Result{}, nil
	}, WithOrder(1))

	opts, _ := baseOptions(t, nil)
	run, _ := New(reg, cat, opts)
	rep, err := run.Run(ctx)
	if err == nil {
		t.Fatal("Run returned nil after cancellation")
	}
	if len(rep.Cases) != 1 {
		t.Errorf("cases = %d, want just the first", len(rep.Cases))
	}
	if !strings.Contains(console(opts), "run cancelled") {
		t.Error("cancellation was not reported")
	}
}

// TestRegistrationTimeoutOverridesTheGlobalOne is Registration.Timeout /
// WithTimeout's own test: a check whose own procedure has to wait out a
// DUT's independent cadence (suitemodbusclient's CLI-4/ERR-2/PROT-1/READ-2,
// after runs/warnmeas-mc-ssm-20260802T134537's live-hardware findings) needs
// MORE time than the run's global -timeout, without raising that timeout
// for every OTHER check on the run. A global CheckTimeout far too short for
// the check below, paired with a per-registration WithTimeout comfortably
// long enough, must let the check complete on its own terms.
func TestRegistrationTimeoutOverridesTheGlobalOne(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(ctx context.Context, _ *RunCtx) (Result, error) {
		select {
		case <-time.After(120 * time.Millisecond):
			return Skipped("slow but within its own budget"), nil
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}, WithOrder(0), WithTimeout(2*time.Second))

	opts, _ := baseOptions(t, nil)
	opts.CheckTimeout = 30 * time.Millisecond // far too short for the check above WITHOUT the override
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got *CaseResult
	for i := range rep.Cases {
		if rep.Cases[i].Case.UID == "doc-a::A-001" {
			got = &rep.Cases[i]
		}
	}
	if got == nil {
		t.Fatalf("no result for doc-a::A-001: %+v", rep.Cases)
	}
	if got.Err != nil {
		t.Fatalf("the case errored — the per-registration timeout was not honoured: %v", got.Err)
	}
	if got.Verdict != Skip {
		t.Errorf("verdict = %s, want SKIP (the check's own successful return)", got.Verdict)
	}
}

// Missing capabilities produce a named SKIP, never a silent omission.
func TestMissingCapabilitySkipsWithAReason(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		t.Error("a check ran without its required capability")
		return Result{}, nil
	}, WithRequires("keylog"))

	opts, _ := baseOptions(t, nil)
	run, _ := New(reg, cat, opts)
	rep, _ := run.Run(context.Background())
	c := rep.Cases[0]
	if c.Verdict != Skip || !strings.Contains(c.Notes, "keylog") {
		t.Fatalf("case = %s / %q, want a SKIP naming the missing capability", c.Verdict, c.Notes)
	}
}

// The wire order of a run must be reproducible.
func TestPlanIsDeterministic(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-b::B-001", "z", noopCheck, WithOrder(5))
	reg.Register("doc-a::A-002", "y", noopCheck, WithOrder(3))
	reg.Register("doc-a::A-001", "x", noopCheck, WithOrder(9))

	opts, _ := baseOptions(t, nil)
	run, _ := New(reg, cat, opts)
	var first []string
	for i := 0; i < 5; i++ {
		var got []string
		for _, p := range run.Plan() {
			got = append(got, p.Case.UID)
		}
		if first == nil {
			first = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("plan order changed between calls:\n%v\n%v", first, got)
		}
	}
	// Documents first (catalog order), then the within-suite Order key.
	want := "doc-a::A-003,doc-a::A-002,doc-a::A-001,doc-b::B-001"
	if got := strings.Join(first, ","); got != want {
		t.Errorf("plan = %s, want %s", got, want)
	}
}

func TestNewRejectsSelectorTypos(t *testing.T) {
	cat := catalogFile(t)
	opts, _ := baseOptions(t, nil)
	opts.Docs = []string{"DOC-NOPE"}
	if _, err := New(NewRegistry(), cat, opts); err == nil {
		t.Fatal("a run selecting a nonexistent document was accepted")
	}
}

func TestBindFlags(t *testing.T) {
	opts := DefaultOptions()
	fs := newFlagSet()
	opts.BindFlags(fs)
	err := fs.Parse([]string{
		"-doc", "DOC-A,DOC-B", "-uid", "A-001", "-uid", "B-001",
		"-automatable", "partial", "-param", "nameplate_w=5000",
		"-iface", "enp1s0", "-dry-run",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(opts.Docs, ",") != "DOC-A,DOC-B" {
		t.Errorf("docs = %v", opts.Docs)
	}
	if strings.Join(opts.UIDs, ",") != "A-001,B-001" {
		t.Errorf("uids = %v", opts.UIDs)
	}
	if opts.MinAutomatable != AutoPartial || !opts.DryRun {
		t.Errorf("opts = %+v", opts)
	}
	if opts.Params["nameplate_w"] != "5000" {
		t.Errorf("params = %v", opts.Params)
	}
	if err := fs.Parse([]string{"-automatable", "sometimes"}); err == nil {
		t.Error("an invalid automation level was accepted")
	}
}

// newFlagSet returns a quiet flag set for the BindFlags test.
func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("certify-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// -require-coverage makes the exit status carry the coverage verdict, so a CI
// gate cannot go green over an incomplete run.
func TestRequireCoverageFailsTheRun(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		return Skipped("ok"), nil
	})
	opts, _ := baseOptions(t, nil)
	opts.RequireCoverage = true
	run, _ := New(reg, cat, opts)
	_, err := run.Run(context.Background())
	if err == nil {
		t.Fatal("an incomplete run exited cleanly under -require-coverage")
	}
	for _, want := range []string{"doc-a::A-002", "doc-b::B-001"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}

	// Same run without the gate: the console still says INCOMPLETE, but the
	// exit status is clean, which is the development default.
	opts2, _ := baseOptions(t, nil)
	run2, _ := New(reg, cat, opts2)
	if _, err := run2.Run(context.Background()); err != nil {
		t.Errorf("Run without -require-coverage returned %v", err)
	}
}

func TestRoleFlag(t *testing.T) {
	opts := DefaultOptions()
	fs := newFlagSet()
	opts.BindFlags(fs)
	if err := fs.Parse([]string{"-role", "csip-client,mbaps-server"}); err != nil {
		t.Fatal(err)
	}
	if len(opts.Roles) != 2 || opts.Roles[0] != RoleCSIPClient || opts.Roles[1] != RoleMBAPSServer {
		t.Errorf("roles = %v", opts.Roles)
	}
	if err := fs.Parse([]string{"-role", "gremlin"}); err == nil {
		t.Error("an unknown dut_role was accepted")
	}
}

// TestGatewayHostIsDerivedFromTheTarget pins the derivation a suite's
// direction test depends on. Before Targets.Normalise existed, an operator who
// pointed the tool at anything but the compiled-in bench address kept
// GatewayHost at 69.0.0.2, and suitessm compared every frame's source against
// a device that was not under test — a wrong answer with no symptom.
func TestGatewayHostIsDerivedFromTheTarget(t *testing.T) {
	cat := catalogFile(t)
	opts, _ := baseOptions(t, nil)
	opts.Targets = DefaultTargets()
	opts.Targets.Gateway = "127.0.0.1:9502"

	r, err := New(NewRegistry(), cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.opts.Targets.GatewayHost; got != "127.0.0.1" {
		t.Errorf("GatewayHost = %q, want 127.0.0.1 (derived from -gateway/-target)", got)
	}

	// A target that is not host:port must not silently produce a nonsense
	// host: the dial's own error is the better message.
	var tg Targets
	tg.Gateway = "not-an-address"
	tg.GatewayHost = "keep-me"
	tg.Normalise()
	if tg.GatewayHost != "keep-me" {
		t.Errorf("GatewayHost = %q, want the caller's value left alone", tg.GatewayHost)
	}
}

// TestSuiteSelectionNarrowsCoverageToo pins that -suite participates in
// SELECTION and not merely in dispatch.
//
// Applied only at dispatch, a single-suite run selected the whole catalog,
// executed its own handful, and skipped everything else with "suite X not
// selected" — so the run summary counted skips the operator never asked about,
// and the coverage report sealed into the bundle described the whole catalog
// rather than the campaign that was run. -doc has always behaved the other way;
// -suite now matches it.
func TestSuiteSelectionNarrowsCoverageToo(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	nop := func(context.Context, *RunCtx) (Result, error) { return Skipped("nothing to do"), nil }
	reg.Register("doc-a::A-001", "alpha", nop)
	reg.Register("doc-b::B-001", "beta", nop)

	opts, _ := baseOptions(t, nil)
	opts.Suites = []string{"alpha"}
	r, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}

	plan := r.Plan()
	for _, p := range plan {
		if p.Registration.Suite != "alpha" {
			t.Errorf("plan contains %s from suite %q; -suite alpha must not select it",
				p.Case.UID, p.Registration.Suite)
		}
	}
	cov := r.Coverage()
	for _, d := range cov.Docs {
		for _, e := range d.Implemented {
			if e.Suite != "alpha" {
				t.Errorf("coverage counts %s from suite %q", e.UID, e.Suite)
			}
		}
		if len(d.Unimplemented)+len(d.Inapplicable) > 0 {
			t.Errorf("%s: a -suite selection reported %d unimplemented and %d inapplicable case(s); "+
				"cases with no registration cannot belong to the selected suite",
				d.Doc, len(d.Unimplemented), len(d.Inapplicable))
		}
	}
}

// TestUnknownSuiteIsRefused is the -suite twin of the -doc / -uid typo guard: a
// name nobody registered selects nothing, and a clean run of zero test cases is
// the exact silent-success this tool exists to prevent.
func TestUnknownSuiteIsRefused(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "alpha", func(context.Context, *RunCtx) (Result, error) {
		return Skipped("nothing to do"), nil
	})
	opts, _ := baseOptions(t, nil)
	opts.Suites = []string{"alfa"}
	if _, err := New(reg, cat, opts); err == nil {
		t.Fatal("a misspelled -suite was accepted; it would have run zero cases and reported them clean")
	} else if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("the refusal does not name the available suites: %v", err)
	}
}

// TestFinaliseRecordsAReconciledVerdict proves the runner keeps the live
// verdict and says, in the case's own notes, when the capture overrode it.
// Without this the bundle carries a verdict whose provenance is invisible.
func TestFinaliseRecordsAReconciledVerdict(t *testing.T) {
	cat := loadTestCatalog(t)
	c, _ := cat.ByUID("doc-a::A-001")
	r := &Runner{opts: DefaultOptions()}
	rep := &RunReport{Cases: []CaseResult{{
		Case: c, Suite: "s", Executed: true,
		Verdict: Skip, LiveVerdict: Skip,
		Notes: "the reversion group is incomplete",
		Assertions: []Assertion{
			{Claim: "step 1", Verdict: Fail, Observed: "WMaxLimPctRvrtRem reads its not-implemented value"},
		},
	}}}
	r.finalise(rep)

	got := rep.Cases[0]
	if got.Verdict != Fail {
		t.Fatalf("verdict = %s, want FAIL: the roll-up takes the worst assertion", got.Verdict)
	}
	if got.LiveVerdict != Skip {
		t.Errorf("LiveVerdict = %s, want SKIP preserved", got.LiveVerdict)
	}
	if got.Reconciled == "" {
		t.Fatal("a case whose verdict moved from SKIP to FAIL carries no reconciliation note; that is exactly " +
			"the runner-logged-SKIP / report-said-FAIL divergence this field exists to surface")
	}
	if !strings.Contains(got.Notes, "VERDICT RECONCILED") {
		t.Errorf("notes = %q, want the reconciliation recorded where the bundle will carry it", got.Notes)
	}
}

// TestBundleAndReportBucketAnInapplicableCase closes the loop the bucketing
// defect ran through: the catalog's `applicable` flag has to reach the per-case
// bundle record AND the REPORT.md an assessor reads. It reached the record and
// stopped there, so REPORT.md counted three informative failures in the same
// headline number as five claim-relevant ones.
func TestBundleAndReportBucketAnInapplicableCase(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "applicable row", noopCheck)  // applicable: true
	reg.Register("doc-a::A-003", "informative row", noopCheck) // applicable: false
	opts, out := baseOptions(t, nil)
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v\n%s", err, console(opts))
	}

	b, err := bundle.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range b.Cases {
		got[c.ID] = c.Applicable
	}
	if !got["doc-a::A-001"] {
		t.Error("the bundle lost the catalog's applicable:true")
	}
	if got["doc-a::A-003"] {
		t.Error("the bundle records an inapplicable case as applicable, so its verdict would be " +
			"counted against the certification claim")
	}
	app, inf := b.CountsByClaim()
	if app.Total() == 0 || inf.Total() == 0 {
		t.Errorf("CountsByClaim did not split the run: %+v / %+v", app, inf)
	}

	report, err := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Applicable to the claim:", "Informative", "| info |"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("REPORT.md does not bucket the informative row (%q missing):\n%s", want, report)
		}
	}
}

// TestBundleCarriesTheRedactedInvocation: the bundle recorded dumpcap's whole
// command line and nothing about the command that chose the interface, the
// filter, the selection and the targets. It now records both — with the values
// of credential-shaped flags withheld, since a bundle is a thing we hand to an
// assessor.
func TestBundleCarriesTheRedactedInvocation(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", noopCheck)
	opts, out := baseOptions(t, nil)
	opts.Command = []string{
		"certify", "-doc", "doc-a", "-gateway-ssh", "cc93", "-param", "lab.token=hunter2",
	}
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v\n%s", err, console(opts))
	}

	b, err := bundle.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(b.Run.Command, " ")
	if !strings.Contains(got, "-doc doc-a") || !strings.Contains(got, "-gateway-ssh cc93") {
		t.Errorf("the bundle's invocation lost arguments: %q", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("the bundle's invocation carries a secret: %q", got)
	}
	// The runner must not have edited what the caller handed it: the process
	// may still be using that slice.
	if opts.Command[6] != "lab.token=hunter2" {
		t.Errorf("Run redacted the caller's own argv in place: %v", opts.Command)
	}
	// And it reads back in REPORT.md, which is where the asymmetry showed:
	// dumpcap's argv was already printed there and the run's was not.
	report, err := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "How this run was invoked") {
		t.Errorf("REPORT.md does not show the invocation:\n%s", report)
	}
}
