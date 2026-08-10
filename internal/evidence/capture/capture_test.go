package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// requireTool skips a test when no capture tool is usable here, with a reason
// that says what to do about it.
func requireTool(t *testing.T) Tool {
	t.Helper()
	tool, err := Detect()
	if err != nil {
		t.Skipf("no capture tool: %v (install wireshark-common or tcpdump)", err)
	}
	return tool
}

func TestDetect(t *testing.T) {
	tool := requireTool(t)
	if tool.Name != "dumpcap" && tool.Name != "tcpdump" {
		t.Fatalf("Name = %q", tool.Name)
	}
	if !filepath.IsAbs(tool.Path) {
		t.Errorf("Path = %q, want an absolute path", tool.Path)
	}
	if tool.Version == "" {
		t.Logf("no version string from %s; the bundle will record an empty tool version", tool.Name)
	}
	if s := tool.String(); !strings.Contains(s, tool.Name) {
		t.Errorf("String() = %q", s)
	}
}

// TestArgs pins the argument vectors without running anything, so the flags
// that matter (packet-buffered output for tcpdump, no snaplen truncation, the
// filter placement each tool wants) are checked even where a tool is absent.
//
// The single-interface rows are the regression guard for the split-bench work:
// one interface must still produce character for character the vector it always
// produced, because the recorded command line is part of the bundle.
func TestArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tool     string
		ifaces   []string
		snaplen  int
		promisc  bool
		filter   string
		wantArgs []string
	}{
		{
			name:     "dumpcap single with filter",
			tool:     "dumpcap",
			ifaces:   []string{"lo"},
			wantArgs: []string{"-i", "lo", "-w", "/tmp/x.pcapng", "-q", "-p", "-f", "tcp port 802"},
			filter:   "tcp port 802",
		},
		{
			name:     "dumpcap single promiscuous and snapped",
			tool:     "dumpcap",
			ifaces:   []string{"lo"},
			promisc:  true,
			snaplen:  128,
			wantArgs: []string{"-i", "lo", "-w", "/tmp/x.pcapng", "-q", "-s", "128"},
		},
		{
			name:     "tcpdump single with filter",
			tool:     "tcpdump",
			ifaces:   []string{"lo"},
			filter:   "tcp port 802",
			wantArgs: []string{"-i", "lo", "-w", "/tmp/x.pcapng", "-U", "-n", "-p", "-s", "0", "tcp port 802"},
		},
		{
			// The split bench: northbound on WiFi, southbound on ethernet, one
			// file. -i repeats, in the order given, and everything after it is
			// unchanged.
			name:   "dumpcap split bench",
			tool:   "dumpcap",
			ifaces: []string{"wlp2s0", "enp1s0"},
			filter: "tcp port 802",
			wantArgs: []string{"-i", "wlp2s0", "-i", "enp1s0", "-w", "/tmp/x.pcapng",
				"-q", "-p", "-f", "tcp port 802"},
		},
		{
			// Rendered honestly even though Start refuses to run it: a command
			// line recorded as something other than what was asked for would be
			// the worst of both.
			name:   "tcpdump multi renders but does not run",
			tool:   "tcpdump",
			ifaces: []string{"wlp2s0", "enp1s0"},
			wantArgs: []string{"-i", "wlp2s0", "-i", "enp1s0", "-w", "/tmp/x.pcapng",
				"-U", "-n", "-p", "-s", "0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Capture{
				tool: Tool{Name: tc.tool}, ifaces: tc.ifaces, outPath: "/tmp/x.pcapng",
				filter: tc.filter, Snaplen: tc.snaplen, Promiscuous: tc.promisc,
			}
			if got := fmt.Sprint(c.Args()); got != fmt.Sprint(tc.wantArgs) {
				t.Errorf("%s args = %v, want %v", tc.tool, c.Args(), tc.wantArgs)
			}
		})
	}
}

// TestSplitInterfaces covers the lenient display splitter.
func TestSplitInterfaces(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want []string
	}{
		{"lo", []string{"lo"}},
		{"wlp2s0,enp1s0", []string{"wlp2s0", "enp1s0"}},
		{" wlp2s0 , enp1s0 ", []string{"wlp2s0", "enp1s0"}},
		{"", nil},
		{",,", nil},
	} {
		if got := SplitInterfaces(tc.spec); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("SplitInterfaces(%q) = %v, want %v", tc.spec, got, tc.want)
		}
	}
}

// TestParseInterfaces pins the strict reader New uses, including the two things
// it must refuse: an empty entry, and the same interface twice.
func TestParseInterfaces(t *testing.T) {
	got, err := parseInterfaces("wlp2s0, enp1s0")
	if err != nil {
		t.Fatalf("parseInterfaces: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint([]string{"wlp2s0", "enp1s0"}) {
		t.Errorf("parsed = %v", got)
	}
	for _, spec := range []string{"", "   ", "lo,", ",lo", "lo,,eth0"} {
		if _, err := parseInterfaces(spec); err == nil {
			t.Errorf("parseInterfaces(%q) must fail", spec)
		}
	}
	err = func() error { _, e := parseInterfaces("enp1s0,enp1s0"); return e }()
	if err == nil {
		t.Fatal("a duplicated interface must be refused: it records every frame twice")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate error = %q, want it to say why", err)
	}
}

// TestMultiInterfaceNeedsDumpcap is the safety rail: tcpdump takes the LAST -i
// and says nothing, so half the split bench would vanish from a capture that
// looked complete.
func TestMultiInterfaceNeedsDumpcap(t *testing.T) {
	if err := checkToolInterfaces("dumpcap", []string{"wlp2s0", "enp1s0"}); err != nil {
		t.Errorf("dumpcap must accept two interfaces: %v", err)
	}
	if err := checkToolInterfaces("tcpdump", []string{"lo"}); err != nil {
		t.Errorf("tcpdump must accept one interface: %v", err)
	}
	err := checkToolInterfaces("tcpdump", []string{"wlp2s0", "enp1s0"})
	if err == nil {
		t.Fatal("tcpdump must refuse a multi-interface capture")
	}
	for _, want := range []string{"dumpcap", "wlp2s0", "enp1s0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	// Never a silent fallback to 'any': the cooked link type would break frame
	// dissection, which is a different failure wearing the same clothes.
	if strings.Contains(err.Error(), "falling back") {
		t.Error("the error must refuse, not announce a fallback")
	}

	// And the refusal holds at Start for a directly-built Capture, which is the
	// only way past New.
	c := &Capture{
		tool:   Tool{Name: "tcpdump", Path: "/nonexistent/tcpdump"},
		ifaces: []string{"wlp2s0", "enp1s0"}, outPath: filepath.Join(t.TempDir(), "x.pcapng"),
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("Start must refuse a multi-interface tcpdump capture")
	} else if !strings.Contains(err.Error(), "dumpcap") {
		t.Errorf("Start error = %q", err)
	}
}

func TestNewValidation(t *testing.T) {
	requireTool(t)
	if _, err := New("", "", "/tmp/x.pcapng"); err == nil {
		t.Error("New with no interface must fail")
	}
	if _, err := New("lo", "", ""); err == nil {
		t.Error("New with no output path must fail")
	}
	c, err := New("lo", "tcp", filepath.Join(t.TempDir(), "nested", "dir", "out.pcapng"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(c.Path())); err != nil {
		t.Errorf("New should have created the output directory: %v", err)
	}
	if _, err := c.Stop(); err == nil {
		t.Error("Stop before Start must fail")
	}
	if got := c.Command(); got[0] != c.Tool().Path {
		t.Errorf("Command()[0] = %q, want the tool path", got[0])
	}
	// A single interface reads back exactly as given — the string a bundle
	// records and a golden diff compares.
	if got := c.Interface(); got != "lo" {
		t.Errorf("Interface() = %q, want %q", got, "lo")
	}
	if got := c.Interfaces(); fmt.Sprint(got) != fmt.Sprint([]string{"lo"}) {
		t.Errorf("Interfaces() = %v", got)
	}
}

// TestNewMultiInterface covers the comma form end to end at construction time.
func TestNewMultiInterface(t *testing.T) {
	tool := requireTool(t)
	out := filepath.Join(t.TempDir(), "split.pcapng")
	c, err := New(" wlp2s0 , enp1s0 ", "tcp port 802", out)
	if tool.Name != "dumpcap" {
		if err == nil {
			t.Fatalf("%s must refuse the comma form", tool.Name)
		}
		return
	}
	if err != nil {
		t.Fatalf("New with two interfaces: %v", err)
	}
	if got := c.Interface(); got != "wlp2s0,enp1s0" {
		t.Errorf("Interface() = %q, want the normalised list", got)
	}
	want := []string{"-i", "wlp2s0", "-i", "enp1s0", "-w", out, "-q", "-p", "-f", "tcp port 802"}
	if got := fmt.Sprint(c.Args()); got != fmt.Sprint(want) {
		t.Errorf("Args() = %v, want %v", c.Args(), want)
	}
	if _, err := New("wlp2s0,wlp2s0", "", out); err == nil {
		t.Error("the same interface twice must be refused")
	}
}

// TestCaptureLoopback is the real thing: start a capture on lo, generate known
// TCP traffic, stop, and read the file back. It proves the readiness wait
// works — a capture that returned from Start too early would miss the SYN, and
// the assertion on the first frame would fail.
func TestCaptureLoopback(t *testing.T) {
	requireTool(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	out := filepath.Join(t.TempDir(), "loopback.pcapng")
	c, err := New("lo", fmt.Sprintf("tcp port %d", port), out)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Skipf("cannot capture on lo here: %v", err)
	}

	const payload = "EVIDENCE-ENGINE-CAPTURE-PROBE"
	srvDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, len(payload))
		if _, err := conn.Read(buf); err != nil {
			srvDone <- err
			return
		}
		_, err = conn.Write([]byte(payload))
		srvDone <- err
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-srvDone; err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let the FIN exchange reach the capture

	sum, err := c.Stop()
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if sum.Packets == 0 {
		t.Fatalf("captured no packets; summary = %+v", sum)
	}
	if sum.FileBytes == 0 {
		t.Error("FileBytes = 0")
	}
	if sum.Interface != "lo" || !strings.Contains(sum.Filter, "tcp port") {
		t.Errorf("summary metadata = %+v", sum)
	}
	if sum.Tool == "" || sum.Format == "" {
		t.Errorf("tool/format not recorded: %+v", sum)
	}
	if sum.Started.IsZero() || sum.Stopped.Before(sum.Started) {
		t.Errorf("timestamps = %v .. %v", sum.Started, sum.Stopped)
	}
	if sum.FirstPacket.IsZero() {
		t.Error("FirstPacket not recorded")
	}

	pkts, err := pcapng.ReadFile(out)
	if err != nil {
		t.Fatalf("reading back the capture: %v", err)
	}
	if len(pkts) != sum.Packets {
		t.Errorf("re-read %d packets, summary says %d", len(pkts), sum.Packets)
	}

	// The first frame must be the SYN. This is the readiness assertion: a
	// capture started too late would begin mid-connection.
	first, err := netdis.DecodePacket(pkts[0])
	if err != nil {
		t.Fatalf("dissecting frame 1: %v", err)
	}
	if first.TCP == nil || !first.TCP.Flags.Has(netdis.SYN) || first.TCP.Flags.Has(netdis.ACK) {
		t.Errorf("frame 1 is %v, want the initial SYN — Start returned before the capture was live",
			first.TCP)
	}

	// And the payload must be recoverable through reassembly.
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatalf("frame %d: %v", p.Index, err)
		}
	}
	streams := asm.FindPort(uint16(port))
	if len(streams) != 1 {
		t.Fatalf("found %d streams on port %d", len(streams), port)
	}
	found := 0
	for _, d := range streams[0].Dirs {
		if strings.Contains(string(d.Bytes.Bytes()), payload) {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("payload recovered in %d of 2 directions", found)
	}
}

// TestCaptureRepeatedInterfaceFlag proves against the INSTALLED dumpcap that a
// repeated -i really does produce one file with one Interface Description Block
// per -i, and that packets carry the interface id they arrived on — which is the
// whole basis of the split-bench capture.
//
// It captures lo twice rather than two NICs so it runs anywhere: the duplicate
// is exactly what New refuses for a real run (every frame twice), and here that
// is the point — the same traffic must appear under BOTH interface ids, which is
// only possible if both -i flags took effect.
func TestCaptureRepeatedInterfaceFlag(t *testing.T) {
	tool := requireTool(t)
	if tool.Name != "dumpcap" {
		t.Skipf("multi-interface capture needs dumpcap; found %s", tool.Name)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	out := filepath.Join(t.TempDir(), "two-interfaces.pcapng")
	c := &Capture{
		ReadyTimeout: 10 * time.Second,
		SettleDelay:  150 * time.Millisecond,
		StopTimeout:  10 * time.Second,
		tool:         tool,
		ifaces:       []string{"lo", "lo"},
		filter:       fmt.Sprintf("tcp port %d", port),
		outPath:      out,
	}
	if err := c.Start(context.Background()); err != nil {
		t.Skipf("cannot capture on lo here: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("SPLIT-BENCH-PROBE"))
		_ = conn.Close()
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Read(make([]byte, 32))
	_ = conn.Close()
	time.Sleep(300 * time.Millisecond)

	sum, err := c.Stop()
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if sum.Interface != "lo,lo" {
		t.Errorf("Summary.Interface = %q, want the recorded list", sum.Interface)
	}
	if sum.Packets == 0 {
		t.Fatalf("captured nothing: %+v", sum)
	}

	pkts, err := pcapng.ReadFile(out)
	if err != nil {
		t.Fatalf("reading back a two-interface capture: %v", err)
	}
	byIface := map[int]int{}
	for _, p := range pkts {
		byIface[p.Interface]++
		// Every frame must still dissect: a multi-interface file must not
		// change the link type under the dissector's feet.
		f, err := netdis.DecodePacket(p)
		if err != nil {
			t.Fatalf("frame %d from interface %d does not dissect: %v", p.Index, p.Interface, err)
		}
		if f.TCP == nil {
			t.Errorf("frame %d from interface %d dissected to no TCP", p.Index, p.Interface)
		}
	}
	if len(byIface) < 2 {
		t.Fatalf("frames landed on %d interface id(s) (%v); the second -i had no effect, so a "+
			"split-bench run would silently capture only one side", len(byIface), byIface)
	}
	if byIface[0] == 0 || byIface[1] == 0 {
		t.Errorf("frames per interface id = %v, want both non-zero", byIface)
	}
}

func TestStartFailsOnBadInterface(t *testing.T) {
	requireTool(t)
	out := filepath.Join(t.TempDir(), "bad.pcapng")
	c, err := New("definitely-not-an-interface", "", out)
	if err != nil {
		t.Fatal(err)
	}
	c.ReadyTimeout = 3 * time.Second
	err = c.Start(context.Background())
	if err == nil {
		_, _ = c.Stop()
		t.Fatal("capturing a non-existent interface must fail")
	}
	if !strings.Contains(err.Error(), "definitely-not-an-interface") && !strings.Contains(err.Error(), "exited") {
		t.Errorf("err = %q, want it to explain what went wrong", err)
	}
}

func TestDoubleStart(t *testing.T) {
	requireTool(t)
	out := filepath.Join(t.TempDir(), "double.pcapng")
	c, err := New("lo", "tcp port 1", out)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Skipf("cannot capture on lo here: %v", err)
	}
	defer func() { _, _ = c.Stop() }()
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("a second Start must fail")
	}
}

// TestStartClearsStaleOutput guards a subtle readiness bug: if a previous run
// left a file at the same path, the header check would pass immediately and
// Start would return before the new capture was live.
func TestStartClearsStaleOutput(t *testing.T) {
	requireTool(t)
	out := filepath.Join(t.TempDir(), "stale.pcapng")
	// A valid but stale pcapng header.
	stale := []byte{
		0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0x00, 0x00, 0x00,
		0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x1C, 0x00, 0x00, 0x00,
	}
	if err := os.WriteFile(out, stale, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := New("lo", "tcp port 1", out)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Skipf("cannot capture on lo here: %v", err)
	}
	sum, err := c.Stop()
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if sum.FileBytes == int64(len(stale)) {
		t.Fatal("the stale file survived; Start must remove it before capturing")
	}
}

func TestContextCancellationStopsCapture(t *testing.T) {
	requireTool(t)
	out := filepath.Join(t.TempDir(), "cancelled.pcapng")
	c, err := New("lo", "tcp port 1", out)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Start(ctx); err != nil {
		cancel()
		t.Skipf("cannot capture on lo here: %v", err)
	}
	cancel()
	time.Sleep(300 * time.Millisecond)
	// Stop must still produce a usable summary: cancellation interrupts rather
	// than kills, so the file is flushed and valid.
	sum, err := c.Stop()
	if err != nil {
		t.Logf("Stop after cancellation: %v", err)
	}
	if sum.Path != out {
		t.Errorf("summary path = %q", sum.Path)
	}
	if _, err := pcapng.ReadFile(out); err != nil {
		t.Errorf("a cancelled capture must still leave a valid file: %v", err)
	}
}

func TestExitErrorFiltersInterrupt(t *testing.T) {
	if err := exitError(nil); err != nil {
		t.Errorf("exitError(nil) = %v", err)
	}
	if err := exitError(errors.New("boom")); err == nil {
		t.Error("a non-exit error must pass through")
	}
}
