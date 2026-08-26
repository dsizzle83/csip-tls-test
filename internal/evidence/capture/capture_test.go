package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// No sleep here. There used to be 200 ms of "let the FIN exchange reach the
	// capture", which was a guess at dumpcap's ~250 ms ring poll cycle and lost
	// that bet often enough to be the standing flake in this suite: the capture
	// would come back holding the SYN and nothing else. Stop now waits for the
	// capture file to go quiet, so the wait is a signal instead of a wish, and
	// this test is the regression guard for it — everything below asserts that
	// the WHOLE conversation, first frame to last, is in the file.

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
	// A capture of one quiet loopback port has nothing to keep it busy, so Stop
	// must have seen it go quiet. A warning here means the flush wait gave up,
	// and the frames this test is about to look for may be missing for that
	// reason rather than any other.
	if sum.StopWarning != "" {
		t.Errorf("StopWarning on a quiet loopback capture: %s", sum.StopWarning)
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
		// The summary is printed because the two ways this fails look identical
		// from the assertion alone: a capture that started late (few packets, no
		// SYN) and a capture that lost the tail (SYN present, data missing). The
		// tool's own stderr is where dropped-packet counts appear.
		t.Fatalf("payload recovered in %d of 2 directions; frames=%d summary=%+v",
			found, len(pkts), sum)
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
//
// Every assertion below is scoped to frames carrying this test's own port,
// rather than to the whole file. That is not a weaker test — see the comment
// above byPort — it is what makes the interface-split proof actually
// trustworthy instead of incidentally correct.
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
	// Built as a literal rather than through New, which is also the case that
	// proves the zero-value duration rule: nothing here sets a flush window, so
	// this capture must still get the default one.
	c := &Capture{
		ReadyTimeout: 10 * time.Second,
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
	// No settle sleep before Stop, for the same reason as TestCaptureLoopback:
	// Stop waits for the file to go quiet.

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

	// Every frame must still dissect cleanly: a multi-interface file must not
	// change the link type under the dissector's feet, no matter whose traffic
	// a frame turns out to be. A dissect ERROR is always this package's bug,
	// so it is checked on every frame, unscoped.
	//
	// Whether a frame is TCP at all, and whether it is OUR TCP, is a different
	// question, and — measured directly against the installed dumpcap, with no
	// Go involved — the answer is not "obviously yes". Capturing lo via two -i
	// flags means two independent raw-socket taps on the one NIC every other
	// process on this machine also uses, and under load one of those taps can
	// go a full capture without its kernel filter armed: dumpcap still prints
	// "Capturing on 'Loopback: lo' and 'Loopback: lo'" and the file still gets
	// a valid header — both readiness signals Start waits on are genuinely
	// true — while that tap quietly records everything on lo (mDNS, an
	// unrelated loopback connection from whatever else is running) instead of
	// just tcp port <port>. Confirmed with plain dumpcap 4.2.2 on the command
	// line, no test harness involved: a busy machine handed back thousands of
	// frames on a filter that nothing was ever sent to, on EITHER the
	// duplicate-lo construction this test uses or a genuine two-NIC -i lo -i
	// enp1s0. So this is not a quirk of the lo/lo trick, and not something any
	// amount of additional waiting in Start can detect — dumpcap gives no
	// external signal for "my per-interface filter is armed", and there is no
	// bench safe to assume otherwise once the machine is loaded.
	//
	// So the file this test reads back is not guaranteed to hold only the
	// probe's own frames, and never was guaranteed to on a shared lo — the
	// earlier version of this test just never ran loaded enough to notice.
	// TestCaptureLoopback already handles this correctly for its own
	// assertions by identifying its stream through the port it dialed rather
	// than assuming the capture holds nothing else; byPort does the same
	// here, and is the reason every assertion below reads "this connection's
	// frames" rather than "the file's frames".
	byPort := func(f *netdis.Frame) bool {
		return f.TCP != nil && (f.TCP.SrcPort == uint16(port) || f.TCP.DstPort == uint16(port))
	}
	byIface := map[int]int{}
	mine := 0
	for _, p := range pkts {
		f, err := netdis.DecodePacket(p)
		if err != nil {
			t.Fatalf("frame %d from interface %d does not dissect: %v", p.Index, p.Interface, err)
		}
		if !byPort(f) {
			continue // background traffic sharing lo with the rest of the machine, not this probe
		}
		mine++
		byIface[p.Interface]++
	}
	t.Logf("%d of %d captured frames belong to this test's own connection on port %d; the rest is "+
		"other traffic sharing lo", mine, len(pkts), port)
	if mine == 0 {
		t.Fatalf("none of the %d captured frames belong to this test's own connection on port %d", len(pkts), port)
	}

	// The live proof of the hygiene pass, on the real tool, on the construction
	// that reproduces the race.
	//
	// The paragraph above says the FILE may hold traffic that is not this
	// probe's, because the tap's kernel filter may never have been armed. That
	// is true of what dumpcap WRITES, and it is exactly why Stop re-applies the
	// filter to what it wrote. So the file this test just read back must hold
	// nothing the filter would have excluded: every frame either matches
	// `tcp port <port>`, or is one the re-filter could not decide and therefore
	// kept on purpose (refilter.go). A frame that is neither means the hygiene
	// pass did not run, and the bundle would carry somebody else's traffic.
	flt, err := ParseFilter(c.filter)
	if err != nil {
		t.Fatalf("the filter this capture ran with does not parse: %v", err)
	}
	for _, p := range pkts {
		matched, decided := flt.Match(p)
		if !matched && decided {
			t.Errorf("frame %d (interface %d) survived Stop but does not match %q; the capture in a "+
				"bundle would carry traffic the run never asked for", p.Index, p.Interface, c.filter)
		}
	}

	// And the accounting that makes the race visible to an operator: one row
	// per -i, and the flag on any tap that delivered frames the filter excludes.
	if len(sum.Interfaces) != 2 {
		t.Fatalf("Summary.Interfaces = %+v, want one row per -i flag", sum.Interfaces)
	}
	total := 0
	for _, in := range sum.Interfaces {
		total += in.Kept
	}
	if total != sum.Packets {
		t.Errorf("per-interface kept counts total %d but the file holds %d frames", total, sum.Packets)
	}
	if sum.FilterUnarmed() {
		// Not a failure: it is the defect happening, caught, and disclosed.
		t.Logf("the tool's kernel filter was unarmed on %v; %d unrelated frame(s) were re-filtered "+
			"out of the capture and recorded in the summary",
			sum.UnarmedInterfaces(), sum.RefilterDropped())
	}
	if len(byIface) < 2 {
		t.Fatalf("this connection's frames landed on %d interface id(s) (%v); the second -i had no "+
			"effect, so a split-bench run would silently capture only one side", len(byIface), byIface)
	}
	if byIface[0] == 0 || byIface[1] == 0 {
		t.Errorf("this connection's frames per interface id = %v, want both non-zero", byIface)
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

// shbHeader is a minimal valid pcapng Section Header Block: enough for
// headerWritten to say a capture file exists and parses.
var shbHeader = []byte{
	0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0x00, 0x00, 0x00,
	0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0x00, 0x00, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x1C, 0x00, 0x00, 0x00,
}

// TestReadinessNeedsBothSignals pins the readiness contract without running a
// capture tool at all: BOTH the tool's own announcement and the capture-file
// header are required, and the timeout says which of the two never arrived.
//
// The expiry message matters as much as the wait does. The 150 ms settle sleep
// this replaced could not fail — a sleep always succeeds — which is how a 14%
// flake stayed invisible for months. Anything that goes wrong here now has to
// name what was seen and what was not.
func TestReadinessNeedsBothSignals(t *testing.T) {
	newC := func(out string) *Capture {
		return &Capture{
			ReadyTimeout: 80 * time.Millisecond,
			tool:         Tool{Name: "dumpcap", Path: "/usr/bin/dumpcap"},
			ifaces:       []string{"lo"},
			outPath:      out,
			stderr:       newStderrTap(),
			exited:       make(chan struct{}),
		}
	}

	t.Run("neither signal", func(t *testing.T) {
		c := newC(filepath.Join(t.TempDir(), "never.pcapng"))
		err := c.waitUntilLive(context.Background())
		if err == nil {
			t.Fatal("waitUntilLive must not return success with no signals at all")
		}
		for _, want := range []string{"never announced", "never wrote a parseable capture header"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not say %q", err, want)
			}
		}
	})

	t.Run("header only", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "hdr.pcapng")
		if err := os.WriteFile(out, shbHeader, 0o644); err != nil {
			t.Fatal(err)
		}
		c := newC(out)
		err := c.waitUntilLive(context.Background())
		if err == nil {
			t.Fatal("a capture header alone must not count as live: dumpcap writes it before " +
				"it is recording, so this is precisely the window that loses the ClientHello")
		}
		if !strings.Contains(err.Error(), "it wrote a parseable capture header") ||
			!strings.Contains(err.Error(), "never announced") {
			t.Errorf("error %q must credit the header and name the missing announcement", err)
		}
	})

	t.Run("announcement only", func(t *testing.T) {
		c := newC(filepath.Join(t.TempDir(), "noheader.pcapng"))
		_, _ = c.stderr.Write([]byte("Capturing on 'Loopback: lo'\n"))
		err := c.waitUntilLive(context.Background())
		if err == nil {
			t.Fatal("an announcement alone must not count as live: dumpcap says it ~2 ms in and " +
				"records nothing for tens of milliseconds afterwards")
		}
		if !strings.Contains(err.Error(), "it announced itself") ||
			!strings.Contains(err.Error(), "never wrote a parseable capture header") {
			t.Errorf("error %q must credit the announcement and name the missing header", err)
		}
	})

	t.Run("both signals", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "live.pcapng")
		if err := os.WriteFile(out, shbHeader, 0o644); err != nil {
			t.Fatal(err)
		}
		c := newC(out)
		_, _ = c.stderr.Write([]byte("listening on lo, link-type EN10MB (Ethernet)\n"))
		if err := c.waitUntilLive(context.Background()); err != nil {
			t.Fatalf("both signals present, waitUntilLive should return: %v", err)
		}
	})

	t.Run("cancellation names the signals too", func(t *testing.T) {
		c := newC(filepath.Join(t.TempDir(), "cancel.pcapng"))
		c.ReadyTimeout = 10 * time.Second
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := c.waitUntilLive(ctx)
		if err == nil {
			t.Fatal("a cancelled wait must fail")
		}
		if !strings.Contains(err.Error(), "never announced") {
			t.Errorf("cancellation error %q should still say how far the capture got", err)
		}
	})
}

// TestReadinessNoticesTheToolDying covers the third outcome: the tool exits
// during the wait, which is what a bad filter or a missing capability looks
// like, and must be reported as that rather than as a timeout.
func TestReadinessNoticesTheToolDying(t *testing.T) {
	c := &Capture{
		ReadyTimeout: 5 * time.Second,
		tool:         Tool{Name: "dumpcap"},
		outPath:      filepath.Join(t.TempDir(), "dead.pcapng"),
		stderr:       newStderrTap(),
		exited:       make(chan struct{}),
	}
	_, _ = c.stderr.Write([]byte("dumpcap: The capture session could not be initiated\n"))
	c.waitErr = errors.New("exit status 2")
	close(c.exited)
	err := c.waitUntilLive(context.Background())
	if err == nil {
		t.Fatal("a tool that has exited cannot become live")
	}
	if !strings.Contains(err.Error(), "exited before the capture became live") ||
		!strings.Contains(err.Error(), "could not be initiated") {
		t.Errorf("error %q must say it exited and quote what it said", err)
	}
}

// TestFlushWaitOutcomes pins the stop-side contract: a file that goes quiet is
// waited out and reported as quiet, a file that never does is bounded and
// reported as NOT quiet, and a negative window is the documented way to switch
// the wait off entirely.
//
// This is the wait that fixes the real flake. Interrupting the tool while its
// kernel ring still holds frames loses them with no drop counted anywhere, so
// "we waited long enough" has to be an observation, and "we could not" has to
// come back as a fact rather than as silence.
func TestFlushWaitOutcomes(t *testing.T) {
	t.Run("quiet file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "quiet.pcapng")
		if err := os.WriteFile(out, shbHeader, 0o644); err != nil {
			t.Fatal(err)
		}
		c := &Capture{outPath: out, FlushWindow: 60 * time.Millisecond,
			FlushTimeout: 3 * time.Second, exited: make(chan struct{})}
		waited, quiet := c.waitForFlush()
		if !quiet {
			t.Errorf("a file nobody is writing to must read as quiet (waited %v)", waited)
		}
		if waited < 60*time.Millisecond {
			t.Errorf("waited %v, less than the window: the wait must actually elapse, or it is "+
				"not evidence that the tool had a chance to drain", waited)
		}
	})

	t.Run("file that keeps growing", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "busy.pcapng")
		f, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				case <-time.After(10 * time.Millisecond):
					_, _ = f.Write([]byte("more frames arriving"))
				}
			}
		}()
		c := &Capture{outPath: out, FlushWindow: 60 * time.Millisecond,
			FlushTimeout: 250 * time.Millisecond, exited: make(chan struct{})}
		waited, quiet := c.waitForFlush()
		close(stop)
		<-done
		if quiet {
			t.Error("a file still being written to must not read as quiet")
		}
		if waited < 250*time.Millisecond {
			t.Errorf("waited %v, want the full FlushTimeout", waited)
		}
	})

	t.Run("already exited", func(t *testing.T) {
		// Nothing can be added to a file by a process that is gone, so the wait
		// must be skipped rather than sat through.
		exited := make(chan struct{})
		close(exited)
		c := &Capture{outPath: filepath.Join(t.TempDir(), "gone.pcapng"),
			FlushWindow: 5 * time.Second, FlushTimeout: 10 * time.Second, exited: exited}
		waited, quiet := c.waitForFlush()
		if !quiet || waited > time.Second {
			t.Errorf("an exited capture must return at once: waited=%v quiet=%v", waited, quiet)
		}
	})

	t.Run("switched off", func(t *testing.T) {
		c := &Capture{outPath: filepath.Join(t.TempDir(), "off.pcapng"),
			FlushWindow: -1, exited: make(chan struct{})}
		waited, quiet := c.waitForFlush()
		if !quiet || waited > 50*time.Millisecond {
			t.Errorf("a negative FlushWindow must switch the wait off: waited=%v quiet=%v", waited, quiet)
		}
	})
}

// TestStderrTapIsRaceFreeAndSpotsBothTools covers the readiness detector: it is
// written by os/exec's copier goroutine while Start and Stop read it, so it
// carries a mutex, and it has to recognise what either tool says — including
// when the line arrives split across two writes, which is how a pipe delivers
// it when the timing is unkind.
func TestStderrTapIsRaceFreeAndSpotsBothTools(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts []string
		want  bool
	}{
		{"dumpcap", []string{"Capturing on 'Loopback: lo'\n"}, true},
		{"tcpdump", []string{"tcpdump: listening on lo, link-type EN10MB\n"}, true},
		{"split across writes", []string{"Captur", "ing on 'wlp2s0'\n"}, true},
		{"nothing useful", []string{"dumpcap: no such interface\n"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tap := newStderrTap()
			for _, p := range tc.parts {
				_, _ = tap.Write([]byte(p))
			}
			if got := tap.Announced(); got != tc.want {
				t.Errorf("Announced() = %v, want %v (from %q)", got, tc.want, tc.parts)
			}
			if got := tap.String(); !strings.Contains(got, strings.TrimSpace(tc.parts[len(tc.parts)-1])) {
				t.Errorf("String() = %q, want it to keep what the tool said", got)
			}
		})
	}

	// Concurrent writers and readers: the point of the mutex.
	tap := newStderrTap()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = tap.Write([]byte("Capturing on 'lo'\n"))
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = tap.String()
				_ = tap.Announced()
			}
		}()
	}
	wg.Wait()
}

// TestCaptureKeepsBothEndsOfTheConversation is the flake's regression test.
//
// It repeats the cycle that used to fail about once in twenty on a busy
// machine: start, talk immediately with no settle pause, stop immediately with
// no drain pause. The two assertions are the two ends — frame 1 must be the
// SYN (nothing lost at the start) and a FIN must be present (nothing lost at
// the end). Both used to be a matter of luck, in opposite directions: the old
// 150 ms settle after the header pushed the conversation LATER, which was the
// only reason the old 200 ms pause before Stop usually beat dumpcap's ~250 ms
// ring poll. Removing one without the other would have made this worse, and
// that is why they were fixed together.
func TestCaptureKeepsBothEndsOfTheConversation(t *testing.T) {
	requireTool(t)
	const cycles = 3
	for i := 0; i < cycles; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		out := filepath.Join(t.TempDir(), fmt.Sprintf("cycle-%d.pcapng", i))
		c, err := New("lo", fmt.Sprintf("tcp port %d", port), out)
		if err != nil {
			_ = ln.Close()
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			_ = ln.Close()
			t.Skipf("cannot capture on lo here: %v", err)
		}
		accepted := make(chan struct{})
		go func() {
			defer close(accepted)
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello"))
			_ = conn.Close()
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Read(make([]byte, 8))
		_ = conn.Close()
		<-accepted
		sum, err := c.Stop()
		_ = ln.Close()
		if err != nil {
			t.Fatalf("cycle %d Stop: %v", i, err)
		}
		if sum.StopWarning != "" {
			t.Errorf("cycle %d: %s", i, sum.StopWarning)
		}
		pkts, err := pcapng.ReadFile(out)
		if err != nil {
			t.Fatalf("cycle %d: reading the capture back: %v", i, err)
		}
		if len(pkts) == 0 {
			t.Fatalf("cycle %d captured nothing; summary = %+v", i, sum)
		}
		first, err := netdis.DecodePacket(pkts[0])
		if err != nil {
			t.Fatalf("cycle %d: dissecting frame 1: %v", i, err)
		}
		if first.TCP == nil || !first.TCP.Flags.Has(netdis.SYN) || first.TCP.Flags.Has(netdis.ACK) {
			t.Errorf("cycle %d: frame 1 is %v, want the initial SYN — Start returned before the "+
				"capture was recording", i, first.TCP)
		}
		sawFIN := false
		for _, p := range pkts {
			f, err := netdis.DecodePacket(p)
			if err != nil || f.TCP == nil {
				continue
			}
			if f.TCP.Flags.Has(netdis.FIN) {
				sawFIN = true
			}
		}
		if !sawFIN {
			t.Errorf("cycle %d: %d frames captured and not one FIN — the capture was interrupted "+
				"while the tail of the conversation was still in the tool's ring; summary = %+v",
				i, len(pkts), sum)
		}
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
