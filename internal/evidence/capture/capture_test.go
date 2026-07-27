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
func TestArgs(t *testing.T) {
	for _, tc := range []struct {
		tool     string
		snaplen  int
		promisc  bool
		filter   string
		wantArgs []string
	}{
		{
			tool:     "dumpcap",
			wantArgs: []string{"-i", "lo", "-w", "/tmp/x.pcapng", "-q", "-p", "-f", "tcp port 802"},
			filter:   "tcp port 802",
		},
		{
			tool:     "dumpcap",
			promisc:  true,
			snaplen:  128,
			wantArgs: []string{"-i", "lo", "-w", "/tmp/x.pcapng", "-q", "-s", "128"},
		},
		{
			tool:     "tcpdump",
			filter:   "tcp port 802",
			wantArgs: []string{"-i", "lo", "-w", "/tmp/x.pcapng", "-U", "-n", "-p", "-s", "0", "tcp port 802"},
		},
	} {
		c := &Capture{
			tool: Tool{Name: tc.tool}, iface: "lo", outPath: "/tmp/x.pcapng",
			filter: tc.filter, Snaplen: tc.snaplen, Promiscuous: tc.promisc,
		}
		if got := fmt.Sprint(c.Args()); got != fmt.Sprint(tc.wantArgs) {
			t.Errorf("%s args = %v, want %v", tc.tool, c.Args(), tc.wantArgs)
		}
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
