// Package capture starts and stops a packet capture as a child process and
// records what it did, so the resulting file can be described in an evidence
// bundle by something other than the operator's memory.
//
// # Why not a Go capture library
//
// Capturing needs raw-socket privilege. gopacket/pcap needs cgo and libpcap
// headers; a raw AF_PACKET socket in pure Go needs the whole process to hold
// CAP_NET_RAW, which would mean running the conformance runner as root or
// granting it capabilities. Shelling out to dumpcap keeps the privilege where
// the distribution already put it — /usr/bin/dumpcap carries cap_net_raw and
// the operator is in the wireshark group — and it keeps this package, like the
// rest of the evidence engine, cgo-free and dependency-free.
//
// It also has an evidentiary advantage: the capture is produced by a tool the
// certification body already trusts and can run themselves, not by our code.
//
// # The race that destroys evidence
//
// dumpcap does not capture the instant it is exec'd. It parses arguments, opens
// the capture handle, and writes the file header. A runner that starts dumpcap
// and immediately opens a TLS connection can lose the ClientHello — and a
// bundle whose first frame is the middle of a handshake is not evidence of
// anything. Start therefore does not return until the capture file exists AND
// its header has been written, which is the observable moment after the kernel
// capture handle is open. A short settle delay follows for good measure. If
// that never happens, Start fails loudly rather than letting a test run against
// a capture that is not running.
package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"csip-tls-test/internal/evidence/pcapng"
)

// Tool describes the capture binary that was found.
type Tool struct {
	Name    string // "dumpcap" or "tcpdump"
	Path    string
	Version string // first line of the tool's own --version output
}

func (t Tool) String() string {
	if t.Version == "" {
		return t.Name
	}
	return t.Name + " (" + t.Version + ")"
}

// Candidate tools, in preference order. dumpcap is preferred: it is the
// purpose-built privilege-separated capture binary, it writes pcapng (which
// carries the interface name and nanosecond timestamps), and it is the one that
// ships with the capability bit already set.
var candidates = []string{"dumpcap", "tcpdump"}

// ErrNoTool is returned when neither dumpcap nor tcpdump can be found.
var ErrNoTool = errors.New("capture: neither dumpcap nor tcpdump is available")

// Detect finds a usable capture tool.
func Detect() (Tool, error) {
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		return Tool{Name: name, Path: path, Version: toolVersion(name, path)}, nil
	}
	return Tool{}, ErrNoTool
}

// toolVersion reads a tool's version line. A failure here is not fatal — a
// capture with an unrecorded tool version is still a capture — so it degrades
// to an empty string.
func toolVersion(name, path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(line)
}

// Summary is the capture metadata an evidence bundle records. Every field is
// something a reader of the bundle would otherwise have to take on trust.
type Summary struct {
	Tool        string    `json:"tool"`
	ToolVersion string    `json:"tool_version"`
	Command     []string  `json:"command"`
	Interface   string    `json:"interface"`
	Filter      string    `json:"filter"`
	Path        string    `json:"path"`
	Format      string    `json:"format"`
	Started     time.Time `json:"started"`
	Stopped     time.Time `json:"stopped"`
	Duration    string    `json:"duration"`
	FileBytes   int64     `json:"file_bytes"`
	Packets     int       `json:"packets"`
	FirstPacket time.Time `json:"first_packet,omitempty"`
	LastPacket  time.Time `json:"last_packet,omitempty"`
	// Stderr keeps whatever the tool said. dumpcap reports dropped packets
	// there, and "dropped 412 packets" turns a confusing gap in a reassembled
	// stream into a known fact.
	Stderr string `json:"stderr,omitempty"`
}

// Capture is one capture-tool invocation.
type Capture struct {
	// ReadyTimeout bounds the wait for the capture to become live.
	ReadyTimeout time.Duration
	// SettleDelay is an extra pause after the file header appears.
	SettleDelay time.Duration
	// StopTimeout bounds the wait for a clean shutdown after SIGINT before the
	// process is killed.
	StopTimeout time.Duration
	// Snaplen is the per-packet capture length; 0 means the whole packet.
	// Truncated packets cannot support byte-range evidence, so the default is 0.
	Snaplen int
	// Promiscuous puts the interface in promiscuous mode. The bench is an
	// endpoint of the traffic it captures, so this defaults to false: it avoids
	// pulling in unrelated traffic that would have to be redacted before the
	// bundle could be handed over.
	Promiscuous bool

	tool    Tool
	iface   string
	filter  string
	outPath string

	cmd     *exec.Cmd
	stderr  bytes.Buffer
	waitErr chan error
	started time.Time
	stopped time.Time
	running bool
	done    bool
}

// New prepares a capture of iface, with an optional BPF filter, writing to
// outPath. Nothing is executed until Start.
func New(iface, bpfFilter, outPath string) (*Capture, error) {
	if iface == "" {
		return nil, errors.New("capture: no interface given")
	}
	if outPath == "" {
		return nil, errors.New("capture: no output path given")
	}
	tool, err := Detect()
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(outPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("capture: create output directory: %w", err)
		}
	}
	return &Capture{
		ReadyTimeout: 10 * time.Second,
		SettleDelay:  150 * time.Millisecond,
		StopTimeout:  10 * time.Second,
		tool:         tool,
		iface:        iface,
		filter:       bpfFilter,
		outPath:      outPath,
	}, nil
}

// Tool reports which capture binary will be (or was) used.
func (c *Capture) Tool() Tool { return c.tool }

// Path returns the output file path.
func (c *Capture) Path() string { return c.outPath }

// Args returns the argument vector, without executing anything. It is exported
// so a bundle can record the exact command and a test can assert it.
func (c *Capture) Args() []string {
	switch c.tool.Name {
	case "dumpcap":
		args := []string{"-i", c.iface, "-w", c.outPath, "-q"}
		if !c.Promiscuous {
			args = append(args, "-p")
		}
		if c.Snaplen > 0 {
			args = append(args, "-s", strconv.Itoa(c.Snaplen))
		}
		if c.filter != "" {
			args = append(args, "-f", c.filter)
		}
		return args
	default: // tcpdump
		// -U is packet-buffered output: without it tcpdump holds packets in a
		// stdio buffer and a short capture can end up empty.
		args := []string{"-i", c.iface, "-w", c.outPath, "-U", "-n"}
		if !c.Promiscuous {
			args = append(args, "-p")
		}
		args = append(args, "-s", strconv.Itoa(c.Snaplen))
		if c.filter != "" {
			args = append(args, c.filter)
		}
		return args
	}
}

// Command returns the full command line, for the record.
func (c *Capture) Command() []string { return append([]string{c.tool.Path}, c.Args()...) }

// Start launches the capture and returns only once it is actually live.
func (c *Capture) Start(ctx context.Context) error {
	if c.running {
		return errors.New("capture: already started")
	}
	// A stale file from a previous run would make the readiness check pass
	// instantly and the capture would appear live before it was.
	if err := os.Remove(c.outPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("capture: clear previous output %s: %w", c.outPath, err)
	}

	cmd := exec.CommandContext(ctx, c.tool.Path, c.Args()...)
	cmd.Stderr = &c.stderr
	// Interrupt rather than kill on context cancellation, so the capture file
	// is still flushed and valid if the caller's context expires.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("capture: start %s: %w", c.tool.Path, err)
	}
	c.cmd = cmd
	c.started = time.Now().UTC()
	c.running = true
	c.waitErr = make(chan error, 1)
	go func() { c.waitErr <- cmd.Wait() }()

	if err := c.waitUntilLive(ctx); err != nil {
		_ = c.terminate()
		c.running = false
		return err
	}
	return nil
}

// waitUntilLive polls for the capture file's header. Waiting for a fixed sleep
// instead would be a coin flip: on a loaded machine dumpcap can take hundreds of
// milliseconds to open its handle, and the packets lost in that window are
// exactly the first ones of the test.
func (c *Capture) waitUntilLive(ctx context.Context) error {
	deadline := time.Now().Add(c.ReadyTimeout)
	for {
		select {
		case err := <-c.waitErr:
			// The tool exited before it ever captured anything: a bad
			// interface, a bad filter, or no permission.
			c.waitErr <- err
			return fmt.Errorf("capture: %s exited before the capture became live: %v\n%s",
				c.tool.Name, err, strings.TrimSpace(c.stderr.String()))
		default:
		}
		if c.headerWritten() {
			// The header is written after the capture handle is open, so from
			// here on the kernel is already queueing packets for us.
			time.Sleep(c.SettleDelay)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("capture: %s did not write a capture header to %s within %s\n%s",
				c.tool.Name, c.outPath, c.ReadyTimeout, strings.TrimSpace(c.stderr.String()))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("capture: cancelled while waiting for the capture to start: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// headerWritten reports whether the output file exists and begins with a
// parseable capture-file header.
func (c *Capture) headerWritten() bool {
	fi, err := os.Stat(c.outPath)
	if err != nil || fi.Size() < 24 {
		return false
	}
	r, err := pcapng.Open(c.outPath)
	if err != nil {
		return false
	}
	_ = r.Close()
	return true
}

// Stop interrupts the capture, waits for it to flush, and reports what it
// captured.
//
// SIGINT, not SIGKILL: both dumpcap and tcpdump treat it as "finish the file
// and exit", and a killed capture leaves a file whose last block may be half
// written — which the reader would then have to report as truncated, in a
// bundle, for no reason.
func (c *Capture) Stop() (Summary, error) {
	if !c.running {
		return Summary{}, errors.New("capture: not started")
	}
	c.running = false

	sum := Summary{
		Tool:        c.tool.Name,
		ToolVersion: c.tool.Version,
		Command:     c.Command(),
		Interface:   c.iface,
		Filter:      c.filter,
		Path:        c.outPath,
		Started:     c.started,
	}

	waitErr := c.terminate()
	c.stopped = time.Now().UTC()
	sum.Stopped = c.stopped
	sum.Duration = c.stopped.Sub(c.started).Round(time.Millisecond).String()
	sum.Stderr = strings.TrimSpace(c.stderr.String())

	if waitErr != nil {
		return sum, fmt.Errorf("capture: %s exited with an error: %w\n%s", c.tool.Name, waitErr, sum.Stderr)
	}

	fi, err := os.Stat(c.outPath)
	if err != nil {
		return sum, fmt.Errorf("capture: output file is missing after the capture: %w", err)
	}
	sum.FileBytes = fi.Size()

	// Reading the file back is both the packet count and a validity check: a
	// bundle should never ship a capture that its own reader cannot parse.
	r, err := pcapng.Open(c.outPath)
	if err != nil {
		return sum, fmt.Errorf("capture: capture file does not parse: %w", err)
	}
	defer func() { _ = r.Close() }()
	sum.Format = string(r.Format())
	pkts, err := pcapng.ReadAll(r)
	sum.Packets = len(pkts)
	if len(pkts) > 0 {
		sum.FirstPacket = pkts[0].Time
		sum.LastPacket = pkts[len(pkts)-1].Time
	}
	if err != nil {
		return sum, fmt.Errorf("capture: capture file is damaged after %d packets: %w", len(pkts), err)
	}
	c.done = true
	return sum, nil
}

// terminate signals the child and waits for it, escalating if it does not go.
func (c *Capture) terminate() error {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	_ = c.cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-c.waitErr:
		return exitError(err)
	case <-time.After(c.StopTimeout):
	}
	_ = c.cmd.Process.Kill()
	select {
	case <-c.waitErr:
	case <-time.After(2 * time.Second):
	}
	return fmt.Errorf("did not exit within %s of SIGINT and was killed", c.StopTimeout)
}

// exitError filters out the exit statuses that mean "interrupted as asked".
func exitError(err error) error {
	if err == nil {
		return nil
	}
	// A cancelled context is how a caller asks for a clean stop; exec reports
	// it as the Wait error even though the child was interrupted, flushed and
	// exited normally.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() && ws.Signal() == syscall.SIGINT {
				return nil
			}
			// tcpdump exits 0 on SIGINT; dumpcap does too. Anything else is
			// worth surfacing, including the "1" a filter error produces.
			if ws.Exited() && ws.ExitStatus() == 0 {
				return nil
			}
		}
	}
	return err
}
