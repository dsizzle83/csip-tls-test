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
// # The two races that destroy evidence
//
// A capture tool is live for less time than the process is alive, at BOTH ends,
// and both windows have silently eaten evidence here before.
//
// At the start: dumpcap does not capture the instant it is exec'd. It parses
// arguments, announces itself, opens the capture handle, and writes the file
// header. A runner that starts dumpcap and immediately opens a TLS connection
// can lose the ClientHello — and a bundle whose first frame is the middle of a
// handshake is not evidence of anything. Start therefore returns only once TWO
// things have been observed: the tool's own readiness announcement on stderr,
// and a parseable capture-file header on disk. Neither alone is enough, and the
// measurements are what say so rather than the reading of anyone's source:
// against a 1 ms probe train on lo, dumpcap 4.2.2 announces "Capturing on ..."
// about 2 ms in but does not record a packet for another 10-60 ms, while the
// file header appears at — or 1-2 ms after — the first packet it can record.
// The announcement proves the arguments and the permissions; the header proves
// the capture handle. Waiting for both takes the later of the two, and no
// duration is guessed at anywhere: what used to be a fixed 150 ms settle sleep
// after the header was a coin flip whose bias depended on how fast the machine
// was that day, and it is gone.
//
// At the stop: the tool reads its kernel ring on a poll cycle (about 250 ms for
// dumpcap), so at any instant up to a quarter-second of already-captured frames
// are in the ring and not yet in the file — and SIGINT ends the capture loop
// without draining them. That is the real, long-standing flake this package had
// (IW12-007): a capture stopped shortly after the traffic it was recording ends
// up holding the SYN and nothing else, or nothing at all, while the tool reports
// "0 dropped" because from the kernel's point of view nothing was dropped —
// nobody ever asked for it. Stop therefore watches the capture file until it
// has stopped growing for a full window (see FlushWindow) before it signals,
// which is the observable form of "the tool has drained what it had". When that
// window cannot be reached inside FlushTimeout, the capture is still stopped —
// a stop is not optional — but Summary.StopWarning says so, in the bundle, so
// that a gap at the end of a capture is a recorded fact rather than a mystery.
//
// # More than one interface
//
// A split bench puts the northbound conversation on one NIC and the southbound
// one on another, and a run that captures only the WAN side cannot cite a
// single southbound frame — the rows that rest on southbound observables become
// unmeasurable rather than failing, which is the worst of the three outcomes.
// The interface argument therefore accepts a comma-separated list
// ("wlp2s0,enp1s0"), which becomes a repeated -i on the dumpcap command line
// and ONE pcapng carrying an Interface Description Block per NIC. Frames keep
// their interface id and their own link type, so the reader and the frame
// dissector need no special case (pcapng.Packet.Interface / .LinkType), and
// frame numbering — the citation key for the whole engine — stays a single
// sequence over the single file, exactly as Wireshark numbers it.
//
// tcpdump cannot do this: it takes one -i, and given two it silently uses the
// last, which would produce a capture that looks complete and is missing half
// the evidence. The comma form is refused outright when tcpdump is the detected
// tool. The obvious workaround — capture 'any' — is worse than refusing: the
// Linux cooked link type it yields discards the Ethernet header the dissector
// needs, so it would trade missing frames for undissectable ones.
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
	"sync"
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
	Tool        string   `json:"tool"`
	ToolVersion string   `json:"tool_version"`
	Command     []string `json:"command"`
	// Interface is what was captured. A multi-interface capture records the
	// comma-separated list it was given ("wlp2s0,enp1s0") rather than gaining a
	// second field, so a bundle written before the split bench existed and a
	// bundle written after it parse under the same schema, and SplitInterfaces
	// recovers the names. Command is the ground truth either way.
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
	// StopWarning is set ONLY when the capture had to be interrupted without
	// first seeing the file go quiet, which means the tool may still have been
	// holding frames in its kernel ring — up to one read-timeout of them, at
	// the very end of the capture, exactly where a closing alert or a final ACK
	// lives. It is empty on every clean stop, so a bundle written on a healthy
	// bench is byte-for-byte what it always was, and an unexplained gap at the
	// end of a capture is never left to be discovered by a reviewer.
	StopWarning string `json:"stop_warning,omitempty"`
}

// Capture is one capture-tool invocation.
//
// Every duration below reads a zero as "use the default" and a negative value
// as "switch this off", so a Capture built as a struct literal — which the
// multi-interface tests and any future caller do — gets the same protection
// New hands out instead of silently inheriting a zero-length timeout. Switching
// one off has to be typed on purpose.
type Capture struct {
	// ReadyTimeout bounds the wait for the capture to become live.
	ReadyTimeout time.Duration
	// StopTimeout bounds the wait for a clean shutdown after SIGINT before the
	// process is killed.
	StopTimeout time.Duration
	// FlushWindow is how long the capture file must go unchanged before Stop
	// concludes the tool has written out everything it holds. It has to exceed
	// the tool's ring poll cycle — about 250 ms for dumpcap, and the longest
	// file-write lag measured on this bench was 343 ms — because a shorter
	// window can mistake the pause BETWEEN two drains for the quiet after the
	// last one, which is the flake wearing a new hat.
	FlushWindow time.Duration
	// FlushTimeout bounds that wait. Reaching it is not an error: a capture on
	// an interface with unrelated background traffic never goes quiet at all,
	// and stopping is not optional. It is recorded in Summary.StopWarning.
	FlushTimeout time.Duration
	// Snaplen is the per-packet capture length; 0 means the whole packet.
	// Truncated packets cannot support byte-range evidence, so the default is 0.
	Snaplen int
	// Promiscuous puts the interface in promiscuous mode. The bench is an
	// endpoint of the traffic it captures, so this defaults to false: it avoids
	// pulling in unrelated traffic that would have to be redacted before the
	// bundle could be handed over.
	Promiscuous bool

	tool Tool
	// ifaces is the interface list in the order it was given; length 1 is the
	// ordinary case and produces exactly the command line it always did.
	ifaces  []string
	filter  string
	outPath string

	cmd    *exec.Cmd
	stderr *stderrTap
	// exited is closed when the child has been reaped; waitErr is then readable.
	// A channel that is CLOSED rather than one that carries the error is what
	// lets several places ask "has it exited?" without racing each other for
	// the one value a buffered channel would hold.
	exited  chan struct{}
	waitErr error
	started time.Time
	stopped time.Time
	running bool
	done    bool
}

// defaults for the durations above. They are values, not literals scattered
// through the code, because each one is a measurement with a reason.
const (
	defaultReadyTimeout = 10 * time.Second
	defaultStopTimeout  = 10 * time.Second
	// defaultFlushWindow is ~2x dumpcap's 250 ms ring poll cycle and ~1.75x the
	// longest write lag measured here (343 ms).
	defaultFlushWindow  = 600 * time.Millisecond
	defaultFlushTimeout = 10 * time.Second
	// flushPoll is how often the file is stat'ed while waiting for quiet.
	flushPoll = 25 * time.Millisecond
	// readyPoll is how often the capture file is opened while waiting for its
	// header. It costs one open+parse of a 100-byte file.
	readyPoll = 10 * time.Millisecond
)

// orDefault applies the zero-means-default, negative-means-off rule.
func orDefault(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

// readyMarkers are the lines the two supported tools print once they have
// opened the device: dumpcap says "Capturing on 'Loopback: lo'", tcpdump says
// "listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes".
// Both strings are older than this repo and are not localised, but the match is
// deliberately a lower-cased substring rather than a full-line pattern so that a
// reworded suffix cannot turn a working bench into a hung one.
var readyMarkers = []string{"capturing on", "listening on"}

// stderrTap collects the child's stderr and watches it for the readiness line.
//
// It exists because os/exec copies into cmd.Stderr from its own goroutine: the
// bare bytes.Buffer this used to be was read by Start and Stop while that
// goroutine was still writing to it, which is a data race that -race would
// eventually have caught in the middle of a conformance run.
type stderrTap struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	seen bool
}

func newStderrTap() *stderrTap { return &stderrTap{} }

// Write matches against the whole accumulated text rather than against this
// chunk, because a pipe is free to deliver "Captur" and "ing on 'lo'" as two
// writes and a line split down the middle must not read as silence.
func (s *stderrTap) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.buf.Write(p)
	if !s.seen && containsAny(strings.ToLower(s.buf.String()), readyMarkers) {
		s.seen = true
	}
	return n, err
}

// String returns everything the tool has said so far, trimmed.
func (s *stderrTap) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimSpace(s.buf.String())
}

// Announced reports whether the readiness line has been seen.
func (s *stderrTap) Announced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// SplitInterfaces splits the comma-separated interface form into names,
// ignoring surrounding whitespace and empty entries. It is the lenient reader
// used to DESCRIBE a capture — a report line, a recorded Summary — where a
// malformed spec should still print something rather than abort. New validates.
func SplitInterfaces(spec string) []string {
	var out []string
	for _, f := range strings.Split(spec, ",") {
		if name := strings.TrimSpace(f); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// parseInterfaces is the strict reader New uses.
//
// A duplicate is refused rather than deduplicated. dumpcap accepts the same
// interface twice and dutifully records every frame twice, under two interface
// ids; the reassembler would then see each segment as its own retransmission
// and every "the alert is frame N" citation would have a twin. Silently
// dropping the duplicate would be just as wrong: the operator asked for
// something that cannot be honoured and should hear so.
func parseInterfaces(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, errors.New("capture: no interface given")
	}
	var out []string
	seen := make(map[string]bool)
	for _, f := range strings.Split(spec, ",") {
		name := strings.TrimSpace(f)
		if name == "" {
			return nil, fmt.Errorf("capture: interface list %q has an empty entry", spec)
		}
		if seen[name] {
			return nil, fmt.Errorf("capture: interface %q appears twice in %q; capturing one "+
				"interface twice records every frame twice, under two interface ids, and every "+
				"frame citation in the bundle would then have an ambiguous twin", name, spec)
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// checkToolInterfaces refuses a combination the tool cannot honour truthfully.
// See the package doc: tcpdump given two -i flags uses the last one and says
// nothing, which is a capture that looks whole and is half missing.
func checkToolInterfaces(toolName string, ifaces []string) error {
	if len(ifaces) < 2 || toolName == "dumpcap" {
		return nil
	}
	return fmt.Errorf("capture: capturing %s at once requires dumpcap, but the tool found here is "+
		"%s, which takes ONE interface and would silently record only the last of them. Install "+
		"wireshark-common (dumpcap carries cap_net_raw), or run one leg per interface. Capturing "+
		"'any' instead is not a substitute: its Linux cooked link type drops the Ethernet header "+
		"the frame dissector needs", strings.Join(ifaces, " and "), toolName)
}

// New prepares a capture of iface, with an optional BPF filter, writing to
// outPath. Nothing is executed until Start.
//
// iface is one interface name, or several separated by commas
// ("wlp2s0,enp1s0") for a split bench whose northbound and southbound traffic
// do not share a NIC. The multi-interface form needs dumpcap.
func New(iface, bpfFilter, outPath string) (*Capture, error) {
	ifaces, err := parseInterfaces(iface)
	if err != nil {
		return nil, err
	}
	if outPath == "" {
		return nil, errors.New("capture: no output path given")
	}
	tool, err := Detect()
	if err != nil {
		return nil, err
	}
	if err := checkToolInterfaces(tool.Name, ifaces); err != nil {
		return nil, err
	}
	if dir := filepath.Dir(outPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("capture: create output directory: %w", err)
		}
	}
	return &Capture{
		ReadyTimeout: defaultReadyTimeout,
		StopTimeout:  defaultStopTimeout,
		FlushWindow:  defaultFlushWindow,
		FlushTimeout: defaultFlushTimeout,
		tool:         tool,
		ifaces:       ifaces,
		filter:       bpfFilter,
		outPath:      outPath,
	}, nil
}

// Tool reports which capture binary will be (or was) used.
func (c *Capture) Tool() Tool { return c.tool }

// Path returns the output file path.
func (c *Capture) Path() string { return c.outPath }

// Interfaces reports the interfaces this capture covers, in the order given.
func (c *Capture) Interfaces() []string { return append([]string(nil), c.ifaces...) }

// Interface is the recorded interface string: one name, or the comma-separated
// list for a multi-interface capture. A single-interface capture returns
// exactly the name it was given.
func (c *Capture) Interface() string { return strings.Join(c.ifaces, ",") }

// Args returns the argument vector, without executing anything. It is exported
// so a bundle can record the exact command and a test can assert it.
//
// One -i per interface. With a single interface — every capture before the
// split bench, and every ordinary one after it — the vector is character for
// character what it always was, which matters because the recorded command line
// is part of the bundle a reviewer diffs.
func (c *Capture) Args() []string {
	ifaceArgs := make([]string, 0, 2*len(c.ifaces))
	for _, name := range c.ifaces {
		ifaceArgs = append(ifaceArgs, "-i", name)
	}
	switch c.tool.Name {
	case "dumpcap":
		args := append(ifaceArgs, "-w", c.outPath, "-q")
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
		// Multiple -i is rendered rather than hidden, so the recorded command
		// matches the request; Start refuses to RUN it. See checkToolInterfaces.
		//
		// -U is packet-buffered output: without it tcpdump holds packets in a
		// stdio buffer and a short capture can end up empty.
		args := append(ifaceArgs, "-w", c.outPath, "-U", "-n")
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
	// New refuses this combination, but a Capture can be built directly, and
	// the one thing that must never happen is running it: tcpdump would exit 0
	// having captured one of the two interfaces.
	if err := checkToolInterfaces(c.tool.Name, c.ifaces); err != nil {
		return err
	}
	// A stale file from a previous run would make the readiness check pass
	// instantly and the capture would appear live before it was.
	if err := os.Remove(c.outPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("capture: clear previous output %s: %w", c.outPath, err)
	}

	cmd := exec.CommandContext(ctx, c.tool.Path, c.Args()...)
	c.stderr = newStderrTap()
	cmd.Stderr = c.stderr
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
	c.exited = make(chan struct{})
	go func() {
		c.waitErr = cmd.Wait()
		close(c.exited)
	}()

	if err := c.waitUntilLive(ctx); err != nil {
		_ = c.terminate()
		c.running = false
		return err
	}
	return nil
}

// waitUntilLive returns when the capture is genuinely recording, judged by two
// signals the tool itself produces, and never by a duration:
//
//  1. the readiness line on stderr — the tool's own statement that it parsed
//     its arguments, had the privilege it needed, and opened the device;
//  2. a parseable capture-file header on disk — which both tools write only
//     after that device is open, and which is therefore the observable moment
//     at or after which the kernel is queueing packets for them.
//
// Both are required because each is insufficient alone, as measured on this
// bench (see the package doc): the announcement comes tens of milliseconds too
// early, and a header with no announcement would mean believing a file we
// cannot attribute to a healthy tool.
//
// Waiting for the first PACKET instead — the strongest signal there is, since
// it proves recording rather than readiness — is not available here: Start runs
// before the caller has generated the traffic it wants captured, the capture
// filter is the caller's (`tcp port 802`), so no probe frame this package could
// synthesise is guaranteed to match it, and a synthetic frame injected into an
// evidence capture would shift the frame numbering that every citation in the
// bundle is keyed to. The measured file-write lag of up to 343 ms would also
// make it the slowest of the three by an order of magnitude.
func (c *Capture) waitUntilLive(ctx context.Context) error {
	timeout := orDefault(c.ReadyTimeout, defaultReadyTimeout)
	deadline := time.Now().Add(timeout)
	headerSeen := false
	for {
		select {
		case <-c.exited:
			// The tool exited before it ever captured anything: a bad
			// interface, a bad filter, or no permission.
			return fmt.Errorf("capture: %s exited before the capture became live: %v\n%s",
				c.tool.Name, c.waitErr, c.stderr.String())
		default:
		}
		if !headerSeen {
			headerSeen = c.headerWritten()
		}
		announced := c.stderr.Announced()
		if headerSeen && announced {
			return nil
		}
		if time.Now().After(deadline) {
			// A decided error naming what WAS and was NOT observed. The 14%
			// flake this replaced was invisible for so long because the old
			// code's answer to "is it live yet?" was a sleep, which cannot
			// fail; whatever goes wrong here now says which half went wrong.
			return fmt.Errorf("capture: %s never became live within %s: %s, %s. "+
				"Capture file %s\nThe tool said:\n%s",
				c.tool.Name, timeout,
				describeSignal(announced, "announced itself on stderr"),
				describeSignal(headerSeen, "wrote a parseable capture header"),
				c.outPath, c.stderr.String())
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("capture: cancelled while waiting for the capture to start "+
				"(%s, %s): %w", describeSignal(announced, "announced itself on stderr"),
				describeSignal(headerSeen, "wrote a parseable capture header"), ctx.Err())
		case <-time.After(readyPoll):
		}
	}
}

// describeSignal renders one readiness signal for an error message, in words
// that say what was observed rather than printing a bare boolean.
func describeSignal(ok bool, what string) string {
	if ok {
		return "it " + what
	}
	return "it never " + what
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

// Stop lets the capture finish writing what it holds, interrupts it, and
// reports what it captured.
//
// The waiting comes FIRST and is the whole point: SIGINT ends the tool's
// capture loop wherever it is, and whatever is still sitting in the kernel ring
// at that moment is gone — silently, with the tool reporting zero drops,
// because from the kernel's side nothing was dropped. See the package doc.
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
		Interface:   c.Interface(),
		Filter:      c.filter,
		Path:        c.outPath,
		Started:     c.started,
	}

	if waited, quiet := c.waitForFlush(); !quiet {
		sum.StopWarning = fmt.Sprintf("the capture file was still growing after %s, so %s was "+
			"interrupted while it may still have held frames in its kernel ring: up to one "+
			"read-timeout (~250ms) of frames at the END of this capture may be missing. This is "+
			"normal on an interface carrying traffic unrelated to the run, and it is recorded "+
			"rather than hidden so that a gap at the tail is a known fact",
			waited.Round(time.Millisecond), c.tool.Name)
	}

	waitErr := c.terminate()
	c.stopped = time.Now().UTC()
	sum.Stopped = c.stopped
	sum.Duration = c.stopped.Sub(c.started).Round(time.Millisecond).String()
	sum.Stderr = c.stderr.String()

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

// waitForFlush waits until the capture file has stopped growing, which is the
// observable form of "the tool has emptied its kernel ring into the file".
//
// Why file size and not something more direct: the tool tells us nothing while
// it runs (dumpcap's live packet counter is exactly what -q turns off, and -q
// is on because a bundle should not be paid for in stderr noise), the kernel's
// AF_PACKET table cannot be attributed to our process (dumpcap carries file
// capabilities, so /proc/<pid>/fd is root-owned and unreadable — verified on
// this bench), and the file is in any case the thing the evidence is IN. A
// write that has landed in the file cannot be lost by the SIGINT that follows;
// bytes still in the tool's own stdio buffer are flushed by its clean exit.
//
// It returns how long it waited and whether quiet was actually observed.
func (c *Capture) waitForFlush() (time.Duration, bool) {
	window := orDefault(c.FlushWindow, defaultFlushWindow)
	if window < 0 {
		return 0, true // switched off on purpose
	}
	timeout := orDefault(c.FlushTimeout, defaultFlushTimeout)
	if timeout < 0 {
		timeout = defaultFlushTimeout
	}
	start := time.Now()
	var lastSize int64 = -1
	lastChange := start
	for {
		select {
		case <-c.exited:
			// Nothing can be added to the file by a process that has already
			// gone, so there is nothing left to wait for.
			return time.Since(start), true
		default:
		}
		size := int64(-1)
		if fi, err := os.Stat(c.outPath); err == nil {
			size = fi.Size()
		}
		now := time.Now()
		if size != lastSize {
			lastSize, lastChange = size, now
		}
		if now.Sub(lastChange) >= window {
			return time.Since(start), true
		}
		if now.Sub(start) >= timeout {
			return time.Since(start), false
		}
		time.Sleep(flushPoll)
	}
}

// terminate signals the child and waits for it, escalating if it does not go.
func (c *Capture) terminate() error {
	if c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	stopTimeout := orDefault(c.StopTimeout, defaultStopTimeout)
	_ = c.cmd.Process.Signal(os.Interrupt)
	select {
	case <-c.exited:
		return exitError(c.waitErr)
	case <-time.After(stopTimeout):
	}
	_ = c.cmd.Process.Kill()
	select {
	case <-c.exited:
	case <-time.After(2 * time.Second):
	}
	return fmt.Errorf("did not exit within %s of SIGINT and was killed", stopTimeout)
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
