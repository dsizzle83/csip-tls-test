package certify

// window.go is the mechanism by which a check says "frames 4471-4498 are mine".
//
// # Why time alone is not sound
//
// The obvious implementation — stamp the check's start and end, then claim
// every frame in between — is wrong on this bench, and wrong in a way that
// produces confident false evidence rather than an obvious error.
//
// The bench wire carries continuous background traffic that no test case
// caused: the gateway polls the southbound Modbus sims every 10 seconds, its
// CSIP client walks the 2030.5 server on its own schedule, and other agents'
// services chatter. A TLS test case that took 300 ms would, under time-only
// attribution, sweep up whatever Modbus poll happened to overlap it and cite
// those frames as evidence of a TLS fact. The citation would hash correctly.
// bundle.Verify would pass it. It would still be a lie.
//
// # Why flow alone is not sound either
//
// Attributing by 4-tuple alone fails the other way: ephemeral ports are reused.
// Two checks that both dial 69.0.0.2:802 can, minutes apart, be assigned the
// same local port by the kernel, and the second check would inherit the first
// one's frames.
//
// # The rule
//
// A frame belongs to a check iff BOTH hold:
//
//	(a) its capture timestamp lies within the check's interval (plus a small,
//	    bounded guard at each end — see Guard), and
//	(b) its 4-tuple matches, in either direction, one of the connections the
//	    check itself registered.
//
// A check that registers no connections gets no frames. That is deliberate: the
// alternative — falling back to time alone — is exactly the unsound behaviour
// this file exists to prevent, and a check with no attributable frames should
// produce SKIP assertions saying so, not confident citations of someone else's
// traffic.
//
// A frame that two windows both claim under (a)+(b) is CONTESTED. It is
// narrowed once (by re-testing the time predicate without the guard slack) and,
// if still ambiguous, given to NEITHER window and recorded in
// Attribution.Contested. An ambiguous frame is not evidence.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/evidence/netdis"
)

// DefaultGuard is the slack added at each end of a check's interval before the
// time predicate is applied.
//
// It exists because the check's clock and the capture's clock are not the same
// clock: dumpcap timestamps a frame when the kernel hands it over, Go stamps
// the window when the check returns, and a FIN or RST belonging to a connection
// the check opened can land a few milliseconds after the check's last
// statement. The guard is small and bounded, and — this is the point — it can
// never pull in another check's traffic on its own, because the flow predicate
// still has to hold.
const DefaultGuard = 250 * time.Millisecond

// Precision records how a window's frames were claimed, which the bundle prints
// so a reader can judge the strength of the attribution.
type Precision string

const (
	// PrecisionConnection — every claim names a full 4-tuple. This is the
	// sound case and what every check should aim for.
	PrecisionConnection Precision = "connection"
	// PrecisionEndpoint — at least one claim names only a remote endpoint, so
	// attribution rests on "traffic to this endpoint during this interval".
	// Sound only where the check can argue no other party talks to that
	// endpoint; the argument is recorded in the claim's Reason.
	PrecisionEndpoint Precision = "endpoint"
	// PrecisionNone — the check claimed nothing, so it owns no frames.
	PrecisionNone Precision = "none"
)

// ConnClaim is one connection a check opened, as the 4-tuple the capture will
// show. Either endpoint may be partially specified (a zero Addr or Port matches
// anything), which is how a claim made before connect(2) returns can still be
// narrowed later.
type ConnClaim struct {
	Proto  string // "tcp" or "udp"
	Local  netip.AddrPort
	Remote netip.AddrPort
	Note   string
	At     time.Time
}

// String renders a claim the way a Wireshark filter reads.
func (c ConnClaim) String() string {
	s := fmt.Sprintf("%s %s <> %s", c.Proto, addrPortOrAny(c.Local), addrPortOrAny(c.Remote))
	if c.Note != "" {
		s += " (" + c.Note + ")"
	}
	return s
}

func addrPortOrAny(a netip.AddrPort) string {
	switch {
	case !a.Addr().IsValid() && a.Port() == 0:
		return "*:*"
	case !a.Addr().IsValid():
		return fmt.Sprintf("*:%d", a.Port())
	case a.Port() == 0:
		return a.Addr().String() + ":*"
	}
	return a.String()
}

// matches reports whether a dissected frame belongs to this claim, in either
// direction. Both directions count: a claim is about a CONNECTION, and the
// server's replies are as much the check's evidence as its own requests.
func (c ConnClaim) matches(f *netdis.Frame) bool {
	var src, dst netip.AddrPort
	switch {
	case f.TCP != nil:
		if c.Proto != "" && c.Proto != "tcp" {
			return false
		}
		src = netip.AddrPortFrom(f.Src, f.TCP.SrcPort)
		dst = netip.AddrPortFrom(f.Dst, f.TCP.DstPort)
	case f.UDP != nil:
		if c.Proto != "" && c.Proto != "udp" {
			return false
		}
		src = netip.AddrPortFrom(f.Src, f.UDP.SrcPort)
		dst = netip.AddrPortFrom(f.Dst, f.UDP.DstPort)
	default:
		return false
	}
	return (endpointMatches(c.Local, src) && endpointMatches(c.Remote, dst)) ||
		(endpointMatches(c.Local, dst) && endpointMatches(c.Remote, src))
}

// endpointMatches treats a zero address or zero port in the claim as a
// wildcard.
func endpointMatches(want, got netip.AddrPort) bool {
	if want.Addr().IsValid() && want.Addr().Unmap() != got.Addr().Unmap() {
		return false
	}
	if want.Port() != 0 && want.Port() != got.Port() {
		return false
	}
	return true
}

// specificity scores a claim so the narrowing pass can prefer the more precise
// of two competing claims: 2 for a full 4-tuple, 1 for one fully-specified
// endpoint, 0 for anything looser.
func (c ConnClaim) specificity() int {
	full := func(a netip.AddrPort) bool { return a.Addr().IsValid() && a.Port() != 0 }
	switch {
	case full(c.Local) && full(c.Remote):
		return 2
	case full(c.Local) || full(c.Remote):
		return 1
	default:
		return 0
	}
}

// Window is one check's claim on the run's capture: an interval plus the set of
// connections the check opened. It is safe for concurrent use, because a check
// may claim connections from a goroutine it spawned.
type Window struct {
	// UID and Suite identify the owning check.
	UID   string
	Suite string
	// Guard is the slack applied at each end of the interval. Zero means
	// DefaultGuard; set it negative to disable the slack entirely.
	Guard time.Duration

	mu     sync.Mutex
	start  time.Time
	end    time.Time
	claims []ConnClaim
	loose  int // claims that are not a full 4-tuple
	reason string
}

// NewWindow returns an unopened window for a check.
func NewWindow(uid, suite string) *Window { return &Window{UID: uid, Suite: suite} }

// Open marks the start of the check's interval.
func (w *Window) Open(t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.start = t.UTC()
}

// Close marks the end of the check's interval. Closing twice keeps the later
// time, so a deferred Close after an explicit one cannot shrink the window.
func (w *Window) Close(t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t = t.UTC(); t.After(w.end) {
		w.end = t
	}
}

// Interval returns the window's start and end, guard included. A window that
// was never opened returns two zero times, and attributes nothing.
func (w *Window) Interval() (start, end time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.interval(w.guard())
}

func (w *Window) guard() time.Duration {
	switch {
	case w.Guard == 0:
		return DefaultGuard
	case w.Guard < 0:
		return 0
	default:
		return w.Guard
	}
}

// interval computes the bounded interval; callers hold w.mu.
func (w *Window) interval(g time.Duration) (time.Time, time.Time) {
	if w.start.IsZero() {
		return time.Time{}, time.Time{}
	}
	end := w.end
	if end.IsZero() || end.Before(w.start) {
		end = w.start
	}
	return w.start.Add(-g), end.Add(g)
}

// ClaimConn registers a connection the check opened, taking the 4-tuple from
// the live socket. This is the call every check should be making: it is the
// only one that yields PrecisionConnection without the author having to think
// about addresses.
//
// It works for any net.Conn, including the decrypted stream returned by
// internal/mbtls (whose LocalAddr/RemoteAddr delegate to the underlying TCP
// socket), so a TLS check claims its connection the same way a plain one does.
func (w *Window) ClaimConn(c net.Conn, note string) error {
	if c == nil {
		return errors.New("certify: ClaimConn(nil)")
	}
	local, lerr := addrPortOf(c.LocalAddr())
	remote, rerr := addrPortOf(c.RemoteAddr())
	if lerr != nil || rerr != nil {
		return fmt.Errorf("certify: ClaimConn %s: cannot read the socket's addresses (local %v, remote %v)",
			note, lerr, rerr)
	}
	proto := "tcp"
	if _, ok := c.(net.PacketConn); ok {
		proto = "udp"
	}
	w.ClaimAddrs(proto, local, remote, note)
	return nil
}

// ClaimAddrs registers a connection by its addresses, for the cases where no
// net.Conn is in hand — a listener's accepted peer recorded by address, or a
// connection opened by a library that hides its socket.
func (w *Window) ClaimAddrs(proto string, local, remote netip.AddrPort, note string) {
	c := ConnClaim{Proto: proto, Local: local, Remote: remote, Note: note, At: time.Now().UTC()}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.claims = append(w.claims, c)
	if c.specificity() < 2 {
		w.loose++
	}
}

// ClaimEndpointDuring registers "all traffic to this endpoint during my
// interval", for the cases where the check genuinely cannot know the local
// port — most often when the DUT is the one dialling out and the bench is only
// listening on a well-known port.
//
// The reason is mandatory and is printed in the bundle, because this claim is
// weaker than a connection claim and a reader is entitled to see the argument
// for why no other party's traffic can reach that endpoint during the window.
func (w *Window) ClaimEndpointDuring(proto string, remote netip.AddrPort, reason string) error {
	if !remote.Addr().IsValid() || remote.Port() == 0 {
		return fmt.Errorf("certify: ClaimEndpointDuring needs a fully specified endpoint, got %s",
			addrPortOrAny(remote))
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("certify: ClaimEndpointDuring requires a reason: it is printed in the bundle " +
			"as the argument for why this weaker attribution is sound")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.claims = append(w.claims, ConnClaim{
		Proto: proto, Remote: remote, Note: reason, At: time.Now().UTC(),
	})
	w.loose++
	if w.reason == "" {
		w.reason = reason
	}
	return nil
}

// Claims returns the registered connection claims.
func (w *Window) Claims() []ConnClaim {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]ConnClaim(nil), w.claims...)
}

// Precision reports how the window's frames were claimed.
func (w *Window) Precision() Precision {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case len(w.claims) == 0:
		return PrecisionNone
	case w.loose > 0:
		return PrecisionEndpoint
	default:
		return PrecisionConnection
	}
}

// EndpointReason returns the argument recorded for an endpoint-precision
// window, empty otherwise.
func (w *Window) EndpointReason() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reason
}

// matches applies the full rule to one dissected frame. withGuard=false is the
// narrowing pass used to break a contested frame.
func (w *Window) matches(f *netdis.Frame, withGuard bool) (bool, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	g := time.Duration(0)
	if withGuard {
		g = w.guard()
	}
	start, end := w.interval(g)
	if start.IsZero() {
		return false, 0
	}
	if f.Time.Before(start) || f.Time.After(end) {
		return false, 0
	}
	best := -1
	for _, c := range w.claims {
		if c.matches(f) && c.specificity() > best {
			best = c.specificity()
		}
	}
	if best < 0 {
		return false, 0
	}
	return true, best
}

// inInterval reports whether a frame's timestamp is inside the window,
// regardless of flow. It is what lets a FrameSet report how many frames the
// FLOW predicate rejected — the number that proves the mechanism is doing
// something.
func (w *Window) inInterval(t time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	start, end := w.interval(w.guard())
	return !start.IsZero() && !t.Before(start) && !t.After(end)
}

// FrameSet is the frames attributed to one check.
type FrameSet struct {
	UID       string    `json:"uid"`
	Suite     string    `json:"suite,omitempty"`
	Precision Precision `json:"precision"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	// Frames are the attributed capture frame numbers, ascending. They are the
	// only frames the check is permitted to cite.
	Frames []int `json:"frames,omitempty"`
	// Streams are the TCP conversations those frames belong to.
	Streams []string `json:"streams,omitempty"`
	// TimeOnlyRejected counts frames that fell inside the interval but failed
	// the flow test — the background traffic a time-only attribution would have
	// stolen. It is reported, not hidden: a large number here is the evidence
	// that the two-signal rule earned its keep.
	TimeOnlyRejected int `json:"time_only_rejected"`
	// Contested are frames this window matched but had to give up because
	// another window matched them too.
	Contested []int `json:"contested,omitempty"`
	// Claims is what the check registered, for the record.
	Claims []string `json:"claims,omitempty"`
	// EndpointReason is set for PrecisionEndpoint windows.
	EndpointReason string `json:"endpoint_reason,omitempty"`

	owns map[int]bool
}

// Owns reports whether a frame was attributed to this check.
func (s *FrameSet) Owns(frame int) bool { return s.owns[frame] }

// Span renders the frame range for a report line.
func (s *FrameSet) Span() string {
	if len(s.Frames) == 0 {
		return "—"
	}
	if len(s.Frames) == 1 {
		return fmt.Sprint(s.Frames[0])
	}
	return fmt.Sprintf("%d–%d", s.Frames[0], s.Frames[len(s.Frames)-1])
}

// Attribution is the result of attributing a whole capture to a run's windows.
type Attribution struct {
	// Sets is keyed by test-case uid.
	Sets map[string]*FrameSet `json:"sets"`
	// Contested maps a frame number to the uids that both claimed it. Such a
	// frame is attributed to nobody. A non-empty map is worth investigating: it
	// means two checks' connections were indistinguishable in both time and
	// 4-tuple, which normally means ephemeral port reuse inside the guard.
	Contested map[int][]string `json:"contested,omitempty"`
	// Unattributed is how many capture frames no check claimed — the
	// background traffic, and the expected majority on this bench.
	Unattributed int `json:"unattributed"`
	// Frames is the total number of frames considered.
	Frames int `json:"frames"`
}

// Set returns a uid's frame set, or an empty one so callers need no nil check.
func (a *Attribution) Set(uid string) *FrameSet {
	if s, ok := a.Sets[uid]; ok {
		return s
	}
	return &FrameSet{UID: uid, Precision: PrecisionNone, owns: map[int]bool{}}
}

// Summary renders a one-line description for the console.
func (a *Attribution) Summary() string {
	return fmt.Sprintf("%d frames: %d attributed to %d test case(s), %d unattributed (background), %d contested",
		a.Frames, a.Frames-a.Unattributed-len(a.Contested), len(a.Sets), a.Unattributed, len(a.Contested))
}

// attribute applies the two-signal rule across every window in one pass over
// the dissected frames.
func attribute(frames []*netdis.Frame, wins []*Window) *Attribution {
	att := &Attribution{Sets: make(map[string]*FrameSet, len(wins)), Frames: len(frames)}
	streams := map[string]map[string]bool{}
	for _, w := range wins {
		start, end := w.Interval()
		fs := &FrameSet{
			UID: w.UID, Suite: w.Suite, Precision: w.Precision(),
			Start: start, End: end, owns: map[int]bool{},
			EndpointReason: w.EndpointReason(),
		}
		for _, c := range w.Claims() {
			fs.Claims = append(fs.Claims, c.String())
		}
		att.Sets[w.UID] = fs
		streams[w.UID] = map[string]bool{}
	}

	for _, f := range frames {
		if f == nil {
			continue
		}
		// Which windows want this frame? A window whose interval contains the
		// frame but whose flow test rejects it records the near-miss: that
		// count is exactly the background traffic a time-only attribution
		// would have stolen, and reporting it is how the rule shows its work.
		var winners []*Window
		bestSpec := map[string]int{}
		for _, w := range wins {
			if ok, spec := w.matches(f, true); ok {
				winners = append(winners, w)
				bestSpec[w.UID] = spec
				continue
			}
			if w.inInterval(f.Time) {
				att.Sets[w.UID].TimeOnlyRejected++
			}
		}
		switch len(winners) {
		case 0:
			att.Unattributed++
			continue
		case 1:
			assign(att, streams, winners[0].UID, f)
			continue
		}

		// Contested. Narrow once: drop the guard slack, then prefer the more
		// specific claim. Anything still ambiguous goes to nobody.
		narrowed := narrow(winners, f, bestSpec)
		if narrowed != nil {
			assign(att, streams, narrowed.UID, f)
			continue
		}
		uids := make([]string, 0, len(winners))
		for _, w := range winners {
			uids = append(uids, w.UID)
			att.Sets[w.UID].Contested = append(att.Sets[w.UID].Contested, f.Index)
		}
		sort.Strings(uids)
		if att.Contested == nil {
			att.Contested = map[int][]string{}
		}
		att.Contested[f.Index] = uids
	}

	for uid, fs := range att.Sets {
		sort.Ints(fs.Frames)
		for s := range streams[uid] {
			fs.Streams = append(fs.Streams, s)
		}
		sort.Strings(fs.Streams)
	}
	return att
}

// narrow breaks a tie between windows that all matched a frame. It first
// re-tests the time predicate without the guard slack, then prefers the
// strictly most specific claim. It returns nil when the frame remains
// ambiguous, which is the honest outcome.
func narrow(winners []*Window, f *netdis.Frame, bestSpec map[string]int) *Window {
	var strict []*Window
	for _, w := range winners {
		if ok, _ := w.matches(f, false); ok {
			strict = append(strict, w)
		}
	}
	if len(strict) == 1 {
		return strict[0]
	}
	cands := strict
	if len(cands) == 0 {
		cands = winners
	}
	top, count := -1, 0
	var best *Window
	for _, w := range cands {
		s := bestSpec[w.UID]
		switch {
		case s > top:
			top, count, best = s, 1, w
		case s == top:
			count++
		}
	}
	if count == 1 {
		return best
	}
	return nil
}

func assign(att *Attribution, streams map[string]map[string]bool, uid string, f *netdis.Frame) {
	fs := att.Sets[uid]
	fs.Frames = append(fs.Frames, f.Index)
	fs.owns[f.Index] = true
	if flow, ok := f.Flow(); ok {
		streams[uid][flow.Stream().String()] = true
	}
}

// addrPortOf converts a net.Addr to a netip.AddrPort.
func addrPortOf(a net.Addr) (netip.AddrPort, error) {
	if a == nil {
		return netip.AddrPort{}, errors.New("nil address")
	}
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("unparseable TCP address %v", v)
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(v.Port)), nil
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("unparseable UDP address %v", v)
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(v.Port)), nil
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address %q (%s) is not an ip:port: %w", a.String(), a.Network(), err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
