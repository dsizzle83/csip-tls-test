package certify

// evidence.go is the second phase of a check: the capture has been stopped and
// read back, the frames have been attributed, and now the check turns what it
// observed into assertions a stranger can re-check.
//
// The one rule this file enforces, and the reason the citation constructors
// live here rather than being taken straight from internal/evidence/bundle: a
// check may cite ONLY the frames attributed to it. bundle.CiteFrames will
// happily digest any frame in the capture — it has no idea which check is
// asking — so a suite calling it directly could cite a background Modbus poll
// as evidence of a TLS fact and produce a bundle that verifies perfectly and
// says something false. Evidence.CiteFrames refuses, naming the offending frame
// and, when it can, the check that actually owns it.
//
// Every constructor here is also a refusal path: a check that cannot cite gets
// an explicit SKIP assertion carrying the reason, never a bare PASS.

import (
	"fmt"
	"net/netip"
	"strings"

	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// FrameIndex is the run's capture, dissected and reassembled once.
//
// Once, not per check: dissecting a 200 MB capture per test case would dominate
// the run, and — more importantly — every check must see the SAME reassembly,
// or two checks could disagree about what byte 120 of a stream is.
//
// "Once" still means the WHOLE capture, unconditionally, before attribution
// exists to say which of it any check will ever want: fi.asm's reassembly
// (below) walks every packet — including background traffic no test case
// claims — and netdis.Direction keeps every contiguous delivered byte for the
// life of the run (its out-of-order buffer is capped at DefaultMaxPending,
// but the DELIVERED stream is not — see reassembly.go's StreamBytes). On an
// unfiltered capture with a long-lived, high-volume background connection
// (the 2026-08-11 CSIP-leg OOM: an aggregator loop hammering mbaps :802 on
// the same interface for the leg's whole 1h47m, 98.4% of the capture's
// frames) that is where the memory goes: one persistent Direction's byte
// stream, held in full, for a conversation no check ever cites. This index
// used to pay for that reassembly TWICE (attribute() rebuilt its own
// Assembler from the same frames — see attribute's doc comment in window.go);
// Attribute now reuses fi.asm instead, which halves the cost but does not
// bound it — the real fix for an unfiltered capture is not indexing the
// background traffic into the pcap in the first place (see the -bpf comments
// in runs/wave11-qa-20260811/qa-cycle.sh and
// runs/ethsplit-20260807/soak-attempt6-partial/soak-driver.sh). A genuine
// bound here (e.g. a byte cap per Direction, or deferring reassembly until
// attribution has picked which streams matter) was left undone: attribution
// itself is computed FROM the dissected frames this same pass produces, so
// bounding reassembly by attribution needs a second pass over the capture —
// not a rounding-error change, and not one to make blind the night of an OOM.
type FrameIndex struct {
	packets []pcapng.Packet
	frames  []*netdis.Frame
	byIndex map[int]pcapng.Packet
	byFrame map[int]*netdis.Frame
	asm     *netdis.Assembler

	// Undissectable lists frames that could not be dissected. They are reported
	// rather than silently skipped: a capture with unreadable frames is a
	// capture whose evidence may be incomplete.
	Undissectable []int
	// Problems collects capture-level integrity findings — conflicting
	// overlapping segments, incomplete streams — that a reader of the bundle
	// needs to weigh the evidence.
	Problems []string
}

// NewFrameIndex dissects and reassembles a capture's packets.
func NewFrameIndex(pkts []pcapng.Packet) *FrameIndex {
	fi := &FrameIndex{
		packets: pkts,
		frames:  make([]*netdis.Frame, 0, len(pkts)),
		byIndex: make(map[int]pcapng.Packet, len(pkts)),
		byFrame: make(map[int]*netdis.Frame, len(pkts)),
		asm:     netdis.NewAssembler(),
	}
	for _, p := range pkts {
		fi.byIndex[p.Index] = p
		f, err := netdis.DecodePacket(p)
		if err != nil {
			fi.Undissectable = append(fi.Undissectable, p.Index)
			continue
		}
		fi.asm.AddFrame(f)
		fi.frames = append(fi.frames, f)
		fi.byFrame[f.Index] = f
	}
	if n := len(fi.Undissectable); n > 0 {
		fi.Problems = append(fi.Problems, fmt.Sprintf("%d frame(s) did not dissect: %v",
			n, firstN(fi.Undissectable, 8)))
	}
	for _, st := range fi.asm.Streams() {
		for _, d := range st.Dirs {
			if d.HasConflictingOverlap() {
				fi.Problems = append(fi.Problems, fmt.Sprintf(
					"stream %s has CONFLICTING overlapping segments — two readers of this capture "+
						"can disagree about what was said: %v", d.Flow, d.Overlaps))
			}
			if !d.Complete() {
				fi.Problems = append(fi.Problems, fmt.Sprintf(
					"stream %s is missing %d byte(s): a segment was never captured, so byte offsets "+
						"after the gap are not the peer's offsets", d.Flow, d.PendingGap()))
			}
		}
	}
	return fi
}

// LoadFrameIndex reads a capture file and indexes it.
func LoadFrameIndex(path string) (*FrameIndex, error) {
	pkts, err := pcapng.ReadFile(path)
	if err != nil && len(pkts) == 0 {
		return nil, fmt.Errorf("certify: read capture %s: %w", path, err)
	}
	fi := NewFrameIndex(pkts)
	if err != nil {
		// A truncated tail is survivable evidence — the frames before it are
		// still exactly what was on the wire — but it must be recorded.
		fi.Problems = append(fi.Problems,
			fmt.Sprintf("capture %s is damaged after %d frames: %v", path, len(pkts), err))
	}
	return fi, nil
}

// Packets returns every captured packet, in file order.
func (fi *FrameIndex) Packets() []pcapng.Packet { return fi.packets }

// Len is the number of captured packets.
func (fi *FrameIndex) Len() int { return len(fi.packets) }

// Packet returns one capture frame by its 1-based index.
func (fi *FrameIndex) Packet(index int) (pcapng.Packet, bool) {
	p, ok := fi.byIndex[index]
	return p, ok
}

// frame returns one dissected frame by its 1-based index.
func (fi *FrameIndex) frame(index int) (*netdis.Frame, bool) {
	f, ok := fi.byFrame[index]
	return f, ok
}

// Frames returns every dissected frame.
func (fi *FrameIndex) Frames() []*netdis.Frame { return fi.frames }

// Streams returns every reassembled TCP conversation.
func (fi *FrameIndex) Streams() []*netdis.Stream { return fi.asm.Streams() }

// Attribute applies the two-signal rule to the run's windows.
//
// Calls attributeStreams directly with fi.asm — the Assembler NewFrameIndex
// already built — rather than going through attribute(), which would
// reassemble the whole capture a second time. See attribute's doc comment in
// window.go for why that second pass is pure waste on a background-heavy
// capture (the 2026-08-11 CSIP-leg OOM).
func (fi *FrameIndex) Attribute(wins []*Window) *Attribution {
	return attributeStreams(fi.frames, wins, fi.asm)
}

// owner returns the uid that owns a frame, for a better error message when a
// check cites someone else's traffic.
func (a *Attribution) owner(frame int) string {
	if a == nil {
		return ""
	}
	for uid, fs := range a.Sets {
		if fs.owns[frame] {
			return uid
		}
	}
	if uids, ok := a.Contested[frame]; ok {
		return "contested between " + strings.Join(uids, ", ")
	}
	return ""
}

// Evidence is what a CiteFunc is handed: the capture, scoped to the frames the
// check's own connections produced.
type Evidence struct {
	// Case is the catalog record being evidenced.
	Case *Case
	// Set is this check's attributed frames.
	Set *FrameSet
	// Index is the whole run's dissected capture. It is exposed because a check
	// legitimately needs to look at the capture as a whole (to prove the
	// ABSENCE of a frame, for instance) — but anything it CITES still has to be
	// in Set.
	Index *FrameIndex
	// KeyLog is the run's NSS key log, when one was exported. nil otherwise;
	// a check that needs decryption must SKIP with that reason rather than
	// assert on ciphertext.
	KeyLog *keylog.Log
	// Capture is the capture's own metadata.
	Capture capture.Summary
	// Attribution is the whole run's attribution, for diagnostics.
	Attribution *Attribution

	// offWire / offWireReason are set by DeclareOffWire. They are the citation
	// phase's equivalent of Result.OffWire: the runner reads them back after the
	// CiteFunc returns and treats the case the same way it treats a Result that
	// declared itself off-wire — the "uncited PASS -> WARN" downgrade is
	// suppressed and the reason is printed in the bundle. See DeclareOffWire.
	offWire       bool
	offWireReason string
}

// DeclareOffWire records — from inside a CiteFunc, after the capture has been
// read — that this row's PASS rests on something the pcap cannot show for a
// stated NON-product reason, so the "uncited PASS was downgraded to WARN" rule
// must not fire against it.
//
// Result.OffWire says the same thing, but it is declared up front, before the
// capture exists. Some obstacles are only knowable once the capture is in hand:
// the canonical one is TLS 1.3 SESSION RESUMPTION. A resumed handshake carries
// no Certificate message at all (RFC 8446 §2.2 — a resumed session continues
// the ORIGINAL handshake's authentication), so a run that captured only resumed
// sessions has no client-certificate frame to cite for RBAC-011 even though the
// gateway behaved correctly. That is a property of TLS, not a product failure,
// and it must not read as a product WARN. A CiteFunc that hits it calls this
// with a reason naming the limitation and the remedy (drive a full handshake,
// e.g. mbapsdev -no-tickets); the last non-empty reason wins.
//
// It does NOT invent evidence or upgrade a verdict: a failing assertion still
// fails, and a check that simply forgot to cite must not call this to quiet the
// warning. It only stops an honest citation limitation from being mislabelled.
func (e *Evidence) DeclareOffWire(reason string) {
	e.offWire = true
	if reason != "" {
		e.offWireReason = reason
	}
}

// OffWire reports what a CiteFunc declared via DeclareOffWire, for the runner.
func (e *Evidence) OffWire() (bool, string) { return e.offWire, e.offWireReason }

// Frames returns the frame numbers attributed to this check.
func (e *Evidence) Frames() []int { return append([]int(nil), e.Set.Frames...) }

// Owns reports whether a frame belongs to this check.
func (e *Evidence) Owns(frame int) bool { return e.Set.Owns(frame) }

// HasFrames reports whether anything at all was attributed. A CiteFunc should
// check this first and SKIP with a reason rather than assert on nothing.
func (e *Evidence) HasFrames() bool { return len(e.Set.Frames) > 0 }

// sessionNote is the caveat attached to a citation that rests on the
// session-indivisible rule rather than a frame attributed to this check's
// window.
const sessionNote = "cited as part of a TLS conversation this check owns whose establishing handshake " +
	"landed just before the window opened (a long-lived connection the DUT kept alive into it); the same " +
	"\"a TLS session is indivisible evidence\" rule the attributor applies to a split conversation"

// mayCite reports whether this check is entitled to cite a frame, and whether
// the entitlement comes from the session-indivisible rule rather than direct
// attribution.
//
// A frame the check's window OWNS is always citable — the ordinary case. Beyond
// that, a frame is citable when it belongs to a TCP conversation this check owns
// the rest of AND no other check claims it. That is not a loosening: it is the
// same doctrine consolidateStreams already enforces for a conversation SPLIT
// across two windows — a TLS session is indivisible evidence, so its handshake,
// keys and records belong together — extended to the one case consolidation
// cannot reach, where the establishing handshake fell in a GAP between windows
// (attributed to no one) while the session's body is squarely this check's.
// This is what lets an identity check cite the leaf on the very connection it
// observed when the DUT presented it on a long-lived session established just
// before the window. It never lets a check reach into another check's frames:
// a frame owned or contested by anyone else is refused.
func (e *Evidence) mayCite(frame int) (ok, viaSession bool) {
	if e.Set.Owns(frame) {
		return true, false
	}
	if _, found := e.Index.frame(frame); !found {
		return false, false
	}
	// The frame's connection INSTANCE, not its bare endpoint pair (see
	// consolidateStreams's doc): two connections that only share a port
	// because the kernel recycled it must never be treated as "the same
	// stream" here either, or this would reopen exactly the hole
	// consolidateStreams closes, just on the citation path instead of the
	// attribution one.
	st := e.Index.asm.StreamFor(frame)
	if st == nil {
		return false, false
	}
	key := st.InstanceKey()
	owned := false
	for _, s := range e.Set.Streams {
		if s == key {
			owned = true
			break
		}
	}
	if !owned {
		return false, false
	}
	// The frame must belong to no OTHER check: never steal, never cite a
	// contested frame.
	if e.Attribution != nil {
		for uid, fs := range e.Attribution.Sets {
			if uid == e.Case.UID {
				continue
			}
			if fs.owns[frame] {
				return false, false
			}
		}
		if _, contested := e.Attribution.Contested[frame]; contested {
			return false, false
		}
	}
	return true, true
}

// Packets returns only the packets attributed to this check.
func (e *Evidence) Packets() []pcapng.Packet {
	out := make([]pcapng.Packet, 0, len(e.Set.Frames))
	for _, n := range e.Set.Frames {
		if p, ok := e.Index.Packet(n); ok {
			out = append(out, p)
		}
	}
	return out
}

// Streams returns the TCP conversations this check's frames belong to.
//
// Matched by InstanceKey, not by the bare endpoint pair: a capture can hold
// several unrelated connections that share a pair because the kernel reused a
// local port (see netdis.Stream.InstanceKey), and this check's Streams list
// names the specific connection ITS window actually attributed, never every
// connection that ever used that pair.
func (e *Evidence) Streams() []*netdis.Stream {
	want := map[string]bool{}
	for _, s := range e.Set.Streams {
		want[s] = true
	}
	var out []*netdis.Stream
	for _, st := range e.Index.Streams() {
		if want[st.InstanceKey()] {
			out = append(out, st)
		}
	}
	return out
}

// Stream returns this check's single conversation with the given remote
// endpoint. It is the usual way from "I dialled 69.0.0.2:802" to the bytes:
// the check does not have to know which ephemeral port it got.
//
// The second result is false when there was no such conversation; an error is
// returned when there was more than one, because silently picking one of two
// candidate connections is how a bundle ends up citing the wrong handshake.
func (e *Evidence) Stream(remote netip.AddrPort) (*netdis.Stream, error) {
	var hits []*netdis.Stream
	for _, st := range e.Streams() {
		if endpointOf(st.Key.A) == remote || endpointOf(st.Key.B) == remote {
			hits = append(hits, st)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("certify: %s: no attributed conversation with %s (attributed streams: %s)",
			e.Case.UID, remote, strings.Join(e.Set.Streams, ", "))
	case 1:
		return hits[0], nil
	default:
		return nil, fmt.Errorf("certify: %s: %d attributed conversations with %s; "+
			"cite one explicitly rather than letting the framework guess", e.Case.UID, len(hits), remote)
	}
}

// StreamsOn returns every attributed conversation whose remote port is port,
// in capture order.
//
// Prefer this over StreamOn wherever more than one conversation to the same
// service is ORDINARY rather than exceptional. It is ordinary more often than
// it looks: a DUT that runs several client roles against one server (a 2030.5
// gateway walking discovery while its telemetry role POSTs meter readings to
// the same host:port) opens an independent connection per role, and a server
// with an idle timeout gives every poll cycle a fresh one. A caller that
// demands uniqueness in that setting never gets an answer at all.
//
// Callers pick the conversation they mean by INSPECTING it, and record why.
func (e *Evidence) StreamsOn(port uint16) ([]*netdis.Stream, error) {
	var hits []*netdis.Stream
	for _, st := range e.Streams() {
		if st.Key.A.Port == port || st.Key.B.Port == port {
			hits = append(hits, st)
		}
	}
	if len(hits) == 0 {
		return nil, fmt.Errorf("certify: %s: no attributed conversation on port %d (attributed streams: %s)",
			e.Case.UID, port, strings.Join(e.Set.Streams, ", "))
	}
	return hits, nil
}

// StreamOn returns this check's single conversation whose remote port is port,
// which is what a check that dialled a well-known port actually knows.
//
// It is deliberately strict: if the check's window caught more than one
// conversation, the check cannot know which one it meant, and guessing would
// silently cite someone else's traffic. Use StreamsOn and choose deliberately
// when several conversations are expected.
func (e *Evidence) StreamOn(port uint16) (*netdis.Stream, error) {
	hits, err := e.StreamsOn(port)
	if err != nil {
		return nil, err
	}
	if len(hits) > 1 {
		return nil, fmt.Errorf("certify: %s: %d attributed conversations on port %d; "+
			"cite one explicitly", e.Case.UID, len(hits), port)
	}
	return hits[0], nil
}

func endpointOf(e netdis.Endpoint) netip.AddrPort {
	return netip.AddrPortFrom(e.Addr.Unmap(), e.Port)
}

// CiteFrames builds a frame-cited assertion, refusing frames this check does
// not own.
func (e *Evidence) CiteFrames(claim, method string, v Verdict, observed string, frames []int) (Assertion, error) {
	if len(frames) == 0 {
		return Assertion{}, fmt.Errorf("certify: %s: CiteFrames with no frames — "+
			"use Narrative or SkipAssertion for a claim with nothing on the wire behind it", e.Case.UID)
	}
	viaSession := false
	for _, f := range frames {
		ok, s := e.mayCite(f)
		if !ok {
			owner := e.Attribution.owner(f)
			if owner == "" {
				owner = "no test case (background traffic or outside every window)"
			}
			return Assertion{}, fmt.Errorf("certify: %s may not cite frame %d: it was attributed to %s. "+
				"A check may cite only the frames its own connections produced",
				e.Case.UID, f, owner)
		}
		viaSession = viaSession || s
	}
	a, err := bundle.CiteFrames(claim, method, v, observed, e.Index.Packets(), frames)
	if err != nil {
		return Assertion{}, fmt.Errorf("certify: %s: %w", e.Case.UID, err)
	}
	if viaSession {
		a.Note = joinNote(a.Note, sessionNote)
	}
	return e.annotate(a), nil
}

// CiteBytes builds a byte-range assertion over a reassembled direction,
// refusing a direction or a range that strays outside this check's frames.
//
// The direction is normally obtained from Stream/StreamOn:
//
//	st, err := ev.StreamOn(802)
//	dir := st.ByFlow(netdis.FlowKey{Src: ..., Dst: ...})
func (e *Evidence) CiteBytes(claim, method string, v Verdict, observed string,
	d *netdis.Direction, start, end int) (Assertion, error) {

	if d == nil {
		return Assertion{}, fmt.Errorf("certify: %s: CiteBytes with a nil direction", e.Case.UID)
	}
	ref := bundle.StreamRef(d)
	owned := false
	for _, s := range e.Set.Streams {
		if s == d.InstanceKey() {
			owned = true
			break
		}
	}
	if !owned {
		return Assertion{}, fmt.Errorf("certify: %s may not cite stream %s: it is not one of this "+
			"check's attributed conversations (%s)", e.Case.UID, ref, strings.Join(e.Set.Streams, ", "))
	}
	// The frames those bytes arrived in must be ours too. They normally are —
	// the whole stream is ours — but a connection that outlived the window
	// (a late FIN, a reused socket) would otherwise let a citation reach past
	// the window's end. A frame of THIS owned conversation that no other check
	// claims is still ours by the session-indivisible rule (mayCite), which is
	// what lets a citation reach the establishing handshake of a long-lived
	// connection whose start fell in a gap before the window.
	viaSession := false
	for _, f := range d.Bytes.PacketsFor(start, end) {
		ok, s := e.mayCite(f)
		if !ok {
			return Assertion{}, fmt.Errorf("certify: %s may not cite %s bytes [%d,%d): they arrived in "+
				"frame %d, which is outside this check's window", e.Case.UID, ref, start, end, f)
		}
		viaSession = viaSession || s
	}
	a, err := bundle.CiteBytes(claim, method, v, observed, ref, d.Bytes, start, end)
	if err != nil {
		return Assertion{}, fmt.Errorf("certify: %s: %w", e.Case.UID, err)
	}
	if viaSession {
		a.Note = joinNote(a.Note, sessionNote)
	}
	return e.annotate(a), nil
}

// annotate records weaker attribution on the assertion itself, so the caveat
// travels with the claim into the bundle rather than living only in a summary
// nobody reads.
func (e *Evidence) annotate(a Assertion) Assertion {
	if e.Set.Precision == PrecisionEndpoint {
		note := "frames attributed by remote endpoint and time, not by connection 4-tuple"
		if e.Set.EndpointReason != "" {
			note += ": " + e.Set.EndpointReason
		}
		a.Note = joinNote(a.Note, note)
	}
	return a
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

// Narrative builds an assertion with no re-checkable citation: a fact the check
// established somewhere other than the pcap (an admin API, a certificate file,
// a configuration read-back). The note is mandatory and says where the fact
// came from, because "PASS, source unstated" is the shape of every dishonest
// conformance report ever written.
func (e *Evidence) Narrative(claim, method string, v Verdict, observed, source string) (Assertion, error) {
	if strings.TrimSpace(source) == "" {
		return Assertion{}, fmt.Errorf("certify: %s: Narrative requires a source — "+
			"an uncitable claim must at least say where it came from", e.Case.UID)
	}
	return Assertion{
		Claim: claim, Method: method, Verdict: v, Observed: observed,
		Note: "not wire-cited; source: " + source,
	}, nil
}

// SkipAssertion records that a criterion was addressed but could not be
// asserted here, with the reason. This is the constructor to reach for whenever
// the honest answer is "we did not actually check that".
func (e *Evidence) SkipAssertion(claim, method, reason string) Assertion {
	return Assertion{
		Claim: claim, Method: method, Verdict: Skip,
		Observed: reason,
		Note:     "not asserted in this run",
	}
}

// NoEvidence is the standard SKIP for "nothing was attributed to this check",
// spelling out why so the bundle explains itself.
func (e *Evidence) NoEvidence(claim string) Assertion {
	reason := "no capture frames were attributed to this test case"
	switch e.Set.Precision {
	case PrecisionNone:
		reason += ": the check registered no connections, so the framework had nothing to attribute by"
	default:
		reason += fmt.Sprintf(": %d frame(s) fell inside the window but belonged to other conversations",
			e.Set.TimeOnlyRejected)
	}
	return e.SkipAssertion(claim, "frame attribution (time AND flow)", reason)
}

// firstN truncates a diagnostic list so one bad capture cannot print ten
// thousand frame numbers into the report.
func firstN(v []int, n int) []int {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
