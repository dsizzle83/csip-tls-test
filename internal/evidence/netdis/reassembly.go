package netdis

import (
	"bytes"
	"fmt"
	"sort"

	"csip-tls-test/internal/evidence/pcapng"
)

// DefaultMaxPending bounds the out-of-order bytes held per direction. A capture
// with a permanent hole (the missing segment was never captured, or was crafted
// to be missing) would otherwise buffer the rest of the connection forever.
const DefaultMaxPending = 8 << 20

// Overlap records a TCP segment whose sequence range had already been claimed.
//
// Conflict is the field that matters. Overlapping segments carrying IDENTICAL
// bytes are ordinary retransmission and say nothing; overlapping segments
// carrying DIFFERENT bytes for the same sequence numbers are the signature of
// either a broken middlebox or a deliberate attempt to make two readers of the
// same capture disagree about what was said. A bundle built from a capture with
// conflicting overlaps is not evidence, and the Verify step says so.
type Overlap struct {
	Offset      int  // stream offset where the overlap starts
	Length      int  // overlapping byte count
	Packet      int  // the frame whose bytes were DISCARDED (the later writer)
	KeptPacket  int  // the frame whose bytes were kept (the first writer), 0 if unknown
	Conflict    bool // the two frames disagree about these bytes
	AlreadyGone bool // the overlap was with bytes already delivered, not merely buffered
}

func (o Overlap) String() string {
	kind := "duplicate"
	if o.Conflict {
		kind = "CONFLICTING"
	}
	return fmt.Sprintf("%s overlap at stream offset %d (%d bytes): frame %d discarded, frame %d kept",
		kind, o.Offset, o.Length, o.Packet, o.KeptPacket)
}

// run maps a half-open range of delivered stream bytes to the frame it came in.
type run struct {
	start  int // inclusive stream offset
	packet int
}

// StreamBytes is one direction's reassembled byte stream plus the mapping from
// every delivered byte back to the frame that carried it.
type StreamBytes struct {
	data []byte
	runs []run // sorted by start, contiguous, no gaps
}

// Len returns the number of bytes delivered so far.
func (sb *StreamBytes) Len() int { return len(sb.data) }

// Bytes returns the delivered stream. The slice aliases the reassembler's
// buffer; callers must not modify it.
func (sb *StreamBytes) Bytes() []byte { return sb.data }

// Range returns the bytes in [start,end). It is the accessor an assertion's
// ByteRange resolves through, so it errors rather than clamping: a citation
// that runs off the end of the stream is a broken citation, not a short read.
func (sb *StreamBytes) Range(start, end int) ([]byte, error) {
	if start < 0 || end < start || end > len(sb.data) {
		return nil, fmt.Errorf("netdis: byte range [%d,%d) is outside the %d-byte stream", start, end, len(sb.data))
	}
	return sb.data[start:end], nil
}

// OffsetToPacket returns the 1-based frame index that delivered the byte at
// off, or 0 if the offset is outside the stream.
func (sb *StreamBytes) OffsetToPacket(off int) int {
	if off < 0 || off >= len(sb.data) || len(sb.runs) == 0 {
		return 0
	}
	i := sort.Search(len(sb.runs), func(i int) bool { return sb.runs[i].start > off }) - 1
	if i < 0 {
		return 0
	}
	return sb.runs[i].packet
}

// PacketsFor returns the distinct frame indices covering [start,end), in
// ascending stream order. This is what turns "the alert is at stream offset
// 1024" into "the alert is in frames 41 and 42".
func (sb *StreamBytes) PacketsFor(start, end int) []int {
	if start < 0 {
		start = 0
	}
	if end > len(sb.data) {
		end = len(sb.data)
	}
	var out []int
	for off := start; off < end; {
		pkt := sb.OffsetToPacket(off)
		if pkt == 0 {
			break
		}
		if len(out) == 0 || out[len(out)-1] != pkt {
			out = append(out, pkt)
		}
		// Jump to the start of the next run rather than stepping byte by byte.
		i := sort.Search(len(sb.runs), func(i int) bool { return sb.runs[i].start > off })
		if i >= len(sb.runs) {
			break
		}
		off = sb.runs[i].start
	}
	return out
}

// append records len(data) bytes delivered from frame pkt.
func (sb *StreamBytes) append(data []byte, pkt int) {
	if len(data) == 0 {
		return
	}
	if len(sb.runs) == 0 || sb.runs[len(sb.runs)-1].packet != pkt {
		sb.runs = append(sb.runs, run{start: len(sb.data), packet: pkt})
	}
	sb.data = append(sb.data, data...)
}

// pending is an out-of-order segment waiting for the gap before it to fill.
type pending struct {
	start  int // absolute stream offset
	data   []byte
	packet int
}

func (p pending) end() int { return p.start + len(p.data) }

// Direction is one half of a TCP conversation: the byte stream one endpoint
// sent, plus everything the reassembler noticed while building it.
type Direction struct {
	Flow  FlowKey
	Bytes *StreamBytes

	// Gen mirrors the owning Stream's Gen: which connection instance over
	// Flow.Stream()'s pair this direction belongs to. See Stream.InstanceKey.
	Gen int

	SYNSeen bool
	FINSeen bool
	RSTSeen bool

	// MidStream is set when the first segment seen for this direction was not a
	// SYN — the capture started after the connection did. Offsets are then
	// relative to the first byte captured, NOT to the first byte the peer sent,
	// which an assertion citing an absolute offset must take into account.
	MidStream bool

	Segments      int // segments carrying payload
	Retransmits   int // segments entirely re-delivering bytes already seen
	OutOfOrder    int // segments that arrived ahead of a gap
	DroppedOOO    int // segments discarded because the pending buffer was full
	OutOfWindow   int // segments whose sequence number was implausibly far away
	Overlaps      []Overlap
	FirstPacket   int
	LastPacket    int
	pendingBytes  int
	pendingSegs   []pending
	expectSeq     uint32 // sequence number of the next byte to deliver
	haveExpect    bool
	maxPendingCap int
}

// InstanceKey renders the identity of the exact connection this direction
// belongs to, not just the endpoint pair — see Stream.InstanceKey. Two
// Directions with the same Flow but different InstanceKey are unrelated
// connections that happened to reuse a local port.
func (d *Direction) InstanceKey() string { return instanceKeyString(d.Flow.Stream(), d.Gen) }

// HasConflictingOverlap reports whether any overlap carried different bytes for
// the same sequence range — the tamper signal described on Overlap.
func (d *Direction) HasConflictingOverlap() bool {
	for _, o := range d.Overlaps {
		if o.Conflict {
			return true
		}
	}
	return false
}

// Complete reports whether the direction's stream has no unfilled gap: every
// buffered segment was eventually delivered.
func (d *Direction) Complete() bool { return len(d.pendingSegs) == 0 }

// PendingGap returns the number of bytes still buffered behind a gap, which is
// non-zero exactly when a segment was never captured.
func (d *Direction) PendingGap() int { return d.pendingBytes }

// Stream is a full TCP conversation: both directions plus the frames that
// bracket it.
//
// Key alone does not identify a CONNECTION, only an endpoint PAIR: ephemeral
// ports are reused, sometimes within seconds, so a capture can hold several
// unrelated Streams that all share one Key. Gen disambiguates them — 0 for
// the first connection this Assembler saw over that pair, 1 for the next,
// and so on — and InstanceKey is the identity that actually names one
// physical connection. See Assembler.AddFrame for how a generation boundary
// is detected.
type Stream struct {
	Key   StreamKey
	Gen   int
	Dirs  [2]*Direction
	First int // first frame index of the conversation
	Last  int // last frame index seen

	synSeen bool   // a bare (non-ACK) SYN has been seen for this generation
	synSeq  uint32 // that SYN's sequence number
}

// InstanceKey renders the identity of this exact connection, not just the
// endpoint pair it used: two Streams with the same Key can be entirely
// unrelated connections, but two with the same InstanceKey are always the
// same one. Plain Key.String() for the (overwhelmingly common) first
// connection over a pair, so the ordinary case prints exactly as before.
func (s *Stream) InstanceKey() string { return instanceKeyString(s.Key, s.Gen) }

func instanceKeyString(k StreamKey, gen int) string {
	if gen == 0 {
		return k.String()
	}
	return fmt.Sprintf("%s (reuse #%d)", k, gen)
}

// Dir returns the direction whose sender is src.
func (s *Stream) Dir(src Endpoint) *Direction {
	if src == s.Key.A {
		return s.Dirs[0]
	}
	return s.Dirs[1]
}

// ByFlow returns the direction matching f.
func (s *Stream) ByFlow(f FlowKey) *Direction { return s.Dirs[s.Key.DirIndex(f)] }

// Assembler turns a sequence of dissected frames into TCP streams.
//
// It is single-threaded by design: packets must be fed in capture order, which
// is the only order in which "first writer wins" has a defined meaning, and
// which is what lets AddFrame tell a retransmitted SYN (does not start a new
// connection) from a fresh one reusing an old local port (does).
type Assembler struct {
	current    map[StreamKey]*Stream // the generation currently receiving frames, by endpoint pair
	all        []*Stream             // every generation ever seen, in first-seen order
	frameOwner map[int]*Stream       // frame index -> the Stream it was added to
	MaxPending int                   // per direction; zero means DefaultMaxPending
}

// NewAssembler returns an empty Assembler.
func NewAssembler() *Assembler {
	return &Assembler{
		current:    make(map[StreamKey]*Stream),
		frameOwner: make(map[int]*Stream),
	}
}

// AddPacket dissects and feeds one captured packet. The dissected Frame is
// returned even for non-TCP packets so callers can build a single pass over the
// capture; a dissection error is returned as-is and the packet is not fed.
func (a *Assembler) AddPacket(p pcapng.Packet) (*Frame, error) {
	f, err := DecodePacket(p)
	if err != nil {
		return nil, err
	}
	a.AddFrame(f)
	return f, nil
}

// AddFrame feeds an already-dissected frame. Non-TCP frames, and TCP frames
// that were IP fragments, are ignored.
//
// # Detecting a reused port
//
// A bare SYN (SYN without ACK) can only legitimately open a connection. If one
// arrives for a pair that already has a generation in progress, two things can
// have happened: an ordinary retransmission of THAT generation's own opening
// SYN (the client's stack gave up waiting for a SYN-ACK and resent it
// byte-for-byte, including its sequence number), or a brand new connection
// that the kernel handed the exact same local port a prior, already-closed
// connection used. The two are told apart by sequence number: a genuine
// retransmit repeats the original ISN exactly, while a fresh connection's ISN
// is generated independently and — bar the astronomically unlikely case of a
// collision — differs. A SYN with a different ISN therefore starts a new
// generation.
func (a *Assembler) AddFrame(f *Frame) {
	if f == nil || f.TCP == nil || f.Fragmented {
		return
	}
	flow, ok := f.Flow()
	if !ok {
		return
	}
	key := flow.Stream()
	st := a.current[key]
	bareSYN := f.TCP.Flags&SYN != 0 && f.TCP.Flags&ACK == 0
	fresh := st == nil || (bareSYN && st.synSeen && f.TCP.Seq != st.synSeq)
	if fresh {
		gen := 0
		if st != nil {
			gen = st.Gen + 1
		}
		st = &Stream{Key: key, Gen: gen, First: f.Index}
		for i := 0; i < 2; i++ {
			st.Dirs[i] = &Direction{
				Flow:          key.Flow(i),
				Gen:           gen,
				Bytes:         &StreamBytes{},
				maxPendingCap: a.maxPending(),
			}
		}
		a.current[key] = st
		a.all = append(a.all, st)
	}
	if bareSYN && !st.synSeen {
		st.synSeen = true
		st.synSeq = f.TCP.Seq
	}
	st.Last = f.Index
	a.frameOwner[f.Index] = st
	st.Dirs[key.DirIndex(flow)].add(f)
}

func (a *Assembler) maxPending() int {
	if a.MaxPending > 0 {
		return a.MaxPending
	}
	return DefaultMaxPending
}

// Streams returns every conversation in first-seen order — every generation
// of every endpoint pair, each a distinct physical connection.
func (a *Assembler) Streams() []*Stream {
	return append([]*Stream(nil), a.all...)
}

// Stream looks up the MOST RECENT generation seen over a pair. A capture with
// port reuse holds earlier generations too; use Streams and filter by
// InstanceKey to reach a specific one.
func (a *Assembler) Stream(k StreamKey) *Stream { return a.current[k] }

// StreamFor returns the connection instance frame idx was added to, or nil if
// idx was never fed to this Assembler (a non-TCP or fragmented frame, or an
// index this Assembler never saw).
func (a *Assembler) StreamFor(idx int) *Stream { return a.frameOwner[idx] }

// FindPort returns the streams with an endpoint on the given port — every
// generation, oldest first. Conformance runs address a single well-known port
// (802 for mbaps), so this is the usual way a test case gets from a capture to
// its conversation.
func (a *Assembler) FindPort(port uint16) []*Stream {
	var out []*Stream
	for _, st := range a.all {
		if st.Key.A.Port == port || st.Key.B.Port == port {
			out = append(out, st)
		}
	}
	return out
}

// seqDelta is the signed distance from base to seq in TCP's 32-bit modular
// sequence space. Wraparound is not an edge case to be handled somewhere else:
// it is what this one conversion is for. A stream that passes 4 GiB (or that
// simply started with an ISN near the top of the space, which is the common
// case since ISNs are random) crosses zero, and the difference stays correct
// because it is computed in uint32 and only then reinterpreted as signed.
func seqDelta(seq, base uint32) int32 { return int32(seq - base) }

// maxSeqJump bounds how far ahead of the expected sequence number a segment may
// claim to be before it is treated as out of window rather than as a gap. Half
// the sequence space is the theoretical limit; 1 GiB is far past any real
// window and keeps a crafted sequence number from allocating a gap that large.
const maxSeqJump = 1 << 30

func (d *Direction) add(f *Frame) {
	seg := f.TCP
	if d.FirstPacket == 0 {
		d.FirstPacket = f.Index
	}
	d.LastPacket = f.Index

	if seg.Flags&RST != 0 {
		d.RSTSeen = true
	}
	if seg.Flags&SYN != 0 {
		// The SYN consumes one sequence number; the first data byte is ISN+1.
		// A retransmitted SYN must not reset a stream that has already begun.
		if !d.haveExpect {
			d.expectSeq = seg.Seq + 1
			d.haveExpect = true
		}
		d.SYNSeen = true
	}
	if seg.Flags&FIN != 0 {
		d.FINSeen = true
	}
	if len(seg.Payload) == 0 {
		return
	}
	d.Segments++

	if !d.haveExpect {
		// Capture started mid-connection: anchor the stream at this segment.
		d.expectSeq = seg.Seq
		d.haveExpect = true
		d.MidStream = true
	}

	delta := seqDelta(seg.Seq, d.expectSeq)
	start := d.Bytes.Len() + int(delta)
	if delta > maxSeqJump || delta < -maxSeqJump {
		d.OutOfWindow++
		return
	}
	d.insert(start, seg.Payload, f.Index)
}

// insert places a segment's bytes at absolute stream offset start, resolving
// every conflict in favour of whatever arrived first.
func (d *Direction) insert(start int, data []byte, pkt int) {
	delivered := d.Bytes.Len()

	// Bytes before the start of the stream (a retransmitted pre-ISN segment, or
	// a crafted negative offset) have nowhere to go.
	if start < 0 {
		if start+len(data) <= 0 {
			d.Retransmits++
			return
		}
		data = data[-start:]
		start = 0
	}

	// Overlap with bytes already delivered: keep what was delivered.
	if start < delivered {
		n := min(delivered-start, len(data))
		old := d.Bytes.data[start : start+n]
		conflict := !bytes.Equal(old, data[:n])
		d.Overlaps = append(d.Overlaps, Overlap{
			Offset:      start,
			Length:      n,
			Packet:      pkt,
			KeptPacket:  d.Bytes.OffsetToPacket(start),
			Conflict:    conflict,
			AlreadyGone: true,
		})
		if n == len(data) {
			d.Retransmits++
			return
		}
		data = data[n:]
		start = delivered
	}

	outOfOrder := start > delivered

	// Overlap with segments already buffered: again, first writer wins. The new
	// segment is cut into the pieces that nobody has claimed yet.
	pieces := []pending{{start: start, data: data, packet: pkt}}
	for _, held := range d.pendingSegs {
		var next []pending
		for _, p := range pieces {
			left, right, ov := subtract(p, held)
			if ov != nil {
				d.Overlaps = append(d.Overlaps, *ov)
			}
			if left != nil {
				next = append(next, *left)
			}
			if right != nil {
				next = append(next, *right)
			}
		}
		pieces = next
		if len(pieces) == 0 {
			break
		}
	}
	if len(pieces) == 0 {
		// Every byte was already claimed by an earlier segment: this is a
		// retransmission, not a hole-filler, whatever its sequence number.
		d.Retransmits++
		return
	}
	if outOfOrder {
		d.OutOfOrder++
	}

	for _, p := range pieces {
		if d.pendingBytes+len(p.data) > d.maxPendingCap {
			d.DroppedOOO++
			continue
		}
		d.pendingSegs = append(d.pendingSegs, p)
		d.pendingBytes += len(p.data)
	}
	sort.Slice(d.pendingSegs, func(i, j int) bool { return d.pendingSegs[i].start < d.pendingSegs[j].start })
	d.flush()
}

// flush moves every buffered segment that is now contiguous with the delivered
// stream into the stream, advancing the expected sequence number with it.
func (d *Direction) flush() {
	for len(d.pendingSegs) > 0 && d.pendingSegs[0].start == d.Bytes.Len() {
		p := d.pendingSegs[0]
		d.pendingSegs = d.pendingSegs[1:]
		d.pendingBytes -= len(p.data)
		d.Bytes.append(p.data, p.packet)
		d.expectSeq += uint32(len(p.data))
	}
}

// subtract removes the part of p that held already covers. It returns the piece
// before held, the piece after held, and an Overlap describing what was cut —
// all three nil when there was no intersection.
func subtract(p, held pending) (left, right *pending, ov *Overlap) {
	lo, hi := max(p.start, held.start), min(p.end(), held.end())
	if lo >= hi {
		cp := p
		return &cp, nil, nil
	}
	pOff, hOff := lo-p.start, lo-held.start
	ov = &Overlap{
		Offset:     lo,
		Length:     hi - lo,
		Packet:     p.packet,
		KeptPacket: held.packet,
		Conflict:   !bytes.Equal(p.data[pOff:pOff+hi-lo], held.data[hOff:hOff+hi-lo]),
	}
	if p.start < lo {
		left = &pending{start: p.start, data: p.data[:lo-p.start], packet: p.packet}
	}
	if p.end() > hi {
		right = &pending{start: hi, data: p.data[hi-p.start:], packet: p.packet}
	}
	return left, right, ov
}
