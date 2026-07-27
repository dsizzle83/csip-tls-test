package mbapref

// corpus.go seeds the fuzz corpus from real captured traffic.
//
// # Why not hand-written vectors
//
// A hand-written seed encodes what its author already believed the protocol
// looks like, and that belief is precisely what is under test. Every
// hand-written Modbus vector in every repository looks the same: one frame per
// buffer, starting at offset zero, with a length field that agrees with the
// PDU. Real traffic does not look like that. The bench's own captures contain
// frames coalesced two and three to a segment, frames split across segment
// boundaries, a request and its response 400 microseconds apart, retransmits,
// and tails that stop mid-header because the run ended. Those are the shapes a
// framing bug lives in, and a corpus without them sends the fuzzer's whole
// budget into territory the parser was written looking at.
//
// The libFuzzer-style mutation engine in Go's testing package works by
// perturbing seeds. The quality of a corpus is therefore not "how many bytes"
// but "how many distinct SHAPES are within a few mutations of a seed". A
// coalesced three-frame segment is one byte-flip away from a length field that
// makes the second frame overlap the third — which is exactly the case where
// two readers can disagree about where a frame ends, and exactly the case no
// hand-written vector will ever be near.
//
// # Provenance is kept
//
// Each entry records the capture it came from and the packet numbers its bytes
// occupied. A divergence found by mutating a seed is not itself traceable to a
// packet — it has been mutated — but the SEED is, and "this started life as
// packets 4012-4013 of run-20260727-025512" is the difference between a
// reproducer someone can reason about and a blob.
//
// # No decryption here
//
// The bench's captures carry three Modbus-bearing conversations: plain
// Modbus/TCP to the southbound sim, and two TLS-wrapped ones (mbaps on :802 and
// :8021). This file reads only the plaintext port. Extracting the TLS-wrapped
// streams is possible — internal/evidence/tlsdecrypt does it with the run's
// keys.log — but it would make the corpus depend on a key file whose presence
// is a bench-only property, and a seed corpus that silently shrinks to nothing
// on a machine without the keys is a corpus nobody can trust. The plaintext
// conversation carries the same framing shapes; it is the same gateway
// speaking.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// DefaultModbusPorts are the plaintext Modbus/TCP ports the bench uses. 502 is
// the assigned port; 5020 is where the unprivileged sims bind (see the bench
// notes in CLAUDE.md).
var DefaultModbusPorts = []uint16{502, 5020}

// Entry is one corpus seed with its provenance.
type Entry struct {
	// Bytes is the seed itself: a byte range of one direction of one
	// reassembled TCP stream.
	Bytes []byte
	// Dir says which end sent it, which the differential needs and cannot
	// infer. Losing this is how a corpus turns into noise.
	Dir Dir
	// Flow is the direction rendered as "src > dst".
	Flow string
	// Packets are the capture frame numbers these bytes came out of.
	Packets []int
	// Frames is how many complete ADUs the reference found in Bytes.
	Frames int
	// Whole is set when the entry is an entire direction of a stream rather
	// than a single extracted frame.
	Whole bool
}

// Name is a stable, filesystem-safe identifier: the shape, then a content
// hash. Content-addressing means re-running extraction against the same
// capture rewrites the same files, so a corpus directory can be committed and
// a later extraction shows up as an honest diff rather than a churn of
// timestamps.
func (e Entry) Name() string {
	sum := sha256.Sum256(e.Bytes)
	kind := "frame"
	if e.Whole {
		kind = "stream"
	}
	return fmt.Sprintf("%s-%s-%dx-%s", kind, e.Dir, e.Frames, hex.EncodeToString(sum[:6]))
}

func (e Entry) String() string {
	return fmt.Sprintf("%s: %d B, %d frame(s), %s, packets %v", e.Name(), len(e.Bytes), e.Frames, e.Flow, e.Packets)
}

// FromCapture extracts Modbus seeds from a pcapng or pcap file.
//
// It returns entries in a deterministic order (by name), because a corpus that
// depends on map iteration order produces a different set of files on every
// run and cannot be committed.
//
// Streams that carry no framable Modbus are skipped silently: a capture taken
// on a bench interface contains ssh, CSIP and TLS as well, and reporting those
// as failures would bury the one thing that matters.
func FromCapture(path string, ports []uint16) ([]Entry, error) {
	if len(ports) == 0 {
		ports = DefaultModbusPorts
	}
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mbapref: read capture %s: %w", path, err)
	}
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		// A packet this bench's dissector cannot make sense of is not a
		// corpus problem. Skipping it loses one seed; failing loses all of
		// them.
		_, _ = asm.AddPacket(p)
	}

	seen := make(map[string]bool)
	var out []Entry
	for _, port := range ports {
		for _, s := range asm.FindPort(port) {
			for _, d := range s.Dirs {
				if d == nil || d.Bytes == nil || d.Bytes.Len() == 0 {
					continue
				}
				dir := FromServer
				if d.Flow.Dst.Port == port {
					dir = FromClient
				}
				for _, e := range extractDirection(d, dir) {
					n := e.Name()
					if seen[n] {
						continue
					}
					seen[n] = true
					out = append(out, e)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// maxWholeStream caps a whole-direction seed. Go's fuzzer spends its budget
// proportionally to input size, and a 17 KB seed is 100 frames the engine will
// mutate one byte of at a time. The cap keeps whole-stream seeds in the range
// where mutation still reaches the framing arithmetic, while single-frame
// seeds carry the fine detail.
const maxWholeStream = 2048

// extractDirection turns one direction of a stream into seeds: every complete
// ADU on its own, plus a bounded prefix of the coalesced stream.
func extractDirection(d *netdis.Direction, dir Dir) []Entry {
	b := d.Bytes.Bytes()
	frames, _ := FrameStream(b)
	if len(frames) == 0 {
		return nil
	}

	out := make([]Entry, 0, len(frames)+1)
	for _, f := range frames {
		seed := make([]byte, f.End-f.Off)
		copy(seed, b[f.Off:f.End])
		out = append(out, Entry{
			Bytes:   seed,
			Dir:     dir,
			Flow:    d.Flow.String(),
			Packets: d.Bytes.PacketsFor(f.Off, f.End),
			Frames:  1,
		})
	}

	// The coalesced prefix, cut on a frame boundary so the seed is a whole
	// number of messages. A seed that ends mid-frame teaches the fuzzer that
	// truncation is normal, and truncation is the one stop class the
	// differential deliberately does not treat as a disagreement.
	end, n := 0, 0
	for _, f := range frames {
		if f.End > maxWholeStream {
			break
		}
		end, n = f.End, n+1
	}
	if n > 1 {
		seed := make([]byte, end)
		copy(seed, b[:end])
		out = append(out, Entry{
			Bytes: seed, Dir: dir, Flow: d.Flow.String(),
			Packets: d.Bytes.PacketsFor(0, end), Frames: n, Whole: true,
		})
	}
	return out
}

// Thin reduces a corpus to at most perShape single-frame seeds of each
// distinct message shape, keeping every coalesced multi-frame seed.
//
// A raw extraction from an hour of bench traffic is 90% redundant: a polling
// gateway sends the same twelve-byte read request thousands of times, and the
// only thing that differs is the transaction id. Committing all of them costs
// review attention and buys nothing, because the mutation engine reaches every
// transaction id from any one of them within a byte flip.
//
// What redundancy would cost is subtler than disk. Go's fuzzing engine works
// through the seed corpus and keeps inputs that reach new coverage; a corpus
// where nineteen inputs in twenty are the same shape spends its first pass
// re-confirming the same edges, and on a time-budgeted smoke run (which is the
// only kind this project can afford — see the strategy §6) that first pass may
// be most of the budget.
//
// Shape is (direction, function code, frame length). Length is part of it
// because a 259-byte read response and a 13-byte one exercise different
// arithmetic, and function code because an exception response is a different
// shape from the read it refused. Transaction id, unit and register values are
// deliberately NOT part of it: those are what the mutator is for.
//
// Multi-frame seeds are never thinned. They are the scarce ones — a capture
// yields a handful — and they are the only seeds that exercise framing across
// a boundary, which is where the two readers can actually disagree.
func Thin(entries []Entry, perShape int) []Entry {
	if perShape < 1 {
		perShape = 1
	}
	type shape struct {
		dir Dir
		fc  byte
		n   int
	}
	count := make(map[shape]int)
	var out []Entry
	for _, e := range entries {
		if e.Whole || e.Frames != 1 {
			out = append(out, e)
			continue
		}
		fc := byte(0)
		if len(e.Bytes) > HeaderLen {
			fc = e.Bytes[HeaderLen]
		}
		s := shape{e.Dir, fc, len(e.Bytes)}
		if count[s] >= perShape {
			continue
		}
		count[s]++
		out = append(out, e)
	}
	return out
}

// WriteCorpus writes entries into dir as raw seed files, one per entry, and
// returns the number written.
//
// The files are raw bytes rather than Go's own corpus-file encoding on
// purpose: raw seeds are readable with xxd, usable by the product repo's fuzz
// targets (which are in a different module and cannot import this package),
// and diffable when the capture changes. A target loads them with f.Add over a
// directory read rather than relying on testdata layout, which is four lines
// and costs nothing.
func WriteCorpus(dir string, entries []Entry) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("mbapref: corpus dir: %w", err)
	}
	n := 0
	for _, e := range entries {
		p := filepath.Join(dir, e.Name()+".bin")
		if err := os.WriteFile(p, e.Bytes, 0o644); err != nil {
			return n, fmt.Errorf("mbapref: write seed %s: %w", p, err)
		}
		n++
	}
	return n, nil
}

// LoadCorpus reads raw seed files written by WriteCorpus. Direction and frame
// count are recovered from the filename, which is why Name encodes them.
func LoadCorpus(dir string) ([]Entry, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, de := range ents {
		if de.IsDir() || filepath.Ext(de.Name()) != ".bin" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			return nil, err
		}
		dir := FromClient
		if strings.Contains(de.Name(), "-"+string(FromServer)+"-") {
			dir = FromServer
		}
		frames, _ := FrameStream(b)
		out = append(out, Entry{Bytes: b, Dir: dir, Frames: len(frames)})
	}
	return out, nil
}
