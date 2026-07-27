package mbapref

// fuzz_test.go is the differential fuzz target.
//
// # The oracle is disagreement, not survival
//
// The fuzz targets this project had before this one asserted that a decoder
// did not panic. lexa-proto/mbap does not panic; it has never panicked; a
// no-panic oracle over it is satisfied by the first seed and will be satisfied
// by the last one, and the hours in between buy nothing. The oracle here is
// that two independently written readers put the frame boundaries in the same
// places, read the same fields out of them, agree about what to refuse, and
// both re-encode to the bytes they were given. No expected answer has to be
// written down anywhere for that to be checkable, which is the property that
// makes differential fuzzing worth the effort of building the second reader.
//
// # Seeds
//
// testdata/corpus holds seeds extracted from a real bench capture — see
// corpus.go for why that matters and Thin for why there are 46 of them rather
// than 302. The hostile seeds added below are the shapes real traffic does not
// contain because both peers are working correctly: a length field that
// overruns its buffer, a frame whose declared length points into the middle of
// the next frame, a maximum-size PDU, an exception in the wrong direction.
// Those are one mutation from a disagreement and zero mutations from anything
// the capture holds.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

const corpusDir = "testdata/corpus"

// hostileSeeds are the shapes a healthy bench never produces. Each is the
// smallest buffer that puts the two readers in a position to disagree.
func hostileSeeds() [][]byte {
	max := make([]byte, MaxPDU)
	max[0] = FCReadHolding
	return [][]byte{
		// A one-byte PDU: the enumerated DIV-LEN2 divergence, seeded so the
		// mutator explores its neighbourhood rather than rediscovering it.
		{0, 1, 0, 0, 0, 2, 1, FCReadHolding},
		// Length declares more PDU than the buffer holds — the truncation
		// classification's boundary case.
		{0, 1, 0, 0, 0, 40, 1, FCReadHolding, 0, 0},
		// Two frames where the first declares a length that lands inside the
		// second. This is the only shape in which a framing disagreement can
		// hide, and no capture of two correct peers contains it.
		append(frame(1, 1, readReqPDU(0, 1)...), frame(2, 1, readReqPDU(1, 1)...)[2:]...),
		// The maximum legal PDU, and one byte past it.
		frame(1, 1, max...),
		frame(1, 1, append(max, 0)...),
		// A nonzero protocol id: both must refuse, and refuse at the same
		// offset.
		{0, 1, 0, 9, 0, 6, 1, FCReadHolding, 0, 0, 0, 1},
		// An exception response in the request direction.
		frame(1, 1, FCReadHolding|ExceptionBit, 2),
		// A write of 123 registers, the FC 16 ceiling, and one past it.
		fc16(0, 123), fc16(0, 124),
		// A read span that wraps the register space.
		frame(1, 1, readReqPDU(0xFFFF, 2)...),
		// A byte count that disagrees with the register count.
		{0, 1, 0, 0, 0, 9, 1, FCWriteMultiple, 0, 0, 0, 2, 2, 0, 1},
	}
}

func fc16(addr uint16, n int) []byte {
	p := make([]byte, 6+2*n)
	p[0] = FCWriteMultiple
	binary.BigEndian.PutUint16(p[1:3], addr)
	binary.BigEndian.PutUint16(p[3:5], uint16(n))
	p[5] = byte(2 * n)
	return frame(1, 1, p...)
}

// seedFromCorpus adds every committed seed to f, in both directions.
//
// Direction is fuzzed as a separate parameter rather than taken from the
// filename because the interesting question is not "was this bytes from a
// client" but "does either reader change its answer when told the other
// thing". A reader whose framing depends on direction has a bug; a reader
// whose PDU decoding does not is missing one.
func seedFromCorpus(f *testing.F) int {
	ents, err := os.ReadDir(corpusDir)
	if err != nil {
		f.Fatalf("seed corpus %s is missing — it is committed, and a run without it "+
			"would fuzz from nothing and report a pass: %v", corpusDir, err)
	}
	n := 0
	for _, de := range ents {
		if de.IsDir() || filepath.Ext(de.Name()) != ".bin" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(corpusDir, de.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, false)
		f.Add(b, true)
		n++
	}
	for _, b := range hostileSeeds() {
		f.Add(b, false)
		f.Add(b, true)
		n++
	}
	if n == 0 {
		f.Fatal("no seeds at all")
	}
	return n
}

func dirOf(server bool) Dir {
	if server {
		return FromServer
	}
	return FromClient
}

// FuzzMBAPDifferential is the single-direction differential: framing,
// semantics, acceptance and identity over one byte stream.
func FuzzMBAPDifferential(f *testing.F) {
	seedFromCorpus(f)
	sub := ProtoSubject()

	f.Fuzz(func(t *testing.T, b []byte, server bool) {
		// A buffer too short to hold a header cannot distinguish the readers
		// and is not worth a report; both classify it as truncated. Skipping
		// it here rather than in the oracle keeps the oracle's silence
		// meaningful.
		if len(b) < HeaderLen {
			return
		}
		fs := Differential(Compare(sub, b, dirOf(server)))
		if len(fs) == 0 {
			return
		}
		for _, x := range fs {
			t.Errorf("%s", x)
		}
		t.Fatalf("input (% x) direction=%s produced %d unenumerated divergence(s) between "+
			"lexa-proto/mbap and the bench reference", b, dirOf(server), len(fs))
	})
}

// FuzzMBAPExchange fuzzes both directions of a conversation at once, which is
// the only way to reach the response-direction checks: a response cannot be
// judged without the request it answers.
func FuzzMBAPExchange(f *testing.F) {
	f.Add(frame(1, 1, readReqPDU(40000, 2)...), frame(1, 1, FCReadHolding, 4, 0, 1, 0, 2))
	f.Add(frame(1, 1, writeSinglePDU(40233, 80)...), frame(1, 1, writeSinglePDU(40233, 80)...))
	f.Add(frame(1, 1, readReqPDU(40000, 4)...), frame(1, 1, FCReadHolding, 2, 0, 1))
	f.Add(frame(1, 1, readReqPDU(40000, 1)...), frame(1, 1, FCReadHolding|ExceptionBit, 2))
	f.Add(fc16(40000, 2), frame(1, 1, FCWriteMultiple, 0x9c, 0x40, 0, 2))

	sub := ProtoSubject()
	f.Fuzz(func(t *testing.T, client, server []byte) {
		if len(client) < HeaderLen || len(server) < HeaderLen {
			return
		}
		fs, _ := CompareStreams(sub, client, server)
		u := Differential(fs)
		if len(u) == 0 {
			return
		}
		for _, x := range u {
			t.Errorf("%s", x)
		}
		t.Fatalf("client (% x) / server (% x) produced %d unenumerated divergence(s)",
			client, server, len(u))
	})
}

// FuzzMBAPRoundTrip is the identity claim on its own, stated as a property
// rather than a comparison: anything the REFERENCE frames must re-encode to
// the bytes it was framed from, and re-framing those bytes must give the same
// frames back.
//
// It exists separately from the differential because it can fail when the two
// readers agree — they could agree on a wrong answer — and a property that
// needs no second implementation should not be made to depend on one.
func FuzzMBAPRoundTrip(f *testing.F) {
	seedFromCorpus(f)

	f.Fuzz(func(t *testing.T, b []byte, _ bool) {
		frames, _ := FrameStream(b)
		var rebuilt []byte
		for _, fr := range frames {
			enc, err := Encode(fr)
			if err != nil {
				t.Fatalf("framed a frame that will not re-encode: %v (frame %s)", err, fr)
			}
			if got, want := string(enc), string(b[fr.Off:fr.End]); got != want {
				t.Fatalf("re-encode differs at [%d,%d): got % x, want % x", fr.Off, fr.End, enc, b[fr.Off:fr.End])
			}
			rebuilt = append(rebuilt, enc...)
		}
		if len(frames) == 0 {
			return
		}
		again, _ := FrameStream(rebuilt)
		if len(again) != len(frames) {
			t.Fatalf("re-framing the re-encoded bytes gave %d frames, not %d", len(again), len(frames))
		}
		for i := range again {
			if again[i].TID != frames[i].TID || again[i].Unit != frames[i].Unit ||
				again[i].Length != frames[i].Length || string(again[i].PDU) != string(frames[i].PDU) {
				t.Fatalf("frame %d changed across a round trip: %s then %s", i, frames[i], again[i])
			}
		}
	})
}
