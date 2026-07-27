package mbapref

// corpus_test.go is the standing regression against real traffic, and the
// entry point that regenerates the corpus when a new capture supersedes the
// old one.
//
// The regression is the cheap half and it earns its place: every committed
// seed is a message the gateway actually sent or received on the bench, and
// asserting that the two readers agree about all of them is the claim "the
// evidence bundles this project emits describe the frames the DUT really
// exchanged". That claim underwrites every conformance report the bench
// produces, and until now nothing tested it.

import (
	"os"
	"path/filepath"
	"testing"
)

// liveCapture is the run this corpus was extracted from. It is deliberately a
// specific path rather than a glob: a test that silently picks up whichever
// capture happens to be newest reports on something different every week, and
// its passing means nothing you can write down.
const liveCapture = "../../runs/20260726T225512/capture/run-20260727-025512.pcapng"

func TestCorpus_TheCommittedSeedsAreRealAndFrame(t *testing.T) {
	ents, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatalf("the seed corpus is committed and must be readable: %v", err)
	}
	if len(ents) < 20 {
		t.Fatalf("only %d seeds — the corpus has been emptied or thinned past usefulness", len(ents))
	}

	// The assertion floor. A corpus of bytes that do not frame would run the
	// differential's truncation path over and over and report agreement,
	// which is agreement about nothing. Counting frames is what makes the
	// silence in the next test mean something.
	var frames, multi int
	for _, e := range ents {
		frames += e.Frames
		if e.Frames > 1 {
			multi++
		}
	}
	if frames < 100 {
		t.Fatalf("the corpus frames only %d adus across %d seeds; the oracle would barely run", frames, len(ents))
	}
	if multi < 5 {
		t.Fatalf("only %d multi-frame seeds — coalesced framing is the one shape a boundary bug hides in", multi)
	}
	t.Logf("%d seeds, %d framed adus, %d coalesced multi-frame seeds", len(ents), frames, multi)
}

func TestCorpus_RealTrafficProducesNoUnenumeratedDivergence(t *testing.T) {
	ents, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, e := range ents {
		// Both directions, not just the recorded one. A reader whose framing
		// depends on which way the bytes were going has a bug this catches
		// for free.
		for _, d := range []Dir{FromClient, FromServer} {
			checked++
			if fs := Unenumerated(Compare(ProtoSubject(), e.Bytes, d)); len(fs) != 0 {
				for _, f := range fs {
					t.Errorf("%s (%s): %s", e.Name(), d, f)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("nothing was checked")
	}
	t.Logf("%d comparisons, no unenumerated divergence", checked)
}

func TestCorpus_TheSeedsRoundTrip(t *testing.T) {
	ents, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		frames, fault := FrameStream(e.Bytes)
		if fault != nil {
			t.Errorf("%s: a committed seed must frame cleanly: %v", e.Name(), fault)
			continue
		}
		for _, f := range frames {
			enc, err := Encode(f)
			if err != nil {
				t.Errorf("%s: %v", e.Name(), err)
				continue
			}
			if string(enc) != string(e.Bytes[f.Off:f.End]) {
				t.Errorf("%s: frame at [%d,%d) does not re-encode to itself", e.Name(), f.Off, f.End)
			}
			n++
		}
	}
	t.Logf("%d frames re-encoded byte for byte", n)
}

// TestCorpus_ExtractionAgreesWithWhatIsCommitted re-runs extraction against the
// capture and checks the committed set is what the capture yields.
//
// It SKIPs when the capture is absent rather than failing, because runs/ is
// not committed — but the skip names the file, so a machine that has the
// capture and a machine that does not are distinguishable in the log. A silent
// skip here would let the corpus drift away from its source without anyone
// noticing.
func TestCorpus_ExtractionAgreesWithWhatIsCommitted(t *testing.T) {
	if _, err := os.Stat(liveCapture); err != nil {
		t.Skipf("capture %s is not present on this machine (runs/ is not committed); "+
			"the committed corpus is still checked by the other tests in this file", liveCapture)
	}
	es, err := FromCapture(liveCapture, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, e := range Thin(es, 3) {
		want[e.Name()] = true
	}
	got := map[string]bool{}
	des, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if filepath.Ext(de.Name()) == ".bin" {
			got[de.Name()[:len(de.Name())-4]] = true
		}
	}
	for n := range want {
		if !got[n] {
			t.Errorf("the capture yields %s but it is not committed — re-run with MBAPREF_REGEN=1", n)
		}
	}
	for n := range got {
		if !want[n] {
			t.Errorf("%s is committed but the capture does not yield it", n)
		}
	}
	t.Logf("%d raw entries thinned to %d, all committed", len(es), len(want))
}

// TestRegenerateCorpus rewrites testdata/corpus from the live capture.
//
// It is a test rather than a cmd/ program because the extraction is four lines
// and a program would need a module entry, a flag set and a README nobody
// reads. It does nothing unless MBAPREF_REGEN is set, so it costs an ordinary
// run one skipped test and the reason it skipped.
func TestRegenerateCorpus(t *testing.T) {
	if os.Getenv("MBAPREF_REGEN") == "" {
		t.Skip("set MBAPREF_REGEN=1 to rewrite testdata/corpus from " + liveCapture)
	}
	es, err := FromCapture(liveCapture, nil)
	if err != nil {
		t.Fatal(err)
	}
	thin := Thin(es, 3)
	if err := os.RemoveAll(corpusDir); err != nil {
		t.Fatal(err)
	}
	n, err := WriteCorpus(corpusDir, thin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("extracted %d entries from %s, thinned to %d, wrote %d files",
		len(es), liveCapture, len(thin), n)
	for _, e := range thin {
		if e.Whole {
			t.Logf("  %s", e)
		}
	}
}
