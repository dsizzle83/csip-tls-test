package certify

// artifacts_test.go exercises the per-test capture export against the two
// mistakes that would turn it from evidence into a liability: writing a file
// whose contents are not the frames the name claims, and writing nothing while
// reporting success.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// twoConnections builds a capture holding two distinct TCP conversations plus
// a third the case does not own, which is the background traffic a naive
// exporter would sweep in.
func twoConnections(t *testing.T) (*FrameIndex, []int, []int) {
	t.Helper()
	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	dut, srvA, srvB := ap("10.0.0.5:41000"), ap("10.0.0.9:802"), ap("10.0.0.9:803")
	other := ap("10.0.0.7:5020")

	specs := []synthFrame{
		{src: dut, dst: srvA, seq: 1, flags: tcpSYN, at: base},
		{src: srvA, dst: dut, seq: 1, flags: tcpSYN | tcpACK, at: base.Add(time.Millisecond)},
		{src: other, dst: srvA, seq: 1, payload: "background", at: base.Add(2 * time.Millisecond)},
		{src: dut, dst: srvA, seq: 2, payload: "first-conn", at: base.Add(3 * time.Millisecond)},
		{src: dut, dst: srvB, seq: 1, flags: tcpSYN, at: base.Add(4 * time.Millisecond)},
		{src: srvB, dst: dut, seq: 1, payload: "second-conn", at: base.Add(5 * time.Millisecond)},
	}
	pkts := synthPackets(specs)
	fi := NewFrameIndex(pkts)
	// The case owns both of its own conversations and not the background one.
	return fi, []int{1, 2, 4, 5, 6}, []int{3}
}

func TestExportCaseCapturesWritesOneFilePerName(t *testing.T) {
	fi, owned, _ := twoConnections(t)
	dir := t.TempDir()
	set := &FrameSet{UID: "ssm-conf-v0.8::TLSF-005", Frames: owned}

	arts := exportCaseCaptures(fi, set, set.UID,
		[]string{"tlsf_005.pcap", "tlsf_005_resume.pcap"}, dir)
	if len(arts) != 2 {
		t.Fatalf("got %d artefact(s), want one per declared name", len(arts))
	}

	// First-seen order: the :802 conversation opened first, so it is
	// tlsf_005.pcap and the :803 one is the resumption attempt.
	want := [][]int{{1, 2, 4}, {5, 6}}
	for i, a := range arts {
		if a.Problem != "" {
			t.Fatalf("%s: %s", a.Name, a.Problem)
		}
		if len(a.Frames) != len(want[i]) {
			t.Fatalf("%s holds frames %v, want %v", a.Name, a.Frames, want[i])
		}
		for j := range want[i] {
			if a.Frames[j] != want[i][j] {
				t.Errorf("%s frame %d = %d, want %d", a.Name, j, a.Frames[j], want[i][j])
			}
		}
		// The FILE is the deliverable, so assert against the file.
		back, err := pcapng.ReadFile(filepath.Join(dir, a.Name))
		if err != nil {
			t.Fatalf("%s does not read back: %v", a.Name, err)
		}
		if len(back) != len(want[i]) {
			t.Errorf("%s reads back with %d frame(s), want %d", a.Name, len(back), len(want[i]))
		}
		// Assert on the BYTES, not on the re-read file's frame numbering: a
		// libpcap file numbers its own records from 1, so an exported slice's
		// indices say nothing about which run-capture frames are in it. The
		// background conversation's payload is the thing that must be absent.
		for _, p := range back {
			if bytes.Contains(p.Data, []byte("background")) {
				t.Errorf("%s contains the background conversation's payload", a.Name)
			}
			if p.LinkType != netdis.LinkTypeEthernet {
				t.Errorf("%s frame lost its link type", a.Name)
			}
		}
	}
}

// TestExportCaseCapturesRefusesToGuessASplit is the one that matters. A file
// called tlsf_003_untrusted.pcap holding the expired certificate's handshake
// parses perfectly and evidences the wrong thing under a name that says
// otherwise — strictly worse than no file, because a reviewer would believe it.
func TestExportCaseCapturesRefusesToGuessASplit(t *testing.T) {
	fi, owned, _ := twoConnections(t)
	dir := t.TempDir()
	set := &FrameSet{UID: "ssm-conf-v0.8::TLSF-003", Frames: owned}

	names := []string{"tlsf_003_expired.pcap", "tlsf_003_badsig.pcap", "tlsf_003_untrusted.pcap"}
	arts := exportCaseCaptures(fi, set, set.UID, names, dir)
	if len(arts) != 3 {
		t.Fatalf("got %d artefact(s), want one report per declared name even when none was written", len(arts))
	}
	for _, a := range arts {
		if a.Problem == "" {
			t.Errorf("%s was written from 2 connections under 3 names", a.Name)
		}
		if a.Path != "" {
			t.Errorf("%s reports a path despite not being written", a.Name)
		}
		if _, err := os.Stat(filepath.Join(dir, a.Name)); err == nil {
			t.Errorf("%s exists on disk despite the refusal", a.Name)
		}
	}
	// And the refusal has to say what a submitter should do about it.
	if got := arts[0].Problem; got == "" || !strings.Contains(got, "TCP connection") {
		t.Errorf("the refusal does not explain the mismatch: %q", got)
	}
}

// TestExportCaseCapturesReportsAnEmptyAttribution: a case that produced no
// frames must be reported as missing its file, not quietly skipped — the gap
// belongs in the bundle, where a submitter sees it, rather than at the lab.
func TestExportCaseCapturesReportsAnEmptyAttribution(t *testing.T) {
	fi, _, _ := twoConnections(t)
	arts := exportCaseCaptures(fi, &FrameSet{UID: "x"}, "x", []string{"prot_004.pcap"}, t.TempDir())
	if len(arts) != 1 || arts[0].Problem == "" {
		t.Fatalf("an unattributed case must report its missing file: %+v", arts)
	}
	if note := captureArtifactNote(arts); note == "" || !strings.Contains(note, "NOT WRITTEN") {
		t.Errorf("the bundle note hides the gap: %q", note)
	}

	// A single-name case takes the whole frame set, connections and all: the
	// document asks for "the entire session".
	fi, owned, _ := twoConnections(t)
	arts = exportCaseCaptures(fi, &FrameSet{UID: "y", Frames: owned}, "y",
		[]string{"tlsf_001.pcap"}, t.TempDir())
	if len(arts) != 1 || arts[0].Problem != "" {
		t.Fatalf("a single-name case must not be split: %+v", arts)
	}
	if len(arts[0].Frames) != len(owned) {
		t.Errorf("tlsf_001.pcap holds %d frame(s), want the whole session's %d",
			len(arts[0].Frames), len(owned))
	}
	if note := captureArtifactNote(arts); strings.Contains(note, "NOT WRITTEN") {
		t.Errorf("a clean export reports a gap it does not have: %q", note)
	}
}
