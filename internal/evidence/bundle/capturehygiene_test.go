package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/pcapng"
)

// hygieneBundle writes a minimal bundle whose capture summary is sum, with the
// packet count filled in from the capture that is actually shipped — which is
// the one field Verify re-derives.
func hygieneBundle(t *testing.T, sum capture.Summary) (dir string, pkts []pcapng.Packet) {
	t.Helper()
	work := t.TempDir()
	capturePath := filepath.Join(work, "run.pcapng")
	pkts = writeSyntheticCapture(t, capturePath)

	sum.Packets = len(pkts)
	b := NewBuilder(RunMeta{Tool: "evidence-engine-test", Operator: "bench"})
	b.SetCapture(sum, capturePath)
	b.AddCase(TestCaseResult{ID: "HYG-1", Title: "capture hygiene fixture", Verdict: Pass})

	dir = filepath.Join(work, "bundle")
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir, pkts
}

func readReport(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustVerify(t *testing.T, dir string) *VerifyReport {
	t.Helper()
	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("Verify reported problems: %v", rep.Problems)
	}
	return rep
}

// TestBundleWithoutHygieneAccountingStillVerifies is the compatibility floor.
//
// Every bundle written before the post-capture re-filter existed has no
// per-interface accounting in its capture summary at all, and there are 199 of
// them on this bench. They must keep verifying, and the report must not invent
// a reassuring "0 dropped" for a measurement nobody took: absent is silence,
// not zero traffic.
func TestBundleWithoutHygieneAccountingStillVerifies(t *testing.T) {
	dir, _ := hygieneBundle(t, capture.Summary{
		Tool: "dumpcap", ToolVersion: "4.2.2", Interface: "enp1s0",
		Filter: "tcp port 802", Format: "pcapng", FileBytes: 1234,
	})

	raw, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\"interfaces\"") {
		t.Fatal("a summary with no per-interface accounting still emitted an interfaces key")
	}
	// Loading it back is the old-bundle path: absent reads as the zero value.
	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := b.Capture.RefilterDropped(); got != 0 {
		t.Errorf("RefilterDropped() = %d on a bundle that never measured it", got)
	}
	if b.Capture.FilterUnarmed() {
		t.Error("FilterUnarmed() = true on a bundle that never measured it")
	}
	mustVerify(t, dir)

	if rep := readReport(t, dir); strings.Contains(rep, "Capture hygiene") {
		t.Error("REPORT.md claims a hygiene result for a bundle that carries none")
	}
}

// TestBundleDisclosesAnUnarmedFilter is the operator-facing half of the fix.
//
// The tool race leaves no other trace: dumpcap announces itself, writes a valid
// file and reports no drops while one of its taps runs unfiltered. If the
// report does not say it happened, nobody learns that a leg of their run
// captured everything on the NIC.
func TestBundleDisclosesAnUnarmedFilter(t *testing.T) {
	dir, _ := hygieneBundle(t, capture.Summary{
		Tool: "dumpcap", ToolVersion: "4.2.2", Interface: "wlp2s0,enp1s0",
		Filter: "tcp port 802", Format: "pcapng", FileBytes: 4096,
		Interfaces: []capture.InterfaceFrames{
			{ID: 0, Name: "wlp2s0", Captured: 2451, Kept: 5, Dropped: 2446,
				FilterUnarmedSuspected: true},
			{ID: 1, Name: "enp1s0", Captured: 5, Kept: 5},
		},
	})

	mustVerify(t, dir)
	rep := readReport(t, dir)

	for _, want := range []string{
		"kernel filter was not armed on every interface",
		"wlp2s0",
		"2446",
		"| wlp2s0 | 2451 | 5 | 2446 | 0 |",
		"| enp1s0 | 5 | 5 | 0 | 0 |",
		"Capture hygiene",
		"did not match and were dropped",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("REPORT.md does not mention %q", want)
		}
	}

	// The accounting round-trips through bundle.json under
	// DisallowUnknownFields, which is what makes it readable by a verifier
	// rather than a comment.
	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := b.Capture.RefilterDropped(); got != 2446 {
		t.Errorf("RefilterDropped() = %d, want 2446", got)
	}
	if got := b.Capture.UnarmedInterfaces(); len(got) != 1 || got[0] != "wlp2s0" {
		t.Errorf("UnarmedInterfaces() = %v, want [wlp2s0]", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		Capture struct {
			Interfaces []map[string]any `json:"interfaces"`
		} `json:"capture"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if len(probe.Capture.Interfaces) != 2 {
		t.Fatalf("bundle.json records %d interfaces", len(probe.Capture.Interfaces))
	}
	if probe.Capture.Interfaces[0]["filter_unarmed_suspected"] != true {
		t.Errorf("bundle.json does not carry filter_unarmed_suspected on the leaky interface: %v",
			probe.Capture.Interfaces[0])
	}
	if _, present := probe.Capture.Interfaces[1]["filter_unarmed_suspected"]; present {
		t.Error("bundle.json carries filter_unarmed_suspected on an interface that filtered correctly")
	}
}

// TestBundleReportsACleanHygienePass: the ordinary run. One line in the run
// table, no banner, no table — a healthy bench's report should not grow a
// section about a defect that did not happen.
func TestBundleReportsACleanHygienePass(t *testing.T) {
	dir, pkts := hygieneBundle(t, capture.Summary{
		Tool: "dumpcap", Interface: "enp1s0", Filter: "tcp port 802", Format: "pcapng",
		Interfaces: []capture.InterfaceFrames{{ID: 0, Name: "enp1s0", Captured: 5, Kept: 5}},
	})
	mustVerify(t, dir)

	rep := readReport(t, dir)
	if !strings.Contains(rep, "none had to be dropped") {
		t.Error("REPORT.md does not record that the re-filter found nothing to drop")
	}
	if strings.Contains(rep, "kernel filter was not armed") {
		t.Error("REPORT.md raises the unarmed-filter banner on a clean capture")
	}
	if strings.Contains(rep, "| Capture interface |") {
		t.Error("REPORT.md prints a per-interface table for a single clean interface")
	}
	if len(pkts) != 5 {
		t.Fatalf("fixture drifted: %d packets", len(pkts))
	}
}

// TestBundleDisclosesUndecidedFrames: frames the re-filter kept because it
// could not decide them are a disclosure of their own — the report has to say
// the capture may hold something the filter did not ask for, rather than
// implying the pcap is exactly the filter's image.
func TestBundleDisclosesUndecidedFrames(t *testing.T) {
	dir, _ := hygieneBundle(t, capture.Summary{
		Tool: "dumpcap", Interface: "enp1s0", Filter: "tcp port 802", Format: "pcapng",
		Interfaces: []capture.InterfaceFrames{
			{ID: 0, Name: "enp1s0", Captured: 7, Kept: 5, Dropped: 2, Undecided: 1,
				FilterUnarmedSuspected: true},
		},
	})
	mustVerify(t, dir)

	rep := readReport(t, dir)
	if !strings.Contains(rep, "were KEPT although the re-filter could not decide them") {
		t.Error("REPORT.md does not disclose the frames the re-filter could not decide")
	}
	if !strings.Contains(rep, "never destroy evidence") {
		t.Error("REPORT.md does not state the direction the re-filter fails in")
	}
}
