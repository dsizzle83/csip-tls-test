package bundle

// timebase_test.go — the clock channel, from authorship to verification.
//
// The property under test is the one an adversarial gate found missing (IW15
// H6): an accelerated run must be unable to reach a reader looking like a
// wall-clock one. The tests below take the three routes by which it could —
// the declaration never being written, the declaration being re-worded after
// the fact, and the declaration being absent from an older bundle and quietly
// assumed benign — and pin what happens on each.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/capture"
)

// scaledLabel is the sentence a 900× clock renders as. It is written out here
// rather than computed so that a change to the wording has to be made twice, on
// purpose. The fixture-side pin lives in timebase_pin_test.go, which asserts
// sim/southbound produces this exact string.
const scaledLabel = "scaled 900× (ACCELERATED TEST TIME — proves this harness's expiry semantics, " +
	"NOT any real device's timing)"

// buildTimebaseBundle is buildBundle's sibling for the clock channel: the same
// synthetic capture and one cited case, plus an ACCELERATED clock declaration
// of the kind a run driving the 704 reversion engine at 900× would record.
func buildTimebaseBundle(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	capturePath := filepath.Join(work, "run.pcapng")
	pkts := writeSyntheticCapture(t, capturePath)

	syn, err := CiteFrames("The session was opened to port 802.", "TCP SYN to the mbaps port",
		Pass, "SYN from 69.0.0.20:51422 to 69.0.0.2:802", pkts, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}

	tb, err := DeclareScaled("sim/southbound: model 704 reversion engine",
		"in-process handle held by the run that wrote this bundle", 900)
	if err != nil {
		t.Fatalf("DeclareScaled: %v", err)
	}

	b := NewBuilder(RunMeta{
		Tool: "evidence-engine-test", ToolVersion: "0.0.1",
		Started:  time.Unix(1_700_000_000, 0).UTC(),
		Finished: time.Unix(1_700_000_060, 0).UTC(),
		DUT:      DUT{Name: "battery pack", Address: "69.0.0.11:5021"},
	})
	b.SetCapture(capture.Summary{
		Tool: "dumpcap", Interface: "enp1s0", Packets: len(pkts), Format: "pcapng",
	}, capturePath)
	b.AddCase(TestCaseResult{
		ID: "REV-1", Title: "Reversion timeout", Applicable: true,
		Assertions: []Assertion{syn},
	})
	b.AddTimebase(tb)

	dir := filepath.Join(work, "bundle")
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir
}

// The whole point of the channel: the declaration reaches bundle.json, REPORT.md
// says so on its face, and the verifier re-derives it.
func TestTimebaseDeclarationSurvivesWriteAndVerify(t *testing.T) {
	dir := buildTimebaseBundle(t)

	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(b.Timebases) != 1 {
		t.Fatalf("bundle carries %d clock declarations, want 1", len(b.Timebases))
	}
	got := b.Timebases[0]
	if got.Kind != TimebaseScaled || got.Scale != 900 {
		t.Errorf("declaration = %+v, want a scaled 900× clock", got)
	}
	if got.Label != scaledLabel {
		t.Errorf("label = %q\nwant %q", got.Label, scaledLabel)
	}
	if !got.Accelerated() {
		t.Error("a 900× clock does not report itself as accelerated")
	}
	if got.Source == "" {
		t.Error("the declaration lost its provenance in the round trip")
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("bundle does not verify: %v", rep.Problems)
	}
	if rep.TimebasesDeclared != 1 || rep.TimebasesAccelerated != 1 || rep.TimebaseUndeclared {
		t.Errorf("verify report = declared %d, accelerated %d, undeclared %v",
			rep.TimebasesDeclared, rep.TimebasesAccelerated, rep.TimebaseUndeclared)
	}
	if !strings.Contains(rep.String(), "ACCELERATED TEST TIME") {
		t.Errorf("the verifier's own output does not say the run was accelerated:\n%s", rep.String())
	}

	report := mustReport(t, dir)
	for _, want := range []string{
		"## Fixture timebase",
		"THIS RUN DID NOT RUN ON THE WALL CLOCK",
		scaledLabel,
		"in-process handle held by the run that wrote this bundle",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("REPORT.md does not carry %q\n---\n%s", want, report)
		}
	}
	if strings.Contains(report, "%!") {
		t.Error("REPORT.md contains a formatting error")
	}
}

// THE FINDING, closed: re-labelling an accelerated bundle must not verify.
//
// Each edit below is a way somebody — or a merge, or a hand-fix — could make
// the bundle understate its own acceleration. All of them leave every citation
// in the bundle intact and the manifest freshly consistent, which is exactly
// why re-deriving the label from the numbers is the check that catches them.
func TestVerifyRefusesARelabelledClock(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Bundle)
		want string
	}{
		{
			name: "the accelerated label rewritten to wall",
			edit: func(b *Bundle) { b.Timebases[0].Label = "wall" },
			want: "the label and the numbers in this declaration describe different clocks",
		},
		{
			name: "the kind rewritten to wall, scale left at 900",
			edit: func(b *Bundle) { b.Timebases[0].Kind = TimebaseWall },
			want: "real time is 1× by definition",
		},
		{
			name: "the scale rewritten to 1, label left accelerated",
			edit: func(b *Bundle) { b.Timebases[0].Scale = 1 },
			want: "describe different clocks",
		},
		{
			name: "a kind nobody can re-derive",
			edit: func(b *Bundle) { b.Timebases[0].Kind = TimebaseKind("realtime-ish") },
			want: "does not recognise",
		},
		{
			name: "the component erased, so nobody knows whose clock it was",
			edit: func(b *Bundle) { b.Timebases[0].Component = "" },
			want: "names no component",
		},
		{
			name: "elapsed time smuggled onto a scaled clock",
			edit: func(b *Bundle) { b.Timebases[0].ElapsedS = 42 },
			want: "which only a manual clock has",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := buildTimebaseBundle(t)
			editBundle(t, dir, tc.edit)
			rep, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK {
				t.Fatal("verification passed a clock declaration that contradicts itself")
			}
			if !strings.Contains(strings.Join(rep.Problems, "\n"), tc.want) {
				t.Errorf("problems do not say %q:\n%s", tc.want, strings.Join(rep.Problems, "\n"))
			}
		})
	}
}

// BACKWARD COMPATIBILITY, which is not optional: every bundle in runs/ predates
// this channel. Such a bundle must verify exactly as it did, gain no key and no
// section, and have its SILENCE disclosed — "this bundle does not say" is a
// different statement from "this bundle says wall", and the verifier must not
// turn either into a fault.
func TestBundleWithoutATimebaseIsUnchangedAndDisclosed(t *testing.T) {
	dir, _, _ := buildBundle(t)

	data, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\"timebases\"") {
		t.Error("bundle.json gained a timebases key for a run that declared no clock")
	}
	if strings.Contains(mustReport(t, dir), "Fixture timebase") {
		t.Error("REPORT.md invents a timebase section for a bundle that has none")
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a bundle predating the clock channel must still verify: %v", rep.Problems)
	}
	if rep.TimebasesDeclared != 0 || !rep.TimebaseUndeclared {
		t.Errorf("verify report = declared %d, undeclared %v", rep.TimebasesDeclared, rep.TimebaseUndeclared)
	}
	if len(rep.Problems) != 0 {
		t.Errorf("absence of a declaration was recorded as a problem: %v", rep.Problems)
	}
	if !strings.Contains(rep.String(), "NOT DECLARED") {
		t.Errorf("the verifier does not disclose that the bundle is silent about its clock:\n%s", rep.String())
	}
}

// The authoring side refuses too, so a contradictory declaration is a build
// failure on the bench rather than a verification failure in a reviewer's
// hands — where it would read as tampering rather than as the slip it was.
func TestWriteRefusesAContradictoryDeclaration(t *testing.T) {
	work := t.TempDir()
	capturePath := filepath.Join(work, "run.pcapng")
	writeSyntheticCapture(t, capturePath)

	b := NewBuilder(RunMeta{Tool: "evidence-engine-test"})
	b.AddTimebase(Timebase{
		Component: "hand-assembled", Kind: TimebaseScaled, Scale: 900, Label: "wall",
	})
	if _, err := b.Write(filepath.Join(work, "bundle")); err == nil {
		t.Fatal("Write accepted a 900× clock labelled \"wall\"")
	} else if !strings.Contains(err.Error(), "describe different clocks") {
		t.Errorf("error = %v", err)
	}

	if _, err := DeclareScaled("c", "s", 0); err == nil {
		t.Error("DeclareScaled accepted a scale of 0")
	}
	if _, err := DeclareScaled("c", "s", -900); err == nil {
		t.Error("DeclareScaled accepted a negative scale")
	}
}

// A wall-clock declaration is a real statement and must survive too: it is the
// difference between a run that said it used real time and one that said
// nothing at all, and only the first supports a claim about a device's timing.
func TestWallClockDeclarationIsRecordedQuietly(t *testing.T) {
	work := t.TempDir()
	capturePath := filepath.Join(work, "run.pcapng")
	pkts := writeSyntheticCapture(t, capturePath)

	b := NewBuilder(RunMeta{Tool: "evidence-engine-test"})
	b.SetCapture(capture.Summary{Tool: "dumpcap", Packets: len(pkts), Format: "pcapng"}, capturePath)
	syn, err := CiteFrames("c", "m", Pass, "o", pkts, []int{1})
	if err != nil {
		t.Fatal(err)
	}
	b.AddCase(TestCaseResult{ID: "REV-1", Assertions: []Assertion{syn}})
	b.AddTimebase(DeclareWall("sim/southbound: model 704 reversion engine", "in-process handle"))

	dir := filepath.Join(work, "bundle")
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("verify: %v", rep.Problems)
	}
	if rep.TimebasesDeclared != 1 || rep.TimebasesAccelerated != 0 || rep.TimebaseUndeclared {
		t.Errorf("verify report = declared %d, accelerated %d, undeclared %v",
			rep.TimebasesDeclared, rep.TimebasesAccelerated, rep.TimebaseUndeclared)
	}
	if s := rep.String(); !strings.Contains(s, "all wall-clock") || strings.Contains(s, "ACCELERATED") {
		t.Errorf("a wall-clock run should be stated without a banner:\n%s", s)
	}
	report := mustReport(t, dir)
	if !strings.Contains(report, "## Fixture timebase") || strings.Contains(report, "DID NOT RUN ON THE WALL CLOCK") {
		t.Errorf("REPORT.md = \n%s", report)
	}
}

// The manual clock's rendering, including the position it had reached: a
// declaration taken at t+1.5 s and one taken at t+0 describe different moments
// of the same test, and the label carries it.
func TestManualDeclarationCarriesItsPosition(t *testing.T) {
	d := DeclareManual("fixture", "unit test", 1500*time.Millisecond)
	if err := d.Check(); err != nil {
		t.Fatalf("a manual declaration must be self-consistent: %v", err)
	}
	if !strings.Contains(d.Label, "t+1.500s") {
		t.Errorf("label = %q, want it to state how far the clock had been advanced", d.Label)
	}
	if !d.Accelerated() {
		t.Error("a manual clock is not the wall clock and must report as accelerated")
	}
	if d.Scale != 0 {
		t.Errorf("manual scale = %v, want 0 — hand-advanced time has no rate", d.Scale)
	}
}
