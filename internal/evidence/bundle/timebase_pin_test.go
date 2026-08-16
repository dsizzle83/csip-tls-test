package bundle_test

// timebase_pin_test.go — THE PIN the adversarial gate proved was missing.
//
// # What went wrong, exactly
//
// sim/southbound's model 704 reversion engine can run on an accelerated clock,
// and declared it by publishing a label on GET /state. The gate rewrote
// ScaledTimebase.Label() to return the flat lie "wall" and ran the tree:
// `go test ./sim/southbound/` reported ok. Nothing anywhere asserted the
// string, so the entire acceleration fence rested on a sentence no test read.
//
// # Why the pin lives HERE and not beside the fixture
//
// The party that would be lied to is the READER OF A BUNDLE, and the verifier
// acts on their behalf: bundle.Timebase.Render owns the wording, and
// bundle.Verify refuses a declaration whose label does not follow from its
// numbers. This test is the seam between that verifier and the fixture that
// feeds it — it asserts the literal sentences and that sim/southbound produces
// exactly them, so neither end can be re-worded alone.
//
// It is an EXTERNAL test package (bundle_test) on purpose: sim/southbound
// imports internal/evidence/bundle, so an internal test importing the sim would
// be an import cycle. The dependency runs one way — a fixture describes itself
// in the evidence package's terms — and this file is the only place the two are
// compiled together.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
	sim "csip-tls-test/sim/southbound"
)

// The sentences, verbatim. A change to any of them is a change to what a
// reviewer reads on the face of an evidence bundle, and must be made here,
// deliberately, in the same commit as the change to the renderer.
const (
	wallLabel     = "wall"
	scaled900     = "scaled 900× (ACCELERATED TEST TIME — proves this harness's expiry semantics, NOT any real device's timing)"
	scaled10000   = "scaled 1e+04× (ACCELERATED TEST TIME — proves this harness's expiry semantics, NOT any real device's timing)"
	manualAtStart = "manual (ACCELERATED TEST TIME, t+0.000s — proves this harness's expiry semantics, NOT any real device's timing)"
	manualAt1500  = "manual (ACCELERATED TEST TIME, t+1.500s — proves this harness's expiry semantics, NOT any real device's timing)"
)

// THE ROW THE GATE'S MUTATION TURNS RED. Rewriting ScaledTimebase.Label() —
// or bundle.Timebase.Render, which is where the words now live — fails here.
func TestFixtureTimebaseLabelsArePinned(t *testing.T) {
	if got := sim.WallTimebase().Label(); got != wallLabel {
		t.Errorf("wall clock labels itself %q, want %q — a fixture that cannot say it ran on real time "+
			"is as broken as one that cannot say it did not", got, wallLabel)
	}
	if got := sim.NewScaledTimebase(900).Label(); got != scaled900 {
		t.Errorf("a 900× clock labels itself\n  %q\nwant\n  %q", got, scaled900)
	}
	// 10 000× is the scale sim/southbound's own reversion-loop test uses, and
	// it pins the %.4g rendering, which is the one part of this sentence a
	// reader could mistake for a typo.
	if got := sim.NewScaledTimebase(10000).Label(); got != scaled10000 {
		t.Errorf("a 10 000× clock labels itself\n  %q\nwant\n  %q", got, scaled10000)
	}

	man := sim.NewManualTimebase()
	if got := man.Label(); got != manualAtStart {
		t.Errorf("a fresh manual clock labels itself\n  %q\nwant\n  %q", got, manualAtStart)
	}
	man.Advance(1500 * 1000 * 1000)
	if got := man.Label(); got != manualAt1500 {
		t.Errorf("a manual clock advanced 1.5 s labels itself\n  %q\nwant\n  %q", got, manualAt1500)
	}
	for _, l := range []string{scaled900, scaled10000, manualAtStart, manualAt1500} {
		if !strings.Contains(l, "ACCELERATED TEST TIME") {
			t.Errorf("%q does not warn the reader it is not real time", l)
		}
	}
}

// The structural half: a fixture's label is a PROJECTION of its declaration, so
// the two cannot be made to disagree without editing the evidence package
// itself — and the declaration is one the verifier accepts.
func TestFixtureDeclarationsAreSelfConsistentAndVerifiable(t *testing.T) {
	man := sim.NewManualTimebase()
	man.Advance(1500 * 1000 * 1000)
	for _, tb := range []sim.ReversionTimebase{
		sim.WallTimebase(),
		sim.NewScaledTimebase(900),
		man,
	} {
		d := tb.Declare()
		if err := d.Check(); err != nil {
			t.Errorf("%s: the fixture's own declaration does not verify: %v", d.Kind, err)
		}
		if d.Label != tb.Label() {
			t.Errorf("%s: /state says %q, the bundle would carry %q — the label must be the "+
				"declaration's, or the two can drift apart", d.Kind, tb.Label(), d.Label)
		}
		if d.Label != d.Render() {
			t.Errorf("%s: label %q is not what its own numbers render as (%q)", d.Kind, d.Label, d.Render())
		}
		if d.Component == "" {
			t.Errorf("%s: the declaration does not say whose clock it is", d.Kind)
		}
	}
	if !sim.NewScaledTimebase(900).Declare().Accelerated() {
		t.Error("a 900× clock declares itself un-accelerated")
	}
	if sim.WallTimebase().Declare().Accelerated() {
		t.Error("the wall clock declares itself accelerated")
	}
}

// The one call a bundle-producing run makes, end to end: the clock the run
// installed lands in the builder, with the provenance the recorder supplied.
func TestRecordTimebasePutsTheFixtureClockInTheBundle(t *testing.T) {
	b := bundle.NewBuilder(bundle.RunMeta{Tool: "pin-test"})
	sim.RecordTimebase(b, sim.NewScaledTimebase(900), "in-process handle to the pack under test")
	sim.RecordTimebase(b, nil, "a run that installed no clock")

	ts := b.Timebases()
	if len(ts) != 1 {
		t.Fatalf("recorded %d declaration(s), want 1 — a nil timebase must record nothing rather than "+
			"assert a wall clock nobody claimed", len(ts))
	}
	if ts[0].Label != scaled900 {
		t.Errorf("recorded label = %q", ts[0].Label)
	}
	if ts[0].Source != "in-process handle to the pack under test" {
		t.Errorf("recorded source = %q", ts[0].Source)
	}
	if ts[0].Component != sim.TimebaseComponent {
		t.Errorf("recorded component = %q, want %q", ts[0].Component, sim.TimebaseComponent)
	}
	if err := ts[0].Check(); err != nil {
		t.Errorf("the recorded declaration does not verify: %v", err)
	}
}
