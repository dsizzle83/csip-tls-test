package suitecsip

// m123_fixture_test.go — the test whose ABSENCE let a wrong register map live
// in three repos at once.
//
// Model 123 was hand-transcribed and wrong at every one of its 24 points, and
// nothing caught it for one reason: the bench sim built its own model-123 block
// from the SAME constants the product wrote through. Fixture and product agreed
// with each other and both disagreed with the standard, so every test that
// exercised the pair passed. The referee could not see it either, because
// internal/invariant deliberately SHARES lexa-proto's layout tables — and model
// 123 had no layout table, only the constants.
//
// The test that closes that class is not a test of the product and not a test
// of the referee. It is a test of the FIXTURE, asserting the bench's own device
// image against the published model through the referee's independent
// transcription — two derivations that can disagree, over the register image a
// row actually reads.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/invariant"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/sunspec"
)

// TestLegacySimServesThePublishedModel123 reads the bench's own legacy DER and
// requires its model-123 block to be the model SunSpec publishes.
//
// It reads through internal/invariant's own transcription (legacyctl.go), which
// is derived from the vendored JSON independently of lexa-proto's constants —
// so a disagreement between the two is a real finding and not a tautology.
func TestLegacySimServesThePublishedModel123(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})
	uv := f.unitView(t)

	regs := uv.Regs[sunspec.ModelImmediateCtrl]
	if len(regs) == 0 {
		t.Fatal("the legacy DER sim serves no model 123 at all, so the legacy scalar control surface " +
			"has no register on this bench and BASIC-009/014's legacy arms are unmeasurable")
	}
	t.Logf("the bench's own M123 data block, %d registers: %v", len(regs), regs)

	if len(regs) != invariant.M123PublishedLen {
		t.Errorf("the sim declares %d model-123 data registers; the published model has %d "+
			"(SunSpec models @ 7abdf89, json/model_123.json). A block of the wrong LENGTH is the "+
			"signature of a hand-transcribed map: the old one collapsed the mode-selected reactive trio "+
			"VArWMaxPct/VArMaxPct/VArAvalPct into a single point and lost a register doing it",
			len(regs), invariant.M123PublishedLen)
	}

	lc := uv.LegacyCommands(oracleSimName)
	if lc.Shape != invariant.M123Published {
		t.Errorf("the referee reads the sim's block as shape %q, want %q: %s",
			lc.Shape, invariant.M123Published, lc.Note)
	}

	// THE VALUES, not just the geometry. A block of the right LENGTH whose
	// points sit in the wrong ORDER reads as a device holding zeros in every
	// register the fixture meant to populate — which is exactly what the old
	// map produced when read through the published offsets, and exactly what a
	// length-only assertion would wave through.
	byPoint := map[string]invariant.Command{}
	for _, c := range lc.Commands {
		byPoint[c.Point] = c
	}

	conn, ok := byPoint[invariant.PointM123Conn]
	if !ok {
		t.Fatal("the referee decoded no connect point from the sim's block")
	}
	if !conn.Enabled || conn.Raw.Val != 1 {
		t.Errorf("the sim's M123 Conn reads %v (enabled=%v); the fixture sets the DER CONNECTED, so a "+
			"reading of 0 here means the referee and the fixture disagree about where Conn lives — "+
			"which is the whole defect, seen from the bench side", conn.Raw, conn.Enabled)
	}

	lim, ok := byPoint[invariant.PointM123WMaxLimPct]
	if !ok {
		t.Fatal("the referee decoded no active-power ceiling from the sim's block")
	}
	// The fixture sets 10000 at SF -2 = 100.00 %, its "no curtailment" resting
	// state, with the enable set.
	if lim.Raw.Unit != invariant.UnitPercent || lim.Raw.Val != 100 {
		t.Errorf("the sim's M123 WMaxLimPct reads %v; the fixture sets raw 10000 at WMaxLimPct_SF=-2 = "+
			"100.00 %%. A zero here means the ceiling and its scale factor were read from registers the "+
			"fixture never wrote", lim.Raw)
	}
	if !lim.Enabled {
		t.Errorf("the sim's M123 WMaxLim_Ena reads clear; the fixture sets it. Reading the enable from " +
			"the wrong offset is how a live ceiling reports as an unarmed one")
	}
	if lim.Unresolved != "" {
		t.Errorf("the ceiling did not resolve: %s", lim.Unresolved)
	}

	t.Logf("the referee's reading of the bench's own M123:\n  %s", strings.Join(commandLines(lc), "\n  "))
}

// commandLines renders a legacy reading one point per line, for a log a reader
// can compare against the fixture by eye.
func commandLines(lc invariant.LegacyControls) []string {
	out := make([]string, 0, len(lc.Commands))
	for _, c := range lc.Commands {
		state := "disabled"
		if c.Enabled {
			state = "ENABLED"
		}
		line := c.Point + "=" + c.Raw.String() + " (" + state + ")"
		if c.Unresolved != "" {
			line += " UNRESOLVED: " + c.Unresolved
		}
		out = append(out, line)
	}
	return out
}
