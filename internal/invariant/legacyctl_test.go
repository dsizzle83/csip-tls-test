package invariant

// legacyctl_test.go — the model-123 transcription, and the disagreement it
// found.
//
// The tests below are in two halves that must both hold. The first proves this
// referee's transcription is the model SunSpec publishes, by stating the point
// sequence a SECOND time as a literal — the same two-independent-statements
// discipline suitecsip's legacyExpectations applies to curve breakpoints, and
// for the same reason: a transcription checked against itself is not checked.
// The second pins the disagreement with lexa-proto's shipping constants AS A
// FACT, computed from the constants themselves, so the day the product
// reconciles model 123 against the vendored JSON this file fails and forces the
// reconciliation to be noticed rather than silently absorbed.

import (
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

// publishedM123Points is SunSpec model 123's data-block point sequence, stated
// independently of legacyctl.go's offset constants.
//
// Source: github.com/sunspec/models, json/model_123.json, pinned commit
// 7abdf8982d5364f8ae916deee18aac86c11be36d, vendored at lexa-proto
// docs/schema/sunspec-models/model_123.json. The ID and L header words are
// excluded, because every decoder in this package consumes the DATA block that
// sunspec.Reader.ReadModel returns.
var publishedM123Points = []string{
	"Conn_WinTms",        // 0
	"Conn_RvrtTms",       // 1
	"Conn",               // 2
	"WMaxLimPct",         // 3
	"WMaxLimPct_WinTms",  // 4
	"WMaxLimPct_RvrtTms", // 5
	"WMaxLimPct_RmpTms",  // 6
	"WMaxLim_Ena",        // 7
	"OutPFSet",           // 8
	"OutPFSet_WinTms",    // 9
	"OutPFSet_RvrtTms",   // 10
	"OutPFSet_RmpTms",    // 11
	"OutPFSet_Ena",       // 12
	"VArWMaxPct",         // 13
	"VArMaxPct",          // 14
	"VArAvalPct",         // 15
	"VArPct_WinTms",      // 16
	"VArPct_RvrtTms",     // 17
	"VArPct_RmpTms",      // 18
	"VArPct_Mod",         // 19
	"VArPct_Ena",         // 20
	"WMaxLimPct_SF",      // 21
	"OutPFSet_SF",        // 22
	"VArPct_SF",          // 23
}

// TestM123_ThisRefereesOffsetsAreThePublishedModel checks legacyctl.go's
// constants against the independent statement above.
func TestM123_ThisRefereesOffsetsAreThePublishedModel(t *testing.T) {
	if len(publishedM123Points) != M123PublishedLen {
		t.Fatalf("the published model has %d data points and M123PublishedLen says %d",
			len(publishedM123Points), M123PublishedLen)
	}
	for _, tc := range []struct {
		off  int
		name string
	}{
		{m123ConnWinTms, "Conn_WinTms"},
		{m123ConnRvrtTms, "Conn_RvrtTms"},
		{m123Conn, "Conn"},
		{m123WMaxLimPct, "WMaxLimPct"},
		{m123WMaxLimPctWinTms, "WMaxLimPct_WinTms"},
		{m123WMaxLimPctRvrtTms, "WMaxLimPct_RvrtTms"},
		{m123WMaxLimPctRmpTms, "WMaxLimPct_RmpTms"},
		{m123WMaxLimEna, "WMaxLim_Ena"},
		{m123OutPFSet, "OutPFSet"},
		{m123OutPFSetEna, "OutPFSet_Ena"},
		{m123VArWMaxPct, "VArWMaxPct"},
		{m123VArMaxPct, "VArMaxPct"},
		{m123VArAvalPct, "VArAvalPct"},
		{m123VArPctMod, "VArPct_Mod"},
		{m123VArPctEna, "VArPct_Ena"},
		{m123WMaxLimPctSF, "WMaxLimPct_SF"},
		{m123OutPFSetSF, "OutPFSet_SF"},
		{m123VArPctSF, "VArPct_SF"},
	} {
		if got := publishedM123Points[tc.off]; got != tc.name {
			t.Errorf("this referee reads %s at data-block offset %d; the published model holds %s there",
				tc.name, tc.off, got)
		}
	}
	// M123Divergence's Published column is the same statement a third time, and
	// it is what a bundle quotes — so it is checked too rather than trusted.
	if len(M123Divergence) != M123PublishedLen {
		t.Fatalf("M123Divergence describes %d offsets; the published model has %d",
			len(M123Divergence), M123PublishedLen)
	}
	for _, d := range M123Divergence {
		if d.Offset < 0 || d.Offset >= len(publishedM123Points) {
			t.Errorf("M123Divergence names offset %d, outside the published block", d.Offset)
			continue
		}
		if got := publishedM123Points[d.Offset]; got != d.Published {
			t.Errorf("M123Divergence says offset %d holds %q; the published model holds %q",
				d.Offset, d.Published, got)
		}
	}
}

// TestM123_LexaProtoOffsetsDisagreeWithThePublishedModel is the FINDING, pinned.
//
// It asserts that lexa-proto's hand-written M123_* constants name a different
// register at every offset than the model SunSpec publishes. It passes today,
// which is the uncomfortable part and the point: the disagreement is real, it
// reaches a flashed image, and a test that merely failed here would be deleted
// or skipped by whoever ran the gate next. Pinned instead, it says exactly what
// is wrong, and it BREAKS the moment either side moves — which is when someone
// has to look.
//
// What is wrong, concretely (see M123Divergence's own doc for the citations):
// the product's failsafe CEASE for a 704-less pack writes offset 16 believing
// it is Conn; a conformant device holds VArPct_WinTms there, the pack stays
// energized, and because the plan's L1 proof re-reads the offset it just wrote,
// the echo matches and a disconnect that never happened is reported as proven.
//
// Nothing on either bench catches it because sim/southbound builds its model-123
// block from the same constants: the fixture and the product agree with each
// other and both disagree with the standard.
func TestM123_LexaProtoOffsetsDisagreeWithThePublishedModel(t *testing.T) {
	// The shipping transcription, read from the constants themselves so this
	// cannot drift from what the product actually compiles against.
	shipping := map[int]string{
		sunspec.M123_WMaxLimPct:         "M123_WMaxLimPct",
		sunspec.M123_WMaxLimPct_WinTms:  "M123_WMaxLimPct_WinTms",
		sunspec.M123_WMaxLimPct_RvrtTms: "M123_WMaxLimPct_RvrtTms",
		sunspec.M123_WMaxLimPct_RmpTms:  "M123_WMaxLimPct_RmpTms",
		sunspec.M123_WMaxLimPct_Ena:     "M123_WMaxLimPct_Ena",
		sunspec.M123_OutPFSet:           "M123_OutPFSet",
		sunspec.M123_OutPFSet_WinTms:    "M123_OutPFSet_WinTms",
		sunspec.M123_OutPFSet_RvrtTms:   "M123_OutPFSet_RvrtTms",
		sunspec.M123_OutPFSet_RmpTms:    "M123_OutPFSet_RmpTms",
		sunspec.M123_OutPFSet_Ena:       "M123_OutPFSet_Ena",
		sunspec.M123_VArPct_Mod:         "M123_VArPct_Mod",
		sunspec.M123_VArPct:             "M123_VArPct",
		sunspec.M123_VArPct_WinTms:      "M123_VArPct_WinTms",
		sunspec.M123_VArPct_RvrtTms:     "M123_VArPct_RvrtTms",
		sunspec.M123_VArPct_RmpTms:      "M123_VArPct_RmpTms",
		sunspec.M123_VArPct_Ena:         "M123_VArPct_Ena",
		sunspec.M123_Conn:               "M123_Conn",
		sunspec.M123_Conn_WinTms:        "M123_Conn_WinTms",
		sunspec.M123_Conn_RvrtTms:       "M123_Conn_RvrtTms",
		sunspec.M123_Conn_RmpTms:        "M123_Conn_RmpTms",
		sunspec.M123_WMaxLimPct_SF:      "M123_WMaxLimPct_SF",
		sunspec.M123_OutPFSet_SF:        "M123_OutPFSet_SF",
		sunspec.M123_VArPct_SF:          "M123_VArPct_SF",
	}

	// THE TWO SAFETY-RELEVANT ONES, named individually so a reader of a failure
	// sees the consequence and not only the arithmetic.
	if sunspec.M123_Conn == m123Conn {
		t.Fatalf("lexa-proto's M123_Conn now agrees with the published model (offset %d). THE FINDING "+
			"THIS TEST PINS HAS BEEN FIXED — delete this test, delete M123Divergence, and re-check every "+
			"sim/southbound M123 fixture, which was built from the OLD offsets and is now the thing that "+
			"disagrees with the standard", m123Conn)
	}
	if sunspec.M123_Conn != 16 {
		t.Errorf("lexa-proto's M123_Conn is %d; this finding was recorded against 16, where a conformant "+
			"model 123 holds %s. The constant has MOVED without this pin being updated",
			sunspec.M123_Conn, publishedM123Points[16])
	}
	if sunspec.M123_WMaxLimPct != 0 {
		t.Errorf("lexa-proto's M123_WMaxLimPct is %d; this finding was recorded against 0, where a "+
			"conformant model 123 holds %s", sunspec.M123_WMaxLimPct, publishedM123Points[0])
	}

	// And every point, so a partial fix cannot slip through as "still diverged".
	agreements := 0
	for _, d := range M123Divergence {
		got, ok := shipping[d.Offset]
		if !ok {
			// Offset 23: the shipping block is 23 registers long and declares
			// nothing there. M123Divergence says so in its own Shipping text.
			if !strings.Contains(d.Shipping, "no register") {
				t.Errorf("offset %d: no shipping constant names it and M123Divergence does not say so "+
					"(it says %q)", d.Offset, d.Shipping)
			}
			continue
		}
		if got != strings.SplitN(d.Shipping, " ", 2)[0] {
			t.Errorf("offset %d: M123Divergence records the shipping constant as %q; the constants "+
				"themselves put %s there", d.Offset, d.Shipping, got)
		}
		if d.Published == got {
			agreements++
		}
	}
	if agreements != 0 {
		t.Errorf("%d offset(s) now agree between the published model and the shipping constants; this "+
			"pin was written against total disagreement and must be re-derived", agreements)
	}

	// The summary form rides on every legacy reading, so it must name the
	// safety-relevant offset — and the literal it names must be the constant
	// the product actually compiles against, or a bundle would carry a
	// confidently wrong sentence.
	if shippingConnOffset != sunspec.M123_Conn {
		t.Errorf("the summary sentence names offset %d as the shipping writer's Conn; the constant says "+
			"%d. A bundle would be carrying a wrong number about a safety path",
			shippingConnOffset, sunspec.M123_Conn)
	}
	s := DescribeM123Divergence()
	if s == "" {
		t.Fatal("DescribeM123Divergence returned nothing while the transcriptions still disagree")
	}
	if !strings.Contains(s, "failsafe CEASE") {
		t.Errorf("the summary does not name the consequence, so a reader has no reason to act on it:\n  %s", s)
	}
	full := DescribeM123DivergenceFull()
	if len(full) <= len(s) {
		t.Errorf("the full form (%d chars) is no longer than the summary (%d); the split exists so a "+
			"verdict carries the sentence and a report carries the table", len(full), len(s))
	}
	t.Logf("the summary, as every legacy verdict carries it:\n  %s", s)
	t.Logf("the full table, as a finding quotes it once:\n  %s", full)
}

// m123Block builds a published-shape model-123 data block.
//
// The scale factor goes in through fixture_test.go's sfReg rather than a
// `uint16(int16(-2))` conversion: on an untyped constant that is a compile
// error, because constant conversions are range-checked, so the value has to
// travel through a variable to reach the two's-complement bit pattern a device
// actually serves.
func m123Block(mutate func(r []uint16)) []uint16 {
	r := make([]uint16, M123PublishedLen)
	r[m123Conn] = 1
	r[m123WMaxLimPct] = 10000
	r[m123WMaxLimEna] = 1
	r[m123WMaxLimPctSF] = sfReg(-2)
	if mutate != nil {
		mutate(r)
	}
	return r
}

func TestDecodeLegacyControls_PublishedBlock(t *testing.T) {
	lc := DecodeLegacyControls("test", m123Block(nil))
	if !lc.Present || lc.Shape != M123Published {
		t.Fatalf("shape = %q present = %v, want a published-shape reading", lc.Shape, lc.Present)
	}
	if lc.Note != "" {
		t.Errorf("a published block carries a note it should not: %s", lc.Note)
	}
	byPoint := map[string]Command{}
	for _, c := range lc.Commands {
		byPoint[c.Point] = c
	}
	conn, ok := byPoint[PointM123Conn]
	if !ok {
		t.Fatal("no M123.Conn was decoded")
	}
	if !conn.Enabled || conn.Raw.Val != 1 {
		t.Errorf("M123.Conn = %v enabled=%v, want the connected register 1", conn.Raw, conn.Enabled)
	}
	lim, ok := byPoint[PointM123WMaxLimPct]
	if !ok {
		t.Fatal("no M123.WMaxLimPct was decoded")
	}
	// 10000 at 10^-2 is 100.00 percent — the ceiling the bench fixture holds.
	if lim.Raw.Unit != UnitPercent || lim.Raw.Val != 100 {
		t.Errorf("M123.WMaxLimPct = %v, want 100 %% (10000 scaled by WMaxLimPct_SF = -2)", lim.Raw)
	}
	if !lim.Enabled || lim.Ref != RefWMax {
		t.Errorf("M123.WMaxLimPct enabled=%v ref=%q, want enabled against WMax", lim.Enabled, lim.Ref)
	}
}

// TestDecodeLegacyControls_ShortBlockIsNamedNotGuessed covers the shape the
// BENCH actually serves today: 23 data registers, the shipping transcription's
// own length. The points this referee names still have registers, so it reads
// them — and it says, on the reading, that the block is not the published model.
func TestDecodeLegacyControls_ShortBlockIsNamedNotGuessed(t *testing.T) {
	lc := DecodeLegacyControls("test", m123Block(nil)[:23])
	if lc.Shape != M123Short {
		t.Fatalf("shape = %q, want %q for a 23-register block", lc.Shape, M123Short)
	}
	if lc.Note == "" {
		t.Fatal("a short block was decoded with no note; a reader would take it for the published model")
	}
	for _, c := range lc.Commands {
		if c.Point != PointM123WMaxLimPct {
			continue
		}
		if c.Unresolved == "" {
			t.Error("the ceiling was scaled on a block too short to hold WMaxLimPct_SF; the scale " +
				"factor would have been read out of a register holding something else")
		}
		if c.Raw.Unit == UnitPercent {
			t.Errorf("the ceiling reads %v — a percentage — on a block with no scale factor", c.Raw)
		}
	}
	t.Logf("the short-block note:\n  %s", lc.Note)
}

func TestDecodeLegacyControls_TruncatedAndAbsentAreDifferentAnswers(t *testing.T) {
	if lc := DecodeLegacyControls("test", nil); lc.Present || lc.Shape != M123Absent {
		t.Errorf("an unserved model decodes as present=%v shape=%q, want absent", lc.Present, lc.Shape)
	}
	lc := DecodeLegacyControls("test", make([]uint16, 3))
	if lc.Shape != M123Truncated {
		t.Errorf("a 3-register block decodes as %q, want %q", lc.Shape, M123Truncated)
	}
	if !lc.Present {
		t.Error("a truncated block is still a block the device SERVED; reporting it absent would " +
			"lose the difference between a device that has no model 123 and one whose block is broken")
	}
	if len(lc.Commands) != 0 {
		t.Errorf("a truncated block decoded %d command(s); it must decode none", len(lc.Commands))
	}
}

func TestDecodeLegacyControls_UnimplementedConnIsNotAValue(t *testing.T) {
	lc := DecodeLegacyControls("test", m123Block(func(r []uint16) { r[m123Conn] = 0xFFFF }))
	for _, c := range lc.Commands {
		if c.Point != PointM123Conn {
			continue
		}
		if c.Enabled {
			t.Error("an unimplemented Conn (0xFFFF) reported as enabled")
		}
		if c.Unresolved == "" {
			t.Error("an unimplemented Conn was decoded as a connect state; 0xFFFF is the SunSpec " +
				"not-implemented sentinel and reading it as 65535 would invent a state")
		}
	}
}

func TestDecodeLegacyControls_CorruptScaleFactorRefusesToScale(t *testing.T) {
	lc := DecodeLegacyControls("test", m123Block(func(r []uint16) {
		r[m123WMaxLimPctSF] = sfReg(-20) // outside the sunssf domain
	}))
	for _, c := range lc.Commands {
		if c.Point != PointM123WMaxLimPct {
			continue
		}
		if c.Unresolved == "" {
			t.Error("an out-of-domain WMaxLimPct_SF was applied; a hostile scale factor must never be " +
				"laundered into a plausible percentage (LXR-004)")
		}
	}
}

// TestLegacyFingerprint_MovesWhenAnyRegisterMoves is the property the refusal
// rows rest on. It covers the registers this referee does NOT name on purpose:
// the writer under test uses a different register map, so the register a
// refused axis lands on may be one no point of this decoder reads.
func TestLegacyFingerprint_MovesWhenAnyRegisterMoves(t *testing.T) {
	base, ok := DecodeLegacyControls("test", m123Block(nil)).Fingerprint()
	if !ok {
		t.Fatal("a served model-123 block produced no fingerprint")
	}
	for _, tc := range []struct {
		what string
		off  int
		val  uint16
	}{
		{"the connect register", m123Conn, 0},
		{"the active-power ceiling", m123WMaxLimPct, 6000},
		{"the ceiling's enable", m123WMaxLimEna, 0},
		// The unnamed ones. Offset 16 is where the shipping writer puts a
		// commanded DISCONNECT; a conformant device holds VArPct_WinTms there,
		// and a fingerprint blind to it would certify a clean refusal over the
		// exact write this bench most needs to see.
		{"VArPct_WinTms — where the shipping writer's disconnect lands", 16, 1},
		{"a reactive percentage this referee names no command for", m123VArMaxPct, 500},
		{"the connect window", m123ConnWinTms, 30},
	} {
		off, val := tc.off, tc.val
		got, ok := DecodeLegacyControls("test", m123Block(func(r []uint16) { r[off] = val })).Fingerprint()
		if !ok {
			t.Fatalf("%s: the mutated block produced no fingerprint", tc.what)
		}
		if got == base {
			t.Errorf("%s moved (offset %d -> %d) and the fingerprint did not change; a refusal row "+
				"would certify that nothing landed", tc.what, off, val)
		}
	}
}

func TestUnitView_LegacyCommands_ReadsTheModel123Slot(t *testing.T) {
	uv := UnitView{Unit: 1, Regs: map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123Block(nil)}}
	lc := uv.LegacyCommands("src")
	if !lc.Present || len(lc.Commands) != 2 {
		t.Fatalf("LegacyCommands present=%v commands=%d, want a two-point reading", lc.Present, len(lc.Commands))
	}
	if !strings.Contains(lc.Source, "M123") || !strings.Contains(lc.Source, "unit 1") {
		t.Errorf("the reading's source is %q; it must name the unit and the model it came from", lc.Source)
	}
	// The 704 decoder must be untouched by this: a unit serving only model 123
	// has no 704 commands, and a caller selecting "WMaxLimPct" by bare name
	// (oracleMaxLimW does) must not pick up the legacy point.
	if cmds := uv.Commands("src"); len(cmds) != 0 {
		t.Errorf("a 123-only unit decoded %d model-704 command(s); the two surfaces must stay separate", len(cmds))
	}
	for _, c := range lc.Commands {
		if c.Point == "WMaxLimPct" {
			t.Error("the legacy ceiling is named WMaxLimPct unqualified — oracleMaxLimW selects that " +
				"bare name and would judge it under model 704's semantics")
		}
	}
}

func TestModelsOfInterest_IncludesTheLegacyControlSurface(t *testing.T) {
	for _, m := range modelsOfInterest {
		if m == sunspec.ModelImmediateCtrl {
			return
		}
	}
	t.Fatal("model 123 is not read by the register sources, so UnitView.LegacyCommands can only ever " +
		"report absent and the legacy refusal fingerprint is unmeasurable again")
}
