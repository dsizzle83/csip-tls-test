package invariant

// legacyctl_test.go — the model-123 transcription, the disagreement it found,
// and the agreement that replaced it.
//
// Three tests that must all hold. The first proves this referee's transcription
// is the model SunSpec publishes, by stating the point sequence a SECOND time as
// a literal — the same two-independent-statements discipline suitecsip's
// legacyExpectations applies to curve breakpoints, and for the same reason: a
// transcription checked against itself is not checked.
//
// The second used to pin a DISAGREEMENT with lexa-proto's constants as a live
// finding. lexa-proto 32150e1 fixed the map, so it is inverted: the two
// independently-maintained transcriptions must now AGREE at every point, and a
// silent re-divergence on either side fails here.
//
// The third is what keeps the second honest. An agreement assertion is
// satisfied by a checker that always answers "they agree", so the map that
// actually shipped wrong is kept as a would-have-caught record and fed back in;
// the checker must report all 24 of its points. Agreement on the live map and
// disagreement on the historical one — neither half means anything alone.

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
	// The lookup the comparison functions actually run on is the same statement
	// a third time, and it is the one that decides verdicts — so it is checked
	// rather than trusted. (The generation-1 record's own Published column is
	// checked in TestM123_TheRefereeWouldHaveCaughtGeneration1, where it is
	// used.)
	for name, off := range m123PublishedOffsets() {
		if off < 0 || off >= len(publishedM123Points) {
			t.Errorf("m123PublishedOffsets puts %s at %d, outside the published block", name, off)
			continue
		}
		if got := publishedM123Points[off]; got != name {
			t.Errorf("m123PublishedOffsets puts %s at offset %d; the published model holds %s there",
				name, off, got)
		}
	}
}

// TestM123_LexaProtoOffsetsAgreeWithThePublishedModel is the AGREEMENT PIN, and
// it is the inversion of a test that used to assert the opposite.
//
// Until 2026-08-15 this file carried
// TestM123_LexaProtoOffsetsDisagreeWithThePublishedModel, which pinned a real
// finding: lexa-proto's hand-written M123_* constants named a different register
// at every one of the model's 24 points, the bench sim was built from the same
// constants so nothing could see it, and the failsafe CEASE path wrote a timer
// register believing it was Conn. lexa-proto 32150e1 fixed the map (vendored
// here at 04a0409) and this repo's fixture half landed with it.
//
// The finding is closed, so the assertion INVERTS rather than being deleted:
// two independently-maintained transcriptions — this referee's, written from
// the vendored JSON in legacyctl.go, and lexa-proto's own — must now agree at
// every point. That is a stronger statement than the old one and it is the
// statement the heal has to keep true; a silent re-divergence on either side is
// exactly what the original defect was.
func TestM123_LexaProtoOffsetsAgreeWithThePublishedModel(t *testing.T) {
	if rows := M123Disagreements(m123ShippingOffsets()); len(rows) != 0 {
		t.Errorf("this referee's transcription and lexa-proto's M123_* constants disagree at %d point(s), "+
			"which is the defect lexa-proto 32150e1 closed re-opening:\n  %s",
			len(rows), strings.Join(rows, "\n  "))
	}
	// The two safety-relevant offsets, named individually so a failure says the
	// consequence rather than only the arithmetic.
	if sunspec.M123_Conn != m123Conn {
		t.Errorf("lexa-proto's M123_Conn is %d and the published model holds Conn at %d. This is the "+
			"register the failsafe CEASE writes on a 704-less pack: at the wrong offset the pack STAYS "+
			"ENERGIZED and the L1 echo proof, which re-reads the offset it just wrote, reports the "+
			"disconnect as PROVEN", sunspec.M123_Conn, m123Conn)
	}
	if sunspec.M123_WMaxLimPct != m123WMaxLimPct {
		t.Errorf("lexa-proto's M123_WMaxLimPct is %d and the published model holds it at %d. At the old "+
			"offset 0 a 60.00 %% ceiling (raw 6000 at SF -2) landed on Conn_WinTms and became a "+
			"6000-second connect window, curtailing nothing", sunspec.M123_WMaxLimPct, m123WMaxLimPct)
	}

	// A THIRD derivation, now that lexa-proto ships one. L123 is built against
	// the same vendored JSON this file transcribes by hand, so it is an
	// independent statement of the same fact by a different mechanism — and
	// checking it is nearly free. The constants are proven against L123 in
	// lexa-proto's own suite; this closes the ring from the referee's side.
	for name, want := range m123PublishedOffsets() {
		if !sunspec.L123.Has(name) {
			t.Errorf("sunspec.L123 declares no point named %q, which this referee reads at offset %d",
				name, want)
			continue
		}
		if got := sunspec.L123.Offset(name); got != want {
			t.Errorf("sunspec.L123 places %s at offset %d; this referee reads it at %d", name, got, want)
		}
	}

	if s := DescribeM123Divergence(); s != "" {
		t.Errorf("the transcription caveat is still being emitted onto every legacy verdict:\n  %s", s)
	}
	if s := DescribeM123DivergenceFull(); s != "" {
		t.Errorf("the full transcription table is still being emitted:\n  %s", s)
	}
}

// TestM123_TheRefereeWouldHaveCaughtGeneration1 is the other half of the pin,
// and without it the half above proves nothing.
//
// An agreement assertion is satisfied by a checker that always answers "they
// agree". The only map anyone is CERTAIN this checker must catch is the one
// that actually shipped, so it is fed back in and the disagreement must be
// reported — all 24 points of it, including the two whose consequences were
// safety-relevant, and including the point generation 1 invented
// (M123_Conn_RmpTms, which model 123 does not have).
func TestM123_TheRefereeWouldHaveCaughtGeneration1(t *testing.T) {
	if len(M123Generation1) != M123PublishedLen {
		t.Fatalf("the generation-1 record describes %d offsets; the published model has %d",
			len(M123Generation1), M123PublishedLen)
	}
	// The record's Published column is this file's independent transcription
	// stated a third time, so it is checked rather than trusted.
	for _, d := range M123Generation1 {
		if d.Offset < 0 || d.Offset >= len(publishedM123Points) {
			t.Errorf("the generation-1 record names offset %d, outside the published block", d.Offset)
			continue
		}
		if got := publishedM123Points[d.Offset]; got != d.Published {
			t.Errorf("the generation-1 record says offset %d holds %q; the published model holds %q",
				d.Offset, d.Published, got)
		}
	}

	// Rebuild generation 1 as an offset map and run the live checker over it.
	// Each entry says "the constant named X had THIS offset's value", so the
	// map is {stripped constant name -> offset}.
	gen1 := map[string]int{}
	for _, d := range M123Generation1 {
		name := strings.TrimPrefix(strings.SplitN(d.Generation1, " ", 2)[0], "M123_")
		if name == "" || strings.HasPrefix(d.Generation1, "(") {
			continue // offset 23: generation 1 declared no register there
		}
		gen1[name] = d.Offset
	}
	// Generation 1 spelled the enable M123_WMaxLimPct_Ena where the model says
	// WMaxLim_Ena — the same spelling lexa-proto still keeps — so the same
	// mapping the live comparison applies is applied here, or the check would
	// "catch" a rename instead of a relocation.
	if off, ok := gen1["WMaxLimPct_Ena"]; ok {
		gen1["WMaxLim_Ena"] = off
		delete(gen1, "WMaxLimPct_Ena")
	}

	rows := M123Disagreements(gen1)
	if len(rows) == 0 {
		t.Fatal("the referee finds NO disagreement with the map that shipped wrong at every point. The " +
			"agreement pin above is then worthless: a checker that reports agreement with everything " +
			"reports it with the live map too")
	}
	if len(rows) != len(m123PublishedOffsets()) {
		t.Errorf("the referee catches %d of %d generation-1 points; it was wrong at every one",
			len(rows), len(m123PublishedOffsets()))
	}
	for _, want := range []string{"Conn is at published offset 2", "WMaxLimPct is at published offset 3"} {
		found := false
		for _, r := range rows {
			if strings.HasPrefix(r, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the would-have-caught record does not name %q — one of the two points whose "+
				"misplacement was a safety property", want)
		}
	}
	t.Logf("the referee, pointed at the map that shipped, catches all %d points; the two that mattered:\n"+
		"  %s\n  %s", len(rows), rows[2], rows[3])
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
	// has no 704 commands.
	//
	// The namespacing below is now MORE load-bearing, not less. suitecsip's
	// ceiling oracle reads BOTH generations (ceilingHomeOf, H-B 2026-08-17), and
	// it distinguishes them by exactly this: it resolves a home — a point name
	// AND the command slice that name is selected from — and a legacy ceiling
	// named bare "WMaxLimPct" would let a 7xx selection match a legacy register
	// (or the reverse) whenever a device served both, which the advanced sims
	// do. Two readings, two names, no accidental match.
	if cmds := uv.Commands("src"); len(cmds) != 0 {
		t.Errorf("a 123-only unit decoded %d model-704 command(s); the two surfaces must stay separate", len(cmds))
	}
	for _, c := range lc.Commands {
		if c.Point == "WMaxLimPct" {
			t.Error("the legacy ceiling is named WMaxLimPct unqualified — the 7xx arm of the ceiling " +
				"oracle selects that bare name and would judge this register under model 704's semantics")
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
