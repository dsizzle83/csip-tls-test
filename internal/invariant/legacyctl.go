package invariant

// legacyctl.go — SunSpec model 123 (Immediate Inverter Controls): the LEGACY
// generation's entire scalar control surface, transcribed INDEPENDENTLY of the
// product and read as a fingerprintable view.
//
// ── Why this file exists at all ─────────────────────────────────────────────
//
// The scalar REFUSAL rows (BASIC-014, and every row that follows its shape)
// rest on one southbound claim: no register of the refused axis moved. They
// measure that by fingerprinting the points a write of the axis would land on,
// and until now the only points they could read came from [DecodeCommands],
// which decodes model 704 and nothing else. On a 7xx bench that is the whole
// story. On a LEGACY bench there is no 704 at all, so the fingerprint came back
// empty, oracleRefusal reported Unavailable, and the row FAILED for want of a
// register to look at — a bench gap wearing a verdict's clothes.
//
// The legacy generation puts its scalar controls in model 123: one active-power
// ceiling (WMaxLimPct with its own enable and scale factor) and one connect
// register (Conn). Those are the two a refused scalar axis could land on, and
// reading them is what makes the refusal rows MEASURABLE on both generations
// rather than merely applicable to both.
//
// ── Why the offsets are transcribed HERE and not imported ───────────────────
//
// units.go states this package's sharing rule: the SunSpec LAYOUT TABLES are
// shared with the product deliberately (they are wire definitions, like mbap
// framing) and none of the INTERPRETATION is. Model 123 does not have a layout
// table. lexa-proto ships L126/L127/L128/L129/L130/L131/L132/L134/L160 and
// L701..L714, every one of them written against the vendored SunSpec model JSON
// — and model 123 alone is still driven by hand-written offset constants
// (lexa-proto sunspec/models.go's M123_* block) that predate the vendoring.
//
// A hand transcription is not a wire definition. It is exactly the artefact the
// vendoring exists to replace: lexa-proto docs/schema/sunspec-models/README.md
// says so in its own words — "every legacy offset in sunspec/models.go was
// previously hand-transcribed with no spec source on the machine, a failure
// mode that has already produced two register-map bugs". So this referee
// transcribes model 123 from the vendored JSON itself, which is the only way it
// can DISAGREE with the product about where a register is.
//
// ── And it does disagree. See [M123Divergence] ──────────────────────────────
//
// The transcription below and lexa-proto's M123_* constants do not name the
// same registers, at any offset. That is a finding about the product, recorded
// as data (M123Divergence) so a test can assert it and a bundle can quote it,
// rather than as a comment nobody executes.

import (
	"fmt"
	"sort"
	"strings"

	"lexa-proto/sunspec"
)

// ── The transcription ───────────────────────────────────────────────────────
//
// Source: SunSpec Alliance official model repository (github.com/sunspec/models),
// json/model_123.json, pinned commit 7abdf8982d5364f8ae916deee18aac86c11be36d,
// vendored at lexa-proto docs/schema/sunspec-models/model_123.json.
//
// The offsets are DATA-BLOCK relative — register 0 is the first word after the
// model's ID and L header words, which is what sunspec.Reader.ReadModel returns
// and what every other decoder in this package consumes.
//
// The full point sequence, in the order the model declares it:
//
//	 0 Conn_WinTms          uint16   Secs
//	 1 Conn_RvrtTms         uint16   Secs
//	 2 Conn                 enum16
//	 3 WMaxLimPct           uint16   % WMax    (WMaxLimPct_SF)
//	 4 WMaxLimPct_WinTms    uint16   Secs
//	 5 WMaxLimPct_RvrtTms   uint16   Secs
//	 6 WMaxLimPct_RmpTms    uint16   Secs
//	 7 WMaxLim_Ena          enum16
//	 8 OutPFSet             int16    cos()     (OutPFSet_SF)
//	 9 OutPFSet_WinTms      uint16   Secs
//	10 OutPFSet_RvrtTms     uint16   Secs
//	11 OutPFSet_RmpTms      uint16   Secs
//	12 OutPFSet_Ena         enum16
//	13 VArWMaxPct           int16    % WMax    (VArPct_SF)
//	14 VArMaxPct            int16    % VArMax  (VArPct_SF)
//	15 VArAvalPct           int16    % VArAval (VArPct_SF)
//	16 VArPct_WinTms        uint16   Secs
//	17 VArPct_RvrtTms       uint16   Secs
//	18 VArPct_RmpTms        uint16   Secs
//	19 VArPct_Mod           enum16
//	20 VArPct_Ena           enum16
//	21 WMaxLimPct_SF        sunssf
//	22 OutPFSet_SF          sunssf
//	23 VArPct_SF            sunssf
//
// Note what the published model does NOT contain, because the shipping
// transcription believes both: there is no Conn_RmpTms point, and there is no
// single "VArPct" point — the reactive percentage is THREE points selected by
// VArPct_Mod, each against a different reference.
const (
	m123ConnWinTms        = 0
	m123ConnRvrtTms       = 1
	m123Conn              = 2
	m123WMaxLimPct        = 3
	m123WMaxLimPctWinTms  = 4
	m123WMaxLimPctRvrtTms = 5
	m123WMaxLimPctRmpTms  = 6
	m123WMaxLimEna        = 7
	m123OutPFSet          = 8
	m123OutPFSetWinTms    = 9
	m123OutPFSetRvrtTms   = 10
	m123OutPFSetRmpTms    = 11
	m123OutPFSetEna       = 12
	m123VArWMaxPct        = 13
	m123VArMaxPct         = 14
	m123VArAvalPct        = 15
	m123VArPctWinTms      = 16
	m123VArPctRvrtTms     = 17
	m123VArPctRmpTms      = 18
	m123VArPctMod         = 19
	m123VArPctEna         = 20
	m123WMaxLimPctSF      = 21
	m123OutPFSetSF        = 22
	m123VArPctSF          = 23

	// M123PublishedLen is the model's declared data-block length: twenty-four
	// registers, the twenty-four points above. The published model's L value is
	// 24 and a conformant device declares exactly that.
	M123PublishedLen = 24
)

// m123Point names one point of the published model at one offset, beside the
// name lexa-proto's own constant of that value carried when the two disagreed.
type m123Point struct {
	Offset    int
	Published string
	// Generation1 is what lexa-proto's constant OF THIS OFFSET VALUE was called
	// in the hand transcription. Empty where the two already agreed — which,
	// for generation 1, is nowhere.
	Generation1 string
}

// M123Generation1 is the register map lexa-proto shipped until 2026-08-15,
// preserved as a WOULD-HAVE-CAUGHT record rather than as a live finding.
//
// ── Why a wrong map is kept in the tree at all ─────────────────────────────
//
// It was wrong at every one of its 24 points. Model 123 was the last register
// map in lexa-proto still driven by hand-written constants — every other legacy
// model (126-134, 160) got a NewLayout written against the vendored SunSpec
// JSON, and 123 was missed — and the transcription put the four function groups
// in the wrong ORDER, leading with WMaxLimPct where the published model leads
// with the Conn group. Two consequences were load-bearing for safety on a
// conformant legacy DER:
//
//   - The failsafe CEASE for a 704-less pack wrote offset 16 believing it was
//     Conn. A conformant device holds VArPct_WinTms there, so the pack stayed
//     ENERGIZED — and because the plan's L1 proof re-reads the offset it just
//     wrote, the echo matched and a disconnect that never happened was reported
//     as PROVEN.
//   - A commanded curtailment wrote the percentage to offset 0 believing it was
//     WMaxLimPct. A conformant device holds Conn_WinTms there, in seconds: a
//     60.00 % ceiling at SF -2 encodes to raw 6000 and became a 6000-second
//     connect window, curtailing nothing.
//
// lexa-proto 32150e1 fixed it, and this repo's own fixture half landed with it
// (sim/southbound/m123.go). So the table below no longer describes anything
// live. It is kept for the reason this suite keeps every superseded generation
// of a decoder it has been wrong about (see suitecsip's modes-oracle tripwires):
// a checker is only known to work if it is shown catching something, and the
// only thing anyone is certain this checker must catch is the map that actually
// shipped. TestM123_TheRefereeWouldHaveCaughtGeneration1 feeds it back in and
// requires the disagreement to be reported.
//
// DELETING IT WOULD COST THE PROOF. The agreement pin below asserts that the
// live constants match the published model; on its own that is satisfied by a
// checker that always answers "they agree". The pair — agreement on the live
// map, disagreement on the historical one — is what makes either meaningful.
var M123Generation1 = []m123Point{
	{0, "Conn_WinTms", "M123_WMaxLimPct"},
	{1, "Conn_RvrtTms", "M123_WMaxLimPct_WinTms"},
	{2, "Conn", "M123_WMaxLimPct_RvrtTms"},
	{3, "WMaxLimPct", "M123_WMaxLimPct_RmpTms"},
	{4, "WMaxLimPct_WinTms", "M123_WMaxLimPct_Ena"},
	{5, "WMaxLimPct_RvrtTms", "M123_OutPFSet"},
	{6, "WMaxLimPct_RmpTms", "M123_OutPFSet_WinTms"},
	{7, "WMaxLim_Ena", "M123_OutPFSet_RvrtTms"},
	{8, "OutPFSet", "M123_OutPFSet_RmpTms"},
	{9, "OutPFSet_WinTms", "M123_OutPFSet_Ena"},
	{10, "OutPFSet_RvrtTms", "M123_VArPct_Mod"},
	{11, "OutPFSet_RmpTms", "M123_VArPct"},
	{12, "OutPFSet_Ena", "M123_VArPct_WinTms"},
	{13, "VArWMaxPct", "M123_VArPct_RvrtTms"},
	{14, "VArMaxPct", "M123_VArPct_RmpTms"},
	{15, "VArAvalPct", "M123_VArPct_Ena"},
	{16, "VArPct_WinTms", "M123_Conn"},
	{17, "VArPct_RvrtTms", "M123_Conn_WinTms"},
	{18, "VArPct_RmpTms", "M123_Conn_RvrtTms"},
	{19, "VArPct_Mod", "M123_Conn_RmpTms (no such point exists)"},
	{20, "VArPct_Ena", "M123_WMaxLimPct_SF"},
	{21, "WMaxLimPct_SF", "M123_OutPFSet_SF"},
	{22, "OutPFSet_SF", "M123_VArPct_SF"},
	{23, "VArPct_SF", "(the shipping transcription declared no register here; its block was 23 long)"},
}

// m123PublishedOffsets is this referee's own transcription as a lookup, so a
// comparison against ANOTHER transcription can be written once and run against
// whichever one it is handed — the live constants, or a historical generation.
func m123PublishedOffsets() map[string]int {
	return map[string]int{
		"Conn_WinTms": m123ConnWinTms, "Conn_RvrtTms": m123ConnRvrtTms, "Conn": m123Conn,
		"WMaxLimPct": m123WMaxLimPct, "WMaxLimPct_WinTms": m123WMaxLimPctWinTms,
		"WMaxLimPct_RvrtTms": m123WMaxLimPctRvrtTms, "WMaxLimPct_RmpTms": m123WMaxLimPctRmpTms,
		"WMaxLim_Ena": m123WMaxLimEna,
		"OutPFSet":    m123OutPFSet, "OutPFSet_WinTms": m123OutPFSetWinTms,
		"OutPFSet_RvrtTms": m123OutPFSetRvrtTms, "OutPFSet_RmpTms": m123OutPFSetRmpTms,
		"OutPFSet_Ena": m123OutPFSetEna,
		"VArWMaxPct":   m123VArWMaxPct, "VArMaxPct": m123VArMaxPct, "VArAvalPct": m123VArAvalPct,
		"VArPct_WinTms": m123VArPctWinTms, "VArPct_RvrtTms": m123VArPctRvrtTms,
		"VArPct_RmpTms": m123VArPctRmpTms,
		"VArPct_Mod":    m123VArPctMod, "VArPct_Ena": m123VArPctEna,
		"WMaxLimPct_SF": m123WMaxLimPctSF, "OutPFSet_SF": m123OutPFSetSF, "VArPct_SF": m123VArPctSF,
	}
}

// m123ShippingOffsets is the map lexa-proto's constants describe RIGHT NOW,
// read from the constants themselves so this can never drift from what the
// product actually compiles against.
//
// The published spelling is on the left and lexa-proto's constant on the right,
// and the two differ in one place: the point is WMaxLim_Ena and the constant is
// M123_WMaxLimPct_Ena, a spelling lexa-proto kept deliberately so its consumers
// needed no edits when the VALUES were corrected. Mapping it here rather than
// renaming anything is what lets a name-keyed comparison run across a rename
// that never happened.
//
// M123_VArPct is deliberately absent: it is a compatibility ALIAS for
// VArMaxPct, not a point of the model, and including it would compare an alias
// against a name the model does not carry.
func m123ShippingOffsets() map[string]int {
	return map[string]int{
		"Conn_WinTms": sunspec.M123_Conn_WinTms, "Conn_RvrtTms": sunspec.M123_Conn_RvrtTms,
		"Conn":       sunspec.M123_Conn,
		"WMaxLimPct": sunspec.M123_WMaxLimPct, "WMaxLimPct_WinTms": sunspec.M123_WMaxLimPct_WinTms,
		"WMaxLimPct_RvrtTms": sunspec.M123_WMaxLimPct_RvrtTms,
		"WMaxLimPct_RmpTms":  sunspec.M123_WMaxLimPct_RmpTms,
		"WMaxLim_Ena":        sunspec.M123_WMaxLimPct_Ena,
		"OutPFSet":           sunspec.M123_OutPFSet,
		"OutPFSet_WinTms":    sunspec.M123_OutPFSet_WinTms,
		"OutPFSet_RvrtTms":   sunspec.M123_OutPFSet_RvrtTms,
		"OutPFSet_RmpTms":    sunspec.M123_OutPFSet_RmpTms,
		"OutPFSet_Ena":       sunspec.M123_OutPFSet_Ena,
		"VArWMaxPct":         sunspec.M123_VArWMaxPct, "VArMaxPct": sunspec.M123_VArMaxPct,
		"VArAvalPct":    sunspec.M123_VArAvalPct,
		"VArPct_WinTms": sunspec.M123_VArPct_WinTms, "VArPct_RvrtTms": sunspec.M123_VArPct_RvrtTms,
		"VArPct_RmpTms": sunspec.M123_VArPct_RmpTms,
		"VArPct_Mod":    sunspec.M123_VArPct_Mod, "VArPct_Ena": sunspec.M123_VArPct_Ena,
		"WMaxLimPct_SF": sunspec.M123_WMaxLimPct_SF, "OutPFSet_SF": sunspec.M123_OutPFSet_SF,
		"VArPct_SF": sunspec.M123_VArPct_SF,
	}
}

// M123Disagreements compares this referee's transcription against another one
// and returns the points they place differently, ascending by offset.
//
// It takes the other map as an ARGUMENT rather than reading the constants
// itself, which is the whole reason the would-have-caught proof is possible: the
// same function that answers "does the shipping map agree today" answers "would
// it have caught the map that shipped yesterday", and a checker that could only
// ever be pointed at today's map could not be shown to work at all.
func M123Disagreements(other map[string]int) []string {
	pub := m123PublishedOffsets()
	names := make([]string, 0, len(pub))
	for n := range pub {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return pub[names[i]] < pub[names[j]] })

	var out []string
	for _, n := range names {
		got, ok := other[n]
		if !ok {
			out = append(out, fmt.Sprintf("%s (published offset %d) has no counterpart in the map under "+
				"comparison", n, pub[n]))
			continue
		}
		if got != pub[n] {
			out = append(out, fmt.Sprintf("%s is at published offset %d and the map under comparison "+
				"places it at %d", n, pub[n], got))
		}
	}
	return out
}

// ── The point names this referee reports ────────────────────────────────────
//
// They are MODEL-QUALIFIED, and that is deliberate rather than decorative.
// Model 704 has a WMaxLimPct too, it means a different thing (Pct of the
// device's own WMax against a different enable register and a different scale
// factor), and every existing caller of [UnitView.Commands] selects points by
// bare name — oracleMaxLimW in suitecsip filters on `c.Point == "WMaxLimPct"`.
// An unqualified legacy point of the same name would have been silently picked
// up by that oracle and judged against the 704 semantics, which is a defect one
// import away from the fix it was supposed to be.
const (
	PointM123WMaxLimPct = "M123.WMaxLimPct"
	PointM123Conn       = "M123.Conn"
)

// M123Shape is what the device's own model-123 block turned out to be.
type M123Shape string

const (
	// M123Absent: the device serves no model 123.
	M123Absent M123Shape = "absent"
	// M123Published: the block is at least as long as the published model, so
	// every point above has a register and the reading below is a reading of
	// SunSpec model 123.
	M123Published M123Shape = "published"
	// M123Short: the device serves a model-123 block SHORTER than the
	// published model. It is a real answer and never a decode failure: the
	// points this referee names still have registers (Conn at 2 and WMaxLimPct
	// at 3 are early in the block), but the block cannot be the model SunSpec
	// publishes, and anything read from it is reported with that said.
	//
	// The 23-register case is the shipping bench's own shape — see
	// [M123Divergence].
	M123Short M123Shape = "short"
	// M123Truncated: the block is too short to hold even the points this
	// referee reads. Nothing is decoded.
	M123Truncated M123Shape = "truncated"
)

// LegacyControls is model 123's control surface as the DEVICE's own registers
// report it, decoded against the published model.
//
// It carries the raw block as well as the decoded commands because its first
// consumer is a REFUSAL FINGERPRINT, and a fingerprint's job is to change when
// anything moves — including a register this referee does not name. A rendering
// built only from the two named points would be blind to a gateway that wrote
// the ceiling into the ramp window beside it, which on this generation is not a
// hypothetical: it is what [M123Divergence] says the shipping writer does.
type LegacyControls struct {
	// Source names where this reading came from, for a finding that cites it.
	Source string
	// Present is true when the device served a model-123 block at all.
	Present bool
	// Shape says what that block turned out to be.
	Shape M123Shape
	// DeclaredLen is the length of the data block the device served.
	DeclaredLen int
	// Commands are the control points a scalar write could land on, in this
	// package's own Command vocabulary so a refusal fingerprint can render
	// them exactly as it renders the 704 ones.
	Commands []Command
	// Raw is the block verbatim, so a fingerprint covers every register a write
	// could have moved and not only the named ones.
	Raw []uint16
	// Note, when non-empty, is what a verdict must say about this reading
	// alongside whatever it concluded — a short block, or a divergence between
	// the published model and the transcription the writer under test uses.
	Note string
}

// LegacyCommands decodes this unit's model 123.
//
// It is a SIBLING of [UnitView.Commands] rather than an extension of it. The
// two decode different models with different semantics, the point names would
// collide (see PointM123WMaxLimPct), and every present caller of Commands
// selects 704 points by name — so folding model 123 into the same slice would
// have changed what BASIC-010's oracle judges as a side effect of making
// BASIC-014's fingerprint measurable. Two readings, two calls, no collision.
func (u UnitView) LegacyCommands(source string) LegacyControls {
	return DecodeLegacyControls(
		fmt.Sprintf("%s unit %d M123", source, u.Unit), u.Regs[sunspec.ModelImmediateCtrl])
}

// DecodeLegacyControls reads a model-123 data block into the control points a
// scalar axis could land on.
//
// regs must be the model's DATA registers (no id/length header), exactly as
// sunspec.Reader.ReadModel returns them and as every other decoder here takes
// them.
func DecodeLegacyControls(source string, regs []uint16) LegacyControls {
	lc := LegacyControls{Source: source, Shape: M123Absent}
	if len(regs) == 0 {
		return lc
	}
	lc.Present = true
	lc.DeclaredLen = len(regs)
	lc.Raw = append([]uint16(nil), regs...)

	switch {
	case len(regs) >= M123PublishedLen:
		lc.Shape = M123Published
	case len(regs) > m123WMaxLimEna:
		lc.Shape = M123Short
		lc.Note = fmt.Sprintf("the device served %d model-123 data registers where the published model "+
			"declares %d (SunSpec models @ 7abdf89, json/model_123.json), so this block is NOT that "+
			"model: the points read below sit at the published offsets and the registers past %d have no "+
			"published meaning here", len(regs), M123PublishedLen, len(regs)-1)
	default:
		lc.Shape = M123Truncated
		lc.Note = fmt.Sprintf("the device served only %d model-123 data registers, which is too few to "+
			"hold the connect and ceiling points at their published offsets (%d and %d), so nothing was "+
			"decoded from it", len(regs), m123Conn, m123WMaxLimEna)
		return lc
	}

	// ── Conn ──
	//
	// enum16, no scale factor: 1 = connect, 0 = disconnect, 0xFFFF = the point
	// is not implemented. It is reported as a UNITLESS quantity rather than
	// forced into a percentage, and its ENABLE is itself — a connect register
	// has no separate enable point in this model, so Enabled reports whether
	// the device implements the point at all. A reading that claimed a
	// disconnect register was "disabled" would invite the reader to discount
	// exactly the register the failsafe path writes.
	conn := regs[m123Conn]
	connCmd := Command{
		Point:     PointM123Conn,
		Enabled:   conn != 0xFFFF,
		Raw:       Q(float64(conn), UnitNone),
		Ref:       RefNone,
		ModePoint: "",
		Sign:      1,
	}
	if conn == 0xFFFF {
		connCmd.Unresolved = "the device leaves M123 Conn unimplemented (0xFFFF), so its connect state " +
			"cannot be read from this model at all"
	}
	lc.Commands = append(lc.Commands, connCmd)

	// ── WMaxLimPct ──
	//
	// uint16, "% WMax", scaled by WMaxLimPct_SF, governed by WMaxLim_Ena. All
	// three come from the published model; the scale factor is at offset 21 and
	// is present only on a block long enough to hold it, which a short block by
	// definition is not — so a short block yields the RAW register and says the
	// scale factor was unavailable, rather than scaling by a register that
	// holds something else.
	limRaw := regs[m123WMaxLimPct]
	ena := regs[m123WMaxLimEna]
	limCmd := Command{
		Point:     PointM123WMaxLimPct,
		Enabled:   ena == 1,
		Ref:       RefWMax,
		ModePoint: "WMaxLim_Ena",
		ModeVal:   ena,
		Sign:      1,
	}
	if lc.Shape == M123Published {
		sf := int16(regs[m123WMaxLimPctSF])
		limCmd.Raw = Q(sunspec.ApplyScaleUint(limRaw, sf), UnitPercent)
		if !sunspec.ValidSF(sf) {
			limCmd.Unresolved = fmt.Sprintf("M123 WMaxLimPct_SF reads %d, outside the legal sunssf "+
				"domain [%d,%d], so the raw register %d cannot be scaled into a percentage",
				sf, sunspec.MinValidSF, sunspec.MaxValidSF, limRaw)
		}
	} else {
		limCmd.Raw = Q(float64(limRaw), UnitNone)
		limCmd.Unresolved = "this block is shorter than the published model, so WMaxLimPct_SF (published " +
			"offset 21) has no register: the value above is the RAW register and is not a percentage"
	}
	lc.Commands = append(lc.Commands, limCmd)

	return lc
}

// Fingerprint renders everything a scalar write into model 123 could have
// moved, so two readings taken minutes apart can be compared for ANY movement.
//
// It renders the NAMED points and then the WHOLE BLOCK, and the second half is
// the load-bearing one. A refusal row asserts that nothing landed; a writer
// whose register map disagrees with the published model (see [M123Divergence])
// lands its write somewhere in this block that this referee does not name, and
// a fingerprint built from the named points alone would report a clean refusal
// over a real write. Rendering the raw block makes the assertion "no register
// of model 123 moved" rather than "no register I recognise moved".
//
// ok=false is "there was nothing to read", which stays distinguishable from
// "read it and it was empty": the first establishes nothing and the second is a
// clean baseline.
//
// ── One thing a reader of a FAIL must check first ──────────────────────────
//
// Because the whole block is rendered, ANY register moving moves this — and
// model 123 declares six registers that a device may legitimately count down on
// its own: Conn_WinTms, Conn_RvrtTms, WMaxLimPct_WinTms, WMaxLimPct_RvrtTms,
// WMaxLimPct_RmpTms and VArPct_RvrtTms. A device with a live timer in any of
// them will move this fingerprint without anything having been WRITTEN to it.
//
// That is not a reason to narrow the rendering — narrowing it is how a refusal
// row certifies a clean refusal over a write it was not looking at, which is
// the defect this width exists to catch, and the transcription divergence makes
// the unnamed offsets exactly where a write is most likely to land. It is a
// reason for the FAIL to be DIAGNOSABLE: both readings are printed in full, so
// whoever reads one can see which register index moved and whether it is a
// timer or a landing. A bench whose legacy DER runs such a timer during a
// refusal row's window should say so in its own notes rather than have this
// look away.
func (lc LegacyControls) Fingerprint() (string, bool) {
	if !lc.Present {
		return "", false
	}
	parts := make([]string, 0, len(lc.Commands)+2)
	for _, c := range lc.Commands {
		state := "disabled"
		if c.Enabled {
			state = "ENABLED"
		}
		if c.ModePoint != "" {
			parts = append(parts, fmt.Sprintf("%s=%s %s(%s=%d)", c.Point, c.Raw, state, c.ModePoint, c.ModeVal))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s %s", c.Point, c.Raw, state))
	}
	raw := make([]string, 0, len(lc.Raw))
	for _, r := range lc.Raw {
		raw = append(raw, fmt.Sprintf("%d", r))
	}
	parts = append(parts, fmt.Sprintf("M123[0:%d]={%s}", len(lc.Raw), strings.Join(raw, ",")))
	if lc.Note != "" {
		parts = append(parts, "NOTE: "+lc.Note)
	}
	return strings.Join(parts, ", "), true
}

// DescribeM123Divergence renders, in ONE sentence a verdict can carry, the
// disagreement between the model SunSpec publishes and the map lexa-proto's
// constants describe — or the EMPTY STRING when they agree.
//
// It agrees today (lexa-proto 32150e1, vendored at 04a0409), so this returns ""
// and the legacy verdicts that used to carry a transcription caveat carry none.
// That is deliberate and is how the heal reaches the evidence: the disclosure
// was never a fixed paragraph, it was a COMPUTATION over the two maps, so
// fixing the product made it stop printing without anyone editing a verdict.
// The withdrawn sentence is not re-worded and is not left behind — the same
// rule IW15-027 established for the vRef gaps.
//
// It still exists, and is still called on every legacy reading, because the
// disagreement it reports is a live property of two independently-maintained
// transcriptions rather than a historical fact. If either side moves again, the
// caveat comes back on its own, in the verdict, on the run that first sees it.
func DescribeM123Divergence() string {
	rows := M123Disagreements(m123ShippingOffsets())
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf("model 123's published register map (SunSpec models @ 7abdf89, "+
		"json/model_123.json, %d data registers) and lexa-proto's own M123_* offsets "+
		"(sunspec/models.go) disagree at %d of %d points: %s. This referee reads the PUBLISHED map, so a "+
		"reading it takes of a device the shipping writer wrote is a reading of different registers than "+
		"the writer believes it moved",
		M123PublishedLen, len(rows), len(m123PublishedOffsets()), strings.Join(rows, "; "))
}

// DescribeM123DivergenceFull is the summary plus the whole table, for a report
// or a finding that has to be actionable on its own. Empty when they agree.
func DescribeM123DivergenceFull() string {
	rows := M123Disagreements(m123ShippingOffsets())
	if len(rows) == 0 {
		return ""
	}
	return DescribeM123Divergence() + ". The full disagreement: " + strings.Join(rows, "; ")
}
