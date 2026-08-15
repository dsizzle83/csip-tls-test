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
	m123OutPFSetEna       = 12
	m123VArWMaxPct        = 13
	m123VArMaxPct         = 14
	m123VArAvalPct        = 15
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

// M123Divergence is the point-by-point disagreement between the model SunSpec
// publishes and the offsets lexa-proto's sunspec/models.go declares — recorded
// as DATA so a test can assert it and a bundle can quote it.
//
// It is not a style complaint. Every entry below is a register the product
// writes or reads believing it is one point when a conformant device holds
// another, and two of them are load-bearing for safety:
//
//   - The product's failsafe CEASE for a 704-less pack disconnects "through the
//     M123 Conn register" (lexa-gw cmd/modbus/failsafe_posture.go). It writes
//     offset 16. A conformant model 123 holds VArPct_WinTms there. The pack
//     stays energized — and because the plan's L1 proof re-reads the SAME
//     offset it just wrote, the echo matches and the gateway reports a PROVEN
//     disconnect that never happened.
//   - A commanded curtailment writes the percent to offset 0 believing it is
//     WMaxLimPct. A conformant device holds Conn_WinTms there, in seconds. A
//     60.00 % ceiling becomes a 6000-second connect window and curtails
//     nothing.
//
// The reason no test on either side catches it is the one this repo keeps
// finding: the BENCH SIM is built from the same constants (sim/southbound's
// M123 block, 23 data registers), so the fixture and the product agree with
// each other and both disagree with the standard. That is why the referee had
// to transcribe the model itself before it could see anything.
//
// Each row is {offset, what the published model holds there, what lexa-proto's
// constant of that value names}.
var M123Divergence = []struct {
	Offset    int
	Published string
	Shipping  string
}{
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
	{23, "VArPct_SF", "(the shipping transcription declares no register here; its block is 23 long)"},
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

// DescribeM123Divergence renders [M123Divergence] as ONE sentence a verdict can
// carry, or the empty string when the two transcriptions agree.
//
// It is the SUMMARY form, and the split from [DescribeM123DivergenceFull] is
// about where each belongs. This one rides on every legacy reading, so it has
// to say enough for a reader to act — how wide the disagreement is, and the one
// offset whose consequence is a safety property — without putting a
// twenty-four-row table inside every verdict of every run. The full table is
// what a report or a finding quotes once.
//
// Both compute the disagreement rather than restating it, so the day lexa-proto
// reconciles model 123 against the vendored JSON they stop printing without
// anyone having to remember to delete a paragraph.
func DescribeM123Divergence() string {
	n := m123DisagreeingOffsets()
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("model 123's published register map (SunSpec models @ 7abdf89, "+
		"json/model_123.json, %d data registers) and lexa-proto's hand-written M123_* offsets "+
		"(sunspec/models.go, 23 data registers) disagree at %d of %d points — including offset %d, where "+
		"the published model holds %s and the shipping writer believes it is writing Conn, which is the "+
		"register its failsafe CEASE path uses. This referee reads the PUBLISHED map, so a reading it "+
		"takes of a device the shipping writer wrote is a reading of different registers than the writer "+
		"believes it moved (invariant.DescribeM123DivergenceFull has the whole table)",
		M123PublishedLen, n, len(M123Divergence), shippingConnOffset,
		publishedPointAt(shippingConnOffset))
}

// DescribeM123DivergenceFull renders the whole table, offset by offset, for a
// report or a finding that has to be actionable on its own.
func DescribeM123DivergenceFull() string {
	var rows []string
	for _, d := range M123Divergence {
		if d.Published == d.Shipping {
			continue
		}
		rows = append(rows, fmt.Sprintf("offset %d holds %s, transcribed as %s",
			d.Offset, d.Published, d.Shipping))
	}
	if len(rows) == 0 {
		return ""
	}
	return DescribeM123Divergence() + ". The full disagreement: " + strings.Join(rows, "; ")
}

// shippingConnOffset is the data-block offset lexa-proto's M123_Conn names. It
// is written here as a literal rather than imported so this package's rendering
// does not depend on the constant it is reporting on — and legacyctl_test.go
// pins the two together, so a move on either side is a test failure rather than
// a silently wrong sentence in a bundle.
const shippingConnOffset = 16

// publishedPointAt names what the published model holds at an offset.
func publishedPointAt(off int) string {
	for _, d := range M123Divergence {
		if d.Offset == off {
			return d.Published
		}
	}
	return "(an offset outside the published block)"
}

// m123DisagreeingOffsets counts the points the two transcriptions place
// differently.
func m123DisagreeingOffsets() int {
	n := 0
	for _, d := range M123Divergence {
		if d.Published != d.Shipping {
			n++
		}
	}
	return n
}
