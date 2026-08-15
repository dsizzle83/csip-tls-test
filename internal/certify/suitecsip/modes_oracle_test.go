package suitecsip

// modes_oracle_test.go proves four separate things about the independent
// modesSupported oracle, and they are separate on purpose:
//
//  1. the TRANSCRIPTION is right — derControlTypeBits says what IEEE Std
//     2030.5-2018 says (TestModesOracleBitTable_TranscriptionMatches2018Quote,
//     and the live cross-check against the published PDF itself);
//  2. the ANCHOR is right — the table diverges from the vendored draft schema in
//     exactly the way lexa-proto's census documents, so nobody can re-anchor
//     this file to the document it can reach
//     (TestModesOracleBitTable_DivergesFromTheDraftExactlyAsTheCensusSays);
//  3. the ORACLE has teeth in both directions — a DUT that advertises a mode it
//     refuses fails, and a DUT that executes a mode it never advertised fails
//     (TestModesSupportedOracle_HasTeethBothDirections, and the red-proof
//     against the preserved product fixture);
//  4. the two TABLES in this tree — this file's transcription and
//     lexa-proto/csipmodel's Mode* constants — either agree, or a human is told
//     to go and adjudicate against the STANDARD
//     (TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong).
//
// # THREE GENERATIONS OF TABLE, TWO OF THEM PROVEN WRONG
//
// This tripwire has now been run against three different claims about which bit
// means which mode, and the history is kept in this file because a tripwire's
// worth is exactly the evidence that it can go red:
//
//	GENERATION 1 — legacyCsipmodelBits, csipmodel @ 468f8bf. Its own doc comment
//	called it a "RECORDED DIVERGENCE". It packed the modes into bits 0..26 in an
//	order of its own, gave one bit to "opModConnect / opModEnergize" jointly, and
//	spent 23..26 on the CSIP-Aus quartet, which no revision assigns. WRONG.
//
//	GENERATION 2 — draftAnchoredCsipmodelBits, csipmodel @ 9856710 ("the
//	conformance pass"). Transcribed faithfully from docs/schema/sep-2.0.4.xsd,
//	twenty-two bits 0..21, and it is the table THIS FILE'S FIRST VERSION also
//	carried. The two agreed and the tripwire went green — because both had read
//	the same book, and the book is the pre-publication ZigBee SEP 2.0 draft, not
//	IEEE 2030.5-2018. WRONG, and wrong in a way three witnesses could not see.
//
//	GENERATION 3 — the live table, csipmodel @ 13e9106 and derControlTypeBits
//	here, both re-derived from the PUBLISHED standard, p.251-252, independently.
//	The tripwire is green again, and this time the two derivations do not share a
//	source.
//
// Generations 1 and 2 are both preserved below and both must still go RED
// through the same comparison. That is the whole point: a green tripwire proves
// nothing about whether it COULD have gone red, and generation 2 is the proof
// that "it went red once" is not enough either — it went red against generation
// 1, then green against a wrong table, and only the SOURCE of the witness
// separated the two cases.
//
//	A WITNESS IS INDEPENDENT ONLY IF ITS SOURCE IS.
//
// Nothing here is t.Skip'd and nothing is marked "expected failure". This suite
// has no honest mechanism for either: a skipped test reports nothing, and an
// expected-failure marker would go green the day a disagreement is FIXED and
// green again the day a NEW one appears — precisely the blindness the tripwire
// exists to end. The live comparison is a plain assertion; when it fails, its
// text names both claims and sends the reader to the standard, because neither
// this file nor csipmodel has standing to settle it.

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	model "lexa-proto/csipmodel"
)

// ── (1) The transcription ────────────────────────────────────────────────────

// standard2018Quote is IEEE Std 2030.5-2018, PRINTED PAGES 251-252, VERBATIM:
// the "DERControlType object" definition and its twenty-seven bit assignments.
//
// It is quoted rather than referenced because the standard is not in this
// repository and cannot be: it is a purchased IEEE document. That is a feature
// and not a limitation — it is precisely what makes this witness independent of
// everything else in the tree (see the file doc's independence rule). A reviewer
// with a copy of the standard compares this block against printed page 251 and
// 252, which is a thing a human can actually do; a reviewer without one can
// still check that the table in modes_oracle.go is a faithful parse of this
// text, which is what TestModesOracleBitTable_TranscriptionMatches2018Quote
// does hermetically.
//
// The live document is compared against this quote whenever the corpus copy and
// a PDF text extractor are both reachable, by
// TestModesOracleBitTable_MatchesThePublishedStandardItself.
//
// PAGE BOUNDARY: assignments 0..6 are printed on page 251, 7..26 on page 252.
// bitPageIn2018 below encodes that, and the transcription's Page field is
// checked against it.
const standard2018Quote = `DERControlType object (HexBinary32)
Control modes supported by the DER. Bit positions SHALL be defined as follows:
0 = Charge mode
1 = Discharge mode
2 = opModConnect (connect/disconnect—implies galvanic isolation)
3 = opModEnergize (energize/de-energize)
4 = opModFixedPFAbsorbW (fixed power factor setpoint when absorbing active power)
5 = opModFixedPFInjectW (fixed power factor setpoint when injecting active power)
6 = opModFixedVar (reactive power setpoint)
7 = opModFixedW (charge/discharge setpoint)
8 = opModFreqDroop (Frequency-Watt Parameterized mode)
9 = opModFreqWatt (Frequency-Watt Curve mode)
10 = opModHFRTMayTrip (High Frequency Ride-Through, May Trip mode)
11 = opModHFRTMustTrip (High Frequency Ride-Through, Must Trip mode)
12 = opModHVRTMayTrip (High Voltage Ride-Through, May Trip mode)
13 = opModHVRTMomentaryCessation (High Voltage Ride-Through, Momentary Cessation mode)
14 = opModHVRTMustTrip (High Voltage Ride-Through, Must Trip mode)
15 = opModLFRTMayTrip (Low Frequency Ride-Through, May Trip mode)
16 = opModLFRTMustTrip (Low Frequency Ride-Through, Must Trip mode)
17 = opModLVRTMayTrip (Low Voltage Ride-Through, May Trip mode)
18 = opModLVRTMomentaryCessation (Low Voltage Ride-Through, Momentary Cessation mode)
19 = opModLVRTMustTrip (Low Voltage Ride-Through, Must Trip mode)
20 = opModMaxLimW (maximum active power)
21 = opModTargetVar (target reactive power)
22 = opModTargetW (target active power)
23 = opModVoltVar (Volt-Var mode)
24 = opModVoltWatt (Volt-Watt mode)
25 = opModWattPF (Watt-Powerfactor mode)
26 = opModWattVar (Watt-Var mode)
All other values reserved.`

// standardBitLine matches one assignment line of the quote above. The standard
// writes "N = name"; the draft schema writes "N - name", and the two parsers
// are deliberately NOT shared so that a copy-paste from one document into the
// other's quote block cannot go unnoticed.
var standardBitLine = regexp.MustCompile(`^(\d+) = (\S+)`)

// bitPageIn2018 is the printed page each assignment is on: the DERControlType
// block starts partway down p.251 and runs over onto p.252.
func bitPageIn2018(bit uint) int {
	if bit <= 6 {
		return 251
	}
	return 252
}

// bitsFrom2018Quote re-derives the assignment from the quoted standard text. It
// is deliberately a DIFFERENT route to the same answer than the hand-written
// table in modes_oracle.go: one is a Go literal a human typed, the other is a
// parse of the standard's own sentence.
func bitsFrom2018Quote(t *testing.T) map[uint]string {
	t.Helper()
	out := map[uint]string{}
	sc := bufio.NewScanner(strings.NewReader(standard2018Quote))
	for sc.Scan() {
		m := standardBitLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		pos, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("the 2018 quote has a non-numeric bit position %q", m[1])
		}
		name := m[2]
		// "0 = Charge mode" and "1 = Discharge mode" are two-word names; the
		// regexp took only the first word, so put the rest back.
		if name == "Charge" || name == "Discharge" {
			name += " mode"
		}
		if prev, dup := out[uint(pos)]; dup {
			t.Fatalf("the 2018 quote assigns bit %d twice: %q then %q", pos, prev, name)
		}
		out[uint(pos)] = name
	}
	return out
}

func TestModesOracleBitTable_TranscriptionMatches2018Quote(t *testing.T) {
	want := bitsFrom2018Quote(t)
	if len(want) != 27 {
		t.Fatalf("the 2018 quote yields %d bit assignments, want 27 (0..26)", len(want))
	}
	if len(derControlTypeBits) != len(want) {
		t.Fatalf("derControlTypeBits has %d entries, IEEE 2030.5-2018 assigns %d",
			len(derControlTypeBits), len(want))
	}
	seen := map[uint]bool{}
	for _, b := range derControlTypeBits {
		if seen[b.Bit] {
			t.Errorf("derControlTypeBits lists bit %d twice", b.Bit)
		}
		seen[b.Bit] = true
		got, ok := want[b.Bit]
		if !ok {
			t.Errorf("derControlTypeBits assigns bit %d to %q; IEEE 2030.5-2018 assigns nothing to it",
				b.Bit, b.Mode)
			continue
		}
		if got != b.Mode {
			t.Errorf("bit %d: the transcription says %q, IEEE 2030.5-2018 p.%d says %q",
				b.Bit, b.Mode, b.Page, got)
		}
		if wantPage := bitPageIn2018(b.Bit); b.Page != wantPage {
			t.Errorf("bit %d cites printed page %d; the DERControlType block puts it on p.%d",
				b.Bit, b.Page, wantPage)
		}
	}
	// Bits 0 and 1 are the two the standard names without giving them a
	// DERControlBase element. Nothing else may claim that shape, or the oracle
	// would silently stop being able to evidence a mode.
	//
	// THE PAIR MOVED. Under the draft schema they were bits 19 and 20; under
	// IEEE 2030.5-2018 they are 0 and 1, and bit 20 is opModMaxLimW — the single
	// most-exercised mode in this whole campaign. A table that got this wrong
	// would credit "Discharge mode, which no transcript can evidence" for every
	// CORE-022 run.
	for _, b := range derControlTypeBits {
		hasElement := b.Element != ""
		wantElement := b.Bit != 0 && b.Bit != 1
		if hasElement != wantElement {
			t.Errorf("bit %d (%s): Element=%q, but IEEE 2030.5-2018 %s give this mode a DERControlBase "+
				"element", b.Bit, b.Mode, b.Element,
				map[bool]string{true: "does", false: "does not"}[wantElement])
		}
		if hasElement && b.ElementPage == 0 {
			t.Errorf("bit %d (%s) names element <%s> without citing the page that declares it",
				b.Bit, b.Mode, b.Element)
		}
		// DERControlBase's attribute listing runs from p.248 to p.251. A cite
		// outside that range is a transcription slip whatever else is right.
		if hasElement && (b.ElementPage < 248 || b.ElementPage > 251) {
			t.Errorf("bit %d (%s) cites p.%d for element <%s>; IEEE 2030.5-2018's DERControlBase "+
				"attribute listing occupies pages 248-251", b.Bit, b.Mode, b.ElementPage, b.Element)
		}
	}
	// Every element name must be an opMod* name. The two bits without one are
	// checked above; nothing else may carry a name from a different vocabulary.
	for _, b := range derControlTypeBits {
		if b.Element != "" && !strings.HasPrefix(b.Element, "opMod") {
			t.Errorf("bit %d names element %q, which is not a DERControlBase opMod* attribute",
				b.Bit, b.Element)
		}
	}
}

// TestModesOracleBitTable_ReservedFromIs27UnderThisAnchor pins the boundary the
// reserved-bit direction grades on, and the reason it is a NARROWER claim than
// it looks.
//
// 2018 reserves everything above 26. 2023 defines 27..31. Both statements are
// true, they are about different documents, and a finding that reported only the
// first would tell a vendor shipping a 2030.5-2023 device that it invented a
// mode. The oracle grades 2018 (the revision CSIP profiles and this campaign
// certifies against) and quotes 2023 beside the verdict.
func TestModesOracleBitTable_ReservedFromIs27UnderThisAnchor(t *testing.T) {
	if modesSupportedReservedFrom != 27 {
		t.Fatalf("modesSupportedReservedFrom = %d; IEEE 2030.5-2018 p.252 assigns bits 0..26 and "+
			"reserves everything above", modesSupportedReservedFrom)
	}
	for _, b := range derControlTypeBits {
		if b.Bit >= modesSupportedReservedFrom {
			t.Errorf("the table assigns bit %d (%s), at or above the first reserved position %d",
				b.Bit, b.Mode, modesSupportedReservedFrom)
		}
	}
	if _, ok := bitAt(27); ok {
		t.Error("bit 27 resolves to a mode; 2018 reserves it (2023 defines it as opModDeltaVar, which " +
			"is the whole reason the finding text has to name both revisions)")
	}
	for _, want := range []string{"2030.5-2023", "opModDeltaVar", "opModIslandPermit", "27-31"} {
		if !strings.Contains(reservedBitNote, want) {
			t.Errorf("the reserved-bit note omits %q, so a 2023-era DUT would be reported as having "+
				"invented a mode: %q", want, reservedBitNote)
		}
	}
}

// standardPDFPath is where the published standard lives in the local corpus. It
// is overridable so a machine that keeps it elsewhere can still run the live
// cross-check rather than silently skipping it.
func standardPDFPath() string {
	if p := os.Getenv("IEEE_20305_2018_PDF"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Documents", "standards", "20305-2018.pdf")
}

// TestModesOracleBitTable_MatchesThePublishedStandardItself is the
// belt-and-braces half, and it is the ONE test in this file whose witness is
// outside the repository entirely — which, after IW15-027, is the only kind of
// witness that settles anything.
//
// It re-extracts the text of PDF pages 252-253 (PRINTED 251-252: the printed
// number runs one lower than the PDF index) and requires every assignment line
// of the verbatim quote above to still be there.
//
// It reports rather than fails when the corpus copy or a PDF text extractor is
// absent — a CI runner has neither, and a purchased IEEE document cannot be
// committed. The hermetic guarantee belongs to
// TestModesOracleBitTable_TranscriptionMatches2018Quote, which needs nothing but
// this file. On a developer machine and on the bench, where the standard IS
// reachable, this is a hard check and a drifted quote is a failure.
func TestModesOracleBitTable_MatchesThePublishedStandardItself(t *testing.T) {
	pdf := standardPDFPath()
	if pdf == "" {
		t.Log("the live standard cross-check did not run: no home directory to resolve the corpus path")
		return
	}
	if _, err := os.Stat(pdf); err != nil {
		t.Logf("the live standard cross-check did not run: %v. IEEE Std 2030.5-2018 is a purchased "+
			"document and cannot be committed; set IEEE_20305_2018_PDF to a local copy to enable this "+
			"check. The hermetic half still proves the table against the verbatim quote in this file", err)
		return
	}
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Logf("the live standard cross-check did not run: pdftotext is not installed (%v). Install "+
			"poppler-utils to enable it", err)
		return
	}
	// PDF pages 252-253 == printed pages 251-252.
	out, err := exec.Command(tool, "-f", "252", "-l", "253", "-layout", pdf, "-").Output()
	if err != nil {
		t.Fatalf("extracting printed pages 251-252 of %s failed: %v", pdf, err)
	}
	text := string(out)
	// The header sentence, which is what makes these assignments NORMATIVE
	// rather than a table someone drew.
	for _, want := range []string{
		"DERControlType object (HexBinary32)",
		"Control modes supported by the DER. Bit positions SHALL be defined as follows:",
		"All other values reserved.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("printed pages 251-252 of the published standard no longer contain %q; the quote "+
				"in this file has drifted from the document, or the page mapping has", want)
		}
	}
	// Every assignment line, verbatim.
	for _, line := range strings.Split(standard2018Quote, "\n") {
		if standardBitLine.FindStringSubmatch(line) == nil {
			continue
		}
		if !strings.Contains(text, line) {
			t.Errorf("the published standard's printed pages 251-252 do not contain the quoted "+
				"assignment line %q", line)
		}
	}
	// And the page boundary the transcription's Page field depends on: bit 6 is
	// the last on p.251, bit 7 the first on p.252. The extractor prints the
	// running page number in the footer, so the two halves are separable.
	half := strings.Index(text, "\n                                                                  251")
	if half < 0 {
		t.Log("the extracted text carries no recognisable page-251 footer, so the page-boundary half " +
			"of this check did not run; the assignment lines above were still verified")
		return
	}
	first, second := text[:half], text[half:]
	if !strings.Contains(first, "6 = opModFixedVar (reactive power setpoint)") {
		t.Error("bit 6 is not on printed page 251; the transcription's Page cites are derived from that " +
			"boundary")
	}
	if !strings.Contains(second, "7 = opModFixedW (charge/discharge setpoint)") {
		t.Error("bit 7 is not on printed page 252; the transcription's Page cites are derived from that " +
			"boundary")
	}
}

// ── (2) The anchor ───────────────────────────────────────────────────────────

// draftSchemaPath is the vendored pre-publication ZigBee schema, reachable when
// the workspace's sibling module is checked out (`use ../lexa-proto` in
// go.work). It is NOT the anchor; see the census test below for what it is for.
const draftSchemaPath = "../../../../lexa-proto/docs/schema/sep-2.0.4.xsd"

// draftBitLine matches one assignment line of the DRAFT's own documentation
// block, which writes "N - name" where the standard writes "N = name".
var draftBitLine = regexp.MustCompile(`^\s*(\d+) - (\S+)`)

// bitsFromDraftSchema parses the vendored draft's DERControlType block.
func bitsFromDraftSchema(t *testing.T, raw string) map[uint]string {
	t.Helper()
	out := map[uint]string{}
	lines := strings.Split(raw, "\n")
	// The block is delimited by its own sentences, located by content rather
	// than by line number so a re-vendored file with a different layout is
	// still parsed (and its CONTENT is what the assertions are about).
	start, end := -1, -1
	for i, l := range lines {
		if start < 0 && strings.Contains(l, "Bit positions SHALL be defined as follows") {
			start = i
			continue
		}
		if start >= 0 && strings.Contains(l, "All other values reserved") {
			end = i
			break
		}
	}
	if start < 0 || end < 0 {
		t.Fatalf("the vendored sep-2.0.4.xsd no longer carries a DERControlType bit block " +
			"(start/end sentences not found); the census cannot be checked against it")
	}
	for _, l := range lines[start+1 : end] {
		m := draftBitLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		pos, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		name := m[2]
		if name == "Charge" || name == "Discharge" {
			name += " mode"
		}
		out[uint(pos)] = name
	}
	return out
}

// TestModesOracleBitTable_DivergesFromTheDraftExactlyAsTheCensusSays is the
// ANCHOR guard, and it is this file's answer to how IW15-027 happened.
//
// The vendored sep-2.0.4.xsd is still in the tree, it is still the only
// machine-readable artifact anywhere near this problem, and it is still the
// easiest thing for a future edit to reach for. This test makes reaching for it
// LOUD: it asserts that the draft and the standard agree on NOTHING, and that
// the element-set difference is precisely the one lexa-proto's
// docs/schema/NORMATIVE_ANCHOR.md §3.1 documents.
//
// Two ways it fires. If someone re-vendors the schema — or swaps in a real
// published sep.xsd for 2030.5-2018 — the divergence set moves and this fails,
// which is the moment to re-read the census rather than to update a number. If
// someone "simplifies" derControlTypeBits back towards the file they can open,
// the agreement count stops being zero and this fails first.
//
// It does NOT assert the draft is wrong about anything. The draft is a correct
// transcription of a different document. That is exactly what made it dangerous.
func TestModesOracleBitTable_DivergesFromTheDraftExactlyAsTheCensusSays(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(draftSchemaPath))
	if err != nil {
		t.Logf("the draft-divergence census did not run: %v. It needs the sibling lexa-proto checkout "+
			"(go.work's `use ../lexa-proto`); every other check in this file is hermetic", err)
		return
	}
	draft := bitsFromDraftSchema(t, string(raw))
	if len(draft) != 22 {
		t.Fatalf("the vendored sep-2.0.4.xsd yields %d bit assignments; the census (NORMATIVE_ANCHOR.md "+
			"§3.1) records the draft as assigning 22, bits 0..21", len(draft))
	}

	// (a) NOT ONE position agrees. The census's headline: the draft-anchored
	// pass "happened to match 2018 on twelve of twenty-two positions" BEFORE it
	// was 'fixed', and the fix took that to zero.
	var agreements []string
	for pos := uint(0); pos < 27; pos++ {
		d, inDraft := draft[pos]
		s, inStd := "", false
		if b, ok := bitAt(pos); ok {
			s, inStd = b.Mode, true
		}
		if inDraft && inStd && d == s {
			agreements = append(agreements, fmt.Sprintf("bit %d = %q", pos, s))
		}
	}
	if len(agreements) != 0 {
		t.Errorf("the draft schema and IEEE 2030.5-2018 agree on %d bit position(s): %s.\n\n"+
			"The census (lexa-proto docs/schema/NORMATIVE_ANCHOR.md §3.1) records that they agree on "+
			"NONE. Either the vendored schema changed, or this file's table has been edited towards the "+
			"document it can open — which is the IW15-027 re-anchoring this test exists to catch. Do not "+
			"update this count; go and read the census.",
			len(agreements), strings.Join(agreements, ", "))
	}

	// (b) The element-set difference is exactly the documented one.
	draftNames, stdNames := map[string]bool{}, map[string]bool{}
	for _, n := range draft {
		draftNames[n] = true
	}
	for _, b := range derControlTypeBits {
		stdNames[b.Mode] = true
	}
	onlyDraft := setDifference(draftNames, stdNames)
	only2018 := setDifference(stdNames, draftNames)
	wantOnlyDraft := []string{"opModFixedPF"}
	want2018Only := []string{
		"opModFixedPFAbsorbW", "opModFixedPFInjectW",
		"opModHFRTMayTrip", "opModHVRTMayTrip", "opModLFRTMayTrip", "opModLVRTMayTrip",
	}
	if strings.Join(onlyDraft, ",") != strings.Join(wantOnlyDraft, ",") {
		t.Errorf("modes named ONLY by the draft = %v, census says %v (the draft folds the two "+
			"power-factor directions into one opModFixedPF)", onlyDraft, wantOnlyDraft)
	}
	if strings.Join(only2018, ",") != strings.Join(want2018Only, ",") {
		t.Errorf("modes named ONLY by IEEE 2030.5-2018 = %v, census says %v (the absorb/inject pair, "+
			"and the four MayTrip ride-through modes the draft has no bit for at all)",
			only2018, want2018Only)
	}
}

// setDifference is the sorted membership difference, for stable failure text.
func setDifference(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestModesOracle_DerivesItsBitsFromThePublishedStandardAndNothingInThisTree is
// the structural half of the IW15-011 rule, WIDENED by IW15-027.
//
// The oracle path may not reference the product's table — a decode that asks the
// product's own table what the product's own table means cannot fail. And it may
// not reference the vendored DRAFT SCHEMA either, which is the half this suite
// learned the hard way: the first version of this file obeyed the letter of the
// rule (no csipmodel import) and still ended up agreeing with a wrong product
// table, because both had read the same file.
//
// The forbidden list is therefore about SOURCES, not about imports.
func TestModesOracle_DerivesItsBitsFromThePublishedStandardAndNothingInThisTree(t *testing.T) {
	src, err := os.ReadFile("modes_oracle.go")
	if err != nil {
		t.Fatalf("read the oracle's own source: %v", err)
	}
	body := string(src)
	// The doc comment legitimately NAMES both csipmodel and the draft schema to
	// explain why neither is used, so the check is on the import and on the
	// identifiers, not on the words.
	for _, forbidden := range []string{`"lexa-proto/csipmodel"`, "csipmodel.Mode", "model.Mode"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("modes_oracle.go references %s. The oracle's bit positions must come from the "+
				"hand transcription of IEEE Std 2030.5-2018 and from nothing else: a decode that asks "+
				"the product's own table what the product's own table means cannot fail, which is the "+
				"IW15-011 shared-oracle blindness this file was written to end", forbidden)
		}
	}
	if strings.Contains(body, "sep-2.0.4.xsd") && strings.Contains(body, "os.ReadFile") {
		t.Error("modes_oracle.go both names sep-2.0.4.xsd and reads a file. The oracle path must not " +
			"derive anything from the vendored draft schema: it is the pre-publication ZigBee document, " +
			"its bit order is not the standard's, and reading it is exactly how IW15-027's three " +
			"'independent' witnesses came to agree on a wrong table")
	}
	// The table must cite the standard, positively — an absent citation is the
	// state this whole wave exists to leave behind.
	if !strings.Contains(body, "2030.5-2018") {
		t.Error("modes_oracle.go does not cite IEEE Std 2030.5-2018 anywhere; every bit position in it " +
			"is a claim about that document and must say so")
	}
}

// ── (4) The tripwire ─────────────────────────────────────────────────────────

// TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong is THE
// TRIPWIRE.
//
// Two tables in this tree claim to say which bit of DERCapability.modesSupported
// means which operating mode. One of them is written to the wire by the product
// (lexa-proto/csipmodel, via lexa-gw's derproducer). The other is what this
// harness grades against (derControlTypeBits, transcribed from IEEE Std
// 2030.5-2018 by hand, in modes_oracle.go). While they disagree, at least one of
// them is wrong; and a campaign in which BOTH sides read the same wrong table
// would report green forever — the IW15-011 shared-oracle blindness.
//
// It does NOT assert that the harness is right. It asserts that the two AGREE,
// and when they do not it prints both claims for every position and sends the
// reader to the STANDARD, which is the only document with standing to settle it.
//
// # State on 2026-08-15, and why the green is worth more than the last one
//
// This comparison has been green before, against generation 2, and that green
// was worthless: both tables had been derived from docs/schema/sep-2.0.4.xsd.
// lexa-proto 13e9106 re-derived csipmodel's table from the published standard
// and this file was re-derived from the same published standard by a different
// hand, from the printed page rather than from each other. Agreement between two
// independent readings of a document neither party can edit is evidence;
// agreement between two readings of a file in the repo is not.
//
// The comparison goes through csipmodel's PUBLIC projection (ModeBit /
// ModeBitName) rather than through its constants, for two reasons: it is what
// the product's own consumers use to build a mask, so it is the mapping that
// actually reaches the wire; and it survives a rename of a constant, which a
// hand-copied constant list does not.
func TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong(t *testing.T) {
	// model.ModeBit answers in csipmodel's own HexBinary32 type — 72d91be made
	// the Mode* constants typed, so a mask composed from them cannot be assigned
	// to anything but the field it belongs to. Widen it to the plain uint32 this
	// file compares in: the comparison is about BIT POSITIONS, and adopting the
	// product's type to make it would put a second product dependency inside the
	// one test whose whole job is to be independent of the product.
	productBit := func(name string) (uint32, bool) {
		b, ok := model.ModeBit(name)
		return uint32(b), ok
	}
	disagreements := compareAgainstProductTable(model.ModeBitName, productBit)
	if len(disagreements) == 0 {
		return
	}
	t.Fatalf(`the two modesSupported bit tables in this tree DISAGREE in %d position(s).

This is not a statement that either side is right. It is a statement that they
cannot both be, and that a human has to open the STANDARD and decide:

    IEEE Std 2030.5-2018, printed pages 251-252 — "DERControlType object
    (HexBinary32) ... Bit positions SHALL be defined as follows".

    NOT lexa-proto docs/schema/sep-2.0.4.xsd. That file is the pre-publication
    ZigBee draft; settling this against it is what produced IW15-027.

The two claims:

  %s

Whichever way it is settled, BOTH tables move together, or the next campaign is
graded by a referee that agrees with the thing it is grading — the IW15-011
shared-oracle blindness. In particular: do NOT silence this by editing
derControlTypeBits to match the product. That is the exact failure mode this
test exists to prevent. Change whichever table the STANDARD says is wrong, and
change it because the standard says so.`,
		len(disagreements), strings.Join(disagreements, "\n  "))
}

// compareAgainstProductTable is the tripwire's comparison, factored out so it
// can also be run against a RECORDED table — see the two would-have-caught
// tests, which are what prove this machinery has teeth now that the live
// comparison is green.
//
// It checks BOTH directions. Position -> name catches a bit that means
// something different on the two sides; name -> bit catches an alias that
// resolves somewhere else, which a one-way check would walk straight past.
func compareAgainstProductTable(nameAt func(int) string, bitOf func(string) (uint32, bool)) []string {
	var out []string
	for pos := 0; pos < 32; pos++ {
		schemaName, schemaWhere := "", "IEEE 2030.5-2018 p.252 (\"All other values reserved\")"
		if b, ok := bitAt(uint(pos)); ok {
			schemaName = b.Mode
			schemaWhere = fmt.Sprintf("IEEE 2030.5-2018 p.%d", b.Page)
		}
		productName := nameAt(pos)
		if sameMode(schemaName, productName) {
			continue
		}
		out = append(out, fmt.Sprintf(
			"bit %2d: the standard (%s) assigns %s | lexa-proto/csipmodel assigns %s",
			pos, schemaWhere, quoteOrNothing(schemaName), quoteOrNothing(productName)))
	}
	for _, b := range derControlTypeBits {
		if b.Element == "" {
			continue
		}
		got, ok := bitOf(b.Element)
		if !ok {
			out = append(out, fmt.Sprintf(
				"<%s>: the standard assigns it bit %d (p.%d) | lexa-proto/csipmodel's ModeBit does not "+
					"resolve the name at all", b.Element, b.Bit, b.Page))
			continue
		}
		if want := uint32(1) << b.Bit; got != want {
			out = append(out, fmt.Sprintf(
				"<%s>: the standard assigns it bit %d (p.%d, mask 0x%08X) | lexa-proto/csipmodel's "+
					"ModeBit answers 0x%08X (bit %d)",
				b.Element, b.Bit, b.Page, want, got, singleBit(got)))
		}
	}
	return out
}

// tableTeeth runs the tripwire's comparison against a recorded table and
// requires it to go RED, loudly and in the places named.
//
// Factored out because there are now TWO wrong generations to keep teeth
// against, and a copy-pasted assertion block would have let the second one be
// added with a weaker check than the first.
func tableTeeth(t *testing.T, generation string, recorded map[int]string, wantSubstrings []string,
	minDisagreements int) {
	t.Helper()
	nameAt := func(pos int) string { return recorded[pos] }
	bitOf := func(name string) (uint32, bool) {
		for pos, n := range recorded {
			for _, alt := range strings.Split(n, "/") {
				if strings.EqualFold(strings.TrimSpace(alt), name) {
					return uint32(1) << uint(pos), true
				}
			}
		}
		return 0, false
	}
	got := compareAgainstProductTable(nameAt, bitOf)
	if len(got) == 0 {
		t.Fatalf("the tripwire found NO disagreement with %s. That table is known-wrong against IEEE "+
			"2030.5-2018, so a comparison reporting agreement is broken and every green run of the live "+
			"tripwire is worthless", generation)
	}
	for _, want := range wantSubstrings {
		var found bool
		for _, d := range got {
			if strings.Contains(d, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the tripwire did not report %q against %s:\n  %s",
				want, generation, strings.Join(got, "\n  "))
		}
	}
	if len(got) < minDisagreements {
		t.Errorf("the tripwire reported only %d disagreements against %s; at least %d were expected:\n  %s",
			len(got), generation, minDisagreements, strings.Join(got, "\n  "))
	}
	t.Logf("tripwire against %s — %d disagreements, verbatim:\n  %s",
		generation, len(got), strings.Join(got, "\n  "))
}

// legacyCsipmodelBits is GENERATION 1: lexa-proto/csipmodel's Mode* table AS IT
// STOOD at commit 468f8bf, the state the first version of this oracle was
// written against and the state its own doc comment called a "RECORDED
// DIVERGENCE". Recorded here verbatim, by bit position, from that revision's
// const block.
var legacyCsipmodelBits = map[int]string{
	0: "opModConnect / opModEnergize", 1: "opModMaxLimW", 2: "opModFixedW", 3: "opModFixedVar",
	4: "opModFixedPFAbsorbW", 5: "opModFixedPFInjectW", 6: "opModVoltVar", 7: "opModFreqWatt",
	8: "opModWattPF", 9: "opModVoltWatt", 10: "opModHFRTMayTrip", 11: "opModHFRTMustTrip",
	12: "opModHVRTMayTrip", 13: "opModHVRTMomentaryCessation", 14: "opModHVRTMustTrip",
	15: "opModLFRTMayTrip", 16: "opModLFRTMustTrip", 17: "opModLVRTMayTrip",
	18: "opModLVRTMomentaryCessation", 19: "opModLVRTMustTrip", 20: "opModFreqDroop",
	21: "opModTargetW", 22: "opModTargetVar", 23: "opModExpLimW", 24: "opModImpLimW",
	25: "opModGenLimW", 26: "opModLoadLimW",
}

// draftAnchoredCsipmodelBits is GENERATION 2: the table lexa-proto/csipmodel
// carried between 9856710 and 13e9106, and the table the FIRST version of THIS
// FILE carried at the same time.
//
// It is a faithful transcription of docs/schema/sep-2.0.4.xsd, and it is wrong
// about IEEE 2030.5-2018 at every one of the twenty-seven positions. It is
// preserved because it is the only recorded case of this tripwire going green
// while both sides were wrong, and a suite that kept only the generation-1 teeth
// would be recording the lesson it already knew instead of the one it paid for.
var draftAnchoredCsipmodelBits = map[int]string{
	0: "opModVoltVar", 1: "opModFreqWatt", 2: "opModFreqDroop", 3: "opModWattPF",
	4: "opModVoltWatt", 5: "opModLVRTMomentaryCessation", 6: "opModLVRTMustTrip",
	7: "opModHVRTMomentaryCessation", 8: "opModHVRTMustTrip", 9: "opModLFRTMustTrip",
	10: "opModHFRTMustTrip", 11: "opModConnect", 12: "opModEnergize", 13: "opModMaxLimW",
	14: "opModFixedVar", 15: "opModFixedPF", 16: "opModFixedW", 17: "opModTargetW",
	18: "opModTargetVar", 19: "Charge mode", 20: "Discharge mode", 21: "opModWattVar",
}

// TestModesOracleTripwire_WouldHaveCaughtGeneration1 runs the tripwire's own
// comparison against the table csipmodel carried at 468f8bf and requires it to
// go RED.
func TestModesOracleTripwire_WouldHaveCaughtGeneration1(t *testing.T) {
	tableTeeth(t, "GENERATION 1 (lexa-proto@468f8bf's table)", legacyCsipmodelBits, []string{
		// Its headline mis-assignments under the CORRECT anchor, named so a
		// future edit that weakens the comparison cannot pass by finding some
		// other, cosmetic difference.
		"<opModMaxLimW>: the standard assigns it bit 20",
		"<opModConnect>: the standard assigns it bit 2",
		"<opModVoltVar>: the standard assigns it bit 23",
		"<opModWattVar>",
	}, 16)
}

// TestModesOracleTripwire_WouldHaveCaughtGeneration2_TheDraftAnchoredTable is
// the teeth proof this wave adds, and the more important of the two.
//
// Generation 1 was caught by a comparison whose own table was ALSO wrong: the
// tripwire went red for the right reason by accident, and then went green
// against generation 2 for the wrong reason. This asserts that the comparison,
// re-anchored, would now catch the table that fooled it.
func TestModesOracleTripwire_WouldHaveCaughtGeneration2_TheDraftAnchoredTable(t *testing.T) {
	tableTeeth(t, "GENERATION 2 (the draft-anchored table, csipmodel@9856710 and this file's own "+
		"first version)", draftAnchoredCsipmodelBits, []string{
		// The three numbers the campaign actually depends on, each of which the
		// draft-anchored table gets wrong.
		"<opModMaxLimW>: the standard assigns it bit 20",
		"<opModConnect>: the standard assigns it bit 2",
		"<opModFixedW>: the standard assigns it bit 7",
		// The four modes the draft has no bit for at all — the ones a
		// draft-anchored ModeBit answers "not a mode" for.
		"<opModHFRTMayTrip>",
		"<opModHVRTMayTrip>",
		"<opModLFRTMayTrip>",
		"<opModLVRTMayTrip>",
		// And the absorb/inject pair the draft folds into one.
		"<opModFixedPFAbsorbW>",
		"<opModFixedPFInjectW>",
	}, 27)
}

// TestModesOracleTripwire_TheTwoWrongGenerationsAreThemselvesDifferent guards
// the history against a copy-paste that would quietly reduce three generations
// to two.
func TestModesOracleTripwire_TheTwoWrongGenerationsAreThemselvesDifferent(t *testing.T) {
	same := 0
	for pos := 0; pos < 32; pos++ {
		if legacyCsipmodelBits[pos] != "" && legacyCsipmodelBits[pos] == draftAnchoredCsipmodelBits[pos] {
			same++
		}
	}
	if same > 4 {
		t.Errorf("the two preserved wrong tables agree on %d positions; they are supposed to be two "+
			"DIFFERENT wrong claims (generation 1 was csipmodel's own invention, generation 2 was a "+
			"faithful reading of the draft schema). Check that one has not been pasted over the other",
			same)
	}
	if len(draftAnchoredCsipmodelBits) != 22 {
		t.Errorf("the draft-anchored table has %d entries; sep-2.0.4.xsd assigns 22 bits, 0..21",
			len(draftAnchoredCsipmodelBits))
	}
}

// singleBit reports which bit a single-bit value is, or -1.
func singleBit(v uint32) int {
	for i := 0; i < 32; i++ {
		if v == 1<<uint(i) {
			return i
		}
	}
	return -1
}

func quoteOrNothing(s string) string {
	if s == "" {
		return "no mode"
	}
	return strconv.Quote(s)
}

// sameMode compares the standard's name for a bit with the product's, tolerating
// the two cosmetic differences that are NOT disagreements about bit positions:
// csipmodel keys the two element-less bits by "Charge"/"Discharge" where the
// standard writes "Charge mode"/"Discharge mode", and a name may be written as a
// slash-separated alias list.
func sameMode(schema, product string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), " mode"))
	}
	if norm(schema) == norm(product) {
		return true
	}
	for _, alt := range strings.Split(product, "/") {
		if norm(alt) == norm(schema) {
			return true
		}
	}
	return false
}

// ── (3) Teeth ────────────────────────────────────────────────────────────────

// The masks these fixtures use, named rather than spelled, because every one of
// them MOVED in this wave and a bare hex literal in a fixture is exactly what
// made the previous set survive an anchor change without anyone noticing.
//
// Each is one bit, from IEEE 2030.5-2018 p.251-252.
const (
	maskConnect  = "00000004" // bit 2
	maskFixedW   = "00000080" // bit 7
	maskMaxLimW  = "00100000" // bit 20
	maskVoltVar  = "00800000" // bit 23
	maskVoltWatt = "01000000" // bit 24
	maskNone     = "00000000"
	// bit 27: the first position 2018 reserves. 2023 defines it (opModDeltaVar),
	// which is why the finding has to name both revisions.
	maskReserved27 = "08000000"
	// bits 23|24 — the two curve axes the overclaim proof advertises.
	maskVoltVarAndVoltWatt = "01800000"
)

// capabilityXML builds a DERCapability PUT body carrying a modesSupported.
func capabilityXML(modes string) string {
	return `<DERCapability xmlns="` + Namespace + `"><type>83</type>` +
		`<modesSupported>` + modes + `</modesSupported>` +
		`<rtgMaxW><multiplier>0</multiplier><value>5000</value></rtgMaxW></DERCapability>`
}

// capPUT is the DUT self-report exchange.
func capPUT(modes string) Exchange {
	return Exchange{Req: msg(Request, "PUT", "/edev/0/der/1/dercap", 0, capabilityXML(modes)),
		Resp: msg(Response, "", "", 204, "")}
}

// controlList builds the DERControlList the DUT fetches, one control per
// (mRID, DERControlBase element) pair.
func controlList(controls ...[2]string) Exchange {
	var b strings.Builder
	b.WriteString(`<DERControlList xmlns="` + Namespace + `" all="` +
		strconv.Itoa(len(controls)) + `" results="` + strconv.Itoa(len(controls)) + `">`)
	for _, c := range controls {
		b.WriteString(`<DERControl replyTo="/rsps/0/r" responseRequired="03"><mRID>` + c[0] + `</mRID>` +
			`<DERControlBase><` + c[1] + `>1</` + c[1] + `></DERControlBase></DERControl>`)
	}
	b.WriteString(`</DERControlList>`)
	return get("/derp/0/derc", 200, b.String())
}

// wantModesVerdict runs the oracle's wire arm over a synthetic transcript.
func wantModesVerdict(t *testing.T, name string, tr *Transcript, pics string, want certify.Verdict) Finding {
	t.Helper()
	o := &Observation{Params: map[string]string{}}
	f := critModesSupportedCoherent(o, pics).Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("%s: the oracle declined to decide: %s", name, f.Unavailable)
	}
	if f.Verdict != want {
		t.Fatalf("%s: verdict = %s, want %s\nobserved: %s", name, f.Verdict, want, f.Observed)
	}
	return f
}

func TestModesSupportedOracle_HasTeethBothDirections(t *testing.T) {
	// A coherent DUT: it advertises exactly opModMaxLimW (bit 20 -> 0x00100000)
	// and it executes a control that named <opModMaxLimW>.
	coherent := synthTranscript(
		capPUT(maskMaxLimW),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 1), responsePOST("M-LIM", 2),
	)
	f := wantModesVerdict(t, "coherent", coherent, "", certify.Pass)
	if !strings.Contains(f.Observed, "opModMaxLimW") {
		t.Errorf("the PASS does not name the mode it credited: %q", f.Observed)
	}
	if !strings.Contains(f.Observed, "bit 20 opModMaxLimW") {
		t.Errorf("the PASS does not place opModMaxLimW on IEEE 2030.5-2018's bit 20: %q", f.Observed)
	}

	// ── (b) UNDERCLAIM: executed but not advertised ──────────────────────
	under := synthTranscript(
		capPUT(maskNone),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 1), responsePOST("M-LIM", 2),
	)
	f = wantModesVerdict(t, "executed but not advertised", under, "", certify.Fail)
	for _, want := range []string{"opModMaxLimW", "bit 20", "CLEAR", "Event started", "2030.5-2018 p.252"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the underclaim FAIL omits %q: %s", want, f.Observed)
		}
	}

	// A status=1 (Event received) is NOT an execution. A DUT that merely
	// acknowledged a control has not proven it runs the mode, and grading that
	// as executed would manufacture underclaims out of acknowledgements.
	acked := synthTranscript(
		capPUT(maskNone),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 1),
	)
	f = wantModesVerdict(t, "received but not started", acked, "", certify.Pass)
	if !strings.Contains(f.Observed, "proves NO mode executed") {
		t.Errorf("an acknowledged-only control was not reported as unproven: %q", f.Observed)
	}

	// ── (a) OVERCLAIM: advertised but refused ────────────────────────────
	// opModVoltVar is bit 23. The DUT advertises it and answers the control
	// with the cannot-comply status this product uses (8, partial opt-out).
	over := synthTranscript(
		capPUT(maskVoltVar),
		controlList([2]string{"M-VV", "opModVoltVar"}),
		responsePOST("M-VV", 1), responsePOST("M-VV", 8),
	)
	f = wantModesVerdict(t, "advertised but refused", over, "", certify.Fail)
	for _, want := range []string{"opModVoltVar", "bit 23", "REFUSED", "M-VV"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the overclaim FAIL omits %q: %s", want, f.Observed)
		}
	}

	// The LEXA profile's own refusal code must count the same way.
	overLegacy := synthTranscript(
		capPUT(maskVoltVar),
		controlList([2]string{"M-VV", "opModVoltVar"}),
		responsePOST("M-VV", 0xF0),
	)
	wantModesVerdict(t, "advertised but refused (0xF0)", overLegacy, "", certify.Fail)

	// A DUT that refuses a mode it does NOT advertise is coherent. The refusal
	// is the honest answer; nothing was promised.
	honest := synthTranscript(
		capPUT(maskNone),
		controlList([2]string{"M-VV", "opModVoltVar"}),
		responsePOST("M-VV", 8),
	)
	wantModesVerdict(t, "refused and not advertised", honest, "", certify.Pass)

	// ── (a) OVERCLAIM: a bit the anchor revision does not assign ─────────
	// Bit 27 is the first reserved position under 2018 (p.252).
	res := synthTranscript(capPUT(maskReserved27))
	f = wantModesVerdict(t, "reserved bit set", res, "", certify.Fail)
	for _, want := range []string{"bit 27", "reserved", "p.252"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the reserved-bit FAIL omits %q: %s", want, f.Observed)
		}
	}
	// And it must say that 2023 defines the bit, or a vendor shipping to the
	// newer revision is told it invented a mode.
	for _, want := range []string{"2030.5-2023", "opModDeltaVar"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the reserved-bit FAIL does not disclose that 2030.5-2023 defines bits 27-31 "+
				"(missing %q): %s", want, f.Observed)
		}
	}

	// ── The silent case: advertised, never exercised, no PICS ────────────
	// Not a failure — nothing in the window speaks to it — but it must be
	// DISCLOSED rather than counted as a pass on the merits.
	silent := synthTranscript(capPUT(maskMaxLimW))
	f = wantModesVerdict(t, "advertised, unexercised", silent, "", certify.Pass)
	if !strings.Contains(f.Observed, "neither for nor against") {
		t.Errorf("an unexercised advertised bit was not disclosed: %q", f.Observed)
	}

	// ── The PICS half of direction (a) ───────────────────────────────────
	// With a declaration in hand, an unexercised bit outside it becomes a
	// finding: nobody stands behind it.
	f = wantModesVerdict(t, "advertised outside the PICS", silent, "opModVoltVar", certify.Fail)
	for _, want := range []string{"opModMaxLimW", "PICS", "nobody stands behind"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the PICS overclaim FAIL omits %q: %s", want, f.Observed)
		}
	}
	// Declared, so the same unexercised bit is fine.
	wantModesVerdict(t, "advertised inside the PICS", silent, "opModMaxLimW", certify.Pass)
	// A PICS may name the bit by number too — and the number is now 20.
	wantModesVerdict(t, "PICS by bit number", silent, "20", certify.Pass)
	// The DRAFT's number for the same mode must NOT satisfy the declaration. A
	// PICS transcribed from sep 2.0.4 names bit 13, which under the standard is
	// opModHVRTMomentaryCessation — a different mode this DUT cannot perform.
	wantModesVerdict(t, "PICS by the draft's bit number", silent, "13", certify.Fail)
	// Executed but undeclared: the device and its paperwork disagree.
	f = wantModesVerdict(t, "executed outside the PICS", coherent, "opModVoltVar", certify.Fail)
	if !strings.Contains(f.Observed, "does not declare it") {
		t.Errorf("the device/PICS disagreement is not named: %q", f.Observed)
	}
}

func TestModesSupportedOracle_MalformedAndAbsentMasks(t *testing.T) {
	// modesSupported is [1] (2018 p.246). Absent is a FAIL of the payload, not
	// an unmeasured DUT.
	noField := synthTranscript(Exchange{
		Req: msg(Request, "PUT", "/dercap", 0,
			`<DERCapability xmlns="`+Namespace+`"><type>83</type></DERCapability>`),
		Resp: msg(Response, "", "", 204, ""),
	})
	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, noField)
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "p.246") {
		t.Errorf("a DERCapability with no modesSupported = %s: %s", f.Verdict, f.Observed)
	}

	// Text outside HexBinary32's lexical space.
	bad := synthTranscript(capPUT("zz"))
	f = critModesSupportedCoherent(&Observation{}, "").Wire(nil, bad)
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "HexBinary32") {
		t.Errorf("a non-HexBinary32 mask = %s: %s", f.Verdict, f.Observed)
	}

	// No DERCapability anywhere: undecidable at this tier, NOT a verdict about
	// the DUT. The row's own critDERPut("DERCapability") is where the absence
	// becomes a failure.
	none := synthTranscript(get("/dcap", 200, dcapXML()))
	f = critModesSupportedCoherent(&Observation{}, "").Wire(nil, none)
	if f.Unavailable == "" {
		t.Errorf("a window with no DERCapability produced a verdict (%s) instead of unavailable: %s",
			f.Verdict, f.Observed)
	}
}

// TestModesSupportedOracle_AmbiguousSerializationIsDisclosed pins the reading
// this oracle must never make silently. IEEE 2030.5-2018 p.251 gives
// DERControlType the base HexBinary32, so "1048576" is bits 1/2/4/5/6/8/10/15/
// 18/24 — but a serializer that models the field as a plain uint32 means bit 20
// by exactly those characters. The oracle grades the standard's reading and says
// out loud that the other one exists and what it would have decided.
func TestModesSupportedOracle_AmbiguousSerializationIsDisclosed(t *testing.T) {
	tr := synthTranscript(
		capPUT("1048576"),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 2),
	)
	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide: %s", f.Unavailable)
	}
	// Under HexBinary32 "1048576" does NOT set bit 20, so the executed
	// opModMaxLimW is an underclaim: a decided FAIL, with the decimal reading
	// disclosed as the thing that would have made it pass.
	if f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL under the standard's reading: %s", f.Verdict, f.Observed)
	}
	for _, want := range []string{"AMBIGUOUS SERIALIZATION", "HexBinary32", "0x01048576", "0x00100000"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the ambiguity disclosure omits %q: %s", want, f.Observed)
		}
	}

	// The mirror: a mask that PASSES under the standard's reading but would fail
	// under the decimal one is not a clean pass. It is a pass that rested on a
	// choice the payload left open, and it is downgraded to WARN.
	//   "20" reads as 0x20 = bit 5 (opModFixedPFInjectW) under the standard, and
	//   as 20 = bits 2 and 4 under decimal. The DUT refuses opModConnect
	//   (bit 2), which only the decimal reading advertises.
	warnCase := synthTranscript(
		capPUT("20"),
		controlList([2]string{"M-CONN", "opModConnect"}),
		responsePOST("M-CONN", 8),
	)
	f = critModesSupportedCoherent(&Observation{}, "").Wire(nil, warnCase)
	if f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN where only the standard's reading passes: %s",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "AMBIGUOUS SERIALIZATION") {
		t.Errorf("the WARN does not disclose the ambiguity: %s", f.Observed)
	}

	// LEADING ZEROS settle it, and the disclosure must NOT fire on a zero-padded
	// value: no integer serializer writes "00100000" for one million. Without
	// this rule every conformant eight-digit mask made of decimal digits would
	// carry a spurious ambiguity caveat and lose its PASS to a WARN — and a
	// caveat that fires on the normal case is a caveat nobody reads.
	for _, padded := range []string{"00100000", "0000000B", "00000011", "0"} {
		m, err := parseModesSupported(padded)
		if err != nil {
			t.Fatalf("parse %q: %v", padded, err)
		}
		if m.Ambiguous() {
			t.Errorf("%q was reported ambiguous; a zero-padded (or single-character) text is the "+
				"standard's own rendering and no decimal serializer produces it", padded)
		}
	}
	for _, bare := range []string{"20", "1048576", "13"} {
		m, err := parseModesSupported(bare)
		if err != nil {
			t.Fatalf("parse %q: %v", bare, err)
		}
		if !m.Ambiguous() {
			t.Errorf("%q was NOT reported ambiguous; an unpadded all-decimal text is exactly what both "+
				"a HexBinary32 and an integer serializer could have written", bare)
		}
	}
}

// TestModesSupportedOracle_ServerTierGradesTheMaskAndSaysWhatItCannot pins the
// tier-3 behaviour: gridsim stores the DERCapability body, so the mask itself is
// gradable from the admin API, but the mode<->mRID correspondence exists only in
// the transcript — and the finding must SAY that rather than reporting a
// vacuous pass on the executed-mode direction.
func TestModesSupportedOracle_ServerTierGradesTheMaskAndSaysWhatItCannot(t *testing.T) {
	c := critModesSupportedCoherent(&Observation{}, "")

	// Nothing stored at all: undecidable.
	if f := c.Server(&ServerView{Available: true}); f.Unavailable == "" {
		t.Errorf("an empty server view produced a verdict (%s) instead of unavailable: %s",
			f.Verdict, f.Observed)
	}

	// A reserved bit is decidable from the mask alone, at any tier.
	v := &ServerView{Available: true, DERPuts: []AdminDERPut{
		{Path: "/dercap", Resource: "DERCapability", Body: capabilityXML(maskReserved27)},
	}}
	f := c.Server(v)
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "bit 27") {
		t.Errorf("server tier, reserved bit = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "gridsim stored") {
		t.Errorf("the server-tier finding does not say it was not the wire: %s", f.Observed)
	}
	if !strings.Contains(f.Observed, "not testable at this tier") {
		t.Errorf("the server-tier finding does not disclose what it could NOT check: %s", f.Observed)
	}

	// The run-scoped fallback: the DER self-reports are cadence-driven and
	// routinely land before a narrow window opens.
	runOnly := &ServerView{Available: true, RunDERPuts: []AdminDERPut{
		{Path: "/dercap", Resource: "DERCapability", Body: capabilityXML(maskReserved27)},
	}}
	if f := c.Server(runOnly); f.Verdict != certify.Fail {
		t.Errorf("run-scoped fallback = %s: %s", f.Verdict, f.Observed)
	}
}

// ── The proofs against the product build ────────────────────────────────────

// productDERCapability builds a DERCapability body with the PRODUCT'S OWN
// serializer, carrying whatever mask the caller pins.
//
// The type and the marshalling are lexa-proto/csipmodel's (DERCapabilityFull,
// the same struct lexa-gw's internal/northbound/derreport buildCapability
// fills), so the TEXT these fixtures carry is the text the gateway puts on the
// wire, encoding convention and all. Since lexa-proto 72d91be that convention
// is uppercase hexBinary32, zero-padded to eight digits.
//
// Using csipmodel HERE — in a test, to build the DUT's side of a fixture — is
// the opposite of the thing
// TestModesOracle_DerivesItsBitsFromThePublishedStandardAndNothingInThisTree
// forbids. The product's serializer is the right authority on what the product
// EMITS. It has no standing whatsoever on what those bytes MEAN, and the oracle
// path never asks it.
func productDERCapability(t *testing.T, modes model.HexBinary32) string {
	t.Helper()
	cap := &model.DERCapabilityFull{
		Type:           83, // storage — the battery in the bench census
		ModesSupported: modes,
		RtgMaxW:        model.ActivePower{Multiplier: 0, Value: 5000},
	}
	b, err := xml.Marshal(cap)
	if err != nil {
		t.Fatalf("marshal the product's own DERCapability type: %v", err)
	}
	return string(b)
}

// shippedMask is what lexa-gw advertises under the posture it ships, RE-DERIVED
// against IEEE Std 2030.5-2018 (IW15-027).
//
// derproducer.ModesSupported (internal/derproducer/modes.go) composes the mask
// from the per-device supported-axes screen, and the shipped scalar screen is
// scheduler.ScalarSupportedAxes() = {opModConnect, opModFixedW, opModExpLimW,
// opModMaxLimW, opModGenLimW}. Two of those five are UNADVERTISABLE:
// opModExpLimW and opModGenLimW are CSIP-Aus dynamic-operating-envelope elements
// that NO revision of 2030.5 declares and DERControlType has no bit for, so
// derproducer drops them rather than folding them onto a neighbour. What
// survives is
//
//	bit 2 opModConnect | bit 7 opModFixedW  | bit 20 opModMaxLimW
//	0x00000004         | 0x00000080         | 0x00100000          = 0x00100084
//
// IT USED TO READ 0x00012800, and that value is the whole IW15-027 finding in
// one number. Composed against the draft schema it means bits 11|13|16, which
// the DRAFT reads as opModConnect|opModMaxLimW|opModFixedW — the three modes the
// posture intends. A conformant reader applies the STANDARD and gets
// opModHFRTMustTrip | opModHVRTMomentaryCessation | opModLFRTMustTrip: three
// ride-through modes this product cannot perform, and not one of the three it
// can. The mask was not merely mis-encoded; it advertised the wrong promises to
// a utility server.
//
// The value is written as a LITERAL rather than composed from csipmodel's Mode*
// constants on purpose. This fixture's job is to pin the bytes the product
// ships; composing it from the product's table would make the fixture move
// silently with the table, and the whole point of the surrounding file is that
// the table is a thing to be checked and not a thing to be trusted.
const shippedMask model.HexBinary32 = 0x00100084

// TestModesSupportedOracle_GreenProofAgainstTheShippedTruthfulMask is the
// re-baselined proof: the same oracle, the same evidence, and the mask the
// product PUTs once its own table is anchored to the published standard.
//
// The red shape is not lost:
// TestModesSupportedOracle_RedProofAgainstThePreservedHardcodedZero keeps the
// original, and
// TestModesSupportedOracle_RedProofAgainstThePreservedDraftAnchoredMask keeps
// the one this wave created. A criterion whose only recorded behaviour is
// passing has been demonstrated, not tested.
func TestModesSupportedOracle_GreenProofAgainstTheShippedTruthfulMask(t *testing.T) {
	body := productDERCapability(t, shippedMask)
	// The EMITTED TEXT, not the value: a round-trip through a wrong convention
	// passes happily, so only the bytes can prove the encoding half.
	if !strings.Contains(body, "<modesSupported>00100084</modesSupported>") {
		t.Fatalf("the product's serializer no longer emits the shipped mask as zero-padded hexBinary32; "+
			"this proof's premise has changed and must be re-stated against what it emits now:\n%s", body)
	}

	tr := synthTranscript(
		Exchange{Req: msg(Request, "PUT", "/edev/0/der/1/dercap", 0, body),
			Resp: msg(Response, "", "", 204, "")},
		// The two modes the campaign proves this DUT executes: CORE-022
		// publishes an opModMaxLimW control and asserts the DUT's status=2, and
		// the inverter-control rows drive opModConnect to completion.
		controlList(
			[2]string{"CERT-CORE-022", "opModMaxLimW"},
			[2]string{"CERT-BASIC-011", "opModConnect"},
		),
		responsePOST("CERT-CORE-022", 1), responsePOST("CERT-CORE-022", 2),
		responsePOST("CERT-BASIC-011", 1), responsePOST("CERT-BASIC-011", 3),
	)

	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide against the shipped build: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("the shipped truthful mask graded %s, want PASS. It advertises bits 2/7/20 and the "+
			"evidence proves it executes bits 2 and 20:\n%s", f.Verdict, f.Observed)
	}
	// The PASS must SAY what it credited, or it is indistinguishable from a
	// criterion that found nothing to check.
	for _, want := range []string{
		"00100084", "bit 2 opModConnect", "bit 20 opModMaxLimW", "bit 7 opModFixedW",
		"Modes this evidence PROVES the DUT executed",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the green proof's PASS omits %q:\n%s", want, f.Observed)
		}
	}
	// bit 7 opModFixedW is advertised and this window did not exercise it. That
	// is the disclosed-not-credited case, and it must be disclosed.
	if !strings.Contains(f.Observed, "neither for nor against") {
		t.Errorf("the advertised-but-unexercised bit 7 was not disclosed:\n%s", f.Observed)
	}
	// ZERO-PADDED hex is unambiguous: no serialization caveat may appear, or
	// every conformant mask would carry noise (and lose its PASS to a WARN).
	if strings.Contains(f.Observed, "AMBIGUOUS SERIALIZATION") {
		t.Errorf("a zero-padded hexBinary32 mask was reported ambiguous:\n%s", f.Observed)
	}
	t.Logf("GREEN PROOF (shipped mask 0x00100084), verbatim:\n%s", f.Observed)
}

// TestModesSupportedOracle_RedProofAgainstThePreservedDraftAnchoredMask is the
// teeth proof THIS WAVE adds, and it is the one that shows the anchor mattered
// on the wire rather than only in a comment.
//
// The fixture is the mask lexa-gw PUT between 066b416 and the IW15-027 wave:
// 0x00012800, composed correctly from a table transcribed correctly from the
// wrong document. Every byte of it is defensible and the promise it makes is
// false. Under the published standard those three bits are opModHFRTMustTrip,
// opModHVRTMomentaryCessation and opModLFRTMustTrip — three ride-through modes
// this product does not implement — while opModConnect (bit 2) and opModMaxLimW
// (bit 20), which the campaign PROVES it executes, are clear.
//
// So the oracle must report it in BOTH directions at once: two underclaims and
// three unexercised over-advertisements. The mask is PINNED here, not read from
// the product, for the same reason the tripwire's recorded tables are.
func TestModesSupportedOracle_RedProofAgainstThePreservedDraftAnchoredMask(t *testing.T) {
	const draftAnchoredMask model.HexBinary32 = 0x00012800
	body := productDERCapability(t, draftAnchoredMask)
	if !strings.Contains(body, "<modesSupported>00012800</modesSupported>") {
		t.Fatalf("the preserved draft-anchored fixture no longer emits 00012800:\n%s", body)
	}

	tr := synthTranscript(
		Exchange{Req: msg(Request, "PUT", "/edev/0/der/1/dercap", 0, body),
			Resp: msg(Response, "", "", 204, "")},
		controlList(
			[2]string{"CERT-CORE-022", "opModMaxLimW"},
			[2]string{"CERT-BASIC-011", "opModConnect"},
		),
		responsePOST("CERT-CORE-022", 1), responsePOST("CERT-CORE-022", 2),
		responsePOST("CERT-BASIC-011", 1), responsePOST("CERT-BASIC-011", 3),
	)

	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide against the draft-anchored mask: %s", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("the draft-anchored mask graded %s. It advertises three ride-through modes this DUT "+
			"cannot perform and clears the bits of the two it demonstrably runs; an oracle that does "+
			"not fail that is still reading the draft.\n%s", f.Verdict, f.Observed)
	}
	for _, want := range []string{
		"opModMaxLimW", "bit 20", "opModConnect", "bit 2", "CLEAR", "INCOHERENT in 2 place(s)",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the draft-anchored red proof's FAIL omits %q:\n%s", want, f.Observed)
		}
	}
	// And it must SHOW what the bits actually mean under the standard, or a
	// reader cannot tell this apart from an ordinary underclaim.
	for _, want := range []string{
		"bit 11 opModHFRTMustTrip", "bit 13 opModHVRTMomentaryCessation", "bit 16 opModLFRTMustTrip",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the finding does not render the draft-anchored mask in the STANDARD's vocabulary "+
				"(missing %q), which is the whole content of the defect:\n%s", want, f.Observed)
		}
	}
	t.Logf("RED PROOF, PRESERVED (the draft-anchored shipped mask 0x00012800), verbatim:\n%s", f.Observed)
}

// TestModesSupportedOracle_RedProofAgainstThePreservedHardcodedZero is the
// original historical teeth test, and it survives the anchor change untouched in
// substance: a mask of zero means the same thing under every revision.
//
// The fixture is the DERCapability lexa-gw PUT before 066b416: derproducer.go
// carried, verbatim,
//
//	ModesSupported: 0, // conservative empty truth mask — see package doc
//
// while the campaign had the DUT executing opModMaxLimW (CORE-022 asserts its
// status=2), opModConnect and opModFixedW (BASIC-013 commands it and proves it
// southbound). Every one of those was a mode the DUT ran and did not advertise.
func TestModesSupportedOracle_RedProofAgainstThePreservedHardcodedZero(t *testing.T) {
	body := productDERCapability(t, 0)
	// 0 is the one value that reads identically under both the pre-72d91be
	// decimal emission and the hexBinary one, so this fixture is byte-faithful
	// to the document the product actually PUT — modulo the zero padding, which
	// carries no bits.
	if !strings.Contains(body, "<modesSupported>00000000</modesSupported>") {
		t.Fatalf("the preserved zero fixture no longer emits an all-zero mask:\n%s", body)
	}

	tr := synthTranscript(
		Exchange{Req: msg(Request, "PUT", "/edev/0/der/1/dercap", 0, body),
			Resp: msg(Response, "", "", 204, "")},
		controlList(
			[2]string{"CERT-CORE-022", "opModMaxLimW"},
			[2]string{"CERT-BASIC-011", "opModConnect"},
		),
		responsePOST("CERT-CORE-022", 1), responsePOST("CERT-CORE-022", 2),
		responsePOST("CERT-BASIC-011", 1), responsePOST("CERT-BASIC-011", 3),
	)

	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide against the preserved zero mask: %s", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("the pre-066b416 build graded %s. It PUT modesSupported=0 and executed opModMaxLimW "+
			"and opModConnect; an oracle that does not fail that has no teeth, and the green proof "+
			"above would be worthless.\n%s", f.Verdict, f.Observed)
	}
	for _, want := range []string{
		"opModMaxLimW", "bit 20", "opModConnect", "bit 2", "CLEAR", "INCOHERENT in 2 place(s)",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the preserved red proof's FAIL omits %q:\n%s", want, f.Observed)
		}
	}
	t.Logf("RED PROOF, PRESERVED (pre-066b416 hardcoded zero), verbatim:\n%s", f.Observed)
}

// TestModesSupportedOracle_ModesTheBitmapCannotExpressAreDisclosedNotGraded is
// the third shape the shipped posture makes real, and the disclosure it pins is
// RE-VERIFIED against the published standard rather than inherited.
//
// lexa-gw executes opModExpLimW and opModGenLimW — CSIP-Aus
// dynamic-operating-envelope elements for which DERControlType has no bit at
// all. That was believed on the draft schema's evidence; it is now checked
// against IEEE Std 2030.5-2018, whose DERControlBase attribute listing
// (p.248-251) runs opModConnect..rampTms with no *LimW quartet anywhere, and
// whose DERControlType (p.251-252) assigns twenty-seven bits none of which names
// one. 2030.5-2023 adds bits 27-31 and none of those is a *LimW either. So the
// conclusion survives its own re-derivation, which is the only reason it is
// still allowed to stand.
//
// derproducer drops them from the mask, which is right: there is no position to
// set. But "no underclaim" is not "nothing to say". A mask that cannot express
// two of the five axes a device runs is an incomplete description of it, and a
// reader comparing modesSupported against a campaign transcript has to be told
// which executed modes the field could never have carried, and where they ARE
// declared (the PICS).
func TestModesSupportedOracle_ModesTheBitmapCannotExpressAreDisclosedNotGraded(t *testing.T) {
	// The re-derivation, asserted rather than asserted-in-a-comment: neither
	// name resolves to a bit in the 2018-anchored table.
	for _, name := range []string{"opModExpLimW", "opModGenLimW", "opModImpLimW", "opModLoadLimW"} {
		if b, ok := bitForElement(name); ok {
			t.Fatalf("<%s> resolves to bit %d in the 2018-anchored table. The CSIP-Aus quartet is "+
				"absent from IEEE 2030.5-2018 p.248-251 (DERControlBase) and from its DERControlType "+
				"assignment (p.251-252); a bit for it here is a transcription defect", name, b.Bit)
		}
	}

	tr := synthTranscript(
		Exchange{Req: msg(Request, "PUT", "/edev/0/der/1/dercap", 0, productDERCapability(t, shippedMask)),
			Resp: msg(Response, "", "", 204, "")},
		controlList(
			[2]string{"CERT-CORE-022", "opModMaxLimW"},
			[2]string{"CERT-DOE-EXP", "opModExpLimW"},
			[2]string{"CERT-DOE-GEN", "opModGenLimW"},
		),
		responsePOST("CERT-CORE-022", 2),
		responsePOST("CERT-DOE-EXP", 2),
		responsePOST("CERT-DOE-GEN", 3),
	)
	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS: a mode the standard gives no bit is not an underclaim, and "+
			"demanding a bit that does not exist would fail every conformant CSIP-Aus device\n%s",
			f.Verdict, f.Observed)
	}
	for _, want := range []string{
		"CANNOT express", "<opModExpLimW>", "<opModGenLimW>", "assigns it\nno bit", "PICS",
	} {
		// The finding wraps; compare on the unwrapped text.
		if !strings.Contains(strings.ReplaceAll(f.Observed, "\n", " "),
			strings.ReplaceAll(want, "\n", " ")) {
			t.Errorf("the unadvertisable-mode disclosure omits %q:\n%s", want, f.Observed)
		}
	}
	// It must NOT have been counted as an executed-and-advertised mode either.
	if strings.Contains(f.Observed, "opModExpLimW (bit") {
		t.Errorf("an unadvertisable mode was given a bit:\n%s", f.Observed)
	}
	t.Logf("UNADVERTISABLE-MODE DISCLOSURE, verbatim:\n%s", f.Observed)
}

// TestModesSupportedOracle_RedProofOverclaimDirection is the other half of the
// teeth proof: a synthetic DERCapability with CURVE bits set, against a DUT that
// refuses the axes.
//
// This is not hypothetical. BASIC-004/005/007 exist because this product
// refuses the curve axes at receipt and answers cannot-comply, and the refusal
// rows (curve.go's refusalBinding) assert exactly that. A mask that advertised
// opModVoltVar alongside those refusals would be promising a utility server a
// mode the device declines to perform, and that is the shape below.
func TestModesSupportedOracle_RedProofOverclaimDirection(t *testing.T) {
	// bit 23 opModVoltVar | bit 24 opModVoltWatt = 0x01800000
	tr := synthTranscript(
		capPUT(maskVoltVarAndVoltWatt),
		controlList(
			[2]string{"CERT-BASIC-004", "opModVoltVar"},
			[2]string{"CERT-BASIC-005", "opModVoltWatt"},
		),
		responsePOST("CERT-BASIC-004", 1), responsePOST("CERT-BASIC-004", 8),
		responsePOST("CERT-BASIC-005", 1), responsePOST("CERT-BASIC-005", 0xF0),
	)
	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("a DUT advertising two curve modes it refuses graded %s:\n%s", f.Verdict, f.Observed)
	}
	for _, want := range []string{"opModVoltVar", "opModVoltWatt", "REFUSED", "INCOHERENT in 2 place(s)"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the overclaim FAIL omits %q:\n%s", want, f.Observed)
		}
	}
	t.Logf("RED PROOF (overclaim direction), verbatim:\n%s", f.Observed)
}

// TestCORE014_CarriesTheModesSupportedOracle pins the row placement. CORE-014
// is the only catalog row whose observables name modesSupported at all, and the
// criterion has to be in the list it mints or the oracle is dead code.
//
// It also pins the row's OWN number, which this wave vindicated: CORE-014's
// observables say "modesSupported bit for opModMaxLimW shown as
// modesSupported=20 in the doc", and IEEE 2030.5-2018 p.252 assigns opModMaxLimW
// to bit 20. The catalog was right; the docket entry accusing it is withdrawn.
func TestCORE014_CarriesTheModesSupportedOracle(t *testing.T) {
	o := &Observation{Params: map[string]string{}}
	var found bool
	for _, c := range core014Criteria(o, "") {
		if strings.Contains(c.Claim, "modesSupported") {
			found = true
			if c.Skip == "" {
				t.Errorf("the modesSupported criterion has no Skip reason, so a run that observed no "+
					"DERCapability at all would report an empty explanation: %q", c.Claim)
			}
			if !strings.Contains(c.How, "2030.5-2018") {
				t.Errorf("the criterion's How does not cite the standard it transcribes: %q", c.How)
			}
			if strings.Contains(c.How, "HAND-TRANSCRIBED from lexa-proto docs/schema") {
				t.Errorf("the criterion's How still claims the draft schema as its source: %q", c.How)
			}
		}
	}
	if !found {
		t.Fatalf("CORE-014 mints no modesSupported criterion")
	}
	// The catalog's own number for opModMaxLimW, checked against the anchor.
	b, ok := bitForElement("opModMaxLimW")
	if !ok || b.Bit != 20 {
		t.Fatalf("opModMaxLimW resolves to bit %d (found=%t); CORE-014's observables say 20 and IEEE "+
			"2030.5-2018 p.252 agrees", b.Bit, ok)
	}
}
