package suitecsip

// modes_oracle_test.go proves three separate things about the independent
// modesSupported oracle, and they are separate on purpose:
//
//  1. the TRANSCRIPTION is right — derControlTypeBits says what the schema says
//     (TestModesOracleBitTable_TranscriptionMatchesTheSchemaQuote, and the live
//     cross-check against the schema file itself);
//  2. the ORACLE has teeth in both directions — a DUT that advertises a mode it
//     refuses fails, and a DUT that executes a mode it never advertised fails
//     (TestModesSupportedOracle_HasTeethBothDirections, and the red-proof
//     against the current product build);
//  3. the two TABLES in this tree — this file's transcription and
//     lexa-proto/csipmodel's Mode* constants — either agree, or a human is told
//     to go and adjudicate against the schema
//     (TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong).
//
// # (3) WAS WRITTEN TO BE RED, AND IS GREEN — read this before trusting it
//
// The tripwire was designed against the table lexa-proto's csipmodel/der.go
// then documented under "RECORDED DIVERGENCE": a different assignment entirely,
// with sixteen of the twenty-two schema modes on the wrong bit. It was expected
// to FAIL on delivery, and that failure was to be the deliverable.
//
// lexa-proto 9856710 ("csipmodel: the conformance pass") landed the corrected
// table on 2026-08-15, WHILE this file was being written, from the same schema
// and by a different hand. The two transcriptions now agree, so the tripwire is
// green.
//
// A green tripwire is worth exactly as much as the evidence that it could have
// gone red, and no more — which is why
// TestModesOracleTripwire_WouldHaveCaughtTheTableItWasWrittenFor exists. It
// records the pre-9856710 table verbatim and runs the same comparison against
// it, requiring the disagreement to be reported. Without that, this file would
// contain a check that has only ever been seen passing, which by this suite's
// own rule (teeth_test.go's opening paragraph) has been demonstrated rather
// than tested.
//
// Nothing here is t.Skip'd and nothing is marked "expected failure". This suite
// has no honest mechanism for either: a skipped test reports nothing, and an
// expected-failure marker would go green the day a disagreement is FIXED and
// green again the day a NEW one appears — precisely the blindness the tripwire
// exists to end. The live comparison is a plain assertion; when it fails, its
// text names both claims and sends the reader to the schema, because neither
// this file nor csipmodel has standing to settle it.

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	model "lexa-proto/csipmodel"
)

// ── (1) The transcription ────────────────────────────────────────────────────

// schemaDocQuote is lines 3827-3850 of lexa-proto docs/schema/sep-2.0.4.xsd,
// VERBATIM: the <xs:documentation> of complexType "DERControlType".
//
// It is quoted rather than referenced so that the transcription in
// modes_oracle.go can be checked without the sibling repository present — and
// so that a reviewer comparing this block against the schema is comparing text
// against text, which is a thing a human can actually do. The live schema file
// is compared against this quote too, whenever it is reachable, by
// TestModesOracleBitTable_MatchesTheSchemaFileItself.
const schemaDocQuote = `Control modes supported by the DER.  Bit positions SHALL be defined as follows:
0 - opModVoltVar (Volt-Var Mode)
1 - opModFreqWatt (Frequency-Watt Curve Mode)
2 - opModFreqDroop (Frequency-Watt Parameterized Mode)
3 - opModWattPF (Watt-PowerFactor Mode)
4 - opModVoltWatt (Volt-Watt Mode)
5 - opModLVRTMomentaryCessation (Low Voltage Ride Through, Momentary Cessation Mode)
6 - opModLVRTMustTrip (Low Voltage Ride Through, Must Trip Mode)
7 - opModHVRTMomentaryCessation (High Voltage Ride Through, Momentary Cessation Mode)
8 - opModHVRTMustTrip (High Voltage Ride Through, Must Trip Mode)
9 - opModLFRTMustTrip (Low Frequency Ride Through, Must Trip Mode)
10 - opModHFRTMustTrip (High Frequency Ride Through, Must Trip Mode)
11 - opModConnect (Connect / Disconnect - implies galvanic isolation)
12 - opModEnergize (Energize / De-Energize)
13 - opModMaxLimW (Maximum Active Power)
14 - opModFixedVar (Reactive Power Setpoint)
15 - opModFixedPF (Fixed Power Factor Setpoint)
16 - opModFixedW (Charge / Discharge Setpoint)
17 - opModTargetW (Target Active Power)
18 - opModTargetVar (Target Reactive Power)
19 - Charge mode
20 - Discharge mode
21 - opModWattVar (Watt-Var Mode)
All other values reserved.`

// schemaBitLine matches one assignment line of the quote above.
var schemaBitLine = regexp.MustCompile(`^(\d+) - (\S+)`)

// bitsFromQuote re-derives the assignment from the quoted schema text. It is
// deliberately a DIFFERENT route to the same answer than the hand-written table
// in modes_oracle.go: one is a Go literal a human typed, the other is a parse of
// the standard's own sentence.
func bitsFromQuote(t *testing.T) map[uint]string {
	t.Helper()
	out := map[uint]string{}
	sc := bufio.NewScanner(strings.NewReader(schemaDocQuote))
	for sc.Scan() {
		m := schemaBitLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		pos, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("the schema quote has a non-numeric bit position %q", m[1])
		}
		name := m[2]
		// "19 - Charge mode" and "20 - Discharge mode" are two-word names; the
		// regexp took only the first word, so put the rest back.
		if name == "Charge" || name == "Discharge" {
			name += " mode"
		}
		if prev, dup := out[uint(pos)]; dup {
			t.Fatalf("the schema quote assigns bit %d twice: %q then %q", pos, prev, name)
		}
		out[uint(pos)] = name
	}
	return out
}

func TestModesOracleBitTable_TranscriptionMatchesTheSchemaQuote(t *testing.T) {
	want := bitsFromQuote(t)
	if len(want) != 22 {
		t.Fatalf("the schema quote yields %d bit assignments, want 22 (0..21)", len(want))
	}
	if len(derControlTypeBits) != len(want) {
		t.Fatalf("derControlTypeBits has %d entries, the schema assigns %d", len(derControlTypeBits), len(want))
	}
	seen := map[uint]bool{}
	for _, b := range derControlTypeBits {
		if seen[b.Bit] {
			t.Errorf("derControlTypeBits lists bit %d twice", b.Bit)
		}
		seen[b.Bit] = true
		got, ok := want[b.Bit]
		if !ok {
			t.Errorf("derControlTypeBits assigns bit %d to %q; sep 2.0.4 assigns nothing to it", b.Bit, b.Mode)
			continue
		}
		if got != b.Mode {
			t.Errorf("bit %d: the transcription says %q, sep 2.0.4 line %d says %q",
				b.Bit, b.Mode, b.XSDLine, got)
		}
		// The XSDLine citation must point at the line the quote's own ordering
		// implies: the block starts at 3827 and bit N is on 3828+N.
		if wantLine := 3828 + int(b.Bit); b.XSDLine != wantLine {
			t.Errorf("bit %d cites schema line %d; the DERControlType documentation puts it on line %d",
				b.Bit, b.XSDLine, wantLine)
		}
	}
	// Bits 19 and 20 are the two the schema names without giving them a
	// DERControlBase element. Nothing else may claim that shape, or the oracle
	// would silently stop being able to evidence a mode.
	for _, b := range derControlTypeBits {
		hasElement := b.Element != ""
		wantElement := b.Bit != 19 && b.Bit != 20
		if hasElement != wantElement {
			t.Errorf("bit %d (%s): Element=%q, but sep 2.0.4 %s give this mode a DERControlBase element",
				b.Bit, b.Mode, b.Element, map[bool]string{true: "does", false: "does not"}[wantElement])
		}
		if hasElement && b.ElementLine == 0 {
			t.Errorf("bit %d (%s) names element <%s> without citing its schema line", b.Bit, b.Mode, b.Element)
		}
	}
}

// schemaPath is where the schema lives relative to this package when the
// workspace's sibling module is checked out, which is how go.work is set up
// (`use ../lexa-proto`).
const schemaPath = "../../../../lexa-proto/docs/schema/sep-2.0.4.xsd"

// TestModesOracleBitTable_MatchesTheSchemaFileItself is the belt-and-braces
// half: it re-reads the ACTUAL schema and requires the verbatim quote above to
// still be what the file says, line for line, and every ElementLine citation to
// land on the element it claims.
//
// This is the ONE test in this file that depends on something outside the
// module, so it reports rather than fails when the sibling checkout is absent —
// the hermetic guarantee belongs to
// TestModesOracleBitTable_TranscriptionMatchesTheSchemaQuote, which needs
// nothing but this file. When the schema IS reachable — which is every
// developer machine and the bench — it is a hard check and a drifted quote is a
// failure.
func TestModesOracleBitTable_MatchesTheSchemaFileItself(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(schemaPath))
	if err != nil {
		t.Logf("the live schema cross-check did not run: %v. The hermetic half "+
			"(TestModesOracleBitTable_TranscriptionMatchesTheSchemaQuote) still proves the table "+
			"against the verbatim quote in this file", err)
		return
	}
	lines := strings.Split(string(raw), "\n")
	at := func(n int) string { // 1-based, like an editor and like the citations
		if n < 1 || n > len(lines) {
			t.Fatalf("sep-2.0.4.xsd has %d lines; a citation names line %d", len(lines), n)
		}
		return lines[n-1]
	}

	// The quote, line for line. Line 3827 carries the <xs:documentation> open
	// tag and line 3850 the close tag, so those two are compared on their
	// content rather than byte-for-byte.
	quote := strings.Split(schemaDocQuote, "\n")
	if got, want := at(3827), "      <xs:documentation>"+quote[0]; got != want {
		t.Errorf("schema line 3827 has drifted from the quote:\n file: %q\nquote: %q", got, want)
	}
	for i := 1; i < len(quote)-1; i++ {
		if got := at(3827 + i); got != quote[i] {
			t.Errorf("schema line %d has drifted from the quote:\n file: %q\nquote: %q",
				3827+i, got, quote[i])
		}
	}
	if got, want := at(3850), quote[len(quote)-1]+"</xs:documentation>"; got != want {
		t.Errorf("schema line 3850 has drifted from the quote:\n file: %q\nquote: %q", got, want)
	}
	// HexBinary32 is the base this oracle decodes modesSupported as.
	if got := strings.TrimSpace(at(3853)); got != `<xs:extension base="HexBinary32" />` {
		t.Errorf("schema line 3853 no longer declares DERControlType's base as HexBinary32: %q", got)
	}
	// modesSupported's own declaration, which is what makes it mandatory.
	if got := strings.TrimSpace(at(3571)); !strings.Contains(got, `name="modesSupported"`) ||
		!strings.Contains(got, `minOccurs="1"`) || !strings.Contains(got, `type="DERControlType"`) {
		t.Errorf("schema line 3571 no longer declares modesSupported minOccurs=1 type=DERControlType: %q", got)
	}
	// Every element citation must land on that element's declaration.
	for _, b := range derControlTypeBits {
		if b.Element == "" {
			continue
		}
		if got := at(b.ElementLine); !strings.Contains(got, `name="`+b.Element+`"`) {
			t.Errorf("bit %d cites schema line %d for element <%s>; that line reads %q",
				b.Bit, b.ElementLine, b.Element, strings.TrimSpace(got))
		}
	}
}

// TestModesOracle_DerivesItsBitsFromTheSchemaAndNotFromTheProduct is the
// structural half of the IW15-011 rule: the ORACLE PATH may not reference the
// product's table at all. A future edit that reaches for csipmodel.Mode* to
// "simplify" the decode would re-create the exact blindness this file exists to
// end, and it would do it silently — every row would keep passing.
func TestModesOracle_DerivesItsBitsFromTheSchemaAndNotFromTheProduct(t *testing.T) {
	src, err := os.ReadFile("modes_oracle.go")
	if err != nil {
		t.Fatalf("read the oracle's own source: %v", err)
	}
	// The doc comment legitimately NAMES csipmodel to explain why it is not
	// used, so the check is on the import and on the constants, not on the word.
	body := string(src)
	for _, forbidden := range []string{`"lexa-proto/csipmodel"`, "csipmodel.Mode", "model.Mode"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("modes_oracle.go references %s. The oracle's bit positions must come from the "+
				"hand transcription of sep-2.0.4.xsd and from nothing else: a decode that asks the "+
				"product's own table what the product's own table means cannot fail, which is the "+
				"IW15-011 shared-oracle blindness this file was written to end", forbidden)
		}
	}
}

// ── (3) The tripwire ─────────────────────────────────────────────────────────

// TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong is THE
// TRIPWIRE.
//
// Two tables in this tree claim to say which bit of DERCapability.modesSupported
// means which operating mode. One of them is written to the wire by the product
// (lexa-proto/csipmodel, via lexa-gw's derproducer). The other is what this
// harness grades against (derControlTypeBits, transcribed from the schema by
// hand, in modes_oracle.go). While they disagree, at least one of them is
// wrong; and a campaign in which BOTH sides read the same wrong table would
// report green forever — the IW15-011 shared-oracle blindness, and the same
// defect that let the DERCurveType codes be wrong for every value >= 4 for
// months without a single one of 282 catalog rows noticing.
//
// It does NOT assert that the harness is right. It asserts that the two AGREE,
// and when they do not it prints both claims for every position and sends the
// reader to sep-2.0.4.xsd, which is the only document with standing to settle
// it.
//
// # State on 2026-08-15
//
// This test was written to be RED: at the time the oracle was designed,
// csipmodel's table was the one its own doc comment called a "RECORDED
// DIVERGENCE" — a different assignment entirely, sixteen of twenty-two modes on
// the wrong bit. lexa-proto 9856710 ("csipmodel: the conformance pass") landed
// the correction while this file was being written, so the two tables now
// agree and the test is GREEN.
//
// That green is worth something precisely because the two transcriptions were
// made independently, from the same schema, by different hands, and neither
// consulted the other: agreement between two independent readings is evidence,
// where agreement between a reading and a copy of itself is not. It stays here
// as a standing tripwire — the day either table moves without the other, this
// fails and names both claims.
//
// The comparison goes through csipmodel's PUBLIC projection (ModeBit /
// ModeBitName) rather than through its constants, for two reasons: it is what
// the product's own consumers use to build a mask, so it is the mapping that
// actually reaches the wire; and it survives a rename of a constant, which a
// hand-copied constant list does not.
func TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong(t *testing.T) {
	disagreements := compareAgainstProductTable(model.ModeBitName, model.ModeBit)
	if len(disagreements) == 0 {
		return
	}
	t.Fatalf(`the two modesSupported bit tables in this tree DISAGREE in %d position(s).

This is not a statement that either side is right. It is a statement that they
cannot both be, and that a human has to open the schema and decide:

    lexa-proto docs/schema/sep-2.0.4.xsd, complexType "DERControlType",
    lines 3827-3850 — "Bit positions SHALL be defined as follows".

The two claims:

  %s

Whichever way it is settled, BOTH tables move together, or the next campaign is
graded by a referee that agrees with the thing it is grading — the IW15-011
shared-oracle blindness. In particular: do NOT silence this by editing
derControlTypeBits to match the product. That is the exact failure mode this
test exists to prevent. Change whichever table the SCHEMA says is wrong, and
change it because the schema says so.`,
		len(disagreements), strings.Join(disagreements, "\n  "))
}

// compareAgainstProductTable is the tripwire's comparison, factored out so it
// can also be run against a RECORDED table — see
// TestModesOracleTripwire_WouldHaveCaughtTheTableItWasWrittenFor, which is what
// proves this machinery has teeth now that the live comparison is green.
//
// It checks BOTH directions. Position -> name catches a bit that means
// something different on the two sides; name -> bit catches an alias that
// resolves somewhere else, which a one-way check would walk straight past.
func compareAgainstProductTable(nameAt func(int) string, bitOf func(string) (uint32, bool)) []string {
	var out []string
	for pos := 0; pos < 32; pos++ {
		schemaName, schemaWhere := "", "sep-2.0.4.xsd line 3850 (\"All other values reserved\")"
		if b, ok := bitAt(uint(pos)); ok {
			schemaName = b.Mode
			schemaWhere = fmt.Sprintf("sep-2.0.4.xsd line %d", b.XSDLine)
		}
		productName := nameAt(pos)
		if sameMode(schemaName, productName) {
			continue
		}
		out = append(out, fmt.Sprintf(
			"bit %2d: the schema (%s) assigns %s | lexa-proto/csipmodel assigns %s",
			pos, schemaWhere, quoteOrNothing(schemaName), quoteOrNothing(productName)))
	}
	for _, b := range derControlTypeBits {
		if b.Element == "" {
			continue
		}
		got, ok := bitOf(b.Element)
		if !ok {
			out = append(out, fmt.Sprintf(
				"<%s>: the schema assigns it bit %d (line %d) | lexa-proto/csipmodel's ModeBit does not "+
					"resolve the name at all", b.Element, b.Bit, b.XSDLine))
			continue
		}
		if want := uint32(1) << b.Bit; got != want {
			out = append(out, fmt.Sprintf(
				"<%s>: the schema assigns it bit %d (line %d, mask 0x%08X) | lexa-proto/csipmodel's "+
					"ModeBit answers 0x%08X (bit %d)",
				b.Element, b.Bit, b.XSDLine, want, got, singleBit(got)))
		}
	}
	return out
}

// legacyCsipmodelBits is lexa-proto/csipmodel's Mode* table AS IT STOOD at
// commit 468f8bf, the state this oracle was written against and the state its
// own doc comment called a "RECORDED DIVERGENCE". Recorded here verbatim, by
// bit position, from that revision's const block.
//
// It exists so the tripwire's TEETH survive the fix. lexa-proto 9856710 landed
// the corrected table while this file was being written, so the live comparison
// is green — and a green comparison proves nothing about whether the comparison
// could ever have gone red. This does.
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

// TestModesOracleTripwire_WouldHaveCaughtTheTableItWasWrittenFor runs the
// tripwire's own comparison against the table csipmodel carried at 468f8bf and
// requires it to go RED, loudly and in the right places.
//
// This is the teeth proof for the tripwire itself. Without it,
// TestModesOracleBitTable_AgreesWithCsipmodelOrOneOfThemIsWrong is a test that
// has only ever been seen passing, which — by this suite's own rule (see
// teeth_test.go's opening) — has been demonstrated rather than tested.
func TestModesOracleTripwire_WouldHaveCaughtTheTableItWasWrittenFor(t *testing.T) {
	nameAt := func(pos int) string { return legacyCsipmodelBits[pos] }
	bitOf := func(name string) (uint32, bool) {
		for pos, n := range legacyCsipmodelBits {
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
		t.Fatalf("the tripwire found NO disagreement with the table csipmodel carried at 468f8bf. That " +
			"table put opModMaxLimW on bit 1 where sep 2.0.4 line 3841 puts it on bit 13, so a " +
			"comparison that reports agreement is broken and every green run of the live tripwire is " +
			"worthless")
	}
	// The headline mis-assignments, named so a future edit that weakens the
	// comparison cannot pass by finding some other, cosmetic difference.
	for _, want := range []string{
		"<opModMaxLimW>: the schema assigns it bit 13",
		"<opModConnect>: the schema assigns it bit 11",
		"<opModVoltVar>: the schema assigns it bit 0",
		"<opModWattVar>",
	} {
		var found bool
		for _, d := range got {
			if strings.Contains(d, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the tripwire did not report %q against the 468f8bf table:\n  %s",
				want, strings.Join(got, "\n  "))
		}
	}
	if len(got) < 16 {
		t.Errorf("the tripwire reported only %d disagreements against the 468f8bf table; sixteen of the "+
			"twenty-two schema modes were on the wrong bit there:\n  %s", len(got), strings.Join(got, "\n  "))
	}
	t.Logf("tripwire against lexa-proto@468f8bf's table — %d disagreements, verbatim:\n  %s",
		len(got), strings.Join(got, "\n  "))
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

// sameMode compares the schema's name for a bit with the product's, tolerating
// the two cosmetic differences that are NOT disagreements about bit positions:
// csipmodel keys bits 19 and 20 by "Charge"/"Discharge" where the schema writes
// "Charge mode"/"Discharge mode", and a name may be written as a slash-separated
// alias list.
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

// ── (2) Teeth ────────────────────────────────────────────────────────────────

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
	// A coherent DUT: it advertises exactly opModMaxLimW (bit 13 -> 0x2000)
	// and it executes a control that named <opModMaxLimW>.
	coherent := synthTranscript(
		capPUT("00002000"),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 1), responsePOST("M-LIM", 2),
	)
	f := wantModesVerdict(t, "coherent", coherent, "", certify.Pass)
	if !strings.Contains(f.Observed, "opModMaxLimW") {
		t.Errorf("the PASS does not name the mode it credited: %q", f.Observed)
	}

	// ── (b) UNDERCLAIM: executed but not advertised ──────────────────────
	under := synthTranscript(
		capPUT("00000000"),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 1), responsePOST("M-LIM", 2),
	)
	f = wantModesVerdict(t, "executed but not advertised", under, "", certify.Fail)
	for _, want := range []string{"opModMaxLimW", "bit 13", "CLEAR", "Event started"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the underclaim FAIL omits %q: %s", want, f.Observed)
		}
	}

	// A status=1 (Event received) is NOT an execution. A DUT that merely
	// acknowledged a control has not proven it runs the mode, and grading that
	// as executed would manufacture underclaims out of acknowledgements.
	acked := synthTranscript(
		capPUT("00000000"),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 1),
	)
	f = wantModesVerdict(t, "received but not started", acked, "", certify.Pass)
	if !strings.Contains(f.Observed, "proves NO mode executed") {
		t.Errorf("an acknowledged-only control was not reported as unproven: %q", f.Observed)
	}

	// ── (a) OVERCLAIM: advertised but refused ────────────────────────────
	// opModVoltVar is bit 0. The DUT advertises it and answers the control
	// with the cannot-comply status this product uses (8, partial opt-out).
	over := synthTranscript(
		capPUT("00000001"),
		controlList([2]string{"M-VV", "opModVoltVar"}),
		responsePOST("M-VV", 1), responsePOST("M-VV", 8),
	)
	f = wantModesVerdict(t, "advertised but refused", over, "", certify.Fail)
	for _, want := range []string{"opModVoltVar", "bit 0", "REFUSED", "M-VV"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the overclaim FAIL omits %q: %s", want, f.Observed)
		}
	}

	// The LEXA profile's own refusal code must count the same way.
	overLegacy := synthTranscript(
		capPUT("00000001"),
		controlList([2]string{"M-VV", "opModVoltVar"}),
		responsePOST("M-VV", 0xF0),
	)
	wantModesVerdict(t, "advertised but refused (0xF0)", overLegacy, "", certify.Fail)

	// A DUT that refuses a mode it does NOT advertise is coherent. The refusal
	// is the honest answer; nothing was promised.
	honest := synthTranscript(
		capPUT("00000000"),
		controlList([2]string{"M-VV", "opModVoltVar"}),
		responsePOST("M-VV", 8),
	)
	wantModesVerdict(t, "refused and not advertised", honest, "", certify.Pass)

	// ── (a) OVERCLAIM: a bit the schema does not assign ──────────────────
	// Bit 22 is the first reserved position (line 3850).
	res := synthTranscript(capPUT("00400000"))
	f = wantModesVerdict(t, "reserved bit set", res, "", certify.Fail)
	for _, want := range []string{"bit 22", "reserved", "3850"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the reserved-bit FAIL omits %q: %s", want, f.Observed)
		}
	}

	// ── The silent case: advertised, never exercised, no PICS ────────────
	// Not a failure — nothing in the window speaks to it — but it must be
	// DISCLOSED rather than counted as a pass on the merits.
	silent := synthTranscript(capPUT("00002000"))
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
	// A PICS may name the bit by number too.
	wantModesVerdict(t, "PICS by bit number", silent, "13", certify.Pass)
	// Executed but undeclared: the device and its paperwork disagree.
	f = wantModesVerdict(t, "executed outside the PICS", coherent, "opModVoltVar", certify.Fail)
	if !strings.Contains(f.Observed, "does not declare it") {
		t.Errorf("the device/PICS disagreement is not named: %q", f.Observed)
	}
}

func TestModesSupportedOracle_MalformedAndAbsentMasks(t *testing.T) {
	// modesSupported is minOccurs=1 (schema line 3571). Absent is a FAIL of the
	// payload, not an unmeasured DUT.
	noField := synthTranscript(Exchange{
		Req: msg(Request, "PUT", "/dercap", 0,
			`<DERCapability xmlns="`+Namespace+`"><type>83</type></DERCapability>`),
		Resp: msg(Response, "", "", 204, ""),
	})
	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, noField)
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "minOccurs=1") {
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
// this oracle must never make silently. sep 2.0.4 gives DERControlType the base
// HexBinary32 (line 3853), so "8192" is bits 1/4/7/8/15 — but a serializer that
// models the field as a plain uint32 means bit 13 by exactly those characters.
// The oracle grades the schema reading and says out loud that the other one
// exists and what it would have decided.
func TestModesSupportedOracle_AmbiguousSerializationIsDisclosed(t *testing.T) {
	tr := synthTranscript(
		capPUT("8192"),
		controlList([2]string{"M-LIM", "opModMaxLimW"}),
		responsePOST("M-LIM", 2),
	)
	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide: %s", f.Unavailable)
	}
	// Under HexBinary32 "8192" does NOT set bit 13, so the executed
	// opModMaxLimW is an underclaim: a decided FAIL, with the decimal reading
	// disclosed as the thing that would have made it pass.
	if f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL under the schema reading: %s", f.Verdict, f.Observed)
	}
	for _, want := range []string{"AMBIGUOUS SERIALIZATION", "HexBinary32", "0x00008192", "0x00002000"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the ambiguity disclosure omits %q: %s", want, f.Observed)
		}
	}

	// The mirror: a mask that PASSES under the schema reading but would fail
	// under the decimal one is not a clean pass. It is a pass that rested on a
	// choice the payload left open, and it is downgraded to WARN.
	//   "20" reads as 0x20 = bit 5 (opModLVRTMomentaryCessation) under the
	//   schema, and as 20 = bits 2 and 4 under decimal. The DUT refuses
	//   opModFreqDroop (bit 2), which only the decimal reading advertises.
	warnCase := synthTranscript(
		capPUT("20"),
		controlList([2]string{"M-FD", "opModFreqDroop"}),
		responsePOST("M-FD", 8),
	)
	f = critModesSupportedCoherent(&Observation{}, "").Wire(nil, warnCase)
	if f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN where only the schema reading passes: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "AMBIGUOUS SERIALIZATION") {
		t.Errorf("the WARN does not disclose the ambiguity: %s", f.Observed)
	}

	// LEADING ZEROS settle it, and the disclosure must NOT fire on a zero-padded
	// value: no integer serializer writes "00002000" for two thousand. Without
	// this rule every conformant eight-digit mask made of decimal digits would
	// carry a spurious ambiguity caveat and lose its PASS to a WARN — and a
	// caveat that fires on the normal case is a caveat nobody reads.
	for _, padded := range []string{"00002000", "0000000B", "00000011", "0"} {
		m, err := parseModesSupported(padded)
		if err != nil {
			t.Fatalf("parse %q: %v", padded, err)
		}
		if m.Ambiguous() {
			t.Errorf("%q was reported ambiguous; a zero-padded (or single-character) text is the "+
				"schema's own rendering and no decimal serializer produces it", padded)
		}
	}
	for _, bare := range []string{"20", "8192", "13"} {
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
		{Path: "/dercap", Resource: "DERCapability", Body: capabilityXML("00400000")},
	}}
	f := c.Server(v)
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "bit 22") {
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
		{Path: "/dercap", Resource: "DERCapability", Body: capabilityXML("00400000")},
	}}
	if f := c.Server(runOnly); f.Verdict != certify.Fail {
		t.Errorf("run-scoped fallback = %s: %s", f.Verdict, f.Observed)
	}
}

// ── The red proof against the current product build ──────────────────────────

// productDERCapabilityToday is the DERCapability body the CURRENT product
// build serves, assembled by the PRODUCT'S OWN serializer.
//
// The type and the marshalling are lexa-proto/csipmodel's
// (DERCapabilityFull, the same struct lexa-gw's
// internal/northbound/derreport buildCapability fills). The ModesSupported
// VALUE is 0 because lexa-gw's internal/derproducer/derproducer.go line 244
// sets it so, verbatim:
//
//	ModesSupported: 0, // conservative empty truth mask — see package doc
//
// Nothing else in lexa-gw writes that field, so 0 is what every DERCapability
// this product PUTs carries today. Running this file's oracle over it, in a
// window where the product demonstrably executed opModMaxLimW and
// opModConnect, is the red proof: the underclaim direction has to fire, and
// the FAIL below is captured verbatim in the handoff.
//
// Using csipmodel HERE — in a test, to build the DUT's side of the fixture — is
// the opposite of the thing TestModesOracle_DerivesItsBitsFromTheSchemaAndNotFromTheProduct
// forbids. The product's serializer is the right authority on what the product
// emits. It has no standing whatsoever on what the bytes MEAN, and the oracle
// path never asks it.
func productDERCapabilityToday(t *testing.T) string {
	t.Helper()
	cap := &model.DERCapabilityFull{
		Type:           83, // storage — the battery in the bench census
		ModesSupported: 0,  // lexa-gw internal/derproducer/derproducer.go:244
		RtgMaxW:        model.ActivePower{Multiplier: 0, Value: 5000},
	}
	b, err := xml.Marshal(cap)
	if err != nil {
		t.Fatalf("marshal the product's own DERCapability type: %v", err)
	}
	return string(b)
}

// TestModesSupportedOracle_RedProofAgainstTheCurrentProductBuild is the
// Stage-7/9 red proof, run hermetically.
//
// The product PUTs modesSupported=0 while the campaign has it executing scalar
// modes — BASIC-013 commands opModFixedW and proves it southbound, CORE-022
// publishes an opModMaxLimW control and asserts the DUT's status=2 (Event
// started) for it, and the inverter-control rows drive opModConnect. Every one
// of those is a mode the DUT runs and does not advertise, and until the mask
// becomes truthful this oracle MUST report it. A green run here would mean the
// oracle had no teeth.
//
// When the product's mask becomes truthful this test does not go green by
// itself: the fixture is pinned to modesSupported=0 (the value derproducer sets
// TODAY, cited above) so that it keeps proving the ORACLE rather than tracking
// the product. Whoever lands the truthful mask should update the cited line and
// keep the assertion.
func TestModesSupportedOracle_RedProofAgainstTheCurrentProductBuild(t *testing.T) {
	body := productDERCapabilityToday(t)
	if !strings.Contains(body, "<modesSupported>0</modesSupported>") {
		t.Fatalf("the product's DERCapability no longer carries modesSupported=0; this red proof's "+
			"premise has changed and the test must be re-stated against what it carries now: %s", body)
	}

	tr := synthTranscript(
		Exchange{Req: msg(Request, "PUT", "/edev/0/der/1/dercap", 0, body),
			Resp: msg(Response, "", "", 204, "")},
		// The two modes the campaign proves this DUT executes.
		controlList(
			[2]string{"CERT-CORE-022", "opModMaxLimW"},
			[2]string{"CERT-BASIC-011", "opModConnect"},
		),
		responsePOST("CERT-CORE-022", 1), responsePOST("CERT-CORE-022", 2),
		responsePOST("CERT-BASIC-011", 1), responsePOST("CERT-BASIC-011", 3),
	)

	f := critModesSupportedCoherent(&Observation{}, "").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide against the current product build: %s", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("the current product build graded %s. It PUTs modesSupported=0 and executes "+
			"opModMaxLimW and opModConnect; an oracle that does not fail that has no teeth.\n%s",
			f.Verdict, f.Observed)
	}
	for _, want := range []string{
		"opModMaxLimW", "bit 13", "opModConnect", "bit 11", "CLEAR", "INCOHERENT in 2 place(s)",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the red proof's FAIL omits %q:\n%s", want, f.Observed)
		}
	}
	t.Logf("RED PROOF (underclaim direction), verbatim:\n%s", f.Observed)
}

// TestModesSupportedOracle_RedProofOverclaimDirection is the other half of the
// teeth proof the handoff asks for: a synthetic DERCapability with a CURVE bit
// set, against a DUT that refuses the axis.
//
// This is not hypothetical. BASIC-004/005/007 exist because this product
// refuses the curve axes at receipt and answers cannot-comply, and the refusal
// rows (curve.go's refusalBinding) assert exactly that. A mask that advertised
// opModVoltVar alongside those refusals would be promising a utility server a
// mode the device declines to perform, and that is the shape below.
func TestModesSupportedOracle_RedProofOverclaimDirection(t *testing.T) {
	// bit 0 opModVoltVar | bit 4 opModVoltWatt = 0x00000011
	tr := synthTranscript(
		capPUT("00000011"),
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
			if !strings.Contains(c.How, "sep-2.0.4.xsd") {
				t.Errorf("the criterion's How does not cite the schema it transcribes: %q", c.How)
			}
		}
	}
	if !found {
		t.Fatalf("CORE-014 mints no modesSupported criterion")
	}
}
