package suitecsip

// mup_oracle_test.go proves the MirrorUsagePoint content oracle four ways:
//
//  1. the TRANSCRIPTION is right — roleFlagBits says what IEEE Std 2030.5-2018
//     p.169 says, checked against a verbatim quote and, where the corpus is
//     reachable, against the published PDF itself;
//  2. the ORACLE has teeth on each CLASS of claim — the resource-decidable bit,
//     the complementary pair, the evidenced bit, the reserved range;
//  3. it does NOT invent facts — a claim about the installation that the wire
//     cannot settle is disclosed and never graded, absent a PICS;
//  4. it is RED against the product, in two distinct shapes, and each shape says
//     which fix cures it.
//
// # The two red proofs, and why there are two
//
// The product's MirrorUsagePoint had TWO independent defects, and they are
// closed by changes in two different repositories:
//
//	THE MISSING MANDATORY ELEMENT is cured by lexa-proto 13e9106 alone. That
//	commit removed `omitempty` from UsagePointBase's three [1] elements, so the
//	moment lexa-gw re-vendors, serviceCategoryKind appears on the wire with no
//	product edit at all. TestMUPOracle_RedProofAgainstThePreservedPreFixBytes
//	pins the OLD bytes as a literal so that cure cannot erase its own evidence.
//
//	THE WRONG roleFlags VALUE is not cured by anything upstream. 0x0002 is a
//	number cmd/telemetry writes, and no schema change moves it; lexa-gw has to
//	change what it MEANS to say. TestMUPOracle_RedProofAgainstTheShippedRoleFlags
//	builds the resource with the product's CURRENT serializer and the product's
//	pinned literal, so it is red against a re-vendored build too — which is the
//	honest thing for a harness to be while the product wave is still in flight.
//
// Both fixtures are PINNED rather than read from the product, on the rule the
// modes oracle's preserved masks follow: a teeth test that tracked the product
// would go green the moment the product was fixed, taking the evidence of its
// own teeth with it.

import (
	"encoding/xml"
	"os"
	"os/exec"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	model "lexa-proto/csipmodel"
)

// ── (1) The transcription ────────────────────────────────────────────────────

// roleFlags2018Quote is IEEE Std 2030.5-2018, PRINTED PAGE 169, VERBATIM: the
// "RoleFlagsType object" definition and its seven bit assignments.
//
// Quoted rather than referenced because the standard is a purchased IEEE
// document that cannot be committed — which is exactly what makes it an
// independent witness (see mup_oracle.go's independence note and the IW15-027
// lesson behind it).
const roleFlags2018Quote = `RoleFlagsType object (HexBinary16)
Specifies the roles that apply to a usage point.
Bit 0—isMirror—SHALL be set if the server is not the measurement device
Bit 1—isPremisesAggregationPoint—SHALL be set if the UsagePoint is the point of delivery for a
premises
Bit 2—isPEV—SHALL be set if the usage applies to an electric vehicle
Bit 3—isDER—SHALL be set if the usage applies to a distributed energy resource, capable of delivering
power to the grid
Bit 4—isRevenueQuality—SHALL be set if usage was measured by a device certified as revenue quality
Bit 5—isDC—SHALL be set if the usage point measures direct current
Bit 6—isSubmeter—SHALL be set if the usage point is not a premises aggregation point
Bit 7 to 15—Reserved`

// TestMUPOracle_RoleFlagTranscriptionMatchesThe2018Quote rebuilds the table from
// the quoted standard text — a different route to the same answer than the Go
// literal in mup_oracle.go.
func TestMUPOracle_RoleFlagTranscriptionMatchesThe2018Quote(t *testing.T) {
	// The quote wraps mid-sentence where the printed page does, so it is joined
	// before parsing: a line break inside a SHALL is a fact about the page, not
	// about the rule.
	joined := strings.ReplaceAll(roleFlags2018Quote, "\n", " ")
	if len(roleFlagBits) != 7 {
		t.Fatalf("roleFlagBits has %d entries; IEEE 2030.5-2018 p.169 assigns 7 (bits 0..6)",
			len(roleFlagBits))
	}
	seen := map[uint]bool{}
	for _, b := range roleFlagBits {
		if seen[b.Bit] {
			t.Errorf("roleFlagBits lists bit %d twice", b.Bit)
		}
		seen[b.Bit] = true
		// The standard writes "Bit N—name—SHALL ..." with em dashes. The
		// transcription must reproduce the name AND the sentence exactly, in
		// that order, which is a stronger check than either alone.
		want := "Bit " + itoa(int64(b.Bit)) + "\u2014" + b.Name + "\u2014" + b.SHALL
		if !strings.Contains(joined, want) {
			t.Errorf("the 2018 quote does not contain the transcribed row %q.\nQuote:\n%s",
				want, roleFlags2018Quote)
		}
	}
	if !strings.Contains(joined, "Bit 7 to 15\u2014Reserved") {
		t.Error("the 2018 quote no longer carries the reserved-range sentence, which is the whole " +
			"warrant for grading bits 7..15")
	}
	if roleFlagsReservedFrom != 7 {
		t.Errorf("roleFlagsReservedFrom = %d; the standard reserves 7 to 15", roleFlagsReservedFrom)
	}
	// The complementary pair must point at each other, or the pair check reads
	// one bit against a bit that is not its partner.
	for _, b := range roleFlagBits {
		if b.Class != roleFlagComplementary {
			continue
		}
		p, ok := roleFlagAt(b.Partner)
		if !ok || p.Class != roleFlagComplementary || p.Partner != b.Bit {
			t.Errorf("bit %d %s names partner %d, which does not name it back as a complementary bit",
				b.Bit, b.Name, b.Partner)
		}
	}
}

// TestMUPOracle_RoleFlagsMatchThePublishedStandardItself is the independent
// half: it re-extracts printed page 169 from the corpus copy of the standard and
// requires every SHALL sentence to still be there.
//
// It reports rather than fails when the document or a PDF text extractor is
// absent — a CI runner has neither — exactly like the modes oracle's equivalent.
func TestMUPOracle_RoleFlagsMatchThePublishedStandardItself(t *testing.T) {
	pdf := standardPDFPath()
	if pdf == "" {
		t.Log("the live standard cross-check did not run: no home directory to resolve the corpus path")
		return
	}
	if _, err := os.Stat(pdf); err != nil {
		t.Logf("the live standard cross-check did not run: %v. Set IEEE_20305_2018_PDF to a local copy "+
			"to enable it; the hermetic half still proves the table against the quote in this file", err)
		return
	}
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Logf("the live standard cross-check did not run: pdftotext is not installed (%v)", err)
		return
	}
	// PDF page 170 == printed page 169.
	out, err := exec.Command(tool, "-f", "170", "-l", "170", "-layout", pdf, "-").Output()
	if err != nil {
		t.Fatalf("extracting printed page 169 of %s failed: %v", pdf, err)
	}
	text := strings.Join(strings.Fields(string(out)), " ")
	for _, b := range roleFlagBits {
		want := strings.Join(strings.Fields("Bit "+itoa(int64(b.Bit))+"\u2014"+b.Name+"\u2014"+b.SHALL), " ")
		if !strings.Contains(text, want) {
			t.Errorf("printed page 169 of the published standard does not contain %q; the transcription "+
				"has drifted from the document, or the page mapping has", want)
		}
	}
	if !strings.Contains(text, "RoleFlagsType object (HexBinary16)") {
		t.Error("printed page 169 no longer declares RoleFlagsType a HexBinary16, which is what the " +
			"oracle decodes the element text as")
	}
}

// TestMUPOracle_DerivesItsBitsFromTheStandardAndNotFromTheProduct is the
// IW15-011 structural rule applied to this oracle.
func TestMUPOracle_DerivesItsBitsFromTheStandardAndNotFromTheProduct(t *testing.T) {
	src, err := os.ReadFile("mup_oracle.go")
	if err != nil {
		t.Fatalf("read the oracle's own source: %v", err)
	}
	body := string(src)
	for _, forbidden := range []string{`"lexa-proto/csipmodel"`, "csipmodel.", "model."} {
		if strings.Contains(body, forbidden) {
			t.Errorf("mup_oracle.go references %s. Its bit positions and SHALLs must come from the hand "+
				"transcription of IEEE Std 2030.5-2018 p.169 and from nothing else: a decode that asks "+
				"the product's own model what the product's own bytes mean cannot fail", forbidden)
		}
	}
	if !strings.Contains(body, "2030.5-2018") {
		t.Error("mup_oracle.go does not cite IEEE Std 2030.5-2018 anywhere")
	}
}

// ── (2)/(3) Teeth, and the limits of them ────────────────────────────────────

// mupXML builds a MirrorUsagePoint registration body from raw element text, so a
// test can express an ABSENT element — which is the defect class this oracle
// exists for and which no Go struct can express.
func mupXML(elements string) string {
	return `<MirrorUsagePoint xmlns="` + Namespace + `"><mRID>MUP-1</mRID>` +
		elements + `<deviceLFDI>AABBCCDDEEFF00112233445566778899AABBCCDD</deviceLFDI>` +
		`<postRate>300</postRate></MirrorUsagePoint>`
}

// mupPOST is the DUT's registration exchange.
func mupPOST(body string) Exchange {
	return Exchange{
		Req:  msg(Request, "POST", "/mup", 0, body),
		Resp: msg(Response, "", "", 201, ""),
	}
}

// conformantMUP is a registration that honours every SHALL this oracle can
// decide: isMirror | isDER | isSubmeter = 0x0049, all three mandatory elements
// present. It is the value this suite's own fixtures settled on.
const conformantMUP = `<roleFlags>0049</roleFlags><serviceCategoryKind>0</serviceCategoryKind>` +
	`<status>1</status>`

// derCapPUT is the premise isDER's SHALL needs: the DUT telling this same server
// it is a 2030.5 DER client.
func derCapPUT() Exchange {
	return Exchange{
		Req: msg(Request, "PUT", "/edev/0/der/1/dercap", 0,
			`<DERCapability xmlns="`+Namespace+`"><modesSupported>00100084</modesSupported></DERCapability>`),
		Resp: msg(Response, "", "", 204, ""),
	}
}

func wantMUPVerdict(t *testing.T, name string, tr *Transcript, pics string, want certify.Verdict) Finding {
	t.Helper()
	f := critMUPElementsAndRoleFlags(pics).Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("%s: the oracle declined to decide: %s", name, f.Unavailable)
	}
	if f.Verdict != want {
		t.Fatalf("%s: verdict = %s, want %s\nobserved: %s", name, f.Verdict, want, f.Observed)
	}
	return f
}

func TestMUPOracle_HasTeethOnEveryDecidableClass(t *testing.T) {
	// The conformant baseline, with the DER premise in hand.
	ok := synthTranscript(derCapPUT(), mupPOST(mupXML(conformantMUP)))
	f := wantMUPVerdict(t, "conformant", ok, "", certify.Pass)
	for _, want := range []string{"0x0049", "bit 0 isMirror", "bit 3 isDER", "bit 6 isSubmeter"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the PASS does not name what it credited (missing %q): %s", want, f.Observed)
		}
	}

	// ── Mandatory elements ───────────────────────────────────────────────
	for _, tc := range []struct{ name, elements, want string }{
		{"no roleFlags", `<serviceCategoryKind>0</serviceCategoryKind><status>1</status>`, "roleFlags"},
		{"no serviceCategoryKind", `<roleFlags>0049</roleFlags><status>1</status>`, "serviceCategoryKind"},
		{"no status", `<roleFlags>0049</roleFlags><serviceCategoryKind>0</serviceCategoryKind>`, "status"},
	} {
		tr := synthTranscript(derCapPUT(), mupPOST(mupXML(tc.elements)))
		f := wantMUPVerdict(t, tc.name, tr, "", certify.Fail)
		if !strings.Contains(f.Observed, "<"+tc.want+"> is ABSENT") {
			t.Errorf("%s: the FAIL does not name the missing element: %s", tc.name, f.Observed)
		}
		if !strings.Contains(f.Observed, "p.215") {
			t.Errorf("%s: the FAIL does not cite the page that makes it mandatory: %s", tc.name, f.Observed)
		}
	}
	// An EMPTY mandatory element is not a present one.
	empty := synthTranscript(derCapPUT(), mupPOST(mupXML(
		`<roleFlags>0049</roleFlags><serviceCategoryKind></serviceCategoryKind><status>1</status>`)))
	f = wantMUPVerdict(t, "empty serviceCategoryKind", empty, "", certify.Fail)
	if !strings.Contains(f.Observed, "present but EMPTY") {
		t.Errorf("an empty mandatory element was not reported as such: %s", f.Observed)
	}

	// ── isMirror: decidable from the resource ────────────────────────────
	// 0x0048 = isDER | isSubmeter, with isMirror clear.
	noMirror := synthTranscript(derCapPUT(), mupPOST(mupXML(
		`<roleFlags>0048</roleFlags><serviceCategoryKind>0</serviceCategoryKind><status>1</status>`)))
	f = wantMUPVerdict(t, "isMirror clear", noMirror, "", certify.Fail)
	for _, want := range []string{"bit 0 isMirror is CLEAR", "not the measurement device", "p.215"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the isMirror FAIL omits %q: %s", want, f.Observed)
		}
	}

	// ── The complementary pair ───────────────────────────────────────────
	// 0x004B = isMirror | isPremisesAggregationPoint | isDER | isSubmeter:
	// bits 1 and 6 BOTH set, which no site reconciles.
	both := synthTranscript(derCapPUT(), mupPOST(mupXML(
		`<roleFlags>004B</roleFlags><serviceCategoryKind>0</serviceCategoryKind><status>1</status>`)))
	f = wantMUPVerdict(t, "both complementary bits set", both, "", certify.Fail)
	for _, want := range []string{"BOTH set", "isPremisesAggregationPoint", "isSubmeter", "complementary"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the both-set FAIL omits %q: %s", want, f.Observed)
		}
	}
	// 0x0009 = isMirror | isDER: bits 1 and 6 both CLEAR, so neither SHALL is
	// honoured whichever way the site is arranged.
	neither := synthTranscript(derCapPUT(), mupPOST(mupXML(
		`<roleFlags>0009</roleFlags><serviceCategoryKind>0</serviceCategoryKind><status>1</status>`)))
	f = wantMUPVerdict(t, "neither complementary bit set", neither, "", certify.Fail)
	for _, want := range []string{"BOTH clear", "exhaustive", "exactly one of these SHALLs"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the neither-set FAIL omits %q: %s", want, f.Observed)
		}
	}
	// And the coherent case is DISCLOSED, not silently credited: which of the
	// two is right is a fact about the site.
	f = wantMUPVerdict(t, "conformant, pair disclosed", ok, "", certify.Pass)
	if !strings.Contains(f.Observed, "COHERENT") {
		t.Errorf("the complementary pair was not disclosed on a PASS: %s", f.Observed)
	}

	// ── isDER: decidable only against evidence ───────────────────────────
	// 0x0041 = isMirror | isSubmeter, isDER clear. WITH the DERCapability
	// premise this fails; WITHOUT it, it is disclosed and the row passes.
	noDER := mupXML(`<roleFlags>0041</roleFlags><serviceCategoryKind>0</serviceCategoryKind>` +
		`<status>1</status>`)
	withPremise := synthTranscript(derCapPUT(), mupPOST(noDER))
	f = wantMUPVerdict(t, "isDER clear, premise present", withPremise, "", certify.Fail)
	for _, want := range []string{"bit 3 isDER is CLEAR", "DERCapability", "filters usage points by isDER"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the isDER FAIL omits %q: %s", want, f.Observed)
		}
	}
	noPremise := synthTranscript(mupPOST(noDER))
	f = wantMUPVerdict(t, "isDER clear, no premise", noPremise, "", certify.Pass)
	if !strings.Contains(f.Observed, "established no premise") {
		t.Errorf("an ungradable isDER was not disclosed as such: %s", f.Observed)
	}
	if strings.Contains(f.Observed, "NON-CONFORMANT") {
		t.Errorf("the oracle invented the isDER premise from a window that did not establish it: %s",
			f.Observed)
	}

	// ── Reserved ─────────────────────────────────────────────────────────
	// 0x0089 = the conformant set with bit 7 added.
	res := synthTranscript(derCapPUT(), mupPOST(mupXML(
		`<roleFlags>00C9</roleFlags><serviceCategoryKind>0</serviceCategoryKind><status>1</status>`)))
	f = wantMUPVerdict(t, "reserved bit set", res, "", certify.Fail)
	for _, want := range []string{"bit 7 is set", "Reserved", "2030.5-2023 p.179"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the reserved-bit FAIL omits %q: %s", want, f.Observed)
		}
	}

	// ── Encoding ─────────────────────────────────────────────────────────
	// RoleFlagsType is a HexBinary16, so a decimal serializer's output for any
	// value above 9 is not in the type's lexical space at all.
	bad := synthTranscript(derCapPUT(), mupPOST(mupXML(
		`<roleFlags>zz</roleFlags><serviceCategoryKind>0</serviceCategoryKind><status>1</status>`)))
	f = wantMUPVerdict(t, "non-hexBinary roleFlags", bad, "", certify.Fail)
	if !strings.Contains(f.Observed, "HexBinary16") {
		t.Errorf("a non-HexBinary16 roleFlags did not cite the type: %s", f.Observed)
	}
}

// TestMUPOracle_SiteFactsAreDisclosedNotInvented is the limit half, and it is as
// important as the teeth: a claim about an installation that no transcript can
// check must never become a verdict about the DUT.
func TestMUPOracle_SiteFactsAreDisclosedNotInvented(t *testing.T) {
	// 0x0069 = isMirror | isDER | isDC | isSubmeter. isDC is a fact about the
	// wiring; nothing here can refute it.
	dc := synthTranscript(derCapPUT(), mupPOST(mupXML(
		`<roleFlags>0069</roleFlags><serviceCategoryKind>0</serviceCategoryKind><status>1</status>`)))
	f := wantMUPVerdict(t, "isDC claimed, no PICS", dc, "", certify.Pass)
	for _, want := range []string{"bit 5 isDC is SET", "fact about the installation", mupRoleFlagsPICSParam} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the site-fact disclosure omits %q: %s", want, f.Observed)
		}
	}
	// With a PICS that does NOT declare it, the same bit becomes gradable:
	// nobody stands behind it.
	f = wantMUPVerdict(t, "isDC outside the PICS", dc, "isMirror,isDER,isSubmeter", certify.Fail)
	if !strings.Contains(f.Observed, "does not declare it") {
		t.Errorf("an undeclared site-fact claim was not graded against the PICS: %s", f.Observed)
	}
	// Declared, so it is fine.
	wantMUPVerdict(t, "isDC inside the PICS", dc, "isMirror,isDER,isSubmeter,isDC", certify.Pass)
	// And the other direction: a declared role the device does not carry.
	f = wantMUPVerdict(t, "PICS declares a role the device omits", dc,
		"isMirror,isDER,isSubmeter,isDC,isPEV", certify.Fail)
	if !strings.Contains(f.Observed, "isPEV") || !strings.Contains(f.Observed, "own declaration disagree") {
		t.Errorf("a declared-but-absent role was not reported: %s", f.Observed)
	}
}

// TestMUPOracle_ServerTierGradesTheStoredRegistration pins the tier that
// actually decides this criterion on a real campaign.
//
// MirrorUsagePoint registration is a ONE-TIME event: the DUT does it at first
// contact and never again, and BASIC-029 has no Setup that forces a fresh one.
// By the time this row's window opens the POST is usually long past, so the wire
// tier finds nothing and gridsim's durable store is the only witness left. That
// is why AdminMUP carries the raw POST body at all.
func TestMUPOracle_ServerTierGradesTheStoredRegistration(t *testing.T) {
	c := critMUPElementsAndRoleFlags("")

	// Nothing stored: undecidable, not a verdict about the DUT.
	if f := c.Server(&ServerView{Available: true}); f.Unavailable == "" {
		t.Errorf("an empty server view produced a verdict (%s) instead of unavailable: %s",
			f.Verdict, f.Observed)
	}

	// A stored registration missing a mandatory element is decidable from the
	// store alone.
	v := &ServerView{Available: true, MUPs: []AdminMUP{{
		Href: "/mup/0", LFDI: "AABB",
		Body: mupXML(`<roleFlags>0049</roleFlags><status>1</status>`),
	}}}
	f := c.Server(v)
	if f.Verdict != certify.Fail || !strings.Contains(f.Observed, "serviceCategoryKind") {
		t.Errorf("server tier, missing mandatory element = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "gridsim stored") {
		t.Errorf("the server-tier finding does not say it was not the wire: %s", f.Observed)
	}

	// A registration this bench recorded before AdminMUP carried a body is
	// UNAVAILABLE, and must say so rather than reading as "the DUT registered
	// nothing": the registration happened, the content did not survive.
	old := &ServerView{Available: true, MUPs: []AdminMUP{{Href: "/mup/0", LFDI: "AABB"}}}
	f = c.Server(old)
	if f.Unavailable == "" {
		t.Errorf("a body-less stored MUP produced a verdict (%s) instead of unavailable: %s",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Unavailable, "registration HAPPENED") {
		t.Errorf("the unavailable does not distinguish 'no content stored' from 'never registered': %s",
			f.Unavailable)
	}
}

// ── (4) The proofs against the product ──────────────────────────────────────

// shippedRoleFlags is what lexa-gw's cmd/telemetry registerMUP writes, verbatim:
//
//	RoleFlags: 0x0002,
//
// which is isPremisesAggregationPoint ALONE. Under IEEE Std 2030.5-2018 p.169
// that says: this usage point is the point of delivery for a premises; the
// server IS the measurement device (isMirror clear, on a MirrorUsagePoint); the
// usage does NOT apply to a distributed energy resource (isDER clear, on a
// gateway that PUTs a DERCapability to the same server); and it is not a
// submeter.
//
// PINNED, not read from the product, on the rule the modes oracle's preserved
// masks follow: a teeth test that tracked the product would go green the moment
// the product was fixed and take the evidence of its own teeth with it. Whoever
// changes the shipped posture adds a green proof beside this one and leaves this
// one alone.
const shippedRoleFlags model.HexBinary16 = 0x0002

// productMUP builds a MirrorUsagePoint with the PRODUCT'S OWN serializer,
// carrying the values cmd/telemetry's registerMUP sets.
//
// Using csipmodel HERE — in a test, to build the DUT's side of a fixture — is
// the opposite of what
// TestMUPOracle_DerivesItsBitsFromTheStandardAndNotFromTheProduct forbids. The
// product's serializer is the right authority on what the product EMITS. It has
// no standing whatsoever on what those bytes MEAN, and the oracle path never
// asks it.
func productMUP(t *testing.T, roleFlags model.HexBinary16) string {
	t.Helper()
	mup := &model.MirrorUsagePoint{
		MRID:                "AABBCCDD-bat-704",
		Description:         "bat-704 Measurements (W,var,Wh)",
		RoleFlags:           roleFlags,
		ServiceCategoryKind: 0, // electricity
		Status:              1, // on
		DeviceLFDI:          "AABBCCDDEEFF00112233445566778899AABBCCDD",
		PostRate:            300,
	}
	b, err := xml.Marshal(mup)
	if err != nil {
		t.Fatalf("marshal the product's own MirrorUsagePoint type: %v", err)
	}
	return string(b)
}

// TestMUPOracle_RedProofAgainstTheShippedRoleFlags is the live red proof, and it
// is red against a build that has ALREADY taken the upstream fix.
//
// lexa-proto 13e9106 cured the missing mandatory element; it did not and could
// not change 0x0002, which is a number cmd/telemetry writes. So this fixture is
// built with the CURRENT vendored serializer — serviceCategoryKind present, as
// it now will be on the wire — and is still non-conformant in two places that
// only lexa-gw can close.
func TestMUPOracle_RedProofAgainstTheShippedRoleFlags(t *testing.T) {
	body := productMUP(t, shippedRoleFlags)
	// The proto fix, asserted on the BYTES rather than assumed: with the pinned
	// proto this element is on the wire, and if it ever leaves again this proof
	// is about a different document and must be re-stated.
	if !strings.Contains(body, "<serviceCategoryKind>0</serviceCategoryKind>") {
		t.Fatalf("the product's serializer no longer emits serviceCategoryKind at value 0. That is the "+
			"omitempty defect returning, and it changes what this proof is about:\n%s", body)
	}
	if !strings.Contains(body, "<roleFlags>0002</roleFlags>") {
		t.Fatalf("the product's serializer no longer emits the shipped roleFlags as zero-padded "+
			"hexBinary16; this proof's premise has changed:\n%s", body)
	}

	tr := synthTranscript(derCapPUT(), mupPOST(body))
	f := critMUPElementsAndRoleFlags("").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide against the shipped build: %s", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("the shipped MirrorUsagePoint graded %s. It clears isMirror on a MIRROR usage point "+
			"and clears isDER on a device that PUTs a DERCapability to the same server; an oracle that "+
			"does not fail that is not grading the resource at all.\n%s", f.Verdict, f.Observed)
	}
	for _, want := range []string{
		"NON-CONFORMANT in 2 place(s)",
		"bit 0 isMirror is CLEAR",
		"bit 3 isDER is CLEAR",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the shipped-roleFlags red proof omits %q:\n%s", want, f.Observed)
		}
	}
	// It must NOT fail for the mandatory element any more: that half IS cured by
	// the re-vendor, and a proof that conflated the two would not tell lexa-gw
	// what is left to do.
	if strings.Contains(f.Observed, "is ABSENT") {
		t.Errorf("the shipped build is still missing a mandatory element, so the proto re-vendor did "+
			"not take:\n%s", f.Observed)
	}
	// And the pair check must be SILENT here: 0x0002 sets exactly one of the
	// complementary bits, which is coherent however odd the choice.
	if strings.Contains(f.Observed, "BOTH set") || strings.Contains(f.Observed, "BOTH clear") {
		t.Errorf("the complementary pair was reported as incoherent for a mask that sets exactly one "+
			"of them:\n%s", f.Observed)
	}
	t.Logf("RED PROOF (shipped roleFlags 0x0002, current proto), verbatim:\n%s", f.Observed)
}

// preFixMUPBytes is the MirrorUsagePoint lexa-gw POSTed BEFORE lexa-proto
// 13e9106 — the same struct, the same values, marshalled by a csipmodel that
// tagged UsagePointBase's three mandatory elements `omitempty`.
//
// serviceCategoryKind is GONE from it, and that is the whole point: the value is
// 0 (electricity), which is exactly what omitempty deletes, so the element the
// standard makes mandatory vanished while the Go field was set correctly. status
// survives only because this product happens to send 1.
//
// Pinned as a LITERAL because it cannot be produced any more: the fix is
// upstream and vendored, so nothing in this tree can emit these bytes. A teeth
// test whose fixture the fix erased would be a teeth test with no teeth.
const preFixMUPBytes = `<MirrorUsagePoint xmlns="urn:ieee:std:2030.5:ns">` +
	`<mRID>AABBCCDD-bat-704</mRID>` +
	`<description>bat-704 Measurements (W,var,Wh)</description>` +
	`<roleFlags>0002</roleFlags>` +
	`<status>1</status>` +
	`<deviceLFDI>AABBCCDDEEFF00112233445566778899AABBCCDD</deviceLFDI>` +
	`<postRate>300</postRate>` +
	`</MirrorUsagePoint>`

// TestMUPOracle_RedProofAgainstThePreservedPreFixBytes keeps the defect the
// upstream fix cured, so that cure cannot erase its own evidence.
//
// It is THREE failures where the live proof is two, and the difference is
// exactly what lexa-proto 13e9106 bought: the missing mandatory element. Naming
// the difference is the point — a bundle reader, and the next wave, must be able
// to see which repository closed which half.
func TestMUPOracle_RedProofAgainstThePreservedPreFixBytes(t *testing.T) {
	tr := synthTranscript(derCapPUT(), mupPOST(preFixMUPBytes))
	f := critMUPElementsAndRoleFlags("").Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("the oracle declined to decide against the preserved pre-fix bytes: %s", f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("the pre-13e9106 registration graded %s; it is missing a mandatory element AND clears "+
			"isMirror on a mirror usage point\n%s", f.Verdict, f.Observed)
	}
	for _, want := range []string{
		"NON-CONFORMANT in 3 place(s)",
		"<serviceCategoryKind> is ABSENT",
		"omitempty",
		"bit 0 isMirror is CLEAR",
		"bit 3 isDER is CLEAR",
	} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the preserved pre-fix red proof omits %q:\n%s", want, f.Observed)
		}
	}
	t.Logf("RED PROOF, PRESERVED (pre-13e9106 bytes), verbatim:\n%s", f.Observed)
}

// TestMUPOracle_ProtoFixAloneCuresExactlyOneOfTheThree states the division of
// labour as an ASSERTION rather than as a paragraph, because the two waves are
// running in parallel and a note in a commit message is not checkable.
//
// Same roleFlags, same values, two serializers: the only difference between the
// fixtures is the `omitempty` lexa-proto removed. The failure count must drop by
// exactly one, and the one that goes must be the mandatory element.
func TestMUPOracle_ProtoFixAloneCuresExactlyOneOfTheThree(t *testing.T) {
	before := critMUPElementsAndRoleFlags("").Wire(nil,
		synthTranscript(derCapPUT(), mupPOST(preFixMUPBytes)))
	after := critMUPElementsAndRoleFlags("").Wire(nil,
		synthTranscript(derCapPUT(), mupPOST(productMUP(t, shippedRoleFlags))))

	if !strings.Contains(before.Observed, "in 3 place(s)") ||
		!strings.Contains(after.Observed, "in 2 place(s)") {
		t.Fatalf("the re-vendor did not close exactly one finding.\nbefore: %s\n\nafter: %s",
			before.Observed, after.Observed)
	}
	// What the re-vendor cured.
	if !strings.Contains(before.Observed, "<serviceCategoryKind> is ABSENT") ||
		strings.Contains(after.Observed, "<serviceCategoryKind> is ABSENT") {
		t.Errorf("the cured finding is not the missing mandatory element.\nbefore: %s\n\nafter: %s",
			before.Observed, after.Observed)
	}
	// What it did NOT cure, and cannot: these are values cmd/telemetry writes.
	for _, want := range []string{"bit 0 isMirror is CLEAR", "bit 3 isDER is CLEAR"} {
		if !strings.Contains(after.Observed, want) {
			t.Errorf("a roleFlags finding disappeared with the re-vendor, which no schema change can "+
				"do (missing %q): %s", want, after.Observed)
		}
	}
	t.Logf("DIVISION OF LABOUR: lexa-proto 13e9106 closes the mandatory-element finding on re-vendor; "+
		"the two roleFlags findings need a lexa-gw change to cmd/telemetry's registerMUP.\n"+
		"  before (3): %s\n\n  after (2): %s", before.Observed, after.Observed)
}

// TestBasic029_CarriesTheMUPContentOracle pins the row placement: BASIC-029 is
// the MirrorUsagePoint row, and a criterion not in the list it mints is dead
// code.
func TestBasic029_CarriesTheMUPContentOracle(t *testing.T) {
	var found bool
	for _, c := range basicMeterReadingCriteria(&Observation{Params: map[string]string{}}) {
		if !strings.Contains(c.Claim, "roleFlags") {
			continue
		}
		found = true
		if c.Skip == "" {
			t.Errorf("the MirrorUsagePoint content criterion has no Skip reason, so a run that observed "+
				"no registration would report an empty explanation: %q", c.Claim)
		}
		if !strings.Contains(c.How, "2030.5-2018") {
			t.Errorf("the criterion's How does not cite the standard it transcribes: %q", c.How)
		}
		if c.Server == nil {
			t.Error("the criterion has no Server tier, and MirrorUsagePoint registration is a ONE-TIME " +
				"event that routinely predates this row's window — a wire-only criterion would be " +
				"unavailable on most real runs")
		}
	}
	if !found {
		t.Fatal("BASIC-029 mints no MirrorUsagePoint content criterion")
	}
}
