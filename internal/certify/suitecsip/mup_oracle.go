package suitecsip

// mup_oracle.go grades the MirrorUsagePoint the DUT REGISTERS — its mandatory
// elements, and what its roleFlags claim about the device.
//
// # The gap this closes
//
// critMUPRegistered (basic.go) already asks whether a MirrorUsagePoint POST
// happened, was answered 201/204 with a Location, and carried a deviceLFDI and a
// ReadingType. Everything about the resource's own CONTENT went ungraded: a
// mandatory element could be missing and a roleFlags could say anything at all,
// and 282 catalog rows would report a clean run. That is IW15-028, and it was
// found by reading the standard rather than by any run failing.
//
// Both halves turned out to be live on this product.
//
//	MANDATORY ELEMENTS. IEEE Std 2030.5-2018 p.215 (Figure B.26) and p.217
//	declare roleFlags, serviceCategoryKind and status on UsagePointBase with NO
//	[0..1] marker — all three are [1], and MirrorUsagePoint extends
//	UsagePointBase. lexa-proto tagged all three `omitempty`, and this product's
//	values for two of them are ZERO (serviceCategoryKind 0 = electricity), which
//	is exactly what omitempty deletes. So every MirrorUsagePoint the product
//	ever POSTed was missing a mandatory element, correctly set in Go and dropped
//	on the way out. The defect is revision-INDEPENDENT — the draft schema and
//	2018 agree all three are mandatory — so it is one the wrong anchor neither
//	caused nor excused. FIXED upstream by lexa-proto 13e9106.
//
//	roleFlags. 2018 p.169 gives RoleFlagsType seven bits, every one of them a
//	SHALL, and this product SENT 0x0002: isPremisesAggregationPoint alone, with
//	isMirror CLEAR on a MIRROR usage point. FIXED by lexa-gw 675ffdf, which
//	sends 0x0049 (isMirror | isDER | isSubmeter).
//
// BOTH ARE PAST TENSE NOW, and the tense is not cosmetic. This paragraph is
// provenance prose in a file whose whole subject is what a certifier may
// conclude about the DUT, and while it read "this product sends 0x0002" it was
// telling a reader that the device under test violates an unconditional SHALL —
// after the product had stopped. The ORACLE was correct throughout (it grades
// the resource in front of it, and green-proofs 0x0049); only the narration had
// gone stale, which is the more dangerous of the two failures because nothing
// executes it. See TestMUPOracle_TheThreeGenerationsOfThisRegistration for the
// state each of these sentences is now a record OF.
//
// # What this oracle will and will not decide
//
// A roleFlags bit is a claim about a physical installation, and most of those
// claims a transcript cannot refute: whether a usage point measures direct
// current, or was metered by a revenue-quality device, is not visible on the
// wire. An oracle that failed a DUT for those would be inventing facts.
//
// So the bits are adjudicated in three classes, and the class is stated in the
// finding so a reader knows which kind of statement they are looking at:
//
//	DECIDABLE FROM THE RESOURCE ITSELF — isMirror (bit 0). "SHALL be set if the
//	server is not the measurement device." On a MirrorUsagePoint the server is
//	BY DEFINITION not the measurement device: that is what mirroring is, it is
//	what the resource's own name says, and it is what deviceLFDI — "the LFDI of
//	the device being mirrored" (2018 p.215) — records. There is no deployment in
//	which this bit is legitimately clear on this resource. Clear = FAIL.
//
//	DECIDABLE BETWEEN THEMSELVES — isPremisesAggregationPoint (bit 1) and
//	isSubmeter (bit 6). "SHALL be set if the UsagePoint is the point of delivery
//	for a premises" and "SHALL be set if the usage point is not a premises
//	aggregation point". The two conditions are complementary and exhaustive:
//	every usage point either is a premises point of delivery or is not.
//	EXACTLY ONE of the two bits satisfies its SHALL, whatever the site looks
//	like. Both set, or neither set, is incoherent on the standard alone, without
//	the oracle knowing anything about the installation. That is a check no
//	amount of site knowledge is needed for and none of the 282 rows was making.
//
//	DECIDABLE ONLY AGAINST EVIDENCE — isDER (bit 3). "SHALL be set if the usage
//	applies to a distributed energy resource, capable of delivering power to the
//	grid." Whether it does is a fact about the deployment — but this campaign
//	often has the fact in hand: a DUT that PUT a DERCapability from the same
//	LFDI has told this very server that it is a DER client. When that evidence
//	is present the SHALL is decidable and a clear bit FAILS; when it is absent
//	the bit is DISCLOSED and not graded, which is the honest answer for a window
//	that did not establish the premise.
//
//	NOT DECIDABLE FROM THE WIRE — isPEV (2), isRevenueQuality (4), isDC (5).
//	Reported, never graded, unless the operator supplies a PICS.
//
//	RESERVED — bits 7..15. 2018 p.169: "Bit 7 to 15—Reserved". Set = FAIL, on
//	the standard alone. Unlike DERControlType's reserved range, 2030.5-2023
//	p.179 reserves these too, so there is no newer-revision escape here and the
//	finding does not offer one.
//
// # Independence
//
// The bit table below is HAND-TRANSCRIBED from IEEE Std 2030.5-2018 p.169, with
// the SHALL sentence quoted per bit, and imports nothing from
// lexa-proto/csipmodel — same rule as modes_oracle.go, and for the same reason
// IW15-027 made unmissable: a witness is independent only if its SOURCE is. The
// 2018 text is corroborated by 2030.5-2023 p.179 (identical) and by the
// vendored draft schema (also identical) — this is one of the places all three
// documents agree, which is worth saying out loud precisely because so much of
// this wave was about places where they do not.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"csip-tls-test/internal/certify"
)

// roleFlagClass says what KIND of claim a bit makes, which decides whether this
// oracle may grade it.
type roleFlagClass int

const (
	// roleFlagResource: decidable from the resource's own identity.
	roleFlagResource roleFlagClass = iota
	// roleFlagComplementary: decidable against its partner bit, with no
	// knowledge of the site.
	roleFlagComplementary
	// roleFlagEvidenced: decidable when the campaign establishes the premise.
	roleFlagEvidenced
	// roleFlagSiteFact: a claim about the installation the wire cannot settle.
	roleFlagSiteFact
)

// There is deliberately NO roleFlagReserved class. Bits 7..15 are not rows of
// the transcription — the standard assigns them no name and no SHALL, so there
// is nothing to transcribe — and they are graded by position, after the table,
// against roleFlagsReservedFrom. A class for them would invite someone to add a
// row with an invented name.

// roleFlagBit is one row of IEEE 2030.5-2018's RoleFlagsType, hand-transcribed.
type roleFlagBit struct {
	// Bit is the position, 0-based, as the standard numbers it.
	Bit uint
	// Name is the standard's own name for the bit, verbatim.
	Name string
	// SHALL is the standard's own sentence, verbatim, minus the "Bit N—name—"
	// prefix. It is quoted rather than paraphrased because it is the whole
	// warrant for any verdict this oracle reaches.
	SHALL string
	// Class decides how (and whether) the bit is graded.
	Class roleFlagClass
	// Partner is the complementary bit's position, for roleFlagComplementary.
	Partner uint
}

// roleFlagBits is the transcription: IEEE Std 2030.5-2018, PRINTED PAGE 169,
// "RoleFlagsType object (HexBinary16) — Specifies the roles that apply to a
// usage point."
//
// Read it against the standard. The test file quotes the whole block verbatim
// and rebuilds this table from the quote, so a typo here cannot pass unnoticed
// on a machine with no copy of the document.
var roleFlagBits = []roleFlagBit{
	{Bit: 0, Name: "isMirror", Class: roleFlagResource,
		SHALL: "SHALL be set if the server is not the measurement device"},
	{Bit: 1, Name: "isPremisesAggregationPoint", Class: roleFlagComplementary, Partner: 6,
		SHALL: "SHALL be set if the UsagePoint is the point of delivery for a premises"},
	{Bit: 2, Name: "isPEV", Class: roleFlagSiteFact,
		SHALL: "SHALL be set if the usage applies to an electric vehicle"},
	{Bit: 3, Name: "isDER", Class: roleFlagEvidenced,
		SHALL: "SHALL be set if the usage applies to a distributed energy resource, capable of " +
			"delivering power to the grid"},
	{Bit: 4, Name: "isRevenueQuality", Class: roleFlagSiteFact,
		SHALL: "SHALL be set if usage was measured by a device certified as revenue quality"},
	{Bit: 5, Name: "isDC", Class: roleFlagSiteFact,
		SHALL: "SHALL be set if the usage point measures direct current"},
	{Bit: 6, Name: "isSubmeter", Class: roleFlagComplementary, Partner: 1,
		SHALL: "SHALL be set if the usage point is not a premises aggregation point"},
}

// roleFlagsReservedFrom is the first bit position 2018 p.169 does not assign:
// "Bit 7 to 15—Reserved". 2030.5-2023 p.179 reserves the same range, so unlike
// DERControlType there is no newer revision that defines them.
const roleFlagsReservedFrom = 7

// roleFlagAt returns the transcription row for a position.
func roleFlagAt(pos uint) (roleFlagBit, bool) {
	for _, b := range roleFlagBits {
		if b.Bit == pos {
			return b, true
		}
	}
	return roleFlagBit{}, false
}

// hexBinary16 is RoleFlagsType's lexical space. 2018 p.169 declares
// "RoleFlagsType object (HexBinary16)"; HexBinary16 is "A 16-bit field encoded
// as a hex string (4 hex characters maximum)".
var hexBinary16 = regexp.MustCompile(`^[0-9a-fA-F]{1,4}$`)

// mupMandatory are the three elements of UsagePointBase that MirrorUsagePoint
// inherits and that IEEE Std 2030.5-2018 declares [1] — Figure B.26 (p.215)
// shows them with no cardinality marker, and the prose on p.217 declares them
// with none either, which is the standard's notation for mandatory.
//
// deviceLFDI is [1] too (p.215) and is NOT in this list: critMUPRegistered
// already fails a MirrorUsagePoint that carries none, and two criteria failing
// the same row for the same byte reads as two defects.
var mupMandatory = []struct {
	Element string
	Why     string
}{
	{"roleFlags", "IEEE Std 2030.5-2018 p.215 Figure B.26 and p.217 declare UsagePointBase.roleFlags " +
		"[1] — RoleFlagsType, no cardinality marker, which is this document's notation for mandatory"},
	{"serviceCategoryKind", "IEEE Std 2030.5-2018 p.215 Figure B.26 and p.217 declare " +
		"UsagePointBase.serviceCategoryKind [1] — a ServiceKind, whose value 0 is \"Electricity\" " +
		"(p.169). A MANDATORY element with a MEANINGFUL ZERO is precisely what an `omitempty` tag " +
		"deletes, which is how this one went missing from every registration this product ever made"},
	{"status", "IEEE Std 2030.5-2018 p.215 Figure B.26 and p.217 declare UsagePointBase.status [1] — " +
		"UInt8, \"0 = Off, 1 = On\" (p.217). Same meaningful zero, same omitempty hazard"},
}

// mupEvidence is what the oracle knows before it grades.
type mupEvidence struct {
	// Doc is the parsed MirrorUsagePoint registration.
	Doc *Node
	// Where says which observation it came from, in a sentence.
	Where string
	// Cite is the message to cite when it came from the transcript.
	Cite *Message
	// DERClient records that the DUT told THIS SERVER it is a DER client, which
	// is what makes isDER's SHALL decidable. Empty when nothing established it.
	DERClient string
	// PICS is the operator-declared role list, empty when none was supplied.
	PICS []string
	// PICSRaw is what the operator actually typed, for the finding.
	PICSRaw string
}

// mupRoleFlagsPICSParam is how an operator supplies the vendor's declared
// roles: a comma-separated list of 2018 role names (isDER), or bit numbers.
//
// Without it, a SITE-FACT bit that is set is DISCLOSED and not graded — the
// honest answer for a claim about an installation the wire cannot see. With it,
// such a bit becomes gradable: a role outside the declaration is a claim nobody
// stands behind, and a declared role the resource does not carry is a
// disagreement between the device and its own paperwork.
const mupRoleFlagsPICSParam = "csip.pics_role_flags"

// parseRoleFlags decodes the character data of a <roleFlags> element.
func parseRoleFlags(text string) (uint16, error) {
	t := strings.TrimSpace(text)
	if t == "" {
		return 0, fmt.Errorf("the <roleFlags> element is present but EMPTY; IEEE Std 2030.5-2018 p.215 " +
			"declares it [1] with type RoleFlagsType, whose lexical space (p.169, HexBinary16) has no " +
			"empty member")
	}
	if !hexBinary16.MatchString(t) {
		return 0, fmt.Errorf("the <roleFlags> text %q is not a HexBinary16 value; IEEE Std 2030.5-2018 "+
			"p.169 declares RoleFlagsType a HexBinary16, whose lexical space is one to four hexadecimal "+
			"digits. A serializer that models the field as a plain integer emits decimal and produces "+
			"exactly this failure for any value above 9", t)
	}
	v, err := strconv.ParseUint(t, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("the <roleFlags> text %q did not decode as HexBinary16: %w", t, err)
	}
	return uint16(v), nil
}

// describeRoleFlags renders a mask as the standard's own role names.
func describeRoleFlags(mask uint16) string {
	var parts []string
	for i := uint(0); i < 16; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		if b, ok := roleFlagAt(i); ok {
			parts = append(parts, fmt.Sprintf("bit %d %s", i, b.Name))
			continue
		}
		parts = append(parts, fmt.Sprintf("bit %d RESERVED by IEEE 2030.5-2018 p.169", i))
	}
	if len(parts) == 0 {
		return "no bits set"
	}
	return strings.Join(parts, ", ")
}

// gradeMUP is the decision. It never returns Unavailable for anything that is a
// fact about the DUT: the only unavailability it can produce is "no
// MirrorUsagePoint was observed at all", which is a fact about the window and
// which BASIC-029's own critMUPRegistered already turns into a verdict.
func gradeMUP(e mupEvidence) Finding {
	if e.Doc == nil {
		return unavailable("no MirrorUsagePoint registration was observed in this window or in gridsim's " +
			"durable MUP store, so there is nothing to grade; BASIC-029's own critMUPRegistered is where " +
			"that absence is a verdict")
	}

	var problems, disclosed []string

	// ── The mandatory elements ───────────────────────────────────────────
	var present []string
	for _, m := range mupMandatory {
		el := e.Doc.Child(m.Element)
		switch {
		case el == nil:
			problems = append(problems, fmt.Sprintf(
				"<%s> is ABSENT from the registration. %s. A server that validates this document rejects "+
					"it, and a head end reading it cannot tell what kind of service this usage point "+
					"measures or whether it is in service",
				m.Element, m.Why))
		case strings.TrimSpace(el.Text) == "":
			problems = append(problems, fmt.Sprintf(
				"<%s> is present but EMPTY, which is not a value of its type. %s", m.Element, m.Why))
		default:
			present = append(present, fmt.Sprintf("%s=%s", m.Element, strings.TrimSpace(el.Text)))
		}
	}

	// ── roleFlags, if it is there to grade ───────────────────────────────
	head := fmt.Sprintf("%s carries mandatory elements %s", e.Where, orText(strings.Join(present, ", "),
		"NONE of the three"))
	rf := e.Doc.Child("roleFlags")
	if rf == nil {
		// The absence is already a problem above; there is no mask to adjudicate.
		return mupFinding(head+". No roleFlags element, so its bits could not be adjudicated at all",
			problems, disclosed)
	}
	mask, err := parseRoleFlags(rf.Text)
	if err != nil {
		problems = append(problems, err.Error())
		return mupFinding(head+". The roleFlags element could not be decoded, so its bits could not be "+
			"adjudicated", problems, disclosed)
	}
	head += fmt.Sprintf(". roleFlags=%q, which IEEE Std 2030.5-2018 p.169 (RoleFlagsType is a "+
		"HexBinary16) reads as 0x%04X = %s", strings.TrimSpace(rf.Text), mask, describeRoleFlags(mask))
	if len(e.PICS) > 0 {
		head += fmt.Sprintf(". PICS declaration supplied by the operator: %s", e.PICSRaw)
	}

	set := func(pos uint) bool { return mask&(1<<pos) != 0 }

	// reported records the bits whose OWN class check has already produced a
	// finding, so the PICS pass at the end does not say the same thing twice.
	// A bit like isMirror, declared in a PICS and clear on the wire, is one
	// defect: the device did not set a bit its own resource type requires. Two
	// findings about one byte read as two defects and inflate a count a reader
	// uses to judge severity.
	reported := map[uint]bool{}

	for _, b := range roleFlagBits {
		switch b.Class {
		case roleFlagResource:
			// isMirror. The only bit whose SHALL the resource's own identity
			// settles, and the one this product gets wrong.
			if !set(b.Bit) {
				reported[b.Bit] = true
				problems = append(problems, fmt.Sprintf(
					"bit %d %s is CLEAR. IEEE Std 2030.5-2018 p.169: \"%s\" — and this is a "+
						"MirrorUsagePoint, whose whole definition (p.215: \"A parallel to UsagePoint to "+
						"support mirroring\", carrying deviceLFDI, \"The LFDI of the device being "+
						"mirrored\") is that the server is NOT the measurement device. There is no "+
						"deployment in which this bit is legitimately clear on this resource",
					b.Bit, b.Name, b.SHALL))
			}
		case roleFlagComplementary:
			// Adjudicated once, from the lower bit, so the pair produces ONE
			// finding rather than two halves of the same sentence.
			if b.Bit > b.Partner {
				continue
			}
			partner, ok := roleFlagAt(b.Partner)
			if !ok {
				continue
			}
			switch {
			case set(b.Bit) && set(partner.Bit):
				reported[b.Bit], reported[partner.Bit] = true, true
				problems = append(problems, fmt.Sprintf(
					"bits %d %s and %d %s are BOTH set, and their conditions are complementary: "+
						"\"%s\" against \"%s\". A usage point cannot both be a premises point of "+
						"delivery and not be a premises aggregation point. No fact about the site "+
						"reconciles this; it is incoherent on the standard's text alone",
					b.Bit, b.Name, partner.Bit, partner.Name, b.SHALL, partner.SHALL))
			case !set(b.Bit) && !set(partner.Bit):
				reported[b.Bit], reported[partner.Bit] = true, true
				problems = append(problems, fmt.Sprintf(
					"bits %d %s and %d %s are BOTH clear, and between them the two conditions are "+
						"exhaustive: \"%s\" against \"%s\". Every usage point either is a premises "+
						"point of delivery or is not, so exactly one of these SHALLs applies to this "+
						"device and neither has been honoured. Which one is a fact about the site; "+
						"that one of them is missing is not",
					b.Bit, b.Name, partner.Bit, partner.Name, b.SHALL, partner.SHALL))
			default:
				which, other := b, partner
				if set(partner.Bit) {
					which, other = partner, b
				}
				disclosed = append(disclosed, fmt.Sprintf(
					"bit %d %s is set and bit %d %s is clear, which is COHERENT — exactly one of the "+
						"complementary pair, as the standard requires. Whether it is the RIGHT one is a "+
						"fact about the installation this transcript cannot settle: the device claims "+
						"\"%s\"", which.Bit, which.Name, other.Bit, other.Name, which.SHALL))
			}
		case roleFlagEvidenced:
			// isDER. Gradable only once the campaign has established that the
			// usage does apply to a DER.
			switch {
			case set(b.Bit):
				// Claiming it is never a failure: a DER client claiming to be a
				// DER client is the ordinary case.
			case e.DERClient != "":
				reported[b.Bit] = true
				problems = append(problems, fmt.Sprintf(
					"bit %d %s is CLEAR. IEEE Std 2030.5-2018 p.169: \"%s\" — and this campaign has the "+
						"premise in hand: %s. A head end that filters usage points by isDER will not "+
						"find this device's measurements at all",
					b.Bit, b.Name, b.SHALL, e.DERClient))
			default:
				disclosed = append(disclosed, fmt.Sprintf(
					"bit %d %s is clear and this window established no premise for its SHALL (\"%s\"): "+
						"nothing here shows the mirrored usage applies to a distributed energy resource, "+
						"so the bit is reported and NOT graded. A window that also observed a "+
						"DERCapability from this LFDI would decide it",
					b.Bit, b.Name, b.SHALL))
			}
		case roleFlagSiteFact:
			if !set(b.Bit) {
				continue
			}
			if picsDeclaresRole(e.PICS, b) {
				continue
			}
			if len(e.PICS) > 0 {
				problems = append(problems, fmt.Sprintf(
					"bit %d %s is SET and the operator-supplied PICS (%s) does not declare it. "+
						"IEEE Std 2030.5-2018 p.169: \"%s\" — a claim about the installation that "+
						"nothing on the wire can check and nobody has stood behind",
					b.Bit, b.Name, e.PICSRaw, b.SHALL))
				continue
			}
			disclosed = append(disclosed, fmt.Sprintf(
				"bit %d %s is SET, asserting \"%s\". That is a fact about the installation and not about "+
					"the protocol, so no transcript can confirm or refute it; supply %s to make it "+
					"gradable", b.Bit, b.Name, b.SHALL, mupRoleFlagsPICSParam))
		}
	}

	// Reserved positions.
	for i := uint(roleFlagsReservedFrom); i < 16; i++ {
		if !set(i) {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"bit %d is set and IEEE Std 2030.5-2018 p.169 assigns no role to it — \"Bit 7 to "+
				"15—Reserved\" — so nothing the device could be would make this bit honest. "+
				"2030.5-2023 p.179 reserves the same range, so there is no newer revision that "+
				"defines it either", i))
	}

	// The PICS's other direction: a declared role the resource does not carry.
	//
	// Bits whose own class check already failed are SKIPPED. A PICS that
	// declares isMirror on a device that leaves it clear adds nothing to
	// "isMirror is CLEAR and this is a MirrorUsagePoint" — it is the same byte,
	// the same fix, and one defect. Reporting it twice would inflate the
	// NON-CONFORMANT count a bundle reader uses to judge how bad a row is.
	for _, p := range e.PICS {
		b, ok := roleFlagNamed(p)
		if !ok || set(b.Bit) || reported[b.Bit] {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"the operator-supplied PICS declares %s and bit %d is CLEAR in the roleFlags the device "+
				"registered. The device and its own declaration disagree, which is a finding about the "+
				"submission whichever of the two is right", b.Name, b.Bit))
	}

	return mupFinding(head, problems, disclosed)
}

// mupFinding assembles the verdict from what was decided and what was not.
func mupFinding(head string, problems, disclosed []string) Finding {
	if len(problems) > 0 {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"%s. NON-CONFORMANT in %d place(s): %s", head, len(problems), strings.Join(problems, " | "))}
	}
	tail := ". Every mandatory element of UsagePointBase is present, every roleFlags bit whose SHALL " +
		"this evidence can decide is honoured, and no reserved bit is set"
	if len(disclosed) > 0 {
		tail += ". Claims this evidence can say nothing about, neither for nor against: " +
			strings.Join(disclosed, "; ")
	}
	return Finding{Verdict: certify.Pass, Observed: head + tail}
}

// roleFlagNamed resolves a PICS entry to a bit, by the standard's name or by
// number.
func roleFlagNamed(s string) (roleFlagBit, bool) {
	s = strings.TrimSpace(s)
	for _, b := range roleFlagBits {
		if strings.EqualFold(s, b.Name) || s == strconv.Itoa(int(b.Bit)) {
			return b, true
		}
	}
	return roleFlagBit{}, false
}

// picsDeclaresRole reports whether the operator's list names this bit.
func picsDeclaresRole(pics []string, b roleFlagBit) bool {
	for _, p := range pics {
		if got, ok := roleFlagNamed(p); ok && got.Bit == b.Bit {
			return true
		}
	}
	return false
}

// ── Gathering ────────────────────────────────────────────────────────────────

// gatherMUPFromTranscript finds the DUT's MirrorUsagePoint registration and the
// DER-client premise isDER's SHALL needs.
func gatherMUPFromTranscript(t *Transcript, pics []string, picsRaw string) mupEvidence {
	e := mupEvidence{PICS: pics, PICSRaw: picsRaw}
	for _, ex := range t.Method("POST") {
		if ex.Req == nil || len(ex.Req.Body) == 0 {
			continue
		}
		doc, err := ex.Req.SEP()
		if err != nil || doc.Local() != "MirrorUsagePoint" {
			continue
		}
		// FIRST registration wins. A DUT that re-registers has not changed what
		// it first told the server, and the registration this row is about is
		// the one that created the resource.
		e.Doc, e.Cite = doc, ex.Req
		e.Where = "the MirrorUsagePoint the DUT POSTed to " + ex.Req.Target
		break
	}
	// The isDER premise: a DERCapability PUT from this DUT is the DUT telling
	// THIS SERVER that it is a 2030.5 DER client, which is what makes "the usage
	// applies to a distributed energy resource" a fact this campaign holds
	// rather than an assumption it makes.
	for _, ex := range t.Method("PUT") {
		if ex.Req == nil || len(ex.Req.Body) == 0 {
			continue
		}
		doc, err := ex.Req.SEP()
		if err != nil {
			continue
		}
		if l := doc.Local(); l == "DERCapability" || l == "DERSettings" {
			e.DERClient = "the DUT PUT a " + l + " to " + ex.Req.Target +
				", which is this device declaring itself a 2030.5 DER client to this same server"
			break
		}
	}
	return e
}

// gatherMUPFromServer reads gridsim's durable MUP store.
//
// This tier matters more here than almost anywhere else in the suite.
// Registration is a ONE-TIME event — the DUT does it at first contact and never
// again — and BASIC-029 has no Setup that forces a fresh one, so by the time
// this row's window opens the POST has usually happened minutes or a whole
// campaign earlier. The store is the only thing that still remembers it, and
// AdminMUP.Body is what makes it gradable rather than merely countable.
func gatherMUPFromServer(v *ServerView, pics []string, picsRaw string) mupEvidence {
	e := mupEvidence{PICS: pics, PICSRaw: picsRaw}
	if v == nil {
		return e
	}
	for _, m := range v.MUPs {
		if m.Body == "" {
			continue
		}
		doc, err := ParseSEP([]byte(m.Body))
		if err != nil || doc.Local() != "MirrorUsagePoint" {
			continue
		}
		e.Doc = doc
		e.Where = fmt.Sprintf("the MirrorUsagePoint the DUT registered at %s (deviceLFDI=%s), as gridsim "+
			"stored the POST body", m.Href, m.LFDI)
		break
	}
	// The same premise, from the same store: a DERCapability the DUT PUT during
	// this run.
	if puts := v.PutsForInRun("DERCapability"); len(puts) > 0 {
		e.DERClient = "gridsim's durable store records a DERCapability this DUT PUT during this run, " +
			"which is this device declaring itself a 2030.5 DER client to this same server"
	}
	return e
}

// ── The criterion ────────────────────────────────────────────────────────────

// critMUPElementsAndRoleFlags is the MirrorUsagePoint content oracle as a
// catalog-row criterion. Mandatory elements and role bits, one verdict.
//
// It is deliberately SEPARATE from critMUPRegistered rather than folded into it.
// That criterion answers "did the DUT register at all, and was it accepted";
// this one answers "is what it registered a conformant resource". They fail for
// different reasons, they are fixed in different places, and a bundle in which
// one sentence covers both cannot tell a reader which.
func critMUPElementsAndRoleFlags(picsRaw string) criterion {
	pics := parsePICSModes(picsRaw) // same comma/space splitter; the vocabulary differs, not the syntax
	return criterion{
		Claim: "the MirrorUsagePoint the DUT registered carries every element IEEE 2030.5-2018 makes " +
			"mandatory, and its roleFlags honour every SHALL of RoleFlagsType this evidence can decide",
		How: "the sep+xml of the MirrorUsagePoint registration POST, checked for UsagePointBase's three " +
			"[1] elements (roleFlags, serviceCategoryKind, status — IEEE Std 2030.5-2018 p.215 Figure " +
			"B.26 and p.217) and decoded against a roleFlags bit table HAND-TRANSCRIBED from that " +
			"standard's p.169, carrying no dependency on lexa-proto/csipmodel — the product's own " +
			"model, whose agreement with the DUT would make this check vacuous (IW15-011) — with each " +
			"bit adjudicated by whether its SHALL is decidable from the resource, from its complementary " +
			"bit, from campaign evidence, or not at all",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			e := gatherMUPFromTranscript(t, pics, picsRaw)
			f := gradeMUP(e)
			if f.Unavailable != "" || e.Cite == nil {
				return f
			}
			return citeMessage(t, e.Cite, f.Verdict, "%s", f.Observed)
		},
		Server: func(v *ServerView) Finding {
			e := gatherMUPFromServer(v, pics, picsRaw)
			f := gradeMUP(e)
			if f.Unavailable != "" {
				if v != nil && len(v.MUPs) > 0 {
					return unavailable("gridsim's durable MUP store holds a registration for this DUT but " +
						"no stored POST body to grade — an older gridsim, predating the AdminMUP.Body " +
						"field this oracle reads. The registration HAPPENED (critMUPRegistered says so); " +
						"what it contained is not recoverable from this server")
				}
				return f
			}
			f.Observed += " (evaluated on the body gridsim stored, not on the wire)"
			return f
		},
		Skip: "neither the decrypted transcript nor gridsim's durable MUP store carried a " +
			"MirrorUsagePoint registration for this run, so what the DUT registered was never observed",
	}
}
