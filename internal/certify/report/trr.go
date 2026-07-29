package report

// trr.go assembles a Test Results Report PACKAGE from one or more completed
// evidence bundles.
//
// generate.go already knows how to write ONE submission for ONE certificate
// type. What was missing — and what this file adds — is everything between a
// campaign's evidence and that call:
//
//	which document's verdicts belong in which of the two reports,
//	how a bench verdict becomes one of the three the format enumerates,
//	where the Software Checksum comes from,
//	and which absent keys are the operator's fault and which nobody but a
//	SunSpec Authorized Test Laboratory can ever supply.
//
// # The verdict mapping, and why it is the only interesting decision here
//
// Both specifications enumerate exactly three values for a `Test <Test ID>`
// row:
//
//	SS-MODBUS-RESULTS-v1.2 §3.1.1, `Test <Test ID>`:
//	  "The result of the test performed. … Enumerated list. Choices are
//	   \"PASS\" or \"FAIL\" or \"NOT SUPPORTED\""
//	SS-CSIP-RESULTS-v1.1 §3.1.1 prints the identical row.
//
// This bench has four: PASS, FAIL, SKIP, WARN. Two map straight through. The
// other two do not map, and the temptation to make them is the whole reason
// this file is written down rather than inlined:
//
//	PASS  → PASS
//	FAIL  → FAIL
//	SKIP, where the CATALOG marks the case inapplicable to this product
//	      → NOT SUPPORTED, carrying the catalog's applicability_reason
//	SKIP, for any other reason  → NO ROW, recorded as a gap
//	WARN                        → NO ROW, recorded as a gap
//
// The third line is the one that needs its citation. "NOT SUPPORTED" is a
// statement about the IMPLEMENTATION — the feature is not there — and the only
// thing in this bench that makes that statement is the catalog's per-case
// `applicable: false` plus its `applicability_reason` ("the DUT is a direct DER
// client, not an aggregator client"). That is the PICS-backed fact the format's
// own §3.1.1 points at when it says of the PICS key that it is "the Protocol
// Implementation Conformance Statement of the Certified Software": the PICS is
// where a reader goes to confirm the feature was never claimed. So a
// catalog-inapplicable case earns NOT SUPPORTED and carries the reason.
//
// Every other SKIP is a fact about THIS RUN, not about the product: a capture
// nobody took, a capability the bench lacked, an assertion the check could not
// re-derive. And a WARN means "asserted, with a caveat". Neither is expressible
// in a three-member enumeration whose members are all claims about the device,
// so neither gets a row. The format has no fourth value and no per-test comment
// field, so the honest rendering is OMISSION WITH A RECORDED GAP: the case, its
// bench verdict and the reason land in the readiness report and in the package
// README, and Additional Test Comments carries the count. Mapping either to
// PASS would forge a result; mapping either to NOT SUPPORTED would tell SunSpec
// the device lacks a feature this run never established anything about.
//
// # The one place the two documents disagree with this rule
//
// SS-CSIP-RESULTS-v1.1 §3.1.2's worked example simply OMITS the procedures its
// subject did not implement — COMM-001 and CORE-001/002/018/019 are absent, not
// reported NOT SUPPORTED — while §3.1.1 defines NOT SUPPORTED and never says
// when to use it. The two halves of the document leave the treatment of an
// inapplicable procedure genuinely unresolved, which the catalog already
// records at RPT-041. This tool takes the NORMATIVE §3.1.1 enumeration over the
// non-normative example, emits NOT SUPPORTED with the reason attached, and says
// so in the emitted report so a laboratory can overrule it before submission.
// Silently omitting 28 aggregator rows would have produced a report that looks
// complete and quietly under-reports what was assessed.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
)

// DocCertType routes a catalog document key — the lower-case prefix of a case
// uid, before the "::" — to the certificate type whose Results Reporting
// specification governs it.
//
// The routing is data because it is a judgement, not a derivation. SSM-CONF
// (Secure SunSpec Modbus) and SS-TEST-PKI are not the SunSpec Modbus
// Conformance Test Procedures; they are TLS and certificate layers other
// submissions rest on, and this map still buckets their GAPS with the Modbus
// report — where a reviewer of that submission already looks — rather than in
// a third document that has no Results Reporting specification at all. It does
// NOT mean their rows earn a `Test <ID>` row in that report's SUMMARY.csv: see
// NoCertificationBasis immediately below, which is consulted first and governs
// whether a row is written at all.
var DocCertType = map[string]string{
	"csip-conf-v1.3":             CertTypeCSIP,
	"ss-modbus-conf-v1.4":        CertTypeModbus,
	"ss-modbus-client-conf-v1.1": CertTypeModbus,
	"ss-1547-test-v1.1":          CertTypeModbus,
	"ssm-conf-v0.8":              CertTypeModbus,
	"ss-test-pki":                CertTypeModbus,
}

// NoCertificationBasis names document keys whose rows must never become a
// `Test <ID>` row in a SUBMITTED SUMMARY.csv, with the reason a reviewer of
// the readiness report needs. Every case belonging to one of these documents
// becomes a Gap (kind GapNoCertBasis) regardless of its bench verdict — even a
// PASS does not earn a row, because the row itself has nowhere valid to go —
// while staying visible in the readiness report exactly like any other Gap.
//
//   - ss-modbus-client-conf-v1.1: SunSpec offers no Modbus CLIENT
//     certification. The document's 16 CLI-*/READ-*/WR-*/INFO-*/PROT-*/ERR-*
//     rows have no Test Description token and no Certificate Type in either
//     §3.1.1 key table to be reported under.
//   - ssm-conf-v0.8: Secure SunSpec Modbus is a v0.8 TEST-status
//     specification — SunSpec's own draft marking, not a certification basis
//     it issues certificates against. Its 39 rows are catalogued and
//     assessed, but there is no certification for them to be a result OF yet.
//   - ss-test-pki: not itself one of the two Results Reporting specs'
//     governed procedure documents, and Certificate Type "SunSpec Modbus"
//     does not obviously cover it either. This suite's registered rows
//     (PKI-4/5/6/7) judge the DUT's IEEE 2030.5/CSIP device identity profile
//     (see internal/certify/suitepki/doc.go: the SunSpec Test PKI
//     application note scopes itself in its own §1 to certificates "for use
//     with SunSpec CSIP Test Procedures", not Secure SunSpec Modbus ones).
//     Filing them under Certificate Type "SunSpec Modbus" — the previous
//     behaviour, and the one this map corrects — would misattribute a 2030.5
//     identity-profile finding to a submission that says nothing about it.
var NoCertificationBasis = map[string]string{
	"ss-modbus-client-conf-v1.1": "SunSpec offers no Modbus CLIENT certification: this document's rows carry " +
		"no Test Description token and no Certificate Type in either Results Reporting specification's " +
		"§3.1.1 key table, so they have no `Test <ID>` row to be in any SUMMARY.csv",
	"ssm-conf-v0.8": "SSM-CONF-v0.8 (Secure SunSpec Modbus) is a v0.8 TEST-status specification, SunSpec's own " +
		"draft marking, not a certification basis SunSpec issues certificates against; its rows have no " +
		"`Test <ID>` home in a submitted Summary Test Results until the specification reaches a certifiable " +
		"revision",
	"ss-test-pki": "SS-TEST-PKI is not itself one of the two Results Reporting specifications' governed " +
		"procedure documents, and Certificate Type \"SunSpec Modbus\" does not cover it: the rows this suite " +
		"registers (PKI-4/5/6/7) judge the DUT's IEEE 2030.5/CSIP device identity profile, per the SunSpec " +
		"Test PKI application note's own §1 scope (\"for use with SunSpec CSIP Test Procedures\"), not a " +
		"Secure SunSpec Modbus one — reporting them under Certificate Type \"SunSpec Modbus\" would " +
		"misattribute a 2030.5 finding to a submission it says nothing about",
}

// ReportOnSelf are the two documents whose subject is this tool rather than the
// device. Their rows say things about a Test Results Report; putting them in
// one as `Test RPT-KV-14,PASS` would report the report on itself.
var ReportOnSelf = map[string]bool{
	"ss-csip-results-v1.1":   true,
	"ss-modbus-results-v1.2": true,
}

// DocKeyOf returns the document key a case uid belongs to.
func DocKeyOf(uid string) string {
	if before, _, ok := strings.Cut(uid, "::"); ok {
		return before
	}
	return ""
}

// TestIDOf returns the procedure identifier a `Test <Test ID>` row must carry:
// the uid with its document prefix removed, which is the name the procedure
// document itself prints ("COMM-002", "MOD-1").
func TestIDOf(uid string) string {
	if _, after, ok := strings.Cut(uid, "::"); ok {
		return after
	}
	return uid
}

// GapKind classifies why a case carries no `Test <Test ID>` row.
type GapKind string

// The four reasons a bundle case produces no verdict row.
const (
	// GapEvidence — the case was SKIPped for a reason that is a fact about this
	// RUN (no capture, a missing bench capability, an assertion that could not
	// be re-derived), not about the device.
	GapEvidence GapKind = "evidence-unavailable"
	// GapCaveat — the case WARNed: asserted, with a caveat. The enumeration has
	// no member meaning "passed with a reservation".
	GapCaveat GapKind = "asserted-with-caveat"
	// GapUnrouted — the case belongs to a document DocCertType does not route,
	// so no Results Reporting specification governs its verdict.
	GapUnrouted GapKind = "unrouted-document"
	// GapNoCertBasis — the case belongs to a document NoCertificationBasis
	// names: it IS routed to a certificate type's report for the purpose of
	// grouping its readiness gaps, but the document itself carries no
	// certification a `Test <ID>` row could be reported AGAINST (no Test
	// Description token, a TEST-status specification, or — SS-TEST-PKI — a
	// scope that belongs to a different submission entirely). Applies
	// regardless of bench verdict: even a PASS earns no row here.
	GapNoCertBasis GapKind = "no-certification-basis"
)

// Gap is a bundle case that carries no verdict row, with the reason. Every gap
// is printed, written into the readiness report and counted in Additional Test
// Comments: an omission nobody can see is indistinguishable from a test that
// was never run.
type Gap struct {
	// ID is the procedure identifier, as a `Test <ID>` row would have spelled it.
	ID string `json:"id"`
	// UID is the full catalog uid, so the gap can be traced back to the bundle.
	UID string `json:"uid"`
	// DocKey is the document the case belongs to.
	DocKey string `json:"doc"`
	// BenchVerdict is what the evidence bundle recorded.
	BenchVerdict string  `json:"bench_verdict"`
	Kind         GapKind `json:"kind"`
	// Reason is the bundle's own note, trimmed to its first sentence.
	Reason string `json:"reason"`
	// Source is the evidence bundle directory the case came from.
	Source string `json:"source"`
}

// CaseApplicability is the catalog's per-case scoping decision, keyed by uid,
// carrying the reason for every case the catalog marks INAPPLICABLE to this
// product. It is the only thing in a bundle that licenses a NOT SUPPORTED row.
type CaseApplicability map[string]string

// LoadApplicability reads the catalog a bundle archived beside its evidence.
//
// A bundle carries its own catalog.json precisely so a later reader is not at
// the mercy of a catalog that has since changed; the applicability decisions
// this function returns are therefore the ones the campaign actually ran under.
//
// A bundle with no archived catalog is not an error here — it yields an empty
// map, under which NO case can be reported NOT SUPPORTED and every SKIP becomes
// a recorded gap. That is the conservative direction: the failure mode of a
// missing catalog is a report that claims less, not one that claims more.
func LoadApplicability(dir string, b *bundle.Bundle) (CaseApplicability, error) {
	path := ""
	if b != nil {
		for _, rel := range b.Files.Extra {
			if filepath.Base(rel) == "catalog.json" {
				path = filepath.Join(dir, filepath.FromSlash(rel))
			}
		}
	}
	if path == "" {
		return CaseApplicability{}, fmt.Errorf(
			"report: evidence bundle %s archives no catalog.json, so no case's applicability can be read "+
				"back; every SKIP will be recorded as a gap rather than reported NOT SUPPORTED", dir)
	}
	cat, err := certify.Load(path)
	if err != nil {
		return CaseApplicability{}, fmt.Errorf("report: read %s: %w", path, err)
	}
	out := CaseApplicability{}
	for _, c := range cat.All() {
		if c.Applicable {
			continue
		}
		reason := strings.TrimSpace(c.ApplicabilityReason)
		if reason == "" {
			reason = "the catalog marks this case inapplicable to this product but records no reason"
		}
		out[c.UID] = reason
	}
	return out, nil
}

// MapVerdict applies the rule the file comment derives. Exactly one of the two
// results is non-zero.
func MapVerdict(c bundle.TestCaseResult, na CaseApplicability, source string) (*TestVerdict, *Gap) {
	doc := DocKeyOf(c.ID)
	id := TestIDOf(c.ID)
	gap := func(kind GapKind, reason string) (*TestVerdict, *Gap) {
		return nil, &Gap{
			ID: id, UID: c.ID, DocKey: doc, BenchVerdict: string(c.Verdict),
			Kind: kind, Reason: reason, Source: source,
		}
	}
	if _, routed := DocCertType[doc]; !routed {
		return gap(GapUnrouted, fmt.Sprintf(
			"no Results Reporting specification governs document %q, so its verdict has no report to go in", doc))
	}
	// Checked ahead of the verdict switch, and unconditionally of it: a
	// document with no certification basis earns no `Test <ID>` row no matter
	// what the bench observed — a PASS included. See NoCertificationBasis.
	if reason, excluded := NoCertificationBasis[doc]; excluded {
		return gap(GapNoCertBasis, reason)
	}
	switch c.Verdict {
	case bundle.Pass:
		return &TestVerdict{ID: id, Verdict: "PASS"}, nil
	case bundle.Fail:
		return &TestVerdict{ID: id, Verdict: "FAIL"}, nil
	case bundle.Skip:
		if reason, inapplicable := na[c.ID]; inapplicable {
			return &TestVerdict{ID: id, Verdict: "NOT SUPPORTED", Note: reason}, nil
		}
		return gap(GapEvidence, firstSentence(c.Notes))
	case bundle.Warn:
		return gap(GapCaveat, firstSentence(c.Notes))
	default:
		return gap(GapEvidence, fmt.Sprintf("bench verdict %q has no mapping", c.Verdict))
	}
}

// firstSentence trims a bundle note to something that fits a table cell without
// losing the reason. The runner prefixes live-phase prose to many notes; that
// prefix is dropped here because it says the same thing on every row and would
// crowd out the part that differs.
func firstSentence(s string) string {
	const prefix = "Live-phase observation"
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if strings.HasPrefix(s, prefix) {
		if _, after, ok := strings.Cut(s, "): "); ok {
			s = after
		}
	}
	if i := strings.Index(s, ". "); i > 0 && i < 300 {
		return s[:i+1]
	}
	if len(s) > 300 {
		return s[:297] + "…"
	}
	if s == "" {
		return "the evidence bundle records no reason"
	}
	return s
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// Source is one completed evidence bundle contributing to a report, optionally
// narrowed to some of the documents it covers.
//
// The narrowing exists because two campaigns legitimately cover the same
// document with different results — a CSIP-only re-run beside an earlier full
// run — and a package built from both would carry two verdicts for one
// procedure. Rather than pick one silently, the assembler refuses and names the
// conflict; Docs is how the operator resolves it.
type Source struct {
	// Dir is the evidence bundle directory.
	Dir string
	// Bundle is the loaded bundle.
	Bundle *bundle.Bundle
	// Docs, when non-empty, restricts this source to those document keys.
	Docs []string
	// Applicability is the catalog scoping this bundle archived.
	Applicability CaseApplicability
	// Note records anything the loader wants carried into the report, such as a
	// missing archived catalog.
	Note string
}

func (s Source) covers(docKey string) bool {
	if len(s.Docs) == 0 {
		return true
	}
	for _, d := range s.Docs {
		if strings.EqualFold(strings.TrimSpace(d), docKey) {
			return true
		}
	}
	return false
}

// Collated is the verdict set for one certificate type, gathered across sources.
type Collated struct {
	CertType string
	Verdicts []TestVerdict
	Gaps     []Gap
	// Sources are the bundle directories that contributed a row.
	Sources []string
}

// Collate maps every source bundle's cases into the two certificate types'
// verdict sets.
//
// It refuses two things rather than resolving them:
//
//   - the same procedure reported twice with DIFFERENT verdicts. A Summary Test
//     Results has one row per test id; choosing between two campaigns' answers
//     is the operator's decision, not a tie-break rule.
//   - two DIFFERENT procedures whose ids collide once the document prefix is
//     stripped. `Test PROT-1` from the Modbus client procedures and a
//     hypothetical `PROT-1` elsewhere would occupy one key, and the format has
//     no way to distinguish them.
func Collate(sources []Source) (map[string]*Collated, error) {
	out := map[string]*Collated{}
	type origin struct {
		uid, source, verdict string
	}
	seen := map[string]origin{} // certType+"|"+id
	var conflicts []string

	for _, src := range sources {
		if src.Bundle == nil {
			continue
		}
		for _, c := range src.Bundle.Cases {
			doc := DocKeyOf(c.ID)
			if ReportOnSelf[doc] {
				continue
			}
			if !src.covers(doc) {
				continue
			}
			certType, routed := DocCertType[doc]
			if !routed {
				certType = CertTypeModbus // only so the gap has somewhere to be reported
			}
			col := out[certType]
			if col == nil {
				col = &Collated{CertType: certType}
				out[certType] = col
			}
			if !containsStr(col.Sources, src.Dir) {
				col.Sources = append(col.Sources, src.Dir)
			}
			row, gap := MapVerdict(c, src.Applicability, src.Dir)
			if gap != nil {
				col.Gaps = append(col.Gaps, *gap)
				continue
			}
			key := certType + "|" + row.ID
			if prev, dup := seen[key]; dup {
				switch {
				case prev.uid != c.ID:
					conflicts = append(conflicts, fmt.Sprintf(
						"`Test %s` would be written by two different procedures, %s (%s) and %s (%s); "+
							"one CSV key cannot carry both",
						row.ID, prev.uid, prev.source, c.ID, src.Dir))
				case prev.verdict != row.Verdict:
					conflicts = append(conflicts, fmt.Sprintf(
						"%s is %s in %s and %s in %s; a Summary Test Results carries one verdict per "+
							"procedure, and which campaign is the submitted one is not this tool's decision "+
							"(narrow a source with dir=<doc-key>)",
						c.ID, prev.verdict, prev.source, row.Verdict, src.Dir))
				}
				continue
			}
			seen[key] = origin{uid: c.ID, source: src.Dir, verdict: row.Verdict}
			col.Verdicts = append(col.Verdicts, *row)
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return nil, fmt.Errorf("report: the evidence bundles disagree and the disagreement cannot be "+
			"resolved by a tool:\n  · %s", strings.Join(conflicts, "\n  · "))
	}
	for _, col := range out {
		sort.SliceStable(col.Verdicts, func(i, j int) bool { return col.Verdicts[i].ID < col.Verdicts[j].ID })
		sort.SliceStable(col.Gaps, func(i, j int) bool { return col.Gaps[i].UID < col.Gaps[j].UID })
	}
	return out, nil
}

// Counts returns the verdict distribution, for a console line and for the
// report's own comments.
func (c *Collated) Counts() map[string]int {
	m := map[string]int{}
	for _, v := range c.Verdicts {
		m[v.Verdict]++
	}
	return m
}

// ---------------------------------------------------------------------------
// Software Checksum autofill
// ---------------------------------------------------------------------------

// ParseBuildStamp reads the DUT build string an evidence bundle records —
// `mbaps:856bc322 nb:ba8d13dd modbus:dcfc6b4b`, the campaign's convention of
// naming each deployed binary and the leading digits of its sha256 — into a
// map from element name to digest.
//
// A token that is not `name:value` is ignored rather than guessed at: the field
// is free text an operator types, and a report must not turn a typo into a
// Software Checksum.
func ParseBuildStamp(s string) map[string]string {
	out := map[string]string{}
	for _, tok := range strings.Fields(s) {
		name, digest, ok := strings.Cut(tok, ":")
		if !ok || name == "" || digest == "" {
			continue
		}
		out[name] = digest
	}
	return out
}

// ChecksumFill is the record of what autofill did, for the console and for the
// readiness report. Nothing here is silent: a checksum that appeared in the CSV
// without the operator typing it must be traceable to the bundle it came from.
type ChecksumFill struct {
	// Filled names each `Software Checksum <n>` that was derived, and from what.
	Filled []string
	// Unresolved names each software record whose Element matched nothing in any
	// bundle's build stamp.
	Unresolved []string
	// Stamps is the merged element→digest map the fill drew on.
	Stamps map[string]string
}

// FillChecksums derives absent `Software Checksum <n>` values from the DUT build
// stamps the evidence bundles recorded.
//
// It fills only an EMPTY checksum on a record that names an Element, and never
// overwrites a value the operator supplied: a submitter who computed the digest
// another way is stating something this tool has no standing to correct.
//
// A build stamp that two bundles disagree about is a hard error. The whole
// point of §2.1 — "All tests must be completed without altering the software or
// hardware during the testing process" — is that one image is behind every
// reported result, and two campaigns run against different binaries cannot be
// covered by one Software Checksum.
func FillChecksums(cfg *SubmissionConfig, sources []Source) (*ChecksumFill, error) {
	fill := &ChecksumFill{Stamps: map[string]string{}}
	from := map[string]string{}
	var drift []string
	for _, src := range sources {
		if src.Bundle == nil {
			continue
		}
		for name, digest := range ParseBuildStamp(src.Bundle.Run.DUT.Build) {
			if prev, ok := fill.Stamps[name]; ok && prev != digest {
				drift = append(drift, fmt.Sprintf(
					"element %q is %s in %s and %s in %s", name, prev, from[name], digest, src.Dir))
				continue
			}
			fill.Stamps[name], from[name] = digest, src.Dir
		}
	}
	if len(drift) > 0 {
		sort.Strings(drift)
		return nil, fmt.Errorf("report: the evidence bundles were produced against different builds, so no "+
			"single `Software Checksum` covers them — §2.1 requires the software to be unaltered across the "+
			"whole campaign:\n  · %s", strings.Join(drift, "\n  · "))
	}
	for i := range cfg.Software {
		rec := &cfg.Software[i]
		if strings.TrimSpace(rec.Element) == "" || strings.TrimSpace(rec.Checksum) != "" {
			continue
		}
		digest, ok := fill.Stamps[rec.Element]
		if !ok {
			fill.Unresolved = append(fill.Unresolved, fmt.Sprintf(
				"`Software Checksum %d` (%s): no evidence bundle records a build stamp for element %q "+
					"(stamps present: %s)", i+1, rec.Name, rec.Element, stampNames(fill.Stamps)))
			continue
		}
		rec.Checksum = digest
		fill.Filled = append(fill.Filled, fmt.Sprintf(
			"`Software Checksum %d` = %s, from the `%s` element of the evidence bundle's recorded DUT build "+
				"stamp (%s)", i+1, digest, rec.Element, from[rec.Element]))
	}
	if len(fill.Filled) > 0 && strings.TrimSpace(cfg.ChecksumAlgorithm) == "" {
		// The format defines no key for the algorithm and generate.go states it
		// in Additional Test Comments. Saying exactly what these digits are is a
		// fact about the bundle, not an invention.
		cfg.ChecksumAlgorithm = "leading hex digits of the SHA-256 of the deployed binary, as recorded in " +
			"the evidence bundle's DUT build stamp"
	}
	return fill, nil
}

func stampNames(m map[string]string) string {
	if len(m) == 0 {
		return "none"
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// ---------------------------------------------------------------------------
// Which absent keys are whose fault
// ---------------------------------------------------------------------------

// AuthorityKeys are the required §3.1.1 keys that NO self-test can honestly
// fill, with the reason. Each names a fact that comes into existence only when
// SunSpec issues a certificate or when one of the Appendix A1 laboratories runs
// the campaign.
//
// They are treated differently from the rest not to excuse them but to make the
// error message useful: telling an operator to "supply Certificate Number" is
// telling them to invent one.
var AuthorityKeys = map[string]string{
	"Certificate Number":        "assigned by SunSpec when the certificate is issued; it does not exist yet",
	"Date Issued":               "the date SunSpec issues the certificate; it does not exist yet",
	"Certificate Signer Name":   "the SunSpec Alliance person who approves the certificate, filled in post-submission",
	"Test Laboratory":           "one of the Appendix A1 Nationally Recognized Test Labs; an in-house bench is not one",
	"Supervising Test Engineer": "an employee of that laboratory, per the §3.1.1 description of the key",
}

// SelfTestDeclaration is the sentence a report generated outside an Authorized
// Test Laboratory must carry, so that nobody reading the CSV mistakes the
// absent laboratory rows for an oversight.
//
// It goes in Additional Test Comments because that is the only free-text key
// either format has. It is NOT written into the laboratory keys themselves: the
// results-report suite's keyCheck validates a SUPPLIED value against its rule,
// and `Test Laboratory,SELF-TEST` would be a value outside the Appendix A1
// enumeration — a document that fails its own validation, which is worse than
// one that visibly omits the row. §3.1's "keys must match the documented key
// values" governs the key; nothing licenses a placeholder value.
const SelfTestDeclaration = "SELF-TEST: this report was generated from an in-house conformance campaign, not " +
	"by a SunSpec Authorized Test Laboratory. The Certificate Number, Date Issued, Certificate Signer Name, " +
	"Test Laboratory and Supervising Test Engineer keys are therefore ABSENT rather than filled in: each is a " +
	"fact only SunSpec or an Appendix A1 laboratory can state, and this tool does not invent one."

// MissingOperatorKeys returns the required keys the SUBMITTER could have
// supplied and did not. These are a hard error: a blank company name or a
// missing PICS URL is an unfinished configuration file, not a limit of the
// process.
func MissingOperatorKeys(cfg *SubmissionConfig, certType string, verdicts []TestVerdict) []MissingKey {
	sum := BuildSummary(cfg, certType, verdicts)
	var out []MissingKey
	for _, m := range sum.Missing {
		if _, authority := AuthorityKeys[m.Key]; authority {
			continue
		}
		out = append(out, m)
	}
	return out
}

// MissingAuthorityKeys returns the required keys nobody but SunSpec or an
// Authorized Test Laboratory can supply, with the reason, so the emitted report
// can say which absences are structural.
func MissingAuthorityKeys(cfg *SubmissionConfig, certType string, verdicts []TestVerdict) []MissingKey {
	sum := BuildSummary(cfg, certType, verdicts)
	var out []MissingKey
	for _, m := range sum.Missing {
		if why, authority := AuthorityKeys[m.Key]; authority {
			out = append(out, MissingKey{Key: m.Key, UID: m.UID, Why: why})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The package
// ---------------------------------------------------------------------------

// TRROptions is everything a Test Results Report package is built from.
type TRROptions struct {
	// Dir is the package directory. Each certificate type gets a subdirectory
	// under it.
	Dir string
	// Sources are the completed evidence bundles.
	Sources []Source
	// Config is the submitter metadata. It is COPIED before checksum autofill,
	// so the caller's value is not mutated behind its back.
	Config *SubmissionConfig
	// Logs supplies the §4 detailed test logs per certificate type, keyed by
	// certificate type. A nil map emits no logs and the readiness report says so.
	ModbusLogs *ModbusTestLogs
	CSIPLogs   *CSIPTestLogs
	// LogNotes are the log-derivation notes to carry into the README.
	LogNotes []string
	// LogUndecryptable names every captured conversation the §4 logs do not
	// carry because this run holds no secret for it. §4 requires ALL messages in
	// unencrypted form; an archive that is short must say by exactly what.
	LogUndecryptable []string
	// Tool and ToolVersion identify the generator.
	Tool, ToolVersion string
	// Now overrides the clock. It is the ONE value that legitimately differs
	// between two runs over the same bundles, which is why it is separable: the
	// determinism test pins it and compares the rest byte for byte.
	Now time.Time
	// AllowAuthorityGaps writes the package even though the laboratory and
	// certificate keys are absent, under the SUMMARY-INCOMPLETE.csv name and
	// with the SELF-TEST declaration. It does NOT excuse a missing operator key.
	AllowAuthorityGaps bool
}

// TRRPart is one certificate type's submission inside the package.
type TRRPart struct {
	CertType   string
	Submission *Submission
	Collated   *Collated
	// AuthorityGaps are the required keys only SunSpec or a laboratory can fill.
	AuthorityGaps []MissingKey
}

// TRR is the emitted package.
type TRR struct {
	Dir   string
	Parts []*TRRPart
	// Fill records what the Software Checksum autofill did.
	Fill *ChecksumFill
	// Files are every path written, relative to Dir.
	Files []string
	// Generated is the one field that legitimately varies between two runs over
	// the same evidence.
	Generated time.Time
}

// GenerateTRR writes the package: one submission per certificate type covered
// by the sources, a README stating the verdict-mapping rule and every gap, and
// a manifest over the lot.
func GenerateTRR(o TRROptions) (*TRR, error) {
	if o.Dir == "" {
		return nil, fmt.Errorf("report: GenerateTRR needs an output directory")
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	cfg := &SubmissionConfig{}
	if o.Config != nil {
		local := *o.Config
		local.Software = append([]SoftwareRecord(nil), o.Config.Software...)
		local.OS = append([]OSRecord(nil), o.Config.OS...)
		cfg = &local
	}

	collated, err := Collate(o.Sources)
	if err != nil {
		return nil, err
	}
	if len(collated) == 0 {
		return nil, fmt.Errorf("report: no evidence bundle contributed a case belonging to a document any " +
			"Results Reporting specification governs; there is nothing to report")
	}

	fill, err := FillChecksums(cfg, o.Sources)
	if err != nil {
		return nil, err
	}

	// Every operator-suppliable key, across every certificate type in the
	// package, refused in ONE message. Discovering the second missing key after
	// fixing the first is a worse experience than being told both.
	var missing []string
	for _, certType := range sortedCertTypes(collated) {
		for _, m := range MissingOperatorKeys(cfg.For(certType), certType, collated[certType].Verdicts) {
			missing = append(missing, fmt.Sprintf("%s (%s) — %s", m.Key, certType, m.Why))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("report: %d required key(s) have no value and every one of them is the "+
			"submitter's to supply — no blank is written in their place:\n  · %s",
			len(missing), strings.Join(uniq(missing), "\n  · "))
	}

	trr := &TRR{Dir: o.Dir, Fill: fill, Generated: o.Now}
	for _, certType := range sortedCertTypes(collated) {
		col := collated[certType]
		typed := cfg.For(certType)
		part := &TRRPart{
			CertType: certType, Collated: col,
			AuthorityGaps: MissingAuthorityKeys(typed, certType, col.Verdicts),
		}
		if len(part.AuthorityGaps) > 0 && !o.AllowAuthorityGaps {
			var names []string
			for _, m := range part.AuthorityGaps {
				names = append(names, fmt.Sprintf("%s — %s", m.Key, m.Why))
			}
			return nil, fmt.Errorf("report: %d required key(s) can only be supplied by SunSpec or a SunSpec "+
				"Authorized Test Laboratory:\n  · %s\nPass AllowAuthorityGaps to write the package anyway; "+
				"the summary is then written as %s and carries the SELF-TEST declaration",
				len(part.AuthorityGaps), strings.Join(names, "\n  · "), IncompleteFile)
		}

		local := *typed
		local.AdditionalTestComments = composeTRRComments(typed, part, o)
		opts := GenerateOptions{
			Dir:             filepath.Join(o.Dir, certTypeSlug(certType)),
			CertType:        certType,
			Doc:             docFor(certType),
			Config:          &local,
			Verdicts:        col.Verdicts,
			Gaps:            col.Gaps,
			AllowIncomplete: true,
			Tool:            o.Tool,
			ToolVersion:     o.ToolVersion,
			Now:             o.Now,
		}
		if certType == CertTypeModbus {
			opts.ModbusLogs = o.ModbusLogs
		} else {
			opts.CSIPLogs = o.CSIPLogs
			// RRS v1.1 §5 (Chapter 5, CSIP only): a raw TLS packet trace per
			// COMM-004 connection scenario. The traces were written by an
			// earlier live run of the results-report suite (RPT-060) into
			// each contributing bundle's own archive/traces/ directory —
			// discovered from col.Sources rather than threaded through as a
			// caller-supplied option, so a TRR built from a bundle that has
			// them can never omit them by forgetting to pass a field.
			traces, err := DiscoverTraces(col.Sources)
			if err != nil {
				return nil, err
			}
			traces, err = CopyTraces(opts.Dir, traces)
			if err != nil {
				return nil, err
			}
			opts.Traces = traces
		}
		sub, err := Generate(opts)
		if err != nil {
			return nil, err
		}
		part.Submission = sub
		trr.Parts = append(trr.Parts, part)
		for _, rel := range sub.Files {
			trr.Files = append(trr.Files, filepath.Join(certTypeSlug(certType), rel))
		}
	}

	if err := writeFile(o.Dir, TRRReadmeFile, []byte(trr.Readme(o))); err != nil {
		return nil, err
	}
	trr.Files = append(trr.Files, TRRReadmeFile)
	man, err := manifest(o.Dir, trr.Files)
	if err != nil {
		return nil, err
	}
	if err := writeFile(o.Dir, ManifestFile, man); err != nil {
		return nil, err
	}
	return trr, nil
}

// TRRReadmeFile is the package-level statement of what the package is, which
// rule produced its verdicts, and what it does not carry.
const TRRReadmeFile = "TEST-RESULTS-REPORT.md"

func sortedCertTypes(m map[string]*Collated) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func uniq(v []string) []string {
	out := v[:0:0]
	for i, s := range v {
		if i > 0 && s == v[i-1] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// composeTRRComments builds the Additional Test Comments value for one part.
//
// Everything here is a fact about how this report was produced, stated in the
// only free-text key the format has, because a reader of the public CSV must be
// able to see the two things that would otherwise be invisible: that no
// laboratory supervised the campaign, and that the report covers fewer
// procedures than the campaign ran.
func composeTRRComments(cfg *SubmissionConfig, part *TRRPart, o TRROptions) string {
	parts := []string{}
	if s := strings.TrimSpace(cfg.AdditionalTestComments); s != "" {
		parts = append(parts, s)
	}
	if len(part.AuthorityGaps) > 0 {
		parts = append(parts, SelfTestDeclaration)
	}
	counts := part.Collated.Counts()
	if counts["NOT SUPPORTED"] > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d procedure(s) are reported NOT SUPPORTED because the test catalog scopes them out of this "+
				"product (for example an aggregator-client or 2030.5-server role it does not implement); "+
				"the reason for each is in %s.", counts["NOT SUPPORTED"], ReadinessFile))
	}
	if n := len(part.Collated.Gaps); n > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d procedure(s) the campaign ran carry NO row in this report: the bench verdict was SKIP for a "+
				"reason about this RUN rather than about the device, or WARN (asserted with a caveat), and "+
				"the PASS / FAIL / NOT SUPPORTED enumeration has no member for either. They are omitted, not "+
				"passed: each is named with its reason in %s.", n, ReadinessFile))
	}
	return strings.Join(parts, " ")
}

// Readme renders the package-level document.
func (t *TRR) Readme(o TRROptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Test Results Report package\n\n")
	fmt.Fprintf(&b, "**Generated:** %s  \n", t.Generated.UTC().Format(time.RFC3339))
	if o.Tool != "" {
		fmt.Fprintf(&b, "**Generated by:** %s %s\n", o.Tool, o.ToolVersion)
	}
	fmt.Fprintf(&b, "\nThis package is the submission artefact the two SunSpec Results Reporting\n"+
		"specifications define — a public Summary Test Results CSV and an archived JSON\n"+
		"Detailed Test Log per certificate type. Nothing in it was typed by this tool:\n"+
		"the verdicts come from the evidence bundles named below, the submitter fields\n"+
		"from a configuration file, and any key nobody supplied is absent rather than\n"+
		"filled in.\n\n")

	fmt.Fprintf(&b, "## Evidence bundles\n\n")
	for _, s := range o.Sources {
		scope := "every document it covers"
		if len(s.Docs) > 0 {
			scope = strings.Join(s.Docs, ", ")
		}
		cases := 0
		tool := ""
		if s.Bundle != nil {
			cases = len(s.Bundle.Cases)
			tool = fmt.Sprintf("%s %s", s.Bundle.Run.Tool, s.Bundle.Run.ToolVersion)
		}
		fmt.Fprintf(&b, "- `%s` — %d case(s), %s; contributing %s\n", s.Dir, cases, tool, scope)
		if s.Note != "" {
			fmt.Fprintf(&b, "  - ⚠ %s\n", s.Note)
		}
	}

	fmt.Fprintf(&b, "\n## The verdict mapping\n\n")
	fmt.Fprintf(&b, "Both specifications enumerate exactly three values for a `Test <Test ID>` row\n"+
		"(§3.1.1: “Enumerated list. Choices are \"PASS\" or \"FAIL\" or “NOT SUPPORTED””).\n"+
		"This bench records four. The mapping, and the reason for each line:\n\n")
	fmt.Fprintf(&b, "| Bench verdict | Reported as | Why |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| PASS | `PASS` | direct |\n")
	fmt.Fprintf(&b, "| FAIL | `FAIL` | direct |\n")
	fmt.Fprintf(&b, "| SKIP, case marked inapplicable by the test catalog | `NOT SUPPORTED` | "+
		"the catalog's `applicable: false` and its `applicability_reason` are a statement about what the "+
		"product implements — the same thing the PICS records — and NOT SUPPORTED is the enumeration's "+
		"member for it. The reason is carried into `%s`. |\n", ReadinessFile)
	fmt.Fprintf(&b, "| SKIP, any other reason | *(no row)* | the reason is a fact about this RUN — no "+
		"capture, a bench capability that was absent, an assertion that could not be re-derived — not about "+
		"the device. None of the three members says that. |\n")
	fmt.Fprintf(&b, "| WARN | *(no row)* | “asserted, with a caveat”. The enumeration has no member "+
		"meaning “passed with a reservation”, and the format has no per-test comment field. |\n\n")
	fmt.Fprintf(&b, "An omitted row is NOT a pass and NOT a NOT SUPPORTED. Every omission is listed\n"+
		"below and in each part's `%s`, with the bench verdict and the reason.\n\n", ReadinessFile)
	fmt.Fprintf(&b, "> **Known divergence.** SS-CSIP-RESULTS-v1.1 §3.1.2's worked example simply OMITS the\n"+
		"> procedures its subject did not implement (COMM-001, CORE-001/002/018/019 are absent) rather than\n"+
		"> reporting them NOT SUPPORTED, while §3.1.1 defines NOT SUPPORTED and never says when to use it.\n"+
		"> This tool follows the NORMATIVE §3.1.1 enumeration over the non-normative example. A laboratory\n"+
		"> that knows SunSpec's ingest expects the example's treatment should say so before submission.\n\n")

	for _, part := range t.Parts {
		counts := part.Collated.Counts()
		fmt.Fprintf(&b, "## %s\n\n", part.CertType)
		fmt.Fprintf(&b, "Directory: `%s/`\n\n", certTypeSlug(part.CertType))
		fmt.Fprintf(&b, "- %d verdict row(s): %d PASS, %d FAIL, %d NOT SUPPORTED\n",
			len(part.Collated.Verdicts), counts["PASS"], counts["FAIL"], counts["NOT SUPPORTED"])
		fmt.Fprintf(&b, "- %d procedure(s) omitted with a recorded gap\n", len(part.Collated.Gaps))
		if part.Submission != nil {
			fmt.Fprintf(&b, "- summary: `%s`\n", filepath.Base(part.Submission.SummaryPath))
			if part.Submission.LogsPath == "" {
				fmt.Fprintf(&b, "- **no §4 Detailed Test Log was emitted** — see the log notes below\n")
			}
		}
		if len(part.AuthorityGaps) > 0 {
			fmt.Fprintf(&b, "\n### Keys only SunSpec or an Authorized Test Laboratory can supply\n\n")
			for _, m := range part.AuthorityGaps {
				fmt.Fprintf(&b, "- `%s` — %s\n", m.Key, m.Why)
			}
			fmt.Fprintf(&b, "\n%s\n", SelfTestDeclaration)
		}
		if len(part.Collated.Gaps) > 0 {
			fmt.Fprintf(&b, "\n### Omitted procedures\n\n")
			fmt.Fprintf(&b, "| Procedure | Bench verdict | Kind | Reason |\n|---|---|---|---|\n")
			for _, g := range part.Collated.Gaps {
				fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n",
					g.ID, g.BenchVerdict, g.Kind, mdEscape(g.Reason))
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	if t.Fill != nil && (len(t.Fill.Filled) > 0 || len(t.Fill.Unresolved) > 0) {
		fmt.Fprintf(&b, "## Software Checksum\n\n")
		for _, f := range t.Fill.Filled {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		for _, u := range t.Fill.Unresolved {
			fmt.Fprintf(&b, "- ⚠ %s\n", u)
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(o.LogNotes) > 0 {
		fmt.Fprintf(&b, "## Detailed Test Logs\n\n")
		fmt.Fprintf(&b, "§4 of both documents requires the logs to carry the messages in UNENCRYPTED form.\n"+
			"What follows is exactly what could and could not be rendered from each bundle's own capture.\n"+
			"The §4.1.x JSON objects are closed — this repository's parsers reject unknown fields, because\n"+
			"the documents describe no extension element — so a session that could not be decrypted cannot\n"+
			"be recorded INSIDE the log document, and is recorded here instead.\n\n")
		for _, n := range o.LogNotes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		fmt.Fprintf(&b, "\n")
	}
	if len(o.LogUndecryptable) > 0 {
		fmt.Fprintf(&b, "### Conversations that could not be read\n\n")
		fmt.Fprintf(&b, "%d captured conversation(s). Each is a message set §4 asked for and this run cannot\n"+
			"supply: the capture holds the ciphertext and the key log holds no secret for the session.\n"+
			"They are listed rather than dropped because a short archive with no explanation is exactly the\n"+
			"kind of gap a certification reviewer is right to distrust.\n\n", len(o.LogUndecryptable))
		for _, u := range o.LogUndecryptable {
			fmt.Fprintf(&b, "- %s\n", u)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}
