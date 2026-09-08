package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/metricscrape"
	"csip-tls-test/internal/evidence/pcapng"
)

// SchemaVersion identifies the bundle.json layout every NEW bundle is written
// with. A verifier that does not recognise a bundle's schema must refuse to pass
// it rather than check what it happens to understand.
const SchemaVersion = "lexa-evidence-bundle/2"

// SchemaVersion1 is the layout every bundle in the archive up to 2026-08-26
// carries. It is still read, and still verified, by this package.
//
// # Why /2 exists at all
//
// The bundle package's standing convention is that a purely ADDITIVE field needs
// no version bump: Load rejects unknown fields but tolerates missing ones, so an
// older bundle simply carries no key and an older reader of a newer bundle
// ignores nothing it needed (see Bundle.Metrics and Bundle.Timebases, both added
// that way). VerdictNotApplicable is the first change that convention does not
// cover. It adds a VALUE to a vocabulary, not a key to a struct, and a /1-era
// verifier meeting it would reject the bundle with "records verdict "N/A", which
// is not one of PASS/FAIL/SKIP/WARN" — a true statement about that verifier
// dressed up as a finding about the evidence. The version is what lets the old
// reader say the honest thing instead: this bundle is newer than I am.
const SchemaVersion1 = "lexa-evidence-bundle/1"

// knownSchemas are the layouts this package reads, newest first. Writing is
// always SchemaVersion; reading accepts any of these, and features introduced
// after a given layout are refused in bundles declaring it (see
// schemaAtLeast2).
var knownSchemas = []string{SchemaVersion, SchemaVersion1}

// schemaAtLeast2 reports whether a bundle's declared layout is one in which the
// not-applicable verdict exists. A /1 bundle carrying it was not written by this
// engine, and the verifier says so rather than accepting a vocabulary that
// layout never had.
func schemaAtLeast2(schema string) bool { return schema == SchemaVersion }

// File names inside a bundle directory. They are fixed so that "run Verify on
// this directory" needs no arguments and no explanation.
const (
	BundleFile   = "bundle.json"
	ReportFile   = "REPORT.md"
	ManifestFile = "MANIFEST.sha256"
	CaptureDir   = "capture"
)

// Verdict is a test case's or assertion's outcome, using the same values as the
// rest of this bench's conformance reporting (sim/ssm-conformance), plus the
// out-of-scope verdict VerdictNotApplicable this engine needs and that
// vocabulary has no word for.
type Verdict string

// The verdicts.
const (
	// Pass — the criterion was asserted on the wire and held.
	Pass Verdict = "PASS"
	// Fail — the criterion was asserted and did not hold.
	Fail Verdict = "FAIL"
	// Skip — addressed but not wire-assertable by this run; Observed says why.
	Skip Verdict = "SKIP"
	// Warn — asserted with a caveat.
	Warn Verdict = "WARN"
	// VerdictNotApplicable — the row is NOT IN SCOPE for this candidate at all,
	// so no outcome about it exists to report.
	//
	// It is deliberately a different word from Skip, and the difference is the
	// whole point. Skip says "this run could not measure it" — a fact about the
	// bench, an evidence gap, something an operator might fix by re-running with
	// a capture or a -gateway-ssh. N/A says "there is nothing here to measure" —
	// a fact about the CANDIDATE's declared scope, which no amount of re-running
	// changes. Reporting the second as the first is how a campaign accumulates
	// dozens of SKIP lines that look like unfinished work and bury the handful
	// that really are (LAB29-001).
	//
	// A case carrying this verdict MUST also carry a NotApplicable record saying
	// WHY and on WHOSE AUTHORITY; Verify refuses a bundle where it does not, and
	// refuses this verdict entirely in a schema older than the one that
	// introduced it. The spelling is an uppercase token like every other verdict,
	// because these strings are printed verbatim into REPORT.md's tables and the
	// console, and a lone lowercase one reads as a typo.
	VerdictNotApplicable Verdict = "N/A"
)

// Severity orders verdicts so a test case can take the worst of its assertions.
//
// VerdictNotApplicable and Skip share the bottom, and neither can raise a
// roll-up. That is correct for both: "nobody measured it" and "there was nothing
// to measure" are each the absence of an outcome, and an absence must never
// out-rank the observations beside it. What separates them is not severity, it
// is what the reader is being told — see VerdictNotApplicable.
func (v Verdict) Severity() int {
	switch v {
	case Fail:
		return 3
	case Warn:
		return 2
	case Pass:
		return 1
	case Skip, VerdictNotApplicable:
		return 0
	default:
		// An unrecognised verdict sorts at the bottom rather than panicking, and
		// verifyCaseVerdicts refuses it separately — a value this package does
		// not define is a bundle nobody can check, not a bundle to rank.
		return 0
	}
}

// NASource names WHOSE declaration put a row out of scope. It rides in the
// bundle beside the reason because the two answer different questions for a
// reader: the reason says what was decided, the source says who is entitled to
// have decided it, and an N/A whose source is unstated is an assertion rather
// than a citation.
type NASource string

// The sources a not-applicable verdict can rest on.
const (
	// NASourceCatalog — the conformance catalog's own `applicable` field, with
	// `applicability_reason` as the reason. A fact about the SPECIFICATION and
	// the claimed profile.
	NASourceCatalog NASource = "catalog-applicability"
	// NASourceManifest — the candidate manifest the DUT publishes
	// (/etc/lexa/candidate.json). A fact about what this CANDIDATE claims.
	NASourceManifest NASource = "manifest"
	// NASourcePICS — a PICS declaration. A fact about what the vendor declared
	// to the certifying body.
	NASourcePICS NASource = "pics"
)

// Valid reports whether the source is one this package defines.
func (s NASource) Valid() bool {
	switch s {
	case NASourceCatalog, NASourceManifest, NASourcePICS:
		return true
	}
	return false
}

// NotApplicable explains a VerdictNotApplicable verdict.
type NotApplicable struct {
	// Reason is why the row is out of scope, in the reader's language.
	Reason string `json:"reason"`
	// Source is whose declaration decided it.
	Source NASource `json:"source"`
	// Detail carries the exact declaration the decision was read out of — the
	// manifest key and its value, the catalog field — so a reader can go and
	// look at it rather than take this record's word.
	Detail string `json:"detail,omitempty"`
}

// Assertion is one checkable claim about the capture.
//
// The Frames / StreamRef / ByteRange / digest fields are what separate an
// evidence bundle from a test report. Without them a reader has to believe the
// verdict; with them they can open the pcap, go to the frame, and see the bytes
// for themselves — and Verify does exactly that mechanically.
type Assertion struct {
	// Claim is the sentence being asserted, in the language of the procedure
	// being certified against.
	Claim string `json:"claim"`
	// Method says how it was checked, so a reader can judge whether the check
	// actually establishes the claim.
	Method  string  `json:"method"`
	Verdict Verdict `json:"verdict"`
	// Observed is what was actually seen, in human-readable form.
	Observed string `json:"observed"`

	// Frames are 1-based capture frame numbers, matching Wireshark's
	// frame.number and pcapng.Packet.Index.
	Frames []int `json:"frames,omitempty"`
	// FramesSHA256 is the digest of the cited frames' bytes, concatenated in
	// ascending frame order. Without it Verify can only confirm the frames
	// exist.
	FramesSHA256 string `json:"frames_sha256,omitempty"`

	// StreamRef names a reassembled TCP direction as "src > dst", e.g.
	// "69.0.0.20:51422 > 69.0.0.2:802".
	StreamRef string `json:"stream_ref,omitempty"`
	// ByteRange is a half-open [start,end) range of that direction's stream.
	ByteRange [2]int `json:"byte_range,omitempty"`
	// BytesSHA256 is the digest of those bytes.
	BytesSHA256 string `json:"bytes_sha256,omitempty"`

	// Note carries anything a reader needs in order not to over-read the claim.
	Note string `json:"note,omitempty"`

	// LoadBearing marks an assertion that carries its test case's WHOLE
	// SUBJECT — the "did the device actually do it" claim — as opposed to a
	// supporting observation about the wire.
	//
	// It exists because of an arithmetic property of this file that is easy to
	// miss and impossible to un-see once seen. Skip is severity 0 (see
	// Severity), and every roll-up here and in the runner takes the WORST and
	// therefore only ever RAISES — so a Skip cannot dent a case verdict. A case
	// whose only "did it happen" assertion skips reports exactly the same
	// verdict as a case that measured everything and passed. Absence of
	// measurement reads as success, and the only thing distinguishing the two
	// is prose nobody re-reads on a green row.
	//
	// The suites' answer so far has been per-criterion discipline: the
	// release-enforcing criteria are written with NO Skip path at all, so every
	// shape they can end in is a decided verdict (see
	// csip-tls-test/internal/certify/suitecsip/doc.go). That works, and it is
	// unenforced — a new criterion, or an edit to an old one, can reintroduce a
	// Skip on a load-bearing claim and nothing anywhere will say so.
	//
	// This flag makes the roll-up itself refuse to launder it: a Skip on a
	// load-bearing assertion CAPS its case below PASS (see RollUp). It is
	// deliberately a cap rather than a FAIL — "nobody measured this" is not the
	// same statement as "the device got it wrong" — and the runner already
	// applies exactly this WARN cap to the analogous uncited-PASS case.
	//
	// Marking is opt-in per criterion, and it changes NO verdict on a suite
	// whose load-bearing criteria already have no Skip path, which is the whole
	// set as of 2026-08-15. It is a guard against the next one, not a
	// re-grading of this one.
	LoadBearing bool `json:"load_bearing,omitempty"`
}

// Citable reports whether the assertion carries a digest Verify can re-check.
// An assertion without one is still useful prose, but it is not proof, and the
// verify report says so.
func (a Assertion) Citable() bool { return a.BytesSHA256 != "" || a.FramesSHA256 != "" }

// Unmeasured reports an assertion that carries its case's whole subject and did
// not reach a conclusion — the shape RollUp caps a case for.
func (a Assertion) Unmeasured() bool { return a.LoadBearing && a.Verdict == Skip }

// TestCaseResult is one procedure step's outcome.
type TestCaseResult struct {
	// ID is the identifier from the procedure document, e.g. "SunSpecTCP-11".
	ID string `json:"id"`
	// Doc names the document the ID belongs to.
	Doc     string  `json:"doc,omitempty"`
	Title   string  `json:"title"`
	Verdict Verdict `json:"verdict"`
	// Applicable records whether this case applies to the certification CLAIM
	// (catalog `applicable`), as opposed to an INFORMATIVE row the suite
	// implements but does not claim. It rides in the per-case record so a reader —
	// and the headline tally — can separate a FAIL that bears on the claim from
	// one that is merely informative. It is always emitted (no omitempty): a
	// false is a fact about the row, not an absent one.
	Applicable bool `json:"applicable"`
	// Certifiable records whether ANY published procedure covers this case. It
	// is a fact about the SPECIFICATION, where Applicable is a fact about the
	// product: a case can apply to the product and be covered by nothing, which
	// is what a local-extension row is. Absent in a bundle written before this
	// field existed, which decodes to false — so it is written only when the
	// case is NON-certifiable, and read through BearsOnClaim below, which
	// treats an absent marker as "certifiable" and therefore leaves every older
	// bundle's meaning unchanged.
	NonCertifiable bool `json:"non_certifiable,omitempty"`
	// NotApplicable explains a VerdictNotApplicable verdict: why this row is out
	// of scope for the candidate, and on whose declaration. It is REQUIRED when
	// Verdict is VerdictNotApplicable and forbidden otherwise — Verify enforces
	// both, because an unexplained N/A is indistinguishable from a row that was
	// quietly dropped, which is the one thing this verdict must never be usable
	// for.
	NotApplicable *NotApplicable `json:"not_applicable,omitempty"`
	Notes         string         `json:"notes,omitempty"`
	Assertions    []Assertion    `json:"assertions"`
}

// RollUp returns the worst verdict among the assertions, which is what
// TestCaseResult.Verdict should normally be set to — CAPPED below PASS when a
// LOAD-BEARING assertion skipped.
//
// The cap is the only place in this file where the roll-up does something other
// than take a maximum, and it is there because taking a maximum is precisely
// what lets an unmeasured case pass: Skip is severity 0, so a case whose
// "did the device do it" assertion skipped rolls up to whatever its supporting
// wire assertions said, which on a healthy bench is PASS. See
// Assertion.LoadBearing.
//
// WARN rather than FAIL: the case is not evidence that the device misbehaved,
// it is evidence that nobody looked. Those are different findings and a bundle
// that conflated them would send a reader hunting a defect that may not exist.
// A case whose assertions are ALL not-applicable rolls up to
// VerdictNotApplicable rather than to Skip. Both sit at severity 0, so the
// maximum-taking loop cannot tell them apart and would hand back its Skip seed —
// which would then read, in the verifier's own message, as a bundle claiming
// N/A over assertions that say SKIP. One N/A among real assertions is not the
// same shape and does not qualify: an out-of-scope observation beside measured
// ones is a note, not a scope declaration about the case.
func (tc TestCaseResult) RollUp() Verdict {
	worst := Skip
	unmeasured := false
	naOnly := len(tc.Assertions) > 0
	for _, a := range tc.Assertions {
		if a.Verdict.Severity() > worst.Severity() {
			worst = a.Verdict
		}
		if a.Verdict != VerdictNotApplicable {
			naOnly = false
		}
		if a.Unmeasured() {
			unmeasured = true
		}
	}
	if unmeasured && worst.Severity() < Warn.Severity() {
		return Warn
	}
	if naOnly && worst.Severity() == Skip.Severity() {
		return VerdictNotApplicable
	}
	return worst
}

// DUT identifies the device under test.
type DUT struct {
	Name string `json:"name,omitempty"`
	// Address is where it was reached, e.g. "69.0.0.2:802".
	Address string `json:"address,omitempty"`
	// Identity is the credential it presented — an LFDI, a certificate
	// fingerprint, a serial number.
	Identity string `json:"identity,omitempty"`
	Role     string `json:"role,omitempty"`
	// Build is the firmware/build version, when the operator can supply it.
	Build string `json:"build,omitempty"`
}

// RunMeta is everything about the run itself.
type RunMeta struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
	// GitCommit and GitDirty pin the code that produced the bundle. A dirty
	// tree is recorded rather than hidden: a bundle produced from uncommitted
	// changes is still evidence, but a reader is entitled to know.
	GitCommit string `json:"git_commit,omitempty"`
	GitDirty  bool   `json:"git_dirty,omitempty"`
	// Command is the argument vector that produced this bundle, with the
	// values of credential-shaped flags replaced. It is optional: a bundle
	// written before this field existed carries none, and Verify neither needs
	// it nor is entitled to reject a bundle for lacking it.
	//
	// It is here because the bundle already records dumpcap's full argv in
	// capture.Summary.Command, and recorded NOTHING about the invocation that
	// chose the interface, the filter, the selection, the targets and the
	// timeouts. So a reader could re-derive exactly how the packets were
	// captured and had to guess what was being asked of the device — the
	// smaller question answered and the larger one left open. Two bundles that
	// disagree are most often two different command lines, and until now
	// telling them apart meant finding the operator.
	//
	// The values recorded are what the process was given, not what it decided:
	// the flags, not the resolved defaults. Those are elsewhere in this struct
	// and in the capture summary, and conflating them would make the line
	// unusable for the one thing it is for — being pasted back into a shell.
	Command  []string  `json:"command,omitempty"`
	Host     string    `json:"host,omitempty"`
	Operator string    `json:"operator,omitempty"`
	Note     string    `json:"note,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	DUT      DUT       `json:"dut"`
	// Campaign is the declared campaign this bundle is evidence FOR, and
	// whether it is GATING. Absent on an exploratory run and on every bundle
	// written before campaigns existed, which is the same thing said twice:
	// a bundle with no campaign record is not evidence for any campaign.
	//
	// A CI gate reads this field rather than parsing Command, because the
	// question "may this bundle decide a release?" must not be answerable only
	// by re-lexing a shell line.
	Campaign *CampaignRecord `json:"campaign,omitempty"`
	// Candidate is the candidate manifest this run was measured against: the
	// declaration of what the DUT claims to be. Absent when no manifest was
	// supplied.
	Candidate *CandidateRef `json:"candidate,omitempty"`
	// KeyLog summarises how Write scoped the run's key log to THIS bundle's
	// own capture (Builder.SetKeyLog, keylog.go, REV0907-E5): how many source
	// lines survived the filter and how many were dropped — a session outside
	// the capture, or a malformed source line. Nil when no key log was set at
	// all, so a bundle written with -keylog and one written without are
	// distinguishable from bundle.json alone, without opening
	// capture/*.keylog and counting.
	//
	// Before this field existed the same counts were readable only off the
	// live Builder, post-Write (KeyLogLinesKept/KeyLogLinesDropped) — useful
	// to the process that just wrote the bundle, useless to anyone reading it
	// back later. See the REV0907-E5 TODO this field closes, write.go.
	KeyLog *KeyLogFilterSummary `json:"keylog,omitempty"`
}

// KeyLogFilterSummary is how many key-log lines Builder.Write kept and
// dropped when scoping the source key log to this bundle's own capture. See
// RunMeta.KeyLog.
type KeyLogFilterSummary struct {
	// LinesKept is how many source lines named a session captureClientRandoms
	// found in this bundle's own capture, and so were copied in.
	LinesKept int `json:"lines_kept"`
	// LinesDropped is how many source lines were NOT copied in — either their
	// session is outside this bundle's own capture, or the line did not parse
	// as a key-log entry at all.
	LinesDropped int `json:"lines_dropped"`
}

// CampaignRecord is the campaign a run declared, as the bundle carries it.
type CampaignRecord struct {
	// Name is the campaign key ("csip", "mbaps", "modbus-client"), empty on an
	// exploratory run.
	Name string `json:"name,omitempty"`
	// Suites are the suites the campaign expanded to, recorded so a reader can
	// see the selection without re-deriving it from a table that may since have
	// changed.
	Suites []string `json:"suites,omitempty"`
	// Authority is the DUT arbitration posture the campaign REQUIRED, and
	// AuthorityObserved is what was actually read off the live DUT before case
	// one. Both present means the precondition was proven, not assumed.
	Authority         string `json:"authority,omitempty"`
	AuthorityObserved string `json:"authority_observed,omitempty"`
	// Gating records whether this run may decide anything. It is written even
	// when false — no omitempty — because "this bundle is not gating" is a fact
	// a reader needs stated, not inferred from a missing key.
	Gating bool `json:"gating"`
	// Exploratory records why a run is non-gating, when it is.
	Exploratory string `json:"exploratory,omitempty"`
	// Weakened lists every evidence-weakening switch that was in effect while
	// this bundle was produced — "skip-preflight", "require-citation=false",
	// "allow-dirty", "no-data-plane" are the ones internal/certify's runner
	// writes today (see its Weakened* constants and Runner.recordWeakened),
	// and any future weakening switch belongs in this same list rather than
	// only in free prose, so a reader — human or CI gate — can see it without
	// grepping RunMeta.Note.
	//
	// A GATING bundle (Gating true) must never carry a non-empty Weakened: the
	// two claims contradict each other — one says this evidence may decide a
	// release, the other says a precondition that decision rests on was
	// asserted rather than proven. The runner that writes this package's
	// bundles enforces that by construction (a GATING campaign refuses every
	// weakening switch outright, except -allow-dirty, which instead drops the
	// run out of Gating the moment it actually waves something through), and
	// Verify refuses the combination defensively for every bundle this package
	// did not itself just write — a hand-edited one, or one written by a
	// runner version this package does not trust. See REV0907-E3.
	Weakened []string `json:"weakened,omitempty"`
}

// CandidateRef identifies the candidate manifest a run was measured against.
// The digest is what makes it checkable: the manifest file itself is copied into
// the bundle, so a reader can hash the copy and compare.
type CandidateRef struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Profile string `json:"profile,omitempty"`
}

// Bundle is the machine-checkable half of an evidence bundle: exactly what
// bundle.json contains.
type Bundle struct {
	Schema  string           `json:"schema"`
	Run     RunMeta          `json:"run"`
	Capture capture.Summary  `json:"capture"`
	Files   BundleFiles      `json:"files"`
	Cases   []TestCaseResult `json:"cases"`
	// Metrics are the DUT metrics scrapes this run took, one record per
	// measurement window (metrics.go, IW15-030). Omitted entirely when the run
	// took none, so a bundle written before this channel existed and one
	// written after it are the same document — Load's DisallowUnknownFields
	// tolerates a MISSING field, never an unknown one, which is why the channel
	// could be added without a schema version bump but could not have been
	// added as an out-of-band file.
	Metrics []metricscrape.Record `json:"metrics,omitempty"`
	// Timebases are the clock declarations of the fixtures this run drove
	// (timebase.go, IW15 H6): what clock each one's timers counted against, and
	// whether it was the wall one. Omitted entirely when the run recorded none,
	// on the same terms as Metrics above — a bundle written before this channel
	// existed carries no key, still loads under DisallowUnknownFields, and
	// still verifies, with the SILENCE disclosed by the verifier rather than
	// treated as a fault.
	Timebases []Timebase `json:"timebases,omitempty"`
}

// BundleFiles records where the artefacts live inside the bundle directory,
// relative to it.
type BundleFiles struct {
	Capture string   `json:"capture,omitempty"`
	KeyLog  string   `json:"keylog,omitempty"`
	Extra   []string `json:"extra,omitempty"`
}

// Counts tallies the test cases by verdict.
//
// N/A is returned SEPARATELY from skip rather than folded into it. Folding was
// the original defect: a campaign's headline read "0 PASS / 0 FAIL / 61 SKIP"
// over a run in which fifty-odd of those rows had never been in scope, and the
// eleven that were genuinely unmeasured — the only ones anyone could act on —
// were invisible inside the same number.
func (b *Bundle) Counts() (pass, fail, skip, warn, na int) {
	for _, c := range b.Cases {
		switch c.Verdict {
		case Pass:
			pass++
		case Fail:
			fail++
		case Skip:
			skip++
		case Warn:
			warn++
		case VerdictNotApplicable:
			na++
		}
	}
	return
}

// OK reports whether the run is a clean pass: at least one case, and no FAIL
// THAT BEARS ON THE CLAIM.
//
// It used to aggregate EVERY failure, saying that whether an informative FAIL
// should stop a run being called clean was "a policy call for the owner of the
// claim". THAT CALL HAS BEEN MADE, and narrowly: a row the catalog marks
// non-certifiable measures behaviour no published procedure covers, so its
// verdict cannot be a conformance result and must not decide whether a campaign
// was clean. Every failure remains in Counts() and in the informative half of
// CountsByClaim, and REPORT.md prints both — nothing is hidden, only
// re-attributed.
//
// certify.RunReport.OK applies the identical rule, so the live run and the
// bundle written from it cannot disagree.
// A case declared NOT APPLICABLE is neither a pass nor a failure and cannot
// decide this either way: it contributes nothing to app.Fail, and it does not
// count towards the "at least one case" floor. A bundle whose every row was out
// of scope has established nothing, and must not report itself clean.
func (b *Bundle) OK() bool {
	app, inf := b.CountsByClaim()
	return app.InScope()+inf.InScope() > 0 && app.Fail == 0
}

// VerdictCounts is a per-verdict tally of test cases.
type VerdictCounts struct{ Pass, Fail, Skip, Warn, NotApplicable int }

func (v *VerdictCounts) add(k Verdict) {
	switch k {
	case Pass:
		v.Pass++
	case Fail:
		v.Fail++
	case Skip:
		v.Skip++
	case Warn:
		v.Warn++
	case VerdictNotApplicable:
		v.NotApplicable++
	}
}

// Total is the number of cases in the tally.
func (v VerdictCounts) Total() int { return v.Pass + v.Fail + v.Skip + v.Warn + v.NotApplicable }

// InScope is the number of cases in the tally that were in scope at all — the
// total less the ones declared not applicable. It is what a completion
// percentage must be taken over: a campaign that ran every row it claimed is
// complete whether or not the catalog also contained rows nobody claimed.
func (v VerdictCounts) InScope() int { return v.Total() - v.NotApplicable }

// CountsByClaim splits the tally into the cases that bear on the certification
// CLAIM (TestCaseResult.Applicable) and the INFORMATIVE ones the suite
// implements but the product does not claim.
//
// The bundle has carried the per-case flag since the console report learned to
// split its headline, and REPORT.md — the artefact an assessor actually reads —
// ignored it. So runs/certfix-validate-20260729T192416 announced "✗ 8 test
// case(s) FAILED" over a table in which AGG-009, AGG-012 and UTIL-002 sat
// unmarked beside five claim-relevant failures, with no way to tell them apart
// short of opening bundle.json. Three of those eight are rows nobody is
// certifying against: the catalog marks all twenty-two aggregator-only rows
// applicable:false under the DER-Client claim, the runner carried that flag
// into every per-case record, and the run honoured it everywhere except in what
// it printed.
//
// No verdict changes here. This is the grouping, and only the grouping.
func (b *Bundle) CountsByClaim() (applicable, informative VerdictCounts) {
	for _, c := range b.Cases {
		if c.BearsOnClaim() {
			applicable.add(c.Verdict)
		} else {
			informative.add(c.Verdict)
		}
	}
	return
}

// BearsOnClaim reports whether this case's verdict can count toward a
// certification claim: it must apply to the product AND be covered by some
// published procedure. It mirrors certify.Case.BearsOnClaim, which is what the
// runner grades with, so the bundle and the run cannot disagree about which
// failures were certification failures.
func (c TestCaseResult) BearsOnClaim() bool { return c.Applicable && !c.NonCertifiable }

// ByteSource is the part of a reassembled TCP direction an assertion needs.
// internal/evidence/netdis.StreamBytes satisfies it; declaring it as an
// interface keeps the bundle's authoring API independent of the dissector.
type ByteSource interface {
	Range(start, end int) ([]byte, error)
	PacketsFor(start, end int) []int
}

// CiteBytes builds an assertion that cites a byte range of a reassembled
// stream, filling in the frames that carried those bytes and their digest.
//
// This is the constructor conformance checks should use: it is not possible to
// cite a byte range through it without also recording something Verify can
// re-derive from the capture.
func CiteBytes(claim, method string, v Verdict, observed, streamRef string, src ByteSource, start, end int) (Assertion, error) {
	data, err := src.Range(start, end)
	if err != nil {
		return Assertion{}, fmt.Errorf("bundle: cannot cite %s bytes [%d,%d): %w", streamRef, start, end, err)
	}
	sum := sha256.Sum256(data)
	return Assertion{
		Claim:       claim,
		Method:      method,
		Verdict:     v,
		Observed:    observed,
		StreamRef:   streamRef,
		ByteRange:   [2]int{start, end},
		BytesSHA256: hex.EncodeToString(sum[:]),
		Frames:      src.PacketsFor(start, end),
	}, nil
}

// CiteFrames builds an assertion that cites whole frames, digesting their
// captured bytes in ascending frame order.
func CiteFrames(claim, method string, v Verdict, observed string, pkts []pcapng.Packet, frames []int) (Assertion, error) {
	sum, err := digestFrames(pkts, frames)
	if err != nil {
		return Assertion{}, err
	}
	sorted := append([]int(nil), frames...)
	sort.Ints(sorted)
	return Assertion{
		Claim:        claim,
		Method:       method,
		Verdict:      v,
		Observed:     observed,
		Frames:       sorted,
		FramesSHA256: sum,
	}, nil
}

// digestFrames hashes the cited frames' captured bytes, in ascending order.
func digestFrames(pkts []pcapng.Packet, frames []int) (string, error) {
	byIndex := make(map[int]pcapng.Packet, len(pkts))
	for _, p := range pkts {
		byIndex[p.Index] = p
	}
	sorted := append([]int(nil), frames...)
	sort.Ints(sorted)
	h := sha256.New()
	for _, f := range sorted {
		p, ok := byIndex[f]
		if !ok {
			return "", fmt.Errorf("bundle: cannot cite frame %d: the capture has %d frames", f, len(pkts))
		}
		h.Write(p.Data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GitCommit reports the HEAD commit of the repository containing dir and
// whether the working tree was dirty. Both results are best-effort: a bundle
// built outside a checkout is still a bundle.
func GitCommit(dir string) (commit string, dirty bool) {
	run := func(args ...string) (string, bool) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(out)), true
	}
	commit, ok := run("rev-parse", "HEAD")
	if !ok {
		return "", false
	}
	status, ok := run("status", "--porcelain")
	return commit, ok && status != ""
}
