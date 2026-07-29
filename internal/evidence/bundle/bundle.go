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
	"csip-tls-test/internal/evidence/pcapng"
)

// SchemaVersion identifies the bundle.json layout. A verifier that does not
// recognise it must refuse to pass the bundle rather than check what it happens
// to understand.
const SchemaVersion = "lexa-evidence-bundle/1"

// File names inside a bundle directory. They are fixed so that "run Verify on
// this directory" needs no arguments and no explanation.
const (
	BundleFile   = "bundle.json"
	ReportFile   = "REPORT.md"
	ManifestFile = "MANIFEST.sha256"
	CaptureDir   = "capture"
)

// Verdict is a test case's or assertion's outcome, using the same four values
// as the rest of this bench's conformance reporting (sim/ssm-conformance).
type Verdict string

// The four verdicts.
const (
	// Pass — the criterion was asserted on the wire and held.
	Pass Verdict = "PASS"
	// Fail — the criterion was asserted and did not hold.
	Fail Verdict = "FAIL"
	// Skip — addressed but not wire-assertable by this run; Observed says why.
	Skip Verdict = "SKIP"
	// Warn — asserted with a caveat.
	Warn Verdict = "WARN"
)

// Severity orders verdicts so a test case can take the worst of its assertions.
func (v Verdict) Severity() int {
	switch v {
	case Fail:
		return 3
	case Warn:
		return 2
	case Pass:
		return 1
	default:
		return 0
	}
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
}

// Citable reports whether the assertion carries a digest Verify can re-check.
// An assertion without one is still useful prose, but it is not proof, and the
// verify report says so.
func (a Assertion) Citable() bool { return a.BytesSHA256 != "" || a.FramesSHA256 != "" }

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
	Applicable bool        `json:"applicable"`
	Notes      string      `json:"notes,omitempty"`
	Assertions []Assertion `json:"assertions"`
}

// RollUp returns the worst verdict among the assertions, which is what
// TestCaseResult.Verdict should normally be set to.
func (tc TestCaseResult) RollUp() Verdict {
	worst := Skip
	for _, a := range tc.Assertions {
		if a.Verdict.Severity() > worst.Severity() {
			worst = a.Verdict
		}
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
}

// Bundle is the machine-checkable half of an evidence bundle: exactly what
// bundle.json contains.
type Bundle struct {
	Schema  string           `json:"schema"`
	Run     RunMeta          `json:"run"`
	Capture capture.Summary  `json:"capture"`
	Files   BundleFiles      `json:"files"`
	Cases   []TestCaseResult `json:"cases"`
}

// BundleFiles records where the artefacts live inside the bundle directory,
// relative to it.
type BundleFiles struct {
	Capture string   `json:"capture,omitempty"`
	KeyLog  string   `json:"keylog,omitempty"`
	Extra   []string `json:"extra,omitempty"`
}

// Counts tallies the test cases by verdict.
func (b *Bundle) Counts() (pass, fail, skip, warn int) {
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
		}
	}
	return
}

// OK reports whether the run is a clean pass: at least one case, and no FAIL.
//
// It deliberately aggregates EVERY failure, informative rows included. Whether
// an informative FAIL should stop a run being called clean is a policy call for
// the owner of the claim; grouping it separately in the report — see
// CountsByClaim — is a reporting question and is answered there.
func (b *Bundle) OK() bool {
	_, fail, _, _ := b.Counts()
	return len(b.Cases) > 0 && fail == 0
}

// VerdictCounts is a per-verdict tally of test cases.
type VerdictCounts struct{ Pass, Fail, Skip, Warn int }

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
	}
}

// Total is the number of cases in the tally.
func (v VerdictCounts) Total() int { return v.Pass + v.Fail + v.Skip + v.Warn }

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
		if c.Applicable {
			applicable.add(c.Verdict)
		} else {
			informative.add(c.Verdict)
		}
	}
	return
}

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
