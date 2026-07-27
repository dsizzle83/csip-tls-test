package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// FileCheck is one manifest line's result.
type FileCheck struct {
	Name string `json:"name"`
	Want string `json:"want"`
	Got  string `json:"got"`
	OK   bool   `json:"ok"`
}

// AssertionCheck is one assertion's re-check result.
type AssertionCheck struct {
	Case   string `json:"case"`
	Claim  string `json:"claim"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Citable is false when the assertion carried no digest. Such an assertion
	// cannot fail verification — there is nothing to check — and is counted
	// separately so a reader is never told that narrative was proved.
	Citable bool `json:"citable"`
}

// VerifyReport is the outcome of Verify.
type VerifyReport struct {
	Dir          string           `json:"dir"`
	OK           bool             `json:"ok"`
	Schema       string           `json:"schema"`
	Files        []FileCheck      `json:"files"`
	Assertions   []AssertionCheck `json:"assertions"`
	Problems     []string         `json:"problems,omitempty"`
	Packets      int              `json:"packets"`
	Checked      int              `json:"checked"`
	Unverifiable int              `json:"unverifiable"`
}

// Verify re-checks a bundle directory from nothing but its own contents.
//
// # What this is for
//
// Everything else in this engine produces claims. This function is what makes
// them a proof: a third party runs it against the directory we handed them, and
// it re-derives, from the capture file itself, that
//
//   - every file is byte-for-byte what the manifest says it is (so the capture
//     has not been edited since the report was written), and
//   - every frame an assertion cites exists in that capture, and
//   - the bytes at every cited stream offset hash to the value recorded in the
//     assertion.
//
// It reads only the bundle directory. It does not contact the bench, does not
// need the device, and does not trust bundle.json about anything it can check
// against the pcap.
//
// # What it deliberately does not claim
//
// The manifest is not signed. It detects corruption and piecemeal tampering —
// change a byte in the capture and the hashes stop agreeing with the report —
// but somebody who rewrites the whole bundle can rewrite the manifest too.
// Non-repudiation needs a signature or a trusted timestamp over the manifest,
// and that is a deployment decision, not something this package can fake. What
// Verify does establish is internal consistency: the report's claims and the
// capture in front of you describe the same traffic.
func Verify(dir string) (*VerifyReport, error) {
	rep := &VerifyReport{Dir: dir, OK: true}

	b, err := Load(dir)
	if err != nil {
		return nil, err
	}
	rep.Schema = b.Schema

	if err := verifyManifest(dir, rep); err != nil {
		return rep, err
	}

	if b.Files.Capture == "" {
		rep.problem("bundle declares no capture file; no assertion can be re-checked against the wire")
		rep.OK = false
		return rep, nil
	}
	pkts, err := pcapng.ReadFile(filepath.Join(dir, filepath.FromSlash(b.Files.Capture)))
	if err != nil {
		rep.problem(fmt.Sprintf("capture %s does not read back: %v", b.Files.Capture, err))
		rep.OK = false
		return rep, nil
	}
	rep.Packets = len(pkts)
	if b.Capture.Packets != 0 && b.Capture.Packets != len(pkts) {
		rep.problem(fmt.Sprintf("capture holds %d packets but bundle.json records %d", len(pkts), b.Capture.Packets))
		rep.OK = false
	}

	byIndex := make(map[int]pcapng.Packet, len(pkts))
	for _, p := range pkts {
		byIndex[p.Index] = p
	}
	streams := reassemble(pkts, rep)

	for _, c := range b.Cases {
		for _, a := range c.Assertions {
			chk := checkAssertion(c, a, pkts, byIndex, streams)
			rep.Assertions = append(rep.Assertions, chk)
			if !chk.Citable {
				rep.Unverifiable++
				continue
			}
			rep.Checked++
			if !chk.OK {
				rep.OK = false
			}
		}
	}
	return rep, nil
}

func (r *VerifyReport) problem(s string) { r.Problems = append(r.Problems, s) }

// verifyManifest re-hashes every listed file and looks for files that are on
// disk but not listed, which is how something slipped into a bundle after the
// fact would show up.
func verifyManifest(dir string, rep *VerifyReport) error {
	listed, err := ReadManifest(dir)
	if err != nil {
		return err
	}
	actual, err := manifestEntries(dir)
	if err != nil {
		return err
	}
	actualByName := make(map[string]string, len(actual))
	for _, e := range actual {
		actualByName[e.Name] = e.Sum
	}
	listedNames := make(map[string]bool, len(listed))

	for _, e := range listed {
		listedNames[e.Name] = true
		got, present := actualByName[e.Name]
		fc := FileCheck{Name: e.Name, Want: e.Sum, Got: got, OK: present && got == e.Sum}
		if !present {
			fc.Got = "(missing)"
		}
		rep.Files = append(rep.Files, fc)
		if !fc.OK {
			rep.OK = false
			rep.problem(fmt.Sprintf("%s does not match the manifest", e.Name))
		}
	}
	for _, e := range actual {
		if !listedNames[e.Name] {
			rep.OK = false
			rep.problem(fmt.Sprintf("%s is present but not listed in %s", e.Name, ManifestFile))
			rep.Files = append(rep.Files, FileCheck{Name: e.Name, Want: "(unlisted)", Got: e.Sum})
		}
	}
	sort.Slice(rep.Files, func(i, j int) bool { return rep.Files[i].Name < rep.Files[j].Name })
	return nil
}

// reassemble rebuilds every TCP direction so byte-range citations can be
// resolved. Failures are recorded as problems rather than aborting: a bundle
// whose assertions are all frame-based is still verifiable from a capture with
// one undissectable frame in it.
func reassemble(pkts []pcapng.Packet, rep *VerifyReport) map[string]*netdis.Direction {
	asm := netdis.NewAssembler()
	bad := 0
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			bad++
			if bad <= 3 {
				rep.problem(fmt.Sprintf("frame %d does not dissect: %v", p.Index, err))
			}
		}
	}
	if bad > 3 {
		rep.problem(fmt.Sprintf("%d frames in total do not dissect", bad))
	}
	out := make(map[string]*netdis.Direction)
	for _, st := range asm.Streams() {
		for _, d := range st.Dirs {
			out[d.Flow.String()] = d
			if d.HasConflictingOverlap() {
				// Overlapping segments with different bytes mean two readers of
				// this capture can disagree about what was said. That is not a
				// bundle anyone should certify from.
				rep.problem(fmt.Sprintf("stream %s contains CONFLICTING overlapping segments: %v",
					d.Flow, d.Overlaps))
				rep.OK = false
			}
		}
	}
	return out
}

// StreamRef renders the canonical stream reference for a reassembled direction.
// Authoring code and Verify must agree on this spelling, so both go through it.
func StreamRef(d *netdis.Direction) string { return d.Flow.String() }

func checkAssertion(c TestCaseResult, a Assertion, pkts []pcapng.Packet,
	byIndex map[int]pcapng.Packet, streams map[string]*netdis.Direction) AssertionCheck {

	chk := AssertionCheck{Case: c.ID, Claim: a.Claim, Citable: a.Citable(), OK: true}

	// Cited frames must exist, digest or not.
	for _, f := range a.Frames {
		if _, ok := byIndex[f]; !ok {
			chk.OK = false
			chk.Detail = fmt.Sprintf("cites frame %d, which the capture (%d frames) does not contain", f, len(pkts))
			chk.Citable = true // a bogus frame citation is a failure even without a digest
			return chk
		}
	}

	if a.FramesSHA256 != "" {
		got, err := digestFrames(pkts, a.Frames)
		if err != nil {
			chk.OK = false
			chk.Detail = err.Error()
			return chk
		}
		if got != a.FramesSHA256 {
			chk.OK = false
			chk.Detail = fmt.Sprintf("frames %v hash to %s, assertion claims %s", a.Frames, got, a.FramesSHA256)
			return chk
		}
	}

	if a.BytesSHA256 != "" {
		d, ok := streams[a.StreamRef]
		if !ok {
			chk.OK = false
			chk.Detail = fmt.Sprintf("cites stream %q, which the capture does not contain (streams: %s)",
				a.StreamRef, strings.Join(streamNames(streams), ", "))
			return chk
		}
		data, err := d.Bytes.Range(a.ByteRange[0], a.ByteRange[1])
		if err != nil {
			chk.OK = false
			chk.Detail = err.Error()
			return chk
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != a.BytesSHA256 {
			chk.OK = false
			chk.Detail = fmt.Sprintf("%s bytes [%d,%d) hash to %s, assertion claims %s",
				a.StreamRef, a.ByteRange[0], a.ByteRange[1], got, a.BytesSHA256)
			return chk
		}
		// The frames a citation names must be the frames those bytes actually
		// came in — otherwise a report could point a reviewer at the wrong
		// place while still hashing correctly.
		want := d.Bytes.PacketsFor(a.ByteRange[0], a.ByteRange[1])
		if len(a.Frames) > 0 && fmt.Sprint(want) != fmt.Sprint(a.Frames) {
			chk.OK = false
			chk.Detail = fmt.Sprintf("%s bytes [%d,%d) were carried in frames %v, assertion cites %v",
				a.StreamRef, a.ByteRange[0], a.ByteRange[1], want, a.Frames)
			return chk
		}
	}

	if !chk.Citable {
		chk.Detail = "no digest recorded; existence of the cited frames is all that can be checked"
	}
	return chk
}

func streamNames(streams map[string]*netdis.Direction) []string {
	out := make([]string, 0, len(streams))
	for k := range streams {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// String renders a verify report for a terminal, in the bench's house style.
func (r *VerifyReport) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", strings.Repeat("═", 72))
	fmt.Fprintf(&sb, "EVIDENCE BUNDLE VERIFICATION\n")
	fmt.Fprintf(&sb, "%s\n", strings.Repeat("─", 72))
	fmt.Fprintf(&sb, "Bundle:   %s\n", r.Dir)
	fmt.Fprintf(&sb, "Schema:   %s\n", r.Schema)
	fmt.Fprintf(&sb, "Capture:  %d frames\n", r.Packets)
	fmt.Fprintf(&sb, "%s\n", strings.Repeat("─", 72))

	badFiles := 0
	for _, f := range r.Files {
		if !f.OK {
			badFiles++
			fmt.Fprintf(&sb, "  ✗ %s: %s\n", f.Name, f.Got)
		}
	}
	fmt.Fprintf(&sb, "  Files:      %d checked, %d bad\n", len(r.Files), badFiles)

	badAssert := 0
	for _, a := range r.Assertions {
		if !a.OK {
			badAssert++
			fmt.Fprintf(&sb, "  ✗ %s: %s\n     %s\n", a.Case, a.Claim, a.Detail)
		}
	}
	fmt.Fprintf(&sb, "  Assertions: %d re-checked against the capture, %d bad\n", r.Checked, badAssert)
	if r.Unverifiable > 0 {
		fmt.Fprintf(&sb, "  Narrative:  %d assertion(s) carry no digest and were not re-checked\n", r.Unverifiable)
	}
	for _, p := range r.Problems {
		fmt.Fprintf(&sb, "  ! %s\n", p)
	}
	fmt.Fprintf(&sb, "%s\n", strings.Repeat("═", 72))
	if r.OK {
		fmt.Fprintf(&sb, "✓ VERIFIED — every file matches the manifest and every cited byte is in the capture.\n")
	} else {
		fmt.Fprintf(&sb, "✗ NOT VERIFIED — this bundle does not describe the capture it ships with.\n")
	}
	return sb.String()
}
