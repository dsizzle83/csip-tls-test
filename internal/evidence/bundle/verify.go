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
	// MetricsWindows and MetricsSeries count the DUT metrics scrape channel's
	// re-checks: how many measurement windows the bundle carries, and how many
	// individual counter readings were re-derived from the exposition bodies
	// shipped with them (metrics.go). Zero for every bundle that took no
	// scrapes, which is every bundle written before the channel existed.
	MetricsWindows int `json:"metrics_windows,omitempty"`
	MetricsSeries  int `json:"metrics_series,omitempty"`
	// TimebasesDeclared and TimebasesAccelerated count the clock channel's
	// re-checks: how many fixture clock declarations the bundle carries, and
	// how many of them were NOT the wall clock (timebase.go).
	TimebasesDeclared    int `json:"timebases_declared,omitempty"`
	TimebasesAccelerated int `json:"timebases_accelerated,omitempty"`
	// TimebaseUndeclared marks a bundle that says nothing at all about the
	// clock its fixtures ran on. It is a DISCLOSURE, never a failure: it is
	// true of every bundle written before the channel existed, and the
	// verifier's job there is to tell the reader the bundle is silent — not to
	// invent a fault out of a question it was never asked.
	TimebaseUndeclared bool `json:"timebase_undeclared,omitempty"`
	// CasesRolledUp counts the test cases whose stored verdict was re-derived
	// from their own printed assertions (verifyCaseVerdicts).
	CasesRolledUp int `json:"cases_rolled_up,omitempty"`
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

	// The metrics scrape channel is re-derived BEFORE the capture is opened,
	// and deliberately not behind the "no capture, nothing to check" exit
	// below: a scrape record's evidence is the exposition bodies in this
	// directory, and it is re-checkable whether or not there is a pcap beside
	// it.
	verifyMetrics(dir, b, rep)

	// Two more re-derivations that need no capture at all, and are therefore
	// deliberately ahead of the "no capture, nothing to check" exit below: the
	// clock each fixture declared (timebase.go) and every case's verdict
	// against its own assertions. Both are properties of bundle.json read back
	// against itself, and a bundle with no pcap is still entitled to be told
	// that its verdicts do not follow from its evidence.
	verifyTimebases(b, rep)
	verifyCaseVerdicts(b, rep)

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
	asm := reassemble(pkts, rep)

	for _, c := range b.Cases {
		for _, a := range c.Assertions {
			chk := checkAssertion(c, a, pkts, byIndex, asm)
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

// verifyCaseVerdicts re-derives every case's verdict from the assertions
// printed beside it in the same bundle.
//
// # The hole this closes
//
// Everything else in Verify re-checks the CITATIONS: the frames exist, the
// bytes hash, the scrape readings follow from their exposition bodies. Nothing
// re-checked the arithmetic ON TOP of them. A bundle whose stored case verdict
// had been edited — FAIL rewritten to PASS in bundle.json, the manifest
// refreshed to cover it — verified clean, with the FAIL assertion still printed
// three lines below the PASS heading in its own REPORT.md. Every individual
// citation in that bundle was true; the sentence a reader actually acts on was
// not (IW15 M2). The same hole covers honest DRIFT: a case whose assertions
// were re-graded without its verdict following them along.
//
// # The rule, and why it is an inequality rather than an equality
//
// THE STORED VERDICT MUST NEVER BE WEAKER THAN THE ROLL-UP OF ITS OWN
// ASSERTIONS — stored.Severity() >= RollUp().Severity(). Equality is the wrong
// rule, and asserting it would fail a large share of the honest archive,
// because the runner deliberately records verdicts STRICTER than the raw
// roll-up. Two places do it, both in internal/certify/runner.go:
//
//   - finalise's uncited-PASS rule: a case that rolled up to PASS but carries
//     no assertion with a digest the verifier can re-derive is downgraded to
//     WARN ("PASS downgraded to WARN: no assertion carries a digest…").
//   - citeWithoutCapture: when the run took no capture at all, every case that
//     expected to cite gains a SKIP assertion and any PASS becomes WARN.
//
// Both raise severity after the roll-up, and both are the framework being
// honest about a weakness in its own evidence. runs/tail-fullsuite-20260801T173831
// carries eighteen such cases — sixteen WARN over a PASS roll-up, two WARN over
// a SKIP one — and a verifier demanding equality would call that clean archive
// tampered.
//
// The direction that is never legitimate is the other one. finalise's own first
// act is `if worst := worstOf(c.Assertions); worst.Severity() > c.Verdict.Severity()
// { c.Verdict = worst }` — it RAISES a case to its roll-up and never lowers it —
// so "stored is at least the roll-up" is exactly the runner's own invariant,
// restated where a third party can check it against the document rather than
// against the code that produced it. worstOf and TestCaseResult.RollUp
// implement the same rule, load-bearing Skip cap included, precisely so this
// check can be made against either.
//
// An unrecognised stored verdict is its own failure. Severity() maps anything
// it does not know to 0, so a case whose verdict had been edited to "PASSED" or
// "" would slip through the inequality against a SKIP roll-up; a bundle
// carrying a verdict outside the four this package defines is not a bundle
// whose arithmetic anyone can check.
func verifyCaseVerdicts(b *Bundle, rep *VerifyReport) {
	for _, c := range b.Cases {
		rep.CasesRolledUp++
		switch c.Verdict {
		case Pass, Fail, Skip, Warn:
		default:
			rep.problem(fmt.Sprintf("case %s records verdict %q, which is not one of PASS/FAIL/SKIP/WARN — "+
				"a verdict this verifier cannot place in the severity order is one it cannot re-derive",
				c.ID, c.Verdict))
			rep.OK = false
			continue
		}
		derived := c.RollUp()
		if c.Verdict.Severity() >= derived.Severity() {
			continue
		}
		rep.problem(fmt.Sprintf("case %s records verdict %s, but its own %d printed assertion(s) (%s) "+
			"roll up to %s. A stored verdict may be STRICTER than its assertions — the runner downgrades "+
			"an uncited PASS, and a run with no capture, to WARN — but never weaker: this bundle's "+
			"headline does not follow from the evidence printed under it",
			c.ID, c.Verdict, len(c.Assertions), assertionVerdicts(c), derived))
		rep.OK = false
	}
}

// assertionVerdicts renders a case's assertion verdicts in order, so the
// problem message shows the reader WHICH assertion made the roll-up what it is
// rather than making them open bundle.json to find out.
func assertionVerdicts(c TestCaseResult) string {
	if len(c.Assertions) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(c.Assertions))
	for _, a := range c.Assertions {
		v := string(a.Verdict)
		if a.Unmeasured() {
			// The load-bearing cap is invisible in a bare list of verdicts —
			// a SKIP that caps the case looks exactly like one that does not.
			v += " (load-bearing, unmeasured)"
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ", ")
}

// reassemble rebuilds every TCP connection GENERATION so byte-range citations
// can be resolved, and returns the netdis.Assembler itself rather than a
// flattened "src > dst" -> Direction map.
//
// A flattened map is exactly the bug this used to have: a.StreamRef
// (bundle.StreamRef) is deliberately just the bare endpoint pair, stable
// across connection generations so old bundles keep reading, so a capture
// with ephemeral-port reuse can hold several unrelated connection instances
// that all render to the same map key (see netdis.Stream.InstanceKey and
// e166ec1, which hit the identical ambiguity on the AUTHORING side —
// window.go's consolidateStreams and evidence.go's mayCite/CiteBytes were
// fixed there to key by InstanceKey instead of the bare pair). This function
// used to build exactly that map, last-write-wins across asm.Streams()'s
// first-seen order, so a citation against an EARLIER generation silently
// resolved against whichever generation was reassembled last — a byte range
// valid in the generation that authored it landing "outside" a shorter or
// differently-shaped later generation's stream, or worse, resolving in-range
// against the wrong generation's bytes and failing the hash check instead.
// See resolveDirection for how a citation now finds its own generation.
//
// Failures are recorded as problems rather than aborting: a bundle whose
// assertions are all frame-based is still verifiable from a capture with one
// undissectable frame in it.
func reassemble(pkts []pcapng.Packet, rep *VerifyReport) *netdis.Assembler {
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
	for _, st := range asm.Streams() {
		for _, d := range st.Dirs {
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
	return asm
}

// StreamRef renders the canonical stream reference for a reassembled direction.
// Authoring code and Verify must agree on this spelling, so both go through it.
func StreamRef(d *netdis.Direction) string { return d.Flow.String() }

// resolveDirection finds the reassembled Direction a byte-range assertion's
// StreamRef names.
//
// The ordinary case — one connection ever used that endpoint pair — is
// unambiguous: there is exactly one candidate Direction and this returns it.
//
// When ephemeral-port reuse means more than one connection GENERATION shares
// the pair (netdis.Stream.InstanceKey), a.StreamRef alone cannot say which one
// the assertion means, because bundle.StreamRef deliberately renders only the
// bare pair. The disambiguator is the frames the citation itself already
// names: bundle.CiteBytes always sets Frames = src.PacketsFor(start, end)
// alongside BytesSHA256, so an assertion built through the normal authoring
// path (internal/certify/evidence.go's Evidence.CiteBytes) already records
// which frames carried the cited bytes. asm.StreamFor resolves one of those
// frames back to the exact connection instance that owns it — the same
// mechanism e166ec1 added for window.go's consolidateStreams and evidence.go's
// mayCite/CiteBytes to use on the authoring side — so this picks the
// generation that actually authored the citation instead of whichever
// generation reassemble happened to walk last.
//
// If the pair is shared and the cited frames do not resolve to any of the
// candidates (a malformed or hand-edited assertion, not anything the
// authoring path produces), this refuses to guess and returns an error: the
// old behavior of silently picking the most-recently-seen generation is
// exactly the false-negative/false-positive risk this function exists to
// close, and guessing on the fallback path would just move the bug rather
// than fix it.
func resolveDirection(asm *netdis.Assembler, a Assertion) (*netdis.Direction, error) {
	var candidates []*netdis.Direction
	for _, st := range asm.Streams() {
		if d := directionByFlow(st, a.StreamRef); d != nil {
			candidates = append(candidates, d)
		}
	}
	switch len(candidates) {
	case 0:
		return nil, fmt.Errorf("cites stream %q, which the capture does not contain (streams: %s)",
			a.StreamRef, strings.Join(streamNames(asm), ", "))
	case 1:
		return candidates[0], nil
	}
	for _, f := range a.Frames {
		st := asm.StreamFor(f)
		if st == nil {
			continue
		}
		if d := directionByFlow(st, a.StreamRef); d != nil {
			return d, nil
		}
	}
	return nil, fmt.Errorf("cites stream %q; %d connection generations share this endpoint pair "+
		"(ephemeral port reuse — see netdis.Stream.InstanceKey) and the assertion's cited frames %v "+
		"do not resolve to any of them, so which generation this citation names cannot be determined",
		a.StreamRef, len(candidates), a.Frames)
}

// directionByFlow returns st's Direction whose Flow renders as flow, or nil.
func directionByFlow(st *netdis.Stream, flow string) *netdis.Direction {
	for _, d := range st.Dirs {
		if d.Flow.String() == flow {
			return d
		}
	}
	return nil
}

func checkAssertion(c TestCaseResult, a Assertion, pkts []pcapng.Packet,
	byIndex map[int]pcapng.Packet, asm *netdis.Assembler) AssertionCheck {

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
		d, err := resolveDirection(asm, a)
		if err != nil {
			chk.OK = false
			chk.Detail = err.Error()
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

// streamNames lists every distinct "src > dst" pair the capture reassembled,
// across every connection generation, for use in a "no such stream" detail
// message. A pair that had more than one generation appears once, same as it
// does in a.StreamRef — generation identity is not part of this spelling.
func streamNames(asm *netdis.Assembler) []string {
	seen := map[string]bool{}
	var out []string
	for _, st := range asm.Streams() {
		for _, d := range st.Dirs {
			s := d.Flow.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
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
	fmt.Fprintf(&sb, "  Verdicts:   %d case verdict(s) re-derived from their own assertions\n", r.CasesRolledUp)
	// The clock, stated either way round. An accelerated bundle says so on its
	// face; a bundle that says nothing has that silence named, because "no
	// declaration" and "declared wall" are different facts and only one of them
	// is a statement about the run.
	switch {
	case r.TimebasesAccelerated > 0:
		fmt.Fprintf(&sb, "  Timebase:   %d of %d declared fixture clock(s) are ACCELERATED TEST TIME — "+
			"this bundle's timing claims are about the harness, not a real device\n",
			r.TimebasesAccelerated, r.TimebasesDeclared)
	case r.TimebasesDeclared > 0:
		fmt.Fprintf(&sb, "  Timebase:   %d declared fixture clock(s), all wall-clock\n", r.TimebasesDeclared)
	case r.TimebaseUndeclared:
		fmt.Fprintf(&sb, "  Timebase:   NOT DECLARED — this bundle does not state what clock its fixtures' "+
			"timers ran on (disclosure, not a fault)\n")
	}
	if r.MetricsWindows > 0 {
		fmt.Fprintf(&sb, "  Metrics:    %d reading(s) re-derived from the exposition bodies of %d "+
			"scrape window(s)\n", r.MetricsSeries, r.MetricsWindows)
	}
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
