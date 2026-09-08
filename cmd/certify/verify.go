package main

// verify.go is the mode that matters most to somebody who does not trust us.
//
// It reads ONE directory and nothing else. No bench, no device, no network, no
// catalog, no state from the run that produced the bundle. It re-derives, from
// the capture file sitting in that directory, that every file is byte-for-byte
// what the manifest says, that every frame an assertion cites exists, and that
// the bytes at every cited stream offset hash to the value recorded in the
// assertion. See bundle.Verify's doc for what it deliberately does NOT claim —
// the manifest is unsigned, so this is internal consistency, not
// non-repudiation.
//
// Two rules of presentation follow from that, and both are about not
// overclaiming:
//
//   - An assertion that carries no digest is counted SEPARATELY, never folded
//     into the pass count. Nothing was checked about it; saying "42 assertions
//     verified" when eleven of them were narrative would be the tool lying at
//     the last possible moment.
//   - A verification failure prints the case, the claim, and the detail, not a
//     summary line. The reader's next action is to open the pcap at that frame,
//     and this output is what tells them where to look.

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"csip-tls-test/internal/evidence/bundle"
)

func (c *cli) runVerify(stdout, stderr io.Writer) int {
	dir := c.verify
	var rep *bundle.VerifyReport
	var err error
	if c.pubkey != "" {
		pub, kerr := bundle.LoadVerifyKey(c.pubkey)
		if kerr != nil {
			fmt.Fprintf(stderr, "certify: -pubkey: %v\n", kerr)
			return exitUsage
		}
		rep, err = bundle.VerifySigned(dir, pub)
	} else {
		rep, err = bundle.Verify(dir)
	}
	if err != nil {
		// Verify returns an error only when the bundle cannot be read at all —
		// a missing bundle.json, an unreadable manifest. That is not a verdict
		// about the evidence; it is a statement that there is none here.
		fmt.Fprintf(stderr, "certify: %s is not a readable evidence bundle: %v\n", dir, err)
		if rep != nil && len(rep.Problems) > 0 {
			for _, p := range rep.Problems {
				fmt.Fprintf(stderr, "  · %s\n", p)
			}
		}
		return exitUsage
	}

	if c.jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "certify: encode verification report: %v\n", err)
			return exitUsage
		}
		if rep.OK {
			return exitOK
		}
		return exitFail
	}

	abs, _ := filepath.Abs(dir)
	fmt.Fprintf(stdout, "VERIFY  %s\n", abs)
	fmt.Fprintf(stdout, "        schema %s · %d file(s) · %d packet(s) in the capture\n", rep.Schema, len(rep.Files), rep.Packets)
	// Whether this run checked a signature is stated in as many words, right
	// under the header — a reader must never mistake a hash-only pass for a
	// signed one, and the only thing that tells them apart is this line. See
	// VerifyReport.Unsigned.
	if rep.Unsigned {
		fmt.Fprintf(stdout, "        ⚠ UNSIGNED VERIFICATION — no -pubkey given; internal consistency only,\n"+
			"          not a check that any particular key produced this manifest (REV0907-E4)\n\n")
	} else {
		fmt.Fprintf(stdout, "        ✓ signature checked against the supplied -pubkey\n\n")
	}

	// Files first: if the manifest does not agree with the bytes on disk,
	// nothing below it means anything.
	bad := 0
	for _, f := range rep.Files {
		if !f.OK {
			bad++
			fmt.Fprintf(stdout, "  ✗ FILE  %s\n      manifest: %s\n      on disk:  %s\n",
				f.Name, orNone(f.Want), orNone(f.Got))
		}
	}
	if bad == 0 {
		fmt.Fprintf(stdout, "  ✓ all %d file(s) match the manifest byte for byte\n", len(rep.Files))
	}

	// The clock, before the verdicts, because it changes what the verdicts
	// MEAN. A run whose fixture timers were accelerated proves this harness's
	// expiry semantics and nothing about a real device's timing; a reader who
	// learns that after reading the tally has already misread it. A bundle that
	// declares NOTHING is told so in as many words — "does not say" and "says
	// wall" are different facts, and every bundle written before this channel
	// existed is the first of them.
	switch {
	case rep.TimebasesAccelerated > 0:
		fmt.Fprintf(stdout, "\n  ⏱ ACCELERATED TEST TIME — %d of %d declared fixture clock(s) in this bundle\n"+
			"      were NOT the wall clock. Timing claims resting on them are claims about this\n"+
			"      harness's expiry semantics, not about any real device's timing.\n",
			rep.TimebasesAccelerated, rep.TimebasesDeclared)
	case rep.TimebasesDeclared > 0:
		fmt.Fprintf(stdout, "\n  ⏱ %d declared fixture clock(s), all wall-clock; every label re-derived from\n"+
			"      the kind and scale recorded beside it.\n", rep.TimebasesDeclared)
	case rep.TimebaseUndeclared:
		fmt.Fprintf(stdout, "\n  ⏱ timebase NOT DECLARED — this bundle does not state what clock its fixtures'\n"+
			"      timers ran on. That is a gap in what it tells you, not a fault in what it says.\n")
	}

	failed := 0
	for _, a := range rep.Assertions {
		if a.Citable && !a.OK {
			failed++
			fmt.Fprintf(stdout, "\n  ✗ %s\n      claim:  %s\n      detail: %s\n",
				a.Case, trunc(a.Claim, 110), a.Detail)
		}
	}
	fmt.Fprintf(stdout, "\n  assertions re-derived from the capture: %d\n", rep.Checked)
	fmt.Fprintf(stdout, "  assertions carrying no digest (nothing to re-check): %d\n", rep.Unverifiable)
	if failed > 0 {
		fmt.Fprintf(stdout, "  assertions that did NOT re-derive: %d\n", failed)
	}
	// The arithmetic on top of the citations: every case's stored verdict must
	// follow from the assertions printed under it. A bundle can be made of
	// nothing but true citations and still carry a headline nobody can derive
	// from them, which is what this line reports having checked.
	fmt.Fprintf(stdout, "  case verdicts re-derived from their own assertions: %d\n", rep.CasesRolledUp)
	for _, p := range rep.Problems {
		fmt.Fprintf(stdout, "\n  ⚠ %s\n", p)
	}

	fmt.Fprintf(stdout, "\n%s\n", strings.Repeat("═", 78))
	if rep.OK {
		fmt.Fprintf(stdout, "✓ BUNDLE VERIFIES — every cited frame and byte range is in this capture and\n"+
			"  hashes to the value the report records. This says the report and the pcap in\n"+
			"  front of you describe the same traffic; the manifest is unsigned, so it is not\n"+
			"  a claim about who produced them.\n")
		fmt.Fprintf(stdout, "%s\n", strings.Repeat("═", 78))
		return exitOK
	}
	fmt.Fprintf(stdout, "✗ BUNDLE DOES NOT VERIFY — do not submit or cite it until the findings above\n"+
		"  are explained. %s\n", verifyFailureCause(rep))
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("═", 78))
	return exitFail
}

// verifyFailureCause explains what actually failed, rather than asserting a
// cause the report may not support.
//
// This line used to read "A hash mismatch means the capture and the report
// disagree" on EVERY failure. Verification has several independent legs now —
// file digests, assertion citations, the metrics channel, the fixture timebase,
// and the case-verdict re-derivation — and most of them can fail with every
// byte matching. A campaign bundle that declares no capture is the common case:
// its files hash correctly, and a reader chasing a phantom hash mismatch is
// being sent to look at the one thing that is fine.
//
// It reads the report's STRUCTURED results rather than its prose, so the
// attribution follows what was checked and not what the strings happen to say.
func verifyFailureCause(rep *bundle.VerifyReport) string {
	digests := 0
	for _, f := range rep.Files {
		if !f.OK {
			digests++
		}
	}
	citations := 0
	for _, a := range rep.Assertions {
		if a.Citable && !a.OK {
			citations++
		}
	}
	switch {
	case digests > 0 && citations > 0:
		return fmt.Sprintf("%d manifest file(s) and %d cited assertion(s) hash to something other than "+
			"the report records: the capture and the report disagree.", digests, citations)
	case digests > 0:
		return fmt.Sprintf("%d manifest file(s) hash to something other than the report records: the "+
			"bundle's own contents have changed since it was written.", digests)
	case citations > 0:
		return fmt.Sprintf("%d cited assertion(s) do not hash to the value the report records: the "+
			"capture and the report disagree.", citations)
	default:
		// Every digest matched. The failure is one of the structural legs, and
		// saying "hash mismatch" here would point a reader at the only part of
		// the bundle that is demonstrably intact.
		return "every file and citation hashes correctly, so this is NOT a hash mismatch — the finding(s) " +
			"above are about what the bundle CLAIMS rather than about its bytes."
	}
}

// orNone renders an absent digest as something a reader will not mistake for a
// value.
func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(absent)"
	}
	return s
}
