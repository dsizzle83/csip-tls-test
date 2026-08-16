package bundle

import (
	"fmt"
	"strings"
	"time"
)

// Report renders REPORT.md: the human-readable half of the bundle, in the same
// house style as this bench's other conformance reports (✓ PASS / ✗ FAIL, a
// tally, one section per case).
//
// Frame numbers are cited INLINE, in every assertion, deliberately. The report
// is what a reviewer reads with Wireshark open beside it, and a claim whose
// evidence is "see bundle.json" is a claim nobody checks.
func (b *Bundle) Report() string {
	var sb strings.Builder
	pass, fail, skip, warn := b.Counts()

	fmt.Fprintf(&sb, "# Conformance evidence bundle\n\n")
	if b.Run.DUT.Name != "" || b.Run.DUT.Address != "" {
		fmt.Fprintf(&sb, "**Device under test:** %s", orDash(b.Run.DUT.Name))
		if b.Run.DUT.Address != "" {
			fmt.Fprintf(&sb, " at `%s`", b.Run.DUT.Address)
		}
		fmt.Fprintf(&sb, "\n\n")
	}
	fmt.Fprintf(&sb, "| | |\n|---|---|\n")
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&sb, "| %s | %s |\n", k, mdEscape(v))
		}
	}
	row("Tool", strings.TrimSpace(b.Run.Tool+" "+b.Run.ToolVersion))
	commit := b.Run.GitCommit
	if commit != "" && b.Run.GitDirty {
		commit += " (working tree dirty)"
	}
	row("Source commit", commit)
	row("Operator", b.Run.Operator)
	row("Host", b.Run.Host)
	row("Started", ts(b.Run.Started))
	row("Finished", ts(b.Run.Finished))
	row("DUT identity", b.Run.DUT.Identity)
	row("DUT role", b.Run.DUT.Role)
	row("DUT build", b.Run.DUT.Build)
	row("Capture", fmt.Sprintf("`%s` — %d packets, %d bytes, %s",
		b.Files.Capture, b.Capture.Packets, b.Capture.FileBytes, b.Capture.Format))
	row("Capture tool", strings.TrimSpace(b.Capture.Tool+" "+b.Capture.ToolVersion))
	row("Interface", b.Capture.Interface)
	row("Capture filter", b.Capture.Filter)
	row("Key log", b.Files.KeyLog)
	fmt.Fprintf(&sb, "\n")

	// A bundle carrying a key log carries REAL TLS session secrets. That is
	// deliberate and necessary — an assessor cannot re-derive an
	// application-layer citation from an encrypted capture without them, which is
	// the whole reason the key log is in the manifest. But it also means handing
	// someone the bundle hands them the ability to decrypt every session in it,
	// and nothing else in this report said so. State it where it cannot be
	// missed, rather than leaving it to be inferred from a filename.
	if b.Files.KeyLog != "" {
		fmt.Fprintf(&sb, "> **This bundle contains TLS session secrets.** `%s` is an NSS key log for the\n"+
			"> capture above: anyone holding this directory can decrypt every session it\n"+
			"> records. It is included on purpose — the application-layer citations below\n"+
			"> cannot be re-derived without it — and it is covered by the manifest, so it\n"+
			"> cannot be quietly dropped either. Treat the bundle as sensitive: share it\n"+
			"> with an assessor, not publicly. The secrets are per-session and grant no\n"+
			"> lasting access to the device.\n\n", b.Files.KeyLog)
	}

	// The clock banner goes HERE — above the run note, the capture output and
	// every tally — because it changes what the rest of the document means. A
	// reader who learns on page three that the timers ran at 900× has already
	// read the timing claims as if they were about a device.
	b.timebaseReport(&sb)

	if b.Run.Note != "" {
		fmt.Fprintf(&sb, "> %s\n\n", strings.ReplaceAll(b.Run.Note, "\n", "\n> "))
	}
	if b.Capture.Stderr != "" {
		fmt.Fprintf(&sb, "Capture tool output:\n\n```\n%s\n```\n\n", b.Capture.Stderr)
	}

	// Both argv lines, together, deliberately. The bundle has always recorded
	// how the packets were CAPTURED — dumpcap's whole command line — while
	// recording nothing about the invocation that chose the interface, the
	// filter, the selection and the targets. That asymmetry answered the
	// smaller question and left the larger one to the operator's memory.
	// Printing them side by side is what makes the run reproducible from the
	// bundle alone.
	if len(b.Run.Command) > 0 || len(b.Capture.Command) > 0 {
		fmt.Fprintf(&sb, "## How this run was invoked\n\n")
		if len(b.Run.Command) > 0 {
			fmt.Fprintf(&sb, "```\n%s\n```\n\n", shellLine(b.Run.Command))
			fmt.Fprintf(&sb, "Credential-shaped flag values are replaced with `%s`; every other argument is "+
				"verbatim. Defaults the tool resolved for itself are NOT shown here — they are the rest of "+
				"this table.\n\n", Redacted)
		}
		if len(b.Capture.Command) > 0 {
			fmt.Fprintf(&sb, "The capture itself:\n\n```\n%s\n```\n\n", shellLine(b.Capture.Command))
		}
	}

	app, inf := b.CountsByClaim()
	split := inf.Total() > 0

	fmt.Fprintf(&sb, "## Result\n\n")
	fmt.Fprintf(&sb, "**%d PASS · %d FAIL · %d SKIP · %d WARN** across %d test case(s).\n\n",
		pass, fail, skip, warn, len(b.Cases))
	// Split the headline by whether a row bears on the certification CLAIM. A
	// row the product does not claim conformance to still runs and its verdict
	// is still evidence — but folding its FAIL into the same number as a
	// claim-relevant one overstates the run, which is exactly what
	// runs/certfix-validate-20260729T192416's "✗ 8 test case(s) FAILED" did with
	// AGG-009, AGG-012 and UTIL-002. Printed only when informative rows are
	// present, so a claim-only bundle stays quiet.
	if split {
		fmt.Fprintf(&sb, "- **Applicable to the claim:** %d PASS · %d FAIL · %d SKIP · %d WARN "+
			"(%d case(s))\n", app.Pass, app.Fail, app.Skip, app.Warn, app.Total())
		fmt.Fprintf(&sb, "- **Informative** — implemented, not claimed, marked `%s` in the table below: "+
			"%d PASS · %d FAIL · %d SKIP · %d WARN (%d case(s))\n\n",
			informativeTag, inf.Pass, inf.Fail, inf.Skip, inf.Warn, inf.Total())
	}
	switch {
	case b.OK():
		fmt.Fprintf(&sb, "✓ No failures.\n\n")
	case fail > 0 && split:
		fmt.Fprintf(&sb, "✗ %d test case(s) FAILED — %d applicable to the claim, %d informative. Only the "+
			"applicable failures bear on the certification claim.\n\n", fail, app.Fail, inf.Fail)
	case fail > 0:
		fmt.Fprintf(&sb, "✗ %d test case(s) FAILED.\n\n", fail)
	}

	fmt.Fprintf(&sb, "| Case | Title | Claim | Verdict | Assertions | Frames |\n")
	fmt.Fprintf(&sb, "|------|-------|-------|---------|-----------:|--------|\n")
	for _, c := range b.Cases {
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %d | %s |\n",
			mdEscape(c.ID), mdEscape(c.Title), claimTag(c), c.Verdict, len(c.Assertions), frameSpan(c))
	}
	fmt.Fprintf(&sb, "\n")

	fmt.Fprintf(&sb, "## Verifying this bundle\n\n")
	fmt.Fprintf(&sb, "This directory is self-checking. Independent checks, in the order a sceptical reader\n")
	fmt.Fprintf(&sb, "would run them:\n\n")
	// Numbered by a counter rather than by literals: the list grew a channel
	// twice, and a hand-numbered list is a list that eventually says "2." twice.
	n := 0
	item := func(format string, args ...any) {
		n++
		fmt.Fprintf(&sb, "%d. %s\n", n, fmt.Sprintf(format, args...))
	}
	item("`sha256sum -c %s` — every file, the capture included, is covered.", ManifestFile)
	item("The evidence verifier re-reads `%s` and confirms that every cited frame\n"+
		"   exists and carries the exact bytes each assertion claims. It reads only this\n"+
		"   directory and needs nothing from the bench that produced it.", b.Files.Capture)
	item("Every case verdict in the table above is re-derived from that case's own printed\n" +
		"   assertions. A stored verdict may be stricter than they roll up to — an uncited PASS is\n" +
		"   downgraded on purpose — but never weaker, so a headline cannot drift away from, or be\n" +
		"   edited away from, the evidence underneath it.")
	if len(b.Metrics) > 0 {
		item("The DUT metrics scrapes below are re-derived from the raw exposition bodies in\n"+
			"   `%s/`: every value, delta and outcome must follow from the bytes shipped with\n"+
			"   them. That proves the readings were recorded faithfully — not that the device\n"+
			"   was telling the truth about itself.", MetricsDir)
	}
	if len(b.Timebases) > 0 {
		item("Each fixture clock declared above is re-derived: its human label must follow from the\n" +
			"   kind and scale recorded beside it, so an accelerated run cannot be re-labelled as a\n" +
			"   wall-clock one without the bundle ceasing to verify.")
	}
	fmt.Fprintf(&sb, "\n")
	fmt.Fprintf(&sb, "Assertions marked *(no digest)* below carry no re-checkable citation: they are\n")
	fmt.Fprintf(&sb, "narrative, not proof.\n\n")

	b.metricsReport(&sb)

	fmt.Fprintf(&sb, "## Test cases\n\n")
	for _, c := range b.Cases {
		fmt.Fprintf(&sb, "### %s %s — %s\n\n", glyph(c.Verdict), mdEscape(caseTitle(c)), c.Verdict)
		// An informative row says so on its own heading, not only in a column
		// forty lines up. A reader who lands here from a search for "FAIL"
		// must not have to reconstruct whether anyone is certifying against it.
		if !c.Applicable {
			fmt.Fprintf(&sb, "**Informative row — NOT applicable to the certification claim.** The catalog "+
				"marks this case out of scope for the claimed profile; it is run and reported because its "+
				"verdict is evidence about the implementation, but it does not bear on the claim.\n\n")
		}
		if c.Doc != "" {
			fmt.Fprintf(&sb, "Reference: %s\n\n", mdEscape(c.Doc))
		}
		if c.Notes != "" {
			fmt.Fprintf(&sb, "%s\n\n", c.Notes)
		}
		if len(c.Assertions) == 0 {
			fmt.Fprintf(&sb, "_No assertions recorded._\n\n")
			continue
		}
		for i, a := range c.Assertions {
			fmt.Fprintf(&sb, "%d. **%s** — %s\n", i+1, a.Verdict, mdEscape(a.Claim))
			if a.Method != "" {
				fmt.Fprintf(&sb, "   - Method: %s\n", mdEscape(a.Method))
			}
			if a.Observed != "" {
				fmt.Fprintf(&sb, "   - Observed: %s\n", mdEscape(a.Observed))
			}
			if len(a.Frames) > 0 {
				fmt.Fprintf(&sb, "   - Frames: %s\n", frameList(a.Frames))
			}
			if a.StreamRef != "" {
				fmt.Fprintf(&sb, "   - Stream: `%s` bytes [%d,%d)\n", a.StreamRef, a.ByteRange[0], a.ByteRange[1])
			}
			switch {
			case a.BytesSHA256 != "":
				fmt.Fprintf(&sb, "   - Bytes sha256: `%s`\n", a.BytesSHA256)
			case a.FramesSHA256 != "":
				fmt.Fprintf(&sb, "   - Frames sha256: `%s`\n", a.FramesSHA256)
			default:
				fmt.Fprintf(&sb, "   - _(no digest — narrative, not re-checkable)_\n")
			}
			if a.Note != "" {
				fmt.Fprintf(&sb, "   - Note: %s\n", mdEscape(a.Note))
			}
		}
		fmt.Fprintf(&sb, "\n")
	}
	return sb.String()
}

// informativeTag marks a row nobody is certifying against, in the index table.
const informativeTag = "info"

// claimTag renders one case's bearing on the certification claim.
func claimTag(c TestCaseResult) string {
	if c.Applicable {
		return "yes"
	}
	return informativeTag
}

func caseTitle(c TestCaseResult) string {
	if c.Title == "" {
		return c.ID
	}
	return c.ID + " " + c.Title
}

func glyph(v Verdict) string {
	switch v {
	case Pass:
		return "✓"
	case Fail:
		return "✗"
	case Warn:
		return "⚠"
	default:
		return "·"
	}
}

// frameList renders frame numbers so they can be pasted straight into a
// Wireshark display filter.
func frameList(frames []int) string {
	parts := make([]string, len(frames))
	for i, f := range frames {
		parts[i] = fmt.Sprint(f)
	}
	return strings.Join(parts, ", ")
}

// frameSpan summarises the frames a case touched, for the index table.
func frameSpan(c TestCaseResult) string {
	lo, hi := 0, 0
	for _, a := range c.Assertions {
		for _, f := range a.Frames {
			if lo == 0 || f < lo {
				lo = f
			}
			if f > hi {
				hi = f
			}
		}
	}
	switch {
	case lo == 0:
		return "—"
	case lo == hi:
		return fmt.Sprint(lo)
	default:
		return fmt.Sprintf("%d–%d", lo, hi)
	}
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// mdEscape neutralises the pipe so a value cannot break a table row.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}
