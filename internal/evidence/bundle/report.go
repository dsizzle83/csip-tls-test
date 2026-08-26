package bundle

import (
	"fmt"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/capture"
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
	pass, fail, skip, warn, na := b.Counts()

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
	row("Capture hygiene", captureHygieneLine(b.Capture))
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

	// The capture-hygiene disclosure goes with the capture rows it qualifies,
	// for the same reason: it says what is and is not in the pcap the frame
	// numbers below count over.
	b.captureHygieneReport(&sb)

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
	fmt.Fprintf(&sb, "**%d PASS · %d FAIL · %d SKIP · %d WARN** across %d in-scope test case(s).\n\n",
		pass, fail, skip, warn, len(b.Cases)-na)
	// N/A is stated on its own line, outside the headline, because it is not an
	// outcome. A row this candidate never claimed has no verdict to average in,
	// and printing it beside the four that do is how a campaign comes to look
	// mostly-unfinished when it is in fact complete — LAB29-001's whole
	// complaint. The reasons are one table away, per row, so a reader who
	// disputes a scope decision can see exactly whose declaration made it.
	if na > 0 {
		fmt.Fprintf(&sb, "%d further case(s) are **NOT APPLICABLE** to this candidate and were not run: "+
			"each carries a reason and the declaration it rests on, in its own section below. They are "+
			"neither passes nor failures and bear on nothing.\n\n", na)
	}
	// Split the headline by whether a row bears on the certification CLAIM. A
	// row the product does not claim conformance to still runs and its verdict
	// is still evidence — but folding its FAIL into the same number as a
	// claim-relevant one overstates the run, which is exactly what
	// runs/certfix-validate-20260729T192416's "✗ 8 test case(s) FAILED" did with
	// AGG-009, AGG-012 and UTIL-002. Printed only when informative rows are
	// present, so a claim-only bundle stays quiet.
	if split {
		fmt.Fprintf(&sb, "- **Applicable to the claim:** %d PASS · %d FAIL · %d SKIP · %d WARN "+
			"(%d in-scope case(s)%s)\n", app.Pass, app.Fail, app.Skip, app.Warn, app.InScope(),
			naSuffix(app.NotApplicable))
		fmt.Fprintf(&sb, "- **Informative** — implemented but not bearing on the claim, marked `%s` "+
			"(not applicable to the claimed profile) or `%s` (covered by no published procedure) in the "+
			"table below: %d PASS · %d FAIL · %d SKIP · %d WARN (%d in-scope case(s)%s)\n\n",
			informativeTag, localExtTag, inf.Pass, inf.Fail, inf.Skip, inf.Warn, inf.InScope(),
			naSuffix(inf.NotApplicable))
	}
	// THE BANNER MEANS WHAT IT SAYS, so it is gated on the RAW failure count and
	// not on b.OK().
	//
	// Those were the same thing until OK() was narrowed to claim-bearing
	// failures. After that, `case b.OK()` fired while an informative FAIL
	// existed and printed "✓ No failures." over a report whose own headline two
	// lines above says otherwise — shadowing the split branch below, whose
	// wording is exactly right and which became unreachable whenever the only
	// failures were non-certifiable.
	//
	// It is the mirror image of the defect the split was introduced for.
	// certfix-validate-20260729T192416 OVERSTATED, printing "✗ 8 test case(s)
	// FAILED" for failures that did not bear on the claim; this UNDERSTATED,
	// which is the worse direction: a reader who trusts the banner never reaches
	// the row.
	switch {
	case fail == 0 && len(b.Cases) == na:
		// Every row out of scope. There is no failure to report and no result
		// either; announcing "no failures" over it would be true and useless.
		fmt.Fprintf(&sb, "⚠ Nothing was measured: every case in this bundle is out of scope for the "+
			"candidate.\n\n")
	case fail == 0:
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
		switch {
		case c.NonCertifiable:
			fmt.Fprintf(&sb, "**LOCAL EXTENSION — certifiable under no standard.** No published procedure "+
				"covers this case: its Test Values are the harness's own and its verdict is supplementary "+
				"PRODUCT EVIDENCE, not a conformance result. It is run, bundled and re-verified like any "+
				"other row, and it is excluded from every applicable-FAIL tally and from the clean-run "+
				"criterion. A FAIL here is a finding about the implementation; it is not a certification "+
				"failure.\n\n")
		case !c.Applicable:
			fmt.Fprintf(&sb, "**Informative row — NOT applicable to the certification claim.** The catalog "+
				"marks this case out of scope for the claimed profile; it is run and reported because its "+
				"verdict is evidence about the implementation, but it does not bear on the claim.\n\n")
		}
		// The scope declaration, stated where the reader meets the row rather
		// than only in bundle.json. Printed for a not-applicable case whatever
		// else is true of it, so "why is this row not measured?" is answered on
		// the spot and with an attributable source.
		if c.Verdict == VerdictNotApplicable && c.NotApplicable != nil {
			fmt.Fprintf(&sb, "**NOT APPLICABLE — not run.** %s\n\n", mdEscape(c.NotApplicable.Reason))
			fmt.Fprintf(&sb, "- Declared by: `%s`\n", c.NotApplicable.Source)
			if c.NotApplicable.Detail != "" {
				fmt.Fprintf(&sb, "- Declaration: %s\n", mdEscape(c.NotApplicable.Detail))
			}
			fmt.Fprintf(&sb, "\n")
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

// localExtTag marks a row no published procedure covers, in the index table. It
// is distinct from informativeTag because the two mean different things: "info"
// is a real procedure that does not apply to this product, "local-ext" is a
// measurement no procedure exists for at all.
const localExtTag = "local-ext"

// claimTag renders one case's bearing on the certification claim.
func claimTag(c TestCaseResult) string {
	switch {
	case c.NonCertifiable:
		return localExtTag
	case c.Applicable:
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
	case VerdictNotApplicable:
		// A dash, not the SKIP dot: at a glance down the report a reader must be
		// able to tell "nobody measured this" from "there was nothing here to
		// measure" without reading the word beside it.
		return "—"
	default:
		return "·"
	}
}

// naSuffix renders the out-of-scope count as a parenthetical addition to an
// in-scope tally, or nothing at all when there is none — so a bundle with
// nothing out of scope reads exactly as it did before this verdict existed.
func naSuffix(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", plus %d not applicable", n)
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

// captureHygieneLine is the one-line summary of the post-capture re-filter for
// the run table.
//
// It is empty — so the row disappears entirely — for a bundle whose capture
// summary carries no per-interface accounting, which is every bundle written
// before that accounting existed. Absent is not "zero frames captured"; it is
// "this bundle does not say", and inventing a reassuring "0 dropped" for it
// would be the report asserting something nobody measured.
func captureHygieneLine(sum capture.Summary) string {
	if len(sum.Interfaces) == 0 {
		return ""
	}
	captured := 0
	for _, in := range sum.Interfaces {
		captured += in.Captured
	}
	switch dropped := sum.RefilterDropped(); {
	case sum.Filter == "":
		return fmt.Sprintf("%d frame(s) captured; no filter was requested, so every frame the "+
			"tool wrote is in this bundle", captured)
	case dropped == 0:
		return fmt.Sprintf("the capture filter was re-applied to all %d captured frame(s) after "+
			"the capture; none had to be dropped", captured)
	default:
		return fmt.Sprintf("the capture filter was re-applied to all %d captured frame(s) after "+
			"the capture; %d did not match and were dropped — see below", captured, dropped)
	}
}

// captureHygieneReport prints the per-interface frame accounting, and the
// banner that has to go with it when the capture tool's kernel filter was not
// doing its job.
//
// # Why a report section and not just a number in bundle.json
//
// The failure it discloses is invisible from anywhere else. dumpcap given more
// than one -i can leave its kernel filter unarmed on the first-listed
// interface for a whole capture; it announces itself normally, writes a valid
// file, reports no drops, and delivers every frame on that NIC. The capture
// tool's own output — printed further down this report — says nothing. Without
// this section the only trace would be a packet count that looks large, and an
// operator who never learns that a leg of their run ran with no filter at all.
//
// The frames themselves are NOT in the bundle: they are traffic the run did not
// ask for and could not be handed to a laboratory unredacted, which is the
// whole point of asking for a filter. What is here is the count of what went,
// per interface, so nothing is hidden by removing it.
func (b *Bundle) captureHygieneReport(sb *strings.Builder) {
	ifs := b.Capture.Interfaces
	if len(ifs) == 0 {
		return
	}
	dropped := b.Capture.RefilterDropped()
	// One interface, nothing dropped, nothing undecided: the table row above
	// already said everything there is to say.
	if len(ifs) < 2 && dropped == 0 && b.Capture.RefilterUndecided() == 0 {
		return
	}

	if b.Capture.FilterUnarmed() {
		fmt.Fprintf(sb, "> **The capture tool's kernel filter was not armed on every interface.** `%s` was\n"+
			"> given the filter `%s`, and %s still delivered %d frame(s) that do not match it. This is a\n"+
			"> known defect of a multi-interface capture: the tool announces itself, writes a valid\n"+
			"> file and reports no drops while one of its taps runs unfiltered. Those frames were\n"+
			"> re-filtered out of this bundle's capture before it was written, so the pcap holds only\n"+
			"> traffic the run asked for and every frame number in this report counts over the\n"+
			"> filtered file. The counts below are what was removed.\n\n",
			mdEscape(b.Capture.Tool), mdEscape(b.Capture.Filter),
			mdEscape(strings.Join(b.Capture.UnarmedInterfaces(), " and ")), dropped)
	}

	fmt.Fprintf(sb, "| Capture interface | Frames captured | In this bundle | Re-filtered out | Undecided |\n")
	fmt.Fprintf(sb, "|---|---:|---:|---:|---:|\n")
	for _, in := range ifs {
		name := in.Name
		if name == "" {
			name = fmt.Sprintf("interface %d", in.ID)
		}
		fmt.Fprintf(sb, "| %s | %d | %d | %d | %d |\n",
			mdEscape(name), in.Captured, in.Kept, in.Dropped, in.Undecided)
	}
	fmt.Fprintf(sb, "\n")

	if n := b.Capture.RefilterUndecided(); n > 0 {
		fmt.Fprintf(sb, "%d frame(s) were KEPT although the re-filter could not decide them against `%s` — a\n"+
			"header the dissector rejects, the first fragment of a fragmented datagram, or a transport\n"+
			"this tool does not dissect. The re-filter only ever removes a frame it can prove does not\n"+
			"match, so it can add redaction but never destroy evidence.\n\n",
			n, mdEscape(b.Capture.Filter))
	}
}
