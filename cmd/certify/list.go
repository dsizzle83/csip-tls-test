package main

// list.go answers the first question anybody asks this tool: "what does it
// cover?"
//
// The answer is deliberately structured so it cannot flatter us. Every document
// prints five numbers — selected, applicable, implemented, unimplemented,
// not-applicable — and the unimplemented and not-applicable rows are printed BY
// NAME with the extraction's own reason when there is one. A tool that reported
// "256 checks" and left it there would be reporting its own size; what a
// certification reviewer needs is the complement: which of the 282 published
// test cases this tool does not exercise, and why not.
//
// -details prints every case. -json prints the same information as the
// framework's Coverage structure, for a pipeline that wants to gate on it.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suites"
)

func (c *cli) runList(stdout, stderr io.Writer) int {
	cat, err := c.catalog()
	if err != nil {
		fatal(stderr, err)
		return exitUsage
	}
	filter := c.opts.Filter()
	if err := cat.Validate(filter); err != nil {
		fatal(stderr, err)
		return exitUsage
	}
	reg := suites.Registry()
	cov := reg.Coverage(cat, filter)

	if c.jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cov); err != nil {
			fmt.Fprintf(stderr, "certify: encode coverage: %v\n", err)
			return exitUsage
		}
		return listStatus(cov)
	}

	ref := cat.Ref()
	fmt.Fprintf(stdout, "CATALOG  %s\n", ref.Source)
	fmt.Fprintf(stdout, "         sha256 %s · %d test cases · %d document(s)\n\n",
		ref.SHA256, ref.Cases, len(cat.Docs()))

	fmt.Fprintf(stdout, "%-30s %-10s %6s %6s %6s %6s %6s  %s\n",
		"DOCUMENT", "VERSION", "SEL", "APPL", "IMPL", "GAP", "N/A", "SUITE")
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("─", 100))
	suiteDocs := suites.Docs(cat)
	docSuites := invert(suiteDocs)
	naTotal := 0
	for _, d := range cov.Docs {
		naTotal += len(d.Inapplicable)
		fmt.Fprintf(stdout, "%-30s %-10s %6d %6d %6d %6d %6d  %s\n",
			d.Doc, shortVersion(d.Version), d.Total, d.Applicable,
			len(d.Implemented), len(d.Unimplemented), len(d.Inapplicable),
			strings.Join(docSuites[d.Doc], ", "))
	}
	total, applicable, implemented, missing := cov.Totals()
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("─", 100))
	fmt.Fprintf(stdout, "%-30s %-10s %6d %6d %6d %6d %6d\n",
		"TOTAL", "", total, applicable, implemented, missing, naTotal)
	fmt.Fprintf(stdout, "SEL selected · APPL applicable to this product · IMPL has a check · "+
		"GAP applicable with none · N/A inapplicable, no check\n")
	// The three columns do not add up, and the reason is a deliberate
	// engineering choice rather than an arithmetic slip: a case the extraction
	// marked inapplicable may STILL carry a check, when exercising the row is
	// worth more than assuming it. Those land in IMPL, not N/A, so the numbers
	// are stated rather than left for a reviewer to reconcile.
	if extra := implemented - (applicable - missing); extra > 0 {
		fmt.Fprintf(stdout, "%d implemented case(s) are marked inapplicable by the extraction and are "+
			"exercised anyway,\nrather than assumed: they count in IMPL, not N/A.\n", extra)
	}
	fmt.Fprintln(stdout)

	fmt.Fprintf(stdout, "SUITES (-suite)\n")
	for _, s := range suites.Names() {
		n := 0
		for _, reg := range reg.Registrations() {
			if reg.Suite == s {
				n++
			}
		}
		fmt.Fprintf(stdout, "  %-18s %3d check(s)   %s\n", s, n, strings.Join(suiteDocs[s], ", "))
	}
	fmt.Fprintln(stdout)

	// The gaps, by name. This section is the point of the whole mode.
	if missing > 0 {
		fmt.Fprintf(stdout, "APPLICABLE TEST CASES WITH NO IMPLEMENTATION (%d)\n", missing)
		for _, d := range cov.Docs {
			for _, e := range d.Unimplemented {
				fmt.Fprintf(stdout, "  ✗ %-28s %s\n", e.ID, trunc(e.Title, 60))
			}
		}
		fmt.Fprintln(stdout)
	}
	if len(cov.Orphans) > 0 {
		fmt.Fprintf(stdout, "REGISTERED UIDS THAT ARE NOT IN THE CATALOG (%d) — suite and catalog have diverged\n",
			len(cov.Orphans))
		for _, o := range cov.Orphans {
			fmt.Fprintf(stdout, "  ✗ %s\n", o)
		}
		fmt.Fprintln(stdout)
	}

	if c.details {
		listCases(stdout, cov)
	} else {
		fmt.Fprintf(stdout, "Per-case detail: -details (add -doc / -suite / -uid to narrow it).\n")
		fmt.Fprintf(stdout, "Inapplicable cases carry the extraction's own reason; -details prints it.\n\n")
	}

	switch {
	case missing > 0 || len(cov.Orphans) > 0:
		fmt.Fprintf(stdout, "✗ %d applicable case(s) unimplemented, %d orphaned registration(s)\n",
			missing, len(cov.Orphans))
	default:
		fmt.Fprintf(stdout, "✓ every applicable test case in this selection has an implementation\n")
	}
	return listStatus(cov)
}

// listStatus makes -list usable as a gate: a coverage regression is a negative
// result, not a formatting preference.
func listStatus(cov certify.Coverage) int {
	if cov.Complete() {
		return exitOK
	}
	return exitFail
}

// listCases prints every selected case with its status.
func listCases(stdout io.Writer, cov certify.Coverage) {
	for _, d := range cov.Docs {
		fmt.Fprintf(stdout, "── %s (%s) %s\n", d.Doc, shortVersion(d.Version),
			strings.Repeat("─", max(0, 74-len(d.Doc)-len(shortVersion(d.Version)))))
		type row struct {
			glyph string
			e     certify.CoverageEntry
			note  string
		}
		var rows []row
		for _, e := range d.Implemented {
			rows = append(rows, row{"✓", e, e.Suite})
		}
		for _, e := range d.Unimplemented {
			rows = append(rows, row{"✗", e, "NO IMPLEMENTATION"})
		}
		for _, e := range d.Inapplicable {
			rows = append(rows, row{"·", e, "n/a: " + firstSentence(e.Reason)})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].e.ID < rows[j].e.ID })
		for _, r := range rows {
			fmt.Fprintf(stdout, "  %s %-16s %-46s %s\n",
				r.glyph, r.e.ID, trunc(r.e.Title, 46), trunc(r.note, 58))
		}
		fmt.Fprintln(stdout)
	}
}

// runCapabilities prints the capability tags this invocation carries and the
// checks each one gates.
//
// It exists because "SKIP: missing capability: keylog" is a dead end for an
// operator who does not know which flag supplies the tag. Here every tag is
// listed with what turns it on and how many checks depend on it, so the cost of
// a missing piece of bench is visible BEFORE the run rather than as a pile of
// skips afterwards.
func (c *cli) runCapabilities(stdout io.Writer) int {
	have := map[string]bool{
		"capture": !c.opts.NoCapture,
		"keylog":  c.opts.KeyLogPath != "",
		"gridsim": c.opts.Targets.GridSimAdmin != "",
		"gateway": c.opts.GatewaySSH != "",
		"pki":     c.opts.PKIDir != "",
		"bench":   c.opts.Targets.Gateway != "",
	}
	for _, tag := range c.caps {
		have[tag] = true
	}
	source := map[string]string{
		"capture": "a capture is running (off with -no-capture)",
		"keylog":  "-keylog <path>, and a binary built with -tags keylog",
		"gridsim": "-gridsim-admin <url>",
		"gateway": "-gateway-ssh <dest> (READ-ONLY introspection)",
		"pki":     "-pki <dir>",
		"bench":   "-target / -gateway <host:port>",
	}

	need := map[string]int{}
	for _, reg := range suites.Registry().Registrations() {
		for _, tag := range reg.Requires {
			need[tag]++
		}
	}
	tags := make([]string, 0, len(need))
	for t := range need {
		tags = append(tags, t)
	}
	for t := range have {
		if _, ok := need[t]; !ok {
			tags = append(tags, t)
		}
	}
	sort.Strings(tags)

	fmt.Fprintf(stdout, "CAPABILITIES for this invocation\n\n")
	fmt.Fprintf(stdout, "%-12s %-5s %6s  %s\n", "TAG", "HAVE", "GATES", "SUPPLIED BY")
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("─", 88))
	blocked := 0
	for _, t := range tags {
		mark := "no"
		if have[t] {
			mark = "yes"
		} else {
			blocked += need[t]
		}
		src := source[t]
		if src == "" {
			src = "-cap " + t + " (operator assertion; the runner cannot detect it)"
		}
		fmt.Fprintf(stdout, "%-12s %-5s %6d  %s\n", t, mark, need[t], src)
	}
	fmt.Fprintf(stdout, "%s\n", strings.Repeat("─", 88))
	if blocked > 0 {
		fmt.Fprintf(stdout, "\n%d check(s) would SKIP for a missing capability. A skip names its missing tag;\n"+
			"none of them is ever silently dropped.\n", blocked)
		return exitOK
	}
	fmt.Fprintf(stdout, "\nEvery capability any registered check requires is present.\n")
	return exitOK
}

func invert(m map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, vs := range m {
		for _, v := range vs {
			out[v] = append(out[v], k)
		}
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

// shortVersion trims the catalog's version strings, one of which carries a
// multi-sentence extraction note that would otherwise wreck the table. The full
// text stays in the catalog and in the bundle; this is a column, not a record.
func shortVersion(v string) string {
	if i := strings.IndexAny(v, " ("); i > 0 {
		v = v[:i]
	}
	return trunc(v, 10)
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	return s
}
