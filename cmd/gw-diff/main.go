// Command gw-diff runs the differential-testing layer of the adversarial QA
// suite and writes an auditable artifact.
//
// The premise, in one line: show the SAME input to two independently-written
// implementations and report every disagreement. No one has to state the
// expected answer first, which is what makes this layer able to find defects
// nobody thought to write a case for.
//
// # Why this is a command and not just a test
//
// docs/ADVERSARIAL_QA_STRATEGY.md §6 is blunt about the constraint this project
// actually operates under: there is no CI budget, so everything runs locally,
// and "anything that needs a human to remember a sequence of steps will not be
// run." A differential layer reachable only as `go test -run` with the right
// flags, whose output scrolls past in a test log, is a layer that gets run once
// by the person who wrote it. So this command exists to make the whole layer one
// word, and to leave behind a file somebody can read next month.
//
// It writes REPORT.md (for a human) and report.json (for a diff between runs),
// both carrying the seed, the lineage of both sides, and the limitations —
// because a differential's blind spots are the part a reader is most likely to
// get wrong.
//
// # Exit status
//
//	0  every comparison agreed, or disagreed only in enumerated ways
//	1  at least one disagreement — see REPORT.md
//	2  the run compared NOTHING, or could not start
//
// Exit 2 is deliberately distinct from 0. A run that compared nothing has not
// tested anything, and the single most common way a harness rots is to keep
// exiting 0 while quietly doing less and less. Treating "compared nothing" as a
// distinct, non-success outcome is the same assertion floor internal/diff and
// internal/invariant enforce internally, surfaced where a shell script can see
// it.
//
// # Usage
//
//	gw-diff                        # every family, into ./runs/diff-<timestamp>
//	gw-diff -family ctl,chain      # a subset
//	gw-diff -seed 42 -out /tmp/d   # a reproducible run in a chosen place
//
// Nothing here touches the bench, a network, or a live device: every family
// drives an in-process register bank, so this is safe to run at any time,
// including while the bench is in use by somebody else.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/diff"
)

// family names the runnable families, in the order a reader should meet them:
// the control first, then the three that carry findings.
var families = []string{"reg", "sf", "chain", "ctl"}

func main() {
	var (
		seed      = flag.Int64("seed", 1, "seed for the generated-input families; recorded in the artifact so a run replays exactly")
		out       = flag.String("out", "", "directory for REPORT.md and report.json (default ./runs/diff-<timestamp>)")
		only      = flag.String("family", "", "comma-separated subset of: "+strings.Join(families, ",")+" (default all)")
		images    = flag.Int("images", 3, "random register images per model for the reg family")
		generated = flag.Int("generated", 64, "generated scale-factor cases beyond the standing catalogue")
		quiet     = flag.Bool("quiet", false, "suppress the full report on stdout; still writes the artifact")
	)
	flag.Parse()

	selected, err := selectFamilies(*only)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gw-diff: %v\n", err)
		os.Exit(2)
	}

	dir := *out
	if dir == "" {
		dir = filepath.Join("runs", "diff-"+time.Now().UTC().Format("20060102-150405"))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "gw-diff: cannot create %s: %v\n", dir, err)
		os.Exit(2)
	}

	ctx := context.Background()
	rep := diff.NewReport(*seed)

	for _, f := range selected {
		switch f {
		case "reg":
			diff.RunRegCatalog(ctx, rep, *images)
		case "sf":
			diff.RunSFCatalog(ctx, rep, *generated)
		case "chain":
			diff.RunChainCatalog(ctx, rep)
		case "ctl":
			if err := diff.RunCtlCatalog(ctx, rep); err != nil {
				// A family that could not run at all is not a family that
				// found nothing, and the difference must not be lost.
				fmt.Fprintf(os.Stderr, "gw-diff: the ctl family could not run: %v\n", err)
				os.Exit(2)
			}
		}
	}

	sum := rep.Summary()
	md := rep.Markdown()

	if err := os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(md), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gw-diff: writing REPORT.md: %v\n", err)
		os.Exit(2)
	}
	blob, err := json.MarshalIndent(struct {
		Summary diff.Summary `json:"summary"`
		Report  *diff.Report `json:"report"`
	}{sum, rep}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gw-diff: encoding report.json: %v\n", err)
		os.Exit(2)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gw-diff: writing report.json: %v\n", err)
		os.Exit(2)
	}

	if !*quiet {
		fmt.Print(md)
	}
	fmt.Printf("\nfamilies: %s\nseed: %d\ncases: %d, comparisons evaluated: %d, findings: %d\nartifact: %s\nVERDICT: %s\n",
		strings.Join(selected, ","), *seed, sum.Cases, sum.Compared, len(sum.Findings), dir, sum.Verdict)

	switch {
	case sum.Compared == 0:
		fmt.Fprintln(os.Stderr, "\ngw-diff: this run compared NOTHING; a differential that compared "+
			"nothing has not tested anything and cannot report success")
		os.Exit(2)
	case sum.Verdict == diff.Fail:
		os.Exit(1)
	default:
		os.Exit(0)
	}
}

// selectFamilies resolves the -family flag, rejecting an unknown name rather
// than silently running a smaller suite than the operator asked for. Silently
// ignoring a typo is how a nightly job ends up running one family for a year.
func selectFamilies(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		return families, nil
	}
	known := map[string]bool{}
	for _, f := range families {
		known[f] = true
	}
	var picked []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(spec, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !known[name] {
			return nil, fmt.Errorf("unknown family %q; known families are %s", name, strings.Join(families, ", "))
		}
		if !seen[name] {
			seen[name] = true
			picked = append(picked, name)
		}
	}
	if len(picked) == 0 {
		return nil, fmt.Errorf("-family was given but named no family")
	}
	// Keep the canonical order regardless of the order on the command line, so
	// two runs of the same set produce comparable artifacts.
	sort.Slice(picked, func(i, j int) bool {
		return indexOf(families, picked[i]) < indexOf(families, picked[j])
	})
	return picked, nil
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return len(ss)
}
