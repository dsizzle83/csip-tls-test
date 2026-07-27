package campaign

// shrink.go reduces a failing campaign to the SMALLEST action set that still
// reproduces the same violation.
//
// Strategy §4.4: "A 40-fault run that violates I1 is nearly useless as a bug
// report. Re-run with subsets to find the minimal fault set that reproduces,
// the way a property-testing framework shrinks a counterexample." That sentence
// is the difference between a chaos toy and a debugging tool, and this file is
// where it is paid for.
//
// # What "reproduces" means, and why it is not "failed again"
//
// A naive shrinker keeps any subset that fails. That is wrong here and would
// produce confidently misleading bug reports: a campaign has ten invariants
// running, and a subset that trips a DIFFERENT one has not reproduced anything
// — it has found a second bug while losing the first. So the oracle is
// [invariant.Violation.Signature], the fingerprint of WHAT went wrong with
// timestamps and tick numbers deliberately excluded. A subset reproduces if and
// only if the same signature appears.
//
// # ddmin, and why not plain greedy removal
//
// Greedy one-at-a-time removal is O(n²) and, worse, is defeated by the case
// this suite most wants to shrink: a violation that needs TWO faults together.
// Remove either one and the violation vanishes, so greedy removal concludes
// every fault is essential and returns the original set. Zeller's ddmin handles
// that: it partitions, tests complements, and only then increases granularity,
// so it converges on a 2-of-40 interaction in a few dozen attempts instead of
// declaring defeat. The implementation below is ddmin restricted to subsets (we
// only ever need 1-minimality, and the actions are not independently
// composable in the way full dd assumes).
//
// # Nondeterminism is reported, not hidden
//
// A campaign against real hardware is not perfectly reproducible: timing moves,
// the bench is shared, a session cap is momentarily full. So the shrink first
// CONFIRMS the violation still reproduces with the FULL set. If it does not,
// shrinking is abandoned and the report says the finding did not reproduce —
// which is itself important information and much better than a "minimal set" of
// two faults derived from a run whose failures were random.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// Attempt is one shrink re-run.
type Attempt struct {
	// N is the attempt number, from 1.
	N int `json:"n"`
	// Keep is the action set this attempt ran.
	Keep []string `json:"keep"`
	// Reproduced says whether the target signature appeared.
	Reproduced bool `json:"reproduced"`
	// Elapsed is the attempt's wall time.
	Elapsed time.Duration `json:"elapsed_ns"`
	// Err records an attempt that could not run at all. Such an attempt is
	// treated as NOT reproducing, and the count is reported: a shrink whose
	// attempts mostly errored has produced a "minimal set" by accident.
	Err string `json:"err,omitempty"`
}

// ShrinkResult is a completed shrink.
type ShrinkResult struct {
	// Signature is the violation that was being chased.
	Signature string `json:"signature"`
	// InvariantID is which invariant it falsified.
	InvariantID string `json:"invariant"`
	// Reason is the violation's own one-sentence finding.
	Reason string `json:"reason"`
	// Original is the full action set the failing run used.
	Original []string `json:"original"`
	// Minimal is the smallest set found that still reproduces. Equal to
	// Original when nothing could be removed.
	Minimal []string `json:"minimal"`
	// MinimalPlan is the reduced plan, so the reader can see the surviving
	// actions with their parameters and timing rather than just their ids.
	MinimalPlan Plan `json:"minimal_plan"`
	// Attempts is every re-run, in order — the audit trail for the claim that
	// the set is minimal.
	Attempts []Attempt `json:"attempts"`
	// Confirmed reports whether the FULL set reproduced the violation on re-run.
	// False means the finding is flaky and Minimal is not trustworthy; the
	// report says so rather than quietly presenting a number.
	Confirmed bool `json:"confirmed"`
	// Exhausted reports that the attempt budget ran out before 1-minimality was
	// proved. Minimal is then an upper bound, not a minimum, and saying which
	// is the difference between a bug report and a guess.
	Exhausted bool `json:"exhausted"`
	// Errored counts attempts that could not run.
	Errored int `json:"errored"`
}

// Minimal1 reports whether the result is proved 1-minimal: every single action
// was shown to be necessary.
func (s ShrinkResult) Minimal1() bool { return s.Confirmed && !s.Exhausted }

// String renders the shrink the way a bug report wants it.
func (s ShrinkResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SHRINK %s (%s) — %d actions -> %d\n", s.InvariantID, s.Signature, len(s.Original), len(s.Minimal))
	fmt.Fprintf(&b, "  finding : %s\n", s.Reason)
	switch {
	case !s.Confirmed:
		fmt.Fprintf(&b, "  status  : NOT REPRODUCED on re-run with the full action set — the finding is "+
			"non-deterministic and no minimal set can be claimed for it\n")
	case s.Exhausted:
		fmt.Fprintf(&b, "  status  : budget exhausted after %d attempts — the set below REPRODUCES but was not "+
			"proved minimal (it is an upper bound)\n", len(s.Attempts))
	default:
		fmt.Fprintf(&b, "  status  : 1-MINIMAL over %d attempts — removing any single action below stops the "+
			"violation reproducing\n", len(s.Attempts))
	}
	if s.Errored > 0 {
		fmt.Fprintf(&b, "  caution : %d attempt(s) could not run; a non-reproduction from those is not evidence\n", s.Errored)
	}
	fmt.Fprintf(&b, "  minimal reproducer:\n")
	for _, e := range s.MinimalPlan.Events {
		fmt.Fprintf(&b, "    t+%-6s %s\n", e.At.Round(100*time.Millisecond), e.action)
	}
	return b.String()
}

// ShrinkConfig bounds a shrink.
type ShrinkConfig struct {
	// Budget is the maximum number of re-runs. Zero means the default.
	Budget int
	// Config is the campaign config the attempts run under. It should be the
	// FAILING run's config — the same seed, the same window, the same cadence —
	// so that only the action set varies.
	Config Config
	// Log receives progress.
	Log interface{ Printf(string, ...any) }
}

func (c ShrinkConfig) budget() int {
	if c.Budget <= 0 {
		return defaultShrinkTo
	}
	return c.Budget
}

func (c ShrinkConfig) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log.Printf(format, args...)
	}
}

// Shrink reduces the action set of a failing campaign to a 1-minimal subset
// that still reproduces sig.
//
// It re-runs the campaign, so it needs the same envFn and layers the original
// run used. envFn is called fresh for every attempt — a shrink that reused a
// world whose DERs had already been lied to would be measuring residue.
func Shrink(ctx context.Context, sig string, orig Result, sc ShrinkConfig, envFn EnvFunc, layers []Layer) (ShrinkResult, error) {
	out := ShrinkResult{Signature: sig, Original: orig.Plan.ActionIDs()}
	for _, v := range orig.Violations {
		if v.Signature() == sig {
			out.InvariantID, out.Reason = v.ID, v.Reason
			break
		}
	}
	if len(out.Original) == 0 {
		return out, fmt.Errorf("campaign: cannot shrink a run with no scheduled actions")
	}

	budget := sc.budget()
	spent := 0

	// run executes one attempt and reports whether sig reproduced.
	run := func(keep []string) bool {
		if spent >= budget {
			return false
		}
		spent++
		at := Attempt{N: spent, Keep: append([]string(nil), keep...)}
		t0 := time.Now()
		cfg := sc.Config
		cfg.MustViolate = false // the shrinker judges by signature, not by the gate
		res, err := runSubset(ctx, cfg, envFn, layers, keep)
		at.Elapsed = time.Since(t0)
		if err != nil {
			at.Err = err.Error()
			out.Errored++
		} else {
			at.Reproduced = res.Has(sig)
		}
		out.Attempts = append(out.Attempts, at)
		sc.logf("shrink attempt %d/%d: %d action(s) -> reproduced=%t%s",
			spent, budget, len(keep), at.Reproduced, errSuffix(at.Err))
		return at.Reproduced
	}

	// Step 0: confirm. A finding that does not reproduce with the FULL set is
	// flaky, and every "minimal" set derived from it would be noise.
	if !run(out.Original) {
		out.Minimal = out.Original
		out.MinimalPlan = orig.Plan
		return out, nil
	}
	out.Confirmed = true

	current := append([]string(nil), out.Original...)
	n := 2
	for len(current) > 1 && spent < budget {
		chunks := partition(current, n)
		reduced := false

		// Try each COMPLEMENT: remove one chunk, keep the rest. This is the
		// step that finds a two-fault interaction, because it removes many
		// actions at once rather than one.
		for i := range chunks {
			if spent >= budget {
				break
			}
			cand := without(current, chunks[i])
			if len(cand) == 0 {
				continue
			}
			if run(cand) {
				current = cand
				n = maxInt(n-1, 2)
				reduced = true
				break
			}
		}
		if reduced {
			continue
		}
		// Also try each chunk ALONE, which catches the case where the
		// reproducer is a small contiguous group.
		for i := range chunks {
			if spent >= budget {
				break
			}
			if len(chunks[i]) == 0 || len(chunks[i]) == len(current) {
				continue
			}
			if run(chunks[i]) {
				current = chunks[i]
				n = 2
				reduced = true
				break
			}
		}
		if reduced {
			continue
		}
		if n >= len(current) {
			break // granularity is already one action per chunk: 1-minimal
		}
		n = minInt(2*n, len(current))
	}

	out.Minimal = current
	out.MinimalPlan = orig.Plan.Subset(current)
	out.Exhausted = spent >= budget && len(current) > 1
	return out, nil
}

func errSuffix(e string) string {
	if e == "" {
		return ""
	}
	return " (attempt errored: " + e + ")"
}

// runSubset re-plans the campaign from the same seed and runs only the kept
// actions, with their original timing.
//
// Re-planning rather than replaying the previous Plan is deliberate: the
// actions carry closures onto a world that has been torn down, so they must be
// rebuilt. Re-planning from the same seed against a fresh env is what makes
// them rebuildable at all, and it is also a continuous check that the plan
// really is a pure function of the seed — if it were not, the shrink would stop
// reproducing immediately and say so.
//
// The action budget is raised to the size of the kept set: selection has
// already happened, and re-applying a budget here would silently drop actions
// the shrinker asked for, so an attempt would be testing a set nobody chose.
func runSubset(ctx context.Context, cfg Config, envFn EnvFunc, layers []Layer, keep []string) (Result, error) {
	want := make(map[string]bool, len(keep))
	for _, id := range keep {
		want[id] = true
	}
	cfg.Actions = len(keep)
	return Run(ctx, cfg, envFn, FilterLayers(layers, want))
}

// FilterLayers wraps each layer so it offers only the actions whose ids are in
// keep. Filtering at the LAYER level, before the scheduler runs, is what makes
// a shrink attempt a genuine subset of the original campaign rather than a
// different campaign that happens to have fewer faults.
//
// It is safe only because timing is derived per action from (seed, action id)
// rather than from draw order — see BuildPlan. If timing depended on how many
// actions were planned, every shrink attempt would move the surviving faults
// around and the shrinker would chase its own tail.
func FilterLayers(layers []Layer, keep map[string]bool) []Layer {
	out := make([]Layer, 0, len(layers))
	for _, l := range layers {
		out = append(out, &filtered{Layer: l, keep: keep})
	}
	return out
}

type filtered struct {
	Layer
	keep map[string]bool
}

// Plan numbers the wrapped layer's actions exactly as BuildPlan would, then
// drops the ones not kept. Numbering BEFORE filtering is essential: the seq is
// part of the id, so filtering first would renumber the survivors and break
// every id the shrinker is tracking.
func (f *filtered) Plan(inv Inventory, rng *rand.Rand) []Action {
	numbered := assignSeqs(f.Layer.Plan(inv, rng))
	out := make([]Action, 0, len(numbered))
	for _, a := range numbered {
		if f.keep[a.ID()] {
			out = append(out, a)
		}
	}
	return out
}

// partition splits ids into n roughly equal chunks.
func partition(ids []string, n int) [][]string {
	if n < 1 {
		n = 1
	}
	if n > len(ids) {
		n = len(ids)
	}
	out := make([][]string, 0, n)
	size := len(ids) / n
	rem := len(ids) % n
	i := 0
	for c := 0; c < n; c++ {
		sz := size
		if c < rem {
			sz++
		}
		out = append(out, ids[i:i+sz])
		i += sz
	}
	return out
}

// without returns ids minus the members of drop.
func without(ids, drop []string) []string {
	bad := make(map[string]bool, len(drop))
	for _, d := range drop {
		bad[d] = true
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !bad[id] {
			out = append(out, id)
		}
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
