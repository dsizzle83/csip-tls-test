package invariant

// invariant.go is the contract every checker implements and the vocabulary
// every verdict is spoken in.
//
// The one design decision worth defending here is that Check returns a [Result]
// struct rather than the (Verdict, []Assertion, error) triple the strategy
// sketched. The requirement that forced it is "a violation must record WHAT WAS
// TRUE, not just 'I1 failed'". A bundle.Assertion's Observed field is prose —
// excellent for a human reading REPORT.md, useless for the shrinker that has to
// re-run a 40-fault campaign with subsets and decide whether the same violation
// reproduced. [Fact] is the machine-readable half: a key, a value, the unit that
// value is in, and the source that observed it. Both travel together, so the
// report reads well AND the shrinker can compare two violations without parsing
// English.
//
// The second decision is [Pending]. I9 ("a recoverable outage recovers without
// human intervention, in bounded time") must not encode a threshold the product
// never promised — the gateway backs off to 15 minutes and promises nothing
// about promptness. So while a cleared fault has not yet recovered, the honest
// verdict is neither PASS nor FAIL: the claim is not yet decidable. Pending says
// that, and [Monitor.Finalize] resolves it at the end of the run — a channel
// that never came back before the run ended is a FAIL, and no invented deadline
// was needed to say so.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/evidence/bundle"
)

// Verdict is an invariant's outcome at one check. The first four values are the
// bench's standard four (sim/ssm-conformance, internal/certify); Pending is
// this package's addition for claims whose resolution is deferred to the end of
// the run.
type Verdict string

// The verdicts.
const (
	// Pass — the property was asserted against observed state and held.
	Pass Verdict = "PASS"
	// Fail — the property was asserted and did not hold. Always P1.
	Fail Verdict = "FAIL"
	// Skip — not assertable from what this run can observe. Reason says why,
	// and a Reason is mandatory: a SKIP that does not name its missing
	// observation is indistinguishable from a checker that forgot to run.
	Skip Verdict = "SKIP"
	// Warn — asserted, held, but something adjacent is off enough to say so.
	Warn Verdict = "WARN"
	// Pending — the claim is not yet decidable at this instant and the run's
	// end decides it. Monitor.Finalize converts a still-Pending claim into
	// Fail, because "the run ended and it never resolved" IS the falsification.
	Pending Verdict = "PENDING"
)

// Severity orders verdicts so a roll-up can take the worst. Pending sorts
// between Warn and Fail: it is not yet a failure, but it is more alarming than
// a caveat.
func (v Verdict) Severity() int {
	switch v {
	case Fail:
		return 4
	case Pending:
		return 3
	case Warn:
		return 2
	case Pass:
		return 1
	default:
		return 0
	}
}

// Bundle maps a verdict onto the evidence bundle's four-value vocabulary. A
// Pending claim becomes a SKIP in the bundle — it was not decided — and
// Monitor.Finalize is what stops a run ending with an undecided claim silently
// recorded as "skipped".
func (v Verdict) Bundle() bundle.Verdict {
	switch v {
	case Pass:
		return bundle.Pass
	case Fail:
		return bundle.Fail
	case Warn:
		return bundle.Warn
	default:
		return bundle.Skip
	}
}

// Worse returns the more severe of two verdicts.
func Worse(a, b Verdict) Verdict {
	if b.Severity() > a.Severity() {
		return b
	}
	return a
}

// Fact is one machine-readable thing that was true when a verdict was reached.
//
// The Unit field is not decoration. Half this package exists because a number
// lost its unit somewhere (BR-01), so a fact that records "3000" without
// recording whether that is vars or percent-of-rated reproduces the very defect
// it is evidence for.
type Fact struct {
	// Key is a stable dotted identifier, e.g. "der.inv-plain.VarSetPct.raw".
	// Stable because the shrinker compares facts across runs by key.
	Key string `json:"key"`
	// Value is the observed value rendered as text.
	Value string `json:"value"`
	// Unit is the unit Value is expressed in — "var", "W", "%", "s", "count",
	// or "" for a genuinely dimensionless identifier like an mRID.
	Unit string `json:"unit,omitempty"`
	// Source names the observation channel, e.g. "mbaps:69.0.0.2:802",
	// "modbus:69.0.0.20:5020", "gridsim-admin". A fact whose source is not
	// externally observable does not belong in this package.
	Source string `json:"source,omitempty"`
}

// F builds a Fact.
func F(key, unit, source string, format string, args ...any) Fact {
	return Fact{Key: key, Value: fmt.Sprintf(format, args...), Unit: unit, Source: source}
}

// Result is one invariant's outcome at one check.
type Result struct {
	// Verdict is the outcome.
	Verdict Verdict `json:"verdict"`
	// Reason explains a non-Pass verdict in one sentence. It is REQUIRED for
	// Fail, Skip, Warn and Pending; Validate enforces that.
	Reason string `json:"reason,omitempty"`
	// Facts are the structured record of what was true. A Fail with no facts
	// is rejected by Validate: "I1 failed" is not a bug report.
	Facts []Fact `json:"facts,omitempty"`
	// Assertions are the citable claims for the evidence bundle. Build them
	// with bundle.CiteFrames / bundle.CiteBytes when the capture can back
	// them; a non-citable assertion is still useful prose and the bundle's
	// verifier reports it as such.
	Assertions []bundle.Assertion `json:"assertions,omitempty"`
	// Checked counts the individual sub-claims this check actually evaluated —
	// per DER, per point, per ledger entry. It is the assertion floor: a Pass
	// with Checked == 0 asserted nothing and Validate rejects it, for the same
	// reason gw-mayhem grew an assertion floor in wave 1.
	Checked int `json:"checked"`
}

// Validate enforces the honesty rules a Result must satisfy before it may be
// reported. It is called by the Monitor on every result, so a checker cannot
// silently produce a pass it did not earn.
func (r Result) Validate(id string) error {
	switch r.Verdict {
	case Pass:
		if r.Checked <= 0 {
			return fmt.Errorf("invariant %s: PASS with zero sub-claims checked — a check that asserted nothing cannot pass", id)
		}
	case Fail:
		if r.Reason == "" {
			return fmt.Errorf("invariant %s: FAIL with no reason", id)
		}
		if len(r.Facts) == 0 {
			return fmt.Errorf("invariant %s: FAIL with no facts — a violation must record what was true", id)
		}
	case Skip, Warn, Pending:
		if r.Reason == "" {
			return fmt.Errorf("invariant %s: %s with no reason", id, r.Verdict)
		}
	default:
		return fmt.Errorf("invariant %s: unknown verdict %q", id, r.Verdict)
	}
	return nil
}

// Invariant is a safety property that must hold no matter what the adversary
// does.
//
// Implementations must be PURE with respect to the DUT: Check may read from the
// World's sources, and must not drive, configure, restart, or write to anything.
// The campaign arms faults and records what it attempted in the [Ledger]; the
// invariant only ever judges.
//
// Check must be safe to call concurrently with other invariants against the
// same World, and must tolerate a World whose sources are partly unreachable —
// that is the normal state during a chaos campaign, and it is a SKIP with a
// reason, never a panic and never a fabricated pass.
type Invariant interface {
	// ID is the strategy document's identifier: "I1" … "I10".
	ID() string
	// Statement is the falsifiable claim, in words, exactly as it should
	// appear next to the verdict. Where the implementation checks a weaker
	// property than the strategy's ideal, the statement SAYS SO — the honest
	// approximation is stated here, not hidden in a comment.
	Statement() string
	// Grounding names the defect class this invariant exists to catch, so a
	// reader can judge whether the check would actually have caught it.
	Grounding() string
	// Check evaluates the property against the world as most recently
	// observed. A returned error means the check could not run at all (a
	// programming error or an unusable World); a property that could not be
	// decided is a Skip or Pending Result with a reason, not an error.
	Check(ctx context.Context, w *World) (Result, error)
}

// Standard returns I1–I10 in order, configured from p.
//
// This is the set a campaign runs. Constructing them from Params rather than
// from package state means two Monitors in one process (a hermetic self-test
// and a live run) cannot interfere.
func Standard(p Params) []Invariant {
	return []Invariant{
		NewI1(p), NewI2(p), NewI3(p), NewI4(p), NewI5(p),
		NewI6(p), NewI7(p), NewI8(p), NewI9(p), NewI10(p),
	}
}

// ByID returns one standard invariant.
func ByID(id string, p Params) (Invariant, bool) {
	for _, inv := range Standard(p) {
		if strings.EqualFold(inv.ID(), id) {
			return inv, true
		}
	}
	return nil, false
}

// Select returns the standard invariants whose IDs appear in ids, preserving
// I1..I10 order, plus the names of any ids that matched nothing — so a caller
// that typos "-invariants I11" is told rather than silently running nine.
func Select(ids []string, p Params) ([]Invariant, []string) {
	if len(ids) == 0 {
		return Standard(p), nil
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[strings.ToUpper(strings.TrimSpace(id))] = true
	}
	var out []Invariant
	for _, inv := range Standard(p) {
		if want[strings.ToUpper(inv.ID())] {
			out = append(out, inv)
			delete(want, strings.ToUpper(inv.ID()))
		}
	}
	unknown := make([]string, 0, len(want))
	for k := range want {
		unknown = append(unknown, k)
	}
	sort.Strings(unknown)
	return out, unknown
}

// narrate builds a non-citable assertion. It is the right constructor when the
// evidence is a control-plane observation (a sim's /state, gridsim's admin
// record) rather than bytes in the capture: bundle.Assertion.Citable() will
// report false and the bundle's verify report will say the claim rests on
// narrative, which is exactly the disclosure wanted.
func narrate(claim, method string, v Verdict, observed string) bundle.Assertion {
	return bundle.Assertion{
		Claim:    claim,
		Method:   method,
		Verdict:  v.Bundle(),
		Observed: observed,
		Note:     "control-plane observation (sim/admin API), not a wire citation",
	}
}
