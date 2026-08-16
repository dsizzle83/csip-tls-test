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
	// Key is the checker's own statement of WHAT MAKES TWO VIOLATIONS THE SAME
	// VIOLATION — e.g. "accepted:ReadOnlySunSpec:1:WMaxLimPct". It is optional,
	// and when it is absent [Violation.Signature] falls back to hashing the
	// facts.
	//
	// It exists because the fallback is not always right, and the first teeth
	// run demonstrated how. I4 caught one defect — a read-only credential whose
	// write was accepted — and reported it as TWO distinct findings, because on
	// the first tick the commanded value was still visible at the DER (adding
	// four corroborating facts) and on a later tick a reboot_forget fault had
	// wiped it (removing them). Same defect, same credential, same register;
	// different fact set, therefore different hash, therefore two signatures —
	// and the shrinker dutifully spent two full budgets chasing one bug.
	//
	// Corroboration that comes and goes as the campaign perturbs the world is
	// the NORMAL case, not an edge case, so a checker whose violation has a
	// stable identity should say what it is rather than let the hash guess.
	//
	// IW15-031 made that "should" a MUST for I1–I10. Leaving nine of the ten on
	// the fallback cost more than duplicate tickets: a fact list containing a
	// wall-clock instant re-hashes on every monitor tick, so one I3 finding at
	// SEED=4242 was reported as four distinct violations AND could never be
	// re-identified on a re-run — which made the shrinker declare its own
	// deterministic finding non-deterministic. Every standard invariant now
	// names its Key with [keyer]; see that type for the naming convention.
	//
	// Key is the FIRST identity noted at the check's worst verdict. When one
	// check falsified its claim about several different things at once, the rest
	// are in Keys and Key is simply Keys[0].
	Key string `json:"key,omitempty"`
	// Keys is EVERY identity this check reported at this instant, Key first.
	//
	// It exists because one Check call is not one finding. A tick that observes
	// two devices over their nameplates, two credentials whose writes were
	// accepted, or two mRIDs applied in part has found TWO defects, and IW15-032
	// caught the harness reporting one: [keyer] kept the first identity offered
	// at the worst verdict and discarded every later one, so the second defect
	// left no signature, was never counted, and could never be shrunk to its own
	// minimal reproducer. That is the exact inverse of the defect IW15-031 fixed
	// and it is no less serious — a run that found three violations and reported
	// one has hidden two P1s inside a ticket somebody will close.
	//
	// [Monitor.record] mints one [Violation] per entry, so the run's distinct-
	// violation count is the count of distinct findings. The three traps in
	// [keyer] apply to every entry: a list whose members differ only by an
	// observed magnitude or an instant is the over-report defect wearing the
	// other hat.
	Keys []string `json:"keys,omitempty"`
}

// identities returns the violation identities this result carries, in the order
// the check noted them, and is what turns one Result into the right NUMBER of
// violations. The empty string means "no identity was named": the caller mints
// a single violation and [Violation.Signature] falls back to hashing the facts.
func (r Result) identities() []string {
	switch {
	case len(r.Keys) > 0:
		return r.Keys
	case r.Key != "":
		return []string{r.Key}
	default:
		return []string{""}
	}
}

// keyer accumulates a violation identity across the several arms of one check.
//
// # The convention every invariant follows
//
//	<arm>:<identity field>:<identity field>…
//
// The arm name says WHICH claim was falsified — an invariant that checks three
// different things must not report them under one identity — and the fields
// name the thing it was falsified ABOUT: a witness label, a register point, a
// credential, a file path, an mRID, a fault's target and kind.
//
// What must NEVER go in a key is anything a chaos campaign moves underneath it,
// because the key's whole job is to survive that. Three traps, all of them live
// in this package:
//
//   - OBSERVED MAGNITUDES and counters. They are the corroboration that comes
//     and goes; that is what drove IW15-031's fallback off the rails.
//   - TIMESTAMPS AND ELAPSED TIMES. "The same defect one tick later" is the
//     same defect.
//   - LEDGER SEQUENCE NUMBERS and [Fault.ID]. Both look stable and are not:
//     Ledger.seq is assigned in the order the campaign's per-action goroutines
//     happen to reach it, and Fault.ID embeds the arm-order index
//     (`target.kind#n`). Re-run the same seed, or shrink to a subset, and both
//     renumber — so a key built from either stops matching exactly when the
//     shrinker needs it to match. Use the credential/target/kind instead.
//
// # Why the WORST verdict's key wins
//
// A check whose Warn arm fires first and whose Fail arm fires second reports
// verdict Fail, and its identity must be the Fail's. First-wins-overall would
// file the P1 under the caveat's name, and two runs that reached the same P1 by
// different Warn routes would look like different findings. A worse verdict
// therefore DISPLACES every identity noted at a lesser one: the violation the
// harness mints carries a single verdict, and filing a WARN's identity under a
// FAIL verdict would misdescribe it.
//
// # Why a check may note SEVERAL identities, and why it must
//
// Until IW15-032 the first offer at the worst verdict won OUTRIGHT and every
// later one was dropped. That is correct only if a Check call can find at most
// one thing — and none of these can. I1 loops over witnesses × registers, I4
// over credentials, I6 over witnesses, I9 over faults, I10 over controls, I3
// over (refused write × witness). Two devices over their nameplates in the same
// tick is two defects; the harness recorded one, spent one shrink budget on it,
// and printed "1 distinct invariant violation" over a fact list that plainly
// described two. The dropped finding was not even a duplicate ticket: it had no
// signature at all, so no re-run could match it and no shrink could reduce it.
//
// So identities ACCUMULATE, de-duplicated, in the order they were noted, and
// the Monitor mints one violation per identity. The two directions are one
// property and neither may be traded for the other:
//
//	COLLAPSE   the same finding on tick 1 and tick 40 is ONE finding. That is
//	           what keeps timestamps, magnitudes and renumbering ids out of a
//	           key (IW15-031).
//	SEPARATE   two different findings in ONE tick are TWO findings. That is what
//	           requires every discriminating field — the witness, the register,
//	           the credential, the mRID, the fault target — to be IN the key
//	           (IW15-032).
//
// A key built from too little merges real defects; a key built from too much
// splits one defect into a stream. [TestViolationIdentityCollapsesAndSeparates]
// pins both at once, per invariant, because fixing either alone re-breaks the
// other.
type keyer struct {
	// res, when set, receives the identity the instant it is noted. Writing
	// through rather than at the end of the check is deliberate: a finalising
	// step is a step somebody adds a `return` in front of, and the first draft
	// of this helper lost every key it computed to exactly that — a deferred
	// stamp cannot reach an unnamed return value.
	res  *Result
	keys []string
	seen map[string]bool
	at   Verdict
}

// keysOf returns a keyer that stamps res.Key/res.Keys as identities are noted.
func keysOf(res *Result) *keyer { return &keyer{res: res} }

// note offers an identity for a violation reached at verdict v.
//
// Identities offered at the worst verdict seen are all kept, in order, without
// duplicates; an offer at a lesser verdict is ignored, and an offer at a worse
// one discards what came before. See [keyer] for why it is both of those things
// at once.
func (k *keyer) note(v Verdict, format string, args ...any) {
	switch {
	case len(k.keys) == 0:
		k.at = v
	case v.Severity() < k.at.Severity():
		return
	case v.Severity() > k.at.Severity():
		k.keys, k.seen, k.at = nil, nil, v
	}
	key := fmt.Sprintf(format, args...)
	if k.seen[key] {
		return
	}
	if k.seen == nil {
		k.seen = map[string]bool{}
	}
	k.seen[key] = true
	k.keys = append(k.keys, key)
	if k.res != nil {
		k.res.Key = k.keys[0]
		k.res.Keys = append(k.res.Keys[:0:0], k.keys...)
	}
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
