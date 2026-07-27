package invariant

// monitor.go runs the invariants on a cadence while a campaign does arbitrary
// things, and turns what it sees into an evidence bundle.
//
// Four properties are load-bearing, and each of them is a lesson from a harness
// that got it wrong first:
//
//  1. A VIOLATION CARRIES THE ADVERSARY. Every [Violation] embeds the fault
//     manifest exactly as it stood at the observed instant, plus the campaign
//     seed. Without that, a P1 finding is an anecdote — nobody can reproduce it
//     and nobody can shrink it.
//
//  2. A VIOLATION RECORDS WHAT WAS TRUE. Not "I1 failed": the resolved value,
//     its unit, the reference base the device declared, the rating it was
//     compared against, and which witness observed it. That is what makes the
//     shrinker possible (it can compare two violations by [Violation.Signature]
//     without parsing English) and what makes a bug report actionable.
//
//  3. A RUN THAT ASSERTED NOTHING IS NOT A PASS. [Monitor.Finalize] refuses to
//     report success when the campaign armed no faults, or when every invariant
//     skipped. That is gw-mayhem's FI-01 defect, fixed in wave 1 there and
//     structurally prevented here.
//
//  4. AN UNDECIDED CLAIM IS RESOLVED, NOT DROPPED. I2, I9 and I10 report
//     [Pending] rather than inventing deadlines the product never promised.
//     Finalize turns any claim still pending at the end of the run into a FAIL,
//     because "the run ended and it never resolved" is the falsification.
//
// The Monitor never drives the DUT. It observes, checks, records. The campaign
// arms faults through [FaultManifest] and records its attempts through
// [Ledger]; both are held by the campaign and only read here.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"csip-tls-test/internal/evidence/bundle"
)

// Violation is one invariant failing, with everything needed to reproduce it.
type Violation struct {
	// ID is the invariant, e.g. "I1".
	ID string `json:"id"`
	// Statement is the claim that was falsified, verbatim, so a reader of the
	// bundle does not have to go find it.
	Statement string `json:"statement"`
	// Grounding names the defect class the invariant exists to catch.
	Grounding string `json:"grounding,omitempty"`
	// Verdict is Fail or Warn (a Pending resolved into a Fail at the end of the
	// run is recorded as Fail with Resolved set).
	Verdict Verdict `json:"verdict"`
	// At is when the observation the verdict rests on was taken.
	At time.Time `json:"at"`
	// Tick is the monitor tick number.
	Tick int `json:"tick"`
	// Reason is the one-sentence finding.
	Reason string `json:"reason"`
	// Facts are the structured record of what was true.
	Facts []Fact `json:"facts"`
	// Faults is the manifest as it stood at At — the adversary in force.
	Faults ManifestSnapshot `json:"faults"`
	// Assertions are the citable claims for the bundle.
	Assertions []bundle.Assertion `json:"assertions,omitempty"`
	// Resolved marks a violation produced by Finalize from a claim that was
	// still Pending when the run ended, and says so.
	Resolved string `json:"resolved,omitempty"`
}

// Signature is a stable fingerprint of WHAT went wrong, deliberately excluding
// timestamps and tick numbers. Two runs that hit the same defect produce the
// same signature, which is what lets a shrinker decide whether a reduced fault
// set still reproduces the original finding.
func (v Violation) Signature() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n", v.ID)
	keys := make([]string, 0, len(v.Facts))
	byKey := make(map[string]string, len(v.Facts))
	for _, f := range v.Facts {
		// Values that are timestamps or elapsed times are excluded: the same
		// defect at a different second is the same defect.
		if strings.HasSuffix(f.Key, "_at") || f.Unit == "s" {
			continue
		}
		keys = append(keys, f.Key)
		byKey[f.Key] = f.Value + "\x00" + f.Unit
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, byKey[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// String renders the violation the way the console should print it: the finding,
// then the adversary that produced it, then the facts.
func (v Violation) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s [%s] tick %d\n", v.Verdict, v.ID, v.Signature(), v.Tick)
	fmt.Fprintf(&b, "  claim   : %s\n", v.Statement)
	fmt.Fprintf(&b, "  finding : %s\n", v.Reason)
	if v.Resolved != "" {
		fmt.Fprintf(&b, "  resolved: %s\n", v.Resolved)
	}
	fmt.Fprintf(&b, "  adversary: %s\n", indentLines(v.Faults.String(), "    "))
	for _, f := range v.Facts {
		unit := ""
		if f.Unit != "" {
			unit = " " + f.Unit
		}
		src := ""
		if f.Source != "" {
			src = "   (" + f.Source + ")"
		}
		fmt.Fprintf(&b, "    %-44s = %s%s%s\n", f.Key, f.Value, unit, src)
	}
	return b.String()
}

func indentLines(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i := 1; i < len(lines); i++ {
		lines[i] = pad + strings.TrimLeft(lines[i], " ")
	}
	return strings.Join(lines, "\n")
}

// TickResult is one pass over every invariant.
type TickResult struct {
	Tick int               `json:"tick"`
	At   time.Time         `json:"at"`
	Took time.Duration     `json:"took_ns"`
	By   map[string]Result `json:"by"`
	// New holds only the violations whose signature was not seen before, so a
	// console watching a long campaign reports each distinct finding once
	// rather than once per cadence.
	New  []Violation       `json:"new_violations,omitempty"`
	Obs  *Observation      `json:"-"`
	Errs map[string]string `json:"errs,omitempty"`
}

// Worst returns the most severe verdict in the tick.
func (t TickResult) Worst() Verdict {
	worst := Skip
	for _, r := range t.By {
		worst = Worse(worst, r.Verdict)
	}
	return worst
}

// Logger is the logging surface a Monitor writes to. *log.Logger satisfies it.
type Logger interface {
	Printf(format string, v ...any)
}

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}

// Monitor runs invariants against a World on a cadence.
type Monitor struct {
	world   *World
	checks  []Invariant
	cadence time.Duration
	log     Logger

	mu         sync.Mutex
	ticks      []TickResult
	violations []Violation
	bySig      map[string]int
	pending    map[string]Result // invariant ID -> last Pending result
	pendingAt  map[string]TickResult
	started    time.Time
	finished   time.Time
	tick       int
}

// MonitorConfig configures a Monitor.
type MonitorConfig struct {
	// World is the observable state. Required.
	World *World
	// Checks are the invariants to run. Nil means Standard(World.Params()).
	Checks []Invariant
	// Cadence is the interval between ticks. Zero means 10s, which is roughly
	// the DUT's own southbound poll period — checking much faster than the
	// device acts produces identical snapshots and no extra information.
	Cadence time.Duration
	// Log receives per-tick lines. Nil discards.
	Log Logger
}

// NewMonitor builds a Monitor.
func NewMonitor(cfg MonitorConfig) (*Monitor, error) {
	if cfg.World == nil {
		return nil, fmt.Errorf("invariant: Monitor needs a World")
	}
	checks := cfg.Checks
	if checks == nil {
		checks = Standard(cfg.World.Params())
	}
	if len(checks) == 0 {
		return nil, fmt.Errorf("invariant: Monitor needs at least one invariant")
	}
	cadence := cfg.Cadence
	if cadence <= 0 {
		cadence = 10 * time.Second
	}
	log := cfg.Log
	if log == nil {
		log = nopLogger{}
	}
	return &Monitor{
		world:     cfg.World,
		checks:    checks,
		cadence:   cadence,
		log:       log,
		bySig:     map[string]int{},
		pending:   map[string]Result{},
		pendingAt: map[string]TickResult{},
	}, nil
}

// Tick takes one observation and runs every invariant against it.
//
// A checker that returns an error, or a Result that fails [Result.Validate], is
// itself reported as a violation of a kind: the harness records it rather than
// dropping it, because a checker that silently stopped working looks exactly
// like a device that stopped misbehaving.
func (m *Monitor) Tick(ctx context.Context) (TickResult, error) {
	start := time.Now()
	m.mu.Lock()
	m.tick++
	tick := m.tick
	if m.started.IsZero() {
		m.started = start
	}
	m.mu.Unlock()

	obs, err := m.world.Observe(ctx)
	if err != nil {
		return TickResult{Tick: tick, At: start}, err
	}
	tr := TickResult{Tick: tick, At: obs.At, By: map[string]Result{}, Obs: obs, Errs: map[string]string{}}
	for k, v := range obs.Errs {
		tr.Errs[k] = v
	}

	for _, inv := range m.checks {
		res, err := inv.Check(ctx, m.world)
		if err != nil {
			res = Result{
				Verdict: Warn,
				Reason:  fmt.Sprintf("the checker itself failed: %v", err),
				Facts:   []Fact{F(inv.ID()+".checker_error", "", "monitor", "%v", err)},
			}
		} else if verr := res.Validate(inv.ID()); verr != nil {
			res = Result{
				Verdict: Warn,
				Reason:  fmt.Sprintf("the checker returned an unusable result: %v", verr),
				Facts:   []Fact{F(inv.ID()+".invalid_result", "", "monitor", "%v", verr)},
			}
		}
		tr.By[inv.ID()] = res
		m.record(inv, res, &tr, obs)
	}

	tr.Took = time.Since(start)
	m.mu.Lock()
	m.ticks = append(m.ticks, tr)
	m.mu.Unlock()

	if len(tr.New) > 0 {
		for _, v := range tr.New {
			m.log.Printf("INVARIANT %s", v.String())
		}
	} else {
		m.log.Printf("tick %d: %s (%d invariants, %s)", tick, tr.Worst(), len(tr.By), tr.Took.Round(time.Millisecond))
	}
	return tr, nil
}

// record folds one result into the monitor's state, minting a Violation for a
// Fail (and for a Warn, which is recorded but does not fail the run).
func (m *Monitor) record(inv Invariant, res Result, tr *TickResult, obs *Observation) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch res.Verdict {
	case Pending:
		m.pending[inv.ID()] = res
		m.pendingAt[inv.ID()] = *tr
		return
	case Pass, Skip:
		// A claim that was pending and has now resolved is no longer pending.
		delete(m.pending, inv.ID())
		delete(m.pendingAt, inv.ID())
		return
	}

	v := Violation{
		ID:         inv.ID(),
		Statement:  inv.Statement(),
		Grounding:  inv.Grounding(),
		Verdict:    res.Verdict,
		At:         obs.At,
		Tick:       tr.Tick,
		Reason:     res.Reason,
		Facts:      res.Facts,
		Faults:     obs.Faults,
		Assertions: res.Assertions,
	}
	sig := v.Signature()
	if _, dup := m.bySig[sig]; !dup {
		tr.New = append(tr.New, v)
	}
	m.bySig[sig]++
	m.violations = append(m.violations, v)
	delete(m.pending, inv.ID())
	delete(m.pendingAt, inv.ID())
}

// Run ticks until ctx is cancelled, then returns. A cancelled context is the
// intended stop, not a failure, so Run returns nil for it.
func (m *Monitor) Run(ctx context.Context) error {
	t := time.NewTicker(m.cadence)
	defer t.Stop()
	for {
		if _, err := m.Tick(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Violations returns every violation recorded, in order.
func (m *Monitor) Violations() []Violation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Violation, len(m.violations))
	copy(out, m.violations)
	return out
}

// Ticks returns every tick result.
func (m *Monitor) Ticks() []TickResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TickResult, len(m.ticks))
	copy(out, m.ticks)
	return out
}

// Summary is the run's verdict.
type Summary struct {
	Started  time.Time     `json:"started"`
	Finished time.Time     `json:"finished"`
	Ticks    int           `json:"ticks"`
	Elapsed  time.Duration `json:"elapsed_ns"`
	// Violations are the distinct findings, one per signature.
	Violations []Violation `json:"violations,omitempty"`
	// Repeats counts how many times each signature recurred.
	Repeats map[string]int `json:"repeats,omitempty"`
	// PerInvariant is the worst verdict each invariant reached.
	PerInvariant map[string]Verdict `json:"per_invariant"`
	// Asserted counts the sub-claims actually evaluated across the run. It is
	// the assertion floor: zero means the run proved nothing.
	Asserted int `json:"asserted"`
	// Manifest is the campaign's final fault manifest.
	Manifest ManifestSnapshot `json:"manifest"`
	// OK is the run's bottom line.
	OK bool `json:"ok"`
	// Why explains a not-OK run, or explains what a passing run actually
	// established.
	Why string `json:"why"`
}

// Finalize closes the run: it resolves every still-Pending claim into a
// violation, applies the assertion floor, and produces the bottom line.
//
// The floor has two clauses and both matter. A run whose campaign armed NOTHING
// cannot pass: it demonstrated only that an unattacked device behaves, which is
// the FI-01 defect. And a run in which every invariant SKIPped cannot pass
// either: skipping is honest, but ten honest skips are not evidence of safety.
func (m *Monitor) Finalize() Summary {
	m.mu.Lock()
	m.finished = time.Now()
	pending := make(map[string]Result, len(m.pending))
	for k, v := range m.pending {
		pending[k] = v
	}
	pendingAt := make(map[string]TickResult, len(m.pendingAt))
	for k, v := range m.pendingAt {
		pendingAt[k] = v
	}
	m.mu.Unlock()

	// Resolve pending claims: the run ended and they never resolved.
	for _, inv := range m.checks {
		res, ok := pending[inv.ID()]
		if !ok {
			continue
		}
		at := pendingAt[inv.ID()]
		v := Violation{
			ID:         inv.ID(),
			Statement:  inv.Statement(),
			Grounding:  inv.Grounding(),
			Verdict:    Fail,
			At:         at.At,
			Tick:       at.Tick,
			Reason:     res.Reason,
			Facts:      res.Facts,
			Assertions: res.Assertions,
			Resolved: "the claim was still undecided when the run ended; an outstanding claim that never " +
				"resolved is a failure, and no promptness threshold had to be invented to say so",
		}
		if at.Obs != nil {
			v.Faults = at.Obs.Faults
		}
		m.mu.Lock()
		m.violations = append(m.violations, v)
		m.bySig[v.Signature()]++
		m.mu.Unlock()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sum := Summary{
		Started:      m.started,
		Finished:     m.finished,
		Ticks:        len(m.ticks),
		Repeats:      map[string]int{},
		PerInvariant: map[string]Verdict{},
	}
	if !m.started.IsZero() {
		sum.Elapsed = m.finished.Sub(m.started)
	}
	for _, inv := range m.checks {
		sum.PerInvariant[inv.ID()] = Skip
	}
	for _, t := range m.ticks {
		for id, r := range t.By {
			sum.PerInvariant[id] = Worse(sum.PerInvariant[id], r.Verdict)
			sum.Asserted += r.Checked
		}
	}
	seen := map[string]bool{}
	for _, v := range m.violations {
		sig := v.Signature()
		sum.Repeats[sig] = m.bySig[sig]
		if !seen[sig] {
			seen[sig] = true
			sum.Violations = append(sum.Violations, v)
		}
		if v.Verdict == Fail {
			sum.PerInvariant[v.ID] = Fail
		}
	}
	sort.Slice(sum.Violations, func(i, j int) bool {
		if sum.Violations[i].ID != sum.Violations[j].ID {
			return sum.Violations[i].ID < sum.Violations[j].ID
		}
		return sum.Violations[i].At.Before(sum.Violations[j].At)
	})
	if len(m.ticks) > 0 && m.ticks[len(m.ticks)-1].Obs != nil {
		sum.Manifest = m.ticks[len(m.ticks)-1].Obs.Faults
	}

	failed := 0
	for _, v := range sum.Violations {
		if v.Verdict == Fail {
			failed++
		}
	}
	switch {
	case len(m.ticks) == 0:
		sum.OK, sum.Why = false, "the monitor never ran a tick, so nothing was checked"
	case failed > 0:
		sum.OK = false
		sum.Why = fmt.Sprintf("%d distinct invariant violations (every one a P1)", failed)
	case !sum.Manifest.AnyArmed() && m.world.Ledger().Empty():
		sum.OK = false
		sum.Why = "the campaign armed no fault and attempted no attack, so this run demonstrated only that an " +
			"unattacked device behaves — that is not a pass"
	case sum.Asserted == 0:
		sum.OK = false
		sum.Why = "every invariant skipped: nothing was asserted, so nothing was proved"
	default:
		sum.OK = true
		sum.Why = fmt.Sprintf("%d sub-claims asserted across %d ticks against %d armed faults, with no violation",
			sum.Asserted, len(m.ticks), len(sum.Manifest.Faults))
	}
	return sum
}

// Cases renders the run as evidence-bundle test cases, one per invariant, so a
// campaign's findings land in the same bundle format the conformance runner
// produces and bundle.Verify can check.
//
// Each case's assertions are the invariant's own, plus a synthesised assertion
// carrying the fault manifest — because a bundle reader who cannot see what the
// adversary was doing cannot evaluate the verdict.
func (m *Monitor) Cases(sum Summary) []bundle.TestCaseResult {
	byID := map[string][]bundle.Assertion{}
	for _, v := range sum.Violations {
		byID[v.ID] = append(byID[v.ID], v.Assertions...)
		byID[v.ID] = append(byID[v.ID], bundle.Assertion{
			Claim:    "the violation is recorded with the adversary that produced it",
			Method:   "fault manifest snapshotted at the observed instant, with the campaign seed",
			Verdict:  v.Verdict.Bundle(),
			Observed: v.Faults.String(),
			Note:     "signature " + v.Signature(),
		})
	}
	out := make([]bundle.TestCaseResult, 0, len(m.checks))
	for _, inv := range m.checks {
		verdict := sum.PerInvariant[inv.ID()]
		tc := bundle.TestCaseResult{
			ID:      inv.ID(),
			Doc:     "lexa-gw docs/ADVERSARIAL_QA_STRATEGY.md §2",
			Title:   inv.Statement(),
			Verdict: verdict.Bundle(),
			Notes:   "grounded in: " + inv.Grounding(),
		}
		tc.Assertions = byID[inv.ID()]
		if len(tc.Assertions) == 0 {
			tc.Assertions = []bundle.Assertion{{
				Claim:    inv.Statement(),
				Method:   "continuous evaluation against externally-observable state on the monitor's cadence",
				Verdict:  verdict.Bundle(),
				Observed: m.observedFor(inv.ID(), verdict),
			}}
		}
		out = append(out, tc)
	}
	return out
}

// observedFor renders the run-level observation for an invariant that produced
// no violation, so a SKIP in the bundle always carries its reason.
func (m *Monitor) observedFor(id string, verdict Verdict) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	checked := 0
	reason := ""
	for _, t := range m.ticks {
		r, ok := t.By[id]
		if !ok {
			continue
		}
		checked += r.Checked
		if r.Reason != "" {
			reason = r.Reason
		}
	}
	switch verdict {
	case Pass:
		return fmt.Sprintf("%d sub-claims asserted across %d ticks; the property held throughout", checked, len(m.ticks))
	case Skip:
		if reason == "" {
			reason = "not assertable from what this run could observe"
		}
		return "not asserted: " + reason
	default:
		return reason
	}
}

// Emit adds the run's invariant cases to an evidence-bundle builder and writes
// the campaign's fault manifest alongside them as a JSON artefact.
//
// The manifest file is not decoration. A bundle whose cases say "I1 FAIL" with
// no record of what the adversary was doing is not reproducible evidence, and
// the whole point of writing findings into the same bundle format the
// conformance runner uses is that a reader six months later can re-derive them.
// dir is the bundle directory the builder will be written to.
func (m *Monitor) Emit(b *bundle.Builder, sum Summary, dir string) error {
	for _, tc := range m.Cases(sum) {
		b.AddCase(tc)
	}
	payload := struct {
		Schema   string           `json:"schema"`
		Summary  Summary          `json:"summary"`
		Manifest ManifestSnapshot `json:"manifest"`
	}{Schema: "lexa-invariant-run/1", Summary: sum, Manifest: sum.Manifest}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("invariant: encode the run record: %w", err)
	}
	path := filepath.Join(dir, InvariantRunFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("invariant: create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("invariant: write %s: %w", path, err)
	}
	b.AddFile(path)
	return nil
}

// InvariantRunFile is the name of the run record Emit writes into a bundle
// directory: the summary, the resolved violations, and the fault manifest that
// produced them.
const InvariantRunFile = "invariants.json"
