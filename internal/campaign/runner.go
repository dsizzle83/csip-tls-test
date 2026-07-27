package campaign

// runner.go executes a [Plan] against a live [invariant.World] while the
// monitor checks every invariant throughout, and produces the run's verdict.
//
// # The shape of a run
//
//	t=0            a BASELINE tick, before anything is armed
//	[0, window)    the scheduled events fire; the monitor ticks on its cadence
//	window-tail    every fault has cleared by here (the scheduler reserves it)
//	[.., window]   RECOVERY ticks: the same monitor, nothing armed
//	end            teardown (idempotent), Finalize, verdict
//
// The baseline tick earns its place. An invariant that was ALREADY failing
// before the adversary did anything is not this campaign's finding, and
// [Result.Baseline] records the pre-attack verdict so a reader can tell a bug
// the campaign caused from a bug it merely walked past. It is recorded rather
// than subtracted: silently discarding a pre-existing violation would hide the
// most interesting kind of finding there is.
//
// The recovery window earns its place too. I9's whole claim is that a cleared,
// recoverable fault heals without a human, and a run that ended the instant it
// stopped attacking could never observe healing — every I9 claim would be
// Pending, and Finalize would then turn each one into a FAIL. That would be an
// invariant failing because of how the harness was written, which is the worst
// kind of false positive.
//
// # Teardown is unconditional and idempotent
//
// The bench is shared. A campaign that panicked, was cancelled, or lost its
// context halfway must not leave a DER lying or a head-end in outage mode for
// the next agent. Every fault's Clear runs in the deferred teardown regardless
// of whether the scheduler already cleared it, which is why [Action.Clear] is
// specified as idempotent.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"csip-tls-test/internal/invariant"
)

// Default run shape. They are small deliberately: a campaign nobody can afford
// to run is a campaign nobody runs, and the strategy's §6 constraint is that
// the entry points have to be cheap enough to be habitual.
const (
	defaultActions  = 8
	defaultWindow   = 90 * time.Second
	defaultCadence  = 5 * time.Second
	defaultOverlap  = 0.45
	defaultShrinkTo = 24
)

// Config is a campaign's whole configuration.
type Config struct {
	// Label names the run in evidence, e.g. "hermetic-teeth".
	Label string
	// Seed drives every choice: which actions, their parameters, their timing.
	Seed int64
	// Window is the run's length, from the baseline tick to the last recovery
	// tick.
	Window time.Duration
	// Cadence is the monitor's tick interval.
	Cadence time.Duration
	// Actions is the budget: how many of the offered actions to schedule.
	Actions int
	// Require pins actions into the plan regardless of the budget or the
	// seeded draw. Each entry is matched as a SUBSTRING of an action id, so
	// "authz-probe/write-readonlysunspec" pins that probe without anyone
	// having to know its sequence number.
	//
	// It exists for one honest purpose. A run that injects a KNOWN defect and
	// asserts the suite catches it (MustViolate) is only meaningful if the
	// action that can see that defect is actually scheduled — and with a seeded
	// draw over thirty-odd offered actions, it usually is not. Leaving that to
	// luck would mean a teeth run that reported "the harness is blind" whenever
	// the dice went the other way, which trains an operator to re-roll until it
	// passes. Pinning the probe states the experiment instead.
	//
	// It is NOT for steering an ordinary campaign. A campaign whose actions
	// were chosen by hand is a test case, and the whole argument of this suite
	// is that test cases enumerate what someone thought to check.
	Require []string
	// Overlap is the fraction of the window over which faults are armed. A
	// smaller number packs them closer together and makes compound conditions
	// more likely; 1.0 spreads them out and makes the run more like a sequence
	// of independent experiments.
	Overlap float64
	// Invariants selects which of I1–I10 run. Empty means all ten.
	Invariants []string
	// Params are the operator-supplied values the invariants need and cannot
	// observe (a configured failsafe, a site export limit).
	Params invariant.Params
	// Log receives progress lines.
	Log invariant.Logger
	// MustViolate makes a run in which NOTHING was violated a failure. It is
	// the teeth switch: a campaign pointed at a deliberately non-conformant
	// peer that comes back clean has proved that the harness cannot see, and
	// must say so rather than printing a pass.
	MustViolate bool
}

func (c Config) window() time.Duration {
	if c.Window <= 0 {
		return defaultWindow
	}
	return c.Window
}

func (c Config) cadence() time.Duration {
	if c.Cadence <= 0 {
		return defaultCadence
	}
	return c.Cadence
}

func (c Config) overlap() float64 {
	if c.Overlap <= 0 || c.Overlap > 1 {
		return defaultOverlap
	}
	return c.Overlap
}

// recoveryTail is the slice of the window reserved for observing recovery after
// the last fault clears: three cadences, so an eventual-consistency claim gets
// more than one look before the run ends.
func (c Config) recoveryTail() time.Duration {
	tail := 3 * c.cadence()
	if max := c.window() / 3; tail > max {
		tail = max
	}
	return tail
}

// Normalize fills in the defaults, so a caller that built a Config by hand and
// a caller that came through the CLI run the same shape.
func (c Config) Normalize() Config {
	c.Window, c.Cadence, c.Overlap = c.window(), c.cadence(), c.overlap()
	if c.Actions <= 0 {
		c.Actions = defaultActions
	}
	if c.Params.Values == nil {
		c.Params = invariant.DefaultParams()
	}
	return c
}

// Env is everything a run needs from the outside world: the inventory to attack
// and the sources to judge from. It is a function rather than a value because
// the shrinker builds a FRESH one per attempt — a shrink that reused a world
// whose DERs had already been lied to would be measuring the residue of the
// previous attempt.
type Env struct {
	// Inventory is what the layers plan against.
	Inventory Inventory
	// Sources are the invariant World's witnesses.
	Sources invariant.Sources
	// Close releases anything the env opened. May be nil.
	Close func()
}

// EnvFunc builds a fresh Env. The shrinker calls it once per attempt.
type EnvFunc func(ctx context.Context) (Env, error)

// Result is a campaign's outcome.
type Result struct {
	// Plan is what was scheduled — the fault manifest, as data.
	Plan Plan `json:"plan"`
	// Summary is the invariant monitor's verdict.
	Summary invariant.Summary `json:"summary"`
	// Baseline is the worst invariant verdict observed BEFORE anything was
	// armed. A run whose baseline is already FAIL found a standing defect, not
	// one the campaign caused, and the report says which.
	Baseline string `json:"baseline"`
	// Armed counts the actions that armed successfully; ArmErrors records the
	// ones that did not, keyed by action id. An arm error is not a device
	// finding and must never be reported as one — but a run in which most arms
	// failed asserted far less than its manifest suggests, so it is surfaced.
	Armed     int               `json:"armed"`
	ArmErrors map[string]string `json:"arm_errors,omitempty"`
	// Elapsed is the wall time of the run.
	Elapsed time.Duration `json:"elapsed_ns"`
	// OK is the bottom line, and Why explains it.
	OK  bool   `json:"ok"`
	Why string `json:"why"`
	// Violations are the distinct findings, copied out of Summary for
	// convenience.
	Violations []invariant.Violation `json:"-"`

	monitor *invariant.Monitor
}

// Signatures returns the distinct violation signatures, sorted — the shrinker's
// target set.
func (r Result) Signatures() []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range r.Violations {
		if v.Verdict != invariant.Fail {
			continue
		}
		sig := v.Signature()
		if !seen[sig] {
			seen[sig] = true
			out = append(out, sig)
		}
	}
	sort.Strings(out)
	return out
}

// Has reports whether the run reproduced a particular violation signature.
func (r Result) Has(sig string) bool {
	for _, s := range r.Signatures() {
		if s == sig {
			return true
		}
	}
	return false
}

// Monitor exposes the run's monitor, for the caller that wants to emit the
// evidence bundle.
func (r Result) Monitor() *invariant.Monitor { return r.monitor }

// Run executes one campaign: build the env, plan, arm on schedule, monitor
// throughout, tear down, and decide.
//
// A cancelled context stops the run early and is NOT an error — the teardown
// still runs and the partial result is returned with its own honest verdict,
// because an operator who hit ^C should still get the manifest and whatever the
// monitor saw.
func Run(ctx context.Context, cfg Config, envFn EnvFunc, layers []Layer) (Result, error) {
	cfg = cfg.Normalize()
	start := time.Now()

	env, err := envFn(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("campaign: build the environment: %w", err)
	}
	if env.Close != nil {
		defer env.Close()
	}

	plan := BuildPlan(cfg, env.Inventory, layers)
	res := Result{Plan: plan, ArmErrors: map[string]string{}}

	manifest := invariant.NewManifest(cfg.Label, cfg.Seed)
	ledger := invariant.NewLedger()
	world := invariant.NewWorld(env.Sources, manifest, ledger, cfg.Params)

	checks, unknown := invariant.Select(cfg.Invariants, cfg.Params)
	if len(unknown) > 0 {
		return res, fmt.Errorf("campaign: -invariants names checks this build does not have: %v", unknown)
	}
	mon, err := invariant.NewMonitor(invariant.MonitorConfig{
		World: world, Checks: checks, Cadence: cfg.Cadence, Log: cfg.Log,
	})
	if err != nil {
		return res, fmt.Errorf("campaign: %w", err)
	}
	res.monitor = mon

	rt := &Runtime{Ledger: ledger, Faults: manifest, Log: cfg.Log, Seed: cfg.Seed}

	// Teardown is unconditional: the bench is shared and a cancelled run must
	// not leave a peer faulted. Clear is specified idempotent for exactly this.
	defer func() {
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		for _, e := range plan.Events {
			if e.action.Clear == nil {
				continue
			}
			if err := e.action.Clear(tctx, rt); err != nil {
				rt.Logf("teardown: clearing %s: %v", e.ActionID, err)
			}
		}
	}()

	// The baseline tick: what was already true before the adversary moved.
	if base, err := mon.Tick(ctx); err == nil {
		res.Baseline = string(base.Worst())
	} else {
		res.Baseline = "UNOBSERVED"
		rt.Logf("baseline tick failed: %v", err)
	}

	runCtx, stop := context.WithTimeout(ctx, cfg.Window)
	defer stop()

	var wg sync.WaitGroup
	var mu sync.Mutex

	// The monitor ticks on its own cadence for the whole window, independent of
	// what the scheduler is doing. That independence is requirement 2 of the
	// strategy: scenarios create conditions, invariants decide.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(cfg.Cadence)
		defer t.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
				if _, err := mon.Tick(ctx); err != nil {
					rt.Logf("monitor tick: %v", err)
				}
			}
		}
	}()

	// Every event gets its own goroutine, so faults genuinely overlap rather
	// than being applied in sequence by a single scheduler loop.
	for i := range plan.Events {
		e := plan.Events[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !sleepUntil(runCtx, start, e.At) {
				return
			}
			var faultID string
			if !e.Oneshot {
				faultID = manifest.Arm(e.action.fault())
			}
			if e.action.Arm != nil {
				if err := e.action.Arm(ctx, rt); err != nil {
					mu.Lock()
					res.ArmErrors[e.ActionID] = err.Error()
					mu.Unlock()
					rt.Logf("ARM-ERR %s: %v", e.ActionID, err)
					if faultID != "" {
						// The manifest must not claim a fault that never took
						// effect: a violation carrying a fault the bench
						// refused to arm would send a reader chasing a
						// condition that did not exist.
						manifest.Clear(faultID, time.Now())
					}
					return
				}
			}
			mu.Lock()
			res.Armed++
			mu.Unlock()
			rt.Logf("ARMED   %s", e.action)

			if e.Oneshot {
				return
			}
			if !sleepUntil(runCtx, start, e.Until()) {
				// The window ended before the hold did. Clear anyway — the
				// deferred teardown would too, but doing it here keeps the
				// manifest's cleared-at honest.
				manifest.Clear(faultID, time.Now())
				return
			}
			if e.action.Clear != nil {
				if err := e.action.Clear(ctx, rt); err != nil {
					rt.Logf("clear %s: %v", e.ActionID, err)
				}
			}
			manifest.Clear(faultID, time.Now())
			rt.Logf("CLEARED %s", e.ActionID)
		}()
	}

	wg.Wait()

	// Recovery ticks after the window: nothing is armed now, and this is where
	// an eventual-recovery claim gets to resolve rather than being failed for
	// having been asked too early.
	for i := 0; i < 2 && ctx.Err() == nil; i++ {
		if _, err := mon.Tick(ctx); err != nil {
			rt.Logf("recovery tick: %v", err)
		}
	}

	sum := mon.Finalize()
	res.Summary = sum
	res.Violations = sum.Violations
	res.Elapsed = time.Since(start)
	res.OK, res.Why = decide(cfg, res, sum)
	return res, nil
}

// decide is the campaign's bottom line. It defers to the monitor's own floor
// (which already refuses a run that armed nothing or asserted nothing) and adds
// the two clauses only the campaign can judge.
func decide(cfg Config, res Result, sum invariant.Summary) (bool, string) {
	violated := len(res.Signatures()) > 0
	switch {
	case cfg.MustViolate && !violated:
		return false, "this run was pointed at a deliberately non-conformant peer and found NOTHING — " +
			"the harness cannot see the defect it was aimed at, which is a failure of the harness, not a pass"
	case !sum.OK:
		return false, sum.Why
	case cfg.MustViolate:
		return true, fmt.Sprintf("teeth confirmed: %d distinct invariant violation(s) against a known-bad peer; %s",
			len(res.Signatures()), sum.Why)
	case res.Armed == 0:
		return false, "no action armed successfully, so nothing was injected — a run that injected no fault is an " +
			"error, not a pass (strategy §4.1)"
	default:
		return true, sum.Why
	}
}

// sleepUntil waits until offset from start, reporting false if the context ends
// first.
func sleepUntil(ctx context.Context, start time.Time, offset time.Duration) bool {
	d := time.Until(start.Add(offset))
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
