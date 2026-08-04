package campaign

// campaign_test.go proves the four properties the rest of this suite is
// entitled to assume, each of them a property that is easy to believe and easy
// to lose:
//
//	the plan is a PURE FUNCTION OF THE SEED — otherwise `-seed N` is not a
//	reproduction and a violation report is an anecdote;
//
//	a SUBSET keeps its survivors' timing — otherwise every shrink attempt is a
//	different experiment and a two-action interaction "stops reproducing" for
//	reasons that have nothing to do with the actions;
//
//	the SHRINKER converges on an interaction — greedy removal cannot, and the
//	whole value of the mechanism is the case it cannot handle;
//
//	the HONESTY FLOOR holds — a run that armed nothing, and a teeth run that
//	found nothing, must both fail.
//
// The world here is entirely fake and in-process: no TLS, no sockets, no
// loopback. What is under test is the ENGINE, and a test that needed a gateway
// to prove the scheduler is deterministic would be testing the gateway.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/invariant"
)

// ── a fake world ─────────────────────────────────────────────────────────────

// stubDER is the minimum a World needs to produce an Observation. It reports a
// reachable device with no registers, which is enough for the ledger-driven
// invariants (I3, I4, I5) and makes the register-driven ones SKIP — exactly the
// separation these tests want.
type stubDER struct{ name string }

func (s stubDER) Name() string { return s.name }
func (s stubDER) Observe(context.Context) (invariant.DERView, error) {
	return invariant.DERView{Name: s.name, Source: "stub", Reachable: true}, nil
}

// defectState is the fake DUT's bug: it accepts an unauthorized write, but only
// while BOTH of its trigger faults are armed.
//
// A conditional-on-two-faults defect is the shape that defeats greedy shrinking
// — remove either trigger and the violation disappears, so one-at-a-time
// removal concludes that every action is essential and gives up. It is also not
// an artificial shape: "the write path only mishandles authorization while the
// device is reconnecting AND a control is being applied" is an ordinary
// compound bug.
type defectState struct {
	mu     sync.Mutex
	armed  map[string]bool
	needed []string
}

func newDefect(needed ...string) *defectState {
	return &defectState{armed: map[string]bool{}, needed: needed}
}

func (d *defectState) arm(kind string)   { d.mu.Lock(); d.armed[kind] = true; d.mu.Unlock() }
func (d *defectState) clear(kind string) { d.mu.Lock(); d.armed[kind] = false; d.mu.Unlock() }

func (d *defectState) triggered() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, k := range d.needed {
		if !d.armed[k] {
			return false
		}
	}
	return true
}

// fakeLayer offers n plain faults plus one unauthorized-write probe.
type fakeLayer struct {
	id     string
	n      int
	defect *defectState
}

func (f fakeLayer) ID() string { return f.id }

func (f fakeLayer) Describe() string { return "a fake layer, for the engine's own tests" }

func (f fakeLayer) Plan(inv Inventory, rng *rand.Rand) []Action {
	var out []Action
	for i := 0; i < f.n; i++ {
		kind := fmt.Sprintf("fault%d", i)
		out = append(out, Action{
			Layer: f.id, Kind: kind, Target: "der", Class: invariant.ClassPeerLie,
			Recoverable: true, Why: "a fake fault",
			Arm:   func(ctx context.Context, rt *Runtime) error { f.defect.arm(kind); return nil },
			Clear: func(ctx context.Context, rt *Runtime) error { f.defect.clear(kind); return nil },
		})
	}
	if f.defect != nil {
		out = append(out, Action{
			Layer: f.id, Kind: "unauthorized-write", Target: "dut",
			Class: invariant.ClassTransportAbuse, Oneshot: true, Why: "a fake probe",
			Arm: func(ctx context.Context, rt *Runtime) error {
				rt.Ledger.NoteWrite(invariant.WriteRecord{
					Credential: "read-only", Role: "ReadOnly", Domain: "d",
					Authorized: false, Unit: 1, Model: 704, Point: "WMaxLimPct",
					Value:    invariant.Quantity{Val: 29, Unit: invariant.UnitPercent},
					Accepted: f.defect.triggered(), Refused: !f.defect.triggered(),
				})
				return nil
			},
		})
	}
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func fakeEnv() EnvFunc {
	return func(context.Context) (Env, error) {
		return Env{
			Inventory: Inventory{DERs: []DERTarget{{Name: "der"}}},
			Sources:   invariant.Sources{DERs: map[string]invariant.DERSource{"der": stubDER{"der"}}},
		}, nil
	}
}

// fastConfig is a whole campaign in under a second, so these tests can afford to
// run a shrink.
func fastConfig(label string, seed int64) Config {
	return Config{
		Label: label, Seed: seed, Window: 600 * time.Millisecond, Cadence: 60 * time.Millisecond,
		Actions: 8, Invariants: []string{"I4"}, Params: invariant.DefaultParams(),
	}
}

// ── the plan is a pure function of the seed ──────────────────────────────────

func TestPlanIsAPureFunctionOfTheSeed(t *testing.T) {
	t.Parallel()
	cfg := fastConfig("determinism", 4242)
	inv := Inventory{DERs: []DERTarget{{Name: "der"}}}
	layers := []Layer{fakeLayer{id: "fake", n: 6, defect: newDefect()}}

	a := BuildPlan(cfg, inv, layers)
	b := BuildPlan(cfg, inv, layers)
	if a.String() != b.String() {
		t.Fatalf("two BuildPlan calls with the same seed disagree.\nA:\n%s\nB:\n%s", a, b)
	}

	// And a different seed must actually produce a different plan, or the
	// "determinism" above is just a constant.
	cfg2 := cfg
	cfg2.Seed = 4243
	if c := BuildPlan(cfg2, inv, layers); c.String() == a.String() {
		t.Fatal("changing the seed did not change the plan — the seed is not driving anything")
	}
}

// TestSubsetPreservesSurvivorTiming is the property the shrinker rests on: a
// re-planned subset must place its survivors at exactly the times the full plan
// did.
//
// It is stated against a RE-PLAN, not against Plan.Subset, because that is what
// the shrinker actually does — it rebuilds the actions from the seed through
// FilterLayers, since the originals hold closures onto a world that has been
// torn down. If the two ever diverge, a shrink attempt silently becomes a
// different experiment.
func TestSubsetPreservesSurvivorTiming(t *testing.T) {
	t.Parallel()
	cfg := fastConfig("subset", 99)
	inv := Inventory{DERs: []DERTarget{{Name: "der"}}}
	layers := []Layer{fakeLayer{id: "fake", n: 6, defect: newDefect()}}

	full := BuildPlan(cfg, inv, layers)
	if len(full.Events) < 3 {
		t.Fatalf("need at least three events to subset; got %d", len(full.Events))
	}
	keep := full.ActionIDs()[:2]
	want := map[string]Event{}
	for _, e := range full.Events {
		want[e.ActionID] = e
	}

	sub := cfg
	sub.Actions = len(keep)
	keepSet := map[string]bool{keep[0]: true, keep[1]: true}
	got := BuildPlan(sub, inv, FilterLayers(layers, keepSet))

	if len(got.Events) != len(keep) {
		t.Fatalf("re-planned subset has %d events, want %d: %v", len(got.Events), len(keep), got.ActionIDs())
	}
	for _, e := range got.Events {
		w, ok := want[e.ActionID]
		if !ok {
			t.Fatalf("re-planned subset produced an action the full plan never had: %s", e.ActionID)
		}
		if e.At != w.At || e.Hold != w.Hold {
			t.Errorf("%s moved between the full plan and the subset: at %s/%s hold %s/%s — "+
				"every shrink attempt would then be a different experiment",
				e.ActionID, w.At, e.At, w.Hold, e.Hold)
		}
	}
}

// ── the honesty floor ────────────────────────────────────────────────────────

func TestARunThatArmedNothingIsNotAPass(t *testing.T) {
	t.Parallel()
	cfg := fastConfig("empty", 1)
	// A layer that offers nothing: the inventory has no target it can use.
	res, err := Run(context.Background(), cfg, fakeEnv(), []Layer{fakeLayer{id: "fake", n: 0}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK {
		t.Fatalf("a campaign that armed nothing reported a PASS: %s", res.Why)
	}
	if !strings.Contains(res.Why, "not a pass") && !strings.Contains(res.Why, "no fault") {
		t.Errorf("the failure does not say WHY an empty run is not a pass: %q", res.Why)
	}
}

func TestMustViolateFailsARunThatFoundNothing(t *testing.T) {
	t.Parallel()
	cfg := fastConfig("teeth", 5)
	cfg.MustViolate = true
	// The defect needs a fault that this layer never offers, so nothing trips.
	res, err := Run(context.Background(), cfg, fakeEnv(),
		[]Layer{fakeLayer{id: "fake", n: 3, defect: newDefect("never-armed")}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK {
		t.Fatal("a teeth run that found nothing reported a PASS — the whole point is that it cannot")
	}
	if !strings.Contains(res.Why, "harness") {
		t.Errorf("the teeth failure does not name the harness as the thing that failed: %q", res.Why)
	}
}

// TestMustViolatePassesTheRunThatFoundTheDefect is the direction the teeth gate
// never had a test for, and the reason it sat DEAD.
//
// TestMustViolateFailsARunThatFoundNothing above covers the blind case, and it
// passed throughout — a broken gate that refuses everything refuses that run
// too. Nothing asserted the other half: that a MustViolate run which CATCHES
// the injected defect reports OK. It could not, because decide() asked
// `!sum.OK` before `cfg.MustViolate`, and catching the defect is exactly what
// makes sum.OK false (invariant.Finalize marks any run with failed violations
// not-OK). So `make qa-campaign-teeth` exited non-zero precisely when the
// harness worked, and the gate could not be left switched on.
//
// Pre-fix this test reports:
//
//	a teeth run that CAUGHT the injected defect reported a FAILURE:
//	  1 distinct invariant violations (every one a P1)
//
// which is the monitor faithfully describing a successful teeth run and the
// campaign then reading it as a failure.
func TestMustViolatePassesTheRunThatFoundTheDefect(t *testing.T) {
	t.Parallel()
	cfg := fastConfig("teeth-found", 5)
	cfg.MustViolate = true
	cfg.Require = []string{"fake/unauthorized-write"}
	// No triggers needed: the probe always fires, so the run is guaranteed to
	// catch the deliberately non-conformant write.
	layers := []Layer{fakeLayer{id: "fake", n: 3, defect: newDefect()}}

	res, err := Run(context.Background(), cfg, fakeEnv(), layers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Signatures()) == 0 {
		t.Fatalf("precondition: the teeth run found nothing to confirm with: %s", res.Why)
	}
	if !res.OK {
		t.Fatalf("a teeth run that CAUGHT the injected defect reported a FAILURE:\n  %s", res.Why)
	}
	if !strings.Contains(res.Why, "teeth confirmed") {
		t.Errorf("a confirmed teeth run must say so — the operator needs to read that the harness "+
			"SAW the defect, not just that the run exited 0: %q", res.Why)
	}
	// And the underlying summary is still honestly not-OK: the run really did
	// observe violations. Only the campaign's INTERPRETATION of them differs
	// when the peer was known-bad on purpose.
	if res.Summary.OK {
		t.Error("the monitor must still report the violations it found; MustViolate changes what the " +
			"campaign concludes from them, never what the monitor observed")
	}
}

// TestMustViolateStillHonoursTheFloor pins the half of the fix that is easy to
// lose: a teeth run must not be able to pass by REPORTING violations off a run
// that proved nothing. Skipping the whole `!sum.OK` clause for MustViolate
// would have done exactly that, trading a gate that always fails for one that
// cannot fail.
//
// A zero-tick summary carrying a violation is not reachable from Run (a
// violation implies a tick), so the clause is exercised at decide() directly —
// which is also the only way to state the property without inventing a fake
// monitor that lies about its own history.
func TestMustViolateStillHonoursTheFloor(t *testing.T) {
	t.Parallel()
	res := Result{Violations: []invariant.Violation{{ID: "I4", Verdict: invariant.Fail, Reason: "a fake finding"}}}
	for _, tc := range []struct {
		name string
		sum  invariant.Summary
		want string
	}{
		{"never ticked", invariant.Summary{Ticks: 0, Asserted: 3, Attacked: true}, "never ran a tick"},
		{"armed and attacked nothing", invariant.Summary{Ticks: 4, Asserted: 3}, "armed no fault"},
		{"asserted nothing", invariant.Summary{Ticks: 4, Asserted: 0, Attacked: true}, "nothing was asserted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := decide(Config{MustViolate: true}, res, tc.sum)
			if ok {
				t.Fatalf("a teeth run that %s reported a PASS: %q", tc.name, why)
			}
			if !strings.Contains(why, tc.want) {
				t.Errorf("the refusal does not name the floor it broke (want %q): %q", tc.want, why)
			}
		})
	}
}

func TestRequirePinsAnActionPastTheBudget(t *testing.T) {
	t.Parallel()
	cfg := fastConfig("require", 12345)
	cfg.Actions = 1
	cfg.Require = []string{"fake/unauthorized-write"}
	inv := Inventory{DERs: []DERTarget{{Name: "der"}}}
	plan := BuildPlan(cfg, inv, []Layer{fakeLayer{id: "fake", n: 8, defect: newDefect()}})

	found := false
	for _, id := range plan.ActionIDs() {
		if strings.Contains(id, "unauthorized-write") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a pinned action was dropped to fit the budget: %v", plan.ActionIDs())
	}
}

// ── the shrinker ─────────────────────────────────────────────────────────────

// TestShrinkConvergesOnATwoFaultInteraction is the test that justifies ddmin
// over greedy removal.
//
// The fake defect fires only while fault0 AND fault2 are both armed, and only
// the probe can observe it. So the minimal reproducer is exactly three actions
// out of eight, and removing any one of them makes the violation vanish —
// which is precisely the case one-at-a-time removal reports as "nothing can be
// removed".
func TestShrinkConvergesOnATwoFaultInteraction(t *testing.T) {
	defect := newDefect("fault0", "fault2")
	cfg := fastConfig("shrink", 20260727)
	cfg.Actions = 8
	// Pin the three actions that matter so the seeded draw cannot leave the
	// experiment unstated; the other five are along for the ride and are what
	// the shrinker has to remove.
	cfg.Require = []string{"fake/fault0@", "fake/fault2@", "fake/unauthorized-write"}
	layers := []Layer{fakeLayer{id: "fake", n: 8, defect: defect}}

	res, err := Run(context.Background(), cfg, fakeEnv(), layers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	sigs := res.Signatures()
	if len(sigs) != 1 {
		t.Fatalf("want exactly one violation to shrink, got %d (%v): %s", len(sigs), sigs, res.Why)
	}
	if len(res.Plan.Events) < 5 {
		t.Fatalf("the run scheduled only %d actions; there is nothing to shrink", len(res.Plan.Events))
	}

	sr, err := Shrink(context.Background(), sigs[0], res, ShrinkConfig{Budget: 40, Config: cfg}, fakeEnv(), layers)
	if err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if !sr.Confirmed {
		t.Fatal("the shrink could not reproduce the violation with the FULL action set — the finding is flaky " +
			"and no minimal set can be claimed")
	}
	if len(sr.Minimal) >= len(sr.Original) {
		t.Fatalf("the shrinker removed nothing: %d -> %d (%v)", len(sr.Original), len(sr.Minimal), sr.Minimal)
	}
	for _, want := range []string{"fault0", "fault2", "unauthorized-write"} {
		if !containsSubstr(sr.Minimal, want) {
			t.Errorf("the minimal set dropped %q, which the defect needs: %v", want, sr.Minimal)
		}
	}
	if len(sr.Minimal) != 3 {
		t.Errorf("minimal set is %d actions, want exactly 3 (the two triggers and the probe): %v",
			len(sr.Minimal), sr.Minimal)
	}
	t.Logf("shrank %d actions to %d in %d attempts:\n%s", len(sr.Original), len(sr.Minimal), len(sr.Attempts), sr)
}

// TestShrinkReportsANonReproducingFindingRatherThanInventingAMinimalSet covers
// the flaky case. A finding that does not come back on re-run must be reported
// as such: presenting a two-action "minimal reproducer" derived from a run
// whose failures were random is worse than reporting nothing, because somebody
// will spend a day on it.
func TestShrinkReportsANonReproducingFinding(t *testing.T) {
	t.Parallel()
	cfg := fastConfig("flaky", 777)
	cfg.Require = []string{"fake/unauthorized-write"}
	defect := newDefect() // no triggers needed: it always fires
	layers := []Layer{fakeLayer{id: "fake", n: 4, defect: defect}}

	res, err := Run(context.Background(), cfg, fakeEnv(), layers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Signatures()) == 0 {
		t.Fatalf("expected a violation to chase: %s", res.Why)
	}

	// Chase a signature that never existed. Every attempt must fail to
	// reproduce it, and the result must say the finding did not reproduce
	// rather than hand back a confident minimum.
	sr, err := Shrink(context.Background(), "deadbeefdeadbeef", res, ShrinkConfig{Budget: 6, Config: cfg}, fakeEnv(), layers)
	if err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if sr.Confirmed {
		t.Fatal("the shrinker claimed to have confirmed a signature that no run produces")
	}
	if len(sr.Minimal) != len(sr.Original) {
		t.Errorf("an unconfirmed finding was 'shrunk' anyway: %d -> %d", len(sr.Original), len(sr.Minimal))
	}
	if !strings.Contains(sr.String(), "NOT REPRODUCED") {
		t.Errorf("the report does not warn that the finding did not reproduce:\n%s", sr)
	}
}

func containsSubstr(ids []string, want string) bool {
	for _, id := range ids {
		if strings.Contains(id, want) {
			return true
		}
	}
	return false
}
