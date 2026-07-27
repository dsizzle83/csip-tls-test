package invariant

// monitor_test.go covers the properties the Monitor exists to guarantee, as
// opposed to the properties the invariants check.
//
// Three of them are honesty rules, and each has a test that would fail if the
// rule were quietly relaxed: a run that armed nothing cannot pass, a run whose
// invariants all skipped cannot pass, and a claim left undecided at the end of
// the run becomes a failure rather than disappearing.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/bundle"
	"lexa-proto/sunspec"
)

// alwaysPass is a stub invariant that asserts one sub-claim and passes.
type alwaysPass struct{ id string }

func (a alwaysPass) ID() string        { return a.id }
func (a alwaysPass) Statement() string { return "a stub that always passes, asserting one sub-claim" }
func (a alwaysPass) Grounding() string { return "nothing; it is a stub" }
func (a alwaysPass) Check(context.Context, *World) (Result, error) {
	return Result{Verdict: Pass, Checked: 1}, nil
}

// alwaysSkip asserts nothing.
type alwaysSkip struct{ id string }

func (a alwaysSkip) ID() string        { return a.id }
func (a alwaysSkip) Statement() string { return "a stub that always skips" }
func (a alwaysSkip) Grounding() string { return "nothing; it is a stub" }
func (a alwaysSkip) Check(context.Context, *World) (Result, error) {
	return skipf("this stub never asserts anything"), nil
}

// dishonest returns a PASS having asserted nothing, which Result.Validate must
// refuse.
type dishonest struct{}

func (dishonest) ID() string        { return "IX" }
func (dishonest) Statement() string { return "a stub that claims a pass it did not earn" }
func (dishonest) Grounding() string { return "nothing; it is a stub" }
func (dishonest) Check(context.Context, *World) (Result, error) {
	return Result{Verdict: Pass, Checked: 0}, nil
}

func emptyWorld(t *testing.T, faults *FaultManifest) *World {
	t.Helper()
	src := Sources{DERs: map[string]DERSource{
		"inv": &scriptedDER{name: "inv", views: []DERView{{Reachable: true, Unit: unitFixture(1, nil)}}},
	}}
	return NewWorld(src, faults, nil, DefaultParams())
}

// TestMonitor_ARunThatArmedNothingIsNotAPass is gw-mayhem's FI-01, made
// structurally impossible here.
func TestMonitor_ARunThatArmedNothingIsNotAPass(t *testing.T) {
	t.Parallel()
	w := emptyWorld(t, NewManifest("no-faults", 1))
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{alwaysPass{"I1"}}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	if _, err := m.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	sum := m.Finalize()
	if sum.OK {
		t.Fatal("a run that armed no fault and attempted no attack reported OK")
	}
	if !strings.Contains(sum.Why, "armed no fault") {
		t.Fatalf("the refusal does not say why: %q", sum.Why)
	}
}

// TestMonitor_AllSkipsIsNotAPass covers the other half of the floor.
func TestMonitor_AllSkipsIsNotAPass(t *testing.T) {
	t.Parallel()
	faults := NewManifest("some-faults", 42)
	faults.Arm(Fault{Kind: "outage", Class: ClassCommLoss, Target: "inv"})
	w := emptyWorld(t, faults)
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{alwaysSkip{"I1"}, alwaysSkip{"I2"}}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	if _, err := m.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	sum := m.Finalize()
	if sum.OK {
		t.Fatal("a run in which every invariant skipped reported OK")
	}
	if !strings.Contains(sum.Why, "skipped") {
		t.Fatalf("the refusal does not say why: %q", sum.Why)
	}
}

func TestMonitor_AnArmedRunWithRealAssertionsPasses(t *testing.T) {
	t.Parallel()
	faults := NewManifest("armed", 7)
	faults.Arm(Fault{Kind: "stale_values", Class: ClassPeerLie, Target: "inv"})
	w := emptyWorld(t, faults)
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{alwaysPass{"I1"}}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := m.Tick(context.Background()); err != nil {
			t.Fatalf("tick: %v", err)
		}
	}
	sum := m.Finalize()
	if !sum.OK {
		t.Fatalf("a properly armed, properly asserted run was rejected: %s", sum.Why)
	}
	if sum.Asserted != 3 {
		t.Fatalf("Asserted = %d, want 3 (one sub-claim per tick)", sum.Asserted)
	}
}

// TestMonitor_RejectsAnUnearnedPass proves the validator runs on every result,
// so a checker cannot report a pass it did not assert.
func TestMonitor_RejectsAnUnearnedPass(t *testing.T) {
	t.Parallel()
	faults := NewManifest("armed", 7)
	faults.Arm(Fault{Kind: "outage", Class: ClassCommLoss, Target: "inv"})
	w := emptyWorld(t, faults)
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{dishonest{}}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	tr, err := m.Tick(context.Background())
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	got := tr.By["IX"]
	if got.Verdict != Warn || !strings.Contains(got.Reason, "unusable result") {
		t.Fatalf("an unearned PASS was accepted: %+v", got)
	}
}

// TestMonitor_ViolationCarriesTheAdversaryAndTheFacts is requirement 3: a
// violation must record what was true, with the fault manifest in force.
func TestMonitor_ViolationCarriesTheAdversaryAndTheFacts(t *testing.T) {
	t.Parallel()
	faults := NewManifest("units-campaign", 8134297)
	faults.Arm(Fault{ID: "he.clock#1", Kind: "clock", Class: ClassClockWarp, Target: "head-end",
		Params: map[string]string{"offset_s": "-3600"}})
	faults.Arm(Fault{ID: "inv.stale#1", Kind: "stale_values", Class: ClassPeerLie, Target: "inv"})

	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 2_000, 2_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("VarSetEna", 1)
			v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_WMaxPct)
			v.SetFloat("VarSetPct", 80)
		}),
	})
	src := Sources{DERs: map[string]DERSource{
		"inv": &scriptedDER{name: "inv", views: []DERView{derFixture("inv", uv)}},
	}}
	w := NewWorld(src, faults, nil, DefaultParams())
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{NewI1(DefaultParams())}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	tr, err := m.Tick(context.Background())
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(tr.New) != 1 {
		t.Fatalf("want exactly one new violation, got %d", len(tr.New))
	}
	v := tr.New[0]
	if v.Faults.Seed != 8134297 {
		t.Fatalf("the violation does not carry the campaign seed: %d", v.Faults.Seed)
	}
	if len(v.Faults.Active(v.At)) != 2 {
		t.Fatalf("the violation does not carry the two faults in force: %+v", v.Faults.Faults)
	}
	if v.Statement == "" || v.Grounding == "" {
		t.Fatal("the violation does not carry the claim it falsified or its grounding defect")
	}
	// The facts must contain the resolved value WITH its unit — a record that
	// drops the unit reproduces the defect it is reporting.
	found := false
	for _, f := range v.Facts {
		if f.Key == "der.inv.VarSetPct.physical" && f.Unit == "var" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the violation does not record the resolved value in vars: %+v", v.Facts)
	}
	rendered := v.String()
	for _, want := range []string{"seed=8134297", "clock-warp", "der.inv.VarSetPct.physical"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("the printed violation omits %q:\n%s", want, rendered)
		}
	}

	// Repeating the same violation must not multiply the finding.
	if _, err := m.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	sum := m.Finalize()
	if len(sum.Violations) != 1 {
		t.Fatalf("the same violation was reported %d times; the signature should have deduplicated it", len(sum.Violations))
	}
	if sum.Repeats[sum.Violations[0].Signature()] != 2 {
		t.Fatalf("the repeat count is wrong: %+v", sum.Repeats)
	}
}

// TestMonitor_EmitsBundleCases checks the evidence emission: every invariant
// gets a case, and a SKIP always carries its reason.
func TestMonitor_EmitsBundleCases(t *testing.T) {
	t.Parallel()
	faults := NewManifest("armed", 3)
	faults.Arm(Fault{Kind: "outage", Class: ClassCommLoss, Target: "inv"})
	w := emptyWorld(t, faults)
	checks := []Invariant{alwaysPass{"I1"}, alwaysSkip{"I2"}}
	m, err := NewMonitor(MonitorConfig{World: w, Checks: checks, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	if _, err := m.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	cases := m.Cases(m.Finalize())
	if len(cases) != 2 {
		t.Fatalf("want a bundle case per invariant, got %d", len(cases))
	}
	byID := map[string]bundle.TestCaseResult{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	if byID["I1"].Verdict != bundle.Pass {
		t.Fatalf("I1 case verdict = %s, want PASS", byID["I1"].Verdict)
	}
	skip := byID["I2"]
	if skip.Verdict != bundle.Skip {
		t.Fatalf("I2 case verdict = %s, want SKIP", skip.Verdict)
	}
	if len(skip.Assertions) == 0 || !strings.Contains(skip.Assertions[0].Observed, "never asserts") {
		t.Fatalf("the SKIP case does not carry its reason: %+v", skip.Assertions)
	}
	if !strings.Contains(byID["I1"].Notes, "grounded in") {
		t.Fatalf("the case does not name the grounding defect: %q", byID["I1"].Notes)
	}
}

// TestVerdict_PendingMapsToSkipInTheBundle locks the mapping, since a Pending
// that leaked into the bundle as a PASS would be a lie.
func TestVerdict_PendingMapsToSkipInTheBundle(t *testing.T) {
	t.Parallel()
	if Pending.Bundle() != bundle.Skip {
		t.Fatalf("Pending maps to %s in the bundle, want SKIP", Pending.Bundle())
	}
	if Pending.Severity() <= Warn.Severity() || Pending.Severity() >= Fail.Severity() {
		t.Fatal("Pending must sort between Warn and Fail")
	}
}

// TestStandard_HasAllTenAndTheyAreDistinct guards against a copy-paste that
// registers the same invariant twice, which would silently drop one of I1–I10.
func TestStandard_HasAllTenAndTheyAreDistinct(t *testing.T) {
	t.Parallel()
	all := Standard(DefaultParams())
	if len(all) != 10 {
		t.Fatalf("Standard returned %d invariants, want 10", len(all))
	}
	seen := map[string]bool{}
	for i, inv := range all {
		want := "I" + itoa(i+1)
		if inv.ID() != want {
			t.Fatalf("Standard[%d].ID() = %q, want %q", i, inv.ID(), want)
		}
		if seen[inv.ID()] {
			t.Fatalf("duplicate invariant %s", inv.ID())
		}
		seen[inv.ID()] = true
		if inv.Statement() == "" {
			t.Fatalf("%s has no statement", inv.ID())
		}
		if inv.Grounding() == "" {
			t.Fatalf("%s does not name its grounding defect", inv.ID())
		}
	}
	// Every partial invariant must SAY it is partial, in the statement itself.
	for _, id := range []string{"I1", "I2", "I3", "I4", "I6", "I7", "I8", "I9", "I10"} {
		inv, _ := ByID(id, DefaultParams())
		s := inv.Statement()
		if !strings.Contains(s, "PARTIAL") && !strings.Contains(s, "NO PROMPTNESS") && !strings.Contains(s, "COVERAGE") {
			t.Fatalf("%s checks less than its ideal form but its statement does not say so:\n%s", id, s)
		}
	}
}

func TestSelect_ReportsUnknownIDs(t *testing.T) {
	t.Parallel()
	got, unknown := Select([]string{"I1", "I11", "i3"}, DefaultParams())
	if len(got) != 2 || got[0].ID() != "I1" || got[1].ID() != "I3" {
		t.Fatalf("Select returned %v", ids(got))
	}
	if len(unknown) != 1 || unknown[0] != "I11" {
		t.Fatalf("Select did not report the unknown id: %v", unknown)
	}
}

func ids(invs []Invariant) []string {
	out := make([]string, 0, len(invs))
	for _, i := range invs {
		out = append(out, i.ID())
	}
	return out
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// TestMonitor_EmitWritesTheAdversaryAlongsideTheCases proves the bundle carries
// enough to reproduce a finding, not just the finding.
func TestMonitor_EmitWritesTheAdversaryAlongsideTheCases(t *testing.T) {
	t.Parallel()
	faults := NewManifest("emit", 4242)
	faults.Arm(Fault{ID: "inv.stale#1", Kind: "stale_values", Class: ClassPeerLie, Target: "inv"})
	w := emptyWorld(t, faults)
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{alwaysPass{"I1"}}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	if _, err := m.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	dir := t.TempDir()
	b := bundle.NewBuilder(bundle.RunMeta{Tool: "invariant-test", Started: time.Now(), Finished: time.Now()})
	if err := m.Emit(b, m.Finalize(), dir); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(b.Cases()) != 1 {
		t.Fatalf("Emit added %d cases, want 1", len(b.Cases()))
	}
	raw, err := os.ReadFile(filepath.Join(dir, InvariantRunFile))
	if err != nil {
		t.Fatalf("read the run record: %v", err)
	}
	for _, want := range []string{`"seed": 4242`, "stale_values", "lexa-invariant-run/1"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("the run record omits %q:\n%s", want, raw)
		}
	}
}
