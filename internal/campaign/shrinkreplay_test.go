package campaign

// shrinkreplay_test.go pins the half of IW15-031 that mattered most: the
// SHRINKER MUST BE ABLE TO RE-IDENTIFY A FINDING IT JUST SAW.
//
// # What went wrong
//
// [Shrink]'s step 0 re-runs the FULL action set and asks whether the target
// signature came back. If it did not, the shrink is abandoned and the report
// says the finding "is non-deterministic and no minimal set can be claimed for
// it". That is the right thing to say about a genuinely flaky finding — and it
// was being said about a finding that reproduced 6 times out of 6.
//
// The cause was not in this package at all. [invariant.Violation.Signature]
// hashed the violation's FACTS when the checker named no [invariant.Result.Key],
// and its timestamp exclusion matched only keys ending "_at" or facts carrying
// unit "s" — while I3's fact block carries `i3.write.at` and `i3.observed.at`.
// Wall-clock therefore entered the identity, so:
//
//	within one run   every monitor tick minted a NEW signature for the SAME
//	                 finding — the "4 distinct invariant violations" a SEED=4242
//	                 hermetic campaign reported for one ghost;
//	across runs      no re-run could ever produce a signature a previous run had
//	                 produced, so step 0 failed with probability 1.
//
// The shrinker was working perfectly. Its oracle was a clock.
//
// # What this test does
//
// It drives the REAL [Run] and the REAL [Shrink] over a fake world that presents
// IW15-031's exact shape — a distinctive write refused with a Modbus exception,
// and a DER whose own register image nonetheless holds the refused value — and
// asserts that the shrink CONFIRMS on re-run and converges on the probe alone.
//
// It is an IN-PROCESS REPLAY, deliberately, because that is the thing that was
// failing: the campaign at SEED=4242 reproduced 6/6 from a fresh process and
// 0/4 from the shrinker's own re-run loop, and the difference between those two
// numbers was the only evidence that the divergence was in the harness rather
// than in the device.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/invariant"

	"lexa-proto/sunspec"
)

// ghostValue is the distinctive setpoint the probe writes and the device holds.
// Unround on purpose, for the reason internal/campaign's probeValues are: a
// round number is what a scheduler default lands on, and I3 SKIPs any write the
// campaign did not mark distinctive.
const ghostValue = 63

// ghostDER is a device whose register image holds a value the DUT refused. It
// is the same shape sim/southbound's exception_on_applied_write produces on the
// bench, built by hand here so the test needs no sim, no TLS and no sockets.
type ghostDER struct{ name string }

func (g ghostDER) Name() string { return g.name }

func (g ghostDER) Observe(context.Context) (invariant.DERView, error) {
	regs := make([]uint16, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetEnum("WMaxLimPct_SF", 0)
	v.SetEnum("WMaxLimPctEna", 0) // refused, so nothing ever enabled it…
	v.SetFloat("WMaxLimPct", ghostValue)
	return invariant.DERView{
		Name: g.name, Source: "stub:" + g.name, Reachable: true, Animating: true,
		Unit: invariant.UnitView{
			Unit:   1,
			Models: []uint16{704},
			Regs:   map[uint16][]uint16{704: regs},
			Base:   map[uint16]uint16{704: 40002},
		},
	}, nil
}

// ghostLayer offers n inert faults plus the one probe that records the refused
// write. The inert faults exist so the shrinker has something to remove: a
// one-action plan would converge trivially and prove nothing about ddmin.
type ghostLayer struct {
	id string
	n  int
}

func (g ghostLayer) ID() string { return g.id }

func (g ghostLayer) Describe() string {
	return "a fake layer that records one refused distinctive write against a device that holds the " +
		"refused value, plus inert faults for the shrinker to remove"
}

func (g ghostLayer) Plan(inv Inventory, rng *rand.Rand) []Action {
	var out []Action
	for i := 0; i < g.n; i++ {
		out = append(out, Action{
			Layer: g.id, Kind: fmt.Sprintf("inert%d", i), Target: "der",
			Class: invariant.ClassCommLoss, Recoverable: true, Why: "an inert fault",
			Arm:   func(context.Context, *Runtime) error { return nil },
			Clear: func(context.Context, *Runtime) error { return nil },
		})
	}
	out = append(out, Action{
		Layer: g.id, Kind: "refused-write", Target: "dut", Class: invariant.ClassTransportAbuse,
		Oneshot: true, Why: "the write whose refusal I3 judges",
		Arm: func(ctx context.Context, rt *Runtime) error {
			rt.Ledger.NoteWrite(invariant.WriteRecord{
				Credential: "SuperAdministratorSunSpec", Role: "SuperAdministratorSunSpec",
				Authorized: true, Unit: 1, Model: 704, Point: "WMaxLimPct",
				Value:       invariant.Quantity{Val: ghostValue, Unit: invariant.UnitPercent},
				Ref:         invariant.RefWMax,
				Distinctive: true, Refused: true, ExceptionCode: 0x04,
			})
			return nil
		},
	})
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func ghostEnv() EnvFunc {
	return func(context.Context) (Env, error) {
		return Env{
			Inventory: Inventory{DERs: []DERTarget{{Name: "der"}}},
			Sources:   invariant.Sources{DERs: map[string]invariant.DERSource{"der": ghostDER{"der"}}},
		}, nil
	}
}

func ghostConfig(label string, seed int64) Config {
	return Config{
		Label: label, Seed: seed, Window: 600 * time.Millisecond, Cadence: 60 * time.Millisecond,
		Actions: 6, Invariants: []string{"I3"}, Params: invariant.DefaultParams(),
	}
}

// TestTheSameFindingHasTheSameSignatureOnEveryRerun is the property the
// shrinker's confirm step rests on, stated on its own.
//
// Pre-fix this reported two different signatures for two runs of one seed, and
// a different one again on every tick within each run.
func TestTheSameFindingHasTheSameSignatureOnEveryRerun(t *testing.T) {
	t.Parallel()
	cfg := ghostConfig("identity", 4242)
	layers := []Layer{ghostLayer{id: "ghost", n: 5}}

	var sigs [][]string
	for i := 0; i < 3; i++ {
		res, err := Run(context.Background(), cfg, ghostEnv(), layers)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		s := res.Signatures()
		if len(s) != 1 {
			t.Fatalf("run %d reported %d distinct violations for ONE ghost (%v) — a finding observed on "+
				"several ticks must collapse to one", i, len(s), s)
		}
		sigs = append(sigs, s)
	}
	for i := 1; i < len(sigs); i++ {
		if sigs[i][0] != sigs[0][0] {
			t.Fatalf("three runs of seed 4242 produced signatures %s and %s — the shrinker's confirm step "+
				"compares exactly these, so it could never reproduce anything", sigs[0][0], sigs[i][0])
		}
	}
}

// TestShrinkConfirmsAFindingWhoseFactsCarryTimestamps is the end-to-end pin:
// the real shrinker, replaying in-process, must CONFIRM and then converge.
//
// The assertions are ordered by what a reader of a shrink report reads first.
// `Confirmed` is the one that regressed; `Minimal` is what the report is for.
func TestShrinkConfirmsAFindingWhoseFactsCarryTimestamps(t *testing.T) {
	t.Parallel()
	cfg := ghostConfig("shrink-replay", 4242)
	layers := []Layer{ghostLayer{id: "ghost", n: 5}}

	res, err := Run(context.Background(), cfg, ghostEnv(), layers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	sigs := res.Signatures()
	if len(sigs) != 1 {
		t.Fatalf("precondition: want exactly one finding to shrink, got %d (%v): %s", len(sigs), sigs, res.Why)
	}
	// The finding must actually carry a wall-clock fact, or this test is
	// pinning the easy case.
	var carriesAnInstant bool
	for _, v := range res.Violations {
		for _, f := range v.Facts {
			if strings.HasSuffix(f.Key, ".at") {
				carriesAnInstant = true
			}
		}
	}
	if !carriesAnInstant {
		t.Fatal("precondition: the finding carries no timestamp fact, so it cannot pin IW15-031")
	}

	sr, err := Shrink(context.Background(), sigs[0], res,
		ShrinkConfig{Budget: 16, Config: cfg}, ghostEnv(), layers)
	if err != nil {
		t.Fatalf("Shrink: %v", err)
	}
	if !sr.Confirmed {
		t.Fatalf("the shrinker could not reproduce a deterministic finding on re-run with the FULL action "+
			"set, and would report it as non-deterministic:\n%s", sr.String())
	}
	if sr.Errored > 0 {
		t.Errorf("%d shrink attempt(s) errored; a non-reproduction from those is not evidence", sr.Errored)
	}
	if len(sr.Minimal) != 1 || !strings.Contains(sr.Minimal[0], "refused-write") {
		t.Errorf("the minimal reproducer is %v, want the single refused-write probe — the inert faults "+
			"contribute nothing and every one of them should have been removed", sr.Minimal)
	}
	if !sr.Minimal1() {
		t.Errorf("the shrink was not proved 1-minimal (exhausted=%t) over %d attempts", sr.Exhausted, len(sr.Attempts))
	}
	// And the rendered report must not carry the flaky-finding language, which
	// is what a reader would have acted on.
	if strings.Contains(sr.String(), "NOT REPRODUCED") {
		t.Errorf("the shrink report still labels a deterministic finding non-deterministic:\n%s", sr.String())
	}
}

// TestProbeValuesAreDistinct pins the fix for the OTHER false I3 finding this
// wave turned up, which is the same defect class as the lying-peer confound and
// arrives from the campaign's side rather than the invariant's.
//
// The write probes assert [invariant.WriteRecord.Distinctive] — "no legitimate
// path was commanding this value, so seeing it downstream can only have come
// from this write" — and I3 is entitled to believe it, because only the issuer
// knows what else it issued. The list held six values and was indexed modulo its
// length against a PKI of more than six credentials, so a `-teeth` run at seed
// 1096004868 gave ReadOnlySunSpec and oversize-role BOTH 29% and asserted
// distinctiveness for both. The teeth peer accepted the first; the second was
// refused 0x01; I3 saw 29% at the witness and reported a P1 about the refusal.
//
// Two properties therefore have to hold, and the second is the one that stops
// the same bug returning by a different route.
func TestProbeValuesAreDistinct(t *testing.T) {
	t.Parallel()
	seen := map[float64]int{}
	for i, v := range probeValues {
		if prev, dup := seen[v]; dup {
			t.Errorf("probeValues[%d] and probeValues[%d] are both %v — two credentials would command the "+
				"same witness value and both records would claim to be distinctive", prev, i, v)
		}
		seen[v] = i
		if v <= 0 || v >= 100 {
			t.Errorf("probeValues[%d] = %v is not a legal WMaxLimPct percentage", i, v)
		}
		if int(v)%5 == 0 {
			t.Errorf("probeValues[%d] = %v is round enough to be a scheduler default, which is exactly "+
				"what distinctiveness is supposed to rule out", i, v)
		}
	}

	// Past the end of the supply the probe must STOP claiming distinctiveness
	// rather than wrap silently. This is the assertion the old code failed.
	for i := 0; i < len(probeValues); i++ {
		if _, ok := probeValue(i); !ok {
			t.Fatalf("probeValue(%d) declined distinctiveness while values remain", i)
		}
	}
	v, ok := probeValue(len(probeValues))
	if ok {
		t.Fatalf("probeValue(%d) still claims distinctiveness past the end of a %d-value list — that claim "+
			"is false and I3 will act on it", len(probeValues), len(probeValues))
	}
	if v <= 0 || v >= 100 {
		t.Errorf("the non-distinctive fallback value %v is not a legal percentage; the probe must still run", v)
	}
	if !strings.Contains(probeNote(false), "skip") {
		t.Error("the ledger note for a non-distinctive probe does not say I3 will skip it, so a reader of " +
			"the bundle cannot tell why the write went unjudged")
	}
}

// TestConsoleDoesNotCallAWarnAP1 guards the reporting half of the IW15-031
// change. I3's lying-peer exemption made WARN an ordinary campaign outcome, and
// the console's violation heading was hard-coded to "every one a P1" — so a run
// whose only finding was a caveat printed "VIOLATIONS (0 distinct — every one a
// P1)" and then listed one. A heading a reader has to argue with is worse than
// no heading.
func TestConsoleDoesNotCallAWarnAP1(t *testing.T) {
	t.Parallel()
	res := Result{
		Plan:    Plan{Label: "warn-only", Seed: 1},
		Summary: invariant.Summary{PerInvariant: map[string]invariant.Verdict{"I3": invariant.Warn}},
		Violations: []invariant.Violation{{
			ID: "I3", Verdict: invariant.Warn, Reason: "exempted", Key: "lying-peer-confound:x",
			Statement: "…", Facts: []invariant.Fact{{Key: "i3.exempt.count", Value: "1"}},
		}},
		OK: true, Why: "no P1",
	}
	out := Console(res)
	if strings.Contains(out, "every one a P1") {
		t.Errorf("a WARN-only run is reported under a P1 heading:\n%s", out)
	}
	if !strings.Contains(out, "WARNINGS (1 distinct") {
		t.Errorf("a WARN-only run does not report its warnings as warnings:\n%s", out)
	}
	// And the mixed case must count the two kinds separately rather than
	// silently dropping either.
	res.Violations = append(res.Violations, invariant.Violation{
		ID: "I4", Verdict: invariant.Fail, Reason: "accepted", Key: "accepted:x",
		Statement: "…", Facts: []invariant.Fact{{Key: "i4.accepted.seq", Value: "1"}},
	})
	out = Console(res)
	if !strings.Contains(out, "VIOLATIONS (1 distinct — every one a P1) and WARNINGS (1, not P1s)") {
		t.Errorf("a mixed run does not count P1s and warnings separately:\n%s", out)
	}
}
