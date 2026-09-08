package certify

// preflight_weakened_test.go pins REV0907-E3: a GATING campaign refuses every
// evidence-weakening switch preflight can check outright — -skip-preflight, an
// old gridsim's unreported data_plane, -require-citation=false — through the
// same unprovable error class the dirty-tree/-allow-dirty refusal already used
// (preflight_provenance.go, TestCheckHarnessTree_DirtyIsFatalOnGatingUnlessAllowed).
// An EXPLORATORY (non-gating) run keeps every one of them and records its use
// in Runner.weakened, the audit trail writeBundle turns into
// bundle.CampaignRecord.Weakened — and that record reaches an actual written
// bundle, not just the in-memory field.

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

// weakeningSwitch is one preflight-refusable weakening switch: how to arm it on
// a fresh Runner, and the Weakened key it should be recorded under once armed.
type weakeningSwitch struct {
	key   string
	setup func(t *testing.T) *Runner
	check func(t *testing.T, r *Runner, rep *Reporter) error
}

func weakeningSwitches(t *testing.T) []weakeningSwitch {
	return []weakeningSwitch{
		{
			key: WeakenedSkipPreflight,
			setup: func(t *testing.T) *Runner {
				return &Runner{opts: Options{
					SkipPreflight: true,
					Targets:       Targets{GridSim: "127.0.0.1:11113", GridSimAdmin: "http://69.0.0.20:11114"},
					Iface:         "enp1s0",
				}}
			},
			check: func(t *testing.T, r *Runner, rep *Reporter) error {
				return r.preflight(context.Background(), rep)
			},
		},
		{
			key: WeakenedNoDataPlane,
			setup: func(t *testing.T) *Runner {
				admin := gridsimAdmin(t, 5, "") // a gridsim too old to publish data_plane
				return &Runner{opts: Options{
					Targets: Targets{GridSim: "127.0.0.1:11113", GridSimAdmin: admin.URL},
					Iface:   "enp1s0",
				}}
			},
			check: func(t *testing.T, r *Runner, rep *Reporter) error {
				return r.preflight(context.Background(), rep)
			},
		},
		{
			key: WeakenedRequireCitationFalse,
			setup: func(t *testing.T) *Runner {
				return &Runner{opts: Options{RequireCitation: false}}
			},
			check: func(t *testing.T, r *Runner, rep *Reporter) error {
				return r.preflightCitation(rep)
			},
		},
	}
}

// The table: each switch, crossed with {gating, non-gating}. Gating must
// refuse outright (unprovable's FATAL branch); non-gating must proceed and
// record the switch's key in Runner.weakened (unprovable's WARN branch).
func TestWeakeningSwitchesRefuseGatingRecordExploratory(t *testing.T) {
	for _, sw := range weakeningSwitches(t) {
		sw := sw
		t.Run(sw.key+"/gating_refused", func(t *testing.T) {
			r := sw.setup(t)
			r.campaign = CampaignSpec{Name: "csip"}
			rep := NewReporter(&strings.Builder{})
			err := sw.check(t, r, rep)
			if err == nil {
				t.Fatalf("%s was accepted on a GATING campaign", sw.key)
			}
			for _, want := range []string{"GATING", "-campaign csip"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: refusal does not mention %q: %v", sw.key, want, err)
				}
			}
		})
		t.Run(sw.key+"/exploratory_recorded", func(t *testing.T) {
			r := sw.setup(t)
			rep := NewReporter(&strings.Builder{})
			if err := sw.check(t, r, rep); err != nil {
				t.Fatalf("%s was refused on an EXPLORATORY run (no -campaign): %v", sw.key, err)
			}
			if !reflect.DeepEqual(r.weakened, []string{sw.key}) {
				t.Errorf("%s: Runner.weakened = %v, want [%s]", sw.key, r.weakened, sw.key)
			}
		})
	}
}

// The default posture (every switch off) must never touch the audit trail or
// refuse anything, gating or not — recordWeakened firing on an unweakened run
// would make Weakened meaningless.
func TestUnweakenedRunRecordsNothing(t *testing.T) {
	gating := &Runner{campaign: CampaignSpec{Name: "csip"}, opts: Options{RequireCitation: true}}
	if err := gating.preflightCitation(NewReporter(&strings.Builder{})); err != nil {
		t.Fatalf("the default -require-citation=true was refused on a GATING campaign: %v", err)
	}
	if len(gating.weakened) != 0 {
		t.Errorf("an unweakened gating run recorded: %v", gating.weakened)
	}
}

// The audit trail must reach the bundle this package actually writes, not just
// the in-memory field a unit test can inspect directly — otherwise the whole
// mechanism could be right in isolation and still never make it to the
// evidence a reader holds. Two switches at once also pins that recordWeakened
// accumulates rather than overwrites.
func TestWeakenedSwitchesReachTheWrittenBundle(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", noopCheck)
	opts, out := baseOptions(t, nil)
	opts.SkipPreflight = true
	opts.RequireCitation = false
	opts.Targets.GridSim = "127.0.0.1:11113"
	opts.Targets.GridSimAdmin = "http://69.0.0.20:11114" // would otherwise be refused; skip-preflight bypasses it
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, err := bundle.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if b.Run.Campaign == nil {
		t.Fatal("the bundle carries no campaign record at all")
	}
	if b.Run.Campaign.Gating {
		t.Error("an EXPLORATORY run's bundle claims campaign.gating=true")
	}
	want := []string{WeakenedRequireCitationFalse, WeakenedSkipPreflight}
	sort.Strings(want)
	if !reflect.DeepEqual(b.Run.Campaign.Weakened, want) {
		t.Errorf("campaign.weakened = %v, want %v", b.Run.Campaign.Weakened, want)
	}
}
