package invariant

// world_test.go pins the World's contract, which the invariants all rely on
// without restating: one snapshot per tick, a bounded history, a failed source
// recorded rather than hidden, and no method that lets a checker change
// anything.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// failingDER always fails, to prove a broken witness is recorded rather than
// silently read as a healthy empty one.
type failingDER struct{ name string }

func (f failingDER) Name() string { return "failing:" + f.name }
func (f failingDER) Observe(context.Context) (DERView, error) {
	return DERView{}, errors.New("dial tcp 127.0.0.1:5020: connection refused")
}

func TestWorld_RecordsAFailedSourceRatherThanHidingIt(t *testing.T) {
	t.Parallel()
	w := NewWorld(Sources{DERs: map[string]DERSource{"inv": failingDER{"inv"}}}, nil, nil, DefaultParams())
	obs, err := w.Observe(context.Background())
	if err != nil {
		t.Fatalf("Observe returned an error for a partly-unreachable bench; during a chaos campaign that is "+
			"the normal state and must still produce a snapshot: %v", err)
	}
	d := obs.DERs["inv"]
	if d.Reachable {
		t.Fatal("an unreachable device was reported reachable")
	}
	if d.Err == "" {
		t.Fatal("the view does not carry the failure")
	}
	if len(obs.Errs) == 0 {
		t.Fatal("the observation does not record which source failed")
	}
}

func TestWorld_RefusesToObserveWithNoSources(t *testing.T) {
	t.Parallel()
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	if _, err := w.Observe(context.Background()); err == nil {
		t.Fatal("a World with no sources produced a snapshot, which would read as a healthy empty bench")
	}
}

func TestWorld_HistoryIsBoundedAndOrdered(t *testing.T) {
	t.Parallel()
	p := DefaultParams()
	p.HistoryDepth = 5
	w := NewWorld(Sources{}, nil, nil, p)
	for i := 0; i < 12; i++ {
		w.Inject(&Observation{At: time.Unix(int64(1000+i), 0)})
	}
	h := w.History()
	if len(h) != 5 {
		t.Fatalf("history holds %d observations, want the configured bound of 5", len(h))
	}
	for i := 1; i < len(h); i++ {
		if !h[i].At.After(h[i-1].At) {
			t.Fatal("history is not oldest-first")
		}
	}
	if w.Now() != h[len(h)-1] {
		t.Fatal("Now() is not the newest retained observation")
	}
	if got := len(w.Since(time.Unix(1009, 0))); got != 3 {
		t.Fatalf("Since returned %d observations, want 3", got)
	}
}

func TestWorld_SnapshotCarriesTheManifestAtThatInstant(t *testing.T) {
	t.Parallel()
	faults := NewManifest("c", 5)
	w := NewWorld(Sources{DERs: map[string]DERSource{
		"inv": &scriptedDER{name: "inv", views: []DERView{{Reachable: true}}},
	}}, faults, nil, DefaultParams())

	first, _ := w.Observe(context.Background())
	if len(first.Faults.Faults) != 0 {
		t.Fatal("the first snapshot carries faults that were not armed yet")
	}
	faults.Arm(Fault{ID: "f1", Kind: "outage", Class: ClassCommLoss, Target: "inv"})
	second, _ := w.Observe(context.Background())

	if len(first.Faults.Faults) != 0 {
		t.Fatal("arming a fault mutated an earlier snapshot — a violation would then record the wrong adversary")
	}
	if len(second.Faults.Faults) != 1 {
		t.Fatalf("the later snapshot does not carry the armed fault: %+v", second.Faults)
	}
	if second.Faults.Seed != 5 {
		t.Fatal("the snapshot does not carry the campaign seed")
	}
}

func TestWorld_ObserveIsRaceFreeUnderConcurrentReaders(t *testing.T) {
	t.Parallel()
	w := NewWorld(Sources{DERs: map[string]DERSource{
		"inv": &scriptedDER{name: "inv", views: []DERView{{Reachable: true}}},
	}}, nil, nil, DefaultParams())

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = w.Now()
					_ = w.History()
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		if _, err := w.Observe(context.Background()); err != nil {
			t.Errorf("observe: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

func TestFaultManifest_InForceAndClear(t *testing.T) {
	t.Parallel()
	m := NewManifest("c", 1)
	t0 := time.Now()
	id := m.Arm(Fault{Kind: "outage", Class: ClassAuthorityLoss, Target: "head-end", Armed: t0, Recoverable: true})
	snap := m.Snapshot()
	if !snap.Faults[0].InForce(t0.Add(time.Minute)) {
		t.Fatal("an armed, uncleared fault is not in force")
	}
	if snap.Faults[0].InForce(t0.Add(-time.Minute)) {
		t.Fatal("a fault is in force before it was armed")
	}
	if !m.Clear(id, t0.Add(2*time.Minute)) {
		t.Fatal("Clear did not find the armed fault")
	}
	if m.Clear(id, t0.Add(3*time.Minute)) {
		t.Fatal("Clear reported success on an already-cleared fault")
	}
	snap = m.Snapshot()
	if snap.Faults[0].InForce(t0.Add(3 * time.Minute)) {
		t.Fatal("a cleared fault is still in force")
	}
	if got, ok := snap.LatestCleared(func(f Fault) bool { return f.Class == ClassAuthorityLoss }); !ok || !got.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("LatestCleared = %v, %t", got, ok)
	}
	if !strings.Contains(snap.String(), "seed=1") {
		t.Fatalf("the rendered manifest omits the seed: %s", snap.String())
	}
}

func TestParams_SkipRatherThanDefault(t *testing.T) {
	t.Parallel()
	p := DefaultParams()
	if _, ok := p.Float("failsafe_wmaxlimpct"); ok {
		t.Fatal("an absent parameter returned a value; a checker would then assert the operator's intent")
	}
	p.Values["failsafe_deadline"] = "45s"
	d, ok := p.Duration("failsafe_deadline")
	if !ok || d != 45*time.Second {
		t.Fatalf("Duration = %v, %t", d, ok)
	}
	p.Values["growth_files"] = "/var/lib/lexa/outbox.ndjson, /var/lib/lexa/shadow.ndjson"
	files, ok := p.List("growth_files")
	if !ok || len(files) != 2 || files[1] != "/var/lib/lexa/shadow.ndjson" {
		t.Fatalf("List = %v, %t", files, ok)
	}
}

func TestMemTransportIsReadOnly(t *testing.T) {
	t.Parallel()
	m := newMemTransport(map[uint16]uint16{40000: 0x5375})
	if err := m.WriteHolding(40000, []uint16{1}); err == nil {
		t.Fatal("an invariant source accepted a write; a witness must never be an actor")
	}
	regs, err := m.ReadHolding(40000, 2)
	if err != nil || regs[0] != 0x5375 || regs[1] != 0 {
		t.Fatalf("ReadHolding = %v, %v", regs, err)
	}
}
