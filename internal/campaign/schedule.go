package campaign

// schedule.go turns a seed, a layer set and an inventory into a concrete,
// replayable plan: which actions fire, when they fire, and how long the faults
// stay in force.
//
// # Why the schedule is data and not a goroutine
//
// A chaos runner that decides what to do next while it is running cannot be
// replayed, because "next" depended on timing that will never recur. So the
// whole plan is computed up front from the seed, written into the run record,
// and then merely EXECUTED. Two consequences follow, and both are the point:
// a failure is reproducible from `-seed N` alone, and the shrinker can hand the
// runner a subset of the same plan and be sure that nothing else moved.
//
// # Why concurrency is deliberate rather than incidental
//
// The interesting defects are compound: a lying DER while the head-end is
// timing out, a session flood while a control is being applied. So the
// scheduler places arm times so that faults OVERLAP by construction — it does
// not merely permit overlap and hope. The overlap fraction is a knob
// ([Config.Overlap]) because a shrink wants the same actions with the same
// relative timing and a smaller set, and a scheduler that re-spread the
// survivors over the whole window would change the experiment mid-shrink.
// [Plan.Subset] therefore keeps every surviving action's ORIGINAL timing.
//
// # Why a probe fires late
//
// A probe records an attempt in the ledger and the invariants judge it against
// the world as it then is. Firing every probe at t=0, before any fault is in
// force, would produce a ledger full of attempts made against an unattacked
// device — the FI-01 defect in a subtler costume. Probes are therefore placed
// in the second half of the window by default, after the first faults are up.

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// Event is one scheduled thing: an action, when it fires, and (for a fault)
// when it is withdrawn.
type Event struct {
	// ActionID is the [Action.ID] this event drives.
	ActionID string `json:"action_id"`
	Layer    string `json:"layer"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Class    string `json:"class"`
	// Oneshot marks a probe.
	Oneshot bool `json:"oneshot"`
	// At is the offset from run start at which the action is armed or fired.
	At time.Duration `json:"at_ns"`
	// Hold is how long a fault stays in force. Zero for a probe.
	Hold time.Duration `json:"hold_ns,omitempty"`
	// Params are the action's parameters, recorded so the plan is readable
	// without re-running the planner.
	Params map[string]string `json:"params,omitempty"`

	action Action
}

// Until is when the fault is withdrawn, as an offset from run start.
func (e Event) Until() time.Duration { return e.At + e.Hold }

// Plan is the full run record: the seed, the window, the layers, and every
// scheduled event. It is written into the evidence bundle verbatim.
type Plan struct {
	Seed   int64         `json:"seed"`
	Label  string        `json:"label"`
	Window time.Duration `json:"window_ns"`
	// Layers are the layer ids that contributed, in the order they were run.
	Layers []string `json:"layers"`
	// Offered is how many actions the layers offered in total, before
	// selection. The ratio of len(Events) to Offered is how much of the
	// available adversity this run actually used, and printing it stops a
	// twelve-action campaign from reading like an exhaustive one.
	Offered int     `json:"offered"`
	Events  []Event `json:"events"`
	// Declined records layers that offered nothing and why, so a run that
	// silently lost a whole family says so.
	Declined map[string]string `json:"declined,omitempty"`
}

// ActionIDs returns the scheduled action ids in fire order.
func (p Plan) ActionIDs() []string {
	out := make([]string, 0, len(p.Events))
	for _, e := range p.Events {
		out = append(out, e.ActionID)
	}
	return out
}

// Subset returns the plan restricted to the named actions, PRESERVING each
// survivor's original timing. Preserving timing is not a nicety: a shrink that
// re-spread the survivors would be running a different experiment on every
// attempt, and could then "fail to reproduce" a violation that the original
// timing causes.
func (p Plan) Subset(keep []string) Plan {
	want := make(map[string]bool, len(keep))
	for _, id := range keep {
		want[id] = true
	}
	out := p
	out.Events = nil
	for _, e := range p.Events {
		if want[e.ActionID] {
			out.Events = append(out.Events, e)
		}
	}
	return out
}

// Faults counts the scheduled faults (as opposed to probes).
func (p Plan) Faults() int {
	n := 0
	for _, e := range p.Events {
		if !e.Oneshot {
			n++
		}
	}
	return n
}

// Probes counts the scheduled probes.
func (p Plan) Probes() int { return len(p.Events) - p.Faults() }

// String renders the plan as the fault manifest a verdict is printed with
// (strategy §4.1). It is deliberately verbose: a campaign's verdict is not
// interpretable without knowing what the adversary was doing.
func (p Plan) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "seed=%d window=%s layers=[%s] actions=%d/%d offered (%d faults, %d probes)",
		p.Seed, p.Window.Round(time.Second), strings.Join(p.Layers, ","),
		len(p.Events), p.Offered, p.Faults(), p.Probes())
	for _, e := range p.Events {
		when := fmt.Sprintf("t+%-6s", e.At.Round(100*time.Millisecond))
		span := "one-shot"
		if !e.Oneshot {
			span = fmt.Sprintf("hold %s", e.Hold.Round(100*time.Millisecond))
		}
		fmt.Fprintf(&b, "\n    %s %-9s %s", when, span, e.action)
	}
	for _, id := range sortedKeys(p.Declined) {
		fmt.Fprintf(&b, "\n    DECLINED %-14s %s", id, p.Declined[id])
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// layerSeed derives a layer's own RNG seed from the campaign seed and the layer
// id. Deriving rather than sharing one stream means adding a layer to a run
// does not change what the other layers planned — so a campaign re-run with one
// extra layer is still comparable to the original, which matters constantly
// when bisecting a finding.
func layerSeed(seed int64, id string) int64 {
	h := int64(1469598103934665603)
	for _, c := range id {
		h = (h ^ int64(c)) * 1099511628211
	}
	return seed ^ h
}

// BuildPlan enumerates every layer against the inventory, selects up to
// cfg.Actions of them on the seed, and lays them out over the window.
//
// Selection is a seeded shuffle of the offered set with a per-layer floor: at
// least one action from every layer that offered anything survives, as long as
// the budget allows. Without the floor, a seed that happened to draw twelve
// peer-lies would produce a "six-layer campaign" that exercised one layer, and
// the run header would still print six.
func BuildPlan(cfg Config, inv Inventory, layers []Layer) Plan {
	p := Plan{
		Seed:     cfg.Seed,
		Label:    cfg.Label,
		Window:   cfg.Window,
		Declined: map[string]string{},
	}

	byLayer := map[string][]Action{}
	for _, l := range layers {
		p.Layers = append(p.Layers, l.ID())
		rng := rand.New(rand.NewSource(layerSeed(cfg.Seed, l.ID())))
		offered := assignSeqs(l.Plan(inv, rng))
		p.Offered += len(offered)
		if len(offered) == 0 {
			why := "the layer offered no action against this inventory — its targets are absent or " +
				"advertise none of the kinds it needs"
			if e, ok := l.(Explainer); ok {
				if detail := e.Explain(inv); detail != "" {
					why = detail
				}
			}
			p.Declined[l.ID()] = why
			continue
		}
		byLayer[l.ID()] = offered
	}

	selected := selectActions(cfg, p.Layers, byLayer)
	if len(selected) == 0 {
		return p
	}

	// Timing. Faults are spread over the first Overlap fraction of the window
	// so that they are in force TOGETHER, and each holds until near the end;
	// probes land in the back half, once the adversary is actually up.
	//
	// EACH ACTION DRAWS FROM ITS OWN STREAM, seeded from (campaign seed, action
	// id) rather than from a single stream consumed in draw order. That is not
	// a style choice — it is the property the shrinker rests on. With a shared
	// stream, removing one action shifts every later action's arm time, so
	// every shrink attempt would be a different experiment and a genuine
	// two-fault interaction could "stop reproducing" purely because the
	// survivors moved. Per-action streams make [Plan.Subset] and a re-planned
	// subset agree exactly.
	armSpan := time.Duration(float64(cfg.Window) * cfg.overlap())
	if armSpan <= 0 {
		armSpan = cfg.Window / 2
	}
	// Reserve the tail so every fault has been cleared before the run's final
	// ticks: I9 asks whether a cleared fault RECOVERED, and a fault still in
	// force at the last tick makes that claim undecidable rather than false.
	tail := cfg.recoveryTail()

	for _, a := range selected {
		rng := rand.New(rand.NewSource(layerSeed(cfg.Seed^0x5eed5ced, a.ID())))
		e := Event{
			ActionID: a.ID(), Layer: a.Layer, Kind: a.Kind, Target: a.Target,
			Class: string(a.Class), Oneshot: a.Oneshot, Params: a.Params, action: a,
		}
		if a.Oneshot {
			// Back half of the armed window, so a probe is made against a
			// device that is already under attack.
			lo := armSpan / 2
			e.At = lo + time.Duration(rng.Int63n(int64(maxDur(armSpan-lo, time.Millisecond))))
		} else {
			e.At = time.Duration(rng.Int63n(int64(maxDur(armSpan, time.Millisecond))))
			// Hold until the recovery tail, with a seeded jitter so faults do
			// not all clear on the same instant.
			remaining := cfg.Window - tail - e.At
			if remaining < cfg.Cadence {
				remaining = cfg.Cadence
			}
			jitter := time.Duration(rng.Int63n(int64(maxDur(remaining/4, time.Millisecond))))
			e.Hold = remaining - jitter
		}
		p.Events = append(p.Events, e)
	}
	sort.SliceStable(p.Events, func(i, j int) bool {
		if p.Events[i].At != p.Events[j].At {
			return p.Events[i].At < p.Events[j].At
		}
		return p.Events[i].ActionID < p.Events[j].ActionID
	})
	return p
}

// matchesAny reports whether id contains any of the patterns. Substring rather
// than equality so a pin can name an action without knowing its sequence
// number, which is an implementation detail of the planner.
func matchesAny(id string, patterns []string) bool {
	for _, p := range patterns {
		if p != "" && strings.Contains(id, p) {
			return true
		}
	}
	return false
}

func maxDur(d, floor time.Duration) time.Duration {
	if d < floor {
		return floor
	}
	return d
}

// selectActions picks the run's action set: the operator's pinned actions
// first, then one from each contributing layer (in layer order, so the floor
// itself is deterministic), then a seeded shuffle of the remainder up to the
// budget.
func selectActions(cfg Config, order []string, byLayer map[string][]Action) []Action {
	budget := cfg.Actions
	if budget <= 0 {
		budget = defaultActions
	}
	rng := rand.New(rand.NewSource(cfg.Seed ^ 0x5e1ec7))

	pinned := map[string]bool{}
	var chosen []Action
	for _, id := range order {
		for _, a := range byLayer[id] {
			if matchesAny(a.ID(), cfg.Require) {
				chosen = append(chosen, a)
				pinned[a.ID()] = true
			}
		}
	}

	var rest []Action
	for _, id := range order {
		as := byLayer[id]
		if len(as) == 0 {
			continue
		}
		shuffled := make([]Action, 0, len(as))
		for _, a := range as {
			if !pinned[a.ID()] {
				shuffled = append(shuffled, a)
			}
		}
		if len(shuffled) == 0 {
			continue // every action from this layer was pinned
		}
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		chosen = append(chosen, shuffled[0])
		rest = append(rest, shuffled[1:]...)
	}
	if len(chosen) >= budget {
		// The pins plus the per-layer floor already exceed the budget. Honour
		// them rather than the budget: a run that silently dropped a pinned
		// action, or a whole layer, to fit a number would be reporting a
		// campaign it did not run.
		sort.SliceStable(chosen, func(i, j int) bool { return chosen[i].ID() < chosen[j].ID() })
		return chosen
	}
	rng.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	need := budget - len(chosen)
	if need > len(rest) {
		need = len(rest)
	}
	chosen = append(chosen, rest[:need]...)
	sort.SliceStable(chosen, func(i, j int) bool { return chosen[i].ID() < chosen[j].ID() })
	return chosen
}
