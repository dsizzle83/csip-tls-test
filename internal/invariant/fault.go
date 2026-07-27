package invariant

// fault.go is the fault manifest — the record of what the adversary has armed,
// against what, and when.
//
// It is here rather than in the chaos runner because a violation is meaningless
// without it. "I1 failed" is not a bug report; "I1 failed at t+412s with a
// gridsim clock warp of -3600s and a stale_values fault on inv-plain in force,
// seed 8134297" is. Requirement 3 of the invariant harness is precisely that
// every violation carries the manifest that was in force at the time, and the
// only way to guarantee that is for the manifest to be a first-class object the
// Monitor snapshots on every tick, not a log line the runner happens to print.
//
// The classes exist because several invariants are ABOUT a fault class rather
// than about a particular fault: I2 asks what happens when control authority is
// lost, whatever caused the loss; I9 asks whether a RECOVERABLE outage recovers,
// and needs to know which armed faults were recoverable and when they cleared.
// A checker that had to enumerate fault ids would go stale the first time
// someone added a new one.

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// FaultClass groups faults by what they do to the DUT's world, so an invariant
// can reason about "authority was lost" without knowing which of a dozen ways
// the adversary chose.
type FaultClass string

// The fault classes.
const (
	// ClassAuthorityLoss — the DUT can no longer be told what to do by a
	// legitimate authority: the head-end is unreachable, its controls have
	// expired, or its credentials no longer validate. I2's precondition.
	ClassAuthorityLoss FaultClass = "authority-loss"
	// ClassCommLoss — a southbound device is unreachable or silent.
	ClassCommLoss FaultClass = "comm-loss"
	// ClassPeerLie — a peer answers, but dishonestly: ACKs without applying,
	// applies then reverts, returns stale or sentinel values, changes its
	// model layout, claims a different unit id.
	ClassPeerLie FaultClass = "peer-lie"
	// ClassMalform — a peer's messages are structurally hostile: malformed
	// XML, lying Content-Length, redirect loops, oversized bodies.
	ClassMalform FaultClass = "malform"
	// ClassClockWarp — time moves wrongly: a step forward or back, an unset
	// RTC, skew across a certificate validity boundary.
	ClassClockWarp FaultClass = "clock-warp"
	// ClassResource — the host is starved: disk full, fds exhausted, memory
	// pressure, CPU starvation, a read-only remount.
	ClassResource FaultClass = "resource"
	// ClassInterruption — the DUT was interrupted: a power cut, a SIGKILL, a
	// service restart. I6's precondition.
	ClassInterruption FaultClass = "interruption"
	// ClassTransportAbuse — TLS-layer hostility against :802: handshake
	// floods, half-open exhaustion, resumption confusion, alert floods.
	ClassTransportAbuse FaultClass = "transport-abuse"
)

// Fault is one armed adversary, with its lifetime.
type Fault struct {
	// ID is the runner's identifier for this instance, e.g.
	// "gridsim.outage#3". Unique within a manifest.
	ID string `json:"id"`
	// Kind is the injector's own name, e.g. "outage", "ack_before_effect".
	Kind string `json:"kind"`
	// Class groups it for invariants that reason about classes.
	Class FaultClass `json:"class"`
	// Target names what it was armed against: "head-end", a DER name
	// ("inv-plain"), or "gateway".
	Target string `json:"target"`
	// Params are the injector's parameters, recorded verbatim so the fault can
	// be re-armed identically during shrinking.
	Params map[string]string `json:"params,omitempty"`
	// Armed is when it took effect.
	Armed time.Time `json:"armed"`
	// Cleared is when it was withdrawn; the zero time means still in force.
	Cleared time.Time `json:"cleared,omitzero"`
	// Recoverable records the campaign's claim that this fault, once cleared,
	// leaves nothing a human must do — which is exactly what I9 audits. A
	// fault the campaign does NOT claim is recoverable (a corrupted store, a
	// revoked certificate) is out of I9's scope, and saying so here keeps I9
	// from failing the device for not healing something nobody promised it
	// would heal.
	Recoverable bool `json:"recoverable"`
}

// InForce reports whether the fault was armed and not yet cleared at t.
func (f Fault) InForce(t time.Time) bool {
	if f.Armed.IsZero() || t.Before(f.Armed) {
		return false
	}
	return f.Cleared.IsZero() || t.Before(f.Cleared)
}

// String renders the fault for a log line or a violation header.
func (f Fault) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s(%s) on %s", f.Kind, f.Class, f.Target)
	if len(f.Params) > 0 {
		keys := make([]string, 0, len(f.Params))
		for k := range f.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+f.Params[k])
		}
		fmt.Fprintf(&b, " [%s]", strings.Join(parts, " "))
	}
	return b.String()
}

// FaultManifest is the set of faults a campaign has armed, with the seed that
// generated them.
//
// It is safe for concurrent use: the campaign arms and clears from its own
// goroutines while the Monitor snapshots it on every tick.
type FaultManifest struct {
	mu sync.RWMutex
	// Seed is the campaign's RNG seed. Recorded in every violation so a
	// failure is reproducible (strategy §4.5).
	seed   int64
	label  string
	faults []Fault
}

// NewManifest returns an empty manifest for a campaign identified by label and
// driven by seed.
func NewManifest(label string, seed int64) *FaultManifest {
	return &FaultManifest{seed: seed, label: label}
}

// Seed returns the campaign seed.
func (m *FaultManifest) Seed() int64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.seed
}

// Label returns the campaign label.
func (m *FaultManifest) Label() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.label
}

// Arm records a fault as taking effect now (or at f.Armed if the caller set
// it) and returns its ID.
func (m *FaultManifest) Arm(f Fault) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Armed.IsZero() {
		f.Armed = time.Now()
	}
	if f.ID == "" {
		f.ID = fmt.Sprintf("%s.%s#%d", f.Target, f.Kind, len(m.faults)+1)
	}
	m.faults = append(m.faults, f)
	return f.ID
}

// Clear marks a fault withdrawn at t (now, if t is zero). Clearing an unknown
// or already-cleared fault is a no-op returning false, so a runner's teardown
// can be unconditional.
func (m *FaultManifest) Clear(id string, t time.Time) bool {
	if t.IsZero() {
		t = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.faults {
		if m.faults[i].ID == id && m.faults[i].Cleared.IsZero() {
			m.faults[i].Cleared = t
			return true
		}
	}
	return false
}

// Snapshot returns a copy of every fault ever armed, in arm order. The Monitor
// takes one per tick and stores it in the Observation, so a violation carries
// the manifest as it stood, not as it later became.
func (m *FaultManifest) Snapshot() ManifestSnapshot {
	if m == nil {
		return ManifestSnapshot{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := ManifestSnapshot{Seed: m.seed, Label: m.label, Faults: make([]Fault, len(m.faults))}
	copy(out.Faults, m.faults)
	return out
}

// ManifestSnapshot is an immutable copy of a manifest at one instant — what a
// violation records.
type ManifestSnapshot struct {
	Seed   int64   `json:"seed"`
	Label  string  `json:"label,omitempty"`
	Faults []Fault `json:"faults"`
}

// Active returns the faults in force at t.
func (s ManifestSnapshot) Active(t time.Time) []Fault {
	var out []Fault
	for _, f := range s.Faults {
		if f.InForce(t) {
			out = append(out, f)
		}
	}
	return out
}

// ActiveOf returns the faults of a class in force at t.
func (s ManifestSnapshot) ActiveOf(t time.Time, class FaultClass) []Fault {
	var out []Fault
	for _, f := range s.Active(t) {
		if f.Class == class {
			out = append(out, f)
		}
	}
	return out
}

// Of returns every fault of a class, in force or not.
func (s ManifestSnapshot) Of(class FaultClass) []Fault {
	var out []Fault
	for _, f := range s.Faults {
		if f.Class == class {
			out = append(out, f)
		}
	}
	return out
}

// Targeting returns every fault armed against target, in force or not.
func (s ManifestSnapshot) Targeting(target string) []Fault {
	var out []Fault
	for _, f := range s.Faults {
		if f.Target == target {
			out = append(out, f)
		}
	}
	return out
}

// AnyArmed reports whether the campaign ever armed anything. A run that armed
// nothing must not be reported as a pass — that is FI-01, the defect wave 1
// fixed in gw-mayhem, and the Monitor enforces the same floor via this.
func (s ManifestSnapshot) AnyArmed() bool { return len(s.Faults) > 0 }

// LatestCleared returns the most recent clear time among faults matching pred,
// and whether any matched and cleared.
func (s ManifestSnapshot) LatestCleared(pred func(Fault) bool) (time.Time, bool) {
	var latest time.Time
	found := false
	for _, f := range s.Faults {
		if f.Cleared.IsZero() || !pred(f) {
			continue
		}
		if !found || f.Cleared.After(latest) {
			latest, found = f.Cleared, true
		}
	}
	return latest, found
}

// String renders the manifest one fault per line, which is what a verdict
// prints alongside itself (strategy §4.1: print the fault manifest with every
// verdict).
func (s ManifestSnapshot) String() string {
	if len(s.Faults) == 0 {
		return fmt.Sprintf("seed=%d faults=NONE", s.Seed)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "seed=%d faults=%d", s.Seed, len(s.Faults))
	for _, f := range s.Faults {
		state := "in-force"
		if !f.Cleared.IsZero() {
			state = fmt.Sprintf("cleared after %s", f.Cleared.Sub(f.Armed).Round(time.Second))
		}
		fmt.Fprintf(&b, "\n    %-28s %s (%s)", f.ID, f, state)
	}
	return b.String()
}

// Facts renders the manifest as Facts, so a violation's structured record
// carries the adversary as data rather than as a formatted string.
func (s ManifestSnapshot) Facts() []Fact {
	out := []Fact{F("fault.seed", "", "manifest", "%d", s.Seed)}
	for _, f := range s.Faults {
		state := "in-force"
		if !f.Cleared.IsZero() {
			state = "cleared"
		}
		out = append(out, F("fault."+f.ID, "", "manifest", "%s %s", f, state))
	}
	return out
}
