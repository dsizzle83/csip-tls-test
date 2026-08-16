package campaign

// action.go defines the schedulable unit of adversity and the inventory a layer
// plans against.
//
// The one design decision worth defending is that [Action] carries closures
// (Arm/Clear) while its IDENTITY is pure data (Layer, Kind, Target, Params).
// The shrinker needs both halves and they have different lifetimes: a shrink
// re-plans the whole campaign from the same seed and then keeps a SUBSET by id,
// so the closures are rebuilt fresh each attempt against a fresh world, while
// the ids stay stable across attempts and across processes. An Action that
// carried its own live handle to a sim would shrink correctly once and then be
// useless on the second attempt.
//
// The second is that a layer NEVER decides whether it is applicable — it is
// handed an [Inventory] and plans against what is there. A layer that probed
// for its own targets would give a different answer on a bench where one sim is
// briefly down, and a campaign whose action set depends on transient bench
// state is not reproducible from a seed, which is the whole point.

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"csip-tls-test/internal/invariant"
)

// Runtime is what an action is handed when it fires: the record-keeping the
// invariants read, plus the run's context. It is deliberately narrow — an
// action may record what it attempted and may act on its target, and may not
// touch the monitor, the schedule, or another action.
type Runtime struct {
	// Ledger is where a probe records the attempt it made and the answer it
	// got. I3, I4 and I5 read nothing else.
	Ledger *invariant.Ledger
	// Faults is the manifest. Actions do NOT arm into it directly — the runner
	// does that from the action's own metadata, so a layer cannot forget — but
	// a layer that needs to consult what else is in force may read it.
	Faults *invariant.FaultManifest
	// Log receives one line per significant event.
	Log invariant.Logger
	// Seed is the campaign seed, for an action that needs its own determinism.
	Seed int64
}

// Logf logs, tolerating a nil logger.
func (rt *Runtime) Logf(format string, args ...any) {
	if rt != nil && rt.Log != nil {
		rt.Log.Printf(format, args...)
	}
}

// Action is one thing the adversary does. It is either a FAULT (Arm now, Clear
// later, recorded in the fault manifest) or a PROBE (Oneshot: Arm fires once,
// Clear is nil, and whatever it learns goes in the ledger).
type Action struct {
	// Layer is the layer that planned it, e.g. "peer-lie".
	Layer string
	// Kind is the injector's own name, e.g. "ack_no_apply", "unauthorized-write".
	Kind string
	// Target names what it acts on: a DER name, "head-end", or "dut".
	Target string
	// Class groups it for the invariants that reason about classes rather than
	// about particular faults (I2 asks "was authority lost", not "which of the
	// nine ways").
	Class invariant.FaultClass
	// Params are recorded verbatim in the manifest so a violation can be
	// re-armed identically during a shrink.
	Params map[string]string
	// Recoverable is the campaign's claim that clearing this leaves nothing a
	// human must do. I9 audits exactly that claim, so a layer that is not sure
	// must say false — I9 then leaves the fault alone rather than failing the
	// device for not healing something nobody promised it would heal.
	Recoverable bool
	// Oneshot marks a probe: it fires once and is not armed into the manifest.
	Oneshot bool
	// Why is one sentence a reader can use to judge whether the action was
	// worth running. It is printed in the manifest table.
	Why string

	// Arm applies the action. For a probe this IS the attack.
	Arm func(ctx context.Context, rt *Runtime) error
	// Clear withdraws it. Nil for a probe. It must be idempotent: the runner
	// calls it on the normal path and again during teardown, because a campaign
	// interrupted mid-run must not leave the bench faulted.
	Clear func(ctx context.Context, rt *Runtime) error

	// seq is assigned by the planner so two identical actions against the same
	// target get distinct ids. Not exported: it is an implementation detail of
	// id stability, and a layer that set it would break that stability.
	seq int
}

// ID is the action's stable identity: the same seed and the same layer set
// produce the same id for the same action, in this process and the next. The
// shrinker's entire contract rests on that.
func (a Action) ID() string {
	return fmt.Sprintf("%s/%s@%s#%d", a.Layer, a.Kind, a.Target, a.seq)
}

// String renders the action for the manifest table.
func (a Action) String() string {
	kind := "fault"
	if a.Oneshot {
		kind = "probe"
	}
	s := fmt.Sprintf("%-34s %-5s %-16s %s", a.ID(), kind, a.Class, a.Target)
	if len(a.Params) > 0 {
		s += " [" + renderParams(a.Params) + "]"
	}
	return s
}

func renderParams(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+p[k])
	}
	return strings.Join(parts, " ")
}

// fault renders the action as the manifest entry the runner arms.
func (a Action) fault() invariant.Fault {
	return invariant.Fault{
		ID:          a.ID(),
		Kind:        a.Kind,
		Class:       a.Class,
		Target:      a.Target,
		Params:      a.Params,
		Recoverable: a.Recoverable,
	}
}

// DERTarget is one downstream device a layer may attack, with the handle it
// needs to do so.
type DERTarget struct {
	// Name is the bench name, e.g. "inv-plain". It is the key that pairs this
	// target with the invariant World's DER source of the same name.
	Name string
	// Fault posts a fault body to the device. A device with no fault surface
	// leaves this nil and the layers that need it plan nothing against it,
	// which is how a campaign against an unfaultable device honestly reports a
	// smaller action set rather than a silently weaker one.
	Fault func(ctx context.Context, body map[string]any) error
	// Kinds are the fault kinds this device advertises. A layer plans only
	// kinds that are in here, so a sim too old to know a kind produces a
	// smaller campaign rather than a run full of arm errors.
	Kinds []string
	// Pause and Resume stop and restart the device's animation, which is the
	// cheapest honest comm-loss short of dropping the socket.
	Pause  func(ctx context.Context) error
	Resume func(ctx context.Context) error
}

// Has reports whether the device advertises a fault kind.
func (d DERTarget) Has(kind string) bool {
	for _, k := range d.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// HeadEndTarget is the utility server, with the handle needed to make it
// misbehave.
type HeadEndTarget struct {
	// Name identifies it in evidence.
	Name string
	// Mode arms one of gridsim's fault modes (malform, outage, delay, gone,
	// redirect, paginate, cannotcomply). Nil where no admin API is wired.
	Mode func(ctx context.Context, mode string, on bool, params map[string]any) error
	// Clock warps the head-end's notion of now by an offset in seconds.
	Clock func(ctx context.Context, offsetS int) error
	// Modes are the fault modes this head-end advertises.
	Modes []string
}

// Has reports whether the head-end advertises a mode.
func (h HeadEndTarget) Has(mode string) bool {
	for _, m := range h.Modes {
		if m == mode {
			return true
		}
	}
	return false
}

// DUTTarget is the device under test, as an ATTACK surface. Reading it is the
// invariant World's job and is deliberately not here: this is the half that
// writes, floods and presents hostile credentials.
type DUTTarget struct {
	// Addr is the northbound endpoint, e.g. "69.0.0.2:802".
	Addr string
	// Domain is the trust domain that endpoint belongs to. I5 compares a
	// credential's domain against it.
	Domain string
	// Unit is the served unit that advertises the control model, resolved once
	// by the campaign's setup. Zero means discovery failed and the layers that
	// need a control target plan nothing.
	Unit uint8
	// DERs names the downstream devices this DUT PROJECTS onto its northbound
	// units — the devices a write through this target could reach.
	//
	// It exists because I3's lying-peer exemption has a TARGET clause that has
	// to know it, and for one release nothing populated it: WriteRecord.DERs
	// was left empty by the only production constructor, the exemption's scope
	// check degenerated to "any device's lie excuses anything", and real ghost
	// findings were downgraded to WARN. Empty here is still legal — a campaign
	// that cannot enumerate the projection says so by leaving it empty — and
	// the invariant now fails CLOSED on an unscoped exemption rather than open.
	DERs []string
	// UnitDetail says what happened during that discovery — which is REQUIRED
	// reading when Unit is zero. A silent zero is the failure mode this suite
	// exists to abolish: it makes "the gateway serves no control model", "the
	// credential was refused" and "nobody looked" indistinguishable, and all
	// three then present as three quiet SKIPs.
	UnitDetail string
	// Write attempts a control write with a named credential and reports what
	// the DUT answered. The layer records it in the ledger; the invariants
	// judge it. Nil disables the authz layer.
	Write func(ctx context.Context, cred Credential, unit uint8, point string, value float64) WriteOutcome
	// Present opens a session with a credential and reports whether it
	// authenticated, without writing. It is I5's instrument.
	Present func(ctx context.Context, cred Credential) AuthOutcome
	// Flood opens n concurrent sessions, HOLDS them, and returns how many the
	// DUT served plus a release to close them.
	//
	// Holding rather than opening-and-closing is what makes it a fault instead
	// of a burst. A burst tests the accept path; a held flood tests the thing
	// that actually breaks — whether the session table drains (I8) and whether
	// the port serves again once the pressure stops (I9).
	Flood func(ctx context.Context, n int) (served int, refused int, release func(), err error)
	// Creds are the credentials available to the campaign, in stable order.
	Creds []Credential
}

// Credential is one identity the campaign can present, and what the bench
// believes about it.
type Credential struct {
	// Name is the fixture name, e.g. "read-only" or "expired-gridservice".
	Name string
	// Role is the role it asserts.
	Role string
	// Domain is the trust domain it was issued in.
	Domain string
	// MayWrite records whether this credential is SUPPOSED to be able to write.
	// An accepted write by a credential with MayWrite false is I4's
	// falsification, so getting this wrong turns the invariant into a liar —
	// it is derived from the PKI manifest, never guessed.
	MayWrite bool
	// DenialCause is why a presentation of this credential is expected to be
	// denied; empty for one expected to succeed. I4's indistinguishability arm
	// groups by it.
	DenialCause invariant.DenialCause
}

// WriteOutcome is what the DUT answered a write attempt.
type WriteOutcome struct {
	Accepted     bool
	Refused      bool
	Exception    uint8
	TransportErr string
	ClosedConn   bool
	RTTns        int64
}

// AuthOutcome is what a credential presentation produced.
type AuthOutcome struct {
	// Authenticated means the handshake completed AND the peer then served at
	// least one request. A session that handshakes and is refused everything is
	// NOT authentication — conflating the two would make I5 fire on a device
	// behaving exactly correctly.
	Authenticated bool
	Stage         string
	Exception     uint8
	ClosedConn    bool
	TLSAlert      string
	Detail        string
	RTTns         int64
}

// Inventory is everything a layer may plan against. A layer reads it and
// returns actions; it never probes the bench itself.
type Inventory struct {
	DUT     DUTTarget
	DERs    []DERTarget
	HeadEnd HeadEndTarget
	// Hermetic marks an in-process run. A layer may use it to choose cheaper
	// parameters, but must NOT use it to decide whether to run at all — the
	// point of the hermetic mode is that it exercises the same layers.
	Hermetic bool
}

// DER returns the named device.
func (inv Inventory) DER(name string) (DERTarget, bool) {
	for _, d := range inv.DERs {
		if d.Name == name {
			return d, true
		}
	}
	return DERTarget{}, false
}

// Layer is one family of adversity. A layer's job is to enumerate what it COULD
// do against the inventory; the scheduler decides what actually runs.
type Layer interface {
	// ID is the layer's name, e.g. "peer-lie". It is what -layers selects on.
	ID() string
	// Describe is one sentence: what this layer does and what it is trying to
	// falsify. It appears in -list-layers and in the run header.
	Describe() string
	// Plan enumerates the actions this layer offers against inv. rng is seeded
	// per (campaign seed, layer id), so a layer may randomise parameters and
	// still be reproducible. Plan must be PURE with respect to the bench: it
	// may not dial, arm, or otherwise touch anything.
	Plan(inv Inventory, rng *rand.Rand) []Action
}

// Explainer is the optional half of [Layer]: a layer that offered nothing can
// say WHY, in terms of what was missing from the inventory.
//
// It exists because the generic decline message — "its targets are absent or
// advertise none of the kinds it needs" — is a dead end for an operator. The
// first live campaign declined its entire authz-probe layer, and therefore ran
// with I3, I4 and I5 all skipped, and the manifest gave no way to tell whether
// the gateway had no control model, whether the credential had failed, or
// whether discovery had simply not been attempted. A harness that cannot say
// why it did not test something is one nobody can fix.
type Explainer interface {
	// Explain returns one sentence naming what was missing. It is called only
	// when the layer offered no action.
	Explain(inv Inventory) string
}

// assignSeqs numbers a layer's actions so their ids are unique and stable.
//
// It is IDEMPOTENT: an action that already carries a sequence number keeps it.
// That matters because the shrinker's filtering wrapper numbers a layer's
// output before dropping the actions it is not keeping, and BuildPlan then
// numbers again. Re-numbering the survivors there would renumber them from one
// and break every id the shrinker is tracking — the subset would silently
// become a different experiment.
func assignSeqs(actions []Action) []Action {
	counts := map[string]int{}
	out := make([]Action, 0, len(actions))
	for _, a := range actions {
		key := a.Layer + "/" + a.Kind + "@" + a.Target
		counts[key]++
		if a.seq == 0 {
			a.seq = counts[key]
		}
		out = append(out, a)
	}
	return out
}
