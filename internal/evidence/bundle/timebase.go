package bundle

// timebase.go carries the CLOCK CHANNEL into the bundle: what clock the
// fixture's timers actually counted against while the evidence was taken, and
// whether that clock was the wall one.
//
// # Why a channel and not a sentence in a note
//
// The bench can accelerate a device-side timer. sim/southbound's model 704
// reversion engine runs against an injectable ReversionTimebase — 1×/wall by
// default, and accelerable only by Go code calling SetReversionTimebase — so a
// 900-second reversion can be proven in a second of real time. That capability
// is legitimate and carefully fenced, and it comes with an obligation: an
// accelerated run proves the HARNESS's expiry semantics and says nothing
// whatever about a real device's timing, so a reader must be able to tell the
// two apart WITHOUT being told by whoever ran it.
//
// The fence used to be a self-declaration and nothing else: the timebase's
// label rode on the sim's GET /state, and that was the entire mechanism. Two
// holes, both found by an adversarial gate (IW15 H6):
//
//	(a) the label was UNPINNED. Rewriting ScaledTimebase.Label() to return the
//	    flat lie "wall" left every test in the tree green — `go test
//	    ./sim/southbound/` reported ok. A self-declaration that nothing asserts
//	    is decoration.
//	(b) the label NEVER REACHED THE EVIDENCE. It lived only in a live HTTP
//	    response that no bundle carries, and neither this package nor
//	    `certify -verify` knew the word "timebase". An accelerated bundle and a
//	    wall-clock bundle were, on their face and to the verifier, the same
//	    document.
//
// So the declaration is recorded IN the bundle at capture time, rendered in
// REPORT.md where a human reads it, and re-derived by Verify — the same shape
// the metrics channel uses (metrics.go): the summary goes in bundle.json, and
// Verify re-derives the summary rather than believing it.
//
// # What "re-derived" means for a clock, and where the wording lives
//
// A scrape record is re-derivable against the exposition bodies shipped beside
// it. A clock has no bytes: it is a property of the run, gone by the time
// anyone reads the bundle. What CAN be re-derived is the AGREEMENT between the
// machine-readable half of the declaration (kind, scale, elapsed) and the prose
// half (the label a human reads and a /state consumer sees) — so the prose is
// not the fixture's to choose. Render below owns every word of it, the fixture
// obtains its label by calling these constructors, and Verify recomputes the
// label from the numbers and refuses a bundle where the two disagree.
//
// That is what closes (a) structurally rather than by exhortation: a fixture
// cannot spell its own acceleration "wall", because it does not spell it at
// all. The literal strings are additionally pinned by a test
// (timebase_pin_test.go), so a change to the wording is a change somebody had
// to make on purpose and defend in review.
//
// # What this channel does NOT establish
//
// It records what the fixture said about its own clock, checked for internal
// consistency. It cannot prove the fixture told the truth — the same limit the
// metrics channel states about counters, for the same reason: there is no
// independent instrument in the bundle to check it against. What it does
// guarantee is that an accelerated run cannot QUIETLY look like a wall-clock
// one: the declaration is in bundle.json, under the manifest, printed on the
// report's face, and re-derived by the verifier.
//
// # Absence
//
// A bundle carrying no declaration at all — every bundle written before this
// channel existed, and every producer that has not been taught to record one —
// verifies exactly as it did before, and the verifier DISCLOSES the silence
// rather than treating it as a failure ("this bundle does not state what clock
// its timers ran on"). Absence of a declaration is a gap in what the bundle
// tells you, not evidence of tampering, and a verifier that conflated the two
// would be unusable against the archive.

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// TimebaseKind is the shape of clock a fixture ran its timers against. It is
// the machine-readable half of a declaration: Render turns it, plus the scale
// or elapsed figure, into the sentence a human reads.
type TimebaseKind string

// The kinds a declaration may take. A bundle naming any other kind does not
// verify: the verifier cannot re-derive a label for a clock it has never heard
// of, and passing it anyway would be the "unrecognised means fine" hole in a
// different costume.
const (
	// TimebaseWall is real time, unscaled — the default of every shipped path
	// and the only clock a claim about a real device's timing may rest on.
	TimebaseWall TimebaseKind = "wall"
	// TimebaseScaled is a fixed multiple of the wall clock, running from the
	// moment the timebase was constructed.
	TimebaseScaled TimebaseKind = "scaled"
	// TimebaseManual is simulated time that advances only when the test says
	// so. It has no rate at all, which is why Scale is zero for it rather than
	// some notional multiplier.
	TimebaseManual TimebaseKind = "manual"
)

// Timebase is one fixture's declaration of the clock its timers ran against.
//
// Build one through DeclareWall / DeclareScaled / DeclareManual. Those fill
// Label from Render, which is what makes the label and the numbers incapable of
// disagreeing at the point of authorship; Verify then re-checks the same
// property on the bundle as read back, which is what makes an EDIT to either
// half visible.
type Timebase struct {
	// Component names whose clock this is, in enough detail for a reader to go
	// and look at it — "sim/southbound: model 704 reversion engine". Required:
	// a declaration that does not say whose clock it describes cannot be acted
	// on by anybody.
	Component string `json:"component"`
	// Kind, Scale and ElapsedS are the machine-readable half.
	Kind  TimebaseKind `json:"kind"`
	Scale float64      `json:"scale"`
	// ElapsedS is how far a manual clock had been advanced when the
	// declaration was taken. It is meaningless for the other kinds and must be
	// zero there.
	ElapsedS float64 `json:"elapsed_s,omitempty"`
	// Label is the human half — the exact sentence the fixture publishes about
	// itself (sim/southbound puts it on GET /state). It is written by Render,
	// never composed by the fixture, and Verify recomputes it.
	Label string `json:"label"`
	// Source records how the declaration was obtained: an in-process handle, a
	// GET /state read, the URL it came from. Optional — a declaration without
	// provenance is weaker but not inconsistent, and the report says "—" rather
	// than inventing one.
	Source string `json:"source,omitempty"`
}

// Accelerated reports whether this clock was anything other than real time.
// Both non-wall kinds are accelerated: a manual clock is not "slower", it is
// unmoored from the wall entirely, and a reader must treat both the same way.
func (t Timebase) Accelerated() bool { return t.Kind != TimebaseWall }

// Render is the CANONICAL wording of a declaration, and the single place any of
// these sentences exist.
//
// The wording is deliberately the evidence package's rather than the fixture's.
// A fixture that composed its own sentence could compose "wall" while running
// at 900× — which is exactly the mutation the gate made and nothing caught. Here
// the label is a function of the numbers, so the only way to make a bundle say
// "wall" is for it to BE wall.
//
// The strings are held byte-identical to what sim/southbound published before
// this channel existed, so a reader comparing an old /state capture with a new
// bundle sees the same sentence, and so that this change re-words nothing while
// it re-homes it.
func (t Timebase) Render() string {
	switch t.Kind {
	case TimebaseWall:
		return "wall"
	case TimebaseScaled:
		return fmt.Sprintf("scaled %.4g× (ACCELERATED TEST TIME — proves this harness's expiry semantics, "+
			"NOT any real device's timing)", t.Scale)
	case TimebaseManual:
		return fmt.Sprintf("manual (ACCELERATED TEST TIME, t+%.3fs — proves this harness's expiry "+
			"semantics, NOT any real device's timing)", t.ElapsedS)
	default:
		return ""
	}
}

// Check reports why a declaration is not internally consistent, or nil.
//
// Every rule here is a way a declaration could be made to UNDERSTATE the
// acceleration, which is the only direction that matters: a bundle overstating
// how synthetic its clock was costs its own claims and fools nobody.
func (t Timebase) Check() error {
	if strings.TrimSpace(t.Component) == "" {
		return fmt.Errorf("names no component, so it does not say whose clock it describes")
	}
	switch t.Kind {
	case TimebaseWall:
		if t.Scale != 1 {
			return fmt.Errorf("declares the WALL clock at scale %v; real time is 1× by definition, and a "+
				"scaled clock must declare kind %q", t.Scale, TimebaseScaled)
		}
		if t.ElapsedS != 0 {
			return fmt.Errorf("declares the wall clock with %vs of simulated elapsed time, which only a "+
				"manual clock has", t.ElapsedS)
		}
	case TimebaseScaled:
		if !(t.Scale > 0) || math.IsInf(t.Scale, 0) {
			return fmt.Errorf("declares a scaled clock at %v; a scale must be a positive, finite multiplier", t.Scale)
		}
		if t.ElapsedS != 0 {
			return fmt.Errorf("declares a scaled clock with %vs of simulated elapsed time, which only a "+
				"manual clock has", t.ElapsedS)
		}
	case TimebaseManual:
		if t.Scale != 0 {
			return fmt.Errorf("declares a manual clock at scale %v; manual time advances only when a test "+
				"advances it and has no rate, so its scale is 0", t.Scale)
		}
		if t.ElapsedS < 0 || math.IsNaN(t.ElapsedS) || math.IsInf(t.ElapsedS, 0) {
			return fmt.Errorf("declares a manual clock advanced by %vs, which is not a duration a clock "+
				"can have run for", t.ElapsedS)
		}
	default:
		return fmt.Errorf("declares clock kind %q, which this verifier does not recognise and therefore "+
			"cannot re-derive a label for", t.Kind)
	}
	if want := t.Render(); t.Label != want {
		return fmt.Errorf("is labelled %q, but a %s clock of scale %v renders as %q — the label and the "+
			"numbers in this declaration describe different clocks",
			t.Label, t.Kind, t.Scale, want)
	}
	return nil
}

// DeclareWall declares real, unscaled time.
func DeclareWall(component, source string) Timebase {
	t := Timebase{Component: component, Kind: TimebaseWall, Scale: 1, Source: source}
	t.Label = t.Render()
	return t
}

// DeclareScaled declares a clock running scale× the wall clock.
//
// It refuses a scale that is not a positive finite multiplier rather than
// coercing it: a declaration nobody can re-derive is worse than no declaration,
// because it looks like one.
func DeclareScaled(component, source string, scale float64) (Timebase, error) {
	t := Timebase{Component: component, Kind: TimebaseScaled, Scale: scale, Source: source}
	t.Label = t.Render()
	if err := t.Check(); err != nil {
		return Timebase{}, fmt.Errorf("bundle: refusing a timebase declaration that %w", err)
	}
	return t, nil
}

// DeclareManual declares simulated time advanced by hand, and records how far
// it had been advanced when the declaration was taken.
func DeclareManual(component, source string, elapsed time.Duration) Timebase {
	t := Timebase{Component: component, Kind: TimebaseManual, ElapsedS: elapsed.Seconds(), Source: source}
	t.Label = t.Render()
	return t
}

// AddTimebase records one fixture's clock declaration in the bundle under
// construction.
//
// Call it at CAPTURE TIME, from the code that installed (or read back) the
// clock: that code is the only party that knows, and the whole point of the
// channel is that the knowledge travels with the evidence instead of staying in
// the operator's head. See sim/southbound's RecordTimebase for the one-call
// form a run using an accelerated fixture uses.
func (b *Builder) AddTimebase(t Timebase) { b.timebases = append(b.timebases, t) }

// Timebases returns the declarations recorded so far.
func (b *Builder) Timebases() []Timebase { return b.timebases }

// checkTimebases refuses to WRITE a bundle carrying a declaration that
// contradicts itself.
//
// Defence in depth, and cheap: the constructors already render the label, so
// the only way to reach this is a caller assembling the struct by hand. Failing
// at authorship time is far better than shipping a bundle that fails
// verification in a reviewer's hands, where the finding reads as tampering
// rather than as the mistake it was.
func checkTimebases(ts []Timebase) error {
	for _, t := range ts {
		if err := t.Check(); err != nil {
			return fmt.Errorf("bundle: the timebase declaration for %q %w", t.Component, err)
		}
	}
	return nil
}

// verifyTimebases re-derives every recorded clock declaration and records what
// it found in rep.
//
// Two outcomes, and the difference between them is the whole design:
//
//   - A declaration whose label does not follow from its own numbers — or whose
//     numbers are not a clock anyone could have run — is a VERIFICATION FAILURE.
//     That is the "accelerated bundle relabelled as wall-clock" case.
//   - A bundle with NO declaration is not a failure. It is disclosed
//     (rep.TimebaseUndeclared, printed by String and by `certify -verify`) so a
//     reader knows the bundle is silent on the question, which is exactly what
//     every bundle written before this channel existed is.
func verifyTimebases(b *Bundle, rep *VerifyReport) {
	if len(b.Timebases) == 0 {
		rep.TimebaseUndeclared = true
		return
	}
	for _, t := range b.Timebases {
		rep.TimebasesDeclared++
		if t.Accelerated() {
			rep.TimebasesAccelerated++
		}
		if err := t.Check(); err != nil {
			rep.problem(fmt.Sprintf("the timebase declaration for %q %v", t.Component, err))
			rep.OK = false
		}
	}
}

// timebaseReport renders the clock channel for REPORT.md.
//
// An accelerated run gets a banner, in the same place and the same voice as the
// key-log warning above it, because it is the same class of fact: something a
// reader must know before they read anything else, which nothing in the tables
// below would tell them. A wall-clock declaration gets a quiet line — it is the
// unremarkable case, and shouting about it would train readers to skip the
// banner that matters.
func (b *Bundle) timebaseReport(sb *strings.Builder) {
	if len(b.Timebases) == 0 {
		return
	}
	accel := 0
	for _, t := range b.Timebases {
		if t.Accelerated() {
			accel++
		}
	}
	fmt.Fprintf(sb, "## Fixture timebase\n\n")
	if accel > 0 {
		fmt.Fprintf(sb, "> **THIS RUN DID NOT RUN ON THE WALL CLOCK.** %d of %d declared fixture clock(s)\n"+
			"> below are ACCELERATED TEST TIME. Every timing claim in this bundle that rests on one of\n"+
			"> them is a claim about THIS HARNESS's expiry semantics — that a timer arms, counts down,\n"+
			"> expires and reverts — and is NOT evidence about any real device's timing. Nothing here\n"+
			"> establishes that firmware honours a reversion time to any tolerance, survives clock\n"+
			"> drift, or behaves across a comms outage; only a run on the device's own wall clock can.\n\n",
			accel, len(b.Timebases))
	}
	fmt.Fprintf(sb, "| Component | Clock | Declared as | Read from |\n|---|---|---|---|\n")
	for _, t := range b.Timebases {
		fmt.Fprintf(sb, "| %s | %s | %s | %s |\n",
			mdEscape(t.Component), string(t.Kind), mdEscape(t.Label), mdEscape(orDash(t.Source)))
	}
	fmt.Fprintf(sb, "\nThe verifier recomputes each label above from the kind and scale recorded beside it, so a\n"+
		"declaration cannot be re-worded without the bundle ceasing to verify. It cannot, and does not,\n"+
		"establish that the fixture reported its own clock honestly.\n\n")
}
