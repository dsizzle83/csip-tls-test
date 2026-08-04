package derbase

import (
	"fmt"
	"math"
	"strings"
)

// Actuation plans (LXR-012): measured, ordered, whole-request device writes.
//
// A CSIP control axis is almost never ONE register. The legacy active-power
// ceiling is three (ramp time, value, enable); a 704 ceiling is a whole-block
// read-modify-write; a request can carry several axes at once. Every one of
// those writes can be accepted and not applied, accepted and applied to
// something else, or lost half-way — which means "no error came back" says
// nothing about what the device is doing. An actuation plan is the unit that
// makes it say something.
//
// Every plan runs the same three phases:
//
//	preflight  validate the WHOLE request — model presence, block length,
//	           corrupt-read gate, scale-factor domain, encode representability,
//	           nameplate — and snapshot the device's pre-state. A preflight
//	           failure writes NOTHING: a request that cannot be executed in
//	           full must not be executed in part (the LXR-002 precedent).
//	execute    write the elements in restrictive-first order, enable last, so
//	           every intermediate state of the sequence is at least as safe as
//	           the state the plan started from.
//	classify   re-read the touched elements and decide from the READING what
//	           happened.
//
// ── THE LOAD-BEARING RULE ────────────────────────────────────────────────────
//
// The partial-state verdict is MEASURED, NOT INFERRED. Execute re-reads the
// touched elements after any failure and classifies from that reading — never
// from which write returned an error. The two directions this cuts are both
// real device behaviour and both were mis-handled before:
//
//   - A write that returned an error may still have LANDED (the exception came
//     back on the response, or the ACK was lost, not the command). Inferring
//     "errored ⇒ not applied" would report a device as un-actuated while it
//     executes the command, and would send a compensating write to a device
//     that does not need one.
//   - A write that returned success may have been DROPPED (accepted-and-
//     ignored is a real and common firmware behaviour). Inferring "no error ⇒
//     applied" is how an uncurtailed inverter gets reported to a head end as
//     Started — the exact defect this file exists to close.
//
// And the third state is genuine: an element whose post-state CANNOT BE READ
// is Unverified, never Failed. "The device stopped answering" is not evidence
// that the write did not take effect; classifying it as Failed would invite a
// corrective write toward a state the device may already have left, and would
// report a definite verdict the plan does not hold. Unverified is a first-
// class outcome that callers must treat as unproven in BOTH directions.
//
// Compensation (plan §5, adopted decision D1) is likewise bounded: only
//
//	(a) ONE bounded re-attempt of the completing element — this COMPLETES the
//	    operator's command and is not a compensating move at all; or
//	(b) writing the MORE RESTRICTIVE of {pre-state, achieved state}.
//
// Never anything toward less restrictive; if neither applies, the plan
// freezes the device where it is and DECLARES the mixed state with a typed
// PartialActuationError. Reverting the enable is deliberately NOT an option:
// the staged value is inert while the enable is off, so reverting discards a
// more-restrictive staged value and risks a later loose latch.

// ElementState is the disposition of one plan element after the plan has
// re-read the device. It is a MEASURED verdict — see the load-bearing rule
// above — not a record of which write returned an error.
type ElementState uint8

const (
	// ElementNotAttempted: no write was issued for this element. Either the
	// plan aborted before reaching it, or an earlier element failed in a way
	// that made continuing unsafe (never enable a value that is not proven).
	ElementNotAttempted ElementState = iota
	// ElementApplied: the device MEASURABLY holds this element's intended
	// value. Nothing else is Applied — not an ACK, not the absence of an
	// error (LXR-006: absence of failure evidence is not success).
	ElementApplied
	// ElementUnverified: the element was written but its post-state could not
	// be READ (device went dark, read errored, block came back short). We do
	// not know what the device is doing; both "applied" and "failed" would be
	// fabrications.
	ElementUnverified
	// ElementFailed: the post-state WAS read and does not carry the intended
	// value.
	ElementFailed
	// ElementCompensated: the element was not applied, and the plan moved the
	// device to a compensating state that is no less restrictive than the one
	// it found (§5(b)).
	ElementCompensated
)

func (s ElementState) String() string {
	switch s {
	case ElementNotAttempted:
		return "not-attempted"
	case ElementApplied:
		return "applied"
	case ElementUnverified:
		return "unverified"
	case ElementFailed:
		return "failed"
	case ElementCompensated:
		return "compensated"
	}
	return fmt.Sprintf("ElementState(%d)", uint8(s))
}

// ElementOutcome is what a plan learned about one register element.
//
// Before/After are MEASURED engineering values, read from the device before
// the first write and after the last one. NaN means "not known" — the point
// was unreadable, unimplemented, or carried a sentinel — and must never be
// laundered into a number by a consumer.
//
// Advisory carries context that is not a failure of the actuation (a ramp
// time the device did not adopt, a grouped write it refused, an element that
// only landed on the plan's one bounded re-attempt). Err carries the write
// error, which is diagnostic only: State is measured, so an element can carry
// a non-nil Err and still be Applied — that is the point.
//
// Sub is the element's OWN plan outcome when the element is itself a plan —
// the case a plan of plans produces (ApplyControlPlan's per-axis elements,
// where the M123 limit and connect axes each run a full measuring plan). It is
// nil for a leaf element and for an axis whose writer does not measure, and a
// consumer must read the nil as "this level holds no measurement", never as
// "nothing happened".
type ElementOutcome struct {
	Name     string
	Model    uint16
	State    ElementState
	Before   float64
	After    float64
	Advisory string
	Err      error
	Sub      *PlanOutcome
}

// addAdvisory appends one advisory to an element, keeping any already there.
// Advisories accumulate rather than replace because they are independent facts
// about one element — "this ceiling min-combined three axes", "it landed on the
// bounded re-attempt", "its sub-plan is applied-degraded" can all be true at
// once, and a caller that is shown only the last one is missing evidence.
func addAdvisory(e *ElementOutcome, s string) {
	if s == "" {
		return
	}
	if e.Advisory == "" {
		e.Advisory = s
		return
	}
	e.Advisory += "; " + s
}

// PlanOutcome is the whole-plan verdict.
//
// Mixed means the device was measured in NEITHER the state the plan found it
// in NOR the state it was commanded into: an actuation stopped part-way and
// the device is now in a state nobody asked for. It is the verdict a caller
// must escalate — a mixed-state device cannot be reported as Started, and its
// full nameplate has to be reserved because what it will do next is unknown.
//
// LessRestrictiveThanIntended means the state the device was LEFT in holds it
// back less than the commanded state would have. It is the safety-relevant
// half of Mixed and is set independently: a plan can fail cleanly (device
// exactly where it started) and still leave the site less restricted than the
// head end believes.
type PlanOutcome struct {
	Tag                         string
	Plan                        string
	Elements                    []ElementOutcome
	Mixed                       bool
	LessRestrictiveThanIntended bool
}

// Element returns the outcome of the named element, and whether the plan has
// one by that name.
func (o PlanOutcome) Element(name string) (ElementOutcome, bool) {
	for _, e := range o.Elements {
		if e.Name == name {
			return e, true
		}
	}
	return ElementOutcome{}, false
}

// State returns the measured state of the named element (ElementNotAttempted
// when the plan has no such element).
func (o PlanOutcome) State(name string) ElementState {
	e, _ := o.Element(name)
	return e.State
}

// Degraded reports whether any element is not Applied. On a plan that
// returned a nil error this is the applied-DEGRADED shape (D9): the
// load-bearing actuation is measured in force, an advisory element is not, and
// the control may be reported as started with the degradation on the report.
//
// The applied verdict itself is the plan's returned error: nil means the
// commanded state was measured in force on the device, and nothing else does.
func (o PlanOutcome) Degraded() bool {
	for _, e := range o.Elements {
		if e.State != ElementApplied {
			return true
		}
	}
	return false
}

func (o PlanOutcome) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%s:", o.Tag, o.Plan)
	for _, e := range o.Elements {
		fmt.Fprintf(&b, " %s=%s(%g→%g)", e.Name, e.State, e.Before, e.After)
	}
	if o.Mixed {
		b.WriteString(" MIXED")
	}
	if o.LessRestrictiveThanIntended {
		b.WriteString(" LESS-RESTRICTIVE-THAN-INTENDED")
	}
	return b.String()
}

// firstElementErr returns the first write error recorded on any element, so a
// plan that failed without leaving a mixed state can return the device's own
// error rather than inventing one.
func firstElementErr(o PlanOutcome) error {
	for _, e := range o.Elements {
		if e.Err != nil {
			return e.Err
		}
	}
	return nil
}

// worstElementState collapses a plan's element states into the single verdict
// an ENCLOSING plan should record for it (a plan of plans — see
// ApplyControlPlan). The order is by how much the state constrains what the
// caller may conclude, worst first: a measured contradiction (Failed) outranks
// an unreadable post-state (Unverified), which outranks an element the plan
// never got to (NotAttempted), which outranks a compensated one, which
// outranks Applied. An empty plan measured nothing, so it reports
// NotAttempted rather than a vacuous Applied.
func worstElementState(o PlanOutcome) ElementState {
	if len(o.Elements) == 0 {
		return ElementNotAttempted
	}
	worst := ElementApplied
	rank := func(s ElementState) int {
		switch s {
		case ElementFailed:
			return 4
		case ElementUnverified:
			return 3
		case ElementNotAttempted:
			return 2
		case ElementCompensated:
			return 1
		}
		return 0 // ElementApplied
	}
	for _, e := range o.Elements {
		if rank(e.State) > rank(worst) {
			worst = e.State
		}
	}
	return worst
}

// ── The never-less-restrictive ordering ──────────────────────────────────────

// ceilingRestriction scores how much a measured active-power ceiling holds a
// device back. SMALLER IS MORE RESTRICTIVE; +Inf means "no limit is in force
// at all", which is the least restrictive state a ceiling axis has.
//
// Every "cannot interpret" case scores +Inf on purpose. An unreadable or
// sentinel value is not evidence of a limit, and the compensation rule only
// ever moves the device toward a STRICTLY more restrictive score — so scoring
// the unknown as unrestricted is safe in both roles it appears in:
//
//   - as the ACHIEVED state it assumes the worst (the device may be running
//     free), which is the assumption that triggers escalation;
//   - as the PRE state it makes the pre-state ineligible as a compensation
//     target, so the plan freezes and declares instead of writing back a
//     value it could not interpret.
//
// pct is a percent of the nameplate; the magnitude is what bounds the device,
// and a value that decodes out of that domain lands on NaN/±Inf and scores
// unrestricted, above. Abs() is kept rather than assuming a non-negative
// reading: it is the decoded DEVICE state, and a device that hands back a
// negative word must not score as more restrictive than one holding zero.
func ceilingRestriction(pct float64, enabled bool) float64 {
	if !enabled || math.IsNaN(pct) || math.IsInf(pct, 0) {
		return math.Inf(1)
	}
	return math.Abs(pct)
}

// strictlyMoreRestrictive reports whether a holds the device back strictly
// more than b — the only direction a compensating write is ever allowed to
// move a device (§5(b)). Equal scores are NOT more restrictive: there is
// nothing to gain and a needless write to a device already in a partial state
// is its own hazard.
func strictlyMoreRestrictive(a, b float64) bool { return a < b }
