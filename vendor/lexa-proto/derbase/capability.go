package derbase

import (
	"fmt"
	"math"

	"lexa-proto/sunspec"
)

// Capability gating: DENY BY DEFAULT (2026-08-03 audit finding 4, closing the
// half of LXR-005 the first pass left open).
//
// ── What was wrong ───────────────────────────────────────────────────────────
//
// The pre-fix rule was "a NONZERO CtrlModes is enforced exactly; anything else
// falls back to model presence", implemented as
//
//	if !b.HasCap || b.CtrlModes == 0 { return true }   // permit
//
// and fed by sunspec's View.Bitfield32, which returns 0 for a point carrying
// the bitfield32 not-implemented sentinel (0xFFFFFFFF). Those two facts
// compose into a laundering path: a device that says, in the spec's own
// vocabulary, "I do not implement the supported-control-modes point" had that
// statement rewritten to the empty bitfield, which was then read as "no
// declaration", which was then read as "no restriction". Absent 702, empty
// CtrlModes and explicitly-not-implemented CtrlModes all arrived at the same
// destination: permission for every control mode. "Garbage is never
// permission" was the claim; garbage was permission.
//
// ── The rule now ─────────────────────────────────────────────────────────────
//
// AN AXIS IS PERMITTED ONLY BY A POSITIVE CAPABILITY SIGNAL. Three states are
// distinguished and only one of them permits:
//
//	CapSet             702 present, CtrlModes implemented, the mode's bit SET
//	                   → permit. The only permitting state.
//	CapClear           702 present, CtrlModes implemented, the mode's bit
//	                   CLEAR → deny (ErrUnsupportedControl). The device has
//	                   positively declared it does not do this.
//	CapNotImplemented  702 present, CtrlModes at the 0xFFFFFFFF sentinel (or
//	                   truncated out of the block) → deny, naming WHY.
//	CapAbsent          no model 702 at all → deny, naming WHY.
//
// The two denial reasons are deliberately different strings: "702 absent" and
// "CtrlModes not implemented" are different device defects with different
// fixes, and an operator reading a CannotComply needs to know which one they
// have.
//
// ── The legacy allowlist (and why it is not a hole) ──────────────────────────
//
// A 704-less/702-less legacy inverter — the bench's inv-legacy shape, der_gen
// "12x", model chain 1,120,121,122,103,123 — is legitimately controlled
// through M123 WMaxLimPct and M123 Conn. It has no 702 to claim anything with,
// so a flat "no positive 702 signal ⇒ no control" would brick every legacy
// device on the bench and in the field.
//
// THE ALLOWLIST RULE: the M123 limit and connect plans remain available
// without a 702 capability claim when, and only when, the device's MEASURED
// model scan shows the legacy shape — M123 present AND model 702 absent AND
// model 704 absent (see LegacyM123Shape). It is keyed on measured model
// presence, never on silence: a device that publishes 702 is a device that CAN
// make a claim, so it MUST, and its M123 ceiling is gated on MAX_W like any
// other axis. A device that publishes 704 is not legacy at all.
//
// Everything in the 7xx family goes the other way. write704 and every 7xx
// ApplyControl axis require the positive 702 signal; there is no fallback,
// no "the device is probably fine", and no path by which absence becomes
// permission.
//
// Two axes are outside this scheme because model 702 has no bit for them:
// opModEnergize (model 703 enter service) and opModConnect (M123 Conn). The
// CtrlModes bitfield defines MAX_W, FIXED_W, FIXED_VAR, FIXED_PF, VOLT_VAR,
// FREQ_WATT, DYN_REACT_CURR, LV/HV/LF/HF_TRIP, WATT_VAR, VOLT_WATT and
// SCHEDULED — and nothing for enter-service or connect. Gating them on a
// claim the spec gives a device no way to make would be denial by
// construction, so both stay gated on model presence, which is itself a
// measured positive signal.

// CtrlModesNotImplemented is the value Base.CtrlModes carries when the device
// did NOT tell us its supported control modes — model 702's CtrlModes point
// read the SunSpec bitfield32 not-implemented sentinel, or the block was too
// short to contain it.
//
// It is the raw sentinel rather than a separate bool so that a Base built by
// hand (tests, consumers assembling a device snapshot) cannot accidentally
// express "not implemented" as the zero value: the zero value of CtrlModes is
// the empty bitfield, which is CapClear — a denial — and the zero value of
// HasCap is false, which is CapAbsent — also a denial. A zero Base denies
// everything, which is what deny-by-default means.
//
// The all-ones pattern is not a legitimate declaration: SunSpec reserves it as
// the not-implemented sentinel for every bitfield32 point, and only 14 of the
// 32 bits are defined, so a device putting 0xFFFFFFFF on the wire is saying
// "not implemented", not "all modes".
const CtrlModesNotImplemented = uint32(0xFFFFFFFF)

// CapClaim is the three-state disposition of a device's model 702 capability
// declaration for one control mode. Exactly one of the four values permits.
type CapClaim uint8

const (
	// CapAbsent: the device implements no model 702. There is no capability
	// claim to evaluate, and no claim is not a claim of capability.
	CapAbsent CapClaim = iota
	// CapNotImplemented: model 702 is present but leaves CtrlModes at the
	// bitfield32 not-implemented sentinel (or truncates the block before it).
	// The device has explicitly declined to say what it supports.
	CapNotImplemented
	// CapClear: CtrlModes is implemented and the requested mode's bit is
	// CLEAR. The device positively declares it does not do this mode.
	CapClear
	// CapSet: CtrlModes is implemented and the requested mode's bit is SET.
	// The only state that permits an axis.
	CapSet
)

func (c CapClaim) String() string {
	switch c {
	case CapAbsent:
		return "702-absent"
	case CapNotImplemented:
		return "ctrlmodes-not-implemented"
	case CapClear:
		return "ctrlmodes-bit-clear"
	case CapSet:
		return "ctrlmodes-bit-set"
	}
	return fmt.Sprintf("CapClaim(%d)", uint8(c))
}

// Permits reports whether this claim permits an axis. Only CapSet does.
func (c CapClaim) Permits() bool { return c == CapSet }

// reason renders the WHY for a denial, naming the device defect rather than
// restating the verdict. mode is the CtrlModes symbol ("FIXED_PF", "MAX_W", …).
func (c CapClaim) reason(mode string) string {
	switch c {
	case CapAbsent:
		return "702 absent: the device implements no M702 (DERCapacity), so it declares no " +
			mode + " capability — an axis is permitted only by a positive capability signal"
	case CapNotImplemented:
		return "CtrlModes not implemented: M702 is present but leaves the supported-control-modes " +
			"bitfield at the SunSpec not-implemented sentinel (0xFFFFFFFF), so it declares no " +
			mode + " capability"
	case CapClear:
		// Unchanged from the pre-fix wording: this is the one state that was
		// already handled correctly, and operator log-greps depend on it.
		return "device CtrlModes does not declare " + mode
	}
	return "capability claim permits " + mode
}

// CtrlModeClaim reports the device's three-state 702 capability claim for one
// control-mode bit (sunspec.M702_CtrlMode_*). It never guesses: every state
// the device could be in maps onto exactly one CapClaim.
func (b *Base) CtrlModeClaim(bit uint32) CapClaim {
	switch {
	case !b.HasCap:
		return CapAbsent
	case b.CtrlModes == CtrlModesNotImplemented:
		return CapNotImplemented
	case b.CtrlModes&bit == 0:
		return CapClear
	}
	return CapSet
}

// requireCtrlMode is the preflight gate: nil only on a positive claim, and a
// typed UnsupportedControlError naming the specific device defect otherwise.
func (b *Base) requireCtrlMode(axis string, bit uint32, mode string) error {
	c := b.CtrlModeClaim(bit)
	if c.Permits() {
		return nil
	}
	return &UnsupportedControlError{Axis: axis, Reason: c.reason(mode)}
}

// DeclaresCtrlModes reports whether the device made a supported-control-modes
// declaration AT ALL: model 702 present and its CtrlModes point implemented.
// It says nothing about which modes — that is CtrlModeClaim — only that there
// is a claim to consult. A device for which this is false has told us nothing
// about its 7xx control surface, and nothing is not permission.
func (b *Base) DeclaresCtrlModes() bool {
	return b.HasCap && b.CtrlModes != CtrlModesNotImplemented
}

// requireCtrlModesDeclaration is the claim-LEVEL gate used where the caller
// does not know which mode it is serving (write704). It distinguishes the two
// silent states so the error names WHY, exactly as the per-bit gate does.
func (b *Base) requireCtrlModesDeclaration(axis string) error {
	switch {
	case !b.HasCap:
		return &UnsupportedControlError{Axis: axis, Reason: CapAbsent.reason("any 7xx control mode")}
	case b.CtrlModes == CtrlModesNotImplemented:
		return &UnsupportedControlError{Axis: axis, Reason: CapNotImplemented.reason("any 7xx control mode")}
	}
	return nil
}

// LegacyM123Shape reports whether the device presents the LEGACY control shape
// that the M123 allowlist covers: model 123 (immediate controls) present, and
// neither model 702 nor model 704 present.
//
// This is the allowlist key, and it is a MEASUREMENT — three model-presence
// facts from the discovery scan, all of which the device asserted by
// publishing (or not publishing) a model header. It is never keyed on a silent
// or empty field inside a model the device does publish: a device carrying 702
// can make a capability claim and is therefore required to, and a device
// carrying 704 is not legacy in the first place.
//
// The shape it recognises is the bench's inv-legacy inverter (der_gen "12x",
// model chain 1,120,121,122,103,123) and every plain Modbus PV inverter like
// it: no capability model to consult, one active-power ceiling and one connect
// register, both of which the M123 plans write and PROVE by read-back.
func (b *Base) LegacyM123Shape() bool {
	return b.Reader != nil && b.Reader.HasModel(sunspec.ModelImmediateCtrl) &&
		!b.Has702 && !b.Has704
}

// ── Rating bounds: the same three states, one level down ─────────────────────
//
// Model 702's rating points (PFOvrExtRtg, WChaRteMaxRtg, …) are magnitude
// bounds, not permissions — the axis they refine is already deny-by-default
// above. They still get the three-state treatment, because the pre-fix guards
// (`minRated > 0 && minRated <= 1`, `r > 0`) silently DISABLED the bound for
// every value outside the window they expected. A device declaring a rated PF
// of 1.5 had its own claim discarded and was then commanded to any PF at all,
// which is the same garbage-becomes-permission shape one level down.
//
// Both readers share the first two states and differ on the third, because
// zero means opposite things in a MINIMUM rating and a MAXIMUM one:
//
//	NaN            absent / not-implemented sentinel / unusable scale factor.
//	               No bound from this rating. Honest unknown — and no longer
//	               the last line of defence, because the axis needed a positive
//	               CtrlModes bit to reach the rating check at all.
//	out of domain  an implemented rating that cannot be true (a rated PF above
//	               1, anything negative or non-finite). The claim is garbage,
//	               and a garbage claim is not a bound to relax: DENY.
//	zero           minRatingBound: a rated MINIMUM of 0 is "no floor" — the
//	               device supports the whole domain. No bound, no denial.
//	               maxRatingBound: a rated MAXIMUM of 0 is the device saying
//	               its maximum rate is zero, i.e. it cannot do this at all:
//	               DENY.

// minRatingBound reads a rating that is a LOWER bound on what the device
// supports (702's rated minimum power factors). ok=false means no floor.
func minRatingBound(axis, point string, v, domainMax float64) (float64, bool, error) {
	if math.IsNaN(v) {
		return 0, false, nil // absent / not implemented / unusable SF
	}
	if math.IsInf(v, 0) || v < 0 || v > domainMax {
		return 0, false, outOfDomainRating(axis, point, v)
	}
	if v == 0 {
		return 0, false, nil // no floor declared; the whole domain is supported
	}
	return v, true, nil
}

// maxRatingBound reads a rating that is an UPPER bound on what the device can
// do (702's rated max charge/discharge rates). An implemented zero is a
// positive declaration of incapacity, not an absence.
//
// Field-triage note: firmware that zero-fills unimplemented 702 points instead
// of writing the 0xFFFF sentinel will now be REFUSED on the axis that rating
// bounds. That is the intended direction — the refusal surfaces as a
// CannotComply rather than as an unbounded command to a device that told us it
// cannot take one — and the conformant fix on the device side is to declare
// the rating or leave it at the not-implemented sentinel.
func maxRatingBound(axis, point string, v float64) (float64, bool, error) {
	if math.IsNaN(v) {
		return 0, false, nil // absent / not implemented / unusable SF
	}
	if math.IsInf(v, 0) || v < 0 {
		return 0, false, outOfDomainRating(axis, point, v)
	}
	if v == 0 {
		return 0, false, &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
			"device declares %s = 0 W: its rated maximum for this axis is zero, so it positively "+
				"declares it cannot perform the axis", point)}
	}
	return v, true, nil
}

func outOfDomainRating(axis, point string, v float64) error {
	return &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
		"device declares an out-of-domain %s rating (%g); a capability claim that cannot be true "+
			"is not a bound to relax", point, v)}
}
