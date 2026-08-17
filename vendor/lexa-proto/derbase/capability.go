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
// ── The rule holds at EVERY exported writer (round-2 audit F2) ───────────────
//
// The rule above says "every 7xx axis requires its positive M702 CtrlModes
// bit", and for one release it was enforced in preflightControl and NOWHERE
// ELSE. The exported writers are reachable directly — lexa-hub's reconciler
// calls SetFixedPF, SetConstantVar, SetWMaxLimPctW and the curve writers
// without going through ApplyControl — and they checked strictly less:
//
//	write704       only that SOME CtrlModes declaration existed, because it
//	               did not know which axis it was serving. A device declaring
//	               MAX_W and nothing else therefore accepted a fixed-PF write.
//	curve writers  only model presence. A device declaring MAX_W and nothing
//	               else accepted a volt-var curve, adopted it, and ENABLED it.
//
// A gate that only one caller passes through is not a gate. Every exported
// writer now names the mode(s) it is about to write and requires each one's
// bit: write704 takes the UNION of bits for the fields the write touches (one
// per control function — a PF write needs FIXED_PF, a var write FIXED_VAR),
// and each curve writer requires its own function's bit. requireCtrlModes is
// the single place that decision is made, so a new writer cannot forget it
// without failing to compile.
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

// ctrlMode pairs one M702 CtrlModes bit with its spec symbol, so a writer
// names the control FUNCTION it is about to write rather than a bare bit.
// The symbol is not decoration: it is what the operator reads in the
// CannotComply, and CapClaim.reason renders it.
type ctrlMode struct {
	bit  uint32
	mode string
}

// The 7xx control functions this package writes, in CtrlModes bit order. Every
// exported writer picks its own from here; nothing constructs a ctrlMode
// inline, so the set of gated functions is enumerable by reading this block.
var (
	modeMaxW     = ctrlMode{sunspec.M702_CtrlMode_MaxW, "MAX_W"}
	modeFixedW   = ctrlMode{sunspec.M702_CtrlMode_FixedW, "FIXED_W"}
	modeFixedVar = ctrlMode{sunspec.M702_CtrlMode_FixedVar, "FIXED_VAR"}
	modeFixedPF  = ctrlMode{sunspec.M702_CtrlMode_FixedPF, "FIXED_PF"}
	modeVoltVar  = ctrlMode{sunspec.M702_CtrlMode_VoltVar, "VOLT_VAR"}
	modeFreqWatt = ctrlMode{sunspec.M702_CtrlMode_FreqWatt, "FREQ_WATT"}
	modeLVTrip   = ctrlMode{sunspec.M702_CtrlMode_LVTrip, "LV_TRIP"}
	modeHVTrip   = ctrlMode{sunspec.M702_CtrlMode_HVTrip, "HV_TRIP"}
	modeWattVar  = ctrlMode{sunspec.M702_CtrlMode_WattVar, "WATT_VAR"}
	modeVoltWatt = ctrlMode{sunspec.M702_CtrlMode_VoltWatt, "VOLT_WATT"}
	modeLFTrip   = ctrlMode{sunspec.M702_CtrlMode_LFTrip, "LF_TRIP"}
	modeHFTrip   = ctrlMode{sunspec.M702_CtrlMode_HFTrip, "HF_TRIP"}
)

// requireCtrlModes enforces EVERY bit in a write's mode set — the exported-
// writer gate (audit F2). A write that touches the fields of two control
// functions needs both bits: partial permission is not permission for the
// write, because the device would end up running a function it declared it
// does not do.
//
// It denies on the FIRST unclaimed mode in the caller's order, which is the
// order the writer's fields appear in, so the error names the mode an operator
// can act on rather than an arbitrary one. Callers with a single mode get
// exactly requireCtrlMode's behaviour and message.
func (b *Base) requireCtrlModes(axis string, modes ...ctrlMode) error {
	for _, m := range modes {
		if err := b.requireCtrlMode(axis, m.bit, m.mode); err != nil {
			return err
		}
	}
	return nil
}

// DeclaresCtrlModes reports whether the device made a supported-control-modes
// declaration AT ALL: model 702 present and its CtrlModes point implemented.
// It says nothing about which modes — that is CtrlModeClaim — only that there
// is a claim to consult. A device for which this is false has told us nothing
// about its 7xx control surface, and nothing is not permission.
func (b *Base) DeclaresCtrlModes() bool {
	return b.HasCap && b.CtrlModes != CtrlModesNotImplemented
}

// The claim-LEVEL gate that used to live here (requireCtrlModesDeclaration) is
// GONE. It answered "does the device publish a CtrlModes declaration at all",
// which was write704's gate while write704 did not know which axis it served,
// and it is round-2 audit finding F2: a declaration is not permission for the
// mode it does not contain. Every writer now names its modes and gets the
// per-bit gate, so there is no caller for the weaker question and no way to
// reach for it by accident. DeclaresCtrlModes above remains for REPORTING —
// telling an operator the device said nothing is useful; deciding a write on
// it is not.

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

// settingOrRatingBound resolves the quantity a percentage-of-capacity control is
// answered against when 702 publishes BOTH a mutable SETTING and an immutable
// RATING for the same axis (IW15-002). It is maxRatingBound's settings-aware
// sibling and delegates to it for the rating half, so the two can never drift.
//
// THE SETTING WINS OVER THE RATING when both are published. That is not a
// preference, it is what the standard says. IEEE Std 2030.5-2018 states the
// whole rating/setting family as ONE normative rule in §10.10.4.4.3, printed
// p.124: "Each rating value in a DER's DERCapability instance MAY have a
// corresponding setting value in its DERSettings instance (which equals the
// rating value by default). A modified rating SHALL have a corresponding
// setting." The per-attribute sentences on p.244 say the same thing three
// times — setMaxW "Defaults to rtgMaxW.", setMaxChargeRateW "Defaults to
// rtgMaxChargeRateW.", setMaxDischargeRateW "Defaults to
// rtgMaxDischargeRateW." — which makes the rating the FALLBACK for an absent
// setting rather than the reference; and DERControlBase.opModMaxLimW is "a
// percentage of set capacity (%setMaxW, in hundredths)" (2018 p.250).
//
// The cite above named sep.xsd 2.0.4 elements 3457/3429/3439 until IW15-027
// demoted that draft. Same verdict, same watts, published anchor — and the
// upgrade is real rather than cosmetic: the draft states the three attribute
// defaults and nothing else, while §10.10.4.4.3 is also the normative home of
// the setting-above-its-rating bound this function applies below ("subject to
// the maximum limit by rtgMaxW", same page), which the draft states nowhere.
// A control is answered by the machine AS CONFIGURED — a device an installer
// derated to 6 kW answers "60 %" with 3.6 kW, not 6 kW. derbase already
// reasoned exactly this way on the reactive axis (reactiveCapability,
// varsetmod.go); this is the active-power copy of that rule, and the same
// second reason applies with more force: this must be the SAME quantity the
// GATEWAY resolves its percent against (lexa-gw internal/derref implements this
// identical rule), or a 60 % ceiling computed against one point and written as
// a percent of another lands as some other number entirely.
//
// The four states, in the order they are tested:
//
//	setting > 0, <= rating   the setting, named by setPoint. The ordinary path.
//	setting > 0, > rating    a LIMIT cannot exceed the CAPABILITY it limits: the
//	                         device is malformed. The rating is used (the
//	                         fail-safe direction — a smaller reference commands
//	                         fewer watts) and defect=true says so, for a caller
//	                         that can journal it.
//	setting == 0             INCAPACITY, never overridden by the rating. An
//	                         operator who configured a rate of zero has SAID
//	                         something; falling back to the rating would overrule
//	                         a live configuration with a physical capability the
//	                         machine has been told not to use. Same rule
//	                         maxRatingBound already applies to a rated zero.
//	setting absent/garbage   the rating, through maxRatingBound — the 2018
//	                         §10.10.4.4.3 p.124 / p.244 default. "Absent" is
//	                         the not-implemented sentinel (NaN); "garbage" is a
//	                         non-finite or negative value, which is IGNORED
//	                         here rather than denied, because unlike a rating a
//	                         setting has a defined fallback the standard itself
//	                         names. defect=true reports it.
//
// point names whichever input the bound came from, for evidence. ok=false with
// a nil error is honest unknown (neither published) — no bound, exactly as
// maxRatingBound's own NaN case.
func settingOrRatingBound(axis, setPoint string, setting float64, rtgPoint string, rating float64) (w float64, point string, ok bool, defect bool, err error) {
	switch {
	case math.IsNaN(setting):
		// Absent / not implemented / unusable scale factor — fall through to
		// the rating, which is what IEEE Std 2030.5-2018 says an absent setting
		// defaults to (§10.10.4.4.3 p.124; per-attribute on p.244).
	case math.IsInf(setting, 0) || setting < 0:
		// An implemented setting that cannot be true. Unlike a garbage RATING
		// (which denies — see outOfDomainRating), a garbage SETTING has a
		// standards-named fallback, so it is discarded in favour of the rating
		// and reported rather than turned into a refusal.
		defect = true
	case setting == 0:
		return 0, setPoint, false, false, &UnsupportedControlError{Axis: axis, Reason: fmt.Sprintf(
			"device declares the %s SETTING = 0 W: it is configured to perform none of this axis, "+
				"so its %s rating is not a reference to fall back to", setPoint, rtgPoint)}
	default:
		if r, rok, rerr := maxRatingBound(axis, rtgPoint, rating); rerr == nil && rok && setting > r {
			// A setting above its own rating is a malformed device. Use the
			// rating (smaller, fail-safe) and say so.
			return r, rtgPoint, true, true, nil
		}
		return setting, setPoint, true, defect, nil
	}
	r, rok, rerr := maxRatingBound(axis, rtgPoint, rating)
	if rerr != nil {
		return 0, rtgPoint, false, defect, rerr
	}
	return r, rtgPoint, rok, defect, nil
}
