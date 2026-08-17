package invariant

// units.go is the unit algebra I1 rests on, and it is the most load-bearing
// file in this package.
//
// # Why a whole algebra for a comparison
//
// I1's grounding defect is BR-01: an absolute var count written into a
// percent-of-rated field. Consider what a naive I1 would look like —
//
//	if commanded > nameplate { violation }
//
// — and what it misses. A device rated 2 000 var injection is commanded
// VarSetPct = 3000. As a bare number, 3000 > 2000, so the naive check fires by
// accident. Now change the fixture: the same device is commanded VarSetPct = 80
// while the device declares VarSetMod = 0, meaning "percent of WMax", and WMax
// is 100 kW. Eighty percent of 100 kW, interpreted as vars, is 80 000 var
// against a 2 000 var rating — a 40× overcommand — and the naive check sees the
// number 80 against the number 2000 and reports PASS. The bug it exists to
// catch is invisible to it, because it forgot that its two operands were in
// different units and that one of them was a percentage of something the device
// itself gets to nominate.
//
// So the rule this file enforces is: a number never travels without its unit,
// a percentage never travels without the rating it is a percentage OF, and the
// reference base is read from the DEVICE's own mode enum rather than assumed.
// [ResolveCommand] then converts into the DER's own physical units, and only
// then is a comparison legal. When the reference cannot be resolved — the mode
// enum is unimplemented, or the base needs a live measurement the device is not
// reporting — the command is returned Unresolved with the reason, and I1 SKIPs
// that point rather than guessing. Guessing is the bug.
//
// # Which registers
//
// Everything here decodes SunSpec models 701 (DER AC measurement), 702 (DER
// capacity: the nameplate ratings and their settable counterparts) and 704 (DER
// AC controls: the commanded setpoints), using the shared lexa-proto layouts.
// Sharing the layout tables with the product is deliberate and is the one thing
// referee independence permits (they are wire definitions, like mbap framing);
// what is NOT shared is any of the interpretation below.

import (
	"fmt"
	"math"

	"lexa-proto/sunspec"
)

// Unit is a physical unit. Percent is included and is deliberately NOT
// convertible to anything without a [RefBase] — that refusal is the whole
// point.
type Unit string

// The units this package reasons in.
const (
	UnitWatt    Unit = "W"
	UnitVar     Unit = "var"
	UnitVA      Unit = "VA"
	UnitAmp     Unit = "A"
	UnitVolt    Unit = "V"
	UnitHertz   Unit = "Hz"
	UnitPF      Unit = "PF"
	UnitPercent Unit = "%"
	UnitSecond  Unit = "s"
	UnitNone    Unit = ""
)

// Quantity is a number that knows its unit.
type Quantity struct {
	Val  float64 `json:"val"`
	Unit Unit    `json:"unit"`
}

// Q builds a Quantity.
func Q(v float64, u Unit) Quantity { return Quantity{Val: v, Unit: u} }

// Known reports whether the quantity carries a usable value. A SunSpec point
// that is unimplemented decodes to NaN by the codec's own convention, and NaN
// must never be compared as if it were a reading.
func (q Quantity) Known() bool { return !math.IsNaN(q.Val) && !math.IsInf(q.Val, 0) }

// String renders "1500 W", "-250 var", "80 %".
func (q Quantity) String() string {
	if !q.Known() {
		return "n/a"
	}
	if q.Unit == UnitNone {
		return trimFloat(q.Val)
	}
	return trimFloat(q.Val) + " " + string(q.Unit)
}

// Abs returns the magnitude, unit preserved.
func (q Quantity) Abs() Quantity { return Quantity{Val: math.Abs(q.Val), Unit: q.Unit} }

func trimFloat(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.4g", v)
}

// RefBase names the rating a percentage is a percentage OF. It exists because
// SunSpec's percent setpoints are percentages of DIFFERENT bases depending on a
// mode enum the device publishes, and a checker that hardcodes one of them will
// be right most of the time and catastrophically wrong the rest.
type RefBase string

// The reference bases model 704's mode enums can select.
const (
	RefNone      RefBase = ""
	RefWMax      RefBase = "WMax"      // maximum active power setting
	RefVarMaxInj RefBase = "VarMaxInj" // maximum injected reactive power
	RefVarMaxAbs RefBase = "VarMaxAbs" // maximum absorbed reactive power
	// RefVarAvail is IEEE 2030.5's %statVarAvail base: the reactive power the
	// DER can produce AT THIS INSTANT, bounded by BOTH the converter's
	// apparent-power headroom and its reactive nameplate. Nameplate.Base
	// carries the definition and its citations; this is the one place in the
	// repo it is defined, and internal/diff's referee reads it from here.
	RefVarAvail RefBase = "VarAvail"
	RefVAMax    RefBase = "VAMax" // maximum apparent power
	// RefWRteMax is the DIRECTIONAL active-power rate maximum: the base
	// IEEE 2030.5's opModFixedW SignedPerCent applies against. It is the one
	// base in this list that is not a single 702 point, because the quantity
	// it names is not: a NEGATIVE (charge/import) percent is a percent of
	// WChaRteMaxRtg and a POSITIVE (discharge/export) one is a percent of
	// WDisChaRteMaxRtg, with WMax standing in for whichever direction the
	// device leaves unimplemented. See Nameplate.Base for the resolution and
	// for why resolving both signs against WMax is a defect rather than a
	// simplification.
	RefWRteMax RefBase = "WRteMax"
)

// Nameplate is a DER's own ratings and settings, decoded from ITS OWN model 702
// — read from the device, never from the DUT's report of the device, because
// the DUT's report of a nameplate it mis-parsed is exactly what I1 must be able
// to contradict.
//
// Each rating appears twice in 702: a read-only *Rtg (what the hardware can
// physically do) and a settable counterpart (what the operator has configured
// it to do). The narrowest applicable limit is the smaller of the two, which is
// what [Nameplate.Limit] returns, and it names which one bound the answer so a
// violation can say "over the CONFIGURED WMax, within the hardware rating" —
// an operationally different finding from blowing past the hardware.
type Nameplate struct {
	// Source names where this was read, for evidence, e.g.
	// "modbus:69.0.0.20:5020 unit 1 M702".
	Source string `json:"source"`
	// Present is false when the device serves no 702 at all.
	Present bool `json:"present"`

	WMaxRtg, WMax             Quantity `json:"-"`
	VarMaxInjRtg, VarMaxInj   Quantity `json:"-"`
	VarMaxAbsRtg, VarMaxAbs   Quantity `json:"-"`
	VAMaxRtg, VAMax           Quantity `json:"-"`
	AMaxRtg, AMax             Quantity `json:"-"`
	VNomRtg, VMaxRtg, VMinRtg Quantity `json:"-"`

	// WChaRteMaxRtg / WDisChaRteMaxRtg are the device's own rated maximum
	// charge and discharge rates. They are NOT a decorative addition to the
	// list above: they are what a signed percent-of-active-power setpoint is a
	// percentage of on a device that declares them (RefWRteMax), and a checker
	// that resolves both signs against WMax instead reports a correct gateway
	// as broken on any pack whose charge rating differs from its nameplate.
	//
	// WChaRteMax / WDisChaRteMax are their SETTABLE counterparts — what the
	// operator has configured the device to do, which is what a percentage is a
	// percentage OF (IW15-002; IEEE Std 2030.5-2018 p.244: DERSettings
	// setMaxChargeRateW "Defaults to rtgMaxChargeRateW", setMaxDischargeRateW
	// "Defaults to rtgMaxDischargeRateW" — re-anchored from sep-2.0.4.xsd under
	// IW15-027, which cost nothing here because the STANDARD carries the same
	// two sentences word for word; only the authority named was wrong).
	// Without these fields the rate axis was the ONE
	// place in this struct where a rating stood in for a setting, and
	// [Nameplate.wRteMax] could only ever answer with the hardware number.
	WChaRteMaxRtg, WChaRteMax       Quantity `json:"-"`
	WDisChaRteMaxRtg, WDisChaRteMax Quantity `json:"-"`
}

// LimitRef is a resolved limit together with the name of the rating that
// produced it.
type LimitRef struct {
	Q Quantity
	// Name is the 702 point that bound the limit, e.g. "WMax" or "WMaxRtg".
	Name string
}

// Limit returns the narrowest applicable limit in unit u for the given sign
// (+1 injecting/exporting, -1 absorbing/importing). ok is false when the
// device published neither the rating nor the setting, in which case the
// caller must SKIP rather than compare against zero.
//
// ── Two rules, two questions: do NOT unify this with [Nameplate.Base] ───────
//
// This function takes the NARROWEST of the rating and the setting; Base's pick
// (and [Nameplate.wRteMax]) take the SETTING FIRST and fall back to the rating.
// That is not an inconsistency to be tidied away — the two answer different
// questions, and each answer is wrong for the other question:
//
//   - Limit answers "what could this machine POSSIBLY be doing right now" — a
//     plausibility bound on an observation. Neither declaration may be
//     exceeded, so the smaller one governs, and an observation above it is a
//     finding whichever number produced it.
//   - Base answers "what is a commanded PERCENTAGE a percentage OF" — a
//     reference for arithmetic. "80% of WMax" means 80% of what the device is
//     CONFIGURED to do; the machine answers a control as configured, and the
//     harness must resolve the percent against the same quantity the device's
//     own register layer does or a 100% request could be judged against a
//     bound read off a different point.
//
// Collapsing them would break one of the two: a min() reference would silently
// re-scale every commanded percent on a device whose setting exceeds its
// rating, and a settings-first plausibility bound would wave through an
// observation above the hardware rating.
func (n Nameplate) Limit(u Unit, sign int) (LimitRef, bool) {
	narrowest := func(pairs ...LimitRef) (LimitRef, bool) {
		var best LimitRef
		found := false
		for _, p := range pairs {
			if !p.Q.Known() || p.Q.Val <= 0 {
				continue
			}
			if !found || p.Q.Val < best.Q.Val {
				best, found = p, true
			}
		}
		return best, found
	}
	switch u {
	case UnitWatt:
		return narrowest(LimitRef{n.WMaxRtg, "WMaxRtg"}, LimitRef{n.WMax, "WMax"})
	case UnitVar:
		if sign < 0 {
			return narrowest(LimitRef{n.VarMaxAbsRtg, "VarMaxAbsRtg"}, LimitRef{n.VarMaxAbs, "VarMaxAbs"})
		}
		return narrowest(LimitRef{n.VarMaxInjRtg, "VarMaxInjRtg"}, LimitRef{n.VarMaxInj, "VarMaxInj"})
	case UnitVA:
		return narrowest(LimitRef{n.VAMaxRtg, "VAMaxRtg"}, LimitRef{n.VAMax, "VAMax"})
	case UnitAmp:
		return narrowest(LimitRef{n.AMaxRtg, "AMaxRtg"}, LimitRef{n.AMax, "AMax"})
	}
	return LimitRef{}, false
}

// Base resolves a reference base into a physical quantity. meas supplies the
// live measurement RefVarAvail needs; pass a zero Measurement when none is
// available and RefVarAvail will report why it could not be resolved. sign is
// +1 injecting/exporting/discharging and -1 absorbing/importing/charging;
// RefVarAvail and RefWRteMax read it, because those are the two bases whose
// value depends on WHICH SIDE is being commanded — the others name a specific
// side already.
//
// The error is deliberately not swallowed into a zero value: a percentage whose
// base is unknown cannot be converted, and inventing a base is precisely the
// class of mistake this package exists to catch.
//
// ── %statVarAvail: ONE definition, and where it comes from (DIFF-CTL-004) ────
//
// This function is the repository's single definition of available reactive
// power. internal/diff's referee used to hold a second one — csipref.capVarAvail
// narrowed this base to the reactive nameplate while this function returned the
// uncapped apparent-power headroom — and the two disagreed by 1.8x on an
// ordinary idle inverter. That split is closed HERE rather than there, because
// the narrower reading is the correct one and a referee is not entitled to a
// private physics.
//
// Available reactive power at an instant is bounded by TWO independent things,
// and the available figure is the SMALLER:
//
//	(1) the converter's apparent-power headroom, sqrt(VAMax^2 - W^2): vars the
//	    machine has no thermal/current envelope left to carry;
//	(2) its REACTIVE nameplate on the side being commanded, VarMaxInj injecting
//	    or VarMaxAbs absorbing: vars the machine is not built to make at all.
//
// A 60 kW / 63 kVA inverter idling at 42 kW has 47 kvar of apparent-power
// headroom and a 26.4 kvar reactive rating. It has 26.4 kvar available, not 47.
// Term (1) alone answers "what is left of the envelope", which is a different
// question from "how much reactive power can this machine produce now".
//
// The citations, all in-tree. No repo here quotes 2030.5's DERUnitRefType table
// verbatim, so the reading is built from the reference material that exists:
//
//   - lexa-proto csipmodel/resources.go, RefTypeStatVarAvail: "%statVarAvail —
//     percent of PRESENTLY available reactive power". The commanded quantity is
//     REACTIVE power, not apparent power, so an apparent-power rating cannot be
//     the whole bound on it.
//   - lexa-hub docs/standards-buildout/digests/ieee-1547.md, §10.3 Table 28
//     minimum point list: the nameplate carries "apparent power max rating"
//     AND "reactive power injected max; reactive power absorbed max" as
//     SEPARATE mandatory points. Two independently declared ratings bound the
//     same machine; a quantity described as available reactive power cannot
//     exceed either of them.
//   - the same digest, §4.7.5 + 5.2 reactive-priority note: "DER may curtail
//     active power to honor reactive demands within its kVA envelope ('reactive
//     power priority'); an apparent-power-based export limit can starve
//     reactive capability". The kVA envelope and the reactive capability are
//     stated as distinct constraints, neither subsuming the other — which is
//     exactly the min() above.
//   - lexa-hub docs/standards-buildout/digests/ieee-2030.5-2023-delta.md item
//     9: 2018's DERAvailability carries the INJECTION-side statVarAvail only;
//     statVarAbsorbAvail was added in 2023. The quantity is DIRECTIONAL.
//     sqrt(VAMax^2 - W^2) is sign-symmetric and therefore cannot be the whole
//     definition; the directional term is the reactive nameplate side, which is
//     why this function needs the sign.
//
// lexa-proto derbase e2d9a37 (commandedVar) reaches the same reading from the
// product side — it resolves refType=3 against the reactive nameplate as an
// upper bound on VarAval — so the two repos now agree on what the base IS.
func (n Nameplate) Base(r RefBase, sign int, meas Measurement) (LimitRef, error) {
	pick := func(rtg, set Quantity, rtgName, setName string) (LimitRef, error) {
		// The SETTING governs a percentage: "80% of WMax" means 80% of what
		// the device is configured to do, not of what it could do. Fall back
		// to the rating only when no setting is published.
		if set.Known() && set.Val > 0 {
			return LimitRef{set, setName}, nil
		}
		if rtg.Known() && rtg.Val > 0 {
			return LimitRef{rtg, rtgName}, nil
		}
		return LimitRef{}, fmt.Errorf("device publishes neither %s nor %s", setName, rtgName)
	}
	switch r {
	case RefWMax:
		return pick(n.WMaxRtg, n.WMax, "WMaxRtg", "WMax")
	case RefVarMaxInj:
		return pick(n.VarMaxInjRtg, n.VarMaxInj, "VarMaxInjRtg", "VarMaxInj")
	case RefVarMaxAbs:
		return pick(n.VarMaxAbsRtg, n.VarMaxAbs, "VarMaxAbsRtg", "VarMaxAbs")
	case RefVAMax:
		return pick(n.VAMaxRtg, n.VAMax, "VAMaxRtg", "VAMax")
	case RefWRteMax:
		return n.wRteMax(sign)
	case RefVarAvail:
		va, err := pick(n.VAMaxRtg, n.VAMax, "VAMaxRtg", "VAMax")
		if err != nil {
			return LimitRef{}, fmt.Errorf("VarAvail needs an apparent-power rating: %w", err)
		}
		// meas.Present is checked as well as W.Known(): the zero Measurement
		// has W = 0, which is a perfectly plausible active power, so relying on
		// Known() alone would silently treat "no 701 served" as "the device is
		// producing nothing" and resolve a base that was never published.
		if !meas.Present || !meas.W.Known() {
			return LimitRef{}, fmt.Errorf("VarAvail needs the live active power (M701 W), which the device is not reporting")
		}
		hdr := va.Q.Val*va.Q.Val - meas.W.Val*meas.W.Val
		if hdr <= 0 {
			return LimitRef{Q: Q(0, UnitVar), Name: "VarAvail(" + va.Name + ")"}, nil
		}
		avail := LimitRef{Q: Q(math.Sqrt(hdr), UnitVar), Name: "VarAvail(" + va.Name + ")"}
		// Term (2). Limit gives the NARROWEST of the rating and the setting on
		// the commanded side, which is the right edge for a capability bound: a
		// machine configured below its hardware rating cannot produce the
		// hardware rating. A device that publishes no reactive rating at all
		// leaves term (1) standing alone — honest unknown, not a licence to
		// assume a wider machine.
		if lim, ok := n.Limit(UnitVar, sign); ok && lim.Q.Known() && lim.Q.Val < avail.Q.Val {
			return LimitRef{Q: lim.Q, Name: "VarAvail capped by " + lim.Name}, nil
		}
		return avail, nil
	}
	return LimitRef{}, fmt.Errorf("no reference base declared")
}

// wRteMax resolves RefWRteMax: the rate reference for the side being commanded
// — the device's own SETTING where it publishes one, its rating where it does
// not, and the nameplate when it declares neither.
//
// ── Why this is not "both signs against WMax" (IW14-001 / adversarial F5) ────
//
// A signed percent-of-active-power setpoint (IEEE 2030.5 opModFixedW, carried
// as SignedPerCent) is a percentage of the device's rated ability IN THE
// DIRECTION COMMANDED. lexa-proto derbase — the code that actually writes the
// register on the product side — resolves it that way (derbase.go
// fixedWReference: WChaRteMaxRtg for a negative value, WDisChaRteMaxRtg for a
// positive one, WMax when the device leaves that rating unimplemented), and a
// referee that resolved both signs against WMax would not be independent, it
// would simply be WRONG about the physics on any device whose charge and
// discharge ratings differ. Concretely, on the bench's own asymmetric pack
// (WMax 5000 W, WChaRteMaxRtg 2000 W, WDisChaRteMaxRtg 4500 W) a CORRECT
// gateway commanded −60.00% writes −1200 W; a checker expecting −3000 W calls
// that "not applied" and, worse, passes the broken nameplate-fallback
// implementation that really did write −3000 W. Both errors are decided here,
// once, for every caller.
//
// The three-way outcome mirrors derbase.maxRatingBound exactly, including the
// case the shorthand "use the rating if it is > 0, else WMax" gets wrong:
//
//   - the reference is unimplemented (the SunSpec sentinel, decoded to NaN) —
//     honest absence, fall back to WMax;
//   - the reference is implemented and positive — that is the base;
//   - the reference is implemented and zero, negative or infinite — the device
//     positively declares it cannot perform this direction (or declares
//     something that cannot be true). That is a CLAIM, not an absence, and
//     falling back to WMax would silently overrule it, so it is returned as an
//     error naming the point. derbase refuses the control outright in the same
//     situation, so a referee that quietly resolved a base here would be
//     grading a command the product would never have sent.
//
// ── Settings first, and the three cases that decides (IW15-002) ─────────────
//
// This used to read the *Rtg RATINGS and nothing else, which made the rate axis
// the one place in this file where the hardware number stood in for the
// configured one. Everywhere else — Base's own pick — already resolves a
// percentage against the SETTING ("80% of WMax means 80% of what the device is
// configured to do"), and IEEE 2030.5 says the same thing about this very axis:
// IEEE Std 2030.5-2018 p.244 defines DERSettings setMaxChargeRateW /
// setMaxDischargeRateW as the commanded quantity's reference and says each
// "Defaults to" its rating.
//
// The citation used to name sep-2.0.4.xsd. It was re-anchored under IW15-027 —
// that file is a pre-publication ZigBee SEP 2.0 draft and is reference-only —
// and the re-anchoring changed nothing but the authority: 2018 p.244 states both
// definitions in the same words the draft did, so the rule this chain implements
// was right all along and was merely sourced to the wrong book.
// The chain below is that rule, and it mirrors what the product's own register
// layer must do (lexa-proto derbase settingOrRatingBound), so referee and
// product cannot disagree about what a commanded percent is a percent of:
//
//	setting present and LOWER than the rating   -> the setting (a lower
//	    configured maximum is the whole point of having settings; using the
//	    rating here silently over-commands a device the operator derated)
//	setting present and EQUAL                   -> the setting, named as such
//	setting ABSENT (SunSpec sentinel -> NaN)    -> the rating, named
//	    "rating-default", which is what IEEE Std 2030.5-2018 p.244 prescribes
//	    ("Defaults to rtgMaxChargeRateW" / "... rtgMaxDischargeRateW") — this
//	    is the ONE
//	    permitted rating fallback, and it is recorded rather than assumed
//	setting present and ZERO                    -> declared incapacity, never
//	    overruled by the rating: an operator who configured a zero charge rate
//	    has SAID something, and derbase.maxRatingBound already refuses the axis
//	    for exactly this shape on the rating
//	setting ABOVE its own rating                -> the RATING, named as a
//	    device defect: a configured limit cannot exceed the capability it
//	    limits, and the fail-safe direction is the smaller reference
//	setting out of domain (±Inf, negative)      -> ignored, the rating stands
//	    in, and the finding says the setting was out of domain
//	rating present and ZERO                     -> declared incapacity for the
//	    whole direction, whatever the setting says: the hardware claim bounds
//	    the configured one, never the other way round
//
// Staleness — the third forbidden case in the product-side rule — has no analogue
// here and needs none: this Nameplate is decoded from a register image the
// harness has just read from the device itself, so there is no cached settings
// snapshot that could silently age into a wrong reference.
func (n Nameplate) wRteMax(sign int) (LimitRef, error) {
	ratingPoint, rating := "WDisChaRteMaxRtg", n.WDisChaRteMaxRtg
	settingPoint, setting := "WDisChaRteMax", n.WDisChaRteMax
	side := "discharge/export"
	if sign < 0 {
		ratingPoint, rating = "WChaRteMaxRtg", n.WChaRteMaxRtg
		settingPoint, setting = "WChaRteMax", n.WChaRteMax
		side = "charge/import"
	}

	// The RATING's own claims are read first, because they bound the whole
	// direction: an implemented zero or an impossible value is a statement
	// about the machine that no configured value can relax.
	switch {
	case math.IsInf(rating.Val, 0) || rating.Val < 0:
		return LimitRef{}, fmt.Errorf("the device declares an out-of-domain %s (%s); a capability claim that "+
			"cannot be true is not a bound to relax", ratingPoint, rating)
	case rating.Val == 0:
		return LimitRef{}, fmt.Errorf("the device declares %s = 0 W: its rated maximum for %s is zero, so it "+
			"positively declares it cannot perform that direction and no percentage of it is commandable",
			ratingPoint, side)
	}

	// Then the SETTING, which governs whenever it is usable.
	switch {
	case setting.Val == 0:
		return LimitRef{}, fmt.Errorf("the device declares %s = 0 W: it is CONFIGURED to a maximum of zero "+
			"for %s, so it declares it cannot perform that direction as configured and no percentage of it "+
			"is commandable (its %s rating is %s, which does not overrule a configured zero)",
			settingPoint, side, ratingPoint, rating)
	case setting.Known() && setting.Val > 0:
		switch {
		case !rating.Known():
			return LimitRef{Q: setting, Name: settingPoint}, nil
		case setting.Val <= rating.Val:
			return LimitRef{Q: setting, Name: settingPoint}, nil
		default:
			// A configured maximum ABOVE the hardware rating cannot be true.
			// Use the rating and say so, rather than commanding a percentage of
			// a number the machine cannot reach.
			return LimitRef{Q: rating, Name: fmt.Sprintf(
				"%s (this device declares a %s SETTING of %s, above its own rating)",
				ratingPoint, settingPoint, setting)}, nil
		}
	case !math.IsNaN(setting.Val):
		// Implemented, positive-domain-violating (±Inf or negative): not a
		// usable reference and not a capability claim either. The rating stands
		// in, and the finding carries what was read.
		if rating.Known() {
			return LimitRef{Q: rating, Name: fmt.Sprintf(
				"%s (this device declares an out-of-domain %s SETTING of %s)",
				ratingPoint, settingPoint, setting)}, nil
		}
	}

	// No usable setting. The rating is the standards-prescribed default.
	if rating.Known() {
		return LimitRef{Q: rating, Name: ratingPoint + " (rating-default: no " + settingPoint +
			" setting published)"}, nil
	}

	// Neither: the nameplate is the honest stand-in, and naming the reason in
	// the LimitRef keeps a finding from reading as though the device had
	// declared a rate reference equal to its nameplate.
	base, err := n.Base(RefWMax, sign, Measurement{})
	if err != nil {
		return LimitRef{}, fmt.Errorf("the device declares no %s and no nameplate to fall back on: %w",
			ratingPoint, err)
	}
	base.Name = base.Name + " (this device implements no " + ratingPoint + ")"
	return base, nil
}

// Facts renders the nameplate for a violation record.
func (n Nameplate) Facts(prefix string) []Fact {
	if !n.Present {
		return []Fact{F(prefix+".nameplate", "", n.Source, "absent (device serves no M702)")}
	}
	add := func(out []Fact, name string, q Quantity) []Fact {
		if !q.Known() {
			return out
		}
		return append(out, F(prefix+".nameplate."+name, string(q.Unit), n.Source, "%s", trimFloat(q.Val)))
	}
	var out []Fact
	out = add(out, "WMaxRtg", n.WMaxRtg)
	out = add(out, "WMax", n.WMax)
	out = add(out, "VarMaxInjRtg", n.VarMaxInjRtg)
	out = add(out, "VarMaxInj", n.VarMaxInj)
	out = add(out, "VarMaxAbsRtg", n.VarMaxAbsRtg)
	out = add(out, "VarMaxAbs", n.VarMaxAbs)
	out = add(out, "VAMaxRtg", n.VAMaxRtg)
	out = add(out, "VAMax", n.VAMax)
	// The per-sign rate ratings are reported for the same reason as the rest:
	// a finding about a signed active-power setpoint is unreadable without the
	// rating its percentage was taken against (RefWRteMax) — and, since
	// IW15-002, without the SETTING that governs it where the device publishes
	// one. Both numbers appear so a reader can see WHY a reference resolved the
	// way it did (a derated machine, a rating-default, or a setting above its
	// own rating) instead of having to trust the name alone.
	out = add(out, "WChaRteMaxRtg", n.WChaRteMaxRtg)
	out = add(out, "WChaRteMax", n.WChaRteMax)
	out = add(out, "WDisChaRteMaxRtg", n.WDisChaRteMaxRtg)
	out = add(out, "WDisChaRteMax", n.WDisChaRteMax)
	return out
}

// Measurement is the live electrical state from model 701 — needed both as
// I1's RefVarAvail input and as I10's evidence that a control was actually
// carried out.
type Measurement struct {
	Source  string   `json:"source"`
	Present bool     `json:"present"`
	W       Quantity `json:"-"`
	VA      Quantity `json:"-"`
	Var     Quantity `json:"-"`
	PF      Quantity `json:"-"`
	A       Quantity `json:"-"`
	Hz      Quantity `json:"-"`
	LNV     Quantity `json:"-"`
	// St / ConnSt / Alrm are the raw 701 state words; interpretation belongs
	// to the invariants, not here.
	St     uint16 `json:"st"`
	ConnSt uint16 `json:"conn_st"`
	Alrm   uint32 `json:"alrm"`
	// Corrupt mirrors the codec's own sentinel-saturation gate: the device
	// answered but the block does not look like a fresh reading.
	Corrupt bool `json:"corrupt"`
}

// Command is one commanded control point decoded from model 704, carrying
// everything needed to compare it against a nameplate without losing a unit on
// the way.
type Command struct {
	// Point is the 704 field name, e.g. "VarSetPct".
	Point string `json:"point"`
	// Enabled reports whether the device's own enable/mode enums say this
	// point is the one presently governing behaviour. A disabled point holding
	// an absurd value is a WARN, not a FAIL — it commands nothing today, but
	// it is staged to command something tomorrow.
	Enabled bool `json:"enabled"`
	// Raw is the value as it appears in the register, in the FIELD's declared
	// unit: percent for a *Pct point, watts or vars for an absolute one.
	Raw Quantity `json:"raw"`
	// Ref is the rating Raw is a percentage of. Empty for an absolute point.
	Ref RefBase `json:"ref,omitempty"`
	// ModePoint and ModeVal record the enum that selected Ref, so a violation
	// can say which mode the DEVICE declared rather than which one we assumed.
	ModePoint string `json:"mode_point,omitempty"`
	ModeVal   uint16 `json:"mode_val,omitempty"`
	// Physical is Raw converted into the DER's own physical unit. Known()
	// is false when Unresolved says why it could not be.
	Physical Quantity `json:"-"`
	// BaseUsed names the nameplate point that resolved the percentage.
	BaseUsed string `json:"base_used,omitempty"`
	// Sign is +1 when the command injects/exports and -1 when it
	// absorbs/imports, which selects which nameplate rating bounds it.
	Sign int `json:"sign"`
	// Unresolved, when non-empty, is why Physical could not be derived. The
	// checker must SKIP the point with this reason rather than compare.
	Unresolved string `json:"unresolved,omitempty"`
}

// DecodeNameplate reads a device's 702 register image into a Nameplate. regs
// must be the model's data registers (no id/length header), exactly as
// sunspec.Reader.ReadModel returns them.
func DecodeNameplate(source string, regs []uint16) Nameplate {
	n := Nameplate{Source: source}
	if len(regs) < sunspec.L702.Len() {
		return n
	}
	n.Present = true
	v := sunspec.L702.View(regs)
	n.WMaxRtg = Q(v.Float("WMaxRtg"), UnitWatt)
	n.WMax = Q(v.Float("WMax"), UnitWatt)
	n.VarMaxInjRtg = Q(v.Float("VarMaxInjRtg"), UnitVar)
	n.VarMaxInj = Q(v.Float("VarMaxInj"), UnitVar)
	n.VarMaxAbsRtg = Q(v.Float("VarMaxAbsRtg"), UnitVar)
	n.VarMaxAbs = Q(v.Float("VarMaxAbs"), UnitVar)
	n.VAMaxRtg = Q(v.Float("VAMaxRtg"), UnitVA)
	n.VAMax = Q(v.Float("VAMax"), UnitVA)
	n.AMaxRtg = Q(v.Float("AMaxRtg"), UnitAmp)
	n.AMax = Q(v.Float("AMax"), UnitAmp)
	n.VNomRtg = Q(v.Float("VNomRtg"), UnitVolt)
	n.VMaxRtg = Q(v.Float("VMaxRtg"), UnitVolt)
	n.VMinRtg = Q(v.Float("VMinRtg"), UnitVolt)
	// The per-sign rate ratings come off the SAME register image as everything
	// above — the DER's own 702 — so RefWRteMax never needs a second read or a
	// second source to resolve a signed setpoint's base. Their SETTABLE
	// counterparts come off the same image too (IW15-002): the settings-first
	// rule wRteMax now applies costs no extra read, because the point the
	// operator configured sits four registers from the rating it derates.
	n.WChaRteMaxRtg = Q(v.Float("WChaRteMaxRtg"), UnitWatt)
	n.WDisChaRteMaxRtg = Q(v.Float("WDisChaRteMaxRtg"), UnitWatt)
	n.WChaRteMax = Q(v.Float("WChaRteMax"), UnitWatt)
	n.WDisChaRteMax = Q(v.Float("WDisChaRteMax"), UnitWatt)
	return n
}

// DecodeMeasurement reads a device's 701 register image.
func DecodeMeasurement(source string, regs []uint16) Measurement {
	m := Measurement{Source: source}
	if len(regs) < sunspec.L701.Len() {
		return m
	}
	m.Present = true
	parsed := sunspec.Parse701(regs)
	m.W = Q(parsed.W, UnitWatt)
	m.VA = Q(parsed.VA, UnitVA)
	m.Var = Q(parsed.Var, UnitVar)
	m.PF = Q(parsed.PF, UnitPF)
	m.A = Q(parsed.A, UnitAmp)
	m.Hz = Q(parsed.Hz, UnitHertz)
	m.LNV = Q(parsed.LNV, UnitVolt)
	m.St, m.ConnSt, m.Alrm = parsed.St, parsed.ConnSt, parsed.Alrm
	m.Corrupt = sunspec.L701.View(regs).ReadLooksCorrupt()
	return m
}

// varSetModRef maps model 704's VarSetMod enum to the reference base it
// selects. This table IS the interpretation BR-01 got wrong, so it is spelled
// out here against the spec rather than derived from anything the product does.
//
//	0 — percent of WMax
//	1 — percent of VarMax (injection or absorption, by sign)
//	2 — percent of VarAvail (the headroom at the present operating point)
//	3 — percent of VAMax
//	4 — absolute vars (VarSet, not VarSetPct, is the governing register)
func varSetModRef(mode uint16, sign int) (RefBase, bool) {
	switch mode {
	case sunspec.M704_VarSetMod_WMaxPct:
		return RefWMax, true
	case sunspec.M704_VarSetMod_VarMaxPct:
		if sign < 0 {
			return RefVarMaxAbs, true
		}
		return RefVarMaxInj, true
	case sunspec.M704_VarSetMod_VarAvailPct:
		return RefVarAvail, true
	case sunspec.M704_VarSetMod_VAMaxPct:
		return RefVAMax, true
	case sunspec.M704_VarSetMod_Vars:
		return RefNone, false // the absolute register governs
	}
	return RefNone, false
}

// DecodeCommands reads a device's 704 register image into the commanded
// setpoints, in the units the device's own mode enums declare.
//
// Both members of each percent/absolute pair are returned. The one the device's
// mode enum selects is marked Enabled; its twin is returned disabled so a
// checker can still SEE an absurd value parked in an inactive register. That
// distinction matters operationally: a 60 000-var value sitting in VarSetPct
// with VarSetEna=0 is not curtailing anything right now, but it is one enable
// write away from doing so, and a suite that could not distinguish "commanding
// something impossible" from "staged to command something impossible" would
// either cry wolf or miss the setup.
func DecodeCommands(source string, regs []uint16) []Command {
	if len(regs) < sunspec.L704.Len() {
		return nil
	}
	v := sunspec.L704.View(regs)
	enum := func(name string) uint16 {
		val, _ := v.Enum(name)
		return val
	}
	signOf := func(x float64) int {
		if x < 0 {
			return -1
		}
		return 1
	}

	var out []Command

	// ── Active power limit: WMaxLimPct, always a percent of WMax ──────────
	wLimPct := v.Float("WMaxLimPct")
	out = append(out, Command{
		Point:     "WMaxLimPct",
		Enabled:   enum("WMaxLimPctEna") == 1,
		Raw:       Q(wLimPct, UnitPercent),
		Ref:       RefWMax,
		ModePoint: "WMaxLimPctEna",
		ModeVal:   enum("WMaxLimPctEna"),
		Sign:      1,
	})

	// ── Set active power: WSetMod picks watts (1) or percent of WMax (0) ──
	wSetEna := enum("WSetEna") == 1
	wSetMod := enum("WSetMod")
	wSetIsWatts := wSetMod == sunspec.M704_WSetMod_Watts
	wSet := v.Float("WSet")
	wSetPct := v.Float("WSetPct")
	out = append(out,
		Command{
			Point:     "WSet",
			Enabled:   wSetEna && wSetIsWatts,
			Raw:       Q(wSet, UnitWatt),
			Ref:       RefNone,
			ModePoint: "WSetMod",
			ModeVal:   wSetMod,
			Sign:      signOf(wSet),
		},
		Command{
			Point:     "WSetPct",
			Enabled:   wSetEna && !wSetIsWatts,
			Raw:       Q(wSetPct, UnitPercent),
			Ref:       RefWMax,
			ModePoint: "WSetMod",
			ModeVal:   wSetMod,
			Sign:      signOf(wSetPct),
		},
	)

	// ── Set reactive power: VarSetMod picks the base, and this is where
	//    BR-01 lived. The percent register's reference is whatever the device
	//    declares — NOT "obviously VarMax".
	varSetEna := enum("VarSetEna") == 1
	varSetMod := enum("VarSetMod")
	varIsAbsolute := varSetMod == sunspec.M704_VarSetMod_Vars
	varSet := v.Float("VarSet")
	varSetPct := v.Float("VarSetPct")
	pctRef, pctRefOK := varSetModRef(varSetMod, signOf(varSetPct))
	pctCmd := Command{
		Point:     "VarSetPct",
		Enabled:   varSetEna && !varIsAbsolute,
		Raw:       Q(varSetPct, UnitPercent),
		Ref:       pctRef,
		ModePoint: "VarSetMod",
		ModeVal:   varSetMod,
		Sign:      signOf(varSetPct),
	}
	if !pctRefOK && !varIsAbsolute {
		pctCmd.Unresolved = fmt.Sprintf("VarSetMod=%d selects no reference base this decoder recognises "+
			"(spec allows 0=%%WMax 1=%%VarMax 2=%%VarAvail 3=%%VAMax 4=vars)", varSetMod)
	}
	out = append(out,
		Command{
			Point:     "VarSet",
			Enabled:   varSetEna && varIsAbsolute,
			Raw:       Q(varSet, UnitVar),
			Ref:       RefNone,
			ModePoint: "VarSetMod",
			ModeVal:   varSetMod,
			Sign:      signOf(varSet),
		},
		pctCmd,
	)

	// ── Power factor: bounded by construction, not by the nameplate ───────
	for _, pf := range []struct{ point, ena string }{
		{"PFWInj_PF", "PFWInjEna"},
		{"PFWAbs_PF", "PFWAbsEna"},
	} {
		out = append(out, Command{
			Point:     pf.point,
			Enabled:   enum(pf.ena) == 1,
			Raw:       Q(v.Float(pf.point), UnitPF),
			Ref:       RefNone,
			ModePoint: pf.ena,
			ModeVal:   enum(pf.ena),
			Sign:      1,
		})
	}

	// Mark the whole set unresolved where the register was unimplemented, so
	// a NaN never reaches a comparison.
	for i := range out {
		if !out[i].Raw.Known() && out[i].Unresolved == "" {
			out[i].Unresolved = "point is unimplemented on this device (SunSpec not-implemented sentinel)"
		}
	}
	_ = source
	return out
}

// ResolveCommand converts a command into the DER's own physical unit against
// its nameplate, filling Physical and BaseUsed — or Unresolved, with the reason.
//
// The physical unit of a percentage is NOT the unit of its base in one case
// that matters: VarSetPct with VarSetMod = 0 (%WMax) or 3 (%VAMax) is a
// REACTIVE power command whose base is an active or apparent power rating. The
// percentage is taken against a watt or VA number, and the result is vars. That
// asymmetry is exactly the trap, so it is handled explicitly below rather than
// by inheriting the base's unit.
func ResolveCommand(c Command, n Nameplate, meas Measurement) Command {
	if c.Unresolved != "" {
		return c
	}
	if !c.Raw.Known() {
		c.Unresolved = "value is unimplemented / not a number"
		return c
	}
	// An absolute point is already physical.
	if c.Raw.Unit != UnitPercent {
		c.Physical = c.Raw
		return c
	}
	if !n.Present {
		c.Unresolved = "the device serves no M702, so a percentage has no resolvable base"
		return c
	}
	base, err := n.Base(c.Ref, c.Sign, meas)
	if err != nil {
		c.Unresolved = fmt.Sprintf("cannot resolve %s (declared by %s=%d): %v", c.Ref, c.ModePoint, c.ModeVal, err)
		return c
	}
	c.BaseUsed = base.Name
	c.Physical = Quantity{
		Val:  c.Raw.Val / 100 * base.Q.Val,
		Unit: physicalUnitOf(c.Point, base.Q.Unit),
	}
	return c
}

// physicalUnitOf returns the unit a percent command resolves INTO, which is a
// property of the commanded quantity, not of the rating the percentage is taken
// against. VarSetPct resolves to vars even when its base is a watt or VA
// rating; WMaxLimPct and WSetPct resolve to watts.
func physicalUnitOf(point string, baseUnit Unit) Unit {
	switch point {
	case "VarSetPct":
		return UnitVar
	case "WMaxLimPct", "WSetPct":
		return UnitWatt
	}
	return baseUnit
}

// Tolerance is the slack a comparison allows before calling something a
// violation. A percent setpoint round-trips through a scale factor, so an exact
// comparison would fire on rounding; a generous one would hide a real
// overcommand. Rel is a fraction of the limit and Abs is a floor in the limit's
// own unit; the larger of the two applies.
type Tolerance struct {
	Rel float64
	Abs float64
}

// DefaultTolerance allows 1% of the limit. A half-LSB of a scaled percent is
// far below that, and every real overcommand this suite is designed to catch is
// a multiple of the limit, not a percent over it.
func DefaultTolerance() Tolerance { return Tolerance{Rel: 0.01} }

// Exceeds reports whether value exceeds limit beyond tolerance, and by how
// much. Both must be in the same unit; a mismatch is reported as an error
// rather than silently compared, because a silent cross-unit comparison is the
// defect this file exists to prevent.
func (t Tolerance) Exceeds(value, limit Quantity) (over float64, exceeded bool, err error) {
	if value.Unit != limit.Unit {
		return 0, false, fmt.Errorf("refusing to compare %s against %s: different units", value, limit)
	}
	if !value.Known() || !limit.Known() {
		return 0, false, fmt.Errorf("refusing to compare %s against %s: not both known", value, limit)
	}
	slack := math.Max(math.Abs(limit.Val)*t.Rel, t.Abs)
	over = math.Abs(value.Val) - math.Abs(limit.Val)
	return over, over > slack, nil
}
