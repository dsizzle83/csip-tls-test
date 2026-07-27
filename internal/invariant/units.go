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
	RefVarAvail  RefBase = "VarAvail"  // reactive power headroom at the present W
	RefVAMax     RefBase = "VAMax"     // maximum apparent power
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
// available and RefVarAvail will report why it could not be resolved.
//
// The error is deliberately not swallowed into a zero value: a percentage whose
// base is unknown cannot be converted, and inventing a base is precisely the
// class of mistake this package exists to catch.
func (n Nameplate) Base(r RefBase, meas Measurement) (LimitRef, error) {
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
		return LimitRef{Q: Q(math.Sqrt(hdr), UnitVar), Name: "VarAvail(" + va.Name + ")"}, nil
	}
	return LimitRef{}, fmt.Errorf("no reference base declared")
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
	base, err := n.Base(c.Ref, meas)
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
