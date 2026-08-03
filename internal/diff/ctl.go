package diff

// ctl.go runs the control-semantics differential: a CSIP DERControlBase is
// handed to the product's control-application path, which writes real SunSpec
// registers into a real register bank, and the resulting register state is then
// read back by an INDEPENDENT decoder and compared with what this bench's own
// referee says the document asked for.
//
// The shape matters. Nothing here inspects the product's intermediate state or
// asks it what it thinks it did; the comparison is made entirely on the register
// image, which is what the physical device would actually be holding. That is
// the difference between a differential and a unit test with two authors: the
// register bank is the ground truth both readings are about.
//
//	head-end document ──> product: derbase.ApplyControl ──> registers ─┐
//	        │                                                          │
//	        └──> referee: Intents(...) ──> physical instruction        │
//	                                              │                    │
//	                                              └──── compared ──────┘
//	                                                       ▲
//	                                         registers decoded by
//	                                         internal/invariant (independent)
//
// # Four questions per case
//
//  1. MAGNITUDE. Does the setpoint the device now holds equal the setpoint the
//     document asked for, in the device's own units?
//  2. KIND. Did the product express a ceiling as a ceiling? A limit written into
//     a setpoint register is not a weaker version of the limit; it is a
//     different instruction, and on an idle battery it is the difference
//     between 0 kW and 5 kW of import.
//  3. COMPLETENESS. If the document carried several conjunctive limits, is the
//     one the device now holds the BINDING one? A reader that takes the first
//     limit it finds discards the rest, and the discarded one is sometimes the
//     tight one.
//  4. ATOMICITY. If the application FAILED, did the device end up holding part
//     of the control? This is invariant I10's grounding restated at the register
//     level, and the case hands the register state to I1 as well, so that an
//     overcommand is failed by the invariant rather than by this package's own
//     opinion.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"csip-tls-test/internal/invariant"
	model "lexa-proto/csipmodel"
	"lexa-proto/derbase"
	"lexa-proto/sunspec"
)

// CtlCase is one control-semantics probe.
type CtlCase struct {
	// ID is stable and is what a reader cites.
	ID    string
	Title string
	// Spec is the device the control is applied to.
	Spec DeviceSpec
	// Ctrl is the head-end document.
	Ctrl model.DERControlBase
	// Rendered is a human-readable rendering of Ctrl for the report; a case
	// that does not supply one gets a generic one.
	Rendered string
	// ExpectApplyError is set when the case exists specifically to observe
	// what a failed application leaves behind. It changes no verdict; it only
	// stops the runner treating the error as a harness fault.
	ExpectApplyError bool
	// Prepare, when set, runs against the device before the control is
	// applied — for arming a refusal, or parking a value in a register.
	Prepare func(d *Device)
}

// CtlTolerance is the slack a resolved setpoint comparison allows: 1 % of the
// REFEREE's value, plus a 1 W / 1 var floor so a value that scales to a single
// register count does not fail on the last digit.
//
// It is a constant of the family, not a function of the value under test. Audit
// BR-02 found the product's own scale-factor cross-check deriving its tolerance
// from the number it was checking; a tolerance chosen that way cannot fail, and
// this comment exists so nobody reintroduces it here.
func CtlTolerance() invariant.Tolerance { return invariant.Tolerance{Rel: 0.01, Abs: 1} }

// RunCtl applies one control case and returns the differential result.
//
// The returned Case always carries a verdict and, when it evaluated nothing,
// a reason. The error return is reserved for a HARNESS failure — a device that
// would not build, a SunSpec scan that found nothing — never for a device
// result.
func RunCtl(ctx context.Context, c CtlCase) (Case, error) {
	out := Case{
		ID:      c.ID,
		Family:  "ctl",
		Title:   c.Title,
		Input:   c.input(),
		Product: ProductSide,
		Referee: RefereeSide,
		Limitation: "the CSIP wire types and the SunSpec 704 mode-enum VALUES are shared between both " +
			"sides; this case differentiates SEMANTICS (which base, which register, which of several " +
			"limits binds), not the spelling of either wire format",
	}

	dev := NewDevice(c.Spec)
	if c.Prepare != nil {
		c.Prepare(dev)
	}

	// The nameplate and the operating point are read from the DEVICE, before
	// anything is written, and they are what BOTH sides resolve against.
	np, meas := readDevice(dev)

	rdr, err := sunspec.NewReader(dev)
	if err != nil {
		return out, fmt.Errorf("ctl %s: the fixture device did not present a SunSpec chain: %w", c.ID, err)
	}
	base, err := derbase.Init(rdr, "diff-ctl")
	if err != nil {
		return out, fmt.Errorf("ctl %s: derbase could not initialise against the fixture: %w", c.ID, err)
	}

	before := dev.Snapshot()
	applyErr := base.ApplyControl(c.Ctrl, "diff-ctl")
	after := dev.Snapshot()

	// The product's resulting state, decoded by a decoder the product does not
	// share: internal/invariant's 704 reading, resolved against the device's
	// own nameplate.
	regs704, ok704 := dev.Model(sunspec.ModelDERCtlAC)
	if !ok704 {
		out.Finalize("the fixture device serves no 704, so no control register state exists to compare")
		return out, nil
	}
	held := resolveHeld(invariant.DecodeCommands(dev.Spec.Name, regs704), np, meas)

	intents := Intents(c.Ctrl, np, meas)
	if len(intents) == 0 {
		out.Finalize("the control document carried no operating mode this referee reads, so there was " +
			"nothing to compare (an empty DERControlBase is a legal no-op)")
		return out, nil
	}

	for _, in := range intents {
		compareIntent(&out, in, held, np, applyErr)
	}
	checkAtomicity(&out, c, applyErr, before, after, dev)
	checkEnumSharing(&out, intents)

	// Hand the resulting register state to the invariant that owns the safety
	// claim. This package does not get to decide that a device is overcommanded
	// — I1 does, and if it fails, the finding cites it.
	judgeWithI1(ctx, &out, dev, np)

	out.Finalize("no intent in this document resolved to a comparable physical quantity on this device")
	return out, nil
}

// heldPoint is one 704 setpoint the device is holding after the write.
type heldPoint struct {
	cmd  invariant.Command
	kind Kind
}

// resolveHeld turns the decoded 704 into resolved, physically-typed setpoints.
//
// The REGISTER SEMANTICS assignment below is the referee's, and it is the
// mapping the kind comparison rests on: WMaxLimPct is a maximum, WSet/WSetPct
// and VarSet/VarSetPct are setpoints. That is what the SunSpec point names say
// and it is why writing an import LIMIT into WSet is a category error rather
// than a rounding one.
func resolveHeld(cmds []invariant.Command, np invariant.Nameplate, meas invariant.Measurement) map[string]heldPoint {
	kinds := map[string]Kind{
		"WMaxLimPct": KindCeiling,
		"WSet":       KindSetpoint,
		"WSetPct":    KindSetpoint,
		"VarSet":     KindSetpoint,
		"VarSetPct":  KindSetpoint,
		"PFWInj_PF":  KindPowerFactor,
		"PFWAbs_PF":  KindPowerFactor,
	}
	out := map[string]heldPoint{}
	for _, c := range cmds {
		out[c.Point] = heldPoint{cmd: invariant.ResolveCommand(c, np, meas), kind: kinds[c.Point]}
	}
	return out
}

// activeOfUnit returns the enabled held point whose resolved value is in unit u,
// preferring an enabled one and naming what it found. Two enabled points in the
// same unit is itself reportable, so the caller is told how many there were.
func activeOfUnit(held map[string]heldPoint, u invariant.Unit) (names []string, chosen heldPoint, found bool) {
	keys := make([]string, 0, len(held))
	for k := range held {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h := held[k]
		if !h.cmd.Enabled {
			continue
		}
		if h.cmd.Physical.Unit != u {
			continue
		}
		names = append(names, k)
		if !found {
			chosen, found = h, true
		}
	}
	return names, chosen, found
}

// compareIntent adjudicates one referee intent against the device's held state.
func compareIntent(out *Case, in Intent, held map[string]heldPoint, np invariant.Nameplate, applyErr error) {
	key := in.Mode
	if in.Unresolved != "" {
		out.Compare(SkipComparison(key, "the referee could not resolve this instruction: "+in.Unresolved))
		checkUnresolvableApplied(out, in, held)
		return
	}

	switch in.Kind {
	case KindBoolean, KindPowerFactor:
		// Booleans go to models 703/123 and power factor to the PF sync
		// groups; neither is a magnitude this family adjudicates today, and
		// saying so is better than a comparison that always passes.
		out.Compare(SkipComparison(key, fmt.Sprintf("%s is a %s instruction; this family adjudicates "+
			"active/reactive magnitudes and register semantics, and does not yet compare %s state",
			in.Mode, in.Kind, in.Kind)))
		return
	}

	unit := in.Want.Unit
	_, chosen, found := activeOfUnit(held, unit)

	if !found {
		if applyErr != nil {
			out.Compare(SkipComparison(key, fmt.Sprintf("the product's application returned an error "+
				"(%v) and left no enabled %s setpoint; atomicity is adjudicated separately below",
				applyErr, unit)))
			return
		}
		out.Compare(Comparison{
			Key:     key,
			Product: T(ProductSide.Name, key, "no enabled %s setpoint on the device", unit),
			Referee: Q(RefereeSide.Name, key, in.Want).WithNote("%s", in.String()),
			Verdict: Fail,
			Reason: fmt.Sprintf("the document commanded %s and the product left the device holding no "+
				"enabled %s control at all — the instruction was accepted and then not carried out",
				in.Want, unit),
		})
		return
	}

	product := Q(ProductSide.Name, key, chosen.cmd.Physical).
		WithNote("%s enabled, %s (%s=%d), base %s", chosen.cmd.Point, chosen.cmd.Raw,
			chosen.cmd.ModePoint, chosen.cmd.ModeVal, orNone(chosen.cmd.BaseUsed))
	referee := Q(RefereeSide.Name, key, in.Want).WithNote("%s", in.String())

	// (2) KIND — a ceiling written into a setpoint register is a different
	// instruction, and it is checked BEFORE magnitude because two instructions
	// of different kinds carrying the same number still disagree.
	if chosen.kind != in.Kind {
		out.Compare(Comparison{
			Key:     key + ".kind",
			Product: T(ProductSide.Name, key+".kind", "%s (%s)", chosen.cmd.Point, chosen.kind),
			Referee: T(RefereeSide.Name, key+".kind", "%s", in.Kind),
			Verdict: Fail,
			Reason: fmt.Sprintf("the document's %s is a %s, and the product expressed it in %s, which is "+
				"a %s. A %s and a %s carrying the same number are different instructions: the first bounds "+
				"the device, the second commands it", in.Mode, in.Kind, chosen.cmd.Point, chosen.kind,
				in.Kind, chosen.kind),
			Facts: []invariant.Fact{
				invariant.F(key+".register", "", ProductSide.Name, "%s", chosen.cmd.Point),
				invariant.F(key+".kind.want", "", RefereeSide.Name, "%s", in.Kind),
				invariant.F(key+".kind.got", "", ProductSide.Name, "%s", chosen.kind),
			},
		})
		// The register the product used does not necessarily carry THIS mode's
		// number. When several modes of one unit land in one register the point
		// holds whichever of them the product wrote — derbase's import/load
		// fan-in is `first non-nil wins`, so opModImpLimW and opModLoadLimW both
		// resolve to WSet and only one is ever written (DIFF-CTL-022) — and a
		// finding headed "<this mode> applied through WSet" would then assert an
		// application that never happened. Both sides' numbers print either way;
		// what changes is the sentence a reader quotes.
		title := fmt.Sprintf("%s (%s) applied through %s, a %s register",
			in.Mode, in.Kind, chosen.cmd.Point, chosen.kind)
		impact := fmt.Sprintf("a device that was under no obligation to %s anything is now commanded "+
			"to %s %s, because a bound was written into a register that means 'produce this'",
			flowVerb(unit), flowVerb(unit), chosen.cmd.Physical)
		if !withinCtlTolerance(chosen.cmd.Physical, in.Want) {
			title = fmt.Sprintf("%s (%s) is expressed nowhere: the device's only %s control is %s, "+
				"a %s register holding %s", in.Mode, in.Kind, unit, chosen.cmd.Point, chosen.kind,
				chosen.cmd.Physical)
			impact += fmt.Sprintf("; and this document's %s bound of %s is not in force on the device at all",
				in.Mode, in.Want)
		}
		out.Note(Finding{
			ID:       out.ID + "/kind",
			Title:    title,
			Severity: "P1",
			Input:    out.Input,
			Product:  product,
			Referee:  referee,
			Impact:   impact,
			Limitation: "this establishes that the two readings of the mode disagree; which reading the " +
				"utility intended is a specification question this differential does not settle",
		})
		return
	}

	// (3) COMPLETENESS — the device may only hold ONE active-power ceiling, so
	// a document carrying several is only faithfully applied if the one held is
	// the binding one. A superseded intent that the device IS holding means the
	// tighter limit was discarded.
	if !in.Binding {
		over, exceeded, err := CtlTolerance().Exceeds(chosen.cmd.Physical, in.Want)
		_ = over
		if err == nil && !exceeded && math.Abs(chosen.cmd.Physical.Val-in.Want.Val) <= math.Max(math.Abs(in.Want.Val)*0.01, 1) {
			out.Compare(Comparison{
				Key:     key + ".superseded",
				Product: product,
				Referee: referee.WithNote("superseded by %s, which binds tighter", in.SupersededBy),
				Verdict: Fail,
				Reason: fmt.Sprintf("the document carried both %s (%s) and %s, and %s binds tighter; the "+
					"device is holding %s, so the tighter limit was discarded",
					in.Mode, in.Want, in.SupersededBy, in.SupersededBy, chosen.cmd.Physical),
				Facts: []invariant.Fact{
					invariant.F(key+".applied", string(unit), ProductSide.Name, "%g", chosen.cmd.Physical.Val),
					invariant.F(key+".binding_mode", "", RefereeSide.Name, "%s", in.SupersededBy),
				},
			})
			out.Note(Finding{
				ID:       out.ID + "/dropped-limit",
				Title:    fmt.Sprintf("simultaneous limits: %s applied, the tighter %s discarded", in.Mode, in.SupersededBy),
				Severity: "P1",
				Input:    out.Input,
				Product:  product,
				Referee:  referee,
				Impact: fmt.Sprintf("the head-end commanded two conjunctive limits and the device is bounded " +
					"only by the looser one; the tighter bound the utility asked for is not in force"),
				Limitation: "the referee's rule — simultaneous limits are conjunctive, so the narrowest binds — " +
					"is stated in csipref.go and is the claim a reviewer should check against the profile",
			})
			return
		}
		out.Compare(Comparison{
			Key:     key + ".superseded",
			Product: product,
			Referee: referee.WithNote("superseded by %s", in.SupersededBy),
			Verdict: Pass,
		})
		return
	}

	// (1) MAGNITUDE.
	cmp := CompareQuantity(key, product, referee, CtlTolerance())
	cmp.Facts = append(cmp.Facts, np.Facts("device")...)
	out.Compare(cmp)
	if cmp.Verdict != Fail {
		return
	}
	// A disagreement that lands exactly on the device's own rating is not an
	// arithmetic error; it is a SILENT CLAMP, and it deserves its own name.
	// The head-end asked for something the device cannot do, the product
	// quietly substituted the largest thing it can, and told nobody. The
	// substituted value is physically safe — which is why this is not P1 —
	// but the head-end now believes a limit is in force that is not, and IEEE
	// 2030.5's answer to "I cannot do that" is CannotComply, not a different
	// number applied without comment.
	if lim, ok := np.Limit(unit, signOfQ(in.Want)); ok && lim.Q.Known() &&
		math.Abs(math.Abs(chosen.cmd.Physical.Val)-lim.Q.Val) <= math.Max(lim.Q.Val*0.01, 1) &&
		math.Abs(in.Want.Val) > lim.Q.Val {
		out.Note(Finding{
			ID:       out.ID + "/silent-clamp",
			Title:    fmt.Sprintf("%s beyond the nameplate was clamped to %s and applied without comment", in.Mode, lim.Name),
			Severity: "P2",
			Input:    out.Input,
			Product:  product.WithNote("clamped to %s (%s)", lim.Q, lim.Name),
			Referee:  referee,
			Impact: fmt.Sprintf("the head-end commanded %s, the device is holding %s, and the head-end "+
				"has no way to learn the difference: the control was accepted, not answered with "+
				"CannotComply", in.Want, chosen.cmd.Physical),
			Invariant: "I10",
			Facts:     cmp.Facts,
		})
		return
	}
	out.Note(Finding{
		ID:       out.ID + "/magnitude",
		Title:    fmt.Sprintf("%s resolves to a different physical quantity on each side", in.Mode),
		Severity: severityFor(product, referee),
		Input:    out.Input,
		Product:  product,
		Referee:  referee,
		Impact: fmt.Sprintf("the device is holding %s where the document asked for %s on a %s device",
			chosen.cmd.Physical, in.Want, np.Source),
		Facts: cmp.Facts,
	})
}

// withinCtlTolerance reports whether two quantities agree under this family's
// standing slack. The slack is a fraction of the REFEREE's value, never the
// product's — the same anchoring CompareQuantity enforces, restated here because
// this helper is used to CHOOSE WORDS and a reader must be able to see that the
// choice was not made with a tolerance derived from the number under test.
func withinCtlTolerance(product, referee invariant.Quantity) bool {
	if product.Unit != referee.Unit || !product.Known() || !referee.Known() {
		return false
	}
	tol := CtlTolerance()
	return math.Abs(product.Val-referee.Val) <= math.Max(math.Abs(referee.Val)*tol.Rel, tol.Abs)
}

func signOfQ(q invariant.Quantity) int {
	if q.Val < 0 {
		return -1
	}
	return 1
}

// checkUnresolvableApplied asks the question a SKIP would otherwise hide: the
// referee could not work out what this instruction MEANS on this device — did
// the product act on it anyway?
//
// The two ways to get here are both real head-end behaviour. A document can
// carry opModFixedVar with refType 0 (N/A), nominating no rating for its
// percentage to be a percentage of; and a device can serve no model 702, so
// there is no rating to take a percentage of even when the document names one.
// In both cases the number is uninterpretable, and the only two defensible
// responses are to refuse it or to leave the device alone. Enabling a setpoint
// derived from it is a third thing: acting on an instruction whose magnitude
// nobody can state. That is invariant I10's grounding — "never accepts a
// control it cannot safely carry out, and says so" — reached from the register
// side.
func checkUnresolvableApplied(out *Case, in Intent, held map[string]heldPoint) {
	var enabled []string
	for _, point := range varPointsFor(in.Mode) {
		if h, ok := held[point]; ok && h.cmd.Enabled {
			enabled = append(enabled, fmt.Sprintf("%s=%s", point, h.cmd.Raw))
		}
	}
	key := in.Mode + ".unresolvable-applied"
	if len(enabled) == 0 {
		out.Compare(Comparison{
			Key:     key,
			Product: T(ProductSide.Name, key, "no setpoint enabled"),
			Referee: T(RefereeSide.Name, key, "no setpoint enabled (the instruction is uninterpretable)"),
			Verdict: Pass,
		})
		return
	}
	product := T(ProductSide.Name, key, "enabled %s", strings.Join(enabled, ", "))
	referee := T(RefereeSide.Name, key, "refuse or leave alone — %s", in.Unresolved)
	out.Compare(Comparison{
		Key:     key,
		Product: product,
		Referee: referee,
		Verdict: Fail,
		Reason: fmt.Sprintf("the referee cannot state what %s asks for on this device (%s), and the "+
			"product enabled a setpoint from it anyway (%s). A number nobody can interpret was turned "+
			"into a live control", in.Mode, in.Unresolved, strings.Join(enabled, ", ")),
		Facts: []invariant.Fact{
			invariant.F(key+".enabled", "", ProductSide.Name, "%s", strings.Join(enabled, ", ")),
			invariant.F(key+".why", "", RefereeSide.Name, "%s", in.Unresolved),
		},
	})
	out.Note(Finding{
		ID:        out.ID + "/uninterpretable-applied",
		Title:     fmt.Sprintf("%s applied although its magnitude is uninterpretable on this device", in.Mode),
		Severity:  "P1",
		Input:     out.Input,
		Product:   product,
		Referee:   referee,
		Impact:    "a live setpoint is in force on a DER and no party — head-end, gateway or referee — can say what physical quantity it commands",
		Invariant: "I10",
	})
}

// varPointsFor names the 704 points a CSIP mode could have landed in. It is a
// small fixed table rather than a search, so a mode whose landing site changes
// shows up as a failing check here rather than as a silently-widened search.
func varPointsFor(mode string) []string {
	switch mode {
	case "opModFixedVar":
		return []string{"VarSet", "VarSetPct"}
	case "opModFixedW", "opModImpLimW", "opModLoadLimW":
		return []string{"WSet", "WSetPct"}
	case "opModExpLimW", "opModMaxLimW", "opModGenLimW":
		return []string{"WMaxLimPct"}
	}
	return nil
}

// severityFor calls an overcommand P1 and an undercommand P2. Both are wrong;
// only one of them puts a device past its own rating, and a report that graded
// them the same would be making the reader do the triage.
func severityFor(product, referee Claim) string {
	if !product.HasValue || !referee.HasValue {
		return "P2"
	}
	if math.Abs(product.Value.Val) > math.Abs(referee.Value.Val) {
		return "P1"
	}
	return "P2"
}

func flowVerb(u invariant.Unit) string {
	switch u {
	case invariant.UnitVar:
		return "produce reactive power"
	case invariant.UnitWatt:
		return "move active power"
	}
	return "hold a setpoint"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// checkAtomicity adjudicates question (4): a control application that failed
// must not leave the device holding part of the control.
//
// This is invariant I10's grounding restated where it is observable — "the
// device never accepts a control it cannot safely carry out, and says so rather
// than partially applying it". Here the register bank IS the observation: if
// ApplyControl returned an error and registers moved anyway, the device is
// holding a fragment of an instruction nobody ever decided was safe.
func checkAtomicity(out *Case, c CtlCase, applyErr error, before, after map[uint16]uint16, dev *Device) {
	if applyErr == nil {
		// A successful application makes no partial-application claim, and a
		// PASS here would be a pass nobody earned: it would hold for every
		// case that happened not to fail, inflating the run's comparison count
		// with an assertion that cannot fail. SKIP with the reason is the
		// honest row.
		out.Compare(SkipComparison("atomicity", "the product's application of this control reported "+
			"success, so there is no partial-application claim to adjudicate; this row exists so the "+
			"absence of the claim is visible rather than silent"))
		return
	}

	var moved []uint16
	for addr, v := range after {
		if before[addr] != v {
			moved = append(moved, addr)
		}
	}
	sort.Slice(moved, func(i, j int) bool { return moved[i] < moved[j] })

	product := T(ProductSide.Name, "atomicity", "error %q, %d registers changed", applyErr.Error(), len(moved))
	referee := T(RefereeSide.Name, "atomicity", "error ⇒ 0 registers changed")
	if len(moved) == 0 {
		out.Compare(Comparison{Key: "atomicity", Product: product, Referee: referee, Verdict: Pass})
		return
	}

	names := pointsAt(dev, moved)
	out.Compare(Comparison{
		Key:     "atomicity",
		Product: product.WithNote("changed: %s", strings.Join(names, ", ")),
		Referee: referee,
		Verdict: Fail,
		Reason: fmt.Sprintf("the product's application of this control FAILED (%v) and yet left %d "+
			"register(s) changed on the device (%s) — the device is holding a fragment of a control "+
			"that was never fully applied and whose failure the head-end will be told about",
			applyErr, len(moved), strings.Join(names, ", ")),
		Facts: []invariant.Fact{
			invariant.F("atomicity.error", "", ProductSide.Name, "%v", applyErr),
			invariant.F("atomicity.registers_changed", "count", ProductSide.Name, "%d", len(moved)),
			invariant.F("atomicity.points", "", ProductSide.Name, "%s", strings.Join(names, ", ")),
		},
	})
	out.Note(Finding{
		ID:       out.ID + "/partial-apply",
		Title:    "a control that failed to apply left the device holding part of it",
		Severity: "P1",
		Input:    out.Input,
		Product:  product.WithNote("changed: %s", strings.Join(names, ", ")),
		Referee:  referee,
		Impact: "the head-end is told the control failed; the device is nevertheless operating under " +
			"part of it. Nothing on either side holds the true state",
		Invariant: "I10",
	})
}

// pointsAt names the 704 points a set of absolute addresses falls in, so a
// finding says "VarSetEna, VarSetMod, VarSetPct" rather than "40123, 40124".
func pointsAt(dev *Device, addrs []uint16) []string {
	base704, ok := dev.Bases[sunspec.ModelDERCtlAC]
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		name := fmt.Sprintf("reg %d", a)
		if ok && a >= base704 {
			if off := int(a - base704); off < sunspec.L704.Len() {
				if n := pointNameAt(sunspec.L704, off); n != "" {
					name = n
				}
			}
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// pointNameAt finds the field covering a 0-based model offset.
func pointNameAt(l *sunspec.Layout, off int) string {
	best, bestOff := "", -1
	for _, f := range l.Fields {
		o := l.Offset(f.Name)
		if o <= off && o > bestOff {
			best, bestOff = f.Name, o
		}
	}
	return best
}

// checkEnumSharing raises the standing WARN this family owes the reader: both
// sides read the SunSpec 704 mode enum from the same shared constants, so their
// agreement about which mode number means what is not evidence of anything.
//
// It fires only on a case that actually depended on a mode enum, so it is a
// caveat attached to a real comparison rather than boilerplate on every case.
func checkEnumSharing(out *Case, intents []Intent) {
	depends := false
	for _, in := range intents {
		if in.Ref != invariant.RefNone {
			depends = true
		}
	}
	if !depends {
		return
	}
	out.Compare(Comparison{
		Key:      "enum-independence",
		Advisory: true,
		Product:  T(ProductSide.Name, "enum-independence", "lexa-proto/sunspec.M704_VarSetMod_*"),
		Referee:  T(RefereeSide.Name, "enum-independence", "lexa-proto/sunspec.M704_VarSetMod_* (the same constants)"),
		Verdict:  Warn,
		Reason: "this case turned on a SunSpec 704 mode enum, and both sides read that enum's numeric " +
			"values from the SAME shared constants. If the product's transcription of the SunSpec model " +
			"definition is wrong, this referee reads the same wrong number and agrees. Nothing here " +
			"establishes the enum values; only a copy of the model definition can",
	})
}

// judgeWithI1 hands the post-write register state to invariant I1, so the safety
// verdict comes from the invariant that was written to make it and not from this
// package's own arithmetic. Where I1 fails, the case records the finding as
// invariant-adjudicated, which is a materially stronger claim than "the two
// implementations differ".
func judgeWithI1(ctx context.Context, out *Case, dev *Device, np invariant.Nameplate) {
	world, obs, err := BuildWorld(dev)
	if err != nil {
		out.Compare(SkipComparison("invariant.I1", "the post-write register state could not be presented "+
			"to the invariant harness: "+err.Error()))
		return
	}
	_ = obs
	res, err := invariant.NewI1(invariant.DefaultParams()).Check(ctx, world)
	if err != nil {
		out.Compare(SkipComparison("invariant.I1", "I1 returned an error on the post-write state: "+err.Error()))
		return
	}
	switch res.Verdict {
	case invariant.Fail:
		out.Invariant = "I1"
		out.Compare(Comparison{
			Key:     "invariant.I1",
			Product: T(ProductSide.Name, "invariant.I1", "%s", res.Reason),
			Referee: T(RefereeSide.Name, "invariant.I1", "no commanded value exceeds the device's own nameplate"),
			Verdict: Fail,
			Reason:  "I1 failed on the register state this control left behind: " + res.Reason,
			Facts:   res.Facts,
		})
		out.Note(Finding{
			ID:        out.ID + "/I1",
			Title:     "the applied control left the device commanded beyond its own nameplate",
			Severity:  "P1",
			Input:     out.Input,
			Product:   T(ProductSide.Name, "invariant.I1", "%s", res.Reason),
			Referee:   T(RefereeSide.Name, "invariant.I1", "within nameplate"),
			Impact:    "a physical DER would be asked to produce more than it is rated for",
			Invariant: "I1",
			Facts:     res.Facts,
		})
	case invariant.Pass:
		out.Compare(Comparison{
			Key:     "invariant.I1",
			Product: T(ProductSide.Name, "invariant.I1", "PASS over %d sub-claims", res.Checked),
			Referee: T(RefereeSide.Name, "invariant.I1", "PASS over %d sub-claims", res.Checked),
			Verdict: Pass,
		})
	default:
		out.Compare(SkipComparison("invariant.I1", fmt.Sprintf("I1 returned %s: %s", res.Verdict, res.Reason)))
	}
}

// input renders the control document for the report, so a finding can be
// reproduced from the artifact alone.
func (c CtlCase) input() string {
	if c.Rendered != "" {
		return fmt.Sprintf("device=%s ctrl={%s}", c.Spec.Name, c.Rendered)
	}
	return fmt.Sprintf("device=%s ctrl=%s", c.Spec.Name, RenderControl(c.Ctrl))
}

// RenderControl renders a DERControlBase compactly and deterministically.
func RenderControl(c model.DERControlBase) string {
	var parts []string
	add := func(f string, a ...any) { parts = append(parts, fmt.Sprintf(f, a...)) }
	if c.OpModEnergize != nil {
		add("opModEnergize=%v", *c.OpModEnergize)
	}
	if c.OpModConnect != nil {
		add("opModConnect=%v", *c.OpModConnect)
	}
	if c.OpModFixedPFInjectW != nil {
		add("opModFixedPFInjectW=%d", c.OpModFixedPFInjectW.Value)
	}
	if c.OpModFixedPFAbsorbW != nil {
		add("opModFixedPFAbsorbW=%d", c.OpModFixedPFAbsorbW.Value)
	}
	if c.OpModFixedVar != nil {
		add("opModFixedVar{refType=%d,value=%d}", c.OpModFixedVar.RefType, c.OpModFixedVar.Value.Value)
	}
	for _, p := range []struct {
		name string
		ap   *model.ActivePower
	}{
		{"opModFixedW", c.OpModFixedW},
		{"opModMaxLimW", c.OpModMaxLimW},
		{"opModExpLimW", c.OpModExpLimW},
		{"opModGenLimW", c.OpModGenLimW},
		{"opModImpLimW", c.OpModImpLimW},
		{"opModLoadLimW", c.OpModLoadLimW},
	} {
		if p.ap != nil {
			add("%s{mult=%d,value=%d}", p.name, p.ap.Multiplier, p.ap.Value)
		}
	}
	if len(parts) == 0 {
		return "{}"
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// readDevice decodes the device's own nameplate and operating point with the
// referee's decoder, before anything is written to it.
func readDevice(dev *Device) (invariant.Nameplate, invariant.Measurement) {
	var np invariant.Nameplate
	if regs, ok := dev.Model(sunspec.ModelDERCapacity); ok {
		np = invariant.DecodeNameplate(dev.Spec.Name+" M702", regs)
	} else {
		np = invariant.Nameplate{Source: dev.Spec.Name + " (no M702)"}
	}
	var meas invariant.Measurement
	if regs, ok := dev.Model(sunspec.ModelDERMeasureAC); ok {
		meas = invariant.DecodeMeasurement(dev.Spec.Name+" M701", regs)
	}
	return np, meas
}
