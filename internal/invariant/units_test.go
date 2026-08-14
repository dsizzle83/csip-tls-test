package invariant

// units_test.go pins the unit algebra directly, because every invariant that
// compares a physical quantity is only as trustworthy as this file.
//
// The tests are written as claims about the ALGEBRA, not about I1 — a future
// change that made ResolveCommand pick a base when the device declared none
// would break these long before it broke a scenario, which is the point of
// testing it here.

import (
	"math"
	"strings"
	"testing"

	"lexa-proto/sunspec"
)

func TestVarSetModSelectsTheDeclaredBase(t *testing.T) {
	t.Parallel()
	cases := []struct {
		mode uint16
		sign int
		want RefBase
		ok   bool
	}{
		{sunspec.M704_VarSetMod_WMaxPct, 1, RefWMax, true},
		{sunspec.M704_VarSetMod_VarMaxPct, 1, RefVarMaxInj, true},
		{sunspec.M704_VarSetMod_VarMaxPct, -1, RefVarMaxAbs, true},
		{sunspec.M704_VarSetMod_VarAvailPct, 1, RefVarAvail, true},
		{sunspec.M704_VarSetMod_VAMaxPct, 1, RefVAMax, true},
		{sunspec.M704_VarSetMod_Vars, 1, RefNone, false},
		{99, 1, RefNone, false}, // an unknown mode must NOT resolve to a guess
	}
	for _, c := range cases {
		got, ok := varSetModRef(c.mode, c.sign)
		if got != c.want || ok != c.ok {
			t.Fatalf("varSetModRef(%d, %d) = (%q, %t), want (%q, %t)", c.mode, c.sign, got, ok, c.want, c.ok)
		}
	}
}

// TestResolveCommand_VarPercentOfWattBaseYieldsVars is the asymmetry that makes
// BR-01 possible: the percentage is taken against a WATT rating, and the result
// is still a REACTIVE power. A resolver that inherited the base's unit would
// produce watts here and the subsequent comparison would be against the wrong
// rating.
func TestResolveCommand_VarPercentOfWattBaseYieldsVars(t *testing.T) {
	t.Parallel()
	np := DecodeNameplate("test", nameplateRegs(t, 100_000, 2_000, 2_000, 110_000))
	cmd := Command{
		Point: "VarSetPct", Enabled: true, Raw: Q(80, UnitPercent),
		Ref: RefWMax, ModePoint: "VarSetMod", ModeVal: 0, Sign: 1,
	}
	got := ResolveCommand(cmd, np, Measurement{})
	if got.Unresolved != "" {
		t.Fatalf("unexpectedly unresolved: %s", got.Unresolved)
	}
	if got.Physical.Unit != UnitVar {
		t.Fatalf("physical unit = %q, want var — a var command against a watt base is still vars", got.Physical.Unit)
	}
	if math.Abs(got.Physical.Val-80_000) > 1 {
		t.Fatalf("physical = %s, want 80000 var", got.Physical)
	}
	if got.BaseUsed != "WMax" {
		t.Fatalf("BaseUsed = %q, want the nameplate point that resolved it", got.BaseUsed)
	}
}

func TestResolveCommand_AbsolutePointsPassThrough(t *testing.T) {
	t.Parallel()
	np := DecodeNameplate("test", nameplateRegs(t, 100_000, 2_000, 2_000, 110_000))
	got := ResolveCommand(Command{Point: "VarSet", Raw: Q(1500, UnitVar), Sign: 1}, np, Measurement{})
	if got.Physical != Q(1500, UnitVar) {
		t.Fatalf("an absolute point was transformed: %s", got.Physical)
	}
}

func TestNameplate_LimitTakesTheNarrower(t *testing.T) {
	t.Parallel()
	regs := nameplateRegs(t, 100_000, 44_000, 44_000, 110_000)
	// Configure the settable WMax below the hardware rating, as commissioning
	// would.
	sunspec.L702.View(regs).SetFloat("WMax", 60_000)
	np := DecodeNameplate("test", regs)

	lim, ok := np.Limit(UnitWatt, 1)
	if !ok {
		t.Fatal("no active-power limit resolved")
	}
	if lim.Name != "WMax" || math.Abs(lim.Q.Val-60_000) > 1 {
		t.Fatalf("Limit = %s (%s), want the narrower configured WMax of 60000 W", lim.Q, lim.Name)
	}
}

func TestNameplate_LimitPicksTheSignedRating(t *testing.T) {
	t.Parallel()
	regs := nameplateRegs(t, 100_000, 44_000, 10_000, 110_000)
	np := DecodeNameplate("test", regs)
	inj, _ := np.Limit(UnitVar, 1)
	abs, _ := np.Limit(UnitVar, -1)
	if math.Abs(inj.Q.Val-44_000) > 1 {
		t.Fatalf("injection limit = %s, want 44000 var", inj.Q)
	}
	if math.Abs(abs.Q.Val-10_000) > 1 {
		t.Fatalf("absorption limit = %s, want 10000 var — a signed command must be bounded by its own rating", abs.Q)
	}
}

func TestNameplate_VarAvailNeedsALiveMeasurement(t *testing.T) {
	t.Parallel()
	np := DecodeNameplate("test", nameplateRegs(t, 100_000, 44_000, 44_000, 110_000))
	if _, err := np.Base(RefVarAvail, 1, Measurement{}); err == nil {
		t.Fatal("VarAvail resolved with no live measurement — the zero Measurement's W of 0 must not be " +
			"mistaken for a reading")
	}
	// 105 kW of a 110 kVA converter leaves sqrt(110k^2 - 105k^2) = 32.8 kvar of
	// headroom, INSIDE the 44 kvar reactive rating — so the apparent-power term
	// is the binding one here and the answer is the headroom itself. The other
	// term is exercised by TestNameplate_VarAvailIsCappedByTheReactiveNameplate.
	meas := DecodeMeasurement("test", measurementRegs(t, 105_000, 1))
	got, err := np.Base(RefVarAvail, 1, meas)
	if err != nil {
		t.Fatalf("VarAvail did not resolve with a live measurement: %v", err)
	}
	want := math.Sqrt(110_000*110_000 - 105_000*105_000)
	if math.Abs(got.Q.Val-want) > 500 {
		t.Fatalf("VarAvail = %s, want ≈%.0f var", got.Q, want)
	}
	if got.Name != "VarAvail(VAMax)" {
		t.Errorf("BaseUsed = %q, want VarAvail(VAMax) — the evidence has to name which term bound it", got.Name)
	}
}

// TestNameplate_VarAvailIsCappedByTheReactiveNameplate is the DIFF-CTL-004
// reconciliation. See Nameplate.Base for the definition and its citations.
//
// This test's predecessor asserted VarAvail == sqrt(VAMax^2 - W^2) flat, on a
// machine at 60 kW of a 110 kVA converter — 92 kvar of "available reactive
// power" on a 44 kvar machine — and so PINNED half a definition. Apparent-power
// headroom is one of the two terms, not the answer: what is left of the
// envelope and what the machine can produce as vars are different questions,
// and the available figure is the smaller.
func TestNameplate_VarAvailIsCappedByTheReactiveNameplate(t *testing.T) {
	t.Parallel()
	// Asymmetric on purpose: 44 kvar injecting, 10 kvar absorbing. A sign-blind
	// cap would be wrong on one side of this machine, and 2030.5 treats
	// available reactive power as directional — 2018's DERAvailability carries
	// the injection-side statVarAvail only.
	np := DecodeNameplate("test", nameplateRegs(t, 100_000, 44_000, 10_000, 110_000))
	meas := DecodeMeasurement("test", measurementRegs(t, 60_000, 1))
	headroom := math.Sqrt(110_000*110_000 - 60_000*60_000) // ≈ 92 195 var

	for _, tc := range []struct {
		name string
		sign int
		want float64
		base string
	}{
		{"injecting: capped by the injection rating", 1, 44_000, "VarAvail capped by VarMaxInjRtg"},
		{"absorbing: capped by the SMALLER absorb rating", -1, 10_000, "VarAvail capped by VarMaxAbsRtg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := np.Base(RefVarAvail, tc.sign, meas)
			if err != nil {
				t.Fatalf("VarAvail did not resolve: %v", err)
			}
			if math.Abs(got.Q.Val-tc.want) > 1 {
				t.Errorf("VarAvail = %s, want %.0f var. The uncapped apparent-power headroom is "+
					"%.0f var, which this machine cannot produce as reactive power at any "+
					"operating point.", got.Q, tc.want, headroom)
			}
			if got.Name != tc.base {
				t.Errorf("BaseUsed = %q, want %q — a violation record has to say which of the two "+
					"terms bound the answer", got.Name, tc.base)
			}
		})
	}

	// A device that publishes no reactive rating leaves the apparent-power term
	// standing alone. Honest unknown: nothing was declared, so nothing caps it.
	npNoVar := DecodeNameplate("test", nameplateRegs(t, 100_000, 0, 0, 110_000))
	got, err := npNoVar.Base(RefVarAvail, 1, meas)
	if err != nil {
		t.Fatalf("VarAvail did not resolve without a reactive rating: %v", err)
	}
	if math.Abs(got.Q.Val-headroom) > 500 {
		t.Errorf("VarAvail = %s, want ≈%.0f var — an undeclared rating is not a bound", got.Q, headroom)
	}
}

func TestDecodeCommands_MarksTheGoverningPointOnly(t *testing.T) {
	t.Parallel()
	regs := controlRegs(t, func(v sunspec.View) {
		v.SetEnum("WSetEna", 1)
		v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
		v.SetFloat("WSet", 12_000)
		v.SetFloat("WSetPct", 95) // present but NOT governing
	})
	cmds := DecodeCommands("test", regs)
	wSet, _ := commandOf(cmds, "WSet")
	wPct, _ := commandOf(cmds, "WSetPct")
	if !wSet.Enabled {
		t.Fatal("WSet is not marked governing although WSetMod selects watts")
	}
	if wPct.Enabled {
		t.Fatal("WSetPct is marked governing although WSetMod selects watts")
	}
}

func TestTolerance_RefusesCrossUnitAndUnknownComparisons(t *testing.T) {
	t.Parallel()
	tol := DefaultTolerance()
	if _, _, err := tol.Exceeds(Q(1, UnitWatt), Q(1, UnitVar)); err == nil {
		t.Fatal("a watt was compared against a var without complaint")
	}
	if _, _, err := tol.Exceeds(Q(math.NaN(), UnitWatt), Q(1, UnitWatt)); err == nil {
		t.Fatal("an unimplemented point was compared as if it were a reading")
	}
	over, exceeded, err := tol.Exceeds(Q(-3000, UnitVar), Q(2000, UnitVar))
	if err != nil || !exceeded || math.Abs(over-1000) > 1e-9 {
		t.Fatalf("a magnitude comparison of a signed command failed: over=%v exceeded=%t err=%v", over, exceeded, err)
	}
}

func TestParseDERStatus(t *testing.T) {
	t.Parallel()
	claim, ok := parseDERStatus(derStatusConnected)
	if !ok {
		t.Fatal("a well-formed DERStatus did not parse")
	}
	if claim.GenConnectStatus != 1 || claim.OperationalMode != 2 {
		t.Fatalf("decoded %+v", claim)
	}
	if !claim.ClaimsConnected() {
		t.Fatal("a DERStatus with genConnectStatus bit 0 set does not read as a connectivity claim")
	}
	if _, ok := parseDERStatus(`<DERCapability xmlns="urn:ieee:std:2030.5:ns"/>`); ok {
		t.Fatal("a DERCapability body was accepted as a DERStatus")
	}
	if _, ok := parseDERStatus("not xml at all <<<"); ok {
		t.Fatal("garbage was accepted as a DERStatus")
	}
}

// packRegs builds a STORAGE 702 image: a nameplate plus the two per-direction
// rate ratings, at unity scale so the numbers in the assertions are the numbers
// in the registers. A rating passed as <= 0 is published as the SunSpec
// not-implemented sentinel rather than a raw zero, because those are two
// DIFFERENT declarations — absence versus "my rated maximum in this direction
// is zero" — and RefWRteMax has to tell them apart.
func packRegs(t *testing.T, wMaxW, chaW, disW float64) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L702.Len())
	v := sunspec.L702.View(regs)
	v.SetEnum("W_SF", 0)
	v.SetEnum("Var_SF", 0)
	v.SetEnum("VA_SF", 0)
	v.SetEnum("PF_SF", sfReg(-3))
	v.SetEnum("V_SF", 0)
	v.SetEnum("A_SF", 0)
	v.SetEnum("S_SF", 0)
	if wMaxW > 0 {
		v.SetFloat("WMaxRtg", wMaxW)
		v.SetFloat("WMax", wMaxW)
	} else {
		regs[sunspec.L702.Offset("WMaxRtg")] = 0xFFFF
		regs[sunspec.L702.Offset("WMax")] = 0xFFFF
	}
	for name, val := range map[string]float64{"WChaRteMaxRtg": chaW, "WDisChaRteMaxRtg": disW} {
		if math.IsNaN(val) {
			regs[sunspec.L702.Offset(name)] = 0xFFFF // not implemented
			continue
		}
		v.SetFloat(name, val)
	}
	return regs
}

// TestNameplate_FixedWReferenceIsPerSign is IW14-001/F5's headline proof, in
// the layer that owns the arithmetic.
//
// A signed percent-of-active-power setpoint is a percentage of the device's
// rated ability IN THE DIRECTION COMMANDED. On the bench's own asymmetric pack
// (nameplate 5000 W, charge 2000 W, discharge 4500 W) the three candidate
// references produce three different numbers, so this test can state the
// difference rather than merely exercise the code: −60.00 % is −1200 W and
// +60.00 % is +2700 W, and the ±3000 W a checker resolving both signs against
// the nameplate would want is the WRONG answer in both directions — it reports
// a correct gateway as not-applied and passes one that mis-resolved the
// reference.
func TestNameplate_FixedWReferenceIsPerSign(t *testing.T) {
	t.Parallel()
	np := DecodeNameplate("test", packRegs(t, 5000, 2000, 4500))

	for _, c := range []struct {
		name     string
		pct      float64
		sign     int
		wantBase float64
		wantName string
		wantW    float64
	}{
		{"charge", -60, -1, 2000, "WChaRteMaxRtg", -1200},
		{"discharge", +60, +1, 4500, "WDisChaRteMaxRtg", +2700},
	} {
		base, err := np.Base(RefWRteMax, c.sign, Measurement{})
		if err != nil {
			t.Fatalf("%s: Base(RefWRteMax, %d) = %v", c.name, c.sign, err)
		}
		if base.Name != c.wantName || math.Abs(base.Q.Val-c.wantBase) > 1 {
			t.Fatalf("%s: reference = %s (%s), want %g W (%s)", c.name, base.Q, base.Name, c.wantBase, c.wantName)
		}
		if got := c.pct / 100 * base.Q.Val; math.Abs(got-c.wantW) > 1 {
			t.Fatalf("%s: %g%% of this device's own %s resolves to %g W, want %g W (the nameplate would "+
				"have given %g W, which is the defect this test exists to catch)",
				c.name, c.pct, base.Name, got, c.wantW, c.pct/100*5000)
		}
	}
}

// TestNameplate_FixedWReferenceFallsBackToTheNameplate pins the OTHER half of
// derbase's rule: a device that does not publish a rate rating for the
// commanded direction has only its nameplate to offer, and that is the honest
// stand-in — the pre-storage shape every PV inverter on the bench serves.
func TestNameplate_FixedWReferenceFallsBackToTheNameplate(t *testing.T) {
	t.Parallel()
	np := DecodeNameplate("test", packRegs(t, 5000, math.NaN(), math.NaN()))
	for _, sign := range []int{-1, +1} {
		base, err := np.Base(RefWRteMax, sign, Measurement{})
		if err != nil {
			t.Fatalf("sign %d: Base(RefWRteMax) = %v, want the nameplate fallback", sign, err)
		}
		if math.Abs(base.Q.Val-5000) > 1 {
			t.Fatalf("sign %d: reference = %s, want the 5000 W nameplate", sign, base.Q)
		}
		if !strings.Contains(base.Name, "WMax") || !strings.Contains(base.Name, "implements no") {
			t.Fatalf("sign %d: reference name = %q — a fallback must say BOTH which rating it used and "+
				"that the device declared no rate rating, or a report reads as though it had", sign, base.Name)
		}
	}

	// One side declared, the other not: each side answers for itself.
	np = DecodeNameplate("test", packRegs(t, 5000, 2000, math.NaN()))
	cha, err := np.Base(RefWRteMax, -1, Measurement{})
	if err != nil || cha.Name != "WChaRteMaxRtg" || math.Abs(cha.Q.Val-2000) > 1 {
		t.Fatalf("charge reference = %v (%v), want the declared 2000 W WChaRteMaxRtg", cha, err)
	}
	dis, err := np.Base(RefWRteMax, +1, Measurement{})
	if err != nil || math.Abs(dis.Q.Val-5000) > 1 {
		t.Fatalf("discharge reference = %v (%v), want the 5000 W nameplate fallback", dis, err)
	}
}

// TestNameplate_FixedWReferenceRefusesADeclaredIncapacity is the case the
// shorthand "use the rating if it is positive, else the nameplate" gets wrong,
// and it is not a corner: an implemented rated maximum of ZERO is the device
// declaring it cannot move in that direction at all, which is why derbase
// (maxRatingBound) REFUSES the control rather than writing a percentage of
// something else. A referee that quietly fell back to the nameplate here would
// be grading a command the product never sends.
func TestNameplate_FixedWReferenceRefusesADeclaredIncapacity(t *testing.T) {
	t.Parallel()
	np := DecodeNameplate("test", packRegs(t, 5000, 0, 4500))

	_, err := np.Base(RefWRteMax, -1, Measurement{})
	if err == nil {
		t.Fatal("a declared WChaRteMaxRtg of 0 W resolved to a reference — an implemented zero is a positive " +
			"declaration of incapacity, not an absence to fall back from")
	}
	if !strings.Contains(err.Error(), "WChaRteMaxRtg") {
		t.Fatalf("the refusal does not name the point that produced it: %v", err)
	}
	// The other direction is untouched by its neighbour's claim.
	if base, err := np.Base(RefWRteMax, +1, Measurement{}); err != nil || math.Abs(base.Q.Val-4500) > 1 {
		t.Fatalf("discharge reference = %v (%v), want the declared 4500 W", base, err)
	}
	// And a device with neither a rate rating nor a nameplate resolves
	// nothing at all, rather than inventing a base.
	bare := DecodeNameplate("test", packRegs(t, 0, math.NaN(), math.NaN()))
	if _, err := bare.Base(RefWRteMax, -1, Measurement{}); err == nil {
		t.Fatal("a device publishing neither a rate rating nor a WMax resolved a reference")
	}
}
