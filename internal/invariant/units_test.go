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
	if _, err := np.Base(RefVarAvail, Measurement{}); err == nil {
		t.Fatal("VarAvail resolved with no live measurement — the zero Measurement's W of 0 must not be " +
			"mistaken for a reading")
	}
	meas := DecodeMeasurement("test", measurementRegs(t, 60_000, 1))
	got, err := np.Base(RefVarAvail, meas)
	if err != nil {
		t.Fatalf("VarAvail did not resolve with a live measurement: %v", err)
	}
	want := math.Sqrt(110_000*110_000 - 60_000*60_000)
	if math.Abs(got.Q.Val-want) > 500 {
		t.Fatalf("VarAvail = %s, want ≈%.0f var", got.Q, want)
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
