package invariant

// i1_test.go is I1's teeth.
//
// The load-bearing test in this file is TestI1_CatchesTheUnitBlindCase. It
// stands up a device commanded VarSetPct = 80 — a perfectly ordinary-looking
// percentage, inside [-100, 100], that no range check would blink at — while
// the device's own VarSetMod declares that percentage to be a percentage of
// WMax rather than of VarMax. Against a 100 kW WMax and a 2 kvar reactive
// rating, that is 80 kvar demanded from a 2 kvar device: a 40× overcommand
// hiding inside a legal-looking number.
//
// The test asserts two things, and the second is the one that matters: that I1
// FAILS the fixture, and that a naive range check on the same fixture PASSES
// it. Without the second assertion the first proves only that some check fired;
// with it, the file demonstrates that the unit algebra is doing work no simpler
// check could do — which is the entire justification for units.go existing.

import (
	"context"
	"testing"
	"time"

	"lexa-proto/sunspec"
)

func TestI1_PassesAConformantDevice(t *testing.T) {
	t.Parallel()
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 60)
			v.SetEnum("VarSetEna", 1)
			v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_VarMaxPct)
			v.SetFloat("VarSetPct", 50) // 50% of 44 kvar = 22 kvar, well inside
		}),
	})
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI1(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I1 returned an error: %v", err)
	}
	if res.Verdict != Pass {
		t.Fatalf("I1 verdict = %s (%s), want PASS\nfacts: %+v", res.Verdict, res.Reason, res.Facts)
	}
	if res.Checked == 0 {
		t.Fatal("I1 passed while asserting nothing — the assertion floor should have caught this")
	}
	if err := res.Validate("I1"); err != nil {
		t.Fatalf("result failed its own validation: %v", err)
	}
}

// TestI1_CatchesAbsoluteVarsInAPercentField is BR-01's literal shape: an
// absolute var count landing in the percent register.
func TestI1_CatchesAbsoluteVarsInAPercentField(t *testing.T) {
	t.Parallel()
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 2_000, 2_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("VarSetEna", 1)
			v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_VarMaxPct)
			// 3000 "vars" written into a percent-of-VarMax field.
			v.SetFloat("VarSetPct", 3000)
		}),
	})
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI1(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I1 returned an error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I1 verdict = %s, want FAIL — an absolute var count in a percent field must trip I1\nreason: %s",
			res.Verdict, res.Reason)
	}
	requireFact(t, res, "der.inv.VarSetPct.physical", "var")
	requireFact(t, res, "der.inv.VarSetPct.ref_base", "")
	if err := res.Validate("I1"); err != nil {
		t.Fatalf("the violation is not reportable: %v", err)
	}
	t.Logf("finding: %s", res.Reason)
}

// TestI1_CatchesTheUnitBlindCase is the test this invariant exists for: a
// percentage that is entirely legal AS a percentage, and catastrophic once
// resolved against the base the device itself declares.
func TestI1_CatchesTheUnitBlindCase(t *testing.T) {
	t.Parallel()
	const (
		wMax   = 100_000.0 // 100 kW
		varMax = 2_000.0   // 2 kvar
		pct    = 80.0      // a wholly unremarkable percentage
	)
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, wMax, varMax, varMax, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("VarSetEna", 1)
			// The device declares the percentage is of WMax, not of VarMax.
			v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_WMaxPct)
			v.SetFloat("VarSetPct", pct)
		}),
	})
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI1(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I1 returned an error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I1 verdict = %s, want FAIL — 80%% of a 100 kW base is 80 kvar against a 2 kvar rating\nreason: %s",
			res.Verdict, res.Reason)
	}

	// The other half of the proof: a naive range check on the SAME fixture
	// passes it, which is why the unit algebra is not decoration.
	if naiveRangeCheckPasses(t, uv) != true {
		t.Fatal("the naive range check unexpectedly rejected the fixture; the test no longer demonstrates " +
			"that I1 catches something a range check cannot")
	}
	t.Logf("unit-resolved I1 = FAIL; naive |pct| <= 100 range check = PASS. finding: %s", res.Reason)
}

// naiveRangeCheckPasses is the check I1 must beat: is the raw percentage inside
// [-100, 100]. It is written here, in the test, so the comparison is explicit
// and nobody has to take the doc comment's word for it.
func naiveRangeCheckPasses(t *testing.T, uv UnitView) bool {
	t.Helper()
	v := sunspec.L704.View(uv.Regs[704])
	pct := v.Float("VarSetPct")
	return pct >= -100 && pct <= 100
}

// TestI1_StagedSetpointIsWarnNotFail proves the enabled/disabled distinction is
// real: the same absurd value in a register the device's own mode enum says is
// not governing is reported, but not as a safety violation.
func TestI1_StagedSetpointIsWarnNotFail(t *testing.T) {
	t.Parallel()
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 2_000, 2_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("VarSetEna", 0) // NOT governing
			v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_VarMaxPct)
			v.SetFloat("VarSetPct", 3000)
		}),
	})
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI1(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I1 returned an error: %v", err)
	}
	if res.Verdict != Warn {
		t.Fatalf("I1 verdict = %s, want WARN for a staged but non-governing setpoint\nreason: %s", res.Verdict, res.Reason)
	}
}

// TestI1_SkipsRatherThanGuessesAnUnresolvableBase proves the refusal to guess.
// VarSetMod = 2 selects the VarAvail base, which needs the live active power;
// with no 701 served, I1 must say it cannot resolve rather than pick a base.
func TestI1_SkipsRatherThanGuessesAnUnresolvableBase(t *testing.T) {
	t.Parallel()
	uv := unitFixture(1, map[uint16][]uint16{
		702: nameplateRegs(t, 100_000, 2_000, 2_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("VarSetEna", 1)
			v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_VarAvailPct)
			v.SetFloat("VarSetPct", 90)
		}),
	})
	w := NewWorld(Sources{}, nil, nil, DefaultParams())
	w.Inject(obsFixture(time.Now(), derFixture("inv", uv)))

	res, err := NewI1(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I1 returned an error: %v", err)
	}
	if res.Verdict == Fail {
		t.Fatalf("I1 failed a device whose reference base it could not resolve — it must SKIP the point, not guess: %s", res.Reason)
	}
	// The other setpoints are still checkable, so the overall verdict is a
	// pass; what matters is that VarSetPct contributed no verdict.
	for _, f := range res.Facts {
		if f.Key == "der.inv.VarSetPct.physical" {
			t.Fatalf("I1 produced a physical value for an unresolvable base: %+v", f)
		}
	}
}

// TestI1_RefusesACrossUnitComparison locks the guard in the algebra itself.
func TestI1_RefusesACrossUnitComparison(t *testing.T) {
	t.Parallel()
	_, _, err := DefaultTolerance().Exceeds(Q(80, UnitPercent), Q(2000, UnitVar))
	if err == nil {
		t.Fatal("Tolerance.Exceeds compared a percentage against a var rating without complaint — " +
			"that silent cross-unit comparison IS BR-01")
	}
}

func requireFact(t *testing.T, res Result, key, unit string) {
	t.Helper()
	for _, f := range res.Facts {
		if f.Key == key {
			if unit != "" && f.Unit != unit {
				t.Fatalf("fact %s has unit %q, want %q — a violation record that drops a unit reproduces the defect", key, f.Unit, unit)
			}
			return
		}
	}
	t.Fatalf("the violation does not record %q; facts were %+v", key, res.Facts)
}
