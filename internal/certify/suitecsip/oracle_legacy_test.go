package suitecsip

// oracle_legacy_test.go — the scalar oracles read on a LEGACY 12x DER (H-B).
//
// THE DEFECT THESE PIN. oracleMaxLimW reached models 704 and 702 by name. A
// legacy 12x DER serves neither — its ceiling is model 123's WMaxLimPct and its
// active-power reference is models 121/120 — so on the 2026-08-17 battery's
// legacy leg the oracle read NOTHING, returned "the DER serves no M702, so its
// own WMax has no value to resolve the commanded ceiling against", and the row
// FAILed under the criterion claim "the DER's own southbound registers hold the
// value ... commanded". The bundle's summary then wrote that up as "the register
// never holds the commanded limit ... a pure southbound-execution failure",
// which is a statement about the product; the gateway's readback-derived
// Started(2) on the same run says the ceiling landed. One harness cause,
// three rows (BASIC-008, BASIC-010, BASIC-013).
//
// Every test here runs against a REAL legacy sim through the same referee path
// the bench uses (oracleUnitView -> invariant.SimAPIDER -> readUnit), so a
// regression that re-hardcodes a model id goes red here rather than on a board.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/sunspec"
)

// legacyFixtureWMaxW is the nameplate every legacyFixture/curveFixture sim is
// built with (newLegacyFixture passes 5000 to NewSolarServerLegacyCurves), and
// therefore the denominator these rows' percents resolve against. Named so a
// changed fixture breaks the tests loudly instead of shifting their arithmetic.
const legacyFixtureWMaxW = 5000.0

// TestOracleMaxLimW_ReadsTheLegacyCeilingHome is the H-B oracle: on a DER that
// serves model 123 and no 704, the ceiling oracle finds the ceiling.
//
// RED BEFORE THE FIX: "the DER serves no M702, so its own WMax has no value to
// resolve the commanded ceiling against", verdict Fail.
func TestOracleMaxLimW_ReadsTheLegacyCeilingHome(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})

	// The DER holds a 60.00% ceiling of its own 5000 W reference = 3000 W.
	if err := f.ss.Inject([]byte(`{"WMaxLimPct_pct": 60}`)); err != nil {
		t.Fatalf("inject the legacy ceiling: %v", err)
	}

	got := oracleMaxLimW(6000)(context.Background(), f.rc)
	if got.Verdict != certify.Pass {
		t.Fatalf("verdict = %v, want Pass\nobserved: %s", got.Verdict, got.Observed)
	}
	// The verdict must NAME the home it read, or a reader cannot tell a real
	// legacy pass from a 7xx one that happened to be pointed at this bench.
	for _, want := range []string{
		invariant.PointM123WMaxLimPct,
		"M121/M120",
		"3000.0 W",
	} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("observed does not mention %q:\n%s", want, got.Observed)
		}
	}
	if strings.Contains(got.Observed, "no M702") {
		t.Errorf("the verdict still blames a missing M702 on a device that never has one:\n%s", got.Observed)
	}
}

// TestOracleMaxLimW_LegacyCeilingMismatchFailsWithTheValueItRead proves the
// legacy arm is a real oracle and not a rubber stamp: a DER holding the wrong
// ceiling FAILs, and the FAIL prints what it read.
func TestOracleMaxLimW_LegacyCeilingMismatchFailsWithTheValueItRead(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})

	// The DER holds 40.00% (2000 W) where the row commanded 60.00% (3000 W).
	if err := f.ss.Inject([]byte(`{"WMaxLimPct_pct": 40}`)); err != nil {
		t.Fatalf("inject the legacy ceiling: %v", err)
	}

	got := oracleMaxLimW(6000)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("verdict = %v, want Fail\nobserved: %s", got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "2000.0 W") || !strings.Contains(got.Observed, "3000.0 W") {
		t.Errorf("the FAIL does not print both the read and the commanded ceiling:\n%s", got.Observed)
	}
}

// TestOracleMaxLimW_LegacyReferenceIsTheDERsOwn checks the denominator comes
// from the DER rather than from a constant in the harness: move the device's own
// M121 WMax setting and the same commanded percent must resolve to new watts.
//
// This is the half that makes the legacy arm a MEASUREMENT. An oracle that
// resolved 60% against a hardcoded 5000 W would pass this bench and misreport
// every other one.
func TestOracleMaxLimW_LegacyReferenceIsTheDERsOwn(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})

	// Derate the SETTING to 4000 W, leaving the M120 rating at 5000 W. A
	// commanded 60.00% is now 2400 W, and a referee still using the rating
	// would want 3000 W and fail a correct device.
	if err := f.ss.Inject([]byte(`{"M121_WMax_W": 4000}`)); err != nil {
		t.Fatalf("derate the DER's own WMax setting: %v", err)
	}
	if err := f.ss.Inject([]byte(`{"WMaxLimPct_pct": 60}`)); err != nil {
		t.Fatalf("inject the legacy ceiling: %v", err)
	}

	got := oracleMaxLimW(6000)(context.Background(), f.rc)
	if got.Verdict != certify.Pass {
		t.Fatalf("verdict = %v, want Pass against the DER's own 4000 W setting\nobserved: %s",
			got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Observed, "2400.0 W") {
		t.Errorf("the verdict did not resolve against the DER's own derated setting:\n%s", got.Observed)
	}
}

// TestCeilingHomeOf_PrefersThe7xxHomeWhenTheDERServesBoth pins the precedence
// rule. The advanced sims lay a legacy 123 block down beside 704, and a 1547
// DER actuates through 704 — judging it on the legacy mirror would grade a
// shadow of the real write.
func TestCeilingHomeOf_PrefersThe7xxHomeWhenTheDERServesBoth(t *testing.T) {
	adv := newCurveFixture(t)
	uv, err := oracleUnitView(context.Background(), adv.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the advanced DER through the referee: %v", err)
	}
	// Precondition: this device really does serve both homes, or the test
	// proves nothing about precedence.
	if len(uv.Regs[sunspec.ModelDERCtlAC]) == 0 {
		t.Fatal("the advanced fixture serves no model 704")
	}
	if !uv.LegacyCommands(oracleSimName).Present {
		t.Fatal("the advanced fixture serves no model 123, so there is no precedence to test")
	}

	home, why := ceilingHomeOf(uv)
	if why != "" {
		t.Fatalf("no ceiling home on an advanced DER: %s", why)
	}
	if home.Point != "WMaxLimPct" {
		t.Errorf("ceiling home point = %q, want the 704 point on a DER serving both", home.Point)
	}
	if !strings.Contains(home.NPWhere, "M702") {
		t.Errorf("ceiling reference = %q, want the 702 nameplate on a DER serving both", home.NPWhere)
	}
	if home.Note != "" {
		t.Errorf("a 7xx home carries a legacy-generation caveat: %s", home.Note)
	}

	// ...and the legacy fixture resolves the other way.
	leg := newLegacyFixture(t, sim.LegacyCurveOptions{})
	luv, err := oracleUnitView(context.Background(), leg.rc, oracleSimName)
	if err != nil {
		t.Fatalf("read the legacy DER through the referee: %v", err)
	}
	if len(luv.Regs[sunspec.ModelDERCtlAC]) != 0 {
		t.Fatal("the legacy fixture serves a model 704, so it is not a legacy device")
	}
	lhome, why := ceilingHomeOf(luv)
	if why != "" {
		t.Fatalf("no ceiling home on a legacy DER: %s", why)
	}
	if lhome.Point != invariant.PointM123WMaxLimPct {
		t.Errorf("legacy ceiling home point = %q, want %q", lhome.Point, invariant.PointM123WMaxLimPct)
	}
	if lhome.Note == "" {
		t.Error("a legacy home carries no caveat; the verdict would not say which generation it read")
	}
}

// TestOracleFixedW_OnALegacyDERNamesTheGenerationNotTheNameplate: BASIC-013's
// oracle also blamed a missing M702. The true fact is different in kind — the
// legacy generation declares no set-active-power register ANYWHERE, so no
// nameplate would have helped — and the verdict has to say so, because "no
// M702" reads as a bench fault and "this generation has no setpoint register"
// is a scoping fact about the row.
func TestOracleFixedW_OnALegacyDERNamesTheGenerationNotTheNameplate(t *testing.T) {
	f := newLegacyFixture(t, sim.LegacyCurveOptions{})

	got := oracleFixedW(6000)(context.Background(), f.rc)
	if got.Verdict != certify.Fail {
		t.Fatalf("verdict = %v, want a decided Fail\nobserved: %s", got.Verdict, got.Observed)
	}
	for _, want := range []string{
		"LEGACY 12x",
		"no set-active-power register",
		"WMaxLimPct",
	} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("observed does not mention %q:\n%s", want, got.Observed)
		}
	}
	if strings.Contains(got.Observed, "serves no M702") {
		t.Errorf("the verdict still blames a missing M702:\n%s", got.Observed)
	}
}

// TestCeilingHomeOf_ADeviceWithNeitherHomeIsADecidedFact: a DER serving neither
// 704 nor 123 has nowhere for a ceiling to land, and that is a fact about the
// device — the refusal text has to name BOTH homes it looked in, so nobody
// reads it as the referee having looked in one place.
func TestCeilingHomeOf_ADeviceWithNeitherHomeIsADecidedFact(t *testing.T) {
	_, why := ceilingHomeOf(invariant.UnitView{Unit: 1})
	if why == "" {
		t.Fatal("an empty register image yielded a ceiling home")
	}
	for _, want := range []string{"704", "123"} {
		if !strings.Contains(why, want) {
			t.Errorf("the refusal does not name model %s as a home it looked in:\n%s", want, why)
		}
	}
}
