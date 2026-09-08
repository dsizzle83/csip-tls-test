package suitecsip

// baseline_precondition_test.go proves WP7-T6 (REV0907-E6;
// CSIP-BENCH-BASIC007-ORACLE-STATE-CONTAMINATION;
// QAGAMUT2-001-SIMULATOR-STATE-NOT-RESET-BETWEEN-RUNS): a row whose own
// pre-publication oracle read finds the DER's baseline already
// indistinguishable from the value it is about to command must publish
// NOTHING and report an honest SKIP — never a PASS, never the FAIL
// oracleOutcome/curveOutcome used to produce after burning the row's whole
// observation window on a control that could prove nothing.
//
// Each apparatus (directSetup, oracledSetup's exhausted ladder, curveSetup)
// is proved at the point it actually decides — Setup refuses to publish and
// records oracleContaminationParam — and the shared consequence (controlMode.
// outcome / inverterControlSpec's Criteria and Verdict) is proved once,
// against the ONE definition every apparatus feeds.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
)

// ── directSetup ──────────────────────────────────────────────────────────────

// fakeDirectOracle builds a directOracle whose Judge is fully controlled by
// the caller, wired through a real (if minimal) simapi sidecar so
// directOracle.judgeWith's own HTTP round trip — the thing under test here is
// what directSetup DOES with the verdict, not whether a real register bank
// produces it (directoracle_test.go already proves that against BASIC-008/009's
// real bindings) — has a device to reach.
func fakeDirectOracle(verdict certify.Verdict, observed string) *directOracle {
	return &directOracle{
		Axis:      "test axis",
		Commanded: "the test's fake target",
		Registers: "a fake register this test controls directly",
		Judge: func(invariant.UnitView) Finding {
			return Finding{Verdict: verdict, Observed: observed}
		},
	}
}

func TestDirectSetup_ContaminatedBaselineRefusesToPublish(t *testing.T) {
	dev, _ := oracleFixture(t)
	rc := oracleTestRunCtx(t, dev)
	d := NewDriver(rc)
	o := fakeDirectOracle(certify.Pass, "the DER's own fake register already reads 6000 (the row's own target)")

	published := false
	publish := func(context.Context, *Driver, string) error {
		published = true
		return nil
	}

	params := map[string]string{}
	if err := directSetup(context.Background(), d, params, o, publish, "CERT-TEST-DIRECT"); err != nil {
		t.Fatalf("directSetup: %v", err)
	}
	if published {
		t.Fatal("directSetup published a control although its own pre-read already matched the target — " +
			"the WP7-T6 refusal did not fire")
	}
	reason := params[oracleContaminationParam]
	if reason == "" {
		t.Fatal("directSetup recorded no oracleContaminationParam although the baseline already matched")
	}
	for _, want := range []string{"baseline indistinguishable from target", "residual from prior row?",
		"6000"} {
		if !strings.Contains(reason, want) {
			t.Errorf("contamination reason does not contain %q:\n  %s", want, reason)
		}
	}
}

func TestDirectSetup_DistinguishableBaselinePublishesNormally(t *testing.T) {
	dev, _ := oracleFixture(t)
	rc := oracleTestRunCtx(t, dev)
	d := NewDriver(rc)
	o := fakeDirectOracle(certify.Fail, "the DER's own fake register reads 0, not the row's target")

	published := false
	publish := func(context.Context, *Driver, string) error {
		published = true
		return nil
	}

	params := map[string]string{}
	if err := directSetup(context.Background(), d, params, o, publish, "CERT-TEST-DIRECT"); err != nil {
		t.Fatalf("directSetup: %v", err)
	}
	if !published {
		t.Fatal("directSetup refused to publish although the baseline was DISTINGUISHABLE from the target " +
			"— a real transition would have gone unmeasured")
	}
	if reason := params[oracleContaminationParam]; reason != "" {
		t.Fatalf("directSetup recorded a contamination reason on a distinguishable baseline: %s", reason)
	}
}

// ── oracledSetup's exhausted ladder ─────────────────────────────────────────

func TestOracledSetup_LadderExhaustedRefusesToPublish(t *testing.T) {
	dev, _ := oracleFixture(t)
	rc := oracleTestRunCtx(t, dev)
	d := NewDriver(rc)

	published := false
	b := &oracleBinding{
		Commanded: 6000,
		Ladder:    []int64{4000, 5000}, // every alternate ALSO reads Pass below — exhausted
		Publish: func(ctx context.Context, d *Driver, mrid string, hundredths int64) error {
			published = true
			return nil
		},
		// Every value this row could name — Commanded and every Ladder entry
		// — already reads Pass, so alternate() finds nothing it can move to.
		Judge: func(int64) func(context.Context, *certify.RunCtx) Finding {
			return func(context.Context, *certify.RunCtx) Finding {
				return Finding{Verdict: certify.Pass, Observed: "the DER's own fake register already " +
					"reads whatever this row asks for"}
			}
		},
	}

	params := map[string]string{}
	if err := oracledSetup(context.Background(), d, params, b, "CERT-TEST-LADDER"); err != nil {
		t.Fatalf("oracledSetup: %v", err)
	}
	if published {
		t.Fatal("oracledSetup published a control after exhausting its ladder — the WP7-T6 refusal did " +
			"not fire")
	}
	reason := params[oracleContaminationParam]
	if reason == "" {
		t.Fatal("oracledSetup recorded no oracleContaminationParam although the ladder was exhausted")
	}
	if !strings.Contains(reason, "baseline indistinguishable from target") ||
		!strings.Contains(reason, "residual from prior row?") {
		t.Errorf("contamination reason does not match the required wording:\n  %s", reason)
	}
}

// TestOracledSetup_LadderAlternateStillPublishes is the pre-existing ladder
// path, pinned so this file's edits cannot be read as having disturbed it: an
// alternate the DER provably does not hold is still commanded, exactly as
// oracledSetup's own doc describes.
func TestOracledSetup_LadderAlternateStillPublishes(t *testing.T) {
	dev, _ := oracleFixture(t)
	rc := oracleTestRunCtx(t, dev)
	d := NewDriver(rc)

	var gotHundredths int64 = -1
	b := &oracleBinding{
		Commanded: 6000,
		Ladder:    []int64{4000, 5000},
		Publish: func(ctx context.Context, d *Driver, mrid string, hundredths int64) error {
			gotHundredths = hundredths
			return nil
		},
		Judge: func(want int64) func(context.Context, *certify.RunCtx) Finding {
			return func(context.Context, *certify.RunCtx) Finding {
				if want == 4000 {
					// The first ladder alternate the DER does NOT already hold.
					return Finding{Verdict: certify.Fail, Observed: "the DER reads 0, not 40.00%"}
				}
				return Finding{Verdict: certify.Pass, Observed: "the DER already reads this value"}
			}
		},
	}

	params := map[string]string{}
	if err := oracledSetup(context.Background(), d, params, b, "CERT-TEST-LADDER-ALT"); err != nil {
		t.Fatalf("oracledSetup: %v", err)
	}
	if gotHundredths != 4000 {
		t.Fatalf("oracledSetup published %d, want the ladder's first provably-distinguishable alternate 4000",
			gotHundredths)
	}
	if reason := params[oracleContaminationParam]; reason != "" {
		t.Fatalf("oracledSetup recorded a contamination reason although a ladder alternate was available: %s",
			reason)
	}
}

// ── curveSetup ───────────────────────────────────────────────────────────────

// TestCurveSetup_ContaminatedBaselineRefusesToPublish drives BASIC-006's
// SHIPPING binding against a DER that already holds BASIC-006's own curve —
// adopted through the real derbase writer (curveFixture.adoptBasic006Curve),
// the exact residue a prior row (or a prior campaign against the same bench,
// QAGAMUT2-001) would leave behind.
func TestCurveSetup_ContaminatedBaselineRefusesToPublish(t *testing.T) {
	f := newCurveFixture(t)
	f.adoptBasic006Curve(t)
	d, _ := f.withGridSimServer(t)

	params := map[string]string{}
	if err := curveSetup(context.Background(), d, params, basic006Binding(), "CERT-BASIC-006"); err != nil {
		t.Fatalf("curveSetup: %v", err)
	}
	if pub := params[curvePublishedParam]; pub != "" {
		t.Fatalf("curveSetup published a control (curvePublishedParam=%q) although the DER already held "+
			"this row's own curve — the WP7-T6 refusal did not fire", pub)
	}
	reason := params[oracleContaminationParam]
	if reason == "" {
		t.Fatal("curveSetup recorded no oracleContaminationParam although the DER already held this row's " +
			"own curve")
	}
	if !strings.Contains(reason, "baseline indistinguishable from target") ||
		!strings.Contains(reason, "residual from prior row?") {
		t.Errorf("contamination reason does not match the required wording:\n  %s", reason)
	}
}

// TestCurveSetup_UnadoptedDERPublishesNormally is the distinguishable
// baseline's pin: an unadopted DER (the as-built fixture) is exactly what a
// correct campaign starts from, and curveSetup must publish on it exactly as
// it always has.
func TestCurveSetup_UnadoptedDERPublishesNormally(t *testing.T) {
	f := newCurveFixture(t)
	d, _ := f.withGridSimServer(t)

	params := map[string]string{}
	if err := curveSetup(context.Background(), d, params, basic006Binding(), "CERT-BASIC-006"); err != nil {
		t.Fatalf("curveSetup: %v", err)
	}
	if params[curvePublishedParam] == "" {
		t.Fatal("curveSetup did not publish against an unadopted DER — a real transition would go " +
			"unmeasured")
	}
	if reason := params[oracleContaminationParam]; reason != "" {
		t.Fatalf("curveSetup recorded a contamination reason against an unadopted DER: %s", reason)
	}
}

// ── The shared consequence: controlMode.outcome, Criteria, Verdict ─────────

// TestControlModeOutcome_ContaminationShortCircuitsToSkip proves outcome() —
// the ONE definition Notes, the criterion and spec.Verdict all read — decides
// SKIP from oracleContaminationParam alone, before it ever dispatches to
// refusalOutcome/curveOutcome/oracleOutcome (which assume a control went out
// and would misreport the same state as a FAIL, the exact defect this closes).
func TestControlModeOutcome_ContaminationShortCircuitsToSkip(t *testing.T) {
	m := controlMode{Oracle: &oracleBinding{Commanded: 6000}}
	o := &Observation{Params: map[string]string{
		oracleContaminationParam: "baseline indistinguishable from target: fake=6000 (residual from prior row?)",
		// Deliberately ALSO populate the post-publication keys a real (buggy)
		// oracleOutcome dispatch would read, so a regression that stops
		// checking oracleContaminationParam first is caught here rather than
		// by an accidental absence of the other keys.
		oracleVerdictParam:     string(certify.Pass),
		oracleObservedParam:    "the DER reads 6000",
		oraclePreVerdictParam:  string(certify.Pass),
		oraclePreObservedParam: "the DER already read 6000 before anything was published",
	}}
	f := m.outcome(o)
	if f.Verdict != certify.Skip {
		t.Fatalf("controlMode.outcome on a contaminated Observation = %s, want SKIP (got: %s)",
			f.Verdict, f.Observed)
	}
	if f.Observed != o.Params[oracleContaminationParam] {
		t.Errorf("outcome's Observed does not carry the contamination reason verbatim:\n  got:  %s\n  want: %s",
			f.Observed, o.Params[oracleContaminationParam])
	}
}

// TestInverterControlSpec_ContaminatedRowCriteriaIsOneLoadBearingSkip proves
// Criteria() short-circuits to EXACTLY critBaselineContaminated on a
// contaminated row — nothing else, because any Pass/Fail assertion beside it
// would outrank the Skip in worstOf's max-taking roll-up (runner.go) and the
// case would read as decided when Setup published nothing.
func TestInverterControlSpec_ContaminatedRowCriteriaIsOneLoadBearingSkip(t *testing.T) {
	row := rowByID(t, "BASIC-010")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-010")
	reason := "baseline indistinguishable from target: WMaxLimPct=6000 (residual from prior row?)"
	o := &Observation{Params: map[string]string{oracleContaminationParam: reason}}

	crits := s.Criteria(o)
	if len(crits) != 1 {
		t.Fatalf("a contaminated row's Criteria() returned %d criteria, want exactly 1 (any other criterion "+
			"can only raise the roll-up past the SKIP this is supposed to be)", len(crits))
	}
	if !crits[0].LoadBearing {
		t.Fatal("the contaminated row's one criterion is not LoadBearing — an unmarked Skip vanishes into " +
			"a maximum-taking roll-up instead of capping it")
	}
	got := crits[0].Construction()
	if got.Verdict != certify.Skip {
		t.Fatalf("the contaminated criterion's Construction verdict = %s, want SKIP", got.Verdict)
	}
	if got.Observed != reason {
		t.Errorf("the contaminated criterion does not carry the reason verbatim:\n  got:  %s\n  want: %s",
			got.Observed, reason)
	}
}

// TestInverterControlSpec_ContaminatedRowVerdictIsSkip proves the SECOND half
// of the pair that must agree: spec.Verdict (declared, from m.outcome — see
// its own doc) also reports SKIP on a measured row's contaminated
// Observation, so run()'s rollUp (registry.go) — the worse of the declared
// verdict and the citation phase's assertions — cannot disagree with what
// Criteria() just minted.
func TestInverterControlSpec_ContaminatedRowVerdictIsSkip(t *testing.T) {
	row := rowByID(t, "BASIC-010")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-010")
	if s.Verdict == nil {
		t.Fatal("BASIC-010 (a measured row) declares no spec.Verdict at all")
	}
	o := &Observation{Params: map[string]string{
		oracleContaminationParam: "baseline indistinguishable from target: WMaxLimPct=6000 (residual from prior row?)",
	}}
	if got := s.Verdict(o); got != certify.Skip {
		t.Fatalf("spec.Verdict on a contaminated Observation = %s, want SKIP", got)
	}
}

// TestInverterControlSpec_ContaminatedRowNotesNamesTheReason proves the
// row's prose (what a bundle reader sees first) is the reason, verbatim —
// not the row's ordinary "published a DERControl ... and waited" line, which
// would describe a control that was never sent.
func TestInverterControlSpec_ContaminatedRowNotesNamesTheReason(t *testing.T) {
	row := rowByID(t, "BASIC-010")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-010")
	reason := "baseline indistinguishable from target: WMaxLimPct=6000 (residual from prior row?)"
	o := &Observation{Params: map[string]string{oracleContaminationParam: reason}}
	if got := s.Notes(o); got != reason {
		t.Fatalf("a contaminated row's Notes = %q, want the contamination reason verbatim (%q)", got, reason)
	}
}
