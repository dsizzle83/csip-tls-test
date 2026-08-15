package suitecsip

// hold_test.go — the persistence half, red and green.
//
// The claim under test is narrow and easy to get wrong in the flattering
// direction: a hold that returned PASS on a DER that dropped the ceiling would
// be worse than no hold at all, because the bundle would then carry a positive
// sentence about a property nothing measured. So every test below is paired —
// the value stays and the hold passes, the value goes and the hold FAILS at the
// sample where it went — and the outcome function is driven through every
// params shape the live phase can leave behind, to show it has no Skip path.

import (
	"context"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

// holdFast is the sampling shape the tests use: real samples, millisecond
// spacing, so the deadline arithmetic is exercised without the wall clock.
var holdFast = holdBinding{Samples: 3, Step: time.Millisecond, Why: "a test's own claim"}

func pass(observed string) Finding  { return Finding{Verdict: certify.Pass, Observed: observed} }
func fail(observed string) Finding  { return Finding{Verdict: certify.Fail, Observed: observed} }
func unavail(reason string) Finding { return Finding{Unavailable: reason} }

// scriptedJudge returns the findings in order, repeating the last one forever.
func scriptedJudge(fs ...Finding) func() Finding {
	i := 0
	return func() Finding {
		f := fs[i]
		if i < len(fs)-1 {
			i++
		}
		return f
	}
}

// GREEN: the ceiling stayed.
func TestHoldOracle_PassesWhenTheValueRemains(t *testing.T) {
	f := holdOracle(context.Background(), holdFast, scriptedJudge(pass("4800 W ceiling")))
	if f.Verdict != certify.Pass {
		t.Fatalf("hold = %s over three confirming reads that all matched: %s", f.Verdict, f.Observed)
	}
	// A PASS must state its own strength. A bare "held" would let a reader
	// assume a horizon nobody measured.
	for _, want := range []string{"3 confirming read", "1ms"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the PASS does not say %q, so it does not state how strong it is:\n  %s",
				want, f.Observed)
		}
	}
}

// RED: the ceiling arrived and was then relaxed. This is the defect the whole
// apparatus exists for — an arbitration that re-derives its desired state each
// tick and drops the limit — and it must FAIL at the sample where it happened,
// not merely at the end.
func TestHoldOracle_FailsAtTheSampleWhereTheValueWentAway(t *testing.T) {
	f := holdOracle(context.Background(), holdFast, scriptedJudge(
		pass("4800 W ceiling"),
		fail("the DER's own WMaxLimPct resolves to an 8000 W active-power ceiling"),
	))
	if f.Verdict != certify.Fail {
		t.Fatalf("hold = %s on a DER that dropped the ceiling at the second sample: %s",
			f.Verdict, f.Observed)
	}
	t.Logf("RED — the ceiling did not remain:\n  %s", f.Observed)
	for _, want := range []string{"ARRIVED and then did NOT REMAIN", "sample 2 of 3", "8000 W"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not say %q; a reader cannot tell WHEN the value went:\n  %s",
				want, f.Observed)
		}
	}
}

// An Unavailable mid-hold is a FAILURE of this criterion, not an abstention.
// The arrival poll retries an Unavailable because there it is the
// not-yet-applied shape it exists to wait out; here the value has already been
// seen in place, so an unreadable DER is this row losing the ability to support
// the claim it is making.
func TestHoldOracle_UnavailableMidHoldIsDecidedNotAbstained(t *testing.T) {
	f := holdOracle(context.Background(), holdFast, scriptedJudge(
		pass("4800 W ceiling"),
		unavail("read alarm-sim's own registers: connection refused"),
	))
	if f.Verdict != certify.Fail {
		t.Fatalf("hold = %s when the DER became unreadable mid-hold: %s", f.Verdict, f.Observed)
	}
	if f.Unavailable != "" {
		t.Errorf("the hold returned an Unavailable (%q); Skip is severity 0 in the roll-up and cannot "+
			"hold a release, which is exactly why the release-enforcing criteria have no Skip path",
			f.Unavailable)
	}
	if !strings.Contains(f.Observed, "connection refused") {
		t.Errorf("the FAIL does not carry the reason the sample failed:\n  %s", f.Observed)
	}
}

func TestHoldOracle_CancellationIsDecidedToo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := holdOracle(ctx, holdFast, scriptedJudge(pass("4800 W ceiling")))
	if f.Verdict != certify.Fail || f.Unavailable != "" {
		t.Fatalf("a cancelled hold = %s (unavailable %q), want a decided FAIL: %s",
			f.Verdict, f.Unavailable, f.Observed)
	}
}

// recordHold must not run a hold over a value that never arrived: reporting the
// arrival failure twice under two headings would double-count one defect.
func TestRecordHold_DefersWhenTheValueNeverArrived(t *testing.T) {
	params := map[string]string{}
	called := 0
	recordHold(context.Background(), holdFast, params, fail("no enabled WMaxLimPct"), func() Finding {
		called++
		return pass("")
	})
	if called != 0 {
		t.Errorf("the hold took %d sample(s) after the value never arrived", called)
	}
	if params[holdVerdictParam] != "" {
		t.Errorf("a hold verdict was recorded for a value that never arrived: %q", params[holdVerdictParam])
	}
	if params[holdNotRunParam] == "" {
		t.Fatal("nothing was recorded at all; holdOutcome would then report the claim as unmeasured " +
			"rather than as deferred to the arrival criterion")
	}
	// And it still does not roll up green.
	if f := holdOutcome(&holdFast, &Observation{Params: params}); f.Verdict == certify.Pass {
		t.Error("a deferred hold reported PASS; a row whose value never arrived must not gain a passing " +
			"persistence criterion")
	}
}

func TestRecordHold_WritesTheVerdictAndTheSampleCount(t *testing.T) {
	params := map[string]string{}
	recordHold(context.Background(), holdFast, params, pass("4800 W"), scriptedJudge(pass("4800 W")))
	if params[holdVerdictParam] != string(certify.Pass) {
		t.Fatalf("hold verdict = %q, want Pass", params[holdVerdictParam])
	}
	if params[holdSamplesParam] != "3" {
		t.Errorf("hold samples = %q, want 3 — a PASS that does not record its own sample count lets a "+
			"reader assume a horizon nobody measured", params[holdSamplesParam])
	}
}

// THE NO-SKIP-PATH PROOF. Every shape the live phase can leave behind must come
// back a decided verdict; doc.go's rule for the release-enforcing criteria.
func TestHoldOutcome_HasNoSkipPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params map[string]string
	}{
		{"the hold failed", map[string]string{holdVerdictParam: string(certify.Fail),
			holdObservedParam: "did not remain"}},
		{"the hold did not run", map[string]string{holdNotRunParam: "the value never arrived"}},
		{"nothing at all was recorded", map[string]string{}},
		{"a params map with unrelated keys only", map[string]string{"mrid": "CERT-BASIC-010"}},
	} {
		f := holdOutcome(&holdFast, &Observation{Params: tc.params})
		if f.Verdict == certify.Pass {
			t.Errorf("%s: holdOutcome reported PASS", tc.name)
		}
		if f.Unavailable != "" {
			t.Errorf("%s: holdOutcome abstained (%q). A Skip is severity 0 and cannot hold a release, "+
				"so this criterion must decide", tc.name, f.Unavailable)
		}
		if f.Observed == "" {
			t.Errorf("%s: holdOutcome decided with no observation", tc.name)
		}
	}
	// And the criterion built over it carries the decision rather than a Skip.
	c := critDERValueRemainedAcrossTheWindow("a maximum active power limit", &holdFast,
		&Observation{Params: map[string]string{}})
	got := c.Wire(nil, nil)
	if got.Verdict == certify.Pass || got.Unavailable != "" {
		t.Errorf("the criterion over an empty observation = %s / unavailable %q, want a decided non-PASS",
			got.Verdict, got.Unavailable)
	}
}

// ── The SHIPPING rows, not copies of their literals ─────────────────────────

// TestBASIC010_ArmsThePersistenceClaimAndBASIC013DoesNot is the construction
// test: it drives the rows a campaign actually runs.
//
// Both halves are assertions. That BASIC-010 arms the hold is the feature; that
// BASIC-013 does NOT is equally deliberate and equally worth pinning, because
// arming it there would fail a gateway that legitimately re-arbitrates a
// setpoint against a newer input — and "we turned it on everywhere" is the
// obvious next edit somebody makes.
func TestBASIC010_ArmsThePersistenceClaimAndBASIC013DoesNot(t *testing.T) {
	ten := rowByID(t, "BASIC-010").mode
	if ten.Hold == nil {
		t.Fatal("BASIC-010 arms no hold: the row commands a standing CONSTRAINT and its oracle returns " +
			"the instant the ceiling arrives, so without one the row cannot tell a held ceiling from one " +
			"the gateway's next reconcile tick undid")
	}
	if ten.Hold.Samples < 2 {
		t.Errorf("BASIC-010 holds for %d sample(s); one confirming read establishes only that the "+
			"arrival read was not a transient", ten.Hold.Samples)
	}
	if !strings.Contains(ten.Hold.Why, "opModMaxLimW") {
		t.Errorf("BASIC-010's hold does not name the control it is about:\n  %s", ten.Hold.Why)
	}

	thirteen := rowByID(t, "BASIC-013").mode
	if thirteen.Hold != nil {
		t.Errorf("BASIC-013 now arms a persistence claim (%s). opModFixedW is a SETPOINT, not a standing "+
			"constraint, and a gateway may legitimately re-arbitrate it against a newer input — asserting "+
			"persistence there fails correct behaviour. If this is intended, it is a decision about the "+
			"product's contract and belongs in the row's own comment", describeHold(thirteen.Hold))
	}

	// No row without an oracle may carry a hold: there would be no arrival for
	// the claim to be about.
	for _, r := range inverterControlRows() {
		if r.mode.Hold != nil && r.mode.Oracle == nil {
			t.Errorf("%s carries a hold with no southbound oracle", r.id)
		}
	}
}

func TestWithHold_RefusesAConstructionThatCannotMeanAnything(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func()
	}{
		{"no oracle", func() { withHold(unreachableMode("opModMaxLimW", "why"), holdMaxLim) }},
		{"no Why", func() {
			m := withOracle(scalarModeOracled("opModMaxLimW", 6000,
				func(r *ControlRequest, h int64) { r.MaxLimW = ptr(h) }), oracleMaxLimW)
			withHold(m, holdBinding{Samples: 2, Step: time.Second})
		}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("withHold(%s) did not panic; a construction error here reaches a campaign "+
						"as a row that claims something it cannot measure", tc.name)
				}
			}()
			tc.run()
		}()
	}
}

// The row-level sentence must carry the persistence half too, or a reader of
// the headline verdict sees only arrival.
func TestControlModeOutcome_CarriesBothHalves(t *testing.T) {
	ten := rowByID(t, "BASIC-010").mode

	arrived := map[string]string{
		oracleVerdictParam:     string(certify.Pass),
		oracleObservedParam:    "the DER's own WMaxLimPct resolves to a 4800.0 W active-power ceiling",
		oraclePreVerdictParam:  string(certify.Fail),
		oraclePreObservedParam: "the DER reports NO enabled WMaxLimPct",
	}

	held := map[string]string{}
	for k, v := range arrived {
		held[k] = v
	}
	held[holdVerdictParam] = string(certify.Pass)
	held[holdObservedParam] = "the commanded value REMAINED in place across 3 confirming read(s)"
	if f := ten.outcome(&Observation{Params: held}); f.Verdict != certify.Pass {
		t.Fatalf("a row whose ceiling arrived AND remained = %s: %s", f.Verdict, f.Observed)
	} else if !strings.Contains(f.Observed, "REMAINED") {
		t.Errorf("the PASS does not mention the persistence half, so a reader sees only arrival:\n  %s",
			f.Observed)
	}

	dropped := map[string]string{}
	for k, v := range arrived {
		dropped[k] = v
	}
	dropped[holdVerdictParam] = string(certify.Fail)
	dropped[holdObservedParam] = "the commanded value ARRIVED and then did NOT REMAIN: confirming " +
		"sample 2 of 3 no longer holds it"
	f := ten.outcome(&Observation{Params: dropped})
	if f.Verdict != certify.Fail {
		t.Fatalf("a row whose ceiling arrived and was then relaxed = %s — the defect this apparatus "+
			"exists to catch rolled up green: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "did NOT REMAIN") {
		t.Errorf("the row-level FAIL does not say what went wrong:\n  %s", f.Observed)
	}
	t.Logf("RED at row level — %s", holdSummary(&Observation{Params: dropped}))
}
