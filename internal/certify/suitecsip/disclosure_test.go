package suitecsip

// disclosure_test.go — IW15-030's loop, closed end to end.
//
// The claim under test is not "the scrape works" — internal/evidence/metricscrape
// proves that. It is that a ROW carries the reading to a verdict, that the
// verdict says the right thing about each shape the DUT can present, and that a
// bench which did not look never reads as a bench that looked and saw nothing.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/metricscrape"
)

// familyBody renders the ignored-content family the way the DUT serves it —
// every series present, zeros included, which is what lexa-gw's eagerly-built
// ignoredContentCounts guarantees and what makes "measured zero" a different
// reading from "absent".
func familyBody(vref, targetVar int) string {
	var b strings.Builder
	line := func(name string, v int) {
		b.WriteString("# TYPE " + name + " counter\n")
		b.WriteString(name + " " + itoaTest(v) + "\n")
	}
	line("lexa_nb_ignored_control_content_total", vref+targetVar)
	for _, k := range metricscrape.IgnoredContentKinds() {
		sel, _ := metricscrape.IgnoredContentKind(k)
		switch k {
		case metricscrape.KindAutonomousVRef:
			line(sel.Name, vref)
		case metricscrape.KindTargetVar:
			line(sel.Name, targetVar)
		default:
			line(sel.Name, 0)
		}
	}
	return b.String()
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// runDisclosure drives HOOK 1 and HOOK 2 over a fake endpoint serving `open`
// then `closed`, and returns the params a criterion would grade.
func runDisclosure(t *testing.T, kind, open, closed string) map[string]string {
	t.Helper()
	n := 0
	src := metricscrape.FuncSource{
		Description: "http://69.0.0.2:9102/metrics",
		Fn: func(context.Context) (metricscrape.Fetch, error) {
			n++
			if n == 1 {
				return metricscrape.Fetch{Body: []byte(open), HTTPStatus: 200}, nil
			}
			return metricscrape.Fetch{Body: []byte(closed), HTTPStatus: 200}, nil
		},
	}
	// The row reaches its endpoint through Targets.Extra; the source is
	// substituted here rather than standing up an HTTP server, because what is
	// under test is the ROW's use of the channel and not the channel's own
	// transport (which metricscrape tests directly).
	params := map[string]string{}
	sels := []metricscrape.Selector{metricscrape.IgnoredContentTotal()}
	for _, k := range metricscrape.IgnoredContentKinds() {
		ks, _ := metricscrape.IgnoredContentKind(k)
		sels = append(sels, ks)
	}
	s, err := metricscrape.New(src, sels...)
	if err != nil {
		t.Fatal(err)
	}
	sel, isolated := metricscrape.IgnoredContentKind(kind)
	if kind != "" && !isolated {
		params[disclosureCaveatParam] = metricscrape.IgnoredContentKindCaveat
	}
	d := &Driver{disclosure: &disclosureWindow{
		win: s.Open(context.Background(), "TEST"), sel: sel, isolated: isolated, kind: kind,
	}}
	recordDisclosure(context.Background(), d, params)
	if len(d.metrics) != 1 {
		t.Fatalf("the row recorded %d scrape record(s); the runner persists these into the bundle and "+
			"verify re-derives from them, so a row that records none has no re-checkable evidence",
			len(d.metrics))
	}
	return params
}

// GREEN on the claim that arms today: a well-formed curve, and not one counter
// of the family moved.
func TestDisclosure_NothingDroppedIsAPassOnAQuietFamily(t *testing.T) {
	params := runDisclosure(t, "", familyBody(8, 4), familyBody(8, 4))
	f := droppedContentOutcome(&Observation{Params: params})
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s over a family that did not move: %s", f.Verdict, findingObserved(f))
	}
	t.Logf("GREEN — %s", f.Observed)
}

// RED: something the row published was accepted and dropped. The FAIL must NAME
// the kind, or it is unactionable.
func TestDisclosure_AMovedCounterIsAFailThatNamesTheKind(t *testing.T) {
	params := runDisclosure(t, "", familyBody(8, 4), familyBody(8, 5))
	f := droppedContentOutcome(&Observation{Params: params})
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s while an ignored-content counter moved: %s", f.Verdict, findingObserved(f))
	}
	if !strings.Contains(f.Observed, metricscrape.KindTargetVar) {
		t.Errorf("the FAIL does not name the kind that moved:\n  %s", f.Observed)
	}
	t.Logf("RED — %s", f.Observed)
}

// The p.252 arm: a row that DID publish autonomousVRefEnable=true asserts the
// disclosure happened, and passes only when the kind's own counter moved.
func TestDisclosure_TheVRefArmPassesOnlyWhenItsOwnCounterMoves(t *testing.T) {
	moved := runDisclosure(t, metricscrape.KindAutonomousVRef, familyBody(8, 4), familyBody(9, 4))
	if f := disclosureOutcome(metricscrape.KindAutonomousVRef, &Observation{Params: moved}); f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s when the vref counter moved: %s", f.Verdict, findingObserved(f))
	} else {
		t.Logf("GREEN (p.252 disclosure) — %s", f.Observed)
	}

	// A SOUND reading of nothing: the counter exists, was read at both ends,
	// and did not move. That is the finding this channel was built to state —
	// the gateway accepted content it could not act on and disclosed nothing.
	still := runDisclosure(t, metricscrape.KindAutonomousVRef, familyBody(8, 4), familyBody(8, 5))
	f := disclosureOutcome(metricscrape.KindAutonomousVRef, &Observation{Params: still})
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s when the vref counter did NOT move: %s", f.Verdict, findingObserved(f))
	}
	t.Logf("RED (undisclosed) — %s", f.Observed)
}

// A gateway too old to split the family reads ABSENT, and ABSENT must never be
// graded as a pass or as a device failure. This is the absent-versus-zero rule
// arriving at a verdict.
func TestDisclosure_APreSplitGatewayIsWarnedNotFailed(t *testing.T) {
	old := "# TYPE lexa_nb_ignored_control_content_total counter\n" +
		"lexa_nb_ignored_control_content_total 12\n"
	params := runDisclosure(t, metricscrape.KindAutonomousVRef, old, old)
	f := disclosureOutcome(metricscrape.KindAutonomousVRef, &Observation{Params: params})
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s against a gateway that exports no per-kind series: %s",
			f.Verdict, findingObserved(f))
	}
	if !strings.Contains(f.Observed, "NOT a reading of zero") {
		t.Errorf("the verdict does not say what absent means:\n  %s", f.Observed)
	}
	t.Logf("WARN (pre-split gateway) — %s", f.Observed)
}

// A bench with no endpoint configured must say so, and must never read as a
// bench that looked and saw nothing.
func TestDisclosure_AnUnconfiguredBenchIsAWarnNamingItself(t *testing.T) {
	params := map[string]string{}
	rc := &certify.RunCtx{Targets: certify.Targets{}}
	if w := openDisclosureWindow(context.Background(), rc, params, "", "TEST"); w != nil {
		t.Fatal("a run with no metrics endpoint opened a window anyway")
	}
	why := params[disclosureUnavailableParam]
	if why == "" {
		t.Fatal("nothing was recorded, so the criterion cannot tell 'not configured' from 'nothing moved'")
	}
	if !strings.Contains(why, metricsTargetKey) || !strings.Contains(why, "9102") {
		t.Errorf("the reason does not say how to configure it:\n  %s", why)
	}
	// UNAVAILABLE, not a verdict. This criterion is supplementary — the row's
	// subject is execution, and the southbound oracle carries that — so an
	// unconfigured bench must not WARN every curve row in the campaign about
	// the operator's flags. It must also never PASS.
	for _, f := range []Finding{
		droppedContentOutcome(&Observation{Params: params}),
		disclosureOutcome(metricscrape.KindAutonomousVRef, &Observation{Params: params}),
	} {
		if f.Unavailable == "" {
			t.Errorf("verdict = %s on an unconfigured bench; a bench that did not look must abstain "+
				"rather than grade the device: %s", f.Verdict, findingObserved(f))
		}
		if f.Verdict == certify.Pass {
			t.Error("an unconfigured bench produced a PASS")
		}
		if !strings.Contains(f.Unavailable, "fact about the bench") {
			t.Errorf("the abstention does not say whose fact this is:\n  %s", f.Unavailable)
		}
	}
	t.Logf("WARN (bench did not look) — %s", why)
}

// The kind a row asserts is DERIVED from what it published, so a row cannot
// claim a disclosure it never asked for.
func TestDisclosureKindFor_FollowsWhatTheRowPublished(t *testing.T) {
	six := rowByID(t, "BASIC-006").mode.Curve
	if six == nil {
		t.Fatal("BASIC-006 carries no curve binding")
	}
	if got := disclosureKindFor(six); got != "" {
		t.Errorf("BASIC-006 asserts the %q disclosure. Figure 6 prints autonomousVrefEnable false in "+
			"BOTH columns, so this row publishes false and the p.252 obligation does not arise; "+
			"asserting it would fail a correct gateway for not disclosing something nobody asked it to "+
			"ignore", got)
	}
	// And the arm does exist: a binding that publishes true takes it.
	enable := true
	armed := *six
	armed.AutonomousVRefEnable = &enable
	if got := disclosureKindFor(&armed); got != metricscrape.KindAutonomousVRef {
		t.Errorf("a row publishing autonomousVRefEnable=true derives kind %q, want %q",
			got, metricscrape.KindAutonomousVRef)
	}
}
