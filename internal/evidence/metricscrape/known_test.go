package metricscrape

import (
	"context"
	"strings"
	"testing"
)

// TestIgnoredContentKindIsNotYetIsolated is the test that has to move in the
// same commit as the product's `kind` label (known.go's integration TODO).
//
// It pins the CURRENT, honest state: IgnoredContentKind hands back the untagged
// family total and says so by returning false. If somebody lands the labelled
// selector without landing the product label, the selector matches nothing and
// every disclosure reading in the fleet quietly becomes ABSENT; if somebody
// lands the product label without flipping this, every reading keeps claiming
// the caveat it no longer needs. Either way the check and its disclosure have
// moved apart, which is the process rule the IW15-030 wave recorded — so the
// two are pinned together here.
func TestIgnoredContentKindIsNotYetIsolated(t *testing.T) {
	sel, isolated := IgnoredContentKind(KindAutonomousVRef)
	if isolated {
		t.Fatal("IgnoredContentKind reports the kind as isolated. If the product has landed the " +
			"`kind` label on lexa_nb_ignored_control_content_total, this test is the OTHER HALF of " +
			"that landing: update it to assert the labelled selector and drop the caveat requirement " +
			"from every criterion that carries IgnoredContentKindCaveat.")
	}
	if got, want := sel.String(), ignoredContentMetric; got != want {
		t.Errorf("selector = %q, want the untagged total %q — a labelled selector against a product "+
			"that exports no labels reads as ABSENT, which is a different and false fact", got, want)
	}
	if len(sel.Labels) != 0 {
		t.Errorf("selector carries labels %v the product does not export", sel.Labels)
	}
	if !strings.Contains(IgnoredContentKindCaveat, "UNTAGGED") {
		t.Error("the caveat must state the limitation it exists to disclose")
	}
	// Every kind the product can report goes through the same door today.
	for _, kind := range []string{
		KindAutonomousVRef, KindTargetVar, KindUnresolvableCurve,
		KindMalformedCurve, KindUnsupportedDefaultAxis,
	} {
		if s, iso := IgnoredContentKind(kind); iso || s.String() != ignoredContentMetric {
			t.Errorf("kind %q: got (%s, %v)", kind, s, iso)
		}
	}
}

func TestIgnoredContentTotalIsAValidSelector(t *testing.T) {
	sel := IgnoredContentTotal()
	if err := sel.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sel.Name != "lexa_nb_ignored_control_content_total" {
		t.Errorf("name = %q; it must match cmd/northbound/main.go:232 exactly", sel.Name)
	}
}

// The end-to-end shape a disclosure criterion will use, against a body in the
// form the DUT serves TODAY (one untagged total): the counter moved, the
// reading is sound, and the caveat is the sentence that keeps the claim honest.
func TestUntaggedDisclosureReadingIsUsableToday(t *testing.T) {
	open := "# TYPE lexa_nb_ignored_control_content_total counter\n" +
		"lexa_nb_ignored_control_content_total 12\n"
	closed := "# TYPE lexa_nb_ignored_control_content_total counter\n" +
		"lexa_nb_ignored_control_content_total 13\n"

	n := 0
	src := FuncSource{Description: "http://69.0.0.2:9102/metrics", Fn: func(context.Context) (Fetch, error) {
		n++
		if n == 1 {
			return Fetch{Body: []byte(open), HTTPStatus: 200}, nil
		}
		return Fetch{Body: []byte(closed), HTTPStatus: 200}, nil
	}}

	sel, isolated := IgnoredContentKind(KindAutonomousVRef)
	s, err := New(src, sel)
	if err != nil {
		t.Fatal(err)
	}
	rec := s.Open(context.Background(), "CORE-XXX").Close(context.Background())
	d, ok := rec.Find(sel)
	if !ok {
		t.Fatal("no reading")
	}
	if !d.Moved() || d.Delta != 1 {
		t.Fatalf("got %+v, want a single-step increase", d)
	}
	if isolated {
		t.Fatal("see TestIgnoredContentKindIsNotYetIsolated")
	}
	// What the criterion may claim from this, and no more.
	observed := d.Observed() + " — " + IgnoredContentKindCaveat
	if !strings.Contains(observed, "INCREASED") || !strings.Contains(observed, "IW15-030") {
		t.Errorf("the assertion text must carry both the reading and its limitation: %q", observed)
	}
}
