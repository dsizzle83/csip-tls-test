package metricscrape

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// TestIgnoredContentKindIsIsolated is the OTHER HALF of lexa-gw 49a84c6's
// landing, and it is the inversion of a test that pinned the opposite.
//
// It used to be TestIgnoredContentKindIsNotYetIsolated, pinning the honest
// state of the day: the product exported one untagged family total, so
// IgnoredContentKind handed that back and said so by returning false. The rule
// it enforced was that the check and its disclosure must move together — land
// the selector without the product surface and every disclosure reading
// silently becomes ABSENT; land the product surface without the selector and
// every reading keeps carrying a caveat it no longer needs.
//
// The product surface landed, so this moved with it. The shape was not what the
// TODO predicted — per-kind metric NAMES rather than a `kind` label, because
// lexa-platform/metrics has no label support and an inline label set in a name
// would emit an invalid TYPE line and fail the whole scrape — and the boolean
// contract absorbed that completely, which is the argument for having had one.
func TestIgnoredContentKindIsIsolated(t *testing.T) {
	sel, isolated := IgnoredContentKind(KindAutonomousVRef)
	if !isolated {
		t.Fatal("IgnoredContentKind still reports autonomous-vref as unisolated. lexa-gw 49a84c6 " +
			"exports lexa_nb_ignored_control_content_autonomous_vref_total; if that has been reverted, " +
			"this test is the other half of the revert.")
	}
	if got, want := sel.Name, "lexa_nb_ignored_control_content_autonomous_vref_total"; got != want {
		t.Errorf("selector = %q, want %q — transcribed from lexa-gw walker.go:977-983, the one place "+
			"the product enumerates the family", got, want)
	}
	if len(sel.Labels) != 0 {
		t.Errorf("selector carries labels %v; the product exports none and a labelled selector against "+
			"it would match nothing and read as ABSENT", sel.Labels)
	}
	if err := sel.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}

	// Every enumerated kind isolates, and each names a DISTINCT series — a map
	// typo that pointed two kinds at one counter would make both readings true
	// and one of them wrong.
	seen := map[string]string{}
	for _, kind := range IgnoredContentKinds() {
		s, iso := IgnoredContentKind(kind)
		if !iso {
			t.Errorf("kind %q does not isolate", kind)
			continue
		}
		if prev, dup := seen[s.Name]; dup {
			t.Errorf("kinds %q and %q both select %q", prev, kind, s.Name)
		}
		seen[s.Name] = kind
		if !strings.HasPrefix(s.Name, "lexa_nb_ignored_control_content_") ||
			!strings.HasSuffix(s.Name, "_total") {
			t.Errorf("kind %q selects %q, which is not a member of the family", kind, s.Name)
		}
	}
	if len(seen) != 7 {
		t.Errorf("the bench enumerates %d series; the product enumerates six kinds plus the "+
			"other-bucket (walker.go:977-990, incl. unsupported-event-axis at walker.go:1425)", len(seen))
	}

	// A kind the bench does NOT enumerate must fall back to the untagged total
	// and say so — never to a composed name for a series nobody exports.
	fallback, iso := IgnoredContentKind("a-kind-nobody-has-added-yet")
	if iso {
		t.Error("an unenumerated kind reports as isolated; the selector would name a series the " +
			"product does not export, and an ABSENT reading is a different and false fact")
	}
	if fallback.Name != ignoredContentMetric {
		t.Errorf("the fallback selects %q, want the untagged total %q", fallback.Name, ignoredContentMetric)
	}
	if !strings.Contains(IgnoredContentKindCaveat, "not one the bench can isolate") {
		t.Error("the caveat no longer states the limitation it exists to disclose")
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

// The end-to-end shape the autonomous-vRef disclosure criterion uses, against a
// body in the form the DUT serves NOW: the per-kind counter moved by exactly
// one, the reading isolates, and no caveat is owed.
//
// This test used to serve one untagged total and require the caveat. Both
// halves changed at lexa-gw 49a84c6 and the change is visible here rather than
// only in the selector's unit test, because THIS is the shape a bundle carries.
func TestPerKindDisclosureReadingIsolatesTheVRefKind(t *testing.T) {
	// The whole family, as the product exposes it — every series present at 0
	// from process start (walker.go's ignoredContentCounts is built eagerly),
	// which is what makes "measured zero" distinguishable from "absent" at all.
	body := func(vref int) string {
		return "# TYPE lexa_nb_ignored_control_content_total counter\n" +
			"lexa_nb_ignored_control_content_total " + itoa(12+vref) + "\n" +
			"# TYPE lexa_nb_ignored_control_content_target_var_total counter\n" +
			"lexa_nb_ignored_control_content_target_var_total 4\n" +
			"# TYPE lexa_nb_ignored_control_content_autonomous_vref_total counter\n" +
			"lexa_nb_ignored_control_content_autonomous_vref_total " + itoa(8+vref) + "\n" +
			"# TYPE lexa_nb_ignored_control_content_other_total counter\n" +
			"lexa_nb_ignored_control_content_other_total 0\n"
	}

	n := 0
	src := FuncSource{Description: "http://69.0.0.2:9102/metrics", Fn: func(context.Context) (Fetch, error) {
		n++
		if n == 1 {
			return Fetch{Body: []byte(body(0)), HTTPStatus: 200}, nil
		}
		return Fetch{Body: []byte(body(1)), HTTPStatus: 200}, nil
	}}

	sel, isolated := IgnoredContentKind(KindAutonomousVRef)
	if !isolated {
		t.Fatal("see TestIgnoredContentKindIsIsolated")
	}
	s, err := New(src, sel)
	if err != nil {
		t.Fatal(err)
	}
	rec := s.Open(context.Background(), "BASIC-006").Close(context.Background())
	d, ok := rec.Find(sel)
	if !ok {
		t.Fatal("no reading")
	}
	if !d.Moved() || d.Delta != 1 {
		t.Fatalf("got %+v, want a single-step increase on the vref series alone", d)
	}
	observed := d.Observed()
	if !strings.Contains(observed, "INCREASED") {
		t.Errorf("the assertion text does not carry the reading: %q", observed)
	}
	// The other-bucket must be readable in the same window and must be ZERO —
	// a non-zero there means a ReportIgnoredContent call site exists whose kind
	// nobody enumerated, so the family's attribution is incomplete and this
	// row's own series may never move for a reason nothing else would show.
	other, _ := IgnoredContentKind(KindOther)
	if od, ok := rec.Find(other); ok && od.CloseValue != 0 {
		t.Errorf("the other-bucket reads %v; a non-zero value is a finding on the product's "+
			"enumeration, not on this row", od.CloseValue)
	}
}

// An OLD gateway — one that predates the per-kind split and exports only the
// untagged total — must read ABSENT on the per-kind series, not zero.
//
// This is the absent-vs-present-and-zero distinction doing the job it was built
// for, on the exact case that will occur: a bench pointed at a stale image. A
// scrape that reported the missing series as 0 would let a disclosure criterion
// conclude "the gateway disclosed nothing" from a gateway that cannot disclose
// anything on that surface — the false PASS this channel exists to refuse.
func TestAPreSplitGatewayReadsAbsentNotZero(t *testing.T) {
	old := "# TYPE lexa_nb_ignored_control_content_total counter\n" +
		"lexa_nb_ignored_control_content_total 12\n"
	src := FuncSource{Description: "http://69.0.0.2:9102/metrics", Fn: func(context.Context) (Fetch, error) {
		return Fetch{Body: []byte(old), HTTPStatus: 200}, nil
	}}
	sel, _ := IgnoredContentKind(KindAutonomousVRef)
	s, err := New(src, sel)
	if err != nil {
		t.Fatal(err)
	}
	rec := s.Open(context.Background(), "BASIC-006").Close(context.Background())
	d, ok := rec.Find(sel)
	if !ok {
		t.Fatal("no reading")
	}
	if d.Outcome != OutcomeAbsent {
		t.Fatalf("outcome = %s, want ABSENT: a gateway too old to split the family must not read as a "+
			"gateway that disclosed nothing", d.Outcome)
	}
	if d.Moved() {
		t.Error("an absent series reported as moved")
	}
	if !strings.Contains(d.Detail, "NOT a reading of zero") {
		t.Errorf("the detail must say what absent means: %q", d.Detail)
	}
}

// itoa keeps the fixture bodies readable without pulling strconv into the
// test's own vocabulary at every call site.
func itoa(n int) string { return strconv.Itoa(n) }
