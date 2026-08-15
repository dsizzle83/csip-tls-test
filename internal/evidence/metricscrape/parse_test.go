package metricscrape

import (
	"math"
	"strings"
	"testing"
)

// The body shapes here are the DUT's own, not invented ones: lexa-platform's
// registry writes "# TYPE <name> counter" then "<name> <value>", counters
// before gauges, names sorted (vendor/lexa-platform/metrics/metrics.go
// writeTo). The labelled samples are the shape the product's ignored-content
// counter is expected to take once it grows a `kind` label — see known.go's
// integration TODO.
const dutBody = `# TYPE lexa_bus_decode_failures_total counter
lexa_bus_decode_failures_total 0
# TYPE lexa_nb_ignored_control_content_total counter
lexa_nb_ignored_control_content_total 7
# TYPE lexa_nb_walk_failures_total counter
lexa_nb_walk_failures_total 2
# TYPE lexa_goroutines gauge
lexa_goroutines 43
# TYPE lexa_nb_clock_offset_seconds gauge
lexa_nb_clock_offset_seconds -0.5
# TYPE lexa_up gauge
lexa_up 1
`

func TestParseReadsTheDUTBodyShape(t *testing.T) {
	e, err := Parse([]byte(dutBody))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(e.Series) != 6 {
		t.Fatalf("parsed %d series, want 6", len(e.Series))
	}
	got := e.Select(Sel("lexa_nb_ignored_control_content_total"))
	if len(got) != 1 || got[0].Value != 7 {
		t.Fatalf("ignored-content total = %+v, want one series valued 7", got)
	}
	if got[0].Type != "counter" {
		t.Errorf("type = %q, want counter (from the # TYPE line)", got[0].Type)
	}
	if got[0].Line != 4 {
		t.Errorf("line = %d, want 4 so a reader can find the sample in the artefact", got[0].Line)
	}
	// A gauge is not special-cased anywhere; it reads like anything else.
	if g := e.Select(Sel("lexa_nb_clock_offset_seconds")); len(g) != 1 || g[0].Value != -0.5 {
		t.Errorf("clock offset = %+v, want -0.5", g)
	}
}

func TestParseLabelsAndSelectorMatching(t *testing.T) {
	body := `# HELP lexa_nb_ignored_control_content_total content the carriage cannot represent
# TYPE lexa_nb_ignored_control_content_total counter
lexa_nb_ignored_control_content_total{kind="autonomous-vref"} 3
lexa_nb_ignored_control_content_total{kind="target_var"} 11
lexa_nb_ignored_control_content_total{kind="unresolvable-curve",program="prog-1"} 1
`
	e, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sel := Sel(ignoredContentMetric).WithLabel("kind", KindAutonomousVRef)
	got := e.Select(sel)
	if len(got) != 1 || got[0].Value != 3 {
		t.Fatalf("%s selected %+v, want the single series valued 3", sel, got)
	}
	// Subset matching: a selector naming one label still finds a series that
	// carries a second one.
	sub := Sel(ignoredContentMetric).WithLabel("kind", KindUnresolvableCurve)
	if got := e.Select(sub); len(got) != 1 || got[0].Value != 1 {
		t.Fatalf("%s selected %+v, want the two-label series", sub, got)
	}
	// And the bare name matches every one of them, which is precisely why an
	// unlabelled reading of a labelled family is AMBIGUOUS rather than a total.
	if got := e.Select(Sel(ignoredContentMetric)); len(got) != 3 {
		t.Fatalf("bare name selected %d series, want all 3", len(got))
	}
}

func TestParseHandlesTheFormatsAwkwardCorners(t *testing.T) {
	body := "# a bare comment\n" +
		"\n" +
		"empty_labels{} 4\n" +
		"escaped{note=\"a \\\"quoted\\\" \\\\ value\",second=\"line\\nbreak\"} 1\n" +
		"with_timestamp 12 1700000000000\n" +
		"exponent 1.5e3\n" +
		"not_a_number{k=\"v\"} NaN\n" +
		"positive_inf +Inf\r\n" +
		"comma_in_label{k=\"a,b}c\"} 9\n"
	e, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := e.Select(Sel("empty_labels")); len(got) != 1 || got[0].Labels != nil {
		t.Errorf("`name{} 4` should read as the unlabelled series, got %+v", got)
	}
	esc := e.Select(Sel("escaped"))
	if len(esc) != 1 {
		t.Fatalf("escaped: %+v", esc)
	}
	if esc[0].Labels["note"] != `a "quoted" \ value` {
		t.Errorf("note label = %q", esc[0].Labels["note"])
	}
	if esc[0].Labels["second"] != "line\nbreak" {
		t.Errorf("second label = %q", esc[0].Labels["second"])
	}
	if got := e.Select(Sel("with_timestamp")); len(got) != 1 || got[0].Value != 12 {
		t.Errorf("a trailing timestamp must not disturb the value: %+v", got)
	}
	if got := e.Select(Sel("exponent")); len(got) != 1 || got[0].Value != 1500 {
		t.Errorf("exponent = %+v", got)
	}
	if got := e.Select(Sel("not_a_number")); len(got) != 1 || !math.IsNaN(got[0].Value) {
		t.Errorf("NaN is a legal sample value: %+v", got)
	}
	if got := e.Select(Sel("positive_inf")); len(got) != 1 || !math.IsInf(got[0].Value, 1) {
		t.Errorf("+Inf (with a CRLF line ending) = %+v", got)
	}
	if got := e.Select(Sel("comma_in_label")); len(got) != 1 || got[0].Labels["k"] != "a,b}c" {
		t.Errorf("a label value may contain commas and braces: %+v", got)
	}
}

// A malformed line must fail the WHOLE body. Skipping it would let a scrape
// report the counter it was looking for as ABSENT because the line it could not
// read happened to be that counter's — the exact false reading this channel
// exists to prevent.
func TestParseRefusesMalformedBodies(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"no value", "lexa_up\n", "has no value"},
		{"value is not a number", "lexa_up yes\n", "is not a number"},
		{"unclosed label set", `lexa_up{kind="x"` + "\n", "label set is not closed"},
		{"label set runs into the value", `lexa_up{kind="x" 1` + "\n", `expected ',' or '}'`},
		{"unquoted label value", "lexa_up{kind=x} 1\n", "not quoted"},
		{"undefined escape", `lexa_up{kind="a\tb"} 1` + "\n", "does not define"},
		{"junk line", "!!!\n", "does not start with a metric name"},
		{"three fields", "lexa_up 1 2 3\n", "fields after the label set"},
		{"duplicate series", "lexa_up 1\nlexa_up 2\n", "appears twice"},
		{"duplicate label", `lexa_up{k="a",k="b"} 1` + "\n", "appears twice in one label set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.body))
			if err == nil {
				t.Fatalf("Parse accepted %q", c.body)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not say %q", err, c.want)
			}
		})
	}
}

func TestSelectorRendersAndParsesBack(t *testing.T) {
	cases := []Selector{
		Sel("lexa_up"),
		Sel(ignoredContentMetric).WithLabel("kind", KindAutonomousVRef),
		Sel("m").WithLabel("b", "2").WithLabel("a", `quote" and \ backslash`),
	}
	for _, sel := range cases {
		key := sel.String()
		back, err := ParseSelector(key)
		if err != nil {
			t.Fatalf("ParseSelector(%q): %v", key, err)
		}
		if back.String() != key {
			t.Errorf("round trip: %q -> %q", key, back.String())
		}
	}
	// Label order must not change the key: the key is a bundle's lookup handle.
	a := Sel("m").WithLabel("z", "1").WithLabel("a", "2")
	b := Sel("m").WithLabel("a", "2").WithLabel("z", "1")
	if a.String() != b.String() {
		t.Errorf("selector rendering is order-dependent: %q vs %q", a, b)
	}
	if _, err := ParseSelector("lexa_up{kind=x}"); err == nil {
		t.Error("ParseSelector accepted an unquoted label value")
	}
	if _, err := ParseSelector(`lexa_up{k="v"} trailing`); err == nil {
		t.Error("ParseSelector accepted trailing text")
	}
}

func TestSelectorValidateCatchesOurOwnMistakes(t *testing.T) {
	for _, sel := range []Selector{
		{},
		{Name: "has space"},
		{Name: "ok", Labels: map[string]string{"bad-label": "v"}},
		{Name: "1_leading_digit"},
	} {
		if err := sel.Validate(); err == nil {
			t.Errorf("Validate accepted %#v — a malformed selector must not be able to masquerade "+
				"as an absent counter", sel)
		}
	}
	if err := (Sel("lexa:recording_rule_style").WithLabel("k", "v")).Validate(); err != nil {
		t.Errorf("a legal name with a colon was rejected: %v", err)
	}
}
