package metricscrape

// parse.go is a small, strict reader for the Prometheus TEXT EXPOSITION FORMAT
// (version 0.0.4 — the Content-Type the DUT's handler sets,
// vendor/lexa-platform/metrics/metrics.go:249).
//
// WHY NOT A LIBRARY. The obvious answer is
// github.com/prometheus/client_golang's expfmt. This repository vendors no
// prometheus package at all (`grep -rn prometheus go.mod vendor/modules.txt`
// finds nothing), and the PRODUCT deliberately hand-rolls the same format for
// the same reason — see the package doc of lexa-platform/metrics: "the text
// exposition format itself is trivial: `# TYPE name counter|gauge` followed by
// `name value`", against client_golang's procfs+protobuf dependency tree. A
// harness that pulled in that tree to read forty series the product writes with
// fmt.Fprintf would be adding supply chain to the referee to check something
// the referee could parse in a hundred lines. The grammar implemented here is
// the whole documented format, not the subset the product happens to emit
// today: LABELS, escapes, exponents, NaN/±Inf and trailing timestamps are all
// handled, because the point of this channel is to keep working when the
// product's output grows.
//
// STRICT, AND SAYS WHICH LINE. A line this parser does not understand makes the
// whole body malformed, with the line number and what was expected. It does not
// skip what it cannot read: a scrape that silently dropped the one line it could
// not parse would report the counter it was looking for as ABSENT, which is the
// exact false reading this package exists to prevent (see the package doc,
// "Absent is not zero").

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Series is one sample line: a metric name, its label set, and its value.
//
// Labels is nil for an unlabelled series rather than an empty map, so a caller
// can tell "no labels" from "labels that happen to be empty" by the same
// present/absent logic used everywhere else here.
type Series struct {
	Name   string
	Labels map[string]string
	Value  float64
	// Type is what the most recent "# TYPE <name> …" line declared for this
	// metric name, or "" when the body declared none. Recorded, never
	// enforced: a counter's monotonicity is checked across the window (see
	// OutcomeBackwards), not by trusting a TYPE line.
	Type string
	// Line is the 1-based line number in the body, for error messages and so a
	// reader can find the sample in the recorded artefact.
	Line int
}

// Exposition is one parsed scrape body.
type Exposition struct {
	Series []Series
	// Types maps metric name to the type its # TYPE line declared.
	Types map[string]string
}

// Parse reads a Prometheus text exposition body.
//
// It returns an error for anything it cannot read exactly — see the file
// comment. The error is what a Record stores as StatusMalformed's detail, so it
// is written to be read by somebody looking at the recorded body, i.e. it names
// the line.
func Parse(body []byte) (*Exposition, error) {
	e := &Exposition{Types: map[string]string{}}
	seen := map[string]int{} // rendered selector -> line it was first seen on

	for i, raw := range strings.Split(string(body), "\n") {
		lineNo := i + 1
		line := strings.TrimRight(raw, "\r")
		line = strings.TrimLeft(line, " \t")
		if line == "" {
			continue
		}
		if line[0] == '#' {
			// "# TYPE <name> <type>", "# HELP <name> <docstring>", or a plain
			// comment. Only TYPE carries anything worth keeping.
			f := strings.Fields(line)
			if len(f) >= 4 && f[1] == "TYPE" {
				e.Types[f[2]] = f[3]
			}
			continue
		}

		s, err := parseSample(line, fmt.Sprintf("line %d", lineNo))
		if err != nil {
			return nil, err
		}
		key := Selector{Name: s.Name, Labels: s.Labels}.String()
		if first, dup := seen[key]; dup {
			// Two samples for one series make every reading of it ambiguous,
			// and picking either one would be inventing an answer.
			return nil, fmt.Errorf("metricscrape: line %d: %s appears twice (first on line %d); "+
				"a body that reports one series two different times cannot support a reading of it",
				lineNo, key, first)
		}
		seen[key] = lineNo
		s.Line = lineNo
		s.Type = e.Types[s.Name]
		e.Series = append(e.Series, s)
	}
	return e, nil
}

// parseSample reads one sample line:
//
//	name [ "{" label "=" quoted { "," label "=" quoted } [ "," ] "}" ] value [ timestamp ]
func parseSample(line, loc string) (Series, error) {
	name, rest := takeName(line, isNameStart, isNameChar)
	if name == "" {
		return Series{}, fmt.Errorf("metricscrape: %s: %q does not start with a metric name", loc, trunc(line))
	}
	s := Series{Name: name}

	if strings.HasPrefix(rest, "{") {
		labels, after, err := parseLabels(rest, loc)
		if err != nil {
			return Series{}, err
		}
		s.Labels = labels
		rest = after
	}

	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return Series{}, fmt.Errorf("metricscrape: %s: %s has no value", loc, name)
	}
	fields := strings.Fields(rest)
	if len(fields) > 2 {
		return Series{}, fmt.Errorf("metricscrape: %s: %s has %d fields after the label set, "+
			"want a value and at most a timestamp", loc, name, len(fields))
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return Series{}, fmt.Errorf("metricscrape: %s: %s value %q is not a number", loc, name, trunc(fields[0]))
	}
	if len(fields) == 2 {
		// A trailing timestamp is legal and this package has no use for it —
		// the window's own clock is what timestamps a reading — but it must
		// still be a number, or the line is not the line we think it is.
		if _, err := strconv.ParseFloat(fields[1], 64); err != nil {
			return Series{}, fmt.Errorf("metricscrape: %s: %s trailing field %q is neither a timestamp "+
				"nor part of the value", loc, name, trunc(fields[1]))
		}
	}
	s.Value = v
	return s, nil
}

// parseLabels reads a "{…}" label set, returning the labels and the rest of the
// line. It is a character scanner rather than a split on commas because a label
// VALUE may legally contain commas, braces and escaped quotes.
func parseLabels(in, loc string) (map[string]string, string, error) {
	labels := map[string]string{}
	i := 1 // past '{'
	for {
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i >= len(in) {
			return nil, "", fmt.Errorf("metricscrape: %s: label set is not closed", loc)
		}
		if in[i] == '}' {
			return nilIfEmpty(labels), in[i+1:], nil
		}
		name, rest := takeName(in[i:], isLabelNameStart, isLabelNameChar)
		if name == "" {
			return nil, "", fmt.Errorf("metricscrape: %s: %q is not a label name", loc, trunc(in[i:]))
		}
		i = len(in) - len(rest)
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i >= len(in) || in[i] != '=' {
			return nil, "", fmt.Errorf("metricscrape: %s: label %q is not followed by '='", loc, name)
		}
		i++
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i >= len(in) || in[i] != '"' {
			return nil, "", fmt.Errorf("metricscrape: %s: label %q value is not quoted", loc, name)
		}
		val, next, err := parseQuoted(in, i, loc, name)
		if err != nil {
			return nil, "", err
		}
		if _, dup := labels[name]; dup {
			return nil, "", fmt.Errorf("metricscrape: %s: label %q appears twice in one label set", loc, name)
		}
		labels[name] = val
		i = next

		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i >= len(in) {
			return nil, "", fmt.Errorf("metricscrape: %s: label set is not closed", loc)
		}
		switch in[i] {
		case ',':
			i++
		case '}':
			return nilIfEmpty(labels), in[i+1:], nil
		default:
			return nil, "", fmt.Errorf("metricscrape: %s: expected ',' or '}' after label %q, got %q",
				loc, name, string(in[i]))
		}
	}
}

// parseQuoted reads a quoted label value starting at in[start] == '"',
// unescaping the three sequences the format defines (\\ \" \n) and refusing any
// other backslash sequence rather than guessing what it meant.
func parseQuoted(in string, start int, loc, label string) (string, int, error) {
	var sb strings.Builder
	for i := start + 1; i < len(in); i++ {
		switch in[i] {
		case '"':
			return sb.String(), i + 1, nil
		case '\\':
			if i+1 >= len(in) {
				return "", 0, fmt.Errorf("metricscrape: %s: label %q value ends in a backslash", loc, label)
			}
			i++
			switch in[i] {
			case '\\':
				sb.WriteByte('\\')
			case '"':
				sb.WriteByte('"')
			case 'n':
				sb.WriteByte('\n')
			default:
				return "", 0, fmt.Errorf("metricscrape: %s: label %q value contains the escape %q, "+
					"which the exposition format does not define", loc, label, `\`+string(in[i]))
			}
		default:
			sb.WriteByte(in[i])
		}
	}
	return "", 0, fmt.Errorf("metricscrape: %s: label %q value is not closed", loc, label)
}

// takeName consumes a leading identifier, returning it and the remainder.
func takeName(in string, start, cont func(byte) bool) (string, string) {
	if in == "" || !start(in[0]) {
		return "", in
	}
	i := 1
	for i < len(in) && cont(in[i]) {
		i++
	}
	return in[:i], in[i:]
}

// The identifier charsets of the exposition format: metric names may contain
// ':' (it is reserved for recording rules, but it is legal in a name and a
// scraper that rejected it would be wrong about a legal body); label names may
// not.
func isNameStart(c byte) bool {
	return c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isNameChar(c byte) bool { return isNameStart(c) || (c >= '0' && c <= '9') }
func isLabelNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isLabelNameChar(c byte) bool { return isLabelNameStart(c) || (c >= '0' && c <= '9') }

// Selector names the series a criterion cares about: a metric name plus the
// labels it must carry.
//
// Matching is by SUBSET, as PromQL's is: a selector's labels must all be
// present and equal on the series, and a series may carry labels the selector
// does not mention. That is what makes {kind="autonomous-vref"} keep working
// when the product later adds a second label to the same family — and it is
// also why a selector that matches MORE than one series is reported as
// OutcomeAmbiguous rather than resolved to whichever came first. An evidence
// channel does not get to pick.
type Selector struct {
	Name   string
	Labels map[string]string
}

// Sel is shorthand for an unlabelled selector.
func Sel(name string) Selector { return Selector{Name: name} }

// WithLabel returns a copy of s with one more label required. It copies rather
// than mutating so a package-level selector (see known.go) cannot be edited by
// one caller for everybody.
func (s Selector) WithLabel(name, value string) Selector {
	out := Selector{Name: s.Name, Labels: make(map[string]string, len(s.Labels)+1)}
	for k, v := range s.Labels {
		out.Labels[k] = v
	}
	out.Labels[name] = value
	return out
}

// String renders the selector in exposition spelling, with labels sorted by
// name so the same selector always renders the same string. That string is the
// KEY a bundle records and a criterion looks a reading up by, so its stability
// is part of the evidence format, not a display detail.
func (s Selector) String() string {
	if len(s.Labels) == 0 {
		return s.Name
	}
	names := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, k := range names {
		parts = append(parts, k+`="`+escapeLabelValue(s.Labels[k])+`"`)
	}
	return s.Name + "{" + strings.Join(parts, ",") + "}"
}

// ParseSelector reads back a selector from the spelling String produces.
//
// It exists so that the selector key recorded in an evidence bundle is
// SELF-DESCRIBING: a verifier — ours or a third party's — can take the string
// out of bundle.json, turn it back into the question that was asked, and put it
// to the recorded exposition body itself. Without it the bundle would record a
// number derived from a query it did not preserve, which is the shape of every
// unverifiable claim this engine exists to avoid.
func ParseSelector(s string) (Selector, error) {
	name, rest := takeName(s, isNameStart, isNameChar)
	if name == "" {
		return Selector{}, fmt.Errorf("metricscrape: %q does not start with a metric name", trunc(s))
	}
	sel := Selector{Name: name}
	if rest == "" {
		return sel, nil
	}
	if rest[0] != '{' {
		return Selector{}, fmt.Errorf("metricscrape: %q is not a selector: expected a label set after %q",
			trunc(s), name)
	}
	labels, after, err := parseLabels(rest, "selector "+strconv.Quote(trunc(s)))
	if err != nil {
		return Selector{}, err
	}
	if strings.TrimSpace(after) != "" {
		return Selector{}, fmt.Errorf("metricscrape: %q has trailing text %q after its label set",
			trunc(s), trunc(after))
	}
	sel.Labels = labels
	return sel, nil
}

// Validate reports whether the selector is a well-formed thing to ask for. A
// malformed selector is the harness's own bug — see the package doc — so New
// refuses one instead of letting it report as an absent counter.
func (s Selector) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("metricscrape: selector has no metric name")
	}
	if n, rest := takeName(s.Name, isNameStart, isNameChar); n != s.Name || rest != "" {
		return fmt.Errorf("metricscrape: %q is not a metric name", trunc(s.Name))
	}
	for k := range s.Labels {
		if n, rest := takeName(k, isLabelNameStart, isLabelNameChar); n != k || rest != "" {
			return fmt.Errorf("metricscrape: %q is not a label name (selector %s)", trunc(k), s.Name)
		}
	}
	return nil
}

// Matches reports whether one parsed series satisfies the selector.
func (s Selector) Matches(ser Series) bool {
	if ser.Name != s.Name {
		return false
	}
	for k, want := range s.Labels {
		if got, ok := ser.Labels[k]; !ok || got != want {
			return false
		}
	}
	return true
}

// Select returns every series matching sel, in body order.
//
// It returns a slice, not a value-and-found pair, because the three cases a
// caller must distinguish are none, one and MORE THAN ONE, and a signature that
// could only express the first two would have to hide the third.
func (e *Exposition) Select(sel Selector) []Series {
	var out []Series
	for _, s := range e.Series {
		if sel.Matches(s) {
			out = append(out, s)
		}
	}
	return out
}

// nilIfEmpty keeps "no labels" spelled one way — nil — whether the body wrote
// `name 1` or the legal-but-odd `name{} 1`, so two spellings of the same series
// cannot render as two different keys.
func nilIfEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

// escapeLabelValue is the inverse of parseQuoted, for rendering a selector.
func escapeLabelValue(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// trunc keeps an error message about a malformed body from quoting the whole
// body back at the reader.
func trunc(s string) string {
	const max = 60
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
