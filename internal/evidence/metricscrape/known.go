package metricscrape

import "sort"

// known.go names the DUT counters this bench has a reason to read, so that a
// criterion cites a NAME defined next to its provenance instead of a string
// literal three packages away from any evidence that the product exports it.
//
// Everything here is cited from lexa-gw source, read at harness commit time
// against lexa-gw branch remediation/rc0-failsafe-core. A counter that is
// renamed on the product side must break HERE — one file, with the file:line
// that justified it — rather than quietly start reporting ABSENT in a run.

// The ignored-content family.
//
// WHAT IT COUNTS. lexa-gw's northbound walker sweeps everything the utility
// server serves — the extended default control and every extended event, not
// just the active one — for content its bus carriage cannot represent, and
// reports each occurrence through discovery.ReportIgnoredContent(kind, detail)
// (internal/northbound/discovery/walker.go:936-944). That function does two
// things: a rate-limited slog WARN carrying the kind, and an atomic increment
// of a process-global total exposed as discovery.IgnoredContentTotal()
// (walker.go:946-951). cmd/northbound/main.go:231-233 registers a scrape-time
// Collect hook that mirrors that total into the Prometheus counter named below.
//
// WHY THE BENCH CARES. One member of the family is not a defect. 2030.5-2018
// p.252 prescribes executing a volt-var curve WITHOUT autonomous vRef
// adjustment when the DER cannot support it, so the gateway ACCEPTS the
// control, executes the curve, owes no CannotComply — and discloses the
// unacted-upon element rather than dropping it silently (walker.go:907-918).
// The harness can see the acceptance and the execution on the wire. The
// disclosure is what this channel exists to make bench-readable (IW15-030).
const (
	// KindAutonomousVRef — a volt-var curve carrying autonomousVRefEnable=true
	// (publish/publish.go:913). Not a defect; see above.
	KindAutonomousVRef = "autonomous-vref"
	// KindTargetVar — opModTargetVar, which has no ActiveControl field
	// (walker.go:974).
	KindTargetVar = "target_var"
	// KindUnresolvableCurve — a curve-linked opMod whose href is empty or is
	// not in the program's fetched DERCurveList (walker.go:984-988).
	KindUnresolvableCurve = "unresolvable-curve"
	// KindMalformedCurve — a resolved curve that fails the publish-side content
	// gate (publish/publish.go:890).
	KindMalformedCurve = "malformed-curve"
	// KindUnsupportedDefaultAxis — a default-control axis the scheduler cannot
	// support (scheduler/supported.go:954).
	KindUnsupportedDefaultAxis = "unsupported-default-axis"
	// KindUnsupportedEventAxis — a CAPABILITY-unsupported axis TRIMMED off an
	// EVENT DERControl, the event-scoped sibling of KindUnsupportedDefaultAxis:
	// the same axis-support gate applied to a scheduled/active event rather than
	// to the DefaultDERControl (lexa-gw walker.go:1425,
	// IgnoredContentUnsupportedEventAxis, series
	// lexa_nb_ignored_control_content_unsupported_event_axis_total). Before it
	// was enumerated here its reading fell into the untagged family total, so a
	// criterion about a trimmed EVENT axis could not tell it apart from every
	// other ignored-content kind — the isolation this map exists to give.
	KindUnsupportedEventAxis = "unsupported-event-axis"
	// KindOther is not a kind the product reports — it is the bucket a kind
	// with no enumerated series lands in (walker.go:990,
	// ignoredContentOtherMetric). A NON-ZERO reading here is itself a finding
	// on the product: someone added a ReportIgnoredContent call site without
	// adding its kind to the enumeration, so the disclosure is incomplete and
	// whichever criterion cares about that kind is reading a series that will
	// never move. It is named here so a bench criterion can assert it stays
	// zero rather than having to know the string.
	KindOther = "other"
)

// ignoredContentMetric is the exported counter's name, from the one place the
// product registers it: cmd/northbound/main.go:232.
const ignoredContentMetric = "lexa_nb_ignored_control_content_total"

// IgnoredContentTotal selects the family's UNTAGGED total: every kind, summed,
// since the process started.
//
// This is the whole-family observable and it is sound on its own terms — "the
// gateway reported ignored content during this window" — but it does not
// isolate a kind. Use IgnoredContentKind when the criterion is about one.
func IgnoredContentTotal() Selector { return Sel(ignoredContentMetric) }

// ignoredContentKindMetric is the per-kind series the product exports, keyed by
// the kind string, transcribed from the ONE place the product enumerates them:
// lexa-gw internal/northbound/discovery/walker.go:977-983
// (ignoredContentKindMetric) plus walker.go:990's other-bucket. Read at gw
// 49a84c6.
//
// ── The shape is NAMES, not a label, and that was not what this bench
//
//	predicted ─────────────────────────────────────────────────────────────
//
// The TODO this replaces said the integration would be "return
// Sel(metric).WithLabel(\"kind\", kind)". It is not: lexa-platform/metrics has no
// label support at all — Registry.Counter(name) takes a plain string and writeTo
// renders `# TYPE <name> counter` verbatim — so a {kind="…"} suffix smuggled
// into a name would emit an invalid TYPE line and fail the WHOLE scrape, taking
// every other metric on the endpoint with it. The product put the kind in the
// NAME instead, one counter per kind (walker.go's own note says so). The
// prediction being wrong cost nothing because the boolean contract absorbed it:
// every caller branches on `isolated`, not on how isolation is achieved.
//
// The map is explicit rather than composed from a prefix, mirroring the
// product's own reasoning: a name derived from a caller string is one refactor
// away from letting a DERMS document choose what appears on a /metrics
// endpoint, and a kind with no entry must land in the other-bucket LOUDLY
// rather than be silently renamed.
var ignoredContentKindMetric = map[string]string{
	KindTargetVar:              "lexa_nb_ignored_control_content_target_var_total",
	KindUnresolvableCurve:      "lexa_nb_ignored_control_content_unresolvable_curve_total",
	KindMalformedCurve:         "lexa_nb_ignored_control_content_malformed_curve_total",
	KindAutonomousVRef:         "lexa_nb_ignored_control_content_autonomous_vref_total",
	KindUnsupportedDefaultAxis: "lexa_nb_ignored_control_content_unsupported_default_axis_total",
	KindUnsupportedEventAxis:   "lexa_nb_ignored_control_content_unsupported_event_axis_total",
	KindOther:                  "lexa_nb_ignored_control_content_other_total",
}

// IgnoredContentKind selects one KIND of ignored content, and reports whether
// the selector it returned actually ISOLATES that kind.
//
// IT NOW ISOLATES, for every enumerated kind. lexa-gw 49a84c6 gave the family a
// series per kind, so a criterion about autonomous-vref reads a counter that
// only autonomous-vref moves — which is what IW15-030 needed and could not have
// before: summed into one total, an ACCEPTED control whose vRef element is the
// only unacted-upon part (2018 p.252) was indistinguishable from the kinds that
// ARE defects, and "disclosed rather than silent" degraded to "a number went
// up, cause unknown".
//
// The second return value stays, and stays load-bearing, for the kind this
// bench does NOT know: an unenumerated kind gets the untagged family total and
// false, because a selector naming a series the product never exports would
// read ABSENT — and an absent series and an unisolated kind are different
// facts. A criterion MUST still branch on it and carry
// IgnoredContentKindCaveat when it is false.
//
// ONE THING THE ISOLATION DOES NOT BUY, and a criterion must not assume it: a
// per-kind counter attributes the disclosure, not its CAUSE. Two controls in
// one window that both carry autonomous vRef move it twice, and the counter
// cannot say which. Where a row needs that, it must bound the window to one
// control — which is what the suite's per-row Open/Close already does.
func IgnoredContentKind(kind string) (sel Selector, isolated bool) {
	if name, ok := ignoredContentKindMetric[kind]; ok {
		return Sel(name), true
	}
	return Sel(ignoredContentMetric), false
}

// IgnoredContentKinds returns every kind this bench can isolate, ascending, so
// a criterion that wants the whole family can ask for it without restating the
// list.
func IgnoredContentKinds() []string {
	out := make([]string, 0, len(ignoredContentKindMetric))
	for k := range ignoredContentKindMetric {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IgnoredContentKindCaveat is the sentence an assertion must carry when it
// cites IgnoredContentKind's selector while isolated is false — now only for a
// kind this bench does not enumerate. It is a constant so that every row
// leaning on the unisolated total says the same thing, and so that grepping for
// it finds every claim that has to be revisited.
const IgnoredContentKindCaveat = "this kind is not one the bench can isolate, so the reading falls back " +
	"to the gateway's UNTAGGED ignored-content total (lexa_nb_ignored_control_content_total): it shows " +
	"that ignored content was disclosed during the window, not that this particular kind was, because " +
	"any other ignorable content served in the same window contributes to the same counter (IW15-030)"
