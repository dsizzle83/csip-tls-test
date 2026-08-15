package metricscrape

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

// IgnoredContentKind selects one KIND of ignored content, and reports whether
// the selector it returned actually ISOLATES that kind.
//
// The second return value is the honest half. TODAY IT IS ALWAYS false: the
// product exports one untagged total (cmd/northbound/main.go:232 sets a plain
// Counter from discovery.IgnoredContentTotal()), the kind reaches only the
// slog WARN, and the internal kind|detail map behind it
// (walker.go:925-927, ignoredContentSeen) is never exported. This was gate
// #17's finding on the IW15-030 remediation proposal, and it is why this
// function returns the untagged selector rather than a labelled one that would
// match nothing and read as ABSENT — an absent series and an unisolated kind
// are different facts, and only one of them is true here.
//
// A criterion MUST branch on the second value. With isolated == false, a
// movement in this counter proves that the gateway disclosed SOMETHING ignored
// inside the window, not that it disclosed this kind, and any assertion built
// on it has to say so — which is what IgnoredContentKindCaveat is for.
//
// TODO(IW15-030 integration): when the product side lands the `kind` label on
// lexa_nb_ignored_control_content_total, THIS FUNCTION'S BODY IS THE ONE-LINE
// CHANGE — return `Sel(ignoredContentMetric).WithLabel("kind", kind), true`
// instead of the untagged selector and false. Nothing else in this package or
// in a calling suite changes: the parser already reads labels, Selector already
// matches them, and the caveat below already keys off the boolean. Land it in
// the same commit as the product's label, and flip
// TestIgnoredContentKindIsNotYetIsolated (known_test.go) with it — the test
// exists so the disclosure and the check that cites it cannot move apart, which
// is the process rule the same wave recorded.
func IgnoredContentKind(kind string) (sel Selector, isolated bool) {
	_ = kind // the product has no per-kind series to select on yet — see the TODO above
	return Sel(ignoredContentMetric), false
}

// IgnoredContentKindCaveat is the sentence an assertion must carry when it
// cites IgnoredContentKind's selector while isolated is false. It is a constant
// so that every row that leans on the unisolated total says the same thing, and
// so that grepping for it finds every claim that has to be revisited when the
// label lands.
const IgnoredContentKindCaveat = "the gateway exports one UNTAGGED ignored-content total " +
	"(lexa_nb_ignored_control_content_total), so this reading shows that ignored content was " +
	"disclosed during the window, not that this particular kind was: any other ignorable content " +
	"served in the same window contributes to the same counter (IW15-030)"
