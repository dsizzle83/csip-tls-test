// Package metricscrape reads NAMED counters off the device under test's
// Prometheus endpoint across a measurement window, and records what it saw —
// including everything it could NOT see — as evidence a criterion can grade on.
//
// # The gap this closes
//
// Some things a certifier is asked to rely on never reach the wire. The case
// that forced this package is IW15-030
// (lexa-gw docs/known_issues.json, "IW15-030-disclosure-channel-not-bench-observable"):
// IEEE 2030.5-2018 p.252 tells a DER that cannot support autonomous vRef
// adjustment to execute the volt-var curve WITHOUT it, so the gateway accepts
// the control, runs the curve, and DISCLOSES the dropped element rather than
// losing it silently. The disclosure is a slog WARN plus a counter — see
// lexa-gw internal/northbound/discovery/walker.go:936-951 (ReportIgnoredContent
// and IgnoredContentTotal) and cmd/northbound/main.go:231-233, where a
// scrape-time Collect hook mirrors that total into
// lexa_nb_ignored_control_content_total. Nothing about it is on the wire, in a
// register, or in any 2030.5 resource: gate #17 of that wave independently
// confirmed no revision of the standard defines a disclosure element for it in
// DERCapability or DERSettings. So the harness could assert the observable
// halves (accepted, executed at the right breakpoints, VRefAutoEna not armed)
// and had to stay silent on the half the ACCEPT ruling leans on.
//
// A counter delta is a poor substitute for a wire artefact and an excellent
// substitute for nothing. This package makes it an artefact of the same kind as
// the rest of the bundle: named up front, sampled at both ends of a stated
// window, recorded with the raw exposition bodies it was derived from, and
// re-derivable by somebody who does not trust us (see bundle.Verify, which
// re-parses those bodies rather than believing this package's summary).
//
// It is DELIBERATELY general. The ignored-content family is the first consumer,
// not the design: name the counters a row cares about, get their values at
// window open and window close, get the delta, and get an honest answer when
// there is no such counter.
//
// # Absent is not zero
//
// The distinction this package refuses to blur: a counter that is PRESENT AND
// ZERO says the DUT exports that series and nothing has happened yet. A counter
// that is ABSENT says the DUT does not export that series at all — wrong
// service scraped, wrong build, endpoint answering for a different process,
// metric renamed. A scraper that reads a missing counter as 0 turns the second
// into the first, and a disclosure oracle built on it would PASS on a gateway
// that never disclosed anything. So Present is carried separately from Value at
// both ends of the window, and the Outcome vocabulary keeps ABSENT, UNCHANGED
// and INCREASED apart from each other and from every way the reading can fail.
//
// # Failures are evidence, not exceptions
//
// An endpoint that will not answer is a fact about the run, and a run that
// aborts on it produces no evidence at all. So Open and Close never fail:
// unreachable, non-200, malformed body, series absent, series ambiguous, series
// non-finite and counter WENT BACKWARDS (a process restart mid-window, which
// makes the delta meaningless rather than negative) each land as a distinct
// recorded Status/Outcome that a criterion reads and grades.
//
// The exception to the exception is a fault that is OURS: a selector that is not
// a well-formed metric name is a bug in the harness, not a fact about the DUT,
// and New returns an error for it rather than letting it masquerade as an absent
// counter.
//
// # The DUT endpoint, as verified in lexa-gw
//
// Plain HTTP, no TLS, no authentication, one path:
//
//   - lexa-northbound serves Prometheus text exposition at /metrics on
//     cfg.MetricsAddr (cmd/northbound/config.go:85-87), default
//     "127.0.0.1:9102" (config.go:440-442, configs/northbound.json:13). The
//     literal "off" disables the listener.
//   - The handler is lexa-platform/metrics.Registry.Handler — no auth wrapper
//     anywhere in it (vendor/lexa-platform/metrics/metrics.go:242-253); in
//     lexa-api the /metrics route is explicitly never wrapped
//     (cmd/api/main.go:444-447, "an unauthenticated liveness endpoint … and an
//     infra scrape surface").
//   - The default bind is LOOPBACK, so a desktop scrape needs either the bench
//     posture — this repo's docs/BENCH.md §Metrics (TASK-044/AD-008): bench
//     configs bind metrics_addr to the LAN IP, lexa-northbound on
//     69.0.0.2:9102 — or an ssh local forward. Both are plain HTTP GETs and
//     both work through HTTPSource unchanged; the forward is the reason Source
//     is an interface at all (a FuncSource can shell out through
//     certify.Gateway instead, though note that curl/wget are not on that
//     client's read-only allowlist today).
//
// # Honest limits
//
// A scraped counter is the DUT's statement about itself. It is not a wire
// artefact, it is not signed, and re-checking it re-checks that we recorded
// faithfully what the endpoint said — not that what the endpoint said was true.
// A bundle should say so wherever it leans on one; that is why Record.Source
// spells out the endpoint and the window rather than rendering a bare number.
//
// The delta is also a property of the WINDOW, not of a request: any other actor
// that provokes the same counter inside it contributes to the same delta. Keep
// windows tight around the stimulus, and prefer a selector that isolates the
// kind you mean — which, for the ignored-content family, is exactly what the
// integration TODO in known.go is about.
package metricscrape
