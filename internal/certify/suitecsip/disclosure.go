package suitecsip

// disclosure.go — the bench-readable end of IW15-030, wired into the rows.
//
// ── What was missing, and what closed it ───────────────────────────────────
//
// IEEE Std 2030.5-2018 p.252 tells a DER that cannot support autonomous vRef
// adjustment to EXECUTE the volt-var curve without it. So a gateway handed
// autonomousVRefEnable=true owes no CannotComply: it accepts the control,
// executes the breakpoints, and the correct handling of the one unacted-upon
// ELEMENT is to DISCLOSE it rather than drop it silently.
//
// This suite could see two thirds of that. The acceptance is on the wire, the
// execution is in the DER's own curve bank (curve.go's oracle), and the third —
// "and it was disclosed" — was a gateway-internal counter plus a slog WARN,
// on no surface this bench could read. The oracle asserted what it could see
// and said, in every bundle, that it could not confirm the disclosure. A
// certifier leaning on "disclosed rather than silent" was leaning on the
// product's own account of itself.
//
// It is readable now. lexa-gw 49a84c6 splits the ignored-content family into
// one counter per kind, and internal/evidence/metricscrape scrapes the DUT's
// Prometheus endpoint across a row's window and records the named counters into
// the bundle where certify -verify re-derives them from the captured bodies.
//
// ── Three hooks, and why they are where they are ──────────────────────────
//
// 1. THE SOURCE (metricsScraper): built from Targets.Extra["metrics"], the
//    framework's own escape hatch for a suite-specific endpoint. A run that
//    does not configure one gets no scraper and every row below reports that
//    fact — never a pass, never a silent skip.
// 2. THE WINDOW (openDisclosureWindow / recordDisclosure): opened in Setup
//    BEFORE the control is published, closed in PostWait AFTER the DUT's poll
//    cycle. Those are the same two moments the southbound oracle reads at, and
//    they have to be: a delta over any wider window would count disclosures
//    this row did not cause.
// 3. THE CRITERION (critDisclosedIgnoredContent): grades the delta, and is the
//    only place that decides what a reading means.
//
// ── The claim this can and cannot support ─────────────────────────────────
//
// It can say: during this row's window, the gateway's autonomous-vref counter
// moved. That is the disclosure, observed from outside the product, by a
// channel whose recording is re-derivable from the bodies it captured.
//
// It cannot say WHICH control caused it. A per-kind counter attributes the KIND,
// not the occurrence, so two controls carrying autonomous vRef in one window
// move it twice and the counter cannot separate them. The row bounds its window
// to its own control, which is what makes the attribution sound — and the
// criterion says so rather than leaving a reader to assume it.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/metricscrape"
)

// The Observation.Params keys the disclosure channel writes. Distinct from
// every oracle's, so a bundle shows which apparatus produced which half.
const (
	disclosureOutcomeParam  = "iw15.disclosure_outcome"
	disclosureObservedParam = "iw15.disclosure_observed"
	// disclosureUnavailableParam is why no reading was taken at all — an
	// unconfigured endpoint, or a window that was never opened. It is a
	// separate key from the outcome so "the bench did not look" cannot be
	// mistaken for "the bench looked and saw nothing", which is the same
	// absent-versus-zero distinction the scrape channel itself is built on.
	disclosureUnavailableParam = "iw15.disclosure_unavailable"
	// disclosureCaveatParam carries the sentence a non-isolating reading owes.
	disclosureCaveatParam = "iw15.disclosure_caveat"
	// disclosureMovedParam lists every kind of the family that moved across the
	// window, so a row asserting that NOTHING of its content was dropped can
	// name what did move when it fails.
	disclosureMovedParam = "iw15.disclosure_moved"
	// disclosureUnsoundParam counts the family's series whose reading was not
	// sound (absent, backwards, unreadable), because a negative claim built on
	// series nobody could read is not a negative claim.
	disclosureUnsoundParam = "iw15.disclosure_unsound"
)

// metricsTargetKey is the Targets.Extra key holding the DUT's Prometheus
// endpoint.
//
// The endpoint is lexa-gw's MetricsAddr (cmd/northbound/config.go), which
// defaults to 127.0.0.1:9102 — LOOPBACK on the DUT — and which BENCH.md binds
// to 69.0.0.2:9102 on the bench. A desktop run against the loopback default
// needs an ssh forward; that is an operator decision and this suite makes none,
// which is why the endpoint is configured rather than derived from
// Targets.GatewayHost.
const metricsTargetKey = "metrics"

// metricsScraper builds the scrape source for a run, or reports why there is
// none.
//
// A missing endpoint is a configuration fact and is returned as an error the
// caller records; it is never substituted with a guess at the DUT's address.
// Scraping something that merely answers on :9102 would be worse than not
// scraping: the reading would look sound and be about a different process.
func metricsScraper(rc *certify.RunCtx, sels ...metricscrape.Selector) (*metricscrape.Scraper, error) {
	endpoint := ""
	if rc != nil && rc.Targets.Extra != nil {
		endpoint = rc.Targets.Extra[metricsTargetKey]
	}
	if endpoint == "" {
		return nil, fmt.Errorf("no %q endpoint is configured for this run (-target %s=http://host:9102/metrics), "+
			"so the DUT's own disclosure counters were not read; lexa-gw serves them on MetricsAddr, "+
			"default 127.0.0.1:9102, which BENCH.md binds to 69.0.0.2:9102 on the bench",
			metricsTargetKey, metricsTargetKey)
	}
	src, err := metricscrape.NewHTTPSource(endpoint)
	if err != nil {
		return nil, fmt.Errorf("the configured %q endpoint %q is unusable: %w", metricsTargetKey, endpoint, err)
	}
	return metricscrape.New(src, sels...)
}

// disclosureWindow is a row's open scrape window, carried across the live phase.
//
// It is held on the Driver rather than in params because a Window is a live
// object with an opening reading inside it; params carry strings into the
// citation phase, which is a different job.
type disclosureWindow struct {
	win      *metricscrape.Window
	sel      metricscrape.Selector
	isolated bool
	kind     string
}

// openDisclosureWindow takes the pre-publication reading. HOOK 1 of 3.
//
// Called from a row's Setup, before the control goes on the wire, so the delta
// below is over this row's own window and not over whatever the counter had
// been doing.
func openDisclosureWindow(ctx context.Context, rc *certify.RunCtx, params map[string]string,
	kind, label string) *disclosureWindow {

	sel, isolated := metricscrape.IgnoredContentKind(kind)

	// THE WHOLE FAMILY IS SCRAPED, not just the kind under test, and that is
	// what lets a row assert the negative. A row whose content the gateway can
	// represent in full should move NO ignored-content counter at all; reading
	// only the one kind would leave a row unable to notice that some OTHER part
	// of its own curve was quietly dropped — which is the same silent-drop
	// failure this channel exists to expose, one kind over.
	sels := []metricscrape.Selector{metricscrape.IgnoredContentTotal()}
	for _, k := range metricscrape.IgnoredContentKinds() {
		ks, _ := metricscrape.IgnoredContentKind(k)
		sels = append(sels, ks)
	}
	s, err := metricsScraper(rc, sels...)
	if err != nil {
		params[disclosureUnavailableParam] = err.Error()
		return nil
	}
	if !isolated && kind != "" {
		params[disclosureCaveatParam] = metricscrape.IgnoredContentKindCaveat
	}
	return &disclosureWindow{win: s.Open(ctx, label), sel: sel, isolated: isolated, kind: kind}
}

// recordDisclosure closes the window and writes what it saw. HOOK 2 of 3.
//
// Called from PostWait, after the DUT's poll cycle — the same moment the
// southbound oracle reads at, and for the same reason: the control has to have
// reached the DUT for either half to mean anything.
//
// The RECORD goes into the evidence bundle as well as the params, because the
// params carry a sentence and the bundle carries the captured bodies. Only the
// second is re-derivable, and a disclosure claim that a certifier is asked to
// lean on has to be the second.
func recordDisclosure(ctx context.Context, d *Driver, params map[string]string) {
	w := d.disclosure
	if w == nil {
		if params[disclosureUnavailableParam] == "" {
			params[disclosureUnavailableParam] = "no disclosure window was opened for this row, so the " +
				"DUT's own ignored-content counters were not read across it"
		}
		return
	}
	rec := w.win.Close(ctx)
	d.metrics = append(d.metrics, rec)
	// Which kinds moved, for the negative claim. A row asserting that nothing
	// of its content was dropped has to be able to NAME what did move when it
	// fails, or the failure is unactionable.
	var moved []string
	unsound := 0
	for _, k := range metricscrape.IgnoredContentKinds() {
		ks, _ := metricscrape.IgnoredContentKind(k)
		kd, ok := rec.Find(ks)
		if !ok {
			continue
		}
		switch {
		case kd.Moved():
			moved = append(moved, fmt.Sprintf("%s +%v", k, kd.Delta))
		case !kd.Sound():
			unsound++
		}
	}
	params[disclosureMovedParam] = strings.Join(moved, ", ")
	params[disclosureUnsoundParam] = strconv.Itoa(unsound)

	if w.kind == "" {
		// A row with no kind under test is asserting the negative only; its
		// verdict comes from the moved list above.
		params[disclosureOutcomeParam] = string(metricscrape.OutcomeUnchanged)
		params[disclosureObservedParam] = fmt.Sprintf("the DUT's ignored-content family was read across "+
			"this row's window at %s: %d of %d series moved", rec.Endpoint, len(moved),
			len(metricscrape.IgnoredContentKinds()))
		return
	}

	kd, ok := rec.Find(w.sel)
	if !ok {
		params[disclosureUnavailableParam] = fmt.Sprintf("the scrape of %s recorded no reading for %s",
			rec.Endpoint, w.sel)
		return
	}
	params[disclosureOutcomeParam] = string(kd.Outcome)
	params[disclosureObservedParam] = kd.Observed()
}

// critDisclosedIgnoredContent grades the disclosure. HOOK 3 of 3.
//
// ── Why it is a WARN and not a FAIL when nothing was read ─────────────────
//
// The row's SUBJECT is that the DUT accepted and executed the control; the
// southbound oracle carries that and is load-bearing. This criterion carries a
// supplementary claim about how the product ACCOUNTED for the one element it
// did not act on — real, and worth evidence, and not the thing the row exists
// to establish. A bench with no metrics endpoint configured is a bench that did
// not look, which must not read as a pass and must not fail a device.
//
// It carries no Skip path all the same: every shape comes back decided, because
// a Skip here would be severity 0 and would vanish from the roll-up entirely.
func critDisclosedIgnoredContent(kind string, o *Observation) criterion {
	claim := "the DUT DISCLOSED the " + kind + " content it accepted and did not act on, on a surface " +
		"outside its own logs"
	how := "a scrape of the DUT's own Prometheus endpoint taken BEFORE this row published its control " +
		"and again after the DUT's poll cycle, comparing the ignored-content counter for this kind. " +
		"Both raw exposition bodies are recorded in the bundle and certify -verify re-derives the delta " +
		"from them, so the reading is checkable rather than reported. IEEE Std 2030.5-2018 p.252 makes " +
		"this content a thing to DISCLOSE rather than refuse — the DER executes the curve without the " +
		"adjustment — so this criterion is about the accounting, not about compliance with the control"

	return criterion{
		Claim: claim,
		How:   how,
		Tier:  tierMetrics,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return disclosureOutcome(kind, o)
		},
	}
}

// disclosureOutcome collapses what the live phase recorded into one decided
// verdict.
func disclosureOutcome(kind string, o *Observation) Finding {
	if o == nil {
		return Finding{Verdict: certify.Warn, Observed: "no observation carries a disclosure reading"}
	}
	caveat := ""
	if c := o.Params[disclosureCaveatParam]; c != "" {
		caveat = " " + c
	}
	if why := o.Params[disclosureUnavailableParam]; why != "" {
		// UNAVAILABLE, which mints a Skip carrying this reason — not a WARN.
		//
		// This criterion is SUPPLEMENTARY: the row's whole subject is that the
		// DUT accepted and executed the control, and the southbound oracle
		// carries that and is load-bearing. doc.go's no-Skip rule is scoped to
		// the criteria that carry a row's subject, precisely so the suite does
		// not manufacture verdict noise about the bench's own configuration.
		// A run with no metrics endpoint would otherwise WARN every curve row
		// in the campaign for a fact about the operator's flags — which is how
		// a real signal gets trained out of a reader.
		return unavailable("%s", "the DUT's own disclosure counters were NOT read across this row's "+
			"window, so whether it disclosed the element it did not act on is not established here — a "+
			"fact about the bench, not about the device: "+why)
	}
	observed := o.Params[disclosureObservedParam]
	switch metricscrape.Outcome(o.Params[disclosureOutcomeParam]) {
	case metricscrape.OutcomeIncreased:
		return Finding{Verdict: certify.Pass, Observed: "the DUT disclosed it: " + observed + "." + caveat}
	case metricscrape.OutcomeUnchanged:
		// A SOUND reading of nothing. The counter exists, it was read at both
		// ends, and it did not move — so the gateway did not disclose this kind
		// during the window. That is a decided non-pass and is exactly the
		// finding this channel was built to be able to state.
		return Finding{Verdict: certify.Fail, Observed: "the DUT's own counter for this kind did NOT " +
			"move across the window, so the content it accepted and did not act on was not disclosed on " +
			"any surface this bench can read: " + observed + "." + caveat}
	case metricscrape.OutcomeAbsent:
		return Finding{Verdict: certify.Warn, Observed: "the DUT's endpoint exports no counter for this " +
			"kind, which is NOT a reading of zero — a gateway predating the per-kind split (lexa-gw " +
			"49a84c6) exports only the untagged family total, and nothing about its disclosure behaviour " +
			"follows from the absence: " + observed}
	default:
		return Finding{Verdict: certify.Warn, Observed: "the disclosure reading is not sound, so nothing " +
			"is claimed from it: " + observed}
	}
}

// critNothingOfThisRowsContentWasDropped is the claim that arms on the SHIPPING
// rows, and it is the disclosure channel's other direction.
//
// ── Why the negative is the useful one today ──────────────────────────────
//
// The p.252 disclosure obligation arises only for a control carrying
// autonomousVRefEnable=true, and no catalog row publishes one: Figure 6 prints
// false in both its columns, so BASIC-006 authors false and is right to. The
// criterion above is therefore correct and inert on a campaign as it stands —
// it arms itself the moment a row publishes the element that creates the
// obligation, and not before.
//
// What EVERY curve row can assert is the complement, and it is worth more than
// it first looks. The gateway's walker sweeps everything the server serves for
// content its bus carriage cannot represent, and counts each occurrence by kind
// (lexa-gw walker.go:936-944). A row that published a well-formed, fully
// representable curve should move NONE of those counters. If one moves during
// its window, part of what that row put on the wire was accepted and quietly
// dropped — and the row's own southbound oracle would not necessarily see it,
// because the oracle compares the breakpoints it DOES find and an element that
// never reached the bus leaves no register to disagree with.
//
// So this is the row asking the DUT: did you take all of what I sent? It is the
// silent-drop check for the parts of a control that have no register home, and
// it is the reason the scrape reads the whole family rather than one kind.
func critNothingOfThisRowsContentWasDropped(o *Observation) criterion {
	return criterion{
		Claim: "the DUT dropped NO part of this row's published control: none of its ignored-content " +
			"counters moved while this row's control was on the wire",
		How: "a scrape of the DUT's own Prometheus endpoint taken BEFORE this row published and again " +
			"after the DUT's poll cycle, over EVERY series of the ignored-content family (lexa-gw " +
			"walker.go's per-kind enumeration plus its other-bucket), with both raw exposition bodies " +
			"recorded in the bundle so certify -verify re-derives the deltas. The gateway increments one " +
			"of these for each piece of served content its bus carriage cannot represent, so a row that " +
			"published a fully representable control should move none of them — and an element that " +
			"never reached the bus leaves no register for the southbound oracle to disagree with, which " +
			"is why this is a separate question from whether the curve was executed",
		Tier: tierMetrics,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return droppedContentOutcome(o)
		},
		Skip: "the DUT's own metrics endpoint was not read across this row's window, so whether any of " +
			"this row's published content was silently dropped could not be observed (configure -target " +
			"metrics=http://host:9102/metrics)",
	}
}

// droppedContentOutcome decides the negative claim.
func droppedContentOutcome(o *Observation) Finding {
	if o == nil {
		return Finding{Verdict: certify.Warn, Observed: "no observation carries a disclosure reading"}
	}
	if why := o.Params[disclosureUnavailableParam]; why != "" {
		// Unavailable, not WARN — see disclosureOutcome for why a supplementary
		// criterion must not turn an unconfigured bench into a verdict on every
		// curve row.
		return unavailable("%s", "the DUT's own ignored-content counters were NOT read across this row's "+
			"window, so whether any of its published content was silently dropped is not established — a "+
			"fact about the bench, not about the device: "+why)
	}
	unsound, _ := strconv.Atoi(o.Params[disclosureUnsoundParam])
	moved := o.Params[disclosureMovedParam]
	switch {
	case moved != "":
		return Finding{Verdict: certify.Fail, Observed: "the DUT reported IGNORED CONTENT while this " +
			"row's control was on the wire, so part of what this row published was accepted and not " +
			"acted upon: " + moved + ". Which control caused it is not recoverable from a per-kind " +
			"counter — the attribution rests on this row's window holding only its own control"}
	case unsound > 0:
		// Some series could not be read soundly. A negative claim built on
		// series nobody could read is not a negative claim, and saying so is
		// the whole reason the channel distinguishes absent from zero.
		return Finding{Verdict: certify.Warn, Observed: fmt.Sprintf(
			"%d of the ignored-content series could not be read soundly across this row's window "+
				"(absent, backwards or unreadable), so 'nothing was dropped' cannot be asserted over the "+
				"whole family: %s", unsound, o.Params[disclosureObservedParam])}
	default:
		return Finding{Verdict: certify.Pass, Observed: "no ignored-content counter moved while this " +
			"row's control was on the wire, so the DUT represented everything it published: " +
			o.Params[disclosureObservedParam]}
	}
}

// disclosureKindFor names the ignored-content kind a row's own published
// content OBLIGES the DUT to disclose, or "" when the row's content should be
// representable in full.
//
// It is derived from the binding rather than configured, so a row cannot end up
// asserting a disclosure it never asked for — or, worse, asserting that nothing
// was dropped while publishing the one element the standard says will be.
//
// Only one kind is derivable today, and it is the one IW15-030 is about:
// autonomousVRefEnable=true is content a DER unable to support the adjustment
// must execute WITHOUT and disclose (2018 p.252). No catalog row publishes one —
// Figure 6 prints false in both columns, so BASIC-006 authors false and is right
// to — so on a campaign as it stands every curve row takes the "" arm and
// asserts the complement. That is not a gap: the obligation genuinely does not
// arise, and the criterion arms itself the moment a row publishes the element
// that creates it.
func disclosureKindFor(b *curveBinding) string {
	if b != nil && b.AutonomousVRefEnable != nil && *b.AutonomousVRefEnable {
		return metricscrape.KindAutonomousVRef
	}
	return ""
}
