package invariant

// i7.go — Reported status never claims success for something that did not
// happen.
//
// Grounding: GT-01 — telemetry reporting connected = 1 and 0 failures while it
// had posted nothing to the head-end for 3.6 days, because the comm-loss path
// skipped every device BEFORE any POST was attempted and therefore never
// touched a single counter.
//
// # This is a two-witness invariant, and that is the whole idea
//
// GT-01 is undetectable from inside the device. Every internal signal agreed:
// the gauge said connected, the failure counter said zero, no log line
// disagreed. It is detectable in one line from outside, because the head-end
// knows how long it has been since the device said anything, and the inverter
// knows how long it has been since anyone polled it. The device's claim and the
// world's record of that claim's subject are two independent witnesses, and
// this invariant is nothing but the assertion that they agree.
//
// Three arms:
//
//	connectivity — the DUT PUT a DERStatus asserting its DER is connected and
//	  operational, while the DER's own request counter says nobody has polled it
//	  for the whole window. One of the two is wrong and only the DUT had a
//	  motive.
//
//	control acknowledgement — the DUT POSTed Response status 2 ("Event started")
//	  or 3 ("Event completed") for a control, while no axis of that control is
//	  reflected in any DER's register image. It reported doing something it did
//	  not do.
//
//	telemetry fidelity — a reported measurement disagrees with the device's own
//	  reading by more than tolerance. This is a WARN: telemetry legitimately
//	  lags, and a reading that is merely stale is not a false claim of success.
//
// # The parser is ours
//
// The DER* report bodies are parsed here, by this package's own reader, rather
// than by any model the product shares. That is the same reason internal/csipref
// exists: a referee that parses with the parser under test cannot catch a
// parsing bug, and "the DUT emitted a DERStatus that means something other than
// what it thinks it means" is squarely in scope for this invariant.

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type i7 struct{ p Params }

// NewI7 returns the truthful-status invariant.
func NewI7(p Params) Invariant { return &i7{p: p} }

func (i *i7) ID() string { return "I7" }

func (i *i7) Grounding() string {
	return "GT-01 — telemetry reported connected=1 with 0 failures while it had posted nothing " +
		"for 3.6 days, because the comm-loss path skipped each device before any POST was attempted."
}

func (i *i7) Statement() string {
	return "Reported status never claims success for something that did not happen: every claim " +
		"the DUT makes northbound is corroborated by an independent witness — a DERStatus asserting " +
		"connectivity requires the DER's own request counter to have advanced, and a Response " +
		"reporting an event started or completed requires at least one axis of that control to be " +
		"reflected in a DER's own register image. PARTIAL: a reported measurement that merely " +
		"disagrees with the device's own reading is reported WARN rather than FAIL, because " +
		"telemetry legitimately lags and staleness is not a false claim of success."
}

func (i *i7) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	if !obs.HeadEnd.Reachable {
		return skipf("the head-end is unreachable, so the DUT's northbound claims cannot be read (%s)", obs.HeadEnd.Err), nil
	}
	if len(obs.HeadEnd.Reports) == 0 && len(obs.HeadEnd.Responses) == 0 {
		return skipf("the DUT has made no claim to the head-end yet (no DER* report PUT, no Response POST)"), nil
	}

	res := Result{Verdict: Pass}
	// I7's three arms judge three different claims the DUT made northbound, so
	// they keep three different key prefixes. The acknowledgement arm carries
	// the control mRID — the head-end's own stable name for the thing that was
	// claimed. Kept OUT: `i7.claim.received`, an RFC3339 instant under a key
	// ending in neither "_at" nor unit "s", and therefore one of the two facts
	// whose entry into the fact hash was IW15-031's root cause. See [keyer].
	key := keysOf(&res)
	i.connectivityArm(w, obs, &res, key)
	i.acknowledgementArm(obs, &res, key)
	i.fidelityArm(obs, &res, key)

	if res.Checked == 0 {
		return skipf("the DUT's claims could not be corroborated: no DER publishes a request counter and no " +
			"active control is being served, so there is nothing to check them against"), nil
	}
	if res.Verdict == Pass {
		res.Assertions = append(res.Assertions, narrate(
			"every claim the DUT made northbound was corroborated by an independent witness",
			"cross-check each DERStatus and Response against the DERs' own request counters and register images",
			Pass, fmt.Sprintf("%d claims corroborated", res.Checked)))
	}
	return res, nil
}

// connectivityArm checks a claimed-connected DERStatus against the DERs' own
// request counters.
func (i *i7) connectivityArm(w *World, obs *Observation, res *Result, key *keyer) {
	report, ok := newestReport(obs.HeadEnd.Reports, "DERStatus")
	if !ok {
		return
	}
	claim, ok := parseDERStatus(report.Body)
	if !ok {
		return
	}
	if !claim.ClaimsConnected() {
		return
	}
	// Independent witness: has ANY DER seen a request from the DUT across the
	// retained window? A single healthy device legitimately keeps the fleet
	// gauge green, which is the correction the GT-01 finding itself carries, so
	// the violation is "no device at all has been polled".
	window := i.window(w)
	if window == nil {
		return
	}
	advanced, counted, detail := pollAdvance(window)
	if counted == 0 {
		return // no DER counts requests; nothing to corroborate against
	}
	res.Checked++
	if advanced {
		return
	}
	span := window[len(window)-1].At.Sub(window[0].At)
	res.Verdict = Fail
	// One DUT, one connectivity claim: the finding has no per-device identity
	// to carry, and every tick that re-reads the same uncorroborated claim is
	// the same finding.
	key.note(Fail, "connectivity-claim-uncorroborated")
	res.Facts = append(res.Facts,
		F("i7.claim.resource", "", obs.HeadEnd.Source, "DERStatus at %s", report.Path),
		F("i7.claim.received", "", obs.HeadEnd.Source, "%s", report.Received.Format(time.RFC3339)),
		F("i7.claim.genConnectStatus", "", obs.HeadEnd.Source, "%d", claim.GenConnectStatus),
		F("i7.claim.operationalModeStatus", "", obs.HeadEnd.Source, "%d", claim.OperationalMode),
		F("i7.witness.window", "s", "der counters", "%s", dur(span)),
		F("i7.witness.poll_counters", "count", "der counters", "%s", detail),
	)
	if res.Reason == "" {
		res.Reason = fmt.Sprintf(
			"the DUT PUT a DERStatus at %s asserting genConnectStatus=%d (connected) and "+
				"operationalModeStatus=%d, but across the last %s NOT ONE of the %d DERs that count "+
				"requests saw a single poll from it (%s)",
			report.Received.Format(time.RFC3339), claim.GenConnectStatus, claim.OperationalMode,
			dur(span), counted, detail)
	}
	res.Assertions = append(res.Assertions, narrate(
		"a DERStatus claiming connectivity is corroborated by the DERs' own request counters",
		"read each DER's own count of requests received from the DUT across the retained window",
		Fail, res.Reason))
}

// acknowledgementArm checks that a success Response corresponds to something
// observable at a DER.
func (i *i7) acknowledgementArm(obs *Observation, res *Result, key *keyer) {
	if len(obs.HeadEnd.Responses) == 0 {
		return
	}
	ders := derViews(obs)
	if len(ders) == 0 {
		return
	}
	for _, resp := range obs.HeadEnd.Responses {
		if !isSuccessStatus(resp.Status) {
			continue
		}
		ctrl, ok := findControl(obs.HeadEnd, resp.Subject)
		if !ok {
			continue // the head-end no longer serves it; nothing to compare
		}
		axes := ctrl.Base.Axes()
		if len(axes) == 0 {
			continue
		}
		res.Checked++
		applied, _, detail := appliedAxes(ctrl, ders, i.p.Tol)
		if applied > 0 {
			continue
		}
		res.Verdict = Fail
		key.note(Fail, "success-without-effect:%s", resp.Subject)
		res.Facts = append(res.Facts,
			F("i7.response.subject", "", obs.HeadEnd.Source, "%s", resp.Subject),
			F("i7.response.status", "", obs.HeadEnd.Source, "%d (%s)", resp.Status, statusName(resp.Status)),
			F("i7.response.axes", "count", obs.HeadEnd.Source, "%d", len(axes)),
			F("i7.response.applied", "count", "der register images", "0"),
			F("i7.response.detail", "", "der register images", "%s", detail),
		)
		if res.Reason == "" {
			res.Reason = fmt.Sprintf(
				"the DUT reported status %d (%s) for control %s, but none of its %d axes is reflected in any "+
					"DER's own register image (%s) — it reported success for something that did not happen",
				resp.Status, statusName(resp.Status), resp.Subject, len(axes), detail)
		}
		res.Assertions = append(res.Assertions, narrate(
			fmt.Sprintf("the success reported for control %s corresponds to an observable action", resp.Subject),
			"compare each axis of the control's base against the DERs' own register images",
			Fail, res.Reason))
	}
}

// fidelityArm compares a reported measurement against the device's own reading.
func (i *i7) fidelityArm(obs *Observation, res *Result, key *keyer) {
	report, ok := newestReport(obs.HeadEnd.Reports, "DERStatus")
	if !ok {
		return
	}
	claim, ok := parseDERStatus(report.Body)
	if !ok || !claim.HasW {
		return
	}
	total, counted := 0.0, 0
	for _, v := range derViews(obs) {
		m := v.Unit.Measurement(v.Source)
		if m.Present && m.W.Known() {
			total += m.W.Val
			counted++
		}
	}
	if counted == 0 {
		return
	}
	res.Checked++
	if nearly(claim.W, total, 0.10, 50) {
		return
	}
	res.Verdict = Worse(res.Verdict, Warn)
	key.note(Warn, "telemetry-divergence")
	res.Facts = append(res.Facts,
		F("i7.fidelity.reported_W", "W", obs.HeadEnd.Source, "%s", trimFloat(claim.W)),
		F("i7.fidelity.measured_W", "W", "der register images", "%s (sum of %d DERs)", trimFloat(total), counted),
		F("i7.fidelity.report_age", "s", obs.HeadEnd.Source, "%s", dur(obs.At.Sub(report.Received))),
	)
	if res.Reason == "" {
		res.Reason = fmt.Sprintf("the DUT reported %s W northbound while its DERs' own readings sum to %s W "+
			"(report is %s old) — reported as WARN because telemetry legitimately lags",
			trimFloat(claim.W), trimFloat(total), dur(obs.At.Sub(report.Received)))
	}
}

// window returns the retained observations, or nil when there are too few to
// say anything about advance.
func (i *i7) window(w *World) []*Observation {
	h := w.History()
	if len(h) < 2 {
		return nil
	}
	if d, ok := i.p.Duration("poll_stale_window"); ok {
		since := h[len(h)-1].At.Add(-d)
		var out []*Observation
		for _, o := range h {
			if !o.At.Before(since) {
				out = append(out, o)
			}
		}
		if len(out) >= 2 {
			return out
		}
	}
	return h
}

// pollAdvance reports whether any DER's request counter advanced across the
// window, how many DERs publish one at BOTH ends of it, and a per-DER detail
// string.
//
// A DER whose counter is readable only at the end of the window is deliberately
// not counted. Its apparent delta from an assumed zero baseline would read as a
// large advance and would silently absolve a DUT that has been polling nobody —
// exactly the false negative this invariant exists to prevent.
func pollAdvance(window []*Observation) (advanced bool, counted int, detail string) {
	first, last := window[0], window[len(window)-1]
	var parts []string
	for _, name := range last.DERNames() {
		lastD := last.DERs[name]
		firstD, ok := first.DERs[name]
		if !lastD.HasPollCount || !ok || !firstD.HasPollCount {
			continue
		}
		counted++
		delta := lastD.PollRequests - firstD.PollRequests
		if delta > 0 {
			advanced = true
		}
		parts = append(parts, fmt.Sprintf("%s %d→%d (%+d)", name, firstD.PollRequests, lastD.PollRequests, delta))
	}
	return advanced, counted, joinComma(parts)
}

// isSuccessStatus reports whether a 2030.5 Response status asserts the event
// was carried out. 2 = Event started, 3 = Event completed; 1 = Event received
// asserts only receipt and is therefore NOT a success claim.
func isSuccessStatus(s int) bool { return s == 2 || s == 3 }

// statusName renders the 2030.5 Table 27 statuses this invariant reasons about.
func statusName(s int) string {
	switch s {
	case 1:
		return "Event received"
	case 2:
		return "Event started"
	case 3:
		return "Event completed"
	case 6:
		return "Event cancelled"
	case 7:
		return "Event superseded"
	case 8:
		return "Event partially opted out"
	case 10:
		return "Event acknowledged, no participation"
	case 252:
		return "Rejected — parameter not applicable"
	case 253:
		return "Rejected — invalid content"
	case 254:
		return "Rejected — already expired"
	}
	if s >= 0xF0 {
		return "CannotComply (LEXA extension)"
	}
	return "unclassified"
}

// findControl locates a control by mRID among the head-end's programs.
func findControl(h HeadEndView, mrid string) (Ctrl, bool) {
	for _, p := range h.Programs {
		for _, c := range append(append([]Ctrl{}, p.Active...), p.Scheduled...) {
			if c.MRID == mrid {
				return c, true
			}
		}
	}
	return Ctrl{}, false
}

// newestReport returns the most recently received report of a resource type.
func newestReport(reports []Report, resource string) (Report, bool) {
	var out Report
	found := false
	for _, r := range reports {
		if !strings.EqualFold(r.Resource, resource) {
			continue
		}
		if !found || r.Received.After(out.Received) {
			out, found = r, true
		}
	}
	return out, found
}

// ── The DER* report reader ───────────────────────────────────────────────────

// DERStatusClaim is what a DERStatus document asserts, decoded by this
// package's own reader rather than by any product model (referee independence).
//
// In 2030.5 each status field is an element wrapping a <value> and a
// <dateTime>; only the value is decoded here. genConnectStatus is a bitmap
// whose bit 0 is "connected" and bit 1 is "available"; operationalModeStatus is
// an enumeration where 2 = "Operational mode".
type DERStatusClaim struct {
	GenConnectStatus int
	OperationalMode  int
	InverterStatus   int
	// W is the reported active power when the document carries one.
	W    float64
	HasW bool
	// Raw keeps every decoded element for the evidence record.
	Raw map[string]string
}

// ClaimsConnected reports whether the document asserts the DER is connected —
// the claim GT-01 made falsely for 3.6 days.
func (c DERStatusClaim) ClaimsConnected() bool {
	return c.GenConnectStatus&0x01 != 0 || c.OperationalMode == 2
}

// parseDERStatus decodes a DERStatus body. It is deliberately tolerant of
// namespace prefixes and element ordering and deliberately intolerant of
// guessing: an element it does not recognise is kept in Raw and influences
// nothing.
func parseDERStatus(body string) (DERStatusClaim, bool) {
	if strings.TrimSpace(body) == "" {
		return DERStatusClaim{}, false
	}
	claim := DERStatusClaim{Raw: map[string]string{}}
	dec := xml.NewDecoder(strings.NewReader(body))
	var path []string
	var chars strings.Builder
	seenRoot := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return claim, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if !seenRoot {
				if !strings.EqualFold(t.Name.Local, "DERStatus") {
					return claim, false
				}
				seenRoot = true
			}
			path = append(path, t.Name.Local)
			chars.Reset()
		case xml.CharData:
			chars.Write(t)
		case xml.EndElement:
			if len(path) == 0 {
				break
			}
			text := strings.TrimSpace(chars.String())
			if len(path) >= 2 && text != "" {
				parent := path[len(path)-2]
				leaf := path[len(path)-1]
				if strings.EqualFold(leaf, "value") {
					claim.Raw[parent] = text
				}
			}
			path = path[:len(path)-1]
			chars.Reset()
		}
	}
	if !seenRoot {
		return claim, false
	}
	geti := func(name string) int {
		for k, v := range claim.Raw {
			if strings.EqualFold(k, name) {
				n, err := strconv.Atoi(v)
				if err == nil {
					return n
				}
			}
		}
		return -1
	}
	claim.GenConnectStatus = geti("genConnectStatus")
	claim.OperationalMode = geti("operationalModeStatus")
	claim.InverterStatus = geti("inverterStatus")
	for k, v := range claim.Raw {
		if strings.EqualFold(k, "activePower") || strings.EqualFold(k, "W") {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				claim.W, claim.HasW = f, true
			}
		}
	}
	return claim, true
}
