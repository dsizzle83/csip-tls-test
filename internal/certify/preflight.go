package certify

// preflight.go refuses a run whose bench cannot mean what the flags say it
// means.
//
// # The landmine
//
// gridsim serves two ports from one process: the 2030.5 data plane the DUT
// dials (-gridsim, :11113) and the admin API this harness reads its server-side
// observations from (-gridsim-admin, :11114). Nothing outside that process ties
// the two together, and on 2026-07-28 they came apart. An instance survived its
// own SIGTERM — its shutdown was parked waiting on a 2030.5 client's blocking
// read — and kept :11114. The replacement took :11113, logged "address already
// in use" for the admin port, and carried on serving. For the next several
// hours the DUT talked to the new process while the harness asked the
// eight-hour-old orphan what the DUT had done. The orphan answered honestly:
// nothing. Every case that rested on it published "gridsim's request log
// records no GET /dcap from the DUT in this window" — a device defect, written
// down, from two ports that were never one server.
//
// The same shape has a second face. A -gridsim 127.0.0.1:11113 against a
// -gridsim-admin on the bench address is not merely inconsistent: loopback
// traffic never appears on the capture interface at all, so every wire citation
// for the 2030.5 conversation silently becomes impossible and the cases
// downgrade for want of evidence that was never going to exist.
//
// # The rule
//
// Both of those are answerable before a single packet is captured, so they are
// answered there — the run fails in its first second with a message naming the
// consequence, rather than in its fortieth minute with a bundle full of
// findings about a device that was behaving perfectly.
//
// What preflight will NOT do is guess. It checks only what it can establish:
// that the two flags name one host, and that the process answering the admin
// port says it serves the data-plane port the flags point the DUT at.
//
// # An unprovable pairing is not a merely-weaker one (REV0907-E3)
//
// -skip-preflight and a gridsim too old to report its own data-plane address
// both mean the same thing: this run cannot establish that -gridsim and
// -gridsim-admin name one live process. That used to be reported and allowed
// unconditionally — an unproven pairing is a weaker position than a proven
// one, but it is not the same thing as a proven mismatch, and refusing to run
// against every previously-built simulator would make this check something
// operators disable by habit. The gap was that this held on a GATING campaign
// too: a certification bundle could rest on server-side observations from a
// process nothing had confirmed was the one the DUT dialled. Both cases now go
// through unprovable (below), which keeps exactly that WARN-and-continue
// posture on an exploratory run and refuses a GATING one outright — a
// certification bundle may not rest on a precondition this run did not
// establish, and the run's use of the switch is recorded in
// bundle.CampaignRecord.Weakened either way (see Runner.recordWeakened).

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// preflightTimeout bounds the whole check. It is short: preflight exists to
// fail fast, and a gridsim that needs longer than this to describe itself is
// itself the finding.
const preflightTimeout = 10 * time.Second

// SkipPreflightNote is recorded in the bundle whenever -skip-preflight was
// used, so a reader of the evidence knows the pairing behind it was asserted by
// an operator rather than established by the tool.
const SkipPreflightNote = "preflight SKIPPED (-skip-preflight): the run did not verify that -gridsim and " +
	"-gridsim-admin name one live process, so any claim resting on gridsim's server-side observations " +
	"assumes a pairing this bundle does not evidence"

// Weakening switch keys, exactly as they are written into
// bundle.CampaignRecord.Weakened. Spelled once here so every recordWeakened
// call site, this package's tests, and a reader of a bundle's JSON agree on the
// string. See recordWeakened and REV0907-E3.
const (
	// WeakenedSkipPreflight is recorded whenever -skip-preflight left the
	// -gridsim/-gridsim-admin pairing unverified.
	WeakenedSkipPreflight = "skip-preflight"
	// WeakenedNoDataPlane is recorded whenever the gridsim admin API answered
	// but reported no data-plane address, leaving the pairing unprovable the
	// same way -skip-preflight does.
	WeakenedNoDataPlane = "no-data-plane"
	// WeakenedRequireCitationFalse is recorded whenever -require-citation=false
	// let an uncited PASS stand as PASS instead of being downgraded to WARN.
	WeakenedRequireCitationFalse = "require-citation=false"
	// WeakenedAllowDirty is recorded whenever -allow-dirty actually waved a
	// dirty or unidentifiable harness worktree through.
	WeakenedAllowDirty = "allow-dirty"
)

// recordWeakened appends a weakening-switch key (one of the Weakened* constants
// above) to this run's audit trail, deduplicated, so writeBundle can carry it
// into bundle.CampaignRecord.Weakened.
//
// It is called on every run where the switch was in effect, gating or not —
// calling it before a GATING campaign's refusal is harmless, since that run
// aborts before writeBundle is ever reached and nothing reads the entry, and
// recording it unconditionally is simpler than threading the gating decision
// through every call site a second time. See REV0907-E3.
func (r *Runner) recordWeakened(key string) {
	for _, k := range r.weakened {
		if k == key {
			return
		}
	}
	r.weakened = append(r.weakened, key)
}

// unprovable renders a preflight precondition that could NOT be established —
// the one shape every candidate/bench preflight has more than one of, spelled
// ONE way so a reader meets the same words wherever the gap is.
//
// The split is the fixture preflight's, generalised: on a GATING campaign it is
// FATAL and this returns an error the caller aborts the run on, because a
// certification bundle may not rest on a precondition the run never proved — a
// bundle whose scope decisions ride an UNVERIFIED topology records this tool's
// unproven assumption as the product's own claim. On an exploratory run (no
// -campaign) it is a WARN: the check names the gap, the run continues, and a
// quick poke is not blocked by a precondition only a cert campaign must have.
//
// This is the SAME posture split preflightFixture already applied to a served-
// but-undeclared model and preflightManifest to an under-declaration; before
// this helper the two files each answered "the DUT could not be asked at all"
// with a bare warn-and-continue on BOTH paths, so a gating campaign would
// generate cert evidence for a topology nothing in the run had established.
//
// `what` names, in a few words, exactly what could not be proven (it leads both
// the fatal error and the warn line); `detail` is the full sentence — the
// consequence and, where there is one, the flag that would close the gap.
func (r *Runner) unprovable(reporter *Reporter, what, detail string) error {
	if r.gatingCampaign() {
		return fmt.Errorf("certify: preflight: %s could not be proven, and this is a GATING campaign "+
			"(-campaign %s): a certification bundle may not rest on a precondition this run did not "+
			"establish. %s", what, r.campaign.Name, detail)
	}
	reporter.Line("preflight: %s could not be proven — %s. This is an EXPLORATORY run (no -campaign), so "+
		"it is a WARNING, not a refusal; a gating campaign would stop here", what, detail)
	return nil
}

// preflight verifies that the bench the flags describe is the bench that
// exists. It returns an error the caller should abandon the run on.
func (r *Runner) preflight(ctx context.Context, reporter *Reporter) error {
	if r.opts.SkipPreflight {
		r.recordWeakened(WeakenedSkipPreflight)
		return r.unprovable(reporter,
			"the -gridsim / -gridsim-admin pairing (-skip-preflight was passed)",
			"the run did not check that -gridsim and -gridsim-admin name one live process — the orphan-"+
				"and-replacement shape this file's own header documents. Drop -skip-preflight, or run "+
				"exploratory (no -campaign)")
	}

	data, admin := r.opts.Targets.GridSim, r.opts.Targets.GridSimAdmin
	switch {
	case admin == "" && data == "":
		return nil
	case admin == "":
		// No admin API: caps["gridsim"] is off and every check needing it
		// skips with that reason. Nothing to cross-check.
		return nil
	case data == "":
		// An admin URL with no data-plane target is the shape a report-only or
		// sim-driving run takes. There is no pair to check, and inventing a
		// failure here would only teach operators to pass -skip-preflight.
		reporter.Line("preflight: -gridsim-admin %s is configured with no -gridsim data-plane target, so "+
			"the two cannot be cross-checked", admin)
		return nil
	}

	dataHost, err := hostOfTarget(data)
	if err != nil {
		return fmt.Errorf("certify: preflight: -gridsim %q: %w", data, err)
	}
	adminHost, err := hostOfURL(admin)
	if err != nil {
		return fmt.Errorf("certify: preflight: -gridsim-admin %q: %w", admin, err)
	}
	if a, b := normaliseHost(dataHost), normaliseHost(adminHost); a != b {
		msg := fmt.Sprintf("certify: preflight: -gridsim %s and -gridsim-admin %s name DIFFERENT hosts "+
			"(%s vs %s). The DUT would dial one 2030.5 server while this run read its server-side "+
			"observations from another, and a server that saw no traffic answers honestly that it saw "+
			"none — which is then published as a device that never dialled",
			data, admin, dataHost, adminHost)
		if a == loopbackHost || b == loopbackHost {
			msg += fmt.Sprintf(". One of them is loopback, which makes it worse than inconsistent: traffic "+
				"to %s never crosses the capture interface (%s), so no frame of the DUT's 2030.5 "+
				"conversation can be captured, cited, or verified — every wire citation for it becomes "+
				"impossible rather than merely absent", loopbackNameOf(dataHost, adminHost), orNone(r.opts.Iface))
		}
		return fmt.Errorf("%s. Pass -skip-preflight only if this split is deliberate", msg)
	}

	ctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()

	var st struct {
		PID       int    `json:"pid"`
		DataPlane string `json:"data_plane"`
		PollRateS uint32 `json:"poll_rate_s"`
	}
	if err := NewAdminClient(admin, r.opts.HTTP).Status(ctx, &st); err != nil {
		return fmt.Errorf("certify: preflight: the 2030.5 server admin API at %s did not answer: %w. "+
			"Every check that reads gridsim's server-side observations would produce an empty answer "+
			"indistinguishable from a silent DUT", admin, err)
	}
	if st.DataPlane == "" {
		r.recordWeakened(WeakenedNoDataPlane)
		return r.unprovable(reporter,
			fmt.Sprintf("the -gridsim / -gridsim-admin pairing (%s reports no data-plane address)", admin),
			fmt.Sprintf("a gridsim built before it published data_plane cannot prove it is the same process "+
				"serving -gridsim %s. Rebuild gridsim to a version that reports data_plane before running a "+
				"gating campaign", data))
	}
	if err := sameListener(st.DataPlane, data); err != nil {
		return fmt.Errorf("certify: preflight: the process answering %s (pid %d) serves its 2030.5 data "+
			"plane on %s, but this run points the DUT at -gridsim %s: %v. That is the orphan-and-"+
			"replacement shape — one gridsim holding the admin port beside another holding the data port "+
			"— and it makes every server-side observation in this run a fact about the wrong server. "+
			"Pass -skip-preflight only if this split is deliberate",
			admin, st.PID, st.DataPlane, data, err)
	}
	reporter.Line("preflight: gridsim pid %d serves %s and answers on %s — one process, both ports"+
		pollRateSuffix(st.PollRateS), st.PID, st.DataPlane, admin)
	return nil
}

// preflightCitation refuses a GATING run whose -require-citation=false would
// let an uncited PASS stand as though it were a re-checkable claim.
//
// finalise's uncited-PASS rule (runner.go) is what makes a PASS in this
// engine's bundles a claim a third party can re-derive rather than a narrated
// one: a case that rolls up to PASS but carries no assertion bundle.Verify can
// re-derive from the capture is downgraded to WARN. -require-citation=false
// exists for framework development, where end-to-end digest wiring is not yet
// complete everywhere; it has no legitimate use on a bundle meant to decide a
// release, because it is exactly the switch that lets an unproven PASS stand
// as PASS. See REV0907-E3.
func (r *Runner) preflightCitation(reporter *Reporter) error {
	if r.opts.RequireCitation {
		return nil
	}
	r.recordWeakened(WeakenedRequireCitationFalse)
	return r.unprovable(reporter,
		"that every PASS in this run is citable (-require-citation=false was passed)",
		"an uncited PASS is not a claim a third party can re-check against the capture, and "+
			"-require-citation=false is exactly the switch that lets one stand as PASS instead of being "+
			"downgraded to WARN. Drop -require-citation=false, or run exploratory (no -campaign)")
}

// preflightSigning refuses a GATING run with no -sign-key.
//
// A hash-only MANIFEST.sha256 detects piecemeal tampering — edit one byte and
// the digest stops agreeing — but not the shape REV0907-E4 names: rewrite the
// WHOLE bundle, capture included, and rehash the manifest to agree with the
// rewrite, and every check bundle.Verify runs still passes, because internal
// consistency is all a hash ever claimed to establish (see
// bundle.Verify's own doc). A detached ed25519 signature over the manifest
// closes that gap — see bundle/sign.go — but only if one was actually taken,
// which needs a key the run was given.
//
// This is deliberately NOT recorded in bundle.CampaignRecord.Weakened the way
// -skip-preflight, -require-citation=false and an unprovable gridsim pairing
// are (see recordWeakened): every one of THOSE switches has a legitimate,
// recorded EXPLORATORY use — an operator's development run that -campaign
// would otherwise treat the same as a certification attempt. An unsigned
// GATING campaign has no analogous legitimate shape to disclose, because
// unprovable's own gating branch refuses the run before writeBundle is ever
// reached: no bundle this package writes ever carries campaign.gating=true,
// so there is nothing for a Weakened entry to describe that a reader could
// ever actually see.
func (r *Runner) preflightSigning(reporter *Reporter) error {
	if r.signKey != nil {
		return nil
	}
	return r.unprovable(reporter,
		"that this bundle's manifest will be SIGNED (-sign-key was not passed)",
		"an unsigned MANIFEST.sha256 detects piecemeal tampering but not a whole-bundle rewrite that "+
			"rehashes itself to agree (REV0907-E4). Pass -sign-key (see certify -gen-sign-key), or run "+
			"exploratory (no -campaign)")
}

func pollRateSuffix(seconds uint32) string {
	if seconds == 0 {
		return ""
	}
	return fmt.Sprintf(" (advertising a %ds pollRate)", seconds)
}

// loopbackHost is the token every loopback spelling normalises to, so
// "localhost", "127.0.0.1" and "::1" compare equal to each other and unequal to
// everything else.
const loopbackHost = "\x00loopback"

func hostOfTarget(target string) (string, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("not a host:port: %w", err)
	}
	return host, nil
}

func hostOfURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("names no host (want a base URL like http://69.0.0.20:11114)")
	}
	return u.Hostname(), nil
}

// normaliseHost reduces a host to something comparable: every loopback spelling
// to one token, every IP to its canonical unmapped form, everything else to
// lower case. It deliberately does NOT resolve names — a preflight that made
// DNS queries would fail in ways unrelated to the question it is asking.
func normaliseHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "localhost" {
		return loopbackHost
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		if addr.IsLoopback() {
			return loopbackHost
		}
		return addr.Unmap().String()
	}
	return h
}

func loopbackNameOf(a, b string) string {
	if normaliseHost(a) == loopbackHost {
		return a
	}
	return b
}

// sameListener reports whether an address a server says it is listening on
// covers the address this run dials.
//
// A listener bound to a wildcard (0.0.0.0, ::) serves every local address, so
// only the port can be compared; a listener bound to one address must match
// both. Getting this backwards in either direction would make the check
// useless: too strict and every 0.0.0.0 bench fails preflight, too loose and
// the orphan slips through on a port collision.
func sameListener(reported, dialled string) error {
	rHost, rPort, err := net.SplitHostPort(reported)
	if err != nil {
		return fmt.Errorf("the reported address %q is not a host:port: %v", reported, err)
	}
	dHost, dPort, err := net.SplitHostPort(dialled)
	if err != nil {
		return fmt.Errorf("the dialled address %q is not a host:port: %v", dialled, err)
	}
	if rPort != dPort {
		return fmt.Errorf("port %s is not port %s", rPort, dPort)
	}
	addr, perr := netip.ParseAddr(rHost)
	if rHost == "" || (perr == nil && addr.IsUnspecified()) {
		// A wildcard bind serves the dialled address too.
		return nil
	}
	if normaliseHost(rHost) != normaliseHost(dHost) {
		return fmt.Errorf("address %s is not %s", rHost, dHost)
	}
	return nil
}
