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
// port says it serves the data-plane port the flags point the DUT at. A gridsim
// too old to answer the second question is reported and allowed — an unproven
// pairing is a weaker position than a proven one, but it is not the same thing
// as a proven mismatch, and refusing to run against every previously-built
// simulator would make this check something operators disable by habit.

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
		reporter.Line("preflight SKIPPED (-skip-preflight) — the -gridsim / -gridsim-admin pairing is " +
			"unverified for this run, and the bundle records that")
		return nil
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
		reporter.Line("preflight: %s answers but reports no data-plane address (a gridsim built before it "+
			"published one), so it is NOT established that it is the same process serving -gridsim %s",
			admin, data)
		return nil
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
