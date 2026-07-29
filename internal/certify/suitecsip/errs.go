package suitecsip

// errs.go implements ERR-001 — Error Scenario 1: the DUT must follow an HTTP
// 301/302 redirect to a new URI and carry on walking.
//
// The row's published erratum (seq 8) matters here and is honoured: the
// procedure as written has the client make both a TLS and a non-TLS GET of
// /dcap, and the correction states that ALL testing for this row is done over
// the TLS link, including the request that triggers the redirect. This check
// therefore arms the redirect INSIDE the 2030.5 server, so the 301/302 is served
// over TLS, and never expects a cleartext request — which the DUT is in any case
// forbidden to make (CSIP §6.3.1.1: "HTTP is not permitted for utility to DER
// communications").
//
// # The backoff hazard, and how this check stays clear of it
//
// A redirect the DUT cannot resolve is a failed walk, and enough failed walks
// push the gateway into its 15-minute retry interval, which would poison every
// test case that runs after this one. The injection is therefore bounded to a
// SINGLE GET and points back at the same path, so the DUT's very next request
// succeeds. The check also disarms the injection in a cleanup that runs even if
// the check is killed by its timeout.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// redirectBudget is how many GETs of the discovery root answer with a redirect.
// One: enough to observe the follow, few enough that the DUT's walk succeeds on
// the very next request and never approaches its failure backoff.
const redirectBudget = 1

// errRedirect implements ERR-001.
func errRedirect(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			// A self-redirect: Location points back at the same path, so the
			// DUT's follow resolves immediately and the walk completes. An
			// absolute or cross-host Location would exercise the refusal path
			// instead, which is a different row's subject.
			params["redirect_path"] = DiscoveryRoot
			params["redirect_code"] = "302"
			return d.ArmRedirect(ctx, DiscoveryRoot, DiscoveryRoot, 302, redirectBudget)
		},
		Cleanup: func(ctx context.Context, d *Driver) { _ = d.ClearRedirect(ctx) },
		Want: func(base ServerView) func(ServerView) bool {
			// Two more GETs of the root than the baseline: the one that gets
			// redirected, and the follow.
			want := base.GETs(DiscoveryRoot) + 2
			return func(v ServerView) bool { return v.GETs(DiscoveryRoot) >= want }
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("armed a single 302 on %s with Location pointing back at it, over TLS per the "+
				"row's erratum (seq 8); waited %s, predicate satisfied: %t",
				DiscoveryRoot, o.Waited.Round(rounding), o.Satisfied)
		},
		Criteria: func(o *Observation) []criterion { return errRedirectCriteria() },
	})
}

// errRedirectCriteria is ERR-001's pass criteria, factored out of errRedirect
// so a test can evaluate each one directly against a fixture transcript
// without driving the whole check. None of the five reads the Observation
// argument the spec hands them, so nothing is lost calling it standalone.
//
//  1. the server's GET answered 301/302 with a Location -- read directly off
//     t.Exchanges because THIS criterion's subject IS the redirect response
//     itself, whichever exchange carries it.
//  2. the DUT re-issued the target inside the same TLS conversation -- same
//     reasoning, and it deliberately looks PAST the redirect exchange for the
//     follow-up.
//  3. critDiscoveryRoot(), i.e. critGET(DiscoveryRoot, ...): the ordinary
//     "GET /dcap -> 200 conformant DeviceCapability" restated by nearly every
//     row. This was the one reading exs[0] unconditionally and grading the
//     302 instead of the followed 200 -- see resourceExchange in
//     criteria_common.go for the fix.
//  4. critFollowedLink(): unaffected by the redirect fix; it also reads
//     t.Exchanges directly.
//  5. the whole exchange, redirect included, stayed on the TLS session.
func errRedirectCriteria() []criterion {
	return []criterion{
		{
			Claim: "the server answered the DUT's GET of the discovery root with a 301 or 302 carrying " +
				"a Location header",
			How:             "the status line and Location header of the first response to a discovery-root GET",
			NeedsTranscript: true,
			Wire: func(_ *certify.Evidence, t *Transcript) Finding {
				for _, e := range t.Exchanges {
					if e.Req == nil || e.Resp == nil {
						continue
					}
					if e.Resp.Status != 301 && e.Resp.Status != 302 {
						continue
					}
					loc := e.Resp.Header.Get("Location")
					if loc == "" {
						return citeMessage(t, e.Resp, certify.Fail,
							"%s -> %s with NO Location header; 2030.5 §5.5.2 requires one on a 302",
							e.Req.Line(), e.Resp.Line())
					}
					return citeExchange(t, e, certify.Pass, "%s -> %s, Location: %s",
						e.Req.Line(), e.Resp.Line(), loc)
				}
				return unavailable("no 301 or 302 appears in the recovered transcript; the injection "+
					"was armed for %d GET(s) of %s and the window saw %d exchange(s)",
					redirectBudget, DiscoveryRoot, len(t.Exchanges))
			},
			Server: func(v *ServerView) Finding {
				n := v.GETs(DiscoveryRoot)
				if n < 2 {
					return Finding{Verdict: certify.Fail,
						Observed: fmt.Sprintf("gridsim's request log records %d GET %s in this window; "+
							"a redirect and its follow would be two", n, DiscoveryRoot)}
				}
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("gridsim's request log records %d GET %s in this window, "+
						"consistent with the redirect being served and followed (the status codes are "+
						"not recoverable from the log)", n, DiscoveryRoot)}
			},
		},
		{
			Claim: "the DUT followed the Location header and re-issued the GET over the same TLS " +
				"session, rather than in cleartext or not at all",
			How: "a second request for the redirect target inside the same TLS conversation, after " +
				"the 3xx response",
			NeedsTranscript: true,
			Wire: func(_ *certify.Evidence, t *Transcript) Finding {
				redirectAt := -1
				var target string
				for i, e := range t.Exchanges {
					if e.Resp != nil && (e.Resp.Status == 301 || e.Resp.Status == 302) {
						redirectAt, target = i, e.Resp.Header.Get("Location")
						break
					}
				}
				if redirectAt < 0 {
					return unavailable("no 3xx appears in the recovered transcript, so there was no " +
						"redirect for the DUT to follow")
				}
				if target == "" {
					return unavailable("the 3xx carried no Location, so there was nothing to follow")
				}
				want := target
				if i := strings.IndexByte(want, '?'); i >= 0 {
					want = want[:i]
				}
				for _, e := range t.Exchanges[redirectAt+1:] {
					if e.Req != nil && e.Req.Path == want {
						return citeExchange(t, e, certify.Pass,
							"the DUT re-issued %s inside the same TLS session and the server answered %s",
							e.Req.Line(), e.Resp.Line())
					}
				}
				return found(certify.Fail, t.Exchanges[redirectAt].Frames(),
					"the DUT did not re-request %s within this window; the requests after the redirect "+
						"were: %s", want, strings.Join(pathsAfter(t, redirectAt), " "))
			},
		},
		critDiscoveryRoot(),
		critFollowedLink(),
		{
			Claim: "the whole exchange, redirect included, stayed inside TLS on the 2030.5 port " +
				"(ERR-001 erratum seq 8)",
			How: "the absence of any cleartext HTTP start line in the conversation the DUT opened, " +
				"together with the redirect being recovered from INSIDE the decrypted session",
			Wire: func(_ *certify.Evidence, t *Transcript) Finding {
				if t.ClientDir == nil || t.ClientDir.Bytes == nil {
					return unavailable("the DUT direction of the conversation was not reassembled")
				}
				head := t.ClientDir.Bytes.Bytes()
				if len(head) < 5 {
					return unavailable("the DUT direction carries fewer than 5 bytes")
				}
				if looksLikeHTTP(head[:min(16, len(head))]) {
					return Finding{Verdict: certify.Fail,
						Observed: "the DUT opened the conversation with cleartext HTTP, which CSIP " +
							"§6.3.1.1 forbids for utility-to-DER communications",
						Dir: t.ClientDir, Start: 0, End: min(16, len(head))}
				}
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("the conversation carries %d/%d application-data records and "+
						"no cleartext HTTP start line", t.ClientAppRecords, t.ServerAppRecords),
					Dir: t.ClientDir, Start: 0, End: 5}
			},
		},
	}
}

func pathsAfter(t *Transcript, i int) []string {
	var out []string
	for _, e := range t.Exchanges[i+1:] {
		if e.Req != nil {
			out = append(out, e.Req.Line())
		}
	}
	if len(out) == 0 {
		return []string{"(none)"}
	}
	return out
}
