package suitecsip

// errs_test.go is the regression for the ERR-001 evaluator bug: critGET took
// exs[0] unconditionally, so criterion 3 (critDiscoveryRoot, restated by
// nearly every row) graded the one-shot 302 self-redirect instead of the
// followed 200 that criterion 2 already proves came from the very same
// capture. See resourceExchange in criteria_common.go for the fix and
// errRedirectCriteria in errs.go for why these criteria can be evaluated
// directly against a fixture transcript.

import (
	"net/http"
	"testing"

	"csip-tls-test/internal/certify"
)

// redirectOnceHandler answers the FIRST GET of path with a 302 pointing back
// at itself, and every subsequent GET of it with a conformant
// DeviceCapability — exactly the shape errRedirect's Setup arms on the DUT's
// live server (ArmRedirect with redirectBudget=1), reduced to a fixture the
// suite can record without gridsim.
func redirectOnceHandler(path string) http.Handler {
	seen := 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			w.WriteHeader(404)
			return
		}
		seen++
		if seen == 1 {
			w.Header().Set("Location", path)
			w.WriteHeader(302)
			return
		}
		w.Header().Set("Content-Type", "application/sep+xml")
		_, _ = w.Write([]byte(`<DeviceCapability xmlns="urn:ieee:std:2030.5:ns">` +
			`<EndDeviceListLink href="/edev"/></DeviceCapability>`))
	})
}

// TestERR001RedirectWindowGradesTheFollowedGET is the direct regression: a
// window holding the 302 AND the followed 200 for the same path must pass
// criterion 1 (the 3xx was observed), criterion 2 (the DUT followed it) and
// criterion 3 (critDiscoveryRoot: the resource itself was fetched and is
// conformant) — all from this one capture.
func TestERR001RedirectWindowGradesTheFollowedGET(t *testing.T) {
	p := newTestPKI(t)
	h := redirectOnceHandler(DiscoveryRoot)
	rec := recordSession(t, p, h, []*http.Request{
		mustGET(t, DiscoveryRoot), // gets the 302
		mustGET(t, DiscoveryRoot), // the follow: gets 200
	})
	resetRunWireCache()
	t.Cleanup(resetRunWireCache)
	ev, server := evidenceFrom(t, rec, true)
	tr, err := RecoverSession(ev, server)
	if err != nil {
		t.Fatalf("RecoverSession: %v", err)
	}
	if !tr.Decrypted {
		t.Fatal("fixture must decrypt: the criteria under test all require the transcript")
	}

	// Sanity on the fixture itself: the window really does hold both
	// exchanges of the same path, redirect first.
	exs := tr.GETs(DiscoveryRoot)
	if len(exs) != 2 {
		t.Fatalf("fixture must present exactly 2 GET %s exchanges, got %d", DiscoveryRoot, len(exs))
	}
	if exs[0].Resp == nil || exs[0].Resp.Status != 302 {
		t.Fatalf("first exchange must be the 302, got %+v", exs[0].Resp)
	}
	if exs[1].Resp == nil || exs[1].Resp.Status != 200 {
		t.Fatalf("second exchange must be the followed 200, got %+v", exs[1].Resp)
	}

	crits := errRedirectCriteria()
	if len(crits) < 3 {
		t.Fatalf("errRedirectCriteria returned %d criteria, want at least 3", len(crits))
	}

	// Criterion 1: the server answered with a 301/302 carrying Location. This
	// must keep passing — it is what the fix must not regress.
	f1 := crits[0].Wire(ev, tr)
	if f1.Verdict != certify.Pass {
		t.Fatalf("criterion 1 (3xx observed) = %s (%s / %s), want Pass",
			f1.Verdict, f1.Observed, f1.Unavailable)
	}
	if len(f1.Frames) == 0 && f1.End <= f1.Start {
		t.Error("criterion 1 must cite the 3xx exchange it found")
	}

	// Criterion 2: the DUT followed the Location header on the same session.
	f2 := crits[1].Wire(ev, tr)
	if f2.Verdict != certify.Pass {
		t.Fatalf("criterion 2 (followed the redirect) = %s (%s / %s), want Pass",
			f2.Verdict, f2.Observed, f2.Unavailable)
	}

	// Criterion 3: critDiscoveryRoot() / critGET(DiscoveryRoot, ...) — the bug.
	// It must grade the FOLLOWED 200, not the 302 sitting at exs[0].
	f3 := crits[2].Wire(ev, tr)
	if f3.Verdict != certify.Pass {
		t.Fatalf("criterion 3 (critDiscoveryRoot) = %s (%s / %s), want Pass -- "+
			"this is the exact ERR-001 evaluator bug if it FAILs", f3.Verdict, f3.Observed, f3.Unavailable)
	}
	if f3.Observed == "" {
		t.Error("criterion 3 must record what it observed")
	}
}

// TestResourceExchangePrefersLastNonRedirect is the unit-level check on the
// selection helper itself, independent of the ERR-001 plumbing: given a GET
// history with a redirect followed by the real answer, the resource
// exchange is the answer, and a fully-stuck redirect still falls back to the
// last (redirect) exchange rather than becoming unavailable.
func TestResourceExchangePrefersLastNonRedirect(t *testing.T) {
	ok := &Message{Kind: Response, Status: 200}
	redirect := &Message{Kind: Response, Status: 302}
	notAnswered := Exchange{Req: &Message{Kind: Request}, Resp: nil}

	// Ordinary case: exactly one exchange, as in the ~70 rows that never see a
	// redirect. Must reduce to that one exchange.
	single := []Exchange{{Req: &Message{Kind: Request}, Resp: ok}}
	if got := resourceExchange(single); got.Resp != ok {
		t.Errorf("single-exchange case must return the only exchange unchanged")
	}

	// Redirect then the real answer: must prefer the answer.
	pair := []Exchange{
		{Req: &Message{Kind: Request}, Resp: redirect},
		{Req: &Message{Kind: Request}, Resp: ok},
	}
	if got := resourceExchange(pair); got.Resp != ok {
		t.Errorf("resourceExchange must prefer the last non-redirect exchange, got Resp=%v", got.Resp)
	}

	// Every exchange redirected (a walk that never resolved): must fall back
	// to the last one, so the FAIL that deserves is still produced, not an
	// unavailable/empty result.
	allRedirects := []Exchange{
		{Req: &Message{Kind: Request}, Resp: redirect},
		{Req: &Message{Kind: Request}, Resp: redirect},
	}
	if got := resourceExchange(allRedirects); got.Resp != redirect {
		t.Errorf("all-redirect case must fall back to the last exchange, got Resp=%v", got.Resp)
	}

	// An unanswered request is not a redirect either, and must be preferred
	// over an earlier fully-formed redirect exchange, matching the pre-fix
	// behaviour for a single unanswered exchange.
	unanswered := []Exchange{
		{Req: &Message{Kind: Request}, Resp: redirect},
		notAnswered,
	}
	if got := resourceExchange(unanswered); got.Resp != nil {
		t.Errorf("an unanswered exchange must be selected over an earlier redirect")
	}
}
