package invariant

// i5.go — A certificate valid in one trust domain never authenticates in
// another.
//
// Grounding: SEC-004, the split trust domains. The gateway keeps separate trust
// stores for its northbound mbaps clients and its southbound devices (and, in a
// field device, for its utility CSIP peer). A leaf that chains correctly in one
// of them must be worthless in the others; if it is not, the operator's
// separation of concerns is decorative, and compromising the least-protected
// domain compromises all of them.
//
// # What counts as "authenticates"
//
// This is the only subtle decision in the file, and getting it wrong in either
// direction produces a useless invariant.
//
// Too strict: "the handshake completed" is not authentication. A conformant
// server may well complete the TLS handshake with a leaf that chains to a CA it
// trusts for SOME purpose and then refuse it every request, because the identity
// carries no role for this service. That is correct behaviour, and an invariant
// that failed it would fire constantly on a device doing the right thing.
//
// Too loose: "the peer accepted a write" would miss a cross-domain credential
// that can read the whole register map, which is plainly an authentication it
// should not have had.
//
// So [AuthRecord.Authenticated] means: the handshake completed AND the peer
// subsequently SERVED at least one request. A session that answers every request
// with a denial has not authenticated the peer, it has merely tolerated the
// connection. The campaign is responsible for setting the flag on that basis,
// and the statement says so, because the whole invariant turns on it.
//
// # Coverage is the campaign's responsibility, and is reported
//
// I5 can only judge cross-domain attempts that were actually made. A run in
// which nobody presented a southbound certificate to :802 gets a SKIP naming
// exactly that, never a PASS. A pass here means "N cross-domain presentations
// were made and all N were refused", and the N is printed.

import (
	"context"
	"fmt"
	"sort"
)

type i5 struct{ p Params }

// NewI5 returns the trust-domain separation invariant.
func NewI5(p Params) Invariant { return &i5{p: p} }

func (i *i5) ID() string { return "I5" }

func (i *i5) Grounding() string {
	return "SEC-004 — split trust domains, where a leaf valid for the southbound device store " +
		"must be worthless against the northbound client store and vice versa."
}

func (i *i5) Statement() string {
	return "A certificate valid in one trust domain never authenticates in another: every " +
		"credential presented to an endpoint outside its issuing domain is refused. " +
		"'Authenticates' means the handshake completed AND the peer went on to serve at least one " +
		"request — a session that is tolerated but denied every request has NOT authenticated the " +
		"peer, and treating it as a violation would fail a device that is behaving correctly. " +
		"COVERAGE IS THE CAMPAIGN'S: a run that made no cross-domain presentation is reported SKIP " +
		"with that reason, never PASS, and a pass states how many presentations were refused."
}

func (i *i5) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	auths := w.Ledger().Auths()
	if len(auths) == 0 {
		return skipf("the campaign recorded no authentication attempt"), nil
	}

	res := Result{Verdict: Pass}
	// The identity is the credential, the domain pair it crossed, and the
	// endpoint it crossed at — "this leaf authenticates against :802" and "the
	// same leaf authenticates against the southbound port" are two separations
	// that failed, not one. The ledger seq and the free-text detail stay out;
	// see [keyer].
	key := keysOf(&res)
	pairs := map[string]int{}
	for _, a := range auths {
		if a.CredDomain == "" || a.TargetDomain == "" {
			continue // the campaign did not label the domains; nothing to compare
		}
		if a.CredDomain == a.TargetDomain {
			continue // same-domain presentation is not this invariant's business
		}
		res.Checked++
		pairs[a.CredDomain+" -> "+a.TargetDomain]++
		if !a.Authenticated {
			continue
		}
		res.Verdict = Fail
		key.note(Fail, "cross-domain-auth:%s:%s->%s:%s", a.Credential, a.CredDomain, a.TargetDomain, a.Target)
		res.Facts = append(res.Facts,
			F("i5.credential", "", "ledger", "%s", a.Credential),
			F("i5.cred_domain", "", "ledger", "%s", a.CredDomain),
			F("i5.target_domain", "", "ledger", "%s", a.TargetDomain),
			F("i5.target", "", "ledger", "%s", a.Target),
			F("i5.stage", "", "ledger", "%s", a.Stage),
			F("i5.authenticated", "", "ledger", "true — the handshake completed AND the peer served a request"),
			F("i5.detail", "", "ledger", "%s", a.Detail),
		)
		if res.Reason == "" {
			res.Reason = fmt.Sprintf("credential %q issued in trust domain %q authenticated against %s, "+
				"which belongs to trust domain %q — the domains are not separated",
				a.Credential, a.CredDomain, a.Target, a.TargetDomain)
		}
		res.Assertions = append(res.Assertions, narrate(
			fmt.Sprintf("a %s credential does not authenticate against a %s endpoint", a.CredDomain, a.TargetDomain),
			"present the foreign credential and observe whether the peer serves any request on the resulting session",
			Fail, res.Reason))
	}

	if res.Checked == 0 {
		return skipf("the campaign made no CROSS-DOMAIN presentation (%d attempts recorded, all same-domain or "+
			"unlabelled) — trust-domain separation was not exercised", len(auths)), nil
	}
	if res.Verdict == Pass {
		res.Assertions = append(res.Assertions, narrate(
			"every cross-domain credential presentation was refused",
			"present credentials from one trust domain to endpoints in another and require that none serves a request",
			Pass, fmt.Sprintf("%d cross-domain presentations refused across pairs: %s",
				res.Checked, joinComma(sortedPairs(pairs)))))
	}
	return res, nil
}

func sortedPairs(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s ×%d", k, v))
	}
	sort.Strings(out)
	return out
}
