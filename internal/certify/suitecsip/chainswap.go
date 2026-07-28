package suitecsip

// chainswap.go drives gridsim's runtime certificate-chain lever for the four
// COMM-004 rejection sub-tests, and is mostly concerned with the ways that can
// go wrong on a shared bench.
//
// The happy path is three lines: mint the fixture, install it, wait for the DUT
// to dial. Everything else in this file is one of the four failure modes that
// would each, quietly, produce a verdict about something other than the DUT.
//
//  1. THE BENCH IS LEFT POISONED. A chain installed and not removed fails every
//     conformance case that runs afterwards, including other agents'. The
//     restore is therefore unconditional (spec.Cleanup, which the check runner
//     defers with a context detached from the check's own deadline), it is
//     VERIFIED by reading the chain back, and its outcome is carried into the
//     verdict — see chainSwap.restoreCriterion. A check that silently failed to
//     restore would look green while breaking the campaign.
//
//  2. THE FIXTURE IS ANCHORED SOMEWHERE THE DUT HAS NEVER HEARD OF. Then the
//     DUT rejects it for not knowing the root, the detector sees a rejection,
//     and the row passes without ever exercising the defect it is named for.
//     armed() therefore compares the anchor it minted under against the anchor
//     of the chain the bench NORMALLY serves, as GET /admin/chain reports it,
//     and refuses to run when they differ.
//
//  3. THE DUT NEVER DIALS DURING THE WINDOW. A 2030.5 client keeps ONE session
//     across poll cycles, and a swap only affects NEW connections, so on a
//     bench whose gridsim runs without -idle-timeout-s the DUT may hold a
//     connection established under the ORIGINAL chain for the whole window and
//     never see the fixture. That is not a rejection and must not be scored as
//     one; the criterion detects it by fingerprint and reports it as
//     unexercised, naming the flag.
//
//  4. THE BENCH HAS NO LEVER. An older gridsim answers /admin/chain 404; one
//     with no TLS data plane answers 501. Either way the sub-test SKIPs with
//     the reason it always had — which is why probe() runs first and its
//     result, not an exception, decides whether anything is installed.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suitepki"
)

// AdminChain mirrors gridsim's GET/POST /admin/chain response.
type AdminChain struct {
	Active   AdminChainState `json:"active"`
	Original AdminChainState `json:"original"`
}

// AdminChainState is one chain gridsim reports.
type AdminChainState struct {
	Label         string   `json:"label"`
	LeafSHA256    string   `json:"leaf_sha256"`
	ChainLen      int      `json:"chain_len"`
	Subjects      []string `json:"subjects"`
	Issuers       []string `json:"issuers"`
	Original      bool     `json:"original"`
	InstalledUnix int64    `json:"installed_unix"`
	Swaps         int      `json:"swaps"`
	Warnings      []string `json:"warnings"`
}

// Anchor is the DN of the trust anchor this chain expects the peer to hold: the
// issuer of the topmost certificate presented. Empty when the chain is empty or
// gridsim could not parse it.
func (s AdminChainState) Anchor() string {
	if len(s.Issuers) == 0 {
		return ""
	}
	return s.Issuers[len(s.Issuers)-1]
}

// chainSwap is one rejection sub-test's live-phase state, shared between the
// Setup that installs the fixture, the Cleanup that removes it, and the
// criteria that report on both.
//
// It is a pointer captured by all three closures rather than something stashed
// in Observation.Params, because the restore's outcome is not a string: a check
// has to be able to say "the restore FAILED and here is what the bench is
// serving now", and that has to reach the verdict.
type chainSwap struct {
	defect suitepki.MICADefect

	// skip is set when the sub-test could not be armed, and is the whole reason
	// the row reports SKIP.
	skip string
	// installed is the chain gridsim confirmed it installed.
	installed AdminChainState
	// original is what the bench was serving before, and what a restore must
	// put back.
	original AdminChainState
	// armedOK reports whether the fixture actually went on the wire.
	armedOK bool

	// restored, restoreErr and restoreState record the cleanup. restored FALSE
	// with a non-empty restoreErr is the loud case: the bench is still serving
	// the fixture.
	restored     bool
	restoreErr   string
	restoreState AdminChainState
}

// probe reads the lever, returning the reason a sub-test cannot run.
func (cs *chainSwap) probe(ctx context.Context, d *Driver) string {
	if !d.Available() {
		return "gridsim's admin API is needed to install the non-conformant chain this sub-test presents, " +
			"and no admin URL was configured (-gridsim-admin)"
	}
	var got AdminChain
	if err := d.Admin.Chain(ctx, &got); err != nil {
		return fmt.Sprintf("the bench's 2030.5 server does not offer the runtime certificate-chain lever "+
			"this sub-test needs (GET %s/admin/chain: %v). A gridsim predating the lever answers 404; one "+
			"with no TLS data plane wired to it answers 501. Without it the only way to present a "+
			"non-conformant chain is to restart the server, which would invalidate the evidence of every "+
			"test case already run against the running instance", d.Admin.BaseURL, err)
	}
	if got.Original.LeafSHA256 == "" {
		return "the bench's chain lever answered but reported no original chain, so there would be nothing " +
			"to restore afterwards; refusing to install a fixture that could not be removed"
	}
	cs.original = got.Original
	if got.Active.LeafSHA256 != got.Original.LeafSHA256 {
		return fmt.Sprintf("the bench is already serving a swapped chain (%q, leaf %s) rather than its "+
			"start-up chain (%q, leaf %s) — another run left a fixture installed, and this sub-test will "+
			"not stack a second one on top of it",
			got.Active.Label, shortSHA(got.Active.LeafSHA256), got.Original.Label, shortSHA(got.Original.LeafSHA256))
	}
	return ""
}

// arm mints the fixture and installs it. It returns a SKIP reason when the
// fixture cannot be minted honestly; a genuine failure to install is an error,
// because the bench state is then unknown and the run must say so.
func (cs *chainSwap) arm(ctx context.Context, rc *certify.RunCtx, d *Driver) (string, error) {
	if reason := cs.probe(ctx, d); reason != "" {
		return reason, nil
	}

	var serca *suitepki.CA
	if cs.defect.NeedsAnchor() {
		var why string
		if rc.PKI == nil {
			why = "no mbaps certificate fixtures are configured (-pki)"
		} else {
			serca, why = suitepki.BenchRoot(rc.PKI.CA)
		}
		if why != "" {
			return fmt.Sprintf("this sub-test's chain must be issued under the root the DUT ALREADY "+
				"TRUSTS, or the DUT rejects it for not knowing the root and the row passes without ever "+
				"exercising %s. That root is not available here: %s", cs.defect, why), nil
		}
		// The anchor has to be the one the bench's normal chain uses, or the
		// same false-PASS follows by another route.
		if got, want := cs.original.Anchor(), serca.Cert.Subject.String(); got != "" && got != want {
			return fmt.Sprintf("the trust anchor of the chain the bench normally serves (%q) is not the "+
				"root this harness can mint under (%q), so a fixture built here would be rejected by the "+
				"DUT for the wrong reason — not knowing the root, rather than %s. Point -pki at the "+
				"fixture tree the bench's 2030.5 server chains to", got, want, cs.defect), nil
		}
	}

	host := hostOf(rc.Targets.GridSim)
	chain, err := suitepki.MintServerChain(cs.defect, serca, suitepki.ServerLeafSpec{
		CommonName:  "csip-tls-test bench 2030.5 server (COMM-004 fixture)",
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{host},
	})
	if err != nil {
		return fmt.Sprintf("the fixture chain for %s could not be minted: %v", cs.defect, err), nil
	}

	var got AdminChain
	err = d.Admin.SwapChain(ctx, map[string]any{
		"label":    chain.Label,
		"cert_pem": string(chain.CertPEM),
		"key_pem":  string(chain.KeyPEM),
	}, &got)
	if err != nil {
		// Not a SKIP. The lever answered the probe and then refused the
		// install, so the bench may or may not be in the state we left it, and
		// a run that shrugged at that would be exactly the failure this file
		// exists to prevent. The caller's error path also runs Cleanup.
		return "", fmt.Errorf("install the %s fixture chain on the bench's 2030.5 server: %w", cs.defect, err)
	}
	if got.Active.LeafSHA256 != chain.LeafSHA256 {
		return "", fmt.Errorf("the bench reports it installed leaf %s but the fixture minted here is %s; "+
			"refusing to run a rejection sub-test against a chain this check cannot identify",
			shortSHA(got.Active.LeafSHA256), shortSHA(chain.LeafSHA256))
	}
	cs.installed = got.Active
	cs.armedOK = true
	rc.Logf("installed the %s fixture on the bench's 2030.5 server: %d certificate(s), leaf %s "+
		"(NEW connections only — an existing DUT session keeps the original chain until it closes)",
		cs.defect, cs.installed.ChainLen, shortSHA(cs.installed.LeafSHA256))
	return "", nil
}

// restore puts the bench back and VERIFIES it, recording what happened.
//
// It runs unconditionally from the check's cleanup path, including when the
// check was killed by its own timeout — the runner hands cleanup a context
// detached from the check's deadline for exactly this. It is safe to call when
// nothing was ever installed.
func (cs *chainSwap) restore(ctx context.Context, d *Driver) {
	if !cs.armedOK || !d.Available() {
		cs.restored = !cs.armedOK
		return
	}
	var got AdminChain
	if err := d.Admin.RestoreChain(ctx, &got); err != nil {
		cs.restoreErr = err.Error()
		return
	}
	// Trust the read-back, not the call's own success. The whole reason the
	// restore is verified is that "the POST returned 200" and "the bench is
	// serving the original chain" are different facts.
	if err := d.Admin.Chain(ctx, &got); err != nil {
		cs.restoreErr = "the restore was accepted but the chain could not be read back to confirm it: " + err.Error()
		return
	}
	cs.restoreState = got.Active
	if got.Active.LeafSHA256 != cs.original.LeafSHA256 {
		cs.restoreErr = fmt.Sprintf("the bench is serving leaf %s (%q) after the restore, not the original "+
			"%s (%q)", shortSHA(got.Active.LeafSHA256), got.Active.Label,
			shortSHA(cs.original.LeafSHA256), cs.original.Label)
		return
	}
	cs.restored = true
}

// restoreCriterion carries the cleanup's outcome into the verdict.
//
// It is a criterion rather than a log line because a check that installed a
// fixture and could not remove it has broken every case that follows it, and a
// run must not report that as a green row with a note. It FAILs, loudly, with
// the remedy in the text.
func (cs *chainSwap) restoreCriterion() criterion {
	return criterion{
		Claim: "the bench's 2030.5 server was returned to its original certificate chain after this " +
			"sub-test, so no later test case runs against a poisoned bench",
		How: "gridsim's chain lever was told to restore, and the chain it serves was then READ BACK and " +
			"compared to the start-up chain by leaf SHA-256 — the POST returning 200 and the bench " +
			"actually serving the original chain being two different facts",
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			switch {
			case !cs.armedOK && cs.skip != "":
				return unavailable("no chain was installed, so there was nothing to restore")
			case cs.restored:
				return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
					"the bench is serving its original chain again (%q, leaf %s), confirmed by reading "+
						"/admin/chain back after the restore", cs.original.Label, shortSHA(cs.original.LeafSHA256))}
			default:
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"THE BENCH WAS NOT RESTORED: %s. Every conformance case that runs after this one is "+
						"against a 2030.5 server presenting a deliberately non-conformant chain, and its "+
						"verdict is worthless. Restore it before continuing: "+
						"curl -sS -X POST -H 'Content-Type: application/json' -d '{\"restore\":true}' "+
						"<gridsim-admin>/admin/chain", cs.restoreErrText())}
			}
		},
	}
}

func (cs *chainSwap) restoreErrText() string {
	if cs.restoreErr != "" {
		return cs.restoreErr
	}
	return "the restore was never attempted"
}

// servedTheFixture reports whether the chain in the capture is the fixture this
// sub-test installed, by comparing the leaf's SHA-256.
//
// This replaces the old shape-guessing predicate. A fingerprint is exact: it
// cannot mistake the bench's normal chain for a fixture, and — the case that
// actually happens — it cannot mistake a session the DUT opened BEFORE the swap
// (and is entitled to keep) for one that saw the fixture.
func (cs *chainSwap) servedTheFixture(t *Transcript) (bool, string) {
	chain := t.Handshake.ServerChain
	if len(chain) == 0 {
		if t.Handshake.Resumed {
			return false, "the session in this window was RESUMED, so it carries no certificates and " +
				"cannot show which chain was presented"
		}
		return false, "the capture holds no server Certificate message for this session"
	}
	got := suitepki.SHA256Hex(chain[0])
	if got == cs.installed.LeafSHA256 {
		return true, ""
	}
	if got == cs.original.LeafSHA256 {
		return false, "the session in this window presented the bench's ORIGINAL chain (leaf " +
			shortSHA(got) + "), not the installed fixture (leaf " + shortSHA(cs.installed.LeafSHA256) +
			"). A chain swap affects NEW connections only, and a 2030.5 client keeps one session across " +
			"poll cycles — so on a bench whose gridsim runs without -idle-timeout-s the DUT can hold a " +
			"connection opened before the swap for the whole window and never be offered the fixture. " +
			"Start gridsim with -idle-timeout-s below the poll cadence, or lengthen the window " +
			"(-param " + waitParam + ")"
	}
	return false, fmt.Sprintf("the chain in this window (leaf %s — %s) is neither the installed fixture "+
		"(%s) nor the bench's original chain (%s); something else changed the bench mid-window and no "+
		"conclusion about this sub-test can be drawn", shortSHA(got), certSummary(chain[0]),
		shortSHA(cs.installed.LeafSHA256), shortSHA(cs.original.LeafSHA256))
}

// fixtureDescription is the sentence a bundle prints for what was presented.
func (cs *chainSwap) fixtureDescription() string {
	return cs.defect.Description()
}

func shortSHA(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	if s == "" {
		return "(none)"
	}
	return s
}

// hostOf strips the port from an ip:port target, so a minted server leaf can
// carry the address the DUT actually dials in its SAN. A fixture whose SAN does
// not cover that address is refused for the wrong reason.
func hostOf(target string) string {
	if i := strings.LastIndex(target, ":"); i > 0 {
		return target[:i]
	}
	return target
}
