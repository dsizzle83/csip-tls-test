package suitecsip

// check.go is the body every CSIP check shares, so that no individual check has
// to remember the four things it would be catastrophic to forget:
//
//	1. CLAIM the endpoint, or the check produces no citable evidence at all;
//	2. take a BASELINE of the server's view, or it passes on another test case's
//	   evidence;
//	3. CLEAN UP the fault it armed, whatever happens, or it corrupts every later
//	   test case on a shared bench;
//	4. recover the session and mint the criteria from the CAPTURE, not from what
//	   the live phase thought it saw.
//
// A check therefore declares a spec — what to set up, what to wait for, what to
// assert — and this file runs it.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// defaultWait is how long a check waits for the DUT's next poll cycle by
// default. IEEE 2030.5 §10.2.3 lets a non-subscribing client poll as slowly as
// every 15 minutes, so this default is NOT enough for a DUT at the slow end —
// it is chosen to fit inside the runner's default 3-minute per-check timeout so
// that a misconfigured run fails fast and visibly instead of hanging.
//
// A real campaign raises both: `-timeout 20m -param csip.wait=16m`.
const defaultWait = 90 * time.Second

// waitParam is the operator override for the poll-cycle wait.
const waitParam = "csip.wait"

// endpointClaimReason is the argument, printed in every bundle this suite
// produces, for why attributing frames by endpoint rather than by connection
// 4-tuple is sound here.
const endpointClaimReason = "the DUT dials OUT to the bench's 2030.5 server, so this check cannot know the " +
	"DUT's ephemeral local port and cannot claim a full 4-tuple. The claim is therefore every TCP frame " +
	"to or from the CSIP server endpoint during this check's interval. That is sound on this bench because " +
	"the endpoint is the gridsim simulator and the gateway under test is its only client; it would NOT be " +
	"sound if a second conformance run were driving the same simulator concurrently, which is why live runs " +
	"in this campaign are serialized"

// spec declares one check's live phase and its pass criteria.
type spec struct {
	// Setup drives the bench into the state the procedure requires. It may
	// stash facts for the citation phase in params. A returned error means the
	// test could not be carried out, which the runner records as a FAIL saying
	// no conclusion about the DUT can be drawn.
	Setup func(ctx context.Context, d *Driver, params map[string]string) error

	// Want builds the wait predicate from the baseline. nil waits for one fresh
	// discovery walk, which is what most rows need.
	Want func(base ServerView) func(ServerView) bool

	// Wait overrides the poll-cycle wait for this check.
	Wait time.Duration

	// Cleanup always runs, including on error and on a cancelled context. It is
	// given a context that is NOT the check's, so a check killed by its timeout
	// still disarms what it armed.
	Cleanup func(ctx context.Context, d *Driver)

	// Criteria are the pass criteria, evaluated in the citation phase.
	Criteria func(o *Observation) []criterion

	// Notes renders the test case's prose line in the bundle.
	Notes func(o *Observation) string

	// RequiresGridSim declares that the check cannot run at all without the
	// admin API. Most can: the handshake tier needs only the capture.
	RequiresGridSim bool
}

// run executes a spec as a certify.Check.
func run(ctx context.Context, rc *certify.RunCtx, s spec) (certify.Result, error) {
	target, err := certify.AddrPort(rc.Targets.GridSim)
	if err != nil {
		return certify.Skipped("the bench's 2030.5 server address %q is not an ip:port: %v",
			rc.Targets.GridSim, err), nil
	}
	if err := rc.ClaimEndpointDuring("tcp", target, endpointClaimReason); err != nil {
		return certify.Result{}, fmt.Errorf("claim the CSIP server endpoint: %w", err)
	}

	d := NewDriver(rc)
	if s.RequiresGridSim && !d.Available() {
		return certify.Skipped("this test case needs gridsim's admin API to create its precondition, " +
			"and no admin URL was configured (-gridsim-admin)"), nil
	}
	if s.Cleanup != nil {
		// A context detached from the check's own deadline: a check killed by
		// -timeout must still disarm the fault it armed on a shared bench.
		defer func() {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			s.Cleanup(cctx, d)
		}()
	}

	obs := &Observation{Case: rc.Case, Params: map[string]string{}}
	base := d.Snapshot(ctx)
	obs.Server = base

	if s.Setup != nil {
		if err := s.Setup(ctx, d, obs.Params); err != nil {
			return certify.Result{}, fmt.Errorf("set up the procedure's precondition on the bench: %w", err)
		}
	}

	wait := s.Wait
	if wait == 0 {
		wait = defaultWait
	}
	if v, ok := rc.Param(waitParam); ok {
		if parsed, perr := time.ParseDuration(v); perr == nil {
			wait = parsed
		} else {
			rc.Logf("ignoring -param %s=%q: %v", waitParam, v, perr)
		}
	}

	var view ServerView
	var waited time.Duration
	var satisfied bool
	if d.Available() {
		if s.Want != nil {
			view, waited, satisfied = d.Await(ctx, wait, s.Want(base))
		} else {
			view, waited, satisfied = d.AwaitWalk(ctx, base, wait)
		}
		obs.Server = view.Since(base)
		obs.Server.Available = view.Available
		obs.Server.BaseURL = view.BaseURL
		obs.Server.Status = view.Status
		obs.Server.Errors = view.Errors
	} else {
		// No admin API: nothing to wait for and nothing to observe server-side.
		// The handshake tier still works, so the check is not pointless — but it
		// must wait anyway, or the capture window closes before the DUT polls.
		if err := rc.Sleep(ctx, wait); err != nil {
			return certify.Result{}, err
		}
		waited = wait
	}
	obs.Waited, obs.Satisfied = waited, satisfied
	rc.Logf("waited %s for the DUT's poll cycle (predicate satisfied: %t)", waited.Round(time.Second), satisfied)

	notes := ""
	if s.Notes != nil {
		notes = s.Notes(obs)
	}

	return certify.Result{
		Notes: notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			t, rerr := RecoverSession(ev, target)
			if rerr != nil {
				obs.NoSession = rerr.Error()
			} else {
				obs.Transcript = t
			}
			if s.Criteria == nil {
				return nil, fmt.Errorf("suitecsip: %s declared no criteria", rc.Case.UID)
			}
			return mint(ev, obs, s.Criteria(obs))
		},
	}, nil
}

// notApplicable is the check registered for every catalog row the §4 profile
// matrix excludes for this DUT.
//
// It is a real registration rather than an omission on purpose. Coverage that
// simply lacked these uids would read as "nobody got to them"; a registered row
// that reports NOT APPLICABLE and quotes the catalog's own applicability_reason
// reads as a decision a reviewer can check against the profile matrix — and
// disagree with, which is the point.
//
// It also prints the row's published ERRATA, and that breadcrumb has already
// earned its keep once. Until 2026-07-28 twenty-eight rows landed here, and
// twenty-two of them were excluded for a single reason: the DUT was scoped as a
// direct DER client while the §4 matrix marked them required for a DER
// AGGREGATOR client. When the owner re-scoped the certification, whoever
// implemented those rows had to read `steps` and `expected` — which are,
// correctly, a verbatim extraction of the UNAMENDED printed procedure — and
// would otherwise have implemented a body Annex A had already corrected. The
// corrections were in front of them, in this note, before the rows went live.
// The six rows still reported here are excluded for reasons no re-scope can
// change: four are §4 rows required of NO profile, and two are about a 2030.5
// server this DUT does not implement.
func notApplicable(_ context.Context, rc *certify.RunCtx) (certify.Result, error) {
	reason := strings.TrimSpace(rc.Case.ApplicabilityReason)
	if reason == "" {
		reason = "the catalog marks this test case inapplicable to this DUT but records no reason"
	}
	return certify.Result{
		Verdict: certify.Skip,
		Notes: fmt.Sprintf("NOT APPLICABLE to this DUT (%s). %s%s",
			roleWord(rc.Case), reason, errataBreadcrumb(rc)),
		OffWire: true,
		OffWireReason: "applicability is a property of the profile matrix in CSIP Conformance Test Procedures " +
			"V1.3 §4 and of what the DUT implements, not of any exchange on the wire. Asserting it from a " +
			"capture is not possible and pretending otherwise would be the dishonest option; the catalog's " +
			"applicability_reason above is the auditable record of the decision",
	}, nil
}

// errataBreadcrumb renders the row's client-relevant published corrections, or
// "" when it has none.
//
// A check MUST honour the errata for the case it implements — running the
// uncorrected step and calling the result a conformance failure would be the
// harness's bug, not the DUT's — and the rows this suite reports NOT APPLICABLE
// have no check to honour them yet. This is the record that survives until one
// exists.
func errataBreadcrumb(rc *certify.RunCtx) string {
	er := rc.Errata()
	if len(er) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, " PUBLISHED ERRATA that a future implementation of this row MUST honour "+
		"(CSIP Conformance Test Procedures V1.3, Annex A — Errata I, pp. 226-234); the catalog's steps "+
		"and expected criteria are the UNAMENDED printed text and must be read through these %d "+
		"correction(s):", len(er))
	for _, e := range er {
		fmt.Fprintf(&b, " [seq %d] %s → %s", e.Seq,
			strings.TrimSpace(e.Description), strings.Join(e.CorrectiveAction, " "))
		if impact := strings.TrimSpace(e.ObservableImpact); impact != "" {
			fmt.Fprintf(&b, " (observable impact: %s)", impact)
		}
	}
	return b.String()
}

func roleWord(c *certify.Case) string {
	switch c.DUTRole {
	case "":
		return "no DUT role recorded"
	default:
		return "catalog dut_role: " + string(c.DUTRole)
	}
}
