package certify

// preflight_authority.go refuses to let a run measure a control row under a DUT
// posture that guarantees the row measures something else.
//
// # The landmine (RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES, closed
// 2026-08-25 in lexa-gw/docs/known_issues.json)
//
// RBAC-002 and its siblings are Secure-SunSpec-Modbus rows whose own
// precondition is the gateway's Authority=='mbaps' posture. lexa-gw's
// configs/rbac/overlays.d/10-csip-mode.json deliberately denies model 704-712
// control writes to EVERY role, SuperAdministratorSunSpec included, whenever
// Authority=='csip' — the "D1 lock-screen" that keeps CSIP and Secure SunSpec
// Modbus from racing control of the same DER. That overlay is correct,
// intentional product behaviour; the bug was entirely on this side. Nothing in
// the battery confirmed which posture the DUT was actually in before asking a
// write row to prove a write succeeds.
//
// # What changed, and why the old version was not enough
//
// The first fix guarded exactly one family (`ssm-conf-v0.8::RBAC-*`) by prefix,
// read the posture out of a CONFIG FILE, and returned nil — FAIL OPEN — when no
// gateway was configured. All three were too narrow:
//
//   - The prefix. The same arbitration decides every CSIP control row and every
//     northbound WRITE row, and none of them were guarded. The classification is
//     now a table with a stated reason per family and three tests holding it
//     against the catalog — see authority.go.
//
//   - The config file. /etc/lexa/mode.json is the posture the device is
//     CONFIGURED with, which is not the posture it is IN. The live posture is
//     published retained on lexa/mode and projected at the dev API's GET /mode;
//     that is now the reading, and the file (or the intent overlay above it) is
//     kept as a cross-check that must AGREE.
//
//   - Fail open. "No gateway configured" was reported as a console line and the
//     run continued — so the one invocation that could not check the
//     precondition was the one that proceeded regardless. It is now an error,
//     with exactly one escape: an EXPLORATORY (non-campaign) run that passed
//     -skip-preflight, which the bundle then records as non-gating.
//
// The old comment here also asserted that `POST /intent {"type":"authority"}`
// does not work, "so a runbook that flips authority through the intent API is
// silently a no-op". THAT IS NO LONGER TRUE and the refusal messages no longer
// say it: lexa-gw cmd/mode/main.go subscribes lexa/intent/authority and
// internal/authority/intentin.go performs a real fail-closed transition. The
// intent lever is a working way to park the device, alongside editing mode.json
// and restarting lexa-mode.
//
// # What this check does, and does not do
//
// It is read-only, it runs once before the plan executes, and it does NOT flip
// authority itself — this harness must not mutate the DUT it is measuring, which
// is the same rule Gateway's read-only allowlist already enforces. An operator
// who sees it fail parks the DUT and re-runs. The goal is measuring the right
// precondition, not making a row pass regardless of it.

import (
	"context"
	"fmt"
	"strings"
)

// authorityOutcome is what the preflight established, for the bundle's record.
type authorityOutcome struct {
	// Required is the posture this run demanded. AuthorityAny means none was
	// pinned.
	Required AuthorityProfile
	// Reading is what the DUT reported, when the check actually ran.
	Reading *AuthorityReading
	// Unchecked, when non-empty, is why the precondition was NOT established.
	// A run carrying one is not gating, and the bundle says so.
	Unchecked string
}

// preflightAuthority establishes the DUT's control-authority posture before the
// plan executes, or refuses the run.
func (r *Runner) preflightAuthority(ctx context.Context, reporter *Reporter, plan []Planned) (authorityOutcome, error) {
	var out authorityOutcome
	gating := r.opts.Campaign != ""

	required, because, armed := r.authorityRequirement(reporter, plan)
	if !armed {
		return out, nil
	}
	out.Required = required

	gw := r.gateway()
	if !gw.Available() {
		msg := "the rows this run will execute have a DUT control-authority precondition, and no gateway " +
			"introspection is configured, so nothing here can confirm the DUT is in it. Pass -gateway-ssh " +
			"for a remote DUT, or -gateway-exec \"<prefix>\" for one on this host"
		switch {
		case gating:
			return out, fmt.Errorf("certify: preflight: -campaign %s %s. A campaign proves its "+
				"preconditions or it is not a campaign", r.opts.Campaign, msg)
		case r.opts.SkipPreflight:
			out.Unchecked = "the control-authority precondition was NOT established: no gateway " +
				"introspection was configured and -skip-preflight was passed"
			reporter.Line("preflight: %s — -skip-preflight was given, so this EXPLORATORY run continues "+
				"and the bundle records that it is NOT GATING", msg)
			return out, nil
		default:
			return out, fmt.Errorf("certify: preflight: %s. Pass -skip-preflight to run anyway; the "+
				"bundle will then record the run as exploratory and non-gating", msg)
		}
	}

	reading, err := ReadAuthority(ctx, gw, r.opts.DevAPI)
	if err != nil {
		return out, err
	}
	out.Reading = &reading
	if err := CheckAuthority(reading, required, because, r.authorityClaimed); err != nil {
		return out, err
	}
	if required == AuthorityAny {
		reporter.Line("preflight: DUT control authority %s over %s — no single posture required; it is "+
			"one the candidate claims", reading.String(), gw.Describe())
	} else {
		reporter.Line("preflight: DUT control authority %s over %s — the %q precondition is PROVEN before "+
			"case 1", reading.String(), gw.Describe(), required)
	}
	return out, nil
}

// authorityRequirement decides which posture this run must prove, and whether it
// must prove one at all.
//
// Two things arm it. A -campaign always does, whatever it selected: a campaign
// declares a lane, and the lane's posture is its precondition even if every row
// in it happened to skip. Otherwise the PLAN does, through the classification in
// authority.go — which keeps the original behaviour for an exploratory run that
// selects RBAC rows by hand, and extends it to every other control row.
//
// A plan demanding TWO postures cannot be satisfied by any device. That is the
// shape of every whole-catalog run, and refusing it outright would ban a run
// people legitimately do; so it is reported loudly, the check is disarmed
// because there is nothing coherent to check, and the run is marked non-gating.
// A campaign can never reach this branch: each expands to one lane.
func (r *Runner) authorityRequirement(reporter *Reporter, plan []Planned) (AuthorityProfile, string, bool) {
	if r.opts.Campaign != "" {
		if spec, ok := LookupCampaign(string(r.opts.Campaign)); ok {
			return spec.Authority, spec.Precondition, true
		}
	}
	demand := planAuthorityDemand(plan)
	switch len(demand.Rows) {
	case 0:
		return AuthorityAny, "", false
	case 1:
		a := demand.Postures()[0]
		_, because, _ := AuthorityPreconditionFor(demand.Rows[a][0])
		return a, because, true
	default:
		var parts []string
		for _, a := range demand.Postures() {
			uids := demand.Rows[a]
			parts = append(parts, fmt.Sprintf("%q for %d row(s) (%s)", a, len(uids), firstUIDs(uids, 4)))
		}
		reporter.Line("preflight: this selection needs MORE THAN ONE control-authority posture at once — "+
			"%s — and a DUT holds exactly one. Some of these rows will measure the arbitration layer "+
			"declining, not their own subject. This is an EXPLORATORY selection: run one -campaign per "+
			"lane for a result anything may rest on",
			strings.Join(parts, "; "))
		return AuthorityAny, "", false
	}
}

// authorityClaimed reports whether the candidate manifest lists a posture. It is
// nil-safe in both directions: no manifest means nothing is disclaimed, so every
// posture passes and the AuthorityAny branch of CheckAuthority checks only the
// live/configured agreement.
func (r *Runner) authorityClaimed(a AuthorityProfile) bool {
	if r.manifest == nil {
		return true
	}
	return r.manifest.ClaimsAuthority(string(a))
}

// firstUIDs renders the first n uids of a list, with a count of the rest, so a
// message about forty rows stays one line.
func firstUIDs(uids []string, n int) string {
	if len(uids) <= n {
		return strings.Join(uids, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(uids[:n], ", "), len(uids)-n)
}
