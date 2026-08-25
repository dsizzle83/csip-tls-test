package certify

// preflight_authority.go refuses to let the RBAC/mbaps-authority-sensitive
// cluster run under the wrong DUT precondition.
//
// # The landmine (RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES, closed
// 2026-08-25 in lexa-gw/docs/known_issues.json)
//
// RBAC-002 (ssm-conf-v0.8) and its sibling RBAC-* rows are Secure-SunSpec-
// Modbus conformance cases whose own precondition is the gateway's
// Authority=='mbaps' posture — the product default. lexa-gw's
// configs/rbac/overlays.d/10-csip-mode.json deliberately denies model
// 704-712 control writes to EVERY role, including the nominally-unconditional
// SuperAdministratorSunSpec, whenever Authority=='csip' — the "D1
// lock-screen" that keeps CSIP and Secure-SunSpec-Modbus from racing control
// of the same DER. That overlay is correct, intentional product behaviour;
// the bug was entirely on this side: nothing in this battery ever confirmed
// which posture the DUT was actually in before asking an RBAC row to prove a
// write succeeds.
//
// Authority defaults to 'mbaps' and only becomes 'csip' via live arbitration
// while a CSIP DERControl is actively driving a DER (lexa-gw
// internal/authority/manager.go). A battery that runs CSIP-content-publishing
// cases (BASIC-006/011 Volt-Var/Volt-Watt adoption, etc.) ahead of the RBAC
// cluster — in the same session, even across separate `certify` invocations,
// if nothing between them proves the flip actually landed — can leave
// Authority stuck at 'csip', and every RBAC write in the cluster then
// measures the lock-screen instead of the row's own subject.
//
// The one lever that looks like a fix does NOT work: `POST /intent
// {"type":"authority",...}` validates and publishes the intent, but lexa-mode
// never subscribes to it (lexa-gw HANDOFF_2026-07-29_conformance.md task
// #24), so a runbook that "flips" authority through the intent API ahead of
// this leg is silently a no-op. The only proven mechanism today is editing
// /etc/lexa/mode.json's "authority" key on the DUT and `systemctl restart
// lexa-mode`.
//
// # What this check does, and does not do
//
// It is read-only (Gateway.Run's allowlisted `cat`), runs once before the
// plan executes — the same preflight.go discipline: fail in the first second
// with a message naming the consequence, not forty minutes in with a bundle
// full of findings about a lock-screen the run mismeasured. It does NOT flip
// authority itself (this harness must not mutate the DUT it is measuring —
// the same rule preflight.go and Gateway's read-only allowlist already
// enforce) and it does NOT weaken or skip the RBAC checks: an operator who
// sees this fail corrects the DUT's posture (the proven mode.json + restart
// path above) and re-runs. The goal is measuring the right precondition, not
// making the row pass regardless of it.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// mbapsAuthorityUIDPrefix names the cluster this check guards: every
// ssm-conf-v0.8 RBAC row. RBAC-002 is the row that surfaced the bug;
// RBAC-012's own per-model sweep shows the overlay's write-deny boundary
// applies uniformly across the whole model 704-712 family for every role the
// sweep tries, so the whole RBAC family — not only RBAC-002 — shares the same
// precondition, and is guarded the same way.
const mbapsAuthorityUIDPrefix = "ssm-conf-v0.8::RBAC-"

// planRequiresMbapsAuthority reports whether any case this run would actually
// execute belongs to the RBAC/mbaps-authority-sensitive cluster. A case that
// will SKIP anyway (missing capability, suite filter, unimplemented) costs
// nothing to measure wrong, so it does not arm this check.
func planRequiresMbapsAuthority(plan []Planned) bool {
	for _, p := range plan {
		if !p.Implemented || p.Skip != "" {
			continue
		}
		if p.Case != nil && strings.HasPrefix(p.Case.UID, mbapsAuthorityUIDPrefix) {
			return true
		}
	}
	return false
}

// gatewayMode is the subset of /etc/lexa/mode.json this check reads. Reading
// the file directly (rather than the authenticated GET /mode HTTP API) keeps
// this on the same read-only, token-free "cat a config file over
// -gateway-ssh" idiom every other config-derived fact in this package already
// uses, and needs no bearer-token forwarding through the SSH read-only
// allowlist.
type gatewayMode struct {
	Authority string `json:"authority"`
}

// preflightAuthority verifies the DUT's live Authority posture before an
// RBAC/mbaps-authority-sensitive cluster runs. It is a no-op (returns nil
// immediately) whenever no such case is actually planned, or whenever
// -skip-preflight was passed. Absent -gateway-ssh it cannot check anything —
// that is not a new limitation, it is the same "no gateway, no config-derived
// fact" limitation the RBAC rows' own "gateway"/"bench" capability tags
// already carry elsewhere — so it warns rather than fails, the same posture
// preflight's own no-admin-API branch takes.
func (r *Runner) preflightAuthority(ctx context.Context, reporter *Reporter, plan []Planned) error {
	if r.opts.SkipPreflight {
		return nil
	}
	if !planRequiresMbapsAuthority(plan) {
		return nil
	}
	return checkMbapsAuthority(ctx, &Gateway{SSH: r.opts.GatewaySSH}, reporter)
}

// checkMbapsAuthority is preflightAuthority's testable core: given a Gateway
// already known to be needed (the caller has established the plan requires
// it), read the DUT's live Authority and refuse to proceed if it is not
// "mbaps". Split out from preflightAuthority so a test can inject Gateway.Runner
// without a real ssh binary or a real -gateway-ssh flag, the same shape
// clients_test.go already uses for Gateway itself.
func checkMbapsAuthority(ctx context.Context, gw *Gateway, reporter *Reporter) error {
	if !gw.Available() {
		reporter.Line("preflight: the RBAC/mbaps-authority cluster is selected but no -gateway-ssh is " +
			"configured, so this run cannot confirm Authority=='mbaps' before it runs — every RBAC write " +
			"in the cluster risks measuring the D1 lock-screen (configs/rbac/overlays.d/10-csip-mode.json) " +
			"instead of its own subject if a prior CSIP control left Authority=='csip'. Pass -gateway-ssh " +
			"to make this check real")
		return nil
	}

	cctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	out, err := gw.Run(cctx, "cat", "/etc/lexa/mode.json")
	if err != nil {
		return fmt.Errorf("certify: preflight: the RBAC/mbaps-authority cluster is selected and could not "+
			"read the DUT's /etc/lexa/mode.json over -gateway-ssh %s to confirm its Authority posture: %w. "+
			"Pass -skip-preflight only if you have confirmed Authority=='mbaps' by some other means",
			gw.SSH, err)
	}
	var m gatewayMode
	if err := json.Unmarshal(out, &m); err != nil {
		return fmt.Errorf("certify: preflight: /etc/lexa/mode.json on %s did not decode as JSON: %w",
			gw.SSH, err)
	}
	if m.Authority != "mbaps" {
		return fmt.Errorf("certify: preflight: the RBAC/mbaps-authority cluster is selected but the DUT's "+
			"live Authority is %q, not \"mbaps\". Under Authority==\"csip\", "+
			"configs/rbac/overlays.d/10-csip-mode.json denies every model 704-712 control write for every "+
			"role — including SuperAdministratorSunSpec — by design (the D1 lock-screen that keeps CSIP "+
			"and Secure-SunSpec-Modbus from racing control of the same DER). Running the RBAC cluster now "+
			"would measure that lock-screen, not the rows' own subject — this is exactly "+
			"RBAC-002-MODEL704-REG40298-WRITE-DENIED-ALL-ROLES (lexa-gw/docs/known_issues.json). "+
			"`POST /intent {\"type\":\"authority\",...}` does NOT fix this (lexa-mode never subscribed to "+
			"it) — flip it on the DUT with the proven mechanism instead: edit /etc/lexa/mode.json's "+
			"\"authority\" to \"mbaps\" and `systemctl restart lexa-mode`, confirm no CSIP DERControl is "+
			"currently active, then re-run. Pass -skip-preflight only if this is deliberate",
			m.Authority)
	}
	reporter.Line("preflight: DUT Authority=%q confirmed via -gateway-ssh %s before the RBAC/mbaps-"+
		"authority cluster runs", m.Authority, gw.SSH)
	return nil
}
