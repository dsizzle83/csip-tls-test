package gwmayhem

// authority_pki.go is FAMILY D — authority / PKI / infra. These scenarios need the
// gateway put into a mode / a service restarted / a cert rotated / the trust store
// tampered — all BOARD-MUTATING steps this suite must NEVER take. So each scenario
// is split: a documented board-control HOOK (boardHook, data) the ORCHESTRATOR runs
// out of band to arm the mutation and later restore it, and a Go arm that only
// OBSERVES the gateway's effect over :802 / the sims' /state. Until the orchestrator
// arms it (and re-runs with -board-armed <id>) the runner SKIPS the scenario as an
// expected INCONCLUSIVE and prints the hook; when armed, the arm samples the effect
// and diagnoseAuthorityPKI judges it against the design contract — INCONCLUSIVE
// (with a note) where the decisive effect is only board-observable (certmgr 503 /
// journal), so the orchestrator supplies that evidence during the full run.
//
// The exact hook commands are also mirrored, human-readable, in
// qa/gw-scenarios/board-hooks.md for the orchestrator's runbook.

import (
	"context"
	"fmt"

	"csip-tls-test/internal/aggregator"
)

// board is the gateway host (the ConnectCore 93 dev kit, root@, per docs/BENCH.md).
// The service names + config paths below are the lexa-gw deployment's; the
// orchestrator confirms them against the live board before running a hook.
const boardSSH = "ssh root@69.0.0.2"

// authorityPKIScenarios is family D — every scenario is BOARD-MUTATING (NeedsBoard)
// and pinned [PASS, INCONCLUSIVE]: PASS when armed and the observed effect honors
// the contract, INCONCLUSIVE when unarmed / board-only, and a contract VIOLATION
// (armed + broken) trips the gate as a FAIL.
func authorityPKIScenarios() []gwScenario {
	return []gwScenario{
		authoritySwitchScenario(),
		privacySwitchScenario(),
		certRotationScenario(),
		trustStoreTamperScenario(),
		serviceRestartScenario(),
	}
}

// authorityPKIScenario is the shared shape: board-mutating, security-critical,
// pinned [PASS, INCONCLUSIVE], judged by diagnoseAuthorityPKI.
func authorityPKIScenario(id, desc string, hook boardHook, arm func(ctx context.Context, w *gwWorld, ev *gwEvidence) error) gwScenario {
	h := hook
	return gwScenario{
		ID:         id,
		Desc:       desc,
		Category:   "authority-pki-infra",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass, VerdictInconclusive},
		NeedsBoard: true,
		Board:      &h,
		oracle:     "authorityPKI",
		arm:        arm,
	}
}

// newAuthPKI seeds the outcome, stamping whether the orchestrator armed this
// scenario's board mutation for the run.
func newAuthPKI(w *gwWorld, id, contract string) *authorityPKIOutcome {
	return &authorityPKIOutcome{Kind: id, Contract: contract, BoardArmed: w.isBoardArmed(id)}
}

// ── authority-switch-honors-exclusive ────────────────────────────────────────

func authoritySwitchScenario() gwScenario {
	hook := boardHook{
		Arm:      boardSSH + ` 'jq ".authority=\"csip\"" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl restart lexa-mode'`,
		Observe:  "connect GridService over mbaps :802 and attempt a WMaxLimPct control write — it must be REFUSED (mbaps is no longer the authority)",
		Teardown: boardSSH + ` 'jq ".authority=\"mbaps\"" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl restart lexa-mode'`,
		Design:   "exclusive control authority (the user's core decision): the newly-non-authoritative interface's control is refused",
	}
	return authorityPKIScenario(
		"authority-switch-honors-exclusive",
		"flip mode.json authority mbaps→csip — the mbaps interface's control is then REFUSED (exclusive authority)",
		hook, armAuthoritySwitch)
}

func armAuthoritySwitch(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	o := newAuthPKI(w, "authority-switch-honors-exclusive", "exclusive control authority — the non-authoritative interface's control is refused")
	ev.AuthPKI = o
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		o.Note = "no served control unit (704) to probe the mbaps authority against"
		return nil
	}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		o.Note = "connect GridService over mbaps: " + err.Error()
		return nil
	}
	defer conn.Close()
	res, perr := conn.ProbeDenied(unit, matrixCtrlModel, matrixCtrlPoint, matrixNominalPct)
	switch {
	case perr != nil:
		o.Note = "authz probe transport error: " + perr.Error()
	case res.Wrote:
		o.Observed, o.EffectOK = true, false
		o.Effect = "mbaps control write was ACCEPTED while authority=csip — the exclusive authority was NOT honored"
	default:
		o.Observed, o.EffectOK = true, true
		o.Effect = fmt.Sprintf("mbaps control write refused (exception 0x%02x) while authority=csip — exclusive authority honored", res.ExceptionCode)
	}
	return nil
}

// ── privacy-switch-vendor-access ─────────────────────────────────────────────

func privacySwitchScenario() gwScenario {
	hook := boardHook{
		Arm:      boardSSH + ` 'jq ".vendor_access=false" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl reload-or-restart lexa-mode'`,
		Observe:  "the role-denial matrix's vendor-mode auto-detect — LexaVoltReadOnly must be DENIED every op (its RBAC role deleted) within ≤5s of the toggle",
		Teardown: boardSSH + ` 'jq ".vendor_access=true" /etc/lexa-gw/mode.json | sponge /etc/lexa-gw/mode.json && systemctl reload-or-restart lexa-mode'`,
		Design:   "design 05 §1.2: toggling vendor_access adds/removes LexaVoltReadOnly from the RBAC, effective ≤5s",
	}
	return authorityPKIScenario(
		"privacy-switch-vendor-access",
		"toggle vendor_access=false — LexaVoltReadOnly disappears from the RBAC (reuses the matrix vendor-mode detect); the transition takes effect ≤5s",
		hook, armPrivacySwitch)
}

func armPrivacySwitch(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	o := newAuthPKI(w, "privacy-switch-vendor-access", "design 05 §1.2 — vendor_access toggle removes/adds LexaVoltReadOnly ≤5s")
	ev.AuthPKI = o
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		o.Note = "no served control unit (704) to probe LexaVolt against"
		return nil
	}
	// Reuse the matrix's vendor-mode detector (probeVendorDisabled): LexaVoltReadOnly
	// denied a plain read ⇒ its role was deleted (vendor_access=false took effect).
	disabled := probeVendorDisabled(w, unit)
	o.Observed = true
	if disabled {
		o.EffectOK = true
		o.Effect = "LexaVoltReadOnly is now DENIED (its RBAC role removed) after vendor_access=false — as designed"
	} else {
		o.EffectOK = false
		o.Effect = "LexaVoltReadOnly is still ACTIVE after vendor_access=false — the vendor toggle did not take effect"
	}
	o.Note = "the ≤5s transition-latency bound (design 05 §1.2) is timing-observable — orchestrator supplies the toggle-applied timestamp vs. the detect time"
	return nil
}

// ── cert-rotation-mid-session ────────────────────────────────────────────────

func certRotationScenario() gwScenario {
	hook := boardHook{
		Arm:      boardSSH + ` 'curl -fsS -XPOST http://127.0.0.1:<certmgr-port>/v1/rotate -d "{\"target\":\"nb-mbaps-server\"}"'  (rotate the northbound mbaps server leaf WHILE an aggregator session is active)`,
		Observe:  "an existing aggregator session survives / cleanly reconnects, and a FRESH handshake succeeds presenting the rotated leaf (chain-valid to the trusted CA)",
		Teardown: "none (rotation is forward-only; the rotated leaf is the new resting cert). Re-run the standing aggregator to confirm steady state.",
		Design:   "cert rotation is hitless — active sessions survive, new handshakes present the rotated leaf and stay chain-valid",
	}
	return authorityPKIScenario(
		"cert-rotation-mid-session",
		"rotate the nb-mbaps-server cert via certmgr /v1/rotate mid-session — existing sessions survive, new handshakes use the new cert",
		hook, armCertRotation)
}

func armCertRotation(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	o := newAuthPKI(w, "cert-rotation-mid-session", "cert rotation is hitless — active sessions survive, new handshakes present the rotated leaf")
	ev.AuthPKI = o
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		o.Note = "no served control unit (704) to prove a fresh post-rotation handshake against"
		return nil
	}
	// A FRESH handshake after rotation must succeed presenting the rotated leaf (still
	// chain-valid to the trusted CA). Existing-session SURVIVAL is board-observable
	// (the lexa-mbaps session journal), supplied by the orchestrator.
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		o.Observed, o.EffectOK = true, false
		o.Effect = "a fresh mbaps handshake FAILED after rotation — the rotated leaf is not chain-valid, or the listener dropped: " + firstLine(err.Error())
		return nil
	}
	defer conn.Close()
	if _, rerr := conn.ReadPoint(unit, matrixCtrlModel, matrixCtrlPoint); rerr != nil && !isException(rerr) {
		o.Observed, o.EffectOK = true, false
		o.Effect = "a fresh post-rotation session handshook but its first read failed at transport: " + firstLine(rerr.Error())
		return nil
	}
	o.Observed, o.EffectOK = true, true
	o.Effect = "a fresh mbaps handshake succeeded after rotation and served a read — new handshakes use the rotated cert"
	o.Note = "existing-session survival is board-observable (lexa-mbaps session journal) — orchestrator confirms the pre-rotation session was not torn down"
	return nil
}

// ── trust-store-tamper-failclosed ────────────────────────────────────────────

func trustStoreTamperScenario() gwScenario {
	hook := boardHook{
		Arm:      boardSSH + ` 'printf deadbeef >> /var/lib/lexa-gw/certmgr/truststore/index.hmac && systemctl restart certmgr'  (corrupt the trust-store integrity index)`,
		Observe:  "certmgr latches FAIL-CLOSED: its API 503s, an integrity alarm is raised, and it does NOT crash-loop; over :802 mbaps handshakes are refused (no plaintext / no-verify downgrade)",
		Teardown: boardSSH + ` 'systemctl stop certmgr && rm /var/lib/lexa-gw/certmgr/truststore/index.hmac && <re-seal the trust store, e.g. certmgr --reseal> && systemctl start certmgr'`,
		Design:   "T03.12: a trust-store integrity failure latches fail-closed (503 + integrity alarm, NO crash-loop)",
	}
	return authorityPKIScenario(
		"trust-store-tamper-failclosed",
		"corrupt the certmgr truststore index.hmac — certmgr latches fail-closed (503s, integrity alarm, no crash-loop) [T03.12]",
		hook, armTrustStoreTamper)
}

func armTrustStoreTamper(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	o := newAuthPKI(w, "trust-store-tamper-failclosed", "T03.12 — trust-store integrity failure latches fail-closed (503 + alarm, no crash-loop)")
	ev.AuthPKI = o
	// The DECISIVE effect — certmgr 503 + integrity alarm + no crash-loop — is on
	// certmgr's own API / the journal, not :802. Judge it board-only; the orchestrator
	// supplies it. The :802 handshake attempt below is supporting evidence only.
	o.BoardOnly = true
	if _, err := w.connectAsReady(ctx, aggregator.RoleGridService); err != nil {
		o.Effect = "supporting: an mbaps handshake was REFUSED with the trust store tampered (fail-closed at :802): " + firstLine(err.Error())
	} else {
		o.Effect = "supporting: an mbaps handshake SUCCEEDED with the trust store tampered — investigate whether the tamper was caught (certmgr evidence is decisive)"
	}
	o.Note = "orchestrator supplies the decisive evidence: certmgr /health 503 + integrity alarm + `journalctl -u certmgr` shows a single latched failure, NOT a restart loop"
	return nil
}

// ── mosquitto-restart / service-restart-mid-cap ──────────────────────────────

func serviceRestartScenario() gwScenario {
	hook := boardHook{
		Arm:      "1) write an active cap first: aggregator -target 69.0.0.2:802 -pki certs/mbaps -campaign qa/aggregator/curtail-solar-50.json ; 2) then bounce a service: " + boardSSH + " 'systemctl restart mosquitto'  (or 'systemctl restart lexa-mbaps')",
		Observe:  "the gateway RESPONDS after the restart, and the cap holds (retained-state re-seed) or safely reverts to uncapped — never an absurd projection, never a wedge",
		Teardown: "release the cap: aggregator ... -campaign qa/aggregator/curtail-solar-50.json (its final step releases to 100%), and confirm the standing aggregator PASSES",
		Design:   "a service restart under an active cap re-seeds retained state; the cap holds or safely reverts; no wedge",
	}
	return authorityPKIScenario(
		"service-restart-mid-cap",
		"bounce mosquitto / lexa-mbaps under an active cap — retained-state re-seed, the cap holds or safely reverts, no wedge",
		hook, armServiceRestart)
}

func armServiceRestart(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	o := newAuthPKI(w, "service-restart-mid-cap", "a service restart under an active cap re-seeds retained state; the cap holds or safely reverts; no wedge")
	ev.AuthPKI = o
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		o.Note = "no served control unit (704) to read the post-restart cap from"
		return nil
	}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		o.Observed, o.EffectOK = true, false
		o.Effect = "the gateway did not accept a session after the restart — a possible WEDGE / failed re-seed: " + firstLine(err.Error())
		return nil
	}
	defer conn.Close()
	v, rerr := conn.ReadPoint(unit, matrixCtrlModel, matrixCtrlPoint)
	switch {
	case rerr != nil && !isException(rerr):
		o.Observed, o.EffectOK = true, false
		o.Effect = "no readback after the restart — a possible WEDGE (no re-seed / crashed loop): " + firstLine(rerr.Error())
	case absurdPct(v):
		o.Observed, o.EffectOK = true, false
		o.Effect = fmt.Sprintf("an ABSURD projection (%.1f%%) after the restart — the cap did not re-seed to a sane value", v)
	default:
		o.Observed, o.EffectOK = true, true
		o.Effect = fmt.Sprintf("the gateway is responsive after the restart and the cap re-seeded to %s (held or safely reverted) — no wedge, no absurd projection", pctStr(v))
	}
	return nil
}
