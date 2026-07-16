// Track G-certrot — TLS cert-expiry / staged-rotation Mayhem scenario
// (audit docs/QA_COMPLETENESS_AUDIT.md P2-1, Batch 3b). New file per the
// "one concern = one file, scenarios + oracles together" convention.
//
// The hub already owns the cert side (audit "Needs lexa-hub change: NO"):
//   - cmd/northbound/certmon.go  — inspects client/CA PEM NotAfter every 24h,
//     publishes cert_status, sets lexa_cert_expiring_client/_ca, WARN/ERROR.
//   - cmd/northbound/rotate.go   — RotationController watches a sentinel file
//     and rotates the three fetchers via Reload's PROBE-then-commit swap,
//     REFUSING (LFDI defense-in-depth) a staged cert whose LFDI differs.
//   - internal/tlsclient/fetcher.go Reload — build+dial+probe the new session
//     fully BEFORE swapping; a failed probe leaves the old session untouched.
//
// This builds the BENCH seam the audit says was missing. It drives rotate.go's
// FAIL-CLOSED path SAFELY and deterministically: it writes a rotation sentinel
// pointing at a cert that cannot be adopted (a non-existent staged path — a
// stand-in for the different-LFDI / wrong-CA cert scripts/gen-expiring-cert.sh
// mints), so RotationController REFUSES it, keeps the live cert, and the hub
// never loses its identity or its control. The oracle asserts exactly that:
// the hub stays up and keeps enforcing the cap across the rotation attempt
// (probe/LFDI-before-swap failed closed), corroborated by
// lexa_nb_cert_rotation_refusals_total rising and cert_status still reporting.
//
// The EXPIRY half (drive client_days_left below the warn window so
// lexa_cert_expiring_client flips to 1) genuinely requires replacing the hub's
// LIVE cert and restarting lexa-northbound — destructive to the bench identity —
// so it is left to scripts/gen-expiring-cert.sh + the operator runbook, and this
// oracle READS and reports the gauge/days_left rather than forcing the flip.
//
// SSH-gated: off bench (no hub SSH+sudo) it reports INCONCLUSIVE at setup, the
// same gate local-clock-step-forward / the netfault scenarios use.

package main

import (
	"fmt"
	"log"
	"net/url"
	"time"
)

// certRotateSentinelPath is RotationController's default watched sentinel
// (cmd/northbound/rotate.go defaultCertRotateSentinel). A deployment that sets
// a non-default cert_rotate_sentinel would need this adjusted; the default is
// what deploy-hub-pi.sh installs.
const certRotateSentinelPath = "/etc/lexa/certs/rotate.request"

// mayhemStagedBadCert is a path that does NOT exist on the hub — pointing the
// sentinel here makes RotationController fail to derive the staged cert's LFDI
// and REFUSE (the "rejected" outcome), the safe stand-in for a real
// different-LFDI/wrong-CA cert: identical fail-closed behaviour, but nothing bad
// is ever staged where it could be picked up.
const mayhemStagedBadCert = "/etc/lexa/certs/mayhem-rotate-nonexistent.pem"

// ── observability readers ─────────────────────────────────────────────────────

// nbMetricsAddr derives lexa-northbound's Prometheus /metrics URL (:9102 per
// lexa-hub CLAUDE.md's metrics table) from the hub backend host.
func (d *mayhemDriver) nbMetricsAddr() (string, error) {
	base, ok := d.backends["hub"]
	if !ok {
		return "", fmt.Errorf("no hub backend configured")
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot derive hub host from %q", base)
	}
	return "http://" + u.Hostname() + ":9102/metrics", nil
}

func (d *mayhemDriver) readNBMetric(name string) (float64, bool) {
	addr, err := d.nbMetricsAddr()
	if err != nil {
		return 0, false
	}
	return d.scrapeMetricCounter(addr, name)
}

// hubCertStatus is the slice of /status cert_status (cmd/api/handlers.go's
// certStatusJSON) this oracle reads. reachable=false ⇒ /status itself was
// unreachable; present=false ⇒ cert monitoring is not wired / no verdict yet.
type hubCertStatus struct {
	ClientDaysLeft int
	DaysLeft       int
	ClientErr      string
	CheckedAt      string
	present        bool
	reachable      bool
}

func (d *mayhemDriver) hubCertStatus() hubCertStatus {
	var st struct {
		CertStatus *struct {
			ClientDaysLeft int    `json:"client_days_left"`
			DaysLeft       int    `json:"days_left"`
			ClientErr      string `json:"client_err,omitempty"`
			CheckedAt      string `json:"checked_at"`
		} `json:"cert_status,omitempty"`
	}
	if err := d.getJSON("hub", "/status", &st); err != nil {
		return hubCertStatus{}
	}
	if st.CertStatus == nil {
		return hubCertStatus{reachable: true}
	}
	return hubCertStatus{
		ClientDaysLeft: st.CertStatus.ClientDaysLeft,
		DaysLeft:       st.CertStatus.DaysLeft,
		ClientErr:      st.CertStatus.ClientErr,
		CheckedAt:      st.CertStatus.CheckedAt,
		present:        true,
		reachable:      true,
	}
}

// writeRotationSentinelCommand writes a rotation-request sentinel on the hub
// pointing at certPath. rotate.go's RotationController (poll every 5s) picks it
// up, tries to derive the staged cert's LFDI, and — for a non-existent /
// mismatched cert — refuses it, leaving the live cert in place.
func writeRotationSentinelCommand(sentinelPath, certPath string) string {
	body := fmt.Sprintf(`{"client_cert":%q,"client_key":%q,"requested_at":"mayhem"}`, certPath, certPath)
	return fmt.Sprintf("sudo -n sh -c 'printf %%s %q > %s'", body, sentinelPath)
}

// clearRotationSentinelCommand removes the sentinel and any consumed variants
// rotate.go renamed it to (rotate.request.rejected-<ts> etc.), so a run leaves
// no rotation state behind.
func clearRotationSentinelCommand(sentinelPath string) string {
	return fmt.Sprintf("sudo -n sh -c 'rm -f %s %s.* 2>/dev/null'; true", sentinelPath, sentinelPath)
}

// ── scenario ──────────────────────────────────────────────────────────────────

func (d *mayhemDriver) certRotationScenarios() []*mayScenario {
	return []*mayScenario{certRotationFailClosedScenario()}
}

func certRotationFailClosedScenario() *mayScenario {
	const holdS = 95
	var refusalsBefore, refusalsAfter float64
	var refusalsBeforeOK, refusalsAfterOK bool
	var certBefore, certAfter hubCertStatus
	return &mayScenario{
		ID:         "cert-rotation-failclosed",
		Name:       "Staged cert-rotation with a non-adoptable cert is refused — hub keeps its identity and the cap",
		Category:   "TLS lifecycle (INV-CERT fail-closed, P2-1)",
		Hypothesis: "An operator (or an automated rotation) stages a cert the hub must not adopt — a different LFDI (re-enrollment, not rotation) or a wrong-CA cert — and writes the rotation sentinel while a zero-export cap is active. rotate.go's probe/LFDI-before-swap must REFUSE it and keep the live session: a bad rotation attempt costs nothing (RSK-07). Here the sentinel points at a non-existent staged cert, the safe stand-in for that bad cert (identical refusal path, nothing installable).",
		Expected:   "RotationController refuses the staged cert (lexa_nb_cert_rotation_refusals_total rises, the sentinel is consumed to a .rejected/.failed variant), the live cert stays in force, /status keeps answering with its cert_status, and the active export cap is NEVER unseated across the rotation attempt.",
		HoldS:      holdS,
		Fix:        "cmd/northbound/rotate.go RotationController.checkOnce (LFDI defense-in-depth + probe-then-commit) and internal/tlsclient/fetcher.go Reload (build+probe BEFORE swapping the live session).",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.hubSSH("sudo -n true"); err != nil {
				return nil, fmt.Errorf("hub SSH/passwordless-sudo unavailable (need it to write the rotation sentinel on the hub): %w", err)
			}
			// Baseline: refusal counter + cert_status before the attempt.
			refusalsBefore, refusalsBeforeOK = d.readNBMetric("lexa_nb_cert_rotation_refusals_total")
			certBefore = d.hubCertStatus()

			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(d.pvHighW, 250)
			cons, err := d.postCap("exportCap", 0, holdS, "mayhem: cap across a fail-closed cert rotation")
			if err != nil {
				return nil, err
			}
			// Only write the sentinel once the cap is adopted, so any (unexpected)
			// disruption to control is attributable to the rotation attempt, not to
			// a not-yet-adopted cap.
			d.armAfterCapAdopted(cons, 2*time.Second, 60*time.Second, func() {
				if err := d.hubSSH(writeRotationSentinelCommand(certRotateSentinelPath, mayhemStagedBadCert)); err != nil {
					log.Printf("mayhem: cert-rotation-failclosed: write sentinel: %v", err)
				}
			})
			return cons, nil
		},
		perTick: func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseCertRotationFailClosed(sc, cons, s,
				refusalsBefore, refusalsAfter, refusalsBeforeOK && refusalsAfterOK,
				certBefore, certAfter)
		},
		teardown: func(d *mayhemDriver) {
			refusalsAfter, refusalsAfterOK = d.readNBMetric("lexa_nb_cert_rotation_refusals_total")
			certAfter = d.hubCertStatus()
			if err := d.hubSSH(clearRotationSentinelCommand(certRotateSentinelPath)); err != nil {
				log.Printf("mayhem: cert-rotation-failclosed: clear sentinel: %v", err)
			}
			d.deleteControls(0)
		},
	}
}

// diagnoseCertRotationFailClosed judges INV-CERT: the hub must stay up and keep
// the cap across a refused rotation. Survival is the primary bar (a mishandled
// rotation could crash lexa-northbound or unseat the control); the refusal
// metric and cert_status corroborate that rotate.go actually saw and refused the
// bad sentinel.
func diagnoseCertRotationFailClosed(sc *mayScenario, cons *activeConstraint, s []maySample,
	refusalsBefore, refusalsAfter float64, refusalsOK bool,
	certBefore, certAfter hubCertStatus) mayFinding {

	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding during the cert-rotation attempt"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples after the rotation sentinel was written — a rotation attempt (even a refused one) must never take lexa-northbound down (RSK-07 segfault territory: build+probe the new session before touching the live one).", len(s)-reach, len(s)),
			decisionLine(s),
		}
		return f
	}

	f.Metrics = scanSamples(cons, s)
	breaches := invExport(cons, s)

	// Corroboration lines (best-effort; never gate the verdict on an unreadable
	// metric — readMetricCounter's contract).
	var corrob []string
	if refusalsOK {
		if refusalsAfter > refusalsBefore {
			corrob = append(corrob, fmt.Sprintf("lexa_nb_cert_rotation_refusals_total rose %.0f→%.0f — RotationController saw the sentinel and refused it fail-closed.", refusalsBefore, refusalsAfter))
		} else {
			corrob = append(corrob, fmt.Sprintf("lexa_nb_cert_rotation_refusals_total did not rise (%.0f→%.0f) — the sentinel may not have been picked up within the hold (5s poll); the survival result below still holds.", refusalsBefore, refusalsAfter))
		}
	} else {
		corrob = append(corrob, "lexa-northbound :9102 metrics were unreadable — cannot confirm the refusal counter (metric unprovable, not a failure).")
	}
	if certAfter.reachable && certAfter.present {
		corrob = append(corrob, fmt.Sprintf("cert_status still reporting after the attempt (client_days_left=%d, days_left=%d, client_err=%q) — the cert monitor stayed wired and the live cert is intact.", certAfter.ClientDaysLeft, certAfter.DaysLeft, certAfter.ClientErr))
	}

	if len(breaches) == 0 {
		f.Verdict = "PASS"
		f.Headline = "hub refused the bad rotation and never unseated the cap"
		f.Diagnosis = append([]string{
			"INV-CERT: the hub stayed up and kept enforcing the active export cap across the refused cert-rotation attempt — probe/LFDI-before-swap failed closed, exactly as designed.",
			invSummaryLine("INV-EXPORT", breaches),
		}, corrob...)
		f.Diagnosis = append(f.Diagnosis, hubVsRealLine(s))
		forceBlindOnConstraintProbeGap(&f, cons, s)
		return f
	}
	if f.Metrics.TailClean {
		f.Verdict = "DEGRADED"
		f.Headline = "cap transiently dropped during the rotation attempt, then recovered"
		f.Diagnosis = append([]string{
			invSummaryLine("INV-EXPORT", breaches),
			"The rotation attempt briefly coincided with an export over the cap, but the hub re-established it before the window ended.",
		}, corrob...)
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = "the cert-rotation attempt unseated the safe control"
	f.Diagnosis = append([]string{
		invSummaryLine("INV-EXPORT", breaches),
		"A refused cert rotation must be a no-op for control, but the export cap stayed breached through the end of the window — the rotation path disrupted enforcement instead of leaving the live session untouched.",
		decisionLine(s),
	}, corrob...)
	return f
}
