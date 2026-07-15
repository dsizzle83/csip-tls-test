// Track D — OCPP 1.6 / V2G / OpenADR Mayhem scenarios and oracles
// (docs/QA_STANDARDS_BUILDOUT.md). New file per that doc's "Merge discipline"
// section: scenarios live in ocppOpenADRScenarios() below, new oracles in
// this same file. This file does NOT edit scenarios() or oracleRegistry —
// see the comment block at the very end for the exact reviewer-append lines.
//
// Covers four invariants:
//
//	INV-OCPP16          — a 1.6J charger obeys SetChargingProfile and
//	                      releases on ClearChargingProfile, identical
//	                      hub-side reconciler contract as 2.0.1.
//	INV-PAIRING         — an unknown charger is held Pending (no plant, no
//	                      transactions) until approved.
//	INV-V2G-CHARGEONLY  — an EV discharge setpoint is clamped to 0 A at
//	                      actuation.
//	INV-OPENADR         — the VEN adopts VTN price/limit signals; CSIP wins
//	                      on conflict; an OpenADR-only bind does not post a
//	                      2030.5 CannotComply.
//
// Bench-runnable vs unit-only (read this before running any of these):
//
//   - ocpp16-smart-charge / clear-profile-release (INV-OCPP16): evsim's
//     OCPP version is a LAUNCH-TIME flag (-proto 1.6, sim/evsim/main.go) —
//     there is no runtime switch, and main.go's own doc explains why:
//     evsim is "a protocol ADAPTER over one simulator", so nothing in its
//     /state or /inject surface distinguishes 1.6J from 2.0.1. These two
//     scenarios therefore carry a genuine BENCH PRECONDITION this driver
//     cannot arrange by itself: the deployed evsim systemd unit must
//     already be started with -proto 1.6. setup() probes the running
//     process over SSH (evsimRunningProto) and fails to INCONCLUSIVE with
//     an actionable message when it can positively confirm 2.0.1; when the
//     probe itself is inconclusive (no SSH) it proceeds with a loud log
//     line rather than refusing to run at all.
//   - pairing-gate-hold (INV-PAIRING): same shape of precondition —
//     pairing_mode is normally "open" on this bench (the shared default
//     every OTHER evsim scenario in this suite relies on), so exercising
//     the gate needs an explicit hand-set "pairing_mode":"gated" in the
//     deployed /etc/lexa/ocpp.json (CLAUDE.md's "deliberate, binary-only
//     hand-set Pi config" discipline — the same posture as the
//     battery/solar reconciler flips). setup() probes the live config
//     over SSH and fails to INCONCLUSIVE if it isn't gated, or if the
//     running evsim's station ID happens to already be allowlisted.
//   - ev-setpoint-clamp (INV-V2G-CHARGEONLY): the invariant's clamp lives
//     entirely in cmd/ocpp's actuation boundary (mqttBridge.Apply,
//     evseChargeAmpsFromSetpoint) — it fires on ANY setpoint-mode desired
//     doc regardless of how the hub's planner arrived at it. Coercing the
//     REAL day-ahead planner into choosing an EV-discharge action (which
//     needs hub.json's ev_storage:true PLUS specific SoC/pricing
//     conditions across a scheduled day-plan cycle — not something a
//     60-90s reactive Mayhem hold can force) would be a much heavier and
//     flakier precondition than INV-OCPP16/INV-PAIRING's. Instead this
//     scenario injects a synthetic lexa/desired/evse/{station} document
//     directly onto the retained bus topic (bypassing the planner
//     entirely) with a discharge-direction SetpointW — the exact same
//     "bypass the upstream producer, test the downstream consumer in
//     isolation" technique mqtt_scenarios.go already uses for
//     lexa/csip/control (mqttInject). This needs NO hub restart and NO
//     ev_storage config change: the desired-doc TOPIC AD-013 owns it is
//     read by cmd/ocpp's reconciler unconditionally, and the clamp being
//     tested runs at bridge.Apply regardless of the setpoint's origin.
//     Ground truth is evsim's own last_charging_profile.limit_A (the WIRE
//     value, before evsim's own charge-only battery model floors any
//     non-positive commandedA to 0 — see evLastProfileLimitA's doc for why
//     the simulated battery current ALONE cannot catch a missing clamp).
//   - openadr-limit-adopt / openadr-csip-precedence (INV-OPENADR): no VTN
//     sim existed before this track (see sim/vtnsim, built alongside this
//     file and fully unit-tested in isolation). Wiring the REAL
//     lexa-openadr VEN at that stub on the bench needs a vtn_url config
//     change PLUS a service restart (cmd/openadr/config.go: an empty
//     vtn_url is "uncommissioned — idles cleanly, no VTN traffic at all")
//     — too heavy an operational precondition for a routine Mayhem
//     scenario, and it would only exercise cmd/openadr's OWN polling/
//     translate logic, which is ALREADY covered by lexa-hub's
//     internal/openadr/*_test.go (out of this repo's scope, not
//     re-verified here). What THESE two scenarios exercise instead is the
//     HUB's D9 adoption/precedence logic in isolation
//     (cmd/hub/openadr_adopt.go's onOpenADRLimits/mergeOpenADRLimitsLocked
//   - main.go's CannotComply gate): they inject a bus.OpenADRLimits-shaped
//     document directly onto the retained lexa/openadr/limits topic — the
//     document lexa-openadr WOULD have published had a real VTN served the
//     event and the VEN translated it — via mqttInject, same bypass
//     technique as ev-setpoint-clamp above. This is bench-runnable RIGHT
//     NOW (cfg.OpenADRAdoptEnabled() defaults true, so a stock hub.json
//     already subscribes) but does NOT exercise the VEN's HTTP polling,
//     OAuth2 token flow, or CP-profile translation — that half stays
//     unit-only until a follow-up scripts vtn_url + restart into a bench
//     harness (see the follow-up note at the end of this file).
package main

import (
	"fmt"
	"log"
	"math"
	"os/exec"
	"strings"
	"time"
)

// ── Track D scenario battery ─────────────────────────────────────────────────

func (d *mayhemDriver) ocppOpenADRScenarios() []*mayScenario {
	sc := []*mayScenario{
		ocpp16SmartChargeScenario(),
		clearProfileReleaseScenario(),
		pairingGateHoldScenario(),
		evSetpointClampScenario(),
		openADRLimitAdoptScenario(),
		openADRCSIPPrecedenceScenario(),
	}
	return sc
}

// ── INV-OCPP16 ────────────────────────────────────────────────────────────────

// requireOCPP16Evsim is the shared INV-OCPP16 precondition gate for both 1.6J
// scenarios below — see the file doc's "bench-runnable vs unit-only" note for
// why this precondition exists and cannot be arranged by setup() itself.
func requireOCPP16Evsim(d *mayhemDriver, scenarioID string) error {
	proto, ok := d.evsimRunningProto()
	if ok && proto != "1.6" {
		return fmt.Errorf("evsim on the ev-pi is running OCPP %s, not 1.6 — %s requires the bench evsim unit launched with -proto 1.6 (docs/QA_STANDARDS_BUILDOUT.md's INV-OCPP16 precondition); edit the evsim systemd unit's ExecStart to add -proto 1.6, restart it, and re-run", proto, scenarioID)
	}
	if !ok {
		log.Printf("mayhem: %s: could not confirm evsim's running protocol over SSH (node unreachable, or no evsim process found) — proceeding on the DOCUMENTED PRECONDITION that the bench evsim unit was launched with -proto 1.6; if it was not, this scenario's verdict is meaningless", scenarioID)
	}
	return nil
}

const (
	// ocpp16RecoverAmpsFloor (A): a rise this large in the ground-truth
	// charger current after ClearChargingProfile is unambiguous recovery,
	// not sensor/measurement noise.
	ocpp16RecoverAmpsFloor = 2.0
	// ocpp16ReleaseRecoverFrac is the fraction of the station's configured
	// max current (maySample.EvMaxA) clear-profile-release requires the
	// charger to reclaim within mayConvergeDeadlineS of the release — a
	// quantitative regression pin for the WP-13 "stuck at the old limit"
	// bug class, stricter than ocpp16-smart-charge's plain "it moved" check.
	ocpp16ReleaseRecoverFrac = 0.6
)

func ocpp16SmartChargeScenario() *mayScenario {
	var releaseAtS float64 = -1
	return &mayScenario{
		ID: "ocpp16-smart-charge", Name: "1.6J charger obeys SetChargingProfile and releases on Clear",
		Category:   "OCPP 1.6J compatibility (INV-OCPP16)",
		Hypothesis: "A 1.6J-only charger (the compatibility listener, WP-12/cmd/ocpp's port_16 + bridge16.go) connects and charges. Under an import cap achievable only by curtailing the EV (battery full, solar low), the hub must drive the SAME reconciler contract over the 1.6 stack as 2.0.1: SetChargingProfile obeyed (measured current drops), then ClearChargingProfile on release (current resumes) — not a silently-ignored or half-implemented compatibility path.",
		Expected:   "Real (ground-truth) charger current drops under the import cap and the cap holds; after the control is explicitly released, current climbs back up rather than staying pinned.",
		HoldS:      80,
		Fix:        "Verify cmd/ocpp/bridge16.go's SetChargingProfile/ClearChargingProfile wiring and that the EVSE reconciler shell (reconcile_shell.go) dispatches through it identically to the 2.0.1 path for a station tagged protoOCPP16.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := requireOCPP16Evsim(d, "ocpp16-smart-charge"); err != nil {
				return nil, err
			}
			releaseAtS = -1
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // full → not a lever; the EV must be
			_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
			_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
			d.injectEnv(300, 500)
			return d.postCap("importCap", 1000, 80, "mayhem: 1.6J smart-charging under an import cap")
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(300, 500)
			if i == 45 { // cap adopted and settled; release it early to observe recovery
				releaseAtS = float64(i)
				d.deleteControls(0)
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseOCPP16Obey(sc, cons, s, releaseAtS)
		},
		teardown: func(d *mayhemDriver) {
			_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
			d.deleteControls(0)
		},
	}
}

func clearProfileReleaseScenario() *mayScenario {
	var releaseAtS float64 = -1
	return &mayScenario{
		ID: "clear-profile-release", Name: "Curtailed EV fully recovers on ClearChargingProfile (WP-13 regression)",
		Category:   "OCPP 1.6J compatibility (INV-OCPP16)",
		Hypothesis: "The exact WP-13 release-semantics regression: a 1.6J charger is curtailed by an import cap for a solid, settled stretch (not a transient blip), then the control is cleared. A hub that only stops RE-SENDING the old limit — without actually issuing ClearChargingProfile — leaves the charger stuck at the stale ceiling.",
		Expected:   "Within the settling deadline after release, the charger's real current climbs back to a solid majority of the station's configured max — not a small blip, and not left pinned near the curtailed value.",
		HoldS:      95,
		Fix:        "Verify ClearChargingProfile is actually SENT on release for a 1.6J station (bridge16.go), not merely a stop to re-sending SetChargingProfile — see internal/bus's RestoreCurrentA / the reconciler shell's release-vs-reassert distinction.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := requireOCPP16Evsim(d, "clear-profile-release"); err != nil {
				return nil, err
			}
			releaseAtS = -1
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
			_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
			d.injectEnv(300, 500)
			return d.postCap("importCap", 1000, 95, "mayhem: 1.6J deep curtailment then clear-profile release")
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(300, 500)
			if i == 60 { // long, settled curtailment window before release
				releaseAtS = float64(i)
				d.deleteControls(0)
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseOCPP16Release(sc, cons, s, releaseAtS)
		},
		teardown: func(d *mayhemDriver) {
			_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
			d.deleteControls(0)
		},
	}
}

// diagnoseOCPP16Obey judges ocpp16-smart-charge: under an import cap
// achievable only by curtailing the EV, the 1.6J charger must obey
// SetChargingProfile (the real charger draw drops, cap holds) — then, once
// the control is explicitly deleted, resume drawing rather than stay pinned.
// releaseAtS is the scenario-relative second perTick actually deleted the
// control at (-1 if it never fired, only reachable on an aborted run —
// already forced to INCONCLUSIVE upstream by run()'s own ctx.Err() handling).
func diagnoseOCPP16Obey(sc *mayScenario, cons *activeConstraint, s []maySample, releaseAtS float64) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if releaseAtS < 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "the control was never released mid-scenario — cannot judge the release half"
		return f
	}
	var pre, post []maySample
	for _, smp := range s {
		if smp.T < releaseAtS {
			pre = append(pre, smp)
		} else {
			post = append(post, smp)
		}
	}
	m := scanSamples(cons, pre)
	f.Metrics = m
	capStr := fmt.Sprintf("%s <= %.0f W", cons.Typ, cons.LimW)

	if len(pre) == 0 || m.SampleErrors > len(pre)/2 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "grid meter unreachable for most of the pre-release window — cannot judge compliance"
		return f
	}

	settled := m.BreachSeconds == 0 || (m.TailClean && m.ConvergedAtS >= 0 && m.ConvergedAtS <= mayConvergeDeadlineS)
	if !settled && !m.ReportedCannot {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("%s never held before release — the 1.6J charger did not obey SetChargingProfile", capStr)
		f.Diagnosis = []string{
			fmt.Sprintf("Peak %.0f W over for %.0fs before the control was released; with the battery full and solar low, the EV was the only lever and it did not curtail.", m.PeakBreachW, m.BreachSeconds),
			"Either lexa-ocpp never sent SetChargingProfile over the 1.6 stack, the charger did not apply it, or the hub never verified the metered current against the commanded limit (bridge16.go's Apply path).",
			decisionLine(s),
		}
		f.Fix = sc.Fix
		forceBlindOnConstraintProbeGap(&f, cons, pre)
		return f
	}

	// Release half: ground-truth EV draw (evSim, not the hub's OCPP-derived
	// view) must climb back up after the control is deleted.
	var lastSim float64
	haveLastSim := false
	for _, smp := range pre {
		if smp.EvSimOK {
			lastSim = smp.EvSimA
			haveLastSim = true
		}
	}
	var firstPostSim, firstPostT float64
	haveFirstPost := false
	recoveredAtS := -1.0
	for _, smp := range post {
		if !smp.EvSimOK {
			continue
		}
		if !haveFirstPost {
			firstPostSim, firstPostT = smp.EvSimA, smp.T
			haveFirstPost = true
		}
		if haveLastSim && smp.EvSimA > lastSim+ocpp16RecoverAmpsFloor {
			recoveredAtS = smp.T - releaseAtS
			break
		}
	}

	if !haveFirstPost {
		f.Verdict = "BLIND"
		f.Headline = "held the cap, but the ev sim probe went dark before the release could be judged"
		f.Diagnosis = []string{"The import cap held pre-release, but no ev sim reading was available after the control was deleted — the release half of INV-OCPP16 could not be checked this run."}
		return f
	}

	if !haveLastSim || recoveredAtS < 0 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("charger stayed pinned near ~%.1fA after the control was cleared", firstPostSim)
		f.Diagnosis = []string{
			fmt.Sprintf("%.0fs after the control was deleted the real draw was %.1fA — no clear rise from the pre-release reading.", firstPostT-releaseAtS, firstPostSim),
			"This is the release-semantics gap: ClearChargingProfile either was never sent, was sent with the wrong connector/purpose, or the charger accepted it but kept the stale limit applied.",
		}
		f.Fix = "Verify lexa-ocpp's bridge16.go issues ClearChargingProfile (not merely a zero-limit SetChargingProfile) on release, and that sim/evsim's handleClearChargingProfile (state.go, shared by both stacks) actually clears its commanded current."
		return f
	}

	f.Verdict = "PASS"
	f.Headline = fmt.Sprintf("obeyed the cap and resumed %.0fs after release", recoveredAtS)
	f.Diagnosis = []string{
		fmt.Sprintf("Real charger draw stayed within %s (peak overshoot %.0f W, %.0fs to converge) and climbed from ~%.1fA to over %.1fA within %.0fs of ClearChargingProfile.", capStr, m.PeakBreachW, m.ConvergedAtS, lastSim, lastSim+ocpp16RecoverAmpsFloor, recoveredAtS),
	}
	forceBlindOnConstraintProbeGap(&f, cons, pre)
	return f
}

// diagnoseOCPP16Release judges clear-profile-release: the WP-13 regression
// pin. Curtailment must have genuinely settled (not a blip) before release;
// recovery must reach a solid majority (ocpp16ReleaseRecoverFrac) of the
// station's configured max current within the settling deadline — a
// stronger quantitative bound than diagnoseOCPP16Obey's plain "it moved".
func diagnoseOCPP16Release(sc *mayScenario, cons *activeConstraint, s []maySample, releaseAtS float64) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if releaseAtS < 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "the control was never released mid-scenario — cannot judge the release regression"
		return f
	}
	var pre, post []maySample
	for _, smp := range s {
		if smp.T < releaseAtS {
			pre = append(pre, smp)
		} else {
			post = append(post, smp)
		}
	}
	if len(pre) == 0 || len(post) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "not enough samples on one side of the release to judge"
		return f
	}

	// Curtailment half: the charger must actually have been held down before
	// release, so "it recovered" is not vacuous.
	curtailedA := -1.0
	for _, smp := range pre {
		if smp.EvSimOK {
			curtailedA = smp.EvSimA
		}
	}
	if curtailedA < 0 {
		f.Verdict = "BLIND"
		f.Headline = "ev sim probe never answered before release — cannot confirm curtailment took hold"
		return f
	}

	var maxA float64
	for _, smp := range post {
		if smp.EvMaxA > maxA {
			maxA = smp.EvMaxA
		}
	}
	if maxA <= 0 {
		f.Verdict = "BLIND"
		f.Headline = "hub never reported the station's configured max current — cannot judge the recovery fraction"
		return f
	}

	recoveredAtS, bestPostA := -1.0, 0.0
	for _, smp := range post {
		if !smp.EvSimOK {
			continue
		}
		if smp.EvSimA > bestPostA {
			bestPostA = smp.EvSimA
		}
		if recoveredAtS < 0 && smp.EvSimA >= ocpp16ReleaseRecoverFrac*maxA {
			recoveredAtS = smp.T - releaseAtS
		}
	}

	if recoveredAtS < 0 || recoveredAtS > mayConvergeDeadlineS {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("charger stayed near its curtailed limit (best %.1fA of %.1fA station max)", bestPostA, maxA)
		f.Diagnosis = []string{
			fmt.Sprintf("Pre-release the charger drew %.1fA; within %ds of the control being deleted the best reading was only %.1fA of the %.1fA station max (want >= %.0f%%) — it never reclaimed the released capacity.", curtailedA, mayConvergeDeadlineS, bestPostA, maxA, ocpp16ReleaseRecoverFrac*100),
			"This is the exact release-semantics regression WP-13 closed: ClearChargingProfile must actually clear the standing limit, not merely stop re-sending the last one the charger obeyed.",
		}
		f.Fix = sc.Fix
		return f
	}

	f.Verdict = "PASS"
	f.Headline = fmt.Sprintf("recovered within %.0fs of ClearChargingProfile", recoveredAtS)
	f.Diagnosis = []string{
		fmt.Sprintf("Curtailed to %.1fA pre-release; recovered to >= %.0f%% of the %.1fA station max within %.0fs of the control being cleared.", curtailedA, ocpp16ReleaseRecoverFrac*100, maxA, recoveredAtS),
	}
	return f
}

// ── INV-PAIRING ───────────────────────────────────────────────────────────────

func pairingGateHoldScenario() *mayScenario {
	return &mayScenario{
		ID: "pairing-gate-hold", Name: "Unknown charger held Pending — no plant, no transactions",
		Category:   "OCPP pairing gate (INV-PAIRING)",
		Hypothesis: "A charger the hub was never told about (not in ocpp.json's stations[], never installer-approved) dials in while pairing_mode is \"gated\" (D10, cmd/ocpp/pairing.go). It should be answered BootNotification Pending and never promoted to plant state — but evsim itself does not gate its own charging on the registration status (main.go never branches on boot.Status), so the charger WILL try to draw real current regardless. The gate's job is entirely hub-side: fold nothing from this station into control.",
		Expected:   "The charger draws real current (evsim ground truth) while the hub's own EV power accounting stays at ~0 for it — the pending station's transaction/meter traffic is dropped (permitOrLogDrop), never folded into plant.",
		HoldS:      60,
		Fix:        "Verify main.go/bridge16.go route MeterValues/TransactionEvent through pairingGate.permitOrLogDrop before any stationState fold (WP-13) for both OCPP stacks.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			mode, err := d.ocppPairingMode()
			if err != nil {
				return nil, fmt.Errorf("cannot determine the hub's ocpp pairing_mode: %w", err)
			}
			if mode != "gated" {
				return nil, fmt.Errorf(`hub's /etc/lexa/ocpp.json pairing_mode is %q, not "gated" — pairing-gate-hold requires the bench hand-set pairing_mode:"gated" (docs/QA_STANDARDS_BUILDOUT.md's INV-PAIRING precondition; the bench profile default is "open", the same posture every other evsim scenario in this suite relies on, so flipping it is a deliberate, isolated bench config change — see CLAUDE.md's reconciler-flip discipline for the pattern)`, mode)
			}
			id, err := d.evStationID()
			if err != nil {
				return nil, fmt.Errorf("cannot read the ev sim's station id: %w", err)
			}
			configured, err := d.ocppConfiguredStationIDs()
			if err != nil {
				return nil, fmt.Errorf("cannot read the hub's configured ocpp stations: %w", err)
			}
			for _, c := range configured {
				if c == id {
					return nil, fmt.Errorf("ev sim station id %q is already allowlisted in /etc/lexa/ocpp.json stations[] — pairing-gate-hold needs an UNKNOWN station to exercise the gate; remove it from stations[] (or launch evsim with a different -id) and re-run", id)
				}
			}
			_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
			_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
			d.injectEnv(300, 500)
			return &activeConstraint{Typ: "none"}, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 500) },
		evaluate: diagnosePairingHold,
		teardown: func(d *mayhemDriver) {
			_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
		},
	}
}

func diagnosePairingHold(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
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
		f.Headline = "hub stopped responding while an unpaired charger dialed in"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples — a Pending station's BootNotification/traffic must never take the control loop down.", len(s)-reach, len(s)),
		}
		f.Fix = sc.Fix
		return f
	}

	active, chargedEver := 0, false
	for _, smp := range s {
		if smp.EvSimOK {
			active++
			if smp.EvSimA > 1.0 {
				chargedEver = true
			}
		}
	}
	if active < len(s)/2 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "ev sim probe mostly unavailable — cannot judge the pairing gate"
		return f
	}
	if !chargedEver {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "the charger never drew current — nothing for the pairing gate to have blocked"
		f.Diagnosis = []string{"The ev sim never showed a real charging current during the window, so this run cannot distinguish a gate correctly holding it Pending from a session that simply never started."}
		return f
	}

	// Did the hub fold the pending station's telemetry into plant state
	// anyway? A station never promoted to a stationState should contribute
	// ~nothing to the hub's own EV power accounting.
	leaked := 0
	var worstHubW, worstSimW, worstT float64
	for _, smp := range s {
		if !smp.EvSimOK {
			continue
		}
		if smp.EvW > mayEVLiveDrawW/2 {
			leaked++
			if smp.EvW > worstHubW {
				worstHubW, worstSimW, worstT = smp.EvW, smp.EvSimW, smp.T
			}
		}
	}
	if leaked > 0 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub folded the unpaired charger's telemetry into plant state (%.0f W reported)", worstHubW)
		f.Diagnosis = []string{
			fmt.Sprintf("At t=%.0fs the hub reported %.0f W of EV power (real charger draw %.0f W) even though this station is not configured and not approved — the pairing gate should have dropped its transaction/meter traffic (D10, cmd/ocpp/pairing.go's permitOrLogDrop), not folded it into plant.", worstT, worstHubW, worstSimW),
			"A Pending station influencing the optimizer's power accounting is exactly the plant-participation leak INV-PAIRING exists to catch — an unapproved charger must have zero say over dispatch.",
		}
		f.Fix = sc.Fix
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "unpaired charger drew real current but never reached hub plant state"
	f.Diagnosis = []string{
		fmt.Sprintf("The ev sim charged for real (current > 1A on at least one of %d/%d active samples) while the hub's own EV power accounting stayed at ~0 — the pairing gate held the station Pending and dropped its telemetry rather than folding it into control.", active, len(s)),
	}
	return f
}

// ── INV-V2G-CHARGEONLY ───────────────────────────────────────────────────────

// evSetpointClampDischargeW is the injected desired-doc's SetpointW: positive
// = discharge, per the site-wide sign convention (D8/WP-14,
// EVSECommand.SetpointW's doc in lexa-hub/internal/orchestrator/model.go).
const evSetpointClampDischargeW = 3000.0

func evSetpointClampScenario() *mayScenario {
	var stationID string
	var injectAtS float64 = -1
	var minProfileLimitA = math.Inf(1)
	var sawProfileAfterInject bool
	return &mayScenario{
		ID: "ev-setpoint-clamp", Name: "EV discharge setpoint clamped to 0 A (charge-only)",
		Category:   "V2G actuation boundary (INV-V2G-CHARGEONLY)",
		Hypothesis: "Even with a discharge-direction EV setpoint in force (as ev_storage:true's planner term would produce if it chose to discharge the EV), actuation must stay charge-only until a real V2X hardware path exists (D8/WP-14). Rather than coercing the day-ahead planner into a discharge decision — which needs ev_storage enabled AND specific SoC/pricing conditions across a scheduled plan cycle, not something a reactive Mayhem hold can force — this scenario injects a synthetic lexa/desired/evse/{station} document directly (bypassing the planner) with a positive (discharge) SetpointW, exercising cmd/ocpp's actuation-boundary clamp (mqttBridge.Apply) in isolation.",
		Expected:   "The charger's own last_charging_profile.limit_A (the wire-level command, read before evsim's charge-only battery model floors anything <=0) is never negative — the discharge setpoint converts to 0 A suspend, not a negative SetChargingProfile limit.",
		HoldS:      70,
		Fix:        "Verify cmd/ocpp/main.go's Apply (evseChargeAmpsFromSetpoint + the amps<0 clamp, the \"discharge setpoint\" seam) runs on every setpoint-mode command, including one arriving via the reconciler shell (reconcile_shell.go's desiredSetpointW plumbing) — not just a code path the planner happens to exercise today.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.mqttproxyProbe(); err != nil {
				return nil, err
			}
			id, err := d.evStationID()
			if err != nil {
				return nil, fmt.Errorf("cannot read the ev sim's station id: %w", err)
			}
			stationID = id
			injectAtS = -1
			minProfileLimitA = math.Inf(1)
			sawProfileAfterInject = false
			_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
			_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
			d.injectEnv(300, 500)
			return &activeConstraint{Typ: "none"}, nil
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(300, 500)
			if i == 20 { // session established and charging normally before the injection
				injectAtS = float64(i)
				payload := fmt.Sprintf(`{"v":1,"device_class":"evse","device_id":%q,"connector_id":1,"setpoint_w":%f,"source":"economic","issued_at":%d,"seq":1}`,
					stationID, evSetpointClampDischargeW, time.Now().Unix())
				if err := d.mqttInject(fmt.Sprintf("lexa/desired/evse/%s", stationID), payload, true); err != nil {
					log.Printf("mayhem: ev-setpoint-clamp: inject desired doc: %v", err)
				}
			}
			if limitA, ok := d.evLastProfileLimitA(); ok && injectAtS >= 0 && float64(i) >= injectAtS {
				sawProfileAfterInject = true
				if limitA < minProfileLimitA {
					minProfileLimitA = limitA
				}
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseEVSetpointClamp(sc, cons, s, injectAtS, minProfileLimitA, sawProfileAfterInject)
		},
		teardown: func(d *mayhemDriver) {
			_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
			// The injected discharge-setpoint desired doc is retained and, per
			// AD-013's heartbeat (150s — far longer than this scenario's own
			// hold), could otherwise linger well into whatever EV-facing
			// scenario runs next in this same file. Release it explicitly with
			// a FRESH issued_at: AD-013 rule 2 (internal/reconcile/reconcile.go)
			// accepts any strictly-newer issuedAt regardless of seq, so this
			// wins over the injected doc immediately rather than waiting on the
			// hub's own republish cadence.
			if stationID != "" {
				release := fmt.Sprintf(`{"v":1,"device_class":"evse","device_id":%q,"connector_id":1,"max_current_a":1000000,"source":"economic","issued_at":%d,"seq":2}`,
					stationID, time.Now().Unix())
				_ = d.mqttInject(fmt.Sprintf("lexa/desired/evse/%s", stationID), release, true)
			}
			_ = d.mqttReset()
		},
	}
}

// diagnoseEVSetpointClamp judges ev-setpoint-clamp. minProfileLimitA is the
// minimum last_charging_profile.limit_A observed at or after injectAtS
// (math.Inf(1) if none observed — sawProfileAfterInject distinguishes that
// from "observed and it happened to be high"). See evLastProfileLimitA's doc
// for why the wire-level limit, not evsim's own physical battery current, is
// the signal that can actually catch a missing clamp.
func diagnoseEVSetpointClamp(sc *mayScenario, cons *activeConstraint, s []maySample, injectAtS, minProfileLimitA float64, sawProfileAfterInject bool) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if injectAtS < 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "the discharge setpoint was never injected mid-scenario"
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
		f.Headline = "hub stopped responding after the discharge setpoint was injected"
		f.Diagnosis = []string{fmt.Sprintf("The hub's /status was unreachable on %d of %d samples.", len(s)-reach, len(s))}
		f.Fix = sc.Fix
		return f
	}

	// Belt check: evsim's own physical battery current must never go
	// negative either (it shouldn't be ABLE to — battery.go's Tick treats
	// any commandedA<=0 as "not charging" — so this only fires if something
	// bypassed the simulated hardware model entirely).
	for _, smp := range s {
		if smp.EvSimOK && smp.EvSimA < -0.5 {
			f.Verdict = "FAIL"
			f.Headline = fmt.Sprintf("evsim physically reported a negative current (%.1fA) — the EV discharged", smp.EvSimA)
			f.Diagnosis = []string{"The simulated charger itself reported negative current — a real EV was made to discharge. This should be physically impossible given evsim's charge-only battery model."}
			f.Fix = sc.Fix
			return f
		}
	}

	if !sawProfileAfterInject {
		f.Verdict = "BLIND"
		f.Headline = "no SetChargingProfile was observed on the wire after the injected discharge setpoint"
		f.Diagnosis = []string{
			"Neither the reconciler nor the OCPP bridge appears to have acted on the injected lexa/desired/evse/{station} discharge setpoint within this window — the clamp could not be exercised. This may mean the reconciler mode is not \"active\", the station ID did not match, or the doc was rejected (stale/NaN) before reaching bridge.Apply.",
		}
		return f
	}

	if math.IsInf(minProfileLimitA, 1) {
		f.Verdict = "BLIND"
		f.Headline = "could not read the charger's last_charging_profile.limit_A after injection"
		return f
	}

	if minProfileLimitA < 0 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub sent a NEGATIVE charging current limit (%.1fA) to the charger", minProfileLimitA)
		f.Diagnosis = []string{
			fmt.Sprintf("After injecting a +%.0f W (discharge-direction) desired setpoint, the charger's own last_charging_profile.limit_A read %.1fA — negative, on the wire, before evsim's physical model ever saw it.", evSetpointClampDischargeW, minProfileLimitA),
			"This is exactly the WP-14 regression the charge-only clamp exists to prevent: a discharge-direction setpoint must convert to 0 A suspend at cmd/ocpp's Apply, never a negative SetChargingProfile limit.",
		}
		f.Fix = sc.Fix
		return f
	}

	f.Verdict = "PASS"
	f.Headline = fmt.Sprintf("discharge setpoint clamped to %.1fA at the wire", minProfileLimitA)
	f.Diagnosis = []string{
		fmt.Sprintf("After injecting a +%.0f W discharge-direction setpoint, the lowest charging-profile limit the charger ever received was %.1fA — never negative. Actuation stayed charge-only.", evSetpointClampDischargeW, minProfileLimitA),
	}
	return f
}

// ── INV-OPENADR ───────────────────────────────────────────────────────────────

// openADRTopicLimits mirrors lexa-hub/internal/bus.TopicOpenADRLimits
// ("lexa/openadr/limits") — kept as a local constant (not imported: this
// repo has no dependency on lexa-hub's Go packages, only its wire contracts)
// exactly like topicCSIPControl in mqtt_scenarios.go mirrors
// bus.TopicCSIPControl.
const openADRTopicLimits = "lexa/openadr/limits"

func openADRLimitAdoptScenario() *mayScenario {
	var alertsBefore, alertsAfter int
	var beforeOK, afterOK bool
	return &mayScenario{
		ID: "openadr-limit-adopt", Name: "OpenADR-only export cap binds with no CSIP control active",
		Category:   "OpenADR adoption (INV-OPENADR)",
		Hypothesis: "A lexa/openadr/limits document (as lexa-openadr would publish after translating a VTN EXPORT_CAPACITY_LIMIT event — see internal/openadr/translate.go in lexa-hub) lands on the bus with NO CSIP control active at all. cmd/hub/openadr_adopt.go's onOpenADRLimits/mergeOpenADRLimitsLocked must merge it into GridState.ExportLimitW and the optimizer must actually enforce it — and, per D9's last bullet, an OpenADR-only bind must never produce a 2030.5 CannotComply (there is no CSIP mRID for one to reference).",
		Expected:   "The injected export cap holds (measured against the real grid meter) and gridsim's /admin/alerts records no new CannotComply during the window.",
		HoldS:      75,
		Fix:        "Verify cmd/hub/openadr_adopt.go's mergeOpenADRLimitsLocked actually assigns grid.ExportLimitW from the adopted OpenADR doc, and that the CannotComply emit path (main.go's emitAlerts / OpenADRBoundAxis gate) is never reached with no CSIP mRID in force.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.mqttproxyProbe(); err != nil {
				return nil, err
			}
			if n, err := d.gridsimAlertCount(); err == nil {
				alertsBefore, beforeOK = n, true
			}
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // full → PV curtailment is the only lever
			d.injectEnv(4800, 250)
			payload := fmt.Sprintf(`{"v":1,"imp_lim_w":null,"exp_lim_w":1000,"event_id":"vtnsim-openadr-limit-adopt","valid_until":0,"ts":%d}`, time.Now().Unix())
			if err := d.mqttInject(openADRTopicLimits, payload, true); err != nil {
				return nil, fmt.Errorf("inject lexa/openadr/limits: %w", err)
			}
			return &activeConstraint{Typ: "exportCap", LimW: 1000, MRID: ""}, nil
		},
		perTick: func(d *mayhemDriver, i int) { d.injectEnv(4800, 250) },
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseOpenADRBind(alertsBefore, alertsAfter, beforeOK && afterOK)(sc, cons, s)
		},
		teardown: func(d *mayhemDriver) {
			if n, err := d.gridsimAlertCount(); err == nil {
				alertsAfter, afterOK = n, true
			}
			_ = d.mqttInject(openADRTopicLimits, fmt.Sprintf(`{"v":1,"ts":%d}`, time.Now().Unix()), true) // release: both axes absent
			_ = d.mqttReset()
		},
	}
}

func openADRCSIPPrecedenceScenario() *mayScenario {
	var alertsBefore, alertsAfter int
	var beforeOK, afterOK bool
	return &mayScenario{
		ID: "openadr-csip-precedence", Name: "CSIP export cap wins over a looser OpenADR cap (D9 most-restrictive)",
		Category:   "OpenADR adoption (INV-OPENADR)",
		Hypothesis: "A lexa/openadr/limits document asserts a LOOSER export cap (3000 W) at the same time a CSIP DERControl asserts a TIGHTER one (0 W). D9 (architecture.md, NORMATIVE) requires combining most-restrictive — the hub must enforce the tighter 0 W CSIP cap, and if it cannot fully comply, any CannotComply it posts must attribute to the ACTIVE CSIP mRID, never fabricate an OpenADR-sourced Response.",
		Expected:   "The merged cap enforced is the tighter 0 W CSIP value (not the looser 3000 W OpenADR one), and every compliance alert gridsim records during the window is accounted for by the CSIP control's own mRID.",
		HoldS:      75,
		Fix:        "Verify cmd/hub/openadr_adopt.go's mergeOpenADRLimitsLocked takes min(OpenADR, CSIP) per axis rather than letting the looser OpenADR value override an active, tighter CSIP cap.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.mqttproxyProbe(); err != nil {
				return nil, err
			}
			if n, err := d.gridsimAlertCount(); err == nil {
				alertsBefore, beforeOK = n, true
			}
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(4800, 250)
			payload := fmt.Sprintf(`{"v":1,"imp_lim_w":null,"exp_lim_w":3000,"event_id":"vtnsim-openadr-precedence","valid_until":0,"ts":%d}`, time.Now().Unix())
			if err := d.mqttInject(openADRTopicLimits, payload, true); err != nil {
				return nil, fmt.Errorf("inject lexa/openadr/limits: %w", err)
			}
			return d.postCap("exportCap", 0, 75, "mayhem: CSIP cap must win over a looser simultaneous OpenADR cap")
		},
		perTick: func(d *mayhemDriver, i int) { d.injectEnv(4800, 250) },
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseOpenADRBind(alertsBefore, alertsAfter, beforeOK && afterOK)(sc, cons, s)
		},
		teardown: func(d *mayhemDriver) {
			if n, err := d.gridsimAlertCount(); err == nil {
				alertsAfter, afterOK = n, true
			}
			_ = d.mqttInject(openADRTopicLimits, fmt.Sprintf(`{"v":1,"ts":%d}`, time.Now().Unix()), true)
			_ = d.mqttReset()
		},
	}
}

// diagnoseOpenADRBind judges an OpenADR-adopted capacity limit under D9
// precedence, shared by openadr-limit-adopt (cons.MRID == "", no CSIP
// control at all) and openadr-csip-precedence (cons.MRID == the active CSIP
// control's mRID, tighter than the simultaneously-injected OpenADR cap).
//
// alertsBefore/alertsAfter are gridsim's TOTAL /admin/alerts count (every
// subject, not just cons.MRID) snapshotted immediately before/after this
// scenario's hold — needed because gridsim never removes an alert entry
// (mayhem.go's cannotComplyCount doc), so isolating THIS scenario's window
// needs a before/after delta the same way duplicate-client-id/mqtt-storm
// snapshot lexa_mqtt_reconnects_total (mqtt_scenarios.go). "attributed" is
// the last sample's CannotComplyCount for cons.MRID specifically (0 whenever
// cons.MRID == "", since maySample.sample() only populates CannotComply/
// CannotComplyCount when cons.MRID != ""). Any alert beyond that count is a
// misattribution: for openadr-limit-adopt that means ANY new alert at all
// (there is no CSIP mRID it could legitimately reference); for
// openadr-csip-precedence it means an alert beyond what CSIP's own mRID
// accounts for.
func diagnoseOpenADRBind(alertsBefore, alertsAfter int, alertsOK bool) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := baseFinding(sc)
		if len(s) == 0 {
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "no samples collected (aborted before any reading)"
			return f
		}
		m := scanSamples(cons, s)
		f.Metrics = m
		if m.SampleErrors > len(s)/2 {
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "grid meter unreachable for most of the run — cannot judge the OpenADR cap"
			return f
		}

		capStr := fmt.Sprintf("%s <= %.0f W", cons.Typ, cons.LimW)
		source := "an OpenADR-only bind (no CSIP control active)"
		if cons.MRID != "" {
			source = fmt.Sprintf("a CSIP control (mRID %s) simultaneously binding tighter than the injected OpenADR cap", shortMRID(cons.MRID))
		}

		attributed := 0
		if len(s) > 0 {
			attributed = s[len(s)-1].CannotComplyCount
		}
		misattributed := -1
		if alertsOK {
			misattributed = (alertsAfter - alertsBefore) - attributed
		}
		if misattributed > 0 {
			f.Verdict = "FAIL"
			f.Headline = fmt.Sprintf("%d CannotComply alert(s) posted with no CSIP mRID to attribute them to", misattributed)
			f.Diagnosis = []string{
				fmt.Sprintf("gridsim recorded %d new compliance alert(s) during this window; only %d were attributed to %s. D9's last bullet requires an OpenADR-bound cap to never generate a 2030.5 Response of its own (internal/bus/openadr.go).", alertsAfter-alertsBefore, attributed, source),
				"A CannotComply Response is a CSIP protocol object tied to a DERControl mRID; posting one for a limit that only OpenADR ever asserted is a protocol violation the utility head-end has no way to make sense of.",
			}
			f.Fix = "Gate the CannotComply emit path on an active CSIP mRID (OpenADRBoundAxis / episode attribution, cmd/hub/openadr_adopt.go + breach.go) — never post one for a cap that is OpenADR-only or where OpenADR is tighter than CSIP."
			return f
		}

		settled := m.BreachSeconds == 0 || (m.TailClean && m.ConvergedAtS >= 0 && m.ConvergedAtS <= mayConvergeDeadlineS)
		if !settled && attributed == 0 {
			f.Verdict = "FAIL"
			f.Headline = fmt.Sprintf("%s breached %.0fs — the OpenADR-adopted cap never held", capStr, m.BreachSeconds)
			f.Diagnosis = []string{
				fmt.Sprintf("Peak %.0f W over the merged cap, breaching for %.0fs with no sign of convergence and no CannotComply admitting it.", m.PeakBreachW, m.BreachSeconds),
				"This cap only exists because of the injected lexa/openadr/limits document — the hub either never adopted it (cmd/hub/openadr_adopt.go's onOpenADRLimits/mergeOpenADRLimitsLocked) or the optimizer never converged on it.",
				decisionLine(s),
			}
			f.Fix = sc.Fix
			forceBlindOnConstraintProbeGap(&f, cons, s)
			return f
		}
		if !settled && attributed > 0 {
			f.Verdict = "DEGRADED"
			f.Headline = fmt.Sprintf("%s breached but the hub admitted CannotComply against %s", capStr, source)
			f.Diagnosis = []string{
				fmt.Sprintf("The cap breached for %.0fs, but the hub correctly posted CannotComply against the active CSIP control rather than silently exceeding an obligation OpenADR alone asserted.", m.BreachSeconds),
			}
			forceBlindOnConstraintProbeGap(&f, cons, s)
			return f
		}

		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("%s held, correctly attributed (%s)", capStr, source)
		f.Diagnosis = []string{
			fmt.Sprintf("The merged export cap (%.0f W) held for the window with no CannotComply misattributed away from %s.", cons.LimW, source),
		}
		if !alertsOK {
			f.Verdict = "BLIND"
			f.Headline = "cap held, but the gridsim alert probe failed — misattribution could not be verified"
			f.Diagnosis = append(f.Diagnosis, "gridsim /admin/alerts was unreachable for the before/after snapshot in this run; the compliance half of INV-OPENADR passed but the no-misattribution half is unverified.")
		}
		forceBlindOnConstraintProbeGap(&f, cons, s)
		return f
	}
}

// ── Driver helpers (mirroring hubSSH/hubSSHOutput's generalization to "ev",
//    and the parseMQTTClientIDLine/hubMQTTClientID "read the live config
//    rather than assume" pattern in mqtt_scenarios.go) ──────────────────────

// nodeSSHOutput generalizes hubSSHOutput (mayhem_world.go) to an arbitrary
// bench node, the way nodeSSH generalizes hubSSH. Same BatchMode/timeout
// contract; not added to mayhem_world.go itself (this track's file only).
func (d *mayhemDriver) nodeSSHOutput(node, command string) (string, error) {
	target, err := d.nodeSSHTarget(node)
	if err != nil {
		return "", err
	}
	cmd := exec.Command("ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=4",
		target, command)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssh %s %q: %v", target, command, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// evsimRunningProto SSHes to the ev-pi node and inspects the actually-running
// evsim process's command line for -proto 1.6 (sim/evsim/main.go's -proto
// flag — fixed at launch, no runtime switch). ok=false means the probe
// itself could not run (SSH unreachable, no evsim process found) — callers
// must treat that as "unconfirmed", never as "confirmed 2.0.1".
func (d *mayhemDriver) evsimRunningProto() (proto string, ok bool) {
	out, err := d.nodeSSHOutput("ev", `ps -eo args= | grep '[e]vsim'`)
	if err != nil {
		return "", false
	}
	return evsimProtoFromPS(out)
}

// evsimProtoFromPS classifies a `ps -eo args=` dump for the running evsim
// process's -proto flag. Pure so the classification is unit-testable
// without SSH; evsimRunningProto is the only caller. Precondition: psLine is
// either empty (evsimRunningProto's grep found no match — ssh/grep failures
// already return early as their own ok=false in evsimRunningProto, never
// reaching here) or a line grep already matched on '[e]vsim', so "evsim"
// appearing in a non-empty psLine is a given, not something this function
// needs to re-verify defensively.
func evsimProtoFromPS(psLine string) (proto string, ok bool) {
	lower := strings.ToLower(strings.TrimSpace(psLine))
	if lower == "" {
		return "", false
	}
	switch {
	case strings.Contains(lower, "-proto 1.6") || strings.Contains(lower, "-proto=1.6") ||
		strings.Contains(lower, "-proto 1.6j") || strings.Contains(lower, "-proto=1.6j"):
		return "1.6", true
	case strings.Contains(lower, "evsim"):
		return "2.0.1", true // -proto absent/explicit 2.0.1 ⇒ evsim's own default
	default:
		return "", false
	}
}

// ocppPairingMode reads the DEPLOYED hub's ocpp.json pairing_mode over SSH —
// mirrors hubMQTTClientID's "read the live config rather than assume" gate
// (mqtt_scenarios.go). An absent/empty key resolves per profile in
// cmd/ocpp/config.go's loadConfig (almost certainly "open" on this bench).
func (d *mayhemDriver) ocppPairingMode() (string, error) {
	out, err := d.hubSSHOutput(`grep -o '"pairing_mode"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/lexa/ocpp.json 2>/dev/null; true`)
	if err != nil {
		return "", fmt.Errorf("read hub ocpp config over SSH: %w", err)
	}
	if out == "" {
		return "", nil
	}
	return parsePairingModeLine(out)
}

// parsePairingModeLine extracts the value from a grep match of the form
// `"pairing_mode": "gated"` (whitespace around the colon may vary) —
// mirrors parseMQTTClientIDLine's technique for a different key.
func parsePairingModeLine(line string) (string, error) {
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		return "", fmt.Errorf("could not parse pairing_mode from ocpp config line %q", line)
	}
	mode := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
	if mode == "" {
		return "", fmt.Errorf("empty pairing_mode parsed from ocpp config line %q", line)
	}
	return mode, nil
}

// ocppConfiguredStationIDs reads every configured station id from the
// deployed hub's ocpp.json over SSH. StationConfig.ID is the only "id" JSON
// field in cmd/ocpp's Config, so a flat grep across the whole file is safe.
func (d *mayhemDriver) ocppConfiguredStationIDs() ([]string, error) {
	out, err := d.hubSSHOutput(`grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/lexa/ocpp.json 2>/dev/null; true`)
	if err != nil {
		return nil, fmt.Errorf("read hub ocpp config over SSH: %w", err)
	}
	return parseConfiguredStationIDs(out), nil
}

// parseConfiguredStationIDs extracts every "id":"..." value from a grep -o
// dump (see ocppConfiguredStationIDs). Pure for unit testing.
func parseConfiguredStationIDs(out string) []string {
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		id := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// evStationID reads the ev sim's own reported station_id straight from
// /state (sim/evsim/state.go's EVState.StationID) — the identity the CSMS
// actually bridges against, independent of whatever ocpp.json's stations[]
// happens to list.
func (d *mayhemDriver) evStationID() (string, error) {
	var st struct {
		StationID string `json:"station_id"`
	}
	if err := d.getJSON("ev", "/state", &st); err != nil {
		return "", err
	}
	if st.StationID == "" {
		return "", fmt.Errorf("ev sim /state reported an empty station_id")
	}
	return st.StationID, nil
}

// evLastProfileLimitA reads the last SetChargingProfile amperage this
// station's evsim actually received on the wire, straight from /state's
// last_charging_profile.limit_A (sim/evsim/state.go's chargingProfileInfo)
// — recorded BEFORE evsim's own physical battery model floors any
// commandedA<=0 to "not charging" (battery.go's Tick). A hub bug that failed
// to clamp a discharge setpoint would be INVISIBLE in the physical current
// alone (evsim has no discharge model at all); this is the one signal that
// reflects what cmd/ocpp's bridge actually wrote to the wire. ok is false
// when no profile has been received yet, or the probe failed.
func (d *mayhemDriver) evLastProfileLimitA() (limitA float64, ok bool) {
	var st struct {
		LastProfile *struct {
			LimitA float64 `json:"limit_A"`
		} `json:"last_charging_profile"`
	}
	if err := d.getJSON("ev", "/state", &st); err != nil || st.LastProfile == nil {
		return 0, false
	}
	return st.LastProfile.LimitA, true
}

// gridsimAlertCount is cannotComplyCount's total-across-every-subject
// sibling: the raw length of gridsim's /admin/alerts, needed by
// diagnoseOpenADRBind to detect a CannotComply attributed to anything other
// than an active CSIP mRID (cannotComplyCount alone can only count entries
// for ONE specific mRID, and openadr-limit-adopt has none at all).
func (d *mayhemDriver) gridsimAlertCount() (int, error) {
	var out struct {
		Alerts []struct {
			Subject string `json:"subject"`
		} `json:"alerts"`
	}
	if err := d.getJSON("gridsim", "/admin/alerts", &out); err != nil {
		return 0, err
	}
	return len(out.Alerts), nil
}

// ── Reviewer merge instructions (docs/QA_STANDARDS_BUILDOUT.md's "Merge
//    discipline" — DO NOT self-apply; the reviewer wires these) ─────────────
//
// 1. In scenarios() (mayhem.go), alongside the existing
//    `sc = append(sc, d.mqttScenarios()...)` etc. lines, add:
//
//        sc = append(sc, d.ocppOpenADRScenarios()...)
//
// 2. This track's oracles are all Go-literal scenarios (not qa/scenarios/*.json
//    specs), so — matching the existing precedent of diagnoseEVFreeze/
//    diagnoseEVFlap/diagnoseEVUnits/every mqtt_scenarios.go and
//    mayhem_world.go oracle, none of which are registered — NO oracleRegistry
//    entry is required for the suite to build/run/pass go vet. If a future
//    spec-JSON scenario wants to select one of these oracles by name, add to
//    oracleRegistry (scenariospec.go):
//
//        "diagnoseOCPP16Obey":       {build: noParamOracle(...), requiresConstraint: true},   // needs a releaseAtS param — see buildDiagnoseSurvival for the pattern
//        "diagnoseOCPP16Release":    {build: noParamOracle(...), requiresConstraint: true},   // same
//        "diagnosePairingHold":      {build: noParamOracle(diagnosePairingHold), requiresConstraint: false},
//        "diagnoseEVSetpointClamp":  {build: noParamOracle(...), requiresConstraint: false},  // needs injectAtS/minProfileLimitA/sawProfileAfterInject params
//        "diagnoseOpenADRBind":      {build: noParamOracle(...), requiresConstraint: true},    // needs alertsBefore/alertsAfter/alertsOK params
//
//    (diagnoseOCPP16Obey/Release/EVSetpointClamp/OpenADRBind all take extra
//    closure state beyond (sc, cons, s) the same way diagnoseSurvival/
//    diagnoseDuplicateClientID/diagnoseMqttStorm do — noParamOracle does not
//    fit them directly; a parameterized build func à la buildDiagnoseSurvival
//    would be needed, and closure state captured at RUN time (SSH probes,
//    injected station IDs) has no obvious JSON param shape yet. Punted as a
//    follow-up, not attempted here.)
//
// Follow-up (not attempted here, scope explicitly called out in this
// session's task): a full end-to-end OpenADR scenario that actually wires
// lexa-openadr's vtn_url at sim/vtnsim and restarts the service needs (a) a
// "vtn" entry in main.go's mayhemDriver backends map, (b) an SSH-based
// config-patch-and-restart helper (mirroring the reconciler-flip discipline
// CLAUDE.md documents, or the hubSSH-based systemctl restarts
// mayhem_world.go already does for lexa-hub/lexa-modbus/lexa-northbound),
// and (c) launching sim/vtnsim itself somewhere reachable from the hub Pi
// (the desktop, alongside gridsim, is the natural home per
// netemDesktopIP's precedent). That would let a scenario exercise
// cmd/openadr's OWN polling/OAuth2/translate.go logic end-to-end rather than
// the hub-adoption-only slice these two scenarios cover.
