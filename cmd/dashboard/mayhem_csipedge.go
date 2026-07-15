// Track E — CSIP server-edge fault Mayhem scenarios and oracles (audit
// docs/QA_COMPLETENESS_AUDIT.md P1-2/P1-3/P2-4, Batch 2). New file per the
// existing "one track = one file, scenarios in a driver method, oracles in the
// same file" convention (mayhem_reporting.go / mayhem_adv.go /
// mayhem_ocpp_openadr.go).
//
// Covers three invariant families, all driven purely from gridsim admin knobs:
//
//	INV-EVENT-ACK    — the hub POSTs Superseded(7) when an overlapping event
//	                   with a later creationTime wins, and Cancelled(6) when the
//	                   server cancels a previously-received event (CORE-022/023).
//	                   The hub ALREADY does both (responses/tracker.go,
//	                   scheduler.SupersededMRIDs — verified in the audit); this
//	                   track's seams (widened /admin/control + /admin/responses)
//	                   let a bench scenario prove it end-to-end on the wire.
//	INV-RANDOMIZE    — the hub honors randomizeDuration (§11.10.4.2): its adopted
//	                   window length lands inside the legal [dur-|rand|, dur+|rand|]
//	                   band, not the raw dur and not something out of range.
//	INV-SURVIVE      — a hostile/sick CSIP server edge (410 Gone on a served
//	                   resource, a per-path serve delay, or a byte-slow
//	                   slow-loris body) must never unseat the safe control or
//	                   take the hub down: it holds last-known-good and /status
//	                   keeps answering (the audit's "hold LKG on a gone
//	                   resource" / read-deadline fail-closed path).
//
// Oracle registration: like every other mayhem_*.go track, these scenarios are
// Go literals whose oracles are wired directly via each scenario's `evaluate`
// field — NOT qa/scenarios/*.json specs — so no oracleRegistry entry is
// required (the registry is consulted only for JSON-spec scenarios, see
// scenariospec.go). Two of the five oracles (diagnoseCancelledSuperseded,
// diagnoseRandomizeDuration) fundamentally CANNOT be registry oracles: they
// judge per-run gridsim admin state (/admin/responses, /admin/status) captured
// into a closure by setup/teardown — the same closure-threading pattern
// der-report-roundtrip uses — which a stateless registry build() cannot supply.

package main

import (
	"fmt"
	"time"
)

// mRIDs the CSIP-edge scenarios stamp on their admin-injected controls, so the
// oracles can match the exact events they armed (never a bench-default control).
const (
	supersedeLoserMRID  = "DERC-SUP-LOSER"  // earlier creationTime + potentiallySuperseded ⇒ hub 7
	supersedeWinnerMRID = "DERC-SUP-WINNER" // later creationTime, overlapping ⇒ wins
	serverCancelMRID    = "DERC-CANCEL-ME"  // received, then flipped currentStatus→6 ⇒ hub 6
	randomizeMRID       = "DERC-RAND"       // carries randomizeDuration
)

// ── Track E scenario battery ─────────────────────────────────────────────────

func (d *mayhemDriver) csipEdgeScenarios() []*mayScenario {
	return []*mayScenario{
		cancelledSupersededScenario(),
		randomizeDurationScenario(),
		resource410Scenario(),
		eventDelayScenario(),
		slowLorisScenario(),
	}
}

// ── gridsim admin readbacks (thin local DTOs, like gridsimDERPuts) ────────────

// gridResponse mirrors sim/gridsim/admin.go's AdminResponse.
type gridResponse struct {
	Subject string `json:"subject"`
	Status  uint8  `json:"status"`
	LFDI    string `json:"lfdi"`
}

// gridsimResponses fetches every Response the hub has POSTed (all statuses,
// including the Cancelled(6)/Superseded(7) acks /admin/alerts omits).
func (d *mayhemDriver) gridsimResponses() ([]gridResponse, error) {
	var out struct {
		Responses []gridResponse `json:"responses"`
	}
	if err := d.getJSON("gridsim", "/admin/responses", &out); err != nil {
		return nil, err
	}
	return out.Responses, nil
}

// gridControl is the served window of one control, read from /admin/status —
// the randomizeDuration oracle needs the control's actual Start (server time)
// to turn the hub's reported validUntil into an honored window length.
type gridControl struct {
	MRID      string
	Start     int64
	DurationS int
}

func (d *mayhemDriver) gridsimControl(program int, mrid string) (gridControl, bool, error) {
	type gcCtrl struct {
		MRID      string `json:"mrid"`
		Start     int64  `json:"start"`
		DurationS int    `json:"duration_s"`
	}
	var out struct {
		Programs []struct {
			ID        int      `json:"id"`
			Active    []gcCtrl `json:"active"`
			Scheduled []gcCtrl `json:"scheduled"`
		} `json:"programs"`
	}
	if err := d.getJSON("gridsim", "/admin/status", &out); err != nil {
		return gridControl{}, false, err
	}
	for _, p := range out.Programs {
		if p.ID != program {
			continue
		}
		for _, c := range p.Active {
			if c.MRID == mrid {
				return gridControl{c.MRID, c.Start, c.DurationS}, true, nil
			}
		}
		for _, c := range p.Scheduled {
			if c.MRID == mrid {
				return gridControl{c.MRID, c.Start, c.DurationS}, true, nil
			}
		}
	}
	return gridControl{}, false, nil
}

// ── cancelled-superseded-roundtrip (INV-EVENT-ACK) ───────────────────────────

func cancelledSupersededScenario() *mayScenario {
	var resps []gridResponse
	var respErr error
	return &mayScenario{
		ID:         "cancelled-superseded-roundtrip",
		Name:       "Hub POSTs Superseded(7) then Cancelled(6) over the wire (CORE-022/023)",
		Category:   "CSIP events (INV-EVENT-ACK)",
		Hypothesis: "A utility server routinely supersedes one event with a higher-precedence overlapping one and cancels events outright. Per GEN.044/CORE-022/023 the DER client must acknowledge both: status=7 (superseded) for the event that lost to a later-created overlapping event in the same program, and status=6 (cancelled) for an event whose currentStatus the server flips to 6 after the client already received it. The hub's responses.Tracker + scheduler.SupersededMRIDs already implement both (audit P1-2); this drives them on the wire.",
		Expected:   "gridsim's /admin/responses shows a Response with status=7 subject=" + supersedeLoserMRID + " (the superseded loser) AND a Response with status=6 subject=" + serverCancelMRID + " (the server-cancelled event the hub had already received).",
		HoldS:      75,
		Fix:        "internal/northbound/responses/tracker.go's Update (Cancelled + Superseded passes); internal/northbound/scheduler.go's SupersededMRIDs/isSuperseded.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			// Benign env: a full battery + modest PV keeps every injected export
			// cap trivially met, so /admin/responses carries only the lifecycle
			// acks this oracle reads — no CannotComply noise.
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(1500, 250)

			// Supersede pair in program 0 (primacy 1 = highest priority, the only
			// program SupersededMRIDs considers): the LOSER (earlier creationTime,
			// potentiallySuperseded) and the WINNER (later creationTime), both
			// active and overlapping. creation_offset_s makes the ordering
			// deterministic without wall-clock spacing between the two POSTs.
			if _, err := d.postControl(map[string]any{
				"program": 0, "mrid": supersedeLoserMRID, "exp_lim_W": 3000,
				"duration_s": 300, "activate": true,
				"potentially_superseded": true, "creation_offset_s": -5,
				"description": "mayhem: superseded loser",
			}); err != nil {
				return nil, fmt.Errorf("arm supersede loser: %w", err)
			}
			if _, err := d.postControl(map[string]any{
				"program": 0, "mrid": supersedeWinnerMRID, "exp_lim_W": 2500,
				"duration_s": 300, "creation_offset_s": 0,
				"description": "mayhem: superseding winner",
			}); err != nil {
				return nil, fmt.Errorf("arm supersede winner: %w", err)
			}

			// Cancel target in program 1 (tracked by the hub's response state
			// machine but not enforced — it is lower priority). Post it now so the
			// hub RECEIVES it (posts 1), then flip its currentStatus→6 mid-hold:
			// the hub only acks a cancel it previously received (already-cancelled
			// events are dropped), which is why this must be a two-step.
			if _, err := d.postControl(map[string]any{
				"program": 1, "mrid": serverCancelMRID, "exp_lim_W": 4000,
				"duration_s": 300, "activate": true,
				"description": "mayhem: server-cancel target",
			}); err != nil {
				return nil, fmt.Errorf("arm cancel target: %w", err)
			}
			d.afterDelay(25*time.Second, func() {
				_, _ = d.postControl(map[string]any{
					"program": 1, "mrid": serverCancelMRID, "current_status": 6,
					"exp_lim_W": 4000, "duration_s": 300,
					"description": "mayhem: server-cancel target (cancelled)",
				})
			})
			return nil, nil
		},
		perTick: func(d *mayhemDriver, i int) { d.injectEnv(1500, 250) },
		evaluate: func(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
			return diagnoseCancelledSuperseded(sc, s, resps, respErr)
		},
		teardown: func(d *mayhemDriver) {
			resps, respErr = d.gridsimResponses()
			d.deleteControls(0)
			d.deleteControls(1)
		},
	}
}

func diagnoseCancelledSuperseded(sc *mayScenario, s []maySample, resps []gridResponse, fetchErr error) mayFinding {
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
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "hub /status was unreachable for most of the window"
		f.Diagnosis = []string{"Cannot judge event-ack emission when the hub itself was mostly unreachable — fix connectivity and re-run."}
		return f
	}
	if fetchErr != nil {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "gridsim /admin/responses was unreachable — cannot verify 6/7 emission"
		f.Diagnosis = []string{fmt.Sprintf("GET /admin/responses failed: %v", fetchErr)}
		return f
	}

	sawSuperseded, sawCancelled := false, false
	for _, r := range resps {
		if r.Status == 7 && r.Subject == supersedeLoserMRID {
			sawSuperseded = true
		}
		if r.Status == 6 && r.Subject == serverCancelMRID {
			sawCancelled = true
		}
	}

	supLine := fmt.Sprintf("Superseded(7) for %s: %s", supersedeLoserMRID, okOrMissing(sawSuperseded))
	canLine := fmt.Sprintf("Cancelled(6) for %s: %s", serverCancelMRID, okOrMissing(sawCancelled))

	switch {
	case sawSuperseded && sawCancelled:
		f.Verdict = "PASS"
		f.Headline = "hub acknowledged both the supersede (7) and the cancel (6) over the wire"
		f.Diagnosis = []string{
			"INV-EVENT-ACK: the hub POSTed both server-driven lifecycle acks (CORE-022/023).",
			supLine, canLine,
		}
	case !sawSuperseded && !sawCancelled:
		f.Verdict = "FAIL"
		f.Headline = "hub POSTed neither Superseded(7) nor Cancelled(6)"
		f.Diagnosis = []string{
			"The hub never acknowledged the superseded loser OR the server-cancelled event — CORE-022/023 lifecycle acks are not reaching the server.",
			supLine, canLine,
			respVocabLine(resps),
		}
	case !sawSuperseded:
		f.Verdict = "FAIL"
		f.Headline = "hub cancelled (6) but never posted Superseded(7)"
		f.Diagnosis = []string{
			"The server-cancel was acknowledged but the within-program supersede was not — scheduler.SupersededMRIDs never flagged the loser, or the tracker never emitted 7.",
			supLine, canLine,
			respVocabLine(resps),
		}
	default:
		f.Verdict = "FAIL"
		f.Headline = "hub superseded (7) but never posted Cancelled(6)"
		f.Diagnosis = []string{
			"The supersede was acknowledged but the server-cancel was not — the tracker's Cancelled pass never fired for a previously-received event flipped to currentStatus=6.",
			supLine, canLine,
			respVocabLine(resps),
		}
	}
	return f
}

// ── randomize-duration-honored (INV-RANDOMIZE) ───────────────────────────────

func randomizeDurationScenario() *mayScenario {
	const baseDurS = 240
	const randDurS = -60 // magnitude 60s (the value's sign is irrelevant; §11.10.4.2)
	var ctrl gridControl
	var ctrlErr error
	return &mayScenario{
		ID:         "randomize-duration-honored",
		Name:       "Hub honors randomizeDuration within the legal window band (CORE-021)",
		Category:   "CSIP events (INV-RANDOMIZE)",
		Hypothesis: "Utilities set randomizeDuration to stagger DER event windows and avoid a synchronised fleet edge. Per §11.10.4.2 the client jitters the event's duration by a per-event random offset in [-|rand|, +|rand|]. The hub consumes it (scheduler.randomizedDuration, cached per mRID — audit P1-3) but no bench scenario ever served a nonzero randomizeDuration to prove it end-to-end.",
		Expected:   fmt.Sprintf("The hub adopts %s and its reported validUntil implies an honored window length inside the legal band [%d, %d] s (base %d ± |rand| %d) — never the raw %d with no jitter possibility exceeded, and never an out-of-band/negative window.", randomizeMRID, baseDurS-60, baseDurS+60, baseDurS, 60, baseDurS),
		HoldS:      75,
		Fix:        "internal/northbound/scheduler.go's randomizedDuration (§11.10.4.2 duration jitter, clamped ≥0, cached per mRID).",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(1500, 250) // cap non-binding: the hub adopts it without needing to curtail
			mrid, err := d.postControl(map[string]any{
				"program": 0, "mrid": randomizeMRID, "exp_lim_W": 4000,
				"duration_s": baseDurS, "activate": true,
				"randomize_duration": randDurS,
				"description":        "mayhem: randomizeDuration honored",
			})
			if err != nil {
				return nil, fmt.Errorf("arm randomized control: %w", err)
			}
			// Capture the control's actual Start (server time) so the oracle can
			// turn the hub's validUntil into an honored duration.
			ctrl, _, ctrlErr = d.gridsimControl(0, mrid)
			return nil, nil
		},
		perTick: func(d *mayhemDriver, i int) { d.injectEnv(1500, 250) },
		evaluate: func(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
			return diagnoseRandomizeDuration(sc, s, ctrl, ctrlErr, baseDurS, randDurS)
		},
		teardown: func(d *mayhemDriver) { d.deleteControls(0) },
	}
}

func diagnoseRandomizeDuration(sc *mayScenario, s []maySample, ctrl gridControl, ctrlErr error, baseDurS, randDurS int) mayFinding {
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
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "hub /status was unreachable for most of the window"
		return f
	}
	if ctrlErr != nil || ctrl.Start == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "could not read the served control's start from gridsim /admin/status"
		if ctrlErr != nil {
			f.Diagnosis = []string{fmt.Sprintf("GET /admin/status failed: %v", ctrlErr)}
		} else {
			f.Diagnosis = []string{"gridsim /admin/status returned no start for " + randomizeMRID + " — the control was not served as expected."}
		}
		return f
	}

	// The hub caches one duration offset per mRID, so every sample that has
	// adopted this control agrees on validUntil — take the first.
	honored := int64(-1)
	for _, smp := range s {
		if smp.AdoptedMRID == randomizeMRID && smp.ValidUntil > 0 {
			honored = smp.ValidUntil - ctrl.Start
			break
		}
	}
	if honored < 0 {
		f.Verdict = "FAIL"
		f.Headline = "hub never adopted the randomized control / never reported a validUntil"
		f.Diagnosis = []string{
			fmt.Sprintf("No sample shows the hub adopting %s with a validUntil — it either never walked the control or discarded it. A randomizeDuration must not prevent adoption.", randomizeMRID),
			decisionLine(s),
		}
		return f
	}

	mag := int64(randDurS)
	if mag < 0 {
		mag = -mag
	}
	const tolS = 10 // clock-derivation slop between gridsim server time and the hub's /tm-derived view
	lo := int64(baseDurS) - mag - tolS
	hi := int64(baseDurS) + mag + tolS
	if honored < lo || honored > hi {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("honored window %ds is outside the legal randomizeDuration band [%d, %d]s", honored, int64(baseDurS)-mag, int64(baseDurS)+mag)
		f.Diagnosis = []string{
			fmt.Sprintf("Served base duration %ds, randomizeDuration ±%ds ⇒ the hub's effective window must land in [%d, %d]s; it reported %ds (validUntil − start). Off-band means randomizeDuration was mishandled (e.g. treated as an absolute window, applied twice, or produced a negative/clamped-wrong length).", baseDurS, mag, int64(baseDurS)-mag, int64(baseDurS)+mag, honored),
			decisionLine(s),
		}
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "hub's honored window respects the randomizeDuration band"
	diag := []string{
		fmt.Sprintf("INV-RANDOMIZE: the hub adopted %s and honored a %ds window — inside the legal band [%d, %d]s for base %ds ± %ds.", randomizeMRID, honored, int64(baseDurS)-mag, int64(baseDurS)+mag, baseDurS, mag),
	}
	if honored == int64(baseDurS) {
		diag = append(diag, "The offset this run rounded to ~0 (the hub's per-mRID random draw) or randomizeDuration was not applied; either way the window is legal. The band check cannot distinguish those two — a nonzero offset on another run positively confirms consumption.")
	} else {
		diag = append(diag, fmt.Sprintf("The window differs from the raw base by %ds — positive proof the hub applied the randomizeDuration offset rather than ignoring it.", honored-int64(baseDurS)))
	}
	f.Diagnosis = diag
	return f
}

// ── resource-410-failclosed / csip-event-delay / csip-slow-loris (INV-SURVIVE) ─

func resource410Scenario() *mayScenario {
	return edgeFaultScenario(
		"resource-410-failclosed",
		"A 410 Gone on a served CSIP resource must not unseat the safe control",
		"A utility server can answer 410 Gone — 'this resource is permanently gone' — for a resource the hub walks (here /dcap, the walk root). A 410 is a stronger signal than the 503 an outage serves: a hub that special-cases it as 'the resource was deleted, drop my state' fails open. The hub's fail-closed walk discipline (internal/northbound rule 6) must instead HOLD last-known-good.",
		"The walk fails closed on the 410: the active export cap keeps being enforced and /status keeps answering throughout — no unseat, no crash.",
		func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/gone", map[string]any{"path": "/dcap", "count": -1})
		},
		func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/gone", map[string]any{"clear": true})
		},
		diagnoseResource410,
	)
}

func eventDelayScenario() *mayScenario {
	return edgeFaultScenario(
		"csip-event-delay",
		"A slow (delayed) resource must not wedge the walk or drop the safe control",
		"A wedged/overloaded head-end can serve the right bytes LATE. gridsim delays /dcap by 20s per GET (still a correct 200, just slow). A hub whose fetcher has no per-request deadline wedges the whole northbound; a hub that bounds its reads either completes the slow walk or times out and holds last-known-good. Either way it must stay up and keep the safe cap.",
		"The hub tolerates the serve delay: /status keeps answering and the active export cap is never unseated across the slow walks.",
		func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/delay", map[string]any{"path": "/dcap", "delay_ms": 20000, "duration_s": 90})
		},
		func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/delay", map[string]any{"clear": true})
		},
		diagnoseEventDelay,
	)
}

func slowLorisScenario() *mayScenario {
	return edgeFaultScenario(
		"csip-slow-loris",
		"A byte-slow (slow-loris) response body must trip the read deadline, not wedge the hub",
		"A sick server (or a black-holing middlebox) can trickle a response body a few bytes at a time, holding the connection open indefinitely. gridsim's OutageSlow drips its body over ~12s. The hub's read/response deadline (internal/tlsclient, audit says already bounded) must fire and fail the walk closed rather than let a fetcher block forever.",
		"The slow-loris trickle never wedges the hub: /status keeps answering and the active export cap is held (re-enforced from last-known-good) across the byte-slow walks.",
		func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/outage", map[string]any{"mode": "slow", "hang_s": 12, "duration_s": 90})
		},
		func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/outage", map[string]any{"clear": true})
		},
		diagnoseSlowLoris,
	)
}

// edgeFaultScenario builds one INV-SURVIVE scenario: adopt a safe zero-export
// cap (battery full ⇒ PV curtailment is the only lever, isolating the fault's
// effect on the cap), then — once THAT cap is adopted, not merely the
// ever-present bench default — arm the server-edge fault for the rest of the
// hold. Shared by the 410 / delay / slow-loris scenarios; each supplies its own
// arm/clear closures and diagnose* oracle. Same shape as reportingScenarios'
// redirectScenario, whose survival bar these mirror.
func edgeFaultScenario(id, name, hypothesis, expected string, arm, clear func(*mayhemDriver), oracle evaluateFn) *mayScenario {
	return &mayScenario{
		ID:         id,
		Name:       name,
		Category:   "CSIP server-edge robustness (INV-SURVIVE)",
		Hypothesis: hypothesis,
		Expected:   expected,
		HoldS:      75,
		Fix:        "internal/northbound/run.RunOnce's fail-closed walk-error hold (holds last-known-good on a walk error); internal/tlsclient read/response deadlines.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(d.pvHighW, 250)
			cons, err := d.postCap("exportCap", 0, 75, "mayhem: safe export cap then "+id)
			if err != nil {
				return nil, err
			}
			d.armAfterCapAdopted(cons.Typ, cons.LimW, 2*time.Second, 60*time.Second, func() { arm(d) })
			return cons, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: oracle,
		teardown: func(d *mayhemDriver) {
			clear(d)
			d.deleteControls(0)
		},
	}
}

func diagnoseResource410(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	return edgeSurvivalFinding(sc, cons, s, "the 410 Gone on /dcap",
		"internal/northbound/run.RunOnce must treat a 410 like any other walk error and hold last-known-good, not drop the adopted control.")
}

func diagnoseEventDelay(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	return edgeSurvivalFinding(sc, cons, s, "the per-path serve delay",
		"internal/tlsclient must bound each request with a read deadline so a slow resource cannot wedge the walk; internal/northbound/run holds last-known-good on the resulting timeout.")
}

func diagnoseSlowLoris(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	return edgeSurvivalFinding(sc, cons, s, "the slow-loris trickle",
		"internal/tlsclient's response read deadline must fire on a byte-slow body; internal/northbound/run holds last-known-good on the failed walk.")
}

// edgeSurvivalFinding is the shared INV-SURVIVE oracle: the hub must stay
// reachable and keep enforcing the safe export cap through the server-edge
// fault. Same reachability-then-cap-held shape diagnoseRedirectSurvival uses
// (mayhem_reporting.go) for the analogous "hostile/buggy CSIP behaviour must be
// contained" pattern — with edge-fault-specific messaging. A CannotComply never
// excuses a breach here: this is a zero-export cap the hub can always meet by
// curtailing PV (battery held full), so a sustained breach means the fault
// unseated or corrupted the safe control.
func edgeSurvivalFinding(sc *mayScenario, cons *activeConstraint, s []maySample, faultLabel, fix string) mayFinding {
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
		f.Headline = "hub stopped responding under " + faultLabel
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples after %s was armed — a likely panic, hang, or walker deadlock.", len(s)-reach, len(s), faultLabel),
			"A misbehaving/sick CSIP server edge must never be able to take the hub down.",
			decisionLine(s),
		}
		f.Fix = fix
		return f
	}

	f.Metrics = scanSamples(cons, s)
	breaches := invExport(cons, s)
	if len(breaches) == 0 {
		f.Verdict = "PASS"
		f.Headline = "stayed up and kept enforcing the safe cap across " + faultLabel
		f.Diagnosis = []string{
			"The hub stayed up (/status kept answering) and kept enforcing the active export cap across " + faultLabel + ".",
			invSummaryLine("INV-EXPORT", breaches),
			hubVsRealLine(s),
		}
		forceBlindOnConstraintProbeGap(&f, cons, s)
		return f
	}
	if f.Metrics.TailClean {
		f.Verdict = "DEGRADED"
		f.Headline = "transiently dropped the safe cap under " + faultLabel + ", then recovered"
		f.Diagnosis = []string{
			invSummaryLine("INV-EXPORT", breaches),
			faultLabel + " briefly unseated the active export cap (the inverter exported over it) but the hub re-established the cap before the end of the window.",
			hubVsRealLine(s),
		}
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = faultLabel + " unseated the safe control"
	f.Diagnosis = []string{
		invSummaryLine("INV-EXPORT", breaches),
		faultLabel + " was served while a safe export cap was active, and the cap stayed breached through the end of the window instead of holding last-known-good.",
		decisionLine(s),
	}
	f.Fix = fix
	return f
}

// ── small oracle helpers ─────────────────────────────────────────────────────

func okOrMissing(ok bool) string {
	if ok {
		return "seen"
	}
	return "MISSING"
}

// respVocabLine summarises the statuses actually recorded, so a FAIL says what
// the hub DID post instead of the expected 6/7.
func respVocabLine(resps []gridResponse) string {
	if len(resps) == 0 {
		return "gridsim /admin/responses recorded no Response POSTs at all for this run — the hub may not have walked the injected controls."
	}
	counts := map[uint8]int{}
	for _, r := range resps {
		counts[r.Status]++
	}
	return fmt.Sprintf("Response statuses gridsim recorded this run: %s.", statusCounts(counts))
}

func statusCounts(counts map[uint8]int) string {
	var parts []string
	for _, st := range []uint8{1, 2, 3, 6, 7, 8, 10, 240} {
		if n := counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%dx status=%d", n, st))
		}
	}
	if len(parts) == 0 {
		return "(none in the tracked set)"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}
