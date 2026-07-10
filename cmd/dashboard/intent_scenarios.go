package main

// Intent/mode/scan Mayhem scenarios (extension campaign Batch G, units 8.2/8.3/
// 8.4 — DEVICE_ROADMAP §3/§4/§5). These validate the on-hub cloud-goal surface
// that landed in lexa-hub's extension campaign (units 3.3 intentAdopter, 3.4
// modeManager, 4.3 lexa-api /mode + /scan, 5.2 lexa-modbus scan controller):
// the hub must ride a plan-author mode flip mid-event and mid-fault without ever
// dropping a safety cap or the plan heartbeat, must refuse a commissioning scan
// while reconcilers are live, and must survive an intent flood without a wedge,
// a watchdog kill, or a journald flash storm.
//
// Injection path (matches house precedent, corrupted-retained-control /
// mqtt-stale-retained): every intent/scan message is forged straight onto the
// real broker via mqttproxy /inject (d.mqttInject) — the same way the bench
// injects a retained lexa/csip/control today. That is deliberately NOT the
// lexa-api POST /intent path: these scenarios test the hub's RAW bus adoption
// (the retained-redelivery + boot-reseed contract, DEVICE_ROADMAP §3.1), not
// the authenticated HTTP front door, and forging on the bus is the only way to
// reproduce a cloud/app publishing directly (or a stale retained goal surviving
// a broker restart). mqttproxy /inject authenticates as the qa-inject broker
// user (TASK-013), so an un-provisioned bench fails setup to INCONCLUSIVE
// rather than silently no-opping — same as every other mqtt-* scenario.
//
// Observability (all read-only, no new hub surface): the plan-author mode is
// read from lexa-api GET /mode (retained lexa/hub/mode) and the
// lexa_hub_mode_gateway metric; the refused ScanStatus from lexa-api GET /scan
// (the api's scan-status ring, fed by lexa-modbus's non-retained
// lexa/scan/status); intents-applied / tick-overrun counters from the hub
// /metrics scrape (readMetricCounter); mode_change + service_start events and
// journald growth from the hub over SSH; IntentResults counted with a
// bounded mosquitto_sub over SSH (qa-inject creds, same as
// brokerRetainedControlCommand). Where a signal is unavailable the diagnosers
// note it INCONCLUSIVE rather than manufacturing a PASS out of silence — the
// duplicate-client-id detection-half precedent.

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bus topics these scenarios forge onto. Mirrors lexa-hub internal/bus's
// TopicIntentMode/TopicIntentReserve/TopicScanRequest exactly (kept as local
// consts, like topicCSIPControl in mqtt_scenarios.go — the bench deliberately
// does not import the product's internal/bus package).
const (
	topicIntentMode    = "lexa/intent/mode"
	topicIntentReserve = "lexa/intent/reserve"
	topicScanRequest   = "lexa/scan/request"
)

// hubJournalGlob is the on-hub NDJSON event-journal glob (lexa-hub
// configs/hub.json: "dir":"/var/lib/lexa/journal/hub"; the active file is
// journal.ndjson, rotated siblings share the .ndjson suffix). The file is
// 0644 (world-readable), so a plain grep over SSH needs no sudo. Used to count
// transition events (mode_change, service_start) — journal Events are
// transitions only, so a delta across a scenario is exactly the transitions
// that scenario caused.
const hubJournalGlob = "/var/lib/lexa/journal/hub/*.ndjson"

// reserveFloorPct is the reserve_pct the intent-flood scenario injects: the
// hub clamps a reserve intent UP to its configured safety floor and intents
// may only RAISE it (intent.go applyReserve), so injecting the conventional
// 20% floor means the 50 retained goals left on the bus at teardown are a
// no-op for any later scenario/restart — no cross-scenario contamination.
const reserveFloorPct = 20.0

// ── Payload builders (pure; unit-tested) ─────────────────────────────────────

// mayhemIntentID mints a per-injection unique IntentMeta.ID so the hub's
// retained-redelivery dedupe (intentAdopter.lastID, keyed on ID) does NOT
// collapse successive injections into one — every flip / flood entry must be a
// genuinely NEW id to be applied, not a "duplicate" no-op.
func mayhemIntentID(prefix string, n int) string {
	return fmt.Sprintf("mayhem-%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

// modeIntentPayload builds a lexa/intent/mode wire payload (bus.ModeIntent):
// Envelope "v":1 (born-at-1, survives the AD-006 legacy-v0 enforcement flip),
// IntentMeta inline, mode ∈ {optimizer, gateway}.
func modeIntentPayload(mode, id string, issuedAt int64) string {
	return fmt.Sprintf(`{"v":1,"id":%q,"origin":"cloud","actor":"mayhem","issued_at":%d,"mode":%q}`,
		id, issuedAt, mode)
}

// reserveIntentPayload builds a lexa/intent/reserve wire payload
// (bus.BackupReserveIntent). reserve_pct is a *float64 on the wire (never NaN);
// a plain number is what the hub's Finite() gate accepts.
func reserveIntentPayload(pct float64, id string, issuedAt int64) string {
	return fmt.Sprintf(`{"v":1,"id":%q,"origin":"cloud","actor":"mayhem","issued_at":%d,"reserve_pct":%g}`,
		id, issuedAt, pct)
}

// scanRequestPayload builds a lexa/scan/request wire payload (bus.ScanRequest).
// Every field but id/ts is optional (lexa-modbus applies its own "empty = local
// /24, default bauds/unit IDs" fallback) — but on a LIVE hub with active
// reconcilers the request is refused before any of that matters (§5.2 arming
// rule), which is the whole point.
func scanRequestPayload(id string, ts int64) string {
	return fmt.Sprintf(`{"v":1,"id":%q,"ts":%d}`, id, ts)
}

// ── SSH command builders (pure; unit-tested — mirror brokerSnapshotCommand's
// shape so the remote command is auditable without a live bench) ─────────────

// journalEventCountCommand counts NDJSON journal Events of one type across the
// hub's journal (active + rotated). `grep -c` on the concatenated stream prints
// a single number; `; true` swallows grep's exit-1 on zero matches so the SSH
// call does not error on a clean journal.
func journalEventCountCommand(eventType string) string {
	return fmt.Sprintf(`cat %s 2>/dev/null | grep -c '"type":"%s"' ; true`, hubJournalGlob, eventType)
}

// journaldLinesSinceCommand counts journald lines for lexa-hub since a Unix
// epoch (the `@<seconds>` --since form journalctl accepts — no whitespace, so
// no remote-quoting hazard). sudo per the brokerRetainedControlCommand
// precedent (journald reads need privilege for a non-journal-group user).
func journaldLinesSinceCommand(unit string, sinceUnix int64) string {
	return fmt.Sprintf(`sudo journalctl -u %s --since @%d --no-pager -q 2>/dev/null | wc -l`, unit, sinceUnix)
}

// intentResultSubCommand builds the bounded mosquitto_sub that COUNTS
// lexa/intent/result messages of one kind over durationS seconds. Authenticates
// as qa-inject (TASK-013, same creds as brokerRetainedControlCommand); a
// missing credential file fails loud (exit 1 ⇒ the scenario notes detection
// INCONCLUSIVE) rather than silently counting zero. `timeout` bounds the sub so
// it self-terminates even if teardown is skipped; `grep -c` counts only the
// requested kind, ignoring any unrelated result traffic on the shared topic.
func intentResultSubCommand(kind string, durationS int) string {
	return fmt.Sprintf(
		`PASS=$(sudo cat %s 2>/dev/null); if [ -z "$PASS" ]; then echo "qa-inject credentials not provisioned (run scripts/mqtt-chaos.sh deploy)" >&2; exit 1; fi; timeout %d mosquitto_sub -h localhost -p 1883 -u qa-inject -P "$PASS" -t lexa/intent/result 2>/dev/null | grep -c '"kind":"%s"' ; true`,
		qaInjectPassFile, durationS, kind)
}

// retainedBatteryDesiredCommand reads back the first retained
// lexa/desired/battery/{device} document (the standing battery intent the
// reconciler reasserts on reconnect, AD-013). Wildcard `+` so the bench need
// not know the pack's device name; `-C 1` returns the single retained doc.
// Empty output ⇒ no standing battery desired doc on the bus.
func retainedBatteryDesiredCommand() string {
	return fmt.Sprintf(
		`PASS=$(sudo cat %s 2>/dev/null); if [ -z "$PASS" ]; then echo "qa-inject credentials not provisioned" >&2; exit 1; fi; timeout 4 mosquitto_sub -h localhost -p 1883 -u qa-inject -P "$PASS" -C 1 -t 'lexa/desired/battery/+' 2>/dev/null ; true`,
		qaInjectPassFile)
}

// parseCount trims and parses a bare integer line (grep -c / wc -l output).
// Pulled out so the SSH plumbing is unit-testable without a live bench, same
// as parseMQTTClientIDLine / parseRetainedExpLimW.
func parseCount(out string) (int, bool) {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(f[len(f)-1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// ── Driver observation helpers ───────────────────────────────────────────────

// hubMode reads the hub's authoritative plan-author mode from lexa-api GET
// /mode (retained lexa/hub/mode, DEVICE_ROADMAP §4.3). ok=false on the 503
// {"error":"unknown"} the endpoint returns before the first ModeStatus, or on
// any transport error — a caller must not treat "unknown" as a mode reading.
func (d *mayhemDriver) hubMode() (mode string, ok bool) {
	var resp struct {
		Mode string `json:"mode"`
	}
	if err := d.getJSON("hub", "/mode", &resp); err != nil {
		return "", false
	}
	return resp.Mode, resp.Mode != ""
}

// hubPlanHeartbeat reads plan_heartbeat.state from lexa-api GET /status
// (TASK-045: "never" | "ok" | "stalled"). ok=false on transport error or an
// absent field.
func (d *mayhemDriver) hubPlanHeartbeat() (state string, ok bool) {
	var resp struct {
		PlanHeartbeat struct {
			State string `json:"state"`
		} `json:"plan_heartbeat"`
	}
	if err := d.getJSON("hub", "/status", &resp); err != nil {
		return "", false
	}
	return resp.PlanHeartbeat.State, resp.PlanHeartbeat.State != ""
}

// scanRefusedFor polls lexa-api GET /scan (the scan-status ring fed by
// lexa-modbus's non-retained lexa/scan/status) for a "refused" phase matching
// id. ok=false means the /scan endpoint was unreachable (detection
// INCONCLUSIVE, never "not refused").
func (d *mayhemDriver) scanRefusedFor(id string) (refused, ok bool) {
	var resp struct {
		Status []struct {
			ID    string `json:"id"`
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if err := d.getJSON("hub", "/scan", &resp); err != nil {
		return false, false
	}
	for _, st := range resp.Status {
		if st.Phase == "refused" && (id == "" || st.ID == id) {
			return true, true
		}
	}
	return false, true
}

// journalEventCount returns how many NDJSON Events of eventType the hub journal
// holds right now. A delta across a scenario window is the transitions that
// scenario caused (mode_change ×2 for a there-and-back flip; service_start >0
// means the hub restarted mid-scenario).
func (d *mayhemDriver) journalEventCount(eventType string) (int, bool) {
	out, err := d.hubSSHOutput(journalEventCountCommand(eventType))
	if err != nil {
		return 0, false
	}
	return parseCount(out)
}

// journaldLinesSince counts journald lines emitted by unit since sinceUnix.
func (d *mayhemDriver) journaldLinesSince(unit string, sinceUnix int64) (int, bool) {
	out, err := d.hubSSHOutput(journaldLinesSinceCommand(unit, sinceUnix))
	if err != nil {
		return 0, false
	}
	return parseCount(out)
}

// hubUnix reads the hub Pi's wall clock (for a --since anchor).
func (d *mayhemDriver) hubUnix() (int64, bool) {
	out, err := d.hubSSHOutput("date +%s")
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// countReserveIntentResults runs the bounded mosquitto_sub and returns how many
// reserve IntentResults it saw. ok=false ⇒ creds missing / SSH down (detection
// INCONCLUSIVE).
func (d *mayhemDriver) countReserveIntentResults(durationS int) (int, bool) {
	out, err := d.hubSSHOutput(intentResultSubCommand("reserve", durationS))
	if err != nil {
		return 0, false
	}
	return parseCount(out)
}

// retainedBatteryDesiredPresent reports whether a retained
// lexa/desired/battery/{device} document exists on the bus (standing intent the
// reconciler reasserts on reconnect). ok=false ⇒ creds missing / SSH down.
func (d *mayhemDriver) retainedBatteryDesiredPresent() (present, ok bool) {
	out, err := d.hubSSHOutput(retainedBatteryDesiredCommand())
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(out) != "", true
}

// injectModeIntent / injectReserveIntent / injectScanRequest forge one message
// onto the broker via mqttproxy /inject, logging (never swallowing) an error so
// an undeployed proxy is visible, matching corrupted-retained-control's
// mqttInject error handling.
func (d *mayhemDriver) injectModeIntent(mode, id string, retain bool) {
	if err := d.mqttInject(topicIntentMode, modeIntentPayload(mode, id, time.Now().Unix()), retain); err != nil {
		log.Printf("mayhem: inject mode intent (%s): %v", mode, err)
	}
}

func (d *mayhemDriver) injectReserveIntent(pct float64, id string) {
	if err := d.mqttInject(topicIntentReserve, reserveIntentPayload(pct, id, time.Now().Unix()), true); err != nil {
		log.Printf("mayhem: inject reserve intent (%s): %v", id, err)
	}
}

func (d *mayhemDriver) injectScanRequest(id string) {
	if err := d.mqttInject(topicScanRequest, scanRequestPayload(id, time.Now().Unix()), false); err != nil {
		log.Printf("mayhem: inject scan request (%s): %v", id, err)
	}
}

// ── Diagnosers (pure; unit-tested with synthetic obs + samples) ──────────────

// modeFlipObs is the impure signal a mode-flip scenario captures during its run
// (GET /mode + metric during the gateway window, journal delta, heartbeat) and
// hands to diagnoseModeFlipUnderEvent. Separated from the samples so the
// verdict logic stays pure and testable, exactly like diagnoseDuplicateClientID.
type modeFlipObs struct {
	gatewaySeen          bool // GET /mode read "gateway" during the gateway window
	optimizerRestored    bool // GET /mode read "optimizer" after the flip-back
	gatewayMetricSeen    bool // lexa_hub_mode_gateway == 1 during the window
	metricOK             bool // the metric scrape worked at least once
	heartbeatSeen        bool // plan_heartbeat was readable at least once
	heartbeatEverStalled bool // plan_heartbeat ever read "stalled"
	modeChangeDelta      int  // mode_change journal Events during the scenario
	journalOK            bool // the journal read worked
}

// modeDetectionLines renders the shared "what did we actually observe about the
// flip" diagnosis bullets for both mode-flip scenarios.
func modeDetectionLines(o modeFlipObs) []string {
	var out []string
	switch {
	case o.gatewaySeen && o.optimizerRestored:
		out = append(out, "Mode flip observed both ways: GET /mode read \"gateway\" during the window and \"optimizer\" after the flip-back.")
	case o.gatewaySeen:
		out = append(out, "GET /mode read \"gateway\" during the window but the optimizer restore was not confirmed on /mode.")
	default:
		out = append(out, "GET /mode never read \"gateway\" during the window — the flip may not have engaged (or /mode was unavailable).")
	}
	if o.metricOK {
		if o.gatewayMetricSeen {
			out = append(out, "lexa_hub_mode_gateway read 1 during the window — the engine routed to the gateway author.")
		} else {
			out = append(out, "lexa_hub_mode_gateway stayed 0 during the window — the engine never routed to the gateway author.")
		}
	} else {
		out = append(out, "detection INCONCLUSIVE: lexa_hub_mode_gateway not scrapable (TASK-044 metrics not deployed on this bench).")
	}
	if o.journalOK {
		out = append(out, fmt.Sprintf("%d mode_change journal event(s) recorded during the scenario (a there-and-back flip should log 2).", o.modeChangeDelta))
	} else {
		out = append(out, "detection INCONCLUSIVE: hub event journal not readable over SSH — mode_change events unconfirmed.")
	}
	if o.heartbeatSeen {
		if o.heartbeatEverStalled {
			out = append(out, "plan heartbeat read \"stalled\" at least once during the flips — the control loop lagged across the mode switch.")
		} else {
			out = append(out, "plan heartbeat never stalled across either flip.")
		}
	} else {
		out = append(out, "detection INCONCLUSIVE: plan_heartbeat not readable — heartbeat continuity unconfirmed.")
	}
	return out
}

// diagnoseModeFlipUnderEvent is unit 8.3's oracle for mode-flip-under-active-
// event: the export cap is the hard gate (INV-EXPORT must hold across BOTH
// flips beyond the normal convergence budget), heartbeat continuity and the
// mode-flip evidence are surfaced but degrade rather than fabricate a PASS when
// a detection signal is missing (duplicate-client-id precedent). SAFETY
// invariants are added by the run loop's applySafetyAudit.
func diagnoseModeFlipUnderEvent(o modeFlipObs) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := baseFinding(sc)
		if len(s) == 0 {
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "no samples collected (aborted before any reading)"
			return f
		}
		f.Metrics = scanSamples(cons, s)
		breaches := invExport(cons, s)
		det := modeDetectionLines(o)

		switch {
		case len(breaches) > 0:
			f.Verdict = "FAIL"
			f.Headline = "export cap breached during a plan-author mode flip"
			f.Diagnosis = append([]string{
				invSummaryLine("INV-EXPORT", breaches),
				"A mode flip must never open the export cap — the compliance constraints run in BOTH authors, so a breach here means the flip dropped enforcement.",
				hubVsRealLine(s), decisionLine(s),
			}, det...)
			return f
		case o.heartbeatSeen && o.heartbeatEverStalled:
			f.Verdict = "DEGRADED"
			f.Headline = "cap held across the flips, but the plan heartbeat stalled during the mode switch"
			f.Diagnosis = append([]string{
				invSummaryLine("INV-EXPORT", nil),
				"The cap held, but the control loop's heartbeat went stale across a flip — the switch cost the loop a beat it should not have.",
			}, det...)
			return f
		case o.journalOK && o.modeChangeDelta == 0 && !o.gatewaySeen:
			f.Verdict = "DEGRADED"
			f.Headline = "cap held, but the mode flip never engaged (no mode_change, gateway never observed)"
			f.Diagnosis = append([]string{
				invSummaryLine("INV-EXPORT", nil),
				"The injected mode intent produced no mode_change event and /mode never read gateway — the scenario could not exercise the flip (confirm units 3.3/3.4 are deployed and the mode subscribe is wired).",
			}, det...)
			return f
		default:
			f.Verdict = "PASS"
			f.Headline = "export cap held across the gateway flip and back; heartbeat never stalled"
			f.Diagnosis = append([]string{
				invSummaryLine("INV-EXPORT", nil),
				"The zero-export cap held beyond the settling budget through both flips (optimizer→gateway→optimizer) — the utility control survived the plan-author switch.",
			}, det...)
			return f
		}
	}
}

// modeFlipFaultObs adds the fault-specific signals (pack recovery + standing
// desired doc) to the mode-flip observation set.
type modeFlipFaultObs struct {
	modeFlipObs
	desiredDocPresent bool // retained lexa/desired/battery/+ present at teardown
	desiredReadOK     bool // the retained read worked
	packRecovered     bool // hub read a coherent battery SoC after the fault cleared
	hadGroundTruth    bool // batsim ground truth was coherent for INV-SOC judging
}

// diagnoseModeFlipUnderFault is unit 8.3's oracle for mode-flip-under-fault:
// INV-SOC (judged on batsim ground truth) is the hard safety gate — a mode flip
// while the pack is off the bus must never drive it past its reserve — and the
// reconciler must re-establish a coherent reading on the pack's return (standing
// desired doc + hub recovery). Mode-flip evidence and heartbeat are surfaced as
// in the under-event twin.
func diagnoseModeFlipUnderFault(o modeFlipFaultObs) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := baseFinding(sc)
		if len(s) == 0 {
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "no samples collected (aborted before any reading)"
			return f
		}
		f.Metrics = scanSamples(cons, s)
		socV := pastSettling(invSOC(s))
		det := modeDetectionLines(o.modeFlipObs)
		reassert := reassertLine(o)

		switch {
		case len(socV) >= auditEscalateMinSamples:
			f.Verdict = "FAIL"
			f.Headline = "battery driven past its reserve during a mode flip under fault"
			f.Diagnosis = append([]string{
				invSummaryLine("INV-SOC", socV),
				"A plan-author flip while the pack was faulted must never move it the wrong way at its SoC bound — Tier-1 safety is mode-invariant (EvaluateSafety always routes to the legacy evaluator).",
				reassert,
			}, det...)
			return f
		case o.heartbeatSeen && o.heartbeatEverStalled:
			f.Verdict = "DEGRADED"
			f.Headline = "no INV-SOC violation, but the plan heartbeat stalled during the flip under fault"
			f.Diagnosis = append([]string{invSummaryLine("INV-SOC", nil), reassert}, det...)
			return f
		case o.hadGroundTruth && !o.packRecovered:
			f.Verdict = "DEGRADED"
			f.Headline = "mode flips clean and safe, but the pack did not return to a coherent hub reading after the fault cleared"
			f.Diagnosis = append([]string{
				invSummaryLine("INV-SOC", nil),
				"Reassert-on-reconnect unconfirmed: the hub did not re-establish a coherent battery reading in the post-fault window — investigate the reconciler's reconnect path.",
				reassert,
			}, det...)
			return f
		default:
			f.Verdict = "PASS"
			f.Headline = "battery stayed safe across the flip under fault; reconciler re-established the pack on its return"
			f.Diagnosis = append([]string{
				invSummaryLine("INV-SOC", nil),
				"INV-SOC held on the pack's ground truth through the fault and both flips; the reconciler re-established a coherent reading when the pack returned.",
				reassert,
			}, det...)
			return f
		}
	}
}

// reassertLine renders the reassert-on-reconnect evidence bullet.
func reassertLine(o modeFlipFaultObs) string {
	switch {
	case !o.desiredReadOK:
		return "reassert evidence INCONCLUSIVE: retained lexa/desired/battery doc not readable over SSH."
	case o.desiredDocPresent && o.packRecovered:
		return "reassert-on-reconnect evidenced: a standing lexa/desired/battery doc is present AND the pack returned to a coherent hub reading in gateway mode."
	case o.desiredDocPresent:
		return "a standing lexa/desired/battery doc is present (reconciler has intent to reassert), but pack recovery was not confirmed in the window."
	default:
		return "no standing lexa/desired/battery doc found — the reconciler had no intent to reassert (unexpected if the hub was commanding the pack)."
	}
}

// scanRefusedObs captures the refused-ScanStatus observation for
// diagnoseScanRefused.
type scanRefusedObs struct {
	refusedSeen     bool    // GET /scan showed phase=="refused" for our id
	scanEndpointOK  bool    // GET /scan answered at least once
	refusedLatencyS float64 // first-seen latency; -1 = never seen
}

// diagnoseScanRefused is unit 8.4's oracle for scan-during-live-control-refused
// (DEVICE_ROADMAP §5.2 / TASK-092): with reconcilers live, a commissioning scan
// MUST be refused (a ScanStatus{phase:"refused"} within 10 s) and the control
// loop must be undisturbed (no INV-EXPORT breach, no divergence). A scan that
// actually RUNS against live Modbus is the hazard this gate exists to catch;
// the refusal is the proof it did not.
func diagnoseScanRefused(o scanRefusedObs) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := baseFinding(sc)
		if len(s) == 0 {
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "no samples collected (aborted before any reading)"
			return f
		}
		f.Metrics = scanSamples(cons, s)
		breaches := invExport(cons, s)

		// Observability caveat carried on every verdict: a refused ScanStatus is
		// the positive proof the scan never touched the bus; the "no Modbus
		// traffic on the sim Pis" leg is NOT independently observable from the
		// dashboard (the reconcilers poll the sims continuously anyway), so the
		// refusal is the assertion — see the scenario's Fix line.
		caveat := "Note: 'no scan traffic on the sim Modbus ports' is asserted via the refusal itself — lexa-modbus refuses before opening any scan session; independent per-sim Modbus-session accounting is not exposed on this bench."

		switch {
		case !o.scanEndpointOK:
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "lexa-api GET /scan was unreachable — cannot confirm the scan was refused"
			f.Diagnosis = []string{"The /scan status ring could not be read, so neither a refusal nor a run can be proven. Fix connectivity/auth and re-run.", caveat}
			return f
		case len(breaches) > 0:
			f.Verdict = "FAIL"
			f.Headline = "the live control loop was disturbed while a scan request was in flight"
			f.Diagnosis = []string{
				invSummaryLine("INV-EXPORT", breaches),
				"A commissioning scan request must be inert on a live hub — an export breach coincident with it means the request perturbed control.",
				caveat,
			}
			return f
		case o.refusedSeen && o.refusedLatencyS >= 0 && o.refusedLatencyS <= 10:
			f.Verdict = "PASS"
			f.Headline = fmt.Sprintf("scan refused in %.0fs; live control undisturbed", o.refusedLatencyS)
			f.Diagnosis = []string{
				fmt.Sprintf("A ScanStatus{phase:\"refused\"} appeared on lexa-api /scan %.0fs after the request — lexa-modbus refused the sweep while its reconcilers own the bus (§5.2).", o.refusedLatencyS),
				invSummaryLine("INV-EXPORT", nil),
				caveat,
			}
			return f
		case o.refusedSeen:
			f.Verdict = "DEGRADED"
			f.Headline = fmt.Sprintf("scan was refused, but not until %.0fs (> 10s target)", o.refusedLatencyS)
			f.Diagnosis = []string{
				"The refusal eventually appeared but outside the 10 s window — a live hub should refuse promptly.",
				invSummaryLine("INV-EXPORT", nil), caveat,
			}
			return f
		default:
			f.Verdict = "FAIL"
			f.Headline = "no refused ScanStatus appeared within the window while reconcilers were live"
			f.Diagnosis = []string{
				"lexa-api /scan never showed a phase:\"refused\" for the injected request. Either the scan was NOT refused (the hazard §5.2 exists to prevent — a sweep against live Modbus), or the §5.2 scan controller (TASK-092) is not deployed on this bench. Confirm lexa-modbus subscribes lexa/scan/request before trusting a FAIL here.",
				invSummaryLine("INV-EXPORT", nil), caveat,
			}
			return f
		}
	}
}

// intentFloodObs captures the intent-flood health signals for
// diagnoseIntentFlood.
type intentFloodObs struct {
	intentsFired int // how many reserve intents the scenario injected

	appliedBefore, appliedAfter float64
	appliedOK                   bool

	overrunsBefore, overrunsAfter float64
	overrunsOK                    bool

	serviceStartDelta int // hub process restarts during the window (journal)
	journalOK         bool

	resultCount int // reserve IntentResults counted on the bus
	resultSubOK bool

	journaldLines int // journald lines lexa-hub emitted during the flood
	journaldOK    bool

	heartbeatSeen        bool
	heartbeatEverStalled bool
}

// intentFloodJournaldBudget is the journald-line ceiling for the flood window:
// 50 intents each writing a per-intent journald line would be ~50, plus the
// per-tick loop's baseline; anything far past this means the rate caps
// (LogRateLimitIntervalSec/Burst, TASK-009) did NOT hold and a flash storm got
// through. Generous so bench-timing chatter cannot false-trip it.
const intentFloodJournaldBudget = 300

func diagnoseIntentFlood(o intentFloodObs) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := baseFinding(sc)
		if len(s) == 0 {
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "no samples collected (aborted before any reading)"
			return f
		}
		f.Metrics = scanSamples(cons, s)

		appliedDelta := o.appliedAfter - o.appliedBefore
		overrunDelta := o.overrunsAfter - o.overrunsBefore
		tailReachable := s[len(s)-1].HubReachable

		// Detection / health bullets, always emitted.
		var det []string
		if o.appliedOK {
			det = append(det, fmt.Sprintf("lexa_hub_intents_applied_total advanced by %.0f during the flood (fired %d).", appliedDelta, o.intentsFired))
		} else {
			det = append(det, "detection INCONCLUSIVE: lexa_hub_intents_applied_total not scrapable (TASK-044 not deployed).")
		}
		if o.overrunsOK {
			det = append(det, fmt.Sprintf("lexa_hub_tick_overruns_total advanced by %.0f during the flood (exit criterion: 0).", overrunDelta))
		} else {
			det = append(det, "detection INCONCLUSIVE: lexa_hub_tick_overruns_total not scrapable.")
		}
		if o.resultSubOK {
			det = append(det, fmt.Sprintf("%d reserve IntentResult(s) counted on lexa/intent/result for %d intents fired.", o.resultCount, o.intentsFired))
		} else {
			det = append(det, "detection INCONCLUSIVE: could not count IntentResults (qa-inject creds/SSH unavailable).")
		}
		if o.journaldOK {
			det = append(det, fmt.Sprintf("lexa-hub journald grew by %d line(s) during the flood (budget %d).", o.journaldLines, intentFloodJournaldBudget))
		} else {
			det = append(det, "detection INCONCLUSIVE: journald growth not measurable over SSH.")
		}
		if o.journalOK {
			det = append(det, fmt.Sprintf("%d service_start journal event(s) during the flood (any > 0 = a restart/watchdog kill).", o.serviceStartDelta))
		} else {
			det = append(det, "detection INCONCLUSIVE: service_start journal not readable — restart-freedom unconfirmed.")
		}
		if o.heartbeatSeen && o.heartbeatEverStalled {
			det = append(det, "plan heartbeat read \"stalled\" during the flood.")
		}

		// FAIL class: the hub went down or restarted under the flood.
		switch {
		case o.journalOK && o.serviceStartDelta > 0:
			f.Verdict = "FAIL"
			f.Headline = "hub restarted during the intent flood (watchdog kill / crash)"
			f.Diagnosis = append([]string{"A new service_start event landed during the flood — the flood wedged the hub past its watchdog or crashed it."}, det...)
			return f
		case !tailReachable:
			f.Verdict = "FAIL"
			f.Headline = "hub was unreachable at the end of the intent flood"
			f.Diagnosis = append([]string{"The hub's /status did not answer on the final sample — the flood took it offline."}, det...)
			return f
		}

		// DEGRADED class: survived, but a health target slipped.
		var degraded []string
		if o.overrunsOK && overrunDelta > 0 {
			degraded = append(degraded, fmt.Sprintf("tick overruns advanced by %.0f (target 0)", overrunDelta))
		}
		if o.heartbeatSeen && o.heartbeatEverStalled {
			degraded = append(degraded, "plan heartbeat stalled")
		}
		if o.appliedOK && appliedDelta < float64(o.intentsFired)*0.8 {
			degraded = append(degraded, fmt.Sprintf("only %.0f of %d intents applied", appliedDelta, o.intentsFired))
		}
		if o.resultSubOK && o.resultCount < int(float64(o.intentsFired)*0.8) {
			degraded = append(degraded, fmt.Sprintf("only %d of %d intents got a result", o.resultCount, o.intentsFired))
		}
		if o.journaldOK && o.journaldLines > intentFloodJournaldBudget {
			degraded = append(degraded, fmt.Sprintf("journald grew %d lines (> %d budget)", o.journaldLines, intentFloodJournaldBudget))
		}
		if len(degraded) > 0 {
			f.Verdict = "DEGRADED"
			f.Headline = "hub survived the flood but a health target slipped: " + strings.Join(degraded, "; ")
			f.Diagnosis = det
			return f
		}

		f.Verdict = "PASS"
		f.Headline = "hub rode out the intent flood: stayed up, no overruns, results returned, journald capped"
		f.Diagnosis = det
		return f
	}
}

// ── Scenario catalogue ───────────────────────────────────────────────────────

// intentScenarios are appended to the curated suite (scenarios()). They forge
// intent/scan/mode messages onto the broker via mqttproxy /inject and judge the
// hub's response with the diagnosers above. All are SSH- and mqttproxy-gated in
// setup (INCONCLUSIVE without them), and every one's teardown returns the hub
// to optimizer mode and clears its fault, so an abort mid-scenario still
// self-heals.
func (d *mayhemDriver) intentScenarios() []*mayScenario {
	const loadLow = 250.0

	return []*mayScenario{
		d.modeFlipUnderEventScenario(loadLow),
		d.modeFlipUnderFaultScenario(),
		d.scanDuringLiveControlScenario(loadLow),
		d.intentFloodScenario(),
	}
}

// modeFlipUnderEventScenario (unit 8.3, lexa-hub mode.go/intent.go): a zero-
// export cap is active with a full battery (PV curtailment is the only lever);
// the hub is flipped optimizer→gateway mid-event, held ~60 s, then flipped back.
// The cap must never open across either flip.
func (d *mayhemDriver) modeFlipUnderEventScenario(loadLow float64) *mayScenario {
	obs := &modeFlipObs{}
	const (
		flipToGatewayTick = 35 // past the mayConvergeDeadlineS settling window
		flipBackTick      = 95 // ~60 s of gateway
	)
	return &mayScenario{
		ID:         "mode-flip-under-active-event",
		Name:       "Plan-author flips to gateway and back while a zero-export cap is active",
		Category:   "Plan-author mode (INV-EXPORT survivability, unit 8.3)",
		Hypothesis: "A cloud/app publishes a ModeIntent flipping the hub optimizer→gateway (and back) while a utility zero-export cap is active — the plan author changes underneath a live compliance control.",
		Expected:   "The export cap holds beyond the normal convergence budget across BOTH flips (the compliance constraints run in either author), the plan heartbeat never stalls, and lexa/hub/mode + two mode_change journal events reflect each flip.",
		HoldS:      110,
		Fix:        "lexa-hub cmd/hub/mode.go modeManager.request (mode flip, mode_change-before-flip, retained lexa/hub/mode, eng.Wake) + intent.go applyMode; the constraint stack must author-invariantly enforce the cap.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.hubSSH("true"); err != nil {
				return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
			}
			if err := d.mqttReset(); err != nil {
				return nil, fmt.Errorf("mqttproxy unreachable (need scripts/mqtt-chaos.sh deploy): %w", err)
			}
			before, ok := d.journalEventCount("mode_change")
			obs.journalOK = ok
			obs.modeChangeDelta = -before // finalized (after-before) in teardown
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(d.pvHighW, loadLow)
			return d.postCap("exportCap", 0, 110, "mayhem: export cap under a mode flip")
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(d.pvHighW, loadLow)
			switch {
			case i == flipToGatewayTick:
				d.injectModeIntent("gateway", mayhemIntentID("modeflip-gw", i), true)
			case i == flipBackTick:
				d.injectModeIntent("optimizer", mayhemIntentID("modeflip-opt", i), true)
			case i > flipToGatewayTick && i < flipBackTick && i%10 == 0:
				if m, ok := d.hubMode(); ok && m == "gateway" {
					obs.gatewaySeen = true
				}
				if v, ok := d.readMetricCounter("lexa_hub_mode_gateway"); ok {
					obs.metricOK = true
					if v == 1 {
						obs.gatewayMetricSeen = true
					}
				}
			case i > flipBackTick && i%5 == 0:
				if m, ok := d.hubMode(); ok && m == "optimizer" {
					obs.optimizerRestored = true
				}
			}
			if i%15 == 0 {
				if st, ok := d.hubPlanHeartbeat(); ok {
					obs.heartbeatSeen = true
					if st == "stalled" {
						obs.heartbeatEverStalled = true
					}
				}
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseModeFlipUnderEvent(*obs)(sc, cons, s)
		},
		teardown: func(d *mayhemDriver) {
			// Self-heal: force optimizer regardless of where the run stopped.
			d.injectModeIntent("optimizer", mayhemIntentID("modeflip-teardown", 0), true)
			if after, ok := d.journalEventCount("mode_change"); ok {
				obs.modeChangeDelta += after // now = after - before
			}
			_ = d.mqttReset()
			d.deleteControls(0)
		},
	}
}

// modeFlipUnderFaultScenario (unit 8.3): flip to gateway while the battery pack
// is faulted off the bus, confirm the reconciler re-establishes the pack on its
// return in gateway mode, then flip back under the same fault. INV-SOC (on the
// pack's ground truth) is the hard gate.
func (d *mayhemDriver) modeFlipUnderFaultScenario() *mayScenario {
	obs := &modeFlipFaultObs{}
	const (
		flipToGatewayTick = 15 // pack already faulted
		clearFaultTick    = 35 // pack returns → reconciler reasserts in gateway mode
		reFaultTick       = 55
		flipBackTick      = 60 // optimizer flip under the re-armed fault
		clearFinalTick    = 75
	)
	return &mayScenario{
		ID:         "mode-flip-under-fault",
		Name:       "Plan-author flips to gateway (and back) while the battery is faulted off the bus",
		Category:   "Plan-author mode (INV-SOC survivability, unit 8.3)",
		Hypothesis: "A ModeIntent flips the hub to gateway while the battery pack has dropped off the Modbus bus (exception_code), the pack reboots and returns, then the hub is flipped back under the same fault — a mode switch straddling a device dropout.",
		Expected:   "No INV-SOC violation on the pack's ground truth across either flip (Tier-1 safety is mode-invariant), the reconciler reasserts the standing desired doc when the pack returns (evidenced by the retained desired doc + a recovered hub reading), and both flips are clean.",
		HoldS:      90,
		Fix:        "lexa-hub mode.go EvaluateSafety (mode-invariant Tier-1) + the lexa-modbus battery reconciler's reassert-on-reconnect (reconcile.Reconnected, retained lexa/desired/battery doc).",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.hubSSH("true"); err != nil {
				return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
			}
			if err := d.mqttReset(); err != nil {
				return nil, fmt.Errorf("mqttproxy unreachable (need scripts/mqtt-chaos.sh deploy): %w", err)
			}
			before, ok := d.journalEventCount("mode_change")
			obs.journalOK = ok
			obs.modeChangeDelta = -before
			// A mid pack under a genLimit so the hub is actively commanding it
			// (a standing desired doc exists to reassert), then fault it off the
			// bus so the flip straddles a dropout.
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 60, "Conn": 1})
			d.injectEnv(d.pvHighW, 250.0)
			cons, err := d.postCap("genLimit", 1500, 90, "mayhem: gen limit under a mode flip while the pack is faulted")
			if err != nil {
				return nil, err
			}
			if err := d.post("battery", "/fault", map[string]any{"kind": "exception_code"}); err != nil {
				return nil, fmt.Errorf("arm battery exception_code: %w", err)
			}
			return cons, nil
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(d.pvHighW, 250.0)
			switch i {
			case flipToGatewayTick:
				d.injectModeIntent("gateway", mayhemIntentID("faultflip-gw", i), true)
			case clearFaultTick:
				_ = d.post("battery", "/fault", map[string]any{"kind": "exception_code", "clear": true})
			case reFaultTick:
				_ = d.post("battery", "/fault", map[string]any{"kind": "exception_code"})
			case flipBackTick:
				d.injectModeIntent("optimizer", mayhemIntentID("faultflip-opt", i), true)
			case clearFinalTick:
				_ = d.post("battery", "/fault", map[string]any{"kind": "exception_code", "clear": true})
			}
			// Observe the gateway window (post-flip, pre-reFault) and the pack's
			// recovery after the fault first clears.
			if i > flipToGatewayTick && i < flipBackTick && i%10 == 0 {
				if m, ok := d.hubMode(); ok && m == "gateway" {
					obs.gatewaySeen = true
				}
				if v, ok := d.readMetricCounter("lexa_hub_mode_gateway"); ok {
					obs.metricOK = true
					if v == 1 {
						obs.gatewayMetricSeen = true
					}
				}
			}
			if i > clearFaultTick && i < reFaultTick && i%5 == 0 {
				// Pack has returned; a coherent hub battery SoC (near the injected
				// 60%) is evidence the reconciler re-established it.
				if h := d.hubState(); h.ok && h.batSOC > 30 && h.batSOC < 90 {
					obs.packRecovered = true
				}
			}
			if i > flipBackTick && i%5 == 0 {
				if m, ok := d.hubMode(); ok && m == "optimizer" {
					obs.optimizerRestored = true
				}
			}
			if i%15 == 0 {
				if st, ok := d.hubPlanHeartbeat(); ok {
					obs.heartbeatSeen = true
					if st == "stalled" {
						obs.heartbeatEverStalled = true
					}
				}
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			// Ground-truth availability for INV-SOC judging.
			for _, smp := range s {
				if smp.BatterySimOK {
					obs.hadGroundTruth = true
					break
				}
			}
			return diagnoseModeFlipUnderFault(*obs)(sc, cons, s)
		},
		teardown: func(d *mayhemDriver) {
			_ = d.post("battery", "/fault", map[string]any{"kind": "exception_code", "clear": true})
			if present, ok := d.retainedBatteryDesiredPresent(); ok {
				obs.desiredReadOK = true
				obs.desiredDocPresent = present
			}
			d.injectModeIntent("optimizer", mayhemIntentID("faultflip-teardown", 0), true)
			if after, ok := d.journalEventCount("mode_change"); ok {
				obs.modeChangeDelta += after
			}
			_ = d.mqttReset()
			d.deleteControls(0)
		},
	}
}

// scanDuringLiveControlScenario (unit 8.4, DEVICE_ROADMAP §5.2 / TASK-092):
// forge a commissioning ScanRequest at a hub whose reconcilers are live under a
// (loose, trivially-met) export cap. It must be refused within 10 s and the
// control loop must be undisturbed.
func (d *mayhemDriver) scanDuringLiveControlScenario(loadLow float64) *mayScenario {
	obs := &scanRefusedObs{refusedLatencyS: -1}
	var scanID string
	const injectTick = 3 // let the loop settle first
	return &mayScenario{
		ID:         "scan-during-live-control-refused",
		Name:       "Commissioning scan requested while reconcilers are live is refused, not run",
		Category:   "Commissioning safety (INV-EXPORT survivability, unit 8.4)",
		Hypothesis: "A ScanRequest lands on lexa/scan/request while lexa-modbus's reconcilers are actively polling/controlling the pack and inverter — a scan sweep now would share the serial line / TCP session with live control.",
		Expected:   "lexa-modbus REFUSES the scan (ScanStatus{phase:\"refused\"} on lexa/scan/status, surfaced by lexa-api /scan) within 10 s and never opens a scan session; the control loop is undisturbed (no INV-EXPORT breach, no divergence).",
		HoldS:      30,
		Fix:        "lexa-modbus §5.2 scan controller (TASK-092): arming rule refuses a scan whenever any reconciler is live (cfg.Devices non-empty and not all 'off').",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.mqttReset(); err != nil {
				return nil, fmt.Errorf("mqttproxy unreachable (need scripts/mqtt-chaos.sh deploy): %w", err)
			}
			// A loose export cap the hub trivially meets (full pack, low PV): a
			// live-but-quiet control so INV-EXPORT/divergence are measurable
			// while the scan request is in flight.
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(2000, loadLow)
			return d.postCap("exportCap", 4000, 30, "mayhem: loose export cap during a refused scan")
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(2000, loadLow)
			if i == injectTick {
				scanID = mayhemIntentID("scan", i)
				d.injectScanRequest(scanID)
			}
			if i >= injectTick {
				if refused, ok := d.scanRefusedFor(scanID); ok {
					obs.scanEndpointOK = true
					if refused && !obs.refusedSeen {
						obs.refusedSeen = true
						obs.refusedLatencyS = float64(i - injectTick)
					}
				}
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseScanRefused(*obs)(sc, cons, s)
		},
		teardown: func(d *mayhemDriver) {
			_ = d.mqttReset()
			d.deleteControls(0)
		},
	}
}

// intentFloodScenario (unit 8.2, lexa-hub intent.go): fire 50 reserve intents
// (varying IDs) in 10 s and confirm the hub stays healthy — no watchdog kill, no
// tick overruns, every intent answered, and the journald rate caps hold.
func (d *mayhemDriver) intentFloodScenario() *mayScenario {
	obs := &intentFloodObs{intentsFired: 50}
	var wg sync.WaitGroup
	var floodStartUnix int64
	const (
		launchTick = 3  // start the flood + result sub after a brief warmup
		floodSpanS = 10 // 50 intents across 10 s
		resultSubS = 15 // sub outlives the flood
	)
	return &mayScenario{
		ID:         "intent-flood-rate-limit",
		Name:       "50 reserve intents in 10 s must not wedge the hub or storm the journal",
		Category:   "Intent ingestion (liveness, unit 8.2)",
		Hypothesis: "A misbehaving cloud/app floods lexa/intent/reserve with 50 intents (varying IDs) in 10 s — the hub adopts each one on its single control-goroutine funnel (intentAdopter.adopt, under one mutex).",
		Expected:   "The hub stays healthy: plan heartbeat ok, no watchdog kill/restart, zero tick overruns, lexa_hub_intents_applied_total advances ~50, every intent gets an IntentResult on lexa/intent/result, and journald rate caps hold (no flash storm).",
		HoldS:      30,
		Fix:        "lexa-hub cmd/hub/intent.go intentAdopter.adopt (ID-dedupe + bounded publishResult) + TASK-046 async actuator publishes + TASK-009 journald rate caps.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.hubSSH("true"); err != nil {
				return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
			}
			if err := d.mqttReset(); err != nil {
				return nil, fmt.Errorf("mqttproxy unreachable (need scripts/mqtt-chaos.sh deploy): %w", err)
			}
			obs.appliedBefore, obs.appliedOK = d.readMetricCounter("lexa_hub_intents_applied_total")
			obs.overrunsBefore, obs.overrunsOK = d.readMetricCounter("lexa_hub_tick_overruns_total")
			if before, ok := d.journalEventCount("service_start"); ok {
				obs.journalOK = true
				obs.serviceStartDelta = -before
			}
			if t0, ok := d.hubUnix(); ok {
				floodStartUnix = t0
			}
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 50, "Conn": 1})
			d.injectEnv(1500, 250.0)
			return &activeConstraint{Typ: "none"}, nil
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(1500, 250.0)
			if i == launchTick {
				// Background result-counter sub (bounded; self-terminates).
				wg.Add(1)
				go func() {
					defer wg.Done()
					if n, ok := d.countReserveIntentResults(resultSubS); ok {
						obs.resultCount = n
						obs.resultSubOK = true
					}
				}()
				// The flood: 50 intents across floodSpanS seconds.
				wg.Add(1)
				go func() {
					defer wg.Done()
					gap := time.Duration(float64(floodSpanS) * float64(time.Second) / float64(obs.intentsFired))
					for n := 0; n < obs.intentsFired; n++ {
						d.injectReserveIntent(reserveFloorPct, mayhemIntentID("flood", n))
						time.Sleep(gap)
					}
				}()
			}
			if i%5 == 0 {
				if st, ok := d.hubPlanHeartbeat(); ok {
					obs.heartbeatSeen = true
					if st == "stalled" {
						obs.heartbeatEverStalled = true
					}
				}
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseIntentFlood(*obs)(sc, cons, s)
		},
		teardown: func(d *mayhemDriver) {
			// The flood/sub goroutines are bounded (flood ~10 s, sub ~15 s) and
			// started ~3 s into a 30 s hold, so they are already done here; wait
			// defensively with a hard cap so teardown never blocks a run.
			waitWithTimeout(&wg, 25*time.Second)
			obs.appliedAfter, _ = d.readMetricCounter("lexa_hub_intents_applied_total")
			obs.overrunsAfter, _ = d.readMetricCounter("lexa_hub_tick_overruns_total")
			if after, ok := d.journalEventCount("service_start"); ok && obs.journalOK {
				obs.serviceStartDelta += after
			}
			if floodStartUnix > 0 {
				if n, ok := d.journaldLinesSince("lexa-hub", floodStartUnix); ok {
					obs.journaldLines = n
					obs.journaldOK = true
				}
			}
			_ = d.mqttReset()
			d.deleteControls(0)
		},
	}
}

// waitWithTimeout waits for wg or the timeout, whichever is first — so a hung
// background goroutine (e.g. an SSH sub that never returns) can never wedge a
// scenario's teardown and the whole run behind it.
func waitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}
