package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MQTT chaos scenarios. These drive the on-hub mqttproxy (cmd/mqttproxy) to fault
// the message bus — the product's spinal cord — which the in-sim injectors cannot
// reach. They need the proxy deployed (scripts/mqtt-chaos.sh deploy); when it is
// absent the fault call errors and the scenario records a setup error rather than
// a misleading PASS.
//
// topicCSIPControl mirrors lexa-hub internal/bus.TopicCSIPControl. The retained
// CSIP control is the highest-value target: a malformed or stale retained payload
// is exactly what a flapping northbound or a broker hiccup would leave behind.
const topicCSIPControl = "lexa/csip/control"

// mqttFault sets the proxy's transport fault mode (pass|down|latency).
func (d *mayhemDriver) mqttFault(mode string, latencyMs, durationS int) error {
	return d.post("mqttproxy", "/fault", map[string]any{
		"mode": mode, "latency_ms": latencyMs, "duration_s": durationS,
	})
}

// mqttInject publishes a raw payload to a topic on the real broker (bypassing the
// transport fault layer) — for malformed / duplicate / stale retained messages.
func (d *mayhemDriver) mqttInject(topic, payload string, retain bool) error {
	return d.post("mqttproxy", "/inject", map[string]any{
		"topic": topic, "payload": payload, "retain": retain,
	})
}

// mqttReset returns the proxy to transparent pass mode and cancels any active
// /hold (TASK-049) or /storm (TASK-051) — mqttproxy's handleReset cancels both.
func (d *mayhemDriver) mqttReset() error {
	return d.post("mqttproxy", "/reset", map[string]any{})
}

// mqttproxyProbe confirms the on-hub mqttproxy control API is reachable before
// a scenario relies on it, so a missing/undeployed proxy fails setup to
// INCONCLUSIVE instead of silently no-opping every fault call in perTick (the
// four original mqtt-* scenarios predate this explicit gate and swallow the
// same failure quietly; TASK-049/051 make it a named acceptance criterion).
func (d *mayhemDriver) mqttproxyProbe() error {
	var state map[string]any
	if err := d.getJSON("mqttproxy", "/state", &state); err != nil {
		return fmt.Errorf("mqttproxy unreachable: %w", err)
	}
	return nil
}

// holdClientID posts to mqttproxy's /hold endpoint (TASK-049): open a second
// session upstream using clientID and keep it alive for durationS, forcing an
// MQTT broker to evict whatever session already holds that client ID (paho's
// mutual-kick reconnect storm) when clientID collides with a real service.
func (d *mayhemDriver) holdClientID(clientID string, durationS int) error {
	return d.post("mqttproxy", "/hold", map[string]any{
		"client_id": clientID, "duration_s": durationS,
	})
}

// mqttStorm posts to mqttproxy's /storm endpoint (TASK-051): a rate-limited
// QoS-0 publish flood against topic, sized to pressure mosquitto's
// max_queued_messages/max_inflight_messages bounds without touching the
// retained control topic.
func (d *mayhemDriver) mqttStorm(topic string, rateHz, durationS, payloadBytes int) error {
	return d.post("mqttproxy", "/storm", map[string]any{
		"topic": topic, "rate_hz": rateHz, "duration_s": durationS, "payload_bytes": payloadBytes,
	})
}

// defaultHubMQTTClientID is lexa-hub's compiled-in default (cmd/hub/config.go:54
// in lexa-hub). duplicate-client-id must collide with whatever ID the RUNNING
// hub actually uses, not this constant directly — see hubMQTTClientID.
const defaultHubMQTTClientID = "lexa-hub"

// hubMQTTClientID determines the MQTT client ID the running hub is actually
// using. LEXA_SSH_USER-style override first (LEXA_HUB_CLIENT_ID, for a bench
// that needs to force a value), else read /etc/lexa/hub.json on the hub Pi
// over SSH: an absent key means the hub is running its compiled-in default,
// a present key means the bench overrode it — and squatting the wrong ID
// would silently no-op the whole scenario (a false PASS), so this always
// checks the live config rather than assuming the default. Any SSH failure or
// an unparseable value is returned as an error; the caller must fail setup to
// INCONCLUSIVE rather than guess.
func (d *mayhemDriver) hubMQTTClientID() (string, error) {
	if id := os.Getenv("LEXA_HUB_CLIENT_ID"); id != "" {
		return id, nil
	}
	out, err := d.hubSSHOutput(`grep -o '"mqtt_client_id"[[:space:]]*:[[:space:]]*"[^"]*"' /etc/lexa/hub.json 2>/dev/null; true`)
	if err != nil {
		return "", fmt.Errorf("read hub config over SSH: %w", err)
	}
	if out == "" {
		return defaultHubMQTTClientID, nil // no override key present; hub runs the compiled-in default
	}
	return parseMQTTClientIDLine(out)
}

// parseMQTTClientIDLine extracts the value from a grep match of the form
// `"mqtt_client_id": "some-id"` (whitespace around the colon may vary).
// Pulled out as a pure function so the parsing is unit-testable without SSH.
func parseMQTTClientIDLine(line string) (string, error) {
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		return "", fmt.Errorf("could not parse mqtt_client_id from hub config line %q", line)
	}
	id := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
	if id == "" {
		return "", fmt.Errorf("empty mqtt_client_id parsed from hub config line %q", line)
	}
	return id, nil
}

// hubMetricsAddr derives lexa-hub's Prometheus /metrics URL (TASK-044,
// 69.0.0.1:9101 per BENCH.md) from the "hub" backend's host. The "hub"
// backend points at lexa-api (:9100, a different service and port — AD-008),
// so the metrics scrape needs its own address on the same host.
func (d *mayhemDriver) hubMetricsAddr() (string, error) {
	base, ok := d.backends["hub"]
	if !ok {
		return "", fmt.Errorf("no hub backend configured")
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot derive hub host from %q", base)
	}
	return "http://" + u.Hostname() + ":9101/metrics", nil
}

// readMetricCounter scrapes lexa-hub's Prometheus text-format /metrics
// (TASK-044) and returns the value of the named sample. ok=false means the
// metric (or the endpoint) is unavailable — TASK-044 not deployed on this
// bench, most likely — and the caller must treat that as "detection
// unprovable", never as a counter reading of zero.
func (d *mayhemDriver) readMetricCounter(name string) (value float64, ok bool) {
	addr, err := d.hubMetricsAddr()
	if err != nil {
		return 0, false
	}
	resp, err := d.client.Get(addr)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, false
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != name {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// ── Broker persistence faults (GAP-01/02, TASK-043 — validates TASK-042's
// retained-control trust hardening: adoption-time staleness bound +
// lexa/csip/rewalk re-request path) ─────────────────────────────────────────
//
// These two scenarios manipulate the real mosquitto store directly over SSH
// (systemctl/cp/rm — no mqttproxy involved for the store dance itself), plus
// one direct authenticated mosquitto_sub read-back used as a setup-quality
// assertion. mqttInject (mqttproxy's /inject) is still used by
// corrupted-retained-control to forge the truncated payload — see its TASK-013
// credentials note below.

const (
	mosquittoStorePath = "/var/lib/mosquitto/mosquitto.db"
	mayhemStoreTmpPath = "/tmp/mayhem-store.db"

	// qaInjectPassFile is the qa-inject broker user's password file
	// (scripts/mqtt-chaos.sh deploy provisions it via mosquitto_passwd
	// against /etc/mosquitto/lexa-passwd, TASK-013/W7). qa-inject holds
	// `topic readwrite lexa/#` in lexa-hub's systemd/mosquitto-lexa.acl, so
	// it can both forge (mqttproxy's /inject) and read back the retained
	// control — the read-back is needed here, direct over SSH, to confirm
	// which generation of the control the broker is actually serving after
	// an unclean rollback, independent of mqttproxy.
	qaInjectPassFile = "/etc/lexa/mqtt/qa-inject.pass"
)

// brokerSnapshotCommand builds the remote command brokerSnapshot runs: a
// CLEAN stop (mosquitto's on-shutdown flush persists the current retained
// set to disk), a copy of the store to a scratch path, then a restart. Pure
// string builder so the shape is unit-testable without SSH (mirrors
// fillDiskCommand/netemApplyCommand). The store copy is only trustworthy
// when taken via a clean stop — never snapshot a live/running store file,
// since mosquitto may still be writing it.
func brokerSnapshotCommand() string {
	return fmt.Sprintf(`sudo systemctl stop mosquitto && sudo cp %s %s && sudo systemctl start mosquitto`,
		mosquittoStorePath, mayhemStoreTmpPath)
}

// brokerUncleanRollbackCommand builds the remote command
// brokerUncleanRollback runs: SIGKILL mosquitto (bypasses the on-shutdown
// store flush — the software equivalent of a power cut, per docs/BENCH.md's
// "systemctl kill, never pkill" gotcha applied to the broker itself), restore
// the earlier clean snapshot over the now-stale live store, then start.
// `|| true` after the kill keeps this idempotent against a broker that is
// already down (a retried/aborted run must not fail here).
func brokerUncleanRollbackCommand() string {
	return fmt.Sprintf(`sudo systemctl kill -s SIGKILL mosquitto || true; sudo cp %s %s && sudo systemctl start mosquitto`,
		mayhemStoreTmpPath, mosquittoStorePath)
}

// brokerCleanupCommand removes the scratch snapshot. `rm -f`: idempotent,
// safe even when brokerSnapshot was never reached (a setup error before the
// snapshot step, or an abort mid-setup).
func brokerCleanupCommand() string {
	return "sudo rm -f " + mayhemStoreTmpPath
}

// brokerRetainedControlCommand builds the remote command that reads back the
// single current retained lexa/csip/control payload, authenticating as the
// qa-inject broker user — TASK-013 flipped the hub broker's
// `allow_anonymous` to false, so a plain anonymous mosquitto_sub is refused
// here exactly the way an anonymous mqttproxy /inject would be. Fails loud
// (exit 1) when the credential file is missing/empty rather than silently
// returning nothing, so an un-provisioned bench (scripts/mqtt-chaos.sh
// deploy never run) surfaces as INCONCLUSIVE, not a false negative read.
func brokerRetainedControlCommand() string {
	return fmt.Sprintf(
		`PASS=$(sudo cat %s 2>/dev/null); if [ -z "$PASS" ]; then echo "qa-inject credentials not provisioned (run scripts/mqtt-chaos.sh deploy)" >&2; exit 1; fi; timeout 5 mosquitto_sub -h localhost -p 1883 -u qa-inject -P "$PASS" -C 1 -t %s`,
		qaInjectPassFile, topicCSIPControl)
}

func (d *mayhemDriver) brokerSnapshot() error        { return d.hubSSH(brokerSnapshotCommand()) }
func (d *mayhemDriver) brokerUncleanRollback() error { return d.hubSSH(brokerUncleanRollbackCommand()) }

// brokerCleanup is best-effort and never blocks teardown on an SSH error —
// mirrors freeDisk's contract (TASK-050): log and move on so one failed
// cleanup command never skips clearing the gridsim outage or the controls
// that follow it in a scenario's teardown.
func (d *mayhemDriver) brokerCleanup() {
	if err := d.hubSSH(brokerCleanupCommand()); err != nil {
		log.Printf("mayhem: brokerCleanup FAILED — manual cleanup needed (ssh dmitri@69.0.0.1 sudo rm -f %s): %v", mayhemStoreTmpPath, err)
	}
}

// parseRetainedExpLimW extracts the numeric exp_lim_w/exp_lim_W field from a
// raw lexa/csip/control retained JSON payload. Pure so it's unit-testable
// without a live mosquitto_sub (mirrors parseMQTTClientIDLine's pattern) —
// this is the ONLY way, from outside the hub, to tell which generation of the
// control the broker is actually serving after an unclean rollback, which is
// what the power-cut-retained-rollback scenario's setup-quality assertion
// needs before the hub can be judged.
func parseRetainedExpLimW(payload string) (float64, bool) {
	idx := strings.Index(payload, `"exp_lim_w"`)
	if idx < 0 {
		idx = strings.Index(payload, `"exp_lim_W"`) // tolerate either case seen in the wild
	}
	if idx < 0 {
		return 0, false
	}
	rest := payload[idx:]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return 0, false
	}
	rest = strings.TrimSpace(rest[colon+1:])
	end := 0
	for end < len(rest) && (rest[end] == '-' || rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
		end++
	}
	if end == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(rest[:end], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// brokerRetainedExpLimW reads back the retained lexa/csip/control payload
// over SSH and parses its exp_lim_w. Used as the power-cut-retained-rollback
// setup-quality assertion after brokerUncleanRollback: the scenario must
// confirm the bus is actually serving the resurrected STALE value (cap A)
// before the hub is judged — otherwise a mistimed rollback (a northbound walk
// landing in the gap between the outage arming and the rollback) republishes
// cap B over the resurrected A and the scenario would silently no-op-pass.
func (d *mayhemDriver) brokerRetainedExpLimW() (float64, error) {
	out, err := d.hubSSHOutput(brokerRetainedControlCommand())
	if err != nil {
		return 0, err
	}
	v, ok := parseRetainedExpLimW(out)
	if !ok {
		return 0, fmt.Errorf("could not parse exp_lim_w from retained payload %q", out)
	}
	return v, nil
}

// waitForAdoptedExportCap polls the hub's /status for up to timeout for it to
// report an adopted exportCap within 1 W of limW. power-cut-retained-rollback
// must not snapshot the broker's store until the value it intends to capture
// has actually landed there — snapshotting too early would capture no
// control (or the wrong one) and silently invalidate the whole scenario.
func (d *mayhemDriver) waitForAdoptedExportCap(limW float64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		st := d.hubState()
		if st.ok && st.ctrlActive && st.ctrlTyp == "exportCap" && math.Abs(st.ctrlLimW-limW) < 1 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(1 * time.Second)
	}
}

// diagnosePowerCutRollback is the custom ladder for power-cut-retained-
// rollback (GAP-01). cons is cap B (0 W, the constraint being judged); the
// hazard under test is the hub re-adopting the resurrected STALE cap A
// (5000 W) after the unclean broker rollback + hub restart. Reuses
// scanSamples/invExport exactly as every other constraint diagnoser does —
// invExport already excuses the opening settling ramp (mayConvergeDeadlineS),
// so any breach flagged here is either B's own settling ramp (before the
// fault) or the aftermath of the rollback (at/after the fault tick), which is
// exactly what needs judging.
func diagnosePowerCutRollback(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	f.Metrics = scanSamples(cons, s)
	breaches := invExport(cons, s)

	// The strongest FAIL signal: the hub's own /status shows it adopted the
	// resurrected 5000 W control, not the 0 W cap (B) it should have
	// rejected (staleness bound) or re-derived (rewalk).
	enforcingA := false
	for _, smp := range s {
		if smp.HubAdopted && smp.AdoptedTyp == "exportCap" && math.Abs(smp.AdoptedLimW-5000) < 1 {
			enforcingA = true
			break
		}
	}

	switch {
	case len(breaches) == 0:
		f.Verdict = "PASS"
		f.Headline = "cap B held through the unclean broker rollback; the resurrected stale cap A was never enforced"
		f.Diagnosis = []string{
			"The broker died uncleanly (SIGKILL) and came back serving the resurrected, superseded cap A (5000 W) — the hub stayed on (or re-adopted) cap B (0 W) with no sustained breach.",
			hubVsRealLine(s),
		}
		return f
	case enforcingA && !f.Metrics.TailClean:
		f.Verdict = "FAIL"
		f.Headline = "hub adopted the resurrected stale cap A (5000 W) and export sustained over cap B with no alarm"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status showed the adopted control at ~5000 W — the resurrected, superseded control from before the power cut — for part of the run, and %s", invSummaryLine("INV-EXPORT", breaches)),
			"TASK-042's staleness bound (adoption-time Ts vs a bound) did not reject the stale retained control on reboot; a power-cut-class broker death can resurrect an arbitrarily-superseded cap and the hub trusts it (GAP-01).",
			decisionLine(s),
		}
		f.Fix = sc.Fix
		return f
	case f.Metrics.TailClean && f.Metrics.ConvergedAtS >= 0:
		f.Verdict = "DEGRADED"
		f.Headline = "stale enforcement was bounded: the hub recovered onto cap B before the window ended"
		f.Diagnosis = []string{
			invSummaryLine("INV-EXPORT", breaches),
			"The rollback produced a breach, but it was bounded — the hub ended the window back on cap B (or a compliant state) rather than staying wedged on the stale cap A. This ladder is measurement-based and cannot see the alarm counter directly; confirm the post-042 staleness alarm fired via docs/QA_FINDINGS.md/metrics before calling this fully resolved.",
			hubVsRealLine(s),
		}
		return f
	default:
		f.Verdict = "FAIL"
		tail := s[len(s)-1]
		f.Headline = "export sustained over cap B after the rollback and never recovered by the end of the window"
		f.Diagnosis = []string{
			invSummaryLine("INV-EXPORT", breaches),
			fmt.Sprintf("Tail sample: adopted=%v typ=%s lim=%.0f W (want exportCap 0 W).", tail.HubAdopted, tail.AdoptedTyp, tail.AdoptedLimW),
			decisionLine(s),
		}
		f.Fix = sc.Fix
		return f
	}
}

// diagnoseDuplicateClientID is TASK-049's custom ladder: FAIL on any
// INV-CONNECT (back-feed) or sustained INV-EXPORT violation; DEGRADED if the
// cap held but the loop hunted while the storm was confirmed detected, or if
// the cap held cleanly yet the reconnect counter (when available) never
// moved — safety held, but the detection half of the oracle did not, which
// must be visible rather than a silent PASS; PASS if the cap held cleanly and
// either the counter is unavailable (detection INCONCLUSIVE, noted in the
// diagnosis, per TASK-049) or it rose (detection proven).
func diagnoseDuplicateClientID(counterBefore, counterAfter float64, counterOK bool) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := baseFinding(sc)
		if len(s) == 0 {
			f.Verdict = "INCONCLUSIVE"
			f.Headline = "no samples"
			return f
		}
		f.Metrics = scanSamples(cons, s)
		connectV := connectBackfeed(s)
		exportV := invExport(cons, s)
		huntV := invHunt(cons, s)
		detectionRose := counterOK && counterAfter > counterBefore

		var detectionLine string
		switch {
		case !counterOK:
			detectionLine = "detection INCONCLUSIVE: lexa_mqtt_reconnects_total not available (TASK-044 not deployed on this bench)."
		case detectionRose:
			detectionLine = fmt.Sprintf("detection proven: lexa_mqtt_reconnects_total rose by %.0f during the storm (%.0f → %.0f).", counterAfter-counterBefore, counterBefore, counterAfter)
		default:
			detectionLine = fmt.Sprintf("detection NOT observed: lexa_mqtt_reconnects_total stayed flat (%.0f) despite the held collision — the alarm path may be blind to this fault.", counterBefore)
		}

		switch {
		case len(connectV) > 0:
			f.Verdict = "FAIL"
			f.Headline = "back-feed during the duplicate-client-ID storm"
			f.Diagnosis = []string{invSummaryLine("INV-CONNECT", connectV), detectionLine}
		case len(exportV) > 0:
			f.Verdict = "FAIL"
			f.Headline = "export cap breached during the duplicate-client-ID storm"
			f.Diagnosis = []string{invSummaryLine("INV-EXPORT", exportV), detectionLine}
		case detectionRose && len(huntV) > 0:
			f.Verdict = "DEGRADED"
			f.Headline = "cap held, but the loop hunted while the storm was detected"
			f.Diagnosis = []string{invSummaryLine("INV-HUNT", huntV), detectionLine}
		case counterOK && !detectionRose:
			// Safety held, but the oracle's detection half did not — TASK-049
			// requires that be surfaced, not silently absorbed into a PASS.
			f.Verdict = "DEGRADED"
			f.Headline = "cap held cleanly, but the storm went undetected (reconnect counter flat)"
			f.Diagnosis = []string{
				fmt.Sprintf("No INV-CONNECT/INV-EXPORT/INV-HUNT violations across %d samples (%.0fs).", len(s), s[len(s)-1].T),
				detectionLine,
			}
		default:
			f.Verdict = "PASS"
			f.Headline = "cap held cleanly through the duplicate-client-ID storm"
			f.Diagnosis = []string{
				fmt.Sprintf("No INV-CONNECT/INV-EXPORT/INV-HUNT violations across %d samples (%.0fs).", len(s), s[len(s)-1].T),
				detectionLine,
			}
		}
		return f
	}
}

// diagnoseMqttStorm is TASK-051's ladder: diagnoseConstraint (cap held) is the
// primary oracle, extended with an INV-HUNT assertion (no chasing under bus
// pressure) and a TASK-044 overflow/backpressure-visibility check. Per the
// task: either the counter moving (drops surfaced) or staying flat (the queue
// absorbed the flood) is an acceptable outcome — the one unacceptable outcome
// is a cap breach with NO counted overflow at all: a silent wedge where the
// control path starved and nothing surfaced it, which escalates to FAIL even
// if the base ladder called it only DEGRADED.
func diagnoseMqttStorm(counterName string, counterBefore, counterAfter float64, counterOK bool) func(*mayScenario, *activeConstraint, []maySample) mayFinding {
	return func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
		f := diagnoseConstraint(sc, cons, s)
		if len(s) == 0 {
			return f
		}
		hunts := invHunt(cons, s)
		if len(hunts) > 0 {
			f.Diagnosis = append(f.Diagnosis, invSummaryLine("INV-HUNT", hunts))
		} else {
			f.Diagnosis = append(f.Diagnosis, "INV-HUNT held: no chasing under bus pressure.")
		}

		switch {
		case !counterOK:
			f.Diagnosis = append(f.Diagnosis, fmt.Sprintf("detection INCONCLUSIVE: %s not available (TASK-044 not deployed on this bench).", counterName))
		case counterAfter > counterBefore:
			f.Diagnosis = append(f.Diagnosis, fmt.Sprintf("overflow surfaced: %s rose by %.0f during the storm (%.0f → %.0f) — drops are counted, not silent.", counterName, counterAfter-counterBefore, counterBefore, counterAfter))
		default:
			f.Diagnosis = append(f.Diagnosis, fmt.Sprintf("%s stayed flat (%.0f) — the broker queue absorbed the flood without a counted drop.", counterName, counterBefore))
		}

		silentWedge := counterOK && counterAfter == counterBefore && len(invExport(cons, s)) > 0
		if silentWedge && f.Verdict != "FAIL" {
			f.Verdict = "FAIL"
			f.Headline = "control path starved under the storm with no counted overflow (silent wedge)"
		}
		return f
	}
}

// mqttScenarios are appended to the curated suite. Each holds a clean export cap
// (full battery ⇒ PV curtailment is the lever) and injects a bus fault mid-window;
// the hub must ride it out and keep the cap.
func (d *mayhemDriver) mqttScenarios() []*mayScenario {
	const loadLow = 250.0
	const faultTick = 8 // inject once the cap is established and settled

	armCap := func(d *mayhemDriver, desc string) (*activeConstraint, error) {
		_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
		d.injectEnv(d.pvHighW, loadLow)
		return d.postCap("exportCap", 0, 90, desc)
	}

	return []*mayScenario{
		{
			ID: "mqtt-broker-restart", Name: "MQTT broker drops out and restarts mid-cap",
			Category:   "Bus resilience (INV-EXPORT survivability)",
			Hypothesis: "mosquitto restarts (or the link blips) while a zero-export cap is active — every service's MQTT session drops and must reconnect and re-subscribe.",
			Expected:   "Ride out the outage: keep the latched curtailment, recover the retained control on reconnect, and never let export run away during or after the blip.",
			HoldS:      80,
			Fix:        "mqttutil must reconnect AND replay subscriptions (paho does not resend SUBSCRIBE); CSIP control must be retained so the hub re-reads it on reconnect.",
			setup:      func(d *mayhemDriver) (*activeConstraint, error) { return armCap(d, "mayhem: broker-restart cap") },
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == faultTick {
					_ = d.mqttFault("down", 0, 6) // broker down 6 s, auto-reset
				}
			},
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) { _ = d.mqttReset() },
		},
		{
			ID: "mqtt-broker-latency", Name: "MQTT broker adds 800 ms latency under a cap",
			Category:   "Bus resilience (INV-EXPORT survivability)",
			Hypothesis: "The broker (or the bus) slows to ~800 ms per message while a zero-export cap is active — commands and measurements still flow, but late.",
			Expected:   "Hold the cap despite the lag; a slow bus must degrade timing, not correctness.",
			HoldS:      70,
			Fix:        "Optimizer cadence and the curtail command path must tolerate a slow bus without losing the cap.",
			setup:      func(d *mayhemDriver) (*activeConstraint, error) { return armCap(d, "mayhem: broker-latency cap") },
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == faultTick {
					_ = d.mqttFault("latency", 800, 30) // 800 ms/chunk for 30 s
				}
			},
			evaluate: diagnoseConstraint,
			teardown: func(d *mayhemDriver) { _ = d.mqttReset() },
		},
		{
			// Payload has no "v" field (lexa-hub TASK-018: bus.Envelope,
			// AD-006). That is deliberate, not an oversight: this scenario's
			// point is a malformed/truncated payload, and the hub's bus
			// envelope policy treats absent-v as legacy v0 — accepted while
			// bus.LegacyV0Accepted is true (the transition default) — so
			// version-checking would never be what rejects this payload
			// anyway; the truncation itself is what the real json.Unmarshal
			// (unaffected by the version gate, which runs first but defers
			// malformed-JSON detection to it) must catch. When the
			// enforcement flip lands (LegacyV0Accepted=false, tracked in
			// AD-006 as a separate later change), this injected payload
			// gains "v":1 in that same change, same as every other
			// harness-injected control payload — not before, since v0 must
			// stay accepted here until then.
			ID: "mqtt-malformed-control", Name: "Malformed retained CSIP control on the bus",
			Category:   "Bus robustness (INV-EXPORT survivability)",
			Hypothesis: "A truncated/garbage JSON payload is published RETAINED to lexa/csip/control (a half-written message, a buggy publisher) while a real cap is active.",
			Expected:   "Stay up and keep the active cap: a malformed bus message must be dropped, never crash the hub or unseat a safe control.",
			HoldS:      70,
			Fix:        "Hub MQTT handlers must reject a payload that fails to unmarshal and retain the last-good control (lexa-hub onCSIPControl).",
			setup:      func(d *mayhemDriver) (*activeConstraint, error) { return armCap(d, "mayhem: malformed-control cap") },
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == faultTick {
					_ = d.mqttInject(topicCSIPControl, `{"source":"event","exp_lim_W":`, true) // truncated JSON
				}
			},
			evaluate: diagnoseMalform,
			teardown: func(d *mayhemDriver) { _ = d.mqttReset() },
		},
		{
			// Same v0-tolerance note as mqtt-malformed-control above: this
			// payload has no "v" field on purpose. It is well-formed JSON
			// (Source="none") and must still be accepted as legacy v0 by the
			// hub's version gate — the scenario is testing the STALE-VALUE
			// hazard, not decode rejection, so the envelope policy must stay
			// out of its way here. Gains "v":1 alongside every other
			// injected control payload at the future enforcement flip
			// (AD-006), not independently.
			ID: "mqtt-stale-retained", Name: "Stale retained 'no control' overwrites an active cap",
			Category:   "Bus robustness (INV-EXPORT survivability)",
			Hypothesis: "A stale retained message (Source=none) lands on lexa/csip/control — a leftover from a previous session or a flapping northbound — telling the hub there is no control while a real cap is still in force.",
			Expected:   "Do not drop the cap on a spurious 'none': the northbound re-publishes the real control each cycle, so any drop must be a brief transient, not a sustained export.",
			HoldS:      75,
			Fix:        "Treat a 'none' that contradicts an unexpired control conservatively; fail closed to last-known-good until the control actually expires.",
			setup:      func(d *mayhemDriver) (*activeConstraint, error) { return armCap(d, "mayhem: stale-retained cap") },
			perTick: func(d *mayhemDriver, i int) {
				d.injectEnv(d.pvHighW, loadLow)
				if i == faultTick {
					_ = d.mqttInject(topicCSIPControl, fmt.Sprintf(`{"source":"none","ts":%d}`, 1), true)
				}
			},
			evaluate: diagnoseMalform,
			teardown: func(d *mayhemDriver) { _ = d.mqttReset() },
		},
		func() *mayScenario {
			// Closure state: the running hub's actual client ID (read at
			// setup, since a bench override would make squatting the
			// compiled-in default a silent no-op) and the TASK-044 reconnect
			// counter before/after the storm — captured here because run()
			// calls teardown before evaluate, so a value teardown sets is
			// already visible when evaluate reads it.
			var clientID string
			var reconnectBefore, reconnectAfter float64
			var beforeOK, afterOK bool
			return &mayScenario{
				ID: "duplicate-client-id", Name: "A second process squats the hub's MQTT client ID",
				Category:   "Identity/topology (INV-CONNECT/INV-EXPORT)",
				Hypothesis: "A stale unit on the old dev kit, or a duplicate hub deploy, CONNECTs to the broker using lexa-hub's own MQTT client ID (a plausible operator error) — the broker evicts whichever session held it first, both flap, and control outputs risk interleaving (GAP-06 / review §9 identity family).",
				Expected:   "Keep enforcing the cap through the storm, never let an interleaved/contradictory actuation reach a device, and surface the storm via a reconnect-rate alarm/metric.",
				HoldS:      90,
				Fix:        "Give every lexa-hub instance a unique per-deployment client ID and add a broker ACL that refuses a duplicate CONNECT (TASK-013/014, post-hardening).",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					if err := d.hubSSH("true"); err != nil {
						return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
					}
					if err := d.mqttproxyProbe(); err != nil {
						return nil, err
					}
					id, err := d.hubMQTTClientID()
					if err != nil {
						return nil, fmt.Errorf("cannot determine the running hub's MQTT client ID: %w", err)
					}
					clientID = id
					reconnectBefore, beforeOK = d.readMetricCounter("lexa_mqtt_reconnects_total")
					return armCap(d, "mayhem: duplicate-client-ID cap")
				},
				perTick: func(d *mayhemDriver, i int) {
					d.injectEnv(d.pvHighW, loadLow)
					if i == 15 { // cap adopted and settled; now the collision starts
						id, holdS := clientID, 40 // ≤ maxHoldDurationS(45): self-cancels even if teardown is skipped
						go func() {
							if err := d.holdClientID(id, holdS); err != nil {
								log.Printf("mayhem: duplicate-client-id: holdClientID: %v", err)
							}
						}()
					}
				},
				evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
					return diagnoseDuplicateClientID(reconnectBefore, reconnectAfter, beforeOK && afterOK)(sc, cons, s)
				},
				teardown: func(d *mayhemDriver) {
					if v, ok := d.readMetricCounter("lexa_mqtt_reconnects_total"); ok {
						reconnectAfter, afterOK = v, true
					}
					_ = d.mqttReset() // cancels the /hold if still active; the bounded duration is the safety net
					time.Sleep(5 * time.Second)
					var status map[string]any
					if err := d.getJSON("hub", "/status", &status); err != nil {
						log.Printf("mayhem: duplicate-client-id: hub did not answer /status cleanly after teardown: %v", err)
					}
					d.deleteControls(0)
				},
			}
		}(),
		func() *mayScenario {
			// Closure state: TASK-044's publish-failure counter before/after
			// the storm (teardown-before-evaluate ordering, same as above).
			var failBefore, failAfter float64
			var beforeOK, afterOK bool
			const counterName = "lexa_mqtt_publish_failures_total"
			return &mayScenario{
				ID: "mqtt-storm", Name: "MQTT flood pressures the broker's queue mid-cap",
				Category:   "Bus backpressure (INV-EXPORT survivability)",
				Hypothesis: "A chatty/faulty publisher floods the bus (~1500 msg/s) while a zero-export cap is active, pressuring mosquitto's max_queued_messages(1000)/max_inflight_messages(20) bounds (GAP-10 / review §9 load family).",
				Expected:   "The control path stays responsive — the cap holds, the hub keeps adopting/enforcing, and overflow is COUNTED rather than silently starving control.",
				HoldS:      80,
				Fix:        "TASK-046 (async/bounded publishes) is the load-side hardening; if the cap is lost under the flood, the tick loop is blocking on a synchronous publish wait instead of a bounded one.",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					if err := d.mqttproxyProbe(); err != nil {
						return nil, err
					}
					failBefore, beforeOK = d.readMetricCounter(counterName)
					return armCap(d, "mayhem: cap under an MQTT storm")
				},
				perTick: func(d *mayhemDriver, i int) {
					d.injectEnv(d.pvHighW, loadLow)
					if i == 8 { // cap established and settled; now the flood starts
						go func() {
							// Non-control noise topic — bus PRESSURE is the point,
							// not forging control (that's mqtt-malformed-control /
							// mqtt-stale-retained). QoS 0 at max volume, capped by
							// mqttproxy's /storm param limits (rate_hz ≤ 2000,
							// duration_s ≤ 30) so an aborted run's flood ends on
							// its own.
							if err := d.mqttStorm("lexa/measurements/storm-noise", 1500, 25, 256); err != nil {
								log.Printf("mayhem: mqtt-storm: mqttStorm: %v", err)
							}
						}()
					}
				},
				evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
					return diagnoseMqttStorm(counterName, failBefore, failAfter, beforeOK && afterOK)(sc, cons, s)
				},
				teardown: func(d *mayhemDriver) {
					if v, ok := d.readMetricCounter(counterName); ok {
						failAfter, afterOK = v, true
					}
					_ = d.mqttReset()           // cancels the storm if still active; the bounded duration is the safety net
					time.Sleep(5 * time.Second) // let the queue drain before the next scenario
					d.deleteControls(0)
				},
			}
		}(),
		func() *mayScenario {
			// Closure state: the setup-quality assertion result from the
			// rollback goroutine (spawned from perTick, so it races the
			// ongoing sampling loop — guarded by mu, unlike the
			// duplicate-client-id/mqtt-storm closures above, whose
			// before/after counters are only ever written from teardown,
			// which runs strictly after the hold loop stops).
			var mu sync.Mutex
			var rollbackErr error
			setRollbackErr := func(err error) {
				mu.Lock()
				rollbackErr = err
				mu.Unlock()
			}
			getRollbackErr := func() error {
				mu.Lock()
				defer mu.Unlock()
				return rollbackErr
			}
			return &mayScenario{
				ID: "power-cut-retained-rollback", Name: "Unclean broker death resurrects a superseded retained control",
				Category:   "Bus persistence (INV-EXPORT ground truth)",
				Hypothesis: "GAP-01: mosquitto's autosave_interval(60) + a power cut can resurrect a control up to 60 s stale on reboot. This models the software-only equivalent — SIGKILL mosquitto (bypassing the on-shutdown store flush) and restore an aged clean-stop snapshot — so the broker comes back serving a SUPERSEDED retained lexa/csip/control (cap A, 5000 W) instead of the real current one (cap B, 0 W), at the same instant a site power-cut would also take the WAN down and restart the hub.",
				Expected:   "TASK-042's adoption-time staleness bound must reject the resurrected stale control rather than adopting it as authoritative, and a fresh walk (or the rewalk re-request path) must re-establish cap B once the WAN returns — never a sustained export above cap B's limit with no alarm.",
				HoldS:      110,
				Fix:        "lexa-hub's retained-control staleness bound (adoption-time Ts vs a bound, TASK-042) must reject a resurrected control whose Ts predates the last-known-good one; on rejection it must alarm and request re-walk (lexa/csip/rewalk) rather than silently trusting whatever the broker happens to be serving on reboot.",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					// SSH probe first: this scenario cannot manipulate (or
					// safely restore) the broker's store without it, and
					// INCONCLUSIVE beats risking a store nobody can clean up.
					if err := d.hubSSH("true"); err != nil {
						return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
					}
					_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
					d.injectEnv(d.pvHighW, 250.0)
					// Cap A: a real but LOOSE cap (5000 W), distinguishable
					// from both "no control" and from cap B (0 W) — this is
					// the value the rollback must resurrect.
					if _, err := d.postCap("exportCap", 5000, 110, "mayhem: power-cut rollback cap A (5000 W, superseded)"); err != nil {
						return nil, fmt.Errorf("post cap A: %w", err)
					}
					if !d.waitForAdoptedExportCap(5000, 10*time.Second) {
						log.Printf("mayhem: power-cut-retained-rollback: cap A not observed adopted within 10s of setup; proceeding anyway (snapshot may not capture it)")
					}
					// The store now holds retained cap A. Snapshot it via a
					// CLEAN stop (flush-on-shutdown) — only a clean stop
					// produces a trustworthy point-in-time copy.
					if err := d.brokerSnapshot(); err != nil {
						return nil, fmt.Errorf("broker snapshot (clean stop/cp/start) failed: %w", err)
					}
					// Cap B: the constraint this scenario is actually judged
					// against. A≠B (5000 vs 0) is the assertion that makes a
					// misordered/no-op rollback detectable below.
					d.deleteControls(0)
					cons, err := d.postCap("exportCap", 0, 110, "mayhem: power-cut rollback cap B (0 W, judged)")
					if err != nil {
						return nil, fmt.Errorf("post cap B: %w", err)
					}
					return cons, nil
				},
				perTick: func(d *mayhemDriver, i int) {
					d.injectEnv(d.pvHighW, 250.0)
					if i == 30 { // cap B adopted and settled
						// The outage MUST be armed BEFORE the rollback: if a
						// northbound walk fires in the gap, cap B is
						// republished over the resurrected cap A and the
						// scenario would silently no-op-pass. This call is
						// synchronous (a single fast HTTP POST) and completes
						// before the goroutine below even starts running.
						_ = d.gridsimOutage(gridsimOutageDown, 30, 0) // a site power cut takes the WAN down too — router still booting
						go func() {
							if err := d.brokerUncleanRollback(); err != nil {
								setRollbackErr(fmt.Errorf("unclean broker rollback (SIGKILL+restore+start) failed: %w", err))
								return
							}
							// Give mosquitto a moment to finish coming back
							// (and every lexa service to reconnect) before
							// probing it or restarting the hub — SIGKILL
							// severs every session at once; too tight a gap
							// here skews the hub's own connect-retry timing
							// (mqttutil.go, 5 s interval / 30 s timeout).
							time.Sleep(3 * time.Second)
							// Setup-quality assertion (error ⇒ INCONCLUSIVE,
							// not a verdict on the hub): confirm the bus is
							// actually serving the resurrected stale cap A
							// before the hub is judged against it.
							if v, err := d.brokerRetainedExpLimW(); err != nil {
								setRollbackErr(fmt.Errorf("could not confirm the retained control after rollback: %w", err))
							} else if math.Abs(v-5000) > 1 {
								setRollbackErr(fmt.Errorf("expected the resurrected retained control to read cap A (5000 W); observed %.0f W — rollback/misordering was not reproduced as designed", v))
							}
							// A power cut restarts the hub too — this is what
							// makes the hub re-seed its retained-control view
							// from the (now resurrected, stale) store.
							if err := d.hubSSH("sudo systemctl restart lexa-hub"); err != nil {
								log.Printf("mayhem: power-cut-retained-rollback: hub restart: %v", err)
							}
						}()
					}
				},
				evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
					if err := getRollbackErr(); err != nil {
						f := baseFinding(sc)
						f.Verdict = "INCONCLUSIVE"
						f.Headline = "setup-quality assertion failed: could not confirm the rollback resurrected cap A before judging the hub"
						f.Diagnosis = []string{err.Error()}
						return f
					}
					return diagnosePowerCutRollback(sc, cons, s)
				},
				teardown: func(d *mayhemDriver) {
					d.gridsimOutageClear()
					_ = d.mqttReset()
					d.brokerCleanup()
					d.deleteControls(0)
				},
			}
		}(),
		func() *mayScenario {
			// diagnoseSurvival/diagnoseRecovery-style suppressDefault
			// closure: without it, a hub that lost track of cap B after the
			// corruption+restart could fall back to the program-0
			// DefaultDERControl (5 kW cap, ≈4.4 kW ceiling) rather than being
			// truly unconstrained, which would understate the failure this
			// scenario exists to catch (see suppressDefault's doc comment).
			var restoreDefault func()
			return &mayScenario{
				ID: "corrupted-retained-control", Name: "Rogue publisher writes truncated JSON to the retained CSIP control",
				Category:   "Bus persistence (fail-closed survivability)",
				Hypothesis: "GAP-02: Subscribe[T]'s decode-failure path used to log-and-drop a truncated retained lexa/csip/control with no re-request — the hub would run control-less until the next walk happened to republish. This combines that corruption with a WAN outage AND a hub restart: the hub re-seeds its retained-control view from the corrupt payload while there is no live server to walk. mqtt-malformed-control does not cover this — it injects the corruption while the hub is RUNNING and holding last-good in RAM; this scenario injects it across a restart with the WAN dark, the combination TASK-042's rewalk re-request path exists for.",
				Expected:   "TASK-042: the hub's decode-failure alarm fires and it publishes lexa/csip/rewalk; northbound answers by republishing the cached last-good control with a fresh Ts and walking immediately — restoring the cap within seconds, without waiting on the WAN or the next scheduled walk. Without 042: the hub runs with NO control until the WAN returns and the next walk republishes — sustained uncapped export (GAP-02).",
				HoldS:      100,
				Fix:        "TASK-042: on decode failure of a retained control-plane message, alarm + request re-publish (lexa/csip/rewalk) instead of silently running without a control until the next scheduled walk.",
				setup: func(d *mayhemDriver) (*activeConstraint, error) {
					if err := d.hubSSH("true"); err != nil {
						return nil, fmt.Errorf("hub SSH unavailable (need key auth to the hub Pi): %w", err)
					}
					// d.mqttReset() doubles as the mqttproxy presence probe:
					// a missing/undeployed proxy errors here rather than
					// silently no-opping the /inject call in perTick.
					if err := d.mqttReset(); err != nil {
						return nil, fmt.Errorf("mqttproxy unreachable (need scripts/mqtt-chaos.sh deploy): %w", err)
					}
					restoreDefault = d.suppressDefault()
					_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
					d.injectEnv(d.pvHighW, 250.0)
					cons, err := d.postCap("exportCap", 0, 100, "mayhem: export cap ahead of a corrupted retained control")
					if err != nil {
						return nil, err
					}
					if !d.waitForAdoptedExportCap(0, 10*time.Second) {
						log.Printf("mayhem: corrupted-retained-control: cap not observed adopted within 10s of setup; proceeding anyway")
					}
					return cons, nil
				},
				perTick: func(d *mayhemDriver, i int) {
					d.injectEnv(d.pvHighW, 250.0)
					switch i {
					case 15: // cap adopted and settled; the WAN goes dark — walks fail, northbound must hold fail-closed
						_ = d.gridsimOutage(gridsimOutageDown, 45, 0)
					case 18:
						// TASK-013 note: /inject now authenticates as the
						// qa-inject broker user (mqttproxy -user/-passfile,
						// provisioned by scripts/mqtt-chaos.sh deploy) since
						// the hub broker's ACL requires credentials; an
						// undeployed/un-provisioned proxy fails this call
						// and mqttInject's error is logged, never silently
						// swallowed into a false PASS.
						if err := d.mqttInject(topicCSIPControl, `{"source":"event","exp_lim_w":`, true); err != nil {
							log.Printf("mayhem: corrupted-retained-control: mqttInject: %v", err)
						}
					case 21:
						// The hub re-seeds its retained-control view from the
						// corrupt payload while the WAN is still dark.
						go func() {
							if err := d.hubSSH("sudo systemctl restart lexa-hub"); err != nil {
								log.Printf("mayhem: corrupted-retained-control: hub restart: %v", err)
							}
						}()
					}
				},
				evaluate: diagnoseSurvival("the corrupted retained control"),
				teardown: func(d *mayhemDriver) {
					d.gridsimOutageClear()
					_ = d.mqttReset()
					if restoreDefault != nil {
						restoreDefault()
					}
					d.deleteControls(0)
				},
			}
		}(),
	}
}
