package main

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	}
}
