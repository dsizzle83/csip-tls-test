package main

import "fmt"

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

// mqttReset returns the proxy to transparent pass mode.
func (d *mayhemDriver) mqttReset() error {
	return d.post("mqttproxy", "/reset", map[string]any{})
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
			ID: "mqtt-malformed-control", Name: "Malformed retained CSIP control on the bus",
			Category:   "Bus robustness (INV-EXPORT survivability)",
			Hypothesis: "A truncated/garbage JSON payload is published RETAINED to lexa/csip/control (a half-written message, a buggy publisher) while a real cap is active.",
			Expected:   "Stay up and keep the active cap: a malformed bus message must be dropped, never crash the hub or unseat a safe control.",
			HoldS:      70,
			Fix:        "Hub MQTT handlers must reject a payload that fails to unmarshal and retain the last-good control (cmd/hub onCSIPControl).",
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
	}
}
