// Track C — advanced-DER reconciler + CSIP-AUS Mayhem scenarios
// (docs/QA_STANDARDS_BUILDOUT.md). New file per that doc's "Merge discipline"
// section: scenarios live in advScenarios() below, new oracles in this same
// file. This file does NOT edit scenarios() or oracleRegistry — see the
// comment block at the very end for the exact reviewer-append lines.
//
// Covers two invariants:
//
//	INV-ADV-READBACK — advanced-DER curve/PF/energize provisioning trusts
//	                    MEASURED READBACK, not the write/adopt handshake.
//	                    Shadow mode does ZERO writes.
//	INV-AUS          — the CSIP-AUS gross-generation/gross-load caps
//	                    (opModGenLimW/opModLoadLimW) hold with the measured-
//	                    effect convergence backstop when enforced; the shadow
//	                    copies stay wired without diverging from the live
//	                    cascade when both run the same behavior.
//
// # Bench-runnable preconditions (read this before running any of these)
//
// Track A precondition (all five scenarios): the sim target "solar" must be
// launched as `modsim -advanced` (sim/modsim/main.go's -advanced flag) — a
// plain modsim serves none of the SunSpec 7xx models these scenarios drive.
// Each scenario's setup() probes the solar sim's own GET /state for the
// additive "advanced" object and fails to INCONCLUSIVE (not a false PASS) if
// it is absent — see requireAdvSolarSim.
//
// adv-shadow-no-writes / curve-adopt-readback-divergence /
// pf-var-measured-convergence — a SECOND, hub-config precondition, checked
// over SSH the same way pairingGateHoldScenario/requireOCPP16Evsim
// (mayhem_ocpp_openadr.go) already check a live bench config key:
//
//   - modbus.json's "reconciler":{"adv": ...} must be "shadow" (scenario 1)
//     or "active" (scenarios 2/3) — this is a lexa-modbus-side flag,
//     independent of hub.json's advanced_der.
//   - curve-adopt-readback-divergence / pf-var-measured-convergence
//     ADDITIONALLY need the target device's modbus.json entry to carry
//     "der_gen": "7xx" (WP-10's axisSupported execution-truth gate — see
//     reconcile_adv.go's derGen switch: "7xx" is required before ANY curve
//     or fixed-PF/var axis is even considered supported). adv-shadow-no-
//     writes does NOT need this: executeLocked's shadow branch returns
//     (wouldWrites.Inc(); return) BEFORE ever reading capability, so a
//     shadow shell would-write regardless of der_gen.
//
// DESIGN DECISION — these three scenarios deliberately BYPASS cmd/hub's
// WP-9 desired-adv author (advanced_der:"on", ActiveControl+CurveSet
// correlation, per-device der_gen on hub.json, D7 arbitration) and inject a
// synthetic lexa/desired/adv/{device} document directly onto the retained
// bus topic via mqttInject — the SAME "bypass the upstream producer, test
// the downstream consumer in isolation" technique mqtt_scenarios.go's
// topicCSIPControl scenarios and mayhem_ocpp_openadr.go's ev-setpoint-clamp/
// openadr-limit-adopt already use. This is a deliberate scoping choice, not
// an oversight: it isolates WP-10 (the file this track was asked to
// validate) from WP-9's arbitration chain, and removes the need for
// hub.json's advanced_der/der_gen to be set at all for scenarios 1-3 (only
// modbus.json's reconciler.adv + der_gen matter). WP-9's own authoring logic
// is out of scope for this track.
//
// aus-gen-cap / aus-load-cap — hub.json's "enforce_aus_limits" must be true
// (checked over SSH, requireEnforceAusLimits) for the cascade rule
// (internal/orchestrator/auslimits.go) to ACT on an adopted opModGenLimW/
// opModLoadLimW; the limit is otherwise adopted into GridState unconditionally
// but never enforced. UNLIKE the other three scenarios, these two scenarios
// do NOT need a bus-injection bypass: gridsim's /admin/control ALREADY
// accepts gen_lim_W/load_lim_W (sim/gridsim/admin.go's adminCtrlReq, wired
// straight through to DERControlBase.OpModGenLimW/OpModLoadLimW), and
// lexa-northbound's publish/publish.go already decodes OpModGenLimW/
// OpModLoadLimW into bus.ActiveControl.GenLimW/LoadLimW (WP-8). So the REAL
// end-to-end path — gridsim DERControl → northbound discovery walk →
// ActiveControl → the legacy cascade rule — is exercisable today. This
// contradicts the task brief's assumption that opModGenLimW/LoadLimW
// injection might not exist yet; it does, and these two scenarios test the
// real enforcement path rather than scoping down to shadow-only.
//
// One observability gap surfaced while building this: lexa-api's GET /status
// (cmd/api/handlers.go's csipControlInfo/adminBaseInfo-equivalent) does not
// surface GenLimW/LoadLimW at all — only ExpLimW/MaxLimW/ImpLimW/Connect/
// FixedW. There is therefore no HTTP-visible way to directly confirm the hub
// ADOPTED a gen/load cap; these oracles instead read the plan's own
// "csip-aus/gen-limit"/"csip-aus/load-limit" AddDecision lines (already
// surfaced via hubState()'s LastPlan.Decisions → maySample.Decisions) as the
// adoption/enforcement-engaged signal, and ground-truth gross generation/load
// (solar+battery / solar+battery+meter) for the compliance judgement itself.
//
// A second gap: lexa_constraint_shadow_divergence_total (CLAUDE.md's
// constraint-shadow harness) is a SINGLE aggregate counter, not broken out
// per constraint key — there is no way to attribute a divergence specifically
// to "gen_aus" or "load_aus" from the metrics surface alone. The AUS
// oracles below read it purely as an informational secondary signal
// (before/after delta, logged as a diagnosis bullet, never affecting the
// verdict) and say so explicitly.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// advTargetDevice is the lexa-modbus device name these scenarios assume for
// Track A's "solar" simulator target — matching configs/modbus.json's shipped
// example ("inverter-0", url tcp://<solar-pi>:5020, der_gen:"7xx"). This is a
// bench-topology ASSUMPTION, not something this driver can otherwise probe
// (the "solar" backend key is the simulator's own HTTP API, unrelated to what
// name lexa-modbus's config gives the Modbus device polling it); if a bench
// renames the device, every scenario in this file needs the constant updated
// to match.
const advTargetDevice = "inverter-0"

// ── Scenario battery ─────────────────────────────────────────────────────────

func (d *mayhemDriver) advScenarios() []*mayScenario {
	return []*mayScenario{
		advShadowNoWritesScenario(),
		curveAdoptReadbackDivergenceScenario(),
		pfVarMeasuredConvergenceScenario(),
		ausGenCapScenario(),
		ausLoadCapScenario(),
	}
}

// ── Preconditions (SSH-probed) ────────────────────────────────────────────────

// requireAdvSolarSim is the Track A precondition every scenario in this file
// shares: the solar sim's GET /state must carry the additive "advanced"
// object (sim/southbound/solar.go's SolarState.Advanced, nil unless the sim
// was constructed via NewSolarServerAdvanced — i.e. `modsim -advanced`).
func requireAdvSolarSim(d *mayhemDriver) error {
	if _, ok := d.solarAdvancedState(); !ok {
		return fmt.Errorf(`solar sim's GET /state has no "advanced" block — this scenario needs the bench solar simulator launched as "modsim -advanced" (sim/modsim/main.go's -advanced flag, QA track A), which serves the SunSpec 7xx models (701/702/704/705/706/711/712) this scenario drives; a plain modsim serves none of them and this scenario cannot run`)
	}
	return nil
}

// modbusReconcilerAdvModeCommand builds the SSH probe for modbus.json's
// reconciler.adv value — the same grep -o config-key idiom hubMQTTClientID
// (mqtt_scenarios.go) and pairingGateHoldScenario (mayhem_ocpp_openadr.go)
// already use.
func modbusReconcilerAdvModeCommand() string {
	return `grep -o '"adv"[[:space:]]*:[[:space:]]*"[a-z]*"' /etc/lexa/modbus.json 2>/dev/null; true`
}

// modbusReconcilerAdvMode reads the deployed modbus.json's reconciler.adv
// value over SSH. Absent key ⇒ "off" (modbus.json's documented default,
// cmd/modbus/config.go).
func (d *mayhemDriver) modbusReconcilerAdvMode() (string, error) {
	out, err := d.hubSSHOutput(modbusReconcilerAdvModeCommand())
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "" {
		return "off", nil
	}
	return parseMQTTClientIDLine(out) // generic "key": "value" grep-line parser (mqtt_scenarios.go)
}

// requireModbusReconcilerAdvMode fails setup to INCONCLUSIVE when the
// deployed modbus.json's reconciler.adv is not want. SSH failure is NOT
// treated as a hard mismatch — mirrors requireOCPP16Evsim's soft fallback: an
// operator who knows their own bench config is not blocked by an unreachable
// probe, but the run is loudly logged as unverified.
func requireModbusReconcilerAdvMode(d *mayhemDriver, want, scenarioID string) error {
	mode, err := d.modbusReconcilerAdvMode()
	if err != nil {
		log.Printf("mayhem: %s: could not confirm modbus.json's reconciler.adv mode over SSH (%v) — proceeding on the DOCUMENTED PRECONDITION that the bench has reconciler.adv=%q; if it does not, this scenario's verdict is meaningless", scenarioID, err, want)
		return nil
	}
	if mode != want {
		return fmt.Errorf("bench modbus.json has reconciler.adv=%q, not %q — %s requires the deployed /etc/lexa/modbus.json to set reconciler.adv=%q for device %q (docs/QA_STANDARDS_BUILDOUT.md's INV-ADV-READBACK precondition); hand-set it and restart lexa-modbus (CLAUDE.md's reconciler-flip discipline), then re-run", mode, want, scenarioID, want, advTargetDevice)
	}
	return nil
}

// derGen7xxCommand probes for ANY "der_gen":"7xx" entry in modbus.json — a
// COARSE check (not scoped to advTargetDevice specifically; a simple grep -o
// cannot correlate a JSON array element back to its sibling "name" key). Given
// only inverter/battery roles carry der_gen and Track A's solar fixture is the
// only advanced-DER-capable sim on this bench, "some device is 7xx" is a
// reasonable proxy for "advTargetDevice is 7xx" — documented as coarse rather
// than silently assumed exact.
func derGen7xxCommand() string {
	return `grep -o '"der_gen"[[:space:]]*:[[:space:]]*"7xx"' /etc/lexa/modbus.json 2>/dev/null; true`
}

func (d *mayhemDriver) modbusHasDERGen7xx() (bool, error) {
	out, err := d.hubSSHOutput(derGen7xxCommand())
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

func requireModbusDERGen7xx(d *mayhemDriver, scenarioID string) error {
	ok, err := d.modbusHasDERGen7xx()
	if err != nil {
		log.Printf("mayhem: %s: could not confirm modbus.json's der_gen over SSH (%v) — proceeding on the documented precondition that %q is der_gen=\"7xx\"", scenarioID, err, advTargetDevice)
		return nil
	}
	if !ok {
		return fmt.Errorf(`bench modbus.json has no device with der_gen:"7xx" — %s requires %q configured der_gen="7xx" (WP-10's axisSupported execution-truth gate, cmd/modbus/config.go) so the curve/fixed-PF axes are not reported unsupported; this is a COARSE check (any 7xx device in the file, not scoped to %q by name) — verify /etc/lexa/modbus.json by hand if this scenario instead reports adopt_state=unsupported`, scenarioID, advTargetDevice, advTargetDevice)
	}
	return nil
}

// enforceAusLimitsCommand probes hub.json's enforce_aus_limits bool.
func enforceAusLimitsCommand() string {
	return `grep -o '"enforce_aus_limits"[[:space:]]*:[[:space:]]*[a-z]*' /etc/lexa/hub.json 2>/dev/null; true`
}

// parseBoolFieldLine extracts the boolean value from a grep -o match of the
// form `"key": true` / `"key":false` (whitespace around the colon may vary) —
// pulled out so the parsing is unit-testable without SSH, mirroring
// parseMQTTClientIDLine/parseCount's pattern.
func parseBoolFieldLine(line string) (bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return false, fmt.Errorf("empty line")
	}
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		return false, fmt.Errorf("could not parse a bool field from %q", line)
	}
	v := strings.TrimSpace(line[idx+1:])
	if v != "true" && v != "false" {
		return false, fmt.Errorf("unrecognized bool value %q in %q", v, line)
	}
	return v == "true", nil
}

func (d *mayhemDriver) hubEnforceAusLimits() (bool, error) {
	out, err := d.hubSSHOutput(enforceAusLimitsCommand())
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(out) == "" {
		return false, nil // absent ⇒ hub.json's documented default (false)
	}
	return parseBoolFieldLine(out)
}

func requireEnforceAusLimits(d *mayhemDriver, scenarioID string) error {
	on, err := d.hubEnforceAusLimits()
	if err != nil {
		log.Printf("mayhem: %s: could not confirm hub.json's enforce_aus_limits over SSH (%v) — proceeding on the documented precondition that the bench hub.json has enforce_aus_limits:true", scenarioID, err)
		return nil
	}
	if !on {
		return fmt.Errorf(`bench hub.json has enforce_aus_limits:false (or absent) — %s requires the deployed /etc/lexa/hub.json to set "enforce_aus_limits": true (WP-11, docs/QA_STANDARDS_BUILDOUT.md's INV-AUS precondition); the limit is still ADOPTED into GridState either way, but the cascade rule that ACTS on it (internal/orchestrator/auslimits.go) is flag-gated off by default — hand-set the flag and restart lexa-hub, then re-run`, scenarioID)
	}
	return nil
}

// ── Solar-advanced sim state (ground truth) ──────────────────────────────────

// advSolarState mirrors sim/southbound/solar.go's SolarAdvancedState JSON
// shape (this repo cannot import that package's types across module
// boundaries, so — matching topicCSIPControl/topicIntentMode's precedent —
// this is a hand-kept local twin of the wire shape).
type advSolarState struct {
	Meas701 struct {
		WW     float64 `json:"W_W"`
		PF     float64 `json:"PF"`
		VArVar float64 `json:"VAr_var"`
	} `json:"meas_701"`
	FixedPF struct {
		Ena bool    `json:"ena"`
		PF  float64 `json:"pf"`
	} `json:"fixed_pf"`
	FixedVar struct {
		Ena bool    `json:"ena"`
		Pct float64 `json:"pct"`
	} `json:"fixed_var"`
	Ceiling704 struct {
		Ena bool    `json:"ena"`
		Pct float64 `json:"pct"`
	} `json:"wmaxlimpct_704"`
	Curves []struct {
		Model     uint16       `json:"model"`
		AdoptRslt int          `json:"adopt_rslt"`
		ReadOnly  bool         `json:"read_only"`
		Points    [][2]float64 `json:"points"`
	} `json:"curves"`
}

// solarAdvancedState reads the solar sim's /state and decodes the additive
// "advanced" object. ok=false when the field is absent (a non-advanced sim —
// see requireAdvSolarSim) or the sim is unreachable.
func (d *mayhemDriver) solarAdvancedState() (advSolarState, bool) {
	var st struct {
		Advanced *advSolarState `json:"advanced"`
	}
	if err := d.getJSON("solar", "/state", &st); err != nil || st.Advanced == nil {
		return advSolarState{}, false
	}
	return *st.Advanced, true
}

// advWriteSurfaceEqual compares only the DEVICE-COMMAND ground truth (curve
// live points/adopt results, 704 fixed-PF/fixed-var/ceiling command
// registers) — the surface a real Modbus WRITE would change. Meas701 is
// deliberately excluded: it is the MEASUREMENT mirror, refreshed every
// animation tick regardless of any write (temperature/Hz/etc. drift is
// expected background noise, not evidence of a write landing).
func advWriteSurfaceEqual(a, b advSolarState) bool {
	return reflect.DeepEqual(a.Curves, b.Curves) &&
		a.FixedPF == b.FixedPF &&
		a.FixedVar == b.FixedVar &&
		a.Ceiling704 == b.Ceiling704
}

// ── Fault injection (solar sim only — Track A's three 7xx fault knobs) ──────

func (d *mayhemDriver) armSolarAdvFault(kind string) error {
	return d.post("solar", "/fault", map[string]any{"kind": kind})
}

func (d *mayhemDriver) clearSolarAdvFault(kind string) error {
	return d.post("solar", "/fault", map[string]any{"kind": kind, "clear": true})
}

// ── Desired-adv bus injection (bypasses cmd/hub's WP-9 author — see file doc)

// desiredAdvTopic mirrors lexa-hub internal/bus.DesiredAdvTopic exactly
// (kept as a local literal builder, like topicCSIPControl/topicIntentMode —
// this repo does not import lexa-hub's internal/bus package).
func desiredAdvTopic(device string) string { return "lexa/desired/adv/" + device }

// reconcileAdvReportTopic mirrors bus.ReconcileReportTopic("adv", device).
func reconcileAdvReportTopic(device string) string {
	return fmt.Sprintf("lexa/reconcile/adv/%s/report", device)
}

// advCurveSetContentHash mirrors bus.CurveSetContentHash's canonicalization
// EXACTLY (curves.go, WP-8, pinned by lexa-hub's own
// TestCurveSetContentHash_Pinned): a single-entry line
// "mode|curveType|xMult|yMult|yRefType|x1,y1;x2,y2;...;\n", SHA-256, lowercase
// hex. This MUST match bit-for-bit: the hub's own reconciler shell
// (reconcile_adv.go's readbackHashVV) recomputes this same hash from the
// device's readback plus the doc's own CurveType/XMult/YMult/YRefType — for
// an actually-adopted curve, that recomputed hash must equal the "hash" field
// this function stamps into the injected doc.
func advCurveSetContentHash(mode string, curveType uint16, xMult, yMult int8, yRefType uint8, points [][2]int32) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%d|%d|%d|", mode, curveType, xMult, yMult, yRefType)
	for _, p := range points {
		fmt.Fprintf(h, "%d,%d;", p[0], p[1])
	}
	h.Write([]byte("\n"))
	return hex.EncodeToString(h.Sum(nil))
}

// Test curve/PF constants shared by the payload builders below. XMult/YMult
// are 0 so advRaw's readback round-trip (reconcile_adv.go) is exact — no
// scale-factor rounding to muddy a genuine divergence with a quantization
// false-positive.
const (
	advCurveTypeTest = 1 // opaque csipmodel.CurveType*; doesn't affect the SunSpec register write, only echoed into the hash both sides compute — see advCurveSetContentHash's doc.
	advCurveXMult    = 0
	advCurveYMult    = 0
)

func advCurveTestPoints() [][2]int32 { return [][2]int32{{100, 50}, {200, -50}} }

func advCurvePointsJSON(points [][2]int32) string {
	parts := make([]string, len(points))
	for i, p := range points {
		parts[i] = fmt.Sprintf(`{"x":%d,"y":%d}`, p[0], p[1])
	}
	return strings.Join(parts, ",")
}

// desiredAdvVoltVarPayload builds a bus.DesiredAdvanced wire document (see
// internal/bus/desired_adv.go in lexa-hub) commanding a single volt-var curve
// via ReactiveMode — the axis curve-adopt-readback-divergence/
// adv-shadow-no-writes drive.
func desiredAdvVoltVarPayload(device, mrid string, issuedAt int64) string {
	pts := advCurveTestPoints()
	hash := advCurveSetContentHash("volt_var", advCurveTypeTest, advCurveXMult, advCurveYMult, 0, pts)
	return fmt.Sprintf(
		`{"v":1,"device_class":"solar","device_id":%q,`+
			`"reactive_mode":{"kind":"volt_var","curve":{"curve_type":%d,"x_mult":%d,"y_mult":%d,"points":[%s],"hash":%q}},`+
			`"volt_watt":null,"freq_watt":null,"freq_droop":null,"trips":null,"energize":null,`+
			`"source":"csip-event","mrid":%q,"issued_at":%d,"seq":1}`,
		device, advCurveTypeTest, advCurveXMult, advCurveYMult, advCurvePointsJSON(pts), hash, mrid, issuedAt)
}

// desiredAdvFixedPFPayload builds a DesiredAdvanced doc commanding a fixed
// power factor via ReactiveMode — the axis pf-var-measured-convergence
// drives.
func desiredAdvFixedPFPayload(device, mrid string, pf float64, overExcited bool, issuedAt int64) string {
	return fmt.Sprintf(
		`{"v":1,"device_class":"solar","device_id":%q,`+
			`"reactive_mode":{"kind":"fixed_pf","fixed_pf":{"pf":%g,"over_excited":%t}},`+
			`"volt_watt":null,"freq_watt":null,"freq_droop":null,"trips":null,"energize":null,`+
			`"source":"csip-event","mrid":%q,"issued_at":%d,"seq":1}`,
		device, pf, overExcited, mrid, issuedAt)
}

// desiredAdvReleasePayload builds the all-null release doc used at teardown
// (fresh, strictly-later issued_at — AD-013 rule 2 accepts a lower/reset seq
// with a strictly newer issued_at as a publisher-restart — same discipline as
// ev-setpoint-clamp's teardown release in mayhem_ocpp_openadr.go) so the
// injected command doesn't linger retained into whatever adv scenario runs
// next in this file.
func desiredAdvReleasePayload(device string, issuedAt int64) string {
	return fmt.Sprintf(
		`{"v":1,"device_class":"solar","device_id":%q,`+
			`"reactive_mode":null,"volt_watt":null,"freq_watt":null,"freq_droop":null,"trips":null,"energize":null,`+
			`"source":"none","issued_at":%d,"seq":2}`,
		device, issuedAt)
}

// ── Reconciler report readback (SSH mosquitto_sub, retained topic) ──────────

// advReportMsg is the subset of bus.ReconcileReport (WP-10 extension) these
// oracles need.
type advReportMsg struct {
	Kind        string `json:"kind"`
	DeviceClass string `json:"device_class"`
	DeviceID    string `json:"device_id"`
	Axis        string `json:"axis"`
	AdoptState  string `json:"adopt_state"`
	CurveHash   string `json:"curve_hash"`
	Ts          int64  `json:"ts"`
}

// advReconcileReportCommand builds the bounded mosquitto_sub retained-read,
// mirroring retainedBatteryDesiredCommand/brokerRetainedControlCommand's exact
// qa-inject-credentials idiom (intent_scenarios.go / mqtt_scenarios.go).
func advReconcileReportCommand(device string) string {
	return fmt.Sprintf(
		`PASS=$(sudo cat %s 2>/dev/null); if [ -z "$PASS" ]; then echo "qa-inject credentials not provisioned (run scripts/mqtt-chaos.sh deploy)" >&2; exit 1; fi; timeout 4 mosquitto_sub -h localhost -p 1883 -u qa-inject -P "$PASS" -C 1 -t '%s' 2>/dev/null ; true`,
		qaInjectPassFile, reconcileAdvReportTopic(device))
}

// advReconcileReport reads the retained per-device adv ReconcileReport.
// present=false means the topic has nothing retained yet (not an error);
// ok=false means the read itself failed (SSH/creds — detection unprovable).
func (d *mayhemDriver) advReconcileReport(device string) (msg advReportMsg, present, ok bool) {
	out, err := d.hubSSHOutput(advReconcileReportCommand(device))
	if err != nil {
		return advReportMsg{}, false, false
	}
	line := strings.TrimSpace(out)
	if line == "" {
		return advReportMsg{}, false, true
	}
	if jerr := json.Unmarshal([]byte(line), &msg); jerr != nil {
		return advReportMsg{}, false, false
	}
	return msg, true, true
}

// advReportWithRetry polls advReconcileReport up to attempts times, wait apart,
// returning the first present read. WP-10 executes a curve/PF write and its
// readback verification SYNCHRONOUSLY within one setDesired() call (bounded by
// derbase.Base.AdoptPollTimeout, ~3s) — this is a small robustness margin
// against MQTT/SSH round-trip jitter, not a wait for a slow convergence.
func advReportWithRetry(d *mayhemDriver, device string, attempts int, wait time.Duration) (advReportMsg, bool, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		msg, present, ok := d.advReconcileReport(device)
		if ok && present {
			return msg, true, nil
		}
		if !ok {
			lastErr = fmt.Errorf("mosquitto_sub read of %s failed (SSH unreachable or qa-inject creds not provisioned)", reconcileAdvReportTopic(device))
		} else {
			lastErr = fmt.Errorf("no retained report yet on %s", reconcileAdvReportTopic(device))
		}
		if i < attempts-1 {
			time.Sleep(wait)
		}
	}
	return advReportMsg{}, false, lastErr
}

// ── lexa-modbus :9103 metrics (TASK-044) ─────────────────────────────────────

// scrapeMetricCounter scrapes a Prometheus text-exposition endpoint at addr
// for the named sample. Local to this file: readMetricCounter
// (mqtt_scenarios.go) hardcodes lexa-hub's :9101; this suite's merge
// discipline is new-file-only, so this is a parameterized twin rather than a
// refactor of that helper.
func (d *mayhemDriver) scrapeMetricCounter(addr, name string) (value float64, ok bool) {
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

// advModbusMetricsAddr derives lexa-modbus's Prometheus /metrics URL (:9103
// per CLAUDE.md's metrics table) from the "hub" backend's host — lexa-modbus
// runs on the same Pi as lexa-hub/lexa-api in this bench topology (mirrors
// hubMetricsAddr's :9101 derivation, mqtt_scenarios.go).
func (d *mayhemDriver) advModbusMetricsAddr() (string, error) {
	base, ok := d.backends["hub"]
	if !ok {
		return "", fmt.Errorf("no hub backend configured")
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("cannot derive hub host from %q", base)
	}
	return "http://" + u.Hostname() + ":9103/metrics", nil
}

func (d *mayhemDriver) readAdvModbusMetric(name string) (float64, bool) {
	addr, err := d.advModbusMetricsAddr()
	if err != nil {
		return 0, false
	}
	return d.scrapeMetricCounter(addr, name)
}

// ── CSIP-AUS gridsim control injection ───────────────────────────────────────

// postAusCap posts a duration-bounded opModGenLimW/opModLoadLimW control to
// program 0 via gridsim's REAL /admin/control endpoint (sim/gridsim/admin.go
// already accepts gen_lim_W/load_lim_W — see the file doc's "AUS gap" note)
// and returns the constraint to judge against. kind is "gen" or "load".
func (d *mayhemDriver) postAusCap(kind string, limW float64, holdS int, desc string) (*activeConstraint, error) {
	body := map[string]any{
		"program":     0,
		"duration_s":  holdS + 20,
		"activate":    true,
		"description": desc,
	}
	typ := ""
	switch kind {
	case "gen":
		body["gen_lim_W"] = int64(limW)
		typ = "genLimitAus"
	case "load":
		body["load_lim_W"] = int64(limW)
		typ = "loadLimitAus"
	default:
		return nil, fmt.Errorf("postAusCap: unknown kind %q", kind)
	}
	mrid, err := d.postControl(body)
	if err != nil {
		return nil, err
	}
	return &activeConstraint{Typ: typ, LimW: limW, MRID: mrid}, nil
}

// ── Scenario 1: adv-shadow-no-writes (INV-ADV-READBACK) ─────────────────────

func advShadowNoWritesScenario() *mayScenario {
	const device = advTargetDevice
	var (
		haveBefore, haveAfter     bool
		before, after             advSolarState
		wouldBefore, wouldAfter   float64
		writesBefore, writesAfter float64
		failBefore, failAfter     float64
		metricsAvailBefore        bool
		metricsAvailAfter         bool
	)
	return &mayScenario{
		ID:         "adv-shadow-no-writes",
		Name:       "Advanced-DER reconciler in shadow mode writes ZERO hardware registers",
		Category:   "Advanced-DER reconciler (INV-ADV-READBACK)",
		Hypothesis: "PRECONDITION: sim target \"solar\" launched with `modsim -advanced` (Track A); bench modbus.json has reconciler.adv=\"shadow\" for " + device + ". This scenario bypasses cmd/hub's WP-9 desired-adv author and injects a synthetic lexa/desired/adv/" + device + " document directly onto the retained bus topic (isolating WP-10's shell) commanding a volt-var curve. In shadow mode the reconciler shell must record the would-be write (verdict + lexa_mb_adv_would_writes_total) and log it, but its executeLocked shadow branch returns before ever touching a driver — see reconcile_adv.go's \"wouldWrites.Inc(); if !s.active() { ...; return }\", which is unreachable via any real write call in shadow mode by construction.",
		Expected:   "Over the hold, the solar sim's advanced /state curve live-points and 704 PF/var/ceiling command registers NEVER change (zero writes landed) even though a curve command was injected, AND the modbus :9103 metrics show lexa_mb_adv_would_writes_total increasing while lexa_mb_adv_writes_total/lexa_mb_adv_write_failures_total stay flat.",
		HoldS:      75,
		Fix:        "cmd/modbus/reconcile_adv.go's advShell.executeLocked — the shadow-mode early return (wouldWrites.Inc(); return) must stay BEFORE any capsLocked()/driver call.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := requireAdvSolarSim(d); err != nil {
				return nil, err
			}
			if err := requireModbusReconcilerAdvMode(d, advModeShadow, "adv-shadow-no-writes"); err != nil {
				return nil, err
			}
			st, ok := d.solarAdvancedState()
			if !ok {
				return nil, fmt.Errorf("solar sim /state: could not read the advanced block at setup")
			}
			before, haveBefore = st, true
			if v, ok := d.readAdvModbusMetric("lexa_mb_adv_would_writes_total"); ok {
				wouldBefore, metricsAvailBefore = v, true
			}
			writesBefore, _ = d.readAdvModbusMetric("lexa_mb_adv_writes_total")
			failBefore, _ = d.readAdvModbusMetric("lexa_mb_adv_write_failures_total")

			mrid := fmt.Sprintf("mayhem-adv-shadow-%d", time.Now().UnixNano())
			payload := desiredAdvVoltVarPayload(device, mrid, time.Now().Unix())
			if err := d.mqttInject(desiredAdvTopic(device), payload, true); err != nil {
				return nil, fmt.Errorf("inject desired-adv curve doc: %w", err)
			}
			return &activeConstraint{Typ: "none"}, nil
		},
		teardown: func(d *mayhemDriver) {
			if st, ok := d.solarAdvancedState(); ok {
				after, haveAfter = st, true
			}
			if v, ok := d.readAdvModbusMetric("lexa_mb_adv_would_writes_total"); ok {
				wouldAfter, metricsAvailAfter = v, true
			}
			writesAfter, _ = d.readAdvModbusMetric("lexa_mb_adv_writes_total")
			failAfter, _ = d.readAdvModbusMetric("lexa_mb_adv_write_failures_total")

			release := desiredAdvReleasePayload(device, time.Now().Unix())
			_ = d.mqttInject(desiredAdvTopic(device), release, true)
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseAdvShadowNoWrites(sc, s,
				haveBefore, before, haveAfter, after,
				metricsAvailBefore && metricsAvailAfter,
				wouldBefore, wouldAfter, writesBefore, writesAfter, failBefore, failAfter)
		},
	}
}

const advModeShadow = "shadow"
const advModeActive = "active"

func diagnoseAdvShadowNoWrites(sc *mayScenario, s []maySample,
	haveBefore bool, before advSolarState, haveAfter bool, after advSolarState,
	metricsAvail bool, wouldBefore, wouldAfter, writesBefore, writesAfter, failBefore, failAfter float64,
) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if !haveBefore || !haveAfter {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "could not read the solar sim's advanced /state before and after the hold"
		return f
	}

	writesLanded := !advWriteSurfaceEqual(before, after)
	if writesLanded {
		f.Verdict = "FAIL"
		f.Headline = "the solar sim's curve/PF/ceiling command registers changed during a SHADOW-mode hold — a real write landed"
		f.Diagnosis = []string{
			"The advanced reconciler shell is configured shadow, which must never touch hardware. The sim's device-command ground truth (curve live points, 704 fixed-PF/fixed-var/ceiling registers) changed anyway between the pre- and post-hold snapshot.",
			fmt.Sprintf("before=%+v after=%+v", before, after),
		}
		f.Fix = sc.Fix
		return f
	}

	if !metricsAvail {
		f.Verdict = "DEGRADED"
		f.Headline = "zero writes landed (ground truth), but lexa-modbus's :9103 metrics were unavailable — cannot corroborate would-write logging"
		f.Diagnosis = []string{
			"The sim's command registers never changed across the hold — the core shadow-mode invariant held. The lexa_mb_adv_would_writes_total/writes_total/write_failures_total counters could not be scraped (TASK-044 metrics not reachable), so the \"logs shadow verdicts\" half of the invariant is unconfirmed this run.",
		}
		return f
	}

	wouldDelta := wouldAfter - wouldBefore
	writesDelta := writesAfter - writesBefore
	failDelta := failAfter - failBefore

	if writesDelta > 0 || failDelta > 0 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("lexa_mb_adv_writes_total/write_failures_total moved (+%.0f/+%.0f) during a SHADOW-mode hold", writesDelta, failDelta)
		f.Diagnosis = []string{"Ground truth showed no register change, but the shell's own real-write counters advanced — shadow mode is supposed to make these code paths unreachable."}
		f.Fix = sc.Fix
		return f
	}

	if wouldDelta <= 0 {
		f.Verdict = "DEGRADED"
		f.Headline = "zero writes landed, but lexa_mb_adv_would_writes_total never moved — the injected doc may not have reached an engaged axis"
		f.Diagnosis = []string{
			"No real write occurred (correct for shadow mode), but the would-write counter that should fire on the injected volt-var command never advanced. Possible causes: the injected doc did not reach lexa-modbus (wrong device name/topic), or reconciler.adv is not actually \"shadow\" despite the precondition probe.",
			fmt.Sprintf("lexa_mb_adv_would_writes_total: %.0f → %.0f", wouldBefore, wouldAfter),
		}
		return f
	}

	f.Verdict = "PASS"
	f.Headline = fmt.Sprintf("shadow mode logged %.0f would-be write(s) and touched ZERO hardware registers", wouldDelta)
	f.Diagnosis = []string{
		"The solar sim's curve/PF/ceiling command registers are byte-identical before and after the hold, and lexa_mb_adv_writes_total/write_failures_total did not move — the shadow shell never reached a real driver call.",
		fmt.Sprintf("lexa_mb_adv_would_writes_total advanced by %.0f (shadow verdicts logged) while writes/write_failures stayed flat.", wouldDelta),
	}
	return f
}

// ── Scenario 2: curve-adopt-readback-divergence (INV-ADV-READBACK, flagship)

func curveAdoptReadbackDivergenceScenario() *mayScenario {
	const device = advTargetDevice
	var (
		haveReport bool
		report     advReportMsg
		reportErr  error
	)
	return &mayScenario{
		ID:         "curve-adopt-readback-divergence",
		Name:       "Curve adopt handshake reports COMPLETED while the live curve stays stale",
		Category:   "Advanced-DER reconciler (INV-ADV-READBACK, flagship)",
		Hypothesis: "PRECONDITION: sim target \"solar\" launched with `modsim -advanced` (Track A); bench modbus.json has reconciler.adv=\"active\" AND der_gen=\"7xx\" for " + device + ". This scenario bypasses cmd/hub's WP-9 author and injects a synthetic lexa/desired/adv/" + device + " document directly (isolating WP-10's shell), commanding a volt-var curve while curve_adopt_lies is armed on the solar sim: AdptCrvRslt reports COMPLETED but the read-only live curve (index 0) is never actually copied from the staged curve — the exact 'trusted the handshake' bug WP-10's readback re-verification defends against.",
		Expected:   "The reconciler must NEVER report adopt_state=adopted for the volt_var axis while curve_adopt_lies is armed. It must re-read the live curve after the write, recompute the content hash, find a mismatch, and report adopt_state=diverged (lexa/reconcile/adv/" + device + "/report). Corroborating metric: lexa_mb_adv_failed_total on :9103/metrics — NOT lexa_mb_adv_divergences_total, which this suite found only increments for the MEASURED axes (fixed_pf/fixed_var/energize) in reconcile_adv.go's observe(); a curve-axis divergence routes through transitionLocked's AdoptStateFailed/AdoptStateDiverged case into failures, never divergences.",
		HoldS:      85,
		Fix:        "cmd/modbus/reconcile_adv.go's executeCurveLocked (write → re-read live curve → recompute hash → adopted only on an exact match).",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := requireAdvSolarSim(d); err != nil {
				return nil, err
			}
			if err := requireModbusReconcilerAdvMode(d, advModeActive, "curve-adopt-readback-divergence"); err != nil {
				return nil, err
			}
			if err := requireModbusDERGen7xx(d, "curve-adopt-readback-divergence"); err != nil {
				return nil, err
			}
			if err := d.armSolarAdvFault("curve_adopt_lies"); err != nil {
				return nil, fmt.Errorf("arm curve_adopt_lies: %w", err)
			}
			mrid := fmt.Sprintf("mayhem-curve-lies-%d", time.Now().UnixNano())
			payload := desiredAdvVoltVarPayload(device, mrid, time.Now().Unix())
			if err := d.mqttInject(desiredAdvTopic(device), payload, true); err != nil {
				return nil, fmt.Errorf("inject desired-adv curve doc: %w", err)
			}
			return &activeConstraint{Typ: "none"}, nil
		},
		teardown: func(d *mayhemDriver) {
			// WP-10 executes the write+readback synchronously on doc arrival
			// (bounded by ~3s AdptCrvRslt polling); a small retry margin covers
			// MQTT/SSH round-trip jitter, not a wait for slow convergence.
			report, haveReport, reportErr = advReportWithRetry(d, device, 3, 3*time.Second)

			release := desiredAdvReleasePayload(device, time.Now().Unix())
			_ = d.mqttInject(desiredAdvTopic(device), release, true)
			_ = d.clearSolarAdvFault("curve_adopt_lies")
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseCurveAdoptDivergence(sc, s, "volt_var", haveReport, report, reportErr)
		},
	}
}

// diagnoseCurveAdoptDivergence judges curve-adopt-readback-divergence: the
// reconciler must report adopt_state=diverged (never adopted) for wantAxis
// while curve_adopt_lies is armed. Shared with a future watt_var/volt_watt
// variant if one is ever added, hence the explicit wantAxis parameter.
func diagnoseCurveAdoptDivergence(sc *mayScenario, s []maySample, wantAxis string, haveReport bool, report advReportMsg, reportErr error) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if !haveReport {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "could not read the retained reconciler report over SSH"
		f.Diagnosis = []string{
			fmt.Sprintf("Reading lexa/reconcile/adv/%s/report failed: %v. This is a detection gap, not a compliance finding — verify qa-inject creds are provisioned (scripts/mqtt-chaos.sh deploy) and the hub Pi is reachable, then re-run.", advTargetDevice, reportErr),
		}
		return f
	}
	if report.Axis != wantAxis {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = fmt.Sprintf("retained report is for axis %q, not %q — cannot judge this fault from it", report.Axis, wantAxis)
		f.Diagnosis = []string{"The device may have multiple axes reporting on the same per-device topic (the report is retained per DEVICE, not per axis) and something else's transition landed last. Re-run in isolation."}
		return f
	}
	switch report.AdoptState {
	case "adopted":
		f.Verdict = "FAIL"
		f.Headline = "reconciler reported adopt_state=adopted while curve_adopt_lies was armed — it trusted the handshake"
		f.Diagnosis = []string{
			"AdptCrvRslt=COMPLETED but the live curve-1 readback stayed stale (the injected fault). The reconciler reported adopted anyway — exactly the bug WP-10's readback re-verification exists to catch.",
			fmt.Sprintf("curve_hash on the report: %q", report.CurveHash),
		}
		f.Fix = sc.Fix
		return f
	case "diverged":
		f.Verdict = "PASS"
		f.Headline = "reconciler caught the stale readback and reported adopt_state=diverged, not adopted"
		f.Diagnosis = []string{
			"AdptCrvRslt=COMPLETED (the injected fault) but the reconciler re-read the live curve, recomputed the content hash, found a mismatch against the commanded curve, and reported diverged rather than trusting the write/adopt handshake.",
		}
		return f
	case "pending":
		f.Verdict = "DEGRADED"
		f.Headline = "reconciler still reports adopt_state=pending — the write/readback cycle had not resolved by the end of the hold"
		f.Diagnosis = []string{"Neither adopted nor diverged was reached within the hold window. Either the doc arrived late, the device is slow to poll, or something in the write/readback path is stuck. Re-run with a longer hold before drawing a conclusion."}
		return f
	case "unsupported":
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "reconciler reports adopt_state=unsupported for volt_var — the target device's capability (der_gen/live model scan) does not support this axis"
		f.Diagnosis = []string{"This means the precondition (der_gen=\"7xx\" + a live model-705 scan) was not actually satisfied on this bench, despite the setup probe — verify /etc/lexa/modbus.json by hand."}
		return f
	case "failed":
		f.Verdict = "DEGRADED"
		f.Headline = "reconciler reports adopt_state=failed (a write/transport error, not a confirmed readback mismatch)"
		f.Diagnosis = []string{"transitionLocked routes both AdptCrvRslt-FAILED/transport-error cases AND a readback-hash mismatch into overlapping states here — failed does not by itself confirm the specific INV-ADV-READBACK defense fired (that is \"diverged\"). Check the lexa-modbus journal for \"curve adopt failed\" vs \"DIVERGED\" to disambiguate."}
		return f
	default:
		f.Verdict = "INCONCLUSIVE"
		f.Headline = fmt.Sprintf("unexpected adopt_state %q on the retained report", report.AdoptState)
		return f
	}
}

// ── Scenario 3: pf-var-measured-convergence (INV-ADV-READBACK) ─────────────

func pfVarMeasuredConvergenceScenario() *mayScenario {
	const device = advTargetDevice
	const commandedPF = 0.90
	var (
		haveReport                bool
		report                    advReportMsg
		reportErr                 error
		divBefore, divAfter       float64
		divMetricsAvail           bool
		pfBefore, pfAfter         float64
		havePFBefore, havePFAfter bool
	)
	return &mayScenario{
		ID:         "pf-var-measured-convergence",
		Name:       "Fixed-PF write ACKs but measured PF never moves (accept-but-ignore)",
		Category:   "Advanced-DER reconciler (INV-ADV-READBACK)",
		Hypothesis: "PRECONDITION: sim target \"solar\" launched with `modsim -advanced` (Track A); bench modbus.json has reconciler.adv=\"active\" AND der_gen=\"7xx\" for " + device + ". This scenario bypasses cmd/hub's WP-9 author and injects a synthetic lexa/desired/adv/" + device + " document directly (isolating WP-10's shell), commanding a fixed power factor while pf_ack_ignore is armed: the 704 register write ACKs (a readback of the command register would be fooled) but model 701's MEASURED PF never moves off its free-running value — the accept-but-ignore analog of the battery soc_refuse fault this suite already covers for the scalar reconcilers.",
		Expected:   "The reconciler must detect the measured-vs-commanded PF gap and report adopt_state=diverged (not adopted/converged) for the fixed_pf axis, with lexa_mb_adv_divergences_total advancing — this IS one of the two axes (fixed_pf/fixed_var/energize) that counter covers, per reconcile_adv.go's observe()/synthesizeLocked.",
		HoldS:      85,
		Fix:        "cmd/modbus/reconcile_adv.go's synthesizeLocked (AdvAxisFixedPF case) + observe() — measured PF must be re-checked every poll, a write ACK is never convergence.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := requireAdvSolarSim(d); err != nil {
				return nil, err
			}
			if err := requireModbusReconcilerAdvMode(d, advModeActive, "pf-var-measured-convergence"); err != nil {
				return nil, err
			}
			if err := requireModbusDERGen7xx(d, "pf-var-measured-convergence"); err != nil {
				return nil, err
			}
			if err := d.armSolarAdvFault("pf_ack_ignore"); err != nil {
				return nil, fmt.Errorf("arm pf_ack_ignore: %w", err)
			}
			if v, ok := d.readAdvModbusMetric("lexa_mb_adv_divergences_total"); ok {
				divBefore, divMetricsAvail = v, true
			}
			if st, ok := d.solarAdvancedState(); ok {
				pfBefore, havePFBefore = st.Meas701.PF, true
			}
			// Keep the inverter producing well above advPFAssessMinW (100W) —
			// a PF measurement below that floor HOLDS rather than judging
			// (reconcile_adv.go's synthesizeLocked), which would starve this
			// scenario of any evidence either way.
			_ = d.post("solar", "/inject", map[string]any{"W_W": 3000})
			mrid := fmt.Sprintf("mayhem-pf-ignore-%d", time.Now().UnixNano())
			payload := desiredAdvFixedPFPayload(device, mrid, commandedPF, true, time.Now().Unix())
			if err := d.mqttInject(desiredAdvTopic(device), payload, true); err != nil {
				return nil, fmt.Errorf("inject desired-adv fixed-pf doc: %w", err)
			}
			return &activeConstraint{Typ: "none"}, nil
		},
		perTick: func(d *mayhemDriver, i int) {
			_ = d.post("solar", "/inject", map[string]any{"W_W": 3000})
		},
		teardown: func(d *mayhemDriver) {
			report, haveReport, reportErr = advReportWithRetry(d, device, 3, 3*time.Second)
			if v, ok := d.readAdvModbusMetric("lexa_mb_adv_divergences_total"); ok && divMetricsAvail {
				divAfter = v
			} else {
				divMetricsAvail = false
			}
			if st, ok := d.solarAdvancedState(); ok {
				pfAfter, havePFAfter = st.Meas701.PF, true
			}

			release := desiredAdvReleasePayload(device, time.Now().Unix())
			_ = d.mqttInject(desiredAdvTopic(device), release, true)
			_ = d.clearSolarAdvFault("pf_ack_ignore")
			_ = d.post("solar", "/inject", map[string]any{"W_W": 0})
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnosePFVarMeasuredConvergence(sc, s, commandedPF,
				haveReport, report, reportErr,
				divMetricsAvail, divBefore, divAfter,
				havePFBefore && havePFAfter, pfBefore, pfAfter)
		},
	}
}

func diagnosePFVarMeasuredConvergence(sc *mayScenario, s []maySample, commandedPF float64,
	haveReport bool, report advReportMsg, reportErr error,
	divMetricsAvail bool, divBefore, divAfter float64,
	havePF bool, pfBefore, pfAfter float64,
) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if !haveReport {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "could not read the retained reconciler report over SSH"
		f.Diagnosis = []string{fmt.Sprintf("Reading lexa/reconcile/adv/%s/report failed: %v.", advTargetDevice, reportErr)}
		return f
	}
	if report.Axis != "fixed_pf" {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = fmt.Sprintf("retained report is for axis %q, not fixed_pf — cannot judge this fault from it", report.Axis)
		// The common cause is a PREMISE conflict, not a stale topic: this
		// scenario isolates WP-10's shell by injecting a synthetic fixed_pf
		// desired doc while BYPASSING cmd/hub's WP-9 adv author. But when the
		// hub runs with advanced_der="on" AND a CSIP default control
		// (DDERC-SP-001) that energizes the DER, that author continuously
		// re-publishes its OWN retained lexa/desired/adv/<dev> doc
		// (energize:true) to the same topic — overwriting the injection every
		// author cycle, so the reconciler stays adopted on "energize" and never
		// sees fixed_pf. Clearing the retained topic does NOT help; it is
		// re-authored immediately. Say so, so the run is actionable rather than
		// read as flakiness.
		if report.Axis == "energize" && report.AdoptState == "adopted" {
			f.Diagnosis = []string{
				"The reconciler is stably adopted on axis \"energize\" — the signature of cmd/hub's live WP-9 adv author (advanced_der=\"on\" + a CSIP default control energizing the DER) continuously re-publishing its own retained lexa/desired/adv/" + advTargetDevice + " doc, which OVERWRITES this scenario's synthetic fixed_pf injection every author cycle.",
				"This scenario can only isolate WP-10's reconciler shell when the WP-9 author is quiesced. Re-run under a bench profile with advanced_der=\"off\" (or with no default control driving energize) so the synthetic injection is the sole author on that topic. This is the bench-deferred adv-shell / PF-mismatch drill, not a hub or oracle defect — H9's excitation-direction fix is covered by the unit test TestAdvShell_FixedPFWrongExcitationDiverges.",
			}
		}
		return f
	}

	groundTruthNote := "ground truth measured PF unavailable this run"
	if havePF {
		groundTruthNote = fmt.Sprintf("solar sim's own measured PF: %.3f → %.3f (commanded %.2f)", pfBefore, pfAfter, commandedPF)
	}
	metricNote := "lexa_mb_adv_divergences_total unavailable (metrics scrape failed)"
	if divMetricsAvail {
		metricNote = fmt.Sprintf("lexa_mb_adv_divergences_total: %.0f → %.0f", divBefore, divAfter)
	}

	switch report.AdoptState {
	case "adopted", "":
		f.Verdict = "FAIL"
		f.Headline = "reconciler reported the fixed-PF command adopted/converged while pf_ack_ignore was armed"
		f.Diagnosis = []string{
			"The 704 register write ACKed, but the sim's MEASURED PF (model 701) never moved off its free-running value under pf_ack_ignore. The reconciler must judge convergence from measurement, not the write ACK.",
			groundTruthNote, metricNote,
		}
		f.Fix = sc.Fix
		return f
	case "diverged":
		f.Verdict = "PASS"
		f.Headline = "reconciler detected the measured-PF gap and reported adopt_state=diverged"
		f.Diagnosis = []string{
			"The 704 write ACKed but measured PF never converged toward the commanded value; the reconciler correctly judged this from measurement rather than the write ACK.",
			groundTruthNote, metricNote,
		}
		if divMetricsAvail && divAfter <= divBefore {
			f.Verdict = "DEGRADED"
			f.Headline = "reconciler reported diverged, but lexa_mb_adv_divergences_total never advanced — inconsistent evidence"
			f.Diagnosis = append(f.Diagnosis, "The retained report and the metric disagree; the report is the authoritative source per WP-10's contract (\"adoption state rides the report, never the desired doc\"), but this discrepancy is worth investigating before trusting either signal blindly.")
		}
		return f
	case "pending":
		f.Verdict = "DEGRADED"
		f.Headline = "reconciler still reports adopt_state=pending at the end of the hold — no convergence judgement reached yet"
		f.Diagnosis = []string{"The write happened (state moved off released), but no poll-loop measurement cycle resolved a convergence verdict within the hold. lexa-modbus's poll_interval_s may be slow relative to this hold, or the solar sim's W_W injection did not clear the advPFAssessMinW floor.", groundTruthNote}
		return f
	case "unsupported":
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "reconciler reports adopt_state=unsupported for fixed_pf — device capability (der_gen/model 704 scan) not as expected"
		return f
	case "failed":
		f.Verdict = "DEGRADED"
		f.Headline = "reconciler reports adopt_state=failed (a write error) rather than a measured-convergence judgement"
		return f
	default:
		f.Verdict = "INCONCLUSIVE"
		f.Headline = fmt.Sprintf("unexpected adopt_state %q on the retained report", report.AdoptState)
		return f
	}
}

// ── Scenarios 4/5: aus-gen-cap / aus-load-cap (INV-AUS) ──────────────────────

const (
	ausGenCapLimW  = 2000.0
	ausLoadCapLimW = 3000.0
	ausCapHoldS    = 85
)

func ausGenCapScenario() *mayScenario {
	var shadowDivBefore, shadowDivAfter float64
	var shadowDivAvail bool
	return &mayScenario{
		ID:         "aus-gen-cap",
		Name:       "CSIP-AUS gross-generation cap (opModGenLimW) holds solar + battery discharge",
		Category:   "CSIP-AUS dynamic envelope (INV-AUS)",
		Hypothesis: fmt.Sprintf("PRECONDITION: bench hub.json has \"enforce_aus_limits\": true (WP-11's cascade-enforcement gate — the limit is otherwise adopted into GridState but never acted on). Unlike the three adv scenarios above, this one needs NO bus-injection bypass: gridsim's /admin/control already accepts gen_lim_W end-to-end (sim/gridsim/admin.go → lexa-northbound's publish.go decode → bus.ActiveControl.GenLimW). Full sun + a fully-charged battery gives the site more generation headroom than the posted %.0fW cap allows; the CSIP-AUS gross-generation rule (solar output PLUS battery discharge — the disambiguation from the legacy opModMaxLimW rule, which caps inverter output alone) must curtail solar (and trim any committed battery discharge) to hold gross generation under the cap, with checkAusGenerationConvergence's measured-effect backstop posting CannotComply if the site never gets there.", ausGenCapLimW),
		Expected:   "Gross generation (solar + battery discharge, ground truth from the sims) settles at or under the cap within the settling deadline and stays there, evidenced by a \"csip-aus/gen-limit\" plan decision on /status; a sustained breach with no CannotComply admission is a FAIL.",
		HoldS:      ausCapHoldS,
		Fix:        "internal/orchestrator/auslimits.go's applyAusGenerationLimitRule / checkAusGenerationConvergence.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := requireEnforceAusLimits(d, "aus-gen-cap"); err != nil {
				return nil, err
			}
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(d.pvHighW, 250)
			if v, ok := d.readMetricCounter("lexa_constraint_shadow_divergence_total"); ok {
				shadowDivBefore, shadowDivAvail = v, true
			}
			return d.postAusCap("gen", ausGenCapLimW, ausCapHoldS, "mayhem: CSIP-AUS gross-generation cap")
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(d.pvHighW, 250)
		},
		teardown: func(d *mayhemDriver) {
			// Read the shadow-harness counter BEFORE clearing the control —
			// teardown runs before evaluate in the run loop (run()'s
			// setup→hold→recover(teardown)→evaluate order), so this is the
			// last chance to capture it with `d` in scope.
			if shadowDivAvail {
				if v, ok := d.readMetricCounter("lexa_constraint_shadow_divergence_total"); ok {
					shadowDivAfter = v
				} else {
					shadowDivAvail = false
				}
			}
			d.deleteControls(0)
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			f := diagnoseAusGenCap(sc, cons, s)
			appendShadowDivergenceNote(&f, shadowDivAvail, shadowDivBefore, shadowDivAfter)
			return f
		},
	}
}

// appendShadowDivergenceNote appends an INFORMATIONAL-ONLY diagnosis bullet
// reading the aggregate lexa_constraint_shadow_divergence_total delta across
// the hold. It never changes the verdict: this counter is a single aggregate
// across EVERY shadow constraint (export/gen/import/economics/battery_safety/
// gen_aus/load_aus — see cmd/hub/config.go's ConstraintModes key list), not
// broken out per axis, so a delta here cannot be attributed specifically to
// gen_aus/load_aus. Flagged in the file doc as a hub-side observability gap.
func appendShadowDivergenceNote(f *mayFinding, avail bool, before, after float64) {
	if !avail {
		f.Diagnosis = append(f.Diagnosis, "lexa_constraint_shadow_divergence_total unavailable (metrics scrape failed or constraint_shadow is off) — no shadow-harness cross-check this run.")
		return
	}
	delta := after - before
	f.Diagnosis = append(f.Diagnosis, fmt.Sprintf(
		"Informational only (NOT part of the verdict): lexa_constraint_shadow_divergence_total moved by %.0f across the hold (%.0f → %.0f). This is a single AGGREGATE counter across every shadow constraint, not broken out per axis — a nonzero delta here cannot be attributed specifically to gen_aus/load_aus from the metrics surface alone (a real gap; see the file doc).",
		delta, before, after))
}

// ausDecisionPrefix is the "[rule] " prefix hubState()'s decisionLine-style
// formatting (mayhem.go's hubState: fmt.Sprintf("[%s] %s→%s", ...)) stamps
// onto every plan decision — used to detect that the named CSIP-AUS cascade
// rule actually ran this tick (AddDecision fires unconditionally whenever the
// limit is adopted and non-NaN, regardless of whether a breach is underway).
func ausDecisionEngaged(s []maySample, rule string) bool {
	prefix := "[" + rule + "]"
	for _, smp := range s {
		for _, dec := range smp.Decisions {
			if strings.HasPrefix(dec, prefix) {
				return true
			}
		}
	}
	return false
}

// ausGrossGenW computes ground-truth gross generation for one sample: solar
// output plus battery discharge (BatterySimW > 0), mirroring
// checkAusGenerationConvergence's own measuredGrossW definition exactly
// (auslimits.go) so this oracle judges the SAME quantity the invariant names.
// ok=false when the judging sensor (solar) has no coherent reading this tick.
func ausGrossGenW(smp maySample) (float64, bool) {
	if !smp.SolarOK {
		return 0, false
	}
	gross := smp.SolarW
	if smp.BatterySimOK && smp.BatterySimW > 0 {
		gross += smp.BatterySimW
	}
	return gross, true
}

// ausGrossLoadW computes ground-truth gross load for one sample: solar +
// battery discharge + net grid import, mirroring checkAusLoadConvergence's
// own grossLoadW formula exactly (auslimits.go: "grossLoad = solar +
// batteryDischarge + netW", rearranged from the site energy balance). ok=false
// when either judging sensor (solar or the grid meter) is unavailable.
func ausGrossLoadW(smp maySample) (float64, bool) {
	if !smp.SolarOK || !smp.GridOK {
		return 0, false
	}
	gross := smp.SolarW + smp.RealGridW
	if smp.BatterySimOK && smp.BatterySimW > 0 {
		gross += smp.BatterySimW
	}
	if gross < 0 {
		gross = 0
	}
	return gross, true
}

// ausSheddableRemains reports whether, in the convergence-hold tail, the hub
// still had an un-pulled sheddable LOAD lever while over the cap — the pack
// actively CHARGING (BatterySimW < 0 draws load the battery-charge-shed lever
// exists to remove) or the EV still drawing above the "actively charging" floor
// (the EVSE current-ceiling lever exists to remove). applyAusLoadLimitRule is
// required to exhaust BOTH before the hub may honestly post CannotComply, so a
// CannotComply admitted with either lever still holding slack is PREMATURE, not
// a legitimate irreducible-baseload admission. This is the ground-truth backstop
// that keeps the legit-CannotComply PASS branch from degenerating into a
// presence-only pass (fbcaca0 weakening) that never exercises the shed levers.
func ausSheddableRemains(s []maySample) (bool, string) {
	if len(s) == 0 {
		return false, ""
	}
	endT := s[len(s)-1].T
	for _, smp := range s {
		if smp.T < endT-mayConvergeHoldS {
			continue
		}
		// Pack still charging harder than the reaction floor ⇒ the
		// battery-charge-shed lever was not pulled.
		if smp.BatterySimOK && smp.BatterySimW < -mayReactThreshW {
			return true, fmt.Sprintf("pack still charging at %.0fW", -smp.BatterySimW)
		}
		// EV still actively drawing ⇒ the EVSE current ceiling was not pulled
		// toward its floor/suspend.
		if smp.EvSimOK && smp.EvSimW > mayEVLiveDrawW {
			return true, fmt.Sprintf("EV still drawing %.0fW (%.1fA)", smp.EvSimW, smp.EvSimA)
		}
	}
	return false, ""
}

// diagnoseAusCap is the shared oracle body for aus-gen-cap/aus-load-cap: walk
// the adoption(decision)→ground-truth-compliance→admission chain, mirroring
// diagnoseConstraint's shape without touching breachOver/scanSamples (which
// only know the legacy exportCap/importCap/genLimit vocabulary — see
// activeConstraint.Typ's doc comment; gen_aus/load_aus are custom cons.Typ
// values this suite never asks breachOver to interpret).
// cannotComplyLegit distinguishes the two AUS cap families. A GENERATION cap is
// always satisfiable by curtailing PV to zero, so a sustained breach the hub can
// only ADMIT (CannotComply) rather than resolve is a genuine shortfall → DEGRADED.
// A LOAD cap can be irreducibly unmeetable when home load alone exceeds it (no
// lever sheds baseload), so a correct CannotComply there is the standards-correct
// outcome, not a shortfall → PASS (the scenario's own Expected says so). A SILENT
// breach (no CannotComply) is a FAIL for both — that invariant is unchanged.
func diagnoseAusCap(sc *mayScenario, s []maySample, rule, label string, limW float64, grossOf func(maySample) (float64, bool), cannotComplyLegit bool) mayFinding {
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
		f.Headline = "hub unreachable for most of the window — cannot judge the AUS cap"
		return f
	}
	if !ausDecisionEngaged(s, rule) {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = fmt.Sprintf("the hub never logged a %q plan decision during the hold", rule)
		f.Diagnosis = []string{
			"Either enforce_aus_limits is not actually on for this hub (the precondition probe could not confirm it, or the bench config drifted since deploy), the northbound discovery walk had not yet adopted the opMod control within this window (STOCK cadence can be tens of seconds), or ActiveControl never carried the limit through to the cascade. This is a detection gap, not a confirmed pass or fail — re-run with a longer hold, or verify /etc/lexa/hub.json by hand.",
		}
		return f
	}

	okCount, lastBreach := 0, -1
	var peak float64
	for i, smp := range s {
		gross, ok := grossOf(smp)
		if !ok {
			continue
		}
		okCount++
		if over := gross - (limW + complianceTolW); over > 0 {
			lastBreach = i
			if over > peak {
				peak = over
			}
		}
	}
	if okCount < len(s)/2 {
		f.Verdict = "BLIND"
		f.Metrics.HubBlind = true
		f.Headline = fmt.Sprintf("the %s judging sensor(s) were absent for most of the window — cannot trust a clean read", label)
		return f
	}
	if lastBreach < 0 {
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("%s held at or under the %.0fW CSIP-AUS cap for the whole window", label, limW)
		return f
	}

	endT := s[len(s)-1].T
	sawTail, tailClean := false, true
	for _, smp := range s {
		if smp.T < endT-mayConvergeHoldS {
			continue
		}
		sawTail = true
		if gross, ok := grossOf(smp); ok && gross-(limW+complianceTolW) > 0 {
			tailClean = false
		}
	}
	reportedCannot := false
	for _, smp := range s {
		if smp.CannotComply {
			reportedCannot = true
		}
	}
	sheddableRemains, sheddableWhy := ausSheddableRemains(s)
	switch {
	case sawTail && tailClean:
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("%s breached briefly (peak +%.0fW) then converged and held under the %.0fW cap", label, peak, limW)
	case reportedCannot && cannotComplyLegit && !sheddableRemains:
		// Load cap with irreducible baseload above it: CannotComply IS the
		// correct outcome (this scenario's Expected + checkAusLoadConvergence's
		// doc), not a shortfall — BUT ONLY once the hub has exhausted its
		// sheddable levers. Verified by ausSheddableRemains==false: no un-pulled
		// lever (pack still charging / EV still drawing) remained in the tail.
		// The hub pulled everything it could and, unable to fully comply,
		// admitted it honestly rather than faking compliance.
		f.Verdict = "PASS"
		f.Headline = fmt.Sprintf("%s exceeded the %.0fW cap by more than the sheddable levers can remove; hub correctly admitted CannotComply after exhausting them", label, limW)
		f.Diagnosis = []string{"A load cap can be genuinely unmeetable when irreducible home load alone exceeds it — CannotComply is the standards-correct admission here (the scenario's Expected / checkAusLoadConvergence's doc), NOT a control failure. The hub drove both sheddable levers (battery-charge shed, EVSE current ceiling) to their floor and posted an honest CannotComply for the active mRID rather than silently reporting compliance."}
	case reportedCannot && cannotComplyLegit:
		// CannotComply posted while a sheddable lever still held slack — the hub
		// admitted defeat before exhausting applyAusLoadLimitRule's levers. That
		// is a PREMATURE admission, not a legitimate irreducible-baseload one:
		// the very failure the presence-only PASS (fbcaca0) would have masked.
		f.Verdict = "DEGRADED"
		f.Headline = fmt.Sprintf("%s stayed over the %.0fW cap; hub posted CannotComply while sheddable load remained (%s) — levers not exhausted", label, limW, sheddableWhy)
		f.Diagnosis = []string{"CannotComply is only a legitimate load-cap outcome once the sheddable levers are exhausted. Here a lever still held slack in the convergence tail (" + sheddableWhy + "), so the hub gave up early instead of shedding battery-charge / EVSE current further. applyAusLoadLimitRule should have pulled it before admitting non-convergence."}
		f.Fix = sc.Fix
	case reportedCannot:
		f.Verdict = "DEGRADED"
		f.Headline = fmt.Sprintf("%s did not converge under the %.0fW cap; hub reported CannotComply", label, limW)
		f.Diagnosis = []string{"The hub admitted it could not meet the CSIP-AUS limit rather than silently reporting compliance — correct fault-handling posture, but a generation cap is always satisfiable by curtailing PV, so a sustained non-convergence here is a real shortfall the hub could only admit, not resolve."}
	default:
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("%s stayed over the %.0fW CSIP-AUS cap (peak +%.0fW) with no CannotComply admission", label, limW, peak)
		f.Fix = sc.Fix
	}
	return f
}

func diagnoseAusGenCap(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	return diagnoseAusCap(sc, s, "csip-aus/gen-limit", "gross generation (solar + battery discharge)", ausGenCapLimW, ausGrossGenW, false)
}

func diagnoseAusLoadCap(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	return diagnoseAusCap(sc, s, "csip-aus/load-limit", "gross load (solar + battery discharge + net import)", ausLoadCapLimW, ausGrossLoadW, true)
}

func ausLoadCapScenario() *mayScenario {
	var shadowDivBefore, shadowDivAfter float64
	var shadowDivAvail bool
	return &mayScenario{
		ID:         "aus-load-cap",
		Name:       "CSIP-AUS gross-load cap (opModLoadLimW) holds home+EV+battery-charge load",
		Category:   "CSIP-AUS dynamic envelope (INV-AUS)",
		Hypothesis: fmt.Sprintf("PRECONDITION: bench hub.json has \"enforce_aus_limits\": true (same WP-11 gate as aus-gen-cap). Symmetric to aus-gen-cap: gridsim's /admin/control already accepts load_lim_W end-to-end (sim/gridsim/admin.go → northbound → bus.ActiveControl.LoadLimW), so this needs no bus-injection bypass either. Low sun + a heavy meter load + an actively-charging EV session gives the site more gross load than the posted %.0fW cap allows; applyAusLoadLimitRule's two levers (battery-charge shed first, then a sticky EVSE current ceiling) must bring gross load (home + EV + battery charge, from the site energy balance grossLoad = solar + batteryDischarge + netW) under the cap, with checkAusLoadConvergence's measured-effect backstop posting CannotComply if the remaining load is not sheddable.", ausLoadCapLimW),
		Expected:   "Gross load (ground truth) settles at or under the cap within the settling deadline and stays there, evidenced by a \"csip-aus/load-limit\" plan decision; a sustained breach with no CannotComply admission is a FAIL. NOTE: unlike a generation cap (always satisfiable by curtailing PV), a load cap can be genuinely unmeetable if home load alone exceeds it — CannotComply is a legitimate, correct outcome here, not just an acceptable one (see checkAusLoadConvergence's doc comment).",
		HoldS:      ausCapHoldS,
		Fix:        "internal/orchestrator/auslimits.go's applyAusLoadLimitRule / checkAusLoadConvergence.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := requireEnforceAusLimits(d, "aus-load-cap"); err != nil {
				return nil, err
			}
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 50, "Conn": 1})
			_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
			_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
			d.injectEnv(300, 6500)
			if v, ok := d.readMetricCounter("lexa_constraint_shadow_divergence_total"); ok {
				shadowDivBefore, shadowDivAvail = v, true
			}
			return d.postAusCap("load", ausLoadCapLimW, ausCapHoldS, "mayhem: CSIP-AUS gross-load cap")
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(300, 6500)
		},
		teardown: func(d *mayhemDriver) {
			if shadowDivAvail {
				if v, ok := d.readMetricCounter("lexa_constraint_shadow_divergence_total"); ok {
					shadowDivAfter = v
				} else {
					shadowDivAvail = false
				}
			}
			d.deleteControls(0)
			_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			f := diagnoseAusLoadCap(sc, cons, s)
			appendShadowDivergenceNote(&f, shadowDivAvail, shadowDivBefore, shadowDivAfter)
			return f
		},
	}
}

// ── Reviewer merge instructions (docs/QA_STANDARDS_BUILDOUT.md's "Merge
//    discipline" — DO NOT self-apply; the reviewer wires these) ─────────────
//
// 1. In scenarios() (mayhem.go), alongside the existing
//    `sc = append(sc, d.mqttScenarios()...)` etc. lines, add:
//
//        sc = append(sc, d.advScenarios()...)
//
// 2. This track's oracles are all Go-literal scenarios (not qa/scenarios/*.json
//    specs), so — matching mayhem_ocpp_openadr.go's precedent (none of its
//    parameterized-closure oracles are registered either) — NO oracleRegistry
//    entry is required for the suite to build/run/pass go vet. If a future
//    spec-JSON scenario wants to select one of these oracles by name, add to
//    oracleRegistry (scenariospec.go):
//
//        "diagnoseAdvShadowNoWrites":            {build: noParamOracle(...), requiresConstraint: false},  // needs before/after solar-state + metrics params — see buildDiagnoseSurvival for the pattern
//        "diagnoseCurveAdoptDivergence":          {build: noParamOracle(...), requiresConstraint: false},  // needs wantAxis/haveReport/report/reportErr params
//        "diagnosePFVarMeasuredConvergence":      {build: noParamOracle(...), requiresConstraint: false},  // needs commandedPF + report + metric params
//        "diagnoseAusGenCap":                     {build: noParamOracle(diagnoseAusGenCap), requiresConstraint: true},
//        "diagnoseAusLoadCap":                    {build: noParamOracle(diagnoseAusLoadCap), requiresConstraint: true},
//
//    (diagnoseAdvShadowNoWrites/CurveAdoptDivergence/PFVarMeasuredConvergence
//    all take extra closure state captured at RUN time — SSH probes, sim
//    snapshots, injected mrids — the same way diagnoseOCPP16Obey/
//    diagnoseEVSetpointClamp do in mayhem_ocpp_openadr.go; a parameterized
//    build func would be needed and has no obvious JSON param shape yet.
//    diagnoseAusGenCap/diagnoseAusLoadCap take only (sc, cons, s) and WOULD
//    fit noParamOracle directly if ever wanted from a spec file — punted as a
//    follow-up, not attempted here, since neither is asked for by
//    docs/QA_STANDARDS_BUILDOUT.md's scenario matrix.)
//
// Follow-ups NOT attempted here (out of this session's scope):
//
//   - A per-constraint-key lexa_constraint_shadow_divergence_total breakdown
//     (or an additional labeled/named counter per key) so a shadow-harness
//     cross-check can be attributed to gen_aus/load_aus specifically instead
//     of reading one aggregate counter — see appendShadowDivergenceNote's doc.
//   - lexa-api's GET /status surfacing GenLimW/LoadLimW on csip_control.base
//     (cmd/api/handlers.go's csipControlInfo/adminBaseInfo-equivalent
//     currently carries only ExpLimW/MaxLimW/ImpLimW/FixedW/Connect) — would
//     let a future oracle confirm cap ADOPTION directly instead of inferring
//     it from a plan-decision string match.
//   - A watt_var/volt_watt variant of curve-adopt-readback-divergence (this
//     session only exercises volt_var) — diagnoseCurveAdoptDivergence already
//     takes wantAxis as a parameter, so adding one is a new scenario
//     constructor + curve-payload builder, not a new oracle.
