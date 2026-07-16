// Track B — Northbound reporting Mayhem scenarios and oracles
// (docs/QA_STANDARDS_BUILDOUT.md). New file per that doc's "Merge discipline"
// section: scenarios live in reportingScenarios() below, new oracles in this
// same file. This file does NOT edit scenarios() or oracleRegistry — see the
// comment block at the very end for the exact reviewer-append lines.
//
// Covers three invariants:
//
//	INV-REPORT              — the hub PUTs DERCapability/Settings/Status/
//	                          Availability to the server and POSTs LogEvent
//	                          alarm+RTN pairs; a PIN freeze suspends ALL
//	                          server egress (PUT/MUP/Response/LogEvent) and
//	                          heal resumes it.
//	INV-CANNOTCOMPLY-VOCAB  — a forced breach posts IEEE 2030.5 Table 27
//	                          Response codes, not the legacy vendor 0xF0,
//	                          when legacy_cannotcomply_code=false (product
//	                          default).
//	INV-REDIRECT            — the hub follows 301/302 within redirect_max,
//	                          fails closed (holds LKG, no crash) beyond it.
//
// Bench-runnable vs unit-only (read this before running any of these):
//
//   - der-report-roundtrip (INV-REPORT): a plain positive-path conformance
//     check — no fault injected at all. It only asserts gridsim
//     /admin/derputs has ever received all four DER* resources with sane
//     content; DERCapability/DERSettings are PUT on dersite content CHANGE
//     (internal/northbound/derreport's putCapabilitySettings, hub-side), not
//     every walk, so a bench that has been up a while may show them PUT long
//     before this scenario's own hold window — that is still a pass: the
//     roundtrip clearly happened, which is what this scenario exists to
//     prove. DERStatus/DERAvailability PUT every walk (unconditionally
//     refreshed), so those two are always current as of this run.
//   - pin-freeze-egress-halt (INV-REPORT): this is the one scenario in this
//     file that is NOT self-provisioning fault injection. Forcing a
//     registration-PIN mismatch needs the DEPLOYED hub's
//     /etc/lexa/northbound.json registration_pin changed and lexa-northbound
//     restarted — CLAUDE.md's shipped bench default is registration_pin=0
//     (the check disabled). Grepping mayhem.go itself for a config-patch-
//     and-restart helper turns up none (the restart helpers that DO exist —
//     mayhem_world.go's hubSSH-based `systemctl restart lexa-hub` /
//     `lexa-modbus` / `lexa-northbound`, mqtt_scenarios.go's mosquitto
//     stop/cp/start rollback dance — all restart a service with its EXISTING
//     config; none of them patch a JSON key first). Inventing a new
//     config-patch-and-restart helper for one QA scenario against a shared
//     bench service (and having to patch it back afterward, on every code
//     path, including a mid-setup failure) is a materially bigger and
//     riskier change than this track's scope — so, per the task brief's own
//     branching, this is implemented as a DOCUMENTED PRECONDITION scenario,
//     the same shape Track D's ocpp16-smart-charge/pairing-gate-hold use for
//     their own launch-time/config preconditions: setup() PROBES (read-only,
//     over SSH) whether the deployed config already carries a mismatched
//     registration_pin AND whether /status's cert_status.pin_ok is already
//     observably false, and fails to INCONCLUSIVE with the exact remediation
//     command when it isn't — never a fake PASS. Because nothing here ever
//     writes the config, this scenario also cannot exercise the "heal
//     resumes it" half of INV-REPORT (that needs the SAME write capability
//     this file deliberately doesn't add) — the oracle's PASS diagnosis says
//     so explicitly rather than silently only testing half the invariant.
//   - logevent-alarm-pair (INV-REPORT): needs modsim launched with
//     -advanced (sim/southbound/solar_adv.go) — the base solar sim does not
//     advertise the raise_alarm fault kind at all, so setup()'s
//     POST /fault naturally fails with gridsim's own "unsupported kind"
//     error (sim/southbound/faults.go) and the scenario reports INCONCLUSIVE
//     via the normal setup-failure path — no bespoke probe needed for this
//     one, the fault-arming attempt IS the probe.
//   - cannotcomply-table27 (INV-CANNOTCOMPLY-VOCAB): bench-runnable
//     unconditionally, but its PASS bar assumes the deployed
//     northbound.json has legacy_cannotcomply_code=false (the product
//     default — cmd/northbound/config.go's doc comment notes the shipped
//     EXAMPLE config still ships `true` for MTR-4 paired-change reasons). If
//     the deployed bench still carries that override, this oracle correctly
//     reports the legacy vocabulary as a FAIL — that is the honest signal
//     (deployment drifted from the product default), not a bug in this
//     scenario.
//   - dcap-redirect / redirect-storm (INV-REDIRECT): fully bench-runnable,
//     pure fault injection via gridsim's existing /admin/redirect knob.
package main

import (
	"encoding/xml"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	model "lexa-proto/csipmodel"
)

// ── Track B scenario battery ─────────────────────────────────────────────────

func (d *mayhemDriver) reportingScenarios() []*mayScenario {
	return []*mayScenario{
		derReportRoundtripScenario(),
		pinFreezeEgressHaltScenario(),
		logEventAlarmPairScenario(),
		cannotComplyTable27Scenario(),
		dcapRedirectScenario(),
		redirectStormScenario(),
	}
}

// ── der-report-roundtrip (INV-REPORT) ────────────────────────────────────────

// derPutEntry mirrors gridsim's DERPut JSON shape (sim/gridsim/derput.go),
// redefined locally rather than importing the gridsim package — the same
// "thin local reconstruction of an admin JSON shape" style gridsimAlertCount
// already uses for /admin/alerts (mayhem_ocpp_openadr.go).
type derPutEntry struct {
	Path       string `json:"path"`
	Resource   string `json:"resource"`
	Body       string `json:"body"`
	ReceivedAt int64  `json:"received_at"`
}

// gridsimDERPuts fetches the received DER* report PUTs, keyed by resource
// path (see sim/gridsim/derput.go's handleAdminDERPuts).
func (d *mayhemDriver) gridsimDERPuts() (map[string]derPutEntry, error) {
	var out struct {
		DERPuts    map[string]derPutEntry `json:"der_puts"`
		ServerTime int64                  `json:"server_time"`
	}
	if err := d.getJSON("gridsim", "/admin/derputs", &out); err != nil {
		return nil, err
	}
	return out.DERPuts, nil
}

func derReportRoundtripScenario() *mayScenario {
	var derPuts map[string]derPutEntry
	var derErr error
	return &mayScenario{
		ID: "der-report-roundtrip", Name: "Hub PUTs all four DER* self-report resources (WP-4)",
		Category:   "Northbound reporting (INV-REPORT)",
		Hypothesis: "During ordinary operation (no fault injected) the hub's derreport.Manager (internal/northbound/derreport) must PUT DERCapability, DERSettings, DERStatus, and DERAvailability to the hrefs the discovery walk observed on the self EndDevice's DER tree — CORE-009/CORE-014/BASIC-028's reporting duty. This is a positive-path conformance check, not a fault-injection scenario.",
		Expected:   "gridsim's /admin/derputs shows all four resource types received at least once, each a well-formed, correctly namespaced body: DERCapability's rtgMaxW is a real nameplate rating (> 0 W, not a zero/garbage value) and DERStatus carries a stateOfChargeStatus (the bench's battery contributes a SoC to the site aggregate).",
		HoldS:      75,
		Fix:        "internal/northbound/derreport's putCapabilitySettings/putStatusAvailability — verify the walker is feeding hrefs via OnWalk and the fetcher PUTs are not silently 404/405-skipped (derreport.go's putResource skip latch).",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 60, "Conn": 1})
			d.injectEnv(3000, 1200) // a normal, live midday-ish state — not curtailed, not idle
			return nil, nil
		},
		perTick: func(d *mayhemDriver, i int) { d.injectEnv(3000, 1200) },
		evaluate: func(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
			return diagnoseDERReportRoundtrip(sc, s, derPuts, derErr)
		},
		teardown: func(d *mayhemDriver) {
			derPuts, derErr = d.gridsimDERPuts()
		},
	}
}

// diagnoseDERReportRoundtrip judges der-report-roundtrip. puts/fetchErr are
// captured by the scenario's teardown (after the hold, giving the walk the
// whole window to have PUT at least once) — evaluate has no driver reference
// of its own, so external admin state is always threaded through via a
// closure variable set in setup/teardown, mirroring Track D's
// alertsBefore/alertsAfter pattern (mayhem_ocpp_openadr.go).
func diagnoseDERReportRoundtrip(sc *mayScenario, s []maySample, puts map[string]derPutEntry, fetchErr error) mayFinding {
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
	if fetchErr != nil {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "gridsim /admin/derputs was unreachable — cannot verify the DER* report roundtrip"
		f.Diagnosis = []string{fmt.Sprintf("GET /admin/derputs failed: %v", fetchErr)}
		return f
	}

	byResource := map[string]derPutEntry{}
	for _, put := range puts {
		byResource[put.Resource] = put // last one wins; content sanity only needs one sample per type
	}

	required := []string{"DERCapability", "DERSettings", "DERStatus"}
	var missing []string
	for _, r := range required {
		if _, ok := byResource[r]; !ok {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub never PUT %s", strings.Join(missing, ", "))
		f.Diagnosis = []string{fmt.Sprintf("gridsim /admin/derputs has never received: %s. WP-4's DER* reporting duty is not reaching the server at all for these resources.", strings.Join(missing, ", "))}
		return f
	}

	verdict := "PASS"
	var diag []string

	if cap, ok := byResource["DERCapability"]; ok {
		var full model.DERCapabilityFull
		if err := xml.Unmarshal([]byte(cap.Body), &full); err != nil {
			verdict = "FAIL"
			diag = append(diag, fmt.Sprintf("DERCapability body did not parse as valid 2030.5 XML: %v", err))
		} else {
			watts := float64(full.RtgMaxW.Value) * math.Pow10(int(full.RtgMaxW.Multiplier))
			if watts <= 0 {
				verdict = "FAIL"
				diag = append(diag, fmt.Sprintf("DERCapability.rtgMaxW = %.0f W — expected a real nameplate rating > 0.", watts))
			} else {
				diag = append(diag, fmt.Sprintf("DERCapability.rtgMaxW = %.0f W.", watts))
			}
		}
	}

	if st, ok := byResource["DERStatus"]; ok {
		var full model.DERStatusFull
		if err := xml.Unmarshal([]byte(st.Body), &full); err != nil {
			verdict = "FAIL"
			diag = append(diag, fmt.Sprintf("DERStatus body did not parse as valid 2030.5 XML: %v", err))
		} else if full.StateOfChargeStatus == nil {
			verdict = "FAIL"
			diag = append(diag, "DERStatus carried no stateOfChargeStatus — the bench's battery SoC never reached the server.")
		} else {
			diag = append(diag, fmt.Sprintf("DERStatus.stateOfChargeStatus = %.2f%%.", float64(full.StateOfChargeStatus.Value)/100))
		}
	}

	// DERAvailability: presence-only, and EXCUSED (DEGRADED, not FAIL) if
	// absent — cmd/hub/dersite.go's buildAvailLocked doc says a site with
	// nothing derivable legitimately omits it (G27). This bench's idle
	// battery (SoC>0) + a producing inverter should normally populate it, but
	// a borderline state is not a reporting BUG the way a missing
	// Capability/Settings/Status is.
	if _, ok := byResource["DERAvailability"]; !ok {
		if verdict == "PASS" {
			verdict = "DEGRADED"
		}
		diag = append(diag, "DERAvailability was never PUT — legitimate per G27 when nothing is derivable (no positive SoC / no producing inverter), but worth a manual check against the bench's actual state.")
	} else {
		diag = append(diag, "DERAvailability received.")
	}

	f.Verdict = verdict
	switch verdict {
	case "FAIL":
		f.Headline = "hub PUT a DER* resource with insane/malformed content"
	case "DEGRADED":
		f.Headline = "hub PUT the required DER* resources; DERAvailability absent (see G27 note)"
	default:
		f.Headline = "hub PUT all four DER* resources with sane content"
	}
	f.Diagnosis = diag
	return f
}

// ── pin-freeze-egress-halt (INV-REPORT) ──────────────────────────────────────

// gridsimRegistrationPIN is the fixed Registration.pIN value gridsim serves
// (sim/gridsim/server.go: `PIN: 111115`) — never operator-configurable, so
// any OTHER nonzero registration_pin the deployed hub is configured with is,
// by construction, a mismatch.
const gridsimRegistrationPIN = 111115

// northboundRegistrationPIN reads the deployed hub's northbound.json
// registration_pin over SSH — read-only, mirrors ocppPairingMode's "read the
// live config rather than assume" discipline (mayhem_ocpp_openadr.go).
func (d *mayhemDriver) northboundRegistrationPIN() (pin uint32, present bool, err error) {
	out, err := d.hubSSHOutput(`grep -o '"registration_pin"[[:space:]]*:[[:space:]]*[0-9]*' /etc/lexa/northbound.json 2>/dev/null; true`)
	if err != nil {
		return 0, false, fmt.Errorf("read hub northbound config over SSH: %w", err)
	}
	return parseRegistrationPINLine(out)
}

// parseRegistrationPINLine extracts registration_pin's numeric value from a
// grep -o match of the form `"registration_pin": 654321` (whitespace around
// the colon may vary — mirrors parsePairingModeLine's technique for a
// different key, mayhem_ocpp_openadr.go). present=false, err=nil for an
// empty line (the grep found no match — the key is absent, not a parse
// failure).
func parseRegistrationPINLine(line string) (pin uint32, present bool, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return 0, false, nil
	}
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		return 0, false, fmt.Errorf("could not parse registration_pin from config line %q", line)
	}
	v := strings.TrimSpace(line[idx+1:])
	n, convErr := strconv.ParseUint(v, 10, 32)
	if convErr != nil {
		return 0, false, fmt.Errorf("could not parse registration_pin value %q: %w", v, convErr)
	}
	return uint32(n), true, nil
}

// hubPinOK reads /status's cert_status.pin_ok verdict (bus.CertStatus.PinOK,
// surfaced by cmd/api/handlers.go's certStatusJSON). reachable=false means
// /status itself could not be fetched; pinOK is nil whenever the field is
// absent (check disabled, or no verdict yet — internal/northbound/run/pin.go's
// PinOK doc).
func (d *mayhemDriver) hubPinOK() (pinOK *bool, reachable bool) {
	var st struct {
		CertStatus *struct {
			PinOK *bool `json:"pin_ok,omitempty"`
		} `json:"cert_status,omitempty"`
	}
	if err := d.getJSON("hub", "/status", &st); err != nil {
		return nil, false
	}
	if st.CertStatus == nil {
		return nil, true
	}
	return st.CertStatus.PinOK, true
}

// pinOKStr renders a *bool for a diagnosis/error message.
func pinOKStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	return strconv.FormatBool(*b)
}

func pinFreezeEgressHaltScenario() *mayScenario {
	var derBefore, derAfter map[string]derPutEntry
	var derBeforeErr, derAfterErr error
	var alertsBefore, alertsAfter int
	var logsBefore, logsAfter int
	var pinOKTimeline []*bool
	return &mayScenario{
		ID: "pin-freeze-egress-halt", Name: "Registration PIN mismatch freezes ALL server egress (WP-7/D4)",
		Category:   "Northbound reporting (INV-REPORT)",
		Hypothesis: "Requires registration_pin set to a wrong value: the deployed hub's /etc/lexa/northbound.json registration_pin must already be a NONZERO value other than gridsim's fixed Registration.pIN (111115, sim/gridsim/server.go), with lexa-northbound already restarted so the mismatch has taken effect. This is a DOCUMENTED PRECONDITION, not self-provisioning fault injection — see this file's doc comment for why (no config-patch-and-restart helper exists in mayhem.go, and this track chose not to invent one for a single scenario against a shared bench service). Given that precondition, internal/northbound/run/pin.go's PinVerifier must freeze control adoption AND suspend ALL server egress (DER* PUT, LogEvent, Response) via the shared egress.Gate for as long as the mismatch stands.",
		Expected:   "While pin_ok stays observably false for the whole hold, no NEW DER* PUT, LogEvent, or Response reaches gridsim: /admin/derputs' per-resource received_at timestamps do not advance, and /admin/alerts / /admin/logevents counts do not grow.",
		HoldS:      75,
		Fix:        "internal/northbound/run/pin.go's PinVerifier.Check / internal/northbound/egress/gate.go's Gate.Suspend wiring into derreport.Manager / logevent.Manager / responses.Tracker.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if err := d.hubSSH("true"); err != nil {
				return nil, fmt.Errorf("bench SSH unreachable — cannot even probe the precondition: %w", err)
			}
			pin, present, err := d.northboundRegistrationPIN()
			if err != nil {
				return nil, fmt.Errorf("read deployed registration_pin: %w", err)
			}
			if !present || pin == 0 || pin == gridsimRegistrationPIN {
				return nil, fmt.Errorf(
					"precondition not met: deployed /etc/lexa/northbound.json registration_pin is %d (present=%v) — "+
						"this scenario needs it set to a NONZERO value other than gridsim's fixed Registration.pIN (%d), "+
						"then `sudo systemctl restart lexa-northbound` on the hub, BEFORE running this scenario",
					pin, present, gridsimRegistrationPIN)
			}
			pinOK, reachable := d.hubPinOK()
			if !reachable {
				return nil, fmt.Errorf("hub /status unreachable — cannot confirm pin_ok")
			}
			if pinOK == nil || *pinOK {
				return nil, fmt.Errorf(
					"precondition not met: registration_pin=%d is configured but /status cert_status.pin_ok is not currently false (pin_ok=%s) — "+
						"restart lexa-northbound on the hub so the mismatch takes effect, then re-run this scenario",
					pin, pinOKStr(pinOK))
			}
			if m, err := d.gridsimDERPuts(); err == nil {
				derBefore = m
			} else {
				derBeforeErr = err
			}
			if n, err := d.gridsimAlertCount(); err == nil {
				alertsBefore = n
			}
			if evs, err := d.gridsimLogEvents(); err == nil {
				logsBefore = len(evs)
			}
			return nil, nil
		},
		perTick: func(d *mayhemDriver, i int) {
			pinOK, _ := d.hubPinOK()
			pinOKTimeline = append(pinOKTimeline, pinOK)
		},
		evaluate: func(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
			return diagnosePinFreeze(sc, s, pinOKTimeline, derBefore, derAfter, derBeforeErr, derAfterErr, alertsBefore, alertsAfter, logsBefore, logsAfter)
		},
		teardown: func(d *mayhemDriver) {
			if m, err := d.gridsimDERPuts(); err == nil {
				derAfter = m
			} else {
				derAfterErr = err
			}
			if n, err := d.gridsimAlertCount(); err == nil {
				alertsAfter = n
			}
			if evs, err := d.gridsimLogEvents(); err == nil {
				logsAfter = len(evs)
			}
		},
	}
}

// diagnosePinFreeze judges pin-freeze-egress-halt. It only credits the
// egress-silence window to the freeze when pin_ok was observed false on
// every reachable probe across the whole hold — a probe gap is tolerated
// (nil entries are skipped), but a single observed TRUE flips the verdict to
// INCONCLUSIVE rather than risk attributing a quiet window to a freeze that
// wasn't continuously in force.
func diagnosePinFreeze(sc *mayScenario, s []maySample, pinOKTimeline []*bool,
	derBefore, derAfter map[string]derPutEntry, derBeforeErr, derAfterErr error,
	alertsBefore, alertsAfter, logsBefore, logsAfter int) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if derBeforeErr != nil || derAfterErr != nil {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "gridsim /admin/derputs was unreachable at some point — cannot verify egress silence"
		return f
	}

	seenFalse, seenTrue := 0, 0
	for _, p := range pinOKTimeline {
		if p == nil {
			continue
		}
		if *p {
			seenTrue++
		} else {
			seenFalse++
		}
	}
	if seenFalse == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "pin_ok was never observably false during the hold — precondition did not hold for this run"
		return f
	}
	if seenTrue > 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "pin_ok flipped back to true mid-run — the mismatch was not continuously in force"
		f.Diagnosis = []string{"Something restored the registration PIN (or restarted lexa-northbound with the correct value) partway through this scenario's hold — the egress-silence window can no longer be attributed cleanly to the freeze."}
		return f
	}

	var advanced []string
	for path, before := range derBefore {
		if a, ok := derAfter[path]; ok && a.ReceivedAt != before.ReceivedAt {
			advanced = append(advanced, fmt.Sprintf("%s (%s)", path, before.Resource))
		}
	}
	for path, a := range derAfter {
		if _, ok := derBefore[path]; !ok {
			advanced = append(advanced, fmt.Sprintf("%s (%s, new)", path, a.Resource))
		}
	}
	alertsGrew := alertsAfter > alertsBefore
	logsGrew := logsAfter > logsBefore

	if len(advanced) == 0 && !alertsGrew && !logsGrew {
		f.Verdict = "PASS"
		f.Headline = "server egress stayed silent for the whole pin_ok=false window"
		f.Diagnosis = []string{
			fmt.Sprintf("pin_ok read false on every reachable probe across the %.0fs hold (%d confirming reads, 0 contradicting).", s[len(s)-1].T, seenFalse),
			"gridsim /admin/derputs' received_at timestamps did not advance for any resource, and /admin/alerts / /admin/logevents counts did not grow — DER* PUT, Response, and LogEvent egress all stayed suspended, matching the WP-7/D4 fail-closed contract.",
			"NOTE: this scenario only exercises the FREEZE half of the invariant (a documented precondition — the operator must already have set registration_pin to a wrong value and restarted lexa-northbound). The self-healing half (restoring the PIN clears the freeze and egress resumes) is NOT exercised here; see this file's doc comment for why.",
		}
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = "server egress continued despite pin_ok=false"
	var diag []string
	if len(advanced) > 0 {
		diag = append(diag, fmt.Sprintf("DER* PUT(s) advanced during the freeze: %s.", strings.Join(advanced, ", ")))
	}
	if alertsGrew {
		diag = append(diag, fmt.Sprintf("/admin/alerts grew from %d to %d — a Response posted while egress should have been suspended.", alertsBefore, alertsAfter))
	}
	if logsGrew {
		diag = append(diag, fmt.Sprintf("/admin/logevents grew from %d to %d — a LogEvent posted while egress should have been suspended.", logsBefore, logsAfter))
	}
	diag = append(diag, "internal/northbound/egress/gate.go's Gate.Suspended() is not being honored by every egress path (derreport.Manager / logevent.Manager / responses.Tracker each check it independently before their own POST/PUT).")
	f.Diagnosis = diag
	return f
}

// ── logevent-alarm-pair (INV-REPORT) ─────────────────────────────────────────

// gridsimLogEvents fetches gridsim's received LogEvents in arrival order
// (sim/gridsim/logevent.go's handleAdminLogEvents). Decoding straight into
// []model.LogEvent — the exact type the server encodes — rather than a
// hand-rolled local struct: model.LogEvent carries no json tags, so
// encoding/json falls back to its exported Go field names on BOTH the
// server's encode and this decode, and using the same type on both ends
// means there is no field-name drift to keep in sync.
func (d *mayhemDriver) gridsimLogEvents() ([]model.LogEvent, error) {
	var out struct {
		LogEvents  []model.LogEvent `json:"log_events"`
		ServerTime int64            `json:"server_time"`
	}
	if err := d.getJSON("gridsim", "/admin/logevents", &out); err != nil {
		return nil, err
	}
	return out.LogEvents, nil
}

func logEventAlarmPairScenario() *mayScenario {
	const alarmBit uint32 = 256 // over-frequency (TRACK A contract, cmd/hub/logevent.go's alrm701OverFrequency)
	const alarmCode uint8 = 6   // CSIP Table 14 OVER_FREQUENCY (bus.LogEventDEROverFrequency)
	const rtnCode uint8 = 7     // paired RTN = alarmCode+1 (bus.LogEventRTN)
	const clearAtTick = 45      // clear well past the 10s default logevent_min_interval_s rate floor
	var before, after []model.LogEvent
	var beforeErr, afterErr error
	return &mayScenario{
		ID: "logevent-alarm-pair", Name: "Solar over-frequency alarm posts a LogEvent; RTN posts on clear (WP-6)",
		Category:   "Northbound reporting (INV-REPORT)",
		Hypothesis: "Precondition: modsim must be launched with -advanced (sim/southbound/solar_adv.go) — the base solar sim does not advertise the raise_alarm fault kind, and setup()'s POST /fault will fail (gridsim's own \"unsupported kind\" error) to INCONCLUSIVE otherwise, which IS the probe for this precondition. With that met: setting the solar inverter's SunSpec model 701 Alrm bitfield bit 256 (over-frequency) must make cmd/hub's logEventDetector (cmd/hub/logevent.go) map the transition onto CSIP Table 14 code 6 (OVER_FREQUENCY) and POST a LogEvent; clearing the bit must POST the paired RTN (code 7).",
		Expected:   "gridsim /admin/logevents shows a new LogEvent with logEventCode=6 appearing before a later one with logEventCode=7, both functionSet=11 (DER) — an alarm/RTN pair, time-ordered.",
		HoldS:      75,
		Fix:        "cmd/hub/logevent.go's alrm701ToTable14 mapping / observeBits edge detection; internal/northbound/logevent.go's HandleLogEvent POST path.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			if evs, err := d.gridsimLogEvents(); err == nil {
				before = evs
			} else {
				beforeErr = err
			}
			d.injectEnv(3000, 1200)
			if err := d.post("solar", "/fault", map[string]any{"kind": "raise_alarm", "bits": alarmBit}); err != nil {
				return nil, fmt.Errorf("arm raise_alarm (requires modsim -advanced): %w", err)
			}
			return nil, nil
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(3000, 1200)
			if i == clearAtTick {
				_ = d.post("solar", "/fault", map[string]any{"kind": "raise_alarm", "clear": true})
			}
		},
		evaluate: func(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
			return diagnoseLogEventAlarmPair(sc, s, before, after, beforeErr, afterErr, alarmCode, rtnCode)
		},
		teardown: func(d *mayhemDriver) {
			_ = d.post("solar", "/fault", map[string]any{"kind": "raise_alarm", "clear": true}) // idempotent safety-clear
			if evs, err := d.gridsimLogEvents(); err == nil {
				after = evs
			} else {
				afterErr = err
			}
		},
	}
}

// diagnoseLogEventAlarmPair judges logevent-alarm-pair. before/after isolate
// THIS run's events from any earlier scenario's leftovers (gridsim's
// LogEvent list is append-only and never cleared, mirroring gridsimAlertCount's
// need for a before/after delta — mayhem_ocpp_openadr.go).
func diagnoseLogEventAlarmPair(sc *mayScenario, s []maySample, before, after []model.LogEvent, beforeErr, afterErr error, alarmCode, rtnCode uint8) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	if beforeErr != nil || afterErr != nil {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "gridsim /admin/logevents was unreachable — cannot verify the alarm/RTN pair"
		return f
	}
	if len(after) < len(before) {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "gridsim's LogEvent list shrank between snapshots — cannot isolate this run's events"
		return f
	}
	newEvents := after[len(before):]

	alarmAt, rtnAt := -1, -1
	for i, ev := range newEvents {
		if ev.LogEventCode == alarmCode && alarmAt < 0 {
			alarmAt = i
		}
		if ev.LogEventCode == rtnCode && rtnAt < 0 {
			rtnAt = i
		}
	}
	switch {
	case alarmAt < 0 && rtnAt < 0:
		f.Verdict = "FAIL"
		f.Headline = "no LogEvent posted for the alarm or its RTN"
		f.Diagnosis = []string{
			fmt.Sprintf("gridsim recorded %d new LogEvent(s) this run, none with code %d (alarm) or %d (RTN).", len(newEvents), alarmCode, rtnCode),
			"Either the alarm-edge detector never saw the 701 Alrm bit transition, or lexa-northbound's LogEvent poster never POSTed it (no LogEventListLink discovered, or the POST failed and was dropped per its crash-only stance).",
		}
		return f
	case alarmAt < 0:
		f.Verdict = "FAIL"
		f.Headline = "RTN posted with no preceding alarm LogEvent"
		f.Diagnosis = []string{fmt.Sprintf("Found the RTN (code %d) but no onset (code %d) in this run's new events — either the onset was posted before this scenario's baseline snapshot, or the onset edge was never detected.", rtnCode, alarmCode)}
		return f
	case rtnAt < 0:
		f.Verdict = "FAIL"
		f.Headline = "alarm LogEvent posted, but no RTN followed the clear"
		f.Diagnosis = []string{
			fmt.Sprintf("Onset (code %d) posted, but no RTN (code %d) appeared after the fault was cleared.", alarmCode, rtnCode),
			"cmd/hub/logevent.go's observeBits pairs an onset with its RTN on the same bit clearing — check the logevent_min_interval_s rate floor didn't suppress it, or that the clear was actually observed in a measurement.",
		}
		return f
	case rtnAt < alarmAt:
		f.Verdict = "FAIL"
		f.Headline = "RTN LogEvent arrived before its alarm — not time-ordered"
		f.Diagnosis = []string{fmt.Sprintf("RTN (code %d) appeared at index %d, before the alarm (code %d) at index %d, in gridsim's arrival-ordered LogEvent list.", rtnCode, rtnAt, alarmCode, alarmAt)}
		return f
	}
	f.Verdict = "PASS"
	f.Headline = fmt.Sprintf("alarm (code %d) then its RTN (code %d) posted in order", alarmCode, rtnCode)
	f.Diagnosis = []string{fmt.Sprintf("gridsim /admin/logevents recorded the onset before the RTN among %d new event(s) this run.", len(newEvents))}
	return f
}

// ── cannotcomply-table27 (INV-CANNOTCOMPLY-VOCAB) ────────────────────────────

// gridsimAlertVocabsFor returns the "vocab" tag (see sim/gridsim/server.go's
// VocabLegacy/VocabTable27) of every /admin/alerts entry attributed to mrid.
// ok=false means the fetch itself failed; an ok=true empty slice means the
// fetch succeeded but no alert for this mRID has landed (yet).
func (d *mayhemDriver) gridsimAlertVocabsFor(mrid string) (vocabs []string, ok bool) {
	var out struct {
		Alerts []struct {
			Subject string `json:"subject"`
			Vocab   string `json:"vocab"`
		} `json:"alerts"`
	}
	if err := d.getJSON("gridsim", "/admin/alerts", &out); err != nil {
		return nil, false
	}
	for _, a := range out.Alerts {
		if a.Subject == mrid {
			vocabs = append(vocabs, a.Vocab)
		}
	}
	return vocabs, true
}

func cannotComplyTable27Scenario() *mayScenario {
	var arm *activeConstraint
	var vocabs []string
	var vocabsOK bool
	return &mayScenario{
		ID: "cannotcomply-table27", Name: "Forced CannotComply reports IEEE 2030.5 Table 27 codes, not legacy 0xF0 (WP-7/D5)",
		Category:   "Response compliance (INV-CANNOTCOMPLY-VOCAB)",
		Hypothesis: "A zero-export cap combined with an inverter that ACKs curtailment writes but never applies them (ack_before_effect, delay_s far longer than the hold) is a genuine, sustained breach the hub cannot resolve through any other lever (battery held full, so PV curtailment is the only lever and it's the one blocked). It must eventually admit this via a 2030.5 CannotComply Response. Precondition assumed: the deployed northbound.json has legacy_cannotcomply_code=false (the product default, cmd/northbound/config.go) — the shipped EXAMPLE config ships true for MTR-4 paired-change reasons documented on that key; if the deployed bench still carries that override, this oracle correctly reports the legacy vocabulary as a FAIL rather than a false PASS.",
		Expected:   "gridsim /admin/alerts records the CannotComply Response(s) for this control's mRID with vocab=table27 (IEEE 2030.5 Table 27 status codes — 8/10/252/253/254), never vocab=legacy (the retired LEXA 0xF0-0xFF extension).",
		HoldS:      75,
		Fix:        "internal/northbound/responses/tracker.go's SetLegacyCannotComplyCode wiring / cmd/northbound/config.go's LegacyCannotComplyCode default; verify the deployed northbound.json does not carry \"legacy_cannotcomply_code\": true.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1}) // full → not a lever; PV curtailment is the only lever, and it's blocked below
			d.injectEnv(d.pvHighW, 250)
			if err := d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "delay_s": 600}); err != nil {
				return nil, fmt.Errorf("arm ack_before_effect: %w", err)
			}
			cons, err := d.postCap("exportCap", 0, 75, "mayhem: forced CannotComply for Table 27 vocab check")
			if err != nil {
				return nil, err
			}
			arm = cons
			return cons, nil
		},
		perTick: func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return diagnoseCannotComplyVocab(sc, cons, s, vocabs, vocabsOK)
		},
		teardown: func(d *mayhemDriver) {
			_ = d.post("solar", "/fault", map[string]any{"kind": "ack_before_effect", "clear": true})
			if arm != nil {
				vocabs, vocabsOK = d.gridsimAlertVocabsFor(arm.MRID)
			}
		},
	}
}

// diagnoseCannotComplyVocab layers the INV-CANNOTCOMPLY-VOCAB check on top of
// diagnoseConverge's existing "did the hub admit the unresolved breach"
// judgement (mayhem.go) — the same "audit atop a base verdict" shape
// applySafetyAudit uses, rather than re-deriving convergence/CannotComply
// logic that already exists and is already tested.
func diagnoseCannotComplyVocab(sc *mayScenario, cons *activeConstraint, s []maySample, vocabs []string, vocabsOK bool) mayFinding {
	f := diagnoseConverge(sc, cons, s)
	if f.Verdict == "INCONCLUSIVE" || f.Verdict == "BLIND" {
		return f // the base oracle already couldn't judge this window — nothing to add
	}
	if !f.Metrics.ReportedCannot {
		f.Diagnosis = append(f.Diagnosis, "INV-CANNOTCOMPLY-VOCAB: no CannotComply was posted this run — nothing to classify.")
		return f
	}
	if !vocabsOK {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "CannotComply was posted, but /admin/alerts was unreachable to check its vocabulary"
		f.Diagnosis = append(f.Diagnosis, "gridsim's /admin/alerts could not be read after the hold — INV-CANNOTCOMPLY-VOCAB could not be checked this run.")
		return f
	}

	legacy, table27 := 0, 0
	for _, v := range vocabs {
		switch v {
		case "table27":
			table27++
		case "legacy":
			legacy++
		}
	}
	if legacy > 0 {
		f.Verdict = "FAIL"
		f.Headline = fmt.Sprintf("hub posted the legacy 0xF0 CannotComply extension (%d of %d alerts), not IEEE 2030.5 Table 27", legacy, legacy+table27)
		f.Diagnosis = append(f.Diagnosis, fmt.Sprintf("gridsim /admin/alerts recorded %d legacy-vocabulary CannotComply Response(s) for this control — either legacy_cannotcomply_code is still true in the deployed northbound.json (the product default is false, WP-7/D5), or responses.Tracker regressed the code-flip.", legacy))
		f.Fix = "cmd/northbound/config.go's LegacyCannotComplyCode / internal/northbound/responses/tracker.go's SetLegacyCannotComplyCode wiring; verify the deployed northbound.json does not carry \"legacy_cannotcomply_code\": true."
		return f
	}
	if table27 == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "CannotComply was reported via the sample timeline, but /admin/alerts shows no matching entry for this control's mRID"
		f.Diagnosis = append(f.Diagnosis, "cannotComplyCount saw a positive count during the hold, but the post-hold /admin/alerts read found no entry attributed to this mRID — a gridsim/dashboard timing mismatch, not a vocabulary finding.")
		return f
	}
	f.Diagnosis = append(f.Diagnosis, fmt.Sprintf("INV-CANNOTCOMPLY-VOCAB: all %d recorded CannotComply alert(s) for this control used IEEE 2030.5 Table 27 status codes (vocab=table27), not the legacy 0xF0 extension.", table27))
	return f
}

// ── dcap-redirect / redirect-storm (INV-REDIRECT) ────────────────────────────

// redirectScenario builds one INV-REDIRECT scenario: adopt a safe zero-export
// cap (battery full, so PV curtailment is the only lever, isolating the
// redirect's effect on the safe cap from battery behaviour — same isolation
// technique as malformScenario, mayhem.go), then, once THAT cap is adopted
// (not merely the ever-present bench-default control — armAfterCapAdopted's
// doc explains why that distinction matters), arm gridsim's /dcap redirect
// for count hops. Shared by dcap-redirect (count=1, within redirect_max) and
// redirect-storm (count=5, past it) — both are judged by the identical
// survival bar (diagnoseRedirectSurvival): stay up, keep the safe cap held.
func redirectScenario(id, name, hypothesis, expected string, count int) *mayScenario {
	return &mayScenario{
		ID: id, Name: name,
		Category:   "CSIP robustness (INV-REDIRECT)",
		Hypothesis: hypothesis,
		Expected:   expected,
		HoldS:      75,
		Fix:        "internal/tlsclient/redirect.go's followRedirects/resolveRedirectLocation; internal/northbound/run's fail-closed walk-error hold (RunOnce) for the exceeded-limit case.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(d.pvHighW, 250)
			cons, err := d.postCap("exportCap", 0, 75, fmt.Sprintf("mayhem: export cap then %d-redirect /dcap", count))
			if err != nil {
				return nil, err
			}
			d.armAfterCapAdopted(cons, 2*time.Second, 60*time.Second, func() {
				_ = d.post("gridsim", "/admin/redirect", map[string]any{"path": "/dcap", "code": 302, "count": count})
			})
			return cons, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: diagnoseRedirectSurvival,
		teardown: func(d *mayhemDriver) { _ = d.post("gridsim", "/admin/redirect", map[string]any{"clear": true}) },
	}
}

func dcapRedirectScenario() *mayScenario {
	return redirectScenario("dcap-redirect",
		"A single 302 on /dcap is followed and the walk succeeds (ERR-001)",
		"gridsim's /dcap answers one 302 (Location: /dcap, self-redirect) — well within the hub's redirect_max (3, cmd/northbound/config.go's defaultRedirectMax). internal/tlsclient's followRedirects must follow it and the walk must complete normally.",
		"The walk succeeds via the redirect: the active export cap keeps being enforced and the hub's /status keeps answering throughout — no unseat, no crash.",
		1)
}

func redirectStormScenario() *mayScenario {
	return redirectScenario("redirect-storm",
		"Redirect count exceeds redirect_max — hub fails closed, no crash (ERR-001)",
		"gridsim's /dcap is armed for 5 redirects — more than the hub's redirect_max (3). The walk that hits this exhausts its redirect budget and errors out (\"redirect limit exceeded\", internal/tlsclient/redirect.go's followRedirects); internal/northbound/run.RunOnce's fail-closed discipline must hold the last-known-good control rather than drop it and publish nothing, letting the NEXT walk (which lands past the now-exhausted redirect count) recover normally.",
		"The hub never crashes or goes dark: /status keeps answering throughout, and the active export cap is never unseated — held across the one bad walk cycle and freshly re-adopted once the redirect budget is spent.",
		5)
}

// diagnoseRedirectSurvival judges both dcap-redirect and redirect-storm: the
// same reachability-then-cap-held shape diagnoseMalform (mayhem.go) uses for
// the analogous "hostile/buggy CSIP behaviour must be contained" pattern,
// with redirect-specific messaging. A CannotComply never excuses a breach
// here: this is an export cap, and the hub can always meet it by curtailing
// PV (battery held full) — so a sustained breach means the redirect
// unseated or corrupted the safe control, exactly as diagnoseMalform reasons
// for the identical cap shape.
func diagnoseRedirectSurvival(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
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
		f.Headline = "hub stopped responding under the redirect fault"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples after the redirect was armed — a likely panic, hang, or walker deadlock chasing the redirect.", len(s)-reach, len(s)),
			"A misbehaving/hostile CSIP server (even one just misusing 301/302) must never be able to take the hub down.",
			decisionLine(s),
		}
		f.Fix = "internal/tlsclient/redirect.go: bound the redirect-following loop and fail closed on any error rather than hanging."
		return f
	}

	f.Metrics = scanSamples(cons, s)
	breaches := invExport(cons, s)
	excusableCannot := f.Metrics.ReportedCannot && cons.Typ != "exportCap"
	if len(breaches) == 0 || excusableCannot {
		f.Verdict = "PASS"
		f.Headline = "stayed up and kept enforcing the safe control across the redirect"
		f.Diagnosis = []string{
			"The hub stayed up (/status kept answering) and kept enforcing the active export cap across the redirect fault.",
			invSummaryLine("INV-EXPORT", breaches),
			hubVsRealLine(s),
		}
		forceBlindOnConstraintProbeGap(&f, cons, s)
		return f
	}
	if f.Metrics.TailClean {
		f.Verdict = "DEGRADED"
		f.Headline = "transiently dropped the safe control under the redirect, then recovered"
		f.Diagnosis = []string{
			invSummaryLine("INV-EXPORT", breaches),
			"The redirect briefly unseated the active export cap (the inverter exported over it) but the hub re-established the cap before the end of the window.",
			hubVsRealLine(s),
		}
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = "redirect unseated the safe control"
	f.Diagnosis = []string{
		invSummaryLine("INV-EXPORT", breaches),
		"The redirect fault was served while a safe export cap was active, and the cap stayed breached through the end of the window instead of holding last-known-good.",
		decisionLine(s),
	}
	f.Fix = "internal/northbound/run.RunOnce's fail-closed walk-error hold; internal/tlsclient/redirect.go's redirect-following bound."
	return f
}

// ── Reviewer merge instructions (docs/QA_STANDARDS_BUILDOUT.md's "Merge
//    discipline" — DO NOT self-apply; the reviewer wires these) ─────────────
//
// 1. In scenarios() (mayhem.go), alongside the existing
//    `sc = append(sc, d.mqttScenarios()...)` / `d.worldScenarios()...` /
//    `d.intentScenarios()...` lines, add:
//
//        sc = append(sc, d.reportingScenarios()...)
//
// 2. This track's oracles are all Go-literal scenarios (not qa/scenarios/*.json
//    specs), matching the existing precedent of every mqtt_scenarios.go /
//    mayhem_world.go / mayhem_ocpp_openadr.go oracle, none of which are
//    registered — NO oracleRegistry entry is required for the suite to
//    build/run/pass go vet.
