// Track F — transport / OCPP-lifecycle / rogue-value & boundary fault Mayhem
// scenarios and oracles (audit docs/QA_COMPLETENESS_AUDIT.md P2-2, P2-5, P3-1,
// P3-2, P3-3, Batch 3). New file per the "one track = one file, scenarios in a
// driver method, oracles in the same file" convention (mayhem_csipedge.go /
// mayhem_reporting.go / mayhem_adv.go).
//
// These are the "may surface hub bugs" set: each drives a transport, OCPP
// lifecycle, or rogue-value seam that a correct hub must survive/clamp, and
// several fail LOUDLY if the hub genuinely mishandles the fault (a failing
// scenario that documents a real product bug is kept, not papered over — audit
// §0.1 / the task's "IMPORTANT — hub bugs" note).
//
// Invariant families covered:
//
//	INV-SURVIVE   — a Modbus transport fault (a dropped TCP session, a
//	                wrong-slave read, a torn multi-register read) or an OCPP
//	                lifecycle fault (reordered TransactionEvents, a
//	                mid-transaction BootNotification) must never unseat the safe
//	                control, wedge the hub, or make it go silently blind — it
//	                holds last-known-good and /status keeps answering.
//	INV-SOC       — a battery at a boundary SoC (exact 0% / the 10% reserve
//	                edge) must never be driven the wrong way: no discharge at or
//	                below the reserve floor even when a cap would be met by it.
//	INV-CLAMP     — an out-of-range served limit must SATURATE the SunSpec
//	                WMaxLimPct write to a sane [0,100]%, never WRAP an int16 to a
//	                garbage/negative percent the inverter would honour.
//
// Oracle registration: like every other mayhem_*.go track these scenarios are Go
// literals whose oracles are wired via each scenario's `evaluate` field (not
// qa/scenarios/*.json), so no oracleRegistry entry is required. Every oracle is
// pure (samples → finding) and unit-tested in mayhem_transport_test.go.

package main

import (
	"fmt"
	"time"
)

// ── Track F scenario battery ─────────────────────────────────────────────────

func (d *mayhemDriver) transportScenarios() []*mayScenario {
	return []*mayScenario{
		// Modbus transport faults (server-layer seams, sim/southbound; audit P2-2).
		modbusTCPDropScenario(),
		modbusUnitIDScenario(),
		modbusTearingScenario(),
		// Rogue-value / boundary (audit P3-1/P3-2/P3-3).
		negativeExportLimitScenario(),
		saturatingWriteScenario(),
		batterySOCEmptyScenario(),
		batterySOCReserveEdgeScenario(),
		// OCPP lifecycle faults (sim/evsim; audit P2-5).
		outOfOrderTxScenario(),
		bootMidTxScenario(),
	}
}

// ── Modbus transport faults (INV-SURVIVE) ────────────────────────────────────

// modbusTransportScenario builds one INV-SURVIVE scenario around a Modbus
// server-layer fault armed on the SOLAR inverter: battery full (so PV
// curtailment is the only lever, isolating the fault's effect on a safe
// zero-export cap), adopt the cap, then — once THAT cap is enforced, not the
// ever-present bench default — arm the transport fault for the rest of the
// hold. Shared by the tcp_drop / unit_id / register-tearing scenarios; each
// supplies its own arm/clear closures and an optional reArm (called every
// perTick, for the one-shot tcp_drop that must keep re-firing). Same shape as
// mayhem_csipedge.go's edgeFaultScenario, whose survival bar these mirror.
func modbusTransportScenario(id, name, hypothesis, expected, faultLabel, fix string, arm, clear func(*mayhemDriver), reArm func(*mayhemDriver, int)) *mayScenario {
	return &mayScenario{
		ID:         id,
		Name:       name,
		Category:   "Modbus transport robustness (INV-SURVIVE)",
		Hypothesis: hypothesis,
		Expected:   expected,
		HoldS:      75,
		Fix:        fix,
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
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(d.pvHighW, 250)
			if reArm != nil {
				reArm(d, i)
			}
		},
		evaluate: func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
			return modbusSurvivalFinding(sc, cons, s, faultLabel, fix)
		},
		teardown: func(d *mayhemDriver) {
			clear(d)
			d.deleteControls(0)
		},
	}
}

func modbusTCPDropScenario() *mayScenario {
	return modbusTransportScenario(
		"modbus-tcp-drop",
		"Inverter Modbus TCP connection dropped mid-poll",
		"A flaky link or a device reboot severs the hub's Modbus TCP session to the inverter mid-transaction while a safe zero-export cap is active. The hub's poll loop must reconnect AND hold last-known-good across the gap: the curtailment it already wrote stays on the device, so real export stays capped. It must not fail open (restore the ceiling), act on a truncated read, or wedge waiting on a dead socket.",
		"The hub reconnects and keeps enforcing the safe export cap across the connection drops: /status keeps answering and real export is never unseated.",
		"the dropped Modbus connection",
		"lexa-modbus poll-loop reconnect + fail-closed hold on a read/connection error (internal/southbound); the reconciler reasserts the standing desired on reconnect.",
		func(d *mayhemDriver) { _ = d.post("solar", "/fault", map[string]any{"kind": "tcp_drop"}) },
		func(d *mayhemDriver) {}, // stateless one-shot — nothing to clear
		func(d *mayhemDriver, i int) {
			// Re-drop periodically (i ≈ seconds) so reconnect is exercised repeatedly
			// across the window, not just once at the start.
			if i > 0 && i%15 == 0 {
				_ = d.post("solar", "/fault", map[string]any{"kind": "tcp_drop"})
			}
		},
	)
}

func modbusUnitIDScenario() *mayScenario {
	return modbusTransportScenario(
		"modbus-unit-id-confusion",
		"Inverter answers the wrong Modbus slave id",
		"The inverter has been re-addressed (a common field mis-provisioning) so it no longer answers the unit id the hub polls — every read returns a gateway-target-failed exception (0x0B). While a safe zero-export cap is active, the hub must treat this as device-down, hold the last-known-good curtailment already on the device, and never act on absent data or fail open. Distinct from a plain device-failure: this is a bus-addressing fault (0x0B, not 0x04).",
		"The hub treats the wrong-slave exception as device-down and holds the safe export cap: /status keeps answering and real export is never unseated.",
		"the wrong-slave (0x0B) reads",
		"lexa-modbus must treat a gateway-target-failed exception as device-unavailable, fail closed, and hold last-known-good (internal/southbound); never restore the ceiling on a read that never arrived.",
		func(d *mayhemDriver) { _ = d.post("solar", "/fault", map[string]any{"kind": "unit_id_confusion"}) },
		func(d *mayhemDriver) {
			_ = d.post("solar", "/fault", map[string]any{"kind": "unit_id_confusion", "clear": true})
		},
		nil,
	)
}

func modbusTearingScenario() *mayScenario {
	return modbusTransportScenario(
		"modbus-register-tearing",
		"Inverter serves a torn (non-atomic) multi-register read",
		"The inverter's register bank updates mid-read, so a single ReadHolding of the inverter model returns an internally-inconsistent block — a value spliced from two sampling instants (a torn 32-bit field, or a power register that no longer matches the V/I in the same block). A hub that assumes one read is a coherent snapshot may act on the impossible value; under a safe zero-export cap it must sanity-check rather than raise the ceiling on a bogus low reading. The healthy grid meter is the oracle: real export must stay capped no matter what the torn inverter read said.",
		"The hub does not act on the torn inverter reading to relax curtailment: the healthy grid meter shows the safe export cap held and /status keeps answering.",
		"the torn inverter reads",
		"lexa-modbus / sunspec decode must sanity-check a physically-inconsistent reading rather than trust a single non-atomic ReadHolding (internal/southbound); a torn low reading must not relax an active curtailment.",
		func(d *mayhemDriver) { _ = d.post("solar", "/fault", map[string]any{"kind": "register_tearing"}) },
		func(d *mayhemDriver) {
			_ = d.post("solar", "/fault", map[string]any{"kind": "register_tearing", "clear": true})
		},
		nil,
	)
}

// modbusSurvivalFinding is the INV-SURVIVE oracle for the Modbus transport
// scenarios: the hub must stay reachable and keep enforcing the safe export cap
// through the fault. Self-contained (same reachability→cap-held shape as
// mayhem_csipedge.go's edgeSurvivalFinding, but decoupled from that Batch-2
// file). A CannotComply never excuses a breach here: this is a zero-export cap
// the hub can always meet by curtailing PV (battery held full), so a sustained
// breach means the transport fault unseated or corrupted the safe control.
func modbusSurvivalFinding(sc *mayScenario, cons *activeConstraint, s []maySample, faultLabel, fix string) mayFinding {
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
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples after %s hit — a likely panic, hang, or poll-loop deadlock.", len(s)-reach, len(s), faultLabel),
			"A Modbus transport fault on one device must never take the hub down.",
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
			"The hub stayed up (/status kept answering) and kept enforcing the active export cap across " + faultLabel + " — it held last-known-good rather than failing open on the transport error.",
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
		faultLabel + " was in force while a safe export cap was active, and the cap stayed breached through the end of the window instead of holding last-known-good.",
		decisionLine(s),
	}
	f.Fix = fix
	return f
}

// ── Negative served export limit (INV-SOC / survivability, P3-1) ─────────────

func negativeExportLimitScenario() *mayScenario {
	return &mayScenario{
		ID:         "negative-export-limit",
		Name:       "Grid server serves a NEGATIVE export limit",
		Category:   "CSIP rogue value (INV-SOC / survivability)",
		Hypothesis: "A buggy/hostile 2030.5 server serves a NEGATIVE opModExpLimW (−5000 W). It is representable (ActivePower.Value is a signed int16) but nonsensical as an export ceiling — 'export at most −5000 W' really demands importing ≥5000 W. The audit found the hub's plausibility gate accepts a finite negative (it only rejects NaN/Inf and |w|>1e9), so it currently ADOPTS it as a real limit. Whatever it does, it must be SAFE: never drive the battery past its SoC bounds chasing the impossible cap, and never crash.",
		Expected:   "The hub stays up and handles the negative limit safely — clamp to 0, reject, or adopt-and-enforce are all acceptable; driving the pack past its reserve/ceiling (INV-SOC) or crashing is not. The oracle reports which of the three the hub actually did.",
		HoldS:      75,
		Fix:        "internal/northbound scheduler.plausibleLimit accepts a finite negative export limit today; decide whether a negative opModExpLimW is legal (clamp/reject) or a real limit the optimizer must enforce.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 50, "Conn": 1})
			d.injectEnv(d.pvHighW, 250)
			cons, err := d.postCap("exportCap", 2000, 75, "mayhem: clean export cap then negative limit")
			if err != nil {
				return nil, err
			}
			// Once the CLEAN cap is adopted, mutate the served opModExpLimW negative.
			d.armAfterCapAdopted(cons.Typ, cons.LimW, 2*time.Second, 60*time.Second, func() {
				_ = d.post("gridsim", "/admin/malform", map[string]any{"kind": "negative_activepower"})
			})
			// Judge safety + survival + document adoption, NOT compliance against a
			// nonsensical cap — so Typ "none" (invExport/invHunt skip it) but keep the
			// MRID so a CannotComply is still tracked.
			return &activeConstraint{Typ: "none", MRID: cons.MRID}, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: diagnoseNegativeLimit,
		teardown: func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true})
			d.deleteControls(0)
		},
	}
}

func diagnoseNegativeLimit(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
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
		f.Headline = "hub stopped responding under a negative served export limit"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples after the negative opModExpLimW was served — a likely panic on the rogue value.", len(s)-reach, len(s)),
			"A representable-but-nonsensical served value must be contained, never crash the hub.",
			decisionLine(s),
		}
		return f
	}

	// Document what the hub DID with the negative limit (adopt-and-enforce vs
	// clamp vs reject), read from the adopted control on /status.
	adoptedExport := false
	var lastLim float64
	for _, smp := range s {
		if smp.AdoptedTyp == "exportCap" {
			adoptedExport = true
			lastLim = smp.AdoptedLimW
		}
	}
	var handling string
	switch {
	case !adoptedExport:
		handling = "The hub adopted NO export limit while the negative value was served — it appears to REJECT a negative opModExpLimW (fail-closed drop)."
	case lastLim < 0:
		handling = fmt.Sprintf("The hub ADOPTED the negative limit as-is (exp_lim_W=%.0f W) — adopt-and-enforce. The optimizer is treating a negative export ceiling as a real limit; this run proves it does so without an unsafe reaction, but confirms the audit P3-1 finding that a negative is accepted as plausible.", lastLim)
	case lastLim == 0:
		handling = "The hub CLAMPED the negative limit to 0 W (zero-export) — a conservative, safe interpretation."
	default:
		handling = fmt.Sprintf("The hub adopted exp_lim_W=%.0f W while the negative value was served (it may have substituted a different/last-known-good value).", lastLim)
	}

	cannot := false
	for _, smp := range s {
		if smp.CannotComply {
			cannot = true
		}
	}

	f.Verdict = "PASS"
	f.Headline = "survived a negative served export limit without an unsafe reaction"
	f.Diagnosis = []string{
		"The hub stayed up across the negative opModExpLimW. Safety (no pack driven past its SoC bounds) is enforced by the cross-cutting SAFETY AUDIT below — a genuine INV-SOC/INV-CONNECT violation escalates this verdict.",
		handling,
	}
	if cannot {
		f.Diagnosis = append(f.Diagnosis, "The hub also posted a CannotComply for the control — an honest admission it cannot meet a negative export ceiling.")
	}
	f.Diagnosis = append(f.Diagnosis, hubVsRealLine(s))
	return f
}

// ── Out-of-range write saturation (INV-CLAMP, P3-2) ──────────────────────────

func saturatingWriteScenario() *mayScenario {
	return &mayScenario{
		ID:         "saturating-write-clamp",
		Name:       "Out-of-range served limit must saturate the device write, not wrap",
		Category:   "SunSpec write boundary (INV-CLAMP)",
		Hypothesis: "The hub maps a served export limit into a SunSpec WMaxLimPct write (signed int16, scale −2, so 100% = raw 10000). Two out-of-range inputs are swept: a hard 0-export cap (drives a genuinely LOW ceiling write) and then an absurd 32767×10^9 W ceiling (overflow bait). The written register must SATURATE to a sane [0,100]% — never WRAP an int16 to a negative/garbage percent the inverter would honour as a wild setpoint.",
		Expected:   "The inverter's own WMaxLimPct register (read from the sim /state — ground truth for what was actually WRITTEN over Modbus) stays a sane saturated percentage in [0,100]% throughout: the hard cap writes a genuinely low ceiling, the absurd cap saturates high — never a wrapped-negative or absurd (>100%) value.",
		HoldS:      60,
		Fix:        "lexa-proto sunspec/scale.go saturates int16 on encode (never wraps) and derbase.go clamps w→[0,WMax] before pct; this asserts it end-to-end at the device register.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(d.pvHighW, 250)
			cons, err := d.postCap("exportCap", 0, 60, "mayhem: hard export cap → low ceiling write")
			if err != nil {
				return nil, err
			}
			// After the hard 0-cap has driven a low ceiling write, flip the served
			// limit to the absurd 32767e9 W value — the hub must saturate the write
			// toward 100%, not wrap the int16.
			d.armAfterCapAdopted(cons.Typ, cons.LimW, 2*time.Second, 60*time.Second, func() {
				_ = d.post("gridsim", "/admin/malform", map[string]any{"kind": "huge_activepower"})
			})
			return cons, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: diagnoseSaturatingWrite,
		teardown: func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/malform", map[string]any{"clear": true})
			d.deleteControls(0)
		},
	}
}

// saturatingWriteSaneLoPct / HiPct bound a physically-sane written ceiling. A
// value outside [lo, hi] on the device register is an int16 wrap or a scaling
// overflow (e.g. a negative percent, or hundreds of percent) — the failure this
// oracle exists to catch.
const (
	saturatingWriteSaneLoPct = -1.0
	saturatingWriteSaneHiPct = 101.0
	// A ceiling at or below this proves the write path was genuinely exercised by
	// the hard 0-cap (not a vacuous PASS where nothing was ever written low).
	saturatingWriteExercisedPct = 80.0
)

func diagnoseSaturatingWrite(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	reach := 0
	ceilingReadings := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
		if smp.SolarCeilingOK {
			ceilingReadings++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "FAIL"
		f.Headline = "hub stopped responding while sweeping out-of-range limits"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples — a likely panic on the out-of-range value.", len(s)-reach, len(s)),
			decisionLine(s),
		}
		return f
	}
	if ceilingReadings < len(s)/2 {
		f.Verdict = "BLIND"
		f.Metrics.HubBlind = true
		f.Headline = "inverter ceiling register was unreadable for most of the window"
		f.Diagnosis = []string{
			fmt.Sprintf("The solar sim's WMaxLimPct register — the ground truth for what was actually WRITTEN — answered on only %d of %d samples, so the saturation cannot be verified. Fix the probe and re-run.", ceilingReadings, len(s)),
		}
		return f
	}

	var wrapped []maySample
	exercised := false
	for _, smp := range s {
		if !smp.SolarCeilingOK {
			continue
		}
		if smp.T > mayConvergeDeadlineS && (smp.SolarCeilingPct < saturatingWriteSaneLoPct || smp.SolarCeilingPct > saturatingWriteSaneHiPct) {
			wrapped = append(wrapped, smp)
		}
		if smp.SolarCeilingEna && smp.SolarCeilingPct <= saturatingWriteExercisedPct {
			exercised = true
		}
	}

	if len(wrapped) > 0 {
		w := wrapped[0]
		f.Verdict = "FAIL"
		f.Headline = "the out-of-range limit WRAPPED the written ceiling instead of saturating"
		f.Diagnosis = []string{
			fmt.Sprintf("INV-CLAMP: the inverter's WMaxLimPct register read %.1f%% at t=%.0fs — outside the sane [%.0f,%.0f]%% band. An out-of-range served limit was encoded into a wrapped/garbage int16 rather than saturated, so the device is honouring a wild setpoint.", w.SolarCeilingPct, w.T, saturatingWriteSaneLoPct, saturatingWriteSaneHiPct),
			fmt.Sprintf("%d of the window's samples showed an out-of-band written ceiling.", len(wrapped)),
			decisionLine(s),
		}
		return f
	}

	f.Verdict = "PASS"
	f.Headline = "the written ceiling stayed a sane saturated percentage across the boundary sweep"
	diag := []string{
		fmt.Sprintf("INV-CLAMP: every readable WMaxLimPct sample stayed within the sane [%.0f,%.0f]%% band — the hub saturated the out-of-range writes (hard 0-cap and 32767×10^9 W ceiling) rather than wrapping the int16.", saturatingWriteSaneLoPct, saturatingWriteSaneHiPct),
	}
	if exercised {
		diag = append(diag, "The hard 0-export cap drove a genuinely low ceiling write earlier in the window, so the write path was exercised — this is measured saturation, not a vacuous pass.")
	} else {
		diag = append(diag, "NOTE: no low ceiling was observed, so the hard-cap write path may not have engaged — the sane band held, but treat this as weaker evidence than a run that also showed the low write.")
	}
	f.Diagnosis = diag
	return f
}

// ── Boundary SoC (INV-SOC, P3-3) ─────────────────────────────────────────────

func batterySOCEmptyScenario() *mayScenario {
	return &mayScenario{
		ID:         "battery-soc-empty-discharge",
		Name:       "Import cap while the battery is at 0% SoC",
		Category:   "Battery safety boundary (INV-SOC)",
		Hypothesis: "The pack is at exactly 0% SoC when an import cap arrives that the hub would normally meet by discharging the battery. A hub that commands the empty pack to discharge is trying to walk it below its reserve floor. It must instead refuse the discharge — fall back to another lever or post CannotComply — never source from an empty pack.",
		Expected:   "The hub never discharges the 0% pack (INV-SOC holds on the battery-sim ground truth) and stays up. Failing to meet the import cap with an empty battery is acceptable and correct — refusing the unsafe discharge is the right call. (Note: the sim's own physics floor at 0% also prevents phantom energy, so a clean INV-SOC here is survival + the boundary honoured, with the reserve-edge scenario carrying the sharper teeth.)",
		HoldS:      45,
		Fix:        "internal/orchestrator checkBatterySafety / EvaluateSafety must gate discharge on SoC ≥ reserve; the reconciler must not command a pack past its floor.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 0, "Conn": 1})
			d.injectEnv(300, 1500) // deficit: low PV, high load → import; the hub is tempted to discharge
			return d.postCap("importCap", 800, 45, "mayhem: import cap at 0% SoC")
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(300, 1500) },
		evaluate: diagnoseBoundarySOC,
		teardown: func(d *mayhemDriver) { d.deleteControls(0) },
	}
}

func batterySOCReserveEdgeScenario() *mayScenario {
	return &mayScenario{
		ID:         "battery-soc-reserve-edge",
		Name:       "Charge AND discharge commands at the 10% reserve edge",
		Category:   "Battery safety boundary (INV-SOC)",
		Hypothesis: "The pack sits at exactly its 10% reserve floor while the environment alternates surplus (the hub is pulled to CHARGE) and deficit under an import cap (the hub is pulled to DISCHARGE). Charging at the floor is safe; discharging at or below the floor is not. A hub that leans on the pack to offset import walks it below reserve — the sharp INV-SOC edge, since the sim can physically discharge from 10% (unlike exact 0%).",
		Expected:   "The hub may charge the pack (SoC rises off the floor) but must NEVER discharge it at or below the 10% reserve (INV-SOC holds on the battery-sim ground truth); it stays up throughout both command directions.",
		HoldS:      50,
		Fix:        "internal/orchestrator checkBatterySafety / EvaluateSafety must refuse discharge at/below the reserve floor regardless of the cap; charging at the floor is permitted.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 10, "Conn": 1})
			d.injectEnv(300, 1500) // start in deficit (discharge pull)
			return d.postCap("importCap", 800, 50, "mayhem: import cap at the 10% reserve edge")
		},
		perTick: func(d *mayhemDriver, i int) {
			// Alternate the environment so the hub is commanded to BOTH charge and
			// discharge across the window at the reserve edge.
			if i%2 == 0 {
				d.injectEnv(300, 1500) // deficit → discharge pull
			} else {
				d.injectEnv(d.pvHighW, 250) // surplus → charge pull
			}
		},
		evaluate: diagnoseBoundarySOC,
		teardown: func(d *mayhemDriver) { d.deleteControls(0) },
	}
}

// diagnoseBoundarySOC is the INV-SOC boundary oracle: the hub must never drive
// the pack the wrong way at its SoC bound (no discharge at/below the reserve
// floor, no charge at/above the ceiling), judged on the battery-sim ground
// truth. Cap compliance is deliberately NOT judged — with a boundary pack the
// correct behaviour may be to miss the cap (refusing the unsafe move), so a cap
// breach here is expected, not a failure.
func diagnoseBoundarySOC(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
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
		f.Headline = "hub stopped responding at the SoC boundary"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples at a boundary SoC.", len(s)-reach, len(s)),
			decisionLine(s),
		}
		return f
	}

	avail := probeAvailFrac(s, func(smp maySample) bool { return smp.BatterySimOK })
	viol := pastSettling(invSOC(s))
	if len(viol) == 0 {
		f.Verdict = "PASS"
		f.Headline = "respected the battery SoC boundary"
		f.Diagnosis = []string{
			"INV-SOC held on the battery-sim ground truth: the hub never discharged the pack at/below its reserve floor (nor charged it above its ceiling). Charging a low pack is permitted; refusing an unsafe discharge — even at the cost of missing the cap — is correct.",
			invSummaryLine("INV-SOC", viol),
		}
		// A dead battery probe reading as "no violation" must not manufacture a PASS.
		forceBlindOnProbeGap(&f, "battery", avail)
		return f
	}
	f.Verdict = "FAIL"
	f.Headline = "drove the pack the wrong way at its SoC bound"
	f.Diagnosis = []string{
		invSummaryLine("INV-SOC", viol),
		"The hub moved the battery against its SoC bound (discharging at/below reserve, or charging at/above ceiling) — the exact danger this boundary scenario exists to catch.",
		decisionLine(s),
	}
	return f
}

// ── OCPP lifecycle faults (INV-SURVIVE, P2-5) ────────────────────────────────

// ocppLifecycleScenario builds one INV-SURVIVE scenario around an OCPP lifecycle
// fault: start a freely-charging session (no cap, so the hub sees a live draw
// unconfounded by curtailment), let the hub see it, then arm the fault. Each
// scenario supplies its own arm/clear closures and an optional reArm (for the
// one-shot boot_mid_tx that re-fires across the window).
func ocppLifecycleScenario(id, name, hypothesis, expected, faultLabel, fix string, arm, clear func(*mayhemDriver), reArm func(*mayhemDriver, int)) *mayScenario {
	return &mayScenario{
		ID:         id,
		Name:       name,
		Category:   "OCPP lifecycle robustness (INV-SURVIVE)",
		Hypothesis: hypothesis,
		Expected:   expected,
		HoldS:      60,
		Fix:        fix,
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			_ = d.post("ev", "/inject", map[string]any{"action": "set_soc", "soc_pct": 30})
			_ = d.post("ev", "/inject", map[string]any{"action": "start_session", "connector_id": 1})
			d.injectEnv(300, 500) // neutral env; the EV charges freely so the hub sees a live draw
			// Let the session come up and the hub see it, THEN arm the lifecycle fault.
			d.afterDelay(8*time.Second, func() { arm(d) })
			return &activeConstraint{Typ: "none"}, nil
		},
		perTick: func(d *mayhemDriver, i int) {
			d.injectEnv(300, 500)
			if reArm != nil {
				reArm(d, i)
			}
		},
		evaluate: func(sc *mayScenario, _ *activeConstraint, s []maySample) mayFinding {
			return diagnoseOCPPLifecycle(sc, s, faultLabel, fix)
		},
		teardown: func(d *mayhemDriver) {
			clear(d)
			_ = d.post("ev", "/inject", map[string]any{"action": "stop_session", "connector_id": 1})
		},
	}
}

func outOfOrderTxScenario() *mayScenario {
	return ocppLifecycleScenario(
		"ocpp-out-of-order-txevent",
		"Charger emits TransactionEvents with non-monotonic seqNo",
		"A charger (or a link that reorders frames) emits TransactionEvents whose seqNo is non-monotonic — the Started event carries a HIGHER seqNo than the Updated that follows it. Per OCPP 2.0.1 the CSMS must order/dedupe events by seqNo, not by arrival. A hub that trusts arrival order can mis-sequence the session or double-apply a meter sample. (Audit P2-5: the hub reads SequenceNo but does not validate it today, so the likely outcome is survival-with-no-validation — this confirms it at least does not crash or go blind.)",
		"The hub stays up and keeps a coherent view of the live session across the reordered events — it does not crash or go silently blind to the still-charging car.",
		"the reordered TransactionEvents",
		"cmd/ocpp OnTransactionEvent should order/validate by SequenceNo, not arrival order (lexa-ocpp). This scenario confirms the hub survives and keeps tracking the live session.",
		func(d *mayhemDriver) { _ = d.post("ev", "/fault", map[string]any{"kind": "out_of_order_txevent"}) },
		func(d *mayhemDriver) {
			_ = d.post("ev", "/fault", map[string]any{"kind": "out_of_order_txevent", "clear": true})
		},
		nil,
	)
}

func bootMidTxScenario() *mayScenario {
	return ocppLifecycleScenario(
		"ocpp-boot-mid-tx",
		"Charger sends BootNotification during a live transaction",
		"The charger power-cycles or its CSMS link re-establishes mid-session, sending a BootNotification while a transaction is still open. A correct CSMS reconciles the dangling transaction; a hub that ignores the boot keeps a ghost session, and one that mishandles it can wedge or go blind to a still-charging car. (Audit P2-5: OnBootNotification does not void an active tx today.)",
		"The hub stays up and keeps tracking the live session across the mid-transaction boot(s) — it does not wedge or go silently blind to the still-charging car.",
		"the mid-transaction BootNotification",
		"cmd/ocpp OnBootNotification should reconcile an open transaction on a boot (lexa-ocpp). This scenario confirms the hub survives and keeps tracking the live session across the boot.",
		func(d *mayhemDriver) { _ = d.post("ev", "/fault", map[string]any{"kind": "boot_mid_tx"}) },
		func(d *mayhemDriver) {}, // one-shot — nothing to clear
		func(d *mayhemDriver, i int) {
			// Re-boot periodically so the hub sees several mid-tx boots across the window.
			if i > 0 && i%20 == 0 {
				_ = d.post("ev", "/fault", map[string]any{"kind": "boot_mid_tx"})
			}
		},
	)
}

// diagnoseOCPPLifecycle is the INV-SURVIVE oracle for the OCPP lifecycle faults:
// the hub must stay reachable AND not go silently blind to a still-charging car
// after the fault. "Silently blind" = the ev-sim ground truth shows a live draw
// while the hub's own view reads ~0 and it did NOT flag the EVSE stale (a hub
// that correctly detects it lost sync and marks the source stale is acceptable —
// it knows it is blind). INV-EVMAX (an impossible commanded draw) is covered by
// the cross-cutting safety audit. The oracle always notes the audited
// non-validation so the report is honest about what was and was not proven.
func diagnoseOCPPLifecycle(sc *mayScenario, s []maySample, faultLabel, fix string) mayFinding {
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
			fmt.Sprintf("The hub's /status was unreachable on %d of %d samples after %s — a likely panic or wedge.", len(s)-reach, len(s), faultLabel),
			"An OCPP lifecycle fault must never take the hub down.",
			decisionLine(s),
		}
		f.Fix = fix
		return f
	}

	// Silent-blindness tally over the post-settling window.
	live, blind := 0, 0
	for _, smp := range s {
		if smp.T <= mayConvergeDeadlineS {
			continue
		}
		if smp.EvSimOK && smp.EvSimW > mayEVLiveDrawW {
			live++
			if smp.EvW < mayReactThreshW && !smp.EvStale {
				blind++
			}
		}
	}
	note := "The hub does NOT validate TransactionEvent seqNo ordering / void an open tx on a mid-tx boot today (audit P2-5); this scenario proves it at least survives the fault and keeps a coherent view of the live session — a stronger validation is a lexa-ocpp follow-up, not a crash."

	if live == 0 {
		f.Verdict = "PASS"
		f.Headline = "stayed up across " + faultLabel + " (EV draw coherence not exercised)"
		f.Diagnosis = []string{
			"The hub stayed reachable across " + faultLabel + ". The ev-sim never reported a sustained live draw during the window, so hub-vs-truth EV coherence could not be positively exercised — re-run with a confirmed live session to strengthen this.",
			note,
		}
		return f
	}
	frac := float64(blind) / float64(live)
	switch {
	case frac > 0.5:
		f.Verdict = "FAIL"
		f.Headline = "went silently blind to a still-charging EV after " + faultLabel
		f.Diagnosis = []string{
			fmt.Sprintf("On %d of %d samples where the car was truly drawing (>%d W), the hub's own view read near-zero AND it did NOT flag the EVSE stale — it lost the live session silently after %s.", blind, live, mayEVLiveDrawW, faultLabel),
			"A lifecycle fault that makes the hub silently drop a live session is a real defect: it can no longer attribute or bound that load.",
			note,
		}
		f.Fix = fix
		return f
	case frac > 0.2:
		f.Verdict = "DEGRADED"
		f.Headline = "briefly lost sight of the charging EV after " + faultLabel
		f.Diagnosis = []string{
			fmt.Sprintf("On %d of %d live-draw samples the hub read near-zero without flagging stale, then recovered — a transient loss of the session view after %s.", blind, live, faultLabel),
			note,
		}
		return f
	default:
		f.Verdict = "PASS"
		f.Headline = "stayed up and kept tracking the live EV across " + faultLabel
		f.Diagnosis = []string{
			"The hub stayed reachable and its EV view tracked the ev-sim's true draw across " + faultLabel + " — it did not go silently blind to the live session.",
			note,
		}
		return f
	}
}
