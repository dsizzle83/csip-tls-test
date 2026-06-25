package main

// invariants.go — reusable safety-invariant predicates over a maySample
// timeline. Each predicate corresponds to an INV-* oracle in
// docs/QA_FAULT_INJECTION.md and returns the samples that violate it, so a
// diagnoser can localise *when* and *how* the hub left the safety envelope
// rather than only producing a single pass/fail bit.
//
// These are the building blocks the per-scenario diagnosers share: they are
// expressed in terms of the same primitives the diagnosers use (breachOver,
// convergence), so an invariant and a verdict can never disagree about what a
// breach is. They are pure and unit-tested in invariants_test.go over synthetic
// timelines, independent of the hub or the bench.

import (
	"fmt"
	"strings"
)

const (
	// A battery SoC at or below this percent is treated as "empty" (at its
	// reserve floor); at or above invSocCeilingPct it is treated as "full".
	// Mirrors the batsim Model 802 SoCRsvMin (10%) / SoCMax (95%) defaults.
	invSocReserveFloorPct = 10.0
	invSocCeilingPct      = 95.0
	// |battery W| above this counts as actively charging/discharging (filters
	// idle jitter around zero).
	invSocActiveW = 50.0
	// A DER feeding more than this into the grid counts as still energizing
	// during a cease-to-energize disconnect.
	invConnectEnergizeW = 250.0
	// Grace (s) past a control's validUntil before retaining it is a violation.
	invExpiredGraceS = 30
	// EV draw this many amps over the station max counts as a violation (filters
	// rounding/telemetry noise).
	invEVMaxTolA = 1.0
)

// invViolation is one timestamped breach of a named invariant.
type invViolation struct {
	Inv    string  // "INV-EXPORT" | "INV-SOC" | "INV-CONVERGE"
	T      float64 // seconds since scenario start
	Detail string
}

// invExport flags every sample that exceeds the active grid cap *after* the
// settling deadline. A bounded opening ramp (a sticky-guard curtailment driving
// down over the first mayConvergeDeadlineS seconds) is expected closed-loop
// behaviour and is excused, exactly as diagnoseConstraint excuses it — only a
// sustained, post-deadline breach is an INV-EXPORT violation.
func invExport(cons *activeConstraint, s []maySample) []invViolation {
	if cons == nil || cons.Typ == "none" || cons.Typ == "" {
		return nil
	}
	var v []invViolation
	for _, smp := range s {
		if smp.T <= mayConvergeDeadlineS {
			continue // within the allowed settling window
		}
		if over := breachOver(cons, smp); over > 0 {
			v = append(v, invViolation{
				Inv:    "INV-EXPORT",
				T:      smp.T,
				Detail: fmt.Sprintf("%s over cap %.0f W by %.0f W", cons.Typ, cons.LimW, over),
			})
		}
	}
	return v
}

// invConverge flags a commanded limit that measurement never reached and that
// the hub never admitted. A post-deadline breach is acceptable only if the hub
// posted a CannotComply for the control (an honest admission of a physical
// limit); a sustained breach with no admission is the closed-loop gap this
// invariant exists to catch (the device ACKed but lagged or ignored the write,
// and the hub trusted the ACK).
func invConverge(cons *activeConstraint, s []maySample) []invViolation {
	breaches := invExport(cons, s)
	if len(breaches) == 0 {
		return nil
	}
	for _, smp := range s {
		if smp.CannotComply {
			return nil // the hub admitted it — not a hidden convergence failure
		}
	}
	out := make([]invViolation, 0, len(breaches))
	for _, b := range breaches {
		out = append(out, invViolation{
			Inv:    "INV-CONVERGE",
			T:      b.T,
			Detail: "commanded limit not reached and no CannotComply posted: " + b.Detail,
		})
	}
	return out
}

// invSOC flags any sample where the battery moves the wrong way at its SoC
// bound: discharging at or below the reserve floor, or charging at or above the
// ceiling. This is the danger the wrong_sign / soc_refuse faults create — a
// "charge" command that lands as a discharge walks an already-low pack toward
// empty. Net W > 0 is discharging; < 0 is charging (the batsim convention).
//
// It judges the SIMULATOR ground truth (BatterySimW/BatSimSOC), not the hub's
// Modbus-derived view: a wrong_sign/soc_refuse fault, or a blind/stale/sanitizing
// hub, can make the hub's battery reading disagree with what the pack physically
// does — and the safety oracle must catch the physical reality. Samples without a
// coherent sim reading are skipped (no trustworthy ground truth that tick).
func invSOC(s []maySample) []invViolation {
	var v []invViolation
	for _, smp := range s {
		if !smp.BatterySimOK {
			continue // no trustworthy ground-truth battery reading this tick
		}
		switch {
		case smp.BatterySimW > invSocActiveW && smp.BatSimSOC <= invSocReserveFloorPct:
			v = append(v, invViolation{
				Inv:    "INV-SOC",
				T:      smp.T,
				Detail: fmt.Sprintf("discharging %.0f W at SoC %.0f%% (≤ reserve floor %.0f%%)", smp.BatterySimW, smp.BatSimSOC, invSocReserveFloorPct),
			})
		case smp.BatterySimW < -invSocActiveW && smp.BatSimSOC >= invSocCeilingPct:
			v = append(v, invViolation{
				Inv:    "INV-SOC",
				T:      smp.T,
				Detail: fmt.Sprintf("charging %.0f W at SoC %.0f%% (≥ ceiling %.0f%%)", -smp.BatterySimW, smp.BatSimSOC, invSocCeilingPct),
			})
		}
	}
	return v
}

// invConnectSafe flags any sample where a DER is still energizing the grid while
// a CSIP disconnect (cease-to-energize) is in force — solar producing or the
// battery discharging. A disconnect is the most safety-critical control: the hub
// MUST drive all controllable generation and discharge to ~0. Charging is not
// flagged (it draws from, not feeds, the grid); the concern is back-feeding a
// line the utility believes is dead.
func invConnectSafe(s []maySample) []invViolation {
	var v []invViolation
	for _, smp := range s {
		if !smp.DisconnectActive {
			continue
		}
		if smp.SolarOK && smp.SolarW > invConnectEnergizeW {
			v = append(v, invViolation{
				Inv:    "INV-CONNECT",
				T:      smp.T,
				Detail: fmt.Sprintf("solar still producing %.0f W during a disconnect", smp.SolarW),
			})
		}
		if smp.BatteryW > invConnectEnergizeW {
			v = append(v, invViolation{
				Inv:    "INV-CONNECT",
				T:      smp.T,
				Detail: fmt.Sprintf("battery still discharging %.0f W during a disconnect", smp.BatteryW),
			})
		}
	}
	return v
}

// invExpiredControl flags any sample where the hub is still applying a CSIP
// control whose validUntil (in server time) has passed by more than the grace
// window. A hub that keeps enforcing a stale control — or, worse, never lets it
// expire — is acting on authority the grid server has withdrawn. Server time is
// the sampler wall clock plus the hub's reported clock offset (CSIP §5.2.1.3).
func invExpiredControl(s []maySample) []invViolation {
	var v []invViolation
	for _, smp := range s {
		if !smp.HubAdopted || smp.ValidUntil <= 0 || smp.WallUnix == 0 {
			continue
		}
		serverNow := smp.WallUnix + smp.ClockOffsetS
		if serverNow > smp.ValidUntil+invExpiredGraceS {
			v = append(v, invViolation{
				Inv:    "INV-EXPIRED",
				T:      smp.T,
				Detail: fmt.Sprintf("control still active %ds past validUntil (+%ds grace)", serverNow-smp.ValidUntil, invExpiredGraceS),
			})
		}
	}
	return v
}

// invEVStationMax flags any sample where the EVSE draws more than its configured
// station maximum — a hub command (or a charger) must never exceed the hardware
// limit. The effective draw can only exceed it through a telemetry or sign fault,
// so this doubles as a physical-sanity assertion on the EV channel.
func invEVStationMax(s []maySample) []invViolation {
	var v []invViolation
	for _, smp := range s {
		if smp.EvMaxA > 0 && smp.EvCurrentA > smp.EvMaxA+invEVMaxTolA {
			v = append(v, invViolation{
				Inv:    "INV-EVMAX",
				T:      smp.T,
				Detail: fmt.Sprintf("EV drawing %.1f A over station max %.1f A", smp.EvCurrentA, smp.EvMaxA),
			})
		}
	}
	return v
}

// pastSettling drops violations within the opening settling window. A scenario's
// setup injects extreme device states — a battery forced to 100% or 5% SoC, an
// inverter at nameplate — and the first mayConvergeDeadlineS seconds are the
// system settling from that toward the hub's commanded state, not a hub failure.
// It mirrors the grace invExport and connectBackfeed already apply to the opening
// ramp, so the safety audit can be a deployment gate without false-failing on a
// setup transient (e.g. a pack the harness just forced to 100% briefly finishing
// a charge, or a 5%-injected pack discharging for a tick before the hub's
// reserve-disconnect engages). A SUSTAINED violation persists past the window and
// is still caught.
func pastSettling(v []invViolation) []invViolation {
	out := v[:0:0]
	for _, x := range v {
		if x.T > mayConvergeDeadlineS {
			out = append(out, x)
		}
	}
	return out
}

// connectBackfeed returns the INV-CONNECT violations that PERSIST past the
// reaction grace — a bounded cease-to-energize ramp (the hub driving the
// inverter down to zero over the first mayConvergeDeadlineS seconds) is expected
// and excused, so only a sustained back-feed is a real violation. Shared by
// diagnoseDisconnect and the safety audit so they never disagree.
func connectBackfeed(s []maySample) []invViolation {
	return pastSettling(invConnectSafe(s))
}

// safetyAudit is the assertion engine: it runs the cross-cutting safety
// invariants over every scenario's timeline, independent of that scenario's own
// oracle, so a violation the targeted diagnoser would miss (a battery over-
// discharge during an export-cap test, a back-feed during a disconnect, a stale
// control retained, an impossible EV draw) is still surfaced. The constraint-
// specific invariants (INV-EXPORT/INV-CONVERGE) are intentionally NOT re-run here
// — those are the scenario's primary oracle and would double-judge it.
func safetyAudit(s []maySample) []invViolation {
	var v []invViolation
	v = append(v, connectBackfeed(s)...)               // excuses the bounded cease-to-energize ramp
	v = append(v, pastSettling(invSOC(s))...)          // excuses the setup-SoC settling transient
	v = append(v, invExpiredControl(s)...)             // already grace-bounded by validUntil+invExpiredGraceS
	v = append(v, pastSettling(invEVStationMax(s))...) // excuses an opening EV-current transient
	return v
}

// auditEscalateMinSamples is how many samples a noise-prone safety invariant
// (INV-SOC, INV-EVMAX, INV-EXPIRED) must be violated on before it escalates an
// otherwise-passing verdict. A 1–2 sample HIL transient — a momentary settling
// discharge as a cap engages, a single telemetry spike — is not a gate-worthy
// safety failure; a sustained violation is. This mirrors the settling-ramp grace
// the constraint oracles already apply, and lets the audit be a deployment gate
// without false-failing on bench timing jitter. INV-CONNECT is exempt: a
// back-feed during a disconnect is already ramp-excused by connectBackfeed, and
// any residual is too safety-critical to require repetition.
const auditEscalateMinSamples = 3

// escalateForAudit decides how a cross-cutting safety-audit result should change a
// verdict that is otherwise PASS or DEGRADED, so a safety violation the scenario's
// own oracle would miss is never silently passed:
//   - INV-CONNECT (back-feed during a cease-to-energize) → FAIL on any occurrence.
//   - INV-SOC (pack driven past its reserve) / INV-EVMAX (impossible EV draw) →
//     FAIL when SUSTAINED.
//   - INV-EXPIRED (hub still enforcing a withdrawn control) → DEGRADED when
//     sustained: it is acting on withdrawn authority, but a held cap is
//     conservative and any real harm surfaces as a measured breach the scenario's
//     own oracle already FAILs — so it floors at DEGRADED and never masks a FAIL.
//
// Returns the (possibly unchanged) verdict and, when escalated, a headline. Never
// downgrades a FAIL/INCONCLUSIVE (it only tightens PASS/DEGRADED).
func escalateForAudit(verdict string, audit []invViolation) (newVerdict, headline string) {
	if verdict != "PASS" && verdict != "DEGRADED" {
		return verdict, ""
	}
	count := map[string]int{}
	firstDetail := map[string]string{}
	for _, x := range audit {
		count[x.Inv]++
		if _, ok := firstDetail[x.Inv]; !ok {
			firstDetail[x.Inv] = x.Detail
		}
	}

	if count["INV-CONNECT"] > 0 {
		return "FAIL", "cross-cutting safety violation (INV-CONNECT): " + firstDetail["INV-CONNECT"]
	}
	for _, inv := range []string{"INV-SOC", "INV-EVMAX"} {
		if count[inv] >= auditEscalateMinSamples {
			return "FAIL", "cross-cutting safety violation (" + inv + "): " + firstDetail[inv]
		}
	}
	if count["INV-EXPIRED"] >= auditEscalateMinSamples && verdict == "PASS" {
		return "DEGRADED", "stale control retained past validUntil: " + firstDetail["INV-EXPIRED"]
	}
	return verdict, ""
}

// invSummaryLine renders a one-line summary of an invariant's violations for a
// diagnosis bullet: the count, the window, and the first offending sample.
func invSummaryLine(name string, v []invViolation) string {
	if len(v) == 0 {
		return fmt.Sprintf("%s held: no violations across the window.", name)
	}
	first, last := v[0], v[len(v)-1]
	return fmt.Sprintf("%s violated on %d samples (t=%.0f–%.0fs); first: %s",
		name, len(v), first.T, last.T, first.Detail)
}

// invDetails joins the distinct detail strings of a violation list (deduped,
// order-preserving) for a compact diagnosis bullet.
func invDetails(v []invViolation) string {
	seen := map[string]bool{}
	var parts []string
	for _, x := range v {
		if !seen[x.Detail] {
			seen[x.Detail] = true
			parts = append(parts, x.Detail)
		}
	}
	return strings.Join(parts, "; ")
}
