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
// empty. BatteryW > 0 is discharging; < 0 is charging (the batsim convention).
func invSOC(s []maySample) []invViolation {
	var v []invViolation
	for _, smp := range s {
		if !smp.HubReachable {
			continue // no trustworthy battery reading this tick
		}
		switch {
		case smp.BatteryW > invSocActiveW && smp.BatSOC <= invSocReserveFloorPct:
			v = append(v, invViolation{
				Inv:    "INV-SOC",
				T:      smp.T,
				Detail: fmt.Sprintf("discharging %.0f W at SoC %.0f%% (≤ reserve floor %.0f%%)", smp.BatteryW, smp.BatSOC, invSocReserveFloorPct),
			})
		case smp.BatteryW < -invSocActiveW && smp.BatSOC >= invSocCeilingPct:
			v = append(v, invViolation{
				Inv:    "INV-SOC",
				T:      smp.T,
				Detail: fmt.Sprintf("charging %.0f W at SoC %.0f%% (≥ ceiling %.0f%%)", -smp.BatteryW, smp.BatSOC, invSocCeilingPct),
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
