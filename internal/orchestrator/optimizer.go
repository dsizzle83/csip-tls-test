package orchestrator

import (
	"fmt"
	"math"
	"time"

	"csip-tls-test/internal/csip/model"
)

// DefaultOptimizer is a rule-based + heuristic optimizer.
//
// Priority order (higher number = evaluated later, can be overridden):
//
//  1. Safety      — never exceed device or grid hard limits
//  2. CSIP        — respect active DERControl commands from the utility
//  3. Self-use    — battery absorbs excess solar before it hits the grid
//  4. Demand-resp — battery discharges during peak / demand-response events
//  5. EV charging — allocate available budget to EVSEs
//  6. Cost        — time-of-use adjustments (bonus layer, optional)
//
// All decisions are recorded in Plan.Decisions for observability.
type DefaultOptimizer struct {
	// CostModel is optional; when non-nil it influences battery charge/discharge
	// decisions based on time-of-use pricing.
	CostModel *TOUCostModel

	// Debug enables step-by-step logging of each rule evaluation.
	Debug bool

	// SOCReserve is the minimum SOC [0,100] to keep in the battery for
	// demand-response readiness.  Default 20%.
	SOCReserve float64

	// SOCFullThreshold is the SOC level above which we stop charging.  Default 95%.
	SOCFullThreshold float64

	// ExcessSolarThreshold is the minimum surplus watts before routing to battery.
	// Avoids constant tiny adjustments.  Default 100 W.
	ExcessSolarThreshold float64
}

// NewDefaultOptimizer returns an optimizer with sensible defaults.
func NewDefaultOptimizer() *DefaultOptimizer {
	return &DefaultOptimizer{
		SOCReserve:           20.0,
		SOCFullThreshold:     95.0,
		ExcessSolarThreshold: 100.0,
	}
}

// Optimize evaluates all rules against state and returns a Plan.
func (o *DefaultOptimizer) Optimize(state SystemState) Plan {
	plan := Plan{Timestamp: time.Now()}

	// ── Rule 1: CSIP disconnect command ──────────────────────────────────────
	// Highest priority: if the utility says disconnect, we disconnect.
	if cc := state.CSIPControl; cc != nil {
		if cc.Base.OpModConnect != nil && !*cc.Base.OpModConnect {
			for _, b := range state.Batteries {
				f := false
				plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
					Name:    b.Name,
					Connect: &f,
				})
			}
			plan.AddDecision("csip/disconnect",
				"OpModConnect=false received from utility",
				fmt.Sprintf("disconnecting %d batteries", len(state.Batteries)))
			// When disconnecting, there's nothing else to do.
			return plan
		}
	}

	// ── Derive grid constraints from CSIP ─────────────────────────────────────
	exportLimitW := state.Grid.ExportLimitW // from grid meter / CSIP
	importLimitW := state.Grid.ImportLimitW
	maxLimitW := state.Grid.MaxLimitW

	if cc := state.CSIPControl; cc != nil {
		if lim := cc.Base.OpModExpLimW; lim != nil {
			exportLimitW = nanMin(exportLimitW, apW(lim))
		}
		if lim := cc.Base.OpModMaxLimW; lim != nil {
			maxLimitW = nanMin(maxLimitW, apW(lim))
		}
		if lim := cc.Base.OpModImpLimW; lim != nil {
			importLimitW = nanMin(importLimitW, apW(lim))
		}
	}
	// MaxLimW also constrains exports.
	if !math.IsNaN(maxLimitW) {
		exportLimitW = nanMin(exportLimitW, maxLimitW)
	}

	// ── Compute power balance ─────────────────────────────────────────────────
	//
	// Available power budget for self-consumption and EV charging:
	//   surplus = solar - local_load
	//
	// We approximate local_load as:
	//   local_load ≈ -grid.NetW - totalBattery + totalSolar
	// i.e. whatever is not accounted for by solar and battery = load.
	//
	// If we don't have a grid meter (NetW is NaN), fall back to solar only.
	solarW := state.TotalSolarW()
	batteryW := state.TotalBatteryW() // + discharge, - charge
	evseW := state.TotalEVSEW()

	// Sign conventions (throughout this file):
	//   solarW   >= 0            (generation)
	//   batteryW > 0 discharge, < 0 charge
	//   evseW    >= 0            (consumption)
	//   Grid.NetW > 0 import from grid, < 0 export to grid
	//
	// KCL at the site panel:
	//   solarW + batteryW + Grid.NetW = homeLoadW + evseW
	//   homeLoadW = solarW + max(0,batteryW) + Grid.NetW - evseW
	//     (max(0,batteryW) because charging battery is counted as load, not source)
	//   surplusW = solarW - homeLoadW   (watts available above home loads)
	var surplusW float64 // positive = excess solar available for battery/grid
	if !math.IsNaN(state.Grid.NetW) {
		homeLoadW := solarW + math.Max(0, batteryW) + state.Grid.NetW - evseW
		surplusW = solarW - homeLoadW
	} else {
		// No grid meter: use solar as the budget baseline.
		surplusW = solarW
	}

	if o.Debug {
		homeLoadW := math.NaN()
		if !math.IsNaN(state.Grid.NetW) {
			homeLoadW = solarW + math.Max(0, batteryW) + state.Grid.NetW - evseW
		}
		fmt.Printf("[optimizer] solarW=%.0f batteryW=%.0f evseW=%.0f homeLoadW=%.0f surplusW=%.0f gridNetW=%.0f\n",
			solarW, batteryW, evseW, homeLoadW, surplusW, state.Grid.NetW)
	}

	// ── Rule 2: CSIP export limit enforcement ─────────────────────────────────
	if !math.IsNaN(exportLimitW) {
		// Current net export = solar + battery_discharge - local_load - evse
		netExportW := solarW + math.Max(0, batteryW) - evseW
		if !math.IsNaN(state.Grid.NetW) {
			// Use measured value if available (more accurate).
			netExportW = -state.Grid.NetW // positive = export
		}

		if netExportW > exportLimitW {
			excessW := netExportW - exportLimitW

			// First: absorb excess into battery if possible (skip batteries at SOC threshold).
			for i, b := range state.Batteries {
				if !b.Connected {
					continue
				}
				// Don't charge a battery that's already at its comfort ceiling.
				if !math.IsNaN(b.SOC) && b.SOC >= o.SOCFullThreshold {
					continue
				}
				headroom := b.AvailableChargeW()
				absorb := math.Min(headroom, excessW)
				if absorb > 0 {
					newSetpoint := b.PowerW - absorb // more negative = more charge
					plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
						Name:      b.Name,
						SetpointW: newSetpoint,
					})
					excessW -= absorb
					state.Batteries[i].PowerW = newSetpoint // update for downstream rules
					plan.AddDecision("csip/export-limit",
						fmt.Sprintf("export %.0fW > limit %.0fW; charging battery %s with %.0fW",
							netExportW, exportLimitW, b.Name, absorb),
						fmt.Sprintf("battery %s setpoint → %.0fW", b.Name, newSetpoint))
				}
			}

			// Second: curtail solar if battery can't absorb everything.
			if excessW > 1 {
				for _, sol := range state.Solar {
					if !sol.Connected {
						continue
					}
					curtailTo := math.Max(0, sol.PowerW-excessW)
					plan.SolarCommands = append(plan.SolarCommands, SolarCommand{
						Name:       sol.Name,
						CurtailToW: curtailTo,
					})
					excessW -= (sol.PowerW - curtailTo)
					plan.AddDecision("csip/export-limit",
						fmt.Sprintf("curtailing solar %s to %.0fW to stay under export limit %.0fW",
							sol.Name, curtailTo, exportLimitW),
						fmt.Sprintf("solar %s curtailed from %.0fW → %.0fW",
							sol.Name, sol.PowerW, curtailTo))
					if excessW <= 1 {
						break
					}
				}
			}
		}
	}

	// ── Rule 3: Self-consumption — absorb excess solar into battery ───────────
	if surplusW > o.ExcessSolarThreshold {
		for i, b := range state.Batteries {
			if !b.Connected || !b.Energized {
				continue
			}
			// Don't charge past SOCFullThreshold.
			if !math.IsNaN(b.SOC) && b.SOC >= o.SOCFullThreshold {
				plan.AddDecision("self-consumption",
					fmt.Sprintf("battery %s SOC=%.1f%% >= full threshold %.1f%%",
						b.Name, b.SOC, o.SOCFullThreshold),
					"skip charging — battery full")
				continue
			}
			headroom := b.AvailableChargeW()
			absorb := math.Min(headroom, surplusW)
			if absorb < 50 { // below noise floor, skip
				continue
			}
			newSetpoint := b.PowerW - absorb
			// Don't send a duplicate command if export-limit already set this.
			if !hasBatteryCommand(plan.BatteryCommands, b.Name) {
				plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
					Name:      b.Name,
					SetpointW: newSetpoint,
				})
				plan.AddDecision("self-consumption",
					fmt.Sprintf("%.0fW solar surplus → charging battery %s",
						surplusW, b.Name),
					fmt.Sprintf("battery %s setpoint %.0fW", b.Name, newSetpoint))
			}
			surplusW -= absorb
			state.Batteries[i].PowerW = newSetpoint
		}
	}

	// ── Rule 4: Demand response / peak discharge ──────────────────────────────
	// Discharge battery during peak pricing or when grid import would be needed.
	isDemandResponse := isDRActive(state)
	isPeakHour := o.CostModel != nil && o.CostModel.IsPeakHour(time.Now())

	if isDemandResponse || isPeakHour {
		reason := "demand-response event active"
		if isPeakHour && !isDemandResponse {
			reason = fmt.Sprintf("peak TOU hour (rate=%.3f/kWh)",
				o.CostModel.CurrentRate(time.Now()))
		}

		for i, b := range state.Batteries {
			if !b.Connected || !b.Energized {
				continue
			}
			// Reserve minimum SOC.
			if !math.IsNaN(b.SOC) && b.SOC <= o.SOCReserve {
				plan.AddDecision("demand-response",
					fmt.Sprintf("battery %s SOC=%.1f%% at reserve minimum", b.Name, b.SOC),
					"skip discharge — protecting reserve")
				continue
			}
			available := b.AvailableDischargeW()
			if available < 50 {
				continue
			}
			if !hasBatteryCommand(plan.BatteryCommands, b.Name) {
				plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
					Name:      b.Name,
					SetpointW: available,
				})
				plan.AddDecision("demand-response",
					reason,
					fmt.Sprintf("discharging battery %s at %.0fW", b.Name, available))
				state.Batteries[i].PowerW = available
				surplusW += available
			}
		}
	}

	// ── Rule 5: EV charging allocation ───────────────────────────────────────
	// Distribute available power budget across connected EVSEs.
	for _, evse := range state.EVSEs {
		if !evse.Connected || !evse.SessionActive {
			continue
		}

		maxCurrentA := evse.MaxCurrentA
		voltage := evse.VoltageV
		if voltage <= 0 {
			voltage = 230.0 // assume EU nominal
		}
		maxPowerW := maxCurrentA * voltage

		// Check import limit: reduce EVSE budget if needed.
		if !math.IsNaN(importLimitW) {
			// Remaining grid headroom = importLimitW - current grid import
			// Current grid import ≈ evseW + load - solar - battery
			gridImportW := math.NaN()
			if !math.IsNaN(state.Grid.NetW) {
				gridImportW = state.Grid.NetW
			}
			if !math.IsNaN(gridImportW) && gridImportW >= importLimitW {
				// Grid import already at limit; suspend EVSE or reduce to zero.
				plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
					StationID:   evse.StationID,
					ConnectorID: evse.ConnectorID,
					MaxCurrentA: 0, // suspend
				})
				plan.AddDecision("import-limit",
					fmt.Sprintf("grid import %.0fW at/above limit %.0fW; suspending EVSE %s",
						gridImportW, importLimitW, evse.StationID),
					"EVSE session suspended")
				continue
			}
		}

		// Throttle EV charging if solar surplus allows — prefer solar self-use.
		if solarW > 0 && surplusW < maxPowerW {
			// Only allow EVSE to use what surplus exists + a small grid allowance.
			budgetW := math.Max(0, surplusW)
			limitA := budgetW / voltage
			if limitA < 6 { // below minimum charge current, suspend
				plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
					StationID:   evse.StationID,
					ConnectorID: evse.ConnectorID,
					MaxCurrentA: 0,
				})
				plan.AddDecision("ev-charging",
					fmt.Sprintf("insufficient solar surplus (%.0fW < min 1380W); suspending EVSE %s",
						surplusW, evse.StationID),
					"EVSE suspended to minimise grid import")
			} else {
				limitA = math.Min(limitA, maxCurrentA)
				plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
					StationID:   evse.StationID,
					ConnectorID: evse.ConnectorID,
					MaxCurrentA: limitA,
				})
				plan.AddDecision("ev-charging",
					fmt.Sprintf("solar surplus %.0fW → throttling EVSE %s to %.1fA",
						surplusW, evse.StationID, limitA),
					fmt.Sprintf("EVSE %s limited to %.1fA", evse.StationID, limitA))
				surplusW -= limitA * voltage
			}
		} else {
			// Plenty of surplus or no solar: full rate.
			plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
				StationID:   evse.StationID,
				ConnectorID: evse.ConnectorID,
				MaxCurrentA: maxCurrentA,
			})
			plan.AddDecision("ev-charging",
				fmt.Sprintf("sufficient power available; charging EVSE %s at full %.1fA",
					evse.StationID, maxCurrentA),
				fmt.Sprintf("EVSE %s at %.1fA", evse.StationID, maxCurrentA))
		}
	}

	return plan
}

// ── helpers ───────────────────────────────────────────────────────────────────

// apW converts a model.ActivePower to watts.
func apW(ap *model.ActivePower) float64 {
	return float64(ap.Value) * math.Pow10(int(ap.Multiplier))
}

// nanMin returns the minimum of a and b, treating NaN as "no constraint" (infinity).
func nanMin(a, b float64) float64 {
	if math.IsNaN(a) {
		return b
	}
	if math.IsNaN(b) {
		return a
	}
	return math.Min(a, b)
}

// hasBatteryCommand returns true if a BatteryCommand for name already exists.
func hasBatteryCommand(cmds []BatteryCommand, name string) bool {
	for _, c := range cmds {
		if c.Name == name {
			return true
		}
	}
	return false
}

// isDRActive returns true when the active CSIP control carries a demand-response
// signal — specifically when OpModExpLimW or OpModMaxLimW is set to a value
// below the sum of device capacities.
func isDRActive(state SystemState) bool {
	if state.CSIPControl == nil {
		return false
	}
	base := state.CSIPControl.Base
	// Any export/generation limit from the utility counts as DR.
	return base.OpModExpLimW != nil || base.OpModMaxLimW != nil || base.OpModGenLimW != nil
}
