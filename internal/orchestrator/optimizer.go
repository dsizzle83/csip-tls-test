package orchestrator

import (
	"fmt"
	"log"
	"math"
	"time"

	"csip-tls-test/internal/csip/model"
)

// exportGuard carries state across ticks for the conservative export-limit rule.
type exportGuard struct {
	evSetpointA  float64 // last EV current limit issued; math.NaN until first command
	safeCount    int     // consecutive ticks where actual export ≤ conservative target
	activeLimitW float64 // limit value when guard was reset; math.NaN = no active limit
}

// DefaultOptimizer is a rule-based + heuristic optimizer.
//
// Priority order:
//
//  1. Safety        — CSIP disconnect overrides everything
//  2. Fixed dispatch — meet an explicit grid export request (OpModFixedW)
//  3. Export limit  — absorb excess into EVSEs, then battery, then curtail solar
//  4. Self-use      — route solar surplus to battery
//  5. TOU peak      — discharge battery during expensive grid hours
//  6. EV charging   — allocate remaining budget to EVSEs
type DefaultOptimizer struct {
	// CostModel is optional; when non-nil it drives TOU peak discharge.
	CostModel *TOUCostModel

	// Debug enables per-rule logging.
	Debug bool

	// SOCReserve is the minimum SOC [0,100] kept for demand-response.  Default 20%.
	SOCReserve float64

	// SOCFullThreshold is the SOC above which charging stops.  Default 95%.
	SOCFullThreshold float64

	// ExcessSolarThreshold is the minimum surplus watts before routing to battery.
	// Avoids constant tiny adjustments.  Default 100 W.
	ExcessSolarThreshold float64

	// ExportMarginFrac is the safety margin applied to the export limit.
	// The optimizer targets limit×(1−margin) rather than the hard limit.
	// Default 0.15 (operate at 85 % of the limit).
	ExportMarginFrac float64

	// ExportRelaxCycles is the number of consecutive ticks where actual export
	// stays at or below the conservative target before the EV setpoint is
	// allowed to relax.  Default 5.
	ExportRelaxCycles int

	// NowFunc returns the current time.  Nil means time.Now.
	// Override in tests to inject a deterministic clock.
	NowFunc func() time.Time

	// expGuard holds per-limit-session state for the export-limit rule.
	expGuard exportGuard
}

// NewDefaultOptimizer returns an optimizer with sensible defaults.
func NewDefaultOptimizer() *DefaultOptimizer {
	return &DefaultOptimizer{
		SOCReserve:           20.0,
		SOCFullThreshold:     95.0,
		ExcessSolarThreshold: 100.0,
		ExportMarginFrac:     0.15,
		ExportRelaxCycles:    5,
		expGuard:             exportGuard{evSetpointA: math.NaN(), activeLimitW: math.NaN()},
	}
}

func (o *DefaultOptimizer) now() time.Time {
	if o.NowFunc != nil {
		return o.NowFunc()
	}
	return time.Now()
}

// gridConstraints holds effective export/import/max limits after applying CSIP
// overrides on top of grid-reported values.  NaN means unconstrained.
type gridConstraints struct {
	exportLimitW float64
	importLimitW float64
	maxLimitW    float64
}

// Optimize evaluates all rules against state and returns a Plan.
func (o *DefaultOptimizer) Optimize(state SystemState) Plan {
	plan := Plan{Timestamp: o.now()}

	// Rule 1: CSIP disconnect — highest priority, always early-return.
	if csipDisconnectRule(state.CSIPControl, state.Batteries, &plan) {
		return plan
	}

	limits := deriveGridConstraints(state.Grid, state.CSIPControl)
	solarW, batteryW, evseW, surplusW := computePowerBalance(state)
	homeLoadW := state.InferredLoadW()

	if o.Debug {
		log.Printf("[optimizer] solarW=%.0f batteryW=%.0f evseW=%.0f homeLoadW=%.0f surplusW=%.0f gridNetW=%.0f",
			solarW, batteryW, evseW, homeLoadW, surplusW, state.Grid.NetW)
	}

	// Thread a mutable copy of battery states through rules so each rule sees
	// PowerW updated by prior rules (reflects already-committed setpoints).
	batteries := make([]BatteryState, len(state.Batteries))
	copy(batteries, state.Batteries)

	// Rule 2: CSIP fixed dispatch — discharge battery to meet explicit grid export request.
	batteries = applyFixedDispatchRule(state.CSIPControl, batteries, solarW, homeLoadW, o.SOCReserve, &plan)

	// Rule 3: Export/import limit — absorb excess into EVSEs, battery, then curtail solar.
	batteries, surplusW = o.applyExportLimitRule(state.Solar, state.EVSEs, evseW, limits, state.Grid.NetW, o.SOCFullThreshold, surplusW, batteries, &plan)

	// Rule 3.5: Import limit enforcement — discharge battery to reduce grid import.
	batteries = applyImportLimitRule(batteries, limits, state.Grid.NetW, o.SOCReserve, &plan)

	// Rule 4: Self-consumption — route solar surplus to battery.
	batteries, surplusW = applySelfConsumptionRule(batteries, surplusW, o.ExcessSolarThreshold, o.SOCFullThreshold, &plan)

	// Rule 5: TOU peak discharge.
	// CSIP dispatch (OpModFixedW) is handled in Rule 2; this rule covers autonomous peak shifting.
	serverNow := time.Unix(o.now().Unix()+state.ClockOffset, 0)
	isPeak := o.CostModel != nil && o.CostModel.IsPeakHour(serverNow)
	peakReason := ""
	if isPeak {
		peakReason = fmt.Sprintf("peak TOU hour (rate=%.3f/kWh)", o.CostModel.CurrentRate(serverNow))
	}
	batteries, surplusW = applyDemandResponseRule(batteries, surplusW, o.SOCReserve, false, isPeak, peakReason, &plan)

	// Rule 6: EV charging allocation.
	applyEVChargingRule(state.EVSEs, limits, state.Grid.NetW, solarW, surplusW, &plan)

	// Final: restore unconstrained devices so prior setpoints don't persist.
	applyRestoreRule(state.Solar, batteries, o.SOCReserve, &plan)

	return plan
}

// ── Rule functions ─────────────────────────────────────────────────────────────

// csipDisconnectRule issues Connect=false commands when the utility sends
// OpModConnect=false.  Returns true when Optimize should return immediately.
func csipDisconnectRule(cc *CSIPControlState, batteries []BatteryState, plan *Plan) bool {
	if cc == nil || cc.Base.OpModConnect == nil || *cc.Base.OpModConnect {
		return false
	}
	f := false
	for _, b := range batteries {
		plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
			Name:    b.Name,
			Connect: &f,
		})
	}
	plan.AddDecision("csip/disconnect",
		"OpModConnect=false received from utility",
		fmt.Sprintf("disconnecting %d batteries", len(batteries)))
	return true
}

// deriveGridConstraints returns the tightest of CSIP and grid-reported limits.
// NaN in any field means no constraint for that direction.
func deriveGridConstraints(grid GridState, cc *CSIPControlState) gridConstraints {
	c := gridConstraints{
		exportLimitW: grid.ExportLimitW,
		importLimitW: grid.ImportLimitW,
		maxLimitW:    grid.MaxLimitW,
	}
	if cc != nil {
		if lim := cc.Base.OpModExpLimW; lim != nil {
			c.exportLimitW = nanMin(c.exportLimitW, apW(lim))
		}
		if lim := cc.Base.OpModMaxLimW; lim != nil {
			c.maxLimitW = nanMin(c.maxLimitW, apW(lim))
		}
		if lim := cc.Base.OpModImpLimW; lim != nil {
			c.importLimitW = nanMin(c.importLimitW, apW(lim))
		}
	}
	// MaxLimW is an absolute generation cap that also constrains exports.
	if !math.IsNaN(c.maxLimitW) {
		c.exportLimitW = nanMin(c.exportLimitW, c.maxLimitW)
	}
	return c
}

// computePowerBalance returns the site-level power flows and solar surplus.
//
// Sign conventions (throughout the optimizer):
//
//	solarW   >= 0            (generation)
//	batteryW > 0 discharge, < 0 charge
//	evseW    >= 0            (consumption)
//	Grid.NetW > 0 import from grid, < 0 export
//
// surplusW > 0 means solar exceeds home load and is available for battery or grid.
// When no grid meter is present (NetW=NaN) surplusW equals solarW.
func computePowerBalance(state SystemState) (solarW, batteryW, evseW, surplusW float64) {
	solarW = state.TotalSolarW()
	batteryW = state.TotalBatteryW()
	evseW = state.TotalEVSEW()
	if !math.IsNaN(state.Grid.NetW) {
		// surplusW = solar above home load = export available for battery/grid.
		// Grid.NetW < 0 means exporting; evseW is already on the site bus.
		surplusW = -state.Grid.NetW - evseW
	} else {
		surplusW = solarW
	}
	return
}

// applyFixedDispatchRule discharges batteries to meet an explicit grid export
// request (CSIP OpModFixedW).  Solar is credited first; batteries cover the
// shortfall up to SOC reserve.
func applyFixedDispatchRule(cc *CSIPControlState, batteries []BatteryState, solarW, homeLoadW, socReserve float64, plan *Plan) []BatteryState {
	if cc == nil || cc.Base.OpModFixedW == nil {
		return batteries
	}
	targetW := apW(cc.Base.OpModFixedW)

	// How much solar output is already available for grid export?
	var availableW float64
	if !math.IsNaN(homeLoadW) {
		availableW = math.Max(0, solarW-homeLoadW)
	} else {
		availableW = solarW // no grid meter — assume all solar can export
	}

	if availableW >= targetW {
		plan.AddDecision("csip/fixed-dispatch",
			fmt.Sprintf("solar provides %.0fW, covering grid request of %.0fW", availableW, targetW),
			"no battery discharge needed")
		return batteries
	}

	shortfallW := targetW - availableW
	for i, b := range batteries {
		if !b.Connected || !b.Energized {
			continue
		}
		if !math.IsNaN(b.SOC) && b.SOC <= socReserve {
			plan.AddDecision("csip/fixed-dispatch",
				fmt.Sprintf("battery %s SOC=%.1f%% at reserve minimum", b.Name, b.SOC),
				"skip discharge — protecting reserve")
			continue
		}
		if hasBatteryCommand(plan.BatteryCommands, b.Name) {
			continue
		}
		available := b.AvailableDischargeW()
		if available < 50 {
			continue
		}
		dispatchW := math.Min(available, shortfallW)
		newSetpoint := b.PowerW + dispatchW
		plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
			Name:      b.Name,
			SetpointW: newSetpoint,
		})
		plan.AddDecision("csip/fixed-dispatch",
			fmt.Sprintf("grid requests %.0fW; solar covers %.0fW; battery %s dispatches %.0fW",
				targetW, availableW, b.Name, dispatchW),
			fmt.Sprintf("battery %s setpoint → %.0fW", b.Name, newSetpoint))
		batteries[i].PowerW = newSetpoint
		shortfallW -= dispatchW
		if shortfallW <= 1 {
			break
		}
	}
	return batteries
}

// applyExportLimitRule enforces the CSIP/grid export limit conservatively.
//
// Dispatch priority: battery first (absorbs bulk of excess up to rated charge
// power), then EV (absorbs remainder with hysteretic setpoint), then solar
// curtailment as last resort.  Battery-first matches the scenario narrative and
// avoids a round-trip lag: batteries respond in one Modbus write whereas the EV
// ramps over several OCPP MeterValues intervals.
func (o *DefaultOptimizer) applyExportLimitRule(
	solar []SolarState, evses []EVSEState, evseW float64,
	limits gridConstraints, netW, socFull, surplusW float64,
	batteries []BatteryState, plan *Plan,
) ([]BatteryState, float64) {
	if math.IsNaN(limits.exportLimitW) {
		o.expGuard = exportGuard{evSetpointA: math.NaN(), activeLimitW: math.NaN()}
		return batteries, surplusW
	}

	// New limit value → start the guard fresh.
	if limits.exportLimitW != o.expGuard.activeLimitW {
		o.expGuard = exportGuard{evSetpointA: math.NaN(), activeLimitW: limits.exportLimitW}
	}

	margin := o.ExportMarginFrac
	if margin <= 0 {
		margin = 0.15
	}
	relaxCycles := o.ExportRelaxCycles
	if relaxCycles <= 0 {
		relaxCycles = 5
	}
	conservativeW := limits.exportLimitW * (1.0 - margin)

	// Measured export at the meter (positive = sending power to grid).
	// In a settled state actualExportW already reflects whatever the battery is
	// currently absorbing and whatever the EV is currently consuming.
	actualExportW := 0.0
	if !math.IsNaN(netW) {
		actualExportW = math.Max(0, -netW)
	} else {
		for _, sol := range solar {
			actualExportW += sol.PowerW
		}
		for _, b := range batteries {
			actualExportW += math.Max(0, b.PowerW)
		}
		actualExportW -= evseW
	}

	// Track consecutive ticks below the conservative target.
	if actualExportW <= conservativeW {
		o.expGuard.safeCount++
	} else {
		o.expGuard.safeCount = 0
	}

	// Sum current battery absorption across all connected batteries.
	totalBatteryAbsorbW := 0.0
	for _, b := range batteries {
		if b.Connected && b.PowerW < 0 {
			totalBatteryAbsorbW += -b.PowerW
		}
	}

	// Conservation identity: if we removed the battery and the EV, export at the
	// meter would be (current export) + (battery absorption) + (EV consumption).
	// This is independent of how those two devices are currently set, so it is a
	// stable target even when the meter reading lags the device readings.
	unconstrainedExportW := actualExportW + totalBatteryAbsorbW + evseW
	totalAbsorptionNeededW := math.Max(0, unconstrainedExportW-conservativeW)
	remainingAbsorptionW := totalAbsorptionNeededW
	absorbedW := 0.0

	// ── Battery first: absorb up to rated charge power ────────────────────────
	for i, b := range batteries {
		if remainingAbsorptionW <= 1 {
			// No excess to manage — leave the battery to downstream rules
			// (self-consumption, DR/TOU).  Idling it here would just fight
			// applySelfConsumptionRule on the next pass.
			continue
		}
		if !b.Connected {
			continue
		}
		if hasBatteryCommand(plan.BatteryCommands, b.Name) {
			continue
		}
		if !math.IsNaN(b.SOC) && b.SOC >= socFull {
			continue
		}
		// Assign target absolute absorption from this battery, capped by its
		// rated charge power. Note we use MaxChargeW (absolute capability), not
		// AvailableChargeW (headroom from current setpoint), so the command is
		// an absolute setpoint rather than a delta.
		absorb := math.Min(b.MaxChargeW, remainingAbsorptionW)
		if absorb < 50 {
			continue
		}
		newSetpoint := -absorb
		plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
			Name:      b.Name,
			SetpointW: newSetpoint,
		})
		plan.AddDecision("csip/export-limit",
			fmt.Sprintf("export limit %.0fW (target ≤%.0fW); unconstrained export %.0fW; battery %s absorbs %.0fW",
				limits.exportLimitW, conservativeW, unconstrainedExportW, b.Name, absorb),
			fmt.Sprintf("battery %s setpoint → %.0fW", b.Name, newSetpoint))
		remainingAbsorptionW -= absorb
		absorbedW += absorb
		batteries[i].PowerW = newSetpoint
		surplusW -= absorb
	}

	// ── EV: absorb any remaining excess after battery ─────────────────────────
	// Only engage when there is unconstrained excess to manage.  If there is
	// none, Rule 6 (applyEVChargingRule) handles the EV at full rate.  If the
	// batteries cover the full absorption need we still hold the EV at the IEC
	// 61851 minimum so the session doesn't drop — grid import doesn't violate
	// an export limit.
	if totalAbsorptionNeededW >= 50 {
		for i := range evses {
			ev := &evses[i]
			if !ev.Connected || !ev.SessionActive {
				continue
			}
			if hasEVSECommand(plan.EVSECommands, ev.StationID, ev.ConnectorID) {
				continue
			}
			voltage := ev.VoltageV
			if voltage <= 0 {
				voltage = 230.0
			}
			const minChargeA = 6.0 // IEC 61851-1 minimum AC charge current

			targetA := math.Min(remainingAbsorptionW/voltage, ev.MaxCurrentA)
			if targetA < minChargeA {
				targetA = minChargeA // never suspend just because batteries cover the load
			}

			plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
				StationID:   ev.StationID,
				ConnectorID: ev.ConnectorID,
				MaxCurrentA: targetA,
			})
			plan.AddDecision("csip/export-limit",
				fmt.Sprintf("unconstrained export %.0fW; battery absorbs %.0fW; EV absorbs remaining %.0fW",
					unconstrainedExportW, absorbedW, math.Max(0, remainingAbsorptionW)),
				fmt.Sprintf("EVSE %s → %.1fA", ev.StationID, targetA))
			evAbsorbW := math.Min(remainingAbsorptionW, targetA*voltage)
			absorbedW += math.Max(0, evAbsorbW)
			remainingAbsorptionW = math.Max(0, remainingAbsorptionW-targetA*voltage)
			surplusW -= targetA * voltage
			o.expGuard.evSetpointA = targetA
			break // first active EVSE handles the limit; Rule 6 covers the rest
		}
	} else {
		o.expGuard.evSetpointA = math.NaN()
	}

	// ── Solar curtailment: last resort, only above the hard limit ───────────────
	finalExcessW := math.Max(0, unconstrainedExportW-conservativeW-absorbedW)
	if finalExcessW > 1 {
		totalSolarW := 0.0
		for _, sol := range solar {
			if sol.Connected {
				totalSolarW += sol.PowerW
			}
		}
		if totalSolarW > 0 {
			fraction := math.Min(1.0, finalExcessW/totalSolarW)
			for _, sol := range solar {
				if !sol.Connected {
					continue
				}
				curtailTo := sol.PowerW * (1 - fraction)
				plan.SolarCommands = append(plan.SolarCommands, SolarCommand{
					Name:       sol.Name,
					CurtailToW: curtailTo,
				})
				plan.AddDecision("csip/export-limit",
					fmt.Sprintf("curtailing solar %s to %.0fW (hard limit %.0fW still exceeded)",
						sol.Name, curtailTo, limits.exportLimitW),
					fmt.Sprintf("solar %s %.0fW → %.0fW", sol.Name, sol.PowerW, curtailTo))
			}
		}
	}

	return batteries, surplusW
}

// applySelfConsumptionRule routes solar surplus into connected batteries.
// Returns updated battery states and updated surplusW.
//
// When a battery is already charging and its current rate already covers the
// measured surplus (e.g. because the grid meter lags), the rule re-issues the
// current setpoint ("maintain") rather than escalating it each tick.  This
// prevents a runaway charge ramp when the meter reading is stale.
func applySelfConsumptionRule(batteries []BatteryState, surplusW, excessThreshold, socFull float64, plan *Plan) ([]BatteryState, float64) {
	for i, b := range batteries {
		if !b.Connected || !b.Energized {
			continue
		}
		if hasBatteryCommand(plan.BatteryCommands, b.Name) {
			continue
		}
		if !math.IsNaN(b.SOC) && b.SOC >= socFull {
			if surplusW > excessThreshold {
				plan.AddDecision("self-consumption",
					fmt.Sprintf("battery %s SOC=%.1f%% >= full threshold %.1f%%",
						b.Name, b.SOC, socFull),
					"skip charging — battery full")
			}
			continue
		}

		// How much is the battery already absorbing?
		alreadyAbsorbingW := 0.0
		if b.PowerW < 0 {
			alreadyAbsorbingW = -b.PowerW
		}

		// Additional surplus beyond what this battery is already absorbing.
		additionalSurplus := math.Max(0, surplusW-alreadyAbsorbingW)

		if additionalSurplus < excessThreshold {
			// Battery is already covering the surplus; re-issue current setpoint to
			// prevent the restore rule from clearing it, but do not escalate.
			if alreadyAbsorbingW > 0 && surplusW > 0 {
				plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
					Name:      b.Name,
					SetpointW: b.PowerW,
				})
				plan.AddDecision("self-consumption",
					fmt.Sprintf("%.0fW surplus absorbed by %.0fW charge; maintaining battery %s", surplusW, alreadyAbsorbingW, b.Name),
					fmt.Sprintf("battery %s holds %.0fW", b.Name, b.PowerW))
				batteries[i].PowerW = b.PowerW
				surplusW -= alreadyAbsorbingW
			}
			continue
		}

		// Absorb the additional surplus beyond the current charge rate.
		headroom := b.AvailableChargeW()
		absorb := math.Min(headroom, additionalSurplus)
		if absorb < 50 {
			// Battery at capacity — hold current rate so restore rule doesn't idle it.
			if alreadyAbsorbingW > 0 && surplusW > 0 {
				plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
					Name:      b.Name,
					SetpointW: b.PowerW,
				})
				plan.AddDecision("self-consumption",
					fmt.Sprintf("battery %s at capacity (%.0fW); holding while surplus %.0fW remains",
						b.Name, alreadyAbsorbingW, surplusW),
					fmt.Sprintf("battery %s holds %.0fW", b.Name, b.PowerW))
				surplusW -= alreadyAbsorbingW
				batteries[i].PowerW = b.PowerW
			}
			continue
		}
		newSetpoint := b.PowerW - absorb
		plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
			Name:      b.Name,
			SetpointW: newSetpoint,
		})
		plan.AddDecision("self-consumption",
			fmt.Sprintf("%.0fW solar surplus → charging battery %s", surplusW, b.Name),
			fmt.Sprintf("battery %s setpoint %.0fW", b.Name, newSetpoint))
		surplusW -= absorb + alreadyAbsorbingW
		batteries[i].PowerW = newSetpoint
	}
	return batteries, surplusW
}

// applyDemandResponseRule discharges batteries during DR events or TOU peak hours.
// Returns updated battery states and updated surplusW (discharge adds to surplus).
func applyDemandResponseRule(batteries []BatteryState, surplusW, socReserve float64, isDR, isPeak bool, peakReason string, plan *Plan) ([]BatteryState, float64) {
	if !isDR && !isPeak {
		return batteries, surplusW
	}
	reason := "demand-response event active"
	if peakReason != "" {
		reason = peakReason
	}
	for i, b := range batteries {
		if !b.Connected || !b.Energized {
			continue
		}
		if !math.IsNaN(b.SOC) && b.SOC <= socReserve {
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
				SetpointW: b.MaxDischargeW,
			})
			plan.AddDecision("demand-response",
				reason,
				fmt.Sprintf("discharging battery %s at %.0fW", b.Name, b.MaxDischargeW))
			batteries[i].PowerW = b.MaxDischargeW
			surplusW += available
		}
	}
	return batteries, surplusW
}

// applyEVChargingRule distributes the available power budget across connected EVSEs.
//
// When an export limit is active and there is solar surplus but below the IEC 61851
// minimum 6 A, the rule supplements from grid to reach 6 A (provided import headroom
// allows), rather than suspending the session entirely.
func applyEVChargingRule(evses []EVSEState, limits gridConstraints, netW, solarW, surplusW float64, plan *Plan) {
	const minChargeA = 6.0 // IEC 61851-1 minimum AC charge current

	for _, evse := range evses {
		if !evse.Connected || !evse.SessionActive {
			continue
		}
		// Skip EVSEs already commanded (e.g. by export-limit rule).
		if hasEVSECommand(plan.EVSECommands, evse.StationID, evse.ConnectorID) {
			continue
		}

		voltage := evse.VoltageV
		if voltage <= 0 {
			voltage = 230.0
		}
		maxPowerW := evse.MaxCurrentA * voltage
		minChargeW := minChargeA * voltage

		// Suspend if grid import is already at or above the limit.
		if !math.IsNaN(limits.importLimitW) && !math.IsNaN(netW) && netW >= limits.importLimitW {
			plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
				StationID:   evse.StationID,
				ConnectorID: evse.ConnectorID,
				MaxCurrentA: 0,
			})
			plan.AddDecision("import-limit",
				fmt.Sprintf("grid import %.0fW at/above limit %.0fW; suspending EVSE %s",
					netW, limits.importLimitW, evse.StationID),
				"EVSE session suspended")
			continue
		}

		// No grid constraint active: charge at full EVSE rated current.
		// Solar-surplus throttling only makes sense when export is capped —
		// without a constraint the EV is free to draw from the grid.
		if math.IsNaN(limits.exportLimitW) && math.IsNaN(limits.importLimitW) {
			plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
				StationID:   evse.StationID,
				ConnectorID: evse.ConnectorID,
				MaxCurrentA: evse.MaxCurrentA,
			})
			plan.AddDecision("ev-charging",
				fmt.Sprintf("no grid constraint; charging EVSE %s at full %.1fA",
					evse.StationID, evse.MaxCurrentA),
				fmt.Sprintf("EVSE %s at %.1fA", evse.StationID, evse.MaxCurrentA))
			continue
		}

		// Export limit active but site is currently importing (not exporting).
		// The export-limit rule found no excess to manage, so charge at full rate.
		// The export-limit rule re-engages automatically once export exceeds the limit.
		if !math.IsNaN(limits.exportLimitW) && !math.IsNaN(netW) && netW >= 0 {
			plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
				StationID:   evse.StationID,
				ConnectorID: evse.ConnectorID,
				MaxCurrentA: evse.MaxCurrentA,
			})
			plan.AddDecision("ev-charging",
				fmt.Sprintf("export limit %.0fW active but site importing %.0fW; EVSE %s at full %.1fA",
					limits.exportLimitW, netW, evse.StationID, evse.MaxCurrentA),
				fmt.Sprintf("EVSE %s at %.1fA", evse.StationID, evse.MaxCurrentA))
			continue
		}

		if solarW > 0 && surplusW < maxPowerW {
			budgetW := math.Max(0, surplusW)

			// When an export limit is active and there is solar surplus but below minimum
			// charge rate, supplement from grid rather than suspending.
			if !math.IsNaN(limits.exportLimitW) && budgetW > 0 && budgetW < minChargeW {
				supplementW := minChargeW - budgetW
				importHeadroom := math.Inf(1) // unconstrained unless import limit set
				if !math.IsNaN(limits.importLimitW) && !math.IsNaN(netW) {
					importHeadroom = limits.importLimitW - netW
				}
				if supplementW <= importHeadroom {
					plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
						StationID:   evse.StationID,
						ConnectorID: evse.ConnectorID,
						MaxCurrentA: minChargeA,
					})
					plan.AddDecision("ev-charging",
						fmt.Sprintf("%.0fW solar + %.0fW grid supplement → EVSE %s at %.0fA minimum",
							budgetW, supplementW, evse.StationID, minChargeA),
						fmt.Sprintf("EVSE %s at %.0fA", evse.StationID, minChargeA))
					continue
				}
				// Import limit would be violated; suspend.
				plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
					StationID:   evse.StationID,
					ConnectorID: evse.ConnectorID,
					MaxCurrentA: 0,
				})
				plan.AddDecision("ev-charging",
					fmt.Sprintf("%.0fW solar insufficient and import limit prevents supplement; suspending EVSE %s",
						surplusW, evse.StationID),
					"EVSE suspended")
				continue
			}

			limitA := budgetW / voltage
			if limitA < minChargeA {
				plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
					StationID:   evse.StationID,
					ConnectorID: evse.ConnectorID,
					MaxCurrentA: 0,
				})
				plan.AddDecision("ev-charging",
					fmt.Sprintf("insufficient solar surplus (%.0fW < min %.0fW); suspending EVSE %s",
						surplusW, minChargeW, evse.StationID),
					"EVSE suspended to minimise grid import")
			} else {
				limitA = math.Min(limitA, evse.MaxCurrentA)
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
			plan.EVSECommands = append(plan.EVSECommands, EVSECommand{
				StationID:   evse.StationID,
				ConnectorID: evse.ConnectorID,
				MaxCurrentA: evse.MaxCurrentA,
			})
			plan.AddDecision("ev-charging",
				fmt.Sprintf("sufficient power available; charging EVSE %s at full %.1fA",
					evse.StationID, evse.MaxCurrentA),
				fmt.Sprintf("EVSE %s at %.1fA", evse.StationID, evse.MaxCurrentA))
		}
	}
}

// applyImportLimitRule discharges batteries when grid import exceeds the CSIP
// import limit.  It runs after the export-limit rule (which handles EVSEs and
// the charge direction) so it only fires on genuine import over-limit events.
func applyImportLimitRule(batteries []BatteryState, limits gridConstraints, netW, socReserve float64, plan *Plan) []BatteryState {
	if math.IsNaN(limits.importLimitW) {
		return batteries
	}
	importW := 0.0
	if !math.IsNaN(netW) {
		importW = math.Max(0, netW) // positive netW = importing from grid
	}
	if importW <= limits.importLimitW {
		return batteries // within the allowed import window
	}

	result := make([]BatteryState, len(batteries))
	copy(result, batteries)
	deficit := importW - limits.importLimitW

	for i, b := range result {
		if deficit <= 1 {
			break
		}
		if !b.Connected || hasBatteryCommand(plan.BatteryCommands, b.Name) {
			continue
		}
		if !math.IsNaN(b.SOC) && b.SOC <= socReserve {
			continue
		}
		discharge := math.Min(b.AvailableDischargeW(), deficit)
		if discharge <= 0 {
			continue
		}
		result[i].PowerW = discharge
		plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
			Name:      b.Name,
			SetpointW: discharge,
		})
		plan.AddDecision("csip/import-limit",
			fmt.Sprintf("import %.0fW > limit %.0fW; discharging %s at %.0fW", importW, limits.importLimitW, b.Name, discharge),
			fmt.Sprintf("%s → %.0fW discharge", b.Name, discharge))
		deficit -= discharge
	}
	return result
}

// applyRestoreRule sends restore commands for devices that received no command this
// tick so that prior setpoints don't latch in Modbus registers.
// Solar is restored to full output (NaN = nameplate max).
// Battery is idled (0 W) and reconnected so a prior disconnect does not persist.
func applyRestoreRule(solar []SolarState, batteries []BatteryState, socReserve float64, plan *Plan) {
	for _, sol := range solar {
		if sol.Connected && !hasSolarCommand(plan.SolarCommands, sol.Name) {
			plan.SolarCommands = append(plan.SolarCommands, SolarCommand{
				Name:       sol.Name,
				CurtailToW: math.NaN(), // NaN → restore to full nameplate output
			})
		}
	}
	reconnect := true
	for _, b := range batteries {
		if b.Connected && !hasBatteryCommand(plan.BatteryCommands, b.Name) && b.MaxDischargeW > 0 {
			if math.IsNaN(b.SOC) || b.SOC > socReserve {
				plan.BatteryCommands = append(plan.BatteryCommands, BatteryCommand{
					Name:      b.Name,
					SetpointW: 0,          // idle: clear any stale setpoint
					Connect:   &reconnect, // re-assert Conn=1 each tick
				})
			}
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────

func apW(ap *model.ActivePower) float64 {
	return float64(ap.Value) * math.Pow10(int(ap.Multiplier))
}

func nanMin(a, b float64) float64 {
	if math.IsNaN(a) {
		return b
	}
	if math.IsNaN(b) {
		return a
	}
	return math.Min(a, b)
}

func hasBatteryCommand(cmds []BatteryCommand, name string) bool {
	for _, c := range cmds {
		if c.Name == name {
			return true
		}
	}
	return false
}

func hasSolarCommand(cmds []SolarCommand, name string) bool {
	for _, c := range cmds {
		if c.Name == name {
			return true
		}
	}
	return false
}

func hasEVSECommand(cmds []EVSECommand, stationID string, connectorID int) bool {
	for _, c := range cmds {
		if c.StationID == stationID && c.ConnectorID == connectorID {
			return true
		}
	}
	return false
}
