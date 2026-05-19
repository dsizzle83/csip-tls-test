package orchestrator_test

import (
	"math"
	"testing"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/orchestrator"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func boolPtr(b bool) *bool { return &b }

func ap(w int16) *model.ActivePower { return &model.ActivePower{Value: w, Multiplier: 0} }

func newOpt() *orchestrator.DefaultOptimizer {
	return orchestrator.NewDefaultOptimizer()
}

// state0 returns a minimal system state with no devices and no CSIP signal.
func state0() orchestrator.SystemState {
	return orchestrator.SystemState{
		Timestamp: time.Now(),
		Grid:      orchestrator.NewGridState(),
	}
}

// battery returns a BatteryState for use in tests.
func battery(name string, powerW, soc, maxW float64) orchestrator.BatteryState {
	b := orchestrator.NewBatteryState(name)
	b.PowerW = powerW
	b.SOC = soc
	b.MaxChargeW = maxW
	b.MaxDischargeW = maxW
	b.Connected = true
	b.Energized = true
	return b
}

func solar(name string, powerW, maxW float64) orchestrator.SolarState {
	return orchestrator.SolarState{
		Name: name, PowerW: powerW, MaxW: maxW, Connected: true, Energized: true,
	}
}

func evse(stationID string, sessionActive bool, currentA, maxA, voltageV float64) orchestrator.EVSEState {
	powerW := 0.0
	if sessionActive {
		powerW = currentA * voltageV
	}
	return orchestrator.EVSEState{
		StationID:     stationID,
		ConnectorID:   1,
		Connected:     true,
		SessionActive: sessionActive,
		CurrentA:      currentA,
		MaxCurrentA:   maxA,
		VoltageV:      voltageV,
		PowerW:        powerW,
		Status:        "Occupied",
	}
}

// ── No devices ────────────────────────────────────────────────────────────────

func TestOptimizer_NoDevices_EmptyPlan(t *testing.T) {
	opt := newOpt()
	plan := opt.Optimize(state0())
	if len(plan.BatteryCommands) != 0 || len(plan.SolarCommands) != 0 || len(plan.EVSECommands) != 0 {
		t.Error("expected empty plan with no devices")
	}
}

// ── CSIP disconnect ───────────────────────────────────────────────────────────

func TestOptimizer_CSIPDisconnect_DisconnectsBatteries(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Batteries = []orchestrator.BatteryState{
		battery("bat-0", 0, 50, 5000),
		battery("bat-1", 0, 80, 5000),
	}
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModConnect: boolPtr(false)},
	}

	plan := opt.Optimize(s)

	if len(plan.BatteryCommands) != 2 {
		t.Fatalf("expected 2 disconnect commands, got %d", len(plan.BatteryCommands))
	}
	for _, cmd := range plan.BatteryCommands {
		if cmd.Connect == nil || *cmd.Connect {
			t.Errorf("battery %s: expected Connect=false", cmd.Name)
		}
	}
	// Disconnect is the only action — no solar or EVSE commands.
	if len(plan.SolarCommands) != 0 {
		t.Error("unexpected solar commands after disconnect")
	}
}

// ── CSIP export limit ─────────────────────────────────────────────────────────

func TestOptimizer_CSIPExportLimit_ChargesBattery(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Solar generating 8 kW, export limit is 2 kW → 6 kW must be absorbed.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 8000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 50, 7000)}
	s.Grid.NetW = -8000 // 8 kW export (negative = export)
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(2000)},
	}

	plan := opt.Optimize(s)

	// Expect the battery to be commanded to charge.
	if len(plan.BatteryCommands) == 0 {
		t.Fatal("expected battery charge command to absorb excess export")
	}
	cmd := plan.BatteryCommands[0]
	if cmd.SetpointW >= 0 {
		t.Errorf("battery setpoint = %.0f; expected negative (charging)", cmd.SetpointW)
	}
	// Absorbed at least 6 kW.
	if cmd.SetpointW > -5500 {
		t.Errorf("battery setpoint = %.0f; expected ≤ -5500 to absorb 6 kW excess", cmd.SetpointW)
	}
}

func TestOptimizer_CSIPExportLimit_CurtailsSolar_WhenBatteryFull(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Solar 8 kW, battery full (SOC=96%), export limit 2 kW → curtail solar.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 8000, 10000)}
	b := battery("bat-0", 0, 96, 5000) // battery "full" per SOCFullThreshold=95
	s.Batteries = []orchestrator.BatteryState{b}
	s.Grid.NetW = -8000
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(2000)},
	}

	plan := opt.Optimize(s)

	// Expect solar curtailment.
	if len(plan.SolarCommands) == 0 {
		t.Fatal("expected solar curtailment when battery is full and export limit violated")
	}
	sc := plan.SolarCommands[0]
	if sc.CurtailToW > 2500 {
		t.Errorf("solar curtailed to %.0f W; expected ≤ 2500 W", sc.CurtailToW)
	}
}

// ── Self-consumption ──────────────────────────────────────────────────────────

func TestOptimizer_ExcessSolar_ChargesBattery(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Solar 5 kW, no load, no CSIP. Battery has headroom.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 5000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 40, 5000)}

	plan := opt.Optimize(s)

	if len(plan.BatteryCommands) == 0 {
		t.Fatal("expected battery charge command for excess solar self-consumption")
	}
	cmd := plan.BatteryCommands[0]
	if cmd.SetpointW >= 0 {
		t.Errorf("battery setpoint = %.0f; expected negative (charging)", cmd.SetpointW)
	}
	logDecisions(t, plan)
}

func TestOptimizer_ExcessSolar_SkipCharge_WhenBatteryFull(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 5000, 10000)}
	b := battery("bat-0", 0, 96, 5000) // over SOCFullThreshold
	s.Batteries = []orchestrator.BatteryState{b}

	plan := opt.Optimize(s)

	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW < 0 {
			t.Errorf("battery charged when full: setpoint=%.0f", cmd.SetpointW)
		}
	}
}

// ── Fixed dispatch (OpModFixedW) ──────────────────────────────────────────────

func TestOptimizer_FixedDispatch_DischargesBattery(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Grid requests 3 kW export (OpModFixedW). No solar → battery must cover it.
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 80, 5000)}
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModFixedW: ap(3000)},
	}

	plan := opt.Optimize(s)

	found := false
	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected battery discharge command for fixed dispatch")
	}
	logDecisions(t, plan)
}

func TestOptimizer_FixedDispatch_RespectsSOCReserve(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Battery at 15% — below SOCReserve=20%; should NOT discharge even for dispatch.
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 15, 5000)}
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModFixedW: ap(3000)},
	}

	plan := opt.Optimize(s)

	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW > 0 {
			t.Errorf("battery discharged below SOC reserve: setpoint=%.0f SOC=15%%", cmd.SetpointW)
		}
	}
}

// ── EV charging ───────────────────────────────────────────────────────────────

func TestOptimizer_EV_FullRate_WhenSolarAmple(t *testing.T) {
	opt := newOpt()
	s := state0()

	// 10 kW solar, EVSE at 16A / 230V = 3.68 kW → plenty of surplus.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 10000, 10000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 16.0, 230.0)}

	plan := opt.Optimize(s)

	if len(plan.EVSECommands) == 0 {
		t.Fatal("expected EVSE command")
	}
	cmd := plan.EVSECommands[0]
	if cmd.MaxCurrentA != 16.0 {
		t.Errorf("EVSE MaxCurrentA = %.1f, want 16.0", cmd.MaxCurrentA)
	}
}

func TestOptimizer_EV_ThrottledWhenUnconstrainedAndLowSolar(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Self-consumption priority: even with no grid constraint, the EV must not
	// be driven past available solar surplus or we'd be importing from the
	// grid to charge the car.  Solar 1 kW + EV at 32A=7.36 kW would import
	// ~6 kW; throttle instead.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 1000, 10000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 32.0, 230.0)}

	plan := opt.Optimize(s)

	if len(plan.EVSECommands) == 0 {
		t.Fatal("expected EVSE command")
	}
	if plan.EVSECommands[0].MaxCurrentA >= 32.0 {
		t.Errorf("EVSE MaxCurrentA = %.1f, want throttled below 32A when solar < EV max",
			plan.EVSECommands[0].MaxCurrentA)
	}
}

func TestOptimizer_EV_FullRateWhenUnconstrainedAndSolarAmple(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Solar comfortably covers full EV draw — no need to throttle.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 10000, 10000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 16.0, 230.0)}

	plan := opt.Optimize(s)

	if len(plan.EVSECommands) == 0 {
		t.Fatal("expected EVSE command")
	}
	if plan.EVSECommands[0].MaxCurrentA != 16.0 {
		t.Errorf("EVSE MaxCurrentA = %.1f, want 16A (full) when solar amply covers EV draw",
			plan.EVSECommands[0].MaxCurrentA)
	}
}

func TestOptimizer_EV_Throttled_WhenExportLimited(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Export limit active with only 1 kW solar surplus — EV should be throttled/suspended.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 1000, 10000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 32.0, 230.0)}
	s.Grid.ExportLimitW = 500

	plan := opt.Optimize(s)

	// Export-limit rule handles the EVSE command; it should not command full rate.
	evCmd := plan.EVSECommands
	if len(evCmd) == 0 {
		t.Fatal("expected EVSE command")
	}
	if evCmd[0].MaxCurrentA >= 32.0 {
		t.Errorf("EVSE MaxCurrentA = %.1f, want < 32A when export-limited with low solar", evCmd[0].MaxCurrentA)
	}
}

func TestOptimizer_EV_Suspended_WhenImportLimitReached(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Grid.ImportLimitW = 3000
	s.Grid.NetW = 3500 // already over limit
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 10, 16.0, 230.0)}

	plan := opt.Optimize(s)

	if len(plan.EVSECommands) == 0 {
		t.Fatal("expected EVSE command")
	}
	if plan.EVSECommands[0].MaxCurrentA != 0 {
		t.Errorf("EVSE should be suspended when grid import limit exceeded, got %.1f A",
			plan.EVSECommands[0].MaxCurrentA)
	}
}

func TestOptimizer_EV_NoSession_NoCommand(t *testing.T) {
	opt := newOpt()
	s := state0()
	// EVSE connected but no active session.
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", false, 0, 32.0, 230.0)}

	plan := opt.Optimize(s)

	// No active session → no EVSE command.
	if len(plan.EVSECommands) != 0 {
		t.Errorf("expected no EVSE commands with no active session, got %d", len(plan.EVSECommands))
	}
}

// ── Combined scenario: peak demand event ─────────────────────────────────────

func TestScenario_PeakDemandEvent(t *testing.T) {
	// Setup: CSIP sends 5 kW export limit.  Solar = 8 kW.  Battery at 70%.
	// Expected: battery absorbs 3 kW excess solar.
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 8000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 70, 5000)}
	s.Grid.NetW = -8000 // exporting 8 kW
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(5000)},
	}

	plan := opt.Optimize(s)

	// Expect battery to charge.
	if len(plan.BatteryCommands) == 0 {
		t.Fatal("expected battery command in peak demand scenario")
	}
	bc := plan.BatteryCommands[0]
	if bc.SetpointW >= 0 {
		t.Errorf("expected battery to charge (negative setpoint), got %.0f", bc.SetpointW)
	}
	logDecisions(t, plan)
}

// ── Combined scenario: excess solar + EV charging ────────────────────────────

func TestScenario_ExcessSolarWithEV(t *testing.T) {
	// Solar 7 kW, battery at 50%, EVSE active at 16A/230V ≈ 3.7 kW.
	// Expected: battery gets some charge, EVSE gets throttled or full rate.
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 7000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 50, 5000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 16.0, 230.0)}

	plan := opt.Optimize(s)

	// Battery should charge.
	hasBatteryCharge := false
	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW < 0 {
			hasBatteryCharge = true
		}
	}
	if !hasBatteryCharge {
		t.Error("expected battery to charge with 7 kW solar excess")
	}

	// EVSE should get a command.
	if len(plan.EVSECommands) == 0 {
		t.Error("expected EVSE command")
	}
	logDecisions(t, plan)
}

// ── TOU cost model integration ────────────────────────────────────────────────

func TestOptimizer_TOU_PeakHour_DischargeBattery(t *testing.T) {
	opt := orchestrator.NewDefaultOptimizer()
	opt.CostModel = orchestrator.DefaultTOUCostModel()
	// Force 5 pm — within the 16:00–21:00 peak window in DefaultTOUCostModel.
	opt.NowFunc = func() time.Time {
		return time.Date(2025, 1, 15, 17, 0, 0, 0, time.Local)
	}

	s := state0()
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 80, 5000)}

	plan := opt.Optimize(s)

	found := false
	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected battery discharge during TOU peak hour")
	}
}

// ── Decision trace ────────────────────────────────────────────────────────────

func TestOptimizer_DecisionsAreRecorded(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 5000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 40, 5000)}

	plan := opt.Optimize(s)

	if len(plan.Decisions) == 0 {
		t.Error("expected at least one decision in trace when action is taken")
	}
	for _, d := range plan.Decisions {
		if d.Rule == "" {
			t.Error("decision has empty Rule")
		}
		if d.Reason == "" {
			t.Error("decision has empty Reason")
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func logDecisions(t *testing.T, plan orchestrator.Plan) {
	t.Helper()
	for _, d := range plan.Decisions {
		t.Logf("  [%s] %s → %s", d.Rule, d.Reason, d.Impact)
	}
}

// ── Surplus calculation with non-zero home load ───────────────────────────────
//
// This test catches the historical sign-convention bug where surplusW was
// computed as solarW - (evseW - batteryW + Grid.NetW), which gave double the
// correct value when the grid was exporting.  The correct formula is:
//   homeLoadW = solarW + max(0,batteryW) + Grid.NetW - evseW
//   surplusW  = solarW - homeLoadW

func TestOptimizer_SurplusRespectHomeLoad(t *testing.T) {
	opt := newOpt()
	s := state0()

	// 5 kW solar, 2 kW home load (implied: grid exports 3 kW → NetW = -3000).
	// Battery has 5 kW headroom.  Surplus = 3 kW, so battery should charge ≤ 3 kW.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 5000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 50, 5000)}
	s.Grid.NetW = -3000 // 3 kW export → 2 kW goes to home loads

	plan := opt.Optimize(s)

	if len(plan.BatteryCommands) == 0 {
		t.Fatal("expected battery charge command")
	}
	cmd := plan.BatteryCommands[0]
	if cmd.SetpointW >= 0 {
		t.Errorf("battery setpoint = %.0f; expected negative (charging)", cmd.SetpointW)
	}
	// Old (buggy) formula gave surplusW = 8000, charging up to 5 kW.
	// Correct formula gives surplusW = 3000, so setpoint must be ≥ -3100 (allow rounding).
	if cmd.SetpointW < -3100 {
		t.Errorf("battery setpoint = %.0f exceeds available 3 kW surplus — sign-convention bug?", cmd.SetpointW)
	}
	logDecisions(t, plan)
}

// ── BatteryState helpers ──────────────────────────────────────────────────────

func TestBatteryState_AvailableChargeW(t *testing.T) {
	b := battery("bat", -2000, 50, 5000) // charging at 2kW, max 5kW
	// headroom = MaxChargeW + PowerW = 5000 + (-2000) = 3000
	if got := b.AvailableChargeW(); math.Abs(got-3000) > 1 {
		t.Errorf("AvailableChargeW = %.0f, want 3000", got)
	}
}

func TestBatteryState_AvailableChargeW_WhenDischarging(t *testing.T) {
	// Battery discharging at 3kW: full swing to max charge = 5000+3000 = 8000W.
	// This is the cross-zero case — the battery can swing from +3kW to −5kW.
	b := battery("bat", 3000, 50, 5000)
	if got := b.AvailableChargeW(); math.Abs(got-8000) > 1 {
		t.Errorf("AvailableChargeW when discharging = %.0f, want 8000", got)
	}
}

func TestBatteryState_AvailableDischargeW(t *testing.T) {
	b := battery("bat", 1000, 50, 5000) // discharging at 1kW, max 5kW
	// headroom = MaxDischargeW − PowerW = 5000 − 1000 = 4000
	if got := b.AvailableDischargeW(); math.Abs(got-4000) > 1 {
		t.Errorf("AvailableDischargeW = %.0f, want 4000", got)
	}
}

func TestBatteryState_AvailableDischargeW_WhenCharging(t *testing.T) {
	// Battery charging at 3kW: full swing to max discharge = 5000−(−3000) = 8000W.
	b := battery("bat", -3000, 50, 5000)
	if got := b.AvailableDischargeW(); math.Abs(got-8000) > 1 {
		t.Errorf("AvailableDischargeW when charging = %.0f, want 8000", got)
	}
}

func TestBatteryState_Disconnected_ZeroHeadroom(t *testing.T) {
	b := battery("bat", 0, 50, 5000)
	b.Connected = false
	if got := b.AvailableChargeW(); got != 0 {
		t.Errorf("AvailableChargeW disconnected = %.0f, want 0", got)
	}
	if got := b.AvailableDischargeW(); got != 0 {
		t.Errorf("AvailableDischargeW disconnected = %.0f, want 0", got)
	}
}

// TestOptimizer_ExportLimit_SwitchesBatteryFromDischargeToCharge verifies that
// when the battery is discharging and an export limit is applied, the optimizer
// commands immediate charging in a single tick rather than only reducing discharge.
//
// Scenario: battery +3kW, solar 5kW, load 2kW → 6kW export. Limit = 0W.
// Required setpoint: 3000 − 6000 = −3000W.  Old (buggy) headroom capped at
// MaxChargeW=5kW, absorbing only 5kW → setpoint −2000W, still 1kW over limit.
func TestOptimizer_ExportLimit_SwitchesBatteryFromDischargeToCharge(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 5000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 3000, 50, 5000)} // discharging
	s.Grid.NetW = -6000                                                           // 6kW export
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(0)},
	}

	plan := opt.Optimize(s)

	if len(plan.BatteryCommands) == 0 {
		t.Fatal("expected battery command")
	}
	cmd := plan.BatteryCommands[0]
	// Must absorb the full 6kW excess: 3000 − 6000 = −3000W.
	if cmd.SetpointW > -2500 {
		t.Errorf("setpoint = %.0fW; expected ≤ −2500W to absorb the 6kW excess in one tick (was discharging at 3kW)", cmd.SetpointW)
	}
	logDecisions(t, plan)
}

// ── Document scenarios ────────────────────────────────────────────────────────

// Case 1: export limit 1kW, solar 2kW, home 1kW, battery full, EV needs charge.
// Expected: EV charges using solar surplus; no grid export above limit.
func TestScenario_Case1_EVChargesWithSolarSurplus(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 2000, 3000)}
	b := battery("bat-0", 0, 96, 5000) // full (SOC above threshold)
	s.Batteries = []orchestrator.BatteryState{b}
	s.Grid.NetW = -1000 // exporting 1kW, exactly at limit
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(1000)},
	}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 32.0, 230.0)}

	plan := opt.Optimize(s)

	// EV should receive a charge command at ≥ 6A (minimum) using solar + grid supplement.
	if len(plan.EVSECommands) == 0 {
		t.Fatal("expected EVSE command to charge EV with solar surplus")
	}
	cmd := plan.EVSECommands[0]
	if cmd.MaxCurrentA < 6.0 {
		t.Errorf("EV should charge at ≥6A minimum, got %.1fA", cmd.MaxCurrentA)
	}
	// Battery should not charge (already full).
	for _, bc := range plan.BatteryCommands {
		if bc.SetpointW < 0 {
			t.Errorf("battery should not charge when full (SOC=96%%)")
		}
	}
	logDecisions(t, plan)
}

// Case 2: grid requests 10kW (OpModFixedW), solar 10kW, home 1kW, battery full.
// Expected: solar provides 9kW; battery discharges 1kW to cover shortfall.
func TestScenario_Case2_FixedDispatch_BatteryCoversShortfall(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 10000, 10000)}
	b := battery("bat-0", 0, 100, 5000) // full, idle
	s.Batteries = []orchestrator.BatteryState{b}
	s.Grid.NetW = -9000 // exporting 9kW (solar minus home load)
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModFixedW: ap(10000)},
	}

	plan := opt.Optimize(s)

	// Battery must discharge to cover the 1kW shortfall.
	found := false
	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW > 0 {
			found = true
			if cmd.SetpointW < 500 || cmd.SetpointW > 2000 {
				t.Errorf("battery setpoint = %.0fW; expected ~1000W (1kW shortfall)", cmd.SetpointW)
			}
		}
	}
	if !found {
		t.Fatal("expected battery discharge to cover grid dispatch shortfall")
	}
	logDecisions(t, plan)
}

// Case 3: export limit 0W, solar 2kW, home 1kW, battery 50%, EV full.
// Expected: battery absorbs the 1kW surplus; solar not curtailed.
// When battery is full: solar gets curtailed instead.
func TestScenario_Case3_ExportZero_BatteryAbsorbsSurplus(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 2000, 3000)}
	b := battery("bat-0", 0, 50, 5000)
	s.Batteries = []orchestrator.BatteryState{b}
	s.Grid.NetW = -1000 // exporting 1kW (= excess over export limit 0)
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(0)},
	}

	plan := opt.Optimize(s)

	// Battery should charge to absorb the 1kW surplus.
	found := false
	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW < 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected battery to absorb 1kW surplus when export=0W")
	}
	// Solar should not be curtailed (battery has headroom).
	for _, sc := range plan.SolarCommands {
		if !math.IsNaN(sc.CurtailToW) && sc.CurtailToW < 1900 {
			t.Errorf("solar curtailed to %.0fW; battery has headroom, should not curtail", sc.CurtailToW)
		}
	}
	logDecisions(t, plan)
}

// Regression for the demo S1 *discovery-gap* overshoot: the dashboard starts
// the EV session and publishes the export-limit event at the same instant,
// but the hub doesn't fetch the new event until its next discovery cycle
// (~15-20 s later).  In the gap the orchestrator sees an active EV session
// with no grid constraint and used to slam the EV to MaxCurrentA, dragging
// the site into a multi-second 3 kW grid import.  Verify the unconstrained
// branch now throttles to the post-battery solar surplus so we never *create*
// a new import while waiting for the constraint to arrive.
func TestScenario_S1_DiscoveryGap_NoImportFromUnconstrainedEV(t *testing.T) {
	opt := newOpt()
	s := state0()
	// Solar 8 kW, battery 40 % SOC (5 kW max), 1 kW home load, EV session just
	// started.  No CSIP control yet (mirrors the gap between the EV session
	// command and the next discovery walk fetching the export limit).
	s.Solar = []orchestrator.SolarState{solar("pv-0", 8000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 40, 5000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 32.0, 230.0)}
	s.Grid.NetW = -7000 // exporting 7 kW pre-EV-start

	plan := opt.Optimize(s)

	// Find the EV command.
	if len(plan.EVSECommands) == 0 {
		t.Fatal("expected EVSE command")
	}
	evA := plan.EVSECommands[0].MaxCurrentA

	// Find the battery charge command.
	battChargeW := 0.0
	for _, bc := range plan.BatteryCommands {
		if bc.SetpointW < 0 {
			battChargeW += -bc.SetpointW
		}
	}

	// Predicted site export after this tick's commands settle:
	//   8000 (solar) − 1000 (load) − battery_charge − EV
	predictedExportW := 8000.0 - 1000.0 - battChargeW - evA*230.0
	if predictedExportW < -100 { // tolerate sub-100W rounding
		t.Errorf("unconstrained EV would create %.0fW grid import (battery=%.0fW, EV=%.1fA) — self-consumption guardrail failed",
			-predictedExportW, battChargeW, evA)
	}
	logDecisions(t, plan)
}

// Regression for the "demo S1 overshoot": after the first tick commands
// battery=-5kW and EV=6A, the Modbus meter settles to the new export within
// ~1 s but OCPP MeterValues lag ~10 s, so evseW still reports the pre-event
// current.  The old conservation identity
//   unconstrainedExportW = signedNetExportW + measuredBatteryAbsorbW + evseW
// then over-estimated the surplus, the pre-flight branch boosted the EV by
// 15-20 A, and the site flipped from a clean +620 W export into a 3.4 kW
// import.  Verify the optimizer no longer over-tightens the EV when evseW is
// stale relative to the meter.
func TestScenario_S1_ExportOvershoot_StaleEVMeasurement(t *testing.T) {
	opt := newOpt()
	s := state0()
	s.Solar = []orchestrator.SolarState{solar("pv-0", 8000, 10000)}
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 40, 5000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 32.0, 230.0)}
	s.Grid.NetW = -7000
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(1000)},
	}

	// Tick 1 — first time the export limit is seen.  Soft-start should clamp
	// the EV to 6 A, battery should absorb 5 kW.
	plan := opt.Optimize(s)
	if len(plan.EVSECommands) == 0 {
		t.Fatal("tick 1: expected EVSE command")
	}
	if plan.EVSECommands[0].MaxCurrentA != 6.0 {
		t.Errorf("tick 1: EV MaxCurrentA = %.1fA, want 6.0 (soft-start)",
			plan.EVSECommands[0].MaxCurrentA)
	}

	// Tick 2 — the meter has settled to the post-command export (~620 W) but
	// OCPP MeterValues hasn't arrived yet, so evseW still reports the pre-event
	// current.  Simulate this skew explicitly.
	s.Batteries[0].PowerW = -5000   // battery actuator confirmed
	s.EVSEs[0].CurrentA = 13.4      // stale OCPP reading from pre-event tick
	s.EVSEs[0].PowerW = 13.4 * 230  // ≈ 3082 W stale
	s.Grid.NetW = -620              // meter shows 620 W export (post-command reality)

	plan = opt.Optimize(s)

	if len(plan.EVSECommands) == 0 {
		t.Fatal("tick 2: expected EVSE command")
	}
	ev2 := plan.EVSECommands[0].MaxCurrentA
	if ev2 > 8.0 {
		t.Errorf("tick 2: EV ramped to %.1fA from 6A despite stale measurement — the pre-flight branch over-tightened (want ≤ 8A)", ev2)
	}

	// Predicted post-command export should sit just below the 1 kW limit, not
	// drive the site into import.
	battCmdW := 0.0
	for _, bc := range plan.BatteryCommands {
		if bc.SetpointW < 0 {
			battCmdW += -bc.SetpointW
		}
	}
	predictedExportW := 8000.0 - 1000.0 - battCmdW - ev2*230.0
	if predictedExportW < 0 {
		t.Errorf("tick 2: predicted export %.0fW < 0 — site would import (battery=%.0fW, EV=%.1fA)",
			predictedExportW, battCmdW, ev2)
	}
	if predictedExportW > 1000 {
		t.Errorf("tick 2: predicted export %.0fW exceeds 1 kW limit (battery=%.0fW, EV=%.1fA)",
			predictedExportW, battCmdW, ev2)
	}
	logDecisions(t, plan)
}
