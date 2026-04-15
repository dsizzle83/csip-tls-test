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

// ── Demand response ───────────────────────────────────────────────────────────

func TestOptimizer_DemandResponse_DischargesBattery(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Active CSIP export limit = demand response signal.
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 80, 5000)}
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(3000)},
	}
	// No solar → DR rule should discharge battery.
	// Grid.NetW not set → we rely on the battery headroom.
	// The export limit rule fires but there's no excess to absorb (NetW=NaN and solar=0).
	// Then DR discharges.

	plan := opt.Optimize(s)

	// Should issue a discharge command for the battery.
	found := false
	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected battery discharge command during demand response")
	}
	logDecisions(t, plan)
}

func TestOptimizer_DemandResponse_RespectsSOCReserve(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Battery at 15% — below SOCReserve=20%; should NOT discharge.
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 15, 5000)}
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(3000)},
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

func TestOptimizer_EV_Throttled_WhenSolarLow(t *testing.T) {
	opt := newOpt()
	s := state0()

	// Only 1 kW solar, EVSE wants up to 32A / 230V = 7.36 kW.
	s.Solar = []orchestrator.SolarState{solar("pv-0", 1000, 10000)}
	s.EVSEs = []orchestrator.EVSEState{evse("cs-001", true, 0, 32.0, 230.0)}

	plan := opt.Optimize(s)

	if len(plan.EVSECommands) == 0 {
		t.Fatal("expected EVSE command")
	}
	cmd := plan.EVSECommands[0]
	// 1000W / 230V ≈ 4.3A — below minimum 6A, so should suspend.
	if cmd.MaxCurrentA != 0 {
		t.Errorf("EVSE MaxCurrentA = %.1f, want 0 (suspend) when insufficient solar", cmd.MaxCurrentA)
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
	costModel := orchestrator.DefaultTOUCostModel()
	opt := orchestrator.NewDefaultOptimizer()
	opt.CostModel = costModel

	s := state0()
	s.Batteries = []orchestrator.BatteryState{battery("bat-0", 0, 80, 5000)}

	// Force peak conditions by injecting a state with isPeakHour=true
	// via OpModExpLimW (which also triggers DR).
	s.CSIPControl = &orchestrator.CSIPControlState{
		Base: model.DERControlBase{OpModExpLimW: ap(10000)},
	}

	plan := opt.Optimize(s)

	// DR is active (OpModExpLimW set) → battery should discharge.
	found := false
	for _, cmd := range plan.BatteryCommands {
		if cmd.SetpointW > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected battery discharge during DR/peak")
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
	// available headroom = 5000 - 2000 = 3000
	if got := b.AvailableChargeW(); math.Abs(got-3000) > 1 {
		t.Errorf("AvailableChargeW = %.0f, want 3000", got)
	}
}

func TestBatteryState_AvailableDischargeW(t *testing.T) {
	b := battery("bat", 1000, 50, 5000) // discharging at 1kW, max 5kW
	if got := b.AvailableDischargeW(); math.Abs(got-4000) > 1 {
		t.Errorf("AvailableDischargeW = %.0f, want 4000", got)
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
