package adapters_test

import (
	"math"
	"testing"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/orchestrator"
	"csip-tls-test/internal/orchestrator/adapters"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/registry"
)

type mockDevice struct {
	meas     device.Measurements
	readErr  error
	applyErr error
	lastCtrl model.DERControlBase
}

func (m *mockDevice) ReadMeasurements() (device.Measurements, error) { return m.meas, m.readErr }
func (m *mockDevice) Status() (device.DeviceStatus, error) {
	return device.DeviceStatus{Connected: true, Energized: true}, nil
}
func (m *mockDevice) ApplyControl(ctrl model.DERControlBase) error {
	m.lastCtrl = ctrl
	return m.applyErr
}
func (m *mockDevice) Close() error { return nil }

func setup(t *testing.T) (*registry.Registry, *adapters.RegistryAdapter, *mockDevice, *mockDevice, *mockDevice) {
	t.Helper()
	reg := registry.New(10 * time.Millisecond)

	solar := &mockDevice{meas: device.Measurements{W: 3000, V: 240, Hz: 60}}
	bat := &mockDevice{meas: device.Measurements{W: -500, V: 240, Hz: 60}}
	meter := &mockDevice{meas: device.Measurements{W: -2500, V: 240, Hz: 60}}

	reg.Add(&registry.Entry{Name: "solar-0", Device: solar})
	reg.Add(&registry.Entry{Name: "battery-0", Device: bat})
	reg.Add(&registry.Entry{Name: "meter-0", Device: meter})

	ra := adapters.NewRegistryAdapter(reg)
	ra.RegisterDevice("solar-0", adapters.RoleSolar, 5000)
	ra.RegisterDevice("battery-0", adapters.RoleBattery, 5000)
	ra.RegisterDevice("meter-0", adapters.RoleGridMeter, 0)

	reg.Start()
	ra.Start()

	// Wait for at least one poll cycle to populate measurements.
	time.Sleep(30 * time.Millisecond)

	return reg, ra, solar, bat, meter
}

func TestRegistryAdapter_ReadSystemState_Roles(t *testing.T) {
	reg, ra, _, _, _ := setup(t)
	defer reg.Stop()
	defer ra.Stop()

	state, err := ra.ReadSystemState()
	if err != nil {
		t.Fatalf("ReadSystemState: %v", err)
	}

	if len(state.Solar) != 1 {
		t.Fatalf("Solar count = %d, want 1", len(state.Solar))
	}
	if state.Solar[0].Name != "solar-0" {
		t.Errorf("Solar name = %q, want solar-0", state.Solar[0].Name)
	}
	if state.Solar[0].PowerW != 3000 {
		t.Errorf("Solar PowerW = %g, want 3000", state.Solar[0].PowerW)
	}

	if len(state.Batteries) != 1 {
		t.Fatalf("Batteries count = %d, want 1", len(state.Batteries))
	}
	if state.Batteries[0].PowerW != -500 {
		t.Errorf("Battery PowerW = %g, want -500 (charging)", state.Batteries[0].PowerW)
	}

	if math.IsNaN(state.Grid.NetW) {
		t.Fatal("Grid.NetW is NaN, expected meter reading")
	}
	if state.Grid.NetW != -2500 {
		t.Errorf("Grid.NetW = %g, want -2500 (exporting)", state.Grid.NetW)
	}
}

func TestRegistryAdapter_SolarPower_ClampedToZero(t *testing.T) {
	reg := registry.New(10 * time.Millisecond)
	d := &mockDevice{meas: device.Measurements{W: -100}} // negative solar shouldn't happen
	reg.Add(&registry.Entry{Name: "solar-0", Device: d})

	ra := adapters.NewRegistryAdapter(reg)
	ra.RegisterDevice("solar-0", adapters.RoleSolar, 5000)

	reg.Start()
	ra.Start()
	time.Sleep(30 * time.Millisecond)
	defer reg.Stop()
	defer ra.Stop()

	state, _ := ra.ReadSystemState()
	if state.Solar[0].PowerW != 0 {
		t.Errorf("Solar PowerW = %g, want 0 (clamped negative)", state.Solar[0].PowerW)
	}
}

func TestRegistryAdapter_BatteryMetrics_Override(t *testing.T) {
	reg, ra, _, _, _ := setup(t)
	defer reg.Stop()
	defer ra.Stop()

	ra.UpdateBatteryMetrics("battery-0", orchestrator.BatteryMetrics{
		SOC: 75.0, SOH: 98.5, CapacityWh: 10000,
		MaxChargeW: 4000, MaxDischargeW: 4500,
	})

	state, _ := ra.ReadSystemState()
	bat := state.Batteries[0]
	if bat.SOC != 75.0 {
		t.Errorf("SOC = %g, want 75", bat.SOC)
	}
	if bat.MaxChargeW != 4000 {
		t.Errorf("MaxChargeW = %g, want 4000", bat.MaxChargeW)
	}
	if bat.MaxDischargeW != 4500 {
		t.Errorf("MaxDischargeW = %g, want 4500", bat.MaxDischargeW)
	}
}

func TestRegistryBatteryActuator_Discharge(t *testing.T) {
	reg := registry.New(10 * time.Second)
	d := &mockDevice{}
	reg.Add(&registry.Entry{Name: "bat", Device: d})

	act := adapters.NewRegistryBatteryActuator(reg, "bat", 5000)
	err := act.ApplyBatteryCommand(orchestrator.BatteryCommand{SetpointW: 2000})
	if err != nil {
		t.Fatalf("ApplyBatteryCommand: %v", err)
	}
	if d.lastCtrl.OpModExpLimW == nil {
		t.Fatal("expected OpModExpLimW to be set for discharge")
	}
	if d.lastCtrl.OpModExpLimW.Value != 2000 {
		t.Errorf("OpModExpLimW.Value = %d, want 2000", d.lastCtrl.OpModExpLimW.Value)
	}
}

func TestRegistryBatteryActuator_Charge(t *testing.T) {
	reg := registry.New(10 * time.Second)
	d := &mockDevice{}
	reg.Add(&registry.Entry{Name: "bat", Device: d})

	act := adapters.NewRegistryBatteryActuator(reg, "bat", 5000)
	err := act.ApplyBatteryCommand(orchestrator.BatteryCommand{SetpointW: -3000})
	if err != nil {
		t.Fatalf("ApplyBatteryCommand: %v", err)
	}
	if d.lastCtrl.OpModImpLimW == nil {
		t.Fatal("expected OpModImpLimW to be set for charge")
	}
	if d.lastCtrl.OpModImpLimW.Value != 3000 {
		t.Errorf("OpModImpLimW.Value = %d, want 3000 (positive magnitude)", d.lastCtrl.OpModImpLimW.Value)
	}
}

func TestRegistrySolarActuator_Curtail(t *testing.T) {
	reg := registry.New(10 * time.Second)
	d := &mockDevice{}
	reg.Add(&registry.Entry{Name: "solar", Device: d})

	act := adapters.NewRegistrySolarActuator(reg, "solar", 5000)
	err := act.ApplySolarCommand(orchestrator.SolarCommand{CurtailToW: 2500})
	if err != nil {
		t.Fatalf("ApplySolarCommand: %v", err)
	}
	if d.lastCtrl.OpModMaxLimW == nil {
		t.Fatal("expected OpModMaxLimW for curtailment")
	}
	if d.lastCtrl.OpModMaxLimW.Value != 2500 {
		t.Errorf("OpModMaxLimW.Value = %d, want 2500", d.lastCtrl.OpModMaxLimW.Value)
	}
}

func TestRegistrySolarActuator_NoCurtail(t *testing.T) {
	reg := registry.New(10 * time.Second)
	d := &mockDevice{}
	reg.Add(&registry.Entry{Name: "solar", Device: d})

	act := adapters.NewRegistrySolarActuator(reg, "solar", 5000)
	err := act.ApplySolarCommand(orchestrator.SolarCommand{CurtailToW: math.NaN()})
	if err != nil {
		t.Fatalf("ApplySolarCommand: %v", err)
	}
	if d.lastCtrl.OpModMaxLimW.Value != 5000 {
		t.Errorf("OpModMaxLimW.Value = %d, want 5000 (full nameplate)", d.lastCtrl.OpModMaxLimW.Value)
	}
}
