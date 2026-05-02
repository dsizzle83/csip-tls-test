package inverter

import (
	"math"
	"testing"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/southbound/modbus"
	"csip-tls-test/sim/southbound"
	"csip-tls-test/internal/southbound/sunspec"
)

// connect creates an Inverter backed by the in-process test server.
func connect(t *testing.T) (*Inverter, *sim.RegisterMap, func()) {
	t.Helper()
	addr, regs, stopServer := startTestServer(t)

	transport, err := modbus.NewTransport(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	if err := transport.Open(); err != nil {
		t.Fatalf("open transport: %v", err)
	}

	inv, err := newFromTransport(transport)
	if err != nil {
		transport.Close()
		stopServer()
		t.Fatalf("new inverter: %v", err)
	}

	return inv, regs, func() {
		inv.Close()
		stopServer()
	}
}

// ── ReadMeasurements ──────────────────────────────────────────────────────────

func TestReadMeasurements_Power(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	m, err := inv.ReadMeasurements()
	if err != nil {
		t.Fatalf("ReadMeasurements: %v", err)
	}
	if m.W != 3000 {
		t.Errorf("W = %g, want 3000", m.W)
	}
}

func TestReadMeasurements_Voltage(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	m, err := inv.ReadMeasurements()
	if err != nil {
		t.Fatalf("ReadMeasurements: %v", err)
	}
	// 2400 × 10^-1 = 240.0 V
	if math.Abs(m.V-240.0) > 0.01 {
		t.Errorf("V = %g, want 240.0", m.V)
	}
}

func TestReadMeasurements_Frequency(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	m, err := inv.ReadMeasurements()
	if err != nil {
		t.Fatalf("ReadMeasurements: %v", err)
	}
	// 6000 × 10^-2 = 60.00 Hz
	if math.Abs(m.Hz-60.0) > 0.01 {
		t.Errorf("Hz = %g, want 60.00", m.Hz)
	}
}

func TestReadMeasurements_PowerFactor(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	m, err := inv.ReadMeasurements()
	if err != nil {
		t.Fatalf("ReadMeasurements: %v", err)
	}
	// 9677 × 10^-2 = 96.77, then / 100 = 0.9677
	if math.Abs(m.PF-0.9677) > 0.0001 {
		t.Errorf("PF = %g, want ~0.9677", m.PF)
	}
}

func TestReadMeasurements_DC(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	m, err := inv.ReadMeasurements()
	if err != nil {
		t.Fatalf("ReadMeasurements: %v", err)
	}
	// DCV: 3800 × 10^-1 = 380.0 V
	if math.Abs(m.DCV-380.0) > 0.01 {
		t.Errorf("DCV = %g, want 380.0", m.DCV)
	}
	if m.DCW != 3200 {
		t.Errorf("DCW = %g, want 3200", m.DCW)
	}
}

func TestReadMeasurements_Temperature(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	m, err := inv.ReadMeasurements()
	if err != nil {
		t.Fatalf("ReadMeasurements: %v", err)
	}
	// 350 × 10^-1 = 35.0 °C
	if math.Abs(m.TmpCab-35.0) > 0.01 {
		t.Errorf("TmpCab = %g, want 35.0", m.TmpCab)
	}
}

// ── Status ────────────────────────────────────────────────────────────────────

func TestStatus_MPPT(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	st, err := inv.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Connected {
		t.Error("want Connected=true for St=4 (MPPT)")
	}
	if !st.Energized {
		t.Error("want Energized=true for St=4 (MPPT)")
	}
}

// ── ApplyControl ──────────────────────────────────────────────────────────────

func TestApplyControl_Disconnect(t *testing.T) {
	inv, regs, stop := connect(t)
	defer stop()

	b := false
	if err := inv.ApplyControl(model.DERControlBase{OpModConnect: &b}); err != nil {
		t.Fatalf("ApplyControl disconnect: %v", err)
	}

	// Verify the Conn register was set to 0.
	// Find Model 123 base address from the test layout.
	m123Block, err := sunspec.FindModel(inv.Reader.Blocks(), sunspec.ModelImmediateCtrl)
	if err != nil {
		t.Fatalf("find model 123: %v", err)
	}
	connAddr := m123Block.BaseAddr + sunspec.M123_Conn
	if got := regs.Get(connAddr); got != 0 {
		t.Errorf("Conn register = %d after disconnect, want 0", got)
	}
}

func TestApplyControl_Connect(t *testing.T) {
	inv, regs, stop := connect(t)
	defer stop()

	// Start disconnected.
	b := false
	inv.ApplyControl(model.DERControlBase{OpModConnect: &b})

	// Reconnect.
	b = true
	if err := inv.ApplyControl(model.DERControlBase{OpModConnect: &b}); err != nil {
		t.Fatalf("ApplyControl connect: %v", err)
	}

	m123Block, _ := sunspec.FindModel(inv.Reader.Blocks(), sunspec.ModelImmediateCtrl)
	connAddr := m123Block.BaseAddr + sunspec.M123_Conn
	if got := regs.Get(connAddr); got != 1 {
		t.Errorf("Conn register = %d after connect, want 1", got)
	}
}

func TestApplyControl_ExportLimit(t *testing.T) {
	inv, regs, stop := connect(t)
	defer stop()

	// Request 2500 W export limit (WMax=5000 W, so 50%).
	ap := model.ActivePower{Value: 2500, Multiplier: 0}
	if err := inv.ApplyControl(model.DERControlBase{OpModExpLimW: &ap}); err != nil {
		t.Fatalf("ApplyControl export limit: %v", err)
	}

	// WMax=5000, sf=-2 → WMaxLimPct = (2500/5000)*100 = 50.00%
	// raw = 5000 (50.00 × 10^2, since sf=-2 means raw = pct / 10^-2 = pct × 100)
	m123Block, _ := sunspec.FindModel(inv.Reader.Blocks(), sunspec.ModelImmediateCtrl)
	rawAddr := m123Block.BaseAddr + sunspec.M123_WMaxLimPct
	enaAddr := m123Block.BaseAddr + sunspec.M123_WMaxLimPct_Ena

	rawVal := regs.Get(rawAddr)
	// 50.00 with sf=-2 → raw = 5000
	if rawVal != 5000 {
		t.Errorf("WMaxLimPct raw = %d, want 5000 (50.00%% with sf=-2)", rawVal)
	}
	if regs.Get(enaAddr) != 1 {
		t.Error("WMaxLimPct_Ena should be 1 (enabled) after setting export limit")
	}
}

func TestApplyControl_ExportLimitClamped(t *testing.T) {
	inv, regs, stop := connect(t)
	defer stop()

	// Request more than WMax — should clamp to 100%.
	ap := model.ActivePower{Value: 9000, Multiplier: 0} // 9000 W > WMax(5000 W)
	if err := inv.ApplyControl(model.DERControlBase{OpModExpLimW: &ap}); err != nil {
		t.Fatalf("ApplyControl: %v", err)
	}

	m123Block, _ := sunspec.FindModel(inv.Reader.Blocks(), sunspec.ModelImmediateCtrl)
	rawAddr := m123Block.BaseAddr + sunspec.M123_WMaxLimPct
	rawVal := regs.Get(rawAddr)
	// 100.00 with sf=-2 → raw = 10000
	if rawVal != 10000 {
		t.Errorf("WMaxLimPct raw = %d, want 10000 (clamped to 100%% with sf=-2)", rawVal)
	}
}

func TestApplyControl_NilFieldsUnchanged(t *testing.T) {
	inv, regs, stop := connect(t)
	defer stop()

	// Find Model 123 Conn address.
	m123Block, _ := sunspec.FindModel(inv.Reader.Blocks(), sunspec.ModelImmediateCtrl)
	connAddr := m123Block.BaseAddr + sunspec.M123_Conn

	before := regs.Get(connAddr)

	// Apply a control that does NOT include OpModConnect.
	// The Conn register should be unchanged.
	ap := model.ActivePower{Value: 3000, Multiplier: 0}
	inv.ApplyControl(model.DERControlBase{OpModExpLimW: &ap})

	after := regs.Get(connAddr)
	if before != after {
		t.Errorf("Conn changed from %d to %d; nil OpModConnect should leave it unchanged", before, after)
	}
}

// ── WMax ──────────────────────────────────────────────────────────────────────

func TestWMax_ReadFromModel121(t *testing.T) {
	inv, _, stop := connect(t)
	defer stop()

	if math.IsNaN(inv.Wmax) {
		t.Fatal("wmax is NaN; expected 5000 from Model 121")
	}
	if inv.Wmax != 5000 {
		t.Errorf("wmax = %g, want 5000", inv.Wmax)
	}
}
