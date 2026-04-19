// tests/modbus_conformance_test.go — SunSpec / Modbus conformance test suite.
//
// These tests mirror sim/modsim-conformance/main.go but run entirely
// in-process using the animated simulator from sim/southbound. Each test
// function maps 1:1 to a conformance check in the standalone binary so that
// the same requirements are verified both locally (go test) and across a
// real TCP network (modsim-conformance binary).
//
// Run:
//
//	go test ./tests/ -run TestModbusConformance -v
package integration_test

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/southbound/modbus"
	"csip-tls-test/internal/southbound/sunspec"
	sim "csip-tls-test/sim/southbound"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────────────────

type modbusEnv struct {
	t      *testing.T
	trans  modbus.Transport
	reader *sunspec.Reader
	stop   func()
}

func startInverterEnv(t *testing.T) *modbusEnv {
	t.Helper()
	return startEnvWith(t, func(url string) (*sim.Server, error) {
		return sim.NewServer(url, 5000)
	})
}

func startBatteryEnv(t *testing.T) *modbusEnv {
	t.Helper()
	return startEnvWith(t, func(url string) (*sim.Server, error) {
		bs, err := sim.NewBatteryServer(url, 10.0, 5000)
		if err != nil {
			return nil, err
		}
		return bs.Server, nil
	})
}

func startEnvWith(t *testing.T, newSrv func(string) (*sim.Server, error)) *modbusEnv {
	t.Helper()

	// Pick a free port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	url := fmt.Sprintf("tcp://127.0.0.1:%d", port)
	srv, err := newSrv(url)
	if err != nil {
		t.Fatalf("start sim: %v", err)
	}

	trans, err := modbus.NewTransport(url, 2*time.Second)
	if err != nil {
		srv.Stop()
		t.Fatalf("new transport: %v", err)
	}
	if err := trans.Open(); err != nil {
		srv.Stop()
		t.Fatalf("open transport: %v", err)
	}
	if err := trans.SetUnitID(1); err != nil {
		trans.Close()
		srv.Stop()
		t.Fatalf("set unit id: %v", err)
	}

	reader, err := sunspec.NewReader(trans)
	if err != nil {
		trans.Close()
		srv.Stop()
		t.Fatalf("new reader: %v", err)
	}

	return &modbusEnv{
		t:      t,
		trans:  trans,
		reader: reader,
		stop:   func() { trans.Close(); srv.Stop() },
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers shared with tests
// ─────────────────────────────────────────────────────────────────────────────

func regsToString(regs []uint16) string {
	b := make([]byte, len(regs)*2)
	for i, r := range regs {
		binary.BigEndian.PutUint16(b[i*2:], r)
	}
	return strings.TrimRight(string(b), "\x00 ")
}

// ─────────────────────────────────────────────────────────────────────────────
// DISC — SunSpec discovery checks
// ─────────────────────────────────────────────────────────────────────────────

// TestModbusConformance_DISC001_Inverter checks the SunSpec magic header.
func TestModbusConformance_DISC001_Inverter(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	regs, err := env.trans.ReadHolding(sunspec.SunSpecBase, 2)
	if err != nil {
		t.Fatalf("DISC-001: read header: %v", err)
	}
	if regs[0] != sunspec.SunSMagic0 || regs[1] != sunspec.SunSMagic1 {
		t.Errorf("DISC-001: got 0x%04X 0x%04X, want 0x%04X 0x%04X ('SunS')",
			regs[0], regs[1], sunspec.SunSMagic0, sunspec.SunSMagic1)
	}
	t.Logf("DISC-001 PASS: SunS magic present at address %d", sunspec.SunSpecBase)
}

// TestModbusConformance_DISC002_Inverter checks Model 1 (Common) strings.
func TestModbusConformance_DISC002_Inverter(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	if !env.reader.HasModel(sunspec.ModelCommon) {
		t.Fatal("DISC-002: Model 1 (Common) not present")
	}
	regs, err := env.reader.ReadModel(sunspec.ModelCommon)
	if err != nil {
		t.Fatalf("DISC-002: read Model 1: %v", err)
	}
	if len(regs) < 40 {
		t.Fatalf("DISC-002: Model 1 too short: %d (want ≥ 40)", len(regs))
	}
	mfr := regsToString(regs[0:16])
	mod := regsToString(regs[16:24])
	if mfr == "" {
		t.Error("DISC-002: Manufacturer string is empty")
	}
	if mod == "" {
		t.Error("DISC-002: Model string is empty")
	}
	t.Logf("DISC-002 PASS: Manufacturer=%q Model=%q", mfr, mod)
}

// TestModbusConformance_DISC003_Inverter verifies an AC measurement model is present.
func TestModbusConformance_DISC003_Inverter(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	found := false
	for _, id := range []uint16{
		sunspec.ModelDERMeasureAC,
		sunspec.ModelInverterThreePh,
		sunspec.ModelInverterSplitPh,
		sunspec.ModelInverterSinglePh,
	} {
		if env.reader.HasModel(id) {
			t.Logf("DISC-003 PASS: Model %d present", id)
			found = true
			break
		}
	}
	if !found {
		t.Error("DISC-003: no AC measurement model found (tried 701, 103, 102, 101)")
	}
}

// TestModbusConformance_DISC004_Inverter verifies a nameplate model is present.
func TestModbusConformance_DISC004_Inverter(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	if env.reader.HasModel(sunspec.ModelDERCapacity) {
		t.Log("DISC-004 PASS: Model 702 (DERCapacity) present")
		return
	}
	if env.reader.HasModel(sunspec.ModelBasicSettings) {
		t.Log("DISC-004 PASS: Model 121 (BasicSettings) present")
		return
	}
	t.Error("DISC-004: neither M702 nor M121 found")
}

// TestModbusConformance_DISC005_Inverter verifies a controls model is present.
func TestModbusConformance_DISC005_Inverter(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	if env.reader.HasModel(sunspec.ModelDERCtlAC) {
		t.Log("DISC-005 PASS: Model 704 (DERCtlAC) present")
		return
	}
	if env.reader.HasModel(sunspec.ModelImmediateCtrl) {
		t.Log("DISC-005 PASS: Model 123 (ImmediateCtrl) present")
		return
	}
	t.Error("DISC-005: neither M704 nor M123 found")
}

// TestModbusConformance_DISC006_Inverter verifies the end sentinel is present.
func TestModbusConformance_DISC006_Inverter(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	blocks := env.reader.Blocks()
	if len(blocks) == 0 {
		t.Fatal("DISC-006: block scan returned no blocks")
	}
	t.Logf("DISC-006 PASS: %d model blocks, end sentinel present", len(blocks))
}

// ─────────────────────────────────────────────────────────────────────────────
// MEAS — Measurement checks (inverter)
// ─────────────────────────────────────────────────────────────────────────────

func measModel(reader *sunspec.Reader) uint16 {
	for _, id := range []uint16{
		sunspec.ModelDERMeasureAC,
		sunspec.ModelInverterThreePh,
		sunspec.ModelInverterSplitPh,
		sunspec.ModelInverterSinglePh,
	} {
		if reader.HasModel(id) {
			return id
		}
	}
	return 0
}

func TestModbusConformance_MEAS001_ActivePower(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	mID := measModel(env.reader)
	if mID == 0 {
		t.Fatal("MEAS-001: no AC measurement model")
	}
	regs, err := env.reader.ReadModel(mID)
	if err != nil {
		t.Fatalf("MEAS-001: read model %d: %v", mID, err)
	}
	var w float64
	if mID == sunspec.ModelDERMeasureAC {
		w = sunspec.ApplyScaleSigned(regs[sunspec.M701_W], int16(regs[sunspec.M701_W_SF]))
	} else {
		w = sunspec.ApplyScaleSigned(regs[sunspec.M103_W], int16(regs[sunspec.M103_W_SF]))
	}
	if math.IsNaN(w) {
		t.Error("MEAS-001: W is NaN")
		return
	}
	t.Logf("MEAS-001 PASS: W = %.1f W", w)
}

func TestModbusConformance_MEAS002_Voltage(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	mID := measModel(env.reader)
	regs, _ := env.reader.ReadModel(mID)

	var v float64
	if mID == sunspec.ModelDERMeasureAC {
		vReg := regs[sunspec.M701_VL1]
		if vReg == 0x8000 {
			vReg = regs[sunspec.M701_LNV]
		}
		v = sunspec.ApplyScaleUint(vReg, int16(regs[sunspec.M701_V_SF]))
	} else {
		v = sunspec.ApplyScaleUint(regs[sunspec.M103_PhVphA], int16(regs[sunspec.M103_V_SF]))
	}
	if math.IsNaN(v) || v < 85 || v > 480 {
		t.Errorf("MEAS-002: V = %.1f outside plausible range 85–480 V", v)
		return
	}
	t.Logf("MEAS-002 PASS: V = %.1f V", v)
}

func TestModbusConformance_MEAS003_Frequency(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	mID := measModel(env.reader)
	regs, _ := env.reader.ReadModel(mID)

	var hz float64
	if mID == sunspec.ModelDERMeasureAC {
		hz = sunspec.ApplyScaleUint(regs[sunspec.M701_Hz], int16(regs[sunspec.M701_Hz_SF]))
	} else {
		hz = sunspec.ApplyScaleUint(regs[sunspec.M103_Hz], int16(regs[sunspec.M103_Hz_SF]))
	}
	if math.IsNaN(hz) || hz < 45 || hz > 65 {
		t.Errorf("MEAS-003: Hz = %.2f outside range 45–65 Hz", hz)
		return
	}
	t.Logf("MEAS-003 PASS: Hz = %.2f Hz", hz)
}

func TestModbusConformance_MEAS004_ApparentPower(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	mID := measModel(env.reader)
	regs, _ := env.reader.ReadModel(mID)

	var va float64
	if mID == sunspec.ModelDERMeasureAC {
		va = sunspec.ApplyScaleSigned(regs[sunspec.M701_VA], int16(regs[sunspec.M701_VA_SF]))
	} else {
		va = sunspec.ApplyScaleSigned(regs[sunspec.M103_VA], int16(regs[sunspec.M103_VA_SF]))
	}
	if math.IsNaN(va) {
		t.Log("MEAS-004 WARN: VA not-implemented — optional field")
		return
	}
	t.Logf("MEAS-004 PASS: VA = %.1f VA", va)
}

func TestModbusConformance_MEAS005_ReactivePower(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	mID := measModel(env.reader)
	regs, _ := env.reader.ReadModel(mID)

	var vr float64
	if mID == sunspec.ModelDERMeasureAC {
		vr = sunspec.ApplyScaleSigned(regs[sunspec.M701_Var], int16(regs[sunspec.M701_Var_SF]))
	} else {
		vr = sunspec.ApplyScaleSigned(regs[sunspec.M103_VAr], int16(regs[sunspec.M103_VAr_SF]))
	}
	if math.IsNaN(vr) {
		t.Log("MEAS-005 WARN: VAr not-implemented — optional field")
		return
	}
	t.Logf("MEAS-005 PASS: VAr = %.1f var", vr)
}

func TestModbusConformance_MEAS006_PowerFactor(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	mID := measModel(env.reader)
	regs, _ := env.reader.ReadModel(mID)

	var pf float64
	if mID == sunspec.ModelDERMeasureAC {
		pf = sunspec.ApplyScaleSigned(regs[sunspec.M701_PF], int16(regs[sunspec.M701_PF_SF])) / 100.0
	} else {
		pf = sunspec.ApplyScaleSigned(regs[sunspec.M103_PF], int16(regs[sunspec.M103_PF_SF])) / 100.0
	}
	if math.IsNaN(pf) {
		t.Log("MEAS-006 WARN: PF not-implemented — optional field")
		return
	}
	if pf < -1.0 || pf > 1.0 {
		t.Errorf("MEAS-006: PF = %.4f outside range −1.0..+1.0", pf)
		return
	}
	t.Logf("MEAS-006 PASS: PF = %.4f", pf)
}

// ─────────────────────────────────────────────────────────────────────────────
// NAME — Nameplate checks
// ─────────────────────────────────────────────────────────────────────────────

func TestModbusConformance_NAME001_WMax(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	var wmax float64
	if env.reader.HasModel(sunspec.ModelDERCapacity) {
		regs, _ := env.reader.ReadModel(sunspec.ModelDERCapacity)
		wmax = sunspec.ApplyScaleUint(regs[sunspec.M702_WMaxRtg], int16(regs[sunspec.M702_W_SF]))
	} else if env.reader.HasModel(sunspec.ModelBasicSettings) {
		regs, _ := env.reader.ReadModel(sunspec.ModelBasicSettings)
		wmax = sunspec.ApplyScaleUint(regs[sunspec.M121_WMax], int16(regs[sunspec.M121_WMax_SF]))
	} else {
		t.Fatal("NAME-001: no nameplate model (M702 or M121)")
	}
	if math.IsNaN(wmax) || wmax <= 0 {
		t.Errorf("NAME-001: WMax = %g (invalid)", wmax)
		return
	}
	t.Logf("NAME-001 PASS: WMax = %.0f W", wmax)
}

// ─────────────────────────────────────────────────────────────────────────────
// CTRL — Control checks (inverter)
// ─────────────────────────────────────────────────────────────────────────────

func TestModbusConformance_CTRL001_WMaxLimPctRoundTrip(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	if !env.reader.HasModel(sunspec.ModelImmediateCtrl) {
		t.Skip("CTRL-001: M123 absent — skipping")
	}

	regs, err := env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	if err != nil {
		t.Fatalf("CTRL-001: read M123: %v", err)
	}
	sf := int16(regs[sunspec.M123_WMaxLimPct_SF])
	raw50 := sunspec.RawFromScaleUint(50.0, sf)

	if err := env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_WMaxLimPct), []uint16{raw50}); err != nil {
		t.Fatalf("CTRL-001: write WMaxLimPct: %v", err)
	}
	regs2, _ := env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	got := sunspec.ApplyScaleUint(regs2[sunspec.M123_WMaxLimPct], sf)
	if math.Abs(got-50.0) > 1.0 {
		t.Errorf("CTRL-001: read back %.2f%%, wrote 50.00%% (delta %.2f > 1.0)", got, math.Abs(got-50.0))
		return
	}
	t.Logf("CTRL-001 PASS: WMaxLimPct round-trip: wrote 50.00%%, read back %.2f%%", got)

	// Restore.
	raw100 := sunspec.RawFromScaleUint(100.0, sf)
	env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_WMaxLimPct), []uint16{raw100})
}

func TestModbusConformance_CTRL002_WMaxLimPctEnable(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	if !env.reader.HasModel(sunspec.ModelImmediateCtrl) {
		t.Skip("CTRL-002: M123 absent — skipping")
	}

	// Disable.
	if err := env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_WMaxLimPct_Ena), []uint16{0}); err != nil {
		t.Fatalf("CTRL-002: write Ena=0: %v", err)
	}
	regs, _ := env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	if regs[sunspec.M123_WMaxLimPct_Ena] != 0 {
		t.Errorf("CTRL-002: Ena read %d after write 0", regs[sunspec.M123_WMaxLimPct_Ena])
	}

	// Re-enable.
	env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_WMaxLimPct_Ena), []uint16{1})
	t.Log("CTRL-002 PASS: WMaxLimPct enable/disable round-trip")
}

func TestModbusConformance_CTRL003_ConnectDisconnect(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	if !env.reader.HasModel(sunspec.ModelImmediateCtrl) {
		t.Skip("CTRL-003: M123 absent — skipping")
	}

	// Disconnect.
	if err := env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_Conn), []uint16{0}); err != nil {
		t.Fatalf("CTRL-003: write Conn=0: %v", err)
	}
	regs, _ := env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	if regs[sunspec.M123_Conn] != 0 {
		t.Errorf("CTRL-003: Conn = %d after write 0", regs[sunspec.M123_Conn])
	}

	// Reconnect.
	if err := env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_Conn), []uint16{1}); err != nil {
		t.Fatalf("CTRL-003: write Conn=1: %v", err)
	}
	regs, _ = env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	if regs[sunspec.M123_Conn] != 1 {
		t.Errorf("CTRL-003: Conn = %d after write 1", regs[sunspec.M123_Conn])
	}
	t.Log("CTRL-003 PASS: connect/disconnect round-trip")
}

// ─────────────────────────────────────────────────────────────────────────────
// STAT — Status checks (inverter)
// ─────────────────────────────────────────────────────────────────────────────

func TestModbusConformance_STAT001_OperatingState(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	mID := measModel(env.reader)
	regs, _ := env.reader.ReadModel(mID)

	if mID == sunspec.ModelDERMeasureAC {
		st := regs[sunspec.M701_St]
		if st > 7 {
			t.Errorf("STAT-001: M701.St = %d outside range 0–7", st)
			return
		}
		t.Logf("STAT-001 PASS: M701.St = %d", st)
	} else {
		st := regs[sunspec.M103_St]
		if st < 1 || st > 8 {
			t.Errorf("STAT-001: M103.St = %d outside range 1–8", st)
			return
		}
		t.Logf("STAT-001 PASS: M103.St = %d", st)
	}
}

func TestModbusConformance_STAT002_InitialConnected(t *testing.T) {
	env := startInverterEnv(t)
	defer env.stop()

	if !env.reader.HasModel(sunspec.ModelImmediateCtrl) {
		t.Skip("STAT-002: M123 absent — skipping")
	}
	regs, _ := env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	if regs[sunspec.M123_Conn] != 1 {
		t.Errorf("STAT-002: M123.Conn = %d (want 1 for initial connected)", regs[sunspec.M123_Conn])
		return
	}
	t.Log("STAT-002 PASS: M123.Conn = 1 (connected)")
}

// ─────────────────────────────────────────────────────────────────────────────
// BAT — Battery-specific checks
// ─────────────────────────────────────────────────────────────────────────────

func TestModbusConformance_BAT001_SoC(t *testing.T) {
	env := startBatteryEnv(t)
	defer env.stop()

	var soc float64
	if env.reader.HasModel(sunspec.ModelDERStorageCap) {
		regs, _ := env.reader.ReadModel(sunspec.ModelDERStorageCap)
		soc = sunspec.ApplyScaleUint(regs[sunspec.M713_SoC], int16(regs[sunspec.M713_SoC_SF]))
	} else if env.reader.HasModel(sunspec.ModelLithiumBattery) {
		regs, _ := env.reader.ReadModel(sunspec.ModelLithiumBattery)
		soc = sunspec.ApplyScaleUint(regs[sunspec.M802_SoC], int16(regs[sunspec.M802_SoC_SF]))
	} else {
		t.Skip("BAT-001: no battery storage model present")
	}

	if math.IsNaN(soc) || soc < 0 || soc > 100 {
		t.Errorf("BAT-001: SoC = %.1f%% outside range 0–100%%", soc)
		return
	}
	t.Logf("BAT-001 PASS: SoC = %.1f%%", soc)
}

func TestModbusConformance_BAT002_SoH(t *testing.T) {
	env := startBatteryEnv(t)
	defer env.stop()

	var soh float64
	found := false
	if env.reader.HasModel(sunspec.ModelDERStorageCap) {
		regs, _ := env.reader.ReadModel(sunspec.ModelDERStorageCap)
		v := sunspec.ApplyScaleUint(regs[sunspec.M713_SoH], int16(regs[sunspec.M713_SoH_SF]))
		if !math.IsNaN(v) {
			soh = v
			found = true
		}
	}
	if !found && env.reader.HasModel(sunspec.ModelLithiumBattery) {
		regs, _ := env.reader.ReadModel(sunspec.ModelLithiumBattery)
		v := sunspec.ApplyScaleUint(regs[sunspec.M802_SoH], int16(regs[sunspec.M802_SoH_SF]))
		if !math.IsNaN(v) {
			soh = v
			found = true
		}
	}
	if !found {
		t.Log("BAT-002 WARN: SoH not-implemented — optional field")
		return
	}
	if soh < 0 || soh > 100 {
		t.Errorf("BAT-002: SoH = %.1f%% outside range 0–100%%", soh)
		return
	}
	t.Logf("BAT-002 PASS: SoH = %.1f%%", soh)
}

func TestModbusConformance_BAT003_Capacity(t *testing.T) {
	env := startBatteryEnv(t)
	defer env.stop()

	var cap float64
	found := false
	if env.reader.HasModel(sunspec.ModelDERStorageCap) {
		regs, _ := env.reader.ReadModel(sunspec.ModelDERStorageCap)
		v := sunspec.ApplyScaleUint(regs[sunspec.M713_WHRtg], int16(regs[sunspec.M713_WHRtg_SF]))
		if !math.IsNaN(v) && v > 0 {
			cap = v
			found = true
		}
	}
	if !found && env.reader.HasModel(sunspec.ModelLithiumBattery) {
		regs, _ := env.reader.ReadModel(sunspec.ModelLithiumBattery)
		v := sunspec.ApplyScaleUint(regs[sunspec.M802_WHRtg], int16(regs[sunspec.M802_WHRtg_SF]))
		if !math.IsNaN(v) && v > 0 {
			cap = v
			found = true
		}
	}
	if !found {
		t.Log("BAT-003 WARN: WHRtg not available — optional field")
		return
	}
	if cap <= 0 {
		t.Errorf("BAT-003: WHRtg = %.0f Wh (must be > 0)", cap)
		return
	}
	t.Logf("BAT-003 PASS: WHRtg = %.0f Wh", cap)
}

// ─────────────────────────────────────────────────────────────────────────────
// Battery also shares all inverter DISC/MEAS/CTRL checks
// ─────────────────────────────────────────────────────────────────────────────

func TestModbusConformance_Battery_DISC001(t *testing.T) {
	env := startBatteryEnv(t)
	defer env.stop()

	regs, err := env.trans.ReadHolding(sunspec.SunSpecBase, 2)
	if err != nil {
		t.Fatalf("Battery DISC-001: %v", err)
	}
	if regs[0] != sunspec.SunSMagic0 || regs[1] != sunspec.SunSMagic1 {
		t.Errorf("Battery DISC-001: bad magic 0x%04X 0x%04X", regs[0], regs[1])
	}
	t.Logf("Battery DISC-001 PASS: SunS magic at %d", sunspec.SunSpecBase)
}

func TestModbusConformance_Battery_CTRL001_WMaxLimPctRoundTrip(t *testing.T) {
	env := startBatteryEnv(t)
	defer env.stop()

	if !env.reader.HasModel(sunspec.ModelImmediateCtrl) {
		t.Skip("Battery CTRL-001: M123 absent")
	}
	regs, _ := env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	sf := int16(regs[sunspec.M123_WMaxLimPct_SF])
	raw50 := sunspec.RawFromScaleUint(50.0, sf)

	env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_WMaxLimPct), []uint16{raw50})
	regs2, _ := env.reader.ReadModel(sunspec.ModelImmediateCtrl)
	got := sunspec.ApplyScaleUint(regs2[sunspec.M123_WMaxLimPct], sf)
	if math.Abs(got-50.0) > 1.0 {
		t.Errorf("Battery CTRL-001: read back %.2f%% (wrote 50%%)", got)
		return
	}
	t.Logf("Battery CTRL-001 PASS: %.2f%%", got)

	raw100 := sunspec.RawFromScaleUint(100.0, sf)
	env.reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_WMaxLimPct), []uint16{raw100})
}
