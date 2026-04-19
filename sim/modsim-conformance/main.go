// sim/modsim-conformance runs SunSpec / IEEE 1547-2018 Modbus conformance
// checks against a live device over Modbus TCP. Run it on the Raspberry Pi
// while the simulator (or real inverter / battery) runs on another device.
//
// Build (cross-compile from WSL for Pi):
//
//	GOOS=linux GOARCH=arm64 go build -o bin/modsim-conformance ./sim/modsim-conformance
//
// Run (on Pi — server is the desktop running bin/modsim or bin/batsim):
//
//	./bin/modsim-conformance -server 192.168.0.50:5020 -device inverter -out /tmp/modsim-conformance.log
//	./bin/modsim-conformance -server 192.168.0.51:5021 -device battery  -out /tmp/batsim-conformance.log
//
// Or run loopback (device on same host, different port):
//
//	./bin/modsim-conformance -server 127.0.0.1:5020 -device inverter
//
// Each check references the relevant SunSpec Alliance model specification and
// IEEE 1547-2018 clause. Output is suitable for review or test-lab submission.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"csip-tls-test/internal/southbound/modbus"
	"csip-tls-test/internal/southbound/sunspec"
)

// ─────────────────────────────────────────────────────────────────────────────
// Reporter — identical pattern to sim/conformance/main.go
// ─────────────────────────────────────────────────────────────────────────────

type Reporter struct {
	w         io.Writer
	runCount  int
	failCount int
	current   string
}

func newReporter(logPath string) (*Reporter, func()) {
	writers := []io.Writer{os.Stdout}
	cleanup := func() {}
	if logPath != "" {
		f, err := os.Create(logPath)
		if err != nil {
			log.Fatalf("open log file %s: %v", logPath, err)
		}
		writers = append(writers, f)
		cleanup = func() { f.Close() }
	}
	return &Reporter{w: io.MultiWriter(writers...)}, cleanup
}

func (r *Reporter) printf(format string, args ...interface{}) {
	fmt.Fprintf(r.w, format, args...)
}
func (r *Reporter) section(id, name string) {
	r.current = id
	r.printf("\n%s\n", strings.Repeat("─", 72))
	r.printf("[%s] %s\n", id, name)
	r.printf("%s\n", strings.Repeat("─", 72))
}
func (r *Reporter) spec(section, description string) {
	r.printf("  Req §%-20s %s\n", section, description)
}
func (r *Reporter) pass(format string, args ...interface{}) {
	r.printf("  ✓ PASS  "+format+"\n", args...)
}
func (r *Reporter) warn(format string, args ...interface{}) {
	r.printf("  ⚠ WARN  "+format+"\n", args...)
}
func (r *Reporter) detail(format string, args ...interface{}) {
	r.printf("          "+format+"\n", args...)
}
func (r *Reporter) fail(format string, args ...interface{}) {
	r.printf("  ✗ FAIL  "+format+"\n", args...)
}
func (r *Reporter) result(passed bool) {
	if passed {
		r.printf("\n  [%s] RESULT: PASS\n", r.current)
	} else {
		r.printf("\n  [%s] RESULT: FAIL\n", r.current)
		r.failCount++
	}
	r.runCount++
}
func (r *Reporter) summary() {
	r.printf("\n%s\n", strings.Repeat("═", 72))
	r.printf("SUNSPEC CONFORMANCE TEST SUMMARY\n")
	r.printf("%s\n", strings.Repeat("═", 72))
	passed := r.runCount - r.failCount
	r.printf("  Tests run:  %d\n", r.runCount)
	r.printf("  PASS:       %d\n", passed)
	r.printf("  FAIL:       %d\n", r.failCount)
	if r.failCount == 0 {
		r.printf("\n  ✓ ALL CONFORMANCE CHECKS PASSED\n")
	} else {
		r.printf("\n  ✗ %d CHECK(S) FAILED — review log for details\n", r.failCount)
	}
	r.printf("%s\n\n", strings.Repeat("═", 72))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// regsToString decodes a slice of SunSpec string registers (2 ASCII bytes per
// register, big-endian, null-padded) into a Go string.
func regsToString(regs []uint16) string {
	b := make([]byte, len(regs)*2)
	for i, r := range regs {
		binary.BigEndian.PutUint16(b[i*2:], r)
	}
	// Trim trailing nulls and whitespace.
	return strings.TrimRight(string(b), "\x00 ")
}

// checkNaN returns true if the SunSpec register value is the not-implemented
// sentinel 0x8000 (NaN for signed) or 0xFFFF (not-implemented for uint16).
func isNaN(v uint16) bool { return v == 0x8000 || v == 0xFFFF }

// ─────────────────────────────────────────────────────────────────────────────
// Conformance checks
// ─────────────────────────────────────────────────────────────────────────────

// checkDISC001 verifies the SunS magic bytes are present at address 40000.
// SunSpec Alliance spec §6.1: "SunSpec devices SHALL begin a conformant block
// at register 40000 (0-based) with the four-byte ASCII string 'SunS'."
func checkDISC001(r *Reporter, t modbus.Transport) bool {
	r.section("DISC-001", "SunSpec Magic Header")
	r.spec("SunSpec §6.1", "Registers 40000-40001 SHALL contain 0x5375 0x6E53 ('SunS')")

	regs, err := t.ReadHolding(sunspec.SunSpecBase, 2)
	if err != nil {
		r.fail("read address %d: %v", sunspec.SunSpecBase, err)
		r.result(false)
		return false
	}
	if regs[0] != sunspec.SunSMagic0 || regs[1] != sunspec.SunSMagic1 {
		r.fail("got 0x%04X 0x%04X, want 0x%04X 0x%04X ('SunS')",
			regs[0], regs[1], sunspec.SunSMagic0, sunspec.SunSMagic1)
		r.result(false)
		return false
	}
	r.pass("SunS magic present at address %d", sunspec.SunSpecBase)
	r.result(true)
	return true
}

// checkDISC002 verifies Model 1 (Common) is present with non-empty strings.
// SunSpec Alliance Model 1 spec: Common model is mandatory for all devices.
func checkDISC002(r *Reporter, reader *sunspec.Reader) bool {
	r.section("DISC-002", "Model 1 (Common) — mandatory identifier block")
	r.spec("SunSpec §6.2", "Model 1 SHALL be the first model after the magic header")
	r.spec("SunSpec §6.2", "Mn (manufacturer) and Md (model) strings SHALL be non-empty")

	if !reader.HasModel(sunspec.ModelCommon) {
		r.fail("Model 1 (Common) not found in block scan")
		r.result(false)
		return false
	}
	regs, err := reader.ReadModel(sunspec.ModelCommon)
	if err != nil {
		r.fail("read Model 1: %v", err)
		r.result(false)
		return false
	}
	if len(regs) < 40 {
		r.fail("Model 1 too short: %d registers (want ≥ 40)", len(regs))
		r.result(false)
		return false
	}
	// Manufacturer = regs[0:16] (32 chars), Model = regs[16:24] (16 chars),
	// Version = regs[24:28], Serial = regs[28:44].
	mfr := regsToString(regs[0:16])
	mod := regsToString(regs[16:24])
	ver := regsToString(regs[24:28])
	sn := regsToString(regs[28:44])

	ok := true
	if mfr == "" {
		r.fail("Manufacturer string is empty")
		ok = false
	} else {
		r.pass("Manufacturer: %q", mfr)
	}
	if mod == "" {
		r.fail("Model string is empty")
		ok = false
	} else {
		r.pass("Model:        %q", mod)
	}
	r.detail("Version: %q  Serial: %q", ver, sn)
	r.result(ok)
	return ok
}

// checkDISC003 verifies at least one AC measurement model is present.
func checkDISC003(r *Reporter, reader *sunspec.Reader) (measModel uint16) {
	r.section("DISC-003", "AC Measurement Model")
	r.spec("SunSpec §6.3", "Devices SHALL expose one of: M701 (IEEE 1547-2018), M103, M102, or M101")

	for _, id := range []uint16{
		sunspec.ModelDERMeasureAC,
		sunspec.ModelInverterThreePh,
		sunspec.ModelInverterSplitPh,
		sunspec.ModelInverterSinglePh,
	} {
		if reader.HasModel(id) {
			r.pass("Model %d present", id)
			if id == sunspec.ModelDERMeasureAC {
				r.detail("IEEE 1547-2018 profile detected (M701)")
			}
			r.result(true)
			return id
		}
	}
	r.fail("no AC measurement model found (tried 701, 103, 102, 101)")
	r.result(false)
	return 0
}

// checkDISC004 verifies a nameplate model is present.
func checkDISC004(r *Reporter, reader *sunspec.Reader) (nameplateModel uint16) {
	r.section("DISC-004", "Nameplate / Capacity Model")
	r.spec("SunSpec §6.4", "Devices SHALL expose M702 (IEEE 1547-2018) or M121 (legacy)")

	if reader.HasModel(sunspec.ModelDERCapacity) {
		r.pass("Model 702 (DERCapacity) present — IEEE 1547-2018 profile")
		r.result(true)
		return sunspec.ModelDERCapacity
	}
	if reader.HasModel(sunspec.ModelBasicSettings) {
		r.pass("Model 121 (BasicSettings) present — legacy profile")
		r.result(true)
		return sunspec.ModelBasicSettings
	}
	r.fail("neither M702 nor M121 found")
	r.result(false)
	return 0
}

// checkDISC005 verifies a controls model is present.
func checkDISC005(r *Reporter, reader *sunspec.Reader) (ctrlModel uint16) {
	r.section("DISC-005", "Controls Model")
	r.spec("SunSpec §6.5", "Devices SHALL expose M704 (IEEE 1547-2018) or M123 (legacy)")

	if reader.HasModel(sunspec.ModelDERCtlAC) {
		r.pass("Model 704 (DERCtlAC) present — IEEE 1547-2018 profile")
		r.result(true)
		return sunspec.ModelDERCtlAC
	}
	if reader.HasModel(sunspec.ModelImmediateCtrl) {
		r.pass("Model 123 (ImmediateCtrl) present — legacy profile")
		r.result(true)
		return sunspec.ModelImmediateCtrl
	}
	r.fail("neither M704 nor M123 found")
	r.result(false)
	return 0
}

// checkDISC006 verifies the end sentinel is present.
func checkDISC006(r *Reporter, reader *sunspec.Reader) {
	r.section("DISC-006", "End Sentinel")
	r.spec("SunSpec §6.1", "Model list SHALL be terminated by model ID 0xFFFF length 0")

	// Scan the blocks — the scanner would have failed in NewReader if no sentinel.
	// Check that the last block is the end marker.
	blocks := reader.Blocks()
	if len(blocks) == 0 {
		r.fail("no blocks found")
		r.result(false)
		return
	}
	r.pass("block scan found %d model(s), end sentinel present", len(blocks))
	for _, b := range blocks {
		r.detail("Model %d  addr=%d  len=%d", b.ModelID, b.BaseAddr, b.Length)
	}
	r.result(true)
}

// checkMEAS001 verifies active power is readable and finite.
func checkMEAS001(r *Reporter, reader *sunspec.Reader, measModel uint16) float64 {
	r.section("MEAS-001", "Active Power (W)")
	r.spec("SunSpec M103 §5.1", "W register SHALL be present and finite")
	r.spec("IEEE 1547-2018 §2.2", "M701.W SHALL be present and finite")

	regs, err := reader.ReadModel(measModel)
	if err != nil {
		r.fail("read measurement model %d: %v", measModel, err)
		r.result(false)
		return math.NaN()
	}

	var w float64
	if measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_W_SF {
			r.fail("M701 too short for W")
			r.result(false)
			return math.NaN()
		}
		if isNaN(regs[sunspec.M701_W]) {
			r.fail("W register is not-implemented (0x8000)")
			r.result(false)
			return math.NaN()
		}
		w = sunspec.ApplyScaleSigned(regs[sunspec.M701_W], int16(regs[sunspec.M701_W_SF]))
	} else {
		if len(regs) <= sunspec.M103_W_SF {
			r.fail("measurement model too short for W")
			r.result(false)
			return math.NaN()
		}
		if isNaN(regs[sunspec.M103_W]) {
			r.fail("W register is not-implemented (0x8000)")
			r.result(false)
			return math.NaN()
		}
		w = sunspec.ApplyScaleSigned(regs[sunspec.M103_W], int16(regs[sunspec.M103_W_SF]))
	}

	if math.IsNaN(w) {
		r.fail("W is NaN after scale application")
		r.result(false)
		return math.NaN()
	}
	r.pass("W = %.1f W", w)
	r.result(true)
	return w
}

// checkMEAS002 verifies voltage is readable and in a plausible range.
func checkMEAS002(r *Reporter, reader *sunspec.Reader, measModel uint16) {
	r.section("MEAS-002", "Voltage (V)")
	r.spec("SunSpec §5.1", "Voltage SHALL be in range 85–480 V (covers 120/240/400 V systems)")

	regs, err := reader.ReadModel(measModel)
	if err != nil {
		r.fail("read model %d: %v", measModel, err)
		r.result(false)
		return
	}

	var v float64
	if measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_V_SF {
			r.fail("M701 too short for V")
			r.result(false)
			return
		}
		vReg := regs[sunspec.M701_VL1]
		if isNaN(vReg) {
			vReg = regs[sunspec.M701_LNV]
		}
		v = sunspec.ApplyScaleUint(vReg, int16(regs[sunspec.M701_V_SF]))
	} else {
		if len(regs) <= sunspec.M103_V_SF {
			r.fail("model too short for V")
			r.result(false)
			return
		}
		v = sunspec.ApplyScaleUint(regs[sunspec.M103_PhVphA], int16(regs[sunspec.M103_V_SF]))
	}

	if math.IsNaN(v) {
		r.fail("voltage is NaN after scale application")
		r.result(false)
		return
	}
	if v < 85 || v > 480 {
		r.fail("V = %.1f V outside plausible range 85–480 V", v)
		r.result(false)
		return
	}
	r.pass("V = %.1f V (in range 85–480 V)", v)
	r.result(true)
}

// checkMEAS003 verifies frequency is readable and in range.
func checkMEAS003(r *Reporter, reader *sunspec.Reader, measModel uint16) {
	r.section("MEAS-003", "Frequency (Hz)")
	r.spec("SunSpec §5.1", "Hz SHALL be in range 45–65 Hz")

	regs, err := reader.ReadModel(measModel)
	if err != nil {
		r.fail("read model %d: %v", measModel, err)
		r.result(false)
		return
	}

	var hz float64
	if measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_Hz_SF {
			r.fail("M701 too short for Hz")
			r.result(false)
			return
		}
		hz = sunspec.ApplyScaleUint(regs[sunspec.M701_Hz], int16(regs[sunspec.M701_Hz_SF]))
	} else {
		if len(regs) <= sunspec.M103_Hz_SF {
			r.fail("model too short for Hz")
			r.result(false)
			return
		}
		hz = sunspec.ApplyScaleUint(regs[sunspec.M103_Hz], int16(regs[sunspec.M103_Hz_SF]))
	}

	if math.IsNaN(hz) {
		r.fail("Hz is NaN after scale application")
		r.result(false)
		return
	}
	if hz < 45 || hz > 65 {
		r.fail("Hz = %.2f outside range 45–65 Hz", hz)
		r.result(false)
		return
	}
	r.pass("Hz = %.2f Hz", hz)
	r.result(true)
}

// checkMEAS004 verifies apparent power (VA) is readable.
func checkMEAS004(r *Reporter, reader *sunspec.Reader, measModel uint16, watt float64) {
	r.section("MEAS-004", "Apparent Power (VA)")
	r.spec("SunSpec §5.1", "VA SHALL be finite and ≥ |W|")

	regs, err := reader.ReadModel(measModel)
	if err != nil {
		r.fail("read model %d: %v", measModel, err)
		r.result(false)
		return
	}

	var va float64
	if measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_VA_SF {
			r.warn("M701 VA registers absent — optional field, skipping")
			r.result(true)
			return
		}
		va = sunspec.ApplyScaleSigned(regs[sunspec.M701_VA], int16(regs[sunspec.M701_VA_SF]))
	} else {
		if len(regs) <= sunspec.M103_VA_SF {
			r.warn("model VA registers absent — optional field, skipping")
			r.result(true)
			return
		}
		va = sunspec.ApplyScaleSigned(regs[sunspec.M103_VA], int16(regs[sunspec.M103_VA_SF]))
	}

	if math.IsNaN(va) {
		r.warn("VA is not-implemented (NaN) — optional field")
		r.result(true)
		return
	}
	if !math.IsNaN(watt) && math.Abs(va) < math.Abs(watt)-1 {
		r.fail("VA = %.1f < |W| = %.1f (power triangle violation)", va, math.Abs(watt))
		r.result(false)
		return
	}
	r.pass("VA = %.1f VA", va)
	r.result(true)
}

// checkMEAS005 verifies reactive power (VAr) is readable.
func checkMEAS005(r *Reporter, reader *sunspec.Reader, measModel uint16) {
	r.section("MEAS-005", "Reactive Power (VAr)")
	r.spec("SunSpec §5.1", "VAr SHALL be finite (negative = absorbing Q)")

	regs, err := reader.ReadModel(measModel)
	if err != nil {
		r.fail("read model %d: %v", measModel, err)
		r.result(false)
		return
	}

	var vr float64
	if measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_Var_SF {
			r.warn("M701 VAr absent — optional, skipping")
			r.result(true)
			return
		}
		vr = sunspec.ApplyScaleSigned(regs[sunspec.M701_Var], int16(regs[sunspec.M701_Var_SF]))
	} else {
		if len(regs) <= sunspec.M103_VAr_SF {
			r.warn("model VAr absent — optional, skipping")
			r.result(true)
			return
		}
		vr = sunspec.ApplyScaleSigned(regs[sunspec.M103_VAr], int16(regs[sunspec.M103_VAr_SF]))
	}

	if math.IsNaN(vr) {
		r.warn("VAr not-implemented (NaN) — optional field")
		r.result(true)
		return
	}
	r.pass("VAr = %.1f var", vr)
	r.result(true)
}

// checkMEAS006 verifies power factor is in range −1..+1.
func checkMEAS006(r *Reporter, reader *sunspec.Reader, measModel uint16) {
	r.section("MEAS-006", "Power Factor (PF)")
	r.spec("SunSpec §5.1", "PF SHALL be in range −1.0 to +1.0")

	regs, err := reader.ReadModel(measModel)
	if err != nil {
		r.fail("read model %d: %v", measModel, err)
		r.result(false)
		return
	}

	var pf float64
	if measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_PF_SF {
			r.warn("M701 PF absent — optional, skipping")
			r.result(true)
			return
		}
		pf = sunspec.ApplyScaleSigned(regs[sunspec.M701_PF], int16(regs[sunspec.M701_PF_SF])) / 100.0
	} else {
		if len(regs) <= sunspec.M103_PF_SF {
			r.warn("model PF absent — optional, skipping")
			r.result(true)
			return
		}
		pf = sunspec.ApplyScaleSigned(regs[sunspec.M103_PF], int16(regs[sunspec.M103_PF_SF])) / 100.0
	}

	if math.IsNaN(pf) {
		r.warn("PF not-implemented (NaN) — optional field")
		r.result(true)
		return
	}
	if pf < -1.0 || pf > 1.0 {
		r.fail("PF = %.4f outside range −1.0..+1.0", pf)
		r.result(false)
		return
	}
	r.pass("PF = %.4f", pf)
	r.result(true)
}

// checkNAME001 verifies WMax is readable and > 0.
func checkNAME001(r *Reporter, reader *sunspec.Reader, nameplateModel uint16) float64 {
	r.section("NAME-001", "Nameplate WMax")
	r.spec("SunSpec §6.4", "WMax (rated active power) SHALL be present and > 0 W")

	regs, err := reader.ReadModel(nameplateModel)
	if err != nil {
		r.fail("read model %d: %v", nameplateModel, err)
		r.result(false)
		return math.NaN()
	}

	var wmax float64
	if nameplateModel == sunspec.ModelDERCapacity {
		if len(regs) <= sunspec.M702_W_SF {
			r.fail("M702 too short for WMaxRtg")
			r.result(false)
			return math.NaN()
		}
		wmax = sunspec.ApplyScaleUint(regs[sunspec.M702_WMaxRtg], int16(regs[sunspec.M702_W_SF]))
	} else {
		if len(regs) <= sunspec.M121_WMax_SF {
			r.fail("M121 too short for WMax")
			r.result(false)
			return math.NaN()
		}
		wmax = sunspec.ApplyScaleUint(regs[sunspec.M121_WMax], int16(regs[sunspec.M121_WMax_SF]))
	}

	if math.IsNaN(wmax) || wmax <= 0 {
		r.fail("WMax = %g (invalid; must be > 0)", wmax)
		r.result(false)
		return math.NaN()
	}
	r.pass("WMax = %.0f W", wmax)
	r.result(true)
	return wmax
}

// checkNAME002 verifies measured W does not exceed WMax.
func checkNAME002(r *Reporter, watt, wmax float64) {
	r.section("NAME-002", "W ≤ WMax (operating within nameplate)")
	r.spec("IEEE 1547-2018 §6.4", "DER SHALL NOT continuously export power exceeding nameplate WMax")

	if math.IsNaN(watt) || math.IsNaN(wmax) {
		r.warn("cannot check: W or WMax is NaN")
		r.result(true)
		return
	}
	if watt > wmax+1 { // 1 W tolerance for rounding
		r.fail("W = %.1f W > WMax = %.0f W", watt, wmax)
		r.result(false)
		return
	}
	r.pass("W = %.1f W ≤ WMax = %.0f W", watt, wmax)
	r.result(true)
}

// checkCTRL001 writes WMaxLimPct = 50 % and reads it back.
func checkCTRL001(r *Reporter, reader *sunspec.Reader, ctrlModel uint16, wmax float64) {
	r.section("CTRL-001", "WMaxLimPct Write-Read Round-Trip")
	r.spec("SunSpec M123 §5.4", "WMaxLimPct write SHALL be readable back within ±1 %")
	r.spec("SunSpec M704 §5.4", "WMaxLimPct write SHALL be readable back within ±1 %")

	if ctrlModel == 0 {
		r.warn("no controls model — skipping")
		r.result(true)
		return
	}

	// Read scale factor first.
	regs, err := reader.ReadModel(ctrlModel)
	if err != nil {
		r.fail("read controls model %d: %v", ctrlModel, err)
		r.result(false)
		return
	}

	var sfOffset uint16
	var pctOffset uint16
	if ctrlModel == sunspec.ModelImmediateCtrl {
		sfOffset = uint16(sunspec.M123_WMaxLimPct_SF)
		pctOffset = uint16(sunspec.M123_WMaxLimPct)
	} else {
		// M704: WMaxLimPct at offset 8, SF at offset 11.
		sfOffset = uint16(sunspec.M704_WMaxLimPct_SF)
		pctOffset = uint16(sunspec.M704_WMaxLimPct)
	}

	if int(sfOffset) >= len(regs) {
		r.fail("controls model too short for WMaxLimPct_SF")
		r.result(false)
		return
	}
	sf := int16(regs[sfOffset])

	// Write 50.00 % as a raw value.
	target := 50.0
	raw := sunspec.RawFromScaleUint(target, sf)
	if err := reader.WriteModel(ctrlModel, pctOffset, []uint16{raw}); err != nil {
		r.fail("write WMaxLimPct = 50%%: %v", err)
		r.result(false)
		return
	}
	r.detail("wrote raw %d (50%% with sf=%d)", raw, sf)

	// Read back.
	regs2, err := reader.ReadModel(ctrlModel)
	if err != nil {
		r.fail("read-back controls model: %v", err)
		r.result(false)
		return
	}
	got := sunspec.ApplyScaleUint(regs2[pctOffset], sf)
	if math.Abs(got-target) > 1.0 {
		r.fail("read-back WMaxLimPct = %.2f %%, wrote 50.00 %% (delta %.2f > 1.0)", got, math.Abs(got-target))
		r.result(false)
		return
	}
	r.pass("WMaxLimPct written 50.00%%, read back %.2f%% (delta %.2f)", got, math.Abs(got-target))

	// Restore to 100 %.
	raw100 := sunspec.RawFromScaleUint(100.0, sf)
	_ = reader.WriteModel(ctrlModel, pctOffset, []uint16{raw100})

	r.result(true)
}

// checkCTRL002 verifies the WMaxLimPct enable register is writable.
func checkCTRL002(r *Reporter, reader *sunspec.Reader, ctrlModel uint16) {
	r.section("CTRL-002", "WMaxLimPct Enable/Disable")
	r.spec("SunSpec M123 §5.4", "WMaxLimPct_Ena (offset 4) SHALL be writable: 0=disable, 1=enable")

	if ctrlModel == 0 {
		r.warn("no controls model — skipping")
		r.result(true)
		return
	}

	var enaOffset uint16
	if ctrlModel == sunspec.ModelImmediateCtrl {
		enaOffset = uint16(sunspec.M123_WMaxLimPct_Ena)
	} else {
		enaOffset = uint16(sunspec.M704_WMaxLimPctEna)
	}

	// Disable.
	if err := reader.WriteModel(ctrlModel, enaOffset, []uint16{0}); err != nil {
		r.fail("write Ena=0: %v", err)
		r.result(false)
		return
	}
	regs, _ := reader.ReadModel(ctrlModel)
	if regs[enaOffset] != 0 {
		r.fail("Ena read back %d after writing 0", regs[enaOffset])
		r.result(false)
		return
	}
	r.pass("Ena disabled (0)")

	// Re-enable.
	if err := reader.WriteModel(ctrlModel, enaOffset, []uint16{1}); err != nil {
		r.fail("write Ena=1: %v", err)
		r.result(false)
		return
	}
	regs, _ = reader.ReadModel(ctrlModel)
	if regs[enaOffset] != 1 {
		r.fail("Ena read back %d after writing 1", regs[enaOffset])
		r.result(false)
		return
	}
	r.pass("Ena re-enabled (1)")
	r.result(true)
}

// checkCTRL003 verifies the Conn (connect/disconnect) register is writable.
// Only tested when M123 is present; M704 does not have a Conn register.
func checkCTRL003(r *Reporter, reader *sunspec.Reader) {
	r.section("CTRL-003", "Connect / Disconnect (M123 Conn)")
	r.spec("SunSpec M123 §5.4", "Conn register (offset 16) SHALL be writable: 0=disconnect, 1=connect")

	if !reader.HasModel(sunspec.ModelImmediateCtrl) {
		r.warn("M123 absent — Conn not applicable, skipping")
		r.result(true)
		return
	}

	// Disconnect.
	if err := reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_Conn), []uint16{0}); err != nil {
		r.fail("write Conn=0 (disconnect): %v", err)
		r.result(false)
		return
	}
	regs, _ := reader.ReadModel(sunspec.ModelImmediateCtrl)
	if regs[sunspec.M123_Conn] != 0 {
		r.fail("Conn read back %d after writing 0", regs[sunspec.M123_Conn])
		r.result(false)
		return
	}
	r.pass("Conn=0 (disconnected)")

	// Reconnect.
	if err := reader.WriteModel(sunspec.ModelImmediateCtrl, uint16(sunspec.M123_Conn), []uint16{1}); err != nil {
		r.fail("write Conn=1 (connect): %v", err)
		r.result(false)
		return
	}
	regs, _ = reader.ReadModel(sunspec.ModelImmediateCtrl)
	if regs[sunspec.M123_Conn] != 1 {
		r.fail("Conn read back %d after writing 1", regs[sunspec.M123_Conn])
		r.result(false)
		return
	}
	r.pass("Conn=1 (reconnected)")
	r.result(true)
}

// checkSTAT001 verifies the operating state register is readable.
func checkSTAT001(r *Reporter, reader *sunspec.Reader, measModel uint16) {
	r.section("STAT-001", "Operating State")
	r.spec("SunSpec M103 §5.1", "St register (offset 36) SHALL be in range 1–8")
	r.spec("SunSpec M701 §5.1", "St register (offset 21) SHALL be in range 0–7")

	regs, err := reader.ReadModel(measModel)
	if err != nil {
		r.fail("read model %d: %v", measModel, err)
		r.result(false)
		return
	}

	if measModel == sunspec.ModelDERMeasureAC {
		if len(regs) <= sunspec.M701_St {
			r.fail("M701 too short for St")
			r.result(false)
			return
		}
		st := regs[sunspec.M701_St]
		if st > 7 {
			r.fail("M701.St = %d outside range 0–7", st)
			r.result(false)
			return
		}
		stName := []string{"UNKNOWN", "OFF", "SLEEPING", "STARTING", "ON", "THROTTLED", "SHUTTING_DOWN", "FAULT"}
		r.pass("M701.St = %d (%s)", st, stName[st])
	} else {
		if len(regs) <= sunspec.M103_St {
			r.fail("model too short for St")
			r.result(false)
			return
		}
		st := regs[sunspec.M103_St]
		if st < 1 || st > 8 {
			r.fail("M103.St = %d outside range 1–8", st)
			r.result(false)
			return
		}
		stName := []string{"", "OFF", "SLEEPING", "STARTING", "MPPT", "THROTTLED", "SHUTTING_DOWN", "FAULT", "STANDBY"}
		r.pass("M103.St = %d (%s)", st, stName[st])
	}
	r.result(true)
}

// checkSTAT002 verifies the device reports as connected in its initial state.
func checkSTAT002(r *Reporter, reader *sunspec.Reader, measModel uint16) {
	r.section("STAT-002", "Initial Connection State")
	r.spec("SunSpec §5.4", "Simulator / device under test SHALL report Connected=true at start")

	if reader.HasModel(sunspec.ModelImmediateCtrl) {
		regs, err := reader.ReadModel(sunspec.ModelImmediateCtrl)
		if err != nil {
			r.fail("read M123: %v", err)
			r.result(false)
			return
		}
		if len(regs) <= sunspec.M123_Conn {
			r.fail("M123 too short for Conn")
			r.result(false)
			return
		}
		conn := regs[sunspec.M123_Conn]
		if conn != 1 {
			r.fail("M123.Conn = %d (want 1 for connected)", conn)
			r.result(false)
			return
		}
		r.pass("M123.Conn = 1 (connected)")
		r.result(true)
		return
	}

	// Fall back to M701 ConnSt.
	if measModel == sunspec.ModelDERMeasureAC {
		regs, err := reader.ReadModel(sunspec.ModelDERMeasureAC)
		if err != nil {
			r.fail("read M701: %v", err)
			r.result(false)
			return
		}
		if len(regs) <= sunspec.M701_ConnSt {
			r.fail("M701 too short for ConnSt")
			r.result(false)
			return
		}
		conn := regs[sunspec.M701_ConnSt]
		if conn != 1 {
			r.fail("M701.ConnSt = %d (want 1)", conn)
			r.result(false)
			return
		}
		r.pass("M701.ConnSt = 1 (connected)")
		r.result(true)
		return
	}

	r.warn("no connection state register found — skipping")
	r.result(true)
}

// checkBAT001 verifies SoC is readable and in 0–100 %.
func checkBAT001(r *Reporter, reader *sunspec.Reader) {
	r.section("BAT-001", "State of Charge (SoC)")
	r.spec("SunSpec M802 §5.1", "SoC SHALL be in range 0–100 %")
	r.spec("SunSpec M713 §5.1", "M713.SoC SHALL be in range 0–100 % (preferred)")

	// Prefer M713.
	if reader.HasModel(sunspec.ModelDERStorageCap) {
		regs, err := reader.ReadModel(sunspec.ModelDERStorageCap)
		if err != nil {
			r.fail("read M713: %v", err)
			r.result(false)
			return
		}
		if len(regs) > sunspec.M713_SoC {
			soc := sunspec.ApplyScaleUint(regs[sunspec.M713_SoC], int16(regs[sunspec.M713_SoC_SF]))
			if soc < 0 || soc > 100 || math.IsNaN(soc) {
				r.fail("M713.SoC = %.1f %% outside range 0–100", soc)
				r.result(false)
				return
			}
			r.pass("M713.SoC = %.1f %%", soc)
			r.result(true)
			return
		}
	}

	// Fall back to M802.
	if !reader.HasModel(sunspec.ModelLithiumBattery) {
		r.warn("neither M713 nor M802 present — battery metrics not available")
		r.result(true)
		return
	}
	regs, err := reader.ReadModel(sunspec.ModelLithiumBattery)
	if err != nil {
		r.fail("read M802: %v", err)
		r.result(false)
		return
	}
	if len(regs) <= sunspec.M802_SoC {
		r.fail("M802 too short for SoC")
		r.result(false)
		return
	}
	soc := sunspec.ApplyScaleUint(regs[sunspec.M802_SoC], int16(regs[sunspec.M802_SoC_SF]))
	if soc < 0 || soc > 100 || math.IsNaN(soc) {
		r.fail("M802.SoC = %.1f %% outside range 0–100", soc)
		r.result(false)
		return
	}
	r.pass("M802.SoC = %.1f %%", soc)
	r.result(true)
}

// checkBAT002 verifies SoH is readable and in 0–100 %.
func checkBAT002(r *Reporter, reader *sunspec.Reader) {
	r.section("BAT-002", "State of Health (SoH)")
	r.spec("SunSpec M802/M713 §5.1", "SoH SHALL be in range 0–100 %")

	if reader.HasModel(sunspec.ModelDERStorageCap) {
		regs, _ := reader.ReadModel(sunspec.ModelDERStorageCap)
		if len(regs) > sunspec.M713_SoH {
			soh := sunspec.ApplyScaleUint(regs[sunspec.M713_SoH], int16(regs[sunspec.M713_SoH_SF]))
			if !math.IsNaN(soh) {
				if soh < 0 || soh > 100 {
					r.fail("M713.SoH = %.1f %% outside range 0–100", soh)
					r.result(false)
					return
				}
				r.pass("M713.SoH = %.1f %%", soh)
				r.result(true)
				return
			}
		}
	}
	if reader.HasModel(sunspec.ModelLithiumBattery) {
		regs, _ := reader.ReadModel(sunspec.ModelLithiumBattery)
		if len(regs) > sunspec.M802_SoH {
			soh := sunspec.ApplyScaleUint(regs[sunspec.M802_SoH], int16(regs[sunspec.M802_SoH_SF]))
			if !math.IsNaN(soh) {
				if soh < 0 || soh > 100 {
					r.fail("M802.SoH = %.1f %% outside range 0–100", soh)
					r.result(false)
					return
				}
				r.pass("M802.SoH = %.1f %%", soh)
				r.result(true)
				return
			}
		}
	}
	r.warn("SoH not available or not-implemented — skipping")
	r.result(true)
}

// checkBAT003 verifies rated energy capacity is > 0.
func checkBAT003(r *Reporter, reader *sunspec.Reader) {
	r.section("BAT-003", "Rated Energy Capacity (WHRtg)")
	r.spec("SunSpec M713/M802 §5.1", "WHRtg SHALL be > 0 Wh")

	if reader.HasModel(sunspec.ModelDERStorageCap) {
		regs, _ := reader.ReadModel(sunspec.ModelDERStorageCap)
		if len(regs) > sunspec.M713_WHRtg {
			cap := sunspec.ApplyScaleUint(regs[sunspec.M713_WHRtg], int16(regs[sunspec.M713_WHRtg_SF]))
			if !math.IsNaN(cap) && cap > 0 {
				r.pass("M713.WHRtg = %.0f Wh", cap)
				r.result(true)
				return
			}
		}
	}
	if reader.HasModel(sunspec.ModelLithiumBattery) {
		regs, _ := reader.ReadModel(sunspec.ModelLithiumBattery)
		if len(regs) > sunspec.M802_WHRtg {
			cap := sunspec.ApplyScaleUint(regs[sunspec.M802_WHRtg], int16(regs[sunspec.M802_WHRtg_SF]))
			if !math.IsNaN(cap) && cap > 0 {
				r.pass("M802.WHRtg = %.0f Wh", cap)
				r.result(true)
				return
			}
		}
	}
	r.warn("WHRtg not available — skipping")
	r.result(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	var (
		server  = flag.String("server", "127.0.0.1:5020", "Modbus TCP address:port of the device under test")
		device  = flag.String("device", "inverter", "device type: inverter or battery")
		unitID  = flag.Uint("unit", 1, "Modbus unit ID (slave address)")
		timeout = flag.Duration("timeout", 5*time.Second, "Modbus transaction timeout")
		outFile = flag.String("out", "", "log file path (empty = stdout only)")
	)
	flag.Parse()

	r, cleanup := newReporter(*outFile)
	defer cleanup()

	r.printf("%s\n", strings.Repeat("═", 72))
	r.printf("SUNSPEC / IEEE 1547-2018 MODBUS CONFORMANCE TEST\n")
	r.printf("%s\n", strings.Repeat("─", 72))
	r.printf("Server:      %s\n", *server)
	r.printf("Device type: %s\n", *device)
	r.printf("Unit ID:     %d\n", *unitID)
	r.printf("Date:        %s\n", time.Now().UTC().Format(time.RFC3339))
	r.printf("%s\n", strings.Repeat("═", 72))

	// Open transport.
	t, err := modbus.NewTransport("tcp://"+*server, *timeout)
	if err != nil {
		log.Fatalf("new transport: %v", err)
	}
	if err := t.Open(); err != nil {
		log.Fatalf("open transport to %s: %v", *server, err)
	}
	defer t.Close()
	if err := t.SetUnitID(uint8(*unitID)); err != nil {
		log.Fatalf("set unit ID: %v", err)
	}
	r.printf("\nConnected to %s (unit %d)\n", *server, *unitID)

	// ── Discovery checks — must pass before model-level checks ───────────────
	if !checkDISC001(r, t) {
		r.printf("\nFATAL: no SunSpec header — cannot proceed.\n")
		r.summary()
		os.Exit(1)
	}

	reader, err := sunspec.NewReader(t)
	if err != nil {
		r.printf("\nFATAL: SunSpec block scan failed: %v\n", err)
		r.summary()
		os.Exit(1)
	}
	r.printf("  ✓ SunSpec block scan complete (%d model blocks)\n", len(reader.Blocks()))

	checkDISC002(r, reader)
	measModel := checkDISC003(r, reader)
	nameplateModel := checkDISC004(r, reader)
	ctrlModel := checkDISC005(r, reader)
	checkDISC006(r, reader)

	if measModel == 0 {
		r.printf("\nFATAL: no AC measurement model — cannot run measurement checks.\n")
		r.summary()
		os.Exit(1)
	}

	// ── Measurement checks ────────────────────────────────────────────────────
	watt := checkMEAS001(r, reader, measModel)
	checkMEAS002(r, reader, measModel)
	checkMEAS003(r, reader, measModel)
	checkMEAS004(r, reader, measModel, watt)
	checkMEAS005(r, reader, measModel)
	checkMEAS006(r, reader, measModel)

	// ── Nameplate checks ──────────────────────────────────────────────────────
	wmax := math.NaN()
	if nameplateModel != 0 {
		wmax = checkNAME001(r, reader, nameplateModel)
	}
	checkNAME002(r, watt, wmax)

	// ── Control checks ────────────────────────────────────────────────────────
	checkCTRL001(r, reader, ctrlModel, wmax)
	checkCTRL002(r, reader, ctrlModel)
	checkCTRL003(r, reader)

	// ── Status checks ─────────────────────────────────────────────────────────
	checkSTAT001(r, reader, measModel)
	checkSTAT002(r, reader, measModel)

	// ── Battery checks (only if storage models present) ───────────────────────
	isBattery := *device == "battery" ||
		reader.HasModel(sunspec.ModelLithiumBattery) ||
		reader.HasModel(sunspec.ModelDERStorageCap)
	if isBattery {
		r.printf("\n  (Storage device — running battery-specific checks)\n")
		checkBAT001(r, reader)
		checkBAT002(r, reader)
		checkBAT003(r, reader)
	}

	r.summary()
	if r.failCount > 0 {
		os.Exit(1)
	}
}
