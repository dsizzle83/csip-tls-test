package sim

// meter.go — static single-phase AC meter simulator (SunSpec Model 201).
//
// Register layout (Models 1 → 201 → end):
//
//	40000–40001: SunS header
//	40002–40069: Model 1   (Common,              66 data regs)
//	40070–40176: Model 201 (Single-Phase Meter, 105 data regs)
//	40177–40178: end marker
//
// netW sign convention:
//
//	positive = site importing from grid  (utility is a source)
//	negative = site exporting to grid    (utility is a sink)

import (
	"math"

	"csip-tls-test/internal/southbound/sunspec"
)

// MeterServer is a running SunSpec AC meter simulator.
// It extends Server with a convenience method for changing the net power
// reading during tests.
type MeterServer struct {
	*Server
	// M201Base is the Modbus address of the first data register of Model 201.
	// Tests can write registers directly:
	//   srv.Regs.Set(srv.M201Base+sunspec.M201_W, uint16(int16(watts)))
	M201Base uint16
}

// NewMeterServer creates and starts a static single-phase AC meter simulator.
//
// netW is the initial net power (W):
//   - positive  → site is net importing
//   - negative  → site is net exporting
func NewMeterServer(listenURL string, netW float64) (*MeterServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	m201Base := populateMeter(regs, netW)
	srv, err := startServer(listenURL, regs)
	if err != nil {
		return nil, err
	}
	return &MeterServer{Server: srv, M201Base: m201Base}, nil
}

// SetNetW updates the W register so ReadMeasurements reflects a new reading.
// sf=0 so raw == watts; valid range ±32 767 W.
func (ms *MeterServer) SetNetW(netW float64) {
	ms.Regs.Set(ms.M201Base+uint16(sunspec.M201_W), uint16(int16(netW)))
	ms.Regs.Set(ms.M201Base+uint16(sunspec.M201_W_SF), 0)
}

// populateMeter writes the SunSpec header, Model 1, and Model 201 into r.
// Returns the Modbus address of the first Model 201 data register.
func populateMeter(r *RegisterMap, netW float64) uint16 {
	sfN := func(v int16) uint16 { return uint16(v) }
	base := sunspec.SunSpecBase

	// SunS header
	r.Set(base+0, sunspec.SunSMagic0)
	r.Set(base+1, sunspec.SunSMagic1)
	cursor := base + 2

	// Model 1 (Common) — 66 data registers
	const m1Len = 66
	r.Set(cursor, sunspec.ModelCommon)
	r.Set(cursor+1, m1Len)
	m1 := cursor + 2
	setStr16(r, m1+0, "SunSpec Sim")
	setStr8(r, m1+16, "CSIP-Meter-1Ph")
	setStr8(r, m1+32, "SN-MTR-001")
	cursor += 2 + m1Len

	// Model 201 (Single-Phase AC Meter) — 105 data registers
	r.Set(cursor, sunspec.ModelMeterSinglePh)
	r.Set(cursor+1, sunspec.M201Len)
	m201Base := cursor + 2

	// Voltage: 2400 × 10^-1 = 240.0 V
	r.Set(m201Base+sunspec.M201_PhV, 2400)
	r.Set(m201Base+sunspec.M201_PhVphA, 2400)
	r.Set(m201Base+sunspec.M201_V_SF, sfN(-1))

	// Frequency: 6000 × 10^-2 = 60.00 Hz
	r.Set(m201Base+sunspec.M201_Hz, 6000)
	r.Set(m201Base+sunspec.M201_Hz_SF, sfN(-2))

	// Net power (sf=0 → raw == watts, range ±32 767 W)
	r.Set(m201Base+sunspec.M201_W, uint16(int16(netW)))
	r.Set(m201Base+sunspec.M201_W_SF, 0)

	// Apparent power ≈ |W| / pf (sf=0)
	pf := 0.95
	va := math.Abs(netW) / pf
	r.Set(m201Base+sunspec.M201_VA, uint16(int16(va)))
	r.Set(m201Base+sunspec.M201_VA_SF, 0)

	// Reactive power ≈ W × tan(acos(0.95)) ≈ W × 0.329
	varPwr := netW * 0.329
	r.Set(m201Base+sunspec.M201_VAR, uint16(int16(varPwr)))
	r.Set(m201Base+sunspec.M201_VAR_SF, 0)

	// Power factor: 9500 × 10^-2 = 0.9500
	r.Set(m201Base+sunspec.M201_PF, uint16(int16(9500)))
	r.Set(m201Base+sunspec.M201_PF_SF, sfN(-2))

	// Current: A = W / V (sf=0, whole amps)
	amps := int16(netW / 240.0)
	r.Set(m201Base+sunspec.M201_A, uint16(amps))
	r.Set(m201Base+sunspec.M201_AphA, uint16(amps))
	r.Set(m201Base+sunspec.M201_A_SF, 0)

	cursor += 2 + sunspec.M201Len

	// End marker
	r.Set(cursor, sunspec.EndMarker)
	r.Set(cursor+1, 0)

	return m201Base
}
