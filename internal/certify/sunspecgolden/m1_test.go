package sunspecgolden_test

import (
	"fmt"
	"testing"

	"csip-tls-test/internal/certify/sunspecgolden"

	"lexa-proto/sunspec"
)

// fakeTransport is a minimal in-memory modbus.Transport backing a single
// SunSpec register map, used ONLY to drive sunspec.ReadCommon through a real
// Scan()+ReadModel() so model 1's offsets — which lexa-proto keeps as
// UNEXPORTED constants in identity.go (commonMnReg etc.) and therefore
// cannot be read from this external test package — are proven by BEHAVIOR
// instead: values placed at the golden's offsets must come back through the
// fields ReadCommon says they belong to.
type fakeTransport struct {
	regs map[uint16]uint16
}

func (f *fakeTransport) Open() error  { return nil }
func (f *fakeTransport) Close() error { return nil }
func (f *fakeTransport) SetUnitID(uint8) error {
	return nil
}
func (f *fakeTransport) ReadHolding(addr, quantity uint16) ([]uint16, error) {
	out := make([]uint16, quantity)
	for i := uint16(0); i < quantity; i++ {
		out[i] = f.regs[addr+i]
	}
	return out, nil
}
func (f *fakeTransport) WriteHolding(addr uint16, values []uint16) error {
	for i, v := range values {
		f.regs[addr+uint16(i)] = v
	}
	return nil
}
func (f *fakeTransport) ReadInput(addr, quantity uint16) ([]uint16, error) {
	return f.ReadHolding(addr, quantity)
}

// putString big-endian-packs s into count registers at the fake device
// starting at addr, matching the SunSpec string encoding sunspec.regString
// decodes (two bytes per register, NUL-padded on the right).
func (f *fakeTransport) putString(addr uint16, count int, s string) {
	buf := make([]byte, count*2)
	copy(buf, s)
	for i := 0; i < count; i++ {
		f.regs[addr+uint16(i)] = uint16(buf[2*i])<<8 | uint16(buf[2*i+1])
	}
}

// testM1Common proves model 1's offsets (golden.Golden["M1"]) by BEHAVIOR:
// it builds a one-model SunSpec chain (model 1 only) on a fake transport,
// places a distinct value at each golden field's offset, and asserts
// sunspec.ReadCommon decodes each field from where the golden says it lives.
// This is the model-1 equivalent of the M120/M103/etc. raw-constant checks —
// model 1's offsets are private to lexa-proto (identity.go's commonMnReg
// etc.), so there is no exported constant this external test package can
// compare directly.
func testM1Common(t *testing.T) {
	golden, ok := sunspecgolden.Block("M1")
	if !ok {
		t.Fatal("golden has no M1 block")
	}
	byName := make(map[string]sunspecgolden.Point, len(golden))
	for _, p := range golden {
		byName[p.Name] = p
	}
	for _, want := range []string{"Mn", "Md", "Opt", "Vr", "SN", "DA"} {
		if _, ok := byName[want]; !ok {
			t.Fatalf("golden M1 has no point named %q", want)
		}
	}

	const base = uint16(40000) // sunspec.SunSpecBase
	ft := &fakeTransport{regs: make(map[uint16]uint16)}
	ft.regs[base] = sunspec.SunSMagic0
	ft.regs[base+1] = sunspec.SunSMagic1
	ft.regs[base+2] = sunspec.ModelCommon // model ID
	modelLen := uint16(66)                // golden's M1 length: 64 (Mn..DA data span) + DA(1) + Pad(1)
	ft.regs[base+3] = modelLen
	dataBase := base + 4

	// Place a distinct, position-identifying string/value at each golden
	// field's own offset -- proves ReadCommon decodes from where the golden
	// says the field lives, not from lexa-proto's own (private) idea of it.
	ft.putString(dataBase+uint16(byName["Mn"].Offset), byName["Mn"].Size, "ACME-MFR")
	ft.putString(dataBase+uint16(byName["Md"].Offset), byName["Md"].Size, "MODEL-X1")
	ft.putString(dataBase+uint16(byName["Opt"].Offset), byName["Opt"].Size, "OPT-1")
	ft.putString(dataBase+uint16(byName["Vr"].Offset), byName["Vr"].Size, "V9.9")
	ft.putString(dataBase+uint16(byName["SN"].Offset), byName["SN"].Size, "SERIAL-01234567")
	const wantDA = uint16(0xBEEF)
	ft.regs[dataBase+uint16(byName["DA"].Offset)] = wantDA

	// End marker immediately after model 1's data block.
	ft.regs[dataBase+modelLen] = sunspec.EndMarker
	ft.regs[dataBase+modelLen+1] = 0

	r, err := sunspec.NewReader(ft)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	c, err := sunspec.ReadCommon(r)
	if err != nil {
		t.Fatalf("ReadCommon: %v", err)
	}

	var mismatches []string
	if c.Manufacturer != "ACME-MFR" {
		mismatches = append(mismatches, fmt.Sprintf("Mn: got %q, want %q (golden offset %d)", c.Manufacturer, "ACME-MFR", byName["Mn"].Offset))
	}
	if c.Model != "MODEL-X1" {
		mismatches = append(mismatches, fmt.Sprintf("Md: got %q, want %q (golden offset %d)", c.Model, "MODEL-X1", byName["Md"].Offset))
	}
	if c.Options != "OPT-1" {
		mismatches = append(mismatches, fmt.Sprintf("Opt: got %q, want %q (golden offset %d)", c.Options, "OPT-1", byName["Opt"].Offset))
	}
	if c.Version != "V9.9" {
		mismatches = append(mismatches, fmt.Sprintf("Vr: got %q, want %q (golden offset %d)", c.Version, "V9.9", byName["Vr"].Offset))
	}
	if c.Serial != "SERIAL-01234567" {
		mismatches = append(mismatches, fmt.Sprintf("SN: got %q, want %q (golden offset %d)", c.Serial, "SERIAL-01234567", byName["SN"].Offset))
	}
	if c.DeviceAddr != wantDA {
		mismatches = append(mismatches, fmt.Sprintf("DA: got %#04x, want %#04x (golden offset %d)", c.DeviceAddr, wantDA, byName["DA"].Offset))
	}
	reportMismatches(t, "M1", mismatches)
}
