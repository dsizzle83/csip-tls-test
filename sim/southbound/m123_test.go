package sim

// m123_test.go — the model-123 fixture's own properties.

import (
	"testing"

	modbuslib "github.com/simonvetter/modbus"
	"lexa-proto/sunspec"
)

// TestM123BlockIsThePublishedLength pins the one number three sims used to
// restate independently, and got wrong in all three.
func TestM123BlockIsThePublishedLength(t *testing.T) {
	if got, want := int(M123Len()), sunspec.L123.Len(); got != want {
		t.Fatalf("M123Len() = %d, layout says %d", got, want)
	}
	if M123Len() != 24 {
		t.Errorf("the published model 123 has 24 data registers; this reports %d", M123Len())
	}
}

// TestM123ScaleFactorsAreWriteProtected is the A3 adjudication as a test.
//
// The battery DECODES ITS COMMANDED CEILING through M123_WMaxLimPct_SF, so a
// writable scale factor lets a client change the meaning of every subsequent
// ceiling read without touching the ceiling register. Solar listed the three
// cells by hand and was covered; every battery path protected 701/702/703/704/
// 713 and never mentioned 123.
func TestM123ScaleFactorsAreWriteProtected(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	const base = 100
	PopulateM123(r, base, M123Defaults{WMaxLimPctRaw: 10000, WMaxLimPctSF: -2, WMaxLimEna: 1, Conn: 1})
	protectM123SFs(r, base+2)

	// Through the MODBUS WRITE PATH, which is where protection is enforced —
	// the sim's own Set is the populate door and legitimately bypasses it.
	for _, name := range []string{"WMaxLimPct_SF", "OutPFSet_SF", "VArPct_SF"} {
		addr := base + 2 + uint16(sunspec.L123.Offset(name))
		before := r.Get(addr)
		if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
			IsWrite: true, Addr: addr, Args: []uint16{0x0007},
		}); err != nil {
			t.Fatalf("write to %s: %v (protection must mask, never fail the transaction)", name, err)
		}
		if got := r.Get(addr); got != before {
			t.Errorf("%s at %d was writable: %#x -> %#x. A mutable scale factor changes what every "+
				"subsequent read of its group MEANS — and the battery decodes its commanded ceiling "+
				"THROUGH this cell", name, addr, before, got)
		}
	}
	// And a NON-scale-factor point in the same block stays writable — a
	// protection that froze the whole model would break every control test.
	cmd := base + 2 + uint16(sunspec.L123.Offset("WMaxLimPct"))
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		IsWrite: true, Addr: cmd, Args: []uint16{6000},
	}); err != nil {
		t.Fatalf("write the ceiling: %v", err)
	}
	if got := r.Get(cmd); got != 6000 {
		t.Errorf("the commanded ceiling became unwritable (%d); the protection is too wide", got)
	}
}

// TestM123ReactiveTrioIsPublishedWithItsSelector: collapsing the trio into one
// point is half of how a 24-point model became a 23-point one, so all three are
// present and the mode that selects between them agrees with the one the real
// consumer writes.
func TestM123ReactiveTrioIsPublishedWithItsSelector(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	const base = 100
	PopulateM123(r, base, M123Defaults{WMaxLimPctRaw: 10000, WMaxLimPctSF: -2, WMaxLimEna: 1, Conn: 1})

	for _, name := range []string{"VArWMaxPct", "VArMaxPct", "VArAvalPct"} {
		if !sunspec.L123.Has(name) {
			t.Fatalf("the layout declares no %s", name)
		}
	}
	mod := r.Get(base + 2 + uint16(sunspec.L123.Offset("VArPct_Mod")))
	if mod != M123VArPctModVArMax {
		t.Errorf("VArPct_Mod = %d, want %d (VArMax) — the pairing lexa-gw's reconciler writes, and the "+
			"only one lexa-proto's M123_VArPct compatibility alias is correct under", mod, M123VArPctModVArMax)
	}
}
