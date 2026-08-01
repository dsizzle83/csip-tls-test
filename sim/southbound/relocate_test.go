package sim

import (
	"testing"

	"lexa-proto/sunspec"
)

// TestRelocator_DefaultIsSunSpecBase pins the zero-effect starting state: a
// Relocator that has never been told to move reports the same base every
// sim in this package already populates at.
func TestRelocator_DefaultIsSunSpecBase(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	rl := NewRelocator(r)
	if got := rl.Base(); got != sunspec.SunSpecBase {
		t.Fatalf("Base() = %d, want %d", got, sunspec.SunSpecBase)
	}
}

// TestRelocator_RelocateMovesContent proves the SunS header and Model 1 id
// actually move to the new base, and that the OLD addresses no longer hold
// them.
func TestRelocator_RelocateMovesContent(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	rl := NewRelocator(r)

	rl.Relocate(0)

	if got := r.Get(0); got != sunspec.SunSMagic0 {
		t.Fatalf("register 0 = %#04x, want SunS magic0 %#04x", got, sunspec.SunSMagic0)
	}
	if got := r.Get(1); got != sunspec.SunSMagic1 {
		t.Fatalf("register 1 = %#04x, want SunS magic1 %#04x", got, sunspec.SunSMagic1)
	}
	if got := r.Get(2); got != sunspec.ModelCommon {
		t.Fatalf("register 2 (model id) = %d, want %d (Model 1 Common)", got, sunspec.ModelCommon)
	}
	// The vacated original addresses must no longer hold the header — Get on
	// an address nothing maps to returns the map's zero value.
	if got := r.Get(sunspec.SunSpecBase); got == sunspec.SunSMagic0 {
		t.Fatalf("register %d still reads the SunS magic after relocating away from it", sunspec.SunSpecBase)
	}
}

// TestRelocator_RoundTripRestoresExactContent relocates away and back, and
// requires every register to match the pristine image exactly — proving the
// shift is a true bijection, not a lossy approximation.
func TestRelocator_RoundTripRestoresExactContent(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	want := snapshotRegs(r)

	rl := NewRelocator(r)
	rl.Relocate(50000)
	rl.Relocate(sunspec.SunSpecBase)

	got := snapshotRegs(r)
	if len(got) != len(want) {
		t.Fatalf("register count after round trip = %d, want %d", len(got), len(want))
	}
	for addr, v := range want {
		if got[addr] != v {
			t.Errorf("register %d = %d after round trip, want %d", addr, got[addr], v)
		}
	}
}

// TestRelocator_IdempotentReArm calls Relocate to the SAME target twice and
// requires the second call to be a true no-op: the content after two calls
// must be identical to the content after one.
func TestRelocator_IdempotentReArm(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	rl := NewRelocator(r)

	rl.Relocate(40001)
	once := snapshotRegs(r)
	rl.Relocate(40001) // re-arm at the same base
	twice := snapshotRegs(r)

	if len(once) != len(twice) {
		t.Fatalf("register count changed on re-arm: %d vs %d", len(once), len(twice))
	}
	for addr, v := range once {
		if twice[addr] != v {
			t.Errorf("register %d = %d after re-arm, want %d (unchanged from the first arm)", addr, twice[addr], v)
		}
	}
	if rl.Base() != 40001 {
		t.Fatalf("Base() = %d, want 40001", rl.Base())
	}
}

// TestRelocator_NoncompliantBase40001 exercises the ERR-1 scenario directly:
// relocating one register off the legal 40000 base.
func TestRelocator_NoncompliantBase40001(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	rl := NewRelocator(r)
	rl.Relocate(40001)

	if got := r.Get(40001); got != sunspec.SunSMagic0 {
		t.Fatalf("register 40001 = %#04x, want the SunS magic0 the noncompliant map should present there", got)
	}
	if got := r.Get(sunspec.SunSpecBase); got == sunspec.SunSMagic0 {
		t.Fatalf("register %d still reads the SunS magic — the map did not move off the compliant base", sunspec.SunSpecBase)
	}
}

// TestRelocator_ApplyFault_ArmAndClear drives Relocator entirely through the
// POST /fault body shape modsim/main.go wires it to.
func TestRelocator_ApplyFault_ArmAndClear(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	rl := NewRelocator(r)

	handled, err := rl.ApplyFault([]byte(`{"kind":"relocate","base":50000}`))
	if !handled || err != nil {
		t.Fatalf("arm: handled=%v err=%v", handled, err)
	}
	if rl.Base() != 50000 {
		t.Fatalf("Base() = %d after arm, want 50000", rl.Base())
	}
	if got := r.Get(50000); got != sunspec.SunSMagic0 {
		t.Fatalf("register 50000 = %#04x after relocate, want the SunS magic0", got)
	}

	handled, err = rl.ApplyFault([]byte(`{"kind":"relocate","clear":true}`))
	if !handled || err != nil {
		t.Fatalf("clear: handled=%v err=%v", handled, err)
	}
	if rl.Base() != sunspec.SunSpecBase {
		t.Fatalf("Base() = %d after clear, want the default %d", rl.Base(), sunspec.SunSpecBase)
	}
}

// TestRelocator_ApplyFault_MissingBase requires an explicit base (no silent
// default), and TestRelocator_ApplyFault_UnclaimedKind proves an unrelated
// kind is left for the caller's fallback chain.
func TestRelocator_ApplyFault_MissingBase(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	rl := NewRelocator(r)
	handled, err := rl.ApplyFault([]byte(`{"kind":"relocate"}`))
	if !handled {
		t.Fatal("relocate without base or clear must be claimed (and rejected), not silently ignored")
	}
	if err == nil {
		t.Fatal("relocate without base or clear must error")
	}
}

func TestRelocator_ApplyFault_UnclaimedKind(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	rl := NewRelocator(r)
	if handled, _ := rl.ApplyFault([]byte(`{"kind":"tcp_drop"}`)); handled {
		t.Fatal("Relocator claimed a kind it does not own")
	}
}

// snapshotRegs copies the current register map for before/after comparison.
func snapshotRegs(r *RegisterMap) map[uint16]uint16 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint16]uint16, len(r.regs))
	for k, v := range r.regs {
		out[k] = v
	}
	return out
}
