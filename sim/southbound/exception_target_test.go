package sim

import (
	"testing"

	modbuslib "github.com/simonvetter/modbus"
)

// TestTargetedException_UnarmedNeverHits pins "zero behaviour change when
// unused": a fresh TargetedException never fires, for any fc/addr.
func TestTargetedException_UnarmedNeverHits(t *testing.T) {
	texc := NewTargetedException()
	if _, hit := texc.check(3, 40000, 4); hit {
		t.Fatal("an unarmed TargetedException must never hit")
	}
}

// TestTargetedException_TargetsSpecificFC arms code=1 (ILLEGAL FUNCTION) on
// fc=3 only: reads (fc 3) are hit, writes (fc 6, inferred from a single
// value) are not.
func TestTargetedException_TargetsSpecificFC(t *testing.T) {
	texc := NewTargetedException()
	if err := texc.arm(1, 3, 0, 0, true); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if err, hit := texc.check(3, 40000, 2); !hit || err != modbuslib.ErrIllegalFunction {
		t.Fatalf("fc=3 read: hit=%v err=%v, want hit with ErrIllegalFunction", hit, err)
	}
	if _, hit := texc.check(6, 40000, 1); hit {
		t.Fatal("fc=6 must not be hit when only fc=3 is targeted")
	}
}

// TestTargetedException_TargetsAddressRange arms an address window and
// requires overlap, not exact match, to trigger — a client rarely reads
// exactly the targeted register alone.
func TestTargetedException_TargetsAddressRange(t *testing.T) {
	texc := NewTargetedException()
	if err := texc.arm(2, 0, 40072, 40074, false); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if _, hit := texc.check(3, 40070, 4); !hit { // [40070,40074) overlaps [40072,40074)
		t.Fatal("an overlapping read must hit")
	}
	if _, hit := texc.check(3, 40000, 4); hit { // [40000,40004) does not overlap
		t.Fatal("a non-overlapping read must not hit")
	}
	if err, hit := texc.check(3, 40072, 1); !hit || err != modbuslib.ErrIllegalDataAddress {
		t.Fatalf("exact-register read: hit=%v err=%v, want hit with ErrIllegalDataAddress", hit, err)
	}
}

// TestTargetedException_WrapOnRead_Integration exercises the wrapper the way
// modsim/main.go wires it, through a real RegisterMap.
func TestTargetedException_WrapOnRead_Integration(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	for a := uint16(100); a < 110; a++ {
		r.Set(a, a)
	}
	texc := NewTargetedException()
	r.OnRead = texc.WrapOnRead(nil)

	// Unarmed: reads pass through untouched.
	got, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 100, Quantity: 2})
	if err != nil || got[0] != 100 {
		t.Fatalf("unarmed read: got=%v err=%v", got, err)
	}

	if err := texc.arm(3, 3, 104, 106, false); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 104, Quantity: 1}); err != modbuslib.ErrIllegalDataValue {
		t.Fatalf("targeted read err = %v, want ErrIllegalDataValue", err)
	}
	if got, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 100, Quantity: 2}); err != nil || got[0] != 100 {
		t.Fatalf("untargeted read must still succeed: got=%v err=%v", got, err)
	}
}

// TestTargetedException_OnWriteError_Integration exercises the write path:
// FC is inferred from the number of values (1 = single/FC6, >1 = multi/FC16).
func TestTargetedException_OnWriteError_Integration(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	texc := NewTargetedException()
	r.OnWriteError = texc.OnWriteError

	if err := texc.arm(2, 6, 0, 0, true); err != nil { // target FC6 (single writes) only
		t.Fatalf("arm: %v", err)
	}

	// A single-register write (FC6) must fail AFTER landing.
	_, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 200, IsWrite: true, Args: []uint16{7}})
	if err != modbuslib.ErrIllegalDataAddress {
		t.Fatalf("single-register write err = %v, want ErrIllegalDataAddress", err)
	}
	if got := r.Get(200); got != 7 {
		t.Fatalf("register 200 = %d, want 7 — OnWriteError must not prevent the value landing (apply-then-lie)", got)
	}

	// A multi-register write (FC16) must NOT be targeted (only FC6 is armed).
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{Addr: 300, IsWrite: true, Args: []uint16{1, 2}}); err != nil {
		t.Fatalf("multi-register write err = %v, want nil (FC16 is not targeted)", err)
	}
}

// TestTargetedException_ApplyFault_ClassicFormPassesThrough is the "zero
// behaviour change" pin at the /fault-body level: a plain, untargeted
// exception_code body must be left for the classic faultController path.
func TestTargetedException_ApplyFault_ClassicFormPassesThrough(t *testing.T) {
	texc := NewTargetedException()
	if handled, err := texc.ApplyFault([]byte(`{"kind":"exception_code"}`)); handled || err != nil {
		t.Fatalf("classic exception_code: handled=%v err=%v, want handled=false", handled, err)
	}
}

// TestTargetedException_ApplyFault_ArmsTargeted proves the targeted JSON
// shape from the census report arms the layer and the classic path is
// bypassed (handled=true).
func TestTargetedException_ApplyFault_ArmsTargeted(t *testing.T) {
	texc := NewTargetedException()
	handled, err := texc.ApplyFault([]byte(`{"kind":"exception_code","code":1,"on_fc":3}`))
	if !handled || err != nil {
		t.Fatalf("targeted arm: handled=%v err=%v", handled, err)
	}
	if err, hit := texc.check(3, 40000, 2); !hit || err != modbuslib.ErrIllegalFunction {
		t.Fatalf("after arming via ApplyFault: hit=%v err=%v", hit, err)
	}
}

// TestTargetedException_ApplyFault_ClearFallsThrough proves clear disarms
// this layer AND still reports unhandled, so a plain clear body also
// disarms the classic whole-bank flag.
func TestTargetedException_ApplyFault_ClearFallsThrough(t *testing.T) {
	texc := NewTargetedException()
	_, _ = texc.ApplyFault([]byte(`{"kind":"exception_code","code":1,"on_fc":3}`))
	handled, err := texc.ApplyFault([]byte(`{"kind":"exception_code","clear":true}`))
	if handled || err != nil {
		t.Fatalf("clear: handled=%v err=%v, want handled=false (so the classic path also clears)", handled, err)
	}
	if _, hit := texc.check(3, 40000, 2); hit {
		t.Fatal("targeted exception must be disarmed after clear")
	}
}

func TestTargetedException_ApplyFault_UnknownCode(t *testing.T) {
	texc := NewTargetedException()
	handled, err := texc.ApplyFault([]byte(`{"kind":"exception_code","code":99}`))
	if !handled || err == nil {
		t.Fatalf("unknown code: handled=%v err=%v, want handled=true with an error", handled, err)
	}
}

func TestTargetedException_ApplyFault_BadOnAddr(t *testing.T) {
	texc := NewTargetedException()
	handled, err := texc.ApplyFault([]byte(`{"kind":"exception_code","on_addr":[1,2,3]}`))
	if !handled || err == nil {
		t.Fatalf("3-element on_addr: handled=%v err=%v, want handled=true with an error", handled, err)
	}
}

func TestTargetedException_ApplyFault_OtherKindNotClaimed(t *testing.T) {
	texc := NewTargetedException()
	if handled, _ := texc.ApplyFault([]byte(`{"kind":"tcp_drop"}`)); handled {
		t.Fatal("TargetedException claimed a kind it does not own")
	}
}
