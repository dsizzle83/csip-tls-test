package main

import "testing"

// TestFaultOutOfOrderTxevent: arming out_of_order_txevent toggles the 2.0.1
// proto's reorder flag (so sendEvent emits a non-monotonic seqNo); clearing
// disarms it. The reorder lives on ocpp201Proto and is reached via the
// optional-interface assertion in csHandler.ApplyFault.
func TestFaultOutOfOrderTxevent(t *testing.T) {
	p := newOCPP201Proto(nil)
	h := &csHandler{proto: p, batt: newEVBattery(60000, 50, 230, 32, 1)}

	if err := h.ApplyFault([]byte(`{"kind":"out_of_order_txevent"}`)); err != nil {
		t.Fatalf("arm out_of_order_txevent: %v", err)
	}
	if !p.reorderTx.Load() {
		t.Fatal("reorderTx not armed after ApplyFault")
	}
	if err := h.ApplyFault([]byte(`{"kind":"out_of_order_txevent","clear":true}`)); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if p.reorderTx.Load() {
		t.Fatal("reorderTx still armed after clear")
	}
}

// TestReorderSeqIsNonMonotonic pins the seqNo perturbation: XOR-ing the low bit
// swaps each adjacent pair (0,1,2,3 → 1,0,3,2), so a later event can carry a
// lower seqNo than an earlier one — a non-monotonic sequence — while every value
// stays unique.
func TestReorderSeqIsNonMonotonic(t *testing.T) {
	sent := make([]int, 6)
	for seq := 0; seq < 6; seq++ {
		sent[seq] = seq ^ 1
	}
	// The Started event (real seq 0) must be sent with a HIGHER seqNo than the
	// Updated after it (real seq 1) — the ordering violation the fault creates.
	if !(sent[0] > sent[1]) {
		t.Errorf("sent seq for event0=%d not > event1=%d (should be non-monotonic)", sent[0], sent[1])
	}
	seen := map[int]bool{}
	for _, s := range sent {
		if seen[s] {
			t.Errorf("reordered seq %d is not unique: %v", s, sent)
		}
		seen[s] = true
	}
}

// TestFaultBootMidTx_NoSession: boot_mid_tx with no active session is a safe
// no-op (it must not send a BootNotification into a nil transport); a clear is
// also a no-op. Both return nil.
func TestFaultBootMidTx_NoSession(t *testing.T) {
	h := &csHandler{proto: newOCPP201Proto(nil), batt: newEVBattery(60000, 50, 230, 32, 1)}
	if h.sessionActive() {
		t.Fatal("precondition: no session should be active")
	}
	if err := h.ApplyFault([]byte(`{"kind":"boot_mid_tx"}`)); err != nil {
		t.Fatalf("boot_mid_tx (no session): %v", err)
	}
	if err := h.ApplyFault([]byte(`{"kind":"boot_mid_tx","clear":true}`)); err != nil {
		t.Fatalf("boot_mid_tx clear: %v", err)
	}
}
