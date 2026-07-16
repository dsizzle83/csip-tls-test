package sim

// protect_test.go — SF write-protection (protect.go) and the audit-E1
// corruption chain it exists for: nan_sentinel rewrites every Modbus READ to
// 0x8000, the hub's derbase whole-block 704 read-modify-write reads
// all-0x8000 and writes the block straight back, and before the fix the
// register bank stayed poisoned (scale factors included) until a sim restart,
// so Snapshot decoded NaN and GET /state 500'd forever.

import (
	"encoding/json"
	"math"
	"testing"

	modbuslib "github.com/simonvetter/modbus"

	"csip-tls-test/sim/simapi"
	"lexa-proto/sunspec"
)

// TestProtect_MasksOnlySFCells: a write spanning protected and unprotected
// cells lands everywhere except the protected ones (the transaction still
// ACKs), echoing the stored value back is not counted as a divergence, and
// sim-internal Set stays unrestricted.
func TestProtect_MasksOnlySFCells(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(100, 7)
	r.Set(101, uint16(0xFFFE)) // an SF of −2, as a device would hold
	r.Protect(101)

	// A write covering both: the data cell changes, the SF cell is masked.
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		IsWrite: true, Addr: 100, Args: []uint16{55, 0x8000},
	}); err != nil {
		t.Fatalf("write: %v (protection must not fail the transaction)", err)
	}
	if got := r.Get(100); got != 55 {
		t.Errorf("unprotected reg 100 = %d, want 55 (the rest of the write must land)", got)
	}
	if got := r.Get(101); got != 0xFFFE {
		t.Errorf("protected reg 101 = %#x, want 0xFFFE (masked)", got)
	}
	if n := r.ProtectedRejects(); n != 1 {
		t.Errorf("ProtectedRejects = %d, want 1", n)
	}

	// Echoing the stored value back (the hub's routine RMW) is not a divergence.
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		IsWrite: true, Addr: 100, Args: []uint16{56, 0xFFFE},
	}); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	if n := r.ProtectedRejects(); n != 1 {
		t.Errorf("ProtectedRejects after echo write = %d, want 1 (same-value writes are not counted)", n)
	}

	// Sim-internal Set is unrestricted: populate/animation own these cells.
	r.Set(101, 3)
	if got := r.Get(101); got != 3 {
		t.Errorf("Set on protected reg = %d, want 3 (internal writes bypass protection)", got)
	}
}

// TestE1_NanSentinelWriteBack replays the full E1 chain against the advanced
// solar sim: arm nan_sentinel, perform the hub's whole-block 704 RMW (read
// all-0x8000 through the fault, write it back), clear the fault — then the SF
// registers must have survived, the rejection must be observable on /state,
// and the /state encoding path (the simapi sanitizer writeJSON now uses) must
// succeed on the residually-poisoned snapshot.
func TestE1_NanSentinelWriteBack(t *testing.T) {
	ss := newAdvSolar(t, 5000)
	r := ss.Regs
	r.OnRead = ss.faults.transportRead // as NewSolarServerAdvanced wires it

	// Record the pre-fault SF values of model 704 straight from the layout.
	preSF := map[uint16]uint16{} // absolute addr → pre-fault value
	for _, f := range sunspec.L704.Fields {
		if f.Type == sunspec.Tsunssf {
			addr := ss.adv.M704 + uint16(sunspec.L704.Offset(f.Name))
			preSF[addr] = r.Get(addr)
		}
	}
	pfSF := ss.adv.M704 + uint16(sunspec.L704.Offset("PF_SF"))
	if preSF[pfSF] != 0xFFFC { // int16 −4
		t.Fatalf("PF_SF pre-fault = %#x, want 0xFFFC (−4) — populate704 seeding changed?", preSF[pfSF])
	}

	// (1) Arm the read fault: every Modbus read now returns 0x8000.
	if err := ss.ApplyFault([]byte(`{"kind":"nan_sentinel"}`)); err != nil {
		t.Fatalf("arm nan_sentinel: %v", err)
	}

	// (2) The hub's write704 RMW during the window: read the whole block
	// (all sentinels through the fault) and write it straight back.
	blockLen := uint16(sunspec.L704.Len())
	read, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		Addr: ss.adv.M704, Quantity: blockLen,
	})
	if err != nil {
		t.Fatalf("faulted read: %v", err)
	}
	for i, v := range read {
		if v != 0x8000 {
			t.Fatalf("faulted read[%d] = %#x, want 0x8000 (nan_sentinel READ behavior must be unchanged)", i, v)
		}
	}
	if _, err := r.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		IsWrite: true, Addr: ss.adv.M704, Args: read,
	}); err != nil {
		t.Fatalf("whole-block write-back: %v", err)
	}

	// (3) Clear the fault; reads are truthful again.
	if err := ss.ApplyFault([]byte(`{"kind":"nan_sentinel","clear":true}`)); err != nil {
		t.Fatalf("clear nan_sentinel: %v", err)
	}

	// The SF registers survived the write-back...
	for addr, want := range preSF {
		if got := r.Get(addr); got != want {
			t.Errorf("SF register %d = %#x after write-back, want %#x (pre-fault)", addr, got, want)
		}
	}
	// ...while the non-SF cells DID take it — partial masking is deliberate
	// (device-realistic; the corruption of writable cells stays visible).
	wmaxLim := ss.adv.M704 + uint16(sunspec.L704.Offset("WMaxLimPct"))
	if got := r.Get(wmaxLim); got != 0x8000 {
		t.Errorf("WMaxLimPct = %#x, want 0x8000 (non-SF cells accept the write)", got)
	}

	// The masked writes are observable on /state.
	snap := ss.Snapshot()
	if want := uint64(len(preSF)); snap.SFWriteRejects != want {
		t.Errorf("sf_write_rejects = %d, want %d (one per masked SF cell)", snap.SFWriteRejects, want)
	}

	// With the SFs intact, the Tint16 704 cells (e.g. VarSetPct) still decode
	// their own 0x8000 sentinel as NaN — the raw snapshot legitimately carries
	// NaN, and the /state encoding path must degrade it to null, never fail.
	if !math.IsNaN(snap.Advanced.FixedVar.Pct) {
		t.Fatalf("FixedVar.Pct = %v, want NaN (the E1 residue this test exists to exercise)", snap.Advanced.FixedVar.Pct)
	}
	b, err := json.Marshal(simapi.SanitizeNonFinite(snap))
	if err != nil {
		t.Fatalf("sanitized /state marshal: %v (GET /state must never fail on corrupted ground truth)", err)
	}
	var decoded struct {
		Advanced struct {
			FixedVar struct {
				Pct *float64 `json:"pct"`
			} `json:"fixed_var"`
		} `json:"advanced"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("sanitized /state is not valid JSON: %v", err)
	}
	if decoded.Advanced.FixedVar.Pct != nil {
		t.Errorf("sanitized fixed_var.pct = %v, want null", *decoded.Advanced.FixedVar.Pct)
	}
}
