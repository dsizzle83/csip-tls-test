package sim

import (
	"testing"

	"lexa-proto/sunspec"
)

// TestModelSplicer_InsertBeforeEndMarker proves the new header lands exactly
// where the old end marker was, and the end marker itself moves past it.
func TestModelSplicer_InsertBeforeEndMarker(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	end, err := findEndMarker(r)
	if err != nil {
		t.Fatalf("findEndMarker (baseline): %v", err)
	}

	ms := NewModelSplicer(r)
	if err := ms.Insert(65000, 4); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if got := r.Get(end); got != 65000 {
		t.Fatalf("register %d (spliced header id) = %d, want 65000", end, got)
	}
	if got := r.Get(end + 1); got != 4 {
		t.Fatalf("register %d (spliced header len) = %d, want 4", end+1, got)
	}
	newEnd, err := findEndMarker(r)
	if err != nil {
		t.Fatalf("findEndMarker (after insert): %v", err)
	}
	if want := end + 2 + 4; newEnd != want {
		t.Fatalf("new end marker at %d, want %d (old end + 2 header regs + 4 body regs)", newEnd, want)
	}
}

// TestModelSplicer_ClearRestoresOriginalEndMarker proves retraction is
// exact: the chain after Clear is register-for-register identical to a
// fresh, never-spliced map.
func TestModelSplicer_ClearRestoresOriginalEndMarker(t *testing.T) {
	pristine := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(pristine, 5000)
	want := snapshotRegs(pristine)

	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	ms := NewModelSplicer(r)
	if err := ms.Insert(65000, 4); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	ms.Clear()

	end, err := findEndMarker(r)
	if err != nil {
		t.Fatalf("findEndMarker (after clear): %v", err)
	}
	if got := r.Get(end); got != sunspec.EndMarker {
		t.Fatalf("end marker id after clear = %d, want %d", got, sunspec.EndMarker)
	}
	pristineEnd, _ := findEndMarker(pristine)
	if end != pristineEnd {
		t.Fatalf("end marker after clear is at %d, want the pristine map's %d", end, pristineEnd)
	}
	for addr, v := range want {
		if r.Get(addr) != v {
			t.Errorf("register %d = %d after clear, want the pristine %d", addr, r.Get(addr), v)
		}
	}
}

// TestModelSplicer_ReArmIsIdempotent inserts twice without an intervening
// Clear and requires only the SECOND splice to be present.
func TestModelSplicer_ReArmIsIdempotent(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	ms := NewModelSplicer(r)

	if err := ms.Insert(65000, 4); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	firstAt := ms.at
	if err := ms.Insert(65001, 6); err != nil {
		t.Fatalf("second Insert: %v", err)
	}

	// The first splice's address must now read as the SECOND model's header,
	// not a leftover, and there must be exactly one model chain from there
	// on (walking from firstAt must land on 65001, not 65000).
	if got := r.Get(firstAt); got != 65001 {
		t.Fatalf("register %d (should be the re-armed splice) = %d, want 65001", firstAt, got)
	}
	newEnd, err := findEndMarker(r)
	if err != nil {
		t.Fatalf("findEndMarker: %v", err)
	}
	if want := firstAt + 2 + 6; newEnd != want {
		t.Fatalf("end marker at %d, want %d — a stale first splice is still in the chain", newEnd, want)
	}

	ms.Clear()
	end, _ := findEndMarker(r)
	if end != firstAt {
		t.Fatalf("after Clear, end marker at %d, want the ORIGINAL pre-splice position %d", end, firstAt)
	}
}

// TestModelSplicer_ApplyInject_InsertAndClear drives ModelSplicer entirely
// through the POST /inject body shape modsim/main.go wires it to.
func TestModelSplicer_ApplyInject_InsertAndClear(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	ms := NewModelSplicer(r)

	handled, err := ms.ApplyInject([]byte(`{"insert_model":{"id":65000,"len":4}}`))
	if !handled || err != nil {
		t.Fatalf("insert via inject: handled=%v err=%v", handled, err)
	}
	if !ms.active {
		t.Fatal("splice not active after insert_model")
	}

	handled, err = ms.ApplyInject([]byte(`{"clear_insert_model":true}`))
	if !handled || err != nil {
		t.Fatalf("clear via inject: handled=%v err=%v", handled, err)
	}
	if ms.active {
		t.Fatal("splice still active after clear_insert_model")
	}
}

// TestModelSplicer_ApplyInject_PassesThroughClassicBody pins "zero
// behaviour change when unused" at the /inject-body level.
func TestModelSplicer_ApplyInject_PassesThroughClassicBody(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	ms := NewModelSplicer(r)
	if handled, err := ms.ApplyInject([]byte(`{"W_W":4500.0}`)); handled || err != nil {
		t.Fatalf("classic body: handled=%v err=%v, want handled=false", handled, err)
	}
}

// TestModelSplicer_FindEndMarker_NoMarkerErrors proves an unpopulated map
// fails fast (bounded walk) rather than looping unboundedly — this
// package's own I8 discipline.
func TestModelSplicer_FindEndMarker_NoMarkerErrors(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)} // never populated: every Get returns 0
	if _, err := findEndMarker(r); err == nil {
		t.Fatal("an unpopulated map must not find an end marker")
	}
}
