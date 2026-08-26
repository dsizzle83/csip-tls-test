package sim

import "testing"

// TestSentinelInjector_EachType table-drives every fixed-width datatype
// verb 6 was scoped to and checks the EXACT SunSpec not-implemented bit
// pattern lands.
func TestSentinelInjector_EachType(t *testing.T) {
	cases := []struct {
		typ  string
		want []uint16
	}{
		{"int16", []uint16{0x8000}},
		{"uint16", []uint16{0xFFFF}},
		{"enum16", []uint16{0xFFFF}},
		{"int32", []uint16{0x8000, 0x0000}},
		{"uint32", []uint16{0xFFFF, 0xFFFF}},
		{"acc32", []uint16{0x0000, 0x0000}},
		{"bitfield32", []uint16{0xFFFF, 0xFFFF}},
	}
	for _, tc := range cases {
		r := &RegisterMap{regs: make(map[uint16]uint16)}
		for i := range tc.want {
			r.Set(40190+uint16(i), 0x1234) // seed a non-sentinel value so the write is observable
		}
		si := NewSentinelInjector(r)
		if err := si.Seed(40190, tc.typ, 0); err != nil {
			t.Fatalf("%s: Seed: %v", tc.typ, err)
		}
		for i, want := range tc.want {
			if got := r.Get(40190 + uint16(i)); got != want {
				t.Errorf("%s: register %d = %#04x, want %#04x", tc.typ, 40190+i, got, want)
			}
		}
	}
}

// TestSentinelInjector_StringType seeds Len registers of all-zero (a
// leading NUL — an empty string).
func TestSentinelInjector_StringType(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	for i := uint16(0); i < 3; i++ {
		r.Set(40200+i, 0xABCD)
	}
	si := NewSentinelInjector(r)
	if err := si.Seed(40200, "string", 3); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	for i := uint16(0); i < 3; i++ {
		if got := r.Get(40200 + i); got != 0 {
			t.Errorf("register %d = %#04x, want 0 (string not-implemented)", 40200+i, got)
		}
	}
}

// TestSentinelInjector_UnknownType errors and leaves the register untouched.
//
// The type named here is not a SunSpec datatype at all. Every datatype the
// Information Model defines IS now seedable (LAB29-010 widened the table from
// the eight the verb originally shipped with to the whole set), so a test that
// pinned "this real type is out of scope" would now be pinning the gap rather
// than the refusal.
func TestSentinelInjector_UnknownType(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40300, 42)
	si := NewSentinelInjector(r)
	if err := si.Seed(40300, "decimal128", 0); err == nil {
		t.Fatal("a type that is not in the SunSpec Information Model must error")
	}
	if got := r.Get(40300); got != 42 {
		t.Fatalf("register 40300 = %d after a rejected Seed, want the untouched 42", got)
	}
}

// TestSentinelInjector_EveryDatatype seeds one point of EVERY datatype the
// table knows and reads each back, which is the capability §2.7.2 INFO-2 step
// 2 turns on: "for all the data types present in the PICS models, update
// Server 1 to configure at least one of these points to the unimplemented
// value". Before LAB29-010 only eight of the twenty-two were expressible, and
// INFO-2 could demonstrate exactly one.
func TestSentinelInjector_EveryDatatype(t *testing.T) {
	types := SentinelTypes()
	if len(types) < 20 {
		t.Fatalf("SentinelTypes returned %d datatypes (%v) — the Information Model's list is longer, "+
			"and INFO-2 needs every one of them", len(types), types)
	}
	// Every datatype the catalog's own precondition list for CLI-1 enumerates
	// must be seedable, quoted here so a future narrowing of the table fails
	// this test rather than quietly re-opening INFO-2's gap.
	want := []string{
		"int16", "uint16", "count", "acc16", "enum16", "bitfield16", "pad",
		"int32", "uint32", "acc32", "enum32", "bitfield32", "ipaddr",
		"int64", "uint64", "acc64", "ipv6addr", "float32", "float64",
		"string", "sunssf", "eui48",
	}
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	si := NewSentinelInjector(r)
	addr := uint16(41000)
	for _, typ := range want {
		words, ok := SentinelWordsFor(typ, 0)
		if !ok {
			t.Fatalf("datatype %q has no not-implemented sentinel; INFO-2 cannot seed it", typ)
		}
		// Pre-fill with a value no sentinel uses, so "the seed landed" cannot
		// be confused with "the register was already zero".
		for i := range words {
			r.Set(addr+uint16(i), 0x1234)
		}
		if err := si.Seed(addr, typ, 0); err != nil {
			t.Fatalf("Seed(%q): %v", typ, err)
		}
		for i, w := range words {
			if got := r.Get(addr + uint16(i)); got != w {
				t.Errorf("%s: register %d = %#04x, want %#04x", typ, addr+uint16(i), got, w)
			}
		}
		addr += uint16(len(words)) + 1
	}
	si.Clear()
	for a := uint16(41000); a < addr; a++ {
		if got := r.Get(a); got != 0x1234 && got != 0 {
			t.Errorf("register %d = %#04x after Clear, want the pre-seed 0x1234", a, got)
		}
	}
}

// TestSentinelWordsFor_VariableWidth pins the two datatypes whose width their
// point's declaration fixes rather than their type.
func TestSentinelWordsFor_VariableWidth(t *testing.T) {
	if w, _ := SentinelWordsFor("string", 0); len(w) != 1 {
		t.Errorf("string with no declared length = %d register(s), want 1 (a leading NUL)", len(w))
	}
	if w, _ := SentinelWordsFor("string", 8); len(w) != 8 {
		t.Errorf("string len=8 = %d register(s), want 8", len(w))
	}
	if w, _ := SentinelWordsFor("ipv6addr", 0); len(w) != 8 {
		t.Errorf("ipv6addr = %d register(s), want 8 (128 bits)", len(w))
	}
	if _, ok := SentinelWordsFor("nope", 0); ok {
		t.Error("an unknown datatype must not resolve to a sentinel")
	}
}

// TestSentinelInjector_ClearRestoresPriorValue proves Clear undoes a Seed
// exactly.
func TestSentinelInjector_ClearRestoresPriorValue(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40190, 777)
	si := NewSentinelInjector(r)
	if err := si.Seed(40190, "int16", 0); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if got := r.Get(40190); got != 0x8000 {
		t.Fatalf("register 40190 = %#04x after Seed, want 0x8000", got)
	}
	si.Clear()
	if got := r.Get(40190); got != 777 {
		t.Fatalf("register 40190 = %d after Clear, want the original 777", got)
	}
}

// TestSentinelInjector_ReArmIsIdempotent seeds the SAME address twice with
// DIFFERENT types and requires Clear to restore the address's TRUE original
// value, not the first sentinel it happened to pass through.
func TestSentinelInjector_ReArmIsIdempotent(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40190, 555)
	si := NewSentinelInjector(r)

	if err := si.Seed(40190, "int16", 0); err != nil {
		t.Fatalf("first Seed: %v", err)
	}
	if err := si.Seed(40190, "uint16", 0); err != nil {
		t.Fatalf("second Seed: %v", err)
	}
	if got := r.Get(40190); got != 0xFFFF {
		t.Fatalf("register 40190 = %#04x after re-arm, want the SECOND sentinel 0xFFFF", got)
	}
	si.Clear()
	if got := r.Get(40190); got != 555 {
		t.Fatalf("register 40190 = %d after Clear, want the TRUE original 555 (not an intermediate sentinel)", got)
	}
}

// TestSentinelInjector_ApplyInject_ClaimsUnimplementedKey drives
// SentinelInjector through the POST /inject body shape from the census
// report's own worked example.
func TestSentinelInjector_ApplyInject_ClaimsUnimplementedKey(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40190, 111)
	si := NewSentinelInjector(r)

	handled, err := si.ApplyInject([]byte(`{"unimplemented":[{"addr":40190,"type":"int16"}]}`))
	if !handled || err != nil {
		t.Fatalf("inject: handled=%v err=%v", handled, err)
	}
	if got := r.Get(40190); got != 0x8000 {
		t.Fatalf("register 40190 = %#04x, want 0x8000", got)
	}
}

// TestSentinelInjector_ApplyInject_PassesThroughClassicBody pins "zero
// behaviour change when unused" at the /inject-body level.
func TestSentinelInjector_ApplyInject_PassesThroughClassicBody(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	si := NewSentinelInjector(r)
	if handled, err := si.ApplyInject([]byte(`{"W_W":4500.0}`)); handled || err != nil {
		t.Fatalf("classic body: handled=%v err=%v, want handled=false", handled, err)
	}
}

// TestSentinelInjector_ApplyInject_ClearUnimplemented round-trips through
// the JSON envelope's clear key.
func TestSentinelInjector_ApplyInject_ClearUnimplemented(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40190, 111)
	si := NewSentinelInjector(r)
	if _, err := si.ApplyInject([]byte(`{"unimplemented":[{"addr":40190,"type":"int16"}]}`)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	handled, err := si.ApplyInject([]byte(`{"clear_unimplemented":true}`))
	if !handled || err != nil {
		t.Fatalf("clear: handled=%v err=%v", handled, err)
	}
	if got := r.Get(40190); got != 111 {
		t.Fatalf("register 40190 = %d after clear_unimplemented, want the original 111", got)
	}
}
