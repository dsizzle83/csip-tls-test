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
func TestSentinelInjector_UnknownType(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40300, 42)
	si := NewSentinelInjector(r)
	if err := si.Seed(40300, "float64", 0); err == nil {
		t.Fatal("an unscoped type (float64 was not in verb 6's scope) must error")
	}
	if got := r.Get(40300); got != 42 {
		t.Fatalf("register 40300 = %d after a rejected Seed, want the untouched 42", got)
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
