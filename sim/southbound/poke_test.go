package sim

// poke_test.go pins the raw register lever the write rows use to diverge the
// exact cell the client owns.

import "testing"

func TestRegisterPoke_SetAndRestore(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40350, 10000)
	p := NewRegisterPoke(r)

	p.Set(40350, 5000)
	if got := r.Get(40350); got != 5000 {
		t.Fatalf("register 40350 = %d after a poke, want 5000", got)
	}
	// A SECOND poke of the same address must not overwrite the true original
	// with an already-poked value, or a row's teardown would restore the
	// divergence rather than the device.
	p.Set(40350, 1234)
	p.Clear()
	if got := r.Get(40350); got != 10000 {
		t.Fatalf("register 40350 = %d after Clear, want the pristine 10000", got)
	}
	if p.Touched() != 0 {
		t.Errorf("Touched() = %d after Clear, want 0", p.Touched())
	}
}

func TestRegisterPoke_InjectBody(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(40350, 10000)
	r.Set(40351, 1)
	p := NewRegisterPoke(r)

	handled, err := p.ApplyInject([]byte(`{"registers":[{"addr":40350,"value":5000},{"addr":40351,"delta":-1}]}`))
	if !handled || err != nil {
		t.Fatalf("ApplyInject: handled=%v err=%v", handled, err)
	}
	if got := r.Get(40350); got != 5000 {
		t.Errorf("value form: register 40350 = %d, want 5000", got)
	}
	if got := r.Get(40351); got != 0 {
		t.Errorf("delta form: register 40351 = %d, want 0", got)
	}

	handled, err = p.ApplyInject([]byte(`{"clear_registers":true}`))
	if !handled || err != nil {
		t.Fatalf("clear: handled=%v err=%v", handled, err)
	}
	if r.Get(40350) != 10000 || r.Get(40351) != 1 {
		t.Fatalf("clear_registers did not restore both addresses (%d, %d)", r.Get(40350), r.Get(40351))
	}
}

func TestRegisterPoke_LeavesOtherBodiesAlone(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	p := NewRegisterPoke(r)
	for _, body := range []string{
		`{"W_W":4500}`,
		`{"unimplemented":[{"addr":40190,"type":"int16"}]}`,
		`{}`,
		`not json at all`,
	} {
		if handled, _ := p.ApplyInject([]byte(body)); handled {
			t.Errorf("%s: the poke claimed a body it does not own; the classic field-override path "+
				"would never see it", body)
		}
	}
}

func TestRegisterPoke_RefusesAmbiguousOrImpossibleEntries(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	p := NewRegisterPoke(r)
	for _, body := range []string{
		`{"registers":[{"addr":1,"value":5,"delta":1}]}`,
		`{"registers":[{"addr":1}]}`,
		`{"registers":[{"addr":1,"value":70000}]}`,
		`{"registers":[{"addr":1,"value":-40000}]}`,
	} {
		handled, err := p.ApplyInject([]byte(body))
		if !handled {
			t.Errorf("%s: the poke must claim its own key even to refuse the body", body)
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted, want a refusal naming what is wrong", body)
		}
	}
}

// TestRegisterPoke_NegativeValuesAreSigned16: a caller diverging a signed
// control point (a watt setpoint, a signed percent) names the value it means,
// not its two's-complement spelling.
func TestRegisterPoke_NegativeValuesAreSigned16(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	p := NewRegisterPoke(r)
	if _, err := p.ApplyInject([]byte(`{"registers":[{"addr":7,"value":-1200}]}`)); err != nil {
		t.Fatalf("ApplyInject: %v", err)
	}
	if got := int16(r.Get(7)); got != -1200 {
		t.Fatalf("register 7 decodes to %d, want -1200", got)
	}
}
