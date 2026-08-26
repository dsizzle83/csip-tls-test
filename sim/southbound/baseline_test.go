package sim

// baseline_test.go pins what POST /reset promises: a device that is back where
// it started, with nothing armed, and an honest account of what was put back.

import (
	"testing"
)

func TestBaseline_RestoresTheCapturedImage(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(r, 5000)
	b := NewBaselineStore(r)
	b.Capture(BaselineName)

	before := r.Get(40070)
	r.Set(40070, 0xDEAD)
	r.Set(49999, 0xBEEF) // a register the baseline never held at all
	if _, err := b.Restore(BaselineName); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := r.Get(40070); got != before {
		t.Errorf("register 40070 = %#04x after a restore, want the captured %#04x", got, before)
	}
	if got := r.Get(49999); got != 0 {
		t.Errorf("register 49999 = %#04x after a restore; a register the baseline never held must not "+
			"survive one — the image is written back WHOLE, not merged", got)
	}
}

func TestBaseline_RunsClearHooksInOrderBeforeTheImage(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	r.Set(100, 1)
	b := NewBaselineStore(r)
	b.Capture(BaselineName)

	var order []string
	b.OnReset("first", func() {
		order = append(order, "first")
		// A layer that owns registers restores them AS IT CLEARS. If the image
		// were written back before the hooks ran, this would land on top of it.
		r.Set(100, 99)
	})
	b.OnReset("second", func() { order = append(order, "second") })

	ran, err := b.Restore(BaselineName)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("hooks ran %v, want [first second] in registration order", order)
	}
	if len(ran) != 2 || ran[0] != "first" {
		t.Fatalf("Restore reported %v, want the hook names it ran — 'nothing is armed' is a claim a row "+
			"relies on and must be visible rather than trusted", ran)
	}
	if got := r.Get(100); got != 1 {
		t.Fatalf("register 100 = %d; the hook's write survived the image restore, so the clear-up ran "+
			"in the wrong order", got)
	}
}

func TestBaseline_UnknownNameIsRefusedWithTheAlternatives(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := NewBaselineStore(r)
	b.Capture(BaselineName)
	b.Capture("relocated")

	_, err := b.Restore("nope")
	if err == nil {
		t.Fatal("an unknown baseline was accepted; a silent fall-back would leave a row measuring a " +
			"device it did not ask for and reporting the result as a product finding")
	}
	msg := err.Error()
	for _, want := range []string{BaselineName, "relocated"} {
		if !contains(msg, want) {
			t.Errorf("the refusal %q does not name the available baseline %q", msg, want)
		}
	}
	if names := b.Names(); len(names) != 2 || names[0] != BaselineName || names[1] != "relocated" {
		t.Errorf("Names() = %v, want the two captured images sorted", names)
	}
}

func TestBaseline_RestoreClearsServerPlumbingFlags(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := NewBaselineStore(r)
	b.Capture(BaselineName)

	r.mu.Lock()
	r.unitIDConfusion = true
	r.tearing = true
	r.protectedRejects = 7
	r.mu.Unlock()

	if _, err := b.Restore(BaselineName); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unitIDConfusion || r.tearing || r.protectedRejects != 0 {
		t.Fatalf("after a reset: unitIDConfusion=%v tearing=%v protectedRejects=%d — a reset must leave "+
			"no provocation standing", r.unitIDConfusion, r.tearing, r.protectedRejects)
	}
}

// TestFaultController_ClearAllLeavesWiringAlone: the addresses a sim's
// constructor configured describe the DEVICE, not a provocation, and a reset
// that forgot them would leave the sim unable to arm those faults again.
func TestFaultController_ClearAllLeavesWiringAlone(t *testing.T) {
	fc := &faultController{label: "solar"}
	fc.configureScale(40080)
	fc.configureGate(40230)
	fc.nanSentinel = true
	fc.latencyMs = 900
	fc.modbusException = true
	fc.badScale = true
	fc.gate = true
	fc.raiseAlarmBits = 0x40
	fc.lyingConnSt = true

	fc.ClearAll()

	if fc.nanSentinel || fc.latencyMs != 0 || fc.modbusException || fc.badScale || fc.gate ||
		fc.raiseAlarmBits != 0 || fc.lyingConnSt {
		t.Fatalf("ClearAll left a fault armed: %+v", fc)
	}
	if !fc.hasScale || fc.scaleAddr != 40080 || !fc.hasGate || fc.gateAddr != 40230 {
		t.Fatalf("ClearAll discarded construction-time wiring (scale %v/%d gate %v/%d); those describe "+
			"the device, not a provocation", fc.hasScale, fc.scaleAddr, fc.hasGate, fc.gateAddr)
	}
	if fc.label != "solar" {
		t.Errorf("ClearAll discarded the controller's label")
	}
}

// TestLieController_ClearAllKeepsItsCounters: the fired counters are the
// controller's record of what it DID, and a reset that erased them would erase
// evidence — the same reason the transaction ledger is not truncated either.
func TestLieController_ClearAllKeepsItsCounters(t *testing.T) {
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	lc := &lieController{}
	lc.configure("solar", r, 40230, 40070, 50, map[string]uint16{}, func() {}, func() error { return nil })
	lc.note(FaultRevertAfter)
	lc.freeze = true
	lc.frozen = map[uint16]uint16{1: 2}
	lc.holdMs = 500
	lc.excApplied = true

	lc.ClearAll()

	if lc.freeze || lc.frozen != nil || lc.holdMs != 0 || lc.excApplied {
		t.Fatalf("ClearAll left a lie armed: freeze=%v frozen=%v holdMs=%d exc=%v",
			lc.freeze, lc.frozen, lc.holdMs, lc.excApplied)
	}
	if lc.Stats().Fired[string(FaultRevertAfter)] != 1 {
		t.Fatalf("ClearAll erased the fired counters; a reset must clear provocations, not evidence")
	}
	if lc.regs != r || lc.cmdAddr != 40230 {
		t.Error("ClearAll discarded construction-time wiring")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
