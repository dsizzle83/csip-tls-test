package main

import "testing"

func TestParseFaultSpec(t *testing.T) {
	spec, err := parseFaultSpec([]byte(`{"kind":"drop_session"}`))
	if err != nil {
		t.Fatalf("parseFaultSpec: %v", err)
	}
	if spec.Kind != faultDropSession || spec.Clear {
		t.Errorf("spec = %+v, want Kind=%q Clear=false", spec, faultDropSession)
	}

	if _, err := parseFaultSpec([]byte(`not json`)); err == nil {
		t.Errorf("parseFaultSpec(malformed json) = nil error, want an error (audit MOD-4: reject, don't wrap)")
	}
	if _, err := parseFaultSpec([]byte(`{}`)); err == nil {
		t.Errorf("parseFaultSpec(missing kind) = nil error, want an error")
	}
}

func TestMbapsFaultsArmClear(t *testing.T) {
	var f mbapsFaults

	for _, kind := range []string{faultDropSession, faultRefuseResume, faultStallHandshake} {
		handled, err := f.apply(faultSpec{Kind: kind})
		if !handled {
			t.Fatalf("apply(%q) handled=false, want true", kind)
		}
		if err != nil {
			t.Fatalf("apply(%q) arm: %v", kind, err)
		}
	}
	if !f.dropArmed() {
		t.Errorf("drop_session not armed")
	}
	if !f.refuseResumeArmed() {
		t.Errorf("refuse_resume not armed")
	}
	armed, delay := f.stallInfo()
	if !armed {
		t.Errorf("stall_handshake not armed")
	}
	if delay != defaultStallDelay {
		t.Errorf("stall delay = %v, want default %v (no delay_s given)", delay, defaultStallDelay)
	}

	snap := f.snapshot()
	if !snap.DropSession || !snap.RefuseResume || !snap.StallHandshake {
		t.Errorf("snapshot = %+v, want all three armed", snap)
	}

	// Clear each and verify.
	for _, kind := range []string{faultDropSession, faultRefuseResume, faultStallHandshake} {
		if _, err := f.apply(faultSpec{Kind: kind, Clear: true}); err != nil {
			t.Fatalf("apply(%q) clear: %v", kind, err)
		}
	}
	if f.dropArmed() || f.refuseResumeArmed() {
		t.Errorf("faults still armed after clear")
	}
	if armed, _ := f.stallInfo(); armed {
		t.Errorf("stall_handshake still armed after clear")
	}
}

func TestMbapsFaultsStallCustomDelay(t *testing.T) {
	var f mbapsFaults
	if _, err := f.apply(faultSpec{Kind: faultStallHandshake, DelayS: 2.5}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	_, delay := f.stallInfo()
	if delay.Seconds() != 2.5 {
		t.Errorf("stall delay = %v, want 2.5s", delay)
	}
}

func TestMbapsFaultsUnhandledKindDelegates(t *testing.T) {
	var f mbapsFaults
	handled, err := f.apply(faultSpec{Kind: "reject_write"})
	if handled {
		t.Errorf("apply(%q) handled=true, want false (must delegate to the underlying model)", "reject_write")
	}
	if err != nil {
		t.Errorf("apply(%q) err = %v, want nil (handled=false means the caller decides)", "reject_write", err)
	}
}

func TestMbapsFaultsTCPDropRejected(t *testing.T) {
	var f mbapsFaults
	handled, err := f.apply(faultSpec{Kind: faultTCPDrop})
	if !handled {
		t.Fatalf("apply(tcp_drop) handled=false, want true (must be intercepted, not delegated)")
	}
	if err == nil {
		t.Errorf("apply(tcp_drop) err = nil, want a rejection explaining to use drop_session instead")
	}
}
