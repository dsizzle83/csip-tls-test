package sim

import (
	"testing"
	"time"

	"csip-tls-test/internal/southbound/sunspec"
)

// TestSolarStep_PausedAppliesCurtailment guards the bench-replay invariant: a
// PAUSED inverter (PV injected each tick, environment frozen) must still honour
// the hub's WMaxLimPct curtailment.  Before the fix the paused animation skipped
// every register update, so curtailment was inert during replays and export/gen
// caps registered as violations even when the hub commanded curtailment.
func TestSolarStep_PausedAppliesCurtailment(t *testing.T) {
	const wmax = 8000.0
	newRegs := func() (*RegisterMap, SolarBases) {
		r := &RegisterMap{regs: make(map[uint16]uint16)}
		return r, populateSolar(r, wmax)
	}
	// injectPotential mirrors Inject("W_W"): records the panel potential.
	injectPotential := func(r *RegisterMap, b SolarBases, w float64) {
		r.Set(b.M103Base+sunspec.M103_W, sunspec.RawFromScaleSigned(w, int16(r.Get(b.M103Base+sunspec.M103_W_SF))))
		r.Set(b.M122Base+sunspec.M122_WAval, uint16(int16(w)))
	}
	// curtailTo sets WMaxLimPct to limW as a percent of nameplate (SF -2),
	// matching how the modbus bridge writes the hub's curtailment command.
	curtailTo := func(r *RegisterMap, b SolarBases, limW float64) {
		pct := limW / wmax * 100.0
		r.Set(b.M123Base+sunspec.M123_WMaxLimPct, sunspec.RawFromScaleSigned(pct, -2))
		r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
	}
	readW := func(r *RegisterMap, b SolarBases) float64 {
		return float64(int16(r.Get(b.M103Base + sunspec.M103_W)))
	}

	t.Run("paused: curtailment clips held potential", func(t *testing.T) {
		r, b := newRegs()
		injectPotential(r, b, 6000)
		curtailTo(r, b, 2000) // hub caps generation at 2000W
		var wh uint16
		solarStep(r, wmax, b, true /*paused*/, 0, nil, &wh)
		if got := readW(r, b); got != 2000 {
			t.Errorf("paused output = %.0fW, want 2000W (curtailed)", got)
		}
	})

	t.Run("paused: no curtailment holds full potential", func(t *testing.T) {
		r, b := newRegs()
		injectPotential(r, b, 6000)
		// WMaxLimPct disabled (Ena=0) → no clip.
		r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 0)
		var wh uint16
		solarStep(r, wmax, b, true, 0, nil, &wh)
		if got := readW(r, b); got != 6000 {
			t.Errorf("paused output = %.0fW, want 6000W (uncurtailed)", got)
		}
	})

	t.Run("paused: curtailment above potential is a no-op", func(t *testing.T) {
		r, b := newRegs()
		injectPotential(r, b, 3000)
		curtailTo(r, b, 5000) // ceiling above potential
		var wh uint16
		solarStep(r, wmax, b, true, 0, nil, &wh)
		if got := readW(r, b); got != 3000 {
			t.Errorf("paused output = %.0fW, want 3000W (potential, ceiling higher)", got)
		}
	})

	t.Run("inject W_W writes the curtailed value, not raw potential", func(t *testing.T) {
		r, b := newRegs()
		ss := &SolarServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmax}
		curtailTo(r, b, 2000) // hub cap at 2000W active when PV is injected
		if err := ss.Inject([]byte(`{"W_W":6000}`)); err != nil {
			t.Fatalf("inject: %v", err)
		}
		// M103_W must already be clipped to the ceiling — no uncurtailed spike
		// for the linked meter to sample.
		if got := readW(r, b); got != 2000 {
			t.Errorf("after inject, M103_W = %.0fW, want 2000W (clipped to active cap)", got)
		}
		// WAval still records the full potential for the animation to clip later.
		if av := float64(int16(r.Get(b.M122Base + sunspec.M122_WAval))); av != 6000 {
			t.Errorf("WAval = %.0fW, want 6000W (panel potential)", av)
		}
	})

	t.Run("snapshot exposes potential, and actual never exceeds it", func(t *testing.T) {
		r, b := newRegs()
		ss := &SolarServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmax}
		curtailTo(r, b, 2000)
		if err := ss.Inject([]byte(`{"W_W":6000}`)); err != nil {
			t.Fatalf("inject: %v", err)
		}
		st := ss.Snapshot()
		if st.Measurements.Possible_W != 6000 {
			t.Errorf("Possible_W = %.0fW, want 6000W (panel potential)", st.Measurements.Possible_W)
		}
		if st.Measurements.W_W != 2000 {
			t.Errorf("W_W = %.0fW, want 2000W (curtailed actual)", st.Measurements.W_W)
		}
		// The replay curtailment column depends on this invariant holding.
		if st.Measurements.W_W > st.Measurements.Possible_W {
			t.Errorf("actual %.0fW > possible %.0fW — physically impossible", st.Measurements.W_W, st.Measurements.Possible_W)
		}
	})

	t.Run("paused: disconnect zeroes output", func(t *testing.T) {
		r, b := newRegs()
		injectPotential(r, b, 6000)
		r.Set(b.M123Base+sunspec.M123_Conn, 0)
		var wh uint16
		solarStep(r, wmax, b, true, 0, nil, &wh)
		if got := readW(r, b); got != 0 {
			t.Errorf("disconnected output = %.0fW, want 0W", got)
		}
	})
}

// TestSolarServer_AckBeforeEffectFault exercises the ack_before_effect injector:
// a curtailment write must be ACKed (the Modbus interceptor reports handled) but
// its effect on output deferred by delay_s, then converge once the delay elapses.
// This is the fixture for the QA scenario "hub assumes write-success == limit in
// force"; the hub should detect the lag via measurement, not trust the ACK.
func TestSolarServer_AckBeforeEffectFault(t *testing.T) {
	const wmax = 8000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateSolar(r, wmax)
	ss := &SolarServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmax}
	target := b.M123Base + sunspec.M123_WMaxLimPct
	readW := func() float64 { return float64(int16(r.Get(b.M103Base + sunspec.M103_W))) }

	if err := ss.ApplyFault([]byte(`{"kind":"ack_before_effect","delay_s":0.05}`)); err != nil {
		t.Fatalf("arm fault: %v", err)
	}

	// Hub commands 25% curtailment. With the fault armed the interceptor handles
	// the write itself (apply=false) and holds WMaxLimPct.
	curtailRaw := sunspec.RawFromScaleSigned(25, -2)
	if applied := ss.interceptWrite(target, []uint16{curtailRaw}); applied {
		t.Fatal("interceptWrite returned apply=true; ack-before-effect should defer the write")
	}
	if got := r.Get(target); got != 10000 {
		t.Fatalf("WMaxLimPct immediately after write = %d, want 10000 (effect deferred)", got)
	}

	// During the delay the inverter still produces at the OLD (100%) ceiling.
	r.Set(b.M122Base+sunspec.M122_WAval, uint16(int16(6000)))
	var wh uint16
	solarStep(r, wmax, b, true, 0, nil, &wh)
	if got := readW(); got != 6000 {
		t.Fatalf("output during delay = %.0fW, want 6000W (curtailment not yet in effect)", got)
	}

	// After the delay the deferred WMaxLimPct lands and output converges to 2000W.
	deadline := time.Now().Add(2 * time.Second)
	for r.Get(target) == 10000 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := r.Get(target); got != curtailRaw {
		t.Fatalf("WMaxLimPct after delay = %d, want %d (effect applied)", got, curtailRaw)
	}
	solarStep(r, wmax, b, true, 0, nil, &wh)
	if got := readW(); got != 2000 {
		t.Fatalf("output after delay = %.0fW, want 2000W (curtailed)", got)
	}

	// Cleared fault → writes pass through immediately again.
	if err := ss.ApplyFault([]byte(`{"kind":"ack_before_effect","clear":true}`)); err != nil {
		t.Fatalf("clear fault: %v", err)
	}
	if applied := ss.interceptWrite(target, []uint16{sunspec.RawFromScaleSigned(50, -2)}); !applied {
		t.Error("after clear, interceptWrite should pass through (apply=true)")
	}
	// Unknown kind is a 400-worthy error.
	if err := ss.ApplyFault([]byte(`{"kind":"bogus"}`)); err == nil {
		t.Error("unsupported fault kind should return an error")
	}
}
