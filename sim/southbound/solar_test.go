package sim

import (
	"math"
	"testing"
	"time"

	"lexa-proto/sunspec"
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
		return r, populateSolar(r, wmax, "")
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
		solarStep(r, wmax, b, true /*paused*/, 0, 0 /*cloud*/, nil, &wh)
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
		solarStep(r, wmax, b, true, 0, 0, nil, &wh)
		if got := readW(r, b); got != 6000 {
			t.Errorf("paused output = %.0fW, want 6000W (uncurtailed)", got)
		}
	})

	t.Run("paused: curtailment above potential is a no-op", func(t *testing.T) {
		r, b := newRegs()
		injectPotential(r, b, 3000)
		curtailTo(r, b, 5000) // ceiling above potential
		var wh uint16
		solarStep(r, wmax, b, true, 0, 0, nil, &wh)
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
		solarStep(r, wmax, b, true, 0, 0, nil, &wh)
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
	b := populateSolar(r, wmax, "")
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
	solarStep(r, wmax, b, true, 0, 0, nil, &wh)
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
	solarStep(r, wmax, b, true, 0, 0, nil, &wh)
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

// TestCloudTransmittance pins the deterministic cloud-cover model's contract:
// cloud=0 is an exact no-op (so composing it into the irradiance model is
// byte-identical to the pre-cloud sim), cloud=1 is steady overcast at the
// diffuse floor with no transient, and partly-cloudy skies flicker with dips
// that stay bounded and downward-only. df/dipMax mirror cloudTransmittance's
// unexported constants — this test is their contract.
func TestCloudTransmittance(t *testing.T) {
	const df, dipMax = 0.15, 0.7

	// A spread of simTimes across (and beyond) the transient periods 23/37/51.
	times := []int64{0, 1, 7, 13, 23, 37, 51, 100, 251, 600, 997, 5000}

	t.Run("cloud=0 is exactly 1.0 for all t (byte-identical guarantee)", func(t *testing.T) {
		for _, st := range times {
			if got := cloudTransmittance(st, 0); got != 1.0 {
				t.Errorf("cloudTransmittance(%d,0)=%v, want exactly 1.0", st, got)
			}
		}
		// Negative cover clamps to clear as well.
		if got := cloudTransmittance(42, -0.5); got != 1.0 {
			t.Errorf("cloudTransmittance(42,-0.5)=%v, want 1.0 (clamped clear)", got)
		}
	})

	t.Run("cloud=1 is steady Tsus=DF for all t (no transient)", func(t *testing.T) {
		// Compute the reference with cloud as a float64 variable, exactly as
		// cloudTransmittance does — a literal `1 - 1*(1-df)` would be folded at
		// arbitrary precision and differ from the runtime float result by 1 ULP.
		cloud := 1.0
		wantTsus := 1 - cloud*(1-df) // == DF (the diffuse floor), within float rounding
		for _, st := range times {
			if got := cloudTransmittance(st, 1); got != wantTsus {
				t.Errorf("cloudTransmittance(%d,1)=%v, want %v (steady overcast)", st, got, wantTsus)
			}
		}
		if math.Abs(wantTsus-df) > 1e-12 {
			t.Errorf("Tsus at full overcast = %v, want %v (DF)", wantTsus, df)
		}
		// Over-unity cover clamps to overcast.
		if got := cloudTransmittance(42, 1.5); got != wantTsus {
			t.Errorf("cloudTransmittance(42,1.5)=%v, want %v (clamped overcast)", got, wantTsus)
		}
	})

	t.Run("transient is bounded, downward-only, within [Tsus*(1-DIPMAX), Tsus]", func(t *testing.T) {
		for _, cloud := range []float64{0.15, 0.3, 0.5, 0.7, 0.85} {
			tsus := 1 - cloud*(1-df)
			lo, hi := tsus*(1-dipMax), tsus
			for st := int64(0); st < 2000; st++ {
				got := cloudTransmittance(st, cloud)
				if got > hi+1e-9 {
					t.Fatalf("cloud=%.2f t=%d T=%v exceeds Tsus=%v (must be downward-only)", cloud, st, got, hi)
				}
				if got < lo-1e-9 {
					t.Fatalf("cloud=%.2f t=%d T=%v below guaranteed floor %v", cloud, st, got, lo)
				}
			}
		}
	})

	t.Run("sustained value at a transient-free instant equals Tsus", func(t *testing.T) {
		// At t=0 the three sinusoids are all 0, so gust=0 and T=Tsus exactly.
		for _, cloud := range []float64{0, 0.25, 0.6, 1} {
			want := 1 - cloud*(1-df)
			if got := cloudTransmittance(0, cloud); got != want {
				t.Errorf("cloudTransmittance(0,%.2f)=%v, want Tsus=%v", cloud, got, want)
			}
		}
	})

	t.Run("broken cloud produces real transient dips (model is not inert)", func(t *testing.T) {
		// At cloud=0.5 (peak broken weight) at least one instant in a long window
		// must pull T meaningfully below Tsus — otherwise the transient is dead.
		const cloud = 0.5
		tsus := 1 - cloud*(1-df)
		minT := tsus
		for st := int64(0); st < 5000; st++ {
			if got := cloudTransmittance(st, cloud); got < minT {
				minT = got
			}
		}
		if minT >= tsus-1e-6 {
			t.Errorf("no transient dip at cloud=0.5 (minT=%v, Tsus=%v) — model inert", minT, tsus)
		}
		if minT < tsus*(1-dipMax)-1e-9 {
			t.Errorf("transient dip %v below guaranteed floor %v", minT, tsus*(1-dipMax))
		}
	})
}

// TestSolarStep_CloudRunning pins the RUNNING-branch composition: cloud=0 leaves
// potW byte-identical to the clear-sky model, cloud>0 attenuates it downward,
// and the possible/actual invariants (WAval==potW, actual==min(potW,ceiling))
// hold so curtailment still clips actual below the cloud-reduced possible. The
// paused branch is covered (unchanged) by TestSolarStep_PausedAppliesCurtailment.
func TestSolarStep_CloudRunning(t *testing.T) {
	const wmax = 8000.0
	// irrClear replicates solarStep's clear-sky term verbatim (byte-for-byte, so
	// the cloud=0 comparison is exact).
	irrClear := func(tt float64) float64 {
		return math.Max(0.05, math.Min(0.95, 0.5+0.45*math.Sin(2*math.Pi*tt/600)))
	}
	newRegs := func() (*RegisterMap, SolarBases) {
		r := &RegisterMap{regs: make(map[uint16]uint16)}
		return r, populateSolar(r, wmax, "")
	}
	readReg := func(r *RegisterMap, addr uint16) float64 { return float64(int16(r.Get(addr))) }
	times := []float64{0, 37, 123, 200, 351, 500}

	t.Run("cloud=0 running potW is byte-identical to clear-sky", func(t *testing.T) {
		for _, st := range times {
			r, b := newRegs()
			var wh uint16
			solarStep(r, wmax, b, false /*running*/, st, 0 /*cloud*/, nil, &wh)
			want := math.Round(wmax * irrClear(st))
			if got := readReg(r, b.M122Base+sunspec.M122_WAval); got != want {
				t.Errorf("t=%.0f cloud=0 WAval=%.0f, want %.0f (clear-sky potW)", st, got, want)
			}
		}
	})

	t.Run("cloud attenuates potW; WAval==potW and actual==possible (uncurtailed)", func(t *testing.T) {
		for _, cloud := range []float64{0.3, 0.5, 1.0} {
			for _, st := range times {
				r, b := newRegs()
				var wh uint16
				solarStep(r, wmax, b, false, st, cloud, nil, &wh)
				wantPot := math.Round(wmax * irrClear(st) * cloudTransmittance(int64(st), cloud))
				wav := readReg(r, b.M122Base+sunspec.M122_WAval)
				if wav != wantPot {
					t.Errorf("cloud=%.1f t=%.0f WAval=%.0f, want %.0f (cloud-reduced potW)", cloud, st, wav, wantPot)
				}
				// Default ceiling is 100% ⇒ uncurtailed, so actual == round(potW) == WAval.
				if act := readReg(r, b.M103Base+sunspec.M103_W); act != wav {
					t.Errorf("cloud=%.1f t=%.0f actual=%.0f, want %.0f (==possible, uncurtailed)", cloud, st, act, wav)
				}
				// Cloud is downward-only: never above the clear-sky potential.
				if clear := math.Round(wmax * irrClear(st)); wav > clear {
					t.Errorf("cloud=%.1f t=%.0f WAval=%.0f exceeds clear-sky %.0f", cloud, st, wav, clear)
				}
			}
		}
	})

	t.Run("curtailment still clips actual below the cloud-reduced possible", func(t *testing.T) {
		// Heavy overcast at t=0 (irr=0.5): potW ≈ 600W at cloud=1; a 300W cap must
		// clip actual to 300 while possible stays at the (higher) cloud-reduced potW.
		r, b := newRegs()
		pct := 300.0 / wmax * 100.0 // percent-of-nameplate, as the modbus bridge writes
		r.Set(b.M123Base+sunspec.M123_WMaxLimPct, sunspec.RawFromScaleSigned(pct, -2))
		r.Set(b.M123Base+sunspec.M123_WMaxLimPct_Ena, 1)
		var wh uint16
		solarStep(r, wmax, b, false, 0, 1.0, nil, &wh)
		wav := readReg(r, b.M122Base+sunspec.M122_WAval)
		act := readReg(r, b.M103Base+sunspec.M103_W)
		if act != 300 {
			t.Errorf("curtailed actual=%.0f, want 300", act)
		}
		if wav <= act {
			t.Errorf("possible=%.0f must exceed curtailed actual=%.0f", wav, act)
		}
	})
}

// TestSolarServer_CloudInject exercises the Cloud_pct inject key, the SetCloud/
// Cloud [0,1] clamp, and the Snapshot Cloud_pct surface the dashboard reads.
func TestSolarServer_CloudInject(t *testing.T) {
	const wmax = 5000.0
	r := &RegisterMap{regs: make(map[uint16]uint16)}
	b := populateSolar(r, wmax, "")
	ss := &SolarServer{Server: &Server{Regs: r}, bases: b, wmaxW: wmax}

	if ss.Cloud() != 0 {
		t.Fatalf("fresh Cloud()=%v, want 0 (clear default)", ss.Cloud())
	}
	if st := ss.Snapshot(); st.Measurements.Cloud_pct != 0 {
		t.Errorf("fresh snapshot Cloud_pct=%v, want 0", st.Measurements.Cloud_pct)
	}

	if err := ss.Inject([]byte(`{"Cloud_pct":70}`)); err != nil {
		t.Fatalf("inject Cloud_pct: %v", err)
	}
	if math.Abs(ss.Cloud()-0.7) > 1e-9 {
		t.Errorf("after inject 70%%, Cloud()=%v, want 0.7", ss.Cloud())
	}
	if st := ss.Snapshot(); math.Abs(st.Measurements.Cloud_pct-70) > 1e-9 {
		t.Errorf("snapshot Cloud_pct=%v, want 70", st.Measurements.Cloud_pct)
	}
	// Cloud_pct is environmental, not a register; an unknown key still errors.
	if err := ss.Inject([]byte(`{"bogus":1}`)); err == nil {
		t.Error("unknown inject key should error")
	}

	// Clamp: over-unity and negative saturate to [0,1].
	ss.SetCloud(1.5)
	if ss.Cloud() != 1 {
		t.Errorf("SetCloud(1.5) → Cloud()=%v, want 1 (clamped)", ss.Cloud())
	}
	ss.SetCloud(-0.3)
	if ss.Cloud() != 0 {
		t.Errorf("SetCloud(-0.3) → Cloud()=%v, want 0 (clamped)", ss.Cloud())
	}
	if err := ss.Inject([]byte(`{"Cloud_pct":150}`)); err != nil {
		t.Fatalf("inject Cloud_pct 150: %v", err)
	}
	if ss.Cloud() != 1 {
		t.Errorf("inject 150%% → Cloud()=%v, want 1 (clamped)", ss.Cloud())
	}
}
