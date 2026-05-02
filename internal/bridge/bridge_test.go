package bridge_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"csip-tls-test/internal/bridge"
	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/csip/scheduler"
	"csip-tls-test/internal/southbound/device"
	"csip-tls-test/internal/southbound/registry"
)

// ── Mock device ───────────────────────────────────────────────────────────────

type mockDevice struct {
	mu           sync.Mutex
	applyCalls   int
	appliedCtrls []model.DERControlBase
	applyErr     error
}

func (m *mockDevice) ReadMeasurements() (device.Measurements, error) {
	return device.Measurements{}, nil
}
func (m *mockDevice) Status() (device.DeviceStatus, error) {
	return device.DeviceStatus{Connected: true, Energized: true}, nil
}
func (m *mockDevice) ApplyControl(ctrl model.DERControlBase) error {
	m.mu.Lock()
	m.applyCalls++
	m.appliedCtrls = append(m.appliedCtrls, ctrl)
	err := m.applyErr
	m.mu.Unlock()
	return err
}
func (m *mockDevice) Close() error { return nil }

func (m *mockDevice) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyCalls
}

func (m *mockDevice) lastCtrl() model.DERControlBase {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.appliedCtrls) == 0 {
		return model.DERControlBase{}
	}
	return m.appliedCtrls[len(m.appliedCtrls)-1]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// newBridge creates a Bridge with a single mock device for testing.
func newBridge(interval time.Duration) (*bridge.Bridge, *mockDevice) {
	d := &mockDevice{}
	reg := registry.New(10 * time.Second) // long poll — we don't care about measurements here
	reg.Add(&registry.Entry{Name: "test", Device: d})
	sched := scheduler.New()
	b := bridge.New(sched, reg, interval)
	return b, d
}

// activeProgram returns a ProgramState with a DefaultDERControl that is
// currently active (no time-bounded events — just the default).
func activeProgram(primacy uint8, connect bool) discovery.ProgramState {
	return discovery.ProgramState{
		Program: model.DERProgram{
			MRID:    "prog-1",
			Primacy: primacy,
		},
		DefaultControl: &model.DefaultDERControl{
			MRID: "ddc-1",
			DERControlBase: model.DERControlBase{
				OpModConnect: &connect,
			},
		},
	}
}

// activeEvent returns a ProgramState with an event active at the current time.
func activeEventProgram(connect bool) discovery.ProgramState {
	now := time.Now().Unix()
	return discovery.ProgramState{
		Program: model.DERProgram{MRID: "prog-event", Primacy: 1},
		Controls: &model.DERControlList{
			DERControl: []model.DERControl{
				{
					MRID:         "ctrl-1",
					CreationTime: now - 100,
					Interval: model.DateTimeInterval{
						Start:    now - 60,
						Duration: 3600,
					},
					DERControlBase: model.DERControlBase{
						OpModConnect: &connect,
					},
				},
			},
		},
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestBridge_NoPrograms_NoApply verifies that applyOnce is a no-op when no
// programs have been set (northbound hasn't walked the tree yet).
func TestBridge_NoPrograms_NoApply(t *testing.T) {
	b, d := newBridge(10 * time.Second)
	b.Start()
	time.Sleep(30 * time.Millisecond) // let applyOnce fire once on start
	b.Stop()

	if d.callCount() != 0 {
		t.Errorf("ApplyControl called %d times with no programs, want 0", d.callCount())
	}
}

// TestBridge_AppliesDefaultControl verifies that when a program with a
// DefaultDERControl is set, the bridge applies it on the first tick.
func TestBridge_AppliesDefaultControl(t *testing.T) {
	b, d := newBridge(10 * time.Second) // long interval — only the immediate applyOnce fires

	tr := true
	b.SetPrograms([]discovery.ProgramState{activeProgram(1, tr)}, 0)

	b.Start()
	defer b.Stop()
	time.Sleep(30 * time.Millisecond)

	if d.callCount() < 1 {
		t.Fatal("expected at least 1 ApplyControl call after SetPrograms")
	}
	if d.lastCtrl().OpModConnect == nil || *d.lastCtrl().OpModConnect != true {
		t.Errorf("OpModConnect = %v, want true", d.lastCtrl().OpModConnect)
	}
}

// TestBridge_AppliesEventControl verifies that a currently-active DERControl
// event is applied in preference to the default.
func TestBridge_AppliesEventControl(t *testing.T) {
	b, d := newBridge(10 * time.Second)

	f := false
	b.SetPrograms([]discovery.ProgramState{activeEventProgram(f)}, 0)

	b.Start()
	defer b.Stop()
	time.Sleep(30 * time.Millisecond)

	if d.callCount() < 1 {
		t.Fatal("expected at least 1 ApplyControl call for active event")
	}
	if d.lastCtrl().OpModConnect == nil || *d.lastCtrl().OpModConnect != false {
		t.Errorf("OpModConnect = %v, want false", d.lastCtrl().OpModConnect)
	}
}

// TestBridge_SetPrograms_UpdatesOnNextTick verifies that updating programs via
// SetPrograms is reflected on the subsequent tick.
func TestBridge_SetPrograms_UpdatesOnNextTick(t *testing.T) {
	const interval = 20 * time.Millisecond
	b, d := newBridge(interval)

	// Start with connect=false default.
	f := false
	b.SetPrograms([]discovery.ProgramState{activeProgram(1, f)}, 0)

	b.Start()
	defer b.Stop()
	time.Sleep(2 * interval) // let it fire at least once

	// Now switch to connect=true.
	tr := true
	b.SetPrograms([]discovery.ProgramState{activeProgram(1, tr)}, 0)
	time.Sleep(2 * interval) // wait for the next tick

	last := d.lastCtrl()
	if last.OpModConnect == nil || *last.OpModConnect != true {
		t.Errorf("after SetPrograms update, OpModConnect = %v, want true", last.OpModConnect)
	}
}

// TestBridge_TickFires verifies the ticker fires multiple times over a short
// run and that each tick calls ApplyControl.
func TestBridge_TickFires(t *testing.T) {
	const interval = 10 * time.Millisecond
	b, d := newBridge(interval)

	tr := true
	b.SetPrograms([]discovery.ProgramState{activeProgram(1, tr)}, 0)

	b.Start()
	time.Sleep(6 * interval) // expect ≥3 ticks: 1 immediate + ≥2 from ticker
	b.Stop()

	if d.callCount() < 3 {
		t.Errorf("expected ≥3 ApplyControl calls over 6 intervals, got %d", d.callCount())
	}
}

// TestBridge_Stop_DoesNotBlock verifies that Stop returns promptly.
func TestBridge_Stop_DoesNotBlock(t *testing.T) {
	b, _ := newBridge(1 * time.Second)
	b.Start()

	done := make(chan struct{})
	go func() {
		b.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked")
	}
}

// TestBridge_HighestPriorityProgram verifies that when two programs are set,
// the bridge applies the control from the highest-priority one (lowest primacy).
func TestBridge_HighestPriorityProgram(t *testing.T) {
	b, d := newBridge(10 * time.Second)

	tr := true
	f := false
	// primacy=1 → higher priority (connect=true should win)
	// primacy=10 → lower priority (connect=false should lose)
	b.SetPrograms([]discovery.ProgramState{
		activeProgram(10, f),
		activeProgram(1, tr),
	}, 0)

	b.Start()
	defer b.Stop()
	time.Sleep(30 * time.Millisecond)

	if d.callCount() < 1 {
		t.Fatal("no ApplyControl calls")
	}
	if d.lastCtrl().OpModConnect == nil || *d.lastCtrl().OpModConnect != true {
		t.Errorf("OpModConnect = %v; expected primacy-1 program (connect=true) to win", d.lastCtrl().OpModConnect)
	}
}

// TestBridge_ApplyOnce_ConcurrentSafe exercises concurrent SetPrograms and
// tick firing to check for data races (run with -race).
func TestBridge_ApplyOnce_ConcurrentSafe(t *testing.T) {
	const interval = 5 * time.Millisecond
	b, _ := newBridge(interval)

	b.Start()
	defer b.Stop()

	var wg sync.WaitGroup
	var count atomic.Int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v := i%2 == 0
			b.SetPrograms([]discovery.ProgramState{activeProgram(1, v)}, 0)
			count.Add(1)
		}(i)
	}
	wg.Wait()
	time.Sleep(3 * interval)
	// Just verify no race / panic. Final state doesn't matter.
	if count.Load() != 10 {
		t.Error("not all goroutines completed")
	}
}

// TestBridge_Failsafe_WhenNoActiveControl verifies that when programs exist
// but no event or default is active, the bridge applies a failsafe
// (OpModConnect=true) rather than silently doing nothing.
func TestBridge_Failsafe_WhenNoActiveControl(t *testing.T) {
	b, d := newBridge(10 * time.Second)

	// Program with no default and an expired event → scheduler returns nil.
	expiredEvt := model.DERControl{
		MRID:         "old",
		CreationTime: time.Now().Unix() - 10000,
		Interval: model.DateTimeInterval{
			Start:    time.Now().Unix() - 7200,
			Duration: 3600, // ended an hour ago
		},
	}
	b.SetPrograms([]discovery.ProgramState{
		{
			Program: model.DERProgram{MRID: "prog-no-default", Primacy: 1},
			Controls: &model.DERControlList{
				DERControl: []model.DERControl{expiredEvt},
			},
		},
	}, 0)

	b.Start()
	defer b.Stop()
	time.Sleep(30 * time.Millisecond)

	if d.callCount() < 1 {
		t.Fatal("expected failsafe ApplyControl call")
	}
	ctrl := d.lastCtrl()
	if ctrl.OpModConnect == nil || *ctrl.OpModConnect != true {
		t.Errorf("failsafe should set OpModConnect=true, got %v", ctrl.OpModConnect)
	}
}
