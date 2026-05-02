// Package bridge is the translation layer between the northbound CSIP scheduler
// and the southbound device registry. It is the only package that knows about
// both sides — all other packages are protocol-agnostic.
//
// On each control tick the bridge:
//  1. Evaluates the scheduler against the current programs and server time
//  2. Applies the resulting DERControlBase to every device in the registry
//
// On each measurement tick the registry's poll loop emits MeasurementUpdates;
// callers can subscribe to those via Registry.Subscribe() to drive the
// northbound MUP POST flow.
//
// Typical lifecycle:
//
//	b := bridge.New(sched, reg, 30*time.Second)
//	b.Start()
//	defer b.Stop()
//	// ... northbound discovery loop updates programs via b.SetPrograms(...)
package bridge

import (
	"log"
	"sync"
	"time"

	"csip-tls-test/internal/csip/discovery"
	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/csip/scheduler"
	"csip-tls-test/internal/southbound/registry"
)

// Bridge connects the CSIP event scheduler to the southbound device registry.
type Bridge struct {
	sched    *scheduler.Scheduler
	reg      *registry.Registry
	interval time.Duration

	mu          sync.RWMutex
	programs    []discovery.ProgramState
	clockOffset int64 // server_time = time.Now().Unix() + clockOffset

	stop chan struct{}
	done chan struct{}
}

// New creates a Bridge. interval is how often the scheduler is evaluated and
// controls are pushed to devices. A value of 30s is appropriate for most CSIP
// implementations (the spec recommends re-evaluating at least once per minute).
func New(sched *scheduler.Scheduler, reg *registry.Registry, interval time.Duration) *Bridge {
	return &Bridge{
		sched:    sched,
		reg:      reg,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// SetPrograms updates the program list used for scheduler evaluation.
// Call this from the northbound discovery loop whenever programs change.
// Safe for concurrent use.
func (b *Bridge) SetPrograms(programs []discovery.ProgramState, clockOffset int64) {
	b.mu.Lock()
	b.programs = programs
	b.clockOffset = clockOffset
	b.mu.Unlock()
}

// Start launches the control loop goroutine. Pair with Stop.
func (b *Bridge) Start() {
	go b.run()
}

// Stop signals the control loop to exit and waits for it to finish.
func (b *Bridge) Stop() {
	close(b.stop)
	<-b.done
}

func (b *Bridge) run() {
	defer close(b.done)

	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()

	// Apply once immediately on start so devices get their first control
	// without waiting a full interval.
	b.applyOnce()

	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			b.applyOnce()
		}
	}
}

func (b *Bridge) applyOnce() {
	b.mu.RLock()
	programs := b.programs
	clockOffset := b.clockOffset
	b.mu.RUnlock()

	if len(programs) == 0 {
		return // no programs yet — northbound hasn't walked the tree
	}

	serverNow := scheduler.ServerNow(clockOffset)
	active := b.sched.Evaluate(programs, serverNow)
	if active == nil {
		// Programs exist but no event or default is active — apply failsafe.
		// Reconnect all devices (safe state: grid-connected, no power limit).
		t := true
		failsafe := model.DERControlBase{OpModConnect: &t}
		if err := b.reg.ApplyControl(failsafe); err != nil {
			log.Printf("bridge: apply failsafe: %v", err)
		}
		log.Printf("bridge: failsafe applied — programs present but no active control")
		return
	}

	if err := b.reg.ApplyControl(active.Base); err != nil {
		log.Printf("bridge: apply control (source=%s mrid=%s): %v", active.Source, active.MRID, err)
	}
}
