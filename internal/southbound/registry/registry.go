// Package registry manages a set of southbound Device instances and runs a
// periodic measurement poll loop. Devices can be added and removed at runtime
// (hot-swap for testing; on production hardware, typically registered once at
// startup and held for the process lifetime).
//
// The registry exposes a channel of MeasurementUpdate values — the bridge layer
// consumes these to feed the northbound MUP POST flow.
package registry

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"csip-tls-test/internal/csip/model"
	"csip-tls-test/internal/southbound/device"
)

// Entry is a named device in the registry.
type Entry struct {
	Name   string        // human-readable label (e.g. "inverter-0")
	Addr   string        // Modbus URL used to connect (for logging)
	Device device.Device // the live device implementation
}

// MeasurementUpdate is emitted by the poll loop for each device on each poll.
type MeasurementUpdate struct {
	Name         string
	Measurements device.Measurements
	Err          error // non-nil if the read failed
}

// Registry holds a set of Device instances and polls them on a timer.
type Registry struct {
	mu      sync.RWMutex
	entries []*Entry

	updates chan MeasurementUpdate
	dropped atomic.Int64

	pollInterval time.Duration
	stop         chan struct{}
	done         chan struct{}
}

// New creates a Registry that polls each device every pollInterval.
// The returned Registry is not yet polling — call Start to begin.
func New(pollInterval time.Duration) *Registry {
	return &Registry{
		updates:      make(chan MeasurementUpdate, 64),
		pollInterval: pollInterval,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
}

// Add registers a device. Safe to call after Start.
func (reg *Registry) Add(e *Entry) {
	reg.mu.Lock()
	reg.entries = append(reg.entries, e)
	reg.mu.Unlock()
}

// Remove unregisters a device by name and calls Close on it. No-op if not found.
func (reg *Registry) Remove(name string) error {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	for i, e := range reg.entries {
		if e.Name == name {
			reg.entries = append(reg.entries[:i], reg.entries[i+1:]...)
			return e.Device.Close()
		}
	}
	return nil
}

// ApplyControlTo calls ApplyControl on the named device only.
// Returns an error if no device with that name is registered.
func (reg *Registry) ApplyControlTo(name string, ctrl model.DERControlBase) error {
	reg.mu.RLock()
	var target *Entry
	for _, e := range reg.entries {
		if e.Name == name {
			target = e
			break
		}
	}
	reg.mu.RUnlock()

	if target == nil {
		return fmt.Errorf("registry: device %q not found", name)
	}
	return target.Device.ApplyControl(ctrl)
}

// ApplyControl calls ApplyControl on every registered device, collecting errors.
// Partial failures are returned as a combined error string.
func (reg *Registry) ApplyControl(ctrl model.DERControlBase) error {
	reg.mu.RLock()
	entries := make([]*Entry, len(reg.entries))
	copy(entries, reg.entries)
	reg.mu.RUnlock()

	var errs []string
	for _, e := range entries {
		if err := e.Device.ApplyControl(ctrl); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", e.Name, err))
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("registry.ApplyControl: %v", errs)
	}
	return nil
}

// Updates returns the channel on which MeasurementUpdates are published.
// The channel is buffered (64); if the consumer is slow, old updates are
// dropped rather than blocking the poll loop.
func (reg *Registry) Updates() <-chan MeasurementUpdate {
	return reg.updates
}

// Start launches the background poll goroutine. Call Stop to shut it down.
func (reg *Registry) Start() {
	go reg.run()
}

// Stop signals the poll goroutine to exit and waits for it to finish.
// After Stop returns, no further updates will be sent.
func (reg *Registry) Stop() {
	close(reg.stop)
	<-reg.done
}

// run is the background poll goroutine.
func (reg *Registry) run() {
	defer close(reg.done)

	ticker := time.NewTicker(reg.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-reg.stop:
			return
		case <-ticker.C:
			reg.poll()
		}
	}
}

func (reg *Registry) poll() {
	reg.mu.RLock()
	entries := make([]*Entry, len(reg.entries))
	copy(entries, reg.entries)
	reg.mu.RUnlock()

	for _, e := range entries {
		m, err := e.Device.ReadMeasurements()
		upd := MeasurementUpdate{Name: e.Name, Measurements: m, Err: err}
		select {
		case reg.updates <- upd:
		default:
			n := reg.dropped.Add(1)
			if n == 1 || n%100 == 0 {
				log.Printf("registry: update channel full, dropped %d total (device=%s)", n, e.Name)
			}
		}
	}
}
