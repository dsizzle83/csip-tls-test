package main

// reset.go — POST /reset for mbapsdev (WP7-T6, REV0907-E6;
// QAGAMUT2-001-SIMULATOR-STATE-NOT-RESET-BETWEEN-RUNS).
//
// modsim (sim/modsim/reset.go) has carried a baseline-restore endpoint since
// LAB29-010; this device sim never grew one. certify's gating preflight
// (internal/certify/preflight.go's preflightSimReset) resets EVERY southbound
// sim it is configured against before a gating campaign's first case, and a
// sim that answers 501 makes the reset unprovable — the same posture an
// unpaired -gridsim/-gridsim-admin takes (REV0907-E3). Without this, a
// gating campaign against the mbaps leg had no tool-enforced way to start
// from a known device: whatever the previous run (or a manual poke through
// the dashboard) left armed or injected carried straight into the next
// campaign's first row.
//
// The binding lives in the binary rather than in simapi or sim/southbound for
// the reason modsim's own reset.go gives: simapi stays out of every body's
// schema, sim/southbound knows nothing about an HTTP API version, and the
// binary is the one place that legitimately knows both.

import (
	"fmt"

	"csip-tls-test/sim/simapi"
	sim "csip-tls-test/sim/southbound"
)

// resetSpec is POST /reset's body — modsim's own shape, minus PollAnchor:
// mbapsdev serves every mbaps request by calling RegisterMap.
// HandleHoldingRegisters directly (dispatch.go's doc comment) rather than
// through a wire tap, so it has no poll-cycle accounting to declare.
type resetSpec struct {
	// Baseline names the register image to restore. Empty means the as-built
	// image captured at startup.
	Baseline string `json:"baseline,omitempty"`
}

// resetResult is what POST /reset reports back, inside the acknowledgement's
// `result` field — the epoch itself is the acknowledgement's own.
type resetResult struct {
	// Baseline is the image that was restored.
	Baseline string `json:"baseline"`
	// Cleared names, in the order they ran, the fault layers this reset put
	// back — reported, not assumed, for the reason modsim's applyReset gives:
	// "nothing is armed" is a claim a row relies on.
	Cleared []string `json:"cleared"`
	// Baselines lists every image this sim holds.
	Baselines []string `json:"baselines"`
}

// applyReset restores a baseline and reports what it did.
func applyReset(body []byte, baselines *sim.BaselineStore) (any, error) {
	var spec resetSpec
	if err := simapi.DecodeBody(body, &spec); err != nil {
		return nil, fmt.Errorf("reset: %w", err)
	}
	name := spec.Baseline
	if name == "" {
		name = sim.BaselineName
	}
	cleared, err := baselines.Restore(name)
	if err != nil {
		return nil, err
	}
	return resetResult{Baseline: name, Cleared: cleared, Baselines: baselines.Names()}, nil
}

// wireDeterministic registers the epoch counter and the baseline reset — the
// two endpoints that turn mbapsdev into a fixture a gating preflight can
// prove it restored, mirroring modsim's own wireDeterministic (minus the
// ledger/poll pair modsim's wire tap answers and this device has no
// equivalent of).
//
// clearFaults is mb.clearFaults from main.go's modelBundle — nil on the
// battery model, which declares no fault-clear surface yet (modelBundle's own
// doc) — and faultsClear is d.faults.clear, the mbaps-transport layer every
// model carries regardless of which underlying SunSpec model it wraps.
func wireDeterministic(api *simapi.Server, epoch *sim.Epoch, baselines *sim.BaselineStore) {
	api.SetEpochFn(epoch.Next)
	api.SetResetFn(func(body []byte) (any, error) {
		return applyReset(body, baselines)
	})
}
