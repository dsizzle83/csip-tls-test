package sim

// epoch.go — THE SIM'S CONTROL-PLANE STATE VERSION.
//
// Every conformance row in the plain Modbus/TCP client suite has the same
// shape: make the server do something, wait for the client to meet it, then
// judge what crossed the wire. Until now the middle step was a `time.Sleep`
// and the last step was "grep the capture for anything that looks like it".
// Both are guesses. A sleep that is too short judges a window the provocation
// never reached; a sleep that is long enough to be safe is long enough to
// sweep in the NEXT row's traffic. Neither failure is visible in the verdict,
// which is the worst property a conformance tool can have.
//
// The epoch is the fence that removes the guess. It is a monotonically
// increasing integer that names WHEN, in the sim's own history of deliberate
// state changes, something happened:
//
//	POST /reset       → {"epoch": 7}         the baseline is in force AS OF 7
//	POST /fault  …    → {"epoch": 8}         the fault is armed AS OF 8
//	GET  /ledger?since_epoch=8               only transactions the fault could
//	                                         have touched
//
// A row can therefore say, and prove, "these are the transactions that
// happened while my provocation was in force" without owning a clock.
//
// # What moves it, and what deliberately does not
//
// The epoch counts DELIBERATE CONTROL-PLANE MUTATIONS: an accepted POST to
// /reset, /inject, /control or /fault. It is bumped by the simapi server after
// the handler returns success, so exactly one bump corresponds to exactly one
// request a test issued, whatever layers that request passed through inside
// the sim.
//
// The free-running animation does NOT move it. That is the whole design.
// A counter that also ticked with the irradiance model would advance several
// times a second on its own and could never be used as a fence: "everything
// since epoch 8" would mean "everything since some instant a moment ago",
// which is a clock wearing an integer's clothes. An epoch is a boundary
// between things the HARNESS did, and the animation is not one of them.
//
// # Why it is a separate type rather than an atomic in the server
//
// Two consumers need it and they live on opposite sides of the sim: the simapi
// server (which bumps it) and the wire tap (which stamps every ledger entry
// with the epoch in force at the moment the transaction arrived). Passing a
// *Epoch to both keeps simapi free of any dependency on this package — simapi
// takes a plain `func() uint64` — while leaving exactly one counter in the
// process. Two counters that had to be kept in step would be a bug waiting for
// a race detector.

import "sync/atomic"

// Epoch is the sim's control-plane state version. The zero value is not
// usable; construct with NewEpoch.
//
// Safe for concurrent use.
type Epoch struct {
	n atomic.Uint64
}

// NewEpoch returns an Epoch at 1.
//
// It starts at 1, not 0, so that a zero value read out of a JSON body that
// did not carry the field is distinguishable from a real epoch. A row that
// asks for "everything since epoch 0" gets everything, which is the right
// answer for a caller who did not fence; a row that fenced always holds a
// number ≥ 1.
func NewEpoch() *Epoch {
	e := &Epoch{}
	e.n.Store(1)
	return e
}

// Load returns the epoch currently in force.
func (e *Epoch) Load() uint64 {
	if e == nil {
		return 0
	}
	return e.n.Load()
}

// Next advances the epoch and returns the new value — the epoch AT WHICH the
// change the caller just made is in force.
//
// Returning the post-increment value (rather than the pre-increment one) is
// what makes `POST /fault` → `GET /ledger?since_epoch=<that>` mean "the
// transactions this fault could have touched, and no earlier one": the fault
// is in force from the returned epoch onward, and every transaction stamped
// with a lower epoch predates it.
func (e *Epoch) Next() uint64 {
	if e == nil {
		return 0
	}
	return e.n.Add(1)
}
