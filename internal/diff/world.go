package diff

// world.go is the hand-off from this package to internal/invariant.
//
// The differential's job is to CREATE conditions; the invariant's job is to
// decide whether they are safe. Those are different jobs and the strategy is
// explicit that they should stay different: "the invariants are the pass/fail
// authority; your layer creates the conditions"
// (docs/ADVERSARIAL_QA_STRATEGY.md §4.2). Concretely, when this package drives
// a control into a register bank and the resulting state has the device
// commanded past its own nameplate, the FAIL should come from I1 — which was
// written specifically to make that judgement, has its own teeth tests, and
// speaks the same units algebra — and not from a second opinion invented here.
//
// So this file does exactly one thing: it presents a [Device]'s register bank
// to the invariant harness as a DER source, and returns a World the invariants
// can be run against. It writes nothing, and the source it installs is
// read-only by construction — the harness's own rule is that a source is a
// witness, not an actor, and a differential that could write through its
// observation channel would be able to launder its own effects.

import (
	"context"
	"fmt"

	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// deviceSource presents a Device as an invariant.DERSource.
//
// It reads the bank directly rather than re-scanning over the transport,
// because the bank IS the device's state and a second scan would only re-derive
// what NewDevice already recorded. Both the chain (Models) and the block bases
// come from the device's own construction, so an assertion can cite an absolute
// holding-register number.
type deviceSource struct {
	dev *Device
}

// Name identifies the observation channel.
func (s deviceSource) Name() string { return "diff-device:" + s.dev.Spec.Name }

// Observe reads the whole register image the invariants need.
func (s deviceSource) Observe(ctx context.Context) (invariant.DERView, error) {
	v := invariant.DERView{
		Name:      s.dev.Spec.Name,
		Source:    s.Name(),
		Reachable: true,
		Unit: invariant.UnitView{
			Unit: 1,
			Regs: map[uint16][]uint16{},
			Base: map[uint16]uint16{},
		},
	}
	for _, m := range []uint16{
		sunspec.ModelDERMeasureAC,
		sunspec.ModelDERCapacity,
		sunspec.ModelDERCtlAC,
	} {
		regs, ok := s.dev.Model(m)
		if !ok {
			continue
		}
		v.Unit.Models = append(v.Unit.Models, m)
		v.Unit.Regs[m] = regs
		v.Unit.Base[m] = s.dev.Bases[m]
	}
	if len(v.Unit.Models) == 0 {
		v.Reachable = false
		v.Err = "the fixture device serves no SunSpec DER model"
		return v, fmt.Errorf("%s: %s", s.Name(), v.Err)
	}
	return v, nil
}

// BuildWorld presents a device's current register state to the invariant
// harness and takes one observation, so a caller can immediately run any
// invariant against it.
//
// No fault manifest and no ledger are supplied: this package arms nothing
// through the manifest and records no writes in the ledger, and an invariant
// that needs either will SKIP naming it — which is the correct answer, not a
// gap. A differential case that wanted to make I3 or I5 assertable would have
// to record its writes and presentations first, and the honest failure mode of
// not doing so is a SKIP with a reason.
func BuildWorld(dev *Device) (*invariant.World, *invariant.Observation, error) {
	src := deviceSource{dev: dev}
	w := invariant.NewWorld(
		invariant.Sources{DERs: map[string]invariant.DERSource{dev.Spec.Name: src}},
		nil, nil, invariant.DefaultParams(),
	)
	obs, err := w.Observe(context.Background())
	if err != nil {
		return nil, nil, err
	}
	return w, obs, nil
}
