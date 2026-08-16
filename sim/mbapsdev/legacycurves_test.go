package main

// legacycurves_test.go — the mbaps device sim can present the LEGACY curve
// family, and why that is a conformance fact rather than a convenience.
//
// suitemodbusserver's CRV-1 sweeps 126-134/160 across the DUT's northbound
// projection and asserts the D4 read-only posture on each. Every one of those
// sub-verdicts SKIPped on the bench, and the cause was here: the only DER this
// bench presents over SECURE Modbus is this sim, and it could build nothing but
// the 7xx advanced set, so the gateway had no legacy curve models to project.
// modsim has served them since the legacy-curve wave, but it speaks plaintext
// and never reaches the mbaps surface CRV-1 measures.
//
// A SKIP is not a pass. These tests exist so the gap cannot silently reopen.

import (
	"testing"

	"lexa-proto/sunspec"
)

// legacyCurveModels is the family CRV-1 sweeps, minus 133 — which no
// generation registers a layout for, and which CRV-1 reports as a named
// structural absence rather than a device-conditional one.
var legacyCurveModels = []uint16{126, 127, 128, 129, 130, 131, 132, 134, 160}

func TestLegacyCurveModelServesTheFamilyCRV1Sweeps(t *testing.T) {
	mb, err := newModel("inverter-legacy-curves", 5000, 10, "")
	if err != nil {
		t.Fatalf("newModel(inverter-legacy-curves): %v", err)
	}
	defer mb.stop()

	regs, ok := mb.registers().(map[uint16]uint16)
	if !ok {
		// The concrete type varies by sim; fall back to scanning the chain
		// through the register map, which is what a client would do anyway.
		regs = nil
	}
	_ = regs

	chain := chainModelIDs(t, mb)
	have := map[uint16]bool{}
	for _, id := range chain {
		have[id] = true
	}
	for _, id := range legacyCurveModels {
		if !have[id] {
			t.Errorf("the legacy-curve model does not serve model %d; CRV-1.%d then reports "+
				"'the discovery walk found no model %d in this unit's chain' and SKIPs — a harness gap "+
				"wearing a verdict's clothes", id, id, id)
		}
	}
	// And it must NOT also serve the 7xx curve set: a device serves one
	// generation or the other, and a chain with both is one no real DER has.
	for _, id := range []uint16{705, 706, 711, 712} {
		if have[id] {
			t.Errorf("the legacy-curve model also serves 7xx model %d; a device presenting both "+
				"generations' curve families is a fixture no DER matches", id)
		}
	}
	t.Logf("legacy-curve chain: %v", chain)
}

// The two inverter models must be distinguishable by identity, or a bench
// running both puts the referee's identity-keyed mechanisms into their degraded
// mode (internal/invariant/i3.go's identityHolders).
func TestLegacyCurveModelHasItsOwnIdentity(t *testing.T) {
	if defaultMbapsLegacySerial == defaultMbapsInverterSerial {
		t.Fatalf("both mbapsdev inverter models default to serial %q; two co-located sims then share an "+
			"identity and the referee declines to pair them", defaultMbapsLegacySerial)
	}
	if defaultMbapsLegacySerial == "SN-SOLAR-001" {
		t.Error("the legacy model took modsim's default serial")
	}
}

// chainModelIDs walks the sim's own register image the way a SunSpec client
// would, so the assertion is about what a gateway can DISCOVER rather than
// about what the constructor believes it wrote.
func chainModelIDs(t *testing.T, mb *modelBundle) []uint16 {
	t.Helper()
	r := mb.regs
	const base = 40000
	// SunS marker occupies 40000-40001; the chain starts at 40002.
	addr := uint16(base + 2)
	var out []uint16
	for i := 0; i < 64; i++ {
		id := r.Get(addr)
		if id == sunspec.EndMarker || id == 0 {
			break
		}
		length := r.Get(addr + 1)
		out = append(out, id)
		addr += 2 + length
	}
	return out
}
