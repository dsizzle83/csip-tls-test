package invariant

// i3scope_test.go — the lying-peer exemption's TARGET clause, on the witness
// where it was vacuous.
//
// ── The defect this file exists for ────────────────────────────────────────
//
// The exemption's narrowest clause read `len(inScope) > 0 && !inScope[f.Target]`
// over WriteRecord.DERs — a field the campaign's only production constructor
// never set. len(inScope) was therefore always 0, the clause never rejected
// anything, and ANY apply-then-refuse lie in force on ANY device exempted a
// ghost seen on the DUT's projection.
//
// TestI3ExemptionIsNarrow already had an "armed on another device" case and it
// passed the whole time, because its fixture has only a DER witness and the DER
// branch (`f.Target != v.Device`) was always sound. The projection witness — the
// one a real campaign judges, and the only one the vacuous clause guarded — had
// no test at all. That is the shape of this defect and the reason the tests
// below are per-WITNESS rather than per-fault.
//
// For a conformance harness the consequence is the worst available: a FAIL
// silently becomes a WARN. Every case here is written so that a regression
// reappears as a failing test rather than as a quieter bundle.

import (
	"context"
	"strings"
	"testing"
	"time"

	"lexa-proto/sunspec"
)

// ghostRegs is a register image holding the refused value in a register the DUT
// never enabled — the ghost-commit shape.
func ghostRegs(t *testing.T, pct float64) UnitView {
	t.Helper()
	return unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 0)
			v.SetFloat("WMaxLimPct", pct)
		}),
	})
}

// cleanRegs is the same device holding NOTHING — the register is clear, so this
// device cannot be where a projected ghost came from.
func cleanRegs(t *testing.T) UnitView {
	t.Helper()
	return unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 0)
			v.SetFloat("WMaxLimPct", 0)
		}),
	})
}

// projectionWorld builds a world with a DUT PROJECTION witness holding the
// refused value, plus whatever DER views the caller supplies.
//
// The projection is the witness the campaign actually judges and the one the
// vacuous clause guarded, so every test here goes through it.
func projectionWorld(t *testing.T, at, writeAt time.Time, ders []DERView,
	scope []string, arm func(*FaultManifest)) *World {

	t.Helper()
	man := NewManifest("i3-scope", 4242)
	if arm != nil {
		arm(man)
	}
	led := NewLedger()
	led.NoteWrite(WriteRecord{
		At: writeAt, Credential: "SuperAdministratorSunSpec", Role: "SuperAdministratorSunSpec",
		Authorized: true, Unit: 1, Model: 704, Point: "WMaxLimPct",
		Value: Quantity{Val: 63, Unit: UnitPercent}, Ref: RefWMax,
		Distinctive: true, Refused: true, ExceptionCode: 0x04,
		DERs: scope,
	})
	w := NewWorld(Sources{}, man, led, DefaultParams())
	o := obsFixture(at, ders...)
	// The DUT's own projection, holding the refused value: the ghost.
	o.DUT = DUTView{
		Source: "mbaps:dut", Reachable: true,
		Units: map[uint8]UnitView{1: ghostRegs(t, 63)},
	}
	o.Faults = man.Snapshot()
	w.Inject(o)
	return w
}

// armOn arms the apply-then-refuse lie on a named device.
func armOn(device string, armed time.Time) func(*FaultManifest) {
	return func(m *FaultManifest) {
		m.Arm(Fault{
			ID: device + ".exception_on_applied_write#1", Kind: lieApplyThenRefuse,
			Class: ClassPeerLie, Target: device, Params: map[string]string{"ex_code": "4"},
			Armed: armed, Recoverable: true,
		})
	}
}

func i3Verdict(t *testing.T, w *World) Result {
	t.Helper()
	res, err := NewI3(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I3 returned an error: %v", err)
	}
	return res
}

// THE GATE'S PROOF SHAPE, in the form that actually isolates the defect.
//
// The ghost is visible ONLY on the DUT's projection: device A is lying and
// holds nothing, device B is not lying and holds nothing, and the DUT is
// projecting the refused value anyway — durable state in the DUT itself, which
// is exactly what I3 exists to catch. The lie on A cannot account for it.
//
// THE ISOLATION IS THE POINT AND IT IS EASY TO GET WRONG. The obvious version
// of this test — B HOLDS the value while A lies — does not discriminate: B
// holding it produces a DER witness, the DER branch (`f.Target != v.Device`)
// was always sound, and that witness FAILs the run no matter what the
// projection branch does. Written that way the test passes against the broken
// code and proves nothing. The bug lives on the witness where the DUT is the
// only thing holding the value, so that is the witness this test builds.
func TestI3_ALieOnOneDeviceDoesNotExemptAProjectionGhost(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		derFixture("der-a-lying", cleanRegs(t)), // armed, holds nothing
		derFixture("der-b-quiet", cleanRegs(t)), // not armed, holds nothing
	}, nil, armOn("der-a-lying", write.Add(-9*time.Second)))

	res := i3Verdict(t, w)
	if res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL. NO device holds the refused value — der-a-lying is lying and "+
			"holds nothing — yet the DUT is projecting it, which is durable state on the DUT and the "+
			"whole subject of this invariant. The lie was allowed to explain it anyway, converting a "+
			"real ghost-commit finding into a WARN: on a conformance harness, a failure silently "+
			"becoming a pass.\n  reason: %s", res.Verdict, res.Reason)
	}
	t.Logf("FAIL (correct) — %s", res.Reason)
}

// The companion, documenting why the obvious framing does NOT discriminate: a
// device that HOLDS the value produces its own DER witness, and that branch was
// always sound, so the run FAILs through it whatever the projection branch
// decides. Kept so nobody "simplifies" the test above into this one.
func TestI3_ADeviceHoldingItFailsThroughItsOwnWitnessRegardless(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		derFixture("der-a-lying", cleanRegs(t)),
		derFixture("der-b-ghost", ghostRegs(t, 63)),
	}, nil, armOn("der-a-lying", write.Add(-9*time.Second)))

	if res := i3Verdict(t, w); res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL through der-b-ghost's own witness.\n  reason: %s",
			res.Verdict, res.Reason)
	}
}

// The exemption must still FIRE where it is sound: the lying device is itself
// holding the value, so the campaign's own fault explains the projection.
func TestI3_ALieOnTheDeviceHoldingItStillExempts(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		derFixture("loopback-der", ghostRegs(t, 63)),
	}, nil, armOn("loopback-der", write.Add(-9*time.Second)))

	res := i3Verdict(t, w)
	if res.Verdict != Warn {
		t.Fatalf("I3 = %s, want WARN. The lie is armed on the device that HOLDS the refused value, so "+
			"the campaign's own apply-then-refuse fault explains it completely and I3's inference is "+
			"unsound — which is the whole ruling.\n  reason: %s", res.Verdict, res.Reason)
	}
	if !strings.Contains(res.Reason, lieApplyThenRefuse) {
		t.Errorf("the WARN does not name the fault it rests on:\n  %s", res.Reason)
	}
	t.Logf("WARN (correct exemption) — %s", res.Reason)
}

// FAILS CLOSED. The lying device is not observable at all, so the exemption
// cannot establish its own TARGET clause and must not fire.
//
// This is the direction that costs a false FAIL rather than a false PASS: an
// unexplained ghost is adjudicated by a human, an unnoticed one is not.
func TestI3_AnUnobservableLyingDeviceDoesNotExempt(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	for _, tc := range []struct {
		name string
		ders []DERView
	}{
		{"the lying device is not in the observation at all", nil},
		{"the lying device is present but unreachable", []DERView{{
			Name: "gone-der", Source: "modbus:test/gone-der", Reachable: false,
		}}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := projectionWorld(t, obs, write, tc.ders, nil,
				armOn("gone-der", write.Add(-9*time.Second)))
			if res := i3Verdict(t, w); res.Verdict != Fail {
				t.Fatalf("I3 = %s, want FAIL. The exemption fired without being able to check that the "+
					"lying device could account for the value; an exemption that cannot check its own "+
					"scope must not fire.\n  reason: %s", res.Verdict, res.Reason)
			}
		})
	}
}

// The record's own projection is still honoured as an ADDITIONAL narrowing: a
// lie on a device outside the write's reach is rejected before the causal check
// is even reached.
func TestI3_TheRecordedProjectionStillNarrowsTheExemption(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	// der-out holds the value AND is lying — but the write could not reach it,
	// so it cannot be what the DUT projected from.
	w := projectionWorld(t, obs, write,
		[]DERView{derFixture("der-out", ghostRegs(t, 63))},
		[]string{"der-in"},
		armOn("der-out", write.Add(-9*time.Second)))

	if res := i3Verdict(t, w); res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL. The lie is on a device outside this write's recorded projection, "+
			"so it cannot explain what the write's own unit is projecting.\n  reason: %s",
			res.Verdict, res.Reason)
	}
}

// And the projection, when it CONTAINS the lying device, does not get in the
// way of a sound exemption.
func TestI3_AnInScopeLyingDeviceHoldingItStillExempts(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write,
		[]DERView{derFixture("der-in", ghostRegs(t, 63))},
		[]string{"der-in"},
		armOn("der-in", write.Add(-9*time.Second)))

	if res := i3Verdict(t, w); res.Verdict != Warn {
		t.Fatalf("I3 = %s, want WARN: the lying device is in scope AND holds the value.\n  reason: %s",
			res.Verdict, res.Reason)
	}
}
