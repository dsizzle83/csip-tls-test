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

// identified is derFixture plus the model-1 identity a real scan reads
// (sources.go populates UnitView.Identity for every unit it reads, on the DER's
// own channel and on the DUT's northbound alike).
//
// The identity is what pairs a DER with the DUT's projection OF that DER, and
// it is measured rather than configured — which is why the exemption uses it
// instead of a unit number the campaign never mapped to a device.
func identified(name, identity string, uv UnitView) DERView {
	d := derFixture(name, uv)
	d.Unit.Identity = identity
	return d
}

// projectionWorld builds a world with a DUT PROJECTION witness holding the
// refused value, plus whatever DER views the caller supplies.
//
// The projection is the witness the campaign actually judges and the one the
// vacuous clause guarded, so every test here goes through it. dutIdentity is
// the identity the DUT projects on that unit — empty models a DUT (or a scan)
// that produced none, which the exemption must treat as un-pairable.
func projectionWorld(t *testing.T, at, writeAt time.Time, ders []DERView,
	scope []string, dutIdentity string, arm func(*FaultManifest)) *World {

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
	projected := ghostRegs(t, 63)
	projected.Identity = dutIdentity
	o.DUT = DUTView{
		Source: "mbaps:dut", Reachable: true,
		Units: map[uint8]UnitView{1: projected},
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
		identified("der-a-lying", "acme inv sn=A", cleanRegs(t)), // armed, holds nothing
		identified("der-b-quiet", "acme inv sn=B", cleanRegs(t)), // not armed, holds nothing
	}, nil, "acme inv sn=A", armOn("der-a-lying", write.Add(-9*time.Second)))

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
		identified("der-a-lying", "acme inv sn=A", cleanRegs(t)),
		identified("der-b-ghost", "acme inv sn=B", ghostRegs(t, 63)),
	}, nil, "acme inv sn=A", armOn("der-a-lying", write.Add(-9*time.Second)))

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
		identified("loopback-der", "acme inv sn=LB", ghostRegs(t, 63)),
	}, nil, "acme inv sn=LB", armOn("loopback-der", write.Add(-9*time.Second)))

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
			Unit: UnitView{Identity: "acme inv sn=GONE"},
		}}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := projectionWorld(t, obs, write, tc.ders, nil, "acme inv sn=GONE",
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
		[]DERView{identified("der-out", "acme inv sn=OUT", ghostRegs(t, 63))},
		[]string{"der-in"}, "acme inv sn=OUT",
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
		[]DERView{identified("der-in", "acme inv sn=IN", ghostRegs(t, 63))},
		[]string{"der-in"}, "acme inv sn=IN",
		armOn("der-in", write.Add(-9*time.Second)))

	if res := i3Verdict(t, w); res.Verdict != Warn {
		t.Fatalf("I3 = %s, want WARN: the lying device is in scope AND holds the value.\n  reason: %s",
			res.Verdict, res.Reason)
	}
}

// ── H3: the causal clause must be about THIS witness's device ──────────────
//
// Gate #18's fix established that the lying device holds the value. Gate #19
// found that this proves only that SOME in-scope device holds it — not that the
// device holding it is the one the projection is OF. The three probes below are
// that finding, pinned.

// PROBE 1. A lying device that HOLDS the value but is a different device from
// the one this projection is of must NOT excuse the ghost.
//
// This is the multi-DER bench shape and it is not hypothetical: the campaign
// populates the write record's projection with EVERY device in the inventory
// (cmd/gw-campaign's derNames), so the nominal scope clause rejects nothing and
// everything rests on this one. der-a is lying AND holding 63 — but the DUT's
// unit projects der-b, so der-a cannot be where that value came from.
func TestI3_ALyingDeviceHoldingItOnAnotherUnitDoesNotExempt(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		// Lying, and holding the refused value — but a DIFFERENT machine.
		identified("der-a-lying", "acme inv sn=A", ghostRegs(t, 63)),
		// The device this unit actually projects, holding nothing.
		identified("der-b-projected", "acme inv sn=B", cleanRegs(t)),
	}, nil, "acme inv sn=B", armOn("der-a-lying", write.Add(-9*time.Second)))

	res := i3Verdict(t, w)
	if res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL. der-a is lying and holds 63, but the DUT's unit projects der-b "+
			"(sn=B) — so der-a cannot be where that value came from and its lie cannot excuse it. "+
			"Accepting it proves only that SOME in-scope device holds the value, which on a multi-DER "+
			"bench is the vacuous clause again: the ghost lands as a GREEN run.\n  reason: %s",
			res.Verdict, res.Reason)
	}
	t.Logf("FAIL (correct) — %s", res.Reason)
}

// PROBE 2. When the identities DO match, the exemption still fires — the fix
// must not retire the ruling it is narrowing.
func TestI3_AnIdentityMatchedLyingDeviceStillExempts(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		identified("der-a-lying", "acme inv sn=A", ghostRegs(t, 63)),
		identified("der-b-quiet", "acme inv sn=B", cleanRegs(t)),
	}, nil, "acme inv sn=A", armOn("der-a-lying", write.Add(-9*time.Second)))

	res := i3Verdict(t, w)
	if res.Verdict != Warn {
		t.Fatalf("I3 = %s, want WARN: the lying device holds the value AND is the device this unit "+
			"projects (sn=A on both sides), so the campaign's own fault explains it.\n  reason: %s",
			res.Verdict, res.Reason)
	}
	t.Logf("WARN (correct exemption) — %s", res.Reason)
}

// PROBE 3. Identity absent on either side: the exemption cannot show the
// pairing and does not fire.
//
// An unidentified device might be the one the projection is of. "Might" is not
// what an exemption runs on — the whole family of clauses here costs a false
// FAIL rather than a false PASS, because the first is adjudicated by a human
// and the second is not.
func TestI3_AnUnidentifiedDeviceCannotBePairedAndDoesNotExempt(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	for _, tc := range []struct {
		name  string
		derID string
		dutID string
	}{
		{"the DER served no model 1", "", "acme inv sn=A"},
		{"the DUT's projection served no model 1", "acme inv sn=A", ""},
		{"neither side is identified", "", ""},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := projectionWorld(t, obs, write, []DERView{
				identified("der-a-lying", tc.derID, ghostRegs(t, 63)),
			}, nil, tc.dutID, armOn("der-a-lying", write.Add(-9*time.Second)))

			if res := i3Verdict(t, w); res.Verdict != Fail {
				t.Fatalf("I3 = %s, want FAIL. The exemption fired without being able to show the lying "+
					"device is the one this projection is OF.\n  reason: %s", res.Verdict, res.Reason)
			}
		})
	}
}

// ── M8: the judgement follows the record's own model ───────────────────────

// TestI3_JudgesTheModelTheRecordNames pins that a write recorded against model
// 123 is not judged against model 704's register of the same point name.
//
// Latent today — only 704 records are constructed — and it stopped being safely
// latent when model 123 entered modelsOfInterest, because the legacy scalar
// surface is now READ and a legacy write record is one constructor away.
func TestI3_JudgesTheModelTheRecordNames(t *testing.T) {
	t.Parallel()
	i := &i3{p: DefaultParams()}

	// A unit whose 704 holds the refused value and whose 123 does not.
	uv := ghostRegs(t, 63)
	uv.Regs[sunspec.ModelImmediateCtrl] = m123Block(nil)

	if _, ok := i.commandUnderTest(uv, "src", WriteRecord{Model: 704, Point: "WMaxLimPct"}); !ok {
		t.Error("a model-704 record did not resolve against the 704 image")
	}
	// The legacy point is MODEL-QUALIFIED, so a 123 record naming the bare 704
	// point name resolves to nothing rather than to the 704 register.
	if _, ok := i.commandUnderTest(uv, "src",
		WriteRecord{Model: sunspec.ModelImmediateCtrl, Point: "WMaxLimPct"}); ok {
		t.Error("a model-123 record resolved against model 704's WMaxLimPct — a different register on a " +
			"different generation that happens to share a point name")
	}
	// Its own point does resolve.
	if _, ok := i.commandUnderTest(uv, "src",
		WriteRecord{Model: sunspec.ModelImmediateCtrl, Point: PointM123Conn}); !ok {
		t.Error("a model-123 record did not resolve against the 123 image")
	}
	// A model this decoder has no reader for is refused, not guessed.
	if _, ok := i.commandUnderTest(uv, "src", WriteRecord{Model: 705, Point: "WMaxLimPct"}); ok {
		t.Error("a model-705 record resolved against something; an unreadable model must skip the " +
			"witness rather than be judged against the wrong bank")
	}
}

// ── M9: one ghost at two witnesses ────────────────────────────────────────

// TestI3_OneGhostAtTwoWitnessesIsOneFinding is the fold, and the argument for
// it: a DER's own image and the DUT's projection OF that DER are two readings
// of one physical register, so a ghost visible in both is one finding — with
// both readings in its facts.
func TestI3_OneGhostAtTwoWitnessesIsOneFinding(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	// The device holds the ghost AND the DUT projects it, same identity, no
	// lie armed anywhere.
	w := projectionWorld(t, obs, write, []DERView{
		identified("inv-plain", "acme inv sn=A", ghostRegs(t, 63)),
	}, nil, "acme inv sn=A", nil)

	res := i3Verdict(t, w)
	if res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL: %s", res.Verdict, res.Reason)
	}
	if len(res.Keys) != 1 {
		t.Fatalf("one ghost, visible at the DER and at the DUT's projection of that same DER, produced "+
			"%d findings: %v. That is IW15-031's over-count at N=2 — two shrinks and two entries in the "+
			"count for one physical register holding one value", len(res.Keys), res.Keys)
	}
	// The witness set is not lost by folding — it is in the facts.
	var witnesses []string
	for _, f := range res.Facts {
		if f.Key == "i3.observed.witness" {
			witnesses = append(witnesses, f.Value)
		}
	}
	if len(witnesses) < 2 {
		t.Errorf("the folded finding records %d witness fact(s) (%v); folding must move the witness set "+
			"into the facts, not discard it", len(witnesses), witnesses)
	}
	t.Logf("one finding, key %q, witnesses %v", res.Keys[0], witnesses)
}

// And the fold must NOT merge findings that are genuinely different. A ghost in
// the DUT's projection with NO device behind it holding the value is durable
// state in the DUT itself — a different defect, a different owner — and it
// stays its own finding.
func TestI3_AProjectionGhostWithNoDeviceBehindItStaysItsOwn(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	// Device A holds the ghost. The DUT projects an identity NO device here
	// carries — so its ghost is not a second reading of A.
	w := projectionWorld(t, obs, write, []DERView{
		identified("inv-a", "acme inv sn=A", ghostRegs(t, 63)),
	}, nil, "acme inv sn=UNKNOWN", nil)

	res := i3Verdict(t, w)
	if res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL: %s", res.Verdict, res.Reason)
	}
	if len(res.Keys) != 2 {
		t.Fatalf("a device ghost and an unrelated projection ghost produced %d finding(s): %v. Folding "+
			"must key on the physical register, and these are two — merging them hides one behind the "+
			"other, which is the lost-finding crime the shrinker keyer was just fixed for",
			len(res.Keys), res.Keys)
	}
	t.Logf("two findings, correctly: %v", res.Keys)
}

// An UNIDENTIFIED bench keeps the pre-M9 behaviour rather than folding
// everything onto one key on the strength of a pairing nobody measured.
func TestI3_WithoutIdentitiesTheWitnessesDoNotFold(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		derFixture("inv-plain", ghostRegs(t, 63)), // no identity
	}, nil, "", nil)

	res := i3Verdict(t, w)
	if len(res.Keys) != 2 {
		t.Fatalf("with no identity on either side the witnesses folded anyway (%d key(s): %v). "+
			"Over-counting is a reporting defect; merging two findings that were never shown to be one "+
			"is a lost finding", len(res.Keys), res.Keys)
	}
}

// ── F1: an identity that names two devices names none ─────────────────────
//
// Both identity-keyed mechanisms assumed the identity picks out ONE device. On
// real hardware it does; on this bench it need not — sim.go's static Populate
// hardcodes SN-0001 with no override, and the animated sims' own -serial help
// says co-located sims collide unless an operator sets them apart. The probes
// below are the two ways that assumption fails, and they fail in opposite
// mechanisms and the same direction: toward a finding nobody sees.

// PROBE 1 (control). Distinct identities: two ghosts on two devices are two
// findings, as they always were.
func TestI3_DistinctIdentitiesKeepTwoGhostsSeparate(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		identified("der-a", "SunSpec Sim CSIP-Dev-5000 sn=SN-A", ghostRegs(t, 63)),
		identified("der-b", "SunSpec Sim CSIP-Dev-5000 sn=SN-B", ghostRegs(t, 63)),
	}, nil, "SunSpec Sim CSIP-Dev-5000 sn=SN-A", nil)

	res := i3Verdict(t, w)
	if res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL: %s", res.Verdict, res.Reason)
	}
	if len(res.Keys) != 2 {
		t.Fatalf("two ghosts on two distinctly-identified devices produced %d finding(s): %v",
			len(res.Keys), res.Keys)
	}
	t.Logf("control — two devices, two findings: %v", res.Keys)
}

// PROBE 2. COLLIDING identities must still yield two findings.
//
// Folding on an identity two machines share would merge two genuinely distinct
// ghosts into one key: one finding reported and one LOST — IW15-031's crime
// through the very key that fixed it.
func TestI3_CollidingIdentitiesDoNotMergeTwoGhosts(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	// The bench's own default, twice — sim.go:718's hardcoded SN-0001.
	const collided = "SunSpec Sim CSIP-Dev-5000 sn=SN-0001"
	w := projectionWorld(t, obs, write, []DERView{
		identified("der-a", collided, ghostRegs(t, 63)),
		identified("der-b", collided, ghostRegs(t, 63)),
	}, nil, collided, nil)

	res := i3Verdict(t, w)
	if len(res.Keys) < 2 {
		t.Fatalf("two ghosts on two devices sharing an identity produced %d finding(s): %v. Folding on "+
			"an identity that names more than one machine MERGES distinct findings — one is reported and "+
			"the other is lost, which is the crime the fold was introduced to stop",
			len(res.Keys), res.Keys)
	}
	// And the degraded mode DISCLOSES ITSELF. A bundle whose de-duplication
	// silently switched off looks exactly like one that had nothing to
	// de-duplicate; the difference has to be in the evidence, not inferred.
	var ambiguous, effect bool
	for _, f := range res.Facts {
		switch f.Key {
		case "i3.identity.ambiguous":
			ambiguous = true
		case "i3.identity.effect":
			effect = true
		}
	}
	if !ambiguous || !effect {
		t.Errorf("the colliding-identity run records no disclosure (ambiguous=%t effect=%t); a reader "+
			"cannot tell a run whose mechanisms were OFF from one that had nothing to fold",
			ambiguous, effect)
	}
	t.Logf("colliding identities — findings stay separate: %v", res.Keys)
}

// PROBE 3. A lie on der-a must not excuse a ghost der-b caused, when the two
// share an identity.
//
// This is the worst of the three: der-a is lying AND holds the value, so the
// identity "matches" the projection only because der-b's is identical. Pre-fix
// the exemption fires and a real FAIL becomes the lying-peer-confound WARN —
// gate #18's and #19's end-state, reached through the mechanism that closed
// them.
func TestI3_ACollidingIdentityDoesNotLetALieExcuseAnotherDevice(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	const collided = "SunSpec Sim CSIP-Dev-5000 sn=SN-0001"
	w := projectionWorld(t, obs, write, []DERView{
		identified("der-a-lying", collided, ghostRegs(t, 63)), // armed, and holds it
		identified("der-b-ghost", collided, ghostRegs(t, 63)), // NOT armed, holds it too
	}, nil, collided, armOn("der-a-lying", write.Add(-9*time.Second)))

	res := i3Verdict(t, w)
	if res.Verdict != Fail {
		t.Fatalf("I3 = %s, want FAIL: %s", res.Verdict, res.Reason)
	}
	// THE RUN VERDICT DOES NOT DISCRIMINATE HERE, and the first draft of this
	// test rested on it and proved nothing. der-b's OWN witness fails through
	// the DER branch (`f.Target != v.Device`), which was always sound, so the
	// run is FAIL whatever the projection branch decides — the same masking
	// that made gate #19's first framing vacuous.
	//
	// The discriminating signal is whether the DUT'S PROJECTION was exempted.
	// Pre-fix it folds onto the shared identity, der-a's lie "explains" it, and
	// it contributes no finding at all. Post-fix the collision refuses both the
	// fold and the exemption, so it stands as its own ghost.
	var sawProjection bool
	for _, k := range res.Keys {
		if strings.Contains(k, "dut.unit1") {
			sawProjection = true
		}
	}
	if !sawProjection {
		t.Fatalf("the DUT's projection contributed no finding: %v. der-a's lie was allowed to explain a "+
			"value der-b also holds, because the two share an identity — a ghost with an independent "+
			"cause silently downgraded to a WARN about the campaign's own fault. An identity that cannot "+
			"uniquely pair cannot causally explain", res.Keys)
	}
	t.Logf("colliding identities — the projection is NOT exempted: %v", res.Keys)
}

// And the exemption is not broken in general: with a UNIQUE identity it still
// fires, so the guard narrowed the mechanism rather than retiring it.
func TestI3_AUniqueIdentityStillExemptsAfterTheCollisionGuard(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	w := projectionWorld(t, obs, write, []DERView{
		identified("der-a-lying", "SunSpec Sim CSIP-Dev-5000 sn=SN-A", ghostRegs(t, 63)),
		identified("der-b-quiet", "SunSpec Sim CSIP-Dev-5000 sn=SN-B", cleanRegs(t)),
	}, nil, "SunSpec Sim CSIP-Dev-5000 sn=SN-A", armOn("der-a-lying", write.Add(-9*time.Second)))

	if res := i3Verdict(t, w); res.Verdict != Warn {
		t.Fatalf("I3 = %s, want WARN: the lying device is uniquely identified and holds the value, so "+
			"the ruling still applies.\n  reason: %s", res.Verdict, res.Reason)
	}
}
