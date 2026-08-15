package invariant

// key_test.go pins IW15-031: violation IDENTITY.
//
// The bug it exists to stop coming back had two faces that turned out to be one
// mechanism. [Violation.Signature]'s fallback hashed the facts, and its
// timestamp exclusion matched only keys ending in "_at" or facts carrying unit
// "s" — while I3 emits `i3.write.at` / `i3.observed.at` and I7 emits
// `i7.claim.received`, all three of them wall-clock instants under names the
// rule did not cover. So:
//
//   - ONE finding minted a NEW signature on every monitor tick, and the
//     hermetic campaign at SEED=4242 reported "4 distinct invariant violations"
//     for a single I3 finding observed four times;
//
//   - NO re-run could ever produce a signature a previous run had produced, so
//     [campaign.Shrink]'s confirm step failed 100% of the time and printed "NOT
//     REPRODUCED on re-run with the full action set — the finding is
//     non-deterministic and no minimal set can be claimed for it" about a
//     finding that reproduced 6 times out of 6.
//
// The second is much the worse of the two: a shrinker that mislabels a real
// finding as flaky trains an operator to disbelieve the next one. Both are
// closed by the same change — every standard invariant now names its own
// [Result.Key] — with the value-based timestamp exclusion below as the backstop
// for a checker that forgets.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"lexa-proto/sunspec"
)

// ── the backstop: an instant is an instant whatever it is called ─────────────

// TestFallbackSignatureIgnoresTimestampFactsWhateverTheyAreCalled is the direct
// regression on the rule that failed. `i3.observed.at` is the exact key that
// escaped the old suffix test, and the value test now catches it regardless.
func TestFallbackSignatureIgnoresTimestampFactsWhateverTheyAreCalled(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 8, 15, 18, 45, 7, 0, time.UTC)
	build := func(at time.Time) Violation {
		return Violation{
			ID: "IX",
			Facts: []Fact{
				F("ix.write.value", "%", "ledger", "63"),
				F("ix.observed.at", "", "witness", "%s", at.Format(time.RFC3339)),
				F("ix.claim.received", "", "witness", "%s", at.Format(time.RFC3339)),
				F("ix.authority_restored_at", "", "manifest", "%s", at.Format(time.RFC3339)),
			},
		}
	}
	a := build(t0).Signature()
	b := build(t0.Add(5 * time.Second)).Signature()
	if a != b {
		t.Fatalf("the same finding five seconds later hashed to a different signature (%s vs %s) — "+
			"a shrinker cannot re-identify a finding whose identity moves with the clock", a, b)
	}

	// And the guard must not be so broad that it erases the finding: a real
	// change in what was observed still has to change the identity, or two
	// different defects would merge into one ticket.
	changed := build(t0)
	changed.Facts[0] = F("ix.write.value", "%", "ledger", "41")
	if changed.Signature() == a {
		t.Fatal("changing the observed value did not change the signature — the exclusion is over-broad " +
			"and would merge two distinct findings into one")
	}
}

// TestAKeyedViolationIgnoresItsFactsEntirely states the other half of the
// contract: once a checker names its identity, corroboration that a chaos
// campaign makes come and go must not disturb it.
func TestAKeyedViolationIgnoresItsFactsEntirely(t *testing.T) {
	t.Parallel()
	base := Violation{ID: "I3", Key: "ghost:cred:1:WMaxLimPct:63:dut.unit1",
		Facts: []Fact{F("i3.observed.value", "%", "dut", "63")}}
	richer := base
	richer.Facts = append(append([]Fact{}, base.Facts...),
		F("i3.observed.enabled", "", "dut", "false"),
		F("i3.observed.at", "", "dut", "%s", time.Now().Format(time.RFC3339)))
	if base.Signature() != richer.Signature() {
		t.Fatal("a keyed violation's signature moved when corroborating facts appeared — that is the very " +
			"drift Result.Key exists to stop")
	}
}

// ── the structural pin: no standard invariant may fall back ──────────────────

// TestEveryStandardInvariantNamesItsKey is a STRUCTURAL pin, deliberately so.
//
// A behavioural pin would need a fixture that drives each of I1–I10 to a
// violation, and four of them (I2, I7, I8, I10) need a head-end or a shell that
// a unit test would have to fake so thoroughly that the fake, not the invariant,
// would be under test. What can be asserted cheaply and without any fake is the
// thing that actually regressed: that each checker still HAS an identity to
// offer. A new invariant added without one fails here rather than silently
// rejoining the fact-hash fallback — and it fails with the reason attached.
func TestEveryStandardInvariantNamesItsKey(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 10; n++ {
		name := fmt.Sprintf("i%d.go", n)
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(src)
		for _, want := range []string{"keysOf(&res)", "key.note("} {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not contain %q: it will fall back to hashing its facts, which "+
					"re-identifies a finding whenever its corroboration changes (IW15-031)", name, want)
			}
		}
	}
}

// ── I3: identity, and the lying-peer adjudication ────────────────────────────

// ghostWorld builds IW15-031's exact shape: a distinctive write the DUT refused
// with a Modbus exception, and a witness whose register image nonetheless holds
// the refused value. faults, when non-nil, is applied to the manifest before the
// observation is taken.
func ghostWorld(t *testing.T, at time.Time, writeAt time.Time, code uint8, arm func(*FaultManifest)) *World {
	t.Helper()
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 0) // refused, so the DUT never enabled it
			v.SetFloat("WMaxLimPct", 63)  // …and yet the value is in the register
		}),
	})
	man := NewManifest("key-test", 4242)
	if arm != nil {
		arm(man)
	}
	led := NewLedger()
	led.NoteWrite(WriteRecord{
		At: writeAt, Credential: "SuperAdministratorSunSpec", Role: "SuperAdministratorSunSpec",
		Authorized: true, Unit: 1, Model: 704, Point: "WMaxLimPct",
		Value: Quantity{Val: 63, Unit: UnitPercent}, Ref: RefWMax,
		Distinctive: true, Refused: true, ExceptionCode: code,
	})
	w := NewWorld(Sources{}, man, led, DefaultParams())
	o := obsFixture(at, derFixture("loopback-der", uv))
	o.Faults = man.Snapshot()
	w.Inject(o)
	return w
}

// armApplyThenRefuse arms the peer-lie the adjudication turns on, over a window
// that contains the write.
func armApplyThenRefuse(armed, cleared time.Time, params map[string]string) func(*FaultManifest) {
	return func(m *FaultManifest) {
		m.Arm(Fault{
			ID: "loopback-der.exception_on_applied_write#1", Kind: lieApplyThenRefuse,
			Class: ClassPeerLie, Target: "loopback-der", Params: params,
			Armed: armed, Cleared: cleared, Recoverable: true,
		})
	}
}

// TestI3GhostFindingHasOneIdentityAcrossTicks is the SEED=4242 defect itself,
// reduced to a unit test: the campaign observed ONE ghost and reported it FOUR
// times, once per tick, because the fact hash carried `i3.observed.at`.
func TestI3GhostFindingHasOneIdentityAcrossTicks(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	var keys []string
	var asOfA274dc9 []string
	for i := 0; i < 4; i++ {
		w := ghostWorld(t, write.Add(time.Duration(2+5*i)*time.Second), write, 0x04, nil)
		res, err := NewI3(DefaultParams()).Check(context.Background(), w)
		if err != nil {
			t.Fatalf("I3 returned an error: %v", err)
		}
		if res.Verdict != Fail {
			t.Fatalf("tick %d: I3 verdict = %s, want FAIL (no confounding lie was armed)\nreason: %s",
				i, res.Verdict, res.Reason)
		}
		if res.Key == "" {
			t.Fatal("I3 reported a ghost without naming its identity")
		}
		v := Violation{ID: "I3", Verdict: Fail, Facts: res.Facts, Key: res.Key}
		keys = append(keys, v.Signature())
		asOfA274dc9 = append(asOfA274dc9, legacySignature(v))
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] != keys[0] {
			t.Fatalf("the same ghost got signature %s at tick 0 and %s at tick %d — this is exactly what "+
				"reported 4 distinct violations for one finding at SEED=4242", keys[0], keys[i], i)
		}
	}
	// The counterfactual, so this test proves the fix does WORK rather than
	// proving the finding happened to be stable anyway. legacySignature is the
	// identity function exactly as it stood before this change, and it must
	// disagree with itself across the four ticks — otherwise nothing here is
	// pinned and the campaign's "4 distinct violations" had some other cause.
	distinct := map[string]bool{}
	for _, s := range asOfA274dc9 {
		distinct[s] = true
	}
	if len(distinct) != len(asOfA274dc9) {
		t.Fatalf("the pre-fix identity function produced %d distinct signatures over %d ticks; the bug this "+
			"test pins produced one per tick, so the fixture no longer reproduces it", len(distinct), len(asOfA274dc9))
	}
}

// legacySignature is [Violation.Signature]'s fact-hash fallback EXACTLY as it
// stood at a274dc9, before IW15-031: no Key branch, and a timestamp exclusion
// that tested only the key's "_at" suffix and the "s" unit. It exists so the
// test above can show the old rule failing on the same fixture the new one
// handles — a regression test with no before-state proves nothing.
func legacySignature(v Violation) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n", v.ID)
	keys := make([]string, 0, len(v.Facts))
	byKey := make(map[string]string, len(v.Facts))
	for _, f := range v.Facts {
		if strings.HasSuffix(f.Key, "_at") || f.Unit == "s" {
			continue
		}
		if _, dup := byKey[f.Key]; !dup {
			keys = append(keys, f.Key)
		}
		byKey[f.Key] = f.Value + "\x00" + f.Unit
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, byKey[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// TestI3ExemptsTheApplyThenRefuseLie is the (b) adjudication, executable.
//
// The campaign armed a DER that APPLIES a write and then refuses it. The value's
// presence is then fully explained by the injected fault, with no durable state
// on the DUT — so I3's inference ("present, therefore the refusal committed") is
// invalid and the finding is not a P1. It is also not silence: the run must say
// which write was exempted and why, in the emitted Result.
func TestI3ExemptsTheApplyThenRefuseLie(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	w := ghostWorld(t, write.Add(2*time.Second), write, 0x04,
		armApplyThenRefuse(write.Add(-9*time.Second), time.Time{}, map[string]string{"ex_code": "4", "every": "1"}))

	res, err := NewI3(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I3 returned an error: %v", err)
	}
	if res.Verdict != Warn {
		t.Fatalf("I3 verdict = %s, want WARN: the refused value's presence is the campaign's own "+
			"apply-then-refuse lie, not a ghost commit\nreason: %s", res.Verdict, res.Reason)
	}
	if err := res.Validate("I3"); err != nil {
		t.Fatalf("the exempt result failed its own validation: %v", err)
	}
	if !strings.HasPrefix(res.Key, "lying-peer-confound:") {
		t.Errorf("the exemption did not take its own identity: Key = %q", res.Key)
	}

	// The reasoning must be legible from the RESULT, not only from the source:
	// a bundle reader six months from now has the JSON, not this file.
	for _, want := range []string{lieApplyThenRefuse, "NOT judged a violation of I3", "another route"} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("the emitted finding does not explain the exemption (missing %q):\n%s", want, res.Reason)
		}
	}
	factKeys := map[string]string{}
	for _, f := range res.Facts {
		factKeys[f.Key] = f.Value
	}
	for _, want := range []string{"i3.exempt.fault", "i3.exempt.fault_target", "i3.exempt.fault_in_force_at_write",
		"i3.exempt.rule", "i3.exempt.count", "i3.exempt.writes"} {
		if _, ok := factKeys[want]; !ok {
			t.Errorf("the exempt result omits fact %q — the exemption would be invisible in the bundle", want)
		}
	}
	if factKeys["i3.exempt.fault_target"] != "loopback-der" {
		t.Errorf("the exemption does not name the device the lie was armed on: %q", factKeys["i3.exempt.fault_target"])
	}
	// The claim printed next to the verdict must disclose the exemption too.
	if !strings.Contains(NewI3(DefaultParams()).Statement(), lieApplyThenRefuse) {
		t.Error("I3's statement does not disclose the lying-peer exemption, so a reader of the verdict " +
			"cannot tell that some refused writes are reported WARN rather than FAIL")
	}
}

// TestI3ExemptionIsNarrow is the other half of the adjudication, and the half
// that keeps it from quietly retiring the invariant. Each case is a way the
// injected lie CANNOT explain the value, so the ghost claim is still judged.
func TestI3ExemptionIsNarrow(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	obs := write.Add(2 * time.Second)

	cases := []struct {
		name string
		arm  func(*FaultManifest)
		why  string
	}{{
		name: "armed after the write",
		arm:  armApplyThenRefuse(write.Add(time.Second), time.Time{}, map[string]string{"ex_code": "4"}),
		why:  "a lie armed after the refusal cannot have caused it",
	}, {
		name: "cleared before the write",
		arm:  armApplyThenRefuse(write.Add(-30*time.Second), write.Add(-time.Second), map[string]string{"ex_code": "4"}),
		why:  "a lie already withdrawn cannot have caused the refusal",
	}, {
		name: "a different exception code",
		arm:  armApplyThenRefuse(write.Add(-9*time.Second), time.Time{}, map[string]string{"ex_code": "6"}),
		why:  "the refusal carried 0x04 and the lie answers 0x06, so the refusal came from somewhere else",
	}, {
		name: "armed on another device",
		arm: func(m *FaultManifest) {
			m.Arm(Fault{ID: "other.exception_on_applied_write#1", Kind: lieApplyThenRefuse,
				Class: ClassPeerLie, Target: "some-other-der", Params: map[string]string{"ex_code": "4"},
				Armed: write.Add(-9 * time.Second)})
		},
		why: "the lie was armed on a device this write never reached",
	}, {
		name: "a lie of a different kind",
		arm: func(m *FaultManifest) {
			m.Arm(Fault{ID: "loopback-der.ack_no_apply#1", Kind: "ack_no_apply",
				Class: ClassPeerLie, Target: "loopback-der", Armed: write.Add(-9 * time.Second)})
		},
		why: "only exception_on_applied_write has apply-then-refuse semantics",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := ghostWorld(t, obs, write, 0x04, tc.arm)
			res, err := NewI3(DefaultParams()).Check(context.Background(), w)
			if err != nil {
				t.Fatalf("I3 returned an error: %v", err)
			}
			if res.Verdict != Fail {
				t.Fatalf("I3 verdict = %s, want FAIL — %s, so the ghost claim is still judged\nreason: %s",
					res.Verdict, tc.why, res.Reason)
			}
			if !strings.HasPrefix(res.Key, "ghost:") {
				t.Errorf("a judged ghost took the exemption's identity: Key = %q", res.Key)
			}
		})
	}
}

// TestI3ReportsTheP1sReasonWhenBothArmFire is the precedence rule, and it
// guards a mislabelling the exemption itself could have introduced.
//
// Two DERs hold the refused value; the apply-then-refuse lie is armed on only
// ONE of them. The lied-to device's copy is explained by the injection and is
// exempt; the other device's copy is not explained by anything and is a genuine
// ghost. The tick's verdict is therefore FAIL — and the sentence printed beside
// it must be the ghost's, not the exemption's. Sharing one `if res.Reason == ""`
// between the arms would have printed "…so this is NOT judged a violation of I3"
// next to a P1 whenever the exempt witness happened to be visited first.
func TestI3ReportsTheP1sReasonWhenBothArmFire(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	ghost := func() UnitView {
		return unitFixture(1, map[uint16][]uint16{
			701: measurementRegs(t, 40_000, 1),
			702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
			704: controlRegs(t, func(v sunspec.View) {
				v.SetEnum("WMaxLimPctEna", 0)
				v.SetFloat("WMaxLimPct", 63)
			}),
		})
	}
	man := NewManifest("both-arms", 4242)
	// Armed on der-lied only. der-honest's copy of 63 has no explanation.
	man.Arm(Fault{ID: "der-lied.exception_on_applied_write#1", Kind: lieApplyThenRefuse,
		Class: ClassPeerLie, Target: "der-lied", Params: map[string]string{"ex_code": "4"},
		Armed: write.Add(-9 * time.Second)})
	led := NewLedger()
	led.NoteWrite(WriteRecord{
		At: write, Credential: "SuperAdministratorSunSpec", Authorized: true,
		Unit: 1, Model: 704, Point: "WMaxLimPct",
		Value: Quantity{Val: 63, Unit: UnitPercent}, Ref: RefWMax,
		Distinctive: true, Refused: true, ExceptionCode: 0x04,
	})
	w := NewWorld(Sources{}, man, led, DefaultParams())
	o := obsFixture(write.Add(2*time.Second), derFixture("der-honest", ghost()), derFixture("der-lied", ghost()))
	o.Faults = man.Snapshot()
	w.Inject(o)

	res, err := NewI3(DefaultParams()).Check(context.Background(), w)
	if err != nil {
		t.Fatalf("I3 returned an error: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("I3 verdict = %s, want FAIL: one device's copy of the refused value is explained by the "+
			"injected lie and the other's is not\nreason: %s", res.Verdict, res.Reason)
	}
	if strings.Contains(res.Reason, "NOT judged a violation") {
		t.Fatalf("a P1 is reported under the EXEMPTION's sentence:\n%s", res.Reason)
	}
	if !strings.Contains(res.Reason, "the refusal did not prevent the value taking effect") {
		t.Errorf("the P1 does not carry the ghost finding's sentence:\n%s", res.Reason)
	}
	if !strings.HasPrefix(res.Key, "ghost:") {
		t.Errorf("the P1 took the exemption's identity: Key = %q", res.Key)
	}
	// The exempted pair must still be disclosed, or a reader would conclude
	// both devices were judged and both failed.
	if !strings.Contains(res.Reason, "were NOT judged") {
		t.Errorf("the P1 does not disclose that another witness was exempted:\n%s", res.Reason)
	}
	var sawExemptList bool
	for _, f := range res.Facts {
		if f.Key == "i3.exempt.writes" && strings.Contains(f.Value, "der-lied") {
			sawExemptList = true
		}
	}
	if !sawExemptList {
		t.Error("the exempted witness is not named in the facts, so the exemption is invisible in the bundle")
	}
}

// TestMonitorReportsOneGhostOnce is the dedup claim end to end, through the real
// Monitor: the same ghost seen on four consecutive ticks is one violation with a
// repeat count of four, not four violations.
func TestMonitorReportsOneGhostOnce(t *testing.T) {
	t.Parallel()
	write := time.Date(2026, 8, 15, 18, 45, 5, 0, time.UTC)
	man := NewManifest("dedup", 4242)
	man.Arm(Fault{ID: "loopback-der.freeze#1", Kind: "freeze", Class: ClassCommLoss, Target: "loopback-der"})
	led := NewLedger()
	led.NoteWrite(WriteRecord{
		At: write, Credential: "SuperAdministratorSunSpec", Role: "SuperAdministratorSunSpec",
		Authorized: true, Unit: 1, Model: 704, Point: "WMaxLimPct",
		Value: Quantity{Val: 63, Unit: UnitPercent}, Ref: RefWMax,
		Distinctive: true, Refused: true, ExceptionCode: 0x04,
	})
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 0)
			v.SetFloat("WMaxLimPct", 63)
		}),
	})
	views := make([]DERView, 4)
	for i := range views {
		views[i] = derFixture("loopback-der", uv)
	}
	src := Sources{DERs: map[string]DERSource{"loopback-der": &scriptedDER{name: "loopback-der", views: views}}}
	w := NewWorld(src, man, led, DefaultParams())
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{NewI3(DefaultParams())}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := m.Tick(context.Background()); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	sum := m.Finalize()
	if len(sum.Violations) != 1 {
		ids := make([]string, 0, len(sum.Violations))
		for _, v := range sum.Violations {
			ids = append(ids, v.Signature())
		}
		t.Fatalf("one ghost observed on four ticks was reported as %d distinct violations (%s) — "+
			"this is the '4 distinct violations' of IW15-031", len(sum.Violations), strings.Join(ids, ", "))
	}
	if got := sum.Repeats[sum.Violations[0].Signature()]; got != 4 {
		t.Errorf("the repeat count is %d, want 4: the finding must collapse to one line WITHOUT losing "+
			"the fact that it was seen four times", got)
	}
}
