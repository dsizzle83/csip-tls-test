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

// ── IW15-032: the same property, in the other direction ─────────────────────
//
// IW15-031 made a finding's identity survive the clock. The adversarial gate on
// that change asked the inverse question — whether the new identity now merges
// findings that are genuinely different — and the answer was yes, for every one
// of the ten. [keyer] kept the FIRST identity offered at the worst verdict and
// dropped every later one, so a tick that caught two credentials writing where
// they may not, or two devices sitting over their nameplates, reported ONE
// violation. The second defect had no signature at all: it could not be counted,
// could not be re-identified on a re-run, and could not be shrunk to its own
// minimal reproducer. The reproduction, before the fix, was three lines:
//
//	I4  two accepted writes (read-only/unit1/WMaxLimPct, monitor/unit2/VarSetPct)
//	     -> "accepted:read-only:1:704:WMaxLimPct"                         [1 key]
//	I5  two crossings (sb leaf -> :802, nb leaf -> :5020)
//	     -> "cross-domain-auth:sb-device-leaf:sb-devices->…:69.0.0.2:802"  [1 key]
//	I1  two devices, each over its var rating
//	     -> "over-nameplate:der.inv-a:VarSetPct"      (36 facts, both devices) [1 key]
//
// Two of I1–I10 had a SECOND merge underneath that one, in their own arms: I2's
// convergence/release arms returned the first offending device rather than every
// one, and I8's session/host arms returned a single key string per arm. Both are
// fixed at the source rather than papered over here.

// identityCase is one invariant, its fixture, and the axis on which two of its
// findings must differ. The fixture builds the SAME world at n = 1 and n = 2,
// with n = 2 being n = 1 plus one more genuinely distinct defect — which is what
// lets the test assert the strongest form of the property: the first finding's
// identity must be BYTE-IDENTICAL whether or not the second defect is present.
// A composite "A+B" key would satisfy "two findings, two signatures" and still
// break every shrink attempt that reproduces A alone.
type identityCase struct {
	// name is the invariant and the axis its two findings differ on.
	name string
	// id is the invariant id, for the violations minted below.
	id string
	// params configures both the invariant and the world; several rows need
	// operator-supplied thresholds before their arm asserts anything at all.
	params Params
	// inv builds the checker under test.
	inv func(Params) Invariant
	// world builds a world observed at `at` holding exactly n distinct findings.
	world func(t *testing.T, at time.Time, n int) *World
	// want is the verdict the fixture must reach. It is asserted, so a fixture
	// that silently stopped tripping its invariant fails loudly instead of
	// passing this test with zero findings in both directions.
	want Verdict
}

// TestViolationIdentityCollapsesAndSeparates pins BOTH halves of violation
// identity at once, per invariant, because they are one property and a fix to
// either alone re-breaks the other:
//
//	COLLAPSE   the same finding, observed on three ticks seven seconds apart,
//	           is ONE signature. (IW15-031: timestamps, magnitudes and
//	           renumbering ids must stay out of the key.)
//	SEPARATE   two genuinely distinct findings, observed on ONE tick, are TWO
//	           signatures — and the first one's signature is unchanged by the
//	           second one's presence. (IW15-032: every discriminating field must
//	           be IN the key, and nothing else may be.)
//
// The violations are minted through [violationsOf], the Monitor's own code path,
// so what is asserted here is what a campaign would actually report rather than
// a test-local reimplementation of it.
func TestViolationIdentityCollapsesAndSeparates(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 8, 15, 21, 4, 0, 0, time.UTC)

	for _, tc := range identityCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inv := tc.inv(tc.params)

			sigs := func(at time.Time, n, tick int) ([]string, Result) {
				t.Helper()
				res, err := inv.Check(context.Background(), tc.world(t, at, n))
				if err != nil {
					t.Fatalf("%s returned an error: %v", tc.id, err)
				}
				if res.Verdict != tc.want {
					t.Fatalf("%s verdict = %s, want %s — the fixture no longer trips the invariant, so this "+
						"test would pass on an empty finding set\nreason: %s", tc.id, res.Verdict, tc.want, res.Reason)
				}
				var out []string
				for _, v := range violationsOf(inv, res, ManifestSnapshot{}, at, tick) {
					out = append(out, v.Signature())
				}
				return out, res
			}

			// ── direction 1: one finding, three ticks, ONE signature ────────
			var over3Ticks []string
			for i := 0; i < 3; i++ {
				got, res := sigs(t0.Add(time.Duration(i)*7*time.Second), 1, i+1)
				if len(got) != 1 {
					t.Fatalf("tick %d: one defect was reported as %d violations (keys %v)", i+1, len(got), res.Keys)
				}
				over3Ticks = append(over3Ticks, got[0])
			}
			for i := 1; i < len(over3Ticks); i++ {
				if over3Ticks[i] != over3Ticks[0] {
					t.Fatalf("the same finding took signature %s at tick 1 and %s at tick %d — an identity that "+
						"moves with the clock is the IW15-031 defect, and the shrinker cannot re-identify it",
						over3Ticks[0], over3Ticks[i], i+1)
				}
			}

			// ── direction 2: two findings, one tick, TWO signatures ─────────
			got, res := sigs(t0, 2, 1)
			// The counterfactual first, so a fixture that quietly stopped
			// exercising the merge fails here rather than passing the property
			// for the wrong reason. legacyIdentities is the identity function
			// EXACTLY as it stood at 2a9752b — first offer at the worst verdict
			// wins outright — and it must report ONE finding where the fixed one
			// reports two. If it does not, the two findings are not arriving in
			// one Check call and this row is testing nothing.
			if legacy := legacyIdentities(res); len(legacy) != 1 {
				t.Fatalf("the pre-fix identity function reported %d findings (%v) for this fixture; the merge "+
					"it is supposed to reproduce needs both findings in ONE check", len(legacy), legacy)
			}
			distinct := map[string]bool{}
			for _, s := range got {
				distinct[s] = true
			}
			if len(distinct) != 2 {
				t.Fatalf("two genuinely distinct findings (%s) collapsed to %d signature(s): keys %v\n"+
					"a campaign that found two defects would report %d — the second is not merely a duplicate "+
					"ticket, it has no identity at all and can be neither counted nor shrunk",
					tc.name, len(distinct), res.Keys, len(distinct))
			}
			if !distinct[over3Ticks[0]] {
				t.Errorf("the first finding's signature CHANGED when a second, unrelated defect appeared "+
					"(%s alone, %v together) — a composite identity like that fails the shrinker's confirm "+
					"step the moment a subset reproduces one finding without the other",
					over3Ticks[0], got)
			}
		})
	}
}

// identityCases builds the table. Each fixture is written so that n = 2 differs
// from n = 1 by exactly one added defect, on the axis named in the case name.
func identityCases() []identityCase {
	failsafeParams := DefaultParams()
	failsafeParams.Values["failsafe_wmaxlimpct"] = "0"
	failsafeParams.Values["failsafe_deadline"] = "30s"

	budgetParams := DefaultParams()
	budgetParams.Values["recovery_budget"] = "60s"

	return []identityCase{{
		// I1: two devices, each holding an absolute var count in a percent field.
		name: "I1/two devices over their own nameplates",
		id:   "I1", params: DefaultParams(), inv: NewI1, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			over := func() UnitView {
				return unitFixture(1, map[uint16][]uint16{
					701: measurementRegs(t, 40_000, 1),
					702: nameplateRegs(t, 100_000, 2_000, 2_000, 110_000),
					704: controlRegs(t, func(v sunspec.View) {
						v.SetEnum("VarSetEna", 1)
						v.SetEnum("VarSetMod", sunspec.M704_VarSetMod_VarMaxPct)
						v.SetFloat("VarSetPct", 3000) // 3000 "vars" in a percent field
					}),
				})
			}
			w := NewWorld(Sources{}, nil, nil, DefaultParams())
			w.Inject(obsFixture(at, ders(n, func(name string) DERView {
				return derFixture(name, over())
			})...))
			return w
		},
	}, {
		// I2: two devices that both sat out the convergence deadline.
		name: "I2/two devices that never reached failsafe",
		id:   "I2", params: failsafeParams, inv: NewI2, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			faults := NewManifest("identity", 1)
			faults.Arm(Fault{ID: "he.outage#1", Kind: "outage", Class: ClassAuthorityLoss,
				Target: "head-end", Armed: at.Add(-5 * time.Minute), Recoverable: true})
			exporting := func() UnitView {
				return unitFixture(1, map[uint16][]uint16{
					701: measurementRegs(t, 90_000, 1),
					702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
					704: controlRegs(t, func(v sunspec.View) {
						v.SetEnum("WMaxLimPctEna", 1)
						v.SetFloat("WMaxLimPct", 90) // not the configured failsafe of 0
					}),
				})
			}
			w := NewWorld(Sources{}, faults, nil, failsafeParams)
			w.Inject(obsFixture(at, ders(n, func(name string) DERView {
				return derFixture(name, exporting())
			})...))
			return w
		},
	}, {
		// I3: one refused write, two witnesses holding the refused value. The
		// fix reaches I3 through the shared keyer without i3.go changing.
		name: "I3/one refused write, two witnesses holding it",
		id:   "I3", params: DefaultParams(), inv: NewI3, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			write := at.Add(-2 * time.Second)
			ghost := func() UnitView {
				return unitFixture(1, map[uint16][]uint16{
					701: measurementRegs(t, 40_000, 1),
					702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
					704: controlRegs(t, func(v sunspec.View) {
						v.SetEnum("WMaxLimPctEna", 0) // refused, so nothing enabled it…
						v.SetFloat("WMaxLimPct", 63)  // …and the value is in the register
					}),
				})
			}
			led := NewLedger()
			led.NoteWrite(WriteRecord{
				At: write, Credential: "SuperAdministratorSunSpec", Role: "SuperAdministratorSunSpec",
				Authorized: true, Unit: 1, Model: 704, Point: "WMaxLimPct",
				Value: Quantity{Val: 63, Unit: UnitPercent}, Ref: RefWMax,
				Distinctive: true, Refused: true, ExceptionCode: 0x04,
			})
			w := NewWorld(Sources{}, NewManifest("identity", 4242), led, DefaultParams())
			w.Inject(obsFixture(at, ders(n, func(name string) DERView {
				return derFixture(name, ghost())
			})...))
			return w
		},
	}, {
		// I4: two credentials that had no business writing, and both were let in.
		name: "I4/two credentials whose writes were accepted",
		id:   "I4", params: DefaultParams(), inv: NewI4, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			l := NewLedger()
			l.NoteWrite(WriteRecord{At: at, Credential: "read-only", Role: "ReadOnlySunSpec",
				Authorized: false, Unit: 1, Model: 704, Point: "WMaxLimPct",
				Value: Q(10, UnitPercent), Accepted: true})
			if n > 1 {
				l.NoteWrite(WriteRecord{At: at, Credential: "monitor", Role: "MonitorSunSpec",
					Authorized: false, Unit: 2, Model: 704, Point: "VarSetPct",
					Value: Q(20, UnitPercent), Accepted: true})
			}
			w := NewWorld(Sources{}, nil, l, DefaultParams())
			w.Inject(obsFixture(at))
			return w
		},
	}, {
		// I4's OTHER arm, which merged one level deeper than the keyer did: a
		// device that leaks why it denied you at the handshake AND in-session
		// has two leaks to plug, and the arm named only the first stage.
		name: "I4/two stages leaking their denial shape",
		id:   "I4", params: DefaultParams(), inv: NewI4, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			l := NewLedger()
			// handshake: two causes, two shapes — one leak.
			l.NoteAuth(AuthRecord{At: at, Credential: "expired", CredDomain: "nb", TargetDomain: "nb",
				Cause: CauseExpired, Stage: "handshake", ClosedConn: true, TLSAlert: "certificate_expired"})
			l.NoteAuth(AuthRecord{At: at, Credential: "wrong-ca", CredDomain: "nb", TargetDomain: "nb",
				Cause: CauseWrongCA, Stage: "handshake", ClosedConn: true, TLSAlert: "unknown_ca"})
			if n > 1 {
				// authz: two causes, two exception codes — a second, separate leak.
				l.NoteAuth(AuthRecord{At: at, Credential: "no-role", CredDomain: "nb", TargetDomain: "nb",
					Cause: CauseNoRole, Stage: "authz", ExceptionCode: 0x01})
				l.NoteAuth(AuthRecord{At: at, Credential: "read-only", CredDomain: "nb", TargetDomain: "nb",
					Cause: CauseWrongRole, Stage: "authz", ExceptionCode: 0x02})
			}
			w := NewWorld(Sources{}, nil, l, DefaultParams())
			w.Inject(obsFixture(at))
			return w
		},
	}, {
		// I5: the same separation failing in both directions is two failures.
		name: "I5/two credentials crossing two trust boundaries",
		id:   "I5", params: DefaultParams(), inv: NewI5, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			l := NewLedger()
			l.NoteAuth(AuthRecord{At: at, Credential: "sb-device-leaf", CredDomain: "sb-devices",
				TargetDomain: "nb-mbaps-clients", Target: "69.0.0.2:802", Authenticated: true,
				Detail: "the session served a read of model 702"})
			if n > 1 {
				l.NoteAuth(AuthRecord{At: at, Credential: "nb-client-leaf", CredDomain: "nb-mbaps-clients",
					TargetDomain: "sb-devices", Target: "69.0.0.20:5020", Authenticated: true,
					Detail: "the session served a read of model 701"})
			}
			w := NewWorld(Sources{}, nil, l, DefaultParams())
			w.Inject(obsFixture(at))
			return w
		},
	}, {
		// I6: two devices that came back from the interruption unreadable.
		name: "I6/two witnesses unparseable after one interruption",
		id:   "I6", params: DefaultParams(), inv: NewI6, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			l := NewLedger()
			l.NoteRestart(RestartRecord{At: at.Add(-2 * time.Minute), Cause: "campaign",
				Detail: "the campaign power-cycled the gateway"})
			w := NewWorld(Sources{}, nil, l, DefaultParams())
			w.Inject(obsFixture(at, ders(n, func(name string) DERView {
				return DERView{Name: name, Source: "modbus:test/" + name, Reachable: true,
					Unit: UnitView{Unit: 1, Err: "the SunSpec model chain walked off the end of the map"}}
			})...))
			return w
		},
	}, {
		// I7: two controls acknowledged as done, neither of them done.
		name: "I7/two acknowledged controls with no effect",
		id:   "I7", params: DefaultParams(), inv: NewI7, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			w := NewWorld(Sources{}, nil, nil, DefaultParams())
			o := obsFixture(at, derFixture("inv", idleDER(t)))
			o.HeadEnd = ackedControls(at, n)
			w.Inject(o)
			return w
		},
	}, {
		// I8: two devices whose session tables only ever climb.
		name: "I8/two DERs leaking sessions",
		id:   "I8", params: DefaultParams(), inv: NewI8, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			w := NewWorld(Sources{}, nil, nil, DefaultParams())
			for i := 0; i < 3; i++ {
				sessions := i * 10 // 0 -> 10 -> 20: monotone, and past the leak floor
				w.Inject(obsFixture(at.Add(time.Duration(i-2)*time.Minute), ders(n, func(name string) DERView {
					return DERView{Name: name, Source: "simapi:test/" + name, Reachable: true,
						Unit: unitFixture(1, nil), HasSessions: true, Sessions: sessions}
				})...))
			}
			return w
		},
	}, {
		// I9: two channels that were knocked down and never came back.
		name: "I9/two channels that never recovered",
		id:   "I9", params: budgetParams, inv: NewI9, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			cleared := at.Add(-5 * time.Minute)
			faults := NewManifest("identity", 99)
			for _, name := range names(n) {
				id := faults.Arm(Fault{Kind: "outage", Class: ClassCommLoss, Target: name,
					Armed: at.Add(-10 * time.Minute), Recoverable: true})
				faults.Clear(id, cleared)
			}
			w := NewWorld(Sources{}, faults, nil, budgetParams)
			for i := 0; i < 3; i++ {
				w.Inject(obsFixture(cleared.Add(time.Duration(i)*time.Minute), ders(n, func(name string) DERView {
					return DERView{Name: name, Source: "simapi:test/" + name, Reachable: true,
						Unit: unitFixture(1, nil), HasPollCount: true, PollRequests: 900} // frozen
				})...))
			}
			w.Inject(obsFixture(at, ders(n, func(name string) DERView {
				return DERView{Name: name, Source: "simapi:test/" + name, Reachable: true,
					Unit: unitFixture(1, nil), HasPollCount: true, PollRequests: 900}
			})...))
			return w
		},
	}, {
		// I10: two controls each applied on one axis of two.
		name: "I10/two controls applied in part",
		id:   "I10", params: DefaultParams(), inv: NewI10, want: Fail,
		world: func(t *testing.T, at time.Time, n int) *World {
			// The device meets the watt axis (30 kW under a 40 kW limit) and
			// ignores the var axis, for every control served.
			uv := unitFixture(1, map[uint16][]uint16{
				701: measurementRegs(t, 30_000, 1),
				702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
				704: controlRegs(t, func(v sunspec.View) {
					v.SetEnum("WMaxLimPctEna", 1)
					v.SetFloat("WMaxLimPct", 30)
					v.SetEnum("VarSetEna", 0)
				}),
			})
			w := NewWorld(Sources{}, nil, nil, DefaultParams())
			o := obsFixture(at, derFixture("inv", uv))
			o.HeadEnd = partialControls(at, n)
			w.Inject(o)
			return w
		},
	}}
}

// names returns the first n fixture device names. They are distinct strings
// with a common prefix so a merged identity is obvious when a failure prints it.
func names(n int) []string {
	all := []string{"inv-a", "inv-b"}
	return all[:n]
}

// ders builds one DERView per fixture name with build.
func ders(n int, build func(name string) DERView) []DERView {
	var out []DERView
	for _, name := range names(n) {
		out = append(out, build(name))
	}
	return out
}

// idleDER is a device that is applying nothing at all: whatever the head-end
// claims was carried out, this device did not carry it out.
func idleDER(t *testing.T) UnitView {
	t.Helper()
	return unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 90_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 0)
			v.SetEnum("VarSetEna", 0)
		}),
	})
}

// ackedControls serves n active export limits and reports success for every one
// of them — I7's acknowledgement arm, n findings deep.
func ackedControls(at time.Time, n int) HeadEndView {
	head := HeadEndView{Source: "gridsim-admin:test", Reachable: true, ServerTime: at,
		Programs: []Program{{MRID: "DERP-SP-001", Primacy: 1}}}
	for _, mrid := range []string{"CTRL-ACK-A", "CTRL-ACK-B"}[:n] {
		lim := 40_000.0
		head.Programs[0].Active = append(head.Programs[0].Active, Ctrl{
			MRID: mrid, Start: at.Add(-time.Minute), Duration: 3600,
			Base: CtrlBase{ExpLimW: &lim},
		})
		head.Responses = append(head.Responses, Response{Subject: mrid, Status: 2})
	}
	return head
}

// partialControls serves n active controls that each ask for two axes — I10's
// partial-apply arm, n findings deep.
func partialControls(at time.Time, n int) HeadEndView {
	head := HeadEndView{Source: "gridsim-admin:test", Reachable: true, ServerTime: at,
		Programs: []Program{{MRID: "DERP-SP-001", Primacy: 1}}}
	for _, mrid := range []string{"CTRL-PARTIAL-A", "CTRL-PARTIAL-B"}[:n] {
		lim, varPct := 40_000.0, 25.0
		head.Programs[0].Active = append(head.Programs[0].Active, Ctrl{
			MRID: mrid, Start: at.Add(-time.Minute), Duration: 3600,
			Base: CtrlBase{ExpLimW: &lim, FixedVarPct: &varPct},
		})
	}
	return head
}

// legacyIdentities is [Result.identities] EXACTLY as it stood at 2a9752b: one
// check produced one identity, the first offered at the worst verdict, and
// every later one was discarded. It survives here for the same reason
// legacySignature does — a regression test with no before-state proves nothing,
// and this one has to show that its fixtures really do put two findings inside
// one Check call.
func legacyIdentities(res Result) []string {
	if res.Key == "" {
		return nil
	}
	return []string{res.Key}
}

// TestMonitorReportsTwoDefectsTwice is the other half of
// [TestMonitorReportsOneGhostOnce], through the same real Monitor: two distinct
// defects observed on four consecutive ticks are TWO violations with a repeat
// count of four each — not one violation, and not eight.
//
// The two claims are checked together on purpose. Dedup that merges everything
// and dedup that merges nothing both produce a "clean" run summary, and only a
// test that holds a run containing both shapes can tell them apart.
func TestMonitorReportsTwoDefectsTwice(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 15, 21, 30, 0, 0, time.UTC)
	man := NewManifest("two-defects", 4242)
	man.Arm(Fault{ID: "dut.rbac_flip#1", Kind: "rbac_flip", Class: ClassAuthorityLoss, Target: "dut"})
	led := NewLedger()
	led.NoteWrite(WriteRecord{At: at, Credential: "read-only", Role: "ReadOnlySunSpec",
		Authorized: false, Unit: 1, Model: 704, Point: "WMaxLimPct",
		Value: Q(10, UnitPercent), Accepted: true})
	led.NoteWrite(WriteRecord{At: at, Credential: "monitor", Role: "MonitorSunSpec",
		Authorized: false, Unit: 2, Model: 704, Point: "VarSetPct",
		Value: Q(20, UnitPercent), Accepted: true})

	// A plain, conformant device, so the only findings in the run are the two
	// the ledger describes. Neither write is marked Distinctive, so I4's
	// by-any-path arm has nothing to look for at the witness and only the
	// accepted-write arm fires.
	uv := unitFixture(1, map[uint16][]uint16{
		701: measurementRegs(t, 40_000, 1),
		702: nameplateRegs(t, 100_000, 44_000, 44_000, 110_000),
		704: controlRegs(t, func(v sunspec.View) {
			v.SetEnum("WMaxLimPctEna", 1)
			v.SetFloat("WMaxLimPct", 60)
		}),
	})
	views := make([]DERView, 4)
	for i := range views {
		views[i] = derFixture("inv", uv)
	}
	src := Sources{DERs: map[string]DERSource{"inv": &scriptedDER{name: "inv", views: views}}}
	w := NewWorld(src, man, led, DefaultParams())
	m, err := NewMonitor(MonitorConfig{World: w, Checks: []Invariant{NewI4(DefaultParams())}, Cadence: time.Millisecond})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := m.Tick(context.Background()); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	sum := m.Finalize()
	if len(sum.Violations) != 2 {
		keys := make([]string, 0, len(sum.Violations))
		for _, v := range sum.Violations {
			keys = append(keys, v.Key)
		}
		t.Fatalf("two credentials whose writes were ACCEPTED were reported as %d violation(s) (%v) — "+
			"one of two P1s is missing from the count a gate reads", len(sum.Violations), keys)
	}
	for _, v := range sum.Violations {
		if got := sum.Repeats[v.Signature()]; got != 4 {
			t.Errorf("%s: repeat count %d, want 4 — each finding must collapse across ticks even while the "+
				"two of them stay apart", v.Key, got)
		}
		// The shared sentence must not read as a duplicate report: the rendered
		// violation has to name its own identity and disclose the cohort.
		out := v.String()
		if !strings.Contains(out, "identity: "+v.Key) {
			t.Errorf("the rendered violation does not name its identity, so two siblings sharing one "+
				"sentence are indistinguishable to a reader:\n%s", out)
		}
		if !strings.Contains(out, "cohort  : this check reported 2 distinct findings") {
			t.Errorf("the rendered violation does not disclose that the sentence and facts are the whole "+
				"tick's:\n%s", out)
		}
	}
	if sum.Violations[0].Signature() == sum.Violations[1].Signature() {
		t.Fatal("the two violations share a signature")
	}
	if !strings.Contains(sum.Why, "2 distinct invariant violations") {
		t.Errorf("the run's bottom line does not count both P1s: %q", sum.Why)
	}
}
