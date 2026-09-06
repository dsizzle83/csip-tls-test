package suitecsip

// directoracle_test.go — BASIC-008 and BASIC-009 stop skipping, proved red then
// green.
//
// Both rows spent their whole life reporting critDEREffectUnobservable's SKIP:
// nothing read the DER, and a Skip is severity 0 in a roll-up that only raises,
// so "nobody measured it" and "it did it" produced the same verdict. The tests
// below drive the SHIPPING rows — fetched from the registry by catalog id, not
// copies of their literals — against register images that a correct DER and a
// broken one would leave behind, and require the two to be distinguished.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/manifest"
	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// sf packs a signed scale factor into its register word. A function because a
// constant conversion of a negative value into uint16 does not compile.
func sf(v int16) uint16 { return uint16(v) }

// pf704 builds a model 704 image holding a fixed power factor on the INJECT
// axis, with the excitation register set to whatever the caller says.
//
// The image is built from the LAYOUT, never from hand-counted offsets, so a
// test fixture cannot disagree with the decoder about where a point lives —
// which is exactly the disagreement legacyctl.go found one model over.
func pf704(t *testing.T, ena bool, pf float64, ext uint16) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	v.SetEnum("PF_SF", sf(-3))
	v.SetEnum("WMaxLimPct_SF", 0)
	v.SetEnum("WSet_SF", sf(2))
	v.SetEnum("WSetPct_SF", 0)
	v.SetEnum("VarSet_SF", sf(1))
	v.SetEnum("VarSetPct_SF", 0)
	v.SetBool("PFWInjEna", ena)
	v.SetFloat("PFWInj_PF", pf)
	v.SetEnum("PFWInj_Ext", ext)
	return regs
}

func unitWith(models map[uint16][]uint16) invariant.UnitView {
	uv := invariant.UnitView{Unit: 1, Regs: map[uint16][]uint16{}, Base: map[uint16]uint16{}}
	for id, regs := range models {
		uv.Models = append(uv.Models, id)
		uv.Regs[id] = regs
	}
	return uv
}

// ── BASIC-008 ───────────────────────────────────────────────────────────────

// TestBASIC008_IsMeasuredAndItIsTheDirectionGraderThatMeasuresIt is the
// construction proof.
func TestBASIC008_IsMeasuredAndItIsTheDirectionGraderThatMeasuresIt(t *testing.T) {
	m := rowByID(t, "BASIC-008").mode
	if m.Direct == nil {
		t.Fatal("BASIC-008 carries no southbound oracle: its whole 'did the DER do it' half is a SKIP, " +
			"which is severity 0 in a roll-up that only raises — the IW15-008 shape")
	}
	if !m.measured() {
		t.Error("BASIC-008 does not report itself measured, so run() will not fire a PostWait read at all")
	}
	if m.Publish == nil {
		t.Error("BASIC-008 lost its publisher; adopting a direct oracle must change what is MEASURED, " +
			"never what is SENT")
	}
	if !strings.Contains(m.Direct.Registers, "PFWInj_Ext") {
		t.Errorf("BASIC-008's oracle does not name the excitation register in its How, so a verdict "+
			"citing direction is not checkable by a reader:\n  %s", m.Direct.Registers)
	}
}

// GREEN: the DER holds the row's magnitude AND the row's direction.
func TestBASIC008_PassesADERThatHoldsBothHalves(t *testing.T) {
	m := rowByID(t, "BASIC-008").mode
	wantReg, _ := wantExt(figure8FixedPF.Excitation)
	uv := unitWith(map[uint16][]uint16{704: pf704(t, true, figure8FixedPF.PF(), wantReg)})

	got := m.Direct.Judge(uv)
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-008 = %s against a DER holding exactly what it commanded: %s",
			got.Verdict, findingObserved(got))
	}
	t.Logf("GREEN — %s", got.Observed)
}

// RED: the magnitude is PERFECT and the device is pointing the other way. This
// is the shape the product actually shipped (a missing negation in publish.go)
// and the shape a magnitude-only referee reports as compliant.
func TestBASIC008_FailsADERPointingTheWrongWayAtTheRightMagnitude(t *testing.T) {
	m := rowByID(t, "BASIC-008").mode
	wantReg, _ := wantExt(figure8FixedPF.Excitation)
	// The OTHER direction, derived from the expectation rather than restated,
	// so this red proof cannot go stale if the row's own excitation flag moves.
	// (The M704_Ext_* constants are untyped, so they need the conversion.)
	wrong := uint16(sunspec.M704_Ext_OverExcited)
	if wantReg == wrong {
		wrong = uint16(sunspec.M704_Ext_UnderExcited)
	}
	uv := unitWith(map[uint16][]uint16{704: pf704(t, true, figure8FixedPF.PF(), wrong)})

	got := m.Direct.Judge(uv)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-008 = %s against a DER holding the commanded MAGNITUDE and the opposite "+
			"DIRECTION — the exact inversion this oracle was written for: %s",
			got.Verdict, findingObserved(got))
	}
	t.Logf("RED — inverted excitation at the right magnitude:\n  %s", got.Observed)
	if !strings.Contains(got.Observed, "WRONG DIRECTION") {
		t.Errorf("the FAIL does not say the direction was wrong, so a reader would look for a magnitude "+
			"defect that is not there:\n  %s", got.Observed)
	}
}

// RED: the axis was never enabled. A DER holding the right numbers in a
// switched-off sync group is running no power factor at all.
func TestBASIC008_FailsADERThatNeverEnabledTheAxis(t *testing.T) {
	m := rowByID(t, "BASIC-008").mode
	wantReg, _ := wantExt(figure8FixedPF.Excitation)
	uv := unitWith(map[uint16][]uint16{704: pf704(t, false, figure8FixedPF.PF(), wantReg)})

	got := m.Direct.Judge(uv)
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-008 = %s against a DER whose PFWInjEna is CLEAR: %s",
			got.Verdict, findingObserved(got))
	}
	t.Logf("RED — right numbers, switched off:\n  %s", got.Observed)
}

// A DER with no model 704 at all is Unavailable rather than Fail: this row's
// 7xx arm has nowhere to read, and the legacy home (M123 OutPFSet) is not yet
// graded. Saying so is the honest answer; a FAIL would blame the DUT for a
// binding this row has not written.
func TestBASIC008_A704LessDERIsUnavailableNotFailed(t *testing.T) {
	m := rowByID(t, "BASIC-008").mode
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{}))
	if got.Unavailable == "" {
		t.Fatalf("a 704-less DER produced verdict %s rather than an unavailability: %s",
			got.Verdict, got.Observed)
	}
	if !strings.Contains(got.Unavailable, "M123 OutPFSet") {
		t.Errorf("the unavailability does not name the legacy home this row does not yet grade, so the "+
			"gap has no owner:\n  %s", got.Unavailable)
	}
}

// ── BASIC-009 ───────────────────────────────────────────────────────────────

// es703 builds a model 703 image whose enter-service permission is set.
func es703(t *testing.T, enabled bool) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L703.Len())
	v := sunspec.L703.View(regs)
	v.SetEnum("V_SF", 0)
	v.SetEnum("Hz_SF", sf(-2))
	v.SetBool("ES", enabled)
	return regs
}

// m123 builds a published-shape model 123 block with the given connect state.
func m123(t *testing.T, conn uint16) []uint16 {
	t.Helper()
	regs := make([]uint16, invariant.M123PublishedLen)
	// Offsets from the PUBLISHED model, the same transcription
	// internal/invariant reads — Conn at 2, WMaxLimPct at 3, WMaxLim_Ena at 7,
	// WMaxLimPct_SF at 21.
	regs[2] = conn
	regs[3] = 10000
	regs[7] = 1
	regs[21] = sf(-2)
	return regs
}

// judgeBASIC009 drives BASIC-009's connect oracle — now the manifest-aware
// JudgeCtx (it grades the DECLARED connect home, model 123) — against a register
// image. The RunCtx carries no manifest, which the oracle treats as "assert
// everything": the grade is against model 123 regardless, and a manifest only
// adds a disclosure line.
func judgeBASIC009(t *testing.T, regs map[uint16][]uint16) Finding {
	t.Helper()
	m := rowByID(t, "BASIC-009").mode
	if m.Direct == nil || m.Direct.JudgeCtx == nil {
		t.Fatal("BASIC-009 carries no manifest-aware connect oracle (JudgeCtx)")
	}
	return m.Direct.JudgeCtx(unitWith(regs), &certify.RunCtx{})
}

// THE HEADLINE FIX: model 703's ES is REPORTED, not graded, so a DER serving
// BOTH 123 and 703 — the advanced fixture — passes on M123 Conn alone even when
// 703's enter-service permission disagrees with the energize published alongside.
// The prior oracle graded 703 and FAILed this DER on the fixture's as-built ES
// default (the BASIC-009 leg of HARNESS-TEARDOWN-CANCEL-ONLY-LEAVES-APPLIED-STATE).
func TestBASIC009_GradesM123ConnNotM703ES(t *testing.T) {
	// connect=false is commanded; the DER holds M123 Conn=0 (disconnected,
	// MATCHES) and 703 ES=SET (enter-service permitted, DISAGREES with the
	// energize=false published alongside). The verdict must be PASS.
	got := judgeBASIC009(t, map[uint16][]uint16{
		sunspec.ModelImmediateCtrl: m123(t, 0),
		703:                        es703(t, true),
	})
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 = %s on a DER whose M123 Conn matches but whose 703 ES disagrees — 703 was "+
			"GRADED, the exact as-built-default FAIL this fix removes: %s", got.Verdict, findingObserved(got))
	}
	for _, want := range []string{"GRADED (opModConnect via model 123", "model 123 Conn reads false",
		"model 703 ES", "REPORTED, not graded"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the verdict does not say %q, so a reader cannot see that M123 was graded and 703 "+
				"only reported:\n  %s", want, got.Observed)
		}
	}
	t.Logf("GREEN — M123 graded, 703 reported —\n  %s", got.Observed)
}

// A DER that does NOT serve the declared connect home (model 123) FAILs: an
// unmeasured GRADED axis is not a pass, however many models are only REPORTED.
func TestBASIC009_WithoutM123FailsTheDeclaredHome(t *testing.T) {
	got := judgeBASIC009(t, map[uint16][]uint16{703: es703(t, false)})
	if got.Verdict != certify.Fail || got.Unavailable != "" {
		t.Fatalf("BASIC-009 = %s unavailable=%q against a DER that does not serve the declared connect "+
			"home model 123, want a decided FAIL: %s", got.Verdict, got.Unavailable, findingObserved(got))
	}
	for _, want := range []string{"model 123 is NOT served", "model 703 ES", "REPORTED, not graded"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not say %q:\n  %s", want, got.Observed)
		}
	}
	t.Logf("RED — declared home absent —\n  %s", got.Observed)
}

// GREEN when model 123's Conn holds the commanded disconnect. The transcription
// caveat must be ABSENT (lexa-proto 32150e1 aligned the map); a re-divergence is
// caught here, at the verdict a reader sees.
func TestBASIC009_GradesM123ConnMatchingDisconnect(t *testing.T) {
	got := judgeBASIC009(t, map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 0)})
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 = %s against a DER holding the commanded disconnect on M123 Conn: %s",
			got.Verdict, findingObserved(got))
	}
	if !strings.Contains(got.Observed, "model 123 Conn reads false") {
		t.Errorf("the verdict does not report the graded M123 Conn read:\n  %s", got.Observed)
	}
	if strings.Contains(got.Observed, "TRANSCRIPTION") {
		t.Errorf("the verdict still carries a transcription caveat — the referee and lexa-proto have "+
			"re-diverged on model 123's map:\n  %s", got.Observed)
	}
	t.Logf("GREEN — M123 Conn matches —\n  %s", got.Observed)
}

func TestBASIC009_FailsADERStillConnected(t *testing.T) {
	got := judgeBASIC009(t, map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 1)})
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-009 = %s against a DER still CONNECTED (M123 Conn=1) after a commanded "+
			"connect=false: %s", got.Verdict, findingObserved(got))
	}
	t.Logf("RED — still connected —\n  %s", got.Observed)
}

// An unimplemented Conn (0xFFFF) is not a connect state. Reading it as 65535 !=
// 0 would report the DER as connected and FAIL a device that cannot answer.
func TestBASIC009_AnUnimplementedConnIsNotReadAsConnected(t *testing.T) {
	got := judgeBASIC009(t, map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 0xFFFF)})
	if got.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want a decided FAIL naming the unreadable point: %s",
			got.Verdict, findingObserved(got))
	}
	if strings.Contains(got.Observed, "reads true") {
		t.Errorf("the 0xFFFF not-implemented sentinel was read as a connect state:\n  %s", got.Observed)
	}
}

// A DER serving no model 123 is a decided FAIL, not an abstention: the declared
// connect home is the row's whole graded subject, and a Skip there cannot dent
// the verdict.
func TestBASIC009_M123AbsentIsDecidedNotSkipped(t *testing.T) {
	got := judgeBASIC009(t, map[uint16][]uint16{})
	if got.Verdict != certify.Fail || got.Unavailable != "" {
		t.Fatalf("verdict = %s unavailable=%q, want a decided FAIL: %s",
			got.Verdict, got.Unavailable, got.Observed)
	}
	if !strings.Contains(got.Observed, "model 123 is NOT served") {
		t.Errorf("the FAIL does not say the declared connect home was unserved:\n  %s", got.Observed)
	}
	t.Logf("RED — no register for the declared home:\n  %s", got.Observed)
}

// meas701 builds a minimal model 701 image with the given ConnSt.
func meas701(t *testing.T, connSt uint16) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L701.Len())
	v := sunspec.L701.View(regs)
	for _, n := range []string{"A_SF", "V_SF", "TotWh_SF", "TotVarh_SF"} {
		v.SetEnum(n, 0)
	}
	v.SetEnum("W_SF", sf(2))
	v.SetEnum("VA_SF", sf(2))
	v.SetEnum("Var_SF", sf(1))
	v.SetEnum("PF_SF", sf(-3))
	v.SetEnum("Hz_SF", sf(-2))
	v.SetEnum("Tmp_SF", 0)
	v.SetEnum("St", 2)
	v.SetEnum("ConnSt", connSt)
	v.SetFloat("W", 0)
	v.SetFloat("Hz", 60)
	return regs
}

// The DER's own model 701 ConnSt is REPORTED and must never grade. The graded
// axis is M123 Conn (the declared home); 701 ConnSt is the device's own account
// of its connection state, which the connect command may reach by a path this
// register does not reflect, so grading it would blame the device for a
// disagreement that is not a conformance failure.
func TestBASIC009_TheDERsOwnConnStIsReportedAndNeverGrades(t *testing.T) {
	// M123 Conn=0 (disconnected) MATCHES the commanded connect=false, while the
	// DER's own 701 ConnSt=1 still reads connected. The verdict must stay PASS —
	// ConnSt is reported, not graded.
	got := judgeBASIC009(t, map[uint16][]uint16{
		sunspec.ModelImmediateCtrl: m123(t, 0),
		701:                        meas701(t, 1),
	})
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 = %s on a DER whose graded M123 Conn matches but whose 701 ConnSt still reads "+
			"connected — the status was GRADED: %s", got.Verdict, findingObserved(got))
	}
	if !strings.Contains(got.Observed, "ConnSt reads 1") {
		t.Errorf("the DER's own connection status is not reported at all, so the verdict omits the one "+
			"fact that answers 'did the machine go off':\n  %s", got.Observed)
	}
	if !strings.Contains(got.Observed, "REPORTED and not graded") {
		t.Errorf("the reading does not disclaim itself, so a reader would take it for an assertion:\n  %s",
			got.Observed)
	}
	t.Logf("REPORTED, not graded —\n  %s", got.Observed)
}

// ── BASIC-009: EITHER connect home (M123 Conn or M703 ES) ───────────────────

// judgeBASIC009Home drives BASIC-009's connect oracle with an explicit -param
// connect-home selector, so a test can grade the connect transition via M123 OR
// via M703 ES on the bench simulator that serves both.
func judgeBASIC009Home(t *testing.T, home string, regs map[uint16][]uint16) Finding {
	t.Helper()
	m := rowByID(t, "BASIC-009").mode
	if m.Direct == nil || m.Direct.JudgeCtx == nil {
		t.Fatal("BASIC-009 carries no manifest-aware connect oracle (JudgeCtx)")
	}
	rc := &certify.RunCtx{Params: map[string]string{connectHomeParam: home}}
	return m.Direct.JudgeCtx(unitWith(regs), rc)
}

// GRADE VIA M703 ES: with -param connect-home=M703 the enter-service permission
// is the GRADED home, judged against the energize published alongside. The row
// commands energize=false, so ES=cleared is the PASS and ES=set is the FAIL —
// the mirror of the M123 Conn grade, on the axis a pure-7xx candidate declares.
func TestBASIC009_GradesM703ESViaSelector(t *testing.T) {
	// ES cleared MATCHES the commanded energize=false -> PASS.
	got := judgeBASIC009Home(t, "M703", map[uint16][]uint16{703: es703(t, false)})
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 via M703 = %s on a DER whose 703 ES matches the commanded energize=false: %s",
			got.Verdict, findingObserved(got))
	}
	for _, want := range []string{"GRADED (opModEnergize via model 703 ES", "model 703 ES", "reads false"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the M703 verdict does not say %q:\n  %s", want, got.Observed)
		}
	}
	t.Logf("GREEN — M703 ES graded —\n  %s", got.Observed)

	// ES SET disagrees with the commanded energize=false -> FAIL.
	red := judgeBASIC009Home(t, "M703", map[uint16][]uint16{703: es703(t, true)})
	if red.Verdict != certify.Fail {
		t.Fatalf("BASIC-009 via M703 = %s on a DER whose 703 ES is SET against a commanded energize=false: %s",
			red.Verdict, findingObserved(red))
	}
	t.Logf("RED — M703 ES set against commanded energize=false —\n  %s", red.Observed)
}

// GRADE VIA M703 but the DER serves no 703: a decided FAIL, not an abstention —
// an unmeasured GRADED axis is not a pass, the same rule the M123 home holds.
func TestBASIC009_M703SelectedButUnserved_IsDecidedFail(t *testing.T) {
	got := judgeBASIC009Home(t, "M703", map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 0)})
	if got.Verdict != certify.Fail || got.Unavailable != "" {
		t.Fatalf("BASIC-009 via M703 with no model 703 = %s unavailable=%q, want a decided FAIL: %s",
			got.Verdict, got.Unavailable, findingObserved(got))
	}
	if !strings.Contains(got.Observed, "model 703 is NOT served") {
		t.Errorf("the FAIL does not name the unserved graded home:\n  %s", got.Observed)
	}
}

// GRADE VIA M123 by explicit selector, even where the DER also serves 703: the
// selector wins and 703 is REPORTED, not graded.
func TestBASIC009_GradesM123ViaSelector(t *testing.T) {
	got := judgeBASIC009Home(t, "M123", map[uint16][]uint16{
		sunspec.ModelImmediateCtrl: m123(t, 0),
		703:                        es703(t, true),
	})
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 via M123 = %s on a DER whose M123 Conn matches and whose 703 ES disagrees: %s",
			got.Verdict, findingObserved(got))
	}
	for _, want := range []string{"GRADED (opModConnect via model 123", "model 123 Conn reads false",
		"model 703 ES", "REPORTED, not graded"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the M123-via-selector verdict does not say %q:\n  %s", want, got.Observed)
		}
	}
}

// TestResolveConnectHome_KeysOffDeclaredModelsAndSelector proves the whole
// decision tree: the -param selector wins, else a single declared connect-home
// model decides, else — BOTH declared or NEITHER — it DECLINES rather than guess.
// A nil manifest defaults to M123 (the pre-manifest behaviour), the one case
// that is not a guess because silence is not an ambiguous declaration.
func TestResolveConnectHome_KeysOffDeclaredModelsAndSelector(t *testing.T) {
	noParam := func(string) (string, bool) { return "", false }
	sel := func(v string) func(string) (string, bool) {
		return func(k string) (string, bool) {
			if k == connectHomeParam {
				return v, true
			}
			return "", false
		}
	}
	mani := func(ids ...int) *manifest.Manifest { return &manifest.Manifest{Models: ids} }

	cases := []struct {
		name  string
		m     *manifest.Manifest
		param func(string) (string, bool)
		want  connectHome
	}{
		{"123 alone -> M123", mani(1, 123, 704), noParam, connectHomeM123},
		{"703 alone -> M703", mani(1, 703, 704), noParam, connectHomeM703},
		{"BOTH declared -> DECLINE (needs selector)", mani(1, 123, 703, 704), noParam, connectHomeUnset},
		{"NEITHER declared -> DECLINE", mani(1, 704), noParam, connectHomeUnset},
		{"nil manifest -> M123 default", nil, noParam, connectHomeM123},
		{"selector M703 beats a 123-only manifest", mani(1, 123), sel("M703"), connectHomeM703},
		{"selector M123 beats a 703-only manifest", mani(1, 703), sel("M123"), connectHomeM123},
		{"selector resolves the both-present ambiguity", mani(1, 123, 703), sel("M703"), connectHomeM703},
		{"bogus selector -> DECLINE, never guess", mani(1, 123), sel("bogus"), connectHomeUnset},
		{"empty selector falls through to the manifest", mani(1, 703), sel("  "), connectHomeM703},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, why := resolveConnectHome(tc.m, tc.param)
			if got != tc.want {
				t.Fatalf("resolveConnectHome = %v, want %v (reason: %s)", got, tc.want, why)
			}
			if got == connectHomeUnset && !strings.Contains(why, connectHomeParam) {
				t.Errorf("a DECLINE does not point the operator at -param %s: %s", connectHomeParam, why)
			}
		})
	}
}

// BOTH-PRESENT NEEDS A SELECTOR, at the row: a run that cannot resolve the home
// (here a bogus selector standing in for the unresolvable both-present manifest
// the resolver test covers directly) DECLINES — Unavailable — rather than grade
// an axis nobody chose. Through the gating direct-oracle path that Unavailable
// becomes a FAIL (oracleOutcome), which is the fail-closed answer.
func TestBASIC009_UnresolvableHomeDeclines(t *testing.T) {
	got := judgeBASIC009Home(t, "M999", map[uint16][]uint16{
		sunspec.ModelImmediateCtrl: m123(t, 0),
		703:                        es703(t, false),
	})
	if got.Unavailable == "" {
		t.Fatalf("an unresolvable connect home produced verdict %s instead of DECLINING: %s",
			got.Verdict, got.Observed)
	}
	for _, want := range []string{"cannot decide which connect home", connectHomeParam} {
		if !strings.Contains(got.Unavailable, want) {
			t.Errorf("the DECLINE does not say %q:\n  %s", want, got.Unavailable)
		}
	}
	t.Logf("DECLINE —\n  %s", got.Unavailable)
}

// THE COMPOSITE — the exact product bug the harness must catch independently:
// the DUT reports the machine went off (model 701 ConnSt=0, and it POSTs a
// DERControlResponse Started(2)) while the GRADED connect home, model 123 Conn,
// still reads connected after a commanded connect=false. A referee that trusted
// the device's own ConnSt would PASS; grading the declared home FAILs, and the
// Started(2) the graded home does not back is withheld (a response-integrity
// FAIL). This is the lexa-gw defect, reproduced with no bench.
func TestBASIC009_Composite_M123RefusesWhileConnStClaimsDisconnected(t *testing.T) {
	const mrid = "CERT-BASIC-009"
	regs := map[uint16][]uint16{
		sunspec.ModelImmediateCtrl: m123(t, 1),   // STILL connected — the disconnect did not take
		701:                        meas701(t, 0), // the DER's own status claims disconnected
	}

	// 1) The connect oracle grades the declared home (M123 Conn), not ConnSt.
	post := judgeBASIC009Home(t, "M123", regs)
	if post.Verdict != certify.Fail {
		t.Fatalf("connect oracle = %s, want FAIL: the graded M123 Conn still reads connected after a "+
			"commanded disconnect, whatever ConnSt claims: %s", post.Verdict, findingObserved(post))
	}
	if !strings.Contains(post.Observed, "model 123 Conn reads true") {
		t.Errorf("the FAIL does not report the graded home still reading connected:\n  %s", post.Observed)
	}
	if !strings.Contains(post.Observed, "ConnSt reads 0") ||
		!strings.Contains(post.Observed, "REPORTED and not graded") {
		t.Errorf("the verdict does not report ConnSt=0 as reported-not-graded, so a reader cannot see the "+
			"device's own claim was disregarded for grading:\n  %s", post.Observed)
	}

	// 2) The response-integrity gate, fed that FAIL post-verdict: a Started(2)
	//    the graded home does not back is a FAIL — the Started is withheld.
	o := &Observation{Params: map[string]string{
		"mrid":              mrid,
		oracleVerdictParam:  string(post.Verdict),
		oracleObservedParam: post.Observed,
	}}
	c := critConnectStartedIntegrity(mrid, o)
	started := &ServerView{Responses: []AdminResponse{{Subject: mrid, Status: 2}}}
	gate := c.Server(started)
	if gate.Verdict != certify.Fail {
		t.Fatalf("started-integrity gate = %s, want FAIL: a Started(2) the graded connect home did not "+
			"reach is a response-integrity defect: %s", gate.Verdict, gate.Observed)
	}
	if !strings.Contains(gate.Observed, "response-integrity") {
		t.Errorf("the gate FAIL does not name the response-integrity defect:\n  %s", gate.Observed)
	}

	// 3) And a CORRECT withhold (no Started(2)) against the same FAIL is a PASS:
	//    the gate fires only on the false Started, never on a device that told
	//    the truth by staying silent.
	withheld := &ServerView{Responses: []AdminResponse{{Subject: mrid, Status: 1}, {Subject: mrid, Status: 252}}}
	if ok := c.Server(withheld); ok.Verdict != certify.Pass {
		t.Fatalf("a correct CannotComply withhold = %s, want PASS: %s", ok.Verdict, ok.Observed)
	}
	t.Logf("composite RED — oracle FAIL + false Started withheld:\n  oracle: %s\n  gate: %s",
		post.Observed, gate.Observed)
}

// ── The legacy widening's blast radius, bounded ─────────────────────────────

// TestRefusalFingerprint_The7xxReadingIsUnchangedByTheLegacyWidening.
//
// refusalFingerprint now reads model 123 as well as model 704, on EVERY scalar
// refusal row (BASIC-014 is the only one today, and the widening exists so a
// legacy bench has something to fingerprint at all). That is a change to a
// criterion the campaign already runs green, so the 7xx reading has to be
// provably untouched: a DER that serves no model 123 must produce exactly the
// 704 rendering it produced before.
func TestRefusalFingerprint_The7xxReadingIsUnchangedByTheLegacyWidening(t *testing.T) {
	points := []string{"WSet", "WSetPct"}
	uv := unitWith(map[uint16][]uint16{704: pf704(t, false, 0, 0)})

	fp, ok := refusalFingerprint(uv, points)
	if !ok {
		t.Fatal("a 704-serving DER produced no fingerprint")
	}
	if strings.Contains(fp, "M123") {
		t.Errorf("a DER that serves no model 123 has an M123 clause in its fingerprint, so every 7xx "+
			"refusal row's baseline text changed:\n  %s", fp)
	}
	for _, p := range points {
		if !strings.Contains(fp, p) {
			t.Errorf("the 704 rendering lost %s:\n  %s", p, fp)
		}
	}
	t.Logf("the 7xx reading, unchanged:\n  %s", fp)
}

// And the legacy reading is the point of the widening: a DER with no 704 at all
// used to produce NO fingerprint, so oracleRefusal reported the axis
// Unavailable and BASIC-014 failed for want of a register to look at.
func TestRefusalFingerprint_ALegacyDERIsMeasurableAtAll(t *testing.T) {
	points := []string{"WSet", "WSetPct"}
	uv := unitWith(map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 1)})

	fp, ok := refusalFingerprint(uv, points)
	if !ok {
		t.Fatal("a legacy DER still produces no fingerprint, so a scalar refusal row on it reports " +
			"Unavailable and FAILS for want of somewhere to look — the bench gap this widening closes")
	}
	for _, want := range []string{"M123", invariant.PointM123Conn} {
		if !strings.Contains(fp, want) {
			t.Errorf("the legacy fingerprint does not carry %q:\n  %s", want, fp)
		}
	}
	// No transcription caveat: the referee and lexa-proto agree on the map
	// since 32150e1, so the fingerprint is over the registers the writer
	// actually moves. It was a required substring here until that landed.
	if strings.Contains(fp, "TRANSCRIPTION") {
		t.Errorf("the legacy fingerprint still carries a transcription caveat:\n  %s", fp)
	}
	t.Logf("the legacy reading, newly measurable:\n  %s", fp)
}

// ── The class, not the two rows ─────────────────────────────────────────────

// TestNoInverterControlRowSkipsItsSouthboundHalf is the structural assertion.
//
// It is the one that keeps this closed. Every row of the twelve now carries an
// apparatus — an oracle, a curve binding, a refusal binding, a direct oracle,
// or a decided authoring-gap FAIL — and a new row added without one would fall
// through to critDEREffectUnobservable's SKIP and roll up as though it had been
// measured. This test fails the moment that happens.
func TestNoInverterControlRowSkipsItsSouthboundHalf(t *testing.T) {
	for _, r := range inverterControlRows() {
		m := r.mode
		switch {
		case m.Unreachable != "":
			// A decided FAIL naming the missing lever — not a Skip.
		case m.measured():
			// An oracle, a curve, a refusal or a direct oracle.
		default:
			t.Errorf("%s (%s) carries no southbound apparatus, so its 'did the DER do it' criterion is "+
				"critDEREffectUnobservable's SKIP — severity 0 in a roll-up that only raises, which is "+
				"absence of measurement reading as success (IW15-008)", r.id, m.Element)
		}
	}
}
