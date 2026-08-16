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

// GREEN on a 7xx DER: energize is measured against model 703, and the connect
// half is NAMED as having no register on this generation rather than passed
// over.
func TestBASIC009_On7xxMeasuresEnergizeAndNamesTheConnectAbsence(t *testing.T) {
	m := rowByID(t, "BASIC-009").mode
	if m.Direct == nil {
		t.Fatal("BASIC-009 carries no southbound oracle")
	}
	// The row commands energize=false, so a compliant DER holds ES clear.
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{703: es703(t, false)}))
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 = %s against a 7xx DER holding the commanded de-energized state: %s",
			got.Verdict, findingObserved(got))
	}
	for _, want := range []string{"model 703 ES", "NOT ASSERTED", "opModConnect"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the 7xx verdict does not say %q, so a reader could take the PASS for a statement "+
				"about BOTH axes:\n  %s", want, got.Observed)
		}
	}
	t.Logf("GREEN on 7xx —\n  %s", got.Observed)
}

// RED on a 7xx DER: the row commanded energize=false and the DER's own
// enter-service permission is still set.
func TestBASIC009_On7xxFailsADERStillPermittedToEnergize(t *testing.T) {
	m := rowByID(t, "BASIC-009").mode
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{703: es703(t, true)}))
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-009 = %s against a DER whose 703 ES is still SET after a commanded "+
			"energize=false: %s", got.Verdict, findingObserved(got))
	}
	t.Logf("RED on 7xx —\n  %s", got.Observed)
}

// GREEN on a legacy DER: connect is measured against model 123's Conn, and the
// energize half is NAMED.
//
// THIS TEST USED TO REQUIRE A TRANSCRIPTION CAVEAT and now requires its
// ABSENCE. While lexa-proto's M123_* constants disagreed with the published
// model at every point, this referee was reading different registers than the
// product wrote, and every legacy verdict said so. lexa-proto 32150e1 closed
// that and the caveat is computed rather than fixed prose
// (invariant.DescribeM123Divergence), so it stopped printing on its own — which
// is the heal reaching the evidence. The assertion inverts so that a
// re-divergence is caught HERE too, at the verdict a reader actually sees,
// rather than only in the invariant package's own pin.
func TestBASIC009_OnLegacyMeasuresConnectAndTheTranscriptionCaveatIsGone(t *testing.T) {
	m := rowByID(t, "BASIC-009").mode
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 0)}))
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 = %s against a legacy DER holding the commanded disconnect: %s",
			got.Verdict, findingObserved(got))
	}
	for _, want := range []string{"model 123 Conn", "opModEnergize"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the legacy verdict does not say %q:\n  %s", want, got.Observed)
		}
	}
	if strings.Contains(got.Observed, "TRANSCRIPTION") {
		t.Errorf("the legacy verdict still carries a transcription caveat. The referee and lexa-proto "+
			"agree on model 123's register map since 32150e1, so a caveat here means one of the two has "+
			"moved again — and this verdict is now describing registers the writer did not touch:\n  %s",
			got.Observed)
	}
	t.Logf("GREEN on legacy —\n  %s", got.Observed)
}

func TestBASIC009_OnLegacyFailsADERStillConnected(t *testing.T) {
	m := rowByID(t, "BASIC-009").mode
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 1)}))
	if got.Verdict != certify.Fail {
		t.Fatalf("BASIC-009 = %s against a legacy DER still CONNECTED after a commanded connect=false: %s",
			got.Verdict, findingObserved(got))
	}
	t.Logf("RED on legacy —\n  %s", got.Observed)
}

// An unimplemented Conn (0xFFFF) is not a connect state. Reading it as 65535 !=
// 0 would report the DER as connected and FAIL a device that simply cannot
// answer the question.
func TestBASIC009_AnUnimplementedConnIsNotReadAsConnected(t *testing.T) {
	m := rowByID(t, "BASIC-009").mode
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{sunspec.ModelImmediateCtrl: m123(t, 0xFFFF)}))
	if got.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want a decided FAIL naming the unreadable point: %s",
			got.Verdict, findingObserved(got))
	}
	if strings.Contains(got.Observed, "reads true") {
		t.Errorf("the 0xFFFF not-implemented sentinel was read as a connect state:\n  %s", got.Observed)
	}
}

// A DER serving NEITHER register is a decided FAIL, not an abstention: the
// row's whole subject is what the DER holds, and a Skip there cannot dent the
// verdict.
func TestBASIC009_NeitherAxisObservableIsDecidedNotSkipped(t *testing.T) {
	m := rowByID(t, "BASIC-009").mode
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{}))
	if got.Verdict != certify.Fail || got.Unavailable != "" {
		t.Fatalf("verdict = %s unavailable=%q, want a decided FAIL: %s",
			got.Verdict, got.Unavailable, got.Observed)
	}
	if !strings.Contains(got.Observed, "NEITHER") {
		t.Errorf("the FAIL does not say both axes were unobservable:\n  %s", got.Observed)
	}
	t.Logf("RED — no register for either axis:\n  %s", got.Observed)
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

// The DER's own connection status is REPORTED and must never grade. A 7xx solar
// DER has no path to opModConnect at all, so a row that failed it for still
// reading connected would be blaming the device for a register it does not
// serve — which is the mirror of the defect the whole file closes.
func TestBASIC009_TheDERsOwnConnStIsReportedAndNeverGrades(t *testing.T) {
	m := rowByID(t, "BASIC-009").mode
	// ConnSt=1 (connected) against a commanded connect=false, on a DER whose
	// energize half is compliant. The verdict must stay PASS.
	got := m.Direct.Judge(unitWith(map[uint16][]uint16{
		703: es703(t, false),
		701: meas701(t, 1),
	}))
	if got.Verdict != certify.Pass {
		t.Fatalf("BASIC-009 = %s on a 7xx DER whose 701 ConnSt still reads connected — the status was "+
			"GRADED, and this DER has no opModConnect register to have obeyed: %s",
			got.Verdict, findingObserved(got))
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
