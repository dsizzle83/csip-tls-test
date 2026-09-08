package suitecsip

// teardown_baseline_test.go proves WP7-T6's post-teardown baseline note:
// releaseProgramControls logs (never fails) where the DER's own ceiling axis
// sits once its fence-and-delete is done, and the NEXT row's
// markBaselineContamination folds that note into its own reason — so a
// contamination is attributed to the teardown that actually left it.

import (
	"context"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	model "lexa-proto/csipmodel"
)

func TestLogPostTeardownBaseline_RecordsAReadableRegister(t *testing.T) {
	t.Cleanup(resetTeardownNote)
	resetTeardownNote()

	dev, base := oracleFixture(t)
	// A conformant ApplyControl so the ceiling axis this reads back is a real,
	// decodable one (60% of the fixture's own WMax) rather than the as-built
	// zero — the shape a row's teardown would actually leave behind.
	pc := model.PerCent{Value: 6000} // 60.00%
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "teardown-baseline-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	rc.Case = &certify.Case{UID: "csip-conf-v1.3::BASIC-010", ID: "BASIC-010"}
	d := NewDriver(rc)

	logPostTeardownBaseline(context.Background(), d, []int{0})

	note := lastTeardownNote()
	if note == "" {
		t.Fatal("logPostTeardownBaseline recorded no note against a readable DER")
	}
	for _, want := range []string{"BASIC-010", "[0]", "WMaxLimPct"} {
		if !strings.Contains(note, want) {
			t.Errorf("the teardown note does not contain %q:\n  %s", want, note)
		}
	}
}

func TestLogPostTeardownBaseline_UnreadableDERStillLogsNeverFails(t *testing.T) {
	t.Cleanup(resetTeardownNote)
	resetTeardownNote()

	// No Sims configured at all — oracleUnitView must fail, and this must
	// still produce a NOTE (never a panic, never propagated as an error the
	// caller has to handle: logPostTeardownBaseline returns nothing).
	rc := &certify.RunCtx{Case: &certify.Case{UID: "csip-conf-v1.3::BASIC-013", ID: "BASIC-013"},
		Sims: map[string]*certify.SimClient{}}
	d := NewDriver(rc)

	logPostTeardownBaseline(context.Background(), d, []int{0})

	note := lastTeardownNote()
	if note == "" {
		t.Fatal("logPostTeardownBaseline recorded nothing against an unreadable DER — it must log the " +
			"failure, not silently skip it")
	}
	if !strings.Contains(note, "BASIC-013") || !strings.Contains(note, "could not be read") {
		t.Errorf("the note does not attribute the unreadable read to the row that produced it:\n  %s", note)
	}
}

func TestMarkBaselineContamination_FoldsInTheTeardownNote(t *testing.T) {
	t.Cleanup(resetTeardownNote)
	resetTeardownNote()

	dev, base := oracleFixture(t)
	pc := model.PerCent{Value: 6000} // 60.00%
	if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "teardown-baseline-test"); err != nil {
		t.Fatalf("ApplyControl(opModMaxLimW=6000): %v", err)
	}
	rc := oracleTestRunCtx(t, dev)
	rc.Case = &certify.Case{UID: "csip-conf-v1.3::BASIC-010", ID: "BASIC-010"}
	d := NewDriver(rc)
	logPostTeardownBaseline(context.Background(), d, []int{0})

	params := map[string]string{}
	markBaselineContamination(params, Finding{Verdict: certify.Pass, Observed: "the DER already reads 60%"})

	reason := params[oracleContaminationParam]
	if !strings.Contains(reason, "baseline indistinguishable from target") ||
		!strings.Contains(reason, "residual from prior row?") {
		t.Fatalf("markBaselineContamination dropped its own fixed wording:\n  %s", reason)
	}
	if !strings.Contains(reason, "BASIC-010") {
		t.Errorf("markBaselineContamination did not fold in the teardown note naming the row that left "+
			"the residue:\n  %s", reason)
	}
}

func TestMarkBaselineContamination_NoTeardownNoteYetIsStillWellFormed(t *testing.T) {
	t.Cleanup(resetTeardownNote)
	resetTeardownNote() // the first row of a campaign: no teardown has run

	params := map[string]string{}
	markBaselineContamination(params, Finding{Verdict: certify.Pass, Observed: "the DER already reads 60%"})
	reason := params[oracleContaminationParam]
	if !strings.Contains(reason, "baseline indistinguishable from target") ||
		!strings.Contains(reason, "residual from prior row?") {
		t.Fatalf("markBaselineContamination's fixed wording changed shape with no teardown note present:\n  %s",
			reason)
	}
}
