package suitemodbusserver

// checks_crv_test.go proves CRV-1's per-model sub-verdicts over the legacy 12x
// family the gateway's Stage-6 read-only projection serves.
//
// Every test here comes in the pair this package insists on: one against a
// device built to the posture, and one against a device broken in exactly the
// way the check exists to catch. The second is the one that matters. A check
// that reported PASS for "the write was refused" without ever looking at the
// answer would be green against a conformant device too, so
// TestCRV1_AnAcknowledgedLegacyWriteIsAFailure exists to make that check FAIL
// on demand — and it fails for the right reason, on the right model, while its
// eight siblings still pass.

import (
	"testing"

	"csip-tls-test/internal/certify"
	"lexa-proto/mbap"
)

// crv1UID is the catalog row these tests bind checkCRV1 to.
const crv1UID = "ss-modbus-conf-v1.4::CRV-1"

// legacyServed is the set of legacy models the projection serves, in the order
// the gateway chains them. 133 is deliberately absent — see curveModels.
var legacyServed = []uint16{126, 127, 128, 129, 130, 131, 132, 134, 160}

// TestCurveModelsCoversTheLegacyRangeWithoutInventingIt pins the table itself.
// A missing entry would make CRV-1 silently skip a model in the range the
// procedure sweeps, which is the failure mode this whole change exists to
// remove, and an entry claiming 133 is served would make it report a subject
// the DUT cannot have.
func TestCurveModelsCoversTheLegacyRangeWithoutInventingIt(t *testing.T) {
	for _, id := range legacyServed {
		cm, ok := curveModels[id]
		if !ok {
			t.Errorf("model %d is not in curveModels, so CRV-1 would never report it", id)
			continue
		}
		if cm.Gen != curveGenLegacy {
			t.Errorf("model %d is not marked legacy", id)
		}
		if !cm.Served {
			t.Errorf("model %d is marked not-served; the projection serves all nine", id)
		}
		if !cm.HasProbe() {
			t.Errorf("model %d carries no probe point, so its read-only posture could not be verified", id)
		}
		if cm.Probe.Regs() != 1 {
			t.Errorf("model %d's probe %s is %d registers; a multi-register probe would be refused for "+
				"being a partial-point write and the refusal would mean something else",
				id, cm.Probe.Name, cm.Probe.Regs())
		}
	}

	cm, ok := curveModels[133]
	if !ok {
		t.Fatal("model 133 is absent from curveModels, so CRV-1 would leave a silent hole in the " +
			"126-134 range instead of a named row")
	}
	if cm.Served {
		t.Error("model 133 is marked served; the projection registers no layout for it")
	}
	if cm.NotServed == "" {
		t.Error("model 133 is not served and carries no reason, which is the silence this row exists to avoid")
	}
	if cm.HasProbe() {
		t.Error("model 133 carries a probe point for a model that cannot be reached")
	}

	// The 7xx half is unchanged: still no probe, because CRV-1's steps 2 and 3
	// there are about curve 1 specifically and curve 1 cannot be located.
	for _, id := range []uint16{705, 706, 707, 708, 709, 710, 711, 712} {
		c7, ok := curveModels[id]
		if !ok {
			t.Errorf("model %d fell out of curveModels", id)
			continue
		}
		if c7.HasProbe() {
			t.Errorf("model %d gained a probe point; locating one needs the runtime geometry this suite "+
				"does not transcribe", id)
		}
	}
}

// TestCRV1_LegacyModelsAreVerifiedReadOnly is the green case: nine served
// models, each readable end to end and each refusing a write of the value it
// already holds, before any acknowledgement.
func TestCRV1_LegacyModelsAreVerifiedReadOnly(t *testing.T) {
	dev := newDevice(t, deviceOpts{LegacyModels: true})
	o := runCheck(t, crv1UID, checkCRV1, dev, nil)
	o.wantVerdict(t, certify.Pass)

	for _, id := range legacyServed {
		a := o.assertion(t, claimTag(id))
		if a.Verdict != certify.Pass {
			t.Errorf("model %d: verdict %s, want PASS\n  observed: %s", id, a.Verdict, a.Observed)
		}
		if !contains(a.Observed, "exception response") {
			t.Errorf("model %d: the sub-verdict does not cite the refusal it rests on: %s", id, a.Observed)
		}
		if !a.Citable() {
			t.Errorf("model %d: the sub-verdict carries no re-checkable digest", id)
		}
	}

	// The two refusal ladders are reported as the different gates they are, not
	// collapsed into "an error came back".
	if a := o.assertion(t, claimTag(126)); !contains(a.Observed, "SUN-002") {
		t.Errorf("126's 0x02 refusal is not attributed to the executor gate: %s", a.Observed)
	}
	if a := o.assertion(t, claimTag(160)); !contains(a.Observed, "no commanded group") {
		t.Errorf("160's 0x03 refusal is not attributed to the write decoder: %s", a.Observed)
	}

	// 133 is named, with the structural reason, rather than omitted.
	a := o.assertion(t, claimTag(133))
	if a.Verdict != certify.Skip {
		t.Errorf("133: verdict %s, want SKIP", a.Verdict)
	}
	if !contains(a.Observed, "registers no layout") {
		t.Errorf("133's row does not say why it is unreachable: %s", a.Observed)
	}

	// The row-level curve-1 criteria are still unasserted and still say so.
	for _, claim := range []string{crv1ClaimReadOnly, crv1ClaimRefused} {
		if got := o.assertion(t, claim); got.Verdict != certify.Skip {
			t.Errorf("%q reported %s; this suite cannot locate curve 1 on either generation",
				claim, got.Verdict)
		}
	}
	o.wantVerifiableBundle(t)
}

// TestCRV1_AnAcknowledgedLegacyWriteIsAFailure is the red proof. One model
// applies the write instead of refusing it — the ack-then-store defect the D4
// posture forbids — and CRV-1 must FAIL, on that model, while the other eight
// still pass. A check that graded on the register's later value rather than on
// the response type would pass here, because the value written is the value
// that was already there.
func TestCRV1_AnAcknowledgedLegacyWriteIsAFailure(t *testing.T) {
	dev := newDevice(t, deviceOpts{LegacyModels: true, LegacyAcceptWrite: 126})
	o := runCheck(t, crv1UID, checkCRV1, dev, nil)
	o.wantVerdict(t, certify.Fail)

	a := o.assertion(t, claimTag(126))
	if a.Verdict != certify.Fail {
		t.Fatalf("126: verdict %s, want FAIL\n%s", a.Verdict, o.dump())
	}
	if !contains(a.Observed, "ANSWERED THE WRITE NORMALLY") {
		t.Errorf("126's failure does not name the acknowledgement it rests on: %s", a.Observed)
	}
	if !a.Citable() {
		t.Error("126's failure carries no re-checkable digest")
	}

	// Scoped to the model that broke: a blanket failure would prove nothing
	// about where the check is looking.
	for _, id := range []uint16{127, 128, 129, 130, 131, 132, 134, 160} {
		if got := o.assertion(t, claimTag(id)); got.Verdict != certify.Pass {
			t.Errorf("model %d: verdict %s, want PASS — only 126 was broken", id, got.Verdict)
		}
	}
	o.wantVerifiableBundle(t)
}

// TestCRV1_AnAcknowledgedWriteWithABadEchoIsStillAnAcknowledgement is the
// second red proof, and the one that pins WHERE the check looks. The device
// applies the write and answers it with a normal FC 6 response carrying a
// corrupted echo — so the client library returns an error, exactly as it does
// for a refusal. A check that read "refused or not" off that error would call
// this a PASS. Reading the response's function code instead calls it what it
// is.
func TestCRV1_AnAcknowledgedWriteWithABadEchoIsStillAnAcknowledgement(t *testing.T) {
	dev := newDevice(t, deviceOpts{LegacyModels: true, LegacyEchoWrong: 132})
	o := runCheck(t, crv1UID, checkCRV1, dev, nil)
	o.wantVerdict(t, certify.Fail)

	a := o.assertion(t, claimTag(132))
	if a.Verdict != certify.Fail {
		t.Fatalf("132: verdict %s, want FAIL\n%s", a.Verdict, o.dump())
	}
	if !contains(a.Observed, "ACKNOWLEDGED") {
		t.Errorf("132's failure does not identify the answer as an acknowledgement: %s", a.Observed)
	}
	if !contains(a.Observed, "echo was also malformed") {
		t.Errorf("132's failure drops the framing defect it also observed: %s", a.Observed)
	}
}

// TestCRV1_AModelThisUnitDoesNotCarryIsNamedNotSilent covers the two kinds of
// absence, which must not read alike: 130 is missing because this unit's DER
// does not serve it, and 133 is missing because no unit of any build can carry
// one.
func TestCRV1_AModelThisUnitDoesNotCarryIsNamedNotSilent(t *testing.T) {
	dev := newDevice(t, deviceOpts{LegacyModels: true, LegacyOmit: []uint16{130}})
	o := runCheck(t, crv1UID, checkCRV1, dev, nil)
	o.wantVerdict(t, certify.Pass)

	absent := o.assertion(t, claimTag(130))
	if absent.Verdict != certify.Skip {
		t.Errorf("130: verdict %s, want SKIP", absent.Verdict)
	}
	if !contains(absent.Observed, "if and only if its own DER serves it") {
		t.Errorf("130's absence is not attributed to the device-conditional chain: %s", absent.Observed)
	}
	if contains(absent.Observed, "registers no layout") {
		t.Errorf("130's device-conditional absence was reported as a structural one: %s", absent.Observed)
	}

	never := o.assertion(t, claimTag(133))
	if contains(never.Observed, "if and only if its own DER serves it") {
		t.Errorf("133's structural absence was reported as device-conditional: %s", never.Observed)
	}

	// The eight the unit does carry are still verified.
	for _, id := range []uint16{126, 127, 128, 129, 131, 132, 134, 160} {
		if got := o.assertion(t, claimTag(id)); got.Verdict != certify.Pass {
			t.Errorf("model %d: verdict %s, want PASS", id, got.Verdict)
		}
	}
	o.wantVerifiableBundle(t)
}

// TestCRV1_AnAuthorizationDenialIsNotAPass. Exception 0x01 is how this product
// expresses an authorization denial: the write never reached the write path, so
// the read-only posture was not exercised. A suite that counted any exception
// as a refusal would report a PASS it did not earn, and the difference is the
// whole point of the ladder in gradeWrite.
func TestCRV1_AnAuthorizationDenialIsNotAPass(t *testing.T) {
	dev := newDevice(t, deviceOpts{LegacyModels: true, LegacyDenyCode: mbap.ExIllegalFunction})
	o := runCheck(t, crv1UID, checkCRV1, dev, nil)
	o.wantVerdict(t, certify.Warn)

	a := o.assertion(t, claimTag(126))
	if a.Verdict != certify.Warn {
		t.Fatalf("126: verdict %s, want WARN\n%s", a.Verdict, o.dump())
	}
	if !contains(a.Observed, "AUTHORIZATION denial") {
		t.Errorf("126's inconclusive result does not say what it could not reach: %s", a.Observed)
	}
}

// TestCRV1_WithNoCurveModelAtAllStillReportsTheWholeRange. A unit whose DER
// serves no curve model of either generation has no subject for the procedure —
// and the report still has to account for all ten numbers, because a reader
// checking coverage cannot tell an absent model from an unexamined one.
func TestCRV1_WithNoCurveModelAtAllStillReportsTheWholeRange(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, crv1UID, checkCRV1, dev, nil)
	o.wantVerdict(t, certify.Skip)

	if got := o.assertion(t, crv1ClaimSubject); got.Verdict != certify.Skip {
		t.Errorf("the precondition reported %s on a unit with no curve model", got.Verdict)
	}
	for _, id := range []uint16{126, 127, 128, 129, 130, 131, 132, 133, 134, 160} {
		a := o.assertion(t, claimTag(id))
		if a.Verdict != certify.Skip {
			t.Errorf("model %d: verdict %s, want SKIP", id, a.Verdict)
		}
		if a.Observed == "" {
			t.Errorf("model %d: skipped with no reason", id)
		}
	}
}

// claimTag is the per-model label CRV-1 prefixes its claims with. The trailing
// colon keeps "CRV-1.13" from matching model 130's row.
func claimTag(id uint16) string {
	return "CRV-1." + itoa(id) + ":"
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
