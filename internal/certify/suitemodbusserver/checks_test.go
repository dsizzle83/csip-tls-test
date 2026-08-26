package suitemodbusserver

// checks_test.go is where the suite's teeth are proven.
//
// Every check gets at least two tests: one against a device built to the
// specification, and one against a device broken in exactly the way that check
// exists to catch. A check that only ever ran against a good device would be
// indistinguishable from a function that returns PASS.
//
// The write-driven checks get a third: a device that refuses every write with
// exception 0x01, standing in for the gateway's control-authority overlay. The
// correct outcome there is SKIP with the refusal cited — not PASS (nothing was
// demonstrated) and not FAIL (the DUT's exception ladder was never reached).
// That distinction is the single most load-bearing behaviour in this package
// and it is tested for every check that writes.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

// --- DEV-1 / DEV-2 ---------------------------------------------------------

func TestDEV1PassesAConformantChainAndProducesAVerifiableBundle(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::DEV-1", checkDEV1, dev, nil)
	o.wantVerdict(t, certify.Pass)
	if !o.cited() {
		t.Fatalf("DEV-1 passed with no re-checkable citation:\n%s", o.dump())
	}
	base := o.assertion(t, "standard start addresses")
	if base.Verdict != certify.Pass {
		t.Errorf("base-address assertion = %s: %s", base.Verdict, base.Observed)
	}
	if len(base.Frames) == 0 || base.FramesSHA256 == "" {
		t.Errorf("the base-address assertion carries no frame digest: %+v", base)
	}
	o.wantVerifiableBundle(t)
}

func TestDEV1FailsAChainWhoseEndModelHasALength(t *testing.T) {
	dev := newDevice(t, deviceOpts{EndModelLen: 3})
	o := runCheck(t, "ss-modbus-conf-v1.4::DEV-1", checkDEV1, dev, nil)
	o.wantVerdict(t, certify.Fail)
	end := o.assertion(t, "terminated by the SunSpec end model")
	if end.Verdict != certify.Fail {
		t.Fatalf("end-model assertion = %s, want FAIL: %s", end.Verdict, end.Observed)
	}
	if !contains(end.Observed, "length 3") {
		t.Errorf("the failing assertion does not say what was wrong: %q", end.Observed)
	}
}

func TestDEV1SaysItCannotCheckAChainAgainstItself(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::DEV-1", checkDEV1, dev, nil)
	a := o.assertion(t, "device PICS is located by the discovery walk")
	if a.Verdict != certify.Skip {
		t.Fatalf("the PICS comparison claims %s without a PICS: %s", a.Verdict, a.Observed)
	}
}

func TestDEV1ComparesAgainstAnOperatorSuppliedPICSModelList(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::DEV-1", checkDEV1, dev,
		map[string]string{paramPICSModels: "1,701,702,704,999"})
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "device PICS is located by the discovery walk")
	if a.Verdict != certify.Fail || !contains(a.Observed, "999") {
		t.Fatalf("a PICS model the device does not serve was not reported: %s / %s", a.Verdict, a.Observed)
	}
}

func TestDEV2PassesAConformantModel1(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::DEV-2", checkDEV2, dev, nil)
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "mandatory (ID, L, Mn, Md, SN)")
	if a.Verdict != certify.Pass || !contains(a.Observed, "LEXA Bench") {
		t.Fatalf("model 1 identity not evidenced: %s / %s", a.Verdict, a.Observed)
	}
	o.wantVerifiableBundle(t)
}

func TestDEV2FailsAModel1WithAnUnimplementedMandatoryPoint(t *testing.T) {
	dev := newDevice(t, deviceOpts{BlankManufacturer: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::DEV-2", checkDEV2, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "mandatory (ID, L, Mn, Md, SN)")
	if a.Verdict != certify.Fail || !contains(a.Observed, "Mn") {
		t.Fatalf("an unimplemented mandatory Mn was not caught: %s / %s", a.Verdict, a.Observed)
	}
}

func TestDEV2FailsAPICSIdentityMismatch(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::DEV-2", checkDEV2, dev,
		map[string]string{paramPICSMn: "Someone Else"})
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "matches what the device PICS declares")
	if a.Verdict != certify.Fail {
		t.Fatalf("a PICS mismatch was not reported: %s / %s", a.Verdict, a.Observed)
	}
}

// --- MOD-1 / MOD-2 ---------------------------------------------------------

func TestMOD1PassesAConformantDeviceAndSkipsUntranscribedModels(t *testing.T) {
	dev := newDevice(t, deviceOpts{Full1547: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-1", checkMOD1, dev, nil)
	o.wantVerdict(t, certify.Pass)
	if !o.hasAssertion("MOD-1.701 step 5") {
		t.Errorf("no per-model single-point assertion for 701:\n%s", o.dump())
	}
	// A curve model must be named and skipped, never silently dropped.
	skipped := o.assertion(t, "MOD-1.705")
	if skipped.Verdict != certify.Skip || !contains(skipped.Observed, "runtime-geometry") {
		t.Errorf("model 705 was not explicitly skipped with a reason: %s / %s", skipped.Verdict, skipped.Observed)
	}
	o.wantVerifiableBundle(t)
}

func TestMOD1FailsAnUnimplementedMandatoryPoint(t *testing.T) {
	dev := newDevice(t, deviceOpts{UnimplementedACType: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-1", checkMOD1, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "MOD-1.701 step 3")
	if a.Verdict != certify.Fail || !contains(a.Observed, "ACType") {
		t.Fatalf("the unimplemented mandatory ACType was not caught: %s / %s", a.Verdict, a.Observed)
	}
}

func TestMOD2PassesADeviceThatServesWholeModels(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-2", checkMOD2, dev, nil)
	o.wantVerdict(t, certify.Pass)
	// Model 701 spans 155 registers, past the 125-register ceiling, so it must
	// have been read in more than one request and that must be recorded.
	a := o.assertion(t, "MOD-2.701")
	if !contains(a.Observed, "2 request(s)") {
		t.Errorf("the >125-register model was not read in several requests: %q", a.Observed)
	}
	o.wantVerifiableBundle(t)
}

func TestMOD2FailsADeviceThatCannotServeAWholeModelInOneRead(t *testing.T) {
	dev := newDevice(t, deviceOpts{MaxReadQuantity: 60})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-2", checkMOD2, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "MOD-2.704")
	if a.Verdict != certify.Fail {
		t.Fatalf("a model 704 read of 67 registers was refused and MOD-2 did not fail: %s", a.Observed)
	}
}

// --- MB-2 ------------------------------------------------------------------

func TestMB2PassesSingleRegisterReads(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::MB-2", checkMB2, dev, nil)
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "three distinct registers")
	if a.Verdict != certify.Pass || len(a.Frames) == 0 {
		t.Fatalf("MB-2 produced no cited evidence: %s / %+v", a.Verdict, a)
	}
	// The carve-out observation must be present and must not be graded as a
	// failure whichever way the device answered.
	c := o.assertion(t, "longer than 16 bits")
	if c.Verdict == certify.Fail {
		t.Errorf("the partial-value carve-out was graded as a failure: %s", c.Observed)
	}
}

// --- EXC-1 / EXC-2 / EXC-3 -------------------------------------------------

func TestEXC3PassesADeviceThatRejectsAnUndefinedFunctionCode(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::EXC-3", checkEXC3, dev, nil)
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "function code 50")
	if !contains(a.Observed, "0xb2") && !contains(a.Observed, "0xB2") {
		t.Errorf("the exception response was not read back off the wire: %q", a.Observed)
	}
	o.wantVerifiableBundle(t)
}

func TestEXC3FailsADeviceThatAnswersAnUndefinedFunctionCode(t *testing.T) {
	dev := newDevice(t, deviceOpts{AnswerUnknownFunction: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::EXC-3", checkEXC3, dev, nil)
	o.wantVerdict(t, certify.Fail)
}

func TestEXC2PassesADeviceThatRefusesReadOnlyWrites(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::EXC-2", checkEXC2, dev, nil)
	o.wantVerdict(t, certify.Pass)
	o.wantVerifiableBundle(t)
}

func TestEXC2FailsADeviceThatAppliesAReadOnlyWrite(t *testing.T) {
	dev := newDevice(t, deviceOpts{AcceptReadOnlyWrites: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::EXC-2", checkEXC2, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "read-only register")
	if !contains(a.Observed, "ACCEPTED") {
		t.Errorf("the accepted read-only write was not named: %q", a.Observed)
	}
}

func TestEXC1PassesADeviceThatRefusesAnInvalidValue(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::EXC-1", checkEXC1, dev, nil)
	o.wantVerdict(t, certify.Pass)
	o.wantVerifiableBundle(t)
}

func TestEXC1FailsADeviceThatAppliesAnInvalidValue(t *testing.T) {
	dev := newDevice(t, deviceOpts{AcceptInvalidValues: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::EXC-1", checkEXC1, dev, nil)
	o.wantVerdict(t, certify.Fail)
}

// TestEXC1SkipsWhenEveryWriteIsDenied is the check that keeps this suite
// honest: a device refusing every write with 0x01 must NOT be reported as
// failing the exception ladder, because the ladder was never reached.
func TestEXC1SkipsWhenEveryWriteIsDenied(t *testing.T) {
	dev := newDevice(t, deviceOpts{DenyWrites: 0x01})
	o := runCheck(t, "ss-modbus-conf-v1.4::EXC-1", checkEXC1, dev, nil)
	o.wantVerdict(t, certify.Skip)
	a := o.assertion(t, "invalid value written to an RW point")
	if a.Verdict != certify.Skip {
		t.Fatalf("a blanket write denial produced %s rather than a skip: %s", a.Verdict, a.Observed)
	}
	if !contains(o.Case.Notes, "0x01") {
		t.Errorf("the notes do not name the refusing exception: %q", o.Case.Notes)
	}
}

// --- MB-1 / MOD-3 ----------------------------------------------------------

func TestMB1PassesADeviceThatSupportsBothWriteFunctions(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::MB-1", checkMB1, dev, nil)
	o.wantVerdict(t, certify.Pass)
	if !o.hasAssertion("Function Code 16") || !o.hasAssertion("Function Code 6") {
		t.Fatalf("MB-1 did not assert both write functions:\n%s", o.dump())
	}
	o.wantVerifiableBundle(t)
}

func TestMB1FailsADeviceWithoutSingleRegisterWrite(t *testing.T) {
	dev := newDevice(t, deviceOpts{NoSingleWrite: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::MB-1", checkMB1, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "Function Code 6")
	if a.Verdict != certify.Fail {
		t.Fatalf("an FC 6 refusal was not reported: %s / %s", a.Verdict, a.Observed)
	}
}

func TestMB1SkipsWhenWritesAreDenied(t *testing.T) {
	dev := newDevice(t, deviceOpts{DenyWrites: 0x01})
	o := runCheck(t, "ss-modbus-conf-v1.4::MB-1", checkMB1, dev, nil)
	o.wantVerdict(t, certify.Skip)
}

// TestMB1PerturbsWithinEngineeringBoundsWhenAtTheCeiling pins the fix for the
// bug runs/final-fullsuite-20260731T234821 found by byte-level evidence: a
// prior case (e.g. EXC-1) can leave 704.WMaxLimPct sitting at its raw
// ceiling (100.00 % under scale factor -2, raw 10000). The old perturbation
// (`orig[1] + 1`) only guarded against 16-bit wraparound, so at the ceiling
// it wrote 10001 — an out-of-range value the DUT correctly refuses under its
// {0,100} engineering-range enforcement — and MB-1 wrongly graded that
// product-correct refusal as a harness failure. The fix must recognise the
// ceiling and decrement to 9999 instead, so the write is accepted and both
// write functions get a real, fully-cited PASS rather than a refusal-driven
// SKIP.
func TestMB1PerturbsWithinEngineeringBoundsWhenAtTheCeiling(t *testing.T) {
	dev := newDevice(t, deviceOpts{WMaxLimPctAtCeiling: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::MB-1", checkMB1, dev, nil)
	o.wantVerdict(t, certify.Pass)
	if !o.hasAssertion("Function Code 16") || !o.hasAssertion("Function Code 6") {
		t.Fatalf("MB-1 did not assert both write functions at the ceiling:\n%s", o.dump())
	}
	o.wantVerifiableBundle(t)
}

// TestMB1PerturbsWithinEngineeringBoundsMidRange pins the increment branch of
// the same fix: away from the ceiling, the perturbation still moves the
// point up by one engineering unit, exactly as before the fix — the ceiling
// case is the exception, not the rule.
func TestMB1PerturbsWithinEngineeringBoundsMidRange(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::MB-1", checkMB1, dev, nil)
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "Function Code 16")
	if a.Verdict != certify.Pass || !contains(a.Observed, "0x0033") {
		// orig seed is 50 (0x0032); the increment path writes 51 (0x0033).
		t.Fatalf("the mid-range perturbation did not increment as expected: %s / %s", a.Verdict, a.Observed)
	}
}

func TestMOD3PassesAConformantAdjustablePointSweep(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-3", checkMOD3, dev, nil)
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "704.WMaxLimPct accepts every value")
	if a.Verdict != certify.Pass || !contains(a.Observed, "range source") {
		t.Fatalf("MOD-3 did not record where its value range came from: %s / %s", a.Verdict, a.Observed)
	}
	if !o.hasAssertion("written as a group in a single FC 16") {
		t.Errorf("MOD-3 did not assert the group write:\n%s", o.dump())
	}
	o.wantVerifiableBundle(t)
}

// TestMOD3FailsWhenAReadBackDoesNotReturnTheWrittenValue exercises the branch
// that separates MOD-3 from "did the write get an acknowledgement": a device
// that ACKS a write and stores something else. v1.3 removed the 1000 ms
// read-after-write allowance, so the read-back must be exact and immediate.
func TestMOD3FailsWhenAReadBackDoesNotReturnTheWrittenValue(t *testing.T) {
	dev := newDevice(t, deviceOpts{ClampWMaxLimPct: 40})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-3", checkMOD3, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "704.WMaxLimPct accepts every value")
	if a.Verdict != certify.Fail || !contains(a.Observed, "read back") {
		t.Fatalf("an acknowledged-but-clamped write was not reported: %s / %s", a.Verdict, a.Observed)
	}
}

func TestMOD3SkipsWhenWritesAreDenied(t *testing.T) {
	dev := newDevice(t, deviceOpts{DenyWrites: 0x02})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-3", checkMOD3, dev, nil)
	o.wantVerdict(t, certify.Skip)
	if !contains(o.Case.Notes, "refused every control write") {
		t.Errorf("MOD-3's notes do not explain the skip: %q", o.Case.Notes)
	}
}

func TestMOD3SuppressesTheEnumerationSweepOnRequest(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::MOD-3", checkMOD3, dev,
		map[string]string{paramNoEnumWrite: "1"})
	a := o.assertion(t, "704.WMaxLimPctEna accepts every supported")
	if a.Verdict != certify.Skip {
		t.Fatalf("the enumeration sweep ran despite -param %s: %s", paramNoEnumWrite, a.Verdict)
	}
}

// --- TCP-2 / TCP-3 ---------------------------------------------------------

func TestTCP3PassesADeviceThatReassemblesASplitRequest(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-3", checkTCP3, dev, nil)
	o.wantVerdict(t, certify.Pass)
	// The stimulus assertion is the one that matters: without it the PASS is a
	// claim about a reassembly that may never have been asked for.
	a := o.assertion(t, "genuinely arrived at the DUT in more than one piece")
	if a.Verdict != certify.Pass {
		t.Fatalf("the split did not survive to the synthetic wire: %s / %s", a.Verdict, a.Observed)
	}
	o.wantVerifiableBundle(t)
}

func TestTCP3FailsADeviceThatDoesNotReassemble(t *testing.T) {
	dev := newDevice(t, deviceOpts{NoReassembly: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-3", checkTCP3, dev, nil)
	o.wantVerdict(t, certify.Fail)
}

// --- TCP-2's three outcomes, and the pause that separates them --------------
//
// TCP-2 and TCP-3 put the same bytes on the same connection; only the PAUSE
// tells them apart (see checks_tcp.go's header). So the device below is given a
// real FRAME BUDGET, and every row here turns on whether the check waited past
// it. A test suite that only exercised the verdict mapping would pass just as
// well against the 200 ms constant this check used to carry, which is the exact
// defect these rows exist to hold closed.

// tcp2Budget is the fake device's frame budget in these tests. It is longer
// than TCP2Margin on purpose: that is what makes a manifest declaring a TINY
// budget produce a pause SHORTER than the device's own, which is the mutation
// the last test drives.
const tcp2Budget = 1200 * time.Millisecond

// withManifest writes a candidate manifest declaring frameBudgetMS (0 = the key
// omitted) and points the run at it.
func withManifest(t *testing.T, frameBudgetMS int) func(*certify.Options) {
	t.Helper()
	budget := ""
	if frameBudgetMS > 0 {
		budget = fmt.Sprintf(`, "frame_budget_ms": %d`, frameBudgetMS)
	}
	body := fmt.Sprintf(`{
  "profile": "one-to-one-7xx-tcp",
  "topology": {"configured_der": 1, "role": "inverter", "northbound_units": [1]},
  "csip": {"role": "der-client", "end_devices": 1, "der_resources": 1},
  "secure_sunspec": {"roles": ["server"], "transport": "tls-tcp", "port": 802%s},
  "modbus_client": {"transport": "tcp", "device_count": 1, "generation": "7xx"},
  "authority_profiles": ["csip", "mbaps"],
  "models": [1, 701, 702, 703, 704, 705, 706, 711, 712]
}`, budget)
	path := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return func(o *certify.Options) { o.ManifestPath = path }
}

// OUTCOME 1 — the follow-up answered on the SAME connection.
//
// The device has a frame budget and resynchronises when it expires. The check
// declares 2000 ms, waits 2500 ms, and the device has long since dropped the
// partial frame — so the follow-up is a new request and is answered under its
// own transaction id. A server that resynchronises is conformant to §2.7.7's
// literal text, and this is the stricter of the two passing shapes.
func TestTCP2PassesADeviceThatRecoversOnTheSameConnection(t *testing.T) {
	dev := newDevice(t, deviceOpts{FrameBudget: tcp2Budget})
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-2", checkTCP2, dev, nil, withManifest(t, 2000))
	o.wantVerdict(t, certify.Pass)

	a := o.assertion(t, "incomplete Modbus request really was sent")
	if a.Verdict != certify.Pass || !contains(a.Observed, "promises") {
		t.Fatalf("the truncation was not evidenced on the wire: %s / %s", a.Verdict, a.Observed)
	}
	if !contains(a.Note, "declared MBAP frame budget") {
		t.Errorf("the bundle does not record where the pause came from; note = %q", a.Note)
	}
	if b := o.assertion(t, "no Modbus response was returned under the truncated frame"); b.Verdict != certify.Pass {
		t.Errorf("the stale-transaction-id criterion = %s / %s", b.Verdict, b.Observed)
	}
	c := o.assertion(t, "after an incomplete request the DUT recovers")
	if c.Verdict != certify.Pass || !contains(c.Observed, "same connection") {
		t.Fatalf("the criterion = %s / %s", c.Verdict, c.Observed)
	}
	o.wantVerifiableBundle(t)
}

// OUTCOME 2 — the DUT closes the connection at its budget, and a FRESH
// connection is answered normally.
//
// This is lexa-gw's own shape, and it was graded WARN: a device doing exactly
// what §2.7.7 permits, published as a partial result. The catalog's own note
// says the close is "an observation rather than a failure", so it is a PASS
// carrying that observation.
func TestTCP2PassesADeviceThatClosesAfterThePartialAndRecoversOnAFreshConnection(t *testing.T) {
	dev := newDevice(t, deviceOpts{NoReassembly: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-2", checkTCP2, dev, nil, withManifest(t, 2000))
	o.wantVerdict(t, certify.Pass)

	a := o.assertion(t, "after an incomplete request the DUT recovers")
	if a.Verdict != certify.Pass {
		t.Fatalf("close-after-partial + fresh-connection recovery = %s / %s\n%s", a.Verdict, a.Observed, o.dump())
	}
	if !contains(a.Observed, "fresh connection") {
		t.Errorf("the recovery citation does not name the fresh connection: %q", a.Observed)
	}
	if !contains(a.Note, "OBSERVATION rather than as a failure") {
		t.Errorf("the connection-close observation §2.7.7 asks for is not recorded; note = %q", a.Note)
	}
	if !contains(a.Observed, "closed the connection") {
		t.Errorf("the close itself is not in the record: %q", a.Observed)
	}
	o.wantVerifiableBundle(t)
}

// OUTCOME 3 — a response under the TRUNCATED frame's transaction id.
//
// The default device has no frame budget at all: it holds the partial frame
// forever and splices whatever arrives next onto it. After a 2500 ms pause that
// can no longer be confused with TCP-3's reassembly — nothing in §2.7.8 asks a
// server to keep assembling for two and a half seconds — so it is the mis-parse
// §2.7.7 names, and it FAILS.
func TestTCP2FailsADeviceThatAnswersUnderTheStaleTransactionID(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-2", checkTCP2, dev, nil, withManifest(t, 2000))
	o.wantVerdict(t, certify.Fail)

	a := o.assertion(t, "no Modbus response was returned under the truncated frame")
	if a.Verdict != certify.Fail {
		t.Fatalf("the splice was not reported: %s / %s\n%s", a.Verdict, a.Observed, o.dump())
	}
	if !contains(a.Observed, "MIS-PARSED") {
		t.Errorf("the failure does not say what went wrong: %q", a.Observed)
	}
	// And it must not be dressed up as recovery: a second connection is not
	// opened after the DUT has already answered wrongly.
	if contains(o.Case.Notes, "fresh connection") {
		t.Errorf("a stale-id answer was followed by a fresh-connection attempt: %q", o.Case.Notes)
	}
}

// THE PAUSE IS THE EXPERIMENT — the mutation proof.
//
// Same device, same budget, same everything except the DECLARED budget: 1 ms,
// so the check waits 501 ms and the device is still assembling. The follow-up's
// bytes are consumed as the truncated frame's missing tail and the answer comes
// back under the stale id — a CONFORMANT, resynchronising device recorded as
// mis-parsing, purely because the harness did not wait.
//
// This is what the old 200 ms constant did to every device with a frame budget,
// and it is why the number comes from the candidate rather than from this file.
func TestTCP2MisreadsAConformantDeviceWhenThePauseIsShorterThanItsBudget(t *testing.T) {
	dev := newDevice(t, deviceOpts{FrameBudget: tcp2Budget})
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-2", checkTCP2, dev, nil, withManifest(t, 1))
	if o.Case.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL — the point of this row is that too short a pause DOES "+
			"misread a conformant device, so the pause has to come from the device's own declaration\n%s",
			o.Case.Verdict, o.dump())
	}
	if !contains(o.Case.Notes, "still assembling") {
		t.Errorf("the misreading is not explained: %q", o.Case.Notes)
	}
}

// A CAMPAIGN refuses to guess the budget.
//
// Driven directly rather than through the runner: the refusal is made before a
// socket is opened, which is the property being pinned — a row that cannot be
// decided must not spend a connection, and its refusal must not be confusable
// with a bench that was merely unreachable.
func TestTCP2RefusesToRunInACampaignWithNoDeclaredFrameBudget(t *testing.T) {
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	c, ok := cat.ByUID("ss-modbus-conf-v1.4::TCP-2")
	if !ok {
		t.Fatal("the committed catalog has no TCP-2")
	}
	// Targets deliberately point at an address nothing is listening on: if the
	// refusal did not come first, this would be a dial failure instead.
	rc := &certify.RunCtx{
		Case: c, Suite: SuiteName, Log: certify.DiscardLogger,
		Targets: certify.Targets{Gateway: "127.0.0.1:1", GatewayHost: "127.0.0.1"},
	}
	if err := rc.SetPosture(certify.Posture{Campaign: certify.CampaignMBAPS}); err != nil {
		t.Fatal(err)
	}
	res, err := checkTCP2(context.Background(), rc)
	if err != nil {
		t.Fatalf("checkTCP2 = %v, want a refusal Result rather than an error", err)
	}
	if res.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL", res.Verdict)
	}
	for _, want := range []string{"frame_budget_ms", "§2.7.7", "TCP-3"} {
		if !contains(res.Notes, want) {
			t.Errorf("the refusal does not mention %q: %s", want, res.Notes)
		}
	}
}

// An EXPLORATORY run falls back to the documented product default, LOUDLY.
func TestTCP2FallsBackToTheDocumentedDefaultOutsideACampaign(t *testing.T) {
	dev := newDevice(t, deviceOpts{FrameBudget: tcp2Budget})
	// No -manifest at all: the pre-manifest shape, which must still run.
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-2", checkTCP2, dev, nil)
	o.wantVerdict(t, certify.Pass)

	a := o.assertion(t, "incomplete Modbus request really was sent")
	if !contains(a.Note, "declares no") || !contains(a.Note, "DIFFERENT DEVICE") {
		t.Errorf("the assumed budget is not disclosed in the bundle; note = %q", a.Note)
	}
	o.wantVerifiableBundle(t)
}

// TCP-3 is unchanged by any of this. Its 20 ms split is safe under every frame
// budget by construction, and it must keep passing against a device that has
// one — the same device TCP-2 above resynchronises against.
func TestTCP3IsUnaffectedByADeviceWithAFrameBudget(t *testing.T) {
	dev := newDevice(t, deviceOpts{FrameBudget: tcp2Budget})
	o := runCheck(t, "ss-modbus-conf-v1.4::TCP-3", checkTCP3, dev, nil, withManifest(t, 2000))
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "genuinely arrived at the DUT in more than one piece")
	if a.Verdict != certify.Pass {
		t.Fatalf("the split did not survive to the synthetic wire: %s / %s", a.Verdict, a.Observed)
	}
	o.wantVerifiableBundle(t)
}

// --- REV-1 / REV-2 / REV-3 -------------------------------------------------

func TestREV1PassesADeviceWhoseReversionTimerFires(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-1", checkREV1, dev, nil)
	o.wantVerdict(t, certify.Pass)
	if !o.hasAssertion("reversion settings are in effect") {
		t.Fatalf("REV-1 did not assert the reversion itself:\n%s", o.dump())
	}
	o.wantVerifiableBundle(t)
}

func TestREV1FailsADeviceWhoseReversionNeverFires(t *testing.T) {
	dev := newDevice(t, deviceOpts{ReversionNeverFires: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-1", checkREV1, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "reversion settings are in effect")
	if a.Verdict != certify.Fail {
		t.Fatalf("a reversion that never fired was not reported: %s / %s", a.Verdict, a.Observed)
	}
}

// TestREV1IsNotPerformedWhenNoReversionTimerIsImplemented pins §2.6's
// applicability gate, in the section preamble and in full: "Reversion tests
// verify the reversion timer functionality. IF THIS FUNCTIONALITY IS NOT
// IMPLEMENTED IN A MODEL, THE TESTS ARE NOT PERFORMED."
//
// A device with no remaining-time readback has no implemented reversion timer,
// so the three procedures are N/A — not FAIL. Run 20260726T225512 reported
// REV-1/2/3 as three failures on a device where no reversion behaviour had been
// exercised at all: its own runner logged SKIP, every behavioural assertion was
// SKIP, and only step 1's citation was emitted as FAIL, which the report's
// worst-assertion roll-up then took as the case verdict.
func TestREV1IsNotPerformedWhenNoReversionTimerIsImplemented(t *testing.T) {
	dev := newDevice(t, deviceOpts{NoReversionReadback: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-1", checkREV1, dev, nil)
	o.wantVerdict(t, certify.Skip)
	a := o.assertion(t, "every reversion point the timer needs is implemented")
	if a.Verdict == certify.Fail {
		t.Fatalf("step 1 was emitted as a FAIL against a device §2.6 says not to test: %s", a.Observed)
	}
	if !contains(a.Observed, "WMaxLimPctRvrtRem") {
		t.Errorf("the missing remaining-time point must still be NAMED — the observation is the evidence "+
			"the gate applies: %s", a.Observed)
	}
	if !contains(a.Note, "NOT PERFORMED") {
		t.Errorf("the assertion must carry §2.6's gate as its note: %q", a.Note)
	}
}

// TestREV1FailsWhenThePICSDeclaresATimerThatIsNotThere is the other side of the
// same gate. §2.6 performs the tests "for each reversion timer that is
// implemented", and REV-1 step 1 checks the points of "the reversion timer
// SPECIFIED IN THE PICS". A PICS that declares a timer the device does not
// implement is a genuine non-conformance.
func TestREV1FailsWhenThePICSDeclaresATimerThatIsNotThere(t *testing.T) {
	dev := newDevice(t, deviceOpts{NoReversionReadback: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-1", checkREV1, dev,
		map[string]string{paramPICSReversion: "1"})
	a := o.assertion(t, "every reversion point the timer needs is implemented")
	if a.Verdict != certify.Fail || !contains(a.Observed, "WMaxLimPctRvrtRem") {
		t.Fatalf("a PICS-declared reversion timer that is absent must FAIL step 1: %s / %s", a.Verdict, a.Observed)
	}
}

func TestREV2PassesADeviceWhoseTimerCanBeExtended(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-2", checkREV2, dev, nil)
	o.wantVerdict(t, certify.Pass)
	o.wantVerifiableBundle(t)
}

func TestREV2FailsADeviceThatIgnoresAMidCountdownRewrite(t *testing.T) {
	dev := newDevice(t, deviceOpts{ReversionUnextendable: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-2", checkREV2, dev, nil)
	o.wantVerdict(t, certify.Fail)
}

func TestREV3PassesADeviceWhoseTimerCanBeCancelled(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-3", checkREV3, dev, nil)
	o.wantVerdict(t, certify.Pass)
	o.wantVerifiableBundle(t)
}

func TestREV3FailsADeviceThatIgnoresTheCancel(t *testing.T) {
	dev := newDevice(t, deviceOpts{ReversionUncancellable: true})
	o := runCheck(t, "ss-modbus-conf-v1.4::REV-3", checkREV3, dev, nil)
	o.wantVerdict(t, certify.Fail)
}

// --- MOD-4 and the scale factor test ---------------------------------------

// TestMOD4FailsAChainMissingProfileModels is the expected outcome against the
// real DUT, and the test asserts the failure is SPECIFIC: it must name the
// models the IEEE 1547-2018 profile requires and the device does not serve.
func TestMOD4FailsAChainMissingProfileModels(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-1547-test-v1.1::MOD-4", checkMOD4, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "every SunSpec model the IEEE 1547-2018 profile requires")
	if a.Verdict != certify.Fail {
		t.Fatalf("a chain missing 703 and 705-712 passed MOD-4: %s", a.Observed)
	}
	for _, want := range []string{"703", "705", "712"} {
		if !contains(a.Observed, want) {
			t.Errorf("the failing assertion does not name model %s: %q", want, a.Observed)
		}
	}
	o.wantVerifiableBundle(t)
}

func TestMOD4PassesAChainCarryingTheWholeProfile(t *testing.T) {
	dev := newDevice(t, deviceOpts{Full1547: true})
	o := runCheck(t, "ss-1547-test-v1.1::MOD-4", checkMOD4, dev, nil)
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "every SunSpec model the IEEE 1547-2018 profile requires")
	if a.Verdict != certify.Pass {
		t.Fatalf("a complete profile chain did not pass: %s", a.Observed)
	}
}

func TestMOD4RecordsAnOperatorScopedRequirementListAsAnOverride(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-1547-test-v1.1::MOD-4", checkMOD4, dev,
		map[string]string{param1547Models: "1,701,702,704"})
	o.wantVerdict(t, certify.Pass)
	a := o.assertion(t, "every SunSpec model the IEEE 1547-2018 profile requires")
	if !contains(a.Note, "OVERRIDDEN") {
		t.Fatalf("a scoped claim was made without saying so in the bundle: note=%q", a.Note)
	}
}

func TestScaleFactorTestPassesConformantScaleFactors(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	o := runCheck(t, "ss-1547-test-v1.1::2.4", checkSF, dev, nil)
	o.wantVerdict(t, certify.Pass)
	if !o.hasAssertion("does not change between two reads") {
		t.Errorf("the static-value requirement was not asserted:\n%s", o.dump())
	}
	// The procedure's real criterion is delegated to IEEE 1547 and the PICS;
	// the suite must say it did not assert it rather than implying it did.
	a := o.assertion(t, "acceptable range required to meet the IEEE 1547 requirements")
	if a.Verdict != certify.Skip {
		t.Fatalf("the un-sourced 1547 accuracy envelope was claimed as %s", a.Verdict)
	}
	o.wantVerifiableBundle(t)
}

func TestScaleFactorTestFailsAnOutOfRangeScaleFactor(t *testing.T) {
	dev := newDevice(t, deviceOpts{BadScaleFactor: true})
	o := runCheck(t, "ss-1547-test-v1.1::2.4", checkSF, dev, nil)
	o.wantVerdict(t, certify.Fail)
	a := o.assertion(t, "inside the sunssf type's range")
	if a.Verdict != certify.Fail || !contains(a.Observed, "V_SF") {
		t.Fatalf("an out-of-range scale factor was not caught: %s / %s", a.Verdict, a.Observed)
	}
}

// --- the framework's refusal to let an uncited PASS stand ------------------

// TestAnUncitedPassIsRefused proves the two-phase contract end to end: with no
// capture at all, a check that would otherwise PASS must not be allowed to.
func TestAnUncitedPassIsRefused(t *testing.T) {
	dev := newDevice(t, deviceOpts{})
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	reg.Register("ss-modbus-conf-v1.4::DEV-1", SuiteName, checkDEV1)

	opts := certify.DefaultOptions()
	opts.OutDir = t.TempDir()
	opts.Out = discard{}
	opts.Log = certify.DiscardLogger
	opts.PKIDir = ""
	opts.NoCapture = true
	opts.UIDs = []string{"ss-modbus-conf-v1.4::DEV-1"}
	opts.Targets = certify.Targets{Gateway: dev.Addr(), GatewayHost: "127.0.0.1"}
	opts.Params = map[string]string{paramTransport: "plain", paramUnit: "1"}

	run, err := certify.New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cases[0].Verdict == certify.Pass {
		t.Fatalf("a PASS survived a run with no capture behind it: %+v", rep.Cases[0])
	}
	if rep.Cases[0].Downgraded == "" {
		t.Errorf("the downgrade was not recorded")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
