package aggregator

// refusal_test.go pins the one distinction convergeWithinSLA exists to make about
// a FAILED control write: did the DEVICE refuse it, or did we never reach the
// device?
//
// The oracle used to key that on StepResult.Exception, which only the
// expect_exception verb ever populates — so a write step never had one, and every
// refusal was reported as "control write failed at transport … cannot observe
// convergence". The campaign it matters most for is the grant half of the RBAC
// contract, whose whole hypothesis is that a GridService control write must be
// ACCEPTED: a gateway that denied it produced an INCONCLUSIVE about the harness
// instead of a FAIL about the gateway. These are the pure-evidence teeth for the
// fix; specgrant_integration_test.go proves the same thing end to end against a
// loopback that really does deny the write.

import (
	"strings"
	"testing"
)

// converged is a readback step that reached its commanded value — the healthy
// step every case below pairs its failure with, so a FAIL can only come from the
// write step under test.
func converged(idx int) StepResult {
	return StepResult{
		Index: idx, Do: StepReadback, OK: true,
		Readback: &ReadbackRecord{
			Unit: 2, Model: 704, Point: "WMaxLimPct", Expect: 100, Tol: 1,
			SLAS: 15, Reads: 1, HadRead: true, Final: 100, Converged: true, TookS: 0.2,
		},
	}
}

func TestConvergeWithinSLA_RefusedWriteIsAFailNotAnInconclusive(t *testing.T) {
	// The refusal arrives wrapped in a message about SCANNING, exactly as it does
	// live: WritePoint scans the block layout before it can address the point, and
	// a role denied its reads fails there first. Only ExCode survives that wrapping.
	rep := &CampaignReport{Steps: []StepResult{
		{
			Index: 1, Do: StepWritePoint, OK: false, ExCode: 0x01,
			Err:   "aggregator: write M704.WMaxLimPct on unit 2: scan device: sunspec scan: no SunS header at bases [40000 0 50000] (first read error: mbap: server exception 0x01 (illegal function))",
			Write: &WriteRecord{Unit: 2, Model: 704, Point: "WMaxLimPct", Value: 100, ExCode: 0x01},
		},
		converged(2),
	}}
	v, findings := convergeWithinSLA(rep)
	if v != VerdictFail {
		t.Fatalf("verdict %s for a control write the device REFUSED; want FAIL. findings: %v", v, findings)
	}
	joined := strings.Join(findings, " | ")
	if !strings.Contains(joined, "REFUSED") || !strings.Contains(joined, "0x01") {
		t.Errorf("the finding does not name the refusal or its code: %s", joined)
	}
	if strings.Contains(joined, "transport") {
		t.Errorf("a refusal must not be reported as a transport failure: %s", joined)
	}
}

func TestConvergeWithinSLA_TransportFailureIsStillInconclusive(t *testing.T) {
	// No protocol answer at all (ExCode 0): the command never reached the device,
	// so nothing about the device has been observed and nothing may be claimed.
	rep := &CampaignReport{Steps: []StepResult{
		{
			Index: 1, Do: StepWritePoint, OK: false,
			Err:   "aggregator: write M704.WMaxLimPct on unit 2: read: wolfSSL_read: -1",
			Write: &WriteRecord{Unit: 2, Model: 704, Point: "WMaxLimPct", Value: 100},
		},
		converged(2),
	}}
	v, findings := convergeWithinSLA(rep)
	if v != VerdictInconclusive {
		t.Fatalf("verdict %s for a write that never reached the device; want INCONCLUSIVE. findings: %v", v, findings)
	}
	if joined := strings.Join(findings, " | "); !strings.Contains(joined, "transport") {
		t.Errorf("the finding does not name the transport: %s", joined)
	}
}

func TestConvergeWithinSLA_HealthyRunStillPasses(t *testing.T) {
	rep := &CampaignReport{Steps: []StepResult{
		{Index: 1, Do: StepWritePoint, OK: true, Write: &WriteRecord{Unit: 2, Model: 704, Point: "WMaxLimPct", Value: 100, OK: true}},
		converged(2),
	}}
	if v, findings := convergeWithinSLA(rep); v != VerdictPass {
		t.Fatalf("verdict %s on a clean write+convergence; want PASS. findings: %v", v, findings)
	}
}
