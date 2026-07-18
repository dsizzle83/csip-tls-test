//go:build integration

package aggregator

// engine_integration_test.go proves the scenario engine (T06.6) + readback-
// verification oracles (T06.7) end to end against a loopback authz-enforcing mbaps
// server — the same in-process server (mbtls.Listen + mbap dispatch over a solar
// register world, with a per-unit map and a role write-allow set) the emulator
// core's integration test stands up (startAuthzServer / newTestPKI, defined in
// aggregator_integration_test.go). It runs the two mandatory shipped campaigns —
// curtail-solar-50 (readback-verify) and role-denial-readonly (denial matrix) —
// and asserts the ORACLE VERDICTS, plus a sim_fault + poll flow that exercises the
// fault-injection verb. Requires the amd64 wolfSSL sysroot (desktop,
// `make test-integration`). TestMain (wolfssl.Init) is shared with the core test.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// campaignEngine wires an Engine at the loopback: ConnectAs over the minted PKI,
// Resolve to the loopback address for every target, and Fault to the server's
// in-process ApplyFault hook (standing in for a live sim's simapi).
func campaignEngine(srv *authzServer, refs PKIRefs) *Engine {
	return NewEngine(RunOptions{
		ConnectAs: func(addr string, r Role) (*Conn, error) { return ConnectAs(addr, r, refs) },
		Resolve:   func(string) (string, error) { return srv.addr(), nil },
		Fault:     func(_ string, spec json.RawMessage) error { return srv.applyFault(spec) },
	})
}

func seedCampaign(t *testing.T, name string) *Campaign {
	t.Helper()
	c, err := LoadCampaign(filepath.Join("..", "..", "qa", "aggregator", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return c
}

// TestEngine_CurtailReadbackVerify runs the curtail-solar-50 campaign: discover,
// poll, write WMaxLimPct=50, readback to convergence, release to 100, readback
// again — and asserts convergeWithinSLA returns PASS with both readbacks
// converged and telemetry samples captured.
func TestEngine_CurtailReadbackVerify(t *testing.T) {
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin})
	eng := campaignEngine(srv, pki.refs(t))

	rep, err := eng.Run(context.Background(), seedCampaign(t, "curtail-solar-50.json"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict = %s, want PASS. summary: %s; findings: %v", rep.Verdict, rep.SummaryHuman, rep.Findings)
	}
	if !rep.VerdictExpected {
		t.Errorf("verdict %s not in expected set %v", rep.Verdict, rep.ExpectedVerdicts)
	}

	readbacks := 0
	for _, s := range rep.Steps {
		if s.Readback == nil {
			continue
		}
		readbacks++
		if !s.Readback.Converged {
			t.Errorf("readback step %d did not converge: %+v", s.Index, s.Readback)
		}
	}
	if readbacks != 2 {
		t.Errorf("want 2 readbacks, got %d", readbacks)
	}
	if len(rep.Samples) == 0 {
		t.Error("background poll produced no telemetry samples")
	}
	if rep.Session == nil || rep.Session.Cipher == "" {
		t.Errorf("report missing session handshake facts: %+v", rep.Session)
	}

	// The report writes a JSON artifact + human summary a dashboard/operator reads.
	dir := t.TempDir()
	jsonPath, err := rep.WriteReport(dir)
	if err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var back CampaignReport
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("report JSON does not round-trip: %v", err)
	}
	if back.Verdict != VerdictPass {
		t.Errorf("written report verdict = %s", back.Verdict)
	}
}

// TestEngine_RoleDenial runs role-denial-readonly: as ReadOnlySunSpec then,
// mid-campaign, LexaVoltReadOnly, each attempting a control write that the authz
// server denies. Asserts denyExpected returns PASS and every probe saw exactly
// exception 01 with nothing written.
func TestEngine_RoleDenial(t *testing.T) {
	pki := newTestPKI(t)
	// GridService may write; the two read-only roles may NOT — the denial subjects.
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	eng := campaignEngine(srv, pki.refs(t))

	rep, err := eng.Run(context.Background(), seedCampaign(t, "role-denial-readonly.json"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict = %s, want PASS. summary: %s; findings: %v", rep.Verdict, rep.SummaryHuman, rep.Findings)
	}

	checks := 0
	for _, s := range rep.Steps {
		if s.Exception == nil {
			continue
		}
		checks++
		if s.Exception.Result.Wrote {
			t.Errorf("step %d: write was ACCEPTED — authz gap: %+v", s.Index, s.Exception)
		}
		if s.Exception.Result.ExceptionCode != 1 || !s.Exception.Match {
			t.Errorf("step %d: not denied with exactly 01: %+v", s.Index, s.Exception)
		}
	}
	if checks != 2 {
		t.Errorf("want 2 denial probes (ReadOnly + LexaVolt), got %d", checks)
	}
	if len(rep.Denials) != 2 {
		t.Errorf("want 2 denials recorded in the run, got %d", len(rep.Denials))
	}
}

// TestEngine_SimFaultBlindsReadback exercises the sim_fault verb deterministically:
// it arms a nan_sentinel read fault through the injected Fault hook, then a
// readback that can never obtain a finite value (every register reads as the
// SunSpec 0x8000 N/A sentinel). It proves (a) the injector was called for both arm
// and clear, and (b) the readback is scored BLIND — a coverage gap, NOT a false
// FAIL — the exact distinction the readback oracle draws. (The Stale-vs-fresh
// telemetry semantics are proven separately by the core's
// TestEmulatorCore_PollStaleOnSentinel; here the point is the engine's sim_fault
// wiring and the BLIND verdict path.)
func TestEngine_SimFaultBlindsReadback(t *testing.T) {
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})

	faultCalls := 0
	eng := NewEngine(RunOptions{
		ConnectAs: func(addr string, r Role) (*Conn, error) { return ConnectAs(addr, r, pki.refs(t)) },
		Resolve:   func(string) (string, error) { return srv.addr(), nil },
		Fault:     func(_ string, spec json.RawMessage) error { faultCalls++; return srv.applyFault(spec) },
	})

	camp := &Campaign{
		CampV: CampaignV, ID: "fault-blinds-readback", Name: "sim_fault blinds a readback",
		Role: RoleGridService, Target: TargetGateway,
		Steps: []Step{
			{Do: StepDiscover, Units: &UnitSel{Units: []uint8{2}}}, // warm the reader cache before faulting
			{Do: StepSimFault, Target: "solar", Fault: json.RawMessage(`{"kind":"nan_sentinel"}`)},
			{Do: StepReadback, Unit: 2, Model: 704, Point: "WMaxLimPct", Expect: 50, SLAS: 1, Tol: 1},
			{Do: StepSimFault, Target: "solar", Fault: json.RawMessage(`{"kind":"nan_sentinel","clear":true}`)},
		},
		Oracle: OracleRef{Name: "convergeWithinSLA"},
	}
	rep, err := eng.Run(context.Background(), camp)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if faultCalls != 2 {
		t.Errorf("Fault injector called %d times, want 2 (arm + clear)", faultCalls)
	}
	var rb *ReadbackRecord
	for _, s := range rep.Steps {
		if s.Readback != nil {
			rb = s.Readback
		}
	}
	if rb == nil {
		t.Fatal("no readback step recorded")
	}
	if rb.Converged {
		t.Errorf("readback converged under nan_sentinel, want no convergence: %+v", rb)
	}
	if rb.HadRead {
		t.Errorf("readback obtained a finite value under nan_sentinel, want BLIND: %+v", rb)
	}
	if rep.Verdict != VerdictBlind {
		t.Errorf("verdict = %s, want BLIND (readback never saw a value)", rep.Verdict)
	}
}
