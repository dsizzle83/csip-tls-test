//go:build integration

package aggregator

// probes_integration_test.go proves the T06.8 TLS-fault probes end to end against
// the loopback authz-enforcing mbaps server (startAuthzServer / newTestPKI, shared
// with aggregator_integration_test.go). It drives the three shipped TLS-fault
// campaigns through the real engine + real mbtls handshakes and asserts the ORACLE
// VERDICTS, and it proves the headline enhancement directly: after a mid-session
// drop the resumed session reports Resumed=true (SunSpecTCP-46), which was
// structurally impossible before mbtls grew client session reuse. Requires the
// amd64 wolfSSL sysroot (desktop, `make test-integration`); TestMain (wolfssl.Init)
// is shared with the core test.

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"csip-tls-test/internal/mbtls"
)

// faultEngine wires an Engine whose Fault hook understands drop_session (arming
// the authz server's mid-exchange close) in addition to the register-level faults
// the SolarServer implements — the loopback stand-in for a live mbapsdev's
// simapi, which handles drop_session natively.
func faultEngine(srv *authzServer, refs PKIRefs) *Engine {
	return NewEngine(RunOptions{
		ConnectAs: func(addr string, r Role) (*Conn, error) { return ConnectAs(addr, r, refs) },
		Resolve:   func(string) (string, error) { return srv.addr(), nil },
		Fault: func(_ string, spec json.RawMessage) error {
			var f struct {
				Kind  string `json:"kind"`
				Clear bool   `json:"clear"`
			}
			if err := json.Unmarshal(spec, &f); err != nil {
				return err
			}
			if f.Kind == "drop_session" {
				srv.dropNext.Store(!f.Clear)
				return nil
			}
			return srv.applyFault(spec)
		},
	})
}

func tlsFaultCampaign(t *testing.T, name string) *Campaign {
	t.Helper()
	c, err := LoadCampaign(filepath.Join("..", "..", "qa", "aggregator", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return c
}

// TestProbe_ResumptionAfterDrop runs the resumption-after-drop campaign: discover
// (pumping the TLS 1.3 ticket), drop the session mid-exchange, clear the fault,
// and resume — asserting resumeAfterDrop returns PASS and the resume step's
// handshake facts report Resumed=true. This is the end-to-end proof that the mbtls
// client-session-reuse enhancement makes resumption real.
func TestProbe_ResumptionAfterDrop(t *testing.T) {
	mbtls.ClearSessionCache()
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin})
	eng := faultEngine(srv, pki.refs(t))

	rep, err := eng.Run(context.Background(), tlsFaultCampaign(t, "resumption-after-drop.json"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict = %s, want PASS. summary: %s; findings: %v", rep.Verdict, rep.SummaryHuman, rep.Findings)
	}
	if !rep.VerdictExpected {
		t.Errorf("verdict %s not in expected set %v", rep.Verdict, rep.ExpectedVerdicts)
	}

	var resumeStep *StepResult
	for i := range rep.Steps {
		if rep.Steps[i].Do == StepResume {
			resumeStep = &rep.Steps[i]
		}
	}
	if resumeStep == nil {
		t.Fatal("no resume step in the report")
	}
	if resumeStep.Session == nil {
		t.Fatalf("resume step carried no handshake facts: %+v", resumeStep)
	}
	if !resumeStep.Session.Resumed {
		t.Fatalf("resume did NOT resume the TLS session (Resumed=false) — client session reuse is not working: %+v", resumeStep.Session)
	}
	// The resumed session must still expose a cipher/version (a real handshake).
	if resumeStep.Session.Cipher == "" || resumeStep.Session.TLSVersion == "" {
		t.Errorf("resumed session missing handshake facts: %+v", resumeStep.Session)
	}
}

// TestProbe_MidSessionDrop runs the mid-session-drop campaign and asserts
// sessionSurvival returns PASS: after the drop, the follow-up discover
// transparently re-established the session and succeeded (recovery without an
// explicit resume step).
func TestProbe_MidSessionDrop(t *testing.T) {
	mbtls.ClearSessionCache()
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	eng := faultEngine(srv, pki.refs(t))

	rep, err := eng.Run(context.Background(), tlsFaultCampaign(t, "mid-session-drop.json"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict = %s, want PASS. summary: %s; findings: %v", rep.Verdict, rep.SummaryHuman, rep.Findings)
	}
	// The drop must actually have disrupted an op (else there is nothing to
	// recover from and the oracle would be INCONCLUSIVE, not PASS).
	sawDisruption := false
	for _, st := range rep.Steps {
		if st.Err != "" && st.Do != StepExpectException {
			sawDisruption = true
		}
	}
	if !sawDisruption {
		t.Error("no step hit a transport error — the drop_session fault did not disrupt the session")
	}
}

// TestProbe_RenegoRefusal runs the renego-refusal campaign and asserts
// renegotiationRefusal returns PASS: the client-initiated renegotiation was
// attempted, the loopback peer refused it (the conformant TCP-62 indication-only
// policy), and the session stayed usable.
func TestProbe_RenegoRefusal(t *testing.T) {
	mbtls.ClearSessionCache()
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	eng := faultEngine(srv, pki.refs(t))

	rep, err := eng.Run(context.Background(), tlsFaultCampaign(t, "renego-refusal.json"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict = %s, want PASS. summary: %s; findings: %v", rep.Verdict, rep.SummaryHuman, rep.Findings)
	}
	var reneg *RenegotiationResult
	for _, st := range rep.Steps {
		if st.Reneg != nil {
			reneg = st.Reneg
		}
	}
	if reneg == nil {
		t.Fatal("no renegotiate step evidence in the report")
	}
	if !reneg.Attempted {
		t.Error("renegotiation was not attempted")
	}
	if !reneg.SessionUsable {
		t.Errorf("session left unusable after renegotiation: %+v", reneg)
	}
}

// TestProbe_ResumeFullHandshakeFails proves the resumeAfterDrop oracle has teeth:
// with the client session cache cleared just before the resume, the reconnect
// does a FULL handshake and the oracle returns FAIL — so a peer/config that does
// not actually resume cannot green-light the TCP-46 probe.
func TestProbe_ResumeFullHandshakeFails(t *testing.T) {
	mbtls.ClearSessionCache()
	pki := newTestPKI(t)
	srv := startAuthzServer(t, pki, []uint8{2}, []Role{RoleGridService})
	refs := pki.refs(t)

	// Build a report by hand from a resume step whose session did NOT resume: the
	// most direct way to prove the oracle FAILs a full handshake without a special
	// no-resume server profile.
	conn, err := ConnectAs(srv.addr(), RoleGridService, refs)
	if err != nil {
		t.Fatalf("ConnectAs: %v", err)
	}
	defer conn.Close()
	si := conn.SessionInfo()
	if si.Resumed {
		t.Fatalf("fresh connect unexpectedly resumed: %+v", si)
	}
	rep := &CampaignReport{
		Steps: []StepResult{{Index: 0, Do: StepResume, OK: true, Session: &si}},
	}
	v, findings := resumeAfterDrop(rep)
	if v != VerdictFail {
		t.Fatalf("resumeAfterDrop on a full handshake = %s, want FAIL. findings: %v", v, findings)
	}
}
