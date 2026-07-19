//go:build integration

package gwmayhem

// family_integration_test.go runs the whole mbaps-northbound-authz family end to
// end against the FAITHFUL loopback gateway (loopback.go) — the hermetic proof the
// suite has teeth with zero bench access (make test-integration). It mints a
// throwaway certs/mbaps-shaped PKI (role certs + the negative fixtures), stands up
// the loopback, and asserts every scenario reaches its PINNED verdict — including
// the out-of-range gap (FAIL) the loopback models. The identical scenarios then run
// against the live :802 for the evidence runs.
//
// Requires the amd64 wolfSSL sysroot (desktop). TestMain (wolfssl.Init) is in
// testpki_integration_test.go.

import (
	"context"
	"testing"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/sim/gw-mayhem/gwloopback"
)

// TestFamily_AgainstLoopback runs every Go family + the shipped specs against the
// faithful loopback and asserts each scenario's verdict is within its expected set
// (the whole-suite gate PASSes hermetically).
func TestFamily_AgainstLoopback(t *testing.T) {
	pki := newIntegrationPKI(t)
	lb, err := gwloopback.StartLoopback(pki.serverProfile(), 8)
	if err != nil {
		t.Fatalf("StartLoopback: %v", err)
	}
	defer lb.Close()

	w := pki.world(t, lb.Addr())
	scenarios := goScenarios()

	want := map[string]Verdict{
		"authz-role-denial-matrix":    VerdictPass,
		"authz-cert-negatives":        VerdictPass,
		"authz-out-of-range-setpoint": VerdictFail, // pinned gap — the loopback models it
		"authz-malformed-writes":      VerdictPass,
		"transport-session-flood":     VerdictPass,
	}

	sum := RunSuite(context.Background(), w, scenarios, nil, nil, false, testWriter{t})
	if sum.GateFailures != 0 {
		t.Errorf("gate failures = %d, want 0 (every scenario within its expected set)", sum.GateFailures)
	}
	for _, rep := range sum.Reports {
		if exp, ok := want[rep.ID]; ok && rep.Verdict != exp {
			t.Errorf("%s verdict = %s, want %s. findings: %v", rep.ID, rep.Verdict, exp, rep.Findings)
		}
		if !rep.VerdictExpected {
			t.Errorf("%s verdict %s outside expected %v", rep.ID, rep.Verdict, rep.Expected)
		}
	}
}

// TestMatrix_CatchesOverGrant proves the matrix oracle has TEETH: a non-conformant
// loopback that lets NetworkAdmin write a control (a role that must be denied) is
// caught as a FAIL, not a false PASS.
func TestMatrix_CatchesOverGrant(t *testing.T) {
	pki := newIntegrationPKI(t)
	// A deliberately-broken gateway: NetworkAdmin is (wrongly) allowed to write.
	lb, err := gwloopback.StartLoopbackWriteRoles(pki.serverProfile(), 8, []aggregator.Role{
		aggregator.RoleGridService, aggregator.RoleSuperAdmin, aggregator.RoleNetworkAdmin,
	})
	if err != nil {
		t.Fatalf("StartLoopback: %v", err)
	}
	defer lb.Close()

	w := pki.world(t, lb.Addr())
	rep := runScenario(context.Background(), w, roleDenialMatrix())
	if rep.Verdict != VerdictFail {
		t.Fatalf("matrix verdict = %s, want FAIL (NetworkAdmin write over-grant must be caught). findings: %v", rep.Verdict, rep.Findings)
	}
}

// TestCertAuthz_LayerPlacement proves the cert-authz family distinguishes a
// handshake-layer rejection (expired / wrong-CA) from an authz-layer denial
// (role-less / malformed) against the loopback.
func TestCertAuthz_LayerPlacement(t *testing.T) {
	pki := newIntegrationPKI(t)
	lb, err := gwloopback.StartLoopback(pki.serverProfile(), 8)
	if err != nil {
		t.Fatalf("StartLoopback: %v", err)
	}
	defer lb.Close()

	w := pki.world(t, lb.Addr())
	rep := runScenario(context.Background(), w, certNegatives())
	if rep.Verdict != VerdictPass {
		t.Fatalf("cert-authz verdict = %s, want PASS. findings: %v", rep.Verdict, rep.Findings)
	}
	// Every fixture must have been observed at its expected layer.
	for _, c := range rep.Evidence.Certs {
		switch c.ExpectLayer {
		case "handshake":
			if c.Handshake != "failed" {
				t.Errorf("%s: handshake=%s, want failed (chain-invalid must be rejected at TLS)", c.Fixture, c.Handshake)
			}
		case "authz":
			if c.Handshake != "ok" || !c.DeniedAll || c.AuthzExCode != 0x01 {
				t.Errorf("%s: handshake=%s deniedAll=%t code=0x%02x, want ok + denied-all 0x01", c.Fixture, c.Handshake, c.DeniedAll, c.AuthzExCode)
			}
		}
	}
}

// testWriter adapts *testing.T to io.Writer so the runner's evidence table lands in
// the test log.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
