//go:build integration

package gwmayhem

// family_integration_test.go runs the whole mbaps-northbound-authz family end to
// end against the FAITHFUL loopback gateway (loopback.go) — the hermetic proof the
// suite has teeth with zero bench access (make test-integration). It mints a
// throwaway certs/mbaps-shaped PKI (role certs + the negative fixtures), stands up
// the loopback, and asserts every scenario reaches its PINNED verdict. The
// identical scenarios then run against the live :802 for the evidence runs.
//
// It also pins the two properties that make those verdicts mean anything: the run
// used a loopback that could identify every peer it answered, and a loopback that
// CANNOT identify a peer refuses the session rather than manufacturing an
// authorization denial.
//
// Requires the amd64 wolfSSL sysroot (desktop). TestMain (wolfssl.Init) is in
// testpki_integration_test.go.

import (
	"context"
	"testing"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/mbtls"
	"csip-tls-test/sim/gw-mayhem/gwloopback"
	"lexa-proto/sunspec"
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
		"authz-role-denial-matrix": VerdictPass,
		"authz-cert-negatives":     VerdictPass,
		// Was pinned VerdictFail for a LOOPBACK limitation, not a gateway gap: the
		// loopback SERVER lost the peer role on a RESUMED session, so authz collapsed
		// to no-role and answered 0x01 instead of the value rejection 0x03. The cause
		// was never "the client did not re-send its certificate" — wolfSSL is built
		// with SESSION_CERTS and does carry the chain forward, until its bounded
		// session store evicts the row, after which every descendant session in that
		// resumption chain resumes successfully with no peer certificate at all. That
		// is why it bit only in a FULL run and at a different point each time.
		// internal/mbtls now binds peer identity to the TLS session id itself
		// (peerid.go), so the role survives an arbitrarily deep chain, and the pin is
		// back where the product's behaviour puts it. The REAL gateway was always
		// correct here (verified 2026-07-26 against the live :802: all five
		// out-of-range probes rejected 0x03 after a role-denial-matrix run).
		"authz-out-of-range-setpoint": VerdictPass,
		"authz-malformed-writes":      VerdictPass,
		"transport-session-flood":     VerdictPass,
		// Wave-3 control-loop (family C) is NeedsBench (live-driven) — skipped here as
		// expected INCONCLUSIVE; its hermetic teeth are the diagnoseControlLoop unit
		// table (make test-fast). Wave-3 authority/PKI (family D) is NeedsBoard —
		// skipped until the orchestrator arms the board.
	}

	sum := RunSuite(context.Background(), w, scenarios, nil, nil, false, false, testWriter{t})
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
	// Every authz verdict above was reached by a loopback that knew who was asking.
	// If this is non-zero, some scenario ran against a server that could not
	// establish the peer's role, and the whole authz half of the run is worthless
	// regardless of what it printed.
	if n := lb.IdentityRefusals(); n != 0 {
		t.Errorf("loopback refused %d session(s) whose peer identity it could not establish — "+
			"the run's authz verdicts were reached without a role", n)
	}
}

// TestLoopback_RefusesIdentityItCannotEstablish is the teeth for the honesty rule
// the loopback now enforces: a role it CANNOT ESTABLISH must not be served as a
// role it DENIED. The deliberately non-conformant peer here is the loopback itself
// with peer-identity recovery switched off (mbtls.Profile.DisablePeerIdentityRecovery)
// — byte for byte the pre-fix behaviour, in which wolfSSL's session store evicts a
// resumption chain's peer chain partway through and the server then sees an
// anonymous peer.
//
// The assertion is NOT "the client succeeds". It is that the failure the client
// sees is a TRANSPORT failure — which the oracles score INCONCLUSIVE, "I could not
// observe the gateway's answer" — and never exception 0x01, which asserts an
// authorization decision the loopback never made. That single substitution is what
// turned an unrelated harness bug into three fictional gateway findings (4caad35).
func TestLoopback_RefusesIdentityItCannotEstablish(t *testing.T) {
	pki := newIntegrationPKI(t)
	sp := pki.serverProfile()
	sp.DisablePeerIdentityRecovery = true
	lb, err := gwloopback.StartLoopback(sp, 8)
	if err != nil {
		t.Fatalf("StartLoopback: %v", err)
	}
	defer lb.Close()

	w := pki.world(t, lb.Addr())
	mbtls.ClearSessionCache() // start the chain from a full handshake
	ok, transport, denials := probeResumptionChain(t, w, 60)
	t.Logf("recovery off: %d reads ok, %d transport failures, %d exception denials; %d session(s) refused",
		ok, transport, denials, lb.IdentityRefusals())

	if lb.IdentityRefusals() == 0 {
		t.Skipf("wolfSSL retained the peer chain for all 60 resumptions in this run — "+
			"the loss did not reproduce, so the refusal path was not exercised (ok=%d)", ok)
	}
	if denials != 0 {
		t.Errorf("%d read(s) came back as an authorization exception while the loopback could not "+
			"establish the peer's role — a verdict it never computed", denials)
	}
	if transport == 0 {
		t.Errorf("the loopback refused %d session(s) but the client never saw a transport failure — "+
			"the refusal was not observable, which is the same silence the fix exists to remove",
			lb.IdentityRefusals())
	}
}

// TestLoopback_KeepsIdentityAcrossDeepResumption is the healthy half the teeth test
// is paired with: the same chain against the SHIPPED loopback profile never loses a
// role, never refuses a session, and answers every read.
func TestLoopback_KeepsIdentityAcrossDeepResumption(t *testing.T) {
	pki := newIntegrationPKI(t)
	lb, err := gwloopback.StartLoopback(pki.serverProfile(), 8)
	if err != nil {
		t.Fatalf("StartLoopback: %v", err)
	}
	defer lb.Close()

	w := pki.world(t, lb.Addr())
	mbtls.ClearSessionCache()
	ok, transport, denials := probeResumptionChain(t, w, 60)
	if ok != 60 {
		t.Errorf("%d/60 reads succeeded over a deep resumption chain (%d transport, %d denials); want 60",
			ok, transport, denials)
	}
	if n := lb.IdentityRefusals(); n != 0 {
		t.Errorf("loopback refused %d session(s) it should have been able to identify", n)
	}
}

// probeResumptionChain opens n sequential GridService sessions — each closed before
// the next, so every one after the first resumes — and classifies the outcome of a
// benign SunSpec-marker read on each: answered, refused by the transport, or
// answered with a protocol exception (an authorization verdict).
func probeResumptionChain(t *testing.T, w *gwWorld, n int) (ok, transport, denials int) {
	t.Helper()
	for i := 0; i < n; i++ {
		conn, err := w.connectAs(aggregator.RoleGridService)
		if err != nil {
			transport++ // refused at/just after the handshake
			continue
		}
		_, rerr := conn.ReadHolding(pingUnit, sunspec.SunSpecBase, 2)
		switch {
		case rerr == nil:
			ok++
		case isException(rerr):
			denials++
		default:
			transport++
		}
		conn.Close()
	}
	return ok, transport, denials
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
