//go:build integration

package main

// conformance_integration_test.go proves the 62-requirement suite end to end
// against the in-process loopback authz-enforcing mbaps server: a clean run
// addresses every SunSpecTCP row with zero FAILs (the acceptance bar), and a
// deliberately non-conformant peer (a read-only role allowed to write) FAILs the
// denial rows — proving the checks have teeth and cannot rubber-stamp a broken
// gateway. Requires the amd64 wolfSSL sysroot (desktop, `make test-integration`).

import (
	"io"
	"os"
	"testing"
	"time"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
)

// TestMain initialises wolfSSL once for the whole integration binary (CLAUDE.md
// wolfSSL_Init invariant), mirroring internal/mbtls and internal/aggregator.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

func loopbackRunCtx(t *testing.T, served []uint8, writeRoles []Role) *runCtx {
	t.Helper()
	mbtls.ClearSessionCache()
	ps, err := mintLoopbackPKI()
	if err != nil {
		t.Fatalf("mintLoopbackPKI: %v", err)
	}
	t.Cleanup(ps.cleanup)
	srv, stop, err := startLoopbackCustom(ps, served, writeRoles)
	if err != nil {
		t.Fatalf("startLoopbackCustom: %v", err)
	}
	t.Cleanup(stop)
	return &runCtx{target: srv.addr(), ps: ps, port: portOf(srv.addr()), isLoopback: true}
}

func runAllChecks(rc *runCtx) *Reporter {
	r := &Reporter{w: io.Discard, results: make(map[int]Result), target: rc.target, started: time.Now()}
	checkTransportSecurity(r, rc)
	checkCipherSuites(r, rc)
	checkAuthz(r, rc)
	checkPKI(r, rc)
	checkPacketSession(r, rc)
	return r
}

// TestFullLoopbackRun asserts a clean run addresses all 62 rows with zero FAILs.
func TestFullLoopbackRun(t *testing.T) {
	rc := loopbackRunCtx(t, loopbackUnits, []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin})
	r := runAllChecks(rc)

	if missing := r.missingRows(); len(missing) != 0 {
		t.Fatalf("requirements NOT ADDRESSED: %v", missing)
	}
	pass, fail, skip, warn := r.counts()
	if fail != 0 {
		var fails []string
		for _, res := range r.results {
			if res.Status == StatusFail {
				fails = append(fails, res.ID+": "+res.Evidence)
			}
		}
		t.Fatalf("clean loopback run had %d FAIL(s): %v", fail, fails)
	}
	if pass+skip+warn != 62 {
		t.Fatalf("pass(%d)+skip(%d)+warn(%d) = %d, want 62", pass, skip, warn, pass+skip+warn)
	}
	// The suite must actually ASSERT a healthy majority, not skip its way to green.
	if pass < 45 {
		t.Errorf("only %d PASS — expected the loopback to wire-assert ≥45 rows", pass)
	}

	// Spot-check the load-bearing verdicts.
	for _, n := range []int{4, 6, 11, 13, 17, 20, 32, 40, 41, 46, 60} {
		if r.results[n].Status != StatusPass {
			t.Errorf("%s = %s, want PASS (%s)", reqID(n), r.results[n].Status, r.results[n].Evidence)
		}
	}
}

// TestChecksHaveTeeth points the suite at a non-conformant peer that lets a
// read-only role write, and asserts the denial rows FAIL — the suite cannot
// green-light a broken authz engine.
func TestChecksHaveTeeth(t *testing.T) {
	// Every role write-capable ⇒ ReadOnly/LexaVolt writes are (wrongly) accepted.
	allRoles := []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin, RoleReadOnly, RoleLexaVolt}
	rc := loopbackRunCtx(t, loopbackUnits, allRoles)

	r := &Reporter{w: io.Discard, results: make(map[int]Result), target: rc.target, started: time.Now()}
	checkAuthz(r, rc)

	for _, n := range []int{8, 40, 41} {
		if r.results[n].Status != StatusFail {
			t.Errorf("%s = %s against a permissive authz peer, want FAIL (%s)", reqID(n), r.results[n].Status, r.results[n].Evidence)
		}
	}
	// The no-role/malformed denial (TCP-32) is still enforced by the loopback
	// (unrecognized roles are always denied), so it should still PASS — the teeth
	// test isolates the write-grant regression, not the role-less path.
	if r.results[32].Status != StatusPass {
		t.Errorf("SunSpecTCP-32 = %s, want PASS (role-less denial is independent of the write-grant regression)", r.results[32].Status)
	}
}
