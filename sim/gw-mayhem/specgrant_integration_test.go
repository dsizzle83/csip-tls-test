//go:build integration

package gwmayhem

// specgrant_integration_test.go is the end-to-end teeth for the GRANT half of the
// RBAC contract — the claim authz-gridservice-write-granted exists to make, and
// the one it could not previously fail on.
//
// Its hypothesis, in its own words: "A grid-service role DENIED a legitimate
// control write is as much a failure as a read-only role being granted one." The
// deliberately non-conformant peer that proves the scenario can say so is a
// loopback started with GridService REMOVED from the write-allow set
// (StartLoopbackWriteRoles — the same instrument the matrix oracle's over-grant
// teeth use, pointed the other way). Against it the campaign must reach FAIL: the
// gateway refused a control it owes. Against the shipped loopback it must PASS.
//
// Before the ExCode fix in internal/aggregator this test would have gone
// INCONCLUSIVE, because the refusal reaches the caller wrapped inside the block-
// layout scan the typed write performs, and the oracle's transport-vs-refusal
// branch keyed on a field a write step never populates. INCONCLUSIVE is not a
// harmless mis-label here: it says "the harness could not observe" about a
// gateway that made a very clear statement.

import (
	"context"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/sim/gw-mayhem/gwloopback"
)

// grantWorld stands up a loopback whose write-allow set is exactly writeRoles and
// returns a world pointed at it.
func grantWorld(t *testing.T, writeRoles []aggregator.Role) *gwWorld {
	t.Helper()
	pki := newIntegrationPKI(t)
	lb, err := gwloopback.StartLoopbackWriteRoles(pki.serverProfile(), 8, writeRoles)
	if err != nil {
		t.Fatalf("StartLoopbackWriteRoles: %v", err)
	}
	t.Cleanup(lb.Close)
	return pki.world(t, lb.Addr())
}

// TestSpecGrant_DeniedLegitimateWriteIsAFail is the teeth: a peer that denies
// GridService its control write must be FAILED by the shipped campaign, and the
// finding must say the write was refused.
func TestSpecGrant_DeniedLegitimateWriteIsAFail(t *testing.T) {
	// Every role EXCEPT GridService may write — so the denial is specific to the
	// role under test and cannot be confused with a peer that refuses all writes.
	w := grantWorld(t, []aggregator.Role{
		aggregator.RoleSuperAdmin, aggregator.RoleNetworkAdmin,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rep, err := w.eng.Run(ctx, grantedWriteCampaign(t))
	if err != nil {
		t.Fatalf("campaign run: %v", err)
	}
	joined := strings.Join(rep.Findings, " | ")
	if rep.Verdict != VerdictFail {
		t.Fatalf("verdict %s against a peer that DENIES GridService its control write; want FAIL. findings: %s",
			rep.Verdict, joined)
	}
	if !strings.Contains(joined, "REFUSED") {
		t.Errorf("the finding does not name the refusal — an operator reading this cannot tell a denial from an unreachable peer: %s", joined)
	}
}

// TestSpecGrant_ShippedLoopbackPasses is the healthy half the teeth are paired
// with: against the loopback's real write-allow set the same campaign PASSes, so
// the FAIL above is about the peer's authorization and nothing else.
func TestSpecGrant_ShippedLoopbackPasses(t *testing.T) {
	w := grantWorld(t, gwloopback.LoopbackWriteRoles())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rep, err := w.eng.Run(ctx, grantedWriteCampaign(t))
	if err != nil {
		t.Fatalf("campaign run: %v", err)
	}
	if rep.Verdict != VerdictPass {
		t.Errorf("verdict %s against the shipped loopback write-allow set; want PASS. findings: %v",
			rep.Verdict, rep.Findings)
	}
}
