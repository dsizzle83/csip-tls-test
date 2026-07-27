//go:build integration

package gwmayhem

// speccap_integration_test.go asks one question about the SPEC half of the suite:
// when the peer's concurrent-session table is momentarily full, does a spec
// campaign report a verdict about the GATEWAY, or a verdict about the harness?
//
// The Go families already answer this correctly. gwWorld.connectAsReady exists
// precisely because an mbaps server that is at its session cap accepts the
// handshake and then closes the connection POST-handshake, so ConnectAs succeeds
// and the first op fails with a transport read error; the Go families ride that
// out with a bounded backoff. The spec campaigns went through the aggregator
// engine, whose ConnectAs was wired straight to the raw dial with no such gate —
// and the suite CREATES this condition on itself, because transport-session-flood
// deliberately fills the table immediately before the spec scenarios run.
//
// That asymmetry is what these tests pin. The reproducer stands the condition up
// hermetically (a cap-1 loopback with its one slot held), and the pair of tests
// proves both halves of the claim: with the readiness gate the campaign reaches a
// real verdict, and with it disabled — the pre-fix wiring, one field apart — the
// same campaign reports INCONCLUSIVE about a gateway that did nothing wrong.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/sim/gw-mayhem/gwloopback"
)

// grantedWriteCampaign loads the shipped GridService grant campaign — the same
// spec the suite runs, not a fixture written to be easy.
func grantedWriteCampaign(t *testing.T) *aggregator.Campaign {
	t.Helper()
	camps, errs := aggregator.LoadCampaignDir(filepath.Join("..", "..", "qa", "gw-scenarios"))
	for _, e := range errs {
		t.Fatalf("LoadCampaignDir: %v", e)
	}
	for _, c := range camps {
		if c.ID == "authz-gridservice-write-granted" {
			return c
		}
	}
	t.Fatal("qa/gw-scenarios has no authz-gridservice-write-granted campaign")
	return nil
}

// capOneWorld stands up a loopback whose session table holds exactly ONE session,
// takes that slot, and releases it after hold. It returns the world pointed at the
// loopback. Every campaign run against it therefore starts against a peer that is
// AT its cap and becomes free shortly after — the transient the flood scenario
// leaves behind, made deterministic.
func capOneWorld(t *testing.T, hold time.Duration) *gwWorld {
	t.Helper()
	pki := newIntegrationPKI(t)
	lb, err := gwloopback.StartLoopback(pki.serverProfile(), 1)
	if err != nil {
		t.Fatalf("StartLoopback: %v", err)
	}
	t.Cleanup(lb.Close)

	w := pki.world(t, lb.Addr())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	hog, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		t.Fatalf("could not take the loopback's only session slot: %v", err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(hold)
		_ = hog.Close()
		close(released)
	}()
	t.Cleanup(func() { <-released })
	return w
}

// TestSpecCampaign_RidesOutATransientSessionCap is the healthy half: the shipped
// GridService grant campaign, run against a peer whose only session slot is held
// for longer than a single dial takes, still reaches the gateway's real answer.
func TestSpecCampaign_RidesOutATransientSessionCap(t *testing.T) {
	w := capOneWorld(t, 600*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rep, err := w.eng.Run(ctx, grantedWriteCampaign(t))
	if err != nil {
		t.Fatalf("campaign run: %v", err)
	}
	if rep.Verdict != VerdictPass {
		t.Errorf("campaign verdict %s against a peer that was momentarily at its session cap; want PASS. findings: %v",
			rep.Verdict, rep.Findings)
	}
}

// TestSpecCampaign_WithoutReadinessTheCapBecomesAVerdict is the teeth. The
// deliberately non-conformant configuration here is the HARNESS, not the peer:
// the same loopback, the same campaign, with the connect readiness gate switched
// off (disableConnectReadiness — the pre-fix wiring). The assertion is not that
// the campaign fails, it is that it fails for a reason that is about the harness
// and is stated as one: an INCONCLUSIVE whose finding names the transport. If
// this ever comes back PASS, the gate above is passing for free and proves
// nothing.
func TestSpecCampaign_WithoutReadinessTheCapBecomesAVerdict(t *testing.T) {
	w := capOneWorld(t, 600*time.Millisecond)
	w.disableConnectReadiness = true
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rep, err := w.eng.Run(ctx, grantedWriteCampaign(t))
	if err != nil {
		t.Fatalf("campaign run: %v", err)
	}
	if rep.Verdict == VerdictPass {
		t.Fatalf("the campaign PASSed with the readiness gate off — the session-cap transient did not reproduce, "+
			"so TestSpecCampaign_RidesOutATransientSessionCap is not proving anything. findings: %v", rep.Findings)
	}
	joined := strings.Join(rep.Findings, " | ")
	if rep.Verdict != VerdictInconclusive {
		t.Errorf("verdict %s with the readiness gate off; want INCONCLUSIVE (the harness could not observe). findings: %s",
			rep.Verdict, joined)
	}
	if !strings.Contains(joined, "transport") && !strings.Contains(joined, "could not connect") {
		t.Errorf("findings do not name the transport as the reason: %s", joined)
	}
}
