package suitecsip

// core005_test.go pins CORE-005's gateway-ssh clock probe tier (census
// runs/final-csip-20260731T213346, CORE-005 item #4): "server clock skew
// reported, but whether the DUT set its clock is internal state — wire can't
// see it." probeGatewayClock adds an OPTIONAL second tier over the existing
// wire-timestamp inference — a read-only `date -u +%s` on the DUT, taken via
// the same -gateway-ssh channel other suites already use for DUT
// introspection (internal/certify.Gateway, CheckReadOnly-guarded) — and
// critClockAdopted grades it. Both halves are pinned here: the probe's
// plumbing (Params in, Params out, graceful degrade), and the criterion's
// three shapes (no probe configured, probe succeeded, probe output unusable).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

// TestProbeGatewayClock_NoGatewaySSH is the degrade-gracefully case: a run
// with no -gateway-ssh must leave Params untouched and return no error, so
// coreBasicTime's PostWait never turns an ordinary bench run into a spurious
// log line.
func TestProbeGatewayClock_NoGatewaySSH(t *testing.T) {
	rc := &certify.RunCtx{Gateway: &certify.Gateway{}} // Available() == false
	params := map[string]string{}
	if err := probeGatewayClock(context.Background(), NewDriver(rc), params); err != nil {
		t.Fatalf("no -gateway-ssh should be a silent no-op, got error: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("params should stay empty with no gateway configured, got %v", params)
	}
}

// TestProbeGatewayClock_Success proves the happy path: `date -u +%s`'s stdout
// lands in gwClockParam, trimmed, with a probe timestamp alongside it.
func TestProbeGatewayClock_Success(t *testing.T) {
	rc := &certify.RunCtx{Gateway: &certify.Gateway{SSH: "cc93", Runner: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("1785534575\n"), nil
	}}}
	params := map[string]string{}
	if err := probeGatewayClock(context.Background(), NewDriver(rc), params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params[gwClockParam] != "1785534575" {
		t.Errorf("gwClockParam = %q, want %q (trimmed)", params[gwClockParam], "1785534575")
	}
	if params[gwClockAtParam] == "" {
		t.Error("gwClockAtParam (when the probe ran) was not recorded")
	}
	if params[gwClockErrParam] != "" {
		t.Errorf("gwClockErrParam should be empty on success, got %q", params[gwClockErrParam])
	}
}

// TestProbeGatewayClock_Failure proves a probe failure is recorded, not
// swallowed — and that it is NOT fatal to the caller: check.go's PostWait
// only logs the returned error, exactly like Setup/Change treat their own
// bench-lever failures as evidence, not grounds to abandon the run.
func TestProbeGatewayClock_Failure(t *testing.T) {
	rc := &certify.RunCtx{Gateway: &certify.Gateway{SSH: "cc93", Runner: func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("ssh: connect to host 69.0.0.2 port 22: Connection refused")
	}}}
	params := map[string]string{}
	err := probeGatewayClock(context.Background(), NewDriver(rc), params)
	if err == nil {
		t.Fatal("expected the ssh failure to propagate so PostWait's caller can log it")
	}
	if !strings.Contains(params[gwClockErrParam], "Connection refused") {
		t.Errorf("gwClockErrParam should carry the failure, got %q", params[gwClockErrParam])
	}
	if params[gwClockParam] != "" {
		t.Errorf("gwClockParam should stay empty on failure, got %q", params[gwClockParam])
	}
}

// TestCritClockAdopted_NoProbe is today's behaviour, unchanged: no
// -gateway-ssh (or Params simply carrying nothing) still reports the
// wire-timestamp skew and explains why the DUT's actual clock adoption is
// unobservable — the WARN this criterion has always produced.
func TestCritClockAdopted_NoProbe(t *testing.T) {
	o := &Observation{Params: map[string]string{}}
	f := wantVerdict(t, "clock adopted (no probe)", critClockAdopted(o),
		synthTranscript(get("/tm", 200, timeXML(1000, 7))), certify.Warn)
	if !strings.Contains(f.Observed, "internal state") {
		t.Errorf("the no-probe WARN should still explain why clock adoption is unobservable: %q", f.Observed)
	}
	if !strings.Contains(f.Observed, "no -gateway-ssh") {
		t.Errorf("the no-probe WARN should say a probe was never attempted: %q", f.Observed)
	}
}

// TestCritClockAdopted_ProbeFailed names the failure rather than reproducing
// the generic no-probe text — a reader should be able to tell "nobody asked"
// from "we asked and it broke".
func TestCritClockAdopted_ProbeFailed(t *testing.T) {
	o := &Observation{Params: map[string]string{gwClockErrParam: "ssh: connect: timed out"}}
	f := wantVerdict(t, "clock adopted (probe failed)", critClockAdopted(o),
		synthTranscript(get("/tm", 200, timeXML(1000, 7))), certify.Warn)
	if !strings.Contains(f.Observed, "timed out") {
		t.Errorf("the probe-failed WARN should carry the failure reason: %q", f.Observed)
	}
}

// TestCritClockAdopted_ProbeMeasured is the new tier actually working: a real
// gateway-ssh reading lets the criterion report a DIRECT DUT-clock-vs-server
// skew, not just the wire-timestamp inference — and it must stay WARN
// (informational), never PASS, because CORE-005's own catalog text prints no
// numeric tolerance to grade a threshold against (csip-conf-v1.3::CORE-005
// steps 5-6; TIME.011 bounds backward-step SIZE, a different property).
func TestCritClockAdopted_ProbeMeasured(t *testing.T) {
	// Server currentTime=1000; DUT clock probed at 1000+872ms rounds to 1s —
	// close enough to exercise the "measured" branch without asserting an
	// exact rounding boundary this test does not own.
	o := &Observation{Params: map[string]string{
		gwClockParam:   "1001",
		gwClockAtParam: "2026-07-31T21:49:36Z",
	}}
	f := wantVerdict(t, "clock adopted (probe measured)", critClockAdopted(o),
		synthTranscript(get("/tm", 200, timeXML(1000, 7))), certify.Warn)
	for _, want := range []string{"gateway-ssh", "1001", "1000", "no numeric tolerance"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the measured WARN should cite the probe output and explain why it stays informational "+
				"(missing %q): %q", want, f.Observed)
		}
	}
}

// TestCritClockAdopted_ProbeUnparseable proves a garbled probe output degrades
// to a clear WARN rather than a panic or a silently-wrong skew computation.
func TestCritClockAdopted_ProbeUnparseable(t *testing.T) {
	o := &Observation{Params: map[string]string{gwClockParam: "not-a-timestamp"}}
	f := wantVerdict(t, "clock adopted (probe unparseable)", critClockAdopted(o),
		synthTranscript(get("/tm", 200, timeXML(1000, 7))), certify.Warn)
	if !strings.Contains(f.Observed, "did not parse") {
		t.Errorf("the unparseable-probe WARN should say so: %q", f.Observed)
	}
}

// TestCritClockAdopted_NoTimeResource is the pre-existing Unavailable path,
// unchanged by the probe tier: no Time resource means no server currentTime
// to compare EITHER clock reading against.
func TestCritClockAdopted_NoTimeResource(t *testing.T) {
	o := &Observation{Params: map[string]string{gwClockParam: "1001"}}
	wantUnavailable(t, "clock adopted (no Time resource)", critClockAdopted(o),
		synthTranscript(get("/dcap", 200, dcapXML())))
}
