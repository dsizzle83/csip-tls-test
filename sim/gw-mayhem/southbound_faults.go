package gwmayhem

// southbound_faults.go is FAMILY B — southbound fault injection. The gateway polls
// its DERs over two southbound transports (inv-plain = modsim tcp, inv-secure =
// mbapsdev mbaps); here ONE of them is the ADVERSARY — a misbehaving DER — while
// the OTHER is left healthy. The invariant is SAFE DIGEST + ISOLATION: the gateway
// must terminate and digest the fault without crashing, must keep serving the
// HEALTHY device (a faulted secure device never takes the plain device down, and
// vice-versa), must recover the faulted device once it clears (a comm-loss that
// heals), and must never turn a garbage register into an absurd projection.
//
// Observation is from the sims' /state, the desktop-reachable channel: the secure
// (mbaps) device reports the gateway's live poll-request counter, so an advancing
// counter is the gateway-alive / isolation signal, and a counter that stalls then
// resumes across a fault-then-clear is the comm-loss-that-recovers signal. The
// gateway's INTERNAL CommLoss flag and its northbound sentinel-masking are only
// readable over the northbound :802, which is not desktop-reachable — that gap is
// modelled by the hermetic bench stub and noted, not silently passed.

import (
	"context"
)

// sb targets + expectations.
const (
	sbTargetPlain  = "plain"  // fault modsim
	sbTargetSecure = "secure" // fault mbapsdev

	sbExpectIsolation = "isolation" // the healthy device must keep being served
	sbExpectDigest    = "digest"    // the fault must be digested safely (no crash, no absurd projection)
	sbExpectCommLoss  = "comm-loss" // the faulted device's poll must stall then RECOVER after clear
)

// sbSpec parameterises one southbound-fault scenario: the fault verb, which
// device carries it, the invariant probed, and whether the fault is armed via the
// /control (freeze) path instead of /fault.
type sbSpec struct {
	fault  string
	target string
	expect string
	freeze bool // arm via /control pause instead of /fault
}

// southboundFaultScenarios is family B.
func southboundFaultScenarios() []gwScenario {
	return []gwScenario{
		sbScenario("sb-plain-comm-loss-isolation",
			"plain DER comm-loss (listener bounced) — gateway isolates it and keeps polling the secure DER",
			sbSpec{fault: "tcp_drop", target: sbTargetPlain, expect: sbExpectIsolation}),
		sbScenario("sb-plain-register-garbage",
			"plain DER serves NaN-sentinel registers — gateway digests safely, keeps the secure DER, no absurd projection",
			sbSpec{fault: "nan_sentinel", target: sbTargetPlain, expect: sbExpectDigest}),
		sbScenario("sb-secure-register-garbage",
			"secure DER serves NaN-sentinel registers — gateway digests safely (a sentinel is N/A, not comm-loss)",
			sbSpec{fault: "nan_sentinel", target: sbTargetSecure, expect: sbExpectDigest}),
		sbScenario("sb-secure-comm-loss",
			"secure DER drops the mbaps session mid-poll — gateway flags comm-loss and recovers the device on clear",
			sbSpec{fault: "drop_session", target: sbTargetSecure, expect: sbExpectCommLoss}),
		sbScenario("sb-secure-handshake-fault",
			"secure DER stalls the mbaps handshake — gateway fails CLOSED (no plaintext downgrade), recovers on clear",
			sbSpec{fault: "stall_handshake", target: sbTargetSecure, expect: sbExpectCommLoss}),
		sbScenario("sb-stale-frozen-secure",
			"secure DER freezes its values while the world moves — gateway keeps polling, never projects an absurd value",
			sbSpec{fault: "pause", target: sbTargetSecure, expect: sbExpectDigest, freeze: true}),
	}
}

// sbScenario builds one southbound-fault scenario. All are security-critical and
// PINNED to PASS: a conformant gateway isolates + digests + recovers.
func sbScenario(id, desc string, spec sbSpec) gwScenario {
	s := spec
	return gwScenario{
		ID:         id,
		Desc:       desc,
		Category:   "southbound-fault-injection",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "sbFault",
		arm:        func(ctx context.Context, w *gwWorld, ev *gwEvidence) error { return armSB(ctx, w, ev, s) },
		teardown:   func(ctx context.Context, w *gwWorld) { sbTeardown(ctx, w, s) },
	}
}

// armSB is the shared family-B arm: capture the baseline on both devices, arm the
// fault on the target, sample the healthy device's liveness + the faulted
// device's comm-loss/absurd signals across the hold, then clear the fault and
// sample the faulted device's RECOVERY. Fills ev.SBFault.
func armSB(ctx context.Context, w *gwWorld, ev *gwEvidence, s sbSpec) error {
	b := w.bench
	faulted, healthy, ok := w.sbDevices(s.target)
	out := &sbFaultOutcome{Fault: s.fault, Target: s.target, Expect: s.expect, HealthyName: healthy.Name}
	ev.SBFault = out
	if !ok {
		ev.SetupErr = "bench not wired: sb-fault needs BOTH DER sims (-inv-plain and -inv-secure) to prove isolation"
		return nil
	}

	// Baseline: is the gateway polling the faulted device, and the healthy
	// device's liveness reference.
	baseF, _ := b.readDER(ctx, faulted)
	out.FaultedPollObservable = baseF.HasPoll
	out.FaultedPolledAtBase = baseF.HasPoll && baseF.GatewaySessed
	baseFPoll := baseF.PollRequests
	baseH, _ := b.readDER(ctx, healthy)
	baseHPoll := baseH.PollRequests

	// Arm the fault.
	if s.freeze {
		if err := b.controlSim(ctx, faulted, "pause"); err != nil {
			ev.SetupErr = "arm freeze on " + faulted.Name + ": " + err.Error()
			return nil
		}
	} else if err := b.armFault(ctx, faulted, s.fault, 0); err != nil {
		ev.SetupErr = "arm fault " + s.fault + " on " + faulted.Name + ": " + err.Error()
		return nil
	}

	t := b.timing()
	benchSleep(ctx, t.Settle)
	prevHPoll, prevFPoll := baseHPoll, baseFPoll
	faultedAdvanced := false
	for i := 0; i < t.Samples; i++ {
		if i > 0 {
			benchSleep(ctx, t.Interval)
		}
		if ctx.Err() != nil {
			break
		}
		// Healthy device: isolation / gateway-alive (only a real gateway signal on
		// the secure device's poll counter).
		if snapH, err := b.readDER(ctx, healthy); err == nil {
			out.Observed = true
			if healthy.Secure && snapH.HasPoll {
				out.HealthyLiveObs++
				if snapH.PollRequests > prevHPoll {
					out.HealthyLiveOK++
				}
				prevHPoll = snapH.PollRequests
			}
		}
		// Faulted device: comm-loss (poll stalled) + absurd digest.
		if snapF, err := b.readDER(ctx, faulted); err == nil {
			out.Observed = true
			if faulted.Secure && snapF.HasPoll && snapF.PollRequests > prevFPoll {
				faultedAdvanced = true
				prevFPoll = snapF.PollRequests
			}
			if absurdPct(snapF.AppliedPct) {
				out.AbsurdProjected = true
			}
		}
	}
	// Comm-loss = the gateway was polling the faulted (secure) device, and its poll
	// stalled while the fault held.
	if out.FaultedPolledAtBase {
		out.CommLossObserved = !faultedAdvanced
	}

	// Recovery: clear the fault, let the gateway re-establish, and confirm the
	// faulted device's poll resumes.
	sbClear(ctx, b, faulted, s)
	if out.FaultedPollObservable {
		out.Recovered = w.sbAwaitRecovery(ctx, faulted)
	}
	return nil
}

// sbClear removes whichever adversary the scenario armed on the faulted device.
func sbClear(ctx context.Context, b BenchConfig, faulted DERSim, s sbSpec) {
	if s.freeze {
		_ = b.controlSim(ctx, faulted, "resume")
		return
	}
	_ = b.clearFault(ctx, faulted, s.fault)
}

// sbTeardown clears the scenario's fault (idempotent — armSB already cleared it on
// the normal path; this covers an arm that aborted mid-way).
func sbTeardown(ctx context.Context, w *gwWorld, s sbSpec) {
	faulted, _, ok := w.sbDevices(s.target)
	if !ok {
		return
	}
	sbClear(ctx, w.bench, faulted, s)
}

// sbAwaitRecovery waits for the gateway to re-establish polling on the faulted
// secure device after the fault clears (a comm-loss that healed, not a wedge). It
// is robust to the fact that a mbaps comm-loss tears the gateway's session down
// and its per-session request counter RESETS on the fresh reconnect (so an
// absolute-count comparison against the pre-fault total would miss the recovery,
// as the reconnected session climbs from a low number). Recovery is therefore
// either: a live gateway session REAPPEARING after having been absent (the
// dropped-session case), or a live session's request count ADVANCING across two
// post-clear reads (the register/handshake case where the session never fully
// dropped). The window is a little longer than the sample cadence to ride out the
// gateway's reconnect backoff.
func (w *gwWorld) sbAwaitRecovery(ctx context.Context, faulted DERSim) bool {
	t := w.bench.timing()
	iters := t.Samples + 3 // a touch longer than the sample window for the reconnect backoff
	sawAbsent := false
	prevReq := -1
	for i := 0; i < iters; i++ {
		benchSleep(ctx, t.Interval)
		if ctx.Err() != nil {
			return false
		}
		snap, err := w.bench.readDER(ctx, faulted)
		if err != nil {
			continue
		}
		if !snap.GatewaySessed {
			sawAbsent = true
			prevReq = -1
			continue
		}
		if sawAbsent {
			return true // a session reappeared after being absent → recovered
		}
		if prevReq >= 0 && snap.PollRequests > prevReq {
			return true // a live session is actively polling again
		}
		prevReq = snap.PollRequests
	}
	return false
}

// sbDevices resolves the (faulted, healthy) DER pair for a target; ok is false
// unless BOTH sims are configured (isolation needs a healthy peer to survive).
func (w *gwWorld) sbDevices(target string) (faulted, healthy DERSim, ok bool) {
	if !w.bench.Plain.configured() || !w.bench.Secure.configured() {
		return DERSim{}, DERSim{}, false
	}
	if target == sbTargetSecure {
		return w.bench.Secure, w.bench.Plain, true
	}
	return w.bench.Plain, w.bench.Secure, true
}
