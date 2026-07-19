package gwmayhem

// compound_fault.go is the COMPOUND-FAULT family (gap G4) — the "perfect storm".
// Where the wave-2 families each arm ONE adversary (a hostile head-end, or a
// misbehaving DER) and the wave-1/wave-3 families drive the gateway's :802
// authz/control loop, this family composes THREE faults at ONCE and asserts the
// gateway holds FAIL-CLOSED through all of them together: a NORTHBOUND head-end
// WAN outage (family A's nb-headend-wan-outage drive), a SOUTHBOUND secure-DER
// comm-loss (family B's sb-secure-comm-loss drop_session), and a HOSTILE
// out-of-range write (the malformed-write family's WMaxLimPct>100), all armed
// simultaneously over a single hold. The invariant is that the compound load
// opens NO hole a single fault does not: the out-of-range write is still rejected
// and never applied, no absurd setpoint is ever projected onto a DER, the safe
// baseline cap the gateway adopted still HOLDS, the gateway stays responsive (no
// wedge), and it RECOVERS the faulted DER once the storm clears.
//
// Go-literal, not a data campaign: the simultaneous multi-adversary arm ordering
// and the compound-invariant sampling are real logic outside the aggregator
// campaign schema (and outside any single wave-2 arm). It reuses the family-A
// outage drive (armOutage / nbOutageDurationS), the family-B fault drive +
// recovery (armFault / sbDevices / sbAwaitRecovery), and the family-C control
// primitives (writePointRetry / pollReadback) wholesale; the pure
// diagnosePerfectStorm oracle judges the sampled perfectStormOutcome.
//
// The gateway is only OBSERVED, never reconfigured (every arm is a desktop-side
// fault drive against a sim/gridsim admin API plus reads over the aggregator's
// own :802 session), so a live run is safe to arm. NeedsBench: the storm needs
// the live gateway, both DER sims, and the gridsim head-end; its hermetic teeth
// are the pure diagnosePerfectStorm decision table (oracles_test.go, test-fast).

import (
	"context"
	"fmt"
	"math"

	"csip-tls-test/internal/aggregator"
	"lexa-proto/sunspec"
)

// perfect-storm tuning.
const (
	perfectStormCapPct     = 50.0           // the safe baseline cap the gateway must HOLD through the storm
	perfectStormHostilePct = 150.0          // the out-of-range WMaxLimPct the hostile write commands (must be rejected, never applied)
	perfectStormSBFault    = "drop_session" // the southbound comm-loss armed on the secure DER (mirrors sb-secure-comm-loss)
)

// compoundFaultScenarios is the compound-fault family (gap G4) — currently the one
// perfect-storm scenario, appended like the other Go-literal families.
func compoundFaultScenarios() []gwScenario {
	return []gwScenario{perfectStormScenario()}
}

// perfectStormScenario builds the perfect-storm compound-fault scenario. It is
// security-critical and PINNED to PASS: a conformant gateway holds fail-closed
// with no wedge and no absurd projection even under three simultaneous faults.
func perfectStormScenario() gwScenario {
	return gwScenario{
		ID:         "perfect-storm-compound-fault",
		Desc:       "SIMULTANEOUS northbound head-end outage + southbound secure comm-loss + hostile out-of-range write — gateway holds fail-closed, no wedge, no absurd projection, recovers on clear",
		Category:   "compound-fault",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "perfectStorm",
		arm:        armPerfectStorm,
		teardown:   perfectStormTeardown,
	}
}

// armPerfectStorm arms the three adversaries at once, samples the gateway's
// fail-closed behaviour across the hold, then clears both faults and confirms
// recovery. It fills ev.PerfectStorm; the perfectStorm oracle judges it.
func armPerfectStorm(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	b := w.bench
	out := &perfectStormOutcome{}
	ev.PerfectStorm = out

	// The storm needs BOTH DER sims (the secure one is the southbound comm-loss
	// target + the only device with a poll counter; the plain one is a healthy
	// projection peer) AND the gridsim head-end (the northbound outage). Without all
	// of them there is nothing to compound.
	faulted, healthy, ok := w.sbDevices(sbTargetSecure)
	if !ok || b.GridsimAdmin == "" {
		ev.SetupErr = "bench not wired: perfect-storm needs both DER sims (-inv-plain and -inv-secure) and -gridsim-admin to compound a northbound + southbound + write fault"
		return nil
	}

	// 1. Discover a served control unit and open a GridService :802 session (the
	// must-succeed connect the control-loop family uses — rides out a transient
	// session-cap refusal). This aggregator session is INDEPENDENT of both armed
	// faults (the head-end outage is northbound of the gateway's CLIENT; drop_session
	// is on the gateway's SOUTHBOUND poll), so it stays usable throughout the storm.
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		ev.SetupErr = "no served unit advertises the control model (704) — cannot drive the storm"
		return nil
	}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		ev.SetupErr = "connect GridService: " + err.Error()
		return nil
	}
	defer conn.Close()

	// 2. Baseline cap: enable the limit and write WMaxLimPct=50, then confirm the
	// echo converges to 50 (the cap actually took). This is the safe control the
	// gateway must HOLD through the storm; CapSet gates the unseat check so a cap
	// that never took is never scored as "unseated".
	_ = writePointRetry(ctx, conn, unit, pointWMaxLimPctEna, 1)
	if writeBlip(writePointRetry(ctx, conn, unit, matrixCtrlPoint, perfectStormCapPct)) {
		out.Note = joinNote(out.Note, "the baseline-cap write hit a persistent transport error — the readback below judges whether it landed")
	}
	capRB := pollReadback(ctx, conn, unit, perfectStormCapPct, ctlTol, ctlSettleSLA, "baseline-cap", "")
	out.CapSet = capRB.Converged
	if !out.CapSet {
		out.Note = joinNote(out.Note, fmt.Sprintf("baseline cap did not converge to %g%% (final %g) — HOLD sub-invariant not exercised", perfectStormCapPct, capRB.Final))
	}

	// Baseline the secure DER's poll counter (the liveness reference) before arming.
	baseSecure, _ := b.readDER(ctx, faulted)
	if baseSecure.HasPoll {
		out.Observed = true
	}
	basePoll := baseSecure.PollRequests

	// 3. Arm the NORTHBOUND head-end outage — the EXACT drive family-A's
	// nb-headend-wan-outage uses (armOutage "down", self-clearing past the whole
	// sample window so an aborted run never leaves the bench northbound-dead).
	if err := b.armOutage(ctx, outageModeDown, nbOutageDurationS(b), 0); err != nil {
		ev.SetupErr = "arm head-end outage: " + err.Error()
		return nil
	}
	// 4. Arm the SOUTHBOUND comm-loss on the secure DER (drop_session — the gateway's
	// mbaps poll session is torn down mid-exchange, the same fault sb-secure-comm-loss
	// arms).
	if err := b.armFault(ctx, faulted, perfectStormSBFault, 0); err != nil {
		ev.SetupErr = "arm southbound comm-loss on " + faulted.Name + ": " + err.Error()
		return nil
	}

	// 5. HOSTILE out-of-range write while BOTH faults hold: WMaxLimPct=150 must be
	// rejected (exception) and NEVER applied — the compound load must not open the
	// range-check hole the in-range path closes (canonically authz-out-of-range-
	// setpoint, design 02 §4.4). A transport error here is an observation failure
	// (the :802 session should be unaffected by the faults), scored INCONCLUSIVE via
	// SetupErr, never a false FAIL.
	res, perr := conn.ProbeDenied(unit, sunspec.ModelDERCtlAC, matrixCtrlPoint, perfectStormHostilePct)
	switch {
	case perr != nil:
		ev.SetupErr = "hostile out-of-range write probe hit a transport error under the storm: " + perr.Error()
		return nil
	case res.Wrote:
		out.HostileWriteRejected = false
		out.Note = joinNote(out.Note, fmt.Sprintf("gateway ACCEPTED WMaxLimPct=%g under the compound fault (out-of-range not rejected)", perfectStormHostilePct))
	default:
		out.HostileWriteRejected = true
	}

	// 6. Sample across the hold (armSB/armNB cadence): the gateway must stay
	// responsive, never project an absurd setpoint, and never unseat the safe cap.
	t := b.timing()
	benchSleep(ctx, t.Settle)
	prevPoll := basePoll
	for i := 0; i < t.Samples; i++ {
		if i > 0 {
			benchSleep(ctx, t.Interval)
		}
		if ctx.Err() != nil {
			break
		}

		// (a) The gateway's :802 control echo, read over the aggregator session (which
		// both faults leave untouched). A successful read proves the gateway process
		// stayed RESPONSIVE under the triple load — a crashed/wedged gateway stops
		// answering :802 — and the value proves the safe cap still HOLDS: an echo that
		// drifts off the 50% cap up to uncapped is an unseat.
		if v, rerr := conn.ReadPoint(unit, matrixCtrlModel, matrixCtrlPoint); rerr == nil {
			out.Observed = true
			out.Responsive = true // the gateway answered :802 → alive under the storm
			if out.CapSet && !math.IsNaN(v) {
				out.Unseated = !isCap(v) // still a cap → held; uncapped → unseated
			}
		}

		// (b) The secure DER's /state — a corroborating SOUTHBOUND liveness signal plus
		// the absurd-projection check. NOTE — the armed drop_session deliberately stalls
		// this device's request counter (the drop fires BEFORE the sim counts the
		// request; that stall IS the comm-loss), and the plain DER exposes no counter, so
		// a counter-advance signal is not expected DURING the storm. The honest during-
		// hold liveness is therefore "the gateway kept trying" — a live/attempted mbaps
		// session still observed (GatewaySessed) — with a counter-advance also honored if
		// the gateway lands a poll in a reconnect race. The counter-advance RECOVERY is
		// asserted separately after the storm clears (step 7).
		if snap, err := b.readDER(ctx, faulted); err == nil {
			out.Observed = true
			if snap.GatewaySessed || snap.PollRequests > prevPoll {
				out.Responsive = true
			}
			if snap.PollRequests > prevPoll {
				prevPoll = snap.PollRequests
			}
			if absurdPct(snap.AppliedPct) {
				out.AbsurdProjected = true
			}
		}
		// (c) The healthy plain DER's /state — the never-project-garbage check on the
		// device the gateway keeps projecting onto while the secure one is faulted.
		if snap, err := b.readDER(ctx, healthy); err == nil {
			out.Observed = true
			if absurdPct(snap.AppliedPct) {
				out.AbsurdProjected = true
			}
		}
	}

	// 7. Clear BOTH adversaries and confirm the gateway RECOVERS the faulted secure
	// DER (its poll resumes — a comm-loss that healed, not a permanent wedge). The
	// gridsim outage self-clears too, but we clear it explicitly so recovery is not
	// gated on that self-clear timer.
	_ = b.clearFault(ctx, faulted, perfectStormSBFault)
	_ = b.clearOutage(ctx)
	out.Recovered = w.sbAwaitRecovery(ctx, faulted)
	return nil
}

// perfectStormTeardown clears both armed adversaries (idempotent — armPerfectStorm
// clears them on the normal path; this covers an arm that aborted mid-storm) and
// releases the baseline cap so the run never leaves the bench faulted or curtailed.
func perfectStormTeardown(ctx context.Context, w *gwWorld) {
	if faulted, _, ok := w.sbDevices(sbTargetSecure); ok {
		_ = w.bench.clearFault(ctx, faulted, perfectStormSBFault)
	}
	w.bench.clearBench(ctx) // clears the gridsim outage/malform/clock
	releaseControlUnit(ctx, w)
}
