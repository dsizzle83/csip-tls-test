package gwmayhem

// comm_loss_mask.go is the COMM-LOSS SENTINEL-MASK + CONTROL-ECHO-SURVIVAL family
// (gap G5). Where the wave-2 southbound-fault family (southbound_faults.go) can only
// OBSERVE a comm-loss from the sims' desktop-reachable /state — and explicitly
// CANNOT see the gateway's northbound sentinel-masking (southbound_faults.go lines
// 16-18) — this scenario drives the NORTHBOUND :802 aggregator session, the one
// channel where the mask is observable, and proves the product's internal
// regmap "maskOffline" invariant end to end:
//
//   when a DER goes comm-loss (missed polls past the offline threshold), the gateway
//   MASKS that DER's northbound telemetry (measurement model 701) to the
//   not-implemented SENTINEL — a read returns NaN over :802, NEVER a stale or absurd
//   value — WHILE its commanded control echo (model 704 WMaxLimPct) SURVIVES. The 704
//   exemption is deliberate: a commanded setpoint must not be wiped by a transient
//   missed poll (a curtailed DER that briefly stops answering polls must stay
//   curtailed, not silently revert to uncapped).
//
// Serial-independent DIFFERENTIAL: we do NOT hardcode a unit/serial. We fault the
// SECURE DER, then DETECT which :802 unit masks (its 701 telemetry, real at baseline,
// becomes the sentinel) while a peer unit keeps serving real telemetry — so the
// scenario is robust to however units are assigned. The gateway is only OBSERVED
// (the fault is a desktop-side sim drive; every read is over the aggregator's own
// :802 session), so a live run is safe to arm. NeedsBench; its hermetic teeth are the
// pure diagnoseCommLossMask decision table (oracles_test.go, make test-fast).

import (
	"context"
	"math"

	"csip-tls-test/internal/aggregator"
	"lexa-proto/sunspec"
)

// comm-loss mask tuning.
const (
	commLossMaskFault  = "drop_session" // the southbound comm-loss armed on the secure DER (mirrors sb-secure-comm-loss)
	commLossMaskCapPct = 50.0           // the commanded 704 WMaxLimPct control echo that MUST survive the 701 telemetry mask
	// The mask appears only AFTER the gateway crosses its missed-poll OFFLINE threshold,
	// which is several poll cycles later than a single southbound poll — so the sample
	// window runs LONGER than the wave-2 default (armSB clears as soon as the fault holds).
	commLossMaskExtraSamples = 6
)

// commLossMaskScenarios is the comm-loss sentinel-mask family (gap G5) — the one
// scenario, appended like the other Go-literal families.
func commLossMaskScenarios() []gwScenario {
	return []gwScenario{commLossMaskScenario()}
}

// commLossMaskScenario builds the comm-loss sentinel-mask + control-echo-survival
// scenario. It is security-critical and PINNED to PASS: a conformant gateway masks
// an offline DER's telemetry to the sentinel (never a stale projection) while its
// commanded 704 echo survives, and recovers the DER once the fault clears.
func commLossMaskScenario() gwScenario {
	return gwScenario{
		ID:         "comm-loss-sentinel-mask",
		Desc:       "secure DER goes comm-loss — the gateway MASKS its northbound telemetry (701) to the not-implemented sentinel (never a stale value) while its commanded 704 control echo SURVIVES (maskOffline 704 exemption), and recovers on clear",
		Category:   "southbound-fault-injection",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "commLossMask",
		arm:        armCommLossMask,
		teardown:   commLossMaskTeardown,
	}
}

// armCommLossMask runs the serial-independent differential: baseline the 704 cap +
// 701 telemetry on every control+meas unit over :802, arm comm-loss on the secure
// DER, sample until one unit's telemetry masks to the sentinel, confirm its 704 echo
// survived, then clear + confirm recovery. It fills ev.CommLossMask; the
// commLossMask oracle judges it.
func armCommLossMask(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	b := w.bench
	out := &commLossMaskOutcome{CommandedPct: commLossMaskCapPct}
	ev.CommLossMask = out

	// Needs BOTH DER sims: the SECURE one is the comm-loss target we drop, and a plain
	// peer gives the differential a healthy unit to contrast against. Without both there
	// is nothing to fault + no isolation peer.
	faulted, _, ok := w.sbDevices(sbTargetSecure)
	if !ok {
		ev.SetupErr = "bench not wired: comm-loss sentinel-mask needs BOTH DER sims (-inv-plain and -inv-secure) to run the serial-independent differential over :802"
		return nil
	}

	// 1. Open a GridService :802 session — the aggregator drives the NORTHBOUND view
	// where the mask is observable (the southbound-fault family cannot see it,
	// southbound_faults.go 16-18). connectAsReady rides out a transient session-cap
	// refusal (world.go). This session is INDEPENDENT of the armed fault (the drop is on
	// the gateway's SOUTHBOUND poll), so it stays usable throughout.
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		ev.SetupErr = "connect GridService: " + err.Error()
		return nil
	}
	defer conn.Close()

	// 2. Discover the served units and keep the "control+meas" ones — those advertising
	// BOTH the control model (704, whose echo must survive) AND the measurement model
	// (701, whose telemetry must mask). We do NOT pin a unit/serial: which of these masks
	// when the secure DER drops IS the differential.
	devs, err := conn.Discover(ctx, 1, 2, 3, 4, 5, 6, 7, 8)
	if err != nil && len(devs) == 0 {
		ev.SetupErr = "discover served units: " + err.Error()
		return nil
	}
	var units []uint8
	for _, d := range devs {
		hasCtl, hasMeas := false, false
		for _, m := range d.Models {
			if m == sunspec.ModelDERCtlAC {
				hasCtl = true
			}
			if m == sunspec.ModelDERMeasureAC {
				hasMeas = true
			}
		}
		if hasCtl && hasMeas {
			units = append(units, d.Unit)
		}
	}
	if len(units) == 0 {
		ev.SetupErr = "no served unit advertises BOTH the control (704) and measurement (701) models — cannot run the mask differential"
		return nil
	}

	// 3. Enable + command the cap on every control+meas unit and confirm each echo
	// converges to 50 — the commanded 704 setpoint that MUST survive the mask. A unit
	// whose cap never converges is dropped from the set (we only judge echo-survival
	// where a cap actually took); a persistent write blip is judged by the readback, not
	// scored on its own (control_loop.go idiom).
	var commanded []uint8
	for _, u := range units {
		_ = writePointRetry(ctx, conn, u, pointWMaxLimPctEna, 1)
		_ = writePointRetry(ctx, conn, u, matrixCtrlPoint, commLossMaskCapPct)
		if pollReadback(ctx, conn, u, commLossMaskCapPct, ctlTol, ctlSettleSLA, "cap-set", "").Converged {
			commanded = append(commanded, u)
		}
	}
	if len(commanded) == 0 {
		ev.SetupErr = "no control+meas unit's 704 cap converged to 50 — cannot exercise the maskOffline 704 echo-survival invariant"
		return nil
	}

	// 4. BASELINE telemetry per unit: read 701 "W" and record which units returned a REAL
	// (non-NaN, non-error) value. Only a unit REAL at baseline can be SEEN to mask later
	// (a real→sentinel transition); a unit already sentinel has nothing to mask.
	// TelemWasReal gates the oracle: if nothing real baselined, the run could not observe
	// a mask at all → INCONCLUSIVE, never a false FAIL.
	baselineReal := make(map[uint8]bool, len(commanded))
	for _, u := range commanded {
		if v, rerr := conn.ReadPoint(u, matrixMeasModel, matrixMeasPoint); rerr == nil && !math.IsNaN(v) {
			baselineReal[u] = true
			out.TelemWasReal = true // there was real telemetry to mask
		}
	}
	out.Observed = true // baseline obtained over :802

	// 5. Arm comm-loss on the SECURE DER (drop_session — its mbaps poll session is torn
	// down, the same fault sb-secure-comm-loss uses). We do NOT know which :802 unit it
	// projects to; the differential sampling below discovers it.
	if err := b.armFault(ctx, faulted, commLossMaskFault, 0); err != nil {
		ev.SetupErr = "arm comm-loss on " + faulted.Name + ": " + err.Error()
		return nil
	}

	// 6. Sample across a LONGER hold than the wave-2 default: the mask only appears after
	// the gateway crosses its missed-poll offline threshold. Each sample, for every
	// control+meas unit, read 701 "W" (telemetry) and 704 "WMaxLimPct" (control echo).
	// The unit whose telemetry (real at baseline) becomes the sentinel NaN is the masked
	// (faulted) unit; a DIFFERENT unit that keeps REAL telemetry is the healthy peer
	// (isolation). Keep sampling until a mask is observed or the samples run out.
	t := b.timing()
	benchSleep(ctx, t.Settle)
	samples := t.Samples + commLossMaskExtraSamples
	for i := 0; i < samples && out.MaskedUnit == 0; i++ {
		if i > 0 {
			benchSleep(ctx, t.Interval)
		}
		if ctx.Err() != nil {
			break
		}

		var maskedThis, realPeer uint8
		var echoThis float64
		var haveEcho bool
		for _, u := range commanded {
			w701, e701 := conn.ReadPoint(u, matrixMeasModel, matrixMeasPoint)
			if e701 != nil {
				continue // transport error this cycle — the point may come back, keep trying
			}
			switch {
			case baselineReal[u] && math.IsNaN(w701):
				// This unit's telemetry, REAL at baseline, has masked to the sentinel.
				maskedThis = u
				// Read its 704 echo in the SAME cycle: it must still reflect the commanded cap.
				if echo, eerr := conn.ReadPoint(u, matrixCtrlModel, matrixCtrlPoint); eerr == nil && !math.IsNaN(echo) {
					echoThis, haveEcho = echo, true
				}
			case !math.IsNaN(w701):
				// A unit still serving REAL telemetry — a candidate healthy peer.
				realPeer = u
			}
		}
		if maskedThis != 0 {
			out.MaskedUnit = int(maskedThis)
			out.TelemMaskedNaN = true
			// The commanded 704 control echo MUST have survived the mask (the maskOffline
			// 704 exemption): a value still ≈ the cap means the setpoint was not wiped.
			if haveEcho {
				out.EchoSurvived = math.Abs(echoThis-commLossMaskCapPct) <= ctlTol
			}
			// Isolation: a DIFFERENT control+meas unit kept real telemetry — the mask hit
			// only the offline DER, not its peer.
			if realPeer != 0 && realPeer != maskedThis {
				out.HealthyRealTelem = true
			}
		}
	}

	// 7. Clear the fault and confirm the gateway RECOVERS the faulted secure DER (its
	// poll resumes — a comm-loss that healed, not a permanent wedge). sbAwaitRecovery is
	// the family-B recovery probe (robust to the mbaps per-session counter resetting on
	// the fresh reconnect).
	_ = b.clearFault(ctx, faulted, commLossMaskFault)
	out.Recovered = w.sbAwaitRecovery(ctx, faulted)

	if out.MaskedUnit == 0 {
		out.Note = joinNote(out.Note, "no control+meas unit's northbound telemetry masked to the sentinel while the secure DER was offline — a STALE-projection risk (the gateway may be serving a stale/absurd value for an unreachable DER)")
	}

	// Release every unit we capped back to uncapped/disabled on the normal path so a live
	// run never leaves a DER curtailed (teardown's releaseControlUnit covers only the
	// primary discovered unit + the aborted-arm path).
	for _, u := range commanded {
		_ = writePointRetry(ctx, conn, u, matrixCtrlPoint, ctlUncapped)
		_ = writePointRetry(ctx, conn, u, pointWMaxLimPctEna, 0)
	}
	return nil
}

// commLossMaskTeardown clears the armed comm-loss (idempotent — armCommLossMask
// clears it on the normal path; this covers an arm that aborted mid-way) and releases
// the control unit so the run never leaves the bench faulted or curtailed.
func commLossMaskTeardown(ctx context.Context, w *gwWorld) {
	if faulted, _, ok := w.sbDevices(sbTargetSecure); ok {
		_ = w.bench.clearFault(ctx, faulted, commLossMaskFault)
	}
	releaseControlUnit(ctx, w)
}
