package aggregator

// readback.go is the READBACK-VERIFICATION core (T06.7): the driver loop that
// polls a status/echo point to convergence, plus the two oracle bodies that judge
// the resulting evidence — convergeWithinSLA and reversionOnExpiry.
//
// Readback verification is how the emulator proves a control was really APPLIED,
// not merely ACCEPTED. A Modbus success only means the write entered the pipeline
// (design 02 §4.4); the application truth is observable by reading the control
// model's projection back and watching it converge to the commanded value. The
// driver loop here is a data-collection loop (it stops when the value is within
// tolerance or the SLA elapses); the PASS/FAIL judgment over the collected
// ReadbackRecords is the oracle's, keeping measurement (data) and judgment (code)
// on opposite sides of the T06.6 boundary.

import (
	"context"
	"fmt"
	"math"
	"time"
)

const (
	// defaultReadbackTol is the absolute tolerance applied when a readback step
	// omits "tol". 0.5 covers the ±½-least-significant-unit rounding a scaled
	// SunSpec value (e.g. WMaxLimPct at SF=-2) incurs on the round trip, matching
	// the emulator core's own WMaxLimPct readback assertion.
	defaultReadbackTol = 0.5
	// readbackPollInterval is the gap between successive readback reads. Short
	// enough that a fast, write-through echo (the loopback) converges on the first
	// or second read; the loop never busy-spins because each read itself blocks on
	// a bounded op deadline.
	readbackPollInterval = 150 * time.Millisecond
	// slowFraction marks a convergence "slow": arriving past this fraction of the
	// SLA is a DEGRADED signal (it made it, but with little margin) rather than a
	// clean PASS.
	slowFraction = 0.8
)

// doReadback polls one status/echo point until it converges to the step's Expect
// value within tolerance, or the SLA elapses. It records a ReadbackRecord with
// the convergence facts; it makes no PASS/FAIL decision (that is the oracle's).
// Read errors do not end the loop — a momentary outage that recovers before the
// SLA still converges, and the raw ops redial transparently — but if no read ever
// returns a value the record is marked HadRead=false so the oracle can call it
// BLIND rather than a false FAIL.
func (r *campaignRun) doReadback(ctx context.Context, idx int, s Step) StepResult {
	model := s.Model
	if model == 0 {
		model = controlModel // the control model whose projection echoes the command
	}
	tol := s.Tol
	if tol <= 0 {
		tol = defaultReadbackTol
	}
	res := StepResult{Index: idx, Do: StepReadback}
	rb := &ReadbackRecord{
		Unit: s.Unit, Model: model, Point: s.Point, Phase: s.Phase,
		Expect: s.Expect, Tol: tol, SLAS: s.SLAS,
	}
	start := r.e.now()
	deadline := start.Add(secondsDur(s.SLAS))
	for {
		v, err := r.conn.ReadPoint(s.Unit, model, s.Point)
		rb.Reads++
		switch {
		case err != nil:
			// Transport or exception reading the echo: keep the last error for
			// diagnostics but keep trying until the SLA — the point may come back.
			res.Err = err.Error()
		case math.IsNaN(v):
			// The point is present but unimplemented/sentinel this cycle — no fresh
			// value yet; keep polling.
		default:
			rb.HadRead = true
			rb.Final = v
			if math.Abs(v-s.Expect) <= tol {
				rb.Converged = true
			}
		}
		if rb.Converged {
			break
		}
		now := r.e.now()
		if !now.Before(deadline) {
			break
		}
		wait := readbackPollInterval
		if rem := deadline.Sub(now); wait > rem {
			wait = rem
		}
		if !r.wait(ctx, wait) {
			break // campaign cancelled
		}
	}
	rb.TookS = r.e.now().Sub(start).Seconds()
	if rb.Converged {
		res.Err = "" // a converged readback is a success regardless of earlier transient errors
	}
	res.Readback = rb
	res.OK = rb.Converged
	if !rb.HadRead {
		res.Note = "readback never obtained a value (BLIND)"
	}
	return res
}

// convergeWithinSLA judges a readback-verification campaign: every readback must
// converge to its commanded value within its SLA. It distinguishes the three
// failure modes a naive "did the write fail?" check would collapse together:
//
//   - never returned a value ⇒ BLIND (a coverage gap, not a control failure);
//   - returned values but never reached the target ⇒ FAIL (the control was
//     accepted but not applied — the class readback verification exists to catch);
//   - converged, but only past slowFraction of the SLA ⇒ DEGRADED (arrived slow).
//
// A control write that failed at the transport layer (not a clean exception)
// contributes INCONCLUSIVE — the command never left the emulator, so convergence
// cannot be judged. No readback at all ⇒ INCONCLUSIVE (nothing to judge).
func convergeWithinSLA(rep *CampaignReport) (Verdict, []string) {
	var findings []string
	verdict := Verdict("")
	readbacks := 0
	for _, st := range rep.Steps {
		if (st.Do == StepWritePoint || st.Do == StepWriteMulti) && !st.OK && st.Exception == nil && st.Err != "" {
			findings = append(findings, fmt.Sprintf("step %d %s: control write failed at transport (%s) — cannot observe convergence", st.Index, st.Do, st.Err))
			verdict = worse(verdict, VerdictInconclusive)
		}
		if st.Readback == nil {
			continue
		}
		readbacks++
		rb := st.Readback
		switch {
		case !rb.HadRead:
			findings = append(findings, fmt.Sprintf("step %d readback unit %d %s: never returned a value within %.0fs — BLIND", st.Index, rb.Unit, rb.Point, rb.SLAS))
			verdict = worse(verdict, VerdictBlind)
		case !rb.Converged:
			findings = append(findings, fmt.Sprintf("step %d readback unit %d %s: did NOT converge to %g±%g within %.0fs (final %g) — control accepted but not applied", st.Index, rb.Unit, rb.Point, rb.Expect, rb.Tol, rb.SLAS, rb.Final))
			verdict = worse(verdict, VerdictFail)
		default:
			note := ""
			if rb.TookS > slowFraction*rb.SLAS {
				note = " (slow — arrived near the SLA boundary)"
				verdict = worse(verdict, VerdictDegraded)
			}
			findings = append(findings, fmt.Sprintf("step %d readback unit %d %s: converged to %g in %.1fs (SLA %.0fs)%s", st.Index, rb.Unit, rb.Point, rb.Final, rb.TookS, rb.SLAS, note))
		}
	}
	if readbacks == 0 {
		return VerdictInconclusive, []string{"convergeWithinSLA: no readback step ran — nothing to judge"}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}

// reversionOnExpiry judges a WinTms/RvrtTms reversion campaign: a limit is
// commanded with a reversion timer, the ceiling must HOLD through the window
// (phase "hold" readbacks converge to the commanded value), and then the gateway
// must ACTIVELY revert the value to the safe default on expiry (phase "revert"
// readbacks converge to the safe-default Expect). A revert readback that stays at
// the commanded limit is the stuck-curtailment failure class — a safety
// regression, the highest-severity thing this bench exists to catch — and is a
// FAIL. If the ceiling never held, the command never took and reversion cannot be
// judged (INCONCLUSIVE); a phase-tagged readback that never read is BLIND.
func reversionOnExpiry(rep *CampaignReport) (Verdict, []string) {
	var findings []string
	type tagged struct {
		idx int
		rb  *ReadbackRecord
	}
	var holds, reverts []tagged
	for _, st := range rep.Steps {
		if st.Readback == nil {
			continue
		}
		switch st.Readback.Phase {
		case "hold":
			holds = append(holds, tagged{st.Index, st.Readback})
		case "revert":
			reverts = append(reverts, tagged{st.Index, st.Readback})
		}
	}
	if len(reverts) == 0 {
		return VerdictInconclusive, []string{`reversionOnExpiry: needs a readback with phase="revert" (the safe-default check after RvrtTms)`}
	}
	// The commanded ceiling must have held first — otherwise a "reverted" value is
	// indistinguishable from a command that simply never applied.
	for _, h := range holds {
		if !h.rb.HadRead {
			findings = append(findings, fmt.Sprintf("step %d hold readback unit %d %s: never returned a value — BLIND, cannot judge reversion", h.idx, h.rb.Unit, h.rb.Point))
			return VerdictBlind, findings
		}
		if !h.rb.Converged {
			findings = append(findings, fmt.Sprintf("step %d hold readback unit %d %s: ceiling never took (did not converge to %g) — cannot judge reversion", h.idx, h.rb.Unit, h.rb.Point, h.rb.Expect))
			return VerdictInconclusive, findings
		}
		findings = append(findings, fmt.Sprintf("step %d: commanded ceiling %g held on unit %d", h.idx, h.rb.Expect, h.rb.Unit))
	}
	verdict := Verdict("")
	for _, rv := range reverts {
		switch {
		case !rv.rb.HadRead:
			findings = append(findings, fmt.Sprintf("step %d revert readback unit %d %s: never returned a value — BLIND", rv.idx, rv.rb.Unit, rv.rb.Point))
			verdict = worse(verdict, VerdictBlind)
		case !rv.rb.Converged:
			findings = append(findings, fmt.Sprintf("step %d revert readback unit %d %s: did NOT revert to the safe default %g (stuck at %g) — STUCK CURTAILMENT (safety regression)", rv.idx, rv.rb.Unit, rv.rb.Point, rv.rb.Expect, rv.rb.Final))
			verdict = worse(verdict, VerdictFail)
		default:
			findings = append(findings, fmt.Sprintf("step %d: unit %d reverted to safe default %g after RvrtTms", rv.idx, rv.rb.Unit, rv.rb.Expect))
		}
	}
	if verdict == "" {
		verdict = VerdictPass
	}
	return verdict, findings
}
