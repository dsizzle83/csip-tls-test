package gwmayhem

// lying_der.go — FAMILY L: THE LYING SOUTHBOUND DEVICE (strategy §L4).
//
// Family B (southbound_faults.go) faults a DER in ways it cannot hide: the
// socket dies, the registers go blank, the handshake stalls. Those are worth
// testing, and the gateway handles them, because a hub that checks its errors
// notices a device that errors.
//
// This family is the other half. Every scenario here arms a device that answers
// promptly, in range, and falsely: it ACKs a curtailment and reverts it forty
// seconds later; it serves a measurement block frozen at arm time while the
// real machine ramps; it refuses a write it has already applied; it comes back
// from a "firmware update" with every model eight registers further along. None
// of these produce an error anywhere. The gateway's own view stays coherent.
// The grid operator's instruction is simply not being carried out.
//
// # The invariants are the authority; this family only creates the conditions
//
// Nothing here decides pass or fail on its own. Each scenario:
//
//	1. builds an internal/invariant World over the SAME observation channels
//	   the rest of the suite uses — each sim's own /registers (the device's
//	   account of itself), gridsim's admin API (the head-end's record of what
//	   the DUT told it), and the DUT's :802 (what the DUT claims);
//	2. arms its lie, and records it in the World's FAULT MANIFEST, so any
//	   violation carries what was in force when it fired;
//	3. drives a control write through :802 and records it in the LEDGER with
//	   Distinctive set, which is what lets I3 judge a refused write at all;
//	4. runs the Monitor across the hold and the recovery;
//	5. stores the Summary. diagnoseLyingDER then reads the invariant verdicts.
//
// That indirection is the point. A bespoke assertion per fault would be a
// second, weaker set of safety properties maintained in parallel with the real
// one, and the first time the two disagreed we would have to decide which was
// authoritative. There is one answer to that question and it is
// internal/invariant.
//
// # Availability is a SKIP, never a pass
//
// Two things can make a scenario unrunnable: a sim too old to know the fault
// kind, and a wire-level lie on a sim started without -mangle. Both come back
// from POST /fault as an error, and both produce INCONCLUSIVE with the reason
// printed. A run that could not arm its adversary has not shown the gateway
// anything, and the one thing it must never print is a pass.

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"lexa-proto/modbus"
)

// lieScenarioSpec parameterises one lying-device scenario.
type lieScenarioSpec struct {
	// Kind is the POST /fault kind, and Body is the full request body (these
	// faults take parameters, and a fault armed with the wrong parameter is a
	// different fault).
	Kind string
	Body map[string]any
	// Target is which DER carries the lie.
	Target string
	// Invariants are the internal/invariant IDs that judge this scenario.
	// Naming them per scenario rather than running all ten keeps a verdict
	// attributable: I5 has nothing to say about a frozen register block, and a
	// SKIP from it in every row is noise that hides the rows that matter.
	Invariants []string
	// Claim is the oracle contract in one sentence, printed beside the verdict
	// so a reader never has to infer what was being asserted.
	Claim string
	// Wire marks a framing-level lie, which needs the sim started with -mangle.
	Wire bool
	// Commands asks the arm to drive a distinctive curtailment through :802
	// during the hold. Only the lies that are ABOUT a write need it; for the
	// others it would be an unexplained control action in the middle of an
	// observation window.
	Commands bool
}

// lyingDERScenarios is family L. Every kind in sim/southbound/lying.go and
// sim/southbound/wire.go appears exactly once, against the device where it is
// most dangerous: a lie about a control goes on the device the gateway
// curtails, a lie about framing goes on the plain device (the secure one is
// behind mbaps, whose own framing the mangler does not see).
func lyingDERScenarios() []gwScenario {
	return []gwScenario{
		lieScenario("lie-acks-and-applies-nothing",
			"the DER accepts a curtailment and stores none of it — the readback still tells the truth, so a "+
				"gateway that verifies its writes must catch this one",
			lieScenarioSpec{
				Kind: "ack_no_apply", Body: map[string]any{}, Target: sbTargetPlain,
				Invariants: []string{"I2", "I7"}, Commands: true,
				Claim: "a write is not a control; the gateway must confirm the device reached the commanded " +
					"state and must not report a limit as applied on the strength of an ACK alone",
			}),

		lieScenario("lie-acks-and-echoes-a-limit-it-never-stored",
			"the DER accepts a curtailment, stores none of it, and echoes it back on every read — readback "+
				"verification is defeated and only the device's own account reveals it",
			lieScenarioSpec{
				Kind: "ack_no_apply", Body: map[string]any{"echo": true}, Target: sbTargetPlain,
				Invariants: []string{"I2", "I7", "I1"}, Commands: true,
				Claim: "a shadow register that answers for a setpoint it never committed is undetectable over " +
					"Modbus; the gateway is judged here against the DEVICE'S OWN state, not against its echo",
			}),

		lieScenario("lie-ack-then-revert",
			"the DER accepts a curtailment, confirms it on readback, and silently reverts 20 s later — "+
				"the gateway must notice its limit stopped being in force",
			lieScenarioSpec{
				Kind: "revert_after", Body: map[string]any{"delay_s": 20}, Target: sbTargetPlain,
				Invariants: []string{"I2", "I7"}, Commands: true,
				Claim: "a limit that silently reverts must not keep being reported as applied; the gateway " +
					"must re-assert it or stop claiming it (I2 convergence is not a one-shot readback)",
			}),

		lieScenario("lie-stale-measurements",
			"the DER's measurement block is frozen at arm time while the machine ramps — the gateway must "+
				"not publish stale telemetry as current",
			lieScenarioSpec{
				Kind: "freeze_block", Body: map[string]any{}, Target: sbTargetPlain,
				Invariants: []string{"I7", "I1"},
				Claim: "a reading that stopped changing is not a current reading; the gateway must not " +
					"report it as one, nor compute a control from it as though it were",
			}),

		lieScenario("lie-sentinel-in-a-live-field",
			"a single measurement field goes not-implemented while discovery stays intact — the gateway "+
				"must treat the sentinel as absent, never as −32768",
			lieScenarioSpec{
				Kind: "sentinel_field", Body: map[string]any{"fields": []string{"W"}}, Target: sbTargetPlain,
				Invariants: []string{"I1", "I7"},
				Claim: "the SunSpec not-implemented sentinel is the absence of a value; decoding it as a " +
					"magnitude is how an out-of-nameplate command gets computed from a field nobody has",
			}),

		lieScenario("lie-reboot-and-forget",
			"the DER power-cycles, loses its commanded limit, and re-announces — the gateway must re-assert "+
				"the curtailment rather than assume it survived",
			lieScenarioSpec{
				Kind: "reboot_forget", Body: map[string]any{}, Target: sbTargetPlain,
				Invariants: []string{"I2", "I3", "I7"}, Commands: true,
				Claim: "a device that came back is not a device that is still curtailed; the gateway must " +
					"drive it back to the commanded state and must not report the pre-reboot limit as in force",
			}),

		lieScenario("lie-firmware-moved-the-models",
			"the DER returns from a firmware update with every model shifted — a gateway that cached its "+
				"model bases now writes its limit into a vendor block",
			lieScenarioSpec{
				Kind: "layout_shift", Body: map[string]any{"delta": 8}, Target: sbTargetPlain,
				Invariants: []string{"I1", "I7"}, Commands: true,
				Claim: "model bases are valid only for the chain they were walked from; a limit written to " +
					"a stale address is not a limit, and must not be reported as one",
			}),

		lieScenario("lie-refuses-a-write-it-applied",
			"the DER answers exception 0x04 to a write it has already applied — I3's grounding shape, which "+
				"no honest device can produce",
			lieScenarioSpec{
				Kind: "exception_on_applied_write", Body: map[string]any{"ex_code": 4}, Target: sbTargetPlain,
				Invariants: []string{"I3", "I7"}, Commands: true,
				Claim: "a refused write must leave no durable state asserting it applied and must never be " +
					"re-actuated later (OBX-01, TRM-01)",
			}),

		lieScenario("lie-slower-than-the-poll",
			"the DER answers slower than the gateway polls, so requests stack — the gateway must bound its "+
				"in-flight work and recover when the device speeds up",
			lieScenarioSpec{
				Kind: "slow_poll", Body: map[string]any{"hold_ms": 4000}, Target: sbTargetPlain,
				Invariants: []string{"I8", "I9", "I7"},
				Claim: "a slow device must not become an unbounded queue, a growing connection table, or a " +
					"permanent wedge once it is fast again",
			}),

		lieScenario("lie-answers-as-another-slave",
			"the DER stamps a different unit id on its answers — a gateway that does not check will file one "+
				"machine's data under another",
			lieScenarioSpec{
				Kind: "wrong_unit_id", Body: map[string]any{}, Target: sbTargetPlain, Wire: true,
				Invariants: []string{"I7", "I1"},
				Claim: "an answer addressed to a different slave is not an answer to this one; attributing it " +
					"to the polled device is a false report and can curtail the wrong machine",
			}),

		lieScenario("lie-truncates-mid-pdu",
			"the DER's response stops mid-PDU while its length field still promises the rest",
			lieScenarioSpec{
				Kind: "truncate_response", Body: map[string]any{"trunc_bytes": 2}, Target: sbTargetPlain, Wire: true,
				Invariants: []string{"I8", "I9", "I7"},
				Claim: "a frame that never completes must time out and be discarded, not spliced onto the " +
					"next response's bytes, and must not leave the poll loop wedged",
			}),

		lieScenario("lie-mbap-length-disagrees",
			"the DER's MBAP length field disagrees with the bytes that follow, desynchronising the stream",
			lieScenarioSpec{
				Kind: "mbap_length_lie", Body: map[string]any{"len_delta": -2}, Target: sbTargetPlain, Wire: true,
				Invariants: []string{"I7", "I9"},
				Claim: "a desynchronised stream yields values that belong to other questions; the gateway must " +
					"detect the framing violation and resynchronise rather than decode what it finds",
			}),

		lieScenario("lie-answers-out-of-order",
			"the DER answers two in-flight requests in reverse order — a gateway pairing by arrival has every "+
				"value under the wrong question",
			lieScenarioSpec{
				Kind: "stack_responses", Body: map[string]any{"stack_n": 2}, Target: sbTargetPlain, Wire: true,
				Invariants: []string{"I7", "I1"},
				Claim: "the transaction id pairs an answer with its question; a gateway that assumes lockstep " +
					"attributes reads to the wrong register block and reports the result as measurement",
			}),
	}
}

// lieScenario builds one family-L scenario. All are PINNED to PASS: a
// conformant gateway notices the lie, refuses to report success, and converges
// to a safe state. They are marked security-critical because a silently
// unapplied grid instruction is a safety outcome, not a robustness one.
func lieScenario(id, desc string, spec lieScenarioSpec) gwScenario {
	s := spec
	return gwScenario{
		ID:         id,
		Desc:       desc,
		Category:   "lying-southbound-device",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "lyingDER",
		arm:        func(ctx context.Context, w *gwWorld, ev *gwEvidence) error { return armLie(ctx, w, ev, s) },
		teardown:   func(ctx context.Context, w *gwWorld) { clearLie(ctx, w, s) },
	}
}

// ── The arm ──────────────────────────────────────────────────────────────────

// armLie runs one lying-device scenario end to end: build the invariant World,
// arm the lie and record it in the manifest, optionally drive a distinctive
// control write and record it in the ledger, monitor across the hold, clear,
// and monitor the recovery. It fills ev.LyingDER with the invariant Summary,
// which is the entire basis of the verdict.
//
// Every failure path here sets Unavailable rather than returning an error: a
// scenario that could not arm its adversary must be visibly INCONCLUSIVE, and
// an error return would abort the run for a reason that is about the bench.
func armLie(ctx context.Context, w *gwWorld, ev *gwEvidence, s lieScenarioSpec) error {
	out := &lyingDEROutcome{
		Lie: s.Kind, Target: s.Target, Claim: s.Claim,
		InvariantIDs: s.Invariants, Wire: s.Wire,
	}
	ev.LyingDER = out

	faulted, healthy, ok := w.sbDevices(s.Target)
	if !ok {
		out.Unavailable = "bench not wired: family L needs BOTH DER sims (-inv-plain and -inv-secure) so a " +
			"healthy peer proves the lie was isolated"
		return nil
	}
	out.FaultedName, out.HealthyName = faulted.Name, healthy.Name

	checks, unknown := invariant.Select(s.Invariants, invariantParams(w))
	if len(unknown) > 0 {
		out.Unavailable = fmt.Sprintf("scenario names invariants this build does not have: %v", unknown)
		return nil
	}

	manifest := invariant.NewManifest("lying-der/"+s.Kind, lieSeed(s.Kind))
	ledger := invariant.NewLedger()
	world := invariant.NewWorld(lieSources(w, faulted, healthy), manifest, ledger, invariantParams(w))

	mon, err := invariant.NewMonitor(invariant.MonitorConfig{World: world, Checks: checks})
	if err != nil {
		out.Unavailable = "could not build the invariant monitor: " + err.Error()
		return nil
	}

	// A baseline tick BEFORE the lie: an invariant that was already failing is
	// not this scenario's finding, and the summary says so. The tick's OWN worst
	// verdict is what is recorded — Finalize would resolve still-pending claims
	// into failures, and on the first tick of a run every eventual-recovery claim
	// is legitimately pending.
	base, err := mon.Tick(ctx)
	if err != nil {
		out.Unavailable = "the world could not be observed before arming: " + err.Error()
		return nil
	}
	out.BaselineWorst = string(base.Worst())

	// Arm, and record it where a violation can find it.
	body := faultBody(s)
	if err := postJSON(ctx, faulted.BaseURL+"/fault", body); err != nil {
		out.Unavailable = lieUnavailableReason(s, err)
		return nil
	}
	faultID := manifest.Arm(invariant.Fault{
		Kind:        s.Kind,
		Class:       invariant.ClassPeerLie,
		Target:      faulted.Name,
		Params:      stringParams(body),
		Armed:       time.Now(),
		Recoverable: true, // every lie here is cleared by the teardown; I9 may hold us to it
	})
	out.Armed = true

	if s.Commands {
		commandDistinctively(ctx, w, ledger, faulted, out)
	}

	t := w.bench.timing()
	benchSleep(ctx, t.Settle)
	for i := 0; i < t.Samples; i++ {
		if i > 0 {
			benchSleep(ctx, t.Interval)
		}
		if ctx.Err() != nil {
			break
		}
		if _, err := mon.Tick(ctx); err != nil {
			out.Note = joinNote(out.Note, "a monitor tick failed: "+err.Error())
		}
		out.Ticks++
	}

	// Clear, then keep watching: "did it recover once the device stopped lying"
	// is a separate claim from "did it notice", and I9 is the one that holds the
	// gateway to it.
	_ = postJSON(ctx, faulted.BaseURL+"/fault", clearBody(s))
	manifest.Clear(faultID, time.Now())
	for i := 0; i < 2; i++ {
		benchSleep(ctx, t.Interval)
		if ctx.Err() != nil {
			break
		}
		if _, err := mon.Tick(ctx); err != nil {
			out.Note = joinNote(out.Note, "a recovery tick failed: "+err.Error())
		}
		out.Ticks++
	}

	sum := mon.Finalize()
	out.Summary = &sum
	out.Observed = out.Ticks > 0
	return nil
}

// commandDistinctively drives a curtailment through the DUT's :802 and records
// it in the ledger. The value is chosen to be distinctive — 37 % is not a round
// number any scheduler or default would land on — because I3's inference ("the
// refused value never appeared downstream") is only sound if the value could
// not have arrived by another route, and the ledger REQUIRES that assertion
// rather than assuming it.
func commandDistinctively(ctx context.Context, w *gwWorld, ledger *invariant.Ledger, faulted DERSim, out *lyingDEROutcome) {
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		out.Note = joinNote(out.Note, "no served unit advertises the control model — the write arm of this "+
			"scenario did not run, so I3 will SKIP naming that")
		return
	}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		out.Note = joinNote(out.Note, "could not open a control session: "+err.Error())
		return
	}
	defer conn.Close()

	const distinctivePct = 37
	start := time.Now()
	werr := writePointRetry(ctx, conn, unit, matrixCtrlPoint, distinctivePct)
	rec := invariant.WriteRecord{
		At:          start,
		Credential:  "grid-service",
		Role:        string(aggregator.RoleGridService),
		Domain:      "nb-mbaps-clients",
		Authorized:  true,
		Unit:        unit,
		Model:       matrixCtrlModel,
		Point:       matrixCtrlPoint,
		Value:       invariant.Quantity{Val: distinctivePct, Unit: invariant.UnitPercent},
		Ref:         invariant.RefWMax,
		Distinctive: true,
		DERs:        []string{faulted.Name},
		RTT:         time.Since(start),
		Note: "a deliberately unround curtailment, so seeing it downstream can only have come from " +
			"this write and not from a scheduler default",
	}
	switch {
	case werr == nil:
		rec.Accepted = true
	default:
		if ex, isEx := aggregator.AsException(werr); isEx {
			rec.Refused, rec.ExceptionCode = true, uint8(ex.Code)
		} else {
			rec.TransportErr = werr.Error()
		}
	}
	ledger.NoteWrite(rec)
	out.Commanded = true
	out.CommandedPct = distinctivePct
	out.CommandRefused = rec.Refused
}

// lieSources builds the invariant World's witnesses. Each DER is read through
// its OWN simapi sidecar rather than through the DUT, which is what makes the
// device's account independent of the DUT's claim about it — and, for this
// family specifically, what makes a lie detectable at all: every read-path lie
// in sim/southbound/lying.go leaves /registers honest on purpose.
func lieSources(w *gwWorld, faulted, healthy DERSim) invariant.Sources {
	hc := &http.Client{Timeout: 6 * time.Second}
	ders := map[string]invariant.DERSource{}
	for _, d := range []DERSim{faulted, healthy} {
		if !d.configured() {
			continue
		}
		ders[d.Name] = invariant.NewSimAPIDER(d.Name, certify.NewSimClient(d.Name, d.BaseURL, hc), 1)
	}
	src := invariant.Sources{
		DERs: ders,
		DUT: invariant.NewMbapsNorthbound("mbaps:"+w.target, func(ctx context.Context) (modbus.Transport, func(), error) {
			// The least-privileged credential that can read. A monitor auditing a
			// device has no business holding a write-capable session open.
			c, err := w.connectAsReady(ctx, aggregator.RoleReadOnly)
			if err != nil {
				return nil, nil, err
			}
			return c.Transport(), func() { _ = c.Close() }, nil
		}, nil),
	}
	if w.bench.GridsimAdmin != "" {
		src.HeadEnd = invariant.NewGridsimHeadEnd(certify.NewAdminClient(w.bench.GridsimAdmin, hc))
	}
	return src
}

// invariantParams carries the operator-supplied values into the checks. It is
// deliberately thin: an invariant that needs a threshold nobody stated must
// SKIP saying so, and manufacturing a default here would launder a guess into
// a verdict.
func invariantParams(w *gwWorld) invariant.Params {
	p := invariant.DefaultParams()
	_ = w
	return p
}

// faultBody renders the POST /fault body for a scenario.
func faultBody(s lieScenarioSpec) map[string]any {
	body := map[string]any{"kind": s.Kind}
	for k, v := range s.Body {
		body[k] = v
	}
	return body
}

// clearBody renders the disarm body.
func clearBody(s lieScenarioSpec) map[string]any {
	return map[string]any{"kind": s.Kind, "clear": true}
}

// stringParams flattens a fault body for the manifest, which records params
// verbatim so a violation can be re-armed identically during shrinking.
func stringParams(body map[string]any) map[string]string {
	out := make(map[string]string, len(body))
	for k, v := range body {
		if k == "kind" {
			continue
		}
		out[k] = fmt.Sprint(v)
	}
	return out
}

// lieUnavailableReason turns a POST /fault failure into a reason a reader can
// act on. A wire-level kind rejected by a sim without -mangle is the common
// case and deserves to say so rather than read as a gateway problem.
func lieUnavailableReason(s lieScenarioSpec, err error) string {
	if s.Wire {
		return fmt.Sprintf("the %s sim refused the framing-level kind %q (%v) — this scenario needs the sim "+
			"started with -mangle so the MBAP wire mangler is interposed", s.Target, s.Kind, err)
	}
	return fmt.Sprintf("the %s sim refused the fault kind %q (%v) — the sim predates the lying-device layer", s.Target, s.Kind, err)
}

// lieSeed derives a stable per-kind campaign seed, so a violation's manifest
// names a seed that identifies the scenario rather than the wall clock.
func lieSeed(kind string) int64 {
	var h int64 = 1469598103934665603
	for _, c := range kind {
		h = (h ^ int64(c)) * 1099511628211
	}
	if h < 0 {
		h = -h
	}
	return h
}

// clearLie is the teardown: disarm whatever the scenario armed and release any
// curtailment it commanded, so an aborted run never leaves the bench lied-to or
// curtailed. Both are idempotent — armLie already did them on the normal path.
func clearLie(ctx context.Context, w *gwWorld, s lieScenarioSpec) {
	faulted, _, ok := w.sbDevices(s.Target)
	if !ok {
		return
	}
	_ = postJSON(ctx, faulted.BaseURL+"/fault", clearBody(s))
	if s.Commands {
		releaseControlUnit(ctx, w)
	}
}
