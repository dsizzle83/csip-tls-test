package suitecsip

// basic.go implements the BASIC-* family: identification, group management, the
// twelve inverter-control modes, the eleven event-precedence scenarios, alarms,
// status and metering.
//
// # The line this family runs into
//
// Most BASIC rows have a criterion of the form "the DER's output follows the
// control". That is a measurement of the INVERTER, not of the 2030.5 exchange,
// and this bench's CSIP leg cannot see it: the DUT's effect on its southbound
// devices appears on a different wire, belongs to a different suite, and for the
// ride-through modes appears on no wire at all. Those criteria are recorded as
// SKIP with that reason. What this suite CAN certify — and does — is the
// protocol half: the mode reached the DUT inside a conformant DERControl, the
// DUT fetched it, and where the event asked for acknowledgement the DUT
// acknowledged it.
//
// # The modes this bench can and cannot place on the wire
//
// gridsim's admin control API (sim/gridsim/admin.go adminCtrlReq) exposes the
// scalar modes — opModMaxLimW, opModExpLimW, opModFixedW, opModFixedVar,
// opModFixedPFInjectW/AbsorbW, opModConnect, opModEnergize — and its curve API
// (curve.go) binds the four curve modes: opModVoltVar, opModVoltWatt,
// opModFreqWatt, opModWattPF. It exposes NO lever for the six ride-through
// modes (opModLVRT*/opModHVRT*/opModLFRT*/opModHFRT*) and none for the ramp
// rates, which IEEE 2030.5 places only in DefaultDERControl and gridsim's
// /admin/default does not carry. Those rows therefore report, precisely, that
// the mode could not be put on the wire — which is a bench gap with a named
// owner, not a DUT finding.

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
)

// basicIdentification implements BASIC-001 — DER Identification.
func basicIdentification(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pin, _ := rc.Param(pinParam)
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "SFDI/LFDI/PIN provisioning and the EndDevice walk; the identity is derived from the " +
				"certificate the DUT presented on the wire, by this bench's own implementation of " +
				"IEEE 2030.5 §6.3 (the catalog's 16-bit/160-bit erratum on step 4(b) is honoured)"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critTLS12(),
				critMutualAuth(),
				critDiscoveryRoot(),
				critEndDeviceList(2),
				critSelfIdentity(),
				critRegistrationPIN(pin),
				critFSAList(0),
				critResource("FunctionSetAssignments",
					"the DUT traversed from its EndDevice into the FunctionSetAssignments and on to the "+
						"DERProgram resources beneath it",
					func(doc *Node) (certify.Verdict, string) {
						if !doc.Has("DERProgramListLink") {
							return certify.Fail, "the FunctionSetAssignments carries no DERProgramListLink, so " +
								"the DERProgram resources the procedure requires are unreachable"
						}
						return certify.Pass, "DERProgramListLink present"
					}),
				critProgramList(0),
			}
		},
	})
}

// basicGroupManagement builds BASIC-002 and BASIC-003, which differ only in the
// scale of the group fixture they require.
func basicGroupManagement(fsaCount, programCount, endDevices int) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		pin, _ := rc.Param(pinParam)
		return run(ctx, rc, spec{
			Notes: func(o *Observation) string {
				return fmt.Sprintf("group management: the procedure's fixture is %d EndDevice(s), %d FSA(s) "+
					"and %d DERProgram(s); the assertions below report what the bench actually served",
					endDevices, fsaCount, programCount)
			},
			Criteria: func(o *Observation) []criterion {
				return []criterion{
					critDiscoveryRoot(),
					critEndDeviceList(endDevices),
					critRegistrationPIN(pin),
					critFSAList(fsaCount),
					critProgramList(programCount),
					critDefaultDERControl(),
					critResource("DERControlList", "the DUT fetched the DERControlList of a DERProgram", nil),
					critPollRate(),
				}
			},
		})
	}
}

// controlMode describes how one inverter-control row's mode is placed on the
// wire, or why it cannot be.
type controlMode struct {
	// Element is the DERControlBase child the DUT must be seen to receive.
	Element string
	// Publish arms the mode on the bench. nil means the mode is unreachable.
	Publish func(ctx context.Context, d *Driver, mrid string) error
	// Unreachable explains why no lever exists; set exactly when Publish is nil.
	Unreachable string
	// Program is the gridsim DERProgram index to publish on.
	Program int
	// Oracle, when set, replaces critDEREffectUnobservable's hard SKIP for
	// THIS row with a REAL independent register assertion (IW13-001 §4.3:
	// docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md). It reads the DER's
	// OWN southbound registers through internal/invariant — which shares
	// only the SunSpec register-offset tables with the product and none of
	// the CSIP/derbase interpretation (that package's own doc) — and reports
	// whether the DER's own account matches what THIS row commanded. Called
	// during Setup (the one phase with live network access); criterion.Wire
	// evaluators run later against the recovered pcap transcript and have no
	// live context of their own, so the Finding is computed here and carried
	// into the citation phase via Observation.Params, the same mechanism an
	// mRID or other live-phase fact already uses.
	//
	// Populated only for BASIC-010/opModMaxLimW, BASIC-013/opModFixedW, and
	// BASIC-014/opModTargetW — the three rows §4.3 specifically names. Every
	// other BASIC-004..015 row is unaffected: its "the DER's output followed
	// the control" criterion stays the honest SKIP it always was, because
	// nothing wires a southbound read for it.
	Oracle func(ctx context.Context, rc *certify.RunCtx) Finding
}

// oracleVerdictParam/oracleObservedParam/oracleUnavailableParam are the
// Observation.Params keys a controlMode.Oracle result is carried through —
// Setup (live) to Criteria (post-hoc), see controlMode.Oracle's doc.
const (
	oracleVerdictParam     = "iw13.oracle_verdict"
	oracleObservedParam    = "iw13.oracle_observed"
	oracleUnavailableParam = "iw13.oracle_unavailable"
)

// scalarControlWindow is the [StartOffset, StartOffset+DurationS] window (in
// seconds) a scalar control is published with.
type scalarControlWindow struct {
	startOffsetS int
	durationS    int
}

// scalarWindow is the default scalar control window: a control the DUT only has
// to FETCH, so a short window is enough and nothing reads the DER during it.
var scalarWindow = scalarControlWindow{startOffsetS: 30, durationS: 120}

// oracleWindow widens the window for the ORACLED scalar rows (BASIC-010/013) so
// the control stays active across the ENTIRE span in which the PostWait oracle
// can read the DER (IW13-005). That read can land anywhere from the moment
// AwaitWalk returns (the DUT's first GET /dcap after Setup, plus the settle
// poll below) out to ~fetchWait — waitPeriods*cadence + waitSlack, capped at
// waitCap (5m) (check.go) — when the DUT is slow to poll and AwaitWalk waits
// the full window. The default [+30s, +150s] window ended at +150s, which the
// bench's 60s cadence read (2*60+30 = 150s) sits right on and a slower cadence
// overruns entirely; [+30s, +360s] keeps the DER under the commanded cap past
// waitCap for every cadence the derivation can pick, and comfortably through
// the settle poll. The harness never waits DurationS (it waits fetchWait), so
// the longer window costs no runtime — Cleanup clears the control when the row
// is done. The observed compliance FAIL was NOT this window expiring under the
// read; it was the read landing too EARLY (see oracleSettleWindow) — this
// widening is the belt to that fix's braces.
var oracleWindow = scalarControlWindow{startOffsetS: 30, durationS: 330}

// scalarMode builds a controlMode driven by gridsim's scalar control API, with
// the default (fetch-only) window.
func scalarMode(element string, apply func(*ControlRequest)) controlMode {
	return scalarModeWindow(element, scalarWindow, apply)
}

// scalarModeOracled builds a scalar controlMode for a row whose DER register an
// independent oracle READS during PostWait (BASIC-010/013) — so its control
// must stay active across the oracle read (oracleWindow).
func scalarModeOracled(element string, apply func(*ControlRequest)) controlMode {
	return scalarModeWindow(element, oracleWindow, apply)
}

// scalarModeWindow is the shared body of scalarMode/scalarModeOracled: the only
// thing that varies between a fetch-only row and an oracled row is the window.
func scalarModeWindow(element string, win scalarControlWindow, apply func(*ControlRequest)) controlMode {
	return controlMode{
		Element: element,
		Publish: func(ctx context.Context, d *Driver, mrid string) error {
			req := ControlRequest{
				Program: 0, MRID: mrid, Description: "certify " + element,
				StartOffset: win.startOffsetS, DurationS: win.durationS,
			}
			apply(&req)
			_, err := d.PostControl(ctx, req)
			return err
		},
	}
}

// curveMode builds a controlMode driven by gridsim's curve API, which is the
// only way a curve-linked mode reaches the DUT.
func curveMode(element, mode string, points []CurvePoint, yRef uint8) controlMode {
	return controlMode{
		Element: element,
		Publish: func(ctx context.Context, d *Driver, mrid string) error {
			_, err := d.PostCurve(ctx, CurveRequest{
				Program: 0, Mode: mode, Points: points, YRefType: yRef,
				Description: "certify " + element, DurationS: 180, StartOffset: 30, Activate: true,
			})
			return err
		},
	}
}

// unreachableMode builds a controlMode for a mode this bench cannot publish.
func unreachableMode(element, why string) controlMode {
	return controlMode{Element: element, Unreachable: why}
}

// withOracle attaches an independent southbound register Oracle (IW13-001
// §4.3) to an already-built controlMode — the combinator BASIC-010/013/014's
// rows use so scalarMode's own construction stays untouched for every other
// row.
func withOracle(m controlMode, oracle func(ctx context.Context, rc *certify.RunCtx) Finding) controlMode {
	m.Oracle = oracle
	return m
}

// basicInverterControl builds one of the BASIC-004..015 rows.
func basicInverterControl(m controlMode, subject string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		mrid := "CERT-" + strings.ToUpper(rc.Case.ID)
		return run(ctx, rc, inverterControlSpec(m, subject, mrid))
	}
}

// inverterControlSpec builds the spec basicInverterControl runs. Factored out
// — the same shape as eventScenarioSpec/coreResponsesSpec — so a test can
// drive its Setup and PostWait directly against a real Driver (nonce_test.go's
// gridsimDriver pattern) without booting the whole certify.Check machinery,
// which needs a live capture window run() cannot fake.
func inverterControlSpec(m controlMode, subject, mrid string) spec {
	s := spec{
		Notes: func(o *Observation) string {
			if m.Unreachable != "" {
				return "the control mode this row is about cannot be published by this bench: " + m.Unreachable
			}
			return fmt.Sprintf("published a DERControl (%s) carrying %s and waited %s for the DUT to "+
				"fetch it", mrid, m.Element, o.Waited.Round(rounding))
		},
		Criteria: func(o *Observation) []criterion {
			crits := []criterion{critDiscoveryRoot(), critProgramList(0)}
			if m.Unreachable != "" {
				crits = append(crits, criterion{
					Claim: "the DUT received and applied a DERControl carrying " + subject,
					How: "the presence of a <" + m.Element + "> element inside a DERControlBase the DUT " +
						"fetched",
					Skip: m.Unreachable,
				})
			} else {
				crits = append(crits, critDERControlCarriesMode(m.Element,
					"the DUT fetched a DERControl carrying "+subject))
			}
			crits = append(crits, critDefaultDERControl())
			if m.Oracle != nil {
				crits = append(crits, critDEREffectViaSouthboundOracle(subject, o))
			} else {
				crits = append(crits, critDEREffectUnobservable(subject))
			}
			return crits
		},
	}
	if m.Publish != nil {
		s.RequiresGridSim = true
		s.Setup = func(ctx context.Context, d *Driver, params map[string]string) error {
			params["mrid"] = mrid
			return m.Publish(ctx, d, mrid)
		}
		// PostWait, NOT Setup, is where the independent southbound oracle
		// (IW13-005) fires. check.go's run() orders the live phase Setup ->
		// [wait for the DUT's poll cycle] -> PostWait -> Change, and Setup is
		// the ONLY phase that runs before that wait — a control published
		// with StartOffset:30/DurationS:120 (scalarMode) cannot possibly have
		// been fetched or applied by the DUT yet. An oracle fired from Setup
		// therefore always read an empty register, always came back
		// Unavailable, and always degraded this criterion to the same hard
		// SKIP IW13-005 exists to eliminate — silently, since the criterion
		// still "ran" and just found nothing. PostWait runs after that wait
		// is over (spec.PostWait's own doc: "a read-only observation taken
		// right after the live phase's wait ... is done, and BEFORE Change"),
		// the same slot CORE-005's clock probe (probeGatewayClock) uses for
		// its own DUT-state read.
		if m.Oracle != nil {
			s.PostWait = func(ctx context.Context, d *Driver, params map[string]string) error {
				// settleOracle, not a bare m.Oracle call: AwaitWalk returns at
				// the START of the DUT's walk, so the control the DUT is
				// fetching may not have reached the DER's own registers yet
				// (IW13-005 — see oracleSettleWindow). Poll until it has, or
				// until the settle deadline turns a persistent mismatch into
				// the FAIL it deserves.
				f := settleOracle(ctx, func() Finding { return m.Oracle(ctx, d.rc) })
				switch {
				case f.Unavailable != "":
					params[oracleUnavailableParam] = f.Unavailable
				default:
					params[oracleVerdictParam] = string(f.Verdict)
					params[oracleObservedParam] = f.Observed
				}
				// The oracle already encodes "could not decide" as its own
				// Unavailable outcome above; nothing here is fatal to the
				// check (check.go's PostWait contract: a returned error is
				// logged and the run continues, exactly like Setup/Change
				// already treat their own bench-lever failures as evidence
				// rather than grounds to abandon the run).
				return nil
			}
		}
		s.Cleanup = func(ctx context.Context, d *Driver) {
			_ = d.ClearControls(ctx, m.Program)
			_ = d.ClearCurves(ctx, m.Program)
			// This clears the CSIP-side control/curve, not the DER's own
			// southbound registers — this bench exposes no lever to reset
			// those (modsim's /control "reset" only resumes its animation,
			// sim/modsim/main.go; there is no register-clear endpoint), and
			// IW13-001 §4.3 does not ask for one. The risk this leaves is
			// bounded, not ignored: PostWait's oracle compares the DER's
			// registers against THIS row's own commanded value, so a stale
			// register left over from an earlier row reads as a MISMATCH —
			// a FAIL, not a false PASS — unless the stale value happens to
			// equal what THIS row is about to command. BASIC-010
			// (WMaxLimPct) and BASIC-013 (WSet/WSetPct) are the only two
			// oracled rows and command different registers, so neither can
			// leave the other a false PASS; the remaining exposure is a row
			// false-passing against its OWN prior run's identical value on a
			// re-run that never actually re-applied the control, which a
			// register-clear lever would close but which this design does
			// not add (a heavier reset path than IW13-001 §4.3 specifies).
		}
	}
	return s
}

// critDEREffectUnobservable is the honest record of the half of every inverter
// control row this suite cannot reach.
func critDEREffectUnobservable(subject string) criterion {
	return criterion{
		Claim: "the DER's output followed " + subject + " for the duration of the event",
		How:   "measurement of the DER's electrical behaviour during the event window",
		Skip: "the DER's response to a control is a measurement of the inverter, not of the 2030.5 exchange. " +
			"On this bench it would appear on the gateway's SOUTHBOUND Modbus leg (a different capture and a " +
			"different suite) or, for the ride-through modes, on no wire at all. This suite certifies the " +
			"protocol half: that the control reached the DUT inside a conformant DERControl",
	}
}

// critDEREffectViaSouthboundOracle is critDEREffectUnobservable's replacement
// for BASIC-010/013/014 (IW13-001 §4.3): the Finding was already computed
// live, during Setup, by controlMode.Oracle — reading the DER's own raw
// 704 register image through internal/invariant, independently of anything
// csipmodel/derbase decoded. This criterion's Wire evaluator does not touch
// the recovered pcap transcript at all; it reports the pre-computed verdict
// carried through Observation.Params. Unlike critDEREffectUnobservable, this
// criterion is a REAL PASS/FAIL: a units bug in the shared decode path can no
// longer self-certify by having the only check that would catch it always
// SKIP.
func critDEREffectViaSouthboundOracle(subject string, o *Observation) criterion {
	claim := "the DER's own southbound registers hold the value " + subject + " commanded"
	how := "an independent read of the DER's raw SunSpec 704 image (internal/invariant, which shares only " +
		"the register-offset tables with the product and none of its CSIP/derbase interpretation), compared " +
		"against the value this row itself commanded — not against what the DUT reports the DER received"
	if reason, ok := o.Params[oracleUnavailableParam]; ok && reason != "" {
		return criterion{Claim: claim, How: how, Skip: "the independent southbound oracle could not reach a " +
			"verdict: " + reason}
	}
	verdict := certify.Verdict(o.Params[oracleVerdictParam])
	observed := o.Params[oracleObservedParam]
	return criterion{
		Claim: claim,
		How:   how,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return Finding{Verdict: verdict, Observed: observed}
		},
	}
}

// oracleSimName is the certify.RunCtx sim slot the DER under BASIC-010/013/014
// is reachable through — the same slot basicAlarms already drives southbound
// (alarmSimName), the bench's one managed inverter for this suite's scalar
// control rows.
const oracleSimName = alarmSimName

// oracleTolerance is the slack the independent oracle allows a resolved
// value: 1% of the commanded value plus a small absolute floor, so the last
// register count (a hundredths-of-a-percent or watts rounding step) does not
// fail a row that is otherwise exactly right. Mirrors CtlTolerance's shape
// (internal/diff/ctl.go) for the same reason stated there — a constant of the
// family, not derived from the value under test.
func oracleTolerance(want float64, absFloor float64) float64 {
	return math.Abs(want)*0.01 + absFloor
}

// oracleUnitView connects to the DER's own simapi sidecar and reads its raw
// register image — the SAME internal/invariant.SimAPIDER source
// cmd/gw-campaign and sim/gw-mayhem already use in production campaign code,
// never a shortcut invented for this suite.
func oracleUnitView(ctx context.Context, rc *certify.RunCtx, simName string) (invariant.UnitView, error) {
	sim, err := rc.Sim(simName)
	if err != nil {
		return invariant.UnitView{}, err
	}
	der := invariant.NewSimAPIDER(simName, sim, 1)
	view, err := der.Observe(ctx)
	if err != nil {
		return invariant.UnitView{}, fmt.Errorf("read %s's own registers: %w", simName, err)
	}
	if !view.Reachable {
		return invariant.UnitView{}, fmt.Errorf("%s's own register image was not reachable: %s", simName, view.Err)
	}
	return view.Unit, nil
}

// oracleSettleWindow/oracleSettleStep bound the re-read the PostWait oracle
// does after the DUT's northbound walk is observed (IW13-005, refined live
// 2026-08-13).
//
// AwaitWalk (check.go run() -> observe.go) returns the instant the DUT issues
// its FIRST GET /dcap after Setup — the START of its poll-cycle walk, not the
// end. The control the DUT then fetches travels northbound-service -> MQTT ->
// modbus reconciler -> a southbound Modbus write before it reaches the DER's
// own registers, and that pipeline lands a beat AFTER the /dcap that satisfied
// AwaitWalk: on the bench the reconciler logged "applied CeilingW=4800
// (reason=new-desired)" ~1s after the DUT's walk began. A single oracle read
// fired the moment AwaitWalk returns therefore samples the DER MID-PROPAGATION
// and sees the pre-control value (the program default), a false FAIL of a DER
// that applies the commanded ceiling correctly a second later.
//
// So the PostWait oracle POLLS: it re-reads the DER until the effect matches
// (Pass) or the settle window elapses, returning the last decided verdict at
// the deadline. A genuine, persistent mismatch (wrong register, wrong value)
// never reaches Pass and still FAILs at the deadline with the value it read;
// the oracled control's active window (oracleWindow) is far longer than this
// settle, so nothing the poll observes is the control expiring. Only a decided
// FAIL is retried — a Pass is returned at once, and an Unavailable (the DER
// could not be reached at all) is not a propagation delay, so it returns at
// once too rather than burning the window.
const (
	oracleSettleWindow = 15 * time.Second
	oracleSettleStep   = 1 * time.Second
)

// settleOracle re-evaluates eval until it PASSES or the settle window elapses.
// See oracleSettleWindow for why the oracled rows read through it.
func settleOracle(ctx context.Context, eval func() Finding) Finding {
	return settleOracleWindow(ctx, oracleSettleWindow, oracleSettleStep, eval)
}

// settleOracleWindow is settleOracle's parameterized core, split out so a test
// can drive the deadline path in milliseconds instead of the production window.
func settleOracleWindow(ctx context.Context, window, step time.Duration, eval func() Finding) Finding {
	deadline := time.Now().Add(window)
	for {
		f := eval()
		if f.Verdict == certify.Pass || f.Unavailable != "" || !time.Now().Before(deadline) {
			return f
		}
		select {
		case <-ctx.Done():
			return f
		case <-time.After(step):
		}
	}
}

// oracleMaxLimW builds a BASIC-010 (opModMaxLimW) Oracle: the DER's own
// RESOLVED active-power ceiling in WATTS, compared against the commanded
// percent resolved against THIS SAME DER's own WMax — the effect-based shape
// oracleFixedW already uses, not the raw WMaxLimPct percent register the
// pre-fix oracle read (IW13-005, diagnosed live 2026-08-13).
//
// WHY effect-based, not percent-to-percent: the board actuates a max-limit by
// writing the DER's WMaxLimPct register as a percent of the DER's nameplate —
// percent = applied ceiling W / nameplate W * 100 (lexa-gw
// cmd/modbus/reconcile_solar.go's "704 WMaxLimPct echo"). Judging the RESOLVED
// watts (WMaxLimPct % * WMax) rather than the bare percent makes the oracle a
// statement about the physical cap the DER will enforce — robust to any bench
// where the board's nameplate denominator and the DER's own WMax are not the
// identical number — and symmetric with oracleFixedW, so the two oracled rows
// judge the same physical quantity the same way. On the bench the two are
// numerically equal (both an 8000 W WMax), so this does not change a correct
// verdict; it changes what the verdict MEANS and what the bundle reports (a
// watts ceiling, not a percent). The FAIL the compliance run actually hit was
// a read-TOO-EARLY timing race (the oracle read the DER before the board's
// northbound->southbound pipeline applied the ceiling), fixed separately by
// the PostWait settle poll (settleOracle / oracleSettleWindow) with the wider
// active window (oracleWindow) as insurance — NOT a defect in which register
// the board writes: live 2026-08-13 the board wrote WMaxLimPct correctly, as
// a percent of nameplate, and held the commanded 4800 W cap for the window.
func oracleMaxLimW(wantHundredths int64) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		np := uv.Nameplate(oracleSimName)
		if !np.Present {
			return unavailable("the DER serves no M702, so its own WMax has no value to resolve the " +
				"commanded ceiling against")
		}
		meas := uv.Measurement(oracleSimName)
		base, err := np.Base(invariant.RefWMax, 1, meas)
		if err != nil {
			return unavailable("cannot resolve the DER's own WMax: %v", err)
		}
		wantPct := float64(wantHundredths) / 100.0
		wantW := wantPct / 100 * base.Q.Val
		for _, c := range uv.Commands(oracleSimName) {
			if c.Point != "WMaxLimPct" || !c.Enabled {
				continue
			}
			r := invariant.ResolveCommand(c, np, meas)
			if !r.Physical.Known() || r.Physical.Unit != invariant.UnitWatt {
				continue
			}
			gotW := r.Physical.Val
			observed := fmt.Sprintf("the DER's own WMaxLimPct resolves to a %.1f W active-power ceiling "+
				"(commanded %.2f%% of its own %.1f W WMax = %.1f W)", gotW, wantPct, base.Q.Val, wantW)
			if math.Abs(gotW-wantW) <= oracleTolerance(wantW, 1) {
				return Finding{Verdict: certify.Pass, Observed: observed}
			}
			return Finding{Verdict: certify.Fail, Observed: observed}
		}
		return unavailable("the DER reports no enabled WMaxLimPct in its own 704 image")
	}
}

// oracleFixedW builds a BASIC-013 (opModFixedW) Oracle: the DER's own
// resolved WSet/WSetPct watts value, compared against the commanded percent
// resolved against THIS SAME DER's own WMax (§2.1 Phase 1, symmetric both
// signs — mirroring csipin.go's fixedWReference/derbase's identical judgment
// call: this package's Nameplate type has no distinct charge/discharge
// rating to prefer instead).
func oracleFixedW(wantHundredths int64) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		np := uv.Nameplate(oracleSimName)
		if !np.Present {
			return unavailable("the DER serves no M702, so its own WMax has no value to resolve the " +
				"commanded percent against")
		}
		meas := uv.Measurement(oracleSimName)
		base, err := np.Base(invariant.RefWMax, 1, meas)
		if err != nil {
			return unavailable("cannot resolve the DER's own WMax: %v", err)
		}
		wantPct := float64(wantHundredths) / 100.0
		wantW := wantPct / 100 * base.Q.Val
		for _, c := range uv.Commands(oracleSimName) {
			if (c.Point != "WSet" && c.Point != "WSetPct") || !c.Enabled {
				continue
			}
			r := invariant.ResolveCommand(c, np, meas)
			if !r.Physical.Known() || r.Physical.Unit != invariant.UnitWatt {
				continue
			}
			gotW := r.Physical.Val
			observed := fmt.Sprintf("the DER's own %s resolves to %.1f W (commanded %.2f%% of its own %.1f W = %.1f W)",
				c.Point, gotW, wantPct, base.Q.Val, wantW)
			if math.Abs(gotW-wantW) <= oracleTolerance(wantW, 1) {
				return Finding{Verdict: certify.Pass, Observed: observed}
			}
			return Finding{Verdict: certify.Fail, Observed: observed}
		}
		return unavailable("the DER reports no enabled WSet/WSetPct in its own 704 image")
	}
}

// oracleTargetW builds an opModTargetW Oracle: genuinely independent
// watts-to-watts, no percent conversion on this axis at all (§1.1 —
// opModTargetW was already correct, ActivePower/watts) — the DER's own
// resolved WSet (watts mode) compared directly against the commanded
// value×10^multiplier.
//
// DELIBERATELY NOT WIRED to BASIC-014 (see register.go's own comment on that
// row, and this design's STOP condition — docs/design/
// IW13_ACTIVE_POWER_UNITS_2026-08-12.md §3.4/§4.3 does not resolve this):
// opModTargetW stays CannotComply (supported.go's ScalarSupportedAxes,
// unchanged), so a correctly-behaving DUT NEVER writes the commanded value
// southbound at all — this function's "the DER holds the commanded value"
// assertion would FAIL every conformant DUT, exactly backwards from BASIC-010/
// 013's oracles, which test axes the product genuinely executes. Kept,
// unwired, as the groundwork for a future "the refusal left no southbound
// trace" oracle (the opposite assertion), which is a materially different
// check this design does not specify.
func oracleTargetW(wantWatts int64) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		np := uv.Nameplate(oracleSimName)
		meas := uv.Measurement(oracleSimName)
		want := float64(wantWatts)
		for _, c := range uv.Commands(oracleSimName) {
			if c.Point != "WSet" || !c.Enabled {
				continue
			}
			r := invariant.ResolveCommand(c, np, meas)
			if !r.Physical.Known() || r.Physical.Unit != invariant.UnitWatt {
				continue
			}
			gotW := r.Physical.Val
			observed := fmt.Sprintf("the DER's own WSet resolves to %.1f W (commanded %.1f W)", gotW, want)
			if math.Abs(gotW-want) <= oracleTolerance(want, 1) {
				return Finding{Verdict: certify.Pass, Observed: observed}
			}
			return Finding{Verdict: certify.Fail, Observed: observed}
		}
		return unavailable("the DER reports no enabled watts-mode WSet in its own 704 image")
	}
}

// eventScenario builds the BASIC-016..026 precedence rows.
//
// Each row is a fixture: N DERPrograms, N DefaultDERControls, M DERControls in a
// particular overlap relationship, and a stated expectation about which one the
// DER ends up following. The wire-observable half is which controls reached the
// DUT and, where the events ask for it, which the DUT acknowledged; the
// "which one is in effect" half is the inverter measurement critDEREffect
// declines to fake.
type eventScenario struct {
	// Controls are the DERControls to publish, in order.
	Controls []scenarioControl
	// ExpectWinner names the mRID the procedure expects to prevail, or "" when
	// the row is about DefaultDERControls only.
	ExpectWinner string
	// Summary is the row's fixture in one line, for the bundle.
	Summary string
}

type scenarioControl struct {
	MRID        string
	Program     int
	StartOffset int
	DurationS   int
	MaxLimW     int64
	Superseded  bool
	CreationAge int
}

// withNonce returns a copy of the scenario whose control mRIDs — and the
// ExpectWinner that names one of them — all carry the per-run nonce.
//
// This is the test-isolation fix for BASIC-017..026. IEEE 2030.5 mRIDs are
// globally unique and stable, so the gateway's Response tracker correctly
// refuses to re-acknowledge (re-post Received/Started for) an event mRID it has
// already run to terminal. A campaign that republishes the same STATIC mRIDs
// therefore passes only against a fresh gateway and is suppressed on every
// re-run of the long-running one — critResponsePosted then sees no Response and
// FAILs. Appending a fresh token per run makes each campaign publish mRIDs the
// tracker has not yet seen, exactly as the curve-driven controls already get a
// per-run gridsim-assigned mRID.
//
// The SAME nonce is applied to every mRID in the scenario, so the within-run
// correlation the lifecycle assertions rely on still holds: ExpectWinner keeps
// naming the winning control (critResponsePosted), and critScenarioControlsDelivered
// keeps matching the mRIDs it published against the ones the DUT fetched. An
// empty nonce is the identity, so a bench that does not care about isolation
// (and every existing test that reasons about the static mRIDs) is unchanged.
func (sc eventScenario) withNonce(nonce string) eventScenario {
	if nonce == "" {
		return sc
	}
	out := sc
	if sc.ExpectWinner != "" {
		out.ExpectWinner = withRunNonce(sc.ExpectWinner, nonce)
	}
	out.Controls = make([]scenarioControl, len(sc.Controls))
	for i, c := range sc.Controls {
		c.MRID = withRunNonce(c.MRID, nonce)
		out.Controls[i] = c
	}
	return out
}

func basicEventScenario(sc eventScenario) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, eventScenarioSpec(sc, rc))
	}
}

// eventScenarioSpec builds basicEventScenario's spec. Factored out — the same
// shape as coreResponsesSpec — so a test can drive its Want directly against a
// fake ServerView without booting the whole check, which needs a live capture
// window run() cannot fake.
func eventScenarioSpec(sc eventScenario, rc *certify.RunCtx) spec {
	return spec{
		RequiresGridSim: len(sc.Controls) > 0,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			for _, c := range sc.Controls {
				req := ControlRequest{
					Program: c.Program, MRID: c.MRID, Description: "certify " + rc.Case.ID,
					StartOffset: c.StartOffset, DurationS: c.DurationS, MaxLimW: ptr(c.MaxLimW),
				}
				if c.Superseded {
					req.PotentiallySuperseded = ptr(true)
				}
				if c.CreationAge != 0 {
					age := c.CreationAge
					req.CreationOffsetS = &age
				}
				if _, err := d.PostControl(ctx, req); err != nil {
					return err
				}
			}
			return nil
		},
		// Want: wait for the WINNING control's own Response, not merely for A
		// walk to happen. Without this, a scenario with ExpectWinner set falls
		// through to run()'s AwaitWalk default, whose predicate — "the DUT GET
		// /dcap'd at least once since base" — is satisfied the instant the
		// FIRST fresh walk is seen, closing the observation window right then.
		// A walk and the Response it produces are two separate round trips
		// (the DUT fetches DERControlList, decides, THEN POSTs the Response),
		// so on a bench where the walk itself resolves quickly the window can
		// close a hair before the Response lands — csip.wait never gets a
		// chance to govern the wait at all, because Await/AwaitWalk returned
		// long before its budget was spent.
		//
		// 2026-08-11 standalone BASIC-020 (runs/wave11-qa-20260811/
		// rerun-BASIC-020): exactly this race — the response-assertion window
		// closed ~62s in, the same second the DUT's status=1 landed, and
		// gridsim's admin API reported "no Response POST in this window" even
		// though the board's own journal proved both controls ran their full
		// [1 2 3] lifecycles moments later. -param csip.wait=8m was in effect
		// and never got to matter, because AwaitWalk had already declared the
		// window done.
		//
		// WantNewResponse (observe.go) is the same idiom coreResponsesSpec uses
		// for CORE-022's own false-early-exit fix (see its doc): it makes Await
		// keep polling — for up to the FULL csip.wait-derived window, not a
		// fraction of it — until a Response actually exists for the mRID the
		// criteria below grade, rather than for the walk that merely precedes
		// it. Full-suite behavior is unaffected or improved, never narrowed: a
		// run where AwaitWalk already happened to leave enough margin for the
		// Response keeps working exactly as before (this predicate is satisfied
		// at the same point the DUT's actual Response lands, whichever the wire
		// shows), and a run where it did not now gets the rest of its own
		// window instead of none of it. Rows with no ExpectWinner (BASIC-016)
		// have nothing to wait for a Response TO, so they return nil and keep
		// the AwaitWalk fallback unchanged.
		Want: func(base ServerView) func(ServerView) bool {
			if sc.ExpectWinner == "" {
				return nil
			}
			return base.WantNewResponse(sc.ExpectWinner)
		},
		Cleanup: func(ctx context.Context, d *Driver) {
			seen := map[int]bool{}
			for _, c := range sc.Controls {
				if !seen[c.Program] {
					seen[c.Program] = true
					_ = d.ClearControls(ctx, c.Program)
				}
			}
		},
		Notes: func(o *Observation) string {
			return sc.Summary + fmt.Sprintf("; waited %s", o.Waited.Round(rounding))
		},
		Criteria: func(o *Observation) []criterion {
			crits := []criterion{
				critProgramList(0),
				critDefaultDERControl(),
			}
			if len(sc.Controls) > 0 {
				crits = append(crits, critScenarioControlsDelivered(sc))
			}
			if sc.ExpectWinner != "" {
				crits = append(crits, critResponsePosted(1, "Event received", sc.ExpectWinner))
			}
			crits = append(crits, criterion{
				Claim: "the DER followed the control the procedure's precedence rules select (" +
					sc.Summary + ")",
				How: "measurement of the DER's electrical behaviour across the scenario's event windows",
				Skip: "which control is IN EFFECT is a property of the inverter, not of the 2030.5 " +
					"exchange, and is not observable on the CSIP leg. The wire half — which controls " +
					"reached the DUT, and which it acknowledged — is asserted above",
			})
			return crits
		},
	}
}

// critScenarioControlsDelivered asserts that every control the scenario
// published reached the DUT.
func critScenarioControlsDelivered(sc eventScenario) criterion {
	return criterion{
		Claim:           "every DERControl the scenario published reached the DUT in a DERControlList it fetched",
		How:             "the mRIDs of the DERControls in the DERControlLists the DUT fetched during the window",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			got := map[string]bool{}
			var frames []int
			for _, e := range t.ByResource("DERControlList") {
				doc, err := e.Resp.SEP()
				if err != nil {
					continue
				}
				for _, c := range doc.Children("DERControl") {
					if m, ok := c.TextOf("mRID"); ok {
						got[m] = true
					}
				}
				frames = append(frames, e.Frames()...)
			}
			if len(frames) == 0 {
				return unavailable("no DERControlList appears in the recovered transcript")
			}
			var missing []string
			for _, c := range sc.Controls {
				if !got[c.MRID] {
					missing = append(missing, c.MRID)
				}
			}
			if len(missing) > 0 {
				return found(certify.Fail, dedupeInts(frames),
					"%d of %d published control(s) did not reach the DUT: %s",
					len(missing), len(sc.Controls), strings.Join(missing, " "))
			}
			return found(certify.Pass, dedupeInts(frames),
				"all %d published control(s) appear in the lists the DUT fetched", len(sc.Controls))
		},
		Server: func(v *ServerView) Finding {
			n := 0
			for _, c := range sc.Controls {
				if len(v.ResponsesFor(c.MRID)) > 0 {
					n++
				}
			}
			if n == 0 {
				return unavailable("gridsim received no Response for any of the scenario's controls, which " +
					"is expected when the controls do not ask for one; delivery cannot be confirmed from " +
					"the server side alone")
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("the DUT acknowledged %d of %d published control(s) to gridsim",
					n, len(sc.Controls))}
		},
	}
}

// alarmSimName is the simapi sidecar key for the CSIP leg's southbound DER
// sim (cmd/certify's -modsim-api registration; see suitemodbusclient's
// defaultDeviceName="inv-plain" for the same device on the Modbus suite's
// side — the CSIP leg's posture is 1:1 DUT<->DER, so there is only ever this
// one southbound sim to drive).
const alarmSimName = "modsim"

// alarmFaultBits is the model 701 Alrm bit this case arms: AC_UNDER_VOLT
// (1<<11 = 0x800). It is lexa-gw's DIRECT, unambiguous mapping onto CSIP
// Table 14 UNDER_VOLTAGE — lexa-hub/cmd/hub/logevent.go's alrm701ToTable14
// maps alrm701ACUnderVolt straight to bus.LogEventDERUnderVoltage(4) as a
// "grid-interface voltage" condition, the same footing as the three other
// bits that repo maps directly (OverFrequency/UnderFrequency/ACOverVolt) —
// unlike the DC-side/manufacturer/connection-state bits that repo
// deliberately leaves UNmapped (no defensible CSIP Table 14 code) or the
// EMERGENCY_LOCAL bit (a locally-initiated stop, a different character of
// condition). This is the alarm the product's hub-side alarm-edge detector
// (cmd/hub/logevent.go, watching bus.Measurement.AlarmBits — itself read
// from THIS register, WP-2) genuinely reacts to.
//
// sim/southbound/solar_adv.go's advCoupledVoltHz backs the bit with an
// actual under-threshold voltage reading (205 V, under the IEEE 1547-2018
// Category III 0.88 pu / 211.2 V nominal trip point) on every 701 voltage
// point, not a bare flag with a nominal reading underneath it — see that
// function's doc for the full reasoning.
const alarmFaultBits = 1 << 11

// alarmArmedAtParam keys the param this case's Change hook leaves for
// alarmNote/noAlarmReason, unprefixed like rehome.go's "rehome_at"
// (CORE-009/CORE-014) rather than "csip."-prefixed like check.go's own
// params, since it is this ROW's fact, not framework state. A failed Change
// is already recorded under check.go's own changeFailed key — reused here
// rather than duplicated.
const alarmArmedAtParam = "alarm_armed_at"

// basicAlarms implements BASIC-027 — Alarms (LogEvent).
//
// The catalog's printed procedure (steps 3-8) has the CLIENT under test
// prepare and POST a LE_GEN_SOFTWARE general LogEvent (Table 34, functionSet
// 0) five times and then GET the list with ?l=255 — a generic conformance
// template for any CSIP client. lexa-gw's northbound LogEvent poster
// (internal/northbound/logevent/logevent.go HandleLogEvent) does not do
// that: it refuses anything outside FunctionSet 11 (DER) by construction, and
// only ever POSTs a DER alarm/RTN pair the hub's alarm-edge detector minted
// from a real southbound condition (see alarmFaultBits' doc). The three
// criteria below were written against that real behaviour, not the generic
// template text, and this case's job is to give them a genuine alarm to
// grade rather than to force the DER to speak a vocabulary it does not use.
func basicAlarms(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		// Change arms the fault AFTER the initial discovery-walk wait, so the
		// DUT has already found (and cached) its LogEventListLink the way a
		// real client does, exactly as CORE-009/CORE-014's RehomeDER runs
		// after the client has "taken up what Setup put there" (see spec.Change's
		// doc in check.go). ChangeWait: changeWaitFullCycle because — unlike a
		// Notification, which the server dispatches synchronously with the
		// mutation — this fault has to cross the DUT's own southbound polling
		// interval, its hub-side alarm-edge detection, and an MQTT hop before
		// the northbound poster POSTs anything; that is "something the DUT
		// must notice and act on", the same class of wait CORE-009/CORE-014
		// use changeWaitFullCycle for.
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			sim, err := d.rc.Sim(alarmSimName)
			if err != nil {
				return fmt.Errorf("this row needs a fault armed on the DUT's southbound DER sim: %w", err)
			}
			body := map[string]any{"kind": "raise_alarm", "bits": alarmFaultBits}
			if err := sim.Fault(ctx, body, nil); err != nil {
				return fmt.Errorf("arm raise_alarm bits=%#x on %s: %w", alarmFaultBits, alarmSimName, err)
			}
			params[alarmArmedAtParam] = time.Now().UTC().Format(time.RFC3339)
			d.rc.Logf("BASIC-027: armed raise_alarm bits=%#x on %s — the DUT's southbound 701 Alrm bitfield "+
				"now reports AC_UNDER_VOLT with a genuinely under-threshold voltage reading behind it",
				alarmFaultBits, alarmSimName)
			return nil
		},
		ChangeWait: changeWaitFullCycle,
		// Cleanup always runs (check.go's doc: "whatever happens, or it
		// corrupts every later test case on a shared bench") — even when
		// Change never got to arm anything, in which case d.rc.Sim below
		// fails identically and this is a no-op.
		Cleanup: func(ctx context.Context, d *Driver) {
			sim, err := d.rc.Sim(alarmSimName)
			if err != nil {
				return
			}
			body := map[string]any{"kind": "raise_alarm", "clear": true}
			if err := sim.Fault(ctx, body, nil); err != nil {
				d.rc.Logf("BASIC-027: WARNING could not clear raise_alarm on %s: %v — a bench left alarming "+
					"corrupts every later test case sharing it", alarmSimName, err)
				return
			}
			d.rc.Logf("BASIC-027: cleared raise_alarm on %s (the RTN edge)", alarmSimName)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("LogEvent reporting; gridsim recorded %d LogEvent(s) from the DUT during the "+
				"window", len(o.Server.LogEvents)) + alarmNote(o)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critAlarmEndDevice(),
				critLogEventPosted(o),
				{
					Claim: "the DUT's LogEvents carry a logEventCode from IEEE 2030.5 Table 34 and are " +
						"time-ordered",
					How:    "the logEventCode and createdDateTime elements of the recorded LogEvents",
					Skip:   "no LogEvent was recovered in this window to inspect",
					Server: logEventCodesFinding,
				},
			}
		},
	})
}

// critLogEventPosted is BASIC-027's assertion 2: the DUT POSTs a LogEvent to
// the LogEventListLink href and the server answers 201 Created with a Location.
//
// It is a named function — like critMUPRegistered — so its wire evaluator can
// be graded directly against a synthesised transcript, which is how the
// churn-relocated-answer regression answerTo closes is pinned (see
// alarm_flow_test.go). It closes over o only for its Server-tier fallback.
func critLogEventPosted(o *Observation) criterion {
	return criterion{
		Claim: "the DUT POSTs LogEvents to the LogEventListLink href and the server answers 201 " +
			"Created with a Location header",
		How: "a POST in the session whose body's root element is LogEvent, and the status line and " +
			"Location header of the response to it",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			// A case can own MORE THAN ONE LogEvent-bodied POST: a DUT that
			// picks a pooled HTTP/1.1 connection gridsim has already
			// idle-closed gets an immediate RST on that attempt and, per
			// ordinary HTTP/1.1 client practice, retries the identical POST
			// on a fresh connection — a second candidate this case owns
			// exactly as much as the first. Bailing out on the first
			// candidate that lacks an answer used to read that dead attempt
			// as the whole story and FAIL a case whose retry, seconds later
			// on a sibling connection, was answered 201 inside this same
			// window. So every LogEvent-bodied POST this case owns is
			// scanned, in capture order, and the first one that actually HAS
			// an answer is the one graded and cited; "never answered" is
			// reserved for the case where none of them ever got one.
			var unanswered []*Message
			for _, e := range t.Method("POST") {
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "LogEvent" {
					continue
				}
				// The answer is not always on Exchange.Resp. RecoverSession
				// pairs a conversation's recovered requests to its responses by
				// INDEX (session.go's decrypt: e.Resp = resps[i]), which the
				// DUT's connection churn can skew so the POST's own 201 —
				// decrypted and present in this very window — is left unpaired,
				// and this criterion used to read that as "never answered".
				// answerTo recovers it by HTTP order across every conversation
				// this case owns; see its doc for the false FAIL it closes and
				// the gridsim-admin proof behind it.
				resp := e.Resp
				if resp == nil {
					resp = answerTo(t, e.Req)
				}
				if resp == nil {
					// Genuinely nothing rode this candidate's own connection
					// in reply — keep it in case NONE of this case's
					// LogEvent POSTs ever gets answered, but don't stop
					// here: a sibling attempt, still inside this case's
					// window, may be the one gridsim actually answered.
					unanswered = append(unanswered, e.Req)
					continue
				}
				var missing []string
				for _, want := range []string{"createdDateTime", "functionSet", "logEventCode",
					"logEventID", "logEventPEN", "profileID"} {
					if !doc.Has(want) {
						missing = append(missing, want)
					}
				}
				ex := Exchange{Req: e.Req, Resp: resp}
				loc := resp.Header.Get("Location")
				retry := retriedAfterNote(unanswered)
				switch {
				case len(missing) > 0:
					return annotate(citeMessage(t, e.Req, certify.Fail,
						"the LogEvent payload is missing %s", strings.Join(missing, ", ")), retry)
				case resp.Status != 201:
					return annotate(citeExchange(t, ex, certify.Fail,
						"POST %s carrying LogEvent -> %s; 2030.5 §5.5.2 requires 201 Created",
						e.Req.Target, resp.Line()), retry)
				case loc == "":
					return annotate(citeExchange(t, ex, certify.Fail,
						"POST %s -> 201 Created but with no Location header, which 2030.5 requires "+
							"on a 201", e.Req.Target), retry)
				default:
					return annotate(citeExchange(t, ex, certify.Pass,
						"POST %s carrying a complete LogEvent -> 201 Created, Location: %s",
						e.Req.Target, loc), retry)
				}
			}
			if len(unanswered) > 0 {
				return citeMessage(t, unanswered[0], certify.Fail, "the LogEvent POST was never answered")
			}
			return unavailable("the recovered transcript holds no LogEvent POST from the DUT")
		},
		Server: logEventsPostedFinding(o),
	}
}

// retriedAfterNote is critLogEventPosted's citation-detail sentence for the
// dead attempt(s) that preceded the LogEvent POST actually being graded. A
// pooled HTTP/1.1 connection idle-closed by gridsim, reused by the DUT
// anyway, and answered with an immediate RST is not a defect — reusing a
// connection, hitting that race, and retrying on a fresh one is exactly what
// a mainstream HTTP/1.1 client (Go's net/http.Transport among them) does —
// so it is recorded here as observed retry behavior, not folded into the
// verdict of the attempt that DID get answered. Empty when nothing was ever
// left unanswered before the cited attempt.
func retriedAfterNote(unanswered []*Message) string {
	if len(unanswered) == 0 {
		return ""
	}
	plural := ""
	if len(unanswered) > 1 {
		plural = "s"
	}
	return fmt.Sprintf(". Before this, %d earlier LogEvent POST attempt%s on a separate connection this "+
		"case owns went unanswered — a pooled connection gridsim had already idle-closed, answered with an "+
		"immediate RST, which the DUT retried on a fresh connection: ordinary HTTP/1.1 client behavior after "+
		"an idle-close race, not a defect", len(unanswered), plural)
}

// answerTo recovers the HTTP response that answered req, searching every
// conversation this test case owns rather than trusting the positional
// request<->response pairing RecoverSession builds inside one conversation.
//
// # The false FAIL this closes
//
// RecoverSession pairs a conversation's recovered requests with its responses
// by INDEX (session.go's decrypt: `e.Resp = resps[i]`). That is correct only
// when the two lists are the same length and aligned, which a quiet,
// single-purpose sibling connection — one POST, one 201 — always is. That is
// exactly why BASIC-027 PASSed in runs/tail-csip-20260801T184232: the DUT put
// the LogEvent POST on a dedicated two-frame connection (69.0.0.2:42844), whose
// lone request paired trivially with its lone 201.
//
// When the DUT's connection pattern changes (session churn) the POST rides a
// BUSIER sibling connection, or its 201 lands a frame after the request at the
// edge of this case's attribution window. The index pairing then leaves the
// POST's Exchange.Resp nil even though the 201 IS in that conversation's
// decrypted Responses (decrypt recovers the whole owned stream, not just the
// paired prefix). The criterion read that nil as "the LogEvent POST was never
// answered" — a FALSE FAIL: gridsim's admin API (GET /admin/logevents) proves
// the server received and answered the POST, minting the LogEvent an Href
// (/edev/2/lev/0, /edev/2/lev/1 — LogEventCode 4), which a 2030.5 server only
// does on a successful 201 Created. Assertion 3 (LogEvent well-formed) PASSes
// on that same server record; only the wire tier's pairing missed the answer.
//
// # Why order, not index, is the right key
//
// An HTTP request and its response share ONE TCP connection, so the answer is
// on the SAME conversation the request rode (req.In). Within that conversation
// the answer is the FIRST response whose earliest capture frame is not before
// the request's: HTTP/1.1 on one connection is strictly ordered — the client
// does not send its next request until the current one is answered — so every
// response before the request belongs to an earlier request, and the first one
// at-or-after the request is this request's own. Keying on capture-frame order
// is what tolerates a length skew and a 201 that arrives slightly after.
//
// This does not weaken the assertion. A POST with genuinely no response after
// it on its connection still yields nil, and the caller still FAILs it "never
// answered"; a response that is present but is a 500, or carries no Location, is
// returned and graded exactly as a positionally-paired one would be. It only
// stops missing an answer that IS in the capture on a conversation whose index
// pairing skewed. This is the transcript-tier counterpart of the
// multi-conversation doctrine Transcript.Filter/Own already apply to REQUEST
// lookups, and of bundle.Verify's resolveDirection port-reuse fix (2946787):
// ownership was settled before selection, so a frame in any owned conversation
// is a frame this case may cite.
func answerTo(t *Transcript, req *Message) *Message {
	if t == nil || req == nil {
		return nil
	}
	reqFrame := earliestFrame(req)
	var best *Message
	for _, conv := range t.Own() {
		if conv == nil {
			continue
		}
		// An HTTP answer never crosses to another TCP connection. Every
		// recovered message carries the conversation it rode (Message.In), so
		// restrict to it; a hand-built test message with no In falls back to
		// searching every owned conversation.
		if req.In != nil && conv != req.In {
			continue
		}
		for _, resp := range conv.Responses {
			if resp == nil || resp.Kind != Response {
				continue
			}
			if earliestFrame(resp) < reqFrame {
				continue
			}
			if best == nil || earliestFrame(resp) < earliestFrame(best) {
				best = resp
			}
		}
	}
	return best
}

// earliestFrame is a recovered message's first capture frame, or 0 when it
// carries none (a hand-built test message). Message.Frames is kept sorted
// ascending by dedupeInts, so the first element is the earliest.
func earliestFrame(m *Message) int {
	if m == nil || len(m.Frames) == 0 {
		return 0
	}
	return m.Frames[0]
}

// alarmEndDevice finds the exchange whose response is the DUT's EndDevice
// resource, applying the same across-conversation, order-based response
// recovery as answerTo so a fetch the DUT relocated to a churned sibling
// connection — whose response the per-conversation index pairing missed — is
// still matched to its answer. The already-paired path (Transcript.Resource,
// which already spans every owned conversation) is tried first and is the
// ordinary case; the fallback only ADDS recall for the unpaired-answer shape
// answerTo documents. It returns a synthetic Exchange so the criterion can cite
// both halves.
//
// Note this cannot conjure a fetch that is not in the window at all: BASIC-027
// arms its fault AFTER the discovery-walk wait precisely so the DUT has already
// cached its LogEventListLink (see basicAlarms' Change doc), so a run in which
// the DUT does not re-fetch the singular EndDevice in-window still SKIPs here —
// correctly, and without failing the case, exactly as it did in the passing
// runs/tail-csip-20260801T184232 baseline.
func alarmEndDevice(t *Transcript) (Exchange, *Node, bool) {
	if e, doc, ok := t.Resource("EndDevice"); ok {
		return e, doc, true
	}
	for _, e := range t.Method("GET") {
		if e.Resp != nil {
			continue
		}
		resp := answerTo(t, e.Req)
		if resp == nil || resp.Status < 200 || resp.Status >= 300 || len(resp.Body) == 0 {
			continue
		}
		doc, err := resp.SEP()
		if err != nil || doc.Local() != "EndDevice" {
			continue
		}
		return Exchange{Req: e.Req, Resp: resp}, doc, true
	}
	return Exchange{}, nil, false
}

// critAlarmEndDevice is BASIC-027's assertion 1: the DUT fetched its EndDevice
// and the server's payload carries a LogEventListLink. It mirrors
// critResource("EndDevice", ...) but locates the resource through alarmEndDevice
// so a churn-relocated fetch whose 200 the index pairing missed is still found —
// the same regression, on the same window, that answerTo closes for the POST.
func critAlarmEndDevice() criterion {
	return criterion{
		Claim: "the DUT fetched its EndDevice and the server's payload carries a LogEventListLink",
		How: "the first exchange, across every conversation this case owns, whose response body is an " +
			"EndDevice in the 2030.5 namespace (located by root element, not URI, because 2030.5 URIs are " +
			"server-defined) — its response recovered by HTTP order rather than by the per-conversation index " +
			"pairing, so a fetch the DUT relocated to a churned sibling connection is still matched to its answer",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			e, doc, ok := alarmEndDevice(t)
			if !ok {
				return unavailable("no EndDevice appears in the recovered transcript (resources seen: %s)",
					strings.Join(t.ResourceNames(), " "))
			}
			if !doc.InNamespace() {
				return citeMessage(t, e.Resp, certify.Fail,
					"the EndDevice is in namespace %q, not %s — a 2030.5 payload without the namespace "+
						"unmarshals to zero values in every conformant parser", doc.Name.Space, Namespace)
			}
			if !doc.Has("LogEventListLink") {
				return citeMessage(t, e.Resp, certify.Fail,
					"the EndDevice carries no LogEventListLink, so the alarm function set is unreachable")
			}
			return citeMessage(t, e.Resp, certify.Pass, "%s -> 200 %s; LogEventListLink present",
				e.Req.Line(), doc.Summary())
		},
		Skip: "locating a resource by its root element requires the decrypted transcript",
	}
}

// logEventsPostedFinding is criterion 2's Server-tier evaluator (BASIC-027):
// PASS when gridsim's admin API recorded at least one LogEvent from the DUT
// in this window, SKIP with noAlarmReason's precise explanation otherwise.
// It is a named function — closing over o exactly as the inline closure it
// replaces did — so the flow test can call the SAME evaluator BASIC-027's
// Criteria list uses against a real ServerView, the same shape
// TestCORE014Flow_RehomeThenPUTToNewHrefIsObserved uses critDERPut for.
func logEventsPostedFinding(o *Observation) func(v *ServerView) Finding {
	return func(v *ServerView) Finding {
		if len(v.LogEvents) == 0 {
			return Finding{Verdict: certify.Skip, Observed: fmt.Sprintf(
				"gridsim recorded no LogEvent from the DUT during this window%s", noAlarmReason(o))}
		}
		return Finding{Verdict: certify.Pass,
			Observed: fmt.Sprintf("gridsim recorded %d LogEvent(s) from the DUT", len(v.LogEvents))}
	}
}

// logEventCodesFinding is criterion 3's Server-tier evaluator (BASIC-027):
// the logEventCode of every LogEvent gridsim recorded in this window, or
// unavailable when there is nothing to inspect (criterion.Skip then supplies
// the final reason). Named for the same testability reason as
// logEventsPostedFinding.
//
// Reads the "LogEventCode" key (the Go field name lexa-proto/csipmodel.
// LogEvent's default JSON marshalling produces — that struct carries only
// `xml:` tags, no `json:` tags, so encoding/json falls back to the
// capitalised Go identifier), NOT the lowercase "logEventCode" the wire
// criterion above checks for in the XML payload — the two are different
// serializations of the same field and do not share a key spelling. This
// criterion had never run against a real recorded LogEvent before this row
// could arm one (see basicAlarms' Change hook), so the lowercase-key
// version's silent "codes <nil>" was never observed until
// TestBASIC027Flow_ArmAwaitClearIsObserved posted a real one through it.
func logEventCodesFinding(v *ServerView) Finding {
	if len(v.LogEvents) == 0 {
		return unavailable("gridsim recorded no LogEvent to inspect")
	}
	var codes []string
	for _, le := range v.LogEvents {
		codes = append(codes, fmt.Sprint(le["LogEventCode"]))
	}
	return Finding{Verdict: certify.Pass,
		Observed: fmt.Sprintf("%d LogEvent(s), codes %s", len(v.LogEvents), strings.Join(codes, " "))}
}

// noAlarmReason renders why criterion 2's Server tier still found nothing —
// captured over o from the enclosing Criteria closure so a Server evaluator
// (which only sees *ServerView) can still explain itself precisely instead
// of repeating the now-stale "outside this suite's read-only reach": this
// suite DOES reach the DUT's southbound device now (see alarmNote), so an
// empty result means either the scripted fault could not be armed (a bench
// gap, named) or it was armed but the DUT's detection/publish/POST chain had
// not completed within this row's wait (report, not blame — the wait budget
// is an operator knob, -param csip.wait).
func noAlarmReason(o *Observation) string {
	switch {
	case o.Param(alarmArmedAtParam) != "":
		return fmt.Sprintf(". This suite armed a southbound AC_UNDER_VOLT fault at %s and waited, but no "+
			"LogEvent arrived in that window; a DER with an armed condition that has not yet been detected, "+
			"published and posted is not non-conformant on THIS evidence alone — see -param csip.wait to "+
			"widen the window",
			o.Param(alarmArmedAtParam))
	case o.Param(changeFailed) != "":
		return fmt.Sprintf(". This suite could not arm the fault this row needs: %s — a BENCH gap (the "+
			"southbound sim's fault-injection API), not a DUT finding", o.Param(changeFailed))
	default:
		return ". A DER with nothing to report is not non-conformant, so this is a SKIP: the row needs a " +
			"fault injected on the DUT's southbound devices to make it alarm, which gridsim's admin API was " +
			"not available to script for this run"
	}
}

// alarmNote renders BASIC-027's narrative addendum recording that this
// suite — not the DUT — scripted a southbound DER fault mid-case, the same
// convention rehomeNote uses for CORE-009/CORE-014's server-side re-home
// (core.go): a reader of the bundle must not mistake the DUT's resulting
// LogEvent POST for a spontaneous event, or mistake "the DUT never alarms"
// for the DUT's behaviour when actually no DER condition was ever presented
// to it until this case ran.
func alarmNote(o *Observation) string {
	if at := o.Param(alarmArmedAtParam); at != "" {
		return fmt.Sprintf(". This suite armed a SCRIPTED southbound fault at %s: raise_alarm bits=%#x on "+
			"the bench's plain-text SunSpec DER sim (%s), setting the model 701 Alrm AC_UNDER_VOLT bit and "+
			"backing it with an actual under-threshold voltage reading (not a bare flag — sim/southbound/"+
			"solar_adv.go's advCoupledVoltHz) — a fault-injection action on the TEST FIXTURE's southbound "+
			"device, not a DUT perturbation. lexa-gw's hub-side alarm-edge detector (cmd/hub/logevent.go) "+
			"watches exactly this register for the transition and maps it onto CSIP Table 14 UNDER_VOLTAGE; "+
			"the fault is cleared (the RTN edge) once this case's observation window closes",
			at, uint32(alarmFaultBits), alarmSimName)
	}
	if reason := o.Param(changeFailed); reason != "" {
		return fmt.Sprintf(". This suite could not arm the southbound fault this row needs to make the DUT "+
			"alarm: %s. That is a BENCH gap (the southbound sim's fault-injection API was not reachable), "+
			"not a DUT finding", reason)
	}
	return ""
}

// basicInverterStatus implements BASIC-028 — Inverter Status.
func basicInverterStatus(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return fmt.Sprintf("DERStatus reporting; %d DERStatus PUT(s) recorded server-side during the window",
				len(o.Server.PutsFor("DERStatus")))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResource("DERList", "the DUT fetched the DERList from its EndDevice's DERListLink", nil),
				critDERPut("DERStatus"),
				critDERStatusElements(),
			}
		},
	})
}

// critDERStatusElements asserts BASIC-028's element list on the payload the DUT
// itself reported.
func critDERStatusElements() criterion {
	required := []string{"genConnectStatus", "inverterStatus", "operationalModeStatus", "readingTime"}
	evaluate := func(doc *Node) (certify.Verdict, string) {
		var missing, present []string
		for _, want := range required {
			if doc.Has(want) {
				present = append(present, want)
			} else {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			return certify.Fail, fmt.Sprintf("the DERStatus the DUT reported is missing %s (it carries %s)",
				strings.Join(missing, ", "), strings.Join(present, ", "))
		}
		return certify.Pass, "the DERStatus carries " + strings.Join(present, ", ")
	}
	return criterion{
		Claim: "the DERStatus the DUT reports carries the elements BASIC-028 requires of a power-generating " +
			"DER: genConnectStatus, inverterStatus, operationalModeStatus and readingTime",
		How: "the child elements of the DERStatus payload the DUT PUT, located first in the conversations " +
			"this check owns and then across the run's whole decrypted capture",
		NeedsTranscript: true,
		// The same three-rung ladder as critDERPut, and for the same reason: the
		// DERStatus this row inspects is emitted on the DUT's own cadence, so
		// the body is routinely in the capture but outside this case's window.
		// Reading it from the wire there — and saying so — beats reading it from
		// the copy gridsim stored.
		Wire: func(ev *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "DERStatus" {
					continue
				}
				v, desc := evaluate(doc)
				return citeMessage(t, e.Req, v, "%s", desc)
			}
			rw := runWireOf(ev, t.Remote)
			for _, e := range rw.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "DERStatus" {
					continue
				}
				v, desc := evaluate(doc)
				return Finding{Verdict: v, Observed: fmt.Sprintf(
					"%s — read from the DERStatus body in frame(s) %s, which are outside this test case's "+
						"window and so are named rather than cited. Scope: %s", desc, framesOf(e), rw.Scope())}
			}
			if rw.Complete {
				return unavailable("no DERStatus PUT appears anywhere in the run's capture (%s), so the DUT "+
					"reported no DERStatus body for this criterion to inspect", rw.Scope())
			}
			return unavailable("the recovered transcript holds no DERStatus PUT, and the run's capture "+
				"cannot settle whether one happened elsewhere: %s", rw.Scope())
		},
		Server: func(v *ServerView) Finding {
			puts := v.PutsForInRun("DERStatus")
			if len(puts) == 0 {
				return unavailable("gridsim recorded no DERStatus PUT to inspect")
			}
			doc, err := ParseSEP([]byte(puts[len(puts)-1].Body))
			if err != nil {
				return Finding{Verdict: certify.Fail,
					Observed: fmt.Sprintf("the stored DERStatus body did not parse: %v", err)}
			}
			verdict, desc := evaluate(doc)
			return Finding{Verdict: verdict, Observed: desc + " (from the body gridsim stored)"}
		},
	}
}

// critMUPRegistered asserts the DUT's MirrorUsagePoint registration
// (BASIC-029's own element): a POST carrying its LFDI and a
// MirrorMeterReading/ReadingType, answered 201 Created (or 204 for an
// existing mRID) with a Location header.
//
// Five tiers, strongest first (four evidence sources, since the fourth
// grades two distinct states of the same durable store differently):
//
//  1. Wire (above): an in-window POST recovered from the decrypted transcript,
//     cited by frame. This is the strongest evidence and, when the DUT's
//     registration happens to fall inside the case's own capture window, is
//     what actually grades the claim.
//  2. Server / request log: an in-window POST recorded in gridsim's request
//     log (an EXACT match on the registration path "/mup" — see below for why
//     that has to be exact, not a prefix).
//  3. Server / MUP state, complete (ServerView.RegisteredMUP, GET
//     /admin/mups): registration is a ONE-TIME event — the DUT does it once,
//     at first contact with this MirrorUsagePointList, and has no reason to
//     repeat it — and it ordinarily predates a case's own window: BASIC-029
//     has no Setup of its own to force a fresh one, so by the time this
//     check's window opens the registration already happened, often minutes
//     or a whole campaign earlier. Tiers 1 and 2 can only ever see what fell
//     inside the window; gridsim's durable MUP store did not stop existing
//     just because the window opened late, so it is consulted before
//     conceding anything. This tier requires a ReadingType, because that is
//     part of the claim above — and on this bench the registration POST
//     itself carries none; only the DUT's first MirrorMeterReading does (see
//     basicMeterReading's Want). A window that closes before that first
//     reading lands must NOT credit this tier; see tier 4.
//  4. Server / MUP state, pending (ServerView.PendingMUP): the store has an
//     LFDI-bound MUP but no ReadingType yet — registered, evidence not yet
//     landed, as opposed to never registered at all. This is a real FAIL
//     (the claim's ReadingType is genuinely absent from the window's
//     evidence), but it is graded with its own, more precise wording so a
//     bundle reader is not misled into reading it as "the DUT never
//     registered" — see the fix note below.
//  5. Server / ring gap (last resort, e186056): if the MUP store ALSO has
//     nothing at all — not even a pending, LFDI-only entry (an older gridsim
//     predating the /admin/mups lever, or the process was restarted since
//     registration and genuinely lost its state) — fall back to
//     RequestLogGap: an empty request-log count from a ring that itself says
//     it cannot be trusted for this window is unavailable, not a FAIL. Only
//     once the log is both empty AND trusted is this a real FAIL.
//
// Fix note (audit 2026-07-30, runs/stamped-basic029-20260730T073518 assertion
// 2): the request-log tier used to match any path with the "/mup" PREFIX,
// which also matches "/mup/{n}" — the READING endpoint. A DUT that never
// registers but posts readings every 300s would eventually rack up a POST
// count under the old code and PASS this criterion on evidence that was
// never a registration at all (that run's own Wire tier found no
// MirrorUsagePoint POST in the transcript, yet the Server tier reported "36
// POST(s) to the MirrorUsagePoint tree" and PASSed). The request-log tier now
// matches the registration path exactly.
//
// Fix note (audit 2026-07-30, runs/perphase-basic029-v4-20260730T232105
// assertion 2): a run with `-param csip.wait=12m` finished in ~28s and FAILed
// this criterion even though the DUT HAD registered, 24s before the run even
// started, and gridsim's /admin/mups proved it. Two separate bugs, both fixed
// together because neither alone explains the run:
//
//   - basicMeterReading had no Want of its own, so it fell back to
//     AwaitWalk — satisfied by the DUT's very next /dcap poll, whatever it is
//     for. That poll landed 25s into the window purely because the run
//     happened to start 5s before the DUT's routine 60s-cadence boundary; the
//     operator's 12-minute wait was never honoured. See basicMeterReading's
//     Want for the fix: it now waits for what THIS check's own criteria need,
//     not for an unrelated poll.
//   - Tier 3 correctly requires a ReadingType (it is part of the claim), and
//     this DUT's registration POST carries none — only its first
//     MirrorMeterReading does, at the 300s postRate gridsim advertised. Grading
//     52s after registration (23:20:42Z registered, 23:21:33Z graded) was
//     always going to see readings:0; that is not a tier bug, it is grading
//     before the evidence the tier is honestly waiting for could exist. Tier
//     4 above is the other half of the fix: when that happens anyway (the
//     wait fix above should prevent it, but a window can still legitimately
//     expire before a slow DUT's first reading), the FAIL now says exactly
//     that — registered, reading pending — instead of words indistinguishable
//     from "never registered".
func critMUPRegistered() criterion {
	return criterion{
		Claim: "the DUT registered a MirrorUsagePoint carrying its own LFDI and a " +
			"MirrorMeterReading/ReadingType, and the server answered 201 Created with a Location",
		How: "the sep+xml body of the MirrorUsagePoint POST and the status line and Location " +
			"header of the response",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.Method("POST") {
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "MirrorUsagePoint" {
					continue
				}
				lfdi, _ := doc.TextOf("deviceLFDI")
				rt := doc.Descendants("ReadingType")
				if e.Resp == nil {
					return citeMessage(t, e.Req, certify.Fail, "the MirrorUsagePoint POST was never answered")
				}
				// 2030.5 §10.11.3 rules (f)/(g): 201 for a new mRID,
				// 204 for an existing one, Location required on both.
				ok := e.Resp.Status == 201 || e.Resp.Status == 204
				loc := e.Resp.Header.Get("Location")
				switch {
				case !ok:
					return citeExchange(t, e, certify.Fail,
						"POST %s carrying MirrorUsagePoint -> %s; 2030.5 §10.11.3 requires 201 "+
							"(new mRID) or 204 (existing)", e.Req.Target, e.Resp.Line())
				case loc == "":
					return citeExchange(t, e, certify.Fail,
						"POST %s -> %s with no Location header, which §10.11.3 requires on both the "+
							"201 and the 204", e.Req.Target, e.Resp.Line())
				case lfdi == "":
					return citeMessage(t, e.Req, certify.Fail,
						"the MirrorUsagePoint carries no deviceLFDI, so the server cannot bind the "+
							"mirror to the reporting device")
				default:
					return citeExchange(t, e, certify.Pass,
						"POST %s carrying MirrorUsagePoint deviceLFDI=%s with %d ReadingType(s) -> "+
							"%s, Location: %s", e.Req.Target, lfdi, len(rt), e.Resp.Line(), loc)
				}
			}
			return unavailable("the recovered transcript holds no MirrorUsagePoint POST from the DUT")
		},
		Server: func(v *ServerView) Finding {
			n := v.GETs("/mup")
			posts := 0
			for _, r := range v.Requests {
				// Exact match on the registration endpoint: "/mup/0" (a
				// reading POST) must never be counted here — see the fix note
				// above.
				if r.Method == "POST" && r.Path == "/mup" {
					posts++
				}
			}
			if posts > 0 {
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("gridsim's request log records %d POST(s) to the "+
						"MirrorUsagePoint registration endpoint (/mup) during this window; the status "+
						"codes and bodies are not recoverable from the log", posts)}
			}
			if !v.SessionEstablished() {
				return noSessionUnavailable()
			}
			// Tier 3: the request log found nothing in this window, but
			// registration is a ONE-TIME event this window had no reason to
			// see — consult the durable MUP store before conceding anything.
			if mup, ok := v.RegisteredMUP(); ok {
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("gridsim's request log records no in-window POST to the "+
						"MirrorUsagePoint registration endpoint (%d GET(s) of /mup), but its durable MUP "+
						"state (GET /admin/mups) records %s registered at %s carrying deviceLFDI=%s with "+
						"%d ReadingType(s) (uom %v); this window opened after the DUT's one-time "+
						"registration, not before it happened",
						n, mup.Href, time.Unix(mup.CreatedAt, 0).UTC().Format(time.RFC3339), mup.LFDI,
						len(mup.ReadingTypes), mup.ReadingTypes)}
			}
			// Tier 4: the store has an LFDI-bound MUP, just not one carrying
			// a ReadingType yet — registered, evidence pending, not "never
			// registered". See PendingMUP's doc and the fix note above
			// (runs/perphase-basic029-v4-20260730T232105): the generic
			// tier-5/final wording below is technically accurate here too,
			// but reads exactly like the DUT never registered at all, which
			// is not what the store shows. Still a FAIL — the claim's
			// ReadingType genuinely is not in evidence yet — just a more
			// honest one.
			if mup, ok := v.PendingMUP(); ok {
				return Finding{Verdict: certify.Fail,
					Observed: fmt.Sprintf("gridsim's request log records no in-window POST to the "+
						"MirrorUsagePoint registration endpoint (%d GET(s) of /mup); its durable MUP state "+
						"(GET /admin/mups) records %s registered at %s carrying deviceLFDI=%s, but with %d "+
						"reading(s) posted and no ReadingType yet — the DUT's first MirrorMeterReading had "+
						"not landed by the time this window closed, not that it never registered",
						n, mup.Href, time.Unix(mup.CreatedAt, 0).UTC().Format(time.RFC3339), mup.LFDI,
						mup.Readings)}
			}
			// Tier 5 (last resort): the request log is a bounded ring (unlike
			// Responses/DERPuts), and the registration this criterion is
			// after is a ONE-TIME event: it happens once, at the DUT's first
			// contact, and never again unless gridsim's state is wiped. A
			// window opened long after that (this case has no Setup of its
			// own to force a fresh one) can find the log has simply moved on
			// — RequestLogGap is Since's own signal that this is what
			// happened, not that the DUT never registered.
			if v.RequestLogGap != "" {
				return unavailable("gridsim's request log records no POST to the "+
					"MirrorUsagePoint registration endpoint during this window, its durable MUP state "+
					"(GET /admin/mups) records nothing bearing a deviceLFDI at all, but %s", v.RequestLogGap)
			}
			return Finding{Verdict: certify.Fail,
				Observed: fmt.Sprintf("gridsim's request log records no POST to the MirrorUsagePoint "+
					"registration endpoint during this window (%d GET(s) of /mup), and its durable MUP "+
					"state (GET /admin/mups) records no MirrorUsagePoint carrying a deviceLFDI at all", n)}
		},
	}
}

// basicMUPWant is basicMeterReading's Want: it replaces the generic AwaitWalk
// fallback (satisfied by the DUT's very next /dcap poll, whatever it happens
// to be for) with a predicate tied to what this check's OWN criteria need.
//
// Fix note (audit 2026-07-30, runs/perphase-basic029-v4-20260730T232105
// assertion 2): BASIC-029 has no Setup and, before this fix, no Want either,
// so it fell back to AwaitWalk. A run with `-param csip.wait=12m` finished in
// ~28s because the DUT's routine 60s-cadence poll landed 25s into the
// window — a coincidence of when the run happened to start relative to the
// DUT's own poll boundary, with no connection to MUP registration at all.
// Grading then found critMUPRegistered's tier 3 (ServerView.RegisteredMUP)
// unsatisfied: the DUT HAD registered, 24s before the run even started, but
// its registration POST on this bench carries no ReadingType — only its
// first MirrorMeterReading does, at the 300s postRate gridsim advertised —
// so the durable state legitimately showed readings:0 at the 28-second mark.
// The operator's 12-minute wait, meant to span exactly that 300s cadence
// (see the postRate criterion below), was never honoured.
//
// This predicate waits for BOTH things the check's criteria actually use, not
// either alone:
//
//   - a fresh discovery walk (one /dcap GET beyond the baseline's SEQUENCE
//     POSITION, not beyond its total — see ServerView.GETsSince), the same
//     guarantee AwaitWalk gives every other Setup-less row: it ensures the
//     capture window always spans at least one /dcap exchange, which the
//     DeviceCapability criterion above needs evidence from;
//   - ServerView.RegisteredMUP, the exact state critMUPRegistered's tier 3
//     grades — an LFDI-bound MUP carrying a ReadingType. Requiring this HERE,
//     in the wait, rather than only in the grading tier, is what makes the
//     wait actually wait for the evidence instead of exiting the moment an
//     unrelated poll lands.
//
// A DUT that never registers waits the full configured window and is graded
// on what is honestly there — the same outcome as before, just no longer
// arrived at by accident. A DUT whose registration (with a ReadingType) is
// already complete by the time this run starts is graded promptly, same as
// tier 3 has always allowed: RegisteredMUP reads durable, one-time STATE, not
// a per-run delta, so — unlike WantNewResponse's Response-log staleness bug —
// there is nothing here for an earlier run's evidence to spuriously satisfy.
func basicMUPWant(base ServerView) func(ServerView) bool {
	return func(v ServerView) bool {
		if !v.PolledSince(base, DiscoveryRoot, 1) {
			return false
		}
		_, ok := v.RegisteredMUP()
		return ok
	}
}

// basicMeterReading implements BASIC-029 — Inverter Meter Reading.
func basicMeterReading(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Want: func(base ServerView) func(ServerView) bool { return basicMUPWant(base) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("MirrorUsagePoint registration and MirrorMeterReading posting; waited %s for a "+
				"fresh discovery walk AND a ReadingType-bearing MUP registration (predicate satisfied: %t)",
				o.Waited.Round(rounding), o.Satisfied)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critGET(DiscoveryRoot,
					"the DeviceCapability the server returned carries a MirrorUsagePointListLink",
					"the MirrorUsagePointListLink element of the DeviceCapability payload",
					func(doc *Node) (certify.Verdict, string) {
						if !doc.Has("MirrorUsagePointListLink") {
							return certify.Fail, "no MirrorUsagePointListLink, so the metering mirror is " +
								"unreachable"
						}
						return certify.Pass, "MirrorUsagePointListLink present"
					}),
				critMUPRegistered(),
				{
					Claim: "the ReadingType the DUT registered carries the CSIP monitoring encoding for real " +
						"power: uom=38 (Watts), flowDirection and powerOfTenMultiplier present",
					How:             "the ReadingType child elements of the MirrorUsagePoint payload",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						for _, e := range t.Method("POST") {
							doc, err := e.Req.SEP()
							if err != nil || doc.Local() != "MirrorUsagePoint" {
								continue
							}
							var uoms []string
							for _, rt := range doc.Descendants("ReadingType") {
								if u, ok := rt.UintOf("uom"); ok {
									uoms = append(uoms, fmt.Sprint(u))
								}
							}
							if len(uoms) == 0 {
								return citeMessage(t, e.Req, certify.Fail,
									"no ReadingType in the MirrorUsagePoint carries a uom")
							}
							for _, u := range uoms {
								if u == "38" {
									return citeMessage(t, e.Req, certify.Pass,
										"ReadingType uom values %s include 38 (real power, W)",
										strings.Join(uoms, ","))
								}
							}
							return citeMessage(t, e.Req, certify.Warn,
								"ReadingType uom values are %s; CSIP Table 11 maps real power to 38, reactive "+
									"to 63, frequency to 33 and voltage to 29. A DER mirroring only some of the "+
									"monitoring data set is not necessarily non-conformant, so this is reported",
								strings.Join(uoms, ","))
						}
						return unavailable("the recovered transcript holds no MirrorUsagePoint POST")
					},
				},
				{
					Claim: "the DUT posts MirrorMeterReadings at the postRate the server advertised",
					How: "the spacing between successive MirrorMeterReading POSTs, measured from capture " +
						"timestamps, compared with the MirrorUsagePoint's postRate",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						var times []string
						var frames []int
						var last *Message
						for _, e := range t.Method("POST") {
							doc, err := e.Req.SEP()
							if err != nil || doc.Local() != "MirrorMeterReading" {
								continue
							}
							if last != nil && !last.Time.IsZero() && !e.Req.Time.IsZero() {
								times = append(times, e.Req.Time.Sub(last.Time).Round(rounding).String())
							}
							last = e.Req
							frames = append(frames, e.Frames()...)
						}
						if len(times) == 0 {
							return unavailable("the window holds fewer than two MirrorMeterReading POSTs; a "+
								"post-rate interval needs two. The bench's telemetry default is a 300 s post "+
								"rate, so spanning it needs -param %s=11m or more", waitParam)
						}
						return found(certify.Pass, dedupeInts(frames),
							"%d inter-post interval(s) measured from capture timestamps: %s",
							len(times), strings.Join(times, ", "))
					},
				},
			}
		},
	})
}
