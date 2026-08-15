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
	"sort"
	"strconv"
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
	// whether the DER's own account matches what THIS row commanded. Read
	// twice from the live phase (Setup, before the control is published, and
	// PostWait, after the DUT's poll cycle); criterion.Wire evaluators run
	// later against the recovered pcap transcript and have no live context of
	// their own, so the Findings are computed live and carried into the
	// citation phase via Observation.Params, the same mechanism an mRID or
	// other live-phase fact already uses.
	//
	// Populated only for BASIC-010/opModMaxLimW and BASIC-013/opModFixedW —
	// the rows §4.3 names whose axis the product genuinely executes as a
	// SCALAR. The curve-linked and refused-axis rows carry their own
	// apparatus below; only the fetch-only rows (BASIC-008/009) are left with
	// critDEREffectUnobservable's SKIP.
	Oracle *oracleBinding

	// Curve, when set, is a CURVE-linked row's apparatus (IW15-008, curve.go):
	// the breakpoints the row publishes and the SunSpec curve model those
	// breakpoints must be found adopted and enabled in. It replaces Publish
	// entirely — the publisher lives on the binding, because it and the oracle
	// must read the same points.
	Curve *curveBinding

	// Refusal, when set, is a REFUSED-axis row's apparatus (IW15-008,
	// curve.go): the axis the control names, the 704 points a write of it
	// would land on, and the control that names it. Its assertions are the
	// opposite of an execution oracle's — the DUT answered cannot-comply, and
	// the DER shows no trace — which is why it is a separate field and not an
	// Oracle with a negated judge.
	Refusal *refusalBinding

	// LegacyCurve, when set, REPLACES this row's apparatus with a curve
	// EXECUTION binding on a DER that serves the legacy 12x curve family.
	//
	// It exists for the one row whose CORRECT posture is a different KIND of
	// assertion per generation, not merely a different register bank.
	// opModWattPF has an exact register home on legacy (model 131) and none at
	// all on 7xx — 712 is DER Watt-Var, a different function — so the honest
	// question is "did the DER execute it?" on one bench and "did the DUT
	// refuse it honestly, and touch nothing?" on the other. A binding that
	// merely swapped the model would have asked the execution question on a
	// bench where a conformant DUT must refuse, which is the mirror image of
	// the substitution IW15-001 closed.
	//
	// Rows whose posture is the same kind on both generations do NOT use this:
	// they carry one Curve with both arms named (curveBinding's Model7xx /
	// ModelLegacy), and the oracle resolves the bank from the DER's chain.
	LegacyCurve *curveBinding
}

// forGeneration resolves the apparatus this row uses on the DER that was
// actually under test, from the generation the live phase recorded.
//
// It is a pure function of the observation because the citation phase has no
// live context and must not be able to reach a different answer than Setup did:
// the generation is read from the DER once, written into Params, and every
// later reader — Notes, Criteria, spec.Verdict — dispatches on that one record.
// A row with no per-generation split is returned unchanged, so nothing that
// does not declare LegacyCurve can be affected by this at all.
func (m controlMode) forGeneration(params map[string]string) controlMode {
	if m.LegacyCurve == nil || params == nil {
		return m
	}
	if params[curveGenParam] != string(invariant.FamilyLegacy) {
		return m
	}
	m.Refusal, m.Curve = nil, m.LegacyCurve
	return m
}

// forObservation is forGeneration over an Observation.
func (m controlMode) forObservation(o *Observation) controlMode {
	if o == nil {
		return m
	}
	return m.forGeneration(o.Params)
}

// measured reports whether this row has a southbound apparatus at all — the
// three shapes that read the DER's own registers and carry a live verdict
// (spec.Verdict) rather than resting on the capture.
func (m controlMode) measured() bool {
	return m.Oracle != nil || m.Curve != nil || m.Refusal != nil
}

// outcome is the ONE definition of a measured row's verdict, dispatched by
// which apparatus the row carries. Notes, the criterion and spec.Verdict all
// read it, so a bundle can never show the three disagreeing.
func (m controlMode) outcome(o *Observation) Finding {
	m = m.forObservation(o)
	switch {
	case m.Refusal != nil:
		return refusalOutcome(m.Refusal, o)
	case m.Curve != nil:
		return curveOutcome(o)
	default:
		return oracleOutcome(o)
	}
}

// oracleBinding is the apparatus an ORACLED inverter-control row carries beyond
// a plain one: the value it commands, the publisher that takes that value, and
// the oracle builder that judges that same value.
//
// The value is a field rather than a number written twice (IW14-003) for two
// reasons. The first is that the published control and the oracle that judges it
// must not be able to disagree about what was commanded — the pre-fix rows wrote
// 6000 into the ControlRequest and 6000 again into oracleMaxLimW(6000), two
// literals one edit apart from certifying a value nobody sent. The second is
// that an oracled row may have to establish a pre-state before it commands
// anything: a post-publication comparison against registers that already held
// the commanded value proves nothing (a rerun that never re-applied the control
// reads identical to one that did), and there are two different ways to fix
// that — see Prescribed and Ladder, which are alternatives and never both.
type oracleBinding struct {
	// Commanded is the catalog's own value for this row, in hundredths of a
	// percent (6000 = 60.00%).
	Commanded int64

	// Prescribed is the procedure's own DEFAULT value, which this row drives
	// the DER into — and VERIFIES in effect — before it commands Commanded.
	// Zero means the row prescribes no default.
	//
	// It exists because the ladder below is not admissible evidence for a row
	// whose procedure states its values (IW15-004). CSIP CTP v1.3 BASIC-013
	// Figure 13 prescribes a 50 % default and a 60 % test value; a run that
	// commanded 40 % instead — as the ladder let it — certified a transition
	// the procedure never asked for, and said so in its own report. With a
	// prescribed default the stale-register problem the ladder solved is
	// solved WITHOUT substituting values: the DER is put into the default the
	// procedure names, that landing is confirmed by this row's own oracle, and
	// the commanded value is then always exactly the catalog's.
	Prescribed int64

	// Ladder is the fixed set of alternates Setup may command instead of
	// Commanded when the DER already holds Commanded. Deterministic and
	// ordered: the first entry the DER provably does NOT already hold wins.
	//
	// It is for rows that do NOT prescribe a default. A row carrying both would
	// be able to depart from a procedure that told it what to send, so the two
	// are mutually exclusive by construction (scalarModeOracledDefaultFirst
	// leaves this nil) and by test.
	Ladder []int64

	// Publish puts this row's DERControl on the wire carrying `hundredths`.
	Publish func(ctx context.Context, d *Driver, mrid string, hundredths int64) error
	// PublishDefault puts the PRESCRIBED default on the wire, under its own
	// mRID and in a window that opens immediately and outlives the row's own
	// control (oracleDefaultWindow). Nil on a row with no prescribed default.
	PublishDefault func(ctx context.Context, d *Driver, mrid string, hundredths int64) error
	// Judge builds the oracle that reads the DER's own registers and decides
	// whether they hold `hundredths`.
	Judge func(hundredths int64) func(ctx context.Context, rc *certify.RunCtx) Finding
}

// oracleValueLadder is oracleBinding.Ladder's one definition: 40%, 45%, 50%,
// 55%, 60% of the DER's own WMax, in the hundredths-of-a-percent unit the wire
// uses. Every entry is separated from every other by far more than
// oracleTolerance on any nameplate this bench runs, and the list ENDS on the
// catalog's own 6000 so a row that needs no alternate and a row that exhausts
// the ladder both come to rest on the value the catalog states.
var oracleValueLadder = []int64{4000, 4500, 5000, 5500, 6000}

// alternate picks the first ladder value the DER provably does not already
// hold, judged by this row's OWN oracle so the comparison is the same one the
// post-publication read will make (oracleTolerance and all). A decided FAIL from
// the judge means "the DER does not hold this value by more than the tolerance
// the post-read will apply" — precisely the property an alternate needs. It
// returns that finding too, so the caller records the baseline it just proved
// instead of paying for a second read of the same registers. ok is false when no
// entry qualifies, which Setup reports rather than papering over.
func (b *oracleBinding) alternate(ctx context.Context, rc *certify.RunCtx, avoid int64) (int64, Finding, bool) {
	for _, v := range b.Ladder {
		if v == avoid {
			continue
		}
		if f := b.Judge(v)(ctx, rc); f.Verdict == certify.Fail {
			return v, f, true
		}
	}
	return 0, Finding{}, false
}

// publishable reports whether this bench can put the row's mode on the wire at
// all — through the plain publisher, the oracled value-taking one, or the
// curve/refusal bindings' own.
func (m controlMode) publishable() bool { return m.Publish != nil || m.measured() }

// oracleVerdictParam/oracleObservedParam/oracleUnavailableParam are the
// Observation.Params keys the POST-publication controlMode.Oracle result is
// carried through — PostWait (live) to Criteria (post-hoc), see
// controlMode.Oracle's doc.
//
// The oraclePre*/oracleCommanded/oracleNote keys carry what IW14-003 added: the
// reading taken BEFORE the control was published (without which a post-read that
// matches is not evidence that anything changed), the value this run actually
// commanded (which is the catalog's unless the pre-read forced a ladder
// alternate), and the prose explaining any departure. They are a distinct set of
// keys, never the post ones reused, so "the oracle must not fire in Setup"
// (TestInverterControlSpec_OracleFiresPostWaitNotSetup) stays a meaningful
// assertion about the POST read.
const (
	oracleVerdictParam     = "iw13.oracle_verdict"
	oracleObservedParam    = "iw13.oracle_observed"
	oracleUnavailableParam = "iw13.oracle_unavailable"

	oraclePreVerdictParam  = "iw14.oracle_pre_verdict"
	oraclePreObservedParam = "iw14.oracle_pre_observed"
	oracleCommandedParam   = "iw14.oracle_commanded"
	oracleNoteParam        = "iw14.oracle_note"

	// The PRESCRIBED-default step's own record (IW15-004): the value, the mRID
	// it was published under, how long the row waited for it to land, and what
	// the oracle saw when the wait ended. They are separate keys from the pre-
	// and post-read sets because they are a separate claim — "the DER was in
	// the procedure's stated default before the test value was commanded" —
	// and a bundle that could not distinguish it from the baseline read could
	// not show that the prescribed sequence was followed at all.
	oracleDefaultCommandedParam = "iw15.oracle_default_commanded"
	oracleDefaultMRIDParam      = "iw15.oracle_default_mrid"
	oracleDefaultWindowParam    = "iw15.oracle_default_window"
	oracleDefaultVerdictParam   = "iw15.oracle_default_verdict"
	oracleDefaultObservedParam  = "iw15.oracle_default_observed"
)

// defaultControlMRIDSuffix distinguishes the prescribed default's control from
// the row's own. The two must be separately addressable: gridsim treats a
// re-post of an existing mRID as an update-in-place, so publishing both under
// one mRID would REPLACE the default with the test value rather than layer the
// event over it — and, more to the point, every criterion in the row binds to
// the row's own mRID exactly (IW15-004), which the default must therefore not
// share.
const defaultControlMRIDSuffix = "-DEFAULT"

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
// overruns entirely. The harness never waits DurationS (it waits fetchWait), so
// a longer window costs no runtime — Cleanup clears the control when the row is
// done. The observed compliance FAIL was NOT this window expiring under the
// read; it was the read landing too EARLY (see oracleSettleWindow) — this
// widening is the belt to that fix's braces.
//
// The span it has to cover GREW with IW14-005: the settle poll now runs for up
// to the row's own poll-cycle window AFTER the wait, so the last read can land
// as late as wait + settle ≈ 2 x waitCap = 10m after Setup. A control that
// released at +360s would have expired under exactly the slow-bench read this
// widening exists to protect, converting the settle fix into a new false FAIL
// at the other edge. [+30s, +720s] contains the whole span with margin;
// TestOracledScalarWindow_ContainsEveryPostWaitRead pins the arithmetic against
// waitCap so a later change to either bound fails there rather than on a board.
var oracleWindow = scalarControlWindow{startOffsetS: 30, durationS: 690}

// oracleDefaultWindow is the window the PRESCRIBED default is published in
// (IW15-004 — oracleBinding.Prescribed).
//
// It opens at +0s, not +30s: Setup WAITS for this control to reach the DER's
// own registers before it publishes the row's real control, so every second of
// start offset is a second added to the row's critical path for nothing. It
// runs longer than the row's own control (oracleWindow closes at +720s) so the
// default is still standing when the event above it ends — the shape a
// DefaultDERControl would have, which is what CTP Figure 13 actually
// prescribes and what this bench's admin surface has no lever for.
var oracleDefaultWindow = scalarControlWindow{startOffsetS: 0, durationS: 900}

// scalarMode builds a controlMode driven by gridsim's scalar control API, with
// the default (fetch-only) window.
func scalarMode(element string, apply func(*ControlRequest)) controlMode {
	return scalarModeWindow(element, scalarWindow, apply)
}

// scalarModeOracled builds a scalar controlMode for a row whose DER register an
// independent oracle READS during PostWait (BASIC-010/013) — so its control
// must stay active across the oracle read (oracleWindow).
//
// Its apply takes the value the row is actually commanding, rather than closing
// over a literal: the commanded value is decided at run time (see
// oracleBinding), and the publisher must carry whatever Setup selected.
//
// This is the LADDER shape, for a row whose procedure does not prescribe a
// default to reset through. A row that does prescribe one takes
// scalarModeOracledDefaultFirst instead and carries no ladder at all.
func scalarModeOracled(element string, commanded int64, apply func(*ControlRequest, int64)) controlMode {
	// prescribed = 0, so the constructor leaves PublishDefault nil and the
	// ladder is this row's only way to avoid a vacuous comparison.
	m := scalarModeOracledDefaultFirst(element, 0, commanded, apply)
	m.Oracle.Ladder = oracleValueLadder
	return m
}

// scalarModeOracledDefaultFirst builds the oracled scalar row whose procedure
// states BOTH values: a default the DER must be driven into first, and the test
// value it is then commanded (CSIP CTP v1.3 BASIC-013 Figure 13 — default 5000,
// test value 6000).
//
// The two publishers differ only in the window. The default goes out under its
// own mRID in a window that opens IMMEDIATELY (the row has to wait for it to
// land, so thirty seconds of start offset is thirty seconds of nothing) and
// outlives the row's own control, so it sits underneath as the fallback the
// event supersedes — which is what a DefaultDERControl would do if this bench's
// admin surface exposed one. The row's own control is published second, so its
// creationTime is later and it takes precedence at equal primacy.
//
// prescribed == 0 means the row prescribes nothing, which is how scalarModeOracled
// reuses this constructor.
func scalarModeOracledDefaultFirst(element string, prescribed, commanded int64,
	apply func(*ControlRequest, int64)) controlMode {
	publishIn := func(win scalarControlWindow) func(context.Context, *Driver, string, int64) error {
		return func(ctx context.Context, d *Driver, mrid string, hundredths int64) error {
			req := scalarControlRequest(element, mrid, win)
			apply(&req, hundredths)
			_, err := d.PostControl(ctx, req)
			return err
		}
	}
	b := &oracleBinding{
		Commanded:  commanded,
		Prescribed: prescribed,
		Publish:    publishIn(oracleWindow),
	}
	if prescribed != 0 {
		b.PublishDefault = publishIn(oracleDefaultWindow)
	}
	return controlMode{Element: element, Oracle: b}
}

// scalarModeWindow is the body of scalarMode: a fetch-only scalar row, whose
// only variable is the window it publishes with.
func scalarModeWindow(element string, win scalarControlWindow, apply func(*ControlRequest)) controlMode {
	return controlMode{
		Element: element,
		Publish: func(ctx context.Context, d *Driver, mrid string) error {
			req := scalarControlRequest(element, mrid, win)
			apply(&req)
			_, err := d.PostControl(ctx, req)
			return err
		},
	}
}

// scalarControlRequest is the one definition of what a scalar inverter-control
// row publishes, shared by the fetch-only rows and the oracled ones so the two
// cannot drift apart in anything but the value and the window.
func scalarControlRequest(element, mrid string, win scalarControlWindow) ControlRequest {
	return ControlRequest{
		Program: 0, MRID: mrid, Description: "certify " + element,
		StartOffset: win.startOffsetS, DurationS: win.durationS,
	}
}

// curveMode builds a controlMode driven by gridsim's curve API, which is the
// only way a curve-linked mode reaches the DUT — with the independent
// southbound curve oracle (IW15-008, curve.go) attached.
//
// The oracle is not optional on these rows and there is no un-oracled variant
// left. Before IW15-008 a curve row published a curve, watched an
// <opModVoltVar> element appear in something the DUT fetched, and reported
// PASS: the DER's own registers were never read, and the row certified a
// product that refuses the axis outright. The binding below is what makes the
// row's second half a measurement — see curve.go's file doc for what that
// measurement can and cannot establish on a sim with no curve physics.
//
// model is the SunSpec curve model this mode's content must land in, and
// mapping states where that correspondence comes from, because a FAIL that
// names a register bank has to be checkable by whoever reads it.
// The binding is passed WHOLE rather than assembled from eight positional
// arguments. Its per-generation arms have to be readable at the row where they
// are declared — "opModWattPF lands on 131 and nowhere on 7xx" is the row's
// substance, not a parameter — and a positional constructor for a six-field
// target was the shape in which the 712 substitution hid.
func curveMode(element string, b *curveBinding) controlMode {
	return controlMode{Element: element, Curve: b}
}

// scalarModeRefused builds a row whose axis this product DELIBERATELY refuses
// (IW15-008): the control goes out under the row's own mRID, and the row then
// asserts the refusal was HONEST — a cannot-comply Response to the head end,
// and not one register of the axis moved on the DER.
//
// It carries the oracled window rather than the fetch-only one for the same
// reason the executing oracled rows do: the row reads the DER after the DUT's
// poll cycle and a control that released before that read would make the
// absence it observes meaningless.
func scalarModeRefused(element, axis, commanded, why string, points []string,
	apply func(*ControlRequest)) controlMode {
	return controlMode{
		Element: element,
		Refusal: &refusalBinding{
			Axis: axis, Points: points, Commanded: commanded, Why: why,
			Publish: func(ctx context.Context, d *Driver, mrid string) error {
				req := scalarControlRequest(element, mrid, oracleWindow)
				apply(&req)
				_, err := d.PostControl(ctx, req)
				return err
			},
		},
	}
}

// curveModeRefused builds a CURVE row whose axis this product DELIBERATELY
// refuses: the curve goes out exactly as an executing curve row's would, and
// the row then asserts the refusal was HONEST — a cannot-comply Response to the
// head end, and NOT ONE REGISTER of the mode's curve bank moved on the DER.
//
// It is curveMode's mirror, not a negation of it, for the reason
// scalarModeRefused's doc gives: a curve oracle asks "did the DER adopt what
// this row published?", and pointed at an axis the product correctly refuses it
// would FAIL every conformant DUT. The questions a refusal asks are different
// ones, and both must hold — a gateway that answers cannot-comply and adopts
// the curve anyway is lying to the head end; one that adopts nothing but
// reports Started is lying about execution.
//
// The published curve is REAL and well-formed on purpose. A malformed curve, or
// one whose href does not resolve, would also draw a refusal, and from outside
// the DUT the two look identical — so the row must publish a control that a DUT
// supporting the axis would have executed, through the same publisher the
// execution rows use. critDERCurveResolvable stays on the row for the same
// reason: it is what separates "refused the axis" from "never got the curve".
func curveModeRefused(element, axis, why string, b *curveBinding) controlMode {
	return controlMode{
		Element: element,
		Refusal: &refusalBinding{
			Axis: axis, Why: why,
			Commanded: fmt.Sprintf("a %s curve of %d breakpoint(s) linked from <%s>",
				b.Mode, len(b.Points), element),
			Curve: b,
		},
	}
}

// curveModePerGeneration builds a row that is a REFUSAL row on a 7xx DER and an
// EXECUTION row on a legacy 12x one.
//
// It is not a convenience: the two halves assert opposite things, and which is
// correct is a property of the device under test rather than of the catalog.
// Wiring one of them to both benches would either fail every conformant 7xx DUT
// (asking it to execute an axis with no register home) or certify every legacy
// one (asking it to refuse an axis it can perform), and the second is exactly
// the shape a bundle must never contain.
func curveModePerGeneration(element, axis, why string, refused, legacy *curveBinding) controlMode {
	m := curveModeRefused(element, axis, why, refused)
	m.LegacyCurve = legacy
	return m
}

// unreachableMode builds a controlMode for a mode this bench cannot publish.
func unreachableMode(element, why string) controlMode {
	return controlMode{Element: element, Unreachable: why}
}

// withOracle attaches an independent southbound register Oracle (IW13-001
// §4.3) to an already-built oracled controlMode — the combinator BASIC-010/013's
// rows use so scalarMode's own construction stays untouched for every other
// row.
//
// It takes the oracle BUILDER, not a built oracle: the value under test is the
// binding's (see oracleBinding), and an oracle built here against a literal
// could judge a value the row never published. It panics on a mode that carries
// no binding, which is a construction error a row cannot recover from and must
// never reach a campaign — the same posture registerAggregator already takes for
// a missing scenario.
func withOracle(m controlMode, judge func(hundredths int64) func(ctx context.Context, rc *certify.RunCtx) Finding) controlMode {
	if m.Oracle == nil {
		panic("suitecsip: withOracle on a mode built without scalarModeOracled — there is no commanded " +
			"value for the oracle to judge")
	}
	m.Oracle.Judge = judge
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
			m := m.forObservation(o)
			if m.Unreachable != "" {
				return "the control mode this row is about cannot be published by this bench: " + m.Unreachable
			}
			notes := fmt.Sprintf("published a DERControl (%s) carrying %s and waited %s for the DUT to "+
				"fetch it", mrid, m.Element, o.Waited.Round(rounding))
			// An oracled row's verdict can now come from the live phase alone
			// (spec.Verdict), so its REASON has to be printed somewhere the
			// citation phase cannot swallow. A run whose capture yielded no
			// session mints a SkipAssertion for every criterion, this row's
			// included, and a FAIL whose only explanation lived in that
			// assertion would read as unexplained (IW14-003).
			if m.measured() {
				notes += "; " + oracleNotes(m, o)
			}
			return notes
		},
		Criteria: func(o *Observation) []criterion {
			// The apparatus this row used depends on which DER generation the
			// live phase found (forGeneration). Resolving it HERE, from the
			// record Setup left, is what keeps the criteria, the notes and the
			// verdict from being able to describe three different rows.
			m := m.forObservation(o)
			crits := []criterion{critDiscoveryRoot(), critProgramList(0)}
			if m.Unreachable != "" {
				// IW15-008: a decided FAIL, not the Skip this used to be. See
				// critModeUnauthorable for why an untested row must not roll up
				// as a passing one.
				crits = append(crits, critModeUnauthorable(subject, m.Element, m.Unreachable))
			} else {
				// Bound to THIS row's own mRID, and — where the row knows the
				// scalar it commanded — to that exact value and sign
				// (IW15-004). An unrelated control carrying the same mode, from
				// another row or another session's smoke test, must not satisfy
				// anything here; see critDERControlCarriesModeFrom for the
				// assertion that did.
				crits = append(crits, critDERControlCarriesModeFrom(m.Element,
					"the DUT fetched a DERControl carrying "+subject, o.Param("mrid"), commandedOnWire(m, o)))
			}
			crits = append(crits, critDefaultDERControl())
			switch {
			case m.Unreachable != "":
				crits = append(crits, critEffectBlockedByAuthoringGap(subject, m.Element))
			case m.Refusal != nil:
				// A CURVE refusal keeps the resolvability check an execution
				// curve row carries. Without it a bench-side 404 on the curve
				// href would produce the same southbound silence a genuine
				// refusal does, and the row would certify the DUT for something
				// the bench caused (see critDERCurveResolvable).
				if m.Refusal.Curve != nil {
					crits = append(crits, critDERCurveResolvable(curveHrefOf(o)))
				}
				// Two assertions, because a refusal has two halves and either
				// alone lets the other's defect through: what the DUT told the
				// head end, and what it did to the device.
				crits = append(crits, critRefusalAnswered(o.Param("mrid")),
					critRefusedAxisNoSouthboundTrace(m.Refusal, o))
			case m.Curve != nil:
				crits = append(crits, critDERCurveResolvable(curveHrefOf(o)),
					critDEREffectViaCurveOracle(subject, m.Curve, o))
			case m.Oracle != nil:
				crits = append(crits, critDEREffectViaSouthboundOracle(subject, o))
			default:
				crits = append(crits, critDEREffectUnobservable(subject))
			}
			return crits
		},
	}
	if m.Unreachable != "" {
		// The authoring gap decides this row whether or not the capture yielded
		// a session — the same reason spec.Verdict exists for the oracled rows.
		// A criterion cannot carry a verdict past a run with no transcript
		// (criterion.assert reaches Wire only when one was recovered), and this
		// row's whole finding is that nothing was tested.
		s.Verdict = func(*Observation) certify.Verdict { return certify.Fail }
	}
	if m.publishable() {
		s.RequiresGridSim = true
		s.Setup = func(ctx context.Context, d *Driver, params map[string]string) error {
			params["mrid"] = mrid
			// Which generation this DER belongs to has to be settled BEFORE the
			// apparatus is chosen, and it is a question only the device can
			// answer. A row with no per-generation split skips the read
			// entirely, so no existing row pays for this.
			if m.LegacyCurve != nil {
				params[curveGenParam] = detectCurveGeneration(ctx, d.rc)
			}
			m := m.forGeneration(params)
			switch {
			case m.Curve != nil:
				return curveSetup(ctx, d, params, m.Curve, mrid)
			case m.Refusal != nil:
				return refusalSetup(ctx, d, params, m.Refusal, mrid)
			case m.Oracle != nil:
				return oracledSetup(ctx, d, params, m.Oracle, mrid)
			default:
				return m.Publish(ctx, d, mrid)
			}
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
		if m.measured() {
			// The settle poll spends a second poll-cycle window on a row that
			// is not satisfied at once, so the budget arithmetic has to know
			// (IW14-005 — spec.SettlePoll, waitSlots).
			s.SettlePoll = true
			s.PostWait = func(ctx context.Context, d *Driver, params map[string]string) error {
				m := m.forGeneration(params)
				// settleOracle, not a bare judge call: AwaitWalk returns at
				// the START of the DUT's walk, so the control the DUT is
				// fetching may not have reached the DER's own registers yet
				// (IW13-005 — see oracleSettleWindow). Poll until it has, or
				// until the settle deadline turns a persistent mismatch into
				// the FAIL it deserves.
				//
				// The deadline is the row's OWN poll-cycle window, not a fixed
				// 15s: the southbound write follows the modbus reconciler's
				// tick rather than the DUT's fetch, and a window sized for the
				// fetch alone decides rows on where that tick happened to fall
				// (IW14-005 — oracleSettleDeadline, and the three measured
				// latencies in oracleSettleWindow's doc).
				//
				// The value judged is the one Setup actually COMMANDED, read
				// back from params — not the catalog's, which Setup may have
				// departed from when the DER already held it (IW14-003).
				//
				// A REFUSAL row settles the other way round (settleRefusal):
				// an absence observed early is worth nothing, so it polls the
				// whole window and returns early only on a landing caught in
				// the act.
				var f Finding
				switch {
				case m.Refusal != nil:
					judge := oracleRefusal(m.Refusal, params[refusalBaselineParam])
					f = settleRefusal(ctx, oracleSettleDeadline(params), oracleSettleStep,
						func() Finding { return judge(ctx, d.rc) })
				case m.Curve != nil:
					judge := oracleCurve(m.Curve)
					f = settleOracle(ctx, oracleSettleDeadline(params),
						func() Finding { return judge(ctx, d.rc) })
				default:
					judge := m.Oracle.Judge(commandedValue(params, m.Oracle))
					f = settleOracle(ctx, oracleSettleDeadline(params),
						func() Finding { return judge(ctx, d.rc) })
				}
				switch {
				case f.Unavailable != "":
					params[oracleUnavailableParam] = f.Unavailable
				default:
					params[oracleVerdictParam] = string(f.Verdict)
					params[oracleObservedParam] = f.Observed
				}
				// Nothing here is fatal to the check (check.go's PostWait
				// contract: a returned error is logged and the run continues,
				// exactly like Setup/Change already treat their own bench-lever
				// failures as evidence rather than grounds to abandon the run).
				// An oracle that could not decide is no longer waved through
				// either: oracleOutcome turns every shape it can leave behind —
				// including this Unavailable — into a decided verdict.
				return nil
			}
			// A MEASURED row's verdict does not depend on the capture
			// (IW14-003 — see spec.Verdict). Declared for measured rows ONLY;
			// every other row leaves s.Verdict nil and is byte-identical to
			// what it was.
			s.Verdict = func(o *Observation) certify.Verdict {
				if f := m.outcome(o); f.Verdict != certify.Pass {
					return f.Verdict
				}
				// A satisfied oracle declares nothing: the wire criteria decide
				// this row, exactly as they did before. Declaring PASS here
				// would let a row with NO recovered session pass on the
				// southbound read alone, which is the opposite mistake.
				return ""
			}
		}
		s.Cleanup = func(ctx context.Context, d *Driver) {
			_ = d.ClearControls(ctx, m.Program)
			_ = d.ClearCurves(ctx, m.Program)
			// This clears the CSIP-side control/curve, not the DER's own
			// southbound registers — this bench still exposes no lever to
			// reset those (modsim's /control takes pause/resume/reset, and
			// its "reset" only resumes the animation, sim/modsim/main.go;
			// /registers is GET-only; /inject writes the M123 WMaxLimPct the
			// oracle does not read). The old note here called the residual
			// risk "bounded, not ignored" and left it there: a row could
			// false-PASS against its OWN prior run's identical value on a
			// rerun that never re-applied the control. That reasoning is
			// retired (IW14-003). A stale register is no longer waved through
			// with prose, because the row no longer depends on Cleanup to
			// have cleared anything:
			//
			//   - Setup READS the DER before it publishes (oracledSetup) and
			//     records that reading. The post-publication read is evidence
			//     only against that baseline — a TRANSITION — never on its own.
			//   - When the baseline already satisfies the value this row was
			//     about to command, the row commands a ladder alternate the
			//     DER provably does not hold (oracleBinding.alternate), so the
			//     post-read has something to move TO.
			//   - When neither holds — no baseline, or no alternate available
			//     — oracleOutcome says so in a decided verdict naming both
			//     readings, rather than reporting a PASS it cannot support.
			//
			// A register-clear lever would still be the cleaner instrument and
			// is still not in this suite's gift to add; what changed is that
			// its absence can no longer manufacture a PASS.
		}
	}
	return s
}

// commandedOnWire is the exact value this row's control must be seen carrying,
// or nil when the row cannot state one as a single integer (IW15-004).
//
// Only the ORACLED rows can: their value is the one thing the row already
// carries as a number (oracleBinding), and it is read back from the params
// Setup wrote rather than from the binding, so a run that departed from the
// catalog's value is graded against what it actually sent. Every other
// inverter-control row publishes a structure — a boolean connect, a nested
// power factor, a scaled ActivePower — that no single integer describes, so it
// binds its mRID and stops there.
func commandedOnWire(m controlMode, o *Observation) *int64 {
	if m.Oracle == nil {
		return nil
	}
	v := commandedValue(o.Params, m.Oracle)
	return &v
}

// oracledSetup is the ORACLED rows' Setup (BASIC-010/013): read the DER's own
// registers BEFORE publishing anything, decide which value this run can actually
// prove something with, then publish THAT value.
//
// The pre-read is what makes the post-read evidence (IW14-003). "The DER holds
// 60% of its WMax after the control was published" is a fact about the DER, not
// about the DUT, until it is paired with "and it did not hold 60% before": a
// rerun against registers a previous run left behind reads exactly like a run in
// which the DUT genuinely fetched and applied the control, and this bench has no
// register-clear lever to tell the two apart (see the Cleanup note above). So
// the row establishes its own baseline, and where the baseline would make the
// comparison vacuous it commands something else.
func oracledSetup(ctx context.Context, d *Driver, params map[string]string, b *oracleBinding, mrid string) error {
	if b.Prescribed != 0 {
		return prescribedSetup(ctx, d, params, b, mrid)
	}
	want := b.Commanded
	pre := b.Judge(want)(ctx, d.rc)
	if pre.Verdict == certify.Pass {
		// The DER ALREADY holds what the catalog asks this row to command, so
		// a post-publication match would be satisfied by the DUT doing nothing
		// at all. Command a value it demonstrably does not hold instead.
		if alt, altPre, ok := b.alternate(ctx, d.rc, want); ok {
			params[oracleNoteParam] = fmt.Sprintf("the DER's own registers ALREADY held the catalog's "+
				"commanded %s before this row published anything, which would have made the "+
				"post-publication reading no evidence at all; this row therefore commanded %s instead "+
				"— the first ladder alternate the DER provably did not hold — and judges THAT value. "+
				"The departure from the catalog's stated value is deliberate: it is what makes this "+
				"row's PASS mean 'the DUT moved the DER', not 'the DER was already there'",
				pctString(want), pctString(alt))
			want, pre = alt, altPre
		} else {
			params[oracleNoteParam] = fmt.Sprintf("the DER already held the catalog's commanded %s AND "+
				"every alternate on the ladder (%s) was either unreadable or already held, so no value "+
				"exists this run could have commanded and then observed the DER MOVE to. The row "+
				"published the catalog's value anyway (the wire criteria are still worth collecting), "+
				"but its southbound reading cannot be evidence of anything and is reported as such",
				pctString(want), pctList(b.Ladder))
		}
	}
	params[oracleCommandedParam] = strconv.FormatInt(want, 10)
	params[oraclePreVerdictParam] = string(pre.Verdict)
	params[oraclePreObservedParam] = findingObserved(pre)
	return b.Publish(ctx, d, mrid, want)
}

// prescribedSetup is the Setup of a row whose procedure states its values
// (IW15-004 — BASIC-013): drive the DER into the PRESCRIBED default, wait until
// this row's own oracle confirms the default LANDED, then publish exactly the
// catalog's test value. No substitution, ever.
//
// Why this replaces the ladder for such a row. The ladder existed to stop a
// stale register from manufacturing a PASS: if the DER already held what the row
// was about to command, the row commanded something else instead so the
// post-read had somewhere to move to. That solved the evidence problem by
// breaking the procedure — the 2026-08-14 report says in as many words that it
// sent 40 % where the catalog states 60 %, which is a conformance claim about a
// test that was not run. The prescribed default solves the SAME problem the way
// the procedure intends: a stale 60 % is reset THROUGH the 50 % default, so the
// commanded value never has to move.
//
// The default's landing is verified, not assumed. An unverified default would
// leave the row's baseline unknown — exactly the hole the pre-read closed — and
// a run whose default never landed would silently degrade into "the DER held 60 %
// afterwards", which is the reading that started all of this. The verdict of
// that wait is recorded and oracleOutcome FAILS the row on it (see
// prescribedDefaultShortfall): a prescribed sequence that was not followed
// cannot certify the transition it is about.
func prescribedSetup(ctx context.Context, d *Driver, params map[string]string, b *oracleBinding,
	mrid string) error {
	def, defMRID := b.Prescribed, mrid+defaultControlMRIDSuffix
	params[oracleDefaultCommandedParam] = strconv.FormatInt(def, 10)
	params[oracleDefaultMRIDParam] = defMRID

	if b.PublishDefault == nil {
		return fmt.Errorf("suitecsip: %s prescribes a %s default but carries no publisher for it", mrid,
			pctString(def))
	}
	if err := b.PublishDefault(ctx, d, defMRID, def); err != nil {
		return fmt.Errorf("publish the prescribed %s default as %s: %w", pctString(def), defMRID, err)
	}

	window := prescribedDefaultDeadline(ctx, d.rc, params)
	params[oracleDefaultWindowParam] = window.String()
	landed := settleOracle(ctx, window, func() Finding { return b.Judge(def)(ctx, d.rc) })
	params[oracleDefaultVerdictParam] = string(landed.Verdict)
	params[oracleDefaultObservedParam] = findingObserved(landed)

	// The baseline for the row's OWN value is taken AFTER the default landed,
	// so "the DER did not hold 60% before" is a statement about the DER in the
	// procedure's stated starting state rather than in whatever state the
	// previous row left it.
	want := b.Commanded
	pre := b.Judge(want)(ctx, d.rc)
	params[oracleCommandedParam] = strconv.FormatInt(want, 10)
	params[oraclePreVerdictParam] = string(pre.Verdict)
	params[oraclePreObservedParam] = findingObserved(pre)
	params[oracleNoteParam] = fmt.Sprintf("this row followed the procedure's stated sequence: it published a "+
		"%s DEFAULT under its own mRID (%s), waited up to %s for that default to reach the DER's own "+
		"registers (%s: %s), and then commanded EXACTLY the catalog's %s under this row's mRID (%s). No "+
		"ladder alternate is available to it and none was used — a row whose procedure states its values "+
		"certifies those values or nothing",
		pctString(def), defMRID, window, landed.Verdict, findingObserved(landed), pctString(want), mrid)
	return b.Publish(ctx, d, mrid, want)
}

// prescribedDefaultDeadline is how long prescribedSetup waits for the default
// to reach the DER's registers: the same poll-cycle window this row will give
// the DUT to fetch its real control, because it is the same journey — a fetch
// plus the DUT's southbound write.
//
// params is consulted first. run() does not fill pollWindowParam until AFTER
// Setup, so in a campaign this is always the derived value; a caller that
// already has a window (a test, or a later phase driving Setup directly) can
// supply one and keep a unit test from spending a real poll cycle.
//
// The derivation is capped at half of whatever is left of the check's own
// -timeout, so a bench whose default never lands cannot consume the budget the
// row needs for the control it is actually about.
func prescribedDefaultDeadline(ctx context.Context, rc *certify.RunCtx, params map[string]string) time.Duration {
	if d, err := time.ParseDuration(params[pollWindowParam]); err == nil && d > 0 {
		return d
	}
	wait, _ := pollCycleWait(ctx, rc)
	if left := deadlineRemaining(ctx); left > 0 && wait > left/2 {
		wait = left / 2
	}
	if wait <= 0 {
		wait = oracleSettleWindow
	}
	return wait
}

// commandedValue reads back the value Setup actually commanded, falling back to
// the catalog's when the param is absent or unparseable — the value the binding
// would have published if nothing intervened, so a lost param degrades to the
// pre-IW14-003 behaviour rather than to a judgment of a value nobody sent.
func commandedValue(params map[string]string, b *oracleBinding) int64 {
	if v, err := strconv.ParseInt(params[oracleCommandedParam], 10, 64); err == nil {
		return v
	}
	return b.Commanded
}

// findingObserved renders what a finding SAW, for either shape it can carry.
func findingObserved(f Finding) string {
	if f.Unavailable != "" {
		return "the reading could not be taken: " + f.Unavailable
	}
	return f.Observed
}

// pctString renders a hundredths-of-a-percent wire value the way the rows talk
// about it; pctList does the same for the ladder.
func pctString(hundredths int64) string { return fmt.Sprintf("%.2f%%", float64(hundredths)/100) }

func pctList(hundredths []int64) string {
	parts := make([]string, 0, len(hundredths))
	for _, v := range hundredths {
		parts = append(parts, pctString(v))
	}
	return strings.Join(parts, ", ")
}

// oracleOutcome collapses everything the live phase recorded about an oracled
// row into ONE decided verdict. It is the single definition both the criterion
// (critDEREffectViaSouthboundOracle) and the case verdict (spec.Verdict) read,
// so a bundle can never show the two disagreeing.
//
// Every branch decides. Before IW14-003 two of them did not: an oracle that
// could not reach the DER became the criterion's Skip, and a params map with
// neither key set produced Finding{Verdict: ""}. Both were structurally
// incapable of denting the case verdict — Skip is the LOWEST severity there is
// (bundle.Verdict.Severity) and every roll-up in the runner raises only — so the
// only check that can catch a southbound units or actuation bug could be
// silenced by the bench being misconfigured, which is exactly the failure mode
// the a78887f campaign's two-hour run hit. "We could not test it" must never
// read like "it passed": unavailability is a bench fact to FIX, not a criterion
// a release is allowed to skip past.
func oracleOutcome(o *Observation) Finding {
	post := o.Params[oracleObservedParam]
	pre := o.Params[oraclePreObservedParam]
	preVerdict := certify.Verdict(o.Params[oraclePreVerdictParam])

	if reason := o.Params[oracleUnavailableParam]; reason != "" {
		return Finding{Verdict: certify.Fail, Observed: "the independent southbound oracle could not read " +
			"the DER at all: " + reason + " — and an oracle that cannot read the DER cannot certify that " +
			"the commanded control took effect. This row FAILs on that unavailability rather than skipping " +
			"past it: the southbound read is the ONLY check in this suite that can catch a units or " +
			"actuation defect the DUT's own self-report would repeat back to us"}
	}
	switch verdict := certify.Verdict(o.Params[oracleVerdictParam]); {
	case verdict == "":
		return Finding{Verdict: certify.Fail, Observed: "the live phase left no southbound oracle result " +
			"behind at all — neither a verdict (" + oracleVerdictParam + ") nor a reason it could not " +
			"reach one (" + oracleUnavailableParam + ") is recorded, so the oracle either never ran or " +
			"its result was lost. An unrecorded criterion is not a satisfied one"}
	case verdict != certify.Pass:
		if post == "" {
			post = "the oracle recorded no observation with its " + string(verdict)
		}
		return Finding{Verdict: verdict, Observed: post}
	}
	// The post-publication read matched. On its own that is a fact about the
	// DER; it becomes a fact about the DUT only against the baseline Setup took
	// — and, on a row whose procedure prescribes a starting state, only if the
	// DER was actually IN that state first.
	if f, ok := prescribedDefaultShortfall(o); ok {
		return f
	}
	switch preVerdict {
	case certify.Fail:
		return Finding{Verdict: certify.Pass, Observed: "the DER did NOT hold the commanded value before " +
			"this row published its control (" + pre + ") and DOES hold it after the DUT's poll cycle (" +
			post + ") — the reading MOVED, so the match is evidence this control was applied, not a " +
			"register an earlier run left behind" + prescribedDefaultCredit(o)}
	case certify.Pass:
		return Finding{Verdict: certify.Fail, Observed: "the DER holds the commanded value (" + post +
			") but ALREADY held it before this row published anything (" + pre + "), and no ladder " +
			"alternate it did not already hold was available to command instead. Nothing in this reading " +
			"distinguishes a control the DUT fetched and applied from a stale register left over from an " +
			"earlier run, so it is not reported as a PASS"}
	default:
		return Finding{Verdict: certify.Warn, Observed: "the DER holds the commanded value (" + post +
			"), but the pre-publication baseline was not recovered (" + orText(pre, "no reading was "+
			"recorded") + "), so this run cannot show that the reading MOVED. The value is right; that " +
			"it was THIS row's control that put it there is not established"}
	}
}

// prescribedDefaultShortfall is the verdict of the PRESCRIBED-default step, for
// a row that has one, and it is a decided FAIL whenever that step did not
// finish (IW15-004).
//
// ok is false for every row that prescribes no default — i.e. every row but
// BASIC-013 — so nothing else in the suite changes shape.
//
// Why a post-read that MATCHES can still fail here: this row's claim is not
// "the DER holds 60 %", it is "the DUT moved this DER from the procedure's
// prescribed 50 % default to the commanded 60 %". If the default never landed,
// the starting state is unknown, and a DER that was ALREADY at 60 % (the
// previous run's register, an unrelated control, a local default) reads exactly
// the same as one the DUT just moved. That is the reading the 2026-08-14 report
// presented as a PASS. Reporting the shortfall as anything softer than a FAIL
// would leave the row certifying a transition nobody observed.
func prescribedDefaultShortfall(o *Observation) (Finding, bool) {
	want := o.Params[oracleDefaultCommandedParam]
	if want == "" {
		return Finding{}, false
	}
	if certify.Verdict(o.Params[oracleDefaultVerdictParam]) == certify.Pass {
		return Finding{}, false
	}
	observed := orText(o.Params[oracleDefaultObservedParam], "no reading was recorded")
	return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
		"this row's procedure prescribes that the DER be put into a %s DEFAULT before the test value is "+
			"commanded, and that default was NOT confirmed to reach the DER's own registers within %s "+
			"(published as %s; the oracle's last reading was %s). The DER may hold the commanded value now, "+
			"but with the prescribed starting state unestablished nothing distinguishes a DER the DUT MOVED "+
			"from one that was already there — which is exactly the reading this row must not certify",
		pctFromParam(want), orText(o.Params[oracleDefaultWindowParam], "the settle window"),
		orText(o.Params[oracleDefaultMRIDParam], "a separate mRID"), observed)}, true
}

// prescribedDefaultCredit is the sentence a PASS on such a row adds: the
// transition it certifies is the one the procedure states, from the value the
// procedure states. Empty for a row with no prescribed default.
func prescribedDefaultCredit(o *Observation) string {
	want := o.Params[oracleDefaultCommandedParam]
	if want == "" || certify.Verdict(o.Params[oracleDefaultVerdictParam]) != certify.Pass {
		return ""
	}
	return fmt.Sprintf(". The starting state was the procedure's own: the DER was first driven into its "+
		"prescribed %s default and that default was CONFIRMED in the DER's own registers (%s) before the "+
		"commanded value was published, so the transition this row certifies is the one the procedure "+
		"prescribes", pctFromParam(want), o.Params[oracleDefaultObservedParam])
}

// pctFromParam renders a hundredths-of-a-percent value carried in params, and
// falls back to the raw string rather than inventing a number when it cannot be
// parsed — a prose field must never quietly print a different value from the
// one the live phase recorded.
func pctFromParam(v string) string {
	if h, err := strconv.ParseInt(v, 10, 64); err == nil {
		return pctString(h)
	}
	return v
}

// orText is the fallback for a prose field the live phase may not have filled.
func orText(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// oracleNotes renders a MEASURED row's southbound half for the bundle's own
// prose line, so the reason for its verdict is printed on the case whether or
// not the citation phase recovered a session to hang an assertion on.
func oracleNotes(m controlMode, o *Observation) string {
	f := m.outcome(o)
	notes := "independent southbound oracle: " + string(f.Verdict) + " — " + f.Observed
	for _, n := range []string{o.Params[oracleNoteParam], o.Params[curveMRIDNoteParam]} {
		if n != "" {
			notes += "; " + n
		}
	}
	return notes
}

// curveHrefOf is the DERCurve resource path a curve row's control links, for
// the criterion that asks whether the DUT could actually fetch it.
//
// gridsim mints the href itself (sim/gridsim/curve.go: /derp/{program}/dc/{i},
// and Activate:true — which every curve row here sends — replaces the list so
// the new curve is always index 0). The path is derived rather than plumbed
// back through the admin response because the criterion needs a SUFFIX to match
// a fetched target against, not an identity: a DUT fetching it will have
// resolved it against the server's own base.
func curveHrefOf(o *Observation) string {
	if h := o.Param(curveHrefParam); h != "" {
		return h
	}
	return "/derp/0/dc/0"
}

// critDEREffectUnobservable is the SKIP the inverter-control rows used to carry
// for their southbound half, and after IW15-008 only TWO rows still reach it:
//
//	BASIC-008 (opModFixedPFInjectW) — an axis this product refuses with the
//	advanced overlay dark (ModeFixedPFInjectW is in AdvancedSupportedAxes only),
//	so it is the same shape BASIC-014 now measures with a refusal oracle; and
//
//	BASIC-009 (opModConnect) — an axis this product genuinely EXECUTES, whose
//	southbound landing (the device's connect/enter-service state) this suite
//	reads no register for.
//
// Both are therefore rows that can still roll up PASS without measuring
// anything, by the mechanism this file's other criteria were rewritten to
// close: Skip is severity 0 and every roll-up raises only. They are named here
// rather than quietly left, because the next person to read this function
// should be able to see the remaining hole without re-deriving it — and closing
// them is a fixed amount of work each (a refusal binding for BASIC-008, a
// connect-state oracle for BASIC-009), not a redesign.
//
// It is left as a Skip for now for one reason: this criterion is also the honest
// answer wherever the DER's ELECTRICAL response really is the subject, and
// turning it into a blanket FAIL would make that claim dishonest in the other
// direction. The rows above need oracles, not a severity change.
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
// for BASIC-010/013 (IW13-001 §4.3): the Findings were already computed live —
// once before the control was published and once after the DUT's poll cycle —
// by controlMode.Oracle, reading the DER's own raw 704 register image through
// internal/invariant, independently of anything csipmodel/derbase decoded. This
// criterion's Wire evaluator does not touch the recovered pcap transcript at
// all; it reports the verdict oracleOutcome derives from what those reads left
// in Observation.Params. Unlike critDEREffectUnobservable, this criterion is a
// REAL PASS/FAIL: a units bug in the shared decode path can no longer
// self-certify by having the only check that would catch it always SKIP.
//
// It carries NO Skip path (IW14-003). Every shape the live phase can leave
// behind — an unreachable oracle, an empty params map, a post-read that matches
// a register that already matched — comes back from oracleOutcome as a decided
// verdict, because a Skip here cannot dent the case verdict and so cannot hold a
// release. Its Tier says where the answer came from: the DER's own registers,
// read live, NOT the "cleartext TLS handshake in the capture" every other Wire
// criterion is stamped with and this one was mislabelled as.
func critDEREffectViaSouthboundOracle(subject string, o *Observation) criterion {
	claim := "the DER's own southbound registers hold the value " + subject + " commanded"
	how := "an independent read of the DER's raw SunSpec 704 image (internal/invariant, which shares only " +
		"the register-offset tables with the product and none of its CSIP/derbase interpretation), taken " +
		"BEFORE this row published its control and again after the DUT's poll cycle, and compared against " +
		"the value this row itself commanded — not against what the DUT reports the DER received"
	f := oracleOutcome(o)
	return criterion{
		Claim: claim,
		How:   how,
		Tier:  tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
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
// (Pass) or the settle window elapses, returning the LAST finding at the
// deadline. A genuine, persistent mismatch (wrong register, wrong value) never
// reaches Pass and still FAILs at the deadline with the value it read; the
// oracled control's active window (oracleWindow) is far longer than this settle,
// so nothing the poll observes is the control expiring.
//
// Only a Pass short-circuits. Everything else is retried, INCLUDING an
// Unavailable (IW14-003): "the DER reports no enabled WSet/WSetPct in its own
// 704 image" is not a fact about reachability at all, it is the not-yet-enabled
// shape — precisely the mid-propagation state this poll exists to wait out — and
// returning it at once meant the one shape most in need of the window was the
// one shape that never got it. A transport-level Unavailable (the sidecar is
// down) now costs the full window before it is reported, and buys correctness on
// the bench that is merely slow.
//
// HOW LONG the poll runs is no longer this constant (IW14-005). The 15s fixed
// window was sized against ONE observation — a write that landed ~1s after the
// walk began — and the bench then produced the other end of the distribution
// twice in one night, because the southbound write does not follow the DUT's
// fetch, it follows the modbus reconciler's OWN ~10s tick:
//
//	06:38:35.8 walk -> 06:38:49.0 applied (13.2s: PASS with 1.8s to spare)
//	07:04:15.1 walk -> 07:04:35.5 applied (20.3s: FAIL, 5.3s past the deadline)
//	07:05:15.7 walk -> 07:05:16.2 applied ( 0.5s: PASS immediately)
//
// Same board, same build, same control value, three different latencies: where
// the DUT's fetch happens to fall inside the reconciler's tick decides the row.
// A 15s deadline was therefore a coin toss dressed as a measurement — the exact
// mistake defaultWait's own doc records for the poll-cycle wait (check.go).
//
// So the deadline is now the row's OWN poll-cycle window (oracleSettleDeadline
// -> pollWindowParam), the value run() already derived from the DUT's cadence
// and already prints in every bundle. That is a stated reason rather than a
// guess, and it costs nothing on a healthy bench: a Pass still returns on the
// first read that matches. Only a row that is genuinely failing, or a bench that
// is genuinely broken, burns the window — and both of those are worth the wait,
// because the alternative is reporting a verdict about the DUT that is really a
// verdict about a tick boundary. This constant survives as the FALLBACK for a
// PostWait driven without run()'s params (a unit test), where a multi-minute
// deadline would be nothing but a slow test.
const (
	oracleSettleWindow = 15 * time.Second
	oracleSettleStep   = 1 * time.Second
)

// oracleSettleDeadline is how long the PostWait oracle polls the DER: the row's
// own poll-cycle window, recovered from the params run() filled, falling back to
// oracleSettleWindow when there is none to recover (see that constant's doc).
func oracleSettleDeadline(params map[string]string) time.Duration {
	if d, err := time.ParseDuration(params[pollWindowParam]); err == nil && d > 0 {
		return d
	}
	return oracleSettleWindow
}

// settleOracle re-evaluates eval until it PASSES or the settle window elapses.
// See oracleSettleWindow for why the oracled rows read through it, and
// oracleSettleDeadline for where window comes from.
func settleOracle(ctx context.Context, window time.Duration, eval func() Finding) Finding {
	return settleOracleWindow(ctx, window, oracleSettleStep, eval)
}

// settleOracleWindow is settleOracle's parameterized core, split out so a test
// can drive the deadline path in milliseconds instead of the production window.
// A Pass returns at once; every other outcome — a decided Fail and an
// Unavailable alike — is retried until the deadline, which then returns the last
// finding taken (see oracleSettleWindow for why Unavailable belongs in that set).
func settleOracleWindow(ctx context.Context, window, step time.Duration, eval func() Finding) Finding {
	deadline := time.Now().Add(window)
	for {
		f := eval()
		if f.Verdict == certify.Pass || !time.Now().Before(deadline) {
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
		return noEnabledAxis("WMaxLimPct", wantPct, base.Name, base.Q.Val, wantW, uv)
	}
}

// noEnabledAxis is the terminal both effect-based oracles reach when the DER's
// own 704 image carries no ENABLED command on the axis the row commanded.
//
// It is a decided FAIL, not an Unavailable (IW14-003). "No enabled WMaxLimPct"
// is a statement about what the DER holds — the same class of statement as "it
// holds the wrong value" — and the row's whole claim is that the commanded
// control reached the DER's registers. Reporting it as Unavailable made the
// commonest real failure (the DUT never actuated the axis at all) indistinguish-
// able from the bench being unplugged, and routed it into a criterion Skip that
// could not affect the verdict. Because it is now a decided non-Pass, the settle
// poll also RETRIES it, which is what the not-yet-enabled shape needed all along:
// a DER mid-propagation reports exactly this until the write lands.
// baseName names the rating the percent was resolved against — "WMax" for the
// ceiling axis, the direction's own rate rating for the signed setpoint axis
// (IW14-001/F5) — because the two are no longer the same number and a message
// that hardcoded "WMax" would misreport which reference the row applied.
func noEnabledAxis(axis string, wantPct float64, baseName string, baseW, wantW float64,
	uv invariant.UnitView) Finding {
	return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
		"the DER reports NO enabled %s in its own 704 image, so nothing there holds the commanded "+
			"%.2f%% of its own %.1f W %s (= %.1f W); its 704 setpoints read: %s",
		axis, wantPct, baseW, baseName, wantW, commandSummary(uv))}
}

// commandSummary renders what the DER's own 704 image actually held, so a FAIL
// on a missing axis names the registers it read instead of only the one it
// wanted.
//
// It prints the RAW register value first and always (IW14-004). The pre-fix
// version branched on c.Physical.Known() — but invariant.UnitView.Commands
// returns DECODED commands, never resolved ones, so Physical was the zero
// Quantity on every point; Known() is true for a zero (only NaN/Inf are
// unknown), and the branch therefore printed a bare "0" for the whole image.
// The 2026-08-14 ece6499 bundle carries the damage verbatim — "WMaxLimPct=0
// (enabled)" for a register that was holding 60.00%, a 4800 W cap the DER's own
// measured output had converged on. A FAIL whose "here is what I read" line
// reads zero for every point is worse than one that omits it, because it
// invents a second, false defect for whoever reads the bundle. Resolution is
// done HERE, against the DER's own nameplate, and the physical value is shown
// beside the raw one when the two are in different units.
func commandSummary(uv invariant.UnitView) string {
	cmds := uv.Commands(oracleSimName)
	if len(cmds) == 0 {
		return "no commanded setpoints at all"
	}
	np := uv.Nameplate(oracleSimName)
	meas := uv.Measurement(oracleSimName)
	parts := make([]string, 0, len(cmds))
	for _, c := range cmds {
		state := "disabled"
		if c.Enabled {
			state = "enabled"
		}
		r := invariant.ResolveCommand(c, np, meas)
		switch {
		case r.Unresolved != "":
			parts = append(parts, fmt.Sprintf("%s=%s raw, unresolved: %s (%s)", c.Point, c.Raw, r.Unresolved, state))
		case r.Physical.Known() && r.Physical.Unit != c.Raw.Unit:
			parts = append(parts, fmt.Sprintf("%s=%s = %s (%s)", c.Point, c.Raw, r.Physical, state))
		default:
			parts = append(parts, fmt.Sprintf("%s=%s (%s)", c.Point, c.Raw, state))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// oracleFixedW builds a BASIC-013 (opModFixedW) Oracle. It accepts exactly ONE
// actuation and nothing else: a SETPOINT — an enabled WSet/WSetPct holding the
// commanded percent of THIS SAME DER's own PER-SIGN active-power rate reference
// (invariant.RefWRteMax — the charge points when the command is negative, the
// discharge points when it is positive, each resolved SETTING-FIRST, with the
// nameplate standing in where the device declares neither).
//
// ── opModFixedW is a SETPOINT; WMaxLimPct can never satisfy it (IW15-001) ───
//
// This function briefly accepted a second "actuation": for a non-negative
// command, an enabled WMaxLimPct holding the commanded percent — the product's
// solar fold, admitted here as PICS-documented behaviour. That acceptance was
// MINE and it was wrong, and it is deleted rather than narrowed.
//
// The two are different IEEE 2030.5 functions with different registers and
// different meanings, and the schema says so in its own words
// (sep-2.0.4.xsd): opModFixedW "specifies a requested charge or discharge mode
// SETPOINT", while opModMaxLimW "sets the MAXIMUM active power GENERATION
// LEVEL". A setpoint says produce this; a ceiling says do not exceed this. They
// coincide only in the single case where the device happens to be able to
// produce its ceiling and chooses to — under any cloud, at night, on a
// curtailing inverter, or on any device that can absorb, a ceiling permits
// every output at or below itself, including zero, and therefore carries no
// commanded value at all. An oracle that accepts the ceiling cannot tell a
// gateway that EXECUTED the setpoint from one that silently substituted a
// different function for it, which is precisely the substitution the review
// found: BASIC-013's own PASS rested on WMaxLimPct while nothing whatever had
// been written to the set-active-power register.
//
// The register layer already refuses honestly — derbase.preflightActuationWatts
// requires M704 and a FIXED_W CtrlModes claim before it will write a setpoint,
// and answers CannotComply otherwise — so a DER that genuinely cannot take a
// setpoint produces an honest refusal upstream, not a ceiling that has to be
// re-read as one down here. A referee's job is to say what the device holds,
// and the answer to "does the DER hold the commanded setpoint?" on a device
// carrying only a ceiling is NO.
//
// So an enabled WMaxLimPct is now REPORTED (fixedWCeilingRefusal) and never
// accepted: the FAIL names both registers, and both numbers, so a reader can
// see exactly what the gateway did instead of what was asked.
//
// It resolved BOTH signs against WMax until IW14-001/F5. That was not a
// simplification, it was a defect with two heads on any device whose charge
// and discharge ratings differ — which is every storage device the bench
// serves since the pack's ratings became asymmetric (WMax 5000 W, cha 2000 W,
// dis 4500 W): a CORRECT gateway commanded −60.00% writes −1200 W and was
// reported "not applied" against a wanted −3000 W, while a gateway that
// resolved the percent against the nameplate really did write −3000 W and
// read as applied. The oracle mirrors what derbase's fixedWReference actually
// does (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §2.1), which is what
// "mirrors the product's own reference" was always supposed to mean;
// invariant.Nameplate.wRteMax carries the rule, its settings-first resolution
// (IW15-002) and its three-way unimplemented / positive / declared-incapable
// outcome.
func oracleFixedW(wantHundredths int64) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		np := uv.Nameplate(oracleSimName)
		if !np.Present {
			return unavailable("the DER serves no M702, so it declares neither a rate rating nor a WMax to " +
				"resolve the commanded percent against")
		}
		meas := uv.Measurement(oracleSimName)
		wantPct := float64(wantHundredths) / 100.0
		base, err := np.Base(invariant.RefWRteMax, signOfPct(wantPct), meas)
		if err != nil {
			return unavailable("cannot resolve the reference the commanded %.2f%% is a percentage of: %v",
				wantPct, err)
		}
		wantW := wantPct / 100 * base.Q.Val
		alt := fixedWAltReference(np, base, wantPct)
		for _, c := range uv.Commands(oracleSimName) {
			if (c.Point != "WSet" && c.Point != "WSetPct") || !c.Enabled {
				continue
			}
			r := invariant.ResolveCommand(c, np, meas)
			if !r.Physical.Known() || r.Physical.Unit != invariant.UnitWatt {
				continue
			}
			gotW := r.Physical.Val
			observed := fmt.Sprintf("the DER actuated this command as a SETPOINT: its own %s resolves to "+
				"%.1f W (commanded %.2f%% of its own %s = %.1f W, so %.1f W)",
				c.Point, gotW, wantPct, base.Name, base.Q.Val, wantW)
			if math.Abs(gotW-wantW) <= oracleTolerance(wantW, 1) {
				return Finding{Verdict: certify.Pass, Observed: observed}
			}
			return Finding{Verdict: certify.Fail, Observed: observed + alt}
		}
		// No setpoint actuation anywhere in the DER's own 704 image. That is the
		// whole answer to this row's question, whatever else the device may be
		// holding — but WHAT else it holds is worth printing, because the
		// commonest wrong implementation writes the ceiling instead (IW15-001).
		f := noEnabledAxis(fixedWAxisLabel(), wantPct, base.Name, base.Q.Val, wantW, uv)
		f.Observed += fixedWCeilingRefusal(uv, np, meas, wantPct)
		return f
	}
}

// fixedWAxisLabel names the ONE actuation a FixedW row accepts, for the FAIL
// that found it absent. It takes no sign: after IW15-001 the answer is the same
// on both — a maximum-generation limit is not an actuation of a setpoint in
// either direction, and offering it as one in the FAIL text would tell a reader
// this row might have been satisfied some other way.
func fixedWAxisLabel() string { return "WSet/WSetPct setpoint" }

// fixedWCeilingRefusal is the diagnostic clause a FixedW FAIL carries when the
// DER's own WMaxLimPct IS enabled: it names both registers, and both numbers,
// and says why the ceiling did not and cannot satisfy this row.
//
// Empty when no enabled, readable ceiling is present, so the FAIL never
// mentions a register the DER was not holding.
//
// This is the diagnostic half of deleting the fold. The gateway shape it
// describes is real and was observed on the bench: the board wrote an enabled
// WMaxLimPct at exactly the commanded percent and nothing at all to WSet. A
// bare "no enabled WSet/WSetPct" would send a reader looking for a write that
// never happened; naming the ceiling says what the gateway did INSTEAD, which
// is the actionable finding.
func fixedWCeilingRefusal(uv invariant.UnitView, np invariant.Nameplate, meas invariant.Measurement,
	wantPct float64) string {
	for _, c := range uv.Commands(oracleSimName) {
		if c.Point != "WMaxLimPct" || !c.Enabled {
			continue
		}
		if !c.Raw.Known() || c.Raw.Unit != invariant.UnitPercent {
			continue
		}
		clause := fmt.Sprintf(". The DER's own WMaxLimPct IS enabled, at %.2f%%%s, and it was NOT considered "+
			"an acceptable actuation of this command: WMaxLimPct is opModMaxLimW's register — a MAXIMUM "+
			"GENERATION LIMIT — while opModFixedW is a SETPOINT and is actuated on WSet/WSetPct. A ceiling "+
			"permits every output at or below itself, zero included, so it carries no commanded value: it "+
			"cannot express the %.2f%% this row commanded (IW15-001)", c.Raw.Val,
			ceilingWatts(c, np, meas), wantPct)
		if wantPct < 0 {
			clause += ", and less still on a NEGATIVE (charging) command, where a maximum-GENERATION limit " +
				"says nothing whatever about charging"
		}
		return clause
	}
	return ""
}

// ceilingWatts renders the physical cap an enabled WMaxLimPct imposes, as a
// trailing clause for a finding that mentions one — empty when the DER's own
// nameplate cannot resolve it, so the finding never invents a watts figure it
// could not derive.
//
// Its callers are the ceiling ORACLE (where the cap is the subject) and
// fixedWCeilingRefusal (where it is the evidence that the gateway wrote the
// wrong function's register); in neither case does printing the cap imply the
// row accepted it.
func ceilingWatts(c invariant.Command, np invariant.Nameplate, meas invariant.Measurement) string {
	r := invariant.ResolveCommand(c, np, meas)
	if !r.Physical.Known() || r.Physical.Unit != invariant.UnitWatt {
		return ""
	}
	nameplate, err := np.Base(invariant.RefWMax, 1, meas)
	if err != nil {
		return fmt.Sprintf(", a %.1f W cap", r.Physical.Val)
	}
	return fmt.Sprintf(", a %.1f W cap on its own %.1f W %s", r.Physical.Val, nameplate.Q.Val, nameplate.Name)
}

// signOfPct is the direction a signed percent commands: −1 charge/import,
// +1 discharge/export. Zero counts as positive, matching derbase's own
// `ctrl.OpModFixedW.Value < 0` test — a zero setpoint resolves to zero watts
// against either reference, so the choice cannot change a verdict.
func signOfPct(pct float64) int {
	if pct < 0 {
		return -1
	}
	return 1
}

// fixedWAltReference is the diagnostic half of a FixedW FAIL: when the base
// the percent was resolved against is NOT the nameplate, it names the
// nameplate and the watts the same percent would have produced there.
//
// That sentence is what makes the FAIL actionable rather than merely negative.
// The commonest wrong implementation of a signed percent setpoint is to
// resolve it against WMax for both signs, and its signature is precisely "the
// DER holds the number this line quotes" — so the report names both references
// and lets the reader see which one the writer used, instead of printing one
// expected number and leaving the diagnosis to whoever opens the register map.
func fixedWAltReference(np invariant.Nameplate, base invariant.LimitRef, wantPct float64) string {
	if strings.HasPrefix(base.Name, "WMax") {
		return ""
	}
	nameplate, err := np.Base(invariant.RefWMax, 1, invariant.Measurement{})
	if err != nil {
		return ""
	}
	return fmt.Sprintf(". Its nameplate %s is %.1f W, against which the same %.2f%% would be %.1f W: a DER "+
		"holding THAT value would mean the commanded percent was resolved against the nameplate instead of "+
		"the direction's own rate rating", nameplate.Name, nameplate.Q.Val, wantPct, wantPct/100*nameplate.Q.Val)
}

// oracleTargetW builds an opModTargetW Oracle: genuinely independent
// watts-to-watts, no percent conversion on this axis at all (§1.1 —
// opModTargetW was already correct, ActivePower/watts) — the DER's own
// resolved WSet (watts mode) compared directly against the commanded
// value×10^multiplier.
//
// STILL DELIBERATELY NOT WIRED to BASIC-014, and IW15-008 settled what that row
// carries instead. opModTargetW is REFUSED by this product (supported.go's
// ScalarSupportedAxes has no ModeTargetW), so a correctly-behaving DUT never
// writes the commanded value southbound at all: this function's "the DER holds
// the commanded value" assertion would FAIL every conformant DUT, exactly
// backwards from BASIC-010/013's oracles, which test axes the product genuinely
// executes. IW13 left it here as "groundwork for a future 'the refusal left no
// southbound trace' oracle"; that oracle now exists (curve.go's refusalBinding
// and oracleRefusal), and it is NOT this function inverted — it fingerprints the
// whole axis and compares two readings for ANY movement, which catches the
// half-executions a single "does it hold the commanded number" comparison
// cannot see.
//
// What keeps this function alive is the case IW13 built it for and this product
// is not: a DUT that DOES execute opModTargetW. Grading that DUT needs exactly
// this comparison, and rebuilding it later from an empty file would repeat the
// units reasoning §1.1 already settled once.
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
