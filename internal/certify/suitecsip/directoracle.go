package suitecsip

// directoracle.go — the southbound oracle for rows whose commanded content is a
// STRUCTURE, not a scalar.
//
// ── The gap this closes ─────────────────────────────────────────────────────
//
// basic.go's oracleBinding grades a row by carrying ONE int64: the value the
// row commands, published from that field and judged against that same field so
// the two cannot disagree. That shape fits BASIC-010's ceiling and BASIC-013's
// setpoint exactly, and fits nothing else — as commandedOnWire's own doc says,
// "every other inverter-control row publishes a structure — a boolean connect,
// a nested power factor, a scaled ActivePower — that no single integer
// describes".
//
// So the two rows that publish a structure, BASIC-008 (a nested power factor
// with an excitation flag) and BASIC-009 (a pair of booleans), were left with
// critDEREffectUnobservable's hard SKIP — and a SKIP is severity 0 in the
// roll-up while every roll-up raises only, so "nobody measured whether the DER
// did it" reported the same verdict as "it did it". That is the IW15-008 shape
// the curve rows were rescued from, still in place on the two rows nobody had a
// binding shape for.
//
// ── The dead oracle ─────────────────────────────────────────────────────────
//
// For BASIC-008 the gap was sharper than that, and worth stating plainly. The
// oracle already existed. fixedpf_oracle.go's gradeFixedPFDirection is a
// complete, independently-derived, fully-tested grader for exactly this row's
// content — magnitude AND direction, with the 2018 p.258 negation performed
// once and cited — written in response to a real product inversion. It had NO
// PRODUCTION CALLER. A referee that has built the instrument, proved the
// instrument, and never pointed it at the device is in a worse position than
// one that never built it, because the bundle's reader has no way to tell.
//
// ── What a direct oracle is ────────────────────────────────────────────────
//
// A closure that reads the DER's own register image and returns a Finding, plus
// the two sentences a verdict needs (which axis, what was commanded). It reuses
// EVERYTHING the scalar oracle already has: the pre-publication baseline read,
// the PostWait settle poll, the oracleVerdict/oracleObserved params, and
// oracleOutcome's collapse into one decided verdict. The only thing it does not
// reuse is the value ladder, because a structure has no ladder.
//
// It is deliberately NOT a generalisation of oracleBinding. Merging them would
// mean one type where half the fields are meaningless on any given row, and the
// value-in-one-place property that oracleBinding exists to enforce would become
// advisory.

import (
	"context"
	"fmt"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// directOracle is the apparatus for a structured-content row.
type directOracle struct {
	// Axis is the IEEE 2030.5 element this row commands, for the criterion's
	// prose.
	Axis string
	// Commanded describes what the row published, in the row's own terms —
	// prose rather than a number, which is the whole reason this shape exists.
	Commanded string
	// Registers names WHERE the answer is read from, per generation, so a
	// verdict that cites a register bank is checkable by whoever reads the
	// bundle. Same obligation the curve bindings' Mapping7xx/MappingLegacy
	// carry.
	Registers string
	// Judge reads the DER's own register image and grades it.
	//
	// It takes the UnitView rather than a RunCtx so it is a pure function of a
	// reading — testable against a fixture image with no bench, and unable to
	// reach for a second, different observation half way through a comparison.
	Judge func(uv invariant.UnitView) Finding
}

// judgeWith turns a directOracle into the closure the live phase drives,
// reading the DER through the same internal/invariant path every other oracle
// in this suite uses.
func (d *directOracle) judgeWith(ctx context.Context, rc *certify.RunCtx) Finding {
	uv, err := oracleUnitView(ctx, rc, oracleSimName)
	if err != nil {
		return unavailable("%v", err)
	}
	return d.Judge(uv)
}

// directMode builds a row driven by an ordinary scalar control request whose
// southbound half is graded by a directOracle.
//
// The publisher is scalarMode's — the control on the wire is exactly what it
// always was — so adopting this shape on a row changes what is MEASURED and
// not what is SENT. That separation is deliberate: a row that changed both at
// once could not tell an oracle finding from a publication change.
func directMode(element string, d *directOracle, apply func(*ControlRequest)) controlMode {
	m := scalarMode(element, apply)
	m.Direct = d
	return m
}

// directSetup is oracledSetup's sibling: read the DER BEFORE the control is
// published, record that reading, then publish.
//
// The baseline is not decoration. A post-publication reading that matches is
// evidence only against a reading that did NOT — a TRANSITION — because a DER
// that already held this content proves nothing about the control just sent.
// oracleOutcome reads both and says so; see its doc for the shapes.
func directSetup(ctx context.Context, d *Driver, params map[string]string, o *directOracle,
	publish func(ctx context.Context, d *Driver, mrid string) error, mrid string) error {
	pre := o.judgeWith(ctx, d.rc)
	params[oraclePreVerdictParam] = string(pre.Verdict)
	params[oraclePreObservedParam] = findingObserved(pre)
	if publish == nil {
		return fmt.Errorf("suitecsip: %s carries a direct oracle and no publisher", o.Axis)
	}
	return publish(ctx, d, mrid)
}

// critDEREffectViaDirectOracle is critDEREffectViaSouthboundOracle's sibling for
// a structured-content row: the same no-Skip posture, the same params, and a How
// that names the registers THIS row's content lands in rather than 704's scalar
// setpoints.
func critDEREffectViaDirectOracle(subject string, o *directOracle, obs *Observation) criterion {
	f := oracleOutcome(obs)
	return criterion{
		Claim: "the DER's own southbound registers hold the " + subject + " this row commanded",
		How: "an independent read of the DER's raw SunSpec register image (internal/invariant, which " +
			"shares only the register-offset tables with the product and none of its CSIP/derbase " +
			"interpretation), taken BEFORE this row published its control and again after the DUT's poll " +
			"cycle, and compared against what this row itself published — not against what the DUT " +
			"reports the DER received. " + o.Registers,
		LoadBearing: true,
		Tier:        tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}

// ── BASIC-008: the fixed power factor, magnitude AND direction ─────────────

// oracleFixedPFInject grades BASIC-008 against the DER's own model 704.
//
// It is a thin wrapper over gradeFixedPFDirection, and thin is the point: the
// grading logic, the 2018 p.258 negation and the whole argument for why
// direction is half of a power factor live in fixedpf_oracle.go, derived
// independently of the product. This function's only job is to get the DER's
// register image into it.
//
// THE COMMANDED VALUE COMES FROM THE ROW, not from a literal here: figure8FixedPF
// is the same variable BASIC-008's ControlRequest publishes, so the published
// control and the oracle that judges it read one statement. Passing it in is
// what stops the pair drifting the way the pre-IW14-003 scalar rows did, where
// 6000 was written into the request and 6000 again into the oracle.
func oracleFixedPFInject(want FixedPFSettings) *directOracle {
	return &directOracle{
		Axis: "opModFixedPFInjectW",
		Commanded: fmt.Sprintf("a displacement power factor of %s while INJECTING, with excitation=%t "+
			"(IEEE Std 2030.5-2018 p.258: %q)", trimNum(want.PF()), want.Excitation, excitationSentence),
		Registers: "The registers are model 704's inject-direction fixed-PF sync group — PFWInjEna, " +
			"PFWInj_PF and PFWInj_Ext — and all three are read, because a power factor is a magnitude AND " +
			"a direction and a referee that compared only the magnitude would pass a DER pointing the " +
			"opposite way (fixedpf_oracle.go).",
		Judge: func(uv invariant.UnitView) Finding {
			regs := uv.Regs[704]
			if len(regs) == 0 {
				return unavailable("the DER serves no model 704, so its fixed-PF sync group has no " +
					"register for this row to read; on a legacy 12x DER the axis lands on M123 OutPFSet " +
					"instead, which this row does not yet grade")
			}
			return gradeFixedPFDirection(fixedPFInjectAxis, want, sunspec.Parse704(regs), fixedPFTolerance)
		},
	}
}

// fixedPFTolerance is the slack the PF magnitude comparison allows.
//
// A power factor is dimensionless and bounded to [-1,1], so the percentage
// shape oracleTolerance uses for a watts value is the wrong instrument here —
// one percent of 0.9 is 0.009, which is nine times the smallest step model
// 704's own PF register can express at the sim's scale factor. This is the
// register's own quantisation with a margin, not a number chosen to make a row
// pass: 704's PF points are uint16 at PF_SF, and at the conventional -3 that is
// a step of 0.001.
const fixedPFTolerance = 0.0015

// ── BASIC-009: connect and energize, on whichever generation is present ────

// oracleConnect grades BASIC-009's pair of booleans against whichever register
// the DER under test actually has for them.
//
// ── The two axes have HOMES ON OPPOSITE GENERATIONS, and that is the row ────
//
// opModConnect's register home is model 123's Conn point, and model 123 is a
// LEGACY model: a 7xx DER does not serve it, and the 7xx family declares no
// connect register anywhere. opModEnergize's home is model 703's ES
// (enter-service permission) point, and 703 is a 7xx model with no legacy
// counterpart at all. So on either bench exactly ONE of this row's two axes has
// somewhere to be observed, and the other has none.
//
// That is the same shape BASIC-012 carries for its curve and droop halves, and
// it is handled the same way: measure the half this DER can hold, and NAME the
// half it cannot, on every verdict, so a PASS is never read as covering both.
// The alternative — grading only the axis that happens to be measurable and
// staying quiet about the other — is the overclaim this suite's whole
// unmappable-element mechanism exists to prevent.
//
// derbase agrees about both homes and is cited as corroboration rather than as
// the authority: its connect plan writes model 123's Conn
// (derbase.SetConnectPlan -> newM123ConnPlan) and its enter-service path writes
// 703, and lexa-gw's own supported.go names them "opModConnect (M123 Conn)" and
// "opModEnergize (model 703 enter service)" for the same reason.
func oracleConnect(wantConnect, wantEnergize bool) *directOracle {
	return &directOracle{
		Axis:      "opModConnect / opModEnergize",
		Commanded: fmt.Sprintf("connect=%t and energize=%t", wantConnect, wantEnergize),
		Registers: "opModConnect's register home is model 123's Conn point — a LEGACY model, read here " +
			"through this referee's own transcription of the published model (internal/invariant's " +
			"legacyctl.go), not through the product's — and opModEnergize's is model 703's ES " +
			"enter-service permission, which only the 7xx generation serves. Exactly one of the two has " +
			"a register on any given DER, and the verdict names the other rather than passing over it.",
		Judge: func(uv invariant.UnitView) Finding {
			var measured, unmeasurable []string
			verdict := certify.Pass

			// ── opModEnergize -> model 703 ES ──
			if regs := uv.Regs[703]; len(regs) > 0 {
				es := sunspec.Parse703(regs)
				measured = append(measured, fmt.Sprintf("model 703 ES (enter-service permission) reads "+
					"%t against a commanded energize=%t", es.Enabled, wantEnergize))
				if es.Enabled != wantEnergize {
					verdict = certify.Fail
				}
			} else {
				unmeasurable = append(unmeasurable, "opModEnergize: this DER serves no model 703, so its "+
					"enter-service permission has no register here — the legacy 12x family declares no "+
					"enter-service model at all, so on a legacy DER this axis is unobservable by "+
					"construction rather than unmeasured by omission")
			}

			// ── opModConnect -> model 123 Conn ──
			lc := uv.LegacyCommands(oracleSimName)
			switch {
			case !lc.Present:
				unmeasurable = append(unmeasurable, "opModConnect: this DER serves no model 123, which is "+
					"the ONLY register home either SunSpec generation gives a connect command — the 7xx "+
					"family declares no connect register anywhere — so on a 7xx DER this axis is "+
					"unobservable by construction")
			default:
				got, ok := connectState(lc)
				if !ok {
					verdict = certify.Fail
					measured = append(measured, "model 123's Conn point could not be read as a connect "+
						"state ("+lc.Note+")")
					break
				}
				measured = append(measured, fmt.Sprintf("model 123 Conn reads %t against a commanded "+
					"connect=%t", got, wantConnect))
				if got != wantConnect {
					verdict = certify.Fail
				}
				if d := invariant.DescribeM123Divergence(); d != "" {
					unmeasurable = append(unmeasurable, "TRANSCRIPTION: "+d)
				}
			}

			// ── The DER's own CONNECTION STATUS, reported and NOT graded ──
			//
			// Model 701's ConnSt is the device's own account of whether it is
			// connected. It is the closest thing a 7xx DER has to an observable
			// of opModConnect's EFFECT, and it is deliberately corroboration
			// rather than a criterion.
			//
			// Grading it would assert an effect this product may have no path
			// to produce on this device: opModConnect executes through model
			// 123's Conn register (lexa-gw's supported.go names it exactly so),
			// a 7xx solar DER serves no model 123, and a row that FAILED such a
			// device for not disconnecting would be blaming it for a register
			// it does not have. Reporting it costs nothing and gives whoever
			// reads the verdict the fact that actually answers "did the machine
			// go off" — the question behind the row, and one a pure
			// control-register reading cannot reach on this generation.
			if meas := uv.Measurement(oracleSimName); meas.Present {
				measured = append(measured, fmt.Sprintf("the DER's own model 701 ConnSt reads %d — its "+
					"account of its connection state, REPORTED and not graded: opModConnect executes "+
					"through model 123's Conn, this DER may have no path to it, and a verdict resting on "+
					"this would blame a device for a register it does not serve", meas.ConnSt))
			}

			if len(measured) == 0 {
				// Both axes unobservable, and no model 701 to report the
				// device's own connection state either. That is a decided FAIL
				// and not an Unavailable: the row's whole subject is what the
				// DER holds, and a DER serving none of these registers cannot
				// support the claim. Reporting it as unavailable would route it
				// into a Skip that cannot dent the verdict, which is the shape
				// this file exists to remove.
				return Finding{Verdict: certify.Fail, Observed: "NEITHER of this row's two axes has a " +
					"register on this DER, and it serves no model 701 to report its own connection " +
					"state either: " + joinSemis(unmeasurable)}
			}
			obs := joinSemis(measured)
			if len(unmeasurable) > 0 {
				obs += ". NOT ASSERTED: " + joinSemis(unmeasurable)
			}
			return Finding{Verdict: verdict, Observed: obs}
		},
	}
}

// connectState reads model 123's Conn point out of a legacy control reading as
// a boolean, or reports that it could not be.
//
// It goes through the decoded Command rather than indexing the raw block, so
// the not-implemented sentinel (0xFFFF) stays a non-answer instead of decoding
// as "connected" — which is what a bare `regs[off] != 0` would make of it.
func connectState(lc invariant.LegacyControls) (bool, bool) {
	for _, c := range lc.Commands {
		if c.Point != invariant.PointM123Conn {
			continue
		}
		if c.Unresolved != "" || !c.Raw.Known() {
			return false, false
		}
		return c.Raw.Val != 0, true
	}
	return false, false
}

func joinSemis(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out
}
