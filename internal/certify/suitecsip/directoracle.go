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
	"strings"

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
	// It is nil exactly when JudgeCtx is set.
	Judge func(uv invariant.UnitView) Finding

	// JudgeCtx is the manifest-aware alternative to Judge, for the one row whose
	// grading depends on what the CANDIDATE declares and not only on the
	// register reading: BASIC-009's connect axis is graded against the model the
	// candidate declares as its connect home (M123), and reporting-not-grading
	// the model it does not claim (M703 enter-service) reads the manifest to say
	// so. When set, judgeWith calls this and Judge is left nil; BASIC-008 keeps
	// its pure Judge, so the purity property holds everywhere it can.
	JudgeCtx func(uv invariant.UnitView, rc *certify.RunCtx) Finding

	// ConnectHome, when non-empty, marks this as the CONNECT row and names the
	// model its connect axis is graded against ("M123"). It gates the
	// response-integrity criterion (critConnectStartedIntegrity): a Started(2)
	// for a connect control the connect axis never reached is a FAIL, and that
	// assertion belongs only to the row whose axis this is.
	ConnectHome string
}

// judgeWith turns a directOracle into the closure the live phase drives,
// reading the DER through the same internal/invariant path every other oracle
// in this suite uses.
func (d *directOracle) judgeWith(ctx context.Context, rc *certify.RunCtx) Finding {
	uv, err := oracleUnitView(ctx, rc, oracleSimName)
	if err != nil {
		return unavailable("%v", err)
	}
	if d.JudgeCtx != nil {
		return d.JudgeCtx(uv, rc)
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

// ── BASIC-009: connect, graded against the DECLARED connect home ───────────

// oracleConnect grades BASIC-009's connect command against the model the
// CANDIDATE declares as its connect home, and REPORTS — never grades — the
// energize (M703 ES) and connection-status (M701 ConnSt) registers alongside it.
//
// ── Why this stopped grading both M703 and M123 ─────────────────────────────
//
// The prior oracle graded opModEnergize against model 703's ES on any DER that
// served 703, on the assumption that a bench serves EITHER 703 (7xx) OR 123
// (legacy) but not both. That is false for the advanced fixture, which serves
// the whole chain — 703 AND 123 (sim/modsim, -der-models advanced). So a connect
// row that commanded energize=false was FAILed because model 703's ES read its
// as-built default (enter-service permitted), even though the CANDIDATE
// implements connect via model 123's Conn — not enter-service via 703 (the owner
// confirmed the OEM inverter's connect home is M123, and the candidate manifest
// declares model 123). Grading a model the candidate does not claim for this
// axis FAILed a conforming DUT on the fixture's own default (the BASIC-009 leg of
// HARNESS-TEARDOWN-CANCEL-ONLY-LEAVES-APPLIED-STATE, RUN-3).
//
// So the connect axis is now graded against M123's Conn — the DECLARED home —
// and M703 ES and M701 ConnSt are REPORTED, not graded, exactly as BASIC-012
// names the half it cannot hold. The verdict is Pass if and only if M123 Conn
// measurably reached the commanded connect state; an M123 that is absent (the
// declared home unserved — a fixture/candidate mismatch preflightFixture also
// catches) or unreadable is a FAIL, because an unmeasured graded axis is not a
// pass. derbase agrees the home is M123 (SetConnectPlan -> newM123ConnPlan) and
// lexa-gw's supported.go names it "opModConnect (M123 Conn)".
func oracleConnect(wantConnect, wantEnergize bool) *directOracle {
	return &directOracle{
		Axis:        "opModConnect",
		ConnectHome: "M123",
		Commanded:   fmt.Sprintf("connect=%t (energize=%t published alongside)", wantConnect, wantEnergize),
		Registers: "opModConnect's register home is model 123's Conn point — the model the candidate " +
			"declares as its connect home, read here through this referee's own transcription of the " +
			"published model (internal/invariant's legacyctl.go), not through the product's. Model 703's ES " +
			"enter-service permission and model 701's ConnSt are REPORTED alongside the graded axis, never " +
			"graded: the candidate implements connect via M123, not enter-service via 703.",
		JudgeCtx: func(uv invariant.UnitView, rc *certify.RunCtx) Finding {
			var graded, reported []string
			verdict := certify.Pass

			// ── GRADE: opModConnect -> model 123 Conn (the DECLARED home) ──
			lc := uv.LegacyCommands(oracleSimName)
			switch {
			case !lc.Present:
				// The candidate's declared connect home is not served by this
				// DER. That is a fixture/candidate mismatch (preflightFixture
				// fails the campaign on it), and at the oracle level an unmeasured
				// GRADED axis is a FAIL, not a silent pass on the reported ones.
				verdict = certify.Fail
				graded = append(graded, "opModConnect's declared home model 123 is NOT served by this DER, "+
					"so the graded connect axis could not be measured — a fixture that does not serve the "+
					"model the candidate declares as its connect home")
			default:
				got, ok := connectState(lc)
				if !ok {
					verdict = certify.Fail
					graded = append(graded, "model 123's Conn point could not be read as a connect state ("+
						lc.Note+")")
					break
				}
				graded = append(graded, fmt.Sprintf("model 123 Conn reads %t against a commanded connect=%t",
					got, wantConnect))
				if got != wantConnect {
					verdict = certify.Fail
				}
				if d := invariant.DescribeM123Divergence(); d != "" {
					reported = append(reported, "TRANSCRIPTION: "+d)
				}
			}

			// ── REPORT (not grade): opModEnergize -> model 703 ES ──
			if regs := uv.Regs[703]; len(regs) > 0 {
				es := sunspec.Parse703(regs)
				reported = append(reported, fmt.Sprintf("model 703 ES (enter-service permission) reads %t "+
					"against the energize=%t published alongside — REPORTED, not graded: this candidate "+
					"implements connect via model 123, not enter-service via 703, so grading 703 here would "+
					"FAIL a conforming DUT on the fixture's as-built default", es.Enabled, wantEnergize))
			} else {
				reported = append(reported, "opModEnergize: this DER serves no model 703 (reported, not "+
					"graded)")
			}

			// ── REPORT (not grade): the DER's own model 701 ConnSt ──
			if meas := uv.Measurement(oracleSimName); meas.Present {
				reported = append(reported, fmt.Sprintf("the DER's own model 701 ConnSt reads %d — its "+
					"account of its connection state, REPORTED and not graded", meas.ConnSt))
			}

			// ── Manifest disclosure: is the graded home one the candidate claims? ──
			if m := rc.Manifest(); m != nil {
				if m.HasModel(123) {
					reported = append(reported, "the candidate manifest declares model 123, so the graded "+
						"connect home is one it claims")
				} else {
					reported = append(reported, "NOTE: the candidate manifest does NOT declare model 123, "+
						"the model this row grades opModConnect against — the graded home is not one the "+
						"candidate claims (preflightFixture is the campaign-level gate for this)")
				}
			}

			obs := "GRADED (opModConnect via model 123, the declared connect home): " + joinSemis(graded)
			if len(reported) > 0 {
				obs += ". REPORTED, not graded: " + joinSemis(reported)
			}
			return Finding{Verdict: verdict, Observed: obs}
		},
	}
}

// critConnectStartedIntegrity is BASIC-009's response-integrity gate: the DUT
// must NOT POST a DERControlResponse Started(2) for the connect control unless
// the declared connect axis (model 123 Conn) measurably reached the commanded
// state.
//
// A Started(2) tells the head end the control is EXECUTING. If the connect axis
// never reached the commanded state, that report is false — the head end is told
// the machine connected/disconnected while the device's own connect register
// says it did not, a real product response-integrity defect (the LXR-002 shape:
// a Started for an axis nothing executed). A CORRECT withhold — no Started(2), a
// Received(1)+CannotComply(252) — is NOT a failure here and must not read as
// one: this gate fires ONLY on a Started(2) the connect axis does not back.
//
// "reached" is the connect oracle's OWN post verdict, recorded in params:
// oracleConnect grades ONLY model 123 Conn, so its PASS is exactly "model 123
// Conn holds the commanded connect state AFTER the control". But holding the
// commanded state is not the same as MOVING to it — the DER's as-built legacy
// default is Conn=1 (sim.go), so a connect=TRUE row's axis already matches at
// baseline and a Started(2) would be credited against no execution at all. So a
// Started(2) is credited only when the move is DISTINGUISHABLE: the oracle's
// PRE verdict (directSetup's pre-publication read, oraclePreVerdictParam) shows
// the axis did NOT hold the commanded state before the control, and the post
// verdict shows it does now. Where the commanded state already equalled the
// baseline (no observable move), a Started(2) is REPORTED as un-creditable
// (WARN) rather than passed — the same distinguishable-baseline discipline
// BASIC-007's ramp oracle uses. When the oracle could not read the DER
// (oracleUnavailableParam set), this gate DECLINES rather than blaming the DUT.
func critConnectStartedIntegrity(mridKey string, o *Observation) criterion {
	oracleDown := o.Params[oracleUnavailableParam]
	reached := certify.Verdict(o.Params[oracleVerdictParam]) == certify.Pass
	preRecorded := o.Params[oraclePreVerdictParam] != ""
	preHeld := certify.Verdict(o.Params[oraclePreVerdictParam]) == certify.Pass
	// A move is distinguishable only when the axis did NOT already hold the
	// commanded state at baseline (and a baseline was actually recorded).
	distinguishable := preRecorded && !preHeld
	preObs := orText(o.Params[oraclePreObservedParam], "no pre-publication connect read was recorded")
	connectObs := orText(o.Params[oracleObservedParam], "the connect oracle recorded no observation")
	failObs := func() string {
		return fmt.Sprintf("the DUT reported DERControlResponse Started(2) for the connect control "+
			"(subject %s), but the declared connect axis (model 123 Conn) did NOT measurably reach the "+
			"commanded connect state: %s. Reporting a control STARTED while the device's own connect "+
			"register disagrees tells the head end the machine acted when it did not — a response-integrity "+
			"defect (the LXR-002 shape: a Started for an axis nothing executed)", mridKey, connectObs)
	}
	// creditStarted decides a Started(2) whose axis DID reach the commanded state:
	// a PASS only when the move was distinguishable from the baseline, else a WARN
	// that reports — rather than credits — an unbacked Started.
	creditStarted := func() (certify.Verdict, string) {
		if distinguishable {
			return certify.Pass, fmt.Sprintf("the DUT reported Started(2) for the connect control AND the "+
				"declared connect axis (model 123 Conn) MOVED to the commanded state: before, %s; after, %s",
				preObs, connectObs)
		}
		return certify.Warn, fmt.Sprintf("the DUT reported Started(2) for the connect control and model 123 "+
			"Conn holds the commanded state AFTER — but it ALSO held it BEFORE the control (%s), so no "+
			"transition is observable and the Started cannot be credited as proof of execution. Reported, "+
			"not passed: an indistinguishable baseline cannot certify a move (the same discipline BASIC-007's "+
			"ramp oracle uses). Post: %s", preObs, connectObs)
	}

	return criterion{
		Claim: "the DUT did not report DERControlResponse Started(2) for the connect control unless the " +
			"declared connect axis (model 123 Conn) measurably reached the commanded state",
		How: "the DERControlResponse statuses the DUT POSTed for this control — recovered from the session " +
			"(tier 2) or from gridsim's own record (tier 3) — cross-checked against the independent model " +
			"123 Conn read the connect oracle graded: a Started(2) the connect axis does not back is a FAIL, " +
			"and a correct withhold (no Started(2), CannotComply at receipt) is a PASS",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			if oracleDown != "" {
				return Finding{Unavailable: "the connect oracle could not read the DER (" + oracleDown +
					"), so this gate cannot cross-check a Started(2) against the connect axis"}
			}
			for _, e := range t.Method("POST") {
				if e.Req == nil || len(e.Req.Body) == 0 {
					continue
				}
				doc, err := e.Req.SEP()
				if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
					continue
				}
				if subj, _ := doc.TextOf("subject"); subj != mridKey {
					continue
				}
				if st, _ := doc.UintOf("status"); st != 2 {
					continue
				}
				if !reached {
					return citeMessage(t, e.Req, certify.Fail, "%s", failObs())
				}
				v, obs := creditStarted()
				return citeMessage(t, e.Req, v, "%s", obs)
			}
			// No Started(2) in the transcript — let tier 3 make the positive
			// statement against gridsim's own Response record.
			return Finding{Unavailable: "no Started(2) Response for this control appears in the recovered " +
				"transcript"}
		},
		Server: func(v *ServerView) Finding {
			if oracleDown != "" {
				return Finding{Unavailable: "the connect oracle could not read the DER, so this gate cannot " +
					"cross-check a Started(2) against the connect axis"}
			}
			got := v.ResponsesFor(mridKey)
			if len(got) == 0 && !v.SessionEstablished() {
				return noSessionUnavailable()
			}
			var statuses []string
			started := false
			for _, r := range got {
				statuses = append(statuses, fmt.Sprintf("status=%d", r.Status))
				if r.Status == 2 {
					started = true
				}
			}
			switch {
			case started && !reached:
				return Finding{Verdict: certify.Fail, Observed: failObs()}
			case started:
				v, obs := creditStarted()
				return Finding{Verdict: v, Observed: obs}
			default:
				return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf("the DUT reported NO Started(2) "+
					"for the connect control (statuses: %s) — a correct withhold/CannotComply is not a "+
					"response-integrity failure", orText(strings.Join(statuses, ", "), "none"))}
			}
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
