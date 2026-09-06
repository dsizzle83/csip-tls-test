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
	"csip-tls-test/internal/certify/manifest"
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

// ── BASIC-009: connect, graded against EITHER declared connect home ─────────

// connectHome names which SunSpec model BASIC-009 grades its connect transition
// against. The two are the OPPOSITE-generation register homes of the row's two
// axes: opModConnect lands on model 123's Conn point (the legacy connect home),
// opModEnergize on model 703's enter-service permission (the 7xx home). A DER
// implements one, the other, or — the advanced bench fixture — both, so which
// one this row GRADES is a property of the candidate, not of the wire image.
type connectHome int

const (
	connectHomeUnset connectHome = iota // ambiguous / undeclared: DECLINE, never guess
	connectHomeM123                     // opModConnect  -> model 123 Conn
	connectHomeM703                     // opModEnergize -> model 703 ES (enter-service)
)

// connectHomeParam is the -param that names the connect home explicitly. It is
// what lets the bench simulator — which serves BOTH 123 and 703 and so cannot
// be disambiguated from the register image alone — be driven through EITHER
// mode: a run can grade the connect transition via M123 on one pass and via
// M703 ES on the next. It ALWAYS wins over the manifest, because an operator
// exercising one home of a both-home fixture has said which.
const connectHomeParam = "connect-home"

// resolveConnectHome decides which model BASIC-009 grades its connect transition
// against, and DECLINES rather than guess when the choice is genuinely ambiguous.
//
// Order:
//  1. the -param connect-home selector, when set — the explicit override.
//  2. otherwise the candidate manifest's declared models: model 123 alone -> M123,
//     model 703 alone -> M703 ES. A candidate that declares exactly one of the two
//     connect-home models has named its home.
//  3. BOTH declared (the advanced-fixture candidate) or NEITHER (a manifest that
//     named no connect home): no unambiguous home and no selector, so it DECLINES
//     (connectHomeUnset) rather than grade an axis the candidate has not chosen.
//
// A NIL manifest is the one case that DEFAULTS rather than declines, and that is
// deliberate: RunCtx.Manifest()'s contract is that a run with no -manifest must
// behave exactly as the harness did before manifests existed, and before this
// generalisation BASIC-009 graded M123 (derbase's SetConnectPlan -> newM123ConnPlan;
// the owner-confirmed OEM connect home). Silence is NOT an ambiguous declaration
// — it is no declaration — so it takes the historical default; an AMBIGUOUS
// declaration is where "never guess" has teeth. Gating campaigns REQUIRE a
// manifest, so the fail-closed path always reaches step 2 or 3, never the default.
func resolveConnectHome(m *manifest.Manifest, param func(string) (string, bool)) (connectHome, string) {
	if v, ok := param(connectHomeParam); ok && strings.TrimSpace(v) != "" {
		switch strings.ToUpper(strings.TrimSpace(v)) {
		case "M123", "123":
			return connectHomeM123, "the -param " + connectHomeParam + "=M123 selector"
		case "M703", "703", "ES":
			return connectHomeM703, "the -param " + connectHomeParam + "=M703 selector"
		default:
			return connectHomeUnset, fmt.Sprintf("the -param %s=%q selector is neither M123 nor M703",
				connectHomeParam, v)
		}
	}
	if m == nil {
		return connectHomeM123, "no candidate manifest was supplied, so BASIC-009 grades its historical " +
			"default connect home model 123 Conn (the pre-manifest behaviour RunCtx.Manifest() preserves)"
	}
	has123, has703 := m.HasModel(123), m.HasModel(703)
	switch {
	case has123 && !has703:
		return connectHomeM123, "the candidate manifest declares model 123 and not model 703"
	case has703 && !has123:
		return connectHomeM703, "the candidate manifest declares model 703 and not model 123"
	case has123 && has703:
		return connectHomeUnset, "the candidate manifest declares BOTH model 123 and model 703, either of " +
			"which can be the connect home; pass -param " + connectHomeParam + "=M123|M703 to choose"
	default:
		return connectHomeUnset, "the candidate manifest declares neither model 123 nor model 703, so it " +
			"names no connect home; pass -param " + connectHomeParam + "=M123|M703"
	}
}

// oracleConnect grades BASIC-009's connect command against whichever connect
// home resolveConnectHome names for this run — model 123's Conn (opModConnect)
// or model 703's enter-service permission (opModEnergize) — and REPORTS, never
// grades, the OTHER home and the DER's own model 701 ConnSt alongside it.
//
// ── Why the home is chosen, not fixed ───────────────────────────────────────
//
// The prior oracle graded opModEnergize against model 703 ES on any DER that
// served 703, on the assumption that a bench serves EITHER 703 (7xx) OR 123
// (legacy) but not both. That is false for the advanced fixture, which serves
// the whole chain — 703 AND 123 — so a connect row commanding energize=false was
// FAILed on 703's as-built default (enter-service permitted) even where the
// candidate's connect home was M123 (HARNESS-TEARDOWN-CANCEL-ONLY-LEAVES-APPLIED-
// STATE, RUN-3). The fix then hard-pinned the home to M123, which is right for a
// candidate that declares 123 and wrong for one that declares only 703 (the
// common one-to-one-7xx manifest): it graded a model the candidate does not
// claim. So the home is now the candidate's OWN — its declared models, or an
// explicit -param connect-home for the both-home bench — and the verdict is Pass
// iff the GRADED home measurably reached the commanded state. An absent graded
// home (the declared home unserved — a fixture/candidate mismatch preflightFixture
// also catches) or an unreadable one is a FAIL: an unmeasured graded axis is not
// a pass. An UNRESOLVABLE home (ambiguous declaration, no selector) DECLINES —
// which the gating direct-oracle path turns into a FAIL (oracleOutcome), the
// fail-closed answer — rather than grade an axis nobody chose.
func oracleConnect(wantConnect, wantEnergize bool) *directOracle {
	return &directOracle{
		Axis: "opModConnect",
		// A marker that this is THE connect row, so basic.go attaches the
		// response-integrity gate; the GRADED home is chosen per run (see
		// resolveConnectHome), not named here.
		ConnectHome: "connect",
		Commanded:   fmt.Sprintf("connect=%t (energize=%t published alongside)", wantConnect, wantEnergize),
		Registers: "opModConnect's register home is model 123's Conn point and opModEnergize's is model 703's " +
			"enter-service permission (ES) — the OPPOSITE-generation homes of a legacy and a 7xx DER. Which one " +
			"this row GRADES is chosen from the candidate manifest's declared models (123-only -> M123 Conn, " +
			"703-only -> M703 ES) or an explicit -param connect-home, read here through this referee's own " +
			"transcription of the published models (internal/invariant's legacyctl.go, lexa-proto's Parse703), " +
			"not through the product's; the OTHER home and model 701's ConnSt are REPORTED alongside the graded " +
			"axis, never graded.",
		JudgeCtx: func(uv invariant.UnitView, rc *certify.RunCtx) Finding {
			home, why := resolveConnectHome(rc.Manifest(), rc.Param)
			switch home {
			case connectHomeM123:
				return judgeConnectHomeM123(uv, rc, wantConnect, wantEnergize, why)
			case connectHomeM703:
				return judgeConnectHomeM703(uv, rc, wantConnect, wantEnergize, why)
			default:
				return unavailable("BASIC-009 cannot decide which connect home to grade: %s. Its connect "+
					"transition is graded via model 123 Conn OR model 703 ES, and this run established neither "+
					"an unambiguous declared model nor a -param %s selector, so the oracle DECLINES rather than "+
					"grade an axis the candidate has not chosen", why, connectHomeParam)
			}
		},
	}
}

// judgeConnectHomeM123 grades opModConnect against model 123's Conn point (the
// legacy connect home) and reports model 703 ES, model 701 ConnSt, and the
// manifest disclosure alongside.
func judgeConnectHomeM123(uv invariant.UnitView, rc *certify.RunCtx, wantConnect, wantEnergize bool, why string) Finding {
	var graded, reported []string
	verdict := certify.Pass

	// ── GRADE: opModConnect -> model 123 Conn ──
	lc := uv.LegacyCommands(oracleSimName)
	switch {
	case !lc.Present:
		// The graded connect home is not served by this DER. That is a
		// fixture/candidate mismatch (preflightFixture fails the campaign on
		// it), and at the oracle level an unmeasured GRADED axis is a FAIL, not
		// a silent pass on the reported ones.
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
			"against the energize=%t published alongside — REPORTED, not graded on this run: the connect "+
			"home graded here is M123 Conn", es.Enabled, wantEnergize))
	} else {
		reported = append(reported, "opModEnergize: this DER serves no model 703 (reported, not "+
			"graded)")
	}

	reported = reportConnStAndDisclosure(uv, rc, 123, reported)

	obs := "GRADED (opModConnect via model 123, the declared connect home): " + joinSemis(graded)
	if len(reported) > 0 {
		obs += ". REPORTED, not graded: " + joinSemis(reported)
	}
	return Finding{Verdict: verdict, Observed: obs + ". Connect home: " + why}
}

// judgeConnectHomeM703 grades opModEnergize against model 703's enter-service
// permission (the 7xx connect home) and reports model 123 Conn, model 701 ConnSt,
// and the manifest disclosure alongside — the mirror of judgeConnectHomeM123.
func judgeConnectHomeM703(uv invariant.UnitView, rc *certify.RunCtx, wantConnect, wantEnergize bool, why string) Finding {
	var graded, reported []string
	verdict := certify.Pass

	// ── GRADE: opModEnergize -> model 703 ES (enter-service permission) ──
	if regs := uv.Regs[703]; len(regs) > 0 {
		es := sunspec.Parse703(regs)
		graded = append(graded, fmt.Sprintf("model 703 ES (enter-service permission) reads %t against a "+
			"commanded energize=%t", es.Enabled, wantEnergize))
		if es.Enabled != wantEnergize {
			verdict = certify.Fail
		}
	} else {
		verdict = certify.Fail
		graded = append(graded, "opModEnergize's declared home model 703 is NOT served by this DER, so the "+
			"graded enter-service axis could not be measured — a fixture that does not serve the model the "+
			"candidate declares as its connect home")
	}

	// ── REPORT (not grade): opModConnect -> model 123 Conn ──
	lc := uv.LegacyCommands(oracleSimName)
	switch {
	case !lc.Present:
		reported = append(reported, "opModConnect: this DER serves no model 123 (reported, not graded)")
	default:
		if got, ok := connectState(lc); ok {
			reported = append(reported, fmt.Sprintf("model 123 Conn reads %t against the connect=%t published "+
				"alongside — REPORTED, not graded on this run: the connect home graded here is M703 ES",
				got, wantConnect))
		} else {
			reported = append(reported, "model 123's Conn point could not be read as a connect state ("+
				lc.Note+") — REPORTED, not graded")
		}
	}

	reported = reportConnStAndDisclosure(uv, rc, 703, reported)

	obs := "GRADED (opModEnergize via model 703 ES, the declared connect home): " + joinSemis(graded)
	if len(reported) > 0 {
		obs += ". REPORTED, not graded: " + joinSemis(reported)
	}
	return Finding{Verdict: verdict, Observed: obs + ". Connect home: " + why}
}

// reportConnStAndDisclosure appends the DER's own model 701 ConnSt (its account
// of its connection state) and the manifest's model-<gradedModel> disclosure to
// reported — the two lines both connect homes carry unchanged: ConnSt is REPORTED
// whichever home is graded, and the disclosure only asks whether the graded home
// is one the candidate declared.
func reportConnStAndDisclosure(uv invariant.UnitView, rc *certify.RunCtx, gradedModel int, reported []string) []string {
	if meas := uv.Measurement(oracleSimName); meas.Present {
		reported = append(reported, fmt.Sprintf("the DER's own model 701 ConnSt reads %d — its "+
			"account of its connection state, REPORTED and not graded", meas.ConnSt))
	}
	if m := rc.Manifest(); m != nil {
		if m.HasModel(gradedModel) {
			reported = append(reported, fmt.Sprintf("the candidate manifest declares model %d, so the "+
				"graded connect home is one it claims", gradedModel))
		} else {
			reported = append(reported, fmt.Sprintf("NOTE: the candidate manifest does NOT declare model %d, "+
				"the model this row grades against — the graded home is not one the candidate claims "+
				"(preflightFixture is the campaign-level gate for this)", gradedModel))
		}
	}
	return reported
}

// critConnectStartedIntegrity is BASIC-009's response-integrity gate: the DUT
// must NOT POST a DERControlResponse Started(2) for the connect control unless
// the GRADED connect home (model 123 Conn or model 703 ES, whichever this run
// grades — see resolveConnectHome) measurably reached the commanded state.
//
// A Started(2) tells the head end the control is EXECUTING. If the graded home
// never reached the commanded state, that report is false — the head end is told
// the machine connected/disconnected while the device's own connect register
// says it did not, a real product response-integrity defect (the LXR-002 shape:
// a Started for an axis nothing executed). A CORRECT withhold — no Started(2), a
// Received(1)+CannotComply(252) — is NOT a failure here and must not read as
// one: this gate fires ONLY on a Started(2) the graded home does not back.
//
// The gate is home-AGNOSTIC by construction: it reads the connect oracle's own
// recorded verdicts (oracleVerdictParam, oraclePreVerdictParam) and observations,
// which already reflect whichever home was graded, so nothing here needs to know
// which one — the interpolated observation names it. "reached" is that oracle's
// post verdict: its PASS is exactly "the graded home holds the commanded state
// AFTER the control". But holding the commanded state is not the same as MOVING
// to it — a DER whose as-built default already equals the commanded state (the
// legacy Conn=1 default, say) matches at baseline, and a Started(2) would then be
// credited against no execution at all. So a Started(2) is credited only when the
// move is DISTINGUISHABLE: the oracle's PRE verdict (directSetup's pre-publication
// read, oraclePreVerdictParam) shows the home did NOT hold the commanded state
// before the control and the post verdict shows it does now. Where the commanded
// state already equalled the baseline (no observable move), a Started(2) is
// REPORTED as un-creditable (WARN) rather than passed — the same distinguishable-
// baseline discipline BASIC-007's ramp oracle uses. When the oracle could not read
// the DER (oracleUnavailableParam set), this gate DECLINES rather than blame the DUT.
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
			"(subject %s), but the graded connect home did NOT measurably reach the commanded state: %s. "+
			"Reporting a control STARTED while the device's own connect register disagrees tells the head "+
			"end the machine acted when it did not — a response-integrity defect (the LXR-002 shape: a "+
			"Started for an axis nothing executed)", mridKey, connectObs)
	}
	// creditStarted decides a Started(2) whose home DID reach the commanded state:
	// a PASS only when the move was distinguishable from the baseline, else a WARN
	// that reports — rather than credits — an unbacked Started.
	creditStarted := func() (certify.Verdict, string) {
		if distinguishable {
			return certify.Pass, fmt.Sprintf("the DUT reported Started(2) for the connect control AND the "+
				"graded connect home MOVED to the commanded state: before, %s; after, %s", preObs, connectObs)
		}
		return certify.Warn, fmt.Sprintf("the DUT reported Started(2) for the connect control and the graded "+
			"connect home holds the commanded state AFTER — but it ALSO held it BEFORE the control (%s), so no "+
			"transition is observable and the Started cannot be credited as proof of execution. Reported, "+
			"not passed: an indistinguishable baseline cannot certify a move (the same discipline BASIC-007's "+
			"ramp oracle uses). Post: %s", preObs, connectObs)
	}

	return criterion{
		Claim: "the DUT did not report DERControlResponse Started(2) for the connect control unless the " +
			"graded connect home (model 123 Conn or model 703 ES) measurably reached the commanded state",
		How: "the DERControlResponse statuses the DUT POSTed for this control — recovered from the session " +
			"(tier 2) or from gridsim's own record (tier 3) — cross-checked against the independent connect-" +
			"home read the connect oracle graded: a Started(2) the graded home does not back is a FAIL, and a " +
			"correct withhold (no Started(2), CannotComply at receipt) is a PASS",
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
