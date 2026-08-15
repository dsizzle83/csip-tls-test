package suitecsip

// curve.go — IW15-008. The southbound half of the CURVE-linked inverter-control
// rows (BASIC-004/005/006/011/012/015) and of the rows whose axis this product
// deliberately REFUSES (BASIC-007/014).
//
// ── The finding this file closes ────────────────────────────────────────────
//
// Every one of those rows certified applicable-PASS on a product that does not
// execute the axis at all, and it did so by the same mechanism the repaired
// BASIC-013 was failing by: the row carried NO southbound oracle, so its "the
// DER's output followed the control" criterion was a Skip, and a Skip is the
// LOWEST severity there is (bundle.Verdict.Severity: Skip 0 < Pass 1) while
// every roll-up in the runner raises only. Absence of measurement read as
// success. The northbound half — an <opModVoltVar> element appearing inside a
// DERControlBase the DUT fetched — was the whole of the evidence, and it is
// evidence that the BENCH published a control, not that the DUT did anything
// with it.
//
// So: no Skip path survives here. Every row below either MEASURES the DER's own
// registers and reports what it found, or says in a decided FAIL exactly which
// link of the chain it could not measure and why. "We could not test it" must
// never read like "it passed".
//
// ── What a curve oracle can and cannot assert on this bench ─────────────────
//
// The device sims adopt curves realistically (a writable staging curve, the
// §3.1.2 AdptCrvReq/AdptCrvRslt handshake, a read-only live curve at index 0
// that reflects the staged points on COMPLETED) but they simulate NO curve
// PHYSICS: a volt-var curve on the sim moves no measured var. Every assertion
// here is therefore REGISTER- and ADOPT-STATE-based — the curve content landed
// in the model's own live curve, the handshake reached COMPLETED, and the
// function is enabled — correlated to the breakpoints THIS row published. It is
// deliberately NOT an effect-on-output oracle; building one against a sim with
// no curve physics would be measuring the fixture.
//
// ── The authoring gaps are named, not hidden ───────────────────────────────
//
// gridsim authors four of IEEE 2030.5's fourteen curve-valued modes (volt_var,
// volt_watt, freq_watt, watt_pf — sim/gridsim/curve.go). The ride-through modes
// BASIC-004/005 are about, and the ramp gradients BASIC-007 is about, cannot be
// placed on the wire from this bench at all. That is a real gap in the
// evidence, and a gap in the evidence is a row that has not been tested: those
// rows now FAIL, naming the missing lever, instead of skipping past it into a
// PASS. Closing them needs a bench lever, not a change here.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// The Observation.Params keys the curve and refusal rows add to the oracled
// scalar rows' set (basic.go). They are DISTINCT keys, never the scalar ones
// reused, so a bundle can show exactly which apparatus produced a verdict — and
// so a test asserting "the curve row recorded what it published" cannot be
// satisfied by a scalar row's leftover.
const (
	curvePublishedParam = "iw15.curve_published"
	curveModelParam     = "iw15.curve_model"
	curveMRIDNoteParam  = "iw15.curve_mrid_note"
	curveHrefParam      = "iw15.curve_href"
	curveResourceParam  = "iw15.curve_resource_mrid"

	refusalAxisParam     = "iw15.refusal_axis"
	refusalBaselineParam = "iw15.refusal_baseline"
)

// ── Curve rows: the binding ─────────────────────────────────────────────────

// curveBinding is what a CURVE-linked row carries beyond a plain one: the
// breakpoints it publishes northbound, and the SunSpec model those breakpoints
// must be found in southbound.
//
// The two live in ONE structure for the reason oracleBinding's doc gives for the
// scalar rows: the published curve and the oracle that judges it must not be
// able to disagree about what was commanded. The row states its points once,
// the publisher sends those points, and the oracle expects those points.
type curveBinding struct {
	// Mode is gridsim's own curve-mode name (sim/gridsim/curve.go's
	// curveTypeForMode vocabulary): volt_var | volt_watt | freq_watt | watt_pf.
	Mode string
	// Points are the breakpoints this row publishes, in the wire's own raw
	// units — the axis multipliers below say what power of ten they carry.
	Points []CurvePoint
	// XMult/YMult are the DERCurve axis multipliers this row publishes with.
	// They are what converts a published breakpoint into the device
	// engineering value the oracle expects (wantPoints), so they must travel
	// with the points rather than being assumed zero at one end.
	XMult, YMult int8
	// YRefType is the Table-19 code the published curve's y axis carries.
	YRefType uint8

	// Model is the SunSpec model whose LIVE curve must hold this row's content.
	Model uint16
	// Mapping records WHERE that mode→model correspondence comes from, so a
	// FAIL naming a model can be checked by a reader who did not write it.
	Mapping string
	// NoRegisterHome, when non-empty, says this mode has no breakpoint-carrying
	// register home on this DER at all, and why. Such a row publishes
	// northbound (the CSIP half is still real evidence) and its southbound
	// criterion is a decided FAIL carrying this reason — never a PASS, and
	// never a Skip.
	NoRegisterHome string
}

// wantPoints converts the published breakpoints into the device engineering
// values the oracle expects to read back, applying the axis multipliers exactly
// once, here.
func (b *curveBinding) wantPoints() []invariant.CurvePoint {
	out := make([]invariant.CurvePoint, 0, len(b.Points))
	for _, p := range b.Points {
		out = append(out, invariant.CurvePoint{
			X: applyMult(p.X, b.XMult),
			Y: applyMult(p.Y, b.YMult),
		})
	}
	return out
}

// wantDeptRef translates the yRefType this row PUBLISHES into the SunSpec
// DeptRef the DER must be found holding, or returns ok=false for a mode whose
// curve bank carries no such register.
//
// It is a translation this referee performs INDEPENDENTLY, from the standards
// text rather than from the product's table, which is the whole point of the
// check. A curve's y values are a percentage and a percentage is not a quantity
// without its base: IEEE 2030.5 names that base on every DERCurve (yRefType,
// minOccurs=1) and SunSpec names it per bank (DeptRef). Until 2026-08-14 the
// product never translated one into the other — it copied whatever DeptRef the
// device's template already held and wrote the commanded points underneath it —
// and the read-back hash could not see it, because the hash carries the doc's
// OWN yRefType at both ends and so can only ever confirm that the POINTS round
// tripped. This oracle reads the register.
//
// The mapping, from sep 2.0.4's own element documentation:
//
//	opModVoltVar / opModWattVar   y is "one of %setMaxW, %setMaxVar, or
//	                              %statVarAvail" -> W_MAX_PCT / VAR_MAX_PCT /
//	                              VAR_AVAL_PCT
//	opModVoltWatt                 y is "an active power output in %setMaxW"
//	                              and nothing else -> W_MAX_PCT
//
// ok=false is returned for any other model, and for a yRefType outside the set
// its mode allows — those are curves a conformant DUT REFUSES, so this row has
// no register expectation to assert and says so instead of inventing one.
func (b *curveBinding) wantDeptRef() (uint16, bool) {
	switch b.Model {
	case sunspec.ModelDERVoltVar, sunspec.ModelDERWattVar:
		switch b.YRefType {
		case derUnitRefSetMaxW:
			return deptRefWMaxPct, true
		case derUnitRefSetMaxVar:
			return deptRefVarMaxPct, true
		case derUnitRefStatVarAvail:
			return deptRefVarAvalPct, true
		}
	case sunspec.ModelDERVoltWatt:
		if b.YRefType == derUnitRefSetMaxW {
			return deptRefWMaxPct, true
		}
	}
	return 0, false
}

// DERUnitRefType codes (sep 2.0.4, "Specifies context for interpreting percent
// values") and the SunSpec DeptRef codes they translate to. Named here so the
// rows and the oracle read one vocabulary; see wantDeptRef for the provenance
// of the translation and invariant.DeptRefName for the DeptRef enums'.
const (
	derUnitRefNA           uint8 = 0
	derUnitRefSetMaxW      uint8 = 1
	derUnitRefSetMaxVar    uint8 = 2
	derUnitRefStatVarAvail uint8 = 3

	deptRefWMaxPct    uint16 = 0 // 705/706/712
	deptRefVarMaxPct  uint16 = 1 // 705/712 only
	deptRefVarAvalPct uint16 = 2 // 705/712 only
)

// applyMult applies a 2030.5 power-of-ten axis multiplier.
func applyMult(v float64, mult int8) float64 {
	switch {
	case mult == 0:
		return v
	case mult > 0:
		for i := int8(0); i < mult; i++ {
			v *= 10
		}
	default:
		for i := int8(0); i > mult; i-- {
			v /= 10
		}
	}
	return v
}

// describePublished renders the breakpoints this row published, for a finding
// that has to show both curves side by side.
func (b *curveBinding) describePublished() string {
	pts := make([]string, 0, len(b.Points))
	for _, p := range b.Points {
		pts = append(pts, fmt.Sprintf("(%s, %s)", trimNum(p.X), trimNum(p.Y)))
	}
	s := fmt.Sprintf("%d breakpoint(s) %s", len(b.Points), strings.Join(pts, " "))
	if b.XMult != 0 || b.YMult != 0 {
		s += fmt.Sprintf(" (x multiplier 10^%d, y multiplier 10^%d)", b.XMult, b.YMult)
	}
	return s
}

func trimNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// derUnitRefName spells a DERUnitRefType out in a finding, so a reader sees
// what the row published rather than a code.
func derUnitRefName(v uint8) string {
	switch v {
	case 0:
		return "N/A — no reference named"
	case 1:
		return "%setMaxW"
	case 2:
		return "%setMaxVar"
	case 3:
		return "%statVarAvail"
	case 4:
		return "%setEffectiveV"
	case 5:
		return "%setMaxChargeRateW"
	case 6:
		return "%setMaxDischargeRateW"
	case 7:
		return "%statWAvail"
	}
	return "reserved/unknown"
}

// curvePointTolerance is the slack the curve oracle allows one breakpoint
// value: 1 % of the value plus half a unit, the same shape (and for the same
// stated reason) as oracleTolerance — the last register count of a device's own
// scale factor must not fail a curve that is otherwise exactly right.
func curvePointTolerance(want float64) float64 { return oracleTolerance(want, 0.5) }

// ── Curve rows: the oracle ──────────────────────────────────────────────────

// oracleCurve builds the independent southbound oracle for a curve-linked row:
// it reads the DER's OWN curve-model registers through internal/invariant
// (which shares only the SunSpec register-offset tables with the product and
// none of its CSIP/derbase interpretation) and answers ONE question — does the
// DER's live curve for this mode hold the breakpoints THIS row published, in a
// function that is adopted and enabled?
//
// Every terminal is decided. There is no Skip and no "unavailable" that a row
// can rest on: an unreachable sidecar is reported through the same
// Unavailable→FAIL path oracleOutcome already applies to the scalar rows, and
// every register state below is a statement about what the DER holds.
//
// The checks are ordered so the FAIL says the most useful thing first — the
// model is absent, or present-but-never-adopted, or adopted-but-disabled, or
// adopted-and-enabled-with-the-wrong-content — because those are four different
// defects with four different owners, and a bundle that collapsed them into
// "the curve did not land" would send every one of them to the wrong person.
func oracleCurve(b *curveBinding) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		cv := uv.Curve(oracleSimName, b.Model)
		published := b.describePublished()

		if b.NoRegisterHome != "" {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound, and there is NO southbound register home on this DER for "+
					"that content: %s. The row's southbound half therefore cannot be measured at all, which "+
					"is reported as a FAIL rather than skipped — an unmeasured criterion is not a satisfied "+
					"one. What the DER does hold on the nearest model: %s",
				published, b.NoRegisterHome, cv.Describe())}
		}
		if !cv.Present {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound and the DER's own register image carries NOTHING for it: "+
					"%s. %s The models the DER does serve are %s",
				published, cv.Describe(), b.Mapping, modelList(uv))}
		}
		if !cv.Adopted {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"this row published %s northbound and the DER's %s adopt handshake never COMPLETED, so no "+
					"curve was taken up: %s. %s",
				published, cv.Axis.Name, cv.Describe(), b.Mapping)}
		}
		match := invariant.MatchPoints(cv.Points, b.wantPoints(), curvePointTolerance)
		if !match.Matched {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DER's %s reports an adopted curve whose CONTENT is not the one this row published: %s. "+
					"This row published %s. Full register state: %s",
				cv.Axis.Name, match.Reason, published, cv.Describe())}
		}
		// The y-axis REFERENCE, checked separately from the points and after
		// them, because the two are different defects with different owners and
		// the second is invisible to the first. Identical breakpoints under the
		// wrong DeptRef are a different command: "-30" against VAR_MAX_PCT and
		// "-30" against W_MAX_PCT are a 2.3x difference on a 60 kW / 26.4 kvar
		// DER and a 30x one on a 2 kvar machine, in the wrong direction, with
		// every point matching. A referee that stopped at the points would
		// certify that.
		if want, ok := b.wantDeptRef(); ok {
			if !cv.HasDeptRef {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"the DER's %s holds this row's breakpoints but its curve bank reports no DeptRef at "+
						"all, so what its y values are a percentage OF cannot be read. This row published "+
						"yRefType=%d (%s). Full register state: %s",
					cv.Axis.Name, b.YRefType, derUnitRefName(b.YRefType), cv.Describe())}
			}
			if cv.DeptRef != want {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"the DER's %s holds exactly the breakpoints this row published, under the WRONG y-axis "+
						"reference: DeptRef=%d (%s), where this row's yRefType=%d (%s) requires DeptRef=%d "+
						"(%s). The points matching proves nothing here — the same numbers against a "+
						"different base are a different command, and a read-back hash cannot see it "+
						"because it carries the document's own yRefType at both ends. Full register "+
						"state: %s",
					cv.Axis.Name, cv.DeptRef, invariant.DeptRefName(b.Model, cv.DeptRef),
					b.YRefType, derUnitRefName(b.YRefType), want, invariant.DeptRefName(b.Model, want),
					cv.Describe())}
			}
		}
		if !cv.Enabled {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DER's %s holds exactly the breakpoints this row published, but the function itself is "+
					"DISABLED (Ena=%d): a curve adopted into a switched-off function commands nothing, so "+
					"this is not execution of the control. %s",
				cv.Axis.Name, cv.EnaRaw, cv.Describe())}
		}
		if !cv.ReadOnly {
			return Finding{Verdict: certify.Warn, Observed: fmt.Sprintf(
				"the DER's %s holds exactly the breakpoints this row published and is enabled, but its "+
					"index-0 curve reports ReadOnly=false — on a conformant device the ACTIVE curve is "+
					"read-only and the writable ones are the staging indices, so this reading may be of a "+
					"staged curve rather than the governing one. %s",
				cv.Axis.Name, cv.Describe())}
		}
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"the DER's own %s live curve holds exactly the breakpoints this row published, its adopt "+
				"handshake COMPLETED and the function is enabled: %s. %s",
			cv.Axis.Name, match.Reason, cv.Describe())}
	}
}

// modelList renders the SunSpec models the DER actually served, so a FAIL about
// a missing model names what IS there.
func modelList(uv invariant.UnitView) string {
	if len(uv.Models) == 0 {
		return "(the chain walk found none)"
	}
	out := make([]string, 0, len(uv.Models))
	for _, m := range uv.Models {
		out = append(out, strconv.FormatUint(uint64(m), 10))
	}
	return strings.Join(out, " ")
}

// ── Curve rows: the live phase ──────────────────────────────────────────────

// curveSetup is a curve row's Setup: read the DER's own curve registers BEFORE
// publishing anything, then publish this row's curve and record the mRID the
// server actually minted for it.
//
// The pre-read is what makes the post-read evidence, for exactly the reason
// oracledSetup's doc gives: "the DER holds this curve after the control was
// published" is a fact about the DER, not about the DUT, until it is paired
// with "and it did not hold it before". Curve rows have no ladder to fall back
// on — a curve is the row's own published content and may not be substituted —
// so a DER that already holds the row's curve produces a decided non-PASS
// (curveOutcome), not a quiet pass on a stale register.
//
// Recording the minted mRID is a correctness fix in its own right. gridsim
// MINTS the mRID for a curve-bound control (sim/gridsim/curve.go: it is
// "DERC-SP-CURVE-<epoch>", not anything the caller chose), and the row's wire
// criterion binds THIS ROW'S OWN mRID (critDERControlCarriesModeFrom,
// IW15-004). Left at the row's synthetic "CERT-BASIC-006", the criterion was
// binding to an mRID that has never been on any wire.
func curveSetup(ctx context.Context, d *Driver, params map[string]string, b *curveBinding, mrid string) error {
	pre := oracleCurve(b)(ctx, d.rc)
	params[oraclePreVerdictParam] = string(pre.Verdict)
	params[oraclePreObservedParam] = findingObserved(pre)
	params[curvePublishedParam] = b.describePublished()
	params[curveModelParam] = strconv.FormatUint(uint64(b.Model), 10)

	return publishCurveControl(ctx, d, params, b, mrid)
}

// publishCurveControl puts one row's curve on the wire through gridsim's curve
// API and records what the server minted for it.
//
// It is shared by curveSetup and refusalSetup rather than written twice, and
// that sharing is load-bearing rather than tidiness: a REFUSAL row's evidence
// is only about the AXIS if the control it published is identical in kind to
// the one an execution row publishes. Two publishers one edit apart could drift
// into "the DUT refused it because the bench sent it differently", which is the
// one conclusion this row must never support.
func publishCurveControl(ctx context.Context, d *Driver, params map[string]string, b *curveBinding, mrid string) error {
	pub, err := d.PostCurveDetail(ctx, CurveRequest{
		Program: 0, Mode: b.Mode, Points: b.Points, YRefType: b.YRefType,
		XMult: b.XMult, YMult: b.YMult,
		Description: "certify " + b.Mode,
		// The oracled window, not curveMode's old 180 s: the PostWait oracle
		// can read the DER anywhere out to wait+settle (see oracleWindow), and
		// a control that released under that read would convert a correct
		// device into a false FAIL at the late edge.
		DurationS: oracleWindow.durationS, StartOffset: oracleWindow.startOffsetS, Activate: true,
	})
	if err != nil {
		return err
	}
	if pub.CurveHref != "" {
		params[curveHrefParam] = pub.CurveHref
	}
	if pub.CurveMRID != "" {
		params[curveResourceParam] = pub.CurveMRID
	}
	if pub.MRID == "" {
		params[curveMRIDNoteParam] = "the server returned no mRID for the curve-bound control it created, so " +
			"this row's wire criteria fall back to the row's own synthetic mRID (" + mrid + ") and will not " +
			"find it: the correlation is unavailable, not satisfied"
		return nil
	}
	params["mrid"] = pub.MRID
	params[curveMRIDNoteParam] = "the curve-bound control's mRID is the SERVER's (" + pub.MRID + "), not this " +
		"row's synthetic " + mrid + ": gridsim mints it for a POST /admin/curve and ignores any mRID the " +
		"request carries, so every wire criterion on this row binds the minted one"
	return nil
}

// curveOutcome collapses everything the live phase recorded about a curve row
// into ONE decided verdict — the same job oracleOutcome does for the scalar
// oracled rows, over the same Observation.Params keys, in the vocabulary of a
// curve.
//
// It is a separate function rather than a parameterisation of oracleOutcome
// because the two say materially different things: a scalar row reports a
// value that moved, a curve row reports a piecewise function that was adopted
// into an enabled register bank. Sharing the prose would make one of the two
// bundles lie about what was measured.
func curveOutcome(o *Observation) Finding {
	post := o.Params[oracleObservedParam]
	pre := o.Params[oraclePreObservedParam]
	published := orText(o.Params[curvePublishedParam], "the breakpoints this row published")

	if reason := o.Params[oracleUnavailableParam]; reason != "" {
		return Finding{Verdict: certify.Fail, Observed: "the independent southbound oracle could not read the " +
			"DER's own curve registers at all: " + reason + " — and an oracle that cannot read the DER " +
			"cannot certify that a curve control was executed. This row FAILs on that unavailability rather " +
			"than skipping past it: the southbound read is the ONLY check in this suite that can tell a " +
			"gateway which ADOPTED this curve from one which refused the axis and answered the head end anyway"}
	}
	switch verdict := certify.Verdict(o.Params[oracleVerdictParam]); {
	case verdict == "":
		return Finding{Verdict: certify.Fail, Observed: "the live phase left no southbound curve-oracle result " +
			"behind at all — neither a verdict (" + oracleVerdictParam + ") nor a reason it could not reach " +
			"one (" + oracleUnavailableParam + ") is recorded, so the oracle either never ran or its result " +
			"was lost. An unrecorded criterion is not a satisfied one"}
	case verdict != certify.Pass:
		if post == "" {
			post = "the oracle recorded no observation with its " + string(verdict)
		}
		return Finding{Verdict: verdict, Observed: post}
	}
	switch certify.Verdict(o.Params[oraclePreVerdictParam]) {
	case certify.Fail:
		return Finding{Verdict: certify.Pass, Observed: "the DER did NOT hold this row's curve before it was " +
			"published (" + pre + ") and DOES hold it after the DUT's poll cycle (" + post + ") — the " +
			"adopted curve MOVED to " + published + ", so the match is evidence this control was executed, " +
			"not a curve an earlier run left in the register bank"}
	case certify.Pass:
		return Finding{Verdict: certify.Fail, Observed: "the DER holds this row's curve (" + post + ") but " +
			"ALREADY held it before this row published anything (" + pre + "). A curve row has no ladder to " +
			"depart onto — its content is the content the row is about — so nothing in this reading " +
			"distinguishes a curve the DUT fetched and adopted from one left over from an earlier run, and " +
			"it is not reported as a PASS"}
	default:
		return Finding{Verdict: certify.Warn, Observed: "the DER holds this row's curve (" + post + "), but " +
			"the pre-publication baseline was not recovered (" + orText(pre, "no reading was recorded") +
			"), so this run cannot show that the adopted curve CHANGED. The content is right; that it was " +
			"THIS row's control that put it there is not established"}
	}
}

// critDEREffectViaCurveOracle is critDEREffectUnobservable's replacement on a
// curve-linked row. Like its scalar sibling it carries NO Skip path: every
// shape the live phase can leave behind comes back from curveOutcome as a
// decided verdict, because a Skip cannot dent a case verdict and so cannot hold
// a release.
func critDEREffectViaCurveOracle(subject string, b *curveBinding, o *Observation) criterion {
	f := curveOutcome(o)
	return criterion{
		Claim: "the DER's own southbound registers hold the curve " + subject + " carried, adopted and enabled",
		How: fmt.Sprintf("an independent read of the DER's raw SunSpec %s image (internal/invariant, which "+
			"shares only the register-offset tables with the product and none of its CSIP/derbase "+
			"interpretation), taken BEFORE this row published its curve and again after the DUT's poll "+
			"cycle: the model's own adopt handshake (AdptCrvRslt), its function enable (Ena) and the "+
			"breakpoints of its LIVE (index 0) curve, compared point for point and IN ORDER against the "+
			"breakpoints this row itself published — raw values as published, with no axis "+
			"re-interpretation by this referee. %s. The device sims model curve ADOPTION but no curve "+
			"PHYSICS, so this is a register/adopt-state assertion and deliberately not an "+
			"effect-on-output one", curveModelLabel(b), b.Mapping),
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}

func curveModelLabel(b *curveBinding) string {
	if axis, ok := invariant.CurveAxisOf(b.Model); ok {
		return axis.Name
	}
	return fmt.Sprintf("M%d", b.Model)
}

// critDERCurveResolvable asserts that the DERCurve resource this row's control
// LINKS is one the DUT could actually fetch.
//
// It exists because a curve-linked DERControl carries an href, not content: a
// control whose curve href answers 404 delivers nothing to the DUT however
// perfect the control itself is, and the resulting southbound silence is a
// BENCH gap wearing the DUT's clothes. The 2026-08-14 sim-surface sub-audit
// found exactly that shape on this server (individual DERCurve hrefs 404), so
// the row says which of the two it is instead of leaving a reader to guess.
//
// Unavailable — not FAIL — when the DUT never fetched the href at all: a DUT
// that refuses the axis at receipt has no reason to resolve the curve, and
// grading that as a bench 404 would blame the wrong party. The southbound
// oracle is what carries this row's teeth; this criterion only disambiguates.
func critDERCurveResolvable(href string) criterion {
	return criterion{
		Claim: "the DERCurve resource this row's DERControl links resolves for the DUT",
		How: "a GET on " + href + " in the recovered transcript, and the status line the server answered " +
			"it with",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.Method("GET") {
				if e.Req == nil || e.Resp == nil || !strings.HasSuffix(e.Req.Target, href) {
					continue
				}
				if e.Resp.Status/100 == 2 {
					return citeExchange(t, e, certify.Pass, "GET %s answered %s", e.Req.Target, e.Resp.Line())
				}
				return citeExchange(t, e, certify.Fail,
					"GET %s answered %s — the control this row published links a curve resource the server "+
						"does not serve, so the DUT received a link and no curve content. This is a BENCH "+
						"authoring gap, not a DUT defect, and it makes any southbound silence for this row "+
						"unattributable until it is closed", e.Req.Target, e.Resp.Line())
			}
			return unavailable("the DUT issued no GET for %s in this window, so whether the link resolves was "+
				"not exercised (a DUT that refuses this axis at receipt has no reason to fetch the curve)", href)
		},
	}
}

// ── Refused-axis rows ───────────────────────────────────────────────────────

// refusalBinding is what a REFUSED-axis row carries: the axis the control names,
// the 704 points a write of that axis would land on, and the control that names
// it.
//
// A refusal row asserts the OPPOSITE of an execution row, and it is a
// materially different check rather than a negated one. An execution oracle
// asks "does the DER hold what was commanded?"; wired to an axis the product
// correctly refuses it would FAIL every conformant DUT (see oracleTargetW's own
// doc, which flagged exactly this and stopped). This asks two questions
// instead:
//
//	the DUT answered the head end that it cannot comply — not Started, not
//	Completed; and
//
//	NOTHING of that axis moved in the DER's own registers during the row's
//	window.
//
// Both must hold. A gateway that answers CannotComply and writes the setpoint
// anyway is lying to the head end; one that writes nothing but reports Started
// is lying about execution. Either alone would let one of the two through.
type refusalBinding struct {
	// Axis is the human label of the refused axis, for the criterion's prose.
	Axis string
	// Points are the 704 command points a write of this axis would land on
	// (internal/invariant's DecodeCommands vocabulary).
	Points []string
	// Commanded describes what the control asked for, in the row's own terms.
	Commanded string
	// Why records why this product refuses the axis, so the row's PASS says
	// what it is a PASS of.
	Why string
	// Publish puts the refused control on the wire under this row's mRID.
	// nil exactly when Curve is set — a curve-axis refusal publishes through
	// publishCurveControl instead, so that it and an EXECUTION curve row put
	// materially identical controls on the wire.
	Publish func(ctx context.Context, d *Driver, mrid string) error

	// Curve, when set, makes this a CURVE-axis refusal instead of a scalar one,
	// and changes what "nothing moved" is measured over: a refused curve axis
	// would land in a curve MODEL (its adopt handshake, its enable and its live
	// breakpoints), not on a 704 setpoint register, so Points above is empty and
	// the fingerprint is the curve bank's whole state.
	//
	// WHY A REFUSAL ROW PUBLISHES A REAL, WELL-FORMED CURVE. The row's claim is
	// that the DUT refuses this AXIS. A malformed or unresolvable curve would
	// also draw a refusal, and the two are indistinguishable from the outside —
	// so the control has to be one that a DUT which supported the axis would
	// have executed. That is why the publisher is shared with the execution
	// rows and why critDERCurveResolvable still runs on this row: it separates
	// "refused the axis" from "could not fetch the curve".
	Curve *curveBinding
}

// fingerprint renders the state a write of this refused axis would have moved,
// so two readings taken minutes apart can be compared for ANY movement.
//
// The two shapes measure different register banks because a refused axis lands
// in different places depending on what kind of axis it is, and measuring the
// wrong bank would report an absence that was never in question.
func (b *refusalBinding) fingerprint(uv invariant.UnitView) (string, bool) {
	if b.Curve == nil {
		return refusalFingerprint(uv, b.Points)
	}
	cv := uv.Curve(oracleSimName, b.Curve.Model)
	if !cv.Present {
		// Same posture as the scalar shape's empty-points case: a bank we
		// cannot read cannot tell a refused axis from an unreadable one.
		return "", false
	}
	// The LIVE curve is not the whole bank, and a refusal row is the one caller
	// for which that matters. An execution oracle reads index 0 alone on
	// purpose — content in staging is a curve the device was OFFERED, not one it
	// adopted, and grading it as executed would accept the half-completed write
	// the adopt handshake exists to distinguish. But this row asserts that NO
	// WRITE LANDED, and a gateway that stages a refused curve and never triggers
	// the handshake has still written to an axis it told the head end it could
	// not perform. Reading only index 0 would report that as an untouched
	// device.
	//
	// The handshake registers alone do not cover it: they move when the gateway
	// ASKS the device to adopt, so they catch stage-then-adopt and are blind to
	// stage-and-stop.
	parts := []string{cv.Describe()}
	for i := 1; i < cv.NCrv && i <= maxStagingCurvesFingerprinted; i++ {
		parts = append(parts, uv.CurveAt(oracleSimName, b.Curve.Model, i).Describe())
	}
	if cv.NCrv > maxStagingCurvesFingerprinted+1 {
		parts = append(parts, fmt.Sprintf("(%d further staging curve(s) not fingerprinted)",
			cv.NCrv-maxStagingCurvesFingerprinted-1))
	}
	return strings.Join(parts, " | "), true
}

// maxStagingCurvesFingerprinted bounds how much of a curve bank the refusal
// fingerprint renders. A device declares its own NCrv and nothing stops it
// declaring a large one; the fingerprint is a STRING that lands in a bundle, so
// it needs a bound that does not depend on the device's honesty. Devices this
// bench grades declare NCrv=2 (one live, one staging), so the practical cost of
// the bound is nil — and when it does bite, the fingerprint says so rather than
// silently truncating.
const maxStagingCurvesFingerprinted = 4

// describeAxisRegisters names what the fingerprint above covers, for the
// criterion's How and for an unavailability message.
func (b *refusalBinding) describeAxisRegisters() string {
	if b.Curve == nil {
		return strings.Join(b.Points, ", ")
	}
	return curveModelLabel(b.Curve) + " (adopt handshake, function enable, DeptRef, and the breakpoints " +
		"of BOTH the live curve and the writable staging curves)"
}

// refusalFingerprint renders the exact state of the axis's registers — raw
// value, enable, and the mode enum that selects between them — so two readings
// taken minutes apart can be compared for ANY movement, not only for movement
// towards the commanded value.
//
// Comparing fingerprints rather than "does it hold the commanded number" is
// deliberate. A gateway that half-executes a refused axis — writes the enable,
// or writes a value the arbitration then clamped, or flips WSetMod on its way
// to giving up — has written to an axis it told the head end it could not
// perform, and every one of those is a landing this row must catch. Equality of
// the whole fingerprint is the only statement that covers them.
func refusalFingerprint(uv invariant.UnitView, points []string) (string, bool) {
	want := map[string]bool{}
	for _, p := range points {
		want[p] = true
	}
	var parts []string
	for _, c := range uv.Commands(oracleSimName) {
		if !want[c.Point] {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s %s(%s=%d)", c.Point, c.Raw,
			enabledLabel(c.Enabled), orText(c.ModePoint, "mode"), c.ModeVal))
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, ", "), true
}

func enabledLabel(on bool) string {
	if on {
		return "ENABLED"
	}
	return "disabled"
}

// oracleRefusal builds the southbound half of a refusal row: it re-reads the
// axis's registers and reports whether ANYTHING there has moved since the
// baseline the row recorded before it published.
//
// A Fail here means a write landed on an axis the DUT was supposed to refuse.
// Everything else is Pass — with one exception the caller decides, not this
// closure: a baseline that ALREADY held the commanded content makes the whole
// window uninformative, which refusalOutcome reports rather than passing.
//
// THAT EXCEPTION WAS A CLAIM THIS FILE MADE AND DID NOT KEEP until 2026-08-15.
// refusalOutcome had no such guard, so a DUT that had landed the refused
// content BEFORE the row's window — a regression left by an earlier run, or a
// leak from a preceding row — fingerprinted as "nothing moved" and certified as
// a clean refusal on every rerun. The failure mode is the nastier direction: the
// worse the contamination, the more reliably the row passed.
//
// It is now kept for the CURVE shape, where "already holds this row's content"
// is precisely computable — oracleCurve answers exactly that question about
// exactly these breakpoints. It is NOT kept for the scalar shape, and that is a
// bounded gap rather than an oversight: refusalBinding.Commanded is prose, not a
// value, so there is nothing to compare a baseline against, and the obvious
// proxy — "the axis is already ENABLED" — would fail BASIC-014 in every
// campaign, because BASIC-013 runs immediately before it, commands opModFixedW,
// and legitimately leaves WSet/WSetPct enabled on the very points BASIC-014
// fingerprints (oracleFixedW reads the same two). Closing it needs a commanded
// VALUE on the scalar binding, which is oracleBinding's shape and a separate
// change.
func oracleRefusal(b *refusalBinding, baseline string) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		got, ok := b.fingerprint(uv)
		if !ok {
			return unavailable("the DER's own register image carries nothing a write of %s would land on "+
				"(%s), so this row cannot tell a refused axis from an unreadable one",
				b.Axis, b.describeAxisRegisters())
		}
		if baseline == "" {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"no pre-publication baseline of %s was recorded, so this reading (%s) cannot show that "+
					"nothing moved — an unestablished starting state cannot certify an absence", b.Axis, got)}
		}
		if got != baseline {
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"a southbound write of %s LANDED on the DER during this row's window, on an axis the DUT is "+
					"supposed to have refused: the registers read %s before this row published its control "+
					"and %s after the DUT's poll cycle. This row commanded %s. A gateway that answers the "+
					"head end that it cannot comply and then writes the axis anyway has told the head end "+
					"one thing and the device another",
				b.Axis, baseline, got, b.Commanded)}
		}
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"nothing of %s moved in the DER's own registers across this row's window: they read %s both "+
				"before this row published its control and after the DUT's poll cycle, so the refusal left "+
				"no southbound trace. %s", b.Axis, got, b.Why)}
	}
}

// refusalOutcome collapses a refusal row's live-phase record into one decided
// verdict, the way oracleOutcome and curveOutcome do for the execution rows.
//
// It takes the BINDING as well as the observation, which curveOutcome does not
// need to, because whether the baseline-contamination guard applies is a
// property of the ROW (a curve refusal can compute it; a scalar one cannot —
// see oracleRefusal) and not of whether some param happens to be present. An
// absent param must not be the thing that decides whether a check runs.
func refusalOutcome(b *refusalBinding, o *Observation) Finding {
	if reason := o.Params[oracleUnavailableParam]; reason != "" {
		return Finding{Verdict: certify.Fail, Observed: "the independent southbound oracle could not read the " +
			"DER at all: " + reason + " — and an oracle that cannot read the DER cannot certify that a " +
			"refused axis was left untouched. This row FAILs on that unavailability rather than skipping " +
			"past it: an unobserved absence is not an observed one"}
	}
	switch verdict := certify.Verdict(o.Params[oracleVerdictParam]); {
	case verdict == "":
		return Finding{Verdict: certify.Fail, Observed: "the live phase left no southbound refusal-oracle " +
			"result behind at all — neither a verdict (" + oracleVerdictParam + ") nor a reason it could " +
			"not reach one (" + oracleUnavailableParam + ") is recorded. An unrecorded criterion is not a " +
			"satisfied one"}
	case verdict != certify.Pass:
		return Finding{Verdict: verdict,
			Observed: orText(o.Params[oracleObservedParam], "the oracle recorded no observation with its "+
				string(verdict))}
	}
	// Nothing MOVED. That is only evidence of a refusal if the thing this row
	// refuses was not already there when the row started — see oracleRefusal's
	// doc for why this guard exists and why it is curve-only.
	if b != nil && b.Curve != nil {
		post := o.Params[oracleObservedParam]
		pre := orText(o.Params[oraclePreObservedParam], "no pre-publication reading was recorded")
		switch certify.Verdict(o.Params[oraclePreVerdictParam]) {
		case certify.Pass:
			return Finding{Verdict: certify.Fail, Observed: "THE BASELINE WAS CONTAMINATED: the DER " +
				"ALREADY held this row's own " + b.Curve.Mode + " content, adopted and enabled, BEFORE " +
				"this row published anything (" + pre + "). Nothing moved during the window (" + post +
				") — and nothing could have, because the refused content was already there. This row " +
				"cannot prove a refusal against a device that is executing the very thing it is supposed " +
				"to have refused: an unchanged reading distinguishes a DUT that refused the control from " +
				"one that landed it on an earlier run only if the starting state was clean. REMEDY: clear " +
				"the DER's curve bank before the row runs — DELETE /admin/curve (Driver.ClearCurves) " +
				"clears only the CSIP-side control and curve, not the device's registers, so this needs a " +
				"fresh sim (the modsim /control reset resumes the animation and does not reset the " +
				"register image) or a bench lever that resets model " +
				strconv.FormatUint(uint64(b.Curve.Model), 10) + ". Until then this is reported as a FAIL " +
				"rather than a PASS, because an uninformative window is not an observed absence"}
		case certify.Fail:
			// The clean case: the DER did NOT hold this row's content before the
			// window, and still does not. The absence means something.
		default:
			return Finding{Verdict: certify.Fail, Observed: "the pre-publication reading of the " +
				b.Curve.Mode + " bank was not recovered (" + pre + "), so this run cannot show that the " +
				"baseline was clean. Nothing moved during the window (" + post + "), but an unchanged " +
				"reading is only evidence of a refusal against a starting state that was established — " +
				"an unestablished one cannot certify an absence, the same posture this row already takes " +
				"for a missing fingerprint baseline"}
		}
	}
	return Finding{Verdict: certify.Pass, Observed: o.Params[oracleObservedParam]}
}

// critRefusedAxisNoSouthboundTrace is the refusal row's southbound criterion:
// the DER shows no trace of the axis the DUT refused.
func critRefusedAxisNoSouthboundTrace(b *refusalBinding, o *Observation) criterion {
	f := refusalOutcome(b, o)
	return criterion{
		Claim: "no southbound write of " + b.Axis + " reached the DER while this row's refused control was live",
		How: "an independent read of the DER's own raw SunSpec image (internal/invariant, which shares only " +
			"the register-offset tables with the product and none of its CSIP/derbase interpretation), " +
			"taken BEFORE this row published its control and again after the DUT's poll cycle: " +
			b.describeAxisRegisters() + " is fingerprinted and compared for ANY movement, not only for " +
			"movement towards the commanded value",
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}

// refusalStatuses are the Response statuses that constitute an honest refusal.
//
// IEEE 2030.5 Table 27 has no "cannot comply" status; a client that cannot
// perform a control has to say so in the vocabulary that exists. This product
// answers 8 (event partially completed / opted out) at receipt, and keeps a
// legacy mode that answers the manufacturer-range 0xF0 the LEXA profile
// defined for the same meaning (lexa-proto csipmodel's ResponseCannotComply,
// and lexa-gw's responses tracker: `code := model.ResponsePartialOptOut; if
// rt.legacyCannotComply { code = model.ResponseCannotComply }`). BOTH are
// accepted here, because which one is on the wire is a configuration of the
// DUT and not a conformance property of the refusal.
var refusalStatuses = []uint8{8, 0xF0}

// refusalForbiddenStatuses are the answers that make a refusal dishonest: an
// execution signal for a control the DUT did not (and must not) execute.
var refusalForbiddenStatuses = map[uint64]string{
	2: "Event started",
	3: "Event completed",
}

// critRefusalAnswered asserts the DUT told the head end it could not comply
// with this row's control — and did NOT tell it the event started or completed.
//
// The forbidden half is the load-bearing half. A DUT that silently drops an
// axis it cannot execute and reports Started is the LXR-002 defect verbatim:
// the head end receives an execution signal for a control nothing ever
// executed. That is the shape this criterion has to be able to catch, and a
// criterion that only looked for the refusal status would grade a DUT that sent
// BOTH as compliant.
func critRefusalAnswered(mridKey string) criterion {
	return criterion{
		Claim: "the DUT answered this row's control with a cannot-comply Response, and never reported it " +
			"started or completed",
		How: "the sep+xml body of every Response-family POST in the session whose <subject> is this row's " +
			"own mRID, and the <status> each carried: a refusal status (8 partial-opt-out, or the LEXA " +
			"profile's 0xF0) must be present and neither 2 (Event started) nor 3 (Event completed) may be",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			var seen []string
			var refused, forbidden *Message
			var forbiddenWhat string
			for _, e := range t.Method("POST") {
				if e.Req == nil || len(e.Req.Body) == 0 {
					continue
				}
				doc, err := e.Req.SEP()
				if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
					continue
				}
				subj, _ := doc.TextOf("subject")
				if subj != mridKey {
					continue
				}
				st, _ := doc.UintOf("status")
				seen = append(seen, fmt.Sprintf("status=%d", st))
				if what, bad := refusalForbiddenStatuses[st]; bad && forbidden == nil {
					forbidden, forbiddenWhat = e.Req, what
				}
				for _, ok := range refusalStatuses {
					if st == uint64(ok) && refused == nil {
						refused = e.Req
					}
				}
			}
			switch {
			case forbidden != nil:
				return citeMessage(t, forbidden, certify.Fail,
					"the DUT reported <status>%s</status> for this row's control (mRID=%s) — an EXECUTION "+
						"signal for an axis this product does not execute. The head end has been told the "+
						"control ran. Every Response this row's control drew: %s",
					forbiddenWhat, mridKey, strings.Join(seen, ", "))
			case refused != nil:
				return citeMessage(t, refused, certify.Pass,
					"the DUT answered this row's control (mRID=%s) with a cannot-comply Response and "+
						"reported neither started nor completed; the Responses it sent were: %s",
					mridKey, strings.Join(seen, ", "))
			case len(seen) > 0:
				return found(certify.Fail, allFrames(t.Method("POST")),
					"the DUT POSTed %d Response(s) for this row's control (mRID=%s) and none of them says it "+
						"cannot comply: %s. A control whose axis the DUT cannot execute has to be answered, "+
						"not left on an acknowledgement",
					len(seen), mridKey, strings.Join(seen, ", "))
			default:
				return unavailable("the recovered transcript holds no Response POST for subject %s", mridKey)
			}
		},
		Server: func(v *ServerView) Finding {
			got := v.ResponsesFor(mridKey)
			if len(got) == 0 {
				if !v.SessionEstablished() {
					return noSessionUnavailable()
				}
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"gridsim received no Response POST at all for this row's control (mRID=%s), so the head "+
						"end was never told the DUT could not comply", mridKey)}
			}
			var statuses []string
			var refused bool
			for _, r := range got {
				statuses = append(statuses, fmt.Sprintf("status=%d", r.Status))
				if what, bad := refusalForbiddenStatuses[uint64(r.Status)]; bad {
					return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
						"gridsim received a Response reporting %q for this row's control (mRID=%s) — an "+
							"execution signal for an axis this product does not execute. All: %s",
						what, mridKey, strings.Join(statuses, ", "))}
				}
				for _, ok := range refusalStatuses {
					if r.Status == ok {
						refused = true
					}
				}
			}
			if refused {
				return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
					"gridsim received a cannot-comply Response for this row's control (mRID=%s) and no "+
						"started/completed: %s", mridKey, strings.Join(statuses, ", "))}
			}
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"gridsim received %d Response(s) for this row's control (mRID=%s), none saying it cannot "+
					"comply: %s", len(got), mridKey, strings.Join(statuses, ", "))}
		},
	}
}

// refusalSetup is a refusal row's Setup: fingerprint the axis BEFORE anything
// is published, so the post-read has a baseline to be an absence against, then
// publish the control the DUT is expected to refuse.
func refusalSetup(ctx context.Context, d *Driver, params map[string]string, b *refusalBinding, mrid string) error {
	params[refusalAxisParam] = b.Axis
	if uv, err := oracleUnitView(ctx, d.rc, oracleSimName); err == nil {
		if fp, ok := b.fingerprint(uv); ok {
			params[refusalBaselineParam] = fp
			params[oraclePreObservedParam] = fp
		} else {
			params[oraclePreObservedParam] = "the DER's own register image carries nothing of " +
				b.describeAxisRegisters()
		}
	} else {
		params[oraclePreObservedParam] = "the baseline reading could not be taken: " + err.Error()
	}
	if b.Curve != nil {
		params[curvePublishedParam] = b.Curve.describePublished()
		params[curveModelParam] = strconv.FormatUint(uint64(b.Curve.Model), 10)
		// The CONTAMINATION read, and it is a different question from the
		// fingerprint above. The fingerprint asks "what does this bank hold?",
		// so it can detect MOVEMENT; this asks "does it already hold the
		// content this row is about?", which is the only thing that can tell a
		// refusal from a device that was already executing the refused control
		// when the row started. Recorded under the same key curveSetup uses, and
		// read by refusalOutcome exactly as curveOutcome reads it.
		pre := oracleCurve(b.Curve)(ctx, d.rc)
		params[oraclePreVerdictParam] = string(pre.Verdict)
		params[oraclePreObservedParam] = findingObserved(pre)
		return publishCurveControl(ctx, d, params, b.Curve, mrid)
	}
	return b.Publish(ctx, d, mrid)
}

// settleRefusal is settleOracle's mirror image, and the difference is the whole
// point of it.
//
// settleOracle waits for an effect to APPEAR and returns the moment it does: a
// Pass short-circuits, because an effect once observed cannot be un-observed.
// A refusal asserts an ABSENCE, and an absence observed early is worth nothing
// — the southbound write this row must catch lands on the reconciler's own
// tick, which is exactly the beat settleOracle exists to wait out. So this
// polls the WHOLE window and returns early only on a decided FAIL (a landing
// caught in the act). An Unavailable is retried, as it is there, and the last
// reading is what the deadline returns.
func settleRefusal(ctx context.Context, window, step time.Duration, eval func() Finding) Finding {
	deadline := time.Now().Add(window)
	last := eval()
	for last.Verdict != certify.Fail && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return last
		case <-time.After(step):
		}
		last = eval()
	}
	return last
}

// ── Unauthorable rows ───────────────────────────────────────────────────────

// critModeUnauthorable replaces the honest-looking SKIP a row used to carry
// when this bench has no lever for its control mode.
//
// A SKIP was the wrong shape and it hid a real gap for as long as it existed.
// The row's claim is that the DUT received and applied a control carrying this
// mode; nothing on this bench can put that mode on the wire, so the claim was
// never tested — and because Skip is the lowest severity in the roll-up, a row
// that tested nothing reported the same verdict as a row that tested everything
// and passed. Three rows of a twelve-row family certified that way.
//
// It is a FAIL rather than a WARN because the consequence is the same as a
// failure: a conformance bundle that claims these rows were exercised is wrong,
// and a reader has to be stopped rather than nudged. It is a BENCH gap, not a
// DUT defect, and the Observed text says so in its first sentence so nobody
// files it against the product.
func critModeUnauthorable(subject, element, why string) criterion {
	observed := "this row was NOT tested: no lever on this bench can place <" + element + "> on the wire, so " +
		"the DUT was never offered the control this row is about and nothing here is evidence about the " +
		"DUT. This is a BENCH capability gap, not a defect of the device under test — but it is reported " +
		"as a FAIL rather than skipped, because an untested row must not roll up as a passing one (a SKIP " +
		"is the lowest severity in the verdict roll-up and cannot hold a release). The gap: " + why
	return criterion{
		Claim: "the DUT received and applied a DERControl carrying " + subject,
		How: "the presence of a <" + element + "> element inside a DERControlBase the DUT fetched — which " +
			"this bench cannot produce; see the observation",
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return Finding{Verdict: certify.Fail, Observed: observed}
		},
	}
}

// critEffectBlockedByAuthoringGap is the southbound half of the same gap: with
// no control on the wire there is nothing for a southbound oracle to look for,
// so the DER's registers cannot answer this row's question either.
func critEffectBlockedByAuthoringGap(subject, element string) criterion {
	observed := "no southbound reading can settle this claim, because no control carrying <" + element +
		"> was ever placed on the wire for the DER to respond to (see the criterion above). The independent " +
		"southbound oracle this suite runs for the executable modes has nothing to correlate against here; " +
		"reporting that as anything but a FAIL would let an untested row certify itself"
	return criterion{
		Claim: "the DER's own southbound registers reflect " + subject,
		How: "an independent read of the DER's own SunSpec registers, correlated against the control this " +
			"row published — which, for this row, does not exist",
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return Finding{Verdict: certify.Fail, Observed: observed}
		},
	}
}
