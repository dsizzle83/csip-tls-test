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
	Publish func(ctx context.Context, d *Driver, mrid string) error
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
// closure: a baseline that ALREADY held the commanded value makes the whole
// window uninformative, which refusalOutcome reports rather than passing.
func oracleRefusal(b *refusalBinding, baseline string) func(ctx context.Context, rc *certify.RunCtx) Finding {
	return func(ctx context.Context, rc *certify.RunCtx) Finding {
		uv, err := oracleUnitView(ctx, rc, oracleSimName)
		if err != nil {
			return unavailable("%v", err)
		}
		got, ok := refusalFingerprint(uv, b.Points)
		if !ok {
			return unavailable("the DER's own 704 image carries none of the points a write of %s would land "+
				"on (%s), so this row cannot tell a refused axis from an unreadable one",
				b.Axis, strings.Join(b.Points, ", "))
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
func refusalOutcome(o *Observation) Finding {
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
	return Finding{Verdict: certify.Pass, Observed: o.Params[oracleObservedParam]}
}

// critRefusedAxisNoSouthboundTrace is the refusal row's southbound criterion:
// the DER shows no trace of the axis the DUT refused.
func critRefusedAxisNoSouthboundTrace(b *refusalBinding, o *Observation) criterion {
	f := refusalOutcome(o)
	return criterion{
		Claim: "no southbound write of " + b.Axis + " reached the DER while this row's refused control was live",
		How: "an independent read of the DER's raw SunSpec 704 image (internal/invariant, which shares only " +
			"the register-offset tables with the product and none of its CSIP/derbase interpretation), " +
			"taken BEFORE this row published its control and again after the DUT's poll cycle: the raw " +
			"value, the enable and the selecting mode enum of " + strings.Join(b.Points, "/") + " are " +
			"fingerprinted and compared for ANY movement, not only for movement towards the commanded value",
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
		if fp, ok := refusalFingerprint(uv, b.Points); ok {
			params[refusalBaselineParam] = fp
			params[oraclePreObservedParam] = fp
		} else {
			params[oraclePreObservedParam] = "the DER's own 704 image carries none of " +
				strings.Join(b.Points, "/")
		}
	} else {
		params[oraclePreObservedParam] = "the baseline reading could not be taken: " + err.Error()
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
