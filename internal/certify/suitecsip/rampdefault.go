package suitecsip

// rampdefault.go — BASIC-007 (Ramp Rates), CSIP CTP v1.3.
//
// # Why this row is not in the BASIC-004..015 family's own machinery
//
// Every other row in that family (basic.go's controlMode / inverterControlSpec)
// is built around ONE shape: publish a scheduled DERControl EVENT under an mRID,
// wait for the DUT to answer it, and grade the Response lifecycle alongside
// whatever the event commanded. BASIC-007 has none of that. CSIP CTP v1.3's own
// printed procedure states it plainly: "Control Type = Default-Only" (Figure 7's
// own row), no scheduled DERControl with a start/duration/responseRequired is
// defined in the setup, and step 4 / the Pass criterion asks only whether the
// Client "detected and activated the DefaultDERControl (Ramp rates)" — there is
// no event, no mRID for a Response to name, and "No DERControlResponse POST is
// required by this test's procedure" is the catalog's own observable. Bolting
// this onto inverterControlSpec would mean carving mRID/Response exceptions
// into machinery built for the opposite shape, which is exactly the kind of
// force-fit this suite's own precedent (ridethrough.go, directoracle.go) argues
// against — a genuinely different shape gets its own apparatus.
//
// # What WAS missing, and what it turned out not to be
//
// IW15-008/the standing "noRampRate" gap (register.go, now removed) held this
// row at a decided FAIL for two stated reasons: no lever on gridsim's
// POST /admin/default, and no gradient field anywhere in the shared
// lexa-proto/csipmodel for a server to marshal in the first place. The second
// half turned out to be avoidable rather than true: sim/gridsim/softgrad.go
// (added for a different reason — proving lexa-gw's GATE21-001 energize-ramp
// finding) carries setGradW/setSoftGradW on a gridsim-LOCAL wrapper type that
// embeds model.DefaultDERControl and adds the two elements as siblings — the
// same technique lexa-gw's OWN read side already uses
// (internal/northbound/discovery/walker.go's extendedDefaultDERControlDoc), so
// neither side needed a csipmodel change at all. The admin lever
// (set_grad_w/set_soft_grad_w on POST /admin/default) already existed; it had
// simply never been driven from a catalog row. This file drives it.
//
// # What the product side already had, confirmed before writing any of this
//
// lexa-gw's execution path for BOTH elements was already fully wired, in
// source, before this file existed:
//
//   - setGradW → 704's WRmp rate register. internal/authority/csipin_ramp.go's
//     resolveDefaultRampWPerS/rampWPerSToPct convert the wire value (already
//     decoded to percent-of-setMaxW-per-second by internal/northbound/publish's
//     ToActiveControlAt, /100 off the raw PerCent) straight through — the
//     nameplate cancels algebraically, so setGradW=9000 (90.00%) lands as
//     WRmp=90 with no unit ambiguity. csipin.go:913/1160 attaches this to
//     EVERY desired solar-ceiling document the reconciler builds from a
//     DefaultDERControl, whether or not an active event is also in force —
//     csipin.go's own comment: "SetGradW is deliberately NOT part of [the
//     ramp-inexact disclosure] test: ... WRmp is a rate register, and that
//     path is executed exactly — it is not declined and gets no terminal."
//     So this half is genuinely, continuously executed and independently
//     observable with no event needed at all.
//
//   - setSoftGradW → 703's ESRmpTms soft-start ramp. cmd/modbus/reconcile_adv.go
//     resolveEnergizeRampS (100/setSoftGradW seconds) feeds
//     SetEnergizeWithRamp — BUT ONLY when the composed control also carries an
//     actual opModEnergize transition (reconcile_adv.go:1742 `if
//     doc.Energize != nil`). BASIC-007's own printed procedure schedules no
//     such transition — it is Default-Only, and no enter-service event is
//     part of its setup — so the register that would prove this half executed
//     structurally never gets written DURING THIS ROW'S OWN PROCEDURE. This
//     is not a product gap: sim/gridsim/softgrad.go's own commit message
//     records that the SAME setSoftGradW→ESRmpTms path was already
//     bench-proven end-to-end for GATE21-001, under a scenario that DID
//     command an energize transition. BASIC-007 simply is not that scenario.
//     The oracle below reports ESRmpTms's value but does not grade it, and
//     says exactly why.
//
// Nothing in lexa-proto needed to change, and nothing in lexa-gw needed to
// change. This file is a harness-only wave: the gridsim lever was reachable,
// the product's execution path was already proven, and what was missing was a
// catalog row that drove the one and observed the other's real boundary.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/invariant"
	"lexa-proto/sunspec"
)

// rampDefaultProgram is the gridsim DERProgram index CSIP CTP v1.3 BASIC-007's
// own precondition 5c names: "The Service Point DERProgram shall have a
// DefaultDERControl instance with ramp rate setting values" — Figure 3's
// primacy=1, closest-to-DER, highest-priority program, which is gridsim's own
// program 0 (sim/gridsim/server.go's buildProgram0).
const rampDefaultProgram = 0

// rampDefaultFixtureExpLimW is program 0's own pre-existing DefaultDERControl
// content: sim/gridsim/server.go's buildProgram0 seeds
// "/derp/0/dderc" with OpModExpLimW=5000 ("Default: export limit 5kW").
//
// POST /admin/default REPLACES a program's WHOLE DERControlBase on every call
// (sim/gridsim/admin.go's putDefaultBaseLocked doc: "A POST REPLACES this
// program's DERControlBase — it always has"), so a request naming only the
// ramp fields would silently erase the fixture's export limit for as long as
// this row's precondition stands. This row's Setup carries the fixture's own
// value forward explicitly so its precondition ADDS the ramp settings rather
// than replacing what was already there, and Cleanup restores exactly this —
// leaving the tree as buildProgram0 left it, the same discipline
// putDefaultBaseLocked's own "CLEAR NARROWS IT BACK, deliberately" comment
// describes for a droopless POST.
const rampDefaultFixtureExpLimW = int64(5000)

// figure7RampTestSetGradW / figure7RampTestSetSoftGradW are CSIP CTP v1.3
// BASIC-007's Figure 7 (Ramp Rates Settings), TEST VALUES column: setGradW
// 9000 (against a stated Default of 10000, i.e. 100%→90%), setSoftGradW 400
// (against a stated Default of 200, i.e. 2%→4%). Both are IEEE 2030.5's
// PerCent — hundredths of a percent — the raw wire unit both gridsim's
// admin lever (sim/gridsim/softgrad.go) and lexa-gw's own DefaultDERControl
// reader (internal/northbound/discovery/walker.go's
// extendedDefaultDERControlDoc) take.
//
// This row now proves a TRANSITION into the Test Value rather than merely
// matching it: rampDefaultFirstSetup drives the DER through a distinguishable
// baseline first (the IW15-004 default-first discipline BASIC-013 uses via
// scalarModeOracledDefaultFirst, applied to the ramp), so the post-read is
// evidence the DUT MOVED the register rather than a value an earlier row left
// behind. Unlike BASIC-013 the baseline is NOT the catalog's Default column
// (Figure 7's Default is setGradW=10000, WRmp=100); it is a harness-chosen
// distinguishing value (rampBaselineSetGradW) — see that constant's doc for why
// a distinct-from-target value is what register-state-independence requires, and
// CSIP-BENCH-BASIC007-ORACLE-STATE-CONTAMINATION for the campaign FAIL it fixes.
const (
	figure7RampTestSetGradW     = uint16(9000)
	figure7RampTestSetSoftGradW = uint16(400)
)

// rampBaselineSetGradW / rampBaselineSetSoftGradW are the DISTINGUISHABLE
// baseline this row drives the DER into BEFORE it commands Figure 7's Test
// Value — the register-state-independent starting point that fixes
// CSIP-BENCH-BASIC007-ORACLE-STATE-CONTAMINATION.
//
// The registered failure: in a FULL campaign a prior ramp-commanding row leaves
// the DER's model-704 WRmp already at the Figure-7 target (90), so a
// post-publication read of 90 is satisfied by the DUT doing nothing at all, and
// the oracle — correctly refusing to certify a stale register — reconciled this
// clean product to FAIL. In isolation the same row PASSES, because there the
// register started elsewhere and the move to 90 was real.
//
// The fix is the IW15-004 default-first discipline (basic.go's prescribedSetup,
// which BASIC-013 uses) applied to the ramp: drive the DER into a value it
// provably does NOT already hold, confirm that landing in its own registers on
// a fresh DUT poll, THEN command Figure 7's value and prove the register MOVED
// there. "Moved from a confirmed 50 to 90" is a transition only a live DUT
// tracking gridsim's DefaultDERControl can produce, whatever WRmp held when the
// row began.
//
// 5000 is chosen for the one property that matters: setGradW=5000 resolves to
// WRmp=50 (5000/100), which differs from the Figure-7 target (90) and from the
// absent-ramp fixture default (0) by far more than the oracle's ±1 register
// tolerance — so the baseline is always a value the DER did not already hold,
// on any nameplate, and the confirmed move to 90 is always observable. Unlike
// BASIC-013's default, this value is NOT the catalog's own (Figure 7's Default
// column is setGradW=10000, WRmp=100); it is a harness-chosen distinguishing
// value, and every verdict says so (oracleDefaultProvenanceParam) so a bundle
// reader is never told Figure 7 prescribed a 50 it does not.
const (
	rampBaselineSetGradW     = uint16(5000) // 50.00% of setMaxW/s -> model 704 WRmp=50
	rampBaselineSetSoftGradW = uint16(400)
)

// DefaultBaseRequest is the "base" object inside DefaultRequest — a minimal
// mirror of gridsim's adminCtrlReq (sim/gridsim/admin.go), carrying only the
// field this row needs to preserve.
type DefaultBaseRequest struct {
	ExpLimW *int64 `json:"exp_lim_W,omitempty"`
}

// DefaultRequest is the body of gridsim's POST /admin/default, mirrored the
// same way ControlRequest mirrors adminCtrlReq (observe.go's own doc on that
// type): the two shapes are independent Go types kept in sync by JSON tag,
// not a shared import, because gridsim owns its own admin schema.
type DefaultRequest struct {
	Program int                `json:"program"`
	Clear   bool               `json:"clear,omitempty"`
	Base    DefaultBaseRequest `json:"base"`
	// SetGradW / SetSoftGradW are IEEE 2030.5-2018's DefaultDERControl-only
	// ramp-rate defaults (sim/gridsim/admin.go's adminDefaultReq — same JSON
	// keys, same units: hundredths of a percent of setMaxW per second).
	SetGradW     *uint16 `json:"set_grad_w,omitempty"`
	SetSoftGradW *uint16 `json:"set_soft_grad_w,omitempty"`
}

// PostDefault posts to gridsim's POST /admin/default. Unlike PostControl it
// returns no mRID — a DefaultDERControl has no event lifecycle for a Response
// to key on — so it is the raw admin POST and nothing more.
func (d *Driver) PostDefault(ctx context.Context, req DefaultRequest) error {
	return d.Admin.Post(ctx, "default", req, nil)
}

// rampGradientOracle grades BASIC-007's two ramp-rate defaults against the
// DER's own model 704/703 register images.
//
// setGradW → 704 WRmp is ASSERTED: it is a device-wide rate register this
// product writes on every desired-ceiling document a DefaultDERControl
// default feeds, independently of whether an event is also in force (see this
// file's own doc). setSoftGradW → 703 ESRmpTms is REPORTED but NOT asserted,
// for the reason stated at length in this file's doc: this row's own
// procedure never schedules the enter-service transition that would cause
// lexa-gw to actually write it (cmd/modbus/reconcile_adv.go's
// resolveEnergizeRampS runs only when doc.Energize != nil). Grading it here
// would either FAIL a correct DUT for not doing something BASIC-007's own
// setup never asks it to do, or PASS by coincidence against whatever the
// register already held — neither is honest, so the value is surfaced and the
// omission is explained rather than silently dropped (the same posture
// oracleConnect takes for model 701's ConnSt).
func rampGradientOracle(setGradW, setSoftGradW uint16) *directOracle {
	wantWRmpPct := float64(setGradW) / 100.0
	wantESRmpTmsS := 0.0
	if setSoftGradW > 0 {
		wantESRmpTmsS = 100.0 / (float64(setSoftGradW) / 100.0)
	}
	return &directOracle{
		Axis: "setGradW / setSoftGradW (DefaultDERControl)",
		Commanded: fmt.Sprintf("setGradW=%d (%.2f%% of setMaxW per second, which lands as 704 WRmp=%.0f) and "+
			"setSoftGradW=%d (%.2f%%, which WOULD resolve to a %.1f s 703 ESRmpTms soft-start ramp if this "+
			"row's own procedure scheduled an enter-service transition — it does not)",
			setGradW, wantWRmpPct, wantWRmpPct, setSoftGradW, float64(setSoftGradW)/100.0, wantESRmpTmsS),
		Registers: "setGradW's register home is model 704's WRmp (an unscaled uint16 percent-of-WMax-per-" +
			"second, lexa-proto/sunspec/derlayout.go), written from every DefaultDERControl-sourced desired " +
			"ceiling document lexa-gw builds (internal/authority/csipin_ramp.go's resolveDefaultRampWPerS, " +
			"vendor/lexa-proto/derbase/derbase.go's writeWRmp). setSoftGradW's is model 703's ESRmpTms, " +
			"written only when an actual enter-service transition executes (cmd/modbus/reconcile_adv.go's " +
			"resolveEnergizeRampS) — reported below, not asserted, because this row's own procedure never " +
			"commands one.",
		Judge: func(uv invariant.UnitView) Finding {
			regs704 := uv.Regs[704]
			if len(regs704) == 0 {
				return unavailable("the DER serves no model 704, so WRmp has no register for this row to read")
			}
			ac := sunspec.Parse704(regs704)
			gotWRmp := float64(ac.WRmp)
			// Tolerance: 704's WRmp carries no scale factor (derlayout.go), so
			// the register's own finest step is 1 (whole percent). A ±1
			// allowance absorbs that quantization without hiding a genuinely
			// wrong value — the same reasoning fixedPFTolerance's doc gives
			// for a different register family.
			ok := math.Abs(gotWRmp-wantWRmpPct) <= 1.0
			verdict := certify.Pass
			if !ok {
				verdict = certify.Fail
			}
			parts := []string{fmt.Sprintf("the DER's own model 704 WRmp register reads %.0f against a "+
				"commanded setGradW=%d (%.2f%%)", gotWRmp, setGradW, wantWRmpPct)}
			if regs703 := uv.Regs[703]; len(regs703) > 0 {
				es := sunspec.Parse703(regs703)
				parts = append(parts, fmt.Sprintf("model 703 ESRmpTms reads %d s. REPORTED, NOT ASSERTED: "+
					"this row's own procedure is Default-Only and schedules no enter-service transition, and "+
					"lexa-gw only writes ESRmpTms from setSoftGradW when one actually executes "+
					"(cmd/modbus/reconcile_adv.go's resolveEnergizeRampS runs only when an energize axis is "+
					"in force) — a commanded setSoftGradW=%d would resolve to %.1f s if that transition were "+
					"ever exercised, which this row does not do", es.RampS, setSoftGradW, wantESRmpTmsS))
			} else {
				parts = append(parts, "the DER serves no model 703, so ESRmpTms has no register to report "+
					"either")
			}
			return Finding{Verdict: verdict, Observed: strings.Join(parts, "; ")}
		},
	}
}

// critDefaultDERControlCarriesRamp asserts BASIC-007's own printed observable:
// "HTTP GET on the DefaultDERControl href of the highest-priority DERProgram
// -> DefaultDERControl XML with setGradW = 9000 and setSoftGradW = 400".
//
// setGradW/setSoftGradW are DefaultDERControl-level elements — SIBLINGS of
// DERControlBase, not children of it (IEEE Std 2030.5-2018 p.252's own
// DefaultDERControl declaration; sim/gridsim/softgrad.go's
// defaultDERControlRamps and lexa-gw's own read-side
// extendedDefaultDERControlDoc both agree on this placement) — so this
// criterion reads the DefaultDERControl node directly rather than descending
// into DERControlBase the way critDERControlCarriesModeFrom does for an
// event's opMod* children.
//
// It scans EVERY DefaultDERControl the DUT fetched during the session, not
// just the first: gridsim serves one per program (0, 1, 2), and
// critDefaultDERControl's own "first resource of this type" shortcut would
// silently grade whichever program's default happened to appear first in the
// transcript rather than the one this row actually posted to.
func critDefaultDERControlCarriesRamp(setGradW, setSoftGradW uint16) criterion {
	claim := fmt.Sprintf("the DUT fetched a DefaultDERControl carrying setGradW=%d and setSoftGradW=%d",
		setGradW, setSoftGradW)
	how := fmt.Sprintf("a <setGradW>%d</setGradW> and <setSoftGradW>%d</setSoftGradW> pair, siblings of "+
		"<DERControlBase> inside a DefaultDERControl the DUT fetched during the session (IEEE Std "+
		"2030.5-2018 p.252)", setGradW, setSoftGradW)
	return criterion{
		Claim:           claim,
		How:             how,
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			exs := t.ByResource("DefaultDERControl")
			if len(exs) == 0 {
				return unavailable("no DefaultDERControl appears in the recovered transcript (resources "+
					"seen: %s)", strings.Join(t.ResourceNames(), " "))
			}
			var seen []string
			for _, e := range exs {
				doc, err := e.Resp.SEP()
				if err != nil {
					continue
				}
				gotGradW, hasGradW := doc.UintOf("setGradW")
				gotSoftGradW, hasSoftGradW := doc.UintOf("setSoftGradW")
				switch {
				case hasGradW && hasSoftGradW:
					seen = append(seen, fmt.Sprintf("setGradW=%d setSoftGradW=%d (href %s)",
						gotGradW, gotSoftGradW, doc.Href()))
					if uint64(setGradW) == gotGradW && uint64(setSoftGradW) == gotSoftGradW {
						return citeMessage(t, e.Resp, certify.Pass,
							"%s -> 200 DefaultDERControl carrying setGradW=%d setSoftGradW=%d",
							e.Req.Line(), gotGradW, gotSoftGradW)
					}
				case hasGradW || hasSoftGradW:
					seen = append(seen, fmt.Sprintf("only one of the pair present (setGradW present=%t, "+
						"setSoftGradW present=%t) (href %s)", hasGradW, hasSoftGradW, doc.Href()))
				}
			}
			if len(seen) == 0 {
				return citeMessage(t, exs[0].Resp, certify.Fail,
					"%d DefaultDERControl fetch(es) recovered, none carrying a setGradW/setSoftGradW pair "+
						"at all — this bench's own admin lever (sim/gridsim/softgrad.go) was not exercised, "+
						"or the DUT never fetched the program it landed on", len(exs))
			}
			return citeMessage(t, exs[0].Resp, certify.Fail,
				"the DUT fetched %d DefaultDERControl(s); the setGradW/setSoftGradW pair(s) seen were: %s "+
					"— none matches this row's commanded setGradW=%d setSoftGradW=%d",
				len(exs), strings.Join(seen, "; "), setGradW, setSoftGradW)
		},
	}
}

// basicRampRates implements BASIC-007 — Basic Inverter Control (Ramp Rates).
//
// It bypasses inverterControlSpec entirely (see this file's own doc for why)
// and drives the generic run()/spec{} primitives directly, the same layer
// basicIdentification/basicGroupManagement already use for a shape
// inverterControlSpec's uniform machinery does not fit.
func basicRampRates(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, rampRatesSpec())
}

// rampRatesSpec is BASIC-007's spec, factored out so its own tests can drive
// Setup/PostWait/Verdict against a scripted fake DER without standing up run().
//
// The two oracles differ only in the setGradW they judge: `target` grades the
// Figure-7 Test Value (WRmp=90), `baseline` grades the distinguishable
// register-state-independent baseline (WRmp=50, rampBaselineSetGradW). Setup
// drives the baseline first, confirms it, then commands the target; PostWait
// and every criterion grade the target.
func rampRatesSpec() spec {
	target := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW)
	baseline := rampGradientOracle(rampBaselineSetGradW, rampBaselineSetSoftGradW)
	s := spec{
		Notes: func(o *Observation) string {
			notes := fmt.Sprintf("drove gridsim program %d's DefaultDERControl (CSIP CTP v1.3 Figure 3's "+
				"Service Point program) first to a DISTINGUISHABLE setGradW=%d baseline (WRmp=%d — a value "+
				"Figure 7 does not name, commanded only so the move to the Test Value is observable from "+
				"any prior register state), confirmed that landing in the DER's own registers, then "+
				"commanded Figure 7's Test Values setGradW=%d/setSoftGradW=%d and waited %s for the DUT's "+
				"poll cycle. This row's own printed procedure is Default-Only: it schedules no DERControl "+
				"event and requires no DERControlResponse",
				rampDefaultProgram, rampBaselineSetGradW, rampBaselineSetGradW/100,
				figure7RampTestSetGradW, figure7RampTestSetSoftGradW, o.Waited.Round(rounding))
			return notes + "; " + oracleNotes(controlMode{}, o)
		},
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			return rampDefaultFirstSetup(ctx, d, params, baseline, target)
		},
		// Want is left nil (AwaitWalk): the POST above completes, synchronously,
		// before fetchWait even runs, so any walk AwaitWalk detects after the
		// pre-Setup baseline is guaranteed to see the new default — unlike an
		// EVENT published with a future StartOffset (oracleWindow's problem),
		// a DefaultDERControl has no activation delay; it is whatever is
		// currently stored the instant the DUT asks.
		SettlePoll: true,
		PostWait: func(ctx context.Context, d *Driver, params map[string]string) error {
			f := settleOracle(ctx, oracleSettleDeadline(params),
				func() Finding { return target.judgeWith(ctx, d.rc) })
			switch {
			case f.Unavailable != "":
				params[oracleUnavailableParam] = f.Unavailable
			default:
				params[oracleVerdictParam] = string(f.Verdict)
				params[oracleObservedParam] = f.Observed
			}
			return nil
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critProgramList(0),
				critDefaultDERControl(),
				critDefaultDERControlCarriesRamp(figure7RampTestSetGradW, figure7RampTestSetSoftGradW),
				critDEREffectViaDirectOracle("the ramp-rate settings", target, o),
			}
		},
	}
	s.Verdict = func(o *Observation) certify.Verdict {
		if f := oracleOutcome(o); f.Verdict != certify.Pass {
			return f.Verdict
		}
		return ""
	}
	s.Cleanup = func(ctx context.Context, d *Driver) {
		// Restore program 0's DefaultDERControl to exactly what buildProgram0
		// seeded it with — the export limit, no ramp fields — so this row
		// leaves the tree as it found it (rampDefaultFixtureExpLimW's own doc).
		_ = d.PostDefault(ctx, DefaultRequest{
			Program: rampDefaultProgram,
			Base:    DefaultBaseRequest{ExpLimW: ptr(rampDefaultFixtureExpLimW)},
		})
	}
	return s
}

// rampDefaultRequest builds the POST /admin/default body for one ramp value,
// carrying the fixture's own export limit forward (rampDefaultFixtureExpLimW)
// so the precondition ADDS the ramp settings rather than erasing what
// buildProgram0 seeded.
func rampDefaultRequest(setGradW, setSoftGradW uint16) DefaultRequest {
	req := DefaultRequest{Program: rampDefaultProgram}
	req.Base.ExpLimW = ptr(rampDefaultFixtureExpLimW)
	req.SetGradW = ptr(setGradW)
	req.SetSoftGradW = ptr(setSoftGradW)
	return req
}

// rampDefaultFirstSetup is BASIC-007's Setup: the IW15-004 default-first
// discipline (basic.go's prescribedSetup) applied to the ramp, and the whole
// answer to CSIP-BENCH-BASIC007-ORACLE-STATE-CONTAMINATION.
//
//	1. Drive the DER into the DISTINGUISHABLE baseline (WRmp=50) and CONFIRM it
//	   reached the DER's own registers — on a FRESH DUT poll, not a stale
//	   register. The confirmation is recorded into the oracleDefault* keys, so
//	   oracleOutcome FAILs the row (prescribedDefaultShortfall) if the baseline
//	   never landed: a starting state that was not established cannot anchor a
//	   transition claim.
//	2. Take the pre-publication baseline for the TARGET, AFTER the distinguishable
//	   default landed — so "the DER did not hold WRmp=90 before" is a statement
//	   about the DER at a known non-target 50, whatever it held when the row began.
//	3. Command Figure 7's Test Values. PostWait then proves WRmp moved to 90, and
//	   oracleOutcome credits the move (prescribedDefaultCredit) from the confirmed
//	   baseline.
//
// The move 50->90 is a transition only a live DUT tracking gridsim's
// DefaultDERControl can produce, so the row PASSes whether WRmp started at 0, at
// 90, or at anything else — and a DUT that ignores the control fails, at the
// baseline confirmation if it started at 90, at the post-read otherwise.
func rampDefaultFirstSetup(ctx context.Context, d *Driver, params map[string]string,
	baseline, target *directOracle) error {
	// ── 1. The distinguishable baseline, confirmed on a fresh poll ──────────
	params[oracleDefaultCommandedParam] = strconv.Itoa(int(rampBaselineSetGradW))
	params[oracleDefaultMRIDParam] = fmt.Sprintf("gridsim program-%d's DefaultDERControl (setGradW=%d)",
		rampDefaultProgram, rampBaselineSetGradW)
	params[oracleDefaultProvenanceParam] = fmt.Sprintf("a DISTINGUISHABLE setGradW=%d baseline (WRmp=%d), "+
		"a value Figure 7 does not name that this row commands ONLY so the register has a known non-target "+
		"state to move away from — not the catalog's Default column", rampBaselineSetGradW,
		rampBaselineSetGradW/100)

	startPoll, havePoll := derPollOrdinal(ctx, d)
	if err := d.PostDefault(ctx, rampDefaultRequest(rampBaselineSetGradW, rampBaselineSetSoftGradW)); err != nil {
		return fmt.Errorf("publish the distinguishable setGradW=%d ramp baseline: %w", rampBaselineSetGradW, err)
	}
	window := prescribedDefaultDeadline(ctx, d.rc, params)
	params[oracleDefaultWindowParam] = window.String()
	// Fence on the DUT's own poll cycle (LAB29-010, sim/simapi/API.md) so the
	// confirmation below reads a poll the DUT ran AFTER this publish, never the
	// pre-publish register a stale value would match. Best-effort: a sim without
	// the 1.1.0 barrier leans on the settleOracle value-poll, which — with a
	// baseline distinct from the target — still fails a dead DUT at the target
	// read. Never a false PASS.
	if havePoll {
		awaitFreshDERPoll(ctx, d, startPoll, window)
	}
	landed := settleOracle(ctx, window, func() Finding { return baseline.judgeWith(ctx, d.rc) })
	params[oracleDefaultVerdictParam] = string(landed.Verdict)
	params[oracleDefaultObservedParam] = findingObserved(landed)

	// ── 2. The pre-publication baseline for the TARGET, taken after step 1 ──
	pre := target.judgeWith(ctx, d.rc)
	params[oraclePreVerdictParam] = string(pre.Verdict)
	params[oraclePreObservedParam] = findingObserved(pre)

	// ── 3. Command Figure 7's Test Values ──────────────────────────────────
	return d.PostDefault(ctx, rampDefaultRequest(figure7RampTestSetGradW, figure7RampTestSetSoftGradW))
}

// rampPollWaitSlice bounds ONE /poll/wait request, kept under the framework's
// HTTP client timeout so a caller's transport never decides anything — the same
// reason suitemodbusclient's pollWaitSlice is 8s.
const rampPollWaitSlice = 8 * time.Second

// derPollState is the narrow slice of simapi's GET /poll and GET /poll/wait this
// row reads: the completed-cycle ordinal and the reached flag are all the ramp
// baseline's fence needs. It mirrors suitemodbusclient's PollReport (ledger.go)
// but stays local, the same way that suite keeps the deterministic endpoints
// behind SimClient.Raw so the shared client grows no endpoint set.
type derPollState struct {
	Reached bool `json:"reached"`
	Poll    struct {
		Completed uint64 `json:"completed"`
	} `json:"poll"`
}

// derPollOrdinal reads the DER-side sim's completed poll-cycle count without
// blocking (GET /poll). ok is false — never fatal — when the sim does not
// publish the 1.1.0 barrier (an older sim, or -tap=false); the caller then
// relies on the settleOracle value-poll, which still confirms the landing.
func derPollOrdinal(ctx context.Context, d *Driver) (uint64, bool) {
	sim, err := d.rc.Sim(oracleSimName)
	if err != nil || !sim.Available() {
		return 0, false
	}
	raw, err := sim.Raw(ctx, http.MethodGet, "/poll", nil)
	if err != nil {
		return 0, false
	}
	var st derPollState
	if json.Unmarshal(raw, &st) != nil {
		return 0, false
	}
	return st.Poll.Completed, true
}

// awaitFreshDERPoll blocks until the DER-side sim has completed at least one
// poll cycle beyond `start` — one the DUT ran AFTER the caller's publish — or
// until `window`/the context runs out. It is LAB29-010's poll barrier reached
// through SimClient.Raw, and it NEVER decides a verdict: a barrier that times
// out just hands off to the settleOracle value-poll the caller runs next. Its
// only job is to keep the baseline confirmation from reading the pre-publish
// register a stale value would match.
func awaitFreshDERPoll(ctx context.Context, d *Driver, start uint64, window time.Duration) {
	sim, err := d.rc.Sim(oracleSimName)
	if err != nil || !sim.Available() {
		return
	}
	want := start + 1
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		slice := time.Until(deadline)
		if slice > rampPollWaitSlice {
			slice = rampPollWaitSlice
		}
		raw, err := sim.Raw(ctx, http.MethodGet,
			fmt.Sprintf("/poll/wait?epoch=%d&timeout=%s", want, slice), nil)
		if err != nil {
			return
		}
		var st derPollState
		if json.Unmarshal(raw, &st) == nil && (st.Reached || st.Poll.Completed >= want) {
			return
		}
	}
}

// registerRampRates binds BASIC-007, order 53 — the same slot it held as an
// unreachableMode row in inverterControlRows before this file existed. See
// registerInverterControls's own doc for why it is registered separately.
func registerRampRates(reg *certify.Registry) {
	reg.Register(uid("BASIC-007"), Suite, basicRampRates,
		certify.WithRequires(needGridSim...), certify.WithOrder(53))
}
