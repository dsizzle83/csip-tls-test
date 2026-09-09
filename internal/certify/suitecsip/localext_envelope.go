package suitecsip

// localext_envelope.go — EXT-005..008, the LOCAL EXTENSION rows REV0907-D2-IMPL
// P5 requires: docs/design/AUTHORITY_ENVELOPE_2026-09-08.md ("the CSIP
// envelope: concurrent mbaps under CSIP limits", owner ruling D2, REV0907-D2-
// RULING) replaces exclusive control authority with "CSIP defines an envelope,
// mbaps contributes requests, and the retained desired document carries the
// composed result" (design §0). No published CSIP-CONF-v1.3 or SSM-CONF-v0.8
// procedure exercises TWO CONCURRENT NORTHBOUND AUTHORS at all — every existing
// row in this bench drives exactly one lane at a time (authority.go's
// AuthorityCSIP/AuthorityMBAPS families) — so the envelope's own arbitration
// rules (design §2's per-axis table) have no row to be caught by. These four
// do, written against the DESIGN'S OWN STATED CONTRACT rather than against
// lexa-gw's implementation (referee independence, CLAUDE.md /
// docs/ADVERSARIAL_QA_STRATEGY.md §5 PN-1/C9/AD-003(f)): the product side of
// P5 (lexa-mode's compose step, cmd/mbaps's dynamic deny set and envelope
// range check) is being written concurrently with this file, in lexa-gw
// phases P1/P2, and these rows are meant to run unmodified against it.
//
// See localext.go's doc for what a LOCAL EXTENSION row is and is not: run,
// bundled and re-verified like any other case, certifiable under no standard,
// excluded from every applicable-FAIL tally.
//
// # The two lanes these rows drive at once
//
// Every other row in this suite drives gridsim (the CSIP lane) alone; RBAC-*
// in suitessm drives mbaps (the Secure SunSpec lane) alone. These rows need
// both, live, in the same window: a CSIP DERControl in effect on gridsim, and
// a role-bound mbaps GridServiceSunSpec write landing (or being refused) while
// it is. suitessm already owns every line of TLS/PKI/session/chain-discovery
// code an mbaps client needs; suitessm.DialEnvelopeRole (envelope.go) is the
// one exported seam that lets this file reuse it rather than duplicating a
// second mbaps client. Modbus PDU encode/decode uses lexa-proto/mbap directly
// — the wire format is the wire format, the same precedent suitessm/session.go
// states for its own use of that package — and register layout/scale-factor
// encoding uses lexa-proto/sunspec's declarative model description, the same
// precedent directoracle.go states for reading the DER's own registers with
// it. Neither is an oracle: both are shared, product-independent descriptions
// of a WIRE FORMAT (Modbus framing, SunSpec register geometry), never a
// judgement about what a conformant device must do — the judgement in every
// grader below is this file's own, cross-checked against the design doc's own
// words and IEEE Std 2030.5-2018 / the Modbus specification's exception
// vocabulary.
//
// # Evidence tier
//
// The write this row's own mbaps client issued, and the exception (or ack) it
// received, is decided LIVE — during PostWait/Change, before the capture is
// ever opened — and carried into the citation phase through Observation.Params
// (stashFinding/recallFinding), the same "live phase decides, citation phase
// reports" shape directoracle.go's critDEREffectViaDirectOracle and
// localext_eventstatus.go's ext004CeilingStabilityCriterion already use for a
// live southbound read. tierMbapsWrite says so in every assertion's Method
// rather than implying the capture backed a fact it never saw (the same
// misattribution tierOracle's own doc warns against at tierServer/tierWire).
// The DER's OWN register effect, where a criterion also grades one, is read
// through internal/invariant's simapi sidecar path (oracleUnitView), which
// this suite already uses everywhere else and which touches neither the mbaps
// session nor the CSIP session — an observation independent of both lanes
// this row is arbitrating between.

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suitessm"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"
)

// envelopeDesignDoc is the citation every EXT-005..008 claim carries: the
// design's own stated contract, not this bench's or the product's invention.
const envelopeDesignDoc = "docs/design/AUTHORITY_ENVELOPE_2026-09-08.md"

// registerLocalExtensionsEnvelope binds EXT-005..008. Called from
// registerLocalExtensions (localext.go) alongside EXT-001..004, continuing its
// order sequence (65 is EXT-004's).
func registerLocalExtensionsEnvelope(reg *certify.Registry, nonce string) {
	reg.Register(extUID("EXT-005"), Suite, envelopeCeilingRefusal(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(66))
	reg.Register(extUID("EXT-006"), Suite, envelopeValueAxisOwnership(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(67))
	reg.Register(extUID("EXT-007"), Suite, envelopeFailsafeOverride(nonce),
		certify.WithOrder(68))
	reg.Register(extUID("EXT-008"), Suite, envelopeOwnershipTake(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(69))
}

// gridServiceRole is the certs/mbaps fixture stem every write in this file
// authenticates as — design §2's "GridServiceSunSpec" is the role every
// per-axis row names as the mbaps writer, and RBAC-002's kindFor map treats it
// as the role authorized for DER control points.
const gridServiceRole = "grid-service"

// tierMbapsWrite is this file's own evidence tier: a write issued by this
// row's own role-bound mbaps session (suitessm.DialEnvelopeRole), decoded with
// lexa-proto/mbap's framing alone. See the file doc's "Evidence tier" section
// for why this is not tierOracle (that tier is a DER register read; this is a
// northbound write decision) and not tierServer/tierWire (neither the gridsim
// admin log nor the CSIP capture ever sees an mbaps frame).
const tierMbapsWrite tier = "this row's own role-bound mbaps TLS session (GridServiceSunSpec), decoded " +
	"with lexa-proto/mbap wire framing only — independent of the DUT's CSIP path, the gridsim admin log, " +
	"and any product parser (suitessm.DialEnvelopeRole)"

// ── mbaps write/read plumbing shared by all four rows ───────────────────────

// envelopeWriteOutcome is what this row's own mbaps client observed for one
// write: a plain Modbus ADU decision, decoded independently of the DUT's own
// reported state and of any product code.
type envelopeWriteOutcome struct {
	Acked        bool
	HasException bool
	Exception    mbap.ExCode
	Err          error
	Raw          []byte
}

func (w envelopeWriteOutcome) describe() string {
	switch {
	case w.Err != nil:
		return fmt.Sprintf("the write could not even be sent: %v", w.Err)
	case w.HasException:
		return fmt.Sprintf("Modbus exception %d (%s)", uint8(w.Exception), w.Exception)
	case w.Acked:
		return "ACKED (a normal, non-exception response)"
	default:
		return "no decision was recorded"
	}
}

// decodeMbapsExchange turns a raw suitessm.Exchange into a decision, using
// lexa-proto/mbap for framing only — see the file doc.
func decodeMbapsExchange(ex suitessm.Exchange) envelopeWriteOutcome {
	if ex.Err != nil {
		return envelopeWriteOutcome{Err: ex.Err}
	}
	adu, err := mbap.Decode(bytes.NewReader(ex.Response))
	if err != nil {
		return envelopeWriteOutcome{Err: fmt.Errorf("suitecsip: decode mbaps response: %w", err)}
	}
	if len(adu.PDU) > 0 && adu.PDU[0]&0x80 != 0 {
		code := mbap.ExCode(0)
		if len(adu.PDU) > 1 {
			code = mbap.ExCode(adu.PDU[1])
		}
		return envelopeWriteOutcome{HasException: true, Exception: code, Raw: ex.Response}
	}
	return envelopeWriteOutcome{Acked: true, Raw: ex.Response}
}

// readModelBlock reads a whole discovered model's data registers over an
// mbaps session, capped to the Modbus read limit — the same cap
// pickWriteTargetOfKind (suitessm/checks_rbac.go) applies for the same reason:
// one round trip, never dozens.
func readModelBlock(sess *suitessm.EnvelopeSession, m suitessm.ModelBlock, label string) ([]uint16, error) {
	n := m.Length
	if n > mbap.MaxReadCount {
		n = mbap.MaxReadCount
	}
	ex := sess.ReadHolding(sess.Unit, m.First, n, label)
	if ex.Err != nil {
		return nil, fmt.Errorf("suitecsip: read model %d block: %w", m.ID, ex.Err)
	}
	adu, err := mbap.Decode(bytes.NewReader(ex.Response))
	if err != nil {
		return nil, fmt.Errorf("suitecsip: decode model %d block read: %w", m.ID, err)
	}
	if len(adu.PDU) > 0 && adu.PDU[0]&0x80 != 0 {
		code := mbap.ExCode(0)
		if len(adu.PDU) > 1 {
			code = mbap.ExCode(adu.PDU[1])
		}
		return nil, fmt.Errorf("suitecsip: reading model %d drew Modbus exception %d (%s)", m.ID, uint8(code), code)
	}
	return mbap.ParseReadResp(mbap.ReadReq{FC: mbap.FCReadHolding, Addr: m.First, Count: n}, adu.PDU)
}

// contiguousWrite locates a contiguous span of n registers starting at first
// within lyt, applies set to a View over block (block is a live read of the
// model, so any scale factor set encodes against is the DUT's own current
// one), and returns the span to send as one Write Multiple Registers request.
//
// It assumes first..+n are contiguous in lyt's declared field order — true of
// every span this file writes (pinned by
// TestL704EnvelopeSpansAreContiguous/TestL703EnvelopeSpanIsContiguous) — and
// refuses rather than guess when that stops holding.
func contiguousWrite(lyt *sunspec.Layout, block []uint16, first string, n int,
	set func(v sunspec.View) error) (off int, span []uint16, err error) {
	o := lyt.Offset(first)
	if o < 0 {
		return 0, nil, fmt.Errorf("suitecsip: model layout %s declares no point %q", lyt.Name(), first)
	}
	if o+n > len(block) {
		return 0, nil, fmt.Errorf("suitecsip: model layout %s's %q..+%d falls outside the %d-register "+
			"block this row read from the DUT", lyt.Name(), first, n, len(block))
	}
	v := lyt.View(block)
	if err := set(v); err != nil {
		return 0, nil, err
	}
	return o, block[o : o+n], nil
}

// mbapsWriteSpan issues one Write Multiple Registers request at model.First+off
// and classifies the response.
func mbapsWriteSpan(sess *suitessm.EnvelopeSession, model suitessm.ModelBlock, off int, span []uint16,
	label string) envelopeWriteOutcome {
	return decodeMbapsExchange(sess.WriteMultiple(sess.Unit, model.First+uint16(off), span, label))
}

// ── DER-side independent reads (internal/invariant + lexa-proto/sunspec's
// register-layout decode — NOT the mbaps session, NOT the CSIP session) ─────

// read704 reads the DER's own model 704 image through the same southbound
// oracle path every other row in this suite uses (oracleUnitView), and decodes
// it with lexa-proto/sunspec's register geometry only (sunspec.Parse704) —
// the same framing-not-oracle distinction the file doc draws for the mbaps
// side.
func read704(ctx context.Context, rc *certify.RunCtx) (got sunspec.ACControls, ok bool, why string) {
	uv, err := oracleUnitView(ctx, rc, oracleSimName)
	if err != nil {
		return sunspec.ACControls{}, false, err.Error()
	}
	regs := uv.Regs[704]
	if len(regs) == 0 {
		return sunspec.ACControls{}, false, "the DER serves no model 704, so none of this row's axes " +
			"(WMaxLimPct, PFWInj, WSet) has a register home to read"
	}
	return sunspec.Parse704(regs), true, ""
}

// ── Finding stash: Observation.Params carries only strings ──────────────────

func stashFinding(params map[string]string, key string, f Finding) {
	params[key+".unavail"] = f.Unavailable
	params[key+".verdict"] = string(f.Verdict)
	params[key+".observed"] = f.Observed
}

func recallFinding(params map[string]string, key string) Finding {
	if u := params[key+".unavail"]; u != "" {
		return Finding{Unavailable: u}
	}
	if v, ok := params[key+".verdict"]; ok {
		return Finding{Verdict: certify.Verdict(v), Observed: params[key+".observed"]}
	}
	return unavailable("this row's live phase never reached the step that decides %q", key)
}

// envelopeSettle is the propagation window these rows give the DUT between an
// mbaps write and reading its effect (or its absence) off the DER — short,
// because design §3.2 states the envelope range check and the axis-ownership
// denial both happen at DECODE TIME, synchronously, before anything is
// published: a row that needed a whole poll cycle to see a REFUSAL would be
// measuring something the design does not claim takes one.
const envelopeSettle = 5 * time.Second

// envelopeControlDurationS is every EXT-005..008 CSIP control's own event
// interval — long relative to the row's own window, the same "genuinely LIVE,
// not merely elapsed" discipline ext002ControlDurationS documents.
const envelopeControlDurationS = 300

// envelopeProgram is the gridsim program these rows publish to. gridsim
// admits only programs 0-2 (sim/gridsim/admin.go); EXT-001..004 already share
// program 2 for the same reason localext.go's EXT-002/EXT-003 doc gives —
// "these rows have no supersession concern of their own to protect" — and
// this bench runs its rows sequentially, so EXT-005..008 reuse it too.
const envelopeProgram = 2

// ═══════════════════════════════════════════════════════════════════════════
// EXT-005 — envelope refusal (design §2's Active-power ceiling row, §1.4,
// §3.2's decode-time envelope check)
// ═══════════════════════════════════════════════════════════════════════════

const (
	// ext005EnvelopeHundredths is the CSIP opModMaxLimW control's own limit —
	// 50.00% of nameplate, in the CSIP-side hundredths-of-a-percent wire unit
	// (IW13-001, ControlRequest.MaxLimW's own doc).
	ext005EnvelopeHundredths = int64(5000)
	// ext005AbovePct is the mbaps WMaxLimPct value this row writes ABOVE the
	// envelope — a plain percentage, the unit sunspec.View.SetFloat("WMaxLimPct", …)
	// takes.
	ext005AbovePct = 80.0
	// ext005WithinPct is the mbaps WMaxLimPct value this row writes WITHIN the
	// envelope, and ext005WithinHundredths is the same value in the CSIP-side
	// unit oracleMaxLimW takes — the two must name the same number, or this
	// row's own within-envelope write and its own within-envelope oracle
	// would silently disagree about what "within" means.
	ext005WithinPct        = 30.0
	ext005WithinHundredths = int64(3000)
)

const (
	ext005AboveKey  = "ext005.above"
	ext005WithinKey = "ext005.within"
)

func envelopeCeilingRefusal(nonce string) certify.Check {
	s := envelopeCeilingRefusalSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// envelopeCeilingRefusalSpec builds EXT-005's spec, factored out for a direct
// Setup/PostWait/Criteria test the same way reservedCurrentStatusSpec is.
func envelopeCeilingRefusalSpec(nonce string) spec {
	mrid := withRunNonce("CERT-EXT005-ENVELOPE-CEILING", nonce)
	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			id, err := d.PostControl(ctx, ControlRequest{
				Program: envelopeProgram, MRID: mrid, Description: "EXT-005 envelope ceiling control",
				StartOffset: 0, DurationS: envelopeControlDurationS,
				MaxLimW: ptr(ext005EnvelopeHundredths), Activate: true,
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		Want: func(base ServerView) func(ServerView) bool {
			return base.WantResponseAtLeast(mrid, 2)
		},
		// PostWait, not Change: both mbaps writes and both reads happen here,
		// unconditionally, once the DUT has taken up the CSIP envelope — see
		// spec.PostWait's own doc.
		PostWait: func(ctx context.Context, d *Driver, params map[string]string) error {
			sess, skip := suitessm.DialEnvelopeRole(ctx, d.rc, gridServiceRole)
			if skip != nil {
				f := unavailable("could not open the mbaps GridService session this row needs: %s", skip.Notes)
				stashFinding(params, ext005AboveKey, f)
				stashFinding(params, ext005WithinKey, f)
				return nil
			}
			defer sess.Close()
			model, ok := sess.Chain.Model(704)
			if !ok {
				f := unavailable("the DUT's mbaps chain (%v) serves no model 704, so this row's WMaxLimPct "+
					"axis has no register home to write", sess.Chain.IDs())
				stashFinding(params, ext005AboveKey, f)
				stashFinding(params, ext005WithinKey, f)
				return nil
			}

			// The above-envelope write.
			pre := readCeilingSnapshot(ctx, d.rc)
			above, err := ext005Write(sess, model, ext005AbovePct)
			if err != nil {
				f := unavailable("could not encode/send the above-envelope WMaxLimPct write: %v", err)
				stashFinding(params, ext005AboveKey, f)
			} else {
				if err := d.rc.Sleep(ctx, envelopeSettle); err != nil {
					d.rc.Logf("this row's settle wait ended early: %v", err)
				}
				post := readCeilingSnapshot(ctx, d.rc)
				stashFinding(params, ext005AboveKey, gradeEnvelopeAboveRefusal(above, pre, post))
			}

			// The within-envelope write.
			within, err := ext005Write(sess, model, ext005WithinPct)
			if err != nil {
				stashFinding(params, ext005WithinKey,
					unavailable("could not encode/send the within-envelope WMaxLimPct write: %v", err))
				return nil
			}
			effect := settleOracle(ctx, oracleSettleDeadline(params), func() Finding {
				return oracleMaxLimW(ext005WithinHundredths)(ctx, d.rc)
			})
			stashFinding(params, ext005WithinKey, gradeEnvelopeWithinAck(within, effect))
			return nil
		},
		Cleanup: func(ctx context.Context, d *Driver) {
			_ = d.releaseProgramControls(ctx, envelopeProgram)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published a CSIP opModMaxLimW control (%s) at %.2f%% and waited %s for it "+
				"to be Started, then over a role-bound mbaps GridServiceSunSpec session wrote WMaxLimPct "+
				"first ABOVE it (%.2f%%) and then WITHIN it (%.2f%%) — %s",
				mrid, float64(ext005EnvelopeHundredths)/100, o.Waited.Round(rounding), ext005AbovePct,
				ext005WithinPct, envelopeDesignDoc+" §2 (Active-power ceiling row), §3.2")
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResponseStarted(mrid),
				{
					Claim: fmt.Sprintf("an mbaps GridServiceSunSpec write to 704 WMaxLimPct ABOVE the CSIP "+
						"envelope (%.2f%%, control %s) draws Modbus exception 03 (illegal data value) and "+
						"the DER's own ceiling register does not move — %s §1.4/§2/§3.2, owner answer A "+
						"(\"reject with exception 03\"): no clamp-and-ack",
						float64(ext005EnvelopeHundredths)/100, mrid, envelopeDesignDoc),
					How: fmt.Sprintf("this row's own mbaps GridServiceSunSpec write to WMaxLimPct (%.2f%% > "+
						"the %.2f%% envelope), decoded from the raw MBAP response; the DER's own "+
						"active-power ceiling register read independently before and after the write, "+
						"through the same southbound oracle path localext_eventstatus.go's EXT-004 uses",
						ext005AbovePct, float64(ext005EnvelopeHundredths)/100),
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext005AboveKey)
					},
				},
				{
					Claim: fmt.Sprintf("the same mbaps GridServiceSunSpec client's write WITHIN the "+
						"envelope (%.2f%%) is acked (no Modbus exception) and the DER reads it back within "+
						"this row's window — %s §1.4/§2: \"a write within the envelope is acked and "+
						"applied\"",
						ext005WithinPct, envelopeDesignDoc),
					How: "this row's own mbaps GridServiceSunSpec write to WMaxLimPct within the envelope, " +
						"decoded from the raw MBAP response; the DER's own resolved active-power ceiling, " +
						"read through the same effect-based oracle BASIC-010 uses (oracleMaxLimW), polled " +
						"across this row's poll-cycle window",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext005WithinKey)
					},
				},
			}
		},
	}
}

// ext005Write reads the DUT's live model 704 image, encodes WMaxLimPctEna=1 /
// WMaxLimPct=pct against the DUT's OWN current scale factor, and writes both
// registers (they are contiguous in L704 — WMaxLimPctEna then WMaxLimPct) in
// one Write Multiple Registers request.
func ext005Write(sess *suitessm.EnvelopeSession, model suitessm.ModelBlock, pct float64) (envelopeWriteOutcome, error) {
	block, err := readModelBlock(sess, model, "EXT-005 model 704 pre-write read")
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	off, span, err := contiguousWrite(sunspec.L704, block, "WMaxLimPctEna", 2, func(v sunspec.View) error {
		v.SetBool("WMaxLimPctEna", true)
		return v.SetFloat("WMaxLimPct", pct)
	})
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	return mbapsWriteSpan(sess, model, off, span, fmt.Sprintf("EXT-005 WMaxLimPct write (%.2f%%)", pct)), nil
}

// gradeEnvelopeAboveRefusal is EXT-005's above-envelope criterion, a pure
// function of what this row's own write drew and what the DER's own ceiling
// register read before/after — directly unit-testable with synthetic inputs.
func gradeEnvelopeAboveRefusal(w envelopeWriteOutcome, pre, post ceilingSnapshot) Finding {
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the above-envelope WMaxLimPct write could not even be sent: %v — no conclusion about the "+
				"DUT's envelope enforcement can be drawn", w.Err)}
	}
	if !w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the above-envelope WMaxLimPct write was %s, not refused — %s §1.4/§3.2 requires exception "+
				"03 (illegal data value) for a limit-axis write above the envelope; no clamp-and-ack is "+
				"permitted (owner answer A)", w.describe(), envelopeDesignDoc)}
	}
	if w.Exception != mbap.ExIllegalValue {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the above-envelope WMaxLimPct write drew Modbus exception %d (%s), not 03 (illegal data "+
				"value) — %s §3.2", uint8(w.Exception), w.Exception, envelopeDesignDoc)}
	}
	switch {
	case !pre.Available || !post.Available:
		return unavailable("the write correctly drew exception 03, but the DER's own ceiling register "+
			"could not be read independently to confirm it did not move: before=%q after=%q",
			pre.Note, post.Note)
	case pre.Point != post.Point || pre.Enabled != post.Enabled || pre.Raw != post.Raw:
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the write correctly drew exception 03, but the DER's own %s register MOVED anyway: before "+
				"enabled=%t value=%.4f, after enabled=%t value=%.4f — a refusal on the wire that the "+
				"device did not actually honour", pre.Point, pre.Enabled, pre.Raw, post.Enabled, post.Raw)}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the above-envelope write drew Modbus exception 03 (illegal data value) as %s §1.4/§3.2 requires, "+
			"and the DER's own %s register did not move: enabled=%t value=%.4f before and after",
		envelopeDesignDoc, pre.Point, pre.Enabled, pre.Raw)}
}

// gradeEnvelopeWithinAck is EXT-005's within-envelope criterion.
func gradeEnvelopeWithinAck(w envelopeWriteOutcome, effect Finding) Finding {
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the within-envelope WMaxLimPct write could not even be sent: %v", w.Err)}
	}
	if w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the within-envelope WMaxLimPct write drew Modbus exception %d (%s) — %s §1.4 requires a "+
				"write within the envelope to be acked and applied, never refused",
			uint8(w.Exception), w.Exception, envelopeDesignDoc)}
	}
	if effect.Unavailable != "" {
		return unavailable("the within-envelope write was acked, but the DER's own ceiling effect could "+
			"not be confirmed: %s", effect.Unavailable)
	}
	if effect.Verdict != certify.Pass {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the within-envelope write was acked, but the DER's own ceiling register never came to hold "+
				"it within this row's window: %s", effect.Observed)}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the within-envelope write was ACKED (no Modbus exception), and the DER's own ceiling register "+
			"came to hold it: %s", effect.Observed)}
}

// ═══════════════════════════════════════════════════════════════════════════
// EXT-006 — CSIP-owned value axis (design §2's Fixed PF row, §1.4, §2's
// release rule "the effective value returns to the device default, NOT to
// the prior mbaps value" — owner answer B)
// ═══════════════════════════════════════════════════════════════════════════

// ext006CSIPFixedPF is the CSIP opModFixedPFInjectW control this row publishes
// — CSIP CTP v1.3's own Figure 8 Test Values (displacement 900, excitation
// false, multiplier -3 — a displacement power factor of 0.900, injecting/
// over-excited), the same values FixedPFSettings's own doc cites, chosen for
// consistency with BASIC-008 rather than inventing a fourth PF literal in
// this suite.
var ext006CSIPFixedPF = FixedPFSettings{Displacement: 900, Excitation: false, Multiplier: -3}

// ext006MbapsFixedPF is the value this row's mbaps client writes — the SAME
// excitation direction (so a direction bug is not what distinguishes the two)
// and a DIFFERENT, distinguishable magnitude (0.850 vs CSIP's 0.900), so a
// register reading either value unambiguously names which author it came
// from.
var ext006MbapsFixedPF = FixedPFSettings{Displacement: 850, Excitation: false, Multiplier: -3}

const (
	ext006RefusedKey  = "ext006.refused"
	ext006DefaultKey  = "ext006.default"
	ext006ReleasedKey = "ext006.released"
)

func envelopeValueAxisOwnership(nonce string) certify.Check {
	s := envelopeValueAxisOwnershipSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// envelopeValueAxisOwnershipSpec builds EXT-006's spec.
//
// It captures the DER's pre-publication PF baseline in Setup (the "device
// default" C3 grades against — design owner answer B says release restores
// THIS, never a prior mbaps value, so it must be read before either author
// ever touches the axis), drives the refused-while-owned write in PostWait
// once the CSIP control is Started, and drives the gridsim admin cancel plus
// the released write in Change — the same "Setup publishes, Change mutates
// server-side" split every other spec in this suite uses, with the mbaps
// session opened once (sess, captured by the closures below) and closed in
// Cleanup.
func envelopeValueAxisOwnershipSpec(nonce string) spec {
	mrid := withRunNonce("CERT-EXT006-VALUE-AXIS", nonce)
	var sess *suitessm.EnvelopeSession
	var model suitessm.ModelBlock
	var haveModel bool

	closeSess := func() {
		if sess != nil {
			sess.Close()
			sess = nil
		}
	}

	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			base, ok, why := read704(ctx, d.rc)
			if !ok {
				stashFinding(params, ext006DefaultKey, unavailable("could not read the DER's own "+
					"pre-publication model 704 image to establish this row's device-default baseline: %s", why))
			} else {
				params["ext006.baseline_pf"] = trimNum(base.PFWInjPF)
				params["ext006.baseline_ena"] = fmt.Sprintf("%t", base.PFWInjEna)
				params["ext006.baseline_ext"] = fmt.Sprintf("%d", base.PFWInjExt)
			}

			id, err := d.PostControl(ctx, ControlRequest{
				Program: envelopeProgram, MRID: mrid, Description: "EXT-006 CSIP-owned value axis control",
				StartOffset: 0, DurationS: envelopeControlDurationS,
				FixedPFInjectW: &ext006CSIPFixedPF, Activate: true,
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		Want: func(base ServerView) func(ServerView) bool {
			return base.WantResponseAtLeast(mrid, 2)
		},
		PostWait: func(ctx context.Context, d *Driver, params map[string]string) error {
			var skip *certify.Result
			sess, skip = suitessm.DialEnvelopeRole(ctx, d.rc, gridServiceRole)
			if skip != nil {
				f := unavailable("could not open the mbaps GridService session this row needs: %s", skip.Notes)
				stashFinding(params, ext006RefusedKey, f)
				return nil
			}
			m, ok := sess.Chain.Model(704)
			if !ok {
				f := unavailable("the DUT's mbaps chain (%v) serves no model 704", sess.Chain.IDs())
				stashFinding(params, ext006RefusedKey, f)
				return nil
			}
			model, haveModel = m, true

			before, beforeOK, beforeWhy := read704(ctx, d.rc)
			w, err := ext006Write(sess, model, ext006MbapsFixedPF)
			if err != nil {
				stashFinding(params, ext006RefusedKey,
					unavailable("could not encode/send the mbaps PFWInj_PF write: %v", err))
				return nil
			}
			if err := d.rc.Sleep(ctx, envelopeSettle); err != nil {
				d.rc.Logf("this row's settle wait ended early: %v", err)
			}
			after, afterOK, afterWhy := read704(ctx, d.rc)
			stashFinding(params, ext006RefusedKey,
				gradeAxisOwnedRefusal(w, before, after, beforeOK, afterOK, beforeWhy, afterWhy))
			return nil
		},
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The server-cancel idiom EXT-002/EXT-003 use (localext_eventstatus.go's
			// doc): a status-only update on the SAME mRID, driving the control to
			// Annex B currentStatus 2 — releasing CSIP's ownership of the axis.
			if _, err := d.PostControl(ctx, ControlRequest{Program: envelopeProgram, MRID: mrid, Cancel: true}); err != nil {
				return err
			}
			// Design §1.1: "when a control ends, the envelope relaxes to the
			// default" — this settle is the propagation window for lexa-mode to
			// notice the cancellation and recompose before either read below.
			if err := d.rc.Sleep(ctx, envelopeSettle); err != nil {
				return err
			}

			atRelease, ok, why := read704(ctx, d.rc)
			stashFinding(params, ext006DefaultKey, gradeAxisReleaseDefault(params, atRelease, ok, why))

			if !haveModel || sess == nil {
				stashFinding(params, ext006ReleasedKey,
					unavailable("no mbaps session/model was resolved during this row's PostWait, so the "+
						"released write could not be attempted"))
				return nil
			}
			w, err := ext006Write(sess, model, ext006MbapsFixedPF)
			if err != nil {
				stashFinding(params, ext006ReleasedKey,
					unavailable("could not encode/send the post-release mbaps PFWInj_PF write: %v", err))
				return nil
			}
			if err := d.rc.Sleep(ctx, envelopeSettle); err != nil {
				d.rc.Logf("this row's settle wait ended early: %v", err)
			}
			got, gotOK, gotWhy := read704(ctx, d.rc)
			stashFinding(params, ext006ReleasedKey, gradeAxisReleasedWrite(w, ext006MbapsFixedPF, got, gotOK, gotWhy))
			return nil
		},
		ChangeWait: changeWaitFullCycle,
		Cleanup: func(ctx context.Context, d *Driver) {
			closeSess()
			_ = d.releaseProgramControls(ctx, envelopeProgram)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published a CSIP opModFixedPFInjectW control (%s, PF %s injecting) and "+
				"waited %s for it to be Started, attempted an mbaps GridServiceSunSpec PFWInj_PF write "+
				"(PF %s) while it was in effect, then cancelled it and attempted the same write again — %s "+
				"§2 (Fixed PF row)", mrid, trimNum(ext006CSIPFixedPF.PF()), o.Waited.Round(rounding),
				trimNum(ext006MbapsFixedPF.PF()), envelopeDesignDoc)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResponseStarted(mrid),
				{
					Claim: fmt.Sprintf("while the CSIP opModFixedPFInjectW control (%s) is in effect, an "+
						"mbaps GridServiceSunSpec write to 704 PFWInj_PF draws Modbus exception 01 "+
						"(illegal function) and the DER's own PF register does not move — %s §2 (Fixed "+
						"PF: \"refused (01) while CSIP-owned\")", mrid, envelopeDesignDoc),
					How: "this row's own mbaps write to PFWInj_PF/_Ext, decoded from the raw MBAP " +
						"response; the DER's own model 704 PF sync group read independently before and " +
						"after the write",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext006RefusedKey)
					},
				},
				{
					Claim: fmt.Sprintf("%s §2's release rule (owner answer B, \"device default\"): "+
						"immediately after CSIP releases the axis (before this row's second mbaps write), "+
						"the DER's own PF register reads the SAME value this row observed before the CSIP "+
						"control was ever published — never a value mbaps held", envelopeDesignDoc),
					How: "the DER's own model 704 PF sync group, read once before this row published its " +
						"CSIP control (the device-default baseline) and again immediately after the " +
						"control's cancellation was served and this row's settle window elapsed, both " +
						"through the same southbound oracle path",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext006DefaultKey)
					},
				},
				{
					Claim: fmt.Sprintf("after the control ends, the same mbaps write is acked and the "+
						"DER's own PF register moves to the mbaps-commanded value (PF %s) — %s §2 (\"else "+
						"mbaps\")", trimNum(ext006MbapsFixedPF.PF()), envelopeDesignDoc),
					How: "this row's own second mbaps write to PFWInj_PF/_Ext, issued after the CSIP " +
						"control's cancellation, decoded from the raw MBAP response; the DER's own model " +
						"704 PF sync group read independently afterward",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext006ReleasedKey)
					},
				},
			}
		},
	}
}

// ext006Write encodes and sends one PFWInj_PF/_Ext write — the two are
// contiguous in L704 (pinned by TestL704EnvelopeSpansAreContiguous).
func ext006Write(sess *suitessm.EnvelopeSession, model suitessm.ModelBlock, want FixedPFSettings) (envelopeWriteOutcome, error) {
	block, err := readModelBlock(sess, model, "EXT-006 model 704 pre-write read")
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	extReg, _ := wantExt(want.Excitation)
	off, span, err := contiguousWrite(sunspec.L704, block, "PFWInj_PF", 2, func(v sunspec.View) error {
		if err := v.SetFloat("PFWInj_PF", want.PF()); err != nil {
			return err
		}
		v.SetEnum("PFWInj_Ext", extReg)
		return nil
	})
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	return mbapsWriteSpan(sess, model, off, span, fmt.Sprintf("EXT-006 PFWInj_PF write (PF %s)", trimNum(want.PF()))), nil
}

// pfSnapshotUnchanged reports whether the DER's PF sync group is the same
// between two independent reads, within fixedPFTolerance.
func pfSnapshotUnchanged(before, after sunspec.ACControls) bool {
	return before.PFWInjEna == after.PFWInjEna && before.PFWInjExt == after.PFWInjExt &&
		abs(before.PFWInjPF-after.PFWInjPF) <= fixedPFTolerance
}

// pfSnapshotMatches reports whether the DER's PF sync group holds want, within
// fixedPFTolerance — the register-content comparison EXT-006's C3 claim
// makes, deliberately independent of PFWInjEna (the claim is about which
// VALUE the register holds, not about whether the axis is currently applied).
func pfSnapshotMatches(got sunspec.ACControls, want FixedPFSettings) bool {
	wantReg, _ := wantExt(want.Excitation)
	return got.PFWInjExt == wantReg && abs(got.PFWInjPF-want.PF()) <= fixedPFTolerance
}

// gradeAxisOwnedRefusal is EXT-006's first criterion.
func gradeAxisOwnedRefusal(w envelopeWriteOutcome, before, after sunspec.ACControls, beforeOK, afterOK bool,
	beforeWhy, afterWhy string) Finding {
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the mbaps PFWInj_PF write while CSIP owned the axis could not even be sent: %v", w.Err)}
	}
	if !w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the mbaps PFWInj_PF write while CSIP owned the axis was %s, not refused — %s §2 requires "+
				"exception 01 (illegal function) for a value-axis write while CSIP is actively commanding "+
				"it", w.describe(), envelopeDesignDoc)}
	}
	if w.Exception != mbap.ExIllegalFunction {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the mbaps PFWInj_PF write while CSIP owned the axis drew Modbus exception %d (%s), not 01 "+
				"(illegal function) — %s §2", uint8(w.Exception), w.Exception, envelopeDesignDoc)}
	}
	if !beforeOK || !afterOK {
		return unavailable("the write correctly drew exception 01, but the DER's own PF register could "+
			"not be read independently to confirm it did not move: before=%q after=%q", beforeWhy, afterWhy)
	}
	if !pfSnapshotUnchanged(before, after) {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the write correctly drew exception 01, but the DER's own PF register MOVED anyway: before "+
				"ena=%t pf=%s ext=%d, after ena=%t pf=%s ext=%d",
			before.PFWInjEna, trimNum(before.PFWInjPF), before.PFWInjExt,
			after.PFWInjEna, trimNum(after.PFWInjPF), after.PFWInjExt)}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the write drew Modbus exception 01 (illegal function) as %s §2 requires, and the DER's own PF "+
			"register did not move: ena=%t pf=%s ext=%d before and after",
		envelopeDesignDoc, before.PFWInjEna, trimNum(before.PFWInjPF), before.PFWInjExt)}
}

// gradeAxisReleaseDefault is EXT-006's second criterion — the device-default
// half, graded against the baseline Setup stashed BEFORE the CSIP control was
// ever published, per owner answer B.
func gradeAxisReleaseDefault(params map[string]string, atRelease sunspec.ACControls, ok bool, why string) Finding {
	baselinePF, havePF := params["ext006.baseline_pf"], params["ext006.baseline_pf"] != ""
	baselineExt := params["ext006.baseline_ext"]
	if !havePF {
		return unavailable("this row's own pre-publication baseline was never captured, so the device- " +
			"default claim cannot be checked against anything")
	}
	if !ok {
		return unavailable("could not read the DER's own PF register at release: %s", why)
	}
	var wantPF float64
	if _, err := fmt.Sscanf(baselinePF, "%g", &wantPF); err != nil {
		return unavailable("this row's own stashed baseline PF %q did not parse: %v", baselinePF, err)
	}
	var wantExtReg uint16
	if _, err := fmt.Sscanf(baselineExt, "%d", &wantExtReg); err != nil {
		return unavailable("this row's own stashed baseline excitation %q did not parse: %v", baselineExt, err)
	}
	if abs(atRelease.PFWInjPF-wantPF) <= fixedPFTolerance && atRelease.PFWInjExt == wantExtReg {
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"at release the DER's PF register reads pf=%s ext=%d, matching this row's own "+
				"pre-publication baseline (pf=%s ext=%s) — the device default, not a prior mbaps value "+
				"(%s §2 owner answer B)", trimNum(atRelease.PFWInjPF), atRelease.PFWInjExt, baselinePF,
			baselineExt, envelopeDesignDoc)}
	}
	return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
		"at release the DER's PF register reads pf=%s ext=%d, which does NOT match this row's own "+
			"pre-publication baseline (pf=%s ext=%s) — %s §2 owner answer B requires the axis to return "+
			"to the device default on release, not to some other value",
		trimNum(atRelease.PFWInjPF), atRelease.PFWInjExt, baselinePF, baselineExt, envelopeDesignDoc)}
}

// gradeAxisReleasedWrite is EXT-006's third criterion.
func gradeAxisReleasedWrite(w envelopeWriteOutcome, want FixedPFSettings, got sunspec.ACControls, gotOK bool,
	gotWhy string) Finding {
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the post-release mbaps PFWInj_PF write could not even be sent: %v", w.Err)}
	}
	if w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the post-release mbaps PFWInj_PF write drew Modbus exception %d (%s) — %s §2 requires it to "+
				"be acked once CSIP no longer owns the axis (\"else mbaps\")",
			uint8(w.Exception), w.Exception, envelopeDesignDoc)}
	}
	if !gotOK {
		return unavailable("the write was acked, but the DER's own PF register could not be read "+
			"independently afterward: %s", gotWhy)
	}
	if !pfSnapshotMatches(got, want) {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the write was acked, but the DER's own PF register reads pf=%s ext=%d, not the "+
				"mbaps-commanded pf=%s ext=%d", trimNum(got.PFWInjPF), got.PFWInjExt, trimNum(want.PF()),
			func() uint16 { r, _ := wantExt(want.Excitation); return r }())}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the write was ACKED, and the DER's own PF register moved to it: pf=%s ext=%d",
		trimNum(got.PFWInjPF), got.PFWInjExt)}
}

// ═══════════════════════════════════════════════════════════════════════════
// EXT-007 — fail-safe override kept (design §1.5/§2's connect/ceiling rows,
// owner answer C: "keep the override" — the single documented exception to
// "never beyond the envelope")
// ═══════════════════════════════════════════════════════════════════════════

// ext007CeilingPct is the mbaps WMaxLimPct value this row writes while the
// DUT's fail-safe is engaged — any value above zero export exercises the
// claim; this is not a boundary probe.
const ext007CeilingPct = 40.0

const (
	ext007CeilingKey = "ext007.ceiling"
	ext007ESKey      = "ext007.es"
)

// ext007PreconditionUnavailable is stashed under both criteria's keys when
// this row's own precondition — the DUT already in a fail-safe-engaged
// posture — is not met. This harness has no lever that can DRIVE a DUT into
// fail-safe: the fail-safe engages on comm-loss to the CSIP server (design
// §1.5), and no admin endpoint in sim/gridsim (checked: AdminClient's only
// operations are Status/Logs/Control/Clock/Responses/DERPuts/LogEvents/
// Chain/SwapChain/RestoreChain — nothing silences or pauses the server) lets
// this bench simulate a comm-loss from inside a certify run. So this row is
// IMPLEMENTED BUT PRECONDITIONED, exactly as the task that requested it
// anticipated: it reads the DUT's own reported posture
// (certify.ReadAuthority's FailsafeEngaged, the same field
// preflight_authority.go already reads off GET /mode) and grades for real
// when an operator has engaged the fail-safe out of band before the run —
// otherwise both criteria report this reason as SKIP, never as a FAIL of the
// DUT for a precondition this bench itself could not arrange.
func ext007PreconditionUnavailable(reason string) Finding {
	return unavailable("this row's precondition (the DUT already in a fail-safe-engaged posture) is not "+
		"met: %s. No lever in this harness can DRIVE a DUT into fail-safe — sim/gridsim's admin API has "+
		"no silence/pause endpoint — so this row is IMPLEMENTED BUT PRECONDITIONED: engage the fail-safe "+
		"out of band (e.g. block the DUT's route to gridsim, or power gridsim off) and re-run", reason)
}

func envelopeFailsafeOverride(nonce string) certify.Check {
	s := envelopeFailsafeOverrideSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// envelopeFailsafeOverrideSpec builds EXT-007's spec. It publishes NO CSIP
// control — fail-safe engaged means CSIP is SILENT (design §1.5) — so unlike
// EXT-005/006/008 all of its work happens in PostWait, which spec.PostWait's
// own doc says runs unconditionally and is the right hook for "a fact that is
// internal DUT state and not wire-observable at all", exactly CORE-005's own
// precedent for reading rc.Gateway/the dev API rather than the wire.
func envelopeFailsafeOverrideSpec(nonce string) spec {
	return spec{
		PostWait: func(ctx context.Context, d *Driver, params map[string]string) error {
			if !d.rc.Gateway.Available() {
				f := ext007PreconditionUnavailable("no gateway introspection is configured (-gateway-ssh " +
					"or -gateway-exec), so this row cannot read the DUT's own failsafe_engaged posture at all")
				stashFinding(params, ext007CeilingKey, f)
				stashFinding(params, ext007ESKey, f)
				return nil
			}
			reading, err := certify.ReadAuthority(ctx, d.rc.Gateway, certify.DefaultDevAPI)
			if err != nil {
				f := ext007PreconditionUnavailable(fmt.Sprintf("could not read the DUT's posture: %v", err))
				stashFinding(params, ext007CeilingKey, f)
				stashFinding(params, ext007ESKey, f)
				return nil
			}
			if !reading.FailsafeEngaged {
				f := ext007PreconditionUnavailable(fmt.Sprintf("the DUT reports %s", reading.String()))
				stashFinding(params, ext007CeilingKey, f)
				stashFinding(params, ext007ESKey, f)
				return nil
			}

			sess, skip := suitessm.DialEnvelopeRole(ctx, d.rc, gridServiceRole)
			if skip != nil {
				f := unavailable("could not open the mbaps GridService session this row needs: %s", skip.Notes)
				stashFinding(params, ext007CeilingKey, f)
				stashFinding(params, ext007ESKey, f)
				return nil
			}
			defer sess.Close()

			if m704, ok := sess.Chain.Model(704); ok {
				before := readCeilingSnapshot(ctx, d.rc)
				w, err := ext005Write(sess, m704, ext007CeilingPct)
				if err != nil {
					stashFinding(params, ext007CeilingKey,
						unavailable("could not encode/send the fail-safe-engaged WMaxLimPct write: %v", err))
				} else {
					if err := d.rc.Sleep(ctx, envelopeSettle); err != nil {
						d.rc.Logf("this row's settle wait ended early: %v", err)
					}
					after := readCeilingSnapshot(ctx, d.rc)
					stashFinding(params, ext007CeilingKey, gradeFailsafeCeilingAdmitted(w, ext007CeilingPct, before, after))
				}
			} else {
				stashFinding(params, ext007CeilingKey,
					unavailable("the DUT's mbaps chain (%v) serves no model 704", sess.Chain.IDs()))
			}

			if m703, ok := sess.Chain.Model(703); ok {
				w, err := ext007WriteES(sess, m703)
				if err != nil {
					stashFinding(params, ext007ESKey,
						unavailable("could not encode/send the fail-safe-engaged ES=1 write: %v", err))
				} else {
					stashFinding(params, ext007ESKey, gradeFailsafeESRefused(w))
				}
			} else {
				stashFinding(params, ext007ESKey,
					unavailable("the DUT's mbaps chain (%v) serves no model 703", sess.Chain.IDs()))
			}
			return nil
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("checked the DUT's own reported control posture and, when it reported "+
				"fail-safe engaged, wrote an mbaps GridServiceSunSpec WMaxLimPct above zero export and a "+
				"703 ES=1 — %s §1.5/§2, owner answer C", envelopeDesignDoc)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				{
					Claim: fmt.Sprintf("while the DUT's fail-safe is engaged, an mbaps GridServiceSunSpec "+
						"704 WMaxLimPct write above zero export (%.2f%%) IS ADMITTED (no Modbus exception) "+
						"and the DER's own ceiling register RISES — %s §1.5 (owner answer C: \"the "+
						"existing override stays\", the single documented exception to never beyond the "+
						"envelope)", ext007CeilingPct, envelopeDesignDoc),
					How: "this row's own mbaps write to WMaxLimPct, decoded from the raw MBAP response; " +
						"the DER's own active-power ceiling register read independently before and after",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext007CeilingKey)
					},
				},
				{
					Claim: fmt.Sprintf("while the DUT's fail-safe is engaged, an mbaps GridServiceSunSpec "+
						"703 ES=1 write still draws Modbus exception 01 (illegal function) — %s §1.5/§2: "+
						"\"703 ES=1 stays refused while engaged\", the one axis the override does not "+
						"reach", envelopeDesignDoc),
					How:         "this row's own mbaps write to model 703's ES point, decoded from the raw MBAP response",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext007ESKey)
					},
				},
			}
		},
	}
}

// ext007WriteES encodes and sends a 703 ES=1 write.
func ext007WriteES(sess *suitessm.EnvelopeSession, model suitessm.ModelBlock) (envelopeWriteOutcome, error) {
	block, err := readModelBlock(sess, model, "EXT-007 model 703 pre-write read")
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	off, span, err := contiguousWrite(sunspec.L703, block, "ES", 1, func(v sunspec.View) error {
		v.SetEnum("ES", 1)
		return nil
	})
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	return mbapsWriteSpan(sess, model, off, span, "EXT-007 ES=1 write (fail-safe engaged)"), nil
}

// gradeFailsafeCeilingAdmitted is EXT-007's first criterion.
func gradeFailsafeCeilingAdmitted(w envelopeWriteOutcome, pct float64, before, after ceilingSnapshot) Finding {
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the fail-safe-engaged WMaxLimPct write could not even be sent: %v", w.Err)}
	}
	if w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the fail-safe-engaged WMaxLimPct write drew Modbus exception %d (%s), not admitted — %s "+
				"§1.5 (owner answer C) keeps the override: while engaged, mbaps may raise output above "+
				"the fail-safe ceiling", uint8(w.Exception), w.Exception, envelopeDesignDoc)}
	}
	if !after.Available {
		return unavailable("the write was acked, but the DER's own ceiling register could not be read "+
			"independently afterward: %s", after.Note)
	}
	if math.Abs(after.Raw-pct) > ext004CeilingBaselineToleranceP {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the write was acked, but the DER's own ceiling register reads %.4f%%, not the commanded "+
				"%.2f%%", after.Raw, pct)}
	}
	if before.Available && after.Raw <= before.Raw {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the write was acked and the DER's own ceiling register reads the commanded %.2f%%, but it "+
				"did not RISE above the pre-write reading (%.4f%% -> %.4f%%), which fail-safe (a "+
				"zero-export envelope) requires it to have started below", pct, before.Raw, after.Raw)}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the write was ACKED and the DER's own ceiling register rose to the commanded %.2f%% (from "+
			"%.4f%% to %.4f%%), the fail-safe override %s §1.5/§2 documents", pct, before.Raw, after.Raw,
		envelopeDesignDoc)}
}

// gradeFailsafeESRefused is EXT-007's second criterion.
func gradeFailsafeESRefused(w envelopeWriteOutcome) Finding {
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the fail-safe-engaged ES=1 write could not even be sent: %v", w.Err)}
	}
	if !w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the fail-safe-engaged ES=1 write was %s, not refused — %s §1.5/§2 keeps ES=1 refused while "+
				"engaged: this is the one axis the override does not reach", w.describe(), envelopeDesignDoc)}
	}
	if w.Exception != mbap.ExIllegalFunction {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the fail-safe-engaged ES=1 write drew Modbus exception %d (%s), not 01 (illegal function) "+
				"— %s §1.5/§2", uint8(w.Exception), w.Exception, envelopeDesignDoc)}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the ES=1 write drew Modbus exception 01 (illegal function) as %s §1.5/§2 requires while "+
			"fail-safe is engaged", envelopeDesignDoc)}
}

// ═══════════════════════════════════════════════════════════════════════════
// EXT-008 — envelope tightening / ownership take (design §2's Setpoint row,
// §1.1's "one arbitrated answer per axis": CSIP taking a value axis mbaps
// held drops the mbaps contribution; release restores the device default)
// ═══════════════════════════════════════════════════════════════════════════

const (
	// ext008StandingWattsW is the mbaps WSet value this row writes BEFORE any
	// CSIP opModFixedW control is in effect — plain watts, ACControls.WSet's
	// own unit.
	ext008StandingWattsW = 500.0
	// ext008SecondWattsW is the further mbaps WSet write this row attempts
	// WHILE the CSIP control owns the axis — a different value, so a bug that
	// let it through would be visible in the register comparison too, not
	// only in the exception code.
	ext008SecondWattsW = -300.0
	// ext008CSIPFixedWHundredths is the CSIP opModFixedW control's own
	// setpoint, in the CSIP-side hundredths-of-a-percent wire unit
	// (IW13-001) — 40.00% of nameplate.
	ext008CSIPFixedWHundredths = int64(4000)
	// ext008WSetFallbackToleranceW is the tolerance gradeStandingWrite falls
	// back to when the DER declares no usable WSet_SF (ACControls.WSetStepW
	// == 0, "granularity unknown to the gateway" — its own doc).
	ext008WSetFallbackToleranceW = 5.0
)

const (
	ext008StandingKey  = "ext008.standing"
	ext008OwnershipKey = "ext008.ownership"
	ext008DefaultKey   = "ext008.default"
)

func envelopeOwnershipTake(nonce string) certify.Check {
	s := envelopeOwnershipTakeSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// envelopeOwnershipTakeSpec builds EXT-008's spec: Setup captures the
// pre-publication WSet baseline, writes the standing mbaps setpoint (no CSIP
// control is in effect yet, so design §2's setpoint row admits it) and grades
// it, then publishes the CSIP opModFixedW control the row's SECOND and third
// claims are about. PostWait grades the ownership take once the control is
// Started; Change drives gridsim's cancel lever and grades the return to
// default — the same session-captured-across-hooks shape EXT-006 uses.
func envelopeOwnershipTakeSpec(nonce string) spec {
	mrid := withRunNonce("CERT-EXT008-OWNERSHIP-TAKE", nonce)
	var sess *suitessm.EnvelopeSession
	var model suitessm.ModelBlock
	var haveModel bool

	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			base, ok, why := read704(ctx, d.rc)
			if !ok {
				f := unavailable("could not read the DER's own pre-publication model 704 image to "+
					"establish this row's device-default baseline: %s", why)
				stashFinding(params, ext008DefaultKey, f)
				stashFinding(params, ext008StandingKey, f)
				return nil
			}
			params["ext008.baseline_wset"] = trimNum(base.WSet)
			params["ext008.baseline_wset_ena"] = fmt.Sprintf("%t", base.WSetEna)

			var skip *certify.Result
			sess, skip = suitessm.DialEnvelopeRole(ctx, d.rc, gridServiceRole)
			if skip != nil {
				f := unavailable("could not open the mbaps GridService session this row needs: %s", skip.Notes)
				stashFinding(params, ext008StandingKey, f)
			} else if m, ok := sess.Chain.Model(704); !ok {
				stashFinding(params, ext008StandingKey,
					unavailable("the DUT's mbaps chain (%v) serves no model 704", sess.Chain.IDs()))
			} else {
				model, haveModel = m, true
				w, err := ext008WriteWSet(sess, model, ext008StandingWattsW)
				if err != nil {
					stashFinding(params, ext008StandingKey,
						unavailable("could not encode/send the standing mbaps WSet write: %v", err))
				} else {
					if err := d.rc.Sleep(ctx, envelopeSettle); err != nil {
						d.rc.Logf("this row's settle wait ended early: %v", err)
					}
					got, gotOK, gotWhy := read704(ctx, d.rc)
					stashFinding(params, ext008StandingKey,
						gradeStandingWrite(w, ext008StandingWattsW, got, gotOK, gotWhy))
				}
			}

			id, err := d.PostControl(ctx, ControlRequest{
				Program: envelopeProgram, MRID: mrid, Description: "EXT-008 ownership-take control",
				StartOffset: 0, DurationS: envelopeControlDurationS,
				FixedW: ptr(ext008CSIPFixedWHundredths), Activate: true,
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		Want: func(base ServerView) func(ServerView) bool {
			return base.WantResponseAtLeast(mrid, 2)
		},
		PostWait: func(ctx context.Context, d *Driver, params map[string]string) error {
			follows := oracleFixedW(ext008CSIPFixedWHundredths)(ctx, d.rc)
			if !haveModel || sess == nil {
				stashFinding(params, ext008OwnershipKey,
					unavailable("no mbaps session/model was resolved during this row's Setup, so the "+
						"further write while CSIP owns the axis could not be attempted"))
				return nil
			}
			w, err := ext008WriteWSet(sess, model, ext008SecondWattsW)
			if err != nil {
				stashFinding(params, ext008OwnershipKey,
					unavailable("could not encode/send the further mbaps WSet write: %v", err))
				return nil
			}
			stashFinding(params, ext008OwnershipKey, gradeOwnershipTakeEffect(follows, w))
			return nil
		},
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			if _, err := d.PostControl(ctx, ControlRequest{Program: envelopeProgram, MRID: mrid, Cancel: true}); err != nil {
				return err
			}
			if err := d.rc.Sleep(ctx, envelopeSettle); err != nil {
				return err
			}
			atRelease, ok, why := read704(ctx, d.rc)
			stashFinding(params, ext008DefaultKey, gradeSetpointReleaseDefault(params, atRelease, ok, why))
			return nil
		},
		ChangeWait: changeWaitFullCycle,
		Cleanup: func(ctx context.Context, d *Driver) {
			if sess != nil {
				sess.Close()
				sess = nil
			}
			_ = d.releaseProgramControls(ctx, envelopeProgram)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("wrote a standing mbaps WSet setpoint (%.1f W), published a CSIP "+
				"opModFixedW control (%s, %.2f%%) and waited %s for it to be Started, attempted a "+
				"further mbaps WSet write (%.1f W) while it was in effect, then cancelled it — %s §2 "+
				"(Setpoint row)", ext008StandingWattsW, mrid, float64(ext008CSIPFixedWHundredths)/100,
				o.Waited.Round(rounding), ext008SecondWattsW, envelopeDesignDoc)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResponseStarted(mrid),
				{
					Claim: fmt.Sprintf("an mbaps GridServiceSunSpec 704 WSet write made BEFORE any CSIP "+
						"opModFixedW control is in effect stands: it is acked and the DER's own WSet "+
						"register reads it (%.1f W) — %s §2 (\"else mbaps\")",
						ext008StandingWattsW, envelopeDesignDoc),
					How: "this row's own mbaps write to WSet, decoded from the raw MBAP response; the " +
						"DER's own model 704 WSet register read independently afterward",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext008StandingKey)
					},
				},
				{
					Claim: fmt.Sprintf("once the CSIP opModFixedW control (%s) starts, the DER's own WSet "+
						"register follows CSIP's commanded value (%.2f%%), not the standing mbaps value, "+
						"and a further mbaps WSet write (%.1f W) draws Modbus exception 01 (illegal "+
						"function) — %s §1.1/§2: CSIP taking a value axis mbaps held drops the mbaps "+
						"contribution", mrid, float64(ext008CSIPFixedWHundredths)/100, ext008SecondWattsW,
						envelopeDesignDoc),
					How: "the DER's own model 704 WSet register, read through the same effect-based " +
						"oracle BASIC-013 uses (oracleFixedW); this row's own further mbaps write, " +
						"decoded from the raw MBAP response",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext008OwnershipKey)
					},
				},
				{
					Claim: fmt.Sprintf("when the control ends, the DER's own WSet register returns to the "+
						"device default captured at this row's own pre-publication baseline, not to the "+
						"prior mbaps value (%.1f W) — %s §2 owner answer B", ext008StandingWattsW,
						envelopeDesignDoc),
					How: "the DER's own model 704 WSet register, read once before this row published " +
						"anything (the device-default baseline) and again after the CSIP control's " +
						"cancellation was served and this row's settle window elapsed",
					Tier:        tierMbapsWrite,
					LoadBearing: true,
					Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
						return recallFinding(o.Params, ext008DefaultKey)
					},
				},
			}
		},
	}
}

// ext008WriteWSet encodes and sends one WSetEna/WSetMod/WSet write — the
// three are contiguous in L704 (pinned by TestL704EnvelopeSpansAreContiguous).
func ext008WriteWSet(sess *suitessm.EnvelopeSession, model suitessm.ModelBlock, watts float64) (envelopeWriteOutcome, error) {
	block, err := readModelBlock(sess, model, "EXT-008 model 704 pre-write read")
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	off, span, err := contiguousWrite(sunspec.L704, block, "WSetEna", 4, func(v sunspec.View) error {
		v.SetBool("WSetEna", true)
		v.SetEnum("WSetMod", sunspec.M704_WSetMod_Watts)
		return v.SetFloat("WSet", watts)
	})
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	return mbapsWriteSpan(sess, model, off, span, fmt.Sprintf("EXT-008 WSet write (%.1f W)", watts)), nil
}

// gradeStandingWrite is EXT-008's first criterion.
func gradeStandingWrite(w envelopeWriteOutcome, wantWatts float64, got sunspec.ACControls, gotOK bool,
	gotWhy string) Finding {
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the standing mbaps WSet write could not even be sent: %v", w.Err)}
	}
	if w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the standing mbaps WSet write (no CSIP opModFixedW control was yet in effect) drew Modbus "+
				"exception %d (%s), not admitted — %s §2's setpoint row admits mbaps absent a CSIP "+
				"contribution on the axis", uint8(w.Exception), w.Exception, envelopeDesignDoc)}
	}
	if !gotOK {
		return unavailable("the write was acked, but the DER's own WSet register could not be read "+
			"independently afterward: %s", gotWhy)
	}
	tol := got.WSetStepW
	if tol <= 0 {
		tol = ext008WSetFallbackToleranceW
	}
	if !got.WSetEna || math.Abs(got.WSet-wantWatts) > tol {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the write was acked, but the DER's own WSet register reads ena=%t %.1f W, not the "+
				"commanded %.1f W", got.WSetEna, got.WSet, wantWatts)}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the write was ACKED and the DER's own WSet register holds it: ena=%t %.1f W", got.WSetEna, got.WSet)}
}

// gradeOwnershipTakeEffect is EXT-008's second criterion, combining the two
// sub-facts the task's own claim states as one sentence: the DER follows
// CSIP, and mbaps is refused.
func gradeOwnershipTakeEffect(follows Finding, w envelopeWriteOutcome) Finding {
	if follows.Unavailable != "" {
		return unavailable("the DER's own WSet-follows-CSIP effect could not be confirmed: %s", follows.Unavailable)
	}
	if follows.Verdict != certify.Pass {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's own WSet register did not come to follow the CSIP opModFixedW control: %s",
			follows.Observed)}
	}
	if w.Err != nil {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's own WSet register followed CSIP (%s), but the further mbaps WSet write could not "+
				"even be sent: %v", follows.Observed, w.Err)}
	}
	if !w.HasException {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's own WSet register followed CSIP (%s), but the further mbaps WSet write was %s, "+
				"not refused — %s §1.1/§2 requires exception 01 while CSIP owns the setpoint axis",
			follows.Observed, w.describe(), envelopeDesignDoc)}
	}
	if w.Exception != mbap.ExIllegalFunction {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's own WSet register followed CSIP (%s), but the further mbaps WSet write drew "+
				"Modbus exception %d (%s), not 01 (illegal function)", follows.Observed, uint8(w.Exception),
			w.Exception)}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the DER's own WSet register followed the CSIP control (%s), and the further mbaps WSet write "+
			"correctly drew Modbus exception 01 (illegal function)", follows.Observed)}
}

// gradeSetpointReleaseDefault is EXT-008's third criterion.
func gradeSetpointReleaseDefault(params map[string]string, atRelease sunspec.ACControls, ok bool, why string) Finding {
	baseline, have := params["ext008.baseline_wset"], params["ext008.baseline_wset"] != ""
	if !have {
		return unavailable("this row's own pre-publication baseline was never captured, so the device-" +
			"default claim cannot be checked against anything")
	}
	if !ok {
		return unavailable("could not read the DER's own WSet register at release: %s", why)
	}
	var wantW float64
	if _, err := fmt.Sscanf(baseline, "%g", &wantW); err != nil {
		return unavailable("this row's own stashed baseline WSet %q did not parse: %v", baseline, err)
	}
	tol := atRelease.WSetStepW
	if tol <= 0 {
		tol = ext008WSetFallbackToleranceW
	}
	if math.Abs(atRelease.WSet-wantW) <= tol {
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"at release the DER's WSet register reads %.1f W, matching this row's own pre-publication "+
				"baseline (%.1f W) — the device default, not the prior mbaps value (%.1f W) (%s §2 owner "+
				"answer B)", atRelease.WSet, wantW, ext008StandingWattsW, envelopeDesignDoc)}
	}
	return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
		"at release the DER's WSet register reads %.1f W, which does NOT match this row's own "+
			"pre-publication baseline (%.1f W) — %s §2 owner answer B requires the axis to return to "+
			"the device default on release", atRelease.WSet, wantW, envelopeDesignDoc)}
}
