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

// read702CtrlModes reads the DER's own model 702 CtrlModes capability
// bitfield through the same southbound oracle path read704 uses —
// independent of both the mbaps and CSIP lanes — for EXT-008's own
// precondition: does this DER declare FIXED_W at all?
//
// REV0907-D2-P6C: on the bench solar DER it does not, and a standing mbaps
// WSet write drew Modbus exception 02 (illegal data address). The first
// reading of that 02 (this row's FIXED_W precondition, kept because it is a
// real precondition) was wrong: the 2026-09-10 re-run passed the precondition
// and still drew 02. The actual source is the product's SUN-002 pre-ack
// executability gate (lexa-gw internal/writes CheckExecutable over
// regmap's executedCommandPoints): WSetMod is advertised as writable but has
// NO executor in the product, so any window that covers it is refused 02
// before the ack — and this row's original single 4-register span
// WSetEna+WSetMod+WSet covered it. The row therefore writes the axis the way
// an EMS that respects SUN-002 must: WSet (Tint32, 2 registers) first, then
// WSetEna (Tenum16, 1 register), two Write Multiple Registers requests that
// never touch WSetMod (see ext008WriteWSet). TestL704EnvelopeSpansAreContiguous
// pins both spans against L704's declared field order.
func read702CtrlModes(ctx context.Context, rc *certify.RunCtx) (modes uint32, ok bool, why string) {
	uv, err := oracleUnitView(ctx, rc, oracleSimName)
	if err != nil {
		return 0, false, err.Error()
	}
	regs := uv.Regs[702]
	if len(regs) == 0 {
		return 0, false, "the DER serves no model 702, so its CtrlModes capability bitfield cannot be read"
	}
	return sunspec.Parse702(regs).CtrlModes, true, ""
}

// ext008DeclaresFixedW answers EXT-008's own precondition question from an
// already-read CtrlModes bitfield — split out from read702CtrlModes so the
// bit test is directly unit-testable without a live sim
// (TestExt008DeclaresFixedW).
func ext008DeclaresFixedW(modes uint32) bool {
	return modes&sunspec.M702_CtrlMode_FixedW != 0
}

// ext008PreconditionUnavailable is stashed under all three of EXT-008's
// criterion keys when the DER does not declare FIXED_W in its own model 702
// CtrlModes — the same "IMPLEMENTED BUT PRECONDITIONED" shape
// ext007PreconditionUnavailable documents: SKIP with a load-bearing reason,
// never a FAIL of the DUT for a capability the DER itself never claims.
func ext008PreconditionUnavailable(reason string) Finding {
	return unavailable("this row's precondition (the DER declaring FIXED_W in its own model 702 "+
		"CtrlModes) is not met: %s. WSet is not a commandable point on a DER that does not advertise the "+
		"capability (REV0907-D2-P6C) — run this row against a DER that declares FIXED_W (e.g. the battery "+
		"DER) or arrange one on this bench and re-run", reason)
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

// awaitCancelAcknowledged is the release fence EXT-006/EXT-008's Change hooks
// stand behind before they read "the device default at release" or attempt
// the post-release mbaps write. REV0907-D2-P6A (bench 2026-09-10,
// runs/p6-rerun-be30002-20260910T162613Z): both rows POSTed the cancel and
// slept envelopeSettle (5 s), but the DUT is a POLLING client — it learns of
// a cancel only on its next walk, up to a whole pollRate later — so the
// "at release" read and the "post-release" write both landed BEFORE the DUT
// had ever seen the cancel (journal: cancel at ~12:42:48, the row's reads
// and write at 12:42:53, the DUT's poll + release at 12:43:01). The
// observations those rows graded as "the axis stayed CSIP-owned" were
// measurements of a control still legitimately in force. The fence is the
// same fact the design names as the release moment: the DUT's own Response
// status=6 (Table 27 "event cancelled") for the control, observed at the
// server, within the row's own poll-cycle window (d.pollWindow — the same
// window the Want phase waited on, so the two halves of a row share one
// cadence). base must be snapshotted BEFORE the cancel is posted, so a
// status=6 that predates the cancel (impossible for a live control, but a
// stale log line from an earlier run is not) cannot satisfy it.
func awaitCancelAcknowledged(ctx context.Context, d *Driver, base ServerView, mrid string) (waited time.Duration, ok bool) {
	_, waited, ok = d.Await(ctx, d.pollWindow, base.WantResponseAtLeast(mrid, 6))
	if ok {
		d.rc.Logf("the DUT acknowledged the cancel (Response status>=6 for %s) after %s", mrid, waited.Round(rounding))
	} else {
		d.rc.Logf("the DUT did not acknowledge the cancel (no Response status>=6 for %s) within %s", mrid, d.pollWindow)
	}
	return waited, ok
}

// cancelNotAcknowledged is the finding the release-phase criteria carry when
// awaitCancelAcknowledged came back false: measuring the DER then would grade
// a control still in force as a failed release, which is the exact
// misattribution REV0907-D2-P6A's first reading made.
func cancelNotAcknowledged(mrid string, window time.Duration, what string) Finding {
	return unavailable("the DUT never POSTed a Response status=6 for the cancelled control %s within the "+
		"poll-cycle window (%s), so %s could not be measured at a moment the axis was known to be released — "+
		"the control was still in force for everything this phase observed", mrid, window, what)
}

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
			preCancel := d.Snapshot(ctx)
			if _, err := d.PostControl(ctx, ControlRequest{Program: envelopeProgram, MRID: mrid, Cancel: true}); err != nil {
				return err
			}
			// The DUT polls: it sees the cancel on its next walk, not on the
			// POST. Stand behind its own status=6 (awaitCancelAcknowledged's
			// doc, REV0907-D2-P6A) and only THEN give lexa-mode the design
			// §1.1 propagation settle ("when a control ends, the envelope
			// relaxes to the default") before either read below.
			if _, acked := awaitCancelAcknowledged(ctx, d, preCancel, mrid); !acked {
				stashFinding(params, ext006DefaultKey, cancelNotAcknowledged(mrid, d.pollWindow,
					"the DER's own PF register at release"))
				stashFinding(params, ext006ReleasedKey, cancelNotAcknowledged(mrid, d.pollWindow,
					"the post-release mbaps PFWInj_PF write"))
				return nil
			}
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
// half, graded against the axis's own pre-publication baseline (Setup, before
// either author ever touched it), per owner answer B.
//
// # "Device default" is about what is IN FORCE, not about the raw register
//
// A 704 DER's PFWInj_PF register keeps its LAST-WRITTEN contents after
// PFWInjEna is cleared — that is what a value register on this model does,
// not a release failure (REV0907-D2-P6C's own bench evidence: WSet stayed
// 3200 while lexa-modbus logged the WSet axis withdrawn — "the device reports
// no active-power setpoint in force" — with WSetEna correctly cleared). So
// this grader's asserted claim is PFWInjEna matching the baseline's own
// PFWInjEna, not the raw PF register matching the baseline's raw PF register:
//
//   - Ena mismatched against the baseline is UNCONDITIONALLY a FAIL — this is
//     REV0907-D2-P6A's own shape: a control that ended but left the axis
//     still CSIP-owned (Ena/ownership never cleared, or cleared when the
//     baseline itself held it).
//   - Ena matched and FALSE (the ordinary case: neither author's default
//     state is "in force") is a PASS regardless of what the raw register
//     holds — the register is read and reported alongside it, never
//     asserted on, because §2's release rule is a claim about what the DER
//     is DOING, not about what one register remembers.
//   - Ena matched and TRUE (an unusual but legal factory default that ships
//     with the PF axis already in force) additionally requires the raw
//     value to match the baseline's — if the axis is genuinely in force,
//     "the device default" means the DEFAULT VALUE, not merely some value.
func gradeAxisReleaseDefault(params map[string]string, atRelease sunspec.ACControls, ok bool, why string) Finding {
	baselinePF, havePF := params["ext006.baseline_pf"], params["ext006.baseline_pf"] != ""
	baselineEnaStr, haveEna := params["ext006.baseline_ena"], params["ext006.baseline_ena"] != ""
	baselineExt := params["ext006.baseline_ext"]
	if !havePF || !haveEna {
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
	wantEna := baselineEnaStr == "true"

	if atRelease.PFWInjEna != wantEna {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"at release PFWInjEna reads %t, not matching this row's own pre-publication baseline enable "+
				"state (%t) — %s §2 owner answer B requires the axis to return to the device default "+
				"IN-FORCE state (this is REV0907-D2-P6A's own shape if PFWInjEna is still true: the axis "+
				"left CSIP-owned) (raw PF register, reported not asserted: pf=%s ext=%d, baseline was "+
				"pf=%s ext=%s)", atRelease.PFWInjEna, wantEna, envelopeDesignDoc, trimNum(atRelease.PFWInjPF),
			atRelease.PFWInjExt, baselinePF, baselineExt)}
	}
	if !wantEna {
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"at release PFWInjEna reads false, matching this row's own pre-publication baseline (also "+
				"false) — the axis is no longer in force, the device default %s §2 owner answer B "+
				"requires (reported, not asserted: raw PF register reads pf=%s ext=%d, baseline was pf=%s "+
				"ext=%s — a 704 DER's value register keeps its last-written contents after Ena clears, "+
				"which is not what this claim is about)", envelopeDesignDoc, trimNum(atRelease.PFWInjPF),
			atRelease.PFWInjExt, baselinePF, baselineExt)}
	}
	if abs(atRelease.PFWInjPF-wantPF) <= fixedPFTolerance && atRelease.PFWInjExt == wantExtReg {
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"at release the DER's PF register reads pf=%s ext=%d with PFWInjEna=true, matching this "+
				"row's own pre-publication baseline (pf=%s ext=%s, also in force) — the device default, "+
				"not a prior mbaps value (%s §2 owner answer B)", trimNum(atRelease.PFWInjPF),
			atRelease.PFWInjExt, baselinePF, baselineExt, envelopeDesignDoc)}
	}
	return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
		"at release PFWInjEna=true (matching the baseline's own in-force state), but the DER's PF "+
			"register reads pf=%s ext=%d, which does NOT match this row's own pre-publication baseline "+
			"value (pf=%s ext=%s) — %s §2 owner answer B requires the device DEFAULT value when the "+
			"baseline itself holds the axis in force", trimNum(atRelease.PFWInjPF), atRelease.PFWInjExt,
		baselinePF, baselineExt, envelopeDesignDoc)}
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

// ext007OutageWaitDefaultS is this row's own default wait window for the DUT
// to report failsafe_engaged=true after gridsim's northbound outage lever
// (R2, REV0907-D2) cuts its CSIP session off — overridable via -param
// ext007.failsafe_wait_s=<seconds>. The bench's shipped failsafe.json
// declares grace_s=900 (15 min — lexa-gw cmd/mode/config_test.go's "the
// shipped grace_s=900 must not warn" case is this exact value), and 960 s
// adds a minute of margin on top of the DUT's own grace period so this row's
// own poll cadence can never itself be the reason the wait comes up short.
const ext007OutageWaitDefaultS = 960

// ext007OutagePollInterval is how often this row re-reads the DUT's own
// failsafe_engaged posture while waiting for it to flip, in either
// direction — short enough that the bundle records roughly WHEN a flip
// happened, not merely that it eventually did.
const ext007OutagePollInterval = 15 * time.Second

// ext007ReleaseWaitS bounds how long this row waits, after releasing the
// outage lever, for the DUT to report failsafe_engaged=false again before
// moving on. A DUT slow to disengage is worth the log line this produces —
// not a reason for teardown to hang indefinitely, and not part of R2's own
// claim (which is about behaviour WHILE engaged).
const ext007ReleaseWaitS = 300

// ext007OutageAutoClearMarginS pads gridsim's own outage duration_s beyond
// this row's wait+release budget, so a run that panics or is killed mid-row
// still has the lever auto-clear (sim/gridsim/outage.go's own auto-clear)
// rather than leaving the bench northbound-dead for whatever runs next —
// belt-and-suspenders alongside this row's own explicit ClearOutage calls in
// both PostWait and Cleanup.
const ext007OutageAutoClearMarginS = 120

// ext007PreconditionUnavailable is stashed under both criteria's keys when
// this row cannot reach a fail-safe-engaged DUT at all: neither is the DUT
// already there (an operator arranged it out of band before the run) nor is
// gridsim's admin API reachable to drive it there with the northbound outage
// lever (R2, AdminClient.Outage). SKIP with this reason, never a FAIL of the
// DUT for a precondition this bench could not arrange.
func ext007PreconditionUnavailable(reason string) Finding {
	return unavailable("this row's precondition (the DUT in a fail-safe-engaged posture) is not met: %s",
		reason)
}

// ext007DriveOutcome is what ext007DecideDrive answers: given the DUT's own
// reported posture and whether gridsim's admin API is reachable, how (if at
// all) can this row reach a fail-safe-engaged DUT? Split out from PostWait's
// live network calls so the three shapes are directly unit-testable
// (TestExt007DecideDrive) without a live gateway or gridsim.
type ext007DriveOutcome int

const (
	// ext007AlreadyEngaged: the DUT already reports failsafe_engaged=true —
	// an operator arranged it out of band before the run. Grade directly;
	// nothing to arm.
	ext007AlreadyEngaged ext007DriveOutcome = iota
	// ext007ShouldDrive: not engaged yet, but gridsim's admin API is
	// reachable — arm the northbound outage lever (R2) and wait for it.
	ext007ShouldDrive
	// ext007CannotReach: not engaged, and no lever is reachable to drive it
	// there — SKIP.
	ext007CannotReach
)

// ext007DecideDrive is the pure decision behind the three shapes above.
func ext007DecideDrive(alreadyEngaged, adminAvailable bool) ext007DriveOutcome {
	switch {
	case alreadyEngaged:
		return ext007AlreadyEngaged
	case adminAvailable:
		return ext007ShouldDrive
	default:
		return ext007CannotReach
	}
}

// ext007OutageWaitSeconds resolves this row's own wait window for the DUT to
// report failsafe_engaged=true after the outage lever is armed — -param
// ext007.failsafe_wait_s=<seconds>, defaulting to ext007OutageWaitDefaultS.
// An absent, empty, unparseable or non-positive value falls back to the
// default rather than erroring: this parameter tunes a bench timing, and a
// malformed value silently keeping the documented default is a better
// failure mode than a row that cannot run at all over an operator typo.
func ext007OutageWaitSeconds(rc *certify.RunCtx) int {
	if v, ok := rc.Param("ext007.failsafe_wait_s"); ok && v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return ext007OutageWaitDefaultS
}

// ext007AwaitFailsafe polls the DUT's own failsafe_engaged posture
// (certify.ReadAuthority) every ext007OutagePollInterval until it equals
// want or waitS elapses. reached reports which was last observed; err is
// non-nil only for a READ failure — a posture that honestly stayed the wrong
// value for the whole window is a false return, not an error.
func ext007AwaitFailsafe(ctx context.Context, d *Driver, want bool, waitS int) (reached bool, err error) {
	deadline := time.Now().Add(time.Duration(waitS) * time.Second)
	for {
		reading, rerr := certify.ReadAuthority(ctx, d.rc.Gateway, certify.DefaultDevAPI)
		if rerr != nil {
			return false, rerr
		}
		if reading.FailsafeEngaged == want {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		if err := d.rc.Sleep(ctx, ext007OutagePollInterval); err != nil {
			return false, err
		}
	}
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
//
// R2 (REV0907-D2): this row no longer only WAITS for an operator to have
// engaged the DUT's fail-safe out of band. When gridsim's admin API is
// reachable (d.Admin.Available()) it DRIVES the DUT there itself: arms
// gridsim's northbound outage lever (AdminClient.Outage, mode "down" —
// every CSIP request the DUT makes is answered 503) for this row's own wait
// window plus a bench-safety margin, polls the DUT's own failsafe_engaged
// posture (ext007AwaitFailsafe) until it flips true or the window elapses,
// runs the same two writes/grades as before, then releases the lever
// (ClearOutage) and waits — best-effort, logged, never fatal to this row's
// own verdict — for the DUT to report disengaged before returning. A DUT an
// operator already engaged out of band (still supported, for a bench with no
// admin API configured) skips straight to grading. Only when NEITHER path is
// available — not already engaged, and no admin API to drive it — does this
// row fall back to the SKIP shape ext007PreconditionUnavailable documents.
// ext007DecideDrive is the pure decision the three shapes rest on.
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

			drove := false
			switch ext007DecideDrive(reading.FailsafeEngaged, d.Admin.Available()) {
			case ext007CannotReach:
				f := ext007PreconditionUnavailable(fmt.Sprintf("the DUT reports %s, and no gridsim admin "+
					"API is configured to drive it there with the northbound outage lever (R2)",
					reading.String()))
				stashFinding(params, ext007CeilingKey, f)
				stashFinding(params, ext007ESKey, f)
				return nil
			case ext007ShouldDrive:
				waitS := ext007OutageWaitSeconds(d.rc)
				outageDurationS := waitS + ext007ReleaseWaitS + ext007OutageAutoClearMarginS
				if err := d.Admin.Outage(ctx, certify.AdminOutageDown, outageDurationS, 0); err != nil {
					f := unavailable("could not arm gridsim's northbound outage lever to drive the DUT "+
						"into fail-safe (R2): %v", err)
					stashFinding(params, ext007CeilingKey, f)
					stashFinding(params, ext007ESKey, f)
					return nil
				}
				d.rc.Logf("EXT-007: armed gridsim's northbound outage (mode=%s) — waiting up to %s for "+
					"the DUT to report failsafe_engaged=true", certify.AdminOutageDown,
					(time.Duration(waitS) * time.Second).Round(time.Second))
				engaged, waitErr := ext007AwaitFailsafe(ctx, d, true, waitS)
				if waitErr != nil || !engaged {
					_ = d.Admin.ClearOutage(ctx)
					reason := fmt.Sprintf("armed gridsim's northbound outage lever, but the DUT never "+
						"reported failsafe_engaged=true within %ds", waitS)
					if waitErr != nil {
						reason = fmt.Sprintf("%s: %v", reason, waitErr)
					}
					f := ext007PreconditionUnavailable(reason)
					stashFinding(params, ext007CeilingKey, f)
					stashFinding(params, ext007ESKey, f)
					return nil
				}
				drove = true
			}
			// ext007AlreadyEngaged falls straight through to grading below —
			// nothing to arm, nothing to release.

			sess, skip := suitessm.DialEnvelopeRole(ctx, d.rc, gridServiceRole)
			if skip != nil {
				f := unavailable("could not open the mbaps GridService session this row needs: %s", skip.Notes)
				stashFinding(params, ext007CeilingKey, f)
				stashFinding(params, ext007ESKey, f)
				if drove {
					_ = d.Admin.ClearOutage(ctx)
				}
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

			if drove {
				if err := d.Admin.ClearOutage(ctx); err != nil {
					d.rc.Logf("EXT-007: could not release gridsim's northbound outage lever: %v — "+
						"Cleanup will retry", err)
				} else if _, err := ext007AwaitFailsafe(ctx, d, false, ext007ReleaseWaitS); err != nil {
					d.rc.Logf("EXT-007: released the outage lever, but could not confirm the DUT "+
						"reported failsafe_engaged=false within %ds: %v (not fatal to this row's own "+
						"verdict — the disengage window is a bench courtesy, not part of R2's own claim, "+
						"which is about behaviour WHILE engaged)", ext007ReleaseWaitS, err)
				}
			}
			return nil
		},
		Cleanup: func(ctx context.Context, d *Driver) {
			// Safety net: idempotent when PostWait already released the
			// lever, and the only release path left when PostWait returned
			// early (a transport error mid-row) without reaching its own
			// ClearOutage call.
			if d.Admin.Available() {
				_ = d.Admin.ClearOutage(ctx)
			}
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("drove the DUT into a fail-safe-engaged posture with gridsim's northbound "+
				"outage lever (R2) — or found one already arranged out of band — then over a role-bound "+
				"mbaps GridServiceSunSpec session wrote a WMaxLimPct above zero export and a 703 ES=1, "+
				"then released the lever — %s §1.5/§2, owner answer C", envelopeDesignDoc)
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
			modes, modesOK, modesWhy := read702CtrlModes(ctx, d.rc)
			if !modesOK || !ext008DeclaresFixedW(modes) {
				reason := fmt.Sprintf("could not read the DER's own CtrlModes: %s", modesWhy)
				if modesOK {
					reason = fmt.Sprintf("the DER's own CtrlModes reads 0x%08x, with bit 1 (FIXED_W) clear",
						modes)
				}
				f := ext008PreconditionUnavailable(reason)
				stashFinding(params, ext008StandingKey, f)
				stashFinding(params, ext008OwnershipKey, f)
				stashFinding(params, ext008DefaultKey, f)
				params["ext008.precondition_met"] = "false"
				return nil
			}
			params["ext008.precondition_met"] = "true"

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
			preCancel := d.Snapshot(ctx)
			if _, err := d.PostControl(ctx, ControlRequest{Program: envelopeProgram, MRID: mrid, Cancel: true}); err != nil {
				return err
			}
			// Same release fence as EXT-006 (awaitCancelAcknowledged's doc,
			// REV0907-D2-P6A): the DUT's own status=6 first, then the settle.
			if _, acked := awaitCancelAcknowledged(ctx, d, preCancel, mrid); !acked {
				stashFinding(params, ext008DefaultKey, cancelNotAcknowledged(mrid, d.pollWindow,
					"the DER's own WSet enable at release"))
				return nil
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
			crits := []criterion{}
			// No CSIP control is ever published when EXT-008's own
			// precondition (the DER declaring FIXED_W) is unmet — Setup
			// returns before PostControl in that case. critResponseStarted
			// would then grade a control that was never sent as a FAIL,
			// which is not what this row's SKIP means; EXT-007's own
			// precondition (which also publishes no control) has no such
			// criterion for the same reason.
			if o.Params["ext008.precondition_met"] != "false" {
				crits = append(crits, critResponseStarted(mrid))
			}
			return append(crits,
				criterion{
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
				criterion{
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
				criterion{
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
			)
		},
	}
}

// ext008WriteWSet sends the active-power setpoint as two Write Multiple
// Registers requests — WSet (Tint32, 2 registers) first so the value is in
// place before the function is enabled, then WSetEna (Tenum16, 1 register) —
// and never the WSetMod register between them, which the product refuses 02
// before the ack because it has no executor (REV0907-D2-P6C; SUN-002). Both
// spans are pinned by TestL704EnvelopeSpansAreContiguous. The returned
// outcome is the first non-ACK of the two (the WSet write's if it was
// refused, else the WSetEna write's), so a refusal on either register is what
// the row grades; when both ACK the outcome is the WSetEna write's ACK.
func ext008WriteWSet(sess *suitessm.EnvelopeSession, model suitessm.ModelBlock, watts float64) (envelopeWriteOutcome, error) {
	block, err := readModelBlock(sess, model, "EXT-008 model 704 pre-write read")
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	off, span, err := contiguousWrite(sunspec.L704, block, "WSet", 2, func(v sunspec.View) error {
		return v.SetFloat("WSet", watts)
	})
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	w := mbapsWriteSpan(sess, model, off, span, fmt.Sprintf("EXT-008 WSet write (%.1f W)", watts))
	if !w.Acked {
		return w, nil
	}
	off, span, err = contiguousWrite(sunspec.L704, block, "WSetEna", 1, func(v sunspec.View) error {
		v.SetBool("WSetEna", true)
		return nil
	})
	if err != nil {
		return envelopeWriteOutcome{}, err
	}
	return mbapsWriteSpan(sess, model, off, span, "EXT-008 WSetEna write (enable)"), nil
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

// gradeSetpointReleaseDefault is EXT-008's third criterion — the same
// enable-point-first grading gradeAxisReleaseDefault documents for EXT-006's
// PF axis, applied to WSet/WSetEna: a 704 DER's WSet register keeps its
// last-written contents after WSetEna clears (REV0907-D2-P6C's own bench
// evidence for this exact axis), so the asserted claim is WSetEna matching
// the baseline's own WSetEna, not the raw WSet register matching the
// baseline's raw WSet. See gradeAxisReleaseDefault's doc for the three cases
// (Ena mismatched -> FAIL, Ena matched false -> PASS regardless of the raw
// register, Ena matched true -> the raw value must also match).
func gradeSetpointReleaseDefault(params map[string]string, atRelease sunspec.ACControls, ok bool, why string) Finding {
	baseline, have := params["ext008.baseline_wset"], params["ext008.baseline_wset"] != ""
	baselineEnaStr, haveEna := params["ext008.baseline_wset_ena"], params["ext008.baseline_wset_ena"] != ""
	if !have || !haveEna {
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
	wantEna := baselineEnaStr == "true"
	tol := atRelease.WSetStepW
	if tol <= 0 {
		tol = ext008WSetFallbackToleranceW
	}

	if atRelease.WSetEna != wantEna {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"at release WSetEna reads %t, not matching this row's own pre-publication baseline enable "+
				"state (%t) — %s §2 owner answer B requires the axis to return to the device default "+
				"IN-FORCE state (this is REV0907-D2-P6A's own shape if WSetEna is still true: the axis "+
				"left CSIP-owned) (raw WSet register, reported not asserted: %.1f W, baseline was %.1f W)",
			atRelease.WSetEna, wantEna, envelopeDesignDoc, atRelease.WSet, wantW)}
	}
	if !wantEna {
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"at release WSetEna reads false, matching this row's own pre-publication baseline (also "+
				"false) — the axis is no longer in force, the device default %s §2 owner answer B "+
				"requires (reported, not asserted: raw WSet register reads %.1f W, baseline was %.1f W, "+
				"standing mbaps write was %.1f W — a 704 DER's value register keeps its last-written "+
				"contents after Ena clears, which is not what this claim is about)", envelopeDesignDoc,
			atRelease.WSet, wantW, ext008StandingWattsW)}
	}
	if math.Abs(atRelease.WSet-wantW) <= tol {
		return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
			"at release the DER's WSet register reads %.1f W with WSetEna=true, matching this row's "+
				"own pre-publication baseline (%.1f W, also in force) — the device default, not the "+
				"prior mbaps value (%.1f W) (%s §2 owner answer B)", atRelease.WSet, wantW,
			ext008StandingWattsW, envelopeDesignDoc)}
	}
	return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
		"at release WSetEna=true (matching the baseline's own in-force state), but the DER's WSet "+
			"register reads %.1f W, which does NOT match this row's own pre-publication baseline value "+
			"(%.1f W) — %s §2 owner answer B requires the device DEFAULT value when the baseline itself "+
			"holds the axis in force", atRelease.WSet, wantW, envelopeDesignDoc)}
}
