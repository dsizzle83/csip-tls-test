package suitemodbusserver

// checks_crv.go implements CRV-1, Curve 1 Support, of SunSpec Modbus
// Conformance Test Procedures v1.4 §2.5.1.
//
// # Why CRV-1 is here and CRV-2 / CRV-3 are not
//
// The three curve procedures are not one family. CRV-1 asserts a REFUSAL —
// curve 1 exists, is declared read-only, and its points cannot be written —
// while CRV-2 and CRV-3 both require a WRITABLE second curve and the
// adopt-curve handshake that commits it. The DUT's read-only posture is what
// makes CRV-2 and CRV-3 unrunnable and is exactly what CRV-1 asks about, so the
// three separate on the product's own behaviour rather than on the fact that
// they share a section number.
//
// # The correction this file records
//
// Until 2026-07-28 all three were catalogued inapplicable with the same reason:
// that the gateway's chain builder REJECTS models 705-712 northbound. That
// stopped being true when the curve models joined the class chains, and the
// current shape is device-conditional: a unit carries 703 and 705-712 if and
// only if its own DER serves them southbound (lexa-gw
// internal/regmap/chain.go's deviceConditionalModels, applied by
// ClassModelsFor). So a curve model IS reachable northbound, and whether one is
// present on a given unit is a fact about that unit's DER — which is the same
// per-(build, DER model) scoping MOD-4 carries.
//
// # What the Stage-6 legacy projection changed, and what it did not
//
// The gateway's Stage-6 read-only projection (the D4 read-only-verbatim
// decision, lexa-gw docs/design/LEGACY_CURVES_RC0_2026-08-14.md §5.5) put a
// SECOND curve generation northbound: the legacy 12x family, served as itself
// rather than translated into a 7xx. curveModels (models.go) carries both
// generations and says which member is which.
//
// That generation can be verified where the 7xx one still cannot, and the
// reason is a property of the DUT rather than a decision of this suite. On the
// legacy family the product's read-only posture is UNIVERSAL — not one point of
// any of the nine has an executor, so every write to every one of them is
// refused before the acknowledgement (lexa-gw internal/regmap/pointgroups.go's
// executedCommandPoints, whose legacy absence IS the posture) — and a universal
// claim can be probed at any register this suite can name. So CRV-1 now reports
// a per-model sub-verdict for each of 126-134 and 160: the procedure is
// labelled per model (CRV-1.705, CRV-1.706), and the legacy ones are CRV-1.126,
// CRV-1.127 and so on.
//
// Steps 2 and 3 AT CURVE-1 GRANULARITY are still not answerable for either
// generation, and are still reported as SKIPs naming why. The 7xx models size
// their repeating blocks from NPt / NCrv / NCrvSet / NCtl read out of the
// device; the legacy models' banks are flat but untranscribed here. Either way
// the read-only indicator and the registers a curve-1-specific write test would
// target cannot be located, and locating them by arithmetic on a guessed
// geometry would produce a confident verdict about whichever registers the
// guess landed on — which is worse than no verdict at all, because it would
// read as evidence.
//
// A registered SKIP with a reason is an engineering judgement. An unregistered
// row is an oversight. That is why this check exists in this shape rather than
// not existing.
//
// # What "refused before the acknowledgement" is, concretely, on this surface
//
// It is the response TYPE, not the register's later value. The DUT's serve
// ladder (lexa-gw internal/listener/serve.go) resolves a write in this order:
// AuthZ, then writes.Decode against the unit's layout, then
// writes.CheckExecutable, and only THEN the durable outbox submit and
// mbap.BuildWriteResp — the acknowledgement. Every refusal above returns a
// Modbus exception ADU instead, so nothing is ever acknowledged and then
// dropped. Two of those gates are the ones a legacy write meets:
//
//	0x02  ExIllegalAddress. The point IS in the model's commanded group, so
//	      Decode accepted it, and writes.CheckExecutable then rejected the
//	      whole request because no executor applies it (serve.go's step 7b, the
//	      SUN-002 honesty gate). This is the shape a write to ActCrv / WGra /
//	      ArGraMod takes on 126-132 and 134.
//	0x03  ExIllegalValue. Decode itself refused: the point is in no commanded
//	      group, so the write decoder's defence in depth rejected it before the
//	      executor question was ever asked (serve.go's step 7). This is the
//	      shape a write to model 160 takes — 160 declares no writable point at
//	      all, so it has no commanded group.
//
// Both are refusals before the acknowledgement and both satisfy the D4 posture.
// A THIRD outcome, exception 0x01, is not: it is how an authorization denial is
// expressed on this product, which means the write never reached the write path
// and the posture was not exercised by that run. CRV-1 reports that as WARN
// with the reason, not as a PASS it did not earn.
//
// The one outcome that FAILS is a normal write response. An acknowledged write
// is an acknowledged write whether or not the register later reads unchanged;
// ack-then-silently-drop is precisely what SUN-002 exists to forbid, and a
// suite that graded on the readback instead of the response would call it a
// pass.
//
// # Why the probe writes the value that is already there
//
// The probe reads its point and writes that same value straight back — the same
// control-write discipline writes.go documents for the write-driven procedures.
// It cannot be refused for being out of range, out of enumeration or
// mid-point (the probe points are single-register whole points, asserted at
// package init), so a refusal can only be about writability. And in the failure
// case — the DUT accepting it — the value written is the value already present,
// so a conformance run that catches this defect still commands nothing. That
// matters more here than elsewhere: 126's ActCrv SELECTS the live curve bank,
// and a probe that wrote a different index would be a control action nobody
// authorised.
//
// The register's value across the write is RECORDED and not graded. These
// registers mirror the DER, and a mirrored register may legitimately move
// between two reads for reasons that have nothing to do with this suite's
// write, so a change is not evidence the write took effect and stability is not
// evidence it did not.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"lexa-proto/mbap"
)

const (
	// The subject claim names BOTH generations. It used to say "of the 7xx
	// range", which stopped being true when the Stage-6 projection put the
	// legacy 12x family northbound: a run on a legacy DER's unit would have
	// reported a 7xx claim over 126/129/130/131/132/134 evidence.
	crv1ClaimSubject = "a curve-based model — of the 7xx range, or of the legacy 12x family the DUT's " +
		"Stage-6 read-only projection serves as itself — is present in the DUT's northbound projection, " +
		"which is CTP §2.5's precondition for performing the curve tests at all"
	crv1ClaimReadOnly = "curve 1 is present in the model's curve repeating block and is declared " +
		"read-only by the device"
	crv1ClaimRefused = "a write to a point belonging to curve 1 does not take effect: the DUT answers " +
		"with a Modbus exception (per EXC-2, code 2, 3 or 4) or the value reads back unchanged"
)

// crv1NoLayout is the reason steps 2 and 3 cannot be asserted AT CURVE-1
// GRANULARITY, for either generation. It names the suite's own gap rather than
// anything about the DUT, because a reader who mistook it for a DUT finding
// would be reading a harness limit as a defect.
const crv1NoLayout = "this suite carries no transcription of either curve generation's bank layout. Models " +
	"705-712 size their repeating blocks from the NPt / NCrv / NCrvSet / NCtl geometry points read out of " +
	"the device; the legacy 12x models' banks are flat but are transcribed here to one probe point each " +
	"and no further. Either way curve 1's sub-block, its read-only indicator point (which the source " +
	"document does not name) and the registers a curve-1-specific write attempt would target cannot be " +
	"located, and computing them from a guessed geometry would yield a verdict about whichever registers " +
	"the guess landed on. What CAN be asserted is the MODEL-level read-only posture of the legacy family, " +
	"and the per-model CRV-1.126 .. CRV-1.160 assertions in this same test case do exactly that. Closing " +
	"the rest needs the flattened curve layouts transcribed into models.go, the same gap MOD-4's " +
	"per-point sweep reports for these models"

// legacyProbe is one legacy curve model's read-only verification: what was
// found in the chain, what read, what the write was answered with, and the
// sub-verdict that follows.
type legacyProbe struct {
	// Def is the model's curveModels entry.
	Def curveModel
	// Ref is where the discovery walk found it. The zero value means the walk
	// did not find it, in which case the probe was never driven and Observed
	// carries the reason.
	Ref modelRef

	// BlockRegs is how many registers of the model's footprint read back.
	BlockRegs int

	// Before and After are the probe point's value either side of the write.
	Before, After []uint16
	// AfterErr is the re-read's failure, when there was one.
	AfterErr error

	// WriteErr is how the DUT answered the write. nil means it ACKNOWLEDGED
	// it, which is the one answer the D4 posture forbids.
	WriteErr error
	// Acked is the same fact stated positively, so a reader of this struct
	// cannot mistake a nil error for "not attempted".
	Acked bool

	// Fatal marks a transport failure: the stream is no longer trustworthy and
	// the sweep must stop rather than report the models after this one.
	Fatal bool

	// Verdict, Observed and Note are the sub-verdict this probe produces.
	Verdict  certify.Verdict
	Observed string
	Note     string
	// TIDs are the transactions the probe used, for citation.
	TIDs []uint16
}

// crv1LegacyClaim is the per-model claim text. The procedure is labelled per
// model, so the label is in the claim.
func crv1LegacyClaim(cm curveModel) string {
	if !cm.Served {
		return fmt.Sprintf("CRV-1.%d: model %d is not part of the DUT's northbound projection at all, so "+
			"the procedure has no subject for it on any unit", cm.ID, cm.ID)
	}
	return fmt.Sprintf("CRV-1.%d: model %d (%s) is served READ-ONLY on the DUT's northbound projection — "+
		"its whole register block reads back, and a write to %s of the value that register already holds "+
		"is REFUSED with a Modbus exception rather than acknowledged",
		cm.ID, cm.ID, cm.Name, cm.Probe.Name)
}

// crv1LegacyMethod describes how the claim was reached.
func crv1LegacyMethod(cm curveModel) string {
	if !cm.Served {
		return "the discovery walk, read against the DUT's registered model set"
	}
	return fmt.Sprintf("FC 3 read of the model's whole register block; FC 3 single-point read of %s at "+
		"model offset %d (%s); FC 6 write of that same value back to it; FC 3 re-read. The graded "+
		"criterion is the RESPONSE TYPE — an exception ADU is a refusal before the acknowledgement, a "+
		"normal write response is an acknowledgement — not the register's later value",
		cm.Probe.Name, cm.Probe.Off, cm.ProbeSource)
}

// runLegacyProbe performs one legacy model's read-only verification.
func runLegacyProbe(c *client, ref modelRef, cm curveModel) *legacyProbe {
	p := &legacyProbe{Def: cm, Ref: ref}
	first := len(c.log)
	defer func() { p.TIDs = tidsSince(c, first) }()

	note := fmt.Sprintf("CRV-1.%d", cm.ID)
	where := fmt.Sprintf("model %d @%d L=%d", cm.ID, ref.Addr, ref.L)

	// Reachable and readable: the whole footprint, header included.
	block, err := readModelBlock(c, ref, note+" block read")
	p.BlockRegs = len(block)
	if err != nil {
		p.gradeUnreadable(where, "the model's whole register block", err)
		return p
	}
	if cm.Probe.End() > ref.span() {
		p.Verdict = certify.Fail
		p.Observed = fmt.Sprintf("%s; the declared length does not reach %s at model offset %d, so the "+
			"model's own header contradicts its point table", where, cm.Probe.Name, cm.Probe.Off)
		return p
	}

	// The probe point on its own, which is also MOD-1 step 5's "readable as a
	// single point" for the one point of this model this suite transcribes.
	p.Before, err = readPointNow(c, ref, cm.Probe, note+" probe read")
	if err != nil {
		p.gradeUnreadable(where, fmt.Sprintf("%s as a single point", cm.Probe.Name), err)
		return p
	}

	// The write: the value that is already there, so nothing is commanded
	// whichever way the DUT answers.
	p.WriteErr = writePoint(c, ref, cm.Probe, p.Before,
		note+" write-back of the unchanged current value")
	p.Acked = writeWasAcked(c)

	// The re-read is recorded, never graded — see the file header.
	p.After, p.AfterErr = readPointNow(c, ref, cm.Probe, note+" probe re-read")

	p.gradeWrite(where)
	return p
}

// writeWasAcked reports whether the DUT answered the write this suite just sent
// with a NORMAL response rather than an exception.
//
// It reads the exchange log rather than the returned error, and the difference
// is not pedantry. writePoint returns a non-nil error for TWO different
// answers: an exception (a refusal, which is what this claim wants) and a
// normal response whose echoed address or value does not match the request (a
// framing defect). The second is still an acknowledgement — the DUT chose the
// success function code — and grading it off the error alone would have scored
// a DUT that acknowledged the write and then echoed it wrong as a PASS, which
// is the exact failure this whole check exists to catch, wearing a different
// hat. The bit that separates them is on the wire: an exception response's
// function code has 0x80 set and a normal one's does not.
func writeWasAcked(c *client) bool {
	if len(c.log) == 0 {
		return false
	}
	resp := c.log[len(c.log)-1].Resp
	return len(resp) > 0 && resp[0]&0x80 == 0
}

// gradeUnreadable grades a model that is in the chain but did not read. The two
// unit-availability exceptions are separated from everything else because they
// say the procedure could not be carried out, which is not the same statement
// as a conformance failure.
func (p *legacyProbe) gradeUnreadable(where, what string, err error) {
	e, isExc := asException(err)
	if isExc && (e.Code == mbap.ExGatewayPath || e.Code == mbap.ExGatewayTarget) {
		p.Verdict = certify.Skip
		p.Observed = fmt.Sprintf("%s; reading %s was answered %s: the addressed unit is unknown or its "+
			"southbound device has never reported, so this model's read-only posture was not exercised "+
			"and no conformance conclusion about it follows from this run",
			where, what, errText(err))
		return
	}
	if !isExc {
		// Not a protocol answer: the stream's position is unknown from here.
		p.Fatal = true
		p.Verdict = certify.Skip
		p.Observed = fmt.Sprintf("%s; reading %s failed on the transport (%s). The session is no longer "+
			"frame-aligned, so this model and every model after it went unexamined",
			where, what, errText(err))
		return
	}
	p.Verdict = certify.Fail
	p.Observed = fmt.Sprintf("%s is in this unit's chain but reading %s was refused: %s. A model the "+
		"gateway chose to chain must be readable — the projection claims the function by carrying it",
		where, what, errText(err))
}

// gradeWrite turns the DUT's answer to the write-back into the sub-verdict. The
// ladder is the one the file header sets out, and every branch says which of
// the product's gates it attributes the answer to.
func (p *legacyProbe) gradeWrite(where string) {
	state := fmt.Sprintf("%s; %d registers read; %d.%s @%d read %s before the write and %s after",
		where, p.BlockRegs, p.Def.ID, p.Def.Probe.Name, int(p.Ref.Addr)+p.Def.Probe.Off,
		regsText(p.Before), afterText(p.After, p.AfterErr))

	if p.Acked {
		malformed := ""
		if p.WriteErr != nil {
			// A normal response that is not a well-formed echo. Still an
			// acknowledgement — the DUT chose the success function code — and
			// separately a framing defect, so both are reported.
			malformed = fmt.Sprintf(" Its echo was also malformed: %s.", errText(p.WriteErr))
		}
		p.Verdict = certify.Fail
		p.Observed = fmt.Sprintf("%s. The DUT ANSWERED THE WRITE NORMALLY — a response carrying the "+
			"request's own function code rather than the exception code — so it ACKNOWLEDGED a write to a "+
			"model the D4 read-only-verbatim posture serves read-only.%s An acknowledgement is a failure "+
			"of this claim whether or not the register later reads unchanged: the posture refuses before "+
			"the acknowledgement, and an acknowledged-then-dropped write reports a success the client "+
			"cannot detect is false", state, malformed)
		return
	}

	e, isExc := asException(p.WriteErr)
	if !isExc {
		p.Fatal = true
		p.Verdict = certify.Skip
		p.Observed = fmt.Sprintf("%s. The write failed on the transport (%s) rather than being answered, "+
			"so the session is no longer frame-aligned and neither this model nor any after it was "+
			"examined", state, errText(p.WriteErr))
		return
	}

	switch e.Code {
	case mbap.ExIllegalAddress: // 0x02
		p.Verdict = certify.Pass
		p.Observed = fmt.Sprintf("%s. The write was answered %s. On this product that is the SUN-002 "+
			"honesty gate: the point is writable per the register map and the RBAC grammar, no executor "+
			"applies it, and the whole request is rejected BEFORE the acknowledgement rather than "+
			"acknowledged and dropped", state, errText(p.WriteErr))
	case mbap.ExIllegalValue: // 0x03
		p.Verdict = certify.Pass
		p.Observed = fmt.Sprintf("%s. The write was answered %s. On this product that is the write "+
			"decoder's defence in depth: the point belongs to no commanded group, so the request is "+
			"refused at decode, before the executor question is asked and before any acknowledgement",
			state, errText(p.WriteErr))
	case mbap.ExIllegalFunction: // 0x01
		p.Verdict = certify.Warn
		p.Observed = fmt.Sprintf("%s. The write was answered %s. That is an AUTHORIZATION denial on this "+
			"product, not the read-only posture: the request was refused above the write path, so this "+
			"run did not exercise whether the model's points have executors. The register is unwritable "+
			"to THIS role, which is a weaker statement than the one this claim makes, and it is reported "+
			"as such rather than as a pass", state, errText(p.WriteErr))
		p.Note = "re-run with a role whose grant reaches this model to exercise the read-only posture itself"
	case mbap.ExGatewayPath, mbap.ExGatewayTarget: // 0x0A / 0x0B
		p.Verdict = certify.Skip
		p.Observed = fmt.Sprintf("%s. The write was answered %s: the addressed unit is unknown or its "+
			"southbound device has never reported, so no write could be carried out and the posture was "+
			"not exercised", state, errText(p.WriteErr))
	default:
		p.Verdict = certify.Warn
		p.Observed = fmt.Sprintf("%s. The write was answered %s. It was NOT acknowledged, so the register "+
			"is not writable — but this suite cannot attribute that exception code to either of the two "+
			"gates the D4 posture refuses through (0x02 the executor gate, 0x03 the decoder), so it "+
			"reports the refusal without claiming to know which policy produced it", state,
			errText(p.WriteErr))
	}
}

// checkCRV1 implements SS-MODBUS-CONF-v1.4 CRV-1, Curve 1 Support.
//
// The procedure is labelled per model — CRV-1.705, CRV-1.706 and so on — and
// the catalog carries one row, so the check sweeps the curve models and reports
// them together, exactly as MOD-1..MOD-3 do. The 126-134/160 range gets one
// named sub-verdict per model whether or not the model is present, because a
// reader checking the report against the range must be able to see why each
// number is or is not there.
func checkCRV1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "CRV-1 curve 1 support")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	present := map[uint16]modelRef{}
	var all, curves, family []string
	for _, ref := range ch.Models {
		all = append(all, fmt.Sprintf("%d", ref.ID))
		cm, isCurve := curveModels[ref.ID]
		if !isCurve {
			continue
		}
		if _, dup := present[ref.ID]; !dup {
			present[ref.ID] = ref
		}
		if cm.CurveBased {
			curves = append(curves, fmt.Sprintf("%d", ref.ID))
		} else {
			family = append(family, fmt.Sprintf("%d", ref.ID))
		}
	}

	// The legacy sweep. Every entry of the 126-134/160 range is reported;
	// stopped is set when a transport failure made the rest unexaminable, so
	// the models after it say that rather than reporting a false absence.
	var probes []*legacyProbe
	stopped := ""
	for _, id := range curveModelIDs() {
		cm := curveModels[id]
		if cm.Gen != curveGenLegacy {
			continue
		}
		if stopped != "" {
			probes = append(probes, &legacyProbe{Def: cm, Verdict: certify.Skip, Observed: stopped})
			continue
		}
		ref, in := present[id]
		if !in {
			probes = append(probes, &legacyProbe{Def: cm, Verdict: certify.Skip,
				Observed: absentReason(cm, ch)})
			continue
		}
		p := runLegacyProbe(s.client, ref, cm)
		probes = append(probes, p)
		if p.Fatal {
			stopped = fmt.Sprintf("the sweep stopped at model %d on a transport failure, so this model "+
				"was never addressed and its absence from the results below is a fact about the run, "+
				"not about the DUT", p.Def.ID)
		}
	}

	subject := len(curves) > 0
	observed := fmt.Sprintf("chain: %s; curve-based models present: %s; curve-family models present that "+
		"are not curve-based (CTP §2.5's precondition does not reach them): %s",
		orNone(all), orNone(curves), orNone(family))

	verified, failed, warned := 0, 0, 0
	for _, p := range probes {
		switch p.Verdict {
		case certify.Pass:
			verified++
		case certify.Fail:
			failed++
		case certify.Warn:
			warned++
		}
	}

	// The roll-up reports what was measured and nothing else. FAIL when a
	// served legacy model was writable; WARN when a refusal could not be
	// attributed to the posture; PASS when at least one legacy model's
	// read-only posture was verified end to end; SKIP when none was, which is
	// where a 7xx-only unit and a unit with no curve model at all both land —
	// steps 2 and 3 at curve-1 granularity are unreachable for either.
	verdict := certify.Skip
	switch {
	case failed > 0:
		verdict = certify.Fail
	case warned > 0:
		verdict = certify.Warn
	case verified > 0:
		verdict = certify.Pass
	}

	notes := fmt.Sprintf("%s. Legacy 12x sweep: %d model(s) verified read-only, %d failed, %d "+
		"inconclusive, of the 126-134/160 range. Steps 2 and 3 were not asserted at curve-1 "+
		"granularity: %s.", observed, verified, failed, warned, crv1NoLayout)
	if !subject {
		notes = fmt.Sprintf("%s. CTP §2.5's precondition scopes the curve tests to 'each curve-based "+
			"model implemented in the device', and this unit implements none, so the procedure has no "+
			"subject here. On this DUT that is a statement about the DER behind the unit rather than "+
			"about the gateway: the curve and trip models of both generations are chained "+
			"device-conditionally, a unit carrying one only if its own DER serves it southbound. The "+
			"per-model rows below say which of 126-134/160 were looked for and what was found.", observed)
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				claims := []string{crv1ClaimSubject, crv1ClaimReadOnly, crv1ClaimRefused}
				for _, p := range probes {
					claims = append(claims, crv1LegacyClaim(p.Def))
				}
				return skipAll(ev, reason, claims...), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}

			// Step 1's precondition, from the chain the walk actually read.
			if subject {
				a, err := c.frames(crv1ClaimSubject,
					"the SunSpec model chain walked from the standard base address",
					certify.Pass, observed, tidsFor(s.client.log, "DEV-1 model header"))
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			} else {
				out = append(out, ev.SkipAssertion(crv1ClaimSubject,
					"the SunSpec model chain walked from the standard base address",
					"the chain carries no curve-based model on this unit — "+observed+
						". The gateway chains 703, 705-712 and the legacy 12x family "+
						"device-conditionally, so this is a property of the DER behind the unit, and "+
						"the procedure's own precondition excludes it"))
			}

			out = append(out,
				ev.SkipAssertion(crv1ClaimReadOnly, "read of the curve repeating block", crv1NoLayout),
				ev.SkipAssertion(crv1ClaimRefused, "write attempt to a curve-1 point", crv1NoLayout))

			// The per-model rows. A probe with no transactions behind it was
			// never driven — not served, not present, or after a stop — and
			// says so as a SKIP rather than borrowing another model's frames.
			for _, p := range probes {
				claim, method := crv1LegacyClaim(p.Def), crv1LegacyMethod(p.Def)
				if len(p.TIDs) == 0 {
					out = append(out, ev.SkipAssertion(claim, method, p.Observed))
					continue
				}
				a, err := c.frames(claim, method, p.Verdict, p.Observed, p.TIDs)
				if err != nil {
					return nil, err
				}
				if p.Note != "" {
					a.Note = joinNote(a.Note, p.Note)
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// absentReason says why a legacy model the range names is not in this unit's
// chain. The two reasons are different in kind and the report must not conflate
// them: 133 cannot be served by this build at all, while the other eight are
// device-conditional and their absence is a fact about the DER.
func absentReason(cm curveModel, ch *chain) string {
	if !cm.Served {
		return cm.NotServed + ". The discovery walk confirms it: " + ch.Summary()
	}
	return fmt.Sprintf("the discovery walk found no model %d in this unit's chain (%s). The gateway chains "+
		"the legacy 12x family device-conditionally — a unit carries one if and only if its own DER serves "+
		"it southbound — so this is a property of the DER behind the unit and not of the gateway, and the "+
		"procedure's precondition excludes it. It is reported rather than omitted so a reader checking the "+
		"126-134/160 range against this report can see that the model was looked for", cm.ID, ch.Summary())
}

// regsText renders a probe point's registers for an Observed field.
func regsText(regs []uint16) string {
	if len(regs) == 0 {
		return "nothing"
	}
	parts := make([]string, 0, len(regs))
	for _, r := range regs {
		parts = append(parts, fmt.Sprintf("0x%04x", r))
	}
	return strings.Join(parts, " ")
}

// afterText renders the post-write re-read, which may itself have failed.
func afterText(regs []uint16, err error) string {
	if err != nil {
		return "unread (" + errText(err) + ")"
	}
	return regsText(regs)
}

func orNone(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, ", ")
}
