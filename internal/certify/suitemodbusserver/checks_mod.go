package suitemodbusserver

// checks_mod.go implements the General SunSpec Model Tests of SunSpec Modbus
// Conformance Test Procedures v1.4 §2.4: MOD-1 Model Implementation, MOD-2
// Model Read, MOD-3 Point Write.
//
// The document runs these once per model in the device and labels each instance
// "MOD-1.701", "MOD-2.702" and so on. The catalog has one row per procedure,
// not per model, so each check below sweeps every model the discovery walk
// found and emits one assertion per model — the per-model labelling survives in
// the claim text, and the roll-up verdict is the worst of them, which is what
// "the test is performed once for each model implemented" means when it is
// reported as a single row.
//
// A model this suite has no transcription for (the runtime-geometry curve
// models 705-712, or a vendor model) gets an explicit SKIP naming the model and
// the reason. It is not silently dropped, because a reader counting assertions
// against a chain listing would otherwise never know a model went unexamined.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// modelReport is one model's outcome across a sweep.
type modelReport struct {
	Ref modelRef
	Def *Model

	// Block is the model's whole register footprint, header included.
	Block   []uint16
	ReadErr error

	// Skip is set when the model was not examined, and says why.
	Skip string

	LenOK       bool
	LenObserved string

	MandatoryOK   bool
	MandatoryText string

	SinglesOK   bool
	SinglesText string

	// TIDs are the transactions this model's examination used.
	TIDs []uint16
}

// sweepModels reads every model in the chain and evaluates it against this
// suite's transcription. label prefixes the exchange notes so the citation
// phase can select this sweep's transactions.
func sweepModels(c *client, ch *chain, label string, singlePointSweep bool) []*modelReport {
	var out []*modelReport
	for _, ref := range ch.Models {
		rep := &modelReport{Ref: ref}
		before := len(c.log)

		def, transcribed := Models[ref.ID]
		rep.Def = def

		block, err := readModelBlock(c, ref, fmt.Sprintf("%s model %d", label, ref.ID))
		rep.Block, rep.ReadErr = block, err
		if err != nil {
			rep.Skip = fmt.Sprintf("the model's register block could not be read: %s", errText(err))
			rep.TIDs = tidsSince(c, before)
			out = append(out, rep)
			continue
		}

		switch {
		case !transcribed && curveModels[ref.ID]:
			rep.Skip = fmt.Sprintf("model %d is a runtime-geometry curve model: its register offsets depend on "+
				"the NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no "+
				"transcription of its layout, so a per-point sweep would be guessing", ref.ID)
		case !transcribed:
			rep.Skip = fmt.Sprintf("this suite carries no transcription of model %d, so its point set cannot "+
				"be checked; the model was located and its declared length was read", ref.ID)
		}
		if rep.Skip != "" {
			rep.TIDs = tidsSince(c, before)
			out = append(out, rep)
			continue
		}

		// Step 2 — the model's declared length must equal the register span its
		// contents actually need.
		geometry := map[string]uint16{}
		if p, ok := def.Point("NPrt"); ok {
			if regs, ok := pointRegs(block, p); ok && len(regs) == 1 {
				geometry["NPrt"] = regs[0]
			}
		}
		if want, ok := expectedLen(ref.ID, geometry); ok {
			rep.LenOK = int(ref.L) == want
			rep.LenObserved = fmt.Sprintf("model %d declares L=%d; its definition requires %d", ref.ID, ref.L, want)
			if len(geometry) > 0 {
				rep.LenObserved += fmt.Sprintf(" (geometry %v)", geometry)
			}
		} else {
			rep.LenOK = true
			rep.LenObserved = fmt.Sprintf("model %d declares L=%d; its length is runtime-variable and this "+
				"suite cannot predict it, so the declared length is recorded but not judged", ref.ID, ref.L)
		}

		// Step 3 — every point the model definition marks mandatory must carry
		// a real value, and ID and L specifically must be right.
		var bad []string
		idOK, lOK := false, false
		if p, ok := def.Point("ID"); ok {
			if regs, ok := pointRegs(block, p); ok && len(regs) == 1 {
				idOK = regs[0] == ref.ID
				if !idOK {
					bad = append(bad, fmt.Sprintf("ID reads %d, want %d", regs[0], ref.ID))
				}
			}
		}
		if p, ok := def.Point("L"); ok {
			if regs, ok := pointRegs(block, p); ok && len(regs) == 1 {
				lOK = regs[0] == ref.L
				if !lOK {
					bad = append(bad, fmt.Sprintf("L reads %d, want %d", regs[0], ref.L))
				}
			}
		}
		for _, p := range def.Points {
			if !p.Mandatory || p.Name == "ID" || p.Name == "L" {
				continue
			}
			regs, ok := pointRegs(block, p)
			if !ok {
				bad = append(bad, fmt.Sprintf("%s: the declared length does not reach it", p.Name))
				continue
			}
			if p.Type.NotImplemented(regs) {
				bad = append(bad, fmt.Sprintf("%s: mandatory, but reads its type's not-implemented value", p.Name))
			}
		}
		rep.MandatoryOK = idOK && lOK && len(bad) == 0
		if rep.MandatoryOK {
			rep.MandatoryText = fmt.Sprintf("ID=%d L=%d and every mandatory point of model %d carries an "+
				"implemented value", ref.ID, ref.L, ref.ID)
		} else {
			rep.MandatoryText = strings.Join(bad, "; ")
		}

		// Step 5 — every point readable as a single point, every value inside
		// its datatype range.
		if singlePointSweep {
			var singleBad []string
			read := 0
			for _, p := range def.Points {
				if p.End() > len(block) {
					continue
				}
				regs, err := readPoint(c, ref, p, fmt.Sprintf("%s single-point model %d", label, ref.ID))
				if err != nil {
					singleBad = append(singleBad, fmt.Sprintf("%s: %s", p.Name, errText(err)))
					continue
				}
				read++
				if !p.Type.InDatatypeRange(regs) {
					singleBad = append(singleBad, fmt.Sprintf("%s (%s): value % 04x is outside the type's range",
						p.Name, p.Type, regs))
				}
			}
			rep.SinglesOK = len(singleBad) == 0
			if rep.SinglesOK {
				rep.SinglesText = fmt.Sprintf("all %d points of model %d read individually, every value inside "+
					"its datatype range", read, ref.ID)
			} else {
				rep.SinglesText = strings.Join(singleBad, "; ")
			}
		} else {
			rep.SinglesOK = true
		}

		rep.TIDs = tidsSince(c, before)
		out = append(out, rep)
	}
	return out
}

// tidsSince returns the transaction identifiers logged since index i.
func tidsSince(c *client, i int) []uint16 {
	var out []uint16
	for _, x := range c.log[i:] {
		out = append(out, x.TID)
	}
	return out
}

// checkMOD1 implements SS-MODBUS-CONF-v1.4 MOD-1, Model Implementation.
func checkMOD1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "MOD-1 model implementation")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}
	reports := sweepModels(s.client, ch, "MOD-1", true)

	verdict := certify.Pass
	examined, skipped := 0, 0
	for _, r := range reports {
		if r.Skip != "" {
			skipped++
			continue
		}
		examined++
		if !r.LenOK || !r.MandatoryOK || !r.SinglesOK {
			verdict = certify.Fail
		}
	}
	if examined == 0 {
		verdict = certify.Skip
	}

	return certify.Result{
		Verdict: verdict,
		Notes: fmt.Sprintf("%d model(s) examined, %d not transcribed by this suite; chain %s",
			examined, skipped, ch.Summary()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"every model declares the length its contents require",
					"every model implements its mandatory points",
					"every point of every model can be read as a single point, in datatype range"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			for _, r := range reports {
				if r.Skip != "" {
					out = append(out, ev.SkipAssertion(
						fmt.Sprintf("MOD-1.%d: model %d is implemented correctly", r.Ref.ID, r.Ref.ID),
						"per-model examination against this suite's transcription of the model definition",
						r.Skip))
					continue
				}
				a, err := c.frames(
					fmt.Sprintf("MOD-1.%d step 2: model %d declares the length its contents require", r.Ref.ID, r.Ref.ID),
					"FC 3 read of the two-register model header, compared against this suite's transcription "+
						"of the model definition (and, for a variable-length model, the geometry points read "+
						"from the device)",
					verdictIf(r.LenOK), r.LenObserved, r.TIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)

				a, err = c.frames(
					fmt.Sprintf("MOD-1.%d step 3: model %d implements its mandatory points, ID and L included",
						r.Ref.ID, r.Ref.ID),
					"FC 3 read of the model's whole register block; each mandatory point compared against its "+
						"type's not-implemented sentinel",
					verdictIf(r.MandatoryOK), r.MandatoryText, r.TIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)

				a, err = c.frames(
					fmt.Sprintf("MOD-1.%d step 5: every point of model %d can be read as a single point and "+
						"returns a value inside its datatype range", r.Ref.ID, r.Ref.ID),
					"one FC 3 request per point, quantity equal to the point's register width, at the point's "+
						"offset within the model",
					verdictIf(r.SinglesOK), r.SinglesText, r.TIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			out = append(out, ev.SkipAssertion(
				"the set of implemented points equals the set the PICS declares (MOD-1 step 4)",
				"comparison of the decoded point set against the PICS workbook",
				"no PICS workbook was supplied; the implemented point set is recorded by the assertions above, "+
					"but a device's own map cannot stand in for the conformance statement it is checked against"))
			return out, nil
		},
	}, nil
}

// checkMOD2 implements SS-MODBUS-CONF-v1.4 MOD-2, Model Read.
//
// One step: the whole model reads in a single request, or — only when its
// length exceeds the Modbus 125-register maximum — in several consecutive
// requests each within that limit, and every value is inside its datatype
// range. The 125 is the only number the document prints, and it is the number
// the check turns on: a model that needs two requests when one would have
// sufficed is a finding.
func checkMOD2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "MOD-2 model read")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	type readReport struct {
		Ref      modelRef
		Requests int
		Span     int
		OK       bool
		Text     string
		TIDs     []uint16
	}
	var reports []readReport
	verdict := certify.Pass

	for _, ref := range ch.Models {
		before := len(s.client.log)
		span := ref.span()
		rr := readReport{Ref: ref, Span: span}

		var values []uint16
		var rerr error
		if span <= maxReadRegisters {
			rr.Requests = 1
			values, rerr = s.client.readHolding(ref.Addr, uint16(span),
				fmt.Sprintf("MOD-2 whole model %d in one request", ref.ID))
		} else {
			rr.Requests = (span + maxReadRegisters - 1) / maxReadRegisters
			values, rerr = readModelBlock(s.client, ref, "MOD-2 chunked model")
		}
		rr.TIDs = tidsSince(s.client, before)

		switch {
		case rerr != nil:
			rr.OK = false
			rr.Text = fmt.Sprintf("model %d (%d registers, %d request(s)): %s",
				ref.ID, span, rr.Requests, errText(rerr))
			verdict = certify.Fail
		default:
			rr.OK = true
			rr.Text = fmt.Sprintf("model %d read in %d request(s) covering %d registers",
				ref.ID, rr.Requests, span)
			if span <= maxReadRegisters && rr.Requests != 1 {
				rr.OK = false
				rr.Text += fmt.Sprintf("; a %d-register model must be readable in one request", span)
				verdict = certify.Fail
			}
			if def, ok := Models[ref.ID]; ok {
				var bad []string
				for _, p := range def.Points {
					regs, ok := pointRegs(values, p)
					if !ok {
						continue
					}
					if !p.Type.InDatatypeRange(regs) {
						bad = append(bad, fmt.Sprintf("%s (%s) = % 04x", p.Name, p.Type, regs))
					}
				}
				if len(bad) > 0 {
					rr.OK = false
					rr.Text += "; values outside their datatype range: " + strings.Join(bad, ", ")
					verdict = certify.Fail
				}
			} else {
				rr.Text += "; this suite has no transcription of the model, so the returned values were not " +
					"range-checked"
			}
		}
		reports = append(reports, rr)
	}
	if len(reports) == 0 {
		verdict = certify.Skip
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   fmt.Sprintf("%d model(s) read; chain %s", len(reports), ch.Summary()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"every model can be read in a single request, or in consecutive requests when it exceeds "+
						"the Modbus 125-register maximum"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			for _, rr := range reports {
				a, err := c.frames(
					fmt.Sprintf("MOD-2.%d: model %d reads in a single Modbus request, or in consecutive "+
						"requests of at most 125 registers when it is longer than that", rr.Ref.ID, rr.Ref.ID),
					"FC 3 request(s) at the model's start address with quantity equal to its full span "+
						"(header included), each within the 125-register application-protocol maximum",
					verdictIf(rr.OK), rr.Text, rr.TIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// checkMOD3 implements SS-MODBUS-CONF-v1.4 MOD-3, Point Write.
//
// Steps: (1) every adjustable point accepts its minimum, its maximum and three
// intermediate values, or all its values when it has fewer than five; (2) every
// adjustable point can be written and then read, individually and as a group,
// with the read-back returning exactly what was written and no settling delay
// allowed — v1.3 removed the 1000 ms allowance v1.2 had introduced; (3) every
// enumeration value the PICS lists as supported is accepted.
func checkMOD3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "MOD-3 point write")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}
	noEnum := paramBool(rc, paramNoEnumWrite)

	type target struct {
		Adj    adjustable
		Ref    modelRef
		Def    Point
		Probe  *writeProbe
		Values []int64
		Text   string
		OK     bool
		// Exercised distinguishes "the criterion held" from "the criterion was
		// never reached because the DUT refused the control write".
		Exercised bool
		TIDs      []uint16
	}
	var targets []target
	var groupText string
	groupOK, groupExercised := false, false
	var groupTIDs []uint16

	for _, adj := range adjustables {
		ref, present := ch.Model(adj.Model)
		if !present {
			continue
		}
		def := Models[adj.Model]
		p, ok := def.Point(adj.Point)
		if !ok {
			continue
		}
		block, berr := readModelBlock(s.client, ref, "MOD-3 model snapshot")
		if berr != nil {
			return certify.Result{}, fmt.Errorf("read model %d: %w", adj.Model, berr)
		}

		t := target{Adj: adj, Ref: ref, Def: p}
		before := len(s.client.log)

		pr, perr := probeWrite(s.client, ref, p, fmt.Sprintf("MOD-3 %s", adj.key()))
		if perr != nil {
			return certify.Result{}, perr
		}
		t.Probe = pr
		if !pr.Accepted {
			t.Text = pr.Reason
			t.TIDs = tidsSince(s.client, before)
			targets = append(targets, t)
			continue
		}
		t.Exercised = true

		switch {
		case len(adj.Enum) > 0:
			if noEnum {
				t.Text = "the enumeration sweep was suppressed by -param " + paramNoEnumWrite +
					"; writing an enable is a real control action and the operator asked this run not to"
				t.Exercised = false
			} else {
				for _, v := range adj.Enum {
					t.Values = append(t.Values, int64(v))
				}
			}
		default:
			sf := 0
			if adj.SF != "" {
				v, ok := scaleFactor(s.client, ref, block, adj.SF)
				if !ok {
					t.Text = fmt.Sprintf("the scale factor %s is absent or not implemented, so the point's "+
						"engineering range cannot be converted to register values", adj.SF)
					t.Exercised = false
					t.TIDs = tidsSince(s.client, before)
					targets = append(targets, t)
					continue
				}
				sf = v
			}
			min, max := rawBounds(adj, sf)
			t.Values = sweepValues(min, max)
		}

		if t.Exercised {
			var bad []string
			for _, v := range t.Values {
				regs, eerr := encode(p, v)
				if eerr != nil {
					bad = append(bad, fmt.Sprintf("%d: %v", v, eerr))
					continue
				}
				if werr := writePoint(s.client, ref, p, regs,
					fmt.Sprintf("MOD-3 %s write %d", adj.key(), v)); werr != nil {
					bad = append(bad, fmt.Sprintf("write %d refused: %s", v, errText(werr)))
					continue
				}
				got, rerr := readPointNow(s.client, ref, p, fmt.Sprintf("MOD-3 %s read back %d", adj.key(), v))
				if rerr != nil {
					bad = append(bad, fmt.Sprintf("read back after writing %d: %s", v, errText(rerr)))
					continue
				}
				if g := decodeRaw(p, got); g != v {
					bad = append(bad, fmt.Sprintf("wrote %d, read back %d with no settling delay allowed", v, g))
				}
			}
			t.OK = len(bad) == 0
			if t.OK {
				t.Text = fmt.Sprintf("%d value(s) %v written and read back exactly; range source: %s",
					len(t.Values), t.Values, adj.Source)
			} else {
				t.Text = strings.Join(bad, "; ")
			}
		}

		if rerr := restore(s.client, pr, fmt.Sprintf("MOD-3 %s", adj.key())); rerr != nil {
			rc.Logf("MOD-3: could not restore %s: %v", adj.key(), rerr)
			t.Text += fmt.Sprintf("; WARNING: the pre-test value could not be restored: %s", errText(rerr))
		}
		t.TIDs = tidsSince(s.client, before)
		targets = append(targets, t)
	}

	// The group write the procedure's prose calls for: one FC 16 covering more
	// than one adjustable point. WMaxLimPctEna and WMaxLimPct are consecutive
	// single-register RW points, which is the shape the procedure describes.
	if ref, present := ch.Model(704); present {
		def := Models[704]
		ena, okE := def.Point("WMaxLimPctEna")
		pct, okP := def.Point("WMaxLimPct")
		if okE && okP && pct.Off == ena.Off+1 {
			before := len(s.client.log)
			orig, rerr := s.client.readHolding(ref.Addr+uint16(ena.Off), 2, "MOD-3 group write: read the pair")
			switch {
			case rerr != nil:
				groupText = "the adjustable pair could not be read: " + errText(rerr)
			default:
				werr := s.client.writeMultiple(ref.Addr+uint16(ena.Off), orig,
					"MOD-3 group write: FC 16 over two adjustable points")
				if werr != nil {
					groupText = denialReason(werr)
					if groupText == "" {
						groupText = errText(werr)
					}
				} else {
					groupExercised = true
					back, berr := s.client.readHolding(ref.Addr+uint16(ena.Off), 2, "MOD-3 group write: read back")
					switch {
					case berr != nil:
						groupText = "read-back after the group write: " + errText(berr)
					case back[0] != orig[0] || back[1] != orig[1]:
						groupText = fmt.Sprintf("wrote [0x%04x 0x%04x], read back [0x%04x 0x%04x]",
							orig[0], orig[1], back[0], back[1])
					default:
						groupOK = true
						groupText = fmt.Sprintf("one FC 16 request wrote WMaxLimPctEna and WMaxLimPct at %d..%d "+
							"and the read-back returned both values exactly",
							int(ref.Addr)+ena.Off, int(ref.Addr)+ena.Off+1)
					}
				}
			}
			groupTIDs = tidsSince(s.client, before)
		}
	}

	verdict := certify.Skip
	exercised := 0
	for _, t := range targets {
		if !t.Exercised {
			continue
		}
		exercised++
		if !t.OK {
			verdict = certify.Fail
		} else if verdict == certify.Skip {
			verdict = certify.Pass
		}
	}
	if groupExercised {
		exercised++
		if !groupOK {
			verdict = certify.Fail
		} else if verdict == certify.Skip {
			verdict = certify.Pass
		}
	}
	notes := fmt.Sprintf("%d of %d adjustable point(s) exercised", exercised, len(targets)+1)
	if exercised == 0 {
		notes = "no adjustable point could be exercised: the DUT refused every control write. " +
			"See the assertions for the exception the DUT returned to a valid, in-range write."
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"every adjustable point accepts its minimum, maximum and three intermediate values",
					"every adjustable point reads back exactly what was written, with no settling delay",
					"adjustable points can be written as a group in one FC 16 request",
					"every supported enumeration value is accepted"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			for _, t := range targets {
				claim := fmt.Sprintf("MOD-3.%d: the adjustable point %s accepts every value in its range and "+
					"reads back exactly what was written", t.Adj.Model, t.Adj.key())
				if len(t.Adj.Enum) > 0 {
					claim = fmt.Sprintf("MOD-3.%d step 3: the enumerated point %s accepts every supported "+
						"enumeration value", t.Adj.Model, t.Adj.key())
				}
				method := "FC 6 / FC 16 write of each value followed immediately by an FC 3 read of the same " +
					"point, with no settling delay allowed (v1.3 removed v1.2's 1000 ms allowance); the value " +
					"set is the point's minimum, maximum and three intermediates, or its full enumeration"
				if !t.Exercised {
					out = append(out, ev.SkipAssertion(claim, method, t.Text))
					continue
				}
				a, err := c.frames(claim, method, verdictIf(t.OK), t.Text, t.TIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			groupClaim := "MOD-3: adjustable points can be written as a group in a single FC 16 request and " +
				"read back"
			groupMethod := "one FC 16 request covering two consecutive adjustable points, followed by an FC 3 " +
				"read of the same two registers"
			switch {
			case groupText == "":
				out = append(out, ev.SkipAssertion(groupClaim, groupMethod,
					"the DUT serves no model with two consecutive adjustable points this suite is prepared to write"))
			case !groupExercised:
				out = append(out, ev.SkipAssertion(groupClaim, groupMethod, groupText))
			default:
				a, err := c.frames(groupClaim, groupMethod, verdictIf(groupOK), groupText, groupTIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// transportPlus starts a check's assertion list with the transport declaration.
//
// The declaration is context, not a conformance criterion of either source
// procedure, so it must never make a test case's verdict better than the
// procedure's own outcome. The runner rolls a case up to the WORST of its
// declared verdict and its assertions, and PASS outranks SKIP in that ordering
// — so a PASS transport assertion on a case that could not be exercised would
// silently promote a SKIP into a PASS. When the case skipped, the transport
// fact is therefore recorded as a SKIP assertion carrying the same observation:
// the information is in the bundle, and it cannot launder a verdict.
func transportPlus(c *citer, caseVerdict certify.Verdict) ([]certify.Assertion, error) {
	t, err := c.transportAssertion()
	if err != nil {
		return nil, err
	}
	if caseVerdict == certify.Skip {
		t.Verdict = certify.Skip
		t.Note = joinNote(t.Note, "recorded as context; this test case was not exercised, so nothing here "+
			"is claimed as a conformance result")
	}
	return []certify.Assertion{t}, nil
}
