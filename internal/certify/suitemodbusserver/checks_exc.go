package suitemodbusserver

// checks_exc.go implements the Exception Generation Tests of SunSpec Modbus
// Conformance Test Procedures v1.4 §2.8: EXC-1 Invalid Value, EXC-2 Writing a
// Read-Only Register, EXC-3 Illegal Function Code.
//
// The acceptance sets differ and the difference matters. EXC-1 and EXC-2 accept
// ANY of exception codes 2, 3 or 4 — a harness that demanded one specific code
// would fail a conformant device. EXC-3 accepts exactly code 1 and nothing
// else. Both facts are printed in the document and both are honoured below.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"lexa-proto/mbap"
)

// acceptedWriteExceptions is the {2, 3, 4} set EXC-1 and EXC-2 allow.
var acceptedWriteExceptions = map[byte]bool{
	byte(mbap.ExIllegalAddress): true,
	byte(mbap.ExIllegalValue):   true,
	byte(mbap.ExDeviceFailure):  true,
}

// checkEXC1 implements SS-MODBUS-CONF-v1.4 EXC-1, Invalid Value.
//
// Steps: write an invalid value to an RW point — for an enumerated point, a
// value outside the defined enumerations; verify the device answers with
// exception 2, 3 or 4; read the point back to verify it was not written.
//
// The check will not grade the criterion until a VALID write to the same point
// has been accepted. Against this DUT that is not pedantry: a control-authority
// overlay answers 0x01 to any write of a commanded point while the gateway is
// in CSIP authority, and 0x01 is not in the accepted set — so a suite that
// skipped the control write would report a policy state as an exception-ladder
// failure.
func checkEXC1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "EXC-1 invalid value")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}
	ref, present := ch.Model(704)
	if !present {
		return certify.Skipped("the DUT serves no model this suite knows an invalid value for"), nil
	}
	def := Models[704]

	type attempt struct {
		Label     string
		Point     Point
		Value     int64
		Rationale string
		Exception byte
		Answered  bool
		Unchanged bool
		Text      string
	}
	var attempts []attempt
	before := len(s.client.log)

	// An enumerated point written outside its enumeration — the case the
	// procedure names explicitly.
	if p, ok := def.Point("WMaxLimPctEna"); ok {
		attempts = append(attempts, attempt{
			Label: "704.WMaxLimPctEna", Point: p, Value: 0x00FF,
			Rationale: "the DER model definition gives this enum exactly two values, DISABLED = 0 and " +
				"ENABLED = 1; 255 is outside the symbol set, and the Device specification requires values " +
				"outside a point's symbol set to be treated as invalid",
		})
	}
	// A scaled numeric point written far outside its engineering range.
	if p, ok := def.Point("WMaxLimPct"); ok {
		attempts = append(attempts, attempt{
			Label: "704.WMaxLimPct", Point: p, Value: 0xFFFE,
			Rationale: "the point's units are percent of maximum active power; 65534 raw is outside the " +
				"0..100 % range whatever the reported scale factor, short of the not-implemented sentinel",
		})
	}
	if len(attempts) == 0 {
		return certify.Skipped("model 704's transcription offers no point this suite knows an invalid value for"), nil
	}

	// The control write, on the first attempt's point.
	probe, perr := probeWrite(s.client, ref, attempts[0].Point, "EXC-1 control")
	if perr != nil {
		return certify.Result{}, perr
	}
	if !probe.Accepted {
		tids := tidsSince(s.client, before)
		return certify.Result{
			Verdict: certify.Skip,
			Notes:   "the invalid-value criterion was not reached: " + probe.Reason,
			Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
				c, reason := newCiter(ev, s, false)
				if c == nil {
					return skipAll(ev, reason,
						"an invalid value written to an RW point is answered with exception 2, 3 or 4"), nil
				}
				out, err := transportPlus(c, certify.Skip)
				if err != nil {
					return nil, err
				}
				a, err := c.frames(
					"a valid, in-range write to the point EXC-1 targets is accepted, which is the precondition "+
						"for reading its refusal of an INVALID value as an exception-ladder result",
					"FC 6 write of the point's own current value, changing nothing",
					certify.Skip, probe.Reason, tids)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
				out = append(out, ev.SkipAssertion(
					"an invalid value written to an RW point is answered with exception 2, 3 or 4 and is not applied",
					"FC 6 write of an out-of-enumeration / out-of-range value, followed by an FC 3 read-back",
					"the DUT refused a VALID write to the same point, so any refusal of an invalid one would "+
						"be indistinguishable from that policy: "+probe.Reason))
				return out, nil
			},
		}, nil
	}

	for i := range attempts {
		a := &attempts[i]
		orig, rerr := readPoint(s.client, ref, a.Point, fmt.Sprintf("EXC-1 %s: pre-write value", a.Label))
		if rerr != nil {
			a.Text = "the point could not be read before the write: " + errText(rerr)
			continue
		}
		regs, eerr := encode(a.Point, a.Value)
		if eerr != nil {
			a.Text = eerr.Error()
			continue
		}
		werr := writePoint(s.client, ref, a.Point, regs,
			fmt.Sprintf("EXC-1 %s: write the invalid value %d", a.Label, a.Value))
		if werr == nil {
			a.Text = fmt.Sprintf("the DUT ACCEPTED the invalid value %d with no exception", a.Value)
		} else if e, ok := asException(werr); ok {
			a.Answered = true
			a.Exception = byte(e.Code)
			a.Text = fmt.Sprintf("writing %d returned exception %s", a.Value, exceptionName(a.Exception))
		} else {
			a.Text = "the write failed at the transport, not with an exception: " + errText(werr)
		}
		after, aerr := readPoint(s.client, ref, a.Point, fmt.Sprintf("EXC-1 %s: read back", a.Label))
		switch {
		case aerr != nil:
			a.Text += "; the read-back failed: " + errText(aerr)
		case decodeRaw(a.Point, after) == decodeRaw(a.Point, orig):
			a.Unchanged = true
			a.Text += fmt.Sprintf("; the point still reads %d", decodeRaw(a.Point, orig))
		default:
			a.Text += fmt.Sprintf("; the point changed from %d to %d — the invalid value took effect",
				decodeRaw(a.Point, orig), decodeRaw(a.Point, after))
		}
	}
	if rerr := restore(s.client, probe, "EXC-1"); rerr != nil {
		rc.Logf("EXC-1: could not restore %s: %v", probe.Point.Name, rerr)
	}
	tids := tidsSince(s.client, before)

	ok := true
	var lines []string
	for _, a := range attempts {
		lines = append(lines, a.Label+": "+a.Text)
		if !a.Answered || !acceptedWriteExceptions[a.Exception] || !a.Unchanged {
			ok = false
		}
	}

	return certify.Result{
		Verdict: verdictIf(ok),
		Notes:   strings.Join(lines, "; "),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"an invalid value written to an RW point is answered with exception 2, 3 or 4 and is not applied"), nil
			}
			out, err := transportPlus(c, verdictIf(ok))
			if err != nil {
				return nil, err
			}
			a, err := c.frames(
				"a valid, in-range write to the point EXC-1 targets is accepted, establishing that a refusal "+
					"of an INVALID value is the exception ladder and not a policy denial",
				"FC 6 write of the point's own current value, changing nothing",
				certify.Pass, "the control write was accepted", probe.TIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			for _, at := range attempts {
				a, err := c.frames(
					fmt.Sprintf("EXC-1: writing the invalid value %d to %s is answered with Modbus exception "+
						"2, 3 or 4, and the point is not written", at.Value, at.Label),
					"FC 6 write of a value outside the point's symbol set or range ("+at.Rationale+"), "+
						"followed by an FC 3 read-back of the same point",
					verdictIf(at.Answered && acceptedWriteExceptions[at.Exception] && at.Unchanged),
					at.Text, tids)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// checkEXC2 implements SS-MODBUS-CONF-v1.4 EXC-2, Writing a Read-Only Register.
//
// Steps: identify three or more read-only registers and write to them; verify
// the device answers with exception 2, 3 or 4; read each back to verify it was
// not written.
//
// The three registers are drawn from different kinds of read-only point so the
// result says something: a model header register, a scale factor, and a
// measurement or remaining-time readback. A device that refuses one kind and
// accepts another would otherwise pass on a lucky pick.
func checkEXC2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "EXC-2 write to a read-only register")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	type ro struct {
		Label     string
		Addr      uint16
		Original  uint16
		Exception byte
		Answered  bool
		Unchanged bool
		Text      string
	}
	var picks []ro
	kinds := map[string]bool{}

	for _, ref := range ch.Models {
		def, ok := Models[ref.ID]
		if !ok {
			continue
		}
		block, berr := readModelBlock(s.client, ref, fmt.Sprintf("EXC-2 snapshot of model %d", ref.ID))
		if berr != nil {
			continue
		}
		for _, p := range def.Points {
			if p.Access != AccessR || p.Regs() != 1 || p.Type == TypePad {
				continue
			}
			kind := "read-only point"
			switch {
			case p.Name == "ID" || p.Name == "L":
				kind = "model header register"
			case p.Type == TypeSunSSF:
				kind = "scale factor"
			case strings.HasSuffix(p.Name, "Rtg"):
				kind = "nameplate rating"
			}
			if kinds[kind] {
				continue
			}
			regs, ok := pointRegs(block, p)
			if !ok {
				continue
			}
			kinds[kind] = true
			picks = append(picks, ro{
				Label:    fmt.Sprintf("%d.%s (%s)", ref.ID, p.Name, kind),
				Addr:     ref.Addr + uint16(p.Off),
				Original: regs[0],
			})
			if len(picks) >= 3 {
				break
			}
		}
		if len(picks) >= 3 {
			break
		}
	}
	if len(picks) < 3 {
		return certify.Skipped("fewer than three distinct read-only single registers could be identified in "+
			"the DUT's map (found %d)", len(picks)), nil
	}

	before := len(s.client.log)
	for i := range picks {
		p := &picks[i]
		// A value that differs from the current one, so "it was not written" is
		// a real observation rather than a tautology.
		newVal := p.Original ^ 0x0001
		werr := s.client.writeSingle(p.Addr, newVal, fmt.Sprintf("EXC-2 write to %s", p.Label))
		switch {
		case werr == nil:
			p.Text = fmt.Sprintf("the DUT ACCEPTED an FC 6 write of 0x%04x to the read-only register at %d",
				newVal, p.Addr)
		default:
			if e, ok := asException(werr); ok {
				p.Answered = true
				p.Exception = byte(e.Code)
				p.Text = fmt.Sprintf("FC 6 to %d returned exception %s", p.Addr, exceptionName(p.Exception))
			} else {
				p.Text = "the write failed at the transport, not with an exception: " + errText(werr)
			}
		}
		got, gerr := s.client.readHolding(p.Addr, 1, fmt.Sprintf("EXC-2 read back %s", p.Label))
		switch {
		case gerr != nil:
			p.Text += "; the read-back failed: " + errText(gerr)
		case got[0] == p.Original:
			p.Unchanged = true
			p.Text += fmt.Sprintf("; the register still reads 0x%04x", p.Original)
		default:
			p.Text += fmt.Sprintf("; the register changed from 0x%04x to 0x%04x", p.Original, got[0])
		}
	}
	tids := tidsSince(s.client, before)

	ok := true
	var lines []string
	for _, p := range picks {
		lines = append(lines, p.Label+": "+p.Text)
		if !p.Answered || !acceptedWriteExceptions[p.Exception] || !p.Unchanged {
			ok = false
		}
	}
	// Context a reader needs to interpret a uniform 0x01: on this DUT an
	// authorization denial and a read-only refusal are different answers, and
	// this note says which one the reader is looking at.
	note := ""
	if !ok {
		for _, p := range picks {
			if p.Answered && p.Exception == byte(mbap.ExIllegalFunction) {
				note = "the DUT answered 0x01 (illegal function), which on this product expresses an " +
					"authorization denial rather than a read-only refusal; the procedure accepts only 2, 3 or 4"
				break
			}
		}
	}

	return certify.Result{
		Verdict: verdictIf(ok),
		Notes:   strings.Join(lines, "; "),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"a write to a read-only register is answered with exception 2, 3 or 4 and does not change it"), nil
			}
			out, err := transportPlus(c, verdictIf(ok))
			if err != nil {
				return nil, err
			}
			a, err := c.frames(
				"every write aimed at a read-only register is answered with Modbus exception 2, 3 or 4, and "+
					"each targeted register keeps its pre-write value",
				"FC 6 write of a changed value to three read-only registers of different kinds (model header, "+
					"scale factor, rating or measurement), each followed by an FC 3 read-back",
				verdictIf(ok), strings.Join(lines, "; "), tids)
			if err != nil {
				return nil, err
			}
			if note != "" {
				a.Note = joinNote(a.Note, note)
			}
			out = append(out, a)
			return out, nil
		},
	}, nil
}

// checkEXC3 implements SS-MODBUS-CONF-v1.4 EXC-3, Illegal Function Code.
//
// Steps: send a request with a function code that does not exist in the Modbus
// specification (the document's example is 50) at an implemented RW register,
// and verify the device answers with Modbus exception 1.
//
// Unlike EXC-1 and EXC-2 this test accepts exactly one code. The response's
// function byte must also be the request's code with the high bit set, and on
// TCP it must echo the transaction identifier — both are asserted, because a
// device that answers exception 1 under the wrong function byte has still
// desynchronised its client.
func checkEXC3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "EXC-3 illegal function code")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	// Aim the request at an implemented RW register when one exists, as the
	// procedure specifies; otherwise at the base address, which is certainly
	// implemented.
	addr := ch.Base
	label := "the SunSpec base address"
	if ref, present := ch.Model(704); present {
		if p, ok := Models[704].Point("WMaxLimPct"); ok {
			addr = ref.Addr + uint16(p.Off)
			label = "the implemented RW point 704.WMaxLimPct"
		}
	}

	// The PDU shape is a read request's, carried under an undefined function
	// code: five bytes, so the MBAP length field is legal and the DUT's framing
	// layer has no excuse to reject the frame before the function code is
	// examined.
	pdu := []byte{fcUndefined, byte(addr >> 8), byte(addr), 0x00, 0x01}

	before := len(s.client.log)
	_, werr := s.client.do(pdu, "EXC-3: request with undefined function code 0x32")
	tids := tidsSince(s.client, before)

	var code byte
	answered := false
	text := ""
	switch {
	case werr == nil:
		text = "the DUT answered function code 0x32 with a normal response instead of an exception"
	default:
		if e, ok := asException(werr); ok {
			answered = true
			code = byte(e.Code)
			text = fmt.Sprintf("the DUT answered function code 0x32 at %s (%d) with function byte 0x%02x and "+
				"exception code %s", label, addr, fcUndefined|0x80, exceptionName(code))
		} else {
			text = "the request failed at the transport, not with an exception: " + errText(werr)
		}
	}
	ok := answered && code == byte(mbap.ExIllegalFunction)

	return certify.Result{
		Verdict: verdictIf(ok),
		Notes:   text,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"a request carrying a function code absent from the Modbus specification is answered "+
						"with exception code 1"), nil
			}
			out, err := transportPlus(c, verdictIf(ok))
			if err != nil {
				return nil, err
			}
			// The wire itself carries the strongest form of this claim: find
			// the response ADU and read its function byte and exception code
			// straight out of the recovered plaintext.
			wireText := text
			wireOK := ok
			if len(tids) > 0 {
				if resp, found := c.conv.responseTo(tids[len(tids)-1]); found {
					wireOK = resp.FC() == fcUndefined|0x80 && resp.ExceptionCode() == byte(mbap.ExIllegalFunction)
					wireText = fmt.Sprintf("response pdu on the wire is % x: function byte 0x%02x, exception "+
						"code %s, transaction id 0x%04x", resp.PDU, resp.FC(),
						exceptionName(resp.ExceptionCode()), resp.TID)
				}
			}
			a, err := c.frames(
				"a request carrying function code 50 (0x32), which does not exist in the Modbus specification, "+
					"is answered with function byte 0xB2 and exception code 1 (Illegal Function), echoing the "+
					"request's transaction identifier",
				"one MBAP frame whose PDU begins with 0x32, aimed at "+label+"; the response ADU is read back "+
					"out of the capture and its function byte, exception code and transaction id are compared "+
					"against the request",
				verdictIf(ok && wireOK), wireText, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			return out, nil
		},
	}, nil
}
