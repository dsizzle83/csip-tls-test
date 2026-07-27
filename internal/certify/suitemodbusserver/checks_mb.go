package suitemodbusserver

// checks_mb.go implements the two General Modbus Tests of SunSpec Modbus
// Conformance Test Procedures v1.4 §2.7.9 and §2.7.10: MB-1 Modbus
// Single/Multiple Register Write and MB-2 Modbus Single Register Read.
//
// These two sit under the Modbus Protocol Tests heading, after both the RTU and
// the TCP subsections, which is the document's way of saying they apply to
// whatever interface the device has. That is what makes them runnable here at
// all: unlike TCP-1 and the RTU rows, they name no transport.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// checkMB2 implements SS-MODBUS-CONF-v1.4 MB-2, Modbus Single Register Read.
//
// Steps: select a register in the map, read it with FC 3 and register count 1,
// verify it read correctly, and repeat for two more registers.
//
// "Read correctly" needs something to be correct against. This check reads each
// model's whole block first and then re-reads three individual registers out of
// it, so the single-register result has an independently obtained value to
// agree with — which is a real criterion, rather than "a response arrived".
//
// The document prints an explicit carve-out worth honouring: "Some devices may
// reject a read of a register if it's a part of a value longer than 16 bits …
// This is not considered non-compliant." So the three registers are chosen from
// 16-bit points, and a fourth read — deliberately aimed at the low half of a
// 32-bit point — is recorded as an observation of that carve-out rather than
// graded.
func checkMB2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "MB-2 single register read")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	type single struct {
		Label string
		Addr  uint16
		Want  uint16
		Got   uint16
		Err   error
	}
	var picks []single
	var partial *single

	for _, ref := range ch.Models {
		def, ok := Models[ref.ID]
		if !ok {
			continue
		}
		block, berr := readModelBlock(s.client, ref, fmt.Sprintf("MB-2 reference read of model %d", ref.ID))
		if berr != nil {
			continue
		}
		for _, p := range def.Points {
			if p.Regs() != 1 || p.Type == TypePad {
				continue
			}
			regs, ok := pointRegs(block, p)
			if !ok {
				continue
			}
			if len(picks) < 3 {
				picks = append(picks, single{
					Label: fmt.Sprintf("%d.%s", ref.ID, p.Name),
					Addr:  ref.Addr + uint16(p.Off),
					Want:  regs[0],
				})
			}
		}
		if partial == nil {
			for _, p := range def.Points {
				if p.Regs() != 2 {
					continue
				}
				regs, ok := pointRegs(block, p)
				if !ok {
					continue
				}
				partial = &single{
					Label: fmt.Sprintf("%d.%s (second half of a 32-bit point)", ref.ID, p.Name),
					Addr:  ref.Addr + uint16(p.Off) + 1,
					Want:  regs[1],
				}
				break
			}
		}
		if len(picks) >= 3 && partial != nil {
			break
		}
	}

	if len(picks) < 3 {
		return certify.Skipped("the DUT's map does not offer three distinct 16-bit registers this suite can "+
			"identify (found %d)", len(picks)), nil
	}

	before := len(s.client.log)
	var bad []string
	for i := range picks {
		regs, rerr := s.client.readHolding(picks[i].Addr, 1,
			fmt.Sprintf("MB-2 single register read of %s", picks[i].Label))
		picks[i].Err = rerr
		if rerr != nil {
			bad = append(bad, fmt.Sprintf("%s at %d: %s", picks[i].Label, picks[i].Addr, errText(rerr)))
			continue
		}
		picks[i].Got = regs[0]
		if regs[0] != picks[i].Want {
			bad = append(bad, fmt.Sprintf("%s at %d: single-register read returned 0x%04x, the block read "+
				"returned 0x%04x", picks[i].Label, picks[i].Addr, regs[0], picks[i].Want))
		}
	}
	singleTIDs := tidsSince(s.client, before)

	var partialText string
	var partialTIDs []uint16
	if partial != nil {
		before = len(s.client.log)
		regs, rerr := s.client.readHolding(partial.Addr, 1,
			fmt.Sprintf("MB-2 partial-value read of %s", partial.Label))
		partialTIDs = tidsSince(s.client, before)
		switch {
		case rerr != nil:
			partialText = fmt.Sprintf("reading %s at %d returned %s — the v1.4 carve-out permits this",
				partial.Label, partial.Addr, errText(rerr))
		case regs[0] != partial.Want:
			partialText = fmt.Sprintf("reading %s at %d returned 0x%04x but the block read returned 0x%04x",
				partial.Label, partial.Addr, regs[0], partial.Want)
		default:
			partialText = fmt.Sprintf("reading %s at %d returned 0x%04x, matching the block read — the DUT "+
				"allows a partial-value read", partial.Label, partial.Addr, regs[0])
		}
	}

	verdict := verdictIf(len(bad) == 0)
	notes := fmt.Sprintf("three single-register reads: %s, %s, %s",
		picks[0].Label, picks[1].Label, picks[2].Label)
	if len(bad) > 0 {
		notes = strings.Join(bad, "; ")
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"three distinct registers each read correctly with FC 3 and register count 1"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			var lines []string
			for _, p := range picks {
				if p.Err != nil {
					lines = append(lines, fmt.Sprintf("%s@%d: %s", p.Label, p.Addr, errText(p.Err)))
					continue
				}
				lines = append(lines, fmt.Sprintf("%s@%d: 0x%04x (block read: 0x%04x)", p.Label, p.Addr, p.Got, p.Want))
			}
			a, err := c.frames(
				"three distinct registers are each read correctly by an FC 3 request with quantity 1",
				"FC 3 with the quantity field set to 0x0001 at three 16-bit point addresses, each result "+
					"compared against the value the same register returned inside a whole-model read",
				verdict, strings.Join(lines, "; "), singleTIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			if partialText == "" {
				out = append(out, ev.SkipAssertion(
					"the DUT's handling of a single-register read inside a wider point is recorded",
					"FC 3 with quantity 1 at the second register of a 32-bit point",
					"the DUT's map offers no 32-bit point this suite could aim such a read at"))
			} else {
				a, err = c.frames(
					"the DUT's handling of a single-register read aimed inside a value longer than 16 bits is "+
						"recorded; both answering and rejecting are compliant under the v1.4 carve-out",
					"FC 3 with quantity 1 at the second register of a 32-bit point",
					certify.Pass, partialText, partialTIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// checkMB1 implements SS-MODBUS-CONF-v1.4 MB-1, Modbus Single/Multiple Register
// Write.
//
// Steps: select two consecutive RW points; write both with one FC 16 request
// and verify; then write each with FC 6, one at a time, and verify.
//
// The pair used is model 704's WMaxLimPctEna and WMaxLimPct, which are adjacent
// single-register RW points — the exact shape step 4 assumes when it says the
// FC 6 writes go "on the two points one by one" (a 32-bit point cannot be
// written with FC 6 at all).
func checkMB1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "MB-1 single/multiple register write")
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
		return certify.Skipped("the DUT serves no model 704, and this suite identifies no other pair of " +
			"consecutive single-register RW points it is prepared to write"), nil
	}
	def := Models[704]
	ena, okE := def.Point("WMaxLimPctEna")
	pct, okP := def.Point("WMaxLimPct")
	if !okE || !okP || pct.Off != ena.Off+1 {
		return certify.Skipped("model 704's transcription does not place two consecutive single-register RW " +
			"points where MB-1 needs them"), nil
	}
	addr := ref.Addr + uint16(ena.Off)

	before := len(s.client.log)
	orig, rerr := s.client.readHolding(addr, 2, "MB-1: read the two adjustable points")
	if rerr != nil {
		return certify.Result{}, fmt.Errorf("read the MB-1 point pair at %d: %w", addr, rerr)
	}

	// New values that differ from the current ones so success is observable,
	// per the procedure's precondition. The percentage moves by one unit inside
	// its range; the enable is left alone unless enumeration writes are
	// permitted, because toggling an enable is a real control action.
	noEnum := paramBool(rc, paramNoEnumWrite)
	newEna := orig[0]
	if !noEnum {
		if orig[0] == 0 {
			newEna = 1
		} else {
			newEna = 0
		}
	}
	newPct := orig[1] + 1
	if newPct == orig[1] || newPct == 0xFFFF {
		newPct = orig[1] - 1
	}

	fc16OK, fc6OK := false, false
	fc16Text, fc6Text := "", ""
	exercised := false

	werr := s.client.writeMultiple(addr, []uint16{newEna, newPct}, "MB-1 step 2: FC 16 over both points")
	switch {
	case werr != nil:
		fc16Text = denialReason(werr)
		if fc16Text == "" {
			fc16Text = errText(werr)
		}
		fc6Text = "not attempted: the FC 16 write was refused, so the pair's writability is not established"
	default:
		exercised = true
		back, berr := s.client.readHolding(addr, 2, "MB-1 step 3: read back after FC 16")
		switch {
		case berr != nil:
			fc16Text = "read-back after the FC 16 write: " + errText(berr)
		case back[0] != newEna || back[1] != newPct:
			fc16Text = fmt.Sprintf("FC 16 wrote [0x%04x 0x%04x]; the read-back returned [0x%04x 0x%04x]",
				newEna, newPct, back[0], back[1])
		default:
			fc16OK = true
			fc16Text = fmt.Sprintf("one FC 16 request wrote [0x%04x 0x%04x] to registers %d..%d and the "+
				"read-back returned both", newEna, newPct, addr, addr+1)
		}

		// Step 4/5 — FC 6 on the two points one by one.
		var bad []string
		for i, v := range []uint16{orig[0], orig[1]} {
			a := addr + uint16(i)
			if err := s.client.writeSingle(a, v, fmt.Sprintf("MB-1 step 4: FC 6 to register %d", a)); err != nil {
				bad = append(bad, fmt.Sprintf("register %d: %s", a, errText(err)))
				continue
			}
			got, gerr := s.client.readHolding(a, 1, fmt.Sprintf("MB-1 step 5: read back register %d", a))
			if gerr != nil {
				bad = append(bad, fmt.Sprintf("register %d read-back: %s", a, errText(gerr)))
				continue
			}
			if got[0] != v {
				bad = append(bad, fmt.Sprintf("register %d: wrote 0x%04x, read back 0x%04x", a, v, got[0]))
			}
		}
		fc6OK = len(bad) == 0
		if fc6OK {
			fc6Text = fmt.Sprintf("two FC 6 requests restored [0x%04x 0x%04x] to registers %d..%d, each echoed "+
				"and each read back", orig[0], orig[1], addr, addr+1)
		} else {
			fc6Text = strings.Join(bad, "; ")
		}
	}
	tids := tidsSince(s.client, before)

	verdict := certify.Skip
	notes := fc16Text
	if exercised {
		verdict = verdictIf(fc16OK && fc6OK)
		notes = fc16Text + "; " + fc6Text
	}
	if noEnum {
		notes += "; the enable was written with its current value because -param " + paramNoEnumWrite +
			" is set, so only one of the two points changed value"
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"an FC 16 request writes two consecutive RW points and both read back",
					"an FC 6 request writes each of the two points individually and both read back"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			claim16 := "a Function Code 16 request covering two consecutive read-write points is accepted and " +
				"both points read back the values it wrote"
			method16 := "one FC 16 write of two registers at the model 704 WMaxLimPctEna / WMaxLimPct pair, " +
				"followed by an FC 3 read of the same two registers"
			claim6 := "two Function Code 6 requests, one per point, are each accepted and each point reads back " +
				"the value it was written"
			method6 := "two FC 6 writes, each to one register, each response checked for the address-and-value " +
				"echo, each followed by an FC 3 read of that register"
			if !exercised {
				out = append(out, ev.SkipAssertion(claim16, method16, fc16Text))
				out = append(out, ev.SkipAssertion(claim6, method6, fc6Text))
				return out, nil
			}
			a, err := c.frames(claim16, method16, verdictIf(fc16OK), fc16Text, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			a, err = c.frames(claim6, method6, verdictIf(fc6OK), fc6Text, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			return out, nil
		},
	}, nil
}
