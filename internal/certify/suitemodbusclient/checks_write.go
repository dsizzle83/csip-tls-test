package suitemodbusclient

// checks_write.go implements §2.6, the Write Tests: WR-1 (FC 0x06) and WR-2
// (FC 0x10).
//
// # WR-1's subject is a claim the CANDIDATE makes, not a fact this suite hides
//
// §2.6.1's purpose is verbatim:
//
//	"Validates that all implemented adjustable points in the model can be
//	 written individually using Modbus Function Code 0x06."
//
// The DUT has no FC 0x06 path at all. Every register write it can emit goes
// through sunspec.Reader.WriteModel → the transport's WriteHolding → the
// vendored client's writeRegisters, which hardcodes
// `functionCode: fcWriteMultipleRegisters` (client.go:1162-1164) — so even a
// single-register write leaves as FC 0x10 with quantity 1. There is no branch,
// no configuration and no code path that produces an FC 0x06 request.
// PICS_SUNSPEC_MODBUS.md §4.2 (rev g) records the same fact as the candidate's
// own declaration: "WR-2 (Write Multiple Points) — CLAIMED. WR-1 (Write
// Single Point) — NOT CLAIMED."
//
// The row's subject — "all implemented adjustable points … using Modbus
// function code 0x06" — is therefore the empty set on THIS CANDIDATE, and
// that is exactly the shape CAMPAIGNS.md §5's row-level Requires exists for:
// the catalog's WR-1 entry states `requires: {modbus_client.write_function_
// codes: [6]}`, and scope.go's RequirementScope excludes the row, Plan()-time,
// WITH SOURCE manifest, whenever the running candidate's own manifest
// contradicts that — which the RC0 candidate's does (write_function_codes =
// [16] only). That is a fact about the candidate, not about this suite, so it
// is decided centrally rather than by this check declaring its own row out of
// scope (see registry.go's Check doc for why a check must not do that).
//
// This check therefore only RUNS at all for a candidate whose manifest either
// says nothing about the axis, or specifically claims FC 6 — and for either of
// those it still needs to say something honest, because "excluded" is not the
// only reading available: §2.6.1 carries no explicit "if the CUT supports FC
// 0x06" clause the way its own step 3 does for RTU, so a lab could read it as
// unconditional. wr1NotApplicable below states that judgement in full,
// INCLUDING the reading that argues against it, because a certifying lab may
// weigh it differently, and cites the DUT's own frames (there are none at FC
// 0x06) as the wire-level confirmation. What this suite will not do, either
// way, is add an FC 0x06 write path to the product to make a row green: a
// conformance tool that changes the device to suit the test has stopped
// measuring anything.
//
// # WR-2's difficulty, and what fixed it
//
// §2.6 is written for an operator console: the test engineer hands the CUT five
// values per adjustable point and watches it write each one. The DUT is not an
// operator console. It is an autonomous gateway whose southbound writes are a
// CONSEQUENCE — its reconcilers emit a register write only when a northbound
// command gives them something to enforce — and there is no interface, on the
// device or off it, that says "write 0x1234 to register 40230".
//
// A write therefore has to be provoked, and the only provocation available is
// DIVERGENCE: move the control register out from under the DUT and see whether
// an active reconciler puts it back. That failed for a specific and now-fixed
// reason. The lever was `POST /inject {"WMaxLimPct_pct": N}`, which writes the
// LEGACY model 123 ceiling — and on an advanced sim the model 123 ceiling is a
// MIRROR the sim re-derives from model 704 on its next animation tick, while
// the DUT reads and writes 704. The provocation was being restored under itself
// before the DUT ever saw it, and both write rows SKIPped for want of a write
// in every campaign to date.
//
// The fix is not a bigger hammer. It is to stop guessing which register the
// product owns and to LEARN it from the product: the simulator's transaction
// ledger records the DUT's own FC 0x10 write, address and values and all, so
// this row diverges exactly the cell the DUT just wrote. No model definition
// directory is consulted on either side — the same independence ERR-3 rests on
// — and the divergence cannot land on a mirror, because the DUT does not write
// mirrors.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

const paramDERControl = "modbus-client.dercontrol"

// derControlWatts is the generation limit posted when the northbound lever is
// enabled. It is a limit, not a curtailment to zero: the point is to give the
// reconciler something to write, not to swing the bench's power flow.
const derControlWatts = 4000

// derControlSeconds bounds the posted control so it expires on its own even if
// this check is killed mid-run. It outlasts the barrier budget the row can
// spend waiting for a write, so the standing setpoint is still standing when
// the divergence is applied.
const derControlSeconds = 300

// divergeDelta is how far the poked register is moved from the value the DUT
// last wrote. It is a RAW register delta, not a scaled quantity: this row does
// not decode the point (it holds no model directory), it simply moves the word
// far enough that any reconciler comparing its commanded value against the
// read-back sees a difference.
const divergeDelta = -500

// ── WR-1 — Write Single Point (FC 0x06) ───────────────────────────────────────

func checkWR1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	// Registered rather than omitted, for the reason register.go states: an
	// unregistered uid is indistinguishable from an oversight, while a
	// registered row carrying its reasoning is a judgement a reviewer can
	// weigh and disagree with.
	return certify.Result{
		Verdict: certify.Skip,
		Notes: "NOT APPLICABLE to this client. §2.6.1's subject is 'all implemented adjustable points " +
			"in the model … using Modbus Function Code 0x06', and this client implements no FC 0x06 " +
			"write path: every register write it can emit is FC 0x10, hardcoded in the Modbus client it " +
			"is built on, so the row's subject is the empty set. The sibling row WR-2 exercises the " +
			"same adjustable points through the function code this client does use. The full reasoning, " +
			"including the reading that would make this a product gap instead, is in the assertion.",
		OffWire: true,
		OffWireReason: "the row's observables are FC 0x06 requests, and this client emits none — not " +
			"because the bench failed to provoke one, but because no code path in it produces that " +
			"function code. The row is recorded as addressed and not executed, not as passed.",
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, _, _ := citeConversation(ev, o, "the DUT wrote an adjustable point using FC 0x06")
			return emit(ev, c, []finding{wr1NotApplicable(c)}), nil
		},
	}, nil
}

// wr1NotApplicable states the judgement, the evidence for it, and the argument
// against it.
//
// It is one assertion rather than four SKIPs because the row does not have four
// separate gaps: it has one fact about the client, from which everything else
// follows.
func wr1NotApplicable(c *Conversation) finding {
	claim := "§2.6.1 applies to this client"
	method := "the client's own write path, and the function codes it was observed to emit"

	observed := "no write of any kind was attributed to this test case"
	if c != nil {
		fc06, fc10 := 0, 0
		for _, ex := range c.Writes() {
			switch ex.Request.FC {
			case FCWriteSingleRegister:
				fc06++
			case FCWriteMultipleRegisters:
				fc10++
			}
		}
		if fc06+fc10 > 0 {
			observed = fmt.Sprintf("this test case's frames carry %d FC 0x06 write(s) and %d FC 0x10 "+
				"write(s)", fc06, fc10)
		}
	}

	return skipf(claim, method,
		"NOT APPLICABLE, on the client's own construction. §2.6.1 reads: \"Validates that all "+
			"implemented adjustable points in the model can be written individually using Modbus "+
			"Function Code 0x06\", and its step 1: \"Verify all implemented adjustable points can be "+
			"written to the minimum value, maximum value, and three intermediate values as defined in "+
			"the Server 1 PICS using Modbus function code 0x06.\" This client has no FC 0x06 write "+
			"path: every register write it can emit reaches the wire through one function, which "+
			"hardcodes FC 0x10 (the vendored Modbus client's writeRegisters, "+
			"functionCode: fcWriteMultipleRegisters), so even a single-register write leaves as FC 0x10 "+
			"with quantity 1. There is no branch, no setting and no code path that produces FC 0x06. "+
			"The set of \"implemented adjustable points … using Modbus function code 0x06\" is "+
			"therefore empty, and a sweep over an empty set is vacuous rather than failed. %s. "+
			"THE READING THAT WOULD MAKE THIS A PRODUCT GAP, stated so a reviewer can take it: §2.6.1 "+
			"carries no explicit \"if the CUT supports FC 0x06\" clause, where its own step 3 does "+
			"carry one for RTU (\"If the CUT supports RTU server interfaces as indicated in the "+
			"PICS\"). A lab reading §2.6.1 as unconditional would call this a product gap closable only "+
			"by adding an FC 0x06 write path to the client — which this suite will not do to make a row "+
			"green. The counter-argument, and the one recorded here: §2.6.2 is explicit that FC 0x10 is "+
			"a complete per-point alternative (\"This test does not require that multiple points are "+
			"written at once, just that the 0x10 function code can be used to write each of the "+
			"points\"), so WR-2 already covers every adjustable point this client can write, by the "+
			"function code it uses. Resolving the ambiguity is a PICS question for the certifying lab, "+
			"not a bench capability", observed)
}

// ── WR-2 — Write Multiple Points (FC 0x10) ────────────────────────────────────

// writeRun is what one learn-diverge-reassert-readback attempt produced.
type writeRun struct {
	// Northbound records the command posted to give the reconciler something
	// to enforce, and why it was or was not.
	Northbound string
	NorthErr   error
	NorthOn    bool

	// First is the DUT's own write, from which this row LEARNS the register
	// the product owns.
	First     LedgerEntry
	HaveFirst bool
	FirstPage LedgerPage

	// DivergeAddr is the register moved out from under the DUT, DivergeEpoch
	// the fence it moved at, and DivergeErr why it could not be.
	DivergeAddr  uint16
	DivergeEpoch uint64
	DivergeErr   error

	// Reassert is the write the DUT issued in response, and ReadBack the DUT's
	// own later read of the block showing the value took.
	Reassert     LedgerEntry
	HaveReassert bool
	ReassertPage LedgerPage
	ReadBack     LedgerEntry
	HaveReadBack bool
}

func checkWR2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	if r := o.injectionReason(); r != "" {
		return certify.Skipped("this procedure requires the DUT to be made to write, and %s", r), nil
	}
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	run := &writeRun{}
	if v, ok := rc.Param(paramDERControl); ok && strings.EqualFold(strings.TrimSpace(v), "on") {
		run.NorthOn = true
	}

	// STEP 1 — give the reconciler something to enforce, so it has a standing
	// setpoint to re-assert. This is the only lever that reaches outside this
	// suite's own surface, so it is opt-in.
	fence := d.baselineEpoch
	if run.NorthOn && rc.GridSim != nil && rc.GridSim.Available() {
		ctrl := map[string]any{
			"program":    0,
			"gen_lim_W":  derControlWatts,
			"duration_s": derControlSeconds,
			"activate":   true,
		}
		if err := rc.GridSim.Control(ctx, ctrl, nil); err != nil {
			run.NorthErr = err
		} else {
			run.Northbound = fmt.Sprintf("POST %s/admin/control %s — a %d W generation limit lasting "+
				"%d s, posted so the DUT's CSIP client adopts it and its reconciler writes the "+
				"corresponding SunSpec control register southbound. It expires on its own",
				rc.GridSim.BaseURL, jsonish(ctrl), derControlWatts, derControlSeconds)
			o.injected = append(o.injected, run.Northbound)
		}
	}

	// STEP 2 — LEARN the register the product owns, from the product. The
	// ledger records the DUT's own FC 0x10 write, address and values and all;
	// nothing here guesses which model or which offset that is.
	page, saw, err := d.awaitMatch(ctx, fence, "issue a register write",
		func(p LedgerPage) bool { return len(p.Writes()) > 0 })
	if err != nil {
		return certify.Result{}, err
	}
	run.FirstPage = page
	if saw {
		run.First, run.HaveFirst = page.Writes()[0], true
	}

	// STEP 3 — diverge exactly that register, and watch the reconciler put it
	// back.
	if run.HaveFirst {
		run.DivergeAddr = run.First.Addr
		epoch, ierr := d.inject(ctx, map[string]any{
			"registers": []map[string]any{{"addr": int(run.DivergeAddr), "delta": divergeDelta}},
		}, fmt.Sprintf("move register %d — the exact cell the DUT itself wrote at ledger seq %d — by %d "+
			"raw units, so a reconciler comparing its commanded value against the read-back sees a "+
			"divergence and re-asserts", run.DivergeAddr, run.First.Seq, divergeDelta))
		if ierr != nil {
			run.DivergeErr = ierr
		} else {
			run.DivergeEpoch = epoch
			rpage, sawRe, rerr := d.awaitMatch(ctx, epoch, "re-assert the diverged register",
				func(p LedgerPage) bool { return writeCovering(p, run.DivergeAddr) != nil })
			if rerr != nil {
				return certify.Result{}, rerr
			}
			run.ReassertPage = rpage
			if sawRe {
				if w := writeCovering(rpage, run.DivergeAddr); w != nil {
					run.Reassert, run.HaveReassert = *w, true
				}
			}
		}
	}

	// STEP 4 — the read-back. §2.6's "server write operations SHALL be
	// validated by the test engineer" is, on the wire, the DUT's own later read
	// of the block showing the value it wrote.
	if run.HaveReassert {
		bpage, sawB, berr := d.awaitMatch(ctx, run.Reassert.Epoch, "read the written block back",
			func(p LedgerPage) bool {
				return readCoveringAfter(p, run.DivergeAddr, run.Reassert.Seq) != nil
			})
		if berr != nil {
			return certify.Result{}, berr
		}
		if sawB {
			if r := readCoveringAfter(bpage, run.DivergeAddr, run.Reassert.Seq); r != nil {
				run.ReadBack, run.HaveReadBack = *r, true
			}
		}
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("the DUT was provoked into writing rather than commanded to, and the register "+
			"diverged was LEARNED from the DUT's own write in the simulator's transaction ledger rather "+
			"than guessed — so the provocation reached the cell the product owns instead of a legacy "+
			"mirror the sim re-derives each tick, which is why every previous campaign's divergence "+
			"lever produced nothing. %s. %s", run.summary(), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT wrote an adjustable point using Modbus function code 0x10"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
			}
			fs = append(fs, evalWR2Write(c, run, d))
			fs = append(fs, evalWR2Reassert(run, d))
			fs = append(fs, evalWR2ReadBack(run, d))
			fs = append(fs, wr2Skips()...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// writeCovering returns the first write on the page covering addr.
func writeCovering(p LedgerPage, addr uint16) *LedgerEntry {
	for _, w := range p.Writes() {
		if w.Covers(addr) {
			return &w
		}
	}
	return nil
}

// readCoveringAfter returns the first read on the page covering addr that
// happened strictly after seq — the read-back, as distinct from whatever the
// DUT read before it wrote.
func readCoveringAfter(p LedgerPage, addr uint16, seq uint64) *LedgerEntry {
	for _, r := range p.Reads() {
		if r.Seq > seq && r.Covers(addr) {
			return &r
		}
	}
	return nil
}

// summary renders the run for the note.
func (r *writeRun) summary() string {
	switch {
	case !r.HaveFirst && !r.NorthOn:
		return fmt.Sprintf("the DUT issued no write, and the northbound lever was NOT used (-param %s=on)",
			paramDERControl)
	case !r.HaveFirst:
		return "the DUT issued no write to learn a register from"
	case !r.HaveReassert:
		return fmt.Sprintf("the DUT wrote register %d, which was then diverged; no re-assert followed",
			r.First.Addr)
	default:
		return fmt.Sprintf("the DUT wrote register %d, the register was diverged at epoch %d, and the "+
			"DUT re-asserted it", r.First.Addr, r.DivergeEpoch)
	}
}

// evalWR2Write asserts the framing of the DUT's own FC 0x10 write — the half of
// §2.6.2 the wire genuinely owns.
func evalWR2Write(c *Conversation, r *writeRun, d *determinism) finding {
	claim := "the DUT wrote an adjustable point using Modbus function code 0x10 (Write Multiple " +
		"Registers), with a quantity and byte count that agree"
	method := "the function code, address, quantity, byte count and values of the DUT's own write " +
		"request, taken from the simulator's transaction ledger and cited into the capture where this " +
		"test case owns the frame"
	if !r.HaveFirst {
		return skipf(claim, method, "%s", r.noWriteReason())
	}
	w := r.First
	vals, decoded := w.WriteValues()
	switch {
	case !decoded:
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"the DUT issued an FC 0x10 request the independent decoder could not parse: its byte count "+
				"does not match the payload that follows it. Transaction: %s (request bytes: %s)",
			w, w.Request)
	case int(w.Count) != len(vals):
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"the DUT's FC 0x10 request declared quantity %d but carried %d register value(s) — a "+
				"quantity and a byte count that disagree. Transaction: %s", w.Count, len(vals), w)
	case w.Count > MaxWriteQuantity:
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"the DUT asked to write %d registers, over the %d-register maximum for FC 0x10. "+
				"Transaction: %s", w.Count, MaxWriteQuantity, w)
	}
	// Prefer a byte citation into the capture.
	if c != nil {
		for _, ex := range c.Writes() {
			if ex.Request.FC != FCWriteMultipleRegisters {
				continue
			}
			addr, qty, bc, cvals, ok := ex.Request.WriteMultipleRequest()
			if !ok || addr != w.Addr {
				continue
			}
			return bytesf(claim, method, certify.Pass, fromDUT, ex.Request.Start, ex.Request.End,
				"the DUT wrote %d register(s) (byte count %d, matching the quantity) at %d (0x%04x), "+
					"values %v, and %s. The simulator's own ledger independently records the same "+
					"transaction as %s. Request cited in full: [%s]",
				qty, bc, addr, addr, cvals, ackNote(ex), w, ex.Request.Hex())
		}
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"the DUT wrote %d register(s) at %d, values %v, and the server resolved the transaction as %q. "+
			"Transaction: %s. No frame carrying it was attributed to this test case, so this rests on "+
			"the simulator's record rather than on a citation into the capture",
		w.Count, w.Addr, vals, w.Outcome, w)
}

// ackNote renders the server's verdict on a write, which §2.6.2 wants reported
// even though it is the server's answer and not the client's conformance.
func ackNote(ex Exchange) string {
	switch {
	case ex.Response == nil:
		return "the server did not answer it within this test case's frames"
	case ex.Response.IsException():
		code, _ := ex.Response.ExceptionCode()
		return fmt.Sprintf("the server REFUSED it with exception 0x%02x %s", code, ExceptionName(code))
	default:
		return "the server echoed it: " + ex.Response.String()
	}
}

// evalWR2Reassert is the divergence half: the register the DUT owns was moved,
// and the DUT put it back.
func evalWR2Reassert(r *writeRun, d *determinism) finding {
	claim := "the server's write operation was validated: a control register the DUT had written was " +
		"moved out from under it and the DUT re-asserted the value"
	method := "move the EXACT register the DUT was observed writing (learned from the simulator's " +
		"ledger, not from any model definition directory), then wait on the ledger for a write covering " +
		"that address"
	switch {
	case !r.HaveFirst:
		return skipf(claim, method, "no write was observed to learn a register from, so nothing could "+
			"be diverged. %s", r.noWriteReason())
	case r.DivergeErr != nil:
		return skipf(claim, method, "register %d could not be moved on the server: %v",
			r.DivergeAddr, r.DivergeErr)
	case !r.HaveReassert:
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"register %d — the exact cell the DUT wrote at ledger seq %d — was moved by %d raw units at "+
				"epoch %d, and the DUT issued no write covering it within the barrier's budget (%s). "+
				"Either its reconciler holds no standing setpoint for this axis, or it verifies by "+
				"trusting its own last write rather than by reading back. Distinguishing the two needs "+
				"a standing northbound command: this run %s",
			r.DivergeAddr, r.First.Seq, divergeDelta, r.DivergeEpoch, r.ReassertPage.Summary(),
			r.northboundState())
	}
	vals, _ := r.Reassert.WriteValues()
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"register %d — the exact cell the DUT wrote at ledger seq %d — was moved by %d raw units at "+
			"epoch %d, and the DUT re-asserted it: %s, values %v. The device changed its mind and the "+
			"client corrected it, which is the only direction from which this bench can validate a "+
			"server write operation",
		r.DivergeAddr, r.First.Seq, divergeDelta, r.DivergeEpoch, r.Reassert, vals)
}

// evalWR2ReadBack is §2.6's "server write operations SHALL be validated" as the
// wire carries it: the DUT's own later read of the block it wrote.
func evalWR2ReadBack(r *writeRun, d *determinism) finding {
	claim := "the value the DUT wrote was present in the server's register image when the DUT read the " +
		"block back"
	method := "the DUT's own next read covering the written address, from the simulator's ledger, " +
		"decoded against the values its write carried"
	if !r.HaveReassert {
		return skipf(claim, method, "no re-assert was observed, so there is no written value to read back")
	}
	if !r.HaveReadBack {
		return skipf(claim, method,
			"the DUT wrote register %d at ledger seq %d and did not read that block again within the "+
				"barrier's budget. lexa-gw verifies its model 704 writes on a LATER poll rather than "+
				"in-band (cmd/modbus/reconcile_solar.go's applied-ceiling read), so this is a matter of "+
				"the window rather than of the client skipping verification",
			r.DivergeAddr, r.Reassert.Seq)
	}
	wrote, okW := r.Reassert.WriteValues()
	read, okR := r.ReadBack.Values()
	if !okW || !okR {
		return skipf(claim, method, "the write or the read-back could not be decoded independently "+
			"(write %s; read %s)", r.Reassert, r.ReadBack)
	}
	widx := int(r.DivergeAddr) - int(r.Reassert.Addr)
	ridx := int(r.DivergeAddr) - int(r.ReadBack.Addr)
	if widx < 0 || widx >= len(wrote) || ridx < 0 || ridx >= len(read) {
		return skipf(claim, method, "register %d falls outside the decoded extent of the write (%d, %d "+
			"value(s)) or of the read-back (%d, %d value(s))", r.DivergeAddr,
			r.Reassert.Addr, len(wrote), r.ReadBack.Addr, len(read))
	}
	if wrote[widx] != read[ridx] {
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"the DUT wrote 0x%04x to register %d and its own next read of that block returned 0x%04x. "+
				"The write was acknowledged and did not take", wrote[widx], r.DivergeAddr, read[ridx])
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"the DUT wrote 0x%04x to register %d (ledger seq %d) and its own next read of that block "+
			"(seq %d) returned 0x%04x — the value it wrote, in the server's image, read back over the "+
			"wire by the client itself",
		wrote[widx], r.DivergeAddr, r.Reassert.Seq, r.ReadBack.Seq, read[ridx])
}

// noWriteReason explains an absent write.
func (r *writeRun) noWriteReason() string {
	switch {
	case r.NorthErr != nil:
		return fmt.Sprintf("no write was observed, and the northbound DERControl that would have given "+
			"the DUT's reconciler something to enforce could not be posted: %v", r.NorthErr)
	case !r.NorthOn:
		return fmt.Sprintf("no write was observed, and the northbound lever was NOT used: the DUT emits "+
			"a southbound write only when a northbound command gives its reconciler something to "+
			"enforce, and posting one reaches outside this suite's surface, so it is opt-in. Re-run "+
			"with -param %s=on", paramDERControl)
	default:
		return fmt.Sprintf("a bounded northbound DERControl was posted (%s) and the DUT still issued no "+
			"register write within the barrier's budget: %s", r.Northbound, r.FirstPage.Summary())
	}
}

// northboundState renders whether the opt-in lever was used, for a SKIP text.
func (r *writeRun) northboundState() string {
	switch {
	case r.Northbound != "":
		return "posted one (" + r.Northbound + ")"
	case r.NorthErr != nil:
		return fmt.Sprintf("could not post one (%v)", r.NorthErr)
	default:
		return fmt.Sprintf("did not (-param %s=on enables it)", paramDERControl)
	}
}

// wr2Skips records the parts of §2.6.2 no provocation on this bench can reach,
// each with its own reason.
func wr2Skips() []finding {
	return []finding{
		skipf(
			"every implemented adjustable point was written to its minimum, maximum and three "+
				"intermediate values using FC 0x10",
			"a five-value sweep per adjustable point, driven from the server's PICS",
			"the procedure assumes an operator console the test engineer can hand five values per point "+
				"to. The DUT has no such interface: its southbound writes are emitted by reconcilers "+
				"acting on a northbound command, so the VALUE written is a function of the command, not "+
				"of anything this suite can dictate, and only the points its reconcilers drive are "+
				"reachable at all. What IS now demonstrated is that the client can write a point with "+
				"FC 0x10 and re-assert it against a diverging device — the mechanism the sweep would "+
				"repeat. Promoting the row to full needs either a diagnostic write verb on the DUT's "+
				"Modbus client, or a driver that sweeps five northbound setpoints per reconciled axis "+
				"and correlates each with the resulting register write. The latter is buildable on this "+
				"bench now — the ledger already correlates a northbound command with the exact register "+
				"the DUT writes — but it is a campaign, not a single test case"),
		skipf(
			"every supported value of each adjustable enumerated point was written using FC 0x10",
			"a per-enumerated-value sweep, driven from the server's PICS",
			"same constraint as the five-value sweep: the DUT chooses the enumerated values it writes "+
				"from the northbound command it is enforcing"),
		skipf(
			"the write sweep was repeated with unit id 0, the broadcast address, using FC 0x10",
			"repeat §2.6 step 3 over an RTU server interface with unit id 0",
			"§2.6 step 3 is explicitly conditional on the CUT supporting RTU SERVER interfaces, and unit "+
				"id 0 is the RTU broadcast address — it has no meaning over Modbus/TCP, where every "+
				"request is addressed to a unit on a specific connection. The DUT's southbound servers "+
				"on this bench are all TCP, so the step is out of scope here and would remain so even "+
				"with a full write sweep"),
		skipf(
			"the DUT logged every write operation, with the log data represented as hex strings",
			"inspection of the client's own log output",
			"the same client-side-log criterion as READ-1/READ-2: the DUT journals reconciler decisions, "+
				"not per-write hex. Where a write DID occur this bundle quotes the request ADU verbatim "+
				"in hex — but that is the bench's rendering of the bytes, not the DUT's log. This is a "+
				"DUT diagnostic gap, not a bench gap: no sim work promotes it"),
	}
}
