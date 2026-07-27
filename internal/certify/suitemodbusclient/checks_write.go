package suitemodbusclient

// checks_write.go implements §2.6, the Write Tests: WR-1 (FC 0x06) and WR-2
// (FC 0x10).
//
// # Why these two rows are structurally hard on this DUT
//
// §2.6 is written for an operator console: the test engineer hands the CUT a
// list of five values per adjustable point and watches it write each one. The
// DUT is not an operator console. It is an autonomous gateway whose southbound
// writes are a CONSEQUENCE — its reconcilers emit a register write only when a
// northbound command (a CSIP DERControl, or an aggregator's mbaps write) gives
// them something to enforce. There is no interface, on the device or off it,
// that says "write 0x1234 to register 40230".
//
// So a write sweep has to be driven indirectly, and this suite offers exactly
// two levers, in increasing order of blast radius:
//
//	1. Divergence. Move the server's control register out from under the DUT
//	   and see whether an active reconciler puts it back. Costs nothing and
//	   touches nothing but the sim; provokes a write only if a standing setpoint
//	   exists to re-assert.
//	2. A northbound command. Post a short, self-expiring DERControl to the
//	   bench's 2030.5 server so the DUT's CSIP client adopts a limit and its
//	   solar reconciler writes it southbound. This reaches outside this suite's
//	   own surface — it makes the DUT do something it was not doing — so it is
//	   OFF by default and enabled with -param modbus-client.dercontrol=on.
//
// When neither lever produces a write, the rows SKIP with that stated, and with
// the exact command that would produce one. They do not pass on the strength of
// having tried.

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
// this check is killed mid-run.
const derControlSeconds = 120

// writeProvocation records what was done to try to make the DUT write.
type writeProvocation struct {
	Divergence   string
	DERControl   string
	DERAttempt   bool
	DERErr       error
	DivergeErr   error
	NorthboundOn bool
}

// provokeWrites applies the levers and returns what it did.
func provokeWrites(ctx context.Context, rc *certify.RunCtx, o *observer) (*writeProvocation, error) {
	p := &writeProvocation{}
	if v, ok := rc.Param(paramDERControl); ok && strings.EqualFold(strings.TrimSpace(v), "on") {
		p.NorthboundOn = true
	}

	// Lever 1: divergence on the sim's control register.
	body := map[string]any{"WMaxLimPct_pct": 50}
	if err := o.injectValue(ctx, body,
		"move the server's WMaxLimPct control register away from the value the DUT last wrote, so an "+
			"active reconciler that holds a standing setpoint re-asserts it with a register write"); err != nil {
		p.DivergeErr = err
	} else {
		p.Divergence = jsonish(body)
	}

	// Lever 2: a bounded northbound command, opt-in.
	if p.NorthboundOn && rc.GridSim != nil && rc.GridSim.Available() {
		p.DERAttempt = true
		ctrl := map[string]any{
			"program":    0,
			"gen_lim_W":  derControlWatts,
			"duration_s": derControlSeconds,
			"activate":   true,
		}
		if err := rc.GridSim.Control(ctx, ctrl, nil); err != nil {
			p.DERErr = err
		} else {
			p.DERControl = fmt.Sprintf("POST %s/admin/control %s — a %d W generation limit lasting %d s, "+
				"posted so the DUT's CSIP client adopts it and its solar reconciler writes the "+
				"corresponding SunSpec control register southbound. It expires on its own",
				rc.GridSim.BaseURL, jsonish(ctrl), derControlWatts, derControlSeconds)
			o.injected = append(o.injected, p.DERControl)
		}
	}

	// Two poll cycles for the reconciler to act, plus one for the readback it
	// performs after writing.
	if err := o.watch(ctx, 3); err != nil {
		return p, err
	}
	return p, nil
}

// reason renders why no write may have appeared.
func (p *writeProvocation) reason() string {
	var parts []string
	if p.Divergence != "" {
		parts = append(parts, "the server's control register was moved out from under the DUT ("+p.Divergence+")")
	} else if p.DivergeErr != nil {
		parts = append(parts, fmt.Sprintf("the control register could not be diverged (%v)", p.DivergeErr))
	}
	switch {
	case p.DERControl != "":
		parts = append(parts, "and a bounded northbound DERControl was posted to give the reconciler a "+
			"setpoint to enforce")
	case p.DERAttempt && p.DERErr != nil:
		parts = append(parts, fmt.Sprintf("and the northbound DERControl could not be posted (%v)", p.DERErr))
	case !p.NorthboundOn:
		parts = append(parts, fmt.Sprintf("and the northbound lever was NOT used: the DUT emits a "+
			"southbound write only when a northbound command gives its reconciler something to "+
			"enforce, and posting one reaches outside this suite's surface, so it is opt-in "+
			"(-param %s=on)", paramDERControl))
	}
	return joinOr(parts, "no provocation was applied")
}

// ── WR-1 — Write Single Point (FC 0x06) ───────────────────────────────────────

func checkWR1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return writeCheck(ctx, rc, FCWriteSingleRegister)
}

// ── WR-2 — Write Multiple Points (FC 0x10) ────────────────────────────────────

func checkWR2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return writeCheck(ctx, rc, FCWriteMultipleRegisters)
}

// writeCheck is WR-1 and WR-2: the two rows differ only in the function code
// their criterion names, and their criteria text is verbatim identical.
func writeCheck(ctx context.Context, rc *certify.RunCtx, fc uint8) (certify.Result, error) {
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
	prov, err := provokeWrites(ctx, rc, o)
	if err != nil {
		return certify.Result{}, err
	}
	// Put the server's control register back where the DUT expects it, whatever
	// happened, so the next test case starts from a coherent device.
	if prov.Divergence != "" {
		_ = o.injectValue(ctx, map[string]any{"WMaxLimPct_pct": 100},
			"restore the server's control register after the divergence probe")
	}
	if err := o.settle(ctx); err != nil {
		return certify.Result{}, err
	}

	return certify.Result{
		Verdict: certify.Skip,
		Notes: fmt.Sprintf("the DUT was provoked into writing rather than commanded to: %s. %s",
			prov.reason(), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := fmt.Sprintf("the DUT wrote an adjustable point using Modbus function code 0x%02x", fc)
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, writeSkips(fc, prov)...)), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalWrites(c, fc, prov)...)
			fs = append(fs, writeSkips(fc, prov)...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalWrites asserts on whatever writes the provocation produced. If the DUT
// did write, the framing of those writes is fully assertable — which is the
// half of WR-1/WR-2 the wire genuinely owns.
func evalWrites(c *Conversation, fc uint8, prov *writeProvocation) []finding {
	claim := fmt.Sprintf("the DUT wrote an adjustable point using Modbus function code 0x%02x (%s)",
		fc, FunctionName(fc))
	method := "function code, address, quantity, byte count and values of every write request in the " +
		"reassembled DUT→server direction"

	var mine []Exchange
	var others int
	for _, ex := range c.Writes() {
		if ex.Request.FC == fc {
			mine = append(mine, ex)
		} else {
			others++
		}
	}
	if len(mine) == 0 {
		note := ""
		if others > 0 {
			note = fmt.Sprintf(" The DUT DID issue %d write(s) with the other function code in this "+
				"window, so it writes — just not with this one; see the sibling row", others)
		}
		return []finding{skipf(claim, method,
			"no FC 0x%02x request was observed. %s.%s", fc, prov.reason(), note)}
	}

	var out []finding
	ex := mine[0]
	// Framing of the write itself.
	switch fc {
	case FCWriteSingleRegister:
		addr, val, ok := ex.Request.WriteSingle()
		if !ok {
			out = append(out, bytesf(claim, method, certify.Fail, fromDUT, ex.Request.Start, ex.Request.End,
				"an FC 0x06 request was malformed: its payload is %d byte(s), not the 4 the function "+
					"code requires. Request cited in full: [%s]", len(ex.Request.Payload), ex.Request.Hex()))
		} else {
			out = append(out, bytesf(claim, method, certify.Pass, fromDUT, ex.Request.Start, ex.Request.End,
				"%d FC 0x06 request(s); the first wrote value %d (0x%04x) to register %d (0x%04x). "+
					"Request cited in full: [%s]", len(mine), int16(val), val, addr, addr, ex.Request.Hex()))
		}
	case FCWriteMultipleRegisters:
		addr, qty, bc, vals, ok := ex.Request.WriteMultipleRequest()
		switch {
		case !ok:
			out = append(out, bytesf(claim, method, certify.Fail, fromDUT, ex.Request.Start, ex.Request.End,
				"an FC 0x10 request was malformed: byte count %d does not match the %d payload byte(s) "+
					"after it. Request cited in full: [%s]", bc, len(ex.Request.Payload)-5, ex.Request.Hex()))
		case int(qty)*2 != int(bc):
			out = append(out, bytesf(claim, method, certify.Fail, fromDUT, ex.Request.Start, ex.Request.End,
				"an FC 0x10 request declared quantity %d but byte count %d — a register quantity and a "+
					"byte count that disagree. Request cited in full: [%s]", qty, bc, ex.Request.Hex()))
		case qty > MaxWriteQuantity:
			out = append(out, bytesf(claim, method, certify.Fail, fromDUT, ex.Request.Start, ex.Request.End,
				"an FC 0x10 request asked to write %d registers, over the %d-register maximum",
				qty, MaxWriteQuantity))
		default:
			out = append(out, bytesf(claim, method, certify.Pass, fromDUT, ex.Request.Start, ex.Request.End,
				"%d FC 0x10 request(s); the first wrote %d register(s) (byte count %d, matching the "+
					"quantity) at %d (0x%04x), values %v. Request cited in full: [%s]",
				len(mine), qty, bc, addr, addr, vals, ex.Request.Hex()))
		}
	}

	// The server's acknowledgement — WR-1/WR-2's "server write operations SHALL
	// be validated by the test engineer", as far as the wire carries it.
	ackClaim := fmt.Sprintf("the server acknowledged the DUT's FC 0x%02x write", fc)
	ackMethod := "the response matching the write request, by transaction id"
	switch {
	case ex.Response == nil:
		out = append(out, skipf(ackClaim, ackMethod, "the write request was not answered within this "+
			"test case's frames"))
	case ex.Response.IsException():
		code, _ := ex.Response.ExceptionCode()
		out = append(out, bytesf(ackClaim, ackMethod, certify.Warn, fromServer,
			ex.Response.Start, ex.Response.End,
			"the server rejected the write with exception 0x%02x %s. That is the server's verdict on "+
				"the write, not the client's conformance; it is reported here because a bundle that "+
				"showed only the request would misrepresent the outcome", code, ExceptionName(code)))
	default:
		out = append(out, bytesf(ackClaim, ackMethod, certify.Pass, fromServer,
			ex.Response.Start, ex.Response.End,
			"the server echoed the write: %s. Response cited in full: [%s]",
			ex.Response.String(), ex.Response.Hex()))
	}
	return out
}

// writeSkips records the parts of §2.6 that no provocation on this bench can
// reach, each with its own reason.
func writeSkips(fc uint8, prov *writeProvocation) []finding {
	f := fmt.Sprintf("0x%02x", fc)
	return []finding{
		skipf(
			"every implemented adjustable point was written to its minimum, maximum and three "+
				"intermediate values using FC "+f,
			"a five-value sweep per adjustable point, driven from the server's PICS",
			"the procedure assumes an operator console the test engineer can hand five values per point "+
				"to. The DUT has no such interface: its southbound writes are emitted by reconcilers "+
				"acting on a northbound command, so the value written is a function of the command, not "+
				"of anything this suite can dictate, and only the points its reconcilers drive are "+
				"reachable at all. Promoting this row to full requires either a diagnostic write verb on "+
				"the DUT's Modbus client, or a driver that sweeps five northbound setpoints per "+
				"reconciled axis and correlates each with the resulting register write — the latter is "+
				"buildable on this bench (it is what -param %s=on begins) but it is a campaign, not a "+
				"single test case", paramDERControl),
		skipf(
			"every supported value of each adjustable enumerated point was written using FC "+f,
			"a per-enumerated-value sweep, driven from the server's PICS",
			"same constraint as the five-value sweep: the DUT chooses the enumerated values it writes "+
				"from the northbound command it is enforcing. %s", prov.reason()),
		skipf(
			"the write sweep was repeated with unit id 0, the broadcast address, using FC "+f,
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
				"not per-write hex. Where a write DID occur, this bundle quotes the request ADU verbatim "+
				"in hex — but that is the bench's rendering of the bytes, not the DUT's log"),
	}
}
