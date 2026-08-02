package suitemodbusclient

// checks_proto.go implements §2.8, the Modbus Protocol Tests: PROT-1 and
// PROT-2.
//
// # PROT-1 and the word "partial"
//
// §2.8.1 says "preconfigure Server 1 to respond with a partial Modbus response"
// and never defines partial. The catalog's note on this row flags the
// ambiguity: it could mean a short TCP payload, an MBAP length field larger
// than the bytes delivered, a byte count inconsistent with the PDU, or the
// connection dying mid-message. The harness has to pick one and say which.
//
// This suite drives TWO of them and names both:
//
//	(a) a response that never completes because the server severed the
//	    connection mid-transaction, and
//	(b) a response so late that the client's own read timeout expires first.
//
// (a) is the closest thing the bench's server can produce to an incomplete
// message, and (b) is the timeout/retry path that a client which hangs on a
// partial response would fail. The truncated-PDU reading — an MBAP length field
// that promises more bytes than arrive — is the one the sim cannot produce, and
// it is recorded as a SKIP naming the missing verb rather than quietly folded
// into the other two.
//
// # PROT-2 and the absence of a fact
//
// A response ADU is delivered across two TCP segments or it is not, and the
// bench cannot make the sim's TCP stack fragment on demand. So PROT-2 asserts
// segmentation when the capture contains it and SKIPs when it does not — and,
// in either case, asserts the fact that is always available and that the row is
// really about: the DUT framed its peer's stream by MBAP length, consuming
// exactly the declared number of bytes per message with nothing left over.

import (
	"context"
	"fmt"
	"time"

	"csip-tls-test/internal/certify"
)

// latencyMs is the read delay armed for PROT-1's timeout phase. It is well
// beyond any plausible per-read timeout for a 10-second poll loop, so a client
// that bounds its reads will abandon the transaction and one that does not will
// block visibly.
const latencyMs = 9000

// shortResponseTruncateBytes is the number of PDU bytes modsim's
// short_response fault actually writes (sim/southbound/protorelay.go): the
// function code and byte count survive, the register data does not, which
// is the smallest truncation that still leaves the MBAP length field lying
// about a plausible-looking response.
const shortResponseTruncateBytes = 2

// ── PROT-1 — Partial Response ─────────────────────────────────────────────────

func checkPROT1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	if r := o.injectionReason(); r != "" {
		return certify.Skipped("this procedure requires the server to return an incomplete response, "+
			"and %s", r), nil
	}

	// Baseline, so the capture holds a normal exchange before the provocation.
	if err := o.watch(ctx, 1); err != nil {
		return certify.Result{}, err
	}

	// Phase (b): the response that arrives too late.
	latencyArmed := o.fault(ctx, map[string]any{"kind": "latency", "latency_ms": latencyMs},
		fmt.Sprintf("delay every register read by %d ms, far beyond any plausible client read timeout, "+
			"so a client that bounds its reads abandons the transaction", latencyMs))
	if latencyArmed == nil {
		err := o.watch(ctx, 2)
		o.clearFault("latency")
		if err != nil {
			return certify.Result{}, err
		}
	}

	// Phase (a): the transaction severed mid-flight.
	severed := o.fault(ctx, map[string]any{"kind": "tcp_drop"},
		"sever the DUT's live southbound connection so a request in flight never receives a complete "+
			"Modbus response — this suite's chosen reading of §2.8.1's undefined 'partial response'")
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}
	if err := o.settle(ctx); err != nil {
		return certify.Result{}, err
	}

	// Phase (c): the structurally truncated response — PROT-1#5 (census
	// compliance-fullsuite-2-20260802T020946). Deliberately LAST, and
	// deliberately on the SAME connection tcp_drop's recovery just
	// confirmed (no further reconnect is forced here): shortArmedAt is the
	// cutoff evalPROT1/evalPROT1ShortResponse use to keep this phase's own
	// unanswered read from being misattributed to phase (a)'s "severed
	// mid-flight" reading, or vice versa, when both land in the one
	// conversation citeConversation selects for this test case. Needs
	// modsim started with -protofault (sim/southbound/protorelay.go); the
	// sim refuses the fault BY NAME when it was not, so this reports
	// SKIP-with-reason rather than folding into "cannot be served at all".
	var shortArmedAt time.Time
	shortArmed := o.fault(ctx, map[string]any{"kind": "short_response", "truncate_bytes": shortResponseTruncateBytes},
		fmt.Sprintf("write a response with a well-formed MBAP header promising the full PDU but stop the "+
			"socket write after %d bytes of it, leaving the connection open — the structurally truncated "+
			"reading of §2.8.1's undefined 'partial response'", shortResponseTruncateBytes))
	if shortArmed == nil {
		shortArmedAt = time.Now().UTC()
		err := o.watch(ctx, 2)
		o.clearFault("short_response")
		if err != nil {
			return certify.Result{}, err
		}
		if err := o.settle(ctx); err != nil {
			return certify.Result{}, err
		}
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("three readings of §2.8.1's undefined 'partial response' were driven — a "+
			"severed transaction, an over-long response delay, and (when modsim is started with "+
			"-protofault) a structurally truncated response — and the DUT's recovery observed. %s",
			o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT remained functional after a Modbus response failed to complete"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, append(pre, evalPROT1ShortResponse(nil, nil, shortArmed, shortArmedAt))), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalPROT1(c, timeFn(ev), severed == nil, latencyArmed == nil, shortArmedAt)...)
			fs = append(fs, evalPROT1ShortResponse(c, timeFn(ev), shortArmed, shortArmedAt))
			return emit(ev, c, fs), nil
		},
	}, nil
}

// timeFn adapts the frame index to a timestamp lookup for the eval functions,
// so their decision logic can be driven from a synthetic table in a unit test.
func timeFn(ev *certify.Evidence) func(frame int) (time.Time, bool) {
	return func(frame int) (time.Time, bool) {
		p, ok := ev.Index.Packet(frame)
		if !ok {
			return time.Time{}, false
		}
		return p.Time, true
	}
}

// evalPROT1 is PROT-1's decision logic. shortArmedAt, when non-zero, is the
// moment phase (c)'s short_response fault was armed — everything this
// function evaluates about phase (a)'s severed transaction is scoped to
// BEFORE that instant, so a later, structurally-truncated-but-still-open
// exchange (evaluated separately by evalPROT1ShortResponse) is never
// misattributed here as "the server reset/closed the connection", which it
// did not.
func evalPROT1(c *Conversation, at func(int) (time.Time, bool), severed, latency bool,
	shortArmedAt time.Time) []finding {
	var out []finding

	// (1) The incomplete response itself.
	claim := "a Modbus response the DUT requested did not complete"
	method := "a request in the reassembled DUT→server direction with no matching response, in a " +
		"conversation the server closed"
	unanswered := unansweredReadsBefore(c, at, shortArmedAt)
	switch {
	case !severed:
		out = append(out, skipf(claim, method,
			"the connection could not be severed on the server, so no incomplete response was produced"))
	case len(unanswered) == 0:
		out = append(out, skipf(claim, method,
			"the server's connection was severed, but every request this test case observed was "+
				"answered — the severance fell between transactions rather than during one. The DUT's "+
				"reconnect is still asserted below"))
	default:
		q := unanswered[len(unanswered)-1].Request
		closedBy := "the conversation ended"
		switch {
		case c.RSTSeen:
			closedBy = "the server reset the connection (RST)"
		case c.FINSeen:
			closedBy = "the server closed the connection (FIN)"
		}
		out = append(out, bytesf(claim, method, certify.Pass, fromDUT, q.Start, q.End,
			"the DUT issued %s and received no response: %s. %d request(s) in this window went "+
				"unanswered. Request cited in full: [%s]",
			q.String(), closedBy, len(unanswered), q.Hex()))
	}

	// (2) The recovery criterion — the row's actual SHALL.
	claim = "the DUT remained functional and read the Common Model successfully after the failure"
	method = "a complete FC 0x03 exchange, covering model 1's body, occurring after the unanswered request"
	after := 0
	if len(unanswered) > 0 {
		after = unanswered[len(unanswered)-1].Request.End
	}
	if ex, ok := firstSuccessfulReadAfter(c, after); ok {
		_, models, _, _ := c.ModelChain()
		common := ""
		if m, ok := findModel(models, CommonModelID); ok && m.BodyRead {
			common = fmt.Sprintf(" The Common Model (ID 1, header at %d) was among the blocks read "+
				"after the failure.", m.HeaderAddr)
		}
		out = append(out, bytesf(claim, method, certify.Pass, fromServer, ex.Response.Start, ex.Response.End,
			"after the failure the DUT issued %s and the server answered it normally — the client "+
				"neither hung nor stopped polling.%s Recovery response cited in full: [%s]",
			ex.Request.String(), common, ex.Response.Hex()))
	} else {
		out = append(out, skipf(claim, method,
			"no successful read followed the failure within this test case's frames. The DUT may have "+
				"reconnected after the observation window closed; a longer window is needed to assert "+
				"the recovery"))
	}

	// (3) The timeout/retry path.
	out = append(out, evalTimeoutBehaviour(c, at, latency))
	return out
}

// evalTimeoutBehaviour asserts that the DUT bounds its reads: with the server
// delayed far beyond any sane timeout, a conformant client abandons the
// transaction rather than blocking its control loop on it.
func evalTimeoutBehaviour(c *Conversation, at func(int) (time.Time, bool), armed bool) finding {
	claim := "the DUT bounded its read with a timeout rather than blocking on a response that did not arrive"
	method := "elapsed capture time between a request frame and its response frame, with the server's " +
		"read path delayed"
	if !armed {
		return skipf(claim, method,
			"the read-delay fault could not be armed on the server, so no over-long response was produced")
	}
	if at == nil {
		return skipf(claim, method, "no frame timestamps are available for this test case")
	}
	var worst time.Duration
	var worstEx Exchange
	abandoned := 0
	for _, ex := range c.Reads() {
		if len(ex.Request.Frames) == 0 {
			continue
		}
		qt, ok := at(ex.Request.Frames[0])
		if !ok {
			continue
		}
		if ex.Response == nil || len(ex.Response.Frames) == 0 {
			abandoned++
			continue
		}
		rt, ok := at(ex.Response.Frames[len(ex.Response.Frames)-1])
		if !ok {
			continue
		}
		if d := rt.Sub(qt); d > worst {
			worst, worstEx = d, ex
		}
	}
	threshold := time.Duration(latencyMs) * time.Millisecond
	switch {
	case abandoned > 0:
		return framesf(claim, method, certify.Pass, aduFrames(c.Requests...),
			"with the server's read path delayed by %d ms, %d request(s) received no response at all "+
				"within this test case's frames — the DUT gave up on them rather than waiting out the "+
				"delay, and kept issuing new requests", latencyMs, abandoned)
	case worst >= threshold:
		return bytesf(claim, method, certify.Warn, fromDUT, worstEx.Request.Start, worstEx.Request.End,
			"the DUT waited %s for a response — at or beyond the %s the server was delayed by — and "+
				"accepted it. The client did not abandon the over-long read, so its read bound (if any) "+
				"is longer than the injected delay", worst.Round(time.Millisecond), threshold)
	case worst > 0:
		return bytesf(claim, method, certify.Skip, fromDUT, worstEx.Request.Start, worstEx.Request.End,
			"the slowest exchange in this test case's frames completed in %s, well under the %s delay "+
				"armed on the server, so the delay was not in force for the frames observed and the "+
				"timeout path was not exercised", worst.Round(time.Millisecond), threshold)
	default:
		return skipf(claim, method, "no request/response pair with usable frame timestamps was observed")
	}
}

// unansweredReadsBefore returns unansweredReads(c), restricted to requests
// issued strictly before cutoff. A zero cutoff — no later phase needs
// excluding — returns every unanswered read, unfiltered (evalPROT1's
// original, single-phase behaviour). An exchange whose timestamp cannot be
// resolved is KEPT rather than dropped, so a timestamp gap here never
// silently hides a real severance.
func unansweredReadsBefore(c *Conversation, at func(int) (time.Time, bool), cutoff time.Time) []Exchange {
	all := unansweredReads(c)
	if cutoff.IsZero() || at == nil {
		return all
	}
	var out []Exchange
	for _, ex := range all {
		if len(ex.Request.Frames) == 0 {
			out = append(out, ex)
			continue
		}
		t, ok := at(ex.Request.Frames[0])
		if !ok || t.Before(cutoff) {
			out = append(out, ex)
		}
	}
	return out
}

// unansweredReadsFrom is unansweredReadsBefore's complement: requests issued
// at or after cutoff, used to isolate a LATER phase's own provocation
// (short_response) from an earlier one already accounted for by
// unansweredReadsBefore (tcp_drop). A zero cutoff or nil at, meaning the
// later phase never ran, correctly yields nothing.
func unansweredReadsFrom(c *Conversation, at func(int) (time.Time, bool), cutoff time.Time) []Exchange {
	if cutoff.IsZero() || at == nil {
		return nil
	}
	var out []Exchange
	for _, ex := range unansweredReads(c) {
		if len(ex.Request.Frames) == 0 {
			continue
		}
		t, ok := at(ex.Request.Frames[0])
		if ok && !t.Before(cutoff) {
			out = append(out, ex)
		}
	}
	return out
}

// evalPROT1ShortResponse is PROT-1#5: the structurally truncated reading of
// §2.8.1's undefined "partial response" — an MBAP length field promising
// more bytes than the server actually wrote, with the connection left open
// rather than closed (contrast tcp_drop's severed-mid-flight reading,
// evalPROT1's phase (a)). Needs modsim started with -protofault
// (sim/southbound/protorelay.go); without it the sim refuses the fault BY
// NAME and this SKIPs saying so.
func evalPROT1ShortResponse(c *Conversation, at func(int) (time.Time, bool), armed error,
	armedAt time.Time) finding {
	claim := "the DUT recovered from a response whose MBAP length field promised more bytes than were delivered"
	method := "serve a structurally truncated Modbus response (a well-formed MBAP length field, fewer PDU " +
		"bytes actually written, connection left open) via modsim's short_response fault (needs -protofault), " +
		"then look for a complete, successful exchange afterward"
	if armed != nil {
		return skipf(claim, method, "the short_response fault could not be armed on the server: %v", armed)
	}
	if c == nil {
		return skipf(claim, method,
			"the short_response fault was armed, but no capture frame was attributed to this test case, "+
				"so the DUT's reaction to it cannot be observed")
	}
	unanswered := unansweredReadsFrom(c, at, armedAt)
	if len(unanswered) == 0 {
		return skipf(claim, method,
			"the short_response fault was armed, but no request in this test case's frames was left "+
				"without a complete response while it was in force — the truncated write may have fallen "+
				"outside the observed window, or landed on a connection this test case does not cite "+
				"bytes from (see the note on multiple attributed conversations)")
	}
	q := unanswered[len(unanswered)-1].Request
	if ex, ok := firstSuccessfulReadAfter(c, q.End); ok {
		return bytesf(claim, method, certify.Pass, fromServer, ex.Response.Start, ex.Response.End,
			"the DUT issued %s while the server was serving a truncated response (MBAP length promising "+
				"more PDU bytes than were written, connection left open) and received no complete answer "+
				"to it; the client recovered — %s issued afterward and answered normally. Recovery "+
				"response cited in full: [%s]", q.String(), ex.Request.String(), ex.Response.Hex())
	}
	return skipf(claim, method,
		"the short_response fault was armed and left a request unanswered, but no successful read "+
			"followed within this test case's frames to evidence recovery")
}

// ── PROT-2 — TCP Segmentation ─────────────────────────────────────────────────

func checkPROT2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	o, why := newObserver(rc)
	if o == nil {
		return certify.Skipped("%s", why), nil
	}
	if err := o.claimServer(); err != nil {
		return certify.Result{}, err
	}
	// A forced reconnect brings the discovery burst into the window: many
	// responses in quick succession, which is where a segmented or coalesced
	// delivery is most likely to occur naturally.
	forced := o.forceReconnect(ctx)
	if err := o.watch(ctx, 2); err != nil {
		return certify.Result{}, err
	}
	return certify.Result{
		Notes: fmt.Sprintf("the DUT's MBAP-length framing of the server's byte stream was asserted%s; "+
			"whether a response ADU happened to span TCP segments is not something this bench can "+
			"compel. %s", reconnectNote(forced), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT parsed a Modbus response delivered across more than one TCP segment"
			c, pre, ok := citeConversation(ev, o, claim)
			if !ok {
				return emit(ev, c, pre), nil
			}
			fs := []finding{assertAttributionSound(ev, o)}
			fs = append(fs, evalPROT2(c, forced == nil)...)
			fs = append(fs, evalFraming(c)...)
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalPROT2 is PROT-2's decision logic. selfSevered is true when THIS test
// case's own o.forceReconnect (tcp_drop) succeeded, so the retry/reset
// finding below can attribute a TCP reset to a provocation it can positively
// identify rather than guessing.
func evalPROT2(c *Conversation, selfSevered bool) []finding {
	var out []finding

	// (1) The row's literal subject: an ADU spanning segments.
	claim := "the DUT parsed a Modbus response delivered across more than one TCP segment"
	method := "capture frames covering each response ADU's byte range in the reassembled server→DUT " +
		"direction; more than one frame means the ADU spanned segments"
	var seg *ADU
	for i := range c.Responses {
		if c.Responses[i].Segmented() {
			seg = &c.Responses[i]
			break
		}
	}
	if seg == nil {
		out = append(out, skipf(claim, method,
			"every one of the %d response ADU(s) this test case observed arrived in a single TCP "+
				"segment, so the client's reassembly path was not exercised. The server sim writes each "+
				"response with one socket write and every response here is well under the path MTU, so "+
				"segmentation does not occur naturally. Promoting this row to full requires a server "+
				"fault verb that splits a response across writes — e.g. POST /fault "+
				"{\"kind\":\"segment_response\",\"split_after\":4} — or a path MTU small enough to force it",
			len(c.Responses)))
	} else {

		out = append(out, bytesf(claim, method, certify.Pass, fromServer, seg.Start, seg.End,
			"a %d-byte response ADU (transaction id %d) was delivered across %d capture frames %v, and "+
				"the DUT went on to issue its next request rather than resetting or retrying — it "+
				"reassembled the message. Response cited in full: [%s]",
			seg.End-seg.Start, seg.TxID, len(seg.Frames), seg.Frames, seg.Hex()))
	}

	// (2) The fact that is always available: the DUT framed by MBAP length.
	claim = "the DUT consumed the server's byte stream as length-delimited MBAP messages, with no " +
		"dependence on segment boundaries"
	method = "independent re-parse of the reassembled server→DUT direction: every byte accounted for by " +
		"a complete ADU whose MBAP length field matches its delivered payload"
	p := c.RspParse
	switch {
	case len(c.Responses) == 0:
		out = append(out, skipf(claim, method, "no responses were observed"))
	case len(p.Problems) > 0:
		out = append(out, framesf(claim, method, certify.Warn, aduFrames(c.Responses...),
			"%d complete ADU(s) were parsed from the server→DUT direction, but the parse raised %d "+
				"structural finding(s): %s", len(p.ADUs), len(p.Problems), joinOr(p.Problems, "none")))
	case p.TrailingBytes > 0:
		out = append(out, framesf(claim, method, certify.Warn, aduFrames(c.Responses...),
			"%d complete ADU(s) were parsed, but %d byte(s) at the end of the direction formed no "+
				"complete message. At the end of a capture that is normally a message the capture cut "+
				"short rather than a framing defect", len(p.ADUs), p.TrailingBytes))
	default:
		out = append(out, framesf(claim, method, certify.Pass, aduFrames(c.Responses...),
			"all %d byte(s) of the server→DUT direction were accounted for by %d complete ADU(s), each "+
				"with a length field matching its delivered payload and no leftover bytes. The DUT "+
				"issued its next request after each, so it located every message boundary from the "+
				"length field alone", c.RspDir.Bytes.Len(), len(p.ADUs)))
	}

	// (3) No retry, no reset — the row's "CUT does not send a duplicate/retry
	//     request and does not reset the connection".
	claim = "the DUT neither retried nor reset the connection while consuming the server's responses"
	method = "TCP retransmission and RST counters for the DUT→server direction, and duplicate " +
		"transaction ids among its requests"
	switch {
	case c.ReqDir == nil:
		out = append(out, skipf(claim, method, "the DUT→server direction was not reassembled"))
	case c.RSTSeen && selfSevered:
		// PROT-2#4 (census 20260731T234821): the previous text pointed a
		// reader at PROT-1 — an unrelated test case — to settle whether a
		// severance had been injected here, which is not a question PROT-1's
		// outcome can answer. This check knows its OWN provocation directly
		// (o.forceReconnect's result, threaded in as selfSevered) and uses
		// that instead of guessing or deferring to another case's evidence.
		out = append(out, framesf(claim, method, certify.Skip, aduFrames(c.Requests...),
			"the conversation carried a TCP reset, but THIS test case itself severed the DUT's preceding "+
				"southbound connection with tcp_drop to force the reconnect being observed here (see the "+
				"injection note above) — a self-identified provocation, not an unexplained DUT-originated "+
				"reset, so it is not graded as a finding about the DUT's retry/reset discipline"))
	case c.RSTSeen:
		out = append(out, framesf(claim, method, certify.Warn, aduFrames(c.Requests...),
			"the conversation carried a TCP reset, and this test case injected no severance of its own "+
				"(forceReconnect did not succeed here) — this bench cannot rule out a DUT-originated reset, "+
				"so it is reported rather than failed"))
	case c.TxIDs.Repeats > 0:
		out = append(out, framesf(claim, method, certify.Warn, aduFrames(c.Requests...),
			"%d request(s) reused a transaction id that was still outstanding, which is what a retry "+
				"looks like on the wire", c.TxIDs.Repeats))
	default:
		out = append(out, framesf(claim, method, certify.Pass, aduFrames(c.Requests...),
			"no TCP reset, %d retransmitted segment(s) in the DUT→server direction, and no transaction "+
				"id reused while outstanding across %d request(s)", c.ReqDir.Retransmits, len(c.Requests)))
	}
	return out
}
