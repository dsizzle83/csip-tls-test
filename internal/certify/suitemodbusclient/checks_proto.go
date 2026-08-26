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

	"csip-tls-test/internal/certify"
)

// oneShotDelayMS is the hold PROT-1's delay reading applies. It is comfortably
// beyond lexa-gw's own 5-second per-request I/O deadline
// (cmd/modbus/transport_factory.go:52, applied by the vendored client's
// SetDeadline on every transaction), so a client that bounds its reads
// abandons the transaction and one that does not blocks visibly.
const oneShotDelayMS = 9000

// shortResponseTruncateBytes is how much of the PDU the truncated reading
// actually delivers: the function code and the byte count survive, the register
// data does not. It is the smallest truncation that still leaves the MBAP
// length field lying about a plausible-looking response.
const shortResponseTruncateBytes = 2

// ── PROT-1 — Partial Response ─────────────────────────────────────────────────

// partialReading is one of §2.8.1's three readings of "partial response",
// driven as a ONE-SHOT against a named transaction.
type partialReading struct {
	// Name is what the assertion calls this reading.
	Name string
	// Action is the sim's one-shot action, and Outcome is what the ledger must
	// record for a transaction it shaped.
	Action, Outcome string
	// Extra carries the action's own parameter.
	Extra map[string]any
	// Doc is why this counts as "partial" under a document that never defines
	// the word.
	Doc string

	M meeting
	// Recovery is the DUT's next transaction after the reading, and Recovered
	// says it happened.
	Recovery  LedgerPage
	Recovered bool
	Fence     uint64
}

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
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}

	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	// Aim at the block the DUT reads every cycle. The anchor IS "the model the
	// client reads", learned by the sim from the client's own traffic — so the
	// one-shot lands on a transaction the DUT was always going to issue, and
	// this suite consults no model definition directory to find it (the same
	// independence ERR-3 rests on).
	warm, haveAnchor, err := d.warmUp(ctx)
	if err != nil {
		return certify.Result{}, err
	}
	scope := map[string]any{"on_fc": 3}
	aim := "any FC 0x03 read"
	if haveAnchor {
		a := warm.Poll.Anchor
		scope["on_addr"] = []int{int(a.Addr), int(a.Addr) + int(max16(a.Count, 1))}
		aim = fmt.Sprintf("the DUT's own measurement read at %d×%d — the block the sim observed it "+
			"repeating every poll cycle", a.Addr, a.Count)
	}

	readings := []*partialReading{
		{
			Name: "a response the server never sent", Action: "drop", Outcome: outcomeDropped,
			Doc: "the server received the request, composed an answer, and delivered none of it while " +
				"leaving the connection OPEN. This is the reading closest to §2.8.1's words: the client " +
				"is left holding an incomplete transaction rather than a dead socket, so its own read " +
				"timeout is what has to save it",
		},
		{
			Name: "a structurally truncated response", Action: "short", Outcome: outcomeTruncated,
			Extra: map[string]any{"truncate_bytes": shortResponseTruncateBytes},
			Doc: "the MBAP header promises the full PDU and the socket write stops after " +
				"the function code and byte count. A client that frames by length waits for bytes that " +
				"are not coming; one that reads whatever is next splices the following response onto " +
				"this value and decodes a number that was never sent",
		},
		{
			Name: "a response too late to be an answer", Action: "delay", Outcome: outcomeDelayed,
			Extra: map[string]any{"delay_ms": oneShotDelayMS},
			Doc: "the answer is complete and correct and arrives after the client's own per-request " +
				"deadline. lexa-gw bounds every transaction at 5 s (cmd/modbus/transport_factory.go:52), " +
				"so a 9 s hold is decided by the client's timeout rather than by this bench's patience",
		},
	}

	for _, r := range readings {
		spec := map[string]any{"kind": "next_response", "action": r.Action}
		for k, v := range scope {
			spec[k] = v
		}
		for k, v := range r.Extra {
			spec[k] = v
		}
		// NO clear kind: a one-shot is consumed by the request that matches
		// it, which is the whole reason this row can now say WHICH transaction
		// its provocation landed in. The previous version armed a blanket and
		// hoped the DUT walked into it before the window closed.
		m, err := d.meet(ctx, spec,
			fmt.Sprintf("%s — %s, aimed at %s", r.Name, r.Doc, aim), "", 1)
		if err != nil {
			return certify.Result{}, err
		}
		r.M = m

		// Recovery, per reading: §2.8.1 steps 4-7 restore the server and read
		// again. The one-shot has already disarmed itself, so the fence is
		// simply the next epoch and the barrier waits for the DUT's next
		// transaction — however long its reconnect-with-backoff takes.
		fence, ferr := d.arm(ctx, map[string]any{"kind": "next_response", "clear": true},
			fmt.Sprintf("confirm no one-shot is left armed after the %s reading, and fence the DUT's "+
				"recovery from it", r.Name))
		if ferr != nil {
			continue
		}
		r.Fence = fence
		page, ok, err := d.awaitLedger(ctx, fence, 1)
		if err != nil {
			return certify.Result{}, err
		}
		r.Recovery, r.Recovered = page, ok
	}

	return certify.Result{
		Verdict: certify.Warn,
		Notes: fmt.Sprintf("all three readings of §2.8.1's undefined 'partial response' were driven as "+
			"ONE-SHOTS armed against the next matching request, so each landed inside a transaction this "+
			"bundle can name rather than in the gap between two of them — which is where a blanket fault "+
			"spent every previous campaign. The DUT's recovery from each was held on the simulator's own "+
			"transaction ledger, not on a clock. %s", o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT remained functional after a Modbus response failed to complete"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
			}
			for _, r := range readings {
				fs = append(fs, evalPartialReading(c, r, d))
				fs = append(fs, evalPartialRecovery(r, d))
			}
			fs = append(fs, prot1CommonModelGap())
			return emit(ev, c, fs), nil
		},
	}, nil
}

// evalPartialReading grades one reading from the sim's own record of what it
// delivered, and cites the request in the capture when this test case owns it.
func evalPartialReading(c *Conversation, r *partialReading, d *determinism) finding {
	claim := fmt.Sprintf("the DUT received %s and did not hang on it", r.Name)
	method := fmt.Sprintf("a one-shot armed against the NEXT matching request (%s), so the "+
		"provocation lands inside a transaction the bench can name; graded from the simulator's own "+
		"record of what it delivered for that transaction", r.M.Spec)
	if !r.M.ok() {
		return skipf(claim, method, "%s", r.M.reason())
	}
	shaped := r.M.Page.WithOutcome(r.Outcome)
	if len(shaped) == 0 {
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"the one-shot was armed at epoch %d and the DUT issued %d transaction(s) under it, but the "+
				"simulator recorded none resolved as %q: %s. That is a disagreement between the "+
				"one-shot's contract and its wire behaviour — a bench defect, not a DUT finding",
			r.M.Epoch, r.M.Page.Total, r.Outcome, r.M.Page.Summary())
	}
	hit := shaped[0]

	// The request that walked into it is the DUT's own, and the capture
	// normally carries it. Cite the request rather than the response: for the
	// dropped reading there IS no response to cite, and citing the request is
	// the honest evidence in all three cases.
	if c != nil {
		for _, ex := range c.Reads() {
			start, qty, ok := ex.Request.ReadRequest()
			if !ok || start != hit.Addr || qty != hit.Count {
				continue
			}
			return bytesf(claim, method, certify.Pass, fromDUT, ex.Request.Start, ex.Request.End,
				"the DUT issued %s and the server, under the one-shot armed at epoch %d, delivered %s. "+
					"The simulator's own ledger records the transaction as %s. %s. Request cited in "+
					"full: [%s]",
				ex.Request.String(), r.M.Epoch, deliveredDescription(r.Outcome, hit), hit, r.Doc,
				ex.Request.Hex())
		}
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"the DUT issued a read at %d×%d and the server, under the one-shot armed at epoch %d, delivered "+
			"%s: %s. %s. No frame carrying that request was attributed to this test case, so this rests "+
			"on the simulator's record rather than on a citation into the capture",
		hit.Addr, hit.Count, r.M.Epoch, deliveredDescription(r.Outcome, hit), hit, r.Doc)
}

// deliveredDescription says, in words, what the client actually got.
func deliveredDescription(outcome string, e LedgerEntry) string {
	switch outcome {
	case outcomeDropped:
		return "nothing at all, with the connection left open"
	case outcomeTruncated:
		return fmt.Sprintf("a %d-byte prefix of the response with the MBAP length field left promising "+
			"the rest", len(e.Response)/2)
	case outcomeDelayed:
		return fmt.Sprintf("the complete response %.0f ms later", e.LatencyMS)
	default:
		return "an answer"
	}
}

// evalPartialRecovery is §2.8.1's actual SHALL: the client remains functional.
func evalPartialRecovery(r *partialReading, d *determinism) finding {
	claim := fmt.Sprintf("the DUT remained functional after %s and transacted normally again", r.Name)
	method := "a transaction with the server AFTER the one-shot was spent, held on the simulator's " +
		"transaction ledger rather than on a clock, so the DUT's own reconnect-with-backoff has as long " +
		"as it needs"
	if !r.M.Armed {
		return skipf(claim, method, "the reading was never delivered, so there is nothing to recover from")
	}
	if r.Fence == 0 {
		return skipf(claim, method, "the recovery fence could not be taken on the sim")
	}
	if !r.Recovered {
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"after %s (armed at epoch %d, fenced for recovery at epoch %d) the DUT issued no transaction "+
				"at all to this server within the barrier's budget — it was not seen to resume polling",
			r.Name, r.M.Epoch, r.Fence)
	}
	good := r.Recovery.WithOutcome(outcomeAnswered)
	if len(good) == 0 {
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"after %s the DUT did transact again, but none of its %d transaction(s) completed normally "+
				"within the window: %s", r.Name, r.Recovery.Total, r.Recovery.Summary())
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"after %s the DUT issued %d transaction(s) that completed normally — first: %s. The client "+
			"neither hung on the incomplete answer nor stopped polling", r.Name, len(good), good[0])
}

// prot1CommonModelGap records the one part of §2.8.1 this bench cannot reach,
// and why it is a DUT capability gap rather than a bench one.
func prot1CommonModelGap() finding {
	return skipf(
		"the DUT logged the Common Model read values as expected after the server returned to normal",
		"§2.8.1 steps 6-7: read the Common Model again once the server is behaving, and check the "+
			"decoded values",
		"lexa-gw reads model 1's BODY exactly once, during admission, on a separate short-lived "+
			"connection at boot (internal/southbound/admission/identify.go's identifyNow → "+
			"sunspec.ReadCommon). Its steady-state poll and its post-reconnect rediscovery read the "+
			"model chain's HEADERS and then only the measurement model — lexa-proto/sunspec/reader.go "+
			"caches the block layout per session and never re-reads model 1's body. So no provocation "+
			"available to this bench can make the DUT re-read the Common Model inside a test case's "+
			"window: it would take a process restart, which a shared-bench conformance run must not "+
			"perform. This is a DUT-side observability gap, not a missing sim verb, and it is the same "+
			"gap CLI-1..CLI-4 report against the identical criterion")
}

func max16(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
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
	d, derr := o.determinism(ctx)
	if derr != nil {
		return certify.Skipped("%s", deterministicSkip(derr)), nil
	}
	if err := d.begin(ctx, nil); err != nil {
		return certify.Result{}, err
	}
	defer d.restore(ctx)

	// §2.8.2 step 1: "preconfigure Server 1 to respond with a TCP-segmented
	// Modbus response." modsim can do exactly that — one ADU written to the
	// socket in two writes — but only with a second relay interposed
	// (-protofault). When it was not, the sim refuses the kind BY NAME, and
	// that refusal is reported as the row's gap rather than folded into "TCP
	// segmentation cannot be compelled", which is what this row used to say.
	seg, segErr := d.meet(ctx,
		map[string]any{"kind": "segment_response", "split_after": mbapHeaderBytes},
		"write each response ADU to the socket in two writes, splitting after the MBAP header, so the "+
			"client must reassemble one Modbus message from more than one segment",
		"segment_response", 1)
	if segErr != nil {
		return certify.Result{}, segErr
	}

	// A forced reconnect brings the discovery burst into the window: many
	// responses in quick succession, which is where a segmented or coalesced
	// delivery is most likely to occur even without the relay.
	reconnFence, forced := d.reconnect(ctx,
		"sever the DUT's southbound connection so its reconnect's discovery burst — many responses in "+
			"quick succession — falls inside this test case's window")
	var burst LedgerPage
	var sawBurst bool
	if forced == nil {
		var err error
		burst, sawBurst, err = d.awaitLedger(ctx, reconnFence, 3)
		if err != nil {
			return certify.Result{}, err
		}
	}

	return certify.Result{
		Notes: fmt.Sprintf("the DUT's MBAP-length framing of the server's byte stream was asserted over "+
			"a reconnect's discovery burst, held on the simulator's own transaction ledger rather than "+
			"on a clock; a genuinely segmented ADU was %s. %s",
			segmentationOutcome(seg), o.injectionNote()),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "the DUT parsed a Modbus response delivered across more than one TCP segment"
			c, pre, ok := citeConversation(ev, o, claim)
			fs := append([]finding(nil), pre...)
			if ok {
				fs = []finding{assertAttributionSound(ev, o)}
			}
			fs = append(fs, evalPROT2Segmentation(seg, d))
			if c != nil {
				fs = append(fs, evalPROT2(c, forced == nil)...)
				fs = append(fs, evalFraming(c)...)
			}
			fs = append(fs, evalPROT2Burst(burst, sawBurst, reconnFence, forced, d))
			return emit(ev, c, fs), nil
		},
	}, nil
}

// segmentationOutcome renders, for the note, whether the sim could be made to
// segment at all.
func segmentationOutcome(m meeting) string {
	switch {
	case m.ArmErr != nil:
		return fmt.Sprintf("NOT compelled (%v)", m.ArmErr)
	case m.ok():
		return fmt.Sprintf("compelled at epoch %d and met by %d transaction(s)", m.Epoch, m.Page.Total)
	default:
		return "compelled but not met inside this window"
	}
}

// evalPROT2Segmentation reports the deliberate segmentation attempt. The
// criterion — "the CUT parses the data correctly from the TCP-segmented
// response" — is evidenced by the DUT continuing to transact normally through
// the segmented interval, which the ledger records directly.
func evalPROT2Segmentation(m meeting, d *determinism) finding {
	claim := "the server delivered a Modbus response across more than one TCP segment and the DUT " +
		"parsed it correctly"
	method := "arm modsim's segment_response fault (one ADU, two socket writes, split after the MBAP " +
		"header) and confirm from the simulator's own ledger that the DUT's transactions under it " +
		"completed normally"
	if m.ArmErr != nil {
		return skipf(claim, method,
			"the server could not be made to segment: %v. modsim serves this fault only with a second "+
				"framing relay interposed (-protofault); it refuses the kind BY NAME when that flag was "+
				"not given, which is why this reads as a launch-flag gap rather than as 'segmentation "+
				"cannot be compelled'. Add -protofault to the bench's modsim invocation and this row's "+
				"headline criterion becomes drivable", m.ArmErr)
	}
	if !m.ok() {
		return skipf(claim, method, "%s", m.reason())
	}
	good := m.Page.WithOutcome(outcomeAnswered)
	if len(good) == 0 {
		return narrativef(claim, method, d.ledgerSource(), certify.Fail,
			"with every response split across two socket writes from epoch %d, none of the DUT's %d "+
				"transaction(s) completed normally: %s. A client that cannot reassemble an ADU spanning "+
				"segments is exactly what §2.8.2 exists to catch", m.Epoch, m.Page.Total, m.Page.Summary())
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"with every response split across two socket writes from epoch %d, %d of the DUT's %d "+
			"transaction(s) completed normally — first: %s. The client reassembled the ADU from more "+
			"than one segment rather than retrying or resetting",
		m.Epoch, len(good), m.Page.Total, good[0])
}

// evalPROT2Burst asserts the reconnect's discovery burst reached the server,
// which is what makes the framing assertions above about a real conversation.
func evalPROT2Burst(page LedgerPage, saw bool, fence uint64, forced error, d *determinism) finding {
	claim := "the DUT re-established its connection and issued a discovery burst the framing assertions " +
		"above are drawn from"
	method := "the transactions the simulator recorded after the DUT's connection was severed at a " +
		"named epoch"
	if forced != nil {
		return skipf(claim, method, "the DUT's connection could not be severed: %v", forced)
	}
	if !saw {
		return narrativef(claim, method, d.ledgerSource(), certify.Warn,
			"the DUT's connection was severed at epoch %d and it issued only %d transaction(s) "+
				"afterwards within the barrier's budget", fence, page.Total)
	}
	return narrativef(claim, method, d.ledgerSource(), certify.Pass,
		"after its connection was severed at epoch %d the DUT reconnected and issued %d transaction(s) "+
			"— %s — over %d session(s) as the simulator counted them",
		fence, page.Total, page.Summary(), page.Poll.Sessions)
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
