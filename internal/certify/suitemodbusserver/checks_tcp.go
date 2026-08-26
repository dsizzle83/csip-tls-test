package suitemodbusserver

// checks_tcp.go implements the two framing procedures of SunSpec Modbus
// Conformance Test Procedures v1.4 §2.7.7 and §2.7.8: TCP-2 Partial Request and
// TCP-3 Multiple TCP Packets.
//
// Both are catalogued "partial" automatable, with the extraction's reason being
// that the framing has to be manipulated INSIDE the TLS session and the stock
// bench client cannot do it. This suite can: it writes to the decrypted stream
// directly, so a deliberately short write becomes a short TLS record and two
// writes become two records. What the extraction was right about is that the
// evidence is harder — a split that a naive client makes at the socket can be
// coalesced by the kernel, or by the TLS layer, before it reaches the wire. So
// neither check takes its own intent as proof. Each one reads the capture back
// and asserts what the WIRE shows, and reports SKIP when the manipulation did
// not survive to the wire rather than claiming a property it did not
// demonstrate.
//
// # The two procedures differ only in a pause, so the pause is load-bearing
//
// On the wire, TCP-2 and TCP-3 send the SAME THING: part of an MBAP frame, a
// pause, more bytes, on one connection. What separates them is entirely the
// interval, because a Modbus/TCP server holds an incomplete frame for its own
// FRAME BUDGET while it waits for the rest — that is what TCP-3 requires it to
// do — and only afterwards may it treat what arrives next as a new request.
//
//	TCP-3   pause 20 ms      INSIDE any budget: the two writes are one request,
//	                         and reassembling them is the pass criterion.
//	TCP-2   pause budget+margin   PAST the budget: the second write is a new
//	                         request, and splicing it onto the first is the
//	                         failure.
//
// §2.7.7 and §2.7.8 both specify no timing at all, so the number cannot come
// from the documents. TCP-3's 20 ms is safe under every budget; TCP-2's comes
// from the candidate manifest's secure_sunspec.frame_budget_ms, which is the
// DUT's own declaration of its budget. See tcp2WaitFor for what happens when
// the candidate declares none — the answer differs between a campaign and an
// exploratory run, and it differs on purpose.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"csip-tls-test/internal/certify"
)

// checkTCP3 implements SS-MODBUS-CONF-v1.4 TCP-3, Multiple TCP Packets.
//
// Steps: send a Modbus request broken across two TCP frames; verify the
// successful response.
//
// The split is placed at byte 4 — inside the seven-byte MBAP header, between
// the protocol identifier and the length field. The document does not say where
// to split; splitting inside the header is the stricter case and the one most
// likely to break a server that assumes one read is one PDU.
func checkTCP3(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "TCP-3 request split across two segments")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	const splitAt = 4
	pdu, err := buildReadReq(fcReadHolding, ch.Base, 2)
	if err != nil {
		return certify.Result{}, err
	}

	before := len(s.client.log)
	resp, werr := s.client.writeSplit(pdu, splitAt, 20*time.Millisecond,
		"TCP-3: FC 3 request written as two segments split inside the MBAP header")
	tids := tidsSince(s.client, before)

	answered := werr == nil
	text := ""
	switch {
	case werr != nil:
		text = "the split request was not answered normally: " + errText(werr)
	default:
		regs, perr := parseReadResp(fcReadHolding, 2, resp)
		if perr != nil {
			answered = false
			text = "the response to the split request did not parse: " + perr.Error()
		} else {
			text = fmt.Sprintf("the DUT reassembled the two segments and answered FC 3 with 0x%04x 0x%04x",
				regs[0], regs[1])
		}
	}

	return certify.Result{
		Verdict: verdictIf(answered),
		Notes:   text,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"a Modbus request divided across two segments is reassembled and answered once, normally"), nil
			}
			out, err := transportPlus(c, verdictIf(answered))
			if err != nil {
				return nil, err
			}

			// The first claim is about the DUT: one normal response to the
			// split request, echoing its transaction id.
			var respText string
			respOK := false
			if len(tids) > 0 {
				if r, found := c.conv.responseTo(tids[len(tids)-1]); found {
					respOK = !r.IsException() && r.FC() == fcReadHolding
					respText = fmt.Sprintf("one response on the wire, pdu % x, transaction id 0x%04x", r.PDU, r.TID)
				} else {
					respText = "the capture holds no response echoing the split request's transaction id"
				}
			}
			a, err := c.frames(
				"a Modbus request divided across two segments is reassembled by the DUT into one request and "+
					"answered with a single normal response echoing its transaction identifier",
				"one FC 3 request written in two parts split inside the seven-byte MBAP header, with a pause "+
					"between them; the response is read back out of the capture",
				verdictIf(answered && respOK), respText, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The second claim is about the STIMULUS, and it is the one that
			// makes the first claim mean anything: unless the request really
			// did arrive in more than one piece, the DUT was never asked to
			// reassemble anything.
			claim := "the request genuinely arrived at the DUT in more than one piece, so the reassembly the " +
				"first claim rests on was actually exercised"
			method := "the request's byte range in the reconstructed application stream is mapped back to the " +
				"TLS records and capture frames that carried it"
			var reqOff, reqLen int
			for _, x := range s.client.log[before:] {
				if x.ReqLen > 0 {
					reqOff, reqLen = x.ReqOff, x.ReqLen
					break
				}
			}
			if reqLen == 0 {
				out = append(out, ev.SkipAssertion(claim, method, "the split request was never written"))
				return out, nil
			}
			records, frames := c.conv.Request.recordSpanFor(reqOff, reqOff+reqLen)
			pieces := len(frames)
			desc := fmt.Sprintf("the %d-byte request occupied %d capture frame(s)", reqLen, len(frames))
			if c.sess.Encrypted() {
				desc = fmt.Sprintf("the %d-byte request occupied %d TLS record(s) in %d capture frame(s)",
					reqLen, records, len(frames))
				pieces = records
			}
			if pieces < 2 {
				out = append(out, ev.SkipAssertion(claim, method,
					desc+" — the two writes were coalesced before they reached the wire, so the DUT was "+
						"handed one whole request and the reassembly this procedure tests was not exercised"))
				return out, nil
			}
			a, err = c.frames(claim, method, certify.Pass, desc, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			return out, nil
		},
	}, nil
}

// TCP2Margin is what checkTCP2 adds to the DUT's frame budget before sending
// the follow-up ADU.
//
// It is not politeness. The budget is when the DUT DECIDES; the margin is the
// slack between that decision and the harness observing it — a scheduler tick,
// a TLS record boundary, a loaded bench. A pause of exactly the budget races
// the very transition the procedure is trying to observe, and the race is
// SILENT: the losing side looks like a mis-parse.
const TCP2Margin = 500 * time.Millisecond

// TCP2FallbackBudget is the frame budget an EXPLORATORY run assumes when the
// candidate declared none. It is lexa-gw's own default and deployed value
// (configs/mbaps.json limits.frame_budget_ms = 2000, cmd/mbaps Config), which
// makes it a documented number rather than a guess — but it is still a number
// about a DIFFERENT device than whatever is on the other end of the socket, so
// a run that uses it says so loudly and a CAMPAIGN refuses to use it at all.
const TCP2FallbackBudget = 2000 * time.Millisecond

// tcp2Wait is how long checkTCP2 waits between the truncated frame and the
// follow-up ADU, and where that number came from.
type tcp2Wait struct {
	// Pause is the wait itself.
	Pause time.Duration
	// Source is the sentence the bundle records about it.
	Source string
	// Refuse, when non-empty, is why this row cannot be decided at all.
	Refuse string
}

// tcp2WaitFor decides the pause from the CANDIDATE'S OWN declaration.
//
// # Why this is not a constant
//
// It was one — 200 ms — and 200 ms is shorter than any deployed frame budget,
// which makes the stimulus this check sends BYTE-FOR-BYTE INDISTINGUISHABLE
// from TCP-3's:
//
//	TCP-3  write part of an ADU, pause 20 ms, write the rest   -> one request
//	TCP-2  write part of an ADU, pause 200 ms, write another   -> two requests
//
// Both are two writes on one connection inside one frame budget. A server that
// is still assembling the first frame — which is exactly what §2.7.7 gives it
// its budget to do, and exactly what TCP-3 REQUIRES it to do — splices the
// second write onto the first and answers under the first frame's transaction
// id. That is conformant behaviour for the interval it was measured in, and the
// old check recorded it as a defect.
//
// The procedure cannot settle this: §2.7.7 specifies no timing whatsoever, and
// its own note says only that the connection state after the partial request
// should be recorded. So the number has to come from the device, and the
// candidate manifest is where the device states it
// (secure_sunspec.frame_budget_ms; lexa-gw configs/mbaps.json
// limits.frame_budget_ms is the same value on the product side).
//
// # Absent, and the two different answers
//
// A CAMPAIGN refuses. Guessing a budget would publish the guess as a
// measurement, and the guess decides the verdict — the whole finding above.
// An EXPLORATORY run falls back to TCP2FallbackBudget with the fallback named
// in the notes, in the assertion, and in the run log, because an exploratory
// run's job is to tell you something and it is marked NOT GATING anyway.
func tcp2WaitFor(rc *certify.RunCtx) tcp2Wait {
	if m := rc.Manifest(); m != nil {
		if budget, ok := m.SecureSunSpec.FrameBudget(); ok {
			return tcp2Wait{
				Pause: budget + TCP2Margin,
				Source: fmt.Sprintf("%s after the truncated frame (the candidate's declared MBAP frame "+
					"budget %s, from %s secure_sunspec.frame_budget_ms, plus a %s margin), so the DUT's "+
					"budget has certainly expired before the follow-up is written and the follow-up "+
					"cannot be read as the continuation of the truncated frame",
					budget+TCP2Margin, budget, m.Path(), TCP2Margin),
			}
		}
	}
	if rc.Posture().InCampaign() {
		return tcp2Wait{Refuse: fmt.Sprintf(
			"this row cannot be decided without the DUT's MBAP FRAME BUDGET, and the candidate manifest "+
				"declares none (secure_sunspec.frame_budget_ms). SS-MODBUS-CONF v1.4 §2.7.7 specifies no "+
				"timing, so the pause between the truncated frame and the follow-up is the whole "+
				"experiment: shorter than the budget, the follow-up is indistinguishable from TCP-3's "+
				"required segment reassembly and a CONFORMANT server is recorded as mis-parsing. A "+
				"campaign will not guess it — add \"frame_budget_ms\" to the manifest's secure_sunspec "+
				"object (lexa-gw configs/mbaps.json limits.frame_budget_ms is the value; the deployed "+
				"default is %d)", int(TCP2FallbackBudget/time.Millisecond))}
	}
	return tcp2Wait{
		Pause: TCP2FallbackBudget + TCP2Margin,
		Source: fmt.Sprintf("%s after the truncated frame — the candidate manifest declares no "+
			"secure_sunspec.frame_budget_ms, so this EXPLORATORY run assumed the product default of %s "+
			"and added a %s margin. THAT ASSUMPTION IS ABOUT A DIFFERENT DEVICE than the one measured "+
			"here: a DUT whose budget exceeds it would still have been mid-frame when the follow-up "+
			"arrived, and would be recorded as mis-parsing something it was conformantly reassembling. A "+
			"campaign refuses to run this row without the declaration",
			TCP2FallbackBudget+TCP2Margin, TCP2FallbackBudget, TCP2Margin),
	}
}

// checkTCP2 implements SS-MODBUS-CONF-v1.4 TCP-2, Partial Request.
//
// Steps: send an incomplete partial Modbus request; send a different complete
// Modbus request; verify the successful response to the second one.
//
// # The timing, which the document does not give
//
// See tcp2WaitFor. The pause between the two writes is the experiment, and it
// comes from the candidate's declared frame budget rather than from a constant
// in this file.
//
// # The three outcomes, and why two of them are a PASS
//
// §2.7.7's pass criteria are that the device RECOVERS from the incomplete
// request — it does not hang and does not mis-parse the following one — and
// that the following complete request receives a successful response. The
// document is silent on whether the second request may go on the same
// connection and on whether the DUT may close the connection after the partial
// one, and the catalog's own note says the connection-close behaviour is to be
// recorded as an OBSERVATION rather than as a failure.
//
//	the follow-up answered on the SAME connection, echoing its own
//	transaction id                                                     PASS
//	    the server discarded the partial frame and resynchronised. Also
//	    conformant to the literal text, and the stricter reading — it is
//	    what a device with no frame budget at all would have to do.
//
//	the DUT closed the connection at its frame budget, and a complete
//	request on a FRESH connection was answered normally                PASS
//	    with the close recorded as the observation §2.7.7 asks for. This is
//	    the shape a device with a frame budget takes, and the shape lexa-gw
//	    takes. Grading it WARN — as this check did — published a device
//	    doing exactly what the procedure permits as a partial result.
//
//	a response under the TRUNCATED frame's transaction id              FAIL
//	    the DUT spliced the follow-up onto the partial frame: it MIS-PARSED
//	    the following request, which is the failure §2.7.7 names. After a
//	    pause longer than the DUT's own budget this can no longer be
//	    confused with TCP-3's reassembly.
//
// No answer on either connection is a FAIL for the plain reason: the following
// complete request received no successful response.
func checkTCP2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	// FIRST, before a socket is opened: a row that cannot be decided must not
	// spend a connection, and its refusal must not be confusable with a bench
	// that was merely unreachable.
	wait := tcp2WaitFor(rc)
	if wait.Refuse != "" {
		return certify.Failed("%s", wait.Refuse), nil
	}

	s, res, err := open(ctx, rc, "TCP-2 partial request")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	// A five-byte read PDU sent as an MBAP header plus one PDU byte: the header
	// promises six bytes of unit + PDU and only two arrive.
	partial, err := buildReadReq(fcReadHolding, ch.Base, 2)
	if err != nil {
		return certify.Result{}, err
	}
	follow, err := buildReadReq(fcReadHolding, ch.Base, 1)
	if err != nil {
		return certify.Result{}, err
	}

	before := len(s.client.log)
	truncTID, terr := s.client.writeTruncated(partial, 8, "TCP-2 step 1: deliberately truncated request")
	if terr != nil {
		return certify.Result{}, fmt.Errorf("write the truncated request: %w", terr)
	}
	rc.Logf("TCP-2: pausing %s before the follow-up — %s", wait.Pause, wait.Source)
	if err := rc.Sleep(ctx, wait.Pause); err != nil {
		return certify.Result{}, err
	}

	// Three distinguishable same-connection outcomes, kept apart because they
	// are different findings about different criteria: the follow-up answered
	// correctly; a response under the TRUNCATED frame's id (the splice §2.7.7
	// names); and a response under some third id (the response stream no longer
	// aligned with the requests). Only the second is evidence against the
	// no-stale-response criterion; all three decide the recovery criterion.
	sameConnOK, staleTID, misframed := false, false, false
	var sameConnText string
	followTID, adu, ferr := s.client.doTolerant(follow, "TCP-2 step 2: complete request on the same connection")
	switch {
	case ferr == nil && adu.TID == followTID && len(adu.PDU) > 0 && adu.PDU[0] == fcReadHolding:
		sameConnOK = true
		sameConnText = fmt.Sprintf("the DUT discarded the partial frame and answered the follow-up request "+
			"on the same connection: pdu % x, transaction id 0x%04x", adu.PDU, adu.TID)
	case ferr == nil && adu.TID == truncTID:
		staleTID = true
		sameConnText = fmt.Sprintf("the DUT answered under the TRUNCATED frame's transaction id 0x%04x "+
			"(pdu % x), not the follow-up's 0x%04x: %s after the truncated frame it was still assembling "+
			"it, and the follow-up's bytes were consumed as its missing tail. That is the following "+
			"request MIS-PARSED, which §2.7.7 names as the failure",
			adu.TID, adu.PDU, followTID, wait.Pause)
	case ferr == nil:
		misframed = true
		sameConnText = fmt.Sprintf("the DUT answered with pdu % x under transaction id 0x%04x, which is "+
			"neither the follow-up's 0x%04x nor the truncated frame's 0x%04x — the response stream is no "+
			"longer aligned with the request that produced it",
			adu.PDU, adu.TID, followTID, truncTID)
	case errors.Is(ferr, io.EOF):
		sameConnText = "the DUT closed the connection after the truncated request; no response to the follow-up"
	default:
		sameConnText = "no usable response on the same connection: " + errText(ferr)
	}
	sameTIDs := tidsSince(s.client, before)

	// Recovery on a fresh connection. Not attempted after the DUT has ALREADY
	// ANSWERED, wrongly — a stale-id or misframed response settles the
	// criterion, and opening a second connection there would only put a
	// successful exchange beside a failure and invite it to be read as
	// recovery.
	var s2 *session
	newConnOK := false
	var newConnText string
	var newTIDs []uint16
	if !sameConnOK && !staleTID && !misframed {
		s2, err = openSession(ctx, rc, "TCP-2 recovery connection")
		if err != nil {
			newConnText = "a fresh connection could not be established after the truncated request: " + err.Error()
		} else {
			defer s2.Close()
			b2 := len(s2.client.log)
			regs, rerr := s2.client.readHolding(ch.Base, 2, "TCP-2 step 3: complete request on a new connection")
			newTIDs = tidsSince(s2.client, b2)
			if rerr != nil {
				newConnText = "the DUT did not answer a complete request on a fresh connection either: " + errText(rerr)
			} else {
				newConnOK = true
				newConnText = fmt.Sprintf("a complete request on a fresh connection was answered normally: "+
					"0x%04x 0x%04x", regs[0], regs[1])
			}
		}
	}

	// The connection-state observation §2.7.7's own note asks for, carried on
	// the criterion rather than asserted separately: it is not a pass/fail
	// property, and giving it a verdict of its own would put a number in the
	// tally for something the document declines to judge.
	const observation = "SS-MODBUS-CONF v1.4 §2.7.7 does not state whether the second request may be sent " +
		"on the same connection, whether the DUT may close the connection after a partial request, or how " +
		"long the harness should wait — the catalog's own note directs that the connection-close behaviour " +
		"be recorded as an OBSERVATION rather than as a failure, and it is recorded here as one"

	recovered := sameConnOK || newConnOK
	verdict := verdictIf(recovered)
	notes := sameConnText
	switch {
	case sameConnOK, staleTID, misframed:
		// sameConnText already says what happened, on its own connection.
	case newConnOK:
		notes = sameConnText + "; " + newConnText
	default:
		if newConnText != "" {
			notes += "; " + newConnText
		}
	}
	notes = joinNote(notes, "waited "+wait.Pause.String()+" between the two writes")

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			// skipTruncated: the request direction of this session is, by
			// design, no longer MBAP-aligned. The response direction still is,
			// and that is what the criterion is about.
			c, reason := newCiter(ev, s, true)
			if c == nil {
				return skipAll(ev, reason,
					"an incomplete request is followed by a complete one that receives a successful response"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}

			// The stimulus: prove the truncated frame really was truncated on
			// the wire, by mapping its byte range and showing the MBAP length
			// field promised more than arrived.
			var truncOff, truncLen int
			for _, x := range s.client.log[before:] {
				if x.TID == truncTID {
					truncOff, truncLen = x.ReqOff, x.ReqLen
					break
				}
			}
			stimClaim := "an incomplete Modbus request really was sent: a complete MBAP header whose length " +
				"field promises more bytes than were written"
			stimMethod := "the truncated frame's byte range in the reconstructed request stream, compared " +
				"against the MBAP length field inside it"
			if truncLen == 0 || c.conv.Request == nil || truncOff+truncLen > c.conv.Request.Len() {
				out = append(out, ev.SkipAssertion(stimClaim, stimMethod,
					"the truncated frame is not present in the reconstructed request stream"))
			} else {
				raw := c.conv.Request.Data[truncOff : truncOff+truncLen]
				promised := int(raw[4])<<8 | int(raw[5])
				arrived := truncLen - 6
				// The truncated frame is not a complete ADU, so the
				// transaction-keyed citation cannot find it; its frames are
				// cited directly from the byte range instead.
				fs := c.conv.Request.framesFor(truncOff, truncOff+truncLen)
				observed := fmt.Sprintf("% x — the MBAP length field promises %d bytes after it and only %d "+
					"were written", raw, promised, arrived)
				if len(fs) == 0 {
					out = append(out, ev.SkipAssertion(stimClaim, stimMethod,
						"the capture holds no frames for the truncated frame's byte range"))
				} else {
					a, err := ev.CiteFrames(stimClaim, stimMethod, verdictIf(promised > arrived), observed, fs)
					if err != nil {
						return nil, err
					}
					a.Note = joinNote(a.Note, wait.Source)
					out = append(out, a)
				}
			}

			// The catalog's FIRST observable, and its own criterion: no response
			// for the truncated frame's transaction id. This is the assertion
			// that separates a device which recovered from one which spliced the
			// follow-up onto the partial frame, and it is stated separately so a
			// reader sees WHICH of the two failed. A MISFRAMED response — under
			// neither id — is not evidence against this claim and is graded on
			// the recovery criterion below, where it belongs.
			staleClaim := "no Modbus response was returned under the truncated frame's transaction " +
				"identifier: the DUT did not mis-parse the following request as that frame's missing tail"
			staleMethod := fmt.Sprintf("the transaction identifier of the response read back after the "+
				"follow-up request, compared against the truncated frame's 0x%04x", truncTID)
			staleObserved := fmt.Sprintf("no response arrived under 0x%04x", truncTID)
			if staleTID {
				staleObserved = sameConnText
			}
			a, err := c.frames(staleClaim, staleMethod, verdictIf(!staleTID), staleObserved, sameTIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The criterion, and the one every outcome lands on.
			claim := "after an incomplete request the DUT recovers, and a following complete, well-formed " +
				"request receives a successful response"
			method := "a complete FC 3 request issued after the truncated one — on the same connection " +
				"first, and on a fresh connection when the DUT closed that one — with its response read " +
				"back out of the capture and matched by transaction identifier"
			switch {
			case sameConnOK:
				a, err := c.frames(claim, method, certify.Pass, sameConnText, sameTIDs)
				if err != nil {
					return nil, err
				}
				a.Note = joinNote(a.Note, observation)
				out = append(out, a)
			case newConnOK:
				// The recovery happened on a SECOND connection, whose frames
				// are attributed to this same test case but belong to a
				// different conversation. Citing them needs its own citer over
				// that session, or the citation would silently be scoped to the
				// wrong stream — so the criterion is cited THERE, where the
				// successful exchange actually is, and the closed connection is
				// the observation carried beside it.
				recoveryMethod := "FC 3 request on a second session established after the truncated frame; " +
					"its own conversation is reconstructed from the capture and cited separately"
				c2, reason2 := newCiter(ev, s2, false)
				if c2 == nil {
					out = append(out, ev.SkipAssertion(claim, recoveryMethod,
						newConnText+" — but the capture does not corroborate it: "+reason2))
					break
				}
				a2, err := c2.frames(claim, recoveryMethod, certify.Pass,
					joinNote(sameConnText, newConnText), newTIDs)
				if err != nil {
					return nil, err
				}
				a2.Note = joinNote(a2.Note, observation)
				out = append(out, a2)
			default:
				a, err := c.frames(claim, method, verdictIf(recovered), notes, sameTIDs)
				if err != nil {
					return nil, err
				}
				a.Note = joinNote(a.Note, observation)
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}
