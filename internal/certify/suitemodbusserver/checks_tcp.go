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

// checkTCP2 implements SS-MODBUS-CONF-v1.4 TCP-2, Partial Request.
//
// Steps: send an incomplete partial Modbus request; send a different complete
// Modbus request; verify the successful response to the second one.
//
// The document is silent on two things that decide how this reads, and the
// catalog's extraction flags both: it does not say whether the second request
// may go on the same connection, and it does not say whether the DUT may close
// the connection after the partial one. This check therefore tries the
// same-connection case first — the strict reading — and, if that fails, opens a
// second connection and tries again. Same-connection recovery is a PASS;
// recovery only after a reconnect is a WARN with the connection-close behaviour
// recorded as an observation rather than a failure; no recovery at all is a
// FAIL.
func checkTCP2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
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
	// Give the DUT a moment to react to the partial frame before the follow-up,
	// so a server that resets on a malformed request has done so by now.
	if err := rc.Sleep(ctx, 200*time.Millisecond); err != nil {
		return certify.Result{}, err
	}

	sameConnOK := false
	var sameConnText string
	followTID, adu, ferr := s.client.doTolerant(follow, "TCP-2 step 2: complete request on the same connection")
	switch {
	case ferr == nil && adu.TID == followTID && len(adu.PDU) > 0 && adu.PDU[0] == fcReadHolding:
		sameConnOK = true
		sameConnText = fmt.Sprintf("the DUT answered the follow-up request on the same connection: pdu % x, "+
			"transaction id 0x%04x", adu.PDU, adu.TID)
	case ferr == nil:
		sameConnText = fmt.Sprintf("the DUT answered on the same connection but with pdu % x under transaction "+
			"id 0x%04x, not the follow-up's 0x%04x — the truncated frame's promised bytes were consumed from "+
			"the follow-up request", adu.PDU, adu.TID, followTID)
	case errors.Is(ferr, io.EOF):
		sameConnText = "the DUT closed the connection after the truncated request; no response to the follow-up"
	default:
		sameConnText = "no usable response on the same connection: " + errText(ferr)
	}
	sameTIDs := tidsSince(s.client, before)

	// Recovery on a fresh connection, when the same-connection attempt failed.
	var s2 *session
	newConnOK := false
	var newConnText string
	var newTIDs []uint16
	if !sameConnOK {
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

	verdict := certify.Fail
	notes := sameConnText
	switch {
	case sameConnOK:
		verdict = certify.Pass
	case newConnOK:
		verdict = certify.Warn
		notes = sameConnText + "; " + newConnText
	default:
		notes = sameConnText
		if newConnText != "" {
			notes += "; " + newConnText
		}
	}

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
					out = append(out, a)
				}
			}

			// The criterion.
			claim := "after an incomplete request the DUT recovers, and a following complete, well-formed " +
				"request receives a successful response"
			method := "a complete FC 3 request issued on the same connection after the truncated one; its " +
				"response is read back out of the capture and matched by transaction identifier"
			switch {
			case sameConnOK:
				a, err := c.frames(claim, method, certify.Pass, sameConnText, sameTIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			case newConnOK:
				a, err := c.frames(claim, method, certify.Warn, sameConnText, sameTIDs)
				if err != nil {
					return nil, err
				}
				a.Note = joinNote(a.Note, "the procedure does not state whether the second request may be sent "+
					"on the same connection, nor whether the DUT may close the connection after a partial "+
					"request; recovery was demonstrated on a fresh connection and the connection-close "+
					"behaviour is recorded as an observation rather than a failure")
				out = append(out, a)
				// The recovery itself happened on a SECOND connection, whose
				// frames are attributed to this same test case but belong to a
				// different conversation. Citing them needs its own citer over
				// that session, or the citation would silently be scoped to the
				// wrong stream.
				recoveryClaim := "the DUT answers a complete, well-formed request on a connection opened " +
					"after the partial one"
				recoveryMethod := "FC 3 request on a second session established after the truncated frame; " +
					"its own conversation is reconstructed from the capture and cited separately"
				if s2 == nil {
					out = append(out, ev.SkipAssertion(recoveryClaim, recoveryMethod, newConnText))
					break
				}
				c2, reason2 := newCiter(ev, s2, false)
				if c2 == nil {
					out = append(out, ev.SkipAssertion(recoveryClaim, recoveryMethod,
						newConnText+" — but the capture does not corroborate it: "+reason2))
					break
				}
				a2, err := c2.frames(recoveryClaim, recoveryMethod, certify.Pass, newConnText, newTIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a2)
			default:
				a, err := c.frames(claim, method, certify.Fail, notes, sameTIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}
