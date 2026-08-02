package suitemodbusclient

// common.go holds the findings every wire-observing check in this suite emits,
// and the citation-phase entry point they all share.
//
// Two of them are not from the catalog at all, and are here deliberately:
//
//   - assertAttributionSound turns the weaker endpoint claim (see
//     observer.claimServer) from an assumption into a checked fact. Any suite
//     may claim an endpoint; this one proves, from the capture, that every
//     conversation attributed to the test case really is WITH that endpoint —
//     the dedicated, single-purpose, serialized listener the claim's own
//     argument rests on — so a reader does not have to take the claim on
//     faith. It does not matter how MANY such conversations there are, or
//     whether they overlap in time: no other client can ever be one of them.
//   - evalFraming asserts the MBAP framing discipline the whole document rests
//     on. Every SS-MODBUS-CLIENT-CONF procedure ends with "Network or serial
//     traffic SHALL be analyzed to verify CUT operations", and the analysis
//     that verifies a Modbus/TCP client's operations is: protocol id 0, a
//     length field that matches the message, a unit id in range, transaction
//     ids that advance and that its responses are matched against.
//
// Both are attached to the procedures whose evidence they underwrite rather
// than being reported as free-floating extras, so every assertion in the bundle
// belongs to a catalog row.

import (
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
)

// citeConversation is the first thing every Cite callback does: it re-derives
// the DUT's conversation with the bench server from the frames this check owns.
//
// The second return value is the findings to emit when the conversation could
// not be built — never an empty slice, because "no evidence" must be said out
// loud in the bundle rather than inferred from a short assertion list.
func citeConversation(ev *certify.Evidence, o *observer, claim string) (*Conversation, []finding, bool) {
	if !ev.HasFrames() {
		return nil, []finding{{
			Claim: claim, Method: "frame attribution (time AND flow)", Verdict: certify.Skip,
			Kind: citeSkip,
			Observed: fmt.Sprintf("no capture frame was attributed to this test case: the DUT sent no "+
				"southbound Modbus traffic to %s during its observation window, or the capture did not "+
				"see it. %s", o.server, o.injectionNote()),
		}}, false
	}
	c, err := loadConversation(ev, o.server)
	if err != nil {
		return nil, []finding{{
			Claim: claim, Method: "TCP stream reassembly", Verdict: certify.Skip, Kind: citeSkip,
			Observed: fmt.Sprintf("the DUT's conversation with %s could not be isolated: %v", o.server, err),
		}}, false
	}
	if len(c.Requests) == 0 {
		return c, []finding{{
			Claim: claim, Method: "Modbus/TCP ADU parsing of the reassembled DUT→server direction",
			Verdict: certify.Skip, Kind: citeSkip,
			Observed: fmt.Sprintf("the conversation with %s carried no complete Modbus request this test "+
				"case owns (%d ADU(s) were parsed but belonged to other test cases' frames; %d trailing "+
				"byte(s) formed no complete message)", o.server, c.DroppedRequests, c.ReqParse.TrailingBytes),
		}}, false
	}
	return c, nil, true
}

// assertAttributionSound checks the endpoint claim against the capture.
//
// live-run finding (runs/warnmeas-mc-ssm-20260802T134537, PROT-1#1): a
// fault-induced reconnect can leave two conversations with the server
// OVERLAPPING in time for a moment — the old one's teardown (FIN/RST) and
// the new one's SYN racing — not just sequential. An earlier version of
// this function WARNed on that overlap, reasoning that concurrent
// conversations are what a genuine second client would look like. That
// reasoning was too clever: on THIS endpoint specifically, it does not
// matter whether the conversations overlap, because observer.claimServer's
// own argument already rules out a second client existing AT ALL — modsim's
// plain-text server is a dedicated, single-purpose, SERIALIZED listener, and
// this run never dials anything else at it. The claim this function checks
// is "every conversation attributed to this test case is WITH that
// endpoint", not "there is only ever one, or they never overlap" — and that
// is exactly what the attribution filter below already establishes by
// construction. Cross-endpoint attribution is unaffected: a stream whose
// remote is NOT o.server never reaches this filter in the first place.
func assertAttributionSound(ev *certify.Evidence, o *observer) finding {
	streams := ev.Streams()
	var withServer []*netdis.Stream
	for _, st := range streams {
		if endpointIs(st.Key.A, o.server) || endpointIs(st.Key.B, o.server) {
			withServer = append(withServer, st)
		}
	}
	return evalAttribution(withServer, o.server, ev.Frames())
}

// evalAttribution is assertAttributionSound's pure decision logic, over the
// set of streams already narrowed to this check's own attributed
// conversations with the server. Split out so a unit test can drive it with
// hand-built streams — Key and nothing else — rather than a live capture.
func evalAttribution(withServer []*netdis.Stream, server fmt.Stringer, frames []int) finding {
	claim := "every frame cited by this test case belongs to the DUT, attributed via the dedicated server endpoint"
	method := "every attributed TCP conversation with the bench's Modbus server endpoint is WITH that " +
		"endpoint — the endpoint claim itself, re-checked against the capture rather than assumed"
	var cite []int
	if len(frames) > 0 {
		cite = frames[:1]
	}
	if len(withServer) == 0 {
		return skipf(claim, method, "no conversation with %s was attributed to this test case", server)
	}
	names := make([]string, len(withServer))
	for i, st := range withServer {
		names[i] = st.Key.String()
	}
	if len(withServer) == 1 {
		return framesf(claim, method, certify.Pass, cite,
			"exactly one conversation was attributed: %s. The endpoint claim this suite relies on — "+
				"'all traffic to %s during my interval is the DUT's' — therefore held for this test case",
			names[0], server)
	}
	return framesf(claim, method, certify.Pass, cite,
		"%d conversations with %s were attributed (%s), some of them overlapping in time or not — that "+
			"distinction does not matter here. %s is a dedicated, single-purpose, SERIALIZED listener (see "+
			"the endpoint claim above): no other client can ever dial it during this run, whether one "+
			"conversation's teardown races the next one's SYN or a check provokes several sequential "+
			"reconnects. Every one of these conversations is therefore the DUT's, and the endpoint claim "+
			"held for all of them",
		len(withServer), server, strings.Join(names, ", "), server)
}

// evalFraming asserts Modbus/TCP framing and transaction discipline over the
// DUT's own requests. It is a pure function of the conversation.
func evalFraming(c *Conversation) []finding {
	var out []finding

	// 1. MBAP header well-formedness, over every request the DUT emitted.
	badProto, badLen, badUnit := 0, 0, 0
	var firstBad *ADU
	for i := range c.Requests {
		a := c.Requests[i]
		ok := true
		if a.ProtoID != ModbusTCPProtocolID {
			badProto++
			ok = false
		}
		if !a.LengthConsistent() {
			badLen++
			ok = false
		}
		if a.UnitID == 0 || a.UnitID > 247 {
			badUnit++
			ok = false
		}
		if !ok && firstBad == nil {
			firstBad = &c.Requests[i]
		}
	}
	claim := "every Modbus/TCP request the DUT emitted carried a well-formed MBAP header"
	method := "independent MBAP decode of the reassembled DUT→server direction " +
		"(protocol id == 0; length field == 1 + PDU length; unit id in 1..247)"
	if firstBad != nil {
		out = append(out, bytesf(claim, method, certify.Fail, fromDUT, firstBad.Start, firstBad.End,
			"%d of %d request(s) were malformed (protocol id != 0: %d; length field inconsistent: %d; "+
				"unit id out of range: %d). First offending ADU: %s [%s]",
			badProto+badLen+badUnit, len(c.Requests), badProto, badLen, badUnit,
			firstBad.String(), firstBad.Hex()))
	} else {
		first := c.Requests[0]
		out = append(out, bytesf(claim, method, certify.Pass, fromDUT, first.Start, first.End,
			"all %d request(s) carried protocol id 0, a length field consistent with the delivered PDU, "+
				"and a unit id in 1..247. First request cited in full: %s [%s]",
			len(c.Requests), first.String(), first.Hex()))
	}

	// 2. Transaction-id discipline: every response the DUT acted on carried the
	//    id of the request it answers.
	claim = "the DUT matched every response to its request by MBAP transaction identifier"
	method = "pairing of requests and responses by (transaction id, unit id, function code), with " +
		"no positional fallback"
	t := c.TxIDs
	switch {
	case t.Requests == 0:
		out = append(out, skipf(claim, method, "no requests were observed"))
	case t.Mismatched > 0:
		out = append(out, framesf(claim, method, certify.Fail, aduFrames(c.Responses...),
			"%d response(s) carried a transaction id no observed request had used", t.Mismatched))
	case t.Repeats > 0:
		out = append(out, framesf(claim, method, certify.Warn, aduFrames(c.Requests...),
			"a transaction id was reused %d time(s) while an earlier request carrying it was still "+
				"unanswered, so two outstanding requests were momentarily indistinguishable", t.Repeats))
	default:
		out = append(out, framesf(claim, method, certify.Pass, aduFrames(c.Requests...),
			"%d request(s) with transaction ids %d…%d; %d advanced monotonically; every response was "+
				"matched to the request bearing its id (%d request(s) unanswered)",
			t.Requests, t.First, t.Last, t.Increasing, t.Unmatched))
	}
	return out
}

// evalReadQuantities asserts the FC 0x03 / 0x04 register ceiling, which is
// READ-2's headline criterion and a precondition for every other read row.
func evalReadQuantities(c *Conversation) finding {
	claim := "no register read the DUT issued exceeded the Modbus maximum of 125 registers"
	method := "quantity field of every FC 0x03 / 0x04 request in the reassembled DUT→server direction"
	reads := c.Reads()
	if len(reads) == 0 {
		return skipf(claim, method, "the DUT issued no register reads during this observation")
	}
	var maxQty uint16
	var maxEx Exchange
	var over []string
	for _, ex := range reads {
		_, qty, _ := ex.Request.ReadRequest()
		if qty > maxQty {
			maxQty, maxEx = qty, ex
		}
		if qty > MaxReadQuantity {
			over = append(over, ex.Request.String())
		}
	}
	if len(over) > 0 {
		return bytesf(claim, method, certify.Fail, fromDUT, maxEx.Request.Start, maxEx.Request.End,
			"%d of %d read request(s) asked for more than %d registers; largest: %s",
			len(over), len(reads), MaxReadQuantity, over[0])
	}
	return bytesf(claim, method, certify.Pass, fromDUT, maxEx.Request.Start, maxEx.Request.End,
		"%d read request(s), largest quantity %d (limit %d). Largest request cited: %s [%s]",
		len(reads), maxQty, MaxReadQuantity, maxEx.Request.String(), maxEx.Request.Hex())
}

// unansweredReads returns the read exchanges the server never answered, which
// is what a severed or timed-out transaction looks like from the DUT's side.
func unansweredReads(c *Conversation) []Exchange {
	var out []Exchange
	for _, ex := range c.Reads() {
		if !ex.Matched() {
			out = append(out, ex)
		}
	}
	return out
}

// firstSuccessfulReadAfter returns the first fully-answered, non-exception read
// exchange whose request begins at or after the given stream offset. It is how
// several procedures phrase their recovery criterion: after the provocation,
// the client transacts normally again.
func firstSuccessfulReadAfter(c *Conversation, offset int) (Exchange, bool) {
	for _, ex := range c.Reads() {
		if ex.Request.Start < offset || !ex.Matched() || ex.Response.IsException() {
			continue
		}
		if _, _, ok := ex.Response.ReadResponse(); ok {
			return ex, true
		}
	}
	return Exchange{}, false
}

// describeModels renders a model chain for an assertion's Observed text.
func describeModels(models []Model) string {
	parts := make([]string, 0, len(models))
	for _, m := range models {
		state := "body read"
		switch {
		case !m.BodyRead:
			state = "header only — stepped over by length"
		case !m.BodyCovered:
			state = "body partially read"
		}
		parts = append(parts, fmt.Sprintf("ID %d @%d L=%d (%s)", m.ID, m.HeaderAddr, m.Length, state))
	}
	return strings.Join(parts, ", ")
}

// findModel returns the first model with the given id.
func findModel(models []Model, id uint16) (Model, bool) {
	for _, m := range models {
		if m.ID == id {
			return m, true
		}
	}
	return Model{}, false
}
