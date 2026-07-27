package mbapref

// pair.go is the response-direction differential.
//
// Compare cannot do the response direction, and the reason is not an oversight
// in either implementation: a Modbus response is not self-describing. The five
// bytes `03 02 00 7B` are a well-formed read response carrying one register —
// and also, if the request asked for forty, a catastrophically wrong one. The
// product is right to make ParseReadResp take the request; this reader is
// right to check standalone consistency when framing a capture, where the
// request has not been paired yet. DIV-RESPSHAPE records exactly that.
//
// So the response direction gets its own comparison, run once both sides have
// the same request in hand. That is what this file does, and it is where the
// most consequential class of Modbus bug lives: a response accepted against
// the wrong request is a register window read at the wrong offset, and every
// value decoded out of it is some other point's value wearing the right name.
// Nothing downstream catches that. The scale factor still applies, the units
// still look right, the number is plausible, and the gateway reports it.
//
// # Pairing is by transaction id AND order, and refuses when they disagree
//
// MBAP's transaction identifier exists to let a client have several requests
// outstanding. The gateway's own client is single-outstanding (lexa-proto's
// mbap.Client documents that), so on this bench request and response alternate
// and the TIDs match pairwise. Pairing therefore checks BOTH — order and TID —
// and reports a Pairing fault rather than guessing when they disagree, because
// a stream where they disagree is either a device that reuses transaction ids
// or a capture with a gap, and silently repairing either one manufactures
// pairs that were never on the wire.

import (
	"errors"
	"fmt"
)

// Exchange is one request and the response that answered it.
type Exchange struct {
	Req  Frame
	Resp Frame
}

// PairFault is a stream that could not be paired.
type PairFault struct {
	// Index is the position in the request sequence at which pairing failed.
	Index  int
	Reason string
}

func (p *PairFault) Error() string {
	return fmt.Sprintf("mbapref: cannot pair at exchange %d: %s", p.Index, p.Reason)
}

// Pair matches a client-direction byte stream against a server-direction one.
//
// It returns the exchanges it could form and a fault if it stopped early. A
// trailing unanswered request is NOT a fault: a capture that ends between a
// request and its response is ordinary, and treating it as a protocol error
// would report a finding on the tail of every stream on the bench.
func Pair(clientBytes, serverBytes []byte) ([]Exchange, *PairFault) {
	reqs, _ := FrameStream(clientBytes)
	resps, _ := FrameStream(serverBytes)

	var out []Exchange
	for i, req := range reqs {
		if i >= len(resps) {
			break // unanswered tail, see above
		}
		resp := resps[i]
		if resp.TID != req.TID {
			return out, &PairFault{
				Index: i,
				Reason: fmt.Sprintf("request tid %d answered by tid %d — the stream is not strictly alternating, "+
					"so positional pairing would invent an exchange", req.TID, resp.TID),
			}
		}
		if resp.Unit != req.Unit {
			return out, &PairFault{
				Index:  i,
				Reason: fmt.Sprintf("request unit %d answered by unit %d", req.Unit, resp.Unit),
			}
		}
		out = append(out, Exchange{Req: req, Resp: resp})
	}
	return out, nil
}

// CompareExchange answers the response-direction question for one exchange:
// given the same request, do both readers accept the same responses, and read
// the same registers out of them?
//
// The finding that matters most here is the one in the ACCEPTANCE direction
// with the product on the permissive side — the product accepting a response
// the reference refuses means the gateway acted on register values it should
// have discarded. There is no enumerated divergence that way and there is not
// meant to be one.
func CompareExchange(sub Subject, ex Exchange) []Finding {
	name := sub.Name()
	refReq := DecodePDU(ex.Req.PDU, FromClient)
	refResp := DecodePDU(ex.Resp.PDU, FromServer)

	// An exception response is an answer, not a failure, and both readers must
	// agree it is one. Disagreement here would mean one side treated a refusal
	// as data.
	if refResp.Kind == KindException {
		if len(ex.Resp.PDU) == 2 && ex.Resp.PDU[0] == (ex.Req.PDU[0]|ExceptionBit) {
			return nil
		}
		// A traffic finding, not a differential one: both readers read these
		// bytes the same way, and the thing at fault is the device. See [Class].
		return []Finding{{
			Question: QSemantics, Class: ClassTraffic, Off: ex.Resp.Off, Subject: name,
			Detail: fmt.Sprintf("exception response function 0x%02x does not answer request function 0x%02x",
				ex.Resp.PDU[0], ex.Req.PDU[0]),
		}}
	}

	switch refReq.Kind {
	case KindReadReq:
		req, err := sub.ParseRequest(ex.Req.PDU)
		if err != nil {
			return nil // the request-direction comparison already reported this
		}
		vals, perr := sub.ParseReadResponse(req, ex.Resp.PDU)

		// The reference's own request-aware judgement: a read response must
		// answer the function code that was asked and carry exactly as many
		// registers as were asked for. Neither check can be made standalone,
		// which is the whole reason this file exists.
		//
		// The function-code half was missing from the first version of this
		// code and FuzzMBAPExchange found it in under a second: an FC 04 read
		// of input registers answered by an FC 03 read of holding registers.
		// Those are different address spaces, so the values are a different
		// device state entirely, and the reference would have called that
		// agreement. lexa-proto refuses it correctly. The omission is recorded
		// here because it is the exact class this layer exists to catch, and
		// the differential caught it in its own referee first —
		// testdata/fuzz/FuzzMBAPExchange/9689cff97edcc723 keeps it caught.
		refOK := refResp.Kind == KindReadResp &&
			refResp.FC == refReq.FC &&
			int(refResp.Count) == int(refReq.Count)

		// A panic is not a refusal, however it arrives back here. It is
		// reported with the ID of the entry that suppresses it so the finding
		// is filtered out of the fuzz oracle and stays visible everywhere else.
		var pe *PanicError
		if errors.As(perr, &pe) {
			return []Finding{{
				Question: QAcceptance, Off: ex.Resp.Off, Subject: name,
				Divergence: "DEFECT-READRESP-1BYTE",
				Detail: fmt.Sprintf("%s PANICKED parsing a %d-byte response to a %d-register read at addr %d: %v",
					name, len(ex.Resp.PDU), refReq.Count, refReq.Addr, pe.Value),
			}}
		}

		switch {
		case perr != nil && refOK:
			return []Finding{{
				Question: QAcceptance, Off: ex.Resp.Off, Subject: name,
				Detail: fmt.Sprintf("reference accepted a %d-register response to a %d-register read; %s refused: %v",
					refResp.Count, refReq.Count, name, perr),
			}}
		case perr == nil && !refOK:
			return []Finding{{
				Question: QAcceptance, Off: ex.Resp.Off, Subject: name,
				Detail: fmt.Sprintf("%s accepted a response the reference refused: %d register(s) answering a %d-register read at addr %d%s — "+
					"the gateway would decode register values it should have discarded",
					name, refResp.Count, refReq.Count, refReq.Addr, whyClause(refResp.Why)),
			}}
		case perr != nil && !refOK:
			return nil // both refused; agreement
		}

		var out []Finding
		if len(vals) != len(refResp.Values) {
			return []Finding{{
				Question: QSemantics, Off: ex.Resp.Off, Subject: name,
				Detail: fmt.Sprintf("read response register count: reference %d, %s %d",
					len(refResp.Values), name, len(vals)),
			}}
		}
		for i := range vals {
			if vals[i] != refResp.Values[i] {
				out = append(out, Finding{
					Question: QSemantics, Off: ex.Resp.Off, Subject: name,
					Detail: fmt.Sprintf("read response register %d: reference %d, %s %d",
						int(refReq.Addr)+i, refResp.Values[i], name, vals[i]),
				})
			}
		}
		return out

	case KindWriteReq:
		req, err := sub.ParseRequest(ex.Req.PDU)
		if err != nil {
			return nil
		}
		perr := sub.ParseWriteResponse(req, ex.Resp.PDU)

		// The reference's echo rule, stated independently: FC 06 echoes
		// address and value; FC 16 echoes address and register count. A server
		// that echoes a different address has applied the write somewhere
		// else, which is the single most dangerous thing a Modbus response can
		// say, and it must not be tolerated by either reader.
		refOK := refResp.Kind == KindWriteResp && refResp.FC == refReq.FC && refResp.Addr == refReq.Addr
		if refOK && refReq.FC == FCWriteSingle {
			refOK = len(refResp.Values) == 1 && refResp.Values[0] == refReq.Values[0]
		} else if refOK {
			refOK = refResp.Count == refReq.Count
		}

		switch {
		case perr != nil && refOK:
			return []Finding{{
				Question: QAcceptance, Off: ex.Resp.Off, Subject: name,
				Detail: fmt.Sprintf("reference accepted the write echo; %s refused: %v", name, perr),
			}}
		case perr == nil && !refOK:
			return []Finding{{
				Question: QAcceptance, Off: ex.Resp.Off, Subject: name,
				Detail: fmt.Sprintf("%s accepted a write echo the reference refused: request fc=0x%02x addr=%d, "+
					"response fc=0x%02x addr=%d — a mismatched echo means the write may have landed elsewhere",
					name, refReq.FC, refReq.Addr, refResp.FC, refResp.Addr),
			}}
		}
		return nil

	default:
		return nil
	}
}

// CompareStreams runs the whole response-direction differential over a paired
// conversation. It is what the corpus runs and the fuzz target call.
func CompareStreams(sub Subject, clientBytes, serverBytes []byte) ([]Finding, *PairFault) {
	out := Compare(sub, clientBytes, FromClient)
	out = append(out, Compare(sub, serverBytes, FromServer)...)
	exs, fault := Pair(clientBytes, serverBytes)
	for _, ex := range exs {
		out = append(out, CompareExchange(sub, ex)...)
	}
	return out, fault
}

// whyClause renders the reference's own stated rule when it had one. A
// standalone-consistent response that simply answers the wrong request has no
// Why — the rule it broke is the pairing rule, which is stated by the sentence
// around it — and printing "no reason" there would read as though the
// reference had refused for no reason at all.
func whyClause(why string) string {
	if why == "" {
		return ""
	}
	return " (" + why + ")"
}
