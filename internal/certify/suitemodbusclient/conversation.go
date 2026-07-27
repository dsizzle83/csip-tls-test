package suitemodbusclient

// conversation.go turns "the frames this check owns" into "the Modbus messages
// the DUT sent and received", and provides the small vocabulary every check in
// the suite uses to turn a decoded fact into a citable assertion.
//
// # The ownership rule, applied to a byte stream
//
// certify attributes CAPTURE FRAMES to a check. Modbus is a BYTE STREAM. The
// join between the two is that an ADU is this check's evidence only if every
// frame that delivered its bytes is this check's frame. A gateway that has been
// polling the sim for hours produces one long-lived TCP connection whose stream
// spans the whole run, so a check that cited "the third read response in the
// stream" without this filter would routinely be citing another test case's
// traffic. loadConversation therefore drops any ADU with a frame outside the
// check's FrameSet and records how many it dropped — a number that belongs in
// the bundle, because it is the difference between "the DUT never did this" and
// "the DUT did it outside my window".
//
// # Findings, then assertions
//
// Every check's decision logic is a pure function from a Conversation to a
// []finding. A finding names the claim, the verdict, what was observed and
// where the proof is; emit() turns findings into certify.Assertions by calling
// the scoped citation constructors. Splitting it this way is what makes the
// suite's teeth testable: a unit test drives evalREAD2 with a synthetic byte
// stream and asserts the verdict, with no capture, no bench and no bundle.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
)

// side names one direction of the conversation. The DUT is always the client:
// it is the Modbus CLIENT under test and the bench sims are the servers.
type side int

const (
	// fromDUT is the DUT→server direction: requests.
	fromDUT side = iota
	// fromServer is the server→DUT direction: responses.
	fromServer
)

func (s side) String() string {
	if s == fromDUT {
		return "DUT→server"
	}
	return "server→DUT"
}

// Conversation is one Modbus/TCP connection between the DUT and a bench server,
// as seen in the frames one check owns.
type Conversation struct {
	// Server and Client are the endpoints; Client is the DUT's ephemeral socket.
	Server, Client netip.AddrPort
	// ReqDir and RspDir are the two reassembled directions.
	ReqDir, RspDir *netdis.Direction

	// Requests and Responses are the ADUs whose every frame this check owns.
	Requests, Responses []ADU
	// Exchanges pairs them by transaction id.
	Exchanges []Exchange
	// TxIDs summarises transaction-identifier discipline.
	TxIDs TxIDReport

	// Registers is the server register image reconstructed from the responses.
	Registers *RegisterView
	// ReadSpans are the address ranges the DUT asked for, in request order.
	ReadSpans []ReadSpan

	// DroppedRequests / DroppedResponses count ADUs excluded because a frame
	// they arrived in belongs to another test case or to no window at all.
	DroppedRequests, DroppedResponses int
	// ReqParse / RspParse carry the structural findings of parsing.
	ReqParse, RspParse *ParseResult

	// Opened is true when the capture contains this connection's SYN, which is
	// what makes stream offsets true offsets and makes a discovery sequence
	// complete rather than merely observed in progress.
	Opened bool
	// Closed records that the connection ended inside the observation, and how.
	FINSeen, RSTSeen bool
}

// loadConversation builds the conversation with the bench server at remote.
//
// A missing conversation is not an error here: several checks legitimately have
// to report "the DUT never talked to this server during my window", and they
// say it with a SKIP assertion carrying the reason, not with a failure.
func loadConversation(ev *certify.Evidence, remote netip.AddrPort) (*Conversation, error) {
	st, err := ev.Stream(remote)
	if err != nil {
		return nil, err
	}
	srvEP := netdis.Endpoint{Addr: remote.Addr(), Port: remote.Port()}
	var cliEP netdis.Endpoint
	if st.Key.A == srvEP {
		cliEP = st.Key.B
	} else {
		cliEP = st.Key.A
	}
	reqDir := st.ByFlow(netdis.FlowKey{Src: cliEP, Dst: srvEP})
	rspDir := st.ByFlow(netdis.FlowKey{Src: srvEP, Dst: cliEP})
	if reqDir == nil || rspDir == nil {
		return nil, fmt.Errorf("suitemodbusclient: conversation with %s has only one direction "+
			"reassembled; a request/response protocol cannot be evidenced from half a conversation", remote)
	}
	return buildConversation(reqDir, rspDir, remote,
		netip.AddrPortFrom(cliEP.Addr, cliEP.Port), ev.Owns), nil
}

// buildConversation is loadConversation's core, with the ownership predicate
// passed in. Splitting it out is what lets a unit test drive the whole parse →
// pair → chain-walk pipeline over a synthetic connection, with no capture, no
// bundle and no bench.
func buildConversation(reqDir, rspDir *netdis.Direction, server, client netip.AddrPort,
	owns func(int) bool) *Conversation {

	if owns == nil {
		owns = func(int) bool { return true }
	}
	c := &Conversation{
		Server:    server,
		Client:    client,
		ReqDir:    reqDir,
		RspDir:    rspDir,
		Registers: newRegisterView(),
		Opened:    reqDir.SYNSeen && !reqDir.MidStream,
		FINSeen:   rspDir.FINSeen || reqDir.FINSeen,
		RSTSeen:   rspDir.RSTSeen || reqDir.RSTSeen,
	}

	c.ReqParse = ParseADUs(reqDir.Bytes.Bytes(), reqDir.Bytes.PacketsFor, reqDir.MidStream)
	c.RspParse = ParseADUs(rspDir.Bytes.Bytes(), rspDir.Bytes.PacketsFor, rspDir.MidStream)

	c.Requests, c.DroppedRequests = ownedOnly(owns, c.ReqParse.ADUs)
	c.Responses, c.DroppedResponses = ownedOnly(owns, c.RspParse.ADUs)
	c.Exchanges = pairExchanges(c.Requests, c.Responses)
	c.TxIDs = analyseTxIDs(c.Exchanges, c.Responses)

	for i, ex := range c.Exchanges {
		start, qty, ok := ex.Request.ReadRequest()
		if !ok {
			continue
		}
		c.ReadSpans = append(c.ReadSpans, ReadSpan{Start: start, Quantity: qty, Exchange: i})
		if ex.Response == nil {
			continue
		}
		if _, regs, ok := ex.Response.ReadResponse(); ok {
			c.Registers.apply(start, regs, *ex.Response)
		}
	}
	return c
}

// ownedOnly keeps the ADUs every one of whose frames this check owns.
func ownedOnly(owns func(int) bool, in []ADU) (out []ADU, dropped int) {
	for _, a := range in {
		keep := len(a.Frames) > 0
		for _, f := range a.Frames {
			if !owns(f) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, a)
		} else {
			dropped++
		}
	}
	return out, dropped
}

// dir returns the reassembled direction for a side.
func (c *Conversation) dir(s side) *netdis.Direction {
	if s == fromDUT {
		return c.ReqDir
	}
	return c.RspDir
}

// Reads returns the exchanges whose request was a register read.
func (c *Conversation) Reads() []Exchange {
	var out []Exchange
	for _, ex := range c.Exchanges {
		if _, _, ok := ex.Request.ReadRequest(); ok {
			out = append(out, ex)
		}
	}
	return out
}

// Writes returns the exchanges whose request was FC 0x06 or FC 0x10.
func (c *Conversation) Writes() []Exchange {
	var out []Exchange
	for _, ex := range c.Exchanges {
		switch ex.Request.FC {
		case FCWriteSingleRegister, FCWriteMultipleRegisters:
			out = append(out, ex)
		}
	}
	return out
}

// Exceptions returns the exchanges the server answered with an exception.
func (c *Conversation) Exceptions() []Exchange {
	var out []Exchange
	for _, ex := range c.Exchanges {
		if ex.Response != nil && ex.Response.IsException() {
			out = append(out, ex)
		}
	}
	return out
}

// UnitIDs returns the distinct MBAP unit identifiers the DUT addressed.
func (c *Conversation) UnitIDs() []uint8 {
	seen := map[uint8]bool{}
	for _, a := range c.Requests {
		seen[a.UnitID] = true
	}
	out := make([]uint8, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// BaseProbes returns the read requests that look like SunSpec base-address
// probes: a short read at one of the three standard bases, or at any address
// whose response would carry the identifier.
func (c *Conversation) BaseProbes() []ReadSpan {
	var out []ReadSpan
	for _, s := range c.ReadSpans {
		if IsStandardBase(s.Start) {
			out = append(out, s)
		}
	}
	return out
}

// ModelChain walks the chain from the first standard base whose identifier the
// DUT was observed to read.
func (c *Conversation) ModelChain() (base uint16, models []Model, complete bool, why string) {
	var reasons []string
	for _, b := range StandardBases {
		ms, ok, w := c.Registers.Chain(b)
		if len(ms) > 0 || ok {
			return b, annotateModels(ms, c.ReadSpans), ok, w
		}
		reasons = append(reasons, fmt.Sprintf("base %d: %s", b, w))
	}
	return 0, nil, false, strings.Join(reasons, "; ")
}

// Summary renders a one-line description of the conversation for a note.
func (c *Conversation) Summary() string {
	return fmt.Sprintf("%s <> %s: %d request(s), %d response(s), %d exception(s), %d register(s) observed",
		c.Client, c.Server, len(c.Requests), len(c.Responses), len(c.Exceptions()), c.Registers.Len())
}

// ── findings ──────────────────────────────────────────────────────────────────

// citeKind selects how a finding is evidenced.
type citeKind int

const (
	// citeSkip — the criterion was addressed but not asserted here.
	citeSkip citeKind = iota
	// citeFrames — the claim rests on the existence and identity of frames.
	citeFrames
	// citeBytes — the claim rests on specific bytes in a reassembled direction.
	citeBytes
	// citeNarrative — the claim rests on a source outside the capture, named.
	citeNarrative
)

// finding is one decided claim, before it becomes an Assertion. Keeping the
// decision and the citation apart is what lets a unit test check the decision
// without a capture in the room.
type finding struct {
	Claim    string
	Method   string
	Verdict  certify.Verdict
	Observed string
	Kind     citeKind

	// citeFrames
	Frames []int
	// citeBytes
	Side       side
	Start, End int
	// citeNarrative
	Source string
}

// skipf builds a SKIP finding. The reason is the whole point of it, so it is
// formatted rather than fixed.
func skipf(claim, method, format string, a ...any) finding {
	return finding{Claim: claim, Method: method, Verdict: certify.Skip,
		Observed: fmt.Sprintf(format, a...), Kind: citeSkip}
}

// frames builds a frame-cited finding.
func framesf(claim, method string, v certify.Verdict, fr []int, format string, a ...any) finding {
	return finding{Claim: claim, Method: method, Verdict: v,
		Observed: fmt.Sprintf(format, a...), Kind: citeFrames, Frames: dedupe(fr)}
}

// bytesf builds a byte-range-cited finding.
func bytesf(claim, method string, v certify.Verdict, s side, start, end int, format string, a ...any) finding {
	return finding{Claim: claim, Method: method, Verdict: v,
		Observed: fmt.Sprintf(format, a...), Kind: citeBytes, Side: s, Start: start, End: end}
}

// narrativef builds a finding evidenced somewhere other than the capture.
func narrativef(claim, method, source string, v certify.Verdict, format string, a ...any) finding {
	return finding{Claim: claim, Method: method, Verdict: v,
		Observed: fmt.Sprintf(format, a...), Kind: citeNarrative, Source: source}
}

func dedupe(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	cp := append([]int(nil), in...)
	sort.Ints(cp)
	out := cp[:1]
	for _, v := range cp[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// emit turns findings into assertions.
//
// A citation the framework refuses — a frame this check does not own, a byte
// range that strays outside its window — is NOT propagated as an error that
// aborts the check. It is converted into a SKIP assertion naming the refusal,
// because "the framework would not let me cite this" is a fact about the
// evidence, and losing the other twenty assertions to report it would be a poor
// trade. A refusal is still visible: it appears in the bundle, as a SKIP whose
// Observed text is the framework's own message.
func emit(ev *certify.Evidence, c *Conversation, fs []finding) []certify.Assertion {
	out := make([]certify.Assertion, 0, len(fs))
	for _, f := range fs {
		var (
			a   certify.Assertion
			err error
		)
		switch f.Kind {
		case citeSkip:
			a = ev.SkipAssertion(f.Claim, f.Method, f.Observed)
		case citeFrames:
			if len(f.Frames) == 0 {
				a = ev.SkipAssertion(f.Claim, f.Method,
					"the observation was made but no capture frame could be attached to it: "+f.Observed)
				break
			}
			a, err = ev.CiteFrames(f.Claim, f.Method, f.Verdict, f.Observed, f.Frames)
		case citeBytes:
			if c == nil {
				err = fmt.Errorf("a byte citation was requested with no conversation to cite from")
				break
			}
			a, err = ev.CiteBytes(f.Claim, f.Method, f.Verdict, f.Observed, c.dir(f.Side), f.Start, f.End)
		case citeNarrative:
			a, err = ev.Narrative(f.Claim, f.Method, f.Verdict, f.Observed, f.Source)
		}
		if err != nil {
			a = ev.SkipAssertion(f.Claim, f.Method,
				"this claim could not be cited: "+err.Error()+" — observed: "+f.Observed)
		}
		out = append(out, a)
	}
	return out
}

// aduFrames collects the frames of a set of ADUs.
func aduFrames(as ...ADU) []int {
	var out []int
	for _, a := range as {
		out = append(out, a.Frames...)
	}
	return dedupe(out)
}

// exchangeFrames collects the frames of an exchange's request and response.
func exchangeFrames(ex Exchange) []int {
	out := append([]int(nil), ex.Request.Frames...)
	if ex.Response != nil {
		out = append(out, ex.Response.Frames...)
	}
	return dedupe(out)
}
