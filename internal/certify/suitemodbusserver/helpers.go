package suitemodbusserver

// helpers.go holds the moves every check in this suite makes: reading a model
// block, decoding a point out of it, comparing what the socket saw against what
// the capture shows, and turning a recovered exchange into a frame-cited
// assertion.
//
// The cross-check in wireAgrees is the honesty mechanism the rest of the suite
// leans on. Every check's live phase records the ADUs it sent and received;
// every check's citation phase independently re-derives them from the capture.
// If the two disagree — a request the capture does not contain, a response body
// that differs — the check does not get to cite anything, because the thing it
// would be citing is not the thing it observed. It emits a SKIP naming the
// disagreement. That branch is the difference between a tool whose PASS means
// "the wire showed this" and one whose PASS means "we think we remember this".

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"csip-tls-test/internal/certify"
	"lexa-proto/mbap"
)

// readModelBlock reads a model's whole register footprint — its two header
// registers plus its L data registers — using as few FC 3 requests as the
// Modbus 125-register ceiling allows.
func readModelBlock(c *client, m modelRef, note string) ([]uint16, error) {
	total := m.span()
	out := make([]uint16, 0, total)
	for read := 0; read < total; {
		want := total - read
		if want > maxReadRegisters {
			want = maxReadRegisters
		}
		regs, err := c.readHolding(m.Addr+uint16(read), uint16(want),
			fmt.Sprintf("%s: model %d registers %d..%d", note, m.ID, int(m.Addr)+read, int(m.Addr)+read+want-1))
		if err != nil {
			return out, err
		}
		out = append(out, regs...)
		read += want
	}
	return out, nil
}

// pointRegs slices a point's registers out of a model block that starts at the
// model's ID register.
func pointRegs(block []uint16, p Point) ([]uint16, bool) {
	if p.Off < 0 || p.End() > len(block) {
		return nil, false
	}
	return block[p.Off:p.End()], true
}

// readPoint issues one FC 3 request for exactly one point, which is what MOD-1
// step 5 ("all points in the model can be read as a single point") calls for.
func readPoint(c *client, m modelRef, p Point, note string) ([]uint16, error) {
	return c.readHolding(m.Addr+uint16(p.Off), uint16(p.Regs()),
		fmt.Sprintf("%s: %d.%s @%d", note, m.ID, p.Name, int(m.Addr)+p.Off))
}

// wireAgrees compares the live phase's exchange log with the ADUs the capture
// yielded. It returns the number of exchanges corroborated and, when they
// disagree, a sentence saying how.
func wireAgrees(log []exchange, conv *conversation) (int, string) {
	matched := 0
	for _, x := range log {
		req, ok := conv.requestWithTID(x.TID)
		if !ok {
			// A request the harness sent but the capture does not contain. The
			// deliberately truncated ADU of TCP-2 is the one legitimate case,
			// and that check does not run this comparison over it.
			return matched, fmt.Sprintf("the capture holds no request with transaction id 0x%04x (%s)", x.TID, x.Note)
		}
		if !bytes.Equal(req.PDU, x.Req) {
			return matched, fmt.Sprintf(
				"request 0x%04x on the wire is % x but the harness sent % x", x.TID, req.PDU, x.Req)
		}
		if x.Resp == nil {
			continue
		}
		resp, ok := conv.responseTo(x.TID)
		if !ok {
			return matched, fmt.Sprintf("the capture holds no response to transaction id 0x%04x", x.TID)
		}
		if !bytes.Equal(resp.PDU, x.Resp) {
			return matched, fmt.Sprintf(
				"response 0x%04x on the wire is % x but the harness read % x", x.TID, resp.PDU, x.Resp)
		}
		matched++
	}
	return matched, ""
}

// exchangeFrames returns the capture frames carrying the request and response
// of a transaction, ascending.
func exchangeFrames(conv *conversation, tids ...uint16) []int {
	seen := map[int]bool{}
	var out []int
	add := func(fs []int) {
		for _, f := range fs {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	for _, tid := range tids {
		if a, ok := conv.requestWithTID(tid); ok {
			add(a.Frames)
		}
		if a, ok := conv.responseTo(tid); ok {
			add(a.Frames)
		}
	}
	sort.Ints(out)
	return out
}

// tidsFor returns the transaction identifiers of the logged exchanges whose
// note matches any of the given prefixes. Checks label their exchanges as they
// make them, so a citation can select exactly the requests that establish one
// claim rather than citing the whole session.
func tidsFor(log []exchange, prefixes ...string) []uint16 {
	var out []uint16
	for _, x := range log {
		for _, p := range prefixes {
			if strings.HasPrefix(x.Note, p) {
				out = append(out, x.TID)
				break
			}
		}
	}
	return out
}

// citer bundles the state a Cite callback needs, so the per-check callbacks are
// about the procedure rather than about plumbing.
type citer struct {
	ev   *certify.Evidence
	conv *conversation
	sess *session
	// Corroborated is how many exchanges the capture confirmed.
	Corroborated int
}

// newCiter reconstructs the conversation and cross-checks it. When it returns a
// non-nil reason, no citation is possible and the caller must emit the SKIP it
// carries — a check must never fall through to an uncited PASS.
func newCiter(ev *certify.Evidence, s *session, skipTruncated bool) (*citer, string) {
	conv, err := reconstruct(ev, s)
	if err != nil {
		return nil, err.Error()
	}
	if conv.RespParseErr != nil {
		return nil, "the DUT's responses could not be split into MBAP frames: " + conv.RespParseErr.Error()
	}
	log := s.client.log
	if skipTruncated {
		// TCP-2 deliberately sends an ADU that is not a complete frame, so the
		// request direction is not expected to stay MBAP-aligned; that check
		// does its own, narrower comparison against the response direction.
		return &citer{ev: ev, conv: conv, sess: s}, ""
	}
	if conv.ReqParseErr != nil {
		return nil, "the requests this test case sent could not be split back into MBAP frames: " +
			conv.ReqParseErr.Error()
	}
	n, mismatch := wireAgrees(log, conv)
	if mismatch != "" {
		return nil, "the capture does not corroborate the exchange this test case drove: " + mismatch
	}
	return &citer{ev: ev, conv: conv, sess: s, Corroborated: n}, ""
}

// frames cites the frames of the named exchanges.
func (c *citer) frames(claim, method string, v certify.Verdict, observed string, tids []uint16) (certify.Assertion, error) {
	fs := exchangeFrames(c.conv, tids...)
	if len(fs) == 0 {
		return c.ev.SkipAssertion(claim, method,
			"the capture holds no frames for the exchanges this claim rests on"), nil
	}
	return c.ev.CiteFrames(claim, method, v, observed, fs)
}

// transportAssertion records the tunnel the procedure ran inside. It is not
// decoration: both source documents assume plain Modbus/TCP on port 502, and a
// reader of this bundle has to know that every other assertion in it was made
// over Secure SunSpec Modbus instead.
func (c *citer) transportAssertion() (certify.Assertion, error) {
	if !c.sess.Encrypted() {
		return c.ev.Narrative(
			"the procedure ran over plain Modbus/TCP, as the source document assumes",
			"transport selected by -param "+paramTransport,
			certify.Pass,
			fmt.Sprintf("plain TCP %s <> %s", c.sess.Local, c.sess.Remote),
			"the suite's own session record")
	}
	fs := c.conv.AllFrames()
	claim := "the Modbus procedure ran inside a Secure SunSpec Modbus (mbaps) session, " +
		"because the DUT exposes no plain Modbus interface"
	method := "TLS record parse and decryption of the attributed session with the run's NSS key log; " +
		"the Modbus ADUs cited elsewhere in this test case are the recovered plaintext"
	observed := fmt.Sprintf("%s, %s <> %s, %d request records / %d response records, %d ADUs recovered",
		c.sess.TLS, c.sess.Local, c.sess.Remote, c.conv.ReqRecords, c.conv.RespRecords,
		len(c.conv.Requests)+len(c.conv.Responses))
	if len(fs) == 0 {
		return c.ev.SkipAssertion(claim, method, "no application-data frames were recovered"), nil
	}
	a, err := c.ev.CiteFrames(claim, method, certify.Warn, observed, fs)
	if err != nil {
		return certify.Assertion{}, err
	}
	a.Verdict = certify.Pass
	a.Note = joinNote(a.Note, "TRANSPORT DEVIATION from the source procedure, which specifies "+
		"Modbus/TCP port 502: SunSpecTCP-9 requires no change to the MBAP protocol inside the tunnel, "+
		"so the ADUs are the procedure's ADUs")
	return a, nil
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

// exceptionName renders an exception code the way the procedures name them.
func exceptionName(code byte) string {
	return fmt.Sprintf("0x%02x (%s)", code, mbap.ExCode(code))
}

// denialReason classifies an exception returned to a WRITE, distinguishing the
// DUT's product policies from a conformance answer.
//
// This is what keeps a write-dependent procedure honest against this DUT. An
// exception 0x01 to a valid, in-range write is not the exception ladder under
// test; it is the control-authority overlay refusing writes to the commanded
// points of models 704-712. An exception 0x02 to a valid write may be the
// SUN-002 honesty gate refusing a point that has no executor. Reporting either
// as a conformance verdict would be reporting the wrong thing.
func denialReason(err error) string {
	e, ok := asException(err)
	if !ok {
		return ""
	}
	switch e.Code {
	case mbap.ExIllegalFunction:
		return "the DUT answered a valid, in-range write with exception 0x01 (illegal function), which on this " +
			"product is how an authorization denial is expressed — most likely the control-authority overlay " +
			"denying writes to the commanded points of models 704-712 while the gateway is in CSIP authority, " +
			"or a client role without write rights on this point"
	case mbap.ExIllegalAddress:
		return "the DUT answered a valid, in-range write with exception 0x02 (illegal data address), which on " +
			"this product is how a point that is writable per the register map but has no executor behind it is " +
			"refused before the acknowledgement (the SUN-002 honesty gate)"
	case mbap.ExGatewayPath, mbap.ExGatewayTarget:
		return fmt.Sprintf("the DUT answered exception %s: the addressed unit is unknown or its southbound "+
			"device has not reported, so no write can be carried out", exceptionName(byte(e.Code)))
	default:
		return fmt.Sprintf("the DUT answered a valid, in-range write with exception %s", exceptionName(byte(e.Code)))
	}
}

// open is every check's first line. It separates the two ways a check can fail
// to reach the DUT, because they mean different things:
//
//   - No DUT address configured at all is a SKIP: the operator did not ask for
//     a bench run, and reporting a conformance verdict would be inventing one.
//   - A configured DUT that cannot be reached, handshaked with, or addressed is
//     returned as an ERROR, which the runner records as a FAIL carrying "no
//     conformance conclusion about the DUT can be drawn from this row". That is
//     the honest reading: the procedure was not carried out.
func open(ctx context.Context, rc *certify.RunCtx, note string) (*session, certify.Result, error) {
	if rc.Targets.Gateway == "" {
		return nil, certify.Skipped("no DUT address configured (-gateway)"), nil
	}
	s, err := openSession(ctx, rc, note)
	if err != nil {
		return nil, certify.Result{}, err
	}
	return s, certify.Result{}, nil
}

// verdictIf maps a boolean criterion to a verdict.
func verdictIf(ok bool) certify.Verdict {
	if ok {
		return certify.Pass
	}
	return certify.Fail
}

// skipAll turns a citation-phase failure into one SKIP per claim the check
// would otherwise have asserted, each carrying the same reason. Emitting the
// claims rather than a single opaque skip keeps the bundle's coverage of the
// procedure's criteria visible even when the evidence was not recoverable.
func skipAll(ev *certify.Evidence, reason string, claims ...string) []certify.Assertion {
	out := make([]certify.Assertion, 0, len(claims))
	for _, cl := range claims {
		out = append(out, ev.SkipAssertion(cl, "reconstruction of the Modbus exchange from the capture", reason))
	}
	return out
}

// citeOne is the single-assertion shorthand.
func citeOne(c *citer, claim, method string, v certify.Verdict, observed string, tids []uint16) ([]certify.Assertion, error) {
	a, err := c.frames(claim, method, v, observed, tids)
	if err != nil {
		return nil, err
	}
	return []certify.Assertion{a}, nil
}

// parseModelList parses a comma-separated list of SunSpec model ids.
func parseModelList(s string) ([]uint16, error) {
	var out []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("suitemodbusserver: %q is not a SunSpec model id", part)
		}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("suitemodbusserver: %q lists no model ids", s)
	}
	return out, nil
}

// errText renders an error for an Observed field, collapsing an exception to
// the shape the procedures use.
func errText(err error) string {
	if err == nil {
		return "no error"
	}
	if e, ok := asException(err); ok {
		return fmt.Sprintf("exception response 0x%02x to function 0x%02x, code %s",
			e.FC|0x80, e.FC, exceptionName(byte(e.Code)))
	}
	return err.Error()
}
