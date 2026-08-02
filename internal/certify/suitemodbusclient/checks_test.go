package suitemodbusclient

// checks_test.go drives every check's decision logic against a synthetic bench,
// twice: once with a client that behaves the way the procedures require, and
// once with a client that does not.
//
// The second half is the point. A conformance suite that only ever sees a
// conformant peer proves nothing about its own teeth — it would pass a DUT that
// read 200 registers in one request, addressed unit id 0, ignored transaction
// ids, or reported a value its own reads do not account for. Each of those is a
// test below, and each must FAIL.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
)

// verdict looks up a single finding's verdict by a substring of its claim.
func verdict(t *testing.T, fs []finding, sub string) certify.Verdict {
	t.Helper()
	return only(t, fs, sub).Verdict
}

// ── the model chain, reconstructed from the wire ──────────────────────────────

func TestModelChainIsReconstructedFromObservedReadsOnly(t *testing.T) {
	s := newSunSpecServer(40000)
	c := scriptConversation(t, conformantClientScript(s))

	base, models, complete, why := c.ModelChain()
	if base != 40000 {
		t.Fatalf("base = %d, want 40000 (%s)", base, why)
	}
	if !complete {
		t.Fatalf("chain incomplete: %s — %s", why, describeModels(models))
	}
	if len(models) != 3 {
		t.Fatalf("models = %d (%s), want 3", len(models), describeModels(models))
	}
	if models[0].ID != CommonModelID || models[0].Length != 66 {
		t.Errorf("first model = %+v, want the Common Model", models[0])
	}
	// Model 712's body was never requested: it must show as stepped over.
	m, ok := findModel(models, 712)
	if !ok {
		t.Fatal("model 712 missing from the chain")
	}
	if m.BodyRead {
		t.Error("model 712's body was never read, but the chain says it was")
	}
	if long, ok := findModel(models, 701); !ok || !long.BodyCovered {
		t.Errorf("model 701 coverage = %+v", long)
	}
}

func TestModelChainStopsRatherThanGuessing(t *testing.T) {
	s := newSunSpecServer(40000)
	// Only the identifier is read: the chain cannot be walked.
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 2)},
		{payload: readRsp(1, 1, s.read(40000, 2))},
	}}
	c := scriptConversation(t, sc)
	_, models, complete, why := c.ModelChain()
	if complete || len(models) != 0 {
		t.Fatalf("a chain was invented from an identifier-only read: %d model(s), complete=%v",
			len(models), complete)
	}
	if why == "" {
		t.Error("the walk stopped without saying why")
	}
}

// ── CLI-1..CLI-4: discovery ───────────────────────────────────────────────────

func TestDiscoveryPassesAConformantWalk(t *testing.T) {
	s := newSunSpecServer(40000)
	fs := evalDiscovery(scriptConversation(t, conformantClientScript(s)))
	for _, sub := range []string{"'SunS' identifier", "complete SunSpec model chain", "Common Model"} {
		if v := verdict(t, fs, sub); v != certify.Pass {
			t.Errorf("%q = %s, want PASS", sub, v)
		}
	}
	// The Common Model assertion must quote what it decoded, or it is a claim
	// about bytes nobody looked at.
	f := only(t, fs, "Common Model")
	if !strings.Contains(f.Observed, "SN-SOLAR-001") {
		t.Errorf("the Common Model assertion did not quote the decoded serial: %s", f.Observed)
	}
}

func TestDiscoverySkipsWhenTheIdentifierWasNeverRead(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40255, 125)},
		{payload: readRsp(1, 1, s.read(40255, 125))},
	}}
	fs := evalDiscovery(scriptConversation(t, sc))
	if v := verdict(t, fs, "'SunS' identifier"); v != certify.Skip {
		t.Errorf("identifier verdict = %s, want SKIP: a steady-state poll contains no base probe", v)
	}
}

func TestBaseProbesRejectANonStandardBase(t *testing.T) {
	// A client probing 40001 — ERR-1's noncompliant base — must not be reported
	// as having probed only legal bases.
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40001, 2)},
		{payload: readRsp(1, 1, []uint16{0, 0})},
	}}
	c := scriptConversation(t, sc)
	if len(c.BaseProbes()) != 0 {
		t.Errorf("40001 was counted as a standard base probe: %v", c.BaseProbes())
	}
	f := evalBaseProbes(c, nil)
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP when no legal base was probed", f.Verdict)
	}
}

// ── CLI-3: unit ids ───────────────────────────────────────────────────────────

func TestUnitIDsPassTheConfiguredID(t *testing.T) {
	s := newSunSpecServer(40000)
	f := evalUnitIDs(scriptConversation(t, conformantClientScript(s)), "1", true)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
}

func TestUnitIDsFailTheBroadcastAddress(t *testing.T) {
	// Unit id 0 is the RTU broadcast address and has no meaning over TCP.
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 0, 40000, 2)},
		{payload: readRsp(1, 0, []uint16{SunSHigh, SunSLow})},
	}}
	f := evalUnitIDs(scriptConversation(t, sc), "", false)
	if f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL for unit id 0: %s", f.Verdict, f.Observed)
	}
}

func TestUnitIDsFailAMismatchAgainstTheOperatorsDeclaration(t *testing.T) {
	s := newSunSpecServer(40000)
	f := evalUnitIDs(scriptConversation(t, conformantClientScript(s)), "7", true)
	if f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL when the DUT addresses an id the operator did not declare", f.Verdict)
	}
}

func TestUnitIDsFailAResponseFromAnotherSlave(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 2)},
		{payload: readRsp(1, 3, []uint16{SunSHigh, SunSLow})}, // answered by unit 3
	}}
	c := scriptConversation(t, sc)
	// The pairing must not match across unit ids at all, so the exchange is
	// unanswered rather than wrongly matched.
	if c.Exchanges[0].Matched() {
		t.Fatal("a response from a different unit id was paired with the request")
	}
}

// ── READ-2 ────────────────────────────────────────────────────────────────────

func TestREAD2PassesABlockReaderAtTheCeiling(t *testing.T) {
	s := newSunSpecServer(40000)
	fs := evalREAD2(scriptConversation(t, conformantClientScript(s)))
	for _, sub := range []string{
		"no register read the DUT issued exceeded",
		"all points after the ID and L points",
		"maximise the registers retrieved per request",
	} {
		if v := verdict(t, fs, sub); v != certify.Pass {
			t.Errorf("%q = %s, want PASS: %s", sub, v, only(t, fs, sub).Observed)
		}
	}
	// The hex-string logging criterion is a client-side fact and must SKIP.
	if v := verdict(t, fs, "hex strings"); v != certify.Skip {
		t.Errorf("hex-string criterion = %s, want SKIP", v)
	}
}

func TestREAD2FailsAReadOverTheModbusCeiling(t *testing.T) {
	// 200 registers in one FC 0x03 is outside the protocol. A suite that let
	// this pass would be asserting nothing at all.
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 200)},
		{payload: readRsp(1, 1, make([]uint16, 200))},
	}}
	f := evalReadQuantities(scriptConversation(t, sc))
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL for a 200-register read: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "125") {
		t.Errorf("the failure did not name the limit: %s", f.Observed)
	}
}

func TestREAD2FailsACommonModelSplitAcrossRequests(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5}
	tx := uint16(1)
	add := func(start, qty uint16) {
		sc.msgs = append(sc.msgs,
			msg{fromClient: true, payload: readReq(tx, 1, start, qty)},
			msg{payload: readRsp(tx, 1, s.read(start, qty))})
		tx++
	}
	add(40000, 4)
	hdr, l, _ := s.model(CommonModelID)
	add(hdr, 2)
	// The 66-register body split in two, although it fits in one request.
	add(hdr+2, 33)
	add(hdr+35, l-33)
	add(hdr+2+l, 2)

	fs := evalREAD2(scriptConversation(t, sc))
	f := only(t, fs, "all points after the ID and L points")
	if f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL: a 66-register body read in two requests violates the "+
			"single-request criterion (%s)", f.Verdict, f.Observed)
	}
}

func TestREAD2WarnsWhenAChunkIsShortOfTheCeiling(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5}
	tx := uint16(1)
	add := func(start, qty uint16) {
		sc.msgs = append(sc.msgs,
			msg{fromClient: true, payload: readReq(tx, 1, start, qty)},
			msg{payload: readRsp(tx, 1, s.read(start, qty))})
		tx++
	}
	add(40000, 4)
	// Walk every header so the chain reconstructs as far as model 701.
	h1, l1, _ := s.model(CommonModelID)
	add(h1, 2)
	add(h1+2, l1)
	h712, _, _ := s.model(712)
	add(h712, 2)
	hdr, l, _ := s.model(701)
	add(hdr, 2)
	// 137 registers read as 70 + 67 — legal, but not maximal.
	add(hdr+2, 70)
	add(hdr+72, l-70)
	add(hdr+2+l, 2)
	c := scriptConversation(t, sc)
	_, models, _, _ := c.ModelChain()
	f := evalLongModelChunking(c, models)
	if f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN for a non-maximal chunk: %s", f.Verdict, f.Observed)
	}
}

// ── READ-1 ────────────────────────────────────────────────────────────────────

func TestREAD1SkipsABlockReaderAndSaysWhy(t *testing.T) {
	s := newSunSpecServer(40000)
	fs := evalREAD1(scriptConversation(t, conformantClientScript(s)))
	f := only(t, fs, "individually, one request per point")
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP", f.Verdict)
	}
	if !strings.Contains(f.Observed, "capability gap in the device") {
		t.Errorf("the SKIP did not name where the gap lies: %s", f.Observed)
	}
	// The cited observation must NOT carry PASS, or the row's verdict would be
	// promoted by an assertion that is not the criterion.
	for _, g := range fs {
		if g.Verdict == certify.Pass {
			t.Errorf("a PASS assertion escaped from a row nothing demonstrated: %q", g.Claim)
		}
	}
}

func TestREAD1PassesAGenuinePointReader(t *testing.T) {
	// The check must be able to say yes: a client that really did read point by
	// point has to pass, or the SKIP above is a foregone conclusion rather than
	// a finding.
	sc := &script{stepMs: 5}
	for i := uint16(0); i < 6; i++ {
		sc.msgs = append(sc.msgs,
			msg{fromClient: true, payload: readReq(i+1, 1, 40002+i, 1)},
			msg{payload: readRsp(i+1, 1, []uint16{i})})
	}
	fs := evalREAD1(scriptConversation(t, sc))
	if v := verdict(t, fs, "individually, one request per point"); v != certify.Pass {
		t.Errorf("verdict = %s, want PASS for a genuine per-point reader", v)
	}
}

// ── framing ───────────────────────────────────────────────────────────────────

func TestFramingPassesAConformantClient(t *testing.T) {
	s := newSunSpecServer(40000)
	fs := evalFraming(scriptConversation(t, conformantClientScript(s)))
	for _, sub := range []string{"well-formed MBAP header", "matched every response"} {
		if v := verdict(t, fs, sub); v != certify.Pass {
			t.Errorf("%q = %s, want PASS: %s", sub, v, only(t, fs, sub).Observed)
		}
	}
}

func TestFramingFailsAResponseNobodyRequested(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 2)},
		{payload: readRsp(1, 1, []uint16{SunSHigh, SunSLow})},
		{payload: readRsp(4242, 1, []uint16{0, 0})}, // unsolicited
	}}
	fs := evalFraming(scriptConversation(t, sc))
	if v := verdict(t, fs, "matched every response"); v != certify.Fail {
		t.Errorf("verdict = %s, want FAIL when a response carries an id no request used", v)
	}
}

func TestFramingWarnsOnATransactionIDReusedWhileOutstanding(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 2)},
		{fromClient: true, payload: readReq(1, 1, 40002, 2)},
	}}
	fs := evalFraming(scriptConversation(t, sc))
	if v := verdict(t, fs, "matched every response"); v != certify.Warn {
		t.Errorf("verdict = %s, want WARN", v)
	}
}

// ── ERR-2 ─────────────────────────────────────────────────────────────────────

func TestERR2PassesWhenTheExceptionAppearsAndTheClientRecovers(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: excRsp(1, 1, FCReadHoldingRegisters, 0x04)},
		{fromClient: true, payload: readReq(2, 1, 40000, 4)},
		{payload: excRsp(2, 1, FCReadHoldingRegisters, 0x0B)},
		{fromClient: true, payload: readReq(3, 1, 40000, 4)},
		{payload: readRsp(3, 1, s.read(40000, 4))},
	}}
	phases := []*exceptionPhase{
		{Kind: "exception_code", WantCode: 0x04, Armed: true},
		{Kind: "unit_id_confusion", WantCode: 0x0B, Armed: true},
	}
	fs := evalERR2(scriptConversation(t, sc), phases, "injected: (test)")
	if v := verdict(t, fs, "exception code 0x04"); v != certify.Pass {
		t.Errorf("0x04 = %s, want PASS", v)
	}
	if v := verdict(t, fs, "exception code 0x0b"); v != certify.Pass {
		t.Errorf("0x0B = %s, want PASS", v)
	}
	if v := verdict(t, fs, "continued to operate normally"); v != certify.Pass {
		t.Errorf("recovery = %s, want PASS", v)
	}
}

func TestERR2FailsWhenTheClientNeverRecovers(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: excRsp(1, 1, FCReadHoldingRegisters, 0x04)},
	}, rst: true}
	phases := []*exceptionPhase{{Kind: "exception_code", WantCode: 0x04, Armed: true}}
	fs := evalERR2(scriptConversation(t, sc), phases, "injected: (test)")
	if v := verdict(t, fs, "continued to operate normally"); v != certify.Fail {
		t.Errorf("recovery = %s, want FAIL when nothing follows the exception", v)
	}
}

func TestERR2SkipsWhenTheArmedFaultProducedNothing(t *testing.T) {
	s := newSunSpecServer(40000)
	fs := evalERR2(scriptConversation(t, conformantClientScript(s)),
		[]*exceptionPhase{{Kind: "exception_code", WantCode: 0x04, Armed: true}}, "injected: (test)")
	if v := verdict(t, fs, "exception code 0x04"); v != certify.Skip {
		t.Errorf("verdict = %s, want SKIP: the fault was armed but no exception reached the wire", v)
	}
}

func TestERR2JournalFailsASilentClient(t *testing.T) {
	f := err2Journal([]string{"reconciler[active] inv-plain(solar): verdict=match"})
	if f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN when the DUT logged nothing about the failure", f.Verdict)
	}
	g := err2Journal([]string{"level=ERROR msg=\"inv-plain read failed: modbus exception 4\""})
	if g.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS when the DUT logged the failure", g.Verdict)
	}
}

// ── ERR-3 ─────────────────────────────────────────────────────────────────────

func TestERR3ObservesTheStepOverByLength(t *testing.T) {
	s := newSunSpecServer(40000)
	f := evalERR3StepOver(scriptConversation(t, conformantClientScript(s)), nil)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "model 712") {
		t.Errorf("the assertion did not name the model that was stepped over: %s", f.Observed)
	}
}

func TestERR3SkipsWhenEveryModelWasRead(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5}
	tx := uint16(1)
	add := func(start, qty uint16) {
		sc.msgs = append(sc.msgs,
			msg{fromClient: true, payload: readReq(tx, 1, start, qty)},
			msg{payload: readRsp(tx, 1, s.read(start, qty))})
		tx++
	}
	add(40000, 4)
	addr := uint16(40002)
	for i := 0; i < 8; i++ {
		id := s.regs[addr]
		if id == ModelChainEnd {
			add(addr, 2)
			break
		}
		l := s.regs[addr+1]
		add(addr, 2)
		for off := uint16(0); off < l; off += MaxReadQuantity {
			q := uint16(MaxReadQuantity)
			if l-off < q {
				q = l - off
			}
			add(addr+2+off, q)
		}
		addr = addr + 2 + l
	}
	f := evalERR3StepOver(scriptConversation(t, sc), nil)
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP: nothing was stepped over", f.Verdict)
	}
}

// ── PROT-1 ────────────────────────────────────────────────────────────────────

func TestPROT1PassesASeveredTransactionFollowedByRecovery(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)}, // never answered
		{fromClient: true, payload: readReq(2, 1, 40000, 4)},
		{payload: readRsp(2, 1, s.read(40000, 4))},
		{fromClient: true, payload: readReq(3, 1, 40002, 2)},
		{payload: readRsp(3, 1, s.read(40002, 2))},
	}, fin: true}
	c := scriptConversation(t, sc)
	fs := evalPROT1(c, nil, true, false, time.Time{})
	if v := verdict(t, fs, "did not complete"); v != certify.Pass {
		t.Errorf("incomplete-response verdict = %s, want PASS", v)
	}
	if v := verdict(t, fs, "remained functional"); v != certify.Pass {
		t.Errorf("recovery verdict = %s, want PASS", v)
	}
}

func TestPROT1SkipsRecoveryWhenNothingFollows(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
	}, rst: true}
	fs := evalPROT1(scriptConversation(t, sc), nil, true, false, time.Time{})
	if v := verdict(t, fs, "remained functional"); v != certify.Skip {
		t.Errorf("recovery verdict = %s, want SKIP when no successful read follows", v)
	}
}

func TestTimeoutBehaviourPassesWhenTheClientAbandonsTheRead(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)}, // abandoned
		{fromClient: true, payload: readReq(2, 1, 40000, 4)},
		{payload: readRsp(2, 1, []uint16{SunSHigh, SunSLow, 1, 66})},
	}}
	c, at := scriptConversationWithTimes(t, sc)
	f := evalTimeoutBehaviour(c, at, true)
	if f.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS: %s", f.Verdict, f.Observed)
	}
}

func TestTimeoutBehaviourWarnsWhenTheClientWaitsOutTheDelay(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: readRsp(1, 1, []uint16{SunSHigh, SunSLow, 1, 66}), delayMs: latencyMs + 500},
	}}
	c, at := scriptConversationWithTimes(t, sc)
	f := evalTimeoutBehaviour(c, at, true)
	if f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN: a client that waited %d ms did not bound its read",
			f.Verdict, latencyMs+500)
	}
}

// ── PROT-2 ────────────────────────────────────────────────────────────────────

func TestPROT2PassesASegmentedResponse(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: readRsp(1, 1, s.read(40000, 4)), splitAt: 5},
		{fromClient: true, payload: readReq(2, 1, 40002, 2)},
		{payload: readRsp(2, 1, s.read(40002, 2))},
	}}
	fs := evalPROT2(scriptConversation(t, sc), false)
	if v := verdict(t, fs, "delivered across more than one TCP segment"); v != certify.Pass {
		t.Errorf("segmentation verdict = %s, want PASS", v)
	}
	if v := verdict(t, fs, "length-delimited MBAP messages"); v != certify.Pass {
		t.Errorf("framing verdict = %s, want PASS", v)
	}
	if v := verdict(t, fs, "neither retried nor reset"); v != certify.Pass {
		t.Errorf("retry verdict = %s, want PASS", v)
	}
}

func TestPROT2SkipsWhenNothingWasSegmented(t *testing.T) {
	s := newSunSpecServer(40000)
	fs := evalPROT2(scriptConversation(t, conformantClientScript(s)), false)
	f := only(t, fs, "delivered across more than one TCP segment")
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP", f.Verdict)
	}
	if !strings.Contains(f.Observed, "segment_response") {
		t.Errorf("the SKIP did not name the sim verb that would close the gap: %s", f.Observed)
	}
}

// TestPROT2DoesNotGradeAResetItInjectedItself is PROT-2#4 (census
// 20260731T234821): a TCP reset this check identifies as its OWN
// forceReconnect provocation must not be graded as a finding about the DUT's
// retry/reset discipline — see the selfSevered branch in evalPROT2.
func TestPROT2DoesNotGradeAResetItInjectedItself(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5, rst: true, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: readRsp(1, 1, s.read(40000, 4))},
	}}
	fs := evalPROT2(scriptConversation(t, sc), true)
	f := only(t, fs, "neither retried nor reset")
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP (a self-identified provocation, not a DUT finding)", f.Verdict)
	}
	if !strings.Contains(f.Observed, "itself severed") {
		t.Errorf("the SKIP did not attribute the reset to this check's own severance: %s", f.Observed)
	}
}

// TestPROT2WarnsOnAnUnexplainedReset is the contrast: the SAME reset, but this
// check did NOT inject a severance of its own, so it cannot be explained away
// and must still be reported.
func TestPROT2WarnsOnAnUnexplainedReset(t *testing.T) {
	s := newSunSpecServer(40000)
	sc := &script{stepMs: 5, rst: true, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
		{payload: readRsp(1, 1, s.read(40000, 4))},
	}}
	fs := evalPROT2(scriptConversation(t, sc), false)
	f := only(t, fs, "neither retried nor reset")
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN (an unexplained reset)", f.Verdict)
	}
	if !strings.Contains(f.Observed, "injected no severance") {
		t.Errorf("the WARN did not say this check injected nothing: %s", f.Observed)
	}
}

// ── WR-1 / WR-2 ───────────────────────────────────────────────────────────────

func TestWritesPassWellFormedRequests(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: writeSingleReq(1, 1, 40230, 5000)},
		{payload: writeSingleReq(1, 1, 40230, 5000)}, // FC 0x06 echoes the request
		{fromClient: true, payload: writeMultiReq(2, 1, 40232, []uint16{1, 2})},
		{payload: writeMultiRsp(2, 1, 40232, 2)},
	}}
	c := scriptConversation(t, sc)
	prov := &writeProvocation{}
	for _, tc := range []struct {
		fc   uint8
		want string
	}{{FCWriteSingleRegister, "0x06"}, {FCWriteMultipleRegisters, "0x10"}} {
		fs := evalWrites(c, tc.fc, prov)
		if v := verdict(t, fs, "wrote an adjustable point"); v != certify.Pass {
			t.Errorf("FC %s = %s: %s", tc.want, v, only(t, fs, "wrote an adjustable point").Observed)
		}
		if v := verdict(t, fs, "acknowledged the DUT"); v != certify.Pass {
			t.Errorf("FC %s ack = %s", tc.want, v)
		}
	}
}

func TestWritesFailAQuantityByteCountDisagreement(t *testing.T) {
	// An FC 0x10 whose byte count does not match its register quantity is
	// malformed, and a suite that accepted it would be asserting nothing.
	bad := writeMultiReq(1, 1, 40232, []uint16{1, 2})
	bad[MBAPHeaderLen+3] = 0 // quantity high byte
	bad[MBAPHeaderLen+4] = 3 // quantity 3, byte count still 4
	sc := &script{stepMs: 5, msgs: []msg{{fromClient: true, payload: bad}}}
	fs := evalWrites(scriptConversation(t, sc), FCWriteMultipleRegisters, &writeProvocation{})
	if v := verdict(t, fs, "wrote an adjustable point"); v != certify.Fail {
		t.Errorf("verdict = %s, want FAIL", v)
	}
}

func TestWritesSkipWhenTheDUTNeverWrote(t *testing.T) {
	s := newSunSpecServer(40000)
	prov := &writeProvocation{}
	fs := evalWrites(scriptConversation(t, conformantClientScript(s)), FCWriteSingleRegister, prov)
	f := only(t, fs, "wrote an adjustable point")
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP", f.Verdict)
	}
	if !strings.Contains(f.Observed, "dercontrol") {
		t.Errorf("the SKIP did not name the lever that would provoke a write: %s", f.Observed)
	}
}

// ── INFO-1 ────────────────────────────────────────────────────────────────────

func TestScaleFactorPassesWhenTheReportedValueIsDerivable(t *testing.T) {
	s := newSunSpecServer(40000)
	c := scriptConversation(t, conformantClientScript(s))
	// The server holds 1676 at model 701's body+8 and −2 at body+120, so a
	// client applying the scale factor reports 16.76 → rounded to 16 by an
	// integer journal. Use an exactly representable case instead: raw 1676 with
	// scale factor 0 is 1676.
	f := evalScaleFactor(c.Registers, "inv-plain", 1676, true, true)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "1676") {
		t.Errorf("the assertion did not quote the register value: %s", f.Observed)
	}
}

func TestScaleFactorWarnsWhenTheReportedValueIsUnaccountedFor(t *testing.T) {
	s := newSunSpecServer(40000)
	c := scriptConversation(t, conformantClientScript(s))
	f := evalScaleFactor(c.Registers, "inv-plain", 999999, true, true)
	if f.Verdict != certify.Warn {
		t.Errorf("verdict = %s, want WARN: the DUT reported a value its own reads cannot produce",
			f.Verdict)
	}
}

func TestScaleFactorSkipsWithoutAReportedValue(t *testing.T) {
	s := newSunSpecServer(40000)
	c := scriptConversation(t, conformantClientScript(s))
	if f := evalScaleFactor(c.Registers, "inv-plain", 0, false, true); f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
}

// TestScaleFactorUsesTheFrozenReadNotTheDriftedOne is the regression test for
// INFO-1#3 (census 20260731T234821): checkINFO1 freezes the sim, reads it, and
// only then resumes — but resume is a deferred call that fires when the check
// function returns, while the DUT keeps polling on its own independent ~10s
// schedule regardless. A poll already in flight when resume lands can have
// some of its responses timestamped before the boundary and some after, and
// BOTH are still legitimately owned by this check's window: there is no
// window-boundary trick that separates them, because it is the same live
// phase straddling the instant resume actually happened.
//
// This reproduces the exact shape the investigation found on the wire: a
// frozen read of 7374 (correct, verified against the wire at the frozen
// instant) followed ~10 seconds later, in the same owned conversation, by a
// post-resume drifted read of 7593 for the identical address.
func TestScaleFactorUsesTheFrozenReadNotTheDriftedOne(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40100, 2)},
		{payload: readRsp(1, 1, []uint16{7374, 0})}, // frozen: raw 7374, sunssf 0
		{fromClient: true, payload: readReq(2, 1, 40100, 2), delayMs: 10000},
		{payload: readRsp(2, 1, []uint16{7593, 0})}, // post-resume drift, same block
	}}
	c, at := scriptConversationWithTimes(t, sc)

	// Sanity on the synthetic capture's shape: frame 4 is the frozen response,
	// frame 6 the drifted one, roughly ten seconds apart, both owned.
	t4, ok := at(4)
	if !ok {
		t.Fatal("setup: no timestamp for frame 4 (the frozen response)")
	}
	t6, ok := at(6)
	if !ok {
		t.Fatal("setup: no timestamp for frame 6 (the drifted response)")
	}
	if t6.Sub(t4) < 5*time.Second {
		t.Fatalf("setup: frames 4 and 6 are only %s apart, want roughly 10s", t6.Sub(t4))
	}

	// The bug as it actually manifested: ordinary last-write-wins accumulation
	// (what every other check in this suite correctly wants) lets the later,
	// drifted read silently win, and the exact comparison this check makes
	// then WARNs against a value that was, at the frozen instant, correct.
	if v, ok := c.Registers.Get(40100); !ok || v != 7593 {
		t.Fatalf("setup: c.Registers[40100] = %d (ok=%t), want 7593 (last write wins, unscoped)", v, ok)
	}
	if f := evalScaleFactor(c.Registers, "inv-plain", 7374, true, true); f.Verdict != certify.Warn {
		t.Errorf("unscoped verdict = %s, want WARN: this is the shape of the bug this test guards against",
			f.Verdict)
	}

	// The fix: cut off at the instant resume was issued (stood in for here by
	// a cutoff strictly between the two responses), registersAsOf excludes the
	// drifted read entirely rather than letting it overwrite the frozen one.
	cutoff := t4.Add(1 * time.Second)
	frozen := registersAsOf(c.Exchanges, cutoff, at)
	if v, ok := frozen.Get(40100); !ok || v != 7374 {
		t.Fatalf("frozen-scoped register = %d (ok=%t), want 7374 (the drifted read must be excluded, not merely superseded)",
			v, ok)
	}
	f := evalScaleFactor(frozen, "inv-plain", 7374, true, true)
	if f.Verdict != certify.Pass {
		t.Fatalf("frozen-scoped verdict = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "7374") {
		t.Errorf("the assertion did not quote the frozen register value: %s", f.Observed)
	}
}

func TestLastReadbackPicksTheRightDevice(t *testing.T) {
	lines := []string{
		"reconciler[active] inv-secure(solar): readback=W=5000,conn=true",
		"reconciler[active] inv-plain(solar): readback=W=1676,conn=true",
		"reconciler[active] inv-secure(solar): readback=W=5100,conn=true",
	}
	if v, ok := lastReadback(lines, "inv-plain"); !ok || v != 1676 {
		t.Errorf("lastReadback = %d,%v, want 1676", v, ok)
	}
	if v, ok := lastReadback(lines, "inv-secure"); !ok || v != 5100 {
		t.Errorf("lastReadback = %d,%v, want the most recent 5100", v, ok)
	}
	if _, ok := lastReadback(lines, "no-such-device"); ok {
		t.Error("a device with no readback line reported one")
	}
}

// ── INFO-2 ────────────────────────────────────────────────────────────────────

func TestINFO2DetectsTheServedSentinel(t *testing.T) {
	regs := make([]uint16, 20)
	for i := range regs {
		regs[i] = 0x8000
	}
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40190, 20)},
		{payload: readRsp(1, 1, regs)},
	}}
	fs := evalINFO2(scriptConversation(t, sc), "injected: (test)")
	f := only(t, fs, "not-implemented sentinel in response")
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "int16") {
		t.Errorf("the assertion did not name the datatype whose sentinel it saw: %s", f.Observed)
	}
}

func TestINFO2InterpretationFailsAClientThatReportsTheSentinel(t *testing.T) {
	f := info2Interpretation(
		[]string{"reconciler[active] inv-plain(solar): readback=W=-32768,conn=true"}, "inv-plain")
	if f.Verdict != certify.Fail {
		t.Errorf("verdict = %s, want FAIL: the DUT reported the sentinel as a measurement", f.Verdict)
	}
	g := info2Interpretation([]string{"inv-plain: device unavailable"}, "inv-plain")
	if g.Verdict != certify.Pass {
		t.Errorf("verdict = %s, want PASS: the DUT reported no value at all", g.Verdict)
	}
}

// ── the ownership filter ──────────────────────────────────────────────────────

func TestConversationDropsADUsWhoseFramesAnotherCaseOwns(t *testing.T) {
	s := newSunSpecServer(40000)
	pkts := renderScript(conformantClientScript(s), benchClient, benchServer, baseTime, 1)
	asmConv := conversationFrom(t, pkts, benchClient, benchServer)
	total := len(asmConv.Requests)
	if total < 4 {
		t.Fatalf("the synthetic exchange is too short to test the filter: %d requests", total)
	}
	// Rebuild with only the first half of the frames owned. Everything after
	// the cut belongs to "another test case" and must be dropped, not cited.
	cut := pkts[len(pkts)/2].Index
	c := conversationOwned(t, pkts, benchClient, benchServer, func(f int) bool { return f < cut })
	if len(c.Requests) >= total {
		t.Fatalf("the ownership filter dropped nothing: %d of %d requests kept",
			len(c.Requests), total)
	}
	if c.DroppedRequests+c.DroppedResponses == 0 {
		t.Error("ADUs were excluded without being counted; the bundle would not say what was dropped")
	}
	for _, a := range c.Requests {
		for _, f := range a.Frames {
			if f >= cut {
				t.Fatalf("an ADU carrying unowned frame %d survived the filter", f)
			}
		}
	}
}

// ── attribution: self-induced reconnects on a dedicated single-client endpoint ─

// mkStream builds a hand-rolled *netdis.Stream naming only what
// evalAttribution reads (Key, First, Last) — no Dirs, no real capture. That
// is deliberate: it is what lets this decision logic be driven without a
// pcap in the room, the same split checks_test.go uses everywhere else
// (evalX takes a *Conversation built from a synthetic script; here it takes
// streams built by hand instead).
func mkStream(clientPort uint16, first, last int) *netdis.Stream {
	return &netdis.Stream{
		Key: netdis.StreamKey{
			A: netdis.Endpoint{Addr: benchClient.Addr(), Port: clientPort},
			B: netdis.Endpoint{Addr: benchServer.Addr(), Port: benchServer.Port()},
		},
		First: first,
		Last:  last,
	}
}

func TestEvalAttributionSkipsWithNoConversation(t *testing.T) {
	f := evalAttribution(nil, benchServer, nil)
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
}

func TestEvalAttributionPassesASingleConversation(t *testing.T) {
	f := evalAttribution([]*netdis.Stream{mkStream(41234, 10, 20)}, benchServer, []int{10})
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
}

// TestEvalAttributionPassesSequentialReconnects is the census
// compliance-fullsuite-2-20260802T020946 regression: a check's own
// tcp_drop+reconnect (or the DUT's own resilience reconnect under repeated
// exceptions, ERR-2) produces more than one TCP conversation to modsim's
// dedicated, single-client, serialized endpoint. Since no other client can
// ever dial that endpoint, every one of a SEQUENCE of non-overlapping
// conversations is still legitimately the DUT's — this must not WARN.
func TestEvalAttributionPassesSequentialReconnects(t *testing.T) {
	streams := []*netdis.Stream{
		mkStream(41826, 1, 100),
		mkStream(50366, 101, 250), // opens only after 41826 closed
		mkStream(47452, 260, 400),
	}
	f := evalAttribution(streams, benchServer, []int{1})
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s, want PASS for sequential self-induced reconnects: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "3 conversations") {
		t.Errorf("the assertion did not report the count: %s", f.Observed)
	}
}

// TestEvalAttributionWarnsOnOverlappingConversations is the contrast: two
// conversations open AT THE SAME TIME are what a genuine second client
// would look like, and this suite's attribution fix must not paper over
// that — it narrows the false positive, it does not widen what counts as
// suspicious.
func TestEvalAttributionWarnsOnOverlappingConversations(t *testing.T) {
	streams := []*netdis.Stream{
		mkStream(41826, 1, 100),
		mkStream(50366, 50, 200), // opens at frame 50, while 41826 is still open (closes at 100)
	}
	f := evalAttribution(streams, benchServer, []int{1})
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN for overlapping conversations: %s", f.Verdict, f.Observed)
	}
}

// ── CLI-4#8: the base-relocation sweep ────────────────────────────────────────

func TestEvalOtherBasesPassesWhenBothRelocatedBasesCompleteDiscovery(t *testing.T) {
	c0 := scriptConversation(t, conformantClientScript(newSunSpecServer(0)))
	c50000 := scriptConversation(t, conformantClientScript(newSunSpecServer(50000)))
	sweep := []baseSweepAttempt{{base: 0}, {base: 50000}}
	f := evalOtherBases([]*Conversation{c0, c50000}, sweep, "injected: (test)")
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "base 0") || !strings.Contains(f.Observed, "base 50000") {
		t.Errorf("the assertion did not name both bases: %s", f.Observed)
	}
}

func TestEvalOtherBasesWarnsWhenOneBaseCouldNotBeRelocated(t *testing.T) {
	c0 := scriptConversation(t, conformantClientScript(newSunSpecServer(0)))
	sweep := []baseSweepAttempt{
		{base: 0},
		{base: 50000, relocateErr: errors.New("modsim: relocate refused")},
	}
	f := evalOtherBases([]*Conversation{c0}, sweep, "injected: (test)")
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN: one base's relocation failed: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "modsim: relocate refused") {
		t.Errorf("the assertion did not name the relocation failure: %s", f.Observed)
	}
}

func TestEvalOtherBasesSkipsWhenTheSweepNeverRan(t *testing.T) {
	f := evalOtherBases(nil, nil, "fault injection disabled for this run")
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
	if !strings.Contains(f.Observed, "fault injection disabled") {
		t.Errorf("the SKIP did not carry the injection-unavailable reason: %s", f.Observed)
	}
}

// TestFindConversationProbingIsPositionalIndependent proves the lookup goes
// by WHICH base a conversation probed, not by its position in the slice —
// the property evalOtherBases relies on to stay correct when one attempt in
// the sweep fails and the surviving conversations shift.
func TestFindConversationProbingIsPositionalIndependent(t *testing.T) {
	c50000 := scriptConversation(t, conformantClientScript(newSunSpecServer(50000)))
	c0 := scriptConversation(t, conformantClientScript(newSunSpecServer(0)))
	cs := []*Conversation{c50000, c0} // deliberately out of base order
	if got := findConversationProbing(cs, 0); got != c0 {
		t.Errorf("findConversationProbing(0) did not return the base-0 conversation")
	}
	if got := findConversationProbing(cs, 50000); got != c50000 {
		t.Errorf("findConversationProbing(50000) did not return the base-50000 conversation")
	}
	if got := findConversationProbing(cs, 40000); got != nil {
		t.Errorf("findConversationProbing(40000) = %v, want nil: no conversation probed that base", got)
	}
}

// ── ERR-3#4/#3: the spliced unregistered model + admission journal ───────────

// buildERR3SpliceScript walks newSunSpecServer's whole chain plus one extra
// unregistered model spliced immediately before the end marker (mirroring
// modsim's insert_model verb, sim/southbound/modelsplice.go). readSplicedBody
// controls whether the script has the client read into the spliced model's
// body — the FAIL case evalERR3InsertedModel must catch — or only its
// header, as an unregistered model can only legitimately be consumed.
func buildERR3SpliceScript(t *testing.T, readSplicedBody bool) *Conversation {
	t.Helper()
	s := newSunSpecServer(40000)
	end := s.base + 2
	for {
		id, ok := s.regs[end]
		if !ok || id == ModelChainEnd {
			break
		}
		end = end + 2 + s.regs[end+1]
	}
	s.regs[end] = unregisteredModelID
	s.regs[end+1] = unregisteredModelLen
	newEnd := end + 2 + unregisteredModelLen
	s.regs[newEnd] = ModelChainEnd

	sc := &script{stepMs: 5}
	tx := uint16(1)
	add := func(start, qty uint16) {
		sc.msgs = append(sc.msgs,
			msg{fromClient: true, payload: readReq(tx, 1, start, qty)},
			msg{payload: readRsp(tx, 1, s.read(start, qty))})
		tx++
	}
	add(s.base, 4)
	addr := s.base + 2
	for i := 0; i < 8; i++ {
		id := s.regs[addr]
		if id == ModelChainEnd {
			add(addr, 2)
			break
		}
		l := s.regs[addr+1]
		add(addr, 2)
		consume := id != 712 && (id != unregisteredModelID || readSplicedBody)
		if consume {
			body := addr + 2
			for off := uint16(0); off < l; off += MaxReadQuantity {
				q := uint16(MaxReadQuantity)
				if l-off < q {
					q = l - off
				}
				add(body+off, q)
			}
		}
		addr = addr + 2 + l
	}
	return scriptConversation(t, sc)
}

func TestERR3InsertedModelPassesWhenTheDUTStepsOverIt(t *testing.T) {
	c := buildERR3SpliceScript(t, false)
	f := evalERR3InsertedModel(c, true, nil)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "65000") {
		t.Errorf("the assertion did not name the spliced model id: %s", f.Observed)
	}
}

func TestERR3InsertedModelFailsWhenTheDUTConsumesIt(t *testing.T) {
	c := buildERR3SpliceScript(t, true)
	f := evalERR3InsertedModel(c, true, nil)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL: the DUT read into an unregistered model's body: %s",
			f.Verdict, f.Observed)
	}
}

func TestERR3InsertedModelSkipsWhenTheSpliceFailed(t *testing.T) {
	f := evalERR3InsertedModel(nil, false, errors.New("modsim: insert_model refused"))
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
	if !strings.Contains(f.Observed, "modsim: insert_model refused") {
		t.Errorf("the SKIP did not name the splice failure: %s", f.Observed)
	}
}

func TestParseAdmittedModelsFindsTheMostRecentEventForTheDevice(t *testing.T) {
	lines := []string{
		`{"v":1,"type":"admission_admitted","svc":"modbus","data":{"device":"inv-plain","models":[1,120,121]}}`,
		`{"v":1,"type":"admission_refused","svc":"modbus","data":{"device":"inv-plain","reason":"timeout"}}`,
		`{"v":1,"type":"admission_admitted","svc":"modbus","data":{"device":"inv-secure","models":[1]}}`,
		`{"v":1,"type":"admission_admitted","svc":"modbus","data":{"device":"inv-plain","models":[1,120,121,65000]}}`,
	}
	models, found := parseAdmittedModels(lines, "inv-plain")
	if !found {
		t.Fatal("expected an admission_admitted match for inv-plain")
	}
	if !containsModel(models, 65000) {
		t.Errorf("models = %v, want the MOST RECENT event's list (includes 65000)", models)
	}
}

func TestParseAdmittedModelsNotFoundForADeviceNeverAdmitted(t *testing.T) {
	if _, found := parseAdmittedModels(nil, "inv-plain"); found {
		t.Error("found a match against an empty journal")
	}
}

func TestErr3InventoryFailsWhenTheSplicedModelIsAdmitted(t *testing.T) {
	after := []string{`{"type":"admission_admitted","data":{"device":"inv-plain","models":[1,65000]}}`}
	f := err3Inventory(nil, after, nil, nil, "inv-plain")
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s, want FAIL: %s", f.Verdict, f.Observed)
	}
}

func TestErr3InventoryPassesWhenTheSplicedModelIsAbsent(t *testing.T) {
	after := []string{`{"type":"admission_admitted","data":{"device":"inv-plain","models":[1,120]}}`}
	f := err3Inventory(nil, after, nil, nil, "inv-plain")
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
}

func TestErr3InventorySkipsWhenNoFreshAdmissionEventAppears(t *testing.T) {
	before := []string{`{"type":"admission_admitted","data":{"device":"inv-plain","models":[1,120]}}`}
	f := err3Inventory(before, before, nil, nil, "inv-plain")
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP: no admission event was journaled fresh during this window: %s",
			f.Verdict, f.Observed)
	}
}

func TestErr3InventorySkipsWhenTheJournalCannotBeRead(t *testing.T) {
	f := err3Inventory(nil, nil, errors.New("gateway introspection is not configured"), nil, "inv-plain")
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
}

// ── PROT-1#5: the structurally truncated response ─────────────────────────────

// TestUnansweredReadsBeforeAndFromSplitByCutoff is the regression this
// suite's PROT-1 rewrite needs: two unanswered reads in one conversation,
// one from an EARLIER phase (tcp_drop) and one from a LATER one
// (short_response), must never be attributed to each other's claim.
func TestUnansweredReadsBeforeAndFromSplitByCutoff(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},                // early unanswered
		{fromClient: true, payload: readReq(2, 1, 40002, 2), delayMs: 5000}, // late unanswered
	}}
	c, at := scriptConversationWithTimes(t, sc)
	t1, ok := at(3)
	if !ok {
		t.Fatal("setup: no timestamp for frame 3 (the first request)")
	}
	t2, ok := at(4)
	if !ok {
		t.Fatal("setup: no timestamp for frame 4 (the second request)")
	}
	if !t2.After(t1) {
		t.Fatalf("setup: frame 4 (%s) is not after frame 3 (%s)", t2, t1)
	}
	cutoff := t1.Add(t2.Sub(t1) / 2)

	before := unansweredReadsBefore(c, at, cutoff)
	if len(before) != 1 || before[0].Request.TxID != 1 {
		t.Fatalf("unansweredReadsBefore = %+v, want exactly txid=1", before)
	}
	from := unansweredReadsFrom(c, at, cutoff)
	if len(from) != 1 || from[0].Request.TxID != 2 {
		t.Fatalf("unansweredReadsFrom = %+v, want exactly txid=2", from)
	}
}

func TestUnansweredReadsBeforeIsUnfilteredWithAZeroCutoff(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)},
	}}
	c, at := scriptConversationWithTimes(t, sc)
	got := unansweredReadsBefore(c, at, time.Time{})
	if len(got) != 1 {
		t.Fatalf("unansweredReadsBefore with a zero cutoff = %d, want 1 (unfiltered)", len(got))
	}
	if got := unansweredReadsFrom(c, at, time.Time{}); len(got) != 0 {
		t.Errorf("unansweredReadsFrom with a zero cutoff = %d, want 0 (no later phase ran)", len(got))
	}
}

func TestEvalPROT1ShortResponsePassesARecoveredTruncation(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 4)}, // truncated, never completes
		{fromClient: true, payload: readReq(2, 1, 40002, 2)},
		{payload: readRsp(2, 1, []uint16{SunSHigh, SunSLow})},
	}}
	c, at := scriptConversationWithTimes(t, sc)
	t1, ok := at(3) // the truncated request's frame
	if !ok {
		t.Fatal("setup: no timestamp for frame 3 (the truncated request)")
	}
	armedAt := t1.Add(-time.Second) // armed strictly before the request it truncates
	f := evalPROT1ShortResponse(c, at, nil, armedAt)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, f.Observed)
	}
}

func TestEvalPROT1ShortResponseSkipsWhenTheFaultCouldNotBeArmed(t *testing.T) {
	f := evalPROT1ShortResponse(nil, nil, errors.New("segment/truncate framing faults need an interposed "+
		"relay: restart the sim with -protofault"), time.Time{})
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
	if !strings.Contains(f.Observed, "-protofault") {
		t.Errorf("the SKIP did not name the launch flag that would close this row: %s", f.Observed)
	}
}

// ── INFO-2#2: the per-point typed sentinel ────────────────────────────────────

func TestEvalINFO2TypedSentinelPassesWhenTheServedValueIsReadBack(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, infoSentinelAddr, 1)},
		{payload: readRsp(1, 1, []uint16{infoSentinelWant})},
	}}
	c := scriptConversation(t, sc)
	f := evalINFO2TypedSentinel(c, nil)
	if f.Verdict != certify.Warn {
		t.Fatalf("verdict = %s, want WARN (real progress, not full per-datatype coverage): %s",
			f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "now wired") {
		t.Errorf("the assertion did not report the capability as demonstrated: %s", f.Observed)
	}
}

func TestEvalINFO2TypedSentinelSkipsWhenTheFaultCouldNotBeArmed(t *testing.T) {
	f := evalINFO2TypedSentinel(nil, errors.New("modsim's simapi is not configured"))
	if f.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", f.Verdict)
	}
}

func TestEvalINFO2TypedSentinelSkipsWhenTheRegisterWasNeverObserved(t *testing.T) {
	sc := &script{stepMs: 5, msgs: []msg{
		{fromClient: true, payload: readReq(1, 1, 40000, 2)},
		{payload: readRsp(1, 1, []uint16{SunSHigh, SunSLow})},
	}}
	c := scriptConversation(t, sc)
	f := evalINFO2TypedSentinel(c, nil)
	if f.Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP: the seeded register was never read in this test case's "+
			"frames: %s", f.Verdict, f.Observed)
	}
}
