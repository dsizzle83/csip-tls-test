package certify

// example_check_test.go is the worked example a suite author copies.
//
// It implements one catalog test case end to end — live phase, connection
// claim, citation phase, refusal path — and the file is compiled by `go test`,
// so it cannot rot into a doc comment that no longer describes the API.
//
// The shape to internalise:
//
//	1. dial through rc.DialTCP (or dial your own way and rc.ClaimConn), ALWAYS
//	   claiming, because an unclaimed connection produces no citable evidence;
//	2. do the procedure's steps and keep what you observed in a closure;
//	3. return a Result whose Cite callback turns those observations into
//	   assertions over the frames the framework attributed to you;
//	4. when there is nothing to cite, return a SKIP that says why — never a
//	   PASS.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/netdis"
)

// exampleCheck implements a hypothetical "the server answers the request"
// catalog case against the DUT's mbaps port.
//
// Read the catalog record first: Case.Observables is the extraction's list of
// the wire facts the pass criteria rest on, and therefore the list of
// assertions this check owes the bundle.
func exampleCheck(ctx context.Context, rc *RunCtx) (Result, error) {
	target := rc.Targets.Gateway
	if target == "" {
		// Not "we could not reach it, so PASS". A criterion that was not
		// exercised is a SKIP carrying the reason.
		return Skipped("no DUT address configured (-gateway)"), nil
	}

	// 1. Dial AND claim in one step. DialTCP cannot be used without claiming,
	//    which is the point of it existing.
	conn, err := rc.DialTCP(ctx, target, "example mbaps session")
	if err != nil {
		// A connection failure is a real conformance observation if the
		// procedure expected the connection to succeed — but it is the check's
		// job to say so, not the framework's, so return it as a FAIL result
		// rather than an error when that is what it means.
		return Failed("could not reach the DUT at %s: %v", target, err), nil
	}
	defer func() { _ = conn.Close() }()

	// 2. Drive the procedure's steps.
	request := []byte("\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x02")
	if _, err := conn.Write(request); err != nil {
		return Result{}, fmt.Errorf("write request: %w", err) // could not carry out the test
	}
	buf := make([]byte, 260)
	n, err := conn.Read(buf)
	if err != nil {
		return Failed("the DUT sent no response: %v", err), nil
	}
	response := buf[:n]

	// The local socket is what identifies "my" frames in the capture. Capture
	// it here: after Close, LocalAddr is gone.
	local, lerr := addrPortOf(conn.LocalAddr())
	remote, rerr := addrPortOf(conn.RemoteAddr())
	if lerr != nil || rerr != nil {
		return Result{}, fmt.Errorf("read socket addresses: %v %v", lerr, rerr)
	}

	// 3. Decide the verdict from what was observed, and hand the framework a
	//    callback that will cite it once the capture is readable.
	conformant := n >= 9 && response[7]&0x80 == 0
	verdict := Pass
	notes := "the DUT answered the read request"
	if !conformant {
		verdict = Fail
		notes = fmt.Sprintf("the DUT answered with an exception (function byte 0x%02x)", response[7])
	}

	return Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *Evidence) ([]Assertion, error) {
			// 4a. No frames? Say so. This is the branch that keeps the tool
			//     honest when the capture missed the exchange.
			if !ev.HasFrames() {
				return []Assertion{ev.NoEvidence("the DUT answered the read request")}, nil
			}

			// 4b. Find the reply direction of this check's own conversation.
			//     StreamOn refuses to guess if the check opened more than one.
			st, err := ev.StreamOn(remote.Port())
			if err != nil {
				return nil, err
			}
			reply := st.ByFlow(netdis.FlowKey{
				Src: netdis.Endpoint{Addr: remote.Addr(), Port: remote.Port()},
				Dst: netdis.Endpoint{Addr: local.Addr(), Port: local.Port()},
			})
			if reply == nil || reply.Bytes.Len() < len(response) {
				return []Assertion{ev.SkipAssertion(
					"the DUT answered the read request",
					"TCP stream reassembly",
					"the reply direction reassembled to fewer bytes than were read from the socket; "+
						"the capture is incomplete for this exchange")}, nil
			}

			// 4c. Cite the exact bytes. CiteBytes records the byte range, its
			//     sha256, and the frames those bytes arrived in — and refuses
			//     if any of them belongs to another test case.
			a, err := ev.CiteBytes(
				"the DUT answered the Modbus read request without an exception",
				"TCP stream reassembly of the DUT→bench direction, first "+
					fmt.Sprint(len(response))+" bytes",
				verdict,
				fmt.Sprintf("% x", response),
				reply, 0, len(response))
			if err != nil {
				return nil, err
			}

			// 4d. A second, independent assertion: the exchange happened on
			//     the port the procedure names. Frame-cited, so a reviewer can
			//     open the pcap at that frame.
			b, err := ev.CiteFrames(
				"the exchange took place on the DUT's mbaps port",
				"frame attribution (time AND connection 4-tuple)",
				Pass,
				fmt.Sprintf("%s <> %s", local, remote),
				ev.Frames()[:1])
			if err != nil {
				return nil, err
			}
			return []Assertion{a, b}, nil
		},
	}, nil
}

// exampleOffWireCheck shows the other honest shape: a criterion the wire cannot
// show. It PASSes without a citation only because it says, in the bundle, why
// no citation is possible.
func exampleOffWireCheck(ctx context.Context, rc *RunCtx) (Result, error) {
	if !rc.Gateway.Available() {
		return Skipped("gateway introspection is not configured (-gateway-ssh)"), nil
	}
	out, err := rc.Gateway.ReadFile(ctx, "/etc/lexa/trust/roots.pem")
	if err != nil {
		return Skipped("could not read the DUT's trust store: %v", err), nil
	}
	roots := strings.Count(string(out), "-----BEGIN CERTIFICATE-----")
	return Result{
		Verdict:       verdictIf(roots >= 10),
		Notes:         fmt.Sprintf("the DUT's trust store holds %d root certificates", roots),
		OffWire:       true,
		OffWireReason: "a trust-store CAPACITY requirement is a property of the device's storage, not of any exchange on the wire; the observation is a read of /etc/lexa/trust/roots.pem over the read-only gateway client",
	}, nil
}

func verdictIf(ok bool) Verdict {
	if ok {
		return Pass
	}
	return Fail
}

// exampleSuiteInit is how a suite binds its checks. Real suites do this from an
// init function in their own package, against certify.Default().
func exampleSuiteInit(reg *Registry) {
	// Real uids from the committed catalog: RBAC-009 "Information Leakage
	// Prevention" is wire-observable; PKI-001 "Root Store Capacity" is not.
	reg.Register("ssm-conf-v0.8::RBAC-009", "ssm", exampleCheck,
		WithRequires("bench", "capture"))
	reg.Register("ssm-conf-v0.8::PKI-001", "ssm", exampleOffWireCheck,
		WithRequires("gateway"), WithOrder(10))
}

// TestExampleSuiteInitBindsRealCatalogUIDs proves the worked example is not
// aspirational: the uids it registers exist in the committed catalog, so a
// suite copied from it will not be refused as an orphan.
func TestExampleSuiteInitBindsRealCatalogUIDs(t *testing.T) {
	path, err := DefaultCatalogPath()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	cat, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry()
	exampleSuiteInit(reg)
	cov := reg.Coverage(cat, Filter{})
	if len(cov.Orphans) != 0 {
		t.Errorf("the worked example registers uids the catalog does not have: %v", cov.Orphans)
	}
}

// TestExampleCheckEndToEnd runs the worked example through the real runner
// against a loopback peer, and proves its output verifies. If this test breaks,
// every suite copied from the example breaks with it.
func TestExampleCheckEndToEnd(t *testing.T) {
	lis := echoServer(t)
	// The synthetic capture must show the bytes the example actually sends and
	// receives, or the example's own "is the capture complete?" refusal path
	// fires — which is itself the behaviour tested by the SKIP branch below.
	request := "\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x02"
	obs := &observedConn{req: request, rsp: "reply:" + request}
	cat := catalogFile(t)

	reg := NewRegistry()
	reg.Register("doc-a::A-001", "example", func(ctx context.Context, rc *RunCtx) (Result, error) {
		res, err := exampleCheck(ctx, rc)
		if claims := rc.Window().Claims(); len(claims) == 1 {
			obs.noteAddrs(claims[0].Local, claims[0].Remote)
		}
		return res, err
	})

	opts, out := baseOptions(t, obs)
	opts.Targets.Gateway = lis.Addr().String()
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console(opts))
	}
	var got *CaseResult
	for i := range rep.Cases {
		if rep.Cases[i].Case.UID == "doc-a::A-001" {
			got = &rep.Cases[i]
		}
	}
	// The echo peer replies with "reply:" + the request, so byte 7 of the
	// reply is not a Modbus exception and the example's own criterion holds.
	if got.Verdict != Pass {
		t.Fatalf("verdict = %s (%s), assertions %+v", got.Verdict, got.Notes, got.Assertions)
	}
	if len(got.Assertions) != 2 {
		t.Fatalf("assertions = %d, want 2", len(got.Assertions))
	}
	for _, a := range got.Assertions {
		if !a.Citable() {
			t.Errorf("assertion %q carries no re-checkable digest", a.Claim)
		}
	}
	vr, err := bundle.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("the worked example's bundle does not verify:\n%s", vr.String())
	}
}

// TestExampleCheckRefusesAnIncompleteCapture is the branch that matters most:
// when the capture does not actually contain the exchange, the example must
// SKIP with the reason and the runner must refuse to let the PASS stand.
func TestExampleCheckRefusesAnIncompleteCapture(t *testing.T) {
	lis := echoServer(t)
	// Deliberately WRONG payloads: the capture shows a shorter reply than the
	// check read from its socket, so the wire does not evidence the claim.
	obs := &observedConn{req: "short", rsp: "tiny"}
	cat := catalogFile(t)

	reg := NewRegistry()
	reg.Register("doc-a::A-001", "example", func(ctx context.Context, rc *RunCtx) (Result, error) {
		res, err := exampleCheck(ctx, rc)
		if claims := rc.Window().Claims(); len(claims) == 1 {
			obs.noteAddrs(claims[0].Local, claims[0].Remote)
		}
		return res, err
	})
	opts, _ := baseOptions(t, obs)
	opts.Targets.Gateway = lis.Addr().String()
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Cases[0]
	if c.Verdict == Pass {
		t.Fatalf("a PASS survived a capture that does not evidence it: %+v", c.Assertions)
	}
	if len(c.Assertions) == 0 || c.Assertions[0].Verdict != Skip {
		t.Fatalf("assertions = %+v, want a SKIP explaining the missing evidence", c.Assertions)
	}
	if !strings.Contains(c.Assertions[0].Observed, "capture is incomplete") {
		t.Errorf("observed = %q", c.Assertions[0].Observed)
	}
}

// The example must keep compiling against the real signatures.
var (
	_ Check = exampleCheck
	_ Check = exampleOffWireCheck
	_       = exampleSuiteInit
)
