package suitecsip

// siblings_test.go covers the two changes that let a check's evidence be found
// where the DUT actually put it:
//
//   - RecoverSession no longer refuses a window that caught more than one
//     discovery walk. It picks the most complete one, discloses the choice, and
//     carries the rest as siblings. That refusal, on its own, cost twenty-two
//     rows of runs/certfix-validate-20260729T192416 their entire wire evidence:
//     with no transcript at all every criterion fell to gridsim's server-side
//     record, which carries no digest, and every PASS built on one was
//     downgraded to WARN.
//
//   - every transcript lookup spans the conversations the check owns, and a
//     citation drawn from a sibling names the sibling's stream. The DUT does not
//     put everything on the discovery connection: its DER self-report PUTs and
//     its DERControlResponse POSTs ride connections of their own, so a criterion
//     that searched only the selected conversation reported "no PUT from the
//     DUT" with the PUT sitting decrypted and citable in the same frame set.
//
// The fixture is two REAL, independent TLS 1.2 conversations to one server, in
// one recording, rendered to a pcap and read back exactly as a bench capture is
// — the same reasoning as harness_test.go. A hand-built pair of Transcripts
// would prove that the lookup walks a slice; this proves the citation the
// runner will actually accept.

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/keylog"
)

// recordIndependentPair records TWO full, unrelated mTLS conversations to one
// server: no shared session cache, so neither resumes the other and both carry
// their own complete walk.
// gap is the pause between the two dials. It is a parameter because one test
// needs the conversations far enough apart in time that a window can end
// between them — the attributor's 250 ms guard bridges anything closer — and
// the rest should not pay for the wait.
func recordIndependentPair(t *testing.T, p *testPKI, handler http.Handler, gap time.Duration,
	first, second []*http.Request) recorded {
	t.Helper()
	var mu sync.Mutex
	var chunks []chunk
	var keyBuf bytes.Buffer
	keyWriter := writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return keyBuf.Write(b)
	})

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{p.serverDER, p.caDER}, PrivateKey: p.serverKey}},
		MinVersion:   tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.pool,
		KeyLogWriter: keyWriter,
	}
	// No ClientSessionCache: each dial is a FULL handshake, which is what two
	// independent legs of the DUT look like.
	clientCfg := &tls.Config{
		RootCAs: p.pool, ServerName: "localhost",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{p.clientDER, p.caDER}, PrivateKey: p.clientKey}},
		KeyLogWriter: keyWriter,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			raw, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Add(1)
			go func(raw net.Conn) {
				defer wg.Done()
				defer func() { _ = raw.Close() }()
				peer, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
				srv := tls.Server(&tap{Conn: raw, fromClient: false, mu: &mu, out: &chunks,
					client: netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())}, serverCfg)
				if hErr := srv.Handshake(); hErr != nil {
					return
				}
				for {
					req, rErr := http.ReadRequest(newBufReader(srv))
					if rErr != nil {
						return
					}
					rw := &recordingResponseWriter{hdr: http.Header{}}
					handler.ServeHTTP(rw, req)
					if wErr := rw.writeTo(srv, req); wErr != nil {
						return
					}
				}
			}(raw)
		}
	}()

	serverAP := mustAddrPort(t, ln.Addr())
	dial := func(reqs []*http.Request) netip.AddrPort {
		raw, dErr := net.Dial("tcp", ln.Addr().String())
		if dErr != nil {
			t.Fatal(dErr)
		}
		client := mustAddrPort(t, raw.LocalAddr())
		cli := tls.Client(&tap{Conn: raw, fromClient: true, mu: &mu, out: &chunks, client: client}, clientCfg)
		if hErr := cli.Handshake(); hErr != nil {
			t.Fatalf("client handshake: %v", hErr)
		}
		if cli.ConnectionState().DidResume {
			t.Fatal("a conversation resumed: the fixture needs two INDEPENDENT sessions")
		}
		br := newBufReader(cli)
		for _, req := range reqs {
			if wErr := req.Write(cli); wErr != nil {
				t.Fatalf("write request %s: %v", req.URL, wErr)
			}
			resp, rErr := http.ReadResponse(br, req)
			if rErr != nil {
				t.Fatalf("read response for %s: %v", req.URL, rErr)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		_ = cli.CloseWrite()
		_ = raw.Close()
		return client
	}

	firstAP := dial(first)
	if gap > 0 {
		time.Sleep(gap)
	}
	dial(second)
	_ = ln.Close()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	return recorded{
		chunks:   append([]chunk(nil), chunks...),
		keyLog:   append([]byte(nil), keyBuf.Bytes()...),
		clientAP: firstAP, serverAP: serverAP,
	}
}

// twoWalksRecording is the fixture: a long discovery walk on one connection and
// a short one on another, the short one also carrying the DER self-report PUTs.
func twoWalksRecording(t *testing.T, gap time.Duration) recorded {
	t.Helper()
	p := newTestPKI(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sep+xml")
		switch {
		case r.Method == "PUT":
			w.WriteHeader(204)
		case r.URL.Path == "/dcap":
			_, _ = w.Write([]byte(`<DeviceCapability xmlns="urn:ieee:std:2030.5:ns">` +
				`<EndDeviceListLink href="/edev"/></DeviceCapability>`))
		case r.URL.Path == "/edev":
			_, _ = w.Write([]byte(`<EndDeviceList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1">` +
				`<EndDevice><DERListLink href="/edev/0/der"/></EndDevice></EndDeviceList>`))
		case r.URL.Path == "/edev/0/der":
			_, _ = w.Write([]byte(`<DERList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1">` +
				`<DER><DERStatusLink href="/edev/0/der/0/derstat"/></DER></DERList>`))
		default:
			w.WriteHeader(404)
		}
	})
	// The walk: /dcap, /edev, /edev/0/der.
	walk := []*http.Request{
		mustGET(t, "/dcap"), mustGET(t, "/edev"), mustGET(t, "/edev/0/der"),
	}
	// The report leg: its own /dcap (the DUT re-walks per poll cycle) and then
	// the self-report PUTs that are this suite's whole DER-report evidence.
	reports := []*http.Request{
		mustGET(t, "/dcap"),
		mustPUT(t, "/edev/0/der/0/derstat", `<DERStatus xmlns="urn:ieee:std:2030.5:ns">`+
			`<genConnectStatus><value>1</value></genConnectStatus>`+
			`<inverterStatus><value>2</value></inverterStatus>`+
			`<operationalModeStatus><value>2</value></operationalModeStatus>`+
			`<readingTime>1785000000</readingTime></DERStatus>`),
		mustPUT(t, "/edev/0/der/0/dercap", `<DERCapability xmlns="urn:ieee:std:2030.5:ns">`+
			`<rtgMaxW><value>5000</value><multiplier>0</multiplier></rtgMaxW></DERCapability>`),
	}
	return recordIndependentPair(t, p, h, gap, walk, reports)
}

func twoWalks(t *testing.T) (*certify.Evidence, netip.AddrPort) {
	t.Helper()
	rec := twoWalksRecording(t, 0)
	resetRunWireCache()
	t.Cleanup(resetRunWireCache)
	return evidenceFrom(t, rec, true)
}

func mustGET(t *testing.T, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "http://localhost"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func mustPUT(t *testing.T, path, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("PUT", "http://localhost"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/sep+xml")
	req.ContentLength = int64(len(body))
	return req
}

// TestTwoDiscoveryWalksAreSelectedNotRefused is the direct regression for the
// twenty-two downgraded rows: a window that spans more than one poll cycle owns
// two conversations that each carry GET /dcap, and that must yield a transcript.
func TestTwoDiscoveryWalksAreSelectedNotRefused(t *testing.T) {
	ev, server := twoWalks(t)
	tr, err := RecoverSession(ev, server)
	if err != nil {
		t.Fatalf("two owned discovery walks must not refuse recovery: %v", err)
	}
	if tr == nil {
		t.Fatal("no transcript recovered")
	}
	if len(tr.Others) != 1 {
		t.Fatalf("the rejected walk must be carried as a sibling: Others = %d", len(tr.Others))
	}
	// The longer walk is the selection.
	if got := len(tr.Exchanges); got != 3 {
		t.Errorf("selected conversation has %d exchange(s), want the 3-exchange walk", got)
	}
	// The choice is disclosed, not silent.
	joined := strings.Join(tr.Problems, " | ")
	if !strings.Contains(joined, "each carry GET /dcap") || !strings.Contains(joined, "most complete walk") {
		t.Errorf("the selection must be recorded in Problems, got: %s", joined)
	}
}

// TestLookupsSpanTheConversationsTheCheckOwns proves the shared mechanism: a
// message on a sibling connection is found by the ordinary lookups.
func TestLookupsSpanTheConversationsTheCheckOwns(t *testing.T) {
	ev, server := twoWalks(t)
	tr, err := RecoverSession(ev, server)
	if err != nil {
		t.Fatal(err)
	}
	puts := tr.Method("PUT")
	if len(puts) != 2 {
		t.Fatalf("Method(PUT) found %d PUT(s); both are on the sibling conversation and both must be found", len(puts))
	}
	// They came from the sibling, not from the selection.
	for _, e := range puts {
		if e.In() == tr {
			t.Errorf("PUT %s was attributed to the selected conversation, but it rode the sibling", e.Req.Path)
		}
	}
	// Both walks' /dcap exchanges are visible, in capture order.
	if got := len(tr.GETs(DiscoveryRoot)); got != 2 {
		t.Errorf("GETs(/dcap) = %d across the two owned walks, want 2", got)
	}
	if got := tr.ResourceNames(); len(got) == 0 {
		t.Error("ResourceNames must describe the resources of every owned conversation")
	}
}

// TestSiblingCitationNamesTheSiblingStream is the citation-safety half: a
// finding drawn from a sibling must cite the SIBLING's byte range, and the
// runner must accept it.
func TestSiblingCitationNamesTheSiblingStream(t *testing.T) {
	ev, server := twoWalks(t)
	tr, err := RecoverSession(ev, server)
	if err != nil {
		t.Fatal(err)
	}
	f := critDERPut("DERStatus").Wire(ev, tr)
	if f.Verdict != certify.Pass {
		t.Fatalf("the DERStatus PUT is on the wire in this window: verdict = %s (%s / %s)",
			f.Verdict, f.Observed, f.Unavailable)
	}
	if !strings.Contains(f.Observed, "SECOND conversation this test case wholly owns") {
		t.Errorf("a citation from a sibling must disclose it: %q", f.Observed)
	}

	// The elements criterion cites the PUT BODY, so it must resolve the byte
	// range against the sibling's own client direction — the whole reason
	// Message.In exists.
	fb := critDERStatusElements().Wire(ev, tr)
	if fb.Verdict != certify.Pass {
		t.Fatalf("DERStatus elements: verdict = %s (%s / %s)", fb.Verdict, fb.Observed, fb.Unavailable)
	}
	if fb.Dir == nil || fb.End <= fb.Start {
		t.Fatalf("the body citation must be a byte range, got Dir=%v [%d,%d)", fb.Dir, fb.Start, fb.End)
	}
	if fb.Dir == tr.ClientDir {
		t.Error("the body was cited against the SELECTED conversation's stream; it never travelled on it")
	}

	// And the runner accepts it: this is the assertion the bundle would carry.
	a, err := criterion{Claim: "c", How: "h"}.cite(ev, tierTranscript, fb)
	if err != nil {
		t.Fatalf("the sibling citation was refused by the evidence layer: %v", err)
	}
	if a.BytesSHA256 == "" {
		t.Error("the assertion carries no re-derivable digest, which is the whole point")
	}
}

// TestReportOutsideTheWindowIsNamedNotCited covers rung 2 of critDERPut's
// ladder. The DER self-reports are cadence-driven, so the PUT a case is written
// to observe routinely lands outside that case's window. It is still a wire
// fact of the run and must be reported as one — but in frames this case does
// not own, so it is NAMED, never cited.
func TestReportOutsideTheWindowIsNamedNotCited(t *testing.T) {
	// The legs are a second apart so a window can genuinely end between them.
	rec := twoWalksRecording(t, time.Second)
	resetRunWireCache()
	defer resetRunWireCache()

	// A window that closes before the report leg opened: the first conversation
	// is this check's, the second is not.
	pkts := pcapFromRecording(rec)
	fi := certify.NewFrameIndex(pkts)
	var firstClient netip.AddrPort
	var cut time.Time
	for _, c := range rec.chunks {
		if c.fromClient && firstClient == (netip.AddrPort{}) {
			firstClient = c.client
		}
		if c.fromClient && c.client != firstClient {
			cut = c.at
			break
		}
	}
	if cut.IsZero() {
		t.Fatal("the recording holds only one conversation")
	}
	w := certify.NewWindow("csip-conf-v1.3::BASIC-028", Suite)
	w.Open(pkts[0].Time.Add(-time.Second))
	// Half a second before the report leg dialled: comfortably past the
	// attributor's 250 ms guard, and comfortably after the first walk finished.
	w.Close(cut.Add(-500 * time.Millisecond))
	if err := w.ClaimEndpointDuring("tcp", rec.serverAP, "test fixture"); err != nil {
		t.Fatal(err)
	}
	att := fi.Attribute([]*certify.Window{w})
	ev := &certify.Evidence{
		Case:  &certify.Case{UID: "csip-conf-v1.3::BASIC-028", ID: "BASIC-028", Doc: "CSIP-CONF-v1.3"},
		Set:   att.Set("csip-conf-v1.3::BASIC-028"),
		Index: fi, Attribution: att,
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.log")
	if err := os.WriteFile(path, rec.keyLog, 0o600); err != nil {
		t.Fatal(err)
	}
	kl, err := keylog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ev.KeyLog = kl

	tr, err := RecoverSession(ev, rec.serverAP)
	if err != nil {
		t.Fatalf("the first walk is wholly inside the window and must recover: %v", err)
	}
	if len(tr.Method("PUT")) != 0 {
		t.Fatal("the fixture put a PUT inside the window; rung 2 is then unreachable")
	}
	f := critDERPut("DERStatus").Wire(ev, tr)
	if f.Verdict != certify.Pass {
		t.Fatalf("the PUT is on the wire elsewhere in the run: verdict = %s (%s / %s)",
			f.Verdict, f.Observed, f.Unavailable)
	}
	if f.Dir != nil || len(f.Frames) > 0 {
		t.Error("rung 2 must not cite: the frames belong to another test case")
	}
	for _, want := range []string{"NAMED here and not cited", "none of its frames fall in this check's window"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the provenance of a run-scoped find must be exact (%q missing): %q", want, f.Observed)
		}
	}
}

// TestRunWideAbsenceIsAWireFact covers rung 3 of critDERPut's ladder: when the
// capture is fully decrypted and holds no PUT at all, the FAIL is the wire's
// answer, not gridsim's.
func TestRunWideAbsenceIsAWireFact(t *testing.T) {
	p := newTestPKI(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sep+xml")
		_, _ = w.Write([]byte(`<DeviceCapability xmlns="urn:ieee:std:2030.5:ns">` +
			`<EndDeviceListLink href="/edev"/></DeviceCapability>`))
	})
	rec := recordSession(t, p, h, []*http.Request{mustGET(t, "/dcap")})
	resetRunWireCache()
	defer resetRunWireCache()
	ev, server := evidenceFrom(t, rec, true)
	tr, err := RecoverSession(ev, server)
	if err != nil {
		t.Fatal(err)
	}
	f := critDERPut("DERSettings").Wire(ev, tr)
	if f.Verdict != certify.Fail {
		t.Fatalf("no PUT anywhere in a fully decrypted capture is a FAIL: got %s (%s / %s)",
			f.Verdict, f.Observed, f.Unavailable)
	}
	if !strings.Contains(f.Observed, "NO PUT of any resource anywhere in the run") {
		t.Errorf("the FAIL must rest on the capture, not on the admin log: %q", f.Observed)
	}
	if !strings.Contains(f.Observed, "independent of gridsim's admin log") {
		t.Errorf("the source of the finding must be stated: %q", f.Observed)
	}
}

// TestRunWideAbsenceStaysUnavailableWithoutTheKeyLog is the guard on rung 3:
// an undecryptable capture hides application data, so an absence read from it
// would be reporting a decryption gap as a device fault.
func TestRunWideAbsenceStaysUnavailableWithoutTheKeyLog(t *testing.T) {
	rw := &runWire{Complete: false, Opaque: 2, Reason: "no secret in the key log"}
	if rw.Complete {
		t.Fatal("fixture")
	}
	if !strings.Contains(rw.Scope(), "could not be decrypted") {
		t.Errorf("an incomplete scan must say so: %q", rw.Scope())
	}
}
