package suitecsip

// resumption_test.go covers the abbreviated TLS 1.2 handshake: detecting it,
// declining to decide on it, and finding the full handshake that DOES carry the
// certificates when the window happens to own one.
//
// The fixture is a real pair of crypto/tls sessions — a full handshake and a
// second connection that resumes it from the ticket the first one was issued —
// rendered into a pcap and read back exactly as a bench capture is. That is the
// same reason harness_test.go builds real sessions rather than Handshake
// literals: a hand-built abbreviated flight would share this author's idea of
// what one looks like with the detector under test, and the whole question here
// is whether the detector agrees with an independent TLS implementation.
//
// The synthetic cases below are the complement, not a substitute: they pin the
// shapes crypto/tls will not produce on demand (an mbed TLS client's empty
// session_id, a TLS 1.3 flight, a truncated capture).

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// --- the detector, on shapes a fixture cannot be made to produce -------------

// synthHandshake builds the minimum a resumption decision reads.
func synthHandshake(version uint16, sessionID, ticket []byte, flight ...tlsdis.HandshakeType) *Handshake {
	h := &Handshake{
		ClientHello:   &tlsdis.ClientHello{SessionID: sessionID, HasSessionTicket: ticket != nil, SessionTicket: ticket},
		ServerHello:   &tlsdis.ServerHello{SessionID: sessionID},
		Version:       version,
		OfferedTicket: ticket,
		ServerFlight:  flight,
	}
	return h
}

func TestResumptionDetector(t *testing.T) {
	ticket := bytes.Repeat([]byte{0xA5}, 64)
	sid := bytes.Repeat([]byte{0x11}, 32)

	cases := []struct {
		name string
		h    *Handshake
		want bool
	}{
		{
			// The flight the 2026-07-28 capture actually held.
			name: "ticket offered, server flight has neither ServerKeyExchange nor ServerHelloDone",
			h: synthHandshake(TLS12, sid, ticket,
				tlsdis.HandshakeServerHello, tlsdis.HandshakeNewSessionTicket),
			want: true,
		},
		{
			// The case that forbids requiring the session_id echo: mbed TLS
			// resumes on the TICKET and sends an empty session_id beside it, and
			// this DUT is scheduled to migrate to mbed TLS.
			name: "mbed TLS shape: a ticket with an EMPTY session_id",
			h: synthHandshake(TLS12, nil, ticket,
				tlsdis.HandshakeServerHello, tlsdis.HandshakeNewSessionTicket),
			want: true,
		},
		{
			name: "a full handshake, even though the client offered a ticket the server declined",
			h: synthHandshake(TLS12, sid, ticket,
				tlsdis.HandshakeServerHello, tlsdis.HandshakeCertificate, tlsdis.HandshakeServerKeyExchange,
				tlsdis.HandshakeCertificateRequest, tlsdis.HandshakeServerHelloDone),
			want: false,
		},
		{
			name: "tickets supported but none held: the extension is present and EMPTY",
			h: synthHandshake(TLS12, sid, []byte{},
				tlsdis.HandshakeServerHello, tlsdis.HandshakeNewSessionTicket),
			want: false,
		},
		{
			// A capture that starts mid-flight also has no ServerHelloDone. The
			// ticket precondition is what keeps that from reading as resumption.
			name: "a truncated capture: a server flight cut off after the ServerHello",
			h:    synthHandshake(TLS12, sid, nil, tlsdis.HandshakeServerHello),
			want: false,
		},
		{
			name: "TLS 1.3, whose FULL handshake omits both messages too",
			h: synthHandshake(0x0304, sid, ticket,
				tlsdis.HandshakeServerHello, tlsdis.HandshakeEncryptedExtensions,
				tlsdis.HandshakeCertificate, tlsdis.HandshakeCertificateVerify, tlsdis.HandshakeFinished),
			want: false,
		},
		{
			name: "no ServerHello at all: the server refused the connection",
			h: &Handshake{
				ClientHello:   &tlsdis.ClientHello{SessionID: sid, HasSessionTicket: true, SessionTicket: ticket},
				Version:       TLS12,
				OfferedTicket: ticket,
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.h.detectResumption()
			if c.h.Resumed != c.want {
				t.Errorf("Resumed = %t, want %t", c.h.Resumed, c.want)
			}
		})
	}
}

// TestResumptionSummaryNamesItsEvidence keeps the reason a bundle prints tied to
// what was actually read. A SKIP whose text a reviewer cannot check against the
// pcap is not better than no SKIP at all.
func TestResumptionSummaryNamesItsEvidence(t *testing.T) {
	h := synthHandshake(TLS12, bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0xA5}, 64),
		tlsdis.HandshakeServerHello, tlsdis.HandshakeNewSessionTicket)
	h.EchoedSessionID = true
	got := h.ResumptionSummary()
	for _, want := range []string{"64-byte session_ticket", "server_hello", "new_session_ticket", "echoed"} {
		if !strings.Contains(got, want) {
			t.Errorf("ResumptionSummary() = %q, want it to mention %q", got, want)
		}
	}
}

// --- critMutualAuth ---------------------------------------------------------

// TestMutualAuthOnAResumedSessionDeclines is the COMM-003 / BASIC-001 fix: the
// certificates a resumed session does not carry are not a device that skipped
// mutual authentication.
func TestMutualAuthOnAResumedSessionDeclines(t *testing.T) {
	h := synthHandshake(TLS12, nil, bytes.Repeat([]byte{0xA5}, 64),
		tlsdis.HandshakeServerHello, tlsdis.HandshakeNewSessionTicket)
	h.ServerHelloFrames = []int{7}
	h.detectResumption()
	if !h.Resumed {
		t.Fatal("the fixture is not a resumed handshake")
	}

	f := critMutualAuth().Wire(nil, &Transcript{Handshake: *h})
	if f.Unavailable == "" {
		t.Fatalf("verdict = %s (%q), want unavailable", f.Verdict, f.Observed)
	}
	for _, want := range []string{"RESUMED", "FULL handshake", "outside this window"} {
		if !strings.Contains(f.Unavailable, want) {
			t.Errorf("the reason %q does not mention %q", f.Unavailable, want)
		}
	}
}

// TestMutualAuthStillFailsAGenuineFullHandshake is the other half, and the one
// that matters more: nothing above may be reachable by a session that really did
// skip the certificate exchange.
func TestMutualAuthStillFailsAGenuineFullHandshake(t *testing.T) {
	p := newTestPKI(t)
	full := func() *Handshake {
		h := synthHandshake(TLS12, nil, nil,
			tlsdis.HandshakeServerHello, tlsdis.HandshakeCertificate, tlsdis.HandshakeServerKeyExchange,
			tlsdis.HandshakeServerHelloDone)
		h.ServerHelloFrames = []int{7}
		h.ServerCertFrames = []int{8}
		h.detectResumption()
		if h.Resumed {
			t.Fatal("a full handshake was detected as resumed")
		}
		return h
	}

	t.Run("no CertificateRequest and no client certificate", func(t *testing.T) {
		f := critMutualAuth().Wire(nil, &Transcript{Handshake: *full()})
		if f.Verdict != certify.Fail {
			t.Fatalf("verdict = %s (%q / %q), want FAIL", f.Verdict, f.Observed, f.Unavailable)
		}
		if !strings.Contains(f.Observed, "server-authenticated only") {
			t.Errorf("observed = %q", f.Observed)
		}
	})

	t.Run("CertificateRequest answered with an EMPTY certificate list", func(t *testing.T) {
		h := full()
		h.CertificateRequest = &tlsdis.CertificateRequest{}
		h.CertReqFrames = []int{9}
		f := critMutualAuth().Wire(nil, &Transcript{Handshake: *h})
		if f.Verdict != certify.Fail {
			t.Fatalf("verdict = %s (%q / %q), want FAIL", f.Verdict, f.Observed, f.Unavailable)
		}
		if !strings.Contains(f.Observed, "EMPTY certificate list") {
			t.Errorf("observed = %q", f.Observed)
		}
	})

	t.Run("a client certificate the server never asked for", func(t *testing.T) {
		h := full()
		h.ClientChain = [][]byte{p.clientDER}
		h.ClientCertFrames = []int{10}
		f := critMutualAuth().Wire(nil, &Transcript{Handshake: *h})
		if f.Verdict != certify.Fail {
			t.Fatalf("verdict = %s (%q / %q), want FAIL", f.Verdict, f.Observed, f.Unavailable)
		}
	})

	t.Run("the conformant case still passes", func(t *testing.T) {
		h := full()
		h.CertificateRequest = &tlsdis.CertificateRequest{}
		h.CertReqFrames = []int{9}
		h.ClientChain = [][]byte{p.clientDER, p.caDER}
		h.ClientCertFrames = []int{10}
		f := critMutualAuth().Wire(nil, &Transcript{Handshake: *h})
		if f.Verdict != certify.Pass {
			t.Fatalf("verdict = %s (%q / %q), want PASS", f.Verdict, f.Observed, f.Unavailable)
		}
		if !strings.Contains(f.Observed, "2-certificate chain") {
			t.Errorf("observed = %q", f.Observed)
		}
	})
}

// --- the two-conversation window --------------------------------------------

// TestWindowOwningBothPicksTheFullHandshake is the CORE-009 shape: a window that
// wholly owns a full handshake AND a session resumed from it. The transcript
// tier must still choose the conversation carrying the discovery walk, and the
// certificate criteria must read the one carrying the certificates — and say so.
func TestWindowOwningBothPicksTheFullHandshake(t *testing.T) {
	p := newTestPKI(t)
	rec := recordResumedPair(t, p, walkHandler(p.clientLFDI, p.clientSFDI, 111115, time.Now().Unix()),
		// The first connection does the telemetry POST: no discovery root on it,
		// so the transcript tier has no reason to choose it — exactly the
		// situation in which its handshake was going unread.
		[]*http.Request{mustRequest(t, "POST", "/rsps/0/r", responseXML)},
		[]*http.Request{
			mustRequest(t, "GET", "/dcap", ""),
			mustRequest(t, "GET", "/tm", ""),
			mustRequest(t, "GET", "/edev", ""),
		})
	ev, remote := evidenceFrom(t, rec, true)

	tr, err := RecoverSession(ev, remote)
	if err != nil {
		t.Fatalf("RecoverSession: %v", err)
	}

	// The discovery session is still identified by what it CONTAINS. This is the
	// no-regression half: the handshake tier borrowing another conversation must
	// not move the transcript tier off the walk.
	if !tr.Decrypted {
		t.Fatalf("the selected session did not decrypt: %s", tr.Undecryptable)
	}
	if len(tr.GETs(DiscoveryRoot)) == 0 {
		t.Fatalf("the selected conversation carries no GET %s (paths: %v)", DiscoveryRoot, tr.Paths())
	}
	if !tr.Handshake.Resumed {
		t.Fatalf("the discovery conversation was expected to be the RESUMED one; server flight %v",
			tr.Handshake.ServerFlight)
	}
	if len(tr.Handshake.ClientChain) != 0 || tr.Handshake.CertificateRequest != nil {
		t.Fatal("the resumed conversation carries certificates, so this fixture proves nothing")
	}

	// The other conversation of the window is there, and it is the full one.
	if len(tr.Others) != 1 {
		t.Fatalf("the selected transcript carries %d other conversation(s), want 1", len(tr.Others))
	}
	ht := tr.HandshakeSession()
	if ht == tr {
		t.Fatal("HandshakeSession returned the resumed conversation with a full one available")
	}
	if !ht.Handshake.CarriesCertificates() || len(ht.Handshake.ClientChain) == 0 {
		t.Fatal("the conversation chosen for the handshake tier carries no certificate exchange")
	}

	// And the criterion decides, cites frames this case owns, and says where it
	// read them.
	obs := &Observation{Case: ev.Case, Transcript: tr, Params: map[string]string{}}
	as, err := mint(ev, obs, []criterion{critMutualAuth()})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	a := as[0]
	if a.Verdict != certify.Pass {
		t.Fatalf("critMutualAuth = %s: %s", a.Verdict, a.Observed)
	}
	if !a.Citable() {
		t.Error("the assertion carries no re-checkable citation")
	}
	if !strings.Contains(a.Observed, "SECOND conversation") {
		t.Errorf("the assertion does not say it read another conversation: %q", a.Observed)
	}
	for _, f := range a.Frames {
		if !ev.Owns(f) {
			t.Errorf("the assertion cites frame %d, which this test case does not own", f)
		}
	}

	// With no full handshake in the window — the case where the fix cannot
	// help — the criterion must still decline rather than fail the DUT.
	alone := *tr
	alone.Others = nil
	f := critMutualAuth().Wire(ev, &alone)
	if f.Unavailable == "" {
		t.Fatalf("with only the resumed conversation, verdict = %s (%q), want unavailable", f.Verdict, f.Observed)
	}
}

// --- fixture ----------------------------------------------------------------

const responseXML = `<?xml version="1.0"?><DERControlResponse xmlns="urn:ieee:std:2030.5:ns">` +
	`<createdDateTime>1</createdDateTime><endDeviceLFDI>ab</endDeviceLFDI><status>1</status>` +
	`<subject>CERT-TEST</subject></DERControlResponse>`

func mustRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequest(method, "https://localhost"+path, nil)
	} else {
		r, err = http.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	}
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		r.Header.Set("Content-Type", sepCT)
	}
	r.Header.Set("Accept", sepCT)
	return r
}

// recordResumedPair records TWO conversations to one server: a full mTLS
// handshake, and a second connection that RESUMES it from the ticket the first
// was issued. Both are tapped into one recording, so the pcap the suite reads
// back holds the pair a poll cycle caught mid-flight produces.
func recordResumedPair(t *testing.T, p *testPKI, handler http.Handler, first, second []*http.Request) recorded {
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
	// ONE config, hence one session cache, across both dials: that is what makes
	// the second connection resume the first.
	clientCfg := &tls.Config{
		RootCAs: p.pool, ServerName: "localhost",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{p.clientDER, p.caDER}, PrivateKey: p.clientKey}},
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		KeyLogWriter:       keyWriter,
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
	dial := func(reqs []*http.Request) (netip.AddrPort, bool) {
		raw, dErr := net.Dial("tcp", ln.Addr().String())
		if dErr != nil {
			t.Fatal(dErr)
		}
		client := mustAddrPort(t, raw.LocalAddr())
		cli := tls.Client(&tap{Conn: raw, fromClient: true, mu: &mu, out: &chunks, client: client}, clientCfg)
		if hErr := cli.Handshake(); hErr != nil {
			t.Fatalf("client handshake: %v", hErr)
		}
		resumed := cli.ConnectionState().DidResume
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
		return client, resumed
	}

	if _, resumed := dial(first); resumed {
		t.Fatal("the first connection resumed a session that did not exist yet")
	}
	secondAP, resumed := dial(second)
	if !resumed {
		t.Fatal("the second connection did not resume the first: the fixture cannot prove anything about " +
			"an abbreviated handshake")
	}
	_ = ln.Close()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	rec := recorded{
		chunks:   append([]chunk(nil), chunks...),
		keyLog:   append([]byte(nil), keyBuf.Bytes()...),
		clientAP: secondAP, serverAP: serverAP,
	}
	rec.keyLog = withResumedSecret(t, rec, secondAP)
	return rec
}

// withResumedSecret adds the resumed session's key-log line.
//
// crypto/tls writes a CLIENT_RANDOM line only from its FULL handshake path, so
// Go's own key log has no entry for a session it resumed. A bench does not have
// that gap — wolfSSL exports on the CTX, once per session — so the fixture
// closes it the way TLS itself does: an abbreviated handshake REUSES the master
// secret of the session it resumes, so the resumed session's line is that same
// secret under the new client random. Nothing is invented here; both values are
// ones the two peers actually used.
func withResumedSecret(t *testing.T, rec recorded, client netip.AddrPort) []byte {
	t.Helper()
	var secret string
	for _, line := range strings.Split(string(rec.keyLog), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "CLIENT_RANDOM" {
			secret = f[2]
			break
		}
	}
	if secret == "" {
		t.Fatal("the recording produced no CLIENT_RANDOM line")
	}
	random := clientHelloRandom(t, rec, client)
	return append(append([]byte(nil), rec.keyLog...),
		[]byte(fmt.Sprintf("CLIENT_RANDOM %s %s\n", hex.EncodeToString(random), secret))...)
}

// clientHelloRandom reads the 32-byte random out of the ClientHello a given
// connection opened with, straight off the recorded bytes.
func clientHelloRandom(t *testing.T, rec recorded, client netip.AddrPort) []byte {
	t.Helper()
	for _, c := range rec.chunks {
		if !c.fromClient || c.client != client {
			continue
		}
		// record header (5) + handshake header (4) + client_version (2).
		if len(c.data) < 11+32 || c.data[0] != 0x16 || c.data[5] != byte(tlsdis.HandshakeClientHello) {
			t.Fatalf("the first write of %s is not a ClientHello record", client)
		}
		return append([]byte(nil), c.data[11:11+32]...)
	}
	t.Fatalf("no client bytes recorded for %s", client)
	return nil
}
