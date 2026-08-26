//go:build cgo

package tlsprobe

// mtls_cgo_test.go pins the MUTUAL-AUTH half of the probe against a server that
// REQUIRES a client certificate — the shape the bench's board presents and the
// shape MBAPS-CRYP001 was filed against.
//
// The registry's hypothesis was that the probe reaches the board's :802 mbaps
// server without presenting a client cert. It does not: internal/mbtls's server
// always calls wolfssl.RequireClientCert (server.go), the loopback fixture these
// tests stand up therefore demands one, and the probe completes against it on
// every mandated suite — the cert IS wired, from -pki, by suitessm's
// ccmsession.go. So these tests carry two jobs. The positive one proves the
// probe presents its identity and completes mutual TLS on the GCM and CCM-8
// suites. The negative ones prove what the board's bare "err=-308" could not
// say on its own: whether a failed handshake was a peer that REFUSED us with a
// stated alert, or a peer that dropped the connection at the transport layer.
// That distinction is the instrumentation this change adds, and it is what a
// bench operator now reads instead of a naked reason code.

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
)

// TestProbeCompletesMutualTLSPresentingItsClientCert is the positive bar for
// CRYP-001: against a server that REQUIRES a client certificate, the probe
// presents its identity and completes a full session — carrying a Model 1 read
// inside the tunnel — on the GCM suite every stack can do and the CCM-8 suite
// only wolfSSL can. A completed handshake against a RequireClientCert server is
// itself the proof the client cert was presented and accepted.
func TestProbeCompletesMutualTLSPresentingItsClientCert(t *testing.T) {
	dev := startDevice(t, nil) // internal/mbtls server: always RequireClientCert
	for _, s := range []Suite{TLS12GCM, TLS12CCM8} {
		t.Run(s.IANA, func(t *testing.T) {
			rep, err := Complete(context.Background(), dev.spec(s))
			if err != nil {
				t.Fatalf("the probe did not complete mutual TLS on %s against a server that REQUIRES a "+
					"client certificate: %v", s, err)
			}
			if rep.Negotiated.Suite.Code != s.Code {
				t.Errorf("negotiated 0x%04X, want the pinned 0x%04X", rep.Negotiated.Suite.Code, s.Code)
			}
			if len(rep.PeerLeafDER) == 0 {
				t.Error("no peer leaf recovered — a mutual-auth session must have authenticated the server")
			}
			if !rep.Model1.OK() {
				t.Fatalf("no Model 1 read completed inside the mutual-TLS session: %v", rep.Model1.Err)
			}
		})
	}
}

// TestARequireClientCertServerAbortsACertlessClient is the mutation the registry
// asked for: DROP the client certificate and the require-client-cert handshake
// fails. It runs at the wolfSSL layer because the probe's own Spec.validate
// refuses a certless spec on purpose (a probe with no identity would measure a
// different procedure) — so "no client cert" is expressed one level down, where
// the board's server also lives.
//
// The point is not merely that it fails. It is that AlertHistory recovers WHY:
// a require-client-cert server that receives no certificate aborts with a fatal
// handshake_failure alert, and that alert is exactly what the instrumentation
// surfaces in place of a bare reason code.
func TestARequireClientCertServerAbortsACertlessClient(t *testing.T) {
	dev := startDevice(t, nil)

	// Control: the SAME client, WITH a cert, completes — so the abort below is
	// attributable to the missing certificate and nothing else.
	if _, _, err := rawWolfHandshake(t, dev.addr, dev.pki.caFile,
		dev.pki.clientCert, dev.pki.clientKey, TLS12GCM); err != nil {
		t.Fatalf("the control handshake WITH a client cert failed, so the mutation proves nothing: %v", err)
	}

	rx, _, err := rawWolfHandshake(t, dev.addr, dev.pki.caFile, "", "", TLS12GCM)
	if err == nil {
		t.Fatal("a CERTLESS client completed the handshake against a server that must require a client " +
			"certificate — the fixture is not enforcing mutual auth and cannot stand in for the board")
	}
	t.Logf("certless handshake rejected: %v; rx=%s", err, alertText(rx))

	// It must be a genuine server rejection, not a transient WANT_READ/timeout
	// that would prove nothing about mutual auth.
	if code := reasonCode(err); code == 2 || code == 3 {
		t.Fatalf("the certless handshake failed with WANT_READ/WANT_WRITE (err=%d), a transient, not a "+
			"server rejection", code)
	}
	// The reason must be RECOVERABLE: either the server named a fatal alert, or
	// it closed the transport. A bench that only ever saw "-308" could not tell
	// these apart; AlertHistory is what makes the first case legible.
	if !rx.Present() {
		t.Fatalf("the certless rejection surfaced no received alert, so the instrumentation added nothing "+
			"over the bare reason code: %v", err)
	}
	if rx.Level != 2 {
		t.Errorf("the received alert is level %d, want 2 (fatal) for a handshake the server refused", rx.Level)
	}
}

// TestHandshakeErrorSurfacesTheServersReasonNotABareCode drives the same
// rejection through the probe's OWN Dial, and asserts the HandshakeError a
// caller reads names the peer's stated reason. The server here trusts a
// different client CA than the one the probe's certificate is signed by, so it
// requests a cert, receives one it cannot verify, and aborts with unknown_ca —
// a fact the old error ("err=-308") threw away.
func TestHandshakeErrorSurfacesTheServersReasonNotABareCode(t *testing.T) {
	dev := startDeviceTrustingADifferentClientCA(t)
	spec := Spec{
		Target:   dev.addr,
		CAFiles:  []string{dev.pki.caFile}, // the probe DOES trust the server
		CertFile: dev.pki.clientCert,       // but presents a cert the server does not
		KeyFile:  dev.pki.clientKey,
		Suite:    TLS12GCM,
		Unit:     1,
		Deadline: 10 * time.Second,
	}
	_, err := Dial(context.Background(), spec)
	he, ok := Refused(err)
	if !ok {
		t.Fatalf("expected a handshake refusal, got %v", err)
	}
	// This is the server refusing US, not us refusing the server: it must NOT be
	// mislabelled as a peer-certificate rejection by this side.
	if he.PeerRejectedByUs {
		t.Fatalf("the server's refusal of our certificate was mis-classified as THIS side refusing the "+
			"server's: %v", he)
	}
	if !he.RxAlert.Present() {
		t.Fatalf("the probe recovered no received alert from a server that sent one: %v", he)
	}
	msg := he.Error()
	if !strings.Contains(msg, "the peer sent a") || !strings.Contains(msg, "unknown_ca") {
		t.Errorf("the error does not name the peer's stated reason; a bench would still be reading a bare "+
			"code:\n%s", msg)
	}
}

// TestHandshakeErrorRendersABareTransportCloseAsSuch is the board's actual
// symptom, rendered. The board returns SOCKET_ERROR_E (-308) with NO alert —
// unlike a wolfSSL server, which refuses a bad certificate with a fatal alert
// (see the tests above). A -308 with no alert is a transport-layer abort, and
// the message must say so, and must NOT imply a cipher or certificate the peer
// named — otherwise the bench chases a PKI problem that is not there.
func TestHandshakeErrorRendersABareTransportCloseAsSuch(t *testing.T) {
	he := &HandshakeError{
		Target:    "69.0.0.2:802",
		Requested: TLS12GCM,
		Err:       errors.New("wolfSSL_connect failed: ret=-1 err=-308"),
	}
	he.classify() // recovers Code=-308 and the reason string from the wrapper's text
	if he.Code != codeSocketError {
		t.Fatalf("classify did not recover the socket-error code: got %d", he.Code)
	}
	if he.RxAlert.Present() {
		t.Fatal("a fabricated transport close must carry no received alert")
	}
	if !he.transportClosed() {
		t.Fatal("a -308 with no alert must classify as a transport close")
	}
	msg := he.Error()
	if !strings.Contains(msg, "transport layer") {
		t.Errorf("the message does not say the peer aborted at the transport layer:\n%s", msg)
	}
	if strings.Contains(msg, "the peer sent a") {
		t.Errorf("the message claims the peer sent an alert it did not send:\n%s", msg)
	}
}

// reasonCode pulls the wolfSSL reason code out of a wrapped Connect failure, the
// same coupling reason_cgo.go documents.
func reasonCode(err error) int {
	if err == nil {
		return 0
	}
	m := wolfReasonPattern.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	c, _ := strconv.Atoi(m[1])
	return c
}

// rawWolfHandshake performs one client-side wolfSSL handshake to target,
// presenting the given client cert/key when both are non-empty and none at all
// when they are empty. It returns the recorded alert history and the connect
// error, so a test can express "drop the client cert" one level below the
// probe's Spec.validate — which refuses a certless spec by design.
func rawWolfHandshake(t *testing.T, target, ca, cert, key string, s Suite) (rx, tx wolfssl.Alert, cerr error) {
	t.Helper()
	ctx, err := wolfssl.NewClientCtxTLS()
	if err != nil {
		t.Fatalf("new client ctx: %v", err)
	}
	defer wolfssl.FreeCtx(ctx)
	if err := wolfssl.SetMinProtoVersion(ctx, int(s.Version)); err != nil {
		t.Fatal(err)
	}
	if err := wolfssl.SetMaxProtoVersion(ctx, int(s.Version)); err != nil {
		t.Fatal(err)
	}
	if err := wolfssl.SetCipherList(ctx, s.Wolf); err != nil {
		t.Fatal(err)
	}
	if err := wolfssl.LoadVerifyLocations(ctx, ca); err != nil {
		t.Fatal(err)
	}
	if cert != "" && key != "" {
		if err := wolfssl.UseCertChainFile(ctx, cert); err != nil {
			t.Fatal(err)
		}
		if err := wolfssl.UseKeyFile(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := wolfssl.UseSupportedCurve(ctx, wolfssl.ECCSecp256r1); err != nil {
		t.Fatal(err)
	}
	wolfssl.SetSessionCacheOff(ctx)

	raw, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	defer raw.Close()
	file, err := raw.(*net.TCPConn).File()
	if err != nil {
		t.Fatalf("dup socket: %v", err)
	}
	defer file.Close()

	ssl, err := wolfssl.NewSSL(ctx)
	if err != nil {
		t.Fatalf("new ssl: %v", err)
	}
	defer wolfssl.FreeSSL(ssl)
	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		t.Fatal(err)
	}
	if err := armTimeouts(int(file.Fd()), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	cerr = wolfssl.Connect(ssl)
	rx, tx, _ = wolfssl.AlertHistory(ssl)
	return rx, tx, cerr
}

// startDeviceTrustingADifferentClientCA stands up an mbaps server that REQUIRES
// a client cert (every internal/mbtls server does) but trusts a client CA the
// device's own client leaf is NOT signed by — so the server requests a cert,
// receives one, and cannot verify it. The probe still trusts the server's leaf,
// so the failure is unambiguously the server refusing the client.
func startDeviceTrustingADifferentClientCA(t *testing.T) *device {
	t.Helper()
	dir := t.TempDir()
	serverCA, serverCAKey := selfSignedCA(t, "mtls server CA")
	otherCA, otherCAKey := selfSignedCA(t, "mtls unrelated client CA")
	p := probePKI{
		caFile:     filepath.Join(dir, "server-ca.pem"),
		serverCert: filepath.Join(dir, "server-cert.pem"),
		serverKey:  filepath.Join(dir, "server-key.pem"),
		clientCert: filepath.Join(dir, "client-cert.pem"),
		clientKey:  filepath.Join(dir, "client-key.pem"),
	}
	// The server verifies clients against serverCA; the probe verifies the
	// server against the same file. The client leaf is signed by otherCA.
	writeCert(t, p.caFile, serverCA.Raw)
	sc, sk := leaf(t, "mtls server", serverCA, serverCAKey, true, "")
	writeCert(t, p.serverCert, sc.Raw)
	writeKey(t, p.serverKey, sk)
	cc, ck := leaf(t, "mtls untrusted client", otherCA, otherCAKey, false, "GridServiceSunSpec")
	writeCert(t, p.clientCert, cc.Raw)
	writeKey(t, p.clientKey, ck)

	lis, err := mbtls.Listen("127.0.0.1:0", mbtls.DefaultServerProfile(p.caFile, p.serverCert, p.serverKey))
	if err != nil {
		t.Fatalf("mbtls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go serve(lis, nil)
	return &device{addr: lis.Addr().String(), pki: p}
}
