package suitessm

// rbac011_decrypt_test.go proves the fix for RBAC-011's WARN: under TLS 1.3
// the gateway's client Certificate message — the one carrying the SunSpec
// role extension RBAC-011 exists to read — is encrypted with the DEVICE SIM's
// (mbapsdev's) handshake keys, not the bench's own. Once mbapsdev exports its
// session secrets (sim/mbapsdev/main.go's -keylog flag; the export itself was
// already wired into internal/mbtls.Listener.Accept and was a silent no-op
// until something called wolfssl.OpenKeylog), decryptedCertificate in
// checks_rbac.go must be able to recover that Certificate message from the
// capture and read its role extension — exactly as RBAC-011's Cite function
// now does before falling back to a SKIP.
//
// This drives a REAL TLS 1.3 handshake over a real loopback socket — a
// synthetic "gateway" client presenting a role-bearing certificate, and a
// synthetic "mbapsdev" server exporting its OWN session secrets via Go's
// crypto/tls KeyLogWriter — which is the same mechanism wolfSSL's
// per-session secret callback provides on the product's own TLS stack (see
// internal/wolfssl/keylog.go): a TLS 1.3 endpoint derives BOTH directions'
// traffic secrets as part of its own key schedule, so exporting one side's
// secrets is sufficient to decrypt the whole handshake, including the peer's
// Certificate message. The raw bytes that cross the socket are tapped into a
// synthetic pcap with loopback_test.go's own capture machinery, so this test
// exercises the identical parse-and-decrypt path a real bench capture would.

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/tlsdecrypt"
)

// TestDecryptedCertificateRecoversTheGatewaysTLS13RoleCert is the regression
// lock for RBAC-011's WARN (census 20260802): before sim/mbapsdev exported its
// secrets, the gateway's TLS 1.3 client Certificate message was undecryptable
// on this suite's own southbound leg — cleartext-only wireView.
// ClientCertificate() found nothing, both of RBAC-011's citation assertions
// fell back to SKIP, and the "PASS downgraded to WARN: no assertion carries a
// digest" rule (runner.go's finalise) turned the whole row WARN even though
// the live phase had observed exactly what the procedure asks for.
func TestDecryptedCertificateRecoversTheGatewaysTLS13RoleCert(t *testing.T) {
	root, rootKey := testCA(t, "rbac011-root")

	// The "gateway": a TLS 1.3 client presenting a certificate carrying the
	// SunSpec role extension RBAC-011 must read.
	gatewayLeaf, err := mintLeaf(root, rootKey, mintOpts{
		CommonName: "rbac011-gateway", Role: "GridServiceSunSpec",
	})
	if err != nil {
		t.Fatalf("mint gateway leaf: %v", err)
	}
	// The "device sim": mbapsdev's own server identity. It carries no role —
	// RBAC-011's second half requires exactly that (a role is required of
	// clients, not of servers) — so mintOpts.Role is left empty.
	simLeaf, err := mintLeaf(root, rootKey, mintOpts{CommonName: "rbac011-mbapsdev"})
	if err != nil {
		t.Fatalf("mint device-sim leaf: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })

	// The device sim's own exported secrets — the mechanism sim/mbapsdev's
	// -keylog flag now wires up via wolfssl.OpenKeylog / internal/mbtls's
	// Listener.Accept. bytes.Buffer is safe here because it is only read
	// AFTER both goroutines below have signalled completion (wg.Wait()).
	var simKeylog bytes.Buffer

	var wg sync.WaitGroup
	wg.Add(2)

	var acceptErr error
	go func() {
		defer wg.Done()
		conn, aerr := lis.Accept()
		if aerr != nil {
			acceptErr = aerr
			return
		}
		defer func() { _ = conn.Close() }()
		srv := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{simLeaf},
			ClientAuth:   tls.RequireAnyClientCert, // mbtls.Listener demands SOME client cert (TCP-11/13/48)
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			KeyLogWriter: &simKeylog,
		})
		_ = srv.SetDeadline(time.Now().Add(10 * time.Second))
		if herr := srv.Handshake(); herr != nil {
			acceptErr = herr
		}
	}()

	tp := &tap{}
	var (
		clientErr                 error
		gatewayLocal, gatewayPeer net.Addr
	)
	go func() {
		defer wg.Done()
		raw, derr := net.Dial("tcp", lis.Addr().String())
		if derr != nil {
			clientErr = derr
			return
		}
		defer func() { _ = raw.Close() }()
		gatewayLocal, gatewayPeer = raw.LocalAddr(), raw.RemoteAddr()
		tapped := tp.wrap(raw)
		cli := tls.Client(tapped, &tls.Config{
			Certificates: []tls.Certificate{gatewayLeaf},
			// The suite's own dial() does the same (session.go): the point of
			// this test is decrypting and parsing the Certificate message, not
			// exercising Go's chain-verification path.
			InsecureSkipVerify: true, //nolint:gosec // test-only loopback peer
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		})
		_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
		if herr := cli.Handshake(); herr != nil {
			clientErr = herr
		}
	}()
	wg.Wait()

	if acceptErr != nil {
		t.Fatalf("mbapsdev-side handshake: %v", acceptErr)
	}
	if clientErr != nil {
		t.Fatalf("gateway-side handshake: %v", clientErr)
	}

	gatewayAddr, err := addrPortOf(gatewayLocal)
	if err != nil {
		t.Fatalf("gateway local addr: %v", err)
	}
	simAddr, err := addrPortOf(gatewayPeer)
	if err != nil {
		t.Fatalf("mbapsdev addr: %v", err)
	}

	pkts := tp.packets()
	if len(pkts) == 0 {
		t.Fatal("no bytes were tapped from the handshake")
	}
	fi := certify.NewFrameIndex(pkts)
	streams := fi.Streams()
	if len(streams) != 1 {
		t.Fatalf("synthesised capture holds %d conversation(s), want 1", len(streams))
	}

	v, err := parseView(streams[0], gatewayAddr, simAddr)
	if err != nil {
		t.Fatalf("parseView: %v", err)
	}

	// Prove the "before" state first: TLS 1.3 really does leave the cleartext
	// accessor with nothing, which is the whole reason RBAC-011 needed a
	// decryption path at all.
	if cert, _ := v.ClientCertificate(); cert != nil {
		t.Fatal("the client Certificate parsed in the clear under TLS 1.3, which should be impossible")
	}

	kl, err := keylog.Parse(bytes.NewReader(simKeylog.Bytes()))
	if err != nil {
		t.Fatalf("parse mbapsdev's exported key log: %v", err)
	}
	if kl.Len() == 0 {
		t.Fatal("mbapsdev's KeyLogWriter produced no lines — the test's own TLS stack didn't export, so this " +
			"proves nothing about decryptedCertificate")
	}
	ev := &certify.Evidence{KeyLog: kl}

	cert, frames, err := decryptedCertificate(ev, v, tlsdecrypt.Client)
	if err != nil {
		t.Fatalf("decryptedCertificate(Client): %v", err)
	}
	if cert == nil || cert.Leaf() == nil || cert.Leaf().Info == nil {
		t.Fatal("decryptedCertificate recovered no usable Certificate")
	}
	if len(frames) == 0 {
		t.Error("the recovered Certificate carries no capture frames, so it could not be cited")
	}

	verdict, obs := roleExtensionVerdict(cert.Leaf().Info, "")
	if verdict != certify.Pass {
		t.Fatalf("role extension verdict = %s, want Pass (observed: %s)", verdict, obs)
	}
	if !strings.Contains(obs, "GridServiceSunSpec") {
		t.Errorf("observed = %q, want it to name the presented role", obs)
	}

	// The other half mbapsdev's export also unblocks: the DEVICE SIM's own
	// Certificate, which RBAC-011's second assertion reads to confirm it
	// carries no role extension.
	srvCert, srvFrames, err := decryptedCertificate(ev, v, tlsdecrypt.Server)
	if err != nil {
		t.Fatalf("decryptedCertificate(Server): %v", err)
	}
	if srvCert == nil || srvCert.Leaf() == nil || srvCert.Leaf().Info == nil {
		t.Fatal("decryptedCertificate recovered no usable server Certificate")
	}
	if len(srvFrames) == 0 {
		t.Error("the recovered server Certificate carries no capture frames")
	}
	if rf := roleOf(srvCert.Leaf().Info); rf.Present {
		t.Errorf("the device sim's certificate should carry no role extension, but one was found: %+v", rf)
	}
}
