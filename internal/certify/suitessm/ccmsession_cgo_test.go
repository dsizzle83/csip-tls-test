//go:build cgo

package suitessm

// ccmsession_cgo_test.go proves the SEAM: that a check in this suite can reach
// a completed session on an AES-CCM suite through the run's own PKI fixtures
// and its own frame window.
//
// The two halves either side of it are proven elsewhere — internal/tlsprobe's
// loopback tests establish sessions on all six mandated suites, and this
// package's own tests decide verdicts from synthetic captures. What neither
// covers is the plumbing between them: which role fixture is presented, which
// trust anchors are loaded, and whether the connection is registered on the
// check's window BEFORE the handshake, without which none of the session's
// frames could be cited.
//
// The peer is internal/mbtls — the same wolfSSL server sim/mbapsdev runs — for
// the same reason the probe exists at all: Go's crypto/tls cannot complete a
// CCM handshake from either end, so a crypto/tls peer could not answer the
// question this file asks.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/tlsprobe"
	"csip-tls-test/internal/wolfssl"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/mbap"

	modbuslib "github.com/simonvetter/modbus"
)

// TestMain initialises wolfSSL once for this test binary. The suite's package
// code reaches wolfSSL through internal/tlsprobe, which initialises the library
// lazily on its first Dial; the mbaps SERVER this file stands up does not, and
// wolfSSL_CTX_new before wolfSSL_Init is undefined behaviour rather than an
// error. Every other wolfSSL-linking test package in this repository does the
// same.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

// mbapsPeer stands up a conformant mbaps server on loopback and returns its
// address and a certify.PKI holding the fixtures a check would be given.
func mbapsPeer(t *testing.T) (string, *certify.PKI) {
	t.Helper()
	dir := t.TempDir()
	ca, caKey := testCA(t, "ssm-ccm-root")
	writePEM(t, dir+"/ca-cert.pem", "CERTIFICATE", ca.Raw)

	// The server leaf is minted here rather than with mintLeaf, which issues
	// CLIENT fixtures (extendedKeyUsage clientAuth). wolfSSL verifies the peer
	// in the library and raises EXTKEYUSE_AUTH_E for a server leaf that names
	// no serverAuth purpose, so a clientAuth-only leaf would fail this test for
	// a reason that has nothing to do with the suite under test.
	srvCert, srvKey := serverLeaf(t, ca, caKey)
	writePEM(t, dir+"/dev-server-cert.pem", "CERTIFICATE", srvCert.Raw)
	writeECKeyPEM(t, dir+"/dev-server-key.pem", srvKey)

	if err := os.Mkdir(dir+"/clients", 0o755); err != nil {
		t.Fatal(err)
	}
	cli, err := mintLeaf(ca, caKey, mintOpts{CommonName: "mbaps-client-grid-service", Role: "GridServiceSunSpec"})
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, dir+"/clients/grid-service-cert.pem", "CERTIFICATE", cli.Certificate[0])
	writeKeyPEM(t, dir+"/clients/grid-service-key.pem", cli)

	pki, err := certify.LoadPKI(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.Role(sessionRole); err != nil {
		t.Fatalf("the minted fixture set does not carry the role this suite presents: %v", err)
	}

	world, err := sim.NewSolarServerAdvanced("tcp://127.0.0.1:0", 5000, "SSM-CCM-SEAM-01")
	if err != nil {
		t.Fatalf("stand up the SunSpec register world: %v", err)
	}
	t.Cleanup(world.Stop)

	lis, err := mbtls.Listen("127.0.0.1:0",
		mbtls.DefaultServerProfile(dir+"/ca-cert.pem", dir+"/dev-server-cert.pem", dir+"/dev-server-key.pem"))
	if err != nil {
		t.Fatalf("mbtls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			sess, aerr := lis.Accept()
			if aerr != nil {
				if errors.Is(aerr, net.ErrClosed) {
					return
				}
				continue
			}
			go serveSunSpec(sess, world.Regs)
		}
	}()
	return lis.Addr().String(), pki
}

// serveSunSpec is sim/mbapsdev's dispatch loop reduced to the read path.
func serveSunSpec(sess *mbtls.Session, regs *sim.RegisterMap) {
	// REV0907-H2: this runs on its own accept-goroutine with no *testing.T
	// in scope (mirrors sim/mbapsdev/dispatch.go's own dispatchSession,
	// which reports the same class of teardown error the same way), so the
	// close error is logged at this goroutine's edge rather than dropped.
	defer func() {
		if err := sess.Close(); err != nil {
			log.Printf("[ccmsession_cgo_test] serveSunSpec: session close: %v", err)
		}
	}()
	for {
		_ = sess.Conn.SetDeadline(time.Now().Add(20 * time.Second))
		req, err := mbap.Decode(sess.Conn)
		if err != nil {
			return
		}
		var resp mbap.ADU
		rreq, perr := mbap.ParseReadReq(req.PDU)
		switch {
		case len(req.PDU) == 0 || req.PDU[0] != mbap.FCReadHolding:
			resp = mbap.Exception(req, mbap.ExIllegalFunction)
		case perr != nil:
			resp = mbap.Exception(req, mbap.ExIllegalAddress)
		default:
			values, herr := regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
				UnitId: req.UnitID, Addr: rreq.Addr, Quantity: rreq.Count,
			})
			if herr != nil {
				resp = mbap.Exception(req, mbap.ExIllegalAddress)
				break
			}
			pdu, berr := mbap.BuildReadResp(rreq, values)
			if berr != nil {
				return
			}
			resp = mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: pdu}
		}
		raw, eerr := mbap.Encode(resp)
		if eerr != nil {
			return
		}
		if _, werr := sess.Conn.Write(raw); werr != nil {
			return
		}
	}
}

// ctxFor builds the RunCtx a check is handed, with a real frame window so the
// claiming path — the one that decides whether a session's frames can be cited
// at all — is exercised rather than stubbed.
func ctxFor(t *testing.T, uid, addr string, pki *certify.PKI) (*certify.RunCtx, *certify.Window) {
	t.Helper()
	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: uid, ID: caseID(uid)},
		Suite:   suiteName,
		Targets: certify.Targets{Gateway: addr, GatewayHost: "127.0.0.1"},
		PKI:     pki,
		Log:     certify.DiscardLogger,
	}
	w := certify.NewWindow(uid, suiteName)
	w.Open(time.Now().UTC())
	if err := rc.AttachWindow(w); err != nil {
		t.Fatal(err)
	}
	return rc, w
}

// TestCompleteOnSuiteEstablishesEveryMandatedSuiteThroughTheRunsFixtures is the
// seam test. It runs the production path — the one CRYP-001 and CRYP-002 call —
// for all six mandated suites.
func TestCompleteOnSuiteEstablishesEveryMandatedSuiteThroughTheRunsFixtures(t *testing.T) {
	addr, pki := mbapsPeer(t)
	pf := preflight{Target: addr, PKI: pki}

	all := append(append([]tlsprobe.Suite{}, tlsprobe.Mandatory12...), tlsprobe.Mandatory13...)
	for _, want := range all {
		t.Run(want.IANA, func(t *testing.T) {
			rc, w := ctxFor(t, "ssm-conf-v0.8::CRYP-001", addr, pki)
			s, err := completeOnSuite(context.Background(), rc, pf, want.Code, "seam test")
			if err != nil {
				t.Fatalf("no session on %s through the run's own fixtures: %v", want, err)
			}
			if s.Suite.Code != want.Code {
				t.Errorf("the session reports suite 0x%04X, want 0x%04X", s.Suite.Code, want.Code)
			}
			if !s.Local.IsValid() || !s.Remote.IsValid() {
				t.Error("the session carries no socket addresses, so the citation phase could not find " +
					"its conversation in the capture")
			}
			if !s.Model1OK {
				t.Errorf("the session carried no answered Model 1 read: %s", s.Model1)
			}
			if len(w.Claims()) != 1 {
				t.Fatalf("%d connection(s) were claimed on the check's window, want exactly 1: an "+
					"unclaimed connection produces no citable evidence", len(w.Claims()))
			}
			t.Logf("%s", s.Describe())
		})
	}
}

// TestCompleteOnSuiteRefusesASuiteThePeerDoesNotOffer keeps the seam honest: a
// DUT that will not do a mandated suite must produce an error the check reports
// as a FAIL, not a session on something else.
func TestCompleteOnSuiteRefusesASuiteThePeerDoesNotOffer(t *testing.T) {
	addr, pki := mbapsPeer(t)
	// A peer that offers GCM only, in both versions — a legal configuration
	// (SunSpecTCP-20 requires the ability to disable suites), and a
	// non-conformant one (SunSpecTCP-17 requires all three).
	world, err := sim.NewSolarServerAdvanced("tcp://127.0.0.1:0", 5000, "SSM-CCM-GCM-ONLY")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.Stop)
	prof := mbtls.DefaultServerProfile(pki.CA, pki.Server.Cert, pki.Server.Key)
	prof.Suites12 = []string{mbtls.Mandated12[0]}
	prof.Suites13 = []string{mbtls.Mandated13[0]}
	lis, err := mbtls.Listen("127.0.0.1:0", prof)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			sess, aerr := lis.Accept()
			if aerr != nil {
				if errors.Is(aerr, net.ErrClosed) {
					return
				}
				continue
			}
			go serveSunSpec(sess, world.Regs)
		}
	}()

	gcmOnly := lis.Addr().String()
	pf := preflight{Target: gcmOnly, PKI: pki}
	rc, w := ctxFor(t, "ssm-conf-v0.8::CRYP-001", gcmOnly, pki)
	if s, err := completeOnSuite(context.Background(), rc, pf, tlsprobe.TLS12CCM8.Code, "seam refusal"); err == nil {
		t.Fatalf("a session was established on %s against a peer that offers only GCM (%s)",
			tlsprobe.TLS12CCM8, s.Negotiated)
	}
	// Even a refused handshake must have been claimed, or the refusal itself
	// would have no citable frames.
	if len(w.Claims()) != 1 {
		t.Errorf("%d connection(s) claimed on a REFUSED handshake, want 1", len(w.Claims()))
	}
	_ = addr
}

// writeKeyPEM writes a minted leaf's private key beside its certificate, in the
// SEC 1 form certify.LoadPKI and wolfSSL both read.
func writeKeyPEM(t *testing.T, path string, cert tls.Certificate) {
	t.Helper()
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the minted leaf's key is %T, not an EC key (the mandated suites are ECDSA-only)",
			cert.PrivateKey)
	}
	writeECKeyPEM(t, path, key)
}

func writeECKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal the key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// serverLeaf mints a P-256 serverAuth leaf under ca, with a 127.0.0.1 SAN.
func serverLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "ssm-ccm-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
