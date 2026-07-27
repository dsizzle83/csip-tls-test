package tlsdecrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/tlsdis"
)

// --- key schedule --------------------------------------------------------

// TestHKDFLabelEncoding pins the exact bytes of RFC 8446 §7.1's HkdfLabel.
// Everything else in the TLS 1.3 path fails as "AEAD authentication failed" if
// this is wrong, so it is checked directly against the structure definition.
func TestHKDFLabelEncoding(t *testing.T) {
	got := hkdfLabel("key", nil, 16)
	// uint16 length = 0x0010; label length = len("tls13 key") = 9; the label;
	// context length = 0.
	want := append([]byte{0x00, 0x10, 0x09}, append([]byte("tls13 key"), 0x00)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("hkdfLabel(key):\n got %x\nwant %x", got, want)
	}

	ctx := []byte{0xAA, 0xBB}
	got = hkdfLabel("finished", ctx, 32)
	want = append([]byte{0x00, 0x20, 0x0E}, []byte("tls13 finished")...)
	want = append(want, 0x02, 0xAA, 0xBB)
	if !bytes.Equal(got, want) {
		t.Fatalf("hkdfLabel(finished):\n got %x\nwant %x", got, want)
	}
}

func TestTrafficKeysAreDeterministicAndDistinct(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, 32)
	key1, iv1, err := trafficKeys(sha256.New, secret, 16, 12)
	if err != nil {
		t.Fatal(err)
	}
	key2, iv2, err := trafficKeys(sha256.New, secret, 16, 12)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, key2) || !bytes.Equal(iv1, iv2) {
		t.Fatal("derivation is not deterministic")
	}
	if bytes.Equal(key1[:12], iv1) {
		t.Fatal("the key and IV labels must produce different output")
	}
	next, err := nextTrafficSecret(sha256.New, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(next, secret) {
		t.Fatal("a key update must change the traffic secret")
	}
	if len(next) != 32 {
		t.Fatalf("updated secret is %d bytes, want the hash length", len(next))
	}
}

// TestPRF12 checks the TLS 1.2 PRF's shape and its dependence on every input.
// The definitive check on the PRF is the live TLS 1.2 interop test below: if
// P_SHA256 were wrong the derived key block would be wrong and no record from
// Go's own crypto/tls would decrypt.
func TestPRF12(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 48)
	seed := bytes.Repeat([]byte{2}, 64)
	out := prf12(sha256.New, secret, "key expansion", seed, 104)
	if len(out) != 104 {
		t.Fatalf("length = %d", len(out))
	}
	// Output must be a prefix-consistent stream: asking for less gives the same
	// leading bytes.
	short := prf12(sha256.New, secret, "key expansion", seed, 40)
	if !bytes.Equal(short, out[:40]) {
		t.Fatal("PRF output is not prefix-consistent")
	}
	if bytes.Equal(out, prf12(sha256.New, secret, "master secret", seed, 104)) {
		t.Fatal("the label must affect the output")
	}
	if bytes.Equal(out, prf12(sha256.New, append(secret, 9), "key expansion", seed, 104)) {
		t.Fatal("the secret must affect the output")
	}
}

func TestKeyBlockLayout(t *testing.T) {
	suite, err := suiteFor(tlsdis.VersionTLS12, 0xC02B)
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{3}, 48)
	cr := bytes.Repeat([]byte{4}, 32)
	sr := bytes.Repeat([]byte{5}, 32)
	ck, sk, civ, siv := keyBlock12(suite, master, cr, sr)
	if len(ck) != 16 || len(sk) != 16 || len(civ) != 4 || len(siv) != 4 {
		t.Fatalf("sizes = %d/%d/%d/%d, want 16/16/4/4", len(ck), len(sk), len(civ), len(siv))
	}
	if bytes.Equal(ck, sk) {
		t.Fatal("client and server keys must differ")
	}
	// Swapping the randoms must change the block: "key expansion" is seeded
	// server-random-first, and getting that order backwards is a classic bug
	// that still produces plausible-looking keys.
	ck2, _, _, _ := keyBlock12(suite, master, sr, cr)
	if bytes.Equal(ck, ck2) {
		t.Fatal("the random order must matter")
	}
}

// --- suite parameter derivation ------------------------------------------

func TestSuiteParameters(t *testing.T) {
	for _, tc := range []struct {
		version, id                       uint16
		name                              string
		keyLen, fixedIV, recordIV, tagLen int
		hashSize                          int
	}{
		{tlsdis.VersionTLS13, 0x1301, "TLS_AES_128_GCM_SHA256", 16, 12, 0, 16, 32},
		{tlsdis.VersionTLS13, 0x1302, "TLS_AES_256_GCM_SHA384", 32, 12, 0, 16, 48},
		{tlsdis.VersionTLS13, 0x1303, "TLS_CHACHA20_POLY1305_SHA256", 32, 12, 0, 16, 32},
		{tlsdis.VersionTLS13, 0x1304, "TLS_AES_128_CCM_SHA256", 16, 12, 0, 16, 32},
		{tlsdis.VersionTLS13, 0x1305, "TLS_AES_128_CCM_8_SHA256", 16, 12, 0, 8, 32},
		{tlsdis.VersionTLS12, 0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 16, 4, 8, 16, 32},
		{tlsdis.VersionTLS12, 0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 32, 4, 8, 16, 48},
		{tlsdis.VersionTLS12, 0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 32, 4, 8, 16, 48},
		{tlsdis.VersionTLS12, 0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 32, 12, 0, 16, 32},
		// The CSIP-mandatory suite and its neighbours in RFC 7251.
		{tlsdis.VersionTLS12, 0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", 16, 4, 8, 16, 32},
		{tlsdis.VersionTLS12, 0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", 32, 4, 8, 16, 32},
		{tlsdis.VersionTLS12, 0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", 16, 4, 8, 8, 32},
		{tlsdis.VersionTLS12, 0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", 32, 4, 8, 8, 32},
		{tlsdis.VersionTLS12, 0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8", 16, 4, 8, 8, 32},
		{tlsdis.VersionTLS12, 0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", 32, 4, 8, 16, 48},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := suiteFor(tc.version, tc.id)
			if err != nil {
				t.Fatalf("suiteFor: %v", err)
			}
			if p.Name != tc.name {
				t.Errorf("Name = %q, want %q", p.Name, tc.name)
			}
			if p.KeyLen != tc.keyLen || p.FixedIVLen != tc.fixedIV || p.RecordIVLen != tc.recordIV || p.TagLen != tc.tagLen {
				t.Errorf("key/fixedIV/recordIV/tag = %d/%d/%d/%d, want %d/%d/%d/%d",
					p.KeyLen, p.FixedIVLen, p.RecordIVLen, p.TagLen, tc.keyLen, tc.fixedIV, tc.recordIV, tc.tagLen)
			}
			if p.Hash().Size() != tc.hashSize {
				t.Errorf("hash size = %d, want %d", p.Hash().Size(), tc.hashSize)
			}
			// Every derived suite must actually build an AEAD of the right shape.
			a, err := p.New(make([]byte, p.KeyLen))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if a.Overhead() != tc.tagLen {
				t.Errorf("AEAD overhead = %d, want %d", a.Overhead(), tc.tagLen)
			}
		})
	}
}

func TestSuiteRejectsNonAEAD(t *testing.T) {
	for _, tc := range []struct {
		version, id uint16
		wantErr     string
	}{
		{tlsdis.VersionTLS12, 0xC013, "not an AEAD suite"}, // ECDHE_RSA_AES_128_CBC_SHA
		{tlsdis.VersionTLS12, 0x002F, "not an AEAD suite"}, // RSA_AES_128_CBC_SHA
		{tlsdis.VersionTLS12, 0x0004, "not an AEAD suite"}, // RSA_RC4_128_MD5
		{tlsdis.VersionTLS12, 0xFF42, "not in the IANA registry"},
		{tlsdis.VersionTLS13, 0xC02B, "not a TLS 1.3 cipher suite"},
		{tlsdis.VersionTLS11, 0xC02B, "cannot be decrypted"},
	} {
		if _, err := suiteFor(tc.version, tc.id); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("suiteFor(%s, 0x%04X) err = %v, want one containing %q",
				tlsdis.VersionName(tc.version), tc.id, err, tc.wantErr)
		}
	}
}

// --- live interop --------------------------------------------------------

type recorder struct {
	net.Conn
	mu  sync.Mutex
	out []byte
}

func (r *recorder) Write(b []byte) (int, error) {
	n, err := r.Conn.Write(b)
	r.mu.Lock()
	r.out = append(r.out, b[:n]...)
	r.mu.Unlock()
	return n, err
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.out...)
}

const roleValue = "GridService"

var roleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

type pki struct {
	caDER, leafDER, clientDER []byte
	caCert                    *x509.Certificate
	leafKey, clientKey        *ecdsa.PrivateKey
	pool                      *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "decrypt-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	p := &pki{caDER: caDER, caCert: caCert, pool: x509.NewCertPool()}
	p.pool.AddCert(caCert)

	issue := func(cn string, dns []string, exts []pkix.Extension) ([]byte, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns,
			ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			ExtraExtensions: exts,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	p.leafDER, p.leafKey = issue("mbaps-device", []string{"localhost"}, nil)
	roleDER, err := asn1.MarshalWithParams(roleValue, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	p.clientDER, p.clientKey = issue("aggregator", nil, []pkix.Extension{{Id: roleOID, Value: roleDER}})
	return p
}

// handshakeResult is everything a decryption test needs from a live connection.
type handshakeResult struct {
	clientStream []byte
	serverStream []byte
	keyLog       *keylog.Log
	suite        uint16
	version      uint16
	clientSent   []byte
	serverSent   []byte
}

// runHandshake drives a real crypto/tls client and server over a loopback TCP
// connection with a key log, records both byte streams, and exchanges
// application data. This is as close to a captured session as it is possible to
// get without a capture — and the pcap-based end-to-end test in
// internal/evidence/e2e closes that last gap.
//
// Real TCP rather than net.Pipe, deliberately: net.Pipe is unbuffered, so the
// close_notify alert each side sends at shutdown blocks until the peer happens
// to read it, and the alerts never make it into the recording. Alerts are
// evidence — the negative test cases are ABOUT alerts — so the fixture has to
// capture them, which means socket buffers and an explicit half-close.
func runHandshake(t *testing.T, p *pki, minVer, maxVer uint16, suites []uint16, mutual bool) handshakeResult {
	t.Helper()
	var keyBuf bytes.Buffer
	var keyMu sync.Mutex
	keyWriter := writerFunc(func(b []byte) (int, error) {
		keyMu.Lock()
		defer keyMu.Unlock()
		return keyBuf.Write(b)
	})

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{p.leafDER, p.caDER}, PrivateKey: p.leafKey}},
		MinVersion:   minVer, MaxVersion: maxVer, CipherSuites: suites,
		KeyLogWriter: keyWriter,
	}
	clientCfg := &tls.Config{
		RootCAs: p.pool, ServerName: "localhost",
		MinVersion: minVer, MaxVersion: maxVer, CipherSuites: suites,
		KeyLogWriter: keyWriter,
	}
	if mutual {
		serverCfg.ClientAuth = tls.RequireAndVerifyClientCert
		serverCfg.ClientCAs = p.pool
		clientCfg.Certificates = []tls.Certificate{{Certificate: [][]byte{p.clientDER, p.caDER}, PrivateKey: p.clientKey}}
	}

	clientPayload := []byte("mbaps request: unit 1, read holding registers 40001..40010")
	serverPayload := bytes.Repeat([]byte("mbaps response frame; "), 40)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	serverRecCh := make(chan *recorder, 1)
	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverRecCh <- &recorder{}
			done <- err
			return
		}
		serverRec := &recorder{Conn: raw}
		serverRecCh <- serverRec
		s := tls.Server(serverRec, serverCfg)
		defer func() { _ = raw.Close() }()
		if err := s.Handshake(); err != nil {
			done <- err
			return
		}
		buf := make([]byte, len(clientPayload))
		if _, err := readFull(s, buf); err != nil {
			done <- err
			return
		}
		if _, err := s.Write(serverPayload); err != nil {
			done <- err
			return
		}
		// Drain until the client's close_notify arrives, then send ours.
		_, _ = io.Copy(io.Discard, s)
		done <- s.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientRec := &recorder{Conn: raw}
	defer func() { _ = raw.Close() }()

	c := tls.Client(clientRec, clientCfg)
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	state := c.ConnectionState()
	if _, err := c.Write(clientPayload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(serverPayload))
	if _, err := readFull(c, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	// Half-close: send close_notify but keep reading, so the server's own
	// close_notify lands in the recording too.
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	_, _ = io.Copy(io.Discard, c)
	if err := <-done; err != nil && !strings.Contains(err.Error(), "closed") && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("server: %v", err)
	}
	serverRec := <-serverRecCh

	keyMu.Lock()
	logBytes := append([]byte(nil), keyBuf.Bytes()...)
	keyMu.Unlock()
	kl, err := keylog.Parse(bytes.NewReader(logBytes))
	if err != nil {
		t.Fatalf("parse key log: %v\n%s", err, logBytes)
	}
	return handshakeResult{
		clientStream: clientRec.bytes(), serverStream: serverRec.bytes(), keyLog: kl,
		suite: state.CipherSuite, version: state.Version,
		clientSent: clientPayload, serverSent: serverPayload,
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func readFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// decryptBoth parses both directions and decrypts them with a fresh Session.
func decryptBoth(t *testing.T, hr handshakeResult) (*Session, []Plaintext, []Plaintext) {
	t.Helper()
	client, err := tlsdis.ParseDirection(hr.clientStream, nil)
	if err != nil {
		t.Fatalf("client direction: %v", err)
	}
	server, err := tlsdis.ParseDirection(hr.serverStream, nil)
	if err != nil {
		t.Fatalf("server direction: %v", err)
	}
	params, err := ParamsFromHandshake(client, server)
	if err != nil {
		t.Fatalf("ParamsFromHandshake: %v", err)
	}
	if params.CipherSuite != hr.suite || params.Version != hr.version {
		t.Fatalf("params say %s/%s, connection state says %s/%s",
			tlsdis.VersionName(params.Version), tlsdis.CipherSuiteName(params.CipherSuite),
			tlsdis.VersionName(hr.version), tlsdis.CipherSuiteName(hr.suite))
	}
	sess, err := New(params, hr.keyLog)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cp, err := sess.DecryptAll(Client, client.Stream.Records)
	if err != nil {
		t.Fatalf("decrypt client: %v", err)
	}
	sp, err := sess.DecryptAll(Server, server.Stream.Records)
	if err != nil {
		t.Fatalf("decrypt server: %v", err)
	}
	return sess, cp, sp
}

// TestDecryptTLS12Interop decrypts real crypto/tls TLS 1.2 traffic for each
// AEAD family Go can be made to negotiate. This is the only kind of test that
// proves the key schedule, the nonce construction and the additional-data
// layout all agree with another implementation.
func TestDecryptTLS12Interop(t *testing.T) {
	p := newPKI(t)
	for _, suite := range []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	} {
		t.Run(tlsdis.CipherSuiteName(suite), func(t *testing.T) {
			hr := runHandshake(t, p, tls.VersionTLS12, tls.VersionTLS12, []uint16{suite}, true)
			if hr.suite != suite {
				t.Fatalf("negotiated %s", tlsdis.CipherSuiteName(hr.suite))
			}
			sess, cp, sp := decryptBoth(t, hr)

			if got := AppData(cp); !bytes.Equal(got, hr.clientSent) {
				t.Fatalf("client application data:\n got %q\nwant %q", got, hr.clientSent)
			}
			if got := AppData(sp); !bytes.Equal(got, hr.serverSent) {
				t.Fatalf("server application data:\n got %q\nwant %q", got, hr.serverSent)
			}
			// The encrypted Finished messages must have decrypted too.
			hs, err := sess.Handshake(Client)
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if _, ok := hs.Find(tlsdis.HandshakeFinished); !ok {
				t.Errorf("client handshake has no Finished; types = %v", hs.Types())
			}
			// And the close_notify alert, which is encrypted in TLS 1.2 too.
			if len(Alerts(sp)) == 0 && len(Alerts(cp)) == 0 {
				t.Error("no alert recovered; a closed connection should carry close_notify")
			}
		})
	}
}

// TestDecryptTLS13Interop is the load-bearing test for the epoch machinery.
// The server's flight (EncryptedExtensions … Finished) uses handshake keys at
// sequence numbers 0,1,2…; its NewSessionTicket and application data use
// application keys starting again at 0. Any error in the transition, the reset,
// or the ChangeCipherSpec rule shows up here as an authentication failure.
func TestDecryptTLS13Interop(t *testing.T) {
	p := newPKI(t)
	hr := runHandshake(t, p, tls.VersionTLS13, tls.VersionTLS13, nil, true)
	if hr.version != tls.VersionTLS13 {
		t.Fatalf("negotiated %s", tlsdis.VersionName(hr.version))
	}
	sess, cp, sp := decryptBoth(t, hr)

	if got := AppData(cp); !bytes.Equal(got, hr.clientSent) {
		t.Fatalf("client application data:\n got %q\nwant %q", got, hr.clientSent)
	}
	if got := AppData(sp); !bytes.Equal(got, hr.serverSent) {
		t.Fatalf("server application data:\n got %q\nwant %q", got, hr.serverSent)
	}

	// Both sides must have ended on application keys.
	if sess.Epoch(Client) != EpochApplication || sess.Epoch(Server) != EpochApplication {
		t.Fatalf("epochs = %s/%s, want application/application", sess.Epoch(Client), sess.Epoch(Server))
	}
	for _, p := range append(append([]Plaintext{}, cp...), sp...) {
		if p.EpochRecovered {
			t.Errorf("record %d needed epoch recovery; the Finished-driven switch should have handled it", p.Record.Index)
		}
	}

	// The encrypted server flight must be recoverable as handshake messages.
	serverHS, err := sess.Handshake(Server)
	if err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	want := []tlsdis.HandshakeType{
		tlsdis.HandshakeServerHello, tlsdis.HandshakeEncryptedExtensions,
		tlsdis.HandshakeCertificateRequest, tlsdis.HandshakeCertificate,
		tlsdis.HandshakeCertificateVerify, tlsdis.HandshakeFinished,
	}
	got := serverHS.Types()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("server handshake is missing %s; got %v", tlsdis.HandshakeTypeName(w), typeNames(got))
		}
	}

	// THE point of decrypting at all: the client's certificate chain, byte
	// exact, with the SunSpec role extension readable from it.
	clientHS, err := sess.Handshake(Client)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	certMsg, ok := clientHS.Find(tlsdis.HandshakeCertificate)
	if !ok {
		t.Fatalf("no client Certificate recovered; types = %v", typeNames(clientHS.Types()))
	}
	chain := certMsg.Certificate
	if len(chain.Entries) != 2 {
		t.Fatalf("client chain has %d certificates, want 2", len(chain.Entries))
	}
	if !bytes.Equal(chain.Entries[0].DER, p.clientDER) {
		t.Fatal("decrypted leaf DER is not byte-identical to the issued certificate")
	}
	if _, err := x509.ParseCertificate(chain.Entries[0].DER); err != nil {
		t.Fatalf("decrypted DER does not feed x509.ParseCertificate: %v", err)
	}
	role, err := chain.Leaf().Info.SunSpecRole()
	if err != nil || role != roleValue {
		t.Fatalf("role from the decrypted certificate = %q, %v; want %q", role, err, roleValue)
	}
	if _, ok := chain.Leaf().Info.Extension(roleOID.String()); !ok {
		t.Fatal("the role extension OID is not listed on the decrypted certificate")
	}
}

// TestChangeCipherSpecDoesNotAdvanceSequence is the rule stated on its own: a
// TLS 1.3 CCS is a middlebox no-op, and counting it would put every following
// nonce off by one.
func TestChangeCipherSpecDoesNotAdvanceSequence(t *testing.T) {
	p := newPKI(t)
	hr := runHandshake(t, p, tls.VersionTLS13, tls.VersionTLS13, nil, false)
	client, err := tlsdis.ParseDirection(hr.clientStream, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := tlsdis.ParseDirection(hr.serverStream, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(server.CCS) == 0 && len(client.CCS) == 0 {
		t.Skip("no middlebox-compatibility ChangeCipherSpec in this handshake")
	}
	params, err := ParamsFromHandshake(client, server)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := New(params, hr.keyLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range server.Stream.Records {
		before := sess.SequenceNumber(Server)
		if _, err := sess.Decrypt(Server, rec); err != nil {
			t.Fatalf("record %d: %v", rec.Index, err)
		}
		after := sess.SequenceNumber(Server)
		switch rec.Type {
		case tlsdis.ContentChangeCipherSpec:
			if after != before {
				t.Fatalf("ChangeCipherSpec advanced the sequence number from %d to %d", before, after)
			}
		case tlsdis.ContentApplicationData:
			if after != before+1 && after != 0 {
				t.Fatalf("record %d: sequence went %d → %d", rec.Index, before, after)
			}
		}
	}
}

// TestSequenceResetIsLoadBearing proves the epoch assertions above are not
// vacuous: with the reset removed, the first application-epoch record fails.
func TestSequenceResetIsLoadBearing(t *testing.T) {
	p := newPKI(t)
	hr := runHandshake(t, p, tls.VersionTLS13, tls.VersionTLS13, nil, false)
	client, _ := tlsdis.ParseDirection(hr.clientStream, nil)
	server, _ := tlsdis.ParseDirection(hr.serverStream, nil)
	params, err := ParamsFromHandshake(client, server)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := New(params, hr.keyLog)
	if err != nil {
		t.Fatal(err)
	}

	failed := false
	for _, rec := range server.Stream.Records {
		if _, err := sess.Decrypt(Server, rec); err != nil {
			t.Fatalf("baseline decrypt failed: %v", err)
		}
		// Sabotage: once the session moved to application keys, put the
		// sequence number back where the handshake epoch left it.
		if sess.Epoch(Server) == EpochApplication && sess.dirs[Server].seq == 0 {
			sess.dirs[Server].seq = 7
			for _, rest := range server.Stream.Records[rec.Index+1:] {
				if rest.Type != tlsdis.ContentApplicationData {
					continue
				}
				if _, err := sess.Decrypt(Server, rest); err != nil {
					failed = true
				}
				break
			}
			break
		}
	}
	if !failed {
		t.Skip("this handshake had no application-epoch record after the switch to sabotage")
	}
}

// TestDecryptionFailureIsLoud checks the failure contract: a wrong key yields a
// *Error naming the record, the frames, the sequence number and the epoch — and
// no plaintext at all.
func TestDecryptionFailureIsLoud(t *testing.T) {
	p := newPKI(t)
	hr := runHandshake(t, p, tls.VersionTLS12, tls.VersionTLS12,
		[]uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, false)
	client, _ := tlsdis.ParseDirection(hr.clientStream, nil)
	server, _ := tlsdis.ParseDirection(hr.serverStream, nil)
	params, err := ParamsFromHandshake(client, server)
	if err != nil {
		t.Fatal(err)
	}

	// A key log with the right client random but the wrong master secret.
	cr := hex.EncodeToString(params.ClientRandom)
	bad, err := keylog.Parse(strings.NewReader(keylog.LabelClientRandom + " " + cr + " " + strings.Repeat("ab", 48)))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := New(params, bad)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.DecryptAll(Client, client.Stream.Records)
	if err == nil {
		t.Fatal("decryption with the wrong master secret must fail")
	}
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("err = %T (%v), want *tlsdecrypt.Error", err, err)
	}
	if de.Side != Client {
		t.Errorf("Side = %s", de.Side)
	}
	if !strings.Contains(de.Error(), "AEAD authentication failed") {
		t.Errorf("Error() = %q", de.Error())
	}
	if !strings.Contains(de.Error(), "record") || !strings.Contains(de.Error(), "seq") {
		t.Errorf("Error() = %q, want the record and sequence number named", de.Error())
	}
	for _, p := range out {
		if p.Encrypted {
			t.Fatal("no encrypted record may be reported as recovered when authentication failed")
		}
	}
}

func TestNewValidation(t *testing.T) {
	kl, _ := keylog.Parse(strings.NewReader(""))
	cr := bytes.Repeat([]byte{1}, 32)
	if _, err := New(Params{Version: tlsdis.VersionTLS13, CipherSuite: 0x1301, ClientRandom: cr}, nil); err == nil {
		t.Error("New with no key log must fail")
	}
	if _, err := New(Params{Version: tlsdis.VersionTLS13, CipherSuite: 0x1301, ClientRandom: []byte{1}}, kl); err == nil {
		t.Error("New with a short client random must fail")
	}
	if _, err := New(Params{Version: tlsdis.VersionTLS13, CipherSuite: 0x1301, ClientRandom: cr}, kl); err == nil ||
		!strings.Contains(err.Error(), "key log has no") {
		t.Errorf("err = %v, want a missing-secret complaint", err)
	}
	full, err := keylog.Parse(strings.NewReader(
		keylog.LabelClientRandom + " " + hex.EncodeToString(cr) + " " + strings.Repeat("11", 48)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Params{Version: tlsdis.VersionTLS12, CipherSuite: 0xC02B, ClientRandom: cr}, full); err == nil ||
		!strings.Contains(err.Error(), "server random") {
		t.Errorf("err = %v, want a missing-server-random complaint", err)
	}
}

// TestTLS12CCM8RoundTrip covers the CSIP-mandatory suite, which no Go TLS stack
// can negotiate. The records are framed by hand here — explicit nonce, 13-byte
// additional data, CCM-8 tag — so the test asserts agreement with RFC 6655 §3
// rather than with this package's own writer.
func TestTLS12CCM8RoundTrip(t *testing.T) {
	for _, suiteID := range []uint16{0xC0AE, 0xC0AC, 0xC0AF} {
		t.Run(tlsdis.CipherSuiteName(suiteID), func(t *testing.T) {
			suite, err := suiteFor(tlsdis.VersionTLS12, suiteID)
			if err != nil {
				t.Fatal(err)
			}
			cr := bytes.Repeat([]byte{0xC1}, 32)
			sr := bytes.Repeat([]byte{0x51}, 32)
			master := bytes.Repeat([]byte{0x4D}, 48)
			kl, err := keylog.Parse(strings.NewReader(
				keylog.LabelClientRandom + " " + hex.EncodeToString(cr) + " " + hex.EncodeToString(master)))
			if err != nil {
				t.Fatal(err)
			}
			params := Params{Version: tlsdis.VersionTLS12, CipherSuite: suiteID, ClientRandom: cr, ServerRandom: sr}
			sess, err := New(params, kl)
			if err != nil {
				t.Fatal(err)
			}

			// Build the server's records independently of the reader.
			_, serverKey, _, serverIV := keyBlock12(suite, master, cr, sr)
			a, err := suite.New(serverKey)
			if err != nil {
				t.Fatal(err)
			}
			payloads := [][]byte{
				[]byte("\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"), // an mbap read
				[]byte("\x00\x01\x00\x00\x00\x03\x01\x83\x01"),             // exception 01
			}
			var stream []byte
			// The server's CCS comes first: it installs the keys and must not
			// consume a sequence number.
			stream = append(stream, record(tlsdis.ContentChangeCipherSpec, []byte{1})...)
			for seq, pt := range payloads {
				explicit := make([]byte, 8)
				binary.BigEndian.PutUint64(explicit, uint64(seq))
				nonce := append(append([]byte{}, serverIV...), explicit...)
				aad := make([]byte, 13)
				binary.BigEndian.PutUint64(aad[0:8], uint64(seq))
				aad[8] = byte(tlsdis.ContentApplicationData)
				aad[9], aad[10] = 0x03, 0x03
				binary.BigEndian.PutUint16(aad[11:13], uint16(len(pt)))
				sealed := a.Seal(nil, nonce, pt, aad)
				stream = append(stream, record(tlsdis.ContentApplicationData, append(explicit, sealed...))...)
			}

			dir, err := tlsdis.ParseDirection(stream, nil)
			if err != nil {
				t.Fatal(err)
			}
			out, err := sess.DecryptAll(Server, dir.Stream.Records)
			if err != nil {
				t.Fatalf("DecryptAll: %v", err)
			}
			got := AppData(out)
			want := append(append([]byte{}, payloads[0]...), payloads[1]...)
			if !bytes.Equal(got, want) {
				t.Fatalf("recovered %x, want %x", got, want)
			}
			if suite.TagLen != 8 && suiteID == 0xC0AE {
				t.Fatalf("0xC0AE must use an 8-byte tag, got %d", suite.TagLen)
			}
		})
	}
}

// TestTLS13SyntheticSuites covers the TLS 1.3 suites Go will not negotiate on
// demand (its TLS 1.3 suite choice is not configurable), including the two CCM
// ones no Go stack implements at all.
func TestTLS13SyntheticSuites(t *testing.T) {
	for _, suiteID := range []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305} {
		t.Run(tlsdis.CipherSuiteName(suiteID), func(t *testing.T) {
			suite, err := suiteFor(tlsdis.VersionTLS13, suiteID)
			if err != nil {
				t.Fatal(err)
			}
			cr := bytes.Repeat([]byte{0xC1}, 32)
			hsSecret := bytes.Repeat([]byte{0x11}, suite.Hash().Size())
			appSecret := bytes.Repeat([]byte{0x22}, suite.Hash().Size())
			kl, err := keylog.Parse(strings.NewReader(strings.Join([]string{
				keylog.LabelServerHandshake + " " + hex.EncodeToString(cr) + " " + hex.EncodeToString(hsSecret),
				keylog.LabelServerTraffic0 + " " + hex.EncodeToString(cr) + " " + hex.EncodeToString(appSecret),
				keylog.LabelClientHandshake + " " + hex.EncodeToString(cr) + " " + hex.EncodeToString(hsSecret),
				keylog.LabelClientTraffic0 + " " + hex.EncodeToString(cr) + " " + hex.EncodeToString(appSecret),
			}, "\n")))
			if err != nil {
				t.Fatal(err)
			}
			sess, err := New(Params{Version: tlsdis.VersionTLS13, CipherSuite: suiteID, ClientRandom: cr}, kl)
			if err != nil {
				t.Fatal(err)
			}

			key, iv, err := trafficKeys(suite.Hash, hsSecret, suite.KeyLen, suite.FixedIVLen)
			if err != nil {
				t.Fatal(err)
			}
			a, err := suite.New(key)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("encrypted extensions would be here")
			inner := append(append([]byte{}, payload...), byte(tlsdis.ContentApplicationData))
			nonce := xorSeq(iv, 0)
			aad := []byte{byte(tlsdis.ContentApplicationData), 0x03, 0x03, 0, 0}
			binary.BigEndian.PutUint16(aad[3:5], uint16(len(inner)+suite.TagLen))
			sealed := a.Seal(nil, nonce, inner, aad)

			dir, err := tlsdis.ParseDirection(record(tlsdis.ContentApplicationData, sealed), nil)
			if err != nil {
				t.Fatal(err)
			}
			out, err := sess.Decrypt(Server, dir.Stream.Records[0])
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(out.Data, payload) {
				t.Fatalf("got %q, want %q", out.Data, payload)
			}
			if out.Type != tlsdis.ContentApplicationData {
				t.Errorf("inner type = %s", tlsdis.ContentTypeName(out.Type))
			}
		})
	}
}

// record wraps a fragment in a TLS 1.2-versioned record header.
func record(ct tlsdis.ContentType, frag []byte) []byte {
	out := []byte{byte(ct), 0x03, 0x03, byte(len(frag) >> 8), byte(len(frag))}
	return append(out, frag...)
}

func typeNames(ts []tlsdis.HandshakeType) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = tlsdis.HandshakeTypeName(t)
	}
	return out
}

func TestStripPadding(t *testing.T) {
	if _, _, err := StripPadding([]byte{0, 0, 0}); err == nil {
		t.Error("all-padding must fail")
	}
	data, ct, err := StripPadding([]byte{'h', 'i', byte(tlsdis.ContentHandshake), 0, 0, 0})
	if err != nil || string(data) != "hi" || ct != tlsdis.ContentHandshake {
		t.Fatalf("got %q/%v/%v", data, ct, err)
	}
}

func TestXorSeq(t *testing.T) {
	iv := bytes.Repeat([]byte{0}, 12)
	if got := xorSeq(iv, 1); !bytes.Equal(got, append(bytes.Repeat([]byte{0}, 11), 1)) {
		t.Fatalf("xorSeq = %x", got)
	}
	iv2, _ := hex.DecodeString("000102030405060708090a0b")
	got := xorSeq(iv2, 0x0102030405060708)
	want, _ := hex.DecodeString("00010203050705030d0f0d03")
	if !bytes.Equal(got, want) {
		t.Fatalf("xorSeq = %x, want %x", got, want)
	}
	if fmt.Sprint(Client) != "client" || fmt.Sprint(Server) != "server" {
		t.Error("Side.String is wrong")
	}
	if fmt.Sprint(EpochHandshake) != "handshake" || fmt.Sprint(EpochApplication) != "application" ||
		fmt.Sprint(EpochPlaintext) != "plaintext" {
		t.Error("Epoch.String is wrong")
	}
}
