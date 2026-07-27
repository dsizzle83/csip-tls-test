package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
)

// roleOID is the Secure SunSpec Modbus client-role extension, the private
// enterprise OID the RBAC test cases turn on.
var roleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

const clientRole = "GridService"

// --- the loopback pipeline ------------------------------------------------

type testPKI struct {
	caDER, serverDER, clientDER []byte
	caCert                      *x509.Certificate
	serverKey, clientKey        *ecdsa.PrivateKey
	pool                        *x509.CertPool
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e-ca"},
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
	p := &testPKI{caDER: caDER, caCert: caCert, pool: x509.NewCertPool()}
	p.pool.AddCert(caCert)

	issue := func(cn string, ips []net.IP, exts []pkix.Extension) ([]byte, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IPAddresses: ips, ExtraExtensions: exts,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	p.serverDER, p.serverKey = issue("mbaps-device", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	roleValue, err := asn1.MarshalWithParams(clientRole, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	p.clientDER, p.clientKey = issue("aggregator", nil, []pkix.Extension{{Id: roleOID, Value: roleValue}})
	return p
}

// captured is everything one captured TLS session produced.
type captured struct {
	pcapPath   string
	keylogPath string
	summary    capture.Summary
	packets    []pcapng.Packet
	clientAddr string
	serverAddr string
	clientSent []byte
	serverSent []byte
	version    uint16
	suite      uint16
}

// runCapturedSession is the pipeline's input half: capture loopback, run a real
// mutually-authenticated TLS session over it, stop the capture.
func runCapturedSession(t *testing.T, p *testPKI, minVer, maxVer uint16, suites []uint16) captured {
	t.Helper()
	if _, err := capture.Detect(); err != nil {
		t.Skipf("no capture tool available: %v (install wireshark-common or tcpdump)", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	c := captured{
		pcapPath:   filepath.Join(dir, "session.pcapng"),
		keylogPath: filepath.Join(dir, "session.keylog"),
		serverAddr: ln.Addr().String(),
		clientSent: []byte("mbaps: write holding register 100 = 500 as role " + clientRole),
		// Long enough to span several TLS records and several TCP segments, so
		// the reassembler and the record-layer coalescing are both exercised.
		serverSent: bytes.Repeat([]byte("mbaps exception 01 (not authorized); "), 900),
	}

	cp, err := capture.New("lo", fmt.Sprintf("tcp port %d", port), c.pcapPath)
	if err != nil {
		t.Fatalf("capture.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cp.Start(ctx); err != nil {
		t.Skipf("cannot capture on lo here: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_, _ = cp.Stop()
		}
	}()

	keyFile, err := os.Create(c.keylogPath)
	if err != nil {
		t.Fatal(err)
	}
	var keyMu sync.Mutex
	keyWriter := writerFunc(func(b []byte) (int, error) {
		keyMu.Lock()
		defer keyMu.Unlock()
		return keyFile.Write(b)
	})

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{p.serverDER, p.caDER}, PrivateKey: p.serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		MinVersion:   minVer, MaxVersion: maxVer, CipherSuites: suites,
		KeyLogWriter: keyWriter,
	}
	clientCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{p.clientDER, p.caDER}, PrivateKey: p.clientKey}},
		RootCAs:      p.pool,
		ServerName:   "127.0.0.1",
		MinVersion:   minVer, MaxVersion: maxVer, CipherSuites: suites,
		KeyLogWriter: keyWriter,
	}

	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = raw.Close() }()
		s := tls.Server(raw, serverCfg)
		if err := s.Handshake(); err != nil {
			done <- err
			return
		}
		buf := make([]byte, len(c.clientSent))
		if _, err := io.ReadFull(s, buf); err != nil {
			done <- err
			return
		}
		if _, err := s.Write(c.serverSent); err != nil {
			done <- err
			return
		}
		_, _ = io.Copy(io.Discard, s)
		done <- s.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.clientAddr = raw.LocalAddr().String()
	cli := tls.Client(raw, clientCfg)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	st := cli.ConnectionState()
	c.version, c.suite = st.Version, st.CipherSuite
	if _, err := cli.Write(c.clientSent); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(c.serverSent))
	if _, err := io.ReadFull(cli, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf, c.serverSent) {
		t.Fatal("the connection itself did not deliver the payload")
	}
	if err := cli.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	_, _ = io.Copy(io.Discard, cli)
	if err := <-done; err != nil && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("server: %v", err)
	}
	_ = raw.Close()
	if err := keyFile.Close(); err != nil {
		t.Fatal(err)
	}
	// Give the last FIN time to reach the capture before it is torn down.
	time.Sleep(300 * time.Millisecond)

	sum, err := cp.Stop()
	stopped = true
	if err != nil {
		t.Fatalf("capture.Stop: %v", err)
	}
	c.summary = sum
	if sum.Packets == 0 {
		t.Fatal("the capture is empty")
	}
	c.packets, err = pcapng.ReadFile(c.pcapPath)
	if err != nil {
		t.Fatalf("reading the capture back: %v", err)
	}
	return c
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// analysed is the pipeline's output half.
type analysed struct {
	stream               *netdis.Stream
	clientDir, serverDir *netdis.Direction
	client, server       *tlsdis.Direction
	session              *tlsdecrypt.Session
	clientPT, serverPT   []tlsdecrypt.Plaintext
}

// analyse runs everything downstream of the capture: dissect, reassemble,
// parse the record layer, decrypt.
func analyse(t *testing.T, c captured) analysed {
	t.Helper()
	asm := netdis.NewAssembler()
	for _, p := range c.packets {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatalf("frame %d: %v", p.Index, err)
		}
	}
	_, portStr, _ := net.SplitHostPort(c.serverAddr)
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	streams := asm.FindPort(uint16(port))
	if len(streams) != 1 {
		t.Fatalf("found %d streams on port %d, want 1", len(streams), port)
	}
	a := analysed{stream: streams[0]}

	clientEP, err := endpoint(c.clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	a.clientDir = a.stream.Dir(clientEP)
	a.serverDir = a.stream.Dirs[0]
	if a.serverDir == a.clientDir {
		a.serverDir = a.stream.Dirs[1]
	}

	// Reassembly must be complete and unambiguous, or nothing downstream means
	// anything.
	for _, d := range []*netdis.Direction{a.clientDir, a.serverDir} {
		if !d.Complete() {
			t.Fatalf("%s has a %d-byte gap: the capture lost a segment", d.Flow, d.PendingGap())
		}
		if d.HasConflictingOverlap() {
			t.Fatalf("%s has conflicting overlapping segments: %v", d.Flow, d.Overlaps)
		}
		if !d.SYNSeen {
			t.Fatalf("%s has no SYN: the capture started late and Start returned before it was live", d.Flow)
		}
	}

	a.client, err = tlsdis.ParseDirection(a.clientDir.Bytes.Bytes(), a.clientDir.Bytes)
	if err != nil {
		t.Fatalf("client record layer: %v", err)
	}
	a.server, err = tlsdis.ParseDirection(a.serverDir.Bytes.Bytes(), a.serverDir.Bytes)
	if err != nil {
		t.Fatalf("server record layer: %v", err)
	}

	kl, err := keylog.Open(c.keylogPath)
	if err != nil {
		t.Fatalf("key log: %v", err)
	}
	params, err := tlsdecrypt.ParamsFromHandshake(a.client, a.server)
	if err != nil {
		t.Fatalf("ParamsFromHandshake: %v", err)
	}
	if params.Version != c.version || params.CipherSuite != c.suite {
		t.Fatalf("dissected %s/%s, connection reported %s/%s",
			tlsdis.VersionName(params.Version), tlsdis.CipherSuiteName(params.CipherSuite),
			tlsdis.VersionName(c.version), tlsdis.CipherSuiteName(c.suite))
	}
	a.session, err = tlsdecrypt.New(params, kl)
	if err != nil {
		t.Fatalf("tlsdecrypt.New: %v", err)
	}
	a.clientPT, err = a.session.DecryptAll(tlsdecrypt.Client, a.client.Stream.Records)
	if err != nil {
		t.Fatalf("decrypt client: %v", err)
	}
	a.serverPT, err = a.session.DecryptAll(tlsdecrypt.Server, a.server.Stream.Records)
	if err != nil {
		t.Fatalf("decrypt server: %v", err)
	}
	return a
}

func endpoint(hostPort string) (netdis.Endpoint, error) {
	ap, err := net.ResolveTCPAddr("tcp", hostPort)
	if err != nil {
		return netdis.Endpoint{}, err
	}
	addr, ok := netipFrom(ap.IP)
	if !ok {
		return netdis.Endpoint{}, fmt.Errorf("cannot convert %s", ap.IP)
	}
	return netdis.Endpoint{Addr: addr, Port: uint16(ap.Port)}, nil
}

// TestEndToEndCaptureDecryptVerify is the whole engine in one test: dumpcap on
// lo, a real mutually-authenticated TLS session, and then every layer of the
// reader chain, ending in an evidence bundle that verifies itself.
func TestEndToEndCaptureDecryptVerify(t *testing.T) {
	for _, tc := range []struct {
		name           string
		minVer, maxVer uint16
		suites         []uint16
	}{
		{"TLS 1.3", tls.VersionTLS13, tls.VersionTLS13, nil},
		{"TLS 1.2 AES-128-GCM", tls.VersionTLS12, tls.VersionTLS12,
			[]uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
		{"TLS 1.2 ChaCha20-Poly1305", tls.VersionTLS12, tls.VersionTLS12,
			[]uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPKI(t)
			c := runCapturedSession(t, p, tc.minVer, tc.maxVer, tc.suites)
			a := analyse(t, c)

			// 1. The application bytes must come back exactly.
			if got := tlsdecrypt.AppData(a.clientPT); !bytes.Equal(got, c.clientSent) {
				t.Fatalf("client payload:\n got %q\nwant %q", got, c.clientSent)
			}
			if got := tlsdecrypt.AppData(a.serverPT); !bytes.Equal(got, c.serverSent) {
				t.Fatalf("server payload: recovered %d bytes, sent %d", len(got), len(c.serverSent))
			}

			// 2. The negotiated parameters must match what crypto/tls reported.
			shMsg, ok := a.server.Handshake.Find(tlsdis.HandshakeServerHello)
			if !ok {
				t.Fatal("no ServerHello")
			}
			if shMsg.ServerHello.CipherSuite != c.suite {
				t.Errorf("dissected suite %s, want %s",
					tlsdis.CipherSuiteName(shMsg.ServerHello.CipherSuite), tlsdis.CipherSuiteName(c.suite))
			}

			// 3. The client's certificate chain and its role extension must be
			// recoverable — under TLS 1.3 that is only possible after decryption.
			clientHS, err := a.session.Handshake(tlsdecrypt.Client)
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			certMsg, ok := clientHS.Find(tlsdis.HandshakeCertificate)
			if !ok {
				t.Fatalf("no client Certificate; messages = %v", clientHS.Types())
			}
			leaf := certMsg.Certificate.Leaf()
			if !bytes.Equal(leaf.DER, p.clientDER) {
				t.Fatal("recovered client certificate DER is not byte-identical to the one presented")
			}
			if _, err := x509.ParseCertificate(leaf.DER); err != nil {
				t.Fatalf("recovered DER does not parse: %v", err)
			}
			role, err := leaf.Info.SunSpecRole()
			if err != nil || role != clientRole {
				t.Fatalf("role = %q, %v; want %q", role, err, clientRole)
			}
			if len(certMsg.Packets) == 0 {
				t.Fatal("the Certificate message cites no frames; the evidence chain is broken")
			}

			// 4. Every cited frame must really exist in the capture.
			for _, f := range certMsg.Packets {
				if f < 1 || f > len(c.packets) {
					t.Fatalf("Certificate cites frame %d, capture has %d", f, len(c.packets))
				}
			}
		})
	}
}

// TestEndToEndBundle builds a real bundle from a real capture and verifies it,
// then breaks the capture and requires that verification notices.
func TestEndToEndBundle(t *testing.T) {
	p := newPKI(t)
	c := runCapturedSession(t, p, tls.VersionTLS13, tls.VersionTLS13, nil)
	a := analyse(t, c)

	clientHS, err := a.session.Handshake(tlsdecrypt.Client)
	if err != nil {
		t.Fatal(err)
	}
	certMsg, ok := clientHS.Find(tlsdis.HandshakeCertificate)
	if !ok {
		t.Fatal("no client Certificate")
	}
	shMsg, _ := a.server.Handshake.Find(tlsdis.HandshakeServerHello)

	// Cite the ServerHello's bytes in the reassembled server stream: it is
	// plaintext, so its offsets are directly checkable by a third party.
	shStart := shMsg.Offset
	shEnd := shStart + 4 + shMsg.Length
	shRecord := a.server.Stream.Records[0]
	suiteAssert, err := bundle.CiteBytes(
		"The server selected "+tlsdis.CipherSuiteName(shMsg.ServerHello.CipherSuite)+".",
		"cipher_suite field of the ServerHello in the reassembled server stream",
		bundle.Pass,
		fmt.Sprintf("%s, %s", tlsdis.CipherSuiteName(shMsg.ServerHello.CipherSuite),
			tlsdis.VersionName(shMsg.ServerHello.NegotiatedVersion())),
		bundle.StreamRef(a.serverDir), a.serverDir.Bytes,
		shRecord.Offset+5+shStart, shRecord.Offset+5+shEnd)
	if err != nil {
		t.Fatalf("CiteBytes: %v", err)
	}

	roleAssert, err := bundle.CiteFrames(
		"The client presented a certificate carrying the SunSpec role extension "+roleOID.String()+".",
		"Certificate message recovered from the decrypted client handshake",
		bundle.Pass, "role = "+clientRole, c.packets, certMsg.Packets)
	if err != nil {
		t.Fatalf("CiteFrames: %v", err)
	}

	commit, dirty := bundle.GitCommit(".")
	b := bundle.NewBuilder(bundle.RunMeta{
		Tool: "evidence-engine e2e", ToolVersion: "test",
		GitCommit: commit, GitDirty: dirty,
		Operator: "bench", Note: "loopback end-to-end proof",
		DUT: bundle.DUT{Name: "loopback TLS server", Address: c.serverAddr, Role: "device"},
	})
	b.SetCapture(c.summary, c.pcapPath)
	b.SetKeyLog(c.keylogPath)
	b.AddCase(bundle.TestCaseResult{
		ID: "E2E-1", Doc: "internal", Title: "Negotiated suite is recorded on the wire",
		Assertions: []bundle.Assertion{suiteAssert},
	})
	b.AddCase(bundle.TestCaseResult{
		ID: "E2E-2", Doc: "internal", Title: "Client role extension is presented",
		Assertions: []bundle.Assertion{roleAssert},
	})

	dir := filepath.Join(t.TempDir(), "bundle")
	out, err := b.Write(dir)
	if err != nil {
		t.Fatalf("bundle.Write: %v", err)
	}
	if !out.OK() {
		t.Fatal("bundle reports failures")
	}

	rep, err := bundle.Verify(dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("a bundle built from a real capture must verify:\n%s", rep)
	}
	if rep.Checked != 2 {
		t.Errorf("Checked = %d, want 2", rep.Checked)
	}

	// Now corrupt the capture inside the bundle and require a failure. This is
	// the property the whole format exists for.
	inBundle := filepath.Join(dir, out.Files.Capture)
	data, err := os.ReadFile(inBundle)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(inBundle, data, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = bundle.Verify(dir)
	if err == nil && rep.OK {
		t.Fatal("a corrupted capture must not verify")
	}
}

// --- the live bench capture ----------------------------------------------

// TestLiveBenchCapture decrypts a capture of a real mbaps session against the
// gateway on the bench (desktop 69.0.0.20 → 69.0.0.2:802, TLS 1.3).
//
// The artefacts are NOT committed to this repository, deliberately: an NSS key
// log holds the session secrets of a real device's connection, and a repo is
// not the place for those. Point the test at them with EVIDENCE_LIVE_PCAP and
// EVIDENCE_LIVE_KEYLOG (defaulting to where the bench run leaves them); it
// skips when they are absent.
func TestLiveBenchCapture(t *testing.T) {
	pcapPath := envOr("EVIDENCE_LIVE_PCAP", "/tmp/mbaps-live.pcapng")
	keylogPath := envOr("EVIDENCE_LIVE_KEYLOG", "/tmp/evidence.keylog")
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("live bench capture not present at %s (set EVIDENCE_LIVE_PCAP)", pcapPath)
	}
	if _, err := os.Stat(keylogPath); err != nil {
		t.Skipf("live bench key log not present at %s (set EVIDENCE_LIVE_KEYLOG)", keylogPath)
	}

	pkts, err := pcapng.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("reading %s: %v", pcapPath, err)
	}
	t.Logf("live capture: %d frames", len(pkts))

	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatalf("frame %d: %v", p.Index, err)
		}
	}
	streams := asm.FindPort(802)
	if len(streams) == 0 {
		t.Fatalf("no stream on port 802; streams present: %d", len(asm.Streams()))
	}

	kl, err := keylog.Open(keylogPath)
	if err != nil {
		t.Fatalf("key log: %v", err)
	}

	decrypted := 0
	for _, st := range streams {
		clientDir, serverDir := st.Dirs[0], st.Dirs[1]
		if clientDir.Flow.Dst.Port != 802 {
			clientDir, serverDir = serverDir, clientDir
		}
		client, err := tlsdis.ParseDirection(clientDir.Bytes.Bytes(), clientDir.Bytes)
		if err != nil {
			t.Fatalf("client record layer: %v", err)
		}
		server, err := tlsdis.ParseDirection(serverDir.Bytes.Bytes(), serverDir.Bytes)
		if err != nil {
			t.Fatalf("server record layer: %v", err)
		}
		params, err := tlsdecrypt.ParamsFromHandshake(client, server)
		if err != nil {
			t.Logf("stream %s: %v", st.Key, err)
			continue
		}
		if !kl.Has(params.ClientRandom) {
			t.Logf("stream %s: no key-log entry for client random %x", st.Key, params.ClientRandom)
			continue
		}
		sess, err := tlsdecrypt.New(params, kl)
		if err != nil {
			t.Fatalf("tlsdecrypt.New: %v", err)
		}
		clientPT, err := sess.DecryptAll(tlsdecrypt.Client, client.Stream.Records)
		if err != nil {
			t.Fatalf("decrypting the client direction: %v", err)
		}
		serverPT, err := sess.DecryptAll(tlsdecrypt.Server, server.Stream.Records)
		if err != nil {
			t.Fatalf("decrypting the server direction: %v", err)
		}
		decrypted++

		t.Logf("stream %s: %s %s", st.Key,
			tlsdis.VersionName(params.Version), tlsdis.CipherSuiteName(params.CipherSuite))

		// The server flight must decrypt into the full TLS 1.3 handshake.
		serverHS, err := sess.Handshake(tlsdecrypt.Server)
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
		serverTypes := typeSet(serverHS.Types())
		for _, want := range []tlsdis.HandshakeType{
			tlsdis.HandshakeServerHello, tlsdis.HandshakeEncryptedExtensions,
			tlsdis.HandshakeCertificateRequest, tlsdis.HandshakeCertificate,
			tlsdis.HandshakeCertificateVerify, tlsdis.HandshakeFinished,
			tlsdis.HandshakeNewSessionTicket,
		} {
			if !serverTypes[want] {
				t.Errorf("server handshake is missing %s; got %v",
					tlsdis.HandshakeTypeName(want), names(serverHS.Types()))
			}
		}

		// And the client flight: Certificate, CertificateVerify, Finished.
		clientHS, err := sess.Handshake(tlsdecrypt.Client)
		if err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		clientTypes := typeSet(clientHS.Types())
		for _, want := range []tlsdis.HandshakeType{
			tlsdis.HandshakeClientHello, tlsdis.HandshakeCertificate,
			tlsdis.HandshakeCertificateVerify, tlsdis.HandshakeFinished,
		} {
			if !clientTypes[want] {
				t.Errorf("client handshake is missing %s; got %v",
					tlsdis.HandshakeTypeName(want), names(clientHS.Types()))
			}
		}

		// The certificate chains must be byte-exact DER that crypto/x509 accepts,
		// and their extension OIDs must be enumerable — this is what lets the
		// bundle prove a role extension was presented.
		for side, hs := range map[string]*tlsdis.HandshakeStream{"client": clientHS, "server": serverHS} {
			msg, ok := hs.Find(tlsdis.HandshakeCertificate)
			if !ok {
				continue
			}
			if len(msg.Certificate.Entries) == 0 {
				t.Errorf("%s Certificate carries no certificates", side)
				continue
			}
			for i, e := range msg.Certificate.Entries {
				cert, err := x509.ParseCertificate(e.DER)
				if err != nil {
					t.Errorf("%s certificate %d does not parse: %v", side, i, err)
					continue
				}
				var oids []string
				for _, ext := range e.Info.Extensions {
					oids = append(oids, ext.OID)
				}
				t.Logf("  %s cert %d: subject=%q issuer=%q key=%s/%d extensions=%v",
					side, i, cert.Subject.CommonName, cert.Issuer.CommonName,
					e.Info.PublicKeyAlgorithm, e.Info.PublicKeyBits, oids)
				if len(e.Info.Extensions) == 0 {
					t.Errorf("%s certificate %d lists no extensions", side, i)
				}
			}
			if role, err := msg.Certificate.Leaf().Info.SunSpecRole(); err == nil {
				t.Logf("  %s leaf carries SunSpec role %q at %s", side, role, tlsdis.RoleOID)
			} else {
				t.Logf("  %s leaf has no readable SunSpec role: %v", side, err)
			}
		}

		// Alerts are encrypted in TLS 1.3, so a close_notify is only visible
		// after decryption.
		alerts := append(tlsdecrypt.Alerts(clientPT), tlsdecrypt.Alerts(serverPT)...)
		for _, al := range alerts {
			t.Logf("  alert: %s", al)
		}
		if len(alerts) == 0 {
			t.Log("  no alerts in this session")
		}
	}
	if decrypted == 0 {
		t.Fatal("no session in the live capture could be decrypted with the supplied key log")
	}
}

// TestLiveBenchCleartextModbus exercises the non-TLS path against the second
// bench capture: cleartext SunSpec Modbus on port 5020 alongside encrypted
// mbaps, which is the mixed traffic a real bench run produces.
func TestLiveBenchCleartextModbus(t *testing.T) {
	path := envOr("EVIDENCE_LIVE_PROBE_PCAP", "/tmp/bench-probe.pcapng")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("bench probe capture not present at %s", path)
	}
	pkts, err := pcapng.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatalf("frame %d: %v", p.Index, err)
		}
	}
	streams := asm.FindPort(5020)
	if len(streams) == 0 {
		t.Skipf("no cleartext Modbus stream on port 5020 in %s", path)
	}
	found := false
	for _, st := range streams {
		for _, d := range st.Dirs {
			data := d.Bytes.Bytes()
			// A Modbus/TCP ADU starts with a 2-byte transaction id, a zero
			// protocol id, and a length; the protocol id is the reliable marker.
			for off := 0; off+8 <= len(data); {
				if data[off+2] != 0 || data[off+3] != 0 {
					break
				}
				length := int(data[off+4])<<8 | int(data[off+5])
				if length < 2 || off+6+length > len(data) {
					break
				}
				fn := data[off+7]
				frames := d.Bytes.PacketsFor(off, off+6+length)
				t.Logf("%s: mbap unit=%d function=0x%02X at offset %d, frames %v",
					d.Flow, data[off+6], fn, off, frames)
				if len(frames) == 0 {
					t.Errorf("a Modbus PDU at offset %d cites no frames", off)
				}
				found = true
				off += 6 + length
			}
		}
	}
	if !found {
		t.Error("no Modbus/TCP PDU could be located in the cleartext stream")
	}
}

// TestLivePostCCSAlertNeedsTheKeyLog is the bundle-driven half of the
// post-ChangeCipherSpec alert defect.
//
// It reads a real conformance run's capture and key log and proves both halves
// of the rule on the same bytes:
//
//   - the record layer ALONE must not produce a level or a description for an
//     alert sent after the CCS. Those bytes are AEAD output. The bench's own
//     TLSF-005 run read them and reported "the DUT sent no fatal alert" about a
//     device that had sent exactly that alert;
//   - decrypted with the run's key log, the same record comes back as the real
//     fatal alert.
//
// The artefacts are not committed (see TestLiveBenchCapture); point the test at
// a run's capture/ directory with EVIDENCE_LIVE_PCAP and EVIDENCE_LIVE_KEYLOG.
func TestLivePostCCSAlertNeedsTheKeyLog(t *testing.T) {
	pcapPath := envOr("EVIDENCE_LIVE_PCAP", "/tmp/mbaps-live.pcapng")
	keylogPath := envOr("EVIDENCE_LIVE_KEYLOG", "/tmp/evidence.keylog")
	if _, err := os.Stat(pcapPath); err != nil {
		t.Skipf("live bench capture not present at %s (set EVIDENCE_LIVE_PCAP)", pcapPath)
	}
	if _, err := os.Stat(keylogPath); err != nil {
		t.Skipf("live bench key log not present at %s (set EVIDENCE_LIVE_KEYLOG)", keylogPath)
	}
	pkts, err := pcapng.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("reading %s: %v", pcapPath, err)
	}
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		if _, err := asm.AddPacket(p); err != nil {
			t.Fatalf("frame %d: %v", p.Index, err)
		}
	}
	kl, err := keylog.Open(keylogPath)
	if err != nil {
		t.Fatalf("key log: %v", err)
	}

	examined, recovered := 0, 0
	for _, st := range asm.FindPort(802) {
		clientDir, serverDir := st.Dirs[0], st.Dirs[1]
		if clientDir.Flow.Dst.Port != 802 {
			clientDir, serverDir = serverDir, clientDir
		}
		client, _ := tlsdis.ParseDirection(clientDir.Bytes.Bytes(), clientDir.Bytes)
		server, _ := tlsdis.ParseDirection(serverDir.Bytes.Bytes(), serverDir.Bytes)
		if client == nil || server == nil {
			continue
		}
		enc := server.EncryptedAlerts()
		if len(enc) == 0 {
			continue
		}
		examined++
		for _, a := range enc {
			if a.Level != 0 || a.Description != 0 {
				t.Errorf("stream %s frame(s) %v: the record layer produced level %d description %d from "+
					"ciphertext", st.Key, a.Packets, a.Level, a.Description)
			}
		}
		if _, ok := server.FatalAlert(); ok {
			t.Errorf("stream %s: FatalAlert() answered from an encrypted record", st.Key)
		}
		params, err := tlsdecrypt.ParamsFromHandshake(client, server)
		if err != nil || !kl.Has(params.ClientRandom) {
			continue
		}
		sess, err := tlsdecrypt.New(params, kl)
		if err != nil {
			continue
		}
		// The DUT's direction alone: TLSF-005 corrupts a record the BENCH
		// sends, so the other direction is guaranteed not to decrypt, and
		// requiring both would throw away the alert that is the evidence.
		recs, _ := sess.DecryptAll(tlsdecrypt.Server, server.Stream.Records)
		for _, a := range tlsdecrypt.Alerts(recs) {
			if a.Fatal() {
				recovered++
				t.Logf("stream %s: recovered fatal alert description %d (%s) in frame(s) %v",
					st.Key, a.Description, tlsdis.AlertDescriptionName(a.Description), a.Packets)
			}
		}
	}
	if examined == 0 {
		t.Skip("this capture holds no post-ChangeCipherSpec alert record on port 802")
	}
	if recovered == 0 {
		t.Errorf("%d encrypted alert record(s) were found and none could be recovered with the run's key log; "+
			"the point of the key log is that a reader of the bundle can repeat the recovery", examined)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// netipFrom converts a net.IP to the netip.Addr netdis keys endpoints by,
// unmapping the IPv4-in-IPv6 form net.IP uses for loopback addresses.
func netipFrom(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func typeSet(ts []tlsdis.HandshakeType) map[tlsdis.HandshakeType]bool {
	m := make(map[tlsdis.HandshakeType]bool, len(ts))
	for _, t := range ts {
		m[t] = true
	}
	return m
}

func names(ts []tlsdis.HandshakeType) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = tlsdis.HandshakeTypeName(t)
	}
	return out
}
