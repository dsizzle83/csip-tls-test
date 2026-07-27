package suitecsip

// harness_test.go builds the fixture the transcript tests need: a REAL TLS
// session, carrying REAL HTTP/2030.5 traffic, rendered into a pcap this suite
// then reads back exactly as it would read a bench capture.
//
// Why go to this length instead of hand-writing a Transcript? Because the
// transcript machinery's whole job is to survive the gap between "what the
// library did" and "what the wire carried", and a hand-built fixture shares the
// author's assumptions with the code under test. Here, crypto/tls chooses the
// record boundaries, splits the certificate across records as it sees fit, and
// writes the key log; this file only turns the resulting byte streams into TCP
// segments. If the record-to-frame mapping is wrong, these tests fail.
//
// The one thing this fixture cannot reproduce is the CSIP mandatory cipher
// suite: Go's crypto/tls does not implement TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
// so the session negotiates an AES-GCM suite instead. That is fine — the suite's
// cipher criteria are decision logic over a parsed ClientHello and are tested
// directly in criteria_test.go, while what this fixture exercises is the
// record-layer, decryption and HTTP-recovery path, which is cipher-agnostic
// (tlsdecrypt's own tests cover CCM-8 against a real implementation).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// testPKI is a throwaway certificate authority and the two leaves the fixture
// needs. It is minted per test: nothing here touches the bench's real PKI.
type testPKI struct {
	caDER      []byte
	caCert     *x509.Certificate
	pool       *x509.CertPool
	serverDER  []byte
	serverKey  *ecdsa.PrivateKey
	clientDER  []byte
	clientKey  *ecdsa.PrivateKey
	clientLFDI string
	clientSFDI uint64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "suitecsip-test-serca"},
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

	issue := func(cn string, dns []string) ([]byte, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	p.serverDER, p.serverKey = issue("gridsim-test", []string{"localhost"})
	p.clientDER, p.clientKey = issue("lexa-gw-test", nil)
	p.clientLFDI = LFDI(p.clientDER)
	p.clientSFDI = SFDI(p.clientDER)
	return p
}

// pemBlocks renders a certificate for the tests that want a file on disk.
func pemBlocks(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// chunk is one write on the wire, with the direction and the moment it was made.
type chunk struct {
	fromClient bool
	data       []byte
	at         time.Time
}

// tap records every byte written through a connection, tagged with a direction.
type tap struct {
	net.Conn
	fromClient bool
	mu         *sync.Mutex
	out        *[]chunk
}

func (t *tap) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	t.mu.Lock()
	*t.out = append(*t.out, chunk{fromClient: t.fromClient, data: append([]byte(nil), b[:n]...), at: time.Now().UTC()})
	t.mu.Unlock()
	return n, err
}

// recorded is a captured session: the two byte streams as TCP segments, plus
// the key log that decrypts them.
type recorded struct {
	chunks   []chunk
	keyLog   []byte
	clientAP netip.AddrPort
	serverAP netip.AddrPort
}

// recordSession drives a real TLS 1.2 client and server over loopback with the
// given HTTP handler, taps both directions, and returns the recording.
//
// requests is the list of HTTP requests the "DUT" makes, in order, on ONE
// keep-alive connection — which is what the gateway's fetcher does and what the
// transcript recovery has to be able to unpick.
func recordSession(t *testing.T, p *testPKI, handler http.Handler, requests []*http.Request) recorded {
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
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = raw.Close() }()
		srv := tls.Server(&tap{Conn: raw, fromClient: false, mu: &mu, out: &chunks}, serverCfg)
		if err := srv.Handshake(); err != nil {
			return
		}
		// A minimal HTTP/1.1 server loop: net/http's own Server would work but
		// would also add its own connection management, and the point of the
		// fixture is a plain keep-alive exchange.
		for {
			req, err := http.ReadRequest(newBufReader(srv))
			if err != nil {
				return
			}
			rec := &recordingResponseWriter{hdr: http.Header{}}
			handler.ServeHTTP(rec, req)
			if err := rec.writeTo(srv, req); err != nil {
				return
			}
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientAP := mustAddrPort(t, raw.LocalAddr())
	serverAP := mustAddrPort(t, raw.RemoteAddr())
	cli := tls.Client(&tap{Conn: raw, fromClient: true, mu: &mu, out: &chunks}, clientCfg)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	br := newBufReader(cli)
	for _, req := range requests {
		if err := req.Write(cli); err != nil {
			t.Fatalf("write request %s: %v", req.URL, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("read response for %s: %v", req.URL, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	_ = cli.CloseWrite()
	_ = raw.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	return recorded{
		chunks:   append([]chunk(nil), chunks...),
		keyLog:   append([]byte(nil), keyBuf.Bytes()...),
		clientAP: clientAP, serverAP: serverAP,
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func mustAddrPort(t *testing.T, a net.Addr) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// recordingResponseWriter is the tiny http.ResponseWriter the fixture's server
// loop needs.
type recordingResponseWriter struct {
	hdr    http.Header
	status int
	body   bytes.Buffer
}

func (w *recordingResponseWriter) Header() http.Header { return w.hdr }
func (w *recordingResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(b)
}
func (w *recordingResponseWriter) WriteHeader(code int) { w.status = code }

func (w *recordingResponseWriter) writeTo(conn net.Conn, req *http.Request) error {
	if w.status == 0 {
		w.status = 200
	}
	resp := &http.Response{
		StatusCode: w.status, ProtoMajor: 1, ProtoMinor: 1,
		Header: w.hdr, Request: req,
		Body:          io.NopCloser(bytes.NewReader(w.body.Bytes())),
		ContentLength: int64(w.body.Len()),
	}
	return resp.Write(conn)
}

// pcapFromRecording renders a recorded session as Ethernet/IPv4/TCP frames,
// preserving each write's order and timestamp.
//
// Sequence numbers are tracked per direction so the reassembler sees a coherent
// stream; checksums are left zero because netdis does not verify them (a
// capture is not a NIC) and computing them would prove nothing about the code
// under test.
func pcapFromRecording(rec recorded) []pcapng.Packet {
	var pkts []pcapng.Packet
	seq := map[bool]uint32{true: 1000, false: 5000}
	idx := 1
	for _, c := range rec.chunks {
		src, dst := rec.clientAP, rec.serverAP
		if !c.fromClient {
			src, dst = rec.serverAP, rec.clientAP
		}
		// A single TLS write can exceed a real MTU; split so the fixture
		// exercises the reassembler rather than sidestepping it.
		for off := 0; off < len(c.data); off += 1200 {
			end := off + 1200
			if end > len(c.data) {
				end = len(c.data)
			}
			data := tcpFrame(src, dst, seq[c.fromClient], c.data[off:end])
			seq[c.fromClient] += uint32(end - off)
			pkts = append(pkts, pcapng.Packet{
				Index: idx, Time: c.at, LinkType: netdis.LinkTypeEthernet,
				OrigLen: len(data), Data: data,
			})
			idx++
		}
	}
	return pkts
}

func tcpFrame(src, dst netip.AddrPort, seq uint32, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|0x018) // PSH|ACK, data offset 5
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src.Addr().AsSlice())
	copy(ip[16:20], dst.Addr().AsSlice())
	copy(ip[20:], tcp)

	eth := make([]byte, 14+len(ip))
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)
	return eth
}

// evidenceFrom builds the *certify.Evidence a citation phase would be handed,
// with a window claiming the server endpoint exactly as a real check does.
func evidenceFrom(t *testing.T, rec recorded, withKeyLog bool) (*certify.Evidence, netip.AddrPort) {
	t.Helper()
	pkts := pcapFromRecording(rec)
	if len(pkts) == 0 {
		t.Fatal("the recording produced no packets")
	}
	fi := certify.NewFrameIndex(pkts)

	w := certify.NewWindow("csip-conf-v1.3::COMM-003", Suite)
	w.Open(pkts[0].Time.Add(-time.Second))
	w.Close(pkts[len(pkts)-1].Time.Add(time.Second))
	if err := w.ClaimEndpointDuring("tcp", rec.serverAP, "test fixture: the DUT dialled this endpoint"); err != nil {
		t.Fatal(err)
	}
	att := fi.Attribute([]*certify.Window{w})

	ev := &certify.Evidence{
		Case:  &certify.Case{UID: "csip-conf-v1.3::COMM-003", ID: "COMM-003", Doc: "CSIP-CONF-v1.3"},
		Set:   att.Set("csip-conf-v1.3::COMM-003"),
		Index: fi, Attribution: att,
	}
	if withKeyLog {
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
	}
	return ev, rec.serverAP
}
