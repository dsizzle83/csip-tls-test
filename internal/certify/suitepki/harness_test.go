package suitepki

// harness_test.go is the loopback bench: an in-process TLS peer standing in for
// the DUT, a recorder that keeps every byte both sides sent, and a synthetic
// pcap built from those bytes so the whole two-phase pipeline — live check,
// capture stop, frame attribution, citation, bundle, verify — runs with no NIC,
// no root, no dumpcap and, crucially, no live bench.
//
// The last point is a hard constraint, not a convenience. Several agents work
// this bench concurrently and a conformance run from a unit test would
// interleave with theirs and produce garbage evidence for both. Nothing in this
// package's tests dials 69.0.0.x.
//
// The recorder sits on the SERVER side of each connection because that side
// sees both directions and knows the client's ephemeral port, which is the
// 4-tuple the capture has to carry for the framework to attribute frames to the
// check that caused them. Recording real bytes rather than fabricating
// plausible ones is what makes these tests worth running: the pcap contains an
// actual TLS handshake with an actual certificate in it, so a bug in the record
// walk, the coalescing, the record-span arithmetic or the citation refusal
// shows up here rather than on the bench.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

type chunk struct {
	conn       int
	fromClient bool
	data       []byte
	at         time.Time
}

// recorder collects every byte of every connection the peer accepted.
type recorder struct {
	mu     sync.Mutex
	chunks []chunk
	conns  map[int]connAddrs
	next   int
}

type connAddrs struct {
	client, server netip.AddrPort
}

func newRecorder() *recorder { return &recorder{conns: map[int]connAddrs{}} }

func (r *recorder) open(c net.Conn) int {
	client, _ := addrPortOf(c.RemoteAddr())
	server, _ := addrPortOf(c.LocalAddr())
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	r.conns[r.next] = connAddrs{client: client, server: server}
	return r.next
}

// quiesce waits until no new bytes have been recorded for a short while, so a
// capture is never synthesised while the peer is still writing. It returns
// whether it settled.
func (r *recorder) quiesce(max time.Duration) bool {
	deadline := time.Now().Add(max)
	last := -1
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.chunks)
		r.mu.Unlock()
		if n != last {
			last, stableSince = n, time.Now()
		} else if time.Since(stableSince) > 60*time.Millisecond {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func (r *recorder) note(id int, fromClient bool, b []byte) {
	if len(b) == 0 {
		return
	}
	cp := append([]byte(nil), b...)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chunks = append(r.chunks, chunk{conn: id, fromClient: fromClient, data: cp, at: time.Now().UTC()})
}

// recordConn wraps the server's side of a connection.
type recordConn struct {
	net.Conn
	rec *recorder
	id  int
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rec.note(c.id, true, p[:n])
	return n, err
}

func (c *recordConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.rec.note(c.id, false, p[:n])
	return n, err
}

// ---------------------------------------------------------------------------
// The in-process peer
// ---------------------------------------------------------------------------

// peer is a TLS server standing in for the DUT.
type peer struct {
	lis net.Listener
	rec *recorder
}

func (p *peer) addr() string { return p.lis.Addr().String() }

// startPeer stands up a conformant mTLS server presenting the given chain.
//
// clientRoots non-nil makes it demand AND VERIFY a client certificate, which is
// what a conformant Secure SunSpec Modbus server does and what makes the
// negative fixtures fail the way they are supposed to.
func startPeer(t *testing.T, rec *recorder, chain tls.Certificate, clientRoots *x509.CertPool) *peer {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientAuth := tls.RequireAnyClientCert
	if clientRoots != nil {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{chain},
		ClientAuth:   clientAuth,
		ClientCAs:    clientRoots,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	p := &peer{lis: lis, rec: rec}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				wrapped := &recordConn{Conn: c, rec: rec, id: rec.open(c)}
				tc := tls.Server(wrapped, cfg)
				_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
				// Nothing is written after the handshake: no application data,
				// no close_notify. The suite asserts over the handshake, and a
				// peer that kept writing after the check finished would make
				// the synthetic capture's byte counts depend on scheduling.
				_ = tc.Handshake()
			}()
		}
	}()
	t.Cleanup(func() { _ = lis.Close() })
	return p
}

// ---------------------------------------------------------------------------
// Synthetic capture
// ---------------------------------------------------------------------------

const (
	tcpSYN = 0x002
	tcpPSH = 0x008
	tcpACK = 0x010
)

// synthesise renders everything the recorder saw as a classic pcap.
func (r *recorder) synthesise() []pcapng.Packet {
	r.mu.Lock()
	defer r.mu.Unlock()

	type seqState struct{ up, down uint32 }
	seq := map[int]*seqState{}
	var out []pcapng.Packet
	idx := 0
	add := func(src, dst netip.AddrPort, s uint32, flags uint16, payload []byte, at time.Time) {
		idx++
		data := frameBytes(src, dst, s, flags, payload)
		out = append(out, pcapng.Packet{
			Index: idx, Time: at.UTC(), LinkType: netdis.LinkTypeEthernet,
			OrigLen: len(data), Data: data,
		})
	}

	opened := map[int]bool{}
	for _, ch := range r.chunks {
		a := r.conns[ch.conn]
		if !opened[ch.conn] {
			opened[ch.conn] = true
			seq[ch.conn] = &seqState{up: 1000, down: 5000}
			add(a.client, a.server, 1000, tcpSYN, nil, ch.at.Add(-2*time.Millisecond))
			add(a.server, a.client, 5000, tcpSYN|tcpACK, nil, ch.at.Add(-time.Millisecond))
			seq[ch.conn].up++
			seq[ch.conn].down++
		}
		st := seq[ch.conn]
		if ch.fromClient {
			add(a.client, a.server, st.up, tcpPSH|tcpACK, ch.data, ch.at)
			st.up += uint32(len(ch.data))
		} else {
			add(a.server, a.client, st.down, tcpPSH|tcpACK, ch.data, ch.at)
			st.down += uint32(len(ch.data))
		}
	}
	return out
}

// frameBytes renders one Ethernet / IPv4 / TCP frame. Checksums are left zero:
// netdis does not verify them (a capture is not a NIC) and computing them here
// would prove nothing about attribution or dissection.
func frameBytes(src, dst netip.AddrPort, seq uint32, flags uint16, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|flags)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	sa, da := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:16], sa[:])
	copy(ip[16:20], da[:])
	copy(ip[20:], tcp)

	eth := make([]byte, 14+len(ip))
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)
	return eth
}

func pcapBytes(pkts []pcapng.Packet) []byte {
	buf := make([]byte, 0, 24+len(pkts)*256)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 1<<20)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(netdis.LinkTypeEthernet))
	buf = append(buf, hdr...)
	for _, p := range pkts {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(p.Time.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(p.Time.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p.Data)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(p.OrigLen))
		buf = append(buf, rec...)
		buf = append(buf, p.Data...)
	}
	return buf
}

// fakeCapture is the Capturer seam the runner exposes for exactly this.
type fakeCapture struct {
	path    string
	build   func() []pcapng.Packet
	started time.Time
}

func (f *fakeCapture) Start(context.Context) error { f.started = time.Now().UTC(); return nil }
func (f *fakeCapture) Path() string                { return f.path }

func (f *fakeCapture) Stop() (capture.Summary, error) {
	pkts := f.build()
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return capture.Summary{}, err
	}
	if err := os.WriteFile(f.path, pcapBytes(pkts), 0o644); err != nil {
		return capture.Summary{}, err
	}
	fi, err := os.Stat(f.path)
	if err != nil {
		return capture.Summary{}, err
	}
	sum := capture.Summary{
		Tool: "synthetic", ToolVersion: "suitepki-test", Interface: "lo",
		Path: f.path, Format: string(pcapng.FormatPcap),
		Started: f.started, Stopped: time.Now().UTC(),
		FileBytes: fi.Size(), Packets: len(pkts),
	}
	if len(pkts) > 0 {
		sum.FirstPacket, sum.LastPacket = pkts[0].Time, pkts[len(pkts)-1].Time
	}
	return sum, nil
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// lexaPEN is the manufacturer's IANA Private Enterprise Number, visible in the
// SunSpec role OID the product already publishes.
const lexaPEN = 50316

// conformantIdentity is the device identity a 2030.5-conformant leaf carries.
func conformantIdentity() *DeviceIdentitySpec {
	return &DeviceIdentitySpec{
		HWType: append(append([]int(nil), OIDIANAPrivateEnterprise...), lexaPEN, 13, 1),
		Serial: "250905000023",
	}
}

// conformantLeafSpec is a device certificate that PASSES PKI-4/5/6/7: empty
// Subject, identity in the SAN otherName, model OID under the PEN, serial as a
// UTF-8 OCTET STRING.
func conformantLeafSpec(name string) LeafSpec {
	return LeafSpec{
		Name:     name,
		Identity: conformantIdentity(),
		Server:   true, Client: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
}

// dutShapedLeafSpec reproduces what the DUT actually presents today: a Subject
// CN and no 2030.5 identity at all.
func dutShapedLeafSpec(name string) LeafSpec {
	return LeafSpec{
		Name:       name,
		CommonName: "lexa-gw nb-mbaps-server",
		Server:     true, Client: true,
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
}

// benchPKIDir writes a certs/mbaps-shaped fixture tree under a temporary
// directory, so certify.LoadPKI finds a root (with its key), a role client and
// the negative matrix — without ever touching the committed tree.
func benchPKIDir(t *testing.T, h *Hierarchy) string {
	t.Helper()
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "clients"))
	mustMkdir(t, filepath.Join(dir, "negative"))

	writeFile(t, filepath.Join(dir, "ca-cert.pem"), h.SERCA.CertPEM())
	rootKey, err := h.SERCA.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "ca-key.pem"), rootKey)
	writeFile(t, filepath.Join(dir, "intermediate-cert.pem"), h.MICADirect.CertPEM())

	role, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "read-only", CommonName: "suitepki read-only client",
		Roles: []string{"ReadOnlySunSpec"}, Client: true, Server: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := role.WritePEM(filepath.Join(dir, "clients"), "read-only"); err != nil {
		t.Fatal(err)
	}
	grid, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "grid-service", CommonName: "suitepki grid-service client",
		Roles: []string{"GridServiceSunSpec"}, Client: true, Server: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := grid.WritePEM(filepath.Join(dir, "clients"), "grid-service"); err != nil {
		t.Fatal(err)
	}

	mica, err := h.IssuerFor(ShapeSERCAMICADevice)
	if err != nil {
		t.Fatal(err)
	}
	neg, err := NegativeFixtures(mica, "suitepki bench negative")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range neg.Fixtures {
		if _, _, err := f.Leaf.WritePEM(filepath.Join(dir, "negative"), f.Name); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Running the suite against the loopback peer
// ---------------------------------------------------------------------------

type runOutcome struct {
	report *certify.RunReport
	out    string
	dir    string
}

func (o *runOutcome) result(t *testing.T, uid string) *certify.CaseResult {
	t.Helper()
	for i := range o.report.Cases {
		if o.report.Cases[i].Case.UID == uid {
			return &o.report.Cases[i]
		}
	}
	t.Fatalf("no result recorded for %s", uid)
	return nil
}

// runSuite drives the real runner over the real catalog against the loopback
// peer, with a capture synthesised from the bytes that actually crossed the
// loopback socket.
func runSuite(t *testing.T, p *peer, pkiDir string, uids []string) *runOutcome {
	t.Helper()
	return runSuiteWith(t, p, pkiDir, uids, false)
}

// runSuiteNoIdentityTarget is runSuite WITHOUT pointing the identity rows at a
// 2030.5 identity, i.e. the shape of a Secure SunSpec Modbus run. It exists to
// prove those rows go inapplicable rather than judging the mbaps leaf.
func runSuiteNoIdentityTarget(t *testing.T, p *peer, pkiDir string, uids []string) *runOutcome {
	t.Helper()
	return runSuiteOpts(t, p, pkiDir, uids, false, false)
}

func runSuiteWith(t *testing.T, p *peer, pkiDir string, uids []string, noCapture bool) *runOutcome {
	t.Helper()
	return runSuiteOpts(t, p, pkiDir, uids, noCapture, true)
}

func runSuiteOpts(t *testing.T, p *peer, pkiDir string, uids []string, noCapture, identityTarget bool) *runOutcome {
	t.Helper()
	cat, err := certify.LoadDefault()
	if err != nil {
		t.Skipf("no committed catalog: %v", err)
	}
	reg := certify.NewRegistry()
	Register(reg)

	console := &writerBuffer{}
	outDir := filepath.Join(t.TempDir(), "bundle")
	opts := certify.DefaultOptions()
	opts.Targets = certify.Targets{Gateway: p.addr(), GatewayHost: "127.0.0.1"}
	// The loopback peer PRESENTS the identity certificate as a server, so the
	// identity rows are pointed at it explicitly. Without this they are
	// inapplicable — they must never fall back to judging the mbaps leaf, which
	// is the defect this parameter exists to make impossible.
	if opts.Params == nil {
		opts.Params = map[string]string{}
	}
	if identityTarget {
		opts.Params[paramIdentityTarget] = p.addr()
	}
	opts.PKIDir = pkiDir
	opts.OutDir = outDir
	opts.UIDs = uids
	opts.Out = console
	opts.Log = certify.DiscardLogger
	opts.CheckTimeout = 60 * time.Second
	if noCapture {
		opts.NoCapture = true
	} else {
		opts.Capturer = &fakeCapture{
			path: filepath.Join(t.TempDir(), "run.pcap"),
			build: func() []pcapng.Packet {
				p.rec.quiesce(3 * time.Second)
				return p.rec.synthesise()
			},
		}
	}
	run, err := certify.New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console.String())
	}
	return &runOutcome{report: rep, out: console.String(), dir: outDir}
}

type writerBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (w *writerBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *writerBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.buf)
}

var _ io.Writer = (*writerBuffer)(nil)

// describeAssertions renders a case's assertions for a failure message.
func describeAssertions(c *certify.CaseResult) string {
	s := fmt.Sprintf("verdict=%s notes=%q\n", c.Verdict, c.Notes)
	for _, a := range c.Assertions {
		s += fmt.Sprintf("  [%s] %s\n      observed: %s\n      cited: %v frames=%v bytes=%v\n",
			a.Verdict, a.Claim, a.Observed, a.Citable(), a.Frames, a.ByteRange)
	}
	return s
}

// runSuiteNoCapture is the same run with -no-capture, which is how the "an
// uncited PASS is not a PASS" rule is exercised.
func runSuiteNoCapture(t *testing.T, p *peer, pkiDir string, uids []string) *runOutcome {
	t.Helper()
	return runSuiteWith(t, p, pkiDir, uids, true)
}

// removeFile deletes a fixture so a check's "material unavailable" branch can be
// exercised.
func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// closedListener stands in for a peer that is no longer listening, so the
// "could not be carried out" path can be reached without guessing at a port
// nothing has ever bound.
type closedListener struct{ addr string }

func (closedListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (closedListener) Close() error              { return nil }
func (l closedListener) Addr() net.Addr          { return stringAddr(l.addr) }

type stringAddr string

func (stringAddr) Network() string  { return "tcp" }
func (s stringAddr) String() string { return string(s) }
