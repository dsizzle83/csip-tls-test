package suitessm

// loopback_test.go drives a whole check through the REAL runner against an
// in-process peer, and proves the thing that matters most about a conformance
// tool: a NON-CONFORMANT peer FAILS.
//
// The pattern is sim/ssm-conformance's — mint a throwaway PKI, stand up a
// loopback peer, run the suite against it — with the addition the evidence
// engine needs: the bytes that actually crossed the loopback socket are tapped
// and synthesised into a pcap, so the citation phase does the same parsing,
// attribution and digesting it would do on a real capture. Nothing is stubbed
// between the check and its evidence.
//
// Two peers are stood up for each scenario, and the pair is the point:
//
//	conformant     — the check must PASS and the bundle must verify;
//	non-conformant — the check must FAIL, and the failure must name the defect.
//
// Only the conformant half proves the check RUNS. Only the non-conformant half
// proves it has teeth.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// ── the byte tap and the synthetic capture ──────────────────────────────────

// segment is one direction's bytes at one moment, as they crossed the socket.
type segment struct {
	src, dst netip.AddrPort
	payload  []byte
	at       time.Time
}

// tap records everything a check's connections carried, so the run's capture
// can be built from the real bytes rather than from a fixture.
type tap struct {
	mu   sync.Mutex
	segs []segment
}

func (tp *tap) wrap(c net.Conn) net.Conn {
	local, _ := addrPortOf(c.LocalAddr())
	remote, _ := addrPortOf(c.RemoteAddr())
	return &tappedConn{Conn: c, tap: tp, local: local, remote: remote}
}

func (tp *tap) record(src, dst netip.AddrPort, b []byte) {
	if len(b) == 0 {
		return
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.segs = append(tp.segs, segment{
		src: src, dst: dst, payload: append([]byte(nil), b...), at: time.Now().UTC(),
	})
}

type tappedConn struct {
	net.Conn
	tap           *tap
	local, remote netip.AddrPort
}

func (c *tappedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.tap.record(c.local, c.remote, p[:n])
	return n, err
}

func (c *tappedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.tap.record(c.remote, c.local, p[:n])
	return n, err
}

// packets turns the tapped segments into a capture: a SYN pair per conversation
// followed by the recorded payloads, with per-direction sequence numbers so the
// reassembler produces exactly the byte stream that crossed the socket.
func (tp *tap) packets() []pcapng.Packet {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	type dirKey struct{ src, dst netip.AddrPort }
	seq := map[dirKey]uint32{}
	opened := map[string]bool{}

	var specs []synthSpec
	for _, s := range tp.segs {
		conv := convKey(s.src, s.dst)
		if !opened[conv] {
			opened[conv] = true
			specs = append(specs,
				synthSpec{src: s.src, dst: s.dst, seq: 0, flags: tcpSYN, at: s.at.Add(-2 * time.Millisecond)},
				synthSpec{src: s.dst, dst: s.src, seq: 0, flags: tcpSYN | tcpACK, at: s.at.Add(-time.Millisecond)},
			)
			seq[dirKey{s.src, s.dst}] = 1
			seq[dirKey{s.dst, s.src}] = 1
		}
		k := dirKey{s.src, s.dst}
		specs = append(specs, synthSpec{src: s.src, dst: s.dst, seq: seq[k], payload: s.payload, at: s.at})
		seq[k] += uint32(len(s.payload))
	}

	out := make([]pcapng.Packet, 0, len(specs))
	for i, sp := range specs {
		data := sp.bytes()
		out = append(out, pcapng.Packet{
			Index: i + 1, Time: sp.at.UTC(), LinkType: netdis.LinkTypeEthernet,
			OrigLen: len(data), Data: data,
		})
	}
	return out
}

// convKey names a conversation regardless of direction.
func convKey(a, b netip.AddrPort) string {
	if a.String() < b.String() {
		return a.String() + "|" + b.String()
	}
	return b.String() + "|" + a.String()
}

const (
	tcpSYN = 0x002
	tcpACK = 0x010
	tcpPSH = 0x008
)

// synthSpec is one frame to render as Ethernet / IPv4 / TCP.
type synthSpec struct {
	src, dst netip.AddrPort
	seq      uint32
	flags    uint16
	payload  []byte
	at       time.Time
}

// bytes renders the frame. Checksums are left zero: netdis does not verify them
// (a capture is not a NIC), and computing them would add a page of code that
// proves nothing about the evidence path under test.
func (s synthSpec) bytes() []byte {
	tcp := make([]byte, 20+len(s.payload))
	binary.BigEndian.PutUint16(tcp[0:2], s.src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], s.dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], s.seq)
	flags := s.flags
	if flags == 0 {
		flags = tcpPSH | tcpACK
	}
	binary.BigEndian.PutUint16(tcp[12:14], 5<<12|flags)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], s.payload)

	ip := make([]byte, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	sa, da := s.src.Addr().As4(), s.dst.Addr().As4()
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

// tapCapture is the certify.Capturer that writes the tapped bytes out as a
// classic pcap when the run stops the capture.
type tapCapture struct {
	path    string
	tap     *tap
	started time.Time
}

func (c *tapCapture) Start(context.Context) error { c.started = time.Now().UTC(); return nil }
func (c *tapCapture) Path() string                { return c.path }

func (c *tapCapture) Stop() (capture.Summary, error) {
	pkts := c.tap.packets()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return capture.Summary{}, err
	}
	if err := os.WriteFile(c.path, pcapFile(pkts), 0o644); err != nil {
		return capture.Summary{}, err
	}
	fi, err := os.Stat(c.path)
	if err != nil {
		return capture.Summary{}, err
	}
	sum := capture.Summary{
		Tool: "suitessm-tap", ToolVersion: "test", Interface: "lo",
		Path: c.path, Format: string(pcapng.FormatPcap),
		Started: c.started, Stopped: time.Now().UTC(),
		FileBytes: fi.Size(), Packets: len(pkts),
	}
	if len(pkts) > 0 {
		sum.FirstPacket, sum.LastPacket = pkts[0].Time, pkts[len(pkts)-1].Time
	}
	return sum, nil
}

// pcapFile renders a classic little-endian microsecond pcap, which is what
// tcpdump -w produces and what pcapng.Open reads back.
func pcapFile(pkts []pcapng.Packet) []byte {
	buf := make([]byte, 0, 24+len(pkts)*256)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 262144)
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

// ── the loopback peer ───────────────────────────────────────────────────────

// peerOpts describes how conformant the loopback mbaps server should be.
type peerOpts struct {
	// LeafOnly makes the server send its leaf with no intermediate, which is
	// the SunSpecTCP-51 defect PKI-004 exists to catch.
	LeafOnly bool
	// NoCertificateRequest makes the server skip mutual authentication, which
	// is the SunSpecTCP-11 defect TLSF-006 exists to catch.
	NoCertificateRequest bool
}

// loopbackPeer stands up a TLS 1.2 server on 127.0.0.1 with a throwaway
// root → intermediate → leaf PKI, and returns its address and PKI directory.
func loopbackPeer(t *testing.T, o peerOpts) (addr string, pkiDir string) {
	t.Helper()

	root, rootKey := testCA(t, "ssm-loopback-root")
	interCert, interKey := testIntermediate(t, root, rootKey)

	leaf, err := mintServerLeaf(interCert, interKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{leaf.Certificate[0], interCert.Raw}
	if o.LeafOnly {
		chain = [][]byte{leaf.Certificate[0]}
	}
	srvCert := tls.Certificate{Certificate: chain, PrivateKey: leaf.PrivateKey, Leaf: leaf.Leaf}

	clientAuth := tls.RequestClientCert
	if o.NoCertificateRequest {
		clientAuth = tls.NoClientCert
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, cfg)
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				// The probe never completes the handshake, so this returns an
				// error every time; the server flight it already wrote is what
				// the check is about.
				_ = tc.Handshake()
			}()
		}
	}()

	// A PKI directory holding only the root, which is all prepare() needs to
	// consider the fixture set configured.
	pkiDir = t.TempDir()
	writePEM(t, filepath.Join(pkiDir, "ca-cert.pem"), "CERTIFICATE", root.Raw)
	writePEM(t, filepath.Join(pkiDir, "intermediate-cert.pem"), "CERTIFICATE", interCert.Raw)
	return lis.Addr().String(), pkiDir
}

// testIntermediate re-signs a throwaway CA under the root, so the loopback peer
// has a real two-tier chain to deliver (or to withhold).
func testIntermediate(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	sub, subKey := testCA(t, "ssm-loopback-intermediate")
	der, err := x509.CreateCertificate(rand.Reader, sub, root, &subKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, subKey
}

// mintServerLeaf issues a serverAuth leaf under the given issuer.
func mintServerLeaf(issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	c, err := mintLeaf(issuer, issuerKey, mintOpts{CommonName: "ssm-loopback-server"})
	if err != nil {
		return tls.Certificate{}, err
	}
	return c, nil
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ── the runs ────────────────────────────────────────────────────────────────

// runCase executes exactly one catalog uid against a loopback peer and returns
// its result plus the bundle directory.
func runCase(t *testing.T, uid string, o peerOpts) (certify.CaseResult, string, string) {
	t.Helper()
	addr, pkiDir := loopbackPeer(t, o)

	tp := &tap{}
	prev := connTap
	connTap = tp.wrap
	t.Cleanup(func() { connTap = prev })

	out := filepath.Join(t.TempDir(), "bundle")
	console := &bytes.Buffer{}
	opts := certify.DefaultOptions()
	opts.UIDs = []string{uid}
	opts.OutDir = out
	opts.Out = console
	opts.Log = certify.DiscardLogger
	opts.PKIDir = pkiDir
	opts.CheckTimeout = 30 * time.Second
	opts.Targets = certify.Targets{Gateway: addr, GatewayHost: "127.0.0.1"}
	opts.Capturer = &tapCapture{path: filepath.Join(t.TempDir(), "run.pcap"), tap: tp}
	opts.Params = map[string]string{"ssm.client_wait": "10ms"}

	cat := loadCatalog(t)
	run, err := certify.New(registry(t), cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, console.String())
	}
	for _, c := range rep.Cases {
		if c.Case.UID == uid {
			return c, out, console.String()
		}
	}
	t.Fatalf("%s did not appear in the run report\n%s", uid, console.String())
	return certify.CaseResult{}, "", ""
}

// TestPKI004PassesAConformantChainAndFailsALeafOnlyOne is the suite's teeth
// test at full depth: the same check, the same runner, the same citation path,
// one peer that delivers leaf + intermediate and one that delivers only its
// leaf.
func TestPKI004PassesAConformantChainAndFailsALeafOnlyOne(t *testing.T) {
	const uid = "ssm-conf-v0.8::PKI-004"

	t.Run("conformant peer", func(t *testing.T) {
		res, dir, console := runCase(t, uid, peerOpts{})
		if res.Verdict != certify.Pass {
			t.Fatalf("verdict = %s (%s)\nassertions: %s\n%s",
				res.Verdict, res.Notes, renderAssertions(res), console)
		}
		cited := 0
		for _, a := range res.Assertions {
			if a.Citable() {
				cited++
			}
		}
		if cited == 0 {
			t.Fatalf("a PASS with no re-checkable citation: %s", renderAssertions(res))
		}
		vr, err := bundle.Verify(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !vr.OK {
			t.Fatalf("the bundle does not verify:\n%s", vr.String())
		}
	})

	t.Run("non-conformant peer sends only its leaf", func(t *testing.T) {
		res, dir, console := runCase(t, uid, peerOpts{LeafOnly: true})
		if res.Verdict != certify.Fail {
			t.Fatalf("a peer that delivers no intermediate must FAIL SunSpecTCP-51; verdict = %s (%s)\n%s\n%s",
				res.Verdict, res.Notes, renderAssertions(res), console)
		}
		// The FAIL must be cited and must name the defect, or the row is a
		// verdict with nothing behind it.
		found := false
		for _, a := range res.Assertions {
			if a.Verdict != certify.Fail {
				continue
			}
			if !a.Citable() {
				continue
			}
			if strings.Contains(a.Observed, "only its leaf") || strings.Contains(a.Observed, "cannot be a path") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no CITED failing assertion names the missing intermediate: %s", renderAssertions(res))
		}
		// A failing run still has to produce a verifiable bundle: the evidence
		// for a FAIL matters at least as much as for a PASS.
		vr, err := bundle.Verify(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !vr.OK {
			t.Fatalf("the failing run's bundle does not verify:\n%s", vr.String())
		}
	})
}

// TestTLSF006FailsAServerThatNeverAsksForAClientCertificate proves the
// mutual-authentication criterion has teeth: a server configured with
// NoClientCert sends no CertificateRequest, and SunSpecTCP-11 must fail.
func TestTLSF006FailsAServerThatNeverAsksForAClientCertificate(t *testing.T) {
	const uid = "ssm-conf-v0.8::TLSF-006"
	res, _, console := runCase(t, uid, peerOpts{NoCertificateRequest: true})
	if res.Verdict != certify.Fail {
		t.Fatalf("a server that sends no CertificateRequest must FAIL SunSpecTCP-11; verdict = %s (%s)\n%s\n%s",
			res.Verdict, res.Notes, renderAssertions(res), console)
	}
	found := false
	for _, a := range res.Assertions {
		if a.Verdict == certify.Fail && strings.Contains(a.Observed, "no CertificateRequest") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no failing assertion names the missing CertificateRequest: %s", renderAssertions(res))
	}
}

// TestNoCaptureRefusesToLetAPassStand proves the other half of the honesty
// contract: with no capture, a check that would have cited cannot report PASS.
func TestNoCaptureRefusesToLetAPassStand(t *testing.T) {
	const uid = "ssm-conf-v0.8::PKI-004"
	addr, pkiDir := loopbackPeer(t, peerOpts{})

	opts := certify.DefaultOptions()
	opts.UIDs = []string{uid}
	opts.OutDir = filepath.Join(t.TempDir(), "bundle")
	opts.Out = &bytes.Buffer{}
	opts.Log = certify.DiscardLogger
	opts.PKIDir = pkiDir
	opts.NoCapture = true
	opts.CheckTimeout = 30 * time.Second
	opts.Targets = certify.Targets{Gateway: addr, GatewayHost: "127.0.0.1"}
	opts.Params = map[string]string{"ssm.client_wait": "10ms"}

	run, err := certify.New(registry(t), loadCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Cases {
		if c.Case.UID != uid {
			continue
		}
		if c.Verdict == certify.Pass {
			t.Fatalf("a PASS survived a run with no capture, so nothing about it is re-checkable: %s",
				renderAssertions(c))
		}
		return
	}
	t.Fatal("the case did not run")
}

func renderAssertions(c certify.CaseResult) string {
	var b strings.Builder
	for _, a := range c.Assertions {
		b.WriteString("\n  [")
		b.WriteString(string(a.Verdict))
		b.WriteString("] ")
		b.WriteString(a.Claim)
		b.WriteString("\n      observed: ")
		b.WriteString(a.Observed)
		if a.Note != "" {
			b.WriteString("\n      note: ")
			b.WriteString(a.Note)
		}
	}
	return b.String()
}

// TestCRYP007RefusalIsCitedFromTheAlertOnTheWire runs the NULL-encryption
// negative against a loopback peer that has no NULL suite, so the refusal is
// real, and requires the PASS to be cited on the alert the peer actually sent.
//
// The complementary half — a peer that ACCEPTS a NULL-encryption offer, which
// must FAIL — cannot be built from crypto/tls, which implements no NULL cipher
// at all. That branch is proven instead by
// TestRefusalFromDirectionAcceptsEveryConformantRefusalAndOnlyThose, which
// feeds the same decision function a ServerHello selecting 0x0002 and requires
// FAIL. The decision logic is shared, so the branch is covered even though this
// bench cannot stand up a peer perverse enough to exercise it end to end.
func TestCRYP007RefusalIsCitedFromTheAlertOnTheWire(t *testing.T) {
	const uid = "ssm-conf-v0.8::CRYP-007"
	res, dir, console := runCase(t, uid, peerOpts{})
	if res.Verdict != certify.Pass {
		t.Fatalf("a peer with no NULL cipher must PASS CRYP-007; verdict = %s (%s)\n%s\n%s",
			res.Verdict, res.Notes, renderAssertions(res), console)
	}
	cited := false
	for _, a := range res.Assertions {
		if a.Verdict == certify.Pass && a.Citable() && strings.Contains(a.Claim, "SunSpecTCP-53") {
			cited = true
		}
	}
	if !cited {
		t.Fatalf("the refusal PASS carries no frame citation: %s", renderAssertions(res))
	}
	vr, err := bundle.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.OK {
		t.Fatalf("the bundle does not verify:\n%s", vr.String())
	}
}

// TestWholeSuiteDryRunsAgainstTheCommittedCatalog is the cheap guard that every
// registered check at least compiles into a plannable row and that the run
// refuses nothing.
func TestWholeSuiteDryRunsAgainstTheCommittedCatalog(t *testing.T) {
	opts := certify.DefaultOptions()
	opts.Docs = []string{doc}
	opts.DryRun = true
	opts.NoCapture = true
	console := &bytes.Buffer{}
	opts.Out = console
	opts.Log = certify.DiscardLogger

	run, err := certify.New(registry(t), loadCatalog(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := run.Run(context.Background())
	if err != nil {
		t.Fatalf("the dry run was refused: %v\n%s", err, console.String())
	}
	if len(rep.Coverage.Orphans) != 0 {
		t.Fatalf("orphaned registrations: %v", rep.Coverage.Orphans)
	}
	if missing := rep.Unaddressed(); len(missing) != 0 {
		var ids []string
		for _, m := range missing {
			ids = append(ids, m.ID)
		}
		t.Fatalf("unaddressed applicable cases: %s", strings.Join(ids, ", "))
	}
}
