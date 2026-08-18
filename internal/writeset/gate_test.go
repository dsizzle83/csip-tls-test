package writeset

// gate_test.go — the rows for the four defects the gate found in the first cut.
//
// Each names the defect it pins and reproduces the gate's own demonstration
// where there was one, so a reader can see that the row is about the reported
// failure rather than about a nearby one.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
)

// seqr hands out correct running TCP sequence numbers per direction. Hardcoding
// them leaves holes in the reassembled stream, and a stream with a hole is a
// stream the ADU walker cannot finish — which looks exactly like "the tool
// found no writes" and is really "the fixture was malformed".
type seqr struct{ n map[string]uint32 }

func newSeqr() *seqr { return &seqr{n: map[string]uint32{}} }

func (s *seqr) frame(src, dst netip.AddrPort, payload []byte, at time.Time) synthFrame {
	k := src.String() + ">" + dst.String()
	if s.n[k] == 0 {
		s.n[k] = 1
	}
	f := synthFrame{src: src, dst: dst, seq: s.n[k], payload: payload, at: at}
	s.n[k] += uint32(len(payload))
	return f
}

// ── D1: the phantom-block family ─────────────────────────────────────────────

// TestD1_ReversionPollDoesNotManufactureABlock is the gate's own demonstration.
//
// A two-register read of a uint32 under 65536 answers (0, low-word). Polling
// WSetRvrtTms=300 therefore read back as the header "model 0, length 300" and
// manufactured a block at the polled address. The reversion work made that
// polling ROUTINE, so this was not a corner case — it was the normal traffic of
// every bench run since.
func TestD1_ReversionPollDoesNotManufactureABlock(t *testing.T) {
	q := newSeqr()
	frames := []synthFrame{
		// A REAL header: model 705 at 40070.
		q.frame(gw, der, readReq(1, 40070, 2), t0),
		q.frame(der, gw, readResp(1, 705, 30), t0.Add(10*time.Millisecond)),
		// A reversion-timer poll: WSetRvrtTms is a uint32, and 300 fits in the
		// low word, so the pair reads (0, 300).
		q.frame(gw, der, readReq(2, 40122, 2), t0.Add(time.Second)),
		q.frame(der, gw, readResp(2, 0, 300), t0.Add(time.Second+10*time.Millisecond)),
	}
	res, err := Extract(Options{Path: writeCapture(t, frames)})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, b := range res.Chain {
		if b.Model == 0 {
			t.Errorf("a reversion-timer poll manufactured the block M%d@%d+%d. Model id 0 is the high "+
				"word of any uint32 under 65536, not a model", b.Model, b.Base, b.Length)
		}
	}
	if len(res.Chain) != 1 || res.Chain[0].Model != 705 {
		t.Fatalf("chain = %+v, want exactly the real M705 block", res.Chain)
	}
}

// TestD1_ImplausibleModelIDsAndLengthsAreRejected covers the rest of the family:
// a low word that happens to look like a model number is still not one when its
// length is absurd, and an id outside the model-number ranges is never one.
func TestD1_ImplausibleModelIDsAndLengthsAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name       string
		id, length uint16
		want       bool
	}{
		{"a real model", 705, 30, true},
		{"the common model", 1, 66, true},
		{"a vendor block", 64100, 20, true},
		{"id 0 — the high word of a small uint32", 0, 300, false},
		{"the end marker", 0xFFFF, 2, false},
		{"id between the standard and vendor ranges", 5000, 10, false},
		{"zero length", 705, 0, false},
		{"a length no model has", 1, 60000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := plausibleHeader(tc.id, tc.length); got != tc.want {
				t.Errorf("plausibleHeader(%d, %d) = %v, want %v", tc.id, tc.length, got, tc.want)
			}
		})
	}
}

// TestD1_OverlappingBlocksAreAllDropped is the rule that makes SHADOWING
// impossible, and it is the half that matters most: a phantom with a lower base
// used to shadow a real block, because the chain is sorted by base and the
// matcher takes the first containing block. The write then got the wrong axis
// AND the wrong offset — printed as discovered structure.
func TestD1_OverlappingBlocksAreAllDropped(t *testing.T) {
	in := []Block{
		{Model: 705, Base: 40072, Length: 30},
		{Model: 126, Base: 40060, Length: 40}, // overlaps 705's region
		{Model: 712, Base: 40200, Length: 20}, // disjoint
	}
	kept, dropped := rejectOverlaps(in)
	if dropped != 2 {
		t.Errorf("dropped %d, want 2 — BOTH sides of an overlap go, because an overlap proves one is a "+
			"phantom and there is no honest way to choose", dropped)
	}
	if len(kept) != 1 || kept[0].Model != 712 {
		t.Fatalf("kept %+v, want only the disjoint M712", kept)
	}
}

// TestD1_ShadowedWriteReportsUnknownRatherThanTheWrongAxis is the end-to-end
// consequence: with the overlap dropped, the write's address stands alone — a
// weaker claim, and a true one.
func TestD1_ShadowedWriteReportsUnknownRatherThanTheWrongAxis(t *testing.T) {
	q := newSeqr()
	frames := []synthFrame{
		q.frame(gw, der, readReq(1, 40070, 2), t0),
		q.frame(der, gw, readResp(1, 705, 30), t0.Add(10*time.Millisecond)),
		// A second "header" claiming an overlapping region, with a plausible id.
		q.frame(gw, der, readReq(2, 40060, 2), t0.Add(time.Second)),
		q.frame(der, gw, readResp(2, 126, 40), t0.Add(time.Second+10*time.Millisecond)),
		q.frame(gw, der, writeMulti(3, 40072, 5), t0.Add(2*time.Second)),
	}
	res, err := Extract(Options{Path: writeCapture(t, frames)})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(res.Writes) != 1 {
		t.Fatalf("found %d writes, want 1", len(res.Writes))
	}
	if got := res.Writes[0].Axis(); got != "unknown" {
		t.Errorf("the write in the overlapped region is labelled %s; with two blocks claiming it, "+
			"any label is a guess printed as structure", got)
	}
	var sb strings.Builder
	res.Render(&sb)
	if !strings.Contains(sb.String(), "overlapped another and were ALL dropped") {
		t.Errorf("the report does not disclose that blocks were dropped:\n%s", sb.String())
	}
}

// ── D2: the span-shaped window ───────────────────────────────────────────────

// TestD2_RetainedRedeliveryDoesNotSwallowTheGap is the gate's demonstration.
//
// A DERControl stays in /derp/0/derc until it expires or is superseded, and the
// DUT re-fetches every poll cycle — so the mRID is mentioned again and again,
// and "first mention to last mention" is the whole time the control was OFFERED.
// A retained re-delivery ten minutes on used to pull an unrelated write in with
// excluded=0.
func TestD2_RetainedRedeliveryDoesNotSwallowTheGap(t *testing.T) {
	ctrl := "HTTP/1.1 200 OK\r\n\r\n<DERControl><mRID>" + fixtureMRID + "</mRID></DERControl>"
	q := newSeqr()
	frames := []synthFrame{
		q.frame(srv, hub, []byte(ctrl), t0),
		q.frame(gw, der, writeMulti(1, 40072, 1), t0.Add(2*time.Second)),
		// An unrelated write, five minutes in: between two mentions, and inside
		// neither's settle margin.
		q.frame(gw, der, writeMulti(2, 40106, 9), t0.Add(5*time.Minute)),
		// The retained re-delivery: same control, still being served.
		q.frame(srv, hub, []byte(ctrl), t0.Add(10*time.Minute)),
	}
	res, err := Extract(Options{Path: writeCapture(t, frames), MRID: fixtureMRID})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := res.Attributed()
	if len(got) != 1 {
		t.Fatalf("attributed %d writes, want 1: %+v", len(got), got)
	}
	if got[0].Addr != 40072 {
		t.Errorf("attributed the write at %d, want 40072", got[0].Addr)
	}
	if res.Excluded != 1 {
		t.Errorf("excluded=%d, want 1 — the mid-gap write must be excluded AND counted", res.Excluded)
	}
	// And the discontinuity must be disclosed, not merely acted on.
	if len(res.Window.Gaps) != 1 {
		t.Fatalf("recorded %d gaps, want 1", len(res.Window.Gaps))
	}
	var sb strings.Builder
	res.Render(&sb)
	if !strings.Contains(sb.String(), "GAP ") {
		t.Errorf("the report does not disclose the gap between mentions:\n%s", sb.String())
	}
}

// ── D3: two controls in one document ─────────────────────────────────────────

// oneListDoc is a DERControlList carrying BOTH controls, which is how a
// supersession pair is normally served.
func oneListDoc(a, b string) string {
	return "HTTP/1.1 200 OK\r\n\r\n<DERControlList>" +
		"<DERControl><mRID>" + a + "</mRID></DERControl>" +
		"<DERControl><mRID>" + b + "</mRID></DERControl>" +
		"</DERControlList>"
}

const supersessor = "DERC-SP-CURVE-1786940999"

func supersessionFrames() []synthFrame {
	// The realistic shape of a supersession, which is what makes the bound
	// meaningful: the superseded control is served ALONE first and acts; then
	// the supersessor arrives and from that moment BOTH are in the one list
	// document, which is the state no time rule can decompose.
	alone := "HTTP/1.1 200 OK\r\n\r\n<DERControl><mRID>" + fixtureMRID + "</mRID></DERControl>"
	both := oneListDoc(fixtureMRID, supersessor)
	q := newSeqr()
	return []synthFrame{
		q.frame(gw, der, readReq(1, 40070, 2), t0),
		q.frame(der, gw, readResp(1, 705, 30), t0.Add(10*time.Millisecond)),
		q.frame(srv, hub, []byte(alone), t0.Add(time.Second)),
		// The superseded control's own write, while it is the only control.
		q.frame(gw, der, writeMulti(2, 40072, 1), t0.Add(2*time.Second)),
		// The supersession arrives: one document, two controls.
		q.frame(srv, hub, []byte(both), t0.Add(4*time.Second)),
		// The supersessor's write.
		q.frame(gw, der, writeMulti(3, 40074, 2), t0.Add(5*time.Second)),
	}
}

// TestD3_CoResidentControlIsDisclosedLoudly is the headline defect: two controls
// in one list document have IDENTICAL mention sets, so each is credited with the
// other's writes — which is exactly the distinction PC-001 is about. No time
// rule can separate them, so the tool's obligation is to say so.
func TestD3_CoResidentControlIsDisclosedLoudly(t *testing.T) {
	res, err := Extract(Options{Path: writeCapture(t, supersessionFrames()), MRID: fixtureMRID})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !res.Confounded() {
		t.Fatal("an extraction sharing a document with another control reports itself unconfounded")
	}
	var found bool
	for _, c := range res.CoResidents {
		if c.MRID == supersessor && len(c.SharedFrames) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the co-resident control was not detected: %+v", res.CoResidents)
	}
	var sb strings.Builder
	res.Render(&sb)
	out := sb.String()
	for _, want := range []string{"# confounded=YES", "!! CONFOUNDED ATTRIBUTION", "SAME FRAME(S)", supersessor} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not carry %q:\n%s", want, out)
		}
	}
}

// TestD3_CleanAndConfoundedReportsAreVisuallyDistinct is the gate's actual
// requirement: a reader must not have to compare mention lists to tell which
// kind of extraction they are holding.
func TestD3_CleanAndConfoundedReportsAreVisuallyDistinct(t *testing.T) {
	clean := extractFixture(t, fixtureMRID)
	var a strings.Builder
	clean.Render(&a)

	conf, err := Extract(Options{Path: writeCapture(t, supersessionFrames()), MRID: fixtureMRID})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	var b strings.Builder
	conf.Render(&b)

	if !strings.Contains(a.String(), "# confounded=no") {
		t.Error("the clean report does not state that it is clean")
	}
	if strings.Contains(a.String(), "!!") {
		t.Error("the clean report carries the confounded marker")
	}
	if !strings.Contains(b.String(), "!!") {
		t.Error("the confounded report is not visually marked")
	}
}

// TestD3_SupersessionBoundSeparatesThePair is the cut that CAN separate them.
// The caller knows the pair; the capture cannot.
func TestD3_SupersessionBoundSeparatesThePair(t *testing.T) {
	res, err := Extract(Options{
		Path: writeCapture(t, supersessionFrames()), MRID: fixtureMRID, UntilMRID: supersessor,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := res.Attributed()
	if len(got) != 1 {
		t.Fatalf("attributed %d writes, want 1 — only the write before the supersession boundary: %+v",
			len(got), got)
	}
	if got[0].Addr != 40072 {
		t.Errorf("attributed the write at %d, want the superseded control's 40072", got[0].Addr)
	}
	var sb strings.Builder
	res.Render(&sb)
	out := sb.String()
	if !strings.Contains(out, "bound: cut at") {
		t.Errorf("the report does not state the supersession cut:\n%s", out)
	}
	// The co-residency is still disclosed — it is a fact about the capture —
	// but the banner must say the cut addresses it, or a reader cannot tell a
	// resolved confound from an unresolved one.
	if !strings.Contains(out, "THE BOUND ABOVE CUTS AT THIS CONTROL") {
		t.Errorf("the banner does not say the bound addresses the co-residency it names:\n%s", out)
	}
}

// TestD3_UnknownSupersessorIsAnError — a bound that matched nothing would
// silently degrade to "no bound", which is the confounded answer wearing a
// flag that says it was cut.
func TestD3_UnknownSupersessorIsAnError(t *testing.T) {
	_, err := Extract(Options{
		Path: writeCapture(t, supersessionFrames()), MRID: fixtureMRID, UntilMRID: "DERC-NOT-HERE",
	})
	if err == nil {
		t.Fatal("a superseding mRID absent from the capture was accepted")
	}
	if !strings.Contains(err.Error(), "supersession boundary") {
		t.Errorf("the error does not name the missing boundary: %v", err)
	}
}

// ── D4: TLS ──────────────────────────────────────────────────────────────────

// tlsFixture is a REAL TLS session: crypto/tls on both ends over loopback TCP,
// with a real NSS key log. Recording the two byte streams and replaying them as
// packets is as close to a captured TLS leg as a unit test can get, and it is
// the only way to exercise decryptInto at all — the plaintext fixture leaves it
// at 0% while every real southbound capture on this bench is TLS.
type tlsFixture struct {
	clientStream, serverStream []byte
	keylog                     []byte
}

func runTLS(t *testing.T, clientSays, serverSays []byte) tlsFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	var keyMu sync.Mutex
	var keyBuf bytes.Buffer
	kw := writerFn(func(b []byte) (int, error) {
		keyMu.Lock()
		defer keyMu.Unlock()
		return keyBuf.Write(b)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var cRec, sRec recorder
	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = raw.Close() }()
		srvConn := tls.Server(&tapConn{Conn: raw, in: &cRec, out: &sRec}, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			MinVersion:   tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			KeyLogWriter: kw,
		})
		if err := srvConn.Handshake(); err != nil {
			done <- err
			return
		}
		buf := make([]byte, len(clientSays))
		if _, err := io.ReadFull(srvConn, buf); err != nil {
			done <- err
			return
		}
		if _, err := srvConn.Write(serverSays); err != nil {
			done <- err
			return
		}
		_, _ = io.Copy(io.Discard, srvConn)
		done <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli := tls.Client(raw, &tls.Config{
		RootCAs: pool, ServerName: "localhost",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		KeyLogWriter: kw,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := cli.Write(clientSays); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(serverSays))
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatal(err)
	}
	_ = cli.CloseWrite()
	<-done
	_ = raw.Close()

	keyMu.Lock()
	defer keyMu.Unlock()
	return tlsFixture{clientStream: cRec.b.Bytes(), serverStream: sRec.b.Bytes(), keylog: keyBuf.Bytes()}
}

type writerFn func([]byte) (int, error)

func (f writerFn) Write(b []byte) (int, error) { return f(b) }

type recorder struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (r *recorder) add(p []byte) {
	r.mu.Lock()
	r.b.Write(p)
	r.mu.Unlock()
}

// tapConn records the bytes each side puts on the wire, which is what a capture
// would have held.
type tapConn struct {
	net.Conn
	in, out *recorder
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.in.add(p[:n])
	}
	return n, err
}

func (c *tapConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.out.add(p[:n])
	}
	return n, err
}

// tlsCapture replays a recorded TLS session as packets on the given port.
func tlsCapture(t *testing.T, f tlsFixture, port uint16) (capPath, klPath string) {
	t.Helper()
	client := netip.MustParseAddrPort("10.0.0.9:51000")
	server := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.8"), port)
	var frames []synthFrame
	var cSeq, sSeq uint32 = 1, 1
	// One packet per direction is enough: the reassembler joins them and the
	// record parser walks the whole stream.
	frames = append(frames, synthFrame{src: client, dst: server, seq: cSeq, payload: f.clientStream, at: t0})
	frames = append(frames, synthFrame{src: server, dst: client, seq: sSeq, payload: f.serverStream, at: t0.Add(time.Second)})

	dir := t.TempDir()
	capPath = filepath.Join(dir, "tls.pcap")
	writeCaptureAt(t, capPath, frames)
	klPath = filepath.Join(dir, "run.keylog")
	if err := os.WriteFile(klPath, f.keylog, 0o644); err != nil {
		t.Fatal(err)
	}
	return capPath, klPath
}

// TestD4_SouthboundTLSWritesAreRecovered exercises decryptInto on a real TLS
// session — the path every mbaps leg on this bench takes and the plaintext
// fixture never touched.
func TestD4_SouthboundTLSWritesAreRecovered(t *testing.T) {
	req := append(readReq(1, 40070, 2), writeMulti(2, 40072, 11, 22, 33)...)
	resp := readResp(1, 705, 30)
	f := runTLS(t, req, resp)
	capPath, klPath := tlsCapture(t, f, 802)

	res, err := Extract(Options{Path: capPath, KeyLogPath: klPath})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(res.Writes) != 1 {
		t.Fatalf("recovered %d writes from the TLS leg, want 1 (notes: %v)", len(res.Writes), res.Notes)
	}
	w := res.Writes[0]
	if !w.TLS {
		t.Error("the write is not marked as recovered from inside TLS")
	}
	if w.Addr != 40072 || w.Count != 3 {
		t.Errorf("write = addr %d count %d, want 40072/3", w.Addr, w.Count)
	}
	if w.Frame == 0 || w.Time.IsZero() {
		t.Errorf("the TLS write carries no frame/timestamp (frame=%d ts=%v) — a citation needs both",
			w.Frame, w.Time)
	}
	// The chain came out of the encrypted stream too.
	if len(res.Chain) != 1 || res.Chain[0].Model != 705 {
		t.Errorf("chain from the TLS leg = %+v, want M705", res.Chain)
	}
}

// TestD4_NorthboundTLSIsDecryptedSoTheMRIDCanBeFound is the other half of the
// gate finding: the mRID lives on the NORTHBOUND leg, that leg is TLS, and only
// the southbound ports used to be decrypted — so the search ran over ciphertext
// and the error text blamed a key log that was never going to be applied.
func TestD4_NorthboundTLSIsDecryptedSoTheMRIDCanBeFound(t *testing.T) {
	doc := "HTTP/1.1 200 OK\r\n\r\n<DERControlList><DERControl><mRID>" + fixtureMRID + "</mRID></DERControl></DERControlList>"
	f := runTLS(t, []byte("GET /derp/0/derc HTTP/1.1\r\n\r\n"), []byte(doc))
	capPath, klPath := tlsCapture(t, f, 443)

	res, err := Extract(Options{Path: capPath, KeyLogPath: klPath, MRID: fixtureMRID})
	if err != nil {
		t.Fatalf("the mRID was not found on a decrypted northbound leg: %v", err)
	}
	if res.Window == nil || len(res.Window.Mentions) == 0 {
		t.Fatal("no mentions were recovered from the northbound TLS leg")
	}
}

// writeCaptureAt is writeCapture with the path chosen by the caller.
func writeCaptureAt(t *testing.T, path string, specs []synthFrame) {
	t.Helper()
	pkts := make([][]byte, 0, len(specs))
	times := make([]time.Time, 0, len(specs))
	for _, s := range specs {
		pkts = append(pkts, s.bytes())
		times = append(times, s.at)
	}
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(buf[4:6], 2)
	binary.LittleEndian.PutUint16(buf[6:8], 4)
	binary.LittleEndian.PutUint32(buf[16:20], 262144)
	binary.LittleEndian.PutUint32(buf[20:24], 1)
	for i, d := range pkts {
		hdr := make([]byte, 16)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(times[i].Unix()))
		binary.LittleEndian.PutUint32(hdr[4:8], uint32(times[i].Nanosecond()/1000))
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(d)))
		binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(d)))
		buf = append(buf, hdr...)
		buf = append(buf, d...)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}
