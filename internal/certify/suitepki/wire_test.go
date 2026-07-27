package suitepki

// wire_test.go proves the wire view against real TLS handshakes.
//
// These tests are the ones that catch the mistakes a certificate suite makes
// silently: reading the record layer as if it were the handshake, citing a byte
// range that does not contain the message it claims to, or reporting "no
// certificate" for a TLS 1.3 connection where the certificate is merely
// encrypted. Every byte in the synthetic capture came off a real loopback
// socket during the test, so a bug in any of that shows up here.

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdis"
)

// settle waits until the recorder has been quiet for a moment, so a test does
// not synthesise a capture while the peer is still writing. Polling for quiet
// rather than sleeping a fixed interval keeps the test both fast and stable.
func (r *recorder) settle(t *testing.T) {
	t.Helper()
	if !r.quiesce(3 * time.Second) {
		t.Fatal("the peer never stopped writing")
	}
}

// wireOf synthesises the capture and dissects the single conversation in it.
func wireOf(t *testing.T, rec *recorder, server netip.AddrPort, kl *keylog.Log) *WireHandshake {
	t.Helper()
	rec.settle(t)
	fi := certify.NewFrameIndex(rec.synthesise())
	streams := fi.Streams()
	if len(streams) != 1 {
		t.Fatalf("capture holds %d conversations, want 1", len(streams))
	}
	w, err := ReadWireHandshake(streams[0], server, kl)
	if err != nil {
		t.Fatalf("ReadWireHandshake: %v (notes: %v)", err, w)
	}
	return w
}

// dialPeer drives one handshake against the loopback peer.
func dialPeer(t *testing.T, p *peer, opt HandshakeOptions) *TLSFacts {
	t.Helper()
	conn, err := net.Dial("tcp", p.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	facts, err := Handshake(context.Background(), conn, opt)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

// TestWireHandshakeTLS12 is the main path: at TLS 1.2 both Certificate messages
// are plaintext in the capture, and every fact this suite cites has to be
// recoverable from those bytes alone.
func TestWireHandshakeTLS12(t *testing.T) {
	h := testHierarchy(t)
	serverLeaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("server"))
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := h.Mint(ShapeSERCAMCAMICADevice, LeafSpec{
		Name: "client", CommonName: "wire test client", Roles: []string{"ReadOnlySunSpec"}, Client: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, serverLeaf.TLSCertificate(), h.SERCA.Pool())

	tc := clientLeaf.TLSCertificate()
	facts := dialPeer(t, p, HandshakeOptions{Identity: &tc, Roots: h.SERCA.Pool()})
	if !facts.Completed {
		t.Fatalf("handshake did not complete: %s", facts.HandshakeErr)
	}
	if !facts.Verified {
		t.Errorf("the peer chain did not verify against its own root: %s", facts.VerifyErr)
	}
	if facts.Version != tls.VersionTLS12 {
		t.Errorf("negotiated %s, want TLS 1.2 — the default ceiling exists so the certificates land in the "+
			"capture in the clear", tlsdis.VersionName(facts.Version))
	}

	server := mustAddrPort(t, p.addr())
	w := wireOf(t, rec, server, nil)

	if w.ClientHello == nil || w.ServerHello == nil {
		t.Fatalf("hellos not found (notes: %v)", w.Notes)
	}
	if len(w.CertificateRequestFrames) == 0 {
		t.Error("no CertificateRequest located; mutual authentication would be unassertable")
	}
	if w.ServerCertificate == nil || w.ServerCertificate.Chain == nil {
		t.Fatalf("no server certificate on the wire (notes: %v)", w.Notes)
	}
	if w.ClientCertificate == nil || w.ClientCertificate.Chain == nil {
		t.Fatalf("no client certificate on the wire (notes: %v)", w.Notes)
	}

	// The wire and the socket must agree byte for byte, or a citation would be
	// evidence for a different connection.
	if !SameChain(facts.Chain, w.ServerCertificate.Chain) {
		t.Errorf("wire chain %s != socket chain %s",
			w.ServerCertificate.Chain.SHA256, facts.Chain.SHA256)
	}
	if got, want := w.ServerCertificate.Chain.Depth, 2; got != want {
		t.Errorf("server chain depth = %d, want %d", got, want)
	}
	if got, want := w.ClientCertificate.Chain.Depth, 3; got != want {
		t.Errorf("client chain depth = %d, want %d", got, want)
	}
	if w.ServerCertificate.Chain.Leaf().Identity == nil {
		t.Error("the server's 2030.5 identity did not survive the wire round trip")
	}

	// The cited byte range must actually contain the certificate. This is the
	// assertion that catches record-span arithmetic errors, which would
	// otherwise produce a bundle whose digests verify over the wrong bytes.
	if !w.ServerCertificate.HasRange() {
		t.Fatal("the server Certificate message has no plaintext byte range")
	}
	span, err := w.ServerDir.Bytes.Range(w.ServerCertificate.Start, w.ServerCertificate.End)
	if err != nil {
		t.Fatalf("cited range does not resolve: %v", err)
	}
	if !bytes.Contains(span, serverLeaf.DER) {
		t.Errorf("the cited byte range [%d,%d) (%d bytes) does not contain the server's leaf certificate",
			w.ServerCertificate.Start, w.ServerCertificate.End, len(span))
	}
	if !bytes.Contains(mustRange(t, w.ClientDir, w.ClientCertificate), clientLeaf.DER) {
		t.Error("the cited client Certificate range does not contain the client's leaf")
	}

	// Frames must be real capture frames.
	if len(w.ServerCertificate.Frames) == 0 {
		t.Error("the server Certificate message carries no frame numbers")
	}
	if len(sessionFrames(w)) == 0 {
		t.Error("sessionFrames returned nothing")
	}
}

func mustRange(t *testing.T, d *netdis.Direction, cm *CertMessage) []byte {
	t.Helper()
	b, err := d.Bytes.Range(cm.Start, cm.End)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// TestWireHandshakeTLS13NeedsTheKeyLog is the honest-failure path: at TLS 1.3
// the certificates are encrypted, and without a key log the suite must SAY so
// rather than report "no certificate presented".
func TestWireHandshakeTLS13NeedsTheKeyLog(t *testing.T) {
	h := testHierarchy(t)
	serverLeaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("server13"))
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "client13", CommonName: "tls13 client", Roles: []string{"ReadOnlySunSpec"}, Client: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, serverLeaf.TLSCertificate(), h.SERCA.Pool())

	var kloglines bytes.Buffer
	tc := clientLeaf.TLSCertificate()
	facts := dialPeer(t, p, HandshakeOptions{
		Identity: &tc, Roots: h.SERCA.Pool(),
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		KeyLog: &kloglines,
	})
	if !facts.Completed {
		t.Fatalf("handshake did not complete: %s", facts.HandshakeErr)
	}
	if facts.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated %s, want TLS 1.3", tlsdis.VersionName(facts.Version))
	}

	server := mustAddrPort(t, p.addr())

	// Without the key log: no certificate, and a note saying exactly why.
	blind := wireOf(t, rec, server, nil)
	if blind.ServerCertificate != nil {
		t.Error("a TLS 1.3 Certificate message was read in the clear, which is impossible")
	}
	if !containsAny(blind.Notes, "no NSS key log") {
		t.Errorf("notes = %v, want one explaining that the certificates are encrypted and no key log was "+
			"exported — otherwise the suite would report an absent certificate", blind.Notes)
	}

	// With it: the same certificate comes back, cited by frame rather than by a
	// plaintext byte range.
	path := filepath.Join(t.TempDir(), "keylog.txt")
	if err := os.WriteFile(path, kloglines.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	kl, err := keylog.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	seeing := wireOf(t, rec, server, kl)
	if seeing.ServerCertificate == nil || seeing.ServerCertificate.Chain == nil {
		t.Fatalf("the certificate was not recovered with the key log (notes: %v)", seeing.Notes)
	}
	if !seeing.Decrypted {
		t.Error("Decrypted is not set although the certificate came from the decryptor")
	}
	if !seeing.ServerCertificate.Encrypted {
		t.Error("the recovered message is not marked Encrypted, so a citation might claim a plaintext range")
	}
	if seeing.ServerCertificate.HasRange() {
		t.Error("a decrypted message reports a plaintext byte range; citing it would digest ciphertext")
	}
	if len(seeing.ServerCertificate.Frames) == 0 {
		t.Error("a decrypted message carries no frames, so it cannot be cited at all")
	}
	if !SameChain(facts.Chain, seeing.ServerCertificate.Chain) {
		t.Error("the decrypted chain is not the chain the socket saw")
	}
	if seeing.ClientCertificate == nil || seeing.ClientCertificate.Chain == nil {
		t.Error("the client's certificate was not recovered; in TLS 1.3 it is encrypted too, and the role " +
			"extension inside it is what the RBAC rows turn on")
	}
}

func containsAny(notes []string, want string) bool {
	for _, n := range notes {
		if len(n) >= len(want) && bytes.Contains([]byte(n), []byte(want)) {
			return true
		}
	}
	return false
}

// TestHandshakeRecordsARefusalRatherThanErroring: presenting an expired
// certificate must come back as an observation, not as a Go error, or every
// negative row in this suite would be recorded as "could not be carried out".
func TestHandshakeRecordsARefusalRatherThanErroring(t *testing.T) {
	h := testHierarchy(t)
	serverLeaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("server-neg"))
	if err != nil {
		t.Fatal(err)
	}
	mica, err := h.IssuerFor(ShapeSERCAMICADevice)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NegativeFixtures(mica, "wire negatives")
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, serverLeaf.TLSCertificate(), h.SERCA.Pool())

	for _, name := range []string{"expired", "wrong-ca", "not-yet-valid"} {
		f, err := set.Fixture(name)
		if err != nil {
			t.Fatal(err)
		}
		tc := f.Leaf.TLSCertificate()
		facts := dialPeer(t, p, HandshakeOptions{Identity: &tc, Roots: h.SERCA.Pool()})
		if facts.Completed {
			t.Errorf("%s: the peer COMPLETED a handshake with a certificate that is %s", name, f.Defect)
		}
		if facts.HandshakeErr == "" {
			t.Errorf("%s: refused with no reason recorded", name)
		}
		// The DUT's certificate arrives before it rejects us, so the suite can
		// still describe the peer even on a refused handshake.
		if facts.Chain == nil {
			t.Errorf("%s: the peer's chain was not captured on a refused handshake", name)
		}
	}

	// And the positive control, so the refusals above mean something.
	good, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "good", CommonName: "good client", Roles: []string{"ReadOnlySunSpec"}, Client: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tc := good.TLSCertificate()
	if facts := dialPeer(t, p, HandshakeOptions{Identity: &tc, Roots: h.SERCA.Pool()}); !facts.Completed {
		t.Fatalf("the positive control was refused too (%s), so the negatives prove nothing", facts.HandshakeErr)
	}
}

// TestHandshakeRecordsVerificationSeparately: the suite never lets its own
// verification decide whether a chain is recorded, so it must record the
// verification RESULT separately or a report could not tell "we chose not to
// reject" from "it verified".
func TestHandshakeRecordsVerificationSeparately(t *testing.T) {
	server := testHierarchy(t)
	other := testHierarchy(t)
	serverLeaf, err := server.Mint(ShapeSERCAMICADevice, conformantLeafSpec("verify"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := server.Mint(ShapeSERCAMICADevice, LeafSpec{
		Name: "c", CommonName: "c", Roles: []string{"ReadOnlySunSpec"}, Client: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, serverLeaf.TLSCertificate(), server.SERCA.Pool())
	tc := client.TLSCertificate()

	// No roots supplied: recorded, not verified, and not claimed as verified.
	blind := dialPeer(t, p, HandshakeOptions{Identity: &tc})
	if !blind.Completed || blind.Chain == nil {
		t.Fatalf("handshake with no roots: %+v", blind)
	}
	if blind.Verified || blind.RootsSupplied || blind.VerifyErr != "" {
		t.Errorf("with no roots: Verified=%v RootsSupplied=%v VerifyErr=%q — unverified must not read as "+
			"verified", blind.Verified, blind.RootsSupplied, blind.VerifyErr)
	}

	// Wrong roots: the handshake still completes (we never reject), but the
	// failure is recorded.
	wrong := dialPeer(t, p, HandshakeOptions{Identity: &tc, Roots: other.SERCA.Pool()})
	if !wrong.Completed {
		t.Fatalf("the suite rejected a peer over its own verification: %s", wrong.HandshakeErr)
	}
	if wrong.Verified || wrong.VerifyErr == "" {
		t.Errorf("with the wrong roots: Verified=%v VerifyErr=%q", wrong.Verified, wrong.VerifyErr)
	}
	if !wrong.RootsSupplied {
		t.Error("RootsSupplied is false although roots were given")
	}
}

// TestReadWireHandshakeRefusesTheWrongServer guards the one input a caller can
// get backwards: naming the wrong endpoint as the server would attribute the
// DUT's certificate to the bench.
func TestReadWireHandshakeRefusesTheWrongServer(t *testing.T) {
	h := testHierarchy(t)
	leaf, err := h.Mint(ShapeSERCAMICADevice, conformantLeafSpec("mis"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := h.Mint(ShapeSERCAMICADevice, LeafSpec{Name: "c", CommonName: "c", Client: true})
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	p := startPeer(t, rec, leaf.TLSCertificate(), h.SERCA.Pool())
	tc := client.TLSCertificate()
	dialPeer(t, p, HandshakeOptions{Identity: &tc, Roots: h.SERCA.Pool()})
	rec.settle(t)

	fi := certify.NewFrameIndex(rec.synthesise())
	st := fi.Streams()[0]
	if _, err := ReadWireHandshake(st, netip.MustParseAddrPort("10.0.0.1:1"), nil); err == nil {
		t.Fatal("an endpoint that is not part of the conversation was accepted as the server")
	}
	if _, err := ReadWireHandshake(nil, netip.MustParseAddrPort("10.0.0.1:1"), nil); err == nil {
		t.Fatal("a nil stream was accepted")
	}
}
