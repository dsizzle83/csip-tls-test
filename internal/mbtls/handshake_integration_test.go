//go:build integration

package mbtls

import (
	"bytes"
	"crypto/x509/pkix"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"csip-tls-test/internal/wolfssl"
)

// TestMain initialises wolfSSL once for the whole integration binary. wolfSSL
// keeps process-global C state, so Init must run exactly once (CLAUDE.md
// wolfSSL_Init invariant), mirroring sim/tlsserver's TestMain.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

// pki holds the on-disk PEM fixtures a handshake test dials with. Two trust
// domains: the "good" CA the server trusts, and an "other" CA it does not (the
// wrong-CA negative).
type pki struct {
	dir           string
	caFile        string // good CA (server + happy client trust anchor)
	otherCAFile   string // untrusted CA (wrong-ca negative)
	serverCert    string
	serverKey     string
	clientCertFor map[string]string // role -> cert path
	clientKeyFor  map[string]string // role -> key path
	noRoleCert    string            // valid client cert, no role ext
	noRoleKey     string
	wrongCACert   string // client cert signed by otherCA
	wrongCAKey    string
	expiredCert   string // client cert past notAfter
	expiredKey    string
}

const happyRole = "GridServiceSunSpec"

var allRoles = []string{
	"GridServiceSunSpec",
	"SuperAdministratorSunSpec",
	"NetworkAdministratorSunSpec",
	"ReadOnlySunSpec",
	"LexaVoltReadOnly",
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	dir := t.TempDir()
	ca := mkCA(t, "mbtls bench client-CA")
	other := mkCA(t, "mbtls untrusted CA")

	p := &pki{
		dir:           dir,
		clientCertFor: map[string]string{},
		clientKeyFor:  map[string]string{},
	}
	p.caFile = filepath.Join(dir, "ca.pem")
	writeCertPEM(t, p.caFile, ca.der)
	p.otherCAFile = filepath.Join(dir, "other-ca.pem")
	writeCertPEM(t, p.otherCAFile, other.der)

	// Server leaf — no role ext (server certs need no role, TCP-28) — SAN'd for
	// loopback.
	server := mkLeaf(t, "mbtls device server", ca, []string{"127.0.0.1", "localhost"}, nil)
	p.serverCert, p.serverKey = writePEMPair(t, dir, "server", server)

	// One happy client leaf per role.
	for _, role := range allRoles {
		leaf := mkLeaf(t, "client-"+role, ca, nil, roleExts(t, role))
		c, k := writePEMPair(t, dir, "client-"+role, leaf)
		p.clientCertFor[role] = c
		p.clientKeyFor[role] = k
	}

	// Negatives.
	noRole := mkLeaf(t, "client-no-role", ca, nil, nil)
	p.noRoleCert, p.noRoleKey = writePEMPair(t, dir, "client-no-role", noRole)

	wrongCA := mkLeaf(t, "client-wrong-ca", other, nil, roleExts(t, happyRole))
	p.wrongCACert, p.wrongCAKey = writePEMPair(t, dir, "client-wrong-ca", wrongCA)

	expired := mkExpiredLeaf(t, "client-expired", ca, nil)
	p.expiredCert, p.expiredKey = writePEMPair(t, dir, "client-expired", expired)

	return p
}

// roleExts wraps a single role extension for a leaf template.
func roleExts(t *testing.T, role string) []pkix.Extension {
	return []pkix.Extension{roleExtUTF8(t, role)}
}

func (p *pki) serverProfile() Profile {
	return DefaultServerProfile(p.caFile, p.serverCert, p.serverKey)
}

func (p *pki) clientProfile(role string) Profile {
	prof := DefaultClientProfile(p.caFile, p.clientCertFor[role], p.clientKeyFor[role])
	prof.RoleAsserted = role
	return prof
}

type acceptResult struct {
	sess *Session
	err  error
}

// startServer stands up a Listener bound to loopback and accepts in a
// background goroutine, delivering each result over a buffered channel. The
// listener is closed on cleanup, which unblocks the accept loop with
// net.ErrClosed.
func startServer(t *testing.T, p Profile) (addr string, results <-chan acceptResult) {
	t.Helper()
	l, err := Listen("127.0.0.1:0", p)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ch := make(chan acceptResult, 8)
	go func() {
		for {
			s, err := l.Accept()
			ch <- acceptResult{s, err}
			if err != nil && errors.Is(err, net.ErrClosed) {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().String(), ch
}

func waitAccept(t *testing.T, ch <-chan acceptResult) (*Session, error) {
	t.Helper()
	select {
	case r := <-ch:
		return r.sess, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("server Accept timed out")
		return nil, nil
	}
}

// TestHandshake_MutualAuth_MandatedCipher is the headline profile proof: a
// loopback client↔server handshake with the full mandated profile completes
// with mutual auth, negotiates the mandated AES-128-GCM suite over TLS 1.3
// (the C11-ordered list puts 1.3 first), the server extracts the client's role
// from the peer cert, and decrypted application bytes round-trip both ways.
func TestHandshake_MutualAuth_MandatedCipher(t *testing.T) {
	p := newPKI(t)
	addr, results := startServer(t, p.serverProfile())

	cs, err := Dial(addr, p.clientProfile(happyRole))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cs.Close()

	ss, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("server Accept: %v", err)
	}
	defer ss.Close()

	if ss.TLSVer != "TLSv1.3" {
		t.Errorf("server negotiated %s, want TLSv1.3 (default profile keeps 1.3 first)", ss.TLSVer)
	}
	if cs.TLSVer != ss.TLSVer {
		t.Errorf("client/server version mismatch: %s vs %s", cs.TLSVer, ss.TLSVer)
	}
	if ss.Cipher != Mandated13[0] { // TLS13-AES128-GCM-SHA256
		t.Errorf("negotiated cipher %q, want mandated GCM %q", ss.Cipher, Mandated13[0])
	}

	// Server extracts the client's role from the presented cert (TCP-29/30).
	if len(ss.PeerDER) == 0 {
		t.Fatal("server has no client PeerDER — mutual auth did not present a client cert")
	}
	role, err := ss.Role()
	if err != nil {
		t.Fatalf("server RoleFromDER: %v", err)
	}
	if role != happyRole {
		t.Errorf("extracted role %q, want %q", role, happyRole)
	}

	// The client presented a server cert too (mutual auth both directions).
	if len(cs.PeerDER) == 0 {
		t.Error("client has no server PeerDER")
	}

	// Decrypted stream round-trips.
	assertRoundTrip(t, cs, ss)
}

// assertRoundTrip proves the decrypted net.Conn carries application bytes both
// directions — this is the stream mbap would ride on.
func assertRoundTrip(t *testing.T, client, server *Session) {
	t.Helper()
	msg := []byte("mbaps-loopback-probe")
	if _, err := client.Conn.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(msg))
	if err := readFull(server.Conn, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("server got %q, want %q", buf, msg)
	}
	// And the reverse.
	reply := []byte("ack")
	if _, err := server.Conn.Write(reply); err != nil {
		t.Fatalf("server write: %v", err)
	}
	rbuf := make([]byte, len(reply))
	if err := readFull(client.Conn, rbuf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(rbuf, reply) {
		t.Fatalf("client got %q, want %q", rbuf, reply)
	}
}

func readFull(c net.Conn, buf []byte) error {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		got += n
		if err != nil {
			if got == len(buf) {
				return nil
			}
			return err
		}
	}
	return nil
}

// TestHandshake_TLS12_GCM proves a TLS-1.2-capped profile negotiates TLS 1.2
// with the mandated ECDHE-ECDSA-AES128-GCM-SHA256 suite (TCP-17 head).
func TestHandshake_TLS12_GCM(t *testing.T) {
	p := newPKI(t)
	sp := p.serverProfile()
	sp.MaxTLS = TLS12
	addr, results := startServer(t, sp)

	cp := p.clientProfile(happyRole)
	cp.MaxTLS = TLS12
	cs, err := Dial(addr, cp)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cs.Close()
	ss, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer ss.Close()

	if ss.TLSVer != "TLSv1.2" {
		t.Errorf("version %s, want TLSv1.2", ss.TLSVer)
	}
	if ss.Cipher != Mandated12[0] {
		t.Errorf("cipher %q, want %q", ss.Cipher, Mandated12[0])
	}
}

// TestHandshake_CCM8_Only proves CCM-8 is negotiated only when GCM and ChaCha
// are disabled (acceptance a): with the suite lists trimmed to CCM-8, the
// handshake completes on ECDHE-ECDSA-AES128-CCM-8.
func TestHandshake_CCM8_Only(t *testing.T) {
	p := newPKI(t)
	ccmOnly := func(prof Profile) Profile {
		prof.MaxTLS = TLS12
		prof.Suites12 = []string{"ECDHE-ECDSA-AES128-CCM-8"}
		prof.Suites13 = []string{"TLS13-AES128-CCM-SHA256"}
		return prof
	}
	addr, results := startServer(t, ccmOnly(p.serverProfile()))
	cs, err := Dial(addr, ccmOnly(p.clientProfile(happyRole)))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cs.Close()
	ss, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer ss.Close()
	if ss.Cipher != "ECDHE-ECDSA-AES128-CCM-8" {
		t.Errorf("cipher %q, want ECDHE-ECDSA-AES128-CCM-8", ss.Cipher)
	}
}

// TestHandshake_NoClientCert_Rejected proves the server fails closed when the
// client presents no certificate (TCP-11/13/48): the handshake is rejected and
// no Session — hence no application bytes — results. Pinned to TLS 1.2 so the
// rejection surfaces during the handshake (the TLS 1.3 post-handshake variant
// is C12's concern, exercised in T06.8).
func TestHandshake_NoClientCert_Rejected(t *testing.T) {
	p := newPKI(t)
	sp := p.serverProfile()
	sp.MaxTLS = TLS12
	addr, results := startServer(t, sp)

	// No CertChainFile/KeyFile => no client cert presented.
	cp := DefaultClientProfile(p.caFile, "", "")
	cp.MaxTLS = TLS12
	cs, err := Dial(addr, cp)
	if err == nil {
		cs.Close()
		t.Fatal("Dial without a client cert succeeded; want handshake rejection")
	}
	ss, aerr := waitAccept(t, results)
	if aerr == nil {
		ss.Close()
		t.Fatal("server Accept returned a Session for a certless client; want rejection")
	}
}

// TestHandshake_WrongCA_Rejected proves a client cert from an untrusted issuer
// is rejected (the wrong-ca negative): the server's trust store does not
// contain otherCA.
func TestHandshake_WrongCA_Rejected(t *testing.T) {
	p := newPKI(t)
	sp := p.serverProfile()
	sp.MaxTLS = TLS12
	addr, results := startServer(t, sp)

	cp := DefaultClientProfile(p.caFile, p.wrongCACert, p.wrongCAKey)
	cp.MaxTLS = TLS12
	cs, err := Dial(addr, cp)
	if err == nil {
		cs.Close()
		t.Fatal("Dial with wrong-CA client cert succeeded; want rejection")
	}
	ss, aerr := waitAccept(t, results)
	if aerr == nil {
		ss.Close()
		t.Fatal("server Accept returned a Session for a wrong-CA client; want rejection")
	}
}

// TestHandshake_MFL512_Observable proves the mandated 512-byte Maximum Fragment
// Length is genuinely negotiated (not always-on) and observable (TCP-59/60,
// acceptance d). The honouring server records the negotiated MFL in every case;
// wolfSSL's client-side get_session does not surface the MFL on a fresh TLS 1.3
// session (see NegotiatedMaxFragment), so the client is asserted under TLS 1.2
// where get_session is reliable.
func TestHandshake_MFL512_Observable(t *testing.T) {
	p := newPKI(t)

	// Default profile (TLS 1.3): the server, as the honouring peer, observes the
	// client's requested 512-byte MFL.
	t.Run("tls13-server-observes", func(t *testing.T) {
		addr, results := startServer(t, p.serverProfile())
		cs, err := Dial(addr, p.clientProfile(happyRole)) // default MFLCode = MFL512
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cs.Close()
		ss, err := waitAccept(t, results)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		defer ss.Close()
		if ss.TLSVer != "TLSv1.3" {
			t.Fatalf("want TLSv1.3, got %s", ss.TLSVer)
		}
		if ss.MFLCode != wolfssl.MFL512 {
			t.Errorf("server negotiated MFL %d, want MFL512 (%d)", ss.MFLCode, wolfssl.MFL512)
		}
	})

	// TLS 1.2: both peers observe the negotiated 512-byte MFL.
	t.Run("tls12-both-observe", func(t *testing.T) {
		sp := p.serverProfile()
		sp.MaxTLS = TLS12
		addr, results := startServer(t, sp)
		cp := p.clientProfile(happyRole)
		cp.MaxTLS = TLS12
		cs, err := Dial(addr, cp)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cs.Close()
		ss, err := waitAccept(t, results)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		defer ss.Close()
		if cs.MFLCode != wolfssl.MFL512 {
			t.Errorf("client negotiated MFL %d, want MFL512 (%d)", cs.MFLCode, wolfssl.MFL512)
		}
		if ss.MFLCode != wolfssl.MFL512 {
			t.Errorf("server negotiated MFL %d, want MFL512 (%d)", ss.MFLCode, wolfssl.MFL512)
		}
	})

	// With the client's MFL request off, the server negotiates NO MFL — proving
	// the 512 above is genuinely negotiated from the client's extension, not a
	// build-time default masquerading as conformance.
	t.Run("mfl-off-not-negotiated", func(t *testing.T) {
		sp := p.serverProfile()
		sp.MaxTLS = TLS12
		addr, results := startServer(t, sp)
		cp := p.clientProfile(happyRole)
		cp.MaxTLS = TLS12
		cp.MFLCode = wolfssl.MFLDisabled
		cs, err := Dial(addr, cp)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer cs.Close()
		ss, err := waitAccept(t, results)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		defer ss.Close()
		if ss.MFLCode != wolfssl.MFLDisabled {
			t.Errorf("server MFL %d with client MFL off, want 0 (not negotiated)", ss.MFLCode)
		}
	})
}

// TestConn_ReadDeadline proves Session.Conn honours a read deadline: a read
// with no data pending returns a net.Error timeout once the deadline passes,
// then clearing the deadline restores normal blocking I/O. This is the
// per-operation deadline mechanism the aggregator wraps each mbap request in
// (T06.4); mbap.Client itself sets none.
func TestConn_ReadDeadline(t *testing.T) {
	p := newPKI(t)
	addr, results := startServer(t, p.serverProfile())
	cs, err := Dial(addr, p.clientProfile(happyRole))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cs.Close()
	ss, err := waitAccept(t, results)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer ss.Close()

	if err := ss.Conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	_, rerr := ss.Conn.Read(make([]byte, 16))
	if rerr == nil {
		t.Fatal("read with no data returned nil error, want timeout")
	}
	var ne net.Error
	if !errors.As(rerr, &ne) || !ne.Timeout() {
		t.Fatalf("read error %v is not a net.Error timeout", rerr)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("read blocked %v past the 150ms deadline", elapsed)
	}

	// Clear the deadline, then prove normal I/O resumes.
	if err := ss.Conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	assertRoundTrip(t, cs, ss)
}

// TestHandshake_AllRoles_Extracted proves every mandatory + vendor role rides a
// real handshake and is extracted server-side (acceptance e end-to-end), and
// that a valid cert with NO role ext still completes the handshake (session up)
// while extraction reports ErrNoRole — the design-01-§3.1 rule that role errors
// are an AuthZ-layer concern, not a handshake failure.
func TestHandshake_AllRoles_Extracted(t *testing.T) {
	p := newPKI(t)
	addr, results := startServer(t, p.serverProfile())

	for _, role := range allRoles {
		t.Run(role, func(t *testing.T) {
			cs, err := Dial(addr, p.clientProfile(role))
			if err != nil {
				t.Fatalf("Dial as %s: %v", role, err)
			}
			defer cs.Close()
			ss, err := waitAccept(t, results)
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			defer ss.Close()
			got, err := ss.Role()
			if err != nil {
				t.Fatalf("RoleFromDER: %v", err)
			}
			if got != role {
				t.Errorf("extracted %q, want %q", got, role)
			}
		})
	}

	t.Run("no-role-session-stays-up", func(t *testing.T) {
		cp := DefaultClientProfile(p.caFile, p.noRoleCert, p.noRoleKey)
		cs, err := Dial(addr, cp)
		if err != nil {
			t.Fatalf("Dial no-role client: %v (handshake must succeed; role is authz-layer)", err)
		}
		defer cs.Close()
		ss, err := waitAccept(t, results)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		defer ss.Close()
		if _, rerr := ss.Role(); !errors.Is(rerr, ErrNoRole) {
			t.Errorf("no-role cert: Role() err = %v, want ErrNoRole", rerr)
		}
	})
}
