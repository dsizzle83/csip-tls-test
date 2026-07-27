package suitepki

// wire.go is the two views of a TLS handshake this suite reasons about, and the
// strict separation between them.
//
// The SOCKET view (Handshake / TLSFacts) is what our own TLS stack was handed
// while the connection was live. It is convenient — the full presented chain,
// the negotiated version and suite, the verification outcome — and it is NOT
// evidence, because a reader of the bundle cannot re-derive any of it. Facts
// from here become Narrative assertions naming this as their source.
//
// The WIRE view (ReadWireHandshake / WireHandshake) is the same handshake read
// back out of the capture with internal/evidence/tlsdis. It is slower, fussier,
// and it is the only thing this suite is willing to cite: a byte range of a
// reassembled TCP direction, with the frames those bytes arrived in and a
// sha256 the bundle's verifier re-derives from the pcap itself.
//
// The two are compared. When the certificate the DUT presented to our socket
// and the certificate in the capture are not the same bytes, that is reported
// loudly — it means the capture is not of the connection we think it is, and
// every citation resting on it would be misattributed.
//
// # Why the byte range is a RECORD span
//
// tlsdis.HandshakeMessage.Offset is an offset into the COALESCED handshake byte
// stream, which is not the TCP stream: the record headers have been removed.
// Citing it against the reassembled direction would point at the wrong bytes.
// What is exact and available is the span of TLS RECORDS the message occupied
// (Record.Offset .. Record.End), so that is what gets cited, and the assertion's
// Method says so. It is a superset of the message only when another message
// shares its last record — a caveat carried on the assertion rather than papered
// over.
//
// # TLS 1.3
//
// TLS 1.3 encrypts everything after ServerHello, certificates included. When the
// capture shows a 1.3 handshake, ReadWireHandshake decrypts it with
// internal/evidence/tlsdecrypt if the run exported an NSS key log, marks the
// result Decrypted, and cites FRAMES rather than a plaintext byte range —
// because the bytes at that offset on the wire really are ciphertext, and an
// assertion claiming otherwise would be false. With no key log it reports the
// absence and lets the check SKIP with that reason.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
)

// HandshakeOptions configure a handshake this suite drives.
type HandshakeOptions struct {
	// ServerName is the SNI value. Empty sends no SNI, which is what the mbaps
	// profile does — the peer is identified by its certificate, not its name.
	ServerName string
	// Identity is the client certificate to present. nil presents none, which
	// is the deliberate no-client-certificate negative.
	Identity *tls.Certificate
	// Roots verifies the peer chain. nil means the chain is recorded but not
	// verified — see the VerifyErr note on TLSFacts.
	Roots *x509.CertPool
	// MinVersion / MaxVersion bound the negotiation. Zero values mean TLS 1.2
	// only, so the peer's Certificate message lands in the capture as plaintext
	// and the evidence needs no secrets to re-check. See the package doc.
	MinVersion, MaxVersion uint16
	// KeyLog receives NSS key-log lines, so a capture of a TLS 1.3 handshake
	// can be decrypted later.
	KeyLog io.Writer
	// Deadline bounds the handshake. Zero means 15 seconds.
	Deadline time.Duration
}

// TLSFacts is one handshake as the socket saw it.
type TLSFacts struct {
	Local, Remote netip.AddrPort
	// Completed reports a handshake that finished. False is a legitimate and
	// often REQUIRED outcome: presenting an error certificate to a conformant
	// peer must not complete.
	Completed bool
	// HandshakeErr is why it did not complete, verbatim. For a peer that
	// refused us it usually names the TLS alert.
	HandshakeErr string

	Version     uint16
	CipherSuite uint16

	// PeerChain is what the peer presented, leaf first, exactly as received.
	PeerChain [][]byte
	// Chain is PeerChain dissected; nil when the peer presented nothing.
	Chain *ChainFacts

	// VerifyErr is the result of verifying PeerChain against Roots.
	//
	// It is a separate field, and it is populated even though the handshake was
	// allowed to proceed regardless, because "we chose not to reject this
	// chain" and "this chain verified" are different facts and a report that
	// conflated them would credit the DUT with a validation it never passed.
	VerifyErr string
	// Verified reports a chain that verified against Roots. It is false when no
	// roots were supplied — unverified, not verified-and-failed.
	Verified bool
	// RootsSupplied records whether verification was even attempted.
	RootsSupplied bool
}

// VersionName renders the negotiated version.
func (f *TLSFacts) VersionName() string { return tlsdis.VersionName(f.Version) }

// Describe renders the handshake outcome for a report.
func (f *TLSFacts) Describe() string {
	if !f.Completed {
		return "handshake did not complete: " + f.HandshakeErr
	}
	chain := "peer presented no certificate"
	if f.Chain != nil {
		chain = f.Chain.Describe()
	}
	return fmt.Sprintf("%s %s, %s", f.VersionName(), tlsdis.CipherSuiteName(f.CipherSuite), chain)
}

// Handshake performs a TLS handshake over an already-established connection.
//
// The connection is taken rather than dialled so the caller can dial it through
// RunCtx.DialTCP, which claims it for frame attribution in the same call. A
// handshake this function drives over a connection the check forgot to claim
// would produce frames nothing can cite.
//
// A handshake that FAILS is not an error: it is the expected outcome of every
// negative fixture. The returned error is reserved for a call that could not be
// attempted at all.
func Handshake(ctx context.Context, conn net.Conn, opt HandshakeOptions) (*TLSFacts, error) {
	if conn == nil {
		return nil, fmt.Errorf("suitepki: Handshake needs a connection")
	}
	facts := &TLSFacts{RootsSupplied: opt.Roots != nil}
	facts.Local, _ = addrPortOf(conn.LocalAddr())
	facts.Remote, _ = addrPortOf(conn.RemoteAddr())

	min, max := opt.MinVersion, opt.MaxVersion
	if min == 0 {
		min = tls.VersionTLS12
	}
	if max == 0 {
		max = tls.VersionTLS12
	}
	cfg := &tls.Config{
		ServerName: opt.ServerName,
		MinVersion: min,
		MaxVersion: max,
		KeyLogWriter: func() io.Writer {
			if opt.KeyLog == nil {
				return nil
			}
			return opt.KeyLog
		}(),
		// The peer's chain is captured and judged here, never used to abort.
		// A certificate-property test case must be able to inspect a chain that
		// would not validate; that is the whole job.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			facts.PeerChain = append(facts.PeerChain, rawCerts...)
			return nil
		},
	}
	if opt.Identity != nil {
		ident := *opt.Identity
		// GetClientCertificate, not Certificates: Go's default selection
		// filters candidates against the CertificateRequest's acceptable-CA
		// list and would silently send an EMPTY certificate when we are
		// deliberately presenting a leaf from an untrusted root — turning the
		// wrong-CA negative into the no-certificate negative without saying so.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &ident, nil
		}
	}

	deadline := opt.Deadline
	if deadline <= 0 {
		deadline = 15 * time.Second
	}
	hctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(hctx); err != nil {
		facts.HandshakeErr = err.Error()
		// The peer's Certificate may have arrived before it rejected us, so the
		// chain is still worth dissecting.
		facts.Chain, _ = dissectIfAny(facts.PeerChain)
		facts.verify(opt.Roots)
		return facts, nil
	}
	st := tc.ConnectionState()
	facts.Completed = true
	facts.Version = st.Version
	facts.CipherSuite = st.CipherSuite
	if len(facts.PeerChain) == 0 {
		for _, c := range st.PeerCertificates {
			facts.PeerChain = append(facts.PeerChain, c.Raw)
		}
	}
	facts.Chain, _ = dissectIfAny(facts.PeerChain)
	facts.verify(opt.Roots)
	return facts, nil
}

func dissectIfAny(ders [][]byte) (*ChainFacts, error) {
	if len(ders) == 0 {
		return nil, nil
	}
	return InspectChain(ders)
}

// verify records what the peer chain would have done against a real trust
// store, without that outcome having influenced the handshake.
func (f *TLSFacts) verify(roots *x509.CertPool) {
	if roots == nil || len(f.PeerChain) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(f.PeerChain[0])
	if err != nil {
		f.VerifyErr = "leaf does not parse: " + err.Error()
		return
	}
	inter := x509.NewCertPool()
	for _, der := range f.PeerChain[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		f.VerifyErr = err.Error()
		return
	}
	f.Verified = true
}

// ---------------------------------------------------------------------------
// The wire view
// ---------------------------------------------------------------------------

// CertMessage is a Certificate handshake message lifted out of the capture,
// with everything needed to cite it.
type CertMessage struct {
	// Chain is the presented chain, dissected, leaf first.
	Chain *ChainFacts
	// Frames are the capture frames the message occupied.
	Frames []int
	// Start and End bound the TLS RECORDS that carried the message within the
	// reassembled direction. See the file comment for why it is the record span
	// and not the message.
	Start, End int
	// Encrypted marks a message recovered by decryption rather than read in the
	// clear. Its Start/End are meaningless in that case and are left zero.
	Encrypted bool
	// Records is how many TLS records the message spanned.
	Records int
}

// HasRange reports whether the message can be cited as a plaintext byte range.
func (m *CertMessage) HasRange() bool { return m != nil && !m.Encrypted && m.End > m.Start }

// AlertRef is one TLS alert with its provenance.
type AlertRef struct {
	tlsdis.Alert
	FromServer bool
	Encrypted  bool
}

// WireHandshake is one TLS handshake read back out of the capture.
type WireHandshake struct {
	Stream                 *netdis.Stream
	ClientAddr, ServerAddr netip.AddrPort
	ClientDir, ServerDir   *netdis.Direction
	Client, Server         *tlsdis.Direction

	ClientHello *tlsdis.ClientHello
	ServerHello *tlsdis.ServerHello
	// ClientHelloFrames / ServerHelloFrames carry the frames each hello spanned.
	ClientHelloFrames, ServerHelloFrames []int

	// ServerCertificate and ClientCertificate are the two Certificate messages.
	// Either may be nil: a client that presented none, or a capture that
	// started mid-connection.
	ServerCertificate *CertMessage
	ClientCertificate *CertMessage

	// CertificateRequestFrames is non-empty when the server asked for a client
	// certificate — the evidence that mutual authentication was demanded.
	CertificateRequestFrames []int

	Alerts []AlertRef

	// NegotiatedVersion is what the ServerHello settled on.
	NegotiatedVersion uint16
	// Decrypted reports that some of the above came from tlsdecrypt.
	Decrypted bool
	// Notes carry everything a reader needs in order not to over-read the
	// result: a truncated capture, an absent key log, a message whose record
	// span shares its last record with another message.
	Notes []string
}

// FatalAlert returns the first fatal alert observed, and from which side.
func (w *WireHandshake) FatalAlert() (AlertRef, bool) {
	for _, a := range w.Alerts {
		if a.Fatal() {
			return a, true
		}
	}
	return AlertRef{}, false
}

// ServerFlow is the direction key for server->client traffic, which is the one
// a citation of the DUT's certificate is made against.
func (w *WireHandshake) ServerFlow() netdis.FlowKey {
	return netdis.FlowKey{
		Src: netdis.Endpoint{Addr: w.ServerAddr.Addr(), Port: w.ServerAddr.Port()},
		Dst: netdis.Endpoint{Addr: w.ClientAddr.Addr(), Port: w.ClientAddr.Port()},
	}
}

// ClientFlow is the direction key for client->server traffic.
func (w *WireHandshake) ClientFlow() netdis.FlowKey { return w.ServerFlow().Reverse() }

// ReadWireHandshake dissects a captured conversation's TLS handshake.
//
// server names which endpoint of the stream is the server, because a
// reassembled conversation carries no notion of who dialled whom and getting it
// backwards would attribute the DUT's certificate to the bench.
//
// kl may be nil. It is only consulted when the handshake reached TLS 1.3 and
// the certificates are therefore encrypted.
func ReadWireHandshake(st *netdis.Stream, server netip.AddrPort, kl *keylog.Log) (*WireHandshake, error) {
	if st == nil {
		return nil, fmt.Errorf("suitepki: ReadWireHandshake needs a stream")
	}
	a, b := endpointAddr(st.Key.A), endpointAddr(st.Key.B)
	var client netip.AddrPort
	switch {
	case a == server:
		client = b
	case b == server:
		client = a
	default:
		return nil, fmt.Errorf("suitepki: %s is not an endpoint of stream %s <> %s", server, a, b)
	}

	w := &WireHandshake{Stream: st, ClientAddr: client, ServerAddr: server}
	w.ServerDir = st.ByFlow(w.ServerFlow())
	w.ClientDir = st.ByFlow(w.ClientFlow())
	if w.ServerDir == nil || w.ClientDir == nil {
		return nil, fmt.Errorf("suitepki: stream %s <> %s is one-directional; a handshake needs both halves", a, b)
	}

	var err error
	if w.Client, err = tlsdis.ParseDirection(w.ClientDir.Bytes.Bytes(), w.ClientDir.Bytes); err != nil {
		w.Notes = append(w.Notes, "client->server record layer: "+err.Error())
	}
	if w.Server, err = tlsdis.ParseDirection(w.ServerDir.Bytes.Bytes(), w.ServerDir.Bytes); err != nil {
		w.Notes = append(w.Notes, "server->client record layer: "+err.Error())
	}
	if w.Client == nil || w.Server == nil {
		return w, fmt.Errorf("suitepki: conversation %s <> %s does not parse as TLS", a, b)
	}

	if m, ok := w.Client.Handshake.Find(tlsdis.HandshakeClientHello); ok {
		w.ClientHello, w.ClientHelloFrames = m.ClientHello, m.Packets
	}
	if m, ok := w.Server.Handshake.Find(tlsdis.HandshakeServerHello); ok {
		w.ServerHello, w.ServerHelloFrames = m.ServerHello, m.Packets
		if m.ServerHello != nil {
			w.NegotiatedVersion = m.ServerHello.NegotiatedVersion()
		}
	}
	if m, ok := w.Server.Handshake.Find(tlsdis.HandshakeCertificateRequest); ok {
		w.CertificateRequestFrames = m.Packets
	}
	w.ServerCertificate = certMessageFrom(w.Server, &w.Notes, "server")
	w.ClientCertificate = certMessageFrom(w.Client, &w.Notes, "client")
	for _, al := range w.Server.Alerts {
		w.Alerts = append(w.Alerts, AlertRef{Alert: al, FromServer: true})
	}
	for _, al := range w.Client.Alerts {
		w.Alerts = append(w.Alerts, AlertRef{Alert: al})
	}

	if w.needsDecryption() {
		w.decrypt(kl)
	}
	if w.Client.Handshake.Truncated || w.Server.Handshake.Truncated {
		w.Notes = append(w.Notes, "the captured handshake is truncated: the capture ends inside a message, "+
			"so anything after that point is absent rather than absent-from-the-wire")
	}
	return w, nil
}

// needsDecryption reports a handshake whose certificates are not in the clear.
func (w *WireHandshake) needsDecryption() bool {
	return w.ServerCertificate == nil && w.NegotiatedVersion == tlsdis.VersionTLS13
}

// decrypt recovers the encrypted flight of a TLS 1.3 handshake.
func (w *WireHandshake) decrypt(kl *keylog.Log) {
	if kl == nil {
		w.Notes = append(w.Notes, "the handshake negotiated TLS 1.3, so the Certificate messages are "+
			"encrypted on the wire, and this run exported no NSS key log — the certificates cannot be "+
			"recovered from the capture")
		return
	}
	params, err := tlsdecrypt.ParamsFromHandshake(w.Client, w.Server)
	if err != nil {
		w.Notes = append(w.Notes, "TLS 1.3 session parameters could not be read from the handshake: "+err.Error())
		return
	}
	sess, err := tlsdecrypt.New(params, kl)
	if err != nil {
		w.Notes = append(w.Notes, "TLS 1.3 decryption is not possible: "+err.Error())
		return
	}
	for _, side := range []struct {
		s   tlsdecrypt.Side
		dir *tlsdis.Direction
		lbl string
	}{{tlsdecrypt.Client, w.Client, "client"}, {tlsdecrypt.Server, w.Server, "server"}} {
		ps, derr := sess.DecryptAll(side.s, side.dir.Stream.Records)
		if derr != nil {
			w.Notes = append(w.Notes, fmt.Sprintf("%s records did not fully decrypt: %v", side.lbl, derr))
		}
		for _, al := range tlsdecrypt.Alerts(ps) {
			w.Alerts = append(w.Alerts, AlertRef{
				Alert: al, FromServer: side.s == tlsdecrypt.Server, Encrypted: true,
			})
		}
		hs, herr := sess.Handshake(side.s)
		if herr != nil || hs == nil {
			if herr != nil {
				w.Notes = append(w.Notes, fmt.Sprintf("%s handshake did not reassemble after decryption: %v", side.lbl, herr))
			}
			continue
		}
		msg, ok := hs.Find(tlsdis.HandshakeCertificate)
		if !ok || msg.Certificate == nil {
			continue
		}
		cm := certMessageOf(msg, true)
		w.Decrypted = true
		if side.s == tlsdecrypt.Server {
			w.ServerCertificate = cm
		} else {
			w.ClientCertificate = cm
		}
		if side.s == tlsdecrypt.Server {
			// In TLS 1.3 the CertificateRequest is encrypted too, so the
			// "mutual authentication was demanded" evidence only exists here.
			if m, ok := hs.Find(tlsdis.HandshakeCertificateRequest); ok && len(m.Packets) > 0 {
				w.CertificateRequestFrames = m.Packets
			}
		}
	}
}

// certMessageFrom pulls a Certificate message out of a plaintext direction.
func certMessageFrom(d *tlsdis.Direction, notes *[]string, label string) *CertMessage {
	if d == nil || d.Handshake == nil {
		return nil
	}
	msg, ok := d.Handshake.Find(tlsdis.HandshakeCertificate)
	if !ok || msg.Certificate == nil {
		return nil
	}
	cm := certMessageOf(msg, false)
	// Locate the record span so the message can be cited as a byte range.
	if len(msg.Records) > 0 && d.Stream != nil {
		first, last := msg.Records[0], msg.Records[len(msg.Records)-1]
		if first >= 0 && last < len(d.Stream.Records) {
			cm.Start = d.Stream.Records[first].Offset
			cm.End = d.Stream.Records[last].End()
			cm.Records = last - first + 1
			if sharesRecord(d, msg) {
				*notes = append(*notes, fmt.Sprintf(
					"the %s Certificate message shares a TLS record with an adjacent handshake message, so the "+
						"cited byte range is the record span and contains a little more than the message itself", label))
			}
		}
	}
	if cm.Chain == nil {
		*notes = append(*notes, fmt.Sprintf("the %s Certificate message carried no parseable certificate", label))
	}
	return cm
}

// sharesRecord reports whether any other handshake message touches one of this
// message's records.
func sharesRecord(d *tlsdis.Direction, msg tlsdis.HandshakeMessage) bool {
	mine := map[int]bool{}
	for _, r := range msg.Records {
		mine[r] = true
	}
	for _, other := range d.Handshake.Messages {
		if other.Offset == msg.Offset && other.Type == msg.Type {
			continue
		}
		for _, r := range other.Records {
			if mine[r] {
				return true
			}
		}
	}
	return false
}

func certMessageOf(msg tlsdis.HandshakeMessage, encrypted bool) *CertMessage {
	cm := &CertMessage{Frames: append([]int(nil), msg.Packets...), Encrypted: encrypted}
	if msg.Certificate == nil {
		return cm
	}
	if ders := msg.Certificate.DERChain(); len(ders) > 0 {
		cm.Chain, _ = InspectChain(ders)
	}
	return cm
}

// SameChain reports whether a chain observed on the wire is byte-identical to
// one observed at the socket, which is the check that stops a citation from
// resting on somebody else's connection.
func SameChain(a, b *ChainFacts) bool {
	return a != nil && b != nil && a.SHA256 == b.SHA256
}

// AlertText renders an alert the way a report should print it.
func AlertText(a AlertRef) string {
	side := "client"
	if a.FromServer {
		side = "server"
	}
	enc := ""
	if a.Encrypted {
		enc = " (recovered by decryption)"
	}
	return fmt.Sprintf("%s sent %s %s in frame(s) %v%s",
		side, tlsdis.AlertLevelName(a.Level), tlsdis.AlertDescriptionName(a.Description), a.Packets, enc)
}

func endpointAddr(e netdis.Endpoint) netip.AddrPort {
	return netip.AddrPortFrom(e.Addr.Unmap(), e.Port)
}

// addrPortOf converts a net.Addr to a netip.AddrPort, unmapping IPv4-in-IPv6 so
// a loopback socket and its capture frame agree on what address they are.
func addrPortOf(a net.Addr) (netip.AddrPort, error) {
	if a == nil {
		return netip.AddrPort{}, fmt.Errorf("suitepki: nil address")
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("suitepki: %q is not an ip:port: %w", a, err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// joinNotes renders a WireHandshake's notes for an assertion.
func joinNotes(notes []string) string { return strings.Join(notes, "; ") }

// tlsCertificate is a NAMED TLS identity. The name travels with it so a report
// can say which fixture was presented — "the expired fixture was refused" is
// evidence; "a certificate was refused" is not.
type tlsCertificate struct {
	name string
	cert tls.Certificate
}

// Name returns the fixture's name.
func (t *tlsCertificate) Name() string {
	if t == nil {
		return "none"
	}
	return t.name
}

// TLS returns the certificate to present, or nil for "present none".
func (t *tlsCertificate) TLS() *tls.Certificate {
	if t == nil {
		return nil
	}
	return &t.cert
}

// loadKeyPair reads a leaf-first chain PEM and its key.
func loadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("suitepki: load %s / %s: %w", certPath, keyPath, err)
	}
	return cert, nil
}
