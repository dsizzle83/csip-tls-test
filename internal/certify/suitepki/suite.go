package suitepki

// suite.go binds the catalog uids to the checks and holds what they all share:
// opening a claimed, inspected session to the DUT, finding that session again in
// the capture, and turning a certificate fact into a citation.
//
// Ten of SS-TEST-PKI's 21 uids are registered. The other eleven are the
// SunSpec-package and key-import rows the catalog marks inapplicable with
// reasons; they are accounted for in COVERAGE.md's Inapplicable list, not here.
// See the package doc for why registering PKI-4/5/6/7 — which the catalog also
// marks inapplicable, but for the opposite reason — is a deliberate decision
// rather than an oversight.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
)

// Suite is the suite name these checks register under, for -suite.
const Suite = "pki"

// The catalog uids this suite implements.
const (
	UIDMandatoryTLS   = "ss-test-pki::PKI-1"
	UIDCrossIssuer    = "ss-test-pki::PKI-3"
	UIDIdentitySAN    = "ss-test-pki::PKI-4"
	UIDIdentityUnique = "ss-test-pki::PKI-5"
	UIDModelOIDPEN    = "ss-test-pki::PKI-6"
	UIDSerialEncoding = "ss-test-pki::PKI-7"
	UIDSingleChain    = "ss-test-pki::PKI-8"
	UIDDeepestChain   = "ss-test-pki::PKI-11"
	UIDCAHierarchy    = "ss-test-pki::PKI-19"
	UIDErrorCerts     = "ss-test-pki::PKI-20"
)

func init() { Register(certify.Default()) }

// Register binds this suite's checks. Tests call it against a private registry
// so they neither see nor disturb the process-wide one.
func Register(reg *certify.Registry) {
	reg.Register(UIDMandatoryTLS, Suite, checkMandatoryTLS,
		certify.WithRequires("bench"), certify.WithOrder(10))
	reg.Register(UIDIdentitySAN, Suite, checkIdentitySAN,
		certify.WithRequires("bench"), certify.WithOrder(20))
	reg.Register(UIDIdentityUnique, Suite, checkIdentityUnique,
		certify.WithRequires("bench"), certify.WithOrder(21))
	reg.Register(UIDModelOIDPEN, Suite, checkModelOIDPEN,
		certify.WithRequires("bench"), certify.WithOrder(22))
	reg.Register(UIDSerialEncoding, Suite, checkSerialEncoding,
		certify.WithRequires("bench"), certify.WithOrder(23))
	reg.Register(UIDSingleChain, Suite, checkSingleChain,
		certify.WithRequires("bench"), certify.WithOrder(30))
	reg.Register(UIDDeepestChain, Suite, checkDeepestChain,
		certify.WithRequires("bench"), certify.WithOrder(40))
	reg.Register(UIDCAHierarchy, Suite, checkCAHierarchy,
		certify.WithRequires("bench"), certify.WithOrder(41))
	reg.Register(UIDCrossIssuer, Suite, checkCrossIssuer,
		certify.WithRequires("bench", "pki"), certify.WithOrder(50))
	reg.Register(UIDErrorCerts, Suite, checkErrorCertificates,
		certify.WithRequires("bench", "pki"), certify.WithOrder(60))
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// session is one handshake this suite drove against the DUT, kept from the live
// phase into the citation phase.
//
// The 4-tuple is the load-bearing field. It is recorded while the socket is
// open because LocalAddr is gone after Close, and without it the citation phase
// cannot tell which of several conversations in the capture was this one.
type session struct {
	Label         string
	Local, Remote netip.AddrPort
	Facts         *TLSFacts
}

// dialDUT opens a claimed TCP connection to target and drives a handshake over
// it.
//
// The connection is opened with RunCtx.DialTCP, which claims it for frame
// attribution in the same call: a handshake driven over an unclaimed connection
// produces frames no assertion is permitted to cite, which is the failure this
// framework exists to make impossible.
//
// A refused or unreachable DUT comes back as an error, because a check that
// could not reach the DUT has established nothing about it. A handshake that
// FAILS comes back as a session with Facts.Completed false — that is an
// observation, and for the negative fixtures it is the required one.
func dialDUT(ctx context.Context, rc *certify.RunCtx, label string, opt HandshakeOptions) (*session, error) {
	target := rc.Targets.Gateway
	if target == "" {
		return nil, fmt.Errorf("no DUT address configured (-gateway)")
	}
	return dialTarget(ctx, rc, target, label, opt)
}

// dialTarget is dialDUT against an explicitly named endpoint, for the checks
// whose subject is not the mbaps interface.
func dialTarget(ctx context.Context, rc *certify.RunCtx, target, label string, opt HandshakeOptions) (*session, error) {
	conn, err := rc.DialTCP(ctx, target, label)
	if err != nil {
		return nil, fmt.Errorf("could not reach the DUT at %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()

	s := &session{Label: label}
	s.Local, _ = addrPortOf(conn.LocalAddr())
	s.Remote, _ = addrPortOf(conn.RemoteAddr())
	facts, err := Handshake(ctx, conn, opt)
	if err != nil {
		return nil, err
	}
	s.Facts = facts
	rc.Logf("%s: %s", label, facts.Describe())
	return s, nil
}

// wire finds this session's conversation in the capture and dissects its
// handshake. The second result is the reason it could not be done, for a SKIP
// assertion — never a silent nil.
func (s *session) wire(ev *certify.Evidence) (*WireHandshake, string) {
	if !ev.HasFrames() {
		return nil, "no capture frames were attributed to this test case, so nothing on the wire can be cited"
	}
	st := streamFor(ev, s.Local, s.Remote)
	if st == nil {
		return nil, fmt.Sprintf("the capture holds no conversation %s <> %s (attributed streams: %s)",
			s.Local, s.Remote, strings.Join(ev.Set.Streams, ", "))
	}
	w, err := ReadWireHandshake(st, s.Remote, ev.KeyLog)
	if err != nil {
		return nil, "the captured conversation does not dissect as a TLS handshake: " + err.Error()
	}
	return w, ""
}

// streamFor returns the attributed conversation between exactly this pair of
// endpoints. Matching on both ends rather than on the well-known port is what
// keeps a check that opened several sessions to the DUT from citing the wrong
// one.
func streamFor(ev *certify.Evidence, local, remote netip.AddrPort) *netdis.Stream {
	for _, st := range ev.Streams() {
		a, b := endpointAddr(st.Key.A), endpointAddr(st.Key.B)
		if (a == local && b == remote) || (a == remote && b == local) {
			return st
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Citations
// ---------------------------------------------------------------------------

// certificateCitationMethod describes, on every assertion, exactly how a
// certificate fact was reached — including the caveat about the record span.
const certificateCitationMethod = "the peer's X.509 leaf lifted out of the TLS Certificate handshake message in " +
	"the capture (internal/evidence/tlsdis) and its extensions walked from raw DER; cited as the span of TLS " +
	"records carrying that message in the reassembled direction"

// citeCert turns a fact read out of a Certificate message into an assertion
// over the bytes that carried it.
//
// A plaintext message is cited as a byte range, which is the strongest form: a
// reader opens the pcap, extracts those bytes, and parses the certificate for
// themselves. A message recovered by decryption cannot be — the bytes at that
// offset really are ciphertext — so its FRAMES are cited instead and the method
// says why.
func citeCert(ev *certify.Evidence, dir *netdis.Direction, cm *CertMessage,
	claim string, v certify.Verdict, observed string) (certify.Assertion, error) {

	switch {
	case cm == nil:
		return ev.SkipAssertion(claim, certificateCitationMethod,
			"no Certificate handshake message was found in this conversation"), nil
	case cm.HasRange() && dir != nil:
		return ev.CiteBytes(claim, certificateCitationMethod, v, observed, dir, cm.Start, cm.End)
	case len(cm.Frames) > 0:
		method := certificateCitationMethod + "; the message was encrypted on the wire (TLS 1.3) and was " +
			"recovered with the run's NSS key log, so the frames it occupied are cited rather than a " +
			"plaintext byte range"
		return ev.CiteFrames(claim, method, v, observed, cm.Frames)
	default:
		return ev.SkipAssertion(claim, certificateCitationMethod,
			"the Certificate message was located but carries neither a plaintext byte range nor frame numbers"), nil
	}
}

// leafFacts returns the peer leaf from a wire-read handshake, or the reason
// there is none.
func leafFacts(cm *CertMessage) (*CertFacts, string) {
	if cm == nil {
		return nil, "the peer sent no Certificate handshake message"
	}
	if cm.Chain == nil || cm.Chain.Leaf() == nil {
		return nil, "the peer's Certificate message carried no parseable certificate"
	}
	return cm.Chain.Leaf(), ""
}

// crossCheckSocket compares the chain read off the wire against the chain our
// own TLS stack was handed, and returns a WARN assertion when they differ.
//
// They must be the same bytes. When they are not, the capture is not of the
// connection the check thinks it is, and every citation resting on it is
// misattributed — which is a finding about the RUN, not about the DUT, and has
// to be said out loud rather than absorbed.
func crossCheckSocket(ev *certify.Evidence, s *session, w *WireHandshake) *certify.Assertion {
	if s.Facts == nil || s.Facts.Chain == nil || w.ServerCertificate == nil || w.ServerCertificate.Chain == nil {
		return nil
	}
	if SameChain(s.Facts.Chain, w.ServerCertificate.Chain) {
		return nil
	}
	a := ev.SkipAssertion(
		"the certificate chain in the capture is the chain the DUT presented to this check",
		"sha256 of the concatenated chain DER, wire view vs socket view",
		fmt.Sprintf("they differ: socket %s, capture %s — the attributed conversation is not this check's "+
			"handshake, so no citation from it can be trusted",
			shortHash(s.Facts.Chain.SHA256), shortHash(w.ServerCertificate.Chain.SHA256)))
	a.Verdict = certify.Warn
	return &a
}

// ---------------------------------------------------------------------------
// Identities the checks present
// ---------------------------------------------------------------------------

// benchIdentity loads a role certificate from the committed fixture tree to
// present to the DUT, preferring the least-privileged role that exists.
//
// Least privilege is not a nicety here: these checks run against a live gateway
// on a shared bench, and a suite that authenticated as SuperAdministrator to
// read a certificate would be one bug away from writing a register.
func benchIdentity(rc *certify.RunCtx) (*tlsCertificate, string) {
	if rc.PKI == nil {
		return nil, "no mbaps certificate fixtures are configured (-pki)"
	}
	for _, role := range []string{"read-only", "lexavolt-read-only", "grid-service", "net-admin", "super-admin"} {
		kp, err := rc.PKI.Role(role)
		if err != nil {
			continue
		}
		cert, err := loadKeyPair(kp.Cert, kp.Key)
		if err != nil {
			continue
		}
		return &tlsCertificate{cert: cert, name: role}, ""
	}
	return nil, fmt.Sprintf("no usable role fixture in %s", rc.PKI.Dir)
}

// benchIdentities returns up to n distinct role fixtures, so a check that needs
// the FRAMEWORK side to vary between connections can vary it.
func benchIdentities(rc *certify.RunCtx, n int) []*tlsCertificate {
	if rc.PKI == nil {
		return nil
	}
	names := make([]string, 0, len(rc.PKI.Roles))
	for name := range rc.PKI.Roles {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []*tlsCertificate
	for _, name := range names {
		kp, err := rc.PKI.Role(name)
		if err != nil {
			continue
		}
		cert, err := loadKeyPair(kp.Cert, kp.Key)
		if err != nil {
			continue
		}
		out = append(out, &tlsCertificate{cert: cert, name: name})
		if len(out) == n {
			break
		}
	}
	return out
}

// benchRoot adopts the bench root CA, which is the trust anchor the DUT's
// trust domain is configured with. A check that needs the DUT to ACCEPT
// something must issue it under this root; a freshly minted hierarchy can only
// ever demonstrate refusal.
func benchRoot(rc *certify.RunCtx) (*CA, string) {
	if rc.PKI == nil || rc.PKI.CA == "" {
		return nil, "no mbaps certificate fixtures are configured (-pki)"
	}
	keyPath := strings.TrimSuffix(rc.PKI.CA, "-cert.pem") + "-key.pem"
	ca, err := AdoptCAFromFiles("bench root CA", rc.PKI.CA, keyPath)
	if err != nil {
		return nil, fmt.Sprintf("the bench root CA's private key is not available (%v) — this check can only "+
			"mint material the DUT is required to REJECT, not material it is required to ACCEPT", err)
	}
	return ca, ""
}

// summarise renders a list of observations as one line for a report.
func summarise(parts []string) string { return strings.Join(parts, "; ") }
