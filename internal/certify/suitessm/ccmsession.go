package suitessm

// ccmsession.go establishes a real, COMPLETED mbaps session on one mandated
// cipher suite — including the two the rest of this suite cannot reach.
//
// # What was wrong, and what the document actually asks for
//
// SSM-CONF-v0.8 §2.5.1.1 walks the three mandated TLS 1.2 suites one at a time,
// and after each one says:
//
//	[S] EUT-S accepts the connection and completes the handshake.
//
// with §2.5.1.3's criterion "The EUT-S successfully establishes a secure session
// using each of the mandatory TLS v1.2 cipher suites." §2.5.2 says the same of
// 0x1301 / 0x1303 / 0x1304.
//
// Two of the mandated six use AES-CCM — 0xC0AE and 0x1304 — and Go's crypto/tls
// implements no CCM cipher. So this suite could offer a CCM-only ClientHello and
// watch the DUT select it and send its whole server flight, and could not
// establish a session on it. The row therefore carried a permanent WARN caveat:
// "the DUT's SELECTION of the suite and its full server flight are asserted from
// the capture, but this bench's TLS stack (Go crypto/tls) implements no CCM
// cipher, so no session was established on it and none is claimed." Honest, and
// a standing gap on a MUST row (SunSpecTCP-17), published on every run as the
// row's own verdict.
//
// internal/tlsprobe closes it: a small independent client on the wolfSSL the
// bench's sims already link, pinned to one suite, which completes the mTLS
// handshake and carries a SunSpec Model 1 read inside the tunnel. This file is
// the bridge — it turns the run's PKI fixtures and frame window into a probe
// Spec, and turns the probe's report back into the suite's own vocabulary.
//
// # The crypto/tls path is kept, as a fallback with a stated reason
//
// cmd/certify must stay buildable with CGO_ENABLED=0 (the certify gate's second
// step), and in that build tlsprobe.Dial returns ErrUnavailable. For a non-CCM
// suite that is recoverable: crypto/tls can complete GCM and ChaCha20-Poly1305
// perfectly well, so the session is established the old way and the bundle
// records which client established it. For a CCM suite it is not recoverable,
// and the check says so with the same honesty the old caveat had — the
// difference being that it is now a property of ONE BUILD rather than of the
// bench.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
	"csip-tls-test/internal/tlsprobe"
)

// sessionRole is the client identity every completing session in this file
// presents. GridServiceSunSpec is a fully-privileged conformant fixture, which
// is what a cipher-suite procedure wants: the subject is the suite, and an
// identity the DUT might refuse for its ROLE would confound the two.
const sessionRole = "grid-service"

// probeSuites maps this suite's codepoints onto the probe's suite table, so a
// check names a suite once, as the codepoint the capture carries.
//
// It is a lookup rather than a second transcription: tlsprobe/suites.go holds
// the names and the document reference, and mandatedProbeSuite fails loudly for
// a codepoint that is not in it rather than inventing one.
func mandatedProbeSuite(code uint16) (tlsprobe.Suite, error) {
	s, ok := tlsprobe.ByCode(code)
	if !ok {
		return tlsprobe.Suite{}, fmt.Errorf(
			"suitessm: 0x%04X %s is not one of the suites SSM-CONF-v0.8 mandates, so no completing "+
				"session is required on it", code, tlsdis.CipherSuiteName(code))
	}
	return s, nil
}

// benchObstacle reports a session failure whose cause is THIS BENCH rather than
// the DUT, with the sentence a check should print.
//
// A cipher-suite row reads "no session was established" as "the EUT-S would not
// complete a handshake on a suite SunSpecTCP-17 makes mandatory", which is a
// FAIL. That reading is only sound when the DUT is what refused. When the
// bench's own client refused the DUT's CERTIFICATE — no trust anchor for its
// issuer, an extendedKeyUsage naming no serverAuth purpose, an expired leaf —
// the same symptom means something else entirely, and publishing it as the
// row's verdict would be a finding about a device that did nothing wrong.
//
// Those PKI facts are not lost: PKI-003, PKI-004, PKI-007 and PKI-008 measure
// the DUT's certificate on their own rows, where a defect belongs.
func benchObstacle(err error) (string, bool) {
	he, ok := tlsprobe.Refused(err)
	if !ok || !he.PeerRejectedByUs {
		return "", false
	}
	return he.Diagnosis, true
}

// completedSession is one established session on one mandated suite, whichever
// of the bench's two clients established it.
type completedSession struct {
	// Suite is the suite it was pinned to.
	Suite tlsprobe.Suite
	// Client names the stack that established it, for the bundle: a reader
	// must be able to tell which of the bench's clients produced the evidence.
	Client string
	// Local and Remote are the socket's own addresses, captured at dial time so
	// the citation phase can find the conversation after the session is closed.
	Local, Remote netip.AddrPort
	// Negotiated is what the handshake settled on, rendered.
	Negotiated string
	// Model1 is the SunSpec Common Model read carried inside the tunnel, or ""
	// when none was attempted.
	Model1 string
	// Model1OK reports whether that read was answered conformantly.
	Model1OK bool
	// KeylogNote is set when this session's secrets could NOT be exported, so
	// the check can say why its records will not decrypt in the capture.
	KeylogNote string
}

// Describe renders the session for a tally line.
func (s *completedSession) Describe() string {
	out := fmt.Sprintf("an mbaps session was ESTABLISHED on %s (%s, via the %s client)",
		s.Suite, s.Negotiated, s.Client)
	if s.Model1 != "" {
		out += "; " + s.Model1
	}
	if s.KeylogNote != "" {
		// A fact about the BUILD, carried where a reader of the row meets it:
		// this session's records are in the capture and will not decrypt, so an
		// application-layer criterion about it could not be re-derived by a
		// third party. CRYP-001/002's criteria are handshake criteria and do
		// not need it, which is why this is a note and not a caveat.
		out += " (note: " + s.KeylogNote + ")"
	}
	return out
}

// completeOnSuite establishes a session pinned to one mandated suite.
//
// The connection is claimed on the check's frame window BEFORE the handshake —
// tlsprobe.Spec.OnConnect is called at exactly that moment — so a handshake the
// DUT refuses still produces attributable frames and the refusal is citable.
func completeOnSuite(ctx context.Context, rc *certify.RunCtx, pf preflight,
	code uint16, note string) (*completedSession, error) {

	suite, err := mandatedProbeSuite(code)
	if err != nil {
		return nil, err
	}
	if pf.PKI == nil {
		return nil, fmt.Errorf("suitessm: no mbaps certificate fixture set is configured (-pki certs/mbaps), "+
			"so no session can be established on %s", suite)
	}
	kp, err := pf.PKI.Role(sessionRole)
	if err != nil {
		return nil, err
	}
	cas := []string{pf.PKI.CA}
	if pf.PKI.Intermediate != "" {
		cas = append(cas, pf.PKI.Intermediate)
	}

	spec := tlsprobe.Spec{
		Target:     pf.Target,
		CAFiles:    cas,
		CertFile:   kp.Cert,
		KeyFile:    kp.Key,
		Suite:      suite,
		KeylogPath: rc.Capture.KeyLogPath,
		Unit:       pinnedUnit(rc),
		Deadline:   opDeadline * 2,
		OnConnect:  func(c net.Conn) error { return rc.ClaimConn(c, note) },
		Logf:       rc.Logf,
	}
	rep, perr := tlsprobe.Complete(ctx, spec)
	if perr == nil {
		return &completedSession{
			Suite:      suite,
			Client:     "wolfSSL probe",
			Local:      rep.Local,
			Remote:     rep.Remote,
			Negotiated: rep.Negotiated.String(),
			Model1:     rep.Model1.Summary(),
			Model1OK:   rep.Model1.OK(),
			KeylogNote: rep.KeylogNote,
		}, nil
	}
	fallback, ferr := completeWithoutTheProbe(ctx, rc, pf, suite, note, perr)
	if ferr != nil {
		return nil, ferr
	}
	return fallback, nil
}

// completeWithoutTheProbe is the CGO_ENABLED=0 path, and only that path.
//
// A probe failure that is NOT "this binary has no wolfSSL" is returned
// unchanged: a DUT that refused a suite it must accept is the finding, and
// silently retrying it on another client would replace that finding with a
// verdict about the bench's second stack.
func completeWithoutTheProbe(ctx context.Context, rc *certify.RunCtx, pf preflight,
	suite tlsprobe.Suite, note string, cause error) (*completedSession, error) {

	if cause != tlsprobe.ErrUnavailable {
		return nil, cause
	}
	for _, ccm := range tlsprobe.CCMSuites {
		if ccm.Code == suite.Code {
			return nil, fmt.Errorf(
				"no session can be established on %s in this build: it is an AES-CCM suite, Go's crypto/tls "+
					"implements no CCM cipher, and the wolfSSL probe that does is not linked in — %w",
				suite, cause)
		}
	}
	minV, maxV := uint16(tls.VersionTLS12), uint16(tls.VersionTLS12)
	if suite.Version == tlsprobe.TLS13 {
		minV, maxV = tls.VersionTLS13, tls.VersionTLS13
	}
	s, chain, m1, err := completingSessionOnSuite(ctx, rc, pf, minV, maxV, suite.Code, note)
	if s != nil {
		defer s.Close()
	}
	if err != nil {
		return nil, err
	}
	out := &completedSession{
		Suite:  suite,
		Client: "crypto/tls fallback (this binary carries no wolfSSL probe)",
		Local:  s.Local,
		Remote: s.Remote,
		Negotiated: fmt.Sprintf("%s, 0x%04X %s", versionName(s.Version()), s.State.CipherSuite,
			tlsdis.CipherSuiteName(s.State.CipherSuite)),
	}
	if m1.Err == nil && chain != nil {
		v, obs := normalResponseVerdict(m1.Response)
		out.Model1 = fmt.Sprintf("SunSpec Model 1 read on unit %d: %s", chain.Unit, obs)
		out.Model1OK = v == certify.Pass
	} else if m1.Err != nil {
		out.Model1 = "the Model 1 read inside the session failed: " + m1.Err.Error()
	}
	return out, nil
}

// completingSessionOnSuite is completingSession pinned to one TLS 1.2 suite.
func completingSessionOnSuite(ctx context.Context, rc *certify.RunCtx, pf preflight,
	minV, maxV, suite uint16, note string) (*Session, *Chain, Exchange, error) {

	roots, err := rootPool(pf.PKI)
	if err != nil {
		return nil, nil, Exchange{}, err
	}
	cert, err := roleCert(pf.PKI, sessionRole)
	if err != nil {
		return nil, nil, Exchange{}, err
	}
	o := dialOpts{Cert: cert, Roots: roots, MinVersion: minV, MaxVersion: maxV, Note: note}
	if minV == tls.VersionTLS12 {
		// crypto/tls ignores CipherSuites under TLS 1.3; pinning it there would
		// be a silent no-op that reads like a pinned offer.
		o.CipherSuites = []uint16{suite}
	}
	s, err := dial(ctx, rc, pf.Target, o)
	if err != nil {
		return nil, nil, Exchange{}, err
	}
	_, chain, ex, err := readCommonModel(rc, s)
	return s, chain, ex, err
}

// versionName renders a TLS wire version for a report line.
func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

// pinnedUnit reads -param ssm.unit, so the probe reads Model 1 from the same
// slot the rest of the suite does. Zero lets the probe scan.
func pinnedUnit(rc *certify.RunCtx) uint8 {
	v, ok := rc.Param("ssm.unit")
	if !ok || v == "" {
		return 0
	}
	var u int
	if _, err := fmt.Sscanf(v, "%d", &u); err != nil || u < 1 || u > 246 {
		return 0
	}
	return uint8(u)
}

// establishedSessionFact is the CAPTURE-side proof that a session was
// ESTABLISHED on a suite, as opposed to merely selected.
//
// The criterion is made of two things a reader can confirm in Wireshark without
// the key log: the DUT's ServerHello selected the suite this session offered
// alone, and the conversation went on to complete a mutual-auth handshake. The
// second is mutualFlightVerdict — the same decision TLSF-001 makes for
// SunSpecTCP-6/10/12/13, deliberately reused rather than restated, so "the
// handshake completed" means one thing in this suite and not two.
func establishedSessionFact(ev *certify.Evidence, s *completedSession, claim string) (certify.Assertion, error) {
	const method = "the conversation's ServerHello and its full handshake flight, both directions, " +
		"re-parsed from the capture"
	if s == nil {
		return ev.SkipAssertion(claim, method, "no session was established, so it produced no wire evidence"), nil
	}
	return wireFact(ev, s.Local, s.Remote, claim, method, func(v *wireView) (certify.Verdict, string, []int) {
		sh, shFrames := v.ServerHello()
		if sh == nil {
			return certify.Fail, "the capture holds no ServerHello for this conversation", v.Frames
		}
		if sh.CipherSuite != s.Suite.Code {
			return certify.Fail, fmt.Sprintf(
				"ServerHello.cipher_suite = 0x%04X %s, not the 0x%04X %s this session offered alone",
				sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite), s.Suite.Code, s.Suite.IANA), shFrames
		}
		verdict, obs, frames := mutualFlightVerdict(v)
		obs = fmt.Sprintf("ServerHello.cipher_suite = 0x%04X %s; %s (established by the %s)",
			sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite), obs, s.Client)
		if al, fatal := v.ServerFatalAlert(); fatal {
			return certify.Fail, obs + fmt.Sprintf(
				" — but the EUT-S then sent a fatal alert (level %d, description %d %s), so no session stood",
				al.Level, al.Description, tlsdis.AlertDescriptionName(al.Description)), al.Packets
		}
		return verdict, obs, frames
	})
}
