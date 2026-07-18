package main

// probe.go is the shared dial + request machinery the checks compose: build a
// conformant mbaps client profile from a role (or a raw cert/key for negatives),
// apply per-check mutators (force a TLS version, trim the suite list, swap the
// trust anchor, drop the client cert), hand back the live mbtls.Session, and run
// bounded raw mbap requests over it. It never decides PASS/FAIL — that is the
// checks' job; probe.go only produces the wire evidence.

import (
	"fmt"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"
)

// opDeadline bounds every raw request so a wedged peer cannot hang a check
// (CODING_PRINCIPLES §6 — mbap.Client sets no deadlines, the caller owns them).
const opDeadline = 8 * time.Second

// profileMut mutates a client profile before Dial.
type profileMut func(*mbtls.Profile)

// forceTLS12 caps the handshake at TLS 1.2 (TCP-4; also the reliable client-side
// vantage for MFL observation — TCP-59/60).
func forceTLS12(p *mbtls.Profile) { p.MaxTLS = mbtls.TLS12 }

// forceTLS13 keeps TLS 1.3 available so a 1.3 handshake is observable (TCP-5).
func forceTLS13(p *mbtls.Profile) { p.MinTLS = mbtls.TLS12; p.MaxTLS = mbtls.TLS13 }

// ccm8Only trims both segments to the CCM-8 suite so it is negotiated only when
// GCM/ChaCha are disabled — the "disable IANA-discouraged suites" proof (TCP-20).
func ccm8Only(p *mbtls.Profile) {
	p.MaxTLS = mbtls.TLS12
	p.Suites12 = []string{"ECDHE-ECDSA-AES128-CCM-8"}
	p.Suites13 = []string{"TLS13-AES128-CCM-SHA256"}
}

// noMFL turns the client's Maximum Fragment Length request off (TCP-59/60 control).
func noMFL(p *mbtls.Profile) { p.MFLCode = wolfssl.MFLDisabled }

// withCAFile swaps the trust anchor the client verifies the peer against (the
// TCP-2 ten-root trust store).
func withCAFile(ca string) profileMut { return func(p *mbtls.Profile) { p.CAFile = ca } }

// withResume re-enables TLS session resumption for the resumption probes
// (TCP-14/46/47). Every OTHER dial is deliberately non-resuming (see dialCred):
// the mbtls client session cache is process-global and keyed only by
// (addr, CA, cert), so a resumed session would echo an EARLIER handshake's
// cipher/version/MFL and silently corrupt a deterministic cipher-order or
// MFL-negotiation assertion. Non-resuming dials make every cipher/version/MFL
// observation reflect a fresh, real negotiation.
func withResume(p *mbtls.Profile) { p.SessionCache = true }

// dialRole dials target as role r over a conformant client profile, applying
// muts. The caller closes the returned Session.
func dialRole(target string, ps *pkiSet, r Role, muts ...profileMut) (*mbtls.Session, error) {
	c, ok := ps.roles[r]
	if !ok {
		return nil, fmt.Errorf("ssm-conformance: no client credential for role %s", r)
	}
	return dialCred(target, ps.serverCA, c.certFile, c.keyFile, muts...)
}

// dialCred dials target presenting the given leaf chain + key (empty strings =
// no client certificate, the no-cert negative), verifying the peer against ca.
// Session resumption is OFF by default so every dial is a fresh handshake with
// deterministic negotiated parameters; the resumption probes opt in via withResume.
func dialCred(target, ca, certFile, keyFile string, muts ...profileMut) (*mbtls.Session, error) {
	p := mbtls.DefaultClientProfile(ca, certFile, keyFile)
	p.SessionCache = false
	for _, m := range muts {
		m(&p)
	}
	return mbtls.Dial(target, p)
}

// rawRead performs one bounded FC03 read over a live session.
func rawRead(sess *mbtls.Session, unit uint8, addr, n uint16) ([]uint16, error) {
	_ = sess.Conn.SetDeadline(time.Now().Add(opDeadline))
	defer func() { _ = sess.Conn.SetDeadline(time.Time{}) }()
	return mbap.NewClient(sess.Conn).ReadHolding(unit, addr, n)
}

// rawWrite performs one bounded FC16 write over a live session — the raw
// denial primitive for role-less / malformed-role certs, where the higher-level
// aggregator.ConnectAs (which self-checks the presented role) cannot be used.
func rawWrite(sess *mbtls.Session, unit uint8, addr uint16, vals []uint16) error {
	_ = sess.Conn.SetDeadline(time.Now().Add(opDeadline))
	defer func() { _ = sess.Conn.SetDeadline(time.Time{}) }()
	return mbap.NewClient(sess.Conn).WriteMultiple(unit, addr, vals)
}

// pump reads the SunSpec base marker to drive a request/response round trip. It
// both proves the tunnel carries plain mbap unchanged (TCP-9) and, on a fresh
// TLS 1.3 session, pumps the post-handshake NewSessionTicket so the session is
// resumable on the next Dial (TCP-46). A protocol exception still counts as a
// successful round trip (the frame came back); only a transport error fails.
func pump(sess *mbtls.Session, unit uint8) error {
	_, err := rawRead(sess, unit, sunspec.SunSpecBase, 2)
	if _, isEx := aggregator.AsException(err); isEx {
		return nil
	}
	return err
}

// exceptionCode reports the mbap exception code an op error carries and whether
// it was a protocol exception (vs a transport failure).
func exceptionCode(err error) (uint8, bool) {
	if ex, ok := aggregator.AsException(err); ok {
		return uint8(ex.Code), true
	}
	return 0, false
}
