package suitessm

// checks_tlsf.go implements §2.4 "TLS Fundamentals" — TLSF-001 through
// TLSF-006.
//
// This family is where the suite's raw prober earns its keep. Four of the six
// procedures turn on the DUT's answer to a ClientHello no conformant client
// would send: the mandated suites in REVERSED preference order (TLSF-001's
// fourth iteration exists solely to prove the server picks by its own
// preference, not the client's), a certificate whose signature does not verify,
// an empty Certificate message, and a corrupted record mid-session.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// ── TLSF-001 · TLS 1.2 Basic Operation [C, S] ───────────────────────────────

// tlsf001 drives the four server-side cipher-order iterations the procedure
// prescribes, one completing mutual-auth TLS 1.2 session with a Model 1 read,
// and the passive client-half observation.
//
// The iterations matter as a set, not individually: iteration 1 offers the
// mandated suites in REVERSE order and the DUT must still select 0xC02B, which
// is the only way to demonstrate that the server applies its own preference
// list rather than the client's. Iterations 2 and 3 remove the higher-preference
// suites one at a time, so the selection is forced down the list and each
// mandated suite is exercised. Iteration 4 repeats iteration 1 in the mandated
// order as the control.
func tlsf001(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	type iteration struct {
		label string
		offer []uint16
		want  uint16
	}
	iters := []iteration{
		{"iteration 1: reversed mandated order", []uint16{suiteECDHE_ECDSA_AES128_CCM_8, suiteECDHE_ECDSA_CHACHA20_POLY1305, suiteECDHE_ECDSA_AES128_GCM_SHA256}, suiteECDHE_ECDSA_AES128_GCM_SHA256},
		{"iteration 2: GCM withheld", []uint16{suiteECDHE_ECDSA_AES128_CCM_8, suiteECDHE_ECDSA_CHACHA20_POLY1305}, suiteECDHE_ECDSA_CHACHA20_POLY1305},
		{"iteration 3: CCM-8 only", []uint16{suiteECDHE_ECDSA_AES128_CCM_8}, suiteECDHE_ECDSA_AES128_CCM_8},
		{"iteration 4: mandated order", mandated12, suiteECDHE_ECDSA_AES128_GCM_SHA256},
	}

	var t tally
	probes := make([]*ProbeResult, 0, len(iters))
	for _, it := range iters {
		h := conformantHello()
		h.Suites = append([]uint16(nil), it.offer...)
		// TLSF-001's observable is explicit: legacy version 0x0303, session_id
		// length 0, NO supported_versions extension.
		h.SupportedVersions = nil
		h.SessionID = nil
		p := Probe(ctx, rc, pf.Target, it.label, h)
		probes = append(probes, p)
		v, obs := selectedSuite(p, it.want)
		t.add(v, "%s: %s", it.label, obs)
	}

	// The completing half: a real mutual-auth TLS 1.2 session with a Model 1
	// read inside it. Pinned to TLS 1.2 so the whole handshake flight —
	// Certificate, ServerKeyExchange, CertificateRequest, the bench's own
	// Certificate carrying the role extension — is plaintext on the wire.
	sess, chain, m1, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS12, tls.VersionTLS12,
		"TLSF-001 completing TLS 1.2 mutual-auth session")
	if sess != nil {
		defer sess.Close()
	}
	switch {
	case serr != nil:
		t.add(certify.Fail, "the mutual-auth TLS 1.2 session could not be established: %v", serr)
	case m1.Err != nil:
		t.add(certify.Fail, "the SunSpec Model 1 read inside the session failed: %v", m1.Err)
	default:
		v, obs := normalResponseVerdict(m1.Response)
		t.add(v, "Model 1 read on unit %d (chain models %v): %s", chain.Unit, chain.IDs(), obs)
	}

	half := watchClientHalf(ctx, rc)
	if !half.Armed {
		t.caveat("the [C] half was not observed: %s", half.Why)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for i, p := range probes {
				it := iters[i]
				a, err := serverHelloFact(ev, p,
					fmt.Sprintf("SunSpecTCP-17/19: offered %s, the EUT-S selected 0x%04X %s",
						hexSuites(it.offer), it.want, tlsdis.CipherSuiteName(it.want)),
					"TLS 1.2 ServerHello.cipher_suite, parsed from the capture ("+it.label+")",
					func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
						return selectedSuiteFromHello(sh, it.want,
							"the capture holds no ServerHello for this conversation")
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			// The version criterion, asserted once on the control iteration.
			a, err := probeFact(ev, probes[len(probes)-1],
				"SunSpecTCP-4: the ClientHello offered legacy_version 0x0303 with an empty session_id and no supported_versions extension, and the EUT-S negotiated TLS 1.2",
				"ClientHello and ServerHello fields, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					ch, chFrames := v.ClientHello()
					sh, shFrames := v.ServerHello()
					if ch == nil || sh == nil {
						return certify.Fail, "the capture does not carry both hellos for the control iteration", v.Frames
					}
					_, hasSV := ch.Extension(tlsdis.ExtSupportedVersions)
					obs := fmt.Sprintf(
						"ClientHello legacy_version 0x%04X, session_id %d byte(s), supported_versions %s; ServerHello version 0x%04X (%s)",
						ch.LegacyVersion, len(ch.SessionID), presence(hasSV), sh.LegacyVersion,
						tlsdis.VersionName(sh.NegotiatedVersion()))
					if ch.LegacyVersion != tlsdis.VersionTLS12 || len(ch.SessionID) != 0 || hasSV {
						return certify.Fail, obs + " — the probe did not present the ClientHello shape TLSF-001 prescribes", append(chFrames, shFrames...)
					}
					if sh.NegotiatedVersion() != tlsdis.VersionTLS12 {
						return certify.Fail, obs, append(chFrames, shFrames...)
					}
					return certify.Pass, obs, append(chFrames, shFrames...)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// SunSpecTCP-1: the mbaps port. It is a SHOULD, so a target on any
			// other port is a WARN rather than a failure — and a loopback bench
			// run on an ephemeral port must not be reported as a DUT defect.
			a, err = probeFact(ev, probes[0],
				"SunSpecTCP-1: the mbaps exchange took place on TCP port 802",
				"the destination port of the TCP conversation this check opened, from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					port := probes[0].Remote.Port()
					obs := fmt.Sprintf("the bench dialled %s and the conversation in the capture is %s",
						probes[0].Remote, v.Stream.Key)
					if port != mbapsPort {
						return certify.Warn, obs + fmt.Sprintf(
							" — port %d is not the mbaps port %d. SunSpecTCP-1 states port 802 as a SHOULD, "+
								"so a PICS-declared alternative is conformant; this row records what was used.",
							port, mbapsPort), v.Frames
					}
					return certify.Pass, obs, v.Frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The full mutual-auth flight, in the clear.
			a, err = sessionFact(ev, sess,
				"SunSpecTCP-6/10/12/13: the TLS 1.2 mutual-authentication handshake flight was exchanged in full",
				"handshake message types of both directions, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					return mutualFlightVerdict(v)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The Model 1 read, recovered from the capture.
			a, err = decryptedFact(ev, sess,
				"a SunSpec Common Model (Model 1) read was carried inside the established TLS session and answered",
				"TLS decryption of this session's records with the run's key log, then MBAP framing",
				func(p *plaintext, _ *wireView) (certify.Verdict, string, []int) {
					return modbusExchangeFact(p, 0x03, normalResponseVerdict)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The [C] half.
			a, err = half.fact(ev,
				"SunSpecTCP-17/19 [C]: the gateway's own southbound ClientHello offers 0xC02B, 0xCCA9 and 0xC0AE in that relative order",
				"cipher_suites list of the gateway's ClientHello to the bench device sim, parsed from the capture",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					obs := fmt.Sprintf("gateway ClientHello cipher_suites = %s (%s)",
						hexSuites(ch.CipherSuites), namedSuites(ch.CipherSuites))
					if !inRelativeOrder(ch.CipherSuites, mandated12) {
						return certify.Fail, obs + " — the three mandated TLS 1.2 suites do not appear in the mandated relative order"
					}
					return certify.Pass, obs
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── TLSF-002 · TLS 1.3 Basic Operation [C, S] (Optional) ────────────────────

func tlsf002(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	type iteration struct {
		label string
		offer []uint16
		want  uint16
	}
	iters := []iteration{
		{"iteration 1: reversed mandated order", []uint16{suiteTLS13_AES128_CCM_SHA256, suiteTLS13_CHACHA20_POLY1305_SHA25, suiteTLS13_AES128_GCM_SHA256}, suiteTLS13_AES128_GCM_SHA256},
		{"iteration 2: AES-GCM withheld", []uint16{suiteTLS13_AES128_CCM_SHA256, suiteTLS13_CHACHA20_POLY1305_SHA25}, suiteTLS13_CHACHA20_POLY1305_SHA25},
		{"iteration 3: CCM only", []uint16{suiteTLS13_AES128_CCM_SHA256}, suiteTLS13_AES128_CCM_SHA256},
	}

	var t tally
	probes := make([]*ProbeResult, 0, len(iters))
	supported := false
	for _, it := range iters {
		h := conformantHello13()
		h.Suites = append([]uint16(nil), it.offer...)
		p := Probe(ctx, rc, pf.Target, it.label, h)
		probes = append(probes, p)
		if sh := p.ServerHello(); sh != nil && sh.NegotiatedVersion() == tlsdis.VersionTLS13 {
			supported = true
		}
		v, obs := selectedSuite(p, it.want)
		t.add(v, "%s: %s", it.label, obs)
	}
	if !supported {
		// TLS 1.3 is conditional: "mandatory ONLY if the EUT supports TLS 1.3".
		// A DUT that does not is not failing this procedure.
		return certify.Skipped(
			"the DUT negotiated no TLS 1.3 handshake in three attempts, and TLSF-002 is mandatory only "+
				"if TLS 1.3 is supported: %s", t.notes()), nil
	}

	sess, chain, m1, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS13, tls.VersionTLS13,
		"TLSF-002 completing TLS 1.3 mutual-auth session")
	if sess != nil {
		defer sess.Close()
	}
	switch {
	case serr != nil:
		t.add(certify.Fail, "the mutual-auth TLS 1.3 session could not be established: %v", serr)
	case m1.Err != nil:
		t.add(certify.Fail, "the SunSpec Model 1 read inside the TLS 1.3 session failed: %v", m1.Err)
	default:
		v, obs := normalResponseVerdict(m1.Response)
		t.add(v, "Model 1 read on unit %d (chain models %v): %s", chain.Unit, chain.IDs(), obs)
	}

	half := watchClientHalf(ctx, rc)
	if !half.Armed {
		t.caveat("the [C] half was not observed: %s", half.Why)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for i, p := range probes {
				it := iters[i]
				a, err := serverHelloFact(ev, p,
					fmt.Sprintf("SunSpecTCP-18/19: offered %s over TLS 1.3, the EUT-S selected 0x%04X %s",
						hexSuites(it.offer), it.want, tlsdis.CipherSuiteName(it.want)),
					"TLS 1.3 ServerHello.cipher_suite, parsed from the capture ("+it.label+")",
					func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
						return selectedSuiteFromHello(sh, it.want,
							"the capture holds no ServerHello for this conversation")
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			a, err := probeFact(ev, probes[0],
				"SunSpecTCP-5: the ClientHello carried legacy_version 0x0303 with supported_versions 0x0304, and the EUT-S negotiated TLS 1.3 through the supported_versions extension",
				"ClientHello and ServerHello supported_versions extensions, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					ch, chFrames := v.ClientHello()
					sh, shFrames := v.ServerHello()
					if ch == nil || sh == nil {
						return certify.Fail, "the capture does not carry both hellos", v.Frames
					}
					obs := fmt.Sprintf(
						"ClientHello legacy_version 0x%04X, supported_versions %v, session_id %d byte(s); ServerHello legacy_version 0x%04X, supported_versions 0x%04X",
						ch.LegacyVersion, ch.SupportedVersions, len(ch.SessionID), sh.LegacyVersion, sh.SupportedVersion)
					if sh.NegotiatedVersion() != tlsdis.VersionTLS13 {
						return certify.Fail, obs, append(chFrames, shFrames...)
					}
					return certify.Pass, obs, append(chFrames, shFrames...)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// TLS 1.3's own observable: everything after the ServerHello is
			// opaque. Asserting that is asserting the version actually took
			// effect on the record layer, not just in the hello.
			a, err = probeFact(ev, probes[0],
				"under TLS 1.3 only ClientHello and ServerHello are cleartext; EncryptedExtensions, Certificate, CertificateVerify and Finished appear as opaque records",
				"record-type and cleartext-handshake scan of the DUT→bench direction",
				func(v *wireView) (certify.Verdict, string, []int) {
					flight := v.ServerFlight()
					var names []string
					for _, t := range flight {
						names = append(names, tlsdis.HandshakeTypeName(t))
					}
					obs := fmt.Sprintf("cleartext handshake messages from the DUT: %v; %d opaque record(s) followed",
						names, len(v.Server.AppData))
					for _, t := range flight {
						switch t {
						case tlsdis.HandshakeCertificate, tlsdis.HandshakeCertificateRequest,
							tlsdis.HandshakeCertificateVerify, tlsdis.HandshakeFinished,
							tlsdis.HandshakeEncryptedExtensions:
							return certify.Fail, obs + " — a message RFC 8446 encrypts appeared in the clear", v.Frames
						}
					}
					if len(v.Server.AppData) == 0 {
						return certify.Fail, obs + " — no opaque records followed the ServerHello, so the record layer never switched to the handshake keys", v.Frames
					}
					return certify.Pass, obs, v.Frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = decryptedFact(ev, sess,
				"a SunSpec Common Model (Model 1) read was carried inside the established TLS 1.3 session and answered",
				"TLS 1.3 decryption of this session's records with the run's key log, then MBAP framing",
				func(p *plaintext, _ *wireView) (certify.Verdict, string, []int) {
					return modbusExchangeFact(p, 0x03, normalResponseVerdict)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = half.fact(ev,
				"SunSpecTCP-18 [C]: the gateway's own southbound ClientHello offers 0x1301, 0x1303 and 0x1304 in that relative order",
				"cipher_suites list of the gateway's ClientHello to the bench device sim, parsed from the capture",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					obs := fmt.Sprintf("gateway ClientHello cipher_suites = %s; supported_versions %v",
						hexSuites(ch.CipherSuites), ch.SupportedVersions)
					if !inRelativeOrder(ch.CipherSuites, mandated13) {
						return certify.Fail, obs + " — the three mandated TLS 1.3 suites do not appear in the mandated relative order"
					}
					return certify.Pass, obs
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── TLSF-003 · TLS 1.2 Bad Certificate Detection [S] (Negative) ─────────────

// tlsf003 presents three bad client certificates in turn — expired, bad
// signature, untrusted issuer — and requires the DUT to terminate each with a
// fatal alert and no application data.
//
// The "badsig" fixture is minted here rather than committed (see minting.go):
// a certificate whose signature does not verify is not a thing to keep on disk,
// and building it from a GOOD fixture guarantees that the signature is the only
// thing wrong with it.
func tlsf003(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	roots, err := rootPool(pf.PKI)
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	type negative struct {
		name    string
		what    string
		cert    *tls.Certificate
		session *Session
		loadErr error
	}
	negs := []*negative{
		{name: "expired", what: "a client certificate whose validity period has passed"},
		{name: "badsig", what: "a client certificate whose signature does not verify"},
		{name: "untrusted", what: "a client certificate issued by a CA outside the DUT's trust store"},
	}

	if c, err := negativeCert(pf.PKI, "expired"); err != nil {
		negs[0].loadErr = err
	} else {
		negs[0].cert = c
	}
	if good, err := roleCert(pf.PKI, "read-only"); err != nil {
		negs[1].loadErr = err
	} else if bad, err := corruptSignature(*good); err != nil {
		negs[1].loadErr = err
	} else {
		negs[1].cert = &bad
	}
	if c, err := negativeCert(pf.PKI, "wrong-ca"); err != nil {
		negs[2].loadErr = err
	} else {
		negs[2].cert = c
	}

	var t tally
	for _, n := range negs {
		if n.loadErr != nil {
			t.caveat("%s: the fixture is unavailable, so the DUT was never provoked with it: %v", n.name, n.loadErr)
			continue
		}
		s, err := dial(ctx, rc, pf.Target, dialOpts{
			Cert: n.cert, Roots: roots,
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			Note: "TLSF-003 negative: " + n.name,
		})
		if s != nil {
			n.session = s
			s.Close()
			t.add(certify.Fail, "%s: the DUT ACCEPTED %s and completed the handshake (%s / 0x%04X)",
				n.name, n.what, tlsdis.VersionName(s.State.Version), s.State.CipherSuite)
			continue
		}
		if partial, ok := handshakeFailed(err); ok {
			n.session = partial
			t.add(certify.Pass, "%s: the DUT rejected %s — %v", n.name, n.what, err)
			continue
		}
		t.add(certify.Fail, "%s: the connection failed before any certificate was presented: %v", n.name, err)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for _, n := range negs {
				claim := fmt.Sprintf(
					"SunSpecTCP-6/7/13/52: the EUT-S detected %s and terminated the connection with a fatal TLS alert", n.what)
				const method = "TLS record and alert scan of the DUT→bench direction of this connection"
				if n.loadErr != nil {
					out = append(out, ev.SkipAssertion(claim, method,
						"the "+n.name+" fixture was unavailable, so the DUT was never provoked: "+n.loadErr.Error()))
					continue
				}
				if n.session == nil {
					out = append(out, ev.SkipAssertion(claim, method,
						"the "+n.name+" connection produced no socket to attribute"))
					continue
				}
				a, err := sessionFact(ev, n.session, claim, method,
					func(v *wireView) (certify.Verdict, string, []int) {
						return fatalAlertVerdict(ev, v, n.what)
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)

				// The CertificateRequest must have been in the flight, or the
				// rejection proves nothing about mutual authentication.
				a, err = sessionFact(ev, n.session,
					"the EUT-S sent a CertificateRequest in the server flight of the "+n.name+" handshake",
					"handshake message types of the DUT→bench direction",
					func(v *wireView) (certify.Verdict, string, []int) {
						cr, frames := v.CertificateRequest()
						verdict, obs := certificateRequestVerdict(cr)
						if cr == nil {
							return verdict, obs, v.Frames
						}
						return verdict, obs, frames
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)

				a, err = noAppDataFact(ev, n.session, n.what)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// ── TLSF-004 · Fatal Alert: Missing Certificate [S] (Negative) ──────────────

// tlsf004 answers the DUT's CertificateRequest with an EMPTY Certificate
// message — the RFC 5246 §7.4.6 encoding of "I have none" — and requires a
// fatal alert and no application data.
//
// Both legal shapes of "no certificate" are exercised: the empty Certificate
// message (TLS 1.2's required answer) and simply not configuring one, which
// Go's crypto/tls also renders as an empty Certificate message. They are
// reported separately because a server that special-cases one and not the other
// is exactly the kind of asymmetry a conformance run should surface.
func tlsf004(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	roots, err := rootPool(pf.PKI)
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	var t tally
	s, derr := dial(ctx, rc, pf.Target, dialOpts{
		EmptyCert: true, Roots: roots,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Note: "TLSF-004: empty client Certificate message",
	})
	var sess *Session
	if s != nil {
		sess = s
		s.Close()
		t.add(certify.Fail, "the DUT ACCEPTED a handshake in which the client answered the CertificateRequest with no certificate: %s / 0x%04X",
			tlsdis.VersionName(s.State.Version), s.State.CipherSuite)
	} else if partial, ok := handshakeFailed(derr); ok {
		sess = partial
		t.add(certify.Pass, "the DUT rejected the certless handshake: %v", derr)
	} else {
		t.add(certify.Fail, "the connection failed before the CertificateRequest was answered: %v", derr)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := sessionFact(ev, sess,
				"SunSpecTCP-11/14/45/48: the EUT-S sent a CertificateRequest and the bench answered it with an empty Certificate message",
				"handshake message types and Certificate message contents of both directions",
				func(v *wireView) (certify.Verdict, string, []int) {
					cr, crFrames := v.CertificateRequest()
					cc, ccFrames := v.ClientCertificate()
					obs := fmt.Sprintf("EUT-S flight %v; bench flight %v", typeNames(v.ServerFlight()), typeNames(v.ClientFlight()))
					if cr == nil {
						return certify.Fail, obs + " — no CertificateRequest, so the DUT did not demand mutual authentication", v.Frames
					}
					n := 0
					if cc != nil {
						n = len(cc.Entries)
					}
					obs += fmt.Sprintf("; the bench's Certificate message carried %d certificate(s)", n)
					if cc == nil {
						return certify.Warn, obs + " — the bench sent no Certificate message at all rather than an empty one; the provocation reached the DUT either way", append(crFrames, v.Frames...)
					}
					if n != 0 {
						return certify.Fail, obs + " — the bench presented a certificate, so this run did not carry out TLSF-004's provocation", append(crFrames, ccFrames...)
					}
					return certify.Pass, obs, append(crFrames, ccFrames...)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, sess,
				"SunSpecTCP-13/14: the EUT-S terminated the certless handshake with a fatal TLS alert",
				"TLS alert scan of the DUT→bench direction",
				func(v *wireView) (certify.Verdict, string, []int) {
					return fatalAlertVerdict(ev, v, "a client that answered the CertificateRequest with no certificate")
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = noAppDataFact(ev, sess, "a client that answered the CertificateRequest with no certificate")
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── TLSF-005 · Fatal Alert Persistence [S] (Negative) ───────────────────────

// tlsf005 establishes a session, corrupts one application-data record so the
// DUT must answer bad_record_mac, then offers the aborted session's identity
// back and requires that it is NOT resumed.
//
// The corruption is applied by a net.Conn wrapper (corruptingConn) rather than
// by any TLS API, because no TLS API offers "send a record whose AEAD tag is
// wrong" — and that, again, is the referee's whole job.
func tlsf005(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	roots, err := rootPool(pf.PKI)
	if err != nil {
		return certify.Skipped("%v", err), nil
	}
	cert, err := roleCert(pf.PKI, "grid-service")
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	var t tally
	cache := tls.NewLRUClientSessionCache(8)
	corrupt := &corruptingConn{}

	first, derr := dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots, SessionCache: cache,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Wrap: func(c net.Conn) net.Conn { corrupt.Conn = c; return corrupt },
		Note: "TLSF-005: session that will be aborted by a corrupted record",
	})
	if derr != nil {
		return certify.Failed("the session TLSF-005 must abort could not be established: %v", derr), nil
	}
	defer first.Close()

	// A clean exchange first, so the session is genuinely live and the abort is
	// attributable to the corruption rather than to a half-open connection.
	if _, _, m1, err := readCommonModel(rc, first); err != nil {
		t.caveat("the pre-corruption Model 1 read did not complete: %v", err)
	} else if m1.Err != nil {
		t.caveat("the pre-corruption Model 1 read did not complete: %v", m1.Err)
	} else {
		t.add(certify.Pass, "the session carried a clean Model 1 exchange before the corruption")
	}

	corrupt.Arm()
	bad := first.ReadHolding(1, sunspecBase, 2, "deliberately corrupted request")
	if bad.Err == nil {
		t.add(certify.Fail, "the DUT answered a record whose AEAD tag had been corrupted (% x) instead of aborting", bad.Response)
	} else {
		t.add(certify.Pass, "the DUT tore the session down after the corrupted record: %v", bad.Err)
	}
	first.Close()

	// Offer the aborted session back.
	second, derr2 := dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots, SessionCache: cache,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Note: "TLSF-005: resumption attempt after the fatal alert",
	})
	if second != nil {
		defer second.Close()
		if second.State.DidResume {
			t.add(certify.Fail, "the DUT RESUMED the session that had ended in a fatal alert (RFC 5246 §7.2.2 forbids it)")
		} else {
			t.add(certify.Pass, "the DUT refused to resume the aborted session and performed a full handshake")
		}
	} else {
		t.add(certify.Pass, "the DUT refused the resumption attempt outright: %v", derr2)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := sessionFact(ev, first,
				"SunSpecTCP-14 / RFC 5246 §7.2.2: the EUT-S answered a corrupted TLS record with a fatal alert",
				"TLS alert scan of the DUT→bench direction of the aborted session, decrypted with the run's key log",
				func(v *wireView) (certify.Verdict, string, []int) {
					// This alert is necessarily POST-ChangeCipherSpec — the whole
					// point of the procedure is to corrupt a record of an
					// established session — so it is ciphertext on the wire and
					// only the key log can read it. See wireView.serverAlerts.
					sc := v.serverAlerts(ev)
					al, ok := sc.Fatal()
					if !ok {
						if len(sc.Opaque) > 0 {
							return certify.Skip, fmt.Sprintf(
									"the DUT sent %d alert record(s) after the corrupted record, in frame(s) %v, and this "+
										"bundle could not read them: %s", len(sc.Opaque), sc.OpaqueFrames(), sc.Why),
								sc.OpaqueFrames()
						}
						return certify.Fail, fmt.Sprintf(
							"the DUT sent no alert record at all after the corrupted record; its direction holds %d record(s)",
							recordCount(v)), v.Frames
					}
					obs := fmt.Sprintf("fatal alert level %d description %d (%s), recovered from the capture "+
						"with the run's key log", al.Level, al.Description, tlsdis.AlertDescriptionName(al.Description))
					if al.Description != 20 { // bad_record_mac
						return certify.Warn, obs + " — RFC 5246 §7.2.2 names bad_record_mac (20) for a record that fails authentication", al.Packets
					}
					return certify.Pass, obs, al.Packets
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, second,
				"SunSpecTCP-14: the EUT-S did not resume the session that had ended in a fatal alert",
				"ServerHello session_id and handshake message types of the resumption attempt",
				func(v *wireView) (certify.Verdict, string, []int) {
					sh, frames := v.ServerHello()
					if sh == nil {
						return certify.Pass, "the DUT sent no ServerHello at all on the resumption attempt: " +
							"the aborted session was not resumable", v.Frames
					}
					full := hasType(v.ServerFlight(), tlsdis.HandshakeCertificate) &&
						hasType(v.ServerFlight(), tlsdis.HandshakeCertificateRequest)
					obs := fmt.Sprintf("resumption attempt: ServerHello session_id %x, flight %v",
						sh.SessionID, typeNames(v.ServerFlight()))
					if !full {
						return certify.Fail, obs + " — the DUT performed an ABBREVIATED handshake, resuming state from a session that ended in a fatal alert", frames
					}
					return certify.Pass, obs + " — a FULL handshake: Certificate and CertificateRequest were re-exchanged", frames
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// corruptingConn flips a byte in the first record written after Arm, which
// makes its AEAD tag fail on the peer.
//
// The flip lands at offset 5 — the first byte of the record FRAGMENT, past the
// 5-byte record header — so the record still frames correctly and the DUT must
// reject it on authentication rather than on parsing. Corrupting the header
// instead would test a different thing entirely.
type corruptingConn struct {
	net.Conn
	mu    sync.Mutex
	armed bool
	fired bool
}

// Arm makes the next Write corrupt its record.
func (c *corruptingConn) Arm() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = true
}

func (c *corruptingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	corrupt := c.armed && !c.fired && len(p) > 6
	if corrupt {
		c.fired = true
	}
	c.mu.Unlock()
	if !corrupt {
		return c.Conn.Write(p)
	}
	q := append([]byte(nil), p...)
	q[5] ^= 0xFF
	n, err := c.Conn.Write(q)
	return n, err
}

// ── TLSF-006 · CertificateRequest Verification [S] ──────────────────────────

func tlsf006(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	h := conformantHello()
	h.SupportedVersions = nil
	p := Probe(ctx, rc, pf.Target, "TLSF-006 conformant TLS 1.2 hello", h)

	var t tally
	v, obs := certificateRequestVerdict(p.CertificateRequest())
	t.add(v, "%s", obs)
	v, obs = serverFlightVerdict(p.Flight())
	t.add(v, "%s", obs)

	// The completing half proves the CertificateRequest is not decorative: the
	// bench answers it and a Model 1 read follows inside the session.
	sess, chain, m1, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS12, tls.VersionTLS12,
		"TLSF-006 completing session answering the CertificateRequest")
	if sess != nil {
		defer sess.Close()
	}
	switch {
	case serr != nil:
		t.add(certify.Fail, "the session answering the CertificateRequest could not be established: %v", serr)
	case m1.Err != nil:
		t.add(certify.Fail, "the Model 1 read inside the session failed: %v", m1.Err)
	default:
		vv, o := normalResponseVerdict(m1.Response)
		t.add(vv, "Model 1 read on unit %d (chain models %v): %s", chain.Unit, chain.IDs(), o)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := probeFact(ev, p,
				"SunSpecTCP-11: the EUT-S sent a CertificateRequest (handshake type 13) with a non-empty certificate_types and supported_signature_algorithms",
				"CertificateRequest message, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					cr, frames := v.CertificateRequest()
					verdict, obs := certificateRequestVerdict(cr)
					if cr == nil {
						return verdict, obs, v.Frames
					}
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = probeFact(ev, p,
				"SunSpecTCP-11: the EUT-S flight was ServerHello, Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone, in that order",
				"ordered handshake message types of the DUT→bench direction",
				func(v *wireView) (certify.Verdict, string, []int) {
					verdict, obs := serverFlightVerdict(v.ServerFlight())
					return verdict, obs, v.Frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, sess,
				"the bench answered the CertificateRequest with a Certificate, ClientKeyExchange, CertificateVerify and Finished, and the handshake completed",
				"handshake message types of the bench→DUT direction",
				func(v *wireView) (certify.Verdict, string, []int) {
					return mutualFlightVerdict(v)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = decryptedFact(ev, sess,
				"a SunSpec Model 1 read was carried inside the session the CertificateRequest gated, and answered",
				"TLS decryption with the run's key log, then MBAP framing",
				func(pt *plaintext, _ *wireView) (certify.Verdict, string, []int) {
					return modbusExchangeFact(pt, 0x03, normalResponseVerdict)
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── shared bits of this family ──────────────────────────────────────────────

// fatalAlertVerdict is the shared negative-test criterion: a fatal alert, and
// no completed session.
//
// It takes the Evidence, not just the view, because an alert sent after the
// ChangeCipherSpec is ciphertext on the wire and only the run's key log can say
// what it was. Without that resolution the honest verdict for an unresolved
// alert record is not FAIL — it is "this bundle cannot tell", which is a SKIP
// carrying the frames of the record it declined to read.
func fatalAlertVerdict(ev *certify.Evidence, v *wireView, what string) (certify.Verdict, string, []int) {
	sc := v.serverAlerts(ev)
	if al, ok := sc.Fatal(); ok {
		how := ""
		if sc.Decrypted {
			how = ", recovered from the capture with the run's key log"
		}
		return certify.Pass, fmt.Sprintf(
			"the DUT refused %s with a fatal alert: level %d (%s), description %d (%s)%s",
			what, al.Level, tlsdis.AlertLevelName(al.Level), al.Description,
			tlsdis.AlertDescriptionName(al.Description), how), al.Packets
	}
	if len(sc.Opaque) > 0 {
		return certify.Skip, fmt.Sprintf(
			"the DUT sent %d alert record(s) after the ChangeCipherSpec, in frame(s) %v, and this bundle cannot "+
				"read them: %s. Whether %s was refused with a FATAL alert is therefore undetermined — it is not "+
				"an absence", len(sc.Opaque), sc.OpaqueFrames(), sc.Why, what), sc.OpaqueFrames()
	}
	sh, _ := v.ServerHello()
	obs := fmt.Sprintf("the DUT sent no fatal alert; its direction holds %d TLS record(s)", recordCount(v))
	if sh != nil {
		obs += fmt.Sprintf(" and a ServerHello selecting 0x%04X %s",
			sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite))
	}
	return certify.Fail, obs + " — " + what + " was not refused with a fatal alert", v.Frames
}

// mutualFlightVerdict asserts a completed TLS 1.2 mutual-authentication flight
// in the clear, or — under TLS 1.3, where everything past the ServerHello is
// encrypted — that both hellos and opaque records are present.
func mutualFlightVerdict(v *wireView) (certify.Verdict, string, []int) {
	sh, _ := v.ServerHello()
	if sh == nil {
		return certify.Fail, "no ServerHello: the handshake did not begin", v.Frames
	}
	obs := fmt.Sprintf("EUT-S flight %v; bench flight %v", typeNames(v.ServerFlight()), typeNames(v.ClientFlight()))
	if sh.NegotiatedVersion() == tlsdis.VersionTLS13 {
		if len(v.Server.AppData) == 0 || len(v.Client.AppData) == 0 {
			return certify.Fail, obs + " — under TLS 1.3 the mutual-auth messages are encrypted, and this conversation carries no opaque records in both directions", v.Frames
		}
		return certify.Pass, obs + " — under TLS 1.3 the Certificate/CertificateVerify/Finished exchange is encrypted; both directions carry opaque records and the session went on to exchange application data", v.Frames
	}
	need := []tlsdis.HandshakeType{
		tlsdis.HandshakeCertificate, tlsdis.HandshakeCertificateRequest, tlsdis.HandshakeServerHelloDone,
	}
	for _, n := range need {
		if !hasType(v.ServerFlight(), n) {
			return certify.Fail, obs + " — the EUT-S flight is missing " + tlsdis.HandshakeTypeName(n), v.Frames
		}
	}
	for _, n := range []tlsdis.HandshakeType{
		tlsdis.HandshakeCertificate, tlsdis.HandshakeClientKeyExchange, tlsdis.HandshakeCertificateVerify,
	} {
		if !hasType(v.ClientFlight(), n) {
			return certify.Fail, obs + " — the bench flight is missing " + tlsdis.HandshakeTypeName(n) +
				", so mutual authentication was not completed", v.Frames
		}
	}
	if len(v.Client.CCS) == 0 || len(v.Server.CCS) == 0 {
		return certify.Fail, obs + " — one side sent no ChangeCipherSpec, so the handshake did not finish", v.Frames
	}
	return certify.Pass, obs + " — both sides sent a Certificate, the bench sent CertificateVerify, and both sent ChangeCipherSpec", v.Frames
}

// modbusExchangeFact recovers the first request/response pair whose request
// carries the given function code and applies a response criterion.
func modbusExchangeFact(p *plaintext, fc byte,
	decide func([]byte) (certify.Verdict, string)) (certify.Verdict, string, []int) {

	req, _, okReq := findADU(p.FromClient, p.ClientRecords, func(b byte) bool { return b == fc })
	rsp, frames, okRsp := findADU(p.FromServer, p.ServerRecords, func(b byte) bool { return b == fc || b == fc|0x80 })
	switch {
	case !okReq:
		return certify.Fail, fmt.Sprintf(
			"no Modbus request with function code 0x%02X was recovered from the %d decrypted bench→DUT byte(s)",
			fc, len(p.FromClient)), nil
	case !okRsp:
		return certify.Fail, fmt.Sprintf(
			"the request % x was recovered but no matching response appears in the %d decrypted DUT→bench byte(s)",
			req, len(p.FromServer)), nil
	}
	verdict, obs := decide(rsp)
	return verdict, fmt.Sprintf("request % x; %s", req, obs), frames
}

// completingSession dials a real mutual-auth session as a role and reads
// Model 1 inside it — the shape half these procedures end with.
func completingSession(ctx context.Context, rc *certify.RunCtx, pf preflight, role string,
	minV, maxV uint16, note string) (*Session, *Chain, Exchange, error) {

	roots, err := rootPool(pf.PKI)
	if err != nil {
		return nil, nil, Exchange{}, err
	}
	cert, err := roleCert(pf.PKI, role)
	if err != nil {
		return nil, nil, Exchange{}, err
	}
	s, err := dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots, MinVersion: minV, MaxVersion: maxV, Note: note,
	})
	if err != nil {
		return nil, nil, Exchange{}, err
	}
	_, chain, ex, err := readCommonModel(rc, s)
	return s, chain, ex, err
}

func typeNames(ts []tlsdis.HandshakeType) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = tlsdis.HandshakeTypeName(t)
	}
	return out
}

func recordCount(v *wireView) int {
	if v.Server == nil || v.Server.Stream == nil {
		return 0
	}
	return len(v.Server.Stream.Records)
}
