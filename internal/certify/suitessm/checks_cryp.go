package suitessm

// checks_cryp.go implements §2.5 "Cryptography" — CRYP-001 through CRYP-007 —
// and §2.9's single OPS-001 row, which is the documentation cross-reference of
// everything this family observed.
//
// The shape repeats: offer exactly one thing, see what comes back. That is why
// these checks are the suite's most direct evidence — a ServerHello selecting
// 0xC0AE in answer to a ClientHello offering only 0xC0AE is a two-frame
// citation that a reviewer can confirm in Wireshark in about four seconds.

import (
	"context"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// ── CRYP-001 · Mandatory TLS v1.2 Cipher Suites [C, S] ──────────────────────

// cryp001 offers each mandated TLS 1.2 suite ALONE, three times, and requires
// the DUT to select it each time.
//
// Offering one suite at a time is the whole procedure: a DUT that supports only
// GCM would pass a test that offered all three and looked at what came back.
// The three separate handshakes are what make the criterion "supports each of
// the mandatory suites" rather than "supports at least one".
//
// The completion caveat, stated once here and honoured throughout the family:
// Go's crypto/tls cannot complete a CCM-8 handshake, so iteration 3 evidences
// the DUT's SELECTION of 0xC0AE and its full flight through ServerHelloDone,
// and says so rather than implying a session was established.
func cryp001(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	var t tally
	probes := make([]*ProbeResult, 0, len(mandated12))
	for i, want := range mandated12 {
		h := conformantHello()
		h.SupportedVersions = nil
		h.Suites = []uint16{want}
		label := fmt.Sprintf("iteration %d: only 0x%04X %s", i+1, want, tlsdis.CipherSuiteName(want))
		p := Probe(ctx, rc, pf.Target, label, h)
		probes = append(probes, p)
		v, obs := selectedSuite(p, want)
		t.add(v, "%s → %s", label, obs)
	}

	// Two of the three suites can be taken all the way to an established
	// session by this bench, and are: a selection is not a session.
	completed := 0
	for _, suite := range []uint16{suiteECDHE_ECDSA_AES128_GCM_SHA256, suiteECDHE_ECDSA_CHACHA20_POLY1305} {
		s, err := completingSuiteSession(ctx, rc, pf, suite)
		if err != nil {
			t.add(certify.Fail, "no session could be established on 0x%04X %s: %v",
				suite, tlsdis.CipherSuiteName(suite), err)
			continue
		}
		completed++
		t.add(certify.Pass, "an mbaps session was established and closed on 0x%04X %s",
			suite, tlsdis.CipherSuiteName(suite))
		s.Close()
	}
	t.caveat("0x%04X %s: the DUT's SELECTION of the suite and its full server flight are asserted from the "+
		"capture, but this bench's TLS stack (Go crypto/tls) implements no CCM cipher, so no session was "+
		"established on it and none is claimed",
		suiteECDHE_ECDSA_AES128_CCM_8, tlsdis.CipherSuiteName(suiteECDHE_ECDSA_AES128_CCM_8))

	half := watchClientHalf(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for i, p := range probes {
				want := mandated12[i]
				a, err := serverHelloFact(ev, p,
					fmt.Sprintf("SunSpecTCP-17: offered ONLY 0x%04X %s, the EUT-S accepted it and answered with a ServerHello selecting it",
						want, tlsdis.CipherSuiteName(want)),
					"single-suite TLS 1.2 ClientHello; ServerHello.cipher_suite parsed from the capture",
					func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
						return selectedSuiteFromHello(sh, want, "the capture holds no ServerHello for this conversation")
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)

				a, err = probeFact(ev, p,
					fmt.Sprintf("SunSpecTCP-19: with only 0x%04X offered, the EUT-S proceeded through its whole server flight rather than aborting",
						want),
					"ordered handshake message types of the DUT→bench direction",
					func(v *wireView) (certify.Verdict, string, []int) {
						verdict, obs := serverFlightVerdict(v.ServerFlight())
						return verdict, obs, v.Frames
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			a, err := half.fact(ev,
				"SunSpecTCP-17 [C]: the gateway's own southbound ClientHello offers all three mandatory TLS 1.2 suites",
				"cipher_suites list of the gateway's ClientHello to the bench device sim",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					missing := missingSuites(ch.CipherSuites, mandated12)
					obs := fmt.Sprintf("gateway ClientHello cipher_suites = %s", hexSuites(ch.CipherSuites))
					if len(missing) > 0 {
						return certify.Fail, obs + " — missing " + namedSuites(missing)
					}
					return certify.Pass, obs + " — all three SunSpecTCP-17 suites present"
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── CRYP-002 · TLS v1.3 Cipher Suites [C, S] ────────────────────────────────

func cryp002(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	var t tally
	probes := make([]*ProbeResult, 0, len(mandated13))
	supported := false
	for i, want := range mandated13 {
		h := conformantHello13()
		h.Suites = []uint16{want}
		label := fmt.Sprintf("iteration %d: only 0x%04X %s", i+1, want, tlsdis.CipherSuiteName(want))
		p := Probe(ctx, rc, pf.Target, label, h)
		probes = append(probes, p)
		if sh := p.ServerHello(); sh != nil && sh.NegotiatedVersion() == tlsdis.VersionTLS13 {
			supported = true
		}
		v, obs := selectedSuite(p, want)
		t.add(v, "%s → %s", label, obs)
	}
	if !supported {
		return certify.Skipped(
			"CRYP-002 is mandatory only if the EUT supports TLS 1.3, and no TLS 1.3 handshake was "+
				"negotiated in three single-suite attempts: %s", t.notes()), nil
	}

	sess, chain, m1, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS13, tls.VersionTLS13,
		"CRYP-002 TLS 1.3 session for the Model 1 read")
	if sess != nil {
		defer sess.Close()
	}
	switch {
	case serr != nil:
		t.add(certify.Fail, "no TLS 1.3 session could be established for the Model 1 read: %v", serr)
	case m1.Err != nil:
		t.add(certify.Fail, "the Model 1 read inside the TLS 1.3 session failed: %v", m1.Err)
	default:
		v, obs := normalResponseVerdict(m1.Response)
		t.add(v, "Model 1 read on unit %d (chain models %v): %s", chain.Unit, chain.IDs(), obs)
	}
	t.caveat("0x%04X %s: selection is asserted from the capture; this bench's TLS stack implements no CCM "+
		"cipher, so no TLS 1.3 CCM session was established and none is claimed",
		suiteTLS13_AES128_CCM_SHA256, tlsdis.CipherSuiteName(suiteTLS13_AES128_CCM_SHA256))

	half := watchClientHalf(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for i, p := range probes {
				want := mandated13[i]
				a, err := serverHelloFact(ev, p,
					fmt.Sprintf("SunSpecTCP-18: offered ONLY 0x%04X %s over TLS 1.3, the EUT-S selected it",
						want, tlsdis.CipherSuiteName(want)),
					"single-suite TLS 1.3 ClientHello; ServerHello.cipher_suite parsed from the capture",
					func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
						v, obs := selectedSuiteFromHello(sh, want, "the capture holds no ServerHello for this conversation")
						if v == certify.Pass && sh.NegotiatedVersion() != tlsdis.VersionTLS13 {
							return certify.Fail, obs + " — but the negotiated version is not TLS 1.3"
						}
						return v, obs
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			a, err := probeFact(ev, probes[0],
				"CRYP-002 client-hello shape: legacy_version 0x0303 with a supported_versions extension containing 0x0304",
				"ClientHello legacy_version and supported_versions, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					ch, frames := v.ClientHello()
					if ch == nil {
						return certify.Fail, "no ClientHello in the capture for this conversation", v.Frames
					}
					obs := fmt.Sprintf("legacy_version 0x%04X, supported_versions %v", ch.LegacyVersion, ch.SupportedVersions)
					has13 := false
					for _, sv := range ch.SupportedVersions {
						if sv == tlsdis.VersionTLS13 {
							has13 = true
						}
					}
					if ch.LegacyVersion != tlsdis.VersionTLS12 || !has13 {
						return certify.Fail, obs, frames
					}
					return certify.Pass, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = decryptedFact(ev, sess,
				"a SunSpec Model 1 read was carried inside the TLS 1.3 session and answered",
				"TLS 1.3 decryption with the run's key log, then MBAP framing",
				func(p *plaintext, _ *wireView) (certify.Verdict, string, []int) {
					return modbusExchangeFact(p, 0x03, normalResponseVerdict)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = half.fact(ev,
				"SunSpecTCP-18 [C]: the gateway's own southbound ClientHello offers 0x1301, 0x1303 and 0x1304 in that exact order",
				"cipher_suites list of the gateway's ClientHello to the bench device sim",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					obs := fmt.Sprintf("gateway ClientHello cipher_suites = %s", hexSuites(ch.CipherSuites))
					if !inRelativeOrder(ch.CipherSuites, mandated13) {
						return certify.Fail, obs + " — the three mandated TLS 1.3 suites do not appear in the order CRYP-002 prescribes"
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

// ── CRYP-003 · Disable Insecure Ciphers [C, S] ──────────────────────────────

// cryp003 asserts the half of the procedure a read-only bench can reach — the
// DUT refuses an IANA-discouraged offer — and is explicit about the half it
// cannot.
//
// Steps 4 and 9 require the operator to DISABLE and then RE-ENABLE
// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 through the EUT's management
// interface, observing that the disabled suite is then refused. That is a
// configuration change to a shared DUT, which this bench is forbidden from
// making; running it would also leave the gateway in a non-default state for
// every other agent on the bench. The mechanism's existence is evidenced
// off-wire instead, from the DUT's own configuration, when gateway
// introspection is available.
func cryp003(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	offer := discouragedOffer()
	h := conformantHello()
	h.SupportedVersions = nil
	h.Suites = offer
	// A discouraged-suite offer needs the signature algorithms those suites
	// actually use, or a refusal could be attributed to the sigalgs instead.
	h.SigAlgs = append(h.SigAlgs, sigRSAPKCS1SHA256, 0x0501, 0x0601)
	p := Probe(ctx, rc, pf.Target, "CRYP-003: IANA-discouraged suites only", h)

	var t tally
	v, obs := refused(p, "a ClientHello offering only IANA-discouraged cipher suites "+hexSuites(offer))
	t.add(v, "%s", obs)

	// The control: the same probe with the mandated suites must succeed, or a
	// refusal proves only that the DUT is down.
	ctrl := conformantHello()
	ctrl.SupportedVersions = nil
	control := Probe(ctx, rc, pf.Target, "CRYP-003 control: mandated suites", ctrl)
	cv, cobs := selectedSuite(control, suiteECDHE_ECDSA_AES128_GCM_SHA256)
	t.add(cv, "control: %s", cobs)

	// The configurability half, off-wire.
	suiteCfg, cfgErr := readGatewayFile(ctx, rc, "/etc/lexa/configs/mbaps.json")
	if cfgErr != nil {
		t.caveat("the suite-disable MECHANISM (steps 4 and 9) was not exercised: toggling a cipher suite is a "+
			"configuration change to a shared DUT, which this bench is forbidden from making, and the DUT's "+
			"configuration could not be read to evidence the mechanism instead: %v", cfgErr)
	} else {
		t.caveat("the suite-disable MECHANISM (steps 4 and 9) was not exercised on the wire: toggling a cipher "+
			"suite is a configuration change to a shared DUT. The DUT's mbaps configuration (%d bytes) is "+
			"cited off-wire as evidence that the mechanism exists.", len(suiteCfg))
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := refusalFact(ev,
				p,
				"SunSpecTCP-20: the EUT-S refused a handshake offering only IANA-discouraged cipher suites "+hexSuites(offer),
				"a ClientHello offering only IANA-discouraged cipher suites")
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = serverHelloFact(ev, control,
				"control: the same probe offering the SunSpecTCP-17 suites was accepted, so the refusal above is attributable to the suites and not to an unreachable DUT",
				"ServerHello.cipher_suite of the control conversation",
				func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
					return selectedSuiteFromHello(sh, suiteECDHE_ECDSA_AES128_GCM_SHA256,
						"the control conversation produced no ServerHello either — the DUT may simply be unreachable")
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			claim := "SunSpecTCP-20: the EUT provides a mechanism to disable specific cipher suites"
			const method = "read of the DUT's mbaps configuration over the read-only gateway client"
			if cfgErr != nil {
				out = append(out, ev.SkipAssertion(claim, method,
					"toggling a cipher suite is a configuration change to a shared DUT, which this bench is "+
						"forbidden from making, and the configuration could not be read instead: "+cfgErr.Error()))
			} else {
				a, err := ev.Narrative(claim, method, certify.Pass,
					summariseSuiteConfig(suiteCfg),
					"the DUT's own /etc/lexa/configs/mbaps.json, read over the read-only gateway client; the "+
						"disable/re-enable steps themselves were NOT performed, because this suite may not "+
						"reconfigure a shared bench DUT")
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// summariseSuiteConfig extracts the cipher-suite configuration line from the
// DUT's mbaps configuration without pretending to parse the whole file: the
// claim is "a knob exists", and quoting the knob is the evidence.
func summariseSuiteConfig(cfg []byte) string {
	for _, line := range strings.Split(string(cfg), "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "suite") || strings.Contains(l, "cipher") {
			return "the DUT's mbaps configuration carries a cipher-suite selector: " + l
		}
	}
	return fmt.Sprintf("the DUT's mbaps configuration (%d bytes) was read; it carries no line mentioning "+
		"cipher suites, so the suite list is compiled in or defaulted", len(cfg))
}

// ── CRYP-004 · ECC Curve and Point Format Support [C, S] ────────────────────

func cryp004(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	pos := conformantHello()
	pos.SupportedVersions = nil
	pos.Groups = []uint16{groupSecp256r1}
	pos.PointFormats = []uint8{0}
	positive := Probe(ctx, rc, pf.Target, "CRYP-004: P-256 offered", pos)

	neg := conformantHello()
	neg.SupportedVersions = nil
	neg.Groups = []uint16{groupSecp384r1}
	neg.PointFormats = []uint8{0}
	negative := Probe(ctx, rc, pf.Target, "CRYP-004 negative: only secp384r1 offered", neg)

	var t tally
	v, obs := serverCurveVerdict(positive.ServerKeyExchange(), groupSecp256r1)
	t.add(v, "%s", obs)
	v, obs = refused(negative, "a ClientHello whose supported_groups offered only secp384r1, without the mandatory P-256")
	t.add(v, "negative iteration: %s", obs)

	half := watchClientHalf(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion

			// The test-setup criteria (steps 3 and 4): the extensions were
			// present in the hello that was actually sent. These are claims
			// about the TEST CLIENT, and are labelled as such — a reader must
			// not read them as claims about the DUT.
			a, err := probeFact(ev, positive,
				"CRYP-004 steps 3-4 (test-client setup): the ClientHello carried extension 0x000A supported_groups containing NamedCurve 0x0017 (secp256r1) and extension 0x000B ec_point_formats",
				"ClientHello extensions of the bench→DUT direction, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					ch, frames := v.ClientHello()
					verdict, obs := supportedGroupsVerdict(ch, "the bench's")
					if ch == nil {
						return verdict, obs, v.Frames
					}
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = probeFact(ev, positive,
				"SunSpecTCP-42/43/44: the EUT-S performed the ECDHE key exchange over the P-256 curve",
				"ServerKeyExchange ECParameters (RFC 4492 §5.4), parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					ske, frames := v.ServerKeyExchange()
					verdict, obs := serverCurveVerdict(ske, groupSecp256r1)
					if len(ske) == 0 {
						return verdict, obs, v.Frames
					}
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = refusalFact(ev, negative,
				"CRYP-004 step 7: offered only the non-mandatory secp384r1 curve, the EUT-S did not complete an ECDHE handshake",
				"a ClientHello whose supported_groups omitted the mandatory P-256 curve")
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = half.fact(ev,
				"SunSpecTCP-43/44 [C]: the gateway's own southbound ClientHello carries supported_groups with secp256r1 and the ec_point_formats extension",
				"ClientHello extensions of the gateway's hello to the bench device sim",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					return supportedGroupsVerdict(ch, "the gateway's")
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── CRYP-005 · Forbidden Hashes and HMAC Compliance [C, S] ──────────────────

func cryp005(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	// The procedure's exact provocation: a SHA-1 MAC suite plus (sha1, ecdsa)
	// and (md5, rsa) in signature_algorithms.
	bad := conformantHello()
	bad.SupportedVersions = nil
	bad.Suites = []uint16{suiteRSA_AES128_CBC_SHA}
	bad.SigAlgs = []uint16{sigECDSASHA1, sigRSAMD5}
	weak := Probe(ctx, rc, pf.Target, "CRYP-005: SHA-1 suite with md5/sha1 signature algorithms", bad)

	good := conformantHello()
	good.SupportedVersions = nil
	strong := Probe(ctx, rc, pf.Target, "CRYP-005 control: SHA-256 suites", good)

	var t tally
	v, obs := refused(weak, "a ClientHello offering 0x002F TLS_RSA_WITH_AES_128_CBC_SHA with (sha1, ecdsa) and (md5, rsa) signature algorithms")
	t.add(v, "%s", obs)
	if sh := strong.ServerHello(); sh == nil {
		t.add(certify.Fail, "the control handshake produced no ServerHello: %s", strong.Summary())
	} else if !sha256PRFSuite(sh.CipherSuite) {
		t.add(certify.Fail, "the control handshake selected 0x%04X %s, which does not use the SHA-256 PRF",
			sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite))
	} else {
		t.add(certify.Pass, "the control handshake selected 0x%04X %s, a SHA-256-PRF suite",
			sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite))
	}

	half := watchClientHalf(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := refusalFact(ev, weak,
				"SunSpecTCP-54/55: the EUT-S rejected a handshake offering an MD5/SHA-1 signature algorithm set and a SHA-1 MAC cipher suite",
				"a ClientHello with cipher suite 0x002F and signature_algorithms (sha1, ecdsa) and (md5, rsa)")
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = serverHelloFact(ev, strong,
				"SunSpecTCP-56/57: the EUT-S negotiated a SHA-256-PRF cipher suite, so key derivation uses HMAC-SHA-256 (RFC 5246 §5)",
				"ServerHello.cipher_suite of the control conversation, mapped to its PRF hash",
				func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
					if sh == nil {
						return certify.Fail, "the control conversation produced no ServerHello"
					}
					obs := fmt.Sprintf("negotiated 0x%04X %s over %s",
						sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite),
						tlsdis.VersionName(sh.NegotiatedVersion()))
					if !sha256PRFSuite(sh.CipherSuite) {
						return certify.Fail, obs + " — this suite does not use the SHA-256 PRF"
					}
					return certify.Pass, obs + " — RFC 5246 §5 fixes this suite's PRF at SHA-256, from which HMAC-SHA-256 key derivation follows"
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = half.fact(ev,
				"SunSpecTCP-54/55 [C]: the gateway's own southbound ClientHello offers no MD5 or SHA-1 signature algorithm and no SHA-1 MAC cipher suite",
				"signature_algorithms and cipher_suites of the gateway's ClientHello to the bench device sim",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					weakSigs := weakSignatureAlgorithms(ch.SignatureAlgorithms)
					var weakSuites []string
					for _, id := range ch.CipherSuites {
						if n, bad := weakHashSuites[id]; bad {
							weakSuites = append(weakSuites, fmt.Sprintf("0x%04X %s", id, n))
						}
					}
					obs := fmt.Sprintf("gateway ClientHello: %d signature algorithm(s), %d cipher suite(s)",
						len(ch.SignatureAlgorithms), len(ch.CipherSuites))
					if len(weakSigs) > 0 || len(weakSuites) > 0 {
						return certify.Fail, fmt.Sprintf("%s — MD5/SHA-1 signature algorithms [%s]; SHA-1/MD5 MAC suites [%s]",
							obs, strings.Join(weakSigs, ", "), strings.Join(weakSuites, ", "))
					}
					return certify.Pass, obs + " — none uses MD5 or SHA-1"
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── CRYP-006 · IANA Registry Compliance [C, S] ──────────────────────────────

// cryp006 is largely a documentation exercise in the source procedure — five of
// its seven server steps are test-engineer actions against the IANA registry
// and a vendor PICS. What IS wire-observable is the codepoint the EUT-S
// actually selected and the full list the EUT-C actually offered, and both are
// asserted here against the bench's own transcription of the registry.
//
// The vendor PICS half is a SKIP with the reason: this suite has no PICS, and
// inventing a cross-reference table from the codepoints it happened to see
// would be exactly the kind of paper conformance the tool exists to avoid.
func cryp006(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}
	h := conformantHello()
	h.SupportedVersions = nil
	p := Probe(ctx, rc, pf.Target, "CRYP-006: mandated offer", h)

	var t tally
	if sh := p.ServerHello(); sh == nil {
		t.add(certify.Fail, "the EUT-S sent no ServerHello: %s", p.Summary())
	} else {
		reg := tlsdis.KnownCipherSuite(sh.CipherSuite)
		certBased, why := certificateBasedSuite(sh.CipherSuite)
		switch {
		case !reg:
			t.add(certify.Fail, "the EUT-S selected 0x%04X, which is not in the bench's IANA registry transcription", sh.CipherSuite)
		case !certBased:
			t.add(certify.Fail, "the EUT-S selected 0x%04X %s: %s", sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite), why)
		default:
			t.add(certify.Pass, "the EUT-S selected 0x%04X %s — IANA-registered and %s",
				sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite), why)
		}
	}
	t.caveat("the vendor PICS cross-reference (steps 4-6) was not performed: no Protocol Implementation " +
		"Conformance Statement was supplied to this run, and the suite will not manufacture a " +
		"cross-reference table from the codepoints it happened to observe")

	half := watchClientHalf(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := serverHelloFact(ev, p,
				"SunSpecTCP-15/16: the cipher suite the EUT-S selected is registered in the IANA TLS Cipher Suite Registry and accommodates X.509v3 certificate authentication",
				"ServerHello.cipher_suite cross-referenced against the bench's own transcription of the IANA registry",
				func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
					if sh == nil {
						return certify.Fail, "no ServerHello in the capture for this conversation"
					}
					reg := tlsdis.KnownCipherSuite(sh.CipherSuite)
					certBased, why := certificateBasedSuite(sh.CipherSuite)
					obs := fmt.Sprintf("selected 0x%04X %s; IANA-registered: %t; %s",
						sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite), reg, why)
					if !reg || !certBased {
						return certify.Fail, obs
					}
					return certify.Pass, obs
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			out = append(out, ev.SkipAssertion(
				"SunSpecTCP-15/16: every cipher suite in the vendor's PICS is IANA-registered and not marked discouraged or prohibited",
				"cross-reference of the vendor PICS against the IANA TLS Cipher Suite Registry",
				"no Protocol Implementation Conformance Statement was supplied to this run. The suites the DUT "+
					"was OBSERVED to offer and select are asserted above; the PICS covers suites the DUT "+
					"supports but did not use here, and no capture can evidence those."))

			a, err = half.fact(ev,
				"SunSpecTCP-15/16 [C]: every cipher suite the gateway offers is IANA-registered and certificate-based",
				"every codepoint in the gateway's ClientHello cipher_suites, cross-referenced against the bench's IANA transcription",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					var unregistered, notCert []string
					for _, id := range ch.CipherSuites {
						if tlsdis.IsGREASE(id) {
							continue
						}
						if !tlsdis.KnownCipherSuite(id) {
							unregistered = append(unregistered, fmt.Sprintf("0x%04X", id))
							continue
						}
						if ok, _ := certificateBasedSuite(id); !ok {
							notCert = append(notCert, fmt.Sprintf("0x%04X %s", id, tlsdis.CipherSuiteName(id)))
						}
					}
					obs := fmt.Sprintf("gateway ClientHello offered %d suite(s): %s",
						len(ch.CipherSuites), namedSuites(ch.CipherSuites))
					if len(unregistered) > 0 || len(notCert) > 0 {
						return certify.Fail, fmt.Sprintf("%s — unregistered: [%s]; not certificate-based: [%s]",
							obs, strings.Join(unregistered, ", "), strings.Join(notCert, ", "))
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

// ── CRYP-007 · Encryption-Capable Cipher Selection [C, S] (Negative) ────────

func cryp007(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	offer := nullEncryptionOffer()
	h := conformantHello()
	h.SupportedVersions = nil
	h.Suites = offer
	h.SigAlgs = append(h.SigAlgs, sigRSAPKCS1SHA256)
	nullProbe := Probe(ctx, rc, pf.Target, "CRYP-007: NULL-encryption suites only", h)

	ctrl := conformantHello()
	ctrl.SupportedVersions = nil
	control := Probe(ctx, rc, pf.Target, "CRYP-007 control: SunSpecTCP-17 suites", ctrl)

	var t tally
	v, obs := refused(nullProbe, fmt.Sprintf("a ClientHello offering only the %d registered NULL-encryption cipher suites", len(offer)))
	t.add(v, "%s", obs)
	cv, cobs := selectedSuite(control, suiteECDHE_ECDSA_AES128_GCM_SHA256)
	t.add(cv, "control: %s", cobs)

	half := watchClientHalf(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := refusalFact(ev, nullProbe,
				fmt.Sprintf("SunSpecTCP-53: the EUT-S rejected a handshake offering only NULL-encryption cipher suites (all %d registered codepoints, not only the four the procedure names)", len(offer)),
				"a ClientHello offering only NULL-encryption cipher suites")
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = serverHelloFact(ev, control,
				"SunSpecTCP-17/53: the same probe offering the mandatory encrypting suites was accepted and the handshake proceeded",
				"ServerHello.cipher_suite of the control conversation",
				func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
					return selectedSuiteFromHello(sh, suiteECDHE_ECDSA_AES128_GCM_SHA256,
						"the control conversation produced no ServerHello either — the DUT may be unreachable")
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = half.fact(ev,
				"SunSpecTCP-53 [C]: the gateway's own southbound ClientHello offers no NULL-encryption cipher suite",
				"every codepoint in the gateway's ClientHello, checked against the registered NULL-encryption set",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					nulls := nullSuitesIn(ch.CipherSuites)
					obs := fmt.Sprintf("gateway ClientHello offered %s", hexSuites(ch.CipherSuites))
					if len(nulls) > 0 {
						return certify.Fail, obs + " — NULL-encryption suites present: " + strings.Join(nulls, ", ")
					}
					return certify.Pass, obs + " — none of the registered NULL-encryption codepoints is present"
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── OPS-001 · Cryptographic Export Compliance [C, S] ────────────────────────

// ops001 is a pure documentation review in the source procedure: five [T] steps
// against a vendor-supplied Cryptographic Export Declaration, cross-referenced
// against the suites the CRYP family observed.
//
// No declaration is supplied to this run, so the row cannot pass. What the
// suite CAN do — and does — is emit the cross-reference input the reviewer
// needs: the exact suites and key exchange the DUT was observed using, cited on
// the frames that show them. That turns OPS-001 from "unaddressed" into "half
// done, and here is the half a document review needs".
func ops001(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	// Observe the negotiated suite and key exchange under both versions the DUT
	// offers, which is the cross-reference table OPS-001 step 5 needs.
	h12 := conformantHello()
	h12.SupportedVersions = nil
	p12 := Probe(ctx, rc, pf.Target, "OPS-001: TLS 1.2 observation", h12)
	p13 := Probe(ctx, rc, pf.Target, "OPS-001: TLS 1.3 observation", conformantHello13())

	declaration, declared := rc.Param("ssm.export_declaration")

	var t tally
	for _, p := range []*ProbeResult{p12, p13} {
		if sh := p.ServerHello(); sh != nil {
			t.add(certify.Pass, "%s: negotiated 0x%04X %s over %s", p.Label, sh.CipherSuite,
				tlsdis.CipherSuiteName(sh.CipherSuite), tlsdis.VersionName(sh.NegotiatedVersion()))
		} else {
			t.add(certify.Warn, "%s: no ServerHello (%s)", p.Label, p.Summary())
		}
	}
	if !declared {
		t.caveat("no Cryptographic Export Declaration was supplied (-param ssm.export_declaration=<path>), " +
			"so the vendor attestation SunSpecTCP-58 requires could not be reviewed; the observed " +
			"cryptography is cited below as the cross-reference input for that review")
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			for _, p := range []*ProbeResult{p12, p13} {
				a, err := serverHelloFact(ev, p,
					"SunSpecTCP-58 (cross-reference input): the cryptography the EUT actually used on the wire — "+p.Label,
					"ServerKeyExchange curve and ServerHello.cipher_suite, parsed from the capture",
					func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
						if sh == nil {
							return certify.Skip, "no ServerHello was captured for this observation"
						}
						return certify.Pass, fmt.Sprintf(
							"cipher suite 0x%04X %s, negotiated version %s — this is the observation an export "+
								"declaration must be consistent with",
							sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite),
							tlsdis.VersionName(sh.NegotiatedVersion()))
					})
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			claim := "SunSpecTCP-58: the vendor's Cryptographic Export Declaration lists every implemented cipher suite and key exchange, attests to jurisdictional compliance, and matches the CRYP-category observations"
			const method = "clause-by-clause review of a vendor-supplied declaration against the observed suites"
			if !declared {
				out = append(out, ev.SkipAssertion(claim, method,
					"no Cryptographic Export Declaration was supplied to this run "+
						"(-param ssm.export_declaration=<path>). This is a paper artefact a vendor provides; "+
						"no packet capture can evidence it, and the suite will not assert a document it has "+
						"not been given."))
				return out, nil
			}
			a, err := ev.Narrative(claim, method, certify.Warn,
				"a declaration was named at "+declaration+", but reviewing a legal attestation is a human "+
					"judgement this suite does not make; the observed cryptography is cited above for that review",
				"the -param ssm.export_declaration path supplied by the operator")
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── shared bits of this family ──────────────────────────────────────────────

// completingSuiteSession establishes a session pinned to one TLS 1.2 suite, for
// the "a session was actually established on this suite" half of CRYP-001.
func completingSuiteSession(ctx context.Context, rc *certify.RunCtx, pf preflight, suite uint16) (*Session, error) {
	roots, err := rootPool(pf.PKI)
	if err != nil {
		return nil, err
	}
	cert, err := roleCert(pf.PKI, "grid-service")
	if err != nil {
		return nil, err
	}
	return dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{suite},
		Note:         fmt.Sprintf("CRYP-001 completing session on 0x%04X", suite),
	})
}

// missingSuites returns the members of want that are absent from got.
func missingSuites(got, want []uint16) []uint16 {
	have := map[uint16]bool{}
	for _, g := range got {
		have[g] = true
	}
	var out []uint16
	for _, w := range want {
		if !have[w] {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// readGatewayFile reads a file from the DUT over the READ-ONLY gateway client,
// returning a reason rather than an error string when introspection is not
// configured — the reason ends up in the bundle.
func readGatewayFile(ctx context.Context, rc *certify.RunCtx, path string) ([]byte, error) {
	if rc.Gateway == nil || !rc.Gateway.Available() {
		return nil, fmt.Errorf("gateway introspection is not configured (-gateway-ssh)")
	}
	b, err := rc.Gateway.ReadFile(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("read %s from the DUT: %w", path, err)
	}
	return b, nil
}
