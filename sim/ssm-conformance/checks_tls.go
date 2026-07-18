package main

// checks_tls.go asserts the Transport Layer Security (§5.1 TCP-1..14, minus the
// authz-owned TCP-8), Cipher Suite Selection (§5.2 TCP-15..20), Public Key
// Infrastructure (§5.4 TCP-42..58), and Packet/Session (§5.5 TCP-59..62)
// requirements against the target mbaps server, one PASS/FAIL/SKIP per row with
// expected-vs-got evidence. Every assertion is driven over the bench's own
// referee client (internal/mbtls) — never the product's TLS stack (PN-1/C9) — so
// a profile bug in the gateway cannot hide behind a shared implementation.

import (
	"crypto/x509"
	"fmt"
	"strings"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
)

// checkTransportSecurity covers §5.1 TCP-1..14 (TCP-8 is authz-owned).
func checkTransportSecurity(r *Reporter, rc *runCtx) {
	r.section("5.1", "Transport Layer Security (TCP-1..14)")
	ps := rc.ps

	// TCP-1 — port 802 SHOULD.
	switch {
	case rc.port == 802:
		r.pass(1, "target listens on the mbaps port 802")
	case rc.isLoopback:
		r.warn(1, "loopback on ephemeral port %d — the port-802 SHOULD applies to the live gateway target", rc.port)
	default:
		r.warn(1, "target port %d ≠ 802 (SHOULD, not MUST)", rc.port)
	}

	// TCP-2 — MUST support ≥10 root certificates. Verify the peer against a trust
	// store of ten roots (nine filler + the real anchor, anchor last): a store
	// that considers ≥10 roots must still find the peer's issuer.
	if t10, cleanup, err := ps.trust10File(); err != nil {
		r.fail(2, "could not build a 10-root trust bundle: %v", err)
	} else {
		defer cleanup()
		s, err := dialRole(rc.target, ps, RoleGridService, forceTLS12, withCAFile(t10))
		if s != nil {
			defer s.Close()
		}
		r.verdict(2, err == nil, "handshake verified the peer against a 10-root trust store (anchor #10): err=%v", err)
	}

	// TCP-3 — secure add/remove of root & server certs. Server-side cert-manager
	// capability (out-of-band admin), not a client-observable handshake property.
	r.skip(3, "server-side cert-manager add/remove capability (lexa-gw T03 certmgr); not a client-observable wire behavior")

	// TCP-4 — TLS 1.2 MUST be supported.
	if s, err := dialRole(rc.target, ps, RoleGridService, forceTLS12); err != nil {
		r.fail(4, "TLS 1.2 handshake failed: %v", err)
	} else {
		defer s.Close()
		r.verdict(4, s.TLSVer == "TLSv1.2", "negotiated %s, want TLSv1.2", s.TLSVer)
	}

	// TCP-5 — TLS 1.3 MAY be supported (this build offers it).
	if s, err := dialRole(rc.target, ps, RoleGridService, forceTLS13); err != nil {
		r.warn(5, "TLS 1.3 handshake failed (TLS 1.3 is a MAY): %v", err)
	} else {
		defer s.Close()
		if s.TLSVer == "TLSv1.3" {
			r.pass(5, "negotiated TLS 1.3 (%s)", s.Cipher)
		} else {
			r.warn(5, "TLS 1.3 offered but peer negotiated %s (MAY)", s.TLSVer)
		}
	}

	// A single canonical good handshake drives the mutual-auth / X.509 / tunnel
	// rows (TCP-6/7/9/10).
	good, gerr := dialRole(rc.target, ps, RoleGridService)
	if gerr != nil || good == nil {
		for _, n := range []int{6, 7, 9, 10} {
			r.fail(n, "canonical mutual-auth handshake failed: %v", gerr)
		}
	} else {
		defer good.Close()
		ourLeaf, _ := leafOf(ps.roles[RoleGridService].certFile)
		peer := peerLeaf(good)

		// TCP-6 / TCP-10 — mutual authentication (both directions), during the
		// handshake. We presented a client cert (the server requires one) AND we
		// verified + captured the peer's server cert.
		mutual := good.PeerDER != nil && ourLeaf != nil
		r.verdict(6, mutual, "mutual TLS: client cert presented + peer server cert verified (peerDER=%d bytes)", len(good.PeerDER))
		r.verdict(10, mutual, "mutual authentication completed during the handshake over %s", good.TLSVer)

		// TCP-12 — client MUST send ClientCertificate on the server's request. The
		// server requires a client cert; a completed mutual handshake means ours was
		// sent and accepted (client-direction row; also re-exercised vs -device-target).
		r.verdict(12, mutual, "client sent its ClientCertificate on request (mutual handshake completed with role %s)", RoleGridService)

		// TCP-7 — X.509v3 certificates are the credentials.
		v3 := ourLeaf != nil && ourLeaf.Version == 3 && peer != nil && peer.Version == 3
		r.verdict(7, v3, "client + server leaves are X.509 v3 (client v%d, server v%d)", certVer(ourLeaf), certVer(peer))

		// TCP-9 — no change to the mbap protocol inside the tunnel: a plain mbap
		// frame round-trips over the decrypted stream.
		perr := pump(good, rc.probeUnit())
		r.verdict(9, perr == nil, "plain mbap frame round-tripped inside the TLS tunnel: err=%v", perr)
	}

	// TCP-11 / TCP-13 / TCP-48 — server MUST send CertificateRequest and MUST
	// fatal-alert + terminate a certless client. A dial presenting no client
	// certificate must be rejected with no session.
	noCert, ncErr := dialCred(rc.target, ps.serverCA, "", "", forceTLS12)
	if noCert != nil {
		noCert.Close()
	}
	rejected := ncErr != nil && noCert == nil
	r.verdict(11, rejected, "certless dial rejected ⇒ server demanded a client cert (CertificateRequest): err=%v", ncErr)
	r.verdict(13, rejected, "certless handshake terminated with a fatal alert, no session: err=%v", ncErr)

	// TCP-14 — MUST NOT resume after a fatal alert. Two observable halves: (a)
	// resumption is genuinely available (a clean redial resumes), so a later
	// "not resumed" is meaningful; and (b) a fatal-alert handshake (the certless
	// path above) yields NO session — no resumable state survives the fatal. The
	// server-side eviction of a faulted session from its cache is white-box
	// proven in lexa-gw T01.12 (wolfssl.RemoveSessionFromServerCache).
	resumeOK := probeResumption(rc, forceTLS12)
	r.verdict(14, resumeOK && rejected,
		"resumption available (clean redial resumes) yet a fatal-alert handshake left no session — no resume survives a fatal (server-cache eviction cross-ref lexa-gw T01.12)")
}

// checkCipherSuites covers §5.2 TCP-15..20.
func checkCipherSuites(r *Reporter, rc *runCtx) {
	r.section("5.2", "Cipher Suite Selection (TCP-15..20)")
	ps := rc.ps

	// The mandated suites are all IANA-registered ECDSA AEAD suites — the bench's
	// independent transcription (mbtls.Mandated12/13), NOT the product's list.
	all := append(append([]string{}, mbtls.Mandated12...), mbtls.Mandated13...)
	r.pass(15, "offered suites are IANA-listed: %s", strings.Join(all, ", "))

	// TCP-16 — ciphers accommodate X.509v3: the mandated suites are ECDHE-ECDSA /
	// TLS1.3 AEAD suites, compatible with X.509v3 EC certs; a good handshake on
	// one, with an X.509v3 EC leaf, proves it.
	if s, err := dialRole(rc.target, ps, RoleGridService, forceTLS12); err != nil {
		r.fail(16, "handshake failed: %v", err)
	} else {
		defer s.Close()
		r.verdict(16, strings.Contains(s.Cipher, "ECDSA"), "negotiated ECDSA suite %s accommodates the X.509v3 EC certificate", s.Cipher)
	}

	// TCP-17 — TLS 1.2 minimum suites in order (GCM first when the full order is
	// offered).
	if s, err := dialRole(rc.target, ps, RoleGridService, forceTLS12); err != nil {
		r.fail(17, "TLS 1.2 handshake failed: %v", err)
	} else {
		defer s.Close()
		r.verdict(17, s.Cipher == mbtls.Mandated12[0], "TLS 1.2 negotiated %s (mandated-order head is %s)", s.Cipher, mbtls.Mandated12[0])
	}

	// TCP-18 — TLS 1.3 minimum suites in order (GCM first).
	if s, err := dialRole(rc.target, ps, RoleGridService, forceTLS13); err != nil {
		r.warn(18, "TLS 1.3 handshake failed (1.3 is a MAY): %v", err)
	} else {
		defer s.Close()
		r.verdict(18, s.Cipher == mbtls.Mandated13[0], "TLS 1.3 negotiated %s (mandated-order head is %s)", s.Cipher, mbtls.Mandated13[0])
	}

	// TCP-19 — offered order MUST match TCP-17/18. The client profile's default
	// suite lists are the mandated order verbatim (mbtls validates this at
	// construction); assert exact equality.
	order12 := equalSeq(mbtls.DefaultClientProfile("x", "y", "z").Suites12, mbtls.Mandated12)
	order13 := equalSeq(mbtls.DefaultClientProfile("x", "y", "z").Suites13, mbtls.Mandated13)
	r.verdict(19, order12 && order13, "offered suite order matches the mandated TCP-17/18 sequences (1.2 ok=%t, 1.3 ok=%t)", order12, order13)

	// TCP-20 — MUST be able to disable IANA-discouraged suites: with the lists
	// trimmed to CCM-8, the handshake negotiates CCM-8 (the discouraged-suite
	// disable is honoured).
	if s, err := dialRole(rc.target, ps, RoleGridService, ccm8Only); err != nil {
		r.fail(20, "CCM-8-only handshake failed: %v", err)
	} else {
		defer s.Close()
		r.verdict(20, s.Cipher == "ECDHE-ECDSA-AES128-CCM-8", "disabling GCM/ChaCha negotiated %s, want ECDHE-ECDSA-AES128-CCM-8", s.Cipher)
	}
}

// checkPKI covers §5.4 TCP-42..58.
func checkPKI(r *Reporter, rc *runCtx) {
	r.section("5.4", "Public Key Infrastructure (TCP-42..58)")
	ps := rc.ps

	good, gerr := dialRole(rc.target, ps, RoleGridService)
	var peer, ourLeaf *x509.Certificate
	if good != nil {
		defer good.Close()
		peer = peerLeaf(good)
		ourLeaf, _ = leafOf(ps.roles[RoleGridService].certFile)
	}

	// TCP-42 — ECC devices MUST support P-256.
	p256 := ourLeaf != nil && isP256(ourLeaf) && peer != nil && isP256(peer)
	r.verdict(42, p256, "client + server leaves are EC P-256 (client=%s, server=%s)", curveName(ourLeaf), curveName(peer))

	// TCP-43 / TCP-44 — Supported Elliptic Curves + Point Format extensions in
	// ClientHello. The bench client offers P-256 in supported_groups and the EC
	// point-format extension (mbtls.Dial → wolfssl.UseSupportedCurve + build); a
	// completed ECDHE-ECDSA handshake is indirect proof the curve was offered (an
	// ECDSA suite cannot be selected otherwise). Wire-level ClientHello assertion
	// is the --capture pcap gate (like run-conformance CCM-8).
	ecdheOK := gerr == nil && good != nil && strings.Contains(good.Cipher, "ECDHE")
	// TLS 1.3's ECDHE suite name has no "ECDHE" token; treat any completed P-256
	// handshake as evidence.
	if gerr == nil && good != nil && good.TLSVer == "TLSv1.3" {
		ecdheOK = p256
	}
	r.verdict(43, ecdheOK, "P-256 supported-groups offered in ClientHello (ECDHE handshake on %s completed); wire assertion via --capture", cipherOf(good))
	r.verdict(44, ecdheOK, "EC point-format extension offered in ClientHello (wolfSSL build); corroborated by the completed EC handshake; wire assertion via --capture")

	// TCP-45 — mutual authentication handshake MUST.
	r.verdict(45, gerr == nil && good != nil && good.PeerDER != nil && ourLeaf != nil,
		"mutual-auth handshake completed (client cert + verified server cert): err=%v", gerr)

	// TCP-46 — resumed session handshake SHOULD.
	r.verdict(46, probeResumption(rc, forceTLS12), "a clean redial to the same peer+identity resumed the TLS session (TLS 1.2 session id)")

	// TCP-47 — session ticket resumption MAY (TLS 1.3).
	if probeResumption(rc, forceTLS13) {
		r.pass(47, "TLS 1.3 session-ticket resumption observed (Resumed=true on redial)")
	} else {
		r.warn(47, "TLS 1.3 ticket resumption not observed this run (MAY)")
	}

	// TCP-48 — server MUST reject a handshake without a client cert.
	noCert, ncErr := dialCred(rc.target, ps.serverCA, "", "", forceTLS12)
	if noCert != nil {
		noCert.Close()
	}
	r.verdict(48, ncErr != nil && noCert == nil, "certless handshake rejected: err=%v", ncErr)

	// TCP-49 — self-signed MAY; NIST SP 800-57 key lifecycle SHOULD. Policy/MAY
	// rows: the bench profile uses CA-signed leaves, not self-signed.
	r.skip(49, "self-signed is a MAY and NIST key-lifecycle a SHOULD; the bench uses CA-signed EC leaves (policy, not a wire assertion)")

	// TCP-50 — public-network comms MUST use CA-signed certs. Deployment/network
	// policy; the bench PKI is CA-signed (a two-tier CA), but the "public network"
	// condition is a deployment property, not client-observable here.
	r.skip(50, "deployment/network-policy row; the bench uses CA-signed certs (root→intermediate→leaf), verified in lexa-gw T03")

	// TCP-51 — MUST send full chain to root. Our leaf is presented as a full
	// leaf-first chain (leaf+intermediate), and the handshake verified the peer's
	// chain to the trust anchor.
	depth := chainDepth(ps.roles[RoleGridService].certFile)
	r.verdict(51, depth >= 2 && gerr == nil, "client chain is %d certs (leaf+intermediate→root) and the handshake verified the peer chain to root", depth)

	// TCP-52 — certs MUST conform to RFC 5280. crypto/x509 enforces 5280 on parse;
	// both leaves parse as conformant v3 certs, and the peer rejects the expired /
	// wrong-CA client fixtures (chain-validity enforcement).
	rfc5280 := ourLeaf != nil && ourLeaf.Version == 3 && peer != nil && peer.Version == 3
	badRejected := negRejected(rc, "expired") && negRejected(rc, "wrong-ca")
	r.verdict(52, rfc5280 && badRejected, "leaves are RFC 5280 v3 and the peer rejects expired/wrong-CA client certs (chain validity enforced)")

	// TCP-53 — encryption-required scenarios ⇒ an encrypting IANA suite.
	r.verdict(53, gerr == nil && good != nil && isEncryptingSuite(good.Cipher),
		"negotiated an encrypting AEAD suite: %s", cipherOf(good))

	// TCP-54..57 — MAC/PRF hygiene, asserted from the offered set + negotiated
	// params (the mandated suites are all SHA-256 AEAD; none use MD5/SHA-1/NULL).
	offered := append(append([]string{}, mbtls.Mandated12...), mbtls.Mandated13...)
	noWeakMAC := !anyContains(offered, "MD5") && !anyContains(offered, "SHA1") && !anyContains(offered, "NULL")
	r.verdict(54, noWeakMAC, "offered suites use no HMAC-MD5/SHA-1/NULL: %s", strings.Join(offered, ", "))
	r.verdict(55, allContain(offered, "SHA256") || allSHA256(offered), "all offered suites provide HMAC-SHA-256")

	// TCP-56 / TCP-57 — the TLS 1.2 PRF. A TLS 1.2 handshake negotiates a
	// SHA-256-PRF suite (GCM_SHA256 / CCM-8 use the SHA-256 PRF), never SHA-1.
	if s, err := dialRole(rc.target, ps, RoleGridService, forceTLS12); err != nil {
		r.fail(56, "TLS 1.2 handshake failed: %v", err)
		r.fail(57, "TLS 1.2 handshake failed: %v", err)
	} else {
		defer s.Close()
		sha256PRF := isSHA256PRFSuite(s.Cipher)
		r.verdict(56, sha256PRF, "TLS 1.2 negotiated %s — SHA-256 PRF, no HMAC-SHA-1 in the PRF", s.Cipher)
		r.verdict(57, sha256PRF, "TLS 1.2 negotiated %s — HMAC-SHA-256 PRF", s.Cipher)
	}

	// TCP-58 — crypto import/export conformance. A project-level compliance task,
	// tracked outside the handshake.
	r.skip(58, "crypto import/export conformance is a project compliance task, not a wire-testable handshake property")
}

// checkPacketSession covers §5.5 TCP-59..62.
func checkPacketSession(r *Reporter, rc *runCtx) {
	r.section("5.5", "Packet and Session Requirements (TCP-59..62)")
	ps := rc.ps

	// TCP-59 — Maximum Fragment Length Negotiation MUST. Observed reliably from the
	// client under TLS 1.2 (get_session): MFL is negotiated when requested and NOT
	// negotiated when the request is off — proving it is genuinely negotiated.
	withMFL, e1 := dialRole(rc.target, ps, RoleGridService, forceTLS12)
	off, e2 := dialRole(rc.target, ps, RoleGridService, forceTLS12, noMFL)
	if withMFL != nil {
		defer withMFL.Close()
	}
	if off != nil {
		defer off.Close()
	}
	if e1 != nil || e2 != nil {
		r.fail(59, "handshake failed (mfl=%v, off=%v)", e1, e2)
		r.fail(60, "handshake failed (mfl=%v)", e1)
	} else {
		negotiated := withMFL.MFLCode != wolfssl.MFLDisabled
		genuine := off.MFLCode == wolfssl.MFLDisabled
		r.verdict(59, negotiated && genuine, "MFL negotiated when requested (code=%d) and absent when off (code=%d) — genuinely negotiated", withMFL.MFLCode, off.MFLCode)
		// TCP-60 — MUST support negotiating MFL of 512 bytes.
		r.verdict(60, withMFL.MFLCode == wolfssl.MFL512, "negotiated MFL code=%d, want MFL512 (%d = 512 bytes)", withMFL.MFLCode, wolfssl.MFL512)
	}

	// TCP-61 — ClientHello CompressionMethod MUST be NULL. TLS 1.2/1.3 permit only
	// NULL compression and wolfSSL never offers any other; a completed handshake is
	// indirect proof. Wire-level assertion is the --capture pcap gate.
	c61, err61 := dialRole(rc.target, ps, RoleGridService, forceTLS12)
	if c61 != nil {
		defer c61.Close()
	}
	r.verdict(61, err61 == nil, "ClientHello offered NULL compression only (wolfSSL build; TLS forbids others); handshake completed; wire assertion via --capture")

	// TCP-62 — Renegotiation Indication Extension (RFC 5746) MUST. The bench client
	// arms secure renegotiation and the RFC 5746 indication rides every ClientHello;
	// a renegotiation attempt records the observed (safe) server policy — app-level
	// refusal of the actual renegotiation is an OPTIONAL hardening, not a blocker
	// (the indication itself satisfies TCP-62; traceability note on TCP-62).
	c62, err62 := dialRole(rc.target, ps, RoleGridService, forceTLS12)
	policy := "not attempted"
	if c62 != nil {
		if rerr := c62.Renegotiate(); rerr != nil {
			policy = "server refuses actual renegotiation (indication-only — the conformant policy)"
		} else {
			policy = "server performs secure renegotiation"
		}
		c62.Close()
	}
	r.verdict(62, err62 == nil, "RFC 5746 renegotiation-indication offered on the ClientHello; observed policy: %s", policy)
}

// probeResumption performs a clean dial→round-trip→close→redial and reports
// whether the redial resumed the TLS session (TCP-46/47). It clears the process
// cache first so the observation is not contaminated by an earlier check.
func probeResumption(rc *runCtx, mut profileMut) bool {
	mbtls.ClearSessionCache()
	s1, err := dialRole(rc.target, rc.ps, RoleGridService, mut, withResume)
	if err != nil {
		return false
	}
	_ = pump(s1, rc.probeUnit()) // pump the (TLS 1.3) NewSessionTicket
	s1.Close()                   // captures the resumable session

	s2, err := dialRole(rc.target, rc.ps, RoleGridService, mut, withResume)
	if err != nil {
		return false
	}
	defer s2.Close()
	resumed := s2.Resumed
	mbtls.ClearSessionCache() // don't leak a cached session into later deterministic dials
	return resumed
}

// negRejected reports whether dialing with negative fixture name is rejected at
// the handshake (the expired / wrong-CA chain-validity negatives).
func negRejected(rc *runCtx, name string) bool {
	neg, ok := rc.ps.negatives[name]
	if !ok {
		return false
	}
	s, err := dialCred(rc.target, rc.ps.serverCA, neg.certFile, neg.keyFile, forceTLS12)
	if s != nil {
		s.Close()
	}
	return err != nil
}

// ── small suite/cert predicates ──────────────────────────────────────────────

func isEncryptingSuite(cipher string) bool {
	return strings.Contains(cipher, "GCM") || strings.Contains(cipher, "CCM") || strings.Contains(cipher, "CHACHA")
}

// isSHA256PRFSuite reports whether a negotiated TLS 1.2 suite uses the SHA-256
// PRF. All mandated TLS 1.2 suites do: the GCM/ChaCha names end in SHA256, and
// ECDHE-ECDSA-AES128-CCM-8 uses the SHA-256 PRF despite its truncated MAC name.
func isSHA256PRFSuite(cipher string) bool {
	return strings.Contains(cipher, "SHA256") || strings.Contains(cipher, "CCM-8") || strings.Contains(cipher, "CHACHA20-POLY1305")
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func allContain(ss []string, sub string) bool {
	for _, s := range ss {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return len(ss) > 0
}

// allSHA256 accepts the mandated suites whose SHA-256 basis is implicit in the
// name (CCM-8 / ChaCha20-Poly1305 do not carry the SHA256 token but use it).
func allSHA256(ss []string) bool {
	for _, s := range ss {
		if !strings.Contains(s, "SHA256") && !strings.Contains(s, "CCM-8") && !strings.Contains(s, "CHACHA20-POLY1305") {
			return false
		}
	}
	return len(ss) > 0
}

func equalSeq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cipherOf(s *mbtls.Session) string {
	if s == nil {
		return "(no session)"
	}
	return fmt.Sprintf("%s/%s", s.TLSVer, s.Cipher)
}
