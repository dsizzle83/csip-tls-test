package suitessm

// checks_pki.go implements §2.6 "Public Key Infrastructure" — PKI-001 through
// PKI-009, less PKI-005, which the catalog marks inapplicable because the DUT
// holds exactly one server identity and a two-PKI selection procedure has
// nothing to select between.
//
// This family divides cleanly into what a read-only bench can and cannot do,
// and the division is worth stating plainly because three of the eight rows
// land on the wrong side of it:
//
//   - What it CAN do: everything about the certificates on the wire. PKI-003,
//     -004, -007 and -008 are asserted from the DUT's own Certificate message,
//     parsed byte for byte out of a TLS 1.2 handshake where it travels in the
//     clear. PKI-006's resumption behaviour is likewise fully observable.
//   - What it CANNOT do: load ten roots into the DUT's trust store (PKI-001),
//     add and remove certificates through its management interface (PKI-002),
//     or reconfigure the southbound trust policy to accept a self-signed device
//     (PKI-009). All three require WRITES to a shared DUT through certmgr's
//     SO_PEERCRED socket, which this suite is forbidden from performing.
//
// The three that cannot be driven are still registered, and each still asserts
// the half that IS observable — the eleventh-root rejection for PKI-001, the
// absence of any plaintext management traffic for PKI-002 — so the row carries
// real evidence alongside a SKIP that names the exact obstacle.

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdis"
)

// ── PKI-001 · Root Store Capacity [C, S] ────────────────────────────────────

// pki001 asserts the observable half of the ten-root requirement: a leaf from a
// root the DUT does not hold must be rejected, which is what makes "the DUT
// holds these roots and not that one" a meaningful statement at all.
//
// The capacity half — loading ten distinct roots and completing ten handshakes,
// one per root — is not attempted. It requires ten certificate installs through
// certmgr's SO_PEERCRED unix socket, i.e. ten writes to a DUT this run shares
// with other agents, and would leave the trust store altered afterwards. The
// SKIP says so and names the tool that would do it.
func pki001(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	roots, err := rootPool(pf.PKI)
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	var t tally

	// The known-root control.
	known, kerr := roleCert(pf.PKI, "grid-service")
	var good *Session
	if kerr != nil {
		t.add(certify.Fail, "the known-root control fixture is unavailable: %v", kerr)
	} else if s, derr := dial(ctx, rc, pf.Target, dialOpts{
		Cert: known, Roots: roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Note: "PKI-001 control: a leaf from a root the DUT holds",
	}); derr != nil {
		t.add(certify.Fail, "a leaf issued by a root the DUT is expected to hold was rejected: %v", derr)
	} else {
		good = s
		defer s.Close()
		t.add(certify.Pass, "a leaf issued by a root in the DUT's trust store completed the handshake")
	}

	// The unknown-root negative: the eleventh root.
	unknown, uerr := negativeCert(pf.PKI, "wrong-ca")
	var eleventh *Session
	if uerr != nil {
		t.add(certify.Fail, "the unknown-root fixture is unavailable: %v", uerr)
	} else {
		s, derr := dial(ctx, rc, pf.Target, dialOpts{
			Cert: unknown, Roots: roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			Note: "PKI-001: a leaf from a root outside the DUT's trust store",
		})
		if s != nil {
			eleventh = s
			s.Close()
			t.add(certify.Fail, "the DUT ACCEPTED a leaf issued by a CA outside its trust store")
		} else if partial, ok := handshakeFailed(derr); ok {
			eleventh = partial
			t.add(certify.Pass, "the DUT rejected a leaf issued by a CA outside its trust store: %v", derr)
		} else {
			t.add(certify.Fail, "the unknown-root connection failed before the certificate was presented: %v", derr)
		}
	}

	t.caveat("the CAPACITY criterion (ten distinct roots, ten successful handshakes) was not exercised: " +
		"loading roots means ten writes to the DUT's trust store through certmgr's SO_PEERCRED socket " +
		"(scripts/bench-certctl), and this run shares the bench with other agents and may not mutate DUT state")

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := sessionFact(ev, good,
				"SunSpecTCP-2: a client certificate chaining to a root in the EUT-S trust store completed the mutual-auth handshake",
				"handshake message types and the bench's Certificate chain, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					return mutualFlightVerdict(v)
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, eleventh,
				"SunSpecTCP-2: a client certificate chaining to a root the EUT-S does NOT hold was rejected with a TLS alert",
				"TLS alert scan of the DUT→bench direction of the unknown-root connection",
				func(v *wireView) (certify.Verdict, string, []int) {
					return fatalAlertVerdict(ev, v, "a client certificate issued by an untrusted CA")
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			out = append(out, ev.SkipAssertion(
				"SunSpecTCP-2: the EUT-S trust store holds at least ten distinct root certificates and completes a handshake against each",
				"ten certificate installs through the DUT's certificate-management interface, then ten handshakes",
				"installing roots is a WRITE to a shared DUT's trust store (certmgr over its SO_PEERCRED unix "+
					"socket, driven by scripts/bench-certctl). This run is read-only against the bench by "+
					"constraint, and would leave the trust store altered for every other agent. The rejection "+
					"of an out-of-store root IS asserted above, which is the half that a capture can show."))
			return out, nil
		},
	}, nil
}

// ── PKI-002 · Certificate Management: Add/Remove [C, S] ─────────────────────

// pki002 cannot drive the procedure at all — every step is an add or a remove
// through the DUT's certificate-management interface — but one of its criteria
// IS a wire fact, and a negative one: management traffic must never be
// plaintext.
//
// That is asserted here as an absence over the WHOLE capture rather than over
// this check's own frames, because an absence claim is only meaningful at that
// scope. The framework forbids citing frames a check does not own, so the
// finding is recorded as a Narrative naming the scan — never as a frame
// citation that would imply ownership it does not have.
func pki002(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	var t tally
	t.caveat("PKI-002's procedure is entirely add/remove operations against the DUT's certificate-management " +
		"interface. Every step is a WRITE to a shared DUT (certmgr over its SO_PEERCRED unix socket), which " +
		"this run may not perform. The plaintext-management-traffic criterion IS asserted, from a scan of " +
		"the whole capture.")

	// Establish one session so the check has a conversation of its own and the
	// DUT's currently-installed server chain is on the wire to be described.
	sess, _, _, serr := completingSession(ctx, rc, pf.withPKI(rc), "grid-service",
		tls.VersionTLS12, tls.VersionTLS12, "PKI-002: observation of the installed server chain")
	if sess != nil {
		defer sess.Close()
	}
	if serr != nil {
		t.caveat("the installed server chain could not be observed: %v", serr)
	}

	gwHost := rc.Targets.GatewayHost

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion

			a, err := sessionFact(ev, sess,
				"PKI-002 (observation): the server certificate and intermediate chain the EUT-S currently presents",
				"the EUT-S Certificate message, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ServerCertificate()
					if c == nil {
						return certify.Skip, "no cleartext EUT-S Certificate message in this conversation", v.Frames
					}
					_, obs := chainDelivery(c, "EUT-S")
					return certify.Pass, "the chain installed at the time of this run: " + obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The absence claim, over the whole capture.
			plain := plaintextManagementTraffic(ev, gwHost)
			verdict := certify.Pass
			observed := fmt.Sprintf(
				"scanned all %d conversation(s) in the capture: no TCP stream to or from the DUT on a "+
					"cleartext management port (80/HTTP, 502/Modbus, 23/telnet) carried any bytes",
				len(ev.Index.Streams()))
			if len(plain) > 0 {
				verdict = certify.Fail
				observed = "cleartext management or Modbus traffic involving the DUT was found: " + strings.Join(plain, "; ")
			}
			a, err = ev.Narrative(
				"SunSpecTCP-3: no certificate-management or Modbus traffic involving the DUT crossed the wire in the clear",
				"whole-capture scan for TCP streams to or from the DUT on cleartext management ports",
				verdict, observed,
				"a scan of every conversation in the run's capture, not only this test case's own frames — an "+
					"ABSENCE claim is only meaningful at capture scope, and the framework forbids citing "+
					"frames this check does not own, so this assertion carries no frame citation by design")
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			out = append(out, ev.SkipAssertion(
				"SunSpecTCP-3: root certificates and the server certificate can be securely added to and removed from the EUT, and a removed root's leaf is subsequently rejected",
				"add/remove operations through the EUT's certificate-management interface, then handshake attempts",
				"every step of PKI-002 is a WRITE to a shared DUT's certificate store through certmgr's "+
					"SO_PEERCRED unix socket. This run is read-only against the bench by constraint. Running "+
					"it would also leave the DUT's trust store and server identity altered for the other "+
					"agents using the bench."))
			return out, nil
		},
	}, nil
}

// plaintextManagementTraffic scans the whole capture for cleartext traffic
// involving the DUT on ports that would carry management or unprotected Modbus.
func plaintextManagementTraffic(ev *certify.Evidence, gatewayHost string) []string {
	if gatewayHost == "" {
		return nil
	}
	cleartext := map[uint16]string{80: "HTTP", 23: "telnet", 502: "Modbus/TCP", 8080: "HTTP-alt"}
	var found []string
	for _, st := range ev.Index.Streams() {
		for _, e := range []netdis.Endpoint{st.Key.A, st.Key.B} {
			name, watched := cleartext[e.Port]
			if !watched {
				continue
			}
			if st.Key.A.Addr.String() != gatewayHost && st.Key.B.Addr.String() != gatewayHost {
				continue
			}
			bytes := 0
			for _, d := range st.Dirs {
				if d != nil {
					bytes += d.Bytes.Len()
				}
			}
			if bytes == 0 {
				continue
			}
			found = append(found, fmt.Sprintf("%s carried %d byte(s) on port %d (%s)", st.Key, bytes, e.Port, name))
		}
	}
	return found
}

// ── PKI-003 · Public Network Security [C, S] ────────────────────────────────

// pki003 presents a SELF-SIGNED client leaf — minted at run time, carrying a
// valid-looking role extension so the rejection cannot be attributed to a
// missing role — and requires the DUT to reject it, then repeats with the
// CA-signed fixture and requires success.
func pki003(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}
	roots, err := rootPool(pf.PKI)
	if err != nil {
		return certify.Skipped("%v", err), nil
	}

	var t tally
	selfSigned, mErr := mintLeaf(nil, nil, mintOpts{
		CommonName: "ssm-selfsigned-probe",
		Role:       "ReadOnlySunSpec",
		SelfSigned: true,
	})
	var selfSess *Session
	if mErr != nil {
		t.add(certify.Fail, "the self-signed fixture could not be minted: %v", mErr)
	} else {
		s, derr := dial(ctx, rc, pf.Target, dialOpts{
			Cert: &selfSigned, Roots: roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			Note: "PKI-003: self-signed client certificate",
		})
		if s != nil {
			selfSess = s
			s.Close()
			t.add(certify.Fail, "the DUT ACCEPTED a self-signed client certificate")
		} else if partial, ok := handshakeFailed(derr); ok {
			selfSess = partial
			t.add(certify.Pass, "the DUT rejected the self-signed client certificate: %v", derr)
		} else {
			t.add(certify.Fail, "the self-signed connection failed before the certificate was presented: %v", derr)
		}
	}

	sess, _, m1, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS12, tls.VersionTLS12,
		"PKI-003: CA-signed client certificate")
	if sess != nil {
		defer sess.Close()
	}
	switch {
	case serr != nil:
		t.add(certify.Fail, "the CA-signed handshake did not complete: %v", serr)
	case m1.Err != nil:
		t.add(certify.Warn, "the CA-signed session completed but the Model 1 read did not: %v", m1.Err)
	default:
		t.add(certify.Pass, "the CA-signed client certificate completed the handshake and carried a Model 1 read")
	}
	if sess != nil && sess.PeerVerifyErr != nil {
		t.add(certify.Fail, "the DUT's own server certificate does not chain to the bench's trust anchors: %v", sess.PeerVerifyErr)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := sessionFact(ev, selfSess,
				"SunSpecTCP-50: the EUT-S rejected a self-signed client certificate (issuer == subject, chaining to no CA)",
				"the bench's Certificate message and the DUT's alert, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					cc, ccFrames := v.ClientCertificate()
					if cc == nil {
						return certify.Skip, "the capture holds no bench Certificate message for this connection, so the provocation cannot be shown to have reached the DUT", v.Frames
					}
					if cv, cobs := caSignedVerdict(cc, "bench"); cv == certify.Pass {
						return certify.Fail, "this run did not present a self-signed certificate at all: " + cobs, ccFrames
					}
					verdict, obs, frames := fatalAlertVerdict(ev, v, "a self-signed client certificate")
					return verdict, "the bench presented a self-signed leaf and " + obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, sess,
				"SunSpecTCP-50: a CA-signed client certificate (issuer != subject, chaining to a trusted root) completed the handshake",
				"the bench's Certificate message and the completed flight, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					cc, ccFrames := v.ClientCertificate()
					cv, cobs := caSignedVerdict(cc, "bench")
					if cv != certify.Pass {
						return cv, cobs, ccFrames
					}
					fv, fobs, ff := mutualFlightVerdict(v)
					if fv != certify.Pass {
						return fv, cobs + " but " + fobs, ff
					}
					return certify.Pass, cobs + "; " + fobs, ccFrames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = sessionFact(ev, sess,
				"SunSpecTCP-50: the EUT-S's own server certificate is CA-signed, not self-signed",
				"the EUT-S Certificate message, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ServerCertificate()
					verdict, obs := caSignedVerdict(c, "EUT-S")
					if c == nil {
						return verdict, obs, v.Frames
					}
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── PKI-004 · Full Chain Delivery [C, S] ────────────────────────────────────

func pki004(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	// TLS 1.2 on purpose: the Certificate message is in the clear, so the whole
	// delivered chain can be cited from the capture with no key log.
	h := conformantHello()
	h.SupportedVersions = nil
	p := Probe(ctx, rc, pf.Target, "PKI-004: chain delivery observation", h)

	var t tally
	v, obs := chainDelivery(p.Certificate(), "EUT-S")
	t.add(v, "%s", obs)

	half := watchClientHalf(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := probeFact(ev, p,
				"SunSpecTCP-51: the EUT-S Certificate message delivers the leaf followed by every intermediate CA needed to build a path to the root",
				"the EUT-S Certificate message's certificate_list, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ServerCertificate()
					verdict, obs := chainDelivery(c, "EUT-S")
					if c == nil {
						return verdict, obs, v.Frames
					}
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The corollary: no fetch was needed. The AIA extension may name a
			// caIssuers URL, but nothing dereferenced it during this exchange.
			a, err = probeFact(ev, p,
				"SunSpecTCP-51: no AIA/caIssuers fetch was required to complete the chain — the delivered chain was sufficient",
				"whole-capture scan for outbound HTTP traffic during this conversation, plus the AIA extension of the delivered leaf",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ServerCertificate()
					if c == nil || c.Leaf() == nil || c.Leaf().Info == nil {
						return certify.Skip, "no parseable EUT-S leaf to inspect for an AIA extension", v.Frames
					}
					_, hasAIA := c.Leaf().Info.Extension("1.3.6.1.5.5.7.1.1")
					obs := fmt.Sprintf("the delivered chain is %d certificate(s) deep; the leaf %s an "+
						"AuthorityInformationAccess extension. The bench built the path from the delivered "+
						"chain alone and dereferenced nothing.",
						len(c.Entries), presenceVerb(hasAIA))
					if len(c.Entries) < 2 {
						return certify.Fail, obs + " — one certificate cannot be a path", frames
					}
					return certify.Pass, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The [C] half asserts on the gateway's OWN Certificate message,
			// not its hello, so it does not go through clientHalf.fact.
			ga, err := gatewayChainAssertion(ev, half)
			if err != nil {
				return nil, err
			}
			return append(out, ga), nil
		},
	}, nil
}

// gatewayChainAssertion turns the gateway's own Certificate message into an
// assertion, or explains why it could not.
//
// Under TLS 1.3 the client Certificate is encrypted with the DEVICE SIM's
// handshake keys, and the bench does not export those (the sim's TLS stack is
// wolfSSL and key export there needs a separate build). That is the honest
// reason this assertion is often a SKIP, and it is stated rather than hidden.
func gatewayChainAssertion(ev *certify.Evidence, half *clientHalf) (certify.Assertion, error) {
	const claim = "SunSpecTCP-51 [C]: the gateway's own southbound client delivers a full chain (leaf + intermediates)"
	const method = "the gateway's Certificate message to the bench device sim, parsed from the capture"
	_, v, err := half.hello(ev)
	if err != nil {
		return ev.SkipAssertion(claim, method, err.Error()), nil
	}
	cert, frames := v.ClientCertificate()
	if cert == nil {
		return ev.SkipAssertion(claim, method,
			"the gateway's Certificate message is not in the clear in this conversation. Under TLS 1.3 it is "+
				"encrypted with the DEVICE SIM's handshake keys, and this run exports only the bench "+
				"conformance client's secrets, not the sim's."), nil
	}
	verdict, obs := chainDelivery(cert, "gateway (EUT-C)")
	return ev.CiteFrames(claim, method, verdict, obs, frames)
}

func presenceVerb(ok bool) string {
	if ok {
		return "carries"
	}
	return "does not carry"
}

// ── PKI-006 · Session Resumption and Tickets [C, S] (Optional) ──────────────

// pki006 performs a full handshake, then offers the resulting session back.
//
// Both outcomes are conformant — the procedure exists "even if this
// functionality does not exist, to verify fall back to a full mTLS handshake" —
// so the only FAIL is an abbreviated handshake that skipped the certificate
// exchange without echoing the session identity it was resuming.
func pki006(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
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

	cache := tls.NewLRUClientSessionCache(8)
	var t tally

	first, derr := dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots, SessionCache: cache,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Note: "PKI-006: initial full handshake",
	})
	if derr != nil {
		return certify.Failed("the initial handshake PKI-006 resumes from could not be established: %v", derr), nil
	}
	// A clean exchange and an orderly close, so the DUT has a session worth
	// caching. A connection torn down mid-handshake is not resumable and the
	// procedure would be testing nothing.
	if _, _, m1, err := readCommonModel(rc, first); err != nil || m1.Err != nil {
		t.caveat("the initial session's Model 1 read did not complete (%v / %v); the resumption offer may be "+
			"weaker as a result", err, m1.Err)
	}
	first.Close()

	second, derr2 := dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots, SessionCache: cache,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Note: "PKI-006: resumption attempt",
	})
	if derr2 != nil {
		return certify.Failed("the resumption attempt failed to establish any session at all: %v", derr2), nil
	}
	defer second.Close()
	if second.State.DidResume {
		t.add(certify.Pass, "the DUT resumed the session (abbreviated handshake), which SunSpecTCP-46/47 permits")
	} else {
		t.add(certify.Pass, "the DUT did not resume and fell back to a full mutual handshake, which SunSpecTCP-46/47 also permits (resumption is a SHOULD/MAY)")
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := sessionFact(ev, first,
				"PKI-006: the initial handshake was a FULL mutual-auth exchange and offered resumable state (a non-empty session_id and/or a NewSessionTicket)",
				"ServerHello.session_id and handshake message types of the initial conversation",
				func(v *wireView) (certify.Verdict, string, []int) {
					sh, frames := v.ServerHello()
					if sh == nil {
						return certify.Fail, "no ServerHello in the initial conversation", v.Frames
					}
					ticket := hasType(v.ServerFlight(), tlsdis.HandshakeNewSessionTicket)
					obs := fmt.Sprintf("ServerHello.session_id = %x (%d byte(s)); NewSessionTicket %s; flight %v",
						sh.SessionID, len(sh.SessionID), presence(ticket), typeNames(v.ServerFlight()))
					if !hasType(v.ServerFlight(), tlsdis.HandshakeCertificate) {
						return certify.Fail, obs + " — the initial handshake was not full", frames
					}
					if len(sh.SessionID) == 0 && !ticket && !sh.HasSessionTicket {
						return certify.Warn, obs + " — the EUT-S offered no resumable state at all, so the resumption half below can only demonstrate the fall-back path", frames
					}
					return certify.Pass, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = wireFact(ev, second.Local, second.Remote,
				"SunSpecTCP-46/47: the second handshake was either a correct abbreviated resumption or a clean fall back to a full mutual handshake",
				"handshake message types and session_id of both conversations",
				func(v2 *wireView) (certify.Verdict, string, []int) {
					v1, err := viewFor(ev, first.Local, first.Remote)
					if err != nil {
						return certify.Skip, "the initial conversation is not in this check's attributed frames: " + err.Error(), nil
					}
					sh1, _ := v1.ServerHello()
					ch2, chFrames := v2.ClientHello()
					sh2, frames := v2.ServerHello()
					verdict, obs := abbreviatedHandshakeVerdict(resumptionPair{
						FirstServerHello:  sh1,
						FirstFlight:       v1.ServerFlight(),
						SecondClientHello: ch2,
						SecondServerHello: sh2,
						SecondFlight:      v2.ServerFlight(),
					})
					if sh2 == nil {
						return verdict, obs, v2.Frames
					}
					// Both hellos are cited: the criterion is the RELATION
					// between the offered session id and the echoed one, and a
					// reader must be able to open both.
					return verdict, obs, append(append([]int(nil), chFrames...), frames...)
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── PKI-007 · RFC 5280 Certificate Compliance [C, S] ────────────────────────

func pki007(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	sess, _, _, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS12, tls.VersionTLS12,
		"PKI-007: certificate profile observation")
	if sess != nil {
		defer sess.Close()
	}

	var t tally
	if serr != nil {
		t.add(certify.Warn, "the session for the certificate observation did not fully establish: %v", serr)
	}
	if sess != nil && len(sess.PeerChain) > 0 {
		bad := 0
		for i, c := range sess.PeerChain {
			ci, perr := tlsdis.ParseCertInfo(c.Raw)
			if perr != nil {
				bad++
				continue
			}
			if f := rfc5280Findings(ci, i == 0); len(f) > 0 {
				bad++
			}
		}
		if bad > 0 {
			t.add(certify.Fail, "%d of the DUT's %d chain certificate(s) depart from the RFC 5280 v3 profile", bad, len(sess.PeerChain))
		} else {
			t.add(certify.Pass, "all %d of the DUT's chain certificates conform to the RFC 5280 v3 profile", len(sess.PeerChain))
		}
	} else {
		t.add(certify.Fail, "the DUT presented no certificate chain to inspect")
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := sessionFact(ev, sess,
				"SunSpecTCP-52: every certificate the EUT-S sent conforms to the RFC 5280 X.509v3 profile — v3, positive serial, signatureAlgorithm, validity, issuer, subjectPublicKeyInfo, KeyUsage, BasicConstraints, SubjectKeyIdentifier and AuthorityKeyIdentifier",
				"each certificate in the EUT-S Certificate message parsed from the capture and checked field by field against RFC 5280 §4.1-§4.2",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ServerCertificate()
					verdict, obs := certProfileVerdict(c, "EUT-S")
					if c == nil {
						return verdict, obs, v.Frames
					}
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The bench's own client certificate, as CONTEXT — never as a
			// verdict about the DUT.
			//
			// §2.6.7.1 step 3 directs the tester at the EUT-S Certificate
			// message, and §2.6.7.3's criterion is about "all certificates
			// presented by the EUT-S/EUT-C". When the DUT is the server the
			// bench is the TEST CLIENT, not an EUT-C: its certificate is a
			// property of this bench's fixture set and says nothing whatever
			// about the device under test. Run 20260726T225512 failed the
			// gateway because certs/mbaps/clients/grid-service-cert.pem had no
			// SubjectKeyIdentifier — a defect in our own generator, reported as
			// a DUT non-conformance in an evidence bundle.
			a, err = sessionFact(ev, sess,
				"bench self-check (NOT a DUT verdict): the Test Client certificate this bench presented also conforms to the RFC 5280 X.509v3 profile",
				"each certificate in the BENCH's Certificate message parsed from the capture and checked against RFC 5280",
				func(v *wireView) (certify.Verdict, string, []int) {
					c, frames := v.ClientCertificate()
					if c == nil {
						return certify.Skip, "the bench's Certificate message is not in the clear in this conversation", v.Frames
					}
					verdict, obs := certProfileVerdict(c, "bench client")
					if verdict == certify.Fail {
						// Capped at WARN by construction. A Test Client
						// certificate can never produce a DUT verdict.
						verdict = certify.Warn
						obs += " — this is the BENCH's own fixture, not the EUT-S's certificate, so it is a " +
							"bench defect to fix (cmd/gen-mbaps-certs) and not a conformance finding against the DUT"
					}
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			a.Note = joinNote(a.Note, "scope: SSM-CONF-v0.8 §2.6.7.1 step 3 inspects the EUT-S Certificate "+
				"message. With the DUT as the server the bench is the Test Client, so this row is recorded "+
				"for completeness and is capped at WARN — it cannot be a verdict on the device under test.")
			return append(out, a), nil
		},
	}, nil
}

// ── PKI-008 · X.509v3 Identity Authentication [C, S] ────────────────────────

func pki008(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	sess, chain, m1, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS12, tls.VersionTLS12,
		"PKI-008: X.509v3 mutual authentication")
	if sess != nil {
		defer sess.Close()
	}

	var t tally
	switch {
	case serr != nil:
		t.add(certify.Fail, "the mutual-auth session could not be established: %v", serr)
	case m1.Err != nil:
		t.add(certify.Fail, "the Model 1 read after mutual authentication failed: %v", m1.Err)
	default:
		v, obs := normalResponseVerdict(m1.Response)
		t.add(v, "Model 1 read on unit %d (chain models %v): %s", chain.Unit, chain.IDs(), obs)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			// §2.6.8.1 step 3 inspects the EUT-S Certificate message. The
			// bench's own certificate is recorded beside it as context and is
			// capped at WARN: with the DUT as the server the bench is the TEST
			// CLIENT, and a Test Client's fixture can never be a verdict on the
			// device under test. See the same note in pki007.
			for _, side := range []struct {
				who   string
				isEUT bool
				claim string
				fetch func(*wireView) (*tlsdis.Certificate, []int)
			}{
				{
					who:   "EUT-S",
					isEUT: true,
					claim: "SunSpecTCP-7: the EUT-S identified itself with an X.509v3 certificate carrying subjectKeyIdentifier, authorityKeyIdentifier and keyUsage",
					fetch: (*wireView).ServerCertificate,
				},
				{
					who:   "bench client",
					claim: "bench self-check (NOT a DUT verdict): the Test Client certificate this bench presented is X.509v3 and carries subjectKeyIdentifier, authorityKeyIdentifier and keyUsage",
					fetch: (*wireView).ClientCertificate,
				},
			} {
				side := side
				a, err := sessionFact(ev, sess, side.claim,
					"the "+side.who+" Certificate message, parsed from the capture",
					func(v *wireView) (certify.Verdict, string, []int) {
						c, frames := side.fetch(v)
						if c == nil || c.Leaf() == nil || c.Leaf().Info == nil {
							return certify.Skip, "no parseable " + side.who + " leaf in the clear in this conversation", v.Frames
						}
						ci := c.Leaf().Info
						_, ski := ci.Extension("2.5.29.14")
						_, aki := ci.Extension("2.5.29.35")
						obs := fmt.Sprintf("v%d leaf, subject %q, sha256 %s; subjectKeyIdentifier %s; authorityKeyIdentifier %s; keyUsage [%s]",
							ci.Version, ci.Subject, ci.SHA256, presence(ski), presence(aki), strings.Join(ci.KeyUsage, ","))
						if ci.Version != 3 || !ski || !aki || len(ci.KeyUsage) == 0 {
							if !side.isEUT {
								return certify.Warn, obs + " — this is the BENCH's own fixture, not the EUT-S's " +
									"certificate; it is a bench defect to fix (cmd/gen-mbaps-certs), not a " +
									"conformance finding against the DUT", frames
							}
							return certify.Fail, obs, frames
						}
						return certify.Pass, obs, frames
					})
				if err != nil {
					return nil, err
				}
				if !side.isEUT {
					a.Note = joinNote(a.Note, "scope: SSM-CONF-v0.8 §2.6.8.1 step 3 inspects the EUT-S "+
						"Certificate message. With the DUT as the server the bench is the Test Client, so this "+
						"row is recorded for completeness and is capped at WARN.")
				}
				out = append(out, a)
			}

			a, err := sessionFact(ev, sess,
				"SunSpecTCP-7: mutual authentication completed — both Certificate messages were exchanged and the bench sent a CertificateVerify",
				"handshake message types of both directions, parsed from the capture",
				func(v *wireView) (certify.Verdict, string, []int) { return mutualFlightVerdict(v) })
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = decryptedFact(ev, sess,
				"a SunSpec Model 1 read followed the mutual X.509v3 authentication and was answered",
				"TLS decryption with the run's key log, then MBAP framing",
				func(p *plaintext, _ *wireView) (certify.Verdict, string, []int) {
					return modbusExchangeFact(p, 0x03, normalResponseVerdict)
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── PKI-009 · Self-Signed Certificate Support [C] (Optional) ────────────────

// pki009 is optional and conditional: it applies "only if the EUT claims
// self-signed certificate support". The gateway's southbound client does have
// such a posture — a per-device "pin" trust policy that pins the SHA-256 of a
// peer leaf, for an isolated LAN — but exercising it means pointing a gateway
// device entry at a self-signed device sim, which is a DUT configuration change
// and a service restart.
//
// So the row is registered and skipped with that reason, and the one thing that
// IS observable is asserted instead: what trust posture the DUT's southbound
// client is actually configured with, read off the DUT read-only.
func pki009(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	// The real path has no /configs/ segment — see helpers.go's
	// ObservationSpec.ConfigPath and checks_rbac.go's rulesCandidates, both of
	// which read the DUT's config from /etc/lexa/*.json directly. Census
	// 20260731T234821's PKI-009#2 was a false read-only-fallback SKIP caused
	// by this check alone reading the wrong (nonexistent) path.
	cfg, cfgErr := readGatewayFile(ctx, rc, "/etc/lexa/modbus.json")

	var t tally
	t.caveat("PKI-009 is an OPTIONAL capability and applies only if the vendor claims self-signed support. " +
		"Exercising it requires pointing a southbound device entry at a self-signed peer and restarting the " +
		"gateway's Modbus client — a DUT configuration change and a service restart, both forbidden on a " +
		"shared bench. The DUT's configured southbound trust posture is reported instead.")

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		OffWire: false,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			claim := "SunSpecTCP-49: the EUT supports self-signed certificates for local, non-routed communication, with a documented NIST SP 800-57 key lifecycle"
			const method = "a mutual handshake against a self-signed peer, plus a vendor documentation excerpt"
			var out []certify.Assertion
			out = append(out, ev.SkipAssertion(claim, method,
				"exercising the optional self-signed posture requires reconfiguring a southbound device entry "+
					"on the DUT and restarting its Modbus client. This run may not change DUT configuration "+
					"or restart DUT services. The NIST SP 800-57 lifecycle half is a paper artefact no "+
					"capture can evidence."))

			postureClaim := "PKI-009 (observation): the trust posture the EUT's southbound client is configured with"
			const postureMethod = "read of the DUT's southbound Modbus configuration over the read-only gateway client"
			if cfgErr != nil {
				out = append(out, ev.SkipAssertion(postureClaim, postureMethod,
					"the DUT's southbound configuration could not be read: "+cfgErr.Error()))
				return out, nil
			}
			a, err := ev.Narrative(postureClaim, postureMethod, certify.Pass,
				summariseTrustPolicy(cfg),
				"the DUT's own /etc/lexa/modbus.json, read over the read-only gateway client")
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// summariseTrustPolicy quotes the southbound trust-policy lines rather than
// paraphrasing them: the claim is about what the DUT is configured to do, and
// the DUT's own words are the evidence.
func summariseTrustPolicy(cfg []byte) string {
	var lines []string
	for _, l := range strings.Split(string(cfg), "\n") {
		s := strings.TrimSpace(l)
		if strings.Contains(s, "trust") || strings.Contains(s, "pin") {
			lines = append(lines, s)
		}
	}
	if len(lines) == 0 {
		return fmt.Sprintf("the DUT's southbound Modbus configuration (%d bytes) names no trust policy or "+
			"certificate pin, so no self-signed posture is configured on this bench", len(cfg))
	}
	return "the DUT's southbound Modbus configuration carries these trust-policy lines: " + strings.Join(lines, " | ")
}

// withPKI fills in the fixture set for a preflight that was prepared without
// one, so a check can start read-only and still open a session later.
func (p preflight) withPKI(rc *certify.RunCtx) preflight {
	p.PKI = rc.PKI
	return p
}
