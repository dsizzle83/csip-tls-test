package suitessm

// checks_prot.go implements §2.7 "Protocol" — PROT-001 through PROT-004.
//
// PROT-001 is the only procedure in the whole document whose evidence lives
// INSIDE the tunnel: the seven-byte MBAP header, recovered by decrypting the
// capture with the run's key log. The other three are extension-level facts
// that TLS carries in the clear.
//
// Two of the four carry a limitation this bench is explicit about:
//
//	PROT-002  the max_fragment_length ECHO is asserted from the ServerHello.
//	          The follow-on criterion — that a >512-byte Modbus response is
//	          then split into records of at most 512 plaintext bytes — needs a
//	          TLS client that implements RFC 6066, and Go's crypto/tls does
//	          not. That sub-criterion is a SKIP naming the reason.
//	PROT-004  the renegotiation INDICATION is asserted from the wire, in the
//	          form each role is allowed to use: RFC 5746 §3.6 gives the server
//	          exactly one (the empty renegotiation_info extension in the
//	          ServerHello), while §3.4 lets the CLIENT choose between that
//	          extension and TLS_EMPTY_RENEGOTIATION_INFO_SCSV. Both client forms
//	          pass; only their joint absence fails. The follow-on criterion — a
//	          second handshake inside the session whose extension carries the
//	          previous Finished verify_data — needs a client that can INITIATE
//	          renegotiation, which Go's crypto/tls cannot (it only accepts
//	          server-initiated renegotiation). SKIP, with the reason and with
//	          the DUT's own documented refusal policy.

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// ── PROT-001 · MBAP Integrity ───────────────────────────────────────────────

// prot001 proves that wrapping Modbus in TLS does not change Modbus: the MBAP
// header inside the tunnel is the standard seven bytes with Protocol ID 0x0000,
// a Length consistent with the PDU, and an unmodified PDU behind it.
//
// The whole point is that the assertion is made from DECRYPTED CAPTURE BYTES,
// not from the buffer this check wrote. The check obviously knows what it sent
// — it sent it — and an assertion built on that knowledge would evidence
// nothing about what crossed the wire.
func prot001(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, true)
	if skip != nil {
		return *skip, nil
	}

	sess, chain, m1, serr := completingSession(ctx, rc, pf, "grid-service", tls.VersionTLS12, tls.VersionTLS12,
		"PROT-001: MBAP integrity inside the tunnel")
	if sess != nil {
		defer sess.Close()
	}

	var t tally
	switch {
	case serr != nil:
		t.add(certify.Fail, "the session carrying the MBAP exchange could not be established: %v", serr)
	case m1.Err != nil:
		t.add(certify.Fail, "the Model 1 read inside the tunnel failed: %v", m1.Err)
	default:
		v, obs := mbapIntegrityVerdict(m1.Request, m1.Response)
		t.add(v, "unit %d, chain models %v: %s", chain.Unit, chain.IDs(), obs)
	}
	if rc.Capture.KeyLogPath == "" {
		t.caveat("no TLS key log was exported for this run (-keylog), so the MBAP evidence below is not " +
			"recoverable by a reader of the bundle and is reported as SKIP rather than PASS")
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := decryptedFact(ev, sess,
				"SunSpecTCP-9: inside the secure transport the Modbus ADU is unchanged — a 7-byte MBAP header (Transaction ID, Protocol ID 0x0000, Length, Unit ID) followed by the unmodified PDU",
				"TLS decryption of this session's records with the run's key log, then field-by-field decoding of the recovered MBAP frames",
				func(p *plaintext, _ *wireView) (certify.Verdict, string, []int) {
					req, _, okReq := findADU(p.FromClient, p.ClientRecords, func(fc byte) bool { return fc == 0x03 })
					rsp, frames, okRsp := findADU(p.FromServer, p.ServerRecords, func(fc byte) bool { return fc == 0x03 || fc == 0x83 })
					if !okReq || !okRsp {
						return certify.Fail, fmt.Sprintf(
							"the recovered plaintext does not contain a matched FC 0x03 request/response pair "+
								"(%d bench→DUT byte(s), %d DUT→bench byte(s))", len(p.FromClient), len(p.FromServer)), nil
					}
					verdict, obs := mbapIntegrityVerdict(req, rsp)
					return verdict, obs, frames
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The transport-level corollary: the exchange really was inside
			// TLS records, not alongside them.
			a, err = sessionFact(ev, sess,
				"SunSpecTCP-9: the Modbus exchange was carried entirely inside TLS application_data records — no Modbus byte appeared on the wire in the clear",
				"record-type scan of both directions of this session's conversation",
				func(v *wireView) (certify.Verdict, string, []int) {
					clear, obs := cleartextModbus(v)
					if clear {
						return certify.Fail, obs, v.Frames
					}
					return certify.Pass, obs, v.Frames
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// cleartextModbus reports whether anything outside the TLS record framing
// appears in a conversation, which would mean Modbus escaped the tunnel.
func cleartextModbus(v *wireView) (bool, string) {
	desc := func(name string, d *tlsdis.Direction) string {
		if d == nil || d.Stream == nil {
			return name + ": nothing parsed"
		}
		return fmt.Sprintf("%s: %d record(s), %d application_data, %d trailing byte(s) outside record framing",
			name, len(d.Stream.Records), len(d.AppData), d.Stream.Trailing)
	}
	obs := desc("bench→DUT", v.Client) + "; " + desc("DUT→bench", v.Server)
	bad := (v.Client != nil && v.Client.Stream != nil && v.Client.Stream.Trailing > 0 && v.Client.Stream.Need == 0) ||
		(v.Server != nil && v.Server.Stream != nil && v.Server.Stream.Trailing > 0 && v.Server.Stream.Need == 0)
	if bad {
		return true, obs + " — bytes outside the TLS record framing were found"
	}
	if v.Client == nil || v.Server == nil || len(v.Client.AppData) == 0 || len(v.Server.AppData) == 0 {
		return true, obs + " — one direction carries no application_data at all, so no exchange took place inside the tunnel"
	}
	return false, obs + " — every byte of the exchange is inside TLS record framing"
}

// ── PROT-002 · Fragment Length Negotiation ──────────────────────────────────

func prot002(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	code := mflCode512
	h := conformantHello()
	h.SupportedVersions = nil
	h.MaxFragmentLength = &code
	withMFL := Probe(ctx, rc, pf.Target, "PROT-002: max_fragment_length code 1 (512 bytes)", h)

	// The control: the same hello WITHOUT the extension. Without it, an echo
	// could be an unconditional habit rather than a negotiation.
	h2 := conformantHello()
	h2.SupportedVersions = nil
	without := Probe(ctx, rc, pf.Target, "PROT-002 control: no max_fragment_length offered", h2)

	var t tally
	v, obs := mflEchoVerdict(withMFL.ServerHello(), code)
	t.add(v, "%s", obs)
	if sh := without.ServerHello(); sh == nil {
		t.add(certify.Warn, "the control probe produced no ServerHello: %s", without.Summary())
	} else if sh.MaxFragmentLength != nil {
		t.add(certify.Fail, "the control ServerHello echoed max_fragment_length code %d although the ClientHello offered none, so the extension is not negotiated", *sh.MaxFragmentLength)
	} else {
		t.add(certify.Pass, "the control ServerHello carries no max_fragment_length, so the echo above is a genuine negotiation")
	}
	t.caveat("the fragment-SIZE criterion (a >512-byte Modbus response split into records of at most 512 " +
		"plaintext bytes) was not exercised: Go's crypto/tls, this bench's TLS stack, does not implement " +
		"RFC 6066 max_fragment_length, so it cannot establish a session under the negotiated limit. The " +
		"negotiation itself is asserted from the ServerHello.")

	// PROT-002#4 (census 20260731T234821): see watchClientHalfForced's doc
	// in helpers.go for why a plain wait almost never catches this suite's
	// own southbound ClientHello by the time PROT-002 runs.
	half := watchClientHalfForced(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := serverHelloFact(ev, withMFL,
				"SunSpecTCP-59/60: offered the RFC 6066 max_fragment_length extension with code 1 (512 bytes), the EUT-S echoed it in its ServerHello",
				"ServerHello extension 0x0001, parsed from the capture",
				func(sh *tlsdis.ServerHello) (certify.Verdict, string) { return mflEchoVerdict(sh, code) })
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = serverHelloFact(ev, without,
				"SunSpecTCP-59: the extension is genuinely NEGOTIATED — with no max_fragment_length in the ClientHello, the EUT-S echoes none",
				"ServerHello extension list of the control conversation, parsed from the capture",
				func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
					if sh == nil {
						return certify.Skip, "the control conversation produced no ServerHello"
					}
					obs := fmt.Sprintf("control ServerHello extensions: [%s]", strings.Join(tlsdis.ExtensionNames(sh.Extensions), ", "))
					if sh.MaxFragmentLength != nil {
						return certify.Fail, obs + fmt.Sprintf(" — max_fragment_length code %d is present although none was requested", *sh.MaxFragmentLength)
					}
					return certify.Pass, obs + " — no max_fragment_length, as expected when none is requested"
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			out = append(out, ev.SkipAssertion(
				"SunSpecTCP-59/60: with a 512-byte fragment length negotiated, every TLS record of a >512-byte Modbus response carries at most 512 plaintext bytes",
				"record-length measurement of a multi-register read inside a session with MFL 512 negotiated",
				"this bench's TLS stack (Go crypto/tls) does not implement RFC 6066 max_fragment_length, so it "+
					"cannot ESTABLISH a session under the negotiated limit — only offer the extension and "+
					"observe the echo, which is asserted above. Measuring the resulting record sizes needs a "+
					"client that honours the limit it negotiated."))

			a, err = half.fact(ev,
				"SunSpecTCP-59 [C]: the gateway's own southbound ClientHello carries the max_fragment_length extension",
				"ClientHello extension 0x0001 of the gateway's hello to the bench device sim",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					obs := fmt.Sprintf("gateway ClientHello extensions: [%s]", strings.Join(tlsdis.ExtensionNames(ch.Extensions), ", "))
					if ch.MaxFragmentLength == nil {
						return certify.Fail, obs + " — no max_fragment_length extension"
					}
					n, known := tlsdis.MaxFragmentLengthBytes(*ch.MaxFragmentLength)
					return certify.Pass, obs + fmt.Sprintf(" — max_fragment_length code %d (%s)",
						*ch.MaxFragmentLength, fragmentBytesText(n, known))
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}

// ── PROT-003 · TLS Compression Method [C] ───────────────────────────────────

// prot003 is a client-only procedure: its criterion is that the EUT-C's
// ClientHello offers NULL compression and nothing else.
//
// The DUT's northbound server is asserted alongside it as a corollary, because
// a server that ACCEPTED a compression method other than NULL would be a
// finding worth reporting even though this procedure does not ask for it.
func prot003(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	// The server corollary: offer DEFLATE alongside NULL and require that NULL
	// is what comes back.
	h := conformantHello()
	h.SupportedVersions = nil
	h.Compression = []uint8{1, 0} // DEFLATE first, then NULL
	p := Probe(ctx, rc, pf.Target, "PROT-003 corollary: DEFLATE offered ahead of NULL", h)

	var t tally
	if sh := p.ServerHello(); sh == nil {
		t.add(certify.Warn, "the DUT sent no ServerHello when DEFLATE was offered ahead of NULL: %s", p.Summary())
	} else if sh.CompressionMethod != 0 {
		t.add(certify.Fail, "the DUT selected compression method 0x%02X (%s) — TLS compression enables the CRIME attack",
			sh.CompressionMethod, tlsdis.CompressionMethodName(sh.CompressionMethod))
	} else {
		t.add(certify.Pass, "with DEFLATE offered first, the DUT still selected NULL compression")
	}

	half := watchClientHalf(ctx, rc)
	if !half.Armed {
		t.caveat("the [C] half — the procedure's actual criterion — was not observed: %s", half.Why)
	}

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := half.fact(ev,
				"SunSpecTCP-61: the EUT-C's ClientHello offers only the NULL compression method (0x00)",
				"ClientHello.legacy_compression_methods of the gateway's hello to the bench device sim, parsed from the capture",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					return compressionVerdict(ch, "the gateway's")
				})
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			a, err = serverHelloFact(ev, p,
				"SunSpecTCP-61 (server corollary): offered DEFLATE ahead of NULL, the EUT-S selected NULL compression",
				"ServerHello.compression_method, parsed from the capture",
				func(sh *tlsdis.ServerHello) (certify.Verdict, string) {
					if sh == nil {
						return certify.Skip, "the DUT sent no ServerHello for the DEFLATE-first probe; refusing such a hello outright is also conformant"
					}
					obs := fmt.Sprintf("ServerHello.compression_method = 0x%02X (%s)",
						sh.CompressionMethod, tlsdis.CompressionMethodName(sh.CompressionMethod))
					if sh.CompressionMethod != 0 {
						return certify.Fail, obs + " — a method other than NULL was selected"
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

// ── PROT-004 · Renegotiation Indication ─────────────────────────────────────

func prot004(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pf, skip := prepare(rc, false)
	if skip != nil {
		return *skip, nil
	}

	h := conformantHello()
	h.SupportedVersions = nil
	h.RenegotiationInfo = true
	p := Probe(ctx, rc, pf.Target, "PROT-004: TLS 1.2 hello carrying renegotiation_info", h)

	var t tally
	v, obs := renegotiationInfoVerdict(p.ServerHello())
	t.add(v, "%s", obs)
	t.caveat("the RENEGOTIATION itself (a second handshake inside the established session, whose " +
		"renegotiation_info carries the previous Finished messages' verify_data) was not attempted: Go's " +
		"crypto/tls, this bench's TLS stack, cannot INITIATE renegotiation as a client — it can only accept " +
		"a server-initiated one. The RFC 5746 indication, which is what SunSpecTCP-62 requires, is asserted " +
		"from the wire.")

	// PROT-004#3 (census 20260731T234821): see watchClientHalfForced's doc.
	half := watchClientHalfForced(ctx, rc)

	return certify.Result{
		Verdict: t.verdict(),
		Notes:   t.notes(),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			a, err := serverHelloFact(ev, p,
				"SunSpecTCP-62 / RFC 5746: the EUT-S ServerHello carries the renegotiation_info extension (type 0xFF01)",
				"ServerHello extension 0xFF01, parsed from the capture",
				renegotiationInfoVerdict)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			out = append(out, ev.SkipAssertion(
				"SunSpecTCP-62: a renegotiation handshake inside the established session carries the previous handshake's Finished verify_data in renegotiation_info, and Modbus data continues to flow afterwards",
				"a client-initiated renegotiation inside an established mbaps session",
				"Go's crypto/tls — this bench's TLS stack — cannot initiate renegotiation as a client, only "+
					"accept a server-initiated one, so this bench cannot provoke the second handshake. The "+
					"RFC 5746 indication extension itself, which is SunSpecTCP-62's requirement, IS asserted "+
					"above. TLS 1.3 removes renegotiation entirely, so this criterion applies only to the "+
					"DUT's TLS 1.2 sessions."))

			a, err = half.fact(ev,
				"SunSpecTCP-62 [C]: the gateway's own southbound ClientHello provides the RFC 5746 "+
					"secure-renegotiation indication in one of the two forms §3.4 admits — the empty "+
					"renegotiation_info extension, or TLS_EMPTY_RENEGOTIATION_INFO_SCSV in cipher_suites",
				"ClientHello extension 0xFF01 and cipher_suites of the gateway's hello to the bench device sim",
				func(ch *tlsdis.ClientHello) (certify.Verdict, string) {
					return renegotiationIndicationVerdict(ch, "the gateway's")
				})
			if err != nil {
				return nil, err
			}
			return append(out, a), nil
		},
	}, nil
}
