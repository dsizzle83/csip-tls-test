package suitecsip

// criteria_common.go holds the criteria that recur across the CSIP rows.
//
// Nearly every row of CSIP-CONF-v1.3 restates the same handshake preconditions
// ("a TLS 1.2 session with the mandatory suite was established") and the same
// discovery steps ("GET /dcap returned 200 with a conformant DeviceCapability").
// Writing them once means they are wrong in at most one place, and it means the
// twenty rows that share a criterion produce byte-identical claim text — which
// matters more than it sounds, because a reviewer diffing two rows' assertions
// should see the DIFFERENCE between the test cases, not the difference between
// two authors' phrasings of the same sentence.

import (
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// critMandatoryCipherOffered asserts CSIP §5.2.1.1 P9 / IEEE 2030.5 §6.7 on the
// DUT's own ClientHello.
func critMandatoryCipherOffered() criterion {
	return criterion{
		Claim: "the DUT's TLS ClientHello offers the mandatory IEEE 2030.5 cipher suite " +
			"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (IANA 0xC0AE)",
		How: "the cipher_suites vector of the ClientHello, matched on the IANA code point rather than " +
			"on any name spelling",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			h := &t.Handshake
			if h.ClientHello == nil {
				return unavailable("the capture holds no ClientHello for this session")
			}
			v := certify.Fail
			if h.OffersMandatoryCipher() {
				v = certify.Pass
			}
			return found(v, h.ClientHelloFrames, "ClientHello offers %d suite(s): %s",
				len(h.ClientHello.CipherSuites), h.OfferedSuites())
		},
	}
}

// critCipherNegotiated asserts what the session actually agreed on.
func critCipherNegotiated() criterion {
	return criterion{
		Claim: "the negotiated cipher suite is TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE)",
		How:   "the cipher_suite field of the ServerHello",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			h := &t.Handshake
			if h.ServerHello == nil {
				return unavailable("the capture holds no ServerHello for this session")
			}
			v := certify.Fail
			if h.Suite == MandatoryCipher {
				v = certify.Pass
			}
			return found(v, h.ServerHelloFrames, "ServerHello selected 0x%04X %s",
				h.Suite, tlsdis.CipherSuiteName(h.Suite))
		},
	}
}

// critTLS12 asserts CSIP P8: TLS 1.2, and only TLS 1.2.
func critTLS12() criterion {
	return criterion{
		Claim: "the session is TLS 1.2 (0x0303), the only version IEEE 2030.5 / CSIP permit",
		How: "the ServerHello's negotiated version, read from supported_versions when present and from " +
			"legacy_version otherwise",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			h := &t.Handshake
			if h.ServerHello == nil {
				return unavailable("the capture holds no ServerHello for this session")
			}
			v := certify.Fail
			if h.Version == TLS12 {
				v = certify.Pass
			}
			return found(v, h.ServerHelloFrames, "negotiated version %s (0x%04X)",
				tlsdis.VersionName(h.Version), h.Version)
		},
	}
}

// critMutualAuth asserts CSIP §5.2.1.3: certificates are exchanged in both
// directions and the server actually DEMANDED one.
//
// The demand matters as much as the supply. A server that never sends
// CertificateRequest has not authenticated its client no matter what the client
// would have been willing to present, and this bench has its own precedent for
// that failure mode (the wolfSSL RequireClientCert invariant in the repository's
// CLAUDE.md).
//
// The one absence that is NOT evidence of that failure is a RESUMED session,
// where TLS omits the whole certificate exchange by design. That case returns
// unavailable — see resumedNoCertificates.
func critMutualAuth() criterion {
	return criterion{
		Claim: "the session is mutually authenticated: the server sent CertificateRequest and the DUT " +
			"answered with a certificate chain",
		How: "the presence of the CertificateRequest handshake message in the server direction and of a " +
			"non-empty Certificate message in the DUT direction",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			ht, note := handshakeOf(t)
			return annotate(mutualAuthFinding(&ht.Handshake), note)
		},
	}
}

// mutualAuthFinding is critMutualAuth's decision logic over one handshake,
// factored out so the criterion can be pointed at whichever conversation of the
// window actually carries the certificate exchange, and so the unit tests
// exercise the same code the run does.
func mutualAuthFinding(h *Handshake) Finding {
	frames := append(append([]int(nil), h.CertReqFrames...), h.ClientCertFrames...)
	frames = dedupeInts(frames)
	switch {
	case h.CertificateRequest == nil && len(h.ClientChain) == 0:
		if h.Resumed {
			return resumedNoCertificates(h, "whether the session is mutually authenticated")
		}
		if len(h.ServerHelloFrames) == 0 {
			return unavailable("the capture holds no handshake for this session")
		}
		return found(certify.Fail, h.ServerHelloFrames,
			"no CertificateRequest from the server and no Certificate from the DUT: "+
				"the session is server-authenticated only")
	case h.CertificateRequest == nil:
		return found(certify.Fail, frames,
			"the DUT presented %d certificate(s) but the server never sent CertificateRequest",
			len(h.ClientChain))
	case len(h.ClientChain) == 0:
		return found(certify.Fail, frames,
			"the server sent CertificateRequest and the DUT presented an EMPTY certificate list")
	default:
		return found(certify.Pass, frames,
			"CertificateRequest sent; the DUT presented a %d-certificate chain, leaf %s",
			len(h.ClientChain), certSummary(h.ClientChain[0]))
	}
}

// handshakeOf returns the conversation a CERTIFICATE criterion must read, plus
// the sentence it has to append to its Observed when that is not the
// conversation the transcript tier selected.
//
// See Transcript.HandshakeSession for why the two tiers select differently. The
// note is not optional politeness: an assertion citing frames from a second
// conversation of the same window is making a claim about bytes the reader will
// not find in the session named elsewhere in the row, and a bundle that did not
// say so would be citing correctly and reading misleadingly.
func handshakeOf(t *Transcript) (*Transcript, string) {
	ht := t.HandshakeSession()
	if ht == nil || ht == t {
		return t, ""
	}
	return ht, fmt.Sprintf(". These bytes are from %s, a SECOND conversation this test case wholly owns: "+
		"the session recovered for the 2030.5 transcript (%s) is a resumed one and carries no certificates, "+
		"while this one is the full handshake in the same window",
		ht.Stream.Key, t.Stream.Key)
}

// annotate appends a provenance note to a decided finding. An unavailable
// finding is left alone: it has no Observed to qualify, and its own reason
// already says what was missing.
func annotate(f Finding, note string) Finding {
	if note == "" || f.Unavailable != "" || f.Observed == "" {
		return f
	}
	f.Observed += note
	return f
}

// resumedNoCertificates is the shared reason for a certificate criterion that
// finds itself looking at an ABBREVIATED handshake. what names the thing the
// criterion wanted, so each row still reads as a sentence about ITS claim.
//
// This is the same shape — and the same verdict — the sibling certificate
// criteria already produce for the same missing message: critServerChainObserved,
// critDUTChainProfile and chainDepthCriterion all return unavailable when the
// Certificate is not in the capture. critMutualAuth was the one exception, and
// it turned the absence into a FAIL reading "the session is server-authenticated
// only" — a claim about the DUT that a resumed handshake supports neither way.
// The certificates were exchanged; they were exchanged on the FULL handshake
// that established the session, which is somewhere else in the capture or before
// it. Cf. internal/mbtls/peerid.go: "on a RESUMED handshake the client sends no
// Certificate message — that is the whole point of resumption".
//
// Note what this does NOT relax. A FULL handshake missing CertificateRequest, or
// answering one with an empty certificate list, still FAILs: that is a server
// that did not demand a client certificate, or a client that did not supply one,
// and both are exactly what CSIP §5.2.1.3 forbids.
func resumedNoCertificates(h *Handshake, what string) Finding {
	return unavailable("this window's session is a RESUMED TLS 1.2 session (abbreviated handshake — %s), so "+
		"%s cannot be read from it: certificates are exchanged only on the FULL handshake that established "+
		"this session, which lies outside this window's capture",
		h.ResumptionSummary(), what)
}

// critHandshakeComplete asserts the RFC 5246 §7.4 flight actually finished.
func critHandshakeComplete() criterion {
	return criterion{
		Claim: "the RFC 5246 §7.4 handshake completed: both directions sent ChangeCipherSpec and Finished",
		How:   "ChangeCipherSpec records in both directions followed by encrypted handshake records",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			var frames []int
			for _, d := range []*tlsdis.Direction{t.ClientRecords, t.ServerRecords} {
				if d == nil || d.Stream == nil {
					continue
				}
				for _, idx := range d.CCS {
					for _, rec := range d.Stream.Records {
						if rec.Index == idx {
							frames = append(frames, rec.Packets...)
						}
					}
				}
			}
			frames = dedupeInts(frames)
			if !t.Handshake.Complete {
				if alert, ok := firstFatalAlert(t); ok {
					return found(certify.Fail, alert.Packets,
						"the handshake did not complete: fatal alert %s", alert)
				}
				if len(frames) == 0 {
					frames = t.Handshake.ClientHelloFrames
				}
				if len(frames) == 0 {
					return unavailable("the capture holds no handshake records for this session")
				}
				return found(certify.Fail, frames,
					"only %d of the two directions reached ChangeCipherSpec", len(frames))
			}
			return found(certify.Pass, frames,
				"ChangeCipherSpec in both directions; %d/%d application-data records followed",
				t.ClientAppRecords, t.ServerAppRecords)
		},
	}
}

// critGET builds the standard "the DUT fetched this resource and the server
// answered 200" criterion, with the server-side fallback when the payload is
// not recoverable.
//
// want, when non-nil, additionally inspects the returned payload; it returns a
// verdict and a description. A nil want asserts only the status code.
func critGET(path, claim, how string, want func(*Node) (certify.Verdict, string)) criterion {
	return criterion{
		Claim:           claim,
		How:             how,
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			exs := t.GETs(path)
			if len(exs) == 0 {
				return unavailable("no GET %s appears in the recovered transcript (paths seen: %s)",
					path, strings.Join(t.Paths(), " "))
			}
			e := exs[0]
			if e.Resp == nil {
				return citeMessage(t, e.Req, certify.Fail, "GET %s was never answered in the capture", path)
			}
			if e.Resp.Status != 200 {
				return citeExchange(e, certify.Fail, "GET %s -> %s", path, e.Resp.Line())
			}
			if want == nil {
				return citeExchange(e, certify.Pass, "GET %s -> 200, %d-byte %s payload",
					path, len(e.Resp.Body), e.Resp.ContentType())
			}
			doc, err := e.Resp.SEP()
			if err != nil {
				return citeMessage(t, e.Resp, certify.Fail, "GET %s -> 200 but the body is not parseable: %v", path, err)
			}
			v, desc := want(doc)
			return citeMessage(t, e.Resp, v, "GET %s -> 200 %s; %s", path, doc.Summary(), desc)
		},
		Server: func(v *ServerView) Finding {
			n := v.GETs(path)
			if n == 0 {
				return Finding{Verdict: certify.Fail,
					Observed: fmt.Sprintf("gridsim's request log records no GET %s from the DUT in this window", path)}
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("gridsim's request log records %d GET %s from the DUT in this window "+
					"(the server's own record; the status code and payload are not recoverable from it)", n, path)}
		},
		Skip: "asserting the contents of a 2030.5 payload requires the decrypted transcript",
	}
}

// critDiscoveryRoot is the /dcap criterion nearly every row restates.
func critDiscoveryRoot() criterion {
	return critGET(DiscoveryRoot,
		"the DUT issued GET /dcap and the server answered 200 with a conformant DeviceCapability",
		"the request line, status line and sep+xml body of the first /dcap exchange in the session",
		func(doc *Node) (certify.Verdict, string) {
			if doc.Local() != "DeviceCapability" {
				return certify.Fail, "the root element is " + doc.Local() + ", not DeviceCapability"
			}
			if !doc.InNamespace() {
				return certify.Fail, "the root element is in namespace " + doc.Name.Space + ", not " + Namespace
			}
			if !doc.Has("EndDeviceListLink") {
				return certify.Fail, "the DeviceCapability carries no EndDeviceListLink"
			}
			return certify.Pass, "root element in the 2030.5 namespace with an EndDeviceListLink"
		})
}

// critFollowedLink asserts that the DUT did not hard-code any URL but followed
// one it discovered — the rule of IEEE 2030.5 §4.6 that makes the whole
// resource model work.
func critFollowedLink() criterion {
	return criterion{
		Claim: "after /dcap the DUT fetched a resource whose URI it learned from a link in a payload it " +
			"had already retrieved, rather than from a hard-coded path",
		How: "matching each request path after the first /dcap against the href attributes present in the " +
			"payloads the DUT had received up to that point",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			known := map[string]bool{DiscoveryRoot: true}
			for _, e := range t.Exchanges {
				if e.Req == nil {
					continue
				}
				if e.Req.Path != DiscoveryRoot && known[e.Req.Path] {
					return citeExchange(e, certify.Pass,
						"%s was fetched from an href the server had already served", e.Req.Line())
				}
				if e.Resp == nil || e.Resp.Status != 200 || len(e.Resp.Body) == 0 {
					continue
				}
				doc, err := e.Resp.SEP()
				if err != nil {
					continue
				}
				collectHrefs(doc, known)
			}
			if len(t.Exchanges) < 2 {
				return unavailable("the recovered transcript holds fewer than two exchanges")
			}
			return found(certify.Fail, t.Exchanges[1].Frames(),
				"the second request %s does not match any href the server had served",
				t.Exchanges[1].Req.Line())
		},
		Server: func(v *ServerView) Finding {
			n := 0
			for _, r := range v.Requests {
				if r.Method == "GET" && r.Path != DiscoveryRoot {
					n++
				}
			}
			if n == 0 {
				return Finding{Verdict: certify.Fail,
					Observed: "gridsim's request log records no GET beyond /dcap in this window"}
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("gridsim's request log records %d GET(s) beyond /dcap; whether each URI came "+
					"from a served href cannot be decided from the log alone, only that the DUT walked on", n)}
		},
	}
}

func collectHrefs(n *Node, into map[string]bool) {
	if n == nil {
		return
	}
	if h := n.Href(); h != "" {
		if i := strings.IndexByte(h, '?'); i >= 0 {
			h = h[:i]
		}
		into[h] = true
	}
	for _, k := range n.Kids {
		collectHrefs(k, into)
	}
}

// firstFatalAlert returns the first fatal alert seen either direction.
func firstFatalAlert(t *Transcript) (tlsdis.Alert, bool) {
	for _, d := range []*tlsdis.Direction{t.ClientRecords, t.ServerRecords} {
		if d == nil {
			continue
		}
		if a, ok := d.FatalAlert(); ok {
			return a, true
		}
	}
	return tlsdis.Alert{}, false
}

// certSummary renders a certificate for an Observed field: subject, issuer and
// whether it is self-issued, all read from the DER on the wire.
func certSummary(der []byte) string {
	ci, err := tlsdis.ParseCertInfo(der)
	if err != nil {
		return fmt.Sprintf("(%d-byte certificate that did not parse: %v)", len(der), err)
	}
	self := ""
	if ci.SelfIssued {
		self = " SELF-ISSUED"
	}
	return fmt.Sprintf("subject=%q issuer=%q serial=%s sha256=%s%s",
		ci.Subject, ci.Issuer, ci.SerialHex, ci.SHA256[:16], self)
}
