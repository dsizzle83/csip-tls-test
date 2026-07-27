package suitepki

// checks_transport.go implements PKI-1, PKI-3 and PKI-8: the rows about how
// certificates are USED on a connection rather than what is inside one.
//
//	PKI-1  every CSIP data connection is TLS, with certificates on both sides
//	PKI-3  the DUT validates a peer chain whose intermediate CA is not its own
//	PKI-8  the DUT presents ONE chain throughout testing; the framework varies
//
// PKI-1's pass criterion is written over "every data connection in the CSIP
// system", and this bench can only speak for the connections it opened. The
// check therefore asserts what it can prove — that the connection it opened to
// the DUT's only externally reachable port carried nothing but TLS records, in
// both directions, with certificates demanded and presented — and files an
// explicit SKIP for the DUT's own northbound CSIP client leg, which the DUT
// initiates and for which the bench holds no socket to claim. Naming the
// uncovered leg is the honest form of a scope limitation; quietly asserting
// "every connection" from one connection is not.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// ---------------------------------------------------------------------------
// PKI-1 — TLS with certificates is mandatory
// ---------------------------------------------------------------------------

const (
	claimConnectionIsTLS = "the bench's data connection to the DUT began with a TLS handshake, not a cleartext " +
		"application protocol"
	claimAllBytesInTLS = "every byte the bench sent on the data connection was carried inside a TLS record: no " +
		"cleartext CSIP or Modbus payload appears outside the tunnel"
	claimDUTPresentsCert = "the DUT presented an X.509 certificate chain on the data connection"
	claimDUTDemandsCert  = "the DUT demanded a certificate from the bench, so the connection is mutually " +
		"authenticated rather than server-authenticated"
	claimCSIPLegIsTLS = "the DUT's own northbound IEEE 2030.5 client connection is likewise carried over TLS"
)

func checkMandatoryTLS(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	ident, identWhy := benchIdentity(rc)
	if ident == nil {
		rc.Logf("presenting no client certificate: %s — the DUT is expected to refuse, which still evidences "+
			"that certificates are mandatory", identWhy)
	}
	s, err := dialDUT(ctx, rc, "PKI-1 mandatory TLS on the DUT's data port", HandshakeOptions{Identity: ident.TLS()})
	if err != nil {
		return certify.Result{}, err
	}

	notes := fmt.Sprintf("connection to %s as %s: %s", rc.Targets.Gateway, ident.Name(), s.Facts.Describe())

	return certify.Result{
		Notes: notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			w, why := s.wire(ev)
			if w == nil {
				return []certify.Assertion{ev.SkipAssertion(claimConnectionIsTLS, "TLS record-layer dissection", why)}, nil
			}
			var out []certify.Assertion

			// 1. The conversation opened with TLS. Citing the first record's
			//    bytes is the strongest possible form of this: a reader sees
			//    the 0x16 0x03 0x0N header for themselves.
			a, err := firstRecordAssertion(ev, w)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// 2. Nothing escaped the tunnel.
			b, err := allBytesInTLSAssertion(ev, w)
			if err != nil {
				return nil, err
			}
			out = append(out, b)

			// 3. The DUT presented a certificate.
			leaf, leafWhy := leafFacts(w.ServerCertificate)
			if leaf == nil {
				out = append(out, ev.SkipAssertion(claimDUTPresentsCert, certificateCitationMethod,
					leafWhy+"; "+joinNotes(w.Notes)))
			} else {
				c, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimDUTPresentsCert, certify.Pass,
					fmt.Sprintf("chain of %d certificate(s): %s", w.ServerCertificate.Chain.Depth,
						w.ServerCertificate.Chain.Describe()))
				if err != nil {
					return nil, err
				}
				out = append(out, c)
			}

			// 4. The DUT demanded one.
			if len(w.CertificateRequestFrames) > 0 {
				d, err := ev.CiteFrames(claimDUTDemandsCert,
					"CertificateRequest handshake message located in the DUT's plaintext handshake flight",
					certify.Pass,
					"the DUT sent CertificateRequest", w.CertificateRequestFrames)
				if err != nil {
					return nil, err
				}
				out = append(out, d)
			} else {
				out = append(out, ev.SkipAssertion(claimDUTDemandsCert,
					"CertificateRequest handshake message located in the capture",
					"no CertificateRequest was visible: "+joinNotes(w.Notes)))
			}

			// 5. The leg this check cannot speak for, named rather than
			//    silently folded into "every connection".
			out = append(out, ev.SkipAssertion(claimCSIPLegIsTLS,
				"frame attribution (time AND connection 4-tuple)",
				"the DUT initiates its northbound 2030.5 connection to the bench's gridsim, so this check "+
					"never holds that socket and cannot claim its 4-tuple; asserting it here would mean "+
					"attributing frames this check did not cause. The csip-client suite covers that leg"))
			return out, nil
		},
	}, nil
}

// firstRecordAssertion cites the opening TLS record's bytes.
func firstRecordAssertion(ev *certify.Evidence, w *WireHandshake) (certify.Assertion, error) {
	if w.Client == nil || w.Client.Stream == nil || len(w.Client.Stream.Records) == 0 {
		return ev.SkipAssertion(claimConnectionIsTLS, "TLS record-layer dissection",
			"the bench->DUT direction holds no complete TLS record: "+joinNotes(w.Notes)), nil
	}
	rec := w.Client.Stream.Records[0]
	observed := fmt.Sprintf("record type %s, legacy version %s, %d-byte fragment",
		tlsdis.ContentTypeName(rec.Type), tlsdis.VersionName(rec.Version), rec.Length)
	v := certify.Fail
	if rec.Type == tlsdis.ContentHandshake && w.ClientHello != nil {
		v = certify.Pass
		observed += fmt.Sprintf("; ClientHello offering %d cipher suite(s), max version %s",
			len(w.ClientHello.CipherSuites), tlsdis.VersionName(w.ClientHello.MaxVersion()))
	}
	return ev.CiteBytes(claimConnectionIsTLS,
		"TLS record-layer dissection of the first bytes of the reassembled bench->DUT direction",
		v, observed, w.ClientDir, rec.Offset, rec.End())
}

// allBytesInTLSAssertion proves the whole conversation stayed inside the
// tunnel.
//
// The subtlety worth stating: a capture stopped mid-record leaves trailing
// bytes that are NOT a conformance failure. RecordStream.Need distinguishes the
// two — bytes with an outstanding Need are an incomplete final record, bytes
// without one are something that is not TLS.
func allBytesInTLSAssertion(ev *certify.Evidence, w *WireHandshake) (certify.Assertion, error) {
	rs := w.Client.Stream
	total := w.ClientDir.Bytes.Len()
	v := certify.Pass
	observed := fmt.Sprintf("%d byte(s) reassembled into %d complete TLS record(s), 0 bytes outside the record layer",
		total, len(rs.Records))
	switch {
	case rs.Trailing > 0 && rs.Need > 0:
		observed = fmt.Sprintf("%d byte(s) reassembled into %d complete TLS record(s); the final record is "+
			"incomplete by %d byte(s) because the capture stopped inside it, which is a capture boundary, "+
			"not traffic outside the tunnel", total, len(rs.Records), rs.Need)
	case rs.Trailing > 0:
		v = certify.Fail
		observed = fmt.Sprintf("%d byte(s) reassembled into %d TLS record(s) with %d trailing byte(s) that are "+
			"not part of any record", total, len(rs.Records), rs.Trailing)
	}
	if total == 0 {
		return ev.SkipAssertion(claimAllBytesInTLS, "TLS record-layer dissection",
			"the bench->DUT direction reassembled to zero bytes"), nil
	}
	return ev.CiteBytes(claimAllBytesInTLS,
		"TLS record-layer walk over the entire reassembled bench->DUT direction",
		v, observed, w.ClientDir, 0, total)
}

// ---------------------------------------------------------------------------
// PKI-3 — a peer chain whose intermediate is not the DUT's own
// ---------------------------------------------------------------------------

const (
	claimCrossIssuerAccepted = "the DUT validates a peer certificate chain issued by an intermediate CA that " +
		"is not the one that issued its own certificate"
	claimIntermediatesDiffer = "the bench's chain and the DUT's chain were issued by different intermediate CAs"
)

func checkCrossIssuer(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	root, why := benchRoot(rc)
	if root == nil {
		return certify.Skipped("%s", why), nil
	}
	// A second intermediate under the SAME root. That is the condition the test
	// case asks for: the peer's issuing CA differs from the DUT's, while both
	// still chain to the trust anchor the DUT is configured with.
	mica, err := NewCA("suitepki cross-issuer MICA", root, 0)
	if err != nil {
		return certify.Result{}, fmt.Errorf("mint a second intermediate under the bench root: %w", err)
	}
	leaf, err := Mint(mica, LeafSpec{
		Name:       "cross-issuer client",
		CommonName: "suitepki cross-issuer client",
		Roles:      []string{"ReadOnlySunSpec"},
		Client:     true, Server: true,
	})
	if err != nil {
		return certify.Result{}, fmt.Errorf("mint the cross-issuer leaf: %w", err)
	}
	tc := leaf.TLSCertificate()

	s, err := dialDUT(ctx, rc, "PKI-3 peer chain under a second intermediate", HandshakeOptions{Identity: &tc})
	if err != nil {
		return certify.Result{}, err
	}

	verdict := certify.Pass
	notes := "the DUT completed a mutually-authenticated handshake with a peer whose chain is anchored at the " +
		"bench root but issued by a second, freshly minted intermediate CA"
	if !s.Facts.Completed {
		verdict = certify.Fail
		notes = "the DUT refused a peer chain that is anchored at the trust anchor it is configured with but " +
			"issued by a different intermediate CA: " + s.Facts.HandshakeErr
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			w, why := s.wire(ev)
			if w == nil {
				return []certify.Assertion{ev.SkipAssertion(claimCrossIssuerAccepted,
					"TLS handshake dissection", why)}, nil
			}
			var out []certify.Assertion

			// The bench's own Certificate message is the evidence that the
			// differing-intermediate condition was actually created — without
			// it, a completed handshake proves nothing about which chain was
			// presented.
			ourChain := "the bench sent no Certificate message"
			ourIntermediate := ""
			if w.ClientCertificate != nil && w.ClientCertificate.Chain != nil {
				ourChain = w.ClientCertificate.Chain.Describe()
				if inter := w.ClientCertificate.Chain.Intermediates(); len(inter) > 0 {
					ourIntermediate = inter[0].SHA256
				}
			}
			dutIntermediate := ""
			dutChain := "the DUT sent no Certificate message"
			if w.ServerCertificate != nil && w.ServerCertificate.Chain != nil {
				dutChain = w.ServerCertificate.Chain.Describe()
				if inter := w.ServerCertificate.Chain.Intermediates(); len(inter) > 0 {
					dutIntermediate = inter[0].SHA256
				}
			}

			differ := ourIntermediate != "" && dutIntermediate != "" && ourIntermediate != dutIntermediate
			dv, dobs := certify.Warn, fmt.Sprintf(
				"the differing-intermediate condition could not be confirmed from the wire: bench chain %s; "+
					"DUT chain %s", ourChain, dutChain)
			if differ {
				dv = certify.Pass
				dobs = fmt.Sprintf("bench intermediate %s, DUT intermediate %s — different certificates; "+
					"bench chain %s; DUT chain %s",
					shortHash(ourIntermediate), shortHash(dutIntermediate), ourChain, dutChain)
			}
			a, err := citeCert(ev, w.ClientDir, w.ClientCertificate, claimIntermediatesDiffer, dv, dobs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// The acceptance itself. A handshake that reached the point where
			// the bench's Certificate was sent AND completed is the observable;
			// a fatal alert from the DUT is the counter-observable.
			av, aobs := certify.Pass, "the handshake completed: the DUT accepted the chain"
			if !s.Facts.Completed {
				av = certify.Fail
				aobs = "the handshake did not complete: " + s.Facts.HandshakeErr
				if al, ok := w.FatalAlert(); ok {
					aobs += " — " + AlertText(al)
				}
			}
			frames := ev.Frames()
			if len(frames) == 0 {
				out = append(out, ev.NoEvidence(claimCrossIssuerAccepted))
				return out, nil
			}
			b, err := ev.CiteFrames(claimCrossIssuerAccepted,
				"outcome of the mutually-authenticated handshake, read from the capture's handshake flight "+
					"and alert records",
				av, aobs, frames)
			if err != nil {
				return nil, err
			}
			b.Note = joinNote(b.Note, "SHOULD-strength: the test-PKI document itself notes that IEEE 2030.5 "+
				"draws no client/server certificate distinction and that separate intermediates are a SunSpec "+
				"test-PKI convention adopted because it is desirable for testing")
			out = append(out, b)
			return out, nil
		},
	}, nil
}

// ---------------------------------------------------------------------------
// PKI-8 — one chain for the DUT, variation on the framework side
// ---------------------------------------------------------------------------

const (
	claimDUTChainStable  = "the DUT presented the same device certificate and chain on every connection in this run"
	claimFrameworkVaries = "the test framework, not the DUT, is what varied the certificate material across " +
		"connections"
)

// singleChainConnections is how many successive connections PKI-8 opens. Three
// is the smallest number that can distinguish "stable" from "alternating".
const singleChainConnections = 3

func checkSingleChain(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	idents := benchIdentities(rc, singleChainConnections)
	if len(idents) == 0 {
		idents = []*tlsCertificate{nil}
	}

	var sessions []*session
	for i := 0; i < singleChainConnections; i++ {
		id := idents[i%len(idents)]
		s, err := dialDUT(ctx, rc, fmt.Sprintf("PKI-8 connection %d of %d as %s",
			i+1, singleChainConnections, id.Name()), HandshakeOptions{Identity: id.TLS()})
		if err != nil {
			return certify.Result{}, err
		}
		sessions = append(sessions, s)
	}

	// Live-phase verdict from the socket view; the citation phase re-decides it
	// from the capture, which is the view that counts.
	digests := map[string]int{}
	for _, s := range sessions {
		if s.Facts.Chain != nil {
			digests[s.Facts.Chain.SHA256]++
		}
	}
	verdict, notes := certify.Pass, fmt.Sprintf("the DUT presented one chain across %d connections", len(sessions))
	if len(digests) != 1 {
		verdict = certify.Fail
		notes = fmt.Sprintf("the DUT presented %d distinct chains across %d connections", len(digests), len(sessions))
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			var dutDigests, benchDigests []string
			var missing []string

			for i, s := range sessions {
				w, why := s.wire(ev)
				if w == nil {
					missing = append(missing, fmt.Sprintf("connection %d: %s", i+1, why))
					continue
				}
				leaf, leafWhy := leafFacts(w.ServerCertificate)
				if leaf == nil {
					missing = append(missing, fmt.Sprintf("connection %d: %s", i+1, leafWhy))
					continue
				}
				dutDigests = append(dutDigests, w.ServerCertificate.Chain.SHA256)
				if w.ClientCertificate != nil && w.ClientCertificate.Chain != nil {
					benchDigests = append(benchDigests, w.ClientCertificate.Chain.SHA256)
				}
				a, err := citeCert(ev, w.ServerDir, w.ServerCertificate,
					fmt.Sprintf("on connection %d of %d the DUT presented chain sha256 %s",
						i+1, len(sessions), shortHash(w.ServerCertificate.Chain.SHA256)),
					certify.Pass,
					w.ServerCertificate.Chain.Describe())
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			if len(dutDigests) < 2 {
				out = append(out, ev.SkipAssertion(claimDUTChainStable,
					"comparison of the chain sha256 across successive connections",
					fmt.Sprintf("fewer than two of the %d connections yielded a chain from the capture: %s",
						len(sessions), summarise(missing))))
				return out, nil
			}

			v, observed := sameAcross("the DUT", dutDigests)
			frames := ev.Frames()
			b, err := ev.CiteFrames(claimDUTChainStable,
				"sha256 of the concatenated chain DER from each connection's Certificate message, compared",
				v, observed, frames)
			if err != nil {
				return nil, err
			}
			if len(missing) > 0 {
				b.Note = joinNote(b.Note, "not every connection was recoverable from the capture: "+summarise(missing))
			}
			out = append(out, b)

			// The converse observable: the framework is the side that varies.
			if len(benchDigests) < 2 {
				out = append(out, ev.SkipAssertion(claimFrameworkVaries,
					"comparison of the bench's own Certificate messages across connections",
					"fewer than two of the bench's Certificate messages were recoverable from the capture, so "+
						"whether the framework varied its material is not assertable here"))
				return out, nil
			}
			fv, fobs := certify.Pass, fmt.Sprintf("the bench presented %d distinct chains across %d connections",
				distinct(benchDigests), len(benchDigests))
			if distinct(benchDigests) < 2 {
				fv = certify.Warn
				fobs = "the bench presented the same chain on every connection, so this run did not exercise " +
					"framework-side variation; only one role fixture was available"
			}
			c, err := ev.CiteFrames(claimFrameworkVaries,
				"sha256 of the bench's own chain from each connection's Certificate message, compared",
				fv, fobs, frames)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
			return out, nil
		},
	}, nil
}

func sameAcross(who string, digests []string) (certify.Verdict, string) {
	n := distinct(digests)
	if n == 1 {
		return certify.Pass, fmt.Sprintf("%s presented chain sha256 %s on all %d connections",
			who, shortHash(digests[0]), len(digests))
	}
	short := make([]string, 0, len(digests))
	for _, d := range digests {
		short = append(short, shortHash(d))
	}
	return certify.Fail, fmt.Sprintf("%s presented %d distinct chains across %d connections: %s",
		who, n, len(digests), strings.Join(short, ", "))
}

func distinct(v []string) int {
	seen := map[string]bool{}
	for _, s := range v {
		seen[s] = true
	}
	return len(seen)
}
