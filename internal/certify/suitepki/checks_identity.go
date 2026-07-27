package suitepki

// checks_identity.go implements PKI-4, PKI-5, PKI-6 and PKI-7 — the IEEE
// 2030.5-2018 device identification profile — and expects all four to FAIL
// against the DUT as it is built today.
//
// They are written exactly as they would be written for a device that passes.
// Nothing here is rigged to fail: the same code, run against a peer whose leaf
// carries an empty Subject and a hardwareModuleName otherName, returns PASS on
// every criterion, and the suite's tests prove that by standing up such a peer
// on loopback and running the checks against it. That symmetry is the point. A
// FAIL that a conformant peer could not turn into a PASS is not a measurement,
// it is an assertion of the author's opinion.
//
// The four criteria, from the test-PKI document §2.2 and §2.3:
//
//	PKI-4  Subject empty; identity in SubjectAltName otherName hwType/hwSerialNum
//	PKI-5  the (model OID, serial number) pair is unique
//	PKI-6  hwType is an IANA PEN plus a manufacturer model-id hierarchy
//	PKI-7  hwSerialNum is a DER OCTET STRING carrying a UTF-8 string
//
// PKI-5 needs care. Uniqueness is a property of a POPULATION and this bench
// exercises one device, so a check that printed PASS for it would be claiming
// something it cannot see. It is split: the part that IS observable — whether
// the identity tuple whose uniqueness is required exists at all — is asserted
// and cited, and the population half is a SKIP naming exactly what would be
// needed to close it.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// leafCase is the shape the four identity checks share: one session to the DUT,
// a verdict formed from what the socket saw, and assertions minted in the
// citation phase over the DUT's Certificate message as it appeared in the
// capture.
type leafCase struct {
	// label names the connection in the attribution record.
	label string
	// skipClaim is the claim the "no wire evidence" SKIP is filed under, so a
	// reader of the bundle sees WHICH criterion went unasserted.
	skipClaim string
	// decide forms the live-phase verdict from the socket view. leaf is nil
	// when the DUT presented nothing, and why says so.
	decide func(leaf *CertFacts, why string) (certify.Verdict, string)
	// assert mints the wire-cited assertions. leaf is the certificate read out
	// of the CAPTURE, which is the authoritative one.
	assert func(ev *certify.Evidence, w *WireHandshake, leaf *CertFacts) ([]certify.Assertion, error)
}

// runLeafCase drives one identity check end to end.
func runLeafCase(ctx context.Context, rc *certify.RunCtx, c leafCase) (certify.Result, error) {
	ident, identWhy := benchIdentity(rc)
	if ident == nil {
		rc.Logf("presenting no client certificate: %s", identWhy)
	}
	s, err := dialDUT(ctx, rc, c.label, HandshakeOptions{Identity: ident.TLS()})
	if err != nil {
		// The check could not be carried out. That is a FAIL with no
		// conformance conclusion, which the runner records as such — never a
		// SKIP, because "we could not test it" must not read like "it passed".
		return certify.Result{}, err
	}

	var socketLeaf *CertFacts
	why := "the DUT presented no certificate"
	if s.Facts.Chain != nil {
		socketLeaf, why = s.Facts.Chain.Leaf(), ""
	}
	verdict, notes := c.decide(socketLeaf, why)
	if !s.Facts.Completed {
		notes += fmt.Sprintf(" (the handshake did not complete: %s; the DUT's certificate arrives before "+
			"any rejection, so the certificate facts above still stand)", s.Facts.HandshakeErr)
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			w, skipWhy := s.wire(ev)
			if w == nil {
				return []certify.Assertion{ev.SkipAssertion(c.skipClaim, certificateCitationMethod, skipWhy)}, nil
			}
			leaf, leafWhy := leafFacts(w.ServerCertificate)
			if leaf == nil {
				return []certify.Assertion{ev.SkipAssertion(c.skipClaim, certificateCitationMethod,
					leafWhy+"; "+joinNotes(w.Notes))}, nil
			}
			out, err := c.assert(ev, w, leaf)
			if err != nil {
				return nil, err
			}
			if x := crossCheckSocket(ev, s, w); x != nil {
				out = append(out, *x)
			}
			return out, nil
		},
	}, nil
}

// ---------------------------------------------------------------------------
// PKI-4 — empty Subject, identity in the SAN otherName
// ---------------------------------------------------------------------------

const claimEmptySubject = "the DUT's device certificate leaves the Subject field empty, as IEEE 2030.5-2018 requires"

const claimSANIdentity = "the DUT's device certificate carries its identity in a SubjectAltName otherName of type " +
	"id-on-hardwareModuleName (1.3.6.1.5.5.7.8.4), holding the manufacturer model OID as hwType and the device " +
	"serial number as hwSerialNum"

func checkIdentitySAN(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return runLeafCase(ctx, rc, leafCase{
		label:     "PKI-4 device identification profile",
		skipClaim: claimSANIdentity,
		decide: func(leaf *CertFacts, why string) (certify.Verdict, string) {
			if leaf == nil {
				return certify.Skip, why
			}
			switch {
			case leaf.SubjectEmpty && leaf.Identity != nil:
				return certify.Pass, "the DUT's leaf follows the IEEE 2030.5-2018 device identification " +
					"profile: empty Subject, identity in the SAN otherName (" + leaf.Identity.String() + ")"
			case leaf.Identity != nil:
				return certify.Fail, "the DUT's leaf carries the 2030.5 SAN identity but its Subject is not " +
					"empty: " + leaf.Subject()
			default:
				return certify.Fail, "the DUT's leaf carries NO IEEE 2030.5 device identity: " + leaf.Describe()
			}
		},
		assert: func(ev *certify.Evidence, w *WireHandshake, leaf *CertFacts) ([]certify.Assertion, error) {
			var out []certify.Assertion

			v := certify.Fail
			observed := fmt.Sprintf("Subject %q carries %d relative distinguished name(s); "+
				"IEEE 2030.5-2018 requires the Subject DN to be an empty SEQUENCE",
				leaf.Subject(), leaf.SubjectRDNs)
			if leaf.SubjectEmpty {
				v = certify.Pass
				observed = "the Subject DN is an empty SEQUENCE (0 relative distinguished names)"
			}
			a, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimEmptySubject, v, observed)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			v, observed = identityObservation(leaf)
			b, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimSANIdentity, v, observed)
			if err != nil {
				return nil, err
			}
			if leaf.Identity == nil {
				b.Note = joinNote(b.Note, "the illustrative OID in the source document "+
					"(1.3.6.1.4.1.99999.13.1, quoted a second time as ...13.1.1) is an example, not a value the "+
					"DUT is required to carry; only the PRESENCE and structure of the identity is asserted here")
			}
			out = append(out, b)
			return out, nil
		},
	})
}

// identityObservation renders the SAN identity finding, in the vocabulary the
// test procedure's expected output uses.
func identityObservation(leaf *CertFacts) (certify.Verdict, string) {
	switch {
	case leaf.Identity != nil:
		return certify.Pass, fmt.Sprintf("othername: %s", leaf.Identity)
	case leaf.IdentityErr != "":
		return certify.Fail, "an id-on-hardwareModuleName otherName is present but does not decode: " + leaf.IdentityErr
	default:
		detail := "the leaf carries no SubjectAltName extension at all"
		if leaf.SANPresent {
			detail = fmt.Sprintf("the leaf's SubjectAltName carries %d otherName entr(ies)%s, none of type "+
				"id-on-hardwareModuleName", len(leaf.OtherNames), sanContents(leaf))
		}
		ext := "none"
		if len(leaf.PrivateEnterpriseOIDs) > 0 {
			ext = strings.Join(leaf.PrivateEnterpriseOIDs, ", ")
		}
		return certify.Fail, fmt.Sprintf(
			"no IEEE 2030.5 device identity is present: %s. Private-enterprise extension OIDs on the leaf: %s",
			detail, ext)
	}
}

func sanContents(leaf *CertFacts) string {
	if leaf.Info == nil {
		return ""
	}
	var parts []string
	if len(leaf.Info.DNSNames) > 0 {
		parts = append(parts, "DNS:"+strings.Join(leaf.Info.DNSNames, ",DNS:"))
	}
	if len(leaf.Info.IPAddresses) > 0 {
		parts = append(parts, "IP:"+strings.Join(leaf.Info.IPAddresses, ",IP:"))
	}
	if len(parts) == 0 {
		return ""
	}
	return " and " + strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// PKI-5 — uniqueness of (model OID, serial number)
// ---------------------------------------------------------------------------

const claimIdentityTuple = "the DUT's device certificate carries the (manufacturer model OID, device serial " +
	"number) pair whose uniqueness IEEE 2030.5 requires"

const claimIdentityUnique = "no two devices share the same (manufacturer model OID, device serial number) pair"

func checkIdentityUnique(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	// The device's serial number is read from the gateway when read-only
	// introspection is configured. It is corroboration, never a citation: the
	// point it makes is that the DUT HAS a serial number and simply does not
	// publish it in its certificate, which sharpens the finding from "no
	// identity" to "an identity that exists but is not carried".
	var serial string
	if rc.Gateway.Available() {
		if out, err := rc.Gateway.ReadFile(ctx, "/etc/lexa/identity/serial"); err == nil {
			serial = strings.TrimSpace(string(out))
		}
	}

	return runLeafCase(ctx, rc, leafCase{
		label:     "PKI-5 device identity uniqueness",
		skipClaim: claimIdentityTuple,
		decide: func(leaf *CertFacts, why string) (certify.Verdict, string) {
			if leaf == nil {
				return certify.Skip, why
			}
			if leaf.Identity == nil {
				return certify.Fail, "the DUT's leaf carries no (hwType, hwSerialNum) pair, so the pair whose " +
					"uniqueness this case requires does not exist to be unique"
			}
			return certify.Pass, "the DUT's leaf carries the identity pair " + leaf.Identity.String()
		},
		assert: func(ev *certify.Evidence, w *WireHandshake, leaf *CertFacts) ([]certify.Assertion, error) {
			v := certify.Fail
			observed := "no (hwType, hwSerialNum) pair is present in the DUT's leaf"
			if leaf.Identity != nil {
				v = certify.Pass
				observed = "hwType=" + leaf.Identity.HWType.String() + ", hwSerialNum=" + leaf.Identity.Serial
			}
			a, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimIdentityTuple, v, observed)
			if err != nil {
				return nil, err
			}
			out := []certify.Assertion{a}

			// The population half. Saying precisely what would close it is the
			// difference between a SKIP that is engineering and one that is an
			// excuse.
			out = append(out, ev.SkipAssertion(claimIdentityUnique,
				"comparison of the (hwType, hwSerialNum) pairs across a set of issued certificates",
				"uniqueness is a property of a population and this run exercised one device; closing it needs "+
					"the manufacturer's issuance records, or certificates from at least two devices of the "+
					"same model, neither of which is observable on the wire"))

			if serial != "" {
				n, err := ev.Narrative(
					"the DUT has a device serial number available to put in a certificate",
					"read-only gateway introspection",
					certify.Pass,
					"serial "+serial+", which appears in no extension of the certificate the DUT presented",
					"ssh read of /etc/lexa/identity/serial on the DUT")
				if err != nil {
					return nil, err
				}
				out = append(out, n)
			}
			return out, nil
		},
	})
}

// ---------------------------------------------------------------------------
// PKI-6 — the model OID is an IANA PEN plus a model hierarchy
// ---------------------------------------------------------------------------

const claimModelOIDPEN = "the manufacturer model OID in the DUT's certificate (hwType) is rooted at the " +
	"manufacturer's IANA Private Enterprise Number arc, 1.3.6.1.4.1.<pen>"

const claimPENPublished = "the DUT publishes at least one private-enterprise (1.3.6.1.4.1.*) identity in its " +
	"certificate, evidencing an allocated IANA PEN"

func checkModelOIDPEN(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return runLeafCase(ctx, rc, leafCase{
		label:     "PKI-6 manufacturer model OID",
		skipClaim: claimModelOIDPEN,
		decide: func(leaf *CertFacts, why string) (certify.Verdict, string) {
			if leaf == nil {
				return certify.Skip, why
			}
			if leaf.Identity == nil {
				return certify.Fail, "the DUT's leaf publishes no manufacturer model OID (no hwType), so it " +
					"cannot be rooted at a PEN"
			}
			if pen, ok := leaf.Identity.PEN(); ok {
				return certify.Pass, "hwType " + leaf.Identity.HWType.String() + " is rooted at PEN " + pen
			}
			return certify.Fail, "hwType " + leaf.Identity.HWType.String() + " is not rooted at 1.3.6.1.4.1"
		},
		assert: func(ev *certify.Evidence, w *WireHandshake, leaf *CertFacts) ([]certify.Assertion, error) {
			v := certify.Fail
			observed := "the DUT's leaf carries no hwType: there is no manufacturer model OID to root at a PEN"
			if leaf.Identity != nil {
				if pen, ok := leaf.Identity.PEN(); ok {
					v = certify.Pass
					observed = fmt.Sprintf("hwType %s = PEN %s + model arcs %v",
						leaf.Identity.HWType, pen, leaf.Identity.HWType[len(OIDIANAPrivateEnterprise)+1:])
				} else {
					observed = "hwType " + leaf.Identity.HWType.String() +
						" is not under the IANA Private Enterprise arc 1.3.6.1.4.1"
				}
			}
			a, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimModelOIDPEN, v, observed)
			if err != nil {
				return nil, err
			}
			out := []certify.Assertion{a}

			// The second assertion separates two findings that would otherwise
			// be confused: "this manufacturer has no PEN" and "this
			// manufacturer has a PEN but publishes no model OID under it". The
			// DUT is the second, and saying so makes the gap a small one to
			// close rather than an open question.
			pv, pobs := penObservation(leaf)
			b, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimPENPublished, pv, pobs)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
			return out, nil
		},
	})
}

// penObservation reports every PEN-rooted identity the leaf publishes.
//
// hwType counts first when it is present, because it IS the model OID the case
// is about; the private-enterprise extension OIDs count as a fallback. The
// distinction the assertion exists to draw is between "this manufacturer has no
// PEN" and "this manufacturer has a PEN but publishes no model OID under it" —
// the DUT is the second, which makes the PKI-6 gap a small one to close rather
// than an open question.
func penObservation(leaf *CertFacts) (certify.Verdict, string) {
	if leaf.Identity != nil {
		if pen, ok := leaf.Identity.PEN(); ok {
			return certify.Pass, fmt.Sprintf("hwType %s is rooted at PEN %s", leaf.Identity.HWType, pen)
		}
	}
	if len(leaf.PrivateEnterpriseOIDs) == 0 {
		return certify.Warn, "the leaf carries neither a PEN-rooted hwType nor any extension under " +
			"1.3.6.1.4.1, so this certificate evidences no PEN allocation either way"
	}
	return certify.Pass, fmt.Sprintf(
		"no PEN-rooted hwType, but private-enterprise extension OID(s) are present: %s — the manufacturer "+
			"holds a PEN; what is missing is a model OID published as hwType, not the PEN itself",
		strings.Join(leaf.PrivateEnterpriseOIDs, ", "))
}

// ---------------------------------------------------------------------------
// PKI-7 — serial number encoding
// ---------------------------------------------------------------------------

const claimSerialOctetString = "the device serial number in the DUT's certificate (hwSerialNum) is encoded as " +
	"an ASN.1 DER OCTET STRING, as IEEE 2030.5 requires"

const claimSerialUTF8 = "the serial number OCTET STRING holds a UTF-8 string, so the serial renders " +
	"deterministically in human-readable form"

func checkSerialEncoding(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return runLeafCase(ctx, rc, leafCase{
		label:     "PKI-7 serial number encoding",
		skipClaim: claimSerialOctetString,
		decide: func(leaf *CertFacts, why string) (certify.Verdict, string) {
			if leaf == nil {
				return certify.Skip, why
			}
			switch {
			case leaf.Identity == nil:
				return certify.Fail, "the DUT's leaf carries no hwSerialNum field to inspect"
			case !leaf.Identity.SerialIsOctetString:
				return certify.Fail, fmt.Sprintf("hwSerialNum is encoded with ASN.1 tag 0x%02x, not OCTET "+
					"STRING (0x04)", leaf.Identity.SerialTag)
			case !leaf.Identity.SerialIsUTF8:
				return certify.Fail, "hwSerialNum is an OCTET STRING but its contents are not valid UTF-8"
			default:
				return certify.Pass, "hwSerialNum is an OCTET STRING holding the UTF-8 string " + leaf.Identity.Serial
			}
		},
		assert: func(ev *certify.Evidence, w *WireHandshake, leaf *CertFacts) ([]certify.Assertion, error) {
			var out []certify.Assertion

			v := certify.Fail
			observed := "no hwSerialNum field is present: the leaf carries no id-on-hardwareModuleName otherName"
			if leaf.Identity != nil {
				if leaf.Identity.SerialIsOctetString {
					v = certify.Pass
					observed = fmt.Sprintf("hwSerialNum is ASN.1 tag 0x%02x (OCTET STRING), %d byte(s)",
						leaf.Identity.SerialTag, len(leaf.Identity.HWSerialNum))
				} else {
					observed = fmt.Sprintf("hwSerialNum is ASN.1 tag 0x%02x, not the OCTET STRING (0x04) "+
						"IEEE 2030.5 requires", leaf.Identity.SerialTag)
				}
			}
			a, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimSerialOctetString, v, observed)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			if leaf.Identity == nil {
				out = append(out, ev.SkipAssertion(claimSerialUTF8, certificateCitationMethod,
					"there is no OCTET STRING to inspect: the encoding of a field the certificate does not "+
						"carry is not a fact about this DUT"))
				return out, nil
			}
			uv := certify.Fail
			uobs := fmt.Sprintf("hwSerialNum bytes are not valid UTF-8: %s", leaf.Identity.Serial)
			if leaf.Identity.SerialIsUTF8 {
				uv = certify.Pass
				uobs = "hwSerialNum renders as " + leaf.Identity.Serial
			}
			b, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimSerialUTF8, uv, uobs)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
			return out, nil
		},
	})
}

// joinNote appends b to a with a separator, mirroring the runner's own note
// joining so a bundle reads consistently.
func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
