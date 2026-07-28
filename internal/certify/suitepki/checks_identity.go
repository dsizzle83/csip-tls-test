package suitepki

// checks_identity.go implements PKI-4, PKI-5, PKI-6 and PKI-7 — the IEEE
// 2030.5-2018 device identification profile.
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
// # WHICH certificate, and this is the whole of it
//
// All four govern the DUT's IEEE 2030.5 / CSIP DEVICE certificate, and nothing
// else. The SunSpec Test PKI application note scopes itself in its own §1
// Overview — "test certificates FOR USE WITH SUNSPEC CSIP TEST PROCEDURES …
// required to perform the CSIP 2030.5 Test Procedures" — and §2.2 restates the
// requirement as the IEEE 2030.5-2018 specification's, not SunSpec's.
//
// An mbaps certificate is governed by a DIFFERENT document. The Secure SunSpec
// Modbus Specification requires X.509v3 per RFC 5280 (SunSpecTCP-7/52), the
// full chain to the root (TCP-51) and the role extension on client domain
// certificates (TCP-27..31) — and says nothing whatever about the Subject field
// or a hardwareModuleName SAN. Its own worked example (Figure 1) shows an mbaps
// certificate with a fully populated Subject DN. Requiring an EMPTY Subject of
// an mbaps certificate contradicts the specification that governs the interface
// under test.
//
// Run 20260726T225512 pointed all four at whatever leaf the mbaps connection to
// :802 happened to present — CN=lexa-gw-nb-mbaps-server, issued by the BENCH's
// own intermediate CA — and reported four failures about a certificate that was
// a property of our provisioning fixture. So the certificate is now sourced by
// identitySource: the DUT's own 2030.5 client certificate, observed on the
// bench's 2030.5 server, and NEVER the mbaps leaf. When that observation is not
// available the four cases are INAPPLICABLE, with the scope stated — because a
// verdict about the wrong certificate is worse than no verdict.
//
// PKI-5 needs care beyond that. Uniqueness is a property of a POPULATION and
// this bench exercises one device, so a check that printed PASS for it would be
// claiming something it cannot see. It is split: the part that IS observable —
// whether the identity tuple whose uniqueness is required exists at all — is
// asserted and cited, and the population half is a SKIP naming exactly what
// would be needed to close it.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
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
	// of the CAPTURE, which is the authoritative one, and ref says which
	// direction and which Certificate message it came from — the DUT is the
	// CLIENT when its 2030.5 identity is observed passively and the SERVER when
	// an endpoint serving that identity is dialled, and a citation that pointed
	// at the wrong half would be misattributed.
	assert func(ev *certify.Evidence, ref certRef, leaf *CertFacts) ([]certify.Assertion, error)
}

// scopeNote is why an mbaps run cannot answer PKI-4/5/6/7 — carried on every
// inapplicability SKIP so a reader sees the argument, not just the outcome.
const scopeNote = "SCOPE: the SunSpec Test PKI application note scopes itself in §1 to certificates \"for use " +
	"with SunSpec CSIP Test Procedures\", and §2.2 restates an IEEE 2030.5-2018 requirement. It governs the " +
	"DUT's 2030.5 DEVICE certificate. An mbaps certificate is governed by the Secure SunSpec Modbus " +
	"Specification, which requires X.509v3/RFC 5280 (SunSpecTCP-7/52), the full chain (TCP-51) and the role " +
	"extension on client domain certificates (TCP-27..31) — and says nothing about the Subject field or a " +
	"hardwareModuleName SAN; its own worked example carries a fully populated Subject DN. Judging an mbaps " +
	"leaf against this profile would contradict the specification that governs the interface under test, so " +
	"these cases are INAPPLICABLE to an mbaps-only run rather than failed."

// certRef is the Certificate message under test, with the direction it was
// carried in, so an assertion can cite the exact bytes.
type certRef struct {
	Dir *netdis.Direction
	Msg *CertMessage
}

// runLeafCase drives one identity check end to end.
//
// The certificate it judges comes from identitySource — the DUT's own IEEE
// 2030.5 identity, observed passively on the bench's 2030.5 server. It is never
// the mbaps leaf: see the file comment.
func runLeafCase(ctx context.Context, rc *certify.RunCtx, c leafCase) (certify.Result, error) {
	// The escape hatch, and the loopback harness's path: an endpoint that
	// PRESENTS the DUT's 2030.5 identity as a server certificate. It exists
	// because some deployments expose the 2030.5 identity on a server socket,
	// and because the suite's own conformant-peer/DUT-shaped-peer pair — which
	// is what makes a FAIL here a measurement rather than an opinion — needs a
	// peer it can dial. It must be given explicitly: it is never the mbaps
	// target, and it is never inferred.
	if target, ok := rc.Param(paramIdentityTarget); ok && target != "" {
		return dialIdentityCase(ctx, rc, c, target)
	}

	src := observeIdentity(ctx, rc, c.label)
	if !src.Armed {
		r := certify.Skipped("INAPPLICABLE to this run: %s", src.Why)
		r.Assertions = []certify.Assertion{{
			Claim:    c.skipClaim,
			Method:   "the DUT's IEEE 2030.5 client certificate, observed on the bench's 2030.5 server",
			Verdict:  certify.Skip,
			Observed: src.Why,
			Note:     scopeNote,
		}}
		return r, nil
	}

	return certify.Result{
		Verdict: certify.Skip,
		Notes: fmt.Sprintf("waited %s for the DUT's 2030.5 client to dial %s (%s); the verdict is formed in "+
			"the citation phase from the certificate it presented",
			src.Waited.Round(time.Second), src.Endpoint, src.WaitWhy),
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			w, skipWhy := src.handshake(ev)
			if w == nil {
				a := ev.SkipAssertion(c.skipClaim, certificateCitationMethod, skipWhy)
				a.Note = joinNote(a.Note, scopeNote)
				return []certify.Assertion{a}, nil
			}
			// The DUT is the CLIENT on this connection, so its identity is the
			// client Certificate message.
			leaf, leafWhy := leafFacts(w.ClientCertificate)
			if leaf == nil {
				a := ev.SkipAssertion(c.skipClaim, certificateCitationMethod,
					leafWhy+"; "+joinNotes(w.Notes))
				a.Note = joinNote(a.Note, scopeNote)
				return []certify.Assertion{a}, nil
			}
			return c.assert(ev, certRef{Dir: w.ClientDir, Msg: w.ClientCertificate}, leaf)
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
		assert: func(ev *certify.Evidence, ref certRef, leaf *CertFacts) ([]certify.Assertion, error) {
			var out []certify.Assertion

			v := certify.Fail
			observed := fmt.Sprintf("Subject %q carries %d relative distinguished name(s); "+
				"IEEE 2030.5-2018 requires the Subject DN to be an empty SEQUENCE",
				leaf.Subject(), leaf.SubjectRDNs)
			if leaf.SubjectEmpty {
				v = certify.Pass
				observed = "the Subject DN is an empty SEQUENCE (0 relative distinguished names)"
			}
			a, err := citeCert(ev, ref.Dir, ref.Msg, claimEmptySubject, v, observed)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			v, observed = identityObservation(leaf)
			b, err := citeCert(ev, ref.Dir, ref.Msg, claimSANIdentity, v, observed)
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
		assert: func(ev *certify.Evidence, ref certRef, leaf *CertFacts) ([]certify.Assertion, error) {
			v := certify.Fail
			observed := "no (hwType, hwSerialNum) pair is present in the DUT's leaf"
			if leaf.Identity != nil {
				v = certify.Pass
				observed = "hwType=" + leaf.Identity.HWType.String() + ", hwSerialNum=" + leaf.Identity.Serial
			}
			a, err := citeCert(ev, ref.Dir, ref.Msg, claimIdentityTuple, v, observed)
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
		assert: func(ev *certify.Evidence, ref certRef, leaf *CertFacts) ([]certify.Assertion, error) {
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
			a, err := citeCert(ev, ref.Dir, ref.Msg, claimModelOIDPEN, v, observed)
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
			b, err := citeCert(ev, ref.Dir, ref.Msg, claimPENPublished, pv, pobs)
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
		assert: func(ev *certify.Evidence, ref certRef, leaf *CertFacts) ([]certify.Assertion, error) {
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
			a, err := citeCert(ev, ref.Dir, ref.Msg, claimSerialOctetString, v, observed)
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
			b, err := citeCert(ev, ref.Dir, ref.Msg, claimSerialUTF8, uv, uobs)
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

// ---------------------------------------------------------------------------
// Where the 2030.5 identity certificate comes from
// ---------------------------------------------------------------------------

// identitySource is a passive observation of the DUT's IEEE 2030.5 client
// certificate on the bench's 2030.5 server.
//
// Passive because it has to be. The DUT's 2030.5 identity is a CLIENT
// credential — the gateway dials the utility server, not the other way round —
// so there is no port the bench can connect to and be shown it. Making the
// gateway dial on demand would mean changing its northbound configuration or
// restarting a service, and a shared bench forbids both. So the endpoint is
// claimed for this case's window, the check waits a poll interval, and the
// citation phase finds the handshake if one happened.
type identitySource struct {
	// Endpoint is the bench's 2030.5 server the DUT dials.
	Endpoint netip.AddrPort
	// DUTHost is the DUT's address, to tell its side of the conversation from
	// the server's.
	DUTHost netip.Addr
	// Waited is how long the check actually waited.
	Waited time.Duration
	// WaitWhy explains where the wait came from — the DUT's own configured
	// cadence, or a fallback, and which.
	WaitWhy string
	// Armed is false when the observation could not be set up at all.
	Armed bool
	// Why records the reason when it is not armed, or when nothing arrived.
	Why string
}

// observeIdentity claims the bench's 2030.5 endpoint and waits for the DUT's
// own poll.
func observeIdentity(ctx context.Context, rc *certify.RunCtx, label string) *identitySource {
	src := &identitySource{}
	target := rc.Targets.GridSim
	if target == "" {
		src.Why = "no IEEE 2030.5 server is configured for the DUT to dial (-gridsim host:port), and this " +
			"profile governs the DUT's 2030.5 device certificate — not the mbaps leaf that a Secure SunSpec " +
			"Modbus connection happens to present"
		return src
	}
	ep, err := certify.AddrPort(target)
	if err != nil {
		src.Why = fmt.Sprintf("the 2030.5 server address %q is not an ip:port: %v", target, err)
		return src
	}
	src.Endpoint = ep
	if h, herr := netip.ParseAddr(rc.Targets.GatewayHost); herr == nil {
		src.DUTHost = h
	}
	reason := "the DUT's IEEE 2030.5 client dials the bench's 2030.5 server on its own schedule; this suite " +
		"is forbidden from reconfiguring or restarting the DUT to trigger it, so it claims every conversation " +
		"with " + ep.String() + " inside this test case's window. The certificate under test is the one the " +
		"DUT presents there — its 2030.5 device identity — and it is the only certificate this profile governs."
	if err := rc.ClaimEndpointDuring("tcp", ep, reason); err != nil {
		src.Why = "the endpoint claim was refused: " + err.Error()
		return src
	}
	src.Armed = true
	wait, why := rc.ObservationWait(ctx, certify.ObservationSpec{
		What:       "IEEE 2030.5 discovery interval",
		ConfigPath: "/etc/lexa/northbound.json",
		Field:      "discovery_interval_s",
		Fallback:   90 * time.Second,
		Param:      "pki.identity_wait",
		// This is the walk whose rate the SERVER sets: the DUT ships in
		// poll_rate_mode "honor", so discovery_interval_s bounds the rate from
		// below and gridsim's advertised pollRate is what the client keeps to.
		// Derived from the floor alone, this window was only ever long enough
		// because the bench happens to launch gridsim with -poll-rate-s 60.
		ServerPollRate: true,
	})
	src.WaitWhy = why
	start := time.Now()
	rc.Logf("%s: waiting %s for the DUT's 2030.5 client to dial %s", label, wait, ep)
	_ = rc.Sleep(ctx, wait)
	src.Waited = time.Since(start)
	return src
}

// handshake finds the DUT's 2030.5 conversation among this case's frames.
func (src *identitySource) handshake(ev *certify.Evidence) (*WireHandshake, string) {
	if !ev.HasFrames() {
		return nil, fmt.Sprintf("the DUT opened no IEEE 2030.5 connection to %s during the %s this check "+
			"waited (%s), so its 2030.5 device certificate is not in this bundle. %s", src.Endpoint,
			src.Waited.Round(time.Second), src.WaitWhy, scopeNote)
	}
	for _, st := range ev.Streams() {
		a, b := endpointAddr(st.Key.A), endpointAddr(st.Key.B)
		var client netip.AddrPort
		switch {
		case b == src.Endpoint:
			client = a
		case a == src.Endpoint:
			client = b
		default:
			continue
		}
		if src.DUTHost.IsValid() && client.Addr() != src.DUTHost {
			continue
		}
		w, err := ReadWireHandshake(st, src.Endpoint, ev.KeyLog)
		if err != nil {
			continue
		}
		if w.ClientCertificate != nil {
			return w, ""
		}
	}
	return nil, fmt.Sprintf("no IEEE 2030.5 handshake carrying the DUT's client certificate appears in the "+
		"%d frame(s) attributed to this test case during the %s it waited (%s). %s",
		len(ev.Frames()), src.Waited.Round(time.Second), src.WaitWhy, scopeNote)
}

// paramIdentityTarget names an endpoint presenting the DUT's IEEE 2030.5
// identity as a SERVER certificate.
const paramIdentityTarget = "pki.identity-target"

// dialIdentityCase is runLeafCase against an endpoint that serves the identity
// certificate, rather than a peer that presents it as a client.
func dialIdentityCase(ctx context.Context, rc *certify.RunCtx, c leafCase, target string) (certify.Result, error) {
	ident, identWhy := benchIdentity(rc)
	if ident == nil {
		rc.Logf("presenting no client certificate: %s", identWhy)
	}
	s, err := dialTarget(ctx, rc, target, c.label, HandshakeOptions{Identity: ident.TLS()})
	if err != nil {
		// The check could not be carried out. That is a FAIL with no
		// conformance conclusion, which the runner records as such — never a
		// SKIP, because "we could not test it" must not read like "it passed".
		return certify.Result{}, err
	}

	var socketLeaf *CertFacts
	why := "the peer presented no certificate"
	if s.Facts.Chain != nil {
		socketLeaf, why = s.Facts.Chain.Leaf(), ""
	}
	verdict, notes := c.decide(socketLeaf, why)
	if !s.Facts.Completed {
		notes += fmt.Sprintf(" (the handshake did not complete: %s; the peer's certificate arrives before "+
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
			out, err := c.assert(ev, certRef{Dir: w.ServerDir, Msg: w.ServerCertificate}, leaf)
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
