package suitepki

// servechain.go mints the SERVER chains a conformance check installs on the
// bench's 2030.5 server through gridsim's runtime chain lever — the four
// COMM-004 rejection fixtures.
//
// It lives beside mint.go rather than inside the CSIP suite because the CA and
// leaf machinery is here, and because these are PKI facts: what makes a MICA
// non-conformant is a statement about X.509 and RFC 5280, not about 2030.5
// message flow. The CSIP suite decides what to do with the DUT's reaction; this
// file decides what the DUT is shown.
//
// # What each fixture is, and why it is defective in the way the row names
//
// COMM-004 D — "a MICA whose extendedKeyUsage extension is marked critical with
// an invalid value". A CRITICAL extension is one the relying party MUST
// understand or reject (RFC 5280 §4.2). The MICA here carries an EKU marked
// critical whose only purpose OID is a private-arc value under lexa's PEN that
// means nothing to anybody, and which does NOT include id-kp-serverAuth. A
// verifier that enforces EKU chaining (RFC 5280 §4.2.1.12's nested constraint,
// as every mainstream stack implements it) cannot issue a serverAuth leaf under
// it, and one that merely honours criticality must reject the unrecognised
// purpose. Either route is a rejection; the row does not care which.
//
// COMM-004 E — "a MICA whose name extension is non-critical with an invalid
// value". The name extension of a CA is nameConstraints (2.5.29.30), and RFC
// 5280 §4.2.1.10 is unambiguous: "Conforming CAs MUST mark this extension as
// critical". This MICA marks it NON-critical, and gives it a permittedSubtrees
// naming a dNSName the leaf beneath it does not fall under — so the extension is
// wrong in both available senses, its criticality and its content.
//
// COMM-004 F — "a MICA whose policy-mapping extension is non-critical with an
// invalid value". policyMappings is 2.5.29.33. RFC 5280 §4.2.1.5 says
// conforming CAs SHOULD mark it critical, and states flatly that "Policies MUST
// NOT be mapped either to or from the special value anyPolicy". This MICA marks
// it non-critical AND maps anyPolicy (2.5.29.32.0) to a private policy OID,
// which is the forbidden construction named in the text.
//
// COMM-004 G — "a self-signed device certificate with no chain to a trusted
// SERCA". A single self-signed end-entity certificate, issued by nobody, chained
// to nothing.
//
// # The anchor question, which decides whether these fixtures prove anything
//
// D, E and F must be anchored on the root the DUT ALREADY TRUSTS. If they are
// not, the DUT rejects them for the trivial reason "I do not know this root",
// the check records a rejection, and the row passes without ever exercising the
// defect it is named for — a false PASS, which is worse than a SKIP. Hence
// InvalidMICAChain takes the SERCA to build under rather than minting one, and
// the caller is expected to have adopted the bench root (BenchRoot) and to have
// checked that it is in fact the anchor the bench's normal chain uses.
//
// G is different and needs no anchor: "chains to nothing" is the whole defect.

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// Extension OIDs used by the defective MICAs. Named here rather than inline so
// the fixture and the prose above cannot drift apart.
var (
	// OIDExtKeyUsage is RFC 5280 §4.2.1.12.
	OIDExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	// OIDNameConstraints is RFC 5280 §4.2.1.10 — the CA "name" extension, which
	// conforming CAs MUST mark critical.
	OIDNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
	// OIDPolicyMappings is RFC 5280 §4.2.1.5.
	OIDPolicyMappings = asn1.ObjectIdentifier{2, 5, 29, 33}
	// OIDAnyPolicy is the anyPolicy special value, 2.5.29.32.0. RFC 5280
	// §4.2.1.5: policies MUST NOT be mapped either to or from it.
	OIDAnyPolicy = asn1.ObjectIdentifier{2, 5, 29, 32, 0}
	// OIDInvalidPurpose is a private-arc OID under lexa's PEN used as the
	// meaningless extendedKeyUsage purpose of the D fixture. It is deliberately
	// under a PEN we control so it can never collide with a real purpose some
	// stack decides to honour.
	OIDInvalidPurpose = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 99, 1}
	// OIDInvalidPolicy is the private policy OID the F fixture maps anyPolicy
	// onto, for the same reason.
	OIDInvalidPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 99, 2}
)

// MICADefect names one of the deliberately non-conformant MICA extensions the
// COMM-004 rejection sub-tests present. The string values are the fixture names
// a report prints.
type MICADefect string

// The MICA defects this package can mint. See the file comment for what each
// one is and which document says it is wrong.
const (
	MICAEKUCritical     MICADefect = "invalid-mica-eku-critical"
	MICANameNonCritical MICADefect = "invalid-mica-name-noncritical"
	MICAPolicyMapping   MICADefect = "invalid-mica-policymapping-noncritical"
	// SelfSignedLeaf is not a MICA defect at all — there is no MICA. It is
	// carried in the same type so one table can describe all four sub-tests.
	SelfSignedLeaf MICADefect = "self-signed-device-certificate"
)

// AllMICADefects is the D/E/F/G order the catalog registers the sub-tests in.
var AllMICADefects = []MICADefect{MICAEKUCritical, MICANameNonCritical, MICAPolicyMapping, SelfSignedLeaf}

// NeedsAnchor reports whether a fixture must be issued under the root the DUT
// already trusts for the sub-test to mean anything. See the file comment.
func (d MICADefect) NeedsAnchor() bool { return d != SelfSignedLeaf }

// Description is the defect in the language a bundle prints, with the clause of
// the document that condemns it.
func (d MICADefect) Description() string {
	switch d {
	case MICAEKUCritical:
		return "an intermediate CA whose extendedKeyUsage extension is marked CRITICAL and carries a " +
			"single meaningless purpose OID (" + OIDInvalidPurpose.String() + "), so it neither permits " +
			"id-kp-serverAuth beneath it nor names a purpose a relying party can recognise (RFC 5280 " +
			"§4.2: a critical extension the verifier does not understand MUST cause rejection)"
	case MICANameNonCritical:
		return "an intermediate CA whose nameConstraints extension (2.5.29.30 — the CA name extension) is " +
			"marked NON-CRITICAL, which RFC 5280 §4.2.1.10 forbids (\"Conforming CAs MUST mark this " +
			"extension as critical\"), and whose permittedSubtrees names a dNSName the leaf beneath it " +
			"does not fall under"
	case MICAPolicyMapping:
		return "an intermediate CA whose policyMappings extension (2.5.29.33) is marked NON-CRITICAL and " +
			"maps anyPolicy (2.5.29.32.0) onto a private policy OID, the construction RFC 5280 §4.2.1.5 " +
			"forbids outright (\"Policies MUST NOT be mapped either to or from the special value anyPolicy\")"
	case SelfSignedLeaf:
		return "a self-signed end-entity certificate issued by nobody, with no chain to any trusted SERCA"
	default:
		return string(d)
	}
}

// ServerChain is a server credential to install on the bench's 2030.5 listener:
// the PEM the peer will present (leaf first, then intermediates, never the
// anchor) and the key that goes with it.
type ServerChain struct {
	// Defect names which sub-test this chain is for.
	Defect MICADefect
	// Label is what the bench and the report call this chain.
	Label string
	// CertPEM is the chain to present, leaf first.
	CertPEM []byte
	// KeyPEM is the leaf's PKCS#8 private key.
	KeyPEM []byte
	// LeafSHA256 is the hex SHA-256 of the leaf's DER — the fact that settles,
	// against the capture, whether this chain was the one on the wire.
	LeafSHA256 string
	// ChainLen is how many certificates CertPEM holds.
	ChainLen int
	// AnchorSubject is the DN of the root this chain expects the peer to hold,
	// empty for the self-signed fixture.
	AnchorSubject string
}

// ServerLeafSpec describes the end-entity certificate the fixture chains carry.
// It is the SERVER identity the DUT dials, so it needs the bench's hostname or
// address in its SAN like any other server certificate.
type ServerLeafSpec struct {
	// CommonName goes in the leaf's subject.
	CommonName string
	// DNSNames and IPAddresses populate the SAN. A fixture whose SAN does not
	// cover the address the DUT dials is rejected for the wrong reason, so a
	// caller must fill at least one of these with what the bench serves on.
	DNSNames    []string
	IPAddresses []string
}

// MintServerChain builds the fixture chain for one COMM-004 rejection sub-test.
//
// serca is the trust anchor to build under, and is REQUIRED for the three
// invalid-MICA defects (see the file comment on why anchoring elsewhere turns
// the sub-test into a false PASS). It is ignored for the self-signed fixture.
func MintServerChain(defect MICADefect, serca *CA, leaf ServerLeafSpec) (*ServerChain, error) {
	spec := LeafSpec{
		Name:        string(defect) + " server leaf",
		CommonName:  leaf.CommonName,
		DNSNames:    leaf.DNSNames,
		IPAddresses: parseIPs(leaf.IPAddresses),
		Server:      true,
		Client:      true,
	}
	if spec.CommonName == "" {
		spec.CommonName = "csip-tls-test COMM-004 fixture server"
	}

	if defect == SelfSignedLeaf {
		l, err := MintSelfSigned(spec)
		if err != nil {
			return nil, err
		}
		return assembleServerChain(defect, l, "")
	}

	if serca == nil {
		return nil, fmt.Errorf("suitepki: fixture %q must be issued under the root the DUT already trusts; "+
			"minting it under a fresh root would have the DUT reject it for not knowing the root, which "+
			"is not the defect this sub-test is about", defect)
	}
	mica, err := newDefectiveMICA(defect, serca)
	if err != nil {
		return nil, err
	}
	l, err := Mint(mica, spec)
	if err != nil {
		return nil, err
	}
	return assembleServerChain(defect, l, serca.Cert.Subject.String())
}

// newDefectiveMICA mints the intermediate CA carrying one deliberate defect.
func newDefectiveMICA(defect MICADefect, serca *CA) (*CA, error) {
	var ext pkix.Extension
	switch defect {
	case MICAEKUCritical:
		val, err := asn1.Marshal([]asn1.ObjectIdentifier{OIDInvalidPurpose})
		if err != nil {
			return nil, fmt.Errorf("suitepki: marshal the invalid extendedKeyUsage: %w", err)
		}
		ext = pkix.Extension{Id: OIDExtKeyUsage, Critical: true, Value: val}
	case MICANameNonCritical:
		val, err := marshalNameConstraints("invalid.example")
		if err != nil {
			return nil, err
		}
		// Critical: false is THE defect — RFC 5280 §4.2.1.10 requires true.
		ext = pkix.Extension{Id: OIDNameConstraints, Critical: false, Value: val}
	case MICAPolicyMapping:
		val, err := marshalPolicyMappings(OIDAnyPolicy, OIDInvalidPolicy)
		if err != nil {
			return nil, err
		}
		// Critical: false, mapping FROM anyPolicy — both halves are the defect.
		ext = pkix.Extension{Id: OIDPolicyMappings, Critical: false, Value: val}
	default:
		return nil, fmt.Errorf("suitepki: %q is not an invalid-MICA defect", defect)
	}
	return NewCAExt("csip-tls-test "+string(defect)+" MICA", serca, 0, []pkix.Extension{ext})
}

// marshalNameConstraints builds a NameConstraints whose permittedSubtrees holds
// one dNSName. RFC 5280 §4.2.1.10:
//
//	NameConstraints ::= SEQUENCE {
//	     permittedSubtrees  [0] GeneralSubtrees OPTIONAL,
//	     excludedSubtrees   [1] GeneralSubtrees OPTIONAL }
//	GeneralSubtree  ::= SEQUENCE { base GeneralName, minimum [0] ... , maximum [1] ... }
//
// Both the [0] on permittedSubtrees and the [2] on dNSName are IMPLICIT, so the
// tags REPLACE the SEQUENCE / IA5String tags rather than wrapping them — the
// same trap mint.go's file comment documents for otherName.
func marshalNameConstraints(dnsBase string) ([]byte, error) {
	base, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(dnsBase), // dNSName [2] IMPLICIT IA5String
	})
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal nameConstraints dNSName: %w", err)
	}
	subtree, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: base,
	})
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal GeneralSubtree: %w", err)
	}
	permitted, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: subtree,
	})
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal permittedSubtrees: %w", err)
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: permitted,
	})
}

// marshalPolicyMappings builds a single-entry PolicyMappings. RFC 5280 §4.2.1.5:
//
//	PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
//	     issuerDomainPolicy   CertPolicyId,
//	     subjectDomainPolicy  CertPolicyId }
func marshalPolicyMappings(issuerPolicy, subjectPolicy asn1.ObjectIdentifier) ([]byte, error) {
	from, err := asn1.Marshal(issuerPolicy)
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal issuerDomainPolicy: %w", err)
	}
	to, err := asn1.Marshal(subjectPolicy)
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal subjectDomainPolicy: %w", err)
	}
	pair, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append([]byte{}, from...), to...),
	})
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal policy mapping: %w", err)
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: pair,
	})
}

// assembleServerChain renders a minted leaf as installable PEM.
func assembleServerChain(defect MICADefect, l *Leaf, anchorSubject string) (*ServerChain, error) {
	key, err := l.KeyPEM()
	if err != nil {
		return nil, err
	}
	chain := l.ChainDER()
	sc := &ServerChain{
		Defect:        defect,
		Label:         "COMM-004 " + string(defect),
		CertPEM:       l.CertPEM(),
		KeyPEM:        key,
		LeafSHA256:    SHA256Hex(l.DER),
		ChainLen:      len(chain),
		AnchorSubject: anchorSubject,
	}
	return sc, nil
}

// LoadCAKeyPath derives the key path beside a fixture-tree CA certificate,
// which is the tree's own -cert.pem / -key.pem convention.
func LoadCAKeyPath(certPath string) string {
	return strings.TrimSuffix(certPath, "-cert.pem") + "-key.pem"
}

// BenchRoot adopts the bench root CA from the fixture tree's ca-cert.pem, which
// is the trust anchor the DUT's trust domain is configured with.
//
// It returns a REASON rather than an error when the material is not available,
// because "the bench root's private key is not on this machine" is a legitimate
// state of a conformance workstation and the right response to it is a SKIP
// naming the fact — not a failure attributed to the DUT.
func BenchRoot(caCertPath string) (*CA, string) {
	if caCertPath == "" {
		return nil, "no mbaps certificate fixtures are configured (-pki)"
	}
	keyPath := LoadCAKeyPath(caCertPath)
	if _, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Sprintf("the bench root CA's private key (%s) is not readable on this "+
			"workstation (%v), so this check can only mint material the DUT is required to REJECT for "+
			"the wrong reason", keyPath, err)
	}
	ca, err := AdoptCAFromFiles("bench root CA", caCertPath, keyPath)
	if err != nil {
		return nil, fmt.Sprintf("the bench root CA could not be adopted (%v) — this check can only "+
			"mint material the DUT is required to REJECT, not material anchored where the DUT's trust "+
			"domain actually is", err)
	}
	return ca, ""
}

// parseIPs converts textual addresses, dropping anything that is not one. A bad
// address is dropped rather than fatal: the DNS names may still cover the
// fixture, and a fixture that refused to mint teaches nothing at all.
func parseIPs(in []string) []net.IP {
	var out []net.IP
	for _, s := range in {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// SHA256Hex is the fingerprint form this package and the bench's chain lever
// both speak: lower-case hex of the SHA-256 of a certificate's DER.
func SHA256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
