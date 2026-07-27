package tlsdis

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// RoleOID is the Secure SunSpec Modbus client-role certificate extension:
// 1.3.6.1.4.1.50316.802.1, whose value is a single ASN.1 UTF8String naming the
// role (SunSpecTCP-29/30).
//
// It is transcribed from the specification here rather than imported from the
// bench's mbtls package for two independent reasons. The referee-independence
// rule (PN-1/C9) says the evidence engine's view of the wire must not share an
// implementation with the thing it is refereeing. And mbtls is cgo — it links
// wolfSSL — while every line of the evidence engine has to build with
// CGO_ENABLED=0 so a third party can run the verifier with nothing but a Go
// toolchain.
var RoleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

// Role-extraction errors. A gateway's authorization layer collapses all of
// these to "no role"; the bench keeps them apart so a report can say the DUT
// was rejected for the RIGHT reason.
var (
	// ErrNoRole: the certificate carries no role extension.
	ErrNoRole = errors.New("tlsdis: certificate carries no role extension")
	// ErrBadRoleEncoding: the extension is present but is not a single, cleanly
	// encoded ASN.1 UTF8String.
	ErrBadRoleEncoding = errors.New("tlsdis: role extension is not a single UTF8String")
	// ErrMultipleRoles: more than one role extension is present; the spec
	// mandates exactly one.
	ErrMultipleRoles = errors.New("tlsdis: certificate carries multiple role extensions")
)

// CertExtension is one X.509 extension with its value preserved as raw DER.
//
// Every extension is reported, not just the ones this package understands. The
// custom ones are the point: proving a private-enterprise OID was present, and
// encoded the way the specification demands, is a pass criterion, and it can
// only be re-checked by a third party if the exact bytes travel with the claim.
type CertExtension struct {
	OID      string // dotted decimal
	Critical bool
	Value    []byte // the extension's DER value, verbatim
	ValueHex string
	// Standard marks the RFC 5280 (and other well-known) extensions, so a
	// report can list "custom extensions" without a hard-coded exclusion list
	// at the call site.
	Standard bool
	// UTF8String is set when Value decodes as exactly one ASN.1 UTF8String,
	// which is the encoding the SunSpec role extension requires.
	UTF8String string
}

// CertInfo is a dissected X.509 certificate.
type CertInfo struct {
	DER    []byte
	SHA256 string // hex digest of the DER, the stable identifier for citations

	Version            int
	SerialHex          string
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	PublicKeyBits      int
	Curve              string
	SignatureAlgorithm string

	BasicConstraintsValid bool
	IsCA                  bool
	MaxPathLen            int
	MaxPathLenZero        bool
	KeyUsage              []string
	ExtKeyUsage           []string
	UnknownExtKeyUsage    []string

	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	URIs           []string

	Extensions []CertExtension

	SelfIssued bool
	// ParseError records a crypto/x509 failure. The extension list is still
	// populated in that case, because the certificates most worth reporting on
	// are exactly the ones the standard parser rejects.
	ParseError string
}

// ParseCertInfo dissects a DER certificate.
//
// The extension list is always built with this package's own lenient ASN.1
// walk rather than from x509.Certificate.Extensions. crypto/x509 REJECTS a
// certificate carrying two extensions with the same OID outright, which would
// make the "exactly one role extension" requirement (SunSpecTCP-31) impossible
// to fail-report: the certificate the test is about would simply not parse.
// The bench owns its own walk so its verdicts are defined by the specification,
// not by a third-party parser's strictness.
func ParseCertInfo(der []byte) (*CertInfo, error) {
	sum := sha256.Sum256(der)
	ci := &CertInfo{DER: der, SHA256: hex.EncodeToString(sum[:])}

	exts, extErr := rawExtensions(der)
	for _, e := range exts {
		ce := CertExtension{
			OID:      e.Id.String(),
			Critical: e.Critical,
			Value:    e.Value,
			ValueHex: hex.EncodeToString(e.Value),
			Standard: standardExtensionOIDs[e.Id.String()],
		}
		if s, ok := singleUTF8String(e.Value); ok {
			ce.UTF8String = s
		}
		ci.Extensions = append(ci.Extensions, ce)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		ci.ParseError = err.Error()
		if extErr != nil {
			return ci, fmt.Errorf("tlsdis: certificate does not parse (%v) and its extensions are unreadable: %w", err, extErr)
		}
		return ci, fmt.Errorf("tlsdis: parse certificate: %w", err)
	}

	ci.Version = cert.Version
	ci.SerialHex = strings.ToUpper(cert.SerialNumber.Text(16))
	ci.Subject = cert.Subject.String()
	ci.Issuer = cert.Issuer.String()
	ci.NotBefore = cert.NotBefore.UTC()
	ci.NotAfter = cert.NotAfter.UTC()
	ci.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	ci.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
	ci.BasicConstraintsValid = cert.BasicConstraintsValid
	ci.IsCA = cert.IsCA
	ci.MaxPathLen = cert.MaxPathLen
	ci.MaxPathLenZero = cert.MaxPathLenZero
	ci.KeyUsage = keyUsageNames(cert.KeyUsage)
	ci.ExtKeyUsage = extKeyUsageNames(cert.ExtKeyUsage)
	for _, oid := range cert.UnknownExtKeyUsage {
		ci.UnknownExtKeyUsage = append(ci.UnknownExtKeyUsage, oid.String())
	}
	ci.DNSNames = cert.DNSNames
	ci.EmailAddresses = cert.EmailAddresses
	for _, ip := range cert.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		ci.URIs = append(ci.URIs, u.String())
	}
	ci.SelfIssued = cert.Subject.String() == cert.Issuer.String()

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.PublicKeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		ci.PublicKeyBits = pub.Curve.Params().BitSize
		ci.Curve = pub.Curve.Params().Name
	case ed25519.PublicKey:
		ci.PublicKeyBits = 256
		ci.Curve = "Ed25519"
	}
	return ci, nil
}

// Extension returns the extension with the given dotted-decimal OID.
func (ci *CertInfo) Extension(oid string) (CertExtension, bool) {
	for _, e := range ci.Extensions {
		if e.OID == oid {
			return e, true
		}
	}
	return CertExtension{}, false
}

// CustomExtensions returns the extensions that are not part of the standard
// X.509 set — the vendor and private-enterprise OIDs a conformance report has
// to enumerate explicitly.
func (ci *CertInfo) CustomExtensions() []CertExtension {
	var out []CertExtension
	for _, e := range ci.Extensions {
		if !e.Standard {
			out = append(out, e)
		}
	}
	return out
}

// SunSpecRole extracts the Secure SunSpec Modbus role. See RoleFromDER for the
// error taxonomy.
func (ci *CertInfo) SunSpecRole() (string, error) { return RoleFromDER(ci.DER) }

// RoleFromDER extracts the mbaps role string from a DER leaf certificate.
//
// It is a pure extractor: a well-formed but empty or unknown role string comes
// back with no error, because such a value is structurally valid and only
// semantically unauthorized — that judgement belongs to the authorization
// layer, not the parser. Errors are reserved for structural faults: no
// extension (ErrNoRole), several extensions (ErrMultipleRoles), or a value
// that is not exactly one UTF8String (ErrBadRoleEncoding).
func RoleFromDER(der []byte) (string, error) {
	exts, err := rawExtensions(der)
	if err != nil {
		return "", fmt.Errorf("tlsdis: parse certificate extensions: %w", err)
	}
	var value []byte
	count := 0
	for _, e := range exts {
		if e.Id.Equal(RoleOID) {
			count++
			value = e.Value
		}
	}
	switch count {
	case 0:
		return "", ErrNoRole
	case 1:
	default:
		return "", ErrMultipleRoles
	}

	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(value, &raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadRoleEncoding, err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("%w: %d trailing byte(s) after the role value", ErrBadRoleEncoding, len(rest))
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagUTF8String || raw.IsCompound {
		return "", fmt.Errorf("%w: expected UTF8String (class 0 tag 12), got class %d tag %d compound=%t",
			ErrBadRoleEncoding, raw.Class, raw.Tag, raw.IsCompound)
	}
	return string(raw.Bytes), nil
}

// singleUTF8String reports whether b is exactly one ASN.1 UTF8String.
func singleUTF8String(b []byte) (string, bool) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil || len(rest) != 0 {
		return "", false
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagUTF8String || raw.IsCompound {
		return "", false
	}
	return string(raw.Bytes), true
}

// rawExtensions returns a certificate's extension list, tolerating duplicate
// OIDs. Only as much of RFC 5280's Certificate structure is decoded as it takes
// to reach the extensions [3] field; everything in between is absorbed as
// opaque RawValues so any conformant certificate parses.
func rawExtensions(der []byte) ([]pkix.Extension, error) {
	var cert certificateDER
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, err
	}
	return cert.TBS.Extensions, nil
}

type certificateDER struct {
	Raw                asn1.RawContent
	TBS                tbsCertificateDER
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type tbsCertificateDER struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	IssuerUniqueID     asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func keyUsageNames(u x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	var out []string
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageNames(us []x509.ExtKeyUsage) []string {
	name := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "ServerAuth",
		x509.ExtKeyUsageClientAuth:                     "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
		x509.ExtKeyUsageEmailProtection:                "EmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
		x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
	}
	var out []string
	for _, u := range us {
		if n, ok := name[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("UNKNOWN(%d)", int(u)))
		}
	}
	return out
}

// standardExtensionOIDs is the RFC 5280 set plus the handful of widely
// deployed additions, used only to classify an extension as standard or custom.
var standardExtensionOIDs = map[string]bool{
	"2.5.29.9":                true, // subjectDirectoryAttributes
	"2.5.29.14":               true, // subjectKeyIdentifier
	"2.5.29.15":               true, // keyUsage
	"2.5.29.16":               true, // privateKeyUsagePeriod
	"2.5.29.17":               true, // subjectAltName
	"2.5.29.18":               true, // issuerAltName
	"2.5.29.19":               true, // basicConstraints
	"2.5.29.30":               true, // nameConstraints
	"2.5.29.31":               true, // cRLDistributionPoints
	"2.5.29.32":               true, // certificatePolicies
	"2.5.29.33":               true, // policyMappings
	"2.5.29.35":               true, // authorityKeyIdentifier
	"2.5.29.36":               true, // policyConstraints
	"2.5.29.37":               true, // extKeyUsage
	"2.5.29.54":               true, // inhibitAnyPolicy
	"1.3.6.1.5.5.7.1.1":       true, // authorityInfoAccess
	"1.3.6.1.5.5.7.1.11":      true, // subjectInfoAccess
	"1.3.6.1.5.5.7.1.24":      true, // tlsFeature (must-staple)
	"1.3.6.1.4.1.11129.2.4.2": true, // signed certificate timestamps
}
