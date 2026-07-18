package mbtls

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// RoleOID is the Secure SunSpec Modbus client-role certificate extension:
// 1.3.6.1.4.1.50316.802.1, whose value is a single ASN.1 UTF8String naming the
// role (SunSpecTCP-29/30). It is transcribed here from the spec rather than
// imported from securemodbus/role so the bench's role ASSERTION path stays
// independent of the product's (referee independence, PN-1). A copy of the OID
// may be reused for cert MINTING convenience; the extraction below is the
// bench's own referee.
var RoleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

// The role-extraction error taxonomy (design doc 01 §3.1). At a gateway's AuthZ
// layer ALL of these — plus a well-formed-but-unknown or empty role string —
// collapse to "no role" ⇒ exception 01 on every request, with the TLS session
// left up. The bench keeps them distinct so a conformance check can assert the
// gateway rejected for the RIGHT reason, not merely that it rejected.
var (
	// ErrNoRole: the role extension is absent from the certificate.
	ErrNoRole = errors.New("mbtls: certificate carries no role extension")
	// ErrBadEncoding: the extension is present but its value is not a single,
	// cleanly-encoded ASN.1 UTF8String (e.g. PrintableString, or trailing
	// bytes).
	ErrBadEncoding = errors.New("mbtls: role extension is not a single UTF8String")
	// ErrMultipleRoles: more than one role extension is present. The spec
	// mandates exactly one.
	ErrMultipleRoles = errors.New("mbtls: certificate carries multiple role extensions")
)

// RoleFromDER extracts the mbaps role string from a DER-encoded leaf
// certificate. It is a pure extractor: it returns the role EXACTLY as encoded,
// including a well-formed empty string ("") or an over-long string, with no
// error — such values are structurally valid but semantically unauthorized, and
// that rejection is the AuthZ layer's job, not the parser's (design doc 01
// §3.1). Errors are returned only for structural faults: absent extension
// (ErrNoRole), multiple extensions (ErrMultipleRoles), or an extension value
// that is not a single UTF8String (ErrBadEncoding — e.g. the PrintableString
// negative fixture).
//
// Extensions are walked with a deliberately lenient encoding/asn1 pass over the
// certificate structure rather than crypto/x509.ParseCertificate, because the
// standard parser REJECTS a duplicate-OID certificate outright (a "duplicate
// extension" error) before any role logic runs — which would make
// ErrMultipleRoles unreachable and leave the referee's two-role verdict at the
// mercy of Go's x509 strictness. The bench owns its own extension walk so its
// role taxonomy is defined by the spec, not by a third-party parser's quirks.
// This is CGo-free (CODING_PRINCIPLES §4: everything parseable stays in Go).
func RoleFromDER(der []byte) (string, error) {
	exts, err := certExtensions(der)
	if err != nil {
		return "", fmt.Errorf("mbtls: parse peer certificate: %w", err)
	}

	var value []byte
	count := 0
	for _, ext := range exts {
		if ext.Id.Equal(RoleOID) {
			count++
			value = ext.Value
		}
	}
	switch count {
	case 0:
		return "", ErrNoRole
	case 1:
		// ok
	default:
		return "", ErrMultipleRoles
	}

	// The value MUST be a single UTF8String (SunSpecTCP-30). encoding/asn1's
	// "utf8" param governs only MARSHALLING — unmarshalling into a Go string
	// accepts any string tag (PrintableString, IA5String, ...) — so the tag is
	// checked explicitly here. A PrintableString value (the bad-encoding
	// fixture) fails this check, as does any tagged non-string or trailing data.
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(value, &raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadEncoding, err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("%w: %d trailing byte(s) after role value", ErrBadEncoding, len(rest))
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagUTF8String || raw.IsCompound {
		return "", fmt.Errorf("%w: expected UTF8String (class 0 tag 12), got class %d tag %d compound=%t",
			ErrBadEncoding, raw.Class, raw.Tag, raw.IsCompound)
	}
	return string(raw.Bytes), nil
}

// certExtensions returns the raw extension list from a DER certificate,
// tolerating duplicate OIDs (unlike crypto/x509). It parses only as far into
// the X.509 structure as it must to reach the extensions [3] field; the middle
// TBSCertificate fields are absorbed as opaque RawValues.
func certExtensions(der []byte) ([]pkix.Extension, error) {
	var cert certificateDER
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, err
	}
	return cert.TBS.Extensions, nil
}

// certificateDER / tbsCertificateDER mirror RFC 5280 Certificate /
// TBSCertificate just far enough to reach the extensions. Fields the referee
// does not read are opaque asn1.RawValue so any conformant cert parses.
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
