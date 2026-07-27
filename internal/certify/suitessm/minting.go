package suitessm

// minting.go builds the certificate fixtures the committed set (certs/mbaps)
// does not carry, at run time, and loads the ones it does.
//
// The committed matrix is deliberately small — five role leaves and seven
// negatives — because every file in it is a maintained artefact. Three
// SSM-CONF-v0.8 procedures need a fixture outside that matrix:
//
//	PKI-003   a SELF-SIGNED client leaf (issuer == subject, chains to nothing)
//	RBAC-006  a leaf carrying the role under a DIFFERENT, non-compliant OID
//	TLSF-003  a leaf whose SIGNATURE does not verify ("badsig")
//
// Minting them here rather than committing them keeps the fixture directory
// honest about what it is: the inputs a human curates. A minted fixture is
// still fully evidenced — the bundle cites the certificate's DER bytes as they
// crossed the wire, with their sha256, so a reader re-derives everything about
// it from the capture and needs none of this code.
//
// Everything is EC P-256, because SunSpecTCP-42 makes P-256 the mandatory curve
// and the mandated cipher suites are ECDSA-only: an RSA fixture would be
// rejected for the wrong reason and the test would prove nothing.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5280 §4.2.1.2 method 1 specifies SHA-1 as a key identifier
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// roleOIDValue is roleOID as an ASN.1 object identifier.
var roleOIDValue = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

// wrongRoleOIDValue is a sibling arc under the same Modbus.org PEN. RBAC-006's
// provocation is a role that is PRESENT but not where SunSpecTCP-29 says to
// look, so a nearby arc is a sharper test than an unrelated OID: an
// implementation that matched on a prefix rather than the whole OID would pass
// an unrelated-OID test and fail this one.
var wrongRoleOIDValue = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 99}

// ASN.1 universal tags for the role string encodings the procedures exercise.
const (
	tagUTF8String byte = 0x0C
	tagIA5String  byte = 0x16
)

// roleExtension builds an X.509 extension carrying role at oid, encoded with
// the given ASN.1 string tag.
func roleExtension(oid asn1.ObjectIdentifier, role string, tag byte) pkix.Extension {
	body := []byte(role)
	// Roles are short; a single-byte definite length is always sufficient and
	// the specification bounds the value at 255 bytes.
	der := append([]byte{tag, byte(len(body))}, body...)
	return pkix.Extension{Id: oid, Critical: false, Value: der}
}

// mintOpts describes a leaf to mint.
type mintOpts struct {
	// CommonName is the subject CN.
	CommonName string
	// Role, when non-empty, adds a role extension.
	Role string
	// RoleOID defaults to roleOIDValue.
	RoleOID asn1.ObjectIdentifier
	// RoleTag defaults to tagUTF8String.
	RoleTag byte
	// ExtraRoleExtensions adds further role extensions, for the "two roles"
	// shape. Each entry is (oid, value, tag) already assembled.
	ExtraExtensions []pkix.Extension
	// NotBefore / NotAfter default to a one-hour-ago / one-year window.
	NotBefore, NotAfter time.Time
	// SelfSigned mints a self-issued certificate with no CA above it.
	SelfSigned bool
}

// mintLeaf issues a client leaf. When o.SelfSigned is false, issuer and
// issuerKey must be supplied and the returned tls.Certificate carries the
// issuer in its chain so the DUT can build a path.
func mintLeaf(issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, o mintOpts) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("suitessm: generate P-256 key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("suitessm: generate serial: %w", err)
	}
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.CommonName, Organization: []string{"csip-tls-test bench"}},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		// crypto/x509 emits a SubjectKeyIdentifier only for CA certificates
		// unless one is supplied. PKI-007 requires it on every certificate, so
		// a minted fixture that omitted it would fail the suite's OWN RFC 5280
		// check for a reason that has nothing to do with the DUT.
		SubjectKeyId: subjectKeyID(&key.PublicKey),
	}
	if o.Role != "" {
		oid := o.RoleOID
		if oid == nil {
			oid = roleOIDValue
		}
		tag := o.RoleTag
		if tag == 0 {
			tag = tagUTF8String
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, roleExtension(oid, o.Role, tag))
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, o.ExtraExtensions...)

	parent, parentKey := issuer, issuerKey
	if o.SelfSigned {
		parent, parentKey = tmpl, key
	}
	if parent == nil || parentKey == nil {
		return tls.Certificate{}, fmt.Errorf("suitessm: mintLeaf needs an issuer certificate and key")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("suitessm: sign leaf %q: %w", o.CommonName, err)
	}
	// A DELIBERATELY non-conformant fixture may not re-parse — crypto/x509
	// rejects a certificate carrying two extensions with the same OID outright,
	// which is exactly the two-role shape SunSpecTCP-31 exists to test. That is
	// the fixture working, not a failure: the DER is still valid to present, so
	// the Leaf is simply left unset and the bytes go on the wire regardless.
	leaf, _ := x509.ParseCertificate(der)
	chain := [][]byte{der}
	if !o.SelfSigned {
		chain = append(chain, issuer.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

// corruptSignature returns a copy of cert whose LEAF signature bytes have been
// altered, which is TLSF-003's "badsig" fixture. Everything else — the tbs
// bytes, the chain, the private key — is untouched, so the only reason a
// conformant peer can reject it is the signature check itself.
//
// The last byte of the DER is inside the signature BIT STRING for every
// ECDSA-signed certificate (the signature is the final field of the
// Certificate SEQUENCE), so flipping it is a minimal, well-defined corruption.
func corruptSignature(cert tls.Certificate) (tls.Certificate, error) {
	if len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		return tls.Certificate{}, fmt.Errorf("suitessm: corruptSignature on an empty certificate")
	}
	out := tls.Certificate{PrivateKey: cert.PrivateKey}
	for i, der := range cert.Certificate {
		c := append([]byte(nil), der...)
		if i == 0 {
			c[len(c)-1] ^= 0xFF
		}
		out.Certificate = append(out.Certificate, c)
	}
	// Leaf is left nil deliberately: the bytes no longer verify, and handing
	// crypto/tls a parsed Leaf that disagrees with the bytes would be a lie in
	// the other direction.
	return out, nil
}

// loadKeyPair reads a certify.KeyPair into a tls.Certificate, preserving the
// whole chain in the file (leaf first) so SunSpecTCP-51's full-chain delivery
// is exercised rather than accidentally reduced to a bare leaf.
func loadKeyPair(kp certify.KeyPair) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(kp.Cert, kp.Key)
	if err != nil {
		return nil, fmt.Errorf("suitessm: load fixture %q (%s / %s): %w", kp.Name, kp.Cert, kp.Key, err)
	}
	if len(c.Certificate) > 0 && c.Leaf == nil {
		if leaf, perr := x509.ParseCertificate(c.Certificate[0]); perr == nil {
			c.Leaf = leaf
		}
	}
	return &c, nil
}

// roleCert loads one of the committed role fixtures.
func roleCert(pki *certify.PKI, name string) (*tls.Certificate, error) {
	kp, err := pki.Role(name)
	if err != nil {
		return nil, err
	}
	return loadKeyPair(kp)
}

// negativeCert loads one of the committed negative fixtures.
func negativeCert(pki *certify.PKI, name string) (*tls.Certificate, error) {
	kp, err := pki.NegativeFixture(name)
	if err != nil {
		return nil, err
	}
	return loadKeyPair(kp)
}

// rootPool builds the trust anchor set this bench validates the DUT against.
// Both the root and, when present, the intermediate are added: the DUT's leaf
// chains through the intermediate, and a bench that could not verify it would
// report every handshake as untrusted.
func rootPool(pki *certify.PKI) (*x509.CertPool, error) {
	if pki == nil || pki.CA == "" {
		return nil, fmt.Errorf("suitessm: no trust anchor is configured (-pki)")
	}
	pool := x509.NewCertPool()
	for _, p := range []string{pki.CA, pki.Intermediate} {
		if p == "" {
			continue
		}
		pem, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("suitessm: read trust anchor %s: %w", p, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("suitessm: %s holds no PEM certificate", p)
		}
	}
	return pool, nil
}

// issuingCA loads the fixture set's intermediate CA and its private key, which
// is what the minted fixtures must be signed by if the DUT is to accept their
// chain at all.
//
// A missing key is an ordinary outcome, not a crash: the private keys under
// certs/mbaps are gitignored, so a checkout that has never run
// `make gen-mbaps-certs` has the certificates and not the keys. Callers turn
// the error into a SKIP naming the missing file.
func issuingCA(pki *certify.PKI) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if pki == nil {
		return nil, nil, fmt.Errorf("suitessm: no PKI fixture set is configured (-pki)")
	}
	certPath := pki.Intermediate
	if certPath == "" {
		certPath = pki.CA
	}
	if certPath == "" {
		return nil, nil, fmt.Errorf("suitessm: the fixture set at %s carries no CA certificate", pki.Dir)
	}
	keyPath := strings.TrimSuffix(certPath, "-cert.pem") + "-key.pem"
	if keyPath == certPath {
		keyPath = filepath.Join(filepath.Dir(certPath), "ca-key.pem")
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("suitessm: read issuing CA certificate %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("suitessm: the issuing CA private key %s is not available, so fixtures "+
			"that must be signed by the bench CA cannot be minted: %w", keyPath, err)
	}
	cert, err := parseFirstCert(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("suitessm: %s: %w", certPath, err)
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("suitessm: %s: %w", keyPath, err)
	}
	return cert, key, nil
}

// subjectKeyID is RFC 5280 §4.2.1.2 method 1: the SHA-1 of the DER-encoded
// subjectPublicKey BIT STRING value. SHA-1 here is an identifier, not a
// security primitive — the RFC specifies it and every path builder expects it.
func subjectKeyID(pub *ecdsa.PublicKey) []byte {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil
	}
	sum := sha1.Sum(info.Key.RightAlign())
	return sum[:]
}

func parseFirstCert(p []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, p = pem.Decode(p)
		if blk == nil {
			return nil, fmt.Errorf("no CERTIFICATE block found")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

func parseECKey(p []byte) (*ecdsa.PrivateKey, error) {
	for {
		var blk *pem.Block
		blk, p = pem.Decode(p)
		if blk == nil {
			return nil, fmt.Errorf("no private key block found")
		}
		switch blk.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("the private key is %T, not an EC key (the mandated suites are ECDSA-only)", k)
			}
			return ec, nil
		}
	}
}
