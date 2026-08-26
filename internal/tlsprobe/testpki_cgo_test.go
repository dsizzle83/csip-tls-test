//go:build cgo

package tlsprobe

// testpki_cgo_test.go mints the throwaway PKI the loopback tests use.
//
// It is minted rather than read from certs/mbaps because that fixture set's
// private keys are gitignored: a checkout that has never run
// `make gen-mbaps-certs` has every certificate and none of the client keys, and
// a test that skipped on their absence would be a test nobody ran.
//
// The role extension is built against internal/mbtls.RoleOID — the same OID the
// bench's own independent parser reads — so the client leaf is a realistic
// mbaps identity rather than a bare certificate.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"csip-tls-test/internal/mbtls"
)

func selfSignedCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := p256(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("mint the CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the CA: %v", err)
	}
	return cert, key
}

// leaf mints a P-256 leaf. The mandated suites are ECDSA-only (SunSpecTCP-42
// makes P-256 the curve), so an RSA fixture would be refused for a reason that
// has nothing to do with the suite under test.
func leaf(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	server bool, role string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := p256(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if role != "" {
		b, err := asn1.MarshalWithParams(role, "utf8")
		if err != nil {
			t.Fatalf("marshal the role: %v", err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: mbtls.RoleOID, Value: b}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("mint %q: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %q: %v", cn, err)
	}
	return cert, key
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a P-256 key: %v", err)
	}
	return key
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatalf("generate a serial: %v", err)
	}
	return n
}

func writeCert(t *testing.T, path string, der []byte) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal the key: %v", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
