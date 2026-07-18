package mbtls

import (
	"bytes"
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
	"path/filepath"
	"testing"
	"time"
)

// testpki_test.go mints the role-bearing and negative certificate fixtures the
// mbtls tests need, at runtime, so the package is self-contained (no committed
// fixtures — the same approach as sim/tlsserver's chain_integration_test.go).
// It is the bench's own minting convenience; the ASSERTION path (RoleFromDER)
// stays independent of it (PN-1). All certs are EC P-256 (the mbaps ECDSA
// suites' key type; SunSpecTCP-42). These fixtures mirror the T06.1 matrix so
// T06.1's generator and this in-test minting share one expected-role manifest.

// certKey bundles a generated certificate, its DER, and its private key.
type certKey struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// mkCA generates a self-signed CA certificate.
func mkCA(t *testing.T, cn string) certKey {
	t.Helper()
	return mkCert(t, cn, true, nil, nil, nil)
}

// mkLeaf generates a leaf certificate signed by parent, with optional SANs and
// optional extra extensions (the role extension).
func mkLeaf(t *testing.T, cn string, parent certKey, sans []string, exts []pkix.Extension) certKey {
	t.Helper()
	return mkCert(t, cn, false, &parent, sans, exts)
}

// mkExpiredLeaf generates a leaf whose validity window is already in the past.
func mkExpiredLeaf(t *testing.T, cn string, parent certKey, sans []string) certKey {
	t.Helper()
	key := genKey(t)
	tmpl := baseTemplate(t, cn, false, sans, nil)
	tmpl.NotBefore = time.Now().Add(-48 * time.Hour)
	tmpl.NotAfter = time.Now().Add(-24 * time.Hour)
	return signWith(t, tmpl, key, &parent)
}

func mkCert(t *testing.T, cn string, isCA bool, parent *certKey, sans []string, exts []pkix.Extension) certKey {
	t.Helper()
	key := genKey(t)
	tmpl := baseTemplate(t, cn, isCA, sans, exts)
	return signWith(t, tmpl, key, parent)
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return key
}

func baseTemplate(t *testing.T, cn string, isCA bool, sans []string, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	return tmpl
}

func signWith(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey, parent *certKey) certKey {
	t.Helper()
	signerCert, signerKey := tmpl, key // self-signed by default
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert %q: %v", tmpl.Subject.CommonName, err)
	}
	// NOTE: a two-role cert is intentionally NOT re-parsed here — crypto/x509
	// rejects duplicate extensions. Callers that need the *x509.Certificate use
	// single-extension certs; the DER is always valid for wolfSSL + RoleFromDER.
	cert, _ := x509.ParseCertificate(der)
	return certKey{cert: cert, der: der, key: key}
}

// --- role extension builders (the bench's minting convenience) --------------

// roleExtUTF8 builds a conformant role extension: OID + a single UTF8String.
func roleExtUTF8(t *testing.T, role string) pkix.Extension {
	t.Helper()
	b, err := asn1.MarshalWithParams(role, "utf8")
	if err != nil {
		t.Fatalf("marshal utf8 role: %v", err)
	}
	return pkix.Extension{Id: RoleOID, Value: b}
}

// roleExtPrintable builds the bad-encoding negative: a PrintableString value
// where the spec mandates UTF8String (SunSpecTCP-30).
func roleExtPrintable(t *testing.T, role string) pkix.Extension {
	t.Helper()
	b, err := asn1.MarshalWithParams(role, "printable")
	if err != nil {
		t.Fatalf("marshal printable role: %v", err)
	}
	return pkix.Extension{Id: RoleOID, Value: b}
}

// --- PEM writers (files, because wolfSSL loads certs/keys from paths) --------

func writeCertPEM(t *testing.T, path string, ders ...[]byte) {
	t.Helper()
	var buf bytes.Buffer
	for _, der := range ders {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatalf("pem encode: %v", err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	buf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writePEMPair(t *testing.T, dir, name string, ck certKey) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	writeCertPEM(t, certPath, ck.der)
	writeKeyPEM(t, keyPath, ck.key)
	return certPath, keyPath
}
