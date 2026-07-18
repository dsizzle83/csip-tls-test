//go:build integration

package main

// testpki_test.go mints a throwaway CA + server leaf + role-bearing client
// leaf at runtime, so the integration tests are self-contained — the same
// approach internal/mbtls/testpki_test.go and sim/tlsserver's chain
// integration tests use (no committed fixtures; certs/mbaps/ role-fixture
// generation is T06.1, out of this package's scope). mbtls.RoleOID is
// exported (role.go, not a _test.go file) so the role extension here is
// built against the SAME OID mbtls.RoleFromDER parses — this file does not
// reimplement or diverge from that OID, only from mbtls's PRIVATE minting
// helpers, which _test.go visibility rules make unreachable from this
// package anyway.

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
	"path/filepath"
	"testing"
	"time"

	"csip-tls-test/internal/mbtls"
)

type certKey struct {
	der []byte
	key *ecdsa.PrivateKey
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return key
}

func mkCert(t *testing.T, cn string, isCA bool, parent *certKey, sans []string, exts []pkix.Extension) certKey {
	t.Helper()
	key := genKey(t)
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
	signerCert, signerKey := tmpl, key
	if parent != nil {
		pc, err := x509.ParseCertificate(parent.der)
		if err != nil {
			t.Fatalf("parse parent: %v", err)
		}
		signerCert, signerKey = pc, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert %q: %v", cn, err)
	}
	return certKey{der: der, key: key}
}

// roleExt builds a conformant mbaps role extension (OID + single UTF8String),
// against the package's own RoleOID — see file doc comment.
func roleExt(t *testing.T, role string) pkix.Extension {
	t.Helper()
	b, err := asn1.MarshalWithParams(role, "utf8")
	if err != nil {
		t.Fatalf("marshal utf8 role: %v", err)
	}
	return pkix.Extension{Id: mbtls.RoleOID, Value: b}
}

func writeCertPEM(t *testing.T, path string, der []byte) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// testPKI holds the on-disk PEM fixtures the loopback tests dial with: a
// device server leaf (no role — TCP-28) and a SuperAdministratorSunSpec
// client leaf (the southbound identity a real gateway presents,
// ARCHITECTURE.md §6), both under one CA.
type testPKI struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	ca := mkCert(t, "mbapsdev test CA", true, nil, nil, nil)

	server := mkCert(t, "mbapsdev device", false, &ca, []string{"127.0.0.1", "localhost"}, nil)
	client := mkCert(t, "client-SuperAdministratorSunSpec", false, &ca, nil,
		[]pkix.Extension{roleExt(t, "SuperAdministratorSunSpec")})

	p := testPKI{
		caFile:         filepath.Join(dir, "ca.pem"),
		serverCertFile: filepath.Join(dir, "server-cert.pem"),
		serverKeyFile:  filepath.Join(dir, "server-key.pem"),
		clientCertFile: filepath.Join(dir, "client-cert.pem"),
		clientKeyFile:  filepath.Join(dir, "client-key.pem"),
	}
	writeCertPEM(t, p.caFile, ca.der)
	writeCertPEM(t, p.serverCertFile, server.der)
	writeKeyPEM(t, p.serverKeyFile, server.key)
	writeCertPEM(t, p.clientCertFile, client.der)
	writeKeyPEM(t, p.clientKeyFile, client.key)
	return p
}

func (p testPKI) serverProfile() mbtls.Profile {
	return mbtls.DefaultServerProfile(p.caFile, p.serverCertFile, p.serverKeyFile)
}

func (p testPKI) clientProfile() mbtls.Profile {
	return mbtls.DefaultClientProfile(p.caFile, p.clientCertFile, p.clientKeyFile)
}
