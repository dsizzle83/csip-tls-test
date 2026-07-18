package aggregator

// pki_test.go mints a throwaway EC P-256 PKI + a certs/mbaps-shaped manifest at
// runtime, so both the unit tests (LoadPKI / ConnectAs guard rails) and the
// integration test (loopback handshake) are self-contained — the committed
// certs/mbaps tree gitignores its *-key.pem, so a real key is only available by
// minting one. This is the bench's own minting convenience; the ASSERTION path
// (mbtls.RoleFromDER, via ConnectAs's self-check) stays independent of it (PN-1).
// All leaves are EC P-256 (the mbaps ECDSA suites' key type, TCP-42) and the
// role extension is built against mbtls.RoleOID — the SAME OID the parser reads,
// never a divergent copy.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
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

func mkCert(t *testing.T, cn string, isCA bool, parent *certKey, sans []string, exts []pkix.Extension) certKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
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

// testPKI is a minted certs/mbaps-shaped tree on disk: one CA (serving as both
// the client-cert issuer the server trusts AND the server-cert issuer the client
// trusts — a hermetic single-CA loopback stand-in for the real two-domain trust),
// a device server leaf, a role-bearing client leaf per bench role, and a
// manifest.json LoadPKI can read.
type testPKI struct {
	dir            string
	serverCertFile string
	serverKeyFile  string
}

// clientSlug names a role's cert/key files. Any stable name works — LoadPKI
// resolves paths from the manifest, not from a slug convention.
func clientSlug(r Role) string { return string(r) }

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	ca := mkCert(t, "aggregator test CA", true, nil, nil, nil)
	writeCertPEM(t, filepath.Join(dir, "ca-cert.pem"), ca.der)

	server := mkCert(t, "mbaps device", false, &ca, []string{"127.0.0.1", "localhost"}, nil)
	p := testPKI{
		dir:            dir,
		serverCertFile: filepath.Join(dir, "dev-server-cert.pem"),
		serverKeyFile:  filepath.Join(dir, "dev-server-key.pem"),
	}
	writeCertPEM(t, p.serverCertFile, server.der)
	writeKeyPEM(t, p.serverKeyFile, server.key)

	clientsDir := filepath.Join(dir, "clients")
	if err := os.MkdirAll(clientsDir, 0o755); err != nil {
		t.Fatalf("mkdir clients: %v", err)
	}
	type manClient struct {
		Name string `json:"name"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	var clients []manClient
	for _, r := range Roles() {
		leaf := mkCert(t, "client-"+string(r), false, &ca, nil, []pkix.Extension{roleExt(t, string(r))})
		certRel := filepath.Join("clients", clientSlug(r)+"-cert.pem")
		keyRel := filepath.Join("clients", clientSlug(r)+"-key.pem")
		writeCertPEM(t, filepath.Join(dir, certRel), leaf.der)
		writeKeyPEM(t, filepath.Join(dir, keyRel), leaf.key)
		clients = append(clients, manClient{Name: string(r), Cert: certRel, Key: keyRel})
	}

	manifest := struct {
		Device struct {
			CA string `json:"ca"`
		} `json:"device"`
		Clients []manClient `json:"clients"`
	}{Clients: clients}
	manifest.Device.CA = "ca-cert.pem"
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return p
}

// serverProfile is the mbtls server profile the loopback test server presents:
// the device leaf, trusting the minted CA to verify client certs.
func (p testPKI) serverProfile() mbtls.Profile {
	return mbtls.DefaultServerProfile(filepath.Join(p.dir, "ca-cert.pem"), p.serverCertFile, p.serverKeyFile)
}

// refs loads the PKIRefs the emulator dials with (ServerCA already resolved to
// the minted CA via the manifest's device.ca).
func (p testPKI) refs(t *testing.T) PKIRefs {
	t.Helper()
	r, err := LoadPKI(p.dir)
	if err != nil {
		t.Fatalf("LoadPKI: %v", err)
	}
	return r
}
