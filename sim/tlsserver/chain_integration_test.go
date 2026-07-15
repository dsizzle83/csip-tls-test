//go:build integration

package tlsserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestChainServing_DepthTwoAcceptedLeafOnlyRejected is the wolfSSL
// UseCertChainFile smoke test (COMM-004 prerequisite, VERIFICATION_SWEEP
// item 2). It stands up a real mTLS handshake and proves the wrapper's value
// directly: a server that presents the full leaf→intermediate chain is
// accepted by a client that trusts only the root, while the same server
// presenting the leaf alone is refused (the client cannot build the path).
//
// Certificates are generated at runtime (ECDSA P-256, the CCM cipher's key
// type) so the test is self-contained — no committed chain fixtures required.
func TestChainServing_DepthTwoAcceptedLeafOnlyRejected(t *testing.T) {
	dir := t.TempDir()

	root := mkCert(t, "chain-test root", true, nil, nil)
	inter := mkCert(t, "chain-test intermediate", true, &root, nil)
	server := mkCert(t, "chain-test server", false, &inter, []string{"127.0.0.1", "localhost"})
	client := mkCert(t, "chain-test client", false, &root, nil)

	rootPath := filepath.Join(dir, "root.pem")
	chainPath := filepath.Join(dir, "server-chain.pem") // leaf + intermediate
	leafPath := filepath.Join(dir, "server-leaf.pem")   // leaf only
	serverKeyPath := filepath.Join(dir, "server-key.pem")
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")

	writeCertPEM(t, rootPath, root.der)
	writeCertPEM(t, chainPath, server.der, inter.der)
	writeCertPEM(t, leafPath, server.der)
	writeKeyPEM(t, serverKeyPath, server.key)
	writeCertPEM(t, clientCertPath, client.der)
	writeKeyPEM(t, clientKeyPath, client.key)

	clientCfg := testClientConfig{
		CACertPath:     rootPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
	}

	// Positive: full chain served → handshake completes, /dcap → 200.
	t.Run("chain accepted", func(t *testing.T) {
		addr, _ := startTestServer(t, Config{
			CACertPath:          rootPath,
			ServerCertChainPath: chainPath,
			ServerKeyPath:       serverKeyPath,
		})
		c, err := dialServerTestClient(t, addr, clientCfg)
		if err != nil {
			t.Fatalf("chain handshake failed: %v", err)
		}
		defer c.Close()
		resp, err := c.Request("GET /dcap HTTP/1.1\r\nHost: x\r\n\r\n")
		if err != nil {
			t.Fatalf("request over chain-served session: %v", err)
		}
		if !strings.Contains(resp, "200 OK") {
			t.Errorf("want 200 OK over chain-served session, got: %q", resp)
		}
	})

	// Negative: leaf only → client (trusting only root) cannot build the path
	// to the trust anchor, so the handshake is refused. This is the exact gap
	// UseCertChainFile closes.
	t.Run("leaf-only rejected", func(t *testing.T) {
		addr, _ := startTestServer(t, Config{
			CACertPath:     rootPath,
			ServerCertPath: leafPath,
			ServerKeyPath:  serverKeyPath,
		})
		c, err := dialServerTestClient(t, addr, clientCfg)
		if err == nil {
			c.Close()
			t.Fatal("leaf-only handshake unexpectedly succeeded (intermediate should be unresolvable)")
		}
	})
}

// certKey bundles a generated certificate, its DER, and its private key.
type certKey struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// mkCert generates an ECDSA P-256 certificate. isCA marks it a CA; parent nil
// self-signs (root), otherwise it is signed by parent. sans are added as IP or
// DNS SANs.
func mkCert(t *testing.T, cn string, isCA bool, parent *certKey, sans []string) certKey {
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

	signerCert, signerKey := tmpl, key // self-signed by default
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert %q: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert %q: %v", cn, err)
	}
	return certKey{cert: cert, der: der, key: key}
}

// writeCertPEM writes one or more DER certs to path as a PEM bundle (leaf
// first for a chain file).
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

// writeKeyPEM writes an EC private key to path as SEC1 "EC PRIVATE KEY" PEM
// (the form the openssl fixtures and wolfssl.UseKeyFile expect).
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
