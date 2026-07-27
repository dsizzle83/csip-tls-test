package tlsdis

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// --- wire builders --------------------------------------------------------

func u16b(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func u24b(v int) []byte    { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

func vec8(b []byte) []byte  { return append([]byte{byte(len(b))}, b...) }
func vec16(b []byte) []byte { return append(u16b(uint16(len(b))), b...) }
func vec24(b []byte) []byte { return append(u24b(len(b)), b...) }

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// hsMsg wraps a body in a handshake message header.
func hsMsg(t HandshakeType, body []byte) []byte {
	return join([]byte{byte(t)}, u24b(len(body)), body)
}

// rec wraps a fragment in a TLS record header.
func rec(ct ContentType, ver uint16, frag []byte) []byte {
	return join([]byte{byte(ct)}, u16b(ver), u16b(uint16(len(frag))), frag)
}

// ext builds one extension.
func ext(t uint16, data []byte) []byte { return join(u16b(t), vec16(data)) }

// --- test PKI -------------------------------------------------------------

// testPKI is a throwaway CA plus a server and a client certificate. The client
// certificate carries the SunSpec role extension, because the handshake fixture
// exists mainly to prove the engine can recover that extension's exact DER from
// a real Certificate message.
type testPKI struct {
	caDER     []byte
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	serverDER []byte
	serverKey *ecdsa.PrivateKey
	clientDER []byte
	clientKey *ecdsa.PrivateKey
	pool      *x509.CertPool
}

const testRole = "GridService"

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "evidence-test-ca", Organization: []string{"LEXA bench"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	p.caDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.caCert, err = x509.ParseCertificate(p.caDER)
	if err != nil {
		t.Fatal(err)
	}
	p.caKey = caKey
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.caCert)

	p.serverDER, p.serverKey = p.issue(t, "mbaps-device", nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})

	roleValue, err := asn1.MarshalWithParams(testRole, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	p.clientDER, p.clientKey = p.issue(t, "aggregator-gridservice",
		[]pkix.Extension{{Id: RoleOID, Value: roleValue}},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	return p
}

func (p *testPKI) issue(t *testing.T, cn string, extra []pkix.Extension, eku []x509.ExtKeyUsage, dns []string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"LEXA bench"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		DNSNames:              dns,
		ExtraExtensions:       extra,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// --- recording pipe -------------------------------------------------------

// recorder wraps a net.Conn and keeps every byte the local side WROTE. Two of
// them around a net.Pipe give the two reassembled TCP streams a capture of the
// same handshake would have produced — without needing a capture at all, which
// keeps the record-layer tests hermetic.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	out []byte
}

func (r *recorder) Write(b []byte) (int, error) {
	n, err := r.Conn.Write(b)
	r.mu.Lock()
	r.out = append(r.out, b[:n]...)
	r.mu.Unlock()
	return n, err
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.out...)
}
