package tlsdis

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// mintCert issues a leaf under the test CA with an arbitrary extension set,
// which is how the role-extension negative fixtures are built.
func mintCert(t *testing.T, pki *testPKI, cn string, exts []pkix.Extension) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.caCert, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func utf8Ext(t *testing.T, oid asn1.ObjectIdentifier, s string) pkix.Extension {
	t.Helper()
	v, err := asn1.MarshalWithParams(s, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oid, Value: v}
}

func TestParseCertInfo(t *testing.T) {
	pki := newTestPKI(t)
	ci, err := ParseCertInfo(pki.clientDER)
	if err != nil {
		t.Fatalf("ParseCertInfo: %v", err)
	}

	sum := sha256.Sum256(pki.clientDER)
	if ci.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("SHA256 does not match the DER")
	}
	if !bytes.Equal(ci.DER, pki.clientDER) {
		t.Error("CertInfo must retain the exact DER it was handed")
	}
	if !strings.Contains(ci.Subject, "aggregator-gridservice") {
		t.Errorf("Subject = %q", ci.Subject)
	}
	if !strings.Contains(ci.Issuer, "evidence-test-ca") {
		t.Errorf("Issuer = %q", ci.Issuer)
	}
	if ci.SelfIssued {
		t.Error("a CA-issued leaf must not report SelfIssued")
	}
	if ci.PublicKeyAlgorithm != "ECDSA" || ci.PublicKeyBits != 256 || ci.Curve != "P-256" {
		t.Errorf("key = %s/%d/%s, want ECDSA/256/P-256", ci.PublicKeyAlgorithm, ci.PublicKeyBits, ci.Curve)
	}
	if !strings.Contains(ci.SignatureAlgorithm, "ECDSA") {
		t.Errorf("SignatureAlgorithm = %q", ci.SignatureAlgorithm)
	}
	if ci.NotAfter.Before(ci.NotBefore) {
		t.Error("validity window is inverted")
	}
	if len(ci.KeyUsage) == 0 || ci.KeyUsage[0] != "DigitalSignature" {
		t.Errorf("KeyUsage = %v", ci.KeyUsage)
	}
	if len(ci.ExtKeyUsage) != 1 || ci.ExtKeyUsage[0] != "ClientAuth" {
		t.Errorf("ExtKeyUsage = %v", ci.ExtKeyUsage)
	}
	if !ci.BasicConstraintsValid || ci.IsCA {
		t.Errorf("basic constraints: valid=%t isCA=%t", ci.BasicConstraintsValid, ci.IsCA)
	}
	if ci.Version != 3 {
		t.Errorf("Version = %d, want 3", ci.Version)
	}

	// The CA cert exercises the other side of those fields.
	caInfo, err := ParseCertInfo(pki.caDER)
	if err != nil {
		t.Fatalf("ParseCertInfo(ca): %v", err)
	}
	if !caInfo.IsCA || !caInfo.SelfIssued {
		t.Errorf("CA: isCA=%t selfIssued=%t", caInfo.IsCA, caInfo.SelfIssued)
	}

	srvInfo, err := ParseCertInfo(pki.serverDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(srvInfo.DNSNames) != 1 || srvInfo.DNSNames[0] != "localhost" {
		t.Errorf("DNSNames = %v", srvInfo.DNSNames)
	}
}

// TestSunSpecRoleExtension is the RBAC pass criterion in miniature: the role
// extension must be visible with its exact OID, its raw DER, and its decoded
// UTF8String value.
func TestSunSpecRoleExtension(t *testing.T) {
	pki := newTestPKI(t)
	ci, err := ParseCertInfo(pki.clientDER)
	if err != nil {
		t.Fatal(err)
	}

	const oid = "1.3.6.1.4.1.50316.802.1"
	if RoleOID.String() != oid {
		t.Fatalf("RoleOID = %s, want %s", RoleOID, oid)
	}
	e, ok := ci.Extension(oid)
	if !ok {
		t.Fatalf("role extension absent; extensions = %v", extOIDs(ci))
	}
	if e.Standard {
		t.Error("the SunSpec role extension is a private-enterprise OID, not a standard one")
	}
	if e.UTF8String != testRole {
		t.Errorf("decoded UTF8String = %q, want %q", e.UTF8String, testRole)
	}
	// The raw DER must be present and be exactly a UTF8String TLV: tag 0x0C,
	// length, then the bytes. Proving the ENCODING (SunSpecTCP-30) requires the
	// bytes, not a decoded string.
	if len(e.Value) < 2 || e.Value[0] != 0x0C || int(e.Value[1]) != len(testRole) {
		t.Errorf("raw role DER = %x, want a UTF8String TLV", e.Value)
	}
	if e.ValueHex != hex.EncodeToString(e.Value) {
		t.Error("ValueHex disagrees with Value")
	}

	custom := ci.CustomExtensions()
	found := false
	for _, c := range custom {
		if c.OID == oid {
			found = true
		}
	}
	if !found {
		t.Errorf("CustomExtensions = %v, want it to include the role OID", custom)
	}

	role, err := ci.SunSpecRole()
	if err != nil || role != testRole {
		t.Fatalf("SunSpecRole = %q, %v", role, err)
	}
}

func TestRoleFromDERTaxonomy(t *testing.T) {
	pki := newTestPKI(t)

	t.Run("absent", func(t *testing.T) {
		der := mintCert(t, pki, "no-role", nil)
		if _, err := RoleFromDER(der); !errors.Is(err, ErrNoRole) {
			t.Fatalf("err = %v, want ErrNoRole", err)
		}
	})

	t.Run("empty string is valid encoding, not an error", func(t *testing.T) {
		der := mintCert(t, pki, "empty-role", []pkix.Extension{utf8Ext(t, RoleOID, "")})
		role, err := RoleFromDER(der)
		if err != nil || role != "" {
			t.Fatalf("role = %q, err = %v; want an empty role and no error — authorization, not parsing, rejects it", role, err)
		}
	})

	t.Run("wrong ASN.1 string type", func(t *testing.T) {
		v, err := asn1.Marshal("ReadOnly") // PrintableString, not UTF8String
		if err != nil {
			t.Fatal(err)
		}
		der := mintCert(t, pki, "bad-encoding", []pkix.Extension{{Id: RoleOID, Value: v}})
		if _, err := RoleFromDER(der); !errors.Is(err, ErrBadRoleEncoding) {
			t.Fatalf("err = %v, want ErrBadRoleEncoding", err)
		}
	})

	t.Run("trailing bytes after the role value", func(t *testing.T) {
		v, err := asn1.MarshalWithParams("ReadOnly", "utf8")
		if err != nil {
			t.Fatal(err)
		}
		der := mintCert(t, pki, "trailing", []pkix.Extension{{Id: RoleOID, Value: append(v, 0x00)}})
		if _, err := RoleFromDER(der); !errors.Is(err, ErrBadRoleEncoding) {
			t.Fatalf("err = %v, want ErrBadRoleEncoding", err)
		}
	})

	t.Run("two role extensions", func(t *testing.T) {
		der := mintCert(t, pki, "two-roles", []pkix.Extension{
			utf8Ext(t, RoleOID, "ReadOnly"),
			utf8Ext(t, RoleOID, "SuperAdmin"),
		})
		if _, err := RoleFromDER(der); !errors.Is(err, ErrMultipleRoles) {
			t.Fatalf("err = %v, want ErrMultipleRoles", err)
		}
		// And the whole point of owning the extension walk: crypto/x509 refuses
		// this certificate outright, so a CertInfo built only from x509 could
		// never report the duplicate. Ours still lists both.
		ci, err := ParseCertInfo(der)
		if err == nil {
			t.Log("crypto/x509 accepted the duplicate-extension certificate; the walk is still authoritative")
		}
		n := 0
		for _, e := range ci.Extensions {
			if e.OID == RoleOID.String() {
				n++
			}
		}
		if n != 2 {
			t.Fatalf("extension walk found %d role extensions, want 2 (x509 error was: %s)", n, ci.ParseError)
		}
	})

	t.Run("not a certificate", func(t *testing.T) {
		if _, err := RoleFromDER([]byte("definitely not DER")); err == nil {
			t.Fatal("want an error")
		}
	})
}

func TestParseCertInfoMalformed(t *testing.T) {
	pki := newTestPKI(t)
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"empty", nil},
		{"garbage", []byte{0x30, 0x82, 0xFF, 0xFF, 0x01}},
		{"truncated real certificate", pki.clientDER[:len(pki.clientDER)/2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ci, err := ParseCertInfo(tc.der)
			if err == nil {
				t.Fatal("want an error")
			}
			if ci == nil {
				t.Fatal("CertInfo must still be returned so the DER can be cited")
			}
		})
	}
}

func TestCertificateMessageLayoutDetection(t *testing.T) {
	pki := newTestPKI(t)

	t.Run("tls 1.2 layout", func(t *testing.T) {
		body := vec24(join(vec24(pki.clientDER), vec24(pki.caDER)))
		c, err := parseCertificate(body, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if c.TLS13 {
			t.Fatal("TLS 1.2 body detected as TLS 1.3")
		}
		if len(c.Entries) != 2 || !bytes.Equal(c.Entries[0].DER, pki.clientDER) {
			t.Fatal("chain mismatch")
		}
	})

	t.Run("tls 1.3 layout with per-certificate extensions", func(t *testing.T) {
		entry := func(der []byte) []byte { return join(vec24(der), vec16(nil)) }
		body := join(vec8(nil), vec24(join(entry(pki.clientDER), entry(pki.caDER))))
		c, err := parseCertificate(body, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !c.TLS13 {
			t.Fatal("TLS 1.3 body detected as TLS 1.2")
		}
		if len(c.Entries) != 2 || !bytes.Equal(c.Entries[1].DER, pki.caDER) {
			t.Fatal("chain mismatch")
		}
		if role, err := c.Leaf().Info.SunSpecRole(); err != nil || role != testRole {
			t.Fatalf("role = %q, %v", role, err)
		}
	})

	t.Run("tls 1.3 with a non-empty request context", func(t *testing.T) {
		entry := func(der []byte) []byte { return join(vec24(der), vec16(nil)) }
		body := join(vec8([]byte{0xAB, 0xCD}), vec24(entry(pki.clientDER)))
		c, err := parseCertificate(body, Options{TLS13: true})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c.RequestContext, []byte{0xAB, 0xCD}) {
			t.Errorf("RequestContext = %x", c.RequestContext)
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		c, err := parseCertificate(vec24(nil), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Entries) != 0 || c.Leaf() != nil {
			t.Fatalf("entries = %d", len(c.Entries))
		}
	})

	t.Run("chain with an unparseable certificate still reports the DER", func(t *testing.T) {
		bad := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
		c, err := parseCertificate(vec24(vec24(bad)), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Entries) != 1 {
			t.Fatalf("entries = %d", len(c.Entries))
		}
		if c.Entries[0].Err == "" {
			t.Error("Err should say why the certificate did not parse")
		}
		if !bytes.Equal(c.Entries[0].DER, bad) {
			t.Error("the DER must survive even when it does not parse")
		}
		if got := c.DERChain(); len(got) != 1 {
			t.Errorf("DERChain = %d entries", len(got))
		}
	})
}

func extOIDs(ci *CertInfo) []string {
	out := make([]string, len(ci.Extensions))
	for i, e := range ci.Extensions {
		out[i] = e.OID
	}
	return out
}
