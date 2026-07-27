package main

// main_test.go pins the two properties of this generator that a conformance run
// depends on and that nothing else in the tree would notice were broken:
//
//	every LEAF carries a subjectKeyIdentifier — because SSM-CONF-v0.8's RFC 5280
//	checks inspect whatever certificate is on the wire, and when the bench's own
//	fixture is missing an extension the report reads as a DUT non-conformance;
//
//	-reuse-ca leaves the CA identities byte-identical — because the root is
//	installed in the live gateway's nb-mbaps-clients trust domain, and a bench
//	that silently re-roots itself is locked out of the device it certifies.

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// leafFiles are the generated end-entity certificates. RFC 5280 §4.2.1.2 makes
// subjectKeyIdentifier a SHOULD for exactly these — and crypto/x509 derives one
// automatically ONLY for CA templates, which is how they all came to lack it.
var leafFiles = []string{
	"dev-server-cert.pem",
	"clients/grid-service-cert.pem",
	"clients/super-admin-cert.pem",
	"clients/net-admin-cert.pem",
	"clients/read-only-cert.pem",
	"clients/lexavolt-read-only-cert.pem",
	"negative/no-role-cert.pem",
	"negative/bad-encoding-cert.pem",
	"negative/empty-role-cert.pem",
	"negative/oversize-role-cert.pem",
	"negative/expired-cert.pem",
	"negative/wrong-ca-cert.pem",
}

const oidSubjectKeyIdentifier = "2.5.29.14"

// leafDER returns the FIRST certificate in a leaf-first chain PEM.
func leafDER(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s holds no leading CERTIFICATE block", path)
	}
	return block.Bytes
}

// hasSKI walks the certificate's extensions for 2.5.29.14 without going through
// x509.ParseCertificate's convenience field, because the two-role negative
// fixture deliberately does not parse (duplicate extension OID) and must be
// covered too.
func hasSKI(t *testing.T, der []byte) bool {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		return len(cert.SubjectKeyId) > 0
	}
	// The deliberately-malformed fixtures: fall back to the raw extension list
	// via a lenient re-parse of the TBS. crypto/x509 gives no lenient path, so
	// the search is over the DER bytes of the OID itself — 06 03 55 1D 0E.
	needle := []byte{0x06, 0x03, 0x55, 0x1D, 0x0E}
	for i := 0; i+len(needle) <= len(der); i++ {
		match := true
		for j := range needle {
			if der[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	t.Logf("%v", err)
	return false
}

func TestEveryGeneratedLeafCarriesASubjectKeyIdentifier(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "mbaps")
	if err := run(out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, f := range append(leafFiles, "negative/two-role-cert.pem") {
		path := filepath.Join(out, f)
		if !hasSKI(t, leafDER(t, path)) {
			t.Errorf("%s has no subjectKeyIdentifier (OID %s). RFC 5280 §4.2.1.2 makes it a SHOULD for "+
				"end-entity certificates, and SSM-CONF-v0.8 §2.6.7/§2.6.8 check for it on whatever "+
				"certificate is on the wire — including this bench's own", f, oidSubjectKeyIdentifier)
		}
	}
}

// TestReuseCAKeepsTheTrustAnchorByteIdentical is the operational guard. The
// bench's root is installed in the live gateway's nb-mbaps-clients trust domain;
// re-rooting it from this side alone is a DUT configuration change and locks the
// bench out until someone re-provisions the device.
func TestReuseCAKeepsTheTrustAnchorByteIdentical(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "mbaps")
	if err := run(out, false); err != nil {
		t.Fatalf("initial run: %v", err)
	}
	cas := []string{"ca-cert.pem", "intermediate-cert.pem", "wrong-ca-cert.pem", "dev-ca.pem"}
	before := map[string]string{}
	for _, f := range cas {
		before[f] = string(leafDER(t, filepath.Join(out, f)))
	}
	leafBefore := string(leafDER(t, filepath.Join(out, "clients/grid-service-cert.pem")))

	if err := run(out, true); err != nil {
		t.Fatalf("-reuse-ca run: %v", err)
	}
	for _, f := range cas {
		if got := string(leafDER(t, filepath.Join(out, f))); got != before[f] {
			t.Errorf("-reuse-ca changed %s; a CA a peer has installed cannot be re-minted from this side", f)
		}
	}
	if got := string(leafDER(t, filepath.Join(out, "clients/grid-service-cert.pem"))); got == leafBefore {
		t.Error("-reuse-ca did not re-mint the leaves; the whole point is to refresh them under the same root")
	}
	// And the re-minted leaf must still chain to the preserved root.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(mustRead(t, filepath.Join(out, "ca-cert.pem"))) {
		t.Fatal("the reused root does not load as a PEM certificate")
	}
	inter := x509.NewCertPool()
	if !inter.AppendCertsFromPEM(mustRead(t, filepath.Join(out, "intermediate-cert.pem"))) {
		t.Fatal("the reused intermediate does not load")
	}
	leaf, err := x509.ParseCertificate(leafDER(t, filepath.Join(out, "clients/grid-service-cert.pem")))
	if err != nil {
		t.Fatalf("parse the re-minted leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("a leaf re-minted under -reuse-ca must still verify to the preserved root: %v", err)
	}
}

func TestReuseCAWithoutAnExistingTreeIsAnError(t *testing.T) {
	out := filepath.Join(t.TempDir(), "mbaps")
	if err := run(out, true); err == nil {
		t.Fatal("-reuse-ca against an empty directory must fail loudly, not mint a silent new root")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
