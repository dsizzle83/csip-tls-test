// Command gen-mbaps-certs mints the bench's committed Secure SunSpec Modbus
// (mbaps) PKI tree under certs/mbaps/ (T06.1): a two-tier CA (root +
// intermediate), one role-bearing client leaf per mandatory + vendor role,
// a device server leaf for sim/mbapsdev, and the negative-fixture matrix
// (no-role, two-role, bad-encoding, empty-role, oversize-role, expired,
// wrong-ca).
//
// # Referee independence (T06 PN-1 / T00 ruling C9)
//
// This tool is deliberately stdlib-only (crypto/x509 + encoding/asn1) and
// does NOT import lexa-platform/securemodbus or any product-side test-PKI
// tooling — the bench mints and asserts its own certs, independent of the
// product's reading of the spec. It also does NOT import internal/mbtls
// (which is cgo, requiring the wolfSSL sysroot): the role-extension OID
// below is a deliberate, documented COPY of internal/mbtls/role.go's
// RoleOID — role.go's own doc comment sanctions exactly this ("a copy of
// the OID may be reused for cert MINTING convenience"). Keeping the
// generator cgo-free means `make gen-mbaps-certs` needs no C toolchain or
// wolfSSL headers, matching the pure-openssl scripts/gen-*.sh generators
// elsewhere in this repo. Equivalence with the real RoleFromDER parser is
// proven empirically, not just by eyeballing the OID: internal/mbtls's
// TestMbapsFixtures_RoleFromDER round-trips every generated cert through
// the actual mbtls.RoleFromDER — if this file's OID ever drifted from
// role.go's, that test would fail immediately (every generated cert would
// parse as ErrNoRole, since the extension mbtls looks for would be a
// different OID than the one this file wrote).
//
// Usage:
//
//	go run ./cmd/gen-mbaps-certs [-out certs/mbaps]
//
// or: make gen-mbaps-certs
//
// Regeneration is destructive-but-deterministic: the output directory is
// removed and rebuilt from scratch each run (fresh keys/serials every time —
// "idempotent" here means "safe and consistent to re-run", not
// byte-identical output, matching scripts/gen-test-certs.sh's convention).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// readmeTemplate is certs/mbaps/README.md's content, embedded so
// `make gen-mbaps-certs` regenerates it every run — the output directory is
// removed and rebuilt from scratch (see run's doc), which would otherwise
// silently delete a hand-maintained README on every regeneration.
//
//go:embed readme.md
var readmeTemplate string

// roleOID is a deliberate copy of internal/mbtls.RoleOID (role.go) — see the
// package doc above for why this generator does not import mbtls directly.
// 1.3.6.1.4.1.50316.802.1: the Secure SunSpec Modbus client-role certificate
// extension (SunSpecTCP-29/30).
var roleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}

// The five mbaps roles this bench mints happy-path client fixtures for: the
// four mandatory SunSpec roles plus the LEXA vendor role (T06_BENCH_QA.md
// T06.1). slug is the filesystem-safe name used for cert/key file basenames.
type roleSpec struct {
	role string
	slug string
}

var roles = []roleSpec{
	{"GridServiceSunSpec", "grid-service"},
	{"SuperAdministratorSunSpec", "super-admin"},
	{"NetworkAdministratorSunSpec", "net-admin"},
	{"ReadOnlySunSpec", "read-only"},
	{"LexaVoltReadOnly", "lexavolt-read-only"},
}

// certKey bundles a minted certificate's parsed form (nil if parsing failed —
// see the two-role fixture below), DER, and private key.
type certKey struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// genKey generates a P-256 (secp256r1) key — the only curve the mbaps
// ECDSA-only cipher suites accept (SunSpecTCP-42).
func genKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// newSerial returns a random 128-bit certificate serial number.
func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// certParams carries everything mintCert needs beyond the signing parent.
type certParams struct {
	cn         string
	isCA       bool
	sans       []string
	exts       []pkix.Extension
	notBefore  time.Time
	notAfter   time.Time
	skipVerify bool // true only for the two-role fixture — see mintCert doc
}

// mintCert builds and signs one certificate. parent == nil means self-signed
// (used for the two CA roots). The returned certKey's cert field is nil when
// skipVerify is set, because crypto/x509.ParseCertificate rejects a
// certificate with a duplicate extension OID (the two-role fixture,
// deliberately malformed) even though x509.CreateCertificate happily
// produces its DER — CreateCertificate does not validate ExtraExtensions for
// duplicates, only ParseCertificate does. mbtls.RoleFromDER (and this
// generator's own self-check) parse the DER with a lenient hand-rolled ASN.1
// walk instead, precisely so ErrMultipleRoles is reachable (see
// internal/mbtls/role.go's doc comment).
func mintCert(p certParams, parent *certKey) (certKey, error) {
	key, err := genKey()
	if err != nil {
		return certKey{}, fmt.Errorf("gen key for %q: %w", p.cn, err)
	}
	serial, err := newSerial()
	if err != nil {
		return certKey{}, fmt.Errorf("serial for %q: %w", p.cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: p.cn},
		NotBefore:             p.notBefore,
		NotAfter:              p.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       p.exts,
	}
	if p.isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		// Every non-CA leaf in this tree gets both EKUs, mirroring the
		// established local convention in internal/mbtls/testpki_test.go and
		// sim/mbapsdev/testpki_test.go (proven to interoperate with wolfSSL
		// in the existing handshake integration tests) — mbaps role certs
		// double as the southbound identity the gateway presents to devices,
		// so client leaves are dialed both directions in practice.
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	for _, s := range p.sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}

	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		return certKey{}, fmt.Errorf("create cert %q: %w", p.cn, err)
	}
	ck := certKey{der: der, key: key}
	if !p.skipVerify {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return certKey{}, fmt.Errorf("parse minted cert %q: %w", p.cn, err)
		}
		ck.cert = cert
	}
	return ck, nil
}

// roleExtUTF8 builds a conformant mbaps role extension: roleOID + a single
// ASN.1 UTF8String value (the spec-mandated encoding, SunSpecTCP-30).
func roleExtUTF8(role string) (pkix.Extension, error) {
	b, err := asn1.MarshalWithParams(role, "utf8")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal utf8 role %q: %w", role, err)
	}
	return pkix.Extension{Id: roleOID, Value: b}, nil
}

// roleExtPrintable builds the bad-encoding negative fixture: roleOID + a
// PrintableString value where the spec mandates UTF8String.
func roleExtPrintable(role string) (pkix.Extension, error) {
	b, err := asn1.MarshalWithParams(role, "printable")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal printable role %q: %w", role, err)
	}
	return pkix.Extension{Id: roleOID, Value: b}, nil
}

// --- PEM I/O -----------------------------------------------------------

// writeChainPEM writes one or more DER certs (leaf first, per TCP-51) into a
// single PEM file, 0644 (public — tracked in git).
func writeChainPEM(path string, ders ...[]byte) error {
	var buf strings.Builder
	for _, der := range ders {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(buf.String()), 0o644)
}

// writeKeyPEM writes an EC private key, 0600 — the *-key.pem glob in
// .gitignore keeps every one of these out of git regardless of directory.
func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, b, 0o600)
}

// --- manifest ------------------------------------------------------------

// fixture is one manifest row: a cert/key pair plus what RoleFromDER should
// return on it and whether it is expected to chain-verify (time-valid,
// trusted issuer). This is the "manifest mapping fixture name -> file paths
// -> expected role string" T06.1 requires, and what the round-trip test in
// internal/mbtls consumes.
type fixture struct {
	Name          string `json:"name"`
	Cert          string `json:"cert"`
	Key           string `json:"key"`
	ExpectRole    string `json:"expect_role"`
	ExpectRoleErr string `json:"expect_role_err,omitempty"` // "" | ErrNoRole | ErrBadEncoding | ErrMultipleRoles
	ChainValid    bool   `json:"chain_valid"`
	Note          string `json:"note,omitempty"`
}

type manifest struct {
	GeneratedAt time.Time `json:"generated_at"`
	RoleOID     string    `json:"role_oid"`
	CA          struct {
		Root         string `json:"root"`
		Intermediate string `json:"intermediate"`
		WrongCARoot  string `json:"wrong_ca_root"`
	} `json:"ca"`
	Device struct {
		CA   string `json:"ca"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"device"`
	Clients   []fixture `json:"clients"`
	Negatives []fixture `json:"negatives"`
}

func main() {
	out := flag.String("out", "certs/mbaps", "output directory for the mbaps PKI tree (relative to CWD — run from the repo root)")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "gen-mbaps-certs: %v\n", err)
		os.Exit(1)
	}
}

func run(out string) error {
	if !strings.Contains(out, "mbaps") {
		return fmt.Errorf("refusing to regenerate %q — path does not look like an mbaps cert dir (safety check before RemoveAll)", out)
	}
	if err := os.RemoveAll(out); err != nil {
		return fmt.Errorf("clean %s: %w", out, err)
	}
	clientsDir := filepath.Join(out, "clients")
	negDir := filepath.Join(out, "negative")
	for _, d := range []string{out, clientsDir, negDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	now := time.Now()
	// Committed fixtures live in git for a while — give them a comfortable
	// validity window rather than the short-lived windows the in-package
	// runtime-minted test fixtures use.
	rootNotBefore, rootNotAfter := now.Add(-time.Hour), now.Add(10*365*24*time.Hour)
	intNotBefore, intNotAfter := now.Add(-time.Hour), now.Add(7*365*24*time.Hour)
	leafNotBefore, leafNotAfter := now.Add(-time.Hour), now.Add(3*365*24*time.Hour)
	expiredNotBefore, expiredNotAfter := now.Add(-48*time.Hour), now.Add(-24*time.Hour)

	// === Two-tier CA: root + intermediate ("nb-mbaps-clients" trust domain) ===
	root, err := mintCert(certParams{
		cn: "csip-tls-test bench mbaps Root CA", isCA: true,
		notBefore: rootNotBefore, notAfter: rootNotAfter,
	}, nil)
	if err != nil {
		return err
	}
	intermediate, err := mintCert(certParams{
		cn: "csip-tls-test bench mbaps Intermediate CA", isCA: true,
		notBefore: intNotBefore, notAfter: intNotAfter,
	}, &root)
	if err != nil {
		return err
	}
	// A second, wholly unrelated root — the trust domain mbapsdev/the gateway
	// must NOT have loaded, for the wrong-ca negative.
	wrongCA, err := mintCert(certParams{
		cn: "csip-tls-test bench mbaps WRONG Root CA (untrusted, negative fixture)", isCA: true,
		notBefore: rootNotBefore, notAfter: rootNotAfter,
	}, nil)
	if err != nil {
		return err
	}

	if err := writeChainPEM(filepath.Join(out, "ca-cert.pem"), root.der); err != nil {
		return err
	}
	if err := writeKeyPEM(filepath.Join(out, "ca-key.pem"), root.key); err != nil {
		return err
	}
	if err := writeChainPEM(filepath.Join(out, "intermediate-cert.pem"), intermediate.der); err != nil {
		return err
	}
	if err := writeKeyPEM(filepath.Join(out, "intermediate-key.pem"), intermediate.key); err != nil {
		return err
	}
	if err := writeChainPEM(filepath.Join(out, "wrong-ca-cert.pem"), wrongCA.der); err != nil {
		return err
	}
	if err := writeKeyPEM(filepath.Join(out, "wrong-ca-key.pem"), wrongCA.key); err != nil {
		return err
	}
	// dev-ca.pem: the trust anchor sim/mbapsdev loads by default (-ca flag) to
	// verify the gateway's southbound client cert. Same root as ca-cert.pem —
	// written as an independent copy so mbapsdev's default flags
	// (certs/mbaps/dev-ca.pem) resolve without a symlink.
	if err := writeChainPEM(filepath.Join(out, "dev-ca.pem"), root.der); err != nil {
		return err
	}

	var m manifest
	m.GeneratedAt = now
	m.RoleOID = roleOID.String()
	m.CA.Root = "ca-cert.pem"
	m.CA.Intermediate = "intermediate-cert.pem"
	m.CA.WrongCARoot = "wrong-ca-cert.pem"
	m.Device.CA = "dev-ca.pem"
	m.Device.Cert = "dev-server-cert.pem"
	m.Device.Key = "dev-server-key.pem"

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root.cert)
	intPool := x509.NewCertPool()
	intPool.AddCert(intermediate.cert)

	verify := func(cert *x509.Certificate) bool {
		if cert == nil {
			return false
		}
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		return err == nil
	}

	// === Device server leaf (sim/mbapsdev) — no role extension (TCP-28) =====
	devServer, err := mintCert(certParams{
		cn:        "mbapsdev bench device",
		sans:      []string{"127.0.0.1", "localhost", "69.0.0.20"},
		notBefore: leafNotBefore, notAfter: leafNotAfter,
	}, &intermediate)
	if err != nil {
		return err
	}
	if err := writeChainPEM(filepath.Join(out, "dev-server-cert.pem"), devServer.der, intermediate.der); err != nil {
		return err
	}
	if err := writeKeyPEM(filepath.Join(out, "dev-server-key.pem"), devServer.key); err != nil {
		return err
	}
	if !verify(devServer.cert) {
		return fmt.Errorf("self-check: dev-server-cert.pem did not chain-verify against ca-cert.pem")
	}

	// === Happy path: one role-bearing client leaf per role ===================
	for _, rs := range roles {
		ext, err := roleExtUTF8(rs.role)
		if err != nil {
			return err
		}
		leaf, err := mintCert(certParams{
			cn:        "mbaps-client-" + rs.slug,
			exts:      []pkix.Extension{ext},
			notBefore: leafNotBefore, notAfter: leafNotAfter,
		}, &intermediate)
		if err != nil {
			return err
		}
		certPath := filepath.Join(clientsDir, rs.slug+"-cert.pem")
		keyPath := filepath.Join(clientsDir, rs.slug+"-key.pem")
		if err := writeChainPEM(certPath, leaf.der, intermediate.der); err != nil {
			return err
		}
		if err := writeKeyPEM(keyPath, leaf.key); err != nil {
			return err
		}
		if !verify(leaf.cert) {
			return fmt.Errorf("self-check: %s did not chain-verify against ca-cert.pem", certPath)
		}
		m.Clients = append(m.Clients, fixture{
			Name: rs.role, Cert: relOut(certPath), Key: relOut(keyPath),
			ExpectRole: rs.role, ChainValid: true,
		})
	}

	// === Negative fixture matrix ==============================================
	oversize := strings.Repeat("A", 1024)

	type negSpec struct {
		name          string
		exts          func() ([]pkix.Extension, error)
		signer        *certKey // nil => sign with wrong CA
		notBefore     time.Time
		notAfter      time.Time
		skipVerify    bool
		expectRole    string
		expectRoleErr string
		chainValid    bool
		note          string
	}

	negs := []negSpec{
		{
			name:      "no-role",
			exts:      func() ([]pkix.Extension, error) { return nil, nil },
			signer:    &intermediate,
			notBefore: leafNotBefore, notAfter: leafNotAfter,
			expectRoleErr: "ErrNoRole",
			chainValid:    true,
			note:          "role extension absent entirely",
		},
		{
			name: "two-role",
			exts: func() ([]pkix.Extension, error) {
				a, err := roleExtUTF8("GridServiceSunSpec")
				if err != nil {
					return nil, err
				}
				b, err := roleExtUTF8("ReadOnlySunSpec")
				if err != nil {
					return nil, err
				}
				return []pkix.Extension{a, b}, nil
			},
			signer:    &intermediate,
			notBefore: leafNotBefore, notAfter: leafNotAfter,
			skipVerify:    true, // crypto/x509.ParseCertificate rejects duplicate ext OIDs
			expectRoleErr: "ErrMultipleRoles",
			chainValid:    true,
			note:          "two role extensions present (GridServiceSunSpec + ReadOnlySunSpec) — spec mandates exactly one",
		},
		{
			name: "bad-encoding",
			exts: func() ([]pkix.Extension, error) {
				e, err := roleExtPrintable("GridServiceSunSpec")
				return []pkix.Extension{e}, err
			},
			signer:    &intermediate,
			notBefore: leafNotBefore, notAfter: leafNotAfter,
			expectRoleErr: "ErrBadEncoding",
			chainValid:    true,
			note:          "role value is a PrintableString, not the mandated UTF8String (SunSpecTCP-30)",
		},
		{
			name: "empty-role",
			exts: func() ([]pkix.Extension, error) {
				e, err := roleExtUTF8("")
				return []pkix.Extension{e}, err
			},
			signer:    &intermediate,
			notBefore: leafNotBefore, notAfter: leafNotAfter,
			expectRole: "",
			chainValid: true,
			note:       "structurally valid empty UTF8String — parses with no error; unauthorized at the AuthZ layer, not the parser (design doc 01 §3.1)",
		},
		{
			name: "oversize-role",
			exts: func() ([]pkix.Extension, error) {
				e, err := roleExtUTF8(oversize)
				return []pkix.Extension{e}, err
			},
			signer:    &intermediate,
			notBefore: leafNotBefore, notAfter: leafNotAfter,
			expectRole: oversize,
			chainValid: true,
			note:       "1024-byte UTF8String role value — parses verbatim with no error",
		},
		{
			name: "expired",
			exts: func() ([]pkix.Extension, error) {
				e, err := roleExtUTF8("GridServiceSunSpec")
				return []pkix.Extension{e}, err
			},
			signer:    &intermediate,
			notBefore: expiredNotBefore, notAfter: expiredNotAfter,
			expectRole: "GridServiceSunSpec",
			chainValid: false,
			note:       "notAfter in the past — role parses fine (valid role), TLS/chain validation must reject on expiry",
		},
		{
			name: "wrong-ca",
			exts: func() ([]pkix.Extension, error) {
				e, err := roleExtUTF8("GridServiceSunSpec")
				return []pkix.Extension{e}, err
			},
			signer:    nil, // signed by wrongCA below
			notBefore: leafNotBefore, notAfter: leafNotAfter,
			expectRole: "GridServiceSunSpec",
			chainValid: false,
			note:       "valid role, but issued by an untrusted CA (not certs/mbaps/ca-cert.pem)",
		},
	}

	for _, ns := range negs {
		exts, err := ns.exts()
		if err != nil {
			return err
		}
		signer := ns.signer
		if signer == nil {
			signer = &wrongCA
		}
		leaf, err := mintCert(certParams{
			cn:         "mbaps-client-" + ns.name,
			exts:       exts,
			notBefore:  ns.notBefore,
			notAfter:   ns.notAfter,
			skipVerify: ns.skipVerify,
		}, signer)
		if err != nil {
			return fmt.Errorf("mint negative %q: %w", ns.name, err)
		}
		certPath := filepath.Join(negDir, ns.name+"-cert.pem")
		keyPath := filepath.Join(negDir, ns.name+"-key.pem")
		// wrong-ca is single-tier (signed directly by wrongCA, no
		// intermediate involved in that branch) so its chain is the leaf
		// alone; every other negative is signed by the real intermediate and
		// gets the standard leaf+intermediate chain (TCP-51).
		var chainErr error
		if ns.name == "wrong-ca" {
			chainErr = writeChainPEM(certPath, leaf.der)
		} else {
			chainErr = writeChainPEM(certPath, leaf.der, intermediate.der)
		}
		if chainErr != nil {
			return chainErr
		}
		if err := writeKeyPEM(keyPath, leaf.key); err != nil {
			return err
		}
		if !ns.skipVerify {
			gotValid := verify(leaf.cert)
			if gotValid != ns.chainValid {
				return fmt.Errorf("self-check: negative %q chain-verify = %v, want %v", ns.name, gotValid, ns.chainValid)
			}
		}
		m.Negatives = append(m.Negatives, fixture{
			Name: ns.name, Cert: relOut(certPath), Key: relOut(keyPath),
			ExpectRole: ns.expectRole, ExpectRoleErr: ns.expectRoleErr,
			ChainValid: ns.chainValid, Note: ns.note,
		})
	}

	// no-client-cert is a documented negative with NO cert fixture — it drives
	// a handshake with no client certificate at all (DefaultClientProfile with
	// empty CertChainFile/KeyFile), already exercised by
	// internal/mbtls's TestHandshake_NoClientCert_Rejected. Noted here so the
	// manifest documents the full matrix even though it mints no file.

	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), append(mb, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(readmeTemplate), 0o644); err != nil {
		return err
	}

	printSummary(m)
	return nil
}

// relOut strips the "certs/mbaps/" (or whatever -out was) prefix down to a
// path relative to the mbaps root, e.g. "clients/grid-service-cert.pem" — the
// manifest is portable regardless of where -out pointed.
func relOut(p string) string {
	// p is already "<out>/…"; manifest paths are relative to the mbaps root,
	// computed by stripping everything up to and including the first
	// "clients/" or "negative/" or bare filename component. Simpler: just
	// take the last two path elements when nested, else the base name.
	dir, file := filepath.Split(p)
	dir = filepath.Base(strings.TrimSuffix(dir, "/"))
	if dir == "clients" || dir == "negative" {
		return dir + "/" + file
	}
	return file
}

func printSummary(m manifest) {
	fmt.Println("mbaps PKI generated:")
	fmt.Printf("  role OID: %s\n", m.RoleOID)
	fmt.Printf("  CA:  %s (root)  %s (intermediate)  %s (wrong-CA, untrusted)\n", m.CA.Root, m.CA.Intermediate, m.CA.WrongCARoot)
	fmt.Printf("  device: %s / %s (ca: %s)\n", m.Device.Cert, m.Device.Key, m.Device.CA)
	fmt.Println("  clients (happy path):")
	for _, f := range m.Clients {
		fmt.Printf("    %-30s -> %-45s role=%s\n", f.Name, f.Cert, f.ExpectRole)
	}
	fmt.Println("  negatives:")
	for _, f := range m.Negatives {
		errLabel := f.ExpectRoleErr
		if errLabel == "" {
			errLabel = "(no role-parse error)"
		}
		fmt.Printf("    %-15s -> %-35s role_err=%-20s chain_valid=%v\n", f.Name, f.Cert, errLabel, f.ChainValid)
	}
	fmt.Println("  (no-client-cert is a documented negative with no cert fixture — see manifest note)")
	fmt.Println("manifest.json written; see certs/mbaps/README.md")
}
