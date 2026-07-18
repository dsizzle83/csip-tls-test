package main

// pki.go resolves the certificate material the suite dials with, in two modes:
//
//   - LIVE (-target <gateway>): load the committed certs/mbaps tree via its
//     manifest.json (the T06.1 role-cert + negative-fixture matrix). Real keys
//     come from `make gen-mbaps-certs`.
//   - LOOPBACK (default, no -target): mint a throwaway EC P-256 PKI at runtime —
//     a two-tier CA, a device/server leaf, a role-bearing client leaf per bench
//     role, and the negative-fixture matrix — so `make ssm-conformance` is fully
//     self-contained (no cert-gen, no committed-file churn, no bench access),
//     exactly the pattern sim/mbapsdev and internal/aggregator tests use.
//
// The minting here is the bench's own MINTING CONVENIENCE. It is deliberately
// kept independent of the role-ASSERTION path (mbtls.RoleFromDER, which the
// checks call): the referee reads roles back out of the DER it is handed, it does
// not trust what this file claims it put in (PN-1 / C9). All leaves are EC P-256
// (the mbaps ECDSA suites' key type, TCP-42) and role extensions are built
// against mbtls.RoleOID — the SAME OID the parser reads, never a divergent copy.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/mbtls"
)

// Role aliases the aggregator's role type so the suite reuses ConnectAs/
// ProbeDenied and the canonical role set without re-declaring them.
type Role = aggregator.Role

// The five bench roles, aliased to the aggregator's canonical constants (the
// certs/mbaps manifest is the file→role source of truth).
const (
	RoleGridService  = aggregator.RoleGridService
	RoleSuperAdmin   = aggregator.RoleSuperAdmin
	RoleNetworkAdmin = aggregator.RoleNetworkAdmin
	RoleReadOnly     = aggregator.RoleReadOnly
	RoleLexaVolt     = aggregator.RoleLexaVolt
)

// cred is a client credential: a full leaf-first chain (TCP-51) and its key.
type cred struct {
	certFile string
	keyFile  string
}

// negFixture is one negative certificate fixture and the defect that makes it a
// negative — the evidence source for the AuthZ (TCP-32) and PKI (TCP-48/52)
// checks. expectRole is the role the cert carries (may be ""), expectErr names
// the mbtls.RoleFromDER error it should provoke ("" = parses cleanly),
// chainValid is false for fixtures the TLS layer must reject (wrong-ca, expired).
type negFixture struct {
	name       string
	certFile   string
	keyFile    string
	expectRole string
	expectErr  string
	chainValid bool
}

// pkiSet is the resolved certificate material for a run.
type pkiSet struct {
	dir       string
	serverCA  string // CA verifying the TARGET's server certificate
	clientCA  string // CA that issued the client role certs (loopback server trust; trust10 base)
	roles     map[Role]cred
	negatives map[string]negFixture
	devServer cred // device/loopback server leaf+key (loopback only)
	cleanup   func()
}

// refs builds the aggregator PKIRefs the role-matrix checks dial with (ConnectAs
// / ProbeDenied). ServerCA is the anchor that verifies the target's server cert.
func (ps *pkiSet) refs() aggregator.PKIRefs {
	r := aggregator.PKIRefs{ServerCA: ps.serverCA}
	for role, c := range ps.roles {
		r.SetCred(role, aggregator.RoleCred{CertFile: c.certFile, KeyFile: c.keyFile})
	}
	return r
}

// loadManifestPKI resolves the committed certs/mbaps tree from its manifest for a
// live-gateway run. serverCA overrides the anchor that verifies the gateway's
// server cert; empty defaults to the manifest's device CA (dev-ca.pem == the
// bench root), which is correct for a gateway provisioned from the bench PKI.
func loadManifestPKI(dir, serverCA string) (*pkiSet, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("ssm-conformance: read mbaps manifest: %w", err)
	}
	var mf struct {
		CA struct {
			Root         string `json:"root"`
			Intermediate string `json:"intermediate"`
		} `json:"ca"`
		Device struct {
			CA string `json:"ca"`
		} `json:"device"`
		Clients []struct {
			Name       string `json:"name"`
			Cert       string `json:"cert"`
			Key        string `json:"key"`
			ExpectRole string `json:"expect_role"`
		} `json:"clients"`
		Negatives []struct {
			Name       string `json:"name"`
			Cert       string `json:"cert"`
			Key        string `json:"key"`
			ExpectRole string `json:"expect_role"`
			ExpectErr  string `json:"expect_role_err"`
			ChainValid bool   `json:"chain_valid"`
		} `json:"negatives"`
	}
	if err := json.Unmarshal(raw, &mf); err != nil {
		return nil, fmt.Errorf("ssm-conformance: parse mbaps manifest: %w", err)
	}
	ps := &pkiSet{
		dir:       dir,
		roles:     make(map[Role]cred),
		negatives: make(map[string]negFixture),
		clientCA:  join(dir, orDefault(mf.CA.Root, "ca-cert.pem")),
		cleanup:   func() {},
	}
	ps.serverCA = serverCA
	if ps.serverCA == "" {
		ps.serverCA = join(dir, orDefault(mf.Device.CA, "dev-ca.pem"))
	}
	for _, c := range mf.Clients {
		if c.Name == "" || c.Cert == "" || c.Key == "" {
			continue
		}
		ps.roles[Role(c.Name)] = cred{certFile: join(dir, c.Cert), keyFile: join(dir, c.Key)}
	}
	for _, n := range mf.Negatives {
		if n.Name == "" || n.Cert == "" {
			continue
		}
		ps.negatives[n.Name] = negFixture{
			name:       n.Name,
			certFile:   join(dir, n.Cert),
			keyFile:    join(dir, n.Key),
			expectRole: n.ExpectRole,
			expectErr:  n.ExpectErr,
			chainValid: n.ChainValid,
		}
	}
	if len(ps.roles) == 0 {
		return nil, fmt.Errorf("ssm-conformance: mbaps manifest %s lists no client roles", dir)
	}
	return ps, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func join(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// ── runtime minting (loopback) ──────────────────────────────────────────────

type certKey struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// mintCert builds and signs one EC P-256 certificate. parent==nil self-signs (a
// CA root). isCA marks a CA. exts are extra extensions (the role extension and
// its negatives); createFrom always uses the parsed parent so the chain verifies.
func mintCert(cn string, isCA bool, parent *certKey, sans []string, exts []pkix.Extension, notBefore, notAfter time.Time) (certKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certKey{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return certKey{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		return certKey{}, fmt.Errorf("create cert %q: %w", cn, err)
	}
	// A cert with a deliberately-malformed ExtraExtension still produces DER;
	// re-parsing may fail for those negatives, so tolerate a parse error and keep
	// the DER (the negative's whole point is that it is malformed).
	crt, _ := x509.ParseCertificate(der)
	return certKey{der: der, cert: crt, key: key}, nil
}

// roleExtUTF8 is a well-formed role extension (the mandated UTF8String, TCP-30).
func roleExtUTF8(role string) (pkix.Extension, error) {
	b, err := asn1.MarshalWithParams(role, "utf8")
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: mbtls.RoleOID, Value: b}, nil
}

// roleExtPrintable is the bad-encoding negative: a PrintableString value instead
// of the mandated UTF8String (TCP-30). Plain asn1.Marshal of a Go string emits
// PrintableString, which the referee must reject as ErrBadEncoding.
func roleExtPrintable(role string) (pkix.Extension, error) {
	b, err := asn1.Marshal(role)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: mbtls.RoleOID, Value: b}, nil
}

// mintLoopbackPKI mints the full self-contained PKI into a temp dir: root →
// intermediate → {device server leaf, role client leaves, negatives}, plus a
// wholly-unrelated root for the wrong-ca negative. serverCA == clientCA == the
// single root (a hermetic loopback stand-in for the real two-domain trust —
// exactly like sim/mbapsdev's dev-ca.pem == the bench root).
func mintLoopbackPKI() (*pkiSet, error) {
	dir, err := os.MkdirTemp("", "ssm-conf-pki-")
	if err != nil {
		return nil, err
	}
	ps := &pkiSet{
		dir:       dir,
		roles:     make(map[Role]cred),
		negatives: make(map[string]negFixture),
		cleanup:   func() { _ = os.RemoveAll(dir) },
	}
	fail := func(err error) (*pkiSet, error) {
		ps.cleanup()
		return nil, err
	}
	now := time.Now()
	far := now.Add(10 * 365 * 24 * time.Hour)

	root, err := mintCert("ssm-conf root CA", true, nil, nil, nil, now.Add(-time.Hour), far)
	if err != nil {
		return fail(err)
	}
	inter, err := mintCert("ssm-conf intermediate CA", true, &root, nil, nil, now.Add(-time.Hour), far)
	if err != nil {
		return fail(err)
	}
	wrongRoot, err := mintCert("ssm-conf UNTRUSTED CA", true, nil, nil, nil, now.Add(-time.Hour), far)
	if err != nil {
		return fail(err)
	}

	rootFile := filepath.Join(dir, "ca-cert.pem")
	if err := writeChainPEM(rootFile, root.der); err != nil {
		return fail(err)
	}
	ps.serverCA, ps.clientCA = rootFile, rootFile

	// Device / loopback server leaf, presented as a full chain (leaf+intermediate
	// → root) so TCP-51 is genuinely testable.
	devLeaf, err := mintCert("ssm-conf mbaps device", false, &inter, []string{"127.0.0.1", "localhost"}, nil, now.Add(-time.Hour), far)
	if err != nil {
		return fail(err)
	}
	devCert := filepath.Join(dir, "dev-server-cert.pem")
	devKey := filepath.Join(dir, "dev-server-key.pem")
	if err := writeChainPEM(devCert, devLeaf.der, inter.der); err != nil {
		return fail(err)
	}
	if err := writeKeyPEM(devKey, devLeaf.key); err != nil {
		return fail(err)
	}
	ps.devServer = cred{certFile: devCert, keyFile: devKey}

	// One role-bearing client leaf per bench role.
	for _, role := range aggregator.Roles() {
		ext, err := roleExtUTF8(string(role))
		if err != nil {
			return fail(err)
		}
		leaf, err := mintCert("client-"+string(role), false, &inter, nil, []pkix.Extension{ext}, now.Add(-time.Hour), far)
		if err != nil {
			return fail(err)
		}
		c, k, err := writeLeaf(dir, "client-"+string(role), leaf, inter.der)
		if err != nil {
			return fail(err)
		}
		ps.roles[role] = cred{certFile: c, keyFile: k}
	}

	// Negative fixtures.
	if err := ps.mintNegatives(dir, &inter, &wrongRoot, now); err != nil {
		return fail(err)
	}
	return ps, nil
}

// mintNegatives adds the negative-fixture matrix to a loopback PKI.
func (ps *pkiSet) mintNegatives(dir string, inter, wrongRoot *certKey, now time.Time) error {
	far := now.Add(10 * 365 * 24 * time.Hour)
	add := func(name string, leaf certKey, chainDER []byte, expectRole, expectErr string, chainValid bool) error {
		c, k, err := writeLeaf(dir, name, leaf, chainDER)
		if err != nil {
			return err
		}
		ps.negatives[name] = negFixture{name: name, certFile: c, keyFile: k, expectRole: expectRole, expectErr: expectErr, chainValid: chainValid}
		return nil
	}

	noRole, err := mintCert("no-role", false, inter, nil, nil, now.Add(-time.Hour), far)
	if err != nil {
		return err
	}
	if err := add("no-role", noRole, inter.der, "", "ErrNoRole", true); err != nil {
		return err
	}

	e1, _ := roleExtUTF8(string(aggregator.RoleGridService))
	e2, _ := roleExtUTF8(string(aggregator.RoleReadOnly))
	twoRole, err := mintCert("two-role", false, inter, nil, []pkix.Extension{e1, e2}, now.Add(-time.Hour), far)
	if err != nil {
		return err
	}
	if err := add("two-role", twoRole, inter.der, "", "ErrMultipleRoles", true); err != nil {
		return err
	}

	badExt, err := roleExtPrintable(string(aggregator.RoleGridService))
	if err != nil {
		return err
	}
	badEnc, err := mintCert("bad-encoding", false, inter, nil, []pkix.Extension{badExt}, now.Add(-time.Hour), far)
	if err != nil {
		return err
	}
	if err := add("bad-encoding", badEnc, inter.der, "", "ErrBadEncoding", true); err != nil {
		return err
	}

	emptyExt, _ := roleExtUTF8("")
	emptyRole, err := mintCert("empty-role", false, inter, nil, []pkix.Extension{emptyExt}, now.Add(-time.Hour), far)
	if err != nil {
		return err
	}
	if err := add("empty-role", emptyRole, inter.der, "", "", true); err != nil {
		return err
	}

	expired, err := mintCert("expired", false, inter, nil, []pkix.Extension{e1}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	if err := add("expired", expired, inter.der, string(aggregator.RoleGridService), "", false); err != nil {
		return err
	}

	wrongLeaf, err := mintCert("wrong-ca", false, wrongRoot, nil, []pkix.Extension{e1}, now.Add(-time.Hour), far)
	if err != nil {
		return err
	}
	return add("wrong-ca", wrongLeaf, wrongRoot.der, string(aggregator.RoleGridService), "", false)
}

// trust10File writes a CA bundle of ≥10 roots — the real serverCA plus nine
// throwaway CAs — for the TCP-2 check (a client trust store that considers ≥10
// roots must still verify the peer whose chain roots at one of them). Minted at
// runtime in BOTH modes so the check is identical live and loopback.
func (ps *pkiSet) trust10File() (string, func(), error) {
	base, err := os.ReadFile(ps.serverCA)
	if err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp("", "ssm-conf-trust10-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	now := time.Now()
	far := now.Add(24 * time.Hour)
	// Nine unrelated filler roots first, then the real anchor last — proving the
	// store searches past the first nine to the tenth.
	for i := 0; i < 9; i++ {
		ca, err := mintCert(fmt.Sprintf("ssm-conf filler CA %d", i), true, nil, nil, nil, now.Add(-time.Hour), far)
		if err != nil {
			f.Close()
			cleanup()
			return "", func() {}, err
		}
		if _, err := f.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})); err != nil {
			f.Close()
			cleanup()
			return "", func() {}, err
		}
	}
	if _, err := f.Write(base); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return f.Name(), cleanup, nil
}

// ── PEM + cert-inspection helpers ────────────────────────────────────────────

func writeChainPEM(path string, ders ...[]byte) error {
	var buf []byte
	for _, der := range ders {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return os.WriteFile(path, buf, 0o644)
}

func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// writeLeaf writes a leaf's full chain (leaf + issuing chain) and key, returning
// the cert and key file paths.
func writeLeaf(dir, name string, leaf certKey, chainDER []byte) (string, string, error) {
	certFile := filepath.Join(dir, name+"-cert.pem")
	keyFile := filepath.Join(dir, name+"-key.pem")
	if err := writeChainPEM(certFile, leaf.der, chainDER); err != nil {
		return "", "", err
	}
	if err := writeKeyPEM(keyFile, leaf.key); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// leafOf parses the first CERTIFICATE block of a PEM file (the leaf).
func leafOf(certFile string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ssm-conformance: %s is not a PEM CERTIFICATE", certFile)
	}
	return x509.ParseCertificate(block.Bytes)
}

// rawLeafDER returns the DER of the first CERTIFICATE block WITHOUT parsing it
// through crypto/x509 — which rejects a duplicate-OID certificate outright (the
// two-role negative). mbtls.RoleFromDER walks the DER with its own lenient parser,
// so the referee's role taxonomy is not held hostage to Go's x509 strictness.
func rawLeafDER(certFile string) ([]byte, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ssm-conformance: %s is not a PEM CERTIFICATE", certFile)
	}
	return block.Bytes, nil
}

// chainDepth counts the CERTIFICATE blocks in a PEM file (leaf + intermediates
// the peer would send — the TCP-51 "full chain" evidence).
func chainDepth(certFile string) int {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return 0
	}
	n := 0
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return n
		}
		if block.Type == "CERTIFICATE" {
			n++
		}
	}
}

// isP256 reports whether a certificate carries an EC P-256 public key (TCP-42).
func isP256(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && pub.Curve == elliptic.P256()
}

// peerLeaf parses the peer (server) leaf certificate a session captured, for the
// server-side X.509 / P-256 assertions. Returns nil if the session has no peer
// DER or it fails to parse.
func peerLeaf(sess *mbtls.Session) *x509.Certificate {
	if sess == nil || len(sess.PeerDER) == 0 {
		return nil
	}
	c, err := x509.ParseCertificate(sess.PeerDER)
	if err != nil {
		return nil
	}
	return c
}

// certVer returns a certificate's X.509 version number, or 0 if nil.
func certVer(c *x509.Certificate) int {
	if c == nil {
		return 0
	}
	return c.Version
}

// curveName names a certificate's EC curve for evidence strings.
func curveName(c *x509.Certificate) string {
	if c == nil {
		return "?"
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "non-EC"
	}
	return pub.Curve.Params().Name
}
