package suitepki

// mint.go is the PKI precondition toolkit: a throwaway 2030.5-shaped
// certificate authority hierarchy and the leaves — conformant, role-bearing and
// deliberately broken — that a conformance check needs to present to the DUT.
//
// It exists because half the interesting criteria in this catalog are about
// what a conformant peer REFUSES, and a suite that cannot mint an expired
// certificate, a certificate under an untrusted root, or a certificate carrying
// two role extensions cannot demonstrate a refusal. The committed fixture tree
// (certs/mbaps, `make gen-mbaps-certs`) already ships a seven-case negative
// matrix and this package reads it happily — but that tree is shared, static,
// and its defects are role-extension defects, whereas SS-TEST-PKI's error
// certificates are chain and validity defects on a serca-mica-device chain.
// Both kinds are needed, so both are available: the committed tree for what it
// covers, minted material for the rest.
//
// Nothing here writes into certs/mbaps. Material minted for a check lives in
// memory unless a caller explicitly asks for files (WritePEM), and then it goes
// wherever the caller says — normally a temporary directory. The shared fixture
// tree is read-only to this package: other agents build against it
// concurrently, and a suite that regenerated it mid-run would corrupt somebody
// else's evidence.
//
// # The IMPLICIT tag that everyone gets wrong
//
// GeneralName's otherName choice is [0] IMPLICIT OtherName. Implicit tagging
// REPLACES the SEQUENCE tag rather than wrapping it, so the context-0 value's
// content is the SEQUENCE's content, with no inner 0x30. Emitting an explicit
// wrapper instead produces a certificate every strict parser rejects and every
// lenient one silently ignores — the worst possible failure for a test fixture,
// because the test then passes for the wrong reason. marshalOtherName below
// gets it right and TestOtherNameRoundTrip proves it by feeding the output back
// through the independent parser in certfacts.go.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CA is one certificate authority in a test hierarchy, with its private key.
type CA struct {
	Name   string
	Cert   *x509.Certificate
	DER    []byte
	Key    *ecdsa.PrivateKey
	Parent *CA // nil for a root
}

// IsRoot reports whether this CA is the trust anchor of its hierarchy.
func (c *CA) IsRoot() bool { return c == nil || c.Parent == nil }

// CertPEM renders the CA certificate.
func (c *CA) CertPEM() []byte { return pemBlock("CERTIFICATE", c.DER) }

// KeyPEM renders the CA private key as PKCS#8.
func (c *CA) KeyPEM() ([]byte, error) { return keyPEM(c.Key) }

// Path returns this CA and every CA above it, nearest first, ending at the
// root.
func (c *CA) Path() []*CA {
	var out []*CA
	for p := c; p != nil; p = p.Parent {
		out = append(out, p)
	}
	return out
}

// Pool returns a trust pool holding this CA's root, which is what a peer
// verifying certificates issued under this hierarchy needs.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	path := c.Path()
	if len(path) == 0 {
		return pool
	}
	pool.AddCert(path[len(path)-1].Cert)
	return pool
}

// Hierarchy is a 2030.5-shaped test PKI: a Smart Energy Root CA (SERCA), a
// Manufacturer CA (MCA) issued by it, and a Manufacturer Issuing CA (MICA)
// issued by the MCA. §3.1.2 of the test-PKI document also allows a MICA issued
// directly by the SERCA, which is what MICADirect is, so all three of the valid
// device chains can be produced from one hierarchy:
//
//	serca-device            leaf issued by SERCA        (Depth 1 on the wire)
//	serca-mica-device       leaf issued by MICADirect   (Depth 2)
//	serca-mca-mica-device   leaf issued by MICA         (Depth 3)
type Hierarchy struct {
	SERCA *CA
	MCA   *CA
	// MICA is issued by the MCA — the deepest of the three valid chains.
	MICA *CA
	// MICADirect is issued by the SERCA, the two-deep chain.
	MICADirect *CA
}

// NewHierarchy mints a fresh hierarchy. prefix is prepended to each CA's common
// name so two hierarchies in one run are distinguishable in a report.
//
// A hierarchy minted this way is anchored on a root the DUT has never heard of,
// so it can demonstrate REFUSAL but never acceptance. For the acceptance half,
// build the hierarchy under the trust anchor the DUT is actually configured
// with — see HierarchyUnder and AdoptCAFromFiles.
func NewHierarchy(prefix string) (*Hierarchy, error) {
	if prefix == "" {
		prefix = "suitepki"
	}
	serca, err := NewCA(prefix+" SERCA", nil, 2)
	if err != nil {
		return nil, err
	}
	return HierarchyUnder(serca, prefix)
}

// HierarchyUnder builds the MCA and MICA tiers under an existing root, so a
// check can present the DUT with all three IEEE 2030.5 chain depths anchored at
// a root the DUT already trusts.
func HierarchyUnder(serca *CA, prefix string) (*Hierarchy, error) {
	if serca == nil {
		return nil, fmt.Errorf("suitepki: HierarchyUnder needs a root CA")
	}
	if prefix == "" {
		prefix = "suitepki"
	}
	mca, err := NewCA(prefix+" MCA", serca, 1)
	if err != nil {
		return nil, err
	}
	mica, err := NewCA(prefix+" MICA", mca, 0)
	if err != nil {
		return nil, err
	}
	direct, err := NewCA(prefix+" MICA (SERCA-issued)", serca, 0)
	if err != nil {
		return nil, err
	}
	return &Hierarchy{SERCA: serca, MCA: mca, MICA: mica, MICADirect: direct}, nil
}

// IssuerFor returns the CA that issues leaves for a given chain shape.
func (h *Hierarchy) IssuerFor(shape ChainShape) (*CA, error) {
	switch shape {
	case ShapeSERCADevice:
		return h.SERCA, nil
	case ShapeSERCAMICADevice:
		return h.MICADirect, nil
	case ShapeSERCAMCAMICADevice:
		return h.MICA, nil
	default:
		return nil, fmt.Errorf("suitepki: no issuer for chain shape %q", shape)
	}
}

// NewCA mints a CA. parent nil makes a self-signed root; pathLen sets the
// BasicConstraints pathLenConstraint, which is what stops a MICA from being
// used as an MCA.
func NewCA(name string, parent *CA, pathLen int) (*CA, error) {
	return NewCAExt(name, parent, pathLen, nil)
}

// NewCAExt is NewCA with extra extensions emitted verbatim into the CA
// certificate.
//
// It exists for the COMM-004 D/E/F fixtures, whose entire content is an
// intermediate CA carrying one deliberately non-conformant extension: a
// critical extendedKeyUsage naming a meaningless purpose, a non-critical
// nameConstraints, a non-critical policyMappings mapping anyPolicy. See
// servechain.go, which constructs those and records the clause of RFC 5280
// that condemns each one.
func NewCAExt(name string, parent *CA, pathLen int, extra []pkix.Extension) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("suitepki: generate %s key: %w", name, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		ExtraExtensions:       extra,
	}
	signer, issuer := key, tmpl
	if parent != nil {
		signer, issuer = parent.Key, parent.Cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("suitepki: sign %s: %w", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// Deliberately strict, even though this constructor now mints
		// deliberately non-conformant CAs. A CA is used as an ISSUER — the
		// caller signs a leaf with it, and x509.CreateCertificate needs the
		// parsed parent to do that — so a CA whose own certificate does not
		// re-parse cannot be used at all, and saying so here beats a nil
		// dereference two calls later. The COMM-004 defects are wrong in ways
		// a parser accepts and a VERIFIER must reject, which is the point.
		return nil, fmt.Errorf("suitepki: re-parse %s: %w", name, err)
	}
	return &CA{Name: name, Cert: cert, DER: der, Key: key, Parent: parent}, nil
}

// AdoptCAFromFiles loads an existing CA from a certificate and key on disk.
//
// This is how a check reaches the BENCH root (certs/mbaps/ca-cert.pem +
// ca-key.pem): the DUT's trust domain is anchored on it, so a certificate the
// DUT must be shown to ACCEPT has to be issued under it, and a freshly minted
// hierarchy — which the DUT has never heard of — can only demonstrate refusal.
// Both are needed; this is the accept half.
//
// The key file is read but never copied anywhere, and no material issued under
// the adopted CA is written back into its directory.
func AdoptCAFromFiles(name, certPath, keyPath string) (*CA, error) {
	ders, err := LoadPEMChain(certPath)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, fmt.Errorf("suitepki: parse %s: %w", certPath, err)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("suitepki: read %s: %w", keyPath, err)
	}
	key, err := parseECKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("suitepki: %s: %w", keyPath, err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("suitepki: %s does not match %s", keyPath, certPath)
	}
	if name == "" {
		name = cert.Subject.CommonName
	}
	return &CA{Name: name, Cert: cert, DER: ders[0], Key: key}, nil
}

func parseECKeyPEM(raw []byte) (*ecdsa.PrivateKey, error) {
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, fmt.Errorf("no private key PEM block found")
		}
		if !strings.Contains(blk.Type, "PRIVATE KEY") {
			continue
		}
		if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("private key does not parse as SEC1 or PKCS#8: %w", err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, not the EC P-256 key the mbaps profile requires", k)
		}
		return ec, nil
	}
}

// RoleEncoding selects the ASN.1 string type the SunSpec role extension's value
// is encoded with. SunSpecTCP-30 mandates UTF8String; PrintableString is the
// bad-encoding negative fixture.
type RoleEncoding string

// The role encodings this package can emit.
const (
	RoleUTF8String      RoleEncoding = "UTF8String"
	RolePrintableString RoleEncoding = "PrintableString"
	defaultRoleEncoding              = RoleUTF8String
)

// DeviceIdentitySpec describes the IEEE 2030.5 device identity to embed.
type DeviceIdentitySpec struct {
	// HWType is the manufacturer model OID, normally an IANA PEN plus a model
	// hierarchy (1.3.6.1.4.1.<pen>.<model...>).
	HWType asn1.ObjectIdentifier
	// Serial is the device serial number.
	Serial string
	// SerialTag overrides the serial's ASN.1 tag. Zero means OCTET STRING,
	// which is what IEEE 2030.5 requires; setting it to asn1.TagUTF8String
	// mints the wrong-tag negative fixture PKI-7 exists to catch.
	SerialTag int
}

// LeafSpec describes an end-entity certificate to mint.
//
// The zero value mints a leaf with an EMPTY Subject and no identity extension
// at all, which is deliberately useless: every field a fixture depends on has
// to be stated, so a fixture never accidentally acquires a property the test
// then credits it with.
type LeafSpec struct {
	// Name labels the fixture in reports; it is not a certificate field.
	Name string
	// CommonName populates the Subject. Leave it empty to mint the EMPTY
	// Subject IEEE 2030.5-2018 requires of a device certificate.
	CommonName string
	// Identity, when set, emits the 2030.5 SubjectAltName otherName. Leaving it
	// nil reproduces what the DUT does today.
	Identity *DeviceIdentitySpec
	// Roles are SunSpec role extension values. One entry is the conformant
	// case; two mint the two-role fixture; none omits the extension.
	Roles []string
	// RoleEncoding selects the ASN.1 string type; empty means UTF8String.
	RoleEncoding RoleEncoding
	// NotBefore / NotAfter override the validity window. Zero values mint a
	// currently-valid certificate; setting them in the past or the future mints
	// the expired / not-yet-valid fixtures.
	NotBefore, NotAfter time.Time
	DNSNames            []string
	IPAddresses         []net.IP
	// Server and Client select the extended key usages. A role certificate on
	// this bench carries both, because the same identity is presented northbound
	// as a client and southbound as a server.
	Server, Client bool
	// ExtraExtensions are emitted verbatim, for fixtures this struct does not
	// anticipate.
	ExtraExtensions []pkix.Extension
}

// Leaf is a minted end-entity certificate and its key.
type Leaf struct {
	Name   string
	DER    []byte
	Cert   *x509.Certificate
	Key    *ecdsa.PrivateKey
	Issuer *CA
}

// Mint issues a leaf under the given CA.
func Mint(issuer *CA, spec LeafSpec) (*Leaf, error) {
	if issuer == nil {
		return nil, fmt.Errorf("suitepki: Mint needs an issuing CA")
	}
	return mintLeaf(issuer, spec)
}

// MintSelfSigned issues an END-ENTITY certificate signed by its own key: its
// issuer is itself, and it chains to nothing.
//
// This is not NewCA with IsCA false. A CA certificate self-signs as a matter of
// course and says so in BasicConstraints; this is the deliberate anomaly of a
// device certificate that is its own issuer with CA=false, which is exactly
// what COMM-004 sub-test G means by "a self-signed device certificate with no
// chain to a trusted SERCA". The resulting Leaf has a nil Issuer, so ChainDER
// yields the single certificate and nothing else — which is the whole fixture.
func MintSelfSigned(spec LeafSpec) (*Leaf, error) { return mintLeaf(nil, spec) }

// mintLeaf is the shared body. A nil issuer signs the certificate with its own
// key, making it self-issued and self-signed.
func mintLeaf(issuer *CA, spec LeafSpec) (*Leaf, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("suitepki: generate %s key: %w", spec.Name, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	nb, na := spec.NotBefore, spec.NotAfter
	if nb.IsZero() {
		nb = now.Add(-time.Hour)
	}
	if na.IsZero() {
		na = now.AddDate(2, 0, 0)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if spec.CommonName != "" {
		tmpl.Subject = pkix.Name{CommonName: spec.CommonName}
	}
	if spec.Server {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if spec.Client {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	// The SubjectAltName has to be assembled by hand whenever an otherName is
	// wanted: x509.CreateCertificate builds its own SAN from DNSNames and
	// IPAddresses and knows nothing about otherName, so letting it do that AND
	// adding ours would emit two SubjectAltName extensions.
	if spec.Identity != nil {
		san, err := marshalSAN(spec.Identity, spec.DNSNames, spec.IPAddresses)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: OIDSubjectAltName, Value: san,
		})
	} else {
		tmpl.DNSNames = spec.DNSNames
		tmpl.IPAddresses = spec.IPAddresses
	}

	enc := spec.RoleEncoding
	if enc == "" {
		enc = defaultRoleEncoding
	}
	for _, role := range spec.Roles {
		val, err := marshalRoleValue(role, enc)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: OIDSunSpecRole, Value: val,
		})
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, spec.ExtraExtensions...)

	// A nil issuer means self-signed: the template is its own parent and the
	// leaf's own key is the signer.
	issuerCert, signerKey := tmpl, key
	if issuer != nil {
		issuerCert, signerKey = issuer.Cert, issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, &key.PublicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("suitepki: sign leaf %s: %w", spec.Name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// A fixture whose whole point is to be malformed may not re-parse.
		// That is not a minting failure, and the DER is still usable.
		cert = nil
	}
	name := spec.Name
	if name == "" {
		name = spec.CommonName
	}
	return &Leaf{Name: name, DER: der, Cert: cert, Key: key, Issuer: issuer}, nil
}

// Mint issues a leaf under one of this hierarchy's CAs, selected by the chain
// shape the caller wants the DUT to see.
func (h *Hierarchy) Mint(shape ChainShape, spec LeafSpec) (*Leaf, error) {
	issuer, err := h.IssuerFor(shape)
	if err != nil {
		return nil, err
	}
	return Mint(issuer, spec)
}

// ChainDER assembles the chain to present on the wire: the leaf first, then
// every CA above it EXCEPT the root.
//
// Omitting the root is the rule (SunSpecTCP-51, RFC 5246 §7.4.2): the trust
// anchor is configured out of band and a peer that sends it is asking to be
// trusted on its own say-so. It also makes the presented depth mean what
// PKI-19's observable says it means.
func (l *Leaf) ChainDER() [][]byte {
	out := [][]byte{l.DER}
	for _, ca := range l.Issuer.Path() {
		if ca.IsRoot() {
			break
		}
		out = append(out, ca.DER)
	}
	return out
}

// ChainDERWithRoot assembles the chain INCLUDING the root, for the deliberate
// "sender shipped its own trust anchor" case.
func (l *Leaf) ChainDERWithRoot() [][]byte {
	out := [][]byte{l.DER}
	for _, ca := range l.Issuer.Path() {
		out = append(out, ca.DER)
	}
	return out
}

// CertPEM renders the leaf-first chain as PEM, which is the form a TLS stack
// configured from files expects.
func (l *Leaf) CertPEM() []byte {
	var out []byte
	for _, der := range l.ChainDER() {
		out = append(out, pemBlock("CERTIFICATE", der)...)
	}
	return out
}

// KeyPEM renders the private key as PKCS#8.
func (l *Leaf) KeyPEM() ([]byte, error) { return keyPEM(l.Key) }

// TLSCertificate builds the crypto/tls certificate for presenting this leaf and
// its chain.
func (l *Leaf) TLSCertificate() tls.Certificate {
	return tls.Certificate{Certificate: l.ChainDER(), PrivateKey: l.Key, Leaf: l.Cert}
}

// WritePEM writes the leaf-first chain and its key into dir, returning the two
// paths. It is for the callers that configure a TLS stack from files rather
// than from memory; dir should be a temporary directory, never the committed
// fixture tree.
func (l *Leaf) WritePEM(dir, stem string) (certPath, keyPath string, err error) {
	if stem == "" {
		stem = l.Name
	}
	if stem == "" {
		stem = "leaf"
	}
	certPath = filepath.Join(dir, stem+"-cert.pem")
	keyPath = filepath.Join(dir, stem+"-key.pem")
	kp, err := l.KeyPEM()
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, l.CertPEM(), 0o644); err != nil {
		return "", "", fmt.Errorf("suitepki: write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, kp, 0o600); err != nil {
		return "", "", fmt.Errorf("suitepki: write %s: %w", keyPath, err)
	}
	return certPath, keyPath, nil
}

// Fixture is one named piece of test material plus what is expected of it.
type Fixture struct {
	Name string
	Leaf *Leaf
	// Defect names what is deliberately wrong, in the language a report prints.
	Defect string
	// FatalToHandshake records whether a conformant peer must refuse this
	// certificate DURING the TLS handshake (a chain or validity defect), as
	// opposed to accepting the connection and refusing at the authorization
	// layer (a role defect). Getting this distinction right is the difference
	// between a negative test that proves something and one that merely
	// observes a disconnection.
	FatalToHandshake bool
}

// NegativeSet is the deliberate-error material this suite and the transport
// suites present to the DUT.
type NegativeSet struct {
	// Under is the CA the chain-valid fixtures are issued by.
	Under *CA
	// Foreign is an unrelated root, the issuer of the wrong-CA fixture.
	Foreign    *CA
	Fixtures   []Fixture
	byName     map[string]Fixture
	baseCommon string
}

// NegativeFixtures mints the deliberate-error matrix under the given CA.
//
// The seven cases mirror the committed tree (certs/mbaps/negative) so a report
// can speak about both in the same vocabulary, plus not-yet-valid, which the
// committed tree does not carry and which is the cleanest chain-independent
// validity defect there is.
func NegativeFixtures(under *CA, commonName string) (*NegativeSet, error) {
	if under == nil {
		return nil, fmt.Errorf("suitepki: NegativeFixtures needs an issuing CA")
	}
	if commonName == "" {
		commonName = "suitepki negative fixture"
	}
	foreign, err := NewCA("suitepki foreign root (untrusted)", nil, 1)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	base := func(name string) LeafSpec {
		return LeafSpec{
			Name: name, CommonName: commonName + " " + name,
			Roles: []string{"GridServiceSunSpec"}, Client: true, Server: true,
		}
	}
	type plan struct {
		name   string
		defect string
		fatal  bool
		mutate func(*LeafSpec)
		issuer *CA
	}
	plans := []plan{
		{"expired", "validity window ended in the past", true, func(s *LeafSpec) {
			s.NotBefore, s.NotAfter = now.AddDate(-2, 0, 0), now.AddDate(-1, 0, 0)
		}, under},
		{"not-yet-valid", "validity window begins in the future", true, func(s *LeafSpec) {
			s.NotBefore, s.NotAfter = now.AddDate(1, 0, 0), now.AddDate(2, 0, 0)
		}, under},
		{"wrong-ca", "issued by a root the peer does not trust", true, nil, foreign},
		{"no-role", "SunSpec role extension absent", false, func(s *LeafSpec) { s.Roles = nil }, under},
		{"two-role", "two SunSpec role extensions; exactly one is mandated", false, func(s *LeafSpec) {
			s.Roles = []string{"GridServiceSunSpec", "ReadOnlySunSpec"}
		}, under},
		{"empty-role", "role value is the empty UTF8String", false, func(s *LeafSpec) {
			s.Roles = []string{""}
		}, under},
		{"oversize-role", "role value is a 1024-byte UTF8String", false, func(s *LeafSpec) {
			s.Roles = []string{strings.Repeat("A", 1024)}
		}, under},
		{"bad-encoding", "role value is a PrintableString, not the mandated UTF8String", false, func(s *LeafSpec) {
			s.RoleEncoding = RolePrintableString
		}, under},
	}
	set := &NegativeSet{Under: under, Foreign: foreign, byName: map[string]Fixture{}, baseCommon: commonName}
	for _, p := range plans {
		spec := base(p.name)
		if p.mutate != nil {
			p.mutate(&spec)
		}
		leaf, err := Mint(p.issuer, spec)
		if err != nil {
			return nil, err
		}
		f := Fixture{Name: p.name, Leaf: leaf, Defect: p.defect, FatalToHandshake: p.fatal}
		set.Fixtures = append(set.Fixtures, f)
		set.byName[p.name] = f
	}
	return set, nil
}

// Fixture returns one fixture by name.
func (s *NegativeSet) Fixture(name string) (Fixture, error) {
	f, ok := s.byName[name]
	if !ok {
		names := make([]string, 0, len(s.byName))
		for k := range s.byName {
			names = append(names, k)
		}
		return Fixture{}, fmt.Errorf("suitepki: no negative fixture %q (have: %s)", name, strings.Join(names, ", "))
	}
	return f, nil
}

// HandshakeFatal returns the fixtures a conformant peer must refuse during the
// handshake.
func (s *NegativeSet) HandshakeFatal() []Fixture {
	var out []Fixture
	for _, f := range s.Fixtures {
		if f.FatalToHandshake {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// DER assembly
// ---------------------------------------------------------------------------

// marshalRoleValue encodes a SunSpec role extension value: a single ASN.1
// string holding the role name.
func marshalRoleValue(role string, enc RoleEncoding) ([]byte, error) {
	tag := asn1.TagUTF8String
	if enc == RolePrintableString {
		tag = asn1.TagPrintableString
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte(role),
	})
}

// marshalSAN assembles a SubjectAltName holding the 2030.5 otherName plus any
// dNSName / iPAddress entries the caller also wanted.
func marshalSAN(id *DeviceIdentitySpec, dns []string, ips []net.IP) ([]byte, error) {
	var body []byte
	if id != nil {
		hmn, err := marshalHardwareModuleName(id)
		if err != nil {
			return nil, err
		}
		on, err := marshalOtherName(OIDHardwareModuleName, hmn)
		if err != nil {
			return nil, err
		}
		body = append(body, on...)
	}
	for _, name := range dns {
		// dNSName is [2] IMPLICIT IA5String.
		der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(name)})
		if err != nil {
			return nil, fmt.Errorf("suitepki: marshal dNSName %q: %w", name, err)
		}
		body = append(body, der...)
	}
	for _, ip := range ips {
		b := ip.To4()
		if b == nil {
			b = ip.To16()
		}
		// iPAddress is [7] IMPLICIT OCTET STRING.
		der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: b})
		if err != nil {
			return nil, fmt.Errorf("suitepki: marshal iPAddress %s: %w", ip, err)
		}
		body = append(body, der...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})
}

// marshalHardwareModuleName encodes RFC 4108 §5's HardwareModuleName, honouring
// a deliberately wrong serial tag when one is asked for.
func marshalHardwareModuleName(id *DeviceIdentitySpec) ([]byte, error) {
	oid, err := asn1.Marshal(id.HWType)
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal hwType %v: %w", id.HWType, err)
	}
	tag := id.SerialTag
	if tag == 0 {
		tag = asn1.TagOctetString
	}
	serial, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte(id.Serial),
	})
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal hwSerialNum: %w", err)
	}
	body := append(append([]byte{}, oid...), serial...)
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body,
	})
}

// marshalOtherName wraps a value as a GeneralName otherName.
//
// [0] IMPLICIT OtherName: the context tag REPLACES the SEQUENCE tag, so the
// content is the SEQUENCE's content — type-id followed by the [0] EXPLICIT
// value — and there is no inner 0x30. See the file comment.
func marshalOtherName(typeID asn1.ObjectIdentifier, value []byte) ([]byte, error) {
	oid, err := asn1.Marshal(typeID)
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal otherName type-id: %w", err)
	}
	wrapper, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: value,
	})
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal otherName value: %w", err)
	}
	body := append(append([]byte{}, oid...), wrapper...)
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body,
	})
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("suitepki: serial number: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("suitepki: marshal private key: %w", err)
	}
	return pemBlock("PRIVATE KEY", der), nil
}
