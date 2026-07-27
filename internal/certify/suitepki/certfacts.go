package suitepki

// certfacts.go turns DER into the facts this suite decides on.
//
// The one thing here that no library will do for you is the IEEE 2030.5 device
// identity. crypto/x509 parses SubjectAltName, but it keeps only the four
// GeneralName choices it understands (dNSName, iPAddress, rfc822Name,
// uniformResourceIdentifier) and DISCARDS otherName entirely — which is
// precisely the choice 2030.5 puts the device identity in. A check written
// against x509.Certificate.DNSNames et al. would therefore report "no SAN
// identity" for a perfectly conformant certificate and for a certificate with
// no identity at all, with no way to tell them apart. So the SAN extension is
// walked here, by hand, from its raw DER.
//
// The walk is deliberately lenient in one direction and strict in the other.
// Lenient: an otherName whose type-id is id-on-hardwareModuleName but whose
// value does not decode is REPORTED (IdentityErr), not skipped, because "the
// DUT emitted a malformed device identity" is a finding and silently dropping
// it would turn a FAIL into a different FAIL for the wrong reason. Strict: the
// serial number's actual ASN.1 tag is preserved rather than coerced, because
// PKI-7's pass criterion is literally the tag — OCTET STRING (0x04) carrying
// UTF-8 — and a parser that accepted a UTF8String there would make the row
// unfailable.

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"csip-tls-test/internal/evidence/tlsdis"
)

// The object identifiers this suite reasons about.
var (
	// OIDHardwareModuleName is RFC 4108 §5 id-on-hardwareModuleName. IEEE
	// 2030.5-2018 carries the device identity in a SubjectAltName otherName of
	// this type, whose value is a HardwareModuleName SEQUENCE of the
	// manufacturer model OID (hwType) and the device serial number
	// (hwSerialNum). It is what makes `openssl x509 -text` print
	// "othername: hwType=..., hwSerialNum=...".
	OIDHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}

	// OIDSubjectAltName is RFC 5280 §4.2.1.6.
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

	// OIDIANAPrivateEnterprise is the IANA Private Enterprise Number arc,
	// 1.3.6.1.4.1. PKI-6's pass criterion is that hwType begins here.
	OIDIANAPrivateEnterprise = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1}

	// OIDSunSpecRole is the Secure SunSpec Modbus client-role extension,
	// 1.3.6.1.4.1.50316.802.1 — a private-enterprise OID under lexa's PEN
	// (50316) and the only PEN-rooted identity the product publishes today.
	// The extraction path is tlsdis.RoleFromDER, the evidence engine's own
	// independent parser; this is a copy of the OID for reporting only.
	OIDSunSpecRole = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50316, 802, 1}
)

// OtherName is one SubjectAltName otherName entry, kept with its raw DER.
//
// The raw bytes travel with it because an assertion about an extension is an
// assertion about bytes: "the certificate carries no 2030.5 device identity" is
// only re-checkable by a third party if the exact SAN contents are quotable.
type OtherName struct {
	// TypeID is the otherName's type-id OID.
	TypeID asn1.ObjectIdentifier
	// Value is the DER of the value inside the [0] EXPLICIT wrapper.
	Value []byte
	// Raw is the whole GeneralName as it appeared, tag included.
	Raw []byte
	// Err records a structurally broken entry rather than dropping it.
	Err string
}

// DeviceIdentity is the IEEE 2030.5-2018 device identity: a manufacturer model
// OID and a device serial number, carried in a SAN otherName of type
// id-on-hardwareModuleName.
type DeviceIdentity struct {
	// HWType is the manufacturer model OID.
	HWType asn1.ObjectIdentifier
	// HWSerialNum is the serial number's ASN.1 value bytes, verbatim.
	HWSerialNum []byte
	// SerialTag is the ASN.1 tag the serial number was actually encoded with.
	// IEEE 2030.5 requires OCTET STRING (asn1.TagOctetString, 4); anything else
	// is a conformance failure this field is what proves.
	SerialTag int
	// SerialIsOctetString reports SerialTag == 4.
	SerialIsOctetString bool
	// SerialIsUTF8 reports whether the serial bytes are valid UTF-8, which is
	// the SunSpec convention for the OCTET STRING's contents.
	SerialIsUTF8 bool
	// Serial is the serial rendered as a string when it is valid UTF-8,
	// otherwise its hex.
	Serial string
	// Raw is the HardwareModuleName's DER, verbatim.
	Raw []byte
}

// String renders the identity the way openssl x509 -text does, which is the
// form the test procedure's expected output is written in.
func (d *DeviceIdentity) String() string {
	if d == nil {
		return "<none>"
	}
	return fmt.Sprintf("hwType=%s, hwSerialNum=%s", d.HWType, d.Serial)
}

// PEN returns the IANA Private Enterprise Number hwType is rooted at, and
// whether it is rooted at one at all (PKI-6).
func (d *DeviceIdentity) PEN() (string, bool) {
	if d == nil || len(d.HWType) <= len(OIDIANAPrivateEnterprise) {
		return "", false
	}
	for i, arc := range OIDIANAPrivateEnterprise {
		if d.HWType[i] != arc {
			return "", false
		}
	}
	return fmt.Sprint(d.HWType[len(OIDIANAPrivateEnterprise)]), true
}

// CertFacts is one certificate, dissected.
//
// Info is the evidence engine's own dissection (internal/evidence/tlsdis),
// reused rather than reimplemented: it already walks extensions leniently
// enough to report a duplicate-OID certificate that crypto/x509 refuses to
// parse at all, and sharing it means the certificate a report describes and the
// certificate the bundle's verifier sees are dissected by the same code.
type CertFacts struct {
	Info   *tlsdis.CertInfo
	DER    []byte
	SHA256 string

	// SubjectEmpty is PKI-4's first pass criterion. It is derived from the raw
	// Subject RDNSequence, not from a rendered string, because "" is also what
	// a subject rendering can degrade to.
	SubjectEmpty bool
	// SubjectRDNs counts the relative distinguished names in the Subject.
	SubjectRDNs int

	SubjectKeyID   []byte
	AuthorityKeyID []byte

	// SANPresent reports whether a SubjectAltName extension exists at all;
	// OtherNames are its otherName entries.
	SANPresent bool
	OtherNames []OtherName

	// Identity is the 2030.5 device identity, nil when the certificate carries
	// none. IdentityErr is set when a hardwareModuleName otherName was present
	// but could not be decoded — a different finding from its absence.
	Identity    *DeviceIdentity
	IdentityErr string

	// Role is the Secure SunSpec Modbus role, extracted with the evidence
	// engine's independent parser. RoleErr distinguishes absent from malformed.
	Role    string
	RoleErr string

	// PrivateEnterpriseOIDs are the certificate's non-standard extension OIDs
	// that are rooted at the IANA PEN arc. PKI-6 turns on whether the DUT
	// publishes ANY PEN-rooted identity, and on whether a model OID is among
	// them.
	PrivateEnterpriseOIDs []string

	// ParseErr records a crypto/x509 failure. The rest of the struct is still
	// populated: the certificates most worth reporting on are the ones a strict
	// parser rejects.
	ParseErr string

	cert *x509.Certificate
}

// Certificate returns the parsed certificate, or nil when it did not parse.
func (c *CertFacts) Certificate() *x509.Certificate { return c.cert }

// Subject returns the rendered Subject DN, "" for the empty Subject 2030.5
// requires.
func (c *CertFacts) Subject() string {
	if c.Info == nil {
		return ""
	}
	return c.Info.Subject
}

// Issuer returns the rendered Issuer DN.
func (c *CertFacts) Issuer() string {
	if c.Info == nil {
		return ""
	}
	return c.Info.Issuer
}

// Describe renders the one-line summary a report prints for a certificate.
func (c *CertFacts) Describe() string {
	subj := c.Subject()
	if subj == "" {
		subj = "<empty Subject>"
	}
	id := "no 2030.5 SAN identity"
	if c.Identity != nil {
		id = c.Identity.String()
	} else if c.IdentityErr != "" {
		id = "malformed 2030.5 SAN identity: " + c.IdentityErr
	}
	out := fmt.Sprintf("subject %s, issuer %s, sha256 %s, %s", subj, c.Issuer(), shortHash(c.SHA256), id)
	if c.ParseErr != "" {
		// A certificate crypto/x509 refuses still has extensions worth
		// reporting, but a reader must not read its blank Subject as an empty
		// one — that would silently satisfy PKI-4's first criterion.
		out += " [crypto/x509 refuses this certificate: " + c.ParseErr +
			"; the DN fields above are unread, not empty]"
	}
	return out
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// InspectDER dissects one DER certificate.
//
// It never returns an error for a certificate that is merely non-conformant —
// only for input that is not a certificate at all. Everything else is a field
// on the result, because this suite's job is to describe bad certificates
// precisely, not to refuse them.
func InspectDER(der []byte) (*CertFacts, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("suitepki: empty certificate")
	}
	// ParseCertInfo returns BOTH a populated CertInfo and an error when
	// crypto/x509 refuses a certificate whose extensions are still readable —
	// the duplicate-role-extension fixture being the canonical example. Those
	// are exactly the certificates this suite must be able to describe, so the
	// error is recorded rather than propagated. Only a DER that yields neither a
	// parsed certificate NOR any extensions is genuinely not a certificate.
	info, err := tlsdis.ParseCertInfo(der)
	if info == nil || (err != nil && len(info.Extensions) == 0) {
		return nil, fmt.Errorf("suitepki: certificate does not dissect: %w", err)
	}
	sum := sha256.Sum256(der)
	f := &CertFacts{
		Info:   info,
		DER:    append([]byte(nil), der...),
		SHA256: hex.EncodeToString(sum[:]),
	}
	if info.ParseError != "" {
		f.ParseErr = info.ParseError
	}
	if cert, cerr := x509.ParseCertificate(der); cerr == nil {
		f.cert = cert
		f.SubjectKeyID = cert.SubjectKeyId
		f.AuthorityKeyID = cert.AuthorityKeyId
		f.SubjectRDNs, f.SubjectEmpty = rdnCount(cert.RawSubject)
	} else if f.ParseErr == "" {
		f.ParseErr = cerr.Error()
	}

	if ext, ok := info.Extension(OIDSubjectAltName.String()); ok {
		f.SANPresent = true
		f.OtherNames = parseOtherNames(ext.Value)
		f.Identity, f.IdentityErr = deviceIdentity(f.OtherNames)
	}

	role, rerr := info.SunSpecRole()
	f.Role = role
	if rerr != nil {
		f.RoleErr = rerr.Error()
	}

	for _, e := range info.CustomExtensions() {
		if strings.HasPrefix(e.OID, OIDIANAPrivateEnterprise.String()+".") {
			f.PrivateEnterpriseOIDs = append(f.PrivateEnterpriseOIDs, e.OID)
		}
	}
	return f, nil
}

// rdnCount counts the RDNs in a raw Subject/Issuer DN and reports emptiness.
// An unparseable DN is reported as non-empty with a zero count: refusing to
// call something we could not read "empty" keeps a malformed certificate from
// accidentally passing PKI-4's first criterion.
func rdnCount(raw []byte) (n int, empty bool) {
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return 0, false
	}
	return len(seq), len(seq) == 0
}

// parseOtherNames walks a SubjectAltName extension value and returns its
// otherName ([0]) entries. Non-otherName GeneralNames are skipped; a malformed
// entry stops the walk and is recorded, because past a bad tag every subsequent
// offset is fiction.
func parseOtherNames(ext []byte) []OtherName {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(ext, &seq); err != nil {
		return []OtherName{{Err: "SubjectAltName does not decode: " + err.Error()}}
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return []OtherName{{Err: "SubjectAltName is not a GeneralNames SEQUENCE"}}
	}
	var out []OtherName
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		next, err := asn1.Unmarshal(rest, &gn)
		if err != nil {
			out = append(out, OtherName{Err: "GeneralName does not decode: " + err.Error()})
			break
		}
		rest = next
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
			continue // dNSName, iPAddress, ... — not our business here
		}
		out = append(out, parseOtherName(gn))
	}
	return out
}

// parseOtherName decodes one otherName GeneralName.
//
// OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }
// and the GeneralName tag is IMPLICIT, so gn.Bytes is the SEQUENCE's CONTENT,
// not a re-tagged SEQUENCE. Getting that wrong is the classic way to produce a
// parser that reports every otherName as malformed.
func parseOtherName(gn asn1.RawValue) OtherName {
	on := OtherName{Raw: append([]byte(nil), gn.FullBytes...)}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(gn.Bytes, &oid)
	if err != nil {
		on.Err = "otherName type-id does not decode: " + err.Error()
		return on
	}
	on.TypeID = oid
	var wrapper asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &wrapper); err != nil {
		on.Err = "otherName value does not decode: " + err.Error()
		return on
	}
	if wrapper.Class != asn1.ClassContextSpecific || wrapper.Tag != 0 || !wrapper.IsCompound {
		on.Err = "otherName value is not a [0] EXPLICIT wrapper"
		return on
	}
	on.Value = append([]byte(nil), wrapper.Bytes...)
	return on
}

// deviceIdentity finds and decodes the 2030.5 device identity among a
// certificate's otherNames.
func deviceIdentity(names []OtherName) (*DeviceIdentity, string) {
	for _, on := range names {
		if !on.TypeID.Equal(OIDHardwareModuleName) {
			continue
		}
		if on.Err != "" {
			return nil, on.Err
		}
		id, err := parseHardwareModuleName(on.Value)
		if err != nil {
			return nil, err.Error()
		}
		return id, ""
	}
	return nil, ""
}

// parseHardwareModuleName decodes RFC 4108 §5's
//
//	HardwareModuleName ::= SEQUENCE { hwType OBJECT IDENTIFIER, hwSerialNum OCTET STRING }
//
// preserving the serial's real ASN.1 tag rather than demanding an OCTET STRING,
// so a certificate that used the wrong tag can be reported as exactly that.
func parseHardwareModuleName(der []byte) (*DeviceIdentity, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil, fmt.Errorf("HardwareModuleName does not decode: %w", err)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, fmt.Errorf("HardwareModuleName is not a SEQUENCE (tag %d, class %d)", seq.Tag, seq.Class)
	}
	var hwType asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(seq.Bytes, &hwType)
	if err != nil {
		return nil, fmt.Errorf("hwType does not decode as an OBJECT IDENTIFIER: %w", err)
	}
	var serial asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &serial); err != nil {
		return nil, fmt.Errorf("hwSerialNum does not decode: %w", err)
	}
	id := &DeviceIdentity{
		HWType:              hwType,
		HWSerialNum:         append([]byte(nil), serial.Bytes...),
		SerialTag:           serial.Tag,
		SerialIsOctetString: serial.Class == asn1.ClassUniversal && serial.Tag == asn1.TagOctetString,
		Raw:                 append([]byte(nil), der...),
	}
	id.SerialIsUTF8 = utf8.Valid(id.HWSerialNum)
	if id.SerialIsUTF8 {
		id.Serial = string(id.HWSerialNum)
	} else {
		id.Serial = "0x" + hex.EncodeToString(id.HWSerialNum)
	}
	return id, nil
}

// ChainShape names the IEEE 2030.5 certificate chain a presented certificate
// list forms. The names are the specification's own (§3.1.2): the root (SERCA)
// is the trust anchor and is normally NOT sent, so the shape is read off the
// number of certificates in the Certificate handshake message.
type ChainShape string

// The three valid chains of IEEE 2030.5, plus the honest fourth answer.
const (
	ShapeSERCADevice        ChainShape = "serca-device"
	ShapeSERCAMICADevice    ChainShape = "serca-mica-device"
	ShapeSERCAMCAMICADevice ChainShape = "serca-mca-mica-device"
	ShapeUnknown            ChainShape = "unknown"
)

// ChainLink is the relationship between a certificate and the one above it.
//
// All three signals are reported separately because they fail separately: a
// chain can have matching DNs and a signature that does not verify (the
// classic mis-assembled chain), or a verifying signature with no key
// identifiers at all (a minimal CA), and a report that collapsed them to one
// boolean could not tell the operator which.
type ChainLink struct {
	Child, Issuer               int
	ChildSubject, IssuerSubject string
	IssuerDNMatches             bool
	KeyIDPresent                bool
	KeyIDMatches                bool
	SignatureValid              bool
	SignatureErr                string
}

// OK reports a link that holds by every signal available.
func (l ChainLink) OK() bool {
	return l.IssuerDNMatches && l.SignatureValid && (!l.KeyIDPresent || l.KeyIDMatches)
}

// ChainFacts is a certificate chain as it was presented, in wire order.
type ChainFacts struct {
	Certs []*CertFacts
	// Depth is the number of certificates presented — the quantity PKI-19's
	// observable is written in terms of.
	Depth int
	Links []ChainLink
	Shape ChainShape
	// TopSelfIssued reports that the last certificate is self-issued, i.e. the
	// sender included the root in-band. That changes what Depth means and is
	// therefore reported rather than folded into Shape.
	TopSelfIssued bool
	// SHA256 identifies the chain as a whole: the digest of every certificate's
	// DER, concatenated in wire order. It is what PKI-8's "the same chain every
	// time" comparison is made on.
	SHA256   string
	Problems []string
}

// Leaf returns the end-entity certificate, which RFC 5246 §7.4.2 and RFC 8446
// §4.4.2 both place first.
func (c *ChainFacts) Leaf() *CertFacts {
	if c == nil || len(c.Certs) == 0 {
		return nil
	}
	return c.Certs[0]
}

// Intermediates returns everything above the leaf.
func (c *ChainFacts) Intermediates() []*CertFacts {
	if c == nil || len(c.Certs) < 2 {
		return nil
	}
	return c.Certs[1:]
}

// Describe renders the chain for a report.
func (c *ChainFacts) Describe() string {
	if c == nil || len(c.Certs) == 0 {
		return "<no chain>"
	}
	parts := make([]string, 0, len(c.Certs))
	for _, f := range c.Certs {
		subj := f.Subject()
		if subj == "" {
			subj = "<empty Subject>"
		}
		parts = append(parts, subj)
	}
	return fmt.Sprintf("depth %d (%s): %s", c.Depth, c.Shape, strings.Join(parts, " <- "))
}

// InspectChain dissects a presented chain, leaf first.
func InspectChain(ders [][]byte) (*ChainFacts, error) {
	if len(ders) == 0 {
		return nil, fmt.Errorf("suitepki: empty certificate chain")
	}
	out := &ChainFacts{Depth: len(ders)}
	h := sha256.New()
	for i, der := range ders {
		f, err := InspectDER(der)
		if err != nil {
			return nil, fmt.Errorf("suitepki: chain entry %d: %w", i, err)
		}
		out.Certs = append(out.Certs, f)
		h.Write(der)
	}
	out.SHA256 = hex.EncodeToString(h.Sum(nil))

	for i := 1; i < len(out.Certs); i++ {
		out.Links = append(out.Links, linkOf(out.Certs[i-1], out.Certs[i], i-1, i))
	}
	top := out.Certs[len(out.Certs)-1]
	out.TopSelfIssued = top.Info != nil && top.Info.SelfIssued

	switch out.Depth {
	case 1:
		out.Shape = ShapeSERCADevice
	case 2:
		out.Shape = ShapeSERCAMICADevice
	case 3:
		out.Shape = ShapeSERCAMCAMICADevice
	default:
		out.Shape = ShapeUnknown
	}
	if out.TopSelfIssued {
		out.Problems = append(out.Problems, fmt.Sprintf(
			"the top certificate (%s) is self-issued: the sender included its trust anchor in-band, "+
				"so the presented depth %d is one more than the chain's issuing depth",
			top.Subject(), out.Depth))
	}
	for _, l := range out.Links {
		if !l.OK() {
			out.Problems = append(out.Problems, fmt.Sprintf(
				"chain link %d->%d does not hold: issuer DN match=%v, key-id match=%v (present=%v), signature valid=%v%s",
				l.Child, l.Issuer, l.IssuerDNMatches, l.KeyIDMatches, l.KeyIDPresent, l.SignatureValid,
				suffixIf(l.SignatureErr, " ("+l.SignatureErr+")")))
		}
	}
	return out, nil
}

func suffixIf(cond, s string) string {
	if cond == "" {
		return ""
	}
	return s
}

// linkOf evaluates the child/issuer relationship by all three signals.
func linkOf(child, issuer *CertFacts, ci, ii int) ChainLink {
	l := ChainLink{
		Child: ci, Issuer: ii,
		ChildSubject: child.Subject(), IssuerSubject: issuer.Subject(),
		IssuerDNMatches: child.Issuer() == issuer.Subject(),
	}
	if len(child.AuthorityKeyID) > 0 && len(issuer.SubjectKeyID) > 0 {
		l.KeyIDPresent = true
		l.KeyIDMatches = string(child.AuthorityKeyID) == string(issuer.SubjectKeyID)
	}
	switch {
	case child.cert == nil:
		l.SignatureErr = "child certificate did not parse"
	case issuer.cert == nil:
		l.SignatureErr = "issuer certificate did not parse"
	default:
		if err := child.cert.CheckSignatureFrom(issuer.cert); err != nil {
			l.SignatureErr = err.Error()
		} else {
			l.SignatureValid = true
		}
	}
	return l
}

// LoadPEMChain reads a PEM file holding one or more certificates and returns
// their DER in file order. It is the bridge from the committed fixture tree
// (certs/mbaps) into the inspection above.
func LoadPEMChain(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("suitepki: read %s: %w", path, err)
	}
	ders, err := DecodePEMChain(raw)
	if err != nil {
		return nil, fmt.Errorf("suitepki: %s: %w", path, err)
	}
	return ders, nil
}

// DecodePEMChain splits PEM bytes into certificate DER, in order.
func DecodePEMChain(raw []byte) ([][]byte, error) {
	var out [][]byte
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		out = append(out, blk.Bytes)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found")
	}
	return out, nil
}

// InspectPEMFile dissects every certificate in a PEM file, in order.
func InspectPEMFile(path string) (*ChainFacts, error) {
	ders, err := LoadPEMChain(path)
	if err != nil {
		return nil, err
	}
	return InspectChain(ders)
}
