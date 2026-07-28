package suitessm

// analysis.go is every PASS/FAIL/SKIP decision this suite makes, as pure
// functions over already-parsed inputs.
//
// The split is deliberate and it is the reason the suite's teeth can be proven
// without the bench: nothing in this file opens a socket, reads a file, or
// consults the clock. A test can therefore hand each function a synthetic
// non-conformant input — a ServerHello that selected the wrong suite, a
// certificate chain with only a leaf, a Modbus exception with three bytes of
// diagnostic text appended — and assert that the function says FAIL. A check
// whose decision logic lives inline in a network-driving function cannot be
// tested that way, and in practice is never tested at all.
//
// Vocabulary note: these functions return (certify.Verdict, observed string).
// The observed string is what goes into the bundle's Observed field, so it is
// written for a reader who has the pcap open and wants to know what to look at.

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// roleOID is the Modbus.org PEN role extension, transcribed from SSM-CONF-v0.8
// (RBAC-006 / SunSpecTCP-29) — not imported from the product's role package.
const roleOID = "1.3.6.1.4.1.50316.802.1"

// ── cipher suite policy ─────────────────────────────────────────────────────

// nullEncryptionSuites is the full IANA set of registered cipher suites with
// NULL encryption. CRYP-007 gives four codepoints as examples ("e.g.") and its
// own notes observe that the list is not exhaustive, so the suite checks the
// whole registered set rather than the four the document prints.
var nullEncryptionSuites = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0x002C: "TLS_PSK_WITH_NULL_SHA",
	0x002D: "TLS_DHE_PSK_WITH_NULL_SHA",
	0x002E: "TLS_RSA_PSK_WITH_NULL_SHA",
	0x00B0: "TLS_PSK_WITH_NULL_SHA256",
	0x00B1: "TLS_PSK_WITH_NULL_SHA384",
	0x00B2: "TLS_DHE_PSK_WITH_NULL_SHA256",
	0x00B3: "TLS_DHE_PSK_WITH_NULL_SHA384",
	0x00B4: "TLS_RSA_PSK_WITH_NULL_SHA256",
	0x00B5: "TLS_RSA_PSK_WITH_NULL_SHA384",
	0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
	0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
	0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
	0xC039: "TLS_ECDHE_PSK_WITH_NULL_SHA",
	0xC03A: "TLS_ECDHE_PSK_WITH_NULL_SHA256",
	0xC03B: "TLS_ECDHE_PSK_WITH_NULL_SHA384",
}

// nullEncryptionOffer is the provocation ClientHello's suite list for CRYP-007:
// only NULL-encryption suites, so a server with any encrypting suite must still
// find no common ground.
func nullEncryptionOffer() []uint16 {
	out := make([]uint16, 0, len(nullEncryptionSuites))
	for id := range nullEncryptionSuites {
		if id == 0x0000 {
			continue // TLS_NULL_WITH_NULL_NULL is never negotiable
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// nullSuitesIn returns the NULL-encryption suites present in an offer, by name.
func nullSuitesIn(offered []uint16) []string {
	var out []string
	for _, id := range offered {
		if n, ok := nullEncryptionSuites[id]; ok {
			out = append(out, fmt.Sprintf("0x%04X %s", id, n))
		}
	}
	return out
}

// weakHashSuites are registered suites whose MAC or PRF is MD5 or SHA-1, which
// CRYP-005 (SunSpecTCP-54..57) forbids. The list covers the codepoints a DUT
// could plausibly still carry rather than the entire historical registry.
var weakHashSuites = map[uint16]string{
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
}

// weakSignatureHashes are the signature_algorithms hash codes CRYP-005 forbids:
// the low byte of an RFC 5246 SignatureAndHashAlgorithm is the signature type
// and the HIGH byte is the hash, so 0x01 = md5 and 0x02 = sha1 in the high
// position.
func weakSignatureAlgorithms(sigalgs []uint16) []string {
	var out []string
	for _, s := range sigalgs {
		switch s >> 8 {
		case 1:
			out = append(out, fmt.Sprintf("0x%04X (md5, %s)", s, sigTypeName(uint8(s))))
		case 2:
			out = append(out, fmt.Sprintf("0x%04X (sha1, %s)", s, sigTypeName(uint8(s))))
		}
	}
	return out
}

func sigTypeName(t uint8) string {
	switch t {
	case 1:
		return "rsa"
	case 2:
		return "dsa"
	case 3:
		return "ecdsa"
	default:
		return fmt.Sprintf("sigtype %d", t)
	}
}

// discouragedOffer is the CRYP-003 provocation: suites the IANA TLS Cipher
// Suite Registry marks as not recommended. 3DES and the CBC-SHA suites are the
// canonical examples and are the ones a still-deployed server is most likely to
// have left enabled.
func discouragedOffer() []uint16 {
	return []uint16{
		suiteRSA_3DES_EDE_CBC_SHA,
		suiteECDHE_RSA_AES128_CBC_SHA,
		suiteDHE_RSA_AES128_CBC_SHA256,
		0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	}
}

// certificateBasedSuite reports whether a suite's key exchange authenticates
// with an X.509 certificate, which is CRYP-006's SunSpecTCP-16 criterion. The
// TLS 1.3 suites carry no key-exchange in the codepoint at all; RFC 8446 makes
// certificate authentication the default for every one of them.
func certificateBasedSuite(id uint16) (bool, string) {
	name := tlsdis.CipherSuiteName(id)
	switch {
	case id>>8 == 0x13:
		return true, "TLS 1.3 suite; RFC 8446 authenticates with an X.509 certificate unless a PSK is negotiated"
	case strings.Contains(name, "ECDSA"), strings.Contains(name, "_RSA_"),
		strings.Contains(name, "ECDHE_RSA"), strings.Contains(name, "DSS"):
		return true, "certificate-based key exchange in the suite name: " + name
	case strings.Contains(name, "PSK"), strings.Contains(name, "anon"),
		strings.Contains(name, "DH_anon"):
		return false, "not certificate-based: " + name
	case strings.HasPrefix(name, "UNKNOWN"):
		return false, "codepoint is not in the bench's IANA transcription: " + name
	default:
		return false, "cannot classify the key exchange of " + name
	}
}

// offeredSuiteCensusVerdict decides CRYP-006's client half (SunSpecTCP-15/16):
// every cipher suite the peer OFFERS is IANA-registered and certificate-based.
//
// Two classes of codepoint appear in a cipher_suites vector without being
// cipher suites, and neither can be classified by key exchange because neither
// has one:
//
//   - RFC 8701 GREASE values, already excluded here since the beginning;
//   - signalling values (SCSVs). RFC 5746 §3.3: TLS_EMPTY_RENEGOTIATION_INFO_SCSV
//     "is not a true cipher suite (it does not correspond to any valid set of
//     algorithms) and cannot be negotiated". RFC 7507 §3 says the same of
//     TLS_FALLBACK_SCSV.
//
// Counting an SCSV as a suite is a category error with a live consequence.
// RFC 5746 §3.4 lets a client provide the SunSpecTCP-62 renegotiation
// indication EITHER by the extension OR by the SCSV; wolfSSL sends the
// extension, mbed TLS signals with the SCSV. This census therefore decided
// SunSpecTCP-15/16 on which TLS library the DUT happened to be linked against,
// and would have reported a conformant mbed TLS gateway as offering a suite
// that "cannot be classified". They are excluded from the census and NAMED in
// the observation, so a reviewer sees exactly what was set aside and why.
//
// The strict mirror of this rule lives on the server side and is unchanged: an
// SCSV must never be NEGOTIATED, so a ServerHello that selected one still fails
// through certificateBasedSuite.
func offeredSuiteCensusVerdict(ch *tlsdis.ClientHello, whose string) (certify.Verdict, string) {
	if ch == nil {
		return certify.Fail, "no ClientHello was recovered, so the " + whose +
			" cipher_suites vector cannot be censused"
	}
	var unregistered, notCert, signalling []string
	for _, id := range ch.CipherSuites {
		switch {
		case tlsdis.IsGREASE(id):
			continue
		case tlsdis.IsSCSV(id):
			signalling = append(signalling, fmt.Sprintf("0x%04X %s", id, tlsdis.CipherSuiteName(id)))
			continue
		case !tlsdis.KnownCipherSuite(id):
			unregistered = append(unregistered, fmt.Sprintf("0x%04X", id))
			continue
		}
		if ok, _ := certificateBasedSuite(id); !ok {
			notCert = append(notCert, fmt.Sprintf("0x%04X %s", id, tlsdis.CipherSuiteName(id)))
		}
	}
	obs := fmt.Sprintf("%s ClientHello offered %d codepoint(s): %s",
		whose, len(ch.CipherSuites), namedSuites(ch.CipherSuites))
	if len(signalling) > 0 {
		obs += fmt.Sprintf("; %d of them are SIGNALLING values, not cipher suites (RFC 5746 §3.3 / "+
			"RFC 7507 §3), and are excluded from this census: [%s]",
			len(signalling), strings.Join(signalling, ", "))
	}
	if len(unregistered) > 0 || len(notCert) > 0 {
		return certify.Fail, fmt.Sprintf("%s — unregistered: [%s]; not certificate-based: [%s]",
			obs, strings.Join(unregistered, ", "), strings.Join(notCert, ", "))
	}
	return certify.Pass, obs
}

// sha256PRFSuite reports whether a negotiated TLS 1.2 suite derives its keys
// with the SHA-256 PRF, which is what CRYP-005 step 5 infers HMAC-SHA-256 from.
// The GCM and ChaCha suites carry SHA256 in their names; AES_128_CCM_8 does not
// but RFC 6655 §4 fixes its PRF at SHA-256.
func sha256PRFSuite(id uint16) bool {
	switch id {
	case suiteECDHE_ECDSA_AES128_CCM_8:
		return true
	}
	name := tlsdis.CipherSuiteName(id)
	return strings.HasSuffix(name, "_SHA256") || strings.Contains(name, "CHACHA20_POLY1305")
}

// selectedSuiteFromHello decides a "the EUT-S selected suite X" criterion from
// a parsed ServerHello, or from its absence.
//
// It takes the hello rather than the probe on purpose: the SAME function has to
// decide the live phase's verdict (from the bytes read off the socket) and the
// citation phase's verdict (from the bytes in the capture). Two functions would
// drift, and the drift would be invisible — the live phase's verdict is what
// gets printed and the capture's is what gets cited.
func selectedSuiteFromHello(sh *tlsdis.ServerHello, want uint16, why string) (certify.Verdict, string) {
	if sh == nil {
		return certify.Fail, fmt.Sprintf(
			"the EUT-S sent no ServerHello for an offer containing 0x%04X %s — %s",
			want, tlsdis.CipherSuiteName(want), why)
	}
	if sh.CipherSuite != want {
		return certify.Fail, fmt.Sprintf(
			"ServerHello.cipher_suite = 0x%04X %s, want 0x%04X %s",
			sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite),
			want, tlsdis.CipherSuiteName(want))
	}
	return certify.Pass, fmt.Sprintf("ServerHello.cipher_suite = 0x%04X %s, negotiated version %s",
		sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite),
		tlsdis.VersionName(sh.NegotiatedVersion()))
}

// selectedSuite is selectedSuiteFromHello over a live probe.
func selectedSuite(p *ProbeResult, want uint16) (certify.Verdict, string) {
	if p.ConnectErr != nil {
		return certify.Fail, "the probe could not connect: " + p.ConnectErr.Error()
	}
	return selectedSuiteFromHello(p.ServerHello(), want, p.Summary())
}

// refusalFromDirection decides a negative criterion: the EUT-S must NOT
// establish a session.
//
// A refusal is conformant in three observable shapes and the procedures accept
// all of them: a fatal alert (the ideal, and what the documents name), a close
// or reset with no ServerHello, or — for CRYP-004 step 7's explicit alternative
// — a ServerHello that selected something other than the provocation. Only an
// ACCEPTED provocation is a FAIL.
func refusalFromDirection(d *tlsdis.Direction, what, tail string) (certify.Verdict, string) {
	if d == nil {
		return certify.Skip, "nothing from the EUT-S was recovered, so no refusal can be asserted"
	}
	if a, ok := d.FatalAlert(); ok {
		return certify.Pass, fmt.Sprintf(
			"the EUT-S refused %s with a fatal TLS alert: level %d (%s), description %d (%s)",
			what, a.Level, tlsdis.AlertLevelName(a.Level), a.Description,
			tlsdis.AlertDescriptionName(a.Description))
	}
	if m, ok := d.Handshake.Find(tlsdis.HandshakeServerHello); ok && m.ServerHello != nil {
		sh := m.ServerHello
		return certify.Fail, fmt.Sprintf(
			"the EUT-S ACCEPTED %s: ServerHello selected 0x%04X %s over %s",
			what, sh.CipherSuite, tlsdis.CipherSuiteName(sh.CipherSuite),
			tlsdis.VersionName(sh.NegotiatedVersion()))
	}
	if plain := d.PlainAlerts(); len(plain) > 0 {
		a := plain[0]
		return certify.Warn, fmt.Sprintf(
			"the EUT-S refused %s but the alert was level %d (%s), not fatal: description %d (%s)",
			what, a.Level, tlsdis.AlertLevelName(a.Level), a.Description,
			tlsdis.AlertDescriptionName(a.Description))
	}
	if enc := d.EncryptedAlerts(); len(enc) > 0 {
		// The record exists; its content does not, not here. Reading the
		// ciphertext as a level/description pair — which is what a naive scan
		// does — either invents an alert or hides one. See tlsdis.Alert.Encrypted.
		return certify.Skip, fmt.Sprintf(
			"the EUT-S sent %d alert record(s) after the ChangeCipherSpec, in frame(s) %v; their level and "+
				"description are ciphertext, so whether %s was refused with a FATAL alert cannot be read from "+
				"the record layer alone", len(enc), enc[0].Packets, what)
	}
	return certify.Pass, fmt.Sprintf(
		"the EUT-S refused %s with no ServerHello and no alert — it closed the connection. %s", what, tail)
}

// refused is refusalFromDirection over a live probe.
func refused(p *ProbeResult, what string) (certify.Verdict, string) {
	if p.ConnectErr != nil {
		// The DUT was not reachable at all. That is not evidence that it
		// refuses this particular provocation.
		return certify.Skip, "the probe could not connect, so nothing was provoked: " + p.ConnectErr.Error()
	}
	tail := fmt.Sprintf("%d byte(s) were received before the read ended (%v)", len(p.Received), p.ReadErr)
	if p.Server == nil {
		return certify.Skip, "the probe's answer did not parse: " + fmt.Sprint(p.ParseErr)
	}
	return refusalFromDirection(p.Server, what, tail)
}

// ── certificate policy ──────────────────────────────────────────────────────

// chainDelivery decides PKI-004 (SunSpecTCP-51): the peer must send enough of
// the chain that the other side can build a path to a root without fetching
// anything.
func chainDelivery(c *tlsdis.Certificate, who string) (certify.Verdict, string) {
	if c == nil || len(c.Entries) == 0 {
		return certify.Fail, "the " + who + " Certificate message carried no certificates"
	}
	var desc []string
	selfIssuedLeaf := false
	intermediates := 0
	for i, e := range c.Entries {
		if e.Info == nil {
			desc = append(desc, fmt.Sprintf("[%d] UNPARSEABLE: %s", i, e.Err))
			continue
		}
		desc = append(desc, fmt.Sprintf("[%d] subject %q issuer %q ca=%t sha256=%s",
			i, e.Info.Subject, e.Info.Issuer, e.Info.IsCA, e.Info.SHA256))
		if i == 0 {
			selfIssuedLeaf = e.Info.SelfIssued
		} else if e.Info.IsCA {
			intermediates++
		}
	}
	obs := fmt.Sprintf("%d certificate(s), leaf first: %s", len(c.Entries), strings.Join(desc, "; "))
	switch {
	case selfIssuedLeaf && len(c.Entries) == 1:
		return certify.Fail, "the " + who + " sent a single SELF-ISSUED certificate, so no chain to a root exists: " + obs
	case len(c.Entries) == 1:
		return certify.Fail, "the " + who + " sent only its leaf; the peer cannot build a path to the root without an out-of-band fetch: " + obs
	case intermediates == 0:
		return certify.Fail, "the " + who + " sent " + fmt.Sprint(len(c.Entries)) + " certificates but none above the leaf is a CA: " + obs
	default:
		return certify.Pass, "the " + who + " delivered leaf + " + fmt.Sprint(intermediates) + " intermediate CA certificate(s): " + obs
	}
}

// rfc5280Findings lists the ways one certificate departs from the X.509v3
// profile PKI-007 (SunSpecTCP-52) requires. An empty result is conformance.
func rfc5280Findings(ci *tlsdis.CertInfo, isLeaf bool) []string {
	var f []string
	if ci == nil {
		return []string{"the certificate did not parse"}
	}
	if ci.ParseError != "" {
		f = append(f, "parse error: "+ci.ParseError)
	}
	// tbsCertificate.version is 2 for v3; CertInfo.Version reports the human
	// value 3, which is the same fact stated the other way round.
	if ci.Version != 3 {
		f = append(f, fmt.Sprintf("tbsCertificate.version encodes v%d, RFC 5280 §4.1.2.1 requires v3 (encoded value 2)", ci.Version))
	}
	if ci.SerialHex == "" || ci.SerialHex == "00" {
		f = append(f, "serialNumber is absent or zero (RFC 5280 §4.1.2.2 requires a positive integer)")
	}
	if ci.SignatureAlgorithm == "" {
		f = append(f, "signatureAlgorithm is absent (RFC 5280 §4.1.2.3)")
	}
	if ci.NotBefore.IsZero() || ci.NotAfter.IsZero() {
		f = append(f, "validity notBefore/notAfter is absent (RFC 5280 §4.1.2.5)")
	} else if !ci.NotAfter.After(ci.NotBefore) {
		f = append(f, fmt.Sprintf("validity is inverted: notBefore %s is not before notAfter %s",
			ci.NotBefore.Format("2006-01-02T15:04:05Z"), ci.NotAfter.Format("2006-01-02T15:04:05Z")))
	}
	if ci.Issuer == "" {
		f = append(f, "issuer is empty (RFC 5280 §4.1.2.4 requires a non-empty DN)")
	}
	if ci.PublicKeyAlgorithm == "" || ci.PublicKeyBits == 0 {
		f = append(f, "subjectPublicKeyInfo did not decode (RFC 5280 §4.1.2.7)")
	}
	if len(ci.KeyUsage) == 0 {
		f = append(f, "no KeyUsage extension (RFC 5280 §4.2.1.3; PKI-007 names it as required)")
	}
	if !ci.BasicConstraintsValid {
		f = append(f, "no BasicConstraints extension (RFC 5280 §4.2.1.9; PKI-007 names it as required)")
	}
	if !hasExtension(ci, "2.5.29.14") {
		f = append(f, "no SubjectKeyIdentifier extension (OID 2.5.29.14; RFC 5280 §4.2.1.2)")
	}
	// A self-issued root legitimately omits AuthorityKeyIdentifier; every other
	// certificate must carry it so a path builder can follow the chain.
	if !hasExtension(ci, "2.5.29.35") && !ci.SelfIssued {
		f = append(f, "no AuthorityKeyIdentifier extension (OID 2.5.29.35; RFC 5280 §4.2.1.1)")
	}
	if isLeaf && ci.IsCA {
		f = append(f, "the end-entity certificate asserts BasicConstraints cA=TRUE")
	}
	return f
}

func hasExtension(ci *tlsdis.CertInfo, oid string) bool {
	_, ok := ci.Extension(oid)
	return ok
}

// certProfileVerdict turns rfc5280Findings over a whole chain into a verdict.
func certProfileVerdict(c *tlsdis.Certificate, who string) (certify.Verdict, string) {
	if c == nil || len(c.Entries) == 0 {
		return certify.Fail, "no " + who + " Certificate message was observed"
	}
	var lines []string
	bad := false
	for i, e := range c.Entries {
		findings := rfc5280Findings(e.Info, i == 0)
		label := fmt.Sprintf("[%d]", i)
		if e.Info != nil {
			label += fmt.Sprintf(" %q (sha256 %s)", e.Info.Subject, e.Info.SHA256)
		}
		if len(findings) == 0 {
			lines = append(lines, label+" conforms: "+certProfileSummary(e.Info))
			continue
		}
		bad = true
		lines = append(lines, label+" NON-CONFORMANT: "+strings.Join(findings, "; "))
	}
	if bad {
		return certify.Fail, strings.Join(lines, " | ")
	}
	return certify.Pass, strings.Join(lines, " | ")
}

func certProfileSummary(ci *tlsdis.CertInfo) string {
	if ci == nil {
		return "(no parsed certificate)"
	}
	return fmt.Sprintf("v%d serial %s sigalg %s validity %s..%s key %s/%d%s keyUsage [%s] basicConstraints cA=%t SKI+AKI present",
		ci.Version, ci.SerialHex, ci.SignatureAlgorithm,
		ci.NotBefore.Format("2006-01-02"), ci.NotAfter.Format("2006-01-02"),
		ci.PublicKeyAlgorithm, ci.PublicKeyBits, curveSuffix(ci),
		strings.Join(ci.KeyUsage, ","), ci.IsCA)
}

func curveSuffix(ci *tlsdis.CertInfo) string {
	if ci.Curve == "" {
		return ""
	}
	return " " + ci.Curve
}

// roleFinding describes what a certificate says about its SunSpec role.
type roleFinding struct {
	// Present is true when an extension at roleOID exists at all.
	Present bool
	// OIDsSeen lists every custom (non-standard) extension OID on the
	// certificate, so RBAC-006's "carried under a different OID" case can be
	// described precisely rather than as "no role".
	OIDsSeen []string
	// Role is the decoded UTF8String, empty when it did not decode.
	Role string
	// Err is the decode failure, using the same three distinctions the
	// specification draws: absent, not a single UTF8String, more than one.
	Err error
	// ValueHex is the extension's DER value verbatim, for the bundle.
	ValueHex string
}

// roleOf extracts the SunSpec role from a parsed certificate without going
// through the product's role parser (referee independence): tlsdis.RoleFromDER
// is the bench's own transcription of the ASN.1 rule.
func roleOf(ci *tlsdis.CertInfo) roleFinding {
	rf := roleFinding{}
	if ci == nil {
		rf.Err = fmt.Errorf("no parsed certificate")
		return rf
	}
	for _, e := range ci.CustomExtensions() {
		rf.OIDsSeen = append(rf.OIDsSeen, e.OID)
	}
	if e, ok := ci.Extension(roleOID); ok {
		rf.Present = true
		rf.ValueHex = e.ValueHex
	}
	role, err := ci.SunSpecRole()
	rf.Role, rf.Err = role, err
	return rf
}

// roleExtensionVerdict decides RBAC-001/011's "the client certificate carries
// the mandatory role at OID 1.3.6.1.4.1.50316.802.1" criterion.
func roleExtensionVerdict(ci *tlsdis.CertInfo, wantRole string) (certify.Verdict, string) {
	rf := roleOf(ci)
	switch {
	case !rf.Present && len(rf.OIDsSeen) > 0:
		return certify.Fail, fmt.Sprintf(
			"no extension at OID %s; the certificate's custom extension OIDs are [%s]",
			roleOID, strings.Join(rf.OIDsSeen, ", "))
	case !rf.Present:
		return certify.Fail, "the certificate carries no extension at OID " + roleOID
	case rf.Err != nil:
		return certify.Fail, fmt.Sprintf(
			"the extension at OID %s does not decode as a single ASN.1 UTF8String: %v (DER value %s)",
			roleOID, rf.Err, rf.ValueHex)
	case wantRole != "" && rf.Role != wantRole:
		return certify.Fail, fmt.Sprintf(
			"the extension at OID %s carries role %q, expected %q (DER value %s)",
			roleOID, rf.Role, wantRole, rf.ValueHex)
	default:
		return certify.Pass, fmt.Sprintf(
			"extension at OID %s decodes as the single UTF8String %q (DER value %s)",
			roleOID, rf.Role, rf.ValueHex)
	}
}

// selfSignedVerdict decides PKI-003's positive half: the peer's leaf must be
// CA-signed, not self-signed, for a public-network deployment.
func caSignedVerdict(c *tlsdis.Certificate, who string) (certify.Verdict, string) {
	if c == nil || c.Leaf() == nil || c.Leaf().Info == nil {
		return certify.Fail, "no parseable " + who + " leaf certificate was observed"
	}
	ci := c.Leaf().Info
	if ci.SelfIssued {
		return certify.Fail, fmt.Sprintf(
			"the %s leaf is self-signed: issuer %q == subject %q (sha256 %s)",
			who, ci.Issuer, ci.Subject, ci.SHA256)
	}
	return certify.Pass, fmt.Sprintf(
		"the %s leaf is CA-signed: subject %q, issuer %q, %d certificate(s) in the chain (sha256 %s)",
		who, ci.Subject, ci.Issuer, len(c.Entries), ci.SHA256)
}

// ── extension policy ────────────────────────────────────────────────────────

// compressionVerdict decides PROT-003 (SunSpecTCP-61).
func compressionVerdict(ch *tlsdis.ClientHello, who string) (certify.Verdict, string) {
	if ch == nil {
		return certify.Skip, "no " + who + " ClientHello was observed"
	}
	var names []string
	onlyNull := true
	for _, m := range ch.CompressionMethods {
		names = append(names, fmt.Sprintf("0x%02X (%s)", m, tlsdis.CompressionMethodName(m)))
		if m != 0 {
			onlyNull = false
		}
	}
	obs := fmt.Sprintf("%s ClientHello.legacy_compression_methods = [%s]", who, strings.Join(names, ", "))
	if len(ch.CompressionMethods) == 0 {
		return certify.Fail, obs + " — the field is empty, which is not a legal encoding"
	}
	if !onlyNull {
		return certify.Fail, obs + " — a method other than NULL (0x00) is offered, which TLS compression attacks (CRIME) exploit"
	}
	return certify.Pass, obs
}

// supportedGroupsVerdict decides CRYP-004's "supported_groups contains
// secp256r1 and ec_point_formats is present" criterion for a ClientHello.
func supportedGroupsVerdict(ch *tlsdis.ClientHello, who string) (certify.Verdict, string) {
	if ch == nil {
		return certify.Skip, "no " + who + " ClientHello was observed"
	}
	var groups []string
	hasP256 := false
	for _, g := range ch.SupportedGroups {
		groups = append(groups, fmt.Sprintf("0x%04X (%s)", g, tlsdis.NamedGroupName(g)))
		if g == groupSecp256r1 {
			hasP256 = true
		}
	}
	_, hasGroupsExt := ch.Extension(tlsdis.ExtSupportedGroups)
	_, hasPointFmt := ch.Extension(tlsdis.ExtECPointFormats)
	obs := fmt.Sprintf("%s ClientHello: extension 0x000A supported_groups %s = [%s]; extension 0x000B ec_point_formats %s",
		who, presence(hasGroupsExt), strings.Join(groups, ", "), presence(hasPointFmt))
	switch {
	case !hasGroupsExt:
		return certify.Fail, obs
	case !hasP256:
		return certify.Fail, obs + fmt.Sprintf(" — NamedCurve 0x%04X (secp256r1) is absent, and it is the only mandatory curve", groupSecp256r1)
	case !hasPointFmt:
		return certify.Fail, obs + " — RFC 4492 §5.1.2 requires the Supported Point Formats extension alongside the curve list"
	default:
		return certify.Pass, obs
	}
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return "ABSENT"
}

// serverKeyExchangeCurve decodes the ECParameters at the head of a TLS 1.2
// ServerKeyExchange body (RFC 4492 §5.4): curve_type(1) then, for
// named_curve (3), a two-byte NamedCurve.
func serverKeyExchangeCurve(body []byte) (curveType uint8, named uint16, ok bool) {
	if len(body) < 3 {
		return 0, 0, false
	}
	curveType = body[0]
	if curveType != 3 { // named_curve
		return curveType, 0, false
	}
	return curveType, uint16(body[1])<<8 | uint16(body[2]), true
}

// serverCurveVerdict decides CRYP-004 step 5.
func serverCurveVerdict(ske []byte, want uint16) (certify.Verdict, string) {
	if len(ske) == 0 {
		return certify.Skip, "no cleartext ServerKeyExchange was observed; under TLS 1.3 the key share is inside the ServerHello's key_share extension instead"
	}
	ct, named, ok := serverKeyExchangeCurve(ske)
	if !ok {
		return certify.Fail, fmt.Sprintf(
			"ServerKeyExchange.curve_type = %d, which is not named_curve (3), so no NamedCurve is asserted", ct)
	}
	if named != want {
		return certify.Fail, fmt.Sprintf(
			"ServerKeyExchange curve_type=named_curve named_curve=0x%04X (%s), want 0x%04X (%s)",
			named, tlsdis.NamedGroupName(named), want, tlsdis.NamedGroupName(want))
	}
	return certify.Pass, fmt.Sprintf(
		"ServerKeyExchange curve_type=named_curve(3) named_curve=0x%04X (%s)",
		named, tlsdis.NamedGroupName(named))
}

// mflEchoVerdict decides PROT-002's negotiation half (SunSpecTCP-59/60).
func mflEchoVerdict(sh *tlsdis.ServerHello, want uint8) (certify.Verdict, string) {
	if sh == nil {
		return certify.Fail, "the EUT-S sent no ServerHello, so no max_fragment_length echo exists"
	}
	if sh.MaxFragmentLength == nil {
		return certify.Fail, fmt.Sprintf(
			"the ServerHello carries no max_fragment_length extension (type 0x0001); extensions present: [%s]",
			strings.Join(tlsdis.ExtensionNames(sh.Extensions), ", "))
	}
	got := *sh.MaxFragmentLength
	bytesWant, _ := tlsdis.MaxFragmentLengthBytes(want)
	bytesGot, known := tlsdis.MaxFragmentLengthBytes(got)
	if got != want {
		return certify.Fail, fmt.Sprintf(
			"the ServerHello echoed max_fragment_length code %d (%s), the ClientHello requested code %d (%d bytes)",
			got, fragmentBytesText(bytesGot, known), want, bytesWant)
	}
	return certify.Pass, fmt.Sprintf(
		"the ServerHello echoed max_fragment_length code %d = %d bytes, matching the ClientHello request",
		got, bytesGot)
}

func fragmentBytesText(n int, known bool) string {
	if !known {
		return "an unregistered code"
	}
	return fmt.Sprintf("%d bytes", n)
}

// renegotiationInfoVerdict decides PROT-004's SERVER half (SunSpecTCP-62).
//
// The extension is the only conformant answer here, and the asymmetry with the
// client half below is RFC 5746's, not this bench's. §3.6 gives the server one
// behaviour on an initial handshake: on receiving EITHER the SCSV or the
// extension, "the server MUST include an empty 'renegotiation_info' extension
// in the ServerHello message". The SCSV is a CLIENT signal — §3.3 calls it "not
// a true cipher suite … cannot be negotiated" — so there is no second wire form
// for a server to choose, and accepting one would not be leniency toward a
// conformant peer, it would be accepting a ServerHello no conformant peer can
// send. See renegotiationIndicationVerdict for the client half, where §3.4 DOES
// admit two forms.
func renegotiationInfoVerdict(sh *tlsdis.ServerHello) (certify.Verdict, string) {
	if sh == nil {
		return certify.Fail, "the EUT-S sent no ServerHello, so no renegotiation_info can be observed"
	}
	if !sh.HasRenegotiationInfo {
		return certify.Fail, fmt.Sprintf(
			"the ServerHello carries no renegotiation_info extension (type 0xFF01); extensions present: [%s]",
			strings.Join(tlsdis.ExtensionNames(sh.Extensions), ", "))
	}
	if len(sh.RenegotiationInfo) != 0 {
		return certify.Warn, fmt.Sprintf(
			"the ServerHello's renegotiation_info carries %d byte(s) of renegotiated_connection on an INITIAL handshake; RFC 5746 §3.6 requires it to be empty",
			len(sh.RenegotiationInfo))
	}
	return certify.Pass, "the ServerHello carries the RFC 5746 renegotiation_info extension (type 0xFF01) with an empty renegotiated_connection, as required on an initial handshake"
}

// renegotiationIndicationVerdict decides PROT-004's CLIENT half
// (SunSpecTCP-62) from the gateway's own southbound ClientHello.
//
// RFC 5746 §3.4 is explicit that there are TWO conformant wire forms, and that
// the client picks:
//
//	"The client MUST include either an empty 'renegotiation_info' extension,
//	 or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in
//	 the ClientHello. Including both is NOT RECOMMENDED."
//
// SunSpecTCP-62 requires the device to PROVIDE the RFC 5746 renegotiation
// indication; it does not — and cannot — prescribe which of the two forms
// §3.4 leaves to the client. This matters on a live bench: a wolfSSL-linked
// gateway sends the empty extension, a mbed TLS-linked one signals with the
// SCSV by default, and the same device fails or passes depending only on which
// library it was linked against. So the verdict is FAIL when BOTH are absent,
// and only then.
//
// Sending both is accepted with the RFC's own NOT RECOMMENDED recorded: a
// SHOULD NOT is not a MUST NOT, and the indication SunSpecTCP-62 asks for is
// unambiguously present.
func renegotiationIndicationVerdict(ch *tlsdis.ClientHello, whose string) (certify.Verdict, string) {
	if ch == nil {
		return certify.Fail, "no ClientHello was recovered, so " + whose +
			" renegotiation indication cannot be observed"
	}
	scsv := false
	for _, id := range ch.CipherSuites {
		if id == tlsdis.SCSVEmptyRenegotiationInfo {
			scsv = true
			break
		}
	}
	obs := fmt.Sprintf("%s ClientHello: renegotiation_info (0xFF01) %s; TLS_EMPTY_RENEGOTIATION_INFO_SCSV "+
		"(0x00FF) %s; extensions [%s]", whose, presence(ch.HasRenegotiationInfo), presence(scsv),
		strings.Join(tlsdis.ExtensionNames(ch.Extensions), ", "))
	switch {
	case !ch.HasRenegotiationInfo && !scsv:
		return certify.Fail, obs + " — neither of the two forms RFC 5746 §3.4 admits is present, so the " +
			"peer provides no secure-renegotiation indication at all"
	case ch.HasRenegotiationInfo && scsv:
		return certify.Pass, obs + " — both forms are present; RFC 5746 §3.4 says including both is " +
			"NOT RECOMMENDED, but the indication SunSpecTCP-62 requires is unambiguously provided"
	case scsv:
		return certify.Pass, obs + " — signalled by the SCSV, the second of the two forms RFC 5746 §3.4 admits"
	default:
		if len(ch.RenegotiationInfo) != 0 {
			return certify.Warn, obs + fmt.Sprintf(" — the extension carries %d byte(s) of "+
				"renegotiated_connection on what should be an INITIAL handshake; RFC 5746 §3.4 requires it empty",
				len(ch.RenegotiationInfo))
		}
		return certify.Pass, obs + " — signalled by the empty renegotiation_info extension, the first of " +
			"the two forms RFC 5746 §3.4 admits"
	}
}

// certificateRequestVerdict decides TLSF-006 (SunSpecTCP-11).
func certificateRequestVerdict(cr *tlsdis.CertificateRequest) (certify.Verdict, string) {
	if cr == nil {
		return certify.Fail, "the EUT-S sent no CertificateRequest, so it does not demand mutual authentication on this handshake"
	}
	if cr.TLS13 {
		return certify.Pass, fmt.Sprintf(
			"CertificateRequest (TLS 1.3 form): certificate_request_context %d byte(s), extensions [%s]",
			len(cr.RequestContext), strings.Join(tlsdis.ExtensionNames(cr.Extensions), ", "))
	}
	var types []string
	for _, t := range cr.CertificateTypes {
		types = append(types, fmt.Sprintf("%d (%s)", t, clientCertTypeName(t)))
	}
	var sigs []string
	for _, s := range cr.SignatureAlgorithms {
		sigs = append(sigs, fmt.Sprintf("0x%04X (%s)", s, tlsdis.SignatureSchemeName(s)))
	}
	obs := fmt.Sprintf("CertificateRequest: certificate_types [%s], supported_signature_algorithms [%s], %d certificate_authorities DN(s)",
		strings.Join(types, ", "), strings.Join(sigs, ", "), len(cr.CertificateAuthorities))
	switch {
	case len(cr.CertificateTypes) == 0:
		return certify.Fail, obs + " — certificate_types is empty, so the client is told nothing about what to present"
	case len(cr.SignatureAlgorithms) == 0:
		return certify.Fail, obs + " — supported_signature_algorithms is empty, which RFC 5246 §7.4.4 forbids for TLS 1.2"
	default:
		return certify.Pass, obs
	}
}

func clientCertTypeName(t uint8) string {
	switch t {
	case 1:
		return "rsa_sign"
	case 2:
		return "dss_sign"
	case 64:
		return "ecdsa_sign"
	default:
		return fmt.Sprintf("client certificate type %d", t)
	}
}

// serverFlightVerdict decides TLSF-006's ordering criterion: the EUT-S flight
// must be ServerHello, Certificate, ServerKeyExchange, CertificateRequest,
// ServerHelloDone, in that order.
func serverFlightVerdict(flight []tlsdis.HandshakeType) (certify.Verdict, string) {
	want := []tlsdis.HandshakeType{
		tlsdis.HandshakeServerHello,
		tlsdis.HandshakeCertificate,
		tlsdis.HandshakeServerKeyExchange,
		tlsdis.HandshakeCertificateRequest,
		tlsdis.HandshakeServerHelloDone,
	}
	got := make([]string, len(flight))
	for i, t := range flight {
		got[i] = tlsdis.HandshakeTypeName(t)
	}
	obs := "EUT-S cleartext flight: [" + strings.Join(got, ", ") + "]"
	if len(flight) != len(want) {
		return certify.Fail, obs + " — expected exactly [ServerHello, Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone]"
	}
	for i := range want {
		if flight[i] != want[i] {
			return certify.Fail, fmt.Sprintf("%s — message %d is %s, expected %s",
				obs, i+1, tlsdis.HandshakeTypeName(flight[i]), tlsdis.HandshakeTypeName(want[i]))
		}
	}
	return certify.Pass, obs
}

// resumptionPair is the two handshakes PKI-006 compares, already parsed.
//
// It carries the second CLIENTHELLO, which is the field the check was missing:
// see abbreviatedHandshakeVerdict.
type resumptionPair struct {
	FirstServerHello *tlsdis.ServerHello
	FirstFlight      []tlsdis.HandshakeType
	// SecondClientHello is the resumption attempt's hello.
	SecondClientHello *tlsdis.ClientHello
	SecondServerHello *tlsdis.ServerHello
	SecondFlight      []tlsdis.HandshakeType
}

// abbreviatedHandshakeVerdict decides PKI-006 (SunSpecTCP-46/47). The
// specification accepts BOTH outcomes — resumption or a clean fall back to a
// full handshake — so the only FAIL here is an abbreviated handshake that is
// malformed: one that skipped the certificate exchange without echoing the
// session id its peer offered.
//
// "Its peer offered" is the correction. RFC 5077 §3.4: a client resuming with a
// TICKET puts a NEW, self-generated session id in its second ClientHello, and
// the server proves it accepted the ticket by echoing THAT id in the abbreviated
// ServerHello. The initial handshake's ServerHello session id plays no part —
// for a ticket-issuing server §3.4 recommends it be EMPTY, and this gateway
// sends exactly that. Comparing against it, as this check used to, makes a
// textbook-correct RFC 5077 resumption look like a server resuming a session
// nobody offered; run 20260726T225512 failed the DUT on precisely that, while
// the same case's own headline said the resumption was correct.
func abbreviatedHandshakeVerdict(p resumptionPair) (certify.Verdict, string) {
	sh1, sh2, ch2 := p.FirstServerHello, p.SecondServerHello, p.SecondClientHello
	if sh1 == nil || sh2 == nil {
		return certify.Fail, fmt.Sprintf(
			"one of the two handshakes produced no ServerHello (initial %s, resumption attempt %s)",
			presence(sh1 != nil), presence(sh2 != nil))
	}
	if ch2 == nil {
		return certify.Skip, "the capture does not carry the resumption attempt's ClientHello, and RFC 5077 " +
			"§3.4 defines the echo against THAT hello's session id — there is nothing to compare against"
	}
	full2 := hasType(p.SecondFlight, tlsdis.HandshakeCertificate)
	echoed := len(ch2.SessionID) > 0 && string(ch2.SessionID) == string(sh2.SessionID)
	obs := fmt.Sprintf(
		"initial handshake: ServerHello.session_id %d byte(s) (%x), NewSessionTicket %s; resumption attempt: "+
			"ClientHello.session_id %d byte(s) (%x), ServerHello.session_id %d byte(s) (%x), Certificate %s",
		len(sh1.SessionID), sh1.SessionID, presence(hasType(p.FirstFlight, tlsdis.HandshakeNewSessionTicket)),
		len(ch2.SessionID), ch2.SessionID, len(sh2.SessionID), sh2.SessionID, presence(full2))
	switch {
	case !full2 && echoed:
		return certify.Pass, obs + " — the EUT-S performed an ABBREVIATED handshake: it echoed the session id offered in the resumption ClientHello (RFC 5077 §3.4) and re-sent no Certificate or CertificateRequest"
	case !full2 && !echoed:
		return certify.Fail, obs + " — the EUT-S skipped the Certificate exchange WITHOUT echoing the session id its peer offered, so the peer's identity was never re-established"
	default:
		return certify.Pass, obs + " — the EUT-S fell back to a FULL handshake, re-exchanging Certificate and CertificateRequest, which SunSpecTCP-46/47 permits (resumption is a SHOULD/MAY)"
	}
}

func hasType(flight []tlsdis.HandshakeType, t tlsdis.HandshakeType) bool {
	for _, x := range flight {
		if x == t {
			return true
		}
	}
	return false
}

// ── MBAP / Modbus policy ────────────────────────────────────────────────────

// mbapView is one MBAP frame decoded field by field, from the exact bytes.
//
// It deliberately does NOT use lexa-proto/mbap.Decode: PROT-001's criterion is
// about the layout of the seven header bytes, and a decoder that normalises or
// rejects is the wrong instrument for asserting what the bytes were. The
// framing codec is shared with the product for the transport; the assertion
// about the framing is not.
type mbapView struct {
	Raw      []byte
	TID      uint16
	PID      uint16
	Length   uint16
	UnitID   uint8
	PDU      []byte
	Trailing []byte
}

// parseMBAP decodes the first MBAP frame in b and reports what followed it.
func parseMBAP(b []byte) (*mbapView, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("suitessm: %d byte(s) is too short for a 7-byte MBAP header plus a function code", len(b))
	}
	v := &mbapView{
		Raw:    b,
		TID:    uint16(b[0])<<8 | uint16(b[1]),
		PID:    uint16(b[2])<<8 | uint16(b[3]),
		Length: uint16(b[4])<<8 | uint16(b[5]),
		UnitID: b[6],
	}
	end := 6 + int(v.Length)
	if v.Length < 2 {
		return v, fmt.Errorf("suitessm: MBAP Length field is %d, which cannot cover a Unit ID plus a function code", v.Length)
	}
	if end > len(b) {
		return v, fmt.Errorf("suitessm: MBAP Length field %d implies %d bytes but only %d were present",
			v.Length, end, len(b))
	}
	v.PDU = b[7:end]
	v.Trailing = b[end:]
	return v, nil
}

// String renders the header field by field, which is exactly what PROT-001's
// evidence line has to say.
func (v *mbapView) String() string {
	return fmt.Sprintf("MBAP header % x = Transaction ID 0x%04X | Protocol ID 0x%04X | Length %d | Unit ID %d; PDU % x (%d byte(s)); trailing % x",
		v.Raw[:7], v.TID, v.PID, v.Length, v.UnitID, v.PDU, len(v.PDU), v.Trailing)
}

// mbapIntegrityVerdict decides PROT-001 (SunSpecTCP-9): the MBAP header inside
// the tunnel must be the standard seven bytes with Protocol ID 0x0000 and a
// Length consistent with the PDU that follows, and the PDU must be unmodified.
func mbapIntegrityVerdict(reqBytes, rspBytes []byte) (certify.Verdict, string) {
	req, rerr := parseMBAP(reqBytes)
	rsp, serr := parseMBAP(rspBytes)
	if rerr != nil {
		return certify.Fail, "the request frame is not a well-formed MBAP ADU: " + rerr.Error()
	}
	if serr != nil {
		return certify.Fail, "the response frame is not a well-formed MBAP ADU: " + serr.Error()
	}
	obs := "request " + req.String() + " || response " + rsp.String()
	var findings []string
	if req.PID != 0 {
		findings = append(findings, fmt.Sprintf("request Protocol ID is 0x%04X, Modbus requires 0x0000", req.PID))
	}
	if rsp.PID != 0 {
		findings = append(findings, fmt.Sprintf("response Protocol ID is 0x%04X, Modbus requires 0x0000", rsp.PID))
	}
	if rsp.TID != req.TID {
		findings = append(findings, fmt.Sprintf("response Transaction ID 0x%04X does not echo the request's 0x%04X", rsp.TID, req.TID))
	}
	if rsp.UnitID != req.UnitID {
		findings = append(findings, fmt.Sprintf("response Unit ID %d does not echo the request's %d", rsp.UnitID, req.UnitID))
	}
	if int(rsp.Length) != len(rsp.PDU)+1 {
		findings = append(findings, fmt.Sprintf("response Length %d ≠ len(PDU)+1 = %d", rsp.Length, len(rsp.PDU)+1))
	}
	if len(rsp.Trailing) != 0 {
		findings = append(findings, fmt.Sprintf("%d byte(s) followed the response ADU inside the same record: % x",
			len(rsp.Trailing), rsp.Trailing))
	}
	if len(rsp.PDU) > 0 && len(req.PDU) > 0 && rsp.PDU[0] != req.PDU[0] && rsp.PDU[0] != req.PDU[0]|0x80 {
		findings = append(findings, fmt.Sprintf("response function code 0x%02X is neither the request's 0x%02X nor its exception form 0x%02X",
			rsp.PDU[0], req.PDU[0], req.PDU[0]|0x80))
	}
	if len(findings) > 0 {
		return certify.Fail, obs + " — " + strings.Join(findings, "; ")
	}
	return certify.Pass, obs
}

// exceptionVerdict decides "this request was answered with Modbus exception
// code N", the criterion behind every RBAC denial row.
func exceptionVerdict(rspBytes []byte, wantCode uint8) (certify.Verdict, string) {
	v, err := parseMBAP(rspBytes)
	if err != nil {
		return certify.Fail, "the response is not a well-formed MBAP ADU: " + err.Error()
	}
	if len(v.PDU) < 1 {
		return certify.Fail, "the response PDU is empty: " + v.String()
	}
	fc := v.PDU[0]
	if fc&0x80 == 0 {
		return certify.Fail, fmt.Sprintf(
			"the request was answered NORMALLY (function code 0x%02X, no 0x80 exception bit), not with exception code %d: %s",
			fc, wantCode, v.String())
	}
	if len(v.PDU) < 2 {
		return certify.Fail, "the exception response carries no exception code byte: " + v.String()
	}
	if v.PDU[1] != wantCode {
		return certify.Fail, fmt.Sprintf("exception code is %d (%s), expected %d: %s",
			v.PDU[1], exceptionName(v.PDU[1]), wantCode, v.String())
	}
	return certify.Pass, fmt.Sprintf("exception response: function code 0x%02X, exception code %d (%s). %s",
		fc, v.PDU[1], exceptionName(v.PDU[1]), v.String())
}

// normalResponseVerdict decides "this request was answered without an
// exception", the criterion behind every RBAC grant row.
func normalResponseVerdict(rspBytes []byte) (certify.Verdict, string) {
	v, err := parseMBAP(rspBytes)
	if err != nil {
		return certify.Fail, "the response is not a well-formed MBAP ADU: " + err.Error()
	}
	if len(v.PDU) < 1 {
		return certify.Fail, "the response PDU is empty: " + v.String()
	}
	if v.PDU[0]&0x80 != 0 {
		code := uint8(0)
		if len(v.PDU) > 1 {
			code = v.PDU[1]
		}
		return certify.Fail, fmt.Sprintf(
			"the request was DENIED with exception code %d (%s): %s", code, exceptionName(code), v.String())
	}
	return certify.Pass, "normal (non-exception) response: " + v.String()
}

// exceptionName transcribes the Modbus exception codes SSM-CONF-v0.8 and the
// gateway's exception ladder use. Transcribed, not imported, so a renamed
// constant in the product cannot change what this suite reports.
func exceptionName(c uint8) string {
	switch c {
	case 1:
		return "Illegal Function"
	case 2:
		return "Illegal Data Address"
	case 3:
		return "Illegal Data Value"
	case 4:
		return "Server Device Failure"
	case 5:
		return "Acknowledge"
	case 6:
		return "Server Device Busy"
	case 8:
		return "Memory Parity Error"
	case 10:
		return "Gateway Path Unavailable"
	case 11:
		return "Gateway Target Device Failed To Respond"
	default:
		return fmt.Sprintf("exception code %d", c)
	}
}

// leakageVerdict decides RBAC-009 (SunSpecTCP-33/34/41): a denied write must be
// answered by exactly nine bytes — seven header, one error function code, one
// exception code — and nothing else. Any register value, diagnostic string or
// trailing byte is information leakage.
func leakageVerdict(rspBytes []byte) (certify.Verdict, string) {
	v, err := parseMBAP(rspBytes)
	if err != nil {
		return certify.Fail, "the denial response is not a well-formed MBAP ADU: " + err.Error()
	}
	var findings []string
	if len(rspBytes) != 9 {
		findings = append(findings, fmt.Sprintf("the response is %d bytes, the specification requires exactly 9 (7 header + error function code + exception code)", len(rspBytes)))
	}
	if v.Length != 3 {
		findings = append(findings, fmt.Sprintf("the MBAP Length field is %d; a 2-byte exception PDU plus the Unit ID is 3", v.Length))
	}
	if len(v.PDU) != 2 {
		findings = append(findings, fmt.Sprintf("the PDU is %d byte(s) (% x); an exception PDU is exactly 2", len(v.PDU), v.PDU))
	}
	if len(v.PDU) > 0 && v.PDU[0]&0x80 == 0 {
		findings = append(findings, fmt.Sprintf("function code 0x%02X does not carry the 0x80 exception bit, so this is not a denial at all", v.PDU[0]))
	}
	if len(v.Trailing) > 0 {
		findings = append(findings, fmt.Sprintf("%d byte(s) follow the exception code: % x — a denial must reveal nothing further",
			len(v.Trailing), v.Trailing))
	}
	obs := fmt.Sprintf("%d-byte denial response % x. %s", len(rspBytes), rspBytes, v.String())
	if len(findings) > 0 {
		return certify.Fail, obs + " — " + strings.Join(findings, "; ")
	}
	return certify.Pass, obs + " — no register values, no diagnostic text, nothing after the exception code"
}

// ── trust-path evaluation ───────────────────────────────────────────────────

// verifyChain evaluates a peer chain against a root pool WITHOUT letting the
// TLS library decide for us. A referee wants the verification result as an
// observation it can report — "the DUT's leaf does not chain to the bench root,
// here is why" — not as a handshake the library aborted before any evidence was
// produced. session.go therefore always dials with InsecureSkipVerify and calls
// this from VerifyPeerCertificate.
func verifyChain(leaf *x509.Certificate, intermediates, roots *x509.CertPool) error {
	if leaf == nil {
		return fmt.Errorf("suitessm: no leaf certificate to verify")
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// ── CRYP-004 step 7: a procedure defect, recorded as one ────────────────────

// curveExclusivityRationale is why CRYP-004 step 7 cannot produce a FAIL.
//
// It is carried on the assertion itself, verbatim, because the point of a
// documented deviation is that the lab reading the bundle sees the argument
// without having to be told it.
const curveExclusivityRationale = "DOCUMENTED DEVIATION — this step is a defect in the test procedure, not a " +
	"criterion the EUT-S can fail. The only normative requirements §2.5.4 traces to are SunSpecTCP-42/43/44, " +
	"and TCP-42 reads \"mbaps Devices using ECC technology MUST support AT LEAST P-256 NIST curve\" (MBR-61). " +
	"\"At least\" explicitly contemplates supporting more, and nothing anywhere in the Secure SunSpec Modbus " +
	"Specification obliges a server to REFUSE a client that offers a different curve. §2.5.4.1 step 7's " +
	"\"EUT-S must reject the connection or select a different key exchange method\" also contradicts RFC 4492 " +
	"§5.1, which runs the other way — a server declines an ECC suite only when it supports NONE of the offered " +
	"curves — and its \"select a different key exchange method\" alternative would mean falling back to RSA or " +
	"static DH, strictly worse security required by nothing. A device that completes ECDHE over P-384 has " +
	"demonstrated MORE than TCP-42 asks, provided P-256 support is proven separately, which the positive " +
	"iteration of this same case does. Recorded as WARN so the observation survives in the bundle; raise it " +
	"with SunSpec as a defect in a document still at TEST (draft) status."

// curveExclusivityVerdict caps CRYP-004 step 7 at WARN.
//
// It takes the refusal verdict as computed and downgrades a FAIL, rather than
// suppressing the observation: what the DUT did is still reported in full, and
// the rationale rides on the assertion. A PASS — a DUT that really did refuse —
// stays a PASS, because refusing is also permitted; the procedure's error is in
// REQUIRING it.
func curveExclusivityVerdict(v certify.Verdict, obs string) (certify.Verdict, string) {
	if v != certify.Fail {
		return v, obs
	}
	return certify.Warn, obs + " — which SunSpecTCP-42 permits: it requires support for \"at least\" P-256, " +
		"not the refusal of anything else. See this assertion's note."
}
