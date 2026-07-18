// Package mbtls is the bench's own Secure SunSpec Modbus TLS (mbaps) glue: an
// mbaps client (Dial) and server (Listen/Accept) built on the repo's single
// wolfSSL cgo wrapper (internal/wolfssl). It carries all of the mbaps TLS
// profile — TLS 1.2 required + TLS 1.3, the mandated cipher-suite order,
// unconditional client-cert demand, RFC 6066 Maximum Fragment Length, P-256
// curve advertisement, and role-extension extraction — so the aggregator
// emulator (T06.4+) and the mbapsdev device sim (T06.2) inherit a conformant
// handshake and get a decrypted net.Conn to feed to lexa-proto/mbap.
//
// # Referee independence (T06 PN-1 / T00 ruling C9)
//
// This package is DELIBERATELY not the product's lexa-platform/securemodbus. A
// conformance bench that shared its TLS-profile code with the gateway under
// test could not independently catch a profile bug — a mis-ordered suite list
// or fumbled MFL would be reproduced identically on both sides and the
// conformance suite would green-light a non-conformant handshake. So mbtls
// re-derives the profile from the spec (the mandated suite tables and the role
// OID below are transcribed from the SunSpec Modbus/TCP requirements, not
// imported from securemodbus), exactly as internal/csipref is a deliberately
// unsynced second 2030.5 walker kept for referee value (AD-003(f)).
//
// What the bench DOES share with the product is lexa-proto/mbap — the pure-Go
// MBAP framing codec. mbtls never imports it: it hands off Session.Conn (the
// decrypted stream) and lets the mbapsdev/aggregator layers ride mbap on top.
// The wire format is the wire format; a divergent framing codec would be bugs,
// not independent verification. mbtls and the product frame ADUs identically
// and diverge only in TLS profile and role/authz assertion logic.
package mbtls

import (
	"fmt"
	"strings"

	"csip-tls-test/internal/wolfssl"
)

// Version is a TLS wire protocol version (the 0x03NN two-byte code).
type Version uint16

const (
	// TLS12 is the mandated floor (SunSpecTCP-4).
	TLS12 Version = wolfssl.TLS12Version
	// TLS13 is default-on above the floor (SunSpecTCP-5).
	TLS13 Version = wolfssl.TLS13Version
)

func (v Version) String() string {
	switch v {
	case TLS12:
		return "TLSv1.2"
	case TLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", uint16(v))
	}
}

// The mandated cipher suites, transcribed from the Secure SunSpec Modbus/TCP
// requirements as wolfSSL OpenSSL-format suite names, in the spec's exact order
// (SunSpecTCP-17/18/19). These are the bench's independent source of truth for
// suite conformance — NOT securemodbus's list (referee independence, PN-1).
//
// The order matters twice: within a version segment it is the spec's mandated
// preference order (TCP-17/18); across versions the assembled wolfSSL
// cipher-list string must list all TLS 1.3 suites BEFORE the TLS 1.2 suites,
// or wolfSSL 5.7.6 negotiates TLS 1.3 only when a 1.3 suite leads a mixed list
// (T00 ruling C11). WolfCipherList encodes both.
var (
	// Mandated12 is the TLS 1.2 suite order (SunSpecTCP-17). ECDSA-only ⇒ device
	// certs are EC P-256.
	Mandated12 = []string{
		"ECDHE-ECDSA-AES128-GCM-SHA256",
		"ECDHE-ECDSA-CHACHA20-POLY1305",
		"ECDHE-ECDSA-AES128-CCM-8",
	}
	// Mandated13 is the TLS 1.3 suite order (SunSpecTCP-18).
	Mandated13 = []string{
		"TLS13-AES128-GCM-SHA256",
		"TLS13-CHACHA20-POLY1305-SHA256",
		"TLS13-AES128-CCM-SHA256",
	}
)

// Profile carries all mbaps TLS knowledge so both peers inherit conformance.
// The zero value is not usable; build one with DefaultClientProfile or
// DefaultServerProfile and adjust fields, or fill every field and call
// Validate. Suite lists are config-driven but order-validated (Validate) — an
// out-of-order or unknown suite is a fatal config error, never a silent
// downgrade (SunSpecTCP-19/20; CODING_PRINCIPLES §4 TLS profile rules).
type Profile struct {
	MinTLS, MaxTLS Version  // TLS12 required; TLS13 default-on (TCP-4/5)
	Suites12       []string // default = Mandated12 (TCP-17/19)
	Suites13       []string // default = Mandated13 (TCP-18)
	MFLCode        int      // wolfssl.MFL* selector; MFL512 default (TCP-59/60); 0 = off
	SessionCache   bool     // resumption enabled (TCP-46 SHOULD)
	CAFile         string   // trust anchors for verifying the peer
	CertChainFile  string   // full chain this peer sends, leaf first (TCP-51)
	KeyFile        string   // private key matching the leaf
	RoleAsserted   string   // client only: role this identity expects to carry (self-checks)
}

// DefaultClientProfile returns a fully-conformant mbaps client profile: TLS
// 1.2..1.3, the full mandated suite order, 512-byte MFL, resumption on. The
// caller supplies the PKI file paths (leaf chain + key omitted drives the
// no-client-cert negative — the ClientHello then presents no certificate).
func DefaultClientProfile(caFile, certChainFile, keyFile string) Profile {
	return Profile{
		MinTLS:        TLS12,
		MaxTLS:        TLS13,
		Suites12:      append([]string(nil), Mandated12...),
		Suites13:      append([]string(nil), Mandated13...),
		MFLCode:       wolfssl.MFL512,
		SessionCache:  true,
		CAFile:        caFile,
		CertChainFile: certChainFile,
		KeyFile:       keyFile,
	}
}

// DefaultServerProfile returns a fully-conformant mbaps server profile. A
// server honours a client's MFL request automatically, so MFLCode is left off;
// resumption is on by default (TCP-46).
func DefaultServerProfile(caFile, certChainFile, keyFile string) Profile {
	return Profile{
		MinTLS:        TLS12,
		MaxTLS:        TLS13,
		Suites12:      append([]string(nil), Mandated12...),
		Suites13:      append([]string(nil), Mandated13...),
		MFLCode:       wolfssl.MFLDisabled,
		SessionCache:  true,
		CAFile:        caFile,
		CertChainFile: certChainFile,
		KeyFile:       keyFile,
	}
}

// Validate checks the profile is internally consistent and spec-conformant
// BEFORE any socket is opened — a bad profile is a programmer/config error that
// must fail loudly at construction, not produce a subtly non-conformant
// handshake at runtime (SunSpecTCP-19/20). It enforces:
//   - a sane version range with TLS 1.2 as the floor (TCP-4);
//   - at least one suite offered per enabled version;
//   - every suite string is one of the mandated names AND the provided list is
//     a subsequence of the mandated order (disabling suites is allowed —
//     TCP-20; reordering or inventing them is not — TCP-19);
//   - a known MFL selector;
//   - the CA file is set (peer verification is never optional).
func (p Profile) Validate() error {
	if p.MinTLS != TLS12 {
		return fmt.Errorf("mbtls: MinTLS must be TLS 1.2 (the mbaps floor, TCP-4), got %s", p.MinTLS)
	}
	if p.MaxTLS != TLS12 && p.MaxTLS != TLS13 {
		return fmt.Errorf("mbtls: MaxTLS must be TLS 1.2 or 1.3, got %s", p.MaxTLS)
	}
	if p.MaxTLS < p.MinTLS {
		return fmt.Errorf("mbtls: MaxTLS %s below MinTLS %s", p.MaxTLS, p.MinTLS)
	}
	if len(p.Suites12) == 0 {
		return fmt.Errorf("mbtls: no TLS 1.2 suites (TLS 1.2 is mandatory, TCP-17)")
	}
	if err := validateSuiteSubsequence(p.Suites12, Mandated12, "TLS 1.2", "TCP-17"); err != nil {
		return err
	}
	if p.MaxTLS >= TLS13 {
		if len(p.Suites13) == 0 {
			return fmt.Errorf("mbtls: TLS 1.3 enabled but no TLS 1.3 suites offered (TCP-18)")
		}
		if err := validateSuiteSubsequence(p.Suites13, Mandated13, "TLS 1.3", "TCP-18"); err != nil {
			return err
		}
	}
	switch p.MFLCode {
	case wolfssl.MFLDisabled, wolfssl.MFL512, wolfssl.MFL1024, wolfssl.MFL2048, wolfssl.MFL4096:
	default:
		return fmt.Errorf("mbtls: unknown MFL selector %d (use wolfssl.MFL* constants)", p.MFLCode)
	}
	if p.CAFile == "" {
		return fmt.Errorf("mbtls: CAFile is required (peer verification is never optional)")
	}
	return nil
}

// validateSuiteSubsequence rejects any suite name not in the mandated set and
// any ordering that is not a subsequence of the mandated order. This is the
// exact TCP-19/20 rule: an operator may DISABLE a discouraged suite (drop it
// from the list) but may not reorder the preference or introduce an unknown
// suite string.
func validateSuiteSubsequence(provided, mandated []string, label, req string) error {
	mi := 0
	for _, s := range provided {
		found := false
		for mi < len(mandated) {
			if mandated[mi] == s {
				found = true
				mi++
				break
			}
			mi++
		}
		if !found {
			// Either an unknown name or one appearing out of mandated order.
			if !contains(mandated, s) {
				return fmt.Errorf("mbtls: %s suite %q is not a mandated %s suite (%s)", label, s, label, req)
			}
			return fmt.Errorf("mbtls: %s suite %q is out of the mandated order (%s: %s)",
				label, s, req, strings.Join(mandated, " > "))
		}
	}
	return nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// WolfCipherList assembles the single OpenSSL-format cipher-list string wolfSSL
// consumes, with ALL enabled TLS 1.3 suites first, then the TLS 1.2 suites —
// the cross-version ordering wolfSSL 5.7.6 requires to reach TLS 1.3 on a mixed
// 1.2..1.3 context (T00 ruling C11). Each version's mandated internal order
// (TCP-17/18) is preserved within its segment. Call only after Validate.
func (p Profile) WolfCipherList() string {
	var segs []string
	if p.MaxTLS >= TLS13 {
		segs = append(segs, p.Suites13...)
	}
	segs = append(segs, p.Suites12...)
	return strings.Join(segs, ":")
}
