package tlsprobe

// suites.go is the probe's transcription of the cipher suites SSM-CONF-v0.8
// mandates, with the IANA codepoint beside the wolfSSL name.
//
// Both spellings are here on purpose. The codepoint is what appears on the wire
// and therefore what an assertion cites; the wolfSSL name is what pins the
// offer. A table with only one of them forces every call site to keep the other
// in its head, which is how a probe ends up offering one suite and asserting
// about another.
//
// # Where the list comes from
//
// SSM-CONF-v0.8 §2.4.1 Table 1 (TLS 1.2 cipher suite hex codes):
//
//	0xC02B  TLS  ECDHE  ECDSA  AES-128-GCM         SHA-256
//	0xCCA9  TLS  ECDHE  ECDSA  ChaCha20-Poly1305   SHA-256
//	0xC0AE  TLS  ECDHE  ECDSA  AES-128-CCM-8       SHA-256
//
// and §2.5.1.1, which walks them one at a time:
//
//	2. [C] TC initiates a TLS v1.2 handshake offering only
//	       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
//	3. [S] EUT-S accepts the connection and completes the handshake.
//	4. [C] TC repeats step 2 offering only
//	       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
//	5. [S] EUT-S accepts the connection and completes the handshake.
//	6. [C] TC repeats step 2 offering only TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8.
//	7. [S] EUT-S accepts the connection and completes the handshake.
//
// SSM-CONF-v0.8 §2.4.2 Table 2 (TLS 1.3 cipher suite hex codes):
//
//	0x1301  TLS_AES_128_GCM_SHA256        AES-128-GCM        SHA-256
//	0x1303  TLS_CHACHA20_POLY1305_SHA256  ChaCha20-Poly1305  SHA-256
//	0x1304  TLS_AES_128_CCM_SHA256        AES_128_CCM        SHA-256
//
// and §2.5.2.1 steps 3–8, which walk those three the same way. The requirements
// index behind them is SunSpecTCP-17 ("Mandatory TLS v1.2 cipher suites (GCM,
// CHACHA20, CCM_8)", MUST) and SunSpecTCP-18 ("Mandatory TLS v1.3 cipher suites
// if v1.3 is supported", MUST*), with SunSpecTCP-19 fixing the order.
//
// The ORDER of the two slices is the document's order, because CRYP-001 and
// CRYP-002 iterate them in it and TLSF-001/002 assert on it.

import "fmt"

// Version is a TLS wire protocol version code.
type Version uint16

// The versions the mbaps profile allows. TLS 1.2 is the mandated floor
// (SunSpecTCP-4); TLS 1.3 may be supported (SunSpecTCP-5).
const (
	TLS12 Version = 0x0303
	TLS13 Version = 0x0304
)

func (v Version) String() string {
	switch v {
	case TLS12:
		return "TLS 1.2"
	case TLS13:
		return "TLS 1.3"
	case 0:
		return "(unset)"
	default:
		return fmt.Sprintf("0x%04X", uint16(v))
	}
}

// Suite is one cipher suite the probe can be pinned to.
//
// Zero is "not pinned": the probe then offers the whole mandated set for the
// version range it was given, which is the shape a check wants when the suite
// is not the subject (a session for a Model 1 read, say).
type Suite struct {
	// Code is the IANA codepoint, as it appears in ClientHello.cipher_suites
	// and ServerHello.cipher_suite.
	Code uint16
	// IANA is the registered name, as the procedures write it.
	IANA string
	// Wolf is the OpenSSL-format name wolfSSL's cipher list consumes.
	Wolf string
	// Version is the TLS version this suite belongs to. A TLS 1.3 suite cannot
	// be negotiated under TLS 1.2 and vice versa, so pinning a suite also pins
	// the version — see Spec.versionRange.
	Version Version
}

// Pinned reports whether this is a real suite rather than the zero value.
func (s Suite) Pinned() bool { return s.Code != 0 }

// String renders the suite the way an assertion cites it.
func (s Suite) String() string {
	if !s.Pinned() {
		return "(the mandated set)"
	}
	return fmt.Sprintf("0x%04X %s", s.Code, s.IANA)
}

// The mandated TLS 1.2 suites, in SunSpecTCP-17 order.
var (
	TLS12GCM = Suite{
		Code: 0xC02B, IANA: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		Wolf: "ECDHE-ECDSA-AES128-GCM-SHA256", Version: TLS12,
	}
	TLS12ChaCha = Suite{
		Code: 0xCCA9, IANA: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		Wolf: "ECDHE-ECDSA-CHACHA20-POLY1305", Version: TLS12,
	}
	// TLS12CCM8 is the suite Go's crypto/tls cannot complete, and the reason
	// this package exists.
	TLS12CCM8 = Suite{
		Code: 0xC0AE, IANA: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
		Wolf: "ECDHE-ECDSA-AES128-CCM-8", Version: TLS12,
	}
)

// The mandated TLS 1.3 suites, in SunSpecTCP-18 order.
var (
	TLS13GCM = Suite{
		Code: 0x1301, IANA: "TLS_AES_128_GCM_SHA256",
		Wolf: "TLS13-AES128-GCM-SHA256", Version: TLS13,
	}
	TLS13ChaCha = Suite{
		Code: 0x1303, IANA: "TLS_CHACHA20_POLY1305_SHA256",
		Wolf: "TLS13-CHACHA20-POLY1305-SHA256", Version: TLS13,
	}
	// TLS13CCM is the other suite crypto/tls cannot complete.
	TLS13CCM = Suite{
		Code: 0x1304, IANA: "TLS_AES_128_CCM_SHA256",
		Wolf: "TLS13-AES128-CCM-SHA256", Version: TLS13,
	}
)

// Mandatory12 is SunSpecTCP-17's list in the document's order.
var Mandatory12 = []Suite{TLS12GCM, TLS12ChaCha, TLS12CCM8}

// Mandatory13 is SunSpecTCP-18's list in the document's order.
var Mandatory13 = []Suite{TLS13GCM, TLS13ChaCha, TLS13CCM}

// CCMSuites are the mandated suites that use AES-CCM — the two no Go TLS stack
// can complete. They are named as a set because "which of these did the bench
// actually establish a session on?" is the question this package was written to
// be able to answer.
var CCMSuites = []Suite{TLS12CCM8, TLS13CCM}

// ByCode returns the mandated suite with this codepoint.
func ByCode(code uint16) (Suite, bool) {
	for _, s := range append(append([]Suite{}, Mandatory12...), Mandatory13...) {
		if s.Code == code {
			return s, true
		}
	}
	return Suite{}, false
}

// wolfList renders the cipher list for a set of suites, in the order given.
// wolfSSL 5.7.6 needs every TLS 1.3 suite to precede the TLS 1.2 suites in a
// mixed list or it will not negotiate TLS 1.3 at all, so callers that mix must
// pass them that way; the mandated-set helpers below already do.
func wolfList(suites []Suite) string {
	out := ""
	for i, s := range suites {
		if i > 0 {
			out += ":"
		}
		out += s.Wolf
	}
	return out
}
