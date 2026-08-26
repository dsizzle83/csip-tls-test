//go:build cgo

package tlsprobe

// reason_cgo.go classifies a failed handshake into "the PEER refused what we
// offered" and "WE refused the peer's certificate".
//
// # Why the distinction is worth this much code
//
// A cipher-suite procedure reads a failed handshake as a fact about the DUT:
// it was offered a suite SunSpecTCP-17 makes mandatory and would not complete.
// That is a FAIL, and it should be.
//
// But a handshake can also fail because THIS SIDE would not accept the DUT's
// certificate — no trust anchor for its issuer, an extendedKeyUsage that does
// not name serverAuth, an expired leaf. That is a fact about the BENCH's trust
// configuration, or at most about the DUT's PKI (which PKI-003/004/007/008
// measure on their own rows), and reporting it as "the DUT refused a mandatory
// cipher suite" would publish a finding that never happened.
//
// The rest of this suite has never had to make the distinction: its crypto/tls
// sessions dial with InsecureSkipVerify and do their own path validation so the
// verification RESULT is an observation rather than a dial error
// (internal/certify/suitessm/session.go's first design point). wolfSSL verifies
// in the library, and the wrapper this bench shares
// (internal/wolfssl) exposes no way to turn that off — so the distinction is
// made here, from the reason code the library reports.
//
// # The string coupling, stated plainly
//
// internal/wolfssl.Connect formats its failure as
//
//	wolfSSL_connect failed: ret=%d err=%d
//
// and does not carry the reason code in a typed field. Recovering it means
// reading that tail. That is a coupling to a sibling package's error TEXT, and
// it is here rather than in a wrapper change because the wrapper is shared with
// the product-facing sims and this change's remit does not extend to it.
//
// It is written to fail SAFE: a message this parser does not recognise yields
// no classification at all, and an unclassified failure is reported as what it
// has always been reported as — a handshake that did not complete.
// TestReasonSurvivesTheWrappersFormat pins the format against a real failure so
// the coupling cannot rot silently.

import (
	"regexp"
	"strconv"

	"csip-tls-test/internal/wolfssl"
)

// wolfReasonPattern matches internal/wolfssl's Connect/Accept failure tail.
var wolfReasonPattern = regexp.MustCompile(`err=(-?\d+)`)

// peerRejectedCodes are the wolfSSL reasons that mean THIS side refused the
// peer's certificate chain. Transcribed from the bench sysroot's
// wolfssl/error-ssl.h and wolfssl/wolfcrypt/error-crypt.h.
var peerRejectedCodes = map[int]string{
	-140: "ASN_PARSE_E — the peer's certificate did not parse",
	-150: "ASN_BEFORE_DATE_E — the peer's certificate is not yet valid",
	-151: "ASN_AFTER_DATE_E — the peer's certificate has expired",
	-155: "ASN_SIG_CONFIRM_E — the peer's certificate signature did not verify",
	-188: "ASN_NO_SIGNER_E — no trust anchor for the peer's issuer was loaded",
	-237: "ASN_PATHLEN_SIZE_E — the peer's chain exceeds a CA's pathLenConstraint",
	-238: "ASN_PATHLEN_INV_E — the peer's chain inverts a CA's pathLenConstraint",
	-275: "ASN_SELF_SIGNED_E — the peer presented a self-signed certificate",
	-322: "DOMAIN_NAME_MISMATCH — the peer's subject name does not match",
	-329: "VERIFY_CERT_ERROR — the peer's certificate did not verify",
	-362: "CRL_MISSING — no CRL is loaded for the peer's issuer",
	-368: "MAX_CHAIN_ERROR — the peer's chain is deeper than wolfSSL will follow",
	-383: "KEYUSE_SIGNATURE_E — the peer's keyUsage does not permit digitalSignature",
	-385: "KEYUSE_ENCIPHER_E — the peer's keyUsage does not permit keyEncipherment",
	-386: "EXTKEYUSE_AUTH_E — the peer's extendedKeyUsage names neither serverAuth nor clientAuth",
}

// classify fills in a HandshakeError's diagnosis from the wrapped error.
func (e *HandshakeError) classify() {
	if e == nil || e.Err == nil {
		return
	}
	m := wolfReasonPattern.FindStringSubmatch(e.Err.Error())
	if m == nil {
		return
	}
	code, err := strconv.Atoi(m[1])
	if err != nil {
		return
	}
	e.Code = code
	e.Reason = wolfssl.ErrString(code)
	if why, ok := peerRejectedCodes[code]; ok {
		e.PeerRejectedByUs = true
		e.Diagnosis = why
	}
}
