// Package aead supplies the two AEAD constructions the Go standard library
// does not, so the evidence engine can decrypt every cipher suite a CSIP or
// Secure SunSpec Modbus device is allowed to negotiate.
//
//   - CCM (NIST SP 800-38C) over any 128-bit block cipher, with configurable
//     nonce and tag sizes. This is what TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
//     (0xC0AE) needs — the suite CSIP §5.2.1.1 mandates, and the one Go's
//     crypto/tls has never implemented.
//   - ChaCha20-Poly1305 (RFC 8439), because golang.org/x/crypto is not vendored
//     in this repository and an evidence bundle's verifier must build from the
//     standard library alone.
//
// AES-GCM is not here: crypto/cipher.NewGCMWithTagSize covers it, and
// reimplementing a construction the standard library already provides would add
// risk for nothing.
//
// Both types satisfy crypto/cipher.AEAD, so internal/evidence/tlsdecrypt
// selects between these and the standard AES-GCM through one interface.
//
// # Correctness posture
//
// These implementations are written for auditability over speed. They run once
// per capture file, offline, with keys the operator already holds in an NSS key
// log — there is no live secret and no timing surface worth hardening. Tag
// comparison is still constant-time, and Open never returns plaintext that
// failed to authenticate: a partially decrypted record presented as valid would
// be the worst possible failure mode for a tool whose entire output is
// evidence.
//
// The test suite carries the RFC 3610 packet vectors for CCM and the RFC 8439
// vectors for ChaCha20, Poly1305, and the combined AEAD, plus round-trip and
// tamper-detection cases at every boundary of the length encodings.
package aead
