// Package tlsdecrypt turns captured TLS records back into plaintext using an
// NSS key log, for both TLS 1.2 and TLS 1.3.
//
// # What it is for
//
// Some conformance criteria live inside the encryption. In TLS 1.3 the entire
// handshake after ServerHello is encrypted, which means the client's
// certificate chain — and with it the SunSpec role extension at OID
// 1.3.6.1.4.1.50316.802.1 that the role-based authorization test cases turn on
// — is invisible without decryption. So is every alert after the handshake, and
// so is the Modbus PDU whose exception code proves a write was refused.
//
// # The three details that decide whether this works
//
// 1. The record sequence number is implicit. It is a counter, never a field on
// the wire, so records must be fed to a Session in capture order per direction.
// A skipped record puts every subsequent nonce off by one and every subsequent
// AEAD open fails.
//
// 2. A ChangeCipherSpec record does NOT advance that counter. In TLS 1.3 it is
// a middlebox-compatibility no-op that can appear in the middle of an encrypted
// flight; counting it is a popular way to produce a decryptor that works
// against some stacks and not others.
//
// 3. Keys change mid-connection, and the counter RESETS when they do. TLS 1.3
// records between ServerHello and a side's Finished use that side's HANDSHAKE
// traffic secret; everything after uses its APPLICATION traffic secret, from
// sequence number zero. A KeyUpdate does the same thing again. Session tracks
// this by watching the decrypted handshake stream for Finished and KeyUpdate —
// coalesced across records, because a Finished can be split like anything else.
//
// # Failure posture
//
// Every one of those mistakes fails the same way: the AEAD tag does not verify.
// That is indistinguishable, at the point of failure, from a corrupt capture —
// which is why this package never returns partially decrypted output and never
// guesses. A failure comes back as a *Error naming the side, the record index,
// the stream offset, the capture frames, the sequence number and the epoch in
// force, so the difference between "your capture is missing a segment" and
// "your key log is for a different session" is visible at once.
//
// The one exception is deliberate and safe: if a record fails on handshake keys
// and the session also has application keys, the engine retries with those. A
// wrong key cannot forge a valid authentication tag, so success on the retry is
// proof rather than a guess — it means the Finished that should have announced
// the switch was not in the capture. Such records are flagged
// EpochRecovered so a report can say so.
//
// # Cipher suites
//
// All five TLS 1.3 suites and every TLS 1.2 AEAD suite in the IANA registry:
// AES-GCM and ChaCha20-Poly1305 through the standard library, AES-CCM and
// AES-CCM-8 through internal/evidence/aead. CCM matters most — 0xC0AE
// (TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8) is the suite CSIP §5.2.1.1 mandates, and
// no Go TLS stack implements it. Non-AEAD suites are refused outright rather
// than half-supported: they are forbidden by the specifications this bench
// certifies against, and reporting a conformance violation as a decryption
// mystery would help nobody.
package tlsdecrypt
