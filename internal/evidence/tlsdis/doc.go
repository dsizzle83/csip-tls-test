// Package tlsdis dissects the TLS record layer and the handshake it carries.
//
// # Where conformance evidence actually lives
//
// Most of what a Secure SunSpec Modbus or CSIP conformance procedure asks about
// is visible without decrypting anything. The cipher suites a device offers and
// the one a server chooses, the compression methods, the supported groups and
// point formats, max_fragment_length and renegotiation_info, whether the server
// sent a CertificateRequest, whether a fatal alert closed the connection and
// which one — all of it is plaintext in the handshake. This package parses that
// layer and, for TLS 1.3, the same parser is reused on the payloads that
// internal/evidence/tlsdecrypt recovers, so there is exactly one implementation
// of "how a Certificate message is laid out" in the engine.
//
// # The two rules that make handshake parsing correct
//
// First: the handshake is a byte stream layered over the record layer, not a
// sequence of records. A certificate chain of any realistic size spans several
// records, and a message's four-byte header can be split across a record
// boundary. Parsing messages inside each record separately produces multi-
// megabyte phantom messages the first time a chain does not fit — coalesce all
// of a direction's handshake fragments, then parse messages from the result.
// ParseHandshake takes Fragments precisely so this order cannot be skipped.
//
// Second: parsing must stop at the first ChangeCipherSpec. Everything after it
// is ciphertext, and a parser that kept going would report the AEAD's output as
// handshake structure.
//
// # Reporting discipline
//
// Nothing is silently dropped. An unknown cipher suite prints as
// UNKNOWN(0x____) rather than vanishing from the offered list, because a suite
// the bench has never seen appearing in a DUT's ClientHello is a finding.
// Certificate extensions are enumerated in full, custom OIDs included, with
// their raw DER: proving that the SunSpec role extension (OID
// 1.3.6.1.4.1.50316.802.1) was presented, and encoded as the single UTF8String
// the specification demands, is the pass criterion for the role-based
// authorization test cases, and the only way a third party can re-check it is
// from the bytes themselves.
//
// # Provenance
//
// Every record, message, and alert carries the capture frames it spanned, via
// the OffsetMapper the caller supplies (netdis.StreamBytes). That is what turns
// "the server chose TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" into a sentence with a
// frame number in it.
package tlsdis
