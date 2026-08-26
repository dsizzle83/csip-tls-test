// Package suitessm implements the SunSpec "Secure SunSpec Modbus Conformance
// Test Procedures" v0.8 (catalog document SSM-CONF-v0.8) against the LEXA DER
// gateway's northbound mbaps server on :802 — and, for the handful of [C]-half
// procedures, against the gateway's SOUTHBOUND mbaps client as it dials the
// bench's device simulator.
//
// The organising key here is the TEST CASE ID from the procedures document
// (TLSF-001, CRYP-004, RBAC-008 …), not the requirement number. Each test case
// subsumes one or more SunSpecTCP-N requirement rows; those rows are named in
// every assertion's Claim so a reviewer can walk from a requirement to the
// frames that evidence it. sim/ssm-conformance remains the requirement-indexed
// view of the same surface; this suite is the procedure-indexed view, and the
// two are deliberately independent implementations of the decision logic (see
// "Three stacks" below).
//
// # What this suite is for
//
// A conformance report is worth exactly as much as the reader's ability to
// re-check it. So every row this suite produces is one of four things and never
// anything else:
//
//   - PASS with a citation — a claim, the method that established it, and the
//     capture frames (or reassembled byte range, with its sha256) that show it.
//     A stranger opens the pcap at that frame and sees the fact.
//   - FAIL with a citation — the same, for a criterion that did not hold.
//   - SKIP with a reason — the criterion was addressed and NOT asserted here.
//     Every SKIP in this package names the specific thing that prevented the
//     assertion (a DUT configuration change the bench is not permitted to make,
//     a capability the bench client does not have, an absent key log).
//   - WARN — asserted with a caveat that a reader must weigh.
//
// There is no fifth category. In particular there is no "the handshake
// completed, therefore the extension must have been offered" row: that is the
// inference sim/ssm-conformance is explicit about making for TCP-43/44/61, and
// closing it with captured bytes is precisely why this suite exists.
//
// # Three stacks, on purpose
//
// The bench is the referee (this repository's PN-1 / C9 / AD-003(f)). The
// product's TLS is mbed TLS; sim/ssm-conformance drives wolfSSL through
// internal/mbtls; this suite drives Go's crypto/tls plus a raw ClientHello
// prober written from the RFCs in probe.go. That is a THIRD independent
// implementation, and the independence is load-bearing twice over:
//
//  1. A profile bug that both the product and one referee share would be
//     reproduced identically and green-lit. Three stacks make that much less
//     likely, and a disagreement between the suites is itself a finding.
//  2. Half of these procedures require a DELIBERATELY NON-CONFORMANT
//     ClientHello — one carrying only NULL-encryption suites, or SHA-1
//     signature algorithms, or the mandated suites in reversed preference
//     order. internal/mbtls refuses to build such a profile, correctly:
//     Profile.Validate exists to stop a conformant peer being mis-configured.
//     A referee needs to be able to say things a conformant peer never would,
//     so those probes are hand-rolled ClientHello bytes (probe.go) and the
//     server's answer is read straight off the socket and parsed by
//     internal/evidence/tlsdis.
//
// The one place this costs something is completion. Go's crypto/tls implements
// no AES-CCM cipher, so it cannot complete
// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE) or TLS_AES_128_CCM_SHA256
// (0x1304), and it does not implement RFC 6066 max_fragment_length. Where a
// procedure's criterion needs one of those, the suite asserts exactly what it
// did observe — the ServerHello selecting the suite, the server's full flight
// through ServerHelloDone, the ServerHello echoing the MFL code — and records a
// SKIP naming the sub-criterion it could not reach and why. It never rounds
// "the server selected CCM-8 and sent its certificate" up to "a CCM-8 session
// was established".
//
// For the CIPHER-SUITE rows that is no longer where it stops. SSM-CONF-v0.8
// §2.5.1.3 asks that the EUT-S "successfully establishes a secure session using
// each of the mandatory TLS v1.2 cipher suites", and a selection is not a
// session. CRYP-001 and CRYP-002 therefore reach for a FOURTH client —
// internal/tlsprobe, a small wolfSSL client that can be pinned to one suite,
// completes the mTLS handshake, and carries a SunSpec Model 1 read inside the
// tunnel — for every mandated suite including the two that use CCM. See
// ccmsession.go for the bridge and internal/tlsprobe's package doc for why it
// is neither internal/mbtls nor the product's stack.
//
// # The two halves of most procedures
//
// Nearly every SSM-CONF procedure has a server half ([S], EUT-S) and a client
// half ([C], EUT-C). The gateway supplies both surfaces, but they are observed
// completely differently:
//
//   - The [S] half is active: this suite dials 69.0.0.2:802, so every frame is
//     attributable by 4-tuple and the evidence is precise.
//   - The [C] half is passive: the gateway dials the desktop's mbapsdev sim at
//     69.0.0.20:8021 on its own southbound poll schedule. This suite cannot
//     make it dial (that would need a DUT configuration change, which the
//     shared-bench constraint forbids), so it registers the weaker
//     Window.ClaimEndpointDuring claim on that endpoint, waits a poll interval,
//     and asserts on the gateway's ClientHello IF one arrived. If none did,
//     the client half is a SKIP naming the wait and the poll schedule. The
//     framework marks every assertion built on an endpoint claim with the
//     reduced attribution precision, so a reader knows.
//
// A candidate need not have both halves. The catalog's dut_role is one scalar
// per case, which takes a whole mbaps-client ROW out of scope for a server-only
// candidate (internal/certify/scope.go) and can say nothing about the [C]
// assertion sitting inside an mbaps-server row. roles.go supplies that finer
// grain: every assertion this suite mints carries a declared direction, and a
// client-direction one is reported NOT APPLICABLE — with the manifest key that
// decided it — when the candidate does not claim that direction. Those rows
// then roll up on their server assertions instead of carrying a SKIP that reads
// like unfinished work.
//
// # TLS 1.2 on purpose
//
// Several checks force the probe to TLS 1.2 even though the DUT offers 1.3.
// That is not a downgrade attack on the evidence, it is the opposite: in TLS
// 1.2 the Certificate, CertificateRequest and ServerKeyExchange messages are
// PLAINTEXT on the wire, so the certificate chain, the role extension OID
// 1.3.6.1.4.1.50316.802.1, the certificate_authorities list and the negotiated
// curve can be cited byte-for-byte from the capture with no key log at all.
// Under TLS 1.3 the same facts exist only inside the AEAD, and citing them
// requires the run's NSS key log. Where both are asserted, the TLS 1.2 probe
// carries the certificate evidence and a separate 1.3 probe carries the
// version-negotiation evidence.
//
// # Decryption
//
// The application-layer criteria — the MBAP header structure, the Modbus
// exception code 0x01 on an unauthorised write, the exactly-9-byte exception
// response — live inside the tunnel. This suite exports its own session secrets
// to the run's key log (crypto/tls KeyLogWriter, wired in session.go) so the
// capture decrypts with internal/evidence/tlsdecrypt. Every such assertion
// cites the frames carrying the encrypted records and states the recovered
// plaintext in Observed: a reader with the bundle's capture and key log
// reproduces it exactly. Without a key log those assertions are SKIP, never
// PASS-on-trust — the check knows the plaintext (it is one of the two
// endpoints) but knowing is not evidence.
//
// # Layout
//
//	suite.go      registration of every applicable SSM-CONF-v0.8 uid
//	probe.go      the raw ClientHello prober: say anything, parse the answer
//	session.go    completing mTLS sessions (crypto/tls) + MBAP/SunSpec requests
//	minting.go    runtime certificate fixtures the committed set does not carry
//	wire.go       from an Evidence to the parsed TLS view of this check's stream
//	analysis.go   the decision logic — pure functions, no sockets, unit-tested
//	checks_*.go   one file per procedure family
package suitessm
