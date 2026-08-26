// Package tlsprobe is an INDEPENDENT Secure SunSpec Modbus (mbaps) client that
// can be pinned to one cipher suite, completes the mutual-auth TLS handshake,
// carries one SunSpec Model 1 read inside the tunnel, and reports what it
// negotiated.
//
// # Why this exists: "selected" is not "established"
//
// SSM-CONF-v0.8 §2.5.1.1 does not ask whether the EUT-S *picks* a mandated
// suite. It says, for each of the three:
//
//  2. [C] TC initiates a TLS v1.2 handshake offering only
//     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
//  3. [S] EUT-S accepts the connection and completes the handshake.
//
// and its criteria (§2.5.1.3) read "The EUT-S successfully establishes a secure
// session using each of the mandatory TLS v1.2 cipher suites." §2.5.2 (CRYP-002)
// repeats the shape for 0x1301 / 0x1303 / 0x1304 and adds a Model 1 read.
//
// The mandated set includes AES-CCM — 0xC0AE TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
// under TLS 1.2 and 0x1304 TLS_AES_128_CCM_SHA256 under TLS 1.3. Go's
// crypto/tls implements no CCM cipher at all, so the suite's existing probe can
// take a CCM handshake exactly as far as the DUT's ServerHello and its server
// flight, and no further. The evidence that produced was a SELECTION plus a
// standing WARN caveat saying, honestly, that no session had been established
// on it — a gap in the bench, published on the row as though it were the row's
// verdict.
//
// This package closes that gap by not using crypto/tls. The bench already links
// wolfSSL for its sims (sim/tlsserver, sim/mbapsdev, internal/mbtls), and
// wolfSSL implements AES-CCM in both versions. So the probe is a second,
// deliberately small client built on the same single cgo wrapper
// (internal/wolfssl) that can be pinned to ONE suite and driven to a completed
// session and a real Modbus exchange.
//
// # Independence
//
// It is not internal/mbtls, and the difference is deliberate rather than
// duplication for its own sake. mbtls carries the mbaps PROFILE — its
// Profile.Validate refuses any suite list that is not a subsequence of the
// mandated order, and it pins MinTLS to TLS 1.2 — which is exactly right for
// the bench's own conformant peers (the device sim, the aggregator emulator)
// and exactly wrong for a conformance probe, whose whole job is to offer ONE
// suite, sometimes at ONE version, and see what the DUT does. A probe that
// could not express "TLS 1.3 only, 0x1304 only" could not carry out CRYP-002
// step 7.
//
// It is also not the product's TLS stack, for the referee reason recorded in
// internal/mbtls's package doc: a bench that shared TLS-profile code with the
// gateway under test could not independently catch a profile bug.
//
// What it DOES share is lexa-proto/mbap, the pure-Go MBAP framing codec, for
// the same reason mbtls does: the wire format is the wire format, and a
// divergent framing codec would produce bugs rather than independent
// verification. Every DECISION about a response is made here, from the raw
// bytes (see modbus.go).
//
// # Build
//
// The wolfSSL half is behind the `cgo` build constraint and the pure-Go half is
// not, so `CGO_ENABLED=0 go build ./cmd/certify` keeps working — the certify
// gate requires it (Makefile, test-certify step 2). In that build Dial returns
// ErrUnavailable and a caller reports the absence rather than a false negative
// about the DUT.
//
// Key-log export follows the same rule as the rest of the bench: it is armed
// unconditionally and does something only in a `-tags keylog` build against the
// keylog sysroot (internal/wolfssl/keylog.go). A run that asked for a key log
// and did not get one is told at OpenKeylog time, not at analysis time.
//
// # Usage
//
//	rep, err := tlsprobe.Complete(ctx, tlsprobe.Spec{
//	        Target:   "69.0.0.2:802",
//	        CAFiles:  []string{"certs/mbaps/ca-cert.pem"},
//	        CertFile: "certs/mbaps/clients/grid-service-cert.pem",
//	        KeyFile:  "certs/mbaps/clients/grid-service-key.pem",
//	        Suite:    tlsprobe.TLS12CCM8,
//	        OnConnect: func(c net.Conn) error { return rc.ClaimConn(c, "CRYP-001 CCM session") },
//	})
//
// OnConnect is called with the RAW TCP connection after connect and BEFORE the
// handshake, which is the only moment at which a caller can register the
// connection for frame attribution and still have a REFUSED handshake produce
// citable frames.
package tlsprobe
