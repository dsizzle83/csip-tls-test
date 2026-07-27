// Package suitepki implements the SunSpec Test PKI document (catalog slug
// SS-TEST-PKI) and provides the certificate primitives the other suites need
// for their PKI preconditions.
//
// # Why this suite's coverage ratio is the worst in the catalog, and why that
// # is the honest number
//
// SS-TEST-PKI has 21 extracted test cases and the catalog marks only 6 of them
// applicable. That is not an implementation gap, and this package goes out of
// its way not to let it read like one. Eleven of the fifteen inapplicable rows
// are about the SunSpec Alliance's own certificate PACKAGE — what a request to
// the SunSpec PKI program returns, how the files inside it are named
// (sat-<type>_<chain>_<model>_<serial>), which of them must be installed to
// provision a device, and how to ask for one. We are not enrolled in that
// program. The bench is anchored on a private two-tier CA of its own
// (certs/mbaps), so a check asserting "the file name element <chain> is one of
// dev | mica-dev | mca-mica-dev" would be asserting a property of a file that
// does not exist here. Two more (PKI-9, PKI-10) require installing an
// externally generated private key into the DUT, which certmgr cannot do BY
// DESIGN: its rotation lifecycle is stage-csr -> sign -> complete(chainPEM) and
// the private key never leaves the vault. A test tool that reported those rows
// as passes would be lying; a test tool that quietly omitted them would be
// hiding the question. The catalog's Inapplicable list, with each row's
// applicability_reason, is where they are accounted for, and COVERAGE.md prints
// it.
//
// What IS left is the part that matters: the properties of the certificate the
// DUT actually presents on the wire, and the trust operations it actually
// supports. Ten uids are registered here — the 6 applicable ones plus PKI-4,
// PKI-5, PKI-6 and PKI-7, which are discussed next.
//
// # The four rows this suite exists to FAIL
//
// PKI-4/5/6/7 are the IEEE 2030.5-2018 device identification profile: the
// device certificate's Subject MUST be empty and the identity MUST be carried
// in a SubjectAltName otherName of type id-on-hardwareModuleName (RFC 4108
// §5, OID 1.3.6.1.5.5.7.8.4) holding a manufacturer model OID (hwType, rooted
// at the manufacturer's IANA Private Enterprise Number) and a device serial
// number (hwSerialNum, a DER OCTET STRING carrying a UTF-8 string).
//
// The DUT does not do this. certmgr's CSR sets a Subject CN and nothing else,
// and no code in the product or in the bench CA emits a hardwareModuleName.
// The catalog therefore marks these rows inapplicable with the reason "the DUT
// provably fails this check today".
//
// This suite registers and executes them anyway, and reports FAIL with wire
// evidence. That is a deliberate decision, and the reasoning is worth stating
// because it is the single most valuable output of the whole exercise:
//
//   - "Inapplicable" in the catalog means "not executable as the SunSpec test
//     procedure writes it", because that procedure inspects a certificate
//     inside a package we do not have. It does not mean the underlying
//     REQUIREMENT is out of scope. A 2030.5 device is required to carry this
//     identity; ours does not.
//   - The gap is independently observable from the wire without the SunSpec
//     package: pull the DUT's leaf certificate out of the Certificate
//     handshake message in the pcap and look for the extension. This suite
//     does exactly that, and cites the byte range of the Certificate message
//     so a third party can re-derive the finding from the capture alone.
//   - A tool that only ever reports passes is worth nothing. Naming a concrete,
//     re-checkable gap between the device and a certification requirement,
//     before a lab does, is the point of building this.
//
// A reader who disagrees with the judgement can exclude the four rows with
// -applicable; they will then appear in COVERAGE.md under Inapplicable with the
// catalog's own reason, and nothing is hidden either way.
//
// # Evidence discipline in this suite
//
// Every certificate fact this suite asserts comes from the TLS Certificate
// handshake message as it appeared in the capture, dissected by
// internal/evidence/tlsdis, and is cited as a byte range of the reassembled
// server->client (or client->server) direction with its sha256. The socket-level
// view — what crypto/tls handed back as ConnectionState.PeerCertificates — is
// recorded too, but only ever as a Narrative assertion naming that source,
// because a claim a reader cannot re-derive from the pcap is not evidence, it
// is testimony.
//
// # Why crypto/tls and not internal/mbtls
//
// The bench's rule (PN-1 / C9 / AD-003(f)) is that the referee must not share
// an implementation with the thing it referees. The product's TLS stack is
// mbed TLS; the bench's mbaps stack is wolfSSL via internal/mbtls. This suite
// dials with the Go standard library instead, for four reasons, in descending
// order of importance:
//
//  1. A certificate-property test case must be able to complete a handshake
//     against a peer whose certificate is NOT conformant — that is the entire
//     job. Handshake below verifies the peer chain when it is given roots but
//     never lets verification decide whether the chain gets recorded, so the
//     DUT's presented chain is available for inspection even when it would not
//     validate. It also needs the FULL presented chain, not just the leaf:
//     mbtls.Session exposes only PeerDER.
//  2. Independence is strengthened, not weakened. crypto/tls shares no code
//     with mbed TLS, and none with wolfSSL either, so a PKI verdict here does
//     not rest on the same library the transport suite's verdicts rest on.
//  3. tls.Config.KeyLogWriter exports NSS key-log lines with no build tag and
//     no sysroot, so a run of this suite can decrypt its own capture when the
//     handshake reaches TLS 1.3.
//  4. The package stays CGO_ENABLED=0-clean, so the precondition helpers below
//     — which are shared with every other suite — do not drag wolfSSL into
//     pure-Go tooling, and every decision this suite makes is testable with
//     nothing but a Go toolchain.
//
// Handshake defaults to a TLS 1.2 ceiling, deliberately. The certificate a peer
// presents is the same object at either version, but TLS 1.3 encrypts the
// Certificate message: at 1.2 the DUT's certificate sits in the capture in the
// clear, and the evidence is re-checkable by anyone holding the pcap and no
// secrets at all. When a capture does show a 1.3 handshake, ReadWireHandshake
// falls back to internal/evidence/tlsdecrypt if the run exported a key log, and
// says so on the assertion; with no key log it SKIPs with that reason rather
// than asserting on ciphertext.
//
// # The shared precondition helpers
//
// The rest of the package is the PKI toolkit the other suites' preconditions
// need, and it is exported for them:
//
//   - Hierarchy / NewHierarchy mint a throwaway 2030.5-shaped test PKI —
//     SERCA -> MCA -> MICA -> device — so a suite can present the DUT with each
//     of the three chain depths IEEE 2030.5 defines.
//   - LeafSpec / Hierarchy.Mint mint role certificates (the SunSpec role
//     extension at OID 1.3.6.1.4.1.50316.802.1) and the deliberate-error
//     negative fixtures: expired, not-yet-valid, wrong-CA, no-role, two-role,
//     empty-role, oversize-role, PrintableString-encoded role.
//   - Leaf.ChainPEM / Leaf.TLSCertificate assemble a leaf-first chain the way
//     SunSpecTCP-51 requires.
//   - InspectDER / InspectChain turn DER into the facts a check decides on:
//     Subject emptiness, the 2030.5 device identity, the SunSpec role, chain
//     depth, and each link's issuer-DN / key-id / signature relationship.
//   - ReadWireHandshake lifts both peers' certificate chains, the
//     CertificateRequest and any fatal alert out of a captured conversation,
//     with the frames and byte offsets each one occupied.
//
// None of it touches the bench at import time, and none of it writes to
// certs/mbaps: material minted for a check lives in memory, and the shared
// fixture tree is read-only to this package.
package suitepki
