// Package pcapng reads packet-capture files — both the modern pcapng block
// format and the classic libpcap format, in either endianness and in both the
// microsecond and nanosecond timestamp variants.
//
// # Why a hand-rolled reader
//
// The obvious answer is gopacket/pcapgo. This bench does not take it, for two
// reasons that outrank convenience. First, the evidence engine has to build
// with CGO_ENABLED=0 and add nothing to go.mod: the whole point of an evidence
// bundle is that a third party can rebuild the verifier from a tarball and the
// Go toolchain, with no libpcap, no vendored graph to audit, and no version
// skew between what produced a claim and what re-checks it. Second — and this
// is the referee-independence rule this repo lives by (CLAUDE.md, PN-1/C9) —
// the artifact we hand a certification body must not be readable only by the
// same third-party library that wrote it. A reader we own, with tests we own,
// is the thing that turns "our tool says so" into "here are the bytes".
//
// # Why it is paranoid
//
// This parser is pointed at files that arrive from outside: captures taken on
// a customer bench, captures a QA engineer mangled on purpose, captures a
// hostile party would very much like to have us mis-read. Length fields in
// pcapng are attacker-chosen 32-bit integers used directly as allocation sizes,
// so every one of them is bounds-checked against MaxBlockLen/MaxPacketLen and
// against the bytes actually present. The contract is absolute: malformed input
// yields an error, never a panic and never a silently-truncated packet list.
// A truncated file is an error at the point of truncation, with the packets
// read so far already delivered — a capture that was killed mid-block is still
// evidence for the frames that made it to disk, but the reader will not pretend
// the tail was clean.
//
// # What it deliberately does not do
//
//   - No gzip/zstd transparent decompression: the bundle stores captures raw so
//     the MANIFEST.sha256 hash covers exactly the bytes dumpcap wrote.
//   - No Decryption Secrets Blocks (pcapng block type 0x0A). dumpcap does not
//     write them; keys travel as a separate NSS key-log file which the bundle
//     hashes alongside the pcap. See internal/evidence/keylog.
//   - No per-packet options beyond what a timestamp needs (no packet flags,
//     no verdict/comment options). They are skipped, not rejected.
//   - The classic-pcap "thiszone" field is ignored, as libpcap itself has always
//     ignored it; timestamps are UTC.
package pcapng
