// Package netdis dissects captured frames down to the TCP payload and
// reassembles TCP byte streams with full provenance: for every byte of every
// stream it can name the packet index the byte arrived in.
//
// # Why provenance is the feature
//
// An evidence bundle's whole value is the ability to say, and have a third
// party re-check, a sentence of this shape:
//
//	"RBAC-004 passes because the gateway answered the NetworkAdmin write with
//	 Modbus exception 01, and that answer is bytes 120..131 of stream
//	 69.0.0.2:802 → 69.0.0.20:51422, carried in frame 4471."
//
// Every noun in that sentence has to survive an independent re-read of the
// pcap. A reassembler that merely concatenated payloads would make the byte
// offsets meaningless the moment a retransmission or a reordered segment turned
// up, and it would let an operator (or a tampered capture) cite a frame that
// does not actually carry the bytes claimed. So StreamBytes keeps a run table
// mapping delivered offsets back to packet indices, and OffsetToPacket /
// PacketsFor are the primitives the bundle's Verify step re-runs.
//
// # Why overlaps are flagged rather than silently resolved
//
// Overlapping TCP segments with differing content are the classic IDS-evasion
// and evidence-tampering primitive: two segments claim the same sequence range
// with different bytes, and what a receiver "saw" depends on which one its
// stack kept. This package always keeps the first writer — the same rule Linux
// and every modern stack use — and additionally records an Overlap for each
// occurrence, with Conflict set when the discarded bytes DIFFER from the kept
// ones. A conformance run that produced conflicting overlaps has a capture
// nobody should certify from, and the bundle is expected to surface that rather
// than quietly pick a winner.
//
// # Scope
//
// Link types: Ethernet (1, including stacked 802.1Q/802.1ad tags), Null/
// Loopback (0) and OpenBSD LOOP (108), raw IP (101/228/229) and Linux cooked
// capture v1 (113) and v2 (276). Loopback matters because parts of the
// conformance suite run against a loopback target on the desktop itself, and a
// reader that only understood Ethernet would be unable to read half the
// bundle's captures.
//
// IPv4 options are skipped correctly and IPv6 extension-header chains are
// walked. Fragmented datagrams are FLAGGED and never fed to the reassembler:
// IP fragment reassembly is a second, independent evidence problem, and
// pretending a first fragment's partial payload is a complete TCP segment is
// exactly the kind of silent error this package exists to avoid.
package netdis
