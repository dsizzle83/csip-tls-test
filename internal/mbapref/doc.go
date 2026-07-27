// Package mbapref is the bench's own MBAP/Modbus reader and the differential
// oracle that judges the product's reader against it.
//
// It exists for the reason internal/csipref exists, and the reason is
// PN-1/C9 referee independence (AD-003(f)): a referee built from the subject's
// own parser cannot find the bugs they share. If the bench framed Modbus with
// lexa-proto/mbap, then every framing assumption the gateway makes — where a
// frame ends, what a length field may say, which PDU shapes are legal — would
// be assumed identically by the thing checking it, and a mistake in any of
// them would be invisible on both sides of the comparison. The evidence bundle
// would agree with the DUT because it was decoded by the DUT's code.
//
// So decode.go is written from IEC 61131 / the Modbus Application Protocol
// specification and Modbus Messaging on TCP/IP, not from lexa-proto. It shares
// no code with the product: only the bytes on the wire.
//
// # What the differential actually asks
//
// "Do two decoders agree" is not by itself a useful question — of course they
// disagree somewhere, and a diff tool that reports every disagreement gets
// switched off in a week. The questions worth asking are narrower and each one
// corresponds to a way this system could be wrong in the field:
//
//	FRAMING     Given the same byte stream, do both readers put the frame
//	            boundaries in the same places? A framing disagreement is the
//	            worst class: the evidence bundle would render messages the
//	            gateway never saw, or miss ones it acted on, and every
//	            downstream conformance claim built on that log is void.
//	SEMANTICS   For a frame both accept, do they read the same unit, function,
//	            address, count and register values? A semantic disagreement is
//	            a wrong-register write waiting to happen.
//	ACCEPTANCE  Where one accepts and the other refuses, is the divergence one
//	            of the enumerated, justified ones in Divergences()? Strictness
//	            differences are legitimate and expected; an UNENUMERATED one is
//	            a finding, and the enumeration is what keeps the oracle from
//	            decaying into a list of excuses.
//	IDENTITY    A frame that decodes must re-encode to the bytes it came from.
//	            This is the canonicalisation claim, and it is the one that
//	            catches a decoder that silently repairs its input — a length
//	            field it recomputes, a padding byte it drops. A gateway that
//	            repairs a frame answers a request nobody sent.
//
// # Corpus
//
// corpus.go seeds from real captured traffic rather than from hand-written
// vectors. Hand-written vectors encode what their author already believed the
// protocol looks like, which is exactly the belief under test; the bench's
// pcapng captures contain what two real implementations actually said to each
// other, including the coalesced segments, the split frames and the
// retransmits that a hand-written vector never has. internal/evidence/netdis
// already does the TCP reassembly with byte-to-frame provenance, so extracting
// the Modbus stream from a run's capture is a few lines, and the resulting
// corpus entries carry the frame numbers they came from.
package mbapref
