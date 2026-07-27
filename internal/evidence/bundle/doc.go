// Package bundle assembles and verifies conformance evidence bundles.
//
// A bundle is a directory:
//
//	bundle.json          machine-checkable run metadata + every test case result
//	REPORT.md            the same thing for a human, with frame numbers inline
//	MANIFEST.sha256      sha256 of every file in the bundle, sha256sum(1) format
//	capture/*.pcapng     the capture the claims are about
//	capture/*.keylog     the session secrets needed to re-check the encrypted parts
//
// # Why the format is shaped this way
//
// A test report says "the gateway refused the write". An evidence bundle says
// "the gateway refused the write; that refusal is bytes 120..131 of stream
// 69.0.0.2:802 > 69.0.0.20:51422, carried in frame 4471, and those bytes hash
// to 3f2a…". The difference is that the second sentence can be checked by
// somebody who does not trust us — and Verify is the function that checks it,
// reading nothing but the directory it is given.
//
// That is the whole design constraint. Every assertion carries the frames it
// rests on and a digest of the bytes it claims; Verify re-reads the pcap,
// re-runs the reassembly, and confirms both. An assertion with no digest is
// permitted — some things really are narrative — but it is counted separately
// and labelled in the report, so nobody mistakes prose for proof.
//
// # Honest limits
//
// The manifest is not signed. It catches corruption and piecemeal editing: a
// changed byte anywhere makes the hashes disagree with the report. It does not
// stop somebody from regenerating the entire bundle, and pretending otherwise
// would be worse than saying so. Signing the manifest, or timestamping it with
// a third party, is a deployment decision layered on top of this format — the
// manifest is deliberately a plain sha256sum file so any such tool can consume
// it.
//
// The capture itself is the other limit worth stating: a bundle can only prove
// what was on the wire. It cannot prove the device was in the state the
// procedure required when the packets were sent. That is what the run metadata,
// the operator note and the DUT identity fields are for, and they are
// attestations, not evidence.
package bundle
