// Package e2e holds the evidence engine's end-to-end proofs. It has no
// non-test code: its whole purpose is to run the pipeline the way a conformance
// run does — capture, read, dissect, reassemble, decrypt, bundle, verify — and
// assert that what comes out the far end is what went in.
//
// Each package below it is tested in isolation with hand-built fixtures, which
// is the only way to pin exact wire encodings. But hand-built fixtures share
// the author's assumptions with the code under test, and the assumptions are
// where the expensive mistakes live: a reader that agrees with a writer nobody
// else uses, a reassembler whose offsets only line up with the offsets its own
// tests computed. So these tests start dumpcap on the loopback interface,
// generate real TLS traffic with crypto/tls, and require that the whole chain
// recovers the exact bytes sent — with the frame numbers a reviewer would see
// in Wireshark.
//
// They skip, loudly and with a reason, where the environment cannot support
// them (no dumpcap, no capture permission). They do not pretend to pass.
package e2e
