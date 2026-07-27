// Package certify is the framework every conformance suite in this bench plugs
// into: it turns the extracted test-case catalog into a run plan, executes the
// suites' checks against a live capture, attributes captured frames to the check
// that produced them, and emits an evidence bundle a third party can verify
// without trusting us.
//
// # The dishonesty this package exists to prevent
//
// A conformance tool's only asset is that its output is believed. There are
// exactly three ways such a tool lies, and each one has a mechanism here whose
// sole job is to make it impossible:
//
//  1. It claims a PASS it never asserted. Every check returns
//     [bundle.Assertion] values, and an assertion carries a citation — frame
//     numbers, a stream byte range, and a sha256 of the bytes — that
//     bundle.Verify re-derives from the pcap. A run whose PASS carries no
//     re-checkable citation is downgraded to WARN with the reason printed
//     (see [Options.RequireCitation]), unless the check explicitly declares the
//     criterion off-wire ([Result.OffWire]).
//
//  2. It quietly drops a test case. The catalog is the specification, and
//     [Registry.Coverage] reports, per document, exactly which uids have an
//     implementation and which do not. The runner emits a record for every
//     SELECTED case, implemented or not, and the summary refuses to print
//     "ALL TEST CASES ADDRESSED" while an applicable case has no
//     implementation. Silence is never a pass.
//
//  3. It cites the wrong frames. This bench has continuous background traffic —
//     10-second southbound Modbus polls, a CSIP client walking the server — on
//     the same wire as the test. Attributing frames by time alone would let a
//     TLS test case cite a Modbus poll that merely happened to be in flight.
//     [Window] therefore attributes on BOTH signals: a frame belongs to a check
//     only if it falls inside the check's interval AND matches one of the
//     connections the check itself opened. A frame two windows both claim is
//     recorded as contested and given to neither. [Evidence.CiteFrames] and
//     [Evidence.CiteBytes] refuse to build an assertion citing a frame outside
//     the check's own attributed set, so the rule is enforced at the only place
//     that matters — where the citation is minted.
//
// # The two phases of a check
//
// A check runs while the capture is live, so it cannot cite frame numbers: the
// capture file is still being written and the frames it caused do not have
// indices yet. So execution is two-phase.
//
// Phase 1 — live. The [Check] runs. It dials the DUT, drives the sims, reads
// the admin APIs, and returns a [Result] holding whatever it can already say.
// Crucially it registers the connections it opened on its [Window]
// (RunCtx.ClaimConn), which is what makes phase 2 possible.
//
// Phase 2 — citation. Once the run's single capture is stopped and read back,
// the runner builds a [FrameIndex], attributes each window, and calls the
// optional [Result.Cite] callback with an [Evidence] scoped to that check's
// frames. This is where wire-cited assertions are minted.
//
// A check that needs no wire evidence simply leaves Cite nil.
//
// # Why one capture for the whole run
//
// Starting and stopping a capture per test case would drop the frames in the
// start-up race (see internal/evidence/capture's package doc), produce N files
// a reviewer has to correlate by hand, and make "the session was not resumed
// after the fatal alert" — a claim about the ABSENCE of frames between two test
// cases — unprovable. One capture, one file in the bundle, per-case frame
// windows recorded inside it.
//
// # Layout
//
//	catalog.go   the extracted test-case catalog as typed data + filters
//	registry.go  suites bind Checks to catalog uids; coverage reporting
//	runctx.go    what a check is handed: targets, PKI, clients, its window
//	clients.go   gridsim admin, simapi, and READ-ONLY gateway introspection
//	window.go    frame attribution: time AND flow, contested frames dropped
//	evidence.go  post-capture frame index and the scoped citation constructors
//	runner.go    selection, capture, execution, panic containment, bundle
//	report.go    console output in the house style + the markdown section
//
// # Independence
//
// Nothing here imports lexa-platform or the product. The bench is the referee
// (PN-1 / C9 / AD-003(f)); this package deliberately knows nothing about how the
// gateway implements anything, only what the published procedures say must be
// observable on the wire.
package certify
