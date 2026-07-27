// Package invariant is the spine of the adversarial QA suite: the ten safety
// properties I1–I10 that must hold NO MATTER WHAT the adversary does, encoded
// as predicates over externally-observable state, plus the Monitor that checks
// them continuously while faults are being applied.
//
// See docs/ADVERSARIAL_QA_STRATEGY.md §2 (lexa-gw) for the strategy this
// implements. The short version: a test case enumerates what someone thought to
// check; an invariant says what must be true regardless, and can therefore be
// evaluated on a cadence while a chaos runner does arbitrary things. An
// invariant violation is always a P1 finding, and that is the point — it
// removes the argument about whether a given behaviour "counts".
//
// # The three rules this package exists to enforce
//
// **Scenarios create conditions; invariants decide pass/fail.** Nothing in here
// drives the DUT. An Invariant is handed a [World] — a read-only view of what
// the bench can observe — and returns a verdict. A campaign that arms a fault
// and then declares its own success is exactly the failure mode FI-01/FI-05
// recorded against gw-mayhem; the split here makes that structurally
// impossible for the invariant half.
//
// **No white-box access, ever.** A checker that reaches into the product's
// internals — a Prometheus gauge on a loopback port, a file under /var/lib, a
// package-level test seam — cannot run against a fielded device, and an
// invariant that cannot run in the field is documentation, not machinery. So
// [World] is built entirely from things a third party standing on the network
// could see: the DUT's northbound SunSpec register map read over mbaps, each
// downstream DER's own register image read from the DER (not from the DUT's
// report of it), the utility head-end's own record of what the DUT said to it,
// and the packet capture. The single exception is [HostView], which is
// host-level resource accounting (disk, sockets, file sizes) fetched over a
// read-only SSH allowlist; every invariant that uses it SKIPs with a reason
// when it is absent, so the same invariant still runs against a device nobody
// has a shell on.
//
// **A partial invariant, honestly labelled, beats a fake complete one.** Several
// of I1–I10 cannot be fully decided from outside a running device today. Each
// such invariant implements the strongest checkable approximation and says so
// in its [Invariant.Statement] — in the statement itself, not in a comment
// somewhere, because the statement is what gets printed next to the verdict and
// pasted into the report.
//
// # Referee independence
//
// Per PN-1/C9 and AD-003(f), nothing here is built from the product's parsers,
// TLS stack, or state machine. Register decoding goes through the bench's own
// use of the shared lexa-proto wire definitions; the DUT is reached through
// internal/aggregator (which rides internal/mbtls); the head-end is observed
// through sim/gridsim's admin API; DERs are read over plain Modbus or their own
// simapi sidecar. The 2030.5 report bodies the DUT PUTs are parsed by this
// package's own small XML reader (see i7.go) rather than by any product model,
// for the same reason internal/csipref exists.
//
// # Units are load-bearing
//
// I1's grounding defect (BR-01) is an absolute var count written into a
// percent-of-rated field. A comparison that has forgotten what unit its
// operands are in cannot see that bug — it is the bug. So this package carries
// an explicit unit algebra ([Quantity], [Pct], [RefBase], [Nameplate]) and I1
// resolves every commanded point into the DER's own physical units, using the
// reference base the device itself declares in its mode enum, before comparing
// it to the device's own nameplate. See units.go.
//
// # Layout
//
//	invariant.go  the Invariant interface, Verdict, Fact, Violation, the registry
//	world.go      World and the observable views; the source interfaces
//	sources.go    the concrete sources (mbaps northbound, Modbus DER, simapi,
//	              gridsim admin, read-only SSH host)
//	fault.go      the fault manifest a violation is recorded against
//	ledger.go     what the adversary attempted and how the DUT answered
//	units.go      the unit algebra and the 701/702/704 decoders
//	i1.go … i10.go  one file per invariant, each carrying its grounding defect
//	monitor.go    the cadence runner, violation record, and bundle emission
package invariant
