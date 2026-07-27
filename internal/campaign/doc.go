// Package campaign is the continuous adversary: it selects fault layers on a
// seed, applies them CONCURRENTLY on a recorded schedule, monitors every
// invariant throughout, and — when something breaks — shrinks the fault set
// down to the minimum that still reproduces it.
//
// See lexa-gw docs/ADVERSARIAL_QA_STRATEGY.md §4. That section lists five
// requirements, and this package exists because each of them is a structural
// property that cannot be bolted onto a scenario runner afterwards:
//
//  1. A RUN THAT INJECTED NO FAULT IS AN ERROR. Not a pass with a caveat — an
//     error. [Result.OK] is false and [Result.Why] says so. The check is
//     inherited from [invariant.Monitor.Finalize] rather than re-implemented,
//     so there is exactly one place that can decide a campaign passed.
//
//  2. THE FAULT MANIFEST IS PRINTED WITH THE VERDICT. Always, not only on
//     failure. A green campaign whose manifest reads "faults=NONE" is the
//     FI-01 defect wearing a green badge, and printing the manifest is what
//     makes that visible to a human who is not reading the JSON.
//
//  3. EVERY VERDICT CITES EVIDENCE. The run emits an evidence bundle in the
//     same format internal/certify produces, so bundle.Verify can check it and
//     a reader six months later can re-derive the finding.
//
//  4. SHRINK ON FAILURE. See shrink.go. A forty-fault run that trips I1 is
//     nearly useless as a bug report; the same violation attributed to two
//     faults is a ticket someone can act on.
//
//  5. DETERMINISTIC REPLAY. The seed picks the actions, their order, their
//     parameters and their timing. [Schedule] is written into the bundle, and
//     re-running with the same seed and the same layer set reproduces it.
//
// # Actions, not "faults"
//
// The schedulable unit here is an [Action], and it deliberately covers two
// things a chaos runner usually keeps apart: a FAULT (armed for an interval,
// recorded in the [invariant.FaultManifest]) and a PROBE (a one-shot attack
// recorded in the [invariant.Ledger] — an unauthorized write, a cross-domain
// credential presentation).
//
// Unifying them is not tidiness. I3, I4 and I5 are invariants ABOUT attempts:
// "a refused write leaves no ghost", "an unauthorized credential causes no
// write", "a certificate from one domain never authenticates in another". None
// of those can be evaluated unless the adversary attempted something, and the
// ledger is where the attempt is recorded. If probes were a fixed preamble
// rather than schedulable actions, the shrinker could never report "the minimal
// reproducer is one probe and no faults at all" — which, for an authorization
// bug, is precisely the right answer.
//
// # The engine does not know what a fault IS
//
// Nothing in the runner or the shrinker knows what a "lying DER" or a "session
// flood" is. A [Layer] plans [Action]s; the engine schedules, arms, clears and
// re-runs them. That split is what lets a live-bench campaign and a hermetic
// in-process one share every line of scheduling, monitoring, shrinking and
// reporting code, which in turn is what makes the hermetic run credible
// evidence that the live one works.
//
// # Referee independence
//
// Per PN-1/C9 and AD-003(f): the layers here drive the DUT through
// internal/aggregator (which rides the bench's own internal/mbtls), read DERs
// through their own sidecars, and read the head-end through gridsim's admin
// API. Nothing imports the product's parsers, TLS stack or state machine. The
// judging is done entirely by internal/invariant, which has the same rule.
//
// # Layout
//
//	action.go    Action, Layer, the target inventory a layer plans against
//	schedule.go  seeded selection and timing; the replayable run record
//	runner.go    the run loop: arm, monitor, clear, finalize
//	shrink.go    ddmin over the action set, keyed on the violation signature
//	report.go    console rendering and evidence-bundle emission
//	layers.go    the concrete layers (peer lie, comm loss, authz probe,
//	             transport abuse, head-end malform, clock warp)
package campaign
