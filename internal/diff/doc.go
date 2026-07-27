// Package diff is the differential-testing layer of the adversarial QA suite:
// two independently-written implementations are shown the SAME input, and any
// disagreement between them is a finding.
//
// # Why differential, and why here
//
// Every other layer of this suite needs somebody to state the expected answer.
// A conformance case cites a clause; an invariant states a safety property; a
// fuzz oracle states a bound. All three are limited by what the person writing
// them thought to state. A differential test needs none of that: it needs only
// two implementations and the claim that they are talking about the same thing.
// When they disagree, at least one of them is wrong, and that is true whether or
// not anybody wrote the answer down first.
//
// docs/ADVERSARIAL_QA_STRATEGY.md §5 names this as a genuine opportunity the
// project was not exploiting. The gateway implements a SunSpec Modbus client
// AND a SunSpec Modbus server; this bench implements independent versions of
// both; the CSIP control semantics are implemented once in the product and once,
// separately, here. Cross-running them turns a disagreement into a finding
// without anyone having to specify the expected answer.
//
// # The rule that makes it mean anything
//
// A differential test between two implementations that SHARE the code under
// question proves nothing — both sides commit the same error and agree
// perfectly. Referee independence (docs/refactor/02_ARCHITECTURE_DECISIONS.md
// AD-003(f), architecture review §9 "self-confirmation") is therefore not a
// stylistic preference here; it is the precondition for the whole layer.
//
// So every family in this package states its lineage explicitly, as a [Side]
// pair, and the report prints it:
//
//	product side   lexa-proto — the code that actually ships in the DUT
//	referee side   csip-tls-test — written here, from the standards, never
//	               synced with the product and never bug-for-bug matched
//
// And, just as importantly, every family states WHAT IT CANNOT CATCH, because
// the honest boundary of a differential is the surface the two sides share:
//
//   - The SunSpec register LAYOUT TABLES (lexa-proto/sunspec.L701/L702/L704)
//     are shared wire definitions, in the same category as MBAP framing. A
//     differential over them is blind to a field-order or field-list error
//     that both sides inherit. [regview.go]'s referee therefore transcribes the
//     offsets ITSELF, from the field ordering, with its own arithmetic and its
//     own type decisions, so at least offset drift, signedness and
//     scale-factor association are independently derived.
//
//   - The 704 MODE ENUM VALUES (M704_VarSetMod_*, M704_WSetMod_*) are likewise
//     shared constants. If the product's transcription of the SunSpec model
//     definition is off, this bench's referee reads the same wrong number and
//     agrees. That is un-adjudicable without the model definition, which this
//     repo does not have a copy of, and [Family] "ctl" reports it as an explicit
//     WARN rather than pretending the agreement is evidence. See
//     [ReportedLimitations].
//
//   - The CSIP wire TYPES (lexa-proto/csipmodel.DERControlBase and friends) are
//     shared for the same reason. The referee reads the document as the shared
//     type presents it and differs only on SEMANTICS — what the fields mean,
//     which register they belong in, and what happens when several of them
//     arrive at once. That is where the defects in this class actually live.
//
// # The four families
//
//	ctl    CSIP DERControlBase -> SunSpec 704 registers.
//	       Under test: lexa-proto/derbase.Base.ApplyControl, driven over a real
//	       Modbus transport into a real register bank.
//	       Referee: [Intents], this package's own reading of IEEE 2030.5 §10.10
//	       and the CSIP profile, resolved into the DER's own physical units
//	       through internal/invariant's unit algebra.
//	       Oracle: the physical setpoint the device ends up holding equals the
//	       physical setpoint the document asked for, in the DER's own units.
//
//	sf     Scale-factor magnitude preservation.
//	       Under test: sunspec.RawFromScaleSigned/Uint and View.SetFloat/Float.
//	       Referee: [refEncode]/[refDecode], decimal-string arithmetic that
//	       shares no line of code with the product path.
//	       Oracle: MAGNITUDE is preserved to within half a least-significant
//	       unit, or the encoder saturated and SAYS it saturated. Deliberately
//	       NOT round-trip identity: audit BR-02 found the existing
//	       scale-factor cross-check tautological precisely because it derived
//	       its tolerance from the value under test, and a round-trip through a
//	       consistently-wrong codec round-trips perfectly.
//
//	chain  SunSpec model-chain walking.
//	       Under test: sunspec.Scan / ScanAt.
//	       Referee: [walk], an independent walker with its own bounds
//	       reasoning.
//	       Oracle: both walkers return the same block list, or both refuse.
//	       Fed deliberately hostile register spaces — no end marker, a length
//	       that runs past the map, a zero-length model, a list that wraps the
//	       address space.
//
//	reg    Register interpretation for the points that carry setpoints.
//	       Under test: sunspec.Layout.View's decode.
//	       Referee: [refPoints], an independently transcribed offset/type/SF
//	       table for 701/702/704.
//	       Oracle: same engineering value from the same registers.
//
// # Verdicts and the floor
//
// This package speaks internal/invariant's verdict vocabulary — PASS, FAIL,
// SKIP, WARN — so a differential finding and an invariant violation can sit in
// one report without a translation layer, and so the same discipline applies:
// a SKIP must name what it could not observe, and [Report.Summary] applies an
// assertion floor. A family that compared nothing does not get to report PASS;
// it reports SKIP with the count that was zero. That is the same honesty fix
// Wave 1 applied to gw-mayhem, and it is easier to keep than to retrofit.
//
// # Where this layer hands off
//
// This package creates conditions; it does not own safety verdicts. Where a
// disagreement means the device is holding a setpoint beyond its own nameplate,
// [Case.Invariant] carries the ID of the invariant that judged it and
// [BuildWorld] hands the resulting register state to internal/invariant so I1 —
// not this package — returns the FAIL. The differential's own verdict stays a
// statement about the two implementations; the safety claim belongs to the
// invariant that was written to make it.
package diff
