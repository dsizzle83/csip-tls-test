package suitecsip

// localext.go — the LOCAL EXTENSION family: rows this bench measures because the
// behaviour matters, and for which NO PUBLISHED PROCEDURE EXISTS.
//
// # What a row here is, and is not
//
// It is supplementary PRODUCT EVIDENCE. It runs in the ordinary campaign, its
// evidence lands in the bundle, and `certify -verify` re-derives its citations
// from the capture exactly as it does for any conformance row — a row nobody
// certifies is still a row whose citations must hold up.
//
// It is NOT a conformance result. Its Test Values are the harness's own, no
// document prescribes its procedure, and the catalog marks it
// `certifiable: false` so its verdict is excluded from every applicable-FAIL
// tally and from the zero-FAIL exit criterion. A FAIL here is a finding about
// the product; it is not a certification failure, and it cannot turn a clean
// campaign red.
//
// # Why a family and not a catalog entry under CSIP-CONF-v1.3
//
// Because filing it there would be a fabricated conformance claim. The runner
// refuses a registration whose uid the catalog lacks — correctly: "a
// registration for a uid the catalog does not contain means the suite and the
// specification have diverged". The way past that refusal is to make the family
// REAL, with its own document key, its own posture stated in its own catalog
// record, and a machine-readable marker the tallies honour. Inventing a
// BASIC-016 to get the same row to run would have put a procedure into a
// conformance bundle that no published document asks for.
//
// The precedent is report.NoCertificationBasis — coverage without a conformance
// claim, already carried by this campaign for the v0.8 TEST-status Secure
// SunSpec Modbus specification. This family carries the same posture one layer
// deeper, down to the run's own exit criteria, which NoCertificationBasis never
// reached.

import (
	"csip-tls-test/internal/certify"
	"lexa-proto/sunspec"
)

// registerLocalExtensions binds the local-extension rows.
func registerLocalExtensions(reg *certify.Registry, nonce string) {
	reg.Register(extUID("EXT-001"), Suite, basicInverterControl(
		curveMode("opModWattVar", wattVarBinding()), "a Watt-Var curve", nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(62))
	// EXT-002/EXT-003 (REV0907-B1, localext_eventstatus.go): no published
	// CSIP-CONF-v1.3 procedure exercises a RESERVED currentStatus value or
	// currentStatus=3 (Cancelled with Randomization) — CORE-022 only ever
	// drove plain Cancelled(2) — so this is where the defect's negative
	// check and its positive companion live. Ordered right after EXT-001
	// and before the event-precedence scenarios (order 80+), matching
	// EXT-001's own placement in the run sequence.
	reg.Register(extUID("EXT-002"), Suite, reservedCurrentStatus002(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(63))
	reg.Register(extUID("EXT-003"), Suite, cancelWithRandomization003(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(64))
	// EXT-004 (REV0907-B2, localext_eventstatus.go): no published
	// CSIP-CONF-v1.3 procedure exercises an event already past its own
	// Specified End Time at first sighting either — the exact gap the
	// product fix (lexa-gw a943a56) closes. Ordered right after EXT-003.
	reg.Register(extUID("EXT-004"), Suite, expiredAtReceipt004(nonce),
		certify.WithRequires(needGridSim...), certify.WithOrder(65))
}

// mappingWattVar is where the opModWattVar → model 712 correspondence comes
// from, so a FAIL naming that model can be argued with.
const mappingWattVar = "IEEE 2030.5's opModWattVar is the Q(P) function, whose SunSpec/IEEE-1547 carriage " +
	"is model 712 (DER Watt-Var) — the correspondence this product's southbound reconciler uses, and the " +
	"one BASIC-015 proves NEGATIVELY by requiring that opModWattPF never reach it"

// noLegacyWattVarRegister records why this row has no legacy arm. The 12x curve
// family defines no Q(P) bank at all: 126 is Q(V), 131 is PF(P), 132 is P(V),
// 134 is P(f). A binding that named one of them would be repeating exactly the
// substitution BASIC-015 exists to refuse.
const noLegacyWattVarRegister = "the legacy 12x curve family defines no Q(P) bank — 126 is Q(V), 131 is " +
	"PF(P), 132 is P(V), 134 is P(f) — so on a legacy DER this axis has no register home to be measured in"

// wattVarNoPrescribedCurve is this row's Prescribed text, and it says the quiet
// part out loud: the breakpoints are the harness's, not a Figure's.
//
// basic015NoPrescribedCurve is the precedent for stating it plainly rather than
// implying provenance the row does not have.
const wattVarNoPrescribedCurve = "no figure in CSIP-CONF-v1.3 prescribes an opModWattVar curve — the axis " +
	"has no published procedure at all, which is why this row is a LOCAL EXTENSION and not a conformance " +
	"case. These breakpoints are this harness's own, chosen to be distinguishable from the device's seeded " +
	"default so that an adopt cannot be confused with a no-op"

// wattVarBinding is the curve this row publishes and measures.
//
// No OpenLoopTms: model 712 declares NO RspTms register (its Crv group is
// exactly {ActPt, DeptRef, Pri, ReadOnly} in the vendored model_712.json), which
// is why openLoopHome(712) is empty and the oracle asserts no timing for it.
// Authoring one would put an element on the wire this referee could say nothing
// about southbound — see TestWattVar_712HasNoOpenLoopTimingHome, which pins the
// model fact against the compiled layout rather than against this comment.
func wattVarBinding() *curveBinding {
	return &curveBinding{
		Mode: "watt_var",
		// Q(P): as active power rises, absorb increasing reactive power.
		Points:               []CurvePoint{{X: 0, Y: 0}, {X: 5000, Y: 0}, {X: 10000, Y: -3000}},
		XMult:                -2,
		YMult:                -2,
		YRefType:             derUnitRefStatVarAvail,
		Model7xx:             sunspec.ModelDERWattVar,
		Mapping7xx:           mappingWattVar,
		NoRegisterHomeLegacy: noLegacyWattVarRegister,
		Prescribed:           wattVarNoPrescribedCurve,
	}
}

// localExtensionIDs are the in-document ids this family registers, for the tests
// that assert the family's posture holds for every one of them rather than for
// the one that happened to be written first.
func localExtensionIDs() []string { return []string{"EXT-001", "EXT-002", "EXT-003", "EXT-004"} }

// NOTE ON WHERE THE EXCLUSION LIVES. Nothing in this file special-cases itself
// at run time. The rows register, run and are graded exactly like any other; the
// exclusion from certification tallies is carried by the CATALOG record
// (certifiable=false) and read through Case.BearsOnClaim, so a row cannot opt
// ITSELF out of a claim it was registered under — and a reader of the bundle
// sees the posture in the case's own record rather than having to find it in
// code.
