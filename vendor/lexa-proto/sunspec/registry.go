package sunspec

// ── The recognized-model registry ────────────────────────────────────────────
//
// A SunSpec model chain is self-describing by LENGTH, not by content: every
// block carries [ID, L] and a walker steps to the next block by L whether or
// not it has any idea what the ID means (scanner.go's scanModels). That is what
// makes a chain walkable past a model the walker has never heard of — and it is
// also what makes "which of these did I actually RECOGNIZE?" a question with a
// non-trivial answer, because the walk itself answers a different one.
//
// This registry is that answer for this package: the model ids it holds a
// DEFINITION for. It exists because a consumer that reports its "discovered
// models" has to say what discovery means, and "every [ID, L] pair I stepped
// over" is the wrong meaning — SS-MODBUS-CLIENT-CONF-v1.1 §2.9.3 (ERR-3), the
// document's only MUST, requires that "the list of discovered models MUST not
// include the model with the unknown ID". Stepping over an unrecognized block
// correctly is REQUIRED; reporting it as something you discovered is FORBIDDEN.
// The two are different acts and this file is what lets a caller do the first
// without doing the second (see PartitionChain).
//
// WHAT COUNTS AS RECOGNIZED, AND WHY THE BAR IS NOT "HAS A *Layout".
// Three kinds of definition live in this package and all three are recognition:
//
//	SPEC-BACKED    the model has a vendored SunSpec Alliance model definition in
//	               docs/schema/sunspec-models/model_<id>.json AND a Layout or
//	               offset table proven against it, point for point, by
//	               TestLayoutsMatchVendoredSpec / the per-model offset tests.
//	               This is 32 of the 36 ids below and the only tier that grows
//	               without a decision: dropping a model_*.json into the schema
//	               directory and forgetting to register it here FAILS
//	               TestKnownModelsCoversEveryVendoredDefinition.
//	OFFSET-BACKED  the model has a hand-verified register offset table in
//	               models.go but no vendored JSON yet (the meters). A
//	               definition with a weaker proof is still a definition: the
//	               package can decode the block.
//	NAMED          the model has no register map here at all, and the product
//	               nonetheless acts on its PRESENCE. Exactly one id is in this
//	               tier — 801, the battery base model, which lexa-gw's
//	               commissioning sweep reads as "this is a battery".
//
// THE NAMED TIER IS THE DELIBERATE PART, so it is stated rather than buried.
// The temptation is to define recognition as "I can decode it", which would put
// 801 in the unknown list. That would be a FALSE DIAGNOSTIC in the dangerous
// direction: 801 is a registered SunSpec model, this tree names it, and a
// consumer reading "the gateway did not recognize model 801" would go looking
// for a firmware defect that is not there. ERR-3's subject is an UNREGISTERED
// id — a block nothing in the SunSpec registry claims — and the honest line to
// draw is around what this tree knows of, with the basis for each id recorded
// here so the set cannot quietly become "whatever anyone once typed".
//
// THIS IS A CLOSED SET, NOT A RANGE. There is no "7xx means known" rule and
// there must not be: 715 is unallocated today and would be as unknown to this
// package as 65000 is. Adding a model means adding its definition and its id,
// in the same change.
//
// Order is ascending and duplicate-free (pinned by
// TestKnownModelIDsIsAscendingAndUnique), which is what lets KnownModels return
// this slice's contents directly rather than sorting on every call.
var knownModelIDs = []uint16{
	// ── Common ──────────────────────────────────────────────────────────────
	ModelCommon, // 1 — identity.go's fixed offsets; every SunSpec device serves it

	// ── Legacy inverter measurement / nameplate / control ───────────────────
	ModelInverterSinglePh, // 101
	ModelInverterSplitPh,  // 102
	ModelInverterThreePh,  // 103 — models.go's M103_* table
	ModelNameplate,        // 120 — SPEC-BACKED: L120 (M120_* restated REV0907-D1), readNameplateW's legacy source
	ModelBasicSettings,    // 121 — SPEC-BACKED: L121 (M121_* proven against it), the mutable WMax setting
	ModelExtendedStatus,   // 122 — SPEC-BACKED: L122 (M122_* restated REV0907-D2), derbase liveness
	ModelImmediateCtrl,    // 123 — L123, the fail-safe cease chain

	// ── Legacy curve / advanced-function family (D4 served-as-itself) ───────
	ModelVoltVarLegacy,   // 126
	ModelFreqWattParam,   // 127
	ModelReactiveCurrent, // 128
	ModelLVRTLegacy,      // 129
	ModelHVRTLegacy,      // 130
	ModelWattPFLegacy,    // 131
	ModelVoltWattLegacy,  // 132
	ModelFreqWattLegacy,  // 134
	ModelMPPT,            // 160

	// ── AC meters ───────────────────────────────────────────────────────────
	// OFFSET-BACKED: models.go's shared M201_* table (105 data registers,
	// audit finding MTR-4), no vendored JSON yet.
	ModelMeterSinglePh, // 201
	ModelMeterSplitPh,  // 202
	ModelMeterThreePh,  // 203

	// ── IEEE 1547-2018 DER profile ──────────────────────────────────────────
	ModelDERMeasureAC,    // 701
	ModelDERCapacity,     // 702
	ModelDEREnterService, // 703
	ModelDERCtlAC,        // 704
	ModelDERVoltVar,      // 705
	ModelDERVoltWatt,     // 706
	ModelDERTripLV,       // 707
	ModelDERTripHV,       // 708
	ModelDERTripLF,       // 709
	ModelDERTripHF,       // 710
	ModelDERFreqDroop,    // 711
	ModelDERWattVar,      // 712
	ModelDERStorageCap,   // 713
	ModelDERMeasureDC,    // 714

	// ── Battery ─────────────────────────────────────────────────────────────
	// NAMED: 801 carries no register map in this package — see the tier note
	// above for why it is registered anyway. 802 is SPEC-BACKED as of
	// REV0907-D3 (WP4-T4): L802 (M802_* restated), proven against
	// docs/schema/sunspec-models/model_802.json by TestLayoutsMatchVendoredSpec.
	ModelBatteryBase,    // 801
	ModelLithiumBattery, // 802
}

// knownModelSet indexes knownModelIDs for O(1) membership. Built once at
// package initialisation from the one authoritative list above, so the set and
// the ordered slice can never disagree.
var knownModelSet = func() map[uint16]struct{} {
	m := make(map[uint16]struct{}, len(knownModelIDs))
	for _, id := range knownModelIDs {
		m[id] = struct{}{}
	}
	return m
}()

// IsKnownModel reports whether this package holds a definition for model id —
// the predicate behind "did I recognize this block, or merely step over it?".
//
// EndMarker (0xFFFF) is NOT a known model and never can be: it terminates a
// chain rather than naming one, and scanModels stops at it rather than emitting
// it as a block. Neither is 0.
func IsKnownModel(id uint16) bool {
	_, ok := knownModelSet[id]
	return ok
}

// KnownModels returns every model id this package holds a definition for,
// ascending. The returned slice is a fresh copy: the registry is package state
// and a caller sorting or truncating it must not be able to corrupt it.
func KnownModels() []uint16 {
	out := make([]uint16, len(knownModelIDs))
	copy(out, knownModelIDs)
	return out
}

// PartitionChain splits a walked model chain into the ids this package
// RECOGNIZES and the ids it does not, each preserving the order the chain
// presented them in.
//
// This is the whole ERR-3 primitive. The walk hands back everything it stepped
// over; a consumer that reports a model inventory reports `known` and carries
// `unknown` somewhere else — the catalog's own note permits recording the
// unrecognized id elsewhere, and doing so is what keeps the step-over visible
// as evidence rather than silently dropping the fact that a block was there.
//
// ORDER IS PRESERVED, NOT SORTED. A SunSpec chain's order is its ADDRESS order:
// model n sits immediately after model n-1's body, so the sequence is a
// property of the device's register map and not an incidental ordering. Sorting
// it would discard that, and would make an inventory of a device whose chain
// gained a model indistinguishable from one whose chain was rebuilt.
//
// Both results are nil (never an empty non-nil slice) when they would be empty,
// matching the nil-means-absent convention this tree's wire types hold to: a
// chain with nothing unrecognized in it must serialize identically to one from
// a producer that never had the notion.
//
// A duplicate id is not de-duplicated. A chain that presents model 705 twice is
// a real (malformed) chain and this function reports what is there; deciding
// what to do about it belongs to whoever is looking at the device, not here.
func PartitionChain(chain []uint16) (known, unknown []uint16) {
	for _, id := range chain {
		if IsKnownModel(id) {
			known = append(known, id)
			continue
		}
		unknown = append(unknown, id)
	}
	return known, unknown
}
