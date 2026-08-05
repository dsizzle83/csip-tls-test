package suitemodbusserver

// profile1547.go carries the normative content of the SunSpec Modbus IEEE
// 1547-2018 Profile Specification and Implementation Guide that the 1547 test
// procedures delegate to.
//
// This delegation is the single most important fact about MOD-4. The
// SunSpec Modbus for IEEE 1547 Test Procedures PDF says, in §2.3.1, "compare
// the point to the list of mandatory points for IEEE 1547 implementation" and
// then does not print the list, the model ids, the register offsets, the
// function codes or a pass threshold anywhere in the document. A harness that
// executed MOD-4 from that PDF alone would be executing nothing. The list below
// is therefore an EXTERNAL input to the procedure, transcribed from the profile
// specification's normative Section 3 tables (Tables 16-30) via the harness
// fact sheet, and it is recorded in the evidence bundle as such: every MOD-4
// assertion names this file as the source of the requirement it is testing, so
// a reviewer can check the transcription rather than take it on trust.
//
// Two scoping facts from the profile that a reader will otherwise mis-apply:
//
//   - The profile's scope is models 1 and 701-713. Model 714 (DERMeasureDC) is
//     NOT part of it, so a DUT that serves 714 is neither helped nor hurt by
//     MOD-4.
//   - Model 713 is conditionally optional: "if the implementation does not
//     support storage, the DERStorageCapacity model and the SoC point are
//     optional", with the rider that an implementation that DOES expose 713
//     without storage must report SoC = 0.
//
// One qualifier from the profile that a naive presence sweep would fail a
// conformant DUT on: for model 701 the profile says "the voltage points that
// are applicable must be implemented". A single-phase DUT legitimately does not
// implement VL2, VL3, VL2L3 or VL3L1, so those four points are marked
// phase-conditional here and are judged against the DUT's own ACType rather
// than required unconditionally.

import "sort"

// ProfileModels is the set of SunSpec models the IEEE 1547-2018 profile
// requires, in ascending order. 713 is present but flagged conditional by
// ProfileModelConditional.
var ProfileModels = []uint16{1, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713}

// ProfileModelConditional names the models the profile allows an implementation
// to omit, with the condition under which the omission is legitimate.
var ProfileModelConditional = map[uint16]string{
	713: "conditionally optional: the profile makes DERStorageCapacity and its SoC point optional " +
		"for an implementation that does not support storage",
}

// requiredPoints is the profile's Section 3 required-point list per model. Only
// the models this suite can meet on the wire with a transcribed layout are
// listed; the curve models 705-712 are required as MODELS (ProfileModels) but
// their point lists are not transcribed here because this suite cannot compute
// their runtime offsets — a DUT that served one would get an explicit SKIP for
// its point sweep, not a silent pass.
var requiredPoints = map[uint16][]string{
	// Table 16. Note Opt is NOT required by this profile even though the
	// Common Model defines it.
	1: {"ID", "L", "Mn", "Md", "SN", "Vr"},

	// Table 17. The six voltage points are subject to the applicability
	// qualifier; see phaseConditional.
	701: {
		"ID", "L", "W", "Var", "LLV", "LNV",
		"VL1L2", "VL1", "VL2L3", "VL2", "VL3L1", "VL3",
		"Hz", "St", "ConnSt", "Alrm",
	},

	// Table 18 (required). Table 19's optional set is not asserted.
	702: {
		"ID", "L", "WMaxRtg", "WOvrExtRtg", "WOvrExtRtgPF", "WUndExtRtg", "WUndExtRtgPF",
		"VAMaxRtg", "NorOpCatRtg", "AbnOpCatRtg", "VarMaxInjRtg", "VarMaxAbsRtg",
		"WChaRteMaxRtg", "VAChaRteMaxRtg", "VNomRtg", "VMaxRtg", "VMinRtg",
		"CtrlModes", "ReactSusceptRtg",
	},

	// Table 20 (required). ESRndTms is Table 21, optional.
	703: {"ID", "L", "ES", "ESVHi", "ESVLo", "ESHzHi", "ESHzLo", "ESDlyTms", "ESRmpTms", "V_SF", "Hz_SF"},

	// Table 22. The profile prints "VarSetPct _SF" and "WMaxLimPct _SF" with a
	// stray space; the real point names have none.
	704: {
		"ID", "L",
		"PFWInjEna", "PF_SF", "PFWInj.PF", "PFWInj.Ext",
		"VarSetEna", "VarSetMod", "VarSetPri", "VarSetPct", "VarSetPct_SF",
		"WMaxLimPctEna", "WMaxLimPct", "WMaxLimPct_SF",
	},

	// Table 30.
	713: {"ID", "L", "SoC"},
}

// phaseConditional lists, per model, the points whose absence is legitimate for
// a DUT of a given AC topology. The key is the point name; the value is the set
// of ACType enum values for which the point IS required.
//
// ACType (701): SINGLE_PHASE = 0, SPLIT_PHASE = 1, THREE_PHASE = 2.
var phaseConditional = map[string]map[uint16]bool{
	"VL1L2": {1: true, 2: true},
	"VL2":   {1: true, 2: true},
	"VL2L3": {2: true},
	"VL3":   {2: true},
	"VL3L1": {2: true},
}

// storageConditional names the model 702 points that rate a CHARGE axis, which
// a DER with no storage behind it does not have.
//
// ── THIS ENTRY IS AN INTERPRETATION, NOT A TRANSCRIPTION ────────────────────
//
// Everything else in this file is copied from the profile's Section 3 tables.
// This is not: Table 18 lists WChaRteMaxRtg and VAChaRteMaxRtg among model
// 702's required points with no qualifier printed beside them. The
// interpretation applied here is that the profile's OWN storage conditionality
// — "if the implementation does not support storage, the DERStorageCapacity
// model and the SoC point are optional", already transcribed into
// ProfileModelConditional above — governs the charge-RATE ratings for the same
// reason it governs model 713: they are ratings of an axis a non-storage DER
// does not possess. It is labelled here, and named in the excuse text every
// excused assertion carries, so a reviewer reads an interpretation rather than
// mistaking it for the document. It is the same move phaseConditional makes
// one qualifier over, and for the same purpose: a naive presence sweep must
// not fail a conformant DUT.
//
// ── WHY IT IS NEEDED NOW ────────────────────────────────────────────────────
//
// It changes no verdict that was previously correct; it prevents one that
// would newly be wrong. Until harness commit 07178d1 the bench's advanced
// solar sim left WChaRteMaxRtg/WDisChaRteMaxRtg at the Go ZERO value, and a
// Tuint16 zero is IMPLEMENTED data — so MOD-4.702 read "all 19 required points
// implemented" and PASSed (run tail-fullsuite-20260801T173831). That pass was
// manufactured: an implemented rated charge maximum of 0 W is the device
// positively declaring it cannot charge at all, which under lexa-proto
// derbase's maxRatingBound denies every nonzero active-power setpoint outright.
// 07178d1 replaced the zeros with the SunSpec not-implemented sentinel, the
// honest encoding of "this profile models a PV inverter with no battery behind
// it" — and the gateway mirrors it faithfully (lexa-gw's admission readRatings
// OMITS a not-implemented point rather than zero-filling it, so the northbound
// 702 serves 0xFFFF too). Without this qualifier the next campaign turns that
// honest declaration into a DUT conformance FAILURE.
//
// ── WHAT SWITCHES IT OFF ────────────────────────────────────────────────────
//
// The DUT serving model 713. That is the profile's own marker for "this
// implementation supports storage", and it is read from the same discovery
// walk MOD-4 already performs, so nothing is assumed: a DUT that declares
// storage is held to the charge ratings in full. The bench's battery packs
// (`batsim -pack …`) serve 713 and declare real, symmetric
// WChaRteMaxRtg/WDisChaRteMaxRtg strictly below nameplate — which is exactly
// the behaviour this qualifier stops excusing the moment one is admitted.
// Their APPARENT-power rate ratings are still the sentinel, so a pack on the
// bench will produce a VAChaRteMaxRtg finding: see the pre-flight note.
var storageConditional = map[string]bool{
	"WChaRteMaxRtg":  true,
	"VAChaRteMaxRtg": true,
}

// storageModel is the profile model whose presence declares storage support.
const storageModel uint16 = 713

// requiredScaleFactors is the profile's Section 3 per-model `_SF` requirement
// (fact sheet §2.8). Models 1, 701, 702 and 713 list none of their own: their
// scale factors are inherited from the base model definition and are therefore
// checked for VALIDITY by the 2.4 sweep, not for PRESENCE by MOD-4.
var requiredScaleFactors = map[uint16][]string{
	703: {"V_SF", "Hz_SF"},
	704: {"PF_SF", "VarSetPct_SF", "WMaxLimPct_SF"},
	705: {"V_SF", "DeptRef_SF", "RspTms_SF"},
	706: {"V_SF", "DeptRef_SF", "RspTms_SF"},
	707: {"V_SF", "Tms_SF"},
	708: {"V_SF", "Tms_SF"},
	709: {"Hz_SF", "Tms_SF"},
	710: {"Hz_SF", "Tms_SF"},
	711: {"Db_SF", "K_SF", "RspTms_SF"},
	712: {"W_SF", "DeptRef_SF"},
}

// pointRequired reports whether the profile requires the named point of the
// model, given the DUT's own ACType (which only matters for model 701) and
// whether the DUT declares storage by serving model 713 (which only matters
// for model 702's charge-rate ratings). The second result carries the
// applicability qualifier when the point is excused.
func pointRequired(model uint16, name string, acType uint16, acTypeKnown, servesStorage bool) (bool, string) {
	req, ok := requiredPoints[model]
	if !ok {
		return false, ""
	}
	found := false
	for _, p := range req {
		if p == name {
			found = true
			break
		}
	}
	if !found {
		return false, ""
	}
	if model == 702 && storageConditional[name] && !servesStorage {
		return false, "INTERPRETATION (profile1547.go's storageConditional, NOT a qualifier printed in " +
			"Table 18): this point rates a charge axis, and the DUT serves no model 713 — the profile's " +
			"own marker for storage support, which it already makes conditional on exactly that. A DER " +
			"with no storage behind it has no charge-rate rating to declare, and the not-implemented " +
			"sentinel is the honest encoding of that; a zero here would be the device positively " +
			"declaring a rated charge maximum of 0 W"
	}
	if model != 701 {
		return true, ""
	}
	applies, conditional := phaseConditional[name]
	if !conditional {
		return true, ""
	}
	if !acTypeKnown {
		return true, ""
	}
	if applies[acType] {
		return true, ""
	}
	return false, "the profile requires only the voltage points that are applicable; " +
		"the DUT reports ACType=" + acTypeName(acType)
}

func acTypeName(v uint16) string {
	switch v {
	case 0:
		return "0 (SINGLE_PHASE)"
	case 1:
		return "1 (SPLIT_PHASE)"
	case 2:
		return "2 (THREE_PHASE)"
	default:
		return "unrecognised"
	}
}

// missingModels returns the profile-required models absent from the DUT's
// chain, split into unconditionally required and conditionally optional.
func missingModels(present map[uint16]bool, required []uint16) (hard, conditional []uint16) {
	for _, id := range required {
		if present[id] {
			continue
		}
		if _, ok := ProfileModelConditional[id]; ok {
			conditional = append(conditional, id)
			continue
		}
		hard = append(hard, id)
	}
	sort.Slice(hard, func(i, j int) bool { return hard[i] < hard[j] })
	sort.Slice(conditional, func(i, j int) bool { return conditional[i] < conditional[j] })
	return hard, conditional
}
