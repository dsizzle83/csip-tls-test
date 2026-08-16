// Package sunspec — register layouts for the LEGACY (pre-IEEE-1547-2018) curve
// family: models 126, 127, 128, 129, 130, 131, 132, 134 and 160.
//
// These are a different idiom from the 7xx DER models in derlayout.go, and the
// difference is structural, not cosmetic:
//
//	                 7xx (705/706/707-712)          legacy 12x curve family
//	repeat shape     nested Crv[NCrv] × Pt[NPt]     flat curve[NCrv], one fixed
//	                                                block, points inlined as
//	                                                parallel arrays V1..V20 /
//	                                                VAr1..VAr20
//	block size       varies with NPt                CONSTANT per model
//	                                                (54/50/54/54/58) — always 20
//	                                                point slots regardless of NPt
//	enable           Ena enum16                     ModEna BITFIELD16, bit 0
//	curve activation adopt handshake                write bank, then ActCrv = i
//	                 (AdptCrvReq/AdptCrvRslt)       (1-based; 0 = none)
//	reversion        RvrtTms + RvrtRem + RvrtCrv    RvrtTms uint16 ONLY
//
// Consequences that callers must honour:
//
//  1. There is no staging bank. A curve write is DESTRUCTIVE to a live bank, so
//     a writer must never write the bank named by the current ActCrv while that
//     bank is enabled.
//  2. ModEna is a bitfield16 whose enabled value is bit 0, while 7xx Ena is an
//     enum16 whose enabled value is 1. They coincide numerically and differ in
//     type: decode must mask bit 0, not compare against 1, or a device that
//     sets reserved bits reads as disabled.
//  3. DeptRef on 126/132 is 1-BASED (1 %WMax, 2 %VArMax/%WAvail, 3 %VArAval)
//     against the 7xx enum's 0-based numbering. Translating between the two is
//     never a copy.
//
// Every offset, type, scale-factor binding, access and mandatory flag in this
// file is proven against docs/schema/sunspec-models/model_*.json by
// TestLayoutsMatchVendoredSpec (layout_vs_spec_test.go). Nothing here was
// transcribed from a PDF or from memory — the schema README records the two
// register-map bugs that practice already produced.
//
// ADDRESSING. Every Layout in this package is BODY-relative: offset 0 is the
// first register AFTER the model's ID and L (which Reader.ReadModel strips),
// matching Block.BaseAddr. The vendored JSON is MODEL-relative, so
//
//	body offset = model offset − 2
//
// throughout. Curve bank i (1-based, ActCrv numbering) starts at body offset
// legacyCurveHdrLen + blockLen·(i−1).
package sunspec

import (
	"fmt"
	"strconv"
)

// Legacy model IDs.
const (
	ModelVoltVarLegacy   uint16 = 126 // Static Volt-VAR arrays          (volt_var)
	ModelFreqWattParam   uint16 = 127 // Parameterized Frequency-Watt    (freq_watt_param)
	ModelReactiveCurrent uint16 = 128 // Dynamic Reactive Current        (reactive_current)
	ModelLVRTLegacy      uint16 = 129 // LVRT Must Disconnect            (lvrt)
	ModelHVRTLegacy      uint16 = 130 // HVRT Must Disconnect            (hvrt)
	ModelWattPFLegacy    uint16 = 131 // Watt-Power Factor               (watt_pf)
	ModelVoltWattLegacy  uint16 = 132 // Volt-Watt                       (volt_watt)
	ModelFreqWattLegacy  uint16 = 134 // Curve-Based Frequency-Watt      (freq_watt)
	ModelMPPT            uint16 = 160 // Multiple MPPT inverter extension (mppt)
)

// Repeating-block lengths, in registers. Constant per model — the legacy
// family always publishes 20 point slots regardless of the device's NPt.
const (
	Blk126 = 54
	Blk129 = 50
	Blk130 = 50
	Blk131 = 54
	Blk132 = 54
	Blk134 = 58
	Blk160 = 20
)

// LegacyCurveSlots is the fixed number of (x,y) point slots every legacy curve
// bank carries. NPt declares how many the device SUPPORTS and per-bank ActPt
// how many are ACTIVE; the remaining slots exist in the register map either
// way and are read and written like any other register.
const LegacyCurveSlots = 20

// legacyCurveHdrLen is the body length (registers after ID and L) of the shared
// ActCrv-family header carried by 126/129/130/131/132/134. It is also the
// constant term of every one of those models' declared length:
//
//	L = legacyCurveHdrLen + blockLen · NCrv
const legacyCurveHdrLen = 10

// ── Shared ActCrv-family header ──────────────────────────────────────────────
//
// 126/129/130/131/132/134 share the first nine header points and differ only in
// their trailing scale factors, so each header is spelled out rather than
// shared: the scale-factor NAMES are what bind the point arrays, and a shared
// constant would resolve to the wrong SF on four of the six models.

// L126Hdr is model 126's header (body-relative; model offset 2 = ActCrv).
var L126Hdr = NewLayout(
	F("ActCrv", Tuint16).RW().M(),
	F("ModEna", Tbitfield16).RW().M(),
	F("WinTms", Tuint16).RW().O(),
	F("RvrtTms", Tuint16).RW().O(),
	F("RmpTms", Tuint16).RW().O(),
	F("NCrv", Tuint16).R().M(),
	F("NPt", Tuint16).R().M(),
	F("V_SF", Tsunssf).R().M(),
	F("DeptRef_SF", Tsunssf).R().M(),
	F("RmpIncDec_SF", Tsunssf).R().O(),
).As("M126Hdr")

// L129Hdr is model 129's (LVRT Must Disconnect) header. 129 and 130 carry a
// Pad in the slot 126 uses for RmpIncDec_SF — they have no ramp points.
var L129Hdr = NewLayout(
	F("ActCrv", Tuint16).RW().M(),
	F("ModEna", Tbitfield16).RW().M(),
	F("WinTms", Tuint16).RW().O(),
	F("RvrtTms", Tuint16).RW().O(),
	F("RmpTms", Tuint16).RW().O(),
	F("NCrv", Tuint16).R().M(),
	F("NPt", Tuint16).R().M(),
	F("Tms_SF", Tsunssf).R().M(),
	F("V_SF", Tsunssf).R().M(),
	FPad("Pad", 1).R().O(),
).As("M129Hdr")

// L130Hdr is model 130's (HVRT Must Disconnect) header — identical in shape to
// 129's, declared separately so the two models never share a mutable binding.
var L130Hdr = NewLayout(
	F("ActCrv", Tuint16).RW().M(),
	F("ModEna", Tbitfield16).RW().M(),
	F("WinTms", Tuint16).RW().O(),
	F("RvrtTms", Tuint16).RW().O(),
	F("RmpTms", Tuint16).RW().O(),
	F("NCrv", Tuint16).R().M(),
	F("NPt", Tuint16).R().M(),
	F("Tms_SF", Tsunssf).R().M(),
	F("V_SF", Tsunssf).R().M(),
	FPad("Pad", 1).R().O(),
).As("M130Hdr")

// L131Hdr is model 131's (Watt-PF) header.
var L131Hdr = NewLayout(
	F("ActCrv", Tuint16).RW().M(),
	F("ModEna", Tbitfield16).RW().M(),
	F("WinTms", Tuint16).RW().O(),
	F("RvrtTms", Tuint16).RW().O(),
	F("RmpTms", Tuint16).RW().O(),
	F("NCrv", Tuint16).R().M(),
	F("NPt", Tuint16).R().M(),
	F("W_SF", Tsunssf).R().M(),
	F("PF_SF", Tsunssf).R().M(),
	F("RmpIncDec_SF", Tsunssf).R().O(),
).As("M131Hdr")

// L132Hdr is model 132's (Volt-Watt) header.
var L132Hdr = NewLayout(
	F("ActCrv", Tuint16).RW().M(),
	F("ModEna", Tbitfield16).RW().M(),
	F("WinTms", Tuint16).RW().O(),
	F("RvrtTms", Tuint16).RW().O(),
	F("RmpTms", Tuint16).RW().O(),
	F("NCrv", Tuint16).R().M(),
	F("NPt", Tuint16).R().M(),
	F("V_SF", Tsunssf).R().M(),
	F("DeptRef_SF", Tsunssf).R().M(),
	F("RmpIncDec_SF", Tsunssf).R().O(),
).As("M132Hdr")

// L134Hdr is model 134's (Curve-Based Frequency-Watt) header.
var L134Hdr = NewLayout(
	F("ActCrv", Tuint16).RW().M(),
	F("ModEna", Tbitfield16).RW().M(),
	F("WinTms", Tuint16).RW().O(),
	F("RvrtTms", Tuint16).RW().O(),
	F("RmpTms", Tuint16).RW().O(),
	F("NCrv", Tuint16).R().M(),
	F("NPt", Tuint16).R().M(),
	F("Hz_SF", Tsunssf).R().M(),
	F("W_SF", Tsunssf).R().M(),
	F("RmpIncDec_SF", Tsunssf).R().O(),
).As("M134Hdr")

// ── Curve banks ──────────────────────────────────────────────────────────────

// legacyPoints builds the 20 interleaved (x,y) point slots of a legacy curve
// bank: x1,y1,x2,y2,…,x20,y20. Only slot 1 is mandatory in the vendored spec;
// slots 2-20 are optional but always present in the register map.
func legacyPoints(xName string, xType FieldType, xSF string, yName string, yType FieldType, ySF string) []Field {
	out := make([]Field, 0, 2*LegacyCurveSlots)
	for n := 1; n <= LegacyCurveSlots; n++ {
		s := strconv.Itoa(n)
		x := FS(xName+s, xType, xSF).RW()
		y := FS(yName+s, yType, ySF).RW()
		if n == 1 {
			x, y = x.M(), y.M()
		} else {
			x, y = x.O(), y.O()
		}
		out = append(out, x, y)
	}
	return out
}

// joinFields concatenates field groups in declaration order.
func joinFields(groups ...[]Field) []Field {
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	out := make([]Field, 0, n)
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// L126Crv is one 126 curve bank (54 registers). V<n> is % VRef; VAr<n> is a
// SIGNED percentage of whatever DeptRef names.
var L126Crv = NewLayout(joinFields(
	[]Field{
		F("ActPt", Tuint16).RW().M(),
		F("DeptRef", Tenum16).RW().M(), // 1 %WMax, 2 %VArMax, 3 %VArAval — 1-BASED
	},
	legacyPoints("V", Tuint16, "V_SF", "VAr", Tint16, "DeptRef_SF"),
	[]Field{
		FStr("CrvNam", 8).RW().O(),
		F("RmpTms", Tuint16).RW().O(),
		FS("RmpDecTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		FS("RmpIncTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		F("ReadOnly", Tenum16).R().M(), // 0 READWRITE, 1 READONLY
	},
)...).As("M126Crv")

// L129Crv is one 129 curve bank (50 registers). The pair is (Tms<n>, V<n>) —
// TIME FIRST, the opposite of the CSIP ride-through curve convention, which
// puts duration on x and voltage on y. Each bank expresses exactly ONE region,
// the must-disconnect boundary; there is no may-trip and no momentary-cessation
// region, unlike 707/708 which carry all three inside one Crv.
var L129Crv = NewLayout(joinFields(
	[]Field{F("ActPt", Tuint16).RW().M()},
	legacyPoints("Tms", Tuint16, "Tms_SF", "V", Tuint16, "V_SF"),
	[]Field{
		FStr("CrvNam", 8).RW().O(),
		F("ReadOnly", Tenum16).R().M(),
	},
)...).As("M129Crv")

// L130Crv is one 130 curve bank (50 registers) — same shape as 129's.
var L130Crv = NewLayout(joinFields(
	[]Field{F("ActPt", Tuint16).RW().M()},
	legacyPoints("Tms", Tuint16, "Tms_SF", "V", Tuint16, "V_SF"),
	[]Field{
		FStr("CrvNam", 8).RW().O(),
		F("ReadOnly", Tenum16).R().M(),
	},
)...).As("M130Crv")

// L131Crv is one 131 curve bank (54 registers). No DeptRef: the x-axis
// reference is fixed at %WMax by the spec. Note the trailing Pad — 131 is the
// one model in the family whose ReadOnly is NOT the last register, so its
// ReadOnly offset (+52) differs from 132's (+53) despite the equal block
// length. Transcribe per model, never per block length.
var L131Crv = NewLayout(joinFields(
	[]Field{F("ActPt", Tuint16).RW().M()},
	legacyPoints("W", Tint16, "W_SF", "PF", Tint16, "PF_SF"),
	[]Field{
		FStr("CrvNam", 8).RW().O(),
		F("RmpPT1Tms", Tuint16).RW().O(), // upper-case PT1 — 132 spells it RmpPt1Tms
		FS("RmpDecTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		FS("RmpIncTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		F("ReadOnly", Tenum16).R().M(),
		FPad("Pad", 1).R().O(),
	},
)...).As("M131Crv")

// L132Crv is one 132 curve bank (54 registers).
//
// W<n> carries units "% VRef" in the vendored JSON. That is a known SunSpec
// JSON erratum: the point is active power as a percentage of whatever DeptRef
// names (1 %WMax, 2 %WAvail), per the model's own DeptRef description. Decode
// by DeptRef, never by the units string. The units string is deliberately NOT
// asserted anywhere in this package — see TestLayoutsMatchVendoredSpec.
var L132Crv = NewLayout(joinFields(
	[]Field{
		F("ActPt", Tuint16).RW().M(),
		F("DeptRef", Tenum16).RW().M(), // 1 %WMax, 2 %WAvail — 1-BASED
	},
	legacyPoints("V", Tuint16, "V_SF", "W", Tint16, "DeptRef_SF"),
	[]Field{
		FStr("CrvNam", 8).RW().O(),
		F("RmpPt1Tms", Tuint16).RW().O(), // lower-case t — 131/134 spell it RmpPT1Tms
		FS("RmpDecTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		FS("RmpIncTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		F("ReadOnly", Tenum16).R().M(),
	},
)...).As("M132Crv")

// L134Crv is one 134 curve bank (58 registers) — the longest in the family.
//
// Three things in this block change how a caller must treat it:
//
//  1. W<n> is "% WRef", NOT "% WMax". WRef is a per-bank register (default
//     WMax) and the two are equal only when the device says so. A CSIP
//     opModFreqWatt curve is defined against %setMaxW, so translating one to
//     the other requires resolving WRef, never assuming it.
//  2. SnptW is MANDATORY and vendor-defaulted. With snapshot mode enabled the
//     curve's power base becomes the instantaneous output at the moment
//     WRefStrHz was crossed, so the delivered curve depends on irradiance at
//     trigger time. A writer must write SnptW = 0 and read it back.
//  3. Hz<n> is ABSOLUTE frequency in Hz, while WRefStrHz/WRefStopHz are
//     DEVIATIONS from nominal. Two conventions inside one block.
var L134Crv = NewLayout(joinFields(
	[]Field{F("ActPt", Tuint16).RW().M()},
	legacyPoints("Hz", Tuint16, "Hz_SF", "W", Tint16, "W_SF"),
	[]Field{
		FStr("CrvNam", 8).RW().O(),
		F("RmpPT1Tms", Tuint16).RW().O(),
		FS("RmpDecTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		FS("RmpIncTmm", Tuint16, "RmpIncDec_SF").RW().O(),
		FS("RmpRsUp", Tuint16, "RmpIncDec_SF").RW().O(),
		F("SnptW", Tbitfield16).RW().M(),
		FS("WRef", Tuint16, "W_SF").RW().O(),
		FS("WRefStrHz", Tuint16, "Hz_SF").RW().O(),
		FS("WRefStopHz", Tuint16, "Hz_SF").RW().O(),
		F("ReadOnly", Tenum16).R().M(),
	},
)...).As("M134Crv")

// ── Models with no repeating group ───────────────────────────────────────────

// L127 is model 127, Parameterized Frequency-Watt (body length 10, L = 10).
//
// 127 is a PARAMETERIZED droop (a gradient plus start/stop frequencies), not a
// breakpoint curve: it is the legacy analogue of 711 / opModFreqDroop, not of
// opModFreqWatt. Model 134 is the breakpoint-curve target.
var L127 = NewLayout(
	FS("WGra", Tuint16, "WGra_SF").RW().M(),            // % PM/Hz
	FS("HzStr", Tint16, "HzStrStop_SF").RW().M(),       // Hz deviation to start
	FS("HzStop", Tint16, "HzStrStop_SF").RW().M(),      // Hz deviation to stop
	F("HysEna", Tbitfield16).RW().M(),                  // bit 0 ENABLED
	F("ModEna", Tbitfield16).RW().M(),                  // bit 0 ENABLED
	FS("HzStopWGra", Tuint16, "RmpIncDec_SF").RW().O(), // % WMax/min
	F("WGra_SF", Tsunssf).R().O(),
	F("HzStrStop_SF", Tsunssf).R().O(),
	F("RmpIncDec_SF", Tsunssf).R().O(),
	FPad("Pad", 1).R().O(),
).As("M127")

// L128 is model 128, Dynamic Reactive Current (body length 14, L = 14).
//
// 128 declares ELEVEN RW points — it is emphatically not a read-only model.
// The product gives it discovery, decode, read and exposure and NO writer, for
// a reason that is about IEEE 2030.5 rather than about the model: there is no
// opMod* element in DERControlBase and no DERControlType bit for dynamic
// reactive current, so there is no northbound intent for a writer to serve.
// Any write path would have to invent both the control and its semantics.
var L128 = NewLayout(
	F("ArGraMod", Tenum16).RW().M(), // 0 EDGE, 1 CENTER
	FS("ArGraSag", Tuint16, "ArGra_SF").RW().M(),
	FS("ArGraSwell", Tuint16, "ArGra_SF").RW().M(),
	F("ModEna", Tbitfield16).RW().M(),
	F("FilTms", Tuint16).RW().O(),
	FS("DbVMin", Tuint16, "VRefPct_SF").RW().O(),
	FS("DbVMax", Tuint16, "VRefPct_SF").RW().O(),
	FS("BlkZnV", Tuint16, "VRefPct_SF").RW().O(),
	FS("HysBlkZnV", Tuint16, "VRefPct_SF").RW().O(),
	F("BlkZnTmms", Tuint16).RW().O(),
	F("HoldTmms", Tuint16).RW().O(),
	F("ArGra_SF", Tsunssf).R().M(),
	F("VRefPct_SF", Tsunssf).R().O(),
	FPad("Pad", 1).R().O(),
).As("M128")

// ── Model 160: Multiple MPPT ─────────────────────────────────────────────────

// L160Hdr is model 160's header (body length 8; L = 8 + 20·N).
//
// NO POINT IN MODEL 160 DECLARES AN access KEY AT ALL — not "r", absent. SunSpec's
// default for an undeclared point is read-only, so 160 declares no RW point,
// which is the property that matters: it is telemetry. Decode, per-module MPPT
// telemetry and northbound exposure; no writer, no axis.
var L160Hdr = NewLayout(
	F("DCA_SF", Tsunssf).R().O(),
	F("DCV_SF", Tsunssf).R().O(),
	F("DCW_SF", Tsunssf).R().O(),
	F("DCWH_SF", Tsunssf).R().O(),
	F("Evt", Tbitfield32).R().O(),
	F("N", Tuint16).R().O(), // JSON type "count"
	F("TmsPer", Tuint16).R().O(),
).As("M160Hdr")

// L160Mod is one 160 module block (20 registers) at body offset 8 + 20·i,
// i 0-based. DCWH is an acc32: its not-implemented sentinel is 0, not
// 0xFFFFFFFF, so a zero reading is real data.
var L160Mod = NewLayout(
	F("ID", Tuint16).R().O(),
	FStr("IDStr", 8).R().O(),
	FS("DCA", Tuint16, "DCA_SF").R().O(),
	FS("DCV", Tuint16, "DCV_SF").R().O(),
	FS("DCW", Tuint16, "DCW_SF").R().O(),
	FS("DCWH", Tacc32, "DCWH_SF").R().O(),
	F("Tms", Tuint32).R().O(),
	F("Tmp", Tint16).R().O(), // degrees C, UNSCALED (no sf in the spec)
	F("DCSt", Tenum16).R().O(),
	F("DCEvt", Tbitfield32).R().O(),
).As("M160Mod")

// ── Model registry ───────────────────────────────────────────────────────────

type legacyCurveSpec struct {
	hdr      *Layout
	bank     *Layout
	blockLen int
}

// legacyCurveModels is the registry of legacy models that carry an
// ActCrv-selected repeating curve bank. 127, 128 and 160 are deliberately
// absent: the first two have no repeating group at all and 160's repeating
// group is telemetry, not a curve.
var legacyCurveModels = map[uint16]legacyCurveSpec{
	ModelVoltVarLegacy:  {L126Hdr, L126Crv, Blk126},
	ModelLVRTLegacy:     {L129Hdr, L129Crv, Blk129},
	ModelHVRTLegacy:     {L130Hdr, L130Crv, Blk130},
	ModelWattPFLegacy:   {L131Hdr, L131Crv, Blk131},
	ModelVoltWattLegacy: {L132Hdr, L132Crv, Blk132},
	ModelFreqWattLegacy: {L134Hdr, L134Crv, Blk134},
}

// IsLegacyCurveModel reports whether modelID is one of the six ActCrv-family
// curve models this package lays out.
func IsLegacyCurveModel(modelID uint16) bool {
	_, ok := legacyCurveModels[modelID]
	return ok
}

// LegacyCurveLayouts returns the header layout, the curve-bank layout and the
// spec block length for a legacy curve model.
func LegacyCurveLayouts(modelID uint16) (hdr, bank *Layout, blockLen int, ok bool) {
	s, ok := legacyCurveModels[modelID]
	if !ok {
		return nil, nil, 0, false
	}
	return s.hdr, s.bank, s.blockLen, true
}

// LegacyCurveOffset returns the BODY-relative register offset of curve bank i.
// i is 1-BASED, matching ActCrv numbering (ActCrv = 0 means "no active curve",
// so there is no bank 0). ok=false for an unknown model or i < 1.
func LegacyCurveOffset(modelID uint16, i int) (int, bool) {
	s, ok := legacyCurveModels[modelID]
	if !ok || i < 1 {
		return 0, false
	}
	return legacyCurveHdrLen + s.blockLen*(i-1), true
}

// MPPTModuleOffset returns the body-relative offset of MPPT module i (0-based)
// in a model 160 block.
func MPPTModuleOffset(i int) int { return L160Hdr.Len() + i*Blk160 }

// ── Geometry gate ────────────────────────────────────────────────────────────

// LegacyCurveGeometry is everything a caller must know about a legacy curve
// model's shape on a particular device before it may compute a single offset.
type LegacyCurveGeometry struct {
	ModelID  uint16
	DeclLen  int // the device-declared L (body registers)
	NCrv     int // banks declared, ≥ 1
	NPt      int // point slots supported, 1..20
	ActCrv   int // live bank, 0 = none; 1-based
	BlockLen int // derived from L and NCrv; MUST equal the spec constant
}

// ReadLegacyCurveGeometry reads a legacy curve model's header from the device
// and validates its geometry. See LegacyCurveGeometryOf for the rules; the
// returned struct carries whatever WAS read even when the error is non-nil, so
// a caller can record the observed values in a defect record.
func ReadLegacyCurveGeometry(r *Reader, modelID uint16) (LegacyCurveGeometry, error) {
	declLen, ok := r.ModelLen(modelID)
	if !ok {
		return LegacyCurveGeometry{ModelID: modelID}, &GeometryError{
			ModelID: modelID, Detail: "model not present in the device's SunSpec chain",
		}
	}
	regs, err := r.ReadModel(modelID)
	if err != nil {
		return LegacyCurveGeometry{ModelID: modelID, DeclLen: int(declLen)}, err
	}
	return LegacyCurveGeometryOf(modelID, int(declLen), regs)
}

// LegacyCurveGeometryOf validates a legacy curve model's geometry from its
// device-declared length and its header registers. It is the fail-closed gate
// that must run before any bank offset is computed.
//
// SunSpec's legacy models define a fixed 20-slot block, but field firmware
// exists that publishes a SHORTENED block sized to its own NPt. There is no way
// to tell the two apart other than L arithmetic:
//
//	blockLen := (L − 10) / NCrv    // must divide exactly
//	blockLen must equal the model's spec block length (54/50/54/54/58)
//
// A device that fails any check has an UNKNOWN register geometry, and guessing
// offsets on it is precisely how a silent register-map bug happens. Every
// failure returns a *GeometryError, which unwraps to ErrGeometryUnknown.
func LegacyCurveGeometryOf(modelID uint16, declLen int, regs []uint16) (LegacyCurveGeometry, error) {
	s, ok := legacyCurveModels[modelID]
	if !ok {
		return LegacyCurveGeometry{ModelID: modelID}, &GeometryError{
			ModelID: modelID, Detail: "not a legacy curve model",
		}
	}
	g := LegacyCurveGeometry{ModelID: modelID, DeclLen: declLen}
	fail := func(format string, args ...any) (LegacyCurveGeometry, error) {
		return g, &GeometryError{ModelID: modelID, Detail: fmt.Sprintf(format, args...)}
	}
	if declLen < legacyCurveHdrLen {
		return fail("declared L=%d is shorter than the %d-register header", declLen, legacyCurveHdrLen)
	}
	if len(regs) < legacyCurveHdrLen {
		return fail("read %d registers, header needs %d", len(regs), legacyCurveHdrLen)
	}
	h := s.hdr.View(regs)
	// Header scale factors are read-only device constants; an out-of-domain one
	// means the whole model is unusable, not merely one point (LXR-004).
	if h.ReadLooksCorrupt() {
		return fail("header scale factors are out of the sunssf domain — read looks corrupt")
	}
	g.ActCrv = int(h.U16At(s.hdr.Offset("ActCrv")))
	g.NCrv = int(h.U16At(s.hdr.Offset("NCrv")))
	g.NPt = int(h.U16At(s.hdr.Offset("NPt")))
	if g.NCrv < 1 {
		return fail("NCrv=%d — the model declares no curve bank", g.NCrv)
	}
	if g.NPt < 1 || g.NPt > LegacyCurveSlots {
		return fail("NPt=%d outside 1..%d", g.NPt, LegacyCurveSlots)
	}
	body := declLen - legacyCurveHdrLen
	if body%g.NCrv != 0 {
		return fail("L=%d with NCrv=%d leaves %d registers over the %d-register header — not a whole number of banks",
			declLen, g.NCrv, body%g.NCrv, legacyCurveHdrLen)
	}
	g.BlockLen = body / g.NCrv
	if g.BlockLen != s.blockLen {
		return fail("derived block length %d ≠ spec block length %d (L=%d, NCrv=%d)",
			g.BlockLen, s.blockLen, declLen, g.NCrv)
	}
	if g.ActCrv > g.NCrv {
		// Which bank is live decides which bank is unsafe to write. A device
		// naming a bank it does not have leaves that question unanswerable, so
		// this fails closed rather than being clamped away.
		return fail("ActCrv=%d exceeds NCrv=%d — the live bank cannot be identified", g.ActCrv, g.NCrv)
	}
	return g, nil
}

// BankOffset returns the body-relative offset of bank i (1-based) under this
// device's validated geometry, and whether i names a bank the device has.
func (g LegacyCurveGeometry) BankOffset(i int) (int, bool) {
	if i < 1 || i > g.NCrv || g.BlockLen == 0 {
		return 0, false
	}
	return legacyCurveHdrLen + g.BlockLen*(i-1), true
}

// UsablePoints is the number of curve points this device can actually carry:
// min(NPt, 20).
func (g LegacyCurveGeometry) UsablePoints() int {
	if g.NPt > LegacyCurveSlots {
		return LegacyCurveSlots
	}
	if g.NPt < 0 {
		return 0
	}
	return g.NPt
}
