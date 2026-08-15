package suitemodbusserver

// models.go is this suite's OWN transcription of the SunSpec point tables it
// needs, and of the type rules that make a register value meaningful.
//
// It is deliberately not lexa-proto/sunspec/derlayout.go. That file is the
// table the DUT ENCODES with; if one of its offsets were wrong the DUT would
// place a point at the wrong register and a checker built on the same table
// would look for it at the same wrong register and find it. The whole value of
// a referee is that it disagrees when the product is wrong, so the offsets
// below are transcribed from the specification documents (SunSpec Device
// Information Model Specification §4.2.4/§6.4 for the type rules; SunSpec DER
// Information Model Specification v1.2 §4 for models 701-714; the SunSpec
// Common Model definition for model 1) via the harness fact sheets, and the
// per-model length arithmetic is asserted against the transcription at init
// time so a typo here fails this package's own tests rather than the DUT.
//
// Only the models the DUT's northbound projection can actually serve are
// transcribed: 1, 701, 702, 703, 704, 713 and the fixed header of 714. The
// curve models 705-712 have runtime geometry (NPt / NCrv / NCrvSet / NCtl) and
// no fixed table exists to transcribe; a check that meets one says so and
// SKIPs its per-point sweep rather than guessing offsets. The legacy 12x family
// the Stage-6 read-only projection added (126-132, 134, 160) is transcribed to
// exactly ONE point per model — see curveModels at the bottom of this file for
// what that one point is for and why transcribing more of them would be
// guessing.

import (
	"fmt"
	"sort"
)

// PointType is a SunSpec point data type. The set here is the subset that
// appears in the transcribed models; the Device spec defines more.
type PointType int

// The transcribed types. Register counts and not-implemented sentinels are from
// the Device Information Model Specification §4.2.4 Table 3 and §6.4.
const (
	TypeUint16 PointType = iota
	TypeInt16
	TypeEnum16
	TypeBitfield16
	TypeSunSSF
	TypePad
	TypeString
	TypeUint32
	TypeInt32
	TypeBitfield32
	TypeUint64
)

// Regs is the register width of a point of this type. size is the declared
// string size in registers and is ignored for every other type.
func (t PointType) Regs(size int) int {
	switch t {
	case TypeUint16, TypeInt16, TypeEnum16, TypeBitfield16, TypeSunSSF, TypePad:
		return 1
	case TypeUint32, TypeInt32, TypeBitfield32:
		return 2
	case TypeUint64:
		return 4
	case TypeString:
		return size
	default:
		return 0
	}
}

// String renders the type as the specification spells it.
func (t PointType) String() string {
	switch t {
	case TypeUint16:
		return "uint16"
	case TypeInt16:
		return "int16"
	case TypeEnum16:
		return "enum16"
	case TypeBitfield16:
		return "bitfield16"
	case TypeSunSSF:
		return "sunssf"
	case TypePad:
		return "pad"
	case TypeString:
		return "string"
	case TypeUint32:
		return "uint32"
	case TypeInt32:
		return "int32"
	case TypeBitfield32:
		return "bitfield32"
	case TypeUint64:
		return "uint64"
	default:
		return fmt.Sprintf("PointType(%d)", int(t))
	}
}

// NotImplemented reports whether regs carries this type's "not implemented"
// sentinel. A mandatory point MUST NOT read as not-implemented (Device spec
// §4.2.6); an optional one MAY.
//
// The caller passes exactly the point's registers; a short slice is treated as
// not-implemented-unknown (false), because inventing a verdict from a truncated
// read is worse than declining to.
func (t PointType) NotImplemented(regs []uint16) bool {
	if t != TypeString && len(regs) != t.Regs(0) {
		// Width mismatch for a fixed-width type: refuse to judge rather than
		// invent a verdict from a truncated read.
		return false
	}
	switch t {
	case TypeInt16, TypeSunSSF:
		return len(regs) == 1 && regs[0] == 0x8000
	case TypeUint16, TypeEnum16, TypeBitfield16:
		return len(regs) == 1 && regs[0] == 0xFFFF
	case TypePad:
		// A pad register always reads 0x8000; it is never "implemented".
		return true
	case TypeInt32:
		return len(regs) == 2 && regs[0] == 0x8000 && regs[1] == 0x0000
	case TypeUint32, TypeBitfield32:
		return len(regs) == 2 && regs[0] == 0xFFFF && regs[1] == 0xFFFF
	case TypeUint64:
		if len(regs) != 4 {
			return false
		}
		for _, r := range regs {
			if r != 0xFFFF {
				return false
			}
		}
		return true
	case TypeString:
		for _, r := range regs {
			if r != 0 {
				return false
			}
		}
		return len(regs) > 0
	default:
		return false
	}
}

// InDatatypeRange reports whether regs is a legal value for this type, ignoring
// the not-implemented sentinel (which is legal but separately identified). The
// only types with a range narrower than their register width are sunssf
// (-10..10) and the bitfields (whose top bit is reserved).
func (t PointType) InDatatypeRange(regs []uint16) bool {
	if t.NotImplemented(regs) {
		return true
	}
	switch t {
	case TypeSunSSF:
		if len(regs) != 1 {
			return false
		}
		v := int16(regs[0])
		return v >= -10 && v <= 10
	case TypeBitfield16:
		return len(regs) == 1 && regs[0] <= 0x7FFF
	case TypeBitfield32:
		return len(regs) == 2 && (uint32(regs[0])<<16|uint32(regs[1])) <= 0x7FFFFFFF
	case TypeInt16:
		// -32768 is the sentinel, already handled; every other value is legal.
		return len(regs) == 1
	case TypeUint16, TypeEnum16:
		return len(regs) == 1
	default:
		return len(regs) == t.Regs(len(regs)) || t == TypeString
	}
}

// Access is a point's read/write access, defaulting to R (Device spec §4).
type Access int

// The two access values.
const (
	AccessR Access = iota
	AccessRW
)

func (a Access) String() string {
	if a == AccessRW {
		return "RW"
	}
	return "R"
}

// Point is one SunSpec point inside a model.
type Point struct {
	// Name is the point name as the model definition spells it. Nested sync
	// group members are spelled "Group.Member" (e.g. "PFWInj.PF").
	Name string
	// Off is the register offset from the model's ID register.
	Off int
	// Type is the point's data type.
	Type PointType
	// Size is the declared register size; meaningful only for strings.
	Size int
	// Access is R or RW.
	Access Access
	// Mandatory marks a point the model definition declares mandatory. A
	// mandatory point MUST always carry a valid value.
	Mandatory bool
	// SF names the sunssf point this point is scaled by, empty when unscaled.
	SF string
}

// Regs is the point's register width.
func (p Point) Regs() int { return p.Type.Regs(p.Size) }

// End is the offset one past the point's last register.
func (p Point) End() int { return p.Off + p.Regs() }

// Model is a transcribed SunSpec model definition.
type Model struct {
	// ID is the SunSpec model identifier.
	ID uint16
	// Name is the model's group name.
	Name string
	// L is the model's fixed instance length in registers, excluding the two
	// header registers — i.e. the value the DUT must report in its L register.
	// Zero for a model whose length is runtime-variable.
	L int
	// Points is the point table in register order.
	Points []Point
	// Source names the document the transcription came from.
	Source string
}

// Point returns a point by name.
func (m *Model) Point(name string) (Point, bool) {
	for _, p := range m.Points {
		if p.Name == name {
			return p, true
		}
	}
	return Point{}, false
}

// ScaleFactors returns the model's sunssf points.
func (m *Model) ScaleFactors() []Point {
	var out []Point
	for _, p := range m.Points {
		if p.Type == TypeSunSSF {
			out = append(out, p)
		}
	}
	return out
}

// Writable returns the model's RW points.
func (m *Model) Writable() []Point {
	var out []Point
	for _, p := range m.Points {
		if p.Access == AccessRW {
			out = append(out, p)
		}
	}
	return out
}

// span returns the offset one past the last transcribed register.
func (m *Model) span() int {
	end := 0
	for _, p := range m.Points {
		// Sync-group members overlay their parent group's registers, so a
		// member never extends the span beyond what the parent already covers.
		if p.End() > end {
			end = p.End()
		}
	}
	return end
}

// Models is the transcribed model set, keyed by model id.
var Models = map[uint16]*Model{}

func register(m *Model) {
	Models[m.ID] = m
}

// r builds a read-only point.
func r(name string, off int, t PointType, sf string) Point {
	return Point{Name: name, Off: off, Type: t, Access: AccessR, SF: sf}
}

// rw builds a read-write point.
func rw(name string, off int, t PointType, sf string) Point {
	return Point{Name: name, Off: off, Type: t, Access: AccessRW, SF: sf}
}

// mand marks a point mandatory.
func mand(p Point) Point { p.Mandatory = true; return p }

// str builds a read-only string point of the given register size.
func str(name string, off, size int) Point {
	return Point{Name: name, Off: off, Type: TypeString, Size: size, Access: AccessR}
}

func init() {
	// --- Model 1, the Common Model -------------------------------------
	//
	// The Device Information Model Specification fixes the total length at 66
	// (Appendix B's example map: model 1 at 40002 declares 66 and the next
	// header is at 40070). The point list is the SunSpec Common Model
	// definition. Mandatory: ID, L, Mn, Md, SN.
	register(&Model{
		ID: 1, Name: "common", L: 66,
		Source: "SunSpec Device Information Model Specification §6.1 + the Common Model definition",
		Points: []Point{
			mand(r("ID", 0, TypeUint16, "")),
			mand(r("L", 1, TypeUint16, "")),
			mand(str("Mn", 2, 16)),
			mand(str("Md", 18, 16)),
			str("Opt", 34, 8),
			str("Vr", 42, 8),
			mand(str("SN", 50, 16)),
			r("DA", 66, TypeUint16, ""),
			r("Pad", 67, TypePad, ""),
		},
	})

	// --- Model 701, DERMeasureAC ---------------------------------------
	//
	// Entirely read-only. Mandatory: ID, L, ACType. MnAlrmInfo is a string of
	// declared size 32, which is what makes L = 153.
	//
	// PF/PFL1/PFL2/PFL3 ARE int16 — a DELIBERATE departure from the Source
	// document named below, and the one place this transcription knowingly
	// disagrees with a printed spec table.
	//
	// DER Information Model Spec v1.2 Table 4 types these four points uint16;
	// the canonical model definition, model_701.json, types them int16. Device
	// Information Model Specification v1.4 §5.1 makes the JSON definition the
	// canonical encoding of a model and the PDF tables a rendering of it, so
	// the JSON governs the conflict. It is also the only self-consistent
	// reading: the JSON describes these points as "the sign of power factor
	// should be the sign of active power", which an unsigned type cannot
	// express — Table 4 contradicts the text its own model definition ships
	// with.
	//
	// The corroboration is reached WITHOUT consulting derlayout.go, which is
	// what keeps this a referee rather than an echo: every other power-factor
	// point transcribed in THIS file is paired with an explicit
	// over/under-excitation discriminator and is legitimately uint16 — 704's
	// PFWInj.PF/PFWInj.Ext and its three siblings, and 702's
	// PFOvrExtRtg/PFUndExtRtg family where the direction is in the name. Model
	// 701's four have no excitation companion at any offset in this table.
	// Under Table 4's typing, the family's one AC MEASUREMENT model would be
	// the only one structurally unable to report direction.
	//
	// Consequence for this package's checks: these points' not-implemented
	// value is 0x8000, not 0xFFFF (PointType.NotImplemented dispatches on the
	// type recorded here), and a raw word above 0x7FFF is a negative power
	// factor rather than an out-of-range magnitude. A referee still holding
	// uint16 here would report a CONFORMING DUT as non-conforming — the
	// failure mode a referee exists to avoid, in the direction that is hardest
	// to notice.
	register(&Model{
		ID: 701, Name: "DERMeasureAC", L: 153,
		Source: "SunSpec DER Information Model Specification v1.2 §4 (DERMeasureAC); " +
			"PF/PFL1/PFL2/PFL3 per model_701.json, which Device Information Model " +
			"Specification v1.4 §5.1 makes canonical over Table 4 — see the note above",
		Points: []Point{
			mand(r("ID", 0, TypeUint16, "")),
			mand(r("L", 1, TypeUint16, "")),
			mand(r("ACType", 2, TypeEnum16, "")),
			r("St", 3, TypeEnum16, ""),
			r("InvSt", 4, TypeEnum16, ""),
			r("ConnSt", 5, TypeEnum16, ""),
			r("Alrm", 6, TypeBitfield32, ""),
			r("DERMode", 8, TypeBitfield32, ""),
			r("W", 10, TypeInt16, "W_SF"),
			r("VA", 11, TypeInt16, "VA_SF"),
			r("Var", 12, TypeInt16, "Var_SF"),
			r("PF", 13, TypeInt16, "PF_SF"),
			r("A", 14, TypeInt16, "A_SF"),
			r("LLV", 15, TypeUint16, "V_SF"),
			r("LNV", 16, TypeUint16, "V_SF"),
			r("Hz", 17, TypeUint32, "Hz_SF"),
			r("TotWhInj", 19, TypeUint64, "TotWh_SF"),
			r("TotWhAbs", 23, TypeUint64, "TotWh_SF"),
			r("TotVarhInj", 27, TypeUint64, "TotVarh_SF"),
			r("TotVarhAbs", 31, TypeUint64, "TotVarh_SF"),
			r("TmpAmb", 35, TypeInt16, "Tmp_SF"),
			r("TmpCab", 36, TypeInt16, "Tmp_SF"),
			r("TmpSnk", 37, TypeInt16, "Tmp_SF"),
			r("TmpTrns", 38, TypeInt16, "Tmp_SF"),
			r("TmpSw", 39, TypeInt16, "Tmp_SF"),
			r("TmpOt", 40, TypeInt16, "Tmp_SF"),
			r("WL1", 41, TypeInt16, "W_SF"),
			r("VAL1", 42, TypeInt16, "VA_SF"),
			r("VarL1", 43, TypeInt16, "Var_SF"),
			r("PFL1", 44, TypeInt16, "PF_SF"),
			r("AL1", 45, TypeInt16, "A_SF"),
			r("VL1L2", 46, TypeUint16, "V_SF"),
			r("VL1", 47, TypeUint16, "V_SF"),
			r("TotWhInjL1", 48, TypeUint64, "TotWh_SF"),
			r("TotWhAbsL1", 52, TypeUint64, "TotWh_SF"),
			r("TotVarhInjL1", 56, TypeUint64, "TotVarh_SF"),
			r("TotVarhAbsL1", 60, TypeUint64, "TotVarh_SF"),
			r("WL2", 64, TypeInt16, "W_SF"),
			r("VAL2", 65, TypeInt16, "VA_SF"),
			r("VarL2", 66, TypeInt16, "Var_SF"),
			r("PFL2", 67, TypeInt16, "PF_SF"),
			r("AL2", 68, TypeInt16, "A_SF"),
			r("VL2L3", 69, TypeUint16, "V_SF"),
			r("VL2", 70, TypeUint16, "V_SF"),
			r("TotWhInjL2", 71, TypeUint64, "TotWh_SF"),
			r("TotWhAbsL2", 75, TypeUint64, "TotWh_SF"),
			r("TotVarhInjL2", 79, TypeUint64, "TotVarh_SF"),
			r("TotVarhAbsL2", 83, TypeUint64, "TotVarh_SF"),
			r("WL3", 87, TypeInt16, "W_SF"),
			r("VAL3", 88, TypeInt16, "VA_SF"),
			r("VarL3", 89, TypeInt16, "Var_SF"),
			r("PFL3", 90, TypeInt16, "PF_SF"),
			r("AL3", 91, TypeInt16, "A_SF"),
			r("VL3L1", 92, TypeUint16, "V_SF"),
			r("VL3", 93, TypeUint16, "V_SF"),
			r("TotWhInjL3", 94, TypeUint64, "TotWh_SF"),
			r("TotWhAbsL3", 98, TypeUint64, "TotWh_SF"),
			r("TotVarhInjL3", 102, TypeUint64, "TotVarh_SF"),
			r("TotVarhAbsL3", 106, TypeUint64, "TotVarh_SF"),
			r("ThrotPct", 110, TypeUint16, ""),
			r("ThrotSrc", 111, TypeBitfield32, ""),
			r("A_SF", 113, TypeSunSSF, ""),
			r("V_SF", 114, TypeSunSSF, ""),
			r("Hz_SF", 115, TypeSunSSF, ""),
			r("W_SF", 116, TypeSunSSF, ""),
			r("PF_SF", 117, TypeSunSSF, ""),
			r("VA_SF", 118, TypeSunSSF, ""),
			r("Var_SF", 119, TypeSunSSF, ""),
			r("TotWh_SF", 120, TypeSunSSF, ""),
			r("TotVarh_SF", 121, TypeSunSSF, ""),
			r("Tmp_SF", 122, TypeSunSSF, ""),
			str("MnAlrmInfo", 123, 32),
		},
	})

	// --- Model 702, DERCapacity ----------------------------------------
	//
	// Read-only ratings followed by read-write settings that override them.
	// Only ID and L are mandatory.
	register(&Model{
		ID: 702, Name: "DERCapacity", L: 50,
		Source: "SunSpec DER Information Model Specification v1.2 §4 (DERCapacity)",
		Points: []Point{
			mand(r("ID", 0, TypeUint16, "")),
			mand(r("L", 1, TypeUint16, "")),
			r("WMaxRtg", 2, TypeUint16, "W_SF"),
			r("WOvrExtRtg", 3, TypeUint16, "W_SF"),
			r("WOvrExtRtgPF", 4, TypeUint16, "PF_SF"),
			r("WUndExtRtg", 5, TypeUint16, "W_SF"),
			r("WUndExtRtgPF", 6, TypeUint16, "PF_SF"),
			r("VAMaxRtg", 7, TypeUint16, "VA_SF"),
			r("VarMaxInjRtg", 8, TypeUint16, "Var_SF"),
			r("VarMaxAbsRtg", 9, TypeUint16, "Var_SF"),
			r("WChaRteMaxRtg", 10, TypeUint16, "W_SF"),
			r("WDisChaRteMaxRtg", 11, TypeUint16, "W_SF"),
			r("VAChaRteMaxRtg", 12, TypeUint16, "VA_SF"),
			r("VADisChaRteMaxRtg", 13, TypeUint16, "VA_SF"),
			r("VNomRtg", 14, TypeUint16, "V_SF"),
			r("VMaxRtg", 15, TypeUint16, "V_SF"),
			r("VMinRtg", 16, TypeUint16, "V_SF"),
			r("AMaxRtg", 17, TypeUint16, "A_SF"),
			r("PFOvrExtRtg", 18, TypeUint16, "PF_SF"),
			r("PFUndExtRtg", 19, TypeUint16, "PF_SF"),
			r("ReactSusceptRtg", 20, TypeUint16, "S_SF"),
			r("NorOpCatRtg", 21, TypeEnum16, ""),
			r("AbnOpCatRtg", 22, TypeEnum16, ""),
			r("CtrlModes", 23, TypeBitfield32, ""),
			r("IntIslandCatRtg", 25, TypeBitfield16, ""),
			rw("WMax", 26, TypeUint16, "W_SF"),
			rw("WMaxOvrExt", 27, TypeUint16, "W_SF"),
			rw("WOvrExtPF", 28, TypeUint16, "PF_SF"),
			rw("WMaxUndExt", 29, TypeUint16, "W_SF"),
			rw("WUndExtPF", 30, TypeUint16, "PF_SF"),
			rw("VAMax", 31, TypeUint16, "VA_SF"),
			rw("VarMaxInj", 32, TypeUint16, "Var_SF"),
			rw("VarMaxAbs", 33, TypeUint16, "Var_SF"),
			rw("WChaRteMax", 34, TypeUint16, "W_SF"),
			rw("WDisChaRteMax", 35, TypeUint16, "W_SF"),
			rw("VAChaRteMax", 36, TypeUint16, "VA_SF"),
			rw("VADisChaRteMax", 37, TypeUint16, "VA_SF"),
			rw("VNom", 38, TypeUint16, "V_SF"),
			rw("VMax", 39, TypeUint16, "V_SF"),
			rw("VMin", 40, TypeUint16, "V_SF"),
			rw("AMax", 41, TypeUint16, "A_SF"),
			rw("PFOvrExt", 42, TypeUint16, "PF_SF"),
			rw("PFUndExt", 43, TypeUint16, "PF_SF"),
			rw("IntIslandCat", 44, TypeBitfield16, ""),
			r("W_SF", 45, TypeSunSSF, ""),
			r("PF_SF", 46, TypeSunSSF, ""),
			r("VA_SF", 47, TypeSunSSF, ""),
			r("Var_SF", 48, TypeSunSSF, ""),
			r("V_SF", 49, TypeSunSSF, ""),
			r("A_SF", 50, TypeSunSSF, ""),
			r("S_SF", 51, TypeSunSSF, ""),
		},
	})

	// --- Model 703, DEREnterService ------------------------------------
	register(&Model{
		ID: 703, Name: "DEREnterService", L: 17,
		Source: "SunSpec DER Information Model Specification v1.2 §4 (DEREnterService)",
		Points: []Point{
			mand(r("ID", 0, TypeUint16, "")),
			mand(r("L", 1, TypeUint16, "")),
			rw("ES", 2, TypeEnum16, ""),
			rw("ESVHi", 3, TypeUint16, "V_SF"),
			rw("ESVLo", 4, TypeUint16, "V_SF"),
			rw("ESHzHi", 5, TypeUint32, "Hz_SF"),
			rw("ESHzLo", 7, TypeUint32, "Hz_SF"),
			rw("ESDlyTms", 9, TypeUint32, ""),
			rw("ESRndTms", 11, TypeUint32, ""),
			rw("ESRmpTms", 13, TypeUint32, ""),
			r("ESDlyRemTms", 15, TypeUint32, ""),
			r("V_SF", 17, TypeSunSSF, ""),
			r("Hz_SF", 18, TypeSunSSF, ""),
		},
	})

	// --- Model 704, DERCtlAC -------------------------------------------
	//
	// The four trailing power-factor groups are `sync` groups of count 1: their
	// two members must be read and written atomically. They are transcribed as
	// their members ("PFWInj.PF" / "PFWInj.Ext") because that is what occupies
	// registers; the group itself has no registers of its own.
	register(&Model{
		ID: 704, Name: "DERCtlAC", L: 65,
		Source: "SunSpec DER Information Model Specification v1.2 §4 (DERCtlAC)",
		Points: []Point{
			mand(r("ID", 0, TypeUint16, "")),
			mand(r("L", 1, TypeUint16, "")),
			rw("PFWInjEna", 2, TypeEnum16, ""),
			rw("PFWInjEnaRvrt", 3, TypeEnum16, ""),
			rw("PFWInjRvrtTms", 4, TypeUint32, ""),
			r("PFWInjRvrtRem", 6, TypeUint32, ""),
			rw("PFWAbsEna", 8, TypeEnum16, ""),
			rw("PFWAbsEnaRvrt", 9, TypeEnum16, ""),
			rw("PFWAbsRvrtTms", 10, TypeUint32, ""),
			r("PFWAbsRvrtRem", 12, TypeUint32, ""),
			rw("WMaxLimPctEna", 14, TypeEnum16, ""),
			rw("WMaxLimPct", 15, TypeUint16, "WMaxLimPct_SF"),
			rw("WMaxLimPctRvrt", 16, TypeUint16, "WMaxLimPct_SF"),
			rw("WMaxLimPctEnaRvrt", 17, TypeEnum16, ""),
			rw("WMaxLimPctRvrtTms", 18, TypeUint32, ""),
			r("WMaxLimPctRvrtRem", 20, TypeUint32, ""),
			rw("WSetEna", 22, TypeEnum16, ""),
			rw("WSetMod", 23, TypeEnum16, ""),
			rw("WSet", 24, TypeInt32, "WSet_SF"),
			rw("WSetRvrt", 26, TypeInt32, "WSet_SF"),
			rw("WSetPct", 28, TypeInt16, "WSetPct_SF"),
			rw("WSetPctRvrt", 29, TypeInt16, "WSetPct_SF"),
			rw("WSetEnaRvrt", 30, TypeEnum16, ""),
			rw("WSetRvrtTms", 31, TypeUint32, ""),
			r("WSetRvrtRem", 33, TypeUint32, ""),
			rw("VarSetEna", 35, TypeEnum16, ""),
			rw("VarSetMod", 36, TypeEnum16, ""),
			rw("VarSetPri", 37, TypeEnum16, ""),
			rw("VarSet", 38, TypeInt32, "VarSet_SF"),
			rw("VarSetRvrt", 40, TypeInt32, "VarSet_SF"),
			rw("VarSetPct", 42, TypeInt16, "VarSetPct_SF"),
			rw("VarSetPctRvrt", 43, TypeInt16, "VarSetPct_SF"),
			rw("VarSetEnaRvrt", 44, TypeEnum16, ""),
			rw("VarSetRvrtTms", 45, TypeUint32, ""),
			r("VarSetRvrtRem", 47, TypeUint32, ""),
			rw("WRmp", 49, TypeUint16, ""),
			rw("WRmpRef", 50, TypeEnum16, ""),
			r("VarRmp", 51, TypeUint16, ""),
			rw("AntiIslEna", 52, TypeEnum16, ""),
			r("PF_SF", 53, TypeSunSSF, ""),
			r("WMaxLimPct_SF", 54, TypeSunSSF, ""),
			r("WSet_SF", 55, TypeSunSSF, ""),
			r("WSetPct_SF", 56, TypeSunSSF, ""),
			r("VarSet_SF", 57, TypeSunSSF, ""),
			r("VarSetPct_SF", 58, TypeSunSSF, ""),
			rw("PFWInj.PF", 59, TypeUint16, "PF_SF"),
			rw("PFWInj.Ext", 60, TypeEnum16, ""),
			rw("PFWInjRvrt.PF", 61, TypeUint16, "PF_SF"),
			rw("PFWInjRvrt.Ext", 62, TypeEnum16, ""),
			rw("PFWAbs.PF", 63, TypeUint16, "PF_SF"),
			rw("PFWAbs.Ext", 64, TypeEnum16, ""),
			rw("PFWAbsRvrt.PF", 65, TypeUint16, "PF_SF"),
			rw("PFWAbsRvrt.Ext", 66, TypeEnum16, ""),
		},
	})

	// --- Model 713, DERStorageCapacity ---------------------------------
	register(&Model{
		ID: 713, Name: "DERStorageCapacity", L: 7,
		Source: "SunSpec DER Information Model Specification v1.2 §4 (DERStorageCapacity)",
		Points: []Point{
			mand(r("ID", 0, TypeUint16, "")),
			mand(r("L", 1, TypeUint16, "")),
			r("WHRtg", 2, TypeUint16, "WH_SF"),
			r("WHAvail", 3, TypeUint16, "WH_SF"),
			r("SoC", 4, TypeUint16, "Pct_SF"),
			r("SoH", 5, TypeUint16, "Pct_SF"),
			r("Sta", 6, TypeEnum16, ""),
			r("WH_SF", 7, TypeSunSSF, ""),
			r("Pct_SF", 8, TypeSunSSF, ""),
		},
	})

	// --- Model 714, DERMeasureDC (fixed header only) -------------------
	//
	// 714 carries a repeating per-port group whose count is the NPrt point, so
	// its length is runtime-variable: L = 18 + NPrt*33. The transcription below
	// is the FIXED HEADER, which is the whole model when NPrt is 0 — the
	// spec-legal "no per-port breakdown" shape the DUT projects. L is left 0
	// here because a fixed expectation would be wrong for any other NPrt;
	// expectedLen computes it.
	register(&Model{
		ID: 714, Name: "DERMeasureDC", L: 0,
		Source: "SunSpec DER Information Model Specification v1.2 §4 (DERMeasureDC), fixed header",
		Points: []Point{
			mand(r("ID", 0, TypeUint16, "")),
			mand(r("L", 1, TypeUint16, "")),
			r("PrtAlrms", 2, TypeBitfield32, ""),
			r("NPrt", 4, TypeUint16, ""),
			r("DCA", 5, TypeInt16, "DCA_SF"),
			r("DCW", 6, TypeInt16, "DCW_SF"),
			r("DCWhInj", 7, TypeUint64, "DCWH_SF"),
			r("DCWhAbs", 11, TypeUint64, "DCWH_SF"),
			r("DCA_SF", 15, TypeSunSSF, ""),
			r("DCV_SF", 16, TypeSunSSF, ""),
			r("DCW_SF", 17, TypeSunSSF, ""),
			r("DCWH_SF", 18, TypeSunSSF, ""),
			r("Tmp_SF", 19, TypeSunSSF, ""),
		},
	})

	// The transcription must be self-consistent: every fixed-length model's
	// declared L has to equal the register span of its own point table, and no
	// two points may overlap except a sync group's members (which are
	// transcribed as members only, so they never do). A typo in an offset above
	// therefore fails at package init rather than being reported as a DUT
	// defect.
	for _, m := range Models {
		if m.L == 0 {
			continue
		}
		if got := m.span() - 2; got != m.L {
			panic(fmt.Sprintf("suitemodbusserver: model %d transcription spans %d data registers "+
				"but declares L=%d", m.ID, got, m.L))
		}
	}

	// The curve table has to be self-consistent too, and for a sharper reason
	// than the models above: CRV-1 WRITES to the register a legacy entry's
	// Probe names. A probe whose key and ID disagreed, or whose offset landed
	// in the model's [ID, L] header, or that spanned more than one register,
	// would make this suite write somewhere it did not mean to and then report
	// the resulting refusal as if it were about the point it named. Failing at
	// package init is the only acceptable time to discover that.
	for id, cm := range curveModels {
		if cm.ID != id {
			panic(fmt.Sprintf("suitemodbusserver: curveModels[%d] carries ID %d", id, cm.ID))
		}
		if !cm.HasProbe() {
			if cm.Served && cm.Gen == curveGenLegacy {
				panic(fmt.Sprintf("suitemodbusserver: legacy model %d is served but carries no probe point, "+
					"so CRV-1 would report it as unverifiable for a reason that is not true", id))
			}
			continue
		}
		if !cm.Served {
			panic(fmt.Sprintf("suitemodbusserver: model %d is not served but carries a probe point", id))
		}
		if cm.Probe.Off < 2 {
			panic(fmt.Sprintf("suitemodbusserver: model %d's probe point %s sits at offset %d, inside the "+
				"model's own [ID, L] header", id, cm.Probe.Name, cm.Probe.Off))
		}
		if cm.Probe.Regs() != 1 {
			panic(fmt.Sprintf("suitemodbusserver: model %d's probe point %s is %d registers wide; CRV-1's "+
				"write probe must be a single-register whole point so a refusal cannot be a "+
				"partial-point refusal wearing the wrong name", id, cm.Probe.Name, cm.Probe.Regs()))
		}
		if cm.ProbeSource == "" {
			panic(fmt.Sprintf("suitemodbusserver: model %d's probe point has no transcription source", id))
		}
	}
}

// expectedLen returns the L a conformant instance of the model must report,
// given the geometry points already read from the device. The second result is
// false when the length cannot be predicted from the transcription (a
// variable-geometry model whose count point was not supplied).
func expectedLen(id uint16, geometry map[string]uint16) (int, bool) {
	m, ok := Models[id]
	if !ok {
		return 0, false
	}
	if m.L != 0 {
		return m.L, true
	}
	if id == 714 {
		nprt, ok := geometry["NPrt"]
		if !ok {
			return 0, false
		}
		// Fixed header (18 data registers) plus NPrt port blocks of 33.
		return 18 + int(nprt)*33, true
	}
	return 0, false
}

// ─── The curve families ────────────────────────────────────────────────────
//
// curveModels is every model CRV-1 (§2.5.1) and the MOD-1..MOD-3 sweeps have
// to reason about WITHOUT a full point-table transcription. Two generations
// sit in it and they are not interchangeable:
//
//   - The 7xx family, 705-712 (DER Information Model Specification v1.2 §4).
//     Runtime geometry: each sizes its repeating blocks from the NPt / NCrv /
//     NCrvSet / NCtl points read out of the device, so no fixed table exists
//     to transcribe and a check that meets one says so rather than guessing.
//
//   - The LEGACY 12x family — 126, 127, 128, 129, 130, 131, 132, 134 and the
//     160 MPPT extension — which the gateway's Stage-6 read-only projection
//     serves AS ITSELF rather than translating into a 7xx (the D4
//     read-only-verbatim decision, lexa-gw
//     docs/design/LEGACY_CURVES_RC0_2026-08-14.md §5.5, wired in
//     internal/regmap/chain.go's modelLayouts at chain.go:111-119 and
//     classChainModels at chain.go:175-179/189-193). They are chained
//     DEVICE-CONDITIONALLY, exactly as the 7xx family is
//     (deviceConditionalModels, chain.go:251-259), so a unit carries one if
//     and only if its own DER serves it southbound. Their blocks are FLAT — a
//     fixed 54/50/58-register bank repeated NCrv times, with twenty point
//     slots whatever NPt declares — rather than runtime-sized, but this suite
//     still carries no transcription of them, so the same "no per-point
//     sweep" rule applies.
//
// # What the legacy entries carry that the 7xx entries do not
//
// Each served legacy entry carries a Probe: ONE transcribed point, which is
// what lets CRV-1 verify the read-only posture on that model without knowing
// the rest of its block. The asymmetry is a fact about the DUT, not an
// inconsistency here.
//
// On the legacy family the product's posture is UNIVERSAL: not one point of
// any of the nine has an executor, so writes.CheckExecutable refuses every
// write to every point of every one of them BEFORE the Modbus acknowledgement
// (lexa-gw internal/regmap/pointgroups.go:262-273, asserted there by
// TestLegacy_EveryWriteIsRefusedBeforeTheAck). A universal claim is falsified
// by ANY acknowledged write, so it can be probed at any register this suite
// can name — it needs one point's offset and width, not the whole block.
//
// On 705-712 there is no such universal claim. Those models have a commanded
// point group and a write path design Stage 5 will build, and CRV-1's steps 2
// and 3 are specifically about CURVE 1's registers, which cannot be located
// without the geometry this suite does not transcribe. So the 7xx entries
// carry no probe and CRV-1 keeps saying, per step, that it did not reach them.
//
// Model 133 is in the table with Served false. SunSpec's 12x block is not
// contiguous, and the DUT's projection does not serve 133 on any unit of any
// class or DER: chain.go's modelLayouts has no entry for it, and the D4
// decision's own enumeration of the family (pointgroups.go:264, "126/127/128/
// 129/130/131/132/134/160") omits it. Carrying it here as an explicit
// not-served entry is what lets CRV-1 report a NAMED row for it instead of
// leaving a hole in the 126-134 range that a reader would have to notice.
type curveGeneration int

// The two curve generations.
const (
	// curveGen7xx is the DER Information Model Specification's 705-712.
	curveGen7xx curveGeneration = iota
	// curveGenLegacy is the SunSpec inverter-controls 12x family plus 160.
	curveGenLegacy
)

// curveModel is one entry of curveModels.
type curveModel struct {
	// ID is the SunSpec model identifier.
	ID uint16
	// Name is the model definition's own name, as a reader of the SunSpec
	// model definitions would look it up.
	Name string
	// Gen is which generation the model belongs to.
	Gen curveGeneration
	// CurveBased reports whether the model is a BREAKPOINT-CURVE model, which
	// is the scope CTP §2.5's precondition names ("each curve-based model
	// implemented in the device"). It is false for the members of both
	// generations that are shaped like something else: 711 is a droop control
	// block (NCtl control blocks, no point array), 127 is a parameterised
	// gradient with start/stop frequencies, 128 is a dynamic reactive-current
	// parameter block, and 160 is DC telemetry. They stay IN this table
	// because MOD-1..MOD-3 must still report them as untranscribed and because
	// the D4 read-only posture covers all nine legacy models; they are simply
	// outside the procedure's own precondition, and CRV-1 says which is which
	// rather than folding them together.
	CurveBased bool
	// Served reports whether the DUT's northbound projection can serve this
	// model at all, on any unit. False only for 133 — see the block comment.
	Served bool
	// NotServed is why the model is not served, and is set only when Served is
	// false.
	NotServed string
	// Probe is the ONE point of this model this suite transcribes, and the
	// register CRV-1's read-only verification targets. Meaningful only for a
	// served legacy entry; the zero value means "no probe", which is what
	// every 7xx entry carries.
	Probe Point
	// ProbeSource names where the probe point's offset, type and width were
	// transcribed from, so a reviewer can check the one number this suite's
	// legacy verification rests on.
	ProbeSource string
}

// HasProbe reports whether CRV-1 can verify this model's read-only posture.
func (cm curveModel) HasProbe() bool { return cm.Probe.Name != "" }

// noLayoutReason is what a check that met this model on the wire says instead
// of sweeping its points. It names the SUITE's gap rather than anything about
// the DUT, because a reader who mistook it for a DUT finding would be reading a
// harness limit as a defect.
func (cm curveModel) noLayoutReason() string {
	switch {
	case !cm.Served:
		return fmt.Sprintf("model %d is not part of the DUT's northbound projection and this suite carries "+
			"no transcription of it, so its point set cannot be checked", cm.ID)
	case cm.Gen == curveGenLegacy:
		return fmt.Sprintf("model %d is a legacy (12x) curve-family model. The DUT serves it flat, but its "+
			"block is a fixed-size bank repeated NCrv times carrying twenty point slots whatever NPt "+
			"declares, and this suite transcribes only its first data point (%s) — enough to verify the "+
			"read-only posture CRV-1 asks about, not enough for a per-point sweep, which would be guessing",
			cm.ID, cm.Probe.Name)
	default:
		return fmt.Sprintf("model %d is a runtime-geometry curve model: its register offsets depend on the "+
			"NPt / NCrv / NCrvSet / NCtl points read from the device, and this suite carries no "+
			"transcription of its layout, so a per-point sweep would be guessing", cm.ID)
	}
}

// legacyProbeSource is the provenance every legacy probe point shares. The
// point tables come from the SunSpec model definitions themselves, transcribed
// here exactly as the rest of this file is — NOT read out of
// lexa-proto/sunspec/legacycurve.go, which is the table the DUT encodes with.
// The transcription is deliberately MINIMAL, one point per model, so that no
// claim this suite makes about the legacy surface rests on a guessed offset.
const legacyProbeSource = "the SunSpec model definition's own point table, transcribed here (not imported " +
	"from the layout package the DUT encodes with)"

// curveModels is the table itself. Its keys are the only model ids this suite
// treats as curve-family.
var curveModels = map[uint16]curveModel{
	// ── The legacy 12x family ──────────────────────────────────────────────
	//
	// 126/129/130/131/132/134 all open their data block with ActCrv, the
	// 1-based index of the live curve bank: one uint16 register at model
	// offset 2 (data offset 0). It is the natural probe — a single-register
	// whole point, so a write to it can never be refused merely for starting
	// or ending mid-point, which would make the refusal say something other
	// than what CRV-1 is asking.
	126: {
		ID: 126, Name: "volt_var (Static Volt-VAr Arrays)", Gen: curveGenLegacy,
		CurveBased: true, Served: true,
		Probe:       rw("ActCrv", 2, TypeUint16, ""),
		ProbeSource: legacyProbeSource,
	},
	127: {
		ID: 127, Name: "freq_watt_param (Parameterized Frequency-Watt)", Gen: curveGenLegacy,
		CurveBased: false, Served: true,
		// 127 has no repeating group at all; its block opens with WGra, the
		// droop gradient in % of PM per Hz — one uint16 register.
		Probe:       rw("WGra", 2, TypeUint16, "WGra_SF"),
		ProbeSource: legacyProbeSource,
	},
	128: {
		ID: 128, Name: "reactive_current (Dynamic Reactive Current)", Gen: curveGenLegacy,
		CurveBased: false, Served: true,
		// Likewise no repeating group; ArGraMod (0 EDGE, 1 CENTER) is the
		// first point, an enum16 in one register.
		Probe:       rw("ArGraMod", 2, TypeEnum16, ""),
		ProbeSource: legacyProbeSource,
	},
	129: {
		ID: 129, Name: "lvrt (LVRT Must Disconnect)", Gen: curveGenLegacy,
		CurveBased: true, Served: true,
		Probe:       rw("ActCrv", 2, TypeUint16, ""),
		ProbeSource: legacyProbeSource,
	},
	130: {
		ID: 130, Name: "hvrt (HVRT Must Disconnect)", Gen: curveGenLegacy,
		CurveBased: true, Served: true,
		Probe:       rw("ActCrv", 2, TypeUint16, ""),
		ProbeSource: legacyProbeSource,
	},
	131: {
		ID: 131, Name: "watt_pf (Watt-Power Factor)", Gen: curveGenLegacy,
		CurveBased: true, Served: true,
		Probe:       rw("ActCrv", 2, TypeUint16, ""),
		ProbeSource: legacyProbeSource,
	},
	132: {
		ID: 132, Name: "volt_watt (Volt-Watt)", Gen: curveGenLegacy,
		CurveBased: true, Served: true,
		Probe:       rw("ActCrv", 2, TypeUint16, ""),
		ProbeSource: legacyProbeSource,
	},
	133: {
		ID: 133, Name: "(not served)", Gen: curveGenLegacy,
		CurveBased: false, Served: false,
		NotServed: "the DUT's northbound projection registers no layout for model 133 (lexa-gw " +
			"internal/regmap/chain.go's modelLayouts, chain.go:84-120), and the D4 read-only-verbatim " +
			"decision that put the legacy family northbound enumerates it as 126/127/128/129/130/131/132/" +
			"134/160 (internal/regmap/pointgroups.go:264) — 133 is absent from both. Its absence is " +
			"therefore NOT the device-conditional absence the other eight can have: no unit, of any " +
			"class, behind any DER, can carry a 133 on this build, so the procedure has no subject for " +
			"it here and never will on this projection",
	},
	134: {
		ID: 134, Name: "freq_watt (Curve-Based Frequency-Watt)", Gen: curveGenLegacy,
		CurveBased: true, Served: true,
		Probe:       rw("ActCrv", 2, TypeUint16, ""),
		ProbeSource: legacyProbeSource,
	},
	160: {
		ID: 160, Name: "mppt (Multiple MPPT Inverter Extension)", Gen: curveGenLegacy,
		CurveBased: false, Served: true,
		// 160's block opens with its four scale factors, then a bitfield32
		// Evt, then N — the number of DC-input module blocks that follow, at
		// data offset 6 (model offset 8). N is the probe rather than the
		// leading DCA_SF because a refusal on a scale factor is ALSO covered
		// by the DUT's never-write-a-scale-factor rule, so it would not be
		// evidence about the legacy read-only posture specifically. NO point
		// of model 160 declares an access key at all, so every one of them is
		// read-only by the SunSpec default — which is why 160's refusal comes
		// from the write decoder rather than from the executor gate the other
		// eight trip (see checks_crv.go's refusal ladder).
		Probe:       r("N", 8, TypeUint16, ""),
		ProbeSource: legacyProbeSource,
	},

	// ── The 7xx family ─────────────────────────────────────────────────────
	//
	// No probes: see the block comment. 711 is marked not curve-based because
	// it is a droop CONTROL block (NCtl blocks of gains and deadbands, no
	// point array) rather than a breakpoint curve; CTP §2.5's precondition
	// names curve-based models, and folding 711 in with 705/706/707-710/712
	// would overstate what the precondition found.
	705: {ID: 705, Name: "DERVoltVar", Gen: curveGen7xx, CurveBased: true, Served: true},
	706: {ID: 706, Name: "DERVoltWatt", Gen: curveGen7xx, CurveBased: true, Served: true},
	707: {ID: 707, Name: "DERTripLV", Gen: curveGen7xx, CurveBased: true, Served: true},
	708: {ID: 708, Name: "DERTripHV", Gen: curveGen7xx, CurveBased: true, Served: true},
	709: {ID: 709, Name: "DERTripLF", Gen: curveGen7xx, CurveBased: true, Served: true},
	710: {ID: 710, Name: "DERTripHF", Gen: curveGen7xx, CurveBased: true, Served: true},
	711: {ID: 711, Name: "DERFreqDroop", Gen: curveGen7xx, CurveBased: false, Served: true},
	712: {ID: 712, Name: "DERWattVar", Gen: curveGen7xx, CurveBased: true, Served: true},
}

// curveModelIDs returns every curve-family model id, ascending. CRV-1 reports
// in this order so a reader can check the 126-134/160 range against the report
// without holding the table in their head.
func curveModelIDs() []uint16 {
	out := make([]uint16, 0, len(curveModels))
	for id := range curveModels {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
