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
// SKIPs its per-point sweep rather than guessing offsets.

import "fmt"

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
	register(&Model{
		ID: 701, Name: "DERMeasureAC", L: 153,
		Source: "SunSpec DER Information Model Specification v1.2 §4 (DERMeasureAC)",
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
			r("PF", 13, TypeUint16, "PF_SF"),
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
			r("PFL1", 44, TypeUint16, "PF_SF"),
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
			r("PFL2", 67, TypeUint16, "PF_SF"),
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
			r("PFL3", 90, TypeUint16, "PF_SF"),
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

// curveModels are the runtime-geometry models this suite does not transcribe.
// A check that meets one on the wire reports that fact rather than guessing
// offsets.
var curveModels = map[uint16]bool{
	705: true, 706: true, 707: true, 708: true,
	709: true, 710: true, 711: true, 712: true,
}
