// Package sunspec provides SunSpec model discovery and register access on
// top of a Modbus transport. The SunSpec Alliance defines standardized
// Modbus information models (github.com/sunspec/models) supported by most
// grid-tied inverters and batteries manufactured after ~2018.
//
// Entry point: NewReader(transport) scans the device's SunSpec block layout
// then provides ReadModel / WriteModel helpers so callers work with 0-based
// offsets within a named model, not raw Modbus addresses.
package sunspec

// Well-known SunSpec model IDs referenced by this package.
// See the SunSpec Alliance model registry for the full list.
const (
	// ── Legacy / transitional models (pre-IEEE 1547-2018) ────────────────
	ModelCommon           = uint16(1)   // manufacturer, serial number, model, version
	ModelInverterSinglePh = uint16(101) // single-phase inverter measurements
	ModelInverterSplitPh  = uint16(102) // split-phase inverter measurements
	ModelInverterThreePh  = uint16(103) // three-phase inverter measurements
	ModelNameplate        = uint16(120) // DER nameplate ratings
	ModelBasicSettings    = uint16(121) // DER operational settings (WMax, etc.)
	ModelExtendedStatus   = uint16(122) // extended measurements & connection status
	ModelImmediateCtrl    = uint16(123) // immediate controls: WMaxLimPct, Conn, etc.
	ModelBatteryBase      = uint16(801) // battery base model
	ModelLithiumBattery   = uint16(802) // lithium battery detail

	// ── IEEE 1547-2018 SunSpec Modbus Profile (models 701-713) ───────────
	// Reference: SunSpec Modbus IEEE 1547-2018 Profile Specification §2.1
	// These supersede the legacy models for compliant implementations.
	ModelDERMeasureAC    = uint16(701) // DER AC measurements (replaces M103 for 1547)
	ModelDERCapacity     = uint16(702) // DER nameplate + configuration (replaces M120/121)
	ModelDEREnterService = uint16(703) // enter-service / cease-to-energize settings
	ModelDERCtlAC        = uint16(704) // constant PF, constant var, active power limit
	ModelDERVoltVar      = uint16(705) // voltage-reactive power curve (Q(V))
	ModelDERVoltWatt     = uint16(706) // voltage-active power curve (P(V))
	ModelDERTripLV       = uint16(707) // low-voltage trip curve
	ModelDERTripHV       = uint16(708) // high-voltage trip curve
	ModelDERTripLF       = uint16(709) // low-frequency trip curve
	ModelDERTripHF       = uint16(710) // high-frequency trip curve
	ModelDERFreqDroop    = uint16(711) // frequency droop (P(f))
	ModelDERWattVar      = uint16(712) // active power-reactive power curve (Q(P))
	ModelDERStorageCap   = uint16(713) // storage state-of-charge and capacity
)

// SunSpec binary header constants.
const (
	// SunSMagic0 and SunSMagic1 are the two registers that form the ASCII
	// string "SunS" at the start of the SunSpec address space.
	SunSMagic0 = uint16(0x5375) // 'S','u'
	SunSMagic1 = uint16(0x6E53) // 'n','S'

	// EndMarker is the model ID that terminates the SunSpec model list.
	EndMarker = uint16(0xFFFF)

	// SunSpecBase is the most common 0-based Modbus starting address for the
	// SunSpec header (corresponds to Modbus register 40001 in 1-based notation).
	// Per the SunSpec spec, devices may also start at 0 or 50000; the vast
	// majority of commercial hardware uses 40000.
	SunSpecBase = uint16(40000)
)

// ── Model 103 (Three-Phase Inverter) register offsets ────────────────────────
// 0-based within the model data block (i.e. after the model ID and length regs).
// Source: SunSpec Model 103 specification.
const (
	M103_A       = 0  // AC total current (int16, A_SF)
	M103_AphA    = 1  // Phase A current (int16, A_SF)
	M103_AphB    = 2  // Phase B current (int16, A_SF)
	M103_AphC    = 3  // Phase C current (int16, A_SF)
	M103_A_SF    = 4  // current scale factor (int16, power of 10)
	M103_PPVphAB = 5  // Phase A-B voltage (uint16, V_SF)
	M103_PPVphBC = 6  // Phase B-C voltage (uint16, V_SF)
	M103_PPVphCA = 7  // Phase C-A voltage (uint16, V_SF)
	M103_PhVphA  = 8  // Phase A-N voltage (uint16, V_SF)
	M103_PhVphB  = 9  // Phase B-N voltage (uint16, V_SF)
	M103_PhVphC  = 10 // Phase C-N voltage (uint16, V_SF)
	M103_V_SF    = 11 // voltage scale factor (int16)
	M103_W       = 12 // AC power (int16, W_SF)
	M103_W_SF    = 13 // power scale factor (int16)
	M103_Hz      = 14 // frequency (uint16, Hz_SF)
	M103_Hz_SF   = 15 // frequency scale factor (int16)
	M103_VA      = 16 // apparent power (int16, VA_SF)
	M103_VA_SF   = 17 // apparent power scale factor (int16)
	M103_VAr     = 18 // reactive power (int16, VAr_SF)
	M103_VAr_SF  = 19 // reactive power scale factor (int16)
	M103_PF      = 20 // power factor ×100 (int16, PF_SF)
	M103_PF_SF   = 21 // power factor scale factor (int16)
	// WH is AC lifetime energy production: an acc32 spanning offsets 22-23,
	// big-endian (high word first), scaled by M103_WH_SF. It is the legacy
	// model's ONLY accumulator and the only 10x point that can contradict a
	// frozen power reading (a block claiming 5 kW whose lifetime Wh never
	// advances is claiming something physically impossible), which is why it is
	// named here rather than left as the bare "offsets 22-23" comment it was.
	//
	// PRESENCE IS DECIDED BY THE SCALE FACTOR, not by the accumulator's own
	// value. Per the SunSpec type table an acc32 reserves NO not-implemented
	// sentinel — 0 is a legitimate "has not accumulated anything yet" — so a
	// device that does not implement WH is recognised by leaving WH_SF at the
	// int16 sentinel (or outside the legal sunssf domain), exactly the test
	// View.SF already applies.
	M103_WH      = 22 // AC lifetime energy production (acc32, regs 22-23, M103_WH_SF) — Wh
	M103_WH_SF   = 24 // energy scale factor (int16)
	M103_DCA     = 25 // DC current (int16, DCA_SF)
	M103_DCA_SF  = 26 // DC current scale factor (int16)
	M103_DCV     = 27 // DC voltage (uint16, DCV_SF)
	M103_DCV_SF  = 28 // DC voltage scale factor (int16)
	M103_DCW     = 29 // DC power (int16, DCW_SF)
	M103_DCW_SF  = 30 // DC power scale factor (int16)
	M103_TmpCab  = 31 // cabinet temperature (int16, Tmp_SF)
	M103_TmpSnk  = 32 // heat sink temperature (int16, Tmp_SF)
	M103_TmpTrns = 33 // transformer temperature (int16, Tmp_SF)
	M103_TmpOt   = 34 // other temperature (int16, Tmp_SF)
	M103_Tmp_SF  = 35 // temperature scale factor (int16)
	M103_St      = 36 // operating state (uint16): 1=Off 2=Sleeping 3=Starting
	//   4=MPPT 5=Throttled 6=ShuttingDown 7=Fault 8=Standby
	M103_StVnd = 37 // vendor status (uint16)
	// Evt1/Evt2 at 38-41 (two uint32s each spanning two registers)
)

// ── Model 120 (Nameplate Ratings) ────────────────────────────────────────────
//
// # This map was WRONG at 22 of its 25 points (REV0907-D1)
//
// Like M123 before it (see that section below), M120 was hand-transcribed
// with no spec source on the machine. The transcription assumed every scale
// factor trailed its own point immediately, which is true only for WRtg_SF —
// every SF after it was written one point EARLY relative to the published
// model, and the reactive-power quadruplet (VArRtgQ1..Q4) was placed one
// register early as well, dragging every offset after it out of alignment
// too. The worst instance: the transcription invented a point "M120_W_SF" at
// offset 16, believing it was the power scale factor — offset 16 belongs to
// PFRtg_SF. The real power scale factor is WRtg_SF, immediately after WRtg at
// offset 2, exactly where the published model puts it and exactly where a
// consumer reading WRtg needed to look.
//
// lexa-gw's identify.go (readNameplateW / legacyWRtg) is the sole consumer of
// M120_WRtg and the deleted M120_W_SF; WP4-T2 repoints it at M120_WRtg_SF at
// the next pin bump. Deleting the wrong name here rather than leaving it
// wrong-but-compiling is the same call models.go made for M123's
// M123_Conn_RmpTms: a name that used to point at a real register but does not
// exist in the standard must not keep compiling silently.
//
// L120 is derived from docs/schema/sunspec-models/model_120.json exactly like
// L123, and TestLayoutsMatchVendoredSpec proves it against the JSON's own
// names, order, types, widths and access/mandatory flags.
var L120 = NewLayout(
	F("DERTyp", Tenum16).R().M(), // 4=PV, 82=PV_STOR
	FS("WRtg", Tuint16, "WRtg_SF").R().M(),
	F("WRtg_SF", Tsunssf).R().M(),
	FS("VARtg", Tuint16, "VARtg_SF").R().M(),
	F("VARtg_SF", Tsunssf).R().M(),
	FS("VArRtgQ1", Tint16, "VArRtg_SF").R().M(),
	FS("VArRtgQ2", Tint16, "VArRtg_SF").R().M(),
	FS("VArRtgQ3", Tint16, "VArRtg_SF").R().M(),
	FS("VArRtgQ4", Tint16, "VArRtg_SF").R().M(),
	F("VArRtg_SF", Tsunssf).R().M(),
	FS("ARtg", Tuint16, "ARtg_SF").R().M(),
	F("ARtg_SF", Tsunssf).R().M(),
	FS("PFRtgQ1", Tint16, "PFRtg_SF").R().M(),
	FS("PFRtgQ2", Tint16, "PFRtg_SF").R().M(),
	FS("PFRtgQ3", Tint16, "PFRtg_SF").R().M(),
	FS("PFRtgQ4", Tint16, "PFRtg_SF").R().M(),
	F("PFRtg_SF", Tsunssf).R().M(),
	FS("WHRtg", Tuint16, "WHRtg_SF").R().O(),
	F("WHRtg_SF", Tsunssf).R().O(),
	FS("AhrRtg", Tuint16, "AhrRtg_SF").R().O(),
	F("AhrRtg_SF", Tsunssf).R().O(),
	FS("MaxChaRte", Tuint16, "MaxChaRte_SF").R().O(),
	F("MaxChaRte_SF", Tsunssf).R().O(),
	FS("MaxDisChaRte", Tuint16, "MaxDisChaRte_SF").R().O(),
	F("MaxDisChaRte_SF", Tsunssf).R().O(),
	FPad("Pad", 1).R().O(),
).As("M120")

// M120 register offsets, restated from L120 (REV0907-D1). M120_W_SF is
// DELETED — no revision of model 120 declares a point by that name at any
// offset; the power scale factor is M120_WRtg_SF, added here at the offset
// the published model actually uses. Every surviving name is unchanged so
// that a consumer which was already spelling the point correctly keeps
// compiling; only the values move to match L120. Pad carries no constant:
// nothing in this tree reads or writes it.
//
// TestM120ConstantsMatchTheLayout is the drift guard, the twin of
// TestM123ConstantsMatchTheLayout: it asserts every constant below equals
// L120's offset for the point by NAME, so a hand edit here can never again
// disagree with the layout — and the layout is in turn proven against the
// vendored JSON by TestLayoutsMatchVendoredSpec.
const (
	M120Len              = 26 // data registers — equals L120.Len(), asserted by the drift guard
	M120_DERTyp          = 0  // DER type (uint16): 4=PV, 82=PV_STOR
	M120_WRtg            = 1  // nameplate real power (uint16, M120_WRtg_SF)
	M120_WRtg_SF         = 2  // power scale factor (int16) — the published home of the SF
	M120_VARtg           = 3  // nameplate apparent power (uint16, M120_VARtg_SF)
	M120_VARtg_SF        = 4
	M120_VArRtgQ1        = 5 // max reactive power Q1 (int16, M120_VArRtg_SF)
	M120_VArRtgQ2        = 6 // Q2
	M120_VArRtgQ3        = 7 // Q3
	M120_VArRtgQ4        = 8 // Q4
	M120_VArRtg_SF       = 9
	M120_ARtg            = 10 // nameplate current (uint16, M120_ARtg_SF)
	M120_ARtg_SF         = 11
	M120_PFRtgQ1         = 12 // min power factor Q1 ×100 (int16, M120_PFRtg_SF)
	M120_PFRtgQ2         = 13
	M120_PFRtgQ3         = 14
	M120_PFRtgQ4         = 15
	M120_PFRtg_SF        = 16
	M120_WHRtg           = 17 // energy storage rating (uint16, M120_WHRtg_SF) — storage
	M120_WHRtg_SF        = 18
	M120_AhrRtg          = 19 // amp-hour rating (uint16, M120_AhrRtg_SF)
	M120_AhrRtg_SF       = 20
	M120_MaxChaRte       = 21 // max charge rate (uint16, M120_MaxChaRte_SF) — storage
	M120_MaxChaRte_SF    = 22
	M120_MaxDisChaRte    = 23 // max discharge rate (uint16, M120_MaxDisChaRte_SF)
	M120_MaxDisChaRte_SF = 24
)

// ── Model 122 (Extended Measurements & Status) ───────────────────────────────
//
// # WAval / WAval_SF were WRONG, sitting inside another point's accumulator (REV0907-D2)
//
// The hand table put WAval at offset 21 and WAval_SF at 22 — inside the
// ActVArhQ3 acc64 (offsets 19-22), so a read of "available watts" actually
// read half of a lifetime reactive-energy accumulator, reinterpreted as a
// small int16. The published model's four lifetime accumulators (ActWh,
// ActVAh, ActVArhQ1..Q4) are each 4 registers (acc64), not the 2 the old
// table implicitly assumed by starting VArAval/WAval at offset 21; the real
// WAval/WAval_SF sit at 29/30, after VArAval/VArAval_SF at 27/28.
// derbase/liveness.go's m122Volatile reads M122_WAval as one of the last-
// resort liveness points for a legacy device with no second AC model — it
// was digesting the wrong register and is correct by construction once L122
// is proven against the JSON below.
//
// L122 is derived from docs/schema/sunspec-models/model_122.json exactly
// like L123 and L120, proven by TestLayoutsMatchVendoredSpec. Only the
// registers this codebase reads or writes are given restated constants; the
// full model is 44 registers and the sim populates the rest as zero.
var L122 = NewLayout(
	F("PVConn", Tbitfield16).R().M(), // bit 0 = connected
	F("StorConn", Tbitfield16).R().M(),
	F("ECPConn", Tbitfield16).R().M(), // bit 0 = grid-connected
	F("ActWh", Tacc64).R().O(),        // AC lifetime active energy, Wh
	F("ActVAh", Tacc64).R().O(),       // AC lifetime apparent energy, VAh
	F("ActVArhQ1", Tacc64).R().O(),    // AC lifetime reactive energy Q1, varh
	F("ActVArhQ2", Tacc64).R().O(),
	F("ActVArhQ3", Tacc64).R().O(),
	F("ActVArhQ4", Tacc64).R().O(),
	FS("VArAval", Tint16, "VArAval_SF").R().O(),
	F("VArAval_SF", Tsunssf).R().O(),
	FS("WAval", Tuint16, "WAval_SF").R().O(),
	F("WAval_SF", Tsunssf).R().O(),
	F("StSetLimMsk", Tbitfield32).R().O(),
	F("StActCtl", Tbitfield32).R().O(),
	FStr("TmSrc", 4).R().O(),
	F("Tms", Tuint32).R().O(),
	F("RtSt", Tbitfield16).R().O(),
	FS("Ris", Tuint16, "Ris_SF").R().O(),
	F("Ris_SF", Tsunssf).R().O(),
).As("M122")

// M122 register offsets, restated from L122 (REV0907-D2). TestM122ConstantsMatchTheLayout
// is the drift guard, the twin of TestM123ConstantsMatchTheLayout.
const (
	M122Len       = 44 // full model length per SunSpec spec — equals L122.Len()
	M122_PVConn   = 0  // PV connection status bitfield (uint16): bit 0 = connected
	M122_StorConn = 1  // storage connection status bitfield
	M122_ECPConn  = 2  // ECP / grid connection bitfield: bit 0 = grid-connected
	M122_ActWh    = 3  // AC lifetime active energy (acc64, regs 3-6), Wh
	M122_WAval    = 29 // available real power (uint16, M122_WAval_SF)
	M122_WAval_SF = 30 // scale factor (int16)
)

// ── Model 121 (Basic Settings) ───────────────────────────────────────────────
//
// M121_WMax and M121_WMax_SF were already at the published offsets (0 and
// 20) before this correction; they are restated below from L121 rather than
// left as bare literals so TestM121ConstantsMatchTheLayout closes the same
// loop the other legacy models now have: constant → L121 → vendored JSON →
// standard. L121 is derived from
// docs/schema/sunspec-models/model_121.json exactly like L120/L122/L123,
// proven by TestLayoutsMatchVendoredSpec.
var L121 = NewLayout(
	FS("WMax", Tuint16, "WMax_SF").RW().M(),
	FS("VRef", Tuint16, "VRef_SF").RW().M(),
	FS("VRefOfs", Tint16, "VRefOfs_SF").RW().M(),
	FS("VMax", Tuint16, "VMinMax_SF").RW().O(),
	FS("VMin", Tuint16, "VMinMax_SF").RW().O(),
	FS("VAMax", Tuint16, "VAMax_SF").RW().O(),
	FS("VArMaxQ1", Tint16, "VArMax_SF").RW().O(),
	FS("VArMaxQ2", Tint16, "VArMax_SF").RW().O(),
	FS("VArMaxQ3", Tint16, "VArMax_SF").RW().O(),
	FS("VArMaxQ4", Tint16, "VArMax_SF").RW().O(),
	FS("WGra", Tuint16, "WGra_SF").RW().O(),
	FS("PFMinQ1", Tint16, "PFMin_SF").RW().O(),
	FS("PFMinQ2", Tint16, "PFMin_SF").RW().O(),
	FS("PFMinQ3", Tint16, "PFMin_SF").RW().O(),
	FS("PFMinQ4", Tint16, "PFMin_SF").RW().O(),
	F("VArAct", Tenum16).RW().O(),   // 1=SWITCH, 2=MAINTAIN
	F("ClcTotVA", Tenum16).RW().O(), // 1=VECTOR, 2=ARITHMETIC
	FS("MaxRmpRte", Tuint16, "MaxRmpRte_SF").RW().O(),
	FS("ECPNomHz", Tuint16, "ECPNomHz_SF").RW().O(),
	F("ConnPh", Tenum16).RW().O(), // 1=A, 2=B, 3=C
	F("WMax_SF", Tsunssf).R().M(),
	F("VRef_SF", Tsunssf).R().M(),
	F("VRefOfs_SF", Tsunssf).R().M(),
	F("VMinMax_SF", Tsunssf).R().O(),
	F("VAMax_SF", Tsunssf).R().O(),
	F("VArMax_SF", Tsunssf).R().O(),
	F("WGra_SF", Tsunssf).R().O(),
	F("PFMin_SF", Tsunssf).R().O(),
	F("MaxRmpRte_SF", Tsunssf).R().O(),
	F("ECPNomHz_SF", Tsunssf).R().O(),
).As("M121")

// M121 register offsets — the mutable WMax setting. Values unchanged by this
// correction (both were already right); restated from L121, proven below.
const (
	M121_WMax    = 0  // max active power setpoint (uint16, WMax_SF)
	M121_WMax_SF = 20 // WMax scale factor (int16)
)

// ── Model 802 (Li-Ion Battery Base) ──────────────────────────────────────────
//
// # The hand table was wrong at every offset it declared (REV0907-D3)
//
// The old M802_* table claimed a 26-register model starting WHRtg(0),
// WHRtg_SF(1), AHRtg(2)... The published model is 62 registers and starts
// AHRtg(0), WHRtg(1), WChaRteMax(2)... — swapped order at the very first two
// points, and every offset after them wrong by construction. Two further
// defects rode along with the transcription: M802_HeatCool (offset 23) named
// a point no revision of model 802 declares — it is deleted outright, the
// same treatment M120_W_SF got under REV0907-D1 — and the old M802_W_SF
// (offset 6) was being used by lexa-gw and csip-tls-test as the scale factor
// for WChaRteMax/WDisChaRteMax, which is WChaDisChaMax_SF's job (offset 52)
// in the published model; the real W_SF (offset 61) scales W/ReqW, points
// this tree does not yet read. That misuse is a live product defect at the
// pin bump this change causes — see the WP4-T4 report for the consumer list.
//
// L802 is derived from docs/schema/sunspec-models/model_802.json exactly
// like L120/L121/L122/L123, and proven against the JSON's own names, order,
// types, widths and access/mandatory flags by TestLayoutsMatchVendoredSpec.
var L802 = NewLayout(
	FS("AHRtg", Tuint16, "AHRtg_SF").R().M(),                 // nameplate charge capacity, Ah
	FS("WHRtg", Tuint16, "WHRtg_SF").R().M(),                 // nameplate energy capacity, Wh
	FS("WChaRteMax", Tuint16, "WChaDisChaMax_SF").R().M(),    // max charge rate, W
	FS("WDisChaRteMax", Tuint16, "WChaDisChaMax_SF").R().M(), // max discharge rate, W
	FS("DisChaRte", Tuint16, "DisChaRte_SF").R().O(),         // self-discharge rate, %WHRtg/day
	FS("SoCMax", Tuint16, "SoC_SF").R().O(),                  // manufacturer max SoC
	FS("SoCMin", Tuint16, "SoC_SF").R().O(),                  // manufacturer min SoC
	FS("SocRsvMax", Tuint16, "SoC_SF").RW().O(),              // max reserve setpoint (spec spells this "Soc", not "SoC")
	FS("SoCRsvMin", Tuint16, "SoC_SF").RW().O(),              // min reserve setpoint
	FS("SoC", Tuint16, "SoC_SF").R().M(),                     // state of charge
	FS("DoD", Tuint16, "DoD_SF").R().O(),                     // depth of discharge
	FS("SoH", Tuint16, "SoH_SF").R().O(),                     // state of health
	F("NCyc", Tuint32).R().O(),                               // cycle count
	F("ChaSt", Tenum16).R().O(),                              // 1=off .. 7=testing
	F("LocRemCtl", Tenum16).R().M(),                          // 0=remote, 1=local
	F("Hb", Tuint16).R().O(),                                 // battery heartbeat
	F("CtrlHb", Tuint16).RW().O(),                            // controller heartbeat
	F("AlmRst", Tuint16).RW().M(),                            // 1=reset latched alarms
	F("Typ", Tenum16).R().M(),                                // battery chemistry: 4=Li-Ion
	F("State", Tenum16).R().M(),                              // 1=disconnected .. 99=fault
	F("StateVnd", Tenum16).R().O(),                           // vendor bank-state enum
	F("WarrDt", Tuint32).R().O(),                             // warranty date, days since 2000-01-01
	F("Evt1", Tbitfield32).R().M(),                           // alarm/warning bitfield 1
	F("Evt2", Tbitfield32).R().M(),                           // reserved
	F("EvtVnd1", Tbitfield32).R().M(),                        // vendor event bitfield 1
	F("EvtVnd2", Tbitfield32).R().M(),                        // vendor event bitfield 2
	FS("V", Tuint16, "V_SF").R().M(),                         // DC bus voltage
	FS("VMax", Tuint16, "V_SF").R().O(),
	FS("VMin", Tuint16, "V_SF").R().O(),
	FS("CellVMax", Tuint16, "CellV_SF").R().O(),
	F("CellVMaxStr", Tuint16).R().O(),
	F("CellVMaxMod", Tuint16).R().O(),
	FS("CellVMin", Tuint16, "CellV_SF").R().O(),
	F("CellVMinStr", Tuint16).R().O(),
	F("CellVMinMod", Tuint16).R().O(),
	FS("CellVAvg", Tuint16, "CellV_SF").R().O(),
	FS("A", Tint16, "A_SF").R().M(), // total DC current
	FS("AChaMax", Tuint16, "AMax_SF").R().O(),
	FS("ADisChaMax", Tuint16, "AMax_SF").R().O(),
	FS("W", Tint16, "W_SF").R().M(), // total DC power
	F("ReqInvState", Tenum16).R().O(),
	FS("ReqW", Tint16, "W_SF").R().O(),
	F("SetOp", Tenum16).RW().M(), // 1=connect, 2=disconnect
	F("SetInvState", Tenum16).RW().M(),
	F("AHRtg_SF", Tsunssf).R().M(),
	F("WHRtg_SF", Tsunssf).R().M(),
	F("WChaDisChaMax_SF", Tsunssf).R().M(),
	F("DisChaRte_SF", Tsunssf).R().O(),
	F("SoC_SF", Tsunssf).R().M(),
	F("DoD_SF", Tsunssf).R().O(),
	F("SoH_SF", Tsunssf).R().O(),
	F("V_SF", Tsunssf).R().M(),
	F("CellV_SF", Tsunssf).R().M(),
	F("A_SF", Tsunssf).R().M(),
	F("AMax_SF", Tsunssf).R().M(),
	F("W_SF", Tsunssf).R().O(),
).As("M802")

// M802 register offsets, restated from L802 (REV0907-D3). Only the points
// this codebase reads or writes are given restated constants — the full
// model is 62 registers and the sim populates the rest as zero — matching
// the M120/M122 precedent above. M802_HeatCool is DELETED: no revision of
// model 802 declares a point by that name. M802_SocRsvMax is spelled to
// match the vendored spec exactly (the model itself is inconsistent:
// SocRsvMax vs SoCRsvMin); a caller spelling it M802_SoCRsvMax will fail to
// compile rather than silently reading the wrong register, which is the
// point.
//
// TestM802ConstantsMatchTheLayout is the drift guard, the twin of
// TestM120ConstantsMatchTheLayout: it asserts every constant below equals
// L802's offset for the point by NAME, so a hand edit here can never again
// disagree with the layout — and the layout is in turn proven against the
// vendored JSON by TestLayoutsMatchVendoredSpec.
const (
	M802Len               = 62 // data registers — equals L802.Len(), asserted by the drift guard
	M802_AHRtg            = 0  // nameplate charge capacity (uint16, M802_AHRtg_SF) — Ah
	M802_WHRtg            = 1  // nameplate energy capacity (uint16, M802_WHRtg_SF) — Wh
	M802_WChaRteMax       = 2  // max charge rate (uint16, M802_WChaDisChaMax_SF) — W
	M802_WDisChaRteMax    = 3  // max discharge rate (uint16, M802_WChaDisChaMax_SF) — W
	M802_DisChaRte        = 4  // self-discharge rate (uint16, M802_DisChaRte_SF) — %WHRtg/day
	M802_SoCMax           = 5  // manufacturer max SoC (uint16, M802_SoC_SF)
	M802_SoCMin           = 6  // manufacturer min SoC
	M802_SocRsvMax        = 7  // reserve max setpoint (RW) — spec spells this "Soc", not "SoC"
	M802_SoCRsvMin        = 8  // reserve min setpoint (RW)
	M802_SoC              = 9  // state of charge (uint16, M802_SoC_SF)
	M802_DoD              = 10 // depth of discharge (uint16, M802_DoD_SF)
	M802_SoH              = 11 // state of health (uint16, M802_SoH_SF)
	M802_ChaSt            = 14 // charge status enum: 1=off .. 7=testing
	M802_LocRemCtl        = 15 // 0=remote, 1=local
	M802_Typ              = 19 // battery chemistry: 4=Li-Ion
	M802_State            = 20 // bank state enum: 1=disconnected .. 99=fault
	M802_AHRtg_SF         = 50 // scale factor for AHRtg (int16)
	M802_WHRtg_SF         = 51 // scale factor for WHRtg (int16)
	M802_WChaDisChaMax_SF = 52 // scale factor for WChaRteMax/WDisChaRteMax (int16) — NOT M802_W_SF
	M802_DisChaRte_SF     = 53
	M802_SoC_SF           = 54 // SoC scale factor (int16): use -2 → register × 0.01 = %
	M802_DoD_SF           = 55
	M802_SoH_SF           = 56
	M802_W_SF             = 61 // scale factor for W/ReqW (int16) — this tree does not read W/ReqW today
)

// ── Model 201/202/203 (AC Meter) register offsets ────────────────────────────
// SunSpec meters sit at the main service entrance and measure net grid power.
// Sign convention (all three models): W positive = site importing from grid,
// W negative = site exporting to grid.  This is opposite to the inverter sign
// convention (positive = export).

// Model IDs for the three meter variants.
const (
	ModelMeterSinglePh = uint16(201) // single-phase AC meter
	ModelMeterSplitPh  = uint16(202) // split-phase (US 240 V) AC meter
	ModelMeterThreePh  = uint16(203) // three-phase wye AC meter
)

// Models 201 (single-phase), 202 (split-phase), and 203 (three-phase wye)
// share the SunSpec "common meter" layout: identical point lists and offsets,
// 105 data registers each (verified against the published sunspec/models
// model_201/202/203.json). They differ only in wiring type. Audit finding
// MTR-4: earlier revisions used invented compressed offsets; these now match
// the published models, so a real SunSpec meter drops in unmodified.
const (
	M201Len       = 105
	M201_A        = 0  // Total AC current (int16, A_SF)
	M201_AphA     = 1  // Phase A current (int16, A_SF)
	M201_AphB     = 2  // Phase B current (int16, A_SF)
	M201_AphC     = 3  // Phase C current (int16, A_SF)
	M201_A_SF     = 4  // Current scale factor (int16)
	M201_PhV      = 5  // Average L-N voltage (int16, V_SF)
	M201_PhVphA   = 6  // Phase A L-N voltage (int16, V_SF)
	M201_PhVphB   = 7  // Phase B L-N voltage (int16, V_SF)
	M201_PhVphC   = 8  // Phase C L-N voltage (int16, V_SF)
	M201_PPV      = 9  // Average L-L voltage (int16, V_SF)
	M201_V_SF     = 13 // Voltage scale factor (int16)
	M201_Hz       = 14 // AC frequency (int16, Hz_SF)
	M201_Hz_SF    = 15 // Frequency scale factor (int16)
	M201_W        = 16 // Total real power (int16, W_SF); +import −export
	M201_W_SF     = 20 // Power scale factor (int16)
	M201_VA       = 21 // Apparent power (int16, VA_SF)
	M201_VA_SF    = 25 // Apparent power scale factor (int16)
	M201_VAR      = 26 // Reactive power (int16, VAR_SF)
	M201_VAR_SF   = 30 // Reactive power scale factor (int16)
	M201_PF       = 31 // Avg power factor ×100 (int16, PF_SF)
	M201_PF_SF    = 35 // Power factor scale factor (int16)
	M201_TotWhExp = 36 // Total exported energy (acc32, regs 36-37, TotWh_SF)
	M201_TotWhImp = 44 // Total imported energy (acc32, regs 44-45, TotWh_SF)
	M201_TotWh_SF = 52 // Energy scale factor (int16)
)

// Model 202 (Split-Phase AC Meter) — same common-meter offsets as M201.
const (
	M202Len     = 105
	M202_A      = 0
	M202_AphA   = 1
	M202_AphB   = 2
	M202_A_SF   = 4
	M202_PhV    = 5
	M202_PhVphA = 6
	M202_PhVphB = 7
	M202_V_SF   = 13
	M202_Hz     = 14
	M202_Hz_SF  = 15
	M202_W      = 16
	M202_W_SF   = 20
)

// Model 203 (Three-Phase Wye AC Meter) — same common-meter offsets as M201.
const (
	M203Len      = 105
	M203_A       = 0
	M203_AphA    = 1
	M203_AphB    = 2
	M203_AphC    = 3
	M203_A_SF    = 4
	M203_PhV     = 5 // Average L-N voltage (int16, V_SF)
	M203_PhVphA  = 6
	M203_PhVphB  = 7
	M203_PhVphC  = 8
	M203_PPV     = 9  // Average L-L voltage (int16, V_SF)
	M203_PPVphAB = 10 // L-L phase voltages (int16, V_SF)
	M203_PPVphBC = 11
	M203_PPVphCA = 12
	M203_V_SF    = 13
	M203_Hz      = 14
	M203_Hz_SF   = 15
	M203_W       = 16 // Total real power (int16, W_SF); +import −export
	M203_WphA    = 17
	M203_WphB    = 18
	M203_WphC    = 19
	M203_W_SF    = 20
	M203_VA      = 21 // Apparent power (int16, VA_SF)
	M203_VA_SF   = 25
	M203_VAR     = 26 // Reactive power (int16, VAR_SF)
	M203_VAR_SF  = 30
	M203_PF      = 31 // Avg power factor ×100 (int16, PF_SF)
	M203_PF_SF   = 35
)

// ── Model 123 (Immediate Controls) ───────────────────────────────────────────
//
// Writes to these registers take immediate effect on the inverter.
//
// # This map was WRONG at every one of its 24 points until 2026-08-15
//
// Model 123 was the last register map in this package still driven by
// hand-written offset constants: it never got the NewLayout-against-vendored-
// JSON treatment every other legacy model (126-134, 160) received, so nothing
// ever compared it to the standard. The hand transcription put the four
// function groups in the wrong ORDER — it leads with WMaxLimPct where the
// published model leads with the Conn group — so every constant was off by
// between 1 and 9 registers. Two of those are load-bearing for safety on a
// conformant legacy DER:
//
//   - The failsafe CEASE for a 704-less pack wrote offset 16 believing it was
//     Conn. A conformant device holds VArPct_WinTms there, so the pack STAYED
//     ENERGIZED — and because the plan's L1 echo proof re-reads the same offset
//     it just wrote, the read-back matched and the gateway reported a PROVEN
//     disconnect that never happened. A safety proof cannot be built out of an
//     echo of the writer's own belief.
//   - A commanded curtailment wrote the percentage to offset 0 believing it was
//     WMaxLimPct. A conformant device holds Conn_WinTms there, in SECONDS: a
//     60.00 % ceiling at SF −2 encodes to raw 6000 and became a 6000-second
//     connect window, curtailing nothing.
//
// Nothing caught it because the bench sim built its model-123 block from these
// same constants, so fixture and product agreed with each other and both
// disagreed with the standard — the shared-oracle blindness this package keeps
// re-learning (11e8b7d's width oracle was the previous instance).
//
// L123 is now derived from docs/schema/sunspec-models/model_123.json like every
// other model, and TestLayoutsMatchVendoredSpec compares it against the JSON's
// own names, types, widths and accumulated offsets.
var L123 = NewLayout(
	F("Conn_WinTms", Tuint16).RW().O(),
	F("Conn_RvrtTms", Tuint16).RW().O(),
	F("Conn", Tenum16).RW().M(),
	FS("WMaxLimPct", Tuint16, "WMaxLimPct_SF").RW().M(),
	F("WMaxLimPct_WinTms", Tuint16).RW().O(),
	F("WMaxLimPct_RvrtTms", Tuint16).RW().O(),
	F("WMaxLimPct_RmpTms", Tuint16).RW().O(),
	F("WMaxLim_Ena", Tenum16).RW().M(),
	FS("OutPFSet", Tint16, "OutPFSet_SF").RW().M(),
	F("OutPFSet_WinTms", Tuint16).RW().O(),
	F("OutPFSet_RvrtTms", Tuint16).RW().O(),
	F("OutPFSet_RmpTms", Tuint16).RW().O(),
	F("OutPFSet_Ena", Tenum16).RW().M(),
	FS("VArWMaxPct", Tint16, "VArPct_SF").RW().O(),
	FS("VArMaxPct", Tint16, "VArPct_SF").RW().O(),
	FS("VArAvalPct", Tint16, "VArPct_SF").RW().O(),
	F("VArPct_WinTms", Tuint16).RW().O(),
	F("VArPct_RvrtTms", Tuint16).RW().O(),
	F("VArPct_RmpTms", Tuint16).RW().O(),
	F("VArPct_Mod", Tenum16).RW().O(),
	F("VArPct_Ena", Tenum16).RW().M(),
	F("WMaxLimPct_SF", Tsunssf).R().M(),
	F("OutPFSet_SF", Tsunssf).R().M(),
	F("VArPct_SF", Tsunssf).R().O(),
).As("M123")

// M123 register offsets. The VALUES below are the published model's; the names
// are unchanged from the wrong-valued originals ON PURPOSE. Every consumer
// references them by name (swept: lexa-proto, lexa-gw, csip-tls-test — no site
// hard-codes a model-123 offset independently), so correcting the values here
// heals the failsafe path, the curtailment path, the reconcilers and all three
// repos' fixtures at re-vendor with no call-site edits. A rename would have
// turned a precise data fix into a wide diff nobody could review as one.
//
// # Why these are restated constants and not L123.Offset(...) calls
//
// Deriving them was tried first and reverted. L123.Offset returns int, so
// derived offsets become typed `int` vars — and that breaks the two things
// untyped constants currently do for every caller in three repos: implicit
// conversion at a uint16 parameter (Reader.WriteModel takes a uint16 offset,
// used at 8 sites in this package alone and more in lexa-gw) and comparison
// against len(regs), which is int. There is no single Go type that does both;
// only an untyped constant does. Breaking every consumer's call sites to
// enforce single-sourcing would have cost more than the drift it prevents,
// especially in a fix whose entire value is that consumers need not be touched.
//
// The drift is prevented instead by TestM123ConstantsMatchTheLayout, which
// asserts every constant below equals its layout offset by NAME. That closes
// the loop three ways: constants are proven against L123, L123 is proven
// against the vendored JSON (TestLayoutsMatchVendoredSpec), and the JSON is the
// standard. The old map had none of those links, which is why it was wrong for
// as long as it was.
const (
	M123_Conn_WinTms  = 0
	M123_Conn_RvrtTms = 1
	M123_Conn         = 2 // 0=disconnect 1=connect

	M123_WMaxLimPct         = 3 // % of WMax (uint16, WMaxLimPct_SF)
	M123_WMaxLimPct_WinTms  = 4
	M123_WMaxLimPct_RvrtTms = 5
	M123_WMaxLimPct_RmpTms  = 6
	// The published point is spelled WMaxLim_Ena, with no "Pct". The constant
	// keeps the old spelling because every consumer names it; the LAYOUT
	// carries the spec's spelling, which is what the spec test compares.
	M123_WMaxLimPct_Ena = 7

	M123_OutPFSet         = 8 // int16, OutPFSet_SF
	M123_OutPFSet_WinTms  = 9
	M123_OutPFSet_RvrtTms = 10
	M123_OutPFSet_RmpTms  = 11
	M123_OutPFSet_Ena     = 12

	// THE REACTIVE VALUE IS A MODE-SELECTED TRIO, not one register. The old map
	// collapsed all three into a single "M123_VArPct", which is half of how a
	// 24-point model became a 23-point one. VArPct_Mod names which of the three
	// the device applies, and the JSON's own symbols pair them 1:1:
	//   VArPct_Mod = 1 (WMax)    → VArWMaxPct
	//   VArPct_Mod = 2 (VArMax)  → VArMaxPct
	//   VArPct_Mod = 3 (VArAval) → VArAvalPct
	M123_VArWMaxPct = 13
	M123_VArMaxPct  = 14
	M123_VArAvalPct = 15

	// M123_VArPct is a COMPATIBILITY ALIAS for VArMaxPct, correct only for a
	// caller that writes VArPct_Mod = 2 (VArMax). That is what the sole
	// consumer does today — lexa-gw cmd/modbus/reconcile_adv.go writes
	// varPctModVArMax = 2 immediately before the value — so the alias makes
	// that path correct at re-vendor with no call-site edit. A caller writing
	// any other mode MUST name the matching register above: the alias cannot
	// follow the mode, and a mode/value mismatch commands a reactive setpoint
	// against a base the device did not select.
	M123_VArPct = M123_VArMaxPct

	M123_VArPct_WinTms  = 16
	M123_VArPct_RvrtTms = 17
	M123_VArPct_RmpTms  = 18
	M123_VArPct_Mod     = 19
	M123_VArPct_Ena     = 20

	M123_WMaxLimPct_SF = 21
	M123_OutPFSet_SF   = 22
	M123_VArPct_SF     = 23
)

// M123_Conn_RmpTms is DELETED, not corrected: model 123 declares no ramp
// register for the Conn group at all. The old map invented one at offset 19,
// where the published model holds VArPct_Mod — so a caller "setting the connect
// ramp time" was rewriting the reactive-power mode selector. Inventing that
// point is the other half of how the block came out 23 long: one register
// invented, two lost to the merged VAr trio.
//
// Deleted rather than left as a wrong-but-compiling constant. The only
// remaining reference anywhere is csip-tls-test's divergence-record test, which
// exists precisely to be rewritten when this lands.
