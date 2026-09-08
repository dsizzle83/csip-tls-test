package derbase

// MEASUREMENT LIVENESS — the L1 half of the freshness cross-check
// (MEAS-FRESHNESS; docs/design/FRESHNESS_PLAN_2026-08-04.md in lexa-gw).
//
// # The defect this exists for
//
// A SunSpec measurement read has no heartbeat, no sequence number and no
// timestamp. Nothing in models 701 or 10x tells a reader WHEN the values it is
// holding were sampled, so a device (or a proxy, or a fault) that serves the
// same register block forever is indistinguishable, read by read, from a device
// whose measurements genuinely are not changing. On the bench (board cc93,
// 2026-08-04) a frozen 701 block kept reporting W=5000 / ConnSt=connected while
// the machine behind it sat at zero output and disconnected, and every layer
// above — read-back verification included — agreed the control was applied.
// Register read-back compares what the gateway WROTE against what it reads; it
// cannot notice a device that is consistently, plausibly wrong about its own
// present state.
//
// # What this layer does, and what it deliberately does not
//
// It computes a per-sample DIGEST of the points a live device cannot hold
// still, partitioned into classes with different natural timescales, plus the
// energy accumulators. It holds no clock, no history and no verdict: two
// digests and the time between them are the consumer's business (lexa-gw's
// cmd/modbus/freshness.go), because a window is policy and a digest is not.
//
// IT IS AN ACCIDENTAL-FAULT DETECTOR, NOT AN ATTACK DETECTOR. An adversary in
// the register path defeats every signal here by toggling one LSB per poll. The
// faults it is built for — a stuck cache, a frozen proxy, a firmware wedge, a
// simulator serving a snapshot — do not do that. Stating the boundary is the
// point: a reader who mistakes this for a security control would draw the wrong
// conclusion from a passing digest.
//
// # Why classes, and why BY NAME
//
// Points move on different timescales, and lumping them together produces the
// two errors that matter in opposite directions:
//
//	VOLATILE   free-running electrical quantities — power, current, voltage,
//	           frequency, power factor. On a live interconnection these are
//	           never bit-identical between two polls seconds apart, even on an
//	           idle machine: grid voltage and frequency wander. Their stillness
//	           is the primary suspicion signal.
//	SLOW       temperatures. A genuinely idle device's volatile points CAN sit
//	           still (a dark inverter at night reporting exact zeros), but its
//	           cabinet still drifts thermally. Requiring the SLOW class frozen
//	           too is what keeps a becalmed night off the suspect list.
//	ACCUM      lifetime energy counters. Monotone, and the one class that can
//	           CONTRADICT rather than merely fail to corroborate: a block
//	           claiming kilowatts whose lifetime Wh never advances is claiming
//	           something physically impossible, at night or at noon.
//
// Points are selected BY NAME, never by register offset. An offset table drifts
// silently when a layout is corrected (701's length moved 137→153 once already);
// a name that moves fails a test. The three tables below are also deliberately
// SMALLER than the models: scale factors, the alarm/mode bitfields, the static
// enums (ACType/St/InvSt/ConnSt) and the manufacturer alarm string are all
// excluded, because none of them is a free-running measurement and including a
// value that changes for a NON-measurement reason would let a device with a
// flapping alarm bit pass as live while its measurements are frozen.
//
// The digest is over RAW registers (sunspec.View.Raw), not engineering values:
// two raw words can round onto one float64, and the scale factor — a device
// constant this file excludes on purpose — must not participate.

import (
	"fmt"
	"hash/fnv"
	"math"

	"lexa-proto/sunspec"
)

// Liveness is the freshness evidence carried by ONE measurement sample.
//
// The four digests are FNV-1a over the raw register content of the implemented
// points in each class, in table order, each point mixed together with its own
// NAME so that two different points swapping values cannot cancel out. Equal
// digests across two samples mean every implemented point in that class held
// the identical bit pattern; unequal digests mean at least one moved.
//
// A digest is only ever compared with another digest of the SAME model from the
// SAME device. It is not stable across releases, is not a wire value, and must
// never be persisted or compared across model types.
//
// The *Points counts are what make "no evidence" distinguishable from "evidence
// of stillness". A device that implements ZERO volatile points produces a
// perfectly stable Volatile digest forever, and reading that as "frozen" would
// condemn every such device; reading it as "live" would exonerate every one.
// Zero points of an evidence type is NO evidence — the consumer's third verdict
// (unverifiable), never fresh and never suspect.
type Liveness struct {
	// Volatile / Slow / Accum digest their own class; All digests the three
	// together and exists so a consumer can ask "did ANY measurement point
	// move" in one comparison (the cheap first test before it looks at class
	// structure).
	Volatile uint64
	Slow     uint64
	Accum    uint64
	All      uint64

	// VolatilePoints / SlowPoints / AccumPoints count the points of each class
	// the DEVICE actually implements in this sample — present within the
	// returned register block and not carrying their type's not-implemented
	// sentinel.
	VolatilePoints int
	SlowPoints     int
	AccumPoints    int

	// WhInj / WhAbs are the lifetime energy accumulators in engineering units
	// (Wh), carried in the clear — not just digested — because the
	// contradiction test needs their DIFFERENCE over a window, not merely
	// whether they moved. Injected is energy the device exported (701
	// TotWhInj, or the legacy 10x WH); absorbed is 701 TotWhAbs, which the
	// legacy models have no counterpart for.
	//
	// HaveWh reports that WhInj is a real reading. It is false — and both
	// fields are NaN — when the device does not implement the accumulator or
	// leaves its scale factor unimplemented. A consumer MUST test HaveWh
	// before differencing: the energy test is unavailable on such a device,
	// which is a different thing from an energy counter that is not moving.
	WhInj  float64
	WhAbs  float64
	HaveWh bool
}

// Assessable reports whether this sample carries any evidence of the kind the
// primary (volatile-class) staleness test consumes. A false here is the
// unverifiable-by-construction device: the consumer must count it and say so
// once, never silently treat it as fresh.
func (l Liveness) Assessable() bool { return l.VolatilePoints > 0 }

// ── Point classes, by name ───────────────────────────────────────────────────

// m701Volatile are model 701's free-running electrical points. Total AC
// quantities first, then the per-phase block: a single-phase device implements
// only the totals and its own phase, and the per-point presence test drops the
// rest without the table needing to know the device's ACType.
var m701Volatile = []string{
	"W", "VA", "Var", "PF", "A", "LLV", "LNV", "Hz",
	"WL1", "VAL1", "VarL1", "PFL1", "AL1", "VL1L2", "VL1",
	"WL2", "VAL2", "VarL2", "PFL2", "AL2", "VL2L3", "VL2",
	"WL3", "VAL3", "VarL3", "PFL3", "AL3", "VL3L1", "VL3",
}

// m701Slow are the thermal points — the class that keeps a genuinely asleep
// device off the suspect list. All six of 701's temperatures are listed; a
// device implementing one of them contributes that one.
var m701Slow = []string{"TmpAmb", "TmpCab", "TmpSnk", "TmpTrns", "TmpSw", "TmpOt"}

// m701Accum are the lifetime energy/reactive-energy counters, totals and
// per-phase. Monotone by construction, so their stillness while power is
// claimed is a contradiction rather than an absence.
var m701Accum = []string{
	"TotWhInj", "TotWhAbs", "TotVarhInj", "TotVarhAbs",
	"TotWhInjL1", "TotWhAbsL1", "TotVarhInjL1", "TotVarhAbsL1",
	"TotWhInjL2", "TotWhAbsL2", "TotVarhInjL2", "TotVarhAbsL2",
	"TotWhInjL3", "TotWhAbsL3", "TotVarhInjL3", "TotVarhAbsL3",
}

// m701Excluded documents, for the reader and for the regression that pins it,
// every 701 point deliberately absent from the three tables above and WHY.
// It is not consulted at runtime.
//
//	ACType, St, InvSt, ConnSt   static/state enums — a device does not change
//	                            its wiring type, and an operating-state enum
//	                            that flips is a state change, not a measurement
//	Alrm, DERMode, ThrotSrc     bitfields; an alarm flapping must not read as
//	                            "the measurements are moving"
//	ThrotPct                    throttle percentage in force: a control-derived
//	                            value, and on a curtailed device it is CONSTANT
//	                            precisely when the gateway is commanding it
//	*_SF (ten of them)          read-only device constants — a scale factor that
//	                            moves is corruption (View.SF rejects it), never
//	                            liveness
//	MnAlrmInfo                  a 64-byte manufacturer string; no numeric
//	                            content, and View.Raw declines it anyway
var m701Excluded = []string{
	"ACType", "St", "InvSt", "ConnSt", "Alrm", "DERMode", "ThrotPct", "ThrotSrc",
	"A_SF", "V_SF", "Hz_SF", "W_SF", "PF_SF", "VA_SF", "Var_SF",
	"TotWh_SF", "TotVarh_SF", "Tmp_SF", "MnAlrmInfo",
}

// LivenessOfM701 digests one model-701 register block.
func LivenessOfM701(regs []uint16) Liveness {
	v := sunspec.L701.View(regs)
	var l Liveness
	vh, sh, ah, all := fnv.New64a(), fnv.New64a(), fnv.New64a(), fnv.New64a()

	l.VolatilePoints = mixNamed(vh, all, v, m701Volatile)
	l.SlowPoints = mixNamed(sh, all, v, m701Slow)
	l.AccumPoints = mixNamed(ah, all, v, m701Accum)

	l.Volatile, l.Slow, l.Accum, l.All = vh.Sum64(), sh.Sum64(), ah.Sum64(), all.Sum64()

	l.WhInj, l.WhAbs = v.Float("TotWhInj"), v.Float("TotWhAbs")
	l.HaveWh = !math.IsNaN(l.WhInj)
	return l
}

// mixNamed folds each IMPLEMENTED named point's raw content into both the
// class hash and the all-class hash, and returns how many were implemented.
// Each point is mixed as name || raw so two points exchanging values cannot
// produce the same digest.
func mixNamed(class, all hasher, v sunspec.View, names []string) int {
	n := 0
	for _, name := range names {
		raw, ok := v.Raw(name)
		if !ok {
			continue
		}
		n++
		mixOne(class, name, raw)
		mixOne(all, name, raw)
	}
	return n
}

// hasher is the subset of hash.Hash64 this file uses; declared narrowly so the
// mixing helpers cannot accidentally reset or re-key a running digest.
type hasher interface {
	Write(p []byte) (int, error)
	Sum64() uint64
}

func mixOne(h hasher, name string, raw uint64) {
	_, _ = h.Write([]byte(name))
	var b [9]byte
	b[0] = 0xFF // separator: keeps name||raw unambiguous against a longer name
	for i := 0; i < 8; i++ {
		b[1+i] = byte(raw >> (56 - 8*i))
	}
	_, _ = h.Write(b[:])
}

// ── Legacy model 10x ─────────────────────────────────────────────────────────

// acPoint is one legacy-model point: its name (the digest vocabulary, exactly
// as for 701), its register offset, and whether the register is signed — which
// decides only which not-implemented sentinel applies (0x8000 vs 0xFFFF).
type acPoint struct {
	name   string
	off    int
	signed bool
}

// m10xVolatile are the free-running points of models 101/102/103. The offsets
// are the same in all three (the models differ by which phases are populated),
// and a single-phase device leaves the B/C-phase registers at their sentinel,
// which the presence test drops.
var m10xVolatile = []acPoint{
	{"A", sunspec.M103_A, true}, {"AphA", sunspec.M103_AphA, true},
	{"AphB", sunspec.M103_AphB, true}, {"AphC", sunspec.M103_AphC, true},
	{"PPVphAB", sunspec.M103_PPVphAB, false}, {"PPVphBC", sunspec.M103_PPVphBC, false},
	{"PPVphCA", sunspec.M103_PPVphCA, false},
	{"PhVphA", sunspec.M103_PhVphA, false}, {"PhVphB", sunspec.M103_PhVphB, false},
	{"PhVphC", sunspec.M103_PhVphC, false},
	{"W", sunspec.M103_W, true}, {"Hz", sunspec.M103_Hz, false},
	{"VA", sunspec.M103_VA, true}, {"VAr", sunspec.M103_VAr, true},
	{"PF", sunspec.M103_PF, true},
	{"DCA", sunspec.M103_DCA, true}, {"DCV", sunspec.M103_DCV, false},
	{"DCW", sunspec.M103_DCW, true},
}

// m10xSlow are the legacy thermal points.
var m10xSlow = []acPoint{
	{"TmpCab", sunspec.M103_TmpCab, true}, {"TmpSnk", sunspec.M103_TmpSnk, true},
	{"TmpTrns", sunspec.M103_TmpTrns, true}, {"TmpOt", sunspec.M103_TmpOt, true},
}

// LivenessOfACModel digests one legacy model 101/102/103 register block.
//
// Its one accumulator is WH (acc32 at offsets 22-23). Presence is decided by
// the scale factor, not by the counter's own value: an acc32 reserves no
// not-implemented sentinel, so a zero WH on a device with a valid WH_SF is a
// real "nothing accumulated yet" and must be digested as such.
func LivenessOfACModel(regs []uint16) Liveness {
	var l Liveness
	vh, sh, ah, all := fnv.New64a(), fnv.New64a(), fnv.New64a(), fnv.New64a()

	l.VolatilePoints = mixOffsets(vh, all, regs, m10xVolatile)
	l.SlowPoints = mixOffsets(sh, all, regs, m10xSlow)

	if wh, ok := readM103WH(regs); ok {
		l.AccumPoints = 1
		raw := uint64(rawU32At(regs, sunspec.M103_WH))
		mixOne(ah, "WH", raw)
		mixOne(all, "WH", raw)
		l.WhInj, l.WhAbs, l.HaveWh = wh, math.NaN(), true
	} else {
		l.WhInj, l.WhAbs = math.NaN(), math.NaN()
	}

	l.Volatile, l.Slow, l.Accum, l.All = vh.Sum64(), sh.Sum64(), ah.Sum64(), all.Sum64()
	return l
}

// mixOffsets is mixNamed for an offset-addressed legacy model: same name||raw
// mixing, same "implemented" test (in range and not the type's sentinel).
func mixOffsets(class, all hasher, regs []uint16, points []acPoint) int {
	n := 0
	for _, p := range points {
		if p.off >= len(regs) {
			continue
		}
		raw := regs[p.off]
		if (p.signed && raw == 0x8000) || (!p.signed && raw == 0xFFFF) {
			continue
		}
		n++
		mixOne(class, p.name, uint64(raw))
		mixOne(all, p.name, uint64(raw))
	}
	return n
}

func rawU32At(regs []uint16, off int) uint32 {
	if off+1 >= len(regs) {
		return 0
	}
	return uint32(regs[off])<<16 | uint32(regs[off+1])
}

// readM103WH decodes the legacy AC lifetime energy accumulator (D-10).
//
// ok=false means the device does not implement it: the registers are outside
// the returned block, or WH_SF is unimplemented / outside the legal sunssf
// domain [-10,+10]. That scale-factor test is the ONLY presence signal
// available — an acc32 reserves no not-implemented sentinel, so a raw 0 is a
// legitimate un-accumulated counter and must NOT be read as absence.
func readM103WH(regs []uint16) (float64, bool) {
	if sunspec.M103_WH_SF >= len(regs) {
		return math.NaN(), false
	}
	sf := int16(regs[sunspec.M103_WH_SF])
	if !sunspec.ValidSF(sf) {
		return math.NaN(), false
	}
	if sunspec.M103_WH+1 >= len(regs) {
		return math.NaN(), false
	}
	return float64(rawU32At(regs, sunspec.M103_WH)) * math.Pow10(int(sf)), true
}

// ── Cross-model probe (S3) ───────────────────────────────────────────────────

// m802Volatile are the model-802 points a live battery cannot hold still: its
// state of charge, depth of discharge and state of health. They move slowly,
// which is exactly why 802 is a CONFIRMER and never a clearer — an 802 block
// that has not moved proves nothing, while one that HAS moved while the
// primary measurement block sat still proves the primary block is stale.
//
// Every offset here comes from the sunspec.M802_* constants, so REV0907-D3
// (the model-802 offset table was wrong at every point it declared — a
// 26-register table for a 62-register model) fixed this probe by
// construction rather than requiring an edit in this file: before the fix,
// "SoC" was reading the published model's ChaSt register, "DoD" was reading
// LocRemCtl, "SoH" was reading CtrlHb, "ChaSt" was reading StateVnd, and
// "State" was reading half of the Evt1 alarm bitfield — five points digesting
// five unrelated registers under the right English names.
// TestM802VolatileProbeOffsetsMatchL802 (liveness_test.go) is the
// independent oracle that keeps it that way — the twin of
// TestM122WAvalProbeOffsetMatchesL122 for this table.
var m802Volatile = []acPoint{
	{"SoC", sunspec.M802_SoC, false},
	{"DoD", sunspec.M802_DoD, false},
	{"SoH", sunspec.M802_SoH, false},
	{"ChaSt", sunspec.M802_ChaSt, false},
	{"State", sunspec.M802_State, false},
}

// m122Volatile is model 122's available-real-power point — the last resort for
// a legacy device that serves neither a second AC model nor an 802.
var m122Volatile = []acPoint{
	{"WAval", sunspec.M122_WAval, false},
	{"PVConn", sunspec.M122_PVConn, false},
	{"StorConn", sunspec.M122_StorConn, false},
	{"ECPConn", sunspec.M122_ECPConn, false},
}

// LivenessOfModel digests a register block for the named model, dispatching to
// the right table. An unknown model yields the zero Liveness, whose
// VolatilePoints of 0 says "no evidence" — never "frozen".
func LivenessOfModel(modelID uint16, regs []uint16) Liveness {
	switch modelID {
	case sunspec.ModelDERMeasureAC:
		return LivenessOfM701(regs)
	case sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh:
		return LivenessOfACModel(regs)
	case sunspec.ModelLithiumBattery:
		return livenessOfOffsets(m802Volatile, regs)
	case sunspec.ModelExtendedStatus:
		return livenessOfOffsets(m122Volatile, regs)
	}
	return Liveness{WhInj: math.NaN(), WhAbs: math.NaN()}
}

// livenessOfOffsets digests a single volatile-class offset table (the 802/122
// probe models, which carry no thermal or energy points this layer consumes).
func livenessOfOffsets(points []acPoint, regs []uint16) Liveness {
	vh, all := fnv.New64a(), fnv.New64a()
	n := mixOffsets(vh, all, regs, points)
	return Liveness{
		Volatile: vh.Sum64(), All: all.Sum64(), VolatilePoints: n,
		WhInj: math.NaN(), WhAbs: math.NaN(),
	}
}

// ProbeModel names the model this device should be cross-probed on, and
// reports whether it has one at all.
//
// The probe's whole value is that it reads a DIFFERENT block than the one under
// suspicion: a device serving a frozen 701 out of a stuck cache is very often
// still answering its legacy 103 from live state (that is precisely the shape
// of the bench fault), so movement in the alternate model while the primary sits
// still CONFIRMS the primary is stale. The converse does not hold and must not
// be inferred — a still probe is simply no news.
//
// Preference order, most to least informative:
//
//	701 primary + a legacy AC model present  → that AC model (cross-family; the
//	                                           bench fault's own shape)
//	802 present                              → 802 (a battery's own state)
//	122 present                              → 122 (available power / connection)
//	otherwise                                → none; the probe is off for this
//	                                           device, which is a limitation to
//	                                           report, not a verdict to infer
func (b *Base) ProbeModel() (uint16, bool) {
	if b.Reader == nil {
		return 0, false
	}
	if b.MeasModel == sunspec.ModelDERMeasureAC {
		for _, c := range []uint16{sunspec.ModelInverterThreePh, sunspec.ModelInverterSplitPh, sunspec.ModelInverterSinglePh} {
			if b.Reader.HasModel(c) {
				return c, true
			}
		}
	}
	if b.Reader.HasModel(sunspec.ModelLithiumBattery) {
		return sunspec.ModelLithiumBattery, true
	}
	if b.Reader.HasModel(sunspec.ModelExtendedStatus) {
		return sunspec.ModelExtendedStatus, true
	}
	return 0, false
}

// ReadLivenessProbe reads this device's cross-probe model and digests it.
//
// THREE-VALUED, exactly like ReadConnectState and ReadAppliedCeilingW, and for
// the same reason: the caller must be able to tell "this device offers no
// second opinion" apart from "the second opinion is that nothing moved".
//
//	ok=false   the device serves no alternate model (ProbeModel said so), or the
//	           model it serves implements no points this layer digests.
//	           UNAVAILABLE — never evidence in either direction.
//	err        a transport/read failure. Also not evidence: failing to ask says
//	           nothing about the DER, and a caller that scored it as stillness
//	           would escalate an unreachable device on the strength of its own
//	           broken link.
//
// It costs one model read and is intended to be called only while a device is
// already under suspicion — never on the polling path.
func (b *Base) ReadLivenessProbe(tag string) (Liveness, bool, error) {
	id, ok := b.ProbeModel()
	if !ok {
		return Liveness{WhInj: math.NaN(), WhAbs: math.NaN()}, false, nil
	}
	regs, err := b.Reader.ReadModel(id)
	if err != nil {
		return Liveness{WhInj: math.NaN(), WhAbs: math.NaN()}, false,
			fmt.Errorf("%s: liveness probe read model %d: %w", tag, id, err)
	}
	l := LivenessOfModel(id, regs)
	if !l.Assessable() {
		// The model is served but implements nothing this layer can watch —
		// indistinguishable, as evidence, from having no probe model at all.
		return l, false, nil
	}
	return l, true, nil
}
