package diff

// ctlcatalog.go is the standing set of control-semantics probes.
//
// Every case here exists because there is a specific way for a CSIP-to-SunSpec
// translation to be wrong, and each one names that way in its title. They are
// not random: this family's generated arm lives in [GenerateCtl], and its job is
// to find the cases nobody thought of. The catalogue's job is different — it is
// the set of questions that must be asked on every run, so that a regression in
// one of them is caught the first time rather than the first time the generator
// happens to hit it.
//
// The two fixtures the catalogue leans on are [Bench702] (an ordinary,
// reactive-capable 60 kW inverter) and [ReactivePoor] (the same machine with a
// 2 kvar reactive envelope). Running the same document against both is what
// turns "the two readings differ" into "the two readings differ by 24x on a
// device you can buy", and several cases below exist as a matched pair for
// exactly that reason.

import (
	"context"
	"fmt"

	model "lexa-proto/csipmodel"
)

// ap builds an ActivePower from a multiplier and a value, the way a head-end
// carries watts on the wire. Still correct for opModExpLimW/opModImpLimW/
// opModGenLimW/opModLoadLimW (§1.2, unaffected by IW13-001) — NOT for
// opModFixedW/opModMaxLimW any more, see pct/spc below.
func ap(mult int8, val int16) *model.ActivePower {
	return &model.ActivePower{Multiplier: mult, Value: val}
}

// spc builds a SignedPerCent from a raw hundredths-of-a-percent value —
// opModFixedW's real wire type (IW13-001). v=6000 means 60.00%.
func spc(v int16) *model.SignedPerCent { return &model.SignedPerCent{Value: v} }

// pct builds a PerCent from a raw hundredths-of-a-percent value — opModMaxLimW's
// real wire type (IW13-001). v=6000 means 60.00%.
func pct(v int16) *model.PerCent { return &model.PerCent{Value: v} }

func fixedVar(refType uint8, hundredthsPct int16) *model.FixedVar {
	return &model.FixedVar{RefType: refType, Value: model.SignedPerCent{Value: hundredthsPct}}
}

func boolp(b bool) *bool { return &b }

// CtlCatalog returns the standing control-semantics cases.
func CtlCatalog() []CtlCase {
	return []CtlCase{
		// ── The reference base a percentage is taken against ──────────────
		{
			ID:    "DIFF-CTL-001",
			Title: "opModFixedVar refType=1 (%setMaxW) on a reactive-capable device",
			Spec:  Bench702(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxW, 8000)},
		},
		{
			ID:    "DIFF-CTL-002",
			Title: "opModFixedVar refType=1 (%setMaxW) on a reactive-POOR device",
			Spec:  ReactivePoor(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxW, 8000)},
		},
		{
			ID:    "DIFF-CTL-003",
			Title: "opModFixedVar refType=2 (%setMaxVar) — the one base the product assumes",
			Spec:  ReactivePoor(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxVar, 8000)},
		},
		{
			ID:    "DIFF-CTL-004",
			Title: "opModFixedVar refType=3 (%statVarAvail) against a loaded device",
			Spec:  Bench702(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctStatVarAvail, 10000)},
		},
		{
			ID:    "DIFF-CTL-004b",
			Title: "opModFixedVar refType=3 (%statVarAvail) on a device with almost no headroom left",
			Spec:  NearlyLoaded(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctStatVarAvail, 10000)},
		},
		{
			ID:    "DIFF-CTL-005",
			Title: "opModFixedVar refType=0 (N/A) — a document that nominated no base",
			Spec:  Bench702(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypeNA, 8000)},
		},
		{
			ID:    "DIFF-CTL-006",
			Title: "opModFixedVar refType=2 with a NEGATIVE percentage (absorption)",
			Spec:  ReactivePoor(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxVar, -8000)},
		},

		// ── Several conjunctive limits in one document ────────────────────
		//
		// IW13-001: opModMaxLimW is PerCent of THIS device's own setMaxW, not
		// site-level watts — Bench702() is a 60 kW device (WMaxRtg=WMax=
		// 60,000 W), so the percentages below are chosen to reproduce the
		// SAME comparative ordering (which axis binds) these cases pinned
		// before the retype, at clean round percentages rather than forcing
		// the old watts numbers through a non-round conversion.
		{
			ID:    "DIFF-CTL-010",
			Title: "two active-power ceilings, the tighter one second in the document",
			Spec:  Bench702(),
			Ctrl: model.DERControlBase{
				OpModExpLimW: ap(3, 30), // 30 kW
				OpModMaxLimW: pct(1000), // 10% of 60 kW = 6 kW — binds
			},
		},
		{
			ID:    "DIFF-CTL-011",
			Title: "two active-power ceilings, the tighter one first in the document",
			Spec:  Bench702(),
			Ctrl: model.DERControlBase{
				OpModExpLimW: ap(3, 5),  // 5 kW — binds
				OpModMaxLimW: pct(5000), // 50% of 60 kW = 30 kW
			},
		},
		{
			ID:    "DIFF-CTL-012",
			Title: "three active-power ceilings, the tightest last",
			Spec:  Bench702(),
			Ctrl: model.DERControlBase{
				OpModExpLimW: ap(3, 40),
				OpModMaxLimW: pct(2500), // 25% of 60 kW = 15 kW
				OpModGenLimW: ap(3, 2),  // 2 kW — binds
			},
		},

		// ── A limit is not a setpoint ─────────────────────────────────────
		{
			ID:    "DIFF-CTL-020",
			Title: "opModImpLimW — an import CEILING",
			Spec:  Bench702(),
			Ctrl:  model.DERControlBase{OpModImpLimW: ap(3, 5)},
		},
		{
			ID:    "DIFF-CTL-021",
			Title: "opModLoadLimW — a load CEILING",
			Spec:  Bench702(),
			Ctrl:  model.DERControlBase{OpModLoadLimW: ap(3, 8)},
		},
		{
			ID:    "DIFF-CTL-022",
			Title: "opModImpLimW and opModLoadLimW together, the tighter one second",
			Spec:  Bench702(),
			Ctrl: model.DERControlBase{
				OpModImpLimW:  ap(3, 8),
				OpModLoadLimW: ap(3, 3),
			},
		},

		// ── Modes that collide on one register ────────────────────────────
		{
			ID:    "DIFF-CTL-030",
			Title: "opModFixedW and opModImpLimW in one document — both want WSet",
			Spec:  Bench702(),
			Ctrl: model.DERControlBase{
				OpModFixedW:  spc(3000), // 30% of 60 kW = 18 kW
				OpModImpLimW: ap(3, 5),
			},
		},

		// ── Instructions the device cannot carry out ──────────────────────
		//
		// IW13-001: opModFixedW is now bounded to [-100%,100%] by its own
		// SignedPerCent domain (§2.4), so "far beyond the nameplate" can no
		// longer be expressed as an oversized watts figure — 100% of a
		// device's own rating IS its rating, never beyond it. The equivalent
		// "does an extreme value get silently accepted, silently clamped, or
		// honestly refused?" question is now asked at the DOMAIN boundary
		// instead: a value outside the wire type's own [-10000,10000]
		// hundredths range.
		{
			ID:    "DIFF-CTL-040",
			Title: "opModFixedW out of the SignedPerCent domain (>100%) — accepted, clamped, or refused?",
			Spec:  Bench702(),
			Ctrl:  model.DERControlBase{OpModFixedW: spc(15000)}, // 150% — out of [-10000,10000]
		},
		{
			ID:    "DIFF-CTL-041",
			Title: "opModFixedVar beyond the reactive envelope on a reactive-poor device",
			Spec:  ReactivePoor(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxVar, 30000)}, // 300 %
		},
		{
			ID:    "DIFF-CTL-042",
			Title: "a percent-of-rated command on a device that publishes no nameplate",
			Spec:  NameplateAbsent(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxVar, 8000)},
		},

		// ── Partial application ───────────────────────────────────────────
		{
			ID:    "DIFF-CTL-050",
			Title: "a document whose LATER mode cannot be applied — what does the earlier one leave?",
			Spec:  NameplateAbsent(),
			Ctrl: model.DERControlBase{
				OpModFixedVar: fixedVar(RefTypePctSetMaxVar, 5000),
				OpModExpLimW:  ap(3, 10),
			},
			ExpectApplyError: true,
		},
		{
			ID:    "DIFF-CTL-051",
			Title: "a device that refuses the 704 write outright",
			Spec:  Bench702(),
			Ctrl:  model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxVar, 5000)},
			Prepare: func(d *Device) {
				lo, hi := d.Block(704)
				d.RefuseWriteAt(lo, hi)
			},
			ExpectApplyError: true,
		},
		{
			ID:    "DIFF-CTL-052",
			Title: "a device whose VarSetPct scale factor is not implemented",
			Spec: func() DeviceSpec {
				s := Bench702()
				s.Name = "no-VarSetPct_SF"
				s.OmitVarSetPctSF = true
				return s
			}(),
			Ctrl:             model.DERControlBase{OpModFixedVar: fixedVar(RefTypePctSetMaxVar, 5000)},
			ExpectApplyError: true,
		},

		// ── Modes this family does not yet adjudicate, kept so the SKIP is
		//    visible rather than the mode being silently uncovered ─────────
		{
			ID:    "DIFF-CTL-060",
			Title: "opModEnergize and opModFixedPFInjectW — coverage marker",
			Spec:  Bench702(),
			Ctrl: model.DERControlBase{
				OpModEnergize:       boolp(true),
				OpModFixedPFInjectW: spc(9500),
			},
		},
	}
}

// RunCtlCatalog runs every standing case into a report.
func RunCtlCatalog(ctx context.Context, r *Report) error {
	for _, c := range CtlCatalog() {
		res, err := RunCtl(ctx, c)
		if err != nil {
			return fmt.Errorf("catalogue case %s: %w", c.ID, err)
		}
		r.Add(res)
	}
	return nil
}
