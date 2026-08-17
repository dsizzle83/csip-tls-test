package invariant

// legacynameplate.go — the LEGACY generation's active-power reference, read out
// of models 120 (Nameplate) and 121 (Basic Settings).
//
// WHY THIS EXISTS. Every percent-of-active-power control this referee judges is
// a percentage OF something, and [Nameplate] answered that question from model
// 702 alone. 702 is a 1547-2018 model: a legacy 12x DER does not serve it and
// never will. So on a legacy DER every oracle that resolved a percent reported
//
//	"the DER serves no M702, so its own WMax has no value to resolve the
//	 commanded ceiling against"
//
// and the row FAILED — with a claim string about what the DER's registers HOLD.
// The 2026-08-17 bench battery carried three such rows on its legacy leg
// (BASIC-008, BASIC-010, BASIC-013), and the run's own summary wrote them up as
// "the register never holds the commanded limit" and "a pure southbound-
// execution failure". Nothing had read a limit register at all. That is the
// misattribution this file removes: the legacy generation DOES publish an
// active-power reference, in two models this referee simply was not reading.
//
// WHICH REGISTERS, AND WHY THOSE. Model 121's WMax is the operational SETTING —
// what the operator has configured this machine to do — and model 120's WRtg is
// the hardware RATING. That is the same rating/setting pair 702 carries as
// WMaxRtg/WMax, so the resolution rule does not need restating: it is
// [Nameplate.Base]'s, settings-first (IW15-002; a percentage is a percentage of
// what the device is configured to do, falling back to the rating only when no
// setting is published). Filling the SAME two fields means every caller,
// tolerance and message downstream is unchanged — only the source of the number
// moves.
//
// Deliberately NOT filled: the reactive, apparent, current and per-sign rate
// references. Model 120 publishes ratings for some of them, but this file exists
// to answer one question — what is an active-power percent a percent of — and a
// half-populated nameplate would let an unrelated oracle resolve a base off a
// legacy model without anyone having decided that it should. Those references
// keep answering "device publishes neither", which is the honest answer until a
// row needs them.

import (
	"fmt"

	"lexa-proto/sunspec"
)

// DecodeLegacyNameplate reads a legacy DER's active-power reference out of its
// model 120 and model 121 data blocks. Either may be empty (the model is not
// served); Present is true when at least one of the two yielded a number.
//
// regs are DATA registers — no id/length header — exactly as
// sunspec.Reader.ReadModel returns them and as every other decoder here takes
// them. The offsets come from lexa-proto's own vendored model tables
// (sunspec.M120_WRtg / M120_W_SF / M121_WMax / M121_WMax_SF), which are pinned
// against the SunSpec model JSON by that package's own tests; there is no
// Layout for 120/121 to derive them from, and inventing a second transcription
// of offsets that already have a checked home is how the two drift apart.
func DecodeLegacyNameplate(source string, m120, m121 []uint16) Nameplate {
	n := Nameplate{Source: source}
	// The RATING (M120 WRtg).
	if len(m120) > sunspec.M120_W_SF {
		if sf := int16(m120[sunspec.M120_W_SF]); sunspec.ValidSF(sf) {
			n.WMaxRtg = Q(sunspec.ApplyScaleUint(m120[sunspec.M120_WRtg], sf), UnitWatt)
			n.Present = true
		}
	}
	// The SETTING (M121 WMax), which governs a percentage where it is published.
	if len(m121) > sunspec.M121_WMax_SF {
		if sf := int16(m121[sunspec.M121_WMax_SF]); sunspec.ValidSF(sf) {
			n.WMax = Q(sunspec.ApplyScaleUint(m121[sunspec.M121_WMax], sf), UnitWatt)
			n.Present = true
		}
	}
	return n
}

// LegacyNameplate decodes this unit's models 120/121 as an active-power
// reference.
//
// It is a SIBLING of [UnitView.Nameplate] for the reason [UnitView.LegacyCommands]
// is a sibling of [UnitView.Commands]: the two read different models of
// different generations, and a caller has to state WHICH device it believes it
// is looking at rather than have one silently stand in for the other. A DER
// serving both (the advanced sims lay down 120/121 beside 702) must be judged
// on 702 — that is the generation's own nameplate, and it is the one carrying
// the per-sign rate references a signed setpoint needs.
func (u UnitView) LegacyNameplate(source string) Nameplate {
	return DecodeLegacyNameplate(
		fmt.Sprintf("%s unit %d M120/M121", source, u.Unit),
		u.Regs[sunspec.ModelNameplate], u.Regs[sunspec.ModelBasicSettings])
}
