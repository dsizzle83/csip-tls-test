package invariant

// i3.go — A write the device refused never leaves durable state asserting it
// applied, and is never re-actuated later.
//
// Grounding defects: OBX-01 (a write refused with Modbus exception 06 still
// committed durably and re-actuated on every subsequent boot) and TRM-01 (one
// terminal report retiring every outstanding outbox record for a device).
//
// # Why this one has a known-good and a known-bad product to test against
//
// OBX-01 was confirmed and fixed. That makes I3 the rare invariant whose
// checker can be validated against the product itself in both directions: run
// it against the fixed build and it must PASS; run it against the pre-fix
// build, drive a write into the deadline path, and it must FAIL. A checker that
// cannot distinguish those two builds is not checking anything, and this is the
// one place in the suite where that can be demonstrated rather than argued.
//
// # The distinctiveness rule
//
// The inference this invariant makes is "the refused value never appeared
// downstream, therefore the refusal did not commit". That is only sound if the
// value could not have arrived by any other route. If the adversary writes
// WMaxLimPct = 50 while the head-end is independently commanding 50, seeing 50
// at the DER proves nothing at all — and an invariant that reported PASS on
// that basis would be lying by construction, in the specific way this whole
// suite exists to stop.
//
// So [WriteRecord.Distinctive] is mandatory: the campaign must assert it chose a
// witness value no legitimate path was commanding, and I3 SKIPs every record
// that lacks the assertion, naming it. The friction is deliberate. Choosing a
// distinguishable witness costs the campaign nothing; the alternative is a check
// that passes for free.
//
// # What "later" can and cannot mean here
//
// OBX-01's actual harm was replay on EVERY SUBSEQUENT BOOT. A continuous
// monitor does not reboot the device — the bench is shared and a campaign that
// power-cycled it would invalidate every other agent's evidence — so I3 checks
// two things it can: the refused value never appears at any witness during the
// observation window, and, when an interruption IS observed (the campaign
// recorded one, or a peer's session counters discontinued), the value still does
// not appear afterwards. The full boot-replay arm needs a controlled restart and
// belongs to the power-cut harness; the statement says so rather than implying
// coverage that is not there.

import (
	"context"
	"fmt"
	"math"
	"time"
)

type i3 struct{ p Params }

// NewI3 returns the refused-write durability invariant.
func NewI3(p Params) Invariant { return &i3{p: p} }

func (i *i3) ID() string { return "I3" }

func (i *i3) Grounding() string {
	return "OBX-01 — a write refused with Modbus exception 06 committed durably anyway and " +
		"re-actuated on every subsequent boot; TRM-01 — one terminal report retiring writes " +
		"no reconciler ever verified."
}

func (i *i3) Statement() string {
	return "A write the device refused (Modbus exception) never leaves durable state asserting " +
		"it applied, and is never re-actuated later: the refused value appears at no witness — " +
		"neither the DER's own register image nor the DUT's northbound projection — at any point " +
		"after the refusal. PARTIAL: only writes the campaign marked DISTINCTIVE are judged, " +
		"because a value the head-end is independently commanding proves nothing; and the " +
		"boot-replay arm is exercised only when an interruption is observed within the run — a " +
		"continuous monitor does not reboot a shared DUT, so full replay coverage belongs to the " +
		"power-cut harness."
}

func (i *i3) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	refused := w.Ledger().Refused()
	if len(refused) == 0 {
		return skipf("the campaign has recorded no refused write, so there is nothing whose durability to check"), nil
	}

	res := Result{Verdict: Pass}
	var skipped []string
	restarts := w.Ledger().Restarts()

	for _, r := range refused {
		if !r.Distinctive {
			skipped = append(skipped, fmt.Sprintf("write#%d %s=%s (not marked distinctive: seeing this value "+
				"downstream would not prove it came from the refused write)", r.Seq, r.Point, r.Value))
			continue
		}
		for _, v := range i.witnesses(obs, r) {
			cmd, ok := commandOf(v.Unit.Commands(v.Source), r.Point)
			if !ok || !cmd.Raw.Known() {
				continue
			}
			res.Checked++
			if !i.sameValue(cmd.Raw, r.Value) {
				continue
			}
			// The refused value is present. Establish whether it also survived
			// an interruption, which is the stronger OBX-01 shape.
			afterRestart := ""
			for _, rs := range restarts {
				if rs.At.After(r.At) && !rs.At.After(obs.At) {
					afterRestart = fmt.Sprintf(" and it survived the %s interruption at %s",
						rs.Cause, rs.At.Format(time.RFC3339))
					break
				}
			}
			res.Verdict = Fail
			res.Facts = append(res.Facts,
				F("i3.write.seq", "", "ledger", "%d", r.Seq),
				F("i3.write.at", "", "ledger", "%s", r.At.Format(time.RFC3339)),
				F("i3.write.credential", "", "ledger", "%s (role %s)", r.Credential, r.Role),
				F("i3.write.target", "", "ledger", "unit %d model %d point %s", r.Unit, r.Model, r.Point),
				F("i3.write.value", string(r.Value.Unit), "ledger", "%s", trimFloat(r.Value.Val)),
				F("i3.write.exception", "", "ledger", "0x%02X", r.ExceptionCode),
				F("i3.observed.witness", "", v.Source, "%s", v.Label),
				F("i3.observed.value", string(cmd.Raw.Unit), v.Source, "%s", trimFloat(cmd.Raw.Val)),
				F("i3.observed.enabled", "", v.Source, "%t", cmd.Enabled),
				F("i3.observed.at", "", v.Source, "%s", obs.At.Format(time.RFC3339)),
			)
			if res.Reason == "" {
				res.Reason = fmt.Sprintf(
					"write#%d set %s=%s on unit %d and the DUT REFUSED it with exception 0x%02X, "+
						"yet %s now reads %s for that point%s — the refusal did not prevent the value taking effect",
					r.Seq, r.Point, r.Value, r.Unit, r.ExceptionCode, v.Label, cmd.Raw, afterRestart)
			}
			res.Assertions = append(res.Assertions, narrate(
				fmt.Sprintf("the value refused by write#%d is absent from %s", r.Seq, v.Label),
				"compare the refused register value against every witness's own register image after the refusal",
				Fail, res.Reason))
		}
	}

	if res.Checked == 0 {
		reason := "no refused write could be checked"
		if len(skipped) > 0 {
			reason += ": " + joinComma(skipped)
		} else {
			reason += ": no witness published the refused points"
		}
		return skipf("%s", reason), nil
	}
	if res.Verdict == Pass {
		note := fmt.Sprintf("%d refused writes × witnesses checked; none of the refused values is present", res.Checked)
		if len(restarts) == 0 {
			note += "; NO interruption occurred during the window, so the boot-replay arm was not exercised"
		} else {
			note += fmt.Sprintf("; %d interruption(s) occurred and the values did not reappear after them", len(restarts))
		}
		if len(skipped) > 0 {
			note += "; skipped: " + joinComma(skipped)
		}
		res.Assertions = append(res.Assertions, narrate(
			"no refused write left state asserting it applied",
			"compare every distinctive refused value against every witness's own register image",
			Pass, note))
	}
	return res, nil
}

// witnesses returns the register images a refused write could show up in: the
// DERs the campaign said the write could reach (or all of them), plus the DUT's
// own projection of the targeted unit — the DUT's projection matters because
// OBX-01's ghost record lives on the DUT and re-publishes from there.
func (i *i3) witnesses(obs *Observation, r WriteRecord) []devView {
	want := map[string]bool{}
	for _, d := range r.DERs {
		want[d] = true
	}
	var out []devView
	for _, v := range deviceViews(obs) {
		switch v.Witness {
		case witnessDER:
			if len(want) == 0 || want[v.Device] {
				out = append(out, v)
			}
		case witnessDUT:
			if v.Unit.Unit == r.Unit {
				out = append(out, v)
			}
		}
	}
	return out
}

// sameValue compares an observed register value against the refused one in the
// SAME unit. A refused write recorded in percent is compared against the
// observed percent, never against a resolved physical value: the claim is about
// the register the write targeted.
func (i *i3) sameValue(observed, refused Quantity) bool {
	if observed.Unit != refused.Unit || !observed.Known() || !refused.Known() {
		return false
	}
	slack := math.Max(math.Abs(refused.Val)*i.p.Tol.Rel, 0.5)
	return math.Abs(observed.Val-refused.Val) <= slack
}
