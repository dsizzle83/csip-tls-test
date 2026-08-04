package invariant

// i6.go — After any interruption at any point, persisted state is the old
// consistent state or the new one; never a mixture, never unparseable.
//
// Grounding: CCP-05/06/07 — the NDJSON replayers' handling of torn and
// unparseable records, and the absence anywhere of a truncate-at-every-offset
// replay test.
//
// # The honest scope, stated up front
//
// This invariant's ideal form is a statement about FILES: no persistent store
// ever contains a half-written record, and a reopen after a crash at any byte
// offset yields exactly the pre-crash state or exactly the post-crash one. That
// is not externally observable. A monitor standing on the network cannot see
// /var/lib/lexa/outbox.ndjson, and one that could would no longer be a check
// that runs against a fielded device.
//
// What IS externally observable after an interruption is the state the device
// PRESENTS, and that turns out to be a genuinely strong proxy, because every
// defect in this class manifests the same way: the device comes back and either
// cannot serve its register map (unparseable state), or serves a value that is
// neither what it held before nor what it was told during the outage (a
// mixture). Both are checkable from outside, and both are the observable
// signature of the file-level defect.
//
// So I6 checks:
//
//	structural — after an interruption, every register image the DUT serves
//	  walks cleanly: the SunSpec chain resolves, each fixed-shape model's block
//	  is at least its layout length, and the measurement block is not
//	  sentinel-saturated. A device that comes back serving garbage has not
//	  recovered a consistent state.
//
//	old-or-new — for every tracked setpoint, the value observed after the
//	  interruption is either the last value observed before it, or a value that
//	  was legitimately commanded (an accepted write in the ledger, or the
//	  head-end's active control) during or after it. A third value is a mixture.
//
// The file-level arm — truncate at every byte offset and reopen — belongs to
// the Wave-3 store suite and is named in the statement so nobody reads a PASS
// here as covering it.

import (
	"context"
	"fmt"
	"math"
	"time"

	"lexa-proto/sunspec"
)

type i6 struct{ p Params }

// NewI6 returns the crash-consistency invariant.
func NewI6(p Params) Invariant { return &i6{p: p} }

func (i *i6) ID() string { return "I6" }

func (i *i6) Grounding() string {
	return "CCP-05/06/07 — NDJSON replayers that silently skip unparseable records, Compact() " +
		"paths that rename without a directory fsync, and the absence of any " +
		"truncate-at-every-offset replay test."
}

func (i *i6) Statement() string {
	return "After any interruption, the state the device presents is the old consistent state or " +
		"the new one — never a mixture, never unparseable: its register map walks cleanly and " +
		"every setpoint reads either its pre-interruption value or one that was legitimately " +
		"commanded. PARTIAL, and the gap is named: the file-level claim (no persistent store ever " +
		"holds a half-written record; reopening after a cut at ANY byte offset yields exactly one " +
		"of the two states) is not externally observable and is covered by the " +
		"truncate-at-every-offset store suite, not here. What is checked here is the observable " +
		"signature of that defect class, after interruptions the run actually observed."
}

func (i *i6) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	restarts := w.Ledger().Restarts()
	interruptions := obs.Faults.Of(ClassInterruption)
	if len(restarts) == 0 && len(interruptions) == 0 {
		return skipf("no interruption occurred during this run, so crash consistency was not exercised"), nil
	}
	last, ok := lastInterruption(restarts, interruptions)
	if !ok || obs.At.Before(last) {
		return skipf("the most recent interruption has not completed yet"), nil
	}
	// The pre-interruption baseline is the newest observation strictly before
	// the interruption. Without one there is no "old state" to compare against.
	before := latestBefore(w.History(), last)

	res := Result{Verdict: Pass}

	// ── Structural arm ────────────────────────────────────────────────────
	for _, v := range deviceViews(obs) {
		res.Checked++
		if why, bad := i.malformed(v); bad {
			res.Verdict = Fail
			res.Facts = append(res.Facts,
				F("i6.structure.witness", "", v.Source, "%s", v.Label),
				F("i6.structure.problem", "", v.Source, "%s", why),
				F("i6.structure.models", "", v.Source, "%v", v.Unit.Models),
				F("i6.structure.since_interruption", "s", "ledger", "%s", dur(obs.At.Sub(last))),
			)
			if res.Reason == "" {
				res.Reason = fmt.Sprintf("%s ago the device was interrupted; %s now presents state that does not "+
					"parse: %s", dur(obs.At.Sub(last)), v.Label, why)
			}
			res.Assertions = append(res.Assertions, narrate(
				fmt.Sprintf("%s presents a consistent register map after the interruption", v.Label),
				"walk the SunSpec model chain and check every fixed-shape block's length and sentinel saturation",
				Fail, res.Reason))
		}
	}

	// ── Old-or-new arm ────────────────────────────────────────────────────
	if before == nil {
		res.Assertions = append(res.Assertions, narrate(
			"the post-interruption state is old-or-new",
			"compare each setpoint against its pre-interruption value and against what was commanded",
			Skip, "no observation was retained from before the interruption, so there is no 'old' state to compare against"))
	} else {
		legit := i.legitimateValues(w, obs, last)
		for _, v := range deviceViews(obs) {
			prev, ok := matchingView(before, v)
			if !ok {
				continue
			}
			for _, c := range v.Unit.Commands(v.Source) {
				if !c.Raw.Known() {
					continue
				}
				old, ok := commandOf(prev.Unit.Commands(prev.Source), c.Point)
				if !ok || !old.Raw.Known() {
					continue
				}
				res.Checked++
				if nearly(c.Raw.Val, old.Raw.Val, i.p.Tol.Rel, 0.5) {
					continue // the old state
				}
				if i.wasCommanded(legit[c.Point], c.Raw) {
					continue // a new state somebody asked for
				}
				res.Verdict = Fail
				res.Facts = append(res.Facts,
					F("i6.mixture.witness", "", v.Source, "%s", v.Label),
					F("i6.mixture.point", "", v.Source, "%s", c.Point),
					F("i6.mixture.before", string(old.Raw.Unit), prev.Source, "%s", trimFloat(old.Raw.Val)),
					F("i6.mixture.after", string(c.Raw.Unit), v.Source, "%s", trimFloat(c.Raw.Val)),
					F("i6.mixture.commanded", "", "ledger+head-end", "%s", describeValues(legit[c.Point])),
					F("i6.mixture.interrupted_at", "", "ledger", "%s", last.Format(time.RFC3339)),
				)
				if res.Reason == "" {
					res.Reason = fmt.Sprintf(
						"across the interruption at %s, %s %s moved from %s to %s, and %s is neither the "+
							"pre-interruption value nor anything that was commanded — the recovered state is a mixture",
						last.Format(time.RFC3339), v.Label, c.Point, old.Raw, c.Raw, c.Raw)
				}
			}
		}
	}

	if res.Checked == 0 {
		return skipf("no register image was readable after the interruption, so consistency could not be judged"), nil
	}
	if res.Verdict == Pass {
		res.Assertions = append(res.Assertions, narrate(
			"the device recovered a consistent state after the interruption",
			"structural walk of every register image, plus an old-or-new comparison of every setpoint",
			Pass, fmt.Sprintf("%d sub-claims asserted %s after the interruption at %s",
				res.Checked, dur(obs.At.Sub(last)), last.Format(time.RFC3339))))
	}
	return res, nil
}

// malformed reports whether a register image fails a structural walk.
func (i *i6) malformed(v devView) (string, bool) {
	if v.Unit.Err != "" {
		return "the unit could not be read: " + v.Unit.Err, true
	}
	if len(v.Unit.Models) == 0 {
		return "the SunSpec model chain resolved to no models", true
	}
	fixed := map[uint16]*sunspec.Layout{
		701: sunspec.L701, 702: sunspec.L702, 703: sunspec.L703, 704: sunspec.L704, 713: sunspec.L713,
	}
	for model, layout := range fixed {
		regs, ok := v.Unit.Regs[model]
		if !ok || len(regs) == 0 {
			continue // not served is not malformed
		}
		if len(regs) < layout.Len() {
			return fmt.Sprintf("model %d returned %d registers, short of its %d-register layout",
				model, len(regs), layout.Len()), true
		}
	}
	if regs, ok := v.Unit.Regs[701]; ok && len(regs) >= sunspec.L701.Len() {
		if sunspec.L701.View(regs).ReadLooksCorrupt() {
			return "the model 701 measurement block is sentinel-saturated (not a fresh, parseable reading)", true
		}
	}
	return "", false
}

// legitimateValues collects, per point, every value somebody legitimately
// commanded at or after the interruption: accepted writes in the ledger, and
// the head-end's active controls translated where the translation is exact.
func (i *i6) legitimateValues(w *World, obs *Observation, since time.Time) map[string][]Quantity {
	out := map[string][]Quantity{}
	for _, r := range w.Ledger().Writes() {
		if !r.Accepted || r.At.Before(since.Add(-time.Minute)) {
			continue
		}
		out[r.Point] = append(out[r.Point], r.Value)
	}
	// A head-end limit maps exactly onto WMaxLimPct only when there is one DER
	// with a published WMax; with several the allocation is not observable and
	// is deliberately not guessed.
	ders := derViews(obs)
	if len(ders) == 1 {
		np := ders[0].Unit.Nameplate(ders[0].Source)
		if base, err := np.Base(RefWMax, 1, ders[0].Unit.Measurement(ders[0].Source)); err == nil && base.Q.Val > 0 {
			for _, p := range obs.HeadEnd.Programs {
				for _, c := range append(append([]Ctrl{}, p.Active...), p.Scheduled...) {
					for _, ax := range c.Base.Axes() {
						if ax.Unit == UnitWatt {
							out["WMaxLimPct"] = append(out["WMaxLimPct"], Q(ax.Value/base.Q.Val*100, UnitPercent))
						}
					}
				}
			}
		}
	}
	return out
}

// wasCommanded reports whether observed matches any legitimately commanded value.
func (i *i6) wasCommanded(cands []Quantity, observed Quantity) bool {
	for _, c := range cands {
		if c.Unit == observed.Unit && nearly(observed.Val, c.Val, math.Max(i.p.Tol.Rel, 0.02), 0.5) {
			return true
		}
	}
	return false
}

func describeValues(qs []Quantity) string {
	if len(qs) == 0 {
		return "nothing was commanded for this point"
	}
	parts := make([]string, 0, len(qs))
	for _, q := range qs {
		parts = append(parts, q.String())
	}
	return joinComma(parts)
}

// lastInterruption returns the most recent interruption from either the
// campaign's own record or the fault manifest.
func lastInterruption(restarts []RestartRecord, faults []Fault) (time.Time, bool) {
	var latest time.Time
	found := false
	for _, r := range restarts {
		if !found || r.At.After(latest) {
			latest, found = r.At, true
		}
	}
	for _, f := range faults {
		// An interruption's effect starts when it is armed; a cleared one
		// completed then, which is the moment recovery is judged from.
		t := f.Armed
		if !f.Cleared.IsZero() {
			t = f.Cleared
		}
		if !found || t.After(latest) {
			latest, found = t, true
		}
	}
	return latest, found
}

// latestBefore returns the newest retained observation strictly before t.
func latestBefore(hist []*Observation, t time.Time) *Observation {
	var out *Observation
	for _, o := range hist {
		if o.At.Before(t) {
			out = o
		}
	}
	return out
}

// matchingView finds the same witness in an earlier observation.
func matchingView(o *Observation, v devView) (devView, bool) {
	for _, p := range deviceViews(o) {
		if p.Witness == v.Witness && p.Label == v.Label {
			return p, true
		}
	}
	return devView{}, false
}
