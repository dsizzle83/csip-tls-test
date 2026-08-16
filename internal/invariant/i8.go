package invariant

// i8.go — No unbounded growth in memory, goroutines, file descriptors or disk
// under sustained adversarial load.
//
// Grounding: CCP-01 (the outbox self-compaction path has no production caller —
// the log grows without bound; bench proof was 5.05 MB / 26 726 lines / zero
// compact records) and LSN-02 (a persistent EMFILE turns the :802 accept loop
// into an unthrottled hot spin).
//
// # What a monitor can honestly claim about unboundedness
//
// It cannot prove unboundedness. A run of minutes or hours sees a finite prefix
// of a sequence, and no finite prefix distinguishes "grows forever" from "grows
// until it compacts at 10 MB". Pretending otherwise would give this suite a
// check that fires on healthy devices under load, which is the fastest way to
// train operators to ignore it.
//
// So I8 claims exactly three things, in descending strength:
//
//	CEILING CROSSED — a watched file exceeded a ceiling the operator declared,
//	  or free space on a watched mount fell below a declared floor. This is a
//	  FAIL and needs no inference: a stated bound was crossed.
//
//	MONOTONE WITH NO RECLAIM — a watched quantity rose across the whole retained
//	  window and never once fell. That is not proof of unboundedness, but it IS
//	  proof that no compaction ran during the window, which is precisely CCP-01's
//	  observable signature. It is a WARN carrying the observed slope and the
//	  projected time to the ceiling when one is known.
//
//	SESSION LEAK — the count of sessions the DUT holds against a DER rose
//	  monotonically across the window and more than doubled. This one needs no
//	  shell at all: the device sim publishes its own session table, so a
//	  descriptor leak in the DUT's southbound client is visible from outside.
//	  Above a floor it is a FAIL, because a session count that only ever rises
//	  is not load, it is a leak.
//
// The first two need [HostSource], which is host-level accounting over a
// read-only SSH allowlist. When it is absent — and it always will be against a
// fielded device — those arms SKIP with that as their reason and the session arm
// still runs.

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type i8 struct{ p Params }

// NewI8 returns the bounded-resource invariant.
func NewI8(p Params) Invariant { return &i8{p: p} }

func (i *i8) ID() string { return "I8" }

func (i *i8) Grounding() string {
	return "CCP-01 — the outbox self-compaction path has no production caller and the durable log " +
		"grows without bound; LSN-02 — a persistent accept error becomes an unthrottled hot loop."
}

func (i *i8) Statement() string {
	return "No unbounded growth under sustained adversarial load. PARTIAL BY NECESSITY: a finite " +
		"observation window cannot prove unboundedness, so this asserts three weaker things and says " +
		"which one fired — (a) FAIL when a watched file crosses an operator-declared ceiling " +
		"(-param growth_files, growth_ceiling_bytes) or a watched mount falls below a declared floor " +
		"(-param min_free_kb); (b) WARN when a watched quantity rose across the whole window and " +
		"never fell, which is not proof of unboundedness but IS proof no reclaim ran; (c) FAIL when " +
		"the session count a DER sim reports for the DUT rises monotonically and more than doubles " +
		"above a floor, which needs no shell and is a leak rather than load. Arms (a) and (b) SKIP " +
		"with that reason when no host introspection is configured."
}

func (i *i8) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	hist := w.History()
	if len(hist) < 3 {
		return skipf("only %d observations retained; growth needs at least 3 to have a shape", len(hist)), nil
	}

	res := Result{Verdict: Pass}
	// Growth findings are identified by the SERIES that grew — the DER whose
	// session table climbs, the file path, the mount — and never by the numbers
	// in it. Every number here rises on every tick by construction, so a
	// fact-hashed identity would mint a fresh finding per tick for one leak.
	// See [keyer].
	key := keysOf(&res)
	var skips []string

	// ── Session-leak arm: no shell required ───────────────────────────────
	//
	// Both arms note THROUGH the check's own keyer rather than returning one key
	// string. Each of them can find several things at once — two DERs leaking
	// sessions, three files over the ceiling — and the single returned key kept
	// only the first, so every other leak was reported with no identity of its
	// own and could be neither counted nor shrunk (IW15-032).
	sv, sChecked, sFacts, sReason := i.sessionArm(hist, key)
	res.Checked += sChecked
	res.Verdict = Worse(res.Verdict, sv)
	res.Facts = append(res.Facts, sFacts...)
	if sChecked == 0 && sReason != "" {
		skips = append(skips, sReason)
	}

	// ── Host arms ─────────────────────────────────────────────────────────
	if !obs.Host.Available {
		why := "no gateway introspection is configured, so file growth and free space are not observable"
		if obs.Host.Err != "" {
			why += " (" + obs.Host.Err + ")"
		}
		skips = append(skips, why)
	} else {
		hv, hChecked, hFacts, hReason := i.hostArm(hist, key)
		res.Checked += hChecked
		res.Verdict = Worse(res.Verdict, hv)
		res.Facts = append(res.Facts, hFacts...)
		if res.Reason == "" && hv != Pass {
			res.Reason = hReason
		}
		if hChecked == 0 && hReason != "" {
			skips = append(skips, hReason)
		}
	}

	if res.Reason == "" && sv != Pass {
		res.Reason = sReason
	}
	if res.Checked == 0 {
		return skipf("%s", joinComma(skips)), nil
	}
	if res.Verdict == Pass {
		note := fmt.Sprintf("%d growth series checked across %d observations spanning %s",
			res.Checked, len(hist), dur(hist[len(hist)-1].At.Sub(hist[0].At)))
		if len(skips) > 0 {
			note += "; not checked: " + joinComma(skips)
		}
		res.Assertions = append(res.Assertions, narrate(
			"no watched resource grew monotonically or crossed a declared bound",
			"compare each series across the whole retained window for monotone growth and ceiling crossings",
			Pass, note))
	}
	return res, nil
}

// sessionArm looks for a southbound session leak using only what the DER sims
// publish about themselves. It notes one identity per climbing DER into key:
// which DER's session table is climbing, and whether the climb passed the leak
// floor (a FAIL) or is still only suspicious (a WARN) — two different tickets
// that must not share a signature, and two DERs that are two tickets.
func (i *i8) sessionArm(hist []*Observation, key *keyer) (Verdict, int, []Fact, string) {
	const leakFloor = 8 // below this, growth is indistinguishable from warm-up
	last := hist[len(hist)-1]
	checked := 0
	verdict := Pass
	var facts []Fact
	reason := ""
	for _, name := range last.DERNames() {
		if !last.DERs[name].HasSessions {
			continue
		}
		series := make([]int, 0, len(hist))
		for _, o := range hist {
			if d, ok := o.DERs[name]; ok && d.HasSessions {
				series = append(series, d.Sessions)
			}
		}
		if len(series) < 3 {
			continue
		}
		checked++
		if !monotoneNonDecreasing(series) || series[len(series)-1] <= series[0] {
			continue
		}
		first, latest := series[0], series[len(series)-1]
		grew := latest >= leakFloor && (first == 0 || latest >= 2*first)
		v := Warn
		if grew {
			v = Fail
		}
		verdict = Worse(verdict, v)
		facts = append(facts,
			F("i8.sessions."+name+".series", "count", last.DERs[name].Source, "%v", series),
			F("i8.sessions."+name+".first", "count", last.DERs[name].Source, "%d", first),
			F("i8.sessions."+name+".last", "count", last.DERs[name].Source, "%d", latest),
			F("i8.sessions."+name+".window", "s", "monitor", "%s", dur(hist[len(hist)-1].At.Sub(hist[0].At))),
		)
		if grew {
			key.note(Fail, "session-leak:%s", name)
		} else {
			key.note(Warn, "session-growth:%s", name)
		}
		if reason == "" {
			reason = fmt.Sprintf("the sessions %s reports the DUT holding rose monotonically from %d to %d over %s "+
				"and never once fell — a session count that only rises is a leak, not load",
				name, first, latest, dur(hist[len(hist)-1].At.Sub(hist[0].At)))
		}
	}
	if checked == 0 {
		return Pass, 0, nil, "no DER publishes a session table, so a southbound session leak is not observable"
	}
	return verdict, checked, facts, reason
}

// hostArm checks watched files and mounts. It notes one identity per offender
// into key: the PATH or MOUNT at fault, plus which claim it broke — over a
// declared ceiling, growing with no reclaim, or below the free-space floor. The
// byte counts stay out; they change on every sample.
func (i *i8) hostArm(hist []*Observation, key *keyer) (Verdict, int, []Fact, string) {
	last := hist[len(hist)-1]
	ceiling, hasCeiling := i.p.Float("growth_ceiling_bytes")
	minFree, hasMinFree := i.p.Float("min_free_kb")

	checked := 0
	verdict := Pass
	var facts []Fact
	reason := ""

	// key is the CHECK's keyer, shared with the session arm: a free-space FAIL
	// discovered after a growth WARN displaces the WARN's identity wherever that
	// WARN came from, which the per-arm keyer this used to hold could not do.
	// See [keyer].
	for _, path := range sortedFileKeys(last.Host.FileBytes) {
		series := make([]int64, 0, len(hist))
		for _, o := range hist {
			if v, ok := o.Host.FileBytes[path]; ok {
				series = append(series, v)
			}
		}
		if len(series) < 3 {
			continue
		}
		checked++
		first, latest := series[0], series[len(series)-1]
		span := hist[len(hist)-1].At.Sub(hist[0].At)

		if hasCeiling && float64(latest) > ceiling {
			verdict = Fail
			facts = append(facts,
				F("i8.file."+path+".bytes", "bytes", last.Host.Source, "%d", latest),
				F("i8.file."+path+".ceiling", "bytes", "-param growth_ceiling_bytes", "%s", trimFloat(ceiling)),
			)
			if reason == "" {
				reason = fmt.Sprintf("%s is %d bytes, over the declared ceiling of %s", path, latest, trimFloat(ceiling))
			}
			key.note(Fail, "file-over-ceiling:%s", path)
			continue
		}
		if !monotoneNonDecreasingI64(series) || latest <= first || span <= 0 {
			continue
		}
		rate := float64(latest-first) / span.Seconds()
		verdict = Worse(verdict, Warn)
		f := []Fact{
			F("i8.file."+path+".first", "bytes", last.Host.Source, "%d", first),
			F("i8.file."+path+".last", "bytes", last.Host.Source, "%d", latest),
			F("i8.file."+path+".rate", "bytes", last.Host.Source, "%.1f per second over %s", rate, dur(span)),
			F("i8.file."+path+".reclaim", "", last.Host.Source, "no decrease observed in %d samples", len(series)),
		}
		if hasCeiling && rate > 0 {
			eta := time.Duration((ceiling - float64(latest)) / rate * float64(time.Second))
			f = append(f, F("i8.file."+path+".eta_to_ceiling", "s", "projection", "%s", dur(eta)))
		}
		facts = append(facts, f...)
		if reason == "" {
			reason = fmt.Sprintf("%s grew monotonically from %d to %d bytes over %s with no reclaim observed — "+
				"not proof of unboundedness, but proof that no compaction ran", path, first, latest, dur(span))
		}
		key.note(Warn, "file-growth-no-reclaim:%s", path)
	}

	if hasMinFree {
		for _, mount := range sortedFileKeys(last.Host.FSFreeKB) {
			checked++
			free := last.Host.FSFreeKB[mount]
			if float64(free) >= minFree {
				continue
			}
			verdict = Fail
			facts = append(facts,
				F("i8.fs."+mount+".free_kb", "kB", last.Host.Source, "%d", free),
				F("i8.fs."+mount+".floor_kb", "kB", "-param min_free_kb", "%s", trimFloat(minFree)),
			)
			if reason == "" {
				reason = fmt.Sprintf("%s has %d kB free, below the declared floor of %s kB", mount, free, trimFloat(minFree))
			}
			key.note(Fail, "free-space-below-floor:%s", mount)
		}
	}

	if checked == 0 {
		return Pass, 0, nil, "gateway introspection is configured but no files or mounts are watched " +
			"(-param growth_files / the host source's watch list is empty)"
	}
	return verdict, checked, facts, reason
}

func monotoneNonDecreasing(s []int) bool {
	for i := 1; i < len(s); i++ {
		if s[i] < s[i-1] {
			return false
		}
	}
	return true
}

func monotoneNonDecreasingI64(s []int64) bool {
	for i := 1; i < len(s); i++ {
		if s[i] < s[i-1] {
			return false
		}
	}
	return true
}

func sortedFileKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
