package gwmayhem

// northbound_malform.go is FAMILY A — CSIP-northbound malformation. The gateway's
// lexa-northbound is a 2030.5 CLIENT walking a head-end; here the head-end (the
// bench gridsim) is the ADVERSARY, armed to serve a malformed resource or to
// fault the WAN while the gateway is walking it. The invariant is FAIL-CLOSED:
// under a hostile/broken head-end the gateway must never apply a malformed or
// absurd setpoint to a DER, must hold any safe cap it had already adopted, and
// must never go dark (a walker panic / deadlock / hang). This mirrors the
// dashboard Mayhem `malform-*` family (cmd/dashboard/mayhem.go diagnoseMalform),
// but observed from the SOUTHBOUND — the DER's applied state read from the sim
// /state — because the gateway's northbound :802 and dev /status are not
// desktop-reachable.
//
// Go-literal, not data: the arm drives an HTTP admin API (the gridsim
// malformation / outage / clock adversary) and samples the sims' /state over a
// hold — real logic outside the aggregator campaign schema.

import (
	"context"
	"fmt"
	"math"
	"time"
)

// gridsim admin-API vocabulary the family-A adversary drives. These are the WIRE
// strings the gridsim's POST /admin/malform + /admin/outage accept — transcribed
// here (not imported from sim/gridsim) both for referee independence, like the
// RBAC contract in rbac.go, and to keep this package's test binary on the
// client-only wolfSSL link (importing the gridsim TLS SERVER drags in the
// server-side DH object make test-fast must not need).
const (
	malformMissingHref        = "missing_href"
	malformEmptyProgramList   = "empty_program_list"
	malformHugeActivePower    = "huge_activepower"
	malformNegativeActivePwr  = "negative_activepower"
	malformBadDuration        = "bad_duration"
	malformPagination         = "pagination"
	malformHugePrice          = "huge_price"
	malformBadPriceMultiplier = "bad_price_multiplier"
	malformEmptyCurveList     = "empty_curve_list"

	outageModeDown = "down"
	outageModeHang = "hang"
)

// nbMalform classes.
const (
	nbClassResource = "resource"      // a malformed DERProgram/Control resource
	nbClassPricing  = "pricing"       // a malformed tariff/price resource
	nbClassCurve    = "curve"         // a malformed/empty DER curve list
	nbClassHeadend  = "headend-fault" // a WAN outage / hang / clock warp
)

// nbClockJumpOffsetS is the forward clock step the clock-jump adversary warps the
// head-end by (~46 days) — far enough that a naive schedule evaluation that
// trusts the served clock would mis-window every control, so "stays sane" means
// the gateway neither applies an absurd setpoint nor crashes.
const nbClockJumpOffsetS = 4_000_000

// northboundMalformScenarios is family A: one scenario per gridsim malformation
// kind (mirroring the hub's malform-* set) plus the three head-end faults.
func northboundMalformScenarios() []gwScenario {
	return []gwScenario{
		nbResourceScenario("nb-malform-missing-href", "head-end strips the program list's href (unresolvable)", malformMissingHref, nbClassResource),
		nbResourceScenario("nb-malform-empty-program", "head-end serves an empty program list", malformEmptyProgramList, nbClassResource),
		nbResourceScenario("nb-malform-huge-activepower", "head-end serves an absurd ActivePower export limit (overflow bait)", malformHugeActivePower, nbClassResource),
		nbResourceScenario("nb-malform-negative-activepower", "head-end serves a NEGATIVE ActivePower export ceiling", malformNegativeActivePwr, nbClassResource),
		nbResourceScenario("nb-malform-bad-duration", "head-end serves a ~136-year control interval", malformBadDuration, nbClassResource),
		nbResourceScenario("nb-malform-pagination", "head-end lies about list pagination (all=999, one page)", malformPagination, nbClassResource),
		nbResourceScenario("nb-malform-huge-price", "head-end serves a malicious price (int32 max)", malformHugePrice, nbClassPricing),
		nbResourceScenario("nb-malform-bad-price-multiplier", "head-end serves an absurd price multiplier (10^100)", malformBadPriceMultiplier, nbClassPricing),
		nbResourceScenario("nb-malform-empty-curve", "head-end serves an empty DER curve list (link present, curves absent)", malformEmptyCurveList, nbClassCurve),

		nbHeadendScenario("nb-headend-wan-outage", "WAN outage: head-end dies mid-control (503) — gateway holds fail-closed", "outage-down",
			func(ctx context.Context, b BenchConfig) error {
				return b.armOutage(ctx, outageModeDown, nbOutageDurationS(b), 0)
			}),
		nbHeadendScenario("nb-headend-hang", "northbound hang: head-end accepts then stalls — gateway times out + holds", "outage-hang",
			func(ctx context.Context, b BenchConfig) error {
				return b.armOutage(ctx, outageModeHang, nbOutageDurationS(b), 30)
			}),
		nbHeadendScenario("nb-headend-clock-jump", "clock jump: head-end steps its served CSIP clock ~46 days — schedule stays sane", "clock-jump",
			func(ctx context.Context, b BenchConfig) error { return b.setClock(ctx, nbClockJumpOffsetS) }),
	}
}

// nbOutageDurationS is how long a gridsim outage should self-hold: past the whole
// sample window (settle + samples×interval) plus margin, so the outage covers
// every sample yet auto-clears if the run aborts.
func nbOutageDurationS(b BenchConfig) int {
	t := b.timing()
	total := t.Settle + time.Duration(t.Samples)*t.Interval
	return int(total.Seconds()) + 30
}

// nbResourceScenario builds a malformed-resource scenario driven by a gridsim
// malform kind. Every one is security-critical and PINNED to PASS: a conformant
// gateway contains the malformation (holds safe, never applies garbage, never
// crashes).
func nbResourceScenario(id, desc, kind, class string) gwScenario {
	return gwScenario{
		ID:         id,
		Desc:       desc,
		Category:   "csip-northbound-malform",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "nbMalform",
		arm: func(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
			return armNB(ctx, w, ev, kind, class,
				func(ctx context.Context, b BenchConfig) error { return b.armMalform(ctx, kind) })
		},
		teardown: func(ctx context.Context, w *gwWorld) { w.bench.clearBench(ctx) },
	}
}

// nbHeadendScenario builds a head-end-fault scenario (WAN outage / hang / clock
// jump) driven by the supplied adversary closure.
func nbHeadendScenario(id, desc, kind string, arm func(ctx context.Context, b BenchConfig) error) gwScenario {
	return gwScenario{
		ID:         id,
		Desc:       desc,
		Category:   "csip-northbound-malform",
		Source:     SourceGo,
		Security:   true,
		Expected:   []Verdict{VerdictPass},
		NeedsBench: true,
		oracle:     "nbMalform",
		arm: func(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
			return armNB(ctx, w, ev, kind, nbClassHeadend, arm)
		},
		teardown: func(ctx context.Context, w *gwWorld) { w.bench.clearBench(ctx) },
	}
}

// armNB is the shared family-A arm: capture the DER baseline, arm the adversary,
// then sample the DERs' applied state + the gateway's liveness across the hold.
// It fills ev.NBMalform; the nbMalform oracle judges it.
func armNB(ctx context.Context, w *gwWorld, ev *gwEvidence, kind, class string, arm func(ctx context.Context, b BenchConfig) error) error {
	b := w.bench
	out := &nbMalformOutcome{Kind: kind, Class: class, BaselinePct: math.NaN()}
	ev.NBMalform = out

	if b.GridsimAdmin == "" || (!b.Plain.configured() && !b.Secure.configured()) {
		ev.SetupErr = "bench not wired (need -gridsim-admin and at least one -inv-* DER sim) — cannot drive/observe the head-end malformation"
		return nil
	}

	// Baseline: the DER's applied cap BEFORE the malformation, and the secure
	// device's poll counter (the gateway-liveness reference).
	basePoll, havePollBase := w.nbBaseline(ctx, out)

	if err := arm(ctx, b); err != nil {
		ev.SetupErr = "arm head-end adversary: " + err.Error()
		return nil
	}

	t := b.timing()
	benchSleep(ctx, t.Settle)
	prevPoll := basePoll
	for i := 0; i < t.Samples; i++ {
		if i > 0 {
			benchSleep(ctx, t.Interval)
		}
		if ctx.Err() != nil {
			break
		}
		got := false
		for _, sim := range w.nbSims() {
			snap, err := b.readDER(ctx, sim)
			if err != nil {
				continue
			}
			got = true
			out.Samples++ // a per-device sample
			if absurdPct(snap.AppliedPct) {
				out.AbsurdApplied = true
				out.AbsurdPct = snap.AppliedPct
			}
			// Unseat: a safe baseline cap that has become uncapped.
			if out.BaselineCap && !isCap(snap.AppliedPct) && !math.IsNaN(snap.AppliedPct) {
				out.Unseated = true
			} else if out.BaselineCap && isCap(snap.AppliedPct) {
				out.Unseated = false // still capped this sample → recovered/held
			}
			// Liveness comes from the secure device's poll counter advancing.
			if sim.Secure && snap.HasPoll {
				out.LiveObs++
				if snap.PollRequests > prevPoll {
					out.LiveOK++
				}
				prevPoll = snap.PollRequests
			}
		}
		if got {
			out.Observed = true
		}
	}
	if havePollBase && out.LiveObs == 0 {
		out.Note = joinNote(out.Note, "gateway liveness unobservable (secure device reported no poll sessions)")
	}
	return nil
}

// nbBaseline reads the pre-arm DER state: the tightest applied cap across the
// configured sims (the value the gateway must HOLD) and the secure device's poll
// counter. It records BaselineCap/BaselinePct on out.
func (w *gwWorld) nbBaseline(ctx context.Context, out *nbMalformOutcome) (basePoll int, havePoll bool) {
	tightest := math.NaN()
	for _, sim := range w.nbSims() {
		snap, err := w.bench.readDER(ctx, sim)
		if err != nil {
			continue
		}
		if !math.IsNaN(snap.AppliedPct) {
			if math.IsNaN(tightest) || snap.AppliedPct < tightest {
				tightest = snap.AppliedPct
			}
		}
		if sim.Secure && snap.HasPoll {
			basePoll, havePoll = snap.PollRequests, true
		}
	}
	out.BaselinePct = tightest
	out.BaselineCap = isCap(tightest)
	if !out.BaselineCap {
		out.Note = joinNote(out.Note, fmt.Sprintf("no safe cap adopted at baseline (applied=%s) — hold-invariant not asserted, crash+absurd checks apply", pctStr(tightest)))
	}
	return basePoll, havePoll
}

// nbSims returns the configured DER sims for the wave-2 families (plain first, so
// evidence orders the plain device before the secure one).
func (w *gwWorld) nbSims() []DERSim {
	var out []DERSim
	if w.bench.Plain.configured() {
		out = append(out, w.bench.Plain)
	}
	if w.bench.Secure.configured() {
		out = append(out, w.bench.Secure)
	}
	return out
}

// pctStr formats an applied pct for a finding, rendering NaN as "unreadable".
func pctStr(pct float64) string {
	if math.IsNaN(pct) {
		return "unreadable"
	}
	return fmt.Sprintf("%.1f%%", pct)
}
