package invariant

// i4.go — A credential lacking write authorization can never cause a write, by
// any path, and denial is indistinguishable across causes.
//
// Grounding: Secure SunSpec RBAC-009.
//
// # Two claims, and the second one is the interesting one
//
// The first claim is easy to state and easy to check: no unauthorized credential
// ever gets a write accepted, and no value it tried to write ever appears
// downstream. "By any path" is the load-bearing phrase — a credential that is
// refused at the northbound but whose value nonetheless reaches a DER (through
// a queue, a replay, a shared cache) has caused a write, and the register image
// is where that shows up, not the exception code.
//
// The second claim is about what a denial TELLS an attacker. If a role denial
// answers exception 0x01 and a revoked certificate answers 0x02, an attacker
// with one certificate can enumerate the trust store by watching which code
// comes back. So the observable SHAPE of every authorization denial — exception
// code, whether the connection was torn down, what alert was sent — must be
// identical regardless of why the request was denied.
//
// The scope of that second claim is narrower than it first appears, and getting
// the scope wrong would make this invariant fire on correct behaviour. A
// handshake failure and an authorization denial are unavoidably distinguishable:
// one produces a TLS alert and no session, the other produces a session that
// refuses requests. No implementation can hide that and the spec does not ask
// it to. So the indistinguishability arm applies ONLY across causes that were
// denied at the SAME stage, and the statement says so.
//
// Timing gets a WARN, never a FAIL. A timing side channel is a statistical
// claim, and a monitor tick has a handful of samples taken under a chaos
// campaign that is deliberately perturbing latency. Reporting "these two causes
// differed by 8× in mean round-trip over 5 samples" is useful; calling it a
// safety violation on that evidence would not be honest.

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type i4 struct{ p Params }

// NewI4 returns the authorization invariant.
func NewI4(p Params) Invariant { return &i4{p: p} }

func (i *i4) ID() string { return "I4" }

func (i *i4) Grounding() string {
	return "Secure SunSpec RBAC-009 — an authorization denial must not disclose why it was denied, " +
		"and a credential without write authority must not be able to cause a write by any route."
}

func (i *i4) Statement() string {
	return "A credential lacking write authorization can never cause a write, by any path — no " +
		"accepted write, and no value it attempted appearing at any DER — and every authorization " +
		"denial presents the same observable shape (exception code, connection disposition) " +
		"regardless of cause. PARTIAL: indistinguishability is asserted only ACROSS CAUSES DENIED " +
		"AT THE SAME STAGE, because a handshake rejection and an in-session authorization refusal " +
		"are unavoidably distinguishable and no implementation is asked to hide that; and timing " +
		"differences are reported as WARN, never FAIL, because a timing side channel is a " +
		"statistical claim a monitor tick cannot honestly make."
}

func (i *i4) Check(ctx context.Context, w *World) (Result, error) {
	_ = ctx
	obs := w.Now()
	if obs == nil {
		return skipf("the world has not been observed yet"), nil
	}
	writes := w.Ledger().Writes()
	auths := w.Ledger().Auths()
	if len(writes) == 0 && len(auths) == 0 {
		return skipf("the campaign has attempted no write and no authentication, so authorization is not under test"), nil
	}

	res := Result{Verdict: Pass}

	// ── Arm 1: an unauthorized credential must never get a write accepted ──
	unauthorized := 0
	for _, r := range writes {
		if r.Authorized {
			continue
		}
		unauthorized++
		res.Checked++
		if !r.Accepted {
			continue
		}
		res.Verdict = Fail
		res.Facts = append(res.Facts,
			F("i4.accepted.seq", "", "ledger", "%d", r.Seq),
			F("i4.accepted.credential", "", "ledger", "%s (role %s, domain %s)", r.Credential, r.Role, r.Domain),
			F("i4.accepted.target", "", "ledger", "unit %d model %d point %s", r.Unit, r.Model, r.Point),
			F("i4.accepted.value", string(r.Value.Unit), "ledger", "%s", trimFloat(r.Value.Val)),
		)
		if res.Reason == "" {
			res.Reason = fmt.Sprintf("credential %q (role %s) has no write authorization but write#%d was ACCEPTED "+
				"on unit %d point %s", r.Credential, r.Role, r.Seq, r.Unit, r.Point)
		}
		res.Assertions = append(res.Assertions, narrate(
			"an unauthorized credential's write is refused",
			"attempt the write with the unauthorized credential and record the DUT's answer",
			Fail, res.Reason))
	}

	// ── Arm 2: "by any path" — the attempted value must not appear downstream ──
	for _, r := range writes {
		if r.Authorized || !r.Distinctive {
			continue
		}
		for _, v := range deviceViews(obs) {
			cmd, ok := commandOf(v.Unit.Commands(v.Source), r.Point)
			if !ok || !cmd.Raw.Known() {
				continue
			}
			res.Checked++
			if cmd.Raw.Unit != r.Value.Unit || !nearly(cmd.Raw.Val, r.Value.Val, i.p.Tol.Rel, 0.5) {
				continue
			}
			res.Verdict = Fail
			res.Facts = append(res.Facts,
				F("i4.leaked.seq", "", "ledger", "%d", r.Seq),
				F("i4.leaked.credential", "", "ledger", "%s", r.Credential),
				F("i4.leaked.witness", "", v.Source, "%s", v.Label),
				F("i4.leaked.value", string(cmd.Raw.Unit), v.Source, "%s", trimFloat(cmd.Raw.Val)),
			)
			if res.Reason == "" {
				res.Reason = fmt.Sprintf("credential %q was denied write#%d, but its distinctive value %s "+
					"is now present at %s — the write happened by some other path",
					r.Credential, r.Seq, r.Value, v.Label)
			}
		}
	}

	// ── Arm 3: denial shape must not vary with cause, within a stage ──────
	shapeV, shapeChecked, shapeFacts, shapeReason := i.indistinguishable(auths)
	res.Checked += shapeChecked
	res.Verdict = Worse(res.Verdict, shapeV)
	res.Facts = append(res.Facts, shapeFacts...)
	if res.Reason == "" && shapeV != Pass {
		res.Reason = shapeReason
	}

	if res.Checked == 0 {
		return skipf("the campaign recorded no unauthorized attempt and no denial to compare shapes across"), nil
	}
	if res.Verdict == Pass {
		res.Assertions = append(res.Assertions, narrate(
			"no unauthorized credential caused a write, and denials did not vary with cause",
			"ledger of attempts cross-checked against every witness's register image; denial shapes grouped by stage",
			Pass, fmt.Sprintf("%d unauthorized write attempts, all refused; %d denial shapes compared", unauthorized, shapeChecked)))
	}
	return res, nil
}

// denialShape is the observable signature of a refusal: everything an attacker
// on the wire could use to tell one cause from another, excluding timing.
type denialShape struct {
	Stage      string
	Exception  uint8
	ClosedConn bool
	TLSAlert   string
}

func (s denialShape) String() string {
	return fmt.Sprintf("stage=%s exception=0x%02X closed=%t alert=%q", s.Stage, s.Exception, s.ClosedConn, s.TLSAlert)
}

// indistinguishable groups denials by stage and asserts that within a stage,
// every cause produced the same shape.
func (i *i4) indistinguishable(auths []AuthRecord) (Verdict, int, []Fact, string) {
	// stage -> cause -> shapes seen
	byStage := map[string]map[DenialCause]map[denialShape]int{}
	rtt := map[string][]time.Duration{}
	for _, a := range auths {
		if a.Authenticated || a.Cause == "" {
			continue
		}
		stage := a.Stage
		if stage == "" {
			stage = "unspecified"
		}
		sh := denialShape{Stage: stage, Exception: a.ExceptionCode, ClosedConn: a.ClosedConn, TLSAlert: a.TLSAlert}
		if byStage[stage] == nil {
			byStage[stage] = map[DenialCause]map[denialShape]int{}
		}
		if byStage[stage][a.Cause] == nil {
			byStage[stage][a.Cause] = map[denialShape]int{}
		}
		byStage[stage][a.Cause][sh]++
		if a.RTT > 0 {
			key := stage + "/" + string(a.Cause)
			rtt[key] = append(rtt[key], a.RTT)
		}
	}

	checked := 0
	verdict := Pass
	var facts []Fact
	reason := ""
	for _, stage := range sortedKeysOf(byStage) {
		causes := byStage[stage]
		if len(causes) < 2 {
			continue // one cause at this stage: nothing to be distinguishable from
		}
		checked++
		shapes := map[denialShape][]DenialCause{}
		for _, cause := range sortedCauses(causes) {
			for sh := range causes[cause] {
				shapes[sh] = append(shapes[sh], cause)
			}
		}
		if len(shapes) <= 1 {
			continue
		}
		verdict = Fail
		for sh, cs := range shapes {
			names := make([]string, 0, len(cs))
			for _, c := range cs {
				names = append(names, string(c))
			}
			sort.Strings(names)
			facts = append(facts, F("i4.shape."+stage+"."+sh.String(), "", "ledger", "%s", joinComma(names)))
		}
		if reason == "" {
			reason = fmt.Sprintf("at the %s stage, %d distinct denial shapes were observed across %d causes — "+
				"an attacker can tell why they were denied", stage, len(shapes), len(causes))
		}
	}

	// Timing: report, never fail.
	if tv, tf, treason := i.timingSkew(rtt); tv != Pass {
		verdict = Worse(verdict, tv)
		facts = append(facts, tf...)
		if reason == "" {
			reason = treason
		}
		checked++
	}
	return verdict, checked, facts, reason
}

// timingSkew reports a large mean-RTT difference between denial causes as a
// WARN. minSamples keeps a single unlucky measurement under a chaos campaign
// from generating noise.
func (i *i4) timingSkew(rtt map[string][]time.Duration) (Verdict, []Fact, string) {
	const minSamples = 3
	const ratioAlarm = 3.0
	type stat struct {
		key  string
		mean time.Duration
		n    int
	}
	var stats []stat
	for _, k := range sortedKeysOfSlice(rtt) {
		samples := rtt[k]
		if len(samples) < minSamples {
			continue
		}
		var total time.Duration
		for _, d := range samples {
			total += d
		}
		stats = append(stats, stat{k, total / time.Duration(len(samples)), len(samples)})
	}
	if len(stats) < 2 {
		return Pass, nil, ""
	}
	lo, hi := stats[0], stats[0]
	for _, s := range stats {
		if s.mean < lo.mean {
			lo = s
		}
		if s.mean > hi.mean {
			hi = s
		}
	}
	if lo.mean <= 0 || float64(hi.mean)/float64(lo.mean) < ratioAlarm {
		return Pass, nil, ""
	}
	return Warn, []Fact{
			F("i4.timing.fastest", "s", "ledger", "%s mean over %d samples (%s)", lo.mean, lo.n, lo.key),
			F("i4.timing.slowest", "s", "ledger", "%s mean over %d samples (%s)", hi.mean, hi.n, hi.key),
		}, fmt.Sprintf("denial round-trip differs %.1f× between causes (%s vs %s) — reported, not failed: a timing "+
			"side channel needs statistics a monitor tick cannot produce, especially under an active chaos campaign",
			float64(hi.mean)/float64(lo.mean), lo.key, hi.key)
}

func sortedKeysOf(m map[string]map[DenialCause]map[denialShape]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOfSlice(m map[string][]time.Duration) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCauses(m map[DenialCause]map[denialShape]int) []DenialCause {
	out := make([]DenialCause, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func nearly(a, b, rel, floor float64) bool {
	slack := floor
	if s := absf(b) * rel; s > slack {
		slack = s
	}
	return absf(a-b) <= slack
}

func absf(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
