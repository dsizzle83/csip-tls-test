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
// # The SECOND alternative route: the harness's own apply-then-refuse lie
//
// IW15-031, adjudicated here. Distinctiveness guards ONE alternative route —
// the head-end independently commanding the same value. The peer-lie catalogue
// contains a second one, and this suite arms it deliberately:
// `exception_on_applied_write` makes a DER APPLY a write and then answer it with
// a Modbus exception (sim/southbound/lying.go, the OnWriteError hook). Under
// that fault the refused value is at the device BECAUSE OF THIS VERY WRITE, and
// the DUT — which relayed the device's own answer faithfully — contributed
// nothing. The inference "the value is present, therefore the refusal committed"
// is then simply invalid, and a FAIL emitted on it is a misattribution: it reads
// "the refusal did not prevent the value taking effect" when what happened is
// that the device applied it and lied about it.
//
// Three things settle it, and none of them is "gwloopback is only a peer":
//
//  1. I3's OWN soundness rule requires the exemption. The rule above is not a
//     caveat about the head-end; it is a general precondition — the value could
//     not have arrived by any other route — and this fault is another route.
//     Enforcing it against one confound and not the other is not a policy, it is
//     an oversight.
//
//  2. Under this fault the check is INDEPENDENT OF THE DUT. The fault puts the
//     value in the DER's own register bank, and this invariant's statement names
//     that bank as a damning witness. A DUT with no durable state whatsoever
//     fails identically to one riddled with ghost records, so the verdict is
//     measuring the injector. That is exactly the "lying by construction" this
//     file's distinctiveness section says the suite exists to stop.
//
//  3. The obligation the fault DOES probe is real, and it is not I3's. "A
//     gateway must read back rather than trust a write's answer, and must
//     reconcile a divergence it finds" is TRM-01's shape and a genuine product
//     duty — but I3's statement is a claim about STATE (the refused value is
//     absent), not about BEHAVIOUR (the DUT verified). Attaching a read-back
//     duty at judgement time would be inventing a requirement, which every
//     PARTIAL clause in this suite exists to prevent. It is also undischargeable
//     by the hermetic DUT: lexa-gw docs/ADVERSARIAL_QA_RUNBOOK.md §12 defines
//     gwloopback as a peer that does NOT reconcile head-end controls onto a DER
//     — no reconciler, no poll loop, no southbound write path of its own — so a
//     FAIL against it for failing to reconcile would be a finding about the
//     bench's stand-in, the same category error that makes 29 gw-mayhem
//     scenarios DECLINE rather than PASS vacuously.
//
// # Why the exemption is keyed on the ADVERSARY, not on the DUT
//
// An exemption reading "the DUT is gwloopback, so skip I3" would be wrong twice
// over: it would suppress genuine ghost-commit findings against gwloopback in
// every OTHER run, and it would leave the identical misattribution standing on
// the live bench, where the same fault against the real gateway produces the
// same unsound FAIL. So the predicate is a statement about the EXPERIMENT — the
// campaign armed an apply-then-refuse lie at this write's target, in force at
// the instant of the write, answering with the exception code the write got —
// and it is equally true hermetically and live. It costs nothing: every run that
// did not arm that lie still judges the ghost claim at full strength.
//
// # What it costs, said plainly
//
// It means the hermetic loopback can no longer produce an I3 FAIL at all, since
// apply-then-refuse is the only way a write refused there ever lands. That is
// not a loss of coverage, because that FAIL was never evidence about a DUT. A
// REAL I3 finding is a witness holding the refused value with NO apply-then-
// refuse lie in force at that write — OBX-01's actual shape, an outbox ghost —
// and it is reachable on the live bench and by the store suite, not here.
//
// The exemption is reported, never silent: the run emits a WARN carrying the
// confounding fault's target, kind, params and window as facts, so a bundle
// reader sees the exempt run and why it is exempt without opening this file.
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
	"strconv"
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
		"because a value the head-end is independently commanding proves nothing; a write refused " +
		"while the campaign's own apply-then-refuse lie (exception_on_applied_write) was in force at " +
		"its target is reported WARN and not FAIL, because that lie makes the DEVICE apply the value " +
		"and deny it, which explains the value's presence without any durable state on the DUT " +
		"(IW15-031); and the boot-replay arm is exercised only when an interruption is observed " +
		"within the run — a continuous monitor does not reboot a shared DUT, so full replay coverage " +
		"belongs to the power-cut harness."
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
	// The identity of an I3 finding is WHICH refused write left WHICH value at
	// WHICH witness. Deliberately absent: the ledger sequence number (assigned
	// in the order the campaign's goroutines reach the ledger, so it renumbers
	// between runs and under a shrink) and every timestamp. See [keyer].
	key := keysOf(&res)
	var skipped []string
	var exempt []string
	// The two verdicts keep two reasons, and the final one is chosen by the
	// verdict rather than by which fired first. Sharing `if res.Reason == ""`
	// between them would let an exempt WARN seen at an earlier witness claim
	// the sentence, so a genuine P1 later in the same tick would print "…so
	// this is NOT judged a violation of I3" next to a FAIL. Getting that
	// backwards is the exact mislabelling IW15-031 exists to remove.
	var failReason, exemptReason string
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
			// The refused value is present. Before calling that a ghost commit,
			// ask whether the harness itself put it there: an apply-then-refuse
			// lie in force at this write explains the value completely, with no
			// DUT-side durable state involved. See this file's header — the
			// inference is invalid under that fault, and reporting a P1 anyway
			// would be measuring the injector.
			if f, confounded := i.applyThenRefuseLie(obs, r, v); confounded {
				res.Verdict = Worse(res.Verdict, Warn)
				key.note(Warn, "lying-peer-confound:%s:%d:%s:%s:%s",
					r.Credential, r.Unit, r.Point, trimFloat(r.Value.Val), v.Label)
				res.Facts = append(res.Facts, i.factsFor(r, v, cmd, obs)...)
				res.Facts = append(res.Facts,
					F("i3.exempt.fault", "", "manifest", "%s", f),
					F("i3.exempt.fault_target", "", "manifest", "%s", f.Target),
					F("i3.exempt.fault_armed_at", "", "manifest", "%s", f.Armed.Format(time.RFC3339)),
					F("i3.exempt.fault_in_force_at_write", "", "manifest", "%t", f.InForce(r.At)),
					F("i3.exempt.rule", "", "invariant", "%s", exemptRule),
				)
				exemptWhy := fmt.Sprintf(
					"write#%d set %s=%s on unit %d, the DUT relayed a refusal (exception 0x%02X), and %s now "+
						"reads %s for that point — but the campaign had %s in force on %s at the instant of the "+
						"write, which makes the device APPLY a write and then refuse it. The value's presence is "+
						"fully explained by that injected lie and requires no durable state on the DUT, so this is "+
						"NOT judged a violation of I3: %s",
					r.Seq, r.Point, r.Value, r.Unit, r.ExceptionCode, v.Label, cmd.Raw, f.Kind, f.Target, exemptRule)
				if exemptReason == "" {
					exemptReason = exemptWhy
				}
				exempt = append(exempt, fmt.Sprintf("write#%d %s=%s at %s (confounded by %s on %s)",
					r.Seq, r.Point, r.Value, v.Label, f.Kind, f.Target))
				res.Assertions = append(res.Assertions, narrate(
					fmt.Sprintf("the value refused by write#%d is absent from %s", r.Seq, v.Label),
					"compare the refused register value against every witness's own register image after the "+
						"refusal, and attribute a match to the campaign's own apply-then-refuse lie when one was "+
						"in force at the write",
					Warn, exemptWhy))
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
			key.note(Fail, "ghost:%s:%d:%s:%s:%s",
				r.Credential, r.Unit, r.Point, trimFloat(r.Value.Val), v.Label)
			res.Facts = append(res.Facts, i.factsFor(r, v, cmd, obs)...)
			ghostWhy := fmt.Sprintf(
				"write#%d set %s=%s on unit %d and the DUT REFUSED it with exception 0x%02X, "+
					"yet %s now reads %s for that point%s — the refusal did not prevent the value taking effect",
				r.Seq, r.Point, r.Value, r.Unit, r.ExceptionCode, v.Label, cmd.Raw, afterRestart)
			if failReason == "" {
				failReason = ghostWhy
			}
			res.Assertions = append(res.Assertions, narrate(
				fmt.Sprintf("the value refused by write#%d is absent from %s", r.Seq, v.Label),
				"compare the refused register value against every witness's own register image after the refusal",
				Fail, ghostWhy))
		}
	}

	// The sentence belongs to the worst verdict reached, never to whichever
	// witness happened to be visited first.
	switch res.Verdict {
	case Fail:
		res.Reason = failReason
		if exemptReason != "" {
			res.Reason += fmt.Sprintf(" (%d further refused write×witness pair(s) in this tick were NOT judged, "+
				"because the campaign's own apply-then-refuse lie explains them — see i3.exempt.writes)", len(exempt))
		}
	case Warn:
		res.Reason = exemptReason
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
	if len(exempt) > 0 {
		// Surfaced even when something worse also happened, so a reader never
		// has to infer which of the run's refused writes were judged and which
		// the campaign's own adversary made unjudgeable.
		res.Facts = append(res.Facts,
			F("i3.exempt.count", "count", "invariant", "%d", len(exempt)),
			F("i3.exempt.writes", "", "invariant", "%s", joinComma(exempt)))
	}
	return res, nil
}

// exemptRule is the one-sentence statement of IW15-031's ruling, emitted as a
// fact so a bundle reader gets the reasoning without the source. It is a
// constant rather than an inline string because the console finding, the fact
// and the bundle assertion must not be able to drift apart.
const exemptRule = "I3 infers a ghost commit from the refused value's presence, and that inference is sound " +
	"only if the value could not have arrived by another route; an apply-then-refuse lie IS another route, " +
	"and one this campaign armed itself, so the presence is attributed to the injected fault rather than to " +
	"the DUT. The read-back-and-reconcile duty this fault does probe is TRM-01's, not I3's — I3 claims the " +
	"refused value is ABSENT, not that the DUT VERIFIED — and the hermetic DUT (gwloopback, runbook §12) has " +
	"no reconciler with which to discharge it."

// applyThenRefuseLie reports the fault, if any, that fully explains a refused
// write's value being present at a witness without any durable state on the DUT.
//
// Every clause is a load-bearing narrowing, because an over-broad exemption
// here would silently retire the whole invariant:
//
//   - KIND. Only `exception_on_applied_write` has apply-then-refuse semantics.
//     `reject_write` refuses AND does not apply, so a value appearing under it
//     is a genuine ghost; `ack_no_apply` is the mirror image and produces no
//     refused write at all.
//   - IN FORCE AT THE WRITE. A lie armed after the refusal cannot have caused
//     it. The window is the write's instant, not the observation's.
//   - EXCEPTION CODE. The fault answers a configured code (`ex_code`, default
//     0x04 per sim/southbound/lying.go). A refusal carrying a different code
//     came from somewhere else — the DUT's own RBAC or range check — and is
//     still judged.
//   - TARGET. The lie must be armed on a device that can actually account for
//     the value this witness is holding. On a DER witness that is the witness's
//     own device. On the DUT's PROJECTION witness it is the clause below, and
//     it is the one that was wrong.
//
// ── The TARGET clause on the projection witness, and why it fails closed ────
//
// This clause read `len(inScope) > 0 && !inScope[f.Target]`, scoping the
// exemption to the DERs the write record named. WriteRecord.DERs is populated
// by nobody in production — the campaign's own writeProbe never set it — so
// len(inScope) was always 0, the clause never rejected anything, and ANY
// apply-then-refuse lie in force on ANY device exempted a ghost seen on the
// DUT's projection. An exemption whose narrowest clause is a no-op is not an
// exemption; on a conformance harness it is a machine for turning FAILs into
// WARNs, which is the precise inversion of what this one was designed to be.
//
// The empty-means-everything convention came from WriteRecord.DERs' own doc,
// where it is correct FOR THE WITNESS SEARCH — "look at every observed DER" is
// the right default for where to go looking. Read as an exemption scope the
// same sentence says "any device's lie excuses anything", and the field is used
// for both. That is the whole defect: one field, two questions, opposite safe
// defaults.
//
// So the clause is now CAUSAL rather than nominal, and it fails closed:
//
//  1. If the record names a projection, the lying device must be in it.
//  2. The lying device must ITSELF be observed holding the refused value. That
//     is the exemption's actual claim — "the harness put that value there" — and
//     a device that is not holding it cannot be where the DUT's projection got
//     it. A lie on device A therefore cannot excuse a ghost projected from
//     device B, which is the property that was missing.
//  3. If the lying device cannot be observed at all, the exemption does NOT
//     fire. An exemption that cannot check its own scope must not fire: the
//     cost of failing closed is a FAIL a human adjudicates, and the cost of
//     failing open is a silent pass.
func (i *i3) applyThenRefuseLie(obs *Observation, r WriteRecord, v devView) (Fault, bool) {
	inScope := map[string]bool{}
	for _, d := range r.DERs {
		inScope[d] = true
	}
	for _, f := range obs.Faults.Faults {
		if f.Class != ClassPeerLie || f.Kind != lieApplyThenRefuse {
			continue
		}
		if !f.InForce(r.At) {
			continue
		}
		if code, ok := faultExceptionCode(f); !ok || code != r.ExceptionCode {
			continue
		}
		switch v.Witness {
		case witnessDER:
			if f.Target != v.Device {
				continue
			}
		default:
			if len(inScope) > 0 && !inScope[f.Target] {
				continue
			}
			if !i.lyingDeviceHoldsIt(obs, r, f.Target) {
				continue
			}
		}
		return f, true
	}
	return Fault{}, false
}

// lyingDeviceHoldsIt reports whether the device the lie is armed on is itself
// observed holding the refused value, in the register the write targeted.
//
// It is the causal half of the TARGET clause. The exemption's claim is that the
// campaign's own fault put the value where the DUT is projecting it from; a
// lying device that does not hold the value did not, and the ghost on the
// projection has some other source that this invariant is entitled to report.
//
// It returns FALSE when the device is not in the observation, or is
// unreachable, or serves no comparable register — every "cannot tell" answer.
// That is deliberate and is the direction that costs a false FAIL rather than a
// false PASS: an unexplained ghost is adjudicated by a human, an unnoticed one
// is not.
func (i *i3) lyingDeviceHoldsIt(obs *Observation, r WriteRecord, target string) bool {
	d, ok := obs.DERs[target]
	if !ok || !d.Reachable {
		return false
	}
	cmd, ok := commandOf(d.Unit.Commands(d.Source), r.Point)
	if !ok || !cmd.Raw.Known() {
		return false
	}
	return i.sameValue(cmd.Raw, r.Value)
}

// lieApplyThenRefuse is sim/southbound's name for the one fault kind that
// APPLIES a write and then answers it with a Modbus exception. Named here so
// the exemption predicate and the peer-lie catalogue cannot drift apart
// silently — a rename in the sim becomes a failing test, not a quietly dead
// exemption.
const lieApplyThenRefuse = "exception_on_applied_write"

// faultExceptionCode returns the exception the apply-then-refuse lie answers
// with. The sim's default when the parameter is absent is 0x04 (ILLEGAL DATA
// VALUE) — sim/southbound/lying.go's LieConfig.ExCode.
func faultExceptionCode(f Fault) (uint8, bool) {
	raw, ok := f.Params["ex_code"]
	if !ok || raw == "" {
		return 4, true
	}
	n, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, false
	}
	return uint8(n), true
}

// factsFor is the shared fact block for "the refused value is present at this
// witness". It is shared between the violation and the exemption on purpose:
// the two verdicts rest on exactly the same observation, and a reader comparing
// them must not have to reconcile two differently-shaped records.
func (i *i3) factsFor(r WriteRecord, v devView, cmd Command, obs *Observation) []Fact {
	return []Fact{
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
	}
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
