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
	"strings"
	"time"

	"lexa-proto/sunspec"
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
			cmd, ok := i.commandUnderTest(v.Unit, v.Source, r)
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
					r.Credential, r.Unit, r.Point, trimFloat(r.Value.Val), i.ghostSubject(obs, v))
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
				r.Credential, r.Unit, r.Point, trimFloat(r.Value.Val), i.ghostSubject(obs, v))
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
			if !i.lyingDeviceExplains(obs, r, v, f.Target) {
				continue
			}
		}
		return f, true
	}
	return Fault{}, false
}

// lyingDeviceExplains reports whether the device the lie is armed on can
// account for the value THIS witness is holding.
//
// ── Two questions, and the first fix only answered one ─────────────────────
//
// Gate #18 replaced a nominal scope check with a causal one: the lying device
// must itself hold the refused value. That is necessary and it is not
// sufficient, because it establishes only that SOME in-scope device holds the
// value — not that the device holding it is the one this projection is OF.
//
// On a multi-DER bench that gap is the whole defect back again. The campaign
// populates the write record's projection with EVERY device in the inventory
// (cmd/gw-campaign's derNames), so the nominal clause rejects nothing, and a
// lying der-a serving unit 7 would excuse a ghost on dut.unit1 — a value der-a
// cannot have put there. The run then reports OK and the ghost lands green,
// which is gate #18's end-state reached by another route.
//
// So the device must ALSO be the one the witness is a projection of, and the
// evidence for that is on both sides already: sources.go reads model 1 into
// UnitView.Identity for every unit it scans, on the DER's own channel and on
// the DUT's northbound alike. A DUT faithfully projecting a device projects its
// identity with it, so identity equality is the pairing — measured, not
// configured, and not inferred from a unit number the campaign never mapped.
//
// EITHER SIDE EMPTY DOES NOT FIRE. An unidentified device cannot be shown to be
// the one the projection is of, and this exemption does not fire on what it
// cannot show. Same direction as every other clause here: a false FAIL is
// adjudicated by a human, a false PASS is not.
func (i *i3) lyingDeviceExplains(obs *Observation, r WriteRecord, v devView, target string) bool {
	d, ok := obs.DERs[target]
	if !ok || !d.Reachable {
		return false
	}
	// The lying device must be the one this witness projects. Identity is the
	// only pairing either side actually measures — and it pairs only when it
	// picks out ONE device. Two devices sharing an identity (this bench's sims
	// can, by construction: see identityHolders) would let a lie on der-a
	// excuse a ghost der-b caused, which is exactly the false PASS every other
	// clause here is shaped to avoid.
	lyingID := strings.TrimSpace(d.Unit.Identity)
	witnessID := strings.TrimSpace(v.Unit.Identity)
	if lyingID == "" || witnessID == "" || lyingID != witnessID {
		return false
	}
	if identityHolders(obs, witnessID) != 1 {
		return false
	}
	cmd, ok := i.commandUnderTest(d.Unit, d.Source, r)
	if !ok || !cmd.Raw.Known() {
		return false
	}
	return i.sameValue(cmd.Raw, r.Value)
}

// commandUnderTest decodes the point a write RECORD targeted, from the model
// the record itself names.
//
// Both readings in this file used UnitView.Commands unconditionally, which
// decodes model 704 and only model 704 — so a refused write recorded against
// model 123 was judged against M704's WMaxLimPct, a different register on a
// different generation that happens to share a point name.
//
// It is latent today (only 704 records are constructed) and it stopped being
// safely latent the moment model 123 entered modelsOfInterest: the legacy
// scalar surface is now READ, so a legacy write record is one constructor away
// and would have been judged against a register the device may not even serve.
// A silent cross-model comparison is the shape this invariant exists to catch,
// arriving inside the invariant.
//
// A model this decoder has no reader for returns false — the honest answer, and
// the one that costs a skipped witness rather than a judgement against the
// wrong bank.
func (i *i3) commandUnderTest(uv UnitView, source string, r WriteRecord) (Command, bool) {
	switch r.Model {
	case 0, 704:
		// 0 is the historical default: every record this campaign builds names
		// 704 explicitly, and a record that names nothing is treated as the
		// generation it was written for rather than refused.
		return commandOf(uv.Commands(source), r.Point)
	case sunspec.ModelImmediateCtrl:
		return commandOf(uv.LegacyCommands(source).Commands, r.Point)
	}
	return Command{}, false
}

// ghostSubject is what a ghost finding is ABOUT: the physical register, not the
// channel it was read through.
//
// ── M9: one ghost at two witnesses ─────────────────────────────────────────
//
// A ghost is normally visible twice — in the DER's own register image, and in
// the DUT's projection of that DER — and keying on the witness LABEL made that
// two findings, two shrinks, two entries in the count. That is IW15-031's
// over-count at N = 2, and IW15-031's whole lesson is that an identity carrying
// something other than the finding's substance inflates the count.
//
// BUT FOLDING UNCONDITIONALLY WOULD BE WRONG, and this is why the answer is not
// simply "always one". The two witnesses can carry genuinely DIFFERENT findings:
// the DUT's projection may hold the refused value while the DER does not, which
// is durable state in the DUT ITSELF — a different defect, with a different
// owner, from a device that took a write it refused. Merging those would hide
// one behind the other, which is the same crime in the other direction and the
// one gate #19 caught in the shrinker's keyer.
//
// So the rule is neither: FOLD WHEN THE TWO WITNESSES ARE LOOKING AT THE SAME
// PHYSICAL REGISTER, and not otherwise. The relation that decides it is the one
// H3 already needed — a DUT projecting a device projects its model-1 identity
// with it, so identity equality is what makes "der.X" and "dut.unitN" two
// readings of one thing rather than two things.
//
// When the identity cannot be established the subject falls back to the witness
// label, which is the pre-M9 behaviour: an unidentified bench keeps its
// findings separate rather than folding everything into one key on the strength
// of a pairing nobody measured. Over-counting is a reporting defect; merging
// two real findings is a lost one.
//
// The witness set is NOT lost by folding — it goes where it belongs, in the
// facts (i3.observed.witness, one per witness, appended for every witness that
// saw it), so a reader of the finding sees both readings under one identity.
func (i *i3) ghostSubject(obs *Observation, v devView) string {
	if v.Witness == witnessDER {
		// A DER witness is already the device. Prefer its identity so it folds
		// with the DUT's projection of it — but only when that identity picks
		// out ONE device, for the reason uniqueIdentityHolder gives.
		id := strings.TrimSpace(v.Unit.Identity)
		if id != "" && identityHolders(obs, id) == 1 {
			return "device:" + id
		}
		return v.Label
	}
	// A DUT projection: fold onto the DER it is a projection OF, when that can
	// be established from what both sides measured AND the pairing is
	// unambiguous.
	witnessID := strings.TrimSpace(v.Unit.Identity)
	if witnessID == "" {
		return v.Label
	}
	switch identityHolders(obs, witnessID) {
	case 1:
		return "device:" + witnessID
	default:
		// Zero holders: identified, but no DER here carries that identity, so
		// this projection is not a second reading of any device present — the
		// pure projection ghost, its own finding.
		//
		// Two or more: the identity does not pick out a device at all, so
		// folding onto it would merge findings from DIFFERENT machines under
		// one key. Keep them separate.
		return v.Label
	}
}

// identityHolders counts the reachable DERs in an observation carrying an
// identity, and it is the guard both of this file's identity-keyed mechanisms
// consult before trusting one.
//
// ── Why a uniqueness check, when the identity is a serial number ───────────
//
// UnitView.Identity is "<Mn> <Md> sn=<SN>" read from model 1, and the whole
// argument for using it — that a DUT projecting a device projects its identity
// with it — quietly assumes the identity names ONE device. On real hardware it
// does. On this bench it does not have to: sim.go's static Populate hardcodes
// SN-0001 with no override at all, and the animated sims' own -serial help says
// in as many words that co-located sims collide unless an operator sets them
// apart. A harness whose fixtures can be identical by construction must not
// build inferences that assume they are not.
//
// Both mechanisms fail in the WORST direction when the assumption breaks, and
// they fail differently, which is why the guard is here rather than in one of
// them:
//
//	the FOLD (ghostSubject) merges two genuinely distinct ghosts, on two
//	different machines, into one key — one finding reported, one LOST. That is
//	IW15-031's crime committed through the very key that fixed it.
//
//	the EXEMPTION (lyingDeviceExplains) lets a lie armed on der-a excuse a
//	ghost that der-b caused independently: der-a holds the value, der-a's
//	identity "matches" the projection because der-b's is identical, and a real
//	FAIL becomes the lying-peer-confound WARN. That is gate #18's and #19's
//	end-state reached through the mechanism that closed them.
//
// So an identity held by more than one device is treated as NO pairing: the
// findings stay separate and the exemption does not fire. An identity that
// cannot uniquely pair cannot causally explain, and this file's whole family of
// clauses costs a false FAIL rather than a false PASS.
func identityHolders(obs *Observation, identity string) int {
	if strings.TrimSpace(identity) == "" {
		return 0
	}
	n := 0
	for _, name := range obs.DERNames() {
		d := obs.DERs[name]
		if !d.Reachable {
			continue
		}
		if strings.TrimSpace(d.Unit.Identity) == identity {
			n++
		}
	}
	return n
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
	facts := []Fact{
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
	// THE DEGRADED MODE DISCLOSES ITSELF. When the witness's identity is held
	// by more than one reachable device, both identity-keyed mechanisms decline
	// to act: findings that would have folded stay separate, and a lying-peer
	// exemption that would have fired does not. That is the SAFE direction, and
	// it is quieter than the alternative in a way a reader must not have to
	// infer — a bundle whose de-duplication silently switched off looks exactly
	// like a bundle that had nothing to de-duplicate.
	//
	// It rides in the facts rather than a startup log because a log scrolls
	// past and a fact is evidence. The bench's own sims can collide by
	// construction (sim.go's static Populate hardcodes SN-0001 with no
	// override), so this is a condition a real run can be in.
	if id := strings.TrimSpace(v.Unit.Identity); id != "" {
		if n := identityHolders(obs, id); n > 1 {
			facts = append(facts,
				F("i3.identity.ambiguous", "count", v.Source, "%d", n),
				F("i3.identity.value", "", v.Source, "%s", id),
				F("i3.identity.effect", "", "invariant", "%s",
					"this identity is held by more than one reachable device, so it pairs nothing: "+
						"findings at these witnesses are NOT folded onto one device and the lying-peer "+
						"exemption cannot fire for them. Both mechanisms are OFF for this witness, which "+
						"is safe and is narrower than a run with distinct identities would be"))
		}
	}
	return facts
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
