package suitecsip

// randomize.go — CORE-021's second half, which used to be a Skip resting on a
// statement about this bench that had stopped being true.
//
// ── The stale reason ────────────────────────────────────────────────────────
//
// The criterion "the DUT applied the randomization" carried this Skip:
//
//	"the DUT's activation instant is observable only through a status=2
//	 (Started) Response POST, and only for a control whose responseRequired
//	 asks for one. gridsim's admin control API does not expose
//	 responseRequired, so this bench cannot ask the DUT to announce its start
//	 instant and cannot measure the applied randomization from the wire"
//
// The first sentence is true. The second is FALSE and had been for as long as
// CORE-022 has been grading Response lifecycles: gridsim's admin control API
// sets responseRequired on every admin-created control by default
// (sim/gridsim/admin.go's adminDefaultResponseRequired = RespReqMessageReceived
// | RespReqSpecificResponse) and accepts a per-request override
// (adminCtrlReq.ResponseRequired). The bit that asks for the specific-outcome
// Response family — the one that produces status=2 — is ON, and CORE-021's own
// three controls have been carrying it all along.
//
// A Skip whose stated reason is false is worse than a Skip: it tells a reader
// the gap is in the BENCH's levers, so nobody looks for the measurement that
// was available the whole time. That is the adjacent-dishonesty class this
// sweep exists to close.
//
// ── What is genuinely NOT measurable, stated once and precisely ─────────────
//
// The Skip's replacement is not "measure the randomization", because the
// randomization's FULL magnitude is genuinely not recoverable from this
// observation and saying otherwise would be the same error pointing the other
// way. The reason that survives:
//
//	POLL QUANTISATION. The DUT posts its status=2 Response on its own cadence,
//	not at the instant it activates. gridsim advertises a 60 s DERControlList
//	pollRate, so the Response timestamp is an UPPER BOUND on the activation
//	instant with a quantum far larger than the +/-30 s randomization CORE-021
//	commands. A criterion that read the Response timestamp AS the activation
//	instant would be reporting the DUT's poll phase as if it were the DUT's
//	randomization.
//
// THE SIGN CONVENTION IS NOT a second such reason. A prior version of this
// file claimed "which side of the start time a negative value selects is a
// clause this repo has no on-machine copy of" and computed the bound from
// |randomizeStart| — the UNION of both readings. That claim was false: IEEE
// 2030.5-2018 §10.2.4.2.2 states it outright ("If the value is negative,
// randomization SHALL be applied before [the scheduled time] ... if
// positive ... delay"), and §10.2.3.2's own Earliest Effective Start Time
// definition ("minimum of Start Time or Start Time plus the Start
// Randomization") gives the identical rule as a formula: Start +
// min(0, randomizeStart). The convention is SIGNED and ONE-SIDED, not
// symmetric — and taking |randomizeStart| let a control with a POSITIVE
// randomizeStart (delay-only, by the clause above) admit an early start the
// standard forbids outright. See #16.
//
// ── What IS measurable, and rigorously ─────────────────────────────────────
//
// Poll quantisation is ONE-SIDED. A Response observed late may mean the DUT
// activated earlier and only got round to saying so; it can never mean the DUT
// activated LATER than it said. So the EARLIEST-PERMITTED bound is safe from
// quantisation in the direction that matters:
//
//	an activation announced BEFORE the earliest instant the event's own
//	randomization permits — Start + min(0, randomizeStart), per §10.2.4.2.2
//	and §10.2.3.2 — is a violation under any poll cadence.
//
// For CORE-021's randomizeStart=0 control that bound is the interval start
// itself. For a POSITIVE randomizeStart it is ALSO the interval start: the
// clause grants delay only, never an early edge, so the bound does not widen
// just because the field is nonzero. Only a NEGATIVE randomizeStart moves the
// bound earlier, and by exactly its own magnitude.
//
// That is a decided PASS/FAIL over a real wire observation, and the half it
// cannot reach — "was the randomization actually APPLIED, and how much" — is
// named on every verdict rather than left to a Skip.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// randomizeGuardBand is the slack the earliest-permitted comparison allows
// before it calls a Response early.
//
// It absorbs the two measurement uncertainties that could otherwise
// manufacture a FALSE FAIL, and nothing wider. The first is the server-clock
// reconciliation below, which places the control's interval start (a server
// epoch) on the capture clock through a skew measured from ONE Time exchange —
// good to well under a second on a bench where both clocks are the desktop's,
// and worth a margin on one where they are not. The second is capture
// timestamping itself.
//
// It is deliberately NOT sized to absorb a randomization: two seconds against
// a +/-30 s window leaves the assertion able to see a violation of any
// magnitude a procedure cares about.
const randomizeGuardBand = 2 * time.Second

// serverClockSkew recovers how far the CAPTURE clock runs ahead of the SERVER's
// own clock, from the Time resource the DUT fetched.
//
// It is the same computation CORE-005's own criterion makes
// (e.Resp.Time.Sub(time.Unix(currentTime, 0))) and it is factored here rather
// than copied, so a criterion that places a server epoch on the capture clock
// and a criterion that REPORTS the skew cannot drift apart about what the
// number means.
//
// ok=false is "no Time exchange with both halves was recovered", which is a
// fact about the capture and not about the DUT.
func serverClockSkew(t *Transcript) (time.Duration, bool) {
	e, doc, found := t.Resource("Time")
	if !found {
		return 0, false
	}
	ct, has := doc.IntOf("currentTime")
	if !has || e.Resp == nil || e.Resp.Time.IsZero() {
		return 0, false
	}
	return e.Resp.Time.Sub(time.Unix(ct, 0)), true
}

// randomizedControl is one control this criterion grades, as the WIRE
// described it — never as the row's Setup intended it. A row that graded its
// own intent would not notice a bench that published something else.
type randomizedControl struct {
	MRID string
	// Start is interval/start, in the SERVER's epoch.
	Start int64
	// Randomize is the control's own randomizeStart, and Has says whether the
	// element was present at all. A control that carries none permits no
	// randomization, which is the same bound as an explicit zero and a
	// different fact about the document.
	Randomize int64
	Has       bool
}

// randomizedControlsFrom recovers every DERControl the DUT fetched whose mRID
// carries the given stem, deduplicated on mRID (a control appears once per
// DERControlList fetch and the DUT fetches the list every poll cycle).
func randomizedControlsFrom(t *Transcript, mridPrefix string) []randomizedControl {
	seen := map[string]randomizedControl{}
	for _, e := range t.ByResource("DERControlList") {
		if e.Resp == nil {
			continue
		}
		doc, err := e.Resp.SEP()
		if err != nil {
			continue
		}
		for _, c := range doc.Children("DERControl") {
			m, _ := c.TextOf("mRID")
			if !strings.HasPrefix(m, mridPrefix) {
				continue
			}
			rc := randomizedControl{MRID: m}
			if iv := c.Path("interval"); iv != nil {
				rc.Start, _ = iv.IntOf("start")
			}
			rc.Randomize, rc.Has = c.IntOf("randomizeStart")
			seen[m] = rc
		}
	}
	out := make([]randomizedControl, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MRID < out[j].MRID })
	return out
}

// earliestPermitted is the earliest instant, on the SERVER's clock, at which
// this control's own randomization permits it to start.
//
// IEEE 2030.5-2018 §10.2.4.2.2: "If the value is negative, randomization
// SHALL be applied before [the scheduled time] ... if positive ... delay" —
// SIGNED and ONE-SIDED, not a symmetric ± band. §10.2.3.2's own Earliest
// Effective Start Time definition ("minimum of Start Time or Start Time plus
// the Start Randomization") gives the same rule as a formula: Start +
// min(0, randomizeStart). A POSITIVE randomizeStart can only push the start
// LATER; it grants no permission to start early, and this bound must not
// manufacture one. A NEGATIVE randomizeStart is the only case that moves the
// earliest edge before Start, and by exactly its own magnitude.
func (rc randomizedControl) earliestPermitted() int64 {
	if !rc.Has {
		return rc.Start
	}
	w := rc.Randomize
	if w > 0 {
		w = 0
	}
	return rc.Start + w
}

// startedAt finds the capture timestamp of the status=2 (Started) Response the
// DUT POSTed for this control, if the transcript holds one.
func startedAt(t *Transcript, mrid string) (time.Time, bool) {
	for _, e := range t.Method("POST") {
		if e.Req == nil || len(e.Req.Body) == 0 || e.Req.Time.IsZero() {
			continue
		}
		doc, err := e.Req.SEP()
		if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
			continue
		}
		if subj, _ := doc.TextOf("subject"); subj != mrid {
			continue
		}
		if st, _ := doc.UintOf("status"); st != 2 {
			continue
		}
		return e.Req.Time, true
	}
	return time.Time{}, false
}

// critRandomizationNotEarlierThanPermitted grades CORE-021's second claim.
//
// It replaces a Skip whose stated reason was false (see the file doc) with the
// strongest assertion the observation actually supports, and it names the half
// it cannot reach on every verdict — a PASS here means "nothing started before
// it was allowed to", never "the randomization was applied as commanded".
func critRandomizationNotEarlierThanPermitted(mridPrefix string) criterion {
	return criterion{
		Claim: "no randomized event was announced STARTED before the earliest instant its own " +
			"randomizeStart permits — Start + min(0, randomizeStart) per §10.2.4.2.2/§10.2.3.2, the " +
			"signed, one-sided bound a status=2 Response can establish",
		How: "the capture timestamp of the DUT's status=2 (Started) Response for each control, compared " +
			"against that control's own interval/start and randomizeStart AS THE DUT FETCHED THEM, with " +
			"the server's epoch placed on the capture clock through the skew measured from the Time " +
			"resource (the same computation CORE-005 reports). The bound is EARLIEST-only, because the " +
			"DUT announces its start on its own poll cadence and that quantisation can only make a " +
			"Response late, never early; and it takes the SIGNED randomizeStart per §10.2.4.2.2 ('if " +
			"negative, applied before ... if positive, delay') rather than its magnitude, so a positive " +
			"randomizeStart is never read as permitting an early start",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			controls := randomizedControlsFrom(t, mridPrefix)
			if len(controls) == 0 {
				return unavailable("no DERControl carrying this row's mRID stem %q appears in the "+
					"recovered transcript, so there is no scheduled event to grade a start instant against",
					mridPrefix)
			}
			skew, haveSkew := serverClockSkew(t)
			if !haveSkew {
				return unavailable("the recovered transcript holds no Time exchange with both a " +
					"currentTime and a capture timestamp, so this row cannot place the server's own " +
					"interval start on the capture clock; the comparison would otherwise be between two " +
					"clocks whose offset is unknown")
			}

			var (
				early    []string
				measured []string
				silent   []string
			)
			for _, rc := range controls {
				at, ok := startedAt(t, rc.MRID)
				if !ok {
					silent = append(silent, rc.MRID)
					continue
				}
				permitted := time.Unix(rc.earliestPermitted(), 0).Add(skew)
				delta := at.Sub(permitted)
				measured = append(measured, fmt.Sprintf("%s (randomizeStart %s, interval start %s): "+
					"Started announced %s after its earliest permitted instant",
					rc.MRID, randomizeLabel(rc), time.Unix(rc.Start, 0).UTC().Format(time.RFC3339),
					delta.Round(time.Millisecond)))
				if delta < -randomizeGuardBand {
					early = append(early, fmt.Sprintf("%s started %s EARLY (randomizeStart %s permits no "+
						"instant before %s on the capture clock; the Response was captured at %s)",
						rc.MRID, (-delta).Round(time.Millisecond), randomizeLabel(rc),
						permitted.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339)))
				}
			}

			const cannotSay = " This criterion establishes the EARLIEST bound only: whether the DUT " +
				"applied a randomization, and of what magnitude, is not recoverable from a Response the " +
				"DUT posts on its own poll cadence (gridsim advertises a 60 s DERControlList pollRate " +
				"against a +/-30 s randomization), so no verdict here should be read as covering it."

			if len(early) > 0 {
				return found(certify.Fail, allFrames(t.Method("POST")),
					"%d of %d randomized control(s) were announced started before their own randomization "+
						"permitted: %s. Poll quantisation cannot produce this — it can only make a Response "+
						"LATE — so the earliness is the DUT's.%s",
					len(early), len(controls), strings.Join(early, "; "), cannotSay)
			}
			if len(measured) == 0 {
				return unavailable("the DUT posted no status=2 (Started) Response for any of the %d "+
					"randomized control(s) in this window (%s), so no activation instant was announced at "+
					"all. gridsim's admin controls carry responseRequired's specific-response bit by "+
					"default (adminDefaultResponseRequired), so the request WAS made; whether the DUT "+
					"simply had not reached the events' start times inside this capture window is not "+
					"decidable from what was recovered",
					len(controls), strings.Join(controlIDs(controls), ", "))
			}
			obs := fmt.Sprintf("%d of %d randomized control(s) announced a start instant, and none of them "+
				"was earlier than its own randomizeStart permits: %s",
				len(measured), len(controls), strings.Join(measured, "; "))
			if len(silent) > 0 {
				obs += fmt.Sprintf(". %d control(s) announced no start in this window (%s), so nothing is "+
					"claimed about them", len(silent), strings.Join(silent, ", "))
			}
			obs += "."
			// Cite the Response the verdict rests on, not the whole POST
			// stream. citeMessage answers Unavailable for a nil message, which
			// would silently convert this PASS into a Skip — so the frames
			// fallback is explicit rather than left to that path.
			if m := firstStartedResponse(t, controls); m != nil {
				return citeMessage(t, m, certify.Pass, "%s%s", obs, cannotSay)
			}
			return found(certify.Pass, allFrames(t.Method("POST")), "%s%s", obs, cannotSay)
		},
	}
}

// randomizeLabel renders a control's randomizeStart as the wire carried it,
// including the case where the element was absent — which permits no
// randomization and is a different document from an explicit zero.
func randomizeLabel(rc randomizedControl) string {
	if !rc.Has {
		return "absent (no randomization permitted)"
	}
	return fmt.Sprintf("%+d s", rc.Randomize)
}

func controlIDs(cs []randomizedControl) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.MRID)
	}
	return out
}

// firstStartedResponse returns a message to cite for the PASS: the first
// status=2 Response among the graded controls, so the citation points at the
// evidence the verdict rests on rather than at the whole POST stream.
func firstStartedResponse(t *Transcript, cs []randomizedControl) *Message {
	best := (*Message)(nil)
	for _, e := range t.Method("POST") {
		if e.Req == nil || len(e.Req.Body) == 0 {
			continue
		}
		doc, err := e.Req.SEP()
		if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
			continue
		}
		subj, _ := doc.TextOf("subject")
		if st, _ := doc.UintOf("status"); st != 2 {
			continue
		}
		for _, c := range cs {
			if c.MRID != subj {
				continue
			}
			if best == nil || (!e.Req.Time.IsZero() && e.Req.Time.Before(best.Time)) {
				best = e.Req
			}
		}
	}
	return best
}
