package suitecsip

// localext_eventstatus.go — EXT-002/EXT-003/EXT-004, the LOCAL EXTENSION
// rows REV0907-B1/B2 require: no published CSIP-CONF-v1.3 procedure
// exercises a RESERVED currentStatus value (EXT-002), Cancelled-with-
// Randomization, currentStatus=3 (EXT-003), or an event already past its own
// Specified End Time at first sighting (EXT-004) at all — CORE-022 only ever
// drove plain Cancelled(2) — so neither the defects (this bench treating 6
// as Cancelled; lexa-gw's Pass 1 adopting an already-expired event) nor
// their positive companions had a row to be caught by. See localext.go's doc
// for what a LOCAL EXTENSION row is and is not.
//
// EXT-002/EXT-003 share gridsim's admin-driven "server-cancel" idiom
// CORE-022 uses (sim/gridsim/admin.go's adminCtrlReq doc): publish a
// control, wait for it to be Started, then a status-only update on the SAME
// mRID. EXT-004 is a single-post row instead — its whole claim is about
// FIRST SIGHTING, so there is no "already Started" step to wait through, and
// no second POST. Program 2 is used for all three — CORE-022/CORE-023 and
// the aggregator rows already occupy programs 0/1 with their own axis-
// independence bookkeeping, and these rows have no supersession concern of
// their own to protect.

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	csipmodel "lexa-proto/csipmodel"
)

// ext002ControlDurationS is EXT-002's control's own event interval —
// deliberately long relative to the wait this row gives the DUT to react to
// the reserved-currentStatus flip, so the control is still genuinely LIVE
// (would go on executing on its own) when the flip lands: a DUT that
// withdrew would be withdrawing FROM something, not merely noticing an event
// that had already elapsed.
const ext002ControlDurationS = 300

// reservedCurrentStatus002 implements EXT-002 — REV0907-B1's negative check.
func reservedCurrentStatus002(nonce string) certify.Check {
	s := reservedCurrentStatusSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// reservedCurrentStatusSpec builds EXT-002's spec, factored out of
// reservedCurrentStatus002 so a test can drive Setup/Change directly against
// a fake gridsim without booting the whole certify.Check machinery — the same
// split coreResponsesSpec uses for CORE-022.
func reservedCurrentStatusSpec(nonce string) spec {
	mrid := withRunNonce("CERT-EXT002-RESERVED", nonce)
	reserved := uint8(6) // REV0907-B1: Table 27's Response status for "event
	// cancelled" — NOT a currentStatus value; IEEE Std 2030.5-2018 Annex B,
	// p.159-160 reserves it. The raw CurrentStatus override is used here
	// DELIBERATELY: this is the negative test that override exists for.
	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			id, err := d.PostControl(ctx, ControlRequest{
				Program: 2, MRID: mrid, Description: "EXT-002 reserved-currentStatus control",
				StartOffset: 0, DurationS: ext002ControlDurationS, GenLimW: ptr(int64(2000)), Activate: true,
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		Want: func(base ServerView) func(ServerView) bool {
			return base.WantResponseAtLeast(mrid, 2)
		},
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The negative stimulus: a status-only update (IEEE Std
			// 2030.5-2018 §10.2.3.3 c), same idiom as CORE-022's Change)
			// flipping the SAME mRID's currentStatus to a RESERVED value.
			_, err := d.PostControl(ctx, ControlRequest{
				Program: 2, MRID: mrid,
				CurrentStatus: &reserved,
			})
			return err
		},
		ChangeWait: changeWaitFullCycle,
		Cleanup: func(ctx context.Context, d *Driver) {
			_ = d.releaseProgramControls(ctx, 2)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published a DERControl (%s) and waited %s for it to be Started, then served a "+
				"RESERVED currentStatus (6 — IEEE Std 2030.5-2018 Annex B p.159-160 reserves it) on the SAME "+
				"mRID; statuses received: %v", mrid, o.Waited.Round(rounding), o.Server.ResponseStatuses(mrid))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResponseStarted(mrid),
				{
					Claim: "the DUT does not treat a RESERVED currentStatus value (6) as Cancelled: it does " +
						"not POST a Response with status=6 (Table 27 \"event cancelled\") for this control",
					How: "the set of Response statuses gridsim recorded for this control's mRID, gated " +
						"against this control's own responseRequired (#17/F2), checked for the ABSENCE of " +
						"status=6",
					Server: func(v *ServerView) Finding {
						wantCancel := respReqFilterStatuses(o.Transcript, mrid, []int{6})
						got := v.ResponseStatuses(mrid)
						for _, st := range got {
							if st == 6 {
								return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
									"statuses %v include 6 (cancelled) for a control the server only ever "+
										"advertised a RESERVED currentStatus (6) on — REV0907-B1: the DUT "+
										"treated a value IEEE Std 2030.5-2018 Annex B reserves as if it meant "+
										"Cancelled, exactly the defect this row exists to catch", got)}
							}
						}
						if len(wantCancel) == 0 {
							return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
								"statuses %v; the control's own responseRequired did not ask for status=6 "+
									"either way, and none was sent", got)}
						}
						return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
							"statuses %v; no status=6 was sent for the reserved-currentStatus value", got)}
					},
				},
			}
		},
	}
}

// ext003ControlDurationS is EXT-003's control's own event interval.
const ext003ControlDurationS = 600

// ext003RandomizeDurationS is the control's own randomizeDuration —
// deliberately larger than gridsim's default DERControlList pollRate (60s,
// server.go's defaultControlListPollRate) so a withdrawal inside one poll
// cycle of the currentStatus=3 flip is observably distinguishable from a
// timely one. randomizeStart is 0, so IEEE Std 2030.5-2018 Annex B's
// max(|randomizeStart|,|randomizeDuration|) end randomization equals this
// value exactly (csipmodel.EventStatus.EndRandomizationS).
const ext003RandomizeDurationS = int32(150)

// ext003ChangeAtParam is the Observation.Params key EXT-003's Change records
// its own wall-clock time under. The currentStatus=3 flip is a gridsim ADMIN
// POST — a separate, plaintext conversation the DUT-facing pcap this row's
// Criteria reads never captures — so the floor Criteria checks against has
// no wire timestamp of its own to recover; Params carries it instead, the
// same mechanism every other spec here uses to hand a live-phase fact to the
// citation phase.
const ext003ChangeAtParam = "ext003ChangeAt"

// cancelWithRandomization003 implements EXT-003 — the positive companion to
// EXT-002, covering currentStatus=3 (Cancelled with Randomization), which no
// CSIP-CONF-v1.3 procedure and no prior row in this bench ever drove.
func cancelWithRandomization003(nonce string) certify.Check {
	s := cancelWithRandomizationSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// cancelWithRandomizationSpec builds EXT-003's spec, factored out for the
// same reason reservedCurrentStatusSpec is.
func cancelWithRandomizationSpec(nonce string) spec {
	mrid := withRunNonce("CERT-EXT003-RANDCANCEL", nonce)
	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			id, err := d.PostControl(ctx, ControlRequest{
				Program: 2, MRID: mrid, Description: "EXT-003 cancel-with-randomization control",
				StartOffset: 0, DurationS: ext003ControlDurationS, GenLimW: ptr(int64(2000)), Activate: true,
				RandomizeStart: ptr(int32(0)), RandomizeDuration: ptr(ext003RandomizeDurationS),
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		Want: func(base ServerView) func(ServerView) bool {
			return base.WantResponseAtLeast(mrid, 2)
		},
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			params[ext003ChangeAtParam] = time.Now().UTC().Format(time.RFC3339Nano)
			_, err := d.PostControl(ctx, ControlRequest{
				Program: 2, MRID: mrid,
				CancelWithRandomization: true,
			})
			return err
		},
		ChangeWait: changeWaitFullCycle,
		Cleanup: func(ctx context.Context, d *Driver) {
			_ = d.releaseProgramControls(ctx, 2)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published a DERControl (%s) carrying randomizeStart=0/randomizeDuration=%ds "+
				"and waited %s for it to be Started, then served currentStatus=3 (Cancelled with "+
				"Randomization) on the SAME mRID; statuses received: %v",
				mrid, ext003RandomizeDurationS, o.Waited.Round(rounding), o.Server.ResponseStatuses(mrid))
		},
		Criteria: func(o *Observation) []criterion {
			floor := time.Duration((csipmodel.EventStatus{CurrentStatus: csipmodel.EventStatusCancelledWithRandomization}).
				EndRandomizationS(0, ext003RandomizeDurationS)) * time.Second
			return []criterion{
				critResponseStarted(mrid),
				{
					Claim: fmt.Sprintf("the DUT does not withdraw (POST a Response status=6, Table 27 \"event "+
						"cancelled\") for this control before its own end randomization (%s, IEEE Std "+
						"2030.5-2018 Annex B p.159-160) has elapsed since the server served currentStatus=3, "+
						"and eventually does withdraw", floor),
					How: "every Response-family POST in the recovered session whose <subject> is this row's " +
						"own mRID and <status> is 6, each one's own wire timestamp compared against the " +
						"server-recorded currentStatus=3 flip time plus the floor",
					// A Wire evaluator, not Server: the comparison reads the
					// DECRYPTED WIRE TRANSCRIPT (each Response POST's own
					// capture timestamp), not gridsim's admin log — citing it
					// as tierServer ("gridsim admin API... not the wire")
					// would misattribute the evidence. Only changedAt itself
					// (when the admin-port flip was served) comes from
					// Params; the deadline it feeds is checked against wire
					// frames, matching critNoEarlyEndOfEventStatus's own
					// Wire-tier shape for the analogous start-side check.
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						changedAtRaw := o.Params[ext003ChangeAtParam]
						if changedAtRaw == "" {
							return unavailable("this row's Change never recorded %s in Params — the check "+
								"could not confirm when the currentStatus=3 flip was served, so no floor can "+
								"be checked against", ext003ChangeAtParam)
						}
						changedAt, err := time.Parse(time.RFC3339Nano, changedAtRaw)
						if err != nil {
							return unavailable("Params[%s]=%q did not parse as RFC3339: %v",
								ext003ChangeAtParam, changedAtRaw, err)
						}
						deadline := changedAt.Add(floor)
						var early, onTime []string
						for _, e := range t.Method("POST") {
							if e.Req == nil || len(e.Req.Body) == 0 {
								continue
							}
							doc, err := e.Req.SEP()
							if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
								continue
							}
							subj, _ := doc.TextOf("subject")
							if subj != mrid {
								continue
							}
							st, _ := doc.UintOf("status")
							if st != 6 {
								continue
							}
							if e.Req.Time.Before(deadline) {
								early = append(early, fmt.Sprintf("status=6 at %s, %s before the floor %s",
									e.Req.Time.Format(time.RFC3339), deadline.Sub(e.Req.Time).Round(time.Second),
									deadline.Format(time.RFC3339)))
							} else {
								onTime = append(onTime, fmt.Sprintf("status=6 at %s, at or after the floor %s",
									e.Req.Time.Format(time.RFC3339), deadline.Format(time.RFC3339)))
							}
						}
						if len(early) > 0 {
							return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
								"the DUT withdrew before its own end randomization elapsed: %s — IEEE Std "+
									"2030.5-2018 Annex B p.159-160 requires waiting max(|randomizeStart|, "+
									"|randomizeDuration|) = %s before acting on currentStatus=3",
								strings.Join(early, "; "), floor)}
						}
						if len(onTime) > 0 {
							return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
								"the DUT withdrew at or after its own end randomization: %s", strings.Join(onTime, "; "))}
						}
						return unavailable("no status=6 Response for subject %s was recovered in this "+
							"window (floor %s after the flip); the wait may not have been long enough for "+
							"the DUT's own poll cadence plus the end randomization", mrid, floor)
					},
				},
			}
		},
	}
}

// ── EXT-004: expired-at-receipt (REV0907-B2) ────────────────────────────────

// ext004WindowDurationS is EXT-004's own control's window — deliberately
// short, because the row's whole point is that the window's END has already
// passed at post time, not that it is currently running.
const ext004WindowDurationS = 60

// ext004ElapsedMarginS is how far BEFORE the window's own start this row
// posts it (StartOffset = -(ext004WindowDurationS + ext004ElapsedMarginS)),
// so the Specified End Time (IEEE Std 2030.5-2018 §10.2.3.3 l) —
// Interval.Start+Interval.Duration) is comfortably in gridsim's own past at
// post time. Any positive margin is sufficient and stays sufficient forever
// — once an interval is in the past, time only moves forward, it never
// becomes current again — so this is chosen generous for readability, not
// as a minimal bound.
const ext004ElapsedMarginS = 600

// ext004CeilingCandidatesHundredths are the two opModMaxLimW Test Values (in
// PerCent's own hundredths-of-a-percent wire unit, IW13-001) EXT-004's
// expired control may command. Two exist so Setup can fall back to the
// second whenever the first happens to equal the DER's own pre-publication
// ceiling reading — the same "distinguishable baseline" discipline
// critConnectStartedIntegrity (directoracle.go) and BASIC-007's ramp oracle
// already apply elsewhere in this suite: a commanded value indistinguishable
// from what the DER already held would let a DUT that DID actuate the
// expired control read, by this check alone, as one that correctly ignored
// it.
var ext004CeilingCandidatesHundredths = []int64{1234, 8765} // 12.34%, 87.65%

// ext004CeilingBaselineToleranceP is how close (in percentage points) the
// candidate must be to the DER's own pre-publication ceiling reading before
// Setup treats it as INDISTINGUISHABLE and falls back to the other
// candidate. Half a point is comfortably larger than any register
// quantisation step at this scale (see fixedPFTolerance's own doc for the
// same margin-over-quantisation reasoning applied to a different axis).
const ext004CeilingBaselineToleranceP = 0.5

// The Observation.Params keys EXT-004's Setup/PostWait stash the live-phase
// ceiling reads and chosen commanded value under, for the citation phase
// (ext004CeilingStabilityCriterion) to read back — the same
// live-phase-writes/citation-phase-reads split criteria.go's Tier doc
// describes for critDEREffectViaSouthboundOracle.
const (
	ext004CeilingPreParam  = "ext004.ceiling_pre"
	ext004CeilingPostParam = "ext004.ceiling_post"
	ext004WantParam        = "ext004.ceiling_want_hundredths"
)

// ceilingSnapshot is EXT-004's own minimal, self-contained read of whichever
// active-power ceiling register home the DER under test actually serves. It
// reuses basic.go's ceilingHomeOf — the SAME generation resolution
// BASIC-010's oracle uses — but stops at the raw register: EXT-004 asks only
// "did this move between two reads", never "does it now hold X percent of
// nameplate", so none of ceilingHomeOf's callers' nameplate/tolerance/ladder
// machinery is needed. That is what keeps this a CHEAP read: one
// oracleUnitView call plus one loop over an already-decoded command list.
type ceilingSnapshot struct {
	// Available is false when the axis could not be read at all (no 704/123,
	// no nameplate to resolve it against, or the sim was unreachable) — Note
	// says why. A ceiling read is not this row's LOAD-BEARING claim (the
	// Response-status criterion is), so an unavailable snapshot degrades this
	// ONE supporting criterion to Unavailable rather than failing the row.
	Available bool
	Point     string
	Enabled   bool
	Raw       float64 // percent (WMaxLimPct's own unit), meaningful only when Available
	Note      string
}

// encode/decode round-trip a ceilingSnapshot through Observation.Params,
// which carries only strings — the same constraint ext003ChangeAtParam's own
// doc describes, met here with a small pipe-delimited encoding rather than a
// timestamp because a snapshot carries more than one field.
func (c ceilingSnapshot) encode() string {
	if !c.Available {
		return "unavailable|" + c.Note
	}
	return fmt.Sprintf("available|%s|%t|%s", c.Point, c.Enabled, trimNum(c.Raw))
}

func decodeCeilingSnapshot(s string) ceilingSnapshot {
	parts := strings.SplitN(s, "|", 4)
	if len(parts) == 0 || parts[0] != "available" {
		note := "no ceiling snapshot was recorded"
		if len(parts) > 1 {
			note = parts[1]
		}
		return ceilingSnapshot{Note: note}
	}
	if len(parts) != 4 {
		return ceilingSnapshot{Note: "malformed ceiling snapshot encoding: " + s}
	}
	enabled, _ := strconv.ParseBool(parts[2])
	raw, _ := strconv.ParseFloat(parts[3], 64)
	return ceilingSnapshot{Available: true, Point: parts[1], Enabled: enabled, Raw: raw}
}

// readCeilingSnapshot takes one live read of the DER's own active-power
// ceiling register, through the SAME internal/invariant path
// oracleUnitView's own doc describes (the production simapi sidecar source,
// never a shortcut invented for this row).
func readCeilingSnapshot(ctx context.Context, rc *certify.RunCtx) ceilingSnapshot {
	uv, err := oracleUnitView(ctx, rc, oracleSimName)
	if err != nil {
		return ceilingSnapshot{Note: fmt.Sprintf("could not read the DER's own registers: %v", err)}
	}
	home, why := ceilingHomeOf(uv)
	if why != "" {
		return ceilingSnapshot{Note: why}
	}
	for _, c := range home.Cmds {
		if c.Point == home.Point {
			return ceilingSnapshot{Available: true, Point: home.Point, Enabled: c.Enabled, Raw: c.Raw.Val}
		}
	}
	return ceilingSnapshot{Note: fmt.Sprintf("the DER's own image carries no %s command at all", home.Point)}
}

// expiredAtReceipt004 implements EXT-004 — REV0907-B2's positive check that
// the product fix (lexa-gw a943a56, internal/northbound/responses/tracker.go
// Pass 1) exists to close: an event whose Specified End Time has already
// passed AT FIRST SIGHTING must be ignored — status=254 (ResponseRejected
// Expired) and NEVER status=1/2/3 — regardless of what currentStatus the
// server advertises. gridsim's own "expired" lever (REV0907-B2,
// sim/gridsim/admin.go) forces the served currentStatus to 0 (Scheduled),
// which is precisely the combination the harness previously had no way to
// construct at all: before this lever every already-past-start control
// gridsim served defaulted to currentStatus=1 (Active) at post time.
func expiredAtReceipt004(nonce string) certify.Check {
	s := expiredAtReceiptSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// expiredAtReceiptSpec builds EXT-004's spec, factored out for the same
// reason reservedCurrentStatusSpec/cancelWithRandomizationSpec are.
func expiredAtReceiptSpec(nonce string) spec {
	mrid := withRunNonce("CERT-EXT004-EXPIRED", nonce)
	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			pre := readCeilingSnapshot(ctx, d.rc)
			params[ext004CeilingPreParam] = pre.encode()

			want := ext004CeilingCandidatesHundredths[0]
			if pre.Available && math.Abs(pre.Raw-float64(want)/100) < ext004CeilingBaselineToleranceP {
				want = ext004CeilingCandidatesHundredths[1]
			}
			params[ext004WantParam] = strconv.FormatInt(want, 10)

			id, err := d.PostControl(ctx, ControlRequest{
				Program: 2, MRID: mrid, Description: "EXT-004 expired-at-receipt control",
				// The window opened ext004ElapsedMarginS+ext004WindowDurationS
				// seconds ago and lasted only ext004WindowDurationS seconds — its
				// Specified End Time is ext004ElapsedMarginS seconds in gridsim's
				// own past, well before this DUT (which has never seen this mRID
				// before) can possibly first discover it.
				StartOffset: -(ext004WindowDurationS + ext004ElapsedMarginS), DurationS: ext004WindowDurationS,
				MaxLimW: ptr(want), Activate: true,
				// Expired (REV0907-B2, sim/gridsim/admin.go): forces
				// currentStatus=0 (Scheduled) despite the interval above already
				// having elapsed — the server keeps saying "merely scheduled"
				// while its own window is already in the past, exactly the
				// combination §10.2.3.3 l) requires a client to reject on the
				// INTERVAL alone, independent of currentStatus.
				Expired: true,
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		// A control whose interval has already elapsed is never Started — the
		// only Response this row's own claim expects is 254, so the wait is for
		// AT LEAST that, exactly WantResponseAtLeast's own shape.
		Want: func(base ServerView) func(ServerView) bool {
			return base.WantResponseAtLeast(mrid, 254)
		},
		// The post-wait ceiling read — see ceilingSnapshot's doc. Independent
		// of whether the Want predicate above was satisfied: a DUT that
		// silently ignored the control forever (never posting anything) still
		// gets its ceiling axis checked for having moved.
		PostWait: func(ctx context.Context, d *Driver, params map[string]string) error {
			params[ext004CeilingPostParam] = readCeilingSnapshot(ctx, d.rc).encode()
			return nil
		},
		Cleanup: func(ctx context.Context, d *Driver) {
			_ = d.releaseProgramControls(ctx, 2)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published a DERControl (%s) whose own interval (IEEE Std 2030.5-2018 "+
				"§10.2.3.3 l)'s Specified End Time — Interval.Start+Interval.Duration) had ALREADY ELAPSED at "+
				"post time, served with currentStatus=0 (Scheduled — Annex B, p.159-160) throughout, never "+
				"Active or Cancelled; statuses received: %v", mrid, o.Server.ResponseStatuses(mrid))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				ext004ResponseCriterion(mrid),
				ext004CeilingStabilityCriterion(o),
			}
		},
	}
}

// ext004ResponseCriterion is EXT-004's own claim, graded against gridsim's
// own record of every Response POST for this control's mRID.
//
// REFEREE INDEPENDENCE (CLAUDE.md "Referee independence" /
// docs/ADVERSARIAL_QA_STRATEGY.md §5 rule PN-1/C9/AD-003(f)): 254 is
// HARD-CODED below, not read off csipmodel.ResponseRejectedExpired — the
// oracle for what the DUT owes here is the standard's own text (IEEE Std
// 2030.5-2018 §10.2.3.3 l): "If an Event is received after it has expired
// (Specified End Time has passed), this Event SHALL be ignored"; Table 27
// assigns 254 to "rejected — event already expired at receipt") — never a
// constant the product under test also consumes. Same discipline
// reservedCurrentStatus002 already applies to its own literal 6.
func ext004ResponseCriterion(mridKey string) criterion {
	const wantStatus = 254      // Table 27 "rejected — event already expired at receipt" (2018 Table 27, p.159-160)
	forbidden := []int{1, 2, 3} // Received / Started / Completed — "ignored" permits none of them
	return criterion{
		Claim: fmt.Sprintf("the DUT POSTed exactly one DERControlResponse with status=%d (rejected — event "+
			"already expired at receipt, IEEE Std 2030.5-2018 Table 27) for the expired control, and NEVER "+
			"POSTed status=1 (Received), 2 (Started) or 3 (Completed) for it — §10.2.3.3 l): an Event received "+
			"after its own Specified End Time has passed SHALL be ignored", wantStatus),
		How: "gridsim's own record of every DERControlResponse POST for this control's mRID (GET " +
			"/admin/responses) — the definitive record of what reached the server, not subject to a capture " +
			"window the way a wire-tier read would be",
		Server: func(v *ServerView) Finding {
			got := v.ResponseStatuses(mridKey)
			if len(got) == 0 && !v.SessionEstablished() {
				return noSessionUnavailable()
			}
			var forbiddenSeen []int
			count254 := 0
			for _, st := range got {
				switch {
				case st == wantStatus:
					count254++
				case containsInt(forbidden, st):
					forbiddenSeen = append(forbiddenSeen, st)
				}
			}
			if len(forbiddenSeen) > 0 {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"statuses %v include %v — the DUT reported the lifecycle of an event already past its own "+
						"Specified End Time instead of ignoring it (REV0907-B2, IEEE Std 2030.5-2018 "+
						"§10.2.3.3 l))", got, forbiddenSeen)}
			}
			if count254 != 1 {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"statuses %v carry %d status=%d Response(s) for this control, want exactly 1 — a DUT that "+
						"correctly ignores an already-expired event still owes ONE rejection (never zero, "+
						"never a repeat)", got, count254, wantStatus)}
			}
			return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
				"statuses %v — exactly one status=%d and none of %v", got, wantStatus, forbidden)}
		},
	}
}

// ext004CeilingFinding compares two ceiling reads and grades whether the
// axis moved. Factored out of ext004CeilingStabilityCriterion so a test can
// drive it directly against synthetic snapshots without a live bench — the
// same split the rest of this suite uses between "build the criterion" and
// "grade this pair of facts".
func ext004CeilingFinding(pre, post ceilingSnapshot, wantHundredths int64) Finding {
	if !pre.Available {
		return unavailable("could not read the DER's own active-power ceiling register BEFORE publishing the "+
			"expired control, so this row cannot additionally confirm it never moved (the Response-status "+
			"criterion above stands on its own): %s", pre.Note)
	}
	if !post.Available {
		return unavailable("could not re-read the DER's own active-power ceiling register AFTER the "+
			"observation window, so this row cannot additionally confirm it never moved: %s", post.Note)
	}
	if pre.Point != post.Point {
		return unavailable("the DER's own ceiling register home changed between the two reads (%s -> %s), "+
			"which is not a comparable pair", pre.Point, post.Point)
	}
	if pre.Enabled != post.Enabled || pre.Raw != post.Raw {
		return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
			"the DER's own %s moved from enabled=%t raw=%s%% to enabled=%t raw=%s%% between the "+
				"pre-publication read and the post-wait read, despite the published control's own interval "+
				"having ALREADY ELAPSED at receipt (IEEE Std 2030.5-2018 §10.2.3.3 l): \"this Event SHALL be "+
				"ignored\") — the DER acted on an event the DUT should never have adopted",
			pre.Point, pre.Enabled, trimNum(pre.Raw), post.Enabled, trimNum(post.Raw))}
	}
	return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
		"the DER's own %s held enabled=%t raw=%s%% both before publishing the expired control (which "+
			"commanded %s%%) and after the observation window — it was never actuated",
		pre.Point, pre.Enabled, trimNum(pre.Raw), trimNum(float64(wantHundredths)/100))}
}

// ext004CeilingStabilityCriterion is EXT-004's supporting (non-load-bearing)
// claim: the DER's own active-power ceiling register — the axis this row's
// expired control itself commands (opModMaxLimW/WMaxLimPct) — never moved.
// Not this row's PRIMARY claim (ext004ResponseCriterion is: a DUT could
// satisfy this criterion by never reading the control list at all, which
// proves nothing about REV0907-B2's own logic), but real corroborating
// evidence when it IS available: a mover here would mean the DUT reported
// the rejection correctly on the wire while still letting the southbound
// pipeline actuate the axis, a worse defect than either alone.
//
// Tier/Wire (rather than Server, and reporting a verdict computed live from
// Observation.Params) is the SAME shape critDEREffectViaDirectOracle uses
// for the identical reason its own doc gives: this criterion's answer comes
// from an independent read of the DER's own registers, not from the
// gridsim admin log or the 2030.5 wire, and criteria.go's Tier field exists
// precisely so that provenance can be stated honestly.
func ext004CeilingStabilityCriterion(o *Observation) criterion {
	pre := decodeCeilingSnapshot(o.Params[ext004CeilingPreParam])
	post := decodeCeilingSnapshot(o.Params[ext004CeilingPostParam])
	want, _ := strconv.ParseInt(o.Params[ext004WantParam], 10, 64)
	f := ext004CeilingFinding(pre, post, want)
	return criterion{
		Claim: fmt.Sprintf("the DER's own active-power ceiling register (the axis this row's expired control "+
			"itself commands, %s%%) never moved across the observation window", trimNum(float64(want)/100)),
		How: "an independent read of the DER's own active-power ceiling register (whichever generation it " +
			"serves — internal/invariant, via the SAME ceilingHomeOf resolution basic.go's BASIC-010 oracle " +
			"uses), taken before the control was published and again after the wait, compared for EQUALITY " +
			"rather than for a reached value: this row's claim is that nothing happened",
		Tier: tierOracle,
		Wire: func(_ *certify.Evidence, _ *Transcript) Finding {
			return f
		},
	}
}
