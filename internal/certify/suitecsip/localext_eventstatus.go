package suitecsip

// localext_eventstatus.go — EXT-002/EXT-003, the LOCAL EXTENSION rows
// REV0907-B1 requires: no published CSIP-CONF-v1.3 procedure exercises a
// RESERVED currentStatus value (EXT-002) or Cancelled-with-Randomization,
// currentStatus=3 (EXT-003) at all — CORE-022 only ever drove plain
// Cancelled(2) — so neither the defect (this bench treating 6 as Cancelled)
// nor its positive companion (the end-randomization wait 3 requires) had a
// row to be caught by. See localext.go's doc for what a LOCAL EXTENSION row
// is and is not.
//
// Both rows share gridsim's admin-driven "server-cancel" idiom CORE-022 uses
// (sim/gridsim/admin.go's adminCtrlReq doc): publish a control, wait for it
// to be Started, then a status-only update on the SAME mRID. Program 2 is
// used for both — CORE-022/CORE-023 and the aggregator rows already occupy
// programs 0/1 with their own axis-independence bookkeeping, and these rows
// have no supersession concern of their own to protect.

import (
	"context"
	"fmt"
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
