package suitecsip

// aggregator.go implements the twenty-two rows the DER AGGREGATOR CLIENT profile
// requires and the DER Client profile did not.
//
// Owner decision 2026-07-28 (docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md):
// the DUT is certified against §4's DER Aggregator Client column, so AGG-001..012,
// CORE-018, CORE-019, ERR-002, MAINT-001/003/004/005 and UTIL-002/003/004 stop
// being N/A rows carrying an errata breadcrumb and become rows that must run.
//
// # What "must run" means here, precisely
//
// Every one of these rows was written against a fixture this bench does not
// build: the CTP Figure-15 topology (an aggregator EndDevice plus EDA1/EDA2/EDB1/
// EDB2) and, for most of them, the 2030.5 Subscription/Notification function set.
// There were three ways to respond and only one of them is honest.
//
//	1. Report PASS because the DUT handled the one-EndDevice shape it was given.
//	   That is certifying a test that never ran.
//	2. Report FAIL because the four EndDevices are not there. That is reporting a
//	   BENCH gap as a DUT finding — the worst kind of false positive, because it
//	   looks like diligence.
//	3. Drive everything the bench CAN drive, assert it for real, and SKIP each
//	   remaining criterion with the specific missing capability named.
//
// This file does (3). The consequence worth stating plainly: several of these
// rows will report a run of PASSes and SKIPs, never a PASS alone, until
// sim/gridsim grows a four-EndDevice tree and a subscription function set. The
// SKIP reasons are written to be work items, not apologies.
//
// # What the bench really drives
//
// gridsim publishes DERControls on three DERPrograms of different primacy, so
// the event-precedence core of AGG-003..AGG-012 IS exercised against one
// EndDevice: the controls go on the wire with the document's own start offsets
// and durations, and the DUT's Response statuses are read back and judged. That
// includes the one thing in this whole set that a careless implementation would
// get wrong — Annex A Errata I seq 5/6, which change AGG-007's and AGG-008's
// expected supersession status from the printed 7 to 14. See critSupersessionStatus.
//
// # Programs
//
// gridsim's three programs stand in for the CTP's topology nodes, the same way
// registerEventScenarios already uses them:
//
//	program 0, primacy 1  → TFA (the transformer / service-point program, HIGHER priority)
//	program 2, primacy 10 → SY  (the system program, LOWER priority)

import (
	"context"
	"fmt"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// The gridsim DERProgram indices that stand in for the CTP's topology nodes.
const (
	progTFA = 0
	progSY  = 2
)

// ── AGG-001 ──────────────────────────────────────────────────────────────────

// aggSubscription implements AGG-001 — Aggregator Operation Subscription.
//
// ERRATA seq 1 is applied: printed step 5 becomes "[C] Receives the notification
// of the EndDeviceList and responds with 201 Created", and the GET of the newly
// created EDA1X EndDevice moves into a new step 6 tagged [CT] — a TEST CLIENT
// step. That re-tag matters: the uncorrected text demanded the GET of the DUT,
// so a check written straight from the printed steps would fail a conformant
// aggregator for not re-fetching information it had just been pushed.
func aggSubscription(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "aggregator subscription (AGG-001), read through Annex A seq 1: the client answers the " +
				"EndDeviceList Notification 201 Created, and the follow-up GET of the new EDA1X EndDevice is a " +
				"[CT] test-client step, not a demand on the DUT"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critSubscriptionPosted("EndDeviceList",
					"the aggregator EndDevice's SubscriptionListLink"),
				{
					Claim: "the server sends a Notification to the client when an EndDevice is added to the " +
						"aggregator's EndDeviceList",
					How:  "the server-originated Notification POST carrying the changed EndDeviceList",
					Skip: notificationGap,
				},
				critNotificationAnswered([]int{201},
					"AGG-001's printed step 5, as amended by Annex A seq 1, states 201 Created"),
				critPerDeviceFanOut("the newly created EDA1X EndDevice instance is reachable and carries the "+
					"links the setup requires", "the aggregator's managed fleet"),
			}
		},
	})
}

// ── AGG-002..012 ─────────────────────────────────────────────────────────────

// aggControl is one DERControl an aggregator scenario publishes.
type aggControl struct {
	MRID    string
	Program int
	// StartOffset and DurationS are the document's own numbers, in seconds.
	StartOffset int
	DurationS   int
	// Mode selects the control axis. The "independent controls" rows (AGG-010,
	// AGG-011, AGG-012) turn entirely on the two controls carrying DIFFERENT
	// modes, so this is not cosmetic.
	Mode aggMode
	// Superseded marks the control the scenario expects to lose.
	Superseded bool
	// CreationAge back-dates the control's creation so the winner of a pair is
	// deterministic rather than a race between two admin POSTs.
	CreationAge int
	// LateAfterS delays publication by this many seconds. It is how AGG-009 and
	// AGG-012 reproduce "After the start of the SY event, create a DERControl…",
	// which is the entire reason those two rows expect a different outcome from
	// their siblings.
	LateAfterS int
}

// aggMode is a control axis this bench can publish.
type aggMode int

const (
	// modeFixedPFInjectW is the CTP's running example, opModFixedPFInjectW.
	modeFixedPFInjectW aggMode = iota
	// modeFixedW is opModFixedW, the "different control" the independent rows use.
	modeFixedW
)

func (m aggMode) apply(r *ControlRequest) {
	switch m {
	case modeFixedW:
		r.FixedW = ptr(int64(50))
	default:
		r.FixedPFInjectW = ptr(int64(95))
	}
}

func (m aggMode) element() string {
	if m == modeFixedW {
		return "opModFixedW"
	}
	return "opModFixedPFInjectW"
}

// aggFanOut is one pass criterion the document states per managed EndDevice.
type aggFanOut struct{ What, Devices string }

// aggScenario is one aggregator event row.
type aggScenario struct {
	// Summary is the fixture in one line, for the bundle's notes.
	Summary string
	// Controls are published in order at setup, honouring LateAfterS.
	Controls []aggControl
	// Lifecycles name the controls whose 1/2/3 Response sequence is asserted.
	Lifecycles []aggLifecycle
	// Superseded, when set, is the mRID whose supersession status this row pins,
	// with the status the ERRATA prescribe for THIS row.
	Superseded       string
	SupersedeStatus  uint8
	SupersedeMeaning string
	SupersedeWhy     string
	// Independent, when set, names the mRIDs across which NO supersession
	// Response may appear.
	Independent []string
	// Defaults names the DefaultDERControls whose activation the document itself
	// declares unobservable.
	Defaults []string
	// FanOut are the per-EndDevice pass criteria the one-EndDevice bench cannot
	// reach.
	FanOut []aggFanOut
}

type aggLifecycle struct {
	MRID, Label string
	SpanS       int
}

// aggEvent builds one of AGG-002..AGG-012.
func aggEvent(sc aggScenario) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, spec{
			RequiresGridSim: len(sc.Controls) > 0,
			Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
				for _, c := range sc.Controls {
					if c.LateAfterS > 0 {
						// "After the start of the SY event, create a DERControl…"
						// If the check's deadline cannot hold the delay, the row
						// is NOT quietly turned into its sibling: the deviation
						// is recorded and the criteria that depend on it say so.
						if err := rc.Sleep(ctx, time.Duration(c.LateAfterS)*time.Second); err != nil {
							params[lateSkipped] = fmt.Sprintf("the procedure creates %s only AFTER the "+
								"earlier event has started (%d s in), and this check's deadline expired "+
								"during that wait, so the late control was never published and the "+
								"discovery-after-start condition this row turns on was never created. "+
								"Raise -timeout past %d s", c.MRID, c.LateAfterS, c.LateAfterS+120)
							rc.Logf("late publication of %s abandoned: %v", c.MRID, err)
							return nil
						}
					}
					req := ControlRequest{
						Program: c.Program, MRID: c.MRID, Description: "certify " + rc.Case.ID,
						StartOffset: c.StartOffset, DurationS: c.DurationS,
					}
					c.Mode.apply(&req)
					if c.Superseded {
						req.PotentiallySuperseded = ptr(true)
					}
					if c.CreationAge != 0 {
						age := c.CreationAge
						req.CreationOffsetS = &age
					}
					if _, err := d.PostControl(ctx, req); err != nil {
						return err
					}
				}
				return nil
			},
			Want: func(base ServerView) func(ServerView) bool {
				if len(sc.Lifecycles) == 0 {
					return nil
				}
				first := sc.Lifecycles[0].MRID
				return func(v ServerView) bool { return len(v.ResponsesFor(first)) > 0 }
			},
			Cleanup: func(ctx context.Context, d *Driver) {
				seen := map[int]bool{}
				for _, c := range sc.Controls {
					if !seen[c.Program] {
						seen[c.Program] = true
						_ = d.ClearControls(ctx, c.Program)
					}
				}
			},
			Notes: func(o *Observation) string {
				n := sc.Summary + fmt.Sprintf("; waited %s", o.Waited.Round(rounding))
				if r := o.Param(lateSkipped); r != "" {
					n += ". DEVIATION: " + r
				}
				return n
			},
			Criteria: func(o *Observation) []criterion { return aggCriteria(sc, o) },
		})
	}
}

// lateSkipped is the params key recording that a delayed publication did not
// happen, so the criteria that depend on it report the deviation instead of a
// verdict the fixture does not support.
const lateSkipped = "agg.late_publish_skipped"

func aggCriteria(sc aggScenario, o *Observation) []criterion {
	crits := []criterion{critAggregatorFleet(), critProgramList(0)}
	for _, d := range sc.Defaults {
		crits = append(crits, critDefaultControlOutOfBand(d))
	}
	if len(sc.Controls) > 0 {
		crits = append(crits, critAggControlsDelivered(sc))
	}
	for _, l := range sc.Lifecycles {
		crits = append(crits, critEventLifecycle(l.MRID, l.Label, l.SpanS))
	}
	if sc.Superseded != "" {
		c := critSupersessionStatus(sc.Superseded, sc.SupersedeStatus, sc.SupersedeMeaning, sc.SupersedeWhy)
		crits = append(crits, withDeviation(c, o))
	}
	if len(sc.Independent) > 0 {
		crits = append(crits, withDeviation(critNoSupersession(sc.Independent), o))
	}
	for _, f := range sc.FanOut {
		crits = append(crits, critPerDeviceFanOut(f.What, f.Devices))
	}
	return crits
}

// withDeviation turns a criterion into a SKIP when the scenario's delayed
// publication did not happen. The criterion is about a condition the fixture no
// longer created, so a verdict from it would be a verdict about a different test.
func withDeviation(c criterion, o *Observation) criterion {
	r := o.Param(lateSkipped)
	if r == "" {
		return c
	}
	return criterion{Claim: c.Claim, How: c.How, Skip: r}
}

// critAggControlsDelivered asserts that every control the scenario published
// reached the DUT, and that the two rows whose point is DIFFERENT control modes
// really carried different ones.
func critAggControlsDelivered(sc aggScenario) criterion {
	want := map[string]string{}
	for _, c := range sc.Controls {
		want[c.MRID] = c.Mode.element()
	}
	return criterion{
		Claim: "every DERControl the scenario published reached the DUT in a DERControlList it fetched, " +
			"carrying the control mode the procedure names",
		How: "the <mRID> and DERControlBase children of the DERControls in the DERControlLists the DUT " +
			"fetched during the window",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			got := map[string][]string{}
			var frames []int
			for _, e := range t.ByResource("DERControlList") {
				doc, err := e.Resp.SEP()
				if err != nil {
					continue
				}
				for _, c := range doc.Children("DERControl") {
					m, ok := c.TextOf("mRID")
					if !ok {
						continue
					}
					var modes []string
					if base := c.Child("DERControlBase"); base != nil {
						for _, k := range base.Kids {
							modes = append(modes, k.Local())
						}
					}
					got[m] = modes
				}
				frames = append(frames, e.Frames()...)
			}
			if len(frames) == 0 {
				return unavailable("no DERControlList appears in the recovered transcript")
			}
			var missing, wrongMode []string
			for mrid, mode := range want {
				modes, arrived := got[mrid]
				if !arrived {
					missing = append(missing, mrid)
					continue
				}
				if !contains(modes, mode) {
					wrongMode = append(wrongMode, fmt.Sprintf("%s carried [%s], not <%s>",
						mrid, strings.Join(modes, " "), mode))
				}
			}
			switch {
			case len(missing) > 0:
				return found(certify.Fail, dedupeInts(frames),
					"%d of %d published control(s) did not reach the DUT: %s",
					len(missing), len(want), strings.Join(missing, " "))
			case len(wrongMode) > 0:
				return found(certify.Fail, dedupeInts(frames),
					"every published control reached the DUT but the modes are wrong: %s",
					strings.Join(wrongMode, "; "))
			default:
				return found(certify.Pass, dedupeInts(frames),
					"all %d published control(s) reached the DUT carrying the modes the procedure names", len(want))
			}
		},
		Server: func(v *ServerView) Finding {
			n := 0
			for mrid := range want {
				if len(v.ResponsesFor(mrid)) > 0 {
					n++
				}
			}
			if n == 0 {
				return unavailable("gridsim received no Response for any of the scenario's controls, so " +
					"delivery cannot be confirmed from the server side alone")
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("the DUT acknowledged %d of %d published control(s) to gridsim; "+
					"which control MODE each carried is not recoverable from the server's Response log",
					n, len(want))}
		},
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ── CORE-018 / CORE-019 ──────────────────────────────────────────────────────

// coreBasicSubscription implements CORE-018 — Basic Subscription.
//
// ERRATA seq 44 is applied and it TIGHTENS the row: "The 204 response is not
// included in the WADL — Remove the acceptance of 204 response in Procedure and
// Pass/Fail Criteria". 201 Created is therefore the only conformant answer to a
// Notification here. The scope is narrow and the narrowness is the trap: seq 23
// ADDS a 204 expectation to CORE-014's PUTs of DERCapability and DERSettings,
// which critDERPut already asserts. A blanket rule about 204 would break one row
// or the other.
func coreBasicSubscription(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "basic subscription (CORE-018), read through Annex A seq 44: HTTP 204 is NOT an acceptable " +
				"answer to a Notification for this row, so only 201 Created is asserted"
		},
		Criteria: func(o *Observation) []criterion { return core018Criteria() },
	})
}

// core018Criteria is CORE-018's criteria list, named so errata_test.go can pin
// the seq-44 tightening against the code that implements it rather than only
// against the catalog record of it.
func core018Criteria() []criterion {
	return []criterion{
		critDiscoveryRoot(),
		critSubscriptionAdvertised(),
		critFSAList(0),
		critSubscriptionPosted("FunctionSetAssignmentsList", "the DUT's EndDevice SubscriptionListLink"),
		{
			Claim: "the server changes an element of the subscribed FunctionSetAssignments and pushes " +
				"a Notification carrying the updated payload",
			How:  "the server-originated Notification POST to the DUT's notificationURI",
			Skip: notificationGap,
		},
		critNotificationAnswered([]int{201},
			"Annex A seq 44 removes the acceptance of 204 for CORE-018, so 201 Created is the only "+
				"conformant answer"),
		{
			Claim: "the DUT GETs the href carried in the Notification and the payload the server " +
				"returns is identical to the Notification body",
			How: "a GET of the notified href in the window after the Notification, with its response " +
				"body compared to the Notification body",
			Skip: notificationGap,
		},
	}
}

// coreAdvancedSubscription implements CORE-019 — Advanced Subscription.
//
// Two errata apply. seq 44 removes the 204 acceptance, exactly as for CORE-018.
// seq 42 removes printed steps 10 and 11: a change to a SUBORDINATE resource
// requires ONE Notification, not a second one for the parent EndDevice. A check
// that waited for the parent notification would fail a conformant client, so
// this one does not look for it and says so where a reader will see it.
func coreAdvancedSubscription(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "advanced subscription (CORE-019), read through Annex A seq 42 and seq 44: ONE Notification " +
				"per subordinate-resource change (no second notification for the parent EndDevice), and 204 is " +
				"not an acceptable answer to it"
		},
		Criteria: func(o *Observation) []criterion { return core019Criteria() },
	})
}

// core019Criteria is CORE-019's criteria list. See core018Criteria.
func core019Criteria() []criterion {
	return []criterion{
		critDiscoveryRoot(),
		critSubscriptionAdvertised(),
		critSubscriptionPosted("EndDevice", "the DUT's EndDevice SubscriptionListLink"),
		critSubscriptionPosted("FunctionSetAssignmentsList", "the DUT's EndDevice SubscriptionListLink"),
		critNotificationAnswered([]int{201},
			"Annex A seq 44 removes the acceptance of 204 for CORE-019, so 201 Created is the only "+
				"conformant answer"),
		{
			Claim: "a change to a subordinate resource produces exactly ONE Notification — not a " +
				"second one for the parent EndDevice",
			How: "the count of Notification POSTs the server sends for a single subordinate change, " +
				"per Annex A seq 42 which removes printed steps 10 and 11",
			Skip: notificationGap,
		},
		{
			Claim: "the DUT processes a Notification with status=1 (Subscription canceled, no " +
				"additional information) and answers it",
			How:  "the DUT's response to the cancellation Notification POST",
			Skip: notificationGap,
		},
	}
}

// critSubscriptionAdvertised asserts the server-side precondition CORE-018 and
// CORE-019 both open with: the DUT's EndDevice carries a SubscriptionListLink,
// and the FSAList it points at is subscribable.
//
// It is a criterion about the BENCH, not the DUT, and it is stated so that the
// rows below it read correctly: everything they skip skips because this one
// could not be satisfied.
func critSubscriptionAdvertised() criterion {
	return criterion{
		Claim: "the server serves the DUT's EndDevice with a SubscriptionListLink, and the " +
			"FunctionSetAssignmentsList beneath it with subscribable=1 (unconditional subscription)",
		How: "the SubscriptionListLink child of the DUT's EndDevice and the subscribable attribute of the " +
			"FunctionSetAssignmentsList the server served",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			offered, where := subscriptionOffered(t)
			if !offered {
				e, _, ok := t.Resource("EndDeviceList")
				if !ok {
					return unavailable("no EndDeviceList appears in the recovered transcript, so the "+
						"subscription precondition cannot be read. %s", notificationGap)
				}
				return citeMessage(t, e.Resp, certify.Skip,
					"the server advertised no SubscriptionListLink in %s. %s", where, notificationGap)
			}
			sub := "unknown"
			if _, doc, ok := t.Resource("FunctionSetAssignmentsList"); ok {
				if v, has := doc.Attr("subscribable"); has {
					sub = v
				} else {
					sub = "absent"
				}
			}
			e, _, _ := t.Resource("EndDeviceList")
			if sub != "1" {
				return citeMessage(t, e.Resp, certify.Skip,
					"the server advertised a SubscriptionListLink in %s, but the FunctionSetAssignmentsList's "+
						"subscribable attribute is %q where the setup requires 1 (unconditional subscription)",
					where, sub)
			}
			return citeMessage(t, e.Resp, certify.Pass,
				"SubscriptionListLink advertised in %s and the FunctionSetAssignmentsList is subscribable=1", where)
		},
		Skip: "reading the subscription precondition requires the decrypted transcript",
	}
}

// ── ERR-002 ──────────────────────────────────────────────────────────────────

// errNotification implements ERR-002 — Error Scenario 2.
//
// ERRATA seq 38 is applied: "Remove Step 6". Printed step 6 has the client
// re-POST a Subscription after the server cancels it with status 1, and IEEE
// 2030.5 requires no such thing. There is therefore NO criterion below about a
// re-subscription, and the omission is deliberate and stated: a check that
// waited for that POST would hang for its whole timeout and then report a
// conformant client as failing.
//
// Note what ERR-002 does NOT inherit from its siblings: its printed step 3 still
// admits "HTTP 201 Created or 204 No Content". Annex A seq 44 removes the 204
// acceptance for CORE-018 and CORE-019 ONLY, so this row keeps both.
func errNotification(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "error scenario 2 (ERR-002), read through Annex A seq 38: printed step 6 is REMOVED, so " +
				"this check does not look for a re-POSTed Subscription after a status=1 cancellation and does " +
				"not hold the DUT to one. Step 3's '201 Created or 204 No Content' stands — seq 44's removal " +
				"of 204 is scoped to CORE-018/CORE-019"
		},
		Criteria: func(o *Observation) []criterion { return err002Criteria() },
	})
}

// err002Criteria is ERR-002's criteria list. Two things about it are pinned by
// errata_test.go: it accepts BOTH 201 and 204 (seq 44's removal of the 204 is
// scoped to CORE-018/CORE-019), and it contains no criterion demanding a
// re-POSTed Subscription (seq 38 removes printed step 6).
func err002Criteria() []criterion {
	return []criterion{
		critDiscoveryRoot(),
		critSubscriptionAdvertised(),
		critSubscriptionPosted("FunctionSetAssignmentsList", "the DUT's EndDevice SubscriptionListLink"),
		{
			Claim: "the server's outstanding subscriptions survive a power reset and it pushes a " +
				"Notification for a post-reset change to the subscribed FunctionSetAssignmentsList",
			How: "a server restart followed by a Notification POST on the pre-existing subscription, " +
				"with no re-POST of the Subscription required of the DUT",
			Skip: "sim/gridsim has no power-reset lever in its admin API and no subscription state to " +
				"persist across one. " + notificationGap,
		},
		critNotificationAnswered([]int{201, 204},
			"ERR-002's printed step 3 admits either; Annex A seq 44's removal of the 204 acceptance is "+
				"scoped to CORE-018 and CORE-019 and does NOT reach this row"),
		{
			Claim: "the DUT GETs the href carried in the Notification and the payload is identical to " +
				"the Notification body",
			How:  "a GET of the notified href with its response body compared to the Notification body",
			Skip: notificationGap,
		},
		{
			Claim: "on a Notification with status=1 (Subscription canceled) the DUT removes that " +
				"subscription from its own list of outstanding Subscriptions",
			How: "the absence of further client traffic on the cancelled subscription. Per Annex A " +
				"seq 38 the DUT is NOT required to re-POST the Subscription, and this criterion does " +
				"not look for one",
			Skip: notificationGap,
		},
		{
			Claim: "on an INVALID Notification — EndDevice instance information delivered against a " +
				"FunctionSetAssignmentsList subscription — the DUT responds HTTP 400",
			How: "the status line of the DUT's response to the malformed Notification POST",
			Skip: "sim/gridsim's malform injection (POST /admin/malform) rewrites a resource the DUT " +
				"GETs; it cannot originate a malformed Notification, because it originates no " +
				"Notification at all. " + notificationGap,
		},
	}
}

// ── MAINT-001 / 003 / 004 / 005 ──────────────────────────────────────────────

// maintOOBInverter implements MAINT-001 — Inverter Maintenance (Out-Of-Band).
func maintOOBInverter(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "out-of-band inverter maintenance (MAINT-001): the aggregator's fleet shrinks by agreement " +
				"off-protocol and the server deletes the EndDevice. No client-initiated DELETE belongs on the " +
				"wire for this row — that is MAINT-002, which §4 requires of nobody"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critSubscriptionPosted("EndDeviceList", "the aggregator EndDevice's SubscriptionListLink"),
				{
					Claim: "the server deletes the EDA1X EndDevice from the aggregator's EndDeviceList and " +
						"pushes a Notification for the change",
					How: "the EndDeviceList Notification POST after the server-side deletion, its list length " +
						"honouring the limit parameter of the original subscription",
					Skip: "sim/gridsim serves a fixed EndDevice tree and its admin API has no lever to create " +
						"or delete a server-side EndDevice, so the deletion this row is about cannot be " +
						"performed. " + notificationGap,
				},
				{
					Claim: "a GET of the deleted EDA1X EndDevice href returns HTTP 404 Not Found",
					How:   "the status line of a [CT] test-client GET of the deleted EndDevice's href",
					Skip: "there is no EDA1X to delete on this bench (see the fleet criterion), so there is no " +
						"href for the 404 to be about. " + fleetGap,
				},
				critPerDeviceFanOut("the client's internal state stops managing the deleted device",
					"the aggregator's managed fleet"),
			}
		},
	})
}

// maintGroup implements MAINT-003 — Group Maintenance.
func maintGroup(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "group maintenance (MAINT-003): EDB1 is re-parented from SPB1 to SPA1, which moves it from " +
				"the TFB DERProgram to TFA. Procedure steps 9 and 10 are conditional ('If needed'), so they " +
				"are reported, never gated on"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critFSAList(0),
				critSubscriptionPosted("FunctionSetAssignmentsList",
					"each managed EndDevice's SubscriptionListLink"),
				{
					Claim: "the server re-parents EDB1 from SPB1 to SPA1 and pushes a Notification that its " +
						"FunctionSetAssignmentsList changed",
					How: "the FunctionSetAssignmentsList Notification POST following the topology move",
					Skip: "sim/gridsim serves one FunctionSetAssignments over a fixed topology and its admin " +
						"API has no lever to move an EndDevice between nodes, so the regrouping this row is " +
						"about cannot be performed. " + notificationGap,
				},
				{
					Claim: "on that Notification the aggregator GETs the new FunctionSetAssignmentsList and " +
						"the DERProgramList it now belongs to",
					How:  "the GETs following the Notification, compared against the hrefs it carried",
					Skip: notificationGap,
				},
				critPerDeviceFanOut("the aggregator cancels its subscription to the old "+
					"FunctionSetAssignmentsList and subscribes to the new one (both 'If needed', so neither is "+
					"a gate)", "EDB1"),
			}
		},
	})
}

// maintControls implements MAINT-004 — Maintenance of Controls.
//
// This is the one MAINT row with a lever: the change under test is "add a new
// DERControl that starts in plus-fifteen minutes with duration of five minutes
// (no randomization)", and gridsim can publish exactly that. The control really
// goes on the wire and the DUT's acquisition of it is really asserted; only the
// Notification that would announce it, and the per-EndDevice fan-out, skip.
func maintControls(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	const mrid = "CERT-MAINT004"
	return run(ctx, rc, spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The document's own numbers: +15 min, 5 min, no randomization.
			_, err := d.PostControl(ctx, ControlRequest{
				Program: progTFA, MRID: mrid, Description: "MAINT-004 added control",
				StartOffset: 900, DurationS: 300, MaxLimW: ptr(int64(4000)),
			})
			params["mrid"] = mrid
			return err
		},
		Cleanup: func(ctx context.Context, d *Driver) { _ = d.ClearControls(ctx, progTFA) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("maintenance of controls (MAINT-004): published %s on the TFA DERProgram with "+
				"the procedure's own interval — start +15 min, duration 5 min, no randomization — and waited "+
				"%s for the DUT to acquire it", mrid, o.Waited.Round(rounding))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critSubscriptionPosted("DERControlList", "each EndDevice FunctionSetAssignments"),
				{
					Claim: "the server pushes a Notification for the changed DERControlList after the new " +
						"DERControl is added to the TFA DERProgram",
					How:  "the DERControlList Notification POST following the addition",
					Skip: notificationGap,
				},
				critNewControlAcquired(mrid, 900, 300),
				critPerDeviceFanOut("the Event Processing rules of IEEE 2030.5 §12.1.3 are applied to every "+
					"DERControl of every managed EndDevice and a Response POSTed where responseRequired "+
					"demands one", "each managed EndDevice"),
			}
		},
	})
}

// critNewControlAcquired asserts that the DUT fetched the added DERControl with
// the interval the procedure specifies and no randomization.
func critNewControlAcquired(mrid string, startIn, durationS int) criterion {
	return criterion{
		Claim: fmt.Sprintf("the DUT fetched the newly added DERControl, whose interval is start +%d s for a "+
			"%d s duration with no randomization", startIn, durationS),
		How: "the <interval>/<duration> and randomizeStart/randomizeDuration elements of the DERControl " +
			"carrying the published mRID, in the DERControlList the DUT fetched",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.ByResource("DERControlList") {
				doc, err := e.Resp.SEP()
				if err != nil {
					continue
				}
				for _, c := range doc.Children("DERControl") {
					if m, _ := c.TextOf("mRID"); !strings.EqualFold(m, mrid) {
						continue
					}
					dur, hasDur := int64(0), false
					if iv := c.Child("interval"); iv != nil {
						dur, hasDur = iv.IntOf("duration")
					}
					rs, hasRS := c.IntOf("randomizeStart")
					rd, hasRD := c.IntOf("randomizeDuration")
					switch {
					case !hasDur:
						return citeMessage(t, e.Resp, certify.Fail,
							"the DUT fetched %s but its DERControl carries no interval/duration", mrid)
					case dur != int64(durationS):
						return citeMessage(t, e.Resp, certify.Fail,
							"the DUT fetched %s with interval/duration %d s; the procedure specifies %d s",
							mrid, dur, durationS)
					case (hasRS && rs != 0) || (hasRD && rd != 0):
						return citeMessage(t, e.Resp, certify.Fail,
							"the procedure specifies no randomization but %s carries randomizeStart=%d "+
								"randomizeDuration=%d", mrid, rs, rd)
					default:
						return citeMessage(t, e.Resp, certify.Pass,
							"the DUT fetched %s with a %d s interval and no randomization", mrid, dur)
					}
				}
			}
			return unavailable("the DERControlLists in the recovered transcript carry no DERControl with "+
				"mRID %s; the DUT had not acquired the added control within this window", mrid)
		},
		Server: func(v *ServerView) Finding {
			if len(v.ResponsesFor(mrid)) == 0 {
				return unavailable("gridsim received no Response for %s, which is expected when the "+
					"control does not ask for one; acquisition cannot be confirmed from the server side "+
					"alone", mrid)
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("the DUT acknowledged %s to gridsim, so it acquired it; the interval "+
					"and randomization fields are not recoverable from the server's Response log", mrid)}
		},
	}
}

// maintPrograms implements MAINT-005 — Maintenance of Programs.
//
// ERRATA seq 34 is applied: procedure step 2 becomes a subscription to the
// DERProgramLIST (not to the individual DERProgram), and the client pages for
// items a truncated Notification payload omitted rather than being required to
// set limit to "all".
func maintPrograms(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "maintenance of programs (MAINT-005), read through Annex A seq 34: the subscription is to " +
				"the DERProgramLIST, and the client pages for additional items when a Notification payload is " +
				"truncated rather than being required to request them all"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critProgramList(0),
				critSubscriptionPosted("DERProgramList", "each EndDevice FunctionSetAssignments"),
				{
					Claim: "the server swaps the primacy values of the TFA/TFB and SGA/SGB DERPrograms and " +
						"pushes Notifications for the affected DERProgram and DERProgramList",
					How: "the DERProgram/DERProgramList Notification POSTs following the primacy swap",
					Skip: "sim/gridsim's admin API has no lever to change a DERProgram's primacy — its three " +
						"programs carry fixed primacy 1 / 5 / 10 — so the swap this row is about cannot be " +
						"performed. " + notificationGap,
				},
				{
					Claim: "with no DERControl active, the DUT applies the DefaultDERControl of the DERProgram " +
						"that is highest priority AFTER the swap (IEEE 2030.5 DER.005)",
					How: "an out-of-band read of the setpoint in force, compared against the DefaultDERControl " +
						"of the lowest-primacy DERProgram",
					Skip: "the swap could not be performed (see above), and DER.005's effect is a setpoint at " +
						"the DER rather than a 2030.5 artefact: IEEE 2030.5 defines no acknowledgment for " +
						"activating a DefaultDERControl",
				},
			}
		},
	})
}

// ── UTIL-002 / 003 / 004 ─────────────────────────────────────────────────────

// utilCommissioning implements UTIL-002 — Utility-Aggregator Operations
// Commissioning.
//
// This is the row of the aggregator set that this bench drives most completely.
// Its procedure IS the commissioning walk — /dcap → EndDeviceList → match the
// aggregator's own SFDI/LFDI → GET the RegistrationLink → compare the pIN → PUT
// the DER self-report resources — and every one of those steps is asserted for
// real against the aggregator's own EndDevice. Only the "for all other EndDevice
// instances (EDA1, EDA2, EDB1, EDB2)" fan-out needs the fleet.
//
// ERRATA seq 3 is applied and it changes what is asserted: the printed procedure
// PUTs to the DERListLink, which is a list resource and cannot accept a DER
// self-report. The corrected step 6 reads "Do an HTTP PUT on DERCapabilities,
// DERSettings, DERStatus or DERAvailability", so the criteria below assert PUTs
// of those four field resources and NOT of the list href.
func utilCommissioning(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pin, _ := rc.Param(pinParam)
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return fmt.Sprintf("aggregator commissioning (UTIL-002), read through Annex A seq 3: the PUT goes "+
				"to DERCapability / DERSettings / DERStatus / DERAvailability, NOT to the DERListLink. "+
				"gridsim recorded %d DER self-report PUT(s) during the window", len(o.Server.DERPuts))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critEndDeviceList(0),
				critSelfIdentity(),
				critRegistrationPIN(pin),
				critResource("DERList", "the DUT followed the DERListLink of an EndDevice and the server "+
					"answered 200 with a DERList", nil),
				critDERPut("DERCapability"),
				critDERPut("DERSettings"),
				critAggregatorFleet(),
				critPerDeviceFanOut("the aggregator follows each managed EndDevice's DERListLink and PUTs its "+
					"DERCapability / DERSettings / DERStatus / DERAvailability", "EDA1, EDA2, EDB1 and EDB2"),
			}
		},
	})
}

// utilGroupRetrieval implements UTIL-003 — Utility-Aggregator Operations Group
// Assignments Retrieval.
//
// ERRATA seq 12 is applied: the subscription's subscribedResource is the
// DERProgramLIST href, not an individual DERProgram. The source misspells it
// "DERPrgramList" twice; the misspelling is preserved in the catalog and
// corrected here, because a check matching the typo would match nothing.
func utilGroupRetrieval(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "aggregator group-assignment retrieval (UTIL-003), read through Annex A seq 12: the " +
				"subscription targets the DERProgramLIST, not an individual DERProgram. The row's Purpose " +
				"promises coverage of conflicting DERPrograms, but no step exercises one — the conflict " +
				"resolution is AGG-007..AGG-012's subject, not this row's"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critFSAList(0),
				critProgramList(0),
				critSubscriptionPosted("DERProgramList",
					"the aggregator EndDevice's SubscriptionListLink, per Annex A seq 12"),
				critSubscriptionPosted("DERControlList",
					"the aggregator EndDevice's SubscriptionListLink"),
				critPerDeviceFanOut("the aggregator GETs the FunctionSetAssignments and every DERProgram "+
					"beneath them", "EDA1, EDA2, EDB1 and EDB2"),
			}
		},
	})
}

// utilDERRetrieval implements UTIL-004 — Utility-Aggregator Operations DER
// Retrieval.
//
// The single-device core of this row is drivable and is driven: a DERControl at
// start +2 min for a 2 min duration, and the Response(received/started/completed)
// loop read back off the wire. What the bench cannot reproduce is the row's
// point — the SCOPE FAN-OUT, where a control at SPA1 yields Responses for EDA1
// alone, one at FDA for EDA1 and EDA2, and one at SY for all four.
func utilDERRetrieval(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	const mrid = "CERT-UTIL004"
	return run(ctx, rc, spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			_, err := d.PostControl(ctx, ControlRequest{
				Program: progTFA, MRID: mrid, Description: "UTIL-004 scoped control",
				StartOffset: 120, DurationS: 120, FixedPFInjectW: ptr(int64(95)),
			})
			params["mrid"] = mrid
			return err
		},
		Want: func(base ServerView) func(ServerView) bool {
			return func(v ServerView) bool { return len(v.ResponsesFor(mrid)) > 0 }
		},
		Cleanup: func(ctx context.Context, d *Driver) { _ = d.ClearControls(ctx, progTFA) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("aggregator DER retrieval (UTIL-004): published %s with the procedure's own "+
				"interval — start +2 min, duration 2 min — and waited %s; statuses received: %v",
				mrid, o.Waited.Round(rounding), o.Server.ResponseStatuses(mrid))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critResource("DERControlList", "the DUT fetched the DERControlList carrying the new "+
					"DERControl", nil),
				critDERControlCarriesMode("opModFixedPFInjectW",
					"the DUT fetched the new DERControl carrying the procedure's example control"),
				critEventLifecycle(mrid, "scoped DERControl", 240),
				{
					Claim: "a DERControl published at a topology node produces Responses from exactly the " +
						"EndDevices in that node's scope: SPA1 → EDA1; FDA → EDA1 and EDA2; SY → all four",
					How: "the LFDIs of the Response POSTs for each of the three published controls, compared " +
						"against the topology scope of the node each was published at",
					Skip: "this is the row's whole subject and it needs both the Figure-15 fleet and a " +
						"simulator that can publish a DERControl at a NAMED topology node. gridsim publishes " +
						"onto three flat DERPrograms and serves one EndDevice. " + fleetGap,
				},
				{
					Claim: "the server pushes a Notification of the changed DERControlList and the DUT GETs " +
						"the list and the new DERControl in response to it",
					How:  "the Notification POST and the GETs that follow it",
					Skip: notificationGap,
				},
			}
		},
	})
}

// ── scenario table ───────────────────────────────────────────────────────────

// aggScenarios is AGG-002..AGG-012, transcribed from the CTP's Setup sections
// with the errata applied. The timings are the document's own, in seconds.
//
// The two-family split is the thing to read carefully. AGG-007 and AGG-008
// schedule both events ahead of time and expect status 14; AGG-009 creates the
// higher-priority event only AFTER the lower-priority one has started and
// expects status 7. AGG-010/011/012 mirror all three with INDEPENDENT modes and
// expect no supersession Response at all.
func aggScenarios() map[string]aggScenario {
	const (
		superseded14 = "Event Superseded from another program"
		superseded7  = "Event Superseded"
	)
	why14 := "Annex A Errata I corrects this row from the printed status 7 to status 14: the superseded " +
		"control belongs to a DIFFERENT DERProgram and both events were scheduled ahead of time, so " +
		"supersession is known before either starts. A harness asserting 7 here would FAIL a conformant " +
		"aggregator"
	why7 := "This row keeps status 7 and carries NO erratum, and that is the contrast the errata draw: the " +
		"SY event had already STARTED when the higher-priority TFA event was discovered, so it is an " +
		"ordinary supersession rather than AGG-007/AGG-008's before-the-start, across-programs case"

	return map[string]aggScenario{
		"AGG-002": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 0 DERControls: EDA1/EDA2 follow the TFA default " +
				"(primacy 5) and EDB1/EDB2 fall back to the SY default (primacy 10)",
			Defaults: []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"the TFA DefaultDERControl is applied", "EDA1 and EDA2"},
				{"the SY DefaultDERControl is applied", "EDB1 and EDB2"},
			},
		},
		"AGG-003": {
			Summary: "1 DERProgram (TFA), 0 DefaultDERControls, 1 DERControl at +2 min for 1 min",
			Controls: []aggControl{
				{MRID: "CERT-AGG003", Program: progTFA, StartOffset: 120, DurationS: 60},
			},
			Lifecycles: []aggLifecycle{{"CERT-AGG003", "TFA", 180}},
			FanOut: []aggFanOut{
				{"Response status 1 → 2 → 3 is POSTed for the TFA event", "EDA1 and EDA2"},
				{"NO Response is POSTed for the TFA event — the untagged negative pass criterion",
					"EDB1 and EDB2"},
			},
		},
		"AGG-004": {
			Summary: "1 DERProgram (TFA), 1 DefaultDERControl, 1 DERControl at +2 min for 1 min: " +
				"default → event → default",
			Controls: []aggControl{
				{MRID: "CERT-AGG004", Program: progTFA, StartOffset: 120, DurationS: 60},
			},
			Lifecycles: []aggLifecycle{{"CERT-AGG004", "TFA", 180}},
			Defaults:   []string{"TFA (before the event)", "TFA (after the event)"},
			FanOut: []aggFanOut{
				{"Response status 1 → 2 → 3 is POSTed for the TFA event", "EDA1 and EDA2"},
				{"NO Response is POSTed for the TFA event", "EDB1 and EDB2"},
			},
		},
		"AGG-005": {
			Summary: "1 DERProgram (TFA), 1 DefaultDERControl, 2 non-overlapping similar DERControls at " +
				"+2 min and +4 min, each 1 min, with the default restored between them",
			Controls: []aggControl{
				{MRID: "CERT-AGG005A", Program: progTFA, StartOffset: 120, DurationS: 60},
				{MRID: "CERT-AGG005B", Program: progTFA, StartOffset: 240, DurationS: 60},
			},
			Lifecycles: []aggLifecycle{
				{"CERT-AGG005A", "first TFA", 180},
				{"CERT-AGG005B", "second TFA", 300},
			},
			Defaults: []string{"TFA (between and after the two events)"},
			FanOut: []aggFanOut{
				{"both events' Response lifecycles are POSTed — 2 events × 2 EndDevices = 12 Response POSTs",
					"EDA1 and EDA2"},
				{"NO Response is POSTed for either TFA event", "EDB1 and EDB2"},
			},
		},
		"AGG-006": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 non-overlapping similar DERControls: TFA at " +
				"+2 min for 1 min and SY at +4 min for 1 min (Annex A seq 26's corrected setup)",
			Controls: []aggControl{
				{MRID: "CERT-AGG006TFA", Program: progTFA, StartOffset: 120, DurationS: 60},
				{MRID: "CERT-AGG006SY", Program: progSY, StartOffset: 240, DurationS: 60},
			},
			Lifecycles: []aggLifecycle{
				{"CERT-AGG006TFA", "TFA", 180},
				{"CERT-AGG006SY", "SY", 300},
			},
			Defaults: []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"Response status 1 → 2 → 3 is POSTed for the TFA event", "EDA1 and EDA2"},
				{"Response status 1 → 2 → 3 is POSTed for the SY event (Annex A seq 26 adds EDB1/EDB2 to " +
					"procedure steps 11-15 and pass/fail bullets 8, 10, 11 and 12)", "EDB1 and EDB2"},
			},
		},
		"AGG-007": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping similar DERControls: SY at +2 min " +
				"for 2 min, TFA at +3 min for 1 min, both scheduled ahead of time so the TFA control " +
				"supersedes the SY control BEFORE either starts",
			Controls: []aggControl{
				{MRID: "CERT-AGG007SY", Program: progSY, StartOffset: 120, DurationS: 120,
					Superseded: true, CreationAge: -60},
				{MRID: "CERT-AGG007TFA", Program: progTFA, StartOffset: 180, DurationS: 60},
			},
			Lifecycles:       []aggLifecycle{{"CERT-AGG007TFA", "TFA", 240}},
			Superseded:       "CERT-AGG007SY",
			SupersedeStatus:  14,
			SupersedeMeaning: superseded14,
			SupersedeWhy:     why14,
			Defaults:         []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"Response status 14 is POSTed for the SY event and the TFA event is executed instead",
					"EDA1 and EDA2"},
				{"the SY DERControl is executed normally — they are outside the TFA program, so nothing " +
					"supersedes it for them", "EDB1 and EDB2"},
			},
		},
		"AGG-008": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping similar DERControls: TFA at " +
				"+2 min for 2 min, SY at +3 min for 2 min — the mirror of AGG-007, higher priority first",
			Controls: []aggControl{
				{MRID: "CERT-AGG008SY", Program: progSY, StartOffset: 180, DurationS: 120,
					Superseded: true, CreationAge: -60},
				{MRID: "CERT-AGG008TFA", Program: progTFA, StartOffset: 120, DurationS: 120},
			},
			Lifecycles:       []aggLifecycle{{"CERT-AGG008TFA", "TFA", 240}},
			Superseded:       "CERT-AGG008SY",
			SupersedeStatus:  14,
			SupersedeMeaning: superseded14,
			SupersedeWhy:     why14,
			Defaults:         []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"Response status 14 is POSTed for the SY event, and after the TFA event completes they " +
					"return to the TFA DefaultDERControl rather than falling through to the still-running " +
					"SY control", "EDA1 and EDA2"},
				{"the SY DERControl is executed normally", "EDB1 and EDB2"},
			},
		},
		"AGG-009": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping similar DERControls: SY at +1 min " +
				"for 4 min, and the TFA control at +2 min for 2 min created only AFTER the SY event has " +
				"started — so the supersession status is 7, not 14",
			Controls: []aggControl{
				{MRID: "CERT-AGG009SY", Program: progSY, StartOffset: 60, DurationS: 240, Superseded: true},
				{MRID: "CERT-AGG009TFA", Program: progTFA, StartOffset: 120, DurationS: 120, LateAfterS: 75},
			},
			Lifecycles:       []aggLifecycle{{"CERT-AGG009TFA", "TFA", 240}},
			Superseded:       "CERT-AGG009SY",
			SupersedeStatus:  7,
			SupersedeMeaning: superseded7,
			SupersedeWhy:     why7,
			Defaults:         []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"the SY control runs from +1 to +2 min, then Response status 7 is POSTed for it and the " +
					"TFA control runs", "EDA1 and EDA2"},
				{"the SY control runs for its full 4 min", "EDB1 and EDB2"},
			},
		},
		"AGG-010": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping INDEPENDENT DERControls: SY " +
				"opModFixedPFInjectW at +2 min for 2 min and TFA opModFixedW at +3 min for 1 min — " +
				"different modes, so both execute and neither supersedes",
			Controls: []aggControl{
				{MRID: "CERT-AGG010SY", Program: progSY, StartOffset: 120, DurationS: 120,
					Mode: modeFixedPFInjectW},
				{MRID: "CERT-AGG010TFA", Program: progTFA, StartOffset: 180, DurationS: 60,
					Mode: modeFixedW},
			},
			Lifecycles: []aggLifecycle{
				{"CERT-AGG010SY", "SY", 240},
				{"CERT-AGG010TFA", "TFA", 240},
			},
			Independent: []string{"CERT-AGG010SY", "CERT-AGG010TFA"},
			Defaults:    []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"both independent controls are applied concurrently during the overlap window",
					"EDA1 and EDA2"},
				{"only the SY control is applied", "EDB1 and EDB2"},
			},
		},
		"AGG-011": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping INDEPENDENT DERControls: TFA " +
				"opModFixedW at +2 min for 2 min and SY opModFixedPFInjectW at +3 min for 2 min",
			Controls: []aggControl{
				{MRID: "CERT-AGG011TFA", Program: progTFA, StartOffset: 120, DurationS: 120,
					Mode: modeFixedW},
				{MRID: "CERT-AGG011SY", Program: progSY, StartOffset: 180, DurationS: 120,
					Mode: modeFixedPFInjectW},
			},
			Lifecycles: []aggLifecycle{
				{"CERT-AGG011TFA", "TFA", 240},
				{"CERT-AGG011SY", "SY", 300},
			},
			Independent: []string{"CERT-AGG011TFA", "CERT-AGG011SY"},
			Defaults:    []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"both independent controls are applied concurrently in the +3..+4 min overlap",
					"EDA1 and EDA2"},
				{"only the SY control is applied", "EDB1 and EDB2"},
			},
		},
		"AGG-012": {
			Summary: "2 DERPrograms, 2 DefaultDERControls, 2 overlapping INDEPENDENT DERControls: SY " +
				"opModFixedPFInjectW at +1 min for 4 min, and TFA opModFixedW at +2 min for 2 min created " +
				"only AFTER the SY event has started — the independent-control counterpart of AGG-009, " +
				"where the discriminator is that NO status 7 appears despite the late higher-priority event",
			Controls: []aggControl{
				{MRID: "CERT-AGG012SY", Program: progSY, StartOffset: 60, DurationS: 240,
					Mode: modeFixedPFInjectW},
				{MRID: "CERT-AGG012TFA", Program: progTFA, StartOffset: 120, DurationS: 120,
					Mode: modeFixedW, LateAfterS: 75},
			},
			Lifecycles: []aggLifecycle{
				{"CERT-AGG012SY", "SY", 300},
				{"CERT-AGG012TFA", "TFA", 240},
			},
			Independent: []string{"CERT-AGG012SY", "CERT-AGG012TFA"},
			Defaults:    []string{"TFA", "SY"},
			FanOut: []aggFanOut{
				{"the SY control runs for its full 4 min while the TFA control additionally runs from " +
					"+2 to +4 min", "EDA1 and EDA2"},
				{"only the SY control is applied", "EDB1 and EDB2"},
			},
		},
	}
}
