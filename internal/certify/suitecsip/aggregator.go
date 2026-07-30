package suitecsip

// aggregator.go implements the twenty-two rows the DER AGGREGATOR CLIENT profile
// requires and the DER Client profile does not: AGG-001..012, CORE-018,
// CORE-019, ERR-002, MAINT-001/003/004/005 and UTIL-002/003/004.
//
// Owner decision 2026-07-28 (docs/PROFILE_SCOPE_2026-07-28_der-client-gfems.md,
// superseding an aggregator scoping taken earlier the same day): the DUT is
// certified against §4's DER CLIENT column in the GFEMS posture, so none of
// these twenty-two is required of it. They run anyway, as INFORMATIVE evidence
// — the criteria are real evaluators, the bench builds the fixtures they were
// written against, and a check that runs is worth more than a check that was
// deleted. No verdict in this file gates conformance, including and especially
// the negative ones, which is most of them.
//
// # What "run" means here, precisely
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
//
// The change under test — printed step 3, "Create a new EndDevice instance for
// EDA1X and assign it to node SPA1" — is driven by the closest lever gridsim
// has, and the substitution is stated rather than glossed: it REBINDS EDA1 to
// this aggregator, which rebuilds the EndDeviceList and pushes the Notification
// for the changed list. What that exercises is the whole observable of the row —
// the server changes the aggregator's EndDeviceList and the client answers the
// Notification. What it does NOT exercise is a device that was not in the
// fixture beforehand, because gridsim's fleet is the figure's four and has no
// create-EndDevice route.
func aggSubscription(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			agg := aggregatorLFDI(d.Fleet(ctx))
			if agg == "" {
				return fmt.Errorf("no managed EndDevice reports an aggregator binding, so there is no " +
					"EndDeviceList membership to change (is gridsim serving the fleet? -fleet 4)")
			}
			params[changedDevice] = "EDA1"
			return d.RebindDevice(ctx, "EDA1", agg)
		},
		Cleanup: func(ctx context.Context, d *Driver) { restoreFleetBinding(ctx, d) },
		Notes: func(o *Observation) string {
			return "aggregator subscription (AGG-001), read through Annex A seq 1: the client answers the " +
				"EndDeviceList Notification 201 Created, and the follow-up GET of the new EDA1X EndDevice is a " +
				"[CT] test-client step, not a demand on the DUT. The membership change is driven by rebinding " +
				"EDA1 rather than by creating EDA1X, which gridsim's fleet has no route for"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critSubscriptionPosted("EndDeviceList",
					"the aggregator EndDevice's SubscriptionListLink"),
				critNotificationPushed(o, "EndDeviceList",
					"AGG-001's printed step 4: the server notifies the client because there is a change "+
						"(addition) to the EndDeviceList"),
				critNotificationAnswered(o, []int{201},
					"AGG-001's printed step 5, as amended by Annex A seq 1, states 201 Created"),
				critNotifiedHrefRefetched(o),
				critPerDeviceFanOut("the newly created EDA1X EndDevice instance is reachable and carries the "+
					"links the setup requires", "the aggregator's managed fleet",
					"the fixture gridsim builds is CTP Figure 15 exactly — EDA1, EDA2, EDB1, EDB2 — and its "+
						"admin API can rebind or detach one of those but cannot CREATE a fifth. EDA1X is an "+
						"addition, so what this check drove is a membership change to an existing device and "+
						"the reachability of a device that was never in the fixture is not evidence this run "+
						"produced. Closing it needs a create-EndDevice route in sim/gridsim/fleet.go"),
			}
		},
	})
}

// changedDevice is the params key naming the managed EndDevice a check rebound,
// so cleanup restores exactly what it changed rather than rebuilding the fleet.
const changedDevice = "csip.changed_device"

// aggregatorLFDI reads the aggregator every managed device is bound to. It is
// taken from the fleet rather than configured, for the same reason the fleet's
// own LFDIs are: gridsim binds them to whatever certificate handshaked, so the
// bench needs no out-of-band agreement about which aggregator this is.
func aggregatorLFDI(fleet []AdminFleetDevice) string {
	for _, d := range fleet {
		if d.ManagedBy != "" {
			return d.ManagedBy
		}
	}
	return ""
}

// restoreFleetBinding puts a rebound device back under the aggregator that owns
// the rest of the fleet. It runs unconditionally from Cleanup: a device left
// detached would vanish from the EndDeviceList of every test case that follows,
// and those cases would report the missing device as a DUT finding.
func restoreFleetBinding(ctx context.Context, d *Driver) {
	fleet := d.Fleet(ctx)
	agg := aggregatorLFDI(fleet)
	if agg == "" {
		return
	}
	for _, dev := range fleet {
		if dev.ManagedBy == "" {
			_ = d.RebindDevice(ctx, dev.Name, agg)
		}
	}
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
//
// It carries the artefact as well as the words because the artefact is what
// decides it. A bullet naming Response statuses for named devices is checkable
// against <endDeviceLFDI>; a bullet about a setpoint or an internal belief is
// not, and Unobservable is where that is said in the bullet's own terms rather
// than by a shared string that would be wrong for it.
type aggFanOut struct {
	// What is the pass criterion in the procedure's own words.
	What string
	// Devices is how the procedure names the set ("EDA1 and EDA2"); Names is
	// the same set as the CTP identifiers the fleet is keyed by.
	Devices string
	Names   []string

	// MRID is the event the Responses are about, and Statuses the ones each
	// named device owes for it.
	MRID     string
	Statuses []int
	// Forbidden are statuses no named device may report for the event. It is
	// how the rows state the NEGATIVE half of a precedence claim without an
	// out-of-band setpoint read: AGG-007's EDB1/EDB2 are outside the TFA
	// program, so the SY control "is executed normally" for them — which on the
	// wire means their Responses are 1/2/3 and never 14.
	Forbidden []int
	// Absent inverts the claim into the untagged negative bullet — AGG-003's
	// "Client fails if EDB1 and/or EDB2 POSTs any responses to the TFA event".
	Absent bool

	// Unobservable, when non-empty, is why this bullet has no wire artefact
	// even with the fixture served. It is the declared SKIP's reason and it
	// must be about THIS bullet: the fleet is no longer what is missing.
	Unobservable string
}

// The device sets the CTP's bullets are stated over. EDA1/EDA2 hang off SPA1
// and SPA2 and inherit TFA; EDB1/EDB2 hang off SPB1/SPB2 and do not.
var (
	edaPair = []string{"EDA1", "EDA2"}
	edbPair = []string{"EDB1", "EDB2"}
)

// noWireArtefact is the reason for a bullet whose subject is the DUT's own
// belief rather than a message. It is deliberately NOT fleetGap: the fleet is
// served, and blaming it would send a reader to fix something that is not broken.
const noWireArtefact = "this bullet's subject is the client's INTERNAL STATE, not a message. IEEE 2030.5 " +
	"defines no artefact for it, so no simulator lever can produce one — the absence of further traffic for " +
	"a device is consistent with the DUT having dropped it and equally consistent with the DUT having " +
	"nothing to say about it in this window, and reporting the first would be inventing evidence"

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
	// Defaults are the DefaultDERControl bullets. Their ACTIVATION is what the
	// document itself declares unobservable; the per-device walk that reaches
	// them is not, so an entry that names devices produces both criteria.
	Defaults []aggDefault
	// FanOut are the per-EndDevice pass criteria the one-EndDevice bench cannot
	// reach.
	FanOut []aggFanOut
}

type aggLifecycle struct {
	MRID, Label string
	SpanS       int
}

// aggDefault is one DefaultDERControl bullet: whose default, and — when the row
// states it per EndDevice — which devices.
type aggDefault struct {
	// Which is the DERProgram whose default the bullet is about, in the
	// procedure's own naming ("TFA", "TFA (before the event)").
	Which string
	// Devices and Names are set only where the procedure states the bullet per
	// EndDevice. Empty leaves the row with the activation criterion alone,
	// which is what the setup-level entries are.
	Devices string
	Names   []string
}

// aggWant is the wait predicate builder for an aggregator event row: wait for
// the first lifecycle's Response to arrive. A scenario that names NO lifecycle
// (AGG-002's shape) has nothing specific to wait on, so it yields a nil
// predicate — the signal to specWant/check.go that the check should wait for a
// discovery walk (AwaitWalk) instead. That nil is exactly what panicked AGG-002
// in runs/shakedown-20260729T003843 when it reached Await unrouted; keeping the
// builder named lets the test pin the zero-lifecycle case directly.
func aggWant(sc aggScenario) func(base ServerView) func(ServerView) bool {
	return func(base ServerView) func(ServerView) bool {
		if len(sc.Lifecycles) == 0 {
			return nil
		}
		first := sc.Lifecycles[0].MRID
		// WantNewResponse, not a bare len(v.ResponsesFor(first))>0 — see its
		// doc (audit 2026-07-30, CORE-022/CORE-023's identical bug): an
		// AGG-0xx scenario's lifecycle mRID is just as hardcoded as those
		// two, and a focused re-run of one row must not read "satisfied"
		// from a Response an EARLIER run against the same gridsim process
		// already earned for that mRID.
		return base.WantNewResponse(first)
	}
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
			Want: aggWant(sc),
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
		crits = append(crits, critDefaultControlOutOfBand(d.Which))
		if len(d.Names) > 0 {
			crits = append(crits, critDefaultControlFetched(o, d.Which, d.Devices, d.Names))
		}
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
		crits = append(crits, withDeviation(fanOutCriterion(o, f), o))
	}
	return crits
}

// fanOutCriterion picks the evaluator a per-device bullet's artefact supports.
//
// The dispatch is the whole point of aggFanOut carrying more than prose: three
// kinds of bullet appear in these rows and conflating them is how a harness ends
// up either failing a conformant DUT for a fixture it was not given, or passing
// a non-conformant one on a claim nobody checked.
func fanOutCriterion(o *Observation, f aggFanOut) criterion {
	switch {
	case f.Unobservable != "":
		return critPerDeviceFanOut(f.What, f.Devices, f.Unobservable)
	case f.Absent:
		return critNoResponseFanOut(o, f)
	default:
		return critResponseFanOut(o, f)
	}
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
		Change:   touchSubscribedResources,
		Criteria: func(o *Observation) []criterion { return core018Criteria(o) },
	})
}

// core018Criteria is CORE-018's criteria list, named so errata_test.go can pin
// the seq-44 tightening against the code that implements it rather than only
// against the catalog record of it.
func core018Criteria(o *Observation) []criterion {
	return []criterion{
		critDiscoveryRoot(),
		critSubscriptionAdvertised(),
		critFSAList(0),
		critSubscriptionPosted("FunctionSetAssignmentsList", "the DUT's EndDevice SubscriptionListLink"),
		critNotificationPushed(o, "FunctionSetAssignments",
			"CORE-018's setup step 3 and procedure step 6: the server updates an attribute of the Client "+
				"FSAList and sends the notification carrying the updated payload"),
		critNotificationAnswered(o, []int{201},
			"Annex A seq 44 removes the acceptance of 204 for CORE-018, so 201 Created is the only "+
				"conformant answer"),
		critNotifiedHrefRefetched(o),
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
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			// Steps 8 and 11 in order: change the subscribed resource, then
			// cancel the subscription with the status=1 Notification. Both need
			// the DUT to have subscribed already, which is why they are here
			// and not in Setup.
			if err := touchSubscribedResources(ctx, d, params); err != nil {
				return err
			}
			return cancelOneSubscription(ctx, d, params)
		},
		Criteria: func(o *Observation) []criterion { return core019Criteria(o) },
	})
}

// core019Criteria is CORE-019's criteria list. See core018Criteria.
func core019Criteria(o *Observation) []criterion {
	return []criterion{
		critDiscoveryRoot(),
		critSubscriptionAdvertised(),
		critSubscriptionPosted("EndDevice", "the DUT's EndDevice SubscriptionListLink"),
		critSubscriptionPosted("FunctionSetAssignmentsList", "the DUT's EndDevice SubscriptionListLink"),
		critNotificationAnswered(o, []int{201},
			"Annex A seq 44 removes the acceptance of 204 for CORE-019, so 201 Created is the only "+
				"conformant answer"),
		critOneNotificationPerChange(o),
		critNotificationCancelled(o, []int{201}),
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
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			if err := touchSubscribedResources(ctx, d, params); err != nil {
				return err
			}
			return cancelOneSubscription(ctx, d, params)
		},
		Criteria: func(o *Observation) []criterion { return err002Criteria(o) },
	})
}

// err002Criteria is ERR-002's criteria list. Two things about it are pinned by
// errata_test.go: it accepts BOTH 201 and 204 (seq 44's removal of the 204 is
// scoped to CORE-018/CORE-019), and it contains no criterion demanding a
// re-POSTed Subscription (seq 38 removes printed step 6).
func err002Criteria(o *Observation) []criterion {
	return []criterion{
		critDiscoveryRoot(),
		critSubscriptionAdvertised(),
		critSubscriptionPosted("FunctionSetAssignmentsList", "the DUT's EndDevice SubscriptionListLink"),
		{
			Claim: "the server's outstanding subscriptions survive a power reset and it pushes a " +
				"Notification for a post-reset change to the subscribed FunctionSetAssignmentsList",
			How: "a server restart followed by a Notification POST on the pre-existing subscription, " +
				"with no re-POST of the Subscription required of the DUT",
			Skip: "sim/gridsim holds its subscriptions in memory and its admin API has no power-reset " +
				"lever, so the PERSISTENCE half of this bullet cannot be exercised — restarting the " +
				"process loses them, which is the opposite of what the row requires. The change-and-notify " +
				"half IS driven and is asserted in the criteria below; what is missing is the reset " +
				"between them, and closing it needs subscription persistence in sim/gridsim/subscribe.go " +
				"plus a restart route",
		},
		critNotificationAnswered(o, []int{201, 204},
			"ERR-002's printed step 3 admits either; Annex A seq 44's removal of the 204 acceptance is "+
				"scoped to CORE-018 and CORE-019 and does NOT reach this row"),
		critNotifiedHrefRefetched(o),
		critNotificationCancelled(o, []int{201, 204}),
		{
			Claim: "on a Notification with status=1 (Subscription canceled) the DUT removes that " +
				"subscription from its own list of outstanding Subscriptions",
			How: "the absence of further client traffic on the cancelled subscription. Per Annex A " +
				"seq 38 the DUT is NOT required to re-POST the Subscription, and this criterion does " +
				"not look for one",
			Skip: "the subject of this bullet is the DUT's own list of outstanding Subscriptions, which " +
				"is internal state. The server-side artefact — the cancellation Notification and the " +
				"DUT's answer to it — IS asserted above; what no wire shows is what the client then " +
				"believes, and absence of traffic does not distinguish a client that forgot the " +
				"subscription from one that simply had nothing to say",
		},
		{
			Claim: "on an INVALID Notification — EndDevice instance information delivered against a " +
				"FunctionSetAssignmentsList subscription — the DUT responds HTTP 400",
			How: "the status line of the DUT's response to the malformed Notification POST",
			Skip: "sim/gridsim now ORIGINATES Notifications, but it builds each body from the resource " +
				"the subscription actually names, and its malform injection (POST /admin/malform) " +
				"rewrites a resource the DUT GETs rather than one it is pushed. Deliberately sending the " +
				"WRONG resource type on a subscription is a lever sim/gridsim/subscribe.go does not " +
				"have, and this criterion will not manufacture a verdict without it",
		},
	}
}

// touchSubscribedResources makes the change every subscription row's procedure
// calls for: it mutates something the DUT has actually subscribed to, so a
// Notification is owed.
//
// It reads the subscriptions back rather than assuming which resource to touch,
// because which one the DUT chose is a fact about the DUT. When the DUT
// subscribed to an EndDeviceList it rebinds a fleet device; otherwise it
// re-posts the device's own registration pIN, which is a change to the
// EndDevice sub-tree and notifies /edev and that device's href.
//
// A run in which the DUT has subscribed to nothing returns an error naming that,
// and the criteria then report "no Notification was owed" rather than "the DUT
// ignored one".
func touchSubscribedResources(ctx context.Context, d *Driver, params map[string]string) error {
	subs := d.Subscriptions(ctx)
	if len(subs) == 0 {
		return fmt.Errorf("the DUT holds no Subscription on this server, so there is nothing whose change " +
			"would be notified. Whether it OUGHT to have subscribed is asserted separately")
	}
	fleet := d.Fleet(ctx)
	agg := aggregatorLFDI(fleet)
	if agg == "" || len(fleet) == 0 {
		return fmt.Errorf("gridsim is serving no managed EndDevice, so this check has no resource it can " +
			"change without disturbing the DUT's own tree (is the fleet on? -fleet 4)")
	}
	// Rebinding a managed device to the aggregator it is ALREADY bound to is a
	// no-op for the fixture and a real change for the EndDeviceList: gridsim
	// rebuilds it and notifies /edev and the device href. That is the smallest
	// mutation that produces the row's Notification without leaving the shared
	// bench in a different state than it was found in.
	params[changedDevice] = fleet[0].Name
	return d.RebindDevice(ctx, fleet[0].Name, agg)
}

// cancelOneSubscription pulls the status=1 lever CORE-019 step 11 and ERR-002
// step 5 are about, on the LAST subscription the DUT posted.
//
// The last rather than the first, deliberately: the rows cancel the subordinate
// (FSAList) subscription and keep the EndDevice one, and gridsim hands them back
// in creation order.
func cancelOneSubscription(ctx context.Context, d *Driver, params map[string]string) error {
	subs := d.Subscriptions(ctx)
	if len(subs) == 0 {
		return fmt.Errorf("the DUT holds no Subscription, so there is none to cancel")
	}
	target := subs[len(subs)-1]
	params[cancelledSub] = target.Href + " (" + target.SubscribedResource + ")"
	return d.CancelSubscription(ctx, target.Href)
}

// cancelledSub records which subscription a check cancelled, so the bundle says
// what the status=1 Notification was about.
const cancelledSub = "csip.cancelled_subscription"

// ── MAINT-001 / 003 / 004 / 005 ──────────────────────────────────────────────

// maintOOBInverter implements MAINT-001 — Inverter Maintenance (Out-Of-Band).
//
// This row now has its lever, and it is the one the procedure describes. Step 3
// is an OUT-OF-BAND agreement that a device is no longer managed, and step 4 is
// the server acting on it — which is exactly POST /admin/fleet {managed_by:
// "-"}: gridsim drops the device from this aggregator's EndDeviceList and
// pushes the Notification for the changed list. Cleanup rebinds it
// unconditionally, because a device left detached would be missing from every
// later test case's EndDeviceList and would be reported there as a DUT finding.
func maintOOBInverter(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			fleet := d.Fleet(ctx)
			if len(fleet) == 0 {
				return fmt.Errorf("gridsim is serving no managed EndDevice, so there is none to remove " +
					"from the aggregator's list (is the fleet on? -fleet 4)")
			}
			// The LAST device, so a run that is interrupted before cleanup
			// leaves EDA1 — the device every other aggregator row names first —
			// where the next case expects it.
			dev := fleet[len(fleet)-1]
			params[changedDevice] = dev.Name
			params[deletedHref] = dev.Href
			return d.RebindDevice(ctx, dev.Name, "-")
		},
		Cleanup: func(ctx context.Context, d *Driver) { restoreFleetBinding(ctx, d) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("out-of-band inverter maintenance (MAINT-001): the aggregator's fleet shrinks by "+
				"agreement off-protocol and the server drops %s (%s) from its EndDeviceList. No client-initiated "+
				"DELETE belongs on the wire for this row — that is MAINT-002, which §4 requires of nobody",
				o.Param(changedDevice), o.Param(deletedHref))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critSubscriptionPosted("EndDeviceList", "the aggregator EndDevice's SubscriptionListLink"),
				critNotificationPushed(o, "EndDeviceList",
					"MAINT-001's procedure step 4: the server deletes the EndDevice instance from the "+
						"aggregator EndDeviceList and notifies the EndDeviceList subscriptions"),
				critNotificationAnswered(o, []int{201},
					"MAINT-001's first pass criterion requires an HTTP 201 Created for the subscription and "+
						"the notifications on it"),
				critNotificationLimitHonoured(o),
				{
					Claim: "a GET of the deleted EndDevice href returns HTTP 404 Not Found",
					How:   "the status line of a [CT] test-client GET of the deleted EndDevice's href",
					Skip: "the removal this row drives is a MEMBERSHIP change — gridsim drops the device from " +
						"this aggregator's EndDeviceList — and the resource itself remains served, so a GET " +
						"of its href answers 200 rather than 404. That is a real difference from the printed " +
						"procedure and it is reported rather than papered over: gridsim's fleet has no " +
						"delete-EndDevice route, and asserting a 404 against a bench that cannot produce one " +
						"would fail a conformant client on the harness's shortcoming",
				},
				critPerDeviceFanOut("the client's internal state stops managing the deleted device",
					"the aggregator's managed fleet", noWireArtefact),
			}
		},
	})
}

// deletedHref records the EndDevice href a check removed from the aggregator's
// list, so the notes name the resource the row is about.
const deletedHref = "csip.deleted_href"

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
				critPerDeviceResource(o,
					"the aggregator GETs that device's FunctionSetAssignments and the DERProgramList beneath "+
						"it — the row's first two pass criteria, which are stated for every one of the four",
					"EDA1, EDA2, EDB1 and EDB2", managedDevices, "GET", []string{"/fsa"}),
				critDefaultControlFetched(o, "TFA", "EDA1 and EDA2", edaPair),
				critDefaultControlFetched(o, "TFB", "EDB1 and EDB2", edbPair),
				{
					Claim: "the server re-parents EDB1 from SPB1 to SPA1 and pushes a Notification that its " +
						"FunctionSetAssignmentsList changed",
					How: "the FunctionSetAssignmentsList Notification POST following the topology move",
					Skip: "gridsim serves the whole Figure-15 topology now — SPA1/SPA2/SPB1/SPB2, FDA/FDB, " +
						"TFA/TFB, SGA/SGB and SY — and every managed device carries the DERProgram chain of " +
						"its parent nodes. What its admin API has no route for is MOVING a device between " +
						"nodes: POST /admin/fleet adjusts a pIN and an aggregator binding, not an assignment. " +
						"The regrouping this row is entirely about therefore cannot be performed, and neither " +
						"the Notification it would cause nor the client's reaction to it is evidence this run " +
						"produced. Closing it needs a node-reassignment route in sim/gridsim/fleet.go",
				},
				{
					Claim: "on that Notification the aggregator GETs the new FunctionSetAssignmentsList and " +
						"the DERProgramList it now belongs to",
					How: "the GETs following the Notification, compared against the hrefs it carried",
					Skip: "the re-parenting that would cause this Notification could not be performed (see " +
						"above), so a GET of the 'new' FunctionSetAssignmentsList is a GET of the same one " +
						"the device already had. Reporting the DUT's ordinary walk as a reaction to a " +
						"topology change it was never told about would be inventing the finding",
				},
				critPerDeviceFanOut("the aggregator cancels its subscription to the old "+
					"FunctionSetAssignmentsList and subscribes to the new one (both 'If needed', so neither is "+
					"a gate)", "EDB1",
					"the procedure marks both steps conditional ('If needed'), so neither is a gate on any "+
						"verdict, and the topology move that would make them needed could not be performed "+
						"(see the re-parenting criterion above)"),
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
		// The control is added in Change, not Setup, and that is the whole point
		// of the row: procedure step 3 ADDS a DERControl to a list the client is
		// already subscribed to. Publishing it before the DUT has subscribed
		// would match no subscription, push no Notification, and leave this row
		// reporting a bench that works as a server that never notified.
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The document's own numbers: +15 min, 5 min, no randomization.
			_, err := d.PostControl(ctx, ControlRequest{
				Program: progTFA, MRID: mrid, Description: "MAINT-004 added control",
				StartOffset: 900, DurationS: 300, MaxLimW: ptr(int64(4000)),
			})
			params["mrid"] = mrid
			return err
		},
		// A second FULL poll cycle after the change: the DUT has to FETCH the
		// added control, and a subscribing client is still entitled to take its
		// poll interval over it. The short settle would measure the harness.
		ChangeWait: changeWaitFullCycle,
		Cleanup:    func(ctx context.Context, d *Driver) { _ = d.ClearControls(ctx, progTFA) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("maintenance of controls (MAINT-004): published %s on the TFA DERProgram AFTER "+
				"the client's subscription window, with the procedure's own interval — start +15 min, duration "+
				"5 min, no randomization — and waited %s in all for the DUT to be notified of it and acquire it",
				mrid, o.Waited.Round(rounding))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critAggregatorFleet(),
				critSubscriptionPosted("DERControlList", "each EndDevice FunctionSetAssignments"),
				critNotificationPushed(o, "DERControlList",
					"MAINT-004's procedure step 3: the server adds the DERControl to the TFA DERProgram's "+
						"DERControlList and sends a notification message for the affected list"),
				critNotificationAnswered(o, []int{201, 204},
					"MAINT-004 states no status of its own for the Notification answer, so both of IEEE "+
						"2030.5's are accepted; Annex A seq 44's removal of the 204 is scoped to CORE-018 "+
						"and CORE-019 and does not reach this row"),
				critNotifiedHrefRefetched(o),
				critNewControlAcquired(mrid, 900, 300),
				critResponseFanOut(o, aggFanOut{
					What: "the Event Processing rules of IEEE 2030.5 §12.1.3 are applied to the newly added " +
						"DERControl and a Response POSTed for it — the procedure's own bullet ends 'if " +
						"required by the Server', so a window with no Response at all is reported as " +
						"unmeasured rather than as a fan-out failure",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: mrid, Statuses: []int{1},
				}),
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
				critPerDeviceResource(o,
					"the aggregator GETs that device's FunctionSetAssignments and the DERProgramList whose "+
						"primacy ordering this row is about",
					"EDA1, EDA2, EDB1 and EDB2", managedDevices, "GET", []string{"/fsa"}),
				{
					Claim: "the server swaps the primacy values of the TFA/TFB and SGA/SGB DERPrograms and " +
						"pushes Notifications for the affected DERProgram and DERProgramList",
					How: "the DERProgram/DERProgramList Notification POSTs following the primacy swap",
					Skip: "gridsim serves the Figure-15 node programs with the primacy ladder MAINT-005's own " +
						"setup step 5 states — TFA/TFB at 1 and SGA/SGB at 2 — but its admin API has no lever " +
						"to CHANGE a primacy once built, so the swap this row is entirely about cannot be " +
						"performed and neither the Notification it would cause nor the client's " +
						"re-prioritisation is evidence this run produced. Closing it needs a primacy route in " +
						"sim/gridsim/fleet.go",
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
				critPerDeviceResource(o,
					"the aggregator follows that EndDevice's DERListLink and PUTs its DERCapability, "+
						"DERSettings, DERStatus or DERAvailability — Annex A seq 3 corrects the printed step, "+
						"which PUT to the DERListLink itself, and a PUT to any one of the four field resources "+
						"satisfies the procedure's own 'or'",
					"EDA1, EDA2, EDB1 and EDB2", managedDevices, "PUT", []string{"/der/"}),
				critPerDeviceResource(o,
					"the aggregator GETs that EndDevice's DERList before PUTting to it, which is how it finds "+
						"the four field hrefs at all",
					"EDA1, EDA2, EDB1 and EDB2", managedDevices, "GET", []string{"/der"}),
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
				critPerDeviceResource(o,
					"the aggregator finds that EndDevice's FunctionSetAssignmentsListLink and GETs all the "+
						"FunctionSetAssignments — the row's first pass criterion, stated for each "+
						"non-aggregator EndDevice",
					"EDA1, EDA2, EDB1 and EDB2", managedDevices, "GET", []string{"/fsa"}),
				critPerDeviceResource(o,
					"the aggregator GETs all DERPrograms from the DERProgramListLink in that EndDevice's "+
						"FunctionSetAssignments — the row's second pass criterion",
					"EDA1, EDA2, EDB1 and EDB2", managedDevices, "GET", []string{"/fsa/0/derp"}),
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
			// WantNewResponse, not a bare len(v.ResponsesFor(mrid))>0 — see
			// its doc (audit 2026-07-30, CORE-022/CORE-023's identical bug):
			// this hardcoded mRID re-posted by a focused re-run of THIS same
			// case must not be satisfied by a Response an EARLIER run against
			// the same gridsim process already earned.
			return base.WantNewResponse(mrid)
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
					Skip: "this is the row's whole subject and half of what it needs now exists: gridsim " +
						"serves the Figure-15 fleet and gives every node its own DERProgram (SPA1, FDA, SY " +
						"and the rest, sim/gridsim/fleet.go). What is still missing is the other half — POST " +
						"/admin/control addresses a DERProgram by INDEX, so a control can be published onto " +
						"TFA and SY, which are aliases of programs 0 and 2, and onto no other node. Without " +
						"a control at SPA1 there is no scope ladder to observe, and the per-device Responses " +
						"the criteria above DO check would be answering a different question. Closing it " +
						"needs the admin control route to accept a node NAME",
				},
				critNotificationPushed(o, "DERControlList",
					"UTIL-004's procedure step 3: the server notifies the client of the change to the "+
						"node's DERControlList"),
				critNotifiedHrefRefetched(o),
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDB1 and EDB2", edbPair},
			},
		},
		"AGG-003": {
			Summary: "1 DERProgram (TFA), 0 DefaultDERControls, 1 DERControl at +2 min for 1 min",
			Controls: []aggControl{
				{MRID: "CERT-AGG003", Program: progTFA, StartOffset: 120, DurationS: 60},
			},
			Lifecycles: []aggLifecycle{{"CERT-AGG003", "TFA", 180}},
			FanOut: []aggFanOut{
				{What: "aggregator POSTs response with status 1 (Event Received), 2 (Event Started) at start " +
					"time and 3 (Event Completed) after the duration has elapsed, for the TFA event",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG003", Statuses: []int{1, 2, 3}},
				{What: "NO Response is POSTed for the TFA event — the row's untagged pass criterion, " +
					"\"Client fails if EDB1 and/or EDB2 POSTs any responses to the TFA event\"",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG003", Absent: true},
			},
		},
		"AGG-004": {
			Summary: "1 DERProgram (TFA), 1 DefaultDERControl, 1 DERControl at +2 min for 1 min: " +
				"default → event → default",
			Controls: []aggControl{
				{MRID: "CERT-AGG004", Program: progTFA, StartOffset: 120, DurationS: 60},
			},
			Lifecycles: []aggLifecycle{{"CERT-AGG004", "TFA", 180}},
			Defaults: []aggDefault{
				{"TFA (before the event)", "EDA1 and EDA2", edaPair},
				{"TFA (after the event)", "EDA1 and EDA2", edaPair},
			},
			FanOut: []aggFanOut{
				{What: "aggregator POSTs response with status 1 (Event Received), 2 (Event Started) and " +
					"3 (Event Completed) for the TFA event",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG004", Statuses: []int{1, 2, 3}},
				{What: "NO Response is POSTed for the TFA event",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG004", Absent: true},
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
			Defaults: []aggDefault{{"TFA (between and after the two events)", "EDA1 and EDA2", edaPair}},
			FanOut: []aggFanOut{
				{What: "the FIRST TFA event's full Response lifecycle is POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG005A", Statuses: []int{1, 2, 3}},
				{What: "the SECOND TFA event's full Response lifecycle is POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG005B", Statuses: []int{1, 2, 3}},
				{What: "NO Response is POSTed for the first TFA event",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG005A", Absent: true},
				{What: "NO Response is POSTed for the second TFA event",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG005B", Absent: true},
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDB1 and EDB2", edbPair},
			},
			FanOut: []aggFanOut{
				{What: "the TFA event's full Response lifecycle is POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG006TFA", Statuses: []int{1, 2, 3}},
				{What: "the SY event's full Response lifecycle is POSTed — Annex A seq 26 adds EDB1/EDB2 to " +
					"procedure steps 11-15 and to pass/fail bullets 8, 10, 11 and 12",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG006SY", Statuses: []int{1, 2, 3}},
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDB1 and EDB2", edbPair},
			},
			FanOut: []aggFanOut{
				{What: "aggregator POSTs response with status 1 (Event Received) for the SY event",
					Devices: "EDA1, EDA2, EDB1 and EDB2", Names: managedDevices,
					MRID: "CERT-AGG007SY", Statuses: []int{1}},
				{What: "aggregator POSTs response with status 14 for the SY event, which the TFA event " +
					"supersedes for them",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG007SY", Statuses: []int{14}},
				{What: "the SY DERControl is executed normally — they are outside the TFA program, so nothing " +
					"supersedes it for them, and their Responses are 2 (Started) and 3 (Completed) with no " +
					"supersession status at all",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG007SY",
					Statuses: []int{2, 3}, Forbidden: []int{7, 14}},
				{What: "the TFA event's full Response lifecycle is POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG007TFA", Statuses: []int{1, 2, 3}},
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDB1 and EDB2", edbPair},
			},
			FanOut: []aggFanOut{
				{What: "aggregator POSTs response with status 1 (Event Received) for the SY event",
					Devices: "EDA1, EDA2, EDB1 and EDB2", Names: managedDevices,
					MRID: "CERT-AGG008SY", Statuses: []int{1}},
				{What: "aggregator POSTs response with status 14 for the SY event",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG008SY", Statuses: []int{14}},
				{What: "the SY DERControl is executed normally, with no supersession status",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG008SY",
					Statuses: []int{2, 3}, Forbidden: []int{7, 14}},
				{What: "the TFA event's full Response lifecycle is POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG008TFA", Statuses: []int{1, 2, 3}},
				{What: "after the TFA event completes they return to the TFA DefaultDERControl rather than " +
					"falling through to the still-running SY control",
					Devices: "EDA1 and EDA2", Unobservable: "which control a device fell back to is a SETPOINT, " +
						"and the procedure states for every DefaultDERControl bullet that IEEE 2030.5 defines no " +
						"acknowledgment for activating one. What IS asserted, in the criteria above, is that the " +
						"status-14 Response for the SY event was POSTed — which is the wire evidence that the " +
						"device stopped treating it as its control"},
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDB1 and EDB2", edbPair},
			},
			FanOut: []aggFanOut{
				{What: "aggregator POSTs response with status 1 (Event Received) and 2 (Event Started) for " +
					"the SY event, which every device is in scope for",
					Devices: "EDA1, EDA2, EDB1 and EDB2", Names: managedDevices,
					MRID: "CERT-AGG009SY", Statuses: []int{1, 2}},
				{What: "the SY control runs from +1 to +2 min and is then superseded: status 7 is POSTed for it",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG009SY", Statuses: []int{7}},
				{What: "the SY control runs for its full 4 min — status 3 (Event Completed) is POSTed for it " +
					"and no supersession status ever is",
					Devices: "EDB1 and EDB2", Names: edbPair, MRID: "CERT-AGG009SY",
					Statuses: []int{3}, Forbidden: []int{7, 14}},
				{What: "the TFA event's full Response lifecycle is POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG009TFA", Statuses: []int{1, 2, 3}},
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDA1, EDA2, EDB1 and EDB2", managedDevices},
			},
			FanOut: []aggFanOut{
				{What: "the SY event's full Response lifecycle is POSTed — every device is in the SY " +
					"program's scope",
					Devices: "EDA1, EDA2, EDB1 and EDB2", Names: managedDevices,
					MRID: "CERT-AGG010SY", Statuses: []int{1, 2, 3}, Forbidden: []int{7, 14}},
				{What: "the TFA event's full Response lifecycle is POSTed CONCURRENTLY with the SY event, " +
					"because the two carry independent control modes",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG010TFA",
					Statuses: []int{1, 2, 3}, Forbidden: []int{7, 14}},
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDA1, EDA2, EDB1 and EDB2", managedDevices},
			},
			FanOut: []aggFanOut{
				{What: "the TFA event's full Response lifecycle is POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG011TFA",
					Statuses: []int{1, 2, 3}, Forbidden: []int{7, 14}},
				{What: "the SY event's full Response lifecycle is POSTed",
					Devices: "EDA1, EDA2, EDB1 and EDB2", Names: managedDevices,
					MRID: "CERT-AGG011SY", Statuses: []int{1, 2, 3}, Forbidden: []int{7, 14}},
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
			Defaults: []aggDefault{
				{"TFA", "EDA1 and EDA2", edaPair},
				{"SY", "EDA1, EDA2, EDB1 and EDB2", managedDevices},
			},
			FanOut: []aggFanOut{
				{What: "the SY event runs for its full 4 min and its full Response lifecycle is POSTed, with " +
					"no supersession status despite the LATE higher-priority TFA event — that absence is this " +
					"row's whole discriminator against AGG-009",
					Devices: "EDA1, EDA2, EDB1 and EDB2", Names: managedDevices,
					MRID: "CERT-AGG012SY", Statuses: []int{1, 2, 3}, Forbidden: []int{7, 14}},
				{What: "the TFA event additionally runs from +2 to +4 min and its full Response lifecycle is " +
					"POSTed",
					Devices: "EDA1 and EDA2", Names: edaPair, MRID: "CERT-AGG012TFA",
					Statuses: []int{1, 2, 3}, Forbidden: []int{7, 14}},
			},
		},
	}
}
