package suitecsip

// criteria_agg.go holds the criteria the DER AGGREGATOR CLIENT profile adds.
//
// The 2026-07-28 re-scope (docs/PROFILE_SCOPE_2026-07-28_der-aggregator-client.md)
// moved twenty-two rows of CSIP-CONF-v1.3 from "not applicable" to "required",
// and they turn on two things the direct-DER-client rows never needed:
//
//	1. a FLEET. Every AGG / MAINT / UTIL row is written against the Figure-15
//	   topology — an aggregator EndDevice plus EDA1/EDA2 under SPA1/SPA2 and
//	   EDB1/EDB2 under SPB1/SPB2 — and most of their pass criteria are
//	   PER-ENDDEVICE ("for EDA1 and EDA2, POSTs response with status 2").
//	2. SUBSCRIPTION and NOTIFICATION. The server pushes a Notification to the
//	   client's notificationURI and the client answers it.
//
// This bench has neither. sim/gridsim serves one EndDevice and implements no
// Subscription resource, and a Notification arrives on a connection the SERVER
// dials — not the conversation RecoverSession reconstructs from the DUT's own
// outbound session.
//
// The response to that is the same one the rest of this suite already makes for
// a fixture it does not have: report what the bench actually served and SKIP,
// with the gap named precisely enough to be a work item. It is emphatically NOT
// to return PASS because the DUT handled the shape it was given. Every criterion
// below that cannot be answered here returns `unavailable` carrying the specific
// missing capability, which mint() turns into a SKIP assertion with that reason
// printed in the bundle.
//
// What is NOT skipped is the part this bench really can drive. gridsim publishes
// DERControls on three DERPrograms of different primacy, so the event-precedence
// core of AGG-003..AGG-012 — including the errata-corrected supersession status
// that is the whole point of AGG-007/AGG-008 — is exercised for real against one
// EndDevice, and fails a DUT that gets it wrong.

import (
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
)

// aggFleet is the Figure-15 fixture's size: an aggregator EndDevice plus the
// four managed ones (EDA1, EDA2, EDB1, EDB2).
const aggFleet = 5

// managedDevices names the four non-aggregator EndDevices the CTP's aggregator
// rows drive, in the document's own order.
var managedDevices = []string{"EDA1", "EDA2", "EDB1", "EDB2"}

// fleetGap is the sentence every per-EndDevice criterion ends with. It is one
// string so that a reviewer reading twenty SKIPped rows sees one gap reported
// twenty times rather than twenty gaps.
const fleetGap = "the CTP's aggregator rows are written against the Figure-15 topology — an aggregator " +
	"EndDevice plus EDA1/EDA2 under SPA1/SPA2 and EDB1/EDB2 under SPB1/SPB2 — and this bench's 2030.5 server " +
	"(sim/gridsim) builds a fixed tree with ONE EndDevice for the DUT. Until the simulator serves the " +
	"four managed EndDevices, the per-device fan-out this criterion is about cannot be placed on the wire, " +
	"and reporting anything but a SKIP would be certifying a test that was never run"

// notificationGap is the same sentence for the subscription/notification half.
const notificationGap = "this criterion is about a server-originated Notification POST to the DUT's " +
	"notificationURI. Two things are missing and both are named so neither is mistaken for the other: " +
	"sim/gridsim implements no Subscription resource and originates no Notification (sim/gridsim/admin.go " +
	"has no subscription route and its resource tree serves no SubscriptionListLink), and a Notification " +
	"arrives on a connection the SERVER dials, which is not the conversation this suite's RecoverSession " +
	"reconstructs from the DUT's own outbound session. Closing this needs a subscription function set in " +
	"gridsim AND a capture claim on the DUT's inbound listener"

// ── fleet ────────────────────────────────────────────────────────────────────

// critAggregatorFleet asserts the Figure-15 EndDevice fixture.
//
// It is the first criterion of every aggregator row, and it is the one that
// tells a bundle reader why the rest of the row skipped. It never FAILs the DUT
// for a short list: how many EndDevices the server publishes is a fact about the
// bench, not about the device under test.
func critAggregatorFleet() criterion {
	return criterion{
		Claim: "the server serves the aggregator's EndDeviceList carrying the aggregator's own EndDevice plus " +
			"the four managed EndDevice instances (EDA1, EDA2, EDB1, EDB2) of CTP Figure 15, each with a " +
			"FunctionSetAssignmentsListLink and a DERListLink",
		How: "the EndDevice children of the EndDeviceList the DUT fetched, counted and inspected for the " +
			"links the AGG-001 setup requires",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			e, doc, ok := t.Resource("EndDeviceList")
			if !ok {
				return unavailable("no EndDeviceList appears in the recovered transcript (resources seen: %s)",
					strings.Join(t.ResourceNames(), " "))
			}
			eds := doc.Children("EndDevice")
			withFSA, withDER, withSub := 0, 0, 0
			for _, ed := range eds {
				if ed.Has("FunctionSetAssignmentsListLink") {
					withFSA++
				}
				if ed.Has("DERListLink") {
					withDER++
				}
				if ed.Has("SubscriptionListLink") {
					withSub++
				}
			}
			desc := fmt.Sprintf("the server served %d EndDevice instance(s): %d with a "+
				"FunctionSetAssignmentsListLink, %d with a DERListLink, %d with a SubscriptionListLink",
				len(eds), withFSA, withDER, withSub)
			if len(eds) < aggFleet {
				return citeMessage(t, e.Resp, certify.Skip, "%s; the fixture needs %d (%s plus the aggregator's "+
					"own). %s", desc, aggFleet, strings.Join(managedDevices, ", "), fleetGap)
			}
			if withFSA < len(eds) || withDER < len(eds) {
				return citeMessage(t, e.Resp, certify.Fail, "%s; the AGG-001 setup requires every managed "+
					"EndDevice to carry both links", desc)
			}
			return citeMessage(t, e.Resp, certify.Pass, "%s", desc)
		},
		Skip: "counting the served EndDevices requires the decrypted transcript",
	}
}

// critPerDeviceFanOut is the honest record of a pass criterion that is stated
// per managed EndDevice and cannot be reached on a one-EndDevice bench.
//
// what names the artefact in the procedure's own words, so each row still reads
// as a sentence about ITS claim rather than as a shared boilerplate line.
func critPerDeviceFanOut(what, devices string) criterion {
	return criterion{
		Claim: fmt.Sprintf("for %s, %s", devices, what),
		How: "the Response POSTs in the session, grouped by the EndDevice LFDI each was posted for, matched " +
			"against the set of devices in the DERControl's topology scope",
		Skip: fleetGap,
	}
}

// critNotificationAnswered is the honest record of the client's answer to a
// server-pushed Notification.
//
// The published status is a parameter because the errata move it: CORE-018 and
// CORE-019 carry Annex A seq 44, "The 204 response is not included in the WADL —
// Remove the acceptance of 204 response in Procedure and Pass/Fail Criteria", so
// for those two rows 201 Created is the ONLY conformant answer. ERR-002's
// printed step 3 still admits either. Getting this backwards would fail a
// conformant client on one row or pass a non-conformant one on another, which is
// why the accepted set is spelled out per row rather than assumed.
func critNotificationAnswered(accept []int, why string) criterion {
	want := make([]string, len(accept))
	for i, s := range accept {
		want[i] = fmt.Sprint(s)
	}
	return criterion{
		Claim: fmt.Sprintf("the DUT answers a valid server-pushed Notification with HTTP %s",
			strings.Join(want, " or ")),
		How: "the status line of the DUT's response to the server's Notification POST, read from the DUT's " +
			"inbound listener conversation",
		Skip: why + ". " + notificationGap,
	}
}

// critSubscriptionPosted asserts the DUT's Subscription POST.
//
// This one is NOT unconditionally skipped, and the distinction is the point of
// the row. Whether the server ADVERTISES subscription support is a bench fact;
// whether the DUT SUBSCRIBES when it is advertised is a DUT fact, and the second
// is assertable the moment the first is true. The criterion therefore reads the
// EndDeviceList the DUT actually fetched: no SubscriptionListLink anywhere means
// the bench never offered the function set (SKIP, naming the gap); a
// SubscriptionListLink with no Subscription POST from the DUT is a real FAIL.
//
// resource is the subscribedResource the row demands, in the document's spelling.
func critSubscriptionPosted(resource, why string) criterion {
	return criterion{
		Claim: fmt.Sprintf("the DUT POSTed a Subscription whose subscribedResource is the %s href to the "+
			"SubscriptionListLink the server advertised, and the server answered 201 Created with a Location "+
			"header", resource),
		How: "a POST in the session whose body's root element is Subscription, its <subscribedResource> " +
			"element, and the status line and Location header of the response to it",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.Method("POST") {
				if e.Req == nil || len(e.Req.Body) == 0 {
					continue
				}
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "Subscription" {
					continue
				}
				sub, _ := doc.TextOf("subscribedResource")
				switch {
				case e.Resp == nil:
					return citeMessage(t, e.Req, certify.Fail,
						"the Subscription POST to %s was never answered in the capture", e.Req.Target)
				case e.Resp.Status != 201:
					return citeExchange(e, certify.Fail,
						"POST %s carrying a Subscription for %q -> %s; the procedure requires 201 Created",
						e.Req.Target, sub, e.Resp.Line())
				case e.Resp.Header.Get("Location") == "":
					return citeExchange(e, certify.Fail,
						"POST %s -> 201 Created but with no Location header naming the created subscription",
						e.Req.Target)
				default:
					return citeExchange(e, certify.Pass,
						"POST %s carrying a Subscription for %q -> 201 Created, Location: %s",
						e.Req.Target, sub, e.Resp.Header.Get("Location"))
				}
			}
			// No Subscription POST. Whose fault that is depends entirely on
			// whether the server offered the function set at all.
			offered, where := subscriptionOffered(t)
			if !offered {
				return unavailable("the DUT POSTed no Subscription, and the server advertised no "+
					"SubscriptionListLink in %s, so the function set was never offered to it. %s",
					where, notificationGap)
			}
			return found(certify.Fail, allFrames(t.Method("POST")),
				"the server advertised a SubscriptionListLink in %s but the DUT POSTed no Subscription for "+
					"the %s in this window", where, resource)
		},
		Skip: "reading a Subscription POST body requires the decrypted transcript",
	}
}

// subscriptionOffered reports whether the server advertised subscription
// support anywhere in the resources the DUT fetched, and where it looked.
func subscriptionOffered(t *Transcript) (bool, string) {
	var looked []string
	for _, name := range []string{"EndDeviceList", "EndDevice", "FunctionSetAssignmentsList",
		"DERProgramList", "DERControlList"} {
		exs := t.ByResource(name)
		if len(exs) == 0 {
			continue
		}
		looked = append(looked, name)
		for _, e := range exs {
			doc, err := e.Resp.SEP()
			if err != nil {
				continue
			}
			if doc.Has("SubscriptionListLink") {
				return true, name
			}
		}
	}
	if len(looked) == 0 {
		return false, "any resource of the recovered transcript (none carried a 2030.5 payload)"
	}
	return false, "the " + strings.Join(looked, ", ") + " it fetched"
}

// ── event precedence ─────────────────────────────────────────────────────────

// critSupersessionStatus asserts the Response status the DUT reports for a
// control a higher-priority control supersedes.
//
// The whole reason this criterion is parameterised — rather than accepting
// "7 or 14" the way CORE-023's does — is Annex A Errata I seq 5 and seq 6. The
// aggregator rows split into two families and the split is substantive:
//
//   - AGG-007 / AGG-008: both events are scheduled AHEAD of time and the
//     superseded control belongs to a DIFFERENT DERProgram, so the corrected
//     expectation is status 14 (Event Superseded from another program). The
//     printed procedure says 7; a check asserting 7 would FAIL a conformant
//     aggregator, which would be this harness's bug and not the DUT's.
//   - AGG-009: the SY event had already STARTED when the TFA event was
//     discovered, so it legitimately keeps status 7 and carries no erratum.
func critSupersessionStatus(mrid string, want uint8, meaning, why string) criterion {
	return criterion{
		Claim: fmt.Sprintf("the DUT POSTs a Response with status=%d (%s) for the superseded control, and not "+
			"some other supersession status", want, meaning),
		How: "the <status> element of the Response POSTs whose <subject> is the superseded control's mRID, " +
			"compared against the status the published errata prescribe for THIS row",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			got, frames := responseStatusesFor(t, mrid)
			if len(got) == 0 {
				return unavailable("the recovered transcript holds no Response POST for the superseded "+
					"control %s", mrid)
			}
			for _, s := range got {
				if s == int(want) {
					return found(certify.Pass, frames,
						"the DUT POSTed status=%d (%s) for %s. %s", want, meaning, mrid, why)
				}
			}
			return found(certify.Fail, frames,
				"the DUT POSTed status(es) %v for the superseded control %s; this row requires %d (%s). %s",
				got, mrid, want, meaning, why)
		},
		Server: func(v *ServerView) Finding {
			got := v.ResponseStatuses(mrid)
			if len(got) == 0 {
				return unavailable("gridsim received no Response for the superseded control %s within this "+
					"check's window", mrid)
			}
			for _, s := range got {
				if s == int(want) {
					return Finding{Verdict: certify.Pass,
						Observed: fmt.Sprintf("gridsim received status=%d (%s) for %s. %s", want, meaning, mrid, why)}
				}
			}
			return Finding{Verdict: certify.Fail,
				Observed: fmt.Sprintf("gridsim received status(es) %v for the superseded control %s; this row "+
					"requires %d (%s). %s", got, mrid, want, meaning, why)}
		},
	}
}

// critNoSupersession is the discriminating criterion of the INDEPENDENT-control
// family (AGG-010, AGG-011, AGG-012): two controls of DIFFERENT modes overlap,
// so neither supersedes the other and NO supersession Response may appear.
//
// It is an absence claim, which is why it is stated over the whole window's
// Response set rather than over one mRID: a status 7 or 14 for either control
// falsifies it.
func critNoSupersession(mrids []string) criterion {
	return criterion{
		Claim: "the DUT POSTs NO supersession Response (neither status 7 nor status 14) for either of the two " +
			"overlapping controls, because IEEE 2030.5 independent control modes coexist rather than supersede",
		How: "the <status> element of every Response POST in the window whose <subject> is one of the two " +
			"published controls, checked for the absence of 7 and 14",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			var all []int
			var frames []int
			any := false
			for _, m := range mrids {
				got, f := responseStatusesFor(t, m)
				if len(got) > 0 {
					any = true
				}
				all = append(all, got...)
				frames = append(frames, f...)
			}
			if !any {
				return unavailable("the recovered transcript holds no Response POST for either published " +
					"control, so the absence of a supersession Response is not evidence of anything")
			}
			for _, s := range all {
				if s == 7 || s == 14 {
					return found(certify.Fail, dedupeInts(frames),
						"the DUT POSTed status=%d for one of the two INDEPENDENT overlapping controls (%s); "+
							"independent modes do not supersede", s, strings.Join(mrids, ", "))
				}
			}
			sort.Ints(all)
			return found(certify.Pass, dedupeInts(frames),
				"the statuses POSTed for the two independent controls are %v — no 7 and no 14", all)
		},
		Server: func(v *ServerView) Finding {
			var all []int
			for _, m := range mrids {
				all = append(all, v.ResponseStatuses(m)...)
			}
			if len(all) == 0 {
				return unavailable("gridsim received no Response for either published control, so the absence " +
					"of a supersession Response is not evidence of anything")
			}
			for _, s := range all {
				if s == 7 || s == 14 {
					return Finding{Verdict: certify.Fail,
						Observed: fmt.Sprintf("gridsim received status=%d for one of the two INDEPENDENT "+
							"overlapping controls (%s)", s, strings.Join(mrids, ", "))}
				}
			}
			sort.Ints(all)
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("gridsim received statuses %v for the two independent controls — "+
					"no 7 and no 14", all)}
		},
	}
}

// responseStatusesFor reads the statuses the DUT POSTed for one mRID out of the
// transcript, with the frames that carried them.
func responseStatusesFor(t *Transcript, mrid string) ([]int, []int) {
	var got, frames []int
	for _, e := range t.Method("POST") {
		if e.Req == nil || len(e.Req.Body) == 0 {
			continue
		}
		doc, err := e.Req.SEP()
		if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
			continue
		}
		subj, _ := doc.TextOf("subject")
		if !strings.EqualFold(subj, mrid) {
			continue
		}
		st, _ := doc.UintOf("status")
		got = append(got, int(st))
		frames = append(frames, e.Frames()...)
	}
	sort.Ints(got)
	return got, dedupeInts(frames)
}

// critDefaultControlOutOfBand is the honest record of a criterion the DOCUMENT
// itself declares unobservable.
//
// AGG-002 and AGG-004 state it twice, verbatim: "Note that there is no
// acknowledgment for activating a DefaultDERControl in the IEEE 2030.5 protocol.
// Verification of the activation of the DefaultDERControl must be done
// out-of-band." A harness that reported PASS here would be inventing a protocol
// artefact the standard does not define.
func critDefaultControlOutOfBand(which string) criterion {
	return criterion{
		Claim: "the DUT applies the " + which + " DefaultDERControl when no DERControl is active",
		How:   "an out-of-band read of the setpoint in force at the DER",
		Skip: "the procedure itself states that IEEE 2030.5 defines NO acknowledgment for activating a " +
			"DefaultDERControl and that verification 'must be done out-of-band'. There is therefore no wire " +
			"artefact for this criterion to cite, on this bench or any other. What IS asserted above is that " +
			"the DUT fetched the DefaultDERControl; the setpoint it then applied would appear on the " +
			"gateway's SOUTHBOUND Modbus leg, which is a different capture and a different suite",
	}
}

// critEventLifecycle asserts the 1 → 2 → 3 Response lifecycle for one control.
//
// It is stated as one criterion rather than three because the aggregator rows'
// pass criteria are about the SEQUENCE ("status 2 at start time... status 3
// after duration has elapsed"), and because a window that does not span the
// event's whole interval can honestly report only how far the DUT got. Saying
// "statuses 1,2 received in a 90 s window over a 180 s event" is a fact; calling
// it a failure would be reporting the harness's wait as the DUT's behaviour.
func critEventLifecycle(mrid, label string, spanS int) criterion {
	return criterion{
		Claim: fmt.Sprintf("the DUT reports the %s event's lifecycle to the server: Response status 1 "+
			"(Event Received) on discovery, 2 (Event Started) at the interval start and 3 (Event Completed) "+
			"after the duration elapses", label),
		How: "the <status> elements of the Response POSTs whose <subject> is the event's mRID, in the order " +
			"the capture carries them",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			got, frames := responseStatusesFor(t, mrid)
			return lifecycleFinding(got, frames, mrid, label, spanS, "the capture")
		},
		Server: func(v *ServerView) Finding {
			got := v.ResponseStatuses(mrid)
			f := lifecycleFinding(got, nil, mrid, label, spanS, "gridsim's Response log")
			f.Frames = nil
			return f
		},
	}
}

func lifecycleFinding(got, frames []int, mrid, label string, spanS int, src string) Finding {
	if len(got) == 0 {
		return unavailable("%s holds no Response POST for the %s event %s", src, label, mrid)
	}
	has := func(s int) bool {
		for _, g := range got {
			if g == s {
				return true
			}
		}
		return false
	}
	if !has(1) {
		return found(certify.Fail, frames,
			"the DUT POSTed status(es) %v for the %s event %s but never status 1 (Event Received), which the "+
				"procedure requires on discovery", got, label, mrid)
	}
	if has(2) && has(3) {
		return found(certify.Pass, frames,
			"the DUT POSTed the full lifecycle %v for the %s event %s", got, label, mrid)
	}
	return found(certify.Warn, frames,
		"the DUT POSTed status(es) %v for the %s event %s. The event's interval spans %d s, so a window "+
			"shorter than that cannot contain 2 (Started) and 3 (Completed); raise -param %s past the "+
			"interval to close this out, and read this as an incomplete measurement rather than a finding "+
			"about the DUT", got, label, mrid, spanS, waitParam)
}
