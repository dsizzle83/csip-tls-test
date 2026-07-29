package suitecsip

// criteria_agg.go holds the criteria the DER AGGREGATOR CLIENT profile adds.
//
// The DUT is certified against the DER CLIENT column
// (docs/PROFILE_SCOPE_2026-07-28_der-client-gfems.md), so the twenty-two rows of
// CSIP-CONF-v1.3 these criteria serve are INFORMATIVE: outside the claim, inside
// the run. That changes what a reader should conclude from a verdict here and
// changes nothing about how carefully it has to be computed — a wrong
// informative verdict is still wrong.
//
// They turn on two things the direct-DER-client rows never needed:
//
//	1. a FLEET. Every AGG / MAINT / UTIL row is written against the Figure-15
//	   topology — an aggregator EndDevice plus EDA1/EDA2 under SPA1/SPA2 and
//	   EDB1/EDB2 under SPB1/SPB2 — and most of their pass criteria are
//	   PER-ENDDEVICE ("for EDA1 and EDA2, POSTs response with status 2").
//	2. SUBSCRIPTION and NOTIFICATION. The server pushes a Notification to the
//	   client's notificationURI and the client answers it.
//
// The bench has both now. sim/gridsim builds the Figure-15 fleet (fleet.go) and
// serves the Subscription/Notification function set (subscribe.go), and this
// suite claims the DUT's inbound listener from the notificationURI the server
// recorded. So the criteria below DECIDE where they used to declare a SKIP:
//
//	critResponseFanOut / critNoResponseFanOut  group the DUT's Response POSTs by
//	    <endDeviceLFDI> and match them against the LFDIs gridsim derived for
//	    EDA1..EDB2. A row demanding Responses from four devices that got them
//	    from two is a FAIL with both counts printed. It is the finding the whole
//	    re-scope exists to be able to produce.
//	critNotificationPushed / critNotificationAnswered / critNotificationCancelled
//	    read gridsim's own delivery record and, when the notification leg
//	    decrypts, the frames themselves.
//
// Three things did NOT become assertable and are not pretended into verdicts:
//
//	1. the ACTIVATION of a DefaultDERControl. AGG-002 and AGG-004 state it twice,
//	   verbatim: IEEE 2030.5 defines no acknowledgment for it and verification
//	   "must be done out-of-band". There is no wire artefact on this bench or any
//	   other. See critDefaultControlOutOfBand.
//	2. the DUT's INTERNAL STATE — "its internal state should also reflect the
//	   change so it no longer manages that device" (MAINT-001). Absence of
//	   traffic is not evidence of a belief.
//	3. a DERControl published at a NAMED topology node. gridsim's admin control
//	   API addresses a program by INDEX, so the SPA1 → EDA1, FDA → EDA1+EDA2,
//	   SY → all four scope ladder UTIL-004 is entirely about cannot be built.
//
// Every criterion that cannot be answered returns `unavailable` carrying the
// specific missing capability, which mint() turns into a SKIP assertion with
// that reason printed in the bundle. What it must never do is return PASS
// because the DUT handled the shape it was given, or FAIL because the bench did
// not give it the right one.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"csip-tls-test/internal/certify"
)

// aggFleet is the Figure-15 fixture's size: an aggregator EndDevice plus the
// four managed ones (EDA1, EDA2, EDB1, EDB2).
const aggFleet = 5

// managedDevices names the four non-aggregator EndDevices the CTP's aggregator
// rows drive, in the document's own order.
var managedDevices = []string{"EDA1", "EDA2", "EDB1", "EDB2"}

// fleetGap is the sentence a per-EndDevice criterion ends with when the bench
// is not serving the fixture. It is one string so that a reviewer reading
// twenty SKIPped rows sees one gap reported twenty times rather than twenty
// gaps.
//
// It used to say sim/gridsim "builds a fixed tree with ONE EndDevice", and that
// stopped being true at 4d2d551. The fixture exists; what this sentence now
// reports is that the LEVER IS OFF. The distinction is the whole value of the
// string: the first version described work nobody had done and the reader could
// only file it, this one describes a flag the reader can set before the next
// run.
const fleetGap = "the CTP's aggregator rows are written against the Figure-15 topology — an aggregator " +
	"EndDevice plus EDA1/EDA2 under SPA1/SPA2 and EDB1/EDB2 under SPB1/SPB2 — and sim/gridsim BUILDS that " +
	"fixture (sim/gridsim/fleet.go) but serves it only when it is switched on. It is off in this run: start " +
	"the simulator with -fleet 4, or bring the bench up with SIM_FLEET=4 (scripts/bench-sims-up.sh), which " +
	"passes -fleet 4 -subscription. Until it is on, the per-device fan-out this criterion is about is not on " +
	"the wire, and reporting anything but a SKIP would be certifying a test that was never run"

// notificationGap is the same sentence for the subscription/notification half.
//
// It used to say gridsim "implements no Subscription resource and originates no
// Notification". It implements both since 4d2d551 — POST/GET/DELETE of
// Subscriptions, SubscriptionListLink on every EndDevice, subscribable=1, and a
// Notification POSTed on change — and the DUT's inbound listener is claimed
// from the notificationURI the server recorded (check.go's
// claimNotificationEndpoints). So this sentence now reports the two switches
// that were left off, and the one transport condition that is not a switch.
const notificationGap = "this criterion is about a server-originated Notification POST to the DUT's " +
	"notificationURI. sim/gridsim implements the function set (sim/gridsim/subscribe.go: SubscriptionListLink " +
	"on every EndDevice, subscribable=1, POST/GET/DELETE of Subscriptions, and a Notification pushed on " +
	"change) and this suite claims the DUT's inbound listener from the <notificationURI> the server recorded. " +
	"It is off in this run: start the simulator with -subscription, or bring the bench up with SIM_FLEET=4. " +
	"Note the one condition that is not a flag — delivery to an https:// notificationURI needs a Notifier " +
	"that can dial the CSIP-mandatory ECDHE-ECDSA-AES128-CCM-8 suite, which the cgo sim/server binary " +
	"installs and a pure-Go build cannot"

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

// critPerDeviceFanOut is the honest record of a per-EndDevice pass criterion
// that has NO wire artefact even now that the fixture is served.
//
// It is what is left of this function after the Figure-15 fleet arrived. The
// per-device Response bullets became critResponseFanOut and critNoResponseFanOut,
// which really decide; the bullets that remain here are the ones whose subject
// is the DUT's internal state or an out-of-band setpoint, and no simulator can
// change that. why must therefore say what is missing for THIS bullet — passing
// fleetGap to it is now a bug, because the fleet is not what is missing.
//
// what names the artefact in the procedure's own words, so each row still reads
// as a sentence about ITS claim rather than as a shared boilerplate line.
func critPerDeviceFanOut(what, devices, why string) criterion {
	return criterion{
		Claim: fmt.Sprintf("for %s, %s", devices, what),
		How: "the Response POSTs in the session, grouped by the EndDevice LFDI each was posted for, matched " +
			"against the set of devices in the DERControl's topology scope",
		Skip: why,
	}
}

// ── per-device fan-out ───────────────────────────────────────────────────────

// respRec is one Response the DUT POSTed, reduced to the three facts every
// fan-out criterion turns on. It exists so the wire tier and the server tier
// share one decision function rather than two that can drift: the transcript
// and gridsim's Response log carry the same three fields, and the only honest
// difference between the tiers is the citation.
type respRec struct {
	LFDI   string
	Status int
	Frames []int
}

// deviceLFDIs resolves the CTP device names a pass criterion is stated about
// into the LFDIs that will appear in <endDeviceLFDI>, and reports which of them
// the bench is not serving.
//
// The mapping comes from gridsim's own /admin/fleet, never from the order of
// the EndDeviceList: the four LFDIs are DERIVED by the simulator (SHA-256 over
// a documented preimage, see sim/gridsim/fleet.go) and the capture states the
// correspondence to EDA1..EDB2 nowhere at all. Reading it off /edev ordering
// would make every fan-out verdict rest on a bench convention.
func deviceLFDIs(o *Observation, names []string) (byLFDI map[string]string, missing []string) {
	byLFDI = map[string]string{}
	for _, n := range names {
		d, ok := o.Server.FleetDeviceNamed(n)
		if !ok || d.LFDI == "" {
			missing = append(missing, n)
			continue
		}
		byLFDI[strings.ToUpper(d.LFDI)] = d.Name
	}
	return byLFDI, missing
}

// fleetLeverGap is what a fan-out criterion reports when the bench is not
// serving the fixture the bullet is stated about. It names the lever, because
// that is the difference between a SKIP a reader can act on and one they cannot.
func fleetLeverGap(missing []string) string {
	return fmt.Sprintf("gridsim is not serving %s, so the per-device fan-out this criterion is about cannot "+
		"appear on the wire at all. The fixture is a LEVER and it is off: start the simulator with -fleet 4 "+
		"-subscription (scripts/bench-sims-up.sh does it at SIM_FLEET=4), and GET /admin/fleet will then map "+
		"each CTP device name to the LFDI its Responses carry. Reporting anything but a SKIP here would be "+
		"certifying a test that was never run", strings.Join(missing, ", "))
}

// critResponseFanOut asserts the per-EndDevice Response bullet, e.g. AGG-003's
// "[C, S] Client, for EDA1 and EDA2, POSTs response with status 2 (event
// started) at start time".
//
// The three outcomes it must keep apart, and does:
//
//   - the bench is not serving those devices → SKIP naming the lever. Never a
//     FAIL; how many EndDevices the server publishes is a fact about the bench.
//   - the bench serves them and the DUT answered for SOME of them → FAIL with
//     the counts. This is the finding the whole re-scope exists to produce: an
//     aggregator that fans out to two of four devices is non-conformant, and
//     saying so needs both halves of the fixture and none of the charity.
//   - the bench serves them, every one of them answered, but the window was
//     shorter than the event → WARN, exactly as critEventLifecycle does. A
//     measurement that stopped early is not a finding about the DUT.
func critResponseFanOut(o *Observation, f aggFanOut) criterion {
	byLFDI, missing := deviceLFDIs(o, f.Names)
	decide := func(recs []respRec, frames []int, src string) Finding {
		return fanOutFinding(f, byLFDI, missing, recs, frames, src)
	}
	return criterion{
		Claim: fmt.Sprintf("for %s, %s", f.Devices, f.What),
		How: "the <endDeviceLFDI> and <status> elements of the Response POSTs whose <subject> is the event's " +
			"mRID, grouped by device and matched against the LFDIs gridsim derived for the CTP's named " +
			"EndDevices (GET /admin/fleet)",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			recs, frames := wireResponses(t, f.MRID)
			return decide(recs, frames, "the recovered transcript")
		},
		Server: func(v *ServerView) Finding {
			var recs []respRec
			for _, r := range v.ResponsesFor(f.MRID) {
				recs = append(recs, respRec{LFDI: r.LFDI, Status: int(r.Status)})
			}
			fnd := decide(recs, nil, "gridsim's Response log")
			fnd.Frames = nil
			return fnd
		},
	}
}

// critNoResponseFanOut is AGG-003's untagged negative bullet — "Client fails if
// EDB1 and/or EDB2 POSTs any responses to the TFA event" — and its siblings.
//
// It is an absence claim, so it carries the trap every absence claim does: a
// window in which the DUT POSTed nothing at all supports it vacuously. That is
// why it declines to decide unless the event produced Responses from SOMEBODY,
// which is the evidence that the DUT got as far as this criterion is about.
func critNoResponseFanOut(o *Observation, f aggFanOut) criterion {
	byLFDI, missing := deviceLFDIs(o, f.Names)
	decide := func(recs []respRec, frames []int, src string) Finding {
		if len(missing) > 0 {
			return unavailable("%s", fleetLeverGap(missing))
		}
		if len(recs) == 0 {
			return unavailable("%s holds no Response POST for %s from any device, so the absence of one from "+
				"%s is not evidence of anything", src, f.MRID, f.Devices)
		}
		var offenders []string
		for _, r := range recs {
			if name, ok := byLFDI[strings.ToUpper(r.LFDI)]; ok {
				offenders = append(offenders, fmt.Sprintf("%s (status %d)", name, r.Status))
			}
		}
		if len(offenders) > 0 {
			return found(certify.Fail, dedupeInts(frames),
				"%d of the %d Response(s) for %s came from %s: %s. The procedure states this as a FAILURE — "+
					"those devices are outside the control's topology scope and owe it no Response",
				len(offenders), len(recs), f.MRID, f.Devices, strings.Join(offenders, ", "))
		}
		return found(certify.Pass, dedupeInts(frames),
			"%d Response(s) for %s appear and none of them carries the LFDI of %s (%s)",
			len(recs), f.MRID, f.Devices, strings.Join(lfdiNames(byLFDI), ", "))
	}
	return criterion{
		Claim: fmt.Sprintf("for %s, %s", f.Devices, f.What),
		How: "the <endDeviceLFDI> of every Response POST whose <subject> is the event's mRID, checked for the " +
			"absence of the LFDIs gridsim derived for those EndDevices (GET /admin/fleet)",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			recs, frames := wireResponses(t, f.MRID)
			return decide(recs, frames, "the recovered transcript")
		},
		Server: func(v *ServerView) Finding {
			var recs []respRec
			for _, r := range v.ResponsesFor(f.MRID) {
				recs = append(recs, respRec{LFDI: r.LFDI, Status: int(r.Status)})
			}
			fnd := decide(recs, nil, "gridsim's Response log")
			fnd.Frames = nil
			return fnd
		},
	}
}

// fanOutFinding is the shared decision of the POSITIVE per-device bullet. See
// critResponseFanOut for the three outcomes and why they are three.
func fanOutFinding(f aggFanOut, byLFDI map[string]string, missing []string,
	recs []respRec, frames []int, src string) Finding {
	if len(missing) > 0 {
		return unavailable("%s", fleetLeverGap(missing))
	}
	if len(recs) == 0 {
		return unavailable("%s holds no Response POST for %s from any device, so which devices the DUT fanned "+
			"out to is not observable in this window", src, f.MRID)
	}

	got := map[string]map[int]bool{}
	var strangers []string
	for _, r := range recs {
		name, ok := byLFDI[strings.ToUpper(r.LFDI)]
		if !ok {
			strangers = append(strangers, fmt.Sprintf("%s (status %d)", shortLFDI(r.LFDI), r.Status))
			continue
		}
		if got[name] == nil {
			got[name] = map[int]bool{}
		}
		got[name][r.Status] = true
	}

	// A forbidden status is decisive on its own: it is a statement about what
	// the DUT DID, so an incomplete window cannot excuse it the way a missing
	// status can.
	var banned []string
	for _, n := range f.Names {
		for _, s := range f.Forbidden {
			if got[n][s] {
				banned = append(banned, fmt.Sprintf("%s reported status %d", n, s))
			}
		}
	}
	if len(banned) > 0 {
		return found(certify.Fail, dedupeInts(frames),
			"%s for %s, which this row forbids: %s", strings.Join(banned, ", "), f.MRID, f.What)
	}

	var silent, short []string
	for _, n := range f.Names {
		statuses := got[n]
		if len(statuses) == 0 {
			silent = append(silent, n)
			continue
		}
		var wantMissing []string
		for _, s := range f.Statuses {
			if !statuses[s] {
				wantMissing = append(wantMissing, strconv.Itoa(s))
			}
		}
		if len(wantMissing) > 0 {
			short = append(short, fmt.Sprintf("%s (has %v, missing %s)", n, sortedKeys(statuses),
				strings.Join(wantMissing, "/")))
		}
	}

	extra := ""
	if len(strangers) > 0 {
		extra = fmt.Sprintf("; %d Response(s) carried an LFDI that is none of the named devices — %s",
			len(strangers), strings.Join(strangers, ", "))
	}

	switch {
	case len(silent) > 0:
		return found(certify.Fail, dedupeInts(frames),
			"the DUT POSTed Responses for %s on behalf of %d of the %d device(s) this criterion names: %s "+
				"POSTed none at all%s. The procedure states this bullet per EndDevice, so a partial fan-out "+
				"is a finding about the aggregator, not about the window",
			f.MRID, len(f.Names)-len(silent), len(f.Names), strings.Join(silent, ", "), extra)
	case len(short) > 0:
		return found(certify.Warn, dedupeInts(frames),
			"every one of %s POSTed a Response for %s, but not yet every status this row requires (%v): %s%s. "+
				"Raise -param %s past the event's interval to close this out, and read it as an incomplete "+
				"measurement rather than a finding about the DUT",
			f.Devices, f.MRID, f.Statuses, strings.Join(short, "; "), extra, waitParam)
	default:
		return found(certify.Pass, dedupeInts(frames),
			"every one of %s POSTed the Response status(es) %v this row requires for %s%s",
			f.Devices, f.Statuses, f.MRID, extra)
	}
}

// wireResponses reads the Response POSTs for one mRID out of the transcript,
// keeping the endDeviceLFDI each carried.
func wireResponses(t *Transcript, mrid string) ([]respRec, []int) {
	var recs []respRec
	var frames []int
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
		lfdi, _ := doc.TextOf("endDeviceLFDI")
		st, _ := doc.UintOf("status")
		recs = append(recs, respRec{LFDI: lfdi, Status: int(st), Frames: e.Frames()})
		frames = append(frames, e.Frames()...)
	}
	return recs, dedupeInts(frames)
}

func lfdiNames(byLFDI map[string]string) []string {
	out := make([]string, 0, len(byLFDI))
	for _, n := range byLFDI {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// shortLFDI renders an unrecognised LFDI compactly. It is never truncated to
// the point of ambiguity — the whole value is what identifies the device — but
// an empty one is called out, because a Response with NO endDeviceLFDI is a
// different defect from a Response with the wrong one.
func shortLFDI(lfdi string) string {
	if strings.TrimSpace(lfdi) == "" {
		return "no <endDeviceLFDI> at all"
	}
	return "LFDI " + lfdi
}

// critPerDeviceResource asserts that the DUT reached each managed EndDevice's
// OWN sub-tree — UTIL-002's "for all other EndDevice instances (EDA1, EDA2,
// EDB1, and EDB2) … Do an HTTP PUT on DERCapabilities, DERSettings, DERStatus
// or DERAvailability", UTIL-003's per-device GETs of the FSAList and the
// DERPrograms beneath it.
//
// Unlike the Response bullets this one is answerable from the REQUEST side, so
// it works for the rows whose fan-out is a walk rather than an acknowledgment.
// suffixes are appended to each device's own href; a device satisfies the
// criterion when the DUT requested ANY of them, which is the procedure's own
// "DERCapabilities, DERSettings, DERStatus or DERAvailability".
func critPerDeviceResource(o *Observation, what, devices string, names []string,
	method string, suffixes []string) criterion {
	type target struct {
		name  string
		paths []string
	}
	var targets []target
	var missing []string
	for _, n := range names {
		d, ok := o.Server.FleetDeviceNamed(n)
		if !ok || d.Href == "" {
			missing = append(missing, n)
			continue
		}
		t := target{name: d.Name}
		for _, s := range suffixes {
			t.paths = append(t.paths, d.Href+s)
		}
		targets = append(targets, t)
	}
	decide := func(hit func(prefix string) bool, frames []int, src string) Finding {
		if len(missing) > 0 {
			return unavailable("%s", fleetLeverGap(missing))
		}
		var silent []string
		var reached []string
		for _, t := range targets {
			ok := false
			for _, p := range t.paths {
				if hit(p) {
					ok = true
					break
				}
			}
			if ok {
				reached = append(reached, t.name)
			} else {
				silent = append(silent, t.name)
			}
		}
		if len(reached) == 0 {
			return unavailable("%s records no %s of any managed EndDevice's own sub-tree in this window, so "+
				"whether the DUT walks them is not observable here; it may simply not have got that far",
				src, method)
		}
		if len(silent) > 0 {
			return found(certify.Fail, dedupeInts(frames),
				"the DUT %sed the sub-tree of %d of the %d device(s) this criterion names (%s); %s were never "+
					"reached. The procedure states this bullet for every managed EndDevice",
				method, len(reached), len(targets), strings.Join(reached, ", "), strings.Join(silent, ", "))
		}
		return found(certify.Pass, dedupeInts(frames),
			"the DUT %sed the named resource of every one of %s (%s)", method, devices, strings.Join(reached, ", "))
	}
	return criterion{
		Claim:           fmt.Sprintf("for %s, %s", devices, what),
		How:             "the request targets of the DUT's " + method + "s, matched against each managed EndDevice's own href",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			var frames []int
			seen := map[string]bool{}
			for _, e := range t.Method(method) {
				if e.Req == nil {
					continue
				}
				seen[e.Req.Path] = true
				frames = append(frames, e.Frames()...)
			}
			return decide(func(prefix string) bool {
				for p := range seen {
					if strings.HasPrefix(p, prefix) {
						return true
					}
				}
				return false
			}, frames, "the recovered transcript")
		},
		Server: func(v *ServerView) Finding {
			fnd := decide(func(prefix string) bool {
				for _, r := range v.Requests {
					if r.Method == method && strings.HasPrefix(r.Path, prefix) {
						return true
					}
				}
				return false
			}, nil, "gridsim's request log")
			fnd.Frames = nil
			return fnd
		},
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
//
// The Figure-15 fleet did not change that and this criterion was deliberately
// NOT converted with the others. What the fleet DID make assertable is the half
// that is on the wire — that the DUT fetched each managed device's
// DefaultDERControl at all — and that is a different sentence, so it is a
// different criterion: critDefaultControlFetched, which every row carrying this
// one also carries. Folding the two together would let an acquisition PASS read
// as an activation PASS, which is exactly the invention the note above forbids.
func critDefaultControlOutOfBand(which string) criterion {
	return criterion{
		Claim: "the DUT applies the " + which + " DefaultDERControl when no DERControl is active",
		How:   "an out-of-band read of the setpoint in force at the DER",
		Skip: "the procedure itself states that IEEE 2030.5 defines NO acknowledgment for activating a " +
			"DefaultDERControl and that verification 'must be done out-of-band'. There is therefore no wire " +
			"artefact for this criterion to cite, on this bench or any other, and no bench lever can change " +
			"that — this is the one gap in this row that the Figure-15 fleet and the Subscription function " +
			"set did not close. What IS asserted, as its own criterion, is that the DUT FETCHED the " +
			"DefaultDERControl of each managed device; the setpoint it then applied would appear on the " +
			"gateway's SOUTHBOUND Modbus leg, which is a different capture and a different suite",
	}
}

// critDefaultControlFetched is the wire half of the DefaultDERControl bullets:
// the DUT reached the DefaultDERControl of every named managed EndDevice.
//
// It is what the Figure-15 fleet made assertable. Each managed device carries
// its own FunctionSetAssignments and its own DERProgramList of the node programs
// on its parent chain (sim/gridsim/fleet.go), so "for EDA1 and EDA2, applies the
// TFA DefaultDERControl" has an observable precondition per device where the
// single-EndDevice tree had one for the whole bench.
//
// The claim is scoped to what per-device attribution can actually carry. The
// DefaultDERControl itself hangs off the NODE program (/derp/tfa/dderc), which
// EDA1 and EDA2 share, so a GET of it belongs to neither device in particular
// and this criterion does not pretend otherwise. What IS per-device is the walk
// that resolves the topology — the device's own FunctionSetAssignments and the
// DERProgramList beneath it — and that is what is asserted.
//
// It claims acquisition and says so. Activation is critDefaultControlOutOfBand's
// claim and stays a SKIP.
func critDefaultControlFetched(o *Observation, which, devices string, names []string) criterion {
	return critPerDeviceResource(o,
		"the DUT walked that device's OWN FunctionSetAssignments and the DERProgramList beneath it, which is "+
			"how it reaches the "+which+" DERProgram and the DefaultDERControl the bullet is about. The "+
			"DefaultDERControl hangs off the shared node program, so a GET of it is attributable to no single "+
			"device and is not claimed here",
		devices, names, "GET", []string{"/fsa"})
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

// ── subscription / notification ──────────────────────────────────────────────

// subscriptionOff is what a notification criterion reports when the function
// set is not being served. It is separated from notificationGap because the two
// say different things: this one is "the switch is off", notificationGap is the
// whole story including the transport condition that is not a switch.
const subscriptionOff = "gridsim is serving no Subscription/Notification function set in this run, so there " +
	"is no subscription for a Notification to be owed to and nothing about this criterion is on the wire. " +
	"Start the simulator with -subscription (SIM_FLEET=4 does it)"

// notifierRefused explains a Notification the server BUILT and could not
// DELIVER, which is a bench-transport gap and must never read as a DUT that
// ignored one.
func notifierRefused(recs []AdminNotification) string {
	seen := map[string]bool{}
	var why []string
	for _, r := range recs {
		if r.Error == "" || seen[r.Error] {
			continue
		}
		seen[r.Error] = true
		why = append(why, r.Error)
	}
	return fmt.Sprintf("gridsim built %d Notification(s) for the DUT and delivered none of them, so the DUT "+
		"was never given one to answer and nothing here is a finding about it. The transport refused: %s. "+
		"This is the Notifier lever: sim/gridsim is pure Go and Go's crypto/tls has no "+
		"ECDHE-ECDSA-AES128-CCM-8, so an https:// notificationURI needs the wolfSSL-backed Notifier the cgo "+
		"sim/server binary installs (Server.SetNotifier). Run the cgo build of the simulator",
		len(recs), strings.Join(why, "; "))
}

// pushSummary describes what the server had to work with, so an unavailable
// reason distinguishes "nobody subscribed" from "nothing changed".
func pushSummary(v *ServerView) string {
	if len(v.Subscriptions) == 0 {
		return "the DUT holds no Subscription on this server, so no Notification was owed to it. Whether it " +
			"OUGHT to have subscribed is a separate criterion of this row and is asserted there"
	}
	var res []string
	for _, s := range v.Subscriptions {
		res = append(res, s.SubscribedResource)
	}
	sort.Strings(res)
	return fmt.Sprintf("the DUT holds %d Subscription(s) — for %s — but nothing changed a resource any of "+
		"them names during this check's window", len(v.Subscriptions), strings.Join(dedupeStrings(res), ", "))
}

// notifyLegExchanges recovers the server-dialled notification leg for every
// listener this check claimed, and returns the Notification POSTs on it.
func notifyLegExchanges(ev *certify.Evidence, o *Observation) ([]Exchange, string) {
	if ev == nil {
		return nil, "this criterion was evaluated without a capture"
	}
	if len(o.NotifyEndpoints) == 0 {
		reason := "no inbound Notification listener was claimed for this test case, so the server-dialled leg " +
			"is unattributed and its frames may not be cited"
		if rec := o.Param(notifyClaimParam); rec != "" {
			reason += " (" + rec + ")"
		}
		return nil, reason
	}
	var exs []Exchange
	var why []string
	for _, ep := range o.NotifyEndpoints {
		legs, reason := RecoverNotificationLeg(ev, ep)
		if reason != "" {
			why = append(why, reason)
			continue
		}
		for _, leg := range legs {
			exs = append(exs, leg.NotificationPOSTs()...)
		}
	}
	if len(exs) > 0 {
		return exs, ""
	}
	if len(why) == 0 {
		why = append(why, "the recovered notification leg carries no <Notification> POST")
	}
	return nil, strings.Join(why, "; ")
}

// critNotificationPushed is the [S] pass criterion of every subscription row:
// the server changed the subscribed resource and pushed a Notification carrying
// the updated payload.
//
// It is a criterion about the BENCH, and it is stated as one. It exists because
// the rows beneath it are unreadable without it: a reader who sees "the DUT
// answered no Notification" has to be able to tell whether one was ever sent,
// and this is the line that says so.
func critNotificationPushed(o *Observation, resource, why string) criterion {
	decide := func(recs []AdminNotification, v *ServerView) Finding {
		if !v.Status.Subscription.Enabled {
			return unavailable("%s", subscriptionOff)
		}
		if len(recs) == 0 {
			if r := o.Param(changeFailed); r != "" {
				return unavailable("this check could not make the change the procedure calls for, so no "+
					"Notification was owed: %s", r)
			}
			return unavailable("gridsim pushed no Notification in this window: %s", pushSummary(v))
		}
		var delivered, refused []AdminNotification
		for _, r := range recs {
			if r.Delivered() {
				delivered = append(delivered, r)
			} else {
				refused = append(refused, r)
			}
		}
		if len(delivered) == 0 {
			return unavailable("%s", notifierRefused(refused))
		}
		return Finding{Verdict: certify.Pass,
			Observed: fmt.Sprintf("gridsim pushed %d Notification(s) to the DUT's notificationURI %s, "+
				"carrying %s (%d bytes of payload). %s", len(delivered), delivered[0].NotificationURI,
				describeResources(delivered), delivered[0].Bytes, why)}
	}
	return criterion{
		Claim: fmt.Sprintf("the server changes the subscribed %s and pushes a Notification carrying the "+
			"updated payload to the DUT's notificationURI", resource),
		How: "the server-originated Notification POST — read from the notification leg of the capture when it " +
			"decrypts, and from gridsim's own delivery record otherwise",
		Wire: func(ev *certify.Evidence, _ *Transcript) Finding {
			exs, reason := notifyLegExchanges(ev, o)
			if reason != "" {
				return unavailable("%s", reason)
			}
			var frames []int
			var res []string
			for _, e := range exs {
				frames = append(frames, e.Frames()...)
				if doc, err := e.Req.SEP(); err == nil {
					if r, ok := doc.Attr("subscribedResource"); ok {
						res = append(res, r)
					}
				}
			}
			return found(certify.Pass, dedupeInts(frames),
				"%d Notification POST(s) from the server appear on the DUT's inbound listener, carrying %s. %s",
				len(exs), strings.Join(dedupeStrings(res), ", "), why)
		},
		Server: func(v *ServerView) Finding { return decide(v.Notifications, v) },
		Skip:   notificationGap,
	}
}

// critNotificationAnswered asserts the client's answer to a server-pushed
// Notification.
//
// The published status is a parameter because the errata move it: CORE-018 and
// CORE-019 carry Annex A seq 44, "The 204 response is not included in the WADL —
// Remove the acceptance of 204 response in Procedure and Pass/Fail Criteria", so
// for those two rows 201 Created is the ONLY conformant answer. ERR-002's
// printed step 3 still admits either. Getting this backwards would fail a
// conformant client on one row or pass a non-conformant one on another, which is
// why the accepted set is spelled out per row rather than assumed.
//
// The server tier is first-hand here, not hearsay: gridsim read the status line
// off its own socket. That is the same class of observation as a Response POST
// in its request log, and it is why this criterion can decide at all on a run
// whose notification leg was captured but not decrypted.
func critNotificationAnswered(o *Observation, accept []int, why string) criterion {
	want := make([]string, len(accept))
	ok := map[int]bool{}
	for i, s := range accept {
		want[i] = fmt.Sprint(s)
		ok[s] = true
	}
	judge := func(codes []int, frames []int, src string) Finding {
		var bad []string
		for _, c := range codes {
			if !ok[c] {
				bad = append(bad, strconv.Itoa(c))
			}
		}
		if len(bad) > 0 {
			return found(certify.Fail, dedupeInts(frames),
				"the DUT answered %d Notification(s) with HTTP %s; this row requires %s. %s",
				len(codes), strings.Join(dedupeStrings(bad), ", "), strings.Join(want, " or "), why)
		}
		return found(certify.Pass, dedupeInts(frames),
			"the DUT answered all %d Notification(s) with HTTP %s, read from %s. %s",
			len(codes), strings.Join(dedupeStrings(intStrings(codes)), ", "), src, why)
	}
	return criterion{
		Claim: fmt.Sprintf("the DUT answers a valid server-pushed Notification with HTTP %s",
			strings.Join(want, " or ")),
		How: "the status line of the DUT's response to the server's Notification POST, read from the " +
			"server-dialled notification leg of the capture when it decrypts and from gridsim's own delivery " +
			"record otherwise",
		Wire: func(ev *certify.Evidence, _ *Transcript) Finding {
			exs, reason := notifyLegExchanges(ev, o)
			if reason != "" {
				return unavailable("%s", reason)
			}
			var codes, frames []int
			for _, e := range exs {
				if e.Resp == nil {
					continue
				}
				codes = append(codes, e.Resp.Status)
				frames = append(frames, e.Frames()...)
			}
			if len(codes) == 0 {
				return unavailable("the notification leg carries %d Notification POST(s) and no answer to any "+
					"of them; the capture ends before the DUT replied", len(exs))
			}
			return judge(codes, frames, "the wire")
		},
		Server: func(v *ServerView) Finding {
			if !v.Status.Subscription.Enabled {
				return unavailable("%s", subscriptionOff)
			}
			var codes []int
			var refused []AdminNotification
			for _, r := range v.Notifications {
				if r.Delivered() {
					codes = append(codes, r.HTTPStatus)
				} else {
					refused = append(refused, r)
				}
			}
			switch {
			case len(codes) > 0:
				return judge(codes, nil, "gridsim's delivery record")
			case len(refused) > 0:
				return unavailable("%s", notifierRefused(refused))
			default:
				return unavailable("gridsim pushed no Notification in this window, so the DUT answered none: %s",
					pushSummary(v))
			}
		},
		Skip: why + ". " + notificationGap,
	}
}

// critNotificationLimitHonoured is MAINT-001's pass criterion about the SHAPE
// of the pushed body: "The notification resource body for the EndDeviceList was
// correctly formed using the limit parameter requested by the Client in the
// original subscription request."
//
// It has no server tier and could not honestly have one. gridsim's delivery
// record carries the body's LENGTH IN BYTES, not the body, so a server-tier
// answer would be asserting a list length from a byte count. The body itself is
// on the leg the server dialled, so the criterion reads it there or declines.
func critNotificationLimitHonoured(o *Observation) criterion {
	return criterion{
		Claim: "the pushed Notification's list payload honours the <limit> the DUT asked for in its " +
			"Subscription — it carries no more entries than the client requested",
		How: "the child count of the Notification's <Resource> payload on the server-dialled leg, compared " +
			"with the <limit> gridsim recorded for the subscription it was pushed on",
		Wire: func(ev *certify.Evidence, _ *Transcript) Finding {
			limits := map[string]uint32{}
			for _, s := range o.Server.Subscriptions {
				limits[s.Href] = s.Limit
			}
			exs, reason := notifyLegExchanges(ev, o)
			if reason != "" {
				return unavailable("%s", reason)
			}
			var frames []int
			var over, checked []string
			for _, e := range exs {
				doc, err := e.Req.SEP()
				if err != nil {
					continue
				}
				subURI, _ := doc.TextOf("subscriptionURI")
				limit, known := limits[subURI]
				if !known || limit == 0 {
					continue
				}
				res := doc.Child("Resource")
				if res == nil {
					continue
				}
				n := len(res.Kids)
				frames = append(frames, e.Frames()...)
				checked = append(checked, fmt.Sprintf("%s (%d of a requested %d)", subURI, n, limit))
				if uint32(n) > limit {
					over = append(over, fmt.Sprintf("%s carried %d entries where the client asked for %d",
						subURI, n, limit))
				}
			}
			switch {
			case len(checked) == 0:
				return unavailable("no Notification on the leg was pushed on a subscription that requested a " +
					"<limit>, so there is no requested length for this criterion to be about")
			case len(over) > 0:
				return found(certify.Fail, dedupeInts(frames),
					"the server over-filled a Notification payload: %s", strings.Join(over, "; "))
			default:
				return found(certify.Pass, dedupeInts(frames),
					"every pushed Notification honoured the client's requested limit: %s",
					strings.Join(checked, ", "))
			}
		},
		Skip: "this criterion is about the CONTENT of the pushed body, and gridsim's delivery record keeps " +
			"the body's length in bytes rather than the body. Reading it needs the server-dialled leg " +
			"decrypted. " + notificationGap,
	}
}

// critNotificationCancelled is CORE-019 step 12 and ERR-002 step 6: the server
// cancels an outstanding subscription with a status=1 Notification and the
// client answers it.
//
// It is separated from critNotificationAnswered because the two are about
// different messages and a run can produce one without the other — a bench that
// pushed ordinary Notifications and never pulled the cancel lever would
// otherwise report this row's cancellation criterion on the strength of the
// ordinary ones.
func critNotificationCancelled(o *Observation, accept []int) criterion {
	want := make([]string, len(accept))
	ok := map[int]bool{}
	for i, s := range accept {
		want[i] = fmt.Sprint(s)
		ok[s] = true
	}
	return criterion{
		Claim: "the DUT processes a Notification with status=1 (Subscription canceled, no additional " +
			"information) and answers it with HTTP " + strings.Join(want, " or "),
		How: "the <status> element of the server's cancellation Notification and the status line of the DUT's " +
			"response to it",
		Server: func(v *ServerView) Finding {
			if !v.Status.Subscription.Enabled {
				return unavailable("%s", subscriptionOff)
			}
			var cancels []AdminNotification
			for _, r := range v.Notifications {
				if r.Status == 1 {
					cancels = append(cancels, r)
				}
			}
			if len(cancels) == 0 {
				if r := o.Param(changeFailed); r != "" {
					return unavailable("the cancellation this row is about could not be driven: %s", r)
				}
				return unavailable("gridsim sent no status=1 (Subscription canceled) Notification in this " +
					"window. The lever is DELETE /admin/subscriptions?href=…, which this check pulls only " +
					"once the DUT has actually POSTed a Subscription for it to cancel")
			}
			var codes []int
			var refused []AdminNotification
			for _, r := range cancels {
				if r.Delivered() {
					codes = append(codes, r.HTTPStatus)
				} else {
					refused = append(refused, r)
				}
			}
			if len(codes) == 0 {
				return unavailable("%s", notifierRefused(refused))
			}
			for _, c := range codes {
				if !ok[c] {
					return Finding{Verdict: certify.Fail,
						Observed: fmt.Sprintf("the DUT answered the status=1 cancellation Notification with "+
							"HTTP %d; this row requires %s", c, strings.Join(want, " or "))}
				}
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("gridsim cancelled %d subscription(s) with a status=1 Notification and "+
					"the DUT answered HTTP %s", len(cancels), strings.Join(dedupeStrings(intStrings(codes)), ", "))}
		},
		Skip: "this criterion is about the server-originated cancellation Notification. " + notificationGap,
	}
}

// critNotifiedHrefRefetched is CORE-018 step 8 and ERR-002 step 4: the DUT GETs
// the href the Notification carried, and the payload the server returns is
// identical to the Notification body.
//
// It is a WIRE criterion with no server tier, and that is a decision rather than
// an omission. The claim is about ORDER — a GET that FOLLOWS the push — and the
// only clock both events share is the capture's. gridsim timestamps its
// notification log from its own (warpable) 2030.5 clock and its request log from
// the process clock, so a server-tier answer would be comparing two clocks and
// calling the result conformance.
func critNotifiedHrefRefetched(o *Observation) criterion {
	return criterion{
		Claim: "the DUT GETs the href carried in the Notification and the payload the server returns is " +
			"identical to the Notification body",
		How: "the <Resource> payload of the server's Notification POST on the inbound leg, compared with the " +
			"body of the DUT's GET of the same href on its outbound session, both timestamped by the capture",
		NeedsTranscript: true,
		Wire: func(ev *certify.Evidence, t *Transcript) Finding {
			exs, reason := notifyLegExchanges(ev, o)
			if reason != "" {
				return unavailable("%s", reason)
			}
			var frames []int
			var checked, missing, differing []string
			for _, e := range exs {
				doc, err := e.Req.SEP()
				if err != nil {
					continue
				}
				href, ok := doc.Attr("subscribedResource")
				if !ok || href == "" {
					continue
				}
				payload := doc.Child("Resource")
				pushedAt := e.Req.Time
				frames = append(frames, e.Frames()...)

				var after *Exchange
				for _, g := range t.GETs(href) {
					if g.Req == nil || g.Resp == nil {
						continue
					}
					if !pushedAt.IsZero() && !g.Req.Time.After(pushedAt) {
						continue
					}
					c := g
					after = &c
					break
				}
				if after == nil {
					missing = append(missing, href)
					continue
				}
				frames = append(frames, after.Frames()...)
				checked = append(checked, href)
				if payload == nil {
					continue
				}
				got, gerr := after.Resp.SEP()
				if gerr != nil {
					differing = append(differing, href+" (the re-fetched body did not parse as sep+xml)")
					continue
				}
				if d := sameResource(payload, got); d != "" {
					differing = append(differing, href+" ("+d+")")
				}
			}
			switch {
			case len(checked) == 0 && len(missing) == 0:
				return unavailable("the notification leg carries no Notification naming a subscribedResource, " +
					"so there is no href for this criterion to be about")
			case len(missing) > 0:
				return found(certify.Fail, dedupeInts(frames),
					"the DUT did not GET %d of the %d notified href(s) after the push: %s. The procedure "+
						"requires the client to fetch the resource the Notification named",
					len(missing), len(missing)+len(checked), strings.Join(dedupeStrings(missing), ", "))
			case len(differing) > 0:
				return found(certify.Fail, dedupeInts(frames),
					"the DUT re-fetched every notified href but the server's answer is not identical to the "+
						"Notification body it was sent: %s", strings.Join(differing, "; "))
			default:
				return found(certify.Pass, dedupeInts(frames),
					"the DUT GETed each of %s after the Notification that named it, and the payload the server "+
						"returned matches the Notification body", strings.Join(dedupeStrings(checked), ", "))
			}
		},
		Skip: "this criterion compares a payload the SERVER dialled out with one the DUT fetched, so it needs " +
			"both legs of the conversation decrypted. " + notificationGap,
	}
}

// sameResource compares a Notification's <Resource> payload with the resource
// the server served for the same href, and returns "" when they agree.
//
// It compares the CHILD ELEMENTS rather than the bytes, and the reason is in
// sep.xsd: a Notification carries the subscribed resource as
// <Resource xsi:type="DERControlList"> — a differently-named element with the
// same children — so a byte comparison would report every conformant server as
// non-conformant. What the procedure means by "identical" is the resource, and
// the resource is its children.
func sameResource(pushed, fetched *Node) string {
	pk, fk := childNames(pushed), childNames(fetched)
	if len(pk) != len(fk) {
		return fmt.Sprintf("the Notification carried %d child element(s) and the re-fetched resource has %d",
			len(pk), len(fk))
	}
	for i := range pk {
		if pk[i] != fk[i] {
			return fmt.Sprintf("child %d is <%s> in the Notification and <%s> in the re-fetched resource",
				i, pk[i], fk[i])
		}
	}
	return ""
}

func childNames(n *Node) []string {
	if n == nil {
		return nil
	}
	out := make([]string, 0, len(n.Kids))
	for _, k := range n.Kids {
		out = append(out, k.Local())
	}
	sort.Strings(out)
	return out
}

// critOneNotificationPerChange is CORE-019 read through Annex A seq 42, which
// REMOVES printed steps 10 and 11: a change to a SUBORDINATE resource requires
// ONE Notification, not a second one for the parent EndDevice.
//
// The erratum's effect is on the HARNESS, not on the DUT — a check that waited
// for the parent notification would hang and then report a conformant client as
// failing — so what is asserted is the count the server actually produced.
func critOneNotificationPerChange(o *Observation) criterion {
	return criterion{
		Claim: "a change to a subordinate resource produces exactly ONE Notification — not a " +
			"second one for the parent EndDevice",
		How: "the count of Notification POSTs the server sends for a single subordinate change, " +
			"per Annex A seq 42 which removes printed steps 10 and 11",
		Server: func(v *ServerView) Finding {
			if !v.Status.Subscription.Enabled {
				return unavailable("%s", subscriptionOff)
			}
			if len(v.Notifications) == 0 {
				return unavailable("gridsim pushed no Notification in this window, so there is no count to "+
					"take: %s", pushSummary(v))
			}
			perResource := map[string][]int64{}
			for _, n := range v.Notifications {
				r := trimHref(n.SubscribedResource)
				perResource[r] = append(perResource[r], n.At)
			}
			var dup []string
			for r, ats := range perResource {
				if len(ats) > 1 {
					dup = append(dup, fmt.Sprintf("%s (%d)", r, len(ats)))
				}
			}
			sort.Strings(dup)
			if len(dup) > 0 {
				return Finding{Verdict: certify.Warn,
					Observed: fmt.Sprintf("gridsim pushed %d Notification(s) across %d resource(s), and more "+
						"than one for %s. That is a repeat over the whole window rather than a second "+
						"notification for one change — this check makes one change — so it is reported, not "+
						"failed", len(v.Notifications), len(perResource), strings.Join(dup, ", "))}
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("gridsim pushed exactly one Notification per changed resource (%d in "+
					"all: %s). No second Notification for a parent EndDevice appears, which is what Annex A "+
					"seq 42 corrected the printed procedure to expect",
					len(v.Notifications), describeResources(v.Notifications))}
		},
		Skip: notificationGap,
	}
}

func describeResources(recs []AdminNotification) string {
	var out []string
	for _, r := range recs {
		out = append(out, trimHref(r.SubscribedResource))
	}
	sort.Strings(out)
	return strings.Join(dedupeStrings(out), ", ")
}

func intStrings(v []int) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.Itoa(x)
	}
	return out
}
