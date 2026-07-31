package suitecsip

// core.go implements the applicable CORE-* rows: the discovery walk, time,
// registration, function-set assignments, DER programs and controls, event
// randomization, Responses and superseding.
//
// These are the rows where the bench's fixture shape matters most. Several of
// them specify a server the procedure's author configured by hand — seven
// DERPrograms with primacy 4..10 (CORE-010), fifteen FunctionSetAssignments
// (CORE-011), ten DERPrograms with primacy 1..10 (CORE-013) — and gridsim
// builds three programs and one FSA. Where that gap bites, the criterion
// reports the shape the bench actually served and SKIPs rather than passing the
// DUT on a test it was never given. The generic criteria in the same row still
// assert, so these rows are partial evidence with an explicit boundary, which
// is what they honestly are.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// rounding is the precision durations are reported at. Sub-second precision in
// a report line about a multi-minute poll cycle is noise.
const rounding = time.Second

// corePolling implements CORE-003 — Polling Interaction.
func corePolling(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pin, _ := rc.Param(pinParam)
	return run(ctx, rc, spec{
		// CORE-003's erratum (seq 40) adds a setup item: a DERProgram must be
		// associated with the primary end device's topology grouping, or the
		// walk under test has nothing to poll. gridsim's static tree already
		// carries three programs, so the erratum is satisfied by the bench's
		// resting state and the check does not need to create one — but it does
		// need to SAY so, which is what the note does.
		Notes: func(o *Observation) string {
			return fmt.Sprintf("polling walk observed over %s; the procedure's erratum (seq 40) requires a "+
				"DERProgram associated with the end device's topology group, which gridsim's resting tree "+
				"already provides", o.Waited.Round(rounding))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critEndDeviceList(0),
				critRegistrationPIN(pin),
				critFSAList(0),
				critProgramList(0),
				critDefaultDERControl(),
				critPollRate(),
			}
		},
	})
}

// coreBasicTime implements CORE-005 — Basic Time.
func coreBasicTime(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "Time function set: discovery of the TimeLink and retrieval of the Time resource"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				{
					Claim: "the DeviceCapability the server returned carries a TimeLink, and the DUT followed it",
					How: "the TimeLink element of the DeviceCapability payload, and a subsequent request whose " +
						"path equals that link's href",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						e, doc, ok := t.Resource("DeviceCapability")
						if !ok {
							return unavailable("no DeviceCapability appears in the recovered transcript")
						}
						links := doc.Descendants("TimeLink")
						if len(links) == 0 {
							return citeMessage(t, e.Resp, certify.Fail,
								"the DeviceCapability carries no TimeLink, so the Time function set is unreachable")
						}
						href := links[0].Href()
						for _, ex := range t.GETs(href) {
							return citeExchange(t, ex, certify.Pass,
								"DeviceCapability advertised TimeLink href=%q and the DUT fetched it: %s",
								href, ex.String())
						}
						return citeMessage(t, e.Resp, certify.Fail,
							"the DeviceCapability advertised TimeLink href=%q but the DUT never requested it "+
								"(paths requested: %s)", href, strings.Join(t.Paths(), " "))
					},
				},
				critTimeResource(),
				{
					Claim: "the DUT used the server's time rather than its own: its subsequent requests are " +
						"consistent with the server-supplied currentTime",
					How: "comparison of the Time resource's currentTime with the capture timestamp of the " +
						"request that fetched it",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						e, doc, ok := t.Resource("Time")
						if !ok {
							return unavailable("no Time resource appears in the recovered transcript")
						}
						ct, has := doc.IntOf("currentTime")
						if !has || e.Resp.Time.IsZero() {
							return unavailable("the Time payload or its capture timestamp is missing")
						}
						skew := e.Resp.Time.Sub(time.Unix(ct, 0))
						return citeMessage(t, e.Resp, certify.Warn,
							"the server served currentTime=%d and the capture stamped that response at %s, a "+
								"difference of %s. Whether the DUT then SET ITS CLOCK is a property of the "+
								"device's internal state, not of the wire; this run reports the skew the DUT "+
								"was told about rather than asserting an internal effect it cannot observe",
							ct, e.Resp.Time.UTC().Format(time.RFC3339), skew.Round(time.Millisecond))
					},
					Skip: "the client's clock adjustment is internal to the DUT and is not observable from the " +
						"2030.5 exchange",
				},
			}
		},
	})
}

// coreAdvancedEndDevice implements CORE-009 — Advanced End Device.
//
// The row's own printed pass criterion for the DER self-report element is
// DISJUNCTIVE (CTP v1.3 pp.41-42: "did an HTTP PUT [of] DERCapabilities,
// DERSettings, DERStatus or DERAvailability") — a lone, cadence-driven
// DERStatus PUT satisfies it in full, with no lever needed at all. critDERPut
// per resource would grade that as three FAILs and one PASS, holding the row
// to a standard stricter than its own text; critDERPutAny is the criterion
// that actually decides it, and the four critDERPutInformational entries stay
// only as per-resource notes (WARN, never FAIL) on which of the four arrived.
//
// The re-home Change (see rehome.go / coreDERSettings below) is belt and
// braces here, not a requirement: it gives this row a real shot at the
// STRONGER evidence — a capability/settings PUT, not just status — within its
// own window, but the row must PASS without it too, since CORE-009's printed
// criterion does not require gridsim's admin API at all.
func coreAdvancedEndDevice(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pin, _ := rc.Param(pinParam)
	return run(ctx, rc, spec{
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			capHref, setHref, err := d.RehomeDER(ctx)
			if err != nil {
				return err
			}
			params["rehome_cap_href"] = capHref
			params["rehome_set_href"] = setHref
			params["rehome_at"] = time.Now().UTC().Format(time.RFC3339)
			return nil
		},
		ChangeWait: changeWaitFullCycle,
		Notes: func(o *Observation) string {
			return fmt.Sprintf("EndDevice walk and DER self-report PUTs; %d DER PUT(s) recorded server-side "+
				"during the window", len(o.Server.DERPuts)) + rehomeNote(o)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critEndDeviceList(0),
				critSelfIdentity(),
				critRegistrationPIN(pin),
				critResource("DERList", "the DUT fetched the DERList reached from its EndDevice's DERListLink "+
					"and the server answered 200", nil),
				critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability"),
				critDERPutInformational("DERCapability"),
				critDERPutInformational("DERSettings"),
				critDERPutInformational("DERStatus"),
				critDERPutInformational("DERAvailability"),
			}
		},
	})
}

// rehomeNote renders the CORE-009/CORE-014 narrative addendum recording that
// gridsim — the TEST SERVER, not the DUT — performed a scripted re-home
// (rehome.go), so a reader of the bundle does not mistake the DUT's resulting
// DERCapability/DERSettings PUTs for a spontaneous event or the DUT for
// having been perturbed.
//
// Empty when the case's Change hook never ran: no gridsim admin API was
// configured, or the call failed (obs.Params[changeFailed] already carries
// that reason, logged by the runner separately).
func rehomeNote(o *Observation) string {
	at := o.Param("rehome_at")
	if at == "" {
		return ""
	}
	return fmt.Sprintf(". The bench's 2030.5 TEST SERVER (gridsim) performed a SCRIPTED resource re-home at "+
		"%s, moving the DUT's DERCapability and DERSettings to fresh hrefs (%s and %s) mid-case — a "+
		"test-server action, not a DUT perturbation, and the same species of lever the CTP itself scripts on "+
		"the server side (ERR-002's own scripted server power-reset). CSIP IG §6.3.5.2 requires the client "+
		"to PUT DERCapability/DERSettings 'at device start-up and on any changes'; the DUT already satisfied "+
		"that once, at start-up, before this window opened, and had no other reason to repeat it unprompted "+
		"until the SERVER changed the resource out from under it",
		at, o.Param("rehome_cap_href"), o.Param("rehome_set_href"))
}

// coreFSA implements CORE-010 — Function Set Assignments.
func coreFSA(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pin, _ := rc.Param(pinParam)
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "function-set-assignment walk to the DERProgramList; the procedure's seven-program " +
				"topology fixture is not what this bench serves — see the DERProgramList assertion"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critEndDeviceList(3),
				critRegistrationPIN(pin),
				critFSAList(0),
				critResource("FunctionSetAssignments", "the DUT fetched a FunctionSetAssignments instance "+
					"carrying both a DERProgramListLink and a TimeLink",
					func(doc *Node) (certify.Verdict, string) {
						switch {
						case !doc.Has("DERProgramListLink"):
							return certify.Fail, "no DERProgramListLink"
						case !doc.Has("TimeLink"):
							return certify.Warn, "a DERProgramListLink but no TimeLink; IEEE 2030.5 §9.2.3 " +
								"requires one on an FSA carrying an event-based function set"
						default:
							return certify.Pass, "DERProgramListLink and TimeLink both present"
						}
					}),
				critProgramList(7),
			}
		},
	})
}

// coreAdvancedFSA implements CORE-011 — Advanced Function Set Assignments.
func coreAdvancedFSA(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pin, _ := rc.Param(pinParam)
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "the fifteen-FSA scale case (CSIP P27); the bench serves one FSA, so the scale criterion " +
				"reports the shape it saw and skips"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critDiscoveryRoot(),
				critEndDeviceList(3),
				critRegistrationPIN(pin),
				critFSAList(15),
				critProgramList(0),
				{
					Claim: "the DUT selected the highest-priority DERProgram — the lowest primacy value, with " +
						"the mRID descending tiebreak — before fetching its subordinate resources",
					How: "the order of the DUT's requests after the DERProgramList, compared with the primacy " +
						"values in the list the server served",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						e, doc, ok := t.Resource("DERProgramList")
						if !ok {
							return unavailable("no DERProgramList appears in the recovered transcript")
						}
						progs := doc.Children("DERProgram")
						if len(progs) < 2 {
							return unavailable("the server served %d DERProgram(s); a priority-ordering "+
								"criterion needs at least two", len(progs))
						}
						best, bestPrim := "", int64(1<<62)
						for _, p := range progs {
							prim, has := p.IntOf("primacy")
							if !has {
								continue
							}
							if prim < bestPrim {
								bestPrim, best = prim, p.Href()
							}
						}
						if best == "" {
							return citeMessage(t, e.Resp, certify.Fail,
								"no DERProgram in the list carries a primacy, so priority cannot be determined")
						}
						for _, ex := range t.Exchanges {
							if ex.Req != nil && strings.HasPrefix(ex.Req.Path, best) {
								return citeExchange(t, ex, certify.Pass,
									"the lowest-primacy DERProgram is %s (primacy %d) and the DUT fetched %s",
									best, bestPrim, ex.Req.Line())
							}
						}
						return citeMessage(t, e.Resp, certify.Warn,
							"the lowest-primacy DERProgram is %s (primacy %d); the DUT fetched %s and did not "+
								"request it within this window. A client that walks every program is not "+
								"non-conformant, so this is reported rather than failed",
							best, bestPrim, strings.Join(t.Paths(), " "))
					},
				},
			}
		},
	})
}

// coreDERProgram implements CORE-012 — Basic DER Program/Control.
func coreDERProgram(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	const mrid = "CERT-CORE012"
	return run(ctx, rc, spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The procedure wants an event starting in the near future so the
			// DUT is observed fetching it BEFORE it becomes active. Three
			// minutes is the procedure's own figure.
			id, err := d.PostControl(ctx, ControlRequest{
				Program: 0, MRID: mrid, Description: "CORE-012 scheduled control",
				StartOffset: 180, DurationS: 120, MaxLimW: ptr(int64(6000)),
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		Cleanup: func(ctx context.Context, d *Driver) { _ = d.ClearControls(ctx, 0) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published DERControl %s (start +180 s, duration 120 s) and waited %s for the "+
				"DUT to fetch it", o.Param("mrid"), o.Waited.Round(rounding))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critProgramList(0),
				critResource("DERControlList", "the DUT fetched the DERControlList of the DERProgram and the "+
					"server answered 200 with the scheduled control", func(doc *Node) (certify.Verdict, string) {
					ctrls := doc.Children("DERControl")
					for _, c := range ctrls {
						if m, _ := c.TextOf("mRID"); m == o.Param("mrid") {
							start, _ := c.Path("interval").IntOf("start")
							dur, _ := c.Path("interval").IntOf("duration")
							return certify.Pass, fmt.Sprintf("the control this check published (mRID %s) is in "+
								"the list, interval start=%d duration=%d", m, start, dur)
						}
					}
					return certify.Fail, fmt.Sprintf("the list carries %d control(s) but not the mRID this "+
						"check published (%s)", len(ctrls), o.Param("mrid"))
				}),
				critDefaultDERControl(),
				critResource("DERCurveList", "the DUT fetched the DERCurveList of the DERProgram", nil),
				critPollRate(),
			}
		},
	})
}

// coreAdvancedDERProgram implements CORE-013 — Advanced DER Program/Control.
func coreAdvancedDERProgram(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The procedure's ten programs with primacy 1..10 cannot be built:
			// gridsim's program set is fixed at three. What CAN be exercised is
			// the fixed-power-factor mode the row's controls carry, published
			// on each of the three programs the bench does have.
			for p := 0; p < 3; p++ {
				mrid := fmt.Sprintf("CERT-CORE013-%d", p)
				if _, err := d.PostControl(ctx, ControlRequest{
					Program: p, MRID: mrid, Description: "CORE-013 fixed PF control",
					StartOffset: 60 * (p + 1), DurationS: 30, FixedPFInjectW: ptr(int64(95)),
				}); err != nil {
					return err
				}
			}
			params["programs"] = "3"
			return nil
		},
		Cleanup: func(ctx context.Context, d *Driver) {
			for p := 0; p < 3; p++ {
				_ = d.ClearControls(ctx, p)
			}
		},
		Notes: func(o *Observation) string {
			return "published one fixed-power-factor control per DERProgram; the procedure's ten-program " +
				"fixture is beyond what this bench's server can build"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critProgramList(10),
				critDERControlCarriesMode("opModFixedPFInjectW",
					"the DUT fetched a DERControl carrying the fixed-power-factor (injecting) control mode"),
				critDefaultDERControl(),
				critPollRate(),
			}
		},
	})
}

// coreDERSettings implements CORE-014 — Basic DER Settings (Power Generating).
//
// CORE-014 exists to observe the DUT's DERCapability/DERSettings PUTs, and
// CSIP IG §6.3.5.2 has the DUT send those only "at device start-up and on any
// changes" — which, hours into a capture window opened long after boot, have
// already happened and left no further trace to catch. The Change hook
// re-homes the DER's DERCapability/DERSettings hrefs (rehome.go) AFTER the
// initial discovery walk has already been observed at the ORIGINAL hrefs
// (this spec sets no Setup/Want, so run() takes the default AwaitWalk path
// first) — giving the DUT's NEXT walk a change to notice and re-announce,
// which is exactly what CORE-009/CORE-014 are written to catch and what a
// window opened long after boot otherwise cannot.
func coreDERSettings(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			capHref, setHref, err := d.RehomeDER(ctx)
			if err != nil {
				return err
			}
			params["rehome_cap_href"] = capHref
			params["rehome_set_href"] = setHref
			params["rehome_at"] = time.Now().UTC().Format(time.RFC3339)
			return nil
		},
		// A second FULL poll cycle, not the short settle: the DUT notices the
		// href change on its NEXT discovery walk, and a client pacing at
		// poll_rate_mode=honor is entitled to take its whole interval to make it.
		// The short settle would measure the harness's patience, not the DUT's
		// conformant cadence. See maintControls (aggregator.go) for the same
		// sentinel used for the same reason.
		ChangeWait: changeWaitFullCycle,
		Notes: func(o *Observation) string {
			return fmt.Sprintf("DER self-report: %d DERCapability and %d DERSettings PUT(s) recorded "+
				"server-side during the window",
				len(o.Server.PutsFor("DERCapability")), len(o.Server.PutsFor("DERSettings"))) + rehomeNote(o)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResource("DERList", "the DUT fetched the DERList and the server answered 200", nil),
				critDERPut("DERCapability"),
				critDERPut("DERSettings"),
				critNameplateConsistency(),
			}
		},
	})
}

// critNameplateConsistency checks CORE-014's numeric relations BETWEEN the two
// payloads the DUT reported: settings may not exceed ratings.
//
// This is the one criterion in the suite that judges the DUT's own numbers
// rather than the server's, and it can do so from either tier: the PUT bodies
// are in the transcript when it decrypts, and gridsim stores them verbatim when
// it does not — so the same arithmetic runs on the same bytes either way.
func critNameplateConsistency() criterion {
	compare := func(cap, set *Node) (certify.Verdict, string) {
		type rel struct {
			setting, rating string
			mustNotExceed   bool
		}
		rels := []rel{
			{"setMaxW", "rtgMaxW", true},
			{"setMaxVA", "rtgMaxVA", true},
			{"setMaxVAr", "rtgMaxVAr", true},
		}
		var problems, checked []string
		for _, r := range rels {
			sv, sok := valueOf(set, r.setting)
			rv, rok := valueOf(cap, r.rating)
			if !sok || !rok {
				continue
			}
			checked = append(checked, fmt.Sprintf("%s=%d vs %s=%d", r.setting, sv, r.rating, rv))
			if r.mustNotExceed && sv > rv {
				problems = append(problems, fmt.Sprintf("%s (%d) exceeds %s (%d)", r.setting, sv, r.rating, rv))
			}
		}
		switch {
		case len(checked) == 0:
			return certify.Skip, "neither payload carries a comparable rating/setting pair"
		case len(problems) > 0:
			return certify.Fail, "the DUT reported settings above its own ratings: " + strings.Join(problems, "; ")
		default:
			return certify.Pass, "settings are within ratings: " + strings.Join(checked, ", ")
		}
	}
	return criterion{
		Claim: "the DER settings the DUT reported do not exceed the ratings it reported: setMaxW ≤ rtgMaxW, " +
			"setMaxVA ≤ rtgMaxVA, setMaxVAr ≤ rtgMaxVAr",
		How: "the numeric relations of CORE-014 evaluated across the DERCapability and DERSettings payloads " +
			"the DUT itself PUT",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			var capDoc, setDoc *Node
			var last *Message
			for _, e := range t.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil {
					continue
				}
				switch doc.Local() {
				case "DERCapability":
					capDoc, last = doc, e.Req
				case "DERSettings":
					setDoc, last = doc, e.Req
				}
			}
			if capDoc == nil || setDoc == nil {
				return unavailable("the transcript holds %s", missingPair(capDoc, setDoc))
			}
			v, desc := compare(capDoc, setDoc)
			return citeMessage(t, last, v, "%s", desc)
		},
		Server: func(v *ServerView) Finding {
			capPuts, setPuts := v.PutsFor("DERCapability"), v.PutsFor("DERSettings")
			if len(capPuts) == 0 || len(setPuts) == 0 {
				return unavailable("gridsim recorded %d DERCapability and %d DERSettings PUT(s); both are "+
					"needed to compare them", len(capPuts), len(setPuts))
			}
			capDoc, cerr := ParseSEP([]byte(capPuts[len(capPuts)-1].Body))
			setDoc, serr := ParseSEP([]byte(setPuts[len(setPuts)-1].Body))
			if cerr != nil || serr != nil {
				return Finding{Verdict: certify.Fail,
					Observed: fmt.Sprintf("a stored PUT body did not parse: %v %v", cerr, serr)}
			}
			verdict, desc := compare(capDoc, setDoc)
			return Finding{Verdict: verdict,
				Observed: desc + " (evaluated on the bodies gridsim stored, not on the wire)"}
		},
	}
}

func missingPair(capDoc, setDoc *Node) string {
	switch {
	case capDoc == nil && setDoc == nil:
		return "neither a DERCapability nor a DERSettings PUT"
	case capDoc == nil:
		return "a DERSettings PUT but no DERCapability PUT"
	default:
		return "a DERCapability PUT but no DERSettings PUT"
	}
}

// valueOf reads a 2030.5 scaled value: either a bare integer element or the
// <value>/<multiplier> pair the DERCapability/DERSettings types use.
func valueOf(n *Node, name string) (int64, bool) {
	el := n.Child(name)
	if el == nil {
		ds := n.Descendants(name)
		if len(ds) == 0 {
			return 0, false
		}
		el = ds[0]
	}
	if v, ok := el.IntOf("value"); ok {
		mult, _ := el.IntOf("multiplier")
		scaled := v
		for i := int64(0); i < mult; i++ {
			scaled *= 10
		}
		for i := int64(0); i > mult; i-- {
			scaled /= 10
		}
		return scaled, true
	}
	if el.Text == "" {
		return 0, false
	}
	return parseInt(el.Text)
}

func parseInt(s string) (int64, bool) {
	var v int64
	neg := false
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	for i, r := range s {
		if i == 0 && (r == '-' || r == '+') {
			neg = r == '-'
			continue
		}
		if r < '0' || r > '9' {
			return 0, false
		}
		v = v*10 + int64(r-'0')
	}
	if neg {
		v = -v
	}
	return v, true
}

// coreRandomizedEvents implements CORE-021 — Randomized Events.
func coreRandomizedEvents(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The procedure's three controls carry randomizeStart 0, +30 and
			// -30 seconds. gridsim serves randomizeStart/randomizeDuration
			// straight through, so all three are reachable.
			for i, rnd := range []int32{0, 30, -30} {
				mrid := fmt.Sprintf("CERT-CORE021-%d", i)
				if _, err := d.PostControl(ctx, ControlRequest{
					Program: 0, MRID: mrid, Description: "CORE-021 randomized control",
					StartOffset: 120 + 60*i, DurationS: 60, MaxLimW: ptr(int64(5000)),
					RandomizeStart: &rnd,
				}); err != nil {
					return err
				}
			}
			return nil
		},
		Cleanup: func(ctx context.Context, d *Driver) { _ = d.ClearControls(ctx, 0) },
		Notes: func(o *Observation) string {
			return "published three controls with randomizeStart 0/+30/-30 s"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				{
					Claim: "the DUT received DERControls carrying randomizeStart values, which IEEE 2030.5 " +
						"§10.2.3 requires it to apply",
					How:             "the <randomizeStart> elements of the DERControls in the DERControlList the DUT fetched",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						e, doc, ok := t.Resource("DERControlList")
						if !ok {
							return unavailable("no DERControlList appears in the recovered transcript")
						}
						var vals []string
						for _, c := range doc.Children("DERControl") {
							if v, has := c.IntOf("randomizeStart"); has {
								m, _ := c.TextOf("mRID")
								vals = append(vals, fmt.Sprintf("%s:%+d", m, v))
							}
						}
						if len(vals) == 0 {
							return citeMessage(t, e.Resp, certify.Fail,
								"none of the %d control(s) the DUT fetched carries a randomizeStart",
								len(doc.Children("DERControl")))
						}
						return citeMessage(t, e.Resp, certify.Pass,
							"%d control(s) carry randomizeStart: %s", len(vals), strings.Join(vals, " "))
					},
				},
				{
					Claim: "the DUT applied the randomization: its activation of each event is offset from " +
						"interval/start by the event's randomizeStart",
					How: "the capture timestamp of the DUT's status=2 (Started) Response for each control, " +
						"compared with the control's interval start plus its randomizeStart",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						return unavailable("no status=2 Response was recovered for a randomized control in " +
							"this window")
					},
					Skip: "the DUT's activation instant is observable only through a status=2 (Started) " +
						"Response POST, and only for a control whose responseRequired asks for one. " +
						"gridsim's admin control API does not expose responseRequired, so this bench cannot " +
						"ask the DUT to announce its start instant and cannot measure the applied " +
						"randomization from the wire",
				},
			}
		},
	})
}

// coreResponses implements CORE-022 — Responses.
//
// mrid carries the per-run nonce (withRunNonce, register.go) for the same
// reason BASIC-017..026's event-precedence scenarios do (see
// eventScenario.withNonce and withRunNonce's doc): lexa-gw's Response tracker
// dedupes Received(1) — and the rest of the lifecycle — on the bare mRID
// string, retained for the process's whole lifetime AND persisted to disk. A
// long-lived bench that re-runs CORE-022 against the SAME hardcoded
// "CERT-CORE022" therefore never re-earns a status=1 Response, so
// critResponsePosted (assertion 1) FAILs on every run after the first
// regardless of what the DUT does today — not because the DUT stopped
// answering, but because it already answered once, under this exact mRID,
// and correctly declines to answer twice. Per-mRID duplicate suppression is a
// defensible 2030.5 posture, and a genuinely fresh event is what a real ATL
// run would present too, so a re-runnable conformance harness must do the
// same rather than let a stale artifact of its own bench manufacture a FAIL.
// This is not masking a defect: the separate, still-open product question —
// should a same-mRID event carrying a bumped version re-earn responses? — is
// tracked independently and is untouched by this change.
func coreResponses(nonce string) certify.Check {
	s := coreResponsesSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// coreResponsesSpec builds CORE-022's spec for a given per-run nonce. It is
// factored out of coreResponses so a test can drive its Setup/Want directly
// against a fake gridsim (see nonce_test.go) without booting the whole check,
// which needs a live capture window run() cannot fake.
func coreResponsesSpec(nonce string) spec {
	mrid := withRunNonce("CERT-CORE022", nonce)
	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			id, err := d.PostControl(ctx, ControlRequest{
				Program: 0, MRID: mrid, Description: "CORE-022 response control",
				StartOffset: 0, DurationS: 120, MaxLimW: ptr(int64(4000)), Activate: true,
			})
			if err != nil {
				return err
			}
			params["mrid"] = id
			return nil
		},
		Want: func(base ServerView) func(ServerView) bool {
			// Wait for the DUT to acknowledge receipt, which is the first
			// Response of the lifecycle and the one that proves the event
			// reached it at all. WantNewResponse (not a bare
			// len(v.ResponsesFor(mrid))>0) so a Response left over from an
			// EARLIER run against this same mRID — the shape of a focused
			// single-case re-run — cannot satisfy this before the DUT has
			// even seen the control THIS run just posted. Belt-and-braces
			// with the nonce above: WantNewResponse guards the HARNESS's
			// read of a stale Response, the nonce guards the DUT ever
			// having one to read in the first place.
			return base.WantNewResponse(mrid)
		},
		Cleanup: func(ctx context.Context, d *Driver) { _ = d.ClearControls(ctx, 0) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published an immediate DERControl (%s) and waited %s; statuses received: %v",
				mrid, o.Waited.Round(rounding), o.Server.ResponseStatuses(mrid))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResponsePosted(1, "Event received", mrid),
				critResponseStarted(mrid),
				{
					Claim: "the DUT POSTs its Responses to the replyTo URI the event carried, not to a " +
						"hard-coded path",
					How: "the request target of each Response POST compared with the replyTo attribute of the " +
						"DERControl it acknowledges",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						replyTo := map[string]string{}
						for _, e := range t.ByResource("DERControlList") {
							doc, err := e.Resp.SEP()
							if err != nil {
								continue
							}
							for _, c := range doc.Children("DERControl") {
								m, _ := c.TextOf("mRID")
								if rt, ok := c.Attr("replyTo"); ok {
									replyTo[m] = rt
								}
							}
						}
						for _, e := range t.Method("POST") {
							doc, err := e.Req.SEP()
							if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
								continue
							}
							subj, _ := doc.TextOf("subject")
							want, known := replyTo[subj]
							if !known {
								return citeMessage(t, e.Req, certify.Warn,
									"the DUT POSTed a Response for subject %s to %s, but the DERControl carrying "+
										"that mRID and its replyTo was not recovered in this window",
									subj, e.Req.Path)
							}
							v := certify.Fail
							if e.Req.Path == want {
								v = certify.Pass
							}
							return citeMessage(t, e.Req, v,
								"Response for %s POSTed to %s; the event's replyTo is %s", subj, e.Req.Path, want)
						}
						return unavailable("the recovered transcript holds no Response POST")
					},
				},
				{
					Claim: "the DUT reports the event lifecycle: statuses 1 (received), 2 (started) and " +
						"3 (completed), and 6 (cancelled) for an event the server cancels",
					How: "the set of Response statuses received for the control under test",
					Server: func(v *ServerView) Finding {
						got := v.ResponseStatuses(mrid)
						if len(got) == 0 {
							if !v.SessionEstablished() {
								return noSessionUnavailable()
							}
							return Finding{Verdict: certify.Fail,
								Observed: "gridsim received no Response for the control this check published"}
						}
						return Finding{Verdict: certify.Warn,
							Observed: fmt.Sprintf("statuses %v were received within the check's window. The full "+
								"1/2/3 lifecycle needs the window to span the event's whole 120 s interval and "+
								"the 6 (cancelled) case needs a server-side cancel; raise -param %s to span it",
								got, waitParam)}
					},
				},
			}
		},
	}
}

// coreSupersedingWant builds CORE-023's live-phase wait predicate: a
// genuinely NEW Response (WantNewResponse, so a stale one from an earlier run
// against this same hardcoded mRID pair does not short-circuit it — see
// WantNewResponse's doc, audit 2026-07-30) for BOTH winner and loser, not the
// loser alone.
//
// Waiting on the loser alone was the bug (audit 2026-07-30/31,
// runs/perphase-core023-v4-20260730T235854): gridsim resolves an overlapping
// pair's loser to Superseded(7) at ARBITRATION time, which happens the first
// walk after Setup and is independent of either control's own StartOffset —
// so the loser typically earns its Response within one poll cycle. The
// winner's own interval (StartOffset 30s, DurationS 120s here) does not even
// END until Setup+150s. A Want keyed on the loser alone therefore reports
// satisfied, and with it ends the live phase — and the capture shortly after
// — while the winner has posted nothing at all: the cited run's capture
// closed 61s after Setup, but the winner's own end-of-event Response (a
// NoParticipation(10), per gridsim's admin log and the DUT's own journal)
// did not land until roughly two minutes later, entirely outside the window
// that run ever captured. CORE-023's own assertions 1/2 grade the WINNER
// (critResponsePosted(1, ..., winner), critResponseStarted(winner)) — a
// window that structurally cannot contain the winner's Response traffic can
// never pass them, no matter what the DUT does. Waiting for a fresh Response
// on BOTH mRIDs gives the winner's own lifecycle at least one chance to reach
// the wire before the check calls itself done.
func coreSupersedingWant(winner, loser string) func(base ServerView) func(ServerView) bool {
	return func(base ServerView) func(ServerView) bool {
		wantWinner := base.WantNewResponse(winner)
		wantLoser := base.WantNewResponse(loser)
		return func(v ServerView) bool { return wantWinner(v) && wantLoser(v) }
	}
}

// coreSuperseding implements CORE-023 — Superseding Events.
//
// winner and loser carry the per-run nonce (withRunNonce, register.go) for
// the same reason coreResponses' mrid does (see its doc): lexa-gw's Response
// tracker dedupes Received(1) — and the rest of the lifecycle — on the bare
// mRID string, retained for the process's whole lifetime AND persisted to
// disk. A long-lived bench that re-runs CORE-023 against the SAME hardcoded
// "CERT-CORE023-WIN"/"CERT-CORE023-LOSE" pair never re-earns fresh Responses
// for either one, so assertions 1/2 (critResponsePosted/critResponseStarted,
// both graded against the winner) FAIL on every run after the first
// regardless of DUT behavior today. Per-mRID duplicate suppression is a
// defensible 2030.5 posture — a real ATL run's genuinely fresh events would
// sidestep it too — so a re-runnable harness must present fresh mRIDs each
// run rather than let its own bench manufacture a FAIL. This does not mask a
// defect: the separate, still-open product question of whether a same-mRID
// event with a bumped version should re-earn responses is tracked
// independently.
func coreSuperseding(nonce string) certify.Check {
	s := coreSupersedingSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// coreSupersedingSpec builds CORE-023's spec for a given per-run nonce. Like
// coreResponsesSpec, it is factored out of coreSuperseding so a test can drive
// Setup/Want directly against a fake gridsim (see nonce_test.go) without
// booting the whole check.
func coreSupersedingSpec(nonce string) spec {
	winner := withRunNonce("CERT-CORE023-WIN", nonce)
	loser := withRunNonce("CERT-CORE023-LOSE", nonce)
	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			// Two controls with the SAME interval on programs of different
			// primacy. gridsim's creation_offset_s gives the pair a
			// deterministic winner rather than relying on the wall-clock gap
			// between two POSTs.
			older := -60
			if _, err := d.PostControl(ctx, ControlRequest{
				Program: 2, MRID: loser, Description: "CORE-023 superseded control",
				StartOffset: 30, DurationS: 120, MaxLimW: ptr(int64(3000)),
				CreationOffsetS: &older, PotentiallySuperseded: ptr(true),
			}); err != nil {
				return err
			}
			if _, err := d.PostControl(ctx, ControlRequest{
				Program: 0, MRID: winner, Description: "CORE-023 superseding control",
				StartOffset: 30, DurationS: 120, MaxLimW: ptr(int64(2000)),
			}); err != nil {
				return err
			}
			params["winner"], params["loser"] = winner, loser
			return nil
		},
		Want: coreSupersedingWant(winner, loser),
		Cleanup: func(ctx context.Context, d *Driver) {
			_ = d.ClearControls(ctx, 0)
			_ = d.ClearControls(ctx, 2)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published two same-interval controls of different primacy; winner %s statuses "+
				"%v, loser %s statuses %v", winner, o.Server.ResponseStatuses(winner),
				loser, o.Server.ResponseStatuses(loser))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResponsePosted(1, "Event received", winner),
				// Matches CORE-022's status=1-then-status=2 shape (core.go's
				// coreResponses): the winner is a plain, unsuperseded control, so
				// the DUT reporting it started is exactly critResponseStarted's
				// claim, graded/degraded the same way — Pass/Fail when the
				// winner's captured responseRequired asked for a specific
				// response (which admin-created controls do by default — see
				// sim/gridsim/admin.go's adminDefaultResponseRequired), else
				// Unavailable/Skip, never a false FAIL blaming the DUT for a bit
				// this bench didn't ask for.
				critResponseStarted(winner),
				{
					Claim: "the DUT reports status 7 (Superseded) or 14 (Aborted due to alternate program " +
						"event) for the losing control of an overlapping pair",
					How: "the Response statuses received for the lower-priority control of the two the check " +
						"published with identical intervals",
					Server: func(v *ServerView) Finding {
						got := v.ResponseStatuses(loser)
						if len(got) == 0 {
							if !v.SessionEstablished() {
								return noSessionUnavailable()
							}
							return Finding{Verdict: certify.Fail,
								Observed: "gridsim received no Response at all for the superseded control " + loser}
						}
						for _, s := range got {
							if s == 7 || s == 14 {
								return Finding{Verdict: certify.Pass,
									Observed: fmt.Sprintf("gridsim received status %d for %s, the statuses "+
										"IEEE 2030.5 Table 27 defines for a superseded event", s, loser)}
							}
						}
						return Finding{Verdict: certify.Fail,
							Observed: fmt.Sprintf("gridsim received statuses %v for the superseded control %s; "+
								"neither 7 (Superseded) nor 14 (Aborted, alternate program) is among them", got, loser)}
					},
				},
				{
					Claim: "the DUT does not simultaneously execute two overlapping DERControls for the same " +
						"control mode",
					How: "the absence of a status=2 (Started) Response for the losing control after a status=2 " +
						"for the winning one",
					Server: func(v *ServerView) Finding {
						if v.HasResponse(loser, 2) && v.HasResponse(winner, 2) {
							return Finding{Verdict: certify.Fail,
								Observed: "the DUT reported BOTH overlapping controls as started, which IEEE " +
									"2030.5 §10.2.3 forbids for the same control mode"}
						}
						if !v.HasResponse(winner, 2) {
							return unavailable("no status=2 (Started) Response for the winning control was " +
								"received within the window, so the mutual exclusion was not exercised")
						}
						return Finding{Verdict: certify.Pass,
							Observed: "the winning control was reported started and the superseded one was not"}
					},
				},
			}
		},
	}
}

func ptr[T any](v T) *T { return &v }
