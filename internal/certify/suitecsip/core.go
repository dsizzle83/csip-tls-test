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
	"strconv"
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
//
// Its 4th criterion (critClockAdopted) is the one row in this suite where the
// pass criterion is explicitly about DUT-internal state — "the Client ...
// synchronizes the Client time" (CTP steps 5-6) is not something a passive
// capture can observe directly, only the server's offer and the DUT's
// subsequent request timestamps. PostWait adds a second, optional tier: when
// -gateway-ssh is configured, it reads the DUT's own wall clock over the
// read-only Gateway introspection channel right after the live phase's wait —
// close in time to the Time-resource fetch the wire criteria assert — so
// critClockAdopted can report a direct measurement instead of only the
// wire-timestamp inference. See probeGatewayClock's doc for what it can and
// cannot conclude.
func coreBasicTime(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "Time function set: discovery of the TimeLink and retrieval of the Time resource"
		},
		PostWait: probeGatewayClock,
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
				critClockAdopted(o),
			}
		},
	})
}

// gwClockParam/gwClockAtParam/gwClockErrParam are the Params keys
// probeGatewayClock leaves for critClockAdopted's citation-phase read-back —
// see check.go's PostWait for why a live-phase probe has to travel through
// Params rather than being called directly from Wire (Wire only sees the
// Evidence/Transcript the citation phase recovers, which can run long after
// the live phase, and has no Driver/RunCtx to reach the gateway with).
const (
	gwClockParam    = "csip.gw_clock_unix"
	gwClockAtParam  = "csip.gw_clock_probed_at"
	gwClockErrParam = "csip.gw_clock_err"
)

// probeGatewayClock reads the DUT's own wall clock over the read-only
// -gateway-ssh introspection channel (certify.Gateway.Run; "date" is on its
// CheckReadOnly allowlist, clients.go) so CORE-005's clock-adoption criterion
// has something firmer than wire-timestamp inference to grade.
//
// Whether the DUT SET its clock from the server's currentTime is internal
// state — CORE-005's own catalog text (steps 5-6) requires it ("synchronize
// ... using the content information") but a passive capture can only show
// what the server OFFERED and when the DUT's OWN subsequent requests landed,
// never what the DUT's clock actually reads. `date -u +%s` on the DUT is the
// one channel that answers the question directly.
//
// Entirely optional and never fatal to the check: a bench run without
// -gateway-ssh (or one where the probe command itself fails) leaves Params
// unset/carrying only the error, and critClockAdopted falls back to exactly
// the wire-only skew report this criterion always gave.
func probeGatewayClock(ctx context.Context, d *Driver, params map[string]string) error {
	gw := d.rc.Gateway
	if !gw.Available() {
		return nil // no -gateway-ssh configured: nothing to probe, nothing to report
	}
	out, err := gw.Run(ctx, "date", "-u", "+%s")
	if err != nil {
		params[gwClockErrParam] = err.Error()
		return err
	}
	params[gwClockParam] = strings.TrimSpace(string(out))
	params[gwClockAtParam] = time.Now().UTC().Format(time.RFC3339Nano)
	return nil
}

// critClockAdopted is CORE-005's 4th criterion — whether the DUT used the
// server's time. See coreBasicTime and probeGatewayClock's docs for the two
// tiers this grades on.
//
// The catalog's CORE-005 text (csip-conf-v1.3::CORE-005, steps 5-6) requires
// the client to "synchronize ... using the content information" but prints NO
// numeric tolerance for the result — TIME.011 bounds only how a BACKWARD
// adjustment must be made (never a single step backwards by more than 60s),
// a different property from "how close must the clocks be". Absent a printed
// threshold this stays informational even with a real gateway-ssh
// measurement in hand: it reports the skew, and never manufactures a
// pass/fail boundary the procedure itself does not state.
func critClockAdopted(o *Observation) criterion {
	return criterion{
		Claim: "the DUT used the server's time rather than its own: its subsequent requests are " +
			"consistent with the server-supplied currentTime, and — when a gateway-ssh probe is available — " +
			"the DUT's own clock reads within a reported margin of the server's",
		How: "comparison of the Time resource's currentTime with the capture timestamp of the request that " +
			"fetched it; when -gateway-ssh is configured, `date -u +%s` run on the DUT (certify.Gateway, " +
			"CheckReadOnly-allowlisted) immediately after the live phase's wait, compared against the same " +
			"server currentTime",
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
			wireSkew := e.Resp.Time.Sub(time.Unix(ct, 0))

			gwClock := o.Param(gwClockParam)
			if gwClock == "" {
				extra := "; no -gateway-ssh was configured for this run, so the DUT's own clock could not be probed"
				if gwErr := o.Param(gwClockErrParam); gwErr != "" {
					extra = fmt.Sprintf("; a gateway-ssh probe was attempted and failed (%s)", gwErr)
				}
				return citeMessage(t, e.Resp, certify.Warn,
					"the server served currentTime=%d and the capture stamped that response at %s, a "+
						"difference of %s. Whether the DUT then SET ITS CLOCK is a property of the device's "+
						"internal state, not of the wire; this run reports the skew the DUT was told about "+
						"rather than asserting an internal effect it cannot observe%s",
					ct, e.Resp.Time.UTC().Format(time.RFC3339), wireSkew.Round(time.Millisecond), extra)
			}
			gwUnix, perr := strconv.ParseInt(gwClock, 10, 64)
			if perr != nil {
				return citeMessage(t, e.Resp, certify.Warn,
					"the server served currentTime=%d (wire-timestamp skew %s); the gateway-ssh probe's "+
						"output %q did not parse as a unix timestamp (%v), so the DUT's own clock could not be "+
						"compared directly", ct, wireSkew.Round(time.Millisecond), gwClock, perr)
			}
			probeSkew := time.Unix(gwUnix, 0).Sub(time.Unix(ct, 0))
			abs := probeSkew
			if abs < 0 {
				abs = -abs
			}
			return citeMessage(t, e.Resp, certify.Warn,
				"the DUT's own clock (probed over -gateway-ssh, `date -u +%%s` -> %d, at %s) differs from the "+
					"server's currentTime=%d by %s (the independent wire-timestamp skew was %s). CSIP CORE-005 "+
					"requires the client to synchronize using the Time resource (steps 5-6) but prints no "+
					"numeric tolerance for the result (TIME.011 bounds only backward-adjustment STEP SIZE, a "+
					"different property), so this stays informational rather than graded pass/fail against a "+
					"threshold the procedure never states",
				gwUnix, o.Param(gwClockAtParam), ct, abs.Round(time.Second), wireSkew.Round(time.Millisecond))
		},
		Skip: "the client's clock adjustment is internal to the DUT and is not observable from the 2030.5 " +
			"exchange without a gateway-ssh probe",
	}
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
// only as per-resource notes (SKIP, informational — never FAIL, and never a
// WARN either: Verdict.Severity() ranks WARN above PASS, so a WARN here would
// silently pull a row critDERPutAny already passed back down — see
// critDERPutInformational's doc for the CORE-009 #10 census this fixed) on
// which of the four arrived.
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
					StartOffset: 60 * (p + 1), DurationS: 30, FixedPFInjectW: &figure8FixedPF,
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
//
// # Why the modesSupported oracle lives here
//
// CORE-014 is the row whose own observables enumerate the field: "HTTP GET
// DERCapability -> 200 OK, XML contains type ..., modesSupported bitmap, ...",
// "modesSupported bit for opModMaxLimW shown as modesSupported=20 in the doc",
// and "Optional-mode branches keyed off modesSupported bits opModFixedVAr,
// opModFixedPFInjectW, opModVoltWatt, opModVoltVAr, opModWattPF". Its procedure
// steps 6-10 are almost entirely a reading of that bitmap. Until now the suite
// asserted that the DERCapability PUT happened and that its numbers were
// internally consistent, and said nothing at all about the one field the row's
// steps are written around. critModesSupportedCoherent is that missing
// assertion, and it derives its bit positions from the SCHEMA rather than from
// the product's own table — see modes_oracle.go for why that distinction is the
// whole point of it existing.
//
// Erratum 39 is not a licence to skip it. It downgrades "modesSupported MUST
// include X" to "MAY include X" — i.e. the suite may not demand a PARTICULAR
// bit — and says in as many words that a capability's presence is conditional
// on "a specific mode being supported (i.e. bit position in modesSupported)".
// That leaves the bitmap's own COHERENCE entirely in scope: nothing in the
// erratum permits advertising a mode the device refuses, or executing one it
// never advertised.
func coreDERSettings(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	// The operator's PICS declaration, when there is one. Read here rather than
	// inside the criterion because the criterion is minted from the capture,
	// long after the RunCtx's own phase is over.
	pics, _ := rc.Param(modesSupportedPICSParam)
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
			return core014Criteria(o, pics)
		},
	})
}

// core014Criteria is CORE-014's assertion list, named so the row's own tests
// can ask what it mints without standing up a bench.
func core014Criteria(o *Observation, pics string) []criterion {
	return []criterion{
		critResource("DERList", "the DUT fetched the DERList and the server answered 200", nil),
		critDERPut("DERCapability"),
		critDERPut("DERSettings"),
		critNameplateConsistency(),
		critModesSupportedCoherent(o, pics),
	}
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

// core021MRIDPrefix is the mRID stem CORE-021's three controls share, so the
// criterion that grades them can find them on the wire without the row having
// to hand it a list.
const core021MRIDPrefix = "CERT-CORE021-"

// coreRandomizedEvents implements CORE-021 — Randomized Events.
func coreRandomizedEvents(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			// The procedure's three controls carry randomizeStart 0, +30 and
			// -30 seconds. gridsim serves randomizeStart/randomizeDuration
			// straight through, so all three are reachable.
			//
			// They also carry gridsim's DEFAULT responseRequired
			// (adminDefaultResponseRequired = RespReqMessageReceived |
			// RespReqSpecificResponse), which is what asks the DUT to announce
			// its own start instant with a status=2 Response — the observation
			// the second criterion below rests on. That default has existed
			// since the admin API grew RespondableResource attributes; the
			// Skip that used to sit on that criterion said "gridsim's admin
			// control API does not expose responseRequired" and had been false
			// for as long as CORE-022 has been grading Response lifecycles
			// through the same API.
			for i, rnd := range []int32{0, 30, -30} {
				mrid := fmt.Sprintf("%s%d", core021MRIDPrefix, i)
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
				critRandomizationNotEarlierThanPermitted(core021MRIDPrefix),
			}
		},
	})
}

// coreResponses implements CORE-022 — Responses.
//
// mrid and cancelMRID carry the per-run nonce (withRunNonce, register.go) for
// the same reason BASIC-017..026's event-precedence scenarios do (see
// eventScenario.withNonce and withRunNonce's doc): lexa-gw's Response tracker
// dedupes Received(1) — and the rest of the lifecycle — on the bare mRID
// string, retained for the process's whole lifetime AND persisted to disk. A
// long-lived bench that re-runs CORE-022 against the SAME hardcoded mRID(s)
// therefore never re-earns a status=1 Response, so critResponsePosted
// (assertion 1) FAILs on every run after the first regardless of what the DUT
// does today — not because the DUT stopped answering, but because it already
// answered once, under this exact mRID, and correctly declines to answer
// twice. Per-mRID duplicate suppression is a defensible 2030.5 posture, and a
// genuinely fresh event is what a real ATL run would present too, so a
// re-runnable conformance harness must do the same rather than let a stale
// artifact of its own bench manufacture a FAIL. This is not masking a defect:
// the separate, still-open product question — should a same-mRID event
// carrying a bumped version re-earn responses? — is tracked independently and
// is untouched by this change.
//
// # Two phases, one control each
//
// The catalog's own procedure (testdata/catalog/catalog.json, CORE-022 steps
// 6-9) runs TWO DERControls concurrently and drives them to different ends:
// one is cancelled server-side before it completes (expecting 1, 2, 6), the
// other runs its full schedule (expecting 1, 2, 3). Before this fix the check
// published only the completing control and never scripted a cancel at all,
// so half of assertion 4's own claim — "...and 6 (cancelled) for an event the
// server cancels" — was unobservable by construction: the case never gave the
// DUT a cancelled event to answer. mrid is that completing control; cancelMRID
// is the one this check cancels mid-flight (Change, below) — not the
// catalog's full three-program/curve-based fixture (that is beyond what this
// bench's admin API builds, and is not this fix's job; see the package doc's
// note on partial-fixture rows).
func coreResponses(nonce string) certify.Check {
	s := coreResponsesSpec(nonce)
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, s)
	}
}

// core022CompletionDurationS is the completing control's own event interval.
//
// Arithmetic (audit 2026-08-01, runs/final-core022b-20260731T234358 WARN):
// gridsim advertises a 60s DERControlList pollRate (defaultControlListPollRate,
// server.go), and that run saw the DUT POST both status=1 AND status=2 within
// 1m9s of an immediate (StartOffset=0) control's Setup — one poll cycle plus
// jitter. Observing status=3 (Completed) additionally needs the interval to
// CLOSE and then survive one MORE poll cycle for the DUT to notice, so the
// expected time-to-observe-status=3 is roughly
// core022CompletionDurationS + one poll cycle (~60s) + latency. The floor
// (90s) is one poll cycle (60s) plus margin for jitter, so the interval
// cannot close before the DUT has even had its first chance to notice it
// opened; the ceiling (150s) keeps the WORST case of that arithmetic
// (150+60+latency ≈ 220s) plus the fixed post-Change settle a server-cancel
// needs (ChangeWait: changeWaitFullCycle, i.e. a SECOND full -param
// csip.wait — up to 480s at the campaign's own -param csip.wait=8m) inside a
// 12-16m -timeout: 220s + 480s + setup/handshake/capture overhead (~30-40s)
// ≈ 12.2min, which is why the focused re-run this fix is for uses -timeout
// 16m rather than the previous 12m. 120s — this row's original,
// pre-two-phase duration — sits in the middle of the [90,150] band.
const core022CompletionDurationS = 120

// core022CancelDurationS is the SECOND control's own event interval —
// deliberately far longer than core022CompletionDurationS (and than the
// largest wait budget this row's own docs recommend, -param csip.wait=8m =
// 480s) so it is still genuinely mid-flight — not naturally elapsed — no
// matter which poll cycle phase 1 (coreResponsesSpec's Want) actually
// resolves on, including the pathological case where phase 1 never resolves
// at all and times out at its full budget: Change fires unconditionally
// either way (run(), check.go). Cancelling a control whose own interval has
// already elapsed on its own does not exercise "the server cancels a LIVE
// event" — it exercises nothing gridsim's admin API can tell apart from a
// control that simply finished, which is why this margin matters.
const core022CancelDurationS = 600

// coreResponsesSpec builds CORE-022's spec for a given per-run nonce. It is
// factored out of coreResponses so a test can drive its Setup/Want directly
// against a fake gridsim (see nonce_test.go) without booting the whole check,
// which needs a live capture window run() cannot fake.
func coreResponsesSpec(nonce string) spec {
	mrid := withRunNonce("CERT-CORE022", nonce)
	cancelMRID := withRunNonce("CERT-CORE022-CANCEL", nonce)
	return spec{
		RequiresGridSim: true,
		Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
			id, err := d.PostControl(ctx, ControlRequest{
				Program: 0, MRID: mrid, Description: "CORE-022 response control",
				StartOffset: 0, DurationS: core022CompletionDurationS, MaxLimW: ptr(int64(4000)), Activate: true,
			})
			if err != nil {
				return err
			}
			params["mrid"] = id

			// The second control is posted HERE, not in Change, so it is
			// already RECEIVED (and very likely Started) well before phase 2
			// cancels it: gridsim's server-cancel seam is a two-step
			// update-in-place on the SAME mRID (sim/gridsim/admin.go's
			// adminCtrlReq doc, sim/gridsim/admin_ctrl_test.go's
			// TestAdminControl_ExplicitMRIDUpdatesInPlace) — "the hub drops
			// events that arrive already-cancelled" — so the first POST must
			// land, and be picked up by the DUT, before the second one flips
			// currentStatus. It runs on a DIFFERENT program (1, not 0) than
			// the completing control, the same way CORE-023's winner/loser
			// pair does (coreSupersedingSpec) — two controls Activate:true on
			// the SAME program would each replace the other's active-list
			// entry.
			cancelID, err := d.PostControl(ctx, ControlRequest{
				Program: 1, MRID: cancelMRID, Description: "CORE-022 cancellation control",
				StartOffset: 0, DurationS: core022CancelDurationS, MaxLimW: ptr(int64(3000)), Activate: true,
			})
			if err != nil {
				return err
			}
			params["cancelMrid"] = cancelID
			return nil
		},
		Want: func(base ServerView) func(ServerView) bool {
			// Phase 1 ONLY: wait for the completing control's status>=3
			// (Completed) — extending the WantResponseAtLeast(mrid, 2) shape
			// the 2026-07-31 audit fixed this row to (see the doc below and
			// WantResponseAtLeast's own) one step further, so the observation
			// window does not close until the FULL natural 1/2/3 lifecycle has
			// had its chance, not merely 1-then-2 (which is exactly how this
			// row landed as a WARN: runs/final-core022b-20260731T234358 saw
			// [1 2] and closed before the interval even finished).
			//
			// The cancelled control is deliberately NOT part of this
			// predicate: its lifecycle is driven by Change below, which fires
			// only once run() (check.go) has finished waiting on THIS
			// predicate. Gating phase 1 on both controls at once would let
			// the two phases race each other — e.g. satisfied the instant the
			// cancelled control (posted well before this point) earns its own
			// status=2, with the completing control's status=3 still
			// outstanding — instead of running strictly in sequence, which is
			// what "cancel mid-flight, AFTER the completing control's own
			// lifecycle has had its full window" requires.
			//
			// A bare WantNewResponse is satisfied by the FIRST fresh
			// Response, which is status=1 (Event received): a spec-compliant
			// DUT may post that the moment it parses the event, independent
			// of whether the event's own interval has started, let alone
			// finished. Await would then close the observation window on that
			// first Response alone, with status=2/3 never given a chance to
			// arrive. See WantResponseAtLeast's doc for the full argument.
			// Belt-and-braces with the nonce above: the Want guards the
			// HARNESS's read of stale Responses left over from an earlier
			// run, the nonce guards the DUT ever having one to read in the
			// first place.
			return base.WantResponseAtLeast(mrid, 3)
		},
		Change: func(ctx context.Context, d *Driver, params map[string]string) error {
			// Phase 2 trigger: the server-side cancel, mid-flight, of the
			// second control — the same update-in-place idiom
			// coreAdvancedEndDevice/coreDERSettings' RehomeDER Change uses,
			// this time flipping EventStatus.currentStatus to 6 (Cancelled)
			// on the SAME mRID rather than moving a resource's href (same
			// gridsim seam, sim/gridsim/admin.go's adminCtrlReq doc). The
			// control's own base fields are carried through unchanged so this
			// really is "the same event, status updated" rather than a
			// content change riding along with the cancel.
			_, err := d.PostControl(ctx, ControlRequest{
				Program: 1, MRID: cancelMRID, Description: "CORE-022 cancellation control",
				StartOffset: 0, DurationS: core022CancelDurationS, MaxLimW: ptr(int64(3000)),
				CurrentStatus: ptr(uint8(6)),
			})
			return err
		},
		// A second full poll cycle, not the short settle: like
		// coreDERSettings' rehome Change, the DUT only learns of the
		// cancellation on its NEXT discovery walk (gridsim's cancel is a
		// server-side state flip, not a push the DUT is guaranteed to
		// subscribe to), and a client honouring the advertised pollRate is
		// entitled to take its whole interval to make it. See
		// changeWaitFullCycle's doc.
		ChangeWait: changeWaitFullCycle,
		Cleanup: func(ctx context.Context, d *Driver) {
			_ = d.ClearControls(ctx, 0)
			_ = d.ClearControls(ctx, 1)
		},
		Notes: func(o *Observation) string {
			return fmt.Sprintf("published an immediate DERControl (%s) and waited %s for its natural 1/2/3 "+
				"lifecycle; statuses received: %v. A second control (%s) was published alongside it on a "+
				"different program and then CANCELLED server-side mid-flight; statuses received: %v",
				mrid, o.Waited.Round(rounding), o.Server.ResponseStatuses(mrid),
				cancelMRID, o.Server.ResponseStatuses(cancelMRID))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResponsePosted(1, "Event received", mrid),
				critResponseStarted(mrid),
				{
					Claim: "the DUT POSTs its Responses to the replyTo URI the event carried, not to a " +
						"hard-coded path",
					How: "the request target of each Response POST FOR THE COMPLETING CONTROL (mrid) compared " +
						"with the replyTo attribute of the DERControl it acknowledges",
					NeedsTranscript: true,
					// Filtered on subj==mrid (audit 2026-08-01, same cross-control leak class
					// critResponsePosted's fix (criteria_2030.go) closed): before this it graded
					// whichever Response POST it found FIRST in capture order, of ANY subject. With
					// only one live control that was harmless; CORE-022 now runs a second, concurrently
					// live control (the server-cancel target — coreResponsesSpec's doc) whose own
					// Response traffic interleaves with mrid's on the same window, so an unfiltered scan
					// could grade — and cite — the wrong control's exchange for this claim, exactly the
					// misattribution this suite's citation discipline exists to rule out.
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
							if subj != mrid {
								continue
							}
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
						return unavailable("the recovered transcript holds no Response POST for subject %s", mrid)
					},
				},
				{
					Claim: "the DUT reports the event lifecycle: statuses 1 (received), 2 (started) and " +
						"3 (completed), and 6 (cancelled) for an event the server cancels",
					How: "the set of Response statuses received for a control this check lets run its full " +
						"natural lifecycle, and separately for a second control this check cancels server-side " +
						"mid-flight (audit 2026-08-01 — see coreResponsesSpec's doc)",
					Server: func(v *ServerView) Finding {
						gotComplete := v.ResponseStatuses(mrid)
						gotCancel := v.ResponseStatuses(cancelMRID)
						if len(gotComplete) == 0 && len(gotCancel) == 0 {
							if !v.SessionEstablished() {
								return noSessionUnavailable()
							}
							return Finding{Verdict: certify.Fail,
								Observed: "gridsim received no Response at all for either control this check published"}
						}
						has := func(got []int, want int) bool {
							for _, s := range got {
								if s == want {
									return true
								}
							}
							return false
						}
						var missing []string
						if !has(gotComplete, 1) {
							missing = append(missing, "1 (received) for the completing control")
						}
						if !has(gotComplete, 2) {
							missing = append(missing, "2 (started) for the completing control")
						}
						if !has(gotComplete, 3) {
							missing = append(missing, "3 (completed) for the completing control")
						}
						if !has(gotCancel, 6) {
							missing = append(missing, "6 (cancelled) for the server-cancelled control")
						}
						observed := fmt.Sprintf("completing control %s: statuses %v; server-cancelled control "+
							"%s: statuses %v", mrid, gotComplete, cancelMRID, gotCancel)
						if len(missing) == 0 {
							return Finding{Verdict: certify.Pass,
								Observed: observed + " — the full 1/2/3/6 event lifecycle was observed"}
						}
						// Graceful degradation (never a false FAIL for a gap
						// that is a WINDOW-TIMING fact, not necessarily a DUT
						// fact): SessionEstablished is already known true here
						// (at least one of the two controls got SOME
						// Response), so a missing status is reported as
						// exactly that — a gap this window did not capture —
						// with the -param that would close it, not as
						// certainty the DUT never would have sent it.
						return Finding{Verdict: certify.Warn,
							Observed: fmt.Sprintf("%s; missing %s. Raise -param %s to give both phases their "+
								"full room (the completing control's own %ds interval plus one more poll cycle, "+
								"then a second full poll cycle after the server-side cancel)",
								observed, strings.Join(missing, ", "), waitParam, core022CompletionDurationS)}
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
// loser alone — and, for the winner specifically, a response whose status is
// at least 2 (Started), not merely its first.
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
//
// The winner half is further tightened to WantResponseAtLeast(winner, 2)
// (audit 2026-07-31, same class of bug as coreResponsesSpec's CORE-022 fix —
// see WantResponseAtLeast's doc): a bare WantNewResponse(winner) is satisfied
// by the winner's own status=1 (Event received) alone, which a DUT may post
// well before its interval starts, and critResponseStarted needs status=2 to
// grade at all. The loser stays on WantNewResponse: its own criteria (status
// 7/14, and the mutual-exclusion check) do not require status>=2, so holding
// it to that bar would wait on a status the loser is never expected to reach.
func coreSupersedingWant(winner, loser string) func(base ServerView) func(ServerView) bool {
	return func(base ServerView) func(ServerView) bool {
		wantWinner := base.WantResponseAtLeast(winner, 2)
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
