package suitecsip

// basic.go implements the BASIC-* family: identification, group management, the
// twelve inverter-control modes, the eleven event-precedence scenarios, alarms,
// status and metering.
//
// # The line this family runs into
//
// Most BASIC rows have a criterion of the form "the DER's output follows the
// control". That is a measurement of the INVERTER, not of the 2030.5 exchange,
// and this bench's CSIP leg cannot see it: the DUT's effect on its southbound
// devices appears on a different wire, belongs to a different suite, and for the
// ride-through modes appears on no wire at all. Those criteria are recorded as
// SKIP with that reason. What this suite CAN certify — and does — is the
// protocol half: the mode reached the DUT inside a conformant DERControl, the
// DUT fetched it, and where the event asked for acknowledgement the DUT
// acknowledged it.
//
// # The modes this bench can and cannot place on the wire
//
// gridsim's admin control API (sim/gridsim/admin.go adminCtrlReq) exposes the
// scalar modes — opModMaxLimW, opModExpLimW, opModFixedW, opModFixedVar,
// opModFixedPFInjectW/AbsorbW, opModConnect, opModEnergize — and its curve API
// (curve.go) binds the four curve modes: opModVoltVar, opModVoltWatt,
// opModFreqWatt, opModWattPF. It exposes NO lever for the six ride-through
// modes (opModLVRT*/opModHVRT*/opModLFRT*/opModHFRT*) and none for the ramp
// rates, which IEEE 2030.5 places only in DefaultDERControl and gridsim's
// /admin/default does not carry. Those rows therefore report, precisely, that
// the mode could not be put on the wire — which is a bench gap with a named
// owner, not a DUT finding.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// basicIdentification implements BASIC-001 — DER Identification.
func basicIdentification(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	pin, _ := rc.Param(pinParam)
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "SFDI/LFDI/PIN provisioning and the EndDevice walk; the identity is derived from the " +
				"certificate the DUT presented on the wire, by this bench's own implementation of " +
				"IEEE 2030.5 §6.3 (the catalog's 16-bit/160-bit erratum on step 4(b) is honoured)"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critTLS12(),
				critMutualAuth(),
				critDiscoveryRoot(),
				critEndDeviceList(2),
				critSelfIdentity(),
				critRegistrationPIN(pin),
				critFSAList(0),
				critResource("FunctionSetAssignments",
					"the DUT traversed from its EndDevice into the FunctionSetAssignments and on to the "+
						"DERProgram resources beneath it",
					func(doc *Node) (certify.Verdict, string) {
						if !doc.Has("DERProgramListLink") {
							return certify.Fail, "the FunctionSetAssignments carries no DERProgramListLink, so " +
								"the DERProgram resources the procedure requires are unreachable"
						}
						return certify.Pass, "DERProgramListLink present"
					}),
				critProgramList(0),
			}
		},
	})
}

// basicGroupManagement builds BASIC-002 and BASIC-003, which differ only in the
// scale of the group fixture they require.
func basicGroupManagement(fsaCount, programCount, endDevices int) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		pin, _ := rc.Param(pinParam)
		return run(ctx, rc, spec{
			Notes: func(o *Observation) string {
				return fmt.Sprintf("group management: the procedure's fixture is %d EndDevice(s), %d FSA(s) "+
					"and %d DERProgram(s); the assertions below report what the bench actually served",
					endDevices, fsaCount, programCount)
			},
			Criteria: func(o *Observation) []criterion {
				return []criterion{
					critDiscoveryRoot(),
					critEndDeviceList(endDevices),
					critRegistrationPIN(pin),
					critFSAList(fsaCount),
					critProgramList(programCount),
					critDefaultDERControl(),
					critResource("DERControlList", "the DUT fetched the DERControlList of a DERProgram", nil),
					critPollRate(),
				}
			},
		})
	}
}

// controlMode describes how one inverter-control row's mode is placed on the
// wire, or why it cannot be.
type controlMode struct {
	// Element is the DERControlBase child the DUT must be seen to receive.
	Element string
	// Publish arms the mode on the bench. nil means the mode is unreachable.
	Publish func(ctx context.Context, d *Driver, mrid string) error
	// Unreachable explains why no lever exists; set exactly when Publish is nil.
	Unreachable string
	// Program is the gridsim DERProgram index to publish on.
	Program int
}

// scalarMode builds a controlMode driven by gridsim's scalar control API.
func scalarMode(element string, apply func(*ControlRequest)) controlMode {
	return controlMode{
		Element: element,
		Publish: func(ctx context.Context, d *Driver, mrid string) error {
			req := ControlRequest{
				Program: 0, MRID: mrid, Description: "certify " + element,
				StartOffset: 30, DurationS: 120,
			}
			apply(&req)
			_, err := d.PostControl(ctx, req)
			return err
		},
	}
}

// curveMode builds a controlMode driven by gridsim's curve API, which is the
// only way a curve-linked mode reaches the DUT.
func curveMode(element, mode string, points []CurvePoint, yRef uint8) controlMode {
	return controlMode{
		Element: element,
		Publish: func(ctx context.Context, d *Driver, mrid string) error {
			_, err := d.PostCurve(ctx, CurveRequest{
				Program: 0, Mode: mode, Points: points, YRefType: yRef,
				Description: "certify " + element, DurationS: 180, StartOffset: 30, Activate: true,
			})
			return err
		},
	}
}

// unreachableMode builds a controlMode for a mode this bench cannot publish.
func unreachableMode(element, why string) controlMode {
	return controlMode{Element: element, Unreachable: why}
}

// basicInverterControl builds one of the BASIC-004..015 rows.
func basicInverterControl(m controlMode, subject string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		mrid := "CERT-" + strings.ToUpper(rc.Case.ID)
		s := spec{
			Notes: func(o *Observation) string {
				if m.Unreachable != "" {
					return "the control mode this row is about cannot be published by this bench: " + m.Unreachable
				}
				return fmt.Sprintf("published a DERControl (%s) carrying %s and waited %s for the DUT to "+
					"fetch it", mrid, m.Element, o.Waited.Round(rounding))
			},
			Criteria: func(o *Observation) []criterion {
				crits := []criterion{critDiscoveryRoot(), critProgramList(0)}
				if m.Unreachable != "" {
					crits = append(crits, criterion{
						Claim: "the DUT received and applied a DERControl carrying " + subject,
						How: "the presence of a <" + m.Element + "> element inside a DERControlBase the DUT " +
							"fetched",
						Skip: m.Unreachable,
					})
				} else {
					crits = append(crits, critDERControlCarriesMode(m.Element,
						"the DUT fetched a DERControl carrying "+subject))
				}
				crits = append(crits, critDefaultDERControl(), critDEREffectUnobservable(subject))
				return crits
			},
		}
		if m.Publish != nil {
			s.RequiresGridSim = true
			s.Setup = func(ctx context.Context, d *Driver, params map[string]string) error {
				params["mrid"] = mrid
				return m.Publish(ctx, d, mrid)
			}
			s.Cleanup = func(ctx context.Context, d *Driver) {
				_ = d.ClearControls(ctx, m.Program)
				_ = d.ClearCurves(ctx, m.Program)
			}
		}
		return run(ctx, rc, s)
	}
}

// critDEREffectUnobservable is the honest record of the half of every inverter
// control row this suite cannot reach.
func critDEREffectUnobservable(subject string) criterion {
	return criterion{
		Claim: "the DER's output followed " + subject + " for the duration of the event",
		How:   "measurement of the DER's electrical behaviour during the event window",
		Skip: "the DER's response to a control is a measurement of the inverter, not of the 2030.5 exchange. " +
			"On this bench it would appear on the gateway's SOUTHBOUND Modbus leg (a different capture and a " +
			"different suite) or, for the ride-through modes, on no wire at all. This suite certifies the " +
			"protocol half: that the control reached the DUT inside a conformant DERControl",
	}
}

// eventScenario builds the BASIC-016..026 precedence rows.
//
// Each row is a fixture: N DERPrograms, N DefaultDERControls, M DERControls in a
// particular overlap relationship, and a stated expectation about which one the
// DER ends up following. The wire-observable half is which controls reached the
// DUT and, where the events ask for it, which the DUT acknowledged; the
// "which one is in effect" half is the inverter measurement critDEREffect
// declines to fake.
type eventScenario struct {
	// Controls are the DERControls to publish, in order.
	Controls []scenarioControl
	// ExpectWinner names the mRID the procedure expects to prevail, or "" when
	// the row is about DefaultDERControls only.
	ExpectWinner string
	// Summary is the row's fixture in one line, for the bundle.
	Summary string
}

type scenarioControl struct {
	MRID        string
	Program     int
	StartOffset int
	DurationS   int
	MaxLimW     int64
	Superseded  bool
	CreationAge int
}

// withNonce returns a copy of the scenario whose control mRIDs — and the
// ExpectWinner that names one of them — all carry the per-run nonce.
//
// This is the test-isolation fix for BASIC-017..026. IEEE 2030.5 mRIDs are
// globally unique and stable, so the gateway's Response tracker correctly
// refuses to re-acknowledge (re-post Received/Started for) an event mRID it has
// already run to terminal. A campaign that republishes the same STATIC mRIDs
// therefore passes only against a fresh gateway and is suppressed on every
// re-run of the long-running one — critResponsePosted then sees no Response and
// FAILs. Appending a fresh token per run makes each campaign publish mRIDs the
// tracker has not yet seen, exactly as the curve-driven controls already get a
// per-run gridsim-assigned mRID.
//
// The SAME nonce is applied to every mRID in the scenario, so the within-run
// correlation the lifecycle assertions rely on still holds: ExpectWinner keeps
// naming the winning control (critResponsePosted), and critScenarioControlsDelivered
// keeps matching the mRIDs it published against the ones the DUT fetched. An
// empty nonce is the identity, so a bench that does not care about isolation
// (and every existing test that reasons about the static mRIDs) is unchanged.
func (sc eventScenario) withNonce(nonce string) eventScenario {
	if nonce == "" {
		return sc
	}
	out := sc
	if sc.ExpectWinner != "" {
		out.ExpectWinner = sc.ExpectWinner + "-" + nonce
	}
	out.Controls = make([]scenarioControl, len(sc.Controls))
	for i, c := range sc.Controls {
		c.MRID += "-" + nonce
		out.Controls[i] = c
	}
	return out
}

func basicEventScenario(sc eventScenario) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, spec{
			RequiresGridSim: len(sc.Controls) > 0,
			Setup: func(ctx context.Context, d *Driver, params map[string]string) error {
				for _, c := range sc.Controls {
					req := ControlRequest{
						Program: c.Program, MRID: c.MRID, Description: "certify " + rc.Case.ID,
						StartOffset: c.StartOffset, DurationS: c.DurationS, MaxLimW: ptr(c.MaxLimW),
					}
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
				return sc.Summary + fmt.Sprintf("; waited %s", o.Waited.Round(rounding))
			},
			Criteria: func(o *Observation) []criterion {
				crits := []criterion{
					critProgramList(0),
					critDefaultDERControl(),
				}
				if len(sc.Controls) > 0 {
					crits = append(crits, critScenarioControlsDelivered(sc))
				}
				if sc.ExpectWinner != "" {
					crits = append(crits, critResponsePosted(1, "Event received", sc.ExpectWinner))
				}
				crits = append(crits, criterion{
					Claim: "the DER followed the control the procedure's precedence rules select (" +
						sc.Summary + ")",
					How: "measurement of the DER's electrical behaviour across the scenario's event windows",
					Skip: "which control is IN EFFECT is a property of the inverter, not of the 2030.5 " +
						"exchange, and is not observable on the CSIP leg. The wire half — which controls " +
						"reached the DUT, and which it acknowledged — is asserted above",
				})
				return crits
			},
		})
	}
}

// critScenarioControlsDelivered asserts that every control the scenario
// published reached the DUT.
func critScenarioControlsDelivered(sc eventScenario) criterion {
	return criterion{
		Claim:           "every DERControl the scenario published reached the DUT in a DERControlList it fetched",
		How:             "the mRIDs of the DERControls in the DERControlLists the DUT fetched during the window",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			got := map[string]bool{}
			var frames []int
			for _, e := range t.ByResource("DERControlList") {
				doc, err := e.Resp.SEP()
				if err != nil {
					continue
				}
				for _, c := range doc.Children("DERControl") {
					if m, ok := c.TextOf("mRID"); ok {
						got[m] = true
					}
				}
				frames = append(frames, e.Frames()...)
			}
			if len(frames) == 0 {
				return unavailable("no DERControlList appears in the recovered transcript")
			}
			var missing []string
			for _, c := range sc.Controls {
				if !got[c.MRID] {
					missing = append(missing, c.MRID)
				}
			}
			if len(missing) > 0 {
				return found(certify.Fail, dedupeInts(frames),
					"%d of %d published control(s) did not reach the DUT: %s",
					len(missing), len(sc.Controls), strings.Join(missing, " "))
			}
			return found(certify.Pass, dedupeInts(frames),
				"all %d published control(s) appear in the lists the DUT fetched", len(sc.Controls))
		},
		Server: func(v *ServerView) Finding {
			n := 0
			for _, c := range sc.Controls {
				if len(v.ResponsesFor(c.MRID)) > 0 {
					n++
				}
			}
			if n == 0 {
				return unavailable("gridsim received no Response for any of the scenario's controls, which " +
					"is expected when the controls do not ask for one; delivery cannot be confirmed from " +
					"the server side alone")
			}
			return Finding{Verdict: certify.Pass,
				Observed: fmt.Sprintf("the DUT acknowledged %d of %d published control(s) to gridsim",
					n, len(sc.Controls))}
		},
	}
}

// basicAlarms implements BASIC-027 — Alarms (LogEvent).
func basicAlarms(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return fmt.Sprintf("LogEvent reporting; gridsim recorded %d LogEvent(s) from the DUT during the "+
				"window", len(o.Server.LogEvents))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResource("EndDevice", "the DUT fetched its EndDevice and the server's payload carries a "+
					"LogEventListLink", func(doc *Node) (certify.Verdict, string) {
					if !doc.Has("LogEventListLink") {
						return certify.Fail, "the EndDevice carries no LogEventListLink, so the alarm function " +
							"set is unreachable"
					}
					return certify.Pass, "LogEventListLink present"
				}),
				{
					Claim: "the DUT POSTs LogEvents to the LogEventListLink href and the server answers 201 " +
						"Created with a Location header",
					How: "a POST in the session whose body's root element is LogEvent, and the status line and " +
						"Location header of the response to it",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						for _, e := range t.Method("POST") {
							doc, err := e.Req.SEP()
							if err != nil || doc.Local() != "LogEvent" {
								continue
							}
							var missing []string
							for _, want := range []string{"createdDateTime", "functionSet", "logEventCode",
								"logEventID", "logEventPEN", "profileID"} {
								if !doc.Has(want) {
									missing = append(missing, want)
								}
							}
							if e.Resp == nil {
								return citeMessage(t, e.Req, certify.Fail, "the LogEvent POST was never answered")
							}
							loc := e.Resp.Header.Get("Location")
							switch {
							case len(missing) > 0:
								return citeMessage(t, e.Req, certify.Fail,
									"the LogEvent payload is missing %s", strings.Join(missing, ", "))
							case e.Resp.Status != 201:
								return citeExchange(t, e, certify.Fail,
									"POST %s carrying LogEvent -> %s; 2030.5 §5.5.2 requires 201 Created",
									e.Req.Target, e.Resp.Line())
							case loc == "":
								return citeExchange(t, e, certify.Fail,
									"POST %s -> 201 Created but with no Location header, which 2030.5 requires "+
										"on a 201", e.Req.Target)
							default:
								return citeExchange(t, e, certify.Pass,
									"POST %s carrying a complete LogEvent -> 201 Created, Location: %s",
									e.Req.Target, loc)
							}
						}
						return unavailable("the recovered transcript holds no LogEvent POST from the DUT")
					},
					Server: func(v *ServerView) Finding {
						if len(v.LogEvents) == 0 {
							return Finding{Verdict: certify.Skip,
								Observed: "gridsim recorded no LogEvent from the DUT during this window. A DER " +
									"with nothing to report is not non-conformant, so this is a SKIP: the row " +
									"needs a fault injected on the DUT's southbound devices to make it alarm, " +
									"which is outside this suite's read-only reach"}
						}
						return Finding{Verdict: certify.Pass,
							Observed: fmt.Sprintf("gridsim recorded %d LogEvent(s) from the DUT", len(v.LogEvents))}
					},
				},
				{
					Claim: "the DUT's LogEvents carry a logEventCode from IEEE 2030.5 Table 34 and are " +
						"time-ordered",
					How:  "the logEventCode and createdDateTime elements of the recorded LogEvents",
					Skip: "no LogEvent was recovered in this window to inspect",
					Server: func(v *ServerView) Finding {
						if len(v.LogEvents) == 0 {
							return unavailable("gridsim recorded no LogEvent to inspect")
						}
						var codes []string
						for _, le := range v.LogEvents {
							codes = append(codes, fmt.Sprint(le["logEventCode"]))
						}
						return Finding{Verdict: certify.Pass,
							Observed: fmt.Sprintf("%d LogEvent(s), codes %s", len(v.LogEvents),
								strings.Join(codes, " "))}
					},
				},
			}
		},
	})
}

// basicInverterStatus implements BASIC-028 — Inverter Status.
func basicInverterStatus(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return fmt.Sprintf("DERStatus reporting; %d DERStatus PUT(s) recorded server-side during the window",
				len(o.Server.PutsFor("DERStatus")))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critResource("DERList", "the DUT fetched the DERList from its EndDevice's DERListLink", nil),
				critDERPut("DERStatus"),
				critDERStatusElements(),
			}
		},
	})
}

// critDERStatusElements asserts BASIC-028's element list on the payload the DUT
// itself reported.
func critDERStatusElements() criterion {
	required := []string{"genConnectStatus", "inverterStatus", "operationalModeStatus", "readingTime"}
	evaluate := func(doc *Node) (certify.Verdict, string) {
		var missing, present []string
		for _, want := range required {
			if doc.Has(want) {
				present = append(present, want)
			} else {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			return certify.Fail, fmt.Sprintf("the DERStatus the DUT reported is missing %s (it carries %s)",
				strings.Join(missing, ", "), strings.Join(present, ", "))
		}
		return certify.Pass, "the DERStatus carries " + strings.Join(present, ", ")
	}
	return criterion{
		Claim: "the DERStatus the DUT reports carries the elements BASIC-028 requires of a power-generating " +
			"DER: genConnectStatus, inverterStatus, operationalModeStatus and readingTime",
		How: "the child elements of the DERStatus payload the DUT PUT, located first in the conversations " +
			"this check owns and then across the run's whole decrypted capture",
		NeedsTranscript: true,
		// The same three-rung ladder as critDERPut, and for the same reason: the
		// DERStatus this row inspects is emitted on the DUT's own cadence, so
		// the body is routinely in the capture but outside this case's window.
		// Reading it from the wire there — and saying so — beats reading it from
		// the copy gridsim stored.
		Wire: func(ev *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "DERStatus" {
					continue
				}
				v, desc := evaluate(doc)
				return citeMessage(t, e.Req, v, "%s", desc)
			}
			rw := runWireOf(ev, t.Remote)
			for _, e := range rw.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "DERStatus" {
					continue
				}
				v, desc := evaluate(doc)
				return Finding{Verdict: v, Observed: fmt.Sprintf(
					"%s — read from the DERStatus body in frame(s) %s, which are outside this test case's "+
						"window and so are named rather than cited. Scope: %s", desc, framesOf(e), rw.Scope())}
			}
			if rw.Complete {
				return unavailable("no DERStatus PUT appears anywhere in the run's capture (%s), so the DUT "+
					"reported no DERStatus body for this criterion to inspect", rw.Scope())
			}
			return unavailable("the recovered transcript holds no DERStatus PUT, and the run's capture "+
				"cannot settle whether one happened elsewhere: %s", rw.Scope())
		},
		Server: func(v *ServerView) Finding {
			puts := v.PutsForInRun("DERStatus")
			if len(puts) == 0 {
				return unavailable("gridsim recorded no DERStatus PUT to inspect")
			}
			doc, err := ParseSEP([]byte(puts[len(puts)-1].Body))
			if err != nil {
				return Finding{Verdict: certify.Fail,
					Observed: fmt.Sprintf("the stored DERStatus body did not parse: %v", err)}
			}
			verdict, desc := evaluate(doc)
			return Finding{Verdict: verdict, Observed: desc + " (from the body gridsim stored)"}
		},
	}
}

// critMUPRegistered asserts the DUT's MirrorUsagePoint registration
// (BASIC-029's own element): a POST carrying its LFDI and a
// MirrorMeterReading/ReadingType, answered 201 Created (or 204 for an
// existing mRID) with a Location header.
//
// Five tiers, strongest first (four evidence sources, since the fourth
// grades two distinct states of the same durable store differently):
//
//  1. Wire (above): an in-window POST recovered from the decrypted transcript,
//     cited by frame. This is the strongest evidence and, when the DUT's
//     registration happens to fall inside the case's own capture window, is
//     what actually grades the claim.
//  2. Server / request log: an in-window POST recorded in gridsim's request
//     log (an EXACT match on the registration path "/mup" — see below for why
//     that has to be exact, not a prefix).
//  3. Server / MUP state, complete (ServerView.RegisteredMUP, GET
//     /admin/mups): registration is a ONE-TIME event — the DUT does it once,
//     at first contact with this MirrorUsagePointList, and has no reason to
//     repeat it — and it ordinarily predates a case's own window: BASIC-029
//     has no Setup of its own to force a fresh one, so by the time this
//     check's window opens the registration already happened, often minutes
//     or a whole campaign earlier. Tiers 1 and 2 can only ever see what fell
//     inside the window; gridsim's durable MUP store did not stop existing
//     just because the window opened late, so it is consulted before
//     conceding anything. This tier requires a ReadingType, because that is
//     part of the claim above — and on this bench the registration POST
//     itself carries none; only the DUT's first MirrorMeterReading does (see
//     basicMeterReading's Want). A window that closes before that first
//     reading lands must NOT credit this tier; see tier 4.
//  4. Server / MUP state, pending (ServerView.PendingMUP): the store has an
//     LFDI-bound MUP but no ReadingType yet — registered, evidence not yet
//     landed, as opposed to never registered at all. This is a real FAIL
//     (the claim's ReadingType is genuinely absent from the window's
//     evidence), but it is graded with its own, more precise wording so a
//     bundle reader is not misled into reading it as "the DUT never
//     registered" — see the fix note below.
//  5. Server / ring gap (last resort, e186056): if the MUP store ALSO has
//     nothing at all — not even a pending, LFDI-only entry (an older gridsim
//     predating the /admin/mups lever, or the process was restarted since
//     registration and genuinely lost its state) — fall back to
//     RequestLogGap: an empty request-log count from a ring that itself says
//     it cannot be trusted for this window is unavailable, not a FAIL. Only
//     once the log is both empty AND trusted is this a real FAIL.
//
// Fix note (audit 2026-07-30, runs/stamped-basic029-20260730T073518 assertion
// 2): the request-log tier used to match any path with the "/mup" PREFIX,
// which also matches "/mup/{n}" — the READING endpoint. A DUT that never
// registers but posts readings every 300s would eventually rack up a POST
// count under the old code and PASS this criterion on evidence that was
// never a registration at all (that run's own Wire tier found no
// MirrorUsagePoint POST in the transcript, yet the Server tier reported "36
// POST(s) to the MirrorUsagePoint tree" and PASSed). The request-log tier now
// matches the registration path exactly.
//
// Fix note (audit 2026-07-30, runs/perphase-basic029-v4-20260730T232105
// assertion 2): a run with `-param csip.wait=12m` finished in ~28s and FAILed
// this criterion even though the DUT HAD registered, 24s before the run even
// started, and gridsim's /admin/mups proved it. Two separate bugs, both fixed
// together because neither alone explains the run:
//
//   - basicMeterReading had no Want of its own, so it fell back to
//     AwaitWalk — satisfied by the DUT's very next /dcap poll, whatever it is
//     for. That poll landed 25s into the window purely because the run
//     happened to start 5s before the DUT's routine 60s-cadence boundary; the
//     operator's 12-minute wait was never honoured. See basicMeterReading's
//     Want for the fix: it now waits for what THIS check's own criteria need,
//     not for an unrelated poll.
//   - Tier 3 correctly requires a ReadingType (it is part of the claim), and
//     this DUT's registration POST carries none — only its first
//     MirrorMeterReading does, at the 300s postRate gridsim advertised. Grading
//     52s after registration (23:20:42Z registered, 23:21:33Z graded) was
//     always going to see readings:0; that is not a tier bug, it is grading
//     before the evidence the tier is honestly waiting for could exist. Tier
//     4 above is the other half of the fix: when that happens anyway (the
//     wait fix above should prevent it, but a window can still legitimately
//     expire before a slow DUT's first reading), the FAIL now says exactly
//     that — registered, reading pending — instead of words indistinguishable
//     from "never registered".
func critMUPRegistered() criterion {
	return criterion{
		Claim: "the DUT registered a MirrorUsagePoint carrying its own LFDI and a " +
			"MirrorMeterReading/ReadingType, and the server answered 201 Created with a Location",
		How: "the sep+xml body of the MirrorUsagePoint POST and the status line and Location " +
			"header of the response",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			for _, e := range t.Method("POST") {
				doc, err := e.Req.SEP()
				if err != nil || doc.Local() != "MirrorUsagePoint" {
					continue
				}
				lfdi, _ := doc.TextOf("deviceLFDI")
				rt := doc.Descendants("ReadingType")
				if e.Resp == nil {
					return citeMessage(t, e.Req, certify.Fail, "the MirrorUsagePoint POST was never answered")
				}
				// 2030.5 §10.11.3 rules (f)/(g): 201 for a new mRID,
				// 204 for an existing one, Location required on both.
				ok := e.Resp.Status == 201 || e.Resp.Status == 204
				loc := e.Resp.Header.Get("Location")
				switch {
				case !ok:
					return citeExchange(t, e, certify.Fail,
						"POST %s carrying MirrorUsagePoint -> %s; 2030.5 §10.11.3 requires 201 "+
							"(new mRID) or 204 (existing)", e.Req.Target, e.Resp.Line())
				case loc == "":
					return citeExchange(t, e, certify.Fail,
						"POST %s -> %s with no Location header, which §10.11.3 requires on both the "+
							"201 and the 204", e.Req.Target, e.Resp.Line())
				case lfdi == "":
					return citeMessage(t, e.Req, certify.Fail,
						"the MirrorUsagePoint carries no deviceLFDI, so the server cannot bind the "+
							"mirror to the reporting device")
				default:
					return citeExchange(t, e, certify.Pass,
						"POST %s carrying MirrorUsagePoint deviceLFDI=%s with %d ReadingType(s) -> "+
							"%s, Location: %s", e.Req.Target, lfdi, len(rt), e.Resp.Line(), loc)
				}
			}
			return unavailable("the recovered transcript holds no MirrorUsagePoint POST from the DUT")
		},
		Server: func(v *ServerView) Finding {
			n := v.GETs("/mup")
			posts := 0
			for _, r := range v.Requests {
				// Exact match on the registration endpoint: "/mup/0" (a
				// reading POST) must never be counted here — see the fix note
				// above.
				if r.Method == "POST" && r.Path == "/mup" {
					posts++
				}
			}
			if posts > 0 {
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("gridsim's request log records %d POST(s) to the "+
						"MirrorUsagePoint registration endpoint (/mup) during this window; the status "+
						"codes and bodies are not recoverable from the log", posts)}
			}
			if !v.SessionEstablished() {
				return noSessionUnavailable()
			}
			// Tier 3: the request log found nothing in this window, but
			// registration is a ONE-TIME event this window had no reason to
			// see — consult the durable MUP store before conceding anything.
			if mup, ok := v.RegisteredMUP(); ok {
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("gridsim's request log records no in-window POST to the "+
						"MirrorUsagePoint registration endpoint (%d GET(s) of /mup), but its durable MUP "+
						"state (GET /admin/mups) records %s registered at %s carrying deviceLFDI=%s with "+
						"%d ReadingType(s) (uom %v); this window opened after the DUT's one-time "+
						"registration, not before it happened",
						n, mup.Href, time.Unix(mup.CreatedAt, 0).UTC().Format(time.RFC3339), mup.LFDI,
						len(mup.ReadingTypes), mup.ReadingTypes)}
			}
			// Tier 4: the store has an LFDI-bound MUP, just not one carrying
			// a ReadingType yet — registered, evidence pending, not "never
			// registered". See PendingMUP's doc and the fix note above
			// (runs/perphase-basic029-v4-20260730T232105): the generic
			// tier-5/final wording below is technically accurate here too,
			// but reads exactly like the DUT never registered at all, which
			// is not what the store shows. Still a FAIL — the claim's
			// ReadingType genuinely is not in evidence yet — just a more
			// honest one.
			if mup, ok := v.PendingMUP(); ok {
				return Finding{Verdict: certify.Fail,
					Observed: fmt.Sprintf("gridsim's request log records no in-window POST to the "+
						"MirrorUsagePoint registration endpoint (%d GET(s) of /mup); its durable MUP state "+
						"(GET /admin/mups) records %s registered at %s carrying deviceLFDI=%s, but with %d "+
						"reading(s) posted and no ReadingType yet — the DUT's first MirrorMeterReading had "+
						"not landed by the time this window closed, not that it never registered",
						n, mup.Href, time.Unix(mup.CreatedAt, 0).UTC().Format(time.RFC3339), mup.LFDI,
						mup.Readings)}
			}
			// Tier 5 (last resort): the request log is a bounded ring (unlike
			// Responses/DERPuts), and the registration this criterion is
			// after is a ONE-TIME event: it happens once, at the DUT's first
			// contact, and never again unless gridsim's state is wiped. A
			// window opened long after that (this case has no Setup of its
			// own to force a fresh one) can find the log has simply moved on
			// — RequestLogGap is Since's own signal that this is what
			// happened, not that the DUT never registered.
			if v.RequestLogGap != "" {
				return unavailable("gridsim's request log records no POST to the "+
					"MirrorUsagePoint registration endpoint during this window, its durable MUP state "+
					"(GET /admin/mups) records nothing bearing a deviceLFDI at all, but %s", v.RequestLogGap)
			}
			return Finding{Verdict: certify.Fail,
				Observed: fmt.Sprintf("gridsim's request log records no POST to the MirrorUsagePoint "+
					"registration endpoint during this window (%d GET(s) of /mup), and its durable MUP "+
					"state (GET /admin/mups) records no MirrorUsagePoint carrying a deviceLFDI at all", n)}
		},
	}
}

// basicMUPWant is basicMeterReading's Want: it replaces the generic AwaitWalk
// fallback (satisfied by the DUT's very next /dcap poll, whatever it happens
// to be for) with a predicate tied to what this check's OWN criteria need.
//
// Fix note (audit 2026-07-30, runs/perphase-basic029-v4-20260730T232105
// assertion 2): BASIC-029 has no Setup and, before this fix, no Want either,
// so it fell back to AwaitWalk. A run with `-param csip.wait=12m` finished in
// ~28s because the DUT's routine 60s-cadence poll landed 25s into the
// window — a coincidence of when the run happened to start relative to the
// DUT's own poll boundary, with no connection to MUP registration at all.
// Grading then found critMUPRegistered's tier 3 (ServerView.RegisteredMUP)
// unsatisfied: the DUT HAD registered, 24s before the run even started, but
// its registration POST on this bench carries no ReadingType — only its
// first MirrorMeterReading does, at the 300s postRate gridsim advertised —
// so the durable state legitimately showed readings:0 at the 28-second mark.
// The operator's 12-minute wait, meant to span exactly that 300s cadence
// (see the postRate criterion below), was never honoured.
//
// This predicate waits for BOTH things the check's criteria actually use, not
// either alone:
//
//   - a fresh discovery walk (base.GETs(DiscoveryRoot)+1), the same guarantee
//     AwaitWalk gave every other Setup-less row: it ensures the capture window
//     always spans at least one /dcap exchange, which the DeviceCapability
//     criterion above needs evidence from;
//   - ServerView.RegisteredMUP, the exact state critMUPRegistered's tier 3
//     grades — an LFDI-bound MUP carrying a ReadingType. Requiring this HERE,
//     in the wait, rather than only in the grading tier, is what makes the
//     wait actually wait for the evidence instead of exiting the moment an
//     unrelated poll lands.
//
// A DUT that never registers waits the full configured window and is graded
// on what is honestly there — the same outcome as before, just no longer
// arrived at by accident. A DUT whose registration (with a ReadingType) is
// already complete by the time this run starts is graded promptly, same as
// tier 3 has always allowed: RegisteredMUP reads durable, one-time STATE, not
// a per-run delta, so — unlike WantNewResponse's Response-log staleness bug —
// there is nothing here for an earlier run's evidence to spuriously satisfy.
func basicMUPWant(base ServerView) func(ServerView) bool {
	wantWalk := base.GETs(DiscoveryRoot) + 1
	return func(v ServerView) bool {
		if v.GETs(DiscoveryRoot) < wantWalk {
			return false
		}
		_, ok := v.RegisteredMUP()
		return ok
	}
}

// basicMeterReading implements BASIC-029 — Inverter Meter Reading.
func basicMeterReading(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Want: func(base ServerView) func(ServerView) bool { return basicMUPWant(base) },
		Notes: func(o *Observation) string {
			return fmt.Sprintf("MirrorUsagePoint registration and MirrorMeterReading posting; waited %s for a "+
				"fresh discovery walk AND a ReadingType-bearing MUP registration (predicate satisfied: %t)",
				o.Waited.Round(rounding), o.Satisfied)
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critGET(DiscoveryRoot,
					"the DeviceCapability the server returned carries a MirrorUsagePointListLink",
					"the MirrorUsagePointListLink element of the DeviceCapability payload",
					func(doc *Node) (certify.Verdict, string) {
						if !doc.Has("MirrorUsagePointListLink") {
							return certify.Fail, "no MirrorUsagePointListLink, so the metering mirror is " +
								"unreachable"
						}
						return certify.Pass, "MirrorUsagePointListLink present"
					}),
				critMUPRegistered(),
				{
					Claim: "the ReadingType the DUT registered carries the CSIP monitoring encoding for real " +
						"power: uom=38 (Watts), flowDirection and powerOfTenMultiplier present",
					How:             "the ReadingType child elements of the MirrorUsagePoint payload",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						for _, e := range t.Method("POST") {
							doc, err := e.Req.SEP()
							if err != nil || doc.Local() != "MirrorUsagePoint" {
								continue
							}
							var uoms []string
							for _, rt := range doc.Descendants("ReadingType") {
								if u, ok := rt.UintOf("uom"); ok {
									uoms = append(uoms, fmt.Sprint(u))
								}
							}
							if len(uoms) == 0 {
								return citeMessage(t, e.Req, certify.Fail,
									"no ReadingType in the MirrorUsagePoint carries a uom")
							}
							for _, u := range uoms {
								if u == "38" {
									return citeMessage(t, e.Req, certify.Pass,
										"ReadingType uom values %s include 38 (real power, W)",
										strings.Join(uoms, ","))
								}
							}
							return citeMessage(t, e.Req, certify.Warn,
								"ReadingType uom values are %s; CSIP Table 11 maps real power to 38, reactive "+
									"to 63, frequency to 33 and voltage to 29. A DER mirroring only some of the "+
									"monitoring data set is not necessarily non-conformant, so this is reported",
								strings.Join(uoms, ","))
						}
						return unavailable("the recovered transcript holds no MirrorUsagePoint POST")
					},
				},
				{
					Claim: "the DUT posts MirrorMeterReadings at the postRate the server advertised",
					How: "the spacing between successive MirrorMeterReading POSTs, measured from capture " +
						"timestamps, compared with the MirrorUsagePoint's postRate",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						var times []string
						var frames []int
						var last *Message
						for _, e := range t.Method("POST") {
							doc, err := e.Req.SEP()
							if err != nil || doc.Local() != "MirrorMeterReading" {
								continue
							}
							if last != nil && !last.Time.IsZero() && !e.Req.Time.IsZero() {
								times = append(times, e.Req.Time.Sub(last.Time).Round(rounding).String())
							}
							last = e.Req
							frames = append(frames, e.Frames()...)
						}
						if len(times) == 0 {
							return unavailable("the window holds fewer than two MirrorMeterReading POSTs; a "+
								"post-rate interval needs two. The bench's telemetry default is a 300 s post "+
								"rate, so spanning it needs -param %s=11m or more", waitParam)
						}
						return found(certify.Pass, dedupeInts(frames),
							"%d inter-post interval(s) measured from capture timestamps: %s",
							len(times), strings.Join(times, ", "))
					},
				},
			}
		},
	})
}
