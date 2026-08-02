package suitecsip

// core009_test.go pins CORE-009's disjunctive DER self-report grading.
//
// CSIP Conformance Test Procedures v1.3 pp.41-42 states the row's DER
// self-report pass criterion as an "or" across the four resources: a client
// PASSES if it PUT DERCapability, DERSettings, DERStatus OR DERAvailability —
// not all four. Before this fix, CORE-009 asserted critDERPut(resource) once
// per resource, so a DUT that (correctly, per CSIP IG §6.3.5.2) PUTs only a
// cadence-driven DERStatus in a given window failed three of the row's four
// PUT criteria on a bench that was working exactly as specified. The two
// pinned shapes below are the regression lock: DERStatus-only must PASS the
// combined criterion, and PUTting nothing must FAIL it — while the four
// individual critDERPutInformational notes never turn either shape into a row
// FAIL, or (CORE-009 #10, census 20260802) a row WARN, by themselves: they
// demote an absent resource to SKIP, whose severity sits below PASS, so it
// can never outrank the combined criterion's own verdict.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

// TestCritDERPutAny_DERStatusOnlyPasses is the row's own printed criterion,
// literally: a DUT that PUTs DERStatus and nothing else has done exactly what
// CTP v1.3 pp.41-42 requires ("or DERStatus"), so the combined criterion must
// PASS even though DERCapability/DERSettings/DERAvailability never appear.
func TestCritDERPutAny_DERStatusOnlyPasses(t *testing.T) {
	statusOnly := synthTranscript(Exchange{
		Req:  msg(Request, "PUT", "/edev/2/der/0/derstat", 0, derStatusBody(t)),
		Resp: msg(Response, "", "", 204, ""),
	})
	f := wantVerdict(t, "DERStatus-only satisfies the disjunctive criterion",
		critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability"), statusOnly, certify.Pass)
	if !strings.Contains(f.Observed, "DERStatus") {
		t.Errorf("the PASS should name which of the four resources satisfied it: %q", f.Observed)
	}
}

// TestCritDERPutAny_NothingFails is the other half of the pin: a DUT that PUT
// none of the four fails the row's own criterion, and the failure must name
// what it looked for. The window here PUTs something (an unrelated resource,
// same as critDERPut's own "wrong resource" fixture) rather than nothing at
// all: with ev==nil in this Wire-tier test, an EMPTY PUT set can only ever
// reach "unavailable" (the run's capture cannot settle whether one happened
// elsewhere) — a real FAIL requires the wire to have SOMETHING to contrast
// against. The all-nothing-anywhere shape is pinned at the Server tier below
// (TestCritDERPutAny_ServerTierHonoursTheSameDisjunction's sessionNoPuts
// case), which needs no capture at all to construct.
func TestCritDERPutAny_NothingFails(t *testing.T) {
	somethingElse := synthTranscript(Exchange{
		Req:  msg(Request, "PUT", "/x", 0, `<Something xmlns="urn:ieee:std:2030.5:ns"/>`),
		Resp: msg(Response, "", "", 204, ""),
	})
	f := wantVerdict(t, "PUT of an unrelated resource satisfies none of the four",
		critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability"), somethingElse, certify.Fail)
	if !strings.Contains(f.Observed, "DERCapability") || !strings.Contains(f.Observed, "DERAvailability") {
		t.Errorf("the failure should name the four resources it looked for: %q", f.Observed)
	}
}

// TestCritDERPutAny_AnySingleOneSatisfiesIt sweeps all four resources
// individually — the row's "or" is symmetric, not secretly biased toward
// DERStatus because that is the cadence-driven one.
func TestCritDERPutAny_AnySingleOneSatisfiesIt(t *testing.T) {
	bodies := map[string]string{
		"DERCapability":   `<DERCapability xmlns="urn:ieee:std:2030.5:ns"><type>80</type></DERCapability>`,
		"DERSettings":     `<DERSettings xmlns="urn:ieee:std:2030.5:ns"><updatedTime>1</updatedTime></DERSettings>`,
		"DERStatus":       derStatusBody(t),
		"DERAvailability": `<DERAvailability xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERAvailability>`,
	}
	for _, resource := range []string{"DERCapability", "DERSettings", "DERStatus", "DERAvailability"} {
		tr := synthTranscript(Exchange{
			Req:  msg(Request, "PUT", "/x", 0, bodies[resource]),
			Resp: msg(Response, "", "", 204, ""),
		})
		wantVerdict(t, resource+" alone",
			critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability"), tr, certify.Pass)
	}
}

// TestCritDERPutAny_RejectedPUTIsAFail proves the combined criterion still
// grades the response, not merely the request's existence: a PUT of a wanted
// resource that the server REJECTED does not satisfy "did an HTTP PUT" in the
// sense the row means (successfully).
func TestCritDERPutAny_RejectedPUTIsAFail(t *testing.T) {
	rejected := synthTranscript(Exchange{
		Req: msg(Request, "PUT", "/edev/2/der/0/derstat", 0, derStatusBody(t)), Resp: msg(Response, "", "", 400, ""),
	})
	wantVerdict(t, "rejected DERStatus PUT",
		critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability"), rejected, certify.Fail)
}

// TestCritDERPutAny_LaterUnansweredPUTDoesNotEclipseAnEarlierPass is the
// regression this fix locks: CORE-009's live bench capture (2026-07-30) held,
// in capture order, a DERStatus PUT that succeeded (204), then a re-homed
// DERCapability PUT that succeeded (204), then a re-homed DERSettings PUT
// that succeeded (204), then a SECOND DERStatus PUT — the DUT's next ordinary
// cadence report — whose response fell outside this window and so reads as
// "never answered in the capture". The row's own criterion is disjunctive
// ("at least one" of the four), so three satisfying PUTs already earned it a
// PASS; grading only the chronologically LAST matching PUT (this criterion's
// original selection rule) threw all three away and FAILed the row on an
// artifact of when the capture window happened to end, not on anything the
// DUT did wrong.
func TestCritDERPutAny_LaterUnansweredPUTDoesNotEclipseAnEarlierPass(t *testing.T) {
	tr := synthTranscript(
		Exchange{
			Req:  msg(Request, "PUT", "/edev/2/der/0/derstat", 0, derStatusBody(t)),
			Resp: msg(Response, "", "", 204, ""),
		},
		Exchange{
			Req: msg(Request, "PUT", "/edev/2/der/0/g1/dercap", 0,
				`<DERCapability xmlns="urn:ieee:std:2030.5:ns"><type>80</type></DERCapability>`),
			Resp: msg(Response, "", "", 204, ""),
		},
		Exchange{
			Req: msg(Request, "PUT", "/edev/2/der/0/g1/derset", 0,
				`<DERSettings xmlns="urn:ieee:std:2030.5:ns"><updatedTime>1</updatedTime></DERSettings>`),
			Resp: msg(Response, "", "", 204, ""),
		},
		Exchange{
			Req:  msg(Request, "PUT", "/edev/2/der/0/derstat", 0, derStatusBody(t)),
			Resp: nil,
		},
	)
	f := wantVerdict(t, "three earlier PASSes must not be eclipsed by a later unanswered PUT",
		critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability"), tr, certify.Pass)
	if strings.Contains(f.Observed, "never answered") {
		t.Errorf("the PASS must be graded from a satisfying exchange, not the unanswered one: %q", f.Observed)
	}
}

// TestCritDERPutAny_ServerTierHonoursTheSameDisjunction pins the tier-3
// (gridsim admin log) evaluator to the same rule: a DERStatus-only ServerView
// passes, and an empty one — with a session established — fails.
func TestCritDERPutAny_ServerTierHonoursTheSameDisjunction(t *testing.T) {
	c := critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability")

	statusOnly := &ServerView{Available: true, DERPuts: []AdminDERPut{derPut("DERStatus")}}
	if f := c.Server(statusOnly); f.Verdict != certify.Pass {
		t.Fatalf("DERStatus-only in-window: verdict = %s (%s)", f.Verdict, f.Observed)
	}

	// Cadence-driven: the report landed earlier in the RUN, not in this
	// window. Still a PASS — same reasoning as critDERPut's own run-scoped
	// fallback.
	runOnly := &ServerView{Available: true, RunDERPuts: []AdminDERPut{derPut("DERAvailability")}}
	if f := c.Server(runOnly); f.Verdict != certify.Pass {
		t.Fatalf("DERAvailability earlier in the run: verdict = %s (%s)", f.Verdict, f.Observed)
	}

	// A session established (the DUT walked /dcap) but PUT none of the four:
	// a real FAIL, not a soft unavailable.
	sessionNoPuts := &ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}
	f := c.Server(sessionNoPuts)
	if f.Verdict != certify.Fail {
		t.Fatalf("session established, no DER* PUTs anywhere: verdict = %s (%s)", f.Verdict, f.Observed)
	}
	if f.Unavailable != "" {
		t.Errorf("a session with no DER* PUTs must FAIL, not soften to unavailable: %q", f.Unavailable)
	}

	// No session at all: the emptiness is a handshake fact, not a DUT fact.
	noSession := &ServerView{Available: true}
	if f := c.Server(noSession); f.Unavailable == "" {
		t.Fatalf("no session at all: want unavailable, got verdict %s (%q)", f.Verdict, f.Observed)
	}
}

// TestCritDERPutInformational_DemotesFailToSkip is the counterweight this
// fix's disjunctive grading needs: the four per-resource critDERPut
// observations must not be able to FAIL — or WARN — the row on their own once
// critDERPutAny is the criterion that actually decides it.
//
// SKIP, not WARN: Verdict.Severity() ranks WARN (2) above PASS (1), so
// demoting to WARN (the original fix) still pulled a row critDERPutAny had
// already PASSed back down to WARN whenever any ONE of the other three
// resources was absent from this window — CORE-009 #10's census
// (20260802). SKIP's severity (0) sits below PASS, so the informational note
// can never outrank the combined criterion's own verdict.
func TestCritDERPutInformational_DemotesFailToSkip(t *testing.T) {
	// A window that PUT a DIFFERENT resource (not DERSettings): plain
	// critDERPut("DERSettings") FAILs this (pinned by
	// TestDERPutCriterionHasTeeth's "wrong resource" case); wrapped, it must
	// SKIP instead, informationally, and point at the criterion that actually
	// decides the row.
	other := synthTranscript(Exchange{
		Req:  msg(Request, "PUT", "/x", 0, `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERStatus>`),
		Resp: msg(Response, "", "", 204, ""),
	})
	f := wantVerdict(t, "DERSettings absent, informational", critDERPutInformational("DERSettings"),
		other, certify.Skip)
	if !strings.Contains(f.Observed, "INFORMATIONAL") || !strings.Contains(f.Observed, "disjunctive") {
		t.Errorf("the demoted SKIP must say it is informational and point at the disjunctive criterion: %q",
			f.Observed)
	}
}

// TestCritDERPutInformational_SkipDoesNotOutrankTheRowsOwnPass is CORE-009
// #10 itself, reproduced directly: three of the four DER self-reports were
// PUT (so critDERPutAny — the row's real, disjunctive criterion — PASSes),
// and the fourth (DERAvailability) was not. The informational note about the
// missing fourth resource must not carry more severity than the row's own
// combined PASS, or mint()'s per-case rollup (registry.go's Result.rollUp,
// runner.go's worstOf) drags the whole row down to WARN on a criterion the
// CTP itself does not require conjunctively.
func TestCritDERPutInformational_SkipDoesNotOutrankTheRowsOwnPass(t *testing.T) {
	threeOfFour := synthTranscript(
		Exchange{
			Req: msg(Request, "PUT", "/edev/2/der/0/g1/dercap", 0,
				`<DERCapability xmlns="urn:ieee:std:2030.5:ns"><type>80</type></DERCapability>`),
			Resp: msg(Response, "", "", 204, ""),
		},
		Exchange{
			Req: msg(Request, "PUT", "/edev/2/der/0/g1/derset", 0,
				`<DERSettings xmlns="urn:ieee:std:2030.5:ns"><updatedTime>1</updatedTime></DERSettings>`),
			Resp: msg(Response, "", "", 204, ""),
		},
		Exchange{
			Req:  msg(Request, "PUT", "/edev/2/der/0/derstat", 0, derStatusBody(t)),
			Resp: msg(Response, "", "", 204, ""),
		},
	)

	combined := wantVerdict(t, "3 of 4 DER self-reports PUT",
		critDERPutAny("DERCapability", "DERSettings", "DERStatus", "DERAvailability"), threeOfFour, certify.Pass)
	absent := wantVerdict(t, "DERAvailability absent, informational",
		critDERPutInformational("DERAvailability"), threeOfFour, certify.Skip)

	if combined.Verdict.Severity() < absent.Verdict.Severity() {
		t.Fatalf("the row's own combined criterion (%s, severity %d) must outrank the informational absence "+
			"note (%s, severity %d), or CORE-009's rollup regresses to the WARN this fix removed",
			combined.Verdict, combined.Verdict.Severity(), absent.Verdict, absent.Verdict.Severity())
	}
}

// TestCritDERPutInformational_PassStaysPass proves the wrapper gives full
// credit, unmodified, when the resource WAS observed — demotion only ever
// touches a FAIL.
func TestCritDERPutInformational_PassStaysPass(t *testing.T) {
	good := synthTranscript(Exchange{
		Req:  msg(Request, "PUT", "/edev/2/der/0/derset", 0, `<DERSettings xmlns="urn:ieee:std:2030.5:ns"/>`),
		Resp: msg(Response, "", "", 204, ""),
	})
	f := wantVerdict(t, "DERSettings present, informational", critDERPutInformational("DERSettings"),
		good, certify.Pass)
	if strings.Contains(f.Observed, "INFORMATIONAL") {
		t.Errorf("a PASS must not be annotated as if it had been demoted: %q", f.Observed)
	}
}

// TestCritDERPutInformational_UnavailableStaysUnavailable proves demote()
// leaves an undecided finding alone: "no session established" must still SKIP
// (via mint()'s unavailable path), never read as a demoted WARN.
func TestCritDERPutInformational_UnavailableStaysUnavailable(t *testing.T) {
	v := &ServerView{Available: true} // no session evidence at all
	f := critDERPutInformational("DERSettings").Server(v)
	if f.Unavailable == "" {
		t.Fatalf("no session at all: want unavailable, got verdict %s (%q)", f.Verdict, f.Observed)
	}
}

// derStatusBody is a minimal well-formed DERStatus carrying BASIC-028's
// required elements, reused across cases that need a genuine DERStatus PUT
// body rather than a placeholder.
func derStatusBody(t *testing.T) string {
	t.Helper()
	return `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><genConnectStatus><value>1</value></genConnectStatus>` +
		`<inverterStatus><value>2</value></inverterStatus>` +
		`<operationalModeStatus><value>2</value></operationalModeStatus><readingTime>1</readingTime></DERStatus>`
}
