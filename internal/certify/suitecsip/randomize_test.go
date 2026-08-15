package suitecsip

// randomize_test.go — CORE-021's second criterion, red and green.
//
// The Skip this replaced said the bench could not ask the DUT to announce its
// start instant. It could, and had been able to for as long as CORE-022 has
// been grading Response lifecycles. What the bench genuinely cannot do is
// measure the MAGNITUDE of an applied randomization from a Response the DUT
// posts on its own 60 s poll cadence — so the criterion asserts the one-sided
// bound that quantisation cannot forge, and the tests below require it to be
// exactly that: strict about early starts, silent about late ones.

import (
	"fmt"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

// rndMsg builds a synthetic message at an explicit capture time, which the
// shared msg() helper cannot do — every timing assertion here is about WHEN a
// frame was captured, so a fixed timestamp would make the test vacuous.
func rndMsg(kind MessageKind, method, path string, status int, body string, at time.Time) *Message {
	m := &Message{Kind: kind, Method: method, Path: path, Target: path, Status: status,
		Header: textproto.MIMEHeader{}, Body: []byte(body), Time: at,
		Frames: []int{1}, CipherStart: 0, CipherEnd: 10}
	if body != "" {
		m.Header.Set("Content-Type", sepCT)
	}
	return m
}

// timeExchange is the GET /tm the skew is recovered from. The capture stamp and
// the served currentTime are given separately so a test can put the two clocks
// deliberately out of step.
func timeExchange(serverNow int64, capturedAt time.Time) Exchange {
	body := fmt.Sprintf(`<Time xmlns="%s" href="/tm"><currentTime>%d</currentTime>`+
		`<quality>3</quality><tzOffset>0</tzOffset></Time>`, Namespace, serverNow)
	return Exchange{
		Req:  rndMsg(Request, "GET", "/tm", 0, "", capturedAt),
		Resp: rndMsg(Response, "", "", 200, body, capturedAt),
	}
}

// randomizedControlXML is one DERControl as the DUT would have fetched it.
func randomizedControlXML(mrid string, start int64, rnd int32) string {
	return fmt.Sprintf(`<DERControl replyTo="/rsps/0/r" responseRequired="03">`+
		`<mRID>%s</mRID><creationTime>%d</creationTime>`+
		`<interval><duration>60</duration><start>%d</start></interval>`+
		`<randomizeStart>%d</randomizeStart>`+
		`<DERControlBase><opModMaxLimW><multiplier>0</multiplier><value>5000</value></opModMaxLimW>`+
		`</DERControlBase></DERControl>`, mrid, start-60, start, rnd)
}

func controlListExchange(at time.Time, controls ...string) Exchange {
	body := fmt.Sprintf(`<DERControlList xmlns="%s" href="/derp/0/derc" all="%d" results="%d">%s</DERControlList>`,
		Namespace, len(controls), len(controls), strings.Join(controls, ""))
	return Exchange{
		Req:  rndMsg(Request, "GET", "/derp/0/derc", 0, "", at),
		Resp: rndMsg(Response, "", "", 200, body, at),
	}
}

// startedResponse is the DUT's status=2 Response POST, captured at `at`.
func startedResponse(mrid string, at time.Time) Exchange {
	body := fmt.Sprintf(`<DERControlResponse xmlns="%s"><subject>%s</subject>`+
		`<status>2</status><createdDateTime>%d</createdDateTime></DERControlResponse>`,
		Namespace, mrid, at.Unix())
	return Exchange{
		Req:  rndMsg(Request, "POST", "/rsps/0/r", 0, body, at),
		Resp: rndMsg(Response, "", "", 201, "", at),
	}
}

// core021Transcript assembles the whole conversation. serverStart is the
// interval start on the SERVER's clock; the capture clock is aligned with it
// (skew 0) unless a test says otherwise.
func core021Transcript(serverStart int64, startedOffsets map[string]time.Duration) *Transcript {
	base := time.Unix(serverStart, 0)
	exs := []Exchange{
		timeExchange(serverStart-300, base.Add(-300*time.Second)),
		controlListExchange(base.Add(-200*time.Second),
			randomizedControlXML(core021MRIDPrefix+"0", serverStart, 0),
			randomizedControlXML(core021MRIDPrefix+"1", serverStart+60, 30),
			randomizedControlXML(core021MRIDPrefix+"2", serverStart+120, -30),
		),
	}
	for mrid, off := range startedOffsets {
		exs = append(exs, startedResponse(mrid, base.Add(off)))
	}
	return synthTranscript(exs...)
}

// GREEN: every control announced its start at or after its earliest permitted
// instant — including one announced a full poll cycle LATE, which this
// criterion deliberately says nothing about.
func TestCORE021_PassesWhenNoEventStartedEarlierThanPermitted(t *testing.T) {
	const serverStart = 1_800_000_000
	tr := core021Transcript(serverStart, map[string]time.Duration{
		// randomizeStart 0: permitted from serverStart. Announced 5 s later.
		core021MRIDPrefix + "0": 5 * time.Second,
		// randomizeStart +30 on a start 60 s later: permitted from
		// serverStart+30 under the union bound. Announced a poll cycle late.
		core021MRIDPrefix + "1": 120 * time.Second,
		// randomizeStart -30 on a start 120 s later: permitted from
		// serverStart+90. Announced at +95.
		core021MRIDPrefix + "2": 95 * time.Second,
	})

	c := critRandomizationNotEarlierThanPermitted(core021MRIDPrefix)
	f := wantVerdict(t, "CORE-021 randomization bound", c, tr, certify.Pass)
	t.Logf("GREEN —\n  %s", f.Observed)
	// A PASS must not be read as covering the magnitude.
	if !strings.Contains(f.Observed, "EARLIEST bound only") {
		t.Errorf("the PASS does not disclaim the half it cannot measure, so a reader would take it for "+
			"a statement that the randomization was applied:\n  %s", f.Observed)
	}
}

// RED: the DUT announced a start BEFORE the earliest instant its own
// randomization permits. Poll quantisation can only make a Response late, so
// this is the DUT's.
func TestCORE021_FailsAnEventAnnouncedBeforeItWasPermittedToStart(t *testing.T) {
	const serverStart = 1_800_000_000
	tr := core021Transcript(serverStart, map[string]time.Duration{
		// randomizeStart 0 commands NO randomization, and this Response lands
		// 40 s before the interval even opens.
		core021MRIDPrefix + "0": -40 * time.Second,
		core021MRIDPrefix + "1": 120 * time.Second,
		core021MRIDPrefix + "2": 95 * time.Second,
	})

	c := critRandomizationNotEarlierThanPermitted(core021MRIDPrefix)
	f := wantVerdict(t, "CORE-021 randomization bound", c, tr, certify.Fail)
	t.Logf("RED — an event started before it was allowed to:\n  %s", f.Observed)
	for _, want := range []string{"EARLY", core021MRIDPrefix + "0", "Poll quantisation cannot produce this"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not say %q:\n  %s", want, f.Observed)
		}
	}
}

// The guard band must absorb sub-second measurement noise and nothing wider: a
// randomization-sized earliness has to survive it.
func TestCORE021_TheGuardBandAbsorbsNoiseAndNotAViolation(t *testing.T) {
	const serverStart = 1_800_000_000
	c := critRandomizationNotEarlierThanPermitted(core021MRIDPrefix)

	// One second early on the un-randomized control: inside the band.
	within := core021Transcript(serverStart, map[string]time.Duration{
		core021MRIDPrefix + "0": -1 * time.Second,
		core021MRIDPrefix + "1": 120 * time.Second,
		core021MRIDPrefix + "2": 95 * time.Second,
	})
	wantVerdict(t, "one second early", c, within, certify.Pass)

	// Ten seconds early: outside it. A randomization this criterion is about is
	// tens of seconds, so the band must not be able to swallow one.
	beyond := core021Transcript(serverStart, map[string]time.Duration{
		core021MRIDPrefix + "0": -10 * time.Second,
		core021MRIDPrefix + "1": 120 * time.Second,
		core021MRIDPrefix + "2": 95 * time.Second,
	})
	wantVerdict(t, "ten seconds early", c, beyond, certify.Fail)

	if randomizeGuardBand >= 10*time.Second {
		t.Errorf("the guard band is %s — wide enough to absorb a real violation", randomizeGuardBand)
	}
}

// The server's clock and the capture clock are DIFFERENT clocks, and the skew
// between them is what places an interval start on the capture timeline. A
// criterion that ignored it would report a whole run as early (or as late) on
// any bench whose two clocks are not aligned.
func TestCORE021_TheServerClockSkewIsApplied(t *testing.T) {
	const serverStart = 1_800_000_000
	const skew = 45 * time.Second

	// The server's clock runs 45 s BEHIND the capture clock: a Response
	// captured 5 s after the interval start in SERVER time appears 50 s after
	// it in capture time. Correct either way; the point is that a criterion
	// which subtracted the skew with the wrong sign would call it early.
	base := time.Unix(serverStart, 0).Add(skew)
	tr := synthTranscript(
		timeExchange(serverStart-300, time.Unix(serverStart-300, 0).Add(skew)),
		controlListExchange(base.Add(-200*time.Second),
			randomizedControlXML(core021MRIDPrefix+"0", serverStart, 0)),
		startedResponse(core021MRIDPrefix+"0", base.Add(5*time.Second)),
	)
	c := critRandomizationNotEarlierThanPermitted(core021MRIDPrefix)
	wantVerdict(t, "skewed clocks, a legitimate start", c, tr, certify.Pass)

	// And the same conversation with the Response 40 s before the interval
	// opened on the SERVER's clock is still a violation once the skew is
	// applied.
	early := synthTranscript(
		timeExchange(serverStart-300, time.Unix(serverStart-300, 0).Add(skew)),
		controlListExchange(base.Add(-200*time.Second),
			randomizedControlXML(core021MRIDPrefix+"0", serverStart, 0)),
		startedResponse(core021MRIDPrefix+"0", base.Add(-40*time.Second)),
	)
	wantVerdict(t, "skewed clocks, a real earliness", c, early, certify.Fail)
}

// Without a Time exchange the two clocks have no known offset, and the
// criterion declines rather than comparing a server epoch against a capture
// stamp as though they were the same clock.
func TestCORE021_NoTimeResourceMeansNoComparison(t *testing.T) {
	const serverStart = 1_800_000_000
	base := time.Unix(serverStart, 0)
	tr := synthTranscript(
		controlListExchange(base.Add(-200*time.Second),
			randomizedControlXML(core021MRIDPrefix+"0", serverStart, 0)),
		startedResponse(core021MRIDPrefix+"0", base.Add(5*time.Second)),
	)
	c := critRandomizationNotEarlierThanPermitted(core021MRIDPrefix)
	why := wantUnavailable(t, "no Time exchange", c, tr)
	if !strings.Contains(why, "offset is unknown") {
		t.Errorf("the unavailability does not name the missing offset:\n  %s", why)
	}
}

// A DUT that announced no start at all is unavailable, not a FAIL — and the
// reason must NOT repeat the retired claim that the bench cannot ask for the
// announcement, which is the sentence this whole file exists to delete.
func TestCORE021_NoStartAnnouncedIsUnavailableAndSaysWhyHonestly(t *testing.T) {
	const serverStart = 1_800_000_000
	tr := core021Transcript(serverStart, nil)
	c := critRandomizationNotEarlierThanPermitted(core021MRIDPrefix)
	why := wantUnavailable(t, "no Started responses", c, tr)
	t.Logf("the honest unavailability:\n  %s", why)
	if strings.Contains(why, "does not expose responseRequired") {
		t.Error("the reason still says gridsim cannot expose responseRequired; it can, and has been " +
			"setting adminDefaultResponseRequired on every admin-created control the whole time")
	}
	if !strings.Contains(why, "adminDefaultResponseRequired") {
		t.Errorf("the reason does not say the request WAS made, so a reader cannot tell whether the "+
			"bench asked:\n  %s", why)
	}
}

// The row itself must be wired to this criterion — a test that graded a
// criterion the shipping row does not build would prove nothing.
func TestCORE021_TheShippingRowUsesTheBoundCriterion(t *testing.T) {
	if core021MRIDPrefix == "" {
		t.Fatal("CORE-021 has no mRID stem for the criterion to find its controls by")
	}
	c := critRandomizationNotEarlierThanPermitted(core021MRIDPrefix)
	if c.Skip != "" {
		t.Errorf("the criterion carries a Skip reason (%q); the whole point of this work is that it "+
			"DECIDES on what the capture holds", c.Skip)
	}
	if !c.NeedsTranscript {
		t.Error("the criterion does not declare that it needs the decrypted transcript, so it would be " +
			"called against an empty one and report an unavailability about the wrong thing")
	}
}
