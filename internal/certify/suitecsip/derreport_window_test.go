package suitecsip

// derreport_window_test.go covers the DER self-report observation fix: the DUT's
// DERStatus / DERCapability / DERSettings PUTs are cadence- and change-driven,
// so the one a case is written to observe routinely lands earlier in the run
// than that case's narrow window. Observing only the window FAILs cases that
// the board's own lexa_nb_derreport_puts_total metric shows the DUT satisfies
// (BASIC-028, CORE-009/CORE-014, UTIL-002 in runs/overnight-20260729T045336/).
//
// The fix scopes the observation to the RUN (PutsForInRun / RunDERPuts) while
// still FAILing when the DUT never PUT the resource anywhere in the run.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

func derPut(resource string) AdminDERPut {
	return AdminDERPut{Path: "/edev/2/der/0/" + strings.ToLower(resource), Resource: resource,
		Body: "<" + resource + " xmlns=\"urn:ieee:std:2030.5:ns\"/>", ReceivedAt: 1785000000}
}

func TestDERPutObservedEarlierInTheRunStillPasses(t *testing.T) {
	// The window (DERPuts) saw no DERSettings, but the run did — the DUT reported
	// it before this case's window opened.
	v := &ServerView{
		Available:  true,
		Requests:   []ServerRequest{{Method: "GET", Path: "/dcap"}},
		DERPuts:    nil,
		RunDERPuts: []AdminDERPut{derPut("DERCapability"), derPut("DERSettings")},
	}
	f := critDERPut("DERSettings").Server(v)
	if f.Verdict != certify.Pass {
		t.Fatalf("DERSettings reported earlier in the run: verdict = %s, want PASS (%s)", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "during the run") || !strings.Contains(f.Observed, "own cadence") {
		t.Errorf("the observation must disclose it looked past the window: %q", f.Observed)
	}
}

func TestDERPutInWindowStillPasses(t *testing.T) {
	v := &ServerView{
		Available:  true,
		DERPuts:    []AdminDERPut{derPut("DERSettings")},
		RunDERPuts: []AdminDERPut{derPut("DERSettings")},
	}
	f := critDERPut("DERSettings").Server(v)
	if f.Verdict != certify.Pass {
		t.Fatalf("in-window DERSettings PUT: verdict = %s, want PASS", f.Verdict)
	}
	if !strings.Contains(f.Observed, "in this case's window") {
		t.Errorf("an in-window PUT should say so, not credit the wider run: %q", f.Observed)
	}
}

func TestDERPutNeverInRunStillFails(t *testing.T) {
	// The DUT reported OTHER resources in the run — so a session established — but
	// never DERSettings. That is a real DUT failure and must stay a FAIL.
	v := &ServerView{
		Available:  true,
		RunDERPuts: []AdminDERPut{derPut("DERCapability"), derPut("DERStatus")},
	}
	f := critDERPut("DERSettings").Server(v)
	if f.Verdict != certify.Fail {
		t.Fatalf("DERSettings absent from the whole run: verdict = %s, want FAIL", f.Verdict)
	}
	if f.Unavailable != "" {
		t.Errorf("a run with reports is a run with a session; this must FAIL, not soften: %q", f.Unavailable)
	}
	if !strings.Contains(f.Observed, "anywhere in this run") {
		t.Errorf("the failure must say it looked across the whole run: %q", f.Observed)
	}
}

func TestDERPutWithoutASessionStaysUnavailable(t *testing.T) {
	// Nothing anywhere: no window traffic, no run reports. The emptiness is a
	// handshake fact, not a DUT self-report failure — it must SKIP, not FAIL.
	v := &ServerView{Available: true}
	f := critDERPut("DERSettings").Server(v)
	if f.Unavailable == "" {
		t.Fatalf("no session at all: want unavailable, got verdict %s (%q)", f.Verdict, f.Observed)
	}
}

func TestDERStatusElementsReadsTheRunScopedBody(t *testing.T) {
	body := `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><genConnectStatus><value>1</value></genConnectStatus>` +
		`<inverterStatus><value>2</value></inverterStatus>` +
		`<operationalModeStatus><value>2</value></operationalModeStatus><readingTime>1</readingTime></DERStatus>`
	v := &ServerView{
		Available:  true,
		DERPuts:    nil, // nothing in THIS window
		RunDERPuts: []AdminDERPut{{Resource: "DERStatus", Body: body, ReceivedAt: 1785000000}},
	}
	f := critDERStatusElements().Server(v)
	if f.Verdict != certify.Pass {
		t.Fatalf("DERStatus body from earlier in the run: verdict = %s (%q)", f.Verdict, f.Observed)
	}
}

// TestRunBaselineExcludesAPreviousCampaign proves the run scoping: gridsim's
// der_puts log is append-only across campaigns, so the baseline must fence off
// the reports this run did not cause.
func TestRunBaselineExcludesAPreviousCampaign(t *testing.T) {
	resetRunBaseline()
	defer resetRunBaseline()

	// The log already held two PUTs from a previous campaign when this run first
	// looked.
	prior := ServerView{Available: true, DERPuts: []AdminDERPut{derPut("DERSettings"), derPut("DERCapability")}}
	markRunBaseline(prior)

	// This run then adds one of its own.
	now := ServerView{Available: true, DERPuts: []AdminDERPut{
		derPut("DERSettings"), derPut("DERCapability"), derPut("DERStatus")}}
	inRun := derPutsInRun(now)
	if len(inRun) != 1 || inRun[0].Resource != "DERStatus" {
		t.Fatalf("run-scoped puts = %v, want exactly this run's DERStatus", inRun)
	}

	// A second call marks nothing new — the baseline is fixed for the process.
	markRunBaseline(now)
	if got := derPutsInRun(now); len(got) != 1 {
		t.Errorf("baseline moved after being set: run-scoped puts = %v", got)
	}
}

// TestRunBaselineSurvivesALogTruncation guards the fallback: if gridsim
// restarted mid-run and its log came back shorter than the baseline, the safe
// answer is the whole current log, never an empty one (which would resurrect the
// false FAIL).
func TestRunBaselineSurvivesALogTruncation(t *testing.T) {
	resetRunBaseline()
	defer resetRunBaseline()
	markRunBaseline(ServerView{Available: true, DERPuts: []AdminDERPut{
		derPut("a"), derPut("b"), derPut("c")}})
	short := ServerView{Available: true, DERPuts: []AdminDERPut{derPut("DERStatus")}}
	if got := derPutsInRun(short); len(got) != 1 {
		t.Fatalf("after a truncation the whole current log is the safe answer, got %v", got)
	}
}

// TestSortedDERPutsOrdersByReceivedAtThenPath pins the fix that makes
// Driver.Snapshot's DER PUT observation reliable against a REAL gridsim:
// GET /admin/derputs serves a map (see derput.go's handleAdminDERPuts, and
// the doc comment at sortedDERPuts's call site in Snapshot), and a Go map's
// iteration order is randomised — decoding it straight into ServerView.DERPuts
// would hand PutsFor/Since a different, arbitrary order on every read, which
// is fatal to both "the LAST entry is the most recent" (critDERPut's Server
// evaluator) and Since's positional delta. sortedDERPuts must always recover
// a stable, receipt-time order from the map.
func TestSortedDERPutsOrdersByReceivedAtThenPath(t *testing.T) {
	m := map[string]AdminDERPut{
		"/edev/2/der/0/derset":    {Path: "/edev/2/der/0/derset", Resource: "DERSettings", ReceivedAt: 200},
		"/edev/2/der/0/dercap":    {Path: "/edev/2/der/0/dercap", Resource: "DERCapability", ReceivedAt: 100},
		"/edev/2/der/0/g1/dercap": {Path: "/edev/2/der/0/g1/dercap", Resource: "DERCapability", ReceivedAt: 300},
		// Ties on ReceivedAt (same wall-clock second) break on path.
		"/edev/2/der/0/b": {Path: "/edev/2/der/0/b", Resource: "DERStatus", ReceivedAt: 300},
	}
	got := sortedDERPuts(m)
	if len(got) != 4 {
		t.Fatalf("sortedDERPuts returned %d entries, want 4: %+v", len(got), got)
	}
	wantOrder := []string{
		"/edev/2/der/0/dercap",    // 100
		"/edev/2/der/0/derset",    // 200
		"/edev/2/der/0/b",         // 300, path "b" < "g1/dercap"
		"/edev/2/der/0/g1/dercap", // 300
	}
	for i, path := range wantOrder {
		if got[i].Path != path {
			t.Errorf("position %d = %q, want %q (full order: %v)", i, got[i].Path, path, pathsOf(got))
		}
	}

	// The empty map is the empty slice, not nil-vs-empty confusion further up
	// the stack (Since/PutsFor range over it either way, but an explicit check
	// pins the contract).
	if got := sortedDERPuts(nil); len(got) != 0 {
		t.Errorf("sortedDERPuts(nil) = %+v, want empty", got)
	}
}

func pathsOf(puts []AdminDERPut) []string {
	out := make([]string, len(puts))
	for i, p := range puts {
		out[i] = p.Path
	}
	return out
}

func TestPutsForInRunFallsBackToWindow(t *testing.T) {
	// A synthetic view that set only DERPuts (no RunDERPuts) must still answer the
	// run-scoped question — from the window it has.
	v := ServerView{DERPuts: []AdminDERPut{derPut("DERSettings")}}
	if got := v.PutsForInRun("DERSettings"); len(got) != 1 {
		t.Errorf("PutsForInRun with no RunDERPuts should fall back to the window, got %v", got)
	}
}
